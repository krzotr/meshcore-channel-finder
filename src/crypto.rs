// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 krzotr <https://github.com/krzotr/meshcore-channel-finder>

use aes::Aes128;
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, KeyInit};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::collections::HashSet;
use std::sync::OnceLock;

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone)]
pub struct Secret {
    pub key: [u8; 16],
    key_hmac_init: OnceLock<HmacSha256>,
    key_cipher: OnceLock<Aes128>,
}

impl Secret {
    pub fn new(key: [u8; 16]) -> Self {
        Self {
            key,
            key_hmac_init: OnceLock::new(),
            key_cipher: OnceLock::new(),
        }
    }

    pub fn get_hmac(&self) -> &HmacSha256 {
        self.key_hmac_init.get_or_init(|| {
            let mut key_hmac = [0u8; 32];
            key_hmac[..16].copy_from_slice(&self.key);

            <HmacSha256 as KeyInit>::new_from_slice(&key_hmac).expect("HMAC accepts any key length")
        })
    }

    pub fn get_cipher(&self) -> &Aes128 {
        self.key_cipher.get_or_init(|| {
            Aes128::new_from_slice(&self.key).expect("channel key length already validated as 16")
        })
    }
}

#[derive(Debug, Eq, Hash, PartialEq, Clone)]
pub struct Payload {
    pub data: Vec<u8>,
    pub mac: [u8; 2],
}

#[derive(Debug, PartialEq)]
pub enum PayloadError {
    PayloadIsTooShort(usize),
    PayloadIsNotMultipleOf16,
}

impl Payload {
    pub fn new(payload: &[u8]) -> Result<Payload, PayloadError> {
        if payload.len() < 18 {
            return Err(PayloadError::PayloadIsTooShort(payload.len()));
        }

        if (payload.len() - 2) % 16 != 0 {
            return Err(PayloadError::PayloadIsNotMultipleOf16);
        }

        Ok(Self {
            data: payload[2..].to_vec(),
            mac: [payload[0], payload[1]],
        })
    }

    pub fn first_block(&self) -> [u8; 16] {
        let mut block = [0u8; 16];
        block.copy_from_slice(&self.data[..16]);
        block
    }
}

/// Every payload that carries one channel hash.
///
/// A candidate secret has to be tried against each of the bucket's payloads,
/// but a payload whose *first* block does not decrypt to a plausible header can
/// never produce a message. Keeping `first_blocks` in its own contiguous array
/// turns that rejection pass - which runs hundreds of millions of times - from
/// a pointer chase through one heap allocation per payload into a linear scan
/// that the AES backend can chew through several blocks at a time.
#[derive(Default)]
pub struct PayloadBucket {
    pub payloads: Vec<Payload>,
    /// `payloads[i].first_block()` for every `i`, in the same order.
    pub first_blocks: Vec<[u8; 16]>,
}

impl PayloadBucket {
    pub fn new(payloads: Vec<Payload>) -> Self {
        let first_blocks = payloads.iter().map(Payload::first_block).collect();

        Self {
            payloads,
            first_blocks,
        }
    }

    /// Drops the payloads that `matched` covers and rebuilds the index.
    ///
    /// Returns how many payloads actually went away, so a caller pruning while
    /// the search runs can keep a live count without re-reading the bucket.
    pub fn retain_payloads(&mut self, matched: &HashSet<Payload>) -> usize {
        let before = self.payloads.len();

        self.payloads.retain(|payload| !matched.contains(payload));
        self.first_blocks = self.payloads.iter().map(Payload::first_block).collect();

        before - self.payloads.len()
    }

    pub fn is_empty(&self) -> bool {
        self.payloads.is_empty()
    }

    pub fn len(&self) -> usize {
        self.payloads.len()
    }
}

#[inline]
pub fn verify_hmac(payload: &Payload, secret: &Secret) -> bool {
    let mut mac: HmacSha256 = secret.get_hmac().clone();

    mac.update(&payload.data);

    let calculated = mac.finalize().into_bytes();

    calculated[0] == payload.mac[0] && calculated[1] == payload.mac[1]
}

#[inline]
pub fn decrypt_payload(payload: &Payload, secret: &Secret) -> Vec<u8> {
    let mut buf = payload.data.to_vec();

    let cipher = secret.get_cipher();

    for block in buf.chunks_mut(16) {
        cipher.decrypt_block(GenericArray::from_mut_slice(block));
    }

    buf
}

#[cfg(test)]
mod tests {
    mod crypto {
        use super::super::{Payload, PayloadError, Secret, decrypt_payload};
        use crate::crypto::verify_hmac;

        #[test]
        fn test_payload() {
            let payload_hex = "112200112233445566778899AABBCCDDEEFF";
            let payload = hex::decode(payload_hex).expect("invalid hex");

            match Payload::new(payload.as_slice()) {
                Err(_) => assert!(false, "Payload is OK but got error"),
                Ok(_) => assert!(true),
            }
        }

        #[test]
        fn test_payload_invalid() {
            let test_data: Vec<(&str, PayloadError)> = vec![
                // Invalid length of payload
                (
                    "112200112233445566778899AABBCCDD",
                    PayloadError::PayloadIsTooShort(16),
                ),
                // Payload not %16
                (
                    "112200112233445566778899AABBCCDDEEFFAA",
                    PayloadError::PayloadIsNotMultipleOf16,
                ),
            ];

            for (payload_hex, error) in &test_data {
                let payload = hex::decode(payload_hex).expect("invalid hex");

                match Payload::new(payload.as_slice()) {
                    Err(err) => assert_eq!(error, &err),
                    Ok(_) => assert!(false, "Payload length is invalid but got OK"),
                }
            }
        }

        #[test]
        fn test_decrypt_payload_public_key() {
            let secret_key_hex = "8b3387e9c5cdea6ac9e5edbaa115cd72";
            let encrypted_data_hex = "C110B413BEECFC26A71205D48366122B091219D5C2A574C8C4518C6EC82AA9F98066CB70FC74050313D3B87FF031C5BD0A6A849EC2F87028DA7D017C24D14AF9DC44";

            let decrypted_data_hex = "4799a56a004265656b65657065723a20405b50616e63696f5d20656c6567616e636b6f2c207a61707261737a616d79f09f92aa00000000000000000000000000";

            let secret_key: [u8; 16] = hex::decode(secret_key_hex)
                .expect("invalid hex")
                .try_into()
                .expect("expected 16 bytes");
            let encrypted_data = hex::decode(encrypted_data_hex).expect("invalid hex");

            let secret = Secret::new(secret_key);
            let payload = Payload::new(&encrypted_data).ok().unwrap();

            let decrypted_data = hex::decode(decrypted_data_hex).expect("invalid hex");

            assert_eq!(decrypted_data, decrypt_payload(&payload, &secret))
        }

        #[test]
        fn test_decrypt_payload_public_channel() {
            let secret_key_hex = "8b3387e9c5cdea6ac9e5edbaa115cd72";
            let encrypted_data_hex = "C110B413BEECFC26A71205D48366122B091219D5C2A574C8C4518C6EC82AA9F98066CB70FC74050313D3B87FF031C5BD0A6A849EC2F87028DA7D017C24D14AF9DC44";

            let decrypted_data_hex = "4799a56a004265656b65657065723a20405b50616e63696f5d20656c6567616e636b6f2c207a61707261737a616d79f09f92aa00000000000000000000000000";

            let secret_key: [u8; 16] = hex::decode(secret_key_hex)
                .expect("invalid hex")
                .try_into()
                .expect("expected 16 bytes");
            let encrypted_data = hex::decode(encrypted_data_hex).expect("invalid hex");

            let secret = Secret::new(secret_key);
            let payload = Payload::new(&encrypted_data).ok().unwrap();

            let decrypted_data = hex::decode(decrypted_data_hex).expect("invalid hex");

            assert_eq!(decrypted_data, decrypt_payload(&payload, &secret))
        }

        #[test]
        fn test_decrypt_payload_opt_public_channel() {
            let secret_key_hex = "8b3387e9c5cdea6ac9e5edbaa115cd72";
            let encrypted_data_hex = "C110B413BEECFC26A71205D48366122B091219D5C2A574C8C4518C6EC82AA9F98066CB70FC74050313D3B87FF031C5BD0A6A849EC2F87028DA7D017C24D14AF9DC44";

            let decrypted_data_hex = "4799a56a004265656b65657065723a20405b50616e63696f5d20656c6567616e636b6f2c207a61707261737a616d79f09f92aa00000000000000000000000000";

            let secret_key: [u8; 16] = hex::decode(secret_key_hex)
                .expect("invalid hex")
                .try_into()
                .expect("expected 16 bytes");
            let encrypted_data = hex::decode(encrypted_data_hex).expect("invalid hex");

            let secret = Secret::new(secret_key);
            let payload = Payload::new(&encrypted_data).ok().unwrap();

            let decrypted_data = hex::decode(decrypted_data_hex).expect("invalid hex");

            assert_eq!(decrypted_data, decrypt_payload(&payload, &secret))
        }

        #[test]
        fn test_verify_hmac() {
            let secret_key_hex = "8b3387e9c5cdea6ac9e5edbaa115cd72";
            let encrypted_data_hex = "C110B413BEECFC26A71205D48366122B091219D5C2A574C8C4518C6EC82AA9F98066CB70FC74050313D3B87FF031C5BD0A6A849EC2F87028DA7D017C24D14AF9DC44";

            let secret_key: [u8; 16] = hex::decode(secret_key_hex)
                .expect("invalid hex")
                .try_into()
                .expect("expected 16 bytes");
            let encrypted_data = hex::decode(encrypted_data_hex).expect("invalid hex");

            let secret = Secret::new(secret_key);
            let payload = Payload::new(&encrypted_data).ok().unwrap();

            if !verify_hmac(&payload, &secret) {
                assert!(false, "Payload HMAC is invalid, but got success");
            }
        }

        #[test]
        fn test_verify_hmac_invalid() {
            let secret_key_hex = "9cd8fcf22a47333b591d96a2b848b73f";
            let encrypted_data_hex = "AAAA645CC670B4FAA52596F9D61A74EDFCBF9F582348277055799612F79FA8B056BE8F080B892FEE4EC1503D6CCA47FAC104069DDB8B50FC66DC4193B68A372F892EB008AF1DBD03537EF5672061141BDE9B8F47CE032DA4E6885D2BE3A7E61EF45C6C89B372F49FFA127AB246A472195E45";

            let secret_key: [u8; 16] = hex::decode(secret_key_hex)
                .expect("invalid hex")
                .try_into()
                .expect("expected 16 bytes");
            let encrypted_data = hex::decode(encrypted_data_hex).expect("invalid hex");

            let secret = Secret::new(secret_key);
            let payload = Payload::new(&encrypted_data).ok().unwrap();

            if verify_hmac(&payload, &secret) {
                assert!(false, "Payload HMAC is invalid, but got success");
            }
        }
    }
}
