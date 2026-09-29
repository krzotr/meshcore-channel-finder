// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 krzotr <https://github.com/krzotr/meshcore-channel-finder>

use crate::crypto::Secret;
use sha2::{Digest, Sha256};
use std::fmt;

#[derive(Clone)]
pub struct Channel {
    pub name: String,
    pub secret: Secret,
    pub hash: u8,
}

impl fmt::Debug for Channel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Channel")
            .field("name", &self.name)
            .field("hash", &self.hash)
            .finish()
    }
}

impl fmt::Display for Channel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Channel {{ name: {}, secret: {}, hash: {} }}",
            self.name,
            hex::encode(self.secret.key),
            self.hash
        )
    }
}

impl Channel {
    #[allow(dead_code)]
    #[inline(always)]
    /// Derives the secret and channel hash of a channel from its bare name,
    /// i.e. the name as written without the leading `#` MeshCore displays.
    pub fn get_secret_and_hash_by_channel_name(name: &str) -> ([u8; 16], u8) {
        // The `#` is hashed as a prefix instead of being concatenated onto the
        // name, which keeps the hot path allocation free.
        let mut hasher = Sha256::new_with_prefix("#");
        hasher.update(name);

        let digest1 = hasher.finalize_reset();

        let mut secret = [0u8; 16];
        secret.copy_from_slice(&digest1[..16]);

        hasher.update(&secret);
        let digest2 = hasher.finalize();

        (secret, digest2[0])
    }

    #[allow(dead_code)]
    #[inline(always)]
    pub fn get_hash_by_channel_secret(secret: [u8; 16]) -> u8 {
        let hasher = Sha256::new_with_prefix(&secret);

        hasher.finalize()[0]
    }

    #[allow(dead_code)]
    #[inline(always)]
    /// Builds a channel from its bare name, i.e. without the leading `#`.
    pub fn get_from_channel_name(name: String) -> Channel {
        let (secret, hash) = Channel::get_secret_and_hash_by_channel_name(&name);

        Channel {
            name,
            secret: Secret::new(secret),
            hash,
        }
    }

    #[allow(dead_code)]
    #[inline(always)]
    pub fn get_from_secret(secret: [u8; 16]) -> Channel {
        let hasher = Sha256::new_with_prefix(&secret);

        Channel {
            name: "??????????????".to_string(),
            secret: Secret::new(secret),
            hash: hasher.finalize()[0],
        }
    }
}

#[cfg(test)]
mod tests {
    mod channel {
        use super::super::Channel;

        #[test]
        fn test_get_secret_key_from_secret_key() {
            let channel_name = "??????????????".to_string();
            let channel_secret_hex = "9cd8fcf22a47333b591d96a2b848b73f";
            let channel_hash = 217;

            let channel_secret: [u8; 16] = hex::decode(channel_secret_hex)
                .expect("invalid hex")
                .try_into()
                .expect("expected 16 bytes");

            let channel = Channel::get_from_secret(channel_secret);

            assert_eq!(channel_name, channel.name);
            assert_eq!(channel_secret, channel.secret.key);
            assert_eq!(channel_hash, channel.hash);
        }

        #[test]
        fn test_get_secret_key_from_channel_name() {
            let channel_name = "test".to_string();
            let channel_secret_hex = "9cd8fcf22a47333b591d96a2b848b73f";
            let channel_hash = 217;

            let channel_secret: [u8; 16] = hex::decode(channel_secret_hex)
                .expect("invalid hex")
                .try_into()
                .expect("expected 16 bytes");

            let channel = Channel::get_from_channel_name(channel_name.clone());

            assert_eq!(channel_name, channel.name);
            assert_eq!(channel_secret, channel.secret.key);
            assert_eq!(channel_hash, channel.hash);
        }
    }
}
