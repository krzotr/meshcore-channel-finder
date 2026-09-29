// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 krzotr <https://github.com/krzotr/meshcore-channel-finder>

use crate::crypto::{Payload, Secret, decrypt_payload, verify_hmac};
use chrono::{DateTime, Utc};
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, PartialEq)]
pub enum DecryptGroupTextMessage {
    DecryptedMessageTooShort(usize),
    FailedToVerifyPayload,
    TimestampOutOfRange,
    InvalidFlagsAndAttemptsValue,
    NoSenderFound,
}

#[derive(Debug, PartialEq, Clone)]
#[allow(dead_code)]
pub struct MeshcoreGroupMessage {
    pub datetime: DateTime<Utc>,
    pub flags: u8,
    pub sender: String,
    pub message: String,
}

// Hard coded base time in meshcore
// https://github.com/meshcore-dev/MeshCore/blob/0679dbeffc504d562d2f09eb072fdc223f8ffc2a/src/helpers/ArduinoHelpers.h#L11
pub const PAYLOAD_TIMESTAMP_INIT_MIN: u32 = 1_715_770_351;
pub const PAYLOAD_TIMESTAMP_INIT_MAX: u32 = PAYLOAD_TIMESTAMP_INIT_MIN + (30 * 24 * 60 * 60);

static PAYLOAD_TIMESTAMP_MIN: OnceLock<u32> = OnceLock::new();
static PAYLOAD_TIMESTAMP_MAX: OnceLock<u32> = OnceLock::new();

#[inline]
pub fn payload_timestamp_min() -> u32 {
    // - 2 months
    *PAYLOAD_TIMESTAMP_MIN.get_or_init(|| {
        (SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - (62 * 24 * 60 * 60)) as u32
    })
}

#[inline]
pub fn payload_timestamp_max() -> u32 {
    // + 12 hours max
    *PAYLOAD_TIMESTAMP_MAX.get_or_init(|| {
        (SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + (12 * 60 * 60)) as u32
    })
}

#[inline]
pub fn is_plausible_header(block: &[u8]) -> bool {
    // Based on all decrypted packets, flags_and_attemps are always zero
    let flags_and_attempt = block[4];

    if flags_and_attempt != 0 {
        return false;
    }

    // // https://github.com/meshcore-dev/MeshCore/blob/main/src/helpers/BaseChatMesh.cpp#L229
    // if (flags_and_attempt >> 2) > 2 || (flags_and_attempt & 0x03) != 0 {
    //     return Err(DecryptGroupTextMessage::InvalidFlagsAndAttemptsValue);
    // }

    let timestamp = u32::from_le_bytes([block[0], block[1], block[2], block[3]]);

    // Original condition was as below, but it takes too long range of datetime, we can
    // speedup slightly
    // timestamp >= EARLIEST_TIMESTAMP && timestamp <= time_in_the_future()
    //
    // Based on 350 000 messages
    // - 2024-05-15T10:52:31Z-2024-06-10T06:52:31Z - 240 messages, so maximum of 30 days from
    //                                               base time EARLIEST_TIMESTAMP

    (timestamp >= PAYLOAD_TIMESTAMP_INIT_MIN && timestamp <= PAYLOAD_TIMESTAMP_INIT_MAX)
        || (timestamp >= payload_timestamp_min() && timestamp <= payload_timestamp_max())
}

#[allow(dead_code)]
pub fn decrypt_group_text_message(
    payload: &Payload,
    secret: &Secret,
) -> Result<MeshcoreGroupMessage, DecryptGroupTextMessage> {
    // Decrypting is faster than HMAC, so first we decrypt message, checking if timestamp is OK
    // checking flags, checking sender etc., at the end we verify HMAC
    // In my testing environment speed is x3
    let decrypted_payload = decrypt_payload(payload, secret);

    if decrypted_payload.len() < 6 {
        return Err(DecryptGroupTextMessage::DecryptedMessageTooShort(
            decrypted_payload.len(),
        ));
    }

    let flags_and_attempt = decrypted_payload[4];

    if flags_and_attempt != 0 {
        return Err(DecryptGroupTextMessage::InvalidFlagsAndAttemptsValue);
    }

    let timestamp = u32::from_le_bytes(decrypted_payload[0..4].try_into().unwrap());

    if timestamp < PAYLOAD_TIMESTAMP_INIT_MIN {
        return Err(DecryptGroupTextMessage::TimestampOutOfRange);
    }

    let message_bytes = &decrypted_payload[5..];
    let message_text = String::from_utf8_lossy(message_bytes).into_owned();

    let message_text = match message_text.find('\0') {
        Some(idx) => message_text[..idx].to_string(),
        None => message_text,
    };

    let colon_index = message_text.find(": ");
    let mut sender: Option<String> = None;
    let mut content = message_text.clone();

    if let Some(idx) = colon_index {
        if idx > 0 && idx < 100 {
            let potential_sender = &message_text[..idx];
            if !potential_sender
                .chars()
                .any(|c| c == ':' || c == '[' || c == ']')
            {
                sender = Some(potential_sender.to_string());
                content = message_text[idx + 2..].to_string();
            }
        }
    }

    let sender = match sender {
        Some(s) => s,
        None => return Err(DecryptGroupTextMessage::NoSenderFound),
    };

    if !verify_hmac(payload, secret) {
        return Err(DecryptGroupTextMessage::FailedToVerifyPayload);
    }

    Ok(MeshcoreGroupMessage {
        datetime: DateTime::from_timestamp(timestamp as i64, 0).unwrap(),
        flags: flags_and_attempt,
        sender,
        message: content,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decrypt_payload() {
        let secret_key_hex = "9cd8fcf22a47333b591d96a2b848b73f";
        let encrypted_data_hex = "F968645CC670B4FAA52596F9D61A74EDFCBF9F582348277055799612F79FA8B056BE8F080B892FEE4EC1503D6CCA47FAC104069DDB8B50FC66DC4193B68A372F892EB008AF1DBD03537EF5672061141BDE9B8F47CE032DA4E6885D2BE3A7E61EF45C6C89B372F49FFA127AB246A472195E45";

        let decrypted_message = MeshcoreGroupMessage {
            datetime: DateTime::from_timestamp(1789105157, 0).unwrap(),
            flags: 0,
            sender: "B-Bok".to_string(),
            message: "ack @[Pawel SN9PJ 🛸] | 0652,5c78,980f,50b2 (4 hops) 📏52.3km (3 segs) | QTH Bielsko #b-bok".to_string(),
        };

        let secret_key: [u8; 16] = hex::decode(secret_key_hex)
            .expect("invalid hex")
            .try_into()
            .expect("expected 16 bytes");

        let encrypted_data = hex::decode(encrypted_data_hex).expect("invalid hex");

        let secret = Secret::new(secret_key);
        let payload = Payload::new(&encrypted_data).ok().unwrap();

        match decrypt_group_text_message(&payload, &secret) {
            Ok(decrypted_msg) => {
                assert_eq!(decrypted_message, decrypted_msg);
            }
            Err(err) => {
                assert!(false, "Got unexpected error during decryption: {:?}", err);
            }
        };
    }
}
