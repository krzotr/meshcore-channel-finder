// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 krzotr <https://github.com/krzotr/meshcore-channel-finder>

use aes::Aes128;
use aes::cipher::BlockDecrypt;
use aes::cipher::consts::U16;
use aes::cipher::generic_array::GenericArray;

use crate::crypto::{Payload, Secret};
use crate::meshcore_group_text::{
    DecryptGroupTextMessage, MeshcoreGroupMessage,
    decrypt_group_text_message as decrypt_group_text_message_org, is_plausible_header,
};

/// One decrypted AES block (16 bytes), the unit the block cipher works on.
pub type CipherBlock = GenericArray<u8, U16>;

pub fn decrypt_group_text_message(
    payload: &Payload,
    secret: &Secret,
) -> Result<MeshcoreGroupMessage, DecryptGroupTextMessage> {
    // Decrypting is faster than HMAC, so first we try to decrypt first 16
    // bytes, verify flags and timestamp
    // Tested on 1_000_000 probes, only 3000 passed this method, so is
    // slightly faster
    let mut block: [u8; 16] = payload
        .data
        .get(..16)
        .and_then(|slice| slice.try_into().ok())
        .ok_or(DecryptGroupTextMessage::DecryptedMessageTooShort(
            payload.data.len(),
        ))?;

    secret
        .get_cipher()
        .decrypt_block(GenericArray::from_mut_slice(&mut block));

    if !is_plausible_header(&block) {
        let flags_and_attempt = block[4];

        if flags_and_attempt != 0 {
            return Err(DecryptGroupTextMessage::InvalidFlagsAndAttemptsValue);
        }

        return Err(DecryptGroupTextMessage::TimestampOutOfRange);
    }

    decrypt_group_text_message_org(payload, secret)
}

#[inline]
pub fn any_first_block_looks_like_header(
    first_blocks: &[[u8; 16]],
    cipher: &Aes128,
    scratch: &mut Vec<CipherBlock>,
) -> bool {
    scratch.clear();
    scratch.extend(
        first_blocks
            .iter()
            .map(|block| *GenericArray::from_slice(block)),
    );

    cipher.decrypt_blocks(scratch);

    scratch.iter().any(|block| is_plausible_header(block))
}
