// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 krzotr <https://github.com/krzotr/meshcore-channel-finder>

use std::fs::File;
use std::io::{BufRead, BufReader, Read};
use std::path::PathBuf;
use std::sync::Arc;

const MAX_WORD_LENGTH: usize = 32;

/// Raw bytes read per chunk handed to a worker. Chosen to land in the same
/// rough memory envelope as the old word-count batches while being large
/// enough to amortise per-chunk handoff overhead.
const CHUNK_BYTES: usize = 1024 * 1024;

pub fn combos(
    min_length: usize,
    max_length: usize,
    charset: Vec<char>,
) -> impl Iterator<Item = String> {
    let charset = Arc::new(charset);
    let radix = charset.len() as u64;

    (min_length..=max_length).flat_map(move |length| {
        let charset = Arc::clone(&charset);
        let combinations = radix.pow(length as u32);

        (0..combinations).map(move |mut index| {
            let mut buffer = [' '; 32];
            for position in (0..length).rev() {
                buffer[position] = charset[(index % radix) as usize];
                index /= radix;
            }
            buffer[..length].iter().collect::<String>()
        })
    })
}

/// A slice of the bruteforce keyspace: `count` consecutive combinations of
/// `length`, starting at `start_index`, not yet turned into `String`s.
///
/// Building the actual candidate strings is pure CPU work with no
/// cross-index dependency, so unlike the dictionary sources there is no I/O
/// to keep off the reader thread - the fix here is the same shape as
/// [`split_words`] though: a single thread turning every index into a
/// `String` before a worker ever sees it doesn't scale past that one
/// thread's throughput, however many workers are waiting. `combo_batches`
/// hands out cheap index ranges instead; [`expand_combo_batch`] does the
/// actual string-building on whichever worker draws the batch.
pub struct ComboBatch {
    charset: Arc<Vec<char>>,
    length: usize,
    start_index: u64,
    count: u64,
}

pub fn combo_batches(
    min_length: usize,
    max_length: usize,
    charset: Vec<char>,
    batch_size: u64,
) -> impl Iterator<Item = ComboBatch> {
    let charset = Arc::new(charset);
    let radix = charset.len() as u64;

    (min_length..=max_length).flat_map(move |length| {
        let charset = Arc::clone(&charset);
        let combinations = radix.pow(length as u32);
        let mut next_index = 0u64;

        std::iter::from_fn(move || {
            if next_index >= combinations {
                return None;
            }

            let start_index = next_index;
            let count = batch_size.min(combinations - start_index);
            next_index += count;

            Some(ComboBatch {
                charset: Arc::clone(&charset),
                length,
                start_index,
                count,
            })
        })
    })
}

pub fn expand_combo_batch(batch: &ComboBatch) -> impl Iterator<Item = String> + '_ {
    let radix = batch.charset.len() as u64;

    (batch.start_index..batch.start_index + batch.count).map(move |mut index| {
        let mut buffer = [' '; MAX_WORD_LENGTH];
        for position in (0..batch.length).rev() {
            buffer[position] = batch.charset[(index % radix) as usize];
            index /= radix;
        }
        buffer[..batch.length].iter().collect::<String>()
    })
}

/// Which way [`secret_batches`] walks the keyspace from its starting secret.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SecretDirection {
    /// Counts up towards `u128::MAX`.
    Increasing,
    /// Counts down towards `0`.
    Decreasing,
}

/// A slice of the 128-bit secret keyspace: `count` consecutive secrets
/// anchored at `base`, not yet turned into hex `String`s. `base` is the
/// lowest value in the batch when counting up, or the highest when counting
/// down.
///
/// Same shape as [`ComboBatch`]/[`expand_combo_batch`]: cheap ranges handed
/// out by one iterator, expanded into strings on whichever worker draws the
/// batch.
pub struct SecretBatch {
    base: u128,
    count: u64,
    direction: SecretDirection,
}

impl SecretBatch {
    /// The secret this batch was anchored at when it was handed out, used to
    /// track how far a resumed run has to skip back to (see
    /// `--bruteforce-secret` in `main.rs`).
    pub fn start(&self) -> u128 {
        self.base
    }

    pub fn direction(&self) -> SecretDirection {
        self.direction
    }
}

/// Yields consecutive batches of `batch_size` secrets starting at `start`,
/// moving by 1 each time in `direction`, until the keyspace end (`u128::MAX`
/// when increasing, `0` when decreasing) is reached.
pub fn secret_batches(
    start: u128,
    direction: SecretDirection,
    batch_size: u64,
) -> impl Iterator<Item = SecretBatch> {
    let mut next = Some(start);

    std::iter::from_fn(move || {
        let batch_start = next?;

        // Values remaining between `batch_start` and the keyspace end,
        // exclusive of `batch_start` itself; computed this way (rather than
        // the inclusive count) because the inclusive count overflows when
        // `batch_start` is at the far end already (`u128::MAX` increasing,
        // or `0` decreasing).
        let remaining = match direction {
            SecretDirection::Increasing => u128::MAX - batch_start,
            SecretDirection::Decreasing => batch_start,
        };
        let count = if remaining >= batch_size as u128 - 1 {
            batch_size
        } else {
            (remaining + 1) as u64
        };

        next = match direction {
            SecretDirection::Increasing => batch_start.checked_add(count as u128),
            SecretDirection::Decreasing => {
                let lowest = batch_start - (count as u128 - 1);
                lowest.checked_sub(1)
            }
        };

        Some(SecretBatch {
            base: batch_start,
            count,
            direction,
        })
    })
}

pub fn expand_secret_batch(batch: &SecretBatch) -> impl Iterator<Item = String> + '_ {
    (0..batch.count).map(move |offset| {
        let value = match batch.direction {
            SecretDirection::Increasing => batch.base + offset as u128,
            SecretDirection::Decreasing => batch.base - offset as u128,
        };
        format!("{:032x}", value)
    })
}

pub fn wordlist(path: PathBuf) -> impl Iterator<Item = String> {
    let file = File::open(&path)
        .unwrap_or_else(|error| panic!("Failed to open wordlist file {}: {error}", path.display()));

    read_words(BufReader::new(file))
}

pub fn stdin_word_chunks() -> impl Iterator<Item = Vec<u8>> {
    read_chunks(std::io::stdin())
}

/// Chunked counterpart of [`wordlist`]; see [`stdin_word_chunks`].
pub fn wordlist_chunks(path: PathBuf) -> impl Iterator<Item = Vec<u8>> {
    let file = File::open(&path)
        .unwrap_or_else(|error| panic!("Failed to open wordlist file {}: {error}", path.display()));

    read_chunks(file)
}

pub fn split_words(chunk: &[u8]) -> impl Iterator<Item = String> + '_ {
    let chunk = match chunk.last() {
        Some(b'\n') => &chunk[..chunk.len() - 1],
        _ => chunk,
    };

    chunk
        .split(|&b| b == b'\n')
        .filter(|line| line.len() <= MAX_WORD_LENGTH)
        .map(|line| String::from_utf8_lossy(line).into_owned())
}

fn read_chunks<R: Read>(mut reader: R) -> impl Iterator<Item = Vec<u8>> {
    let mut read_buf = vec![0u8; CHUNK_BYTES];
    let mut carry: Vec<u8> = Vec::new();

    std::iter::from_fn(move || {
        loop {
            let read = reader.read(&mut read_buf).ok()?;

            if read == 0 {
                // EOF: hand back whatever partial line is left, if any.
                return (!carry.is_empty()).then(|| std::mem::take(&mut carry));
            }

            carry.extend_from_slice(&read_buf[..read]);

            let Some(last_newline) = carry.iter().rposition(|&b| b == b'\n') else {
                continue; // no complete line yet - keep accumulating
            };

            let remainder = carry.split_off(last_newline + 1);

            return Some(std::mem::replace(&mut carry, remainder));
        }
    })
}

fn read_words<R: BufRead>(mut reader: R) -> impl Iterator<Item = String> {
    let mut line_buffer = Vec::with_capacity(64);

    std::iter::from_fn(move || {
        loop {
            line_buffer.clear();

            let bytes_read = reader.read_until(b'\n', &mut line_buffer).ok()?;

            // end of stream
            if bytes_read == 0 {
                return None;
            }

            let mut line: &[u8] = &line_buffer;

            if line.last() == Some(&b'\n') {
                line = &line[..line.len() - 1];
            }

            if line.len() > MAX_WORD_LENGTH {
                continue;
            }

            return Some(String::from_utf8_lossy(line).into_owned());
        }
    })
}
