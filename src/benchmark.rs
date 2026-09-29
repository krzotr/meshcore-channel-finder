// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 krzotr <https://github.com/krzotr/meshcore-channel-finder>

use crate::combos::combos;
use crate::crypto::{Payload, PayloadBucket, Secret};
use crate::meshcore_channel::Channel;
use crate::meshcore_group_text::decrypt_group_text_message;
use crate::meshcore_group_text_opt::{
    CipherBlock, any_first_block_looks_like_header,
    decrypt_group_text_message as decrypt_group_text_message_opt,
};
use rayon::prelude::*;
use std::collections::HashMap;
use std::sync::RwLock;
use std::time::Instant;

/// Payloads to decrypt against: every possible channel-hash byte, each bucket
/// holding the mean payload count the runs show (`packets.json` after its
/// known-channel pass is 107 706 payloads over 256 hashes).
const TEST_BUCKETS: usize = 256;
const TEST_PAYLOADS_PER_BUCKET: usize = 420;

/// How many candidates between the running speed lines of a `-t 1` benchmark.
const PRINT_EVERY: u64 = 200_000;

/// Deterministic xorshift64*, so the synthetic payloads are identical from run
/// to run and two builds can be A/B'd - without pulling in `rand`.
struct Rng(u64);

impl Rng {
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn fill(&mut self, buffer: &mut [u8]) {
        for chunk in buffer.chunks_mut(8) {
            let bytes = self.next_u64().to_le_bytes();
            let chunk_len = chunk.len();
            chunk.copy_from_slice(&bytes[..chunk_len]);
        }
    }
}

/// One bucket per channel-hash byte, each filled with random payloads. 18 bytes
/// is the shortest payload the parser accepts, and the first-block pass only
/// ever reads the first 16 of them.
fn synthetic_buckets() -> HashMap<u8, RwLock<PayloadBucket>> {
    let mut rng = Rng(0x5EED_1234_ABCD_9876);
    let mut packets = HashMap::with_capacity(TEST_BUCKETS);

    for channel_hash in 0..=u8::MAX {
        let mut payloads = Vec::with_capacity(TEST_PAYLOADS_PER_BUCKET);

        for _ in 0..TEST_PAYLOADS_PER_BUCKET {
            let mut raw = [0u8; 18];
            rng.fill(&mut raw);

            if let Ok(payload) = Payload::new(&raw) {
                payloads.push(payload);
            }
        }

        packets.insert(channel_hash, RwLock::new(PayloadBucket::new(payloads)));
    }

    packets
}

/// The decrypting work `find()` does per candidate, in the unit the run prints
/// as `decrypt attempts`: one payload tried, i.e. one 16-byte first-block
/// decryption. The candidate path is the run's - channel name to secret and
/// hash, bucket lookup under the read lock - so a `-t 1` run's `words:` and
/// `decrypt attempts:` m/s figures should match this. Nothing ever matches, so
/// payloads are never pruned and buckets stay at full size: the worst case,
/// which is what a run's first `Stats:` line shows. Bucket sizes are uniform
/// here, where the real files are skewed.
///
/// `num_threads` runs the same candidates over the same buckets on that many
/// worker threads, with no reader thread, no stdin and no batch channel in
/// between. That is the control for a run that does not speed up with `-t`: if
/// the figures here scale with the thread count, the ceiling is in the input
/// pipeline, and if they do not, it is this data shape on this machine.
pub fn benchmark_find_decrypt(num_threads: usize) {
    const WORDS: u64 = 1_000_000;

    println!(
        "Benchmarking, speed of the find() decrypt path ({} thread(s))",
        num_threads
    );

    // Built before the clock starts - only the search over them is measured.
    let packets = synthetic_buckets();

    let test_charset: Vec<char> = "abcdefghijklmnopqrstuvwxyz0123456789".chars().collect();

    let start = Instant::now();

    let (words_checked, decrypt_attempts) = if num_threads <= 1 {
        scan_word_range(0, WORDS, &test_charset, &packets, Some(&start))
    } else {
        let per_worker = WORDS.div_ceil(num_threads as u64);

        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(num_threads)
            .build()
            .expect("Failed to create rayon thread pool");

        pool.install(|| {
            (0..num_threads as u64)
                .into_par_iter()
                .map(|worker| {
                    let from = worker * per_worker;
                    let count = per_worker.min(WORDS.saturating_sub(from));

                    scan_word_range(from, count, &test_charset, &packets, None)
                })
                .reduce(|| (0, 0), |a, b| (a.0 + b.0, a.1 + b.1))
        })
    };

    let elapsed = start.elapsed().as_secs_f64();

    println!(
        "  Summary: words checked: {} ({:.2} m/s), decrypt attempts: {} ({:.2} m/s), {:.1} payloads per word",
        words_checked,
        words_checked as f64 / elapsed / 1_000_000f64,
        decrypt_attempts,
        decrypt_attempts as f64 / elapsed / 1_000_000f64,
        decrypt_attempts as f64 / words_checked.max(1) as f64,
    );
}

/// The word `combos(6, 6, charset)` yields at `index`, built on demand so the
/// `-t N` workers can each walk a slice of the keyspace without the benchmark
/// materialising a million words first.
fn word_at(index: u64, charset: &[char]) -> String {
    let radix = charset.len() as u64;
    let mut index = index;
    let mut buffer = [' '; 6];

    for position in (0..6).rev() {
        buffer[position] = charset[(index % radix) as usize];
        index /= radix;
    }

    buffer.iter().collect()
}

/// `count` candidates starting at `from`, shared by the single- and
/// multi-threaded benchmark. `progress` is passed only by the single-threaded
/// caller: with several workers the speed lines would interleave.
fn scan_word_range(
    from: u64,
    count: u64,
    charset: &[char],
    packets: &HashMap<u8, RwLock<PayloadBucket>>,
    progress: Option<&Instant>,
) -> (u64, u64) {
    let mut words_checked: u64 = 0;
    let mut decrypt_attempts: u64 = 0;

    // Reused across every candidate, exactly as `process_word_batch` does.
    let mut first_block_scratch: Vec<CipherBlock> = Vec::new();

    for index in from..from + count {
        let channel_name = word_at(index, charset);

        words_checked += 1;

        // Printed before this candidate is tried, so a candidate that skips the
        // prefilter cannot swallow a checkpoint.
        if let Some(start) = progress {
            if words_checked % PRINT_EVERY == 0 {
                print_find_speed(start, words_checked, decrypt_attempts);
            }
        }

        let (channel_secret, channel_hash) =
            Channel::get_secret_and_hash_by_channel_name(&channel_name);

        // The channel hash byte decides whether this candidate is worth
        // decrypting anything at all for.
        let Some(bucket) = packets.get(&channel_hash) else {
            continue;
        };

        let secret = Secret::new(channel_secret);

        let bucket = bucket.read().unwrap();

        if bucket.is_empty() {
            continue;
        }

        decrypt_attempts += bucket.len() as u64;

        // Rule the whole bucket out using only each payload's first 16 bytes.
        // The verdict is deliberately discarded: this benchmark measures the
        // scan itself, so every candidate pays for its whole bucket.
        any_first_block_looks_like_header(
            &bucket.first_blocks,
            secret.get_cipher(),
            &mut first_block_scratch,
        );
    }

    (words_checked, decrypt_attempts)
}

/// Running figures in the units `find()` reports: candidates per second, and
/// payloads tried per second.
fn print_find_speed(start: &Instant, words_checked: u64, decrypt_attempts: u64) {
    let elapsed = start.elapsed().as_secs_f64();

    println!(
        "  Speed: words: {:.2} m/s, decrypt attempts: {:.2} m/s ({:.1} payloads per word)",
        words_checked as f64 / elapsed / 1_000_000f64,
        decrypt_attempts as f64 / elapsed / 1_000_000f64,
        decrypt_attempts as f64 / words_checked as f64,
    );
}

#[allow(dead_code)]
pub fn benchmark_words() {
    println!("Benchmarking, speed of generating words");

    let test_charset: Vec<char> = "abcdefghijklmnopqrstuvwxyz0123456789".chars().collect();

    let mut count = 0;
    let start = Instant::now();
    for _ in combos(5, 5, test_charset) {
        count += 1;

        if count % 20_000_000 == 0 {
            let speed = (count as f64 / start.elapsed().as_secs_f64()) / 1_000_000f64;

            println!("  Speed: {:.1} m/s", speed);
        }
    }
}

#[allow(dead_code)]
pub fn benchmark_channel_secret() {
    println!("Benchmarking, speed of generating channel secrets");

    let start = Instant::now();
    for count in 0u64..30_000_001u64 {
        let _channel = Channel::get_from_channel_name(count.to_string());

        if count > 0 && count % 10_000_000 == 0 {
            let speed = (count as f64 / start.elapsed().as_secs_f64()) / 1_000_000f64;

            println!("  Speed: {:.1} m/s", speed);
        }
    }
}

#[allow(dead_code)]
pub fn benchmark_decrypt_group_text_message() {
    println!("Benchmarking, speed of decrypt_group_text_message");

    let start = Instant::now();

    let encrypted_data_hex = "F968645CC670B4FAA52596F9D61A74EDFCBF9F582348277055799612F79FA8B056BE8F080B892FEE4EC1503D6CCA47FAC104069DDB8B50FC66DC4193B68A372F892EB008AF1DBD03537EF5672061141BDE9B8F47CE032DA4E6885D2BE3A7E61EF45C6C89B372F49FFA127AB246A472195E45";

    let encrypted_data = hex::decode(encrypted_data_hex).expect("invalid hex");

    let payload = Payload::new(&encrypted_data).ok().unwrap();

    for count in 0u128..45_000_001u128 {
        let secret = Secret::new(count.to_be_bytes());

        match decrypt_group_text_message(&payload, &secret) {
            Ok(_) => {}
            Err(_) => {}
        }

        if count > 0 && count % 15_000_000 == 0 {
            let speed = (count as f64 / start.elapsed().as_secs_f64()) / 1_000_000f64;

            println!("  Speed: {:.1} m/s", speed);
        }
    }
}

#[allow(dead_code)]
pub fn benchmark_decrypt_group_text_message_opt() {
    println!("Benchmarking, speed of decrypt_group_text_message opt");

    let start = Instant::now();

    let encrypted_data_hex = "F968645CC670B4FAA52596F9D61A74EDFCBF9F582348277055799612F79FA8B056BE8F080B892FEE4EC1503D6CCA47FAC104069DDB8B50FC66DC4193B68A372F892EB008AF1DBD03537EF5672061141BDE9B8F47CE032DA4E6885D2BE3A7E61EF45C6C89B372F49FFA127AB246A472195E45";

    let encrypted_data = hex::decode(encrypted_data_hex).expect("invalid hex");

    let payload = Payload::new(&encrypted_data).ok().unwrap();

    for count in 0u128..45_000_001u128 {
        let secret = Secret::new(count.to_be_bytes());

        match decrypt_group_text_message_opt(&payload, &secret) {
            Ok(_) => {}
            Err(_) => {}
        }

        if count > 0 && count % 15_000_000 == 0 {
            let speed = (count as f64 / start.elapsed().as_secs_f64()) / 1_000_000f64;

            println!("  Speed: {:.1} m/s", speed);
        }
    }
}

pub fn benchmark(num_threads: usize) {
    benchmark_find_decrypt(num_threads);
    benchmark_words();
    benchmark_channel_secret();
    benchmark_decrypt_group_text_message();
    benchmark_decrypt_group_text_message_opt();
}
