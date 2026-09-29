// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 krzotr <https://github.com/krzotr/meshcore-channel-finder>

mod benchmark;
mod combos;
mod crypto;
mod meshcore_channel;
mod meshcore_group_text;
mod meshcore_group_text_opt;
mod meshcore_packet;
mod packet_loader;

use std::collections::{BTreeSet, HashMap, HashSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, SyncSender};
use std::sync::{Arc, Condvar, Mutex, RwLock};

use std::time::{Duration, Instant};
use std::{env, thread};

use argparse_rs::{ArgParser, ArgType};

use crate::combos::{
    ComboBatch, SecretBatch, SecretDirection, combo_batches, expand_combo_batch,
    expand_secret_batch, secret_batches, split_words, stdin_word_chunks, wordlist, wordlist_chunks,
};
use crate::crypto::{Payload, PayloadBucket, Secret};
use crate::meshcore_channel::Channel;

use crate::meshcore_group_text::MeshcoreGroupMessage;
use crate::meshcore_group_text_opt::{
    CipherBlock, any_first_block_looks_like_header, decrypt_group_text_message,
};

use crate::packet_loader::load_packets_from_json;

use crate::benchmark::benchmark;

use std::process::exit;

use num_format::{Locale, ToFormattedString};

const WORDS_PER_BATCH: usize = 1_024 * 64 * 2;

const QUEUED_BATCH_LIMIT: usize = 12;

const DEFAULT_STATS_PRINT_INTERVAL_SECS: u64 = 60;

#[derive(Clone, Copy)]
struct Config {
    num_threads: usize,
    /// Candidates are literal channel names (`true`) or hex secrets (`false`).
    use_channel_names: bool,
    show_decoded_messages: bool,
    stats_interval: Duration,
}

impl Config {
    fn with_decoded_messages(self, show_decoded_messages: bool) -> Self {
        Self {
            show_decoded_messages,
            ..self
        }
    }
    /// This configuration, with candidates read as channel names or as hex.
    fn with_channel_names(self, use_channel_names: bool) -> Self {
        Self {
            use_channel_names,
            ..self
        }
    }
}

#[derive(Default)]
struct FoundChannels {
    reported_labels: HashSet<String>,
}

struct Progress {
    words_checked: AtomicU64,
    decrypt_attempts: AtomicU64,
    channels_found_live: AtomicU64,
    payloads_left: AtomicU64,
    channel_hashes_left: AtomicU64,
    /// Start of every secret batch a worker is currently chewing through,
    /// during a `bruteforce-secret` run. Combined with `secret_direction`,
    /// the far edge of this set is the first secret not yet fully
    /// processed - i.e. where a resumed run should start from. Unused (and
    /// left empty) by every other command.
    in_flight_secret_starts: Mutex<BTreeSet<u128>>,
    /// Set from the first secret batch a worker processes; read by the
    /// stats printer to know whether the resume point is the lowest or the
    /// highest in-flight start (see `in_flight_secret_starts`).
    secret_direction: Mutex<Option<SecretDirection>>,
}

impl Progress {
    fn new(total_payloads: usize, total_channel_hashes: usize) -> Self {
        Self {
            words_checked: AtomicU64::new(0),
            decrypt_attempts: AtomicU64::new(0),
            channels_found_live: AtomicU64::new(0),
            payloads_left: AtomicU64::new(total_payloads as u64),
            channel_hashes_left: AtomicU64::new(total_channel_hashes as u64),
            in_flight_secret_starts: Mutex::new(BTreeSet::new()),
            secret_direction: Mutex::new(None),
        }
    }
}

fn remaining_payload_count(packets: &HashMap<u8, RwLock<PayloadBucket>>) -> usize {
    packets
        .values()
        .map(|bucket| bucket.read().unwrap().len())
        .sum()
}

fn populated_channel_hash_count(packets: &HashMap<u8, RwLock<PayloadBucket>>) -> usize {
    packets
        .values()
        .filter(|bucket| !bucket.read().unwrap().is_empty())
        .count()
}

fn find<I, B, P>(
    config: &Config,
    raw_packets: &HashMap<u8, RwLock<PayloadBucket>>,
    batch_source: I,
    process_batch: P,
) where
    I: Iterator<Item = B> + Send + 'static,
    B: Send + 'static,
    P: Fn(B, &HashMap<u8, RwLock<PayloadBucket>>, &Config, &Mutex<FoundChannels>, &Progress) + Sync,
{
    let start = Instant::now();

    let found_channels: Mutex<FoundChannels> = Mutex::new(FoundChannels::default());
    let finish_signal = Arc::new((Mutex::new(false), Condvar::new()));

    let total_payloads: usize = remaining_payload_count(raw_packets);
    let total_channel_hashes: usize = populated_channel_hash_count(raw_packets);

    let progress = Arc::new(Progress::new(total_payloads, total_channel_hashes));

    let stats_thread = spawn_stats_printer(
        Arc::clone(&progress),
        Arc::clone(&finish_signal),
        total_payloads,
        total_channel_hashes,
        config.stats_interval,
    );

    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(config.num_threads)
        .build()
        .expect("Failed to create rayon thread pool");

    let worker_count = pool.current_num_threads().max(1);

    let (batch_sender, batch_receiver) = mpsc::sync_channel::<B>(QUEUED_BATCH_LIMIT);
    let batch_receiver = Mutex::new(batch_receiver);
    let reader_thread = thread::spawn(move || stream_batches(batch_source, batch_sender));

    let packets_ref = raw_packets;
    let found_channels_ref = &found_channels;
    let progress_ref = &*progress;

    pool.scope(|scope| {
        for _ in 0..worker_count {
            scope.spawn(|_| {
                loop {
                    let Ok(batch) = batch_receiver.lock().unwrap().recv() else {
                        return; // reader is done, nothing left to take
                    };

                    process_batch(batch, packets_ref, config, found_channels_ref, progress_ref);
                }
            });
        }
    });

    reader_thread
        .join()
        .expect("wordlist reader thread panicked");

    {
        let (lock, cvar) = &*finish_signal;
        let mut done = lock.lock().unwrap();
        *done = true;
        cvar.notify_all();
    }
    let _ = stats_thread.join();

    let total_words = progress.words_checked.load(Ordering::Relaxed);
    let total_decrypts = progress.decrypt_attempts.load(Ordering::Relaxed);

    let found_channels = found_channels.into_inner().unwrap();
    let found_channels_count = found_channels.reported_labels.len();

    let elapsed = start.elapsed();
    let word_speed = if elapsed.as_secs_f64() > 0.0 {
        total_words as f64 / elapsed.as_secs_f64() / 1_000_000f64
    } else {
        0.0
    };
    let decrypt_speed = if elapsed.as_secs_f64() > 0.0 {
        total_decrypts as f64 / elapsed.as_secs_f64() / 1_000_000f64
    } else {
        0.0
    };
    let remaining_payloads = remaining_payload_count(raw_packets);

    println!(
        "Summary: words checked: {} ({:.2} m/s), decrypt attempts: {} ({:.2} m/s), remaining: {}/{} payloads, found: {} channels",
        total_words,
        word_speed,
        total_decrypts,
        decrypt_speed,
        remaining_payloads,
        populated_channel_hash_count(raw_packets),
        found_channels_count
    );
}

fn stream_batches<B, I: Iterator<Item = B>>(mut batch_source: I, batch_sender: SyncSender<B>) {
    while let Some(batch) = batch_source.next() {
        if batch_sender.send(batch).is_err() {
            return; // workers are gone
        }
    }
}

fn batched<I: Iterator<Item = String>>(
    mut source: I,
    batch_size: usize,
) -> impl Iterator<Item = Vec<String>> {
    std::iter::from_fn(move || {
        let mut batch = Vec::with_capacity(batch_size);
        for _ in 0..batch_size {
            match source.next() {
                Some(word) => batch.push(word),
                None => break,
            }
        }

        (!batch.is_empty()).then_some(batch)
    })
}

fn process_word_batch(
    batch: Vec<String>,
    packets: &HashMap<u8, RwLock<PayloadBucket>>,
    config: &Config,
    found_channels: &Mutex<FoundChannels>,
    progress: &Progress,
) {
    process_candidates(batch.into_iter(), packets, config, found_channels, progress);
}

/// Expands a slice of the bruteforce keyspace into candidate strings on the
/// worker that drew it, rather than on the single reader thread - see
/// [`combos::combo_batches`].
fn process_combo_batch(
    batch: ComboBatch,
    packets: &HashMap<u8, RwLock<PayloadBucket>>,
    config: &Config,
    found_channels: &Mutex<FoundChannels>,
    progress: &Progress,
) {
    process_candidates(
        expand_combo_batch(&batch),
        packets,
        config,
        found_channels,
        progress,
    );
}

/// Expands a slice of the 16-byte secret keyspace into candidate hex
/// strings on the worker that drew it - see [`combos::secret_batches`].
///
/// Tracks the batch's start in `progress.in_flight_secret_starts` for the
/// duration of the work, so the stats printer can report the lowest secret
/// not yet fully processed as a resume point.
fn process_secret_batch(
    batch: SecretBatch,
    packets: &HashMap<u8, RwLock<PayloadBucket>>,
    config: &Config,
    found_channels: &Mutex<FoundChannels>,
    progress: &Progress,
) {
    let start = batch.start();

    {
        let mut direction = progress.secret_direction.lock().unwrap();
        if direction.is_none() {
            *direction = Some(batch.direction());
        }
    }

    progress
        .in_flight_secret_starts
        .lock()
        .unwrap()
        .insert(start);

    process_candidates(
        expand_secret_batch(&batch),
        packets,
        config,
        found_channels,
        progress,
    );

    progress
        .in_flight_secret_starts
        .lock()
        .unwrap()
        .remove(&start);
}

fn process_raw_chunk(
    chunk: Vec<u8>,
    packets: &HashMap<u8, RwLock<PayloadBucket>>,
    config: &Config,
    found_channels: &Mutex<FoundChannels>,
    progress: &Progress,
) {
    process_candidates(
        split_words(&chunk),
        packets,
        config,
        found_channels,
        progress,
    );
}

fn process_candidates(
    candidates: impl Iterator<Item = String>,
    packets: &HashMap<u8, RwLock<PayloadBucket>>,
    config: &Config,
    found_channels: &Mutex<FoundChannels>,
    progress: &Progress,
) {
    let mut words_in_batch: u64 = 0;
    let mut decrypts_in_batch: u64 = 0;

    // Reused across every candidate in the batch, so the block batch handed to
    // the AES backend is allocated once rather than once per candidate.
    let mut first_block_scratch: Vec<CipherBlock> = Vec::new();

    for candidate in candidates {
        words_in_batch += 1;

        // A candidate is either a literal channel name, which is hashed into a
        // secret, or an already known secret given as hex.
        let (channel_secret, channel_hash, label) = if config.use_channel_names {
            let (secret, hash) = Channel::get_secret_and_hash_by_channel_name(&candidate);

            (secret, hash, candidate)
        } else {
            let Ok(secret_bytes) = hex::decode(&candidate) else {
                continue; // not a hex secret, nothing we can try
            };
            let Ok(channel_secret) = <[u8; 16]>::try_from(secret_bytes.as_slice()) else {
                continue; // wrong secret length
            };

            (
                channel_secret,
                Channel::get_hash_by_channel_secret(channel_secret),
                candidate,
            )
        };

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

        decrypts_in_batch += bucket.len() as u64;

        // Rule the whole bucket out using only each payload's first 16 bytes.
        // This is the overwhelmingly common outcome: a wrong candidate has to
        // be rejected against every payload, and almost never survives this.
        if !any_first_block_looks_like_header(
            &bucket.first_blocks,
            secret.get_cipher(),
            &mut first_block_scratch,
        ) {
            continue;
        }

        // Something in the bucket looks promising, so pay for the full decrypt
        // of every payload - this is where the message body and HMAC are handled.
        let mut matched_payloads: HashSet<Payload> = HashSet::new();
        let mut decoded_messages: Vec<MeshcoreGroupMessage> = Vec::new();

        for payload in bucket.payloads.iter() {
            if let Ok(decoded) = decrypt_group_text_message(payload, &secret) {
                matched_payloads.insert(payload.clone());
                decoded_messages.push(decoded);
            }
        }

        // The read guard has to go before the write lock below.
        drop(bucket);

        if !matched_payloads.is_empty() {
            if let Some(bucket) = packets.get(&channel_hash) {
                let mut bucket = bucket.write().unwrap();
                let removed = bucket.retain_payloads(&matched_payloads);

                if removed > 0 {
                    progress
                        .payloads_left
                        .fetch_sub(removed as u64, Ordering::Relaxed);

                    if bucket.is_empty() {
                        progress.channel_hashes_left.fetch_sub(1, Ordering::Relaxed);
                    }
                }
            }

            let mut found = found_channels.lock().unwrap();

            if found.reported_labels.insert(label.clone()) {
                progress.channels_found_live.fetch_add(1, Ordering::Relaxed);

                if config.use_channel_names {
                    println!(
                        "       Success: secret: {} channel: #{}",
                        hex::encode(channel_secret),
                        label
                    );
                } else {
                    println!("       Success: secret: {}", hex::encode(channel_secret));
                }

                // Printed here rather than deferred to the end of `find()`,
                // since a bruteforce run may never reach the end of its
                // keyspace within the process's lifetime.
                if config.show_decoded_messages {
                    for decoded_message in &decoded_messages {
                        // In secret-finding mode `label` is just the hex
                        // secret again, so naming it a second time as the
                        // "channel" adds nothing.
                        if config.use_channel_names {
                            println!(
                                "Secret: {}, Channel: #{}, {:?}",
                                hex::encode(channel_secret),
                                label,
                                decoded_message
                            );
                        } else {
                            println!(
                                "Secret: {}, {:?}",
                                hex::encode(channel_secret),
                                decoded_message
                            );
                        }
                    }
                }
            }
        }
    }

    publish_progress(&progress.words_checked, words_in_batch);
    publish_progress(&progress.decrypt_attempts, decrypts_in_batch);
}

#[inline]
fn publish_progress(counter: &AtomicU64, amount: u64) {
    if amount > 0 {
        counter.fetch_add(amount, Ordering::Relaxed);
    }
}

/// Background thread printing throughput while the search runs.
fn spawn_stats_printer(
    progress: Arc<Progress>,
    finish_signal: Arc<(Mutex<bool>, Condvar)>,
    total_payloads: usize,
    total_channel_hashes: usize,
    stats_interval: Duration,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let (lock, cvar) = &*finish_signal;
        let mut finished = lock.lock().unwrap();

        let mut last_print = Instant::now();
        let mut last_words: u64 = 0;
        let mut last_decrypts: u64 = 0;

        while !*finished {
            let wait_for = stats_interval.saturating_sub(last_print.elapsed());
            let (guard, _timeout) = cvar.wait_timeout(finished, wait_for).unwrap();
            finished = guard;

            if *finished {
                break;
            }

            if last_print.elapsed() < stats_interval {
                continue;
            }

            let interval = last_print.elapsed();
            last_print = Instant::now();

            let words = progress.words_checked.load(Ordering::Relaxed);
            let decrypts = progress.decrypt_attempts.load(Ordering::Relaxed);
            let found = progress.channels_found_live.load(Ordering::Relaxed);
            let words_since_last = words - last_words;
            let decrypts_since_last = decrypts - last_decrypts;
            last_words = words;
            last_decrypts = decrypts;

            if interval.as_secs() == 0 {
                continue;
            }

            let word_speed = words_since_last as f64 / interval.as_secs_f64() / 1_000_000f64;
            let decrypt_speed = decrypts_since_last as f64 / interval.as_secs_f64() / 1_000_000f64;

            // Live figures, shown against the starting totals so the drop is
            // visible: payloads leave their bucket the moment a candidate
            // matches them.
            let payloads_remaining = progress.payloads_left.load(Ordering::Relaxed);
            let hashes_remaining = progress.channel_hashes_left.load(Ordering::Relaxed);

            // Only populated during `bruteforce-secret`. Work advances
            // towards `u128::MAX` when increasing or towards `0` when
            // decreasing, so the resume point is the far edge of the
            // in-flight set in that direction - the lowest entry when
            // increasing, the highest when decreasing.
            let resume_secret = {
                let in_flight = progress.in_flight_secret_starts.lock().unwrap();
                match *progress.secret_direction.lock().unwrap() {
                    Some(SecretDirection::Decreasing) => in_flight.iter().next_back().copied(),
                    _ => in_flight.iter().next().copied(),
                }
            };
            let resume_suffix = match resume_secret {
                Some(secret) => format!(", current secret: {:032x}", secret),
                None => String::new(),
            };

            println!(
                "Stats: words: {:.2}m/s ({}), decrypt attempts: {:.2}m/s ({}), payloads: {}/{}, channel hashes: {}/{}, found: {} channels{}",
                word_speed,
                words,
                decrypt_speed,
                decrypts,
                payloads_remaining,
                total_payloads,
                hashes_remaining,
                total_channel_hashes,
                found,
                resume_suffix
            );
        }
    })
}

fn print_header() {
    println!("MeshCore Channel Finder {}", env!("CARGO_PKG_VERSION"));
    println!();
}

fn print_usage() {
    print_header();
    println!("Usage: [--threads N] [--skip-known-channels] <packets.json> <command> [args...]");
    println!("       [--threads N] benchmark");
    println!();

    println!("Options:");
    println!("  -s,   --skip-known-channels           Disable loading predefined channels file");
    println!("  -t N, --threads N                     Set number of threads");
    println!("  -d,   --show-decoded-messages         Print decoded messages for found channels");
    println!(
        "  -i S, --interval S                    Seconds between stats printouts (default: {})",
        DEFAULT_STATS_PRINT_INTERVAL_SECS
    );
    println!();
    println!("Commands:");
    println!("  benchmark                             Run the benchmark (needs no packets file)");
    println!();
    println!("  wordlist");
    println!("    stdin                               Read channel names from stdin");
    println!("    wordlist FILE [FILE...]             Try one or more wordlist files");
    println!("    bruteforce MIN MAX CHARSET          Brute-force combos of CHARSET (plus '-')");
    println!();
    println!("  secrets:");
    println!("    stdin-secret                        Read 32 hex long secrets from stdin");
    println!("    bruteforce-secret START [low|high]  Brute-force 32 hex secrets from START");
    println!("                                        counting down (low) or up (high, default)");
    println!("    example:");
    println!("      bruteforce-secret 00000000000000000000000000000000 high");
    println!("      bruteforce-secret ffffffffffffffffffffffffffffffff low");
    println!();
}

fn arguments_parser() {
    let raw_args: Vec<String> = env::args().collect();

    let mut parser = ArgParser::new("meshcore-cracker".into());
    parser.add_opt(
        "threads",
        None,
        't',
        false,
        "Number of worker threads (default: RAYON_NUM_THREADS env var, or CPU count)",
        ArgType::Option,
    );
    parser.add_opt(
        "interval",
        None,
        'i',
        false,
        "Seconds between stats printouts (default: 60)",
        ArgType::Option,
    );
    parser.add_opt(
        "skip-known-channels",
        Some("false"),
        's',
        false,
        "Skip the built-in known_channels.txt and stdin wordlist checks that normally run first",
        ArgType::Flag,
    );
    parser.add_opt(
        "show-decoded-messages",
        Some("false"),
        'd',
        false,
        "Print decoded messages for found channels (default: false)",
        ArgType::Flag,
    );
    parser.add_opt(
        "packets_file",
        None,
        'p',
        false,
        "Path to the packets.json file",
        ArgType::Positional(0),
    );
    parser.add_opt(
        "command",
        None,
        'c',
        false,
        "Subcommand: benchmark | stdin | wordlist FILE... | bruteforce MIN MAX CHARSET",
        ArgType::Positional(1),
    );

    let parsed = match parser.parse(raw_args.iter()) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Argument error: {e}");
            print_usage();
            exit(1);
        }
    };

    let num_threads: usize = parsed
        .get::<usize>("threads")
        .or_else(|| {
            env::var("RAYON_NUM_THREADS")
                .ok()
                .and_then(|s| s.parse().ok())
        })
        .unwrap_or_else(|| {
            std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(1)
        });

    let mut packets_file: Option<String> = parsed.get::<String>("packets_file");
    let mut command: Option<String> = parsed.get::<String>("command");

    if command.is_none() {
        command = packets_file.take();
    }

    let command: String = match command {
        Some(c) => c,
        None => {
            eprintln!("No command given.");
            print_usage();
            exit(1);
        }
    };

    if command == "benchmark" {
        benchmark(num_threads);
        exit(0);
    }

    let packets_file: String = match packets_file {
        Some(p) => p,
        None => {
            eprintln!("No packets file given.");
            print_usage();
            exit(1);
        }
    };

    let skip_known_channels: bool = parsed.get::<bool>("skip-known-channels").unwrap_or(false);
    let show_decoded_messages: bool = parsed.get::<bool>("show-decoded-messages").unwrap_or(false);
    let stats_interval = Duration::from_secs(
        parsed
            .get::<u64>("interval")
            .unwrap_or(DEFAULT_STATS_PRINT_INTERVAL_SECS),
    );

    let config = Config {
        num_threads,
        use_channel_names: true,
        show_decoded_messages,
        stats_interval,
    };

    let mut extra_args: Vec<String> = Vec::new();
    let mut command_seen = false;
    let mut packets_file_seen = false;
    let mut iter = raw_args.iter().skip(1);
    while let Some(a) = iter.next() {
        if a == "--threads" || a == "-t" {
            iter.next();
        } else if a == "--interval" || a == "-i" {
            iter.next();
        } else if a == "--skip-known-channels" || a == "-s" {
            // flag, no value follows
        } else if a == "--show-decoded-messages" || a == "-d" {
            // flag, no value follows
        } else if !packets_file_seen && a == &packets_file {
            packets_file_seen = true;
        } else if !command_seen && a == &command {
            command_seen = true;
        } else {
            extra_args.push(a.clone());
        }
    }

    if !matches!(
        command.as_str(),
        "stdin" | "stdin-secret" | "wordlist" | "bruteforce" | "bruteforce-secret"
    ) {
        println!("Unknown command: {command}\n");
        print_usage();
        exit(1);
    }

    println!("Loading packets file");
    let raw_packets = load_packets_from_json(&packets_file).ok().unwrap();

    if !skip_known_channels {
        let known_channels_config = config.with_decoded_messages(false);

        println!("Checking known channels secrets from known_channels_secrets.txt");
        find(
            &known_channels_config.with_channel_names(false),
            &raw_packets,
            batched(
                wordlist("known_channels_secrets.txt".into()),
                WORDS_PER_BATCH,
            ),
            process_word_batch,
        );

        println!("Checking known channels from known_channels.txt");
        find(
            &known_channels_config,
            &raw_packets,
            batched(wordlist("known_channels.txt".into()), WORDS_PER_BATCH),
            process_word_batch,
        );
    }

    match command.as_str() {
        "stdin" => {
            println!("Using words from stdin");
            find(
                &config,
                &raw_packets,
                stdin_word_chunks(),
                process_raw_chunk,
            );
        }
        "stdin-secret" => {
            println!("Using hex secrets from stdin");
            find(
                &config.with_channel_names(false),
                &raw_packets,
                stdin_word_chunks(),
                process_raw_chunk,
            );
        }
        "wordlist" => {
            if extra_args.is_empty() {
                println!("wordlist requires at least one file argument\n");
                print_usage();
                exit(1);
            }

            println!("Using wordlist file");

            for file in &extra_args {
                println!("  Checking against file: {file}");
                find(
                    &config,
                    &raw_packets,
                    wordlist_chunks(PathBuf::from(file)),
                    process_raw_chunk,
                );
            }
        }
        "bruteforce" => {
            if extra_args.len() != 3 {
                eprintln!("bruteforce requires exactly 3 arguments: min_len max_len charset");
                print_usage();
                exit(1);
            }
            let min_len: usize = extra_args[0].parse().unwrap_or_else(|_| {
                eprintln!("invalid min_len");
                exit(1);
            });
            let max_len: usize = extra_args[1].parse().unwrap_or_else(|_| {
                eprintln!("invalid max_len");
                exit(1);
            });
            let charset: Vec<char> = format!("{}-", extra_args[2]).chars().collect();
            let radix = charset.len() as u64;

            let keyspace = if radix <= 1 {
                0
            } else {
                (radix.pow(max_len as u32 + 1) - radix.pow(min_len as u32)) / (radix - 1)
            };

            println!("Using bruteforce");
            println!("      charset: {}", extra_args[2]);
            println!("  charset len: {}", radix);
            println!("      min len: {}", min_len);
            println!("      max len: {}", max_len);
            println!(
                "     keyspace: {}",
                keyspace.to_formatted_string(&Locale::en)
            );

            find(
                &config,
                &raw_packets,
                combo_batches(min_len, max_len, charset, WORDS_PER_BATCH as u64),
                process_combo_batch,
            );
        }
        "bruteforce-secret" => {
            if extra_args.is_empty() || extra_args.len() > 2 {
                eprintln!(
                    "bruteforce-secret requires 1-2 arguments: start (32 hex chars / 16 bytes) and an optional direction (low|high, default: high)"
                );
                print_usage();
                exit(1);
            }

            let start_bytes: [u8; 16] = hex::decode(&extra_args[0])
                .ok()
                .and_then(|bytes| <[u8; 16]>::try_from(bytes.as_slice()).ok())
                .unwrap_or_else(|| {
                    eprintln!("invalid start secret: must be 32 hex chars (16 bytes)");
                    exit(1);
                });
            let start = u128::from_be_bytes(start_bytes);

            let direction_arg = extra_args.get(1).map(String::as_str).unwrap_or("high");
            let direction = match direction_arg {
                "low" => SecretDirection::Decreasing,
                "high" => SecretDirection::Increasing,
                other => {
                    eprintln!("invalid direction '{other}': must be 'low' or 'high'");
                    print_usage();
                    exit(1);
                }
            };

            println!("Using bruteforce-secret");
            println!("  start secret: {:032x}", start);
            println!("     direction: {}", direction_arg);

            find(
                &config.with_channel_names(false),
                &raw_packets,
                secret_batches(start, direction, WORDS_PER_BATCH as u64),
                process_secret_batch,
            );
        }
        other => {
            println!("Unknown command: {other}\n");
            print_usage();
            exit(1);
        }
    }
}

fn main() {
    arguments_parser();
}
