use std::fs::File;
use std::io::BufReader;
use std::sync::RwLock;
use struson::reader::{JsonReader, JsonStreamReader};

use crate::crypto::{Payload, PayloadBucket};
use crate::meshcore_packet::get_channel_payload_from_raw_packet;
use std::collections::{HashMap, HashSet};

pub fn load_packets_from_json(
    path: &str,
) -> Result<HashMap<u8, RwLock<PayloadBucket>>, Box<dyn std::error::Error>> {
    let file = File::open(path)?;
    let mut reader = JsonStreamReader::new(BufReader::new(file));

    let mut dict: HashMap<u8, HashSet<Payload>> = HashMap::new();

    // Per-channel-hash set of every 16-byte AES-ECB block already accepted.
    let mut seen_blocks: HashMap<u8, HashSet<[u8; 16]>> = HashMap::new();

    let mut total_processed: usize = 0;
    let mut total_duplicated_blocks: usize = 0;

    reader.begin_object()?;

    while reader.has_next()? {
        let name = reader.next_name()?;

        if name == "packets" {
            reader.begin_array()?;

            while reader.has_next()? {
                reader.begin_object()?;

                while reader.has_next()? {
                    let field_name = reader.next_name()?;

                    if field_name == "raw_hex" {
                        let raw_packet_hex: String = reader.next_string()?;

                        let raw_packet = hex::decode(raw_packet_hex).expect("invalid hex");

                        match get_channel_payload_from_raw_packet(raw_packet) {
                            Ok(channel_payload) => {
                                let channel_hash = channel_payload[0];

                                match Payload::new(&channel_payload[1..]) {
                                    Ok(payload) => {
                                        total_processed += 1;

                                        // Split the new payload data into 16-byte AES-ECB
                                        // blocks and check each against every block already
                                        // accepted for this channel hash.
                                        let channel_blocks = seen_blocks
                                            .entry(channel_hash)
                                            .or_insert_with(HashSet::new);

                                        let blocks_dup = payload
                                            .data
                                            .chunks_exact(16)
                                            .any(|b| channel_blocks.contains(b));

                                        if blocks_dup {
                                            total_duplicated_blocks += 1;
                                        } else {
                                            for b in payload.data.chunks_exact(16) {
                                                let mut block = [0u8; 16];
                                                block.copy_from_slice(b);
                                                channel_blocks.insert(block);
                                            }

                                            dict.entry(channel_hash)
                                                .or_insert_with(HashSet::new)
                                                .insert(payload);
                                        }
                                    }
                                    _ => {}
                                }
                            }
                            Err(_) => {}
                        }
                    } else {
                        reader.skip_value()?;
                    }
                }

                reader.end_object()?;
            }

            reader.end_array()?;
        } else {
            reader.skip_value()?;
        }
    }

    // No longer needed once the file is fully loaded; free the block index early.
    seen_blocks.clear();
    seen_blocks.shrink_to_fit();

    let total_in_dict: usize = dict.values().map(|payloads| payloads.len()).sum();

    println!("    Processed payloads: {}", total_processed);
    println!("    Dupes (16B blocks): {}", total_duplicated_blocks);
    println!("   Payloads to process: {}", total_in_dict);

    Ok(dict
        .into_iter()
        .map(|(channel_hash, payloads)| {
            (
                channel_hash,
                RwLock::new(PayloadBucket::new(payloads.into_iter().collect())),
            )
        })
        .collect())
}
