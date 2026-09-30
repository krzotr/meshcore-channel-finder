# Project Overview

**meshcore-channel-finder** is a Rust tool that finds MeshCore channel names and
secrets by brute-forcing candidate secrets against captured network packets.
Given a `packets.json` file containing encrypted MeshCore group text packets, it
tries secrets from wordlists or brute-force combinations, decrypts them, and
checks if they match known channel hashes.

## Quick start

You just need a `packets.json` file from `CoreScope`, e.g. from `/api/packets`.
Just download and play.

```bash
# ./target/release/meshcore-channel-finder -d packets.json bruteforce 1 5 abcdefghijklmnopqrstuvwxyz
```

## Usage

Just run `./target/release/meshcore-channel-finder` with no arguments to print
the usage help.

### Commands

The commands split into two families:

- **channel-name commands** — candidates are literal channel names (`stdin`,
  `wordlist`, `bruteforce`)
- **secret commands** — candidates are already the 16-byte AES key, given as 32
  hex characters (`stdin-secret`, `bruteforce-secret`)

#### Channel-name commands

- `stdin` — Read candidate channel names from stdin (one per line, ≤32 chars,
  taken as is)
- `wordlist FILE [FILE...]` — Try one or more wordlist files of channel names
- `bruteforce MIN MAX CHARSET` — Generate all combos of CHARSET from MIN to MAX
  length.

#### Secret (key) commands

- `stdin-secret` — Read candidate secrets from stdin, one 32-hex-char (16-byte)
  key per line. Lines that are not valid 16-byte hex are skipped
- `bruteforce-secret START [low|high]` — Walk the 128-bit key space one key at a
  time starting from the 32-hex-char `START`, counting **up** towards
  `ffff…ffff` with `high` (the default) or **down** towards `0000…0000` with
  `low`.
  See [Brute-forcing channel secrets (keys)](#brute-forcing-channel-secrets-keys)

#### Other

- `benchmark` — Run internal benchmarks on synthetic payloads (exits
  immediately). The only command that can be run without a packets file: with a
  single positional given it is taken as the command, so
  `meshcore-channel-finder benchmark` works and `<packets.json> benchmark` is
  still accepted

### Flags

- `-t N`, `--threads N` — Set worker thread count (default: the
  `RAYON_NUM_THREADS` environment variable if set, otherwise the CPU count)
- `-s`, `--skip-known-channels` — Skip the built-in `known_channels_secrets.txt`
  and `known_channels.txt` pre-passes that normally run before the given command
- `-d`, `--show-decoded-messages` — Print the decrypted message of every payload
  that a found channel decrypts (default: off)
- `-i S`, `--interval S` — Seconds between stats printouts (default: 60)

### Details worth knowing

- At the beginning, the application loads the lists of known secrets and
  channels (`known_channels_secrets.txt` first, then `known_channels.txt`) and
  runs them as pre-passes before your command. If you want to skip this, pass
  the `-s` option.
- When a channel is found during a known-channels pre-pass, the decrypted
  message is not shown (the pre-passes always run with decoding disabled).
- **Output order is not stable.** Channels are reported in whatever order the
  worker threads finish, so the lines for one channel are not contiguous across
  runs. Sort before diffing — this is why the regression workflow below sorts
  its output
- Don't use `#` in a wordlist file
- Maximum word length is 32 characters; longer lines are silently skipped
- The Android app allows lowercase letters, `-` and digits in a channel name;
  uppercase is not allowed, but some uppercase / UTF-8 characters have been seen
  in the wild. To increase your odds you should not use uppercase.

## Examples

### Find channel names - Use wordlist from stdin

```console
# cat known_channels.txt | ./target/release/meshcore-channel-finder -d -s  ./example/channel_name_ujazdbot.json stdin


       Success: secret: dd9df90242a483b681222a0dd71d4c9e channel: #ujazdbot
Secret: dd9df90242a483b681222a0dd71d4c9e, Channel: #ujazdbot, MeshcoreGroupMessage { datetime: 2026-09-29T17:36:07Z, flags: 0, sender: "SQ9SZ Zabrze", message: "T" }
```

### Find channel names - Use bruteforce

```console
# ./target/release/meshcore-channel-finder -d -s ./example/channel_name_ujazdbot.json bruteforce 8 8 abdjotuz

Using bruteforce
      charset: abdjotuz
  charset len: 9
      min len: 8
      max len: 8
     keyspace: 43,046,721
       Success: secret: dd9df90242a483b681222a0dd71d4c9e channel: #ujazdbot
Secret: dd9df90242a483b681222a0dd71d4c9e, Channel: #ujazdbot, MeshcoreGroupMessage { datetime: 2026-09-29T17:36:07Z, flags: 0, sender: "SQ9SZ Zabrze", message: "T" }
```

### Find channel secret

```console
# echo '8b3387e9c5cdea6ac9e5edbaa115cd72' | ./target/release/meshcore-channel-finder -d -s ./example/channel_secret_public.json stdin-secret

       Success: secret: 8b3387e9c5cdea6ac9e5edbaa115cd72
Secret: 8b3387e9c5cdea6ac9e5edbaa115cd72, MeshcoreGroupMessage { datetime: 2026-09-29T17:38:11Z, flags: 0, sender: "SQ9SZ Zabrze", message: "👍" }
Summary: words checked: 1 (0.00 m/s), decrypt attempts: 1 (0.00 m/s), remaining: 0/0 payloads, found: 1 channels
```

### Find channel secret - Use bruteforce

```console
# ./target/release/meshcore-channel-finder -d -s ./example/channel_secret_public.json bruteforce-secret 8b3387e9c5cdea6ac9e5edbaa1150000

Using bruteforce-secret
  start secret: 8b3387e9c5cdea6ac9e5edbaa1150000
     direction: high
       Success: secret: 8b3387e9c5cdea6ac9e5edbaa115cd72
Secret: 8b3387e9c5cdea6ac9e5edbaa115cd72, MeshcoreGroupMessage { datetime: 2026-09-29T17:38:11Z, flags: 0, sender: "SQ9SZ Zabrze", message: "👍" }

```

## Brute-forcing channel secrets (keys)

A MeshCore channel secret is a 16-byte (128-bit) `AES-128` key, written as 32
hex characters. When you cannot guess or wordlist the channel *name*, you can
attack the key space directly with the secret commands. This is astronomically
large (`2^128` keys), so a blind full sweep is not realistic — it only pays off
when you already know most of the key and want to fill in the last few unknown
bytes/nibbles.

### From a wordlist / stdin of candidate keys

Feed one 32-hex-char key per line. Non-hex lines and lines that are not exactly
16 bytes are skipped:

```bash
# cat candidate_keys.txt | ./target/release/meshcore-channel-finder -d -s packets.json stdin-secret
```

### Sequential sweep with `bruteforce-secret`

`bruteforce-secret START [low|high]` counts through the key space one key at a
time, starting from `START` (32 hex chars):

- `high` (default) counts **up** from `START` towards
  `ffffffffffffffffffffffffffffffff`
- `low` counts **down** from `START` towards `00000000000000000000000000000000`

```bash
# count UP from a partially-known key (last 4 hex digits unknown → 0000)
# ./target/release/meshcore-channel-finder -d -s packets.json bruteforce-secret 8b3387e9c5cdea6ac9e5edbaa1150000 high

# count DOWN from the top of the key space
# ./target/release/meshcore-channel-finder -d -s packets.json bruteforce-secret ffffffffffffffffffffffffffffffff low
```

> Practical tip: pick `START` and the direction so the unknown part of the key
> is what gets swept. To brute-force the low 16 bits of a key, zero those bits
> in `START` and go `high`; the sweep reaches the real key after at most 65,536
> steps instead of walking the whole `2^128` space.

### Resuming a long sweep

`bruteforce-secret` can run far longer than a single session. The periodic stats
line reports how far the sweep has advanced with a `current secret:` field —
this is the lowest key not yet fully processed when going `high` (or the highest
when going `low`):

```
Stats: words: 12.34m/s (...), decrypt attempts: ..., payloads: .../..., channel hashes: .../..., found: 0 channels, current secret: 8b3387e9c5cdea6ac9e5edbaa1153a80
```

To resume, stop the run, then start a new one with that reported `current
secret:` value as the new `START` (keeping the same direction). Use `-i` to make
the checkpoint print more often, e.g. `-i 10` for every 10 seconds. The
`current secret:` field is only printed for `bruteforce-secret`.

## Prepare packets

You can use the CoreScope API to download encrypted messages. Right now only
`payload_type == 5` (`CHANNEL MSG`) is allowed.

Using `/api/packets?limit=50&groupByHash=true&payload_type=5` filters out a lot
of packets for you.

You can use services to download some data and play:

- live.meshcorekk.xyz
- mc.inside.net.pl
- analyzer.marwoj.net
- corescope.malinovi.com
- map.meshcore.hu
- analyzer.acadianamesh.com
- analyzer.gulfcoastmesh.org
- corescope.wcmesh.com
- mesh.feelthelemon.ru
- analyzer.bostonme.sh
- live.meshcore.ca
- meshview.dk
- map.okimesh.org
- analyzer.montrealmesh.ca
- corescope.chicagolandmesh.org
- live.eastidahomesh.com
- cornmeister.nl
- analyzer.meshcom.dk
- analyzer.868.sk
- analyzer.nashme.sh
- map.nvme.sh
- analyzer.cascadiamesh.org
- rf.rbit.se
- map.lvmesh.com
- analyzer.meshcore.coloradomesh.org
- map.rflab.io
- meshcore.meshat.se

> CoreScope has limit of 10_000 packets per page, make sure you play with
> `offset` to download everything

#### Packets optimization

The loading process checks that each packet is valid (that it is
`PAYLOAD_TYPE_GRP_TXT = 5`, that it carries a correct payload length, etc.).
Messages are encrypted with `AES-128-EBC`, so before loading they are split into
16-byte blocks and de-duplicated.

### raw_hex

The `packets.json` file must contain at minimum:

```json
{
  "packets": [
    {
      "raw_hex": "XXXXXXXXXXXXX"
    },
    {
      "raw_hex": "YYYYYYYYYY"
    }
  ]
}
```

## Build

```bash
# Build release binary
cargo build --release

# Run with arguments
cargo run --release -- <packets.json> <command> [args...]

# Run tests
cargo test

# Run benchmarks
cargo run --release -- benchmark
```

Note that `cargo build --release` **always compiles for the local CPU**. The
resulting binary is not portable to another machine.

To build without it, use the `RUSTFLAGS` environment variable — cargo documents
that it takes precedence over `build.rustflags`, and `build.rustflags` is only
consulted when `RUSTFLAGS` is unset:

```bash
RUSTFLAGS="" cargo build --release
```

### Wordlist

Powerful tools like `John the Ripper jumbo`, `Hashcat` and `hashcat-utils` can
generate wordlists, e.g. to:

- combine multiple dictionaries
- apply a ruleset, e.g. convert to lowercase
- combine a wordlist with a mask
- remove characters

## Author

**krzotr** — <https://github.com/krzotr/meshcore-channel-finder>

## License

This project is licensed under the **GNU General Public License v3.0 or later**
(`GPL-3.0-or-later`). See the [LICENSE](LICENSE) file for the full text.
