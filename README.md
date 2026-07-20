# BlindBit Rust

A Rust implementation of the BlindBit suite for Bitcoin BIP-352 Silent Payments.

## Overview

BlindBit is a comprehensive software suite for Bitcoin BIP-352 Silent Payments. This Rust implementation provides the core libraries and tools for scanning Bitcoin blocks to detect silent payments, integrating with the broader BlindBit ecosystem that includes indexers, scanners, and wallets.

## Features

- **Silent Payments Scanning**: Detects BIP-352 silent payments in Bitcoin transactions
- **BlindBit Oracle Integration**: Connects to BlindBit Oracle services for efficient blockchain data access
- **State Persistence**: Saves and restores scanner state for incremental scanning
- **Electrum Server**: Exposes a local Electrum TCP interface for wallet compatibility (e.g. Sparrow)
- **HTTP API**: Lightweight HTTP server exposing scanner state and subscription endpoints
- **Multi-Network Support**: Works with Bitcoin mainnet, signet, testnet, testnet4, and regtest
- **Privacy-Preserving**: Scanner queries reveal only general interest in Silent Payments, not specific keys or transactions

## Workspace Structure

This is a Cargo workspace containing three main crates:

- **blindbit-lib**: Core library containing the scanning logic and gRPC client
- **friglet**: Lightweight scanner compatible with Frigate's Silent Payments endpoints, with built-in Electrum and HTTP servers
- **blindbit-cli**: Minimal command-line interface for scanning (no server functionality)

## Usage

### friglet (Recommended)

`friglet` is the recommended tool. It scans Bitcoin blocks for Silent Payments and exposes both an Electrum TCP server and an HTTP API, making it compatible with wallets like Sparrow via Frigate.

```bash
cargo run --release --package friglet scan \
  --network signet \
  --scan-secret <SCAN_SECRET_KEY> \
  --spend-pubkey <SPEND_PUB_KEY> \
  --start-height 274010 \
  --p2p-node-addr 152.53.151.148:38333 \
  --oracle-url 'https://signet.oracle.setor.dev' \
  --max-label-num <NUM_OF_LABELS> \
  --state-file <PATH_TO_STORE_SCANNER_DATA>
```

#### Parameters

| Flag | Description | Default |
|------|-------------|---------|
| `--scan-secret` | Scan secret key (32-byte hex, secp256k1) | required |
| `--spend-pubkey` | Spend public key (33-byte hex, secp256k1) | required |
| `--start-height` | Wallet birthday block height | required |
| `--p2p-node-addr` | Bitcoin P2P node address (`host:port`) | required |
| `--oracle-url` | BlindBit Oracle URL | `https://oracle.setor.dev` |
| `--network` | Bitcoin network: `bitcoin\|signet\|testnet\|testnet4\|regtest` | `bitcoin` |
| `--max-label-num` | Maximum number of Silent Payment labels | `0` |
| `--state-file` | Path to persist scanner state | `scanner_state.json` |
| `--http-addr` | HTTP server bind address | `127.0.0.1:8080` |
| `--electrum-addr` | Electrum TCP server bind address | `127.0.0.1:50001` |

#### Configuration

Every flag above can also come from a TOML config file or environment
variables. Precedence: **CLI flags > `FRIGLET_*` env vars > config file >
defaults**. With a complete config file, `friglet` (or `friglet scan`) starts
with no flags at all.

- Config file: `~/.config/friglet/config.toml` (Linux),
  `~/Library/Application Support/friglet/config.toml` (macOS), or `--config <path>`.
  Keys match the flag names (`oracle_url`, `p2p_node_addr`, `start_height`, ...).
- Env vars: flag name upper-cased with the `FRIGLET_` prefix, e.g.
  `FRIGLET_ORACLE_URL`, `FRIGLET_START_HEIGHT`.
- `--print-config` prints the merged configuration as TOML and exits.

The scan secret is kept out of the config file. It is read from, in order:
`--scan-secret` (deprecated), `FRIGLET_SCAN_SECRET`, or the key file at
`<config dir>/friglet/scan.key` (override with `key_file` / `--key-file`).
When the secret is supplied via flag or env and no key file exists yet, it is
written there with `0600` permissions so subsequent runs need no secret on
the command line. Note: the scanner state file also contains the secret
(required for restore); friglet keeps it at `0600`.

While running, the daemon serves a control socket (newline-delimited JSON,
see the `friglet-ipc` crate) for status, start/stop scanning, and shutdown.
Default socket: `$XDG_RUNTIME_DIR/friglet.sock` (Linux),
`~/Library/Application Support/friglet/friglet.sock` (macOS),
`\\.\pipe\friglet` (Windows); override with `FRIGLET_CONTROL_SOCKET`.

#### HTTP API

Once running, `friglet` exposes the following endpoints on `--http-addr`:

| Endpoint | Description |
|----------|-------------|
| `GET /height` | Returns the last scanned block height as `{"height": <n>}` |
| `GET /subscribe` | Returns the current scanner state in Frigate-compatible format |

#### Electrum Server

The built-in Electrum server (bound to `--electrum-addr`) allows wallets such as Sparrow to connect directly and query Silent Payment UTXOs without any additional infrastructure.

---

### blindbit-cli

The `blindbit-cli` provides a minimal command-line interface for scanning blocks without a server:

```bash
cargo run --release --package blindbit-cli scan \
  --scan-secret <32-byte-hex> \
  --spend-pubkey <33-byte-hex> \
  --start-height <height> \
  --p2p-node-addr <address> \
  --oracle-url <url> \
  --state-file <path>
```

#### Parameters

- `--scan-secret`: 32-byte hex string representing the scan secret key
- `--spend-pubkey`: 33-byte hex string representing the spend public key
- `--start-height`: Block height to begin scanning from (wallet birthday)
- `--p2p-node-addr`: Bitcoin P2P node address (`host:port`)
- `--oracle-url`: Oracle service URL (default: `https://oracle.setor.dev`)
- `--state-file`: Path for scanner state persistence (default: `scanner_state.json`)
- `--network`: Bitcoin network `bitcoin|signet|testnet|testnet4|regtest` (default: `bitcoin`)
- `--max-label-num`: Maximum label number (default: `0`)

