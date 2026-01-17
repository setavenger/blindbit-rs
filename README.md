# BlindBit Rust

A Rust implementation of the BlindBit suite for Bitcoin BIP-352 Silent Payments.

## Overview

BlindBit is a comprehensive software suite for Bitcoin BIP-352 Silent Payments. This Rust implementation provides the core libraries and tools for scanning Bitcoin blocks to detect silent payments, integrating with the broader BlindBit ecosystem that includes indexers, scanners, and wallets.

## Features

- **Silent Payments Scanning**: Detects BIP-352 silent payments in Bitcoin transactions
- **BlindBit Oracle Integration**: Connects to BlindBit Oracle services for efficient blockchain data access
- **State Persistence**: Saves and restores scanner state for incremental scanning
- **CLI Interface**: Command-line tool for scanning operations
- **Multi-Network Support**: Works with Bitcoin mainnet and testnet
- **Privacy-Preserving**: Scanner queries reveal only general interest in Silent Payments, not specific keys or transactions

## Workspace Structure

This is a Cargo workspace containing three main crates:

- **blindbit-lib**: Core library containing the scanning logic and gRPC client
- **blindbit-cli**: Command-line interface for the scanning functionality  
- **friglet**: Lightweight Scanner compatible with Frigate's Silent Payments endpoints (WIP)

## Usage

### CLI Tool

The `blindbit-cli` provides a command-line interface for scanning blocks:

```bash
blindbit-cli scan \
  --scan-secret <32-byte-hex> \
  --spend-pubkey <33-byte-hex> \
  --start-height <height> \
  --end-height <height> \
  --p2p-node-addr <address> \
  --oracle-url <url> \
  --state-file <path>
```

### Parameters

- `--scan-secret`: 32-byte hex string representing the scan secret key
- `--spend-pubkey`: 33-byte hex string representing the spend public key
- `--start-height`/`--end-height`: Block height range to scan
- `--p2p-node-addr`: Bitcoin P2P node address (1.2.3.4:8333)
- `--oracle-url`: Oracle service URL (default: <https://oracle.setor.dev>)
- `--state-file`: Path for scanner state persistence (default: scanner_state.json)
- `--network`: Bitcoin network `bitcoin|signet|testnet|testnet4|regtest`
(default: `bitcoin`)
- `--max-label-num`: Maximum label number (default: 0)

