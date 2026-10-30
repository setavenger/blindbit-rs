//! Fetch one full block from a P2P node the way the scanner does, and print
//! the block or the message the scanner would report.
//!
//! ```text
//! cargo run -p blindbit-lib --example fetch_block -- <host:port> <block hash> <height> [mainnet|testnet3|testnet4|signet|regtest]
//! ```
//!
//! `RUST_LOG=info` (the default) shows each failed attempt and its retry.

use std::str::FromStr;

use bitcoin::BlockHash;
use bitcoin_rev::{Network, TestnetVersion};
use blindbit_lib::scanner::BlockFetcher;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [peer, hash, height, rest @ ..] = args.as_slice() else {
        return Err("usage: fetch_block <host:port> <block hash> <height> [network]".into());
    };
    let network = match rest.first().map(String::as_str).unwrap_or("mainnet") {
        "mainnet" => Network::Bitcoin,
        "testnet3" => Network::Testnet(TestnetVersion::V3),
        "testnet4" => Network::Testnet(TestnetVersion::V4),
        "signet" => Network::Signet,
        "regtest" => Network::Regtest,
        other => return Err(format!("unknown network {other}").into()),
    };
    let fetcher = BlockFetcher::new(peer.parse()?, network);
    let hash = BlockHash::from_str(hash)?;
    let height: u64 = height.parse()?;

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let started = std::time::Instant::now();
    match runtime.block_on(fetcher.fetch(hash, height)) {
        Ok(block) => {
            println!(
                "OK block {} at height {height}: {} transactions, {} bytes, in {:?}",
                block.block_hash(),
                block.txdata.len(),
                bitcoin::consensus::encode::serialize(&block).len(),
                started.elapsed()
            );
            Ok(())
        }
        Err(error) => {
            println!("FAILED after {:?}: {error}", started.elapsed());
            std::process::exit(1);
        }
    }
}
