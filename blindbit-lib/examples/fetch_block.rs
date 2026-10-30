//! Fetch one full block over P2P the way the scanner does, and print the
//! block or the message the scanner would report.
//!
//! ```text
//! cargo run -p blindbit-lib --example fetch_block -- <host:port|dns> <block hash> <height> [mainnet|testnet3|testnet4|signet|regtest] [--proxy ip:port]
//! ```
//!
//! `host:port` asks that node (as with `p2p_node_addr` set); `dns` finds
//! peers of the network through its DNS seeds and asks them one after
//! another (as with `p2p_node_addr` empty). `--proxy 127.0.0.1:9050` sends
//! every connection through that SOCKS5 proxy (Tor), as `p2p_proxy` does:
//! the node may then be a host name (also `.onion`), resolved by the proxy,
//! and the seeds are asked through it, never by local DNS.
//!
//! `RUST_LOG=info` (the default) shows each failed attempt and its retry;
//! `RUST_LOG=debug` also the seeds' answers and each peer asked.

use std::str::FromStr;

use bitcoin::BlockHash;
use bitcoin::Network;
use blindbit_lib::net::{Dialer, PeerAddr, PeerHost, PeerSource, Seeds};
use blindbit_lib::scanner::BlockFetcher;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let dialer = match args.iter().position(|arg| arg == "--proxy") {
        Some(at) if at + 1 < args.len() => {
            let proxy = args.remove(at + 1).parse::<std::net::SocketAddr>()?;
            args.remove(at);
            Dialer::Socks5 { proxy }
        }
        Some(_) => return Err("--proxy needs ip:port".into()),
        None => Dialer::Direct,
    };
    let [peer, hash, height, rest @ ..] = args.as_slice() else {
        return Err(
            "usage: fetch_block <host:port|dns> <block hash> <height> [network] [--proxy ip:port]"
                .into(),
        );
    };
    let network = match rest.first().map(String::as_str).unwrap_or("mainnet") {
        "mainnet" => Network::Bitcoin,
        "testnet3" => Network::Testnet,
        "testnet4" => Network::Testnet4,
        "signet" => Network::Signet,
        "regtest" => Network::Regtest,
        other => return Err(format!("unknown network {other}").into()),
    };
    let own_node = match peer.as_str() {
        "dns" => None,
        addr => Some(match addr.parse::<std::net::SocketAddr>() {
            Ok(socket) => socket.into(),
            // A name: the proxy resolves it (directly, the dialer does).
            Err(_) => {
                let (host, port) = addr.rsplit_once(':').ok_or("expected host:port")?;
                PeerAddr {
                    host: PeerHost::Name(host.to_string()),
                    port: port.parse()?,
                }
            }
        }),
    };
    let peers = PeerSource::new(network, dialer, own_node, Seeds::for_network(network));
    let fetcher = BlockFetcher::new(peers.clone());
    let hash = BlockHash::from_str(hash)?;
    let height: u64 = height.parse()?;

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let started = std::time::Instant::now();
    match runtime.block_on(fetcher.fetch(hash, height)) {
        Ok(block) => {
            println!(
                "OK block {} at height {height}: {} transactions, {} bytes, in {:?} ({})",
                block.block_hash(),
                block.txdata.len(),
                bitcoin::consensus::encode::serialize(&block).len(),
                started.elapsed(),
                peers.summary()
            );
            Ok(())
        }
        Err(error) => {
            println!("FAILED after {:?}: {error}", started.elapsed());
            std::process::exit(1);
        }
    }
}
