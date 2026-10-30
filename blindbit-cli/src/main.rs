use bitcoin::secp256k1::{PublicKey, SecretKey};
use blindbit_lib::net::{Dialer, PeerAddr, PeerHost, PeerSource, Seeds};
use blindbit_lib::scanner::{self, ScannerConfig};
use clap::{Parser, Subcommand};
use std::{net::SocketAddr, path::PathBuf, process::ExitCode, str::FromStr};

use bitcoin::Network;

#[derive(Parser)]
#[command(name = "blindbit-cli")]
#[command(about = "A CLI tool for scanning Bitcoin blocks", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan a range of blocks for silent payments
    Scan {
        /// The scan secret key (32 bytes hex string)
        #[arg(long)]
        scan_secret: String,

        /// The spend public key (33 bytes hex string)
        #[arg(long)]
        spend_pubkey: String,

        /// Start block height
        #[arg(long)]
        start_height: u64,

        /// End block height
        #[arg(long)]
        end_height: u64,

        /// Your Bitcoin node's P2P address (ip:port; with --p2p-proxy also
        /// host:port, e.g. an .onion address). Without it, blocks come from
        /// random peers of the network, found through its DNS seeds (they
        /// see this computer's IP, or Tor's with --p2p-proxy, and which
        /// blocks it downloads).
        #[arg(long)]
        p2p_node_addr: Option<String>,

        /// SOCKS5 proxy (Tor) for every P2P connection, ip:port, e.g.
        /// 127.0.0.1:9050. No P2P connection goes out directly, and nothing
        /// is looked up locally (the oracle connection is not proxied).
        #[arg(long)]
        p2p_proxy: Option<String>,

        /// Maximum label number
        #[arg(long, default_value = "0")]
        max_label_num: u32,

        /// Oracle service URL
        #[arg(long, default_value = "https://oracle.setor.dev")]
        oracle_url: String,

        /// Path to save/load scanner state (default: scanner_state.json)
        #[arg(long, default_value = "scanner_state.json")]
        state_file: PathBuf,

        #[arg(long, default_value = "bitcoin")]
        network: Network,

        /// Log level: trace, debug, info, warn, error (overridden by RUST_LOG env var)
        #[arg(long, default_value = "info")]
        log_level: String,
    },
}

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            // Display, not the Debug form `main` would print for a returned error: a
            // stopped scan (`ScanStopped`) says which height it stopped at and where to
            // rescan from, and its Debug form is a struct dump.
            eprintln!("Error: {e}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Scan {
            scan_secret,
            spend_pubkey,
            start_height,
            end_height,
            p2p_node_addr,
            p2p_proxy,
            max_label_num,
            oracle_url,
            state_file,
            network,
            log_level,
        } => {
            let filter = tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(&log_level));
            tracing_subscriber::fmt()
                .with_env_filter(filter)
                .with_target(false)
                .init();

            let secret_scan = SecretKey::from_str(&scan_secret)
                .map_err(|e| format!("Invalid scan_secret: {e}. Must be a valid 32-byte hex string representing a secp256k1 secret key"))?;

            let public_spend = PublicKey::from_str(&spend_pubkey)
                .map_err(|e| format!("Invalid spend_pubkey: {e}. Must be a valid 33-byte hex string representing a secp256k1 public key"))?;

            let dialer = match p2p_proxy.as_deref().map(str::trim) {
                None | Some("") => Dialer::Direct,
                Some(proxy) => Dialer::Socks5 {
                    proxy: parse_proxy(proxy)?,
                },
            };
            let own_node = p2p_node_addr
                .as_deref()
                .map(str::trim)
                .filter(|addr| !addr.is_empty())
                .map(|addr| own_node_addr(addr, &dialer))
                .transpose()?;
            if own_node.is_none() && network == Network::Regtest {
                return Err(
                    "regtest has no public peers: pass --p2p-node-addr with your regtest node"
                        .into(),
                );
            }
            let peers = PeerSource::new(network, dialer, own_node, Seeds::for_network(network));
            peers.start();
            tracing::info!(p2p = %peers.summary(), "block downloads");

            let config = ScannerConfig::new(
                oracle_url.clone(),
                peers,
                secret_scan,
                public_spend,
                max_label_num,
                state_file.clone(),
                network,
            );

            tracing::info!(oracle_url = %oracle_url, "connecting to oracle service");
            let mut sp_scanner = scanner::load_scanner(&config).await?;

            tracing::info!(start = start_height, end = end_height, "scanning blocks");
            let scan_result = sp_scanner.scan_block_range(start_height, end_height).await;

            tracing::info!(path = %state_file.display(), "saving scanner state");
            if let Err(save_err) = sp_scanner.save_to_file(&state_file) {
                tracing::warn!(error = %save_err, "failed to save state");
            } else {
                tracing::info!("state saved");
            }

            scan_result?;

            tracing::info!("scan completed successfully");
        }
    }

    Ok(())
}

/// `ip:port` or `localhost:port`: finding the proxy needs no DNS lookup.
fn parse_proxy(proxy: &str) -> Result<SocketAddr, String> {
    if let Some(port) = proxy.strip_prefix("localhost:") {
        let port = port
            .parse::<u16>()
            .map_err(|e| format!("Invalid p2p_proxy `{proxy}`: {e}"))?;
        return Ok(SocketAddr::from(([127, 0, 0, 1], port)));
    }
    SocketAddr::from_str(proxy).map_err(|e| {
        format!("Invalid p2p_proxy `{proxy}`: {e} (expected ip:port, e.g. 127.0.0.1:9050)")
    })
}

/// The own node: `ip:port`, or through a proxy also `host:port` (the proxy
/// resolves the name).
fn own_node_addr(addr: &str, dialer: &Dialer) -> Result<PeerAddr, String> {
    if let Ok(socket) = SocketAddr::from_str(addr) {
        return Ok(socket.into());
    }
    match (dialer.proxy(), addr.rsplit_once(':')) {
        (Some(_), Some((host, port))) if !host.is_empty() => Ok(PeerAddr {
            host: PeerHost::Name(host.to_string()),
            port: port
                .parse()
                .map_err(|e| format!("Invalid p2p_node_addr `{addr}`: {e}"))?,
        }),
        (Some(_), _) => Err(format!(
            "Invalid p2p_node_addr `{addr}`: expected host:port"
        )),
        (None, _) => Err(format!(
            "Invalid p2p_node_addr `{addr}`: expected ip:port (host names only with --p2p-proxy)"
        )),
    }
}
