use bitcoin::secp256k1::{PublicKey, SecretKey};
use blindbit_lib::scanner::{self, ScannerConfig};
use clap::{Parser, Subcommand};
use std::{net::SocketAddr, path::PathBuf, str::FromStr};

use bitcoin_rev::Network;

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

        #[arg(long)]
        p2p_node_addr: String,

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
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Scan {
            scan_secret,
            spend_pubkey,
            start_height,
            end_height,
            p2p_node_addr,
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

            // Parse the scan secret (32 bytes hex)
            let secret_scan = SecretKey::from_str(&scan_secret)
                .map_err(|e| format!("Invalid scan_secret: {e}. Must be a valid 32-byte hex string representing a secp256k1 secret key"))?;

            // Parse the spend public key (33 bytes hex)
            let public_spend = PublicKey::from_str(&spend_pubkey)
                .map_err(|e| format!("Invalid spend_pubkey: {e}. Must be a valid 33-byte hex string representing a secp256k1 public key"))?;

            // Parse the P2P socket address
            let p2p_socket_addr = SocketAddr::from_str(&p2p_node_addr)
                .map_err(|e| format!("Invalid p2p_node_addr: {e}"))?;

            // Create scanner configuration
            let config = ScannerConfig::new(
                oracle_url.clone(),
                p2p_socket_addr,
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
