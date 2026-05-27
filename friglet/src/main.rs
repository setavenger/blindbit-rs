mod electrum;
mod server;
mod types;

use bitcoin_rev::Network;
use clap::{Parser, Subcommand};
use std::sync::Arc;
use std::{net::SocketAddr, path::PathBuf, str::FromStr};
use tokio::sync::Mutex;

use axum::{Extension, Router, routing::get};
use blindbit_lib::scanner;
use tokio;

use bitcoin::secp256k1::{PublicKey, SecretKey};

#[derive(Parser)]
#[command(name = "blindbit-cli")]
#[command(about = "A CLI tool for scanning Bitcoin blocks", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan from start_height to chain tip, then keep watching for new blocks
    Scan {
        /// The scan secret key (32 bytes hex string)
        #[arg(long)]
        scan_secret: String,

        /// The spend public key (33 bytes hex string)
        #[arg(long)]
        spend_pubkey: String,

        /// Start block height (wallet birthday)
        #[arg(long)]
        start_height: u64,

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

        /// HTTP server address
        #[arg(long, default_value = "127.0.0.1:8080")]
        http_addr: String,

        /// Electrum TCP server address
        #[arg(long, default_value = "127.0.0.1:50001")]
        electrum_addr: String,

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
            p2p_node_addr,
            max_label_num,
            oracle_url,
            state_file,
            network,
            http_addr,
            electrum_addr,
            log_level,
        } => {
            // Initialise structured logging.  RUST_LOG takes precedence; the
            // --log-level flag sets the default when RUST_LOG is not set.
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

            tracing::info!(
                oracle_url = %oracle_url,
                p2p_peer = %p2p_socket_addr,
                network = %network,
                start_height,
                "starting friglet"
            );

            // Create scanner configuration
            let config = scanner::ScannerConfig::new(
                oracle_url,
                p2p_socket_addr,
                secret_scan,
                public_spend,
                max_label_num,
                state_file.clone(),
                network,
            );

            let loaded_scanner = scanner::load_scanner(&config).await?;

            // Pre-populate the Electrum index from the persisted BDK graph so that
            // Sparrow can immediately fetch wallet history after a restart.
            loaded_scanner.rebuild_electrum_index_from_graph(start_height).await;

            let scanner_instance = Arc::new(Mutex::new(loaded_scanner));

            // Grab Electrum index + push receiver before the scan task locks the scanner.
            let (electrum_index, found_utxos_rx) = {
                let s = scanner_instance.lock().await;
                let index = s.electrum_index();
                {
                    let mut idx = index.lock().await;
                    idx.sp_start_height = start_height;
                }
                (index, s.subscribe_to_found_utxos())
            };

            // Ensure watch_chain starts from start_height on a fresh wallet
            // (last_scanned_block_height is 0 when there is no saved state).
            {
                let mut s = scanner_instance.lock().await;
                if s.get_last_scanned_block_height() < start_height {
                    s.update_last_scanned_block_height(start_height.saturating_sub(1));
                }
            }

            // Launch the scanner in the background.  watch_chain polls the
            // oracle for new blocks and runs indefinitely — no end_height needed.
            let bg_scanner_clone = scanner_instance.clone();
            tokio::spawn(async move {
                let mut s = bg_scanner_clone.lock().await;
                if let Err(e) = s.watch_chain().await {
                    tracing::error!(error = %e, "watch_chain terminated with error");
                }
            });

            let bg_scanner = scanner_instance.clone();

            // 4. Create HTTP server
            let app = Router::new()
                .route("/height", get(server::get_height))
                .route("/subscribe", get(server::subscribe))
                .layer(Extension(server::ScanStartHeight(start_height)))
                .layer(Extension(bg_scanner.clone()));

            // 5. Start both HTTP and Electrum servers in parallel
            let http_addr_clone = http_addr.clone();
            let http_server = async move {
                let listener = tokio::net::TcpListener::bind(&http_addr_clone)
                    .await
                    .expect("Failed to bind HTTP server");
                tracing::info!(addr = %http_addr_clone, "HTTP server listening");
                axum::serve(listener, app)
                    .await
                    .expect("HTTP server failed");
            };

            let electrum_p2p_addr = p2p_socket_addr;
            let electrum_network = network;
            let electrum_server = async move {
                if let Err(e) = electrum::run(
                    electrum_index,
                    found_utxos_rx,
                    &electrum_addr,
                    electrum_p2p_addr,
                    electrum_network,
                )
                .await
                {
                    tracing::error!(error = %e, "Electrum server terminated with error");
                }
            };

            // Run both servers concurrently
            tokio::select! {
                _ = http_server => {
                    tracing::info!("HTTP server stopped");
                }
                _ = electrum_server => {
                    tracing::info!("Electrum server stopped");
                }
            }

            Ok(())
        }
    }
}
