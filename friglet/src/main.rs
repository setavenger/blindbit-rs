mod electrum;
mod server;
mod types;

use bitcoin_rev::Network;
use clap::{Parser, Subcommand};
// use server::{FrigateHistory, FrigateResponse, FrigateSubscription};
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

        /// HTTP server address
        #[arg(long, default_value = "127.0.0.1:8080")]
        http_addr: String,

        /// Electrum TCP server address
        #[arg(long, default_value = "127.0.0.1:50001")]
        electrum_addr: String,
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
            http_addr,
            electrum_addr,
        } => {
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

            // launch the scanner in the background
            let bg_scanner_clone = scanner_instance.clone();
            let start = start_height;
            let end = end_height;
            tokio::spawn(async move {
                let mut s = bg_scanner_clone.lock().await;
                s.scan_block_range(start, end).await.unwrap();
            });

            let bg_scanner = scanner_instance.clone();

            // 4. Create HTTP server
            let app = Router::new()
                // .route("/utxos", get(get_utxos))
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
                println!("HTTP server listening on {}", http_addr_clone);
                axum::serve(listener, app)
                    .await
                    .expect("HTTP server failed");
            };

            let electrum_scanner = bg_scanner.clone();
            let electrum_start_height = start_height;
            let electrum_p2p_addr = p2p_socket_addr;
            let electrum_network = network;
            let electrum_server = async move {
                if let Err(e) = electrum::run(
                    electrum_scanner,
                    electrum_start_height,
                    &electrum_addr,
                    electrum_p2p_addr,
                    electrum_network,
                )
                .await
                {
                    eprintln!("Electrum server error: {}", e);
                }
            };

            // Run both servers concurrently
            tokio::select! {
                _ = http_server => {
                    println!("HTTP server stopped");
                }
                _ = electrum_server => {
                    println!("Electrum server stopped");
                }
            }

            Ok(())
        }
    }
}
