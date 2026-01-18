use bitcoin_rev::Network;
use clap::{Parser, Subcommand};
use std::sync::Arc;
use std::{net::SocketAddr, path::PathBuf, str::FromStr};
use tokio::sync::Mutex;

use axum::{Extension, Json, Router, routing::get};
use blindbit_lib::scanner;
use serde::Serialize;
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
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
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
                .route("/height", get(get_height))
                .layer(Extension(bg_scanner));

            // 5. Start server
            let listener = tokio::net::TcpListener::bind("127.0.0.1:8080")
                .await
                .unwrap();
            axum::serve(listener, app).await.unwrap();
            Ok(())
        }
    }
}

#[derive(Serialize)]
struct HeightResponse {
    height: u64,
}

async fn get_height(
    Extension(sp_scanner): Extension<Arc<Mutex<scanner::Scanner>>>,
) -> Json<HeightResponse> {
    let s = sp_scanner.lock().await;
    Json(HeightResponse {
        height: s.get_last_scanned_block_height(),
    })
}
