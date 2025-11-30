use bitcoin::secp256k1::{PublicKey, SecretKey};
use blindbit_lib::oracle_grpc::oracle_service_client::OracleServiceClient;
use blindbit_lib::scanner;
use clap::{Parser, Subcommand};
use std::{net::SocketAddr, path::PathBuf, str::FromStr};

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
        } => {
            // Parse the scan secret (32 bytes hex)
            let secret_scan = SecretKey::from_str(&scan_secret)
                .map_err(|e| format!("Invalid scan_secret: {e}. Must be a valid 32-byte hex string representing a secp256k1 secret key"))?;

            // Parse the spend public key (33 bytes hex)
            let public_spend = PublicKey::from_str(&spend_pubkey)
                .map_err(|e| format!("Invalid spend_pubkey: {e}. Must be a valid 33-byte hex string representing a secp256k1 public key"))?;

            // Connect to the oracle service
            println!("Connecting to oracle service at {oracle_url}...");
            let client = OracleServiceClient::connect(oracle_url.clone()).await?;

            let addr = SocketAddr::from_str(&p2p_node_addr).unwrap();

            // Try to load existing state, or create a new scanner
            let mut sp_scanner = if state_file.exists() {
                println!("Loading scanner state from {}...", state_file.display());
                match scanner::Scanner::load_from_file(&state_file) {
                    Ok(changeset) => {
                        // Clone client for the from_changeset call
                        let client_clone = OracleServiceClient::connect(oracle_url.clone()).await?;
                        match scanner::Scanner::from_changeset(client_clone, addr, changeset) {
                            Ok(scanner) => {
                                let last_height = scanner.get_last_scanned_block_height();
                                println!("Loaded state. Last scanned height: {}", last_height);
                                scanner
                            }
                            Err(e) => {
                                eprintln!("Warning: Failed to restore from state file: {e}");
                                eprintln!("Creating new scanner...");
                                scanner::Scanner::new(
                                    client,
                                    addr,
                                    secret_scan,
                                    public_spend,
                                    max_label_num,
                                )
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("Warning: Failed to load state file: {e}");
                        eprintln!("Creating new scanner...");
                        scanner::Scanner::new(
                            client,
                            addr,
                            secret_scan,
                            public_spend,
                            max_label_num,
                        )
                    }
                }
            } else {
                println!("No existing state file found. Creating new scanner...");
                scanner::Scanner::new(client, addr, secret_scan, public_spend, max_label_num)
            };

            // Scan the block range
            println!("Scanning blocks from {start_height} to {end_height}...");

            // Use a result to capture any errors during scanning
            let scan_result = sp_scanner.scan_block_range(start_height, end_height).await;

            // Always try to save state, even if scanning failed
            println!("Saving scanner state to {}...", state_file.display());
            if let Err(save_err) = sp_scanner.save_to_file(&state_file) {
                eprintln!("Warning: Failed to save state: {save_err}");
            } else {
                println!("State saved successfully!");
            }

            // Return the scan result (will propagate any errors)
            scan_result?;

            println!("Scan completed successfully!");
        }
    }

    Ok(())
}
