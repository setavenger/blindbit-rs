use bitcoin::secp256k1::{PublicKey, SecretKey};
use blindbit_lib::oracle_grpc::oracle_service_client::OracleServiceClient;
use blindbit_lib::scanner;
use clap::{Parser, Subcommand};
use std::str::FromStr;

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

        /// Maximum label number
        #[arg(long, default_value = "0")]
        max_label_num: u32,

        /// Oracle service URL
        #[arg(long, default_value = "https://oracle.setor.dev")]
        oracle_url: String,
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
            max_label_num,
            oracle_url,
        } => {
            // Parse the scan secret (32 bytes hex)
            let secret_scan = SecretKey::from_str(&scan_secret)
                .map_err(|e| format!("Invalid scan_secret: {}. Must be a valid 32-byte hex string representing a secp256k1 secret key", e))?;

            // Parse the spend public key (33 bytes hex)
            let public_spend = PublicKey::from_str(&spend_pubkey)
                .map_err(|e| format!("Invalid spend_pubkey: {}. Must be a valid 33-byte hex string representing a secp256k1 public key", e))?;

            // Connect to the oracle service
            println!("Connecting to oracle service at {}...", oracle_url);
            let client = OracleServiceClient::connect(oracle_url.clone()).await?;

            // Create the scanner
            let mut sp_scanner =
                scanner::Scanner::new(client, secret_scan, public_spend, max_label_num);

            // Scan the block range
            println!("Scanning blocks from {} to {}...", start_height, end_height);
            sp_scanner
                .scan_block_range(start_height, end_height)
                .await?;

            println!("Scan completed successfully!");
        }
    }

    Ok(())
}
