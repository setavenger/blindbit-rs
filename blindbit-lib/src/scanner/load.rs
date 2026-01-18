use super::config::ScannerConfig;
use super::scanner::Scanner;

use crate::oracle_grpc::oracle_service_client::OracleServiceClient;

/// Load a scanner from configuration, optionally restoring from saved state
///
/// This function will attempt to load scanner state from the file specified in the config.
/// If the state file doesn't exist or loading fails, it will create a new scanner.
///
/// Requires the `serde` feature to be enabled for state persistence.
#[cfg(feature = "serde")]
pub async fn load_scanner(config: &ScannerConfig) -> Result<Scanner, Box<dyn std::error::Error>> {
    // Validate configuration
    config.validate()?;

    let sp_scanner = if config.state_file.exists() {
        println!(
            "Loading scanner state from {}...",
            config.state_file.display()
        );
        match Scanner::load_from_file(&config.state_file) {
            Ok(changeset) => {
                // Connect to oracle service for restoring from changeset
                let client = OracleServiceClient::connect(config.oracle_url.clone()).await?;
                match Scanner::from_changeset(
                    client,
                    config.p2p_socket_addr,
                    changeset,
                    config.state_file.clone(),
                    config.network,
                ) {
                    Ok(scanner) => {
                        let last_height = scanner.get_last_scanned_block_height();
                        println!("Loaded state. Last scanned height: {}", last_height);
                        scanner
                    }
                    Err(e) => {
                        eprintln!("Warning: Failed to restore from state file: {e}");
                        eprintln!("Creating new scanner...");
                        create_new_scanner(config).await?
                    }
                }
            }
            Err(e) => {
                eprintln!("Warning: Failed to load state file: {e}");
                eprintln!("Creating new scanner...");
                create_new_scanner(config).await?
            }
        }
    } else {
        println!("No existing state file found. Creating new scanner...");
        create_new_scanner(config).await?
    };

    Ok(sp_scanner)
}

/// Create a new scanner from configuration
#[cfg(feature = "serde")]
async fn create_new_scanner(config: &ScannerConfig) -> Result<Scanner, Box<dyn std::error::Error>> {
    // Connect to oracle service
    let client = OracleServiceClient::connect(config.oracle_url.clone()).await?;

    Ok(Scanner::new(
        client,
        config.p2p_socket_addr,
        config.secret_scan,
        config.public_spend,
        config.max_label_num,
        config.state_file.clone(),
        config.network,
    ))
}
