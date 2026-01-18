use super::scanner::Scanner;

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::Path;
use std::path::PathBuf;

use bitcoin::BlockHash;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{PublicKey, SecretKey};
use bitcoin_rev::Network;
use indexer::bdk_chain::bdk_core::Merge;
use indexer::v2::SpIndexerV2;
use tokio::sync::broadcast;
use tonic::transport::Channel;

use crate::oracle_grpc::oracle_service_client::OracleServiceClient;
use indexer::bdk_chain::ConfirmationBlockTime;

use super::changeset::ChangeSet;

pub async fn load_scanner(
    // TODO: refactor to a config struct which carries all these arguments as fields
    client: OracleServiceClient<Channel>,
    p2p_socket_addr: SocketAddr,
    mut changeset: ChangeSet,
    state_file: PathBuf,
    network: Network,
) -> Result<Scanner, Box<dyn std::error::Error>> {
    let mut sp_scanner = if state_file.exists() {
        println!("Loading scanner state from {}...", state_file.display());
        match Scanner::load_from_file(&state_file) {
            Ok(changeset) => {
                // Clone client for the from_changeset call
                let client_clone = OracleServiceClient::connect(oracle_url.clone()).await?;
                match Scanner::from_changeset(
                    client_clone,
                    addr,
                    changeset,
                    state_file.clone(),
                    network,
                ) {
                    Ok(scanner) => {
                        let last_height = scanner.get_last_scanned_block_height();
                        println!("Loaded state. Last scanned height: {}", last_height);
                        scanner
                    }
                    Err(e) => {
                        eprintln!("Warning: Failed to restore from state file: {e}");
                        eprintln!("Creating new scanner...");
                        Scanner::new(
                            client,
                            addr,
                            secret_scan,
                            public_spend,
                            max_label_num,
                            state_file.clone(),
                            network,
                        )
                    }
                }
            }
            Err(e) => {
                eprintln!("Warning: Failed to load state file: {e}");
                eprintln!("Creating new scanner...");
                Scanner::new(
                    client,
                    addr,
                    secret_scan,
                    public_spend,
                    max_label_num,
                    state_file.clone(),
                    network,
                )
            }
        }
    } else {
        println!("No existing state file found. Creating new scanner...");
        Scanner::new(
            client,
            addr,
            secret_scan,
            public_spend,
            max_label_num,
            state_file.clone(),
            network,
        )
    };

    Ok(sp_scanner)
}
