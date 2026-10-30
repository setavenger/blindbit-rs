use bitcoin::Network;
use bitcoin::secp256k1::{PublicKey, SecretKey};
use std::path::PathBuf;
use std::sync::Arc;

use crate::net::PeerSource;

/// Configuration struct for Scanner initialization
///
/// This struct carries all the required parameters for creating and loading
/// Scanner instances, eliminating the need to pass many individual parameters.
#[derive(Debug, Clone)]
pub struct ScannerConfig {
    /// Oracle service URL for block data
    pub oracle_url: String,

    /// Where full blocks are downloaded from: the own node or discovered
    /// peers (see [`PeerSource`])
    pub peers: Arc<PeerSource>,

    /// Secret key for scanning silent payments
    pub secret_scan: SecretKey,

    /// Public key for spending
    pub public_spend: PublicKey,

    /// Maximum label number to scan
    pub max_label_num: u32,

    /// File path for persisting scanner state
    pub state_file: PathBuf,

    /// Bitcoin network (mainnet, testnet, etc.)
    pub network: Network,
}

impl ScannerConfig {
    /// Create a new ScannerConfig with all required parameters
    pub fn new(
        oracle_url: String,
        peers: Arc<PeerSource>,
        secret_scan: SecretKey,
        public_spend: PublicKey,
        max_label_num: u32,
        state_file: PathBuf,
        network: Network,
    ) -> Self {
        Self {
            oracle_url,
            peers,
            secret_scan,
            public_spend,
            max_label_num,
            state_file,
            network,
        }
    }

    /// Validate that the configuration has valid parameters
    pub fn validate(&self) -> Result<(), String> {
        // Basic validation - could be extended with more checks
        if self.oracle_url.is_empty() {
            return Err("Oracle URL cannot be empty".to_string());
        }

        if !self.oracle_url.starts_with("http://") && !self.oracle_url.starts_with("https://") {
            return Err("Oracle URL must start with http:// or https://".to_string());
        }

        Ok(())
    }
}
