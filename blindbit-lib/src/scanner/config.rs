use bitcoin::secp256k1::{PublicKey, SecretKey};
use bitcoin_rev::Network;
use std::net::SocketAddr;
use std::path::PathBuf;

/// Configuration struct for Scanner initialization
///
/// This struct carries all the required parameters for creating and loading
/// Scanner instances, eliminating the need to pass many individual parameters.
#[derive(Debug, Clone)]
pub struct ScannerConfig {
    /// Oracle service URL for block data
    pub oracle_url: String,

    /// P2P node socket address  
    pub p2p_socket_addr: SocketAddr,

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
        p2p_socket_addr: SocketAddr,
        secret_scan: SecretKey,
        public_spend: PublicKey,
        max_label_num: u32,
        state_file: PathBuf,
        network: Network,
    ) -> Self {
        Self {
            oracle_url,
            p2p_socket_addr,
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

// impl Default for ScannerConfig {
//     /// Default configuration with placeholder values
//     ///
//     /// Note: The crypto keys are placeholder values and should be set explicitly
//     /// for real usage. This is primarily for testing and development.
//     fn default() -> Self {
//         Self {
//             oracle_url: "https://oracle.setor.dev".to_string(),
//             p2p_socket_addr: "127.0.0.1:8333".parse().unwrap(),
//             // Placeholder values - should be set explicitly in real usage
//             secret_scan: SecretKey::from_slice(&[1u8; 32]).unwrap(),
//             public_spend: PublicKey::from_slice(&[2u8; 33]).unwrap(),
//             max_label_num: 0,
//             state_file: PathBuf::from("scanner_state.json"),
//             network: Network::Bitcoin,
//         }
//     }
// }
