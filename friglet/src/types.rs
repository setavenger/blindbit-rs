//! Shared types for Frigate protocol
//!
//! These types are used by both the HTTP server and the Electrum TCP server
//! to ensure consistency with the Frigate Electrum Server protocol.

use bitcoin::Txid;
use bitcoin::secp256k1::PublicKey;
use blindbit_lib::scanner::Scanner;
use serde::{Deserialize, Serialize};

/// Frigate response containing subscription info, progress, and transaction history
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrigateResponse {
    pub subscription: FrigateSubscription,
    pub progress: f32,
    pub history: Vec<FrigateHistory>,
}

/// Frigate subscription info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrigateSubscription {
    pub address: String,
    pub start_height: u64,
    pub labels: Vec<u32>,
}

/// Frigate transaction history entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrigateHistory {
    pub height: u64,
    pub tx_hash: String,
    pub tweak_key: String,
}

impl FrigateHistory {
    /// Create a FrigateHistory from relevant transaction data
    pub fn from_relevant_tx_data(out: &(Txid, &PublicKey, u32)) -> FrigateHistory {
        FrigateHistory {
            height: u64::from(out.2),
            tx_hash: out.0.to_string(),
            tweak_key: out.1.to_string(),
        }
    }
}

impl FrigateResponse {
    /// Create a new FrigateResponse
    pub fn new(
        address: String,
        start_height: u64,
        labels: Vec<u32>,
        progress: f32,
        history: Vec<FrigateHistory>,
    ) -> Self {
        Self {
            subscription: FrigateSubscription {
                address,
                start_height,
                labels,
            },
            progress,
            history,
        }
    }

    /// Build a Frigate response from scanner state.
    ///
    /// `scan_start_height` is the configured scan range start (not last scanned height).
    /// Sparrow uses this value as the canonical subscription key and rejects notifications
    /// where `subscription.start_height` differs.
    pub fn from_scanner(scanner: &Scanner, scan_start_height: u64) -> Self {
        let history: Vec<FrigateHistory> = scanner
            .get_relevant_txs()
            .iter()
            .map(FrigateHistory::from_relevant_tx_data)
            .collect();

        Self::new(
            scanner.get_scanner_sp_address(),
            scan_start_height,
            (0..=scanner.get_max_label_num()).collect(),
            1.0,
            history,
        )
    }
}
