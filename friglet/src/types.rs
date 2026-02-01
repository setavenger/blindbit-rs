//! Shared types for Frigate protocol
//!
//! These types are used by both the HTTP server and the Electrum TCP server
//! to ensure consistency with the Frigate Electrum Server protocol.

use bitcoin::Txid;
use bitcoin::secp256k1::PublicKey;
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
}
