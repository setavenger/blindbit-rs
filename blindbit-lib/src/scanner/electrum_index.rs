//! Wallet-scoped Electrum index for friglet's single-server mode.
//!
//! Populated incrementally during scanning. Only contains data for outputs
//! confirmed to belong to this wallet — no chain-wide indexing.

use bitcoin::ScriptBuf;
use bitcoin::hashes::{Hash, sha256};
use std::collections::HashMap;

/// Lightweight Electrum-compatible index built from scanner state.
#[derive(Default)]
pub struct WalletElectrumIndex {
    /// txid hex → consensus-serialized raw tx bytes.
    /// Populated when the full block is fetched during scan_block_range.
    pub txs: HashMap<String, Vec<u8>>,

    /// block height → 80-byte header hex.
    /// Populated for every block that contained a confirmed match.
    pub headers: HashMap<u32, String>,

    /// Electrum scripthash hex → ordered history entries.
    /// One entry per wallet output (confirmed SP receive / spend output).
    pub scripthash_history: HashMap<String, Vec<ScriptHashEntry>>,

    /// Current best block tip seen by the scanner (height, header hex).
    /// Used for blockchain.headers.subscribe RPC response and push notifications.
    pub tip: Option<(u32, String)>,

    /// Scan progress 0.0–1.0. Used for incremental SP progress notifications.
    pub scan_progress: f32,

    // --- Silent Payments subscription data --------------------------------
    // Stored here so push_notifications never needs to lock the Scanner
    // (the scan task holds the scanner lock for its entire duration).

    /// Bech32m SP address derived from wallet keys.
    pub sp_address: String,

    /// Configured scan start height — used as the subscription key by Sparrow.
    pub sp_start_height: u64,

    /// All label indices this wallet supports (0 = change label).
    pub sp_labels: Vec<u32>,

    /// Ordered list of confirmed SP receives.
    pub sp_history: Vec<SpHistoryEntry>,
}

/// A single entry in a scripthash's transaction history.
/// Matches the Electrum protocol wire format for blockchain.scripthash.get_history.
#[derive(Clone, Debug)]
pub struct ScriptHashEntry {
    pub tx_hash: String,
    pub height: u32,
    /// Always 0 — fee data is not available in the scanner.
    pub fee: u64,
}

/// A single entry in the Silent Payments transaction history.
/// Used to build `blockchain.silentpayments.subscribe` notifications
/// without needing to lock the Scanner.
#[derive(Clone, Debug)]
pub struct SpHistoryEntry {
    pub tx_hash: String,
    pub height: u32,
    /// Hex-encoded tweak public key (partial shared secret).
    pub tweak_hex: String,
}

impl WalletElectrumIndex {
    pub fn new() -> Self {
        Self::default()
    }
}

/// Compute the Electrum scripthash for a script.
/// Electrum scripthash = SHA256(script_pubkey), byte-reversed, hex-encoded.
pub fn electrum_scripthash(script: &ScriptBuf) -> String {
    let hash = sha256::Hash::hash(script.as_bytes());
    let mut bytes = hash.to_byte_array();
    bytes.reverse();
    hex::encode(bytes)
}

/// Compute the Electrum status string for a scripthash's history.
/// Returns `None` for an empty history (Electrum uses null in that case).
///
/// Status = SHA256("txhash:height:" concatenated for all entries).to_hex()
pub fn electrum_status(entries: &[ScriptHashEntry]) -> Option<String> {
    if entries.is_empty() {
        return None;
    }
    let status_str: String = entries
        .iter()
        .map(|e| format!("{}:{}:", e.tx_hash, e.height))
        .collect();
    let hash = sha256::Hash::hash(status_str.as_bytes());
    Some(hex::encode(hash.to_byte_array()))
}
