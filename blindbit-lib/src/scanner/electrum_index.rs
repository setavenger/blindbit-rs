//! Wallet-scoped Electrum index for friglet's single-server mode.
//!
//! Populated incrementally during scanning. Only contains data for outputs
//! confirmed to belong to this wallet — no chain-wide indexing.

use bitcoin::hashes::{Hash, sha256};
use bitcoin::secp256k1::PublicKey;
use bitcoin::{OutPoint, ScriptBuf, Transaction, Txid};
use indexer::bdk_chain::ConfirmationBlockTime;
use indexer::v2::SpIndexerV2;
use std::collections::{BTreeMap, HashMap, HashSet};

use super::health::ScanHealth;

/// Lightweight Electrum-compatible index built from scanner state.
#[derive(Default)]
pub struct WalletElectrumIndex {
    /// txid hex → consensus-serialized raw tx bytes of wallet transactions:
    /// added when a scanned block holds one, rebuilt from the wallet graph on
    /// restore, and by friglet's broadcast handler.
    pub txs: HashMap<String, Vec<u8>>,

    /// block height → 80-byte header hex: every block the scan fetched,
    /// plus the headers friglet fetches or reloads from its header sidecar.
    pub headers: HashMap<u32, String>,

    /// Electrum scripthash hex → ordered history entries.
    /// One entry per wallet output (confirmed SP receive / spend output).
    pub scripthash_history: HashMap<String, Vec<ScriptHashEntry>>,

    /// txid hex → set of scripthashes that have a `height: 0` entry for this tx.
    ///
    /// Populated by `index_unconfirmed_tx` (the broadcast handler) for every
    /// output and resolved input of a just-broadcast transaction.  When the
    /// block that includes the tx is later scanned, all those `height: 0`
    /// entries are promoted to the confirmed block height — including regular
    /// non-SP outputs (change to a taproot address, recipient, etc.) that the
    /// SP scanner would otherwise never update.
    pub pending_scripthashes: HashMap<String, Vec<String>>,

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

    /// Stalls and start-height adjustments of the running scan, published
    /// here for status readers (see `scanner/health.rs`).
    pub scan_health: ScanHealth,
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

/// What an index update needs to know about the wallet: which outpoints are
/// its outputs, the script of each (so a spend is filed under the scripthash
/// of the output it consumes), and the silent-payment tweak of each
/// transaction that paid it.
pub(crate) struct WalletView<'a> {
    outpoints: HashSet<OutPoint>,
    scripts: HashMap<OutPoint, ScriptBuf>,
    tweaks: &'a BTreeMap<Txid, PublicKey>,
}

impl<'a> WalletView<'a> {
    /// Taken from the wallet's index and graph. Build it after the block
    /// being indexed was applied, so an output received and spent in that
    /// same block counts.
    pub(crate) fn of(indexer: &'a SpIndexerV2<ConfirmationBlockTime>) -> Self {
        let outpoints: HashSet<OutPoint> =
            indexer.index().by_shared_secret.keys().cloned().collect();
        let mut scripts = HashMap::new();
        for node in indexer.graph().full_txs() {
            for (vout, out) in node.tx.output.iter().enumerate() {
                let op = OutPoint {
                    txid: node.txid,
                    vout: vout as u32,
                };
                if outpoints.contains(&op) {
                    scripts.insert(op, out.script_pubkey.clone());
                }
            }
        }
        Self {
            outpoints,
            scripts,
            tweaks: &indexer.index().txid_to_partial_secret,
        }
    }
}

impl WalletElectrumIndex {
    pub fn new() -> Self {
        Self::default()
    }

    /// Lists `tx_hash` at `height` in a scripthash's history, which stays
    /// sorted by height (unconfirmed entries, height 0, first). A transaction
    /// the history already lists keeps its entry, except that an unconfirmed
    /// one (added by friglet's broadcast handler) is promoted when the
    /// transaction confirms (`height > 0`). Returns whether it added an
    /// entry.
    pub fn add_history(&mut self, scripthash: String, tx_hash: &str, height: u32) -> bool {
        let history = self.scripthash_history.entry(scripthash).or_default();
        match history.iter().position(|e| e.tx_hash == tx_hash) {
            Some(pos) if history[pos].height == 0 && height > 0 => {
                history[pos].height = height;
                history.sort_by_key(|e| e.height);
                false
            }
            Some(_) => false,
            None => {
                let entry = ScriptHashEntry {
                    tx_hash: tx_hash.to_owned(),
                    height,
                    fee: 0,
                };
                history.insert(insertion_point(history, |e| e.height, height), entry);
                true
            }
        }
    }

    /// Indexes a transaction confirmed at `height`: lists it under the
    /// scripthash of every wallet output it pays and of every wallet output
    /// it spends (Sparrow expects a spend in the history of the scripthash it
    /// spends), keeps its raw bytes for `blockchain.transaction.get` when it
    /// does either, and lists it in the SP history when it paid the wallet a
    /// silent payment.
    pub(crate) fn index_confirmed_tx(
        &mut self,
        tx: &Transaction,
        txid: Txid,
        height: u32,
        wallet: &WalletView,
    ) {
        // Formatted only for a wallet transaction: a matched block is
        // indexed whole, and most of its transactions are not the wallet's.
        let mut tx_hash: Option<String> = None;
        for (vout, output) in tx.output.iter().enumerate() {
            let outpoint = OutPoint {
                txid,
                vout: vout as u32,
            };
            if wallet.outpoints.contains(&outpoint) {
                let tx_hash = tx_hash.get_or_insert_with(|| txid.to_string());
                self.add_history(electrum_scripthash(&output.script_pubkey), tx_hash, height);
            }
        }
        for input in &tx.input {
            if let Some(script) = wallet.scripts.get(&input.previous_output) {
                let tx_hash = tx_hash.get_or_insert_with(|| txid.to_string());
                self.add_history(electrum_scripthash(script), tx_hash, height);
            }
        }
        if let Some(tx_hash) = tx_hash {
            self.txs
                .insert(tx_hash, bitcoin::consensus::encode::serialize(tx));
        }
        if let Some(tweak) = wallet.tweaks.get(&txid) {
            self.add_sp_history(txid, height, tweak);
        }
    }

    /// Lists a silent-payment transaction confirmed at `height`, with its
    /// tweak, in the SP history, which stays sorted by height. A transaction
    /// already listed keeps its entry.
    fn add_sp_history(&mut self, txid: Txid, height: u32, tweak: &PublicKey) {
        let tx_hash = txid.to_string();
        if !self.sp_history.iter().any(|e| e.tx_hash == tx_hash) {
            let entry = SpHistoryEntry {
                tx_hash,
                height,
                tweak_hex: tweak.to_string(),
            };
            let at = insertion_point(&self.sp_history, |e| e.height, height);
            self.sp_history.insert(at, entry);
        }
    }

    /// Height to report as the chain tip once `scanned` is scanned. While a
    /// restored state is rescanned for missed spends (`scan_health.
    /// state_rescan`), the tip stays at the height the state had reached, so
    /// clients never see wallet history above the tip.
    pub fn tip_height_for(&self, scanned: u32) -> u32 {
        match self.scan_health.state_rescan {
            Some(rescan) => scanned.max(u32::try_from(rescan.until_height).unwrap_or(u32::MAX)),
            None => scanned,
        }
    }
}

/// Where an entry at `height` goes in a list sorted by height: after every
/// entry at the same or a lower height, which is where pushing it and then
/// stably sorting the list would put it.
fn insertion_point<T>(sorted: &[T], height_of: impl Fn(&T) -> u32, height: u32) -> usize {
    sorted.partition_point(|e| height_of(e) <= height)
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
