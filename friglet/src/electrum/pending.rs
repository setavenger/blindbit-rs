//! Broadcast transactions that are not confirmed yet.
//!
//! Persisted next to the scanner state so a restart neither forgets them
//! (Sparrow would stop showing a transaction that may still confirm) nor
//! stops re-announcing them. A transaction leaves this list when it
//! confirms, when a confirmed transaction spends one of its inputs, when a
//! newer broadcast replaces it, or when it has been out of the peer's
//! mempool for longer than Bitcoin Core keeps anything in a mempool.

use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use bitcoin::consensus::encode::deserialize;
use bitcoin::{OutPoint, Transaction};
use blindbit_lib::scanner::WalletElectrumIndex;
use serde::{Deserialize, Serialize};

/// Bitcoin Core's default mempool expiry (`-mempoolexpiry`, 336 hours).
pub const EXPIRY_SECS: u64 = 14 * 24 * 60 * 60;

pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default()
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingTx {
    pub raw_hex: String,
    /// Unix seconds of the broadcast the peer accepted.
    pub accepted_at: u64,
    /// Unix seconds the peer last had it in its mempool.
    pub last_in_mempool: u64,
    /// Re-announcements after it went missing from the peer's mempool.
    #[serde(default)]
    pub reannounced: u32,
}

#[derive(Debug)]
pub struct PendingStore {
    path: PathBuf,
    txs: BTreeMap<String, PendingTx>,
}

impl PendingStore {
    /// Load the store; a missing file is an empty store. An unreadable one is
    /// logged and treated as empty (it is rewritten on the next change).
    pub fn load(path: PathBuf) -> Self {
        let txs = match fs::read_to_string(&path) {
            Ok(json) => serde_json::from_str(&json).unwrap_or_else(|error| {
                tracing::warn!(path = %path.display(), %error, "ignoring unreadable pending-broadcast file");
                BTreeMap::new()
            }),
            Err(error) if error.kind() == io::ErrorKind::NotFound => BTreeMap::new(),
            Err(error) => {
                tracing::warn!(path = %path.display(), %error, "cannot read pending-broadcast file");
                BTreeMap::new()
            }
        };
        Self { path, txs }
    }

    pub fn save(&self) {
        if let Err(error) = write_atomic(&self.path, &self.txs) {
            tracing::warn!(path = %self.path.display(), %error, "failed to persist pending broadcasts");
        }
    }

    pub fn is_empty(&self) -> bool {
        self.txs.is_empty()
    }

    pub fn entries(&self) -> impl Iterator<Item = (&String, &PendingTx)> {
        self.txs.iter()
    }

    pub fn get_mut(&mut self, txid: &str) -> Option<&mut PendingTx> {
        self.txs.get_mut(txid)
    }

    pub fn insert(&mut self, txid: String, raw_hex: String) {
        let now = now_secs();
        self.txs.insert(
            txid,
            PendingTx {
                raw_hex,
                accepted_at: now,
                last_in_mempool: now,
                reannounced: 0,
            },
        );
    }

    pub fn remove(&mut self, txid: &str) -> Option<PendingTx> {
        self.txs.remove(txid)
    }

    /// Pending transactions other than `txid` that spend one of `spent`.
    pub fn conflicting(&self, txid: &str, spent: &HashSet<OutPoint>) -> Vec<String> {
        self.txs
            .iter()
            .filter(|(other, _)| other.as_str() != txid)
            .filter(|(_, pending)| {
                decode(&pending.raw_hex).is_some_and(|tx| {
                    tx.input
                        .iter()
                        .any(|input| spent.contains(&input.previous_output))
                })
            })
            .map(|(other, _)| other.clone())
            .collect()
    }
}

fn write_atomic(path: &Path, txs: &BTreeMap<String, PendingTx>) -> io::Result<()> {
    let json = serde_json::to_vec_pretty(txs).map_err(io::Error::other)?;
    let tmp = path.with_extension("json.tmp");
    fs::write(&tmp, json)?;
    fs::rename(&tmp, path)
}

pub fn decode(raw_hex: &str) -> Option<Transaction> {
    deserialize(&hex::decode(raw_hex).ok()?).ok()
}

pub fn spent_outpoints(tx: &Transaction) -> HashSet<OutPoint> {
    tx.input.iter().map(|input| input.previous_output).collect()
}

/// The height at which the index has `txid` confirmed, if it has.
pub fn confirmed_height(index: &WalletElectrumIndex, txid: &str) -> Option<u32> {
    index
        .scripthash_history
        .values()
        .flatten()
        .find(|entry| entry.tx_hash == txid && entry.height > 0)
        .map(|entry| entry.height)
        .or_else(|| {
            index
                .sp_history
                .iter()
                .find(|entry| entry.tx_hash == txid && entry.height > 0)
                .map(|entry| entry.height)
        })
}

/// A confirmed wallet transaction (other than `txid`) that spends one of
/// `spent`: proof that `txid` can never confirm.
pub fn confirmed_conflict(
    index: &WalletElectrumIndex,
    txid: &str,
    spent: &HashSet<OutPoint>,
) -> Option<String> {
    index.txs.iter().find_map(|(other, raw)| {
        if other == txid || confirmed_height(index, other).is_none() {
            return None;
        }
        let tx: Transaction = deserialize(raw).ok()?;
        tx.input
            .iter()
            .any(|input| spent.contains(&input.previous_output))
            .then(|| other.clone())
    })
}

/// Take an unconfirmed transaction back out of the index: its height-0
/// history entries, its pending-promotion record and, unless it is confirmed
/// somewhere, its raw bytes. Returns whether anything changed.
pub fn unindex_unconfirmed(index: &mut WalletElectrumIndex, txid: &str) -> bool {
    let mut changed = false;
    for history in index.scripthash_history.values_mut() {
        let before = history.len();
        history.retain(|entry| !(entry.tx_hash == txid && entry.height == 0));
        changed |= history.len() != before;
    }
    index
        .scripthash_history
        .retain(|_, history| !history.is_empty());
    changed |= index.pending_scripthashes.remove(txid).is_some();
    if confirmed_height(index, txid).is_none() {
        changed |= index.txs.remove(txid).is_some();
    }
    changed
}

#[cfg(test)]
mod tests {
    use super::*;
    use blindbit_lib::scanner::ScriptHashEntry;

    fn temp_path(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "friglet-pending-test-{}-{tag}-{}",
            std::process::id(),
            now_secs()
        ));
        fs::create_dir_all(&dir).unwrap();
        dir.join("scanner_state.pending.json")
    }

    fn entry(txid: &str, height: u32) -> ScriptHashEntry {
        ScriptHashEntry {
            tx_hash: txid.into(),
            height,
            fee: 0,
        }
    }

    #[test]
    fn store_survives_a_restart() {
        let path = temp_path("roundtrip");
        let mut store = PendingStore::load(path.clone());
        assert!(store.is_empty());
        store.insert("aa".into(), "0100".into());
        store.save();

        let reloaded = PendingStore::load(path.clone());
        let entries: Vec<_> = reloaded.entries().collect();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].0, "aa");
        assert_eq!(entries[0].1.raw_hex, "0100");

        fs::write(&path, b"{broken").unwrap();
        assert!(PendingStore::load(path.clone()).is_empty());
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn unindexing_keeps_confirmed_entries() {
        let mut index = WalletElectrumIndex::new();
        index
            .scripthash_history
            .insert("sh1".into(), vec![entry("old", 100), entry("tx", 0)]);
        index
            .scripthash_history
            .insert("sh2".into(), vec![entry("tx", 0)]);
        index
            .pending_scripthashes
            .insert("tx".into(), vec!["sh1".into(), "sh2".into()]);
        index.txs.insert("tx".into(), vec![1]);
        index.txs.insert("old".into(), vec![2]);

        assert!(unindex_unconfirmed(&mut index, "tx"));
        assert_eq!(index.scripthash_history["sh1"].len(), 1);
        assert!(!index.scripthash_history.contains_key("sh2"));
        assert!(!index.pending_scripthashes.contains_key("tx"));
        assert!(!index.txs.contains_key("tx"));
        assert!(index.txs.contains_key("old"));
        assert!(
            !unindex_unconfirmed(&mut index, "tx"),
            "second call changes nothing"
        );
    }

    #[test]
    fn confirmed_height_ignores_unconfirmed_entries() {
        let mut index = WalletElectrumIndex::new();
        index
            .scripthash_history
            .insert("sh".into(), vec![entry("tx", 0)]);
        assert_eq!(confirmed_height(&index, "tx"), None);
        index
            .scripthash_history
            .insert("sh2".into(), vec![entry("tx", 321)]);
        assert_eq!(confirmed_height(&index, "tx"), Some(321));
    }
}
