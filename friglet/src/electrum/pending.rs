//! Broadcast transactions that are not confirmed yet.
//!
//! Persisted next to the scanner state so a restart neither forgets them
//! (Sparrow would stop showing a transaction that may still confirm) nor
//! stops re-announcing them. A transaction leaves this list when it
//! confirms, when a confirmed transaction spends one of its inputs, when a
//! newer broadcast replaces it, or when it has been out of the peer's
//! mempool for longer than Bitcoin Core keeps anything in a mempool.
//!
//! The file also keeps, per transaction, every discovered peer friglet
//! handed it to (`sent_to` of a pending one, `handed_to` for one that is not
//! pending: an attempt that ended unconfirmed, or a replaced or expired
//! one). Those peers hold it because friglet gave it to them, so no later
//! attempt or recheck takes their word that it spread.

use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use bitcoin::consensus::encode::deserialize;
use bitcoin::{OutPoint, Transaction};
use blindbit_lib::net::PeerAddr;
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
    /// Discovered peers it was handed to, oldest first: a recheck asks other
    /// peers, whose word is not their own echo. None is forgotten while the
    /// entry lives (at most one more per recheck, every 10 minutes for up to
    /// 14 days). Empty with an own node.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sent_to: Vec<String>,
}

impl PendingTx {
    /// The peers it was handed to (addresses that do not parse are skipped).
    pub fn sent_to(&self) -> HashSet<PeerAddr> {
        parse_peers(&self.sent_to).collect()
    }

    /// Remember that it was handed to `peer`.
    pub fn note_sent_to(&mut self, peer: &PeerAddr) {
        let peer = peer.to_string();
        if !self.sent_to.contains(&peer) {
            self.sent_to.push(peer);
        }
    }
}

/// The discovered peers friglet handed a transaction to that is not
/// pending.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandedTo {
    /// Unix seconds of the latest hand-over, or of when it stopped being
    /// pending.
    pub at: u64,
    pub peers: Vec<String>,
}

/// The file. Before `handed_to` existed it was the bare `pending` map,
/// which still loads ([`AnyFile::Legacy`]).
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoreFile {
    pending: BTreeMap<String, PendingTx>,
    #[serde(default)]
    handed_to: BTreeMap<String, HandedTo>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum AnyFile {
    Current(StoreFile),
    Legacy(BTreeMap<String, PendingTx>),
}

fn parse_peers(peers: &[String]) -> impl Iterator<Item = PeerAddr> + '_ {
    peers
        .iter()
        .filter_map(|addr| addr.parse::<SocketAddr>().ok())
        .map(PeerAddr::from)
}

/// The store as the Electrum server shares it: a broadcast still running
/// writes every peer it hands a transaction to into it (and to disk)
/// before the bytes go out, as a recheck does (a peer that cannot be
/// written to disk gets nothing), and a peer's copy of a
/// transaction counts only while the peer is not in it for that
/// transaction, looked up after the copy arrived. So a broadcast and a
/// recheck running at the same time never take each other's recipients
/// for unrelated peers.
pub type SharedStore = Arc<tokio::sync::Mutex<PendingStore>>;

#[derive(Debug)]
pub struct PendingStore {
    path: PathBuf,
    txs: BTreeMap<String, PendingTx>,
    /// Transactions that are not pending, and who got them: kept until
    /// [`EXPIRY_SECS`] after the latest hand-over, by when a peer that
    /// got it from friglet has dropped it from its mempool.
    handed_to: BTreeMap<String, HandedTo>,
}

impl PendingStore {
    /// Load the store; a missing file is an empty store. An unreadable one is
    /// logged and treated as empty (it is rewritten on the next change).
    pub fn load(path: PathBuf) -> Self {
        let file = match fs::read_to_string(&path) {
            Ok(json) => match serde_json::from_str(&json) {
                Ok(AnyFile::Current(file)) => file,
                Ok(AnyFile::Legacy(pending)) => StoreFile {
                    pending,
                    ..StoreFile::default()
                },
                Err(error) => {
                    tracing::warn!(path = %path.display(), %error, "ignoring unreadable pending-broadcast file");
                    StoreFile::default()
                }
            },
            Err(error) if error.kind() == io::ErrorKind::NotFound => StoreFile::default(),
            Err(error) => {
                tracing::warn!(path = %path.display(), %error, "cannot read pending-broadcast file");
                StoreFile::default()
            }
        };
        let mut store = Self {
            path,
            txs: file.pending,
            handed_to: file.handed_to,
        };
        store.prune();
        store
    }

    /// Write the store to its file. An error (naming the file) means the
    /// file still holds what it held before; the store in memory keeps
    /// every change.
    pub fn save(&self) -> io::Result<()> {
        write_atomic(&self.path, &self.txs, &self.handed_to).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("cannot write {}: {error}", self.path.display()),
            )
        })
    }

    /// Forget who got transactions that are not pending once they would
    /// have expired from those peers' mempools.
    fn prune(&mut self) {
        let now = now_secs();
        self.handed_to
            .retain(|_, handed| now.saturating_sub(handed.at) <= EXPIRY_SECS);
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

    /// Remember an accepted broadcast and the peers it was handed to, on top
    /// of every peer it went to before (earlier attempts, or the pending
    /// entry it already has).
    pub fn insert(&mut self, txid: String, raw_hex: String, sent_to: &[PeerAddr]) {
        let now = now_secs();
        let earlier = self.handed_to.remove(&txid).unwrap_or_default();
        let pending = self.txs.entry(txid).or_insert_with(|| PendingTx {
            raw_hex: String::new(),
            accepted_at: now,
            last_in_mempool: now,
            reannounced: 0,
            sent_to: Vec::new(),
        });
        // The bytes that are in a mempool now (the witness may differ).
        pending.raw_hex = raw_hex;
        pending.last_in_mempool = now;
        for peer in earlier.peers {
            if !pending.sent_to.contains(&peer) {
                pending.sent_to.push(peer);
            }
        }
        for peer in sent_to {
            pending.note_sent_to(peer);
        }
    }

    /// The pending transactions `tx` descends from: its pending parents,
    /// theirs, and so on. Unconfirmed ancestors a peer may lack, which
    /// friglet can hand over (a peer that gets a parent may ask for its
    /// parent next).
    pub fn held_ancestors(&self, tx: &Transaction) -> Vec<Transaction> {
        let mut ancestors = Vec::new();
        let mut seen = HashSet::new();
        let mut next: Vec<String> = tx
            .input
            .iter()
            .map(|input| input.previous_output.txid.to_string())
            .collect();
        while let Some(id) = next.pop() {
            if !seen.insert(id.clone()) {
                continue;
            }
            let Some(parent) = self.txs.get(&id).and_then(|p| decode(&p.raw_hex)) else {
                continue;
            };
            next.extend(
                parent
                    .input
                    .iter()
                    .map(|input| input.previous_output.txid.to_string()),
            );
            ancestors.push(parent);
        }
        ancestors
    }

    /// Every discovered peer `txid` was handed to, pending or not.
    pub fn handed_to(&self, txid: &str) -> HashSet<PeerAddr> {
        let mut peers = self
            .txs
            .get(txid)
            .map(PendingTx::sent_to)
            .unwrap_or_default();
        if let Some(handed) = self.handed_to.get(txid) {
            peers.extend(parse_peers(&handed.peers));
        }
        peers
    }

    /// Remember that `txid` went to `peers`, whatever came of it.
    pub fn note_handed_to(&mut self, txid: &str, peers: &[PeerAddr]) {
        if peers.is_empty() {
            return;
        }
        if let Some(pending) = self.txs.get_mut(txid) {
            for peer in peers {
                pending.note_sent_to(peer);
            }
            return;
        }
        self.keep_handed_to(txid, peers.iter().map(ToString::to_string));
    }

    fn keep_handed_to(&mut self, txid: &str, peers: impl IntoIterator<Item = String>) {
        self.prune();
        let handed = self.handed_to.entry(txid.to_string()).or_default();
        handed.at = now_secs();
        for peer in peers {
            if !handed.peers.contains(&peer) {
                handed.peers.push(peer);
            }
        }
    }

    /// Forget a transaction that confirmed or can never confirm, and who
    /// got it.
    pub fn remove(&mut self, txid: &str) -> Option<PendingTx> {
        self.handed_to.remove(txid);
        self.txs.remove(txid)
    }

    /// Stop showing a transaction that may still be broadcast again (it was
    /// replaced, or expired), but keep who got it.
    pub fn retire(&mut self, txid: &str) -> Option<PendingTx> {
        let pending = self.txs.remove(txid)?;
        if !pending.sent_to.is_empty() {
            self.keep_handed_to(txid, pending.sent_to.iter().cloned());
        }
        Some(pending)
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

/// Write the file owner-only (0600): it names the peers friglet handed the
/// wallet's transactions to. Durable once this returns: the new file is on
/// disk before it replaces the old one, and the replacement too, so a crash
/// or power loss leaves the old file or the new one, never less.
fn write_atomic(
    path: &Path,
    pending: &BTreeMap<String, PendingTx>,
    handed_to: &BTreeMap<String, HandedTo>,
) -> io::Result<()> {
    #[derive(Serialize)]
    struct Borrowed<'a> {
        pending: &'a BTreeMap<String, PendingTx>,
        #[serde(skip_serializing_if = "BTreeMap::is_empty")]
        handed_to: &'a BTreeMap<String, HandedTo>,
    }
    let json =
        serde_json::to_vec_pretty(&Borrowed { pending, handed_to }).map_err(io::Error::other)?;
    let tmp = path.with_extension("json.tmp");
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let mut file = options.open(&tmp)?;
    // `mode` only applies to a file it creates: a leftover one keeps its own.
    #[cfg(unix)]
    file.set_permissions(std::os::unix::fs::PermissionsExt::from_mode(0o600))?;
    io::Write::write_all(&mut file, &json)?;
    file.sync_all()?;
    drop(file);
    fs::rename(&tmp, path)?;
    sync_dir(path)
}

/// Put a rename in `path`'s directory on disk. Only on Unix, where a
/// directory can be opened and synced, and not on a file system that
/// cannot sync one.
fn sync_dir(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        let dir = match path.parent() {
            Some(dir) if !dir.as_os_str().is_empty() => dir,
            _ => Path::new("."),
        };
        if let Err(error) = fs::File::open(dir)?.sync_all()
            && !matches!(
                error.kind(),
                io::ErrorKind::InvalidInput | io::ErrorKind::Unsupported
            )
        {
            return Err(error);
        }
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
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
        let sender: PeerAddr = "203.0.113.5:38333".parse::<SocketAddr>().unwrap().into();
        store.insert("aa".into(), "0100".into(), std::slice::from_ref(&sender));
        store.save().unwrap();

        let reloaded = PendingStore::load(path.clone());
        let entries: Vec<_> = reloaded.entries().collect();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].0, "aa");
        assert_eq!(entries[0].1.raw_hex, "0100");
        assert_eq!(entries[0].1.sent_to(), HashSet::from([sender.clone()]));

        // A file from before `sent_to` existed still loads.
        fs::write(
            &path,
            br#"{"bb":{"raw_hex":"0100","accepted_at":1,"last_in_mempool":1}}"#,
        )
        .unwrap();
        let old = PendingStore::load(path.clone());
        let entries: Vec<_> = old.entries().collect();
        assert_eq!(entries.len(), 1, "the old file loaded");
        assert_eq!(entries[0].0, "bb");
        assert_eq!(entries[0].1.raw_hex, "0100");
        assert!(entries[0].1.sent_to.is_empty());
        // So does one from before `handed_to`, with `sent_to`.
        fs::write(
            &path,
            br#"{"cc":{"raw_hex":"0200","accepted_at":1,"last_in_mempool":1,"sent_to":["203.0.113.5:38333"]}}"#,
        )
        .unwrap();
        let old = PendingStore::load(path.clone());
        assert_eq!(old.handed_to("cc"), HashSet::from([sender]));

        fs::write(&path, b"{broken").unwrap();
        assert!(PendingStore::load(path.clone()).is_empty());
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    /// The file names the peers the wallet's transactions went to: owner
    /// only, also when an earlier write left a readable one behind.
    #[cfg(unix)]
    #[test]
    fn the_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let path = temp_path("mode");
        let tmp = path.with_extension("json.tmp");
        fs::write(&tmp, b"{}").unwrap();
        fs::set_permissions(&tmp, fs::Permissions::from_mode(0o664)).unwrap();
        let mut store = PendingStore::load(path.clone());
        let sender: PeerAddr = "203.0.113.5:38333".parse::<SocketAddr>().unwrap().into();
        store.insert("aa".into(), "0100".into(), &[sender]);
        store.save().unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    fn peer(n: u8) -> PeerAddr {
        SocketAddr::from(([203, 0, 113, n], 38333)).into()
    }

    /// Who got a transaction is kept whatever became of the attempt, across
    /// a restart, and carried into the pending entry once one is accepted.
    #[test]
    fn every_peer_a_transaction_went_to_is_kept() {
        let path = temp_path("handed-to");
        let mut store = PendingStore::load(path.clone());
        // An attempt that ended unconfirmed, then another one.
        store.note_handed_to("aa", &[peer(1), peer(2)]);
        store.note_handed_to("aa", &[peer(2), peer(3)]);
        store.note_handed_to("aa", &[]);
        assert!(store.is_empty(), "not pending");
        store.save().unwrap();

        let mut store = PendingStore::load(path.clone());
        assert_eq!(
            store.handed_to("aa"),
            HashSet::from([peer(1), peer(2), peer(3)])
        );
        // Accepted later: the pending entry keeps the earlier peers.
        store.insert("aa".into(), "0100".into(), &[peer(4)]);
        let all = HashSet::from([peer(1), peer(2), peer(3), peer(4)]);
        assert_eq!(store.handed_to("aa"), all);
        assert_eq!(store.entries().next().unwrap().1.sent_to(), all);
        // Accepted again (a resend): nobody is forgotten.
        store.insert("aa".into(), "0101".into(), &[peer(5)]);
        assert!(store.handed_to("aa").is_superset(&all));
        assert!(store.handed_to("aa").contains(&peer(5)));
        assert_eq!(store.entries().next().unwrap().1.raw_hex, "0101");
        // Replaced: no longer shown, still not asked to confirm it.
        store.retire("aa");
        assert!(store.is_empty());
        store.save().unwrap();
        let mut store = PendingStore::load(path.clone());
        assert_eq!(store.handed_to("aa").len(), 5);
        // Confirmed (or conflicting): nothing more to keep.
        store.remove("aa");
        assert!(store.handed_to("aa").is_empty());
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    /// Who got a transaction that is not pending is forgotten once their
    /// mempools would have expired it.
    #[test]
    fn who_got_a_transaction_is_forgotten_after_the_mempool_expiry() {
        let path = temp_path("handed-to-expiry");
        fs::write(
            &path,
            format!(
                r#"{{"pending":{{}},"handed_to":{{"old":{{"at":1,"peers":["203.0.113.1:38333"]}},"new":{{"at":{},"peers":["203.0.113.2:38333"]}}}}}}"#,
                now_secs() - 60
            ),
        )
        .unwrap();
        let store = PendingStore::load(path.clone());
        assert!(store.handed_to("old").is_empty());
        assert_eq!(store.handed_to("new"), HashSet::from([peer(2)]));
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    /// The pending ancestors of a transaction: parents, theirs and so on,
    /// each once; a confirmed (or unknown) one ends the line.
    #[test]
    fn held_ancestors_go_back_through_every_pending_generation() {
        use bitcoin::absolute::LockTime;
        use bitcoin::transaction::Version;
        use bitcoin::{Amount, ScriptBuf, Sequence, TxIn, TxOut, Witness};
        let spend = |prev: Vec<bitcoin::Txid>| Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: prev
                .into_iter()
                .map(|txid| TxIn {
                    previous_output: OutPoint { txid, vout: 0 },
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                })
                .collect(),
            output: vec![TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: ScriptBuf::new(),
            }],
        };
        let confirmed = bitcoin::hashes::Hash::from_byte_array([7; 32]);
        let grandparent = spend(vec![confirmed]);
        let (left, right) = (
            spend(vec![grandparent.compute_txid()]),
            spend(vec![grandparent.compute_txid(), confirmed]),
        );
        let child = spend(vec![left.compute_txid(), right.compute_txid()]);
        let path = temp_path("ancestors");
        let mut store = PendingStore::load(path.clone());
        for tx in [&grandparent, &left, &right] {
            let raw_hex = hex::encode(bitcoin::consensus::encode::serialize(tx));
            store.insert(tx.compute_txid().to_string(), raw_hex, &[]);
        }
        let held: HashSet<bitcoin::Txid> = store
            .held_ancestors(&child)
            .iter()
            .map(Transaction::compute_txid)
            .collect();
        let expected = [&grandparent, &left, &right].map(Transaction::compute_txid);
        assert_eq!(held, HashSet::from(expected));
        assert_eq!(store.held_ancestors(&child).len(), 3, "each once");
        assert!(store.held_ancestors(&grandparent).is_empty());
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

    /// However many rechecks hand it over again, no peer that got it is
    /// forgotten: a forgotten one would count as unrelated.
    #[test]
    fn sent_to_forgets_no_peer() {
        let mut pending = PendingTx {
            raw_hex: String::new(),
            accepted_at: 0,
            last_in_mempool: 0,
            reannounced: 0,
            sent_to: Vec::new(),
        };
        for n in 0..200 {
            pending.note_sent_to(&peer(n));
        }
        pending.note_sent_to(&peer(19));
        assert_eq!(pending.sent_to.len(), 200);
        assert!(pending.sent_to().contains(&peer(0)));
        assert_eq!(pending.sent_to.first().unwrap(), "203.0.113.0:38333");
        assert_eq!(pending.sent_to.last().unwrap(), "203.0.113.199:38333");
    }
}
