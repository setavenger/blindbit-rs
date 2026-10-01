//! Chain reorganisations through the live scan path.
//!
//! The scenario mirrors the testkit's T2 `reorg` scenario: a wallet scans a
//! chain, then the oracle switches to a branch that forks at height 104.
//! Blocks above the fork are disconnected; one payment re-confirms on the new
//! branch at a different height, one is evicted. Each test drives a real
//! [`Scanner`] through `scan_range_from`, the body of `scan_block_range`,
//! against an in-process oracle; only the P2P block fetch is replaced (full
//! blocks are served by `stream_safety_tests::serve`).

use std::collections::{BTreeMap, VecDeque};
use std::future::Future;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use bdk_sp::bitcoin::key::Secp256k1;
use bdk_sp::receive::get_silentpayment_pubkey;
use bitcoin::absolute::LockTime;
use bitcoin::hashes::{Hash, sha256d};
use bitcoin::key::TweakedPublicKey;
use bitcoin::secp256k1::{PublicKey, SecretKey};
use bitcoin::transaction::Version;
use bitcoin::{
    Amount, Block, BlockHash, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid,
    Witness, XOnlyPublicKey,
};
use bitcoin_rev::Network;
use tonic::transport::Channel;

use super::health::{OracleProbe, indexed_block_hash};
use super::reorg::ReorgTooDeep;
use super::scanning::{BlockScanDataStream, BlockStreamSource};
use super::stream_safety_tests::serve;
use super::{REORG_LOOKBACK, Scanner, ScannerError};
use crate::oracle_grpc::{
    BlockHashResponse, BlockIdentifier, BlockScanDataShortResponse, ComputeIndexTxItem,
};
use prost::Message as _;

const FORK: u64 = 104;

// ---------------------------------------------------------------------------
// In-process oracle
// ---------------------------------------------------------------------------

type Message = BlockScanDataShortResponse;

/// One chain as the oracle serves it: height -> block message.
#[derive(Clone, Default)]
struct Oracle {
    chain: BTreeMap<u64, Message>,
    /// Ends a stream with an UNAVAILABLE status at this height, if the
    /// stream began below it (so the first block of a stream is always
    /// served).
    fail_at: Option<u64>,
    /// What the scanner asked of this oracle (shared by its clones).
    traffic: Arc<Traffic>,
}

/// Requests and response payload bytes (gRPC message plus its 5-byte frame
/// header), as the oracle would send them.
#[derive(Default)]
struct Traffic {
    streams: AtomicUsize,
    streamed_blocks: AtomicUsize,
    streamed_bytes: AtomicUsize,
    lookups: AtomicUsize,
    lookup_bytes: AtomicUsize,
}

impl Traffic {
    fn take(&self) -> [usize; 5] {
        [
            self.streams.swap(0, Ordering::SeqCst),
            self.streamed_blocks.swap(0, Ordering::SeqCst),
            self.streamed_bytes.swap(0, Ordering::SeqCst),
            self.lookups.swap(0, Ordering::SeqCst),
            self.lookup_bytes.swap(0, Ordering::SeqCst),
        ]
    }
}

struct ChainStream(VecDeque<Result<Message, tonic::Status>>);

impl BlockScanDataStream for ChainStream {
    fn next_message(
        &mut self,
    ) -> impl Future<Output = Result<Option<Message>, tonic::Status>> + Send {
        std::future::ready(self.0.pop_front().transpose())
    }
}

impl BlockStreamSource for Oracle {
    type Stream = ChainStream;

    async fn open(&mut self, start: u64, end: u64) -> Result<ChainStream, ScannerError> {
        self.traffic.streams.fetch_add(1, Ordering::SeqCst);
        let mut items = VecDeque::new();
        for height in start..=end {
            if self.fail_at == Some(height) && start < height {
                items.push_back(Err(tonic::Status::unavailable("connection reset")));
                break;
            }
            match self.chain.get(&height) {
                Some(message) => {
                    self.traffic.streamed_blocks.fetch_add(1, Ordering::SeqCst);
                    self.traffic
                        .streamed_bytes
                        .fetch_add(message.encoded_len() + 5, Ordering::SeqCst);
                    items.push_back(Ok(message.clone()))
                }
                None => break,
            }
        }
        Ok(ChainStream(items))
    }
}

impl OracleProbe for Oracle {
    async fn block_hash_at(&mut self, height: u64) -> Result<Option<BlockHash>, ScannerError> {
        let block_hash = self
            .chain
            .get(&height)
            .and_then(|m| m.block_identifier.as_ref())
            .map(|id| id.block_hash.clone())
            .unwrap_or_default();
        self.traffic.lookups.fetch_add(1, Ordering::SeqCst);
        self.traffic.lookup_bytes.fetch_add(
            BlockHashResponse {
                block_hash: block_hash.clone(),
            }
            .encoded_len()
                + 5,
            Ordering::SeqCst,
        );
        Ok(indexed_block_hash(&block_hash))
    }
}

impl Oracle {
    fn tip(&self) -> u64 {
        *self.chain.keys().next_back().expect("non-empty chain")
    }

    /// A copy of this chain up to and including `fork`, as the start of a
    /// competing branch.
    fn branch_at(&self, fork: u64) -> Oracle {
        Oracle {
            chain: self
                .chain
                .range(..=fork)
                .map(|(h, m)| (*h, m.clone()))
                .collect(),
            fail_at: None,
            traffic: Arc::default(),
        }
    }

    fn empty(&mut self, branch: u8, height: u64) {
        let hash = sha256d::Hash::hash(&[&[branch][..], &height.to_le_bytes()].concat());
        self.chain.insert(
            height,
            message(BlockHash::from_raw_hash(hash), height, vec![], &[]),
        );
    }

    /// A block holding `txs` (payments carry their served tweak), served in
    /// place of P2P.
    fn block(
        &mut self,
        branch: u8,
        height: u64,
        txs: Vec<(Transaction, Option<PublicKey>)>,
        spent: &[XOnlyPublicKey],
    ) {
        let items = txs
            .iter()
            .filter_map(|(tx, tweak)| tweak.map(|tweak| item(tx, tweak)))
            .collect();
        let block = full_block(branch, height, txs.into_iter().map(|(tx, _)| tx).collect());
        serve(&block);
        self.chain
            .insert(height, message(block.block_hash(), height, items, spent));
    }
}

fn message(
    hash: BlockHash,
    height: u64,
    comp_index: Vec<ComputeIndexTxItem>,
    spent: &[XOnlyPublicKey],
) -> Message {
    // The oracle serves hashes in display order.
    let mut display = hash.to_byte_array();
    display.reverse();
    BlockScanDataShortResponse {
        block_identifier: Some(BlockIdentifier {
            block_hash: display.to_vec(),
            block_height: height,
        }),
        comp_index,
        spent_outputs: spent
            .iter()
            .flat_map(|key| key.serialize()[..8].to_vec())
            .collect(),
    }
}

fn item(tx: &Transaction, tweak: PublicKey) -> ComputeIndexTxItem {
    let mut txid = tx.compute_txid().to_byte_array();
    txid.reverse();
    ComputeIndexTxItem {
        txid: txid.to_vec(),
        tweak: tweak.serialize().to_vec(),
        outputs_short: tx
            .output
            .iter()
            .flat_map(|o| o.script_pubkey.as_bytes()[2..10].to_vec())
            .collect(),
    }
}

fn full_block(branch: u8, height: u64, txs: Vec<Transaction>) -> Block {
    let coinbase = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::from_bytes([&[branch][..], &height.to_le_bytes()].concat()),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(312_500_000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x6a]),
        }],
    };
    let mut txdata = vec![coinbase];
    txdata.extend(txs);
    let mut block = Block {
        header: bitcoin::block::Header {
            version: bitcoin::block::Version::TWO,
            prev_blockhash: BlockHash::all_zeros(),
            merkle_root: bitcoin::TxMerkleNode::all_zeros(),
            time: 1_713_571_767 + height as u32,
            bits: bitcoin::CompactTarget::from_consensus(0x207f_ffff),
            nonce: u32::from(branch),
        },
        txdata,
    };
    block.header.merkle_root = block.compute_merkle_root().expect("non-empty block");
    block
}

// ---------------------------------------------------------------------------
// Wallet
// ---------------------------------------------------------------------------

fn secret(byte: u8) -> SecretKey {
    SecretKey::from_slice(&[byte; 32]).expect("valid secret")
}

fn keys() -> (SecretKey, PublicKey) {
    (secret(0x11), secret(0x22).public_key(&Secp256k1::new()))
}

fn state_file(tag: &str) -> PathBuf {
    std::env::temp_dir().join(format!("blindbit-reorg-{tag}-{}.json", std::process::id()))
}

struct TempState(PathBuf);

impl Drop for TempState {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn client() -> crate::OracleServiceClient<Channel> {
    crate::OracleServiceClient::new(Channel::from_static("http://127.0.0.1:1").connect_lazy())
}

fn socket() -> SocketAddr {
    "127.0.0.1:1".parse().expect("socket address")
}

/// A fresh wallet. Must be called inside a Tokio runtime.
fn wallet(tag: &str) -> (Scanner, TempState) {
    let (scan_sk, spend_pk) = keys();
    let path = state_file(tag);
    let _ = std::fs::remove_file(&path);
    let scanner = Scanner::new(
        client(),
        socket(),
        scan_sk,
        spend_pk,
        0,
        path.clone(),
        Network::Regtest,
    );
    (scanner, TempState(path))
}

/// The wallet as a restarted daemon loads it from its state file.
#[cfg(feature = "serde")]
fn restart(path: &std::path::Path) -> Scanner {
    let changeset = Scanner::load_from_file(path).expect("load state");
    Scanner::from_changeset(
        client(),
        socket(),
        changeset,
        path.to_path_buf(),
        Network::Regtest,
    )
    .expect("restore")
}

/// A payment of `sat` to the wallet's unlabelled address; the tweak the
/// oracle serves for it and the paid outpoint.
fn payment(seed: u8, sat: u64) -> (Transaction, PublicKey, OutPoint, XOnlyPublicKey) {
    let (scan_sk, spend_pk) = keys();
    let tweak = secret(seed).public_key(&Secp256k1::new());
    let shared = bdk_sp::compute_shared_secret(&scan_sk, &tweak);
    let key = get_silentpayment_pubkey(&spend_pk, &shared, 0, None)
        .x_only_public_key()
        .0;
    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::new(Txid::from_byte_array([seed; 32]), 0),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(sat),
            script_pubkey: p2tr(key),
        }],
    };
    let outpoint = OutPoint::new(tx.compute_txid(), 0);
    (tx, tweak, outpoint, key)
}

/// A spend of `outpoint` to a foreign key.
fn spend_of(outpoint: OutPoint) -> Transaction {
    let foreign = secret(0x66)
        .public_key(&Secp256k1::new())
        .x_only_public_key()
        .0;
    Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: outpoint,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(1_000),
            script_pubkey: p2tr(foreign),
        }],
    }
}

fn p2tr(key: XOnlyPublicKey) -> ScriptBuf {
    ScriptBuf::new_p2tr_tweaked(TweakedPublicKey::dangerous_assume_tweaked(key))
}

fn run<F: Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime")
        .block_on(future)
}

/// One `watch_chain` iteration against `oracle`.
async fn watch_step(scanner: &mut Scanner, oracle: &Oracle) -> Result<(), ScannerError> {
    let tip = oracle.tip();
    let last = scanner.get_last_scanned_block_height();
    let (from, to) = if tip > last {
        (last + 1, tip)
    } else {
        (tip + 1, tip)
    };
    scanner.scan_range_from(from, to, oracle.clone()).await
}

/// Sum of the unspent owned outputs: the wallet balance.
fn balance(scanner: &Scanner) -> u64 {
    scanner
        .owned_outputs()
        .filter(|r| !r.is_spent())
        .map(|r| r.amount_sat)
        .sum()
}

fn owned_height(scanner: &Scanner, outpoint: OutPoint) -> Option<u32> {
    scanner
        .owned_outputs()
        .find(|r| r.outpoint == outpoint)
        .map(|r| r.height)
}

/// Heights at which the wallet graph holds `txid` confirmed.
fn anchor_heights(scanner: &Scanner, txid: Txid) -> Vec<u32> {
    scanner
        .internal_indexer
        .graph()
        .get_tx_node(txid)
        .map(|node| node.anchors.iter().map(|a| a.block_id.height).collect())
        .unwrap_or_default()
}

async fn sp_history(scanner: &Scanner) -> Vec<(String, u32)> {
    let idx = scanner.electrum_index.lock().await;
    idx.sp_history
        .iter()
        .map(|e| (e.tx_hash.clone(), e.height))
        .collect()
}

async fn in_scripthash_history(scanner: &Scanner, txid: Txid) -> bool {
    let idx = scanner.electrum_index.lock().await;
    idx.scripthash_history
        .values()
        .flatten()
        .any(|e| e.tx_hash == txid.to_string())
}

// ---------------------------------------------------------------------------
// The T2 scenario: fork at 104, 2 blocks disconnected, 3 mined
// ---------------------------------------------------------------------------

struct Scenario {
    old: Oracle,
    new: Oracle,
    survivor: OutPoint,
    reconfirmed: OutPoint,
    evicted: OutPoint,
}

/// Old chain: 101 pays `survivor`, 105 pays `reconfirmed`, 106 pays
/// `evicted`. New chain forks at 104: 105' is empty, 106' re-confirms
/// `reconfirmed`, 107' is empty; `evicted` never confirms again.
fn scenario() -> Scenario {
    let (survivor_tx, survivor_tweak, survivor, _) = payment(0x31, 50_000);
    let (keep_tx, keep_tweak, reconfirmed, _) = payment(0x32, 30_000);
    let (evict_tx, evict_tweak, evicted, _) = payment(0x33, 20_000);

    let mut old = Oracle::default();
    old.block(0xa, 101, vec![(survivor_tx, Some(survivor_tweak))], &[]);
    for h in 102..=FORK {
        old.empty(0xa, h);
    }
    old.block(0xa, 105, vec![(keep_tx.clone(), Some(keep_tweak))], &[]);
    old.block(0xa, 106, vec![(evict_tx, Some(evict_tweak))], &[]);

    let mut new = old.branch_at(FORK);
    new.empty(0xb, 105);
    new.block(0xb, 106, vec![(keep_tx, Some(keep_tweak))], &[]);
    new.empty(0xb, 107);

    Scenario {
        old,
        new,
        survivor,
        reconfirmed,
        evicted,
    }
}

async fn scan_old_chain(scanner: &mut Scanner, s: &Scenario) {
    scanner
        .scan_range_from(101, s.old.tip(), s.old.clone())
        .await
        .expect("old chain scans");
    assert_eq!(balance(scanner), 100_000, "all three payments found");
}

#[test]
fn reorg_evicting_a_payment_drops_its_output_and_balance() {
    run(async {
        let (mut scanner, _state) = wallet("evict");
        let s = scenario();
        scan_old_chain(&mut scanner, &s).await;

        watch_step(&mut scanner, &s.new)
            .await
            .expect("new branch scans");

        assert_eq!(
            owned_height(&scanner, s.evicted),
            None,
            "evicted output is gone"
        );
        assert!(
            !scanner
                .internal_indexer
                .index()
                .by_shared_secret
                .contains_key(&s.evicted),
            "evicted output left the index"
        );
        assert!(anchor_heights(&scanner, s.evicted.txid).is_empty());
        assert_eq!(balance(&scanner), 80_000, "balance no longer counts it");
        assert!(
            !sp_history(&scanner)
                .await
                .iter()
                .any(|(txid, _)| *txid == s.evicted.txid.to_string()),
            "evicted tx left the SP history"
        );
        assert!(!in_scripthash_history(&scanner, s.evicted.txid).await);
        assert_eq!(owned_height(&scanner, s.survivor), Some(101));
        assert_eq!(scanner.get_last_scanned_block_height(), 107);
    });
}

#[test]
fn reorg_reconfirming_a_payment_keeps_it_at_its_new_height() {
    run(async {
        let (mut scanner, _state) = wallet("reconfirm");
        let s = scenario();
        scan_old_chain(&mut scanner, &s).await;
        assert_eq!(owned_height(&scanner, s.reconfirmed), Some(105));

        watch_step(&mut scanner, &s.new)
            .await
            .expect("new branch scans");

        assert_eq!(
            owned_height(&scanner, s.reconfirmed),
            Some(106),
            "found again, at its new height"
        );
        assert_eq!(anchor_heights(&scanner, s.reconfirmed.txid), vec![106]);
        let history = sp_history(&scanner).await;
        assert!(history.contains(&(s.reconfirmed.txid.to_string(), 106)));
        assert!(!history.contains(&(s.reconfirmed.txid.to_string(), 105)));
    });
}

/// The fork replaces the tip without making the chain longer: the watch
/// loop's check with no new block still finds it.
#[test]
fn same_height_tip_replacement_is_detected_without_a_new_block() {
    run(async {
        let (mut scanner, _state) = wallet("same-height");
        let s = scenario();
        scan_old_chain(&mut scanner, &s).await;

        let mut replaced = s.old.branch_at(105);
        replaced.empty(0xc, 106);
        assert_eq!(replaced.tip(), scanner.get_last_scanned_block_height());
        watch_step(&mut scanner, &replaced)
            .await
            .expect("check succeeds");

        assert_eq!(owned_height(&scanner, s.evicted), None);
        assert_eq!(owned_height(&scanner, s.reconfirmed), Some(105));
        assert_eq!(balance(&scanner), 80_000);
        assert_eq!(scanner.get_last_scanned_block_height(), 106);
    });
}

#[test]
fn reorg_disconnecting_a_spend_makes_the_output_unspent_again() {
    run(async {
        let (mut scanner, _state) = wallet("unspend");
        let (recv_tx, tweak, outpoint, key) = payment(0x41, 50_000);
        let mut old = Oracle::default();
        old.block(0xa, 101, vec![(recv_tx, Some(tweak))], &[]);
        for h in 102..=FORK {
            old.empty(0xa, h);
        }
        let spend = spend_of(outpoint);
        old.block(0xa, 105, vec![(spend.clone(), None)], &[key]);
        let mut new = old.branch_at(FORK);
        new.empty(0xb, 105);
        new.empty(0xb, 106);

        scanner
            .scan_range_from(101, 105, old.clone())
            .await
            .expect("old chain scans");
        let spent_by = scanner
            .owned_outputs()
            .find(|r| r.outpoint == outpoint)
            .and_then(|r| r.spent_by);
        assert_eq!(spent_by, Some(spend.compute_txid()));
        assert_eq!(balance(&scanner), 0);

        watch_step(&mut scanner, &new)
            .await
            .expect("new branch scans");

        let record = scanner
            .owned_outputs()
            .find(|r| r.outpoint == outpoint)
            .cloned()
            .expect("output still owned");
        assert_eq!((record.spent_by, record.spent_height), (None, None));
        assert_eq!(balance(&scanner), 50_000, "the output is spendable again");
        assert!(anchor_heights(&scanner, spend.compute_txid()).is_empty());
        assert!(!in_scripthash_history(&scanner, spend.compute_txid()).await);
        // Its prefix is watched again, so a later spend is still detected.
        assert!(scanner.owned_prefixes.contains_key(&record.short_pubkey()));
    });
}

/// Hashes are persisted, so a daemon restarted after the reorg still finds
/// it; the rollback is persisted before the new branch is scanned, so a scan
/// that dies right after it leaves no phantom output on disk; and resuming
/// from that state ends up exactly where an uninterrupted scan does.
#[cfg(feature = "serde")]
#[test]
fn rollback_is_persisted_and_restart_mid_rescan_is_safe() {
    run(async {
        let (mut scanner, state) = wallet("restart");
        let s = scenario();
        scan_old_chain(&mut scanner, &s).await;
        drop(scanner);

        let json: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&state.0).unwrap()).unwrap();
        assert_eq!(
            json["scanned_block_hashes"].as_object().map(|m| m.len()),
            Some(6),
            "every scanned height's hash is persisted"
        );

        // Restart after the reorg. The scan locates the fork, rolls back,
        // scans 105' and then its stream dies before 106'.
        let mut restarted = restart(&state.0);
        let mut flaky = s.new.clone();
        flaky.fail_at = Some(106);
        watch_step(&mut restarted, &flaky)
            .await
            .expect_err("the stream fails mid-rescan");
        drop(restarted);

        // The rollback to the fork point is on disk; 105' was scanned but
        // not yet saved, so it is simply scanned again.
        let mut resumed = restart(&state.0);
        assert_eq!(resumed.get_last_scanned_block_height(), FORK);
        assert_eq!(
            owned_height(&resumed, s.evicted),
            None,
            "no phantom on disk"
        );
        assert_eq!(
            owned_height(&resumed, s.reconfirmed),
            None,
            "not re-found yet"
        );
        assert_eq!(balance(&resumed), 50_000);

        watch_step(&mut resumed, &s.new).await.expect("resume");
        assert_eq!(owned_height(&resumed, s.reconfirmed), Some(106));
        assert_eq!(owned_height(&resumed, s.evicted), None);
        assert_eq!(balance(&resumed), 80_000);
        assert_eq!(resumed.get_last_scanned_block_height(), 107);

        let resumed_again = restart(&state.0);
        assert_eq!(balance(&resumed_again), 80_000, "final state is persisted");
    });
}

/// A fork below every remembered hash cannot be located: the scan fails
/// loudly with `ReorgTooDeep`, on every attempt, and leaves the state (in
/// memory and on disk) exactly as it was.
#[test]
fn reorg_deeper_than_the_lookback_is_a_loud_error_and_changes_nothing() {
    run(async {
        let (mut scanner, state) = wallet("too-deep");
        let (recv_tx, tweak, outpoint, _) = payment(0x51, 50_000);
        let tip = 101 + u64::from(REORG_LOOKBACK) + 10;
        let mut old = Oracle::default();
        old.block(0xa, 101, vec![(recv_tx, Some(tweak))], &[]);
        for h in 102..=tip {
            old.empty(0xa, h);
        }
        let mut new = old.branch_at(101);
        for h in 102..=tip + 1 {
            new.empty(0xb, h);
        }

        scanner
            .scan_range_from(101, tip, old.clone())
            .await
            .expect("old chain scans");
        assert_eq!(
            scanner.scanned_block_hashes.len(),
            REORG_LOOKBACK as usize,
            "only the lookback window is remembered"
        );
        let hashes = scanner.scanned_block_hashes.clone();
        let records: Vec<_> = scanner.owned_outputs().cloned().collect();
        let on_disk = std::fs::read(&state.0).ok();

        for _ in 0..2 {
            let err = watch_step(&mut scanner, &new)
                .await
                .expect_err("a reorg below the lookback must fail");
            let deep = err
                .downcast_ref::<ReorgTooDeep>()
                .unwrap_or_else(|| panic!("expected ReorgTooDeep, got: {err}"));
            assert_eq!(
                deep.lowest_known_height,
                tip - u64::from(REORG_LOOKBACK) + 1
            );
            assert!(err.to_string().contains("rescan"), "says what to do: {err}");
        }

        assert_eq!(scanner.get_last_scanned_block_height(), tip);
        assert_eq!(scanner.scanned_block_hashes, hashes);
        assert_eq!(
            scanner.owned_outputs().cloned().collect::<Vec<_>>(),
            records
        );
        assert_eq!(owned_height(&scanner, outpoint), Some(101));
        assert_eq!(
            std::fs::read(&state.0).ok(),
            on_disk,
            "state file untouched"
        );
    });
}

/// With no reorg, the watch loop's check changes nothing, and continuing
/// the chain still scans new blocks.
#[test]
fn unchanged_chain_passes_the_check() {
    run(async {
        let (mut scanner, _state) = wallet("unchanged");
        let s = scenario();
        scan_old_chain(&mut scanner, &s).await;

        watch_step(&mut scanner, &s.old).await.expect("check");
        assert_eq!(scanner.get_last_scanned_block_height(), 106);
        assert_eq!(balance(&scanner), 100_000);

        let mut longer = s.old.clone();
        longer.empty(0xa, 107);
        watch_step(&mut scanner, &longer).await.expect("extend");
        assert_eq!(scanner.get_last_scanned_block_height(), 107);
        assert_eq!(balance(&scanner), 100_000);
    });
}

// ---------------------------------------------------------------------------
// What a poll costs, and an oracle that switches branches mid-stream
// ---------------------------------------------------------------------------

/// An oracle that switches from `before` to `after` once a stream has
/// delivered `switch_after` blocks; lookups answer from the current branch.
#[derive(Clone)]
struct SwitchingOracle {
    before: Oracle,
    after: Oracle,
    switch_after: usize,
    switched: Arc<std::sync::atomic::AtomicBool>,
}

impl BlockStreamSource for SwitchingOracle {
    type Stream = ChainStream;

    async fn open(&mut self, start: u64, end: u64) -> Result<ChainStream, ScannerError> {
        let mut items = VecDeque::new();
        for height in start..=end {
            let switched = self.switched.load(Ordering::SeqCst);
            if !switched && items.len() == self.switch_after {
                self.switched.store(true, Ordering::SeqCst);
            }
            let chain = if self.switched.load(Ordering::SeqCst) {
                &self.after
            } else {
                &self.before
            };
            match chain.chain.get(&height) {
                Some(message) => items.push_back(Ok(message.clone())),
                None => break,
            }
        }
        Ok(ChainStream(items))
    }
}

impl OracleProbe for SwitchingOracle {
    async fn block_hash_at(&mut self, height: u64) -> Result<Option<BlockHash>, ScannerError> {
        if self.switched.load(Ordering::SeqCst) {
            self.after.block_hash_at(height).await
        } else {
            self.before.block_hash_at(height).await
        }
    }
}

/// With no new block, a poll checks the scanned tip with one hash lookup and
/// downloads no block; a new block is streamed once, not together with the
/// block below it.
#[test]
fn idle_poll_is_one_hash_lookup_and_a_new_block_is_streamed_once() {
    run(async {
        let (mut scanner, _state) = wallet("poll-cost");
        let s = scenario();
        scan_old_chain(&mut scanner, &s).await;
        let tip_block = s.old.chain[&s.old.tip()].encoded_len() + 5;
        s.old.traffic.take();

        for _ in 0..3 {
            assert!(!scanner.watch_step(s.old.tip(), s.old.clone()).await);
            let [streams, blocks, _, lookups, lookup_bytes] = s.old.traffic.take();
            assert_eq!((streams, blocks, lookups), (0, 0, 1), "idle poll");
            assert!(
                lookup_bytes < tip_block,
                "{lookup_bytes} B lookup vs the {tip_block} B block the overlap streamed"
            );
        }

        let mut longer = s.old.clone();
        longer.empty(0xa, 107);
        assert!(!scanner.watch_step(107, longer.clone()).await);
        let [streams, blocks, _, lookups, _] = longer.traffic.take();
        assert_eq!((streams, blocks), (1, 1), "only the new block is streamed");
        // The block below it before, and both again after the stream.
        assert_eq!(lookups, 3);
        assert_eq!(scanner.get_last_scanned_block_height(), 107);
        assert_eq!(scanner.scan_health().await.stall, None);
    });
}

/// A one-block tip replacement is located with lookups; only the fork point
/// and the new block are streamed, not the whole lookback window.
#[test]
fn tip_reorg_streams_from_the_fork_point_only() {
    run(async {
        let (mut scanner, _state) = wallet("locate-cheap");
        let (recv_tx, tweak, outpoint, _) = payment(0x61, 40_000);
        let tip = 101 + u64::from(REORG_LOOKBACK) + 10;
        let mut old = Oracle::default();
        old.block(0xa, 101, vec![(recv_tx, Some(tweak))], &[]);
        for h in 102..=tip {
            old.empty(0xa, h);
        }
        scanner
            .scan_range_from(101, tip, old.clone())
            .await
            .expect("old chain scans");

        let mut replaced = old.branch_at(tip - 1);
        replaced.empty(0xb, tip);
        assert!(!scanner.watch_step(tip, replaced.clone()).await);
        let [streams, blocks, _, lookups, _] = replaced.traffic.take();
        assert_eq!(streams, 1);
        assert_eq!(blocks, 2, "the fork point (checked) and the replaced tip");
        // 1 for the tip, 1 for the oldest remembered height, a binary search
        // over the 144-height window, 3 after the stream.
        assert!(lookups <= 14, "{lookups} lookups");
        assert_eq!(scanner.get_last_scanned_block_height(), tip);
        assert_eq!(owned_height(&scanner, outpoint), Some(101));
    });
}

/// The oracle switches branches while a stream runs: it serves 105 from the
/// old branch (a payment) and 106 from the new one, which forks at 104. Each
/// block looks fine on its own, since nothing links 106' to 105. The check
/// after the stream finds the disagreement and rolls the payment back.
#[test]
fn oracle_switching_branches_mid_stream_is_rolled_back() {
    run(async {
        let (mut scanner, _state) = wallet("mid-stream");
        let s = scenario();
        let mut upto_fork = s.old.branch_at(FORK);
        upto_fork.traffic = Arc::default();
        scanner
            .scan_range_from(101, FORK, upto_fork)
            .await
            .expect("chain up to the fork scans");
        let mut new = s.new.clone();
        new.empty(0xb, 108);
        let oracle = SwitchingOracle {
            before: s.old.clone(),
            after: new.clone(),
            switch_after: 1,
            switched: Arc::default(),
        };

        assert!(!scanner.watch_step(106, oracle).await);

        assert_eq!(
            owned_height(&scanner, s.evicted),
            None,
            "old 106 was never served"
        );
        assert_eq!(
            owned_height(&scanner, s.reconfirmed),
            Some(106),
            "the old 105 payment is gone and found again at 106'"
        );
        assert_eq!(anchor_heights(&scanner, s.reconfirmed.txid), vec![106]);
        assert_eq!(balance(&scanner), 80_000);
        assert_eq!(scanner.get_last_scanned_block_height(), 106);
        let mut probe = new.clone();
        for height in 101..=106 {
            assert_eq!(
                scanner.oracle_view(&mut probe, height).await.unwrap(),
                super::reorg::OracleView::Same,
                "remembered hash at {height} is on the new branch"
            );
        }
    });
}

/// A reorganisation below the lookback halts the wallet loudly: a stall in
/// the status says what to do, every poll fails again, and each poll costs
/// two hash lookups rather than a stream of the lookback window.
#[test]
fn too_deep_reorg_is_a_stall_and_polls_stay_cheap() {
    run(async {
        let (mut scanner, _state) = wallet("too-deep-stall");
        let tip = 101 + u64::from(REORG_LOOKBACK) + 10;
        let mut old = Oracle::default();
        for h in 101..=tip {
            old.empty(0xa, h);
        }
        scanner
            .scan_range_from(101, tip, old.clone())
            .await
            .expect("old chain scans");
        let mut new = old.branch_at(101);
        for h in 102..=tip {
            new.empty(0xb, h);
        }

        let mut first_since = None;
        for _ in 0..3 {
            assert!(!scanner.watch_step(tip, new.clone()).await);
            let [streams, blocks, _, lookups, _] = new.traffic.take();
            assert_eq!((streams, blocks, lookups), (0, 0, 2));
            let stall = scanner
                .scan_health()
                .await
                .stall
                .expect("published as a stall");
            assert!(
                stall
                    .reason
                    .contains("deeper than the scanner can roll back")
                    && stall.reason.contains("rescan"),
                "{}",
                stall.reason
            );
            assert_eq!(stall.height, tip + 1);
            assert_eq!(
                *first_since.get_or_insert(stall.since_unix),
                stall.since_unix
            );
        }
        assert_eq!(scanner.get_last_scanned_block_height(), tip);
    });
}
