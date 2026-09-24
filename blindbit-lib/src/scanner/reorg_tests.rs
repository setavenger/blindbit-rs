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

use super::reorg::ReorgTooDeep;
use super::scanning::{BlockScanDataStream, BlockStreamSource};
use super::stream_safety_tests::serve;
use super::{REORG_LOOKBACK, Scanner, ScannerError};
use crate::oracle_grpc::{BlockIdentifier, BlockScanDataShortResponse, ComputeIndexTxItem};

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
        let mut items = VecDeque::new();
        for height in start..=end {
            if self.fail_at == Some(height) && start < height {
                items.push_back(Err(tonic::Status::unavailable("connection reset")));
                break;
            }
            match self.chain.get(&height) {
                Some(message) => items.push_back(Ok(message.clone())),
                None => break,
            }
        }
        Ok(ChainStream(items))
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

/// With no reorg, the watch loop's check reads one block and changes
/// nothing, and continuing the chain still scans new blocks.
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
