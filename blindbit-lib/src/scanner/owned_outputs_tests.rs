//! Owned-output bookkeeping through the live short receive path.
//!
//! Each test drives a real [`Scanner`] exactly as `scan_block_range` does for
//! one oracle block: `scan_short_block_data` decides whether the block is worth
//! fetching, and only if it is, the full block goes through
//! `apply_matched_block` + `sync_owned_outputs` and becomes a checkpoint. The
//! P2P fetch is the only step replaced (the block is handed in directly).

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::OnceLock;

use bdk_sp::bitcoin::key::Secp256k1;
use bdk_sp::hashes::get_label_tweak;
use bdk_sp::receive::get_silentpayment_pubkey;
use bitcoin::absolute::LockTime;
use bitcoin::hashes::Hash;
use bitcoin::key::TweakedPublicKey;
use bitcoin::secp256k1::{PublicKey, SecretKey};
use bitcoin::transaction::Version;
use bitcoin::{
    Amount, Block, BlockHash, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid,
    Witness, XOnlyPublicKey,
};
use bitcoin_rev::Network;
use indexer::bdk_chain::local_chain::LocalChain;
use indexer::bdk_chain::{BlockId, CanonicalizationParams};
use tonic::transport::Channel;

use super::Scanner;
use crate::oracle_grpc::{BlockIdentifier, BlockScanDataShortResponse, ComputeIndexTxItem};
use crate::scanner::OwnedOutputRecord;

const RECEIVE_HEIGHT: u32 = 100;
const SPEND_HEIGHT: u32 = 200;

fn oracle_client() -> crate::OracleServiceClient<Channel> {
    static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    let runtime = RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime for the lazy tonic channel")
    });
    let _guard = runtime.enter();
    crate::OracleServiceClient::new(Channel::from_static("http://[::1]:50051").connect_lazy())
}

fn state_file(tag: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "blindbit-owned-outputs-{tag}-{}.json",
        std::process::id()
    ))
}

fn secret(byte: u8) -> SecretKey {
    SecretKey::from_slice(&[byte; 32]).expect("valid secret")
}

fn keys() -> (SecretKey, PublicKey) {
    let secp = Secp256k1::new();
    (secret(0x11), secret(0x22).public_key(&secp))
}

fn scanner(tag: &str, max_label_num: u32) -> Scanner {
    let (scan_sk, spend_pk) = keys();
    let socket: SocketAddr = "127.0.0.1:8333".parse().expect("socket address");
    Scanner::new(
        oracle_client(),
        socket,
        scan_sk,
        spend_pk,
        max_label_num,
        state_file(tag),
        Network::Regtest,
    )
}

/// The tweak (`input_hash * A`) the oracle would serve for a payment. Any
/// point works: the receiver only ever sees this value.
fn served_tweak(byte: u8) -> PublicKey {
    secret(byte).public_key(&Secp256k1::new())
}

/// `P_0` for the served tweak, plus `label_m * G` when labelled.
fn sp_output_key(tweak: &PublicKey, label: Option<u32>) -> XOnlyPublicKey {
    let (scan_sk, spend_pk) = keys();
    let shared = bdk_sp::compute_shared_secret(&scan_sk, tweak);
    let p0 = get_silentpayment_pubkey(&spend_pk, &shared, 0, None);
    let key = match label {
        None => p0,
        Some(m) => {
            let label_sk = SecretKey::from_slice(&get_label_tweak(scan_sk, m).to_be_bytes())
                .expect("label tweak is a valid scalar");
            p0.combine(&label_sk.public_key(&Secp256k1::new()))
                .expect("labelled key")
        }
    };
    key.x_only_public_key().0
}

fn foreign_key(byte: u8) -> XOnlyPublicKey {
    secret(byte)
        .public_key(&Secp256k1::new())
        .x_only_public_key()
        .0
}

fn p2tr(key: XOnlyPublicKey) -> ScriptBuf {
    ScriptBuf::new_p2tr_tweaked(TweakedPublicKey::dangerous_assume_tweaked(key))
}

fn tx(inputs: Vec<OutPoint>, outputs: Vec<(XOnlyPublicKey, u64)>) -> Transaction {
    Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: inputs
            .into_iter()
            .map(|previous_output| TxIn {
                previous_output,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            })
            .collect(),
        output: outputs
            .into_iter()
            .map(|(key, sat)| TxOut {
                value: Amount::from_sat(sat),
                script_pubkey: p2tr(key),
            })
            .collect(),
    }
}

fn block(height: u32, txs: Vec<Transaction>) -> Block {
    let coinbase = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::from_bytes(height.to_le_bytes().to_vec()),
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
            time: 1_713_571_767 + height,
            bits: bitcoin::CompactTarget::from_consensus(0x207f_ffff),
            nonce: height,
        },
        txdata,
    };
    block.header.merkle_root = block.compute_merkle_root().expect("non-empty block");
    block
}

/// The oracle's `ComputeIndexTxItem`: wire-order txid, tweak, and the 8-byte
/// prefix of every taproot output key.
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

/// One block of `scan_block_range`, minus the P2P fetch. Returns whether the
/// scanner decided to fetch (and therefore apply) the block.
fn process_block(
    scanner: &mut Scanner,
    block: &Block,
    height: u32,
    items: Vec<ComputeIndexTxItem>,
    spent_prefixes: &[XOnlyPublicKey],
) -> bool {
    let mut hash = block.block_hash().to_byte_array();
    hash.reverse();
    let short = BlockScanDataShortResponse {
        block_identifier: Some(BlockIdentifier {
            block_hash: hash.to_vec(),
            block_height: height as u64,
        }),
        comp_index: items,
        spent_outputs: spent_prefixes
            .iter()
            .flat_map(|key| key.serialize()[..8].to_vec())
            .collect(),
    };
    let Some(probable_match) = scanner.scan_short_block_data(short).expect("short scan") else {
        return false;
    };
    scanner.apply_matched_block(block, &probable_match, height);
    scanner.sync_owned_outputs();
    scanner.block_checkpoints.insert(height, block.block_hash());
    scanner
        .stage
        .block_checkpoints
        .insert(height, block.block_hash());
    true
}

/// The confirmed balance exactly as `scan_block_range` computes it.
fn balance(scanner: &Scanner) -> u64 {
    let (&height, &hash) = scanner
        .block_checkpoints
        .iter()
        .next_back()
        .expect("genesis checkpoint");
    let outpoints: Vec<(u32, OutPoint)> = scanner
        .internal_indexer
        .index()
        .by_shared_secret
        .keys()
        .map(|op| (op.vout, *op))
        .collect();
    let chain = LocalChain::from_blocks(scanner.block_checkpoints.clone()).expect("chain");
    scanner
        .internal_indexer
        .graph()
        .balance(
            &chain,
            BlockId { height, hash },
            CanonicalizationParams::default(),
            outpoints,
            |_, _| true,
        )
        .confirmed
        .to_sat()
}

fn record(scanner: &Scanner, outpoint: OutPoint) -> OwnedOutputRecord {
    scanner
        .owned_outputs()
        .find(|r| r.outpoint == outpoint)
        .cloned()
        .unwrap_or_else(|| panic!("no owned-output record for {outpoint}"))
}

/// Receives 50_000 sat to the unlabelled address at `RECEIVE_HEIGHT`.
fn receive(scanner: &mut Scanner) -> (OutPoint, XOnlyPublicKey) {
    let tweak = served_tweak(0x33);
    let ours = sp_output_key(&tweak, None);
    let recv = tx(
        vec![OutPoint::new(Txid::from_byte_array([0x44; 32]), 0)],
        vec![(foreign_key(0x55), 10_000), (ours, 50_000)],
    );
    let fetched = process_block(
        scanner,
        &block(RECEIVE_HEIGHT, vec![recv.clone()]),
        RECEIVE_HEIGHT,
        vec![item(&recv, tweak)],
        &[],
    );
    assert!(fetched, "receive block must be fetched");
    (OutPoint::new(recv.compute_txid(), 1), ours)
}

/// A spend of `outpoint` paying only a foreign key: no output comes back to
/// the wallet, so only the spent-output prefix can make the scanner fetch it.
fn spend_of(outpoint: OutPoint) -> Transaction {
    tx(vec![outpoint], vec![(foreign_key(0x66), 49_000)])
}

#[test]
fn spend_in_later_block_marks_output_spent_and_balance_drops() {
    let mut scanner = scanner("spend", 0);
    let (outpoint, key) = receive(&mut scanner);

    let rec = record(&scanner, outpoint);
    assert_eq!(rec.pubkey, key, "full x-only key recorded");
    assert_eq!((rec.amount_sat, rec.height), (50_000, RECEIVE_HEIGHT));
    assert!(!rec.is_spent());
    assert_eq!(balance(&scanner), 50_000);

    // A block that spends nothing of ours is not fetched.
    let unrelated = tx(
        vec![OutPoint::new(Txid::from_byte_array([0x77; 32]), 3)],
        vec![(foreign_key(0x78), 1_000)],
    );
    assert!(!process_block(
        &mut scanner,
        &block(150, vec![unrelated]),
        150,
        vec![],
        &[foreign_key(0x79)],
    ));

    let spend = spend_of(outpoint);
    let fetched = process_block(
        &mut scanner,
        &block(SPEND_HEIGHT, vec![spend.clone()]),
        SPEND_HEIGHT,
        // The spend has a (foreign) taproot output, so the oracle indexes it
        // with some tweak that does not match us.
        vec![item(&spend, served_tweak(0x99))],
        &[foreign_key(0x7a), key],
    );
    assert!(
        fetched,
        "spent prefix of an owned output must fetch the block"
    );

    let rec = record(&scanner, outpoint);
    assert_eq!(rec.spent_by, Some(spend.compute_txid()));
    assert_eq!(rec.spent_height, Some(SPEND_HEIGHT));
    assert_eq!(balance(&scanner), 0, "spent coin must leave the balance");
}

#[test]
fn foreign_output_with_colliding_prefix_marks_nothing() {
    let mut scanner = scanner("collision", 0);
    let (outpoint, key) = receive(&mut scanner);

    // Someone else's output shares our key's 8-byte prefix and is spent: the
    // oracle serves exactly our prefix, but the spending tx consumes a
    // different outpoint.
    let foreign_outpoint = OutPoint::new(Txid::from_byte_array([0x88; 32]), 0);
    let foreign_spend = spend_of(foreign_outpoint);
    let fetched = process_block(
        &mut scanner,
        &block(SPEND_HEIGHT, vec![foreign_spend]),
        SPEND_HEIGHT,
        vec![],
        &[key],
    );
    assert!(fetched, "a prefix hit must still fetch the block to check");

    let rec = record(&scanner, outpoint);
    assert!(
        !rec.is_spent(),
        "prefix collision alone must not mark: {rec:?}"
    );
    assert_eq!(scanner.owned_outputs().count(), 1);
    assert_eq!(balance(&scanner), 50_000);
}

#[test]
fn labelled_receive_records_its_label() {
    let mut scanner = scanner("labels", 5);
    let tweak = served_tweak(0x34);
    let unlabelled = sp_output_key(&tweak, None);
    let change = sp_output_key(&tweak, Some(0));
    let labelled = sp_output_key(&tweak, Some(3));
    // Three payments to one wallet in one tx: k = 0 is taken by whichever
    // candidate matches first, so use one tx per key to keep k = 0 each.
    let txs: Vec<Transaction> = [(unlabelled, 0x01u8), (change, 0x02), (labelled, 0x03)]
        .iter()
        .map(|&(key, salt)| {
            tx(
                vec![OutPoint::new(Txid::from_byte_array([salt; 32]), 0)],
                vec![(key, 10_000 * salt as u64)],
            )
        })
        .collect();
    let items = txs.iter().map(|t| item(t, tweak)).collect();
    assert!(process_block(
        &mut scanner,
        &block(RECEIVE_HEIGHT, txs.clone()),
        RECEIVE_HEIGHT,
        items,
        &[],
    ));

    let labels: Vec<(XOnlyPublicKey, Option<u32>)> = txs
        .iter()
        .map(|t| {
            let r = record(&scanner, OutPoint::new(t.compute_txid(), 0));
            (r.pubkey, r.label)
        })
        .collect();
    assert_eq!(
        labels,
        vec![(unlabelled, None), (change, Some(0)), (labelled, Some(3))]
    );
}

#[cfg(feature = "serde")]
#[test]
fn owned_outputs_labels_and_spends_survive_restart() {
    let tag = "restart";
    let path = state_file(tag);
    let _ = std::fs::remove_file(&path);

    let mut scanner = scanner(tag, 2);
    let tweak = served_tweak(0x35);
    let change_key = sp_output_key(&tweak, Some(0));
    let label_key = sp_output_key(&tweak, Some(2));
    let recv_change = tx(
        vec![OutPoint::new(Txid::from_byte_array([0x0a; 32]), 0)],
        vec![(change_key, 20_000)],
    );
    let recv_label = tx(
        vec![OutPoint::new(Txid::from_byte_array([0x0b; 32]), 0)],
        vec![(label_key, 30_000)],
    );
    assert!(process_block(
        &mut scanner,
        &block(
            RECEIVE_HEIGHT,
            vec![recv_change.clone(), recv_label.clone()]
        ),
        RECEIVE_HEIGHT,
        vec![item(&recv_change, tweak), item(&recv_label, tweak)],
        &[],
    ));
    let change_op = OutPoint::new(recv_change.compute_txid(), 0);
    let label_op = OutPoint::new(recv_label.compute_txid(), 0);

    // Spend the change output before the restart.
    let spend = spend_of(change_op);
    assert!(process_block(
        &mut scanner,
        &block(SPEND_HEIGHT, vec![spend.clone()]),
        SPEND_HEIGHT,
        vec![],
        &[change_key],
    ));
    assert_eq!(balance(&scanner), 30_000);
    let before: Vec<_> = scanner.owned_outputs().cloned().collect();
    assert_eq!(before.len(), 2);

    scanner.save_to_file(&path).expect("save state");
    let json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    let persisted = json["owned_outputs"]
        .as_array()
        .expect("owned_outputs array");
    assert_eq!(persisted.len(), 2, "state file lists every owned output");
    let label_entry = persisted
        .iter()
        .find(|e| e["outpoint"] == label_op.to_string())
        .expect("labelled output persisted");
    assert_eq!(label_entry["label"], 2);
    assert_eq!(label_entry["pubkey"], label_key.to_string());

    let changeset = Scanner::load_from_file(&path).expect("load state");
    let socket: SocketAddr = "127.0.0.1:8333".parse().unwrap();
    let mut restored = Scanner::from_changeset(
        oracle_client(),
        socket,
        changeset,
        path.clone(),
        Network::Regtest,
    )
    .expect("restore");
    let _ = std::fs::remove_file(&path);

    let after: Vec<_> = restored.owned_outputs().cloned().collect();
    assert_eq!(after, before, "records survive the restart unchanged");
    assert_eq!(balance(&restored), 30_000, "restored balance");

    // Spend detection keeps working after the restart.
    let spend2 = spend_of(label_op);
    assert!(process_block(
        &mut restored,
        &block(300, vec![spend2.clone()]),
        300,
        vec![],
        &[label_key],
    ));
    assert_eq!(
        record(&restored, label_op).spent_by,
        Some(spend2.compute_txid())
    );
    assert_eq!(balance(&restored), 0);
}
