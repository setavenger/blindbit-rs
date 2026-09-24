//! How a range scan reacts to what an oracle stream can deliver mid-range.
//!
//! A block the scanner cannot vouch for must never be treated as "no
//! payments": a message with an empty or malformed block hash (what an oracle
//! answers for a height it has not indexed), a height other than the next one
//! expected, an error status, or a stream that ends early each stop the scan
//! with an error, and the scan height stays at the last block that was fully
//! processed so the next scan resumes there.
//!
//! Each test drives a real [`Scanner`] through `scan_block_stream` with
//! in-process messages. The P2P block fetch is the only step replaced: full
//! blocks are served from [`served_block`].

use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Mutex;

use bdk_sp::bitcoin::key::Secp256k1;
use bdk_sp::receive::get_silentpayment_pubkey;
use bitcoin::absolute::LockTime;
use bitcoin::block::{Header, Version as BlockVersion};
use bitcoin::hashes::Hash;
use bitcoin::key::TweakedPublicKey;
use bitcoin::secp256k1::{PublicKey, SecretKey};
use bitcoin::transaction::Version;
use bitcoin::{
    Amount, Block, BlockHash, CompactTarget, OutPoint, ScriptBuf, Sequence, Transaction, TxIn,
    TxMerkleNode, TxOut, Txid, Witness,
};
use bitcoin_rev::Network;
use tonic::transport::Channel;

use super::Scanner;
use super::scanning::BlockScanDataStream;
use crate::oracle_grpc::{BlockIdentifier, BlockScanDataShortResponse, ComputeIndexTxItem};

static SERVED_BLOCKS: Mutex<Option<HashMap<BlockHash, Block>>> = Mutex::new(None);

/// The full block a test serves for `hash` in place of a P2P fetch.
pub(super) fn served_block(hash: &BlockHash) -> Option<Block> {
    SERVED_BLOCKS
        .lock()
        .unwrap()
        .as_ref()
        .and_then(|blocks| blocks.get(hash).cloned())
}

fn serve(block: &Block) {
    SERVED_BLOCKS
        .lock()
        .unwrap()
        .get_or_insert_with(HashMap::new)
        .insert(block.block_hash(), block.clone());
}

/// In-process stand-in for the oracle's `StreamBlockScanDataShort` stream.
struct TestStream(VecDeque<Result<BlockScanDataShortResponse, tonic::Status>>);

impl TestStream {
    fn new(items: Vec<Result<BlockScanDataShortResponse, tonic::Status>>) -> Self {
        Self(items.into())
    }
}

impl BlockScanDataStream for TestStream {
    fn next_message(
        &mut self,
    ) -> impl Future<Output = Result<Option<BlockScanDataShortResponse>, tonic::Status>> + Send
    {
        std::future::ready(self.0.pop_front().transpose())
    }
}

fn run<F: Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime")
        .block_on(future)
}

fn secret(byte: u8) -> SecretKey {
    SecretKey::from_slice(&[byte; 32]).expect("valid secret")
}

fn keys() -> (SecretKey, PublicKey) {
    (secret(0x11), secret(0x22).public_key(&Secp256k1::new()))
}

struct TempState(PathBuf);

impl Drop for TempState {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// A scanner whose oracle client points at `oracle` (never contacted unless a
/// test calls `scan_block_range`). Must be called inside a Tokio runtime.
fn scanner(tag: &str, oracle: &'static str) -> (Scanner, TempState) {
    let (scan_sk, spend_pk) = keys();
    let state = std::env::temp_dir().join(format!(
        "blindbit-stream-safety-{tag}-{}.json",
        std::process::id()
    ));
    let client = crate::OracleServiceClient::new(Channel::from_static(oracle).connect_lazy());
    let socket: SocketAddr = "127.0.0.1:1".parse().expect("socket address");
    let scanner = Scanner::new(
        client,
        socket,
        scan_sk,
        spend_pk,
        0,
        state.clone(),
        Network::Regtest,
    );
    (scanner, TempState(state))
}

/// One block at `height` holding a single silent payment to the test wallet,
/// served in place of P2P, and the oracle message that describes it.
struct PaymentBlock {
    height: u64,
    message: BlockScanDataShortResponse,
}

fn payment_block(height: u64) -> PaymentBlock {
    let (scan_sk, spend_pk) = keys();
    // The tweak (`input_hash * A`) the oracle would serve; any point works.
    let tweak = secret(0x40u8.wrapping_add(height as u8)).public_key(&Secp256k1::new());
    let shared = bdk_sp::compute_shared_secret(&scan_sk, &tweak);
    let output_key = get_silentpayment_pubkey(&spend_pk, &shared, 0, None)
        .x_only_public_key()
        .0;

    let coinbase = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::from_bytes(height.to_le_bytes().to_vec()),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![],
    };
    let payment = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array([height as u8; 32]),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(10_000 + height),
            script_pubkey: ScriptBuf::new_p2tr_tweaked(TweakedPublicKey::dangerous_assume_tweaked(
                output_key,
            )),
        }],
    };
    let payment_txid = payment.compute_txid();

    let mut block = Block {
        header: Header {
            version: BlockVersion::ONE,
            prev_blockhash: BlockHash::all_zeros(),
            merkle_root: TxMerkleNode::all_zeros(),
            time: height as u32,
            bits: CompactTarget::from_consensus(0x207f_ffff),
            nonce: 0,
        },
        txdata: vec![coinbase, payment],
    };
    block.header.merkle_root = block.compute_merkle_root().expect("non-empty block");

    // The oracle serves hashes and txids in display order.
    let mut block_hash = block.block_hash().to_byte_array();
    block_hash.reverse();
    let mut txid = payment_txid.to_byte_array();
    txid.reverse();

    let message = BlockScanDataShortResponse {
        block_identifier: Some(BlockIdentifier {
            block_hash: block_hash.to_vec(),
            block_height: height,
        }),
        comp_index: vec![ComputeIndexTxItem {
            txid: txid.to_vec(),
            tweak: tweak.serialize().to_vec(),
            outputs_short: output_key.serialize()[..8].to_vec(),
        }],
        spent_outputs: vec![],
    };
    serve(&block);
    PaymentBlock { height, message }
}

/// What an oracle sends today for a height it has not indexed: OK, with an
/// empty block hash and no data.
fn unindexed_message(height: u64) -> BlockScanDataShortResponse {
    BlockScanDataShortResponse {
        block_identifier: Some(BlockIdentifier {
            block_hash: vec![],
            block_height: height,
        }),
        comp_index: vec![],
        spent_outputs: vec![],
    }
}

fn owned_outputs(scanner: &Scanner) -> usize {
    scanner.internal_indexer.index().by_shared_secret.len()
}

/// The regression the testkit's `unindexed-ok-empty` mutation check proved:
/// an unindexed height mid-range was taken as an empty block, the scan
/// advanced past it and reported success, and the payments in it were never
/// found. Now the scan stops before that block, and the next scan (once the
/// oracle serves it) finds every payment.
#[test]
fn empty_hash_block_mid_range_stops_scan_and_next_scan_finds_its_outputs() {
    run(async {
        let (mut scanner, _state) = scanner("empty-hash", "http://127.0.0.1:1");
        let a = payment_block(1100);
        let b = payment_block(1101);
        let c = payment_block(1102);

        let first = TestStream::new(vec![
            Ok(a.message.clone()),
            Ok(unindexed_message(b.height)),
            Ok(c.message.clone()),
        ]);
        let err = scanner
            .scan_block_stream(a.height, c.height, first)
            .await
            .expect_err("a block without a valid hash must stop the scan");
        let msg = err.to_string();
        assert!(
            msg.contains(&b.height.to_string()),
            "error names the height: {msg}"
        );
        assert_eq!(scanner.get_last_scanned_block_height(), a.height);
        assert_eq!(
            owned_outputs(&scanner),
            1,
            "only the block before the gap is applied"
        );

        // Resume where the scanner says, now that the oracle serves the block.
        let resume = scanner.get_last_scanned_block_height() + 1;
        assert_eq!(resume, b.height);
        let second = TestStream::new(vec![Ok(b.message.clone()), Ok(c.message.clone())]);
        scanner
            .scan_block_stream(resume, c.height, second)
            .await
            .expect("resumed scan succeeds");
        assert_eq!(scanner.get_last_scanned_block_height(), c.height);
        assert_eq!(owned_outputs(&scanner), 3, "no payment is lost");
    });
}

#[test]
fn malformed_block_hash_stops_scan() {
    run(async {
        let (mut scanner, _state) = scanner("short-hash", "http://127.0.0.1:1");
        let a = payment_block(1200);
        let mut bad = payment_block(1201).message;
        bad.block_identifier
            .as_mut()
            .unwrap()
            .block_hash
            .truncate(31);
        let mut zero = payment_block(1201).message;
        zero.block_identifier.as_mut().unwrap().block_hash = vec![0; 32];

        for bad in [bad, zero] {
            let stream = TestStream::new(vec![Ok(a.message.clone()), Ok(bad)]);
            scanner
                .scan_block_stream(a.height, a.height + 1, stream)
                .await
                .expect_err("a malformed block hash must stop the scan");
            assert_eq!(scanner.get_last_scanned_block_height(), a.height);
        }
    });
}

#[test]
fn skipped_height_stops_scan() {
    run(async {
        let (mut scanner, _state) = scanner("skipped", "http://127.0.0.1:1");
        let a = payment_block(1300);
        let c = payment_block(1302);
        let stream = TestStream::new(vec![Ok(a.message.clone()), Ok(c.message.clone())]);
        let err = scanner
            .scan_block_stream(a.height, c.height, stream)
            .await
            .expect_err("a height gap must stop the scan");
        assert!(
            err.to_string().contains("1301"),
            "error names the expected height: {err}"
        );
        assert_eq!(scanner.get_last_scanned_block_height(), a.height);
        assert_eq!(
            owned_outputs(&scanner),
            1,
            "the block after the gap is not applied"
        );
    });
}

#[test]
fn stream_starting_at_wrong_height_stops_scan() {
    run(async {
        let (mut scanner, _state) = scanner("wrong-start", "http://127.0.0.1:1");
        scanner.update_last_scanned_block_height(1399);
        let b = payment_block(1401);
        let stream = TestStream::new(vec![Ok(b.message.clone())]);
        scanner
            .scan_block_stream(1400, 1401, stream)
            .await
            .expect_err("the first block must be the requested start");
        assert_eq!(scanner.get_last_scanned_block_height(), 1399);
        assert_eq!(owned_outputs(&scanner), 0);
    });
}

/// A fixed oracle ends the stream with NOT_FOUND at an unindexed height; a
/// transient failure ends it with UNAVAILABLE. Neither may panic the process,
/// and neither may advance the scan height past the last full block.
#[test]
fn error_status_mid_stream_is_a_clean_error() {
    run(async {
        let statuses = [
            tonic::Status::not_found("height 1501 is not indexed"),
            tonic::Status::unavailable("connection reset"),
        ];
        for (i, status) in statuses.into_iter().enumerate() {
            let code = status.code();
            let (mut scanner, _state) = scanner(&format!("status-{i}"), "http://127.0.0.1:1");
            let a = payment_block(1500);
            let stream = TestStream::new(vec![Ok(a.message.clone()), Err(status)]);
            let err = scanner
                .scan_block_stream(a.height, a.height + 1, stream)
                .await
                .expect_err("an error status must end the scan with an error");
            let msg = err.to_string();
            assert!(
                msg.contains("height 1501") && msg.contains(&format!("{code:?}")),
                "error names the height and the status code: {msg}"
            );
            assert_eq!(
                scanner.get_last_scanned_block_height(),
                a.height,
                "{code:?}"
            );
            assert_eq!(owned_outputs(&scanner), 1, "{code:?}");
        }
    });
}

#[test]
fn stream_ending_before_requested_end_is_an_error() {
    run(async {
        let (mut scanner, _state) = scanner("short-stream", "http://127.0.0.1:1");
        let a = payment_block(1600);
        let stream = TestStream::new(vec![Ok(a.message.clone())]);
        let err = scanner
            .scan_block_stream(a.height, a.height + 2, stream)
            .await
            .expect_err("a stream that stops short of `end` must not report success");
        assert!(
            err.to_string().contains("1601"),
            "error names the missing height: {err}"
        );
        assert_eq!(scanner.get_last_scanned_block_height(), a.height);
    });
}

/// Opening the stream against an unreachable oracle used to `unwrap()`.
#[test]
fn unreachable_oracle_is_a_clean_error() {
    run(async {
        let (mut scanner, _state) = scanner("unreachable", "http://127.0.0.1:1");
        scanner.update_last_scanned_block_height(1699);
        scanner
            .scan_block_range(1700, 1710)
            .await
            .expect_err("an unreachable oracle must be an error, not a panic");
        assert_eq!(scanner.get_last_scanned_block_height(), 1699);
    });
}
