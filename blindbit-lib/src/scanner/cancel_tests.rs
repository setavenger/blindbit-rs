//! Stopping a scan: it gives way at once wherever it waits (a block download
//! from a node that went silent halfway through the block, the wait between
//! download attempts, the wait for the next poll) and never keeps part of a
//! block, so the next run resumes at the block it was downloading.

use std::sync::Arc;
use std::time::{Duration, Instant};

use bitcoin::BlockHash;
use bitcoin::hashes::Hash;
use bitcoin_rev::Network;
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

use super::ScannerError;
use super::health::OracleProbe;
use super::p2p::{BlockFetcher, FetchFailure, RetryPolicy};
use super::p2p_tests::{Conn, Node};
use super::scanning::BlockStreamSource;
use super::stream_safety_tests::{TestStream, owned_outputs, payment_block, served_block, unserve};
use super::test_support::{run, scanner};
use crate::oracle_grpc::BlockScanDataShortResponse;

/// An oracle serving a fixed run of consecutive blocks.
#[derive(Clone)]
struct Chain(Vec<BlockScanDataShortResponse>);

impl BlockStreamSource for Chain {
    type Stream = TestStream;

    async fn open(&mut self, start: u64, end: u64) -> Result<TestStream, ScannerError> {
        Ok(TestStream::new(
            self.0
                .iter()
                .filter(|message| {
                    let height = message.block_identifier.as_ref().unwrap().block_height;
                    (start..=end).contains(&height)
                })
                .cloned()
                .map(Ok)
                .collect(),
        ))
    }
}

impl OracleProbe for Chain {
    async fn block_hash_at(&mut self, _height: u64) -> Result<Option<BlockHash>, ScannerError> {
        Ok(None)
    }
}

/// The hash of the block an oracle message describes (it serves hashes in
/// display order).
fn hash_of(message: &BlockScanDataShortResponse) -> BlockHash {
    let mut bytes: [u8; 32] = message
        .block_identifier
        .as_ref()
        .unwrap()
        .block_hash
        .clone()
        .try_into()
        .unwrap();
    bytes.reverse();
    BlockHash::from_byte_array(bytes)
}

/// Polls `condition` every 5 ms for up to 10 s.
async fn wait_until(what: &str, condition: impl Fn() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !condition() {
        assert!(Instant::now() < deadline, "timed out waiting until {what}");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

/// The daemon's case: three blocks paying the wallet, the middle one
/// downloaded from a node that goes silent halfway through it (it would
/// hold the download for 10 s, then close; with the default policy the
/// fetch would retry and go on). Stopped there, the scan ends within a
/// second, without a stall or a backoff, with the first block complete and
/// nothing of the second; started again, it downloads the second block on
/// a fresh connection and scans on to the end.
#[test]
fn a_stop_during_a_stalled_block_download_ends_the_scan_at_once_and_it_resumes_there() {
    run(async {
        let (mut scanner, _state) = scanner("cancel-stalled-download");
        let (a, b, c) = (
            payment_block(4201),
            payment_block(4202),
            payment_block(4203),
        );
        let b_hash = hash_of(&b.message);
        let b_block = served_block(&b_hash).expect("payment_block serves it");
        unserve(&b_hash);
        let node = Node::serving(&b_block, vec![Conn::StallMidBlock, Conn::Serve]);
        scanner.p2p_peer = node.addr;
        scanner.p2p_retry = RetryPolicy::default();
        scanner.update_last_scanned_block_height(4200);
        let oracle = Chain(vec![a.message, b.message, c.message]);
        let scanner = Arc::new(Mutex::new(scanner));

        // As the daemon runs it: in a task holding the scanner, under a
        // token the supervisor cancels.
        let cancel = CancellationToken::new();
        let task = tokio::spawn({
            let (scanner, cancel, oracle) = (scanner.clone(), cancel.clone(), oracle.clone());
            async move {
                let mut scanner = scanner.lock().await;
                scanner.cancel = cancel;
                let retry_at_once = scanner.watch_step(4203, oracle).await;
                (retry_at_once, Instant::now())
            }
        });
        wait_until("the node goes silent mid-block", || {
            node.stalled().is_some()
        })
        .await;
        tokio::time::sleep(Duration::from_millis(100)).await; // the scan waits on it
        cancel.cancel();
        let (retry_at_once, ended) = tokio::time::timeout(Duration::from_secs(60), task)
            .await
            .expect("the scan ended")
            .expect("the scan task did not panic");
        let took = ended - node.stalled().unwrap();
        assert!(
            took < Duration::from_secs(1),
            "the scan ended {took:?} after the node went silent"
        );
        assert!(!retry_at_once);

        let mut s = scanner.lock().await;
        assert_eq!(s.get_last_scanned_block_height(), 4201, "a complete, b not");
        assert_eq!(s.stage.last_scanned_block_height, 4201);
        assert!(s.scanned_block_hashes.contains_key(&4201));
        assert!(!s.scanned_block_hashes.contains_key(&4202));
        assert_eq!(owned_outputs(&s), 1, "nothing of block b is kept");
        assert!(!s.block_checkpoints.contains_key(&4202));
        {
            let index = s.electrum_index();
            let index = index.lock().await;
            assert!(index.headers.contains_key(&4201));
            assert!(!index.headers.contains_key(&4202));
            assert_eq!(index.txs.len(), 1, "only block a's payment is served");
        }
        assert_eq!(s.scan_health().await.stall, None, "a stop is not a stall");
        assert_eq!(
            s.fetch_backoff.take_wait(),
            None,
            "nor a reason to back off"
        );

        // Started again: on from block b.
        s.cancel = CancellationToken::new();
        assert!(!s.watch_step(4203, oracle).await);
        assert_eq!(s.get_last_scanned_block_height(), 4203);
        assert_eq!(owned_outputs(&s), 3);
        assert_eq!(
            node.connections(),
            2,
            "b downloaded again on a fresh connection"
        );
        assert_eq!(s.scan_health().await.stall, None);
    });
}

/// A stop ends the wait between two download attempts (30 s here) at once,
/// and no further connection is made.
#[test]
fn a_stop_ends_the_wait_between_download_attempts() {
    run(async {
        let node = Node::full(1_000, vec![Conn::CloseAfterRequest, Conn::Serve]);
        let cancel = CancellationToken::new();
        let fetcher = BlockFetcher::new(node.addr, Network::Regtest)
            .with_policy(RetryPolicy {
                attempts: 5,
                first_delay: Duration::from_secs(30),
                max_delay: Duration::from_secs(30),
                block_deadline: Duration::from_secs(5),
            })
            .with_cancel(cancel.clone());
        let genesis = bitcoin::constants::genesis_block(bitcoin::Network::Regtest);
        let stop = async {
            wait_until("the first attempt connected", || node.connections() == 1).await;
            tokio::time::sleep(Duration::from_millis(300)).await;
            cancel.cancel();
            Instant::now()
        };
        let (fetched, stopped) = tokio::join!(fetcher.fetch(genesis.block_hash(), 100), stop);
        let took = stopped.elapsed();
        assert!(
            took < Duration::from_secs(1),
            "the fetch took {took:?} to stop"
        );
        let err = fetched.expect_err("stopped before the second attempt");
        assert_eq!(err.failure, FetchFailure::Cancelled);
        assert_eq!(err.attempts, 1);
        assert_eq!(node.connections(), 1);
    });
}

/// `watch_chain_until` stops in its wait for the next poll (10 s after the
/// oracle could not be reached), returns `Ok`, and leaves the scanner
/// uncancelled for later scans.
#[test]
fn a_stop_ends_the_wait_for_the_next_poll() {
    run(async {
        let (mut scanner, _state) = scanner("cancel-poll");
        let cancel = CancellationToken::new();
        let stop = async {
            tokio::time::sleep(Duration::from_millis(500)).await;
            cancel.cancel();
            Instant::now()
        };
        let (result, stopped) = tokio::join!(scanner.watch_chain_until(cancel.clone()), stop);
        let took = stopped.elapsed();
        assert!(
            took < Duration::from_secs(1),
            "the watch took {took:?} to stop"
        );
        result.expect("a stop is not an error");
        assert!(!scanner.cancel.is_cancelled());
        let stall = scanner
            .scan_health()
            .await
            .stall
            .expect("the oracle is unreachable");
        assert!(
            stall.reason.contains("cannot reach the oracle"),
            "{}",
            stall.reason
        );
    });
}
