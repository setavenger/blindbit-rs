//! A wallet whose start height lies below the oracle's first indexed block
//! starts at that block instead of stalling forever; a height the oracle has
//! not indexed *above* its first block is never skipped. A scan that cannot
//! get past a height is published as a stall.

use std::future::Future;
use std::ops::RangeInclusive;

use bitcoin::BlockHash;
use bitcoin::hashes::Hash;

use super::ScannerError;
use super::health::{OracleProbe, ScanStopped, find_oracle_floor};
use super::scanner::Scanner;
use super::stream_safety_tests::{TestStream, owned_outputs, payment_block, unindexed_message};
use super::test_support::{run, scanner};

/// `GetBlockHashByHeight` over fixed runs of indexed heights.
struct FakeOracle {
    indexed: Vec<RangeInclusive<u64>>,
    probes: u32,
    fail: bool,
}

impl FakeOracle {
    fn contiguous(floor: u64, tip: u64) -> Self {
        Self {
            indexed: std::iter::once(floor..=tip).collect(),
            probes: 0,
            fail: false,
        }
    }

    fn empty() -> Self {
        Self {
            indexed: vec![],
            probes: 0,
            fail: false,
        }
    }

    fn without(mut self, gap: RangeInclusive<u64>) -> Self {
        self.indexed = self
            .indexed
            .into_iter()
            .flat_map(|run| {
                let below = *run.start()..=(*gap.start()).min(run.end() + 1).saturating_sub(1);
                let above = (*gap.end() + 1).max(*run.start())..=*run.end();
                [below, above]
            })
            .filter(|run| !run.is_empty())
            .collect();
        self
    }

    fn is_indexed(&self, height: u64) -> bool {
        self.indexed.iter().any(|run| run.contains(&height))
    }
}

impl OracleProbe for FakeOracle {
    fn block_hash_at(
        &mut self,
        height: u64,
    ) -> impl Future<Output = Result<Option<BlockHash>, ScannerError>> + Send {
        self.probes += 1;
        let result = if self.fail {
            Err("oracle unavailable".into())
        } else {
            Ok(self
                .is_indexed(height)
                .then(|| BlockHash::from_byte_array([1; 32])))
        };
        std::future::ready(result)
    }
}

fn floor(oracle: &mut FakeOracle, from: u64, tip: u64) -> Option<u64> {
    run(find_oracle_floor(oracle, from, tip)).expect("probe succeeds")
}

/// The hosted signet oracle has nothing below 100 000; mainnet nothing below
/// 800 000. A search over the whole chain stays cheap.
#[test]
fn start_below_a_contiguous_index_finds_its_first_block() {
    let mut signet = FakeOracle::contiguous(100_000, 324_494);
    assert_eq!(floor(&mut signet, 1, 324_494), Some(100_000));
    assert!(signet.probes <= 60, "{} lookups", signet.probes);

    let mut mainnet = FakeOracle::contiguous(800_000, 965_000);
    assert_eq!(floor(&mut mainnet, 700_000, 965_000), Some(800_000));
    assert_eq!(floor(&mut mainnet, 799_999, 965_000), Some(800_000));
    assert!(mainnet.probes <= 140, "{} lookups", mainnet.probes);
}

/// Before blindbit-oracle#66 a fresh oracle never indexed its configured
/// start height: nothing at or below it, everything above it.
#[test]
fn oracle_missing_its_own_start_height_starts_one_above() {
    let mut oracle = FakeOracle::contiguous(101, 300);
    assert_eq!(floor(&mut oracle, 100, 300), Some(101));
    assert_eq!(floor(&mut oracle, 1, 300), Some(101));
}

/// A binary search alone would land in the gap at 2000..=2010 (the midpoint
/// of 10..4000 is 2005) and report 2011, skipping 1000 indexed blocks.
#[test]
fn gap_above_the_floor_does_not_move_the_floor_up() {
    let mut oracle = FakeOracle::contiguous(1_000, 4_000).without(2_000..=2_010);
    assert_eq!(floor(&mut oracle, 10, 4_000), Some(1_000));
}

#[test]
fn start_inside_a_gap_above_the_floor_is_never_skipped() {
    let mut oracle = FakeOracle::contiguous(1_000, 4_000).without(2_000..=2_010);
    for from in [2_000, 2_005, 2_010] {
        assert_eq!(floor(&mut oracle, from, 4_000), None, "from {from}");
    }
    // One missing block right above a long indexed run.
    let mut oracle = FakeOracle::contiguous(1_000, 4_000).without(3_000..=3_000);
    assert_eq!(floor(&mut oracle, 3_000, 4_000), None);
}

/// Randomised layouts: a floor, then a handful of gaps above it, each
/// narrower than the run below it. The search must always return the
/// floor, and never skip from inside a gap.
#[test]
fn randomised_gappy_indexes() {
    let mut seed = 0x9e37_79b9_7f4a_7c15_u64;
    let mut next = move |bound: u64| {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed % bound
    };
    for _ in 0..2_000 {
        let tip = 5_000 + next(1_000_000);
        let floor_height = 1 + next(tip - 100);
        let mut oracle = FakeOracle::contiguous(floor_height, tip);
        let mut gaps = Vec::new();
        let mut cursor = floor_height;
        for _ in 0..next(6) {
            let run = 50 + next(5_000);
            let start = cursor + run;
            let width = 1 + next(run.min(40));
            if start + width >= tip {
                break;
            }
            oracle = oracle.without(start..=start + width - 1);
            gaps.push(start..=start + width - 1);
            cursor = start + width;
        }
        let from = next(floor_height);
        assert_eq!(
            floor(&mut oracle, from, tip),
            Some(floor_height),
            "floor {floor_height} tip {tip} gaps {gaps:?} from {from}"
        );
        for gap in &gaps {
            assert_eq!(floor(&mut oracle, *gap.start(), tip), None, "gap {gap:?}");
        }
    }
}

#[test]
fn indexed_start_or_empty_oracle_is_not_a_floor() {
    let mut oracle = FakeOracle::contiguous(100, 300);
    assert_eq!(floor(&mut oracle, 150, 300), None, "start is indexed");
    let mut empty = FakeOracle::empty();
    assert_eq!(
        floor(&mut empty, 1, 300),
        None,
        "nothing indexed at the tip"
    );
}

#[test]
fn oracle_error_is_an_error_not_a_floor() {
    let mut oracle = FakeOracle::contiguous(100, 300);
    oracle.fail = true;
    assert!(run(find_oracle_floor(&mut oracle, 1, 300)).is_err());
}

fn not_indexed_at(height: u64) -> ScannerError {
    Box::new(ScanStopped {
        height,
        reason: "the oracle sent no valid block hash (0 bytes)".into(),
        not_indexed: true,
    })
}

async fn set_wallet_start(scanner: &mut Scanner, start: u64) {
    scanner.update_last_scanned_block_height(start - 1);
    scanner.electrum_index.lock().await.sp_start_height = start;
}

/// End to end through the scan loop's pieces: the first stream stops at the
/// unindexed start height, the wallet moves to the oracle's first block, the
/// next stream from there finds the payment in it, and the adjustment is in
/// the status and survives a restart.
#[test]
fn wallet_start_below_the_floor_starts_at_the_floor_and_says_so() {
    run(async {
        let (mut scanner, state) = scanner("floor-start");
        set_wallet_start(&mut scanner, 50).await;
        let paid = payment_block(1_000);
        let mut oracle = FakeOracle::contiguous(1_000, 1_005);

        let err = scanner
            .scan_block_stream(50, 1_005, TestStream::new(vec![Ok(unindexed_message(50))]))
            .await
            .expect_err("the unindexed start height stops the scan");
        assert!(
            scanner
                .start_at_oracle_floor_if_below(&err, 50, 1_005, &mut oracle)
                .await
        );
        assert_eq!(scanner.get_last_scanned_block_height(), 999);
        let health = scanner.scan_health().await;
        let note = health.oracle_floor_start.expect("adjustment is published");
        assert_eq!((note.requested_height, note.floor_height), (50, 1_000));
        assert_eq!(health.stall, None);

        scanner
            .scan_block_stream(
                1_000,
                1_000,
                TestStream::new(vec![Ok(paid.message.clone())]),
            )
            .await
            .expect("scan from the floor");
        assert_eq!(
            owned_outputs(&scanner),
            1,
            "the payment at the floor is found"
        );

        #[cfg(feature = "serde")]
        {
            scanner.save_to_file(&state.0).expect("save");
            let restored = Scanner::from_changeset(
                scanner.client.clone(),
                scanner.p2p_peer(),
                Scanner::load_from_file(&state.0).expect("load"),
                state.0.clone(),
                scanner.network(),
            )
            .expect("restore");
            assert_eq!(restored.scan_health().await.oracle_floor_start, Some(note));
        }
        let _ = &state;
    });
}

/// Once a block was scanned, an unindexed height after it is a gap in the
/// oracle's index, not its floor: the scan keeps stopping there.
#[test]
fn unindexed_height_after_the_wallet_start_is_never_skipped() {
    run(async {
        let (mut scanner, _state) = scanner("floor-gap");
        set_wallet_start(&mut scanner, 1_000).await;
        scanner.update_last_scanned_block_height(1_499);
        // Even an oracle that has nothing below 1 600 does not justify it.
        let mut oracle = FakeOracle::contiguous(1_600, 2_000);
        assert!(
            !scanner
                .start_at_oracle_floor_if_below(&not_indexed_at(1_500), 1_500, 2_000, &mut oracle)
                .await
        );
        assert_eq!(scanner.get_last_scanned_block_height(), 1_499);
        assert_eq!(oracle.probes, 0);
        assert_eq!(scanner.scan_health().await.oracle_floor_start, None);
    });
}

#[test]
fn only_a_not_indexed_stop_at_the_start_moves_the_start() {
    run(async {
        let (mut scanner, _state) = scanner("floor-other");
        set_wallet_start(&mut scanner, 50).await;
        let mut oracle = FakeOracle::contiguous(1_000, 1_005);
        let unavailable: ScannerError = Box::new(ScanStopped {
            height: 50,
            reason: "oracle stream error Unavailable".into(),
            not_indexed: false,
        });
        let plain: ScannerError = "failed to fetch block".into();
        for err in [unavailable, plain, not_indexed_at(51)] {
            assert!(
                !scanner
                    .start_at_oracle_floor_if_below(&err, 50, 1_005, &mut oracle)
                    .await,
                "{err}"
            );
        }
        assert_eq!(scanner.get_last_scanned_block_height(), 49);
        // Start height inside a gap above the floor.
        let mut gappy = FakeOracle::contiguous(10, 1_005).without(40..=60);
        assert!(
            !scanner
                .start_at_oracle_floor_if_below(&not_indexed_at(50), 50, 1_005, &mut gappy)
                .await
        );
        assert_eq!(scanner.get_last_scanned_block_height(), 49);
    });
}

#[test]
fn a_stall_keeps_its_start_time_until_the_height_changes_and_clears_on_progress() {
    run(async {
        let (scanner, _state) = scanner("stall");
        scanner.report_stall(1_500, "first".into()).await;
        let first = scanner.scan_health().await.stall.expect("stall");
        {
            let mut idx = scanner.electrum_index.lock().await;
            idx.scan_health.stall.as_mut().unwrap().since_unix -= 600;
        }
        scanner.report_stall(1_500, "again".into()).await;
        let again = scanner.scan_health().await.stall.expect("stall");
        assert_eq!(again.height, 1_500);
        assert_eq!(again.reason, "again");
        assert_eq!(
            again.since_unix,
            first.since_unix - 600,
            "same height keeps its start"
        );

        scanner.report_stall(1_600, "later".into()).await;
        let moved = scanner.scan_health().await.stall.expect("stall");
        assert!(
            moved.since_unix >= first.since_unix,
            "a new height starts a new stall"
        );

        scanner.clear_stall().await;
        assert_eq!(scanner.scan_health().await.stall, None);
    });
}
