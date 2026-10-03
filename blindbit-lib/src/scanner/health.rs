//! What a long-running scan (`Scanner::watch_chain_until`) reports besides its
//! progress: why it is stuck, and where it started when the wallet's start
//! height lay below the oracle's first indexed block.
//!
//! The scan task holds the scanner lock for as long as it runs, so these
//! conditions are published through the wallet's [`WalletElectrumIndex`]
//! (`scan_health`), which status readers can lock without waiting for the
//! scan.
//!
//! [`WalletElectrumIndex`]: super::electrum_index::WalletElectrumIndex

use std::future::Future;
use std::time::{SystemTime, UNIX_EPOCH};

use bitcoin::BlockHash;
use bitcoin::hashes::Hash;
use tonic::transport::Channel;

use super::ScannerError;
use super::scanner::Scanner;
use crate::oracle_grpc::BlockHeightRequest;
use crate::oracle_grpc::oracle_service_client::OracleServiceClient;

/// Conditions of a running scan worth showing to the user.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScanHealth {
    /// Set while the scan cannot get past a height. The scan keeps retrying;
    /// the entry is cleared as soon as it makes progress again.
    pub stall: Option<ScanStall>,
    /// Set when the wallet's start height lay below the oracle's first
    /// indexed block, so scanning began at the oracle's floor instead.
    pub oracle_floor_start: Option<OracleFloorStart>,
    /// Set while a state file from before owned outputs were recorded is
    /// being rescanned for spends it missed; cleared once the scan is back
    /// at `until_height`.
    pub state_rescan: Option<StateRescan>,
    /// Set when the state file could not be restored, so it was moved aside
    /// and a new scan started from the configured start height.
    pub state_file_reset: Option<StateFileReset>,
}

/// The state file could not be restored. It was moved to `backup_path`
/// (never overwritten) and a new scan started.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateFileReset {
    /// Where the unreadable state file was moved.
    pub backup_path: std::path::PathBuf,
    /// Why it could not be restored.
    pub error: String,
}

/// The restored state predates owned-output records (state format 0), so
/// blocks `from_height..=until_height` are scanned again to find spends of
/// its outputs that it never fetched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StateRescan {
    /// Height of the oldest output the state still showed unspent.
    pub from_height: u64,
    /// Height the state had been scanned to.
    pub until_height: u64,
}

/// The scan cannot get past `height`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanStall {
    /// First height that could not be scanned (the scan resumes here).
    pub height: u64,
    /// Why, as the scanner reported it.
    pub reason: String,
    /// Unix time (seconds) of the first failed attempt at this height.
    pub since_unix: u64,
}

/// The wallet's start height had no oracle data, so scanning began at the
/// oracle's lowest indexed height. Blocks `requested_height..floor_height`
/// were not scanned. Persisted in the state file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct OracleFloorStart {
    /// The start height the wallet asked for.
    pub requested_height: u64,
    /// The oracle's lowest indexed height, where scanning began.
    pub floor_height: u64,
}

/// A range scan stopped at `height` without scanning it.
///
/// Every block below `height` in the range was fully processed; nothing from
/// `height` on was. The caller resumes at `height`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanStopped {
    /// First height that was not scanned.
    pub height: u64,
    /// What the oracle sent (or failed to send) for `height`.
    pub reason: String,
    /// The oracle reported `height` as not indexed: an empty or zero block
    /// hash, or a `NOT_FOUND` status.
    pub not_indexed: bool,
}

impl std::fmt::Display for ScanStopped {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let height = self.height;
        write!(
            f,
            "scan stopped at height {height}: {}; nothing from height {height} on was scanned, \
             rescan from height {height}",
            self.reason
        )
    }
}

impl std::error::Error for ScanStopped {}

/// The scan was cancelled (the token given to
/// [`Scanner::watch_chain_until`](super::Scanner::watch_chain_until) was
/// cancelled) before it finished.
///
/// It stops only where nothing is half done: between blocks, or while it
/// waits for the oracle, the P2P node or its next poll. Every block up to
/// the scanned height was fully processed and nothing above it was, so the
/// next scan resumes at the block after it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScanCancelled;

impl std::fmt::Display for ScanCancelled {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("scan cancelled")
    }
}

impl std::error::Error for ScanCancelled {}

/// The oracle's per-height block hash lookup (`GetBlockHashByHeight`).
pub(crate) trait OracleProbe {
    /// The block hash the oracle has indexed at `height`, or `None` when it
    /// has not indexed that height (an empty or zero hash, or `NOT_FOUND`).
    /// Any other failure is an error.
    fn block_hash_at(
        &mut self,
        height: u64,
    ) -> impl Future<Output = Result<Option<BlockHash>, ScannerError>> + Send;
}

impl OracleProbe for OracleServiceClient<Channel> {
    async fn block_hash_at(&mut self, height: u64) -> Result<Option<BlockHash>, ScannerError> {
        let request = tonic::Request::new(BlockHeightRequest {
            block_height: height,
        });
        match self.get_block_hash_by_height(request).await {
            Ok(response) => Ok(indexed_block_hash(&response.into_inner().block_hash)),
            Err(status) if status.code() == tonic::Code::NotFound => Ok(None),
            Err(status) => Err(format!(
                "oracle GetBlockHashByHeight({height}) failed: {:?}: {}",
                status.code(),
                status.message()
            )
            .into()),
        }
    }
}

/// A block hash as the oracle serves it (display order), or `None` when it is
/// not a real hash: what an oracle answers for a height it has not indexed.
pub(crate) fn indexed_block_hash(display_order: &[u8]) -> Option<BlockHash> {
    let mut bytes: [u8; 32] = display_order.try_into().ok()?;
    if bytes.iter().all(|b| *b == 0) {
        return None;
    }
    bytes.reverse();
    Some(BlockHash::from_byte_array(bytes))
}

/// Upper bound on `GetBlockHashByHeight` calls one floor search may make.
/// A contiguous index needs about `3 * log2(tip)` (~60 on mainnet).
const FLOOR_SEARCH_MAX_PROBES: u32 = 400;

/// Find the oracle's lowest indexed height when `from`, the wallet's start
/// height, is not indexed.
///
/// Returns `Some(floor)` only when `from` lies *below* the oracle's floor:
/// nothing at or below `from` is indexed and `floor` is the lowest indexed
/// height above it. Returns `None` when `from` is a gap *above* the floor
/// (some lower height is indexed), when `from` is indexed after all, or when
/// the oracle has no data even at `tip`; such a height must not be skipped.
///
/// The index need not be contiguous. A binary search finds a boundary, then
/// probes at exponentially growing distances below it look for indexed
/// heights the search jumped over; any hit restarts the search below it. The
/// same back-off below `from` tells a gap above the floor from the region
/// below it. A gap can only be missed when it is wider than the indexed run
/// below it, which no real oracle produces.
pub(crate) async fn find_oracle_floor<P: OracleProbe>(
    probe: &mut P,
    from: u64,
    tip: u64,
) -> Result<Option<u64>, ScannerError> {
    let mut oracle = CountedProbe { probe, probes: 0 };

    if from >= tip || oracle.indexed(from).await? {
        return Ok(None);
    }
    // Anything indexed below `from` makes it a gap above the floor.
    let mut distance = 1u64;
    while distance <= from {
        if oracle.indexed(from - distance).await? {
            return Ok(None);
        }
        distance *= 2;
    }

    if !oracle.indexed(tip).await? {
        return Ok(None);
    }
    // Invariant: `from` is not indexed, `hi` is.
    let mut hi = tip;
    loop {
        let mut lo = from;
        while hi - lo > 1 {
            let mid = lo + (hi - lo) / 2;
            if oracle.indexed(mid).await? {
                hi = mid;
            } else {
                lo = mid;
            }
        }
        // `hi - 1` is not indexed; look further down for indexed runs the
        // search jumped over.
        let mut lower = None;
        let mut distance = 2u64;
        while hi - from > distance {
            if oracle.indexed(hi - distance).await? {
                lower = Some(hi - distance);
                break;
            }
            distance *= 2;
        }
        match lower {
            Some(height) => hi = height,
            None => return Ok(Some(hi)),
        }
    }
}

/// An [`OracleProbe`] with a lookup budget.
struct CountedProbe<'a, P> {
    probe: &'a mut P,
    probes: u32,
}

impl<P: OracleProbe> CountedProbe<'_, P> {
    async fn indexed(&mut self, height: u64) -> Result<bool, ScannerError> {
        self.probes += 1;
        if self.probes > FLOOR_SEARCH_MAX_PROBES {
            return Err(format!(
                "gave up locating the oracle's first indexed block after \
                 {FLOOR_SEARCH_MAX_PROBES} lookups"
            )
            .into());
        }
        Ok(self.probe.block_hash_at(height).await?.is_some())
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl Scanner {
    /// Record that this scanner replaces a state file that could not be
    /// restored. Called right after construction, before the index is shared.
    #[cfg(feature = "serde")]
    pub(crate) fn note_state_file_reset(&mut self, reset: StateFileReset) {
        if let Some(index) = std::sync::Arc::get_mut(&mut self.electrum_index) {
            index.get_mut().scan_health.state_file_reset = Some(reset);
        }
    }

    /// Current scan health as published to status readers.
    pub async fn scan_health(&self) -> ScanHealth {
        self.electrum_index.lock().await.scan_health.clone()
    }

    /// Publish that the scan cannot get past `height`. Repeated failures at
    /// the same height keep the time of the first one.
    pub(crate) async fn report_stall(&self, height: u64, reason: String) {
        let mut idx = self.electrum_index.lock().await;
        let since_unix = match &idx.scan_health.stall {
            Some(stall) if stall.height == height => stall.since_unix,
            _ => unix_now(),
        };
        idx.scan_health.stall = Some(ScanStall {
            height,
            reason,
            since_unix,
        });
    }

    /// The scan made progress or is caught up: clear any stall, and end a
    /// state rescan ([`StateRescan`]) once it is back where it started.
    pub(crate) async fn clear_stall(&self) {
        let mut idx = self.electrum_index.lock().await;
        if idx.scan_health.stall.take().is_some() {
            tracing::info!(
                height = self.last_scanned_block_height,
                "scan is making progress again"
            );
        }
        if idx
            .scan_health
            .state_rescan
            .is_some_and(|rescan| self.last_scanned_block_height >= rescan.until_height)
        {
            idx.scan_health.state_rescan = None;
            tracing::info!(
                height = self.last_scanned_block_height,
                "rescan for spends missed by the old state file is complete"
            );
        }
    }

    /// After a failed scan of `from..=tip`: when `from` is the wallet's start
    /// height and lies below the oracle's first indexed block, move the
    /// start up to that block and return `true` (scan again right away).
    ///
    /// Only heights below the oracle's floor are ever skipped. A height the
    /// oracle has not indexed above its floor (a gap) is never skipped; the
    /// scan keeps stopping there until the oracle serves it.
    pub(crate) async fn start_at_oracle_floor_if_below<P: OracleProbe>(
        &mut self,
        error: &ScannerError,
        from: u64,
        tip: u64,
        probe: &mut P,
    ) -> bool {
        let Some(stopped) = error.downcast_ref::<ScanStopped>() else {
            return false;
        };
        if !stopped.not_indexed || stopped.height != from {
            return false;
        }
        // Only at the wallet's start: once a block was scanned, the height
        // after it is a gap, not the floor.
        let wallet_start = self.electrum_index.lock().await.sp_start_height;
        if wallet_start == 0 || from > wallet_start {
            return false;
        }
        let floor = match find_oracle_floor(probe, from, tip).await {
            Ok(Some(floor)) => floor,
            Ok(None) => return false,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    height = from,
                    "could not locate the oracle's first indexed block"
                );
                return false;
            }
        };

        tracing::warn!(
            requested_height = from,
            oracle_floor = floor,
            skipped_blocks = floor - from,
            "the wallet's start height is below the oracle's first indexed block; scanning \
             starts at the oracle's first block, and blocks below it are not scanned"
        );
        let note = OracleFloorStart {
            requested_height: from,
            floor_height: floor,
        };
        self.update_last_scanned_block_height(floor - 1);
        self.stage.oracle_floor_start = Some(note);
        {
            let mut idx = self.electrum_index.lock().await;
            idx.scan_health.oracle_floor_start = Some(note);
            idx.scan_health.stall = None;
        }
        #[cfg(feature = "serde")]
        if let Err(e) = self.save_to_file(&self.state_file) {
            tracing::warn!(error = %e, "failed to save state");
        }
        true
    }
}
