//! Chain reorganisation handling.
//!
//! The scanner remembers the block hash of every height it scanned within
//! the last [`REORG_LOOKBACK`] heights (`Scanner::scanned_block_hashes`,
//! persisted as the state file's `scanned_block_hashes`). Every block the
//! oracle streams for a height the scanner already knows is compared with
//! that hash:
//!
//! - A range scan that continues the scanned chain starts its stream one
//!   height early, at the last scanned height, so the first message proves
//!   the chain underneath is unchanged. `watch_chain` does the same when the
//!   oracle has no new block, which catches a same-height tip replacement.
//! - When that first message disagrees, the fork is somewhere below it: the
//!   scan reopens the stream at the lowest remembered height and walks up.
//!   The first height whose hash disagrees is the first disconnected block,
//!   the one below it is the fork point.
//! - Everything learned above the fork point is rolled back
//!   ([`Scanner::rollback_to`]): transactions and anchors from disconnected
//!   blocks, the owned-output records they created, spent marks they set,
//!   checkpoints, remembered hashes, and the Electrum history. The state is
//!   persisted, and the same stream then scans the new branch as new blocks,
//!   so a transaction that re-confirms is found again at its new height and
//!   one that did not simply stays gone.
//! - A fork at or below the lowest remembered height cannot be located. The
//!   scan stops with [`ReorgTooDeep`] and changes nothing; the wallet must be
//!   rescanned from its birthday with a fresh state file. It keeps failing
//!   loudly on every attempt rather than continuing on a chain it cannot
//!   verify.

use std::collections::BTreeSet;

use bitcoin::hashes::Hash;
use bitcoin::{BlockHash, Txid};
use indexer::bdk_chain::ConfirmationBlockTime;
use indexer::v2::SpIndexerV2;

use super::ScannerError;
use super::scanner::Scanner;

/// How many of the most recent scanned heights keep their block hash, and so
/// the deepest reorganisation the scanner can roll back by itself.
///
/// 144 blocks is one day of mainnet blocks, several times deeper than any
/// mainnet reorganisation since 2013; storing it costs a few kilobytes of
/// state.
pub const REORG_LOOKBACK: u32 = 144;

/// A chain reorganisation reaches at or below the oldest block hash the
/// scanner still remembers, so the fork point cannot be found.
///
/// Nothing was rolled back or scanned. The wallet state may hold outputs and
/// spends from blocks that are no longer in the chain; it has to be rebuilt
/// by rescanning from the wallet birthday with a fresh state file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReorgTooDeep {
    /// Lowest height with a remembered hash; the oracle serves a different
    /// block there.
    pub lowest_known_height: u64,
    /// Last height the scanner had scanned.
    pub last_scanned_height: u64,
}

impl std::fmt::Display for ReorgTooDeep {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "chain reorganisation deeper than the scanner can roll back: the oracle serves a \
             different block at height {} (the oldest block hash remembered, lookback {} blocks, \
             last scanned height {}); the wallet state may contain outputs from blocks that are no \
             longer in the chain; nothing was changed; move the state file away and rescan from \
             the wallet birthday",
            self.lowest_known_height, REORG_LOOKBACK, self.last_scanned_height
        )
    }
}

impl std::error::Error for ReorgTooDeep {}

/// The first block of a stream disagrees with the remembered hash, so the
/// fork lies below the stream's start; the scan reopens the stream lower.
#[derive(Debug)]
pub(crate) struct ReorgBelowStreamStart {
    pub height: u64,
}

impl std::fmt::Display for ReorgBelowStreamStart {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "chain reorganisation detected at height {}; the fork point lies below it",
            self.height
        )
    }
}

impl std::error::Error for ReorgBelowStreamStart {}

/// The oracle serves block hashes in display order.
pub(crate) fn block_hash_from_oracle(display_order: &[u8]) -> Option<BlockHash> {
    let mut bytes: [u8; 32] = display_order.try_into().ok()?;
    bytes.reverse();
    Some(BlockHash::from_byte_array(bytes))
}

/// What the scanner does with one oracle block, judged by its hash.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum BlockCheck {
    /// No remembered hash, or the remembered hash matches.
    Consistent,
    /// Remembered hash differs: the chain was reorganised at this height.
    Reorganised,
}

impl Scanner {
    /// Lowest height with a remembered block hash.
    pub(crate) fn lowest_known_block_height(&self) -> Option<u64> {
        self.scanned_block_hashes
            .keys()
            .next()
            .map(|height| u64::from(*height))
    }

    pub(crate) fn knows_block_hash(&self, height: u64) -> bool {
        u32::try_from(height).is_ok_and(|height| self.scanned_block_hashes.contains_key(&height))
    }

    pub(crate) fn check_block_hash(&self, height: u64, hash: &BlockHash) -> BlockCheck {
        match u32::try_from(height)
            .ok()
            .and_then(|height| self.scanned_block_hashes.get(&height))
        {
            Some(known) if known != hash => BlockCheck::Reorganised,
            _ => BlockCheck::Consistent,
        }
    }

    /// Remember the hash of a block that was just scanned, keeping only the
    /// lookback window below the highest remembered height.
    pub(crate) fn record_scanned_block_hash(&mut self, height: u64, hash: BlockHash) {
        let Ok(height) = u32::try_from(height) else {
            return;
        };
        self.scanned_block_hashes.insert(height, hash);
        let highest = *self
            .scanned_block_hashes
            .keys()
            .next_back()
            .expect("just inserted");
        let keep_from = highest.saturating_sub(REORG_LOOKBACK - 1);
        self.scanned_block_hashes = self.scanned_block_hashes.split_off(&keep_from);
        self.stage.scanned_block_hashes = self.scanned_block_hashes.clone();
    }

    /// Undo everything learned from blocks above `fork_height`, which were
    /// disconnected by a chain reorganisation, and persist the result.
    ///
    /// Transactions confirmed only in disconnected blocks leave the wallet
    /// graph (with their tweaks), so their outputs leave the balance and the
    /// owned-output records, and outputs they spent are unspent again. The
    /// indexer is rebuilt from the remaining changeset, the same way a
    /// restart restores it. Whatever the new branch confirms is found by
    /// scanning it afterwards.
    pub(crate) async fn rollback_to(&mut self, fork_height: u64) -> Result<(), ScannerError> {
        let fork = u32::try_from(fork_height)
            .map_err(|_| format!("fork height {fork_height} is out of range"))?;
        let previous_height = self.last_scanned_block_height;

        // Wallet graph and tweaks.
        let removed = drop_blocks_above(&mut self.stage.indexer, fork);
        let scan_sk = *self.internal_indexer.scan_sk();
        let spend_pk = *self.internal_indexer.spend_pk();
        self.stage.indexer.scan_sk = Some(scan_sk);
        self.stage.indexer.spend_pk = Some(spend_pk);
        let mut indexer = SpIndexerV2::<ConfirmationBlockTime>::new(scan_sk, spend_pk);
        // Labels first: applying the changeset re-runs the BIP-352 scan of
        // every stored transaction, which needs them (as on restore).
        _ = indexer.add_label(0);
        for m in 1..=self.max_label_num {
            _ = indexer.add_label(m);
        }
        indexer.apply_changeset(self.stage.indexer.clone());
        self.internal_indexer = indexer;

        // Owned-output records and spent marks are derived from the graph;
        // rebuild them so no record or spend from a disconnected block stays.
        self.owned_outputs.clear();
        self.stage.owned_outputs.clear();
        self.sync_owned_outputs();

        // Chain position.
        self.block_checkpoints.split_off(&(fork + 1));
        self.stage.block_checkpoints.split_off(&(fork + 1));
        self.scanned_block_hashes.split_off(&(fork + 1));
        self.stage.scanned_block_hashes = self.scanned_block_hashes.clone();
        self.last_scanned_block_height = self.last_scanned_block_height.min(fork_height);
        self.stage.last_scanned_block_height = self.last_scanned_block_height;
        self.last_scanned_block_height_rescan =
            self.last_scanned_block_height_rescan.min(fork_height);
        self.stage.last_scanned_block_height_rescan = self.last_scanned_block_height_rescan;

        // Electrum view: history, SP history, raw txs and headers of the
        // disconnected blocks. Unconfirmed (height 0) entries stay.
        {
            let mut idx = self.electrum_index.lock().await;
            for history in idx.scripthash_history.values_mut() {
                history.retain(|entry| entry.height <= fork);
            }
            idx.sp_history.retain(|entry| entry.height <= fork);
            idx.headers.retain(|height, _| *height <= fork);
            for txid in &removed {
                idx.txs.remove(&txid.to_string());
            }
            let header = idx.headers.get(&fork).cloned().unwrap_or_default();
            idx.tip = Some((fork, header));
        }

        tracing::warn!(
            fork_height,
            previous_height,
            disconnected_blocks = previous_height.saturating_sub(fork_height),
            dropped_transactions = removed.len(),
            owned_outputs = self.owned_outputs.len(),
            "chain reorganisation: rolled wallet state back to the fork point; rescanning the new branch"
        );

        #[cfg(feature = "serde")]
        self.save_to_file(&self.state_file)?;

        let _ = self.notify_reorg.send(fork);
        let _ = self
            .notify_found_utxos
            .send(self.internal_indexer.index().by_shared_secret.len());
        Ok(())
    }
}

/// Remove from an indexer changeset every anchor above `fork` and every
/// transaction that was confirmed only in those blocks, with its tweak and
/// timestamps. Returns the removed txids. Transactions that never had an
/// anchor (unconfirmed) are kept.
fn drop_blocks_above(
    changeset: &mut indexer::v2::ChangeSet<ConfirmationBlockTime>,
    fork: u32,
) -> BTreeSet<Txid> {
    let graph = &mut changeset.graph;
    let anchored_before: BTreeSet<Txid> = graph.anchors.iter().map(|(_, txid)| *txid).collect();
    graph
        .anchors
        .retain(|(anchor, _)| anchor.block_id.height <= fork);
    let anchored_after: BTreeSet<Txid> = graph.anchors.iter().map(|(_, txid)| *txid).collect();
    let removed: BTreeSet<Txid> = anchored_before
        .difference(&anchored_after)
        .copied()
        .collect();

    graph.txs.retain(|tx| !removed.contains(&tx.compute_txid()));
    graph.last_seen.retain(|txid, _| !removed.contains(txid));
    graph.first_seen.retain(|txid, _| !removed.contains(txid));
    graph.last_evicted.retain(|txid, _| !removed.contains(txid));
    changeset
        .txid_to_partial_secret
        .retain(|txid, _| !removed.contains(txid));
    removed
}
