use std::collections::HashMap;

use bdk_sp::receive::SpOut;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::PublicKey;
use bitcoin::{BlockHash, OutPoint, Txid};
use indexer::bdk_chain::bdk_core::Merge;
use indexer::bdk_chain::local_chain::LocalChain;
use indexer::bdk_chain::{BlockId, CanonicalizationParams};
use tokio::time;

use crate::oracle_grpc::{
    BlockIdentifier, BlockScanDataShortResponse, ComputeIndexTxItem, FullTxItem,
    RangedBlockHeightRequestFiltered,
};

use super::electrum_index::{ScriptHashEntry, SpHistoryEntry, electrum_scripthash};
use super::p2p;
use super::reorg::{BlockCheck, ReorgBelowStreamStart, ReorgTooDeep, block_hash_from_oracle};
use super::scanner::Scanner;
use super::types::{BlockIdentifierDisplay, ProbableMatch};
use super::utils::{byte_array_to_txid, construct_dummy_tx, match_short_pubkey};
use super::ScannerError;

/// BIP-352 limits one recipient group to this many matched outputs.
///
/// Only [`Scanner::scan_transaction_full`] applies it, and that function has no
/// production caller (see its doc comment); the live receive path does not
/// enforce a K_max.
const BIP352_K_MAX: usize = 2323;

/// Insert or upgrade a scripthash history entry.
///
/// If the tx is already present with a confirmed height (> 0), it is left
/// untouched.  If it is present at height 0 (unconfirmed, added by the
/// broadcast handler), the entry is upgraded to the confirmed height.
/// Otherwise the entry is appended and the list is re-sorted.
fn upsert_history_entry(history: &mut Vec<ScriptHashEntry>, entry: ScriptHashEntry) {
    match history.iter().position(|e| e.tx_hash == entry.tx_hash) {
        Some(pos) if history[pos].height == 0 && entry.height > 0 => {
            // Promote unconfirmed → confirmed.
            history[pos].height = entry.height;
            history.sort_by_key(|e| e.height);
        }
        Some(_) => {} // already confirmed (or same height), leave it
        None => {
            history.push(entry);
            history.sort_by_key(|e| e.height);
        }
    }
}

/// The per-block message source of a block-range scan.
///
/// Production scans read a tonic `Streaming`; tests feed messages and error
/// statuses in-process to exercise how the scanner reacts to what an oracle
/// can send mid-range.
pub(crate) trait BlockScanDataStream {
    fn next_message(
        &mut self,
    ) -> impl Future<Output = Result<Option<BlockScanDataShortResponse>, tonic::Status>> + Send;
}

impl BlockScanDataStream for tonic::Streaming<BlockScanDataShortResponse> {
    fn next_message(
        &mut self,
    ) -> impl Future<Output = Result<Option<BlockScanDataShortResponse>, tonic::Status>> + Send
    {
        self.message()
    }
}

/// Opens `StreamBlockScanDataShort` streams for a range scan. A scan may
/// open a second stream lower down when it has to locate a fork point.
pub(crate) trait BlockStreamSource {
    type Stream: BlockScanDataStream + Send;

    fn open(
        &mut self,
        start: u64,
        end: u64,
    ) -> impl Future<Output = Result<Self::Stream, ScannerError>> + Send;
}

/// The oracle's gRPC service as a [`BlockStreamSource`].
struct OracleStreams(crate::oracle_grpc::oracle_service_client::OracleServiceClient<tonic::transport::Channel>);

impl BlockStreamSource for OracleStreams {
    type Stream = tonic::Streaming<BlockScanDataShortResponse>;

    async fn open(&mut self, start: u64, end: u64) -> Result<Self::Stream, ScannerError> {
        let request = tonic::Request::new(RangedBlockHeightRequestFiltered {
            start,
            end,
            dustlimit: 0,
            cut_through: false,
        });
        Ok(self
            .0
            .stream_block_scan_data_short(request)
            .await
            .map_err(|status| -> ScannerError {
                format!(
                    "oracle refused to stream blocks {start}..={end}: {:?}: {}",
                    status.code(),
                    status.message()
                )
                .into()
            })?
            .into_inner())
    }
}

/// Read the next block message, turning an error status into a scanner error
/// that names the height the scan stopped at.
///
/// There is no retry here: the scan stops at `height` and the caller rescans
/// from there (`watch_chain` on its next poll, `blindbit-cli` on its next run).
async fn next_block<S: BlockScanDataStream>(
    stream: &mut S,
    height: u64,
) -> Result<Option<BlockScanDataShortResponse>, ScannerError> {
    stream.next_message().await.map_err(|status| {
        stream_stopped(
            height,
            &format!("oracle stream error {:?}: {}", status.code(), status.message()),
        )
    })
}

/// A block message is only scannable if it is the next height in the range
/// and carries a real block hash. An oracle answers a height it has not
/// indexed with an empty hash and no data; treating that as an empty block
/// would silently skip any payment in it.
fn check_block_identifier(
    block_identifier: &BlockIdentifier,
    expected_height: u64,
) -> Result<(), ScannerError> {
    if block_identifier.block_height != expected_height {
        return Err(stream_stopped(
            expected_height,
            &format!(
                "the oracle sent height {} instead",
                block_identifier.block_height
            ),
        ));
    }
    let hash = &block_identifier.block_hash;
    if hash.len() != 32 || hash.iter().all(|b| *b == 0) {
        return Err(stream_stopped(
            expected_height,
            &format!(
                "the oracle sent no valid block hash ({} bytes); the height is probably not indexed",
                hash.len()
            ),
        ));
    }
    Ok(())
}

fn stream_stopped(height: u64, reason: &str) -> ScannerError {
    format!(
        "scan stopped at height {height}: {reason}; nothing from height {height} on was scanned, \
         rescan from height {height}"
    )
    .into()
}

impl Scanner {
    /// Scan a block range for new utxos and spent outpoints, after checking
    /// that the chain already scanned below it was not reorganised.
    ///
    /// When `start - 1` is a scanned height, its block is streamed too and
    /// compared with the remembered hash; a reorganisation is rolled back to
    /// the fork point and the new branch scanned (see `scanner/reorg.rs`).
    /// `start = end + 1` only runs that check. A reorganisation deeper than
    /// [`super::REORG_LOOKBACK`] is a [`ReorgTooDeep`] error.
    pub async fn scan_block_range(
        &mut self,
        start: u64,
        end: u64,
    ) -> Result<(), ScannerError> {
        let source = OracleStreams(self.client.clone());
        self.scan_range_from(start, end, source).await
    }

    /// [`Self::scan_block_range`] over any [`BlockStreamSource`].
    pub(crate) async fn scan_range_from<Src: BlockStreamSource>(
        &mut self,
        start: u64,
        end: u64,
        mut source: Src,
    ) -> Result<(), ScannerError> {
        // Overlap one block with what was already scanned, so the stream
        // itself proves the chain below `start` is unchanged.
        let mut first = match start.checked_sub(1) {
            Some(prev) if prev > 0 && self.knows_block_hash(prev) => prev,
            _ => start,
        };
        if first > end {
            return Ok(());
        }
        loop {
            let stream = source.open(first, end).await?;
            match self.scan_block_stream_from(first, start, end, stream).await {
                Err(e) => {
                    let Some(reorg) = e.downcast_ref::<ReorgBelowStreamStart>() else {
                        return Err(e);
                    };
                    // The fork is below the stream's first block: walk up
                    // from the oldest remembered hash to find it.
                    match self.lowest_known_block_height() {
                        Some(lowest) if lowest < reorg.height => {
                            tracing::warn!(
                                height = reorg.height,
                                from = lowest,
                                "chain reorganisation detected; locating the fork point"
                            );
                            first = lowest;
                        }
                        _ => {
                            return Err(Box::new(ReorgTooDeep {
                                lowest_known_height: reorg.height,
                                last_scanned_height: self.last_scanned_block_height,
                            }));
                        }
                    }
                }
                ok => return ok,
            }
        }
    }

    /// Scan the per-block messages of one `StreamBlockScanDataShort` response
    /// for the range `start..=end`.
    ///
    /// Every height in the range must arrive, in order, with a valid block
    /// hash. Anything else — a message the oracle sends for a height it has
    /// not indexed (empty block hash), a skipped or repeated height, an error
    /// status, or a stream that ends before `end` — stops the scan with an
    /// error. Such a block is never taken as "no payments": the scan height
    /// stays at the last block that was fully processed, so the next scan
    /// resumes at the block that could not be scanned.
    #[cfg(test)]
    pub(crate) async fn scan_block_stream<S: BlockScanDataStream>(
        &mut self,
        start: u64,
        end: u64,
        stream: S,
    ) -> Result<(), ScannerError> {
        self.scan_block_stream_from(start, start, end, stream).await
    }

    /// [`Self::scan_block_stream`] for a stream that begins at `first`, at or
    /// below the scan's `start`. Blocks below `start` are only checked
    /// against the remembered hashes, not scanned again. Any block whose
    /// hash differs from the remembered one is a reorganisation: when a
    /// block before it in this stream agreed, the one below it is the fork
    /// point, the state is rolled back there and scanning goes on from that
    /// block; when it is the stream's first block, the scan returns
    /// [`ReorgBelowStreamStart`] (or [`ReorgTooDeep`] if nothing older is
    /// remembered) without changing anything.
    pub(crate) async fn scan_block_stream_from<S: BlockScanDataStream>(
        &mut self,
        first: u64,
        start: u64,
        end: u64,
        mut stream: S,
    ) -> Result<(), ScannerError> {
        // Stamp sp_start_height into the index so the Electrum server's
        // SP subscription response always uses the correct scan start key.
        // Only set it on the first call; watch_chain increments start each
        // iteration, so we must not overwrite the original wallet birthday.
        {
            let mut idx = self.electrum_index.lock().await;
            if idx.sp_start_height == 0 {
                idx.sp_start_height = start;
            }
        }

        let genesis_hash = BlockHash::from_byte_array(
            indexer::bdk_chain::bitcoin::blockdata::constants::ChainHash::BITCOIN.to_bytes(),
        );

        let mut last_block_id: BlockId = BlockId {
            height: 0,
            hash: genesis_hash,
        };

        let mut p2p_conn: Option<p2p::P2pConnection> = None;

        let mut expected_height = first;
        // Blocks from here on are scanned; below it they are only checked.
        let mut scan_from = start;
        // Whether an earlier block of this stream is known to be on the
        // oracle's chain (checked or scanned).
        let mut have_prior_block = false;
        // Whether anything was scanned or rolled back (worth a save).
        let mut changed = false;

        while let Some(block_scan_data) = next_block(&mut stream, expected_height).await? {
            let Some(block_identifier) = block_scan_data.block_identifier.clone() else {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "block identifier is missing",
                )
                .into());
            };
            check_block_identifier(&block_identifier, expected_height)?;
            expected_height += 1;
            let oracle_block_hash = block_hash_from_oracle(&block_identifier.block_hash)
                .expect("block hash length checked above");
            let height = block_identifier.block_height;
            match self.check_block_hash(height, &oracle_block_hash) {
                BlockCheck::Reorganised if !have_prior_block => {
                    if self.lowest_known_block_height() == Some(height) {
                        return Err(Box::new(ReorgTooDeep {
                            lowest_known_height: height,
                            last_scanned_height: self.last_scanned_block_height,
                        }));
                    }
                    return Err(Box::new(ReorgBelowStreamStart { height }));
                }
                BlockCheck::Reorganised => {
                    self.rollback_to(height - 1).await?;
                    scan_from = scan_from.min(height);
                }
                BlockCheck::Consistent if height < scan_from => {
                    // Already scanned, still on the chain.
                    have_prior_block = true;
                    continue;
                }
                BlockCheck::Consistent => {}
            }
            have_prior_block = true;
            changed = true;
            let block_id = BlockIdentifierDisplay(&block_identifier);
            tracing::debug!(height = block_id.0.block_height, "received block data from oracle");

            if block_identifier.block_height % 100 == 0 {
                let scanned = block_identifier.block_height.saturating_sub(start) + 1;
                let total = end.saturating_sub(start) + 1;
                let pct = (scanned * 100 / total).min(100);
                tracing::info!(
                    height = block_identifier.block_height,
                    scanned,
                    total,
                    pct,
                    "scan progress"
                );
            }

            match self.scan_short_block_data(block_scan_data) {
                Ok(probable_match_opt) => {
                    let probable_match = match probable_match_opt {
                        None => {
                            // No match — still advance tip/progress so Sparrow sees sync moving.
                            self.notify_electrum_scan_progress(
                                block_identifier.block_height,
                                start,
                                end,
                            )
                            .await;
                            self.last_scanned_block_height = block_identifier.block_height;
                            self.stage.last_scanned_block_height = block_identifier.block_height;
                            self.record_scanned_block_hash(height, oracle_block_hash);
                            // Periodically checkpoint progress so a crash/restart during a
                            // long initial catch-up scan doesn't lose everything.
                            #[cfg(feature = "serde")]
                            if block_identifier.block_height % 1000 == 0 {
                                if let Err(e) = self.save_to_file(&self.state_file) {
                                    tracing::warn!(error = %e, "failed to save periodic checkpoint");
                                }
                            }
                            continue;
                        }
                        Some(probable_match) => probable_match,
                    };
                    // pull the full block data

                    // Ensure we have exactly 32 bytes
                    let mut reversed_block_hash_slice = block_identifier.block_hash.clone();
                    reversed_block_hash_slice.reverse();
                    let block_hash_arr: [u8; 32] = reversed_block_hash_slice
                        .try_into()
                        .expect("block_hash length already verified to be 32");

                    let block_hash = BlockHash::from_byte_array(block_hash_arr);

                    tracing::debug!(block_hash = %block_hash, "fetching full block via P2P");

                    let block = self
                        .fetch_block_with_retry(&mut p2p_conn, block_hash, block_identifier.block_height)
                        .await?;

                    // Apply block to indexer and stage the changes
                    self.apply_matched_block(
                        &block,
                        &probable_match,
                        block_identifier.block_height as u32,
                    );
                    // Record newly found outputs and confirmed spends of owned ones.
                    self.sync_owned_outputs();

                    // Update block checkpoints: only store blocks where we found something
                    let block_height_u32 = block_identifier.block_height as u32;
                    let block_hash = block.block_hash();
                    let block_id = BlockId {
                        height: block_height_u32,
                        hash: block_hash,
                    };
                    last_block_id = block_id;

                    // Add this block as a checkpoint since we found something in it
                    self.block_checkpoints.insert(block_height_u32, block_hash);
                    self.stage
                        .block_checkpoints
                        .insert(block_height_u32, block_hash);

                    tracing::debug!(height = block_identifier.block_height, "indexer graph transactions after block");
                    for inner_tx in self.internal_indexer.graph().full_txs() {
                        tracing::debug!(txid = %inner_tx.txid, "tracked transaction in graph");
                    }

                    // Print balance from the graph
                    // Following the bdk-sp pattern: get outpoints from index and pass to balance
                    let graph = self.internal_indexer.graph();
                    // Get all outpoints from by_shared_secret - these are our UTXOs
                    // The balance method expects (u32, OutPoint) where u32 is txout_index
                    // We'll use the vout from the OutPoint as the txout_index
                    let outpoints: Vec<(u32, OutPoint)> = self
                        .internal_indexer
                        .index()
                        .by_shared_secret
                        .keys()
                        .map(|outpoint| (outpoint.vout, *outpoint))
                        .collect();

                    // Create LocalChain from sparse checkpoints for balance calculation
                    let local_chain = LocalChain::from_blocks(self.block_checkpoints.clone())
                        .expect("Failed to create LocalChain from checkpoints");

                    let balance = graph.balance(
                        &local_chain,
                        block_id,
                        CanonicalizationParams::default(),
                        outpoints.iter().copied(), // confirmed outpoints from our index
                        |_txout_index, _script| true, // include all pending outputs
                    );

                    #[cfg(feature = "serde")]
                    if let Err(save_err) = self.save_to_file(&self.state_file) {
                        tracing::warn!(error = %save_err, "failed to save state");
                    } else {
                        tracing::debug!("state saved");
                    }
                    tracing::info!(
                        total = %balance.total(),
                        confirmed = %balance.confirmed,
                        trusted_pending = %balance.trusted_pending,
                        untrusted_pending = %balance.untrusted_pending,
                        "balance"
                    );

                    // --- Electrum index update ---
                    // Update the wallet-scoped Electrum index while the full block is in hand.
                    // The block is already fetched from P2P so this costs nothing extra.
                    {
                        let owned_outpoints: std::collections::HashSet<bitcoin::OutPoint> = self
                            .internal_indexer
                            .index()
                            .by_shared_secret
                            .keys()
                            .cloned()
                            .collect();

                        // Build outpoint → script map from the graph so we can derive the
                        // scripthash of a spent output without re-fetching anything.
                        let mut outpoint_scripts: HashMap<bitcoin::OutPoint, bitcoin::ScriptBuf> =
                            HashMap::new();
                        for node in self.internal_indexer.graph().full_txs() {
                            let node_txid = node.txid;
                            for (vout, out) in node.tx.output.iter().enumerate() {
                                let op = bitcoin::OutPoint { txid: node_txid, vout: vout as u32 };
                                if owned_outpoints.contains(&op) {
                                    outpoint_scripts.insert(op, out.script_pubkey.clone());
                                }
                            }
                        }

                        let header_hex = hex::encode(
                            bitcoin::consensus::encode::serialize(&block.header),
                        );

                        let mut idx = self.electrum_index.lock().await;
                        idx.headers.insert(block_height_u32, header_hex.clone());
                        idx.tip = Some((block_height_u32, header_hex));

                        for tx in &block.txdata {
                            let txid = tx.compute_txid();
                            let mut is_ours = false;

                            // Receiving side: outputs belonging to the wallet.
                            for (vout, output) in tx.output.iter().enumerate() {
                                let outpoint = bitcoin::OutPoint {
                                    txid,
                                    vout: vout as u32,
                                };
                                if owned_outpoints.contains(&outpoint) {
                                    is_ours = true;
                                    let scripthash =
                                        electrum_scripthash(&output.script_pubkey);
                                    let entry = ScriptHashEntry {
                                        tx_hash: txid.to_string(),
                                        height: block_height_u32,
                                        fee: 0,
                                    };
                                    let history = idx
                                        .scripthash_history
                                        .entry(scripthash)
                                        .or_default();
                                    upsert_history_entry(history, entry);
                                }
                            }

                            // Spending side: inputs that consume one of our outputs.
                            // Sparrow expects the spending tx to also appear in
                            // blockchain.scripthash.get_history for the spent scripthash.
                            for input in &tx.input {
                                if let Some(script) =
                                    outpoint_scripts.get(&input.previous_output)
                                {
                                    is_ours = true;
                                    let scripthash = electrum_scripthash(script);
                                    let entry = ScriptHashEntry {
                                        tx_hash: txid.to_string(),
                                        height: block_height_u32,
                                        fee: 0,
                                    };
                                    let history = idx
                                        .scripthash_history
                                        .entry(scripthash)
                                        .or_default();
                                    upsert_history_entry(history, entry);
                                }
                            }

                            if is_ours {
                                let raw = bitcoin::consensus::encode::serialize(tx);
                                idx.txs.insert(txid.to_string(), raw);
                            }
                        }

                        // SP history — use confirmed txid_to_partial_secret
                        // (populated by apply_block_relevant for this block's matches).
                        for tx in &block.txdata {
                            let txid = tx.compute_txid();
                            if let Some(secret) = self
                                .internal_indexer
                                .index()
                                .txid_to_partial_secret
                                .get(&txid)
                            {
                                let entry = SpHistoryEntry {
                                    tx_hash: txid.to_string(),
                                    height: block_height_u32,
                                    tweak_hex: secret.to_string(),
                                };
                                if !idx.sp_history.iter().any(|e| e.tx_hash == entry.tx_hash) {
                                    idx.sp_history.push(entry);
                                    idx.sp_history.sort_by_key(|e| e.height);
                                }
                            }
                        }

                        // Promote any pending (unconfirmed) height-0 entries for txs
                        // that appear in this block.  This handles outputs that the SP
                        // scanner does not own (e.g. regular taproot change, recipient
                        // outputs) which were added at height 0 by the broadcast handler
                        // and must now be updated to the confirmed block height.
                        for tx in &block.txdata {
                            let txid_str = tx.compute_txid().to_string();
                            if let Some(pending_shs) = idx.pending_scripthashes.remove(&txid_str) {
                                for sh in &pending_shs {
                                    if let Some(history) = idx.scripthash_history.get_mut(sh) {
                                        let mut updated = false;
                                        for entry in history.iter_mut() {
                                            if entry.tx_hash == txid_str && entry.height == 0 {
                                                entry.height = block_height_u32;
                                                updated = true;
                                            }
                                        }
                                        if updated {
                                            history.sort_by_key(|e| e.height);
                                        }
                                    }
                                }
                                tracing::debug!(
                                    txid = %txid_str,
                                    height = block_height_u32,
                                    scripthashes = pending_shs.len(),
                                    "promoted pending tx to confirmed height"
                                );
                            }
                        }

                        // Track progress for incremental SP notifications.
                        let scanned = block_identifier.block_height.saturating_sub(start) + 1;
                        let total = end.saturating_sub(start) + 1;
                        idx.scan_progress = (scanned as f32 / total as f32).min(1.0);
                    }

                    self.notify_electrum_scan_progress(
                        block_identifier.block_height,
                        start,
                        end,
                    )
                    .await;
                }
                Err(e) => {
                    tracing::error!(error = ?e, "error scanning short block data");
                    return Err(e);
                }
            }

            // Update last scanned block height and stage it
            self.last_scanned_block_height = block_identifier.block_height;
            self.stage.last_scanned_block_height = block_identifier.block_height;
            self.record_scanned_block_hash(height, oracle_block_hash);
        }

        if expected_height <= end {
            return Err(stream_stopped(
                expected_height,
                "the oracle ended the stream before this height",
            ));
        }

        if !changed {
            // Only checked blocks that were already scanned.
            return Ok(());
        }

        let outpoints: Vec<(u32, OutPoint)> = self
            .internal_indexer
            .index()
            .by_shared_secret
            .keys()
            .map(|outpoint| (outpoint.vout, *outpoint))
            .collect();

        // Create LocalChain from sparse checkpoints for balance calculation
        let local_chain = LocalChain::from_blocks(self.block_checkpoints.clone())
            .expect("Failed to create LocalChain from checkpoints");

        let balance = self.internal_indexer.graph().balance(
            &local_chain,
            last_block_id,
            CanonicalizationParams::default(),
            outpoints.iter().copied(), // confirmed outpoints from our index
            |_txout_index, _script| true, // include all pending outputs
        );
        tracing::info!(
            total = %balance.total(),
            confirmed = %balance.confirmed,
            trusted_pending = %balance.trusted_pending,
            untrusted_pending = %balance.untrusted_pending,
            "balance after scan"
        );

        // With persistence enabled, save progress at the end of a scan range so watch_chain
        // resumes from the correct height after a restart, even when no
        // wallet-relevant transactions were found in this range.
        #[cfg(feature = "serde")]
        if let Err(e) = self.save_to_file(&self.state_file) {
            tracing::warn!(error = %e, "failed to save state after scan");
        }

        Ok(())
    }

    /// Fetch a full block over P2P, transparently (re)connecting on failure.
    ///
    /// The P2P fetch is blocking I/O, so it runs on a fresh connection that is
    /// reused across calls via `p2p_conn`.  If a fetch fails (the peer closed
    /// the connection, timed out, or replied notfound), we drop the dead
    /// connection and retry on a brand-new one with linear backoff.  Only after
    /// all attempts are exhausted does the error propagate, at which point
    /// `watch_chain` will retry the whole range on the next poll.
    async fn fetch_block_with_retry(
        &self,
        p2p_conn: &mut Option<p2p::P2pConnection>,
        block_hash: BlockHash,
        height: u64,
    ) -> Result<bitcoin::Block, ScannerError> {
        const MAX_ATTEMPTS: u32 = 4;

        // Tests serve full blocks in-process instead of over P2P.
        #[cfg(test)]
        if let Some(block) = super::stream_safety_tests::served_block(&block_hash) {
            return Ok(block);
        }

        let mut last_err: Option<ScannerError> = None;
        for attempt in 1..=MAX_ATTEMPTS {
            if p2p_conn.is_none() {
                match p2p::P2pConnection::connect(self.p2p_peer, self.network) {
                    Ok(conn) => *p2p_conn = Some(conn),
                    Err(e) => {
                        tracing::warn!(
                            peer = %self.p2p_peer,
                            attempt,
                            error = %e,
                            "failed to open P2P connection"
                        );
                        last_err = Some(e);
                        time::sleep(time::Duration::from_secs(attempt as u64)).await;
                        continue;
                    }
                }
            }

            match p2p_conn.as_mut().unwrap().fetch_block(block_hash) {
                Ok(block) => {
                    // The peer may close the connection after serving a block (connection
                    // limits, rate limiting, etc.).  Proactively discard the connection
                    // so the next fetch starts a fresh handshake rather than discovering
                    // the dead socket mid-read on the next attempt.
                    *p2p_conn = None;
                    return Ok(block);
                }
                Err(e) => {
                    tracing::warn!(
                        peer = %self.p2p_peer,
                        height,
                        block_hash = %block_hash,
                        attempt,
                        max_attempts = MAX_ATTEMPTS,
                        error = %e,
                        "block fetch failed; dropping connection and retrying"
                    );
                    // Drop the (likely dead) connection so the next attempt
                    // starts a fresh handshake.
                    *p2p_conn = None;
                    last_err = Some(e);
                    if attempt < MAX_ATTEMPTS {
                        time::sleep(time::Duration::from_secs(attempt as u64)).await;
                    }
                }
            }
        }

        Err(last_err.unwrap_or_else(|| {
            format!("failed to fetch block {block_hash} from {} after {MAX_ATTEMPTS} attempts", self.p2p_peer)
                .into()
        }))
    }

    /// Update Electrum tip height and scan progress after each scanned block.
    /// Fires a push notification even when no wallet outputs were found.
    async fn notify_electrum_scan_progress(&self, block_height: u64, start: u64, end: u64) {
        let height_u32 = block_height as u32;
        let scanned = block_height.saturating_sub(start) + 1;
        let total = end.saturating_sub(start) + 1;
        let progress = (scanned as f32 / total as f32).min(1.0);

        {
            let mut idx = self.electrum_index.lock().await;
            idx.scan_progress = progress;
            let header_hex = idx
                .tip
                .as_ref()
                .map(|(_, hex)| hex.clone())
                .unwrap_or_default();
            idx.tip = Some((height_u32, header_hex));
        }

        let utxo_count = self.internal_indexer.index().by_shared_secret.len();
        let _ = self.notify_found_utxos.send(utxo_count);
    }

    /// Watch the chain for new blocks indefinitely.
    ///
    /// Polls the oracle every 10 seconds via `GetInfo`.  Whenever the oracle
    /// height advances past `last_scanned_block_height`, the missing range is
    /// scanned with `scan_block_range`.  This mirrors `blindbit-desktop`'s
    /// `Watch()` loop and means callers never need to supply an `end_height`.
    pub async fn watch_chain(&mut self) -> Result<(), ScannerError> {
        loop {
            let oracle_tip = match self
                .client
                .get_info(tonic::Request::new(()))
                .await
            {
                Ok(resp) => resp.into_inner().height,
                Err(e) => {
                    tracing::error!(error = %e, "failed to reach oracle, will retry");
                    time::sleep(time::Duration::from_secs(10)).await;
                    continue;
                }
            };

            // With no new block, still check the scanned tip (or the
            // oracle's, if it is behind) against the oracle: a reorganisation
            // can replace blocks without making the chain longer.
            let (from, to) = if oracle_tip > self.last_scanned_block_height {
                let from = self.last_scanned_block_height + 1;
                tracing::info!(from, to = oracle_tip, "new blocks available, scanning");
                (from, oracle_tip)
            } else {
                (oracle_tip + 1, oracle_tip)
            };
            if let Err(e) = self.scan_block_range(from, to).await {
                if e.downcast_ref::<ReorgTooDeep>().is_some() {
                    tracing::error!(
                        error = %e,
                        "wallet state cannot follow the chain; scanning is halted until it is rescanned"
                    );
                } else {
                    tracing::error!(error = %e, "scan_block_range failed, will retry on next poll");
                }
            }

            time::sleep(time::Duration::from_secs(10)).await;
        }
    }

    /// scan short block data for new utxos and spent outpoints
    fn scan_short_block_data(
        &mut self,
        block_data: BlockScanDataShortResponse,
    ) -> Result<Option<ProbableMatch>, ScannerError> {
        // todo: first append to list then push notifications.
        //  We need to check for the actual match and not just a probablistic match.

        let Some(block_id) = block_data.block_identifier else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "block identifier is missing",
            )
            .into());
        };

        // If block_hash is missing or malformed, we can still run the probabilistic
        // tx filter but must skip spent-output notifications (which need the hash).
        let block_hash_opt: Option<[u8; 32]> = if block_id.block_hash.len() == 32 {
            Some(
                block_id
                    .block_hash
                    .clone()
                    .try_into()
                    .expect("length already checked to be 32"),
            )
        } else {
            tracing::warn!(
                height = block_id.block_height,
                got_bytes = block_id.block_hash.len(),
                "block has malformed block_hash; spent-output notifications will be skipped"
            );
            None
        };

        let mut probable_match = ProbableMatch::new(vec![], false);

        for item in block_data.comp_index {
            match self.probabilistic_match(&item) {
                Ok(true) => {
                    tracing::info!(txid = %hex::encode(&item.txid), "probable match found");
                    let txid_len = item.txid.len();
                    let txid_array: [u8; 32] = item.txid.try_into().map_err(|_| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            format!("txid must be exactly 32 bytes, got {txid_len} bytes"),
                        )
                    })?;

                    let tweak = PublicKey::from_slice(&item.tweak)
                        .expect("tweak must be a valid secp256k1 public key");

                    probable_match.matched_txs.push((txid_array, tweak));

                    if self.notify_probabilistic_matches.is_empty() {
                        continue;
                    }
                    if let Err(e) = self.notify_probabilistic_matches.send(txid_array) {
                        tracing::warn!(error = ?e, "failed to send probabilistic match notification");
                    }
                }
                Ok(false) => continue,
                Err(e) => return Err(e),
            }
        }

        // Spent-output check — only when we have a valid block_hash to report.
        // The oracle serves the first 8 bytes of each spent taproot output's
        // x-only key. A prefix hit on an unspent owned output only makes the
        // block worth fetching; the spend is confirmed (by exact outpoint) when
        // the block is applied, so a foreign key sharing the prefix marks
        // nothing.
        if let Some(block_hash) = block_hash_opt {
            let spent_outputs_count = block_data.spent_outputs.len() / 8;
            for i in 0..spent_outputs_count {
                let prefix: [u8; 8] = block_data.spent_outputs[i * 8..(i + 1) * 8]
                    .try_into()
                    .expect("slice is 8 bytes");
                let Some(candidates) = self.owned_prefixes.get(&prefix) else {
                    continue;
                };
                probable_match.spent = true;
                for outpoint in candidates {
                    tracing::info!(
                        outpoint = %outpoint,
                        short_pubkey = %hex::encode(prefix),
                        "possible spend of owned output; fetching block to confirm"
                    );
                    if self.notify_spent_outpoints.is_empty() {
                        continue;
                    }
                    if let Err(e) = self.notify_spent_outpoints.send(block_hash) {
                        tracing::warn!(error = ?e, "failed to send spent output notification");
                    }
                }
            }
        }

        if !probable_match.spent && probable_match.matched_txs.is_empty() {
            Ok(None)
        } else {
            Ok(Some(probable_match))
        }
    }

    /// The live receive step after a probable match: hands the full block and
    /// the matched transactions' tweaks to the external indexer, which does the
    /// real BIP-352 scan, and stages what it found.
    ///
    /// `probable_match.matched_txs` carries each txid as the oracle serves it
    /// (display order) together with the served tweak (`input_hash * A`), which
    /// `apply_block_relevant` takes as its "partial secret" and finishes the ECDH
    /// on itself.
    ///
    /// Spends need no extra step here: `apply_block_relevant` inserts every
    /// transaction whose input spends an indexed outpoint into the wallet graph,
    /// which is what the balance and [`Scanner::sync_owned_outputs`] read.
    fn apply_matched_block(
        &mut self,
        block: &bitcoin::Block,
        probable_match: &ProbableMatch,
        height: u32,
    ) {
        // build partial secret hashmap, only populate with txids and secrets where we
        // suspect matches, skip the rest
        let mut partial_secrets = HashMap::with_capacity(probable_match.matched_txs.len());

        for tx in &block.txdata {
            for (txid_arr, tweak) in &probable_match.matched_txs {
                // this check should be optimised to a map lookup on all items
                let mut item_txid = *txid_arr;
                item_txid.reverse();

                if Txid::from_byte_array(item_txid) != tx.compute_txid() {
                    continue;
                }

                let txid = byte_array_to_txid(txid_arr);

                partial_secrets.insert(txid, *tweak);
            }
        }
        // Apply block to indexer and stage the changes
        let indexer_changes = self
            .internal_indexer
            .apply_block_relevant(block, partial_secrets, height);
        self.stage.indexer.merge(indexer_changes);
    }

    fn probabilistic_match(
        &mut self,
        item: &ComputeIndexTxItem,
    ) -> Result<bool, ScannerError> {
        let tweak_len = item.tweak.len();
        let tweak_data: [u8; 33] = item.tweak.clone().try_into().map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("tweak must be exactly 33 bytes, got {tweak_len} bytes"),
            )
        })?;
        let tweak = PublicKey::from_slice(&tweak_data).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("tweak must be a valid secp256k1 public key: {e:?}"),
            )
        })?;

        // Call once and match on the result
        match self.scan_transaction_short(&tweak, &item.outputs_short) {
            Ok(true) => Ok(true),
            Ok(false) => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Scans a transaction for outputs which COULD belong to us
    /// only returns true if a probable match is found
    /// everything else returns false
    pub fn scan_transaction_short(
        &self,
        tweak: &PublicKey,
        short_pubkeys: &[u8],
    ) -> Result<bool, ScannerError> {
        let ecdh_shared_secret: PublicKey =
            bdk_sp::compute_shared_secret(self.internal_indexer.scan_sk(), tweak);

        let p_n = bdk_sp::receive::get_silentpayment_pubkey(
            self.internal_indexer.spend_pk(),
            &ecdh_shared_secret,
            0,
            None,
        );

        if match_short_pubkey(&p_n.x_only_public_key().0, short_pubkeys) {
            return Ok(true);
        }

        for label_pk in self.internal_indexer.index().label_lookup.keys() {
            let p_n_label = p_n
                .combine(label_pk)
                .expect("computationally unreachable: can only fail if label = -spend_sk");
            if match_short_pubkey(&p_n_label.x_only_public_key().0, short_pubkeys) {
                return Ok(true);
            }
        }

        Ok(false)
    }

    /// Scans a transaction for outputs which definitely belong to us
    /// returns an array of '`OwnedOutput`'s
    ///
    /// No production code calls this today: the daemon receives through
    /// [`Self::scan_transaction_short`] plus `apply_block_relevant` on the
    /// external indexer. It is kept (and covered by the BIP-352 vector tests in
    /// `bip352_vectors.rs`) as the entry point for scanning full block
    /// responses again.
    pub fn scan_transaction_full(
        &mut self,
        item: &FullTxItem,
    ) -> Result<Vec<SpOut>, ScannerError> {
        let tweak =
            PublicKey::from_slice(&item.tweak).expect("tweak must be a valid secp256k1 public key");

        let ecdh_shared_secret: PublicKey =
            bdk_sp::compute_shared_secret(self.internal_indexer.scan_sk(), &tweak);

        let dummy_tx = construct_dummy_tx(item);

        match bdk_sp::receive::scan_txouts(
            *self.internal_indexer.spend_pk(),
            &self.internal_indexer.index().label_lookup,
            &dummy_tx,
            ecdh_shared_secret,
        ) {
            Ok(mut spouts) => {
                // Scope, stated plainly: `scan_transaction_full` currently has no
                // production caller. It is exercised by the BIP-352 vector tests in
                // `bip352_vectors.rs` and is the intended entry point if/when full
                // block responses are scanned again. The live receive path is
                // `scan_transaction_short` plus `apply_block_relevant` on the
                // external indexer (see `scan_blocks`), and that path enforces no
                // K_max at all. The truncation below therefore does NOT today
                // constrain live scanning; it is here so the full-block entry point
                // is correct whenever it is used again.
                //
                // `bdk_sp` derives one candidate for every matching output. The BIP-352
                // receiver limit is protocol-visible: accepting a 2324th candidate would
                // desynchronise a sender and receiver that correctly stop at K_max.
                //
                // Truncating is equivalent to stopping the scan at K_max because
                // `bdk_sp::receive::scan_txouts` returns its matches in ascending
                // derivation order: it pushes into `spouts_found` from a `while let`
                // loop whose `matched_tweaks` counter starts at 0 and increments once
                // per match, so element `i` is always the match for `k = i`. That
                // holds no matter which candidate a given `k` picks up. Several
                // candidates *can* satisfy one `k` — two identical output scripts, or
                // a transaction carrying both `P_k` and `P_k + m*G` — and
                // `find_spout_for_tweak` then returns whichever comes first in the
                // *candidate pool*, whose order earlier `swap_remove`s have already
                // scrambled. But `swap_remove` mutates only that pool, never the
                // results vector, so pool order can change *which* output is reported
                // for a `k`, not the index it is reported at. `truncate` therefore
                // keeps exactly `k = 0..=K_max-1` and drops the highest `k`, never an
                // arbitrary match. Covered by
                // `bip352_vectors::official_vectors_enforce_k_max_at_the_blindbit_boundary`,
                // which asserts the per-index tweak identity, not just the count.
                spouts.truncate(BIP352_K_MAX);

                // todo: come back here if something does not work due to wrong txids being used in
                // spuot outpoints

                // Ensure we have exactly 32 bytes
                let mut reversed_txid_slice = item.txid.clone();
                reversed_txid_slice.reverse();
                let txid_array: [u8; 32] = reversed_txid_slice
                    .try_into()
                    .expect("Vec<u8> must be exactly 32 bytes long");

                // Construct Txid directly from the byte array (preserves byte order)
                let txid = bitcoin::Txid::from_byte_array(txid_array);

                // we need to change the txid to match the item's txid
                for spout in &mut spouts {
                    spout.outpoint = bitcoin::OutPoint {
                        txid,
                        vout: spout.outpoint.vout,
                    };
                }
                Ok(spouts)
            }
            Err(e) => Err(e.into()),
        }
    }
}

#[cfg(test)]
#[path = "bip352_vectors.rs"]
mod bip352_vectors;

#[cfg(test)]
#[path = "owned_outputs_tests.rs"]
mod owned_outputs_tests;
