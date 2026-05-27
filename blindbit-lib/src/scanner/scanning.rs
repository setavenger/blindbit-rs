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
    BlockScanDataShortResponse, ComputeIndexTxItem, FullTxItem, RangedBlockHeightRequestFiltered,
};

use super::electrum_index::{ScriptHashEntry, SpHistoryEntry, electrum_scripthash};
use super::p2p;
use super::scanner::Scanner;
use super::types::{BlockIdentifierDisplay, ProbableMatch};
use super::utils::{byte_array_to_txid, construct_dummy_tx, match_short_pubkey};
use super::ScannerError;

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

impl Scanner {
    /// scan a block range for new utxos and spent outpoints
    pub async fn scan_block_range(
        &mut self,
        start: u64,
        end: u64,
    ) -> Result<(), ScannerError> {
        // TODO: Implement sync check if needed

        let request = tonic::Request::new(RangedBlockHeightRequestFiltered {
            start,
            end,
            dustlimit: 0,
            cut_through: false,
        });
        let mut stream = self
            .client
            .stream_block_scan_data_short(request)
            .await
            .unwrap()
            .into_inner();

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

        while let Some(block_scan_data) = stream.message().await.unwrap() {
            let Some(block_identifier) = block_scan_data.block_identifier.clone() else {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "block identifier is missing",
                )
                .into());
            };
            let block_id = BlockIdentifierDisplay(&block_identifier);
            tracing::debug!(height = block_id.0.block_height, "received block data from oracle");

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
                            // Periodically checkpoint progress so a crash/restart during a
                            // long initial catch-up scan doesn't lose everything.
                            if block_identifier.block_height % 1000 == 0 {
                        if let Err(e) = self.save_to_file(&self.state_file) {
                            tracing::warn!(error = %e, "failed to save periodic checkpoint");
                        }
                            }
                            continue;
                        }
                        Some(probable_match) => probable_match,
                    };
                    // Guard: if block_hash is malformed (already warned in
                    // scan_short_block_data) we cannot pull the full block
                    // via P2P.  Advance progress and move on.
                    if block_identifier.block_hash.len() != 32 {
                        self.notify_electrum_scan_progress(
                            block_identifier.block_height,
                            start,
                            end,
                        )
                        .await;
                        self.last_scanned_block_height = block_identifier.block_height;
                        self.stage.last_scanned_block_height = block_identifier.block_height;
                        continue;
                    }

                    // pull the full block data

                    // Ensure we have exactly 32 bytes
                    let mut reversed_block_hash_slice = block_identifier.block_hash.clone();
                    reversed_block_hash_slice.reverse();
                    let block_hash_arr: [u8; 32] = reversed_block_hash_slice
                        .try_into()
                        .expect("block_hash length already verified to be 32");

                    let block_hash = BlockHash::from_byte_array(block_hash_arr);

                    tracing::debug!(block_hash = %block_hash, "fetching full block via P2P");

                    // Make multiple parallel requests and wait for the first successful one
                    let block = match p2p::pull_block_from_p2p_by_blockhash(
                        self.p2p_peer,
                        block_hash,
                        self.network,
                    ) {
                        Ok(full_block) => full_block,
                        Err(err) => {
                            tracing::error!(error = %err, "failed to pull block via P2P");
                            return Err(err);
                        }
                    };

                    // build partial secret hashmap, only populate with txids and secrets where we
                    // suspect matches, skip the rest
                    let mut partial_secrets =
                        HashMap::with_capacity(probable_match.matched_txs.len());

                    for tx in &block.txdata {
                        if probable_match.spent {
                            // todo: we will need to look at all spent outpoints in this
                            // block and find the relevant txids for spent
                        }

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
                    let indexer_changes = self.internal_indexer.apply_block_relevant(
                        &block,
                        partial_secrets,
                        block_identifier.block_height as u32,
                    );
                    self.stage.indexer.merge(indexer_changes);

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

        // Always persist progress at the end of a scan range so watch_chain
        // resumes from the correct height after a restart, even when no
        // wallet-relevant transactions were found in this range.
        if let Err(e) = self.save_to_file(&self.state_file) {
            tracing::warn!(error = %e, "failed to save state after scan");
        }

        Ok(())
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
            let oracle_tip = self
                .client
                .get_info(tonic::Request::new(()))
                .await
                .map_err(|e| {
                    std::io::Error::new(std::io::ErrorKind::Other, e.to_string())
                })?
                .into_inner()
                .height;

            if oracle_tip > self.last_scanned_block_height {
                let from = self.last_scanned_block_height + 1;
                tracing::info!(from, to = oracle_tip, "new blocks available, scanning");
                self.scan_block_range(from, oracle_tip).await?;
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
        if let Some(block_hash) = block_hash_opt {
            let spent_outputs_count = block_data.spent_outputs.len() / 8;
            for i in 0..spent_outputs_count {
                let spent_output = &block_data.spent_outputs[i * 8..(i + 1) * 8];
                for pubkey in &self.owned_outputs {
                    if pubkey[..8] == *spent_output {
                        probable_match.spent = true;

                        tracing::info!(pubkey = %hex::encode(pubkey), "spent output detected");
                        if self.notify_spent_outpoints.is_empty() {
                            continue;
                        }
                        if let Err(e) = self.notify_spent_outpoints.send(block_hash) {
                            tracing::warn!(error = ?e, "failed to send spent output notification");
                        }
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
