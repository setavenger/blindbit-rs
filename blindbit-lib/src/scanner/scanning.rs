use std::collections::HashMap;

use bdk_sp::receive::SpOut;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::PublicKey;
use bitcoin::{BlockHash, OutPoint, Txid};
use indexer::bdk_chain::{BlockId, CanonicalizationParams};
use indexer::bdk_chain::bdk_core::Merge;
use indexer::bdk_chain::local_chain::LocalChain;

use crate::oracle_grpc::{
    BlockScanDataShortResponse, ComputeIndexTxItem, FullTxItem, RangedBlockHeightRequestFiltered,
};

use super::scanner::Scanner;
use super::types::{BlockIdentifierDisplay, ProbableMatch};
use super::utils::{byte_array_to_txid, construct_dummy_tx, match_short_pubkey};
use super::p2p;

impl Scanner {
    /// scan a block range for new utxos and spent outpoints
    pub async fn scan_block_range(
        &mut self,
        start: u64,
        end: u64,
    ) -> Result<(), Box<dyn std::error::Error>> {
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
            println!("received: {}", block_id.0.block_height);

            match self.scan_short_block_data(block_scan_data) {
                Ok(probable_match_opt) => {
                    let probable_match = match probable_match_opt {
                        None => continue,
                        Some(probable_match) => probable_match,
                    };
                    // pull the full block data

                    // Ensure we have exactly 32 bytes
                    let mut reversed_block_hash_slice = block_identifier.block_hash.clone();
                    reversed_block_hash_slice.reverse();
                    let block_hash_arr: [u8; 32] = reversed_block_hash_slice
                        .try_into()
                        .expect("this should always work");

                    let block_hash = BlockHash::from_byte_array(block_hash_arr);

                    println!("block_hash: {block_hash}");

                    // Make multiple parallel requests and wait for the first successful one
                    let block = match p2p::pull_block_from_p2p_by_blockhash(
                        self.p2p_peer,
                        block_hash,
                    ) {
                        Ok(full_block) => full_block,
                        Err(err) => {
                            println!("{err}");
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

                    println!("Printing for height: {}", block_identifier.block_height);
                    for inner_tx in self.internal_indexer.graph().full_txs() {
                        println!("txid: {}", inner_tx.txid);
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
                    println!(
                        "Balance - Total: {} sats, Confirmed: {} sats, Trusted Pending: {} sats, Untrusted Pending: {} sats",
                        balance.total(),
                        balance.confirmed,
                        balance.trusted_pending,
                        balance.untrusted_pending
                    );

                    // Update last scanned block height and stage it
                    self.last_scanned_block_height = block_identifier.block_height;
                    self.stage.last_scanned_block_height = block_identifier.block_height;
                }
                Err(e) => {
                    println!("Error scanning short block data: {e:?}");
                    return Err(e);
                }
            }
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
        println!(
            "Balance - Total: {} sats, Confirmed: {} sats, Trusted Pending: {} sats, Untrusted Pending: {} sats",
            balance.total(),
            balance.confirmed,
            balance.trusted_pending,
            balance.untrusted_pending
        );

        Ok(())
    }

    /// watch the chain for new utxos and spent outpoints
    /// this is a long running task that will watch the chain for new utxos and spent outpoints
    /// and notify the user via the notifiers
    pub async fn watch_chain(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        todo!()
    }

    /// scan short block data for new utxos and spent outpoints
    fn scan_short_block_data(
        &mut self,
        block_data: BlockScanDataShortResponse,
    ) -> Result<Option<ProbableMatch>, Box<dyn std::error::Error>> {
        // todo: first append to list then push notifications.
        //  We need to check for the actual match and not just a probablistic match.

        let Some(block_id) = block_data.block_identifier else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "block identifier is missing",
            )
            .into());
        };

        if block_id.block_hash.len() != 32 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "block hash is not 32 bytes",
            )
            .into());
        }

        let block_hash: [u8; 32] = block_id.block_hash.try_into().map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "block hash is not 32 bytes",
            )
        })?;

        let mut probable_match = ProbableMatch::new(vec![], false);

        for item in block_data.comp_index {
            match self.probabilistic_match(&item) {
                Ok(true) => {
                    println!("TxId of interest: {:?}", hex::encode(&item.txid));
                    let txid_len = item.txid.len();
                    // todo: clean this up
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
                        println!("Error probabilistic match notification: {e:?}");
                    }
                    // continue;
                }
                Ok(false) => continue,
                Err(e) => return Err(e),
            }
        }

        // make spent pubkey check
        let spent_outputs_count = block_data.spent_outputs.len() / 8;
        for i in 0..spent_outputs_count {
            let spent_output = &block_data.spent_outputs[i * 8..(i + 1) * 8];
            for pubkey in &self.owned_outputs {
                if pubkey[..8] == *spent_output {
                    probable_match.spent = true;

                    println!("Spent output: {:?}", hex::encode(pubkey));
                    if self.notify_spent_outpoints.is_empty() {
                        continue;
                    }
                    if let Err(e) = self.notify_spent_outpoints.send(block_hash) {
                        println!("Error spent output notification: {e:?}");
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
    ) -> Result<bool, Box<dyn std::error::Error>> {
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
    ) -> Result<bool, Box<dyn std::error::Error>> {
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
    ) -> Result<Vec<SpOut>, Box<dyn std::error::Error>> {
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

