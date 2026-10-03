//! Wallet transactions stored without their witness data.
//!
//! Until the scanner asked for witness blocks (`MSG_WITNESS_BLOCK`), the
//! blocks it fetched came stripped of witnesses. The wallet stored its
//! transactions that way, and the Electrum server served them to wallets
//! that way: right txids, wrong sizes and fee rates. The daemon fetches
//! those blocks again, with witnesses, and puts the witnesses back in the
//! wallet graph, the state file and the Electrum index.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bitcoin::script::Instruction;
use bitcoin::{BlockHash, Script, Transaction, Txid};
use indexer::bdk_chain::bdk_core::Merge;

use super::health::ScanCancelled;
use super::scanner::Scanner;

/// How long to wait before trying again when a block could not be fetched.
const RETRY_AFTER: Duration = Duration::from_secs(5 * 60);

/// Stored without its witness data: no input has a witness, yet some input
/// cannot be valid without one. Its scriptSig is empty (a native segwit or
/// taproot spend) or only pushes a witness program (a P2SH-wrapped segwit
/// spend). A legacy transaction, whose inputs carry their signatures in the
/// scriptSig, does not match.
pub(crate) fn lacks_witness(tx: &Transaction) -> bool {
    !tx.is_coinbase()
        && tx.input.iter().all(|input| input.witness.is_empty())
        && tx
            .input
            .iter()
            .any(|input| needs_witness(&input.script_sig))
}

fn needs_witness(script_sig: &Script) -> bool {
    if script_sig.is_empty() {
        return true;
    }
    let mut instructions = script_sig.instructions();
    match (instructions.next(), instructions.next()) {
        (Some(Ok(Instruction::PushBytes(push))), None) => {
            Script::from_bytes(push.as_bytes()).is_witness_program()
        }
        _ => false,
    }
}

impl Scanner {
    /// Wallet transactions stored without witness data, by the block
    /// (height, hash) that confirms them.
    fn txs_lacking_witness(&self) -> BTreeMap<(u32, BlockHash), BTreeSet<Txid>> {
        let mut lacking: BTreeMap<(u32, BlockHash), BTreeSet<Txid>> = BTreeMap::new();
        for node in self.internal_indexer.graph().full_txs() {
            if !lacks_witness(&node.tx) {
                continue;
            }
            if let Some(anchor) = node.anchors.first() {
                lacking
                    .entry((anchor.block_id.height, anchor.block_id.hash))
                    .or_default()
                    .insert(node.txid);
            }
        }
        lacking
    }

    /// Put back the witnesses of wallet transactions stored without them,
    /// once: called on every `watch_chain_until` poll, it does nothing once a pass
    /// has finished, and after a block could not be fetched it waits 5 min
    /// before trying again. A pass cut short by a stop is taken up again as
    /// soon as scanning resumes.
    pub(crate) async fn restore_missing_witnesses_when_due(&mut self) {
        let Some(due) = self.witness_restore_due else {
            return;
        };
        if Instant::now() < due {
            return;
        }
        let complete = self.restore_missing_witnesses().await;
        if !complete && self.cancel.is_cancelled() {
            return;
        }
        self.witness_restore_due = (!complete).then(|| Instant::now() + RETRY_AFTER);
    }

    /// Fetch the blocks of wallet transactions stored without witness data
    /// and put the witnesses back. Returns `false` when a block could not be
    /// fetched; the transactions left are tried again on the next call.
    pub(crate) async fn restore_missing_witnesses(&mut self) -> bool {
        let lacking = self.txs_lacking_witness();
        if lacking.is_empty() {
            return true;
        }
        tracing::info!(
            blocks = lacking.len(),
            txs = lacking.values().map(BTreeSet::len).sum::<usize>(),
            "fetching blocks again to restore the witness data of wallet transactions stored without it"
        );
        let mut restored = 0;
        let mut complete = true;
        for ((height, hash), txids) in lacking {
            let block = match self.fetch_block_with_retry(hash, height.into()).await {
                Ok(block) => block,
                // Stopping: the blocks restored so far are complete.
                Err(error) if error.is::<ScanCancelled>() => {
                    complete = false;
                    break;
                }
                Err(error) => {
                    tracing::warn!(
                        height,
                        block_hash = %hash,
                        %error,
                        "cannot fetch block to restore witness data; trying again later"
                    );
                    complete = false;
                    break;
                }
            };
            let txs: Vec<Arc<Transaction>> = block
                .txdata
                .into_iter()
                .filter(|tx| txids.contains(&tx.compute_txid()))
                .map(Arc::new)
                .collect();
            restored += self.replace_witnessless(txs).await;
        }
        if restored > 0 {
            tracing::info!(restored, "restored witness data of wallet transactions");
            #[cfg(feature = "serde")]
            if let Err(error) = self.save_to_file(&self.state_file) {
                tracing::warn!(%error, "failed to save state after restoring witness data");
            }
        }
        complete
    }

    /// Replace stored copies of `txs` that lack witness data with `txs`, in
    /// the wallet graph, the state to save and the Electrum index. Returns
    /// how many now have their witnesses.
    async fn replace_witnessless(&mut self, txs: Vec<Arc<Transaction>>) -> usize {
        let txids: BTreeSet<Txid> = txs.iter().map(|tx| tx.compute_txid()).collect();
        // The graph keeps a non-empty witness over an empty one; the saved
        // state drops its stripped copies so it holds each transaction once.
        self.stage
            .indexer
            .graph
            .txs
            .retain(|tx| !(lacks_witness(tx) && txids.contains(&tx.compute_txid())));
        let changeset = indexer::v2::ChangeSet {
            scan_sk: Some(*self.internal_indexer.scan_sk()),
            spend_pk: Some(*self.internal_indexer.spend_pk()),
            graph: indexer::bdk_chain::tx_graph::ChangeSet {
                txs: txs.iter().cloned().collect(),
                ..Default::default()
            },
            ..Default::default()
        };
        self.internal_indexer.apply_changeset(changeset.clone());
        self.stage.indexer.merge(changeset);

        let mut index = self.electrum_index.lock().await;
        let mut restored = 0;
        for txid in &txids {
            let Some(tx) = self.internal_indexer.graph().get_tx(*txid) else {
                continue;
            };
            if lacks_witness(&tx) {
                continue;
            }
            restored += 1;
            if let Some(raw) = index.txs.get_mut(&txid.to_string()) {
                *raw = bitcoin::consensus::encode::serialize(tx.as_ref());
            }
        }
        restored
    }
}
