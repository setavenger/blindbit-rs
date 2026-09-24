use bitcoin::BlockHash;
use indexer::bdk_chain::ConfirmationBlockTime;
use indexer::bdk_chain::bdk_core::Merge;
use std::collections::BTreeMap;

use super::types::OwnedOutputRecord;

/// Deserialisation of the persisted `owned_outputs` array.
#[cfg(feature = "serde")]
mod owned_outputs_serde {
    use super::OwnedOutputRecord;
    use serde::{Deserialize, Deserializer};

    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Entry {
        Record(OwnedOutputRecord),
        /// State files written before owned outputs were recorded stored bare
        /// hex keys here. No released writer ever populated that list, and a
        /// bare key carries no outpoint, so such entries are dropped; the
        /// records are rebuilt from the indexer on load
        /// (`Scanner::sync_owned_outputs`).
        Legacy(#[allow(dead_code)] String),
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<OwnedOutputRecord>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let entries: Vec<Entry> = Vec::deserialize(deserializer)?;
        Ok(entries
            .into_iter()
            .filter_map(|entry| match entry {
                Entry::Record(record) => Some(record),
                Entry::Legacy(_) => None,
            })
            .collect())
    }
}

/// Represents a set of changes that can be applied to a [`Scanner`].
///
/// This struct is used to stage updates to the scanner's internal state,
/// including chain data, indexer data, and metadata.
///
/// It implements [`Merge`] to combine multiple change sets and can be
/// serialized/deserialized when the serde feature is enabled.
#[derive(Default, Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[must_use]
pub struct ChangeSet {
    /// Sparse block checkpoints: only blocks where we found something (height -> hash)
    pub block_checkpoints: BTreeMap<u32, BlockHash>,
    /// Changes related to the Silent Payments indexer data.
    pub indexer: indexer::v2::ChangeSet<ConfirmationBlockTime>,
    /// The last block height that was scanned
    pub last_scanned_block_height: u64,
    /// The last block height that was scanned on most recent rescan
    pub last_scanned_block_height_rescan: u64,
    /// Wallet-owned outputs (full x-only key, label, spent status); the
    /// scanner matches the oracle's spent-output prefixes against these.
    #[cfg_attr(
        feature = "serde",
        serde(default, deserialize_with = "owned_outputs_serde::deserialize")
    )]
    pub owned_outputs: Vec<OwnedOutputRecord>,
    /// Secret scan key (hex encoded) - needed to reconstruct the indexer
    pub secret_scan_hex: Option<String>,
    /// Public spend key (hex encoded) - needed to reconstruct the indexer
    pub public_spend_hex: Option<String>,
    /// Maximum label number used
    pub max_label_num: u32,
}

impl Merge for ChangeSet {
    /// Merges another [`ChangeSet`] into the current one.
    fn merge(&mut self, other: Self) {
        // Merge block checkpoints (extend with new ones)
        self.block_checkpoints.extend(other.block_checkpoints);
        Merge::merge(&mut self.indexer, other.indexer);

        // Update metadata with the latest values
        if other.last_scanned_block_height > self.last_scanned_block_height {
            self.last_scanned_block_height = other.last_scanned_block_height;
        }
        if other.last_scanned_block_height_rescan > self.last_scanned_block_height_rescan {
            self.last_scanned_block_height_rescan = other.last_scanned_block_height_rescan;
        }

        // Merge owned_outputs by outpoint; the newer record wins (it may carry
        // a spend the older one did not).
        for output in other.owned_outputs {
            match self
                .owned_outputs
                .iter_mut()
                .find(|existing| existing.outpoint == output.outpoint)
            {
                Some(existing) => *existing = output,
                None => self.owned_outputs.push(output),
            }
        }

        // Preserve keys if not set
        if self.secret_scan_hex.is_none() {
            self.secret_scan_hex = other.secret_scan_hex;
        }
        if self.public_spend_hex.is_none() {
            self.public_spend_hex = other.public_spend_hex;
        }

        // Use the maximum label number
        if other.max_label_num > self.max_label_num {
            self.max_label_num = other.max_label_num;
        }
    }

    /// Checks if the [`ChangeSet`] is empty (contains no changes).
    fn is_empty(&self) -> bool {
        self.block_checkpoints.is_empty()
            && self.indexer.is_empty()
            && self.last_scanned_block_height == 0
            && self.last_scanned_block_height_rescan == 0
            && self.owned_outputs.is_empty()
    }
}
