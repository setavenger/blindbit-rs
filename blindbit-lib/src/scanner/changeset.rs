use bitcoin::BlockHash;
use indexer::bdk_chain::ConfirmationBlockTime;
use indexer::bdk_chain::bdk_core::Merge;
use std::collections::BTreeMap;

/// Helper module for hex encoding/decoding byte arrays in serialization
#[cfg(feature = "serde")]
mod serde_hex {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize_vec<S>(vec: &Vec<[u8; 32]>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let hex_strings: Vec<String> = vec.iter().map(|bytes| hex::encode(bytes)).collect();
        hex_strings.serialize(serializer)
    }

    pub fn deserialize_vec<'de, D>(deserializer: D) -> Result<Vec<[u8; 32]>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let hex_strings: Vec<String> = Vec::deserialize(deserializer)?;
        let mut result = Vec::new();
        for hex_string in hex_strings {
            let bytes = hex::decode(&hex_string)
                .map_err(|e| serde::de::Error::custom(format!("Invalid hex string: {}", e)))?;
            let bytes_array: [u8; 32] = bytes
                .try_into()
                .map_err(|_| serde::de::Error::custom("Expected 32 bytes"))?;
            result.push(bytes_array);
        }
        Ok(result)
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
    /// Owned output pubkeys; used to check for spent outputs (hex encoded in JSON)
    #[cfg_attr(
        feature = "serde",
        serde(
            serialize_with = "serde_hex::serialize_vec",
            deserialize_with = "serde_hex::deserialize_vec"
        )
    )]
    pub owned_outputs: Vec<[u8; 32]>,
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

        // Merge owned_outputs (deduplicate)
        for output in other.owned_outputs {
            if !self.owned_outputs.contains(&output) {
                self.owned_outputs.push(output);
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
