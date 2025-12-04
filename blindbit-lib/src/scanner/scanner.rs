use std::collections::BTreeMap;
use std::net::SocketAddr;
#[cfg(feature = "serde")]
use std::path::Path;

use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{PublicKey, SecretKey};
use bitcoin::BlockHash;
use indexer::v2::SpIndexerV2;
use indexer::bdk_chain::bdk_core::Merge;
use tokio::sync::broadcast;
use tonic::transport::Channel;

use indexer::bdk_chain::ConfirmationBlockTime;
use crate::oracle_grpc::oracle_service_client::OracleServiceClient;

use super::changeset::ChangeSet;

/// Main scanner struct for scanning the blockchain for Silent Payments outputs
pub struct Scanner {
    /// Client to connect to `BlindBit` Oracle via gRPC
    pub(crate) client: OracleServiceClient<Channel>,

    /// `p2p_peer` as of now one fixed peer connection.
    // todo: use DNS to find peers at random
    pub(crate) p2p_peer: SocketAddr,

    /// the internal indexer used for cryptographic scanning computations
    /// specific to BIP 352
    pub(crate) internal_indexer: SpIndexerV2<ConfirmationBlockTime>,

    /// Sparse block checkpoints: only blocks where we found something (height -> hash)
    /// This avoids storing every block and only tracks blocks with relevant transactions
    pub(crate) block_checkpoints: BTreeMap<u32, BlockHash>,

    /// sends notification when a new utxo is found
    pub(crate) notify_found_utxos: broadcast::Sender<usize>,

    /// probabilistic matches found both used for found utxos and spent outpoints
    /// send the txid of the transaction that is of interest
    pub(crate) notify_probabilistic_matches: broadcast::Sender<[u8; 32]>,

    /// sends notification when a pubkey was probably spent
    /// contains the blockhash which needs to be verified to assert an actual match
    pub(crate) notify_spent_outpoints: broadcast::Sender<[u8; 32]>,

    /// the last block height that was scanned
    pub(crate) last_scanned_block_height: u64,

    /// the last block height that was scanned on most recent rescan
    pub(crate) last_scanned_block_height_rescan: u64,

    /// owned output pubkeys; used to check for spent outputs
    // todo: should this be a hashmap instead of a vector?
    pub(crate) owned_outputs: Vec<[u8; 32]>,

    /// Staged changes that can be persisted
    pub(crate) stage: ChangeSet,
}

impl Scanner {
    pub fn new(
        client: OracleServiceClient<Channel>,
        p2p_socket_addr: SocketAddr,
        secret_scan: SecretKey,
        public_spend: PublicKey,
        max_label_num: u32, // highest m for label index
    ) -> Self {
        // secret scan needed
        // public spend needed
        let mut indexer = SpIndexerV2::new(secret_scan, public_spend);

        // always use the change label m=0
        _ = indexer.add_label(0);

        for i in 1..=max_label_num {
            _ = indexer.add_label(i);
        }

        // Initialize sparse checkpoints with genesis block
        // This ensures LocalChain::from_blocks can always create a valid chain
        let genesis_hash = BlockHash::from_byte_array(
            indexer::bdk_chain::bitcoin::blockdata::constants::ChainHash::BITCOIN.to_bytes(),
        );
        let mut block_checkpoints = BTreeMap::new();
        block_checkpoints.insert(0, genesis_hash);

        // Initialize the staged changeset with initial state
        let mut stage = ChangeSet {
            block_checkpoints: block_checkpoints.clone(),
            indexer: indexer.initial_changeset(),
            last_scanned_block_height: 0,
            last_scanned_block_height_rescan: 0,
            owned_outputs: vec![],
            secret_scan_hex: Some(hex::encode(secret_scan.secret_bytes())),
            public_spend_hex: Some(hex::encode(public_spend.serialize())),
            max_label_num,
        };

        // Merge the initial label changes
        stage.indexer.merge(indexer.add_label(0));
        for i in 1..=max_label_num {
            stage.indexer.merge(indexer.add_label(i));
        }

        Self {
            client,
            p2p_peer: p2p_socket_addr,
            internal_indexer: indexer,
            block_checkpoints,
            notify_probabilistic_matches: broadcast::channel(100).0,
            notify_found_utxos: broadcast::channel(100).0,
            notify_spent_outpoints: broadcast::channel(100).0,
            last_scanned_block_height: 0,
            last_scanned_block_height_rescan: 0,
            owned_outputs: vec![],
            stage,
        }
    }

    /// get the last block height that was scanned
    pub fn get_last_scanned_block_height(&self) -> u64 {
        self.last_scanned_block_height
    }

    pub fn get_last_scanned_block_height_rescan(&self) -> u64 {
        self.last_scanned_block_height_rescan
    }

    /// subscribe to notifications when a new utxo is found
    pub fn subscribe_to_found_utxos(&self) -> broadcast::Receiver<usize> {
        self.notify_found_utxos.subscribe()
    }

    /// subscribe to notifications when a new outpoint is spent
    pub fn subscribe_to_spent_outpoints(&self) -> broadcast::Receiver<[u8; 32]> {
        self.notify_spent_outpoints.subscribe()
    }

    /// subscribe to notifications when a probabilistic match is found
    pub fn subscribe_to_probabilistic_matches(&self) -> broadcast::Receiver<[u8; 32]> {
        self.notify_probabilistic_matches.subscribe()
    }

    /// add an owned output pubkey
    /// if already exists nothing happens
    pub fn add_owned_output(&mut self, pubkey: [u8; 32]) {
        // todo: should this be a hashmap instead of a vector?
        if !self.owned_outputs.contains(&pubkey) {
            self.owned_outputs.push(pubkey);
        }
    }

    /// Returns an optional reference to the currently staged [`ChangeSet`].
    ///
    /// # Returns
    ///
    /// `Some(&ChangeSet)` if changes are staged, `None` otherwise.
    pub fn staged(&self) -> Option<&ChangeSet> {
        if self.stage.is_empty() {
            None
        } else {
            Some(&self.stage)
        }
    }

    /// Returns an optional mutable reference to the currently staged [`ChangeSet`].
    ///
    /// # Returns
    ///
    /// `Some(&mut ChangeSet)` if changes are staged, `None` otherwise.
    pub fn staged_mut(&mut self) -> Option<&mut ChangeSet> {
        if self.stage.is_empty() {
            None
        } else {
            Some(&mut self.stage)
        }
    }

    /// Takes ownership of the currently staged [`ChangeSet`], leaving an empty [`ChangeSet`] in its place.
    ///
    /// This is useful for atomically applying or persisting the staged changes.
    ///
    /// # Returns
    ///
    /// `Some(ChangeSet)` if changes were staged, `None` otherwise.
    pub fn take_staged(&mut self) -> Option<ChangeSet> {
        if self.stage.is_empty() {
            None
        } else {
            let changes = self.stage.clone();
            self.stage = ChangeSet::default();
            Some(changes)
        }
    }

    /// Save the current staged changes to a file using JSON serialization.
    ///
    /// This saves the ChangeSet which contains all the indexer and chain state changes.
    /// The ChangeSet can be used to reconstruct the scanner state on restart.
    ///
    /// Requires the `serde` feature to be enabled.
    #[cfg(feature = "serde")]
    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<(), Box<dyn std::error::Error>> {
        // Ensure we have the keys in the changeset for reconstruction
        let mut changeset = self.stage.clone();
        if changeset.secret_scan_hex.is_none() {
            let secret_scan_bytes: [u8; 32] = self.internal_indexer.scan_sk().secret_bytes();
            changeset.secret_scan_hex = Some(hex::encode(secret_scan_bytes));
        }
        if changeset.public_spend_hex.is_none() {
            let public_spend_bytes = self.internal_indexer.spend_pk().serialize();
            changeset.public_spend_hex = Some(hex::encode(&public_spend_bytes));
        }
        if changeset.max_label_num == 0 {
            let label_count = self.internal_indexer.index().label_lookup.len();
            changeset.max_label_num = if label_count > 0 {
                (label_count - 1) as u32
            } else {
                0
            };
        }
        changeset.last_scanned_block_height = self.last_scanned_block_height;
        changeset.last_scanned_block_height_rescan = self.last_scanned_block_height_rescan;
        changeset.owned_outputs = self.owned_outputs.clone();

        let json = serde_json::to_string_pretty(&changeset)?;
        std::fs::write(path, json)?;
        Ok(())
    }

    /// Load scanner state from a file using JSON deserialization.
    /// Returns the ChangeSet which can be used to restore a Scanner.
    ///
    /// Requires the `serde` feature to be enabled.
    #[cfg(feature = "serde")]
    pub fn load_from_file<P: AsRef<Path>>(
        path: P,
    ) -> Result<ChangeSet, Box<dyn std::error::Error>> {
        let json = std::fs::read_to_string(path)?;
        let mut json_value: serde_json::Value =
            serde_json::from_str(&json).map_err(|e| format!("Failed to parse JSON: {}", e))?;

        // The issue: label_lookup entries are stored as arrays of integers, but the deserializer
        // expects hex strings. However, we don't actually need label_lookup data because we regenerate
        // labels from max_label_num in from_changeset(). So we can just remove/nullify label_lookup.

        // Remove label_lookup from the indexer - we'll regenerate it from max_label_num anyway
        if let Some(indexer_obj) = json_value
            .get_mut("indexer")
            .and_then(|v| v.as_object_mut())
        {
            // Set label_lookup to an empty array (or remove it entirely)
            indexer_obj.insert("label_lookup".to_string(), serde_json::Value::Array(vec![]));
        }

        // Now try to deserialize
        serde_json::from_value::<ChangeSet>(json_value)
            .map_err(|e| format!("Failed to deserialize ChangeSet. Error: {}", e).into())
    }

    /// Update the last scanned block height
    pub fn update_last_scanned_block_height(&mut self, height: u64) {
        self.last_scanned_block_height = height;
        self.stage.last_scanned_block_height = height;
    }

    /// Create a new Scanner from a ChangeSet.
    ///
    /// This allows restoring a scanner's state from persisted changes.
    /// The client and p2p_peer must be provided separately as they can't be serialized.
    ///
    /// Note: Labels are recomputed from the keys and max_label_num on startup,
    /// so label_lookup data in the changeset is redundant but harmless.
    pub fn from_changeset(
        client: OracleServiceClient<Channel>,
        p2p_socket_addr: SocketAddr,
        mut changeset: ChangeSet,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        // Extract keys from changeset
        let secret_scan_hex = changeset
            .secret_scan_hex
            .take()
            .ok_or("secret_scan_hex missing in ChangeSet")?;
        let public_spend_hex = changeset
            .public_spend_hex
            .take()
            .ok_or("public_spend_hex missing in ChangeSet")?;

        let secret_scan_bytes = hex::decode(&secret_scan_hex)?;
        let public_spend_bytes = hex::decode(&public_spend_hex)?;

        // Verify keys are valid (the indexer will be reconstructed from changeset which already contains keys)
        let _secret_scan = SecretKey::from_slice(&secret_scan_bytes)?;
        let _public_spend = PublicKey::from_slice(&public_spend_bytes)?;

        // Reconstruct the indexer from the changeset (this restores the graph and transaction data)
        let mut indexer = SpIndexerV2::try_from(changeset.indexer.clone())
            .map_err(|e| format!("Failed to reconstruct indexer from changeset: {:?}", e))?;

        // Regenerate labels
        // ignore change set and be aligned with max_label_num
        let max_label_num = changeset.max_label_num;
        _ = indexer.add_label(0);
        for i in 1..=max_label_num {
            _ = indexer.add_label(i);
        }

        // Reconstruct block checkpoints from the changeset
        let mut block_checkpoints = changeset.block_checkpoints.clone();
        block_checkpoints.entry(0).or_insert_with(|| {
            BlockHash::from_byte_array(
                indexer::bdk_chain::bitcoin::blockdata::constants::ChainHash::BITCOIN.to_bytes(),
            )
        });

        // Restore the keys in the changeset for future saves
        changeset.secret_scan_hex = Some(secret_scan_hex);
        changeset.public_spend_hex = Some(public_spend_hex);

        Ok(Self {
            client,
            p2p_peer: p2p_socket_addr,
            internal_indexer: indexer,
            block_checkpoints,
            notify_probabilistic_matches: broadcast::channel(100).0,
            notify_found_utxos: broadcast::channel(100).0,
            notify_spent_outpoints: broadcast::channel(100).0,
            last_scanned_block_height: changeset.last_scanned_block_height,
            last_scanned_block_height_rescan: changeset.last_scanned_block_height_rescan,
            owned_outputs: changeset.owned_outputs.clone(),
            stage: changeset,
        })
    }
}

