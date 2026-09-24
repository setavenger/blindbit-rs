use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
#[cfg(feature = "serde")]
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;

use bitcoin::BlockHash;
use bitcoin::Network as BTCNetwork;
use bitcoin::{OutPoint, Txid};
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{PublicKey, SecretKey};
use bitcoin_rev::Network;
use bitcoin_rev::TestnetVersion;
use indexer::bdk_chain::bdk_core::Merge;
use indexer::v2::SpIndexerV2;
use tokio::sync::{Mutex, broadcast};
use tonic::transport::Channel;

use crate::oracle_grpc::oracle_service_client::OracleServiceClient;
use indexer::bdk_chain::ConfirmationBlockTime;

use super::changeset::ChangeSet;
use super::config::ScannerConfig;
use super::types::OwnedOutputRecord;
use super::electrum_index::{ScriptHashEntry, SpHistoryEntry, WalletElectrumIndex, electrum_scripthash};
use super::ScannerError;

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

    /// Wallet-owned outputs, keyed by outpoint. Maintained by
    /// [`Scanner::sync_owned_outputs`] from the indexer after every applied
    /// block and on restore; persisted as the state file's `owned_outputs`.
    pub(crate) owned_outputs: BTreeMap<OutPoint, OwnedOutputRecord>,

    /// 8-byte x-only key prefix -> *unspent* owned outpoints with that prefix.
    /// Lets the per-block spent-output check run in O(spent prefixes).
    pub(crate) owned_prefixes: HashMap<[u8; 8], Vec<OutPoint>>,

    /// Hash of each scanned height within the reorg lookback window; see
    /// [`ChangeSet::scanned_block_hashes`] and `scanner/reorg.rs`.
    pub(crate) scanned_block_hashes: BTreeMap<u32, BlockHash>,

    /// sends the fork height whenever a chain reorganisation rolled the
    /// wallet state back
    pub(crate) notify_reorg: broadcast::Sender<u32>,

    /// Staged changes that can be persisted
    pub(crate) stage: ChangeSet,

    /// Contains the state of the scanner
    pub(crate) state_file: PathBuf,

    /// P2P network setting, important for p2p communication
    pub(crate) network: Network,

    /// highest number m used for a lable, uses continuous gapless labels
    pub(crate) max_label_num: u32,

    /// Wallet-scoped Electrum index for single-server friglet mode.
    /// Shared with the Electrum TCP server via Arc so it can serve requests
    /// without waiting on the scanner lock.
    pub(crate) electrum_index: Arc<Mutex<WalletElectrumIndex>>,
}

impl Scanner {
    // TODO: create a config with defaults instead of a long list of args
    pub fn new(
        client: OracleServiceClient<Channel>,
        p2p_socket_addr: SocketAddr,
        secret_scan: SecretKey,
        public_spend: PublicKey,
        max_label_num: u32, // highest m for label index
        state_file: PathBuf,
        network: Network,
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
            scanned_block_hashes: BTreeMap::new(),
        };

        // Merge the initial label changes
        stage.indexer.merge(indexer.add_label(0));
        for i in 1..=max_label_num {
            stage.indexer.merge(indexer.add_label(i));
        }

        let sp_address = indexer
            .get_address(convert_network(network))
            .to_string();

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
            owned_outputs: BTreeMap::new(),
            owned_prefixes: HashMap::new(),
            scanned_block_hashes: BTreeMap::new(),
            notify_reorg: broadcast::channel(16).0,
            stage,
            state_file,
            network,
            max_label_num,
            electrum_index: Arc::new(Mutex::new({
                let mut idx = WalletElectrumIndex::new();
                idx.sp_address = sp_address;
                idx.sp_labels = (0..=max_label_num).collect();
                idx
            })),
        }
    }

    /// Create a new Scanner from configuration
    ///
    /// This is a convenience constructor that takes a ScannerConfig instead of
    /// individual parameters. The Oracle client will be created automatically.
    pub async fn from_config(config: &ScannerConfig) -> Result<Self, ScannerError> {
        // Validate configuration
        config.validate()?;

        // Connect to oracle service
        let client = OracleServiceClient::connect(config.oracle_url.clone()).await?;

        Ok(Self::new(
            client,
            config.p2p_socket_addr,
            config.secret_scan,
            config.public_spend,
            config.max_label_num,
            config.state_file.clone(),
            config.network,
        ))
    }

    /// get the last block height that was scanned
    pub fn get_last_scanned_block_height(&self) -> u64 {
        self.last_scanned_block_height
    }

    pub fn get_last_scanned_block_height_rescan(&self) -> u64 {
        self.last_scanned_block_height_rescan
    }

    pub fn get_scanner_sp_address(&self) -> String {
        self.internal_indexer
            .get_address(convert_network(self.network))
            .to_string()
    }

    pub fn get_max_label_num(&self) -> u32 {
        self.max_label_num
    }

    pub fn get_relevant_txs(&self) -> Vec<(Txid, &PublicKey, u32)> {
        let mut txs: Vec<(Txid, &PublicKey, u32)> = Vec::new();

        for inner_tx in self.internal_indexer.graph().full_txs() {
            let Some(anchor) = inner_tx.anchors.first() else {
                continue;
            };
            let Some(shared_secret_tx) = self
                .internal_indexer
                .index()
                .txid_to_partial_secret
                .get(&inner_tx.txid)
            else {
                continue;
            };

            txs.push((inner_tx.txid, shared_secret_tx, anchor.block_id.height));
        }

        txs
    }

    // pub fn get_outputs(&self) -> Vec<OwnedOutput> {
    //     let mut outputs: Vec<OwnedOutput> = Vec::new();
    //     self.internal_indexer.index().index_spout(outpoint, spout);
    //     self.internal_indexer.index().txid_to_partial_secret
    //         outputs.push(OwnedOutput {
    //             outpoint: OutPoint {
    //                 txid: inner_tx.txid,
    //                 vout: 0,
    //             },
    //             blockheight: Height::from_consensus(anchor.block_id.height).unwrap(),
    //             tweak: shared_secret_tx.to_x_only_pubkey().serialize(),
    //             amount: Amount::from_sat(0),
    //             script: ScriptBuf::new(),
    //             label: None,
    //             spent: None,
    //         });
    //     outputs
    // }

    /// Returns a cloned Arc to the wallet-scoped Electrum index.
    /// The Electrum TCP server holds this Arc and serves requests without
    /// locking the scanner itself.
    pub fn electrum_index(&self) -> Arc<Mutex<WalletElectrumIndex>> {
        self.electrum_index.clone()
    }

    /// Returns the P2P peer address. Used by the Electrum server to broadcast txs.
    pub fn p2p_peer(&self) -> SocketAddr {
        self.p2p_peer
    }

    /// Returns the network. Used by the Electrum server for P2P broadcast.
    pub fn network(&self) -> Network {
        self.network
    }

    /// Rebuild the Electrum index from the persisted graph after loading from state.
    ///
    /// Raw tx bytes are recovered from the BDK graph (transactions are stored
    /// in the graph changeset and survive restarts). Call this once after
    /// `from_changeset` / `load_scanner` and before starting the Electrum server.
    ///
    /// `scan_start_height` should match the configured scan start so that
    /// Sparrow's subscription key matches across restarts.
    pub async fn rebuild_electrum_index_from_graph(&self, scan_start_height: u64) {
        let owned_outpoints: std::collections::HashSet<bitcoin::OutPoint> = self
            .internal_indexer
            .index()
            .by_shared_secret
            .keys()
            .cloned()
            .collect();

        // Build outpoint → script map once so spend detection can look up the
        // scripthash of a consumed output without re-iterating the graph.
        let mut outpoint_scripts: std::collections::HashMap<bitcoin::OutPoint, bitcoin::ScriptBuf> =
            std::collections::HashMap::new();
        for node in self.internal_indexer.graph().full_txs() {
            let txid = node.txid;
            for (vout, out) in node.tx.output.iter().enumerate() {
                let op = bitcoin::OutPoint { txid, vout: vout as u32 };
                if owned_outpoints.contains(&op) {
                    outpoint_scripts.insert(op, out.script_pubkey.clone());
                }
            }
        }

        let mut index = self.electrum_index.lock().await;
        index.sp_start_height = scan_start_height;

        for inner_tx in self.internal_indexer.graph().full_txs() {
            let Some(anchor) = inner_tx.anchors.first() else {
                continue;
            };
            let height = anchor.block_id.height;
            let txid = inner_tx.txid;

            let raw = bitcoin::consensus::encode::serialize(inner_tx.tx.as_ref());

            let mut is_ours = false;

            // Receiving side: outputs belonging to the wallet.
            for (vout, output) in inner_tx.tx.output.iter().enumerate() {
                let outpoint = bitcoin::OutPoint {
                    txid,
                    vout: vout as u32,
                };
                if owned_outpoints.contains(&outpoint) {
                    is_ours = true;
                    let scripthash = electrum_scripthash(&output.script_pubkey);
                    let entry = ScriptHashEntry {
                        tx_hash: txid.to_string(),
                        height,
                        fee: 0,
                    };
                    let history = index.scripthash_history.entry(scripthash).or_default();
                    if !history.iter().any(|e| e.tx_hash == entry.tx_hash) {
                        history.push(entry);
                    }
                }
            }

            // Spending side: inputs that consume one of our outputs.
            for input in inner_tx.tx.input.iter() {
                if let Some(script) = outpoint_scripts.get(&input.previous_output) {
                    is_ours = true;
                    let scripthash = electrum_scripthash(script);
                    let entry = ScriptHashEntry {
                        tx_hash: txid.to_string(),
                        height,
                        fee: 0,
                    };
                    let history = index.scripthash_history.entry(scripthash).or_default();
                    if !history.iter().any(|e| e.tx_hash == entry.tx_hash) {
                        history.push(entry);
                    }
                }
            }

            if is_ours {
                index.txs.insert(txid.to_string(), raw);
            }

            // SP history from txid_to_partial_secret
            if let Some(secret) = self
                .internal_indexer
                .index()
                .txid_to_partial_secret
                .get(&txid)
            {
                let entry = SpHistoryEntry {
                    tx_hash: txid.to_string(),
                    height,
                    tweak_hex: secret.to_string(),
                };
                if !index.sp_history.iter().any(|e| e.tx_hash == entry.tx_hash) {
                    index.sp_history.push(entry);
                }
            }
        }

        // Sort all histories by height ascending (Electrum spec order).
        for history in index.scripthash_history.values_mut() {
            history.sort_by_key(|e| e.height);
        }
        index.sp_history.sort_by_key(|e| e.height);

        // Restore tip height from last_scanned_block_height.
        // Header hex is not recoverable without re-fetching; Sparrow's BlockHeaderTip
        // handles an empty hex gracefully.
        if self.last_scanned_block_height > 0 {
            let h = self.last_scanned_block_height as u32;
            let hex = index.headers.get(&h).cloned().unwrap_or_default();
            index.tip = Some((h, hex));
        }

        index.scan_progress = 1.0;
    }

    /// subscribe to notifications when a new utxo is found
    pub fn subscribe_to_found_utxos(&self) -> broadcast::Receiver<usize> {
        self.notify_found_utxos.subscribe()
    }

    /// subscribe to notifications when a new outpoint is spent
    pub fn subscribe_to_spent_outpoints(&self) -> broadcast::Receiver<[u8; 32]> {
        self.notify_spent_outpoints.subscribe()
    }

    /// subscribe to chain reorganisations: each message is the fork height
    /// the wallet state was rolled back to (everything above it was dropped
    /// and is rescanned from the oracle's current chain)
    pub fn subscribe_to_reorgs(&self) -> broadcast::Receiver<u32> {
        self.notify_reorg.subscribe()
    }

    /// subscribe to notifications when a probabilistic match is found
    pub fn subscribe_to_probabilistic_matches(&self) -> broadcast::Receiver<[u8; 32]> {
        self.notify_probabilistic_matches.subscribe()
    }

    /// All wallet-owned outputs found so far (spent and unspent), in outpoint
    /// order.
    pub fn owned_outputs(&self) -> impl Iterator<Item = &OwnedOutputRecord> {
        self.owned_outputs.values()
    }

    /// Bring [`Self::owned_outputs`] in line with the indexer.
    ///
    /// Every output the indexer has matched (`by_script`, full BIP-352 match)
    /// gets a record with its full x-only key and label. A record is marked
    /// spent only when a *confirmed* transaction in the wallet graph has an
    /// input whose `previous_output` is exactly that outpoint; the oracle's
    /// 8-byte spent prefixes only decide which blocks get fetched and never
    /// mark anything themselves. New or changed records are staged.
    pub(crate) fn sync_owned_outputs(&mut self) {
        let index = self.internal_indexer.index();
        let graph = self.internal_indexer.graph();

        let labels: HashMap<OutPoint, Option<u32>> = index
            .by_label
            .iter()
            .map(|(label, outpoint)| (*outpoint, *label))
            .collect();
        let anchor_height = |txid: Txid| {
            graph
                .get_tx_node(txid)
                .and_then(|node| node.anchors.iter().map(|a| a.block_id.height).min())
        };

        let mut changed: Vec<OutPoint> = Vec::new();

        for (xonly, outpoint) in index.by_xonly() {
            if self.owned_outputs.contains_key(outpoint) {
                continue;
            }
            let Some(txout) = graph.get_txout(*outpoint) else {
                continue;
            };
            let Some(height) = anchor_height(outpoint.txid) else {
                continue;
            };
            self.owned_outputs.insert(
                *outpoint,
                OwnedOutputRecord {
                    outpoint: *outpoint,
                    pubkey: xonly,
                    amount_sat: txout.value.to_sat(),
                    height,
                    label: labels.get(outpoint).copied().flatten(),
                    spent_by: None,
                    spent_height: None,
                },
            );
            changed.push(*outpoint);
        }

        for node in graph.full_txs() {
            let Some(spent_height) = node.anchors.iter().map(|a| a.block_id.height).min() else {
                continue;
            };
            for input in &node.tx.input {
                let Some(record) = self.owned_outputs.get_mut(&input.previous_output) else {
                    continue;
                };
                if record.spent_by == Some(node.txid) && record.spent_height == Some(spent_height) {
                    continue;
                }
                record.spent_by = Some(node.txid);
                record.spent_height = Some(spent_height);
                changed.push(input.previous_output);
            }
        }

        if !changed.is_empty() {
            self.stage.merge(ChangeSet {
                owned_outputs: changed
                    .iter()
                    .filter_map(|outpoint| self.owned_outputs.get(outpoint).cloned())
                    .collect(),
                ..ChangeSet::default()
            });
        }

        self.owned_prefixes.clear();
        for record in self.owned_outputs.values().filter(|r| !r.is_spent()) {
            self.owned_prefixes
                .entry(record.short_pubkey())
                .or_default()
                .push(record.outpoint);
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
    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<(), ScannerError> {
        // Create parent directory if it does not exist yet.
        if let Some(parent) = path.as_ref().parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }

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
        changeset.owned_outputs = self.owned_outputs.values().cloned().collect();
        changeset.scanned_block_hashes = self.scanned_block_hashes.clone();

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
    ) -> Result<ChangeSet, ScannerError> {
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
        state_file: PathBuf,
        network: Network,
    ) -> Result<Self, ScannerError> {
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
        let (Some(indexer_scan_sk), Some(indexer_spend_pk)) =
            (changeset.indexer.scan_sk, changeset.indexer.spend_pk)
        else {
            return Err("Failed to reconstruct indexer from changeset: keys missing".into());
        };
        let mut indexer = SpIndexerV2::new(indexer_scan_sk, indexer_spend_pk);

        // Regenerate labels BEFORE applying the changeset: `apply_changeset`
        // re-runs the BIP-352 scan (`index_tx`) over every stored transaction,
        // and `load_from_file` blanks the persisted `label_lookup`. Labels added
        // afterwards would leave every labelled output (change included, m = 0)
        // out of the restored index.
        // ignore change set and be aligned with max_label_num
        let max_label_num = changeset.max_label_num;
        _ = indexer.add_label(0);
        for i in 1..=max_label_num {
            _ = indexer.add_label(i);
        }
        indexer.apply_changeset(changeset.indexer.clone());

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

        let sp_address = indexer
            .get_address(convert_network(network))
            .to_string();

        let owned_outputs = changeset
            .owned_outputs
            .iter()
            .map(|record| (record.outpoint, record.clone()))
            .collect();

        let mut scanner = Self {
            client,
            p2p_peer: p2p_socket_addr,
            internal_indexer: indexer,
            block_checkpoints,
            notify_probabilistic_matches: broadcast::channel(100).0,
            notify_found_utxos: broadcast::channel(100).0,
            notify_spent_outpoints: broadcast::channel(100).0,
            last_scanned_block_height: changeset.last_scanned_block_height,
            last_scanned_block_height_rescan: changeset.last_scanned_block_height_rescan,
            owned_outputs,
            owned_prefixes: HashMap::new(),
            scanned_block_hashes: changeset.scanned_block_hashes.clone(),
            notify_reorg: broadcast::channel(16).0,
            stage: changeset,
            state_file: state_file,
            network: network,
            max_label_num,
            electrum_index: Arc::new(Mutex::new({
                let mut idx = WalletElectrumIndex::new();
                idx.sp_address = sp_address;
                idx.sp_labels = (0..=max_label_num).collect();
                idx
            })),
        };
        // Records older state files never had, spends already in the graph,
        // and the prefix lookup, all derived from the restored indexer.
        scanner.sync_owned_outputs();
        Ok(scanner)
    }
}

fn convert_network(nw: Network) -> BTCNetwork {
    match nw {
        Network::Bitcoin => BTCNetwork::Bitcoin,
        Network::Signet => BTCNetwork::Signet,
        Network::Regtest => BTCNetwork::Regtest,
        // if Testnet V4 is sepcified otherwise we use V3
        Network::Testnet(TestnetVersion::V4) => BTCNetwork::Testnet4,
        Network::Testnet(_) => BTCNetwork::Testnet,
    }
}
