use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use bdk_sp::receive::SpOut;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{PublicKey, SecretKey};
use hex;
use indexer::bdk_chain::{self};
use indexer::v2::SpIndexerV2;
// use indexer::v2;

// ======
use bitcoin_p2p::p2p_message_types::message::InventoryPayload;
use std::str::FromStr;

use bitcoin_p2p::p2p_message_types::{message::NetworkMessage, message_blockdata::Inventory};
use bitcoin_p2p::{
    handshake::ConnectionConfig,
    net::{ConnectionExt, TimeoutParams},
};
// ======

use crate::oracle_grpc::oracle_service_client::OracleServiceClient;
use crate::oracle_grpc::{
    BlockIdentifier, BlockScanDataShortResponse, ComputeIndexTxItem, FullTxItem,
    RangedBlockHeightRequestFiltered,
};
use tokio::sync::broadcast;
use tonic::transport::Channel;

use bdk_chain::ConfirmationBlockTime;
use bitcoin::absolute::Height;
use bitcoin::{
    Amount, Block, BlockHash, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid,
    Witness, XOnlyPublicKey,
};
use indexer::v2::indexes::Label;

// use serde::{Serialize, Deserialize};

// TODO: Replace with your peer address
const PEER: &str = "152.53.151.148:8333";

// todo: make scanner data pulling engine flexible

/// Wrapper for BlockIdentifier that implements Display with hex formatting
pub struct BlockIdentifierDisplay<'a>(pub &'a BlockIdentifier);

impl<'a> std::fmt::Display for BlockIdentifierDisplay<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "BlockIdentifier {{ block_hash: {}, block_height: {} }}",
            hex::encode(&self.0.block_hash),
            self.0.block_height
        )
    }
}

impl<'a> std::fmt::Debug for BlockIdentifierDisplay<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "BlockIdentifier {{ block_hash: {}, block_height: {} }}",
            hex::encode(&self.0.block_hash),
            self.0.block_height
        )
    }
}

pub struct Scanner {
    /// Client to connect to BlindBit Oracle via gRPC
    client: OracleServiceClient<Channel>,

    /// kyoto client for node (p2p_node) to pull full blocks via the p2p network
    // p2p_client: bip157::Client,

    // // kyoto node
    // p2p_node: bip157::node::Node,
    /// the internal indexer used for cryptographic scanning computations
    /// specific to BIP 352
    internal_indexer: SpIndexerV2<ConfirmationBlockTime>,

    /// sends notification when a new utxo is found
    notify_found_utxos: broadcast::Sender<usize>,

    /// probabilistic matches found both used for found utxos and spent outpoints
    /// send the txid of the transaction that is of interest
    notify_probabilistic_matches: broadcast::Sender<[u8; 32]>,

    /// sends notification when a pubkey was probably spent
    /// contains the blockhash which needs to be verified to assert an actual match
    notify_spent_outpoints: broadcast::Sender<[u8; 32]>,

    /// the last block height that was scanned
    last_scanned_block_height: u64,

    /// the last block height that was scanned on most recent rescan
    last_scanned_block_height_rescan: u64,

    /// owned output pubkeys; used to check for spent outputs
    // todo: should this be a hashmap instead of a vector?
    owned_outputs: Vec<[u8; 32]>,
}

#[derive(Debug, Clone, PartialEq)]
// #[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct OwnedOutput {
    pub blockheight: Height,
    pub tweak: [u8; 32], // scalar in big endian format
    pub amount: Amount,
    pub script: ScriptBuf,
    pub label: Option<Label>,
    pub spent: Option<bool>,
}

/// ProbableMatch is a struct that contains a list of txids that are probable matches
/// and a boolean indicating if a utxo might be spent
struct ProbableMatch {
    /// txids is a tuple of txid and tweak
    pub matched_txs: Vec<([u8; 32], PublicKey)>,
    pub spent: bool,
}

impl ProbableMatch {
    pub fn new(matched_txs: Vec<([u8; 32], PublicKey)>, spent: bool) -> Self {
        Self { matched_txs, spent }
    }
}

impl Scanner {
    pub fn new(
        client: OracleServiceClient<Channel>,
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

        let (node, ky_client) = {
            // todo: make network variable
            let builder = bip157::Builder::new(bip157::Network::Bitcoin);
            // todo: add checkpoint
            // todo: add whitelisted peers?

            // setup checkpoint
            let block_hash = BlockHash::from_str(
                "00000000000000000000454a94add7bb3876d934307c9bb95e528c133aa7c39a",
            )
            .unwrap();

            let checkpoint = HeaderCheckpoint::new(907429, block_hash);
            let host = (IpAddr::from(Ipv4Addr::new(152, 53, 151, 148)), Some(8333));

            builder
                .chain_state(bip157::chain::ChainState::Checkpoint(checkpoint))
                .required_peers(10)
                .add_peer(host)
                .data_dir("./kyoto/")
                .build()
        };

        tokio::task::spawn(async move {
            if let Err(e) = node.run().await {
                return Err(e);
            }
            Ok(())
        });

        Self {
            client,
            // p2p_client: ky_client,
            internal_indexer: indexer,
            notify_probabilistic_matches: broadcast::channel(100).0,
            notify_found_utxos: broadcast::channel(100).0,
            notify_spent_outpoints: broadcast::channel(100).0,
            last_scanned_block_height: 0,
            last_scanned_block_height_rescan: 0,
            owned_outputs: vec![],
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
}

impl Scanner {
    /// scan a block range for new utxos and spent outpoints
    pub async fn scan_block_range(
        &mut self,
        start: u64,
        end: u64,
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.wait_for_sync().await?;

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

                    println!("block_hash: {}", block_hash);

                    // Make multiple parallel requests and wait for the first successful one
                    let block = match pull_block_from_p2p_by_blockhash(block_hash) {
                        Ok(full_block) => full_block,
                        Err(err) => {
                            println!("{}", err);
                            return Err(err);
                        },
                    };

                    // build partial secret hashmap, only populate with txids and secrets where we
                    // suspect matches, skip the rest
                    let mut partial_secrets =
                        HashMap::with_capacity(probable_match.matched_txs.len());

                    let mut found = false;
                    let mut tx_to_check: Transaction = Transaction {
                        version: bitcoin::transaction::Version::TWO,
                        lock_time: bitcoin::absolute::LockTime::ZERO,
                        input: vec![],
                        output: vec![],
                    };

                    for tx in block.txdata.iter() {
                        if probable_match.spent {
                            // todo: we will need to look at all spent outpoints in this
                            // block and find the relevant txids for spent
                        }

                        for (txid_arr, tweak) in probable_match.matched_txs.iter() {
                            // this check should be optimised to a map lookup on all items
                            let mut item_txid = *txid_arr;
                            item_txid.reverse();

                            if Txid::from_byte_array(item_txid) != tx.compute_txid() {
                                continue;
                            }

                            let txid = byte_array_to_txid(txid_arr);
                            let ecdh_shared_secret: PublicKey = bdk_sp::compute_shared_secret(
                                self.internal_indexer.scan_sk(),
                                tweak,
                            );

                            if !found {
                                tx_to_check = tx.clone();
                                found = true;
                            }

                            partial_secrets.insert(txid, ecdh_shared_secret);
                        }
                    }
                    println!();
                    println!("partial_secrets: {:?}", partial_secrets);
                    println!("partial_secrets length: {}", partial_secrets.len());
                    _ = self.internal_indexer.apply_block_relevant(
                        &block,
                        partial_secrets,
                        block_identifier.block_height as u32,
                    );
                    println!("is_tx_relevant: {}", tx_to_check.compute_txid());
                    if is_tx_relevant(&self.internal_indexer, &tx_to_check) {
                        println!("is relevant")
                    } else {
                        println!("apparently not relevant")
                    }
                    println!("Printing for height: {}", block_identifier.block_height);
                    for inner_tx in self.internal_indexer.graph().full_txs() {
                        println!("txid: {}", inner_tx.txid)
                    }
                }
                Err(e) => {
                    println!("Error scanning short block data: {:?}", e);
                    return Err(e);
                }
            }
        }

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
                            format!("txid must be exactly 32 bytes, got {} bytes", txid_len),
                        )
                    })?;

                    let tweak = PublicKey::from_slice(&item.tweak)
                        .expect("tweak must be a valid secp256k1 public key");

                    probable_match.matched_txs.push((txid_array, tweak));

                    if self.notify_probabilistic_matches.is_empty() {
                        continue;
                    }
                    if let Err(e) = self.notify_probabilistic_matches.send(txid_array) {
                        println!("Error probabilistic match notification: {:?}", e);
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
            for pubkey in self.owned_outputs.iter() {
                if pubkey[..8] == *spent_output {
                    probable_match.spent = true;

                    println!("Spent output: {:?}", hex::encode(pubkey));
                    if self.notify_spent_outpoints.is_empty() {
                        continue;
                    }
                    if let Err(e) = self.notify_spent_outpoints.send(block_hash) {
                        println!("Error spent output notification: {:?}", e);
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
                format!("tweak must be exactly 33 bytes, got {} bytes", tweak_len),
            )
        })?;
        let tweak = PublicKey::from_slice(&tweak_data).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("tweak must be a valid secp256k1 public key: {:?}", e),
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
    /// returns an array of 'OwnedOutput's
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
                let txid = Txid::from_byte_array(txid_array);

                // we need to change the txid to match the item's txid
                for spout in spouts.iter_mut() {
                    spout.outpoint = OutPoint {
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

fn match_short_pubkey(p_n: &XOnlyPublicKey, output_short_vector: &[u8]) -> bool {
    let seralised_p_n = p_n.serialize();

    let outputs_short_len = output_short_vector.len();
    for i in 0..outputs_short_len / 8 {
        let output_short = &output_short_vector[i * 8..(i + 1) * 8];
        if seralised_p_n[..8] == *output_short {
            // we only need to find the first match to assert a probable match
            return true;
        }
    }

    false
}

fn _match_short_pubkey_bytes(p_n: &[u8; 32], output_short_vector: &[u8]) -> bool {
    let outputs_short_len = output_short_vector.len();
    for i in 0..outputs_short_len / 8 {
        let output_short = &output_short_vector[i * 8..(i + 1) * 8];
        if p_n[..8] == *output_short {
            // we only need to find the first match to assert a probable match
            return true;
        }
    }

    false
}

fn construct_dummy_tx(item: &FullTxItem) -> Transaction {
    let mut inputs = Vec::new();
    let input_count = item.inputs.len() / 36;
    for i in 0..input_count {
        let offset = i * 36;
        let txid_bytes: [u8; 32] = item.inputs[offset..offset + 32]
            .try_into()
            .expect("input txid must be 32 bytes");
        let txid = Txid::from_byte_array(txid_bytes);

        let vout_bytes: [u8; 4] = item.inputs[offset + 32..offset + 36]
            .try_into()
            .expect("input vout must be 4 bytes");
        let vout = u32::from_le_bytes(vout_bytes);

        inputs.push(TxIn {
            previous_output: OutPoint { txid, vout },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        });
    }

    let mut outputs = Vec::new();
    for (idx, utxo) in item.utxos.iter().enumerate() {
        let pubkey = XOnlyPublicKey::from_slice(&utxo.pubkey).expect("invalid pubkey");
        let mut script = ScriptBuf::new();
        script.push_opcode(bitcoin::opcodes::all::OP_PUSHNUM_1);
        script.push_slice(pubkey.serialize());

        if idx < utxo.vout as usize {
            outputs.push(TxOut {
                value: Amount::from_sat(0),
                script_pubkey: ScriptBuf::default(),
            })
        }

        outputs.push(TxOut {
            value: Amount::from_sat(utxo.amount),
            script_pubkey: script,
        });
    }

    Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: inputs,
        output: outputs,
    }
}

fn byte_array_to_txid(txid: &[u8; 32]) -> Txid {
    // Ensure we have exactly 32 bytes
    let mut reversed_txid_slice = *txid;
    reversed_txid_slice.reverse();
    let txid_array: [u8; 32] = reversed_txid_slice;

    // Construct Txid directly from the byte array (preserves byte order)
    Txid::from_byte_array(txid_array)
}

fn is_tx_relevant(indexer: &SpIndexerV2<ConfirmationBlockTime>, tx: &Transaction) -> bool {
    let txid = tx.compute_txid();
    let output_matches = (0..tx.output.len() as u32)
        .map(|vout| OutPoint::new(txid, vout))
        .any(|outpoint| indexer.index().by_shared_secret.contains_key(&outpoint));
    let input_matches = tx.input.iter().any(|input| {
        indexer
            .index()
            .by_shared_secret
            .contains_key(&input.previous_output)
    });
    output_matches || input_matches
}

fn pull_block_from_p2p_by_blockhash(block_hash: BlockHash) -> Result<Block, Box<dyn std::error::Error>> {
    let peer_addr: SocketAddr = PEER.parse()?;
    // let block_hash = BlockHash::from_str(BLOCK_HASH_STR)?;

    println!("Connecting to peer: {}", peer_addr);
    println!("Requesting block: {}", block_hash);

    // Connect to peer
    let (writer, mut reader, metadata) =
        ConnectionConfig::new().open_connection(peer_addr, TimeoutParams::default())?;

    println!(
        "Connected! Peer height: {}, services: {}",
        metadata.feeler_data().reported_height,
        metadata.feeler_data().services
    );

    // Request the block
    let inventory = Inventory::Block(block_hash);
    let net_msg = NetworkMessage::GetData(InventoryPayload(vec![inventory]));

    writer.send_message(net_msg)?;
    println!("Sent GetData request, waiting for block...");

    // Read messages until we receive the block
    let mut message_count = 0;
    loop {
        match reader.read_message()? {
            Some(NetworkMessage::Block(block)) => {
                let full_block = block.assume_checked(None);
                println!("\n✓ Received block!");
                println!("  Block hash: {}", full_block.block_hash());
                println!("  Transactions: {:?}", full_block.transactions().first());

                let bitcoin_block = Block{
                    header: *full_block.header(),
                    txdata: full_block.transactions().map(|tx| bitcoin::Transaction::from(tx.clone())).collect(),
                };
                return Ok(bitcoin_block);
            }
            Some(msg) => {
                message_count += 1;
                if message_count <= 5 {
                    println!("  Received: {:?} (waiting for block...)", msg.command());
                } else if message_count == 6 {
                    println!("  ... (continuing to wait for block)");
                }
            }
            None => continue,
        }
    }
}
