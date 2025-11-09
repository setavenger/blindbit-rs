use bitcoin::secp256k1::{SecretKey, PublicKey};
use indexer::bdk_chain;
use indexer::v2::SpIndexerV2;
use hex;
// use indexer::v2;
use tokio::sync::broadcast;
use tonic::transport::Channel;
use crate::ComputeIndexTxItem;
use crate::oracle_grpc::oracle_service_client::OracleServiceClient;
use crate::oracle_grpc::{
    RangedBlockHeightRequestFiltered, 
    BlockScanDataShortResponse,
    BlockIdentifier,
};

use bitcoin::absolute::{Height};
use bitcoin::{Amount, ScriptBuf};
use indexer::v2::indexes::Label;
use bdk_chain::{ConfirmationBlockTime};

// use serde::{Serialize, Deserialize};

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
    client: OracleServiceClient<Channel>,

    /// the internal indexer used for cryptographic scanning computations
    /// specific to BIP 352
    internal_indexer: SpIndexerV2<ConfirmationBlockTime>,

    /// sends notification when a new utxo is found
    notify_found_utxos:  broadcast::Sender<usize>,

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

        // add_label already modifies the indexer's internal state directly
        // The returned changeset is for staging/persistence purposes, not for re-applying
        // _ = indexer.add_label(0);
        // _ = indexer.add_label(3);
        for i in 1..=max_label_num {
            _ = indexer.add_label(i);
        }

        Self { 
            client, 
            internal_indexer: indexer, 
            notify_probabilistic_matches: broadcast::channel(100).0,
            notify_found_utxos: broadcast::channel(100).0 ,
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
    pub async fn scan_block_range(&mut self, start: u64, end: u64) -> Result<(), Box<dyn std::error::Error>> {
        let request = tonic::Request::new(RangedBlockHeightRequestFiltered { start, end, dustlimit: 0, cut_through: false });
        let mut stream = self.client.stream_block_scan_data_short(request).await.unwrap().into_inner();
        while let Some(item) = stream.message().await.unwrap() {
            if let Some(ref block_id) = item.block_identifier {
                println!("received: {}", BlockIdentifierDisplay(block_id));
            } else {
                println!("\treceived: BlockIdentifier {{ block_hash: <missing>, block_height: <missing> }}");
            }
            if let Err(e) = self.scan_short_block_data(item) {
                println!("Error scanning short block data: {:?}", e);
                return Err(e);
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
    fn scan_short_block_data(&mut self, block_data: BlockScanDataShortResponse) -> Result<(), Box<dyn std::error::Error>> {
        // todo: first append to list then push notifications. 
        //  We need to check for the actual match and not just a probablistic match.


        let Some(block_id) = block_data.block_identifier else {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "block identifier is missing").into());
        };

        if block_id.block_hash.len() != 32 {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "block hash is not 32 bytes").into());
        }

        let block_hash: [u8; 32] = block_id.block_hash.try_into()
            .map_err(|_| std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "block hash is not 32 bytes"
            ))?;


        for item in block_data.comp_index {
            match self.probabilistic_match(&item) {
                Ok(true) => {
                    println!("TxId of interest: {:?}", hex::encode(&item.txid));
                    if self.notify_probabilistic_matches.receiver_count() > 0 {
                        let txid_len = item.txid.len();
                        // tood: clean this up
                        let txid_array: [u8; 32] = item.txid.try_into()
                            .map_err(|_| std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                format!("txid must be exactly 32 bytes, got {} bytes", txid_len)
                            ))?;
                        if let Err(e) = self.notify_probabilistic_matches.send(txid_array) {
                            println!("Error probabilistic match notification: {:?}", e);
                        }
                    }
                    return Ok(());
                }
                Ok(false) => continue,
                Err(e) => return Err(e),
            }
        }

        // make spent pubkey check
        let spent_outputs_count = block_data.spent_outputs.len() /8 as usize;
        for i in 0..spent_outputs_count {
            let spent_output = &block_data.spent_outputs[i * 8..(i + 1) * 8];
            for pubkey in self.owned_outputs.iter() {
                if pubkey[..8] == *spent_output {
                    println!("Spent output: {:?}", hex::encode(&pubkey));
                    if self.notify_spent_outpoints.receiver_count() > 0 {
                        if let Err(e) = self.notify_spent_outpoints.send(block_hash) {
                            println!("Error spent output notification: {:?}", e);
                        }
                    }
                    return Ok(());
                }
            }
        }

        Ok(())
    }   

    fn probabilistic_match(&mut self, item: &ComputeIndexTxItem) -> Result<bool, Box<dyn std::error::Error>> {
        let tweak_len = item.tweak.len();
        let tweak_data: [u8; 33] = item.tweak.clone().try_into()
            .map_err(|_| std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("tweak must be exactly 33 bytes, got {} bytes", tweak_len)
            ))?;
        let tweak = PublicKey::from_slice(&tweak_data)
            .map_err(|e| std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("tweak must be a valid secp256k1 public key: {:?}", e)
            ))?;
    
        // compute potential outputs for the tweak
        let spks = self.internal_indexer.derive_spks_for_tweak(&tweak);
    
        // compare against the shortened 8 byte outputs for the transaction to find a match 
        // if a match is found, send a notification
    
        
        // we need to do a m x n comparison to find a match
        // item.outputs_short is a contigous slice of 8 bytes each
        // iterate for len(outputs_short) / 8 times
        // todo: this can be slightly optimised by using a modified iterative scanning function 
        //  modify the common receive scanning function by checking against 8bytes not full pubkeys
        let outputs_short_len = item.outputs_short.len();
        for i in 0..outputs_short_len / 8 {
            let output_short = &item.outputs_short[i * 8..(i + 1) * 8];
            for spk in spks.iter() {
                // derive_spks_for_tweak returns a full script pubkey include 51020 prefix
                if spk[2..10] == *output_short {
                    println!("Potential match found: {:?}", hex::encode(&spk[2..]));
                    return Ok(true);
                }
            }
        }
    
        return Ok(false);
    }
}


