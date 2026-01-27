use crate::scanner;
use axum::{Extension, Json};
use bitcoin::Txid;
use bitcoin::secp256k1::PublicKey;
use serde::Serialize;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Serialize)]
pub struct HeightResponse {
    pub height: u64,
}

#[derive(Serialize)]
pub struct FrigateResponse {
    pub subscription: FrigateSubscription,
    pub progress: f32,
    pub history: Vec<FrigateHistory>,
}

#[derive(Serialize)]
pub struct FrigateSubscription {
    pub address: String,
    pub start_height: u64,
    pub labels: Vec<u32>,
}

#[derive(Serialize)]
pub struct FrigateHistory {
    pub height: u64,
    pub tx_hash: String,
    pub tweak_key: String,
}

impl FrigateHistory {
    pub fn from_relavant_tx_data(out: &(Txid, &PublicKey, u32)) -> FrigateHistory {
        FrigateHistory {
            height: u64::from(out.2),
            tx_hash: out.0.to_string(),
            tweak_key: out.1.to_string(),
        }
    }

    // pub fn from_owned_output(out: &OwnedOutput) -> FrigateHistory {
    //     FrigateHistory {
    //         height: u64::from(out.blockheight.to_consensus_u32()),
    //         tx_hash: out.outpoint.txid.to_string(),
    //         tweak_key: hex::encode(out.tweak),
    //     }
    // }
}

pub async fn get_height(
    Extension(sp_scanner): Extension<Arc<Mutex<scanner::Scanner>>>,
) -> Json<HeightResponse> {
    let s = sp_scanner.lock().await;
    Json(HeightResponse {
        height: s.get_last_scanned_block_height(),
    })
}

pub async fn subscribe(
    Extension(sp_scanner): Extension<Arc<Mutex<scanner::Scanner>>>,
) -> Json<FrigateResponse> {
    let s = sp_scanner.lock().await;

    let outputs = s.get_relevant_txs();

    let history: Vec<FrigateHistory> = outputs
        .iter()
        .map(|out| FrigateHistory::from_relavant_tx_data(out))
        .collect();

    Json(FrigateResponse {
        subscription: FrigateSubscription {
            address: s.get_scanner_sp_address(),
            start_height: s.get_last_scanned_block_height(),
            labels: (0..=s.get_max_label_num()).collect(),
        },
        progress: 1.0,
        history: history,
    })
}
