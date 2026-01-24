use crate::scanner;
use axum::{Extension, Json};
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
    pub tx_response: String,
    pub tweak_key: String,
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
    Json(FrigateResponse {
        subscription: FrigateSubscription {
            address: s.get_scanner_sp_address(),
            start_height: s.get_last_scanned_block_height(),
            labels: Vec::new(),
        },
        progress: 1.0,
        history: Vec::new(),
    })
}
