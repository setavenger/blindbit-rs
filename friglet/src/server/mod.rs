use crate::scanner;
use crate::types::{FrigateHistory, FrigateResponse};
use axum::{Extension, Json};
use serde::Serialize;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Serialize)]
pub struct HeightResponse {
    pub height: u64,
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
        .map(|out| FrigateHistory::from_relevant_tx_data(out))
        .collect();

    Json(FrigateResponse::new(
        s.get_scanner_sp_address(),
        s.get_last_scanned_block_height(),
        (0..=s.get_max_label_num()).collect(),
        1.0,
        history,
    ))
}
