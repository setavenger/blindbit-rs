use crate::types::FrigateResponse;
use axum::{Extension, Json};
use blindbit_lib::scanner::Scanner;
use serde::Serialize;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Clone, Copy)]
pub struct ScanStartHeight(pub u64);

#[derive(Serialize)]
pub struct HeightResponse {
    pub height: u64,
}

pub async fn get_height(
    Extension(sp_scanner): Extension<Arc<Mutex<Scanner>>>,
) -> Json<HeightResponse> {
    let s = sp_scanner.lock().await;
    Json(HeightResponse {
        height: s.get_last_scanned_block_height(),
    })
}

pub async fn subscribe(
    Extension(sp_scanner): Extension<Arc<Mutex<Scanner>>>,
    Extension(ScanStartHeight(scan_start_height)): Extension<ScanStartHeight>,
) -> Json<FrigateResponse> {
    let s = sp_scanner.lock().await;
    Json(FrigateResponse::from_scanner(&s, scan_start_height))
}
