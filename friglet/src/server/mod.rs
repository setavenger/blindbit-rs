use axum::{
    Json, Router,
    http::StatusCode,
    routing::{get, post},
};
use serde::{Deserialize, Serialize};

// Response Types

#[derive(Serialize)]
struct HeightResponse {
    height: u64,
}

// Frigate Routes
//
//

// BlindBit Scan Routes
//
//

pub async fn get_height() -> Json<HeightResponse> {
    Json(HeightResponse { height: 12345 })
}
