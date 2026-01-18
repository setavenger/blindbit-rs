use std::sync::{Arc, Mutex};

use axum::{
    Extension, Json, Router,
    http::StatusCode,
    routing::{get, post},
};
use blindbit_lib::scanner;
use serde::{Deserialize, Serialize};
use tokio;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let scanner = Arc::new(Mutex::new(Scanner::new(/* your params */)));

    // launch the scanner in the background
    let bg_scanner = scanner.clone();
    tokio::spawn(async move {
        let mut s = bg_scanner.lock().unwrap();
        s.scan_block_range(start, end).await.unwrap();
    });

    // 4. Create HTTP server
    let app = Router::new()
        // .route("/utxos", get(get_utxos))
        .route("/height", get(get_height))
        .layer(Extension(bg_scanner));

    // 5. Start server
    let listener = tokio::net::TcpListener::bind("127.0.0.1:8080")
        .await
        .unwrap();
    axum::serve(listener, app).await.unwrap();
    Ok(())
}

#[derive(Serialize)]
struct HeightResponse {
    height: u64,
}

async fn get_height(
    Extension(sp_scanner): Extension<Arc<Mutex<scanner::Scanner>>>,
) -> Json<HeightResponse> {
    let s = sp_scanner.lock().unwrap();
    Json(HeightResponse {
        height: s.get_last_scanned_block_height(),
    })
}
