//! Electrum TCP Server implementation for Silent Payments
//!
//! This module implements a simplified Electrum JSON-RPC protocol over TCP
//! that mimics Frigate's communication pattern for wallet compatibility.
//!
//! This is a personal scanner - keys are configured at startup, not per-request.
//! The Electrum endpoint is just a thin protocol adapter over the scanner's data.

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

use blindbit_lib::scanner::Scanner;

use crate::types::{FrigateHistory, FrigateResponse};

/// Electrum JSON-RPC request
#[derive(Debug, Deserialize)]
struct JsonRpcRequest {
    #[allow(dead_code)]
    jsonrpc: Option<String>,
    id: Value,
    method: String,
    #[allow(dead_code)]
    #[serde(default)]
    params: Vec<Value>,
}

/// Electrum JSON-RPC response
#[derive(Debug, Serialize)]
struct JsonRpcResponse {
    jsonrpc: String,
    id: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<JsonRpcError>,
}

/// Electrum JSON-RPC error
#[derive(Debug, Serialize)]
struct JsonRpcError {
    code: i32,
    message: String,
}

impl JsonRpcResponse {
    fn success(id: Value, result: Value) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            result: Some(result),
            error: None,
        }
    }

    fn error(id: Value, code: i32, message: String) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            result: None,
            error: Some(JsonRpcError { code, message }),
        }
    }
}

/// Build FrigateResponse from scanner state (same logic as HTTP endpoint)
fn build_frigate_response(scanner: &Scanner) -> FrigateResponse {
    let relevant_txs = scanner.get_relevant_txs();
    let history: Vec<FrigateHistory> = relevant_txs
        .iter()
        .map(|tx_data| FrigateHistory::from_relevant_tx_data(tx_data))
        .collect();

    FrigateResponse::new(
        scanner.get_scanner_sp_address(),
        scanner.get_last_scanned_block_height(),
        (0..=scanner.get_max_label_num()).collect(),
        1.0,
        history,
    )
}

/// Run the Electrum TCP server
pub async fn run(
    scanner: Arc<Mutex<Scanner>>,
    addr: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let listener = TcpListener::bind(addr).await?;
    println!("Electrum server listening on {}", addr);

    loop {
        match listener.accept().await {
            Ok((stream, peer_addr)) => {
                println!("Electrum client connected: {}", peer_addr);
                let scanner = scanner.clone();

                tokio::spawn(async move {
                    if let Err(e) = handle_client(stream, scanner).await {
                        eprintln!("Client error {}: {}", peer_addr, e);
                    }
                    println!("Electrum client disconnected: {}", peer_addr);
                });
            }
            Err(e) => eprintln!("Accept error: {}", e),
        }
    }
}

/// Handle a single client connection
async fn handle_client(
    stream: TcpStream,
    scanner: Arc<Mutex<Scanner>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut line = String::new();

    loop {
        line.clear();
        if reader.read_line(&mut line).await? == 0 {
            break; // Connection closed
        }

        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        // Parse JSON-RPC request
        let request: JsonRpcRequest = match serde_json::from_str(line) {
            Ok(req) => req,
            Err(e) => {
                let resp =
                    JsonRpcResponse::error(Value::Null, -32700, format!("Parse error: {}", e));
                writer
                    .write_all((serde_json::to_string(&resp)? + "\n").as_bytes())
                    .await?;
                continue;
            }
        };

        // Handle the request
        handle_request(&request, &scanner, &mut writer).await?;
    }

    Ok(())
}

/// Handle a JSON-RPC request
async fn handle_request(
    request: &JsonRpcRequest,
    scanner: &Arc<Mutex<Scanner>>,
    writer: &mut tokio::net::tcp::OwnedWriteHalf,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    match request.method.as_str() {
        "server.version" => {
            let resp = JsonRpcResponse::success(request.id.clone(), json!(["Friglet", "1.4"]));
            writer
                .write_all((serde_json::to_string(&resp)? + "\n").as_bytes())
                .await?;
        }

        "server.ping" => {
            let resp = JsonRpcResponse::success(request.id.clone(), Value::Null);
            writer
                .write_all((serde_json::to_string(&resp)? + "\n").as_bytes())
                .await?;
        }

        "blockchain.silentpayments.subscribe" => {
            // TODO: send back start height which is provided in the rpc call
            let s = scanner.lock().await;
            let sp_address = s.get_scanner_sp_address();

            // 1. Send initial response with SP address
            let resp = JsonRpcResponse::success(request.id.clone(), Value::String(sp_address));
            writer
                .write_all((serde_json::to_string(&resp)? + "\n").as_bytes())
                .await?;

            // 2. Send notification with full history (same data as HTTP endpoint)
            let frigate_response = build_frigate_response(&s);
            let notification = json!({
                "jsonrpc": "2.0",
                "method": "blockchain.silentpayments.subscribe",
                "params": frigate_response
            });
            writer
                .write_all((serde_json::to_string(&notification)? + "\n").as_bytes())
                .await?;
        }

        "blockchain.silentpayments.unsubscribe" => {
            // No-op internally, but return the SP address as expected
            let s = scanner.lock().await;
            let resp = JsonRpcResponse::success(
                request.id.clone(),
                Value::String(s.get_scanner_sp_address()),
            );
            writer
                .write_all((serde_json::to_string(&resp)? + "\n").as_bytes())
                .await?;
        }

        _ => {
            let resp = JsonRpcResponse::error(
                request.id.clone(),
                -32601,
                format!("Method not found: {}", request.method),
            );
            writer
                .write_all((serde_json::to_string(&resp)? + "\n").as_bytes())
                .await?;
        }
    }

    Ok(())
}
