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

use crate::types::FrigateResponse;

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

struct ElectrumServerState {
    scanner: Arc<Mutex<Scanner>>,
    scan_start_height: u64,
}

/// Run the Electrum TCP server
pub async fn run(
    scanner: Arc<Mutex<Scanner>>,
    scan_start_height: u64,
    addr: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let state = Arc::new(ElectrumServerState {
        scanner,
        scan_start_height,
    });

    let listener = TcpListener::bind(addr).await?;
    println!("Electrum server listening on {}", addr);

    loop {
        match listener.accept().await {
            Ok((stream, peer_addr)) => {
                println!("Electrum client connected: {}", peer_addr);
                let state = state.clone();

                tokio::spawn(async move {
                    if let Err(e) = handle_client(stream, state).await {
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
    state: Arc<ElectrumServerState>,
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
        handle_request(&request, &state, &mut writer).await?;
    }

    Ok(())
}

/// Handle a JSON-RPC request
async fn handle_request(
    request: &JsonRpcRequest,
    state: &ElectrumServerState,
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

        "server.features" => {
            let resp = JsonRpcResponse::success(
                request.id.clone(),
                json!({ "silent_payments": [0] }),
            );
            writer
                .write_all((serde_json::to_string(&resp)? + "\n").as_bytes())
                .await?;
        }

        "blockchain.silentpayments.subscribe" => {
            let s = state.scanner.lock().await;
            let frigate_response =
                FrigateResponse::from_scanner(&s, state.scan_start_height);

            // 1. Send initial response with subscription metadata (Sparrow expects an object)
            let subscription = serde_json::to_value(&frigate_response.subscription)?;
            let resp = JsonRpcResponse::success(request.id.clone(), subscription);
            writer
                .write_all((serde_json::to_string(&resp)? + "\n").as_bytes())
                .await?;

            // 2. Send notification with positional params: [subscription, progress, history]
            let notification = json!({
                "jsonrpc": "2.0",
                "method": "blockchain.silentpayments.subscribe",
                "params": [
                    frigate_response.subscription,
                    frigate_response.progress,
                    frigate_response.history
                ]
            });
            writer
                .write_all((serde_json::to_string(&notification)? + "\n").as_bytes())
                .await?;
        }

        "blockchain.silentpayments.unsubscribe" => {
            // No-op internally, but return the SP address as expected
            let s = state.scanner.lock().await;
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
