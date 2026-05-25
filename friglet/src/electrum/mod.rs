//! Electrum TCP server for friglet — single-server mode.
//!
//! Implements enough of the Electrum JSON-RPC protocol for Sparrow to use friglet
//! as its sole server with a Silent Payments wallet:
//!
//! - `server.*`                              — handshake / keepalive
//! - `blockchain.headers.subscribe`          — tip + push notifications
//! - `blockchain.scripthash.subscribe/get_history/unsubscribe` — wallet nodes
//! - `blockchain.transaction.get`            — raw tx fetch from index
//! - `blockchain.block.header`               — block header fetch from index
//! - `blockchain.silentpayments.subscribe/unsubscribe` — SP scanning
//! - `blockchain.transaction.broadcast`      — relay via P2P
//! - `blockchain.estimatefee/relayfee`       — stubs (Sparrow has fallbacks)
//! - `mempool.get_fee_histogram`             — stub (empty)

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, broadcast};

use bitcoin_rev::Network;
use blindbit_lib::scanner::Scanner;
use blindbit_lib::scanner::{WalletElectrumIndex, electrum_status};
use blindbit_lib::scanner::broadcast_tx;

// ---------------------------------------------------------------------------
// JSON-RPC wire types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct JsonRpcRequest {
    #[allow(dead_code)]
    jsonrpc: Option<String>,
    id: Value,
    method: String,
    #[serde(default)]
    params: Vec<Value>,
}

#[derive(Debug, Serialize)]
struct JsonRpcResponse {
    jsonrpc: String,
    id: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<JsonRpcError>,
}

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

    fn error(id: Value, code: i32, message: impl Into<String>) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            result: None,
            error: Some(JsonRpcError {
                code,
                message: message.into(),
            }),
        }
    }

    fn into_line(self) -> String {
        serde_json::to_string(&self).expect("serialisation infallible") + "\n"
    }
}

// ---------------------------------------------------------------------------
// Server state — shared across all client connections
// ---------------------------------------------------------------------------

struct ElectrumServerState {
    /// Separate Arc so the Electrum server can read index data without waiting
    /// on the scanner lock (which the scan task holds for its full duration).
    index: Arc<Mutex<WalletElectrumIndex>>,
    p2p_peer: SocketAddr,
    network: Network,
    /// Broadcast channel: pre-serialised JSON notification lines sent to every
    /// connected client.
    push_tx: broadcast::Sender<String>,
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Run the Electrum TCP server.
///
/// `scan_start_height` is forwarded to the SP subscription so Sparrow's
/// subscription key matches across reconnects.
pub async fn run(
    scanner: Arc<Mutex<Scanner>>,
    scan_start_height: u64,
    addr: &str,
    p2p_peer: SocketAddr,
    network: Network,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Clone the Arc to the Electrum index — no scanner lock needed at runtime.
    let index = {
        let s = scanner.lock().await;
        let index = s.electrum_index();
        {
            let mut idx = index.lock().await;
            idx.sp_start_height = scan_start_height;
        }
        index
    };

    let (push_tx, _) = broadcast::channel::<String>(256);

    let state = Arc::new(ElectrumServerState {
        index,
        p2p_peer,
        network,
        push_tx: push_tx.clone(),
    });

    // Background push task: receives a signal whenever the scanner updates the
    // index and broadcasts pre-serialised JSON notifications to all clients.
    // Crucially, this never locks the Scanner — it reads only from `index`.
    {
        let state = state.clone();
        let mut found_rx = {
            let s = scanner.lock().await;
            s.subscribe_to_found_utxos()
        };
        tokio::spawn(async move {
            loop {
                match found_rx.recv().await {
                    Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => {
                        push_notifications(&state).await;
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        });
    }

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

// ---------------------------------------------------------------------------
// Push: build and broadcast all notification types after index update
// ---------------------------------------------------------------------------

async fn push_notifications(state: &ElectrumServerState) {
    if state.push_tx.receiver_count() == 0 {
        return;
    }

    let index = state.index.lock().await;

    // blockchain.headers.subscribe
    if let Some((height, hex)) = &index.tip {
        let notification = json!({
            "jsonrpc": "2.0",
            "method": "blockchain.headers.subscribe",
            "params": [{ "height": height, "hex": hex }]
        });
        let _ = state
            .push_tx
            .send(serde_json::to_string(&notification).unwrap() + "\n");
    }

    // blockchain.scripthash.subscribe — one per known scripthash
    for (scripthash, history) in &index.scripthash_history {
        let status = electrum_status(history);
        let notification = json!({
            "jsonrpc": "2.0",
            "method": "blockchain.scripthash.subscribe",
            "params": [scripthash, status]
        });
        let _ = state
            .push_tx
            .send(serde_json::to_string(&notification).unwrap() + "\n");
    }

    // blockchain.silentpayments.subscribe
    // All data comes from the index — no scanner lock required, so this fires
    // even during an ongoing scan_block_range.
    let sp_subscription = json!({
        "address": index.sp_address,
        "start_height": index.sp_start_height,
        "labels": index.sp_labels,
    });
    let sp_history: Vec<Value> = index
        .sp_history
        .iter()
        .map(|e| {
            json!({
                "height": e.height,
                "tx_hash": e.tx_hash,
                "tweak_key": e.tweak_hex,
            })
        })
        .collect();
    let notification = json!({
        "jsonrpc": "2.0",
        "method": "blockchain.silentpayments.subscribe",
        "params": [sp_subscription, index.scan_progress, sp_history]
    });
    let _ = state
        .push_tx
        .send(serde_json::to_string(&notification).unwrap() + "\n");
}

// ---------------------------------------------------------------------------
// Per-client handler
// ---------------------------------------------------------------------------

async fn handle_client(
    stream: TcpStream,
    state: Arc<ElectrumServerState>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (reader, writer) = stream.into_split();
    let mut reader = BufReader::new(reader);

    // All writes go through this mpsc channel so the writer task owns the TCP
    // write half and the read loop / push forwarder just clone the sender.
    let (tx, mut rx) = tokio::sync::mpsc::channel::<String>(128);

    tokio::spawn(async move {
        let mut writer = writer;
        while let Some(msg) = rx.recv().await {
            let _ = writer.write_all(msg.as_bytes()).await;
        }
    });

    // Forward server-wide push notifications to this client.
    let mut push_rx = state.push_tx.subscribe();
    let tx_push = tx.clone();
    tokio::spawn(async move {
        loop {
            match push_rx.recv().await {
                Ok(line) => {
                    if tx_push.send(line).await.is_err() {
                        break;
                    }
                }
                Err(broadcast::error::RecvError::Closed) => break,
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
            }
        }
    });

    let mut line = String::new();
    loop {
        line.clear();
        if reader.read_line(&mut line).await? == 0 {
            break;
        }

        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let request: JsonRpcRequest = match serde_json::from_str(trimmed) {
            Ok(r) => r,
            Err(e) => {
                let resp =
                    JsonRpcResponse::error(Value::Null, -32700, format!("Parse error: {e}"));
                tx.send(resp.into_line()).await?;
                continue;
            }
        };

        let response_line = handle_request(&request, &state).await;
        tx.send(response_line).await?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Request dispatch
// ---------------------------------------------------------------------------

async fn handle_request(req: &JsonRpcRequest, state: &ElectrumServerState) -> String {
    match req.method.as_str() {
        // ---- Handshake ---------------------------------------------------
        "server.version" => {
            JsonRpcResponse::success(req.id.clone(), json!(["Friglet", "1.4"])).into_line()
        }
        "server.ping" => JsonRpcResponse::success(req.id.clone(), Value::Null).into_line(),
        "server.banner" => JsonRpcResponse::success(
            req.id.clone(),
            Value::String(
                "Friglet — personal silent payment scanner (single-server mode).".to_string(),
            ),
        )
        .into_line(),
        "server.features" => JsonRpcResponse::success(
            req.id.clone(),
            json!({ "silent_payments": [0] }),
        )
        .into_line(),

        // ---- Block headers -----------------------------------------------
        "blockchain.headers.subscribe" => {
            let index = state.index.lock().await;
            let result = match &index.tip {
                Some((height, hex)) if !hex.is_empty() => {
                    json!({ "height": height, "hex": hex })
                }
                Some((height, _)) => json!({ "height": height, "hex": Value::Null }),
                None => json!({ "height": 0, "hex": Value::Null }),
            };
            JsonRpcResponse::success(req.id.clone(), result).into_line()
        }

        "blockchain.block.header" => {
            let Some(height_val) = req.params.first() else {
                return JsonRpcResponse::error(req.id.clone(), -32602, "missing height param")
                    .into_line();
            };
            let Some(height) = height_val.as_u64().map(|h| h as u32) else {
                return JsonRpcResponse::error(
                    req.id.clone(),
                    -32602,
                    "height must be integer",
                )
                .into_line();
            };
            let index = state.index.lock().await;
            match index.headers.get(&height) {
                Some(hex) => {
                    JsonRpcResponse::success(req.id.clone(), Value::String(hex.clone()))
                        .into_line()
                }
                None => JsonRpcResponse::error(
                    req.id.clone(),
                    -32603,
                    format!("unknown block at height {height}"),
                )
                .into_line(),
            }
        }

        // ---- Scripthash --------------------------------------------------
        "blockchain.scripthash.subscribe" => {
            let Some(sh_val) = req.params.first() else {
                return JsonRpcResponse::error(req.id.clone(), -32602, "missing scripthash")
                    .into_line();
            };
            let Some(scripthash) = sh_val.as_str() else {
                return JsonRpcResponse::error(
                    req.id.clone(),
                    -32602,
                    "scripthash must be string",
                )
                .into_line();
            };
            let index = state.index.lock().await;
            let status = index
                .scripthash_history
                .get(scripthash)
                .and_then(|h| electrum_status(h));
            JsonRpcResponse::success(
                req.id.clone(),
                match status {
                    Some(s) => Value::String(s),
                    None => Value::Null,
                },
            )
            .into_line()
        }

        "blockchain.scripthash.get_history" => {
            let Some(sh_val) = req.params.first() else {
                return JsonRpcResponse::error(req.id.clone(), -32602, "missing scripthash")
                    .into_line();
            };
            let Some(scripthash) = sh_val.as_str() else {
                return JsonRpcResponse::error(
                    req.id.clone(),
                    -32602,
                    "scripthash must be string",
                )
                .into_line();
            };
            let index = state.index.lock().await;
            let history: Vec<Value> = index
                .scripthash_history
                .get(scripthash)
                .map(|entries| {
                    entries
                        .iter()
                        .map(|e| {
                            json!({ "tx_hash": e.tx_hash, "height": e.height, "fee": e.fee })
                        })
                        .collect()
                })
                .unwrap_or_default();
            JsonRpcResponse::success(req.id.clone(), Value::Array(history)).into_line()
        }

        "blockchain.scripthash.unsubscribe" => {
            JsonRpcResponse::success(req.id.clone(), Value::Bool(true)).into_line()
        }

        // ---- Transaction -------------------------------------------------
        "blockchain.transaction.get" => {
            let Some(txid_val) = req.params.first() else {
                return JsonRpcResponse::error(req.id.clone(), -32602, "missing txid").into_line();
            };
            let Some(txid) = txid_val.as_str() else {
                return JsonRpcResponse::error(req.id.clone(), -32602, "txid must be string")
                    .into_line();
            };
            let index = state.index.lock().await;
            match index.txs.get(txid) {
                Some(raw) => JsonRpcResponse::success(
                    req.id.clone(),
                    Value::String(hex::encode(raw)),
                )
                .into_line(),
                None => JsonRpcResponse::error(
                    req.id.clone(),
                    -32603,
                    "No such mempool or blockchain transaction",
                )
                .into_line(),
            }
        }

        "blockchain.transaction.broadcast" => {
            let Some(hex_val) = req.params.first() else {
                return JsonRpcResponse::error(req.id.clone(), -32602, "missing raw tx hex")
                    .into_line();
            };
            let Some(raw_hex) = hex_val.as_str() else {
                return JsonRpcResponse::error(req.id.clone(), -32602, "raw tx must be string")
                    .into_line();
            };
            match broadcast_tx(state.p2p_peer, state.network, raw_hex) {
                Ok(txid) => {
                    JsonRpcResponse::success(req.id.clone(), Value::String(txid)).into_line()
                }
                Err(e) => JsonRpcResponse::error(
                    req.id.clone(),
                    -32603,
                    format!("broadcast failed: {e}"),
                )
                .into_line(),
            }
        }

        // ---- Silent Payments ---------------------------------------------
        "blockchain.silentpayments.subscribe" => {
            // All data is read from the index — scanner lock NOT required.
            // This means the handler is never blocked by an ongoing scan.
            let index = state.index.lock().await;

            let sp_subscription = json!({
                "address": index.sp_address,
                "start_height": index.sp_start_height,
                "labels": index.sp_labels,
            });
            let sp_history: Vec<Value> = index
                .sp_history
                .iter()
                .map(|e| {
                    json!({
                        "height": e.height,
                        "tx_hash": e.tx_hash,
                        "tweak_key": e.tweak_hex,
                    })
                })
                .collect();
            let progress = index.scan_progress;
            drop(index);

            // RPC response: the subscription descriptor object.
            let rpc_resp =
                JsonRpcResponse::success(req.id.clone(), sp_subscription.clone()).into_line();

            // Immediate notification: current scan state.
            let notification = json!({
                "jsonrpc": "2.0",
                "method": "blockchain.silentpayments.subscribe",
                "params": [sp_subscription, progress, sp_history]
            });
            let notify_line =
                serde_json::to_string(&notification).expect("serialisation infallible") + "\n";

            // Both lines are concatenated; the writer task flushes them together.
            format!("{rpc_resp}{notify_line}")
        }

        "blockchain.silentpayments.unsubscribe" => {
            let index = state.index.lock().await;
            JsonRpcResponse::success(
                req.id.clone(),
                Value::String(index.sp_address.clone()),
            )
            .into_line()
        }

        // ---- Fee stubs (Sparrow has fallbacks) ---------------------------
        "blockchain.estimatefee" => {
            JsonRpcResponse::success(req.id.clone(), json!(0.0001)).into_line()
        }
        "blockchain.relayfee" => {
            JsonRpcResponse::success(req.id.clone(), json!(0.00001)).into_line()
        }
        "mempool.get_fee_histogram" => {
            JsonRpcResponse::success(req.id.clone(), json!([])).into_line()
        }

        // ---- Unknown -----------------------------------------------------
        _ => JsonRpcResponse::error(
            req.id.clone(),
            -32601,
            format!("Method not found: {}", req.method),
        )
        .into_line(),
    }
}
