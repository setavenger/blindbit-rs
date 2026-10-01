//! Electrum TCP server for friglet — single-server mode.
//!
//! Implements enough of the Electrum JSON-RPC protocol for Sparrow to use friglet
//! as its sole server with a Silent Payments wallet:
//!
//! - `server.*`                              — handshake / keepalive
//! - `blockchain.headers.subscribe`          — tip + push notifications, always
//!   with the real header of the tip block (see [`tip_header`])
//! - `blockchain.scripthash.subscribe/get_history/unsubscribe` — wallet nodes
//! - `blockchain.transaction.get`            — raw tx fetch from index
//! - `blockchain.block.header`               — block header fetch from index
//! - `blockchain.silentpayments.subscribe/unsubscribe` — SP scanning
//! - `blockchain.transaction.broadcast`      — relay via P2P; succeeds only once
//!   the peer has the transaction in its mempool (see [`relay`])
//! - `blockchain.relayfee`                   — the P2P peer's mempool minimum
//! - `blockchain.estimatefee`                — `-1`: friglet has no fee estimator
//! - `mempool.get_fee_histogram`             — empty: friglet has no mempool view

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, broadcast};
use tokio::time::{Duration, Instant, timeout, timeout_at};

use bitcoin::BlockHash;
use bitcoin::consensus::encode::deserialize as bitcoin_deserialize;
use bitcoin_rev::Network;
use blindbit_lib::scanner::{
    ScriptHashEntry, WalletElectrumIndex, electrum_scripthash, electrum_status,
};

use crate::blockheader;

mod chain;
#[cfg(test)]
mod fake_peer;
mod p2p;
mod pending;
mod relay;

use self::chain::ChainSource;
use self::pending::PendingStore;
use self::relay::{Candidate, Outcome};

/// How long a broadcast may wait for the peer to accept the transaction.
/// Sparrow's first read timeout is 3 s; on a timeout it resends the request
/// with longer timeouts (8, 16, 34 s), and a resend is answered from
/// [`ElectrumServerState::recent_broadcasts`] as soon as this one finishes.
const BROADCAST_BUDGET: Duration = Duration::from_secs(25);
/// How long a broadcast outcome answers a resend of the same transaction.
const BROADCAST_OUTCOME_TTL: Duration = Duration::from_secs(120);
/// Retry delay after the tip header could not be fetched.
const TIP_RETRY: Duration = Duration::from_secs(15);
/// How often pending broadcasts are checked against the peer's mempool.
const PENDING_RECHECK: Duration = Duration::from_secs(10 * 60);
/// Bitcoin Core's long-standing default minimum relay fee (1 sat/vB),
/// reported only when the peer's own fee filter cannot be read.
const DEFAULT_RELAY_FEE_BTC_PER_KVB: f64 = 0.000_01;

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
    chain: ChainSource,
    block_checkpoints: HashMap<u32, BlockHash>,
    header_sidecar: PathBuf,
    header_fetch_lock: Mutex<()>,
    /// Broadcast channel: pre-serialised JSON notification lines sent to every
    /// connected client.
    push_tx: broadcast::Sender<String>,
    /// Header of the last tip resolved through the oracle: (height, hash, hex).
    tip_cache: Mutex<Option<(u32, BlockHash, String)>>,
    /// The tip last announced to clients, so a tip is announced once.
    last_tip_sent: Mutex<Option<(u32, BlockHash)>>,
    /// Broadcasts the peer accepted that have not confirmed yet.
    pending: Mutex<PendingStore>,
    /// One broadcast at a time; a client's resend waits for the first.
    broadcast_lock: Mutex<()>,
    /// txid → when and how recent broadcasts ended.
    recent_broadcasts: Mutex<HashMap<String, (Instant, RecentBroadcast)>>,
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Run the Electrum TCP server.
///
/// `index` and `found_rx` must be obtained from the scanner before spawning
/// `scan_block_range`, so this server never contends for the scanner mutex.
#[allow(clippy::too_many_arguments)]
pub async fn run(
    index: Arc<Mutex<WalletElectrumIndex>>,
    mut found_rx: broadcast::Receiver<usize>,
    addr: &str,
    p2p_peer: SocketAddr,
    network: Network,
    oracle_url: String,
    block_checkpoints: HashMap<u32, BlockHash>,
    header_sidecar: PathBuf,
    pending_file: PathBuf,
    client_count: Arc<AtomicU64>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (push_tx, _) = broadcast::channel::<String>(256);

    let state = Arc::new(ElectrumServerState {
        index,
        chain: ChainSource::new(p2p_peer, network, oracle_url),
        block_checkpoints,
        header_sidecar,
        header_fetch_lock: Mutex::new(()),
        push_tx: push_tx.clone(),
        tip_cache: Mutex::new(None),
        last_tip_sent: Mutex::new(None),
        pending: Mutex::new(PendingStore::load(pending_file)),
        broadcast_lock: Mutex::new(()),
        recent_broadcasts: Mutex::new(HashMap::new()),
    });

    // Broadcasts from before a restart that have not confirmed: show them as
    // unconfirmed again, as they were.
    restore_pending(&state).await;

    // Background push task: receives a signal whenever the scanner updates the
    // index and broadcasts pre-serialised JSON notifications to all clients.
    //
    // During initial scan the scanner fires a signal for every block, which
    // could be hundreds of thousands of signals.  Without debouncing this
    // floods Sparrow with notifications faster than it can process them,
    // causing UI freezes.  We drain all signals that arrive within a 1-second
    // window and issue a single push for the whole batch.
    {
        let state = state.clone();
        tokio::spawn(async move {
            const DEBOUNCE: Duration = Duration::from_millis(1000);

            // Push current index state immediately so clients don't wait for the
            // first wallet match before seeing scan progress / tip height.
            let mut tip_announced = push_notifications(&state).await;

            loop {
                // While the tip's header could not be fetched, retry on a
                // timer too: the next scanner signal may be a block away.
                let signal = if tip_announced {
                    Some(found_rx.recv().await)
                } else {
                    timeout(TIP_RETRY, found_rx.recv()).await.ok()
                };
                match signal {
                    Some(Err(broadcast::error::RecvError::Closed)) => return,
                    Some(_) => {
                        // Drain any additional signals that arrive within the
                        // debounce window so fast scanning collapses into one push.
                        let deadline = Instant::now() + DEBOUNCE;
                        loop {
                            match timeout_at(deadline, found_rx.recv()).await {
                                Ok(Ok(_)) | Ok(Err(broadcast::error::RecvError::Lagged(_))) => {
                                    // more signals in the window — keep draining
                                }
                                Ok(Err(broadcast::error::RecvError::Closed)) => return,
                                Err(_elapsed) => break, // window expired
                            }
                        }
                    }
                    None => {} // tip retry timer
                }
                tip_announced = push_notifications(&state).await;
            }
        });
    }

    // Pending broadcasts: drop the ones that confirmed or can no longer
    // confirm, re-announce the ones the peer's mempool lost.
    {
        let state = state.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(60)).await;
            loop {
                recheck_pending(&state).await;
                tokio::time::sleep(PENDING_RECHECK).await;
            }
        });
    }

    let listener = TcpListener::bind(addr).await?;
    tracing::info!(addr = %addr, "Electrum server listening");

    loop {
        match listener.accept().await {
            Ok((stream, peer_addr)) => {
                tracing::info!(peer = %peer_addr, "Electrum client connected");
                let state = state.clone();
                let client_count = client_count.clone();
                client_count.fetch_add(1, Ordering::Relaxed);
                tokio::spawn(async move {
                    if let Err(e) = handle_client(stream, state).await {
                        tracing::error!(peer = %peer_addr, error = %e, "Electrum client error");
                    }
                    client_count.fetch_sub(1, Ordering::Relaxed);
                    tracing::info!(peer = %peer_addr, "Electrum client disconnected");
                });
            }
            Err(e) => tracing::error!(error = %e, "Electrum accept error"),
        }
    }
}

// ---------------------------------------------------------------------------
// Push: build and broadcast all notification types after index update
// ---------------------------------------------------------------------------

/// Returns `false` when the tip could not be announced because its header
/// is unavailable right now; the caller retries.
async fn push_notifications(state: &ElectrumServerState) -> bool {
    if state.push_tx.receiver_count() == 0 {
        return true;
    }

    // blockchain.headers.subscribe
    let tip_announced = push_tip(state).await;

    let index = state.index.lock().await;

    // blockchain.scripthash.subscribe — one per known scripthash.
    //
    // Skip during an active scan (progress < 1.0): there is nothing useful
    // Sparrow can do with a scripthash notification while the scan is still
    // running, and broadcasting N notifications per block would flood Sparrow
    // with events faster than it can service them.  A final push is issued
    // when scan_progress reaches 1.0, at which point Sparrow performs its
    // normal one-time history refresh.
    if index.scan_progress >= 1.0 {
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
    tip_announced
}

/// Announce the scanner's tip, with its real header, if it changed since the
/// last announcement. Returns `false` if the header could not be fetched.
async fn push_tip(state: &ElectrumServerState) -> bool {
    let Some(height) = current_tip_height(state).await else {
        return true;
    };
    match tip_header(state, height).await {
        Ok((hash, hex)) => {
            let mut last = state.last_tip_sent.lock().await;
            if *last != Some((height, hash)) {
                let notification = json!({
                    "jsonrpc": "2.0",
                    "method": "blockchain.headers.subscribe",
                    "params": [{ "height": height, "hex": hex }]
                });
                let _ = state
                    .push_tx
                    .send(serde_json::to_string(&notification).unwrap() + "\n");
                *last = Some((height, hash));
            }
            true
        }
        Err(error) => {
            // Announcing the height with a missing or wrong header is worse
            // than waiting: Sparrow ignores a tip whose header does not
            // parse, and records a wrong one as the block at that height.
            tracing::warn!(height, %error, "tip header unavailable; tip not announced yet");
            false
        }
    }
}

async fn current_tip_height(state: &ElectrumServerState) -> Option<u32> {
    state
        .index
        .lock()
        .await
        .tip
        .as_ref()
        .map(|(height, _)| *height)
}

/// The real header of the block at `height`, the scanner's tip.
///
/// The header stored in the index's `tip` is not used: the scanner only
/// sees full headers of blocks it downloads (those with wallet matches) and
/// otherwise carries an older block's header forward to the new height, or
/// has none at all after a restart or a reorg rollback. A header stored for
/// exactly this height is used when there is one. Otherwise the oracle names
/// the block at this height (the chain the scanner follows) and the P2P peer
/// supplies its 80-byte header, checked against that hash. Asking the oracle
/// each time also notices a tip that was replaced at the same height.
async fn tip_header(
    state: &ElectrumServerState,
    height: u32,
) -> Result<(BlockHash, String), String> {
    let stored = state.index.lock().await.headers.get(&height).cloned();
    if let Some(hex) = stored
        && let Ok(header) = blockheader::header_from_hex(&hex)
    {
        return Ok((header.block_hash(), hex));
    }

    let hash = state.chain.block_hash(height).await?;
    if let Some((cached_height, cached_hash, hex)) = state.tip_cache.lock().await.as_ref()
        && *cached_height == height
        && *cached_hash == hash
    {
        return Ok((hash, hex.clone()));
    }
    let header = state.chain.header(hash).await?;
    let hex = blockheader::header_hex(&header);
    *state.tip_cache.lock().await = Some((height, hash, hex.clone()));
    Ok((hash, hex))
}

async fn resolve_block_hash(state: &ElectrumServerState, height: u32) -> Result<BlockHash, String> {
    if let Some(hash) = state.block_checkpoints.get(&height) {
        return Ok(*hash);
    }
    state.chain.block_hash(height).await
}

async fn backfill_header(state: &ElectrumServerState, height: u32) -> Result<String, String> {
    // A single lock is adequate for this personal server and prevents duplicate
    // getdata requests when Sparrow asks for the same missing height at once.
    let _fetch_guard = state.header_fetch_lock.lock().await;

    if let Some(hex) = state.index.lock().await.headers.get(&height).cloned() {
        return Ok(hex);
    }

    let expected_hash = resolve_block_hash(state, height).await?;
    let header = state.chain.header(expected_hash).await?;

    // ChainSource::header already validates this before returning. Keep the
    // check here at the trust boundary so a future fetch implementation cannot
    // serve the wrong block under the requested height.
    let actual_hash = header.block_hash();
    if actual_hash != expected_hash {
        return Err(format!(
            "fetched header hash {actual_hash} does not match expected {expected_hash}"
        ));
    }

    let header_hex = blockheader::header_hex(&header);
    let headers = {
        let mut index = state.index.lock().await;
        index.headers.insert(height, header_hex.clone());
        index.headers.clone()
    };

    let sidecar = state.header_sidecar.clone();
    match tokio::task::spawn_blocking(move || blockheader::save_headers(&sidecar, &headers)).await {
        Ok(Ok(())) => {}
        Ok(Err(error)) => {
            tracing::warn!(
                path = %state.header_sidecar.display(),
                error = %error,
                "failed to persist block-header sidecar"
            );
        }
        Err(error) => {
            tracing::warn!(
                path = %state.header_sidecar.display(),
                error = %error,
                "block-header sidecar write task failed"
            );
        }
    }

    Ok(header_hex)
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
                let resp = JsonRpcResponse::error(Value::Null, -32700, format!("Parse error: {e}"));
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
// Unconfirmed-tx indexing
// ---------------------------------------------------------------------------

/// After the peer accepted a broadcast, index the tx as unconfirmed (`height: 0`)
/// so that Sparrow's `TransactionMempoolService` immediately finds it via
/// `blockchain.scripthash.get_history`.
///
/// Sparrow's poll queries **every wallet node** involved in the tx — both the
/// spent inputs AND any recognized change/receive outputs.  We must therefore
/// index the tx against **all** output scripthashes (not just already-tracked
/// ones), since Sparrow may be polling the change output's scripthash before
/// friglet's SP scanner has seen that output in a confirmed block.
///
/// Input scripthashes are resolved by looking up the previous tx in `idx.txs`.
/// A fallback searches `scripthash_history` for the prev txid in case the raw
/// bytes are not yet cached.
///
/// The set of affected scripthashes is stored in `pending_scripthashes` so
/// that when the block is later confirmed, `scan_block_range` can promote all
/// `height: 0` entries (including non-SP change outputs) to the real height.
async fn index_unconfirmed_tx(index: &Arc<Mutex<WalletElectrumIndex>>, raw_hex: &str, txid: &str) {
    let tx_bytes = match hex::decode(raw_hex) {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!(error = %e, "failed to decode broadcast tx for mempool indexing");
            return;
        }
    };
    let tx: bitcoin::Transaction = match bitcoin_deserialize(&tx_bytes) {
        Ok(t) => t,
        Err(e) => {
            tracing::warn!(error = %e, "failed to parse broadcast tx for mempool indexing");
            return;
        }
    };

    let mut idx = index.lock().await;

    let mut affected: Vec<String> = Vec::new();

    // --- Inputs: resolve the scripthash of each spent output ---
    for input in &tx.input {
        let prev_txid = input.previous_output.txid.to_string();
        let vout = input.previous_output.vout as usize;

        // Primary: decode from raw bytes cached in idx.txs.
        if let Some(raw_prev) = idx.txs.get(&prev_txid)
            && let Ok(prev_tx) = bitcoin_deserialize::<bitcoin::Transaction>(raw_prev)
            && let Some(out) = prev_tx.output.get(vout)
        {
            affected.push(electrum_scripthash(&out.script_pubkey));
            continue;
        }

        // Fallback: the receive tx's scripthash is already in scripthash_history.
        // Find the first scripthash whose history contains the prev txid.
        let mut found = false;
        for (sh, entries) in &idx.scripthash_history {
            if entries.iter().any(|e| e.tx_hash == prev_txid) {
                tracing::debug!(
                    prev_txid = %prev_txid,
                    sh = %sh,
                    "resolved input scripthash via history fallback"
                );
                affected.push(sh.clone());
                found = true;
                break;
            }
        }
        if !found {
            tracing::debug!(prev_txid = %prev_txid, "could not resolve input scripthash (prev tx not cached)");
        }
    }

    // --- Outputs: add ALL output scripthashes unconditionally ---
    //
    // Sparrow calls blockchain.scripthash.get_history for every wallet node
    // involved in the tx (inputs + recognized change/receive outputs).  We
    // must therefore index the tx against the change output's scripthash even
    // if friglet has never seen that script before.  Since Sparrow only queries
    // its own wallet scripthashes, external recipient entries are harmless.
    for out in &tx.output {
        affected.push(electrum_scripthash(&out.script_pubkey));
    }

    // Deduplicate (a self-transfer can produce the same scripthash for input
    // and output if we send back to the same address).
    affected.sort_unstable();
    affected.dedup();

    // Store raw bytes so blockchain.transaction.get can serve the tx.
    idx.txs.insert(txid.to_string(), tx_bytes);

    // Add height-0 entries to every affected scripthash.
    let entry = ScriptHashEntry {
        tx_hash: txid.to_string(),
        height: 0,
        fee: 0,
    };
    let mut added = 0usize;
    for sh in &affected {
        let history = idx.scripthash_history.entry(sh.clone()).or_default();
        match history.iter().position(|e| e.tx_hash == txid) {
            Some(pos) if history[pos].height == 0 => {} // already unconfirmed, no-op
            Some(_) => {}                               // already confirmed, leave it
            None => {
                history.push(entry.clone());
                history.sort_by_key(|e| e.height);
                added += 1;
            }
        }
    }

    // Record affected scripthashes so scan_block_range can promote height-0
    // entries to the confirmed block height when the tx lands in a block.
    idx.pending_scripthashes
        .insert(txid.to_string(), affected.clone());

    tracing::info!(
        txid = %txid,
        new_history_entries = added,
        total_affected_scripthashes = affected.len(),
        "indexed broadcast tx as unconfirmed (height 0)"
    );
}

// ---------------------------------------------------------------------------
// Broadcast and pending transactions
// ---------------------------------------------------------------------------

/// The txid, or a JSON-RPC error code and message.
type BroadcastResult = Result<String, (i32, String)>;

/// How a recent broadcast ended, for answering resends of it.
#[derive(Clone)]
enum RecentBroadcast {
    /// Accepted, or refused for a reason that does not go away.
    Final(BroadcastResult),
    /// Not in the peer's mempool when the wait ended.
    Inconclusive((i32, String)),
}

/// Relay a transaction and answer with its txid only once the P2P peer has
/// it in its mempool; otherwise with an error that says what is known.
async fn broadcast_transaction(state: &ElectrumServerState, raw_hex: &str) -> BroadcastResult {
    let raw = hex::decode(raw_hex.trim())
        .map_err(|error| (1, format!("TX decode failed: invalid hex: {error}")))?;
    let candidate = Candidate::decode(raw).map_err(|message| (1, message))?;
    relay::check_transaction(&candidate.tx).map_err(|message| (1, message))?;
    let txid = candidate.txid.to_string();
    let addr = state.chain.p2p_peer();
    let network = state.chain.network();

    // One broadcast at a time. Sparrow resends a request that took longer
    // than its read timeout; the resend waits here and gets the first
    // attempt's answer instead of starting over.
    let _guard = state.broadcast_lock.lock().await;
    let cached = {
        let mut recent = state.recent_broadcasts.lock().await;
        recent.retain(|_, (at, _)| at.elapsed() < BROADCAST_OUTCOME_TTL);
        recent.get(&txid).map(|(_, outcome)| outcome.clone())
    };
    let mut candidate = match cached {
        Some(RecentBroadcast::Final(result)) => return result,
        // The peer may have accepted it after the wait ended: one quick look
        // before repeating the answer.
        Some(RecentBroadcast::Inconclusive(error)) => {
            let candidate = Arc::new(candidate);
            let task_candidate = candidate.clone();
            let now_in_mempool = tokio::task::spawn_blocking(move || {
                relay::in_mempool(addr, network, &task_candidate)
            })
            .await;
            if !matches!(now_in_mempool, Ok(Ok(true))) {
                return Err(error);
            }
            tracing::info!(%txid, "broadcast reached the peer's mempool after the wait ended");
            accept_pending(state, &candidate).await;
            remember_broadcast(state, &txid, RecentBroadcast::Final(Ok(txid.clone()))).await;
            return Ok(txid);
        }
        None => candidate,
    };

    let already_confirmed = {
        let index = state.index.lock().await;
        candidate.fee = fee_from_index(&index, &candidate.tx);
        pending::confirmed_height(&index, &txid).is_some()
    };
    if already_confirmed {
        return Ok(txid);
    }

    let candidate = Arc::new(candidate);
    let task_candidate = candidate.clone();
    let started = Instant::now();
    let result = tokio::task::spawn_blocking(move || {
        relay::broadcast(addr, network, &task_candidate, BROADCAST_BUDGET)
    })
    .await;
    let (outcome, fee_filter) = match result {
        Ok(Ok(answer)) => answer,
        // The peer could not be asked: not an answer about the transaction,
        // so it is not remembered for resends either.
        Ok(Err(error)) => {
            tracing::warn!(%txid, peer = %addr, %error, "broadcast failed");
            return Err((
                2,
                format!("broadcast failed: P2P peer {addr} unavailable: {error}"),
            ));
        }
        Err(error) => return Err((-32603, format!("broadcast task failed: {error}"))),
    };
    state.chain.note_fee_filter(fee_filter);
    let remembered = match outcome {
        Outcome::InMempool => {
            tracing::info!(
                %txid,
                peer = %addr,
                elapsed_ms = started.elapsed().as_millis() as u64,
                "broadcast accepted into the peer's mempool"
            );
            accept_pending(state, &candidate).await;
            RecentBroadcast::Final(Ok(txid.clone()))
        }
        Outcome::Rejected(message) => {
            tracing::warn!(%txid, peer = %addr, reason = %message, "broadcast rejected");
            RecentBroadcast::Final(Err((1, message)))
        }
        Outcome::NotAccepted(message) => {
            tracing::warn!(%txid, peer = %addr, reason = %message, "broadcast not accepted");
            RecentBroadcast::Inconclusive((1, message))
        }
    };
    let result = match &remembered {
        RecentBroadcast::Final(result) => result.clone(),
        RecentBroadcast::Inconclusive(error) => Err(error.clone()),
    };
    remember_broadcast(state, &txid, remembered).await;
    result
}

async fn remember_broadcast(state: &ElectrumServerState, txid: &str, outcome: RecentBroadcast) {
    state
        .recent_broadcasts
        .lock()
        .await
        .insert(txid.to_string(), (Instant::now(), outcome));
}

/// The fee of `tx` when the index has every transaction it spends from.
fn fee_from_index(index: &WalletElectrumIndex, tx: &bitcoin::Transaction) -> Option<u64> {
    let mut input_sum: u64 = 0;
    for input in &tx.input {
        let raw = index.txs.get(&input.previous_output.txid.to_string())?;
        let previous: bitcoin::Transaction = bitcoin_deserialize(raw).ok()?;
        let output = previous.output.get(input.previous_output.vout as usize)?;
        input_sum = input_sum.checked_add(output.value.to_sat())?;
    }
    let output_sum = tx
        .output
        .iter()
        .try_fold(0u64, |sum, output| sum.checked_add(output.value.to_sat()))?;
    input_sum.checked_sub(output_sum)
}

/// The peer accepted `candidate`: show it as unconfirmed, remember it until
/// it confirms, and retire pending broadcasts it replaced.
async fn accept_pending(state: &ElectrumServerState, candidate: &Candidate) {
    let txid = candidate.txid.to_string();
    let raw_hex = hex::encode(&candidate.raw);
    index_unconfirmed_tx(&state.index, &raw_hex, &txid).await;

    // The peer took this transaction, so whatever pending broadcast spent the
    // same outputs is out of its mempool (replaced): stop showing it.
    let replaced = {
        let mut store = state.pending.lock().await;
        let replaced = store.conflicting(&txid, &pending::spent_outpoints(&candidate.tx));
        for other in &replaced {
            store.remove(other);
        }
        store.insert(txid.clone(), raw_hex);
        store.save();
        replaced
    };
    if !replaced.is_empty() {
        let mut index = state.index.lock().await;
        for other in &replaced {
            pending::unindex_unconfirmed(&mut index, other);
            tracing::info!(replaced = %other, by = %txid, "pending transaction replaced by a newer broadcast");
        }
    }
    push_notifications(state).await;
}

/// After a restart, index pending broadcasts as unconfirmed again.
async fn restore_pending(state: &ElectrumServerState) {
    let store = state.pending.lock().await;
    for (txid, pending_tx) in store.entries() {
        let confirmed = pending::confirmed_height(&*state.index.lock().await, txid).is_some();
        if !confirmed {
            index_unconfirmed_tx(&state.index, &pending_tx.raw_hex, txid).await;
        }
    }
}

/// Settle pending broadcasts against the current chain and the peer's
/// mempool: forget confirmed ones, drop ones that can no longer confirm, and
/// re-announce ones the peer's mempool lost.
async fn recheck_pending(state: &ElectrumServerState) {
    let mut index_changed = false;
    let candidates = {
        let mut store = state.pending.lock().await;
        if store.is_empty() {
            return;
        }
        let mut index = state.index.lock().await;
        // Judge only against a caught-up chain view: a transaction that
        // confirmed in a block the scanner has not reached yet looks missing.
        if index.scan_progress < 1.0 {
            return;
        }
        let mut confirmed = Vec::new();
        let mut dropped = Vec::new();
        let mut candidates = Vec::new();
        for (txid, pending_tx) in store.entries() {
            if pending::confirmed_height(&index, txid).is_some() {
                confirmed.push(txid.clone());
                continue;
            }
            let decoded = hex::decode(&pending_tx.raw_hex)
                .ok()
                .and_then(|raw| Candidate::decode(raw).ok());
            let Some(candidate) = decoded else {
                dropped.push((txid.clone(), "undecodable".to_string()));
                continue;
            };
            let spent = pending::spent_outpoints(&candidate.tx);
            if let Some(other) = pending::confirmed_conflict(&index, txid, &spent) {
                dropped.push((
                    txid.clone(),
                    format!("conflicting transaction {other} confirmed"),
                ));
                continue;
            }
            candidates.push(candidate);
        }
        for txid in &confirmed {
            store.remove(txid);
            tracing::info!(%txid, "pending broadcast confirmed");
        }
        for (txid, reason) in &dropped {
            store.remove(txid);
            index_changed |= pending::unindex_unconfirmed(&mut index, txid);
            tracing::warn!(%txid, %reason, "dropped a pending broadcast that can no longer confirm");
        }
        if !confirmed.is_empty() || !dropped.is_empty() {
            store.save();
        }
        candidates
    };

    if !candidates.is_empty() {
        let addr = state.chain.p2p_peer();
        let network = state.chain.network();
        let candidates = Arc::new(candidates);
        let task_candidates = candidates.clone();
        let result =
            tokio::task::spawn_blocking(move || relay::recheck(addr, network, &task_candidates))
                .await;
        match result {
            Ok(Ok((present, fee_filter))) => {
                state.chain.note_fee_filter(fee_filter);
                let now = pending::now_secs();
                let mut store = state.pending.lock().await;
                let mut expired = Vec::new();
                for (candidate, in_mempool) in candidates.iter().zip(present) {
                    let txid = candidate.txid.to_string();
                    let Some(entry) = store.get_mut(&txid) else {
                        continue;
                    };
                    if in_mempool {
                        entry.last_in_mempool = now;
                    } else if now.saturating_sub(entry.last_in_mempool) > pending::EXPIRY_SECS {
                        expired.push(txid);
                    } else {
                        entry.reannounced += 1;
                    }
                }
                if !expired.is_empty() {
                    let mut index = state.index.lock().await;
                    for txid in &expired {
                        store.remove(txid);
                        index_changed |= pending::unindex_unconfirmed(&mut index, txid);
                        tracing::warn!(
                            %txid,
                            "dropped a pending broadcast the peer has not had in its mempool for \
                             longer than its expiry"
                        );
                    }
                }
                store.save();
            }
            Ok(Err(error)) => {
                tracing::warn!(peer = %addr, %error, "could not recheck pending broadcasts")
            }
            Err(error) => tracing::warn!(%error, "pending recheck task failed"),
        }
    }

    if index_changed {
        push_notifications(state).await;
    }
}

/// `blockchain.relayfee`: the lowest fee rate the P2P peer's mempool accepts
/// right now, in BTC/kvB. Sparrow asks once per connection and drops the
/// connection on an error, so an unreadable peer falls back to Bitcoin
/// Core's long-standing 1 sat/vB default.
async fn relay_fee(state: &ElectrumServerState) -> f64 {
    match timeout(Duration::from_secs(2), state.chain.fee_filter()).await {
        // Above 0.1 BTC/kvB is a peer telling us not to send transactions
        // at all (Bitcoin Core does that during initial block download).
        Ok(Ok(sat_per_kvb)) if sat_per_kvb > 0 && sat_per_kvb <= 10_000_000 => {
            sat_per_kvb as f64 / 100_000_000.0
        }
        Ok(Ok(sat_per_kvb)) => {
            tracing::warn!(
                sat_per_kvb,
                "P2P peer's fee filter is unusable as a relay fee; reporting the default"
            );
            DEFAULT_RELAY_FEE_BTC_PER_KVB
        }
        Ok(Err(error)) => {
            tracing::warn!(%error, "could not read the P2P peer's fee filter; reporting the default relay fee");
            DEFAULT_RELAY_FEE_BTC_PER_KVB
        }
        Err(_) => {
            tracing::warn!(
                "timed out reading the P2P peer's fee filter; reporting the default relay fee"
            );
            DEFAULT_RELAY_FEE_BTC_PER_KVB
        }
    }
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
        "server.features" => {
            JsonRpcResponse::success(req.id.clone(), json!({ "silent_payments": [0] })).into_line()
        }

        // ---- Block headers -----------------------------------------------
        "blockchain.headers.subscribe" => match current_tip_height(state).await {
            // `hex` is not optional in the Electrum protocol: Sparrow drops a
            // connection whose subscribe answer has no valid header. Answer
            // with the real header or with an error that says why not.
            Some(height) => match tip_header(state, height).await {
                Ok((_, hex)) => JsonRpcResponse::success(
                    req.id.clone(),
                    json!({ "height": height, "hex": hex }),
                )
                .into_line(),
                Err(error) => JsonRpcResponse::error(
                    req.id.clone(),
                    1,
                    format!("header unavailable for tip height {height}: {error}"),
                )
                .into_line(),
            },
            None => JsonRpcResponse::error(
                req.id.clone(),
                1,
                "no chain tip known yet; the scanner has not reported a height",
            )
            .into_line(),
        },

        "blockchain.block.header" => {
            let Some(height_val) = req.params.first() else {
                return JsonRpcResponse::error(req.id.clone(), -32602, "missing height param")
                    .into_line();
            };
            let Some(height) = height_val.as_u64().map(|h| h as u32) else {
                return JsonRpcResponse::error(req.id.clone(), -32602, "height must be integer")
                    .into_line();
            };
            if let Some(hex) = state.index.lock().await.headers.get(&height).cloned() {
                return JsonRpcResponse::success(req.id.clone(), Value::String(hex)).into_line();
            }

            match backfill_header(state, height).await {
                Ok(hex) => JsonRpcResponse::success(req.id.clone(), Value::String(hex)).into_line(),
                Err(error) => {
                    tracing::error!(
                        height,
                        error = %error,
                        "failed to backfill requested block header"
                    );
                    JsonRpcResponse::error(
                        req.id.clone(),
                        -32603,
                        format!("unknown block at height {height}: {error}"),
                    )
                    .into_line()
                }
            }
        }

        // ---- Scripthash --------------------------------------------------
        "blockchain.scripthash.subscribe" => {
            let Some(sh_val) = req.params.first() else {
                return JsonRpcResponse::error(req.id.clone(), -32602, "missing scripthash")
                    .into_line();
            };
            let Some(scripthash) = sh_val.as_str() else {
                return JsonRpcResponse::error(req.id.clone(), -32602, "scripthash must be string")
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
                return JsonRpcResponse::error(req.id.clone(), -32602, "scripthash must be string")
                    .into_line();
            };
            let index = state.index.lock().await;
            let history: Vec<Value> = index
                .scripthash_history
                .get(scripthash)
                .map(|entries| {
                    entries
                        .iter()
                        .map(|e| json!({ "tx_hash": e.tx_hash, "height": e.height, "fee": e.fee }))
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
                Some(raw) => {
                    JsonRpcResponse::success(req.id.clone(), Value::String(hex::encode(raw)))
                        .into_line()
                }
                None => JsonRpcResponse::error(
                    req.id.clone(),
                    -32603,
                    "No such mempool or blockchain transaction",
                )
                .into_line(),
            }
        }

        "blockchain.transaction.broadcast" => {
            let Some(raw_hex) = req.params.first().and_then(Value::as_str) else {
                return JsonRpcResponse::error(req.id.clone(), -32602, "missing raw tx hex")
                    .into_line();
            };
            match broadcast_transaction(state, raw_hex).await {
                Ok(txid) => {
                    JsonRpcResponse::success(req.id.clone(), Value::String(txid)).into_line()
                }
                Err((code, message)) => {
                    JsonRpcResponse::error(req.id.clone(), code, message).into_line()
                }
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
            JsonRpcResponse::success(req.id.clone(), Value::String(index.sp_address.clone()))
                .into_line()
        }

        // ---- Fees ----------------------------------------------------------
        // friglet sees no mempool and no fee market, so it does not invent
        // estimates. -1 is the Electrum protocol's "no estimate available".
        // Sparrow keeps fetching rates from its fee rate source (mempool.space
        // by default) whatever the server answers, and turns -1 into its
        // 1 sat/vB floor, the same as for any server without an estimate.
        "blockchain.estimatefee" => JsonRpcResponse::success(req.id.clone(), json!(-1)).into_line(),
        "blockchain.relayfee" => {
            JsonRpcResponse::success(req.id.clone(), json!(relay_fee(state).await)).into_line()
        }
        // No mempool view: an empty histogram. Sparrow only draws its mempool
        // chart from it, and an error here would make Sparrow reconnect.
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::electrum::fake_peer::{FakePeer, Script};
    use bitcoin::absolute::LockTime;
    use bitcoin::transaction::Version;
    use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
    use std::path::Path;

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "friglet-electrum-test-{}-{tag}-{}",
            std::process::id(),
            pending::now_secs()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// No oracle and, unless one is given, no P2P peer: whatever needs them fails.
    fn state(
        index: WalletElectrumIndex,
        p2p: Option<SocketAddr>,
        dir: &Path,
    ) -> ElectrumServerState {
        ElectrumServerState {
            index: Arc::new(Mutex::new(index)),
            chain: ChainSource::new(
                p2p.unwrap_or_else(|| "127.0.0.1:1".parse().unwrap()),
                Network::Regtest,
                "http://127.0.0.1:1".into(),
            ),
            block_checkpoints: HashMap::new(),
            header_sidecar: dir.join("state.headers.json"),
            header_fetch_lock: Mutex::new(()),
            push_tx: broadcast::channel(64).0,
            tip_cache: Mutex::new(None),
            last_tip_sent: Mutex::new(None),
            pending: Mutex::new(PendingStore::load(dir.join("state.pending.json"))),
            broadcast_lock: Mutex::new(()),
            recent_broadcasts: Mutex::new(HashMap::new()),
        }
    }

    fn header_hex_with_nonce(nonce: u32) -> String {
        let mut header = bitcoin::constants::genesis_block(bitcoin::Network::Regtest).header;
        header.nonce = nonce;
        blockheader::header_hex(&header)
    }

    fn drain(rx: &mut broadcast::Receiver<String>) -> Vec<Value> {
        let mut out = Vec::new();
        while let Ok(line) = rx.try_recv() {
            out.push(serde_json::from_str(&line).unwrap());
        }
        out
    }

    fn tip_notifications(rx: &mut broadcast::Receiver<String>) -> Vec<Value> {
        drain(rx)
            .into_iter()
            .filter(|n| n["method"] == "blockchain.headers.subscribe")
            .map(|n| n["params"][0].clone())
            .collect()
    }

    #[tokio::test]
    async fn the_tip_carries_the_header_of_its_own_height_never_a_stale_one() {
        let dir = temp_dir("tip");
        let old = header_hex_with_nonce(1);
        let current = header_hex_with_nonce(2);
        let mut index = WalletElectrumIndex::new();
        index.headers.insert(100, old.clone());
        index.headers.insert(105, current.clone());
        // The scanner carries the last matched block's header forward.
        index.tip = Some((105, old.clone()));
        let state = state(index, None, &dir);
        let mut rx = state.push_tx.subscribe();

        assert!(push_notifications(&state).await);
        assert_eq!(
            tip_notifications(&mut rx),
            vec![json!({ "height": 105, "hex": current })]
        );

        // Same tip again: not announced twice.
        assert!(push_notifications(&state).await);
        assert!(tip_notifications(&mut rx).is_empty());

        // The request path answers the same.
        let request = JsonRpcRequest {
            jsonrpc: None,
            id: json!(1),
            method: "blockchain.headers.subscribe".into(),
            params: vec![],
        };
        let response: Value =
            serde_json::from_str(&handle_request(&request, &state).await).unwrap();
        assert_eq!(response["result"], json!({ "height": 105, "hex": current }));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn a_tip_without_a_fetchable_header_is_not_announced() {
        let dir = temp_dir("tip-missing");
        let mut index = WalletElectrumIndex::new();
        index.headers.insert(100, header_hex_with_nonce(1));
        // No header stored for 106, and neither oracle nor peer reachable;
        // after a reorg rollback the scanner leaves this blank.
        index.tip = Some((106, header_hex_with_nonce(1)));
        let state = state(index, None, &dir);
        let mut rx = state.push_tx.subscribe();

        assert!(
            !push_notifications(&state).await,
            "the caller is told to retry"
        );
        assert!(tip_notifications(&mut rx).is_empty());

        let request = JsonRpcRequest {
            jsonrpc: None,
            id: json!(1),
            method: "blockchain.headers.subscribe".into(),
            params: vec![],
        };
        let response: Value =
            serde_json::from_str(&handle_request(&request, &state).await).unwrap();
        assert!(response["result"].is_null());
        assert!(
            response["error"]["message"]
                .as_str()
                .unwrap()
                .starts_with("header unavailable for tip height 106")
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    fn spend(prev: &Transaction, fee: u64, seq: u32) -> Transaction {
        Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: prev.compute_txid(),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence(seq),
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(prev.output[0].value.to_sat() - fee),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        }
    }

    /// A wallet that received one confirmed output at height 100.
    fn wallet() -> (WalletElectrumIndex, Transaction) {
        let received = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: bitcoin::hashes::Hash::from_byte_array([9; 32]),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(100_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x52]),
            }],
        };
        let mut index = WalletElectrumIndex::new();
        let txid = received.compute_txid().to_string();
        index.txs.insert(
            txid.clone(),
            bitcoin::consensus::encode::serialize(&received),
        );
        index.scripthash_history.insert(
            electrum_scripthash(&received.output[0].script_pubkey),
            vec![ScriptHashEntry {
                tx_hash: txid,
                height: 100,
                fee: 0,
            }],
        );
        index.scan_progress = 1.0;
        (index, received)
    }

    async fn call(state: &ElectrumServerState, method: &str, params: Vec<Value>) -> Value {
        let request = JsonRpcRequest {
            jsonrpc: None,
            id: json!(7),
            method: method.into(),
            params,
        };
        serde_json::from_str(&handle_request(&request, state).await).unwrap()
    }

    #[tokio::test]
    async fn broadcast_errors_are_real_errors() {
        let dir = temp_dir("broadcast-errors");
        let (index, received) = wallet();
        let state = state(index, None, &dir);
        let send = "blockchain.transaction.broadcast";

        let response = call(&state, send, vec![json!("zz")]).await;
        assert!(
            response["error"]["message"]
                .as_str()
                .unwrap()
                .starts_with("TX decode failed")
        );

        let mut no_inputs = spend(&received, 1_000, 0);
        no_inputs.input.clear();
        let raw = hex::encode(bitcoin::consensus::encode::serialize(&no_inputs));
        let response = call(&state, send, vec![json!(raw)]).await;
        assert!(
            response["error"]["message"]
                .as_str()
                .unwrap()
                .starts_with("bad-txns-vin-empty")
        );

        // A valid transaction with no peer to take it: an error, not a txid.
        let raw = hex::encode(bitcoin::consensus::encode::serialize(&spend(
            &received, 1_000, 0,
        )));
        let response = call(&state, send, vec![json!(raw)]).await;
        assert_eq!(response["error"]["code"], 2);
        assert!(response["result"].is_null());
        assert!(state.pending.lock().await.is_empty());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn an_accepted_broadcast_is_shown_persisted_and_replaces_its_predecessor() {
        let dir = temp_dir("broadcast-accepted");
        let (index, received) = wallet();
        // Two broadcasts, two P2P connections.
        let peer = FakePeer::spawn(Script::default(), 2);
        let state = state(index, Some(peer.addr), &dir);
        let send = "blockchain.transaction.broadcast";

        let first = spend(&received, 1_000, 0xffff_fffd);
        let first_txid = first.compute_txid().to_string();
        let raw = hex::encode(bitcoin::consensus::encode::serialize(&first));
        let response = call(&state, send, vec![json!(raw.clone())]).await;
        assert_eq!(response["result"], json!(first_txid));

        // Shown as unconfirmed on the spent output's scripthash.
        let spent_sh = electrum_scripthash(&received.output[0].script_pubkey);
        let history = state.index.lock().await.scripthash_history[&spent_sh].clone();
        assert!(
            history
                .iter()
                .any(|e| e.tx_hash == first_txid && e.height == 0)
        );
        // Persisted for a restart.
        let reloaded = PendingStore::load(dir.join("state.pending.json"));
        assert_eq!(
            reloaded
                .entries()
                .map(|(t, _)| t.clone())
                .collect::<Vec<_>>(),
            vec![first_txid.clone()]
        );

        // A resend (Sparrow's retry after a read timeout) is answered from
        // the first outcome without another P2P round.
        let response = call(&state, send, vec![json!(raw)]).await;
        assert_eq!(response["result"], json!(first_txid));

        // A fee bump spending the same output replaces it.
        let bump = spend(&received, 5_000, 0xffff_fffd);
        let bump_txid = bump.compute_txid().to_string();
        let raw = hex::encode(bitcoin::consensus::encode::serialize(&bump));
        let response = call(&state, send, vec![json!(raw)]).await;
        assert_eq!(response["result"], json!(bump_txid));
        let index = state.index.lock().await;
        let history = &index.scripthash_history[&spent_sh];
        assert!(
            !history.iter().any(|e| e.tx_hash == first_txid),
            "replaced tx no longer shown"
        );
        assert!(
            history
                .iter()
                .any(|e| e.tx_hash == bump_txid && e.height == 0)
        );
        drop(index);
        let reloaded = PendingStore::load(dir.join("state.pending.json"));
        assert_eq!(
            reloaded
                .entries()
                .map(|(t, _)| t.clone())
                .collect::<Vec<_>>(),
            vec![bump_txid]
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn a_resend_after_an_inconclusive_wait_looks_again() {
        let dir = temp_dir("broadcast-late");
        let (index, received) = wallet();
        let tx = spend(&received, 1_000, 0);
        let txid = tx.compute_txid().to_string();
        let raw = bitcoin::consensus::encode::serialize(&tx);
        // The peer has it now, although the first wait ended without it.
        let peer = FakePeer::spawn(
            Script {
                mempool: vec![raw.clone()],
                ..Script::default()
            },
            1,
        );
        let state = state(index, Some(peer.addr), &dir);
        remember_broadcast(
            &state,
            &txid,
            RecentBroadcast::Inconclusive((1, "not accepted".into())),
        )
        .await;

        let response = call(
            &state,
            "blockchain.transaction.broadcast",
            vec![json!(hex::encode(raw))],
        )
        .await;
        assert_eq!(response["result"], json!(txid));
        assert!(!state.pending.lock().await.is_empty());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn pending_broadcasts_survive_a_restart_until_they_confirm_or_conflict() {
        let dir = temp_dir("pending-restart");
        let (index, received) = wallet();
        let tx = spend(&received, 1_000, 0);
        let txid = tx.compute_txid().to_string();
        let raw_hex = hex::encode(bitcoin::consensus::encode::serialize(&tx));
        {
            let mut store = PendingStore::load(dir.join("state.pending.json"));
            store.insert(txid.clone(), raw_hex.clone());
            store.save();
        }

        // Restart: shown as unconfirmed again.
        let state = state(index, None, &dir);
        restore_pending(&state).await;
        let spent_sh = electrum_scripthash(&received.output[0].script_pubkey);
        assert!(
            state.index.lock().await.scripthash_history[&spent_sh]
                .iter()
                .any(|e| e.tx_hash == txid && e.height == 0)
        );

        // A different transaction spending the same output confirms.
        let other = spend(&received, 2_000, 0);
        let other_txid = other.compute_txid().to_string();
        {
            let mut index = state.index.lock().await;
            index.txs.insert(
                other_txid.clone(),
                bitcoin::consensus::encode::serialize(&other),
            );
            index
                .scripthash_history
                .get_mut(&spent_sh)
                .unwrap()
                .push(ScriptHashEntry {
                    tx_hash: other_txid,
                    height: 101,
                    fee: 0,
                });
        }
        recheck_pending(&state).await;
        assert!(state.pending.lock().await.is_empty());
        let index = state.index.lock().await;
        assert!(
            !index.scripthash_history[&spent_sh]
                .iter()
                .any(|e| e.tx_hash == txid)
        );
        assert!(!index.txs.contains_key(&txid));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn a_confirmed_pending_broadcast_is_forgotten() {
        let dir = temp_dir("pending-confirmed");
        let (index, received) = wallet();
        let state = state(index, None, &dir);
        let tx = spend(&received, 1_000, 0);
        let txid = tx.compute_txid().to_string();
        let raw_hex = hex::encode(bitcoin::consensus::encode::serialize(&tx));
        state
            .pending
            .lock()
            .await
            .insert(txid.clone(), raw_hex.clone());
        index_unconfirmed_tx(&state.index, &raw_hex, &txid).await;

        // Still scanning: nothing is judged yet.
        state.index.lock().await.scan_progress = 0.5;
        recheck_pending(&state).await;
        assert!(!state.pending.lock().await.is_empty());

        {
            let mut index = state.index.lock().await;
            index.scan_progress = 1.0;
            for history in index.scripthash_history.values_mut() {
                for entry in history.iter_mut().filter(|e| e.tx_hash == txid) {
                    entry.height = 102;
                }
            }
        }
        recheck_pending(&state).await;
        assert!(state.pending.lock().await.is_empty());
        assert!(PendingStore::load(dir.join("state.pending.json")).is_empty());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn fees_are_the_peers_or_honestly_unavailable() {
        let dir = temp_dir("fees");
        let peer = FakePeer::spawn(
            Script {
                fee_filter: 100,
                ..Script::default()
            },
            1,
        );
        let state = state(WalletElectrumIndex::new(), Some(peer.addr), &dir);

        let response = call(&state, "blockchain.estimatefee", vec![json!(2)]).await;
        assert_eq!(response["result"], json!(-1));
        let response = call(&state, "mempool.get_fee_histogram", vec![]).await;
        assert_eq!(response["result"], json!([]));
        // The peer's 100 sat/kvB fee filter, in BTC/kvB.
        let response = call(&state, "blockchain.relayfee", vec![]).await;
        assert_eq!(response["result"], json!(0.000001));

        // Without a reachable peer: Bitcoin Core's classic default.
        let state = super::tests::state(WalletElectrumIndex::new(), None, &dir);
        let response = call(&state, "blockchain.relayfee", vec![]).await;
        assert_eq!(response["result"], json!(0.00001));
        std::fs::remove_dir_all(dir).unwrap();
    }
}
