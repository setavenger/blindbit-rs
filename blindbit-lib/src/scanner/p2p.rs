use std::io;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use bitcoin::Block;
use bitcoin::BlockHash;
use bitcoin::hashes::Hash;

use bitcoin_p2p::net::{ConnectionReader, ConnectionWriter, Error as P2pNetError};
use bitcoin_p2p::p2p_message_types::message::InventoryPayload;
use bitcoin_p2p::p2p_message_types::{message::NetworkMessage, message_blockdata::Inventory};
use bitcoin_p2p::{
    handshake::ConnectionConfig,
    net::{ConnectionExt, TimeoutParams},
};

// rust-bitcoin on specific commit for use with bitcoin-p2p library
use bitcoin_rev::Network;
use bitcoin_rev::block::BlockHash as PrimitivesBlockHash;
use bitcoin_rev::consensus::encode;

use super::ScannerError;

/// Broadcast a raw transaction to a P2P peer.
///
/// Opens a fresh P2P connection, completes the handshake, sends the raw `tx`
/// message, then reads back up to `MAX_READBACK` messages before closing.
/// Reading back is important: it keeps the connection open long enough for the
/// peer to fully process the payload, and surfaces any `reject` or other
/// diagnostic messages that would otherwise be silently discarded.
///
/// Returns the txid hex string on success.  Returns an error if the peer sends
/// a `reject`-equivalent response or if any I/O step fails.
pub fn broadcast_tx(
    p2p_peer: SocketAddr,
    network: Network,
    raw_tx_hex: &str,
) -> Result<String, ScannerError> {
    let tx_bytes = hex::decode(raw_tx_hex)?;

    // Parse with the standard bitcoin crate to compute the txid.
    let bitcoin_tx: bitcoin::Transaction =
        bitcoin::consensus::encode::deserialize(&tx_bytes)?;
    let txid = bitcoin_tx.compute_txid().to_string();

    // Re-parse with bitcoin_rev (the commit that bitcoin-p2p expects).
    let prim_tx: bitcoin_rev::Transaction = encode::deserialize(&tx_bytes)?;

    tracing::debug!(peer = %p2p_peer, "connecting to P2P peer for broadcast");

    let connection_config = ConnectionConfig::new().change_network(network);
    let (writer, mut reader, metadata) =
        connection_config.open_connection(p2p_peer, TimeoutParams::default())?;

    tracing::debug!(
        peer_height = metadata.feeler_data().reported_height,
        services = %metadata.feeler_data().services,
        "P2P handshake complete"
    );

    writer.send_message(NetworkMessage::Tx(prim_tx))?;
    tracing::info!(txid = %txid, peer = %p2p_peer, "transaction sent to P2P peer");

    // Drain the immediate post-handshake messages the peer sends right after
    // the connection is established (sendcmpct / sendheaders / feefilter /
    // ping).  Reading these:
    //   1. Keeps the TCP socket open long enough for the peer to receive the Tx
    //   2. Surfaces any immediate rejection the peer might send
    //
    // We stop after a small fixed count because after those 3-4 quick setup
    // messages the peer only sends keepalive pings every ~30 s — waiting for
    // them would block the caller for minutes.  Any rejection arrives within
    // the first few messages (BIP-61 reject, if enabled, follows the tx almost
    // immediately).
    const MAX_READBACK: usize = 3;
    let mut n = 0;
    loop {
        match reader.read_message() {
            Ok(Some(msg)) => {
                let cmd = msg.command();
                tracing::debug!(command = %cmd, "received P2P message after broadcast");
                n += 1;
                if n >= MAX_READBACK {
                    break;
                }
            }
            Ok(None) => break,
            Err(e) => {
                tracing::debug!(error = %e, "P2P read ended after broadcast (expected)");
                break;
            }
        }
    }

    tracing::info!(txid = %txid, "broadcast complete");
    Ok(txid)
}

/// How long the peer may stay silent before we give up on a single read.
///
/// This is a per-syscall socket timeout, NOT a per-message budget.  It needs to
/// be generous: after we send `getdata`, the peer may take a moment to load a
/// large block off disk, and during a multi-megabyte transfer there can be
/// short gaps between TCP segments.  A too-short value (the previous code used
/// 1 second) risks firing in the *middle* of a block payload, which makes the
/// library's `read_exact` abort after partially consuming the message and
/// permanently desyncs the stream.  30 s is far longer than any healthy gap but
/// still bounds a dead connection.
const READ_TIMEOUT: Duration = Duration::from_secs(30);

/// Overall wall-clock budget for receiving one block, across any number of
/// tolerated per-syscall read timeouts.
const BLOCK_FETCH_DEADLINE: Duration = Duration::from_secs(90);

/// Persistent P2P connection for fetching multiple blocks without reconnecting.
///
/// Opening a fresh TCP connection + handshake per block caused rapid-fire
/// connect/disconnect churn against the peer, so this keeps one connection
/// alive across an entire scan range.
///
/// Note: the previous "post-handshake drain" has been removed.  It existed on
/// the false premise that the post-`verack` message flood (`sendcmpct`,
/// `feefilter`, `wtxidrelay`, `sendaddrv2`, …) would corrupt later reads.  In
/// fact unrecognised messages decode to `NetworkMessage::Unknown` and every
/// message is read as an exact, checksummed frame, so the stream never desyncs.
/// `fetch_block` simply skips any non-block message while it waits, which makes
/// the drain redundant (and it was the cause of multi-minute startup stalls,
/// since it blocked reading the peer's 30 s keepalive pongs).
pub struct P2pConnection {
    writer: ConnectionWriter,
    reader: ConnectionReader,
    peer: SocketAddr,
}

impl P2pConnection {
    pub fn connect(
        p2p_peer: SocketAddr,
        network: Network,
    ) -> Result<Self, ScannerError> {
        tracing::debug!(peer = %p2p_peer, "opening persistent P2P connection for block fetches");
        let connection_config = ConnectionConfig::new().change_network(network);
        let mut timeout_params = TimeoutParams::new();
        timeout_params.read_timeout(READ_TIMEOUT);
        let (writer, reader, metadata) =
            connection_config.open_connection(p2p_peer, timeout_params)?;

        tracing::debug!(
            peer = %p2p_peer,
            peer_height = metadata.feeler_data().reported_height,
            services = %metadata.feeler_data().services,
            "P2P handshake complete"
        );

        Ok(Self { writer, reader, peer: p2p_peer })
    }

    pub fn fetch_block(&mut self, block_hash: BlockHash) -> Result<Block, ScannerError> {
        let primitives_block_hash =
            PrimitivesBlockHash::from_byte_array(*block_hash.as_byte_array());
        let inventory = Inventory::Block(primitives_block_hash);
        let net_msg = NetworkMessage::GetData(InventoryPayload(vec![inventory]));

        self.writer
            .send_message(net_msg)
            .map_err(|e| -> ScannerError { format!("P2P send failed: {e}").into() })?;
        tracing::debug!(peer = %self.peer, block_hash = %block_hash, "sent getdata for block");

        let started = Instant::now();
        let mut last_idle_log = 0u64;

        loop {
            if started.elapsed() > BLOCK_FETCH_DEADLINE {
                return Err(format!(
                    "gave up waiting for block {block_hash} from {} after {:?}",
                    self.peer,
                    started.elapsed()
                )
                .into());
            }

            match self.reader.read_message() {
                Ok(Some(NetworkMessage::Block(block))) => {
                    let block_bytes = encode::serialize(&block);
                    let block: Block = bitcoin::consensus::encode::deserialize(&block_bytes)?;
                    tracing::info!(
                        peer = %self.peer,
                        block_hash = %block.block_hash(),
                        tx_count = block.txdata.len(),
                        elapsed_ms = started.elapsed().as_millis() as u64,
                        "received block from peer"
                    );
                    return Ok(block);
                }
                Ok(Some(NetworkMessage::Ping(nonce))) => {
                    // Pong inline so the peer doesn't drop us for inactivity
                    // while it's still preparing/streaming the block.
                    let _ = self.writer.send_message(NetworkMessage::Pong(nonce));
                }
                // The peer explicitly told us it does not have/serve this block.
                // Spinning would loop forever; surface a clear, distinct error.
                Ok(Some(NetworkMessage::NotFound(inv))) => {
                    return Err(format!(
                        "peer {} replied notfound for block {block_hash} ({} inv item(s)) \
                         — peer may be pruned or not serving this block",
                        self.peer,
                        inv.0.len()
                    )
                    .into());
                }
                Ok(Some(NetworkMessage::Reject(reject))) => {
                    return Err(format!(
                        "peer {} rejected getdata for block {block_hash}: {reject:?}",
                        self.peer
                    )
                    .into());
                }
                Ok(Some(msg)) => {
                    tracing::trace!(
                        peer = %self.peer,
                        command = %msg.command(),
                        "skipping message while waiting for block"
                    );
                }
                Ok(None) => {} // no message this round; keep waiting
                Err(e) => {
                    if is_read_timeout(&e) {
                        // Per-syscall timeout: the peer just hasn't sent the next
                        // chunk yet. Keep waiting until BLOCK_FETCH_DEADLINE.
                        let waited = started.elapsed().as_secs();
                        if waited >= last_idle_log + READ_TIMEOUT.as_secs() {
                            last_idle_log = waited;
                            tracing::warn!(
                                peer = %self.peer,
                                block_hash = %block_hash,
                                waited_s = waited,
                                "no data from peer yet, still waiting for block"
                            );
                        }
                        continue;
                    }

                    // Anything else means the connection is unusable: EOF means
                    // the peer closed on us ("failed to fill whole buffer"); a
                    // deserialize error means the framed stream is corrupt.
                    let reason = if is_eof(&e) {
                        "peer closed the connection"
                    } else {
                        "unrecoverable read error"
                    };
                    return Err(format!(
                        "block fetch from {} failed ({reason}) while waiting for {block_hash}: {e}",
                        self.peer
                    )
                    .into());
                }
            }
        }
    }
}

/// A per-syscall read timeout (the peer is momentarily quiet), not a fatal error.
fn is_read_timeout(e: &P2pNetError) -> bool {
    matches!(
        e,
        P2pNetError::Io(io_err)
            if matches!(io_err.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut)
    )
}

/// The peer closed the connection mid-read — surfaces as "failed to fill whole buffer".
fn is_eof(e: &P2pNetError) -> bool {
    matches!(
        e,
        P2pNetError::Io(io_err)
            if matches!(
                io_err.kind(),
                io::ErrorKind::UnexpectedEof
                    | io::ErrorKind::ConnectionReset
                    | io::ErrorKind::ConnectionAborted
                    | io::ErrorKind::BrokenPipe
            )
    )
}
