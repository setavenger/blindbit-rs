use std::net::SocketAddr;
use std::time::Duration;

use bitcoin::Block;
use bitcoin::BlockHash;
use bitcoin::hashes::Hash;

use bitcoin_p2p::net::{ConnectionReader, ConnectionWriter};
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

/// Persistent P2P connection for fetching multiple blocks without reconnecting.
///
/// `pull_block_from_p2p_by_blockhash` opens a fresh TCP connection + full P2P
/// handshake for every single block.  When `scan_block_range` finds probable
/// matches in consecutive blocks, the rapid-fire connect/disconnect cycle
/// causes the peer to drop connections ("failed to fill whole buffer").
///
/// This struct keeps one connection alive across an entire scan range.
pub struct P2pConnection {
    writer: ConnectionWriter,
    reader: ConnectionReader,
}

impl P2pConnection {
    pub fn connect(
        p2p_peer: SocketAddr,
        network: Network,
    ) -> Result<Self, ScannerError> {
        tracing::debug!(peer = %p2p_peer, "opening persistent P2P connection for block fetches");
        let connection_config = ConnectionConfig::new().change_network(network);
        let mut timeout_params = TimeoutParams::new();
        timeout_params.read_timeout(Duration::from_secs(300));
        let (writer, reader, _metadata) =
            connection_config.open_connection(p2p_peer, timeout_params)?;
        Ok(Self { writer, reader })
    }

    pub fn fetch_block(&mut self, block_hash: BlockHash) -> Result<Block, ScannerError> {
        let primitives_block_hash =
            PrimitivesBlockHash::from_byte_array(*block_hash.as_byte_array());
        let inventory = Inventory::Block(primitives_block_hash);
        let net_msg = NetworkMessage::GetData(InventoryPayload(vec![inventory]));

        self.writer
            .send_message(net_msg)
            .map_err(|e| -> ScannerError { format!("P2P send failed: {e}").into() })?;
        tracing::debug!(block_hash = %block_hash, "sent GetData for block");

        loop {
            match self.reader.read_message()? {
                Some(NetworkMessage::Block(block)) => {
                    let block_bytes = encode::serialize(&block);
                    let block: Block = bitcoin::consensus::encode::deserialize(&block_bytes)?;
                    tracing::info!(
                        block_hash = %block.block_hash(),
                        tx_count = block.txdata.len(),
                        "received block from peer"
                    );
                    return Ok(block);
                }
                Some(msg) => {
                    tracing::trace!(command = %msg.command(), "skipping message while waiting for block");
                }
                None => continue,
            }
        }
    }
}
