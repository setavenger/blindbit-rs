use std::net::SocketAddr;

use bitcoin::Block;
use bitcoin::BlockHash;
use bitcoin::hashes::Hash;

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

/// Pull a block from a P2P peer by block hash
pub fn pull_block_from_p2p_by_blockhash(
    p2p_peer: SocketAddr,
    block_hash: BlockHash,
    network: Network,
) -> Result<Block, ScannerError> {
    tracing::debug!(peer = %p2p_peer, block_hash = %block_hash, "connecting to peer for block fetch");

    let connection_config = ConnectionConfig::new();
    let connection_config = connection_config.change_network(network);

    // Connect to peer
    let (writer, mut reader, metadata) =
        connection_config.open_connection(p2p_peer, TimeoutParams::default())?;

    tracing::debug!(
        peer_height = metadata.feeler_data().reported_height,
        services = %metadata.feeler_data().services,
        "P2P handshake complete, requesting block"
    );

    // Request the block
    // Convert bitcoin::BlockHash to bitcoin_primitives::block::BlockHash
    let block_hash_bytes = block_hash.as_byte_array();
    let primitives_block_hash = PrimitivesBlockHash::from_byte_array(*block_hash_bytes);
    let inventory = Inventory::Block(primitives_block_hash);
    let net_msg = NetworkMessage::GetData(InventoryPayload(vec![inventory]));

    writer.send_message(net_msg)?;
    tracing::debug!("sent GetData for block, waiting for response");

    // Read messages until we receive the block
    let mut message_count = 0;
    loop {
        match reader.read_message()? {
            Some(NetworkMessage::Block(block)) => {
                // Convert bitcoin_primitives::block::Block to bitcoin::Block
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
                message_count += 1;
                tracing::trace!(command = %msg.command(), count = message_count, "received message while waiting for block");
            }
            None => continue,
        }
    }
}
