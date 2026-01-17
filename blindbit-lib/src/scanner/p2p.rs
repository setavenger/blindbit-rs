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

/// Pull a block from a P2P peer by block hash
pub fn pull_block_from_p2p_by_blockhash(
    p2p_peer: SocketAddr,
    block_hash: BlockHash,
    network: Network,
) -> Result<Block, Box<dyn std::error::Error>> {
    println!("Connecting to peer: {}", p2p_peer);
    println!("Requesting block: {block_hash}");

    let connection_config = ConnectionConfig::new();
    let connection_config = connection_config.change_network(network);

    // Connect to peer
    let (writer, mut reader, metadata) =
        connection_config.open_connection(p2p_peer, TimeoutParams::default())?;

    println!(
        "Connected! Peer height: {}, services: {}",
        metadata.feeler_data().reported_height,
        metadata.feeler_data().services
    );

    // Request the block
    // Convert bitcoin::BlockHash to bitcoin_primitives::block::BlockHash
    let block_hash_bytes = block_hash.as_byte_array();
    let primitives_block_hash = PrimitivesBlockHash::from_byte_array(*block_hash_bytes);
    let inventory = Inventory::Block(primitives_block_hash);
    let net_msg = NetworkMessage::GetData(InventoryPayload(vec![inventory]));

    writer.send_message(net_msg)?;
    println!("Sent GetData request, waiting for block...");

    // Read messages until we receive the block
    let mut message_count = 0;
    loop {
        match reader.read_message()? {
            Some(NetworkMessage::Block(block)) => {
                // Convert bitcoin_primitives::block::Block to bitcoin::Block
                let block_bytes = encode::serialize(&block);

                let block: Block = bitcoin::consensus::encode::deserialize(&block_bytes)?;
                println!("\n✓ Received block!");
                println!("  Block hash: {}", block.block_hash());
                println!("  Transactions: {:?}", block.txdata.len());
                return Ok(block);
            }
            Some(msg) => {
                message_count += 1;
                if message_count <= 5 {
                    println!("  Received: {:?} (waiting for block...)", msg.command());
                } else if message_count == 6 {
                    println!("  ... (continuing to wait for block)");
                }
            }
            None => continue,
        }
    }
}
