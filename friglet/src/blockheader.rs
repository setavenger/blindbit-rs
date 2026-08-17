use std::collections::HashMap;
use std::fs;
use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use bitcoin::BlockHash;
use bitcoin::block::Header;
use bitcoin::hashes::Hash;
use bitcoin_p2p::handshake::ConnectionConfig;
use bitcoin_p2p::net::{ConnectionExt, Error as P2pNetError, TimeoutParams};
use bitcoin_p2p::p2p_message_types::message::{InventoryPayload, NetworkMessage};
use bitcoin_p2p::p2p_message_types::message_blockdata::Inventory;
use bitcoin_rev::Network;
use bitcoin_rev::block::BlockHash as PrimitivesBlockHash;

type HeaderResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

const READ_TIMEOUT: Duration = Duration::from_secs(30);
const BLOCK_FETCH_DEADLINE: Duration = Duration::from_secs(90);

pub fn sidecar_path(state_file: impl AsRef<Path>) -> PathBuf {
    state_file.as_ref().with_extension("headers.json")
}

pub fn load_headers(path: &Path) -> HashMap<u32, String> {
    fs::read_to_string(path)
        .ok()
        .and_then(|json| serde_json::from_str(&json).ok())
        .unwrap_or_default()
}

pub fn save_headers(path: &Path, headers: &HashMap<u32, String>) -> HeaderResult<()> {
    fs::write(path, serde_json::to_vec_pretty(headers)?)?;
    Ok(())
}

pub fn block_hash_from_oracle(mut bytes: Vec<u8>) -> HeaderResult<BlockHash> {
    if bytes.len() != 32 {
        return Err(format!(
            "oracle returned {} block-hash bytes, expected 32",
            bytes.len()
        )
        .into());
    }
    bytes.reverse();
    let bytes: [u8; 32] = bytes.try_into().expect("length checked above");
    Ok(BlockHash::from_byte_array(bytes))
}

pub fn header_hex(header: &Header) -> String {
    hex::encode(bitcoin::consensus::encode::serialize(header))
}

/// Fetch a full block with `getdata` and return its genuine 80-byte header.
///
/// This mirrors blindbit-lib's proven block-fetch path. A fresh connection is
/// sufficient because historical header misses are rare and cached.
pub fn fetch_header(
    peer: SocketAddr,
    network: Network,
    expected_hash: BlockHash,
) -> HeaderResult<Header> {
    let connection_config = ConnectionConfig::new().change_network(network);
    let mut timeout_params = TimeoutParams::new();
    timeout_params.read_timeout(READ_TIMEOUT);
    let (writer, mut reader, metadata) = connection_config.open_connection(peer, timeout_params)?;

    tracing::debug!(
        peer = %peer,
        peer_height = metadata.feeler_data().reported_height,
        services = %metadata.feeler_data().services,
        block_hash = %expected_hash,
        "P2P handshake complete for block-header backfill"
    );

    let primitive_hash = PrimitivesBlockHash::from_byte_array(*expected_hash.as_byte_array());
    writer.send_message(NetworkMessage::GetData(InventoryPayload(vec![
        Inventory::Block(primitive_hash),
    ])))?;

    let started = Instant::now();
    loop {
        if started.elapsed() > BLOCK_FETCH_DEADLINE {
            return Err(format!(
                "gave up waiting for block {expected_hash} from {peer} after {:?}",
                started.elapsed()
            )
            .into());
        }

        match reader.read_message() {
            Ok(Some(NetworkMessage::Block(block))) => {
                let bytes = bitcoin_rev::consensus::encode::serialize(&block);
                let block: bitcoin::Block = bitcoin::consensus::encode::deserialize(&bytes)?;
                let actual_hash = block.header.block_hash();
                if actual_hash != expected_hash {
                    return Err(format!(
                        "peer {peer} returned block {actual_hash}, expected {expected_hash}"
                    )
                    .into());
                }
                tracing::info!(
                    peer = %peer,
                    block_hash = %actual_hash,
                    elapsed_ms = started.elapsed().as_millis() as u64,
                    "backfilled block header from P2P"
                );
                return Ok(block.header);
            }
            Ok(Some(NetworkMessage::Ping(nonce))) => {
                let _ = writer.send_message(NetworkMessage::Pong(nonce));
            }
            Ok(Some(NetworkMessage::NotFound(inv))) => {
                return Err(format!(
                    "peer {peer} replied notfound for block {expected_hash} ({} inv item(s))",
                    inv.0.len()
                )
                .into());
            }
            Ok(Some(NetworkMessage::Reject(reject))) => {
                return Err(format!(
                    "peer {peer} rejected getdata for block {expected_hash}: {reject:?}"
                )
                .into());
            }
            Ok(Some(message)) => {
                tracing::trace!(
                    peer = %peer,
                    command = %message.command(),
                    "skipping P2P message while waiting for block"
                );
            }
            Ok(None) => {}
            Err(error) if is_read_timeout(&error) => continue,
            Err(error) => {
                let reason = if is_eof(&error) {
                    "peer closed the connection"
                } else {
                    "unrecoverable read error"
                };
                return Err(format!(
                    "block fetch from {peer} failed ({reason}) while waiting for \
                     {expected_hash}: {error}"
                )
                .into());
            }
        }
    }
}

fn is_read_timeout(error: &P2pNetError) -> bool {
    matches!(
        error,
        P2pNetError::Io(io_error)
            if matches!(
                io_error.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
            )
    )
}

fn is_eof(error: &P2pNetError) -> bool {
    matches!(
        error,
        P2pNetError::Io(io_error)
            if matches!(
                io_error.kind(),
                io::ErrorKind::UnexpectedEof
                    | io::ErrorKind::ConnectionReset
                    | io::ErrorKind::ConnectionAborted
                    | io::ErrorKind::BrokenPipe
            )
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> PathBuf {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "friglet-blockheader-test-{}-{tag}-{unique}",
            std::process::id()
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn sidecar_roundtrip_and_bad_files_are_empty() {
        let dir = temp_dir("sidecar");
        let path = dir.join("scanner_state.headers.json");
        let missing = dir.join("missing.json");
        let expected = HashMap::from([(311_432, "00".repeat(80)), (311_438, "11".repeat(80))]);

        assert!(load_headers(&missing).is_empty());
        save_headers(&path, &expected).unwrap();
        assert_eq!(load_headers(&path), expected);

        fs::write(&path, b"{not-json").unwrap();
        assert!(load_headers(&path).is_empty());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn oracle_hash_bytes_are_reversed_before_construction() {
        let oracle_bytes: Vec<u8> = (0..32).collect();
        let hash = block_hash_from_oracle(oracle_bytes.clone()).unwrap();
        let mut expected = oracle_bytes;
        expected.reverse();
        assert_eq!(hex::encode(hash.to_byte_array()), hex::encode(expected));
        assert!(block_hash_from_oracle(vec![0; 31]).is_err());
    }

    #[test]
    fn sidecar_is_next_to_state_file() {
        assert_eq!(
            sidecar_path("/tmp/frigtest/scanner_state.json"),
            PathBuf::from("/tmp/frigtest/scanner_state.headers.json")
        );
    }
}
