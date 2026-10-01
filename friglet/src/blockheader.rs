//! The block-header store: headers persisted next to the scanner state, and
//! the helpers to name and encode them. Headers themselves are fetched by
//! `electrum::chain` (80 bytes each over P2P `getheaders`).

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use bitcoin::BlockHash;
use bitcoin::block::Header;
use bitcoin::hashes::Hash;

type HeaderResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

pub fn sidecar_path(state_file: impl AsRef<Path>) -> PathBuf {
    state_file.as_ref().with_extension("headers.json")
}

/// Where the Electrum server keeps broadcasts that have not confirmed yet.
pub fn pending_path(state_file: impl AsRef<Path>) -> PathBuf {
    state_file.as_ref().with_extension("pending.json")
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

pub fn header_from_hex(hex: &str) -> HeaderResult<Header> {
    Ok(bitcoin::consensus::encode::deserialize(&hex::decode(hex)?)?)
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
    fn header_hex_roundtrip() {
        let genesis = bitcoin::constants::genesis_block(bitcoin::Network::Signet).header;
        let hex = header_hex(&genesis);
        assert_eq!(hex.len(), 160);
        assert_eq!(header_from_hex(&hex).unwrap(), genesis);
        assert!(header_from_hex("").is_err());
        assert!(header_from_hex(&hex[..158]).is_err());
    }

    #[test]
    fn sidecar_is_next_to_state_file() {
        assert_eq!(
            sidecar_path("/tmp/frigtest/scanner_state.json"),
            PathBuf::from("/tmp/frigtest/scanner_state.headers.json")
        );
    }
}
