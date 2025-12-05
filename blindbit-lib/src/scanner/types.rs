use crate::oracle_grpc::BlockIdentifier;
use bitcoin::absolute::Height;
use bitcoin::secp256k1::PublicKey;
use bitcoin::{Amount, ScriptBuf};
use indexer::v2::indexes::Label;

/// Wrapper for `BlockIdentifier` that implements Display with hex formatting
pub struct BlockIdentifierDisplay<'a>(pub &'a BlockIdentifier);

impl std::fmt::Display for BlockIdentifierDisplay<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "BlockIdentifier {{ block_hash: {}, block_height: {} }}",
            hex::encode(&self.0.block_hash),
            self.0.block_height
        )
    }
}

impl std::fmt::Debug for BlockIdentifierDisplay<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "BlockIdentifier {{ block_hash: {}, block_height: {} }}",
            hex::encode(&self.0.block_hash),
            self.0.block_height
        )
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct OwnedOutput {
    pub blockheight: Height,
    pub tweak: [u8; 32], // scalar in big endian format
    pub amount: Amount,
    pub script: ScriptBuf,
    pub label: Option<Label>,
    pub spent: Option<bool>,
}

/// `ProbableMatch` is a struct that contains a list of txids that are probable matches
/// and a boolean indicating if a utxo might be spent
pub(crate) struct ProbableMatch {
    /// txids is a tuple of txid and tweak
    pub matched_txs: Vec<([u8; 32], PublicKey)>,
    pub spent: bool,
}

impl ProbableMatch {
    pub fn new(matched_txs: Vec<([u8; 32], PublicKey)>, spent: bool) -> Self {
        Self { matched_txs, spent }
    }
}
