use crate::oracle_grpc::BlockIdentifier;
use bitcoin::absolute::Height;
use bitcoin::secp256k1::PublicKey;
use bitcoin::{Amount, OutPoint, ScriptBuf, Txid, XOnlyPublicKey};
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
    pub outpoint: OutPoint,
    pub blockheight: Height,
    pub tweak: [u8; 32], // scalar in big endian format
    pub amount: Amount,
    pub script: ScriptBuf,
    pub label: Option<Label>,
    pub spent: Option<bool>,
}

/// One wallet-owned Silent Payments output, as the scanner records and
/// persists it (the `owned_outputs` array of the state file).
///
/// A record is created when the indexer confirms an output as ours (full
/// BIP-352 match in a fetched block) and is marked spent only when a
/// confirmed transaction in the wallet graph spends exactly this `outpoint`.
/// The oracle's 8-byte `spent_outputs` prefixes are used solely as a trigger to
/// fetch the block; they never mark a record on their own.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct OwnedOutputRecord {
    /// The output itself (`txid:vout`).
    pub outpoint: OutPoint,
    /// Full x-only taproot output key (the key the oracle's spent-output
    /// prefixes are taken from).
    pub pubkey: XOnlyPublicKey,
    /// Output value in satoshis.
    pub amount_sat: u64,
    /// Height of the block that confirmed the output.
    pub height: u32,
    /// BIP-352 label `m` the output matched; `None` for the unlabelled
    /// address, `Some(0)` for change.
    pub label: Option<u32>,
    /// Confirmed transaction that spends this output, if any.
    pub spent_by: Option<Txid>,
    /// Height of the block that confirmed `spent_by`.
    pub spent_height: Option<u32>,
}

impl OwnedOutputRecord {
    /// The 8-byte prefix the oracle serves for a spent taproot output.
    pub fn short_pubkey(&self) -> [u8; 8] {
        let mut prefix = [0u8; 8];
        prefix.copy_from_slice(&self.pubkey.serialize()[..8]);
        prefix
    }

    pub fn is_spent(&self) -> bool {
        self.spent_by.is_some()
    }
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
