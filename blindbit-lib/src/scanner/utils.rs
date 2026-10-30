use bitcoin::hashes::Hash;
use bitcoin::{Txid, XOnlyPublicKey};

/// Match a short pubkey against a vector of short pubkeys
pub fn match_short_pubkey(p_n: &XOnlyPublicKey, output_short_vector: &[u8]) -> bool {
    let seralised_p_n = p_n.serialize();

    let outputs_short_len = output_short_vector.len();
    for i in 0..outputs_short_len / 8 {
        let output_short = &output_short_vector[i * 8..(i + 1) * 8];
        if seralised_p_n[..8] == *output_short {
            // we only need to find the first match to assert a probable match
            return true;
        }
    }

    false
}

/// The `Txid` of a txid the oracle serves in display order (reversed).
pub fn byte_array_to_txid(txid: &[u8; 32]) -> Txid {
    let mut bytes = *txid;
    bytes.reverse();
    Txid::from_byte_array(bytes)
}
