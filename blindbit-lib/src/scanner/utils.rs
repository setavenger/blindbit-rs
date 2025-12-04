use bitcoin::hashes::Hash;
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness, XOnlyPublicKey};

use crate::oracle_grpc::FullTxItem;

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

#[allow(dead_code)]
fn _match_short_pubkey_bytes(p_n: &[u8; 32], output_short_vector: &[u8]) -> bool {
    let outputs_short_len = output_short_vector.len();
    for i in 0..outputs_short_len / 8 {
        let output_short = &output_short_vector[i * 8..(i + 1) * 8];
        if p_n[..8] == *output_short {
            // we only need to find the first match to assert a probable match
            return true;
        }
    }

    false
}

/// Construct a dummy transaction from a FullTxItem for scanning purposes
pub fn construct_dummy_tx(item: &FullTxItem) -> Transaction {
    let mut inputs = Vec::new();
    let input_count = item.inputs.len() / 36;
    for i in 0..input_count {
        let offset = i * 36;
        let txid_bytes: [u8; 32] = item.inputs[offset..offset + 32]
            .try_into()
            .expect("input txid must be 32 bytes");
        let txid = Txid::from_byte_array(txid_bytes);

        let vout_bytes: [u8; 4] = item.inputs[offset + 32..offset + 36]
            .try_into()
            .expect("input vout must be 4 bytes");
        let vout = u32::from_le_bytes(vout_bytes);

        inputs.push(TxIn {
            previous_output: OutPoint { txid, vout },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        });
    }

    let mut outputs = Vec::new();
    for (idx, utxo) in item.utxos.iter().enumerate() {
        let pubkey = XOnlyPublicKey::from_slice(&utxo.pubkey).expect("invalid pubkey");
        let mut script = ScriptBuf::new();
        script.push_opcode(bitcoin::opcodes::all::OP_PUSHNUM_1);
        script.push_slice(pubkey.serialize());

        if idx < utxo.vout as usize {
            outputs.push(TxOut {
                value: Amount::from_sat(0),
                script_pubkey: ScriptBuf::default(),
            });
        }

        outputs.push(TxOut {
            value: Amount::from_sat(utxo.amount),
            script_pubkey: script,
        });
    }

    Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: inputs,
        output: outputs,
    }
}

/// Convert a byte array to a Txid, handling byte order reversal
pub fn byte_array_to_txid(txid: &[u8; 32]) -> Txid {
    // Ensure we have exactly 32 bytes
    let mut reversed_txid_slice = *txid;
    reversed_txid_slice.reverse();
    let txid_array: [u8; 32] = reversed_txid_slice;

    // Construct Txid directly from the byte array (preserves byte order)
    Txid::from_byte_array(txid_array)
}

