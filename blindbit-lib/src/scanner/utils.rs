use bitcoin::hashes::Hash;
use bitcoin::{
    Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness, XOnlyPublicKey,
};

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

/// A stand-in `TxOut` for a vout the oracle did not serve.
///
/// Its script is empty, so `bdk_sp::receive::scan_txouts`' `is_p2tr` filter
/// skips it and it can never be mistaken for a candidate output.
fn placeholder_txout() -> TxOut {
    TxOut {
        value: Amount::from_sat(0),
        script_pubkey: ScriptBuf::default(),
    }
}

/// Construct a dummy transaction from a FullTxItem for scanning purposes
///
/// `item.utxos` is **sparse**: the oracle only serves the outputs it stored
/// (taproot, unspent, above its dust filter), and each one carries its *true*
/// `vout`. A transaction with non-silent-payment change at vout 0 and the
/// silent payment output at vout 2 therefore arrives as a single utxo with
/// `vout == 2`. Every real output has to land at its own index — the gaps are
/// filled with [`placeholder_txout`]s — because `scan_txouts` enumerates before
/// filtering, so the index in this dummy transaction becomes
/// `SpOut::outpoint.vout` (and, through it, the script and amount attributed to
/// that outpoint).
///
/// Malformed items are tolerated rather than trusted: an out-of-order `vout`
/// still lands at its own index, and a repeated `vout` keeps the first entry
/// and drops the later one with a warning. Neither panics, and neither shifts
/// an output that was already placed.
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

    let mut outputs: Vec<TxOut> = Vec::new();
    for utxo in &item.utxos {
        let pubkey = XOnlyPublicKey::from_slice(&utxo.pubkey).expect("invalid pubkey");
        let mut script = ScriptBuf::new();
        script.push_opcode(bitcoin::opcodes::all::OP_PUSHNUM_1);
        script.push_slice(pubkey.serialize());

        let vout = utxo.vout as usize;
        if vout < outputs.len() && !outputs[vout].script_pubkey.is_empty() {
            // Two served utxos claim the same vout, which the wire format
            // cannot legitimately express. Keep the first; overwriting or
            // inserting would silently misattribute an output.
            tracing::warn!(
                vout = utxo.vout,
                "oracle served a duplicate vout, keeping the first output"
            );
            continue;
        }
        // Pad the gap so that this output lands at index `utxo.vout`.
        if vout >= outputs.len() {
            outputs.resize(vout + 1, placeholder_txout());
        }
        outputs[vout] = TxOut {
            value: Amount::from_sat(utxo.amount),
            script_pubkey: script,
        };
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oracle_grpc::UtxoItemLight;
    use bitcoin::secp256k1::{Secp256k1, SecretKey};

    /// A deterministic, valid 32-byte x-only pubkey.
    fn test_pubkey(seed: u8) -> [u8; 32] {
        let mut scalar = [0u8; 32];
        scalar[31] = seed;
        SecretKey::from_slice(&scalar)
            .expect("seed is a valid non-zero scalar")
            .x_only_public_key(&Secp256k1::new())
            .0
            .serialize()
    }

    /// The `OP_1 <32-byte key>` script `construct_dummy_tx` rebuilds.
    fn taproot_script(pubkey: &[u8; 32]) -> ScriptBuf {
        let mut script = ScriptBuf::new();
        script.push_opcode(bitcoin::opcodes::all::OP_PUSHNUM_1);
        script.push_slice(*pubkey);
        script
    }

    fn utxo(vout: u32, amount: u64, pubkey: &[u8; 32]) -> UtxoItemLight {
        UtxoItemLight {
            vout,
            amount,
            pubkey: pubkey.to_vec(),
        }
    }

    /// A `FullTxItem` carrying only `utxos`; `construct_dummy_tx` reads nothing
    /// else for the output side.
    fn item(utxos: Vec<UtxoItemLight>) -> FullTxItem {
        FullTxItem {
            txid: vec![0u8; 32],
            tweak: vec![0u8; 33],
            inputs: Vec::new(),
            utxos,
        }
    }

    fn assert_placeholder(out: &TxOut, vout: usize) {
        assert_eq!(
            out.script_pubkey,
            ScriptBuf::default(),
            "vout {vout} should be a placeholder"
        );
        assert_eq!(
            out.value,
            Amount::from_sat(0),
            "vout {vout} placeholder amount"
        );
    }

    /// The oracle serves only the outputs it stored, each with its *true* vout,
    /// so gaps of more than one are the normal case (non-silent-payment change
    /// at vout 0, the silent payment output at vout 2, ...).
    #[test]
    fn construct_dummy_tx_places_sparse_vouts_at_their_true_index() {
        let key_a = test_pubkey(1);
        let key_b = test_pubkey(2);
        let tx = construct_dummy_tx(&item(vec![utxo(0, 1_000, &key_a), utxo(5, 2_000, &key_b)]));

        assert_eq!(tx.output.len(), 6, "outputs must span vout 0..=5");
        assert_eq!(tx.output[0].script_pubkey, taproot_script(&key_a));
        assert_eq!(tx.output[0].value, Amount::from_sat(1_000));
        assert_eq!(tx.output[5].script_pubkey, taproot_script(&key_b));
        assert_eq!(tx.output[5].value, Amount::from_sat(2_000));
        for vout in 1..5 {
            assert_placeholder(&tx.output[vout], vout);
        }
    }

    /// A single served utxo at a non-zero vout must still land at that vout, not
    /// one slot after a lone placeholder.
    #[test]
    fn construct_dummy_tx_pads_a_single_offset_vout() {
        let key = test_pubkey(3);
        let tx = construct_dummy_tx(&item(vec![utxo(3, 7_777, &key)]));

        assert_eq!(tx.output.len(), 4, "outputs must span vout 0..=3");
        assert_eq!(tx.output[3].script_pubkey, taproot_script(&key));
        assert_eq!(tx.output[3].value, Amount::from_sat(7_777));
        for vout in 0..3 {
            assert_placeholder(&tx.output[vout], vout);
        }
    }

    /// Several gaps in a row, interleaved: every real output keeps its own vout
    /// and no later output is shifted.
    #[test]
    fn construct_dummy_tx_keeps_every_real_output_at_its_own_vout() {
        let keys = [test_pubkey(4), test_pubkey(5), test_pubkey(6)];
        let tx = construct_dummy_tx(&item(vec![
            utxo(2, 100, &keys[0]),
            utxo(6, 200, &keys[1]),
            utxo(7, 300, &keys[2]),
        ]));

        assert_eq!(tx.output.len(), 8, "outputs must span vout 0..=7");
        for (vout, key, amount) in [
            (2usize, keys[0], 100u64),
            (6, keys[1], 200),
            (7, keys[2], 300),
        ] {
            assert_eq!(
                tx.output[vout].script_pubkey,
                taproot_script(&key),
                "script at vout {vout}"
            );
            assert_eq!(
                tx.output[vout].value,
                Amount::from_sat(amount),
                "amount at vout {vout}"
            );
        }
        for vout in [0, 1, 3, 4, 5] {
            assert_placeholder(&tx.output[vout], vout);
        }
    }

    /// Malformed items (a repeated vout) keep the first entry and drop the
    /// later one; nothing is shifted and nothing panics.
    #[test]
    fn construct_dummy_tx_ignores_a_repeated_vout() {
        let key_a = test_pubkey(7);
        let key_b = test_pubkey(8);
        let key_c = test_pubkey(9);
        let tx = construct_dummy_tx(&item(vec![
            utxo(1, 10, &key_a),
            utxo(1, 20, &key_b),
            utxo(3, 30, &key_c),
        ]));

        assert_eq!(tx.output.len(), 4, "outputs must span vout 0..=3");
        assert_eq!(tx.output[1].script_pubkey, taproot_script(&key_a));
        assert_eq!(tx.output[1].value, Amount::from_sat(10));
        assert_eq!(tx.output[3].script_pubkey, taproot_script(&key_c));
        assert_eq!(tx.output[3].value, Amount::from_sat(30));
        assert_placeholder(&tx.output[0], 0);
        assert_placeholder(&tx.output[2], 2);
    }

    /// Out-of-order items still land at their own vout rather than overwriting
    /// an already-placed output.
    #[test]
    fn construct_dummy_tx_handles_descending_vouts() {
        let key_a = test_pubkey(10);
        let key_b = test_pubkey(11);
        let tx = construct_dummy_tx(&item(vec![utxo(4, 40, &key_a), utxo(1, 10, &key_b)]));

        assert_eq!(tx.output.len(), 5, "outputs must span vout 0..=4");
        assert_eq!(tx.output[4].script_pubkey, taproot_script(&key_a));
        assert_eq!(tx.output[4].value, Amount::from_sat(40));
        assert_eq!(tx.output[1].script_pubkey, taproot_script(&key_b));
        assert_eq!(tx.output[1].value, Amount::from_sat(10));
        for vout in [0, 2, 3] {
            assert_placeholder(&tx.output[vout], vout);
        }
    }
}
