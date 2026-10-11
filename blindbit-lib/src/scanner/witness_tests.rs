//! Wallet transactions keep their witness data from the P2P fetch to what
//! the Electrum server hands Sparrow, across restarts; transactions stored
//! without it (before witness blocks were requested) get it back.

use bdk_sp::bitcoin::key::Secp256k1;
use bdk_sp::receive::get_silentpayment_pubkey;
use bitcoin::absolute::LockTime;
use bitcoin::block::{Header, Version as BlockVersion};
use bitcoin::consensus::encode::{deserialize, serialize};
use bitcoin::hashes::Hash;
use bitcoin::key::TweakedPublicKey;
use bitcoin::transaction::Version;
use bitcoin::{
    Amount, Block, BlockHash, CompactTarget, OutPoint, ScriptBuf, Sequence, Transaction, TxIn,
    TxMerkleNode, TxOut, Txid, Witness,
};
use bitcoin_rev::Network;

use super::p2p::{BlockFetcher, FetchFailure};
use super::p2p_tests::{Conn, Node, OneBlock, fast, stripped};
use super::scanner::Scanner;
use super::stream_safety_tests::{serve, unserve};
use super::test_support::{keys, run, scanner, secret};
use super::witness::lacks_witness;
use crate::oracle_grpc::{BlockIdentifier, BlockScanDataShortResponse, ComputeIndexTxItem};

/// A block at height 1 with a valid witness commitment, holding a taproot
/// key-path spend that pays the test wallet; that payment; and the oracle
/// message describing the block. `seed` keeps the blocks of different tests
/// apart.
fn taproot_payment_block(seed: u8) -> (Block, Transaction, BlockScanDataShortResponse) {
    let (scan_sk, spend_pk) = keys();
    let tweak = secret(seed).public_key(&Secp256k1::new());
    let shared = bdk_sp::compute_shared_secret(&scan_sk, &tweak);
    let output_key = get_silentpayment_pubkey(&spend_pk, &shared, 0, None)
        .x_only_public_key()
        .0;
    let payment = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array([seed; 32]),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            // A key-path spend: one 64-byte Schnorr signature.
            witness: Witness::from_slice(&[[seed; 64]]),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: ScriptBuf::new_p2tr_tweaked(TweakedPublicKey::dangerous_assume_tweaked(
                output_key,
            )),
        }],
    };
    let reserved = [0u8; 32];
    let mut coinbase = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::from_bytes(vec![0x51, seed]),
            sequence: Sequence::MAX,
            witness: Witness::from_slice(&[reserved]),
        }],
        output: vec![],
    };
    let mut block = Block {
        header: Header {
            version: BlockVersion::ONE,
            prev_blockhash: BlockHash::all_zeros(),
            merkle_root: TxMerkleNode::all_zeros(),
            time: u32::from(seed),
            bits: CompactTarget::from_consensus(0x207f_ffff),
            nonce: 0,
        },
        txdata: vec![coinbase.clone(), payment.clone()],
    };
    // The coinbase's own wtxid counts as zero, so the commitment can be
    // computed before it is added.
    let witness_root = block.witness_root().expect("has transactions");
    let commitment = Block::compute_witness_commitment(&witness_root, &reserved);
    let mut script = vec![0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
    script.extend_from_slice(commitment.as_byte_array());
    coinbase.output.push(TxOut {
        value: Amount::ZERO,
        script_pubkey: ScriptBuf::from_bytes(script),
    });
    block.txdata[0] = coinbase;
    block.header.merkle_root = block.compute_merkle_root().expect("has transactions");
    assert!(block.check_merkle_root() && block.check_witness_commitment());

    // The oracle serves hashes and txids in display order.
    let mut block_hash = block.block_hash().to_byte_array();
    block_hash.reverse();
    let mut txid = payment.compute_txid().to_byte_array();
    txid.reverse();
    let message = BlockScanDataShortResponse {
        block_identifier: Some(BlockIdentifier {
            block_hash: block_hash.to_vec(),
            block_height: 1,
        }),
        comp_index: vec![ComputeIndexTxItem {
            txid: txid.to_vec(),
            tweak: tweak.serialize().to_vec(),
            outputs_short: output_key.serialize()[..8].to_vec(),
        }],
        spent_outputs: vec![],
    };
    (block, payment, message)
}

/// The raw transaction `blockchain.transaction.get` would serve for `txid`.
async fn served_raw(scanner: &Scanner, txid: Txid) -> Option<Vec<u8>> {
    scanner
        .electrum_index
        .lock()
        .await
        .txs
        .get(&txid.to_string())
        .cloned()
}

/// The wallet as a restarted daemon has it: loaded from its state file, its
/// Electrum index rebuilt from the graph.
#[cfg(feature = "serde")]
async fn restart(path: &std::path::Path) -> Scanner {
    let restarted = super::test_support::restore_from(path);
    restarted.rebuild_electrum_index_from_graph(1).await;
    restarted
}

#[test]
fn a_block_stripped_of_its_witnesses_is_refused_and_fetched_again() {
    let (block, _, _) = taproot_payment_block(0x92);
    let node = Node::serving(&block, vec![Conn::ServeStripped, Conn::Serve]);
    let got = run(BlockFetcher::new(node.addr, Network::Regtest)
        .with_policy(fast(3))
        .fetch(block.block_hash(), 1))
    .expect("the second connection serves it whole");
    assert_eq!(got, block);
    assert_eq!(node.connections(), 2);

    let node = Node::serving(&block, vec![Conn::ServeStripped; 2]);
    let err = run(BlockFetcher::new(node.addr, Network::Regtest)
        .with_policy(fast(2))
        .fetch(block.block_hash(), 1))
    .expect_err("never whole");
    assert_eq!(err.failure, FetchFailure::WitnessStripped);
    assert!(
        err.to_string()
            .contains("the node sent the block without its witness data (all 2 tries)"),
        "{err}"
    );
}

#[test]
fn a_served_taproot_tx_round_trips_with_its_witness() {
    run(async {
        let (block, payment, message) = taproot_payment_block(0x93);
        let txid = payment.compute_txid();
        let node = Node::serving(&block, vec![Conn::Serve]);
        let (mut scanner, _state) = scanner("witness-roundtrip");
        scanner.p2p_peer = node.addr;
        scanner.p2p_retry = fast(1);

        assert!(!scanner.watch_step(1, OneBlock(message)).await);
        assert_eq!(scanner.scan_health().await.stall, None);
        assert_eq!(node.connections(), 1, "fetched over P2P");

        let raw = served_raw(&scanner, txid).await.expect("wallet tx served");
        assert_eq!(raw, serialize(&payment));
        let served: Transaction = deserialize(&raw).unwrap();
        assert_eq!(served.compute_txid(), txid);
        assert_eq!(served.compute_wtxid(), payment.compute_wtxid());
        assert_ne!(served.compute_wtxid().to_byte_array(), txid.to_byte_array());

        #[cfg(feature = "serde")]
        {
            let restarted = restart(&_state.0).await;
            assert_eq!(
                served_raw(&restarted, txid).await,
                Some(serialize(&payment))
            );
        }
    });
}

#[test]
fn wallet_txs_stored_without_witnesses_get_them_back() {
    run(async {
        let (block, payment, message) = taproot_payment_block(0x94);
        let txid = payment.compute_txid();
        let without = stripped(&block);
        assert_eq!(without.block_hash(), block.block_hash());

        // Scanned before friglet asked for witness blocks.
        serve(&without);
        let (mut scanner, _state) = scanner("witness-restore");
        assert!(!scanner.watch_step(1, OneBlock(message)).await);
        unserve(&block.block_hash());
        let stored = scanner
            .internal_indexer
            .graph()
            .get_tx(txid)
            .expect("wallet tx");
        assert!(lacks_witness(&stored));
        assert_eq!(
            served_raw(&scanner, txid).await,
            Some(serialize(&without.txdata[1]))
        );

        // No node to fetch from: tried again in 5 minutes, not every poll.
        scanner.p2p_retry = fast(1);
        scanner.restore_missing_witnesses_when_due().await;
        let due = scanner.witness_restore_due.expect("still to do");
        assert!(due > std::time::Instant::now() + std::time::Duration::from_secs(4 * 60));

        let node = Node::serving(&block, vec![Conn::Serve]);
        scanner.p2p_peer = node.addr;
        assert!(scanner.restore_missing_witnesses().await);
        assert_eq!(node.connections(), 1);
        let restored = scanner.internal_indexer.graph().get_tx(txid).unwrap();
        assert_eq!(restored.compute_wtxid(), payment.compute_wtxid());
        assert_eq!(served_raw(&scanner, txid).await, Some(serialize(&payment)));
        let saved: Vec<_> = scanner
            .stage
            .indexer
            .graph
            .txs
            .iter()
            .filter(|tx| tx.compute_txid() == txid)
            .collect();
        assert_eq!(saved.len(), 1, "the state keeps one copy");
        assert!(!lacks_witness(saved[0]));

        // Nothing left to restore: no further fetch.
        assert!(scanner.restore_missing_witnesses().await);
        assert_eq!(node.connections(), 1);

        #[cfg(feature = "serde")]
        {
            let restarted = restart(&_state.0).await;
            assert_eq!(
                served_raw(&restarted, txid).await,
                Some(serialize(&payment))
            );
        }
    });
}

/// A stop during the download that restores witness data ends it at once
/// and changes nothing, and the restore is not put off for 5 minutes: it
/// runs again as soon as scanning resumes.
#[test]
fn a_stop_during_a_witness_restore_retries_it_when_scanning_resumes() {
    run(async {
        let (block, payment, message) = taproot_payment_block(0x96);
        let txid = payment.compute_txid();
        serve(&stripped(&block));
        let (mut scanner, _state) = scanner("witness-restore-stop");
        assert!(!scanner.watch_step(1, OneBlock(message)).await);
        unserve(&block.block_hash());
        let node = Node::serving(&block, vec![Conn::StallMidBlock, Conn::Serve]);
        scanner.p2p_peer = node.addr;
        let due = scanner.witness_restore_due.expect("due");

        let cancel = tokio_util::sync::CancellationToken::new();
        scanner.cancel = cancel.clone();
        let stop = async {
            while node.stalled().is_none() {
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
            cancel.cancel();
            std::time::Instant::now()
        };
        let ((), stopped) = tokio::join!(scanner.restore_missing_witnesses_when_due(), stop);
        assert!(stopped.elapsed() < std::time::Duration::from_secs(1));
        assert_eq!(scanner.witness_restore_due, Some(due), "not put off");
        assert!(lacks_witness(
            &scanner.internal_indexer.graph().get_tx(txid).unwrap()
        ));

        scanner.cancel = tokio_util::sync::CancellationToken::new();
        scanner.restore_missing_witnesses_when_due().await;
        assert_eq!(scanner.witness_restore_due, None, "done");
        assert!(!lacks_witness(
            &scanner.internal_indexer.graph().get_tx(txid).unwrap()
        ));
        assert_eq!(node.connections(), 2);
    });
}

#[test]
fn only_transactions_that_need_a_witness_count_as_missing_one() {
    let (block, payment, _) = taproot_payment_block(0x95);
    let without = stripped(&block);
    assert!(!lacks_witness(&payment));
    assert!(lacks_witness(&without.txdata[1]), "taproot spend");
    assert!(!lacks_witness(&without.txdata[0]), "coinbase");

    let mut wrapped = without.txdata[1].clone();
    // P2SH-P2WPKH: the scriptSig only pushes the witness program.
    wrapped.input[0].script_sig =
        ScriptBuf::from_bytes([&[0x16, 0x00, 0x14][..], &[7; 20]].concat());
    assert!(lacks_witness(&wrapped), "P2SH-wrapped segwit spend");

    let mut legacy = without.txdata[1].clone();
    // P2PKH: signature and public key in the scriptSig.
    legacy.input[0].script_sig =
        ScriptBuf::from_bytes([&[0x47][..], &[1; 71], &[0x21], &[2; 33]].concat());
    assert!(!lacks_witness(&legacy), "legacy spend");
}
