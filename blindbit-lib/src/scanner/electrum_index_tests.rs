//! What the wallet's Electrum index holds after the live scan, and that a
//! restarted daemon rebuilds the same index from its state file.
//!
//! Sparrow reads a wallet's history from `blockchain.scripthash.get_history`
//! (each scripthash's `(tx, height)` list), `blockchain.transaction.get` (the
//! raw transactions) and the SP history of `silentpayments.subscribe`. The
//! live scan writes these per matched block; a restart rebuilds them from the
//! wallet graph. Both must agree, entry for entry.

use std::collections::{BTreeMap, BTreeSet};

use bitcoin::Transaction;

use super::Scanner;
use super::electrum_index::electrum_scripthash;
use super::reorg_tests::{Oracle, p2tr, payment, spend_of};
use super::test_support::{run, scanner};

type Histories = BTreeMap<String, Vec<(String, u32)>>;

fn id(tx: &Transaction) -> String {
    tx.compute_txid().to_string()
}

/// Every scripthash's history as `get_history` serves it, in served order.
async fn histories(scanner: &Scanner) -> Histories {
    let idx = scanner.electrum_index.lock().await;
    idx.scripthash_history
        .iter()
        .map(|(sh, entries)| {
            let entries = entries.iter().map(|e| (e.tx_hash.clone(), e.height));
            (sh.clone(), entries.collect())
        })
        .collect()
}

async fn sp_history(scanner: &Scanner) -> Vec<(String, u32)> {
    let idx = scanner.electrum_index.lock().await;
    idx.sp_history
        .iter()
        .map(|e| (e.tx_hash.clone(), e.height))
        .collect()
}

/// The txids `blockchain.transaction.get` can serve.
async fn served_txids(scanner: &Scanner) -> BTreeSet<String> {
    let idx = scanner.electrum_index.lock().await;
    idx.txs.keys().cloned().collect()
}

/// `histories` with same-height entries ordered by txid. A restore walks the
/// wallet graph in hash order, so the order of two transactions confirmed in
/// the same block is not fixed there.
fn by_height_then_txid(mut histories: Histories) -> Histories {
    for entries in histories.values_mut() {
        entries.sort_by(|a, b| (a.1, &a.0).cmp(&(b.1, &b.0)));
    }
    histories
}

/// Receives at 101, 102 and 103; the 103 output is spent in its own block,
/// the 101 output at 104. Each scripthash lists its receive and its spend at
/// their heights; the SP history lists the three payments; all five wallet
/// transactions are served, the coinbases are not.
#[test]
fn live_scan_and_restore_build_the_same_electrum_index() {
    run(async {
        let (mut scanner, _state) = scanner("electrum-index");
        let (a, a_tweak, a_out, a_key) = payment(0x51, 50_000);
        let (b, b_tweak, _, b_key) = payment(0x52, 40_000);
        let (c, c_tweak, c_out, c_key) = payment(0x53, 30_000);
        let a_spend = spend_of(a_out);
        let c_spend = spend_of(c_out);

        let mut chain = Oracle::default();
        chain.block(0xc, 101, vec![(a.clone(), Some(a_tweak))], &[]);
        chain.block(0xc, 102, vec![(b.clone(), Some(b_tweak))], &[]);
        chain.block(
            0xc,
            103,
            vec![(c.clone(), Some(c_tweak)), (c_spend.clone(), None)],
            &[c_key],
        );
        chain.block(0xc, 104, vec![(a_spend.clone(), None)], &[a_key]);
        scanner
            .scan_range_from(101, chain.tip(), chain.clone())
            .await
            .expect("chain scans");

        let sh = |key| electrum_scripthash(&p2tr(key));
        let expected: Histories = [
            (sh(a_key), vec![(id(&a), 101), (id(&a_spend), 104)]),
            (sh(b_key), vec![(id(&b), 102)]),
            (sh(c_key), vec![(id(&c), 103), (id(&c_spend), 103)]),
        ]
        .into();
        let expected_sp = vec![(id(&a), 101), (id(&b), 102), (id(&c), 103)];
        let expected_txids: BTreeSet<String> = [&a, &b, &c, &a_spend, &c_spend]
            .into_iter()
            .map(id)
            .collect();

        // The live scan writes each block's transactions in block order.
        assert_eq!(histories(&scanner).await, expected);
        assert_eq!(sp_history(&scanner).await, expected_sp);
        assert_eq!(served_txids(&scanner).await, expected_txids);

        #[cfg(feature = "serde")]
        {
            drop(scanner);
            let restarted = super::test_support::restore_from(&_state.0);
            restarted.rebuild_electrum_index_from_graph(101).await;
            assert_eq!(
                by_height_then_txid(histories(&restarted).await),
                by_height_then_txid(expected)
            );
            assert_eq!(sp_history(&restarted).await, expected_sp);
            assert_eq!(served_txids(&restarted).await, expected_txids);
        }
    });
}
