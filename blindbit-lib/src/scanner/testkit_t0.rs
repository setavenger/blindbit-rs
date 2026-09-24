//! T0 (in-process library tier) of the blindbit-testkit scenarios, run through
//! blindbit-lib's live receive path.
//!
//! The testkit runs each scenario at T0 in Go: it builds and signs the
//! transactions with its own vector-gated BIP-352 sender, one per block, and
//! exports them with the scenario's expected found-set as a JSON fixture. This
//! module replays those chains, in-process, through exactly the per-block steps
//! `Scanner::scan_block_range` takes, with only the gRPC stream and the P2P
//! block fetch replaced:
//!
//! 1. an in-process oracle derives, from the transactions and their prevouts
//!    alone, what blindbit-oracle serves per block (`BlockScanDataShortResponse`):
//!    the tweak `input_hash * A` of every transaction with a taproot output, the
//!    8-byte prefixes of its taproot output keys, and the 8-byte prefixes of every
//!    taproot output the block spends;
//! 2. [`Scanner::scan_short_block_data`] decides from that short data whether the
//!    block is worth fetching (`scan_transaction_short` / `match_short_pubkey`,
//!    plus the spent-output check);
//! 3. only then does the full block go through [`Scanner::apply_matched_block`],
//!    i.e. `apply_block_relevant` on the external indexer, and become a
//!    checkpoint.
//!
//! Each wallet's found-set is then read from the scanner's indexer, as the
//! balance reads it, and judged against the fixture's answer key: every
//! `must_find` output present with the constructed amount, label and spent
//! status, nothing else reported.
//!
//! No sender is reimplemented here and no scanner output goes into the answer
//! key: it is built by the testkit from the scenario's own declarations. The Go
//! index's tweak is carried in the fixture only as a cross-check; the tweak served
//! here is computed in Rust (`bdk_sp::receive::compute_tweak_data`) and must agree
//! with it.
//!
//! # Fixture provenance
//!
//! * source repo: `setavenger/blindbit-testkit`, commit `b1f962e` (testkit PR #25,
//!   which adds the `export-fixture` command; SNB-517)
//! * command (from the testkit checkout):
//!
//!   ```text
//!   go run ./cmd/testkit export-fixture \
//!     -out-dir <blindbit-rs>/blindbit-lib/tests/data/testkit-t0 \
//!     -scenario scenarios/plain-payment.toml -scenario scenarios/labelled-multi.toml \
//!     -scenario scenarios/k-gap.toml -scenario scenarios/label-parity.toml \
//!     -scenario scenarios/k-counter.toml -scenario scenarios/spent-outputs.toml \
//!     -scenario scenarios/input-types.toml -scenario scenarios/rescan.toml \
//!     -scenario scenarios/dust-boundary.toml
//!   ```
//!
//! * configuration: `full-basic` (the only one T0 executes: nothing is filtered)
//!
//! Export is deterministic, so regenerating from the same scenario files yields
//! the same bytes. The files are never hand-edited; after regenerating, update
//! the digests in [`FIXTURES`] (they must also match `SHA256SUMS`).

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::OnceLock;

use bdk_sp::receive::compute_tweak_data;
use bitcoin::hashes::{Hash, sha256};
use bitcoin::secp256k1::{PublicKey, SecretKey};
use bitcoin::{
    Amount, Block, BlockHash, CompactTarget, OutPoint, ScriptBuf, Sequence, Transaction, TxIn,
    TxMerkleNode, TxOut, Witness, absolute::LockTime, transaction::Version,
};
use bitcoin_rev::Network;
use serde::Deserialize;
use tonic::transport::Channel;

use crate::oracle_grpc::{BlockIdentifier, BlockScanDataShortResponse, ComputeIndexTxItem};

use super::Scanner;

// ---------------------------------------------------------------------------
// Pinned fixtures
// ---------------------------------------------------------------------------

struct Pinned {
    name: &'static str,
    json: &'static str,
    sha256: &'static str,
}

macro_rules! pinned {
    ($name:literal, $sha:literal) => {
        Pinned {
            name: $name,
            json: include_str!(concat!("../../tests/data/testkit-t0/", $name, ".json")),
            sha256: $sha,
        }
    };
}

const FIXTURES: &[Pinned] = &[
    pinned!(
        "dust-boundary",
        "aee7474e6630db357c684fb1939a3bfb766ea8374c25a6929eb41bca7f047317"
    ),
    pinned!(
        "input-types",
        "f05e208f1744e010b39535d2f57c6b24baa5ff61bf09e3c3dbb29cb7ad61ae27"
    ),
    pinned!(
        "k-counter",
        "26f5cd4e133772c784fda3d2eb8d770f9188df8ddf5b9a898d7f185ab8590607"
    ),
    pinned!(
        "k-gap",
        "edab11ba48c7369b4474d05ca083a95d1def072bd3781924a921ceb0b1e17f20"
    ),
    pinned!(
        "label-parity",
        "628ced10358a1c6264f69fa7077c7d8216a611b84baf1aa7f2b4f3ca6fa544e3"
    ),
    pinned!(
        "labelled-multi",
        "84482dec262a7299283af8fdebf3a384bfd70ca67d1022356eebd1cb05037c23"
    ),
    pinned!(
        "plain-payment",
        "8536153126e5373d80491bfd67740325d07ab13b9557da6c0dea101bb6bada30"
    ),
    pinned!(
        "rescan",
        "a5a5142ff831c12749aa360fcfc7bd9c52135a3ad43d0179745aedb1e8acc397"
    ),
    pinned!(
        "spent-outputs",
        "3061aa193d4468e9f30a1b985b034a1fb54af2cef0f168a1535bd090b870e545"
    ),
];

const MANIFEST: &str = include_str!("../../tests/data/testkit-t0/SHA256SUMS");

const FIXTURE_FORMAT: &str = "blindbit-testkit/t0-fixture/1";

/// Outputs whose spent status the live receive path on this branch cannot see
/// yet, and why. Each entry is asserted to still fail in exactly that way, so a
/// fix turns this test red until the entry is removed.
///
/// `Scanner::owned_outputs` is the set `scan_short_block_data` matches the
/// oracle's spent-output prefixes against, and nothing writes it
/// (`add_owned_output` has no caller). A block whose only relevance to the wallet
/// is a spend is therefore never fetched, the spending transaction never reaches
/// the wallet graph, and the output stays unspent in the balance. Outputs listed
/// here are spent by a transaction that pays the wallet nothing, which is every
/// spend the scenarios make.
///
/// The fix is blindbit-rs PR #19 (record owned outputs so spends are detected).
/// With it, `process_block` must also call `scanner.sync_owned_outputs()` after
/// `apply_matched_block`, as `scan_block_range` then does; with that one line
/// added this list must become empty, and every scenario here passes (checked
/// against #19 when this module was written).
const KNOWN_SPEND_GAP: &[(&str, &str)] = &[
    ("dust-boundary", "cut-at-k1"),
    ("dust-boundary", "spent-above"),
    ("k-gap", "spent-k0"),
    ("labelled-multi", "labelled-bob"),
    ("rescan", "paid-then-spent"),
    ("spent-outputs", "spent-alone"),
    ("spent-outputs", "spent-labelled"),
    ("spent-outputs", "spent-pair-k0"),
    ("spent-outputs", "spent-pair-k1"),
];

fn fixture_sha256(bytes: &[u8]) -> String {
    hex::encode(sha256::Hash::hash(bytes).to_byte_array())
}

/// The embedded fixture named `name`, digest-checked and parsed.
fn fixture(name: &str) -> Fixture {
    let pinned = FIXTURES
        .iter()
        .find(|pinned| pinned.name == name)
        .unwrap_or_else(|| panic!("no pinned testkit fixture {name}"));
    assert_eq!(
        fixture_sha256(pinned.json.as_bytes()),
        pinned.sha256,
        "{name}.json is not the pinned testkit export"
    );
    let fixture: Fixture = serde_json::from_str(pinned.json)
        .unwrap_or_else(|e| panic!("{name}.json does not match the modelled schema: {e}"));
    assert_eq!(fixture.format, FIXTURE_FORMAT, "{name}: fixture format");
    assert_eq!(fixture.scenario, name, "{name}: scenario name");
    assert_eq!(fixture.configuration, "full-basic", "{name}: configuration");
    assert_eq!(fixture.network, "regtest", "{name}: network");
    assert!(!fixture.expected.is_empty(), "{name}: empty answer key");
    fixture
}

// ---------------------------------------------------------------------------
// Fixture schema (complete, strict)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Fixture {
    format: String,
    scenario: String,
    #[allow(dead_code)]
    scenario_sha256: String,
    configuration: String,
    network: String,
    wallets: Vec<FixtureWallet>,
    actions: Vec<FixtureAction>,
    blocks: Vec<FixtureBlock>,
    expected: Vec<ExpectedOutput>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureWallet {
    id: String,
    scan_secret: String,
    spend_pubkey: String,
    labels: Vec<u32>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureAction {
    index: usize,
    kind: String,
    #[serde(default)]
    component: Option<String>,
    blocks: Vec<u32>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureBlock {
    height: u32,
    txs: Vec<FixtureTx>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureTx {
    txid: String,
    hex: String,
    prevouts: Vec<FixturePrevout>,
    go_tweak: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FixturePrevout {
    outpoint: String,
    value_sats: u64,
    script_pubkey: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExpectedOutput {
    #[serde(rename = "ref")]
    reference: String,
    wallet: String,
    outpoint: String,
    amount_sats: u64,
    label: Option<u32>,
    spent: bool,
    outcome: String,
}

// ---------------------------------------------------------------------------
// The chain and the in-process oracle
// ---------------------------------------------------------------------------

struct ChainBlock {
    height: u32,
    block: Block,
    short: BlockScanDataShortResponse,
}

/// Parses the fixture's blocks into full blocks plus the short data an oracle
/// serves for them.
fn build_chain(fixture: &Fixture) -> Vec<ChainBlock> {
    let mut prev_blockhash = BlockHash::all_zeros();
    let mut chain = Vec::with_capacity(fixture.blocks.len());
    for (index, fixture_block) in fixture.blocks.iter().enumerate() {
        let height = fixture_block.height;
        assert_eq!(height as usize, index + 1, "blocks are numbered from 1");

        let mut txs = Vec::new();
        for ftx in &fixture_block.txs {
            let raw = hex::decode(&ftx.hex).expect("tx hex");
            let tx: Transaction = bitcoin::consensus::deserialize(&raw).expect("tx decodes");
            assert_eq!(tx.compute_txid().to_string(), ftx.txid, "fixture txid");
            let prevouts: Vec<TxOut> = ftx
                .prevouts
                .iter()
                .map(|prevout| TxOut {
                    value: Amount::from_sat(prevout.value_sats),
                    script_pubkey: ScriptBuf::from_bytes(
                        hex::decode(&prevout.script_pubkey).expect("prevout script hex"),
                    ),
                })
                .collect();
            if tx.is_coinbase() {
                assert!(prevouts.is_empty(), "{}: coinbase with prevouts", ftx.txid);
            } else {
                assert_eq!(
                    prevouts.len(),
                    tx.input.len(),
                    "{}: one prevout per input",
                    ftx.txid
                );
                for (input, prevout) in tx.input.iter().zip(&ftx.prevouts) {
                    assert_eq!(input.previous_output.to_string(), prevout.outpoint);
                }
            }
            txs.push((tx, prevouts, ftx.go_tweak.clone()));
        }

        let short = oracle_short_data(height, &txs);
        let block = assemble_block(height, prev_blockhash, txs.into_iter().map(|(tx, _, _)| tx));
        prev_blockhash = block.block_hash();
        let mut short = short;
        let mut hash = block.block_hash().to_byte_array();
        hash.reverse();
        short.block_identifier = Some(BlockIdentifier {
            block_hash: hash.to_vec(),
            block_height: u64::from(height),
        });
        chain.push(ChainBlock {
            height,
            block,
            short,
        });
    }
    chain
}

/// What blindbit-oracle serves for one block, derived from the transactions and
/// their prevouts alone:
///
/// * one `ComputeIndexTxItem` per non-coinbase transaction with at least one
///   taproot output and a tweak: its txid in display order, the 33-byte tweak
///   `input_hash * A`, and the 8-byte x-only prefix of every taproot output in
///   vout order; items in internal-order txid order, as the oracle sorts them;
/// * `spent_outputs`: the 8-byte x-only prefix of every taproot output any
///   transaction of the block spends.
///
/// The tweak is computed here and must equal the one the testkit's Go index
/// computed for the same transaction (`go_tweak`), including agreeing on which
/// transactions have none.
fn oracle_short_data(
    height: u32,
    txs: &[(Transaction, Vec<TxOut>, Option<String>)],
) -> BlockScanDataShortResponse {
    let mut items = Vec::new();
    let mut spent_outputs = Vec::new();
    for (tx, prevouts, go_tweak) in txs {
        let txid = tx.compute_txid();
        if tx.is_coinbase() {
            assert!(
                go_tweak.is_none(),
                "{txid}: the Go index tweaked a coinbase"
            );
            continue;
        }
        for prevout in prevouts {
            if prevout.script_pubkey.is_p2tr() {
                spent_outputs.extend_from_slice(&prevout.script_pubkey.as_bytes()[2..10]);
            }
        }

        let taproot: Vec<&TxOut> = tx
            .output
            .iter()
            .filter(|o| o.script_pubkey.is_p2tr())
            .collect();
        let tweak = if taproot.is_empty() {
            None
        } else {
            compute_tweak_data(tx, prevouts).ok()
        };
        assert_eq!(
            tweak.map(|t| hex::encode(t.serialize())),
            *go_tweak,
            "block {height} tx {txid}: the Rust tweak disagrees with the testkit's Go index"
        );
        let Some(tweak) = tweak else { continue };

        let mut display = txid.to_byte_array();
        display.reverse();
        items.push(ComputeIndexTxItem {
            txid: display.to_vec(),
            tweak: tweak.serialize().to_vec(),
            outputs_short: taproot
                .iter()
                .flat_map(|o| o.script_pubkey.as_bytes()[2..10].to_vec())
                .collect(),
        });
    }
    items.sort_by(|a, b| {
        let (mut a, mut b) = (a.txid.clone(), b.txid.clone());
        a.reverse();
        b.reverse();
        a.cmp(&b)
    });
    BlockScanDataShortResponse {
        block_identifier: None,
        comp_index: items,
        spent_outputs,
    }
}

/// A block holding `txs`. A coinbase-shaped transaction (the testkit's funding)
/// is the block's coinbase; any other block gets a synthetic coinbase first,
/// because `apply_block_relevant` skips position 0 as the coinbase.
fn assemble_block(
    height: u32,
    prev_blockhash: BlockHash,
    txs: impl Iterator<Item = Transaction>,
) -> Block {
    let mut txdata: Vec<Transaction> = txs.collect();
    if !txdata.first().is_some_and(Transaction::is_coinbase) {
        txdata.insert(
            0,
            Transaction {
                version: Version::TWO,
                lock_time: LockTime::ZERO,
                input: vec![TxIn {
                    previous_output: OutPoint::null(),
                    script_sig: ScriptBuf::from_bytes(height.to_le_bytes().to_vec()),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                }],
                output: vec![TxOut {
                    value: Amount::ZERO,
                    script_pubkey: ScriptBuf::from_bytes(vec![0x6a]),
                }],
            },
        );
    }
    assert!(
        txdata.iter().skip(1).all(|tx| !tx.is_coinbase()),
        "block {height}: more than one coinbase"
    );
    let mut block = Block {
        header: bitcoin::block::Header {
            version: bitcoin::block::Version::TWO,
            prev_blockhash,
            merkle_root: TxMerkleNode::all_zeros(),
            time: 1_700_000_000 + height,
            bits: CompactTarget::from_consensus(0x207f_ffff),
            nonce: height,
        },
        txdata,
    };
    block.header.merkle_root = block.compute_merkle_root().expect("non-empty block");
    block
}

// ---------------------------------------------------------------------------
// The client
// ---------------------------------------------------------------------------

/// See `bip352_vectors::oracle_client`: the lazy channel needs a runtime in
/// scope to be built, and is never connected.
fn oracle_client() -> crate::OracleServiceClient<Channel> {
    static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    let runtime = RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime for the lazy tonic channel")
    });
    let _guard = runtime.enter();
    crate::OracleServiceClient::new(Channel::from_static("http://[::1]:50051").connect_lazy())
}

/// A wallet's scanner, configured as a user would: scan secret, spend public
/// key, and a label range covering every label the wallet publishes (`Scanner`
/// always adds the change label `m = 0`).
fn wallet_scanner(fixture: &Fixture, wallet: &FixtureWallet) -> Scanner {
    let scan_sk = SecretKey::from_str(&wallet.scan_secret).expect("scan secret");
    let spend_pk = PublicKey::from_str(&wallet.spend_pubkey).expect("spend pubkey");
    let max_label = wallet.labels.iter().copied().max().unwrap_or(0);
    let socket: SocketAddr = "127.0.0.1:18444".parse().expect("socket address");
    let state_file: PathBuf = std::env::temp_dir().join(format!(
        "blindbit-testkit-t0-{}-{}-{}.json",
        fixture.scenario,
        wallet.id,
        std::process::id()
    ));
    Scanner::new(
        oracle_client(),
        socket,
        scan_sk,
        spend_pk,
        max_label,
        state_file,
        Network::Regtest,
    )
}

/// One block of `Scanner::scan_block_range`, minus the gRPC stream and the P2P
/// fetch: the short data decides whether the block is fetched, and only a
/// fetched block reaches the indexer and becomes a checkpoint.
///
/// Keep this in step with `scan_block_range`. It calls the same functions in the
/// same order; a step added there after `apply_matched_block` (for example
/// recording owned outputs) must be added here too, or this harness stops
/// exercising it.
fn process_block(scanner: &mut Scanner, block: &ChainBlock) {
    let probable_match = scanner
        .scan_short_block_data(block.short.clone())
        .unwrap_or_else(|e| panic!("block {}: short scan failed: {e:?}", block.height));
    if let Some(probable_match) = probable_match {
        scanner.apply_matched_block(&block.block, &probable_match, block.height);
        let hash = block.block.block_hash();
        scanner.block_checkpoints.insert(block.height, hash);
        scanner.stage.block_checkpoints.insert(block.height, hash);
    }
    scanner.last_scanned_block_height = u64::from(block.height);
    scanner.stage.last_scanned_block_height = u64::from(block.height);
}

/// One output as the wallet reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Found {
    amount_sats: Option<u64>,
    labels: Vec<Option<u32>>,
    spent: bool,
}

/// The wallet's found-set, read from the indexer the way the balance reads it:
/// the outpoints the indexer matched (`by_shared_secret`), their value in the
/// wallet graph, the label they matched (`by_label`), and whether a transaction
/// in the wallet graph spends them.
fn observe(scanner: &Scanner) -> BTreeMap<OutPoint, Found> {
    let index = scanner.internal_indexer.index();
    let graph = scanner.internal_indexer.graph();
    let spent: Vec<OutPoint> = graph
        .full_txs()
        .flat_map(|node| {
            node.tx
                .input
                .iter()
                .map(|input| input.previous_output)
                .collect::<Vec<_>>()
        })
        .collect();
    index
        .by_shared_secret
        .keys()
        .map(|outpoint| {
            let mut labels: Vec<Option<u32>> = index
                .by_label
                .iter()
                .filter(|(_, op)| op == outpoint)
                .map(|(label, _)| *label)
                .collect();
            labels.sort();
            (
                *outpoint,
                Found {
                    amount_sats: graph.get_txout(*outpoint).map(|out| out.value.to_sat()),
                    labels,
                    spent: spent.contains(outpoint),
                },
            )
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Judging
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
enum Failure {
    Missing {
        wallet: String,
        reference: String,
        outpoint: String,
        amount_sats: u64,
    },
    Mismatched {
        wallet: String,
        reference: String,
        outpoint: String,
        field: &'static str,
        expected: String,
        reported: String,
    },
    UnexpectedlyPresent {
        wallet: String,
        reference: String,
        outpoint: String,
    },
    Unexpected {
        wallet: String,
        outpoint: String,
        found: Found,
    },
    RescanDiffers {
        wallet: String,
        after_action: usize,
        live: BTreeMap<OutPoint, Found>,
        rescanned: BTreeMap<OutPoint, Found>,
    },
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Failure::Missing {
                wallet,
                reference,
                outpoint,
                amount_sats,
            } => write!(
                f,
                "MISSING {reference}: wallet {wallet} did not report {outpoint} ({amount_sats} sat)"
            ),
            Failure::Mismatched {
                wallet,
                reference,
                outpoint,
                field,
                expected,
                reported,
            } => write!(
                f,
                "MISMATCHED {reference} ({wallet}, {outpoint}): {field} expected {expected}, reported {reported}"
            ),
            Failure::UnexpectedlyPresent {
                wallet,
                reference,
                outpoint,
            } => write!(
                f,
                "UNEXPECTEDLY PRESENT {reference}: wallet {wallet} reported {outpoint}, declared expected_absent"
            ),
            Failure::Unexpected {
                wallet,
                outpoint,
                found,
            } => write!(
                f,
                "UNEXPECTED: wallet {wallet} reported {outpoint} ({found:?}), which the scenario never paid it"
            ),
            Failure::RescanDiffers {
                wallet,
                after_action,
                live,
                rescanned,
            } => write!(
                f,
                "RESCAN DIFFERS: wallet {wallet} after the scanner restart at action {after_action}: live {live:?}, rescanned {rescanned:?}"
            ),
        }
    }
}

fn label_text(labels: &[Option<u32>]) -> String {
    match labels {
        [None] => "none".into(),
        [Some(m)] => format!("m={m}"),
        other => format!("{other:?}"),
    }
}

/// Compares every wallet's found-set with the fixture's answer key.
fn judge(fixture: &Fixture, found: &BTreeMap<String, BTreeMap<OutPoint, Found>>) -> Vec<Failure> {
    let mut failures = Vec::new();
    let mut declared: HashMap<(&str, OutPoint), ()> = HashMap::new();
    for row in &fixture.expected {
        let outpoint = OutPoint::from_str(&row.outpoint).expect("expected outpoint");
        declared.insert((row.wallet.as_str(), outpoint), ());
        let reported = found
            .get(&row.wallet)
            .unwrap_or_else(|| panic!("wallet {} was never scanned", row.wallet))
            .get(&outpoint);
        match (row.outcome.as_str(), reported) {
            ("must_find", None) => failures.push(Failure::Missing {
                wallet: row.wallet.clone(),
                reference: row.reference.clone(),
                outpoint: row.outpoint.clone(),
                amount_sats: row.amount_sats,
            }),
            ("must_find", Some(reported)) => {
                let mismatch = |field, expected: String, got: String| Failure::Mismatched {
                    wallet: row.wallet.clone(),
                    reference: row.reference.clone(),
                    outpoint: row.outpoint.clone(),
                    field,
                    expected,
                    reported: got,
                };
                if reported.amount_sats != Some(row.amount_sats) {
                    failures.push(mismatch(
                        "amount_sats",
                        row.amount_sats.to_string(),
                        format!("{:?}", reported.amount_sats),
                    ));
                }
                if reported.labels != [row.label] {
                    failures.push(mismatch(
                        "label",
                        label_text(&[row.label]),
                        label_text(&reported.labels),
                    ));
                }
                if reported.spent != row.spent {
                    failures.push(mismatch(
                        "spent",
                        row.spent.to_string(),
                        reported.spent.to_string(),
                    ));
                }
            }
            ("expected_absent", None) => {}
            ("expected_absent", Some(_)) => failures.push(Failure::UnexpectedlyPresent {
                wallet: row.wallet.clone(),
                reference: row.reference.clone(),
                outpoint: row.outpoint.clone(),
            }),
            (outcome, _) => panic!("{}: unknown outcome {outcome}", row.reference),
        }
    }
    for (wallet, outputs) in found {
        for (outpoint, output) in outputs {
            if !declared.contains_key(&(wallet.as_str(), *outpoint)) {
                failures.push(Failure::Unexpected {
                    wallet: wallet.clone(),
                    outpoint: outpoint.to_string(),
                    found: output.clone(),
                });
            }
        }
    }
    failures
}

// ---------------------------------------------------------------------------
// Running a scenario
// ---------------------------------------------------------------------------

/// Replays the fixture's actions in order: every block an action mined goes
/// through every wallet's scanner, a scanner restart rescans from the first
/// block and must reproduce the live found-set, an oracle restart recomputes
/// the served data and must reproduce it. Returns every failure.
fn run_scenario(fixture: &Fixture) -> Vec<Failure> {
    let chain = build_chain(fixture);
    let mut scanners: Vec<(String, Scanner)> = fixture
        .wallets
        .iter()
        .map(|wallet| (wallet.id.clone(), wallet_scanner(fixture, wallet)))
        .collect();
    let mut failures = Vec::new();

    let mut next_height = 1u32;
    for (position, action) in fixture.actions.iter().enumerate() {
        assert_eq!(action.index, position, "actions are listed in order");
        for &height in &action.blocks {
            assert_eq!(
                height, next_height,
                "action {position} mined an unexpected height"
            );
            next_height += 1;
            let block = &chain[height as usize - 1];
            for (_, scanner) in scanners.iter_mut() {
                process_block(scanner, block);
            }
        }
        match (action.kind.as_str(), action.component.as_deref()) {
            ("restart", Some("scanner")) => {
                for (id, scanner) in scanners.iter_mut() {
                    let wallet = fixture
                        .wallets
                        .iter()
                        .find(|w| &w.id == id)
                        .expect("wallet");
                    let live = observe(scanner);
                    *scanner = wallet_scanner(fixture, wallet);
                    for block in &chain[..next_height as usize - 1] {
                        process_block(scanner, block);
                    }
                    let rescanned = observe(scanner);
                    if rescanned != live {
                        failures.push(Failure::RescanDiffers {
                            wallet: id.clone(),
                            after_action: position,
                            live,
                            rescanned,
                        });
                    }
                }
            }
            ("restart", Some("oracle")) => {
                // The served data is a pure function of the chain: rebuilding
                // it must reproduce exactly what was served.
                let rebuilt = build_chain(fixture);
                for block in &chain[..next_height as usize - 1] {
                    assert_eq!(
                        rebuilt[block.height as usize - 1].short,
                        block.short,
                        "block {}: short data rebuilt after an oracle restart differs",
                        block.height
                    );
                }
            }
            ("restart", other) => {
                panic!("action {position}: restart of {other:?} is not a T0 action")
            }
            ("fund" | "send" | "send_multi" | "spend", None) => {}
            (kind, component) => panic!("action {position}: unknown action {kind} {component:?}"),
        }
    }
    assert_eq!(
        next_height as usize - 1,
        chain.len(),
        "every block belongs to exactly one action"
    );

    let found: BTreeMap<String, BTreeMap<OutPoint, Found>> = scanners
        .iter()
        .map(|(id, scanner)| (id.clone(), observe(scanner)))
        .collect();
    failures.extend(judge(fixture, &found));
    failures
}

/// Runs one scenario and fails with every failure named, except the entries of
/// [`KNOWN_SPEND_GAP`], which must fail exactly as recorded.
fn assert_scenario(name: &str) {
    let fixture = fixture(name);
    let failures = run_scenario(&fixture);

    let known: Vec<&str> = KNOWN_SPEND_GAP
        .iter()
        .filter(|(scenario, _)| *scenario == name)
        .map(|(_, reference)| *reference)
        .collect();
    let is_known_gap = |failure: &Failure| {
        matches!(failure, Failure::Mismatched { reference, field: "spent", expected, reported, .. }
            if known.contains(&reference.as_str()) && expected == "true" && reported == "false")
    };
    let unexpected: Vec<String> = failures
        .iter()
        .filter(|failure| !is_known_gap(failure))
        .map(|failure| format!("  {failure}"))
        .collect();
    assert!(
        unexpected.is_empty(),
        "testkit scenario {name} at T0 through blindbit-lib's live receive path:\n{}",
        unexpected.join("\n")
    );
    for &reference in &known {
        assert!(
            failures.iter().any(|failure| is_known_gap(failure)
                && matches!(failure, Failure::Mismatched { reference: r, .. } if r == reference)),
            "{name}/{reference} is listed in KNOWN_SPEND_GAP but its spend is now detected; remove the entry"
        );
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Every pinned fixture matches its digest and the exported `SHA256SUMS`, and
/// the manifest lists nothing that is not pinned.
#[test]
fn testkit_fixtures_match_their_pins() {
    let manifest: BTreeMap<&str, &str> = MANIFEST
        .lines()
        .map(|line| {
            let (sum, file) = line.split_once("  ").expect("sha256sum line");
            (file, sum)
        })
        .collect();
    assert_eq!(
        manifest.len(),
        FIXTURES.len(),
        "SHA256SUMS lists a different set of fixtures"
    );
    for pinned in FIXTURES {
        let file = format!("{}.json", pinned.name);
        assert_eq!(
            manifest.get(file.as_str()),
            Some(&pinned.sha256),
            "{file}: manifest digest"
        );
        fixture(pinned.name);
    }
}

macro_rules! scenario_test {
    ($test:ident, $name:literal) => {
        #[test]
        fn $test() {
            assert_scenario($name);
        }
    };
}

scenario_test!(testkit_t0_plain_payment, "plain-payment");
scenario_test!(testkit_t0_labelled_multi, "labelled-multi");
scenario_test!(testkit_t0_k_gap, "k-gap");
scenario_test!(testkit_t0_label_parity, "label-parity");
scenario_test!(testkit_t0_k_counter, "k-counter");
scenario_test!(testkit_t0_spent_outputs, "spent-outputs");
scenario_test!(testkit_t0_input_types, "input-types");
scenario_test!(testkit_t0_rescan, "rescan");
scenario_test!(testkit_t0_dust_boundary, "dust-boundary");
