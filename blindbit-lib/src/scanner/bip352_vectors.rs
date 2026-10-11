//! Official BIP-352 receiver vectors exercised at the blindbit-lib boundary.
//!
//! The boundary under test is the live receive path the daemon runs: the
//! oracle's short block data through `Scanner::scan_short_block_data` (and so
//! `scan_transaction_short` / `match_short_pubkey`), then, on a probable match,
//! the full block through `Scanner::apply_matched_block` (`apply_block_relevant`
//! on the external indexer). See the section "The live short receive path" at the
//! end of this file. The tests before it check the fixture itself, the input
//! tweaks the oracle would publish, and the wallet's address derivation.
//!
//! Fixture provenance (re-checked at runtime by [`vectors`], so a silent swap or
//! a corrupted copy fails loudly instead of quietly changing coverage):
//!
//! * source repo: `bitcoin/bips`
//! * revision:    `e71448c81fb4f72da33fda5dffbba2f341457b6d`
//! * path:        `bip-0352/send_and_receive_test_vectors.json`
//! * cases:       28 top-level cases / 29 `receiving` sub-cases (case 19 has two)
//! * size:        418648 bytes
//! * SHA-256:     `f5f9ed4afd76a1b76f3c70b1cbe67532f89abbe559f8e02d7fc3d8ecb93af4a1`
//!
//! The JSON is copied verbatim; never hand-edit it. To refresh it, copy the file
//! again from a newer bips revision and update the constants below together with
//! this comment.
//!
//! Every struct below is `deny_unknown_fields` and models the *whole* fixture
//! schema, including the `sending` half this crate does not implement. That is
//! deliberate: an upstream schema change must fail the test rather than silently
//! deserialise into `None`/`vec![]` and quietly shrink what is asserted.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::OnceLock;

use bdk_sp::bitcoin::hashes::{Hash, sha256};
use bdk_sp::bitcoin::key::Secp256k1;
use bdk_sp::bitcoin::secp256k1::{Error as Secp256k1Error, PublicKey, SecretKey};
use bdk_sp::bitcoin::{
    Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness, XOnlyPublicKey,
    absolute::LockTime, transaction::Version,
};
use bdk_sp::encoding::SilentPaymentCode;
use bdk_sp::hashes::{get_label_tweak, get_shared_secret};
use bdk_sp::receive::error::SpReceiveError;
use bdk_sp::receive::{compute_tweak_data, extract_pubkey, get_silentpayment_pubkey};
use bitcoin_rev::Network;
use indexer::v2::SpIndexerV2;
use serde::Deserialize;

use crate::scanner::test_support::{oracle_client, state_file};

use super::Scanner;

const VECTORS_JSON: &str = include_str!("../../tests/data/bip352-official-vectors.json");
const VECTORS_SHA256: &str = "f5f9ed4afd76a1b76f3c70b1cbe67532f89abbe559f8e02d7fc3d8ecb93af4a1";
const VECTORS_LEN: usize = 418_648;

/// Top-level cases in the fixture.
const VECTOR_CASE_COUNT: usize = 28;
/// `receiving` sub-cases across all top-level cases (case 19 carries two).
const RECEIVING_SUBCASE_COUNT: usize = 29;
/// Sub-cases whose inputs are ineligible, so no tweak exists on the wire at all
/// ("No valid inputs, sender generates no outputs" and "Input keys sum up to
/// zero / point at infinity").
const NO_TWEAK_SUBCASE_COUNT: usize = 2;
/// Sub-cases that exceed the BIP-352 per-group recipient limit.
const K_MAX_SUBCASE_COUNT: usize = 1;
/// Sub-cases with a wire tweak: the ones the oracle serves and the receive path
/// scans.
const SCANNED_SUBCASE_COUNT: usize = RECEIVING_SUBCASE_COUNT - NO_TWEAK_SUBCASE_COUNT;
/// Total `expected.outputs` entries across the fixture (the K_max case pins
/// `n_outputs` instead and contributes none).
const EXPECTED_OUTPUT_COUNT: usize = 32;

/// The vectors are mainnet codes.
const SP_NETWORK: bitcoin::Network = bitcoin::Network::Bitcoin;

// ---------------------------------------------------------------------------
// Fixture schema (complete, strict)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TestCase {
    comment: String,
    /// Only checked for presence: blindbit-lib is receive-only. Modelled so
    /// that an upstream change to the sending half is caught instead of
    /// ignored.
    sending: Vec<SendingCase>,
    receiving: Vec<ReceivingCase>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
struct SendingCase {
    given: SendingGiven,
    expected: SendingExpected,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
struct SendingGiven {
    vin: Vec<Vin>,
    recipients: Vec<SendingRecipient>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
struct SendingRecipient {
    address: String,
    scan_pub_key: String,
    spend_pub_key: String,
    /// Only present on the K_max case.
    #[serde(default)]
    count: Option<u32>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
struct SendingExpected {
    /// Absent when the inputs are ineligible.
    #[serde(default)]
    input_private_key_sum: Option<String>,
    input_pub_keys: Vec<String>,
    /// One inner vector per acceptable output ordering.
    outputs: Vec<Vec<String>>,
    shared_secrets: Vec<Option<String>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReceivingCase {
    given: ReceivingGiven,
    expected: ReceivingExpected,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReceivingGiven {
    vin: Vec<Vin>,
    outputs: Vec<String>,
    key_material: KeyMaterial,
    labels: Vec<u32>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Vin {
    txid: String,
    vout: u32,
    #[serde(rename = "scriptSig")]
    script_sig: String,
    txinwitness: String,
    prevout: Prevout,
    /// Always present on `sending` inputs, present on one `receiving` input.
    #[serde(default)]
    #[allow(dead_code)]
    private_key: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Prevout {
    #[serde(rename = "scriptPubKey")]
    script_pubkey: ScriptPubKey,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ScriptPubKey {
    hex: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyMaterial {
    spend_priv_key: String,
    scan_priv_key: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReceivingExpected {
    addresses: Vec<String>,
    /// Absent on the K_max case, which pins `n_outputs` instead.
    #[serde(default)]
    outputs: Vec<ExpectedOutput>,
    #[serde(default)]
    n_outputs: Option<usize>,
    /// `null` when the inputs are ineligible.
    tweak: Option<String>,
    /// `null` when the inputs are ineligible.
    shared_secret: Option<String>,
    /// Absent when the inputs are ineligible.
    #[serde(default)]
    input_pub_key_sum: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExpectedOutput {
    pub_key: String,
    priv_key_tweak: String,
    /// Parsed but unused: signing is out of scope for blindbit-lib.
    #[allow(dead_code)]
    signature: String,
}

// ---------------------------------------------------------------------------
// Loader
// ---------------------------------------------------------------------------

fn fixture_sha256(bytes: &[u8]) -> String {
    hex::encode(sha256::Hash::hash(bytes).to_byte_array())
}

/// Loads, digest-checks and structurally validates the embedded fixture.
///
/// Every guarantee asserted here is inherited by every test in this module: the
/// bytes are the pinned bitcoin/bips revision, the case counts are the ones the
/// constants above describe, and no case is empty. A test can therefore not pass
/// by iterating over nothing.
fn vectors() -> &'static [TestCase] {
    static VECTORS: OnceLock<Vec<TestCase>> = OnceLock::new();
    VECTORS
        .get_or_init(|| {
            assert_eq!(
                fixture_sha256(VECTORS_JSON.as_bytes()),
                VECTORS_SHA256,
                "embedded BIP-352 fixture is not the pinned bitcoin/bips copy"
            );
            assert_eq!(
                VECTORS_JSON.len(),
                VECTORS_LEN,
                "embedded BIP-352 fixture has the wrong size"
            );

            let cases: Vec<TestCase> = serde_json::from_str(VECTORS_JSON)
                .expect("official BIP-352 vectors must match the modelled schema exactly");

            assert_eq!(cases.len(), VECTOR_CASE_COUNT, "fixture case count changed");
            let subcases: usize = cases.iter().map(|case| case.receiving.len()).sum();
            assert_eq!(
                subcases, RECEIVING_SUBCASE_COUNT,
                "fixture receiving sub-case count changed"
            );
            let expected_outputs: usize = cases
                .iter()
                .flat_map(|case| case.receiving.iter())
                .map(|receiving| receiving.expected.outputs.len())
                .sum();
            assert_eq!(
                expected_outputs, EXPECTED_OUTPUT_COUNT,
                "fixture per-output expectations changed"
            );

            for case in &cases {
                assert!(!case.comment.trim().is_empty(), "case without a comment");
                assert!(
                    !case.sending.is_empty(),
                    "{}: no sending sub-cases",
                    case.comment
                );
                assert!(
                    !case.receiving.is_empty(),
                    "{}: no receiving sub-cases",
                    case.comment
                );
                for receiving in &case.receiving {
                    let (given, expected) = (&receiving.given, &receiving.expected);
                    assert!(!given.vin.is_empty(), "{}: no inputs", case.comment);
                    assert!(
                        !given.outputs.is_empty(),
                        "{}: no candidate outputs",
                        case.comment
                    );
                    assert_eq!(
                        expected.addresses.len(),
                        given.labels.len() + 1,
                        "{}: expected one silent payment code per label plus the base code",
                        case.comment
                    );
                    assert_eq!(
                        expected.tweak.is_some(),
                        expected.shared_secret.is_some(),
                        "{}: tweak and shared_secret must agree on input eligibility",
                        case.comment
                    );
                    assert_eq!(
                        expected.tweak.is_some(),
                        expected.input_pub_key_sum.is_some(),
                        "{}: tweak and input_pub_key_sum must agree on input eligibility",
                        case.comment
                    );
                    assert!(
                        expected.n_outputs.is_none() || expected.outputs.is_empty(),
                        "{}: n_outputs and outputs are mutually exclusive",
                        case.comment
                    );
                }
            }

            cases
        })
        .as_slice()
}

// ---------------------------------------------------------------------------
// Harness helpers
// ---------------------------------------------------------------------------

/// The vector's transaction (vector output `i` at vout `i`) and its prevouts.
fn build_transaction(given: &ReceivingGiven) -> (Transaction, Vec<TxOut>) {
    let (inputs, prevouts): (Vec<_>, Vec<_>) = given
        .vin
        .iter()
        .map(|vin| {
            let witness_bytes = hex::decode(&vin.txinwitness).expect("vector witness hex");
            let witness = if witness_bytes.is_empty() {
                Witness::new()
            } else {
                bitcoin::consensus::deserialize(&witness_bytes).expect("vector witness")
            };
            let input = TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_str(&vin.txid).expect("vector txid"),
                    vout: vin.vout,
                },
                script_sig: ScriptBuf::from_bytes(
                    hex::decode(&vin.script_sig).expect("vector scriptSig hex"),
                ),
                sequence: Sequence::MAX,
                witness,
            };
            let prevout = TxOut {
                value: Amount::ZERO,
                script_pubkey: ScriptBuf::from_bytes(
                    hex::decode(&vin.prevout.script_pubkey.hex).expect("vector prevout hex"),
                ),
            };
            (input, prevout)
        })
        .unzip();

    let outputs = given
        .outputs
        .iter()
        .map(|output| {
            let output_key = hex::decode(output).expect("vector output key hex");
            assert_eq!(output_key.len(), 32, "vector output key length");
            let mut script = Vec::with_capacity(34);
            script.extend_from_slice(&[0x51, 0x20]);
            script.extend_from_slice(&output_key);
            TxOut {
                // The vectors say nothing about amounts.
                value: Amount::from_sat(100_000),
                script_pubkey: ScriptBuf::from_bytes(script),
            }
        })
        .collect();

    (
        Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: inputs,
            output: outputs,
        },
        prevouts,
    )
}

/// Silent payment codes re-derived locally from the vector key material, without
/// going through the scanner.
fn expected_codes(given: &ReceivingGiven, scan_sk: SecretKey, spend_pk: PublicKey) -> Vec<String> {
    let secp = Secp256k1::new();
    let scan_pk = scan_sk.public_key(&secp);
    let code = SilentPaymentCode::new_v0(scan_pk, spend_pk, SP_NETWORK);
    let mut codes = vec![code.to_string()];
    for label in &given.labels {
        let label_tweak = SilentPaymentCode::get_label(scan_sk, *label);
        codes.push(
            code.add_label(label_tweak)
                .expect("vector label is valid")
                .to_string(),
        );
    }
    codes
}

fn expected_outputs(expected: &ReceivingExpected) -> BTreeMap<XOnlyPublicKey, SecretKey> {
    expected
        .outputs
        .iter()
        .map(|output| {
            (
                XOnlyPublicKey::from_str(&output.pub_key).expect("expected output key"),
                SecretKey::from_str(&output.priv_key_tweak).expect("expected output tweak"),
            )
        })
        .collect()
}

/// The BIP-352-eligible input pubkeys of `tx`, in input order.
///
/// Mirrors `bdk_sp::receive::compute_tweak_data`, which silently ignores every
/// input it cannot extract a key from.
fn eligible_input_keys(tx: &Transaction, prevouts: &[TxOut]) -> Vec<PublicKey> {
    tx.input
        .iter()
        .cloned()
        .zip(prevouts)
        .filter_map(|(input, prevout)| extract_pubkey(input, &prevout.script_pubkey))
        .map(|(_, key)| key)
        .collect()
}

/// Asserts the eligible input keys sum to the fixture's `input_pub_key_sum`.
///
/// Callable only for a sub-case that *has* one: an early return here would be a
/// silent no-op, so a future caller passing an ineligible sub-case would assert
/// nothing and still look green. It panics instead.
fn assert_input_eligibility(tx: &Transaction, prevouts: &[TxOut], expected: &ReceivingExpected) {
    let expected_sum = expected
        .input_pub_key_sum
        .as_ref()
        .expect("assert_input_eligibility requires a sub-case with eligible inputs");

    let keys = eligible_input_keys(tx, prevouts);
    let key_refs = keys.iter().collect::<Vec<_>>();
    let actual = PublicKey::combine_keys(&key_refs).expect("vector input keys do not cancel");
    assert_eq!(actual.to_string(), *expected_sum);
}

/// Why BIP-352 says a transaction carries no tweak.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NoTweakReason {
    /// Not one input carried an extractable pubkey.
    NoEligibleInputs,
    /// Eligible inputs existed, but their keys sum to the point at infinity.
    InputKeySumIsInfinity,
}

/// Classifies a rejected sub-case by its *actual* BIP-352 skip condition.
///
/// `compute_tweak_data` reports both conditions as the identical
/// `secp256k1::Error::InvalidPublicKeySum` — `PublicKey::combine_keys` returns
/// it for an empty slice just as it does for keys that cancel — so matching on
/// the error alone cannot tell case 25 ("No valid inputs") from case 26 ("Input
/// keys sum up to zero / point at infinity"), and would also accept a
/// regression that dropped every input. The eligible-input set does distinguish
/// them, so that is what is asserted; the caller then pins which sub-case must
/// produce which reason.
fn classify_no_tweak(
    tx: &Transaction,
    prevouts: &[TxOut],
    err: &SpReceiveError,
    what: &str,
) -> NoTweakReason {
    assert!(
        matches!(
            err,
            SpReceiveError::Secp256k1Error(Secp256k1Error::InvalidPublicKeySum)
        ),
        "{what}: unexpected rejection {err}"
    );

    let keys = eligible_input_keys(tx, prevouts);
    if keys.is_empty() {
        NoTweakReason::NoEligibleInputs
    } else {
        let key_refs = keys.iter().collect::<Vec<_>>();
        assert!(
            PublicKey::combine_keys(&key_refs).is_err(),
            "{what}: {} eligible input key(s) that do not cancel, so a tweak must exist",
            keys.len()
        );
        NoTweakReason::InputKeySumIsInfinity
    }
}

/// The skip condition the fixture comment says this sub-case is about.
///
/// Paired with [`classify_no_tweak`] so the two no-tweak vectors cannot swap
/// (or be replaced by an unrelated rejection) without failing.
fn expected_no_tweak_reason(comment: &str) -> NoTweakReason {
    if comment.starts_with("No valid inputs") {
        NoTweakReason::NoEligibleInputs
    } else if comment.contains("point at infinity") {
        NoTweakReason::InputKeySumIsInfinity
    } else {
        panic!("unexpected sub-case without a tweak: {comment}");
    }
}

/// A scanner exactly as `Scanner::new` builds it, i.e. with the change label
/// `m = 0` always registered.
fn default_scanner(scan_sk: SecretKey, spend_pk: PublicKey, tag: &str) -> Scanner {
    // Never contacted: nothing listens on port 1.
    let socket: SocketAddr = "127.0.0.1:1".parse().expect("socket address");
    Scanner::new(
        oracle_client(),
        socket,
        scan_sk,
        spend_pk,
        0,
        state_file(&format!("bip352-vectors-{tag}")),
        Network::Bitcoin,
    )
}

/// A scanner whose indexer holds **exactly** `labels`.
///
/// `Scanner::new` unconditionally registers the change label `m = 0`, so a
/// scanner built through it cannot model a vector whose `given.labels` is empty.
/// Rather than redesigning `Scanner::new` (out of scope here), the harness swaps
/// in a freshly built indexer carrying precisely the labels the vector says the
/// receiver registered. The test
/// [`official_vectors_extra_change_label_is_harmless_on_the_live_path`] proves
/// the difference is unobservable on the live receive path for these vectors, so
/// the swap is not papering over a difference in what a real `Scanner`'s label
/// set would find.
fn blindbit_scanner(scan_sk: SecretKey, spend_pk: PublicKey, labels: &[u32], tag: &str) -> Scanner {
    let mut scanner = default_scanner(scan_sk, spend_pk, tag);
    scanner.internal_indexer = SpIndexerV2::new(scan_sk, spend_pk);
    for &label in labels {
        let _ = scanner.internal_indexer.add_label(label);
    }
    assert_eq!(
        scanner.internal_indexer.index().label_lookup.len(),
        labels.len(),
        "vector labels must be distinct"
    );
    scanner
}

/// `hash(scan_sk || m) * G`, the point the receiver subtracts to recover label `m`.
fn label_point(scan_sk: SecretKey, m: u32) -> PublicKey {
    let secp = Secp256k1::new();
    SecretKey::from_slice(&get_label_tweak(scan_sk, m).to_be_bytes())
        .expect("label tweak is a valid scalar")
        .public_key(&secp)
}

/// Full tweak (`t_k`, plus the label tweak for a labelled output) for derivation
/// order `k`.
fn tweak_for(
    shared_secret: PublicKey,
    scan_sk: SecretKey,
    k: u32,
    label: Option<u32>,
) -> SecretKey {
    let t_k = get_shared_secret(shared_secret, k);
    match label {
        None => t_k,
        Some(m) => t_k
            .add_tweak(&get_label_tweak(scan_sk, m))
            .expect("labelled tweak is valid"),
    }
}

/// Compares the scanner's own address derivation and a local re-derivation
/// against `expected.addresses`.
///
/// **Positionally**, not as sets: `expected.addresses[0]` is the base silent
/// payment code and `addresses[1..]` follow `given.labels` order. Comparing
/// `HashSet`s would discard exactly that mapping and still pass if two labels'
/// codes were swapped.
fn assert_addresses(
    scanner: &mut Scanner,
    given: &ReceivingGiven,
    expected: &ReceivingExpected,
    scan_sk: SecretKey,
    spend_pk: PublicKey,
    what: &str,
) {
    let unique: HashSet<&str> = expected.addresses.iter().map(String::as_str).collect();
    assert_eq!(
        unique.len(),
        expected.addresses.len(),
        "{what}: duplicate addresses in the fixture"
    );
    assert_eq!(
        expected.addresses.len(),
        given.labels.len() + 1,
        "{what}: expected the base code plus one code per label"
    );

    let local = expected_codes(given, scan_sk, spend_pk);
    assert_eq!(
        local, expected.addresses,
        "{what}: locally re-derived silent payment codes (index 0 is the base \
         code, the rest follow given.labels order)"
    );

    // The scanner's own derivation (`SpIndexerV2::get_address` /
    // `get_labeled_address`), which is what friglet shows the user.
    let mut from_scanner = vec![scanner.internal_indexer.get_address(SP_NETWORK).to_string()];
    for &m in &given.labels {
        from_scanner.push(
            scanner
                .internal_indexer
                .get_labeled_address(m, SP_NETWORK)
                .to_string(),
        );
    }
    assert_eq!(
        from_scanner, expected.addresses,
        "{what}: SpIndexerV2 address derivation (index 0 is the base code, the \
         rest follow given.labels order)"
    );
    // `get_labeled_address` registers a missing label; it must not have had to.
    assert_eq!(
        scanner.internal_indexer.index().label_lookup.len(),
        given.labels.len(),
        "{what}: address derivation changed the registered label set"
    );
}

fn scan_keys(given: &ReceivingGiven) -> (SecretKey, PublicKey) {
    let scan_sk = SecretKey::from_str(&given.key_material.scan_priv_key).expect("vector scan key");
    let spend_sk =
        SecretKey::from_str(&given.key_material.spend_priv_key).expect("vector spend key");
    (scan_sk, spend_sk.public_key(&Secp256k1::new()))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn fixture_loader_is_strict() {
    // The loader's own invariants (digest, size, counts, structure) run here too.
    let cases = vectors();
    assert_eq!(cases.len(), VECTOR_CASE_COUNT);

    // A flipped byte must change the digest the loader pins.
    assert_eq!(fixture_sha256(VECTORS_JSON.as_bytes()), VECTORS_SHA256);
    let mut corrupted = VECTORS_JSON.as_bytes().to_vec();
    corrupted[0] ^= 0x01;
    assert_ne!(
        fixture_sha256(&corrupted),
        VECTORS_SHA256,
        "digest check cannot detect corruption"
    );

    // An added field must be rejected (`deny_unknown_fields`).
    let mut value: serde_json::Value =
        serde_json::from_str(VECTORS_JSON).expect("fixture is valid JSON");
    value[0]
        .as_object_mut()
        .expect("case is an object")
        .insert("unexpected".into(), serde_json::Value::Bool(true));
    assert!(
        serde_json::from_value::<Vec<TestCase>>(value).is_err(),
        "loader accepts unknown top-level fields"
    );

    // A renamed nested field must be rejected too, rather than defaulting.
    let mut value: serde_json::Value =
        serde_json::from_str(VECTORS_JSON).expect("fixture is valid JSON");
    let expected = value[0]["receiving"][0]["expected"]
        .as_object_mut()
        .expect("expected is an object");
    let tweak = expected.remove("tweak").expect("tweak is present");
    expected.insert("tweek".into(), tweak);
    assert!(
        serde_json::from_value::<Vec<TestCase>>(value).is_err(),
        "loader silently defaults a renamed nested field"
    );

    // A dropped `sending` half must be rejected: it is modelled precisely so
    // that upstream schema drift cannot shrink coverage unnoticed.
    let mut value: serde_json::Value =
        serde_json::from_str(VECTORS_JSON).expect("fixture is valid JSON");
    value[0]
        .as_object_mut()
        .expect("case is an object")
        .remove("sending");
    assert!(
        serde_json::from_value::<Vec<TestCase>>(value).is_err(),
        "loader accepts a fixture with the sending half removed"
    );

    // And a dropped per-output signature, which is parsed but unused.
    let mut value: serde_json::Value =
        serde_json::from_str(VECTORS_JSON).expect("fixture is valid JSON");
    value[0]["receiving"][0]["expected"]["outputs"][0]
        .as_object_mut()
        .expect("expected output is an object")
        .remove("signature");
    assert!(
        serde_json::from_value::<Vec<TestCase>>(value).is_err(),
        "loader accepts an expected output without its signature"
    );
}

#[test]
fn official_vectors_cover_input_tweaks_and_eligible_inputs() {
    let cases = vectors();

    let mut with_tweak = 0usize;
    let mut no_eligible_inputs = 0usize;
    let mut infinite_key_sum = 0usize;

    for case in cases {
        for receiving in &case.receiving {
            let (tx, prevouts) = build_transaction(&receiving.given);
            let expected = &receiving.expected;

            let tweak = match compute_tweak_data(&tx, &prevouts) {
                Ok(tweak) => tweak,
                Err(err) => {
                    // Not a silent skip: these vectors *must* be rejected, for the
                    // reason their own comment gives, and the fixture must agree
                    // that no tweak exists for them.
                    let reason = classify_no_tweak(&tx, &prevouts, &err, &case.comment);
                    assert_eq!(
                        reason,
                        expected_no_tweak_reason(&case.comment),
                        "{}: BIP-352 skip condition",
                        case.comment
                    );
                    match reason {
                        NoTweakReason::NoEligibleInputs => no_eligible_inputs += 1,
                        NoTweakReason::InputKeySumIsInfinity => infinite_key_sum += 1,
                    }
                    assert!(
                        expected.tweak.is_none() && expected.shared_secret.is_none(),
                        "{}: unexpectedly rejected eligible inputs",
                        case.comment
                    );
                    assert!(
                        expected.outputs.is_empty() && expected.n_outputs.is_none(),
                        "{}: an ineligible transaction cannot produce outputs",
                        case.comment
                    );
                    continue;
                }
            };

            assert_eq!(
                tweak.to_string(),
                expected.tweak.as_deref().expect("valid vector tweak"),
                "{}",
                case.comment
            );
            assert_input_eligibility(&tx, &prevouts, expected);

            let (scan_sk, _) = scan_keys(&receiving.given);
            let shared_secret = bdk_sp::compute_shared_secret(&scan_sk, &tweak);
            assert_eq!(
                shared_secret.to_string(),
                expected
                    .shared_secret
                    .as_deref()
                    .expect("valid vector shared secret"),
                "{}",
                case.comment
            );
            with_tweak += 1;
        }
    }

    // One of each, pinned separately: the two rejections raise the identical
    // secp256k1 error, so only these counts prove both skip conditions were
    // actually reached.
    assert_eq!(
        no_eligible_inputs, 1,
        "the no-eligible-input vector is no longer covered"
    );
    assert_eq!(
        infinite_key_sum, 1,
        "the point-at-infinity vector is no longer covered"
    );
    assert_eq!(
        no_eligible_inputs + infinite_key_sum,
        NO_TWEAK_SUBCASE_COUNT,
        "unexpected number of sub-cases without a wire tweak"
    );
    assert_eq!(
        with_tweak + no_eligible_inputs + infinite_key_sum,
        RECEIVING_SUBCASE_COUNT,
        "not every receiving sub-case was exercised"
    );
}

/// The silent payment codes the wallet shows, for every receiving vector.
///
/// No scanning: the scanner is built from each sub-case's key material and
/// labels, and both its own derivation (`SpIndexerV2::get_address` /
/// `get_labeled_address`) and a local `SilentPaymentCode` re-derivation must
/// equal `expected.addresses`, position by position (see [`assert_addresses`]).
/// The base code must also be the address the daemon serves: the Electrum
/// index's `sp_address` (Electrum and control socket), derived for the
/// scanner's network.
#[test]
fn official_vectors_derive_expected_addresses() {
    let mut checked = 0usize;

    for (case_idx, case) in vectors().iter().enumerate() {
        for (sub_idx, receiving) in case.receiving.iter().enumerate() {
            let what = format!("case {} sub {sub_idx} ({})", case_idx + 1, case.comment);
            let (given, expected) = (&receiving.given, &receiving.expected);
            let (scan_sk, spend_pk) = scan_keys(given);

            let mut scanner = blindbit_scanner(
                scan_sk,
                spend_pk,
                &given.labels,
                &format!("addr-{case_idx}-{sub_idx}"),
            );
            assert_addresses(&mut scanner, given, expected, scan_sk, spend_pk, &what);

            let served = scanner
                .electrum_index()
                .try_lock()
                .expect("nothing else holds the new scanner's Electrum index")
                .sp_address
                .clone();
            assert_eq!(
                served, expected.addresses[0],
                "{what}: sp_address the Electrum index serves"
            );

            checked += 1;
        }
    }

    assert_eq!(
        checked, RECEIVING_SUBCASE_COUNT,
        "not every receiving sub-case's addresses were checked"
    );
}

// ---------------------------------------------------------------------------
// The live short receive path
// ---------------------------------------------------------------------------
//
// Per block the daemon asks the oracle for `BlockScanDataShortResponse`, runs
// `scan_short_block_data` -> `probabilistic_match` -> `scan_transaction_short`
// (k = 0 only, labels enumerated by hand, 8-byte x-only prefixes), and only on a
// probable match fetches the full block and hands it to `apply_matched_block`,
// i.e. `apply_block_relevant` on the external indexer. A false negative in the
// short step means the block is never fetched, so the wallet silently never
// sees the payment. The tests below drive every receiving vector through that
// exact sequence of production functions.

/// Length of one `outputs_short` entry: the oracle stores `Pubkey[:8]` of every
/// taproot output (`blindbit-oracle` `dbpebble/store.go`). Deliberately not
/// shared with `match_short_pubkey`, so a change there cannot silently change
/// what the test builds too.
const SHORT_PREFIX_LEN: usize = 8;

/// Height the synthetic blocks claim to be at.
const LIVE_BLOCK_HEIGHT: u64 = 840_000;

/// A txid as the oracle puts it on the wire: **display order** (the orientation
/// an RPC/REST txid string has), the reverse of the internal order
/// `Txid::from_byte_array` consumes. `apply_matched_block` reverses it back
/// (`byte_array_to_txid`) to find the matched transaction in the block, so a
/// txid served in internal order would match nothing and nothing would be stored.
fn wire_txid(tx: &Transaction) -> [u8; 32] {
    let mut txid = tx.compute_txid().to_raw_hash().to_byte_array();
    txid.reverse();
    txid
}

/// The `ComputeIndexTxItem` the oracle serves for `tx`: the 33-byte tweak
/// (`input_hash * A`) and, for every **taproot** output in output order, the
/// first [`SHORT_PREFIX_LEN`] bytes of its x-only key. Non-taproot outputs are
/// not stored by the oracle and so never appear.
fn short_item(tx: &Transaction, tweak: PublicKey) -> crate::oracle_grpc::ComputeIndexTxItem {
    let outputs_short = tx
        .output
        .iter()
        .filter(|output| output.script_pubkey.is_p2tr())
        .flat_map(|output| output.script_pubkey.as_bytes()[2..2 + SHORT_PREFIX_LEN].to_vec())
        .collect();
    crate::oracle_grpc::ComputeIndexTxItem {
        txid: wire_txid(tx).to_vec(),
        tweak: tweak.serialize().to_vec(),
        outputs_short,
    }
}

/// A non-coinbase transaction that is not ours, so the block the receive step
/// sees is not just the vector transaction on its own.
fn decoy_transaction() -> Transaction {
    let decoy_key = XOnlyPublicKey::from_str(
        "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    )
    .expect("decoy key");
    Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array([0x11; 32]),
                vout: 7,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(5_000),
            script_pubkey: ScriptBuf::new_p2tr_tweaked(
                bdk_sp::bitcoin::key::TweakedPublicKey::dangerous_assume_tweaked(decoy_key),
            ),
        }],
    }
}

/// The full block the daemon would fetch over P2P: a coinbase (which
/// `apply_block_relevant` skips by position), a decoy, then the vector's
/// transaction.
fn live_block(tx: &Transaction) -> bitcoin::Block {
    let coinbase = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::from_bytes(vec![0x03, 0x40, 0xd1, 0x0c]),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(312_500_000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x6a]),
        }],
    };
    let mut block = bitcoin::Block {
        header: bitcoin::block::Header {
            version: bitcoin::block::Version::TWO,
            prev_blockhash: bitcoin::BlockHash::all_zeros(),
            merkle_root: bitcoin::TxMerkleNode::all_zeros(),
            time: 1_713_571_767,
            bits: bitcoin::CompactTarget::from_consensus(0x1703_4219),
            nonce: 0,
        },
        txdata: vec![coinbase, decoy_transaction(), tx.clone()],
    };
    block.header.merkle_root = block.compute_merkle_root().expect("non-empty block");
    block
}

/// The per-block short response the oracle streams, carrying `items`.
fn short_block(
    block: &bitcoin::Block,
    items: Vec<crate::oracle_grpc::ComputeIndexTxItem>,
) -> crate::oracle_grpc::BlockScanDataShortResponse {
    let mut block_hash = block.block_hash().to_raw_hash().to_byte_array();
    block_hash.reverse();
    crate::oracle_grpc::BlockScanDataShortResponse {
        block_identifier: Some(crate::oracle_grpc::BlockIdentifier {
            block_hash: block_hash.to_vec(),
            block_height: LIVE_BLOCK_HEIGHT,
        }),
        comp_index: items,
        spent_outputs: Vec::new(),
    }
}

/// Which k = 0 candidate the vector transaction actually carries, by full
/// 32-byte key: `Some(None)` for the unlabelled `P_0`, `Some(Some(m))` for
/// `P_0 + label_m`, `None` if neither. This is independent of the short path
/// and says which label iteration the short path *must* perform to match.
fn k0_candidates(
    tx: &Transaction,
    given: &ReceivingGiven,
    scan_sk: SecretKey,
    spend_pk: PublicKey,
    shared_secret: PublicKey,
) -> BTreeSet<Option<u32>> {
    let keys: HashSet<XOnlyPublicKey> = tx
        .output
        .iter()
        .filter(|output| output.script_pubkey.is_p2tr())
        .map(|output| {
            XOnlyPublicKey::from_slice(&output.script_pubkey.as_bytes()[2..]).expect("taproot key")
        })
        .collect();
    std::iter::once(None)
        .chain(given.labels.iter().map(|&m| Some(m)))
        .filter(|label| {
            let label_pt = label.map(|m| label_point(scan_sk, m));
            let p_0 = get_silentpayment_pubkey(&spend_pk, &shared_secret, 0, label_pt.as_ref());
            keys.contains(&p_0.x_only_public_key().0)
        })
        .collect()
}

/// No false negatives on the live short path, for every receiving vector.
///
/// Each vector transaction is served the way the oracle serves it (8-byte
/// prefixes of its taproot outputs, the 33-byte tweak, the display-order txid)
/// and pushed through `scan_short_block_data`, the function the daemon calls per
/// block. Wherever the vector expects the wallet to find at least one output,
/// the block must come back as a probable match carrying that txid and tweak.
///
/// The k = 0 candidate each matched vector carries is pinned independently (see
/// [`k0_candidates`]), so the test also proves *which* short-path branch did the
/// work: the unlabelled `P_0`, a labelled one of either output parity, and the
/// change label `m = 0`. Dropping the label iteration, or matching on anything
/// other than the 8-byte x-only prefix, turns this red.
///
/// False positives (a probable match where the vector expects nothing) are only
/// a wasted block fetch; they are counted and reported, and pinned at zero on
/// these vectors because an 8-byte prefix collision among them would be a
/// fixture surprise worth looking at.
#[test]
fn official_vectors_reach_the_live_short_receive_path() {
    let mut no_wire_tweak = 0usize;
    let mut must_match = 0usize;
    let mut must_not_match = 0usize;
    let mut false_positives = Vec::new();
    // Matched sub-cases whose only k = 0 candidate is labelled, by label.
    let mut label_only: BTreeMap<u32, usize> = BTreeMap::new();
    let mut unlabelled_k0 = 0usize;
    let mut parity_cases: BTreeMap<&str, bool> = BTreeMap::new();

    for (case_idx, case) in vectors().iter().enumerate() {
        for (sub_idx, receiving) in case.receiving.iter().enumerate() {
            let what = format!("case {} sub {sub_idx} ({})", case_idx + 1, case.comment);
            let (given, expected) = (&receiving.given, &receiving.expected);
            let (tx, prevouts) = build_transaction(given);

            let tweak = match compute_tweak_data(&tx, &prevouts) {
                Ok(tweak) => tweak,
                Err(err) => {
                    // The oracle cannot publish a tweak for these, so there is no
                    // short item to serve; classified as in
                    // `official_vectors_cover_input_tweaks_and_eligible_inputs`.
                    let reason = classify_no_tweak(&tx, &prevouts, &err, &what);
                    assert_eq!(reason, expected_no_tweak_reason(&case.comment), "{what}");
                    assert!(expected.outputs.is_empty() && expected.n_outputs.is_none());
                    no_wire_tweak += 1;
                    continue;
                }
            };
            assert_eq!(
                tweak.to_string(),
                expected.tweak.as_deref().expect("vector tweak"),
                "{what}: served tweak"
            );
            let (scan_sk, spend_pk) = scan_keys(given);
            let shared_secret = bdk_sp::compute_shared_secret(&scan_sk, &tweak);

            let item = short_item(&tx, tweak);
            assert_eq!(item.tweak.len(), 33, "{what}: served tweak length");
            assert_eq!(
                item.outputs_short.len(),
                SHORT_PREFIX_LEN * given.outputs.len(),
                "{what}: every vector output is taproot and must be served"
            );

            let mut scanner = blindbit_scanner(
                scan_sk,
                spend_pk,
                &given.labels,
                &format!("short-{case_idx}-{sub_idx}"),
            );
            let probable = scanner
                .scan_short_block_data(short_block(&live_block(&tx), vec![item]))
                .expect("short block scan");
            let matched = match &probable {
                Some(probable) => {
                    assert!(!probable.spent, "{what}: no spent outputs were served");
                    assert_eq!(
                        probable.matched_txs,
                        vec![(wire_txid(&tx), tweak)],
                        "{what}: probable match must carry the served txid and tweak"
                    );
                    true
                }
                None => false,
            };

            let expected_count = expected.n_outputs.unwrap_or(expected.outputs.len());
            if expected_count == 0 {
                must_not_match += 1;
                if matched {
                    false_positives.push(what);
                }
                continue;
            }

            must_match += 1;
            assert!(
                matched,
                "{what}: FALSE NEGATIVE on the live short path — the vector expects \
                 {expected_count} output(s), but the block would never be fetched"
            );

            let k0 = k0_candidates(&tx, given, scan_sk, spend_pk, shared_secret);
            assert!(
                !k0.is_empty(),
                "{what}: a transaction paying us must carry a k = 0 output"
            );
            if k0.contains(&None) {
                unlabelled_k0 += 1;
            } else {
                for m in k0.iter().flatten() {
                    *label_only.entry(*m).or_default() += 1;
                }
            }

            for kind in ["even", "odd"] {
                if case.comment.contains(&format!("label with {kind} parity")) {
                    parity_cases.insert(kind, !k0.contains(&None));
                }
            }
        }
    }

    for fp in &false_positives {
        eprintln!("short-path false positive: {fp}");
    }
    eprintln!(
        "short path: {must_match} sub-cases must match (all did), {must_not_match} must \
         not, {} false positive(s), {no_wire_tweak} without a wire tweak",
        false_positives.len()
    );

    assert_eq!(no_wire_tweak, NO_TWEAK_SUBCASE_COUNT);
    assert_eq!(
        must_match + must_not_match + no_wire_tweak,
        RECEIVING_SUBCASE_COUNT,
        "not every receiving sub-case reached the short path"
    );
    assert_eq!(
        must_not_match, 1,
        "the 'recipient ignores unrelated outputs' vector is no longer covered"
    );
    assert!(
        false_positives.is_empty(),
        "unexpected short-path false positives: {false_positives:?}"
    );

    // Branch coverage of the short path: vectors that can only be found through
    // the label iteration, including both parities and the change label m = 0.
    assert_eq!(
        parity_cases.get("even"),
        Some(&true),
        "the even-parity label vector must be reachable only through a label"
    );
    assert_eq!(
        parity_cases.get("odd"),
        Some(&true),
        "the odd-parity label vector must be reachable only through a label"
    );
    assert!(
        label_only.contains_key(&0),
        "no vector is reachable only through the change label m = 0: {label_only:?}"
    );
    let label_only_total: usize = label_only.values().sum();
    assert_eq!(
        label_only_total, 7,
        "label-only coverage changed: {label_only:?}"
    );
    assert!(unlabelled_k0 > 0, "no unlabelled k = 0 vector was matched");
    eprintln!("short path: {unlabelled_k0} matched via P_0, label-only by m: {label_only:?}");
}

/// Runs one vector through the whole live receive sequence — short scan, then
/// (only on a probable match, as the daemon does) the full-block step — with a
/// scanner registering exactly `labels`, and returns every output the indexer
/// now owns in the vector transaction, as `x-only key -> priv_key_tweak`, plus
/// its label.
fn live_receive(
    given: &ReceivingGiven,
    labels: &[u32],
    tx: &Transaction,
    tweak: PublicKey,
    tag: &str,
) -> (Scanner, BTreeMap<XOnlyPublicKey, (SecretKey, Option<u32>)>) {
    let (scan_sk, spend_pk) = scan_keys(given);
    let mut scanner = blindbit_scanner(scan_sk, spend_pk, labels, tag);
    let block = live_block(tx);

    let probable = scanner
        .scan_short_block_data(short_block(&block, vec![short_item(tx, tweak)]))
        .expect("short block scan");
    if let Some(probable) = probable {
        scanner.apply_matched_block(&block, &probable, LIVE_BLOCK_HEIGHT as u32);
    }

    let txid = tx.compute_txid();
    let index = scanner.internal_indexer.index();
    let labels: BTreeMap<OutPoint, Option<u32>> = index
        .by_label
        .iter()
        .map(|&(label, outpoint)| (outpoint, label))
        .collect();
    let mut found = BTreeMap::new();
    for (outpoint, tweak) in &index.by_shared_secret {
        assert_eq!(
            outpoint.txid, txid,
            "{tag}: indexed an output of another tx"
        );
        let script = &tx.output[outpoint.vout as usize].script_pubkey;
        let xonly = XOnlyPublicKey::from_slice(&script.as_bytes()[2..]).expect("taproot output");
        let label = *labels
            .get(outpoint)
            .expect("every indexed output has a label entry");
        assert!(
            found.insert(xonly, (*tweak, label)).is_none(),
            "{tag}: output key indexed twice"
        );
    }
    (scanner, found)
}

/// The real receive step after a probable match, for every vector.
///
/// After [`official_vectors_reach_the_live_short_receive_path`] establishes that
/// the block is fetched, this pins what the daemon then *stores*: the vector
/// transaction is placed in a full block and handed through
/// `Scanner::apply_matched_block` (the production code that maps the oracle's
/// display-order txids to the block's transactions and calls
/// `apply_block_relevant` on the external indexer). The outputs the indexer
/// owns afterwards must be exactly the vector's `expected.outputs`, with the
/// vector's `priv_key_tweak` and a label that reproduces the output key.
///
/// The K_max vector is excluded here and has its own ignored test (SNB-540).
#[test]
fn official_vectors_live_receive_step_finds_expected_outputs() {
    let mut exercised = 0usize;
    let mut asserted_outputs = 0usize;
    let mut labelled_outputs = 0usize;

    for (case_idx, case) in vectors().iter().enumerate() {
        for (sub_idx, receiving) in case.receiving.iter().enumerate() {
            let what = format!("case {} sub {sub_idx} ({})", case_idx + 1, case.comment);
            let (given, expected) = (&receiving.given, &receiving.expected);
            if expected.n_outputs.is_some() {
                continue; // K_max: see the ignored SNB-540 test below.
            }
            let (tx, prevouts) = build_transaction(given);
            let Ok(tweak) = compute_tweak_data(&tx, &prevouts) else {
                continue; // no wire tweak; classified in the short-path test
            };
            let (scan_sk, spend_pk) = scan_keys(given);
            let shared_secret = bdk_sp::compute_shared_secret(&scan_sk, &tweak);

            let (scanner, found) = live_receive(
                given,
                &given.labels,
                &tx,
                tweak,
                &format!("live-{case_idx}-{sub_idx}"),
            );

            let found_tweaks: BTreeMap<XOnlyPublicKey, SecretKey> = found
                .iter()
                .map(|(key, (tweak, _))| (*key, *tweak))
                .collect();
            assert_eq!(
                found_tweaks,
                expected_outputs(expected),
                "{what}: live receive step outputs / priv_key_tweak"
            );

            // Each stored label must reproduce the output key at some k.
            for (key, (tweak, label)) in &found {
                if let Some(m) = label {
                    assert!(given.labels.contains(m), "{what}: stray label {m}");
                    labelled_outputs += 1;
                }
                let k = (0..given.outputs.len() as u32)
                    .find(|&k| tweak_for(shared_secret, scan_sk, k, *label) == *tweak)
                    .unwrap_or_else(|| panic!("{what}: tweak/label mismatch for {key}"));
                let label_pt = label.map(|m| label_point(scan_sk, m));
                let p_k = get_silentpayment_pubkey(&spend_pk, &shared_secret, k, label_pt.as_ref());
                assert_eq!(p_k.x_only_public_key().0, *key, "{what}: stored label");
            }

            // And the transaction is in the wallet graph iff something was found.
            let in_graph = scanner
                .internal_indexer
                .graph()
                .get_tx(tx.compute_txid())
                .is_some();
            assert_eq!(in_graph, !found.is_empty(), "{what}: wallet graph");
            let staged = scanner
                .stage
                .indexer
                .txid_to_partial_secret
                .contains_key(&tx.compute_txid());
            assert_eq!(staged, !found.is_empty(), "{what}: staged for persistence");

            asserted_outputs += found.len();
            exercised += 1;
        }
    }

    assert_eq!(
        exercised,
        SCANNED_SUBCASE_COUNT - K_MAX_SUBCASE_COUNT,
        "not every scannable non-K_max sub-case reached the live receive step"
    );
    assert_eq!(
        asserted_outputs, EXPECTED_OUTPUT_COUNT,
        "the fixture's per-output expectations were not all asserted on the live path"
    );
    assert_eq!(labelled_outputs, 10, "labelled-output coverage changed");
}

/// The live receive step stores each output at its real vout when the
/// transaction also pays non-taproot outputs: here a P2WPKH output sits in
/// front of every vector output, so vector output `i` is at vout `2i + 1`.
/// The external indexer numbers a transaction's outputs before it picks the
/// taproot ones (`bdk_sp::receive::scan_txouts`), and the stored outpoint is
/// what the wallet later spends. Every other receive test pays taproot
/// outputs only, where numbering before or after the filter agrees.
#[test]
fn official_vectors_live_receive_step_keeps_vouts_among_non_taproot_outputs() {
    let p2wpkh = TxOut {
        value: Amount::from_sat(1_000),
        script_pubkey: ScriptBuf::from_bytes([&[0x00, 0x14][..], &[0x42; 20]].concat()),
    };
    let mut exercised = 0usize;
    let mut asserted_outputs = 0usize;

    for (case_idx, case) in vectors().iter().enumerate() {
        for (sub_idx, receiving) in case.receiving.iter().enumerate() {
            let what = format!("case {} sub {sub_idx} ({})", case_idx + 1, case.comment);
            let (given, expected) = (&receiving.given, &receiving.expected);
            if expected.n_outputs.is_some() {
                continue; // K_max: see the ignored SNB-540 test below.
            }
            let (mut tx, prevouts) = build_transaction(given);
            tx.output = tx
                .output
                .into_iter()
                .flat_map(|out| [p2wpkh.clone(), out])
                .collect();
            let Ok(tweak) = compute_tweak_data(&tx, &prevouts) else {
                continue; // no wire tweak; classified in the short-path test
            };

            // `live_receive` reads each stored output's key at its stored
            // vout, so a vout counted among taproot outputs only would land
            // on a P2WPKH output (or another key) and fail here.
            let (scanner, found) = live_receive(
                given,
                &given.labels,
                &tx,
                tweak,
                &format!("live-vouts-{case_idx}-{sub_idx}"),
            );
            let found_tweaks: BTreeMap<XOnlyPublicKey, SecretKey> = found
                .iter()
                .map(|(key, (tweak, _))| (*key, *tweak))
                .collect();
            assert_eq!(
                found_tweaks,
                expected_outputs(expected),
                "{what}: outputs / priv_key_tweak among non-taproot outputs"
            );
            for outpoint in scanner.internal_indexer.index().by_shared_secret.keys() {
                assert_eq!(outpoint.vout % 2, 1, "{what}: stored at a P2WPKH vout");
            }

            asserted_outputs += found.len();
            exercised += 1;
        }
    }

    assert_eq!(
        exercised,
        SCANNED_SUBCASE_COUNT - K_MAX_SUBCASE_COUNT,
        "not every scannable non-K_max sub-case reached the live receive step"
    );
    assert_eq!(
        asserted_outputs, EXPECTED_OUTPUT_COUNT,
        "the fixture's per-output expectations were not all asserted"
    );
}

/// The BIP-352 recipient limit on the live receive path.
///
/// Ignored because it fails today: `apply_block_relevant` enforces no K_max, so
/// the live path stores one output more than BIP-352 allows on this vector.
/// That is SNB-540; this test is the acceptance check for it. It is also slow
/// (the external indexer's scan is quadratic in the 2324 outputs).
#[test]
#[ignore = "SNB-540: the live receive path enforces no K_max (stores 2324 of 2323)"]
fn official_vectors_live_receive_step_enforces_k_max() {
    let mut exercised = 0usize;
    for case in vectors() {
        for receiving in &case.receiving {
            let Some(n_outputs) = receiving.expected.n_outputs else {
                continue;
            };
            let given = &receiving.given;
            let (tx, prevouts) = build_transaction(given);
            let tweak = compute_tweak_data(&tx, &prevouts).expect("K_max vector inputs are valid");
            let (_, found) = live_receive(given, &given.labels, &tx, tweak, "live-kmax");
            assert_eq!(
                found.len(),
                n_outputs,
                "{}: receiver must stop at K_max",
                case.comment
            );
            exercised += 1;
        }
    }
    assert_eq!(exercised, K_MAX_SUBCASE_COUNT);
}

/// `Scanner::new` always registers the change label `m = 0`, even for the vectors
/// whose receiver registered no labels at all.
///
/// The other live tests model the vectors faithfully with exactly the vector's
/// labels (see [`blindbit_scanner`]); this test proves that choice does not hide a
/// defect in the label set a real `Scanner` carries. Every scanned sub-case is
/// run through the live receive step twice, with the vector's labels and with
/// the vector's labels *plus* `m = 0`, and must store the same outputs with the
/// same tweaks and labels: on these vectors the always-on change label produces
/// no false positive. The K_max vector is skipped: it registers `m = 0` itself,
/// and its scan is quadratic in its 2324 outputs.
#[test]
fn official_vectors_extra_change_label_is_harmless_on_the_live_path() {
    let mut compared = 0usize;
    let mut compared_outputs = 0usize;
    let mut change_label_added = 0usize;

    for (case_idx, case) in vectors().iter().enumerate() {
        for (sub_idx, receiving) in case.receiving.iter().enumerate() {
            let given = &receiving.given;
            if receiving.expected.n_outputs.is_some() {
                assert!(
                    given.labels.contains(&0),
                    "{}: K_max vector no longer registers the change label",
                    case.comment
                );
                continue;
            }
            let (tx, prevouts) = build_transaction(given);
            let Ok(tweak) = compute_tweak_data(&tx, &prevouts) else {
                continue; // no wire tweak; classified in the short-path test
            };

            let mut production_labels = given.labels.clone();
            if !production_labels.contains(&0) {
                production_labels.push(0);
                change_label_added += 1;
            }

            let (_, exact) = live_receive(
                given,
                &given.labels,
                &tx,
                tweak,
                &format!("live-exact-{case_idx}-{sub_idx}"),
            );
            let (_, with_change) = live_receive(
                given,
                &production_labels,
                &tx,
                tweak,
                &format!("live-change-{case_idx}-{sub_idx}"),
            );
            assert_eq!(
                exact, with_change,
                "{}: the always-registered change label m=0 changes what the live \
                 receive step stores",
                case.comment
            );
            compared_outputs += exact.len();
            compared += 1;
        }
    }

    assert_eq!(
        compared,
        SCANNED_SUBCASE_COUNT - K_MAX_SUBCASE_COUNT,
        "not every scanned non-K_max sub-case was compared"
    );
    assert_eq!(
        compared_outputs, EXPECTED_OUTPUT_COUNT,
        "the comparison did not cover every expected output"
    );
    assert_eq!(
        change_label_added,
        SCANNED_SUBCASE_COUNT - K_MAX_SUBCASE_COUNT - 1,
        "exactly one non-K_max sub-case (the sender-change vector) registers m=0 itself"
    );
}
