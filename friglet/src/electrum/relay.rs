//! Transaction broadcast that reports what the P2P peer actually did.
//!
//! Bitcoin's P2P protocol has no acknowledgement and, since Bitcoin Core
//! 0.20, no reject message, so "sent" says nothing about "accepted". What the
//! protocol does allow, and what this module uses:
//!
//! 1. Announce with `inv`; the peer answers `getdata` when it wants the
//!    transaction (it does not when it already has it or rejected it
//!    recently). Hand it over then.
//! 2. Ask with `getdata` whether the transaction is in the peer's mempool.
//!    Bitcoin Core answers with the transaction once it has accepted it and
//!    its next announcement round for this connection has passed (about five
//!    seconds on average for an inbound connection), and with `notfound`
//!    otherwise. That is the success criterion: the same one
//!    `sendrawtransaction` uses.
//! 3. Negative evidence ends the wait early: the peer asking for one of the
//!    transaction's parents means it lacks its inputs; the peer dropping the
//!    connection right after receiving it is what Bitcoin Core does for a
//!    consensus-invalid transaction.
//!
//! Everything else — non-standard, a conflict it does not pay enough to
//! replace, a fee below the peer's mempool minimum — looks the same from
//! outside: the transaction never shows up. The error then says so, and
//! names the fee shortfall when the fee is known.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use bitcoin::{Transaction, Txid, Wtxid};
use bitcoin_p2p::p2p_message_types::message::{InventoryPayload, NetworkMessage};
use bitcoin_p2p::p2p_message_types::message_blockdata::Inventory;
use bitcoin_rev::Network;
use bitcoin_rev::consensus::encode;

use super::p2p::{P2pError, Peer, SETTLE_WAIT, inventory_matches};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Bitcoin Core requests an announced transaction after 2 s from an inbound
/// peer, more when it is busy.
const ANNOUNCE_WAIT: Duration = Duration::from_secs(5);
const POLL_INTERVAL: Duration = Duration::from_secs(1);

/// `MAX_MONEY` in Bitcoin Core.
const MAX_MONEY: u64 = 21_000_000 * 100_000_000;
/// `MAX_BLOCK_WEIGHT`: nothing heavier can ever be mined.
const MAX_WEIGHT: u64 = 4_000_000;

/// A decoded transaction ready to broadcast.
pub struct Candidate {
    pub raw: Vec<u8>,
    pub tx: Transaction,
    pub txid: Txid,
    pub wtxid: Wtxid,
    pub vsize: u64,
    /// Fee in sat, when every spent output is known locally (the wallet's
    /// own outputs are).
    pub fee: Option<u64>,
}

impl Candidate {
    pub fn decode(raw: Vec<u8>) -> Result<Self, String> {
        // `deserialize` also refuses trailing bytes.
        let tx: Transaction = bitcoin::consensus::encode::deserialize(&raw)
            .map_err(|error| format!("TX decode failed: {error}"))?;
        Ok(Self {
            txid: tx.compute_txid(),
            wtxid: tx.compute_wtxid(),
            vsize: tx.vsize() as u64,
            raw,
            tx,
            fee: None,
        })
    }

    /// The transaction as the P2P library's type.
    fn wire_tx(&self) -> Result<bitcoin_rev::Transaction, P2pError> {
        encode::deserialize(&self.raw)
            .map_err(|error| P2pError::Protocol(format!("transaction re-encoding failed: {error}")))
    }

    fn fee_rate_note(&self) -> String {
        match self.fee {
            Some(fee) => format!(
                " The transaction pays {fee} sat ({:.2} sat/vB).",
                fee as f64 / self.vsize as f64
            ),
            None => String::new(),
        }
    }
}

/// The context-free checks Bitcoin Core runs first (`CheckTransaction`),
/// with its reject reasons. Refusing these here keeps an obviously broken
/// transaction from costing the connection to the peer.
pub fn check_transaction(tx: &Transaction) -> Result<(), String> {
    if tx.input.is_empty() {
        return Err("bad-txns-vin-empty: the transaction has no inputs".into());
    }
    if tx.output.is_empty() {
        return Err("bad-txns-vout-empty: the transaction has no outputs".into());
    }
    if tx.weight().to_wu() > MAX_WEIGHT {
        return Err("bad-txns-oversize: the transaction is heavier than a block".into());
    }
    let mut total: u64 = 0;
    for output in &tx.output {
        let value = output.value.to_sat();
        if value > MAX_MONEY {
            return Err("bad-txns-vout-toolarge: an output exceeds 21 million BTC".into());
        }
        total = total.saturating_add(value);
        if total > MAX_MONEY {
            return Err("bad-txns-txouttotal-toolarge: the outputs exceed 21 million BTC".into());
        }
    }
    let mut spent = std::collections::HashSet::with_capacity(tx.input.len());
    for input in &tx.input {
        if !spent.insert(input.previous_output) {
            return Err("bad-txns-inputs-duplicate: an output is spent twice".into());
        }
    }
    if tx.is_coinbase() {
        return Err("coinbase: a coinbase transaction cannot be broadcast".into());
    }
    if tx.input.iter().any(|input| input.previous_output.is_null()) {
        return Err("bad-txns-prevout-null: an input spends a null outpoint".into());
    }
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The transaction is in the peer's mempool.
    InMempool,
    /// The peer refused it: it dropped the connection after receiving it, or
    /// it lacks the inputs. The message is meant for the wallet user.
    Rejected(String),
    /// The peer did not have it in its mempool when the wait ended. Most
    /// likely refused, but it may still be accepted a moment later.
    NotAccepted(String),
}

/// What the peer revealed while we waited.
#[derive(Default)]
struct Signals {
    /// The transaction went to the peer.
    sent: bool,
    /// The peer asked for another transaction: a parent of ours.
    missing_inputs: bool,
}

impl Signals {
    fn observe(
        &mut self,
        peer: &mut Peer,
        message: NetworkMessage,
        wire_tx: &bitcoin_rev::Transaction,
        txid: Txid,
        wtxid: Wtxid,
    ) -> Result<(), P2pError> {
        let NetworkMessage::GetData(items) = message else {
            return Ok(());
        };
        let mut unknown = Vec::new();
        for item in items.0 {
            if inventory_matches(&item, txid, wtxid) {
                peer.send(NetworkMessage::Tx(wire_tx.clone()))?;
                self.sent = true;
            } else {
                if matches!(
                    item,
                    Inventory::Transaction(_)
                        | Inventory::WitnessTransaction(_)
                        | Inventory::WTx(_)
                ) && self.sent
                {
                    self.missing_inputs = true;
                }
                unknown.push(item);
            }
        }
        if !unknown.is_empty() {
            peer.send(NetworkMessage::NotFound(InventoryPayload(unknown)))?;
        }
        Ok(())
    }

    /// Announce the transaction with `inv` and hand it over if the peer asks
    /// for it before `deadline`.
    fn announce(
        &mut self,
        peer: &mut Peer,
        wire_tx: &bitcoin_rev::Transaction,
        txid: Txid,
        wtxid: Wtxid,
        deadline: Instant,
    ) -> Result<(), P2pError> {
        let inventory = peer.tx_inventory(txid, wtxid);
        peer.send(NetworkMessage::Inv(InventoryPayload(vec![inventory])))?;
        while !self.sent {
            match peer.recv_until(deadline)? {
                Some(message) => self.observe(peer, message, wire_tx, txid, wtxid)?,
                None => break,
            }
        }
        Ok(())
    }
}

/// Connect with transaction relay on and wait for the peer to settle.
fn connect_settled(addr: SocketAddr, network: Network) -> Result<Peer, P2pError> {
    let mut peer = Peer::connect(addr, network, true, CONNECT_TIMEOUT)?;
    peer.wait_until_settled(Instant::now() + SETTLE_WAIT)?;
    Ok(peer)
}

/// Broadcast `candidate` to the peer and wait up to `budget` for it to show
/// up in the peer's mempool. Blocking. `Err` means the peer could not be
/// asked at all; a transaction the peer did not take is `Ok(Rejected)`.
/// Also returns the peer's fee filter (sat/kvB) when it sent one.
pub fn broadcast(
    addr: SocketAddr,
    network: Network,
    candidate: &Candidate,
    budget: Duration,
) -> Result<(Outcome, Option<u64>), P2pError> {
    let deadline = Instant::now() + budget;
    let wire_tx = candidate.wire_tx()?;
    let mut peer = connect_settled(addr, network)?;
    let mut signals = Signals::default();
    let outcome = match drive(&mut peer, &mut signals, candidate, &wire_tx, deadline) {
        Ok(Some(outcome)) => outcome,
        Ok(None) => {
            Outcome::NotAccepted(not_accepted_message(candidate, peer.fee_filter(), budget))
        }
        // Before the hand-over a dropped connection says nothing about the
        // transaction; after it, it is the peer's answer.
        Err(P2pError::Closed) if signals.sent => Outcome::Rejected(disconnected_message()),
        Err(error) => return Err(error),
    };
    Ok((outcome, peer.fee_filter()))
}

/// The broadcast conversation; `Ok(None)` when the deadline passes without
/// an answer either way.
fn drive(
    peer: &mut Peer,
    signals: &mut Signals,
    candidate: &Candidate,
    wire_tx: &bitcoin_rev::Transaction,
    deadline: Instant,
) -> Result<Option<Outcome>, P2pError> {
    let (txid, wtxid) = (candidate.txid, candidate.wtxid);

    // A resubmission (or a retry after a client timeout) finds it already
    // there.
    let check_deadline = deadline.min(Instant::now() + ANNOUNCE_WAIT);
    if peer.mempool_has(txid, wtxid, check_deadline, |p, m| {
        signals.observe(p, m, wire_tx, txid, wtxid)
    })? {
        return Ok(Some(Outcome::InMempool));
    }

    let ask_deadline = deadline.min(Instant::now() + ANNOUNCE_WAIT);
    signals.announce(peer, wire_tx, txid, wtxid, ask_deadline)?;
    if !signals.sent {
        // No request: the peer knows the transaction already (it is not in
        // its mempool, so it rejected or confirmed it recently) or ignores
        // announcements. Hand it over anyway and let the mempool decide.
        tracing::debug!(%txid, "peer did not request the announced transaction; sending it");
        peer.send(NetworkMessage::Tx(wire_tx.clone()))?;
        signals.sent = true;
    }

    while Instant::now() < deadline {
        if signals.missing_inputs {
            return Ok(Some(Outcome::Rejected(missing_inputs_message())));
        }
        let in_mempool = match peer.mempool_has(txid, wtxid, deadline, |p, m| {
            signals.observe(p, m, wire_tx, txid, wtxid)
        }) {
            Ok(answer) => answer,
            Err(P2pError::Timeout(_)) => return Ok(None),
            Err(error) => return Err(error),
        };
        if in_mempool {
            return Ok(Some(Outcome::InMempool));
        }
        let pause = deadline.min(Instant::now() + POLL_INTERVAL);
        while let Some(message) = peer.recv_until(pause)? {
            signals.observe(peer, message, wire_tx, txid, wtxid)?;
        }
    }
    if signals.missing_inputs {
        return Ok(Some(Outcome::Rejected(missing_inputs_message())));
    }
    Ok(None)
}

/// Is the transaction in the peer's mempool now? Blocking.
pub fn in_mempool(
    addr: SocketAddr,
    network: Network,
    candidate: &Candidate,
) -> Result<bool, P2pError> {
    let mut peer = connect_settled(addr, network)?;
    peer.mempool_has(
        candidate.txid,
        candidate.wtxid,
        Instant::now() + ANNOUNCE_WAIT,
        |_, _| Ok(()),
    )
}

/// Ask whether each transaction is in the peer's mempool and re-announce the
/// ones that are not. Used for pending broadcasts; does not wait for
/// acceptance. Returns, per transaction, whether it was in the mempool.
pub fn recheck(
    addr: SocketAddr,
    network: Network,
    candidates: &[Candidate],
) -> Result<(Vec<bool>, Option<u64>), P2pError> {
    let mut peer = connect_settled(addr, network)?;
    let mut present = Vec::with_capacity(candidates.len());
    for candidate in candidates {
        let wire_tx = candidate.wire_tx()?;
        let (txid, wtxid) = (candidate.txid, candidate.wtxid);
        let mut signals = Signals::default();
        let in_mempool =
            peer.mempool_has(txid, wtxid, Instant::now() + ANNOUNCE_WAIT, |p, m| {
                signals.observe(p, m, &wire_tx, txid, wtxid)
            })?;
        if !in_mempool {
            let ask_deadline = Instant::now() + ANNOUNCE_WAIT;
            signals.announce(&mut peer, &wire_tx, txid, wtxid, ask_deadline)?;
            if signals.sent {
                peer.flush(Instant::now() + ANNOUNCE_WAIT)?;
            }
            tracing::info!(
                %txid,
                requested = signals.sent,
                "pending transaction was not in the peer's mempool; re-announced it"
            );
        }
        present.push(in_mempool);
    }
    Ok((present, peer.fee_filter()))
}

fn missing_inputs_message() -> String {
    "bad-txns-inputs-missingorspent: the P2P peer asked for a parent of this transaction, so it \
     does not have the outputs it spends: they are already spent, or their transaction is \
     unknown to the peer."
        .into()
}

fn disconnected_message() -> String {
    "the P2P peer disconnected right after receiving the transaction. Bitcoin Core does that \
     when a transaction is consensus-invalid, for example when a signature does not verify."
        .into()
}

fn not_accepted_message(
    candidate: &Candidate,
    fee_filter: Option<u64>,
    waited: Duration,
) -> String {
    if let (Some(fee), Some(filter)) = (candidate.fee, fee_filter) {
        let required = (filter * candidate.vsize).div_ceil(1000);
        if fee < required {
            // Sparrow recognises this wording (Bitcoin Core's reject reason as
            // ElectrumX relays it) and tells the user the fee to pay.
            return format!(
                "the transaction was rejected by network rules.\n\nmempool min fee not met, \
                 {fee} < {required}\n\nInferred by friglet: the P2P peer did not accept the \
                 transaction, which pays {:.2} sat/vB, and its mempool currently accepts no \
                 less than {:.2} sat/vB.",
                fee as f64 / candidate.vsize as f64,
                filter as f64 / 1000.0,
            );
        }
    }
    format!(
        "the P2P peer did not accept the transaction into its mempool within {} seconds. The P2P \
         protocol does not report why; common causes are a conflict with a mempool transaction \
         this one does not pay enough to replace, a non-standard transaction, or a peer that is \
         still syncing.{}",
        waited.as_secs(),
        candidate.fee_rate_note(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::absolute::LockTime;
    use bitcoin::transaction::Version;
    use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, TxIn, TxOut, Witness};

    fn tx(inputs: Vec<OutPoint>, outputs: Vec<u64>) -> Transaction {
        Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: inputs
                .into_iter()
                .map(|previous_output| TxIn {
                    previous_output,
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                })
                .collect(),
            output: outputs
                .into_iter()
                .map(|sat| TxOut {
                    value: Amount::from_sat(sat),
                    script_pubkey: ScriptBuf::new(),
                })
                .collect(),
        }
    }

    fn outpoint(byte: u8, vout: u32) -> OutPoint {
        OutPoint {
            txid: bitcoin::hashes::Hash::from_byte_array([byte; 32]),
            vout,
        }
    }

    fn reason(tx: &Transaction) -> String {
        let error = check_transaction(tx).unwrap_err();
        error.split(':').next().unwrap().to_string()
    }

    #[test]
    fn context_free_checks_use_core_reject_reasons() {
        assert!(check_transaction(&tx(vec![outpoint(1, 0)], vec![1000])).is_ok());
        assert_eq!(reason(&tx(vec![], vec![1000])), "bad-txns-vin-empty");
        assert_eq!(
            reason(&tx(vec![outpoint(1, 0)], vec![])),
            "bad-txns-vout-empty"
        );
        assert_eq!(
            reason(&tx(vec![outpoint(1, 0)], vec![MAX_MONEY + 1])),
            "bad-txns-vout-toolarge"
        );
        assert_eq!(
            reason(&tx(vec![outpoint(1, 0)], vec![MAX_MONEY, 1])),
            "bad-txns-txouttotal-toolarge"
        );
        assert_eq!(
            reason(&tx(vec![outpoint(1, 0), outpoint(1, 0)], vec![1000])),
            "bad-txns-inputs-duplicate"
        );
        assert_eq!(reason(&tx(vec![OutPoint::null()], vec![1000])), "coinbase");
        assert_eq!(
            reason(&tx(vec![outpoint(1, 0), OutPoint::null()], vec![1000])),
            "bad-txns-prevout-null"
        );
    }

    #[test]
    fn decode_refuses_garbage_and_trailing_bytes() {
        assert!(Candidate::decode(vec![0xde, 0xad]).is_err());
        let mut raw = bitcoin::consensus::encode::serialize(&tx(vec![outpoint(1, 0)], vec![1000]));
        assert!(Candidate::decode(raw.clone()).is_ok());
        raw.push(0);
        assert!(Candidate::decode(raw).is_err());
    }

    #[test]
    fn fee_shortfall_uses_the_wording_sparrow_parses() {
        let mut candidate = Candidate::decode(bitcoin::consensus::encode::serialize(&tx(
            vec![outpoint(1, 0)],
            vec![1000],
        )))
        .unwrap();
        candidate.fee = Some(10);
        let vsize = candidate.vsize;
        // Peer minimum 1 sat/vB (1000 sat/kvB): the fee is short.
        let message = not_accepted_message(&candidate, Some(1000), Duration::from_secs(25));
        // Sparrow's MIN_MEMPOOL_FEE pattern.
        assert!(message.starts_with("the transaction was rejected by network rules."));
        assert!(message.contains(&format!("mempool min fee not met, 10 < {vsize}\n")));

        // Enough fee: the honest "don't know why" message, with the fee.
        candidate.fee = Some(vsize * 2);
        let message = not_accepted_message(&candidate, Some(1000), Duration::from_secs(25));
        assert!(message.starts_with("the P2P peer did not accept the transaction"));
        assert!(message.contains("2.00 sat/vB"));

        // Unknown fee: no fee claims at all.
        candidate.fee = None;
        let message = not_accepted_message(&candidate, Some(1000), Duration::from_secs(25));
        assert!(!message.contains("sat/vB"));
    }

    use crate::electrum::fake_peer::{FakePeer, Script, TxPolicy};

    fn candidate(seed: u8) -> Candidate {
        Candidate::decode(bitcoin::consensus::encode::serialize(&tx(
            vec![outpoint(seed, 0)],
            vec![5_000],
        )))
        .unwrap()
    }

    fn run(script: Script, candidate: &Candidate, budget: Duration) -> (Outcome, FakePeer) {
        let peer = FakePeer::spawn(script, 1);
        let (outcome, fee_filter) =
            broadcast(peer.addr, Network::Regtest, candidate, budget).unwrap();
        assert_eq!(fee_filter, Some(1000), "the peer's feefilter is read");
        (outcome, peer)
    }

    #[test]
    fn accepted_only_once_the_peer_serves_it_from_its_mempool() {
        let candidate = candidate(1);
        let (outcome, peer) = run(Script::default(), &candidate, Duration::from_secs(10));
        assert_eq!(outcome, Outcome::InMempool);
        let commands = peer.commands();
        // Asked first, announced, handed over on request, then asked again.
        let inv = commands.iter().position(|c| c == "inv").unwrap();
        let tx = commands.iter().position(|c| c == "tx").unwrap();
        assert!(commands[..inv].contains(&"getdata".to_string()));
        assert!(inv < tx);
        assert!(commands[tx..].contains(&"getdata".to_string()));
    }

    #[test]
    fn a_transaction_already_in_the_mempool_is_not_sent_again() {
        let candidate = candidate(2);
        let script = Script {
            mempool: vec![candidate.raw.clone()],
            ..Script::default()
        };
        let (outcome, peer) = run(script, &candidate, Duration::from_secs(10));
        assert_eq!(outcome, Outcome::InMempool);
        assert!(!peer.commands().iter().any(|c| c == "inv" || c == "tx"));
    }

    #[test]
    fn a_silently_dropped_transaction_is_reported_as_not_accepted() {
        let candidate = candidate(3);
        let script = Script {
            policy: TxPolicy::Ignore,
            ..Script::default()
        };
        let (outcome, _peer) = run(script, &candidate, Duration::from_secs(3));
        let Outcome::NotAccepted(message) = outcome else {
            panic!("expected an inconclusive rejection");
        };
        assert!(
            message.starts_with("the P2P peer did not accept the transaction"),
            "{message}"
        );
    }

    #[test]
    fn a_disconnect_after_the_hand_over_is_a_rejection() {
        let candidate = candidate(4);
        let script = Script {
            policy: TxPolicy::Disconnect,
            ..Script::default()
        };
        let (outcome, _peer) = run(script, &candidate, Duration::from_secs(10));
        assert_eq!(outcome, Outcome::Rejected(disconnected_message()));
    }

    #[test]
    fn a_parent_request_means_missing_inputs() {
        let candidate = candidate(5);
        let script = Script {
            policy: TxPolicy::Orphan,
            ..Script::default()
        };
        let (outcome, _peer) = run(script, &candidate, Duration::from_secs(10));
        let Outcome::Rejected(message) = outcome else {
            panic!("expected a rejection");
        };
        // Sparrow keys its "inputs missing or spent" dialog on this prefix.
        assert!(
            message.starts_with("bad-txns-inputs-missingorspent"),
            "{message}"
        );
    }

    #[test]
    fn an_unrequested_announcement_is_followed_by_the_transaction() {
        let candidate = candidate(6);
        let script = Script {
            request_announced: false,
            ..Script::default()
        };
        let (outcome, peer) = run(script, &candidate, Duration::from_secs(15));
        assert_eq!(outcome, Outcome::InMempool);
        assert!(peer.commands().iter().any(|c| c == "tx"));
    }

    #[test]
    fn an_unreachable_peer_is_an_error_not_a_rejection() {
        let unused = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = unused.local_addr().unwrap();
        drop(unused);
        assert!(
            broadcast(
                addr,
                Network::Regtest,
                &candidate(7),
                Duration::from_secs(3)
            )
            .is_err()
        );
    }

    #[test]
    fn recheck_reannounces_only_what_the_mempool_lost() {
        let kept = candidate(8);
        let lost = candidate(9);
        let script = Script {
            mempool: vec![kept.raw.clone()],
            ..Script::default()
        };
        let peer = FakePeer::spawn(script, 1);
        let (present, _) = recheck(peer.addr, Network::Regtest, &[kept, lost]).unwrap();
        assert_eq!(present, vec![true, false]);
        // recheck returns right after handing the transaction over; give the
        // peer's thread a moment to record it.
        let deadline = Instant::now() + Duration::from_secs(2);
        while !peer.commands().iter().any(|c| c == "tx") && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        let commands = peer.commands();
        assert_eq!(commands.iter().filter(|c| *c == "inv").count(), 1);
        assert_eq!(commands.iter().filter(|c| *c == "tx").count(), 1);
    }
}
