//! Broadcast through peers of the network (no own node configured): hand
//! the transaction to a few peers, and call it accepted only once a peer it
//! was *not* handed to serves it.
//!
//! One random peer's word is worth little: it may lie, be behind, or keep
//! the transaction to itself. So the connections of one broadcast have
//! separate roles:
//!
//! - **Observers** ([`OBSERVERS`]): opened first, with transaction relay on,
//!   and settled before anything is sent. Only peers whose `version` says
//!   they relay transactions (not blocks-only nodes).
//! - **Senders** ([`SENDERS`]): opened once observers are ready, with relay
//!   off and nothing else asked for, like Bitcoin Core 31's private
//!   broadcast: `inv`, the peer's `getdata`, `tx`, then `ping`/`pong` so the
//!   peer has processed it. Then they only listen.
//! - Every peer of a broadcast is in a different network group (/16, /32),
//!   so observers and senders are unlikely to share an operator.
//!
//! Success is an observer serving the transaction: to friglet's `getdata`
//! every [`POLL_INTERVAL`], or right after the observer announced it with
//! `inv`. Nothing a sender says counts as success. A rejection needs every
//! sender that got the transaction to give the same answer: all asked for a
//! parent (missing or spent inputs), or all dropped the connection before
//! the pong (what Bitcoin Core does with a consensus-invalid transaction).
//! Anything else runs until the budget ends, as "not confirmed".
//!
//! Pending broadcasts are rechecked the same way: peers they were not handed
//! to are asked, and a lost one is handed to one of those
//! ([`ask_mempools`], [`hand_over`]).
//!
//! Every connection goes through the pool's [`Dialer`](blindbit_lib::net::Dialer):
//! [`connect`] is the only place one is opened. Through a proxy (Tor,
//! `p2p_proxy`) each one gets a circuit of its own, so no exit relay sees
//! both an observer and a sender, and the waits are longer ([`Timing`]).

use std::collections::{HashMap, HashSet};
use std::net::{Shutdown, TcpStream};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use bitcoin::p2p::message::NetworkMessage;
use bitcoin::{Txid, Wtxid};
use blindbit_lib::net::{NetGroup, PeerAddr, PeerEvent, PeerSource, Purpose};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use super::p2p::{P2pError, Peer, SETTLE_WAIT, inventory_matches, random_u64};
use super::relay::{self, Candidate, Signals};

/// Peers that watch for the transaction.
const OBSERVERS: usize = 3;
/// Peers the transaction is handed to.
const SENDERS: usize = 2;
/// Raised to the dialer's `PROXY_CONNECT_TIMEOUT` (20 s) through a proxy.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// How often an observer is asked for the transaction.
const POLL_INTERVAL: Duration = Duration::from_secs(2);
/// Bitcoin Core requests an announced transaction after 2 s from an inbound
/// peer, later when it is busy; also the wait for a mempool answer.
const ANNOUNCE_WAIT: Duration = Duration::from_secs(5);
/// How long a sender waits for the pong that follows the transaction
/// (directly; see [`Timing::flush_wait`]).
const FLUSH_WAIT: Duration = Duration::from_secs(5);
/// How often blocking loops look at the stop token.
const STOP_CHECK: Duration = Duration::from_millis(250);

/// How a broadcast ended, unless no peer could be asked.
#[derive(Debug)]
pub struct Report {
    pub verdict: Verdict,
    /// The peers the transaction was handed to.
    pub sent_to: Vec<PeerAddr>,
    /// Fee filters (sat/kvB) the observers sent.
    pub fee_filters: Vec<(PeerAddr, u64)>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    /// `by`, a peer the transaction was not handed to, served it.
    InMempool { by: PeerAddr },
    /// Every sender asked for a parent: its inputs are missing or spent.
    /// The message is for the user.
    Rejected(String),
    /// Every sender dropped the connection before answering the ping after
    /// the transaction, which Bitcoin Core does with a consensus-invalid
    /// transaction. A peer can also just go away, so this is not final.
    Dropped(String),
    /// No observer had it `waited` after the first hand-over (observers that
    /// went away are replaced while the pool has peers).
    Unconfirmed { waited: Duration },
}

/// How a broadcast paces its connections.
///
/// Through a proxy (Tor) a connection first gets a circuit (1 to 5 s to a
/// live peer, measured on signet), and an address nobody answers at costs
/// the dialer's whole 20 s connect timeout: Tor keeps trying instead of
/// failing fast, and many gossiped addresses are dead. So more observers
/// are opened at once, more are added while too few are up ("hedging",
/// senders too), senders wait longer for observers, and the broadcast
/// itself gets a longer budget (`PROXIED_BROADCAST_BUDGET` in the Electrum
/// server, 45 s).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Timing {
    /// Observer connections opened at the start.
    observers_at_start: usize,
    /// Connection attempts per role, replacements and hedges included.
    observer_tries: usize,
    sender_tries: usize,
    /// Senders start once every observer is ready, or with at least one
    /// ready this long after the start.
    observer_window: Duration,
    /// With no observer ready by then, the broadcast ends without sending.
    observer_limit: Duration,
    /// While too few observers are ready, or too few senders have handed
    /// the transaction over, start more this often: a connection not up
    /// by then is probably to a dead address.
    hedge_every: Option<Duration>,
    /// How long a sender waits for the pong that follows the transaction:
    /// a sender that gets none says nothing about the transaction.
    flush_wait: Duration,
}

impl Timing {
    const DIRECT: Self = Self {
        observers_at_start: OBSERVERS,
        observer_tries: 9,
        sender_tries: 6,
        observer_window: Duration::from_secs(5),
        observer_limit: Duration::from_secs(12),
        hedge_every: None,
        flush_wait: FLUSH_WAIT,
    };

    /// Through Tor: six observers at the start and more every 6 s while
    /// fewer than three are ready (a live peer is up in 1 to 5 s plus the
    /// 2 s settle wait); senders likewise. The window covers a slower
    /// circuit; the limit, two rounds of hedging after the first dead
    /// addresses time out (20 s). The pong crosses a circuit (on signet one
    /// took over 5 s).
    const PROXIED: Self = Self {
        observers_at_start: 2 * OBSERVERS,
        observer_tries: 18,
        sender_tries: 8,
        observer_window: Duration::from_secs(15),
        observer_limit: Duration::from_secs(30),
        hedge_every: Some(Duration::from_secs(6)),
        flush_wait: Duration::from_secs(15),
    };

    fn for_peers(peers: &PeerSource) -> Self {
        if peers.dialer().proxy().is_some() {
            Self::PROXIED
        } else {
            Self::DIRECT
        }
    }
}

/// What one connection reports to the broadcast.
#[derive(Debug)]
enum Event {
    /// An observer is settled and watching.
    Ready {
        addr: PeerAddr,
        fee_filter: Option<u64>,
    },
    /// An observer served the transaction.
    Seen { addr: PeerAddr, announced: bool },
    /// A sender handed the transaction over.
    HandedOver { addr: PeerAddr },
    /// A sender's peer refused the transaction.
    Refused { addr: PeerAddr, signal: Signal },
    /// The proxy every connection goes through failed (`p2p_proxy`): no
    /// peer can be reached, and none is to blame.
    ProxyDown { error: String },
    /// The connection ended (failed, closed, or stopped).
    Gone { addr: PeerAddr },
}

/// How a sender's peer refused the transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Signal {
    /// It asked for a parent: it lacks the inputs.
    MissingInputs,
    /// It dropped the connection before answering the ping that followed
    /// the transaction.
    Dropped,
}

/// What every connection of one broadcast shares.
#[derive(Clone)]
struct Job {
    peers: Arc<PeerSource>,
    candidate: Arc<Candidate>,
    stop: CancellationToken,
    deadline: Instant,
    events: mpsc::UnboundedSender<Event>,
    ledger: Arc<Mutex<Ledger>>,
}

/// Who may hold the transaction and whether anyone else may get it, for
/// every connection of one broadcast. A peer goes in before the bytes are
/// written to it, under the lock that ends the broadcast ([`Job::close`]):
/// the final list has every peer that may hold it, and nobody gets it
/// afterwards.
#[derive(Default)]
struct Ledger {
    closed: bool,
    /// (transaction, peer), in the order they were let through.
    handed: Vec<(Txid, PeerAddr)>,
    /// Hand-over slots taken ([`Job::claim_hand_over`]): with hedged
    /// senders, no more than [`SENDERS`] hand the transaction over.
    slots_taken: usize,
    /// Open connections, shut down when the broadcast ends.
    sockets: Vec<(u64, TcpStream)>,
    next_socket: u64,
}

impl Job {
    fn new(
        peers: Arc<PeerSource>,
        candidate: Arc<Candidate>,
        deadline: Instant,
        events: mpsc::UnboundedSender<Event>,
    ) -> Self {
        Self {
            peers,
            candidate,
            stop: CancellationToken::new(),
            deadline,
            events,
            ledger: Arc::default(),
        }
    }

    fn tell(&self, event: Event) {
        // The broadcast may have ended already; nobody listens then.
        let _ = self.events.send(event);
    }

    fn over(&self) -> bool {
        self.stop.is_cancelled() || Instant::now() >= self.deadline
    }

    fn ledger(&self) -> MutexGuard<'_, Ledger> {
        // A panic while holding it leaves nothing half-updated that matters.
        self.ledger.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Take one of the [`SENDERS`] hand-over slots; `false` when they are
    /// all taken or the broadcast has ended.
    fn claim_hand_over(&self) -> bool {
        let mut ledger = self.ledger();
        if ledger.closed || ledger.slots_taken >= SENDERS {
            return false;
        }
        ledger.slots_taken += 1;
        true
    }

    /// Give a slot back: the sender did not hand the transaction over.
    fn release_hand_over(&self) {
        let mut ledger = self.ledger();
        ledger.slots_taken = ledger.slots_taken.saturating_sub(1);
    }

    /// Shut `peer`'s connection down when the broadcast ends, until the
    /// returned guard drops. An error, and the connection shut down, when
    /// it has ended already.
    fn register(&self, peer: &Peer) -> Result<Registered, P2pError> {
        let socket = peer.closer()?;
        let mut ledger = self.ledger();
        if ledger.closed {
            let _ = socket.shutdown(Shutdown::Both);
            return Err(P2pError::Protocol("the broadcast has ended".into()));
        }
        let id = ledger.next_socket;
        ledger.next_socket += 1;
        ledger.sockets.push((id, socket));
        Ok(Registered {
            ledger: self.ledger.clone(),
            id,
        })
    }

    /// May `txid` be written to `addr` now? If so, `addr` is in the final
    /// list from here on.
    fn may_send(&self, addr: &PeerAddr, txid: Txid) -> bool {
        let mut ledger = self.ledger();
        if ledger.closed || self.over() {
            return false;
        }
        let entry = (txid, addr.clone());
        if !ledger.handed.contains(&entry) {
            ledger.handed.push(entry);
        }
        true
    }

    /// Signals for a sender to `addr`: the transaction is written only
    /// through [`Job::may_send`].
    fn signals_for(&self, addr: &PeerAddr) -> Signals {
        let (job, addr) = (self.clone(), addr.clone());
        Signals::gated(Box::new(move |txid| job.may_send(&addr, txid)))
    }

    /// End the broadcast: nothing more is handed over, and every connection
    /// still open is shut down. Returns every (transaction, peer) let
    /// through, in order.
    fn close(&self) -> Vec<(Txid, PeerAddr)> {
        let mut ledger = self.ledger();
        ledger.closed = true;
        self.stop.cancel();
        for (_, socket) in ledger.sockets.drain(..) {
            let _ = socket.shutdown(Shutdown::Both);
        }
        ledger.handed.clone()
    }
}

/// A connection [`Job::close`] shuts down; dropped with the connection.
struct Registered {
    ledger: Arc<Mutex<Ledger>>,
    id: u64,
}

impl Drop for Registered {
    fn drop(&mut self) {
        let mut ledger = self.ledger.lock().unwrap_or_else(|e| e.into_inner());
        ledger.sockets.retain(|(id, _)| *id != self.id);
    }
}

/// Closes the broadcast's [`Job`] on every way out of [`broadcast`].
struct CloseOnDrop(Job);

impl Drop for CloseOnDrop {
    fn drop(&mut self) {
        self.0.close();
    }
}

/// Where a peer of the broadcast stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Watching { ready: bool },
    ObserverGone,
    Sending { handed_over: bool },
    SenderGone { handed_over: bool },
}

/// The broadcast's book-keeping, driven by [`Event`]s.
struct Round {
    timing: Timing,
    started: Instant,
    peers: HashMap<PeerAddr, State>,
    /// Peers in the order they were handed the transaction.
    sent_to: Vec<PeerAddr>,
    /// When the first of them got it.
    handed_over_at: Option<Instant>,
    refused: HashMap<PeerAddr, Signal>,
    fee_filters: Vec<(PeerAddr, u64)>,
    observer_tries: usize,
    sender_tries: usize,
    senders_started: bool,
    seen_by: Option<PeerAddr>,
    /// Why the pool had no further peer, if it ran out.
    no_peers: Option<String>,
    /// The proxy failed: nothing more is tried.
    proxy_down: Option<String>,
}

impl Round {
    fn new(timing: Timing) -> Self {
        Self {
            timing,
            started: Instant::now(),
            peers: HashMap::new(),
            sent_to: Vec::new(),
            handed_over_at: None,
            refused: HashMap::new(),
            fee_filters: Vec::new(),
            observer_tries: 0,
            sender_tries: 0,
            senders_started: false,
            seen_by: None,
            no_peers: None,
            proxy_down: None,
        }
    }

    fn count(&self, wanted: impl Fn(State) -> bool) -> usize {
        self.peers.values().filter(|state| wanted(**state)).count()
    }

    fn observers_ready(&self) -> usize {
        self.count(|s| s == State::Watching { ready: true })
    }

    fn observers_connecting(&self) -> usize {
        self.count(|s| s == State::Watching { ready: false })
    }

    fn senders_connecting(&self) -> usize {
        self.count(|s| s == State::Sending { handed_over: false })
    }

    /// The network groups no further peer may be in: those of every
    /// observer still watching and of every peer that got the transaction.
    fn groups(&self) -> HashSet<NetGroup> {
        self.peers
            .iter()
            .filter(|(_, state)| {
                matches!(
                    state,
                    State::Watching { .. }
                        | State::Sending { .. }
                        | State::SenderGone { handed_over: true }
                )
            })
            .map(|(addr, _)| addr.netgroup())
            .collect()
    }

    /// Start one more observer or sender, if the pool has a fitting peer.
    async fn launch(&mut self, job: &Job, observer: bool) -> bool {
        if self.proxy_down.is_some() {
            return false;
        }
        let (tries, max) = if observer {
            (&mut self.observer_tries, self.timing.observer_tries)
        } else {
            (&mut self.sender_tries, self.timing.sender_tries)
        };
        if *tries >= max {
            return false;
        }
        *tries += 1;
        let exclude: HashSet<PeerAddr> = self.peers.keys().cloned().collect();
        let picked = tokio::time::timeout_at(
            job.deadline.into(),
            job.peers
                .next_outside(Purpose::Relay, &exclude, &self.groups()),
        )
        .await;
        let addr = match picked {
            Ok(Ok(addr)) => addr,
            Ok(Err(no_peers)) => {
                self.no_peers = Some(no_peers.to_string());
                return false;
            }
            Err(_) => return false,
        };
        let (task_job, task_addr) = (job.clone(), addr.clone());
        if observer {
            self.peers.insert(addr, State::Watching { ready: false });
            tokio::task::spawn_blocking(move || observe(task_job, task_addr));
        } else {
            self.peers
                .insert(addr, State::Sending { handed_over: false });
            tokio::task::spawn_blocking(move || send(task_job, task_addr));
        }
        true
    }

    async fn apply(&mut self, job: &Job, event: Event) {
        match event {
            Event::Ready { addr, fee_filter } => {
                tracing::debug!(peer = %addr, "broadcast: observer ready");
                if let Some(rate) = fee_filter {
                    self.fee_filters.push((addr.clone(), rate));
                }
                self.peers.insert(addr, State::Watching { ready: true });
            }
            Event::Seen { addr, announced } => {
                tracing::debug!(peer = %addr, announced, "broadcast: observer served the transaction");
                self.seen_by.get_or_insert(addr);
            }
            Event::HandedOver { addr } => {
                tracing::debug!(peer = %addr, "broadcast: handed the transaction over");
                self.sent_to.push(addr.clone());
                self.handed_over_at.get_or_insert_with(Instant::now);
                self.peers
                    .insert(addr, State::Sending { handed_over: true });
            }
            Event::Refused { addr, signal } => {
                tracing::debug!(peer = %addr, ?signal, "broadcast: a sender's peer refused the transaction");
                self.refused.insert(addr, signal);
            }
            Event::ProxyDown { error } => {
                tracing::warn!(%error, "broadcast: the P2P proxy failed");
                self.proxy_down.get_or_insert(error);
            }
            Event::Gone { addr } => match self.peers.get(&addr).copied() {
                Some(State::Watching { .. }) => {
                    self.peers.insert(addr, State::ObserverGone);
                    // Keep enough observers; a late one still sees the
                    // transaction in its mempool.
                    if self.observers_ready() + self.observers_connecting() < OBSERVERS {
                        self.launch(job, true).await;
                    }
                }
                Some(State::Sending { handed_over }) => {
                    self.peers.insert(addr, State::SenderGone { handed_over });
                    if !handed_over && self.sent_to.len() + self.senders_connecting() < SENDERS {
                        self.launch(job, false).await;
                    }
                }
                _ => {}
            },
        }
    }

    /// Through a proxy: start more connections alongside the ones not up
    /// yet, which are probably to dead addresses. Observers until enough
    /// are ready; then senders until enough have handed it over (a hedged
    /// sender hands nothing over once [`SENDERS`] slots are taken).
    async fn hedge(&mut self, job: &Job) {
        if self.seen_by.is_some() {
            return;
        }
        let (observer, missing) = if self.senders_started {
            (false, SENDERS.saturating_sub(self.sent_to.len()))
        } else {
            (true, OBSERVERS.saturating_sub(self.observers_ready()))
        };
        for _ in 0..missing {
            if !self.launch(job, observer).await {
                break;
            }
        }
    }

    fn should_start_senders(&self) -> bool {
        let ready = self.observers_ready();
        !self.senders_started
            && self.seen_by.is_none()
            && ready > 0
            && (ready >= OBSERVERS
                || self.observers_connecting() == 0
                || self.started.elapsed() >= self.timing.observer_window)
    }

    /// The broadcast's end, once it is decided. `Err` is a message for the
    /// user: no peer could be asked.
    fn end(&self, deadline: Instant) -> Option<Result<Verdict, String>> {
        if let Some(by) = &self.seen_by {
            return Some(Ok(Verdict::InMempool { by: by.clone() }));
        }
        let observers_left = self.observers_ready() + self.observers_connecting() > 0;
        if !self.senders_started {
            let gave_up = Instant::now() >= deadline
                || self.started.elapsed() >= self.timing.observer_limit
                || !observers_left;
            return gave_up.then(|| Err(self.unreachable("to confirm the broadcast")));
        }
        if self.sent_to.is_empty() {
            let gave_up = Instant::now() >= deadline || self.senders_connecting() == 0;
            return gave_up.then(|| Err(self.unreachable("to take the transaction")));
        }
        if Instant::now() >= deadline {
            return Some(Ok(self.unconfirmed()));
        }
        // Every sender that got it refused it the same way, and no other
        // sender may still get it: none is connecting, or all the hand-over
        // slots are taken (hedged senders still connecting hand nothing
        // over then).
        if self.senders_connecting() == 0 || self.sent_to.len() >= SENDERS {
            let mut signals = self.sent_to.iter().map(|addr| self.refused.get(addr));
            let first = signals.next().flatten().copied()?;
            if signals.all(|signal| signal == Some(&first)) {
                let message = rejected_message(first, self.sent_to.len());
                return Some(Ok(match first {
                    Signal::MissingInputs => Verdict::Rejected(message),
                    Signal::Dropped => Verdict::Dropped(message),
                }));
            }
        }
        None
    }

    /// No observer had it: since the first hand-over (or the start).
    fn unconfirmed(&self) -> Verdict {
        let since = self.handed_over_at.unwrap_or(self.started);
        Verdict::Unconfirmed {
            waited: since.elapsed(),
        }
    }

    fn unreachable(&self, what: &str) -> String {
        if let Some(error) = &self.proxy_down {
            return format!(
                "no Bitcoin peers reachable {what}: {error}. Check that Tor (or the SOCKS5 \
                 proxy) is running and that p2p_proxy names its SOCKS port; friglet never \
                 connects to peers directly while p2p_proxy is set"
            );
        }
        let mut message = format!("no Bitcoin peers reachable {what}");
        if let Some(reason) = &self.no_peers {
            message.push_str(&format!(" ({reason})"));
        }
        message
    }
}

/// Broadcast `candidate` to peers of the network and wait up to `budget`
/// for a peer it was not handed to to serve it. `Err` (a message for the
/// user) when no peer could be asked: nothing was sent then.
pub async fn broadcast(
    peers: Arc<PeerSource>,
    candidate: Arc<Candidate>,
    budget: Duration,
) -> Result<Report, String> {
    let deadline = Instant::now() + budget;
    let timing = Timing::for_peers(&peers);
    let (events, mut received) = mpsc::unbounded_channel();
    let job = Job::new(peers, candidate, deadline, events);
    // Every connection of this broadcast ends when it returns.
    let _close = CloseOnDrop(job.clone());
    let mut round = Round::new(timing);
    for _ in 0..timing.observers_at_start {
        if !round.launch(&job, true).await {
            break;
        }
    }
    let mut next_hedge = timing.hedge_every.map(|every| Instant::now() + every);
    loop {
        if round.should_start_senders() {
            round.senders_started = true;
            for _ in 0..SENDERS {
                if !round.launch(&job, false).await {
                    break;
                }
            }
            next_hedge = timing.hedge_every.map(|every| Instant::now() + every);
        }
        if let (Some(at), Some(every)) = (next_hedge, timing.hedge_every)
            && Instant::now() >= at
        {
            round.hedge(&job).await;
            next_hedge = Some(Instant::now() + every);
        }
        if let Some(end) = round.end(deadline) {
            // From here on nothing is handed over, and every peer that may
            // hold the transaction is in the ledger, including one whose
            // report is still on its way.
            let sent_to: Vec<PeerAddr> = job
                .close()
                .into_iter()
                .filter(|(txid, _)| *txid == job.candidate.txid)
                .map(|(_, addr)| addr)
                .collect();
            let verdict = match end {
                Ok(verdict) => verdict,
                Err(_) if !sent_to.is_empty() => round.unconfirmed(),
                Err(message) => return Err(message),
            };
            return Ok(Report {
                verdict,
                sent_to,
                fee_filters: round.fee_filters,
            });
        }
        let mut wake = deadline;
        if !round.senders_started {
            wake = wake
                .min(round.started + timing.observer_window)
                .min(round.started + timing.observer_limit);
        }
        if let Some(at) = next_hedge {
            wake = wake.min(at);
        }
        tokio::select! {
            event = received.recv() => {
                if let Some(event) = event {
                    round.apply(&job, event).await;
                }
            }
            _ = tokio::time::sleep_until(wake.max(Instant::now() + STOP_CHECK).into()) => {}
        }
    }
}

/// Open a connection to `addr` through the pool's dialer and report how it
/// went. A peer that relays no transactions is refused: it is no use as a
/// sender or observer.
fn connect(peers: &PeerSource, addr: &PeerAddr, relay: bool) -> Result<Peer, P2pError> {
    match Peer::connect(
        peers.dialer(),
        addr,
        peers.network(),
        relay,
        CONNECT_TIMEOUT,
    ) {
        Ok(peer) => {
            peers.report(addr, PeerEvent::Connected(peer.info()));
            if !peer.relays() {
                peers.report(addr, PeerEvent::NoTxRelay);
                return Err(P2pError::Protocol(
                    "the peer relays no transactions (blocks-only)".into(),
                ));
            }
            Ok(peer)
        }
        // The proxy failed, not the peer.
        Err(error) if error.proxy_down() => Err(error),
        Err(error) => {
            let no_route = matches!(
                &error,
                P2pError::Io(io) if io.kind() == std::io::ErrorKind::NetworkUnreachable
            );
            let event = if no_route {
                PeerEvent::NoRoute
            } else {
                error.peer_event()
            };
            peers.report(addr, event);
            Err(error)
        }
    }
}

/// Does `message` announce this transaction?
fn announces(message: &NetworkMessage, txid: Txid, wtxid: Wtxid) -> bool {
    matches!(message, NetworkMessage::Inv(items)
        if items.iter().any(|item| inventory_matches(item, txid, wtxid)))
}

/// An observer: connect with relay on, settle, then ask for the transaction
/// until the peer serves it or the broadcast ends.
fn observe(job: Job, addr: PeerAddr) {
    let watched = (|| {
        let mut peer = connect(&job.peers, &addr, true)?;
        let _registered = job.register(&peer)?;
        peer.wait_until_settled(Instant::now() + SETTLE_WAIT)?;
        job.tell(Event::Ready {
            addr: addr.clone(),
            fee_filter: peer.fee_filter(),
        });
        watch(&mut peer, &job)
    })();
    match watched {
        Ok(Some(announced)) => job.tell(Event::Seen {
            addr: addr.clone(),
            announced,
        }),
        Ok(None) => {}
        Err(error) if error.proxy_down() => job.tell(Event::ProxyDown {
            error: error.to_string(),
        }),
        Err(error) => tracing::debug!(peer = %addr, %error, "broadcast: observer lost"),
    }
    job.tell(Event::Gone { addr });
}

/// Ask every [`POLL_INTERVAL`], and at once after an announcement, until
/// the peer serves the transaction: `Some(whether it announced it)`, or
/// `None` when the broadcast ends first.
fn watch(peer: &mut Peer, job: &Job) -> Result<Option<bool>, P2pError> {
    let (txid, wtxid) = (job.candidate.txid, job.candidate.wtxid);
    let mut announced = false;
    loop {
        if job.over() {
            return Ok(None);
        }
        let mut heard = false;
        let ask_until = job.deadline.min(Instant::now() + ANNOUNCE_WAIT);
        match peer.mempool_has(txid, wtxid, ask_until, |_, message| {
            heard |= announces(&message, txid, wtxid);
            Ok(())
        }) {
            Ok(true) => return Ok(Some(announced || heard)),
            // A slow answer is no answer yet: listen on.
            Ok(false) | Err(P2pError::Timeout(_)) => {}
            Err(error) => return Err(error),
        }
        announced |= heard;
        if heard {
            continue;
        }
        let next_ask = job.deadline.min(Instant::now() + POLL_INTERVAL);
        while Instant::now() < next_ask && !job.stop.is_cancelled() {
            let slice = next_ask.min(Instant::now() + STOP_CHECK);
            if let Some(message) = peer.recv_until(slice)?
                && announces(&message, txid, wtxid)
            {
                announced = true;
                break;
            }
        }
    }
}

/// Open a sender connection: relay off, nothing asked for beyond the
/// handshake (no `getaddr`, no `feefilter`).
fn connect_sender(peers: &PeerSource, addr: &PeerAddr) -> Result<Peer, P2pError> {
    connect(peers, addr, false)
}

/// Announce `candidate` and hand it over when the peer asks for it, or
/// unasked once [`ANNOUNCE_WAIT`] has passed (the peer may know it from
/// before, or be slow). Nothing is announced once `stopped` says so, and
/// nothing handed over that `signals`' gate refuses: a broadcast that has
/// ended must not leave a peer it does not know about holding the
/// transaction. Returns `None` when it was not handed over, else whether
/// the peer asked for it.
fn announce_and_hand_over(
    peer: &mut Peer,
    candidate: &Candidate,
    signals: &mut Signals,
    stopped: impl Fn() -> bool,
) -> Result<Option<bool>, P2pError> {
    let (tx, txid, wtxid) = (&candidate.tx, candidate.txid, candidate.wtxid);
    if stopped() {
        return Ok(None);
    }
    peer.send(NetworkMessage::Inv(vec![peer.tx_inventory(txid, wtxid)]))?;
    let asked_until = Instant::now() + ANNOUNCE_WAIT;
    while !signals.sent && Instant::now() < asked_until {
        if stopped() {
            return Ok(None);
        }
        let slice = asked_until.min(Instant::now() + STOP_CHECK);
        if let Some(message) = peer.recv_until(slice)? {
            signals.observe(peer, message, tx, txid, wtxid)?;
        }
    }
    if signals.sent {
        return Ok(Some(true));
    }
    if stopped() || !signals.may_send(txid) {
        return Ok(None);
    }
    tracing::debug!(peer = %peer.addr(), %txid, "peer did not request the announced transaction; sending it");
    peer.send(NetworkMessage::Tx(tx.clone()))?;
    signals.sent = true;
    Ok(Some(false))
}

/// Ping and wait for the pong: the peer processes messages in order, so by
/// then it has processed the transaction. Requests meanwhile are answered.
fn flush(
    peer: &mut Peer,
    candidate: &Candidate,
    signals: &mut Signals,
    deadline: Instant,
) -> Result<(), P2pError> {
    let nonce = random_u64();
    peer.send(NetworkMessage::Ping(nonce))?;
    loop {
        match peer.recv_until(deadline)? {
            Some(NetworkMessage::Pong(n)) if n == nonce => return Ok(()),
            Some(message) => signals.observe(
                peer,
                message,
                &candidate.tx,
                candidate.txid,
                candidate.wtxid,
            )?,
            None => return Err(P2pError::Timeout("a pong")),
        }
    }
}

/// A sender: hand the transaction over, then listen for the peer's refusal
/// until the broadcast ends.
fn send(job: Job, addr: PeerAddr) {
    let candidate = job.candidate.clone();
    let mut signals = job.signals_for(&addr);
    let mut flushed = false;
    let mut told_missing = false;
    let mut claimed = false;
    let result = (|| {
        let mut peer = connect_sender(&job.peers, &addr)?;
        let _registered = job.register(&peer)?;
        // Enough senders have it already (hedged senders through a proxy).
        if !job.claim_hand_over() {
            return Ok(());
        }
        claimed = true;
        if announce_and_hand_over(&mut peer, &candidate, &mut signals, || job.over())?.is_none() {
            return Ok(());
        }
        job.tell(Event::HandedOver { addr: addr.clone() });
        flush(
            &mut peer,
            &candidate,
            &mut signals,
            job.deadline
                .min(Instant::now() + Timing::for_peers(&job.peers).flush_wait),
        )?;
        flushed = true;
        // A parent request comes seconds later (Bitcoin Core delays
        // requests to an inbound peer).
        while !job.over() {
            if signals.missing_inputs && !told_missing {
                told_missing = true;
                job.tell(Event::Refused {
                    addr: addr.clone(),
                    signal: Signal::MissingInputs,
                });
            }
            let slice = job.deadline.min(Instant::now() + STOP_CHECK);
            if let Some(message) = peer.recv_until(slice)? {
                signals.observe(
                    &mut peer,
                    message,
                    &candidate.tx,
                    candidate.txid,
                    candidate.wtxid,
                )?;
            }
        }
        Ok::<_, P2pError>(())
    })();
    if claimed && !signals.sent {
        job.release_hand_over();
    }
    if signals.missing_inputs && !told_missing {
        job.tell(Event::Refused {
            addr: addr.clone(),
            signal: Signal::MissingInputs,
        });
    } else if let Err(P2pError::Closed) = &result
        && signals.sent
        && !flushed
        // Not when the broadcast's own end shut the connection.
        && !job.stop.is_cancelled()
    {
        job.tell(Event::Refused {
            addr: addr.clone(),
            signal: Signal::Dropped,
        });
    }
    if let Err(error) = &result {
        if error.proxy_down() {
            job.tell(Event::ProxyDown {
                error: error.to_string(),
            });
        }
        tracing::debug!(peer = %addr, %error, handed_over = signals.sent, "broadcast: sender connection ended");
    }
    job.tell(Event::Gone { addr });
}

fn rejected_message(signal: Signal, senders: usize) -> String {
    let peers = if senders == 1 {
        "the peer friglet sent it to"
    } else {
        "every peer friglet sent it to"
    };
    match signal {
        // Sparrow keys its "inputs missing or spent" dialog on the prefix.
        Signal::MissingInputs => format!(
            "bad-txns-inputs-missingorspent: {peers} asked for a parent of this transaction, so \
             the outputs it spends are unknown to the network: they are already spent, or their \
             transaction is unknown."
        ),
        Signal::Dropped => format!(
            "{peers} disconnected right after receiving the transaction. Bitcoin Core does that \
             when a transaction is consensus-invalid, for example when a signature does not \
             verify."
        ),
    }
}

/// The error for a transaction no observer had when the wait ended:
/// Sparrow's fee wording when its fee is below the peers' mempool minimum
/// (`fee_filter`, sat/kvB), otherwise what is known.
pub fn unconfirmed_message(
    candidate: &Candidate,
    fee_filter: Option<u64>,
    waited: Duration,
    sent_to: usize,
) -> String {
    let unseen = format!(
        "{} seconds after friglet handed it to {sent_to} peer{}, no other peer of the network \
         had the transaction",
        waited.as_secs(),
        if sent_to == 1 { "" } else { "s" },
    );
    if let (Some(shortfall), Some(filter)) =
        (relay::fee_shortfall(candidate, fee_filter), fee_filter)
    {
        return relay::fee_shortfall_message(
            candidate,
            shortfall,
            filter,
            &unseen,
            "the network's mempools currently accept",
        );
    }
    format!(
        "{unseen}. The P2P protocol does not report why; common causes are a conflict with a \
         mempool transaction this one does not pay enough to replace, a non-standard \
         transaction, or a fee below what mempools accept now.{} Sending it again checks \
         whether it has spread since.",
        candidate.fee_rate_note(),
    )
}

/// What [`ask_mempools`] found.
#[derive(Debug)]
pub struct Asked {
    /// The peers that answered, in the order they were picked.
    pub peers: Vec<PeerAddr>,
    /// Per candidate: whether any of them has it in its mempool.
    pub present: Vec<bool>,
    pub fee_filters: Vec<(PeerAddr, u64)>,
}

/// Ask up to `count` peers that are not in `exclude` (nor, with
/// `avoid_groups`, in its network groups), each in a group of its own,
/// whether each candidate is in their mempool, on observer connections
/// opened at once. Unreachable peers are replaced a few times; through a
/// proxy two more connections race from the start (a dead address costs
/// 20 s there). `Err` when none answered.
pub async fn ask_mempools(
    peers: &Arc<PeerSource>,
    candidates: Arc<Vec<Candidate>>,
    exclude: &HashSet<PeerAddr>,
    avoid_groups: bool,
    count: usize,
) -> Result<Asked, String> {
    let mut used = exclude.clone();
    let mut groups: HashSet<NetGroup> = if avoid_groups {
        exclude.iter().map(PeerAddr::netgroup).collect()
    } else {
        HashSet::new()
    };
    let mut asking = tokio::task::JoinSet::new();
    let mut tries = 0;
    let mut answers: Vec<(PeerAddr, Vec<bool>, Option<u64>)> = Vec::new();
    let mut last_error = None;
    let racing = if peers.dialer().proxy().is_some() {
        2
    } else {
        0
    };
    let max_tries = count * 3 + racing;
    let mut proxy_down = false;
    while answers.len() < count {
        while !proxy_down && asking.len() + answers.len() < count + racing && tries < max_tries {
            tries += 1;
            let addr = match peers.next_outside(Purpose::Relay, &used, &groups).await {
                Ok(addr) => addr,
                Err(no_peers) => {
                    last_error = Some(no_peers.to_string());
                    tries = max_tries;
                    break;
                }
            };
            used.insert(addr.clone());
            groups.insert(addr.netgroup());
            let (task_peers, task_candidates) = (peers.clone(), candidates.clone());
            asking.spawn_blocking(move || {
                let answer = ask(&task_peers, &addr, &task_candidates);
                (addr, answer)
            });
        }
        let Some(joined) = asking.join_next().await else {
            break;
        };
        let (addr, answer) = joined.map_err(|error| format!("mempool check failed: {error}"))?;
        match answer {
            Ok((present, fee_filter)) => answers.push((addr, present, fee_filter)),
            Err(error) if error.proxy_down() => {
                proxy_down = true;
                last_error = Some(error.to_string());
            }
            Err(error) => {
                tracing::debug!(peer = %addr, %error, "mempool check: peer could not be asked");
                last_error = Some(format!("{addr}: {error}"));
            }
        }
    }
    if answers.is_empty() {
        return Err(format!(
            "no Bitcoin peer could be asked{}",
            last_error.map(|e| format!(" ({e})")).unwrap_or_default()
        ));
    }
    let present = (0..candidates.len())
        .map(|i| answers.iter().any(|(_, present, _)| present[i]))
        .collect();
    Ok(Asked {
        fee_filters: answers
            .iter()
            .filter_map(|(addr, _, rate)| rate.map(|rate| (addr.clone(), rate)))
            .collect(),
        peers: answers.into_iter().map(|(addr, ..)| addr).collect(),
        present,
    })
}

/// One observer connection that asks for each candidate.
fn ask(
    peers: &PeerSource,
    addr: &PeerAddr,
    candidates: &[Candidate],
) -> Result<(Vec<bool>, Option<u64>), P2pError> {
    let mut peer = connect(peers, addr, true)?;
    peer.wait_until_settled(Instant::now() + SETTLE_WAIT)?;
    let mut present = Vec::with_capacity(candidates.len());
    for candidate in candidates {
        present.push(peer.mempool_has(
            candidate.txid,
            candidate.wtxid,
            Instant::now() + ANNOUNCE_WAIT,
            |_, _| Ok(()),
        )?);
    }
    Ok((present, peer.fee_filter()))
}

/// Hand `candidates` to `addr` on one sender connection and wait until the
/// peer has processed them. Blocking. Returns, per candidate, whether the
/// peer asked for it (it did not when it knows it already).
pub fn hand_over(
    peers: &PeerSource,
    addr: &PeerAddr,
    candidates: &[&Candidate],
) -> Result<Vec<bool>, P2pError> {
    let mut peer = connect_sender(peers, addr)?;
    let mut requested = Vec::with_capacity(candidates.len());
    for candidate in candidates {
        let mut signals = Signals::default();
        let asked = announce_and_hand_over(&mut peer, candidate, &mut signals, || false)?;
        requested.push(asked == Some(true));
        flush(
            &mut peer,
            candidate,
            &mut signals,
            Instant::now() + Timing::for_peers(peers).flush_wait,
        )?;
    }
    Ok(requested)
}

/// Fake peers on 127.N.0.1: each in a network group of its own (Linux
/// routes all of 127.0.0.0/8 to the loopback; macOS only 127.0.0.1).
#[cfg(all(test, not(target_os = "macos")))]
mod tests {
    use super::*;
    use crate::electrum::fake_peer::{FakeNet, FakePeer, Script, TxPolicy};
    use bitcoin::absolute::LockTime;
    use bitcoin::transaction::Version;
    use bitcoin::{
        Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
    };
    use blindbit_lib::net::{Dialer, Seeds, USER_AGENT};
    use std::net::{IpAddr, SocketAddr};

    fn candidate(seed: u8) -> Arc<Candidate> {
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: bitcoin::hashes::Hash::from_byte_array([seed; 32]),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(5_000),
                script_pubkey: ScriptBuf::new(),
            }],
        };
        Arc::new(Candidate::decode(bitcoin::consensus::encode::serialize(&tx)).unwrap())
    }

    /// The `n`-th peer address of a test: 127.`base + n`.0.1.
    fn ip(base: u8, n: u8) -> IpAddr {
        [127, base + n, 0, 1].into()
    }

    /// A discovering source that knows exactly `addrs`.
    async fn pool(addrs: &[SocketAddr]) -> Arc<PeerSource> {
        pool_via(addrs, Dialer::Direct).await
    }

    /// [`pool`], connecting through `dialer`.
    async fn pool_via(addrs: &[SocketAddr], dialer: Dialer) -> Arc<PeerSource> {
        let peers = PeerSource::discover(
            Network::Regtest,
            dialer,
            Seeds::Static(addrs.iter().map(|addr| (*addr).into()).collect()),
        );
        peers.next(Purpose::Block, &HashSet::new()).await.unwrap();
        assert_eq!(
            peers.known(),
            addrs.len(),
            "a slot collision dropped a peer: pick other test addresses"
        );
        peers
    }

    fn addrs(fakes: &[FakePeer]) -> Vec<SocketAddr> {
        fakes.iter().map(|fake| fake.addr).collect()
    }

    fn net_of(net: &FakeNet, base: u8, scripts: Vec<Script>) -> Vec<FakePeer> {
        scripts
            .into_iter()
            .enumerate()
            .map(|(n, script)| net.peer(ip(base, n as u8), script))
            .collect()
    }

    fn by_addr<'a>(fakes: &'a [FakePeer], addr: &PeerAddr) -> &'a FakePeer {
        fakes
            .iter()
            .find(|fake| PeerAddr::from(fake.addr) == *addr)
            .expect("one of the fakes")
    }

    /// Did `fake` get the transaction on a connection?
    fn got_tx(fake: &FakePeer) -> bool {
        fake.commands().iter().any(|c| c == "tx")
    }

    async fn run(fakes: &[FakePeer], candidate: &Arc<Candidate>, budget: Duration) -> Report {
        let peers = pool(&addrs(fakes)).await;
        broadcast(peers, candidate.clone(), budget).await.unwrap()
    }

    #[tokio::test]
    async fn a_peer_it_was_not_handed_to_announcing_it_is_success() {
        let net = FakeNet::new();
        let fakes = net_of(&net, 1, vec![Script::default(); 5]);
        let candidate = candidate(1);
        let report = run(&fakes, &candidate, Duration::from_secs(20)).await;
        let Verdict::InMempool { by } = &report.verdict else {
            panic!("expected success, got {report:?}");
        };
        assert_eq!(report.sent_to.len(), SENDERS);
        assert!(!report.sent_to.contains(by), "a sender never confirms");
        assert!(!got_tx(by_addr(&fakes, by)));
        // Every peer that got it is listed, whenever its report came.
        for fake in fakes.iter().filter(|fake| got_tx(fake)) {
            assert!(report.sent_to.contains(&fake.addr.into()), "{}", fake.addr);
        }
        assert!(net.has(candidate.txid));
        // Observers and senders: five peers in five network groups.
        let groups: HashSet<_> = fakes
            .iter()
            .map(|f| PeerAddr::from(f.addr).netgroup())
            .collect();
        assert_eq!(groups.len(), 5);
        assert_eq!(report.fee_filters.len(), OBSERVERS);

        // Sender connections: relay off, height 0, placeholder addresses,
        // the shared user agent, and nothing but the hand-over.
        for sender in &report.sent_to {
            let conns = by_addr(&fakes, sender).conns();
            let conn = conns
                .iter()
                .find(|conn| conn.commands.iter().any(|c| c == "tx"))
                .expect("the hand-over connection");
            assert!(!conn.version.relay);
            assert_eq!(conn.version.start_height, 0);
            assert_eq!(conn.version.user_agent, USER_AGENT);
            assert_eq!(conn.version.services, bitcoin::p2p::ServiceFlags::NONE);
            assert_eq!(conn.version.receiver.port, 1);
            for command in &conn.commands {
                assert!(
                    ["inv", "tx", "ping", "pong", "notfound"].contains(&command.as_str()),
                    "sender sent {command}"
                );
            }
            assert!(
                conns
                    .iter()
                    .all(|conn| !conn.commands.iter().any(|c| c == "getdata"))
            );
        }
    }

    #[tokio::test]
    async fn an_observer_that_only_answers_getdata_is_enough() {
        let net = FakeNet::new();
        let quiet = Script {
            announce: false,
            ..Script::default()
        };
        let fakes = net_of(&net, 20, vec![quiet; 5]);
        let candidate = candidate(2);
        let report = run(&fakes, &candidate, Duration::from_secs(20)).await;
        let Verdict::InMempool { by } = &report.verdict else {
            panic!("expected success, got {report:?}");
        };
        assert!(!report.sent_to.contains(by));
    }

    #[tokio::test]
    async fn a_sender_echoing_its_own_inv_is_not_success() {
        let net = FakeNet::new();
        let echo = Script {
            policy: TxPolicy::Ignore,
            echo_inv: true,
            ..Script::default()
        };
        let fakes = net_of(&net, 30, vec![echo; 5]);
        let candidate = candidate(3);
        let report = run(&fakes, &candidate, Duration::from_secs(5)).await;
        assert!(
            matches!(report.verdict, Verdict::Unconfirmed { .. }),
            "{report:?}"
        );
        assert_eq!(report.sent_to.len(), SENDERS);
        let message = unconfirmed_message(&candidate, Some(1000), Duration::from_secs(25), 2);
        assert!(
            message.starts_with(
                "25 seconds after friglet handed it to 2 peers, no other peer of the network had \
                 the transaction."
            ),
            "{message}"
        );
    }

    #[tokio::test]
    async fn no_reachable_observer_is_an_error_and_nothing_is_sent() {
        // Closed ports, and a blocks-only peer.
        let mut all: Vec<SocketAddr> = (0..3)
            .map(|n| {
                let listener = std::net::TcpListener::bind((ip(40, n), 0)).unwrap();
                listener.local_addr().unwrap()
            })
            .collect();
        let net = FakeNet::new();
        let blocks_only = net.peer(
            ip(40, 5),
            Script {
                relay: false,
                ..Script::default()
            },
        );
        all.push(blocks_only.addr);
        let peers = pool(&all).await;
        let error = broadcast(peers, candidate(4), Duration::from_secs(20))
            .await
            .unwrap_err();
        assert!(
            error.starts_with("no Bitcoin peers reachable to confirm the broadcast"),
            "{error}"
        );
        assert!(
            !blocks_only
                .commands()
                .iter()
                .any(|c| c == "inv" || c == "tx")
        );
    }

    #[tokio::test]
    async fn every_sender_asking_for_a_parent_is_a_rejection() {
        let net = FakeNet::new();
        let orphan = Script {
            policy: TxPolicy::Orphan,
            ..Script::default()
        };
        let fakes = net_of(&net, 55, vec![orphan; 5]);
        let report = run(&fakes, &candidate(5), Duration::from_secs(20)).await;
        let Verdict::Rejected(message) = &report.verdict else {
            panic!("expected a rejection, got {report:?}");
        };
        // Sparrow keys its "inputs missing or spent" dialog on this prefix.
        assert!(
            message.starts_with("bad-txns-inputs-missingorspent: every peer"),
            "{message}"
        );
    }

    #[tokio::test]
    async fn every_sender_dropping_it_is_reported_but_not_final() {
        let net = FakeNet::new();
        let invalid = Script {
            policy: TxPolicy::Disconnect,
            ..Script::default()
        };
        let fakes = net_of(&net, 60, vec![invalid; 5]);
        let report = run(&fakes, &candidate(6), Duration::from_secs(20)).await;
        let Verdict::Dropped(message) = &report.verdict else {
            panic!("expected every sender to drop it, got {report:?}");
        };
        assert!(
            message.contains("disconnected right after receiving"),
            "{message}"
        );
    }

    #[tokio::test]
    async fn one_sender_asking_for_a_parent_does_not_decide() {
        // The first peer handed the transaction lacks its parent; the other
        // takes it, and an observer has it next.
        let net = FakeNet::with_first_policies(vec![TxPolicy::Orphan]);
        let fakes = net_of(&net, 70, vec![Script::default(); 5]);
        let report = run(&fakes, &candidate(7), Duration::from_secs(20)).await;
        let Verdict::InMempool { by } = &report.verdict else {
            panic!("expected success, got {report:?}");
        };
        assert!(!report.sent_to.contains(by));
        assert_eq!(fakes.iter().filter(|f| got_tx(f)).count(), SENDERS);
    }

    #[tokio::test]
    async fn a_blocks_only_peer_is_never_a_sender_or_an_observer() {
        let net = FakeNet::new();
        let mut scripts = vec![Script::default(); 4];
        scripts.push(Script {
            relay: false,
            ..Script::default()
        });
        let fakes = net_of(&net, 80, scripts);
        let blocks_only = &fakes[4];
        let peers = pool(&addrs(&fakes)).await;
        for seed in [8, 9] {
            let report = broadcast(peers.clone(), candidate(seed), Duration::from_secs(20))
                .await
                .unwrap();
            assert!(
                matches!(report.verdict, Verdict::InMempool { .. }),
                "{report:?}"
            );
            assert!(!report.sent_to.contains(&blocks_only.addr.into()));
        }
        // Three observers and two senders out of five peers: it was asked
        // once, and refused for good after its handshake.
        assert_eq!(blocks_only.conns().len(), 1);
        assert!(blocks_only.commands().iter().all(|c| c == "pong"));
    }

    /// A job for `fake` alone, as one connection of a broadcast sees it.
    async fn job_for(fake: &FakePeer, seed: u8) -> (Job, mpsc::UnboundedReceiver<Event>) {
        let peers = pool(&[fake.addr]).await;
        let (events, received) = mpsc::unbounded_channel();
        let deadline = Instant::now() + Duration::from_secs(30);
        (Job::new(peers, candidate(seed), deadline, events), received)
    }

    /// Wait (up to 10 s) until `done` holds.
    async fn wait_for(what: &str, done: impl Fn() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while !done() {
            assert!(Instant::now() < deadline, "timed out waiting for {what}");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// The next event that is not `Ready`/`HandedOver`, within 10 s.
    async fn next_end(received: &mut mpsc::UnboundedReceiver<Event>) -> Event {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let event = tokio::time::timeout_at(deadline.into(), received.recv())
                .await
                .expect("an event within 10 s")
                .expect("the connection reports");
            if !matches!(event, Event::Ready { .. } | Event::HandedOver { .. }) {
                return event;
            }
        }
    }

    #[tokio::test]
    async fn a_sender_that_connects_after_the_broadcast_ended_hands_nothing_over() {
        let net = FakeNet::new();
        let fake = net.peer(ip(100, 0), Script::default());
        let (job, mut received) = job_for(&fake, 11).await;
        job.close();
        let addr = PeerAddr::from(fake.addr);
        let task_job = job.clone();
        tokio::task::spawn_blocking(move || send(task_job, addr))
            .await
            .unwrap();
        assert!(!got_tx(&fake));
        assert!(!fake.commands().iter().any(|c| c == "inv"));
        assert!(matches!(received.recv().await, Some(Event::Gone { .. })));
    }

    /// The end of a broadcast shuts an observer's connection: one waiting
    /// for an answer ends at once instead of after its 5 s wait.
    #[tokio::test]
    async fn the_end_of_a_broadcast_shuts_a_waiting_observer_down() {
        let net = FakeNet::new();
        let quiet = Script {
            unresponsive: true,
            ..Script::default()
        };
        let fake = net.peer(ip(101, 0), quiet);
        let (job, mut received) = job_for(&fake, 12).await;
        let (task_job, addr) = (job.clone(), PeerAddr::from(fake.addr));
        tokio::task::spawn_blocking(move || observe(task_job, addr));
        assert!(matches!(received.recv().await, Some(Event::Ready { .. })));
        wait_for("the observer's request", || {
            fake.commands().iter().any(|c| c == "getdata")
        })
        .await;
        let closed = Instant::now();
        job.close();
        let end = next_end(&mut received).await;
        assert!(matches!(end, Event::Gone { .. }), "{end:?}");
        assert!(
            closed.elapsed() < Duration::from_secs(1),
            "ended {:?} after the broadcast",
            closed.elapsed()
        );
    }

    /// Likewise a sender waiting for the pong after the hand-over.
    #[tokio::test]
    async fn the_end_of_a_broadcast_shuts_a_waiting_sender_down() {
        let net = FakeNet::new();
        let quiet = Script {
            unresponsive: true,
            ..Script::default()
        };
        let fake = net.peer(ip(102, 0), quiet);
        let (job, mut received) = job_for(&fake, 13).await;
        let (task_job, addr) = (job.clone(), PeerAddr::from(fake.addr));
        tokio::task::spawn_blocking(move || send(task_job, addr));
        wait_for("the ping after the hand-over", || {
            let commands = fake.commands();
            commands.iter().any(|c| c == "tx") && commands.iter().any(|c| c == "ping")
        })
        .await;
        let closed = Instant::now();
        let handed = job.close();
        assert_eq!(
            handed,
            vec![(job.candidate.txid, PeerAddr::from(fake.addr))]
        );
        let end = next_end(&mut received).await;
        assert!(matches!(end, Event::Gone { .. }), "{end:?}");
        assert!(
            closed.elapsed() < Duration::from_secs(1),
            "ended {:?} after the broadcast",
            closed.elapsed()
        );
    }

    /// A request that arrives once the broadcast has decided gets no
    /// transaction: the final list of peers holding it stays complete.
    #[tokio::test]
    async fn a_request_after_the_end_is_not_answered_with_the_transaction() {
        let net = FakeNet::new();
        let fake = net.peer(ip(103, 0), Script::default());
        let (job, _received) = job_for(&fake, 14).await;
        let addr = PeerAddr::from(fake.addr);
        let (sent, handed) = tokio::task::spawn_blocking(move || {
            let mut peer = connect_sender(&job.peers, &addr).unwrap();
            let mut signals = job.signals_for(&addr);
            // The broadcast decides while the peer's request is on its way.
            job.close();
            let candidate = &job.candidate;
            let request =
                NetworkMessage::GetData(vec![peer.tx_inventory(candidate.txid, candidate.wtxid)]);
            signals
                .observe(
                    &mut peer,
                    request,
                    &candidate.tx,
                    candidate.txid,
                    candidate.wtxid,
                )
                .unwrap();
            // Everything sent before the pong has reached the peer.
            peer.flush(Instant::now() + Duration::from_secs(5)).unwrap();
            (signals.sent, job.close())
        })
        .await
        .unwrap();
        assert!(!sent);
        assert!(handed.is_empty());
        assert!(!got_tx(&fake));
    }

    /// A peer goes in the final list before the transaction is written to
    /// it; once the list is final nobody else gets in.
    #[tokio::test]
    async fn the_final_list_has_every_peer_let_through_and_no_later_one() {
        let net = FakeNet::new();
        let fake = net.peer(ip(104, 0), Script::default());
        let (job, _received) = job_for(&fake, 15).await;
        let txid = job.candidate.txid;
        let (first, second): (PeerAddr, PeerAddr) = (
            fake.addr.into(),
            "127.105.0.1:1".parse::<SocketAddr>().unwrap().into(),
        );
        assert!(job.claim_hand_over());
        assert!(job.may_send(&first, txid));
        assert_eq!(job.close(), vec![(txid, first.clone())]);
        assert!(!job.may_send(&second, txid));
        assert!(!job.claim_hand_over());
        assert_eq!(
            job.close(),
            vec![(txid, first)],
            "closing again changes nothing"
        );
    }

    #[tokio::test]
    async fn rechecks_ask_only_peers_it_was_not_handed_to() {
        let net = FakeNet::new();
        let fakes = net_of(&net, 90, vec![Script::default(); 4]);
        let peers = pool(&addrs(&fakes)).await;
        let candidate = candidate(10);
        let sent_to: HashSet<PeerAddr> = [fakes[0].addr.into(), fakes[1].addr.into()].into();
        let asked = ask_mempools(
            &peers,
            Arc::new(vec![Candidate::clone(&candidate)]),
            &sent_to,
            true,
            2,
        )
        .await
        .unwrap();
        assert_eq!(asked.present, vec![false]);
        assert_eq!(asked.peers.len(), 2);
        assert!(asked.peers.iter().all(|peer| !sent_to.contains(peer)));
        for sender in &fakes[..2] {
            assert!(sender.conns().is_empty(), "a sender was contacted");
        }
        // Handed to one of the asked peers on a sender connection.
        let requested = tokio::task::spawn_blocking({
            let (peers, target, candidate) =
                (peers.clone(), asked.peers[0].clone(), candidate.clone());
            move || hand_over(&peers, &target, &[&candidate])
        })
        .await
        .unwrap()
        .unwrap();
        assert_eq!(requested, vec![true]);
        assert!(net.has(candidate.txid));
        let target = by_addr(&fakes, &asked.peers[0]);
        let hand_over_conn = target
            .conns()
            .into_iter()
            .find(|conn| conn.commands.iter().any(|c| c == "tx"))
            .unwrap();
        assert!(!hand_over_conn.version.relay);
        assert!(!hand_over_conn.commands.iter().any(|c| c == "getdata"));
    }

    /// Through a proxy (Tor) every connection logs in with its own
    /// credentials, so each gets a circuit of its own: no exit relay sees
    /// both senders, or a sender and an observer. Nothing goes around it.
    #[tokio::test]
    async fn through_a_proxy_every_connection_is_on_its_own_circuit() {
        use blindbit_lib::net::testing::FakeSocks5;

        // Peers that keep the transaction to themselves: the broadcast runs
        // its whole budget, so both senders hand it over.
        let net = FakeNet::new();
        let silent = Script {
            policy: TxPolicy::Ignore,
            ..Script::default()
        };
        let fakes = net_of(&net, 150, vec![silent; 8]);
        let proxy = FakeSocks5::start();
        let peers = pool_via(&addrs(&fakes), proxy.dialer()).await;
        let report = broadcast(peers, candidate(15), Duration::from_secs(6))
            .await
            .unwrap();
        assert!(
            matches!(report.verdict, Verdict::Unconfirmed { .. }),
            "{report:?}"
        );
        assert_eq!(report.sent_to.len(), SENDERS);
        let requests = proxy.requests();
        let sender_logins: Vec<_> = requests
            .iter()
            .filter(|request| report.sent_to.contains(&request.target))
            .map(|request| request.credentials.clone().expect("logged in"))
            .collect();
        assert_eq!(sender_logins.len(), SENDERS);
        assert_ne!(
            sender_logins[0], sender_logins[1],
            "the two senders used different credentials"
        );
        let logins: HashSet<_> = requests.iter().map(|r| r.credentials.clone()).collect();
        assert_eq!(logins.len(), requests.len(), "one login per connection");
        // Every connection a fake peer saw came through the proxy.
        for fake in &fakes {
            let through_proxy = requests
                .iter()
                .filter(|request| request.target == PeerAddr::from(fake.addr))
                .count();
            assert_eq!(fake.conns().len(), through_proxy, "{}", fake.addr);
        }
    }

    /// The proxy is down: the error names it, no peer is blamed and none is
    /// contacted.
    #[tokio::test]
    async fn with_the_proxy_down_a_broadcast_says_so_and_blames_no_peer() {
        let net = FakeNet::new();
        let fakes = net_of(&net, 170, vec![Script::default(); 5]);
        // Nothing listens on port 1, and no parallel test can take it.
        let down = Dialer::Socks5 {
            proxy: "127.0.0.1:1".parse().unwrap(),
        };
        let peers = pool_via(&addrs(&fakes), down).await;
        let error = broadcast(peers.clone(), candidate(16), Duration::from_secs(20))
            .await
            .unwrap_err();
        for expected in [
            "no Bitcoin peers reachable to confirm the broadcast",
            "p2p_proxy 127.0.0.1:1",
            "Check that Tor",
        ] {
            assert!(error.contains(expected), "{expected:?} in {error}");
        }
        let error = ask_mempools(
            &peers,
            Arc::new(vec![Candidate::clone(&candidate(16))]),
            &HashSet::new(),
            true,
            2,
        )
        .await
        .unwrap_err();
        assert!(error.contains("p2p_proxy"), "{error}");
        assert_eq!(peers.known(), fakes.len(), "no peer blamed");
        for fake in &fakes {
            assert!(fake.conns().is_empty());
        }
    }

    /// Through Tor a dead address keeps a connection waiting the whole
    /// 20 s: more observers and senders are started alongside, so the
    /// broadcast succeeds long before, and still hands the transaction to
    /// no more than two peers.
    #[test]
    fn through_a_proxy_dead_addresses_are_hedged_around() {
        use blindbit_lib::net::testing::FakeSocks5;

        let net = FakeNet::new();
        let fakes = net_of(&net, 190, vec![Script::default(); 7]);
        let proxy = FakeSocks5::start();
        let mut all = addrs(&fakes);
        for n in 0..7u8 {
            // Addresses Tor never gets an answer from.
            let dead = SocketAddr::from(([10, 100 + n, 0, 1], 18444));
            proxy.stall(dead.into());
            all.push(dead);
        }
        // The stalled connects outlive the broadcast; a plain runtime drop
        // would wait for them.
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        let (report, waited) = runtime.block_on(async {
            let peers = pool_via(&all, proxy.dialer()).await;
            let started = Instant::now();
            let report = broadcast(peers, candidate(17), Duration::from_secs(45))
                .await
                .unwrap();
            (report, started.elapsed())
        });
        runtime.shutdown_background();
        assert!(
            matches!(report.verdict, Verdict::InMempool { .. }),
            "{report:?}"
        );
        assert!(
            waited < Duration::from_secs(19),
            "waited {waited:?}: a dead address costs 20 s"
        );
        assert!((1..=SENDERS).contains(&report.sent_to.len()), "{report:?}");
        let handed = fakes.iter().filter(|fake| got_tx(fake)).count();
        assert!(handed <= SENDERS, "{handed} peers got the transaction");
    }
}
