use std::collections::HashSet;
use std::fmt;
use std::io;
use std::net::{IpAddr, Shutdown, TcpStream};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bitcoin::hashes::Hash;
use bitcoin::p2p::ServiceFlags;
use bitcoin::p2p::address::{AddrV2, AddrV2Message};
use bitcoin::p2p::message::NetworkMessage;
use bitcoin::p2p::message_blockdata::Inventory;
use bitcoin::{Block, BlockHash, Network};

use bitcoin_p2p::handshake::ConnectionConfig;
use bitcoin_p2p::net::{
    ConnectionExt, ConnectionReader, ConnectionWriter, Error as P2pNetError, TimeoutParams,
};
use tokio_util::sync::CancellationToken;

use crate::net::{PeerAddr, PeerEvent, PeerSource, Purpose, USER_AGENT};

// ---------------------------------------------------------------------------
// Full-block fetch
// ---------------------------------------------------------------------------

/// How long the TCP connect to the own node may take.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// How long the peer may stay silent before we give up on a single read.
///
/// This is a per-syscall socket timeout, NOT a per-message budget.  It needs to
/// be generous: after we send `getdata`, the peer may take a moment to load a
/// large block off disk, and during a multi-megabyte transfer there can be
/// short gaps between TCP segments.  A too-short value risks firing in the
/// *middle* of a block payload, which makes the library's `read_exact` abort
/// after partially consuming the message and permanently desyncs the stream.
/// 30 s is far longer than any healthy gap but still bounds a dead connection.
const READ_TIMEOUT: Duration = Duration::from_secs(30);

/// A discovered peer must answer each handshake message within this; many
/// addresses accept connections and never speak.
const DISCOVERED_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// A discovered peer gets this much on top of the connect timeout and the
/// block deadline for the whole connection, so one that trickles bytes
/// (each read within the timeout, the message never complete) cannot hold
/// the download.
const DISCOVERED_SLACK: Duration = Duration::from_secs(15);

/// After a block, how long a connection that asked for addresses waits for
/// them. It runs on after the block is handed over, so the scan does not
/// wait.
const GOSSIP_WAIT: Duration = Duration::from_secs(3);

/// Bitcoin Core's `NODE_NETWORK_LIMITED_MIN_BLOCKS`: a pruned node serves
/// only this many of the newest blocks, and disconnects peers that ask for
/// older ones.
const LIMITED_BLOCKS: i64 = 288;

/// Bitcoin Core's `HISTORICAL_BLOCK_AGE` (one week) in blocks: once a node
/// reaches its `-maxuploadtarget`, it disconnects peers that ask for older
/// blocks.
const HISTORICAL_BLOCKS: i64 = 7 * 144;

/// The `feefilter` (sat/kvB) sent after the handshake: 1 sat/vB, what the
/// previous P2P library sent. A block-fetch connection takes no
/// transactions, so it only matters to keep the handshake unchanged.
const FEE_FILTER: i64 = 1_000;

/// How [`BlockFetcher::fetch`] retries within one call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryPolicy {
    /// Connections tried before giving up. Each attempt opens a fresh
    /// connection, so a dropped connection is never reused. With discovered
    /// peers each attempt asks another peer.
    pub attempts: u32,
    /// Wait before the second attempt; it doubles for each further attempt.
    pub first_delay: Duration,
    /// Upper bound for the wait between attempts.
    pub max_delay: Duration,
    /// Overall budget for receiving the block on one connection.
    pub block_deadline: Duration,
    /// How long the TCP connect may take.
    pub connect_timeout: Duration,
}

impl Default for RetryPolicy {
    /// The own node: five attempts over about 15 s (waits of 1, 2, 4 and
    /// 8 s).
    fn default() -> Self {
        Self {
            attempts: 5,
            first_delay: Duration::from_secs(1),
            max_delay: Duration::from_secs(8),
            block_deadline: Duration::from_secs(90),
            connect_timeout: CONNECT_TIMEOUT,
        }
    }
}

impl RetryPolicy {
    /// Discovered peers: eight peers, one after another without waiting, each
    /// with 5 s to connect and 30 s for the block. Another peer is likely to
    /// do better than the same one again.
    pub fn discovered() -> Self {
        Self {
            attempts: 8,
            first_delay: Duration::ZERO,
            max_delay: Duration::ZERO,
            block_deadline: Duration::from_secs(30),
            connect_timeout: Duration::from_secs(5),
        }
    }

    /// The default for `peers`.
    pub fn for_source(peers: &PeerSource) -> Self {
        if peers.is_own_node() {
            Self::default()
        } else {
            Self::discovered()
        }
    }

    /// The wait before attempt `attempt` (the first attempt has none).
    fn delay_before(&self, attempt: u32) -> Duration {
        let doublings = attempt.saturating_sub(2).min(16);
        self.first_delay
            .saturating_mul(1 << doublings)
            .min(self.max_delay)
    }
}

/// How one attempt to fetch a block failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FetchFailure {
    /// No TCP connection could be opened.
    Connect(String),
    /// The node speaks another network's P2P protocol (`Some`), or
    /// something that is not Bitcoin P2P at all (`None`).
    WrongNetwork(Option<Network>),
    /// The version handshake failed for another reason.
    Handshake(String),
    /// The node closed the connection before the block arrived, `after` the
    /// TCP connection opened.
    Closed {
        during_handshake: bool,
        after: Duration,
    },
    /// The node answered `notfound`.
    NotFound,
    /// The node sent no block within the deadline and gave no reason,
    /// though it answered the ping sent after the request.
    NoAnswer(Duration),
    /// The connection broke some other way (I/O error, undecodable data, a
    /// `reject`).
    Broken(String),
    /// The node sent the block without its witness data.
    WitnessStripped,
    /// The node sent a block that fails its checks (another block, or a
    /// merkle root or witness commitment mismatch).
    BadBlock(String),
    /// The fetch was cancelled (see [`BlockFetcher::with_cancel`]): the
    /// scan is stopping. Says nothing about the node.
    Cancelled,
    /// Discovered peers only: there was no peer (left) to ask, and why.
    NoPeers(String),
    /// Discovered peers only: the peer's chain ends at this height, below
    /// the block; it was not asked.
    Behind(i32),
}

impl FetchFailure {
    /// Worth another connection right away: the node may well answer
    /// differently next time. The others are settled by the node's state or
    /// configuration and are only retried on a later round.
    fn is_transient(&self) -> bool {
        matches!(
            self,
            Self::Connect(_)
                | Self::Closed { .. }
                | Self::Broken(_)
                | Self::WitnessStripped
                | Self::BadBlock(_)
        )
    }
}

/// A quiet deadline is kept distinct inside one fetch so it gets one fresh
/// connection without spending the full retry budget on repeated 90 s waits.
/// It is still exposed to callers as a broken connection. A missing route
/// is kept distinct so a discovering source can skip that address family.
enum AttemptFailure {
    Regular(FetchFailure),
    QuietDeadline(Duration),
    NoRoute(String),
}

impl AttemptFailure {
    fn into_fetch_failure(self) -> FetchFailure {
        match self {
            Self::Regular(failure) => failure,
            Self::QuietDeadline(waited) => FetchFailure::Broken(format!(
                "the node went quiet: no block and no answer to a ping in {}",
                human_duration(waited)
            )),
            Self::NoRoute(error) => FetchFailure::Connect(error),
        }
    }

    /// What it says about a discovered peer. `connected`: the handshake
    /// completed.
    fn peer_event(&self, connected: bool) -> PeerEvent {
        match self {
            Self::NoRoute(_) => PeerEvent::NoRoute,
            Self::QuietDeadline(_) => PeerEvent::Unhelpful,
            Self::Regular(failure) => match failure {
                FetchFailure::WrongNetwork(_)
                | FetchFailure::WitnessStripped
                | FetchFailure::BadBlock(_) => PeerEvent::Misbehaved,
                FetchFailure::Behind(_) => PeerEvent::Behind,
                _ if !connected => PeerEvent::Unreachable,
                _ => PeerEvent::Unhelpful,
            },
        }
    }
}

impl From<FetchFailure> for AttemptFailure {
    fn from(failure: FetchFailure) -> Self {
        Self::Regular(failure)
    }
}

impl fmt::Display for FetchFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Connect(error) => write!(f, "cannot connect: {error}"),
            Self::WrongNetwork(Some(network)) => {
                write!(f, "peer is a {} node", network_name(*network))
            }
            Self::WrongNetwork(None) => write!(f, "peer does not speak Bitcoin P2P"),
            Self::Handshake(error) => write!(f, "handshake failed: {error}"),
            Self::Closed {
                during_handshake,
                after,
            } => write!(
                f,
                "peer closed the connection {} after connecting, {}",
                human_duration(*after),
                if *during_handshake {
                    "during the handshake"
                } else {
                    "before the block arrived"
                }
            ),
            Self::NotFound => write!(f, "peer answered notfound"),
            Self::NoAnswer(waited) => write!(f, "no block after {}", human_duration(*waited)),
            Self::Broken(error) => write!(f, "connection broke: {error}"),
            Self::WitnessStripped => write!(f, "block came without its witness data"),
            Self::BadBlock(error) => write!(f, "bad block: {error}"),
            Self::Cancelled => write!(f, "cancelled"),
            Self::NoPeers(why) => write!(f, "no peers: {why}"),
            Self::Behind(height) => write!(f, "peer's chain ends at height {height}"),
        }
    }
}

/// What a node said about itself in its `version` message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerInfo {
    pub services: ServiceFlags,
    /// The height of its best chain.
    pub height: i32,
}

/// When a block that could not be fetched is tried again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryNote {
    /// Rounds of attempts that have failed for this block, this one included.
    pub failures: u32,
    /// Wait before the next round.
    pub next_in: Duration,
    /// The longest wait between rounds.
    pub max_wait: Duration,
}

/// Who a [`BlockFetchError`]'s block was asked from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FetchedFrom {
    /// The configured node, every attempt.
    OwnNode(PeerAddr),
    /// Discovered peers: each one asked and how it failed, in order.
    /// `exhausted`: the round ended because no peer was left to ask.
    Network {
        tried: Vec<(PeerAddr, FetchFailure)>,
        exhausted: bool,
    },
}

/// A block could not be fetched over P2P. Its message says what the node (or
/// the peers) did and what the user can do about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockFetchError {
    pub from: FetchedFrom,
    pub network: Network,
    pub height: u64,
    pub block_hash: BlockHash,
    /// Connections tried in this round.
    pub attempts: u32,
    /// How the last attempt failed.
    pub failure: FetchFailure,
    /// What the node said about itself in the last completed handshake.
    pub peer_info: Option<PeerInfo>,
    /// friglet's address on the last connection that opened.
    pub local_ip: Option<IpAddr>,
    /// When the block is tried again, if the caller retries (the daemon
    /// does; a one-shot range scan does not).
    pub retry: Option<RetryNote>,
}

impl std::error::Error for BlockFetchError {}

impl BlockFetchError {
    /// How far below the node's tip the block is, if the node said.
    fn depth(&self) -> Option<i64> {
        self.peer_info
            .map(|info| i64::from(info.height) - self.height as i64)
    }

    /// The block's depth, when the node is pruned and the block is older
    /// than a pruned node serves.
    fn pruned_depth(&self) -> Option<i64> {
        let info = self.peer_info?;
        let depth = self.depth()?;
        (!info.services.has(ServiceFlags::NETWORK) && depth > LIMITED_BLOCKS + 2).then_some(depth)
    }

    /// The own node's address (the network's default port for messages
    /// about discovered peers, which never use it).
    fn node(&self) -> Option<&PeerAddr> {
        match &self.from {
            FetchedFrom::OwnNode(addr) => Some(addr),
            FetchedFrom::Network { .. } => None,
        }
    }

    /// What `whitelist=` should name: friglet's own address when the node is
    /// on this machine or the local network (it sees that address), else a
    /// placeholder for the public address the node sees.
    fn whitelist_address(&self) -> String {
        let local_peer = match self.node().and_then(PeerAddr::ip) {
            Some(IpAddr::V4(ip)) => ip.is_loopback() || ip.is_private() || ip.is_link_local(),
            Some(IpAddr::V6(ip)) => {
                ip.is_loopback() || ip.is_unique_local() || ip.is_unicast_link_local()
            }
            None => false,
        };
        match self.local_ip {
            Some(ip) if local_peer => ip.to_string(),
            _ => "<this computer's public IP>".to_string(),
        }
    }

    /// ": 38333 is the signet port" when the node's port is another
    /// network's default.
    fn other_network_port_hint(&self) -> String {
        let Some(port) = self.node().map(|node| node.port) else {
            return String::new();
        };
        if port == default_p2p_port(self.network) {
            return String::new();
        }
        [
            Network::Bitcoin,
            Network::Testnet,
            Network::Testnet4,
            Network::Signet,
            Network::Regtest,
        ]
        .into_iter()
        .find(|network| default_p2p_port(*network) == port)
        .map(|network| format!(": {port} is the {} port", network_name(network)))
        .unwrap_or_default()
    }

    /// Advice for a node that does not have the block.
    fn missing_block_advice(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let net = network_name(self.network);
        match self.peer_info {
            Some(info) if i64::from(info.height) < self.height as i64 => write!(
                f,
                "It reports height {}: it is still syncing, and the scan continues once it has this block.",
                info.height
            ),
            Some(info) if !info.services.has(ServiceFlags::NETWORK) => write!(
                f,
                "It is pruned and serves only recent blocks. Scanning needs an unpruned {net} node (prune=0): point p2p_node_addr at one."
            ),
            _ => write!(
                f,
                "It is probably pruned below this height or not fully synced. Scanning needs an unpruned (prune=0), fully synced {net} node."
            ),
        }
    }

    /// The message for discovered peers: what the peers asked did, in a
    /// few words, and what the user can do.
    fn fmt_network(
        &self,
        f: &mut fmt::Formatter<'_>,
        tried: &[(PeerAddr, FetchFailure)],
        exhausted: bool,
    ) -> fmt::Result {
        let net = network_name(self.network);
        write!(
            f,
            "cannot get block {} ({}) from the {net} network: ",
            self.height, self.block_hash
        )?;
        if tried.is_empty() {
            match &self.failure {
                FetchFailure::Cancelled => write!(f, "the download was cancelled.")?,
                FetchFailure::NoPeers(why) => write!(f, "no peers to ask ({why}).")?,
                other => write!(f, "{other}.")?,
            }
        } else {
            let (mut unreachable, mut missing, mut behind, mut bad) = (0, 0, 0, 0);
            for (_, failure) in tried {
                match failure {
                    FetchFailure::Connect(_)
                    | FetchFailure::Handshake(_)
                    | FetchFailure::Closed {
                        during_handshake: true,
                        ..
                    } => unreachable += 1,
                    FetchFailure::Behind(_) => behind += 1,
                    FetchFailure::WrongNetwork(_)
                    | FetchFailure::WitnessStripped
                    | FetchFailure::BadBlock(_) => bad += 1,
                    _ => missing += 1,
                }
            }
            let mut parts = Vec::new();
            let count = |n: usize, one: &str, many: &str| {
                if n == 1 {
                    format!("1 {one}")
                } else {
                    format!("{n} {many}")
                }
            };
            if unreachable > 0 {
                parts.push(count(unreachable, "was unreachable", "were unreachable"));
            }
            if missing > 0 {
                parts.push(count(missing, "did not send it", "did not send it"));
            }
            if behind > 0 {
                parts.push(count(behind, "was behind", "were behind"));
            }
            if bad > 0 {
                parts.push(count(
                    bad,
                    "sent a bad block and is ignored now",
                    "sent bad blocks and are ignored now",
                ));
            }
            write!(
                f,
                "asked {}{}: {}.",
                count(tried.len(), "peer", "peers"),
                if exhausted {
                    ", every peer it knows right now"
                } else {
                    ""
                },
                parts.join(", ")
            )?;
        }
        if self.failure != FetchFailure::Cancelled {
            write!(
                f,
                " Check this computer's internet connection, or set p2p_node_addr to your own \
                 {net} node."
            )?;
        }
        Ok(())
    }
}

impl fmt::Display for BlockFetchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let node = match &self.from {
            FetchedFrom::OwnNode(node) => node,
            FetchedFrom::Network { tried, exhausted } => {
                self.fmt_network(f, tried, *exhausted)?;
                return self.fmt_retry(f);
            }
        };
        let net = network_name(self.network);
        let port = default_p2p_port(self.network);
        let tries = if self.attempts > 1 {
            format!(" (all {} tries)", self.attempts)
        } else {
            String::new()
        };
        write!(
            f,
            "cannot get block {} ({}) from your node {}: ",
            self.height, self.block_hash, node
        )?;
        match &self.failure {
            FetchFailure::Connect(error) => write!(
                f,
                "cannot connect ({error}){tries}. Check that bitcoind is running and accepts \
                 P2P connections on that address (listen=1, and bind= if set), that no firewall \
                 blocks it, and that p2p_node_addr is right (the {net} P2P port is usually {port})."
            )?,
            FetchFailure::WrongNetwork(Some(theirs)) => write!(
                f,
                "it is a {} node, but friglet scans {net}. Point p2p_node_addr at a {net} node \
                 (P2P port usually {port}).",
                network_name(*theirs)
            )?,
            FetchFailure::WrongNetwork(None) => write!(
                f,
                "it does not speak the {net} Bitcoin P2P protocol. Point p2p_node_addr at the \
                 P2P port of a {net} node (usually {port}), not its RPC port or another service."
            )?,
            FetchFailure::Handshake(error) => write!(
                f,
                "the Bitcoin handshake failed ({error}). Point p2p_node_addr at the P2P port of \
                 a {net} Bitcoin node (usually {port})."
            )?,
            FetchFailure::NotFound => {
                write!(
                    f,
                    "the node does not have this block (it answered notfound). "
                )?;
                self.missing_block_advice(f)?;
            }
            FetchFailure::NoAnswer(waited) => {
                write!(
                    f,
                    "the node did not send the block within {} and gave no reason, which is what \
                     Bitcoin Core does for a block it does not have. ",
                    human_duration(*waited)
                )?;
                self.missing_block_advice(f)?;
            }
            FetchFailure::Closed { .. } if self.pruned_depth().is_some() => write!(
                f,
                "the node is pruned: it serves only the newest {LIMITED_BLOCKS} blocks and this \
                 one is {} blocks deep, so it closes the connection{tries}. Scanning needs an \
                 unpruned {net} node (prune=0): point p2p_node_addr at one.",
                self.pruned_depth().unwrap_or_default()
            )?,
            // No connection got through the handshake: the node rejects
            // friglet before it even says which network it is on.
            FetchFailure::Closed { .. } if self.peer_info.is_none() => write!(
                f,
                "the node closed the connection during the handshake{tries}. Bitcoin Core does \
                 that to peers of another network, to banned addresses, and when its inbound \
                 slots are full and no peer can be evicted. Check that p2p_node_addr is the P2P \
                 port of a {net} node (usually {port}){}; if it is, add \
                 whitelist=download,noban@{} to bitcoin.conf and restart bitcoind (with \
                 debug=net its debug.log names the reason), or point p2p_node_addr at another \
                 node.",
                self.other_network_port_hint(),
                self.whitelist_address()
            )?,
            FetchFailure::Closed { after, .. } => {
                let upload_limit = if self.depth().is_some_and(|d| d > HISTORICAL_BLOCKS) {
                    ", it may have reached its upload limit (-maxuploadtarget stops it serving \
                     blocks older than a week)"
                } else {
                    ""
                };
                write!(
                    f,
                    "the node accepted the connection and closed it {} later, before the block \
                     arrived{tries}. The node is dropping friglet: its inbound connection slots \
                     may be full (Bitcoin Core then evicts new peers), it may have banned or \
                     discouraged this address{upload_limit}, or a script may be disconnecting \
                     peers. Fix on the node: add whitelist=download,noban@{} to bitcoin.conf and \
                     restart bitcoind (with debug=net its debug.log names the reason), or point \
                     p2p_node_addr at another node.",
                    human_duration(*after),
                    self.whitelist_address()
                )?
            }
            FetchFailure::Broken(error) => write!(f, "the connection broke ({error}){tries}.")?,
            FetchFailure::WitnessStripped => write!(
                f,
                "the node sent the block without its witness data{tries}, which friglet needs \
                 to give your wallet its transactions whole. Point p2p_node_addr at a node that \
                 serves witness data (every Bitcoin Core since 0.13.1 does)."
            )?,
            FetchFailure::BadBlock(error) => write!(
                f,
                "the node sent a block that fails its checks ({error}){tries}. Point \
                 p2p_node_addr at a Bitcoin Core node you trust."
            )?,
            FetchFailure::Cancelled => write!(f, "the download was cancelled.")?,
            // Only discovered peers fail these ways.
            FetchFailure::NoPeers(_) | FetchFailure::Behind(_) => write!(f, "{}.", self.failure)?,
        }
        self.fmt_retry(f)
    }
}

impl BlockFetchError {
    fn fmt_retry(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(retry) = self.retry {
            write!(
                f,
                " friglet retries automatically: next try in {} (failed {} so far; the wait \
                 grows to at most {}).",
                human_duration(retry.next_in),
                if retry.failures == 1 {
                    "once".to_string()
                } else {
                    format!("{} times", retry.failures)
                },
                human_duration(retry.max_wait)
            )?;
        }
        Ok(())
    }
}

/// Rounds of failed fetches of one block across the daemon's polls, so a node
/// that keeps refusing is asked less and less often instead of every poll.
#[derive(Debug, Default)]
pub(crate) struct FetchBackoff {
    block: Option<BlockHash>,
    failures: u32,
    wait: Option<Duration>,
}

impl FetchBackoff {
    pub(crate) const FIRST_WAIT: Duration = Duration::from_secs(30);
    pub(crate) const MAX_WAIT: Duration = Duration::from_secs(5 * 60);

    /// A round of attempts for `block` failed: when to try again (30 s,
    /// doubling up to 5 min while the same block keeps failing).
    pub(crate) fn failed(&mut self, block: BlockHash) -> RetryNote {
        if self.block != Some(block) {
            self.block = Some(block);
            self.failures = 0;
        }
        self.failures += 1;
        let next_in = Self::FIRST_WAIT
            .saturating_mul(1 << (self.failures - 1).min(16))
            .min(Self::MAX_WAIT);
        self.wait = Some(next_in);
        RetryNote {
            failures: self.failures,
            next_in,
            max_wait: Self::MAX_WAIT,
        }
    }

    /// The scan got past every block it fetched.
    pub(crate) fn succeeded(&mut self) {
        *self = Self::default();
    }

    /// The wait the last failure asked for, once.
    pub(crate) fn take_wait(&mut self) -> Option<Duration> {
        self.wait.take()
    }
}

/// Fetches full blocks over P2P, from the own node (retrying on a fresh
/// connection with exponential backoff) or from discovered peers (one peer
/// after another), and says why when it cannot.
#[derive(Debug, Clone)]
pub struct BlockFetcher {
    peers: Arc<PeerSource>,
    policy: RetryPolicy,
    cancel: CancellationToken,
}

/// What an attempt on a discovered peer does beyond the own-node attempt.
struct Discovery {
    peers: Arc<PeerSource>,
    /// Ask the peer for addresses (`getaddr`) and keep what it gossips.
    request_addr: bool,
    /// Refuse a peer whose chain ends below this height, before asking.
    min_height: u64,
}

impl BlockFetcher {
    /// With [`RetryPolicy::for_source`].
    pub fn new(peers: Arc<PeerSource>) -> Self {
        Self {
            policy: RetryPolicy::for_source(&peers),
            peers,
            cancel: CancellationToken::new(),
        }
    }

    pub fn with_policy(mut self, policy: RetryPolicy) -> Self {
        self.policy = policy;
        self
    }

    /// End [`Self::fetch`] as soon as `cancel` is cancelled, wherever it
    /// waits: connecting, in the handshake, for the block, between
    /// attempts or for peers. It then fails with [`FetchFailure::Cancelled`].
    pub fn with_cancel(mut self, cancel: CancellationToken) -> Self {
        self.cancel = cancel;
        self
    }

    fn network(&self) -> Network {
        self.peers.network()
    }

    /// Fetch block `block_hash` (at `height`, which feeds messages and, with
    /// discovered peers, skips peers whose chain is shorter).
    ///
    /// Every attempt opens a fresh connection and closes it afterwards, so a
    /// connection the node dropped is never reused and no connection idles
    /// between fetches (where it would miss the node's pings).
    ///
    /// The own node: failures that another connection may not repeat (see
    /// `FetchFailure::is_transient`) are retried after the policy's waits
    /// (1, 2, 4, 8 s by default); the others end the call at once, since
    /// asking again right away cannot change the answer. When the policy
    /// permits another attempt, a connection that stays quiet through the
    /// full block deadline gets one fresh connection, then ends the round
    /// instead of spending the full retry budget on repeated long waits.
    ///
    /// Discovered peers: each attempt asks a peer not asked yet in this
    /// call, whatever the previous one did, until one serves the block or
    /// the attempts or the peers run out; each outcome is reported to the
    /// [`PeerSource`].
    ///
    /// The connection's I/O is blocking and runs on a thread of its own, so
    /// it never blocks the async runtime and the call stays cancellable:
    /// see [`Self::with_cancel`]. Dropping the future cancels it too.
    pub async fn fetch(
        &self,
        block_hash: BlockHash,
        height: u64,
    ) -> Result<Block, Box<BlockFetchError>> {
        match self.peers.own_node_addr() {
            Some(node) => self.fetch_from_node(node, block_hash, height).await,
            None => self.fetch_from_network(block_hash, height).await,
        }
    }

    fn read_timeout(&self) -> Duration {
        READ_TIMEOUT
            .min(self.policy.block_deadline)
            .max(Duration::from_millis(100))
    }

    async fn fetch_from_node(
        &self,
        node: &PeerAddr,
        block_hash: BlockHash,
        height: u64,
    ) -> Result<Block, Box<BlockFetchError>> {
        let attempts = self.policy.attempts.max(1);
        let read_timeout = self.read_timeout();
        let mut peer_info = None;
        let mut local_ip = None;
        let mut tried = 0;
        let mut last = None;
        let mut quiet_timeouts = 0;
        for attempt in 1..=attempts {
            if attempt > 1 {
                tokio::select! {
                    biased;
                    () = self.cancel.cancelled() => {
                        last = Some(FetchFailure::Cancelled);
                        break;
                    }
                    () = tokio::time::sleep(self.policy.delay_before(attempt)) => {}
                }
            }
            tried = attempt;
            let result = self
                .attempt(
                    node,
                    block_hash,
                    read_timeout,
                    &mut peer_info,
                    &mut local_ip,
                    None,
                )
                .await;
            match result {
                Ok(block) => {
                    if attempt > 1 {
                        tracing::info!(
                            peer = %node,
                            height,
                            %block_hash,
                            attempt,
                            "block fetched after retrying"
                        );
                    }
                    return Ok(block);
                }
                Err(AttemptFailure::Regular(FetchFailure::Cancelled)) => {
                    last = Some(FetchFailure::Cancelled);
                    break;
                }
                Err(attempt_failure) => {
                    let quiet = matches!(&attempt_failure, AttemptFailure::QuietDeadline(_));
                    let failure = attempt_failure.into_fetch_failure();
                    tracing::warn!(
                        peer = %node,
                        height,
                        %block_hash,
                        attempt,
                        max_attempts = attempts,
                        failure = %failure,
                        "block fetch attempt failed"
                    );
                    let again = if quiet {
                        quiet_timeouts += 1;
                        quiet_timeouts == 1
                    } else {
                        failure.is_transient()
                    };
                    last = Some(failure);
                    if !again {
                        break;
                    }
                }
            }
        }
        if last == Some(FetchFailure::Cancelled) {
            tracing::info!(peer = %node, height, %block_hash, "block fetch cancelled");
        }
        Err(Box::new(BlockFetchError {
            from: FetchedFrom::OwnNode(node.clone()),
            network: self.network(),
            height,
            block_hash,
            attempts: tried,
            failure: last.expect("at least one attempt ran"),
            peer_info,
            local_ip,
            retry: None,
        }))
    }

    async fn fetch_from_network(
        &self,
        block_hash: BlockHash,
        height: u64,
    ) -> Result<Block, Box<BlockFetchError>> {
        let attempts = self.policy.attempts.max(1);
        let read_timeout = self.read_timeout();
        let started = Instant::now();
        let mut peer_info = None;
        let mut local_ip = None;
        let mut asked = HashSet::new();
        let mut tried: Vec<(PeerAddr, FetchFailure)> = Vec::new();
        let mut last = None;
        let mut exhausted = false;
        for attempt in 1..=attempts {
            let delay = self.policy.delay_before(attempt);
            if attempt > 1 && !delay.is_zero() {
                tokio::select! {
                    biased;
                    () = self.cancel.cancelled() => {
                        last = Some(FetchFailure::Cancelled);
                        break;
                    }
                    () = tokio::time::sleep(delay) => {}
                }
            }
            let next = tokio::select! {
                biased;
                () = self.cancel.cancelled() => {
                    last = Some(FetchFailure::Cancelled);
                    break;
                }
                next = self.peers.next(Purpose::Block, &asked) => next,
            };
            let peer = match next {
                Ok(peer) => peer,
                Err(no_peers) => {
                    tracing::warn!(height, %block_hash, reason = %no_peers, "no peer to ask for the block");
                    exhausted = true;
                    if tried.is_empty() {
                        last = Some(FetchFailure::NoPeers(no_peers.0));
                    }
                    break;
                }
            };
            asked.insert(peer.clone());
            let discovery = Discovery {
                peers: self.peers.clone(),
                request_addr: self.peers.wants_addr(&peer),
                min_height: height,
            };
            tracing::debug!(%peer, height, %block_hash, attempt, "asking a peer for the block");
            let mut connected = None;
            let result = self
                .attempt(
                    &peer,
                    block_hash,
                    read_timeout,
                    &mut connected,
                    &mut local_ip,
                    Some(discovery),
                )
                .await;
            if let Some(info) = connected {
                peer_info = Some(info);
                self.peers.report(&peer, PeerEvent::Connected(info));
            }
            match result {
                Ok(block) => {
                    self.peers.report(&peer, PeerEvent::Served);
                    tracing::info!(
                        %peer,
                        height,
                        %block_hash,
                        peers_asked = attempt,
                        elapsed_ms = started.elapsed().as_millis() as u64,
                        "block fetched from a peer of the network"
                    );
                    return Ok(block);
                }
                Err(AttemptFailure::Regular(FetchFailure::Cancelled)) => {
                    last = Some(FetchFailure::Cancelled);
                    break;
                }
                Err(attempt_failure) => {
                    let event = attempt_failure.peer_event(connected.is_some());
                    let failure = attempt_failure.into_fetch_failure();
                    self.peers.report(&peer, event);
                    tracing::info!(
                        %peer,
                        height,
                        %block_hash,
                        attempt,
                        max_attempts = attempts,
                        failure = %failure,
                        "peer did not serve the block; asking another"
                    );
                    tried.push((peer, failure.clone()));
                    last = Some(failure);
                }
            }
        }
        if last == Some(FetchFailure::Cancelled) {
            tracing::info!(height, %block_hash, "block fetch cancelled");
        }
        Err(Box::new(BlockFetchError {
            from: FetchedFrom::Network {
                tried: tried.clone(),
                exhausted,
            },
            network: self.network(),
            height,
            block_hash,
            attempts: tried.len() as u32,
            failure: last.expect("at least one attempt ran"),
            peer_info,
            local_ip,
            retry: None,
        }))
    }

    /// One attempt on a fresh connection to `peer`.
    ///
    /// The TCP connect runs on a blocking thread through the source's
    /// [`crate::net::Dialer`]; cancelling stops waiting for it at once. The
    /// handshake and the download then run on a thread of their own, with
    /// blocking socket I/O and per-read timeouts as before; this future only
    /// waits for that thread's answer. On cancellation (or when this future
    /// is dropped) the socket is shut down, which wakes a read or write
    /// blocked on it, so the thread ends right away instead of after its
    /// read timeout.
    async fn attempt(
        &self,
        peer: &PeerAddr,
        block_hash: BlockHash,
        read_timeout: Duration,
        peer_info: &mut Option<PeerInfo>,
        local_ip: &mut Option<IpAddr>,
        discovery: Option<Discovery>,
    ) -> Result<Block, AttemptFailure> {
        tracing::debug!(%peer, "opening P2P connection for a block fetch");
        let opened = Instant::now();
        let connect = {
            let (dialer, target) = (self.peers.dialer().clone(), peer.clone());
            let timeout = self.policy.connect_timeout;
            tokio::task::spawn_blocking(move || dialer.connect(&target, timeout))
        };
        let stream = tokio::select! {
            biased;
            () = self.cancel.cancelled() => return Err(FetchFailure::Cancelled.into()),
            connected = connect => match connected {
                Ok(Ok(stream)) => stream,
                Ok(Err(e)) if is_no_route(&e) => return Err(AttemptFailure::NoRoute(e.to_string())),
                Ok(Err(e)) => return Err(FetchFailure::Connect(e.to_string()).into()),
                Err(e) => {
                    return Err(FetchFailure::Connect(format!("the connect task failed: {e}")).into());
                }
            },
        };
        if let Ok(local) = stream.local_addr() {
            *local_ip = Some(local.ip());
        }
        let mut shutdown = ShutdownOnDrop(Some(
            stream
                .try_clone()
                .map_err(|e| FetchFailure::Broken(e.to_string()))?,
        ));
        let lingers = discovery.as_ref().is_some_and(|d| d.request_addr);
        // A discovered peer gets a deadline for the whole connection.
        let cap = if discovery.is_some() {
            self.policy.connect_timeout + self.policy.block_deadline + DISCOVERED_SLACK
        } else {
            Duration::MAX
        };

        let (answer, answered) = tokio::sync::oneshot::channel();
        let (peer_addr, network, deadline) =
            (peer.clone(), self.network(), self.policy.block_deadline);
        let cancel = self.cancel.clone();
        std::thread::Builder::new()
            .name("p2p-block-fetch".to_string())
            .spawn(move || {
                download(
                    stream,
                    peer_addr,
                    network,
                    read_timeout,
                    opened,
                    block_hash,
                    deadline,
                    &cancel,
                    discovery,
                    answer,
                )
            })
            .map_err(|e| FetchFailure::Broken(format!("cannot start the download: {e}")))?;

        let result = tokio::select! {
            biased;
            () = self.cancel.cancelled() => Err(FetchFailure::Cancelled.into()),
            () = sleep_at_most(cap.saturating_sub(opened.elapsed())) => {
                Err(FetchFailure::Broken(format!(
                    "the peer was too slow: no block within {}",
                    human_duration(cap)
                ))
                .into())
            }
            answered = answered => {
                let (info, result) = answered.map_err(|_| {
                    FetchFailure::Broken("the download ended without an answer".to_string())
                })?;
                if info.is_some() {
                    *peer_info = info;
                }
                result
            }
        };
        // The thread keeps the connection a moment to collect the peer's
        // addresses; it closes it itself.
        if result.is_ok() && lingers {
            shutdown.disarm();
        }
        result
    }
}

/// `tokio::time::sleep`, but never for longer than a timer can represent.
async fn sleep_at_most(duration: Duration) {
    match tokio::time::Instant::now().checked_add(duration) {
        Some(deadline) => tokio::time::sleep_until(deadline).await,
        None => std::future::pending().await,
    }
}

/// The download thread: handshake, block, then (for a discovered peer that
/// was asked for addresses) a short wait for them.
#[allow(clippy::too_many_arguments)]
fn download(
    stream: TcpStream,
    peer: PeerAddr,
    network: Network,
    read_timeout: Duration,
    opened: Instant,
    block_hash: BlockHash,
    deadline: Duration,
    cancel: &CancellationToken,
    discovery: Option<Discovery>,
    answer: tokio::sync::oneshot::Sender<(Option<PeerInfo>, Result<Block, AttemptFailure>)>,
) {
    let mut connection =
        match P2pConnection::handshake(stream, peer, network, read_timeout, opened, &discovery) {
            Ok(connection) => connection,
            Err(failure) => {
                let _ = answer.send((None, Err(failure.into())));
                return;
            }
        };
    let info = connection.info;
    if let Some(discovery) = &discovery
        && i64::from(info.height) < discovery.min_height as i64
    {
        let _ = answer.send((Some(info), Err(FetchFailure::Behind(info.height).into())));
        return;
    }
    let gossip = discovery.as_ref().map(|d| d.peers.as_ref());
    let result = connection.fetch_block(block_hash, deadline, cancel, gossip);
    let served = result.is_ok();
    if answer.send((Some(info), result)).is_err() {
        return;
    }
    if served
        && let Some(discovery) = &discovery
        && discovery.request_addr
        && !connection.got_addr
    {
        connection.wait_for_addr(GOSSIP_WAIT, cancel, &discovery.peers);
    }
}

/// A second handle on a connection's socket that shuts the connection down
/// when dropped. A shutdown ends a read or write blocked on the socket in
/// another thread at once (it then sees the connection closed).
struct ShutdownOnDrop(Option<TcpStream>);

impl ShutdownOnDrop {
    /// Leave the connection to the thread that owns it.
    fn disarm(&mut self) {
        self.0 = None;
    }
}

impl Drop for ShutdownOnDrop {
    fn drop(&mut self) {
        if let Some(stream) = &self.0 {
            let _ = stream.shutdown(Shutdown::Both);
        }
    }
}

/// One open, handshaken P2P connection used for a single block fetch.
///
/// The messages a node sends after `verack` (`sendcmpct`, `feefilter`,
/// `wtxidrelay`, `sendaddrv2`, …) need no draining: unrecognised messages
/// decode to `NetworkMessage::Unknown`, every message is read as an exact,
/// checksummed frame, and `fetch_block` skips any non-block message while it
/// waits.
struct P2pConnection {
    writer: ConnectionWriter,
    reader: ConnectionReader,
    /// Another handle on the socket, to change its timeouts.
    socket: Option<TcpStream>,
    peer: PeerAddr,
    opened: Instant,
    info: PeerInfo,
    /// The peer sent addresses (`addr` / `addrv2`).
    got_addr: bool,
}

impl P2pConnection {
    /// Complete the version handshake on `stream`, a TCP connection to
    /// `peer` opened at `opened`. A discovered peer must serve every block
    /// with its witnesses and answer each handshake message promptly, and
    /// is asked for addresses when `discovery` says so.
    fn handshake(
        stream: TcpStream,
        peer: PeerAddr,
        network: Network,
        read_timeout: Duration,
        opened: Instant,
        discovery: &Option<Discovery>,
    ) -> Result<Self, FetchFailure> {
        let handshake_timeout = match discovery {
            Some(_) => read_timeout.min(DISCOVERED_HANDSHAKE_TIMEOUT),
            None => read_timeout,
        };
        let configure = |stream: &TcpStream| -> io::Result<()> {
            stream.set_read_timeout(Some(handshake_timeout))?;
            stream.set_write_timeout(Some(READ_TIMEOUT))?;
            stream.set_nodelay(true)
        };
        configure(&stream).map_err(|e| FetchFailure::Broken(e.to_string()))?;
        let socket = match discovery {
            Some(_) => Some(
                stream
                    .try_clone()
                    .map_err(|e| FetchFailure::Broken(e.to_string()))?,
            ),
            None => None,
        };
        // `handshake` takes only the ping interval from `TimeoutParams`; the
        // socket timeouts are the ones `configure` set above.
        let mut config = ConnectionConfig::new()
            .change_network(network)
            .user_agent(USER_AGENT.to_string())
            .fee_filter(FEE_FILTER);
        if let Some(discovery) = discovery {
            config = config.set_service_requirement(crate::net::pool::required_services());
            if discovery.request_addr {
                config = config.request_addr();
            }
        }
        let (writer, reader, metadata) = config
            .handshake(stream, TimeoutParams::default())
            .map_err(|e| handshake_failure(e, opened))?;
        if let Some(socket) = &socket {
            socket
                .set_read_timeout(Some(read_timeout))
                .map_err(|e| FetchFailure::Broken(e.to_string()))?;
        }
        let feeler = metadata.feeler_data();
        tracing::debug!(
            peer = %peer,
            peer_height = feeler.reported_height,
            services = %feeler.services,
            "P2P handshake complete"
        );
        Ok(Self {
            writer,
            reader,
            socket,
            peer,
            opened,
            info: PeerInfo {
                services: feeler.services,
                height: feeler.reported_height,
            },
            got_addr: false,
        })
    }

    fn closed(&self) -> FetchFailure {
        FetchFailure::Closed {
            during_handshake: false,
            after: self.opened.elapsed(),
        }
    }

    /// Hand addresses the peer gossiped to `peers`.
    fn take_gossip(&mut self, message: &NetworkMessage, peers: &PeerSource) -> bool {
        let addrs: Vec<AddrV2Message> = match message {
            NetworkMessage::AddrV2(list) => list.clone(),
            NetworkMessage::Addr(list) => list
                .iter()
                .filter_map(|(time, address)| {
                    let socket = address.socket_addr().ok()?;
                    let addr = match socket.ip() {
                        IpAddr::V4(ip) => AddrV2::Ipv4(ip),
                        IpAddr::V6(ip) => AddrV2::Ipv6(ip),
                    };
                    Some(AddrV2Message {
                        time: *time,
                        services: address.services,
                        addr,
                        port: socket.port(),
                    })
                })
                .collect(),
            _ => return false,
        };
        self.got_addr = true;
        peers.add_gossip(&self.peer, addrs);
        true
    }

    fn fetch_block(
        &mut self,
        block_hash: BlockHash,
        deadline: Duration,
        cancel: &CancellationToken,
        gossip: Option<&PeerSource>,
    ) -> Result<Block, AttemptFailure> {
        // With witnesses: the wallet stores these transactions and the
        // Electrum server hands them to wallets, which need them whole (a
        // plain `MSG_BLOCK` strips every witness: right txids, wrong sizes
        // and fee rates).
        let net_msg = NetworkMessage::GetData(vec![Inventory::WitnessBlock(block_hash)]);

        // The writer thread only goes away once a write failed: the peer is gone.
        self.writer
            .send_message(net_msg)
            .map_err(|_| self.closed())?;
        tracing::debug!(peer = %self.peer, block_hash = %block_hash, "sent getdata for block");
        // A node handles a peer's messages in order, so it answers this
        // ping once it has sent the block or decided not to. If the block
        // has not come by the deadline, a pong means the node does not
        // serve it; no pong means the node went quiet, perhaps part way
        // through the block, whose partly read bytes are lost with the
        // read that timed out.
        let ping_nonce =
            u64::from_le_bytes(block_hash.as_byte_array()[..8].try_into().expect("8 bytes"));
        self.writer
            .send_message(NetworkMessage::Ping(ping_nonce))
            .map_err(|_| self.closed())?;
        let mut ping_answered = false;

        let started = Instant::now();
        let mut last_idle_log = 0u64;

        loop {
            // The caller has stopped waiting (and shut the socket down);
            // checked here too in case a platform's shutdown does not wake
            // a blocked read.
            if cancel.is_cancelled() {
                return Err(FetchFailure::Cancelled.into());
            }
            if started.elapsed() > deadline {
                if ping_answered {
                    return Err(FetchFailure::NoAnswer(started.elapsed()).into());
                }
                return Err(AttemptFailure::QuietDeadline(started.elapsed()));
            }

            match self.reader.read_message() {
                Ok(Some(NetworkMessage::Block(block))) => {
                    check_block(&block, block_hash)?;
                    tracing::info!(
                        peer = %self.peer,
                        block_hash = %block.block_hash(),
                        tx_count = block.txdata.len(),
                        elapsed_ms = started.elapsed().as_millis() as u64,
                        "received block from peer"
                    );
                    return Ok(block);
                }
                Ok(Some(NetworkMessage::Ping(nonce))) => {
                    // Pong inline so the peer doesn't drop us for inactivity
                    // while it's still preparing/streaming the block.
                    let _ = self.writer.send_message(NetworkMessage::Pong(nonce));
                }
                Ok(Some(NetworkMessage::Pong(nonce))) if nonce == ping_nonce => {
                    ping_answered = true;
                }
                // The peer explicitly told us it does not have/serve this block.
                Ok(Some(NetworkMessage::NotFound(_))) => {
                    return Err(FetchFailure::NotFound.into());
                }
                Ok(Some(NetworkMessage::Reject(reject))) => {
                    return Err(FetchFailure::Broken(format!(
                        "the node rejected the request: {reject:?}"
                    ))
                    .into());
                }
                Ok(Some(msg)) => {
                    if !gossip.is_some_and(|peers| self.take_gossip(&msg, peers)) {
                        tracing::trace!(
                            peer = %self.peer,
                            command = %msg.command(),
                            "skipping message while waiting for block"
                        );
                    }
                }
                Ok(None) => {} // no message this round; keep waiting
                Err(e) if is_read_timeout(&e) => {
                    // Per-syscall timeout: the peer just hasn't sent the next
                    // chunk yet. Keep waiting until the deadline.
                    let waited = started.elapsed().as_secs();
                    if waited >= last_idle_log + READ_TIMEOUT.as_secs() {
                        last_idle_log = waited;
                        tracing::warn!(
                            peer = %self.peer,
                            block_hash = %block_hash,
                            waited_s = waited,
                            "no data from peer yet, still waiting for block"
                        );
                    }
                }
                // EOF ("failed to fill whole buffer") or a reset: the peer
                // closed the connection.
                Err(P2pNetError::Io(e)) if is_closed(&e) => {
                    return Err(self.closed().into());
                }
                // Anything else means the framed stream is unusable.
                Err(e) => return Err(FetchFailure::Broken(e.to_string()).into()),
            }
        }
    }

    /// After the block: wait up to `wait` for the addresses the handshake
    /// asked for (Bitcoin Core may send them after the block), then close.
    /// Nothing else is read; a read that times out part way through a
    /// message ends the wait, since the connection closes anyway.
    fn wait_for_addr(&mut self, wait: Duration, cancel: &CancellationToken, peers: &PeerSource) {
        let until = Instant::now() + wait;
        if let Some(socket) = &self.socket {
            let _ = socket.set_read_timeout(Some(Duration::from_millis(250)));
        }
        while Instant::now() < until && !cancel.is_cancelled() {
            match self.reader.read_message() {
                Ok(Some(NetworkMessage::Ping(nonce))) => {
                    let _ = self.writer.send_message(NetworkMessage::Pong(nonce));
                }
                Ok(Some(message)) => {
                    if self.take_gossip(&message, peers) {
                        break;
                    }
                }
                Ok(None) => {}
                Err(e) if is_read_timeout(&e) => {}
                Err(_) => break,
            }
        }
        if let Some(socket) = &self.socket {
            let _ = socket.shutdown(Shutdown::Both);
        }
    }
}

/// The block is the one asked for and arrived whole: its transactions match
/// the header's merkle root and, when it holds segwit transactions, their
/// witnesses match the coinbase's commitment. A node that strips or garbles
/// witness data fails here, rather than friglet storing those transactions
/// and serving them to wallets without their witnesses.
fn check_block(block: &Block, requested: BlockHash) -> Result<(), FetchFailure> {
    if block.block_hash() != requested {
        return Err(FetchFailure::BadBlock(format!(
            "it is block {}",
            block.block_hash()
        )));
    }
    if !block.check_merkle_root() {
        return Err(FetchFailure::BadBlock(
            "its transactions do not match its merkle root".to_string(),
        ));
    }
    // A witness commitment requires the coinbase's witness reserved value,
    // so a committed block without it was stripped on the way.
    let coinbase = block.txdata.first();
    let commits = coinbase.is_some_and(|tx| {
        tx.output.iter().any(|out| {
            out.script_pubkey
                .as_bytes()
                .starts_with(&WITNESS_COMMITMENT_PREFIX)
        })
    });
    if commits
        && coinbase
            .and_then(|tx| tx.input.first())
            .is_none_or(|input| input.witness.is_empty())
    {
        return Err(FetchFailure::WitnessStripped);
    }
    if !block.check_witness_commitment() {
        return Err(FetchFailure::BadBlock(
            "its witnesses do not match its witness commitment".to_string(),
        ));
    }
    Ok(())
}

/// `OP_RETURN OP_PUSHBYTES_36 0xaa21a9ed`: the start of a BIP 141 witness
/// commitment output.
const WITNESS_COMMITMENT_PREFIX: [u8; 6] = [0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];

fn handshake_failure(error: P2pNetError, opened: Instant) -> FetchFailure {
    match error {
        P2pNetError::UnexpectedMagic(magic) => {
            FetchFailure::WrongNetwork(Network::from_magic(magic))
        }
        P2pNetError::Io(e) if is_closed(&e) => FetchFailure::Closed {
            during_handshake: true,
            after: opened.elapsed(),
        },
        P2pNetError::Io(e) if is_timeout(&e) => {
            FetchFailure::Handshake("the node did not answer the version message".to_string())
        }
        P2pNetError::Io(e) => FetchFailure::Broken(e.to_string()),
        other => FetchFailure::Handshake(other.to_string()),
    }
}

/// A per-syscall read timeout (the peer is momentarily quiet), not a fatal error.
fn is_read_timeout(e: &P2pNetError) -> bool {
    matches!(e, P2pNetError::Io(io_err) if is_timeout(io_err))
}

fn is_timeout(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    )
}

/// The peer closed the connection; mid-read this surfaces as "failed to fill
/// whole buffer".
fn is_closed(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::UnexpectedEof
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::BrokenPipe
    )
}

/// This computer has no route to the peer's network (typically IPv6 on a
/// host without IPv6 connectivity).
fn is_no_route(e: &io::Error) -> bool {
    e.kind() == io::ErrorKind::NetworkUnreachable
}

fn network_name(network: Network) -> &'static str {
    match network {
        Network::Bitcoin => "mainnet",
        Network::Testnet => "testnet3",
        Network::Testnet4 => "testnet4",
        Network::Signet => "signet",
        Network::Regtest => "regtest",
    }
}

/// The network's default P2P port (Bitcoin Core's `-port` default).
fn default_p2p_port(network: Network) -> u16 {
    crate::net::pool::default_port(network)
}

/// "80 ms", "12 s", "2 min", "2 min 30 s".
fn human_duration(d: Duration) -> String {
    let (secs, minutes, rest) = (d.as_secs(), d.as_secs() / 60, d.as_secs() % 60);
    if d < Duration::from_secs(1) {
        format!("{} ms", d.as_millis())
    } else if secs < 60 {
        format!("{secs} s")
    } else if rest == 0 {
        format!("{minutes} min")
    } else {
        format!("{minutes} min {rest} s")
    }
}
