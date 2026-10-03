use std::fmt;
use std::io;
use std::net::{IpAddr, Shutdown, SocketAddr, TcpStream};
use std::time::{Duration, Instant};

use bitcoin::Block;
use bitcoin::BlockHash;
use bitcoin::hashes::Hash;

use bitcoin_p2p::net::{ConnectionReader, ConnectionWriter, Error as P2pNetError};
use bitcoin_p2p::p2p_message_types::message::InventoryPayload;
use bitcoin_p2p::p2p_message_types::{NetworkExt, ServiceFlags};
use bitcoin_p2p::p2p_message_types::{message::NetworkMessage, message_blockdata::Inventory};
use bitcoin_p2p::{
    handshake::ConnectionConfig,
    net::{ConnectionExt, TimeoutParams},
};

// rust-bitcoin on specific commit for use with bitcoin-p2p library
use bitcoin_rev::block::BlockHash as PrimitivesBlockHash;
use bitcoin_rev::consensus::encode;
use bitcoin_rev::{Network, TestnetVersion};
use tokio_util::sync::CancellationToken;

// ---------------------------------------------------------------------------
// Full-block fetch
// ---------------------------------------------------------------------------

/// How long the TCP connect to the node may take.
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

/// Bitcoin Core's `NODE_NETWORK_LIMITED_MIN_BLOCKS`: a pruned node serves
/// only this many of the newest blocks, and disconnects peers that ask for
/// older ones.
const LIMITED_BLOCKS: i64 = 288;

/// Bitcoin Core's `HISTORICAL_BLOCK_AGE` (one week) in blocks: once a node
/// reaches its `-maxuploadtarget`, it disconnects peers that ask for older
/// blocks.
const HISTORICAL_BLOCKS: i64 = 7 * 144;

/// How [`BlockFetcher::fetch`] retries within one call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryPolicy {
    /// Connections tried before giving up. Each attempt opens a fresh
    /// connection, so a dropped connection is never reused.
    pub attempts: u32,
    /// Wait before the second attempt; it doubles for each further attempt.
    pub first_delay: Duration,
    /// Upper bound for the wait between attempts.
    pub max_delay: Duration,
    /// Overall budget for receiving the block on one connection.
    pub block_deadline: Duration,
}

impl Default for RetryPolicy {
    /// Five attempts over about 15 s (waits of 1, 2, 4 and 8 s).
    fn default() -> Self {
        Self {
            attempts: 5,
            first_delay: Duration::from_secs(1),
            max_delay: Duration::from_secs(8),
            block_deadline: Duration::from_secs(90),
        }
    }
}

impl RetryPolicy {
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

/// A block could not be fetched from the P2P node. Its message says what the
/// node did and what the user can do about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockFetchError {
    pub peer: SocketAddr,
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

    /// What `whitelist=` should name: friglet's own address when the node is
    /// on this machine or the local network (it sees that address), else a
    /// placeholder for the public address the node sees.
    fn whitelist_address(&self) -> String {
        let local_peer = match self.peer.ip() {
            IpAddr::V4(ip) => ip.is_loopback() || ip.is_private() || ip.is_link_local(),
            IpAddr::V6(ip) => {
                ip.is_loopback() || ip.is_unique_local() || ip.is_unicast_link_local()
            }
        };
        match self.local_ip {
            Some(ip) if local_peer => ip.to_string(),
            _ => "<this computer's public IP>".to_string(),
        }
    }

    /// ": 38333 is the signet port" when the node's port is another
    /// network's default.
    fn other_network_port_hint(&self) -> String {
        let port = self.peer.port();
        if port == self.network.default_p2p_port() {
            return String::new();
        }
        [
            Network::Bitcoin,
            Network::Testnet(TestnetVersion::V3),
            Network::Testnet(TestnetVersion::V4),
            Network::Signet,
            Network::Regtest,
        ]
        .into_iter()
        .find(|network| network.default_p2p_port() == port)
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
}

impl fmt::Display for BlockFetchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let net = network_name(self.network);
        let port = self.network.default_p2p_port();
        let tries = if self.attempts > 1 {
            format!(" (all {} tries)", self.attempts)
        } else {
            String::new()
        };
        write!(
            f,
            "cannot get block {} ({}) from your node {}: ",
            self.height, self.block_hash, self.peer
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
                    "the node sent nothing for {} and gave no reason, which is what Bitcoin Core \
                     does for a block it does not have. ",
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
        }
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

/// Fetches full blocks from one P2P node, retrying on a fresh connection
/// with exponential backoff, and says why when it cannot.
#[derive(Debug, Clone)]
pub struct BlockFetcher {
    peer: SocketAddr,
    network: Network,
    policy: RetryPolicy,
    cancel: CancellationToken,
}

impl BlockFetcher {
    pub fn new(peer: SocketAddr, network: Network) -> Self {
        Self {
            peer,
            network,
            policy: RetryPolicy::default(),
            cancel: CancellationToken::new(),
        }
    }

    pub fn with_policy(mut self, policy: RetryPolicy) -> Self {
        self.policy = policy;
        self
    }

    /// End [`Self::fetch`] as soon as `cancel` is cancelled, wherever it
    /// waits: connecting, in the handshake, for the block or between
    /// attempts. It then fails with [`FetchFailure::Cancelled`].
    pub fn with_cancel(mut self, cancel: CancellationToken) -> Self {
        self.cancel = cancel;
        self
    }

    /// Fetch block `block_hash` (at `height`, which only feeds messages).
    ///
    /// Every attempt opens a fresh connection and closes it afterwards, so a
    /// connection the node dropped is never reused and no connection idles
    /// between fetches (where it would miss the node's pings). Failures that
    /// another connection may not repeat (see `FetchFailure::is_transient`)
    /// are retried after the policy's waits (1, 2, 4, 8 s by default); the
    /// others end the call at once, since asking again right away cannot
    /// change the answer.
    ///
    /// The connection's I/O is blocking and runs on a thread of its own, so
    /// it never blocks the async runtime and the call stays cancellable:
    /// see [`Self::with_cancel`]. Dropping the future cancels it too.
    pub async fn fetch(
        &self,
        block_hash: BlockHash,
        height: u64,
    ) -> Result<Block, Box<BlockFetchError>> {
        let attempts = self.policy.attempts.max(1);
        let read_timeout = READ_TIMEOUT
            .min(self.policy.block_deadline)
            .max(Duration::from_millis(100));
        let mut peer_info = None;
        let mut local_ip = None;
        let mut tried = 0;
        let mut last = None;
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
                .attempt(block_hash, read_timeout, &mut peer_info, &mut local_ip)
                .await;
            match result {
                Ok(block) => {
                    if attempt > 1 {
                        tracing::info!(
                            peer = %self.peer,
                            height,
                            %block_hash,
                            attempt,
                            "block fetched after retrying"
                        );
                    }
                    return Ok(block);
                }
                Err(FetchFailure::Cancelled) => {
                    last = Some(FetchFailure::Cancelled);
                    break;
                }
                Err(failure) => {
                    tracing::warn!(
                        peer = %self.peer,
                        height,
                        %block_hash,
                        attempt,
                        max_attempts = attempts,
                        failure = %failure,
                        "block fetch attempt failed"
                    );
                    let again = failure.is_transient();
                    last = Some(failure);
                    if !again {
                        break;
                    }
                }
            }
        }
        if last == Some(FetchFailure::Cancelled) {
            tracing::info!(peer = %self.peer, height, %block_hash, "block fetch cancelled");
        }
        Err(Box::new(BlockFetchError {
            peer: self.peer,
            network: self.network,
            height,
            block_hash,
            attempts: tried,
            failure: last.expect("at least one attempt ran"),
            peer_info,
            local_ip,
            retry: None,
        }))
    }

    /// One attempt on a fresh connection.
    ///
    /// The TCP connect is async, so cancelling abandons it at once. The
    /// handshake and the download then run on a thread of their own, with
    /// blocking socket I/O and per-read timeouts as before; this future only
    /// waits for that thread's answer. On cancellation (or when this future
    /// is dropped) the socket is shut down, which wakes a read or write
    /// blocked on it, so the thread ends right away instead of after its
    /// read timeout.
    async fn attempt(
        &self,
        block_hash: BlockHash,
        read_timeout: Duration,
        peer_info: &mut Option<PeerInfo>,
        local_ip: &mut Option<IpAddr>,
    ) -> Result<Block, FetchFailure> {
        tracing::debug!(peer = %self.peer, "opening P2P connection for a block fetch");
        let opened = Instant::now();
        let connect =
            tokio::time::timeout(CONNECT_TIMEOUT, tokio::net::TcpStream::connect(self.peer));
        let stream = tokio::select! {
            biased;
            () = self.cancel.cancelled() => return Err(FetchFailure::Cancelled),
            connected = connect => match connected {
                Ok(Ok(stream)) => stream,
                Ok(Err(e)) => return Err(FetchFailure::Connect(e.to_string())),
                Err(_) => return Err(FetchFailure::Connect("connection timed out".to_string())),
            },
        };
        let stream = stream
            .into_std()
            .and_then(|stream| stream.set_nonblocking(false).map(|()| stream))
            .map_err(|e| FetchFailure::Broken(e.to_string()))?;
        if let Ok(local) = stream.local_addr() {
            *local_ip = Some(local.ip());
        }
        let _shutdown = ShutdownOnDrop(
            stream
                .try_clone()
                .map_err(|e| FetchFailure::Broken(e.to_string()))?,
        );

        let (answer, answered) = tokio::sync::oneshot::channel();
        let (peer, network, deadline) = (self.peer, self.network, self.policy.block_deadline);
        let cancel = self.cancel.clone();
        std::thread::Builder::new()
            .name("p2p-block-fetch".to_string())
            .spawn(move || {
                let mut info = None;
                let result = P2pConnection::handshake(stream, peer, network, read_timeout, opened)
                    .and_then(|mut connection| {
                        info = Some(connection.info);
                        connection.fetch_block(block_hash, deadline, &cancel)
                    });
                let _ = answer.send((info, result));
            })
            .map_err(|e| FetchFailure::Broken(format!("cannot start the download: {e}")))?;

        tokio::select! {
            biased;
            () = self.cancel.cancelled() => Err(FetchFailure::Cancelled),
            answered = answered => {
                let (info, result) = answered.map_err(|_| {
                    FetchFailure::Broken("the download ended without an answer".to_string())
                })?;
                if info.is_some() {
                    *peer_info = info;
                }
                result
            }
        }
    }
}

/// A second handle on a connection's socket that shuts the connection down
/// when dropped. A shutdown ends a read or write blocked on the socket in
/// another thread at once (it then sees the connection closed).
struct ShutdownOnDrop(TcpStream);

impl Drop for ShutdownOnDrop {
    fn drop(&mut self) {
        let _ = self.0.shutdown(Shutdown::Both);
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
    peer: SocketAddr,
    opened: Instant,
    info: PeerInfo,
}

impl P2pConnection {
    /// Complete the version handshake on `stream`, a TCP connection to
    /// `peer` opened at `opened`.
    fn handshake(
        stream: TcpStream,
        peer: SocketAddr,
        network: Network,
        read_timeout: Duration,
        opened: Instant,
    ) -> Result<Self, FetchFailure> {
        let configure = |stream: &TcpStream| -> io::Result<()> {
            stream.set_read_timeout(Some(read_timeout))?;
            stream.set_write_timeout(Some(READ_TIMEOUT))?;
            stream.set_nodelay(true)
        };
        configure(&stream).map_err(|e| FetchFailure::Broken(e.to_string()))?;
        // `handshake` takes only the ping interval from `TimeoutParams`; the
        // socket timeouts are the ones `configure` set above.
        let (writer, reader, metadata) = ConnectionConfig::new()
            .change_network(network)
            .handshake(stream, TimeoutParams::default())
            .map_err(|e| handshake_failure(e, opened))?;
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
            peer,
            opened,
            info: PeerInfo {
                services: feeler.services,
                height: feeler.reported_height,
            },
        })
    }

    fn closed(&self) -> FetchFailure {
        FetchFailure::Closed {
            during_handshake: false,
            after: self.opened.elapsed(),
        }
    }

    fn fetch_block(
        &mut self,
        block_hash: BlockHash,
        deadline: Duration,
        cancel: &CancellationToken,
    ) -> Result<Block, FetchFailure> {
        let primitives_block_hash =
            PrimitivesBlockHash::from_byte_array(*block_hash.as_byte_array());
        // With witnesses: the wallet stores these transactions and the
        // Electrum server hands them to wallets, which need them whole (a
        // plain `MSG_BLOCK` strips every witness: right txids, wrong sizes
        // and fee rates).
        let inventory = Inventory::WitnessBlock(primitives_block_hash);
        let net_msg = NetworkMessage::GetData(InventoryPayload(vec![inventory]));

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
                return Err(FetchFailure::Cancelled);
            }
            if started.elapsed() > deadline {
                if ping_answered {
                    return Err(FetchFailure::NoAnswer(started.elapsed()));
                }
                return Err(FetchFailure::Broken(format!(
                    "the node went quiet: no block and no answer to a ping in {}",
                    human_duration(started.elapsed())
                )));
            }

            match self.reader.read_message() {
                Ok(Some(NetworkMessage::Block(block))) => {
                    let block_bytes = encode::serialize(&block);
                    let block: Block = bitcoin::consensus::encode::deserialize(&block_bytes)
                        .map_err(|e| FetchFailure::Broken(format!("undecodable block: {e}")))?;
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
                Ok(Some(NetworkMessage::NotFound(_))) => return Err(FetchFailure::NotFound),
                Ok(Some(NetworkMessage::Reject(reject))) => {
                    return Err(FetchFailure::Broken(format!(
                        "the node rejected the request: {reject:?}"
                    )));
                }
                Ok(Some(msg)) => {
                    tracing::trace!(
                        peer = %self.peer,
                        command = %msg.command(),
                        "skipping message while waiting for block"
                    );
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
                Err(P2pNetError::Io(e)) if is_closed(&e) => return Err(self.closed()),
                // Anything else means the framed stream is unusable.
                Err(e) => return Err(FetchFailure::Broken(e.to_string())),
            }
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
            FetchFailure::WrongNetwork(Network::try_from(magic).ok())
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

fn network_name(network: Network) -> &'static str {
    match network {
        Network::Bitcoin => "mainnet",
        Network::Testnet(TestnetVersion::V3) => "testnet3",
        Network::Testnet(_) => "testnet4",
        Network::Signet => "signet",
        Network::Regtest => "regtest",
    }
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
