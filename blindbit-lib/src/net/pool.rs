//! Which peer each P2P connection goes to.
//!
//! With an own node configured, [`PeerSource::OwnNode`]: every connection
//! goes to it, nothing is looked up and nothing is learnt.
//!
//! Otherwise [`PeerSource::Discovered`]: a [`PeerPool`] of addresses from the
//! network's DNS seeds and from what peers gossip, kept in a "new" and a
//! "tried" table (kernel-node's address book, with Kyoto's sizes: a single
//! source can fill only part of a table). Connections report back how they
//! went ([`PeerEvent`]): a peer that completes a handshake moves to "tried";
//! one that cannot be reached or does not help rests for a while; one that
//! sends a bad block is ignored for the rest of the session; and the peer
//! that served the last block is asked first for the next one.
//!
//! The tables can be kept on disk ([`PeerSource::keep_book_in`]), so a
//! restart knows its peers without asking the seeds again.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::fs::File;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::io::{self, BufReader, Read};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant};

use bitcoin::Network;
use bitcoin::p2p::ServiceFlags;
use bitcoin::p2p::address::{AddrV2, AddrV2Message};
use bitcoin_address_book::io::FileExt;
use bitcoin_address_book::{Record, Table};

use super::seeds::{Seeded, Seeding, Seeds};
use super::{Dialer, NetGroup, PeerAddr, PeerHost, Purpose, random_u64};
use crate::scanner::PeerInfo;

// Kyoto's table sizes: 16 x 16 new slots, a source reaches 8 of the 16
// buckets; 4 x 16 tried slots, a source reaches 2 of the 4.
type NewTable = Table<16, 16, 8>;
type TriedTable = Table<4, 16, 2>;
const NEW_SLOTS: u64 = 16 * 16;
const TRIED_SLOTS: u64 = 4 * 16;
/// A saved table holds at most one record per slot; a file listing more
/// than this many per slot is refused unread.
const SAVED_PER_SLOT: u64 = 2;

/// Random draws from the tables before settling for any usable peer.
const MAX_DRAWS: usize = 64;
/// Block downloads ask for addresses (`getaddr`) while fewer are known.
const WANT_ADDRS_BELOW: usize = 200;
/// At most this many addresses are taken from one gossip message (Bitcoin
/// Core's `MAX_ADDR_TO_SEND`).
pub(crate) const MAX_GOSSIP_PER_MESSAGE: usize = 1_000;
/// A peer that could not be reached rests this long, and is forgotten after
/// [`MAX_UNREACHABLE`] failures in a row: the seeds and gossip cannot bring
/// it back for [`FORGET_FOR`].
const UNREACHABLE_REST: Duration = Duration::from_secs(10 * 60);
const MAX_UNREACHABLE: u8 = 3;
const FORGET_FOR: Duration = Duration::from_secs(60 * 60);
/// After an IPv6 connection found no route, IPv6 peers are skipped this long
/// (the network may change).
const IPV6_DEAD_FOR: Duration = Duration::from_secs(30 * 60);
/// A peer that connected but did not help (no block, closed, stalled).
const UNHELPFUL_REST: Duration = Duration::from_secs(10 * 60);
/// The proxy counts as working this long after a connection through it
/// completed a handshake…
const PROXY_WORKS_FOR: Duration = Duration::from_secs(10 * 60);
/// …until this many connects through it got no clear answer since.
const PROXY_UNCLEAR_COUNTED: u8 = 8;
/// A peer whose chain is below the block asked for: it may catch up soon.
const BEHIND_REST: Duration = Duration::from_secs(2 * 60);
/// The DNS seeds are asked again at most this often…
const RESEED_EVERY: Duration = Duration::from_secs(5 * 60);
/// …or this often while they have given nothing.
const RESEED_EVERY_WHILE_EMPTY: Duration = Duration::from_secs(30);
/// At start, the seeds are asked only while fewer addresses are known
/// (from the address book on disk).
const SEED_BELOW: usize = 50;
/// Through a proxy, how many addresses the seeds' nodes must have added to
/// the book before seeding returns; the answers of the seeds still being
/// asked join it as they come.
const ENOUGH_SEEDED: usize = 20;
/// A kept address book is saved this often while it changes, and at exit.
const SAVE_EVERY: Duration = Duration::from_secs(10 * 60);
/// Kyoto's limits for replacing a colliding record that keeps failing.
const TERRIBLE_TRIES: u8 = 2;
const TERRIBLE_WEEKLY_TRIES: u8 = 1;

/// The services a discovered peer must offer: all blocks, with witnesses.
pub(crate) fn required_services() -> ServiceFlags {
    ServiceFlags::NETWORK | ServiceFlags::WITNESS
}

/// How a connection to a peer went, reported with [`PeerSource::report`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerEvent {
    /// The handshake completed; what the peer said about itself. A full
    /// node (every block, with witnesses) moves to "tried".
    Connected(PeerInfo),
    /// The peer served the block asked for.
    Served,
    /// No connection or no handshake (refused, timed out, closed during the
    /// handshake, too old, pruned).
    Unreachable,
    /// The connection failed because this computer has no route to the
    /// peer's network (an IPv6 peer without IPv6 connectivity).
    NoRoute,
    /// Connected, but did not help: no block, closed, went quiet.
    Unhelpful,
    /// Through the proxy, the connect got no clear answer about the peer:
    /// no reply in time, or a general failure. Tor answers that for a dead
    /// address, and for every address while it has no working circuit. So
    /// it counts as [`Self::Unreachable`] only while the proxy works (a
    /// connection through it completed a handshake in the last 10 minutes,
    /// and fewer than 8 connects have failed this way since); otherwise the
    /// peer only rests, and a Tor outage cannot empty the address book.
    ProxyUnclear,
    /// Its chain is below the block asked for.
    Behind,
    /// Sent a block that fails its checks, or speaks another network.
    Misbehaved,
    /// Completed the handshake but relays no transactions (its `version`
    /// says so: a blocks-only node): not used for relaying again this
    /// session. Blocks may still come from it.
    NoTxRelay,
}

/// No peer to connect to: why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoPeers(pub String);

impl fmt::Display for NoPeers {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for NoPeers {}

/// Where P2P connections go. Shared (`Arc`) by everything that opens one:
/// the scanner's block downloads and the Electrum server.
#[derive(Debug)]
pub enum PeerSource {
    /// The user's own node: the only peer, always.
    OwnNode {
        addr: PeerAddr,
        dialer: Dialer,
        network: Network,
    },
    /// Peers of the network, found and judged as connections go.
    Discovered(PeerPool),
}

impl PeerSource {
    /// Every connection goes to `addr`.
    pub fn own_node(addr: PeerAddr, dialer: Dialer, network: Network) -> Arc<Self> {
        Arc::new(Self::OwnNode {
            addr,
            dialer,
            network,
        })
    }

    /// Peers of `network`, starting from `seeds`.
    pub fn discover(network: Network, dialer: Dialer, seeds: Seeds) -> Arc<Self> {
        Arc::new(Self::Discovered(PeerPool::new(network, dialer, seeds)))
    }

    /// The own node when one is configured, else discovery from `seeds`
    /// (which an own node never uses).
    pub fn new(
        network: Network,
        dialer: Dialer,
        own_node: Option<PeerAddr>,
        seeds: Seeds,
    ) -> Arc<Self> {
        match own_node {
            Some(addr) => Self::own_node(addr, dialer, network),
            None => Self::discover(network, dialer, seeds),
        }
    }

    /// Start finding peers now (in a task on the current Tokio runtime), so
    /// the first download does not wait for the DNS seeds; skipped while the
    /// address book loaded from disk knows enough peers. Without it the
    /// first [`Self::next`] asks them. A kept address book
    /// ([`Self::keep_book_in`]) is saved every 10 minutes from now on, when
    /// it changed. Does nothing for an own node.
    pub fn start(self: &Arc<Self>) {
        let Self::Discovered(pool) = &**self else {
            return;
        };
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let known = pool.lock().known();
        if known < SEED_BELOW {
            let this = self.clone();
            runtime.spawn(async move {
                if let Self::Discovered(pool) = &*this {
                    pool.seed().await;
                }
            });
        } else {
            tracing::info!(
                known,
                "peer discovery: the saved address book knows enough peers"
            );
        }
        if pool.book.get().is_some() {
            let this = self.clone();
            runtime.spawn(async move {
                loop {
                    tokio::time::sleep(SAVE_EVERY).await;
                    let this = this.clone();
                    let _ = tokio::task::spawn_blocking(move || {
                        if let Self::Discovered(pool) = &*this {
                            pool.save(true);
                        }
                    })
                    .await;
                }
            });
        }
    }

    /// Keep the address book of discovered peers in `dir`, as
    /// `peers-<network>-new.book` and `peers-<network>-tried.book`: load it
    /// now (an unreadable file is ignored with a warning) and save it with
    /// [`Self::save_book`] and, after [`Self::start`], every 10 minutes
    /// while it changes. Call it once, before [`Self::start`]. Does nothing
    /// for an own node.
    pub fn keep_book_in(&self, dir: &Path) {
        if let Self::Discovered(pool) = self {
            pool.keep_book_in(dir);
        }
    }

    /// Save the kept address book now (blocking file I/O), if it changed.
    pub fn save_book(&self) {
        if let Self::Discovered(pool) = self {
            pool.save(true);
        }
    }

    pub fn network(&self) -> Network {
        match self {
            Self::OwnNode { network, .. } => *network,
            Self::Discovered(pool) => pool.network,
        }
    }

    pub fn dialer(&self) -> &Dialer {
        match self {
            Self::OwnNode { dialer, .. } => dialer,
            Self::Discovered(pool) => &pool.dialer,
        }
    }

    pub fn is_own_node(&self) -> bool {
        matches!(self, Self::OwnNode { .. })
    }

    /// The own node, if this is one.
    pub fn own_node_addr(&self) -> Option<&PeerAddr> {
        match self {
            Self::OwnNode { addr, .. } => Some(addr),
            Self::Discovered(_) => None,
        }
    }

    /// The peer for the next connection, never one in `exclude` (the peers
    /// a caller already tried this round). An own node is always it. A
    /// discovering source waits for the DNS seeds while it knows no peer,
    /// asks them again when every known peer is used up (rate-limited),
    /// and then falls back to a peer that is resting after a failure.
    pub async fn next(
        &self,
        purpose: Purpose,
        exclude: &HashSet<PeerAddr>,
    ) -> Result<PeerAddr, NoPeers> {
        self.next_outside(purpose, exclude, &HashSet::new()).await
    }

    /// [`Self::next`], also passing over every peer in one of `groups`
    /// (see [`NetGroup`]): for connections that must go to different
    /// operators. An own node is always it.
    pub async fn next_outside(
        &self,
        purpose: Purpose,
        exclude: &HashSet<PeerAddr>,
        groups: &HashSet<NetGroup>,
    ) -> Result<PeerAddr, NoPeers> {
        match self {
            Self::OwnNode { addr, .. } => Ok(addr.clone()),
            Self::Discovered(pool) => {
                pool.next(Want {
                    purpose,
                    exclude,
                    groups,
                })
                .await
            }
        }
    }

    /// How a connection to `peer` went. Nothing for an own node.
    pub fn report(&self, peer: &PeerAddr, event: PeerEvent) {
        if let Self::Discovered(pool) = self {
            pool.report(peer, event);
        }
    }

    /// Addresses `from` gossiped (`addr` / `addrv2`). Whether they answer
    /// the peer's `getaddr`: more than one address, or one that is not the
    /// peer's own (a node announces itself with a message of its own
    /// address alone). Only an answer stops [`Self::wants_addr`] asking the
    /// peer again. Nothing for an own node.
    pub fn add_gossip(
        &self,
        from: &PeerAddr,
        addrs: impl IntoIterator<Item = AddrV2Message>,
    ) -> bool {
        match self {
            Self::Discovered(pool) => pool.add_gossip(from, addrs),
            Self::OwnNode { .. } => false,
        }
    }

    /// Should a block download from `peer` ask it for addresses? Only
    /// while a discovering source knows few, and only once per peer (Bitcoin
    /// Core answers a peer's repeated `getaddr` from a cache).
    pub fn wants_addr(&self, peer: &PeerAddr) -> bool {
        match self {
            Self::OwnNode { .. } => false,
            Self::Discovered(pool) => {
                let inner = pool.lock();
                inner.known() < WANT_ADDRS_BELOW && !inner.gossiped.contains(peer)
            }
        }
    }

    /// Peer addresses known (in either table), not counting ignored ones.
    pub fn known(&self) -> usize {
        match self {
            Self::OwnNode { .. } => 1,
            Self::Discovered(pool) => pool.lock().known(),
        }
    }

    /// One line for status displays: "your node 1.2.3.4:38333", "random
    /// peers: 37 known, 1 ignored".
    pub fn summary(&self) -> String {
        let summary = match self {
            Self::OwnNode { addr, .. } => format!("your node {addr}"),
            Self::Discovered(pool) => pool.summary(),
        };
        match self.dialer() {
            Dialer::Direct => summary,
            proxied => format!("{summary}, {proxied}"),
        }
    }
}

/// The address book of a discovering [`PeerSource`].
pub struct PeerPool {
    network: Network,
    dialer: Dialer,
    seeds: Seeds,
    /// Where the tables are kept on disk, if they are.
    book: OnceLock<BookFiles>,
    /// Never held across an `.await`.
    inner: Mutex<Inner>,
    /// One seeding at a time; callers that need peers wait for it.
    seeding: tokio::sync::Mutex<()>,
    /// One save of the kept address book at a time.
    saving: Mutex<()>,
}

impl fmt::Debug for PeerPool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let inner = self.lock();
        f.debug_struct("PeerPool")
            .field("network", &self.network)
            .field("known", &inner.known())
            .field("ignored", &inner.ignored())
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Where {
    New,
    Tried,
}

/// What the pool knows about one address beyond its table record.
struct Meta {
    /// The record as the table holds it: its source decides its bucket, so
    /// table operations on it need this one; connections stamp it as they
    /// stamp the table's copy (see [`count`]), and a saved book keeps it.
    record: Record,
    /// The table it is in; `None` once it is ignored.
    table: Option<Where>,
    resting_until: Option<Instant>,
    /// Failed connections in a row.
    failures: u8,
    /// Ignored for the rest of the session; kept so gossip cannot add it
    /// back.
    ignored: bool,
}

/// What a caller of [`PeerSource::next_outside`] asks for and rules out.
#[derive(Clone, Copy)]
struct Want<'a> {
    purpose: Purpose,
    exclude: &'a HashSet<PeerAddr>,
    groups: &'a HashSet<NetGroup>,
}

impl Want<'_> {
    /// Not ruled out by the caller (the pool's own judgement aside).
    fn allows(&self, addr: &PeerAddr) -> bool {
        !self.exclude.contains(addr)
            && (self.groups.is_empty() || !self.groups.contains(&addr.netgroup()))
    }
}

struct Inner {
    new: Box<NewTable>,
    tried: Box<TriedTable>,
    /// Every address in a table, and the ignored ones.
    meta: HashMap<PeerAddr, Meta>,
    /// The peer that served the last block.
    preferred: Option<PeerAddr>,
    /// When an IPv6 connection found no route: IPv6 peers are skipped for
    /// [`IPV6_DEAD_FOR`].
    ipv6_dead_since: Option<Instant>,
    /// When the seeds were last asked, and how many new addresses they gave.
    last_seed: Option<(Instant, usize)>,
    /// Peers that gossiped addresses this session.
    gossiped: HashSet<PeerAddr>,
    /// Peers that said they relay no transactions: never handed out for
    /// relaying this session, also after they left the tables (a slot
    /// collision, failures) and came back. Learnt again after a restart.
    no_tx_relay: HashSet<PeerAddr>,
    /// The proxy failed the last time the seeds were asked: why.
    seed_error: Option<String>,
    /// When a connection through the proxy last completed a handshake, and
    /// how many connects through it got no clear answer since.
    proxy_worked: Option<(Instant, u8)>,
    /// Answers of seeds still being asked when a seeding returned, one
    /// receiver per seeding until its last seed answered (a later seeding
    /// does not drop them); added to the book on the next
    /// [`PeerPool::next`].
    later_seeds: Vec<tokio::sync::mpsc::UnboundedReceiver<Seeding>>,
    /// The tables changed since they were last saved.
    changed: bool,
}

/// The files a kept address book lives in.
#[derive(Debug, Clone)]
struct BookFiles {
    new: PathBuf,
    tried: PathBuf,
}

impl PeerPool {
    fn new(network: Network, dialer: Dialer, seeds: Seeds) -> Self {
        Self {
            network,
            dialer,
            seeds,
            book: OnceLock::new(),
            inner: Mutex::new(Inner {
                new: Box::default(),
                tried: Box::default(),
                meta: HashMap::new(),
                preferred: None,
                ipv6_dead_since: None,
                last_seed: None,
                gossiped: HashSet::new(),
                no_tx_relay: HashSet::new(),
                seed_error: None,
                proxy_worked: None,
                later_seeds: Vec::new(),
                changed: false,
            }),
            seeding: tokio::sync::Mutex::new(()),
            saving: Mutex::new(()),
        }
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        // A panic while holding it leaves nothing half-updated that matters.
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    async fn next(&self, want: Want<'_>) -> Result<PeerAddr, NoPeers> {
        self.add_later_seeds();
        let mut seeded = false;
        loop {
            if let Some(addr) = self.lock().pick(want) {
                return Ok(addr);
            }
            if !seeded && self.lock().may_seed() {
                self.seed().await;
                seeded = true;
                continue;
            }
            // Only resting peers left: better one of them than none.
            if let Some(addr) = self.lock().resting(want) {
                return Ok(addr);
            }
            return Err(NoPeers(self.no_peers_reason(want)));
        }
    }

    fn no_peers_reason(&self, want: Want<'_>) -> String {
        let exclude = want.exclude;
        let inner = self.lock();
        let known = inner.known();
        if known == 0 {
            if let Some(error) = &inner.seed_error {
                return format!("no peer addresses: the seeds could not be asked: {error}");
            }
            return match (&self.seeds, self.dialer.proxy()) {
                (Seeds::Dns(names), None) => format!(
                    "no peer addresses: the network's DNS seeds ({}) gave none",
                    names.join(", ")
                ),
                (Seeds::Dns(names), Some(proxy)) => format!(
                    "no peer addresses: the nodes of the network's seeds ({}), asked through \
                     p2p_proxy {proxy}, gave none",
                    names.join(", ")
                ),
                (Seeds::Static(_) | Seeds::None, _) => {
                    "no peer addresses to start from".to_string()
                }
            };
        }
        let skipped_v6 = if inner.ipv6_dead() {
            inner
                .meta
                .iter()
                .filter(|(addr, meta)| meta.table.is_some() && addr.is_ipv6())
                .count()
        } else {
            0
        };
        let mut reason = format!("all {known} known peers were tried");
        if !exclude.is_empty() {
            reason.push_str(&format!(" ({} of them just now)", exclude.len()));
        }
        if !want.groups.is_empty() {
            reason.push_str(&format!(
                ", or are in one of the {} network groups already in use",
                want.groups.len()
            ));
        }
        if skipped_v6 > 0 {
            reason.push_str(&format!(
                "; {skipped_v6} are IPv6 peers, and this computer has no IPv6 route"
            ));
        }
        reason
    }

    /// Ask the seeds, unless another caller just did (callers that find the
    /// book empty wait here for a seeding already under way).
    async fn seed(&self) {
        let _one_at_a_time = self.seeding.lock().await;
        if !self.lock().may_seed() {
            return;
        }
        let port = default_port(self.network);
        let started = Instant::now();
        let seeding = self.seeds.resolve(port, &self.dialer, self.network).await;
        let mut found = seeding.found.len();
        let mut added = {
            let mut inner = self.lock();
            inner.seed_error = seeding.proxy_error;
            self.add_seeded(&mut inner, &seeding.found)
        };
        // Through a proxy the seeds' nodes answer one by one. What counts is
        // what the book took: an answer may hold only addresses it refuses
        // (not public, a bad port, known already, a taken slot).
        let mut answers = seeding.later;
        while added < ENOUGH_SEEDED
            && let Some(later) = answers.as_mut()
        {
            let Some(answer) = later.recv().await else {
                answers = None;
                break;
            };
            found += answer.found.len();
            let mut inner = self.lock();
            if let Some(error) = answer.proxy_error {
                inner.seed_error = Some(error);
            }
            added += self.add_seeded(&mut inner, &answer.found);
        }
        let mut inner = self.lock();
        inner.later_seeds.extend(answers);
        inner.last_seed = Some((Instant::now(), added));
        let seeds: Vec<&str> = match &self.seeds {
            Seeds::Dns(names) => names.to_vec(),
            Seeds::Static(_) => vec!["static"],
            Seeds::None => Vec::new(),
        };
        tracing::info!(
            seeds = %seeds.join(", "),
            via = %self.dialer,
            addresses = found,
            added,
            known = inner.known(),
            elapsed_ms = started.elapsed().as_millis() as u64,
            "peer discovery: asked the DNS seeds"
        );
        if let Some(error) = &inner.seed_error {
            tracing::warn!(%error, "peer discovery: the seeds could not be asked");
        }
    }

    /// Put the addresses the seeds gave in the book; how many were new.
    fn add_seeded(&self, inner: &mut Inner, found: &[Seeded]) -> usize {
        let mut added = 0;
        let from_dns = matches!(self.seeds, Seeds::Dns(_));
        for seeded in found {
            let Some(ip) = seeded.addr.ip() else {
                continue;
            };
            // A DNS answer naming this computer or a local network is not a
            // Bitcoin peer (a captive portal, a hijacked resolver).
            if from_dns && !is_public(ip) {
                continue;
            }
            // What a seed's node gossiped is checked like any gossip.
            if seeded.gossiped && !self.worth_keeping(ip, seeded.addr.port, seeded.services, false)
            {
                continue;
            }
            let record = Record::new(
                addrv2(ip),
                seeded.addr.port,
                seeded.services,
                &seed_source(seeded.seed),
            );
            if inner.add(seeded.addr.clone(), record) {
                added += 1;
            }
        }
        added
    }

    /// Add what seeds that answered after seeding returned gave, counted
    /// with what the last seeding added (which decides when the seeds are
    /// asked again); a proxy failure counts as during seeding.
    fn add_later_seeds(&self) {
        use tokio::sync::mpsc::error::TryRecvError;
        let mut inner = self.lock();
        let mut answers = Vec::new();
        inner.later_seeds.retain_mut(|later| {
            loop {
                match later.try_recv() {
                    Ok(answer) => answers.push(answer),
                    Err(TryRecvError::Empty) => break true,
                    Err(TryRecvError::Disconnected) => break false,
                }
            }
        });
        for answer in answers {
            if let Some(error) = answer.proxy_error {
                tracing::warn!(%error, "peer discovery: the seeds could not be asked");
                inner.seed_error = Some(error);
            }
            let added = self.add_seeded(&mut inner, &answer.found);
            if let Some((_, last_added)) = inner.last_seed.as_mut() {
                *last_added += added;
            }
            tracing::debug!(
                addresses = answer.found.len(),
                added,
                known = inner.known(),
                "peer discovery: a seed answered after seeding returned"
            );
        }
    }

    fn report(&self, peer: &PeerAddr, event: PeerEvent) {
        let mut inner = self.lock();
        let now = Instant::now();
        if !matches!(
            event,
            PeerEvent::Served | PeerEvent::Connected(_) | PeerEvent::NoTxRelay
        ) && inner.preferred.as_ref() == Some(peer)
        {
            inner.preferred = None;
        }
        match event {
            PeerEvent::Connected(info) => {
                if self.dialer.proxy().is_some() {
                    inner.proxy_worked = Some((now, 0));
                }
                inner.connected(peer, info.services);
            }
            PeerEvent::Served => {
                inner.preferred = Some(peer.clone());
                if let Some(meta) = inner.meta.get_mut(peer) {
                    meta.resting_until = None;
                    meta.failures = 0;
                }
            }
            PeerEvent::NoRoute if peer.is_ipv6() => {
                if !inner.ipv6_dead() {
                    tracing::info!(
                        %peer,
                        "no IPv6 route from this computer: skipping IPv6 peers for 30 min"
                    );
                }
                inner.ipv6_dead_since = Some(now);
            }
            PeerEvent::Unreachable | PeerEvent::NoRoute => inner.failed(peer, now),
            PeerEvent::Unhelpful => inner.rest(peer, now + UNHELPFUL_REST),
            PeerEvent::ProxyUnclear => {
                let proxy_works = inner
                    .proxy_worked
                    .as_mut()
                    .filter(|(at, unclear)| {
                        now.duration_since(*at) < PROXY_WORKS_FOR
                            && *unclear < PROXY_UNCLEAR_COUNTED
                    })
                    .map(|(_, unclear)| *unclear += 1)
                    .is_some();
                // Tor works: the address does not.
                if proxy_works {
                    inner.failed(peer, now);
                } else {
                    inner.rest(peer, now + UNHELPFUL_REST);
                }
            }
            PeerEvent::Behind => inner.rest(peer, now + BEHIND_REST),
            PeerEvent::Misbehaved => inner.ignore(peer),
            PeerEvent::NoTxRelay => {
                inner.no_tx_relay.insert(peer.clone());
            }
        }
    }

    fn add_gossip(&self, from: &PeerAddr, addrs: impl IntoIterator<Item = AddrV2Message>) -> bool {
        let Some(from_ip) = from.ip() else {
            return false;
        };
        let addrs: Vec<AddrV2Message> = addrs.into_iter().take(MAX_GOSSIP_PER_MESSAGE).collect();
        let own = |message: &AddrV2Message| {
            let ip = match message.addr {
                AddrV2::Ipv4(ip) => IpAddr::V4(ip),
                AddrV2::Ipv6(ip) => IpAddr::V6(ip),
                _ => return false,
            };
            // An IPv4-mapped address is the IPv4 address it maps.
            PeerAddr::from(SocketAddr::new(ip, 0)).ip() == Some(from_ip)
        };
        let answer = addrs.len() > 1 || addrs.first().is_some_and(|message| !own(message));
        // A peer on the public internet cannot point friglet at this
        // computer or its local network; a local one (a test, a LAN node)
        // may name local peers.
        let local_source = !is_public(from_ip);
        let source = addrv2(from_ip);
        let mut inner = self.lock();
        if answer {
            inner.gossiped.insert(from.clone());
        }
        let (offered, mut added) = (addrs.len(), 0);
        for message in addrs {
            let ip = match message.addr {
                AddrV2::Ipv4(ip) => IpAddr::V4(ip),
                AddrV2::Ipv6(ip) => IpAddr::V6(ip),
                // Tor, I2P and CJDNS peers need a proxy.
                _ => continue,
            };
            if !self.worth_keeping(ip, message.port, message.services, local_source) {
                continue;
            }
            let addr = PeerAddr::from(SocketAddr::new(ip, message.port));
            let Some(ip) = addr.ip() else {
                continue;
            };
            let record =
                Record::new_from_addrv2_source(addrv2(ip), message.port, message.services, &source);
            if inner.add(addr, record) {
                added += 1;
            }
        }
        tracing::debug!(
            peer = %from,
            offered,
            added,
            answer,
            known = inner.known(),
            "peer gossiped addresses"
        );
        answer
    }

    /// A gossiped address worth a place in the book: a full node (every
    /// block, with witnesses) on a plausible port, at an address a peer can
    /// have. A local one only from a local source (`local_ok`: a test, a
    /// LAN node): a peer on the internet cannot point friglet at this
    /// computer or its network.
    fn worth_keeping(&self, ip: IpAddr, port: u16, services: ServiceFlags, local_ok: bool) -> bool {
        plausible_port(port, self.network)
            && services.has(required_services())
            && !ip.is_unspecified()
            && !ip.is_multicast()
            && (local_ok || is_public(ip))
    }

    fn keep_book_in(&self, dir: &Path) {
        let network = self.network.to_string();
        let files = BookFiles {
            new: dir.join(format!("peers-{network}-new.book")),
            tried: dir.join(format!("peers-{network}-tried.book")),
        };
        if self.book.set(files.clone()).is_err() {
            return;
        }
        let mut inner = self.lock();
        let mut loaded = 0;
        // "tried" first: an address in both files stays tried.
        for (path, place) in [(&files.tried, Where::Tried), (&files.new, Where::New)] {
            let slots = match place {
                Where::New => NEW_SLOTS,
                Where::Tried => TRIED_SLOTS,
            };
            match read_book(path, SAVED_PER_SLOT * slots) {
                Ok(records) => {
                    for record in records {
                        if inner.add_saved(record, place) {
                            loaded += 1;
                        }
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => tracing::warn!(
                    path = %path.display(),
                    error = %e,
                    "ignoring an unreadable peer address book"
                ),
            }
        }
        if loaded > 0 {
            tracing::info!(
                known = inner.known(),
                dir = %dir.display(),
                "peer discovery: loaded the saved address book"
            );
        }
    }

    /// Write the tables to the kept address book's files, if there is one
    /// (and, with `only_if_changed`, only when they changed). A failure is
    /// logged; the book stays in memory.
    ///
    /// The records are copied under the lock and the files written (and
    /// synced to disk) without it, so connections are not held up by a
    /// slow disk; one save at a time, so an older copy never overwrites a
    /// newer one.
    fn save(&self, only_if_changed: bool) {
        let Some(files) = self.book.get() else {
            return;
        };
        let _one_at_a_time = self.saving.lock().unwrap_or_else(|e| e.into_inner());
        let saved = {
            let mut inner = self.lock();
            if only_if_changed && !inner.changed {
                return;
            }
            inner.changed = false;
            inner.saved_records()
        };
        let (new, tried) = saved_tables(&saved);
        let result = write_book(&files.new, |file| file.write_table(&*new))
            .and_then(|()| write_book(&files.tried, |file| file.write_table(&*tried)));
        match result {
            Ok(()) => tracing::debug!(known = saved.len(), "peer address book saved"),
            Err(e) => {
                self.lock().changed = true;
                tracing::warn!(
                    path = %files.new.display(),
                    error = %e,
                    "cannot save the peer address book"
                );
            }
        }
    }

    fn summary(&self) -> String {
        let inner = self.lock();
        let (known, ignored) = (inner.known(), inner.ignored());
        if known == 0 && inner.last_seed.is_none() {
            return "random peers: looking for peers".to_string();
        }
        let mut summary = format!("random peers: {known} known");
        if ignored > 0 {
            summary.push_str(&format!(", {ignored} ignored"));
        }
        summary
    }

    #[cfg(test)]
    pub(crate) fn place(&self, addr: &PeerAddr) -> Option<Where> {
        self.lock().meta.get(addr).and_then(|meta| meta.table)
    }

    /// As if a seeding had returned while seeds were still being asked:
    /// their answers come through `later`.
    #[cfg(test)]
    pub(crate) fn queue_later_seeds(&self, later: tokio::sync::mpsc::UnboundedReceiver<Seeding>) {
        self.lock().later_seeds.push(later);
    }

    #[cfg(test)]
    pub(crate) fn seed_error(&self) -> Option<String> {
        self.lock().seed_error.clone()
    }

    #[cfg(test)]
    pub(crate) fn services(&self, addr: &PeerAddr) -> Option<ServiceFlags> {
        self.lock()
            .meta
            .get(addr)
            .map(|meta| meta.record.service_flags())
    }

    #[cfg(test)]
    pub(crate) fn is_ignored(&self, addr: &PeerAddr) -> bool {
        self.lock().meta.get(addr).is_some_and(|meta| meta.ignored)
    }

    #[cfg(test)]
    pub(crate) fn is_resting(&self, addr: &PeerAddr) -> bool {
        self.lock()
            .meta
            .get(addr)
            .and_then(|meta| meta.resting_until)
            .is_some_and(|until| until > Instant::now())
    }

    #[cfg(test)]
    pub(crate) fn changed(&self) -> bool {
        self.lock().changed
    }

    #[cfg(test)]
    pub(crate) fn preferred(&self) -> Option<PeerAddr> {
        self.lock().preferred.clone()
    }

    #[cfg(test)]
    pub(crate) fn seeded_at(&self) -> Option<Instant> {
        self.lock().last_seed.map(|(at, _)| at)
    }

    #[cfg(test)]
    pub(crate) fn age_rest(&self, addr: &PeerAddr, by: Duration) {
        if let Some(meta) = self.lock().meta.get_mut(addr) {
            meta.resting_until = meta.resting_until.and_then(|until| until.checked_sub(by));
        }
    }

    #[cfg(test)]
    pub(crate) fn age_proxy_worked(&self, by: Duration) {
        let mut inner = self.lock();
        if let Some((at, unclear)) = inner.proxy_worked {
            inner.proxy_worked = Some((at.checked_sub(by).unwrap_or(at), unclear));
        }
    }

    #[cfg(test)]
    pub(crate) fn age_ipv6_dead(&self, by: Duration) {
        let mut inner = self.lock();
        inner.ipv6_dead_since = inner
            .ipv6_dead_since
            .and_then(|since| since.checked_sub(by));
    }

    #[cfg(test)]
    pub(crate) fn age_last_seed(&self, by: Duration) {
        let mut inner = self.lock();
        if let Some((at, added)) = inner.last_seed {
            inner.last_seed = Some((at.checked_sub(by).unwrap_or(at), added));
        }
    }
}

/// The tables `saved` describes, each record as the live table holds it,
/// with the times connections gave it.
fn saved_tables(saved: &[(Record, Where)]) -> (Box<NewTable>, Box<TriedTable>) {
    let (mut new, mut tried) = (Box::<NewTable>::default(), Box::<TriedTable>::default());
    for (record, table) in saved {
        match table {
            Where::New => new.add(record),
            Where::Tried => tried.add(record),
        };
    }
    (new, tried)
}

/// Do to `record` what a table's `successful_connection` (`connected`) or
/// `failed_connection` does to its copy now: stamp the attempt (and the
/// connection), count or clear the failures. The pool's copy then matches
/// the table's and keeps those times when saved.
fn count(record: &mut Record, connected: bool) {
    // A table of one slot holds only this record, so `select` gives it back.
    let mut one = Table::<1, 1, 1>::new();
    one.add(record);
    if connected {
        one.successful_connection(record);
    } else {
        one.failed_connection(record);
    }
    if let Some(counted) = one.select() {
        *record = counted;
    }
}

impl Inner {
    /// Every record in a table, to save.
    fn saved_records(&self) -> Vec<(Record, Where)> {
        self.meta
            .values()
            .filter_map(|meta| Some((meta.record.clone(), meta.table?)))
            .collect()
    }

    fn ipv6_dead(&self) -> bool {
        self.ipv6_dead_since
            .is_some_and(|since| since.elapsed() < IPV6_DEAD_FOR)
    }

    fn known(&self) -> usize {
        self.meta
            .values()
            .filter(|meta| meta.table.is_some())
            .count()
    }

    fn ignored(&self) -> usize {
        self.meta.values().filter(|meta| meta.ignored).count()
    }

    fn may_seed(&self) -> bool {
        match self.last_seed {
            None => true,
            Some((at, 0)) => at.elapsed() >= RESEED_EVERY_WHILE_EMPTY,
            Some((at, _)) => at.elapsed() >= RESEED_EVERY,
        }
    }

    /// Known, not ignored, fit for `want` and reachable from here, resting
    /// or not.
    fn eligible(&self, addr: &PeerAddr, want: Want<'_>) -> bool {
        let Some(meta) = self.meta.get(addr) else {
            return false;
        };
        meta.table.is_some()
            && !meta.ignored
            && !(want.purpose == Purpose::Relay && self.no_tx_relay.contains(addr))
            && want.allows(addr)
            && !(self.ipv6_dead() && addr.is_ipv6())
    }

    /// Worth connecting to now?
    fn usable(&self, addr: &PeerAddr, want: Want<'_>, now: Instant) -> bool {
        self.eligible(addr, want)
            && self.meta[addr]
                .resting_until
                .is_none_or(|until| until <= now)
    }

    fn pick(&self, want: Want<'_>) -> Option<PeerAddr> {
        let now = Instant::now();
        let purpose = want.purpose;
        let preferred = self.preferred.as_ref();
        if purpose != Purpose::Relay
            && let Some(addr) = preferred
            && self.usable(addr, want, now)
        {
            return Some(addr.clone());
        }
        // Blocks and relay go to different peers when there is a choice.
        let wanted = |addr: &PeerAddr| {
            self.usable(addr, want, now) && (purpose != Purpose::Relay || Some(addr) != preferred)
        };
        for _ in 0..MAX_DRAWS {
            let record = if random_u64() & 1 == 0 {
                self.tried.select().or_else(|| self.new.select())
            } else {
                self.new.select().or_else(|| self.tried.select())
            };
            let Some(record) = record else {
                break;
            };
            if let Some(addr) = peer_addr(&record)
                && wanted(&addr)
            {
                return Some(addr);
            }
        }
        // The draws are random: settle for any usable known peer rather than
        // calling the book used up.
        let usable: Vec<&PeerAddr> = self.meta.keys().filter(|addr| wanted(addr)).collect();
        if !usable.is_empty() {
            return Some(usable[(random_u64() % usable.len() as u64) as usize].clone());
        }
        // Relay: the block peer is the only one left.
        match preferred {
            Some(addr) if purpose == Purpose::Relay && self.usable(addr, want, now) => {
                Some(addr.clone())
            }
            _ => None,
        }
    }

    /// The resting peer whose rest ends first.
    fn resting(&self, want: Want<'_>) -> Option<PeerAddr> {
        self.meta
            .iter()
            .filter(|(addr, _)| self.eligible(addr, want))
            .min_by_key(|(_, meta)| meta.resting_until)
            .map(|(addr, _)| addr.clone())
    }

    /// Add a new address to the "new" table. A colliding record that keeps
    /// failing gives way; otherwise the new one is dropped.
    fn add(&mut self, addr: PeerAddr, record: Record) -> bool {
        match self.meta.get(&addr) {
            // Forgotten after failing, long enough ago: may come back.
            Some(meta)
                if meta.table.is_none()
                    && !meta.ignored
                    && meta
                        .resting_until
                        .is_none_or(|until| until <= Instant::now()) =>
            {
                self.meta.remove(&addr);
            }
            Some(_) => return false,
            None => {}
        }
        if let Some(conflict) = self.new.add(&record) {
            if !conflict.is_terrible(TERRIBLE_TRIES, TERRIBLE_WEEKLY_TRIES) {
                return false;
            }
            self.new.remove(&conflict);
            if let Some(old) = peer_addr(&conflict) {
                self.meta.remove(&old);
            }
            if self.new.add(&record).is_some() {
                return false;
            }
        }
        self.meta.insert(
            addr,
            Meta {
                record,
                table: Some(Where::New),
                resting_until: None,
                failures: 0,
                ignored: false,
            },
        );
        self.changed = true;
        true
    }

    /// Put a record from a saved address book back in its table. A slot
    /// taken already (by an address seen in both files) drops it.
    fn add_saved(&mut self, record: Record, place: Where) -> bool {
        let Some(addr) = peer_addr(&record) else {
            return false;
        };
        if self.meta.contains_key(&addr) {
            return false;
        }
        let conflict = match place {
            Where::New => self.new.add(&record),
            Where::Tried => self.tried.add(&record),
        };
        if conflict.is_some() {
            return false;
        }
        self.meta.insert(
            addr,
            Meta {
                record,
                table: Some(place),
                resting_until: None,
                failures: 0,
                ignored: false,
            },
        );
        true
    }

    /// A handshake completed: the peer's run of failures ends and its
    /// services are what it just said. A full node moves to "tried"
    /// (Kyoto's `tried`), sending a colliding tried peer back to "new" when
    /// it has room there. Header and fee connections take any peer, but the
    /// book is for block downloads, so another peer stays where it is.
    fn connected(&mut self, addr: &PeerAddr, services: ServiceFlags) {
        let Some(meta) = self.meta.get_mut(addr) else {
            return;
        };
        self.changed = true;
        meta.failures = 0;
        meta.record.update_service_flags(services);
        count(&mut meta.record, true);
        let (record, table) = (meta.record.clone(), meta.table);
        match table {
            Some(Where::Tried) => {
                self.tried.successful_connection(&record);
                return;
            }
            Some(Where::New) if !services.has(required_services()) => {
                self.new.successful_connection(&record);
                return;
            }
            Some(Where::New) => self.new.remove(&record),
            None => return,
        }
        if let Some(meta) = self.meta.get_mut(addr) {
            meta.table = Some(Where::Tried);
        }
        if let Some(conflict) = self.tried.add(&record) {
            self.tried.remove(&conflict);
            self.tried.add(&record);
            if let Some(old) = peer_addr(&conflict) {
                if self.new.add(&conflict).is_none() {
                    if let Some(meta) = self.meta.get_mut(&old) {
                        meta.table = Some(Where::New);
                    }
                } else {
                    self.meta.remove(&old);
                }
            }
        }
        self.tried.successful_connection(&record);
    }

    fn failed(&mut self, addr: &PeerAddr, now: Instant) {
        let Some(meta) = self.meta.get_mut(addr).filter(|meta| meta.table.is_some()) else {
            return;
        };
        meta.failures = meta.failures.saturating_add(1);
        meta.resting_until = Some(now + UNREACHABLE_REST);
        count(&mut meta.record, false);
        let (record, table, failures) = (meta.record.clone(), meta.table, meta.failures);
        match table {
            Some(Where::New) => self.new.failed_connection(&record),
            Some(Where::Tried) => self.tried.failed_connection(&record),
            None => return,
        }
        self.changed = true;
        if failures >= MAX_UNREACHABLE {
            // Out of the tables; the entry stays so the seeds and gossip
            // cannot add it back right away.
            self.remove_from_table(addr);
            if let Some(meta) = self.meta.get_mut(addr) {
                meta.table = None;
                meta.resting_until = Some(now + FORGET_FOR);
            }
        }
    }

    fn rest(&mut self, addr: &PeerAddr, until: Instant) {
        if let Some(meta) = self.meta.get_mut(addr) {
            meta.resting_until = Some(until);
        }
    }

    fn ignore(&mut self, addr: &PeerAddr) {
        self.remove_from_table(addr);
        match self.meta.get_mut(addr) {
            Some(meta) => {
                meta.table = None;
                meta.ignored = true;
            }
            // Not in the book (a slot collision kept it out): remember it
            // anyway, so gossip cannot bring it back.
            None => {
                if let Some(ip) = addr.ip() {
                    let record = Record::new(
                        addrv2(ip),
                        addr.port,
                        ServiceFlags::NONE,
                        &seed_source("ignored"),
                    );
                    self.meta.insert(
                        addr.clone(),
                        Meta {
                            record,
                            table: None,
                            resting_until: None,
                            failures: 0,
                            ignored: true,
                        },
                    );
                }
            }
        }
        tracing::warn!(peer = %addr, "ignoring this peer for the rest of the session");
    }

    fn remove_from_table(&mut self, addr: &PeerAddr) {
        let Some(meta) = self.meta.get(addr) else {
            return;
        };
        match meta.table {
            Some(Where::New) => self.new.remove(&meta.record),
            Some(Where::Tried) => self.tried.remove(&meta.record),
            None => return,
        }
        self.changed = true;
    }
}

/// The first bytes of a `bitcoin-address-book` file (`io::FileExt`).
const BOOK_MAGIC: [u8; 4] = *b"ADBK";

/// The records of an address book file written with `io::FileExt`. The
/// crate's `Table` cannot list its records, and the pool needs each one to
/// index it, so the file is read record by record here. A file listing
/// more than `max` records was not written for a table of this size and is
/// refused before any is read.
fn read_book(path: &Path, max: u64) -> io::Result<Vec<Record>> {
    let mut file = BufReader::new(File::open(path)?);
    let mut magic = [0u8; 4];
    file.read_exact(&mut magic)?;
    if magic != BOOK_MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "not a peer address book",
        ));
    }
    let mut count = [0u8; 8];
    file.read_exact(&mut count)?;
    let count = u64::from_le_bytes(count);
    if count > max {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("it lists {count} addresses, more than the {max} it can hold"),
        ));
    }
    let mut records = Vec::new();
    for _ in 0..count {
        records.push(Record::deserialize(&mut file)?);
    }
    let mut rest = [0u8; 1];
    if file.read(&mut rest)? != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "data after the last record",
        ));
    }
    Ok(records)
}

/// When each record of a saved table was last tried and last connected to
/// (Unix seconds), by address.
#[cfg(test)]
pub(crate) fn saved_times(path: &Path) -> HashMap<PeerAddr, (Option<u64>, Option<u64>)> {
    let time = |field: &[u8]| {
        (field[0] == 1).then(|| u64::from_le_bytes(field[1..9].try_into().expect("8 bytes")))
    };
    read_book(path, u64::MAX)
        .expect("a readable book")
        .into_iter()
        .filter_map(|record| {
            let addr = peer_addr(&record)?;
            // A serialized record ends with its two times, 9 bytes each.
            let bytes = record.serialize();
            let end = bytes.len();
            Some((
                addr,
                (time(&bytes[end - 18..end - 9]), time(&bytes[end - 9..])),
            ))
        })
        .collect()
}

/// Write `path` through a temporary file, so a crash leaves the old file.
fn write_book(path: &Path, write: impl FnOnce(&mut File) -> io::Result<()>) -> io::Result<()> {
    if let Some(dir) = path.parent()
        && !dir.as_os_str().is_empty()
    {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("book.tmp");
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    // The peers this computer talks to: owner only, like the wallet state.
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let mut file = options.open(&tmp)?;
    write(&mut file)?;
    drop(file);
    std::fs::rename(&tmp, path)
}

/// The address a table record names.
fn peer_addr(record: &Record) -> Option<PeerAddr> {
    let (addr, port) = record.network_addr();
    let ip = match addr {
        AddrV2::Ipv4(ip) => IpAddr::V4(ip),
        AddrV2::Ipv6(ip) => IpAddr::V6(ip),
        _ => return None,
    };
    Some(PeerAddr {
        host: PeerHost::Ip(ip),
        port,
    })
}

fn addrv2(ip: IpAddr) -> AddrV2 {
    match ip {
        IpAddr::V4(ip) => AddrV2::Ipv4(ip),
        IpAddr::V6(ip) => AddrV2::Ipv6(ip),
    }
}

/// The source the address book files a seed's addresses under, as Bitcoin
/// Core does: one per seed, so a single seed fills only part of a table.
fn seed_source(seed: &str) -> IpAddr {
    let mut hasher = DefaultHasher::new();
    seed.hash(&mut hasher);
    IpAddr::V4(Ipv4Addr::from(hasher.finish() as u32))
}

/// Reachable over the internet: not this computer, not a private or shared
/// network, not a documentation range.
pub(crate) fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let [a, b, ..] = ip.octets();
            !(ip.is_loopback()
                || ip.is_private()
                || ip.is_link_local()
                || ip.is_unspecified()
                || ip.is_broadcast()
                || ip.is_documentation()
                || ip.is_multicast()
                // 100.64.0.0/10, carrier-grade NAT.
                || (a == 100 && (b & 0xc0) == 64)
                // 192.0.0.0/24 (protocol assignments), 198.18.0.0/15
                // (benchmarking), 240.0.0.0/4 (reserved).
                || (a == 192 && b == 0 && ip.octets()[2] == 0)
                || (a == 198 && (b & 0xfe) == 18)
                || a >= 240
                || a == 0)
        }
        IpAddr::V6(ip) => match ip.to_ipv4_mapped() {
            Some(v4) => is_public(IpAddr::V4(v4)),
            None => {
                !(ip.is_loopback()
                    || ip.is_unspecified()
                    || ip.is_multicast()
                    || ip.is_unique_local()
                    || ip.is_unicast_link_local()
                    // 2001:db8::/32, documentation.
                    || ip.segments()[..2] == [0x2001, 0xdb8])
            }
        },
    }
}

/// A port a gossiped peer may be dialled on: the network's own, or one
/// above the well-known range, so gossip cannot point friglet at other
/// services (ssh, mail, web).
fn plausible_port(port: u16, network: Network) -> bool {
    port == default_port(network) || port >= 1024
}

/// The network's default P2P port (Bitcoin Core's `-port` default).
pub(crate) fn default_port(network: Network) -> u16 {
    match network {
        Network::Bitcoin => 8333,
        Network::Testnet => 18333,
        Network::Testnet4 => 48333,
        Network::Signet => 38333,
        Network::Regtest => 18444,
    }
}
