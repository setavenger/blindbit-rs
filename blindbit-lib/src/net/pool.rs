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

use std::collections::hash_map::RandomState;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::hash::{BuildHasher, DefaultHasher, Hash, Hasher};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use bitcoin::Network;
use bitcoin::p2p::ServiceFlags;
use bitcoin::p2p::address::{AddrV2, AddrV2Message};
use bitcoin_address_book::{Record, Table};

use super::seeds::Seeds;
use super::{Dialer, PeerAddr, PeerHost, Purpose};
use crate::scanner::PeerInfo;

// Kyoto's table sizes: 16 x 16 new slots, a source reaches 8 of the 16
// buckets; 4 x 16 tried slots, a source reaches 2 of the 4.
type NewTable = Table<16, 16, 8>;
type TriedTable = Table<4, 16, 2>;

/// Random draws from the tables before settling for any usable peer.
const MAX_DRAWS: usize = 64;
/// Block downloads ask for addresses (`getaddr`) while fewer are known.
const WANT_ADDRS_BELOW: usize = 200;
/// At most this many addresses are taken from one gossip message (Bitcoin
/// Core's `MAX_ADDR_TO_SEND`).
const MAX_GOSSIP_PER_MESSAGE: usize = 1_000;
/// A peer that could not be reached rests this long, and is forgotten after
/// [`MAX_UNREACHABLE`] failures in a row.
const UNREACHABLE_REST: Duration = Duration::from_secs(10 * 60);
const MAX_UNREACHABLE: u8 = 3;
/// A peer that connected but did not help (no block, closed, stalled).
const UNHELPFUL_REST: Duration = Duration::from_secs(10 * 60);
/// A peer whose chain is below the block asked for: it may catch up soon.
const BEHIND_REST: Duration = Duration::from_secs(2 * 60);
/// The DNS seeds are asked again at most this often…
const RESEED_EVERY: Duration = Duration::from_secs(5 * 60);
/// …or this often while they have given nothing.
const RESEED_EVERY_WHILE_EMPTY: Duration = Duration::from_secs(30);
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
    /// The handshake completed; what the peer said about itself.
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
    /// Its chain is below the block asked for.
    Behind,
    /// Sent a block that fails its checks, or speaks another network.
    Misbehaved,
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
    /// the first download does not wait for the DNS seeds. Without it the
    /// first [`Self::next`] asks them. Does nothing for an own node.
    pub fn start(self: &Arc<Self>) {
        let Self::Discovered(_) = **self else {
            return;
        };
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let this = self.clone();
        runtime.spawn(async move {
            if let Self::Discovered(pool) = &*this {
                pool.seed().await;
            }
        });
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
        match self {
            Self::OwnNode { addr, .. } => Ok(addr.clone()),
            Self::Discovered(pool) => pool.next(purpose, exclude).await,
        }
    }

    /// How a connection to `peer` went. Nothing for an own node.
    pub fn report(&self, peer: &PeerAddr, event: PeerEvent) {
        if let Self::Discovered(pool) = self {
            pool.report(peer, event);
        }
    }

    /// Addresses `from` gossiped (`addr` / `addrv2`). Nothing for an own
    /// node.
    pub fn add_gossip(&self, from: &PeerAddr, addrs: impl IntoIterator<Item = AddrV2Message>) {
        if let Self::Discovered(pool) = self {
            pool.add_gossip(from, addrs);
        }
    }

    /// Should the next block download ask its peer for addresses? Only
    /// while a discovering source knows few.
    pub fn wants_addr(&self) -> bool {
        match self {
            Self::OwnNode { .. } => false,
            Self::Discovered(pool) => pool.lock().known() < WANT_ADDRS_BELOW,
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
        match self {
            Self::OwnNode { addr, .. } => format!("your node {addr}"),
            Self::Discovered(pool) => pool.summary(),
        }
    }
}

/// The address book of a discovering [`PeerSource`].
pub struct PeerPool {
    network: Network,
    dialer: Dialer,
    seeds: Seeds,
    /// Never held across an `.await`.
    inner: Mutex<Inner>,
    /// One seeding at a time; callers that need peers wait for it.
    seeding: tokio::sync::Mutex<()>,
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
    /// The record as added: its source decides its bucket, so table
    /// operations on it need this one.
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

struct Inner {
    new: Box<NewTable>,
    tried: Box<TriedTable>,
    /// Every address in a table, and the ignored ones.
    meta: HashMap<PeerAddr, Meta>,
    /// The peer that served the last block.
    preferred: Option<PeerAddr>,
    /// An IPv6 connection found no route: IPv6 peers are skipped.
    ipv6_dead: bool,
    /// When the seeds were last asked, and how many new addresses they gave.
    last_seed: Option<(Instant, usize)>,
}

impl PeerPool {
    fn new(network: Network, dialer: Dialer, seeds: Seeds) -> Self {
        Self {
            network,
            dialer,
            seeds,
            inner: Mutex::new(Inner {
                new: Box::default(),
                tried: Box::default(),
                meta: HashMap::new(),
                preferred: None,
                ipv6_dead: false,
                last_seed: None,
            }),
            seeding: tokio::sync::Mutex::new(()),
        }
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        // A panic while holding it leaves nothing half-updated that matters.
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    async fn next(
        &self,
        purpose: Purpose,
        exclude: &HashSet<PeerAddr>,
    ) -> Result<PeerAddr, NoPeers> {
        let mut seeded = false;
        loop {
            if let Some(addr) = self.lock().pick(purpose, exclude) {
                return Ok(addr);
            }
            if !seeded && self.lock().may_seed() {
                self.seed().await;
                seeded = true;
                continue;
            }
            // Only resting peers left: better one of them than none.
            if let Some(addr) = self.lock().resting(exclude) {
                return Ok(addr);
            }
            return Err(NoPeers(self.no_peers_reason(exclude)));
        }
    }

    fn no_peers_reason(&self, exclude: &HashSet<PeerAddr>) -> String {
        let inner = self.lock();
        let known = inner.known();
        if known == 0 {
            return match &self.seeds {
                Seeds::Dns(names) => format!(
                    "no peer addresses: the network's DNS seeds ({}) gave none",
                    names.join(", ")
                ),
                Seeds::Static(_) | Seeds::None => "no peer addresses to start from".to_string(),
            };
        }
        let skipped_v6 = if inner.ipv6_dead {
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
        let found = self.seeds.resolve(port).await;
        let mut inner = self.lock();
        let mut added = 0;
        for seeded in &found {
            let Some(ip) = seeded.addr.ip() else {
                continue;
            };
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
        inner.last_seed = Some((Instant::now(), added));
        let seeds: Vec<&str> = match &self.seeds {
            Seeds::Dns(names) => names.to_vec(),
            Seeds::Static(_) => vec!["static"],
            Seeds::None => Vec::new(),
        };
        tracing::info!(
            seeds = %seeds.join(", "),
            addresses = found.len(),
            added,
            known = inner.known(),
            elapsed_ms = started.elapsed().as_millis() as u64,
            "peer discovery: asked the DNS seeds"
        );
    }

    fn report(&self, peer: &PeerAddr, event: PeerEvent) {
        let mut inner = self.lock();
        let now = Instant::now();
        if !matches!(event, PeerEvent::Served | PeerEvent::Connected(_))
            && inner.preferred.as_ref() == Some(peer)
        {
            inner.preferred = None;
        }
        match event {
            PeerEvent::Connected(info) => inner.promote(peer, info.services),
            PeerEvent::Served => {
                inner.preferred = Some(peer.clone());
                if let Some(meta) = inner.meta.get_mut(peer) {
                    meta.resting_until = None;
                    meta.failures = 0;
                }
            }
            PeerEvent::NoRoute if peer.is_ipv6() => {
                if !inner.ipv6_dead {
                    tracing::info!(
                        %peer,
                        "no IPv6 route from this computer: skipping IPv6 peers from now on"
                    );
                }
                inner.ipv6_dead = true;
            }
            PeerEvent::Unreachable | PeerEvent::NoRoute => inner.failed(peer, now),
            PeerEvent::Unhelpful => inner.rest(peer, now + UNHELPFUL_REST),
            PeerEvent::Behind => inner.rest(peer, now + BEHIND_REST),
            PeerEvent::Misbehaved => inner.ignore(peer),
        }
    }

    fn add_gossip(&self, from: &PeerAddr, addrs: impl IntoIterator<Item = AddrV2Message>) {
        let Some(from_ip) = from.ip() else {
            return;
        };
        // A peer on the public internet cannot point friglet at this
        // computer or its local network; a local one (a test, a LAN node)
        // may name local peers.
        let local_source = !is_public(from_ip);
        let source = addrv2(from_ip);
        let mut inner = self.lock();
        let (mut offered, mut added) = (0, 0);
        for message in addrs.into_iter().take(MAX_GOSSIP_PER_MESSAGE) {
            offered += 1;
            let ip = match message.addr {
                AddrV2::Ipv4(ip) => IpAddr::V4(ip),
                AddrV2::Ipv6(ip) => IpAddr::V6(ip),
                // Tor, I2P and CJDNS peers need a proxy.
                _ => continue,
            };
            if message.port == 0
                || !message.services.has(required_services())
                || ip.is_unspecified()
                || ip.is_multicast()
                || (!local_source && !is_public(ip))
            {
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
            known = inner.known(),
            "peer gossiped addresses"
        );
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
    pub(crate) fn preferred(&self) -> Option<PeerAddr> {
        self.lock().preferred.clone()
    }

    #[cfg(test)]
    pub(crate) fn seeded_at(&self) -> Option<Instant> {
        self.lock().last_seed.map(|(at, _)| at)
    }

    #[cfg(test)]
    pub(crate) fn age_last_seed(&self, by: Duration) {
        let mut inner = self.lock();
        if let Some((at, added)) = inner.last_seed {
            inner.last_seed = Some((at.checked_sub(by).unwrap_or(at), added));
        }
    }
}

impl Inner {
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

    /// Worth connecting to now?
    fn usable(&self, addr: &PeerAddr, exclude: &HashSet<PeerAddr>, now: Instant) -> bool {
        let Some(meta) = self.meta.get(addr) else {
            return false;
        };
        meta.table.is_some()
            && !meta.ignored
            && !exclude.contains(addr)
            && !(self.ipv6_dead && addr.is_ipv6())
            && meta.resting_until.is_none_or(|until| until <= now)
    }

    fn pick(&self, purpose: Purpose, exclude: &HashSet<PeerAddr>) -> Option<PeerAddr> {
        let now = Instant::now();
        let preferred = self.preferred.as_ref();
        if purpose != Purpose::Relay
            && let Some(addr) = preferred
            && self.usable(addr, exclude, now)
        {
            return Some(addr.clone());
        }
        // Blocks and relay go to different peers when there is a choice.
        let wanted = |addr: &PeerAddr| {
            self.usable(addr, exclude, now)
                && (purpose != Purpose::Relay || Some(addr) != preferred)
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
            Some(addr) if purpose == Purpose::Relay && self.usable(addr, exclude, now) => {
                Some(addr.clone())
            }
            _ => None,
        }
    }

    /// The resting peer whose rest ends first.
    fn resting(&self, exclude: &HashSet<PeerAddr>) -> Option<PeerAddr> {
        self.meta
            .iter()
            .filter(|(addr, meta)| {
                meta.table.is_some()
                    && !meta.ignored
                    && !exclude.contains(*addr)
                    && !(self.ipv6_dead && addr.is_ipv6())
            })
            .min_by_key(|(_, meta)| meta.resting_until)
            .map(|(addr, _)| addr.clone())
    }

    /// Add a new address to the "new" table. A colliding record that keeps
    /// failing gives way; otherwise the new one is dropped.
    fn add(&mut self, addr: PeerAddr, record: Record) -> bool {
        if self.meta.contains_key(&addr) {
            return false;
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
        true
    }

    /// A handshake completed: move the peer to "tried" (Kyoto's `tried`),
    /// sending a colliding tried peer back to "new" when it has room there.
    fn promote(&mut self, addr: &PeerAddr, services: ServiceFlags) {
        let Some(meta) = self.meta.get_mut(addr) else {
            return;
        };
        meta.failures = 0;
        meta.record.update_service_flags(services);
        let (record, table) = (meta.record.clone(), meta.table);
        match table {
            Some(Where::Tried) => {
                self.tried.successful_connection(&record);
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
        let Some(meta) = self.meta.get_mut(addr) else {
            return;
        };
        meta.failures = meta.failures.saturating_add(1);
        meta.resting_until = Some(now + UNREACHABLE_REST);
        let (record, table, failures) = (meta.record.clone(), meta.table, meta.failures);
        match table {
            Some(Where::New) => self.new.failed_connection(&record),
            Some(Where::Tried) => self.tried.failed_connection(&record),
            None => return,
        }
        if failures >= MAX_UNREACHABLE {
            self.remove_from_table(addr);
            self.meta.remove(addr);
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
            None => {}
        }
    }
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

fn random_u64() -> u64 {
    RandomState::new().build_hasher().finish()
}
