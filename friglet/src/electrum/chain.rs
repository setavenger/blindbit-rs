//! Chain data the Electrum server needs but does not index itself.
//!
//! Block hashes come from the oracle, the chain the scanner follows. Headers
//! come from a P2P peer by hash (80 bytes per header via `getheaders`) and
//! are checked against that hash, so the peer cannot substitute another
//! block. Peers' `feefilter`s give the current mempool minimum fee rate.
//!
//! Both connections are reused: the oracle client keeps one gRPC channel,
//! and header requests share one P2P connection that is replaced when it
//! fails or has been idle long enough that the peer may have dropped it.
//! With discovered peers a request that fails, or a peer that does not know
//! the header (it may be behind), moves on to another peer.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

use bitcoin::BlockHash;
use bitcoin::block::Header;
use blindbit_lib::net::{PeerAddr, PeerEvent, PeerSource, Purpose};
use blindbit_lib::{BlockHeightRequest, OracleServiceClient};
use tokio::sync::Mutex;
use tonic::transport::Channel;

use super::p2p::{P2pError, Peer, SETTLE_WAIT};
use crate::blockheader;

const ORACLE_TIMEOUT: Duration = Duration::from_secs(15);
const P2P_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const P2P_REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
/// Reuse the header connection only while it is fresh. Bitcoin Core pings
/// every two minutes and this connection only answers when it is used.
const P2P_IDLE_REUSE: Duration = Duration::from_secs(90);
/// A fee filter older than this is refreshed before it is reported.
const FEE_FILTER_MAX_AGE: Duration = Duration::from_secs(10 * 60);
/// Discovered peers asked for one header before giving up.
const HEADER_PEERS: usize = 3;
/// Discovered peers whose fee filters make up the relay fee.
const FEE_FILTER_PEERS: usize = 5;
/// Fresh fee filters from this many discovered peers before their median is
/// reported; with fewer, the lowest (one peer cannot raise the fee).
const FEE_FILTER_QUORUM: usize = 3;
/// Connect timeout for a connection opened only to read a fee filter.
const FEE_SAMPLE_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// The shared header connection and when it was last used.
type HeaderSlot = Arc<StdMutex<Option<(Peer, Instant)>>>;
/// A request on the header connection.
type HeaderRequest<T> = Arc<dyn Fn(&mut Peer) -> Result<T, P2pError> + Send + Sync>;

pub struct ChainSource {
    peers: Arc<PeerSource>,
    oracle_url: String,
    oracle: Mutex<Option<OracleServiceClient<Channel>>>,
    header_peer: HeaderSlot,
    fee_filters: Arc<StdMutex<FeeFilters>>,
    /// One fee-filter sampling round at a time.
    fee_sampling: Mutex<()>,
}

impl ChainSource {
    pub fn new(peers: Arc<PeerSource>, oracle_url: String) -> Self {
        Self {
            peers,
            oracle_url,
            oracle: Mutex::new(None),
            header_peer: Arc::new(StdMutex::new(None)),
            fee_filters: Arc::new(StdMutex::new(FeeFilters::default())),
            fee_sampling: Mutex::new(()),
        }
    }

    pub fn peers(&self) -> &Arc<PeerSource> {
        &self.peers
    }

    /// The hash of the block the oracle serves at `height`.
    pub async fn block_hash(&self, height: u32) -> Result<BlockHash, String> {
        let mut client = {
            let mut cached = self.oracle.lock().await;
            match cached.as_ref() {
                Some(client) => client.clone(),
                None => {
                    let client = tokio::time::timeout(
                        ORACLE_TIMEOUT,
                        OracleServiceClient::connect(self.oracle_url.clone()),
                    )
                    .await
                    .map_err(|_| "oracle connection timed out".to_string())?
                    .map_err(|error| format!("oracle connection failed: {error}"))?;
                    *cached = Some(client.clone());
                    client
                }
            }
        };
        let request = tonic::Request::new(BlockHeightRequest {
            block_height: u64::from(height),
        });
        let response =
            match tokio::time::timeout(ORACLE_TIMEOUT, client.get_block_hash_by_height(request))
                .await
            {
                Ok(Ok(response)) => response.into_inner(),
                Ok(Err(status)) => {
                    return Err(format!(
                        "oracle hash lookup for height {height} failed: {status}"
                    ));
                }
                Err(_) => {
                    // Start over with a fresh channel next time.
                    *self.oracle.lock().await = None;
                    return Err(format!("oracle hash lookup for height {height} timed out"));
                }
            };
        blockheader::block_hash_from_oracle(response.block_hash).map_err(|error| error.to_string())
    }

    /// The header of block `hash`, from a P2P peer, checked against `hash`.
    pub async fn header(&self, hash: BlockHash) -> Result<Header, String> {
        self.with_header_peer(
            Arc::new(move |peer: &mut Peer| {
                peer.header_by_hash(hash, Instant::now() + P2P_REQUEST_TIMEOUT)
            }),
            Option::is_some,
        )
        .await?
        .ok_or_else(|| format!("the P2P peer does not know block {hash}"))
    }

    /// The current mempool minimum fee rate in sat/kvB: the own node's, or
    /// the median of the latest from at least three (up to five) discovered
    /// peers; with fewer answering, the lowest of theirs.
    pub async fn fee_filter(&self) -> Result<u64, String> {
        if self.peers.is_own_node() {
            if let Some(rate) = self.fee_filters().current(1) {
                return Ok(rate);
            }
            // A fresh connection carries a fresh filter: Bitcoin Core sends
            // it right after the handshake.
            self.header_peer.lock().expect("header peer lock").take();
            self.with_header_peer(
                Arc::new(|peer: &mut Peer| {
                    peer.wait_until_settled(Instant::now() + SETTLE_WAIT)?;
                    Ok(())
                }),
                |_| true,
            )
            .await?;
            return self
                .fee_filters()
                .current(1)
                .ok_or_else(|| "the P2P peer did not send a fee filter".to_string());
        }
        if let Some(rate) = self.fee_filters().current(FEE_FILTER_QUORUM) {
            return Ok(rate);
        }
        self.sample_fee_filters().await;
        let filters = self.fee_filters();
        filters
            .current(FEE_FILTER_QUORUM)
            .or_else(|| filters.lowest())
            .ok_or_else(|| "no P2P peer sent a fee filter".to_string())
    }

    /// [`Self::fee_filter`], waiting at most `wait`. Sampling that takes
    /// longer goes on and counts for the next call; meanwhile what is known
    /// ([`Self::known_fee_filter`]).
    pub async fn fee_filter_within(&self, wait: Duration) -> Result<u64, String> {
        match tokio::time::timeout(wait, self.fee_filter()).await {
            Ok(rate) => rate,
            Err(_) => self.known_fee_filter().ok_or_else(|| {
                format!(
                    "no P2P peer sent a fee filter within {} s",
                    wait.as_secs_f32()
                )
            }),
        }
    }

    /// What [`Self::fee_filter`] would report now, without asking a peer.
    pub fn known_fee_filter(&self) -> Option<u64> {
        let filters = self.fee_filters();
        if self.peers.is_own_node() {
            filters.current(1)
        } else {
            filters
                .current(FEE_FILTER_QUORUM)
                .or_else(|| filters.lowest())
        }
    }

    fn fee_filters(&self) -> std::sync::MutexGuard<'_, FeeFilters> {
        self.fee_filters.lock().expect("fee filter lock")
    }

    /// Discovered peers: read the fee filters of enough further peers for a
    /// quorum, on short connections opened at once, until the quorum is
    /// there. Connections still under way then, or when the caller stops
    /// waiting, finish and count for the next call.
    async fn sample_fee_filters(&self) {
        let _one_at_a_time = self.fee_sampling.lock().await;
        let mut asked = self.fee_filters().fresh_peers();
        let needed = FEE_FILTER_QUORUM.saturating_sub(asked.len());
        if needed == 0 {
            return;
        }
        let mut connections = tokio::task::JoinSet::new();
        // One more than needed: some peers do not answer.
        for _ in 0..=needed {
            let Ok(addr) = self.peers.next(Purpose::Relay, &asked).await else {
                break;
            };
            asked.insert(addr.clone());
            let (peers, filters) = (self.peers.clone(), self.fee_filters.clone());
            connections.spawn_blocking(move || {
                match Peer::connect(
                    peers.dialer(),
                    &addr,
                    peers.network(),
                    false,
                    FEE_SAMPLE_CONNECT_TIMEOUT,
                ) {
                    Ok(mut peer) => {
                        peers.report(&addr, PeerEvent::Connected(peer.info()));
                        let _ = peer.wait_until_settled(Instant::now() + SETTLE_WAIT);
                        note_fee_filter(&filters, &addr, peer.fee_filter());
                    }
                    Err(e) if e.proxy_down() => {}
                    Err(e) => peers.report(&addr, e.peer_event()),
                }
            });
        }
        while connections.join_next().await.is_some() {
            if self.fee_filters().current(FEE_FILTER_QUORUM).is_some() {
                connections.detach_all();
                break;
            }
        }
    }

    /// Remember a fee filter `peer` sent on any connection.
    pub fn note_fee_filter(&self, peer: &PeerAddr, rate: Option<u64>) {
        note_fee_filter(&self.fee_filters, peer, rate);
    }

    /// Run `request` on the shared header connection, opening it when
    /// needed. The own node gets a second try on a fresh connection when
    /// the first fails; with discovered peers the peer already connected
    /// goes first, and each try asks another peer, also when the answer is
    /// not `wanted` (a header the peer does not know), and the last answer
    /// is returned if none is.
    async fn with_header_peer<T: Send + 'static>(
        &self,
        request: HeaderRequest<T>,
        wanted: fn(&T) -> bool,
    ) -> Result<T, String> {
        let own_node = self.peers.is_own_node();
        let tries = if own_node { 2 } else { HEADER_PEERS };
        let mut asked = HashSet::new();
        let mut last_error = None;
        let mut last_answer = None;
        // Through a proxy, open the connection by racing several peers.
        let mut raced = if !own_node && self.peers.dialer().proxy().is_some() {
            self.race_header_connection(&mut asked).await?
        } else {
            None
        };
        for _ in 0..tries {
            let next = match raced.take() {
                Some((addr, peer)) => Ok((addr, Some(peer))),
                None => match self.connected_header_peer(&asked).filter(|_| !own_node) {
                    Some(addr) => Ok((addr, None)),
                    None => self
                        .peers
                        .next(Purpose::Header, &asked)
                        .await
                        .map(|addr| (addr, None)),
                },
            };
            let (addr, connected) = match next {
                Ok(next) => next,
                Err(no_peers) => {
                    last_error = Some(format!("no P2P peer to ask: {no_peers}"));
                    break;
                }
            };
            if !own_node {
                asked.insert(addr.clone());
            }
            let (slot, fee_filters, peers) = (
                self.header_peer.clone(),
                self.fee_filters.clone(),
                self.peers.clone(),
            );
            let request = request.clone();
            let answer = tokio::task::spawn_blocking(move || {
                ask_header_peer(&slot, &peers, &addr, connected, &*request, &fee_filters)
                    .map(|value| (value, addr.clone()))
                    .map_err(|error| (error, addr))
            })
            .await
            .map_err(|error| format!("P2P task failed: {error}"))?;
            match answer {
                Ok((value, _)) if own_node || wanted(&value) => return Ok(value),
                Ok((value, _)) => {
                    // It does not know the block: it is behind, or the
                    // block is newer than its tip. Only this request moves
                    // on; blocks may still come from it.
                    last_answer = Some(value);
                }
                Err((error, _)) => {
                    // Every other peer would fail the same way.
                    let proxy_down = error.proxy_down();
                    last_error = Some(error.to_string());
                    if proxy_down {
                        break;
                    }
                }
            }
        }
        match last_answer {
            Some(value) => Ok(value),
            None => Err(last_error.unwrap_or_else(|| "P2P request failed".to_string())),
        }
    }

    /// The peer of the shared connection while it is fresh enough to reuse
    /// and not in `asked`. `None` also while a request is using it.
    fn connected_header_peer(&self, asked: &HashSet<PeerAddr>) -> Option<PeerAddr> {
        let slot = self.header_peer.try_lock().ok()?;
        let (peer, used) = slot.as_ref()?;
        (used.elapsed() <= P2P_IDLE_REUSE && !asked.contains(peer.addr()))
            .then(|| peer.addr().clone())
    }

    /// Through a proxy (Tor) an address nobody answers at keeps a connect
    /// waiting the whole 20 s, so trying header peers one after another
    /// can hold a request (and with it a new-block notification or a
    /// broadcast's answer) for a minute. Unless the shared connection is
    /// still fresh, connect to [`HEADER_PEERS`] peers at once. The first
    /// connection that opens, for the request to use; the others are
    /// reported as their connects end. `Err` when the proxy is down.
    async fn race_header_connection(
        &self,
        asked: &mut HashSet<PeerAddr>,
    ) -> Result<Option<(PeerAddr, Peer)>, String> {
        // Never wait for the lock here (async context): a request holding
        // it is using the shared connection.
        let fresh = match self.header_peer.try_lock() {
            Ok(slot) => slot
                .as_ref()
                .is_some_and(|(_, used)| used.elapsed() <= P2P_IDLE_REUSE),
            Err(_) => true,
        };
        if fresh {
            return Ok(None);
        }
        let mut connecting = tokio::task::JoinSet::new();
        for _ in 0..HEADER_PEERS {
            let Ok(addr) = self.peers.next(Purpose::Header, asked).await else {
                break;
            };
            asked.insert(addr.clone());
            let peers = self.peers.clone();
            connecting.spawn_blocking(move || {
                let connected = Peer::connect(
                    peers.dialer(),
                    &addr,
                    peers.network(),
                    false,
                    P2P_CONNECT_TIMEOUT,
                );
                match &connected {
                    Ok(peer) => peers.report(&addr, PeerEvent::Connected(peer.info())),
                    Err(e) if e.proxy_down() => {}
                    Err(e) => peers.report(&addr, e.peer_event()),
                }
                (addr, connected)
            });
        }
        // Dropping the set on return leaves the losers running: blocking
        // connects end on their own, within the connect timeout.
        while let Some(joined) = connecting.join_next().await {
            match joined {
                Ok((addr, Ok(peer))) => return Ok(Some((addr, peer))),
                // Every other peer would fail the same way.
                Ok((_, Err(error))) if error.proxy_down() => return Err(error.to_string()),
                _ => {}
            }
        }
        Ok(None)
    }
}

/// One header request to `addr` on the shared connection (blocking), which
/// becomes `connected` when given, reporting to `peers` how the connection
/// went.
fn ask_header_peer<T>(
    slot: &StdMutex<Option<(Peer, Instant)>>,
    peers: &PeerSource,
    addr: &PeerAddr,
    connected: Option<Peer>,
    request: &(dyn Fn(&mut Peer) -> Result<T, P2pError> + Send + Sync),
    fee_filters: &StdMutex<FeeFilters>,
) -> Result<T, P2pError> {
    let mut slot = slot.lock().expect("header peer lock");
    if let Some(peer) = connected {
        *slot = Some((peer, Instant::now()));
    }
    if slot
        .as_ref()
        .is_some_and(|(peer, used)| used.elapsed() > P2P_IDLE_REUSE || peer.addr() != addr)
    {
        *slot = None;
    }
    if slot.is_none() {
        let peer = Peer::connect(
            peers.dialer(),
            addr,
            peers.network(),
            false,
            P2P_CONNECT_TIMEOUT,
        )
        .inspect_err(|e| {
            if !e.proxy_down() {
                peers.report(addr, e.peer_event());
            }
        })?;
        peers.report(addr, PeerEvent::Connected(peer.info()));
        *slot = Some((peer, Instant::now()));
    }
    let (peer, used) = slot.as_mut().expect("connected above");
    match request(peer) {
        Ok(value) => {
            *used = Instant::now();
            note_fee_filter(fee_filters, addr, peer.fee_filter());
            Ok(value)
        }
        Err(error) => {
            *slot = None;
            peers.report(addr, PeerEvent::Unhelpful);
            Err(error)
        }
    }
}

fn note_fee_filter(filters: &StdMutex<FeeFilters>, peer: &PeerAddr, rate: Option<u64>) {
    if let Some(rate) = rate {
        tracing::debug!(%peer, sat_per_kvb = rate, "P2P peer's fee filter");
        filters
            .lock()
            .expect("fee filter lock")
            .note(peer, rate, Instant::now());
    }
}

/// The latest fee filter of each recent peer.
#[derive(Default)]
struct FeeFilters(HashMap<PeerAddr, (u64, Instant)>);

impl FeeFilters {
    fn note(&mut self, peer: &PeerAddr, rate: u64, at: Instant) {
        self.0.insert(peer.clone(), (rate, at));
        // Keep the latest few peers.
        while self.0.len() > FEE_FILTER_PEERS {
            let oldest = self
                .0
                .iter()
                .min_by_key(|(_, (_, at))| *at)
                .map(|(peer, _)| peer.clone())
                .expect("not empty");
            self.0.remove(&oldest);
        }
    }

    fn fresh(&self) -> impl Iterator<Item = (&PeerAddr, u64)> {
        self.0
            .iter()
            .filter(|(_, (_, at))| at.elapsed() < FEE_FILTER_MAX_AGE)
            .map(|(peer, (rate, _))| (peer, *rate))
    }

    fn fresh_peers(&self) -> HashSet<PeerAddr> {
        self.fresh().map(|(peer, _)| peer.clone()).collect()
    }

    /// The median of the fresh filters (the lower middle one for an even
    /// count), once at least `quorum` peers sent one: one peer's outlier,
    /// such as a node in initial block download that announces it wants no
    /// transactions at all, does not decide. With one peer (the own node)
    /// and a quorum of one, its filter.
    fn current(&self, quorum: usize) -> Option<u64> {
        let mut rates: Vec<u64> = self.fresh().map(|(_, rate)| rate).collect();
        if rates.len() < quorum.max(1) {
            return None;
        }
        rates.sort_unstable();
        Some(rates[(rates.len() - 1) / 2])
    }

    /// The lowest fresh filter.
    fn lowest(&self) -> Option<u64> {
        self.fresh().map(|(_, rate)| rate).min()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::electrum::fake_peer::{self, FakePeer, Script};
    use bitcoin::Network;
    use bitcoin::hashes::Hash;
    use blindbit_lib::net::{Dialer, Seeds};

    fn own_node(addr: std::net::SocketAddr) -> Arc<PeerSource> {
        PeerSource::own_node(addr.into(), Dialer::Direct, Network::Regtest)
    }

    #[tokio::test]
    async fn headers_come_by_hash_and_are_checked() {
        let known = fake_peer::header(1);
        let script = Script {
            headers: vec![known],
            fee_filter: 100,
            ..Script::default()
        };
        let peer = FakePeer::spawn(script, 1);
        let chain = ChainSource::new(own_node(peer.addr), "http://127.0.0.1:1".into());

        let expected = known;
        assert_eq!(chain.header(expected.block_hash()).await.unwrap(), expected);
        let unknown = chain.header(BlockHash::all_zeros()).await.unwrap_err();
        assert!(unknown.contains("does not know block"), "{unknown}");
        // One connection served both requests and carried the fee filter.
        assert_eq!(chain.fee_filter().await.unwrap(), 100);
        assert_eq!(
            peer.commands()
                .iter()
                .filter(|c| *c == "getheaders")
                .count(),
            2
        );
    }

    /// Through a proxy a header request races its first connection, so
    /// addresses Tor gets no answer from (20 s each) do not hold it up.
    #[cfg(not(target_os = "macos"))]
    #[test]
    fn through_a_proxy_header_peers_race_past_dead_addresses() {
        use blindbit_lib::net::testing::FakeSocks5;

        let known = fake_peer::header(9);
        let live = FakePeer::spawn_on(
            [127, 0, 0, 43].into(),
            Script {
                headers: vec![known],
                ..Script::default()
            },
            2,
        );
        let proxy = FakeSocks5::start();
        let mut seeds: Vec<PeerAddr> = vec![live.addr.into()];
        for n in 0..2u8 {
            let dead: PeerAddr = std::net::SocketAddr::from(([10, 120 + n, 0, 1], 18444)).into();
            proxy.stall(dead.clone());
            seeds.push(dead);
        }
        // The stalled connects outlive the request; a plain runtime drop
        // would wait for them.
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        let (header, waited) = runtime.block_on(async {
            let peers =
                PeerSource::discover(Network::Regtest, proxy.dialer(), Seeds::Static(seeds));
            let chain = ChainSource::new(peers, "http://127.0.0.1:1".into());
            let started = Instant::now();
            let header = chain.header(known.block_hash()).await;
            (header, started.elapsed())
        });
        runtime.shutdown_background();
        assert_eq!(header.unwrap(), known);
        assert!(waited < Duration::from_secs(10), "waited {waited:?}");
    }

    /// Through `p2p_proxy` the Electrum server's own connections go through
    /// the proxy too, the node's name unresolved, each with its own login;
    /// with the proxy down the peer is not blamed.
    #[tokio::test]
    async fn header_connections_go_through_the_proxy() {
        use blindbit_lib::net::testing::FakeSocks5;
        use blindbit_lib::net::{PeerAddr, PeerHost};

        let known = fake_peer::header(3);
        let script = Script {
            headers: vec![known],
            ..Script::default()
        };
        let peer = FakePeer::spawn(script, 2);
        let proxy = FakeSocks5::start();
        proxy.route("node.invalid", peer.addr);
        let node = PeerAddr {
            host: PeerHost::Name("node.invalid".to_string()),
            port: 18444,
        };
        let peers = PeerSource::own_node(node.clone(), proxy.dialer(), Network::Regtest);
        let chain = ChainSource::new(peers, "http://127.0.0.1:1".into());
        assert_eq!(chain.header(known.block_hash()).await.unwrap(), known);
        let requests = proxy.requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].target, node);
        assert!(requests[0].credentials.is_some());

        // Nothing listens on port 1, and no parallel test can take it.
        let down = "127.0.0.1:1".parse().unwrap();
        let peers = PeerSource::discover(
            Network::Regtest,
            Dialer::Socks5 { proxy: down },
            Seeds::Static(vec![peer.addr.into()]),
        );
        let chain = ChainSource::new(peers.clone(), "http://127.0.0.1:1".into());
        // Three failures would forget a peer that was blamed for them.
        for _ in 0..3 {
            let err = chain.header(known.block_hash()).await.unwrap_err();
            assert!(err.contains("p2p_proxy"), "{err}");
        }
        assert_eq!(peers.known(), 1, "the peer is not blamed for the proxy");
    }

    /// Through a proxy the race's first connection is used also when the
    /// shared connection is busy as it opens. (It used to be dropped, and
    /// with it here the only peer that answers.)
    #[cfg(not(target_os = "macos"))]
    #[test]
    fn a_raced_connection_is_used_while_the_shared_one_is_busy() {
        use blindbit_lib::net::testing::FakeSocks5;
        use std::net::{TcpListener, TcpStream};

        let known = fake_peer::header(11);
        let live = FakePeer::spawn_on(
            [127, 0, 0, 73].into(),
            Script {
                headers: vec![known],
                ..Script::default()
            },
            1,
        );
        // In front of it a gate that holds the connection until opened.
        let gate = TcpListener::bind("127.0.0.74:0").unwrap();
        let gate_addr = gate.local_addr().unwrap();
        let (arrived, arrival) = std::sync::mpsc::channel();
        let (open, opened) = std::sync::mpsc::channel::<()>();
        let live_addr = live.addr;
        std::thread::spawn(move || {
            let (client, _) = gate.accept().unwrap();
            let _ = arrived.send(());
            let _ = opened.recv();
            let upstream = TcpStream::connect(live_addr).unwrap();
            let (mut up_read, mut client_write) =
                (upstream.try_clone().unwrap(), client.try_clone().unwrap());
            std::thread::spawn(move || std::io::copy(&mut up_read, &mut client_write));
            let (mut client_read, mut up_write) = (client, upstream);
            let _ = std::io::copy(&mut client_read, &mut up_write);
        });
        let proxy = FakeSocks5::start();
        let mut seeds: Vec<PeerAddr> = vec![gate_addr.into()];
        for n in 0..2u8 {
            let dead: PeerAddr = std::net::SocketAddr::from(([10, 130 + n, 0, 1], 18444)).into();
            proxy.stall(dead.clone());
            seeds.push(dead);
        }
        // The stalled connects outlive the request.
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        let peers = PeerSource::discover(Network::Regtest, proxy.dialer(), Seeds::Static(seeds));
        let chain = Arc::new(ChainSource::new(peers, "http://127.0.0.1:1".into()));
        let request = runtime.spawn({
            let chain = chain.clone();
            async move { chain.header(known.block_hash()).await }
        });
        arrival
            .recv_timeout(Duration::from_secs(10))
            .expect("the race connects through the gate");
        let busy = chain.header_peer.lock().unwrap();
        open.send(()).unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        while live.conns().is_empty() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        // The handshake ends while the shared connection is still busy.
        std::thread::sleep(Duration::from_millis(300));
        drop(busy);
        let header = runtime.block_on(async {
            tokio::time::timeout(Duration::from_secs(10), request)
                .await
                .expect("the request ends")
                .unwrap()
        });
        runtime.shutdown_background();
        assert_eq!(header.unwrap(), known);
    }

    /// A peer that does not know a header (it may be behind, or the block
    /// newer than its tip) is passed over for that request only: blocks
    /// still come from it first.
    #[cfg(not(target_os = "macos"))]
    #[tokio::test]
    async fn a_header_a_peer_does_not_know_keeps_it_for_blocks() {
        let known = fake_peer::header(12);
        let lacks = FakePeer::spawn_on([127, 0, 0, 75].into(), Script::default(), 1);
        let knows = FakePeer::spawn_on(
            [127, 0, 0, 76].into(),
            Script {
                headers: vec![known],
                ..Script::default()
            },
            1,
        );
        let (lacks_addr, knows_addr): (PeerAddr, PeerAddr) = (lacks.addr.into(), knows.addr.into());
        let peers = PeerSource::discover(
            Network::Regtest,
            Dialer::Direct,
            Seeds::Static(vec![lacks_addr.clone(), knows_addr]),
        );
        peers.next(Purpose::Block, &HashSet::new()).await.unwrap();
        // The last block came from the peer that lacks the header.
        peers.report(&lacks_addr, PeerEvent::Served);
        let chain = ChainSource::new(peers.clone(), "http://127.0.0.1:1".into());
        assert_eq!(chain.header(known.block_hash()).await.unwrap(), known);
        let asked = |peer: &FakePeer| {
            peer.commands()
                .iter()
                .filter(|c| *c == "getheaders")
                .count()
        };
        assert_eq!((asked(&lacks), asked(&knows)), (1, 1));
        assert_eq!(
            peers.next(Purpose::Block, &HashSet::new()).await.unwrap(),
            lacks_addr
        );
    }

    /// A header request goes to the peer already connected while that
    /// connection is fresh, not to a new connection to the peer the pool
    /// would pick.
    #[cfg(not(target_os = "macos"))]
    #[tokio::test]
    async fn header_requests_reuse_the_open_connection() {
        let headers = [fake_peer::header(13), fake_peer::header(14)];
        let script = Script {
            headers: headers.to_vec(),
            ..Script::default()
        };
        let first = FakePeer::spawn_on([127, 0, 0, 77].into(), script.clone(), 1);
        let other = FakePeer::spawn_on([127, 0, 0, 78].into(), script, 1);
        let (first_addr, other_addr): (PeerAddr, PeerAddr) = (first.addr.into(), other.addr.into());
        let peers = PeerSource::discover(
            Network::Regtest,
            Dialer::Direct,
            Seeds::Static(vec![first_addr.clone(), other_addr.clone()]),
        );
        peers.next(Purpose::Block, &HashSet::new()).await.unwrap();
        peers.report(&first_addr, PeerEvent::Served);
        let chain = ChainSource::new(peers.clone(), "http://127.0.0.1:1".into());
        assert_eq!(
            chain.header(headers[0].block_hash()).await.unwrap(),
            headers[0]
        );
        // Blocks now come from the other peer, which the pool picks first.
        peers.report(&other_addr, PeerEvent::Served);
        assert_eq!(
            chain.header(headers[1].block_hash()).await.unwrap(),
            headers[1]
        );
        assert_eq!(first.conns().len(), 1);
        let getheaders = first
            .commands()
            .iter()
            .filter(|c| *c == "getheaders")
            .count();
        assert_eq!(getheaders, 2);
        assert!(other.conns().is_empty(), "a second connection was opened");
    }

    #[tokio::test]
    async fn an_unreachable_oracle_is_an_error() {
        let chain = ChainSource::new(
            own_node("127.0.0.1:1".parse().unwrap()),
            "http://127.0.0.1:1".into(),
        );
        assert!(chain.block_hash(5).await.is_err());
    }

    /// With discovered peers, a peer that does not know the header (behind)
    /// or cannot be reached is passed over for one that does.
    #[cfg(not(target_os = "macos"))]
    #[tokio::test]
    async fn a_discovered_peer_that_lacks_the_header_is_passed_over() {
        let known = fake_peer::header(7);
        let behind = FakePeer::spawn_on([127, 0, 0, 41].into(), Script::default(), 2);
        let knows = FakePeer::spawn_on(
            [127, 0, 0, 42].into(),
            Script {
                headers: vec![known],
                ..Script::default()
            },
            2,
        );
        let peers = PeerSource::discover(
            Network::Regtest,
            Dialer::Direct,
            Seeds::Static(vec![behind.addr.into(), knows.addr.into()]),
        );
        let chain = ChainSource::new(peers, "http://127.0.0.1:1".into());
        assert_eq!(chain.header(known.block_hash()).await.unwrap(), known);
        // Either asked first; the one that knows it answered.
        assert_eq!(
            knows
                .commands()
                .iter()
                .filter(|c| *c == "getheaders")
                .count(),
            1
        );
        let unknown = chain.header(BlockHash::all_zeros()).await.unwrap_err();
        assert!(unknown.contains("does not know block"), "{unknown}");
    }

    #[test]
    fn the_relay_fee_is_the_median_of_recent_peers() {
        let now = Instant::now();
        let peer =
            |n: u8| -> PeerAddr { std::net::SocketAddr::from(([192, 0, 2, n], 8333)).into() };
        let mut filters = FeeFilters::default();
        assert_eq!(filters.current(1), None);
        filters.note(&peer(1), 1_000, now);
        assert_eq!(filters.current(1), Some(1_000), "the own node: its filter");
        assert_eq!(filters.current(FEE_FILTER_QUORUM), None, "no quorum yet");
        filters.note(&peer(3), 100_000, now);
        assert_eq!(filters.current(FEE_FILTER_QUORUM), None);
        assert_eq!(filters.lowest(), Some(1_000), "below quorum: the lowest");
        filters.note(&peer(2), 2_000, now);
        assert_eq!(
            filters.current(FEE_FILTER_QUORUM),
            Some(2_000),
            "an outlier does not decide"
        );
        // A peer's newer filter replaces its older one.
        filters.note(&peer(3), 1_500, now);
        assert_eq!(filters.current(FEE_FILTER_QUORUM), Some(1_500));
        // Even count: the lower middle.
        filters.note(&peer(4), 900_000, now);
        assert_eq!(filters.current(FEE_FILTER_QUORUM), Some(1_500));
        // At most five peers, the latest; stale filters do not count.
        let stale = now - FEE_FILTER_MAX_AGE - Duration::from_secs(1);
        let mut filters = FeeFilters::default();
        filters.note(&peer(9), 50_000, stale);
        filters.note(&peer(10), 50_000, stale);
        filters.note(&peer(11), 1_000, now);
        assert_eq!(filters.current(1), Some(1_000));
        assert_eq!(filters.fresh_peers(), HashSet::from([peer(11)]));
        for n in 20..30 {
            filters.note(&peer(n), 3_000, now);
        }
        assert_eq!(filters.0.len(), FEE_FILTER_PEERS);
        assert_eq!(filters.current(FEE_FILTER_QUORUM), Some(3_000));
    }

    /// Discovered peers: the relay fee comes from three of them, sampled
    /// at once when fewer have sent one.
    #[cfg(not(target_os = "macos"))]
    #[tokio::test]
    async fn the_relay_fee_samples_a_quorum_of_discovered_peers() {
        let rates = [1_000, 2_000, 100_000];
        let fakes: Vec<FakePeer> = rates
            .iter()
            .enumerate()
            .map(|(i, rate)| {
                FakePeer::spawn_on(
                    [127, 0, 0, 43 + i as u8].into(),
                    Script {
                        fee_filter: *rate,
                        ..Script::default()
                    },
                    2,
                )
            })
            .collect();
        let peers = PeerSource::discover(
            Network::Regtest,
            Dialer::Direct,
            Seeds::Static(fakes.iter().map(|fake| fake.addr.into()).collect()),
        );
        let chain = ChainSource::new(peers, "http://127.0.0.1:1".into());
        assert_eq!(chain.fee_filter().await.unwrap(), 2_000);
    }

    /// A peer that accepts the connection and never answers: its handshake
    /// waits the whole connect timeout.
    fn silent_peer(ip: [u8; 4]) -> std::net::TcpListener {
        std::net::TcpListener::bind((std::net::Ipv4Addr::from(ip), 0)).unwrap()
    }

    /// The relay fee is there as soon as a quorum of peers sent filters;
    /// a further peer that does not answer is not waited for (its 5 s
    /// connect timeout used to hold the answer).
    #[cfg(not(target_os = "macos"))]
    #[test]
    fn the_relay_fee_does_not_wait_past_the_quorum() {
        let fakes: Vec<FakePeer> = [1_000, 2_000, 3_000]
            .into_iter()
            .enumerate()
            .map(|(i, fee_filter)| {
                FakePeer::spawn_on(
                    [127, 0, 0, 51 + i as u8].into(),
                    Script {
                        fee_filter,
                        ..Script::default()
                    },
                    1,
                )
            })
            .collect();
        let silent = silent_peer([127, 0, 0, 54]);
        let mut seeds: Vec<PeerAddr> = fakes.iter().map(|fake| fake.addr.into()).collect();
        seeds.push(silent.local_addr().unwrap().into());
        // The silent peer's connect outlives the answer; a plain runtime
        // drop would wait for it.
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        let (rate, waited) = runtime.block_on(async {
            let peers =
                PeerSource::discover(Network::Regtest, Dialer::Direct, Seeds::Static(seeds));
            let chain = ChainSource::new(peers, "http://127.0.0.1:1".into());
            let started = Instant::now();
            let rate = chain.fee_filter().await;
            (rate, started.elapsed())
        });
        runtime.shutdown_background();
        assert_eq!(rate.unwrap(), 2_000);
        assert!(waited < FEE_SAMPLE_CONNECT_TIMEOUT / 2, "waited {waited:?}");
        // The silent peer was asked too.
        silent.set_nonblocking(true).unwrap();
        let asked = (0..100).any(|_| {
            std::thread::sleep(Duration::from_millis(20));
            silent.accept().is_ok()
        });
        assert!(asked, "the silent peer was not asked");
    }

    /// When sampling takes longer than a relay fee request may wait, the
    /// request gets the filters known by then, not an error.
    #[cfg(not(target_os = "macos"))]
    #[test]
    fn a_relay_fee_that_cannot_wait_gets_the_known_filters() {
        let silent: Vec<_> = (61..64).map(|n| silent_peer([127, 0, 0, n])).collect();
        let seeds = silent
            .iter()
            .map(|peer| peer.local_addr().unwrap().into())
            .collect();
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        let rate = runtime.block_on(async {
            let peers =
                PeerSource::discover(Network::Regtest, Dialer::Direct, Seeds::Static(seeds));
            let chain = ChainSource::new(peers, "http://127.0.0.1:1".into());
            let broadcast_peer: PeerAddr =
                std::net::SocketAddr::from(([192, 0, 2, 1], 8333)).into();
            chain.note_fee_filter(&broadcast_peer, Some(1_500));
            chain.fee_filter_within(Duration::from_millis(300)).await
        });
        runtime.shutdown_background();
        assert_eq!(rate, Ok(1_500));
    }
}
