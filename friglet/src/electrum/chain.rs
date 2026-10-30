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
}

impl ChainSource {
    pub fn new(peers: Arc<PeerSource>, oracle_url: String) -> Self {
        Self {
            peers,
            oracle_url,
            oracle: Mutex::new(None),
            header_peer: Arc::new(StdMutex::new(None)),
            fee_filters: Arc::new(StdMutex::new(FeeFilters::default())),
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
    /// the median of the latest from up to five discovered peers.
    pub async fn fee_filter(&self) -> Result<u64, String> {
        if let Some(rate) = self.fee_filters.lock().expect("fee filter lock").current() {
            return Ok(rate);
        }
        // A fresh connection carries a fresh filter: Bitcoin Core sends it
        // right after the handshake.
        self.header_peer.lock().expect("header peer lock").take();
        self.with_header_peer(
            Arc::new(|peer: &mut Peer| {
                peer.wait_until_settled(Instant::now() + SETTLE_WAIT)?;
                Ok(())
            }),
            |_| true,
        )
        .await?;
        self.fee_filters
            .lock()
            .expect("fee filter lock")
            .current()
            .ok_or_else(|| "the P2P peer did not send a fee filter".to_string())
    }

    /// Remember a fee filter `peer` sent on any connection.
    pub fn note_fee_filter(&self, peer: &PeerAddr, rate: Option<u64>) {
        note_fee_filter(&self.fee_filters, peer, rate);
    }

    /// Run `request` on the shared header connection, opening it when
    /// needed. The own node gets a second try on a fresh connection when
    /// the first fails; with discovered peers each try asks another peer,
    /// also when the answer is not `wanted` (a header the peer does not
    /// know), and the last answer is returned if none is.
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
        for _ in 0..tries {
            let addr = match self.peers.next(Purpose::Header, &asked).await {
                Ok(addr) => addr,
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
                ask_header_peer(&slot, &peers, &addr, &*request, &fee_filters)
                    .map(|value| (value, addr.clone()))
                    .map_err(|error| (error, addr))
            })
            .await
            .map_err(|error| format!("P2P task failed: {error}"))?;
            match answer {
                Ok((value, _)) if own_node || wanted(&value) => return Ok(value),
                Ok((value, addr)) => {
                    // It does not know the block: probably behind.
                    self.peers.report(&addr, PeerEvent::Behind);
                    last_answer = Some(value);
                }
                Err((error, _)) => last_error = Some(error.to_string()),
            }
        }
        match last_answer {
            Some(value) => Ok(value),
            None => Err(last_error.unwrap_or_else(|| "P2P request failed".to_string())),
        }
    }
}

/// One header request to `addr` on the shared connection (blocking),
/// reporting to `peers` how the connection went.
fn ask_header_peer<T>(
    slot: &StdMutex<Option<(Peer, Instant)>>,
    peers: &PeerSource,
    addr: &PeerAddr,
    request: &(dyn Fn(&mut Peer) -> Result<T, P2pError> + Send + Sync),
    fee_filters: &StdMutex<FeeFilters>,
) -> Result<T, P2pError> {
    let mut slot = slot.lock().expect("header peer lock");
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
        .inspect_err(|_| peers.report(addr, PeerEvent::Unreachable))?;
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

    /// The median of the fresh filters (the higher middle one for an even
    /// count): one peer's outlier, such as a node in initial block download
    /// that announces it wants no transactions at all, does not decide. With
    /// one peer (the own node), its filter.
    fn current(&self) -> Option<u64> {
        let mut rates: Vec<u64> = self
            .0
            .values()
            .filter(|(_, at)| at.elapsed() < FEE_FILTER_MAX_AGE)
            .map(|(rate, _)| *rate)
            .collect();
        rates.sort_unstable();
        rates.get(rates.len() / 2).copied()
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
        assert_eq!(filters.current(), None);
        filters.note(&peer(1), 1_000, now);
        assert_eq!(filters.current(), Some(1_000), "one peer: its filter");
        filters.note(&peer(2), 2_000, now);
        filters.note(&peer(3), 100_000, now);
        assert_eq!(filters.current(), Some(2_000), "an outlier does not decide");
        // A peer's newer filter replaces its older one.
        filters.note(&peer(3), 1_500, now);
        assert_eq!(filters.current(), Some(1_500));
        // At most five peers, the latest; stale filters do not count.
        let stale = now - FEE_FILTER_MAX_AGE - Duration::from_secs(1);
        let mut filters = FeeFilters::default();
        filters.note(&peer(9), 50_000, stale);
        filters.note(&peer(10), 50_000, stale);
        filters.note(&peer(11), 1_000, now);
        assert_eq!(filters.current(), Some(1_000));
        for n in 20..30 {
            filters.note(&peer(n), 3_000, now);
        }
        assert_eq!(filters.0.len(), FEE_FILTER_PEERS);
        assert_eq!(filters.current(), Some(3_000));
    }
}
