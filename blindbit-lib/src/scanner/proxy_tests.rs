//! Block downloads through a SOCKS5 proxy (`p2p_proxy`): the own node's
//! name goes to the proxy unresolved, and when the proxy fails nothing is
//! tried directly and the message names the proxy.

use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use bitcoin::Network;
use bitcoin::p2p::ServiceFlags;

use super::p2p::{BlockFetchError, BlockFetcher, FetchFailure, RetryPolicy, connect_failure};
use super::p2p_tests::{Conn, Node, assert_version_gives_nothing_away, fast, recording_node};
use super::test_support::run;
use crate::net::testing::FakeSocks5;
use crate::net::{Dialer, PeerAddr, PeerEvent, PeerHost, PeerSource, Seeds};

fn genesis() -> bitcoin::Block {
    bitcoin::constants::genesis_block(Network::Regtest)
}

/// A loopback address of its own for a node of this module (the address
/// book tells peers apart by IP; other modules use other ranges).
fn ip(last: u8) -> IpAddr {
    [127, 0, 0, last].into()
}

/// `fetch`, failing the test after a minute rather than hanging it.
async fn within_a_minute<T>(fetch: impl Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(60), fetch)
        .await
        .expect("the fetch ended within a minute")
}

fn fetch(peers: std::sync::Arc<PeerSource>) -> Result<bitcoin::Block, Box<BlockFetchError>> {
    run(within_a_minute(
        BlockFetcher::new(peers)
            .with_policy(fast(3))
            .fetch(genesis().block_hash(), 0),
    ))
}

/// An address nothing listens on: a proxy that is not running. Port 1
/// (tcpmux): unlike a port freed by dropping a listener, no parallel test
/// can take it.
fn proxy_down() -> SocketAddr {
    "127.0.0.1:1".parse().unwrap()
}

fn node_invalid(port: u16) -> PeerAddr {
    PeerAddr {
        host: PeerHost::Name("node.invalid".to_string()),
        port,
    }
}

#[test]
fn the_own_node_is_reached_by_name_through_the_proxy() {
    let node = Node::full(200, vec![Conn::Serve]);
    let proxy = FakeSocks5::start();
    // `.invalid` never resolves locally: only the proxy knows it.
    proxy.route("node.invalid", node.addr);
    let peers = PeerSource::own_node(
        node_invalid(node.addr.port()),
        proxy.dialer(),
        Network::Regtest,
    );
    let block = fetch(peers).expect("served through the proxy");
    assert_eq!(block.block_hash(), genesis().block_hash());
    assert_eq!(node.connections(), 1);
    let requests = proxy.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].target, node_invalid(node.addr.port()));
}

/// Through the proxy the handshake gives nothing away either, to the own
/// node and to a discovered peer: placeholder addresses, no height, the
/// shared user agent.
#[test]
fn through_the_proxy_the_handshake_gives_nothing_away() {
    let proxy = FakeSocks5::start();
    let (own, own_node) = recording_node(ip(1));
    proxy.route("node.invalid", own);
    let err = fetch(PeerSource::own_node(
        node_invalid(own.port()),
        proxy.dialer(),
        Network::Regtest,
    ))
    .expect_err("notfound");
    assert_eq!(err.failure, FetchFailure::NotFound);
    let (discovered, discovered_node) = recording_node(ip(84));
    fetch(PeerSource::discover(
        Network::Regtest,
        proxy.dialer(),
        Seeds::Static(vec![discovered.into()]),
    ))
    .expect_err("notfound");
    for node in [own_node, discovered_node] {
        let (version, _) = node.join().unwrap();
        assert_version_gives_nothing_away(&version);
    }
    assert_eq!(proxy.requests().len(), 2, "both through the proxy");
}

/// The proxy is down or refuses: the error names `p2p_proxy`, and the node
/// sees no connection at all, so nothing went around the proxy.
#[test]
fn a_failing_proxy_is_named_and_never_bypassed() {
    let node = Node::full(200, vec![Conn::Serve; 10]);
    let refusing = FakeSocks5::start();
    refusing.refuse_with(0x02);
    for dialer in [
        Dialer::Socks5 {
            proxy: proxy_down(),
        },
        refusing.dialer(),
    ] {
        let own = PeerSource::own_node(node.addr.into(), dialer.clone(), Network::Regtest);
        let err = fetch(own).expect_err("no connection through the proxy");
        let message = err.to_string();
        assert!(message.contains("p2p_proxy"), "{message}");

        let discovered = PeerSource::discover(
            Network::Regtest,
            dialer.clone(),
            Seeds::Static(vec![node.addr.into()]),
        );
        let err = fetch(discovered).expect_err("no connection through the proxy");
        let message = err.to_string();
        assert!(message.contains("p2p_proxy"), "{message}");
        if dialer != refusing.dialer() {
            // The proxy itself is down: one attempt, no peer blamed.
            assert!(matches!(err.failure, FetchFailure::Proxy(_)), "{message}");
            assert!(message.contains("Check that Tor"), "{message}");
        }
    }
    assert_eq!(node.connections(), 0, "never a direct connection");
}

#[test]
fn a_proxy_that_is_down_costs_a_discovered_peer_nothing() {
    let node = Node::full(200, vec![Conn::Serve]);
    let source = PeerSource::discover(
        Network::Regtest,
        Dialer::Socks5 {
            proxy: proxy_down(),
        },
        Seeds::Static(vec![node.addr.into()]),
    );
    let err = fetch(source.clone()).expect_err("proxy down");
    assert_eq!(err.attempts, 0, "{err}");
    let PeerSource::Discovered(pool) = &*source else {
        unreachable!()
    };
    assert!(
        !pool.is_resting(&node.addr.into()),
        "the peer is not blamed"
    );
    assert_eq!(node.connections(), 0);
}

#[test]
fn discovered_peers_are_reached_through_the_proxy() {
    let node = Node::full(200, vec![Conn::Serve]);
    let proxy = FakeSocks5::start();
    let source = PeerSource::discover(
        Network::Regtest,
        proxy.dialer(),
        Seeds::Static(vec![node.addr.into()]),
    );
    fetch(source).expect("served through the proxy");
    assert_eq!(node.connections(), 1);
    let targets: Vec<PeerAddr> = proxy.requests().into_iter().map(|r| r.target).collect();
    assert_eq!(targets, vec![PeerAddr::from(node.addr)]);
}

/// Through Tor a dead address costs the whole connect timeout; the
/// connections race, so a live peer serves the block at once anyway, and
/// the losing connects close with the fetch: the runtime shuts down without
/// waiting for them.
#[test]
fn through_a_proxy_connections_race_past_dead_peers() {
    let node = Node::full(200, vec![Conn::Serve]);
    let proxy = FakeSocks5::start();
    let dead: Vec<PeerAddr> = ["203.0.113.5:18444", "198.51.100.9:18444"]
        .iter()
        .map(|addr| addr.parse::<SocketAddr>().unwrap().into())
        .collect();
    for addr in &dead {
        proxy.stall(addr.clone());
    }
    let mut seeds = dead.clone();
    seeds.push(node.addr.into());
    let source = PeerSource::discover(Network::Regtest, proxy.dialer(), Seeds::Static(seeds));
    let started = Instant::now();
    let block = run(within_a_minute(
        BlockFetcher::new(source).fetch(genesis().block_hash(), 0),
    ));
    let waited = started.elapsed();
    let block = block.expect("the live peer serves it");
    assert_eq!(block.block_hash(), genesis().block_hash());
    assert!(
        waited < Duration::from_secs(10),
        "waited {waited:?} (a dead peer costs 20 s)"
    );
    assert_eq!(node.connections(), 1);
}

/// A racer that opens while another connection downloads completes its
/// handshake at once, so when the download fails it is ready, not a socket
/// left idle that the peer may have dropped meanwhile.
#[test]
fn a_racer_that_opens_during_a_download_is_handshaken_at_once() {
    let block = genesis();
    let full = ServiceFlags::NETWORK | ServiceFlags::WITNESS;
    let stalls = Node::spawn_on(ip(81), full, 200, &block, vec![Conn::StallMidBlock]);
    let serves = Node::spawn_on(ip(82), full, 200, &block, vec![Conn::Serve]);
    let proxy = FakeSocks5::start();
    // The serving peer opens half a second after the stalling one, which is
    // asked for the block first.
    proxy.delay(serves.addr.into(), Duration::from_millis(500));
    let source = PeerSource::discover(
        Network::Regtest,
        proxy.dialer(),
        Seeds::Static(vec![stalls.addr.into(), serves.addr.into()]),
    );
    let fetcher = BlockFetcher::new(source).with_policy(RetryPolicy {
        block_deadline: Duration::from_millis(1_500),
        ..RetryPolicy::discovered()
    });
    let got = run(within_a_minute(fetcher.fetch(block.block_hash(), 0)))
        .expect("the second peer serves it");
    assert_eq!(got.block_hash(), block.block_hash());
    assert!(
        stalls.stalled().is_some(),
        "the stalling peer was asked first"
    );
    let [serving] = serves.accepted()[..] else {
        panic!("one connection to the serving peer");
    };
    let version_after = serving.version_after.expect("it got a version");
    assert!(
        version_after < Duration::from_millis(300),
        "the handshake started {version_after:?} after the connection opened"
    );
}

/// How the proxy's refusals count: no clear answer (a general failure, a
/// timeout) is reported as such, for the peer source to weigh by whether
/// the proxy works; a refusal is the peer's; and the proxy having no route
/// to an IPv6 peer (Tor's exit has none) is not this computer lacking one,
/// which would stop it using IPv6 peers.
#[test]
fn refusals_through_the_proxy_count_for_what_they_say() {
    let proxy = FakeSocks5::start();
    let v4: PeerAddr = "203.0.113.79:18444".parse::<SocketAddr>().unwrap().into();
    let v6: PeerAddr = "[2001:db8::79]:18444".parse::<SocketAddr>().unwrap().into();
    for (code, peer, event) in [
        (0x01, &v4, PeerEvent::ProxyUnclear),
        (0x06, &v4, PeerEvent::ProxyUnclear),
        (0x05, &v4, PeerEvent::Unreachable),
        (0x03, &v6, PeerEvent::Unreachable),
    ] {
        proxy.refuse_with(code);
        let err = proxy
            .dialer()
            .connect(peer, Duration::from_secs(5))
            .unwrap_err();
        assert_eq!(
            connect_failure(err, peer).peer_event(false),
            event,
            "SOCKS5 reply {code} for {peer}"
        );
    }
}

/// A refusal through the proxy counts against the peer (forgotten after
/// three); a general failure, what Tor without a working circuit answers,
/// only rests it while nothing went through the proxy, so an outage cannot
/// empty the address book.
#[test]
fn only_a_clear_refusal_through_the_proxy_counts_against_a_peer() {
    for (code, kept) in [(0x05, 0), (0x01, 1)] {
        let proxy = FakeSocks5::start();
        proxy.refuse_with(code);
        let peer: PeerAddr = "203.0.113.77:18444".parse::<SocketAddr>().unwrap().into();
        let source =
            PeerSource::discover(Network::Regtest, proxy.dialer(), Seeds::Static(vec![peer]));
        for _ in 0..3 {
            fetch(source.clone()).expect_err("refused");
        }
        assert_eq!(source.known(), kept, "SOCKS5 reply {code}");
    }
}
