//! Block downloads through a SOCKS5 proxy (`p2p_proxy`): the own node's
//! name goes to the proxy unresolved, and when the proxy fails nothing is
//! tried directly and the message names the proxy.

use std::net::SocketAddr;

use bitcoin::Network;

use super::p2p::{BlockFetchError, BlockFetcher, FetchFailure};
use super::p2p_tests::{Conn, Node, fast};
use super::test_support::run;
use crate::net::testing::FakeSocks5;
use crate::net::{Dialer, PeerAddr, PeerHost, PeerSource, Seeds};

fn genesis() -> bitcoin::Block {
    bitcoin::constants::genesis_block(Network::Regtest)
}

fn fetch(peers: std::sync::Arc<PeerSource>) -> Result<bitcoin::Block, Box<BlockFetchError>> {
    run(BlockFetcher::new(peers)
        .with_policy(fast(3))
        .fetch(genesis().block_hash(), 0))
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
/// connections race, so a live peer serves the block at once anyway.
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
    // The losing connects stay under way until the proxy timeout; a plain
    // runtime drop would wait for them.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let started = std::time::Instant::now();
    let block = runtime.block_on(BlockFetcher::new(source).fetch(genesis().block_hash(), 0));
    let waited = started.elapsed();
    runtime.shutdown_background();
    let block = block.expect("the live peer serves it");
    assert_eq!(block.block_hash(), genesis().block_hash());
    assert!(
        waited < std::time::Duration::from_secs(10),
        "waited {waited:?} (a dead peer costs 20 s)"
    );
    assert_eq!(node.connections(), 1);
}

/// A refusal through the proxy counts against the peer (forgotten after
/// three); a general failure, what Tor without a working circuit answers,
/// only rests it, so an outage cannot empty the address book.
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
