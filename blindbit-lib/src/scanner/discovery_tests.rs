//! Block downloads from discovered peers: scripted nodes on 127.0.0.x (the
//! address book tells peers apart by IP only, so each node gets its own),
//! asked one after another until one serves the block.
//!
//! Not on macOS, where only 127.0.0.1 is configured on the loopback
//! interface.

use std::sync::Arc;
use std::time::{Duration, Instant};

use bitcoin::p2p::ServiceFlags;
use bitcoin::{Block, BlockHash, Network};
use tokio_util::sync::CancellationToken;

use super::p2p::{BlockFetcher, FetchFailure, FetchedFrom, RetryPolicy};
use super::p2p_tests::{Conn, GOSSIP, Node, OneBlock};
use super::stream_safety_tests::{owned_outputs, payment_block, served_block, unserve};
use super::test_support::{run, scanner};
use crate::net::pool::{PeerPool, Where};
use crate::net::{Dialer, PeerAddr, PeerSource, Seeds};

/// A distinct loopback address per node, across all tests of this module
/// (they run in parallel and must not share a listener IP).
fn ip(last: u8) -> std::net::IpAddr {
    [127, 0, 0, last].into()
}

fn full() -> ServiceFlags {
    ServiceFlags::NETWORK | ServiceFlags::WITNESS
}

/// A full node at height 100,000 on `127.0.0.<last>` serving `block`.
fn node(last: u8, block: &Block, script: Vec<Conn>) -> Node {
    Node::spawn_on(ip(last), full(), 100_000, block, script)
}

/// A block with segwit transactions, so a stripped copy fails its checks.
fn witness_block(seed: u8) -> Block {
    super::witness_tests::taproot_payment_block(seed).0
}

/// A discovering source that starts from `nodes`.
fn discovering(nodes: &[&Node]) -> Arc<PeerSource> {
    PeerSource::discover(
        Network::Regtest,
        Dialer::Direct,
        Seeds::Static(nodes.iter().map(|node| node.addr.into()).collect()),
    )
}

fn pool(source: &PeerSource) -> &PeerPool {
    match source {
        PeerSource::Discovered(pool) => pool,
        PeerSource::OwnNode { .. } => panic!("not a discovering source"),
    }
}

/// Discovered-peer policy with short deadlines.
fn quick() -> RetryPolicy {
    RetryPolicy {
        block_deadline: Duration::from_millis(400),
        connect_timeout: Duration::from_secs(2),
        ..RetryPolicy::discovered()
    }
}

fn genesis() -> Block {
    bitcoin::constants::genesis_block(Network::Regtest)
}

fn fetch(
    source: &Arc<PeerSource>,
    hash: BlockHash,
    height: u64,
) -> Result<Block, Box<super::BlockFetchError>> {
    run(BlockFetcher::new(source.clone())
        .with_policy(quick())
        .fetch(hash, height))
}

#[test]
fn a_stalling_and_a_stripping_peer_are_passed_over_for_one_that_serves() {
    let block = witness_block(0xd1);
    let stall = node(11, &block, vec![Conn::StallMidBlock; 2]);
    let strip = node(12, &block, vec![Conn::ServeStripped; 2]);
    let serve = node(13, &block, vec![Conn::Serve; 3]);
    let source = discovering(&[&stall, &strip, &serve]);

    let got = fetch(&source, block.block_hash(), 100).expect("one peer serves it");
    assert_eq!(got.block_hash(), block.block_hash());
    for (name, node) in [("stall", &stall), ("strip", &strip), ("serve", &serve)] {
        assert!(
            node.connections() <= 1,
            "{name} asked {} times",
            node.connections()
        );
    }
    assert_eq!(serve.connections(), 1);
    let serve_addr: PeerAddr = serve.addr.into();
    assert_eq!(pool(&source).preferred(), Some(serve_addr.clone()));
    assert_eq!(pool(&source).place(&serve_addr), Some(Where::Tried));
    let strip_addr: PeerAddr = strip.addr.into();
    if strip.connections() == 1 {
        assert!(
            pool(&source).is_ignored(&strip_addr),
            "a stripped block gets the peer ignored"
        );
    }

    // The next block: the serving peer first; the stripper never again.
    let strip_before = strip.connections();
    fetch(&source, block.block_hash(), 100).expect("served again");
    assert_eq!(
        serve.connections(),
        2,
        "the peer that served is asked first"
    );
    assert_eq!(strip.connections(), strip_before);
}

#[test]
fn a_stripping_peer_is_ignored_and_never_contacted_again() {
    let block = witness_block(0xd2);
    let strip = node(14, &block, vec![Conn::ServeStripped; 3]);
    let source = discovering(&[&strip]);
    let err = fetch(&source, block.block_hash(), 100).expect_err("only a stripper");
    assert_eq!(err.failure, FetchFailure::WitnessStripped);
    assert!(pool(&source).is_ignored(&strip.addr.into()));
    let message = err.to_string();
    for expected in [
        "cannot get block 100",
        "from the regtest network: asked 1 peer, every peer it knows right now: 1 sent a bad \
         block and is ignored now.",
        "set p2p_node_addr to your own regtest node",
    ] {
        assert!(
            message.contains(expected),
            "missing {expected:?} in: {message}"
        );
    }
    let err = fetch(&source, block.block_hash(), 100).expect_err("nobody left");
    assert!(
        matches!(err.failure, FetchFailure::NoPeers(_)),
        "{:?}",
        err.failure
    );
    assert_eq!(
        strip.connections(),
        1,
        "an ignored peer is never asked again"
    );
}

/// The scan itself, with three peers of which one serves the block.
#[test]
fn a_scan_finds_a_payment_in_a_block_from_the_third_peer() {
    run(async {
        let (mut scanner, _state) = scanner("discovery-scan");
        let payment = payment_block(7301);
        let hash = {
            let mut bytes: [u8; 32] = payment
                .message
                .block_identifier
                .as_ref()
                .unwrap()
                .block_hash
                .clone()
                .try_into()
                .unwrap();
            bytes.reverse();
            <BlockHash as bitcoin::hashes::Hash>::from_byte_array(bytes)
        };
        let block = served_block(&hash).expect("payment_block serves it");
        unserve(&hash);
        let close = node(21, &block, vec![Conn::CloseAfterRequest; 2]);
        let missing = node(22, &block, vec![Conn::NotFound; 2]);
        let serve = node(23, &block, vec![Conn::Serve; 2]);
        scanner.peers = discovering(&[&close, &missing, &serve]);
        scanner.p2p_retry = Some(quick());
        scanner.update_last_scanned_block_height(7300);

        assert!(!scanner.watch_step(7301, OneBlock(payment.message)).await);
        assert_eq!(scanner.get_last_scanned_block_height(), 7301);
        assert_eq!(owned_outputs(&scanner), 1);
        assert_eq!(scanner.scan_health().await.stall, None);
        assert_eq!(serve.connections(), 1);
        assert!(close.connections() <= 1 && missing.connections() <= 1);
    });
}

#[test]
fn a_peer_behind_the_block_is_not_asked_for_it() {
    let block = genesis();
    let behind = Node::spawn_on(ip(31), full(), 50, &block, vec![Conn::Serve; 2]);
    let source = discovering(&[&behind]);
    let err = fetch(&source, block.block_hash(), 100).expect_err("its chain is too short");
    assert_eq!(err.failure, FetchFailure::Behind(50));
    assert!(
        !behind.commands().iter().any(|c| c == "getdata"),
        "{:?}",
        behind.commands()
    );
    assert!(pool(&source).is_resting(&behind.addr.into()));
    assert!(err.to_string().contains("1 was behind"), "{err}");
}

#[test]
fn a_pruned_peer_is_refused_at_the_handshake() {
    let block = genesis();
    let pruned = Node::spawn_on(
        ip(32),
        ServiceFlags::NETWORK_LIMITED | ServiceFlags::WITNESS,
        1_000,
        &block,
        vec![Conn::Serve; 2],
    );
    let source = discovering(&[&pruned]);
    let err = fetch(&source, block.block_hash(), 100).expect_err("pruned");
    assert!(
        matches!(&err.failure, FetchFailure::Handshake(e) if e.contains("missing services")),
        "{:?}",
        err.failure
    );
    assert!(pruned.commands().is_empty(), "{:?}", pruned.commands());
    assert!(pool(&source).is_resting(&pruned.addr.into()));
    assert!(err.to_string().contains("1 was unreachable"), "{err}");
}

#[test]
fn addresses_a_peer_gossips_land_in_the_book() {
    let block = genesis();
    let gossiping = node(33, &block, vec![Conn::ServeWithAddr]);
    let source = discovering(&[&gossiping]);
    assert!(source.wants_addr());
    fetch(&source, block.block_hash(), 100).expect("served");
    assert!(gossiping.commands().iter().any(|c| c == "getaddr"));
    assert_eq!(source.known(), 1 + GOSSIP.len());
    for gossiped in GOSSIP {
        let addr: PeerAddr = gossiped.parse::<std::net::SocketAddr>().unwrap().into();
        assert_eq!(pool(&source).place(&addr), Some(Where::New), "{addr}");
    }
}

#[test]
fn without_peers_the_error_says_so_and_what_to_do() {
    let source = PeerSource::discover(Network::Regtest, Dialer::Direct, Seeds::Static(Vec::new()));
    let err = fetch(&source, genesis().block_hash(), 100).expect_err("no peers");
    assert_eq!(
        err.failure,
        FetchFailure::NoPeers("no peer addresses to start from".to_string())
    );
    assert_eq!(err.attempts, 0);
    assert!(
        matches!(&err.from, FetchedFrom::Network { tried, exhausted: true } if tried.is_empty())
    );
    assert_eq!(
        err.to_string(),
        format!(
            "cannot get block 100 ({}) from the regtest network: no peers to ask (no peer \
             addresses to start from). Check this computer's internet connection, or set \
             p2p_node_addr to your own regtest node.",
            genesis().block_hash()
        )
    );
}

/// A stop while a discovered peer has gone quiet in the middle of the block
/// ends the download at once, as with the own node.
#[test]
fn a_stop_during_a_stalled_discovered_peer_is_immediate() {
    run(async {
        let block = genesis();
        let stall = node(34, &block, vec![Conn::StallMidBlock]);
        let source = discovering(&[&stall]);
        let cancel = CancellationToken::new();
        let fetcher = BlockFetcher::new(source).with_cancel(cancel.clone());
        let stop = async {
            while stall.stalled().is_none() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
            cancel.cancel();
            Instant::now()
        };
        let (fetched, stopped) = tokio::join!(fetcher.fetch(block.block_hash(), 100), stop);
        let took = stopped.elapsed();
        assert!(
            took < Duration::from_secs(1),
            "the fetch took {took:?} to stop"
        );
        let err = fetched.expect_err("stopped");
        assert_eq!(err.failure, FetchFailure::Cancelled);
        assert!(!err.to_string().contains("internet connection"), "{err}");
    });
}

/// With an own node, the seeds are never asked, whatever else happens.
#[test]
fn an_own_node_source_never_asks_the_seeds() {
    run(async {
        let block = genesis();
        let own = node(35, &block, vec![Conn::Serve]);
        let source = PeerSource::new(
            Network::Regtest,
            Dialer::Direct,
            Some(own.addr.into()),
            Seeds::Dns(&["own-node-never-seeds.invalid"]),
        );
        source.start();
        let got = BlockFetcher::new(source.clone())
            .with_policy(quick())
            .fetch(block.block_hash(), 100)
            .await
            .expect("the own node serves it");
        assert_eq!(got.block_hash(), block.block_hash());
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!crate::net::seeds_asked("own-node-never-seeds"));
        assert!(!source.wants_addr());
        assert!(!own.commands().iter().any(|c| c == "getaddr"));
    });
}
