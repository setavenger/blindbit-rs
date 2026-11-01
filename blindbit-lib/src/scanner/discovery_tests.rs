//! Block downloads from discovered peers: scripted nodes on 127.0.0.x (the
//! address book tells peers apart by IP only, so each node gets its own),
//! asked one after another until one serves the block.
//!
//! Not on macOS, where only 127.0.0.1 is configured on the loopback
//! interface.

use std::collections::HashSet;
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
use crate::net::{Dialer, PeerAddr, PeerEvent, PeerSource, Purpose, Seeds};

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

/// `fetch`, failing the test after a minute rather than hanging it (a
/// fetch that keeps asking the same peer never ends by itself).
async fn within_a_minute<T>(fetch: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(60), fetch)
        .await
        .expect("the fetch ended within a minute")
}

fn fetch(
    source: &Arc<PeerSource>,
    hash: BlockHash,
    height: u64,
) -> Result<Block, Box<super::BlockFetchError>> {
    run(within_a_minute(
        BlockFetcher::new(source.clone())
            .with_policy(quick())
            .fetch(hash, height),
    ))
}

/// Put `nodes` in the source's book and line them up: the pool hands out a
/// peer that is not resting first, then resting ones by when their rest
/// ends, so resting the second node 2 min (behind) and the third 10 min
/// (unhelpful) makes a fetch ask the nodes in the order given.
async fn in_order(source: &PeerSource, nodes: [&Node; 3]) {
    source
        .next(Purpose::Block, &HashSet::new())
        .await
        .expect("seeded");
    assert_eq!(source.known(), 3, "a slot collision: move the addresses");
    source.report(&nodes[1].addr.into(), PeerEvent::Behind);
    source.report(&nodes[2].addr.into(), PeerEvent::Unhelpful);
}

/// Each node was asked once, in the order given.
fn asked_once_in_order(nodes: [(&str, &Node); 3]) {
    let mut last = None;
    for (name, node) in nodes {
        let [connection] = node.accepted()[..] else {
            panic!("{name} asked {} times", node.connections());
        };
        assert!(
            last.is_none_or(|last| last < connection.at),
            "{name} asked out of order"
        );
        last = Some(connection.at);
    }
}

#[test]
fn a_stalling_and_a_stripping_peer_are_passed_over_for_one_that_serves() {
    let block = witness_block(0xd1);
    let stall = node(11, &block, vec![Conn::StallMidBlock; 2]);
    let strip = node(12, &block, vec![Conn::ServeStripped; 2]);
    let serve = node(13, &block, vec![Conn::Serve; 3]);
    let source = discovering(&[&stall, &strip, &serve]);
    run(in_order(&source, [&stall, &strip, &serve]));

    let got = fetch(&source, block.block_hash(), 100).expect("the third peer serves it");
    assert_eq!(got.block_hash(), block.block_hash());
    asked_once_in_order([("stall", &stall), ("strip", &strip), ("serve", &serve)]);
    assert!(
        stall.stalled().is_some(),
        "the first peer stalled mid-block"
    );
    let strip_addr: PeerAddr = strip.addr.into();
    assert!(
        pool(&source).is_ignored(&strip_addr),
        "a stripped block gets the peer ignored"
    );
    let serve_addr: PeerAddr = serve.addr.into();
    assert_eq!(pool(&source).preferred(), Some(serve_addr.clone()));
    assert_eq!(pool(&source).place(&serve_addr), Some(Where::Tried));

    // The next block: the serving peer first; the stripper never again.
    fetch(&source, block.block_hash(), 100).expect("served again");
    assert_eq!(
        serve.connections(),
        2,
        "the peer that served is asked first"
    );
    assert_eq!(strip.connections(), 1);
}

/// A peer that sends a block failing `check` (its words: `says`) is refused
/// and ignored for the rest of the session.
fn a_block_failing_its_check_gets_the_peer_ignored(last: u8, conn: Conn, says: &str) {
    let block = witness_block(0xd0 ^ last);
    let bad = node(last, &block, vec![conn; 2]);
    let source = discovering(&[&bad]);
    let err = fetch(&source, block.block_hash(), 100).expect_err("refused");
    assert!(
        matches!(&err.failure, FetchFailure::BadBlock(why) if why.contains(says)),
        "{:?}",
        err.failure
    );
    assert!(pool(&source).is_ignored(&bad.addr.into()));
    assert!(
        err.to_string()
            .contains("1 sent a bad block and is ignored now"),
        "{err}"
    );
    let err = fetch(&source, block.block_hash(), 100).expect_err("nobody left");
    assert!(
        matches!(err.failure, FetchFailure::NoPeers(_)),
        "{:?}",
        err.failure
    );
    assert_eq!(bad.connections(), 1, "an ignored peer is never asked again");
}

#[test]
fn a_peer_sending_another_block_than_the_oracle_named_is_ignored() {
    a_block_failing_its_check_gets_the_peer_ignored(15, Conn::ServeAnotherBlock, "it is block ");
}

#[test]
fn a_peer_sending_transactions_that_miss_the_merkle_root_is_ignored() {
    a_block_failing_its_check_gets_the_peer_ignored(16, Conn::ServeBadMerkle, "merkle root");
}

#[test]
fn a_peer_sending_witnesses_that_miss_the_commitment_is_ignored() {
    a_block_failing_its_check_gets_the_peer_ignored(
        17,
        Conn::ServeBadWitness,
        "witness commitment",
    );
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
        in_order(&scanner.peers, [&close, &missing, &serve]).await;
        scanner.p2p_retry = Some(quick());
        scanner.update_last_scanned_block_height(7300);

        assert!(!within_a_minute(scanner.watch_step(7301, OneBlock(payment.message))).await);
        assert_eq!(scanner.get_last_scanned_block_height(), 7301);
        assert_eq!(owned_outputs(&scanner), 1);
        assert_eq!(scanner.scan_health().await.stall, None);
        asked_once_in_order([("close", &close), ("missing", &missing), ("serve", &serve)]);
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
    let peer: PeerAddr = gossiping.addr.into();
    assert!(source.wants_addr(&peer));
    fetch(&source, block.block_hash(), 100).expect("served");
    assert!(!source.wants_addr(&peer), "asked once per peer");
    assert!(gossiping.commands().iter().any(|c| c == "getaddr"));
    assert_eq!(source.known(), 1 + GOSSIP.len());
    for gossiped in GOSSIP {
        let addr: PeerAddr = gossiped.parse::<std::net::SocketAddr>().unwrap().into();
        assert_eq!(pool(&source).place(&addr), Some(Where::New), "{addr}");
    }
}

/// Polls `condition` every 20 ms for up to `within`; whether it came true.
async fn comes_true(within: Duration, condition: impl Fn() -> bool) -> bool {
    let deadline = Instant::now() + within;
    while !condition() {
        if Instant::now() > deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    true
}

/// The addresses a peer sends after the block arrive whole even when the
/// message pauses halfway (400 ms, longer than a short poll would wait).
#[test]
fn addresses_that_pause_halfway_after_the_block_still_land_in_the_book() {
    run(async {
        let block = genesis();
        let gossiping = node(36, &block, vec![Conn::ServeThenSplitAddr]);
        let source = discovering(&[&gossiping]);
        BlockFetcher::new(source.clone())
            .with_policy(quick())
            .fetch(block.block_hash(), 100)
            .await
            .expect("served");
        assert!(
            comes_true(Duration::from_secs(5), || source.known()
                == 1 + GOSSIP.len())
            .await,
            "known: {}",
            source.known()
        );
    });
}

/// A peer announcing its own address has not answered `getaddr`: the
/// connection still waits for the answer after the block.
#[test]
fn a_peer_announcing_itself_is_still_waited_for_its_addresses() {
    run(async {
        let block = genesis();
        let gossiping = node(39, &block, vec![Conn::AnnounceThenServeThenAddr]);
        let source = discovering(&[&gossiping]);
        BlockFetcher::new(source.clone())
            .with_policy(quick())
            .fetch(block.block_hash(), 100)
            .await
            .expect("served");
        assert!(
            comes_true(Duration::from_secs(5), || source.known()
                == 1 + GOSSIP.len())
            .await,
            "known: {}",
            source.known()
        );
        assert!(!source.wants_addr(&gossiping.addr.into()), "it answered");
    });
}

/// A peer that trickles a message after the block cannot keep the
/// connection: it closes when the wait for addresses is over (3 s).
#[test]
fn a_peer_that_trickles_after_the_block_is_hung_up_on_in_time() {
    run(async {
        let block = genesis();
        let trickling = node(37, &block, vec![Conn::ServeThenTrickle]);
        let source = discovering(&[&trickling]);
        BlockFetcher::new(source)
            .with_policy(quick())
            .fetch(block.block_hash(), 100)
            .await
            .expect("served");
        let served = Instant::now();
        assert!(
            comes_true(Duration::from_secs(15), || trickling.hung_up().is_some()).await,
            "still connected after 15 s"
        );
        let after = trickling.hung_up().unwrap() - served;
        assert!(
            after < Duration::from_secs(5),
            "hung up {after:?} after the block"
        );
    });
}

/// A stop while such a peer trickles closes the connection at once, not
/// when the wait for addresses ends. That wait is ten minutes here (3 s
/// normally) and the trickle lasts up to a minute, so nothing but the stop
/// closes the connection first, however late the stop comes.
#[test]
fn a_stop_while_a_peer_trickles_after_the_block_closes_the_connection() {
    run(async {
        let block = genesis();
        let trickling = node(38, &block, vec![Conn::ServeThenTrickle]);
        let source = discovering(&[&trickling]);
        let cancel = CancellationToken::new();
        BlockFetcher::new(source)
            .with_policy(quick())
            .with_cancel(cancel.clone())
            .with_linger(Duration::from_secs(600))
            .fetch(block.block_hash(), 100)
            .await
            .expect("served");
        assert!(
            comes_true(Duration::from_secs(15), || trickling.trickling().is_some()).await,
            "the peer never started trickling"
        );
        let stopped = Instant::now();
        cancel.cancel();
        assert!(
            comes_true(Duration::from_secs(15), || trickling.hung_up().is_some()).await,
            "still connected after 15 s"
        );
        let hung_up = trickling.hung_up().unwrap();
        assert!(
            hung_up >= stopped,
            "the connection closed before the stop, so the stop was not what closed it"
        );
        // At once, with room for a loaded machine: the trickle would have
        // kept it open for most of a minute.
        let after = hung_up - stopped;
        assert!(
            after < Duration::from_secs(10),
            "hung up {after:?} after the stop"
        );
    });
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
        assert!(!source.wants_addr(&own.addr.into()));
        assert!(!own.commands().iter().any(|c| c == "getaddr"));
    });
}
