//! The peer pool on its own: which peer it hands out, what it learns from
//! reports and gossip, and when it asks the seeds. No connection is made.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bitcoin::Network;
use bitcoin::p2p::ServiceFlags;
use bitcoin::p2p::address::{AddrV2, AddrV2Message};

use super::pool::{PeerPool, Where};
use super::{Dialer, PeerAddr, PeerEvent, PeerSource, Purpose, Seeds};
use crate::scanner::PeerInfo;

fn run<F: std::future::Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime")
        .block_on(future)
}

fn addr(s: &str) -> PeerAddr {
    s.parse::<SocketAddr>().unwrap().into()
}

fn pool(source: &PeerSource) -> &PeerPool {
    match source {
        PeerSource::Discovered(pool) => pool,
        PeerSource::OwnNode { .. } => panic!("not a discovering source"),
    }
}

/// A discovering regtest source seeded with `addrs`, seeded already.
fn seeded(addrs: &[&str]) -> Arc<PeerSource> {
    let source = PeerSource::discover(
        Network::Regtest,
        Dialer::Direct,
        Seeds::Static(addrs.iter().map(|a| addr(a)).collect()),
    );
    run(source.next(Purpose::Block, &HashSet::new())).ok();
    assert_eq!(
        source.known(),
        addrs.len(),
        "a slot collision dropped a seed: pick other test addresses"
    );
    source
}

fn none() -> HashSet<PeerAddr> {
    HashSet::new()
}

fn info() -> PeerInfo {
    PeerInfo {
        services: ServiceFlags::NETWORK | ServiceFlags::WITNESS,
        height: 1_000,
    }
}

const PEERS: [&str; 3] = [
    "203.0.113.1:18444",
    "198.51.100.7:18444",
    "192.0.2.33:18444",
];

#[test]
fn a_round_never_gets_a_peer_it_already_asked() {
    let source = seeded(&PEERS);
    let mut asked = none();
    for _ in 0..PEERS.len() {
        let peer = run(source.next(Purpose::Block, &asked)).expect("a peer is left");
        assert!(asked.insert(peer), "handed out twice");
    }
    let err = run(source.next(Purpose::Block, &asked)).expect_err("all asked");
    assert!(err.0.contains("all 3 known peers were tried"), "{err}");
}

#[test]
fn a_handshake_moves_a_peer_to_tried_and_a_bad_block_ignores_it_for_good() {
    let source = seeded(&PEERS);
    let (good, bad) = (addr(PEERS[0]), addr(PEERS[1]));
    assert_eq!(pool(&source).place(&good), Some(Where::New));
    source.report(&good, PeerEvent::Connected(info()));
    assert_eq!(pool(&source).place(&good), Some(Where::Tried));
    // Reported again: stays.
    source.report(&good, PeerEvent::Connected(info()));
    assert_eq!(pool(&source).place(&good), Some(Where::Tried));
    assert_eq!(source.known(), 3);

    source.report(&bad, PeerEvent::Connected(info()));
    source.report(&bad, PeerEvent::Misbehaved);
    assert!(pool(&source).is_ignored(&bad));
    assert_eq!(pool(&source).place(&bad), None);
    assert_eq!(source.known(), 2);
    assert_eq!(source.summary(), "random peers: 2 known, 1 ignored");
    for _ in 0..50 {
        let peer = run(source.next(Purpose::Block, &none())).unwrap();
        assert_ne!(peer, bad, "an ignored peer is never handed out");
    }
    // Gossip cannot bring it back.
    let Some(std::net::IpAddr::V4(ip)) = bad.ip() else {
        panic!("IPv4 test peer");
    };
    source.add_gossip(
        &addr("10.0.0.1:18444"),
        [AddrV2Message {
            time: 0,
            services: ServiceFlags::NETWORK | ServiceFlags::WITNESS,
            addr: AddrV2::Ipv4(ip),
            port: bad.port,
        }],
    );
    assert!(pool(&source).is_ignored(&bad));
    assert_eq!(source.known(), 2);
}

#[test]
fn the_peer_that_served_a_block_is_asked_first_but_not_for_relay() {
    let source = seeded(&PEERS);
    let server = addr(PEERS[2]);
    source.report(&server, PeerEvent::Connected(info()));
    source.report(&server, PeerEvent::Served);
    for _ in 0..20 {
        assert_eq!(run(source.next(Purpose::Block, &none())).unwrap(), server);
        assert_ne!(run(source.next(Purpose::Relay, &none())).unwrap(), server);
    }
    // Not when it was asked already this round.
    let asked = HashSet::from([server.clone()]);
    assert_ne!(run(source.next(Purpose::Block, &asked)).unwrap(), server);
    // A failure ends the preference.
    source.report(&server, PeerEvent::Unhelpful);
    assert_eq!(pool(&source).preferred(), None);
}

#[test]
fn failed_peers_rest_and_are_only_handed_out_when_nothing_else_is_left() {
    let source = seeded(&PEERS[..2]);
    let (a, b) = (addr(PEERS[0]), addr(PEERS[1]));
    source.report(&a, PeerEvent::Unreachable);
    assert!(pool(&source).is_resting(&a));
    for _ in 0..20 {
        assert_eq!(run(source.next(Purpose::Block, &none())).unwrap(), b);
    }
    source.report(&b, PeerEvent::Behind);
    // Both resting: the one whose rest ends first (b: 2 min, a: 10 min).
    assert_eq!(run(source.next(Purpose::Block, &none())).unwrap(), b);
    // Unreachable three times in a row: forgotten.
    source.report(&a, PeerEvent::Unreachable);
    source.report(&a, PeerEvent::Unreachable);
    assert_eq!(pool(&source).place(&a), None);
    assert!(!pool(&source).is_ignored(&a));
    assert_eq!(source.known(), 1);
}

#[test]
fn without_an_ipv6_route_ipv6_peers_are_skipped() {
    let v6 = "[2001:db8::1]:18444";
    let source = seeded(&[v6, PEERS[0]]);
    source.report(&addr(v6), PeerEvent::NoRoute);
    for _ in 0..30 {
        assert_eq!(
            run(source.next(Purpose::Block, &none())).unwrap(),
            addr(PEERS[0])
        );
    }
    let asked = HashSet::from([addr(PEERS[0])]);
    let err = run(source.next(Purpose::Block, &asked)).expect_err("only IPv6 left");
    assert!(err.0.contains("no IPv6 route"), "{err}");
    // An IPv6 peer that cannot be reached for another reason is not the
    // whole family.
    let other = seeded(&["[2001:db8::2]:18444", "[2001:db8::3]:18444"]);
    other.report(&addr("[2001:db8::2]:18444"), PeerEvent::Unreachable);
    assert_eq!(
        run(other.next(Purpose::Block, &none())).unwrap(),
        addr("[2001:db8::3]:18444")
    );
}

#[test]
fn the_seeds_are_asked_again_only_after_a_while() {
    let only = addr(PEERS[0]);
    let source = seeded(&[PEERS[0]]);
    let pool = pool(&source);
    let first = pool.seeded_at().expect("seeded");
    for _ in 0..3 {
        source.report(&only, PeerEvent::Unreachable);
    }
    assert_eq!(source.known(), 0);
    let err = run(source.next(Purpose::Block, &none())).expect_err("forgotten, not reseeded");
    assert!(err.0.contains("no peer addresses"), "{err}");
    assert_eq!(
        pool.seeded_at(),
        Some(first),
        "not asked again within 5 min"
    );

    pool.age_last_seed(Duration::from_secs(5 * 60));
    assert_eq!(run(source.next(Purpose::Block, &none())).unwrap(), only);
    assert_ne!(pool.seeded_at(), Some(first), "asked again");
}

#[test]
fn seeds_that_gave_nothing_are_asked_again_sooner() {
    let source = PeerSource::discover(Network::Regtest, Dialer::Direct, Seeds::Static(Vec::new()));
    let err = run(source.next(Purpose::Block, &none())).expect_err("no seeds");
    assert_eq!(err.0, "no peer addresses to start from");
    let pool = pool(&source);
    let first = pool.seeded_at().expect("asked");
    run(source.next(Purpose::Block, &none())).expect_err("no seeds");
    assert_eq!(pool.seeded_at(), Some(first), "not within 30 s");
    pool.age_last_seed(Duration::from_secs(30));
    run(source.next(Purpose::Block, &none())).expect_err("no seeds");
    assert_ne!(pool.seeded_at(), Some(first), "after 30 s");
}

#[test]
fn regtest_has_no_seeds() {
    assert!(matches!(Seeds::for_network(Network::Regtest), Seeds::None));
    assert!(matches!(Seeds::for_network(Network::Signet), Seeds::Dns(names) if !names.is_empty()));
    let source = PeerSource::discover(
        Network::Regtest,
        Dialer::Direct,
        Seeds::for_network(Network::Regtest),
    );
    let err = run(source.next(Purpose::Block, &none())).expect_err("nothing to find");
    assert_eq!(err.0, "no peer addresses to start from");
}

#[test]
fn gossip_keeps_full_nodes_and_public_peers_cannot_name_local_ones() {
    let source = seeded(&PEERS);
    let message = |ip: [u8; 4], services: ServiceFlags| AddrV2Message {
        time: 0,
        services,
        addr: AddrV2::Ipv4(ip.into()),
        port: 8333,
    };
    let full = ServiceFlags::NETWORK | ServiceFlags::WITNESS;
    source.add_gossip(
        &addr("93.184.216.1:8333"),
        [
            message([93, 184, 216, 34], full),
            // Pruned, or without witnesses: useless for blocks.
            message(
                [93, 184, 216, 35],
                ServiceFlags::NETWORK_LIMITED | ServiceFlags::WITNESS,
            ),
            message([93, 184, 216, 36], ServiceFlags::NETWORK),
            // Local addresses from a public peer.
            message([127, 0, 0, 1], full),
            message([192, 168, 1, 10], full),
            AddrV2Message {
                time: 0,
                services: full,
                addr: AddrV2::TorV3([7; 32]),
                port: 8333,
            },
        ],
    );
    assert_eq!(source.known(), 4, "only 93.184.216.34 is added");
    assert_eq!(
        pool(&source).place(&addr("93.184.216.34:8333")),
        Some(Where::New)
    );
    // A local peer may name local peers.
    source.add_gossip(&addr("127.0.0.5:18444"), [message([127, 0, 0, 9], full)]);
    assert_eq!(source.known(), 5);
}

#[test]
fn an_own_node_is_the_only_peer_and_learns_nothing() {
    let node = addr("192.0.2.1:8333");
    let source = PeerSource::new(
        Network::Bitcoin,
        Dialer::Direct,
        Some(node.clone()),
        Seeds::for_network(Network::Bitcoin),
    );
    assert!(source.is_own_node());
    let asked = HashSet::from([node.clone()]);
    assert_eq!(run(source.next(Purpose::Block, &asked)).unwrap(), node);
    assert_eq!(run(source.next(Purpose::Relay, &none())).unwrap(), node);
    source.report(&node, PeerEvent::Misbehaved);
    assert_eq!(run(source.next(Purpose::Header, &none())).unwrap(), node);
    assert!(!source.wants_addr(&node));
    assert_eq!(source.summary(), "your node 192.0.2.1:8333");
}
