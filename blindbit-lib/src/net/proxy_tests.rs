//! Discovery through a SOCKS5 proxy: the seeds are asked by name through
//! it, never through this computer's resolver.

use std::collections::HashSet;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bitcoin::Network;
use bitcoin::consensus::encode;
use bitcoin::p2p::address::{AddrV2, AddrV2Message};
use bitcoin::p2p::message::{NetworkMessage, RawNetworkMessage};
use bitcoin::p2p::message_network::VersionMessage;
use bitcoin::p2p::{Address, ServiceFlags};

use super::testing::{FakeSocks5, Gate};
use super::{Dialer, PeerAddr, PeerHost, PeerSource, Purpose, Seeds, USER_AGENT, seeds_asked};

fn run<F: std::future::Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime")
        .block_on(future)
}

/// Public addresses a seed's node gossips.
fn gossip() -> Vec<AddrV2Message> {
    gossip_of(1, 5)
}

/// `count` public addresses, `45.<n>.<7n>.<n>:18444` from `n = first` on.
fn gossip_of(first: u8, count: u8) -> Vec<AddrV2Message> {
    (first..first + count)
        .map(|i| AddrV2Message {
            time: 0,
            services: ServiceFlags::NETWORK | ServiceFlags::WITNESS,
            addr: AddrV2::Ipv4(Ipv4Addr::new(45, i, i.wrapping_mul(7), i)),
            port: 18444,
        })
        .collect()
}

/// How a seed's node answers `getaddr`.
#[derive(Clone)]
enum Answer {
    Now,
    /// At once, then opens the gate when friglet hangs up.
    NowThenOpen(Arc<Gate>),
    /// Once the gate opens (or 30 s pass).
    Once(Arc<Gate>),
    /// In a message that pauses for 700 ms halfway through.
    Split,
    /// One byte every 100 ms, for at most 15 s, never complete.
    Trickle,
    /// This many messages of one address each (the answer's first), then
    /// the answer, then the node hangs up.
    SinglesFirst(usize),
}

/// A regtest node on 127.0.0.1 that answers `getaddr` with `addrs`, as
/// `answer` says; and the `version` messages it got.
fn seed_node(
    answer: Answer,
    addrs: Vec<AddrV2Message>,
) -> (SocketAddr, Arc<Mutex<Vec<VersionMessage>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let versions = Arc::new(Mutex::new(Vec::new()));
    let got = versions.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let (answer, addrs, got) = (answer.clone(), addrs.clone(), got.clone());
            std::thread::spawn(move || {
                let _ = serve(stream, &answer, addrs, &got);
            });
        }
    });
    (addr, versions)
}

/// A listener that accepts connections and never says anything.
fn silent_node() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        let mut open = Vec::new();
        for stream in listener.incoming().flatten() {
            open.push(stream);
        }
    });
    addr
}

fn serve(
    mut stream: TcpStream,
    answer: &Answer,
    addrs: Vec<AddrV2Message>,
    versions: &Mutex<Vec<VersionMessage>>,
) -> std::io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    let magic = Network::Regtest.magic();
    let mut buf = Vec::new();
    let bytes = |message| encode::serialize(&RawNetworkMessage::new(magic, message));
    let useless = Address::new(&"127.0.0.1:1".parse().unwrap(), ServiceFlags::NONE);
    loop {
        let message = recv(&mut stream, &mut buf)?;
        match message {
            NetworkMessage::Version(version) => {
                versions.lock().unwrap().push(version);
                stream.write_all(&bytes(NetworkMessage::Version(VersionMessage {
                    version: 70016,
                    services: ServiceFlags::NETWORK | ServiceFlags::WITNESS,
                    timestamp: 0,
                    receiver: useless.clone(),
                    sender: useless.clone(),
                    nonce: 9,
                    user_agent: "/FakeSeedNode:1.0/".to_string(),
                    start_height: 100,
                    relay: true,
                })))?;
                stream.write_all(&bytes(NetworkMessage::Verack))?;
            }
            NetworkMessage::GetAddr => {
                let answer_bytes = bytes(NetworkMessage::AddrV2(addrs.clone()));
                match answer {
                    Answer::Now => stream.write_all(&answer_bytes)?,
                    Answer::NowThenOpen(gate) => {
                        stream.write_all(&answer_bytes)?;
                        while recv(&mut stream, &mut buf).is_ok() {}
                        gate.open();
                        return Ok(());
                    }
                    Answer::Once(gate) => {
                        gate.wait(Duration::from_secs(30));
                        stream.write_all(&answer_bytes)?;
                    }
                    Answer::Split => {
                        let (first, rest) = answer_bytes.split_at(answer_bytes.len() / 2);
                        stream.write_all(first)?;
                        std::thread::sleep(Duration::from_millis(700));
                        stream.write_all(rest)?;
                    }
                    Answer::Trickle => {
                        let started = Instant::now();
                        for byte in &answer_bytes {
                            if started.elapsed() > Duration::from_secs(15) {
                                break;
                            }
                            stream.write_all(&[*byte])?;
                            std::thread::sleep(Duration::from_millis(100));
                        }
                    }
                    Answer::SinglesFirst(count) => {
                        let single = bytes(NetworkMessage::AddrV2(addrs[..1].to_vec()));
                        for _ in 0..*count {
                            stream.write_all(&single)?;
                        }
                        stream.write_all(&answer_bytes)?;
                        return Ok(());
                    }
                }
            }
            _ => {}
        }
    }
}

fn recv(stream: &mut TcpStream, buf: &mut Vec<u8>) -> std::io::Result<NetworkMessage> {
    loop {
        if buf.len() >= 24 {
            let len = u32::from_le_bytes(buf[16..20].try_into().unwrap()) as usize;
            if buf.len() >= 24 + len {
                let raw: RawNetworkMessage = encode::deserialize(&buf[..24 + len])
                    .map_err(|e| std::io::Error::other(e.to_string()))?;
                buf.drain(..24 + len);
                return Ok(raw.into_payload());
            }
        }
        let mut chunk = [0u8; 4096];
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            return Err(std::io::ErrorKind::UnexpectedEof.into());
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

fn name(host: &str) -> PeerAddr {
    PeerAddr {
        host: PeerHost::Name(host.to_string()),
        port: 18444,
    }
}

#[test]
fn through_a_proxy_the_seeds_are_asked_by_name_and_never_looked_up() {
    let proxy = FakeSocks5::start();
    let (seed, versions) = seed_node(Answer::Now, gossip());
    proxy.route("x9.proxied-seed.invalid", seed);
    let source = PeerSource::discover(
        Network::Regtest,
        proxy.dialer(),
        Seeds::Dns(&["proxied-seed.invalid"]),
    );
    let peer = run(source.next(Purpose::Block, &HashSet::new())).expect("seeded");
    assert_eq!(
        source.known(),
        gossip().len(),
        "the seed's node's addresses"
    );
    assert!(
        peer.ip()
            .is_some_and(|ip| ip.to_string().starts_with("45."))
    );
    let targets: Vec<PeerAddr> = proxy.requests().into_iter().map(|r| r.target).collect();
    assert_eq!(targets, vec![name("x9.proxied-seed.invalid")]);
    assert!(
        !seeds_asked("proxied-seed.invalid"),
        "no DNS lookup on this computer"
    );
    assert!(
        source
            .summary()
            .contains(&format!("through p2p_proxy {}", proxy.addr())),
        "{}",
        source.summary()
    );
    // What the seed's node learns about friglet: the shared user agent, no
    // height, no relay, and placeholders for both addresses.
    let [version] = &versions.lock().unwrap()[..] else {
        panic!("one handshake with the seed's node");
    };
    let placeholder = Address::new(&"127.0.0.1:1".parse().unwrap(), ServiceFlags::NONE);
    assert_eq!(version.user_agent, USER_AGENT);
    assert_eq!(version.start_height, 0);
    assert_eq!(version.services, ServiceFlags::NONE);
    assert!(!version.relay);
    assert_eq!(version.sender, placeholder);
    assert_eq!(version.receiver, placeholder);
}

/// The answer of a seed's node arrives whole even when it pauses halfway
/// (700 ms, longer than a short poll would wait).
#[test]
fn a_seed_answer_that_pauses_halfway_still_arrives() {
    let proxy = FakeSocks5::start();
    proxy.route(
        "x9.pausing-seed.invalid",
        seed_node(Answer::Split, gossip()).0,
    );
    let source = PeerSource::discover(
        Network::Regtest,
        proxy.dialer(),
        Seeds::Dns(&["pausing-seed.invalid"]),
    );
    run(source.next(Purpose::Block, &HashSet::new())).expect("seeded");
    assert_eq!(source.known(), gossip().len());
}

/// A seed's node that trickles its answer is hung up on when the wait for
/// it is over.
#[test]
fn a_seed_that_trickles_its_answer_is_hung_up_on_in_time() {
    let proxy = FakeSocks5::start();
    proxy.route(
        "x9.trickling-seed.invalid",
        seed_node(Answer::Trickle, gossip_of(1, 100)).0,
    );
    let started = Instant::now();
    let asked = run(super::seeds::ask_seed_node(
        &proxy.dialer(),
        "trickling-seed.invalid",
        18444,
        Network::Regtest,
        Duration::from_secs(1),
    ));
    let took = started.elapsed();
    assert!(asked.is_err(), "{asked:?}");
    assert!(took < Duration::from_secs(3), "took {took:?}");
}

/// A seed's node that sends one address after another cannot make friglet
/// keep them all: of single addresses only the first is kept, and reading
/// stops after a hundred messages. An answer that comes before then is
/// kept, each address once.
#[test]
fn a_seed_node_sending_single_addresses_gets_one_of_them_kept() {
    let proxy = FakeSocks5::start();
    let mut answer = gossip_of(1, 25);
    answer.push(answer[3].clone());
    proxy.route(
        "x9.flooding-seed.invalid",
        seed_node(Answer::SinglesFirst(5_000), answer.clone()).0,
    );
    proxy.route(
        "x9.announcing-seed.invalid",
        seed_node(Answer::SinglesFirst(3), answer.clone()).0,
    );
    let ask = |seed| {
        run(super::seeds::ask_seed_node(
            &proxy.dialer(),
            seed,
            18444,
            Network::Regtest,
            Duration::from_secs(20),
        ))
    };
    let flooded = ask("flooding-seed.invalid").expect("the first address");
    assert!(
        flooded == answer[..1],
        "{} addresses kept, first {:?}",
        flooded.len(),
        flooded.first()
    );
    let announced = ask("announcing-seed.invalid").expect("the answer");
    assert!(
        announced == answer[..25],
        "{} addresses kept, not each of the 25 once",
        announced.len()
    );
}

/// A seed's node answering with more addresses than a peer may send in one
/// message (1,000) gets the first 1,000 kept.
#[test]
fn of_an_oversized_seed_answer_the_first_thousand_addresses_are_kept() {
    let answer: Vec<AddrV2Message> = (0..1_500u16)
        .map(|i| {
            let [high, low] = i.to_be_bytes();
            AddrV2Message {
                time: 0,
                services: ServiceFlags::NETWORK | ServiceFlags::WITNESS,
                addr: AddrV2::Ipv4(Ipv4Addr::new(46, high, low, 1)),
                port: 18444,
            }
        })
        .collect();
    let proxy = FakeSocks5::start();
    proxy.route(
        "x9.oversized-seed.invalid",
        seed_node(Answer::Now, answer.clone()).0,
    );
    let kept = run(super::seeds::ask_seed_node(
        &proxy.dialer(),
        "oversized-seed.invalid",
        18444,
        Network::Regtest,
        Duration::from_secs(20),
    ))
    .expect("the answer");
    assert_eq!(kept.len(), 1_000);
    assert!(kept == answer[..1_000], "not the answer's first 1,000");
}

/// Seeding through the proxy returns once one seed's node has given enough
/// addresses; a slower seed's answer joins the book later, and one that
/// never answers holds up nothing. The slower seed answers only once
/// seeding has returned.
#[test]
fn proxied_seeding_does_not_wait_for_the_slowest_seed() {
    let proxy = FakeSocks5::start();
    let slow_answers = Gate::new();
    proxy.route(
        "x9.quick-seed.invalid",
        seed_node(Answer::Now, gossip_of(1, 25)).0,
    );
    proxy.route(
        "x9.slow-seed.invalid",
        seed_node(Answer::Once(slow_answers.clone()), gossip_of(101, 5)).0,
    );
    proxy.route("x9.mute-seed.invalid", silent_node());
    let source = PeerSource::discover(
        Network::Regtest,
        proxy.dialer(),
        Seeds::Dns(&[
            "quick-seed.invalid",
            "slow-seed.invalid",
            "mute-seed.invalid",
        ]),
    );
    run(async {
        let started = Instant::now();
        source
            .next(Purpose::Block, &HashSet::new())
            .await
            .expect("seeded");
        let took = started.elapsed();
        // Waiting for the other two would take 20 s, the wait for a seed's
        // node.
        assert!(took < Duration::from_secs(10), "seeding took {took:?}");
        let first = source.known();
        assert!(first > 0 && first <= 25, "{first} known");
        slow_answers.open();
        let deadline = Instant::now() + Duration::from_secs(15);
        while source.known() == first && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(20)).await;
            source
                .next(Purpose::Block, &HashSet::new())
                .await
                .expect("a peer");
        }
        assert!(source.known() > first, "the slow seed's addresses joined");
    });
}

/// Seeding through the proxy counts the addresses the book took, not the
/// ones the seeds' nodes sent: a first answer of more than enough
/// addresses that are all refused (not public) does not end it while
/// another seed is still being asked. That seed answers only once the
/// first one's connection has ended.
#[test]
fn proxied_seeding_waits_while_the_answers_hold_no_usable_address() {
    let refused: Vec<AddrV2Message> = (1..=25u8)
        .map(|i| AddrV2Message {
            time: 0,
            services: ServiceFlags::NETWORK | ServiceFlags::WITNESS,
            addr: AddrV2::Ipv4(Ipv4Addr::new(10, i, 0, 1)),
            port: 18444,
        })
        .collect();
    let first_answered = Gate::new();
    let proxy = FakeSocks5::start();
    proxy.route(
        "x9.local-seed.invalid",
        seed_node(Answer::NowThenOpen(first_answered.clone()), refused).0,
    );
    proxy.route(
        "x9.public-seed.invalid",
        seed_node(Answer::Once(first_answered), gossip()).0,
    );
    let source = PeerSource::discover(
        Network::Regtest,
        proxy.dialer(),
        Seeds::Dns(&["local-seed.invalid", "public-seed.invalid"]),
    );
    let peer = run(source.next(Purpose::Block, &HashSet::new())).expect("seeded");
    assert!(
        peer.ip()
            .is_some_and(|ip| ip.to_string().starts_with("45."))
    );
    assert_eq!(
        source.known(),
        gossip().len(),
        "the public seed's addresses"
    );
}

/// A seed still being asked when seeding returned, whose connection then
/// finds the proxy down, is handled as during seeding: the proxy's failure
/// is noted (and logged as a warning), not taken for the seed's.
#[test]
fn the_proxy_failing_for_a_seed_that_answers_late_is_noted() {
    let proxy = FakeSocks5::start();
    proxy.route(
        "x9.quick-seed.invalid",
        seed_node(Answer::Now, gossip_of(1, 25)).0,
    );
    // Unrouted: once let through, its filter name fails at once and its
    // bare name is asked on a new connection to the proxy.
    let held = proxy.hold(name("x9.late-seed.invalid"));
    let source = PeerSource::discover(
        Network::Regtest,
        proxy.dialer(),
        Seeds::Dns(&["quick-seed.invalid", "late-seed.invalid"]),
    );
    let PeerSource::Discovered(pool) = &*source else {
        unreachable!()
    };
    run(async {
        source
            .next(Purpose::Block, &HashSet::new())
            .await
            .expect("seeded");
        assert_eq!(pool.seed_error(), None);
        proxy.go_down();
        held.open();
        let deadline = Instant::now() + Duration::from_secs(15);
        while pool.seed_error().is_none() && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(20)).await;
            let _ = source.next(Purpose::Block, &HashSet::new()).await;
        }
    });
    let error = pool.seed_error().expect("the proxy's failure is noted");
    assert!(error.contains("p2p_proxy"), "{error}");
}

#[test]
fn a_seed_without_the_filter_name_is_asked_by_its_bare_name() {
    let proxy = FakeSocks5::start();
    proxy.route("bare-seed.invalid", seed_node(Answer::Now, gossip()).0);
    let source = PeerSource::discover(
        Network::Regtest,
        proxy.dialer(),
        Seeds::Dns(&["bare-seed.invalid"]),
    );
    run(source.next(Purpose::Block, &HashSet::new())).expect("seeded");
    assert_eq!(source.known(), gossip().len());
    let targets: Vec<PeerAddr> = proxy.requests().into_iter().map(|r| r.target).collect();
    assert_eq!(
        targets,
        vec![name("x9.bare-seed.invalid"), name("bare-seed.invalid")]
    );
    assert!(!seeds_asked("bare-seed.invalid"));
}

#[test]
fn with_the_proxy_down_discovery_says_so() {
    // Nothing listens on port 1, and no parallel test can take it.
    let proxy: SocketAddr = "127.0.0.1:1".parse().unwrap();
    let source = PeerSource::discover(
        Network::Regtest,
        Dialer::Socks5 { proxy },
        Seeds::Dns(&["down-proxy-seed.invalid"]),
    );
    let err = run(source.next(Purpose::Block, &HashSet::new())).expect_err("no peers");
    for expected in [
        "the seeds could not be asked",
        "p2p_proxy",
        "cannot connect",
    ] {
        assert!(err.0.contains(expected), "{expected:?} in {err}");
    }
    assert!(!seeds_asked("down-proxy-seed.invalid"));
}
