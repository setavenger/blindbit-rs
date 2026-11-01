//! Discovery through a SOCKS5 proxy: the seeds are asked by name through
//! it, never through this computer's resolver.

use std::collections::HashSet;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::time::Duration;

use bitcoin::Network;
use bitcoin::consensus::encode;
use bitcoin::p2p::address::{AddrV2, AddrV2Message};
use bitcoin::p2p::message::{NetworkMessage, RawNetworkMessage};
use bitcoin::p2p::message_network::VersionMessage;
use bitcoin::p2p::{Address, ServiceFlags};

use super::testing::FakeSocks5;
use super::{Dialer, PeerAddr, PeerHost, PeerSource, Purpose, Seeds, seeds_asked};

fn run<F: std::future::Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime")
        .block_on(future)
}

/// Public addresses a seed's node gossips.
fn gossip() -> Vec<AddrV2Message> {
    (1..=5u8)
        .map(|i| AddrV2Message {
            time: 0,
            services: ServiceFlags::NETWORK | ServiceFlags::WITNESS,
            addr: AddrV2::Ipv4(Ipv4Addr::new(45, i, 7 * i, i)),
            port: 18444,
        })
        .collect()
}

/// A regtest node on 127.0.0.1 that answers `getaddr` with [`gossip`].
fn seed_node() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            std::thread::spawn(move || {
                let _ = serve(stream);
            });
        }
    });
    addr
}

fn serve(mut stream: TcpStream) -> std::io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    let magic = Network::Regtest.magic();
    let mut buf = Vec::new();
    let send = |stream: &mut TcpStream, message| {
        stream.write_all(&encode::serialize(&RawNetworkMessage::new(magic, message)))
    };
    let useless = Address::new(&"127.0.0.1:1".parse().unwrap(), ServiceFlags::NONE);
    loop {
        let message = recv(&mut stream, &mut buf)?;
        match message {
            NetworkMessage::Version(_) => {
                send(
                    &mut stream,
                    NetworkMessage::Version(VersionMessage {
                        version: 70016,
                        services: ServiceFlags::NETWORK | ServiceFlags::WITNESS,
                        timestamp: 0,
                        receiver: useless.clone(),
                        sender: useless.clone(),
                        nonce: 9,
                        user_agent: "/FakeSeedNode:1.0/".to_string(),
                        start_height: 100,
                        relay: true,
                    }),
                )?;
                send(&mut stream, NetworkMessage::Verack)?;
            }
            NetworkMessage::GetAddr => send(&mut stream, NetworkMessage::AddrV2(gossip()))?,
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
    proxy.route("x9.proxied-seed.invalid", seed_node());
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
}

#[test]
fn a_seed_without_the_filter_name_is_asked_by_its_bare_name() {
    let proxy = FakeSocks5::start();
    proxy.route("bare-seed.invalid", seed_node());
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
