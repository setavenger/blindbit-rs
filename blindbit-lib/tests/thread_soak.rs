//! Block downloads leave no threads behind: each opens a connection with a
//! download thread and the P2P library's writer thread (plus, for a
//! discovered peer asked for addresses, a short wait for them), and all of
//! them end. Its own test binary, so no other test's threads are counted.

#![cfg(target_os = "linux")]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::time::{Duration, Instant};

use bitcoin::consensus::encode;
use bitcoin::p2p::ServiceFlags;
use bitcoin::p2p::message::{NetworkMessage, RawNetworkMessage};
use bitcoin::p2p::message_network::VersionMessage;
use bitcoin::p2p::{Address, Magic};
use bitcoin::{Block, Network};
use blindbit_lib::net::{Dialer, PeerSource, Seeds};
use blindbit_lib::scanner::{BlockFetcher, RetryPolicy};

fn threads() -> usize {
    std::fs::read_dir("/proc/self/task").unwrap().count()
}

fn block() -> Block {
    bitcoin::constants::genesis_block(Network::Regtest)
}

/// A node on `ip` that serves the block on every connection, each on a
/// thread of its own, for as long as the test runs.
fn node(ip: [u8; 4]) -> SocketAddr {
    let listener = TcpListener::bind(SocketAddr::from((ip, 0))).unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            std::thread::spawn(move || serve(stream));
        }
    });
    addr
}

fn send(stream: &mut TcpStream, magic: Magic, message: NetworkMessage) -> std::io::Result<()> {
    stream.write_all(&encode::serialize(&RawNetworkMessage::new(magic, message)))
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
        let mut chunk = [0u8; 65536];
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            return Err(std::io::ErrorKind::UnexpectedEof.into());
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

fn serve(mut stream: TcpStream) -> std::io::Result<()> {
    let magic = Network::Regtest.magic();
    let mut buf = Vec::new();
    let NetworkMessage::Version(_) = recv(&mut stream, &mut buf)? else {
        return Ok(());
    };
    let nowhere = Address::new(&SocketAddr::from(([127, 0, 0, 1], 1)), ServiceFlags::NONE);
    send(
        &mut stream,
        magic,
        NetworkMessage::Version(VersionMessage {
            version: 70016,
            services: ServiceFlags::NETWORK | ServiceFlags::WITNESS,
            timestamp: 0,
            receiver: nowhere.clone(),
            sender: nowhere,
            nonce: 9,
            user_agent: "/Soak:1.0/".to_string(),
            start_height: 1_000,
            relay: true,
        }),
    )?;
    send(&mut stream, magic, NetworkMessage::Verack)?;
    loop {
        match recv(&mut stream, &mut buf)? {
            NetworkMessage::GetData(_) => {
                send(&mut stream, magic, NetworkMessage::Block(block()))?;
            }
            NetworkMessage::Ping(nonce) => send(&mut stream, magic, NetworkMessage::Pong(nonce))?,
            _ => {}
        }
    }
}

#[test]
fn fifty_block_downloads_leave_no_thread_behind() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        // Blocking-pool threads (the TCP connect) end soon after use.
        .thread_keep_alive(Duration::from_millis(100))
        .build()
        .unwrap();
    let own = node([127, 0, 0, 71]);
    let peers = [
        node([127, 0, 0, 72]),
        node([127, 0, 0, 73]),
        node([127, 0, 0, 74]),
    ];
    let own_node = PeerSource::own_node(own.into(), Dialer::Direct, Network::Regtest);
    let discovered = PeerSource::discover(
        Network::Regtest,
        Dialer::Direct,
        Seeds::Static(peers.iter().map(|addr| (*addr).into()).collect()),
    );
    let quick = |peers: &PeerSource| RetryPolicy {
        block_deadline: Duration::from_secs(5),
        ..RetryPolicy::for_source(peers)
    };
    let baseline = threads();

    runtime.block_on(async {
        for i in 0..50 {
            let source = if i % 2 == 0 { &own_node } else { &discovered };
            BlockFetcher::new(source.clone())
                .with_policy(quick(source))
                .fetch(block().block_hash(), 100)
                .await
                .expect("served");
        }
    });
    let during = threads();

    // Writer threads end within about a second of their connection; a
    // discovered peer's wait for addresses within 3 s.
    let deadline = Instant::now() + Duration::from_secs(15);
    while threads() > baseline && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(
        threads() <= baseline,
        "{} threads before, {during} right after the downloads, {} now",
        baseline,
        threads()
    );
}
