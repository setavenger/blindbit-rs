//! The full-block fetch against a scripted P2P node: a dropped connection is
//! retried on a fresh one, and a block the node will not serve ends in a
//! message that says what the node did, what the user can do, and (in the
//! daemon) when it is tried again.

use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bitcoin::hashes::Hash;
use bitcoin::{Block, BlockHash};
use bitcoin_p2p::p2p_message_types::message::{
    InventoryPayload, NetworkMessage, RawNetworkMessage,
};
use bitcoin_p2p::p2p_message_types::message_blockdata::Inventory;
use bitcoin_p2p::p2p_message_types::message_network::{
    ClientSoftwareVersion, UserAgent, UserAgentVersion, VersionMessage,
};
use bitcoin_p2p::p2p_message_types::{Address, NetworkExt, ProtocolVersion, ServiceFlags};
use bitcoin_rev::Network;
use bitcoin_rev::consensus::encode;

use super::ScannerError;
use super::health::OracleProbe;
use super::p2p::{BlockFetchError, BlockFetcher, FetchBackoff, FetchFailure, RetryPolicy};
use super::scanning::BlockStreamSource;
use super::stream_safety_tests::{TestStream, payment_block};
use super::test_support::{run, scanner};
use crate::oracle_grpc::{BlockIdentifier, BlockScanDataShortResponse};

/// What the node does on one connection.
#[derive(Clone, Copy, Debug)]
pub(super) enum Conn {
    /// Close right after the handshake, as a node that evicts, bans or
    /// disconnects friglet does.
    CloseAfterHandshake,
    /// Start sending the block and close halfway through it.
    CloseMidBlock,
    /// Start sending the block and go silent halfway through it, keeping
    /// the connection open until the client hangs up (or 10 s pass).
    StallMidBlock,
    /// Serve the block as Bitcoin Core does: with its witnesses for
    /// `MSG_WITNESS_BLOCK`, without them for `MSG_BLOCK`.
    Serve,
    /// Serve the block without its witnesses whatever was asked.
    ServeStripped,
    NotFound,
    /// Never answer the request.
    Ignore,
    /// Answer in another network's P2P protocol.
    Magic(Network),
    /// Answer like a web server.
    Http,
    /// Close without answering the version message.
    CloseBeforeVersion,
}

pub(super) struct Node {
    pub(super) addr: SocketAddr,
    connections: Arc<AtomicUsize>,
    /// When a [`Conn::StallMidBlock`] connection went silent.
    stalled: Arc<Mutex<Option<Instant>>>,
}

/// The block a node serves, as it goes on the wire with and without its
/// witnesses.
struct Served {
    full: bitcoin_rev::Block,
    stripped: bitcoin_rev::Block,
}

impl Served {
    fn new(block: &Block) -> Self {
        let wire = |block: &Block| -> bitcoin_rev::Block {
            encode::deserialize(&bitcoin::consensus::encode::serialize(block)).unwrap()
        };
        Self {
            full: wire(block),
            stripped: wire(&stripped(block)),
        }
    }
}

/// `block` with every input's witness removed.
pub(super) fn stripped(block: &Block) -> Block {
    let mut block = block.clone();
    for tx in &mut block.txdata {
        for input in &mut tx.input {
            input.witness.clear();
        }
    }
    block
}

impl Node {
    /// A full node at `height` serving the default block.
    pub(super) fn full(height: i32, script: Vec<Conn>) -> Self {
        Self::spawn(ServiceFlags::NETWORK | ServiceFlags::WITNESS, height, &block(), script)
    }

    /// A full node at height 1,000 serving `block`.
    pub(super) fn serving(block: &Block, script: Vec<Conn>) -> Self {
        Self::spawn(ServiceFlags::NETWORK | ServiceFlags::WITNESS, 1_000, block, script)
    }

    /// A node advertising `services` and `height` and serving `block` that
    /// handles one connection after another as `script` says, then stops
    /// listening.
    fn spawn(services: ServiceFlags, height: i32, block: &Block, script: Vec<Conn>) -> Self {
        let served = Served::new(block);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let connections = Arc::new(AtomicUsize::new(0));
        let counter = connections.clone();
        let stalled = Arc::new(Mutex::new(None));
        let stalled_at = stalled.clone();
        std::thread::spawn(move || {
            for conn in script {
                let Ok((stream, _)) = listener.accept() else {
                    return;
                };
                counter.fetch_add(1, Ordering::SeqCst);
                let _ = serve(stream, conn, services, height, &served, &stalled_at);
            }
        });
        Node {
            addr,
            connections,
            stalled,
        }
    }

    pub(super) fn connections(&self) -> usize {
        self.connections.load(Ordering::SeqCst)
    }

    /// When the node went silent in the middle of the block, if it did.
    pub(super) fn stalled(&self) -> Option<Instant> {
        *self.stalled.lock().unwrap()
    }
}

struct Wire {
    stream: TcpStream,
    buf: Vec<u8>,
    magic: bitcoin_p2p::p2p_message_types::Magic,
}

impl Wire {
    fn send(&mut self, message: NetworkMessage) -> std::io::Result<()> {
        self.stream
            .write_all(&encode::serialize(&RawNetworkMessage::new(
                self.magic, message,
            )))
    }

    fn recv(&mut self) -> std::io::Result<NetworkMessage> {
        loop {
            if self.buf.len() >= 24 {
                let len = u32::from_le_bytes(self.buf[16..20].try_into().unwrap()) as usize;
                if self.buf.len() >= 24 + len {
                    let raw: RawNetworkMessage = encode::deserialize(&self.buf[..24 + len])
                        .map_err(|e| std::io::Error::other(e.to_string()))?;
                    self.buf.drain(..24 + len);
                    return Ok(raw.into_payload());
                }
            }
            let mut chunk = [0u8; 65536];
            let n = self.stream.read(&mut chunk)?;
            if n == 0 {
                return Err(std::io::ErrorKind::UnexpectedEof.into());
            }
            self.buf.extend_from_slice(&chunk[..n]);
        }
    }

    /// Read until the client hangs up, so closing never resets the
    /// connection under data the client has not read yet.
    fn drain(mut self) -> std::io::Result<()> {
        let mut sink = [0u8; 4096];
        while self.stream.read(&mut sink)? > 0 {}
        Ok(())
    }
}

/// The block every node here serves.
fn block() -> Block {
    bitcoin::constants::genesis_block(bitcoin::Network::Regtest)
}

fn serve(
    stream: TcpStream,
    conn: Conn,
    services: ServiceFlags,
    height: i32,
    served: &Served,
    stalled: &Mutex<Option<Instant>>,
) -> std::io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    let magic = match conn {
        Conn::Magic(network) => network.default_network_magic(),
        _ => Network::Regtest.default_network_magic(),
    };
    let mut wire = Wire {
        stream,
        buf: Vec::new(),
        magic,
    };
    let NetworkMessage::Version(_) = wire.recv()? else {
        return Ok(());
    };
    if let Conn::CloseBeforeVersion = conn {
        return Ok(());
    }
    if let Conn::Http = conn {
        wire.stream
            .write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")?;
        return wire.drain();
    }
    wire.send(NetworkMessage::Version(VersionMessage {
        version: ProtocolVersion::WTXID_RELAY_VERSION,
        services,
        timestamp: 0,
        receiver: Address::useless(),
        sender: Address::useless(),
        nonce: 7,
        user_agent: UserAgent::new(
            "Fake",
            UserAgentVersion::new(ClientSoftwareVersion::SemVer {
                major: 1,
                minor: 0,
                revision: 0,
            }),
        ),
        start_height: height,
        relay: true,
    }))?;
    if let Conn::Magic(_) = conn {
        return wire.drain();
    }
    wire.send(NetworkMessage::WtxidRelay)?;
    wire.send(NetworkMessage::Verack)?;
    while !matches!(wire.recv()?, NetworkMessage::Verack) {}
    wire.send(NetworkMessage::Ping(1))?;
    if let Conn::CloseAfterHandshake = conn {
        return Ok(());
    }
    let items = loop {
        if let NetworkMessage::GetData(items) = wire.recv()? {
            break items;
        }
    };
    let witness = matches!(items.0.first(), Some(Inventory::WitnessBlock(_)));
    match conn {
        Conn::Serve if witness => wire.send(NetworkMessage::Block(served.full.clone()))?,
        Conn::Serve | Conn::ServeStripped => {
            wire.send(NetworkMessage::Block(served.stripped.clone()))?
        }
        Conn::NotFound => wire.send(NetworkMessage::NotFound(InventoryPayload(items.0)))?,
        Conn::CloseMidBlock => {
            let bytes = encode::serialize(&RawNetworkMessage::new(
                magic,
                NetworkMessage::Block(served.full.clone()),
            ));
            wire.stream.write_all(&bytes[..bytes.len() / 2])?;
            wire.stream.shutdown(Shutdown::Write)?;
        }
        Conn::StallMidBlock => {
            let bytes = encode::serialize(&RawNetworkMessage::new(
                magic,
                NetworkMessage::Block(served.full.clone()),
            ));
            wire.stream.write_all(&bytes[..bytes.len() / 2])?;
            wire.stream.flush()?;
            *stalled.lock().unwrap() = Some(Instant::now());
        }
        _ => {}
    }
    wire.drain()
}

/// Attempts 10 ms apart, a 2 s budget per block.
pub(super) fn fast(attempts: u32) -> RetryPolicy {
    RetryPolicy {
        attempts,
        first_delay: Duration::from_millis(10),
        max_delay: Duration::from_millis(20),
        block_deadline: Duration::from_secs(2),
    }
}

fn fetch(node: &Node, policy: RetryPolicy, height: u64) -> Result<Block, Box<BlockFetchError>> {
    run(BlockFetcher::new(node.addr, Network::Regtest)
        .with_policy(policy)
        .fetch(block().block_hash(), height))
}

#[test]
fn a_dropped_connection_is_retried_on_a_fresh_one() {
    let node = Node::full(
        200,
        vec![Conn::CloseMidBlock, Conn::CloseAfterHandshake, Conn::Serve],
    );
    let got = fetch(&node, fast(5), 0).expect("third connection serves the block");
    assert_eq!(got.block_hash(), block().block_hash());
    assert_eq!(node.connections(), 3);
}

#[test]
fn a_node_that_drops_every_connection_says_how_to_fix_it() {
    // The mainnet failure: the node accepts each connection and closes it
    // again before the block arrives.
    let node = Node::full(50_000, vec![Conn::CloseAfterHandshake; 3]);
    let err = fetch(&node, fast(3), 2_000).expect_err("never served");
    assert_eq!(node.connections(), 3, "every attempt is a fresh connection");
    assert_eq!(err.attempts, 3);
    assert!(
        matches!(
            err.failure,
            FetchFailure::Closed {
                during_handshake: false,
                ..
            }
        ),
        "{:?}",
        err.failure
    );
    let message = err.to_string();
    for expected in [
        "cannot get block 2000",
        "accepted the connection and closed it",
        "before the block arrived (all 3 tries)",
        // A node on this machine sees friglet's loopback address.
        "whitelist=download,noban@127.0.0.1",
        // 48,000 blocks deep: older than a week.
        "-maxuploadtarget",
        "or point p2p_node_addr at another node",
    ] {
        assert!(
            message.contains(expected),
            "missing {expected:?} in: {message}"
        );
    }
    assert!(!message.contains("retries automatically"), "{message}");
}

#[test]
fn a_node_that_closes_before_answering_is_checked_for_the_network_first() {
    // Bitcoin Core closes a connection from another network's peer before
    // sending anything, as it does for banned addresses.
    let node = Node::full(200, vec![Conn::CloseBeforeVersion; 2]);
    let err = fetch(&node, fast(2), 100).expect_err("rejected");
    assert!(
        matches!(
            err.failure,
            FetchFailure::Closed {
                during_handshake: true,
                ..
            }
        ),
        "{:?}",
        err.failure
    );
    assert_eq!(err.peer_info, None);
    let message = err.to_string();
    for expected in [
        "closed the connection during the handshake (all 2 tries)",
        "peers of another network",
        "P2P port of a regtest node (usually 18444)",
        "whitelist=download,noban@127.0.0.1",
    ] {
        assert!(
            message.contains(expected),
            "missing {expected:?} in: {message}"
        );
    }
}

#[test]
fn a_mainnet_scan_pointed_at_a_signet_port_is_told_so() {
    // What friglet reports when its mainnet config names the signet node's
    // port: Bitcoin Core closes the connection before answering.
    let err = BlockFetchError {
        peer: "152.53.151.148:38333".parse().unwrap(),
        network: Network::Bitcoin,
        height: 921_763,
        block_hash: block().block_hash(),
        attempts: 5,
        failure: FetchFailure::Closed {
            during_handshake: true,
            after: Duration::from_millis(48),
        },
        peer_info: None,
        local_ip: Some("192.168.1.20".parse().unwrap()),
        retry: None,
    };
    let message = err.to_string();
    for expected in [
        "P2P port of a mainnet node (usually 8333): 38333 is the signet port",
        // A remote node sees the public address, not the LAN one.
        "whitelist=download,noban@<this computer's public IP>",
    ] {
        assert!(
            message.contains(expected),
            "missing {expected:?} in: {message}"
        );
    }
}

#[test]
fn a_recent_block_does_not_blame_the_upload_limit() {
    let node = Node::full(1_000, vec![Conn::CloseAfterHandshake; 2]);
    let message = fetch(&node, fast(2), 990)
        .expect_err("never served")
        .to_string();
    assert!(message.contains("whitelist=download,noban@"), "{message}");
    assert!(!message.contains("maxuploadtarget"), "{message}");
}

#[test]
fn a_pruned_node_is_named_as_pruned() {
    let node = Node::spawn(
        ServiceFlags::NETWORK_LIMITED | ServiceFlags::WITNESS,
        10_000,
        &block(),
        vec![Conn::CloseAfterHandshake; 2],
    );
    let message = fetch(&node, fast(2), 100)
        .expect_err("never served")
        .to_string();
    for expected in ["the node is pruned", "9900 blocks deep", "prune=0"] {
        assert!(
            message.contains(expected),
            "missing {expected:?} in: {message}"
        );
    }
    assert!(!message.contains("whitelist"), "{message}");
}

#[test]
fn notfound_ends_the_round_at_once() {
    let node = Node::full(200, vec![Conn::NotFound]);
    let err = fetch(&node, fast(5), 100).expect_err("not found");
    assert_eq!(err.failure, FetchFailure::NotFound);
    assert_eq!(err.attempts, 1, "asking again cannot change the answer");
    let message = err.to_string();
    assert!(message.contains("answered notfound"), "{message}");
    assert!(message.contains("prune=0"), "{message}");
}

#[test]
fn a_silent_node_behind_the_block_is_reported_as_syncing() {
    let node = Node::full(50, vec![Conn::Ignore]);
    let err = fetch(
        &node,
        RetryPolicy {
            block_deadline: Duration::from_millis(300),
            ..fast(5)
        },
        100,
    )
    .expect_err("no answer");
    assert!(
        matches!(err.failure, FetchFailure::NoAnswer(_)),
        "{:?}",
        err.failure
    );
    assert_eq!(err.attempts, 1);
    let message = err.to_string();
    assert!(message.contains("sent nothing"), "{message}");
    assert!(
        message.contains("reports height 50: it is still syncing"),
        "{message}"
    );
}

#[test]
fn a_node_of_another_network_is_named() {
    let node = Node::full(200, vec![Conn::Magic(Network::Signet)]);
    let err = fetch(&node, fast(5), 100).expect_err("wrong network");
    assert_eq!(
        err.failure,
        FetchFailure::WrongNetwork(Some(Network::Signet))
    );
    assert_eq!(err.attempts, 1);
    let message = err.to_string();
    assert!(
        message.contains("it is a signet node, but friglet scans regtest"),
        "{message}"
    );
    assert!(message.contains("usually 18444"), "{message}");
}

#[test]
fn a_service_that_is_not_bitcoin_p2p_is_named() {
    let node = Node::full(200, vec![Conn::Http]);
    let err = fetch(&node, fast(5), 100).expect_err("not bitcoin");
    assert_eq!(err.failure, FetchFailure::WrongNetwork(None));
    assert!(
        err.to_string()
            .contains("does not speak the regtest Bitcoin P2P protocol"),
        "{err}"
    );
}

#[test]
fn a_refused_connection_is_retried_then_explained() {
    let addr = {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap()
    };
    let err = run(BlockFetcher::new(addr, Network::Regtest)
        .with_policy(fast(3))
        .fetch(block().block_hash(), 100))
    .expect_err("nothing listens");
    assert!(
        matches!(err.failure, FetchFailure::Connect(_)),
        "{:?}",
        err.failure
    );
    assert_eq!(err.attempts, 3);
    let message = err.to_string();
    assert!(message.contains("cannot connect"), "{message}");
    assert!(message.contains("listen=1"), "{message}");
}

#[test]
fn the_wait_between_rounds_doubles_up_to_five_minutes_and_restarts_per_block() {
    let a = BlockHash::from_byte_array([1; 32]);
    let b = BlockHash::from_byte_array([2; 32]);
    let mut backoff = FetchBackoff::default();
    let waits: Vec<u64> = (0..6)
        .map(|_| backoff.failed(a).next_in.as_secs())
        .collect();
    assert_eq!(waits, [30, 60, 120, 240, 300, 300]);
    assert_eq!(backoff.take_wait(), Some(Duration::from_secs(300)));
    assert_eq!(backoff.take_wait(), None, "a wait is used once");
    let note = backoff.failed(b);
    assert_eq!((note.failures, note.next_in.as_secs()), (1, 30));
    backoff.succeeded();
    assert_eq!(backoff.failed(b).failures, 1);
}

/// The oracle side of a daemon poll: one block at height 1.
#[derive(Clone)]
pub(super) struct OneBlock(pub(super) BlockScanDataShortResponse);

impl BlockStreamSource for OneBlock {
    type Stream = TestStream;

    async fn open(&mut self, _start: u64, _end: u64) -> Result<TestStream, ScannerError> {
        Ok(TestStream::new(vec![Ok(self.0.clone())]))
    }
}

impl OracleProbe for OneBlock {
    async fn block_hash_at(&mut self, _height: u64) -> Result<Option<BlockHash>, ScannerError> {
        Ok(None)
    }
}

#[test]
fn the_daemon_publishes_an_actionable_stall_with_its_next_try_and_backs_off() {
    run(async {
        let (mut scanner, _state) = scanner("p2p-stall");
        let node = Node::full(1_000, vec![Conn::CloseAfterHandshake; 4]);
        scanner.p2p_peer = node.addr;
        scanner.p2p_retry = fast(2);
        // A payment to the wallet, in a block nobody serves in-process: the
        // scan has to fetch it from the node.
        let mut message = payment_block(1).message;
        message.block_identifier = Some(BlockIdentifier {
            block_hash: vec![0x5a; 32],
            block_height: 1,
        });
        let oracle = OneBlock(message);

        assert!(!scanner.watch_step(1, oracle.clone()).await);
        let stall = scanner.scan_health().await.stall.expect("stalled");
        assert_eq!(stall.height, 1);
        for expected in [
            "closed it",
            "whitelist=download,noban@127.0.0.1",
            "friglet retries automatically: next try in 30 s (failed once so far; the wait \
             grows to at most 5 min)",
        ] {
            assert!(
                stall.reason.contains(expected),
                "missing {expected:?} in: {}",
                stall.reason
            );
        }
        assert_eq!(
            scanner.fetch_backoff.take_wait(),
            Some(Duration::from_secs(30))
        );

        assert!(!scanner.watch_step(1, oracle).await);
        let stall = scanner.scan_health().await.stall.expect("still stalled");
        assert!(
            stall
                .reason
                .contains("next try in 1 min (failed 2 times so far"),
            "{}",
            stall.reason
        );
        assert_eq!(
            scanner.fetch_backoff.take_wait(),
            Some(Duration::from_secs(60))
        );
        assert_eq!(node.connections(), 4);
        assert_eq!(
            scanner.get_last_scanned_block_height(),
            0,
            "nothing skipped"
        );
    });
}
