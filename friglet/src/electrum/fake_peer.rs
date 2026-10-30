//! A scripted Bitcoin P2P peer for tests: it speaks the v1 wire protocol
//! the way Bitcoin Core does for the parts friglet uses (handshake with
//! `wtxidrelay`, `ping`/`feefilter` after `verack`, `getheaders` with an
//! empty locator, transaction `inv`/`getdata`/`notfound`).
//!
//! Peers of one [`FakeNet`] share a mempool, as peers of a real network do
//! eventually: a transaction one accepts is announced by the others to
//! every connection that asked for transaction relay.

use std::collections::{HashSet, VecDeque};
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bitcoin::block::Header;
use bitcoin::consensus::encode;
use bitcoin::p2p::message::{NetworkMessage, RawNetworkMessage};
use bitcoin::p2p::message_blockdata::Inventory;
use bitcoin::p2p::message_network::VersionMessage;
use bitcoin::p2p::{Address, ServiceFlags};
use bitcoin::{Network, Transaction, Wtxid};

/// What the peer does with a transaction handed to it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxPolicy {
    /// Mempool accepts it; `getdata` returns it from then on.
    Accept,
    /// Silently dropped (non-standard, low fee, conflict…).
    Ignore,
    /// Consensus-invalid: the connection is closed.
    Disconnect,
    /// Inputs missing: asks for the parent transaction.
    Orphan,
}

/// One connection the peer served.
#[derive(Clone, Debug)]
pub struct Conn {
    /// The `version` friglet sent.
    pub version: VersionMessage,
    /// Every command received after the handshake, in order.
    pub commands: Vec<String>,
}

pub struct FakePeer {
    pub addr: SocketAddr,
    conns: Arc<Mutex<Vec<Conn>>>,
}

#[derive(Clone)]
pub struct Script {
    pub policy: TxPolicy,
    /// Answer an `inv` with `getdata`.
    pub request_announced: bool,
    /// Transactions already in the mempool (raw bytes).
    pub mempool: Vec<Vec<u8>>,
    /// Block headers the peer knows.
    pub headers: Vec<Header>,
    /// Advertised fee filter, sat/kvB.
    pub fee_filter: u32,
    /// The `version` message's relay flag: false for a blocks-only node,
    /// which also drops a connection that announces a transaction to it.
    pub relay: bool,
    /// Announce mempool transactions (every 200 ms) to connections that
    /// asked for transaction relay.
    pub announce: bool,
    /// Announce a transaction straight back to the connection that handed
    /// it over, serve it when asked, then drop that connection a second
    /// later: a sender pretending its mempool took it.
    pub echo_inv: bool,
}

impl Default for Script {
    fn default() -> Self {
        Self {
            policy: TxPolicy::Accept,
            request_announced: true,
            mempool: Vec::new(),
            headers: Vec::new(),
            fee_filter: 1000,
            relay: true,
            announce: true,
            echo_inv: false,
        }
    }
}

/// A mempool shared by the peers of one fake network.
#[derive(Clone, Default)]
pub struct FakeNet {
    shared: Shared,
}

#[derive(Clone, Default)]
struct Shared {
    mempool: Arc<Mutex<Vec<Vec<u8>>>>,
    /// Policies for the first transactions handed to any peer, in arrival
    /// order; after them each peer's own.
    first_policies: Arc<Mutex<VecDeque<TxPolicy>>>,
}

impl FakeNet {
    pub fn new() -> Self {
        Self::default()
    }

    /// The first transactions handed to any peer of the net meet
    /// `policies`, in arrival order, whichever peer gets them.
    pub fn with_first_policies(policies: Vec<TxPolicy>) -> Self {
        let net = Self::default();
        *net.shared.first_policies.lock().unwrap() = policies.into();
        net
    }

    /// A peer of this net on `ip` (any port), serving any number of
    /// connections at once. `script.mempool` joins the shared mempool.
    pub fn peer(&self, ip: IpAddr, script: Script) -> FakePeer {
        self.shared
            .mempool
            .lock()
            .unwrap()
            .extend(script.mempool.iter().cloned());
        let listener = TcpListener::bind(SocketAddr::new(ip, 0)).unwrap();
        let addr = listener.local_addr().unwrap();
        let conns = Arc::new(Mutex::new(Vec::new()));
        let (thread_conns, shared) = (conns.clone(), self.shared.clone());
        std::thread::spawn(move || {
            while let Ok((stream, _)) = listener.accept() {
                let (script, shared, conns) =
                    (script.clone(), shared.clone(), thread_conns.clone());
                std::thread::spawn(move || {
                    let _ = serve(stream, &script, &shared, &conns);
                });
            }
        });
        FakePeer { addr, conns }
    }

    pub fn has(&self, txid: bitcoin::Txid) -> bool {
        self.shared
            .mempool
            .lock()
            .unwrap()
            .iter()
            .any(|raw| ids(raw).0 == txid)
    }
}

impl FakePeer {
    /// Serve `connections` connections, one after another, with `script`.
    pub fn spawn(script: Script, connections: usize) -> Self {
        Self::spawn_on([127, 0, 0, 1].into(), script, connections)
    }

    /// [`Self::spawn`] listening on `ip` (any port): discovered peers are
    /// told apart by IP only.
    pub fn spawn_on(ip: IpAddr, script: Script, connections: usize) -> Self {
        let listener = TcpListener::bind(SocketAddr::new(ip, 0)).unwrap();
        let addr = listener.local_addr().unwrap();
        let conns = Arc::new(Mutex::new(Vec::new()));
        let shared = Shared {
            mempool: Arc::new(Mutex::new(script.mempool.clone())),
            first_policies: Arc::default(),
        };
        let thread_conns = conns.clone();
        std::thread::spawn(move || {
            for _ in 0..connections {
                let Ok((stream, _)) = listener.accept() else {
                    return;
                };
                let _ = serve(stream, &script, &shared, &thread_conns);
            }
        });
        FakePeer { addr, conns }
    }

    /// Every command received after the handshake, over all connections.
    pub fn commands(&self) -> Vec<String> {
        self.conns
            .lock()
            .unwrap()
            .iter()
            .flat_map(|conn| conn.commands.clone())
            .collect()
    }

    /// The connections served so far (complete handshakes and attempts).
    pub fn conns(&self) -> Vec<Conn> {
        self.conns.lock().unwrap().clone()
    }
}

/// The txid and wtxid of a raw transaction.
fn ids(raw: &[u8]) -> (bitcoin::Txid, Wtxid) {
    let tx: Transaction = encode::deserialize(raw).unwrap();
    (tx.compute_txid(), tx.compute_wtxid())
}

struct Wire {
    stream: TcpStream,
    buf: Vec<u8>,
}

impl Wire {
    fn send(&mut self, message: NetworkMessage) -> std::io::Result<()> {
        let raw = RawNetworkMessage::new(Network::Regtest.magic(), message);
        self.stream.write_all(&encode::serialize(&raw))
    }

    /// The next message, or `None` when the read timeout passes first.
    fn recv(&mut self) -> std::io::Result<Option<NetworkMessage>> {
        loop {
            if self.buf.len() >= 24 {
                let len = u32::from_le_bytes(self.buf[16..20].try_into().unwrap()) as usize;
                if self.buf.len() >= 24 + len {
                    let raw: RawNetworkMessage = encode::deserialize(&self.buf[..24 + len])
                        .map_err(|e| std::io::Error::other(e.to_string()))?;
                    self.buf.drain(..24 + len);
                    return Ok(Some(raw.into_payload()));
                }
            }
            let mut chunk = [0u8; 65536];
            match self.stream.read(&mut chunk) {
                Ok(0) => return Err(std::io::ErrorKind::UnexpectedEof.into()),
                Ok(n) => self.buf.extend_from_slice(&chunk[..n]),
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    return Ok(None);
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// The next message, waiting up to a minute.
    fn recv_blocking(&mut self) -> std::io::Result<NetworkMessage> {
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            if let Some(message) = self.recv()? {
                return Ok(message);
            }
            if Instant::now() >= deadline {
                return Err(std::io::ErrorKind::TimedOut.into());
            }
        }
    }
}

fn serve(
    stream: TcpStream,
    script: &Script,
    shared: &Shared,
    conns: &Mutex<Vec<Conn>>,
) -> std::io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_millis(200)))?;
    let mut wire = Wire {
        stream,
        buf: Vec::new(),
    };
    // Handshake, Bitcoin Core style.
    let NetworkMessage::Version(theirs) = wire.recv_blocking()? else {
        return Ok(());
    };
    let their_relay = theirs.relay;
    let conn = {
        let mut conns = conns.lock().unwrap();
        conns.push(Conn {
            version: theirs,
            commands: Vec::new(),
        });
        conns.len() - 1
    };
    let useless = Address {
        services: ServiceFlags::NONE,
        address: [0; 8],
        port: 0,
    };
    wire.send(NetworkMessage::Version(VersionMessage {
        // BIP 339's `WTXID_RELAY_VERSION`.
        version: 70016,
        services: ServiceFlags::NETWORK | ServiceFlags::WITNESS,
        timestamp: 0,
        receiver: useless.clone(),
        sender: useless,
        nonce: 7,
        user_agent: "/Fake:1.0.0/".to_string(),
        start_height: 0,
        relay: script.relay,
    }))?;
    wire.send(NetworkMessage::WtxidRelay)?;
    wire.send(NetworkMessage::Verack)?;
    let mut wtxid_relay = false;
    loop {
        match wire.recv_blocking()? {
            NetworkMessage::Verack => break,
            NetworkMessage::WtxidRelay => wtxid_relay = true,
            _ => {}
        }
    }
    wire.send(NetworkMessage::Ping(1))?;
    wire.send(NetworkMessage::FeeFilter(i64::from(script.fee_filter)))?;

    let inventory = |raw: &[u8]| {
        let (txid, wtxid) = ids(raw);
        if wtxid_relay {
            Inventory::WTx(wtxid)
        } else {
            Inventory::Transaction(txid)
        }
    };
    // Transactions this connection knows: announced either way.
    let mut known: HashSet<Vec<u8>> = HashSet::new();
    let mut echoed: Option<(Vec<u8>, Instant)> = None;
    loop {
        if script.announce && script.relay && their_relay {
            let fresh: Vec<Vec<u8>> = shared
                .mempool
                .lock()
                .unwrap()
                .iter()
                .filter(|raw| !known.contains(*raw))
                .cloned()
                .collect();
            if !fresh.is_empty() {
                let items = fresh.iter().map(|raw| inventory(raw)).collect();
                known.extend(fresh);
                wire.send(NetworkMessage::Inv(items))?;
            }
        }
        if let Some((_, at)) = &echoed
            && at.elapsed() > Duration::from_secs(1)
        {
            return Ok(());
        }
        let Some(message) = wire.recv()? else {
            continue;
        };
        conns.lock().unwrap()[conn]
            .commands
            .push(message.command().to_string());
        match message {
            NetworkMessage::Ping(nonce) => wire.send(NetworkMessage::Pong(nonce))?,
            NetworkMessage::GetHeaders(request) if request.locator_hashes.is_empty() => {
                if let Some(header) = script
                    .headers
                    .iter()
                    .find(|h| h.block_hash() == request.stop_hash)
                {
                    wire.send(NetworkMessage::Headers(vec![*header]))?;
                }
            }
            // A blocks-only node drops a peer that announces transactions.
            NetworkMessage::Inv(_) if !script.relay => return Ok(()),
            NetworkMessage::Inv(items) if script.request_announced => {
                wire.send(NetworkMessage::GetData(items))?;
            }
            NetworkMessage::GetData(items) => {
                let mut missing = Vec::new();
                for item in items {
                    let mempool = shared.mempool.lock().unwrap().clone();
                    let found = mempool
                        .iter()
                        .chain(echoed.as_ref().map(|(raw, _)| raw))
                        .find(|raw| {
                            let (txid, wtxid) = ids(raw);
                            super::p2p::inventory_matches(&item, txid, wtxid)
                        })
                        .cloned();
                    match found {
                        Some(raw) => {
                            wire.send(NetworkMessage::Tx(encode::deserialize(&raw).unwrap()))?;
                            if echoed.as_ref().is_some_and(|(echo, _)| *echo == raw) {
                                return Ok(());
                            }
                        }
                        None => missing.push(item),
                    }
                }
                if !missing.is_empty() {
                    wire.send(NetworkMessage::NotFound(missing))?;
                }
            }
            NetworkMessage::Tx(tx) => {
                let raw = encode::serialize(&tx);
                known.insert(raw.clone());
                let policy = shared
                    .first_policies
                    .lock()
                    .unwrap()
                    .pop_front()
                    .unwrap_or(script.policy);
                match policy {
                    TxPolicy::Accept => {
                        let mut mempool = shared.mempool.lock().unwrap();
                        if !mempool.contains(&raw) {
                            mempool.push(raw.clone());
                        }
                    }
                    TxPolicy::Ignore => {}
                    TxPolicy::Disconnect => return Ok(()),
                    TxPolicy::Orphan => {
                        let parent = tx.input[0].previous_output.txid;
                        wire.send(NetworkMessage::GetData(vec![
                            Inventory::WitnessTransaction(parent),
                        ]))?;
                    }
                }
                if script.echo_inv {
                    wire.send(NetworkMessage::Inv(vec![inventory(&raw)]))?;
                    echoed = Some((raw, Instant::now()));
                }
            }
            _ => {}
        }
    }
}

/// A regtest-style header that is not on any real chain.
pub fn header(nonce: u32) -> Header {
    let mut header = bitcoin::constants::genesis_block(Network::Regtest).header;
    header.nonce = nonce;
    header
}
