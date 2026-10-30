//! A scripted Bitcoin P2P peer for tests: it speaks the v1 wire protocol
//! the way Bitcoin Core does for the parts friglet uses (handshake with
//! `wtxidrelay`, `ping`/`feefilter` after `verack`, `getheaders` with an
//! empty locator, transaction `inv`/`getdata`/`notfound`).

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bitcoin_p2p::p2p_message_types::message::{
    HeadersMessage, InventoryPayload, NetworkMessage, RawNetworkMessage,
};
use bitcoin_p2p::p2p_message_types::message_blockdata::Inventory;
use bitcoin_p2p::p2p_message_types::message_network::{
    ClientSoftwareVersion, UserAgent, UserAgentVersion, VersionMessage,
};
use bitcoin_p2p::p2p_message_types::{Address, NetworkExt, ProtocolVersion, ServiceFlags};
use bitcoin_rev::Network;
use bitcoin_rev::consensus::encode;

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

pub struct FakePeer {
    pub addr: SocketAddr,
    /// Every command received after the handshake, in order.
    commands: Arc<Mutex<Vec<String>>>,
}

#[derive(Clone)]
pub struct Script {
    pub policy: TxPolicy,
    /// Answer an `inv` with `getdata`.
    pub request_announced: bool,
    /// Transactions already in the mempool (raw bytes).
    pub mempool: Vec<Vec<u8>>,
    /// Block headers the peer knows.
    pub headers: Vec<bitcoin_rev::block::Header>,
    /// Advertised fee filter, sat/kvB.
    pub fee_filter: u32,
}

impl Default for Script {
    fn default() -> Self {
        Self {
            policy: TxPolicy::Accept,
            request_announced: true,
            mempool: Vec::new(),
            headers: Vec::new(),
            fee_filter: 1000,
        }
    }
}

impl FakePeer {
    /// Serve `connections` connections, one after another, with `script`.
    pub fn spawn(script: Script, connections: usize) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let commands = Arc::new(Mutex::new(Vec::new()));
        let mempool = Arc::new(Mutex::new(script.mempool.clone()));
        let thread_commands = commands.clone();
        std::thread::spawn(move || {
            for _ in 0..connections {
                let Ok((stream, _)) = listener.accept() else {
                    return;
                };
                let _ = serve(stream, &script, &mempool, &thread_commands);
            }
        });
        FakePeer { addr, commands }
    }

    pub fn commands(&self) -> Vec<String> {
        self.commands.lock().unwrap().clone()
    }
}

struct Wire {
    stream: TcpStream,
    buf: Vec<u8>,
}

impl Wire {
    fn send(&mut self, message: NetworkMessage) -> std::io::Result<()> {
        let raw = RawNetworkMessage::new(Network::Regtest.default_network_magic(), message);
        self.stream.write_all(&encode::serialize(&raw))
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
}

fn serve(
    stream: TcpStream,
    script: &Script,
    mempool: &Mutex<Vec<Vec<u8>>>,
    commands: &Mutex<Vec<String>>,
) -> std::io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(60)))?;
    let mut wire = Wire {
        stream,
        buf: Vec::new(),
    };
    // Handshake, Bitcoin Core style.
    let NetworkMessage::Version(_) = wire.recv()? else {
        return Ok(());
    };
    wire.send(NetworkMessage::Version(VersionMessage {
        version: ProtocolVersion::WTXID_RELAY_VERSION,
        services: ServiceFlags::NETWORK | ServiceFlags::WITNESS,
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
        start_height: 0,
        relay: true,
    }))?;
    wire.send(NetworkMessage::WtxidRelay)?;
    wire.send(NetworkMessage::Verack)?;
    loop {
        if let NetworkMessage::Verack = wire.recv()? {
            break;
        }
    }
    wire.send(NetworkMessage::Ping(1))?;
    wire.send(NetworkMessage::FeeFilter(
        bitcoin_rev::FeeRate::from_sat_per_kvb(script.fee_filter),
    ))?;

    let wtxid_of = |raw: &[u8]| {
        let tx: bitcoin::Transaction = bitcoin::consensus::encode::deserialize(raw).unwrap();
        (tx.compute_txid(), tx.compute_wtxid())
    };
    loop {
        let message = wire.recv()?;
        commands.lock().unwrap().push(message.command().to_string());
        match message {
            NetworkMessage::Ping(nonce) => wire.send(NetworkMessage::Pong(nonce))?,
            NetworkMessage::GetHeaders(request) if request.locator_hashes.is_empty() => {
                if let Some(header) = script
                    .headers
                    .iter()
                    .find(|h| h.block_hash() == request.stop_hash)
                {
                    wire.send(NetworkMessage::Headers(HeadersMessage(vec![*header])))?;
                }
            }
            NetworkMessage::Inv(items) if script.request_announced => {
                wire.send(NetworkMessage::GetData(items))?;
            }
            NetworkMessage::GetData(items) => {
                let mut missing = Vec::new();
                for item in items.0 {
                    let found = mempool.lock().unwrap().iter().find_map(|raw| {
                        let (txid, wtxid) = wtxid_of(raw);
                        super::p2p::inventory_matches(&item, txid, wtxid).then(|| raw.clone())
                    });
                    match found {
                        Some(raw) => {
                            wire.send(NetworkMessage::Tx(encode::deserialize(&raw).unwrap()))?
                        }
                        None => missing.push(item),
                    }
                }
                if !missing.is_empty() {
                    wire.send(NetworkMessage::NotFound(InventoryPayload(missing)))?;
                }
            }
            NetworkMessage::Tx(tx) => match script.policy {
                TxPolicy::Accept => mempool.lock().unwrap().push(encode::serialize(&tx)),
                TxPolicy::Ignore => {}
                TxPolicy::Disconnect => return Ok(()),
                TxPolicy::Orphan => {
                    let parent = tx.inputs[0].previous_output.txid;
                    wire.send(NetworkMessage::GetData(InventoryPayload(vec![
                        Inventory::WitnessTransaction(parent),
                    ])))?;
                }
            },
            _ => {}
        }
    }
}

/// A regtest-style header that is not on any real chain.
pub fn header(nonce: u32) -> bitcoin_rev::block::Header {
    let genesis = bitcoin::constants::genesis_block(bitcoin::Network::Regtest).header;
    let mut header: bitcoin_rev::block::Header =
        encode::deserialize(&bitcoin::consensus::encode::serialize(&genesis)).unwrap();
    header.nonce = nonce;
    header
}
