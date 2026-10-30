//! Minimal blocking Bitcoin P2P client for the Electrum server.
//!
//! The Electrum server needs three things from its P2P peer that the
//! scanner's block-fetch connection does not provide:
//!
//! - **Single headers by hash.** `getheaders` with an empty locator makes
//!   Bitcoin Core answer with exactly the header of `hash_stop`: 80 bytes,
//!   instead of downloading the whole block to read its header.
//! - **Mempool membership.** `getdata` for a transaction is answered with the
//!   transaction when it is in the peer's mempool and with `notfound` when it
//!   is not. Bitcoin Core only serves mempool transactions to peers that asked
//!   for transaction relay in their `version` message; the `bitcoin-p2p`
//!   crate's handshake always sends `relay = false`, so this module performs
//!   its own handshake (with bitcoin's `p2p` message types).
//! - **Announce / request.** A broadcast announces the transaction with `inv`
//!   and hands it over when the peer asks for it with `getdata`.
//!
//! Framing is buffered here: a socket read timeout only means "nothing yet",
//! it never loses a partially read message.

use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bitcoin::block::Header;
use bitcoin::consensus::encode;
use bitcoin::p2p::message::{CommandString, NetworkMessage, RawNetworkMessage};
use bitcoin::p2p::message_blockdata::{GetHeadersMessage, Inventory};
use bitcoin::p2p::message_network::VersionMessage;
use bitcoin::p2p::{Address, Magic, ServiceFlags};
use bitcoin::{BlockHash, Network, Txid, Wtxid};

// The scanner's block downloads send the same user agent, so friglet does
// not present two different fingerprints to the same peer.
use blindbit_lib::net::{Dialer, PeerAddr, USER_AGENT};
use blindbit_lib::scanner::PeerInfo;

/// BIP 339's `WTXID_RELAY_VERSION`: the protocol version friglet speaks.
const WTXID_RELAY_VERSION: u32 = 70016;

/// How long one socket read may block before the caller's deadline is
/// checked again.
const READ_POLL: Duration = Duration::from_millis(200);

/// How long to wait for the peer to settle after the handshake; see
/// [`Peer::wait_until_settled`].
pub const SETTLE_WAIT: Duration = Duration::from_secs(2);

/// Bitcoin Core's `MAX_PROTOCOL_MESSAGE_LENGTH` is 4 MB; blocks are larger
/// on the wire only through `MAX_SIZE` (32 MB). Anything above is garbage.
const MAX_PAYLOAD: usize = 32 * 1024 * 1024;

#[derive(Debug)]
pub enum P2pError {
    Io(io::Error),
    /// The peer closed the connection.
    Closed,
    /// No answer before the deadline.
    Timeout(&'static str),
    Protocol(String),
}

impl std::fmt::Display for P2pError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            P2pError::Io(error) => write!(f, "P2P I/O error: {error}"),
            P2pError::Closed => write!(f, "the P2P peer closed the connection"),
            P2pError::Timeout(what) => write!(f, "timed out waiting for {what} from the P2P peer"),
            P2pError::Protocol(message) => write!(f, "P2P protocol error: {message}"),
        }
    }
}

impl std::error::Error for P2pError {}

impl From<io::Error> for P2pError {
    fn from(error: io::Error) -> Self {
        match error.kind() {
            io::ErrorKind::UnexpectedEof
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::BrokenPipe => P2pError::Closed,
            _ => P2pError::Io(error),
        }
    }
}

pub fn random_u64() -> u64 {
    let mut hasher = RandomState::new().build_hasher();
    hasher.write_u128(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default(),
    );
    hasher.finish()
}

/// The `version` message's address fields: 127.0.0.1:1, so the peer learns
/// neither friglet's address nor the one friglet sees for it. The same value
/// the scanner's block-fetch connections send (kernel-node bitcoin-p2p has no
/// override), so both stacks look alike to a peer.
fn useless_address() -> Address {
    Address::new(
        &SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1),
        ServiceFlags::NONE,
    )
}

/// One open, handshaken P2P connection.
pub struct Peer {
    stream: TcpStream,
    magic: Magic,
    buf: Vec<u8>,
    addr: PeerAddr,
    /// What the peer said about itself in its `version` message: services,
    /// chain height, and whether it relays transactions to friglet (BIP 37
    /// `fRelay`; false for a blocks-only node).
    info: PeerInfo,
    their_relay: bool,
    /// Both sides sent `wtxidrelay` (BIP 339): transactions are announced
    /// and requested by wtxid.
    wtxid_relay: bool,
    /// The peer's first `ping` arrived. Bitcoin Core sends it from the same
    /// `SendMessages` pass that starts this connection's transaction
    /// announcement schedule, so mempool `getdata` answers are meaningful
    /// from here on.
    pinged: bool,
    /// The latest `feefilter` the peer sent, in sat/kvB: the lowest fee rate
    /// its mempool currently accepts (at least its minimum relay fee).
    fee_filter: Option<u64>,
}

impl Peer {
    /// Connect and complete the version handshake. `relay` is the BIP 37
    /// `fRelay` flag; it must be true for mempool `getdata` to work.
    pub fn connect(
        dialer: &Dialer,
        addr: &PeerAddr,
        network: Network,
        relay: bool,
        timeout: Duration,
    ) -> Result<Self, P2pError> {
        let stream = dialer.connect(addr, timeout)?;
        stream.set_read_timeout(Some(READ_POLL))?;
        stream.set_write_timeout(Some(timeout))?;
        stream.set_nodelay(true)?;
        let mut peer = Peer {
            stream,
            magic: network.magic(),
            buf: Vec::new(),
            addr: addr.clone(),
            info: PeerInfo {
                services: ServiceFlags::NONE,
                height: 0,
            },
            their_relay: false,
            wtxid_relay: false,
            pinged: false,
            fee_filter: None,
        };
        peer.handshake(relay, Instant::now() + timeout)?;
        Ok(peer)
    }

    pub fn addr(&self) -> &PeerAddr {
        &self.addr
    }

    /// What the peer said about itself in its `version` message.
    pub fn info(&self) -> PeerInfo {
        self.info
    }

    /// Whether the peer relays transactions to friglet (its `version`
    /// message's `fRelay`); a blocks-only node does not.
    pub fn relays(&self) -> bool {
        self.their_relay
    }

    /// The peer's advertised mempool minimum fee rate in sat/kvB, if it sent
    /// one. Bitcoin Core sends it right after the handshake and then about
    /// every ten minutes; it is randomly rounded by up to ~10% for privacy.
    pub fn fee_filter(&self) -> Option<u64> {
        self.fee_filter
    }

    fn handshake(&mut self, relay: bool, deadline: Instant) -> Result<(), P2pError> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or_default();
        self.send(NetworkMessage::Version(VersionMessage {
            version: WTXID_RELAY_VERSION,
            services: ServiceFlags::NONE,
            timestamp,
            receiver: useless_address(),
            sender: useless_address(),
            nonce: random_u64(),
            user_agent: USER_AGENT.to_string(),
            start_height: 0,
            relay,
        }))?;

        let their_version = loop {
            match self.recv_until(deadline)? {
                Some(NetworkMessage::Version(version)) => break version,
                Some(_) => continue,
                None => return Err(P2pError::Timeout("the version message")),
            }
        };
        self.info = PeerInfo {
            services: their_version.services,
            height: their_version.start_height,
        };
        self.their_relay = their_version.relay;
        let we_sent_wtxidrelay = their_version.version >= WTXID_RELAY_VERSION;
        // BIP 339: wtxidrelay must come between version and verack.
        if we_sent_wtxidrelay {
            self.send(NetworkMessage::WtxidRelay)?;
        }
        self.send(NetworkMessage::Verack)?;

        let mut they_sent_wtxidrelay = false;
        loop {
            match self.recv_until(deadline)? {
                Some(NetworkMessage::Verack) => break,
                Some(NetworkMessage::WtxidRelay) => they_sent_wtxidrelay = true,
                Some(_) => continue,
                None => return Err(P2pError::Timeout("verack")),
            }
        }
        self.wtxid_relay = we_sent_wtxidrelay && they_sent_wtxidrelay;
        Ok(())
    }

    pub fn send(&mut self, message: NetworkMessage) -> Result<(), P2pError> {
        let raw = RawNetworkMessage::new(self.magic, message);
        self.stream.write_all(&encode::serialize(&raw))?;
        Ok(())
    }

    /// Next message, or `None` once `deadline` passes. Pings are answered
    /// here (and still returned).
    pub fn recv_until(&mut self, deadline: Instant) -> Result<Option<NetworkMessage>, P2pError> {
        loop {
            if let Some(message) = self.parse_buffered()? {
                match &message {
                    NetworkMessage::Ping(nonce) => {
                        self.pinged = true;
                        self.send(NetworkMessage::Pong(*nonce))?;
                    }
                    NetworkMessage::FeeFilter(rate) => {
                        // A rate outside 0..=u32::MAX sat/kvB says "relay
                        // nothing"; it reads as the largest fee rate.
                        self.fee_filter =
                            Some(u32::try_from(*rate).map_or(u64::MAX / 1000, u64::from));
                    }
                    _ => {}
                }
                return Ok(Some(message));
            }
            if Instant::now() >= deadline {
                return Ok(None);
            }
            let mut chunk = [0u8; 64 * 1024];
            match self.stream.read(&mut chunk) {
                Ok(0) => return Err(P2pError::Closed),
                Ok(n) => self.buf.extend_from_slice(&chunk[..n]),
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock
                            | io::ErrorKind::TimedOut
                            | io::ErrorKind::Interrupted
                    ) => {}
                Err(error) => return Err(error.into()),
            }
        }
    }

    /// Decode one complete frame from the buffer, if there is one. A frame
    /// whose payload does not decode is dropped, not fatal: the length
    /// prefix still tells where the next frame starts.
    fn parse_buffered(&mut self) -> Result<Option<NetworkMessage>, P2pError> {
        loop {
            if self.buf.len() < 24 {
                return Ok(None);
            }
            // The v1 message header: magic, command, payload length, checksum.
            if !self.buf[4..16].is_ascii() {
                return Err(P2pError::Protocol(
                    "bad message header: the command is not ASCII".to_string(),
                ));
            }
            let magic = Magic::from_bytes(self.buf[..4].try_into().expect("4 bytes"));
            if magic != self.magic {
                return Err(P2pError::Protocol(format!(
                    "unexpected network magic {magic:?}"
                )));
            }
            let command: CommandString = encode::deserialize(&self.buf[4..16])
                .map_err(|error| P2pError::Protocol(format!("bad message header: {error}")))?;
            let len = u32::from_le_bytes(self.buf[16..20].try_into().expect("4 bytes")) as usize;
            if len > MAX_PAYLOAD {
                return Err(P2pError::Protocol(format!("oversized {len}-byte message")));
            }
            if self.buf.len() < 24 + len {
                return Ok(None);
            }
            let decoded = encode::deserialize::<RawNetworkMessage>(&self.buf[..24 + len]);
            self.buf.drain(..24 + len);
            match decoded {
                Ok(raw) => return Ok(Some(raw.into_payload())),
                Err(error) => {
                    tracing::debug!(
                        peer = %self.addr,
                        command = %command,
                        error = %error,
                        "skipping undecodable P2P message"
                    );
                }
            }
        }
    }

    /// Wait (up to `deadline`) for the peer's first ping and fee filter;
    /// see `pinged`. Both normally arrive within milliseconds of the
    /// handshake.
    pub fn wait_until_settled(&mut self, deadline: Instant) -> Result<(), P2pError> {
        while !self.pinged || self.fee_filter.is_none() {
            if self.recv_until(deadline)?.is_none() {
                break;
            }
        }
        Ok(())
    }

    /// Is this transaction in the peer's mempool? Asks with `getdata`, which
    /// Bitcoin Core answers with the transaction or with `notfound`. Only
    /// meaningful on a `relay = true` connection that has settled.
    /// `on_other` sees every other message that arrives meanwhile.
    pub fn mempool_has(
        &mut self,
        txid: Txid,
        wtxid: Wtxid,
        deadline: Instant,
        mut on_other: impl FnMut(&mut Self, NetworkMessage) -> Result<(), P2pError>,
    ) -> Result<bool, P2pError> {
        self.send_getdata(self.tx_inventory(txid, wtxid))?;
        loop {
            match self.recv_until(deadline)? {
                Some(NetworkMessage::Tx(tx)) if tx.compute_txid() == txid => {
                    return Ok(true);
                }
                Some(NetworkMessage::NotFound(items))
                    if items
                        .iter()
                        .any(|item| inventory_matches(item, txid, wtxid)) =>
                {
                    return Ok(false);
                }
                Some(message) => on_other(self, message)?,
                None => return Err(P2pError::Timeout("a mempool answer")),
            }
        }
    }

    /// The header of block `hash`, `None` when the peer does not know the
    /// block. Only a header whose hash is `hash` is returned. One round trip:
    /// the `getheaders` is answered before the trailing ping's pong.
    pub fn header_by_hash(
        &mut self,
        hash: BlockHash,
        deadline: Instant,
    ) -> Result<Option<Header>, P2pError> {
        self.send(NetworkMessage::GetHeaders(GetHeadersMessage {
            version: WTXID_RELAY_VERSION,
            locator_hashes: Vec::new(),
            stop_hash: hash,
        }))?;
        let mut found = Vec::new();
        self.sync_with_ping(deadline, "block headers", |message| {
            if let NetworkMessage::Headers(headers) = message {
                found.extend(headers.iter().copied());
            }
        })?;
        Ok(found.into_iter().find(|header| header.block_hash() == hash))
    }

    /// Wait until the peer has processed everything sent so far: it answers
    /// messages in order, so its pong to a new ping comes after them. Closing
    /// a socket with unread input resets it, which can make the peer drop
    /// what it has not read yet; call this before closing after a hand-over.
    pub fn flush(&mut self, deadline: Instant) -> Result<(), P2pError> {
        self.sync_with_ping(deadline, "a pong", |_| {})
    }

    /// Send a ping and feed every message to `on_message` until its pong.
    fn sync_with_ping(
        &mut self,
        deadline: Instant,
        what: &'static str,
        mut on_message: impl FnMut(&NetworkMessage),
    ) -> Result<(), P2pError> {
        let nonce = random_u64();
        self.send(NetworkMessage::Ping(nonce))?;
        loop {
            match self.recv_until(deadline)? {
                Some(NetworkMessage::Pong(n)) if n == nonce => return Ok(()),
                Some(message) => on_message(&message),
                None => return Err(P2pError::Timeout(what)),
            }
        }
    }

    /// The inventory item this peer uses for a transaction.
    pub fn tx_inventory(&self, txid: Txid, wtxid: Wtxid) -> Inventory {
        if self.wtxid_relay {
            Inventory::WTx(wtxid)
        } else {
            Inventory::Transaction(txid)
        }
    }

    pub fn send_getdata(&mut self, inventory: Inventory) -> Result<(), P2pError> {
        self.send(NetworkMessage::GetData(vec![inventory]))
    }
}

/// Does an inventory item name this transaction (by txid or wtxid)?
pub fn inventory_matches(item: &Inventory, txid: Txid, wtxid: Wtxid) -> bool {
    match item {
        Inventory::Transaction(id) | Inventory::WitnessTransaction(id) => *id == txid,
        Inventory::WTx(id) => *id == wtxid,
        _ => false,
    }
}
