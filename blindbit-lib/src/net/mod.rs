//! Where friglet's Bitcoin P2P connections go: the user's own node, or peers
//! of the network found through DNS seeds and address gossip.
//!
//! - [`PeerSource`] hands out the peer for each connection and learns from
//!   how it went ([`PeerEvent`]). With an own node it always names that node
//!   and never looks anything up; otherwise it keeps an address book
//!   ([`pool`]) seeded from the network's DNS seeds ([`seeds`]).
//! - [`Dialer`] opens the TCP connection: directly, or through a SOCKS5
//!   proxy such as Tor ([`socks5`]), below every P2P protocol on top of it.
//!   Through a proxy nothing is looked up locally: host names, the own
//!   node's and the seeds', go to the proxy as names.

mod dialer;
pub(crate) mod pool;
#[cfg(test)]
mod pool_tests;
#[cfg(test)]
mod proxy_tests;
mod seeds;
mod socks5;
#[cfg(any(test, feature = "test-util"))]
pub mod testing;

use std::collections::hash_map::RandomState;
use std::fmt;
use std::hash::{BuildHasher, Hasher};
use std::net::{IpAddr, SocketAddr};

use bitcoin::p2p::address::{AddrV2, AddrV2Message};
use bitcoin::p2p::message::NetworkMessage;

pub use dialer::{Dialer, PROXY_CONNECT_TIMEOUT};
pub use pool::{NoPeers, PeerEvent, PeerPool, PeerSource};
pub use seeds::Seeds;
#[cfg(test)]
pub(crate) use seeds::lookups::asked as seeds_asked;
pub use socks5::{Socks5Error, is_proxy_down};

/// The user agent of every P2P connection friglet opens, block downloads and
/// the Electrum server's own peer alike, so a node sees one client. It is the
/// one the previous P2P library (2140-dev/bitcoin-p2p) sent, kept so nodes
/// see the same client as before.
pub const USER_AGENT: &str = "/SwiftSync:0.1.0/";

/// The host part of a peer address.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PeerHost {
    Ip(IpAddr),
    /// A host name, resolved by the [`Dialer`] when it connects. Only an own
    /// node is named this way; discovered peers are always addresses.
    Name(String),
}

/// A peer's address: host and port.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PeerAddr {
    pub host: PeerHost,
    pub port: u16,
}

impl PeerAddr {
    /// The socket address, unless the host is a name.
    pub fn socket_addr(&self) -> Option<SocketAddr> {
        match &self.host {
            PeerHost::Ip(ip) => Some(SocketAddr::new(*ip, self.port)),
            PeerHost::Name(_) => None,
        }
    }

    pub fn ip(&self) -> Option<IpAddr> {
        match &self.host {
            PeerHost::Ip(ip) => Some(*ip),
            PeerHost::Name(_) => None,
        }
    }

    pub(crate) fn is_ipv6(&self) -> bool {
        matches!(self.host, PeerHost::Ip(IpAddr::V6(_)))
    }
}

impl From<SocketAddr> for PeerAddr {
    fn from(addr: SocketAddr) -> Self {
        // An IPv4-mapped IPv6 address is the IPv4 peer it names.
        let ip = match addr.ip() {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4),
            v4 => v4,
        };
        Self {
            host: PeerHost::Ip(ip),
            port: addr.port(),
        }
    }
}

impl fmt::Display for PeerAddr {
    /// `1.2.3.4:8333`, `[2001:db8::1]:8333`, `node.example:8333`: the
    /// `SocketAddr` spelling for addresses.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.host {
            PeerHost::Ip(ip) => SocketAddr::new(*ip, self.port).fmt(f),
            PeerHost::Name(name) => write!(f, "{name}:{}", self.port),
        }
    }
}

/// What a connection is for; [`PeerSource::next`] picks peers accordingly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Purpose {
    /// Downloading a full block: the peer that served the last one first.
    Block,
    /// Block headers for the Electrum server.
    Header,
    /// Relaying a transaction, or asking a mempool about one: never the
    /// peer blocks are downloaded from, so it does not see both.
    Relay,
}

/// The addresses an `addr` or `addrv2` message gossips, in `addrv2` form;
/// `None` for any other message.
pub(crate) fn gossiped_addrs(message: &NetworkMessage) -> Option<Vec<AddrV2Message>> {
    match message {
        NetworkMessage::AddrV2(list) => Some(list.clone()),
        NetworkMessage::Addr(list) => Some(
            list.iter()
                .filter_map(|(time, address)| {
                    let socket = address.socket_addr().ok()?;
                    let addr = match socket.ip() {
                        IpAddr::V4(ip) => AddrV2::Ipv4(ip),
                        IpAddr::V6(ip) => AddrV2::Ipv6(ip),
                    };
                    Some(AddrV2Message {
                        time: *time,
                        services: address.services,
                        addr,
                        port: socket.port(),
                    })
                })
                .collect(),
        ),
        _ => None,
    }
}

/// A random number, different on every call (not for keys).
pub(crate) fn random_u64() -> u64 {
    let mut hasher = RandomState::new().build_hasher();
    hasher.write_u128(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default(),
    );
    hasher.finish()
}
