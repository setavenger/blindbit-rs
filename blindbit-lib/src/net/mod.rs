//! Where friglet's Bitcoin P2P connections go: the user's own node, or peers
//! of the network found through DNS seeds and address gossip.
//!
//! - [`PeerSource`] hands out the peer for each connection and learns from
//!   how it went ([`PeerEvent`]). With an own node it always names that node
//!   and never looks anything up; otherwise it keeps an address book
//!   ([`pool`]) seeded from the network's DNS seeds ([`seeds`]).
//! - [`Dialer`] opens the TCP connection, so a proxy can slot in below every
//!   P2P protocol on top of it.

mod dialer;
pub(crate) mod pool;
#[cfg(test)]
mod pool_tests;
mod seeds;

use std::fmt;
use std::net::{IpAddr, SocketAddr};

pub use dialer::Dialer;
pub use pool::{NoPeers, PeerEvent, PeerPool, PeerSource};
pub use seeds::Seeds;
#[cfg(test)]
pub(crate) use seeds::lookups::asked as seeds_asked;

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
