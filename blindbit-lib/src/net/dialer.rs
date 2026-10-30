//! Opening the TCP connection under every P2P connection.

use std::fmt;
use std::io;
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;

use super::{PeerAddr, PeerHost, socks5};

/// The least time a connection through a proxy gets: Tor builds a circuit
/// and its exit then connects to the peer.
pub const PROXY_CONNECT_TIMEOUT: Duration = Duration::from_secs(20);

/// How a P2P connection reaches its peer. Every P2P connection friglet opens
/// goes through one, so a proxy slots in here without touching the
/// protocols on top.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum Dialer {
    /// A direct TCP connection; a host name is resolved locally.
    #[default]
    Direct,
    /// Through a SOCKS5 proxy (Tor), every connection: never directly, even
    /// when the proxy is down. A host name goes to the proxy unresolved, so
    /// this computer looks nothing up. Each connection logs in with
    /// credentials of its own, so Tor gives it a circuit of its own.
    Socks5 { proxy: SocketAddr },
}

impl Dialer {
    /// Connect to `peer`, waiting at most `timeout` per address tried (at
    /// least [`PROXY_CONNECT_TIMEOUT`] through a proxy). Blocking: async
    /// callers run it on a blocking thread.
    ///
    /// Through a proxy, an error for which [`super::is_proxy_down`] holds
    /// means the proxy itself failed, not the peer.
    pub fn connect(&self, peer: &PeerAddr, timeout: Duration) -> io::Result<TcpStream> {
        match self {
            Self::Direct => match &peer.host {
                PeerHost::Ip(ip) => {
                    TcpStream::connect_timeout(&SocketAddr::new(*ip, peer.port), timeout)
                }
                PeerHost::Name(name) => {
                    // IPv4 first: it works on every host, while an IPv6
                    // address is useless on the many without IPv6 routing.
                    let mut addrs: Vec<SocketAddr> =
                        (name.as_str(), peer.port).to_socket_addrs()?.collect();
                    addrs.sort_by_key(|addr| addr.is_ipv6());
                    let mut last = None;
                    for addr in addrs {
                        match TcpStream::connect_timeout(&addr, timeout) {
                            Ok(stream) => return Ok(stream),
                            Err(e) => last = Some(e),
                        }
                    }
                    Err(last.unwrap_or_else(|| {
                        io::Error::new(io::ErrorKind::NotFound, format!("{name} has no addresses"))
                    }))
                }
            },
            Self::Socks5 { proxy } => {
                socks5::connect(*proxy, peer, timeout.max(PROXY_CONNECT_TIMEOUT))
            }
        }
    }

    /// The proxy every connection goes through, if any.
    pub fn proxy(&self) -> Option<SocketAddr> {
        match self {
            Self::Direct => None,
            Self::Socks5 { proxy } => Some(*proxy),
        }
    }
}

impl fmt::Display for Dialer {
    /// "direct", "through p2p_proxy 127.0.0.1:9050".
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Direct => f.write_str("direct"),
            Self::Socks5 { proxy } => write!(f, "through p2p_proxy {proxy}"),
        }
    }
}
