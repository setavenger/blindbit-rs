//! Opening the TCP connection under every P2P connection.

use std::io;
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;

use super::{PeerAddr, PeerHost};

/// How a P2P connection reaches its peer. Every P2P connection friglet opens
/// goes through one, so a proxy can be added here without touching the
/// protocols on top.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum Dialer {
    /// A direct TCP connection; a host name is resolved locally.
    #[default]
    Direct,
}

impl Dialer {
    /// Connect to `peer`, waiting at most `timeout` per address tried.
    /// Blocking: async callers run it on a blocking thread.
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
        }
    }
}
