//! Opening the TCP connection under every P2P connection.

use std::fmt;
use std::io;
use std::net::{Shutdown, SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::{Arc, Mutex};
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
    /// callers use [`Self::open`].
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

    /// [`Self::connect`] for async callers, and cancellable: dropping the
    /// future abandons the connection at once. A direct connection opens on
    /// the async runtime (a host name is looked up on a blocking thread);
    /// one through the proxy runs on a blocking thread whose socket is shut
    /// down when the future is dropped, which ends its wait for the proxy.
    pub async fn open(&self, peer: &PeerAddr, timeout: Duration) -> io::Result<TcpStream> {
        match self {
            Self::Direct => open_direct(peer, timeout).await,
            Self::Socks5 { proxy } => {
                let pending = Arc::new(Mutex::new(Pending::default()));
                let mut abandon = AbandonOnDrop(Some(pending.clone()));
                let (proxy, target) = (*proxy, peer.clone());
                let timeout = timeout.max(PROXY_CONNECT_TIMEOUT);
                let connect = tokio::task::spawn_blocking(move || {
                    socks5::connect_watched(proxy, &target, timeout, |socket| {
                        let mut pending = pending.lock().unwrap_or_else(|e| e.into_inner());
                        if pending.abandoned {
                            return Err(io::Error::new(
                                io::ErrorKind::Interrupted,
                                "the connection was abandoned",
                            ));
                        }
                        pending.socket = Some(socket.try_clone()?);
                        Ok(())
                    })
                });
                let connected = connect
                    .await
                    .map_err(|e| io::Error::other(format!("the connect task failed: {e}")))?;
                abandon.0 = None;
                connected
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

/// A direct connection opened on the async runtime, so dropping the future
/// abandons it: the same addresses, order and timeout as
/// [`Dialer::connect`].
async fn open_direct(peer: &PeerAddr, timeout: Duration) -> io::Result<TcpStream> {
    let addrs: Vec<SocketAddr> = match &peer.host {
        PeerHost::Ip(ip) => vec![SocketAddr::new(*ip, peer.port)],
        PeerHost::Name(name) => {
            // IPv4 first, as in `Dialer::connect`.
            let mut addrs: Vec<SocketAddr> = tokio::net::lookup_host((name.as_str(), peer.port))
                .await?
                .collect();
            addrs.sort_by_key(|addr| addr.is_ipv6());
            if addrs.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("{name} has no addresses"),
                ));
            }
            addrs
        }
    };
    let mut last = None;
    for addr in addrs {
        match tokio::time::timeout(timeout, tokio::net::TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => {
                let stream = stream.into_std()?;
                stream.set_nonblocking(false)?;
                return Ok(stream);
            }
            Ok(Err(e)) => last = Some(e),
            // What `TcpStream::connect_timeout` says.
            Err(_) => {
                last = Some(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "connection timed out",
                ))
            }
        }
    }
    Err(last.expect("at least one address"))
}

/// The socket of a connect running on a blocking thread, once it has one,
/// and whether its async caller has stopped waiting.
#[derive(Default)]
struct Pending {
    abandoned: bool,
    socket: Option<TcpStream>,
}

/// Abandons a pending connect when dropped (unless disarmed): its socket is
/// shut down, which ends any read or write blocked on it.
struct AbandonOnDrop(Option<Arc<Mutex<Pending>>>);

impl Drop for AbandonOnDrop {
    fn drop(&mut self) {
        if let Some(pending) = self.0.take() {
            let mut pending = pending.lock().unwrap_or_else(|e| e.into_inner());
            pending.abandoned = true;
            if let Some(socket) = pending.socket.take() {
                let _ = socket.shutdown(Shutdown::Both);
            }
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
