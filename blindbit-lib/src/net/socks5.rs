//! A blocking SOCKS5 client (RFC 1928, with RFC 1929 username/password
//! login) for [`super::Dialer::Socks5`]: P2P connections through Tor.
//!
//! - Every connection offers "no authentication" and a username/password
//!   login with credentials random for that connection. Tor isolates streams
//!   by those credentials (`IsolateSOCKSAuth`, on by default), so each
//!   connection gets a circuit of its own, as with Bitcoin Core's
//!   `-proxyrandomize`: one exit relay does not see all of friglet's peers.
//! - A host name goes to the proxy as a name (`ATYP` 3): the proxy (Tor's
//!   exit relay) resolves it, never this computer's resolver.
//! - A failure says whether the proxy itself failed ([`is_proxy_down`]: no
//!   peer can be reached until it is fixed) or only the connection to the
//!   peer it was asked for.

use std::fmt;
use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::time::{Duration, Instant};

use super::{PeerAddr, PeerHost};

const VERSION: u8 = 0x05;
const NO_AUTH: u8 = 0x00;
const USER_PASS: u8 = 0x02;
const NO_ACCEPTABLE_METHOD: u8 = 0xff;
/// RFC 1929's version of the username/password sub-negotiation.
const USER_PASS_VERSION: u8 = 0x01;
const CONNECT: u8 = 0x01;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

/// A connection through the SOCKS5 proxy failed. Carried inside the
/// `io::Error` that [`super::Dialer::connect`] returns.
#[derive(Debug)]
pub struct Socks5Error {
    proxy_down: bool,
    message: String,
}

impl fmt::Display for Socks5Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for Socks5Error {}

/// Did the proxy itself fail (not reachable, not a SOCKS5 proxy, refused
/// the login), rather than the peer it was asked to connect to? Then every
/// other peer fails the same way until the proxy is fixed, and the failure
/// says nothing about the peer.
pub fn is_proxy_down(error: &io::Error) -> bool {
    error
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<Socks5Error>())
        .is_some_and(|e| e.proxy_down)
}

/// The proxy failed. The kinds are never the "connection closed" ones, so
/// callers that map those to "the peer hung up" keep this message.
fn proxy_failed(kind: io::ErrorKind, message: String) -> io::Error {
    io::Error::new(
        kind,
        Socks5Error {
            proxy_down: true,
            message,
        },
    )
}

/// The proxy works, but could not reach the peer.
fn peer_failed(kind: io::ErrorKind, message: String) -> io::Error {
    io::Error::new(
        kind,
        Socks5Error {
            proxy_down: false,
            message,
        },
    )
}

/// Connect to `target` through the SOCKS5 proxy at `proxy`, all of it
/// (proxy connection, login, the proxy's connection to the peer) within
/// `timeout`. The stream returned talks to the peer and has no timeouts
/// set.
pub(crate) fn connect(
    proxy: SocketAddr,
    target: &PeerAddr,
    timeout: Duration,
) -> io::Result<TcpStream> {
    let deadline = Instant::now() + timeout;
    let mut stream = TcpStream::connect_timeout(&proxy, timeout).map_err(|e| {
        proxy_failed(
            io::ErrorKind::ConnectionRefused,
            format!("cannot connect to p2p_proxy {proxy}: {e}"),
        )
    })?;
    let _ = stream.set_nodelay(true);
    let proxy_io = |e: io::Error| match e.kind() {
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => proxy_failed(
            io::ErrorKind::TimedOut,
            format!(
                "p2p_proxy {proxy} did not answer within {} s",
                timeout.as_secs()
            ),
        ),
        _ => proxy_failed(
            io::ErrorKind::Other,
            format!("p2p_proxy {proxy} is not a working SOCKS5 proxy: {e}"),
        ),
    };

    // Greeting: no authentication, or a username and password.
    set_deadline(&stream, deadline).map_err(proxy_io)?;
    stream
        .write_all(&[VERSION, 2, NO_AUTH, USER_PASS])
        .map_err(proxy_io)?;
    let mut choice = [0u8; 2];
    stream.read_exact(&mut choice).map_err(proxy_io)?;
    if choice[0] != VERSION {
        return Err(proxy_failed(
            io::ErrorKind::Other,
            format!("p2p_proxy {proxy} is not a SOCKS5 proxy"),
        ));
    }
    match choice[1] {
        NO_AUTH => {}
        USER_PASS => {
            set_deadline(&stream, deadline).map_err(proxy_io)?;
            log_in(&mut stream).map_err(proxy_io)?;
            let mut status = [0u8; 2];
            stream.read_exact(&mut status).map_err(proxy_io)?;
            if status[1] != 0 {
                return Err(proxy_failed(
                    io::ErrorKind::PermissionDenied,
                    format!("p2p_proxy {proxy} refused the login"),
                ));
            }
        }
        NO_ACCEPTABLE_METHOD => {
            return Err(proxy_failed(
                io::ErrorKind::PermissionDenied,
                format!(
                    "p2p_proxy {proxy} accepts neither no authentication nor a username and \
                     password"
                ),
            ));
        }
        other => {
            return Err(proxy_failed(
                io::ErrorKind::Other,
                format!(
                    "p2p_proxy {proxy} chose an authentication method it was not offered ({other})"
                ),
            ));
        }
    }

    // The request: CONNECT to the peer.
    let mut request = vec![VERSION, CONNECT, 0];
    match &target.host {
        PeerHost::Ip(IpAddr::V4(ip)) => {
            request.push(ATYP_IPV4);
            request.extend(ip.octets());
        }
        PeerHost::Ip(IpAddr::V6(ip)) => {
            request.push(ATYP_IPV6);
            request.extend(ip.octets());
        }
        PeerHost::Name(name) => {
            let len = u8::try_from(name.len())
                .ok()
                .filter(|len| *len > 0)
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("host name `{name}` is not 1 to 255 bytes long"),
                    )
                })?;
            request.push(ATYP_DOMAIN);
            request.push(len);
            request.extend(name.as_bytes());
        }
    }
    request.extend(target.port.to_be_bytes());
    set_deadline(&stream, deadline).map_err(proxy_io)?;
    stream.write_all(&request).map_err(proxy_io)?;

    // The reply, once the proxy has connected to the peer (or failed to).
    // Through Tor that takes a circuit and the exit's connection.
    let mut head = [0u8; 4];
    stream.read_exact(&mut head).map_err(|e| match e.kind() {
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => peer_failed(
            io::ErrorKind::TimedOut,
            format!(
                "p2p_proxy {proxy} did not connect to {target} within {} s",
                timeout.as_secs()
            ),
        ),
        _ => proxy_io(e),
    })?;
    if head[0] != VERSION {
        return Err(proxy_failed(
            io::ErrorKind::Other,
            format!("p2p_proxy {proxy} sent a reply that is not SOCKS5"),
        ));
    }
    if head[1] != 0 {
        let (kind, reason) = reply_error(head[1]);
        return Err(peer_failed(
            kind,
            format!(
                "p2p_proxy {proxy} could not connect to {target}: {reason} (SOCKS5 reply {})",
                head[1]
            ),
        ));
    }
    // The address the proxy connected from: read and dropped.
    let bound = match head[3] {
        ATYP_IPV4 => 4,
        ATYP_IPV6 => 16,
        ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).map_err(proxy_io)?;
            usize::from(len[0])
        }
        other => {
            return Err(proxy_failed(
                io::ErrorKind::Other,
                format!("p2p_proxy {proxy} sent an unknown address type ({other})"),
            ));
        }
    };
    let mut skip = vec![0u8; bound + 2];
    stream.read_exact(&mut skip).map_err(proxy_io)?;

    stream.set_read_timeout(None)?;
    stream.set_write_timeout(None)?;
    Ok(stream)
}

/// RFC 1929 login with a random username and password, new for every
/// connection, so Tor puts the connection on a circuit of its own.
fn log_in(stream: &mut TcpStream) -> io::Result<()> {
    let user = format!("{:016x}", super::random_u64());
    let password = format!("{:016x}", super::random_u64());
    let mut login = vec![USER_PASS_VERSION, user.len() as u8];
    login.extend(user.as_bytes());
    login.push(password.len() as u8);
    login.extend(password.as_bytes());
    stream.write_all(&login)
}

/// Bound the next reads and writes by `deadline`.
fn set_deadline(stream: &TcpStream, deadline: Instant) -> io::Result<()> {
    let left = deadline
        .saturating_duration_since(Instant::now())
        .max(Duration::from_millis(1));
    stream.set_read_timeout(Some(left))?;
    stream.set_write_timeout(Some(left))
}

/// What a SOCKS5 reply code (RFC 1928, and Tor's onion service codes)
/// means, and the `io::ErrorKind` that says so.
fn reply_error(code: u8) -> (io::ErrorKind, &'static str) {
    use io::ErrorKind as Kind;
    match code {
        0x01 => (Kind::Other, "the proxy failed"),
        0x02 => (Kind::PermissionDenied, "the proxy does not allow it"),
        0x03 => (Kind::NetworkUnreachable, "network unreachable"),
        0x04 => (Kind::HostUnreachable, "host unreachable or unknown"),
        0x05 => (Kind::ConnectionRefused, "connection refused"),
        0x06 => (Kind::TimedOut, "timed out"),
        0x07 => (Kind::Unsupported, "the proxy does not support CONNECT"),
        0x08 => (
            Kind::Unsupported,
            "the proxy does not support this address type",
        ),
        // Tor's extended errors for onion services (`ExtendedErrors`).
        0xf0 => (Kind::HostUnreachable, "onion service not found"),
        0xf1 => (Kind::HostUnreachable, "onion service descriptor is invalid"),
        0xf2 => (Kind::HostUnreachable, "onion service introduction failed"),
        0xf3 => (Kind::HostUnreachable, "onion service rendezvous failed"),
        0xf4 => (
            Kind::PermissionDenied,
            "onion service needs client authorization",
        ),
        0xf5 => (
            Kind::PermissionDenied,
            "onion service rejected the client authorization",
        ),
        0xf6 => (Kind::InvalidInput, "invalid onion address"),
        0xf7 => (Kind::TimedOut, "onion service introduction timed out"),
        _ => (Kind::Other, "unknown SOCKS5 error"),
    }
}

#[cfg(test)]
mod tests {
    use std::net::TcpListener;

    use super::*;
    use crate::net::testing::FakeSocks5;
    use crate::net::{Dialer, PeerHost};

    fn name(host: &str, port: u16) -> PeerAddr {
        PeerAddr {
            host: PeerHost::Name(host.to_string()),
            port,
        }
    }

    /// A listener that echoes one line back, standing in for a peer.
    fn echo() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                std::thread::spawn(move || {
                    let mut stream = stream;
                    let mut buf = [0u8; 64];
                    while let Ok(n) = stream.read(&mut buf) {
                        if n == 0 || stream.write_all(&buf[..n]).is_err() {
                            break;
                        }
                    }
                });
            }
        });
        addr
    }

    fn round_trip(stream: &mut TcpStream) {
        stream.write_all(b"ping").unwrap();
        let mut buf = [0u8; 4];
        stream.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"ping");
    }

    #[test]
    fn a_name_goes_to_the_proxy_unresolved_with_fresh_credentials_each_time() {
        let proxy = FakeSocks5::start();
        proxy.route("node.invalid", echo());
        let dialer = proxy.dialer();
        for _ in 0..2 {
            let mut stream = dialer
                .connect(&name("node.invalid", 8333), Duration::from_secs(5))
                .expect("connected through the proxy");
            round_trip(&mut stream);
        }
        let requests = proxy.requests();
        assert_eq!(requests.len(), 2);
        for request in &requests {
            assert_eq!(request.methods, vec![NO_AUTH, USER_PASS]);
            assert_eq!(request.target, name("node.invalid", 8333));
            assert!(request.credentials.is_some());
        }
        assert_ne!(
            requests[0].credentials, requests[1].credentials,
            "each connection logs in with its own credentials (its own Tor circuit)"
        );
    }

    #[test]
    fn ip_addresses_are_sent_as_addresses() {
        let proxy = FakeSocks5::start();
        let peer = echo();
        let mut stream = proxy
            .dialer()
            .connect(&peer.into(), Duration::from_secs(5))
            .expect("connected through the proxy");
        round_trip(&mut stream);
        // IPv6: the proxy refuses, but the request says which address.
        proxy.refuse_with(0x03);
        let v6: SocketAddr = "[2001:db8::1]:8333".parse().unwrap();
        let err = proxy
            .dialer()
            .connect(&v6.into(), Duration::from_secs(5))
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NetworkUnreachable);
        let targets: Vec<PeerAddr> = proxy.requests().into_iter().map(|r| r.target).collect();
        assert_eq!(targets, vec![peer.into(), v6.into()]);
    }

    #[test]
    fn reply_codes_become_readable_errors_about_the_peer() {
        let proxy = FakeSocks5::start();
        for (code, kind, words) in [
            (0x05, io::ErrorKind::ConnectionRefused, "connection refused"),
            (0x04, io::ErrorKind::HostUnreachable, "host unreachable"),
            (0x02, io::ErrorKind::PermissionDenied, "does not allow"),
            (
                0xf0,
                io::ErrorKind::HostUnreachable,
                "onion service not found",
            ),
        ] {
            proxy.refuse_with(code);
            let err = proxy
                .dialer()
                .connect(&name("peer.invalid", 8333), Duration::from_secs(5))
                .unwrap_err();
            let message = err.to_string();
            assert_eq!(err.kind(), kind, "{message}");
            assert!(!is_proxy_down(&err), "{message}");
            for expected in ["p2p_proxy", "could not connect to peer.invalid:8333", words] {
                assert!(message.contains(expected), "{expected:?} in {message}");
            }
        }
    }

    #[test]
    fn a_proxy_that_is_down_or_not_socks5_is_the_proxy_failing() {
        // Nothing listens on port 1, and no parallel test can take it.
        let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let err = Dialer::Socks5 { proxy: addr }
            .connect(&name("node.invalid", 8333), Duration::from_secs(5))
            .unwrap_err();
        assert!(is_proxy_down(&err));
        assert!(
            err.to_string()
                .contains(&format!("cannot connect to p2p_proxy {addr}")),
            "{err}"
        );

        // Something else answers: an HTTP server.
        let http = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = http.local_addr().unwrap();
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = http.accept() {
                let mut buf = [0u8; 16];
                let _ = stream.read(&mut buf);
                let _ = stream.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n");
            }
        });
        let err = Dialer::Socks5 { proxy: addr }
            .connect(&name("node.invalid", 8333), Duration::from_secs(5))
            .unwrap_err();
        assert!(is_proxy_down(&err));
        assert!(err.to_string().contains("not a SOCKS5 proxy"), "{err}");
    }
}
