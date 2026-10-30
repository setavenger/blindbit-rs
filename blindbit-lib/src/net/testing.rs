//! Test doubles for code that connects through a [`Dialer`] (feature
//! `test-util`).

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::{Dialer, PeerAddr, PeerHost};

/// One connection a [`FakeSocks5`] was asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Socks5Request {
    /// The authentication methods the client offered.
    pub methods: Vec<u8>,
    /// The username and password it logged in with, if it did.
    pub credentials: Option<(String, String)>,
    /// The CONNECT target as sent: a host name stays a name.
    pub target: PeerAddr,
}

#[derive(Default)]
struct State {
    /// Where a host name "resolves" to: a local listener.
    routes: HashMap<String, SocketAddr>,
    /// A SOCKS5 error code every CONNECT is answered with, if set.
    refuse_with: Option<u8>,
    requests: Vec<Socks5Request>,
}

/// A SOCKS5 proxy on 127.0.0.1 that records what it is asked, "resolves"
/// host names only through [`Self::route`] (an unrouted name is
/// unreachable, as an unknown name is for Tor), connects to IP addresses
/// as given, and pipes the bytes. It picks username/password when offered,
/// as Tor does.
pub struct FakeSocks5 {
    addr: SocketAddr,
    state: Arc<Mutex<State>>,
    stop: Arc<AtomicBool>,
}

impl FakeSocks5 {
    pub fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind the fake proxy");
        let addr = listener.local_addr().expect("its address");
        let state = Arc::new(Mutex::new(State::default()));
        let stop = Arc::new(AtomicBool::new(false));
        let (thread_state, thread_stop) = (state.clone(), stop.clone());
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                if thread_stop.load(Ordering::SeqCst) {
                    return;
                }
                let Ok(stream) = stream else {
                    continue;
                };
                let state = thread_state.clone();
                std::thread::spawn(move || {
                    let _ = serve(stream, &state);
                });
            }
        });
        Self { addr, state, stop }
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// A dialer through this proxy.
    pub fn dialer(&self) -> Dialer {
        Dialer::Socks5 { proxy: self.addr }
    }

    /// Connections to `host` (any port) go to `to`.
    pub fn route(&self, host: &str, to: SocketAddr) {
        self.lock().routes.insert(host.to_string(), to);
    }

    /// Answer every CONNECT from now on with SOCKS5 error `code`.
    pub fn refuse_with(&self, code: u8) {
        self.lock().refuse_with = Some(code);
    }

    /// Every connection asked for, in order.
    pub fn requests(&self) -> Vec<Socks5Request> {
        self.lock().requests.clone()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl Drop for FakeSocks5 {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        // Wake the accept loop so it sees the flag.
        let _ = TcpStream::connect_timeout(&self.addr, Duration::from_millis(200));
    }
}

fn serve(mut client: TcpStream, state: &Mutex<State>) -> io::Result<()> {
    client.set_read_timeout(Some(Duration::from_secs(10)))?;
    let mut head = [0u8; 2];
    client.read_exact(&mut head)?;
    if head[0] != 5 {
        return Ok(());
    }
    let mut methods = vec![0u8; usize::from(head[1])];
    client.read_exact(&mut methods)?;
    let credentials = if methods.contains(&2) {
        client.write_all(&[5, 2])?;
        let mut version_len = [0u8; 2];
        client.read_exact(&mut version_len)?;
        let mut user = vec![0u8; usize::from(version_len[1])];
        client.read_exact(&mut user)?;
        let mut len = [0u8; 1];
        client.read_exact(&mut len)?;
        let mut password = vec![0u8; usize::from(len[0])];
        client.read_exact(&mut password)?;
        client.write_all(&[1, 0])?;
        Some((
            String::from_utf8_lossy(&user).into_owned(),
            String::from_utf8_lossy(&password).into_owned(),
        ))
    } else if methods.contains(&0) {
        client.write_all(&[5, 0])?;
        None
    } else {
        return client.write_all(&[5, 0xff]);
    };

    let mut request = [0u8; 4];
    client.read_exact(&mut request)?;
    let host = match request[3] {
        1 => {
            let mut ip = [0u8; 4];
            client.read_exact(&mut ip)?;
            PeerHost::Ip(IpAddr::V4(Ipv4Addr::from(ip)))
        }
        4 => {
            let mut ip = [0u8; 16];
            client.read_exact(&mut ip)?;
            PeerHost::Ip(IpAddr::V6(Ipv6Addr::from(ip)))
        }
        3 => {
            let mut len = [0u8; 1];
            client.read_exact(&mut len)?;
            let mut name = vec![0u8; usize::from(len[0])];
            client.read_exact(&mut name)?;
            PeerHost::Name(String::from_utf8_lossy(&name).into_owned())
        }
        _ => return reply(&mut client, 8),
    };
    let mut port = [0u8; 2];
    client.read_exact(&mut port)?;
    let target = PeerAddr {
        host,
        port: u16::from_be_bytes(port),
    };
    let (refuse_with, destination) = {
        let mut state = state.lock().unwrap_or_else(|e| e.into_inner());
        state.requests.push(Socks5Request {
            methods,
            credentials,
            target: target.clone(),
        });
        let destination = match &target.host {
            PeerHost::Ip(ip) => Some(SocketAddr::new(*ip, target.port)),
            PeerHost::Name(name) => state.routes.get(name).copied(),
        };
        (state.refuse_with, destination)
    };
    if let Some(code) = refuse_with {
        return reply(&mut client, code);
    }
    let Some(destination) = destination else {
        return reply(&mut client, 4);
    };
    let Ok(upstream) = TcpStream::connect_timeout(&destination, Duration::from_secs(5)) else {
        return reply(&mut client, 5);
    };
    reply(&mut client, 0)?;
    client.set_read_timeout(None)?;
    pipe(client, upstream)
}

/// A reply with code `code` and an IPv4 bound address.
fn reply(client: &mut TcpStream, code: u8) -> io::Result<()> {
    client.write_all(&[5, code, 0, 1, 127, 0, 0, 1, 0, 0])
}

/// Copy both ways until either side closes.
fn pipe(client: TcpStream, upstream: TcpStream) -> io::Result<()> {
    let (mut client_read, mut upstream_write) = (client.try_clone()?, upstream.try_clone()?);
    let forward = std::thread::spawn(move || {
        let _ = io::copy(&mut client_read, &mut upstream_write);
        let _ = upstream_write.shutdown(Shutdown::Both);
    });
    let (mut upstream_read, mut client_write) = (upstream, client);
    let _ = io::copy(&mut upstream_read, &mut client_write);
    let _ = client_write.shutdown(Shutdown::Both);
    let _ = forward.join();
    Ok(())
}
