//! Where discovery starts: the network's DNS seeds.
//!
//! Directly, the seeds are DNS names that resolve to addresses of full
//! nodes. Through a proxy nothing is looked up locally (that would tell the
//! local resolver friglet runs Bitcoin); instead, as Bitcoin Core does with
//! a name proxy, friglet connects through the proxy to a few seed names
//! (the proxy, Tor's exit, resolves them to one of their nodes), asks that
//! node for addresses and hangs up.

use std::io;
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::time::{Duration, Instant};

use bitcoin::Network;
use bitcoin::p2p::ServiceFlags;
use bitcoin::p2p::address::AddrV2Message;
use bitcoin_p2p::handshake::ConnectionConfig;
use bitcoin_p2p::net::{ConnectionExt, TimeoutParams};

use super::{Dialer, PeerAddr, PeerHost, USER_AGENT, is_proxy_down, random_u64};

/// How long one DNS seed lookup may take.
const LOOKUP_TIMEOUT: Duration = Duration::from_secs(10);
/// Through a proxy: how many seeds are asked at once…
const PROXIED_SEEDS: usize = 3;
/// …and how long the handshake and the node's addresses may take once
/// connected (the connection itself gets the dialer's proxy timeout).
const PROXIED_SEED_WAIT: Duration = Duration::from_secs(20);

/// Where a discovering [`super::PeerSource`] gets its first addresses.
#[derive(Debug, Clone)]
pub enum Seeds {
    /// DNS seeds: each name resolves to addresses of reachable full nodes.
    Dns(&'static [&'static str]),
    /// Fixed addresses, no DNS (tests, or a list the user provides).
    Static(Vec<PeerAddr>),
    /// Nothing to start from (regtest).
    None,
}

/// What asking the seeds gave.
#[derive(Debug, Default)]
pub(crate) struct Seeding {
    pub(crate) found: Vec<Seeded>,
    /// The proxy failed, so no seed could be asked: why.
    pub(crate) proxy_error: Option<String>,
}

/// An address a seed gave.
#[derive(Debug, Clone)]
pub(crate) struct Seeded {
    pub(crate) addr: PeerAddr,
    pub(crate) services: ServiceFlags,
    pub(crate) seed: &'static str,
    /// Gossiped by a seed's node (through a proxy) rather than vouched for
    /// by the seed's DNS answer: checked like any gossip.
    pub(crate) gossiped: bool,
}

impl Seeds {
    /// The network's DNS seeds, as Bitcoin Core ships them; regtest has none.
    pub fn for_network(network: Network) -> Self {
        use bitcoin_p2p::dns;
        match network {
            Network::Bitcoin => Self::Dns(&dns::BITCOIN_SEEDS),
            Network::Testnet => Self::Dns(&dns::TESTNET3_SEEDS),
            Network::Testnet4 => Self::Dns(&dns::TESTNET4_SEEDS),
            Network::Signet => Self::Dns(&dns::SIGNET_SEEDS),
            Network::Regtest => Self::None,
        }
    }

    /// Every address the seeds give, with the services they vouch for and
    /// the seed they came from.
    ///
    /// Directly, all DNS seeds are asked at once, each first for
    /// `x9.<seed>` (Bitcoin Core's filter for `NODE_NETWORK | NODE_WITNESS`
    /// nodes), then, if that gives nothing, for the bare name.
    ///
    /// Through a proxy ([`Dialer::Socks5`]) there is no DNS lookup:
    /// [`PROXIED_SEEDS`] random seeds are each connected to by name through
    /// the proxy (`x9.<seed>`, else the bare name), and the node the proxy
    /// reaches is asked for addresses (`getaddr`).
    pub(crate) async fn resolve(&self, port: u16, dialer: &Dialer, network: Network) -> Seeding {
        match self {
            Self::None => Seeding::default(),
            Self::Static(addrs) => Seeding {
                found: addrs
                    .iter()
                    .map(|addr| Seeded {
                        addr: addr.clone(),
                        services: ServiceFlags::NONE,
                        seed: "static",
                        gossiped: false,
                    })
                    .collect(),
                proxy_error: None,
            },
            Self::Dns(names) if dialer.proxy().is_some() => {
                through_proxy(names, dialer, network, port).await
            }
            Self::Dns(names) => {
                let mut lookups = tokio::task::JoinSet::new();
                for name in names.iter().copied() {
                    lookups.spawn(lookup_seed(name, port));
                }
                let mut found = Vec::new();
                while let Some(result) = lookups.join_next().await {
                    if let Ok(addrs) = result {
                        found.extend(addrs);
                    }
                }
                Seeding {
                    found,
                    proxy_error: None,
                }
            }
        }
    }
}

async fn lookup_seed(name: &'static str, port: u16) -> Vec<Seeded> {
    let filtered = lookup(format!("x9.{name}"), port).await;
    let (ips, services) = if filtered.is_empty() {
        (lookup(name.to_string(), port).await, ServiceFlags::NONE)
    } else {
        (filtered, ServiceFlags::NETWORK | ServiceFlags::WITNESS)
    };
    tracing::debug!(seed = name, addresses = ips.len(), "DNS seed answered");
    ips.into_iter()
        .map(|ip| Seeded {
            addr: SocketAddr::new(ip, port).into(),
            services,
            seed: name,
            gossiped: false,
        })
        .collect()
}

async fn lookup(host: String, port: u16) -> Vec<IpAddr> {
    #[cfg(test)]
    lookups::record(&host);
    match tokio::time::timeout(
        LOOKUP_TIMEOUT,
        tokio::net::lookup_host((host.as_str(), port)),
    )
    .await
    {
        Ok(Ok(addrs)) => {
            let mut ips: Vec<IpAddr> = addrs.map(|addr| addr.ip()).collect();
            ips.sort();
            ips.dedup();
            ips
        }
        Ok(Err(e)) => {
            tracing::debug!(%host, error = %e, "DNS seed lookup failed");
            Vec::new()
        }
        Err(_) => {
            tracing::debug!(%host, "DNS seed lookup timed out");
            Vec::new()
        }
    }
}

/// Ask [`PROXIED_SEEDS`] random seeds' nodes, through the proxy, at once.
async fn through_proxy(
    names: &'static [&'static str],
    dialer: &Dialer,
    network: Network,
    port: u16,
) -> Seeding {
    let mut names = names.to_vec();
    let mut picked = Vec::new();
    while !names.is_empty() && picked.len() < PROXIED_SEEDS {
        picked.push(names.swap_remove((random_u64() % names.len() as u64) as usize));
    }
    let mut asks = tokio::task::JoinSet::new();
    for seed in picked {
        let dialer = dialer.clone();
        asks.spawn_blocking(move || (seed, ask_seed_node(&dialer, seed, port, network)));
    }
    let mut seeding = Seeding::default();
    while let Some(answer) = asks.join_next().await {
        let Ok((seed, answer)) = answer else {
            continue;
        };
        match answer {
            Ok(addrs) => {
                tracing::debug!(
                    seed,
                    addresses = addrs.len(),
                    "a seed's node answered through the proxy"
                );
                seeding
                    .found
                    .extend(addrs.into_iter().filter_map(|message| {
                        let ip = match message.addr {
                            bitcoin::p2p::address::AddrV2::Ipv4(ip) => IpAddr::V4(ip),
                            bitcoin::p2p::address::AddrV2::Ipv6(ip) => IpAddr::V6(ip),
                            // Onion peers are not dialled yet.
                            _ => return None,
                        };
                        Some(Seeded {
                            addr: SocketAddr::new(ip, message.port).into(),
                            services: message.services,
                            seed,
                            gossiped: true,
                        })
                    }));
            }
            Err(e) if is_proxy_down(&e) => seeding.proxy_error = Some(e.to_string()),
            Err(e) => {
                tracing::debug!(seed, error = %e, "a seed could not be asked through the proxy")
            }
        }
    }
    seeding
}

/// Connect through the proxy to `seed`'s name (`x9.` first), ask the node
/// for addresses and hang up. Blocking.
fn ask_seed_node(
    dialer: &Dialer,
    seed: &'static str,
    port: u16,
    network: Network,
) -> io::Result<Vec<AddrV2Message>> {
    let by_name = |host: String| PeerAddr {
        host: PeerHost::Name(host),
        port,
    };
    let started = Instant::now();
    let stream = match dialer.connect(&by_name(format!("x9.{seed}")), PROXIED_SEED_WAIT) {
        Ok(stream) => stream,
        Err(e) if is_proxy_down(&e) => return Err(e),
        // Not every seed serves the `x9.` filter; a quick failure (the exit
        // could not resolve it) leaves time for the bare name.
        Err(e) if started.elapsed() < PROXIED_SEED_WAIT / 2 => {
            tracing::debug!(seed, error = %e, "x9 seed name failed through the proxy; trying the bare name");
            dialer.connect(&by_name(seed.to_string()), PROXIED_SEED_WAIT)?
        }
        Err(e) => return Err(e),
    };
    addresses_from(stream, network, Instant::now() + PROXIED_SEED_WAIT)
}

/// Handshake on `stream`, ask for addresses and wait for them until
/// `deadline`, then close.
fn addresses_from(
    stream: TcpStream,
    network: Network,
    deadline: Instant,
) -> io::Result<Vec<AddrV2Message>> {
    let socket = stream.try_clone()?;
    let left = || deadline.saturating_duration_since(Instant::now());
    stream.set_read_timeout(Some(left().max(Duration::from_millis(1))))?;
    stream.set_write_timeout(Some(PROXIED_SEED_WAIT))?;
    let result = (|| {
        let (writer, mut reader, _) = ConnectionConfig::new()
            .change_network(network)
            .user_agent(USER_AGENT.to_string())
            .request_addr()
            .handshake(stream, TimeoutParams::default())
            .map_err(|e| io::Error::other(format!("handshake failed: {e}")))?;
        socket.set_read_timeout(Some(Duration::from_millis(500)))?;
        let mut got = Vec::new();
        while !left().is_zero() {
            match reader.read_message() {
                Ok(Some(bitcoin::p2p::message::NetworkMessage::Ping(nonce))) => {
                    let _ = writer.send_message(bitcoin::p2p::message::NetworkMessage::Pong(nonce));
                }
                Ok(Some(message)) => {
                    // Bitcoin Core answers `getaddr` with one big message;
                    // a single address is a node announcing itself.
                    if let Some(addrs) = super::gossiped_addrs(&message) {
                        let answer = addrs.len() > 1;
                        got.extend(addrs);
                        if answer {
                            return Ok(got);
                        }
                    }
                }
                Ok(None) => {}
                Err(bitcoin_p2p::net::Error::Io(e))
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) => {}
                Err(e) => return Err(io::Error::other(e.to_string())),
            }
        }
        if got.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "the seed's node sent no addresses",
            ));
        }
        Ok(got)
    })();
    let _ = socket.shutdown(std::net::Shutdown::Both);
    result
}

/// Every DNS name this process looked up as a seed, for tests that check a
/// name was never asked.
#[cfg(test)]
pub(crate) mod lookups {
    use std::sync::Mutex;

    static NAMES: Mutex<Vec<String>> = Mutex::new(Vec::new());

    pub(super) fn record(host: &str) {
        NAMES.lock().unwrap().push(host.to_string());
    }

    pub(crate) fn asked(fragment: &str) -> bool {
        NAMES
            .lock()
            .unwrap()
            .iter()
            .any(|name| name.contains(fragment))
    }
}
