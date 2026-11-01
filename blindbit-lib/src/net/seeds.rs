//! Where discovery starts: the network's DNS seeds.
//!
//! Directly, the seeds are DNS names that resolve to addresses of full
//! nodes. Through a proxy nothing is looked up locally (that would tell the
//! local resolver friglet runs Bitcoin); instead, as Bitcoin Core does with
//! a name proxy, friglet connects through the proxy to a few seed names
//! (the proxy, Tor's exit, resolves them to one of their nodes), asks that
//! node for addresses and hangs up.

use std::collections::HashSet;
use std::io;
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::time::{Duration, Instant};

use bitcoin::Network;
use bitcoin::p2p::ServiceFlags;
use bitcoin::p2p::address::AddrV2Message;
use bitcoin_p2p::handshake::ConnectionConfig;
use bitcoin_p2p::net::{ConnectionExt, TimeoutParams};

use super::pool::MAX_GOSSIP_PER_MESSAGE;
use super::{Dialer, PeerAddr, PeerHost, ShutdownOnDrop, USER_AGENT, is_proxy_down, random_u64};

/// How long one DNS seed lookup may take.
const LOOKUP_TIMEOUT: Duration = Duration::from_secs(10);
/// Through a proxy: how many seeds are asked at once…
const PROXIED_SEEDS: usize = 3;
/// …how long the handshake and the node's addresses may take once
/// connected (the connection itself gets the dialer's proxy timeout)…
const PROXIED_SEED_WAIT: Duration = Duration::from_secs(20);
/// …and how many addresses are enough to start with: once the seeds' nodes
/// have given this many, seeding returns, and the answers of the seeds
/// still being asked join the book as they come.
const ENOUGH_SEEDED: usize = 20;
/// A seed's node answers `getaddr` within this many messages after the
/// handshake (Bitcoin Core sends a few first: feature messages, a ping, its
/// own address); reading stops after them.
const SEED_MESSAGES: usize = 100;

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
    /// The answers of seeds still being asked when the others had given
    /// enough addresses ([`ENOUGH_SEEDED`]), one message per seed as it
    /// answers.
    pub(crate) later: Option<tokio::sync::mpsc::UnboundedReceiver<Vec<Seeded>>>,
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
                ..Seeding::default()
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
                    ..Seeding::default()
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
/// Returns once they have given [`ENOUGH_SEEDED`] addresses (the others
/// answer into [`Seeding::later`]) or all have answered.
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
    // Dropping the set closes the connections of every seed still asked.
    let mut asks = tokio::task::JoinSet::new();
    for seed in picked {
        let dialer = dialer.clone();
        asks.spawn(async move {
            let answer = ask_seed_node(&dialer, seed, port, network, PROXIED_SEED_WAIT).await;
            (seed, answer)
        });
    }
    let mut seeding = Seeding::default();
    while let Some(answer) = asks.join_next().await {
        let Ok((seed, answer)) = answer else {
            continue;
        };
        match answer {
            Ok(addrs) => seeding.found.extend(seeded_by(seed, addrs)),
            Err(e) if is_proxy_down(&e) => seeding.proxy_error = Some(e.to_string()),
            Err(e) => {
                tracing::debug!(seed, error = %e, "a seed could not be asked through the proxy")
            }
        }
        if seeding.found.len() >= ENOUGH_SEEDED && !asks.is_empty() {
            let (later, answers) = tokio::sync::mpsc::unbounded_channel();
            tokio::spawn(async move {
                while let Some(answer) = asks.join_next().await {
                    match answer {
                        Ok((seed, Ok(addrs))) => {
                            if later.send(seeded_by(seed, addrs)).is_err() {
                                return;
                            }
                        }
                        Ok((seed, Err(e))) => tracing::debug!(
                            seed,
                            error = %e,
                            "a seed could not be asked through the proxy"
                        ),
                        Err(_) => {}
                    }
                }
            });
            seeding.later = Some(answers);
            break;
        }
    }
    seeding
}

/// The addresses `seed`'s node gave, as seeded addresses.
fn seeded_by(seed: &'static str, mut addrs: Vec<AddrV2Message>) -> Vec<Seeded> {
    tracing::debug!(
        seed,
        addresses = addrs.len(),
        "a seed's node answered through the proxy"
    );
    // Most recently seen first: they take the book's slots before older ones
    // collide with them. Many addresses a node knows are days old and gone,
    // and through Tor each dead one costs the whole connect timeout.
    addrs.sort_by_key(|message| std::cmp::Reverse(message.time));
    addrs
        .into_iter()
        .filter_map(|message| {
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
        })
        .collect()
}

/// Connect through the proxy to `seed`'s name (`x9.` first), ask the node
/// for addresses, waiting at most `wait` once connected, and hang up.
/// Dropping the future closes the connection.
pub(super) async fn ask_seed_node(
    dialer: &Dialer,
    seed: &'static str,
    port: u16,
    network: Network,
    wait: Duration,
) -> io::Result<Vec<AddrV2Message>> {
    let by_name = |host: String| PeerAddr {
        host: PeerHost::Name(host),
        port,
    };
    let started = Instant::now();
    let stream = match dialer.open(&by_name(format!("x9.{seed}")), wait).await {
        Ok(stream) => stream,
        Err(e) if is_proxy_down(&e) => return Err(e),
        // Not every seed serves the `x9.` filter; a quick failure (the exit
        // could not resolve it) leaves time for the bare name.
        Err(e) if started.elapsed() < wait / 2 => {
            tracing::debug!(seed, error = %e, "x9 seed name failed through the proxy; trying the bare name");
            dialer.open(&by_name(seed.to_string()), wait).await?
        }
        Err(e) => return Err(e),
    };
    let deadline = Instant::now() + wait;
    // This future owns the deadline: the blocking reads cannot see it while
    // a message trickles in, so the connection is shut down when it passes.
    let shutdown = ShutdownOnDrop::new(&stream)?;
    let mut asking = tokio::task::spawn_blocking(move || addresses_from(stream, network, deadline));
    let asked = match tokio::time::timeout_at(deadline.into(), &mut asking).await {
        Ok(asked) => asked,
        Err(_) => {
            drop(shutdown);
            asking.await
        }
    };
    asked.map_err(|e| io::Error::other(format!("the seed task failed: {e}")))?
}

/// Handshake on `stream`, ask for addresses and wait for them until
/// `deadline` (or [`SEED_MESSAGES`] messages), then close. Each read may
/// take all the time left, so a pause in the middle of a message does not
/// cut it; a read that fails or times out ends the wait. What is kept:
/// the first address the node sent on its own, and its answer, each address
/// once and at most [`MAX_GOSSIP_PER_MESSAGE`] in all, however much it
/// sends.
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
        // Bitcoin Core answers `getaddr` with one big message; a single
        // address is a node announcing itself (kept in case it is all).
        let mut announced = None;
        for _ in 0..SEED_MESSAGES {
            let left = left();
            if left.is_zero() {
                break;
            }
            socket.set_read_timeout(Some(left))?;
            match reader.read_message() {
                Ok(Some(bitcoin::p2p::message::NetworkMessage::Ping(nonce))) => {
                    let _ = writer.send_message(bitcoin::p2p::message::NetworkMessage::Pong(nonce));
                }
                Ok(Some(message)) => {
                    if let Some(addrs) = super::gossiped_addrs(&message) {
                        if addrs.len() > 1 {
                            return Ok(kept(announced, addrs));
                        }
                        if announced.is_none() {
                            announced = addrs.into_iter().next();
                        }
                    }
                }
                Ok(None) => {}
                Err(bitcoin_p2p::net::Error::Io(e))
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
                {
                    break;
                }
                Err(_) if announced.is_some() => break,
                Err(e) => return Err(io::Error::other(e.to_string())),
            }
        }
        match announced {
            Some(announced) => Ok(vec![announced]),
            None => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "the seed's node sent no addresses",
            )),
        }
    })();
    let _ = socket.shutdown(std::net::Shutdown::Both);
    result
}

/// A seed node's answer as kept: the address it `announced` on its own
/// first, then the answer, each address once, at most
/// [`MAX_GOSSIP_PER_MESSAGE`] (what a peer may send in one message).
fn kept(announced: Option<AddrV2Message>, answer: Vec<AddrV2Message>) -> Vec<AddrV2Message> {
    let mut seen = HashSet::new();
    announced
        .into_iter()
        .chain(answer)
        .filter(|message| seen.insert((message.addr.clone(), message.port)))
        .take(MAX_GOSSIP_PER_MESSAGE)
        .collect()
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
