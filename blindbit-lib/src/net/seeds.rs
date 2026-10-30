//! Where discovery starts: the network's DNS seeds.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use bitcoin::Network;
use bitcoin::p2p::ServiceFlags;

use super::PeerAddr;

/// How long one DNS seed lookup may take.
const LOOKUP_TIMEOUT: Duration = Duration::from_secs(10);

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
    /// the seed they came from. All DNS seeds are asked at once, each first
    /// for `x9.<seed>` (Bitcoin Core's filter for `NODE_NETWORK |
    /// NODE_WITNESS` nodes), then, if that gives nothing, for the bare name.
    pub(crate) async fn resolve(&self, port: u16) -> Vec<Seeded> {
        match self {
            Self::None => Vec::new(),
            Self::Static(addrs) => addrs
                .iter()
                .map(|addr| Seeded {
                    addr: addr.clone(),
                    services: ServiceFlags::NONE,
                    seed: "static",
                })
                .collect(),
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
                found
            }
        }
    }
}

/// An address a seed gave.
#[derive(Debug, Clone)]
pub(crate) struct Seeded {
    pub(crate) addr: PeerAddr,
    pub(crate) services: ServiceFlags,
    pub(crate) seed: &'static str,
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
