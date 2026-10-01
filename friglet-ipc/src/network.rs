//! Per-network defaults shared by the daemon and the tray: the hosted
//! BlindBit oracle for each network and the default Bitcoin P2P port, plus
//! the `host[:port]` peer-address parsing both sides validate with.

/// Networks friglet understands, in the spelling used by the `network`
/// config key.
pub const NETWORKS: [&str; 5] = ["bitcoin", "signet", "testnet", "testnet4", "regtest"];

/// The hosted BlindBit oracle for `network`, if one exists. Only mainnet
/// and signet are hosted; other networks need a self-run oracle.
pub fn hosted_oracle_url(network: &str) -> Option<&'static str> {
    match network {
        "bitcoin" => Some("https://oracle.setor.dev"),
        "signet" => Some("https://signet.oracle.setor.dev"),
        _ => None,
    }
}

/// Which network a hosted oracle URL belongs to (trailing slash ignored).
pub fn hosted_oracle_network(url: &str) -> Option<&'static str> {
    let url = url.trim().trim_end_matches('/');
    NETWORKS
        .into_iter()
        .find(|n| hosted_oracle_url(n) == Some(url))
}

/// Default Bitcoin P2P port for `network`.
pub fn default_p2p_port(network: &str) -> Option<u16> {
    match network {
        "bitcoin" => Some(8333),
        "signet" => Some(38333),
        "testnet" => Some(18333),
        "testnet4" => Some(48333),
        "regtest" => Some(18444),
        _ => None,
    }
}

/// Split a P2P peer address into host and port. Accepts `host:port`,
/// `[v6]:port`, a bare host or IP (the network's default port is used) and a
/// bare IPv6 literal. The host is not resolved here.
pub fn split_peer_addr(addr: &str, network: &str) -> Result<(String, u16), String> {
    let addr = addr.trim();
    if addr.is_empty() {
        return Err("P2P node address is empty".to_string());
    }
    let default_port = || {
        default_p2p_port(network).ok_or_else(|| {
            format!("P2P node address `{addr}` has no port and network `{network}` has no default")
        })
    };
    // Bare IPv6 literal (several colons, no brackets).
    if addr.parse::<std::net::Ipv6Addr>().is_ok() {
        return Ok((addr.to_string(), default_port()?));
    }
    if let Some(rest) = addr.strip_prefix('[') {
        let (host, tail) = rest
            .split_once(']')
            .ok_or_else(|| format!("invalid P2P node address `{addr}`: missing `]`"))?;
        let port = match tail {
            "" => default_port()?,
            t => parse_port(addr, t.strip_prefix(':').unwrap_or(t))?,
        };
        return Ok((host.to_string(), port));
    }
    match addr.rsplit_once(':') {
        Some((host, port)) => {
            if host.is_empty() {
                return Err(format!("invalid P2P node address `{addr}`: missing host"));
            }
            Ok((host.to_string(), parse_port(addr, port)?))
        }
        None => Ok((addr.to_string(), default_port()?)),
    }
}

fn parse_port(addr: &str, port: &str) -> Result<u16, String> {
    match port.parse::<u16>() {
        Ok(p) if p != 0 => Ok(p),
        _ => Err(format!(
            "invalid P2P node address `{addr}`: `{port}` is not a valid port (expected host:port)"
        )),
    }
}

/// Resolve a P2P peer address (see [`split_peer_addr`]) to a socket
/// address, doing a blocking DNS lookup for hostnames. IPv4 results are
/// preferred: they work on every host, while an IPv6 result is useless on
/// the many machines without IPv6 routing.
pub fn resolve_peer_addr(addr: &str, network: &str) -> Result<std::net::SocketAddr, String> {
    use std::net::ToSocketAddrs;
    let (host, port) = split_peer_addr(addr, network)?;
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return Ok(std::net::SocketAddr::new(ip, port));
    }
    let resolved: Vec<_> = (host.as_str(), port)
        .to_socket_addrs()
        .map_err(|e| format!("cannot resolve P2P node `{host}`: {e}"))?
        .collect();
    resolved
        .iter()
        .find(|a| a.is_ipv4())
        .or_else(|| resolved.first())
        .copied()
        .ok_or_else(|| format!("cannot resolve P2P node `{host}`: no addresses"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosted_oracles_round_trip() {
        assert_eq!(
            hosted_oracle_url("bitcoin"),
            Some("https://oracle.setor.dev")
        );
        assert_eq!(
            hosted_oracle_url("signet"),
            Some("https://signet.oracle.setor.dev")
        );
        assert_eq!(hosted_oracle_url("testnet4"), None);
        assert_eq!(
            hosted_oracle_network("https://signet.oracle.setor.dev/"),
            Some("signet")
        );
        assert_eq!(hosted_oracle_network("http://127.0.0.1:7000"), None);
    }

    #[test]
    fn split_peer_addr_forms() {
        let ok = |a: &str, n: &str| split_peer_addr(a, n).unwrap();
        assert_eq!(ok("1.2.3.4:38333", "signet"), ("1.2.3.4".into(), 38333));
        assert_eq!(ok("1.2.3.4", "signet"), ("1.2.3.4".into(), 38333));
        assert_eq!(ok("node.example", "bitcoin"), ("node.example".into(), 8333));
        assert_eq!(
            ok(" node.example:1234 ", "bitcoin"),
            ("node.example".into(), 1234)
        );
        assert_eq!(ok("[::1]:18444", "regtest"), ("::1".into(), 18444));
        assert_eq!(ok("[::1]", "testnet4"), ("::1".into(), 48333));
        assert_eq!(ok("::1", "testnet"), ("::1".into(), 18333));

        for bad in ["", ":8333", "host:notaport", "host:0", "host:70000", "[::1"] {
            assert!(split_peer_addr(bad, "signet").is_err(), "{bad:?} must fail");
        }
    }

    #[test]
    fn resolve_peer_addr_ip_and_localhost() {
        assert_eq!(
            resolve_peer_addr("127.0.0.1", "signet").unwrap(),
            "127.0.0.1:38333".parse().unwrap()
        );
        // `localhost` resolves without network access.
        let addr = resolve_peer_addr("localhost:18444", "regtest").unwrap();
        assert!(addr.ip().is_loopback());
        assert_eq!(addr.port(), 18444);
        assert!(resolve_peer_addr("no-such-host.invalid:8333", "bitcoin").is_err());
    }
}
