//! First-run setup for the tray: decide whether the daemon is plausibly
//! configured (so spawning it makes sense), validate a setup-mode form
//! submission, and write the config + key files locally so the daemon can
//! start without the user hand-creating `config.toml`.
//!
//! Deliberately decoupled from tauri so everything is unit-testable; the
//! process environment is injected as a closure rather than read directly.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use friglet_ipc::DaemonConfig;
use friglet_ipc::descriptor::SpDescriptor;
use friglet_ipc::network::{self, NETWORKS};

/// Environment variables the daemon's config layering honors for the
/// settings the tray checks (`figment::Env::prefixed("FRIGLET_")` plus the
/// scan-secret override in `resolve_scan_secret`).
const ENV_P2P_NODE_ADDR: &str = "FRIGLET_P2P_NODE_ADDR";
const ENV_START_HEIGHT: &str = "FRIGLET_START_HEIGHT";
const ENV_SPEND_PUBKEY: &str = "FRIGLET_SPEND_PUBKEY";
const ENV_SCAN_SECRET: &str = "FRIGLET_SCAN_SECRET";
const ENV_START_AT_TIP: &str = "FRIGLET_START_AT_TIP";
const ENV_DESCRIPTOR: &str = "FRIGLET_DESCRIPTOR";

/// Is the daemon plausibly configured, i.e. is spawning it likely to get
/// past `missing required setting ...`? Conservative merged view:
///
/// - the required settings (`p2p_node_addr`, `start_height` — or
///   `start_at_tip` —, `spend_pubkey`) are each present in the config file at
///   `config_path` OR supplied via their `FRIGLET_*` environment variable, AND
/// - a scan secret is available: the key file (the config's `key_file` or
///   `default_key_file`) exists, or `FRIGLET_SCAN_SECRET` is set.
///
/// A `descriptor` (config key or `FRIGLET_DESCRIPTOR`) supplies the spend
/// key and the scan secret, and its `bh=` annotation the start height.
///
/// A config file that exists but fails to parse counts as configured: the
/// spawn attempt surfaces the daemon's own parse error through the existing
/// spawn-failure diagnostics, instead of the tray entering setup mode and
/// overwriting a hand-written file on Save.
pub fn is_configured(
    config_path: Option<&Path>,
    default_key_file: Option<&Path>,
    env: &dyn Fn(&str) -> Option<String>,
) -> bool {
    let file_cfg = match config_path {
        Some(p) if p.exists() => match friglet_ipc::read_config_toml(p) {
            Ok(cfg) => Some(cfg),
            Err(_) => return true,
        },
        _ => None,
    };

    let env_set = |key: &str| env(key).is_some_and(|v| !v.trim().is_empty());
    let file_has = |get: fn(&DaemonConfig) -> bool| file_cfg.as_ref().is_some_and(get);

    // The descriptor lives beside DaemonConfig (it carries the scan secret),
    // so look it up in the raw file / env.
    let descriptor = env(ENV_DESCRIPTOR)
        .filter(|v| !v.trim().is_empty())
        .or_else(|| config_path.and_then(file_descriptor))
        .and_then(|d| SpDescriptor::parse(&d).ok());

    let p2p = file_has(|c| c.p2p_node_addr.is_some()) || env_set(ENV_P2P_NODE_ADDR);
    let start = file_has(|c| c.start_height.is_some() || c.start_at_tip)
        || env_set(ENV_START_HEIGHT)
        || env_set(ENV_START_AT_TIP)
        || descriptor
            .as_ref()
            .is_some_and(|d| d.birth_height.is_some());
    let spend =
        file_has(|c| c.spend_pubkey.is_some()) || env_set(ENV_SPEND_PUBKEY) || descriptor.is_some();

    let key_file = file_cfg
        .as_ref()
        .and_then(|c| c.key_file.clone())
        .or_else(|| default_key_file.map(Path::to_path_buf));
    let secret =
        env_set(ENV_SCAN_SECRET) || descriptor.is_some() || key_file.is_some_and(|p| p.exists());

    p2p && start && spend && secret
}

/// The `descriptor` key of the TOML file at `path`, if any.
fn file_descriptor(path: &Path) -> Option<String> {
    let text = std::fs::read_to_string(path).ok()?;
    let table: toml::Table = toml::from_str(&text).ok()?;
    table.get("descriptor")?.as_str().map(str::to_string)
}

/// [`is_configured`] fed from the real environment and default paths.
pub fn is_configured_from_env() -> bool {
    is_configured(
        friglet_ipc::default_config_path().as_deref(),
        friglet_ipc::default_key_file().as_deref(),
        &|key| std::env::var(key).ok(),
    )
}

/// What the tray shows after a descriptor is pasted: everything derived
/// from it except the scan secret, which never leaves Rust.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct DescriptorSummary {
    /// `true` for spscan (mainnet) keys, `false` for tspscan (test networks).
    pub mainnet: bool,
    /// The network the form should switch to: `bitcoin` for mainnet keys;
    /// for test keys the currently selected test network, else `signet`
    /// (the only test network with a hosted oracle).
    pub network: String,
    pub spend_pubkey: String,
    /// BIP-352 receive address on `network`, to compare with Sparrow.
    pub sp_address: String,
    pub birth_height: Option<u64>,
    /// The pasted text held the spend private key; it was dropped and the
    /// form should replace the pasted text with `watch_only`.
    pub had_spend_secret: bool,
    pub watch_only: String,
}

/// Parse a pasted descriptor for the setup/settings form.
pub fn summarize_descriptor(
    text: &str,
    current_network: &str,
) -> Result<DescriptorSummary, String> {
    let d = SpDescriptor::parse(text)?;
    let network = if d.matches_network(current_network) {
        current_network.to_string()
    } else if d.matches_network("bitcoin") {
        "bitcoin".to_string()
    } else {
        "signet".to_string()
    };
    Ok(DescriptorSummary {
        mainnet: d.matches_network("bitcoin"),
        sp_address: d.sp_address(&network),
        network,
        spend_pubkey: d.spend_pubkey_hex(),
        birth_height: d.birth_height,
        had_spend_secret: d.had_spend_secret,
        watch_only: d.to_watch_only_string(),
    })
}

/// Fold a pasted descriptor into a setup/settings submission: returns the
/// scan key (hex) and fills `cfg.spend_pubkey`. A spend private key in the
/// descriptor is dropped (only its public key is used), so nothing secret
/// beyond the scan key is ever written.
pub fn keys_from_descriptor(cfg: &mut DaemonConfig, text: &str) -> Result<String, String> {
    let d = SpDescriptor::parse(text)?;
    if !d.matches_network(&cfg.network) {
        return Err(format!(
            "{}: pick the matching network",
            d.network_mismatch(&cfg.network)
        ));
    }
    cfg.spend_pubkey = Some(d.spend_pubkey_hex());
    Ok(d.scan_secret_hex())
}

/// Validate a setup-mode save tray-side, mirroring the daemon's own startup
/// validation with friendlier messages. Hex fields are checked for length
/// only; full secp256k1 validation happens daemon-side at startup. The P2P
/// host is checked for syntax only (see [`resolve_peer`] for DNS).
pub fn validate_setup(cfg: &DaemonConfig, scan_key: &str) -> Result<(), String> {
    if !NETWORKS.contains(&cfg.network.as_str()) {
        return Err(format!(
            "invalid network `{}`: must be one of {}",
            cfg.network,
            NETWORKS.join(", ")
        ));
    }
    if !cfg.oracle_url.starts_with("http://") && !cfg.oracle_url.starts_with("https://") {
        return Err(if cfg.oracle_url.trim().is_empty() {
            format!(
                "an oracle URL is required: there is no hosted oracle for {}, enter your own",
                cfg.network
            )
        } else {
            format!(
                "invalid oracle URL `{}`: must start with http:// or https://",
                cfg.oracle_url
            )
        });
    }
    if let Some(hosted_for) = network::hosted_oracle_network(&cfg.oracle_url)
        && hosted_for != cfg.network
    {
        return Err(format!(
            "the oracle URL is the hosted {hosted_for} oracle, but the network is {}",
            cfg.network
        ));
    }

    let p2p = cfg
        .p2p_node_addr
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or("P2P node address is required (host:port of a Bitcoin node)")?;
    network::split_peer_addr(p2p, &cfg.network)
        .map_err(|e| format!("invalid P2P node address: {e}"))?;

    match cfg.start_height {
        None if cfg.start_at_tip => {}
        None => return Err("wallet birthday (start height) is required".to_string()),
        Some(0) => return Err("invalid start height 0: must be at least 1".to_string()),
        Some(_) => {}
    }

    let spend = cfg
        .spend_pubkey
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or(
            "paste your Sparrow wallet descriptor (or enter the spend public key under Advanced)",
        )?;
    if spend.len() != 66 || !is_hex(spend) {
        return Err("invalid spend public key: must be 66 hex characters (33 bytes)".to_string());
    }

    let key = scan_key.trim();
    if key.is_empty() {
        return Err(
            "paste your Sparrow wallet descriptor (or enter the scan key under Advanced)"
                .to_string(),
        );
    }
    if key.len() != 64 || !is_hex(key) {
        return Err("invalid scan key: must be 64 hex characters (32 bytes)".to_string());
    }

    SocketAddr::from_str(&cfg.http_addr)
        .map_err(|e| format!("invalid HTTP bind address `{}`: {e}", cfg.http_addr))?;
    SocketAddr::from_str(&cfg.electrum_addr)
        .map_err(|e| format!("invalid Electrum bind address `{}`: {e}", cfg.electrum_addr))?;
    if cfg.state_file.as_os_str().is_empty() {
        return Err("state file path cannot be empty".to_string());
    }

    Ok(())
}

/// DNS check for the P2P node so a typo fails at Save instead of as a
/// daemon that never connects.
pub async fn resolve_peer(cfg: &DaemonConfig) -> Result<(), String> {
    let Some(p2p) = cfg.p2p_node_addr.as_deref() else {
        return Ok(());
    };
    let (host, port) = network::split_peer_addr(p2p, &cfg.network)?;
    if host.parse::<std::net::IpAddr>().is_ok() {
        return Ok(());
    }
    let lookup = tokio::net::lookup_host((host.as_str(), port));
    match tokio::time::timeout(std::time::Duration::from_secs(10), lookup).await {
        Ok(Ok(mut addrs)) => match addrs.next() {
            Some(_) => Ok(()),
            None => Err(format!("P2P node `{host}` has no addresses")),
        },
        Ok(Err(e)) => Err(format!("cannot resolve P2P node `{host}`: {e}")),
        Err(_) => Err(format!("resolving P2P node `{host}` timed out")),
    }
}

fn is_hex(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Persist a validated setup-mode save: write the scan key file (0600 on
/// Unix), then the config file (atomic TOML) at `config_path`. The key file
/// path comes from the config payload, falling back to the default.
///
/// Key file first, deliberately: if it fails, no config file has been
/// created yet, so the tray stays cleanly in setup mode instead of leaving a
/// config that points at a missing key. Returns the key file path written.
pub fn write_local_config(
    config_path: &Path,
    cfg: &DaemonConfig,
    scan_key: &str,
) -> Result<PathBuf, String> {
    let key_file = cfg
        .key_file
        .clone()
        .or_else(friglet_ipc::default_key_file)
        .ok_or("cannot determine a key file location; set the key file path")?;
    friglet_ipc::write_key_file(&key_file, scan_key.trim(), true)?;
    friglet_ipc::write_config_toml(config_path, cfg)?;
    Ok(key_file)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    const SPEND_HEX: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    const KEY_HEX: &str = "0000000000000000000000000000000000000000000000000000000000000001";

    fn temp_dir(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("friglet-tray-setup-{}-{tag}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn no_env(_: &str) -> Option<String> {
        None
    }

    fn complete_toml() -> String {
        format!(
            "p2p_node_addr = \"127.0.0.1:38333\"\nstart_height = 274010\nspend_pubkey = \"{SPEND_HEX}\"\n"
        )
    }

    fn valid_config() -> DaemonConfig {
        DaemonConfig {
            network: "signet".to_string(),
            oracle_url: "https://signet.oracle.setor.dev".to_string(),
            p2p_node_addr: Some("127.0.0.1:38333".to_string()),
            start_height: Some(274010),
            spend_pubkey: Some(SPEND_HEX.to_string()),
            ..DaemonConfig::default()
        }
    }

    #[test]
    fn not_configured_without_config_file() {
        let dir = temp_dir("no-file");
        assert!(!is_configured(
            Some(&dir.join("config.toml")),
            Some(&dir.join("scan.key")),
            &no_env,
        ));
    }

    #[test]
    fn not_configured_when_file_misses_spend_pubkey() {
        let dir = temp_dir("missing-spend");
        let config = dir.join("config.toml");
        fs::write(
            &config,
            "p2p_node_addr = \"127.0.0.1:38333\"\nstart_height = 274010\n",
        )
        .unwrap();
        let key = dir.join("scan.key");
        fs::write(&key, format!("{KEY_HEX}\n")).unwrap();
        assert!(!is_configured(Some(&config), Some(&key), &no_env));
    }

    #[test]
    fn not_configured_when_key_file_missing() {
        let dir = temp_dir("missing-key");
        let config = dir.join("config.toml");
        fs::write(&config, complete_toml()).unwrap();
        assert!(!is_configured(
            Some(&config),
            Some(&dir.join("scan.key")),
            &no_env
        ));
    }

    #[test]
    fn configured_with_complete_file_and_key_file() {
        let dir = temp_dir("complete");
        let config = dir.join("config.toml");
        fs::write(&config, complete_toml()).unwrap();
        let key = dir.join("scan.key");
        fs::write(&key, format!("{KEY_HEX}\n")).unwrap();
        assert!(is_configured(Some(&config), Some(&key), &no_env));
    }

    #[test]
    fn config_key_file_setting_overrides_default_path() {
        let dir = temp_dir("custom-keyfile");
        let custom_key = dir.join("custom.key");
        fs::write(&custom_key, format!("{KEY_HEX}\n")).unwrap();
        let config = dir.join("config.toml");
        fs::write(
            &config,
            format!(
                "{}key_file = \"{}\"\n",
                complete_toml(),
                custom_key.display()
            ),
        )
        .unwrap();
        // Default key path does not exist; the configured one does.
        assert!(is_configured(
            Some(&config),
            Some(&dir.join("scan.key")),
            &no_env
        ));
    }

    #[test]
    fn configured_via_env_vars_alone() {
        let dir = temp_dir("env-only");
        let env = |key: &str| -> Option<String> {
            match key {
                ENV_P2P_NODE_ADDR => Some("127.0.0.1:38333".to_string()),
                ENV_START_HEIGHT => Some("274010".to_string()),
                ENV_SPEND_PUBKEY => Some(SPEND_HEX.to_string()),
                ENV_SCAN_SECRET => Some(KEY_HEX.to_string()),
                _ => None,
            }
        };
        assert!(is_configured(
            Some(&dir.join("config.toml")),
            Some(&dir.join("scan.key")),
            &env,
        ));
    }

    #[test]
    fn empty_env_values_do_not_count() {
        let dir = temp_dir("env-empty");
        let env = |_: &str| Some("  ".to_string());
        assert!(!is_configured(
            Some(&dir.join("config.toml")),
            Some(&dir.join("scan.key")),
            &env,
        ));
    }

    #[test]
    fn unparseable_config_file_counts_as_configured() {
        // Deliberate: spawning surfaces the daemon's own parse error instead
        // of setup mode overwriting a hand-written (but broken) file.
        let dir = temp_dir("broken-file");
        let config = dir.join("config.toml");
        fs::write(&config, "this is [not toml").unwrap();
        assert!(is_configured(
            Some(&config),
            Some(&dir.join("scan.key")),
            &no_env
        ));
    }

    #[test]
    fn validate_accepts_a_complete_setup() {
        assert_eq!(validate_setup(&valid_config(), KEY_HEX), Ok(()));
    }

    #[test]
    fn validate_rejects_bad_fields_with_friendly_messages() {
        let cases: Vec<(DaemonConfig, &str, &str)> = vec![
            (
                DaemonConfig {
                    network: "mainnet".to_string(),
                    ..valid_config()
                },
                KEY_HEX,
                "invalid network",
            ),
            (
                DaemonConfig {
                    oracle_url: "oracle.setor.dev".to_string(),
                    ..valid_config()
                },
                KEY_HEX,
                "invalid oracle URL",
            ),
            (
                DaemonConfig {
                    p2p_node_addr: None,
                    ..valid_config()
                },
                KEY_HEX,
                "P2P node address is required",
            ),
            (
                DaemonConfig {
                    p2p_node_addr: Some("node.example:notaport".to_string()),
                    ..valid_config()
                },
                KEY_HEX,
                "invalid P2P node address",
            ),
            (
                DaemonConfig {
                    oracle_url: "https://oracle.setor.dev".to_string(),
                    ..valid_config()
                },
                KEY_HEX,
                "hosted bitcoin oracle",
            ),
            (
                DaemonConfig {
                    network: "testnet4".to_string(),
                    oracle_url: String::new(),
                    ..valid_config()
                },
                KEY_HEX,
                "no hosted oracle for testnet4",
            ),
            (
                DaemonConfig {
                    start_height: None,
                    ..valid_config()
                },
                KEY_HEX,
                "wallet birthday (start height) is required",
            ),
            (
                DaemonConfig {
                    start_height: Some(0),
                    ..valid_config()
                },
                KEY_HEX,
                "must be at least 1",
            ),
            (
                DaemonConfig {
                    spend_pubkey: Some("02abc".to_string()),
                    ..valid_config()
                },
                KEY_HEX,
                "invalid spend public key",
            ),
            (valid_config(), "", "paste your Sparrow wallet descriptor"),
            (valid_config(), "zz", "invalid scan key"),
            (
                DaemonConfig {
                    http_addr: "nope".to_string(),
                    ..valid_config()
                },
                KEY_HEX,
                "invalid HTTP bind address",
            ),
        ];
        for (cfg, key, expected) in cases {
            let err = validate_setup(&cfg, key).unwrap_err();
            assert!(err.contains(expected), "expected `{expected}` in `{err}`");
        }
    }

    /// Sparrow's testnet fixture, as Copy Output Descriptor yields it.
    const TEST_DESCRIPTOR: &str = "sp([0f056943/352h/1h/0h]tspscan1q05wxw5wc7wqmkf8cnfc6ry76qej8vhr3a3mmxmwgv35s0tlw24fs82k0npv2hv6p97s8sd9t7vpf44kluka9w863zjwxzfrym2ay9ccfzt06c4)#7eve6al9";
    const MAINNET_SPSPEND: &str = "sp(spspend1qpa55up5q9zn30790dw2pr7dpx0wn2ef9su2vcgn9jje5mwgvrukf66kc2h8rg9l0sn5rdzfwtftrj2lm5p06tktue63sufn02s8q3vch3lrh8)";

    #[test]
    fn validate_accepts_hostnames_bare_hosts_and_start_at_tip() {
        for p2p in [
            "node.example:38333",
            "node.example",
            "10.0.0.2",
            "[::1]:38333",
        ] {
            let cfg = DaemonConfig {
                p2p_node_addr: Some(p2p.to_string()),
                ..valid_config()
            };
            assert_eq!(validate_setup(&cfg, KEY_HEX), Ok(()), "{p2p}");
        }
        let new_wallet = DaemonConfig {
            start_height: None,
            start_at_tip: true,
            ..valid_config()
        };
        assert_eq!(validate_setup(&new_wallet, KEY_HEX), Ok(()));
    }

    #[test]
    fn descriptor_summary_picks_network_and_hides_secret() {
        let s = summarize_descriptor(TEST_DESCRIPTOR, "bitcoin").unwrap();
        assert!(!s.mainnet);
        assert_eq!(s.network, "signet", "test keys default to signet");
        assert!(s.sp_address.starts_with("tsp1q"));
        assert_eq!(
            s.spend_pubkey,
            "03aacf9858abb3412fa07834abf3029ad6dfe5ba571f51149c612464daba42e309"
        );
        assert!(!s.had_spend_secret);
        let json = serde_json::to_string(&s).unwrap();
        assert!(
            !json.contains("7d1c6751d8f381bb24f89a71a193da0664765c71ec77b36dc8646907afee5553"),
            "the scan secret must not reach the UI as hex"
        );

        // An already selected test network is kept.
        assert_eq!(
            summarize_descriptor(TEST_DESCRIPTOR, "testnet4")
                .unwrap()
                .network,
            "testnet4"
        );

        // Spend-secret form: flagged, and the watch-only text replaces it.
        let s = summarize_descriptor(MAINNET_SPSPEND, "signet").unwrap();
        assert!(s.mainnet && s.had_spend_secret);
        assert_eq!(s.network, "bitcoin");
        assert!(s.watch_only.starts_with("sp(spscan1") && !s.watch_only.contains("spspend"));
    }

    #[test]
    fn keys_from_descriptor_fills_spend_key_and_checks_network() {
        let mut cfg = valid_config();
        cfg.spend_pubkey = None;
        let scan = keys_from_descriptor(&mut cfg, TEST_DESCRIPTOR).unwrap();
        assert_eq!(
            scan,
            "7d1c6751d8f381bb24f89a71a193da0664765c71ec77b36dc8646907afee5553"
        );
        assert_eq!(
            cfg.spend_pubkey.as_deref(),
            Some("03aacf9858abb3412fa07834abf3029ad6dfe5ba571f51149c612464daba42e309")
        );
        assert_eq!(validate_setup(&cfg, &scan), Ok(()));

        // Spend private key: only the derived public key is used.
        let mut main = DaemonConfig {
            network: "bitcoin".to_string(),
            ..valid_config()
        };
        let scan = keys_from_descriptor(&mut main, MAINNET_SPSPEND).unwrap();
        assert_eq!(
            scan,
            "0f694e068028a717f8af6b9411f9a133dd3565258714cc226594b34db90c1f2c"
        );
        assert_eq!(
            main.spend_pubkey.as_deref(),
            Some("025cc9856d6f8375350e123978daac200c260cb5b5ae83106cab90484dcd8fcf36")
        );

        let err = keys_from_descriptor(&mut valid_config(), MAINNET_SPSPEND).unwrap_err();
        assert!(err.contains("mainnet"), "{err}");
    }

    #[test]
    fn descriptor_or_start_at_tip_counts_as_configured() {
        let dir = temp_dir("descriptor-configured");
        let config = dir.join("config.toml");
        fs::write(
            &config,
            format!("p2p_node_addr = \"node.example\"\nstart_at_tip = true\ndescriptor = \"{TEST_DESCRIPTOR}\"\n"),
        )
        .unwrap();
        // No key file, no spend_pubkey: the descriptor supplies both.
        assert!(is_configured(
            Some(&config),
            Some(&dir.join("scan.key")),
            &no_env
        ));

        // Without start_at_tip and no bh= annotation, the birthday is missing.
        fs::write(
            &config,
            format!("p2p_node_addr = \"node.example\"\ndescriptor = \"{TEST_DESCRIPTOR}\"\n"),
        )
        .unwrap();
        assert!(!is_configured(
            Some(&config),
            Some(&dir.join("scan.key")),
            &no_env
        ));
    }

    #[tokio::test]
    async fn resolve_peer_reports_dns_failures() {
        let cfg = |p2p: &str| DaemonConfig {
            p2p_node_addr: Some(p2p.to_string()),
            ..valid_config()
        };
        assert_eq!(resolve_peer(&cfg("127.0.0.1:38333")).await, Ok(()));
        assert_eq!(resolve_peer(&cfg("localhost")).await, Ok(()));
        let err = resolve_peer(&cfg("no-such-host.invalid"))
            .await
            .unwrap_err();
        assert!(err.contains("no-such-host.invalid"), "{err}");
    }

    #[test]
    fn write_local_config_persists_toml_and_key_file() {
        let dir = temp_dir("write-local");
        let config_path = dir.join("config.toml");
        let cfg = DaemonConfig {
            key_file: Some(dir.join("scan.key")),
            ..valid_config()
        };

        let key_path = write_local_config(&config_path, &cfg, KEY_HEX).unwrap();
        assert_eq!(key_path, dir.join("scan.key"));

        // Config file readable back as the same DaemonConfig, atomically.
        assert_eq!(friglet_ipc::read_config_toml(&config_path).unwrap(), cfg);
        assert!(
            !config_path.with_extension("toml.tmp").exists(),
            "no temp file may be left behind"
        );

        // Key file content + permissions.
        assert_eq!(fs::read_to_string(&key_path).unwrap().trim(), KEY_HEX);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&key_path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }

        // The pair now passes the configured check.
        assert!(is_configured(Some(&config_path), None, &no_env));
    }
}
