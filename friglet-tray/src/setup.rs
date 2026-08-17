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

/// Environment variables the daemon's config layering honors for the
/// settings the tray checks (`figment::Env::prefixed("FRIGLET_")` plus the
/// scan-secret override in `resolve_scan_secret`).
const ENV_P2P_NODE_ADDR: &str = "FRIGLET_P2P_NODE_ADDR";
const ENV_START_HEIGHT: &str = "FRIGLET_START_HEIGHT";
const ENV_SPEND_PUBKEY: &str = "FRIGLET_SPEND_PUBKEY";
const ENV_SCAN_SECRET: &str = "FRIGLET_SCAN_SECRET";

const NETWORKS: [&str; 5] = ["bitcoin", "signet", "testnet", "testnet4", "regtest"];

/// Is the daemon plausibly configured, i.e. is spawning it likely to get
/// past `missing required setting ...`? Conservative merged view:
///
/// - the required settings (`p2p_node_addr`, `start_height`, `spend_pubkey`)
///   are each present in the config file at `config_path` OR supplied via
///   their `FRIGLET_*` environment variable, AND
/// - a scan secret is available: the key file (the config's `key_file` or
///   `default_key_file`) exists, or `FRIGLET_SCAN_SECRET` is set.
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

    let p2p = file_has(|c| c.p2p_node_addr.is_some()) || env_set(ENV_P2P_NODE_ADDR);
    let start = file_has(|c| c.start_height.is_some()) || env_set(ENV_START_HEIGHT);
    let spend = file_has(|c| c.spend_pubkey.is_some()) || env_set(ENV_SPEND_PUBKEY);

    let key_file = file_cfg
        .as_ref()
        .and_then(|c| c.key_file.clone())
        .or_else(|| default_key_file.map(Path::to_path_buf));
    let secret = env_set(ENV_SCAN_SECRET) || key_file.is_some_and(|p| p.exists());

    p2p && start && spend && secret
}

/// [`is_configured`] fed from the real environment and default paths.
pub fn is_configured_from_env() -> bool {
    is_configured(
        friglet_ipc::default_config_path().as_deref(),
        friglet_ipc::default_key_file().as_deref(),
        &|key| std::env::var(key).ok(),
    )
}

/// Validate a setup-mode save tray-side, mirroring the daemon's own startup
/// validation with friendlier messages. Hex fields are checked for length
/// only; full secp256k1 validation happens daemon-side at startup.
pub fn validate_setup(cfg: &DaemonConfig, scan_key: &str) -> Result<(), String> {
    if !NETWORKS.contains(&cfg.network.as_str()) {
        return Err(format!(
            "invalid network `{}`: must be one of {}",
            cfg.network,
            NETWORKS.join(", ")
        ));
    }
    if !cfg.oracle_url.starts_with("http://") && !cfg.oracle_url.starts_with("https://") {
        return Err(format!(
            "invalid oracle URL `{}`: must start with http:// or https://",
            cfg.oracle_url
        ));
    }

    let p2p = cfg
        .p2p_node_addr
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or("P2P node address is required (host:port of a Bitcoin node)")?;
    SocketAddr::from_str(p2p)
        .map_err(|e| format!("invalid P2P node address `{p2p}`: {e} (expected ip:port)"))?;

    match cfg.start_height {
        None => return Err("start height (wallet birthday) is required".to_string()),
        Some(0) => return Err("invalid start height 0: must be at least 1".to_string()),
        Some(_) => {}
    }

    let spend = cfg
        .spend_pubkey
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or("spend public key is required (33-byte hex)")?;
    if spend.len() != 66 || !is_hex(spend) {
        return Err("invalid spend public key: must be 66 hex characters (33 bytes)".to_string());
    }

    let key = scan_key.trim();
    if key.is_empty() {
        return Err("scan key is required for first-time setup (32-byte hex)".to_string());
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
                    p2p_node_addr: Some("not-an-addr".to_string()),
                    ..valid_config()
                },
                KEY_HEX,
                "invalid P2P node address",
            ),
            (
                DaemonConfig {
                    start_height: None,
                    ..valid_config()
                },
                KEY_HEX,
                "start height (wallet birthday) is required",
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
            (valid_config(), "", "scan key is required"),
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
