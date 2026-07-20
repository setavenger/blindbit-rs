//! Layered daemon configuration: CLI flags > `FRIGLET_*` environment
//! variables > TOML config file > built-in defaults.
//!
//! The merged shape is [`DaemonConfig`] (defined in `friglet-ipc` so the tray
//! UI can reuse it). The scan secret is handled separately — see
//! [`resolve_scan_secret`].

use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use bitcoin::secp256k1::{PublicKey, SecretKey};
use bitcoin_rev::Network;
use clap::Args;
use figment::Figment;
use figment::providers::{Env, Format, Serialized, Toml};
use serde::Serialize;

pub use friglet_ipc::DaemonConfig;

/// CLI flags for the `scan` command. All fields are optional at the clap
/// level so a config file or environment variables can supply them; required
/// fields are validated after the layers are merged (see [`resolve`]).
///
/// Serialization is used as the top figment layer, so `None` fields must be
/// skipped to avoid clobbering file/env values.
#[derive(Args, Clone, Default, Serialize)]
pub struct ScanArgs {
    /// The scan secret key (32 bytes hex) [deprecated: prefer key file]
    #[arg(long)]
    #[serde(skip_serializing)]
    pub scan_secret: Option<String>,

    /// The spend public key (33 bytes hex string)
    #[arg(long)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spend_pubkey: Option<String>,

    /// Start block height (wallet birthday)
    #[arg(long)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_height: Option<u64>,

    /// Bitcoin P2P node address (host:port)
    #[arg(long)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub p2p_node_addr: Option<String>,

    /// Maximum label number [default: 0]
    #[arg(long)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_label_num: Option<u32>,

    /// Oracle service URL [default: https://oracle.setor.dev]
    #[arg(long)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oracle_url: Option<String>,

    /// Path to save/load scanner state [default: scanner_state.json]
    #[arg(long)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state_file: Option<PathBuf>,

    /// Bitcoin network: bitcoin|signet|testnet|testnet4|regtest [default: bitcoin]
    #[arg(long)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,

    /// HTTP server address [default: 127.0.0.1:8080]
    #[arg(long)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_addr: Option<String>,

    /// Electrum TCP server address [default: 127.0.0.1:50001]
    #[arg(long)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub electrum_addr: Option<String>,

    /// Log level: trace, debug, info, warn, error (overridden by RUST_LOG env var) [default: info]
    #[arg(long)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_level: Option<String>,

    /// Path to the scan secret key file [default: <config dir>/friglet/scan.key]
    #[arg(long)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_file: Option<PathBuf>,

    /// Path to a TOML config file [default: <config dir>/friglet/config.toml]
    #[arg(long)]
    #[serde(skip_serializing)]
    pub config: Option<PathBuf>,

    /// Print the merged configuration as TOML and exit
    #[arg(long)]
    #[serde(skip_serializing)]
    pub print_config: bool,
}

pub fn default_config_path() -> Option<PathBuf> {
    dirs::config_dir().map(|d| d.join("friglet").join("config.toml"))
}

pub fn default_key_file() -> Option<PathBuf> {
    dirs::config_dir().map(|d| d.join("friglet").join("scan.key"))
}

/// Merge all configuration layers for the given CLI args.
///
/// Also returns the config file that was used (if any) so the daemon knows
/// where `SetConfig` should persist changes.
pub fn load(args: &ScanArgs) -> Result<(DaemonConfig, Option<PathBuf>), String> {
    let file = match &args.config {
        Some(path) => {
            if !path.exists() {
                return Err(format!("config file not found: {}", path.display()));
            }
            Some(path.clone())
        }
        None => default_config_path().filter(|p| p.exists()),
    };
    let merged = merge_layers(file.as_deref(), args)?;
    Ok((merged, file))
}

fn merge_layers(file: Option<&Path>, args: &ScanArgs) -> Result<DaemonConfig, String> {
    let mut figment = Figment::from(Serialized::defaults(DaemonConfig::default()));
    if let Some(path) = file {
        figment = figment.merge(Toml::file_exact(path));
    }
    figment
        .merge(Env::prefixed("FRIGLET_"))
        .merge(Serialized::defaults(args.clone()))
        .extract()
        .map_err(|e| format!("invalid configuration: {e}"))
}

/// Fully validated configuration with parsed types, ready for scanner setup.
#[derive(Debug)]
pub struct ResolvedConfig {
    /// The merged plain config, kept for `GetConfig` / `--print-config`.
    pub raw: DaemonConfig,
    pub network: Network,
    pub oracle_url: String,
    pub p2p_addr: SocketAddr,
    pub start_height: u64,
    pub spend_pubkey: PublicKey,
    pub max_label_num: u32,
    pub http_addr: String,
    pub electrum_addr: String,
    pub state_file: PathBuf,
    pub key_file: PathBuf,
    pub control_socket: String,
}

fn missing(key: &str) -> String {
    let flag = key.replace('_', "-");
    let env = key.to_uppercase();
    format!(
        "missing required setting `{key}`: pass --{flag}, set FRIGLET_{env}, or add `{key}` to the config file"
    )
}

pub fn resolve(raw: DaemonConfig) -> Result<ResolvedConfig, String> {
    let network = Network::from_str(&raw.network)
        .map_err(|e| format!("invalid network `{}`: {e}", raw.network))?;

    let p2p = raw
        .p2p_node_addr
        .clone()
        .ok_or_else(|| missing("p2p_node_addr"))?;
    let p2p_addr =
        SocketAddr::from_str(&p2p).map_err(|e| format!("invalid p2p_node_addr `{p2p}`: {e}"))?;

    let start_height = raw.start_height.ok_or_else(|| missing("start_height"))?;

    let spend = raw
        .spend_pubkey
        .clone()
        .ok_or_else(|| missing("spend_pubkey"))?;
    let spend_pubkey = PublicKey::from_str(&spend).map_err(|e| {
        format!(
            "invalid spend_pubkey: {e}. Must be a valid 33-byte hex string representing a secp256k1 public key"
        )
    })?;

    let key_file = raw
        .key_file
        .clone()
        .or_else(default_key_file)
        .ok_or("cannot determine a key file location; set `key_file` in the config")?;

    let control_socket = raw
        .control_socket
        .clone()
        .unwrap_or_else(friglet_ipc::default_socket_path);

    Ok(ResolvedConfig {
        network,
        oracle_url: raw.oracle_url.clone(),
        p2p_addr,
        start_height,
        spend_pubkey,
        max_label_num: raw.max_label_num,
        http_addr: raw.http_addr.clone(),
        electrum_addr: raw.electrum_addr.clone(),
        state_file: raw.state_file.clone(),
        key_file,
        control_socket,
        raw,
    })
}

/// Full validation for a config arriving via `SetConfig`: everything
/// [`resolve`] checks (network, p2p address, start height, spend pubkey)
/// plus checks that would otherwise only surface at startup — mirroring
/// blindbit-lib's `ScannerConfig::validate` (oracle URL scheme) and the
/// HTTP/Electrum bind addresses parsing.
pub fn validate_daemon_config(cfg: &DaemonConfig) -> Result<ResolvedConfig, String> {
    let resolved = resolve(cfg.clone())?;

    if resolved.oracle_url.is_empty() {
        return Err("oracle_url cannot be empty".to_string());
    }
    if !resolved.oracle_url.starts_with("http://") && !resolved.oracle_url.starts_with("https://") {
        return Err(format!(
            "invalid oracle_url `{}`: must start with http:// or https://",
            resolved.oracle_url
        ));
    }
    if resolved.start_height == 0 {
        return Err("invalid start_height 0: must be at least 1".to_string());
    }
    SocketAddr::from_str(&resolved.http_addr)
        .map_err(|e| format!("invalid http_addr `{}`: {e}", resolved.http_addr))?;
    SocketAddr::from_str(&resolved.electrum_addr)
        .map_err(|e| format!("invalid electrum_addr `{}`: {e}", resolved.electrum_addr))?;
    if resolved.state_file.as_os_str().is_empty() {
        return Err("state_file cannot be empty".to_string());
    }

    Ok(resolved)
}

/// Persist `cfg` as pretty TOML to `path` (atomically: temp file + rename),
/// creating parent directories as needed.
pub fn write_config_file(path: &Path, cfg: &DaemonConfig) -> Result<(), String> {
    let describe = |e: String| format!("cannot write config file {}: {e}", path.display());
    let toml = toml::to_string_pretty(cfg).map_err(|e| describe(e.to_string()))?;
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent).map_err(|e| describe(e.to_string()))?;
    }
    let tmp = path.with_extension("toml.tmp");
    std::fs::write(&tmp, toml).map_err(|e| describe(e.to_string()))?;
    std::fs::rename(&tmp, path).map_err(|e| describe(e.to_string()))
}

/// Resolve the scan secret. Precedence: `--scan-secret` flag, then
/// `FRIGLET_SCAN_SECRET` env, then the key file. When the secret arrives via
/// flag or env and the key file does not exist yet, it is written there
/// (0600 on Unix) so subsequent runs need no argv/env secret.
pub fn resolve_scan_secret(cli_secret: Option<&str>, key_file: &Path) -> Result<SecretKey, String> {
    let env_secret = std::env::var("FRIGLET_SCAN_SECRET")
        .ok()
        .filter(|s| !s.trim().is_empty());

    let (hex_str, from_key_file) = if let Some(s) = cli_secret {
        (s.trim().to_string(), false)
    } else if let Some(s) = env_secret {
        (s.trim().to_string(), false)
    } else if key_file.exists() {
        let contents = std::fs::read_to_string(key_file)
            .map_err(|e| format!("cannot read key file {}: {e}", key_file.display()))?;
        let line = contents
            .lines()
            .map(str::trim)
            .find(|l| !l.is_empty())
            .ok_or_else(|| format!("key file {} is empty", key_file.display()))?;
        (line.to_string(), true)
    } else {
        return Err(format!(
            "no scan secret available: create the key file at {}, set FRIGLET_SCAN_SECRET, or pass --scan-secret (deprecated)",
            key_file.display()
        ));
    };

    let secret = SecretKey::from_str(&hex_str).map_err(|e| {
        format!(
            "invalid scan secret: {e}. Must be a valid 32-byte hex string representing a secp256k1 secret key"
        )
    })?;

    if !from_key_file && !key_file.exists() {
        write_key_file(key_file, &hex_str)?;
        tracing::info!(path = %key_file.display(), "scan secret written to key file");
    }

    Ok(secret)
}

/// Validate `hex` as a 32-byte secp256k1 secret key and write/replace the
/// key file at `path` (0600 on Unix). Backs the `SetScanKey` control verb.
pub fn replace_scan_key(path: &Path, hex: &str) -> Result<SecretKey, String> {
    let hex = hex.trim();
    let secret = SecretKey::from_str(hex).map_err(|e| {
        format!(
            "invalid scan key: {e}. Must be a valid 32-byte hex string representing a secp256k1 secret key"
        )
    })?;
    write_key_file_impl(path, hex, true)?;
    Ok(secret)
}

fn write_key_file(path: &Path, secret_hex: &str) -> Result<(), String> {
    write_key_file_impl(path, secret_hex, false)
}

fn write_key_file_impl(path: &Path, secret_hex: &str, overwrite: bool) -> Result<(), String> {
    let describe = |e: std::io::Error| format!("cannot write key file {}: {e}", path.display());
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent).map_err(describe)?;
    }

    let mut options = std::fs::OpenOptions::new();
    options.write(true);
    if overwrite {
        options.create(true).truncate(true);
    } else {
        options.create_new(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    // On Windows the file inherits the profile directory's default ACL, which
    // restricts access to the owning user — no tighter per-file ceiling is set.
    let mut file = options.open(path).map_err(describe)?;
    // `mode(0o600)` only applies on creation; enforce it when replacing a
    // pre-existing key file too.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(describe)?;
    }
    file.write_all(secret_hex.as_bytes()).map_err(describe)?;
    file.write_all(b"\n").map_err(describe)?;
    Ok(())
}

/// Restrict the state file to owner read/write.
///
/// Limitation: blindbit-lib's `save_to_file` unconditionally embeds
/// `secret_scan_hex` in the state JSON and `from_changeset` requires it on
/// restore, so friglet cannot stop the secret from being persisted there
/// without modifying blindbit-lib. Tightening permissions is the best we can
/// do at this layer.
pub fn tighten_state_file_perms(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if path.exists()
            && let Err(e) = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        {
            tracing::warn!(path = %path.display(), error = %e, "failed to tighten state file permissions");
        }
    }
    #[cfg(not(unix))]
    let _ = path;
}

#[cfg(test)]
#[allow(clippy::result_large_err)] // figment::Jail closures return figment::Error
mod tests {
    use super::*;

    const SECRET_HEX: &str = "0000000000000000000000000000000000000000000000000000000000000001";

    #[test]
    fn precedence_file_env_cli() {
        figment::Jail::expect_with(|jail| {
            jail.create_file("config.toml", r#"oracle_url = "http://file.example""#)?;
            let file = Some(Path::new("config.toml"));

            let cfg = merge_layers(file, &ScanArgs::default()).unwrap();
            assert_eq!(cfg.oracle_url, "http://file.example");

            jail.set_env("FRIGLET_ORACLE_URL", "http://env.example");
            let cfg = merge_layers(file, &ScanArgs::default()).unwrap();
            assert_eq!(cfg.oracle_url, "http://env.example");

            let args = ScanArgs {
                oracle_url: Some("http://cli.example".to_string()),
                ..ScanArgs::default()
            };
            let cfg = merge_layers(file, &args).unwrap();
            assert_eq!(cfg.oracle_url, "http://cli.example");

            assert_eq!(cfg.network, "bitcoin");
            Ok(())
        });
    }

    #[test]
    fn config_file_alone_supplies_required_fields() {
        figment::Jail::expect_with(|jail| {
            jail.create_file(
                "config.toml",
                r#"
                    spend_pubkey = "02e6642fd69bd211f93f7f1f36ca51a26a5290eb2dd1b0d8279a87bb0d480c8443"
                    start_height = 100
                    p2p_node_addr = "127.0.0.1:8333"
                    network = "signet"
                "#,
            )?;
            let cfg = merge_layers(Some(Path::new("config.toml")), &ScanArgs::default()).unwrap();
            let resolved = resolve(cfg).unwrap();
            assert_eq!(resolved.start_height, 100);
            assert_eq!(resolved.network, Network::Signet);
            Ok(())
        });
    }

    #[test]
    fn resolve_reports_missing_required_fields() {
        let err = resolve(DaemonConfig::default()).unwrap_err();
        assert!(err.contains("p2p_node_addr"), "unexpected error: {err}");
    }

    #[test]
    fn scan_secret_loaded_from_key_file() {
        figment::Jail::expect_with(|jail| {
            let key_path = jail.directory().join("scan.key");
            std::fs::write(&key_path, format!("{SECRET_HEX}\n")).unwrap();

            let secret = resolve_scan_secret(None, &key_path).unwrap();
            assert_eq!(secret, SecretKey::from_str(SECRET_HEX).unwrap());
            Ok(())
        });
    }

    #[test]
    fn scan_secret_flag_writes_key_file_with_0600() {
        figment::Jail::expect_with(|jail| {
            let key_path = jail.directory().join("subdir").join("scan.key");

            let secret = resolve_scan_secret(Some(SECRET_HEX), &key_path).unwrap();
            assert_eq!(secret, SecretKey::from_str(SECRET_HEX).unwrap());

            let written = std::fs::read_to_string(&key_path).unwrap();
            assert_eq!(written.trim(), SECRET_HEX);

            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = std::fs::metadata(&key_path).unwrap().permissions().mode();
                assert_eq!(mode & 0o777, 0o600);
            }
            Ok(())
        });
    }
}
