//! Layered daemon configuration: CLI flags > `FRIGLET_*` environment
//! variables > TOML config file > built-in defaults.
//!
//! The merged shape is [`DaemonConfig`] (defined in `friglet-ipc` so the tray
//! UI can reuse it). The scan secret is handled separately — see
//! [`resolve_scan_secret`].
//!
//! A Silent Payments descriptor (`descriptor = "sp(spscan1…)"` in the config
//! file, or `FRIGLET_DESCRIPTOR`) can stand in for `spend_pubkey`, the scan
//! key and, via its `bh=` annotation, `start_height`. It carries the scan
//! secret, so it is read beside — never into — `DaemonConfig`: `GetConfig`
//! and config rewrites only ever see the derived `spend_pubkey`, and the scan
//! key is moved into the 0600 key file at startup.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use bitcoin::secp256k1::{PublicKey, SecretKey};
use bitcoin_rev::Network;
use clap::Args;
use figment::Figment;
use figment::providers::{Env, Format, Serialized, Toml};
use serde::{Deserialize, Serialize};

pub use friglet_ipc::DaemonConfig;
use friglet_ipc::descriptor::SpDescriptor;

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

    /// New wallet: without --start-height, start at the oracle's current tip
    /// (persisted as start_height in the config file on first start)
    #[arg(long)]
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub start_at_tip: bool,

    /// Bitcoin P2P node address (host:port)
    #[arg(long)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub p2p_node_addr: Option<String>,

    /// Maximum label number [default: 0]
    #[arg(long)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_label_num: Option<u32>,

    /// Oracle service URL [default: the network's hosted oracle (bitcoin, signet)]
    #[arg(long)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oracle_url: Option<String>,

    /// Path to save/load scanner state [default: `<config dir>/friglet/scanner_state.json`]
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

/// Result of [`load`].
pub struct Loaded {
    /// Merged settings; a configured descriptor's spend key (and birth
    /// height, when `start_height` is unset) are already applied.
    pub config: DaemonConfig,
    /// The config file that was used, so `SetConfig` knows where to persist.
    pub file: Option<PathBuf>,
    /// The configured SP descriptor, if any (holds the scan secret).
    pub descriptor: Option<SpDescriptor>,
}

/// Merge all configuration layers for the given CLI args.
pub fn load(args: &ScanArgs) -> Result<Loaded, String> {
    let file = match &args.config {
        Some(path) => {
            if !path.exists() {
                return Err(format!("config file not found: {}", path.display()));
            }
            Some(path.clone())
        }
        None => friglet_ipc::default_config_path().filter(|p| p.exists()),
    };
    let mut config = merge_layers(file.as_deref(), args)?;
    let descriptor = load_descriptor(file.as_deref(), args)?;
    if let Some(d) = &descriptor {
        apply_descriptor(&mut config, d)?;
    }
    Ok(Loaded {
        config,
        file,
        descriptor,
    })
}

/// Settings that carry key material: read from the same file/env layers as
/// [`DaemonConfig`] but deliberately kept out of it.
#[derive(Deserialize, Default)]
struct SecretSettings {
    descriptor: Option<String>,
}

fn load_descriptor(file: Option<&Path>, args: &ScanArgs) -> Result<Option<SpDescriptor>, String> {
    let secrets: SecretSettings = user_layers(file, args)
        .extract()
        .map_err(|e| format!("invalid configuration: {e}"))?;
    secrets
        .descriptor
        .filter(|d| !d.trim().is_empty())
        .map(|d| SpDescriptor::parse(&d).map_err(|e| format!("invalid descriptor: {e}")))
        .transpose()
}

/// Fold a configured descriptor into the merged settings. Refuses a
/// descriptor carrying the spend private key: friglet is watch-only and the
/// config file must not keep that key on disk.
pub fn apply_descriptor(cfg: &mut DaemonConfig, d: &SpDescriptor) -> Result<(), String> {
    if d.had_spend_secret {
        return Err(
            "the configured descriptor contains the wallet's spend PRIVATE key (spspend). \
             friglet is watch-only and will not keep that key on disk: replace it with the \
             watch-only descriptor (in Sparrow: wallet Settings tab, right-click Descriptor, \
             Copy Output Descriptor — it contains spscan, not spspend)"
                .to_string(),
        );
    }
    if !d.matches_network(&cfg.network) {
        return Err(format!(
            "{}: set `network` to match the wallet",
            d.network_mismatch(&cfg.network)
        ));
    }
    let spend = d.spend_pubkey_hex();
    match cfg.spend_pubkey.as_deref().map(str::trim) {
        Some(existing) if !existing.eq_ignore_ascii_case(&spend) => {
            return Err(format!(
                "the descriptor's spend key ({spend}) differs from spend_pubkey ({existing}); \
                 remove one of them"
            ));
        }
        _ => cfg.spend_pubkey = Some(spend),
    }
    if cfg.start_height.is_none()
        && let Some(bh) = d.birth_height
    {
        cfg.start_height = Some(bh);
    }
    Ok(())
}

/// Move a configured descriptor's scan secret into the key file (0600),
/// replacing a different key, so later restarts and settings rewrites that
/// drop the descriptor keep working.
pub fn store_descriptor_scan_key(d: &SpDescriptor, key_file: &Path) -> Result<(), String> {
    let current = std::fs::read_to_string(key_file)
        .ok()
        .and_then(|text| SecretKey::from_str(key_file_line(&text)?).ok());
    if current == Some(d.scan_secret) {
        return Ok(());
    }
    friglet_ipc::write_key_file(key_file, &d.scan_secret_hex(), true)?;
    tracing::info!(path = %key_file.display(), "scan key from the configured descriptor written to the key file");
    Ok(())
}

/// The key in a key file: its first non-empty line, trimmed.
fn key_file_line(text: &str) -> Option<&str> {
    text.lines().map(str::trim).find(|l| !l.is_empty())
}

/// The user-supplied layers (file, env, CLI) without the built-in defaults.
fn user_layers(file: Option<&Path>, args: &ScanArgs) -> Figment {
    let mut figment = Figment::new();
    if let Some(path) = file {
        figment = figment.merge(Toml::file_exact(path));
    }
    figment
        .merge(Env::prefixed("FRIGLET_"))
        .merge(Serialized::defaults(args.clone()))
}

fn merge_layers(file: Option<&Path>, args: &ScanArgs) -> Result<DaemonConfig, String> {
    let user = user_layers(file, args);
    let mut merged: DaemonConfig = Figment::from(Serialized::defaults(DaemonConfig::default()))
        .merge(user.clone())
        .extract()
        .map_err(|e| format!("invalid configuration: {e}"))?;
    // The built-in oracle default is the mainnet one; when no layer set
    // `oracle_url`, follow the configured network instead so `network =
    // "signet"` alone is a working config.
    if user.find_value("oracle_url").is_err()
        && let Some(hosted) = friglet_ipc::network::hosted_oracle_url(&merged.network)
    {
        merged.oracle_url = hosted.to_string();
    }
    Ok(merged)
}

/// Fully validated configuration with parsed types, ready for scanner setup.
/// Settings that need no parsing (`oracle_url`, `max_label_num`, the bind
/// addresses) are read from `raw`.
#[derive(Debug)]
pub struct ResolvedConfig {
    /// The merged plain config, kept for `GetConfig` / `--print-config`.
    pub raw: DaemonConfig,
    pub network: Network,
    pub p2p_addr: SocketAddr,
    pub start_height: u64,
    pub spend_pubkey: PublicKey,
    /// The wallet's state file; `raw.state_file` keeps the configured path.
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

    if let Some(hosted_for) = friglet_ipc::network::hosted_oracle_network(&raw.oracle_url)
        && hosted_for != raw.network
    {
        let fix = match friglet_ipc::network::hosted_oracle_url(&raw.network) {
            Some(url) => format!("set oracle_url to {url}"),
            None => format!(
                "there is no hosted oracle for {}; set oracle_url to your own BlindBit oracle",
                raw.network
            ),
        };
        return Err(format!(
            "oracle_url {} is the hosted {hosted_for} oracle, but network is {}: {fix}",
            raw.oracle_url, raw.network
        ));
    }

    let p2p = raw
        .p2p_node_addr
        .clone()
        .ok_or_else(|| missing("p2p_node_addr"))?;
    // Accepts host:port, ip:port and a bare host (network default port);
    // hostnames are resolved here, i.e. at every daemon (re)start.
    let p2p_addr = friglet_ipc::network::resolve_peer_addr(&p2p, &raw.network)
        .map_err(|e| format!("invalid p2p_node_addr `{p2p}`: {e}"))?;

    let start_height = match raw.start_height {
        Some(h) => h,
        None if raw.start_at_tip => {
            return Err(
                "start_at_tip is set but the oracle tip has not been resolved yet".to_string(),
            );
        }
        None => return Err(missing("start_height")),
    };

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
        .or_else(friglet_ipc::default_key_file)
        .ok_or("cannot determine a key file location; set `key_file` in the config")?;

    let control_socket = raw
        .control_socket
        .clone()
        .unwrap_or_else(friglet_ipc::default_socket_path);

    // Belt-and-suspenders: old configs / CWD-relative defaults land state
    // next to the tray binary's CWD. Rewrite the bare default name to the
    // platform config-dir path when available.
    let mut raw = raw;
    if raw.state_file.as_os_str() == "scanner_state.json"
        && let Some(absolute) = friglet_ipc::default_state_file()
    {
        raw.state_file = absolute;
    }

    Ok(ResolvedConfig {
        network,
        p2p_addr,
        start_height,
        spend_pubkey,
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
    let raw = &resolved.raw;

    if raw.oracle_url.is_empty() {
        return Err("oracle_url cannot be empty".to_string());
    }
    if !raw.oracle_url.starts_with("http://") && !raw.oracle_url.starts_with("https://") {
        return Err(format!(
            "invalid oracle_url `{}`: must start with http:// or https://",
            raw.oracle_url
        ));
    }
    if resolved.start_height == 0 {
        return Err("invalid start_height 0: must be at least 1".to_string());
    }
    SocketAddr::from_str(&raw.http_addr)
        .map_err(|e| format!("invalid http_addr `{}`: {e}", raw.http_addr))?;
    SocketAddr::from_str(&raw.electrum_addr)
        .map_err(|e| format!("invalid electrum_addr `{}`: {e}", raw.electrum_addr))?;
    if resolved.state_file.as_os_str().is_empty() {
        return Err("state_file cannot be empty".to_string());
    }

    Ok(resolved)
}

/// How long the new-wallet birthday lookup waits for the oracle.
const ORACLE_TIP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// Current chain tip according to the BlindBit oracle at `oracle_url`.
pub async fn fetch_oracle_tip(oracle_url: &str) -> Result<u64, String> {
    let fetch = async {
        let mut client = blindbit_lib::OracleServiceClient::connect(oracle_url.to_string())
            .await
            .map_err(|e| format!("cannot connect to oracle {oracle_url}: {e}"))?;
        let info = client
            .get_info(tonic::Request::new(()))
            .await
            .map_err(|e| format!("oracle {oracle_url} GetInfo failed: {e}"))?;
        Ok(info.into_inner().height)
    };
    tokio::time::timeout(ORACLE_TIP_TIMEOUT, fetch)
        .await
        .map_err(|_| format!("oracle {oracle_url} did not answer within {ORACLE_TIP_TIMEOUT:?}"))?
}

/// New-wallet birthday: when `start_height` is unset and `start_at_tip` is
/// set, use the oracle's current tip as `start_height` and clear the flag.
/// Returns the resolved height when `cfg` changed, so the caller persists it
/// (a birthday that moved forward on every restart would skip blocks).
pub async fn resolve_start_at_tip(cfg: &mut DaemonConfig) -> Result<Option<u64>, String> {
    if cfg.start_height.is_some() {
        cfg.start_at_tip = false;
        return Ok(None);
    }
    if !cfg.start_at_tip {
        return Ok(None);
    }
    let tip = fetch_oracle_tip(&cfg.oracle_url)
        .await
        .map_err(|e| format!("cannot start a new wallet at the chain tip: {e}"))?;
    // The oracle never reports height 0 for a real chain; guard anyway since
    // start_height 0 is invalid.
    let height = tip.max(1);
    cfg.start_height = Some(height);
    cfg.start_at_tip = false;
    Ok(Some(height))
}

/// Record a resolved birthday in the config file at `path`: set
/// `start_height`, drop `start_at_tip`, keep every other key as written
/// (no defaults are materialised, so env/CLI layering is unaffected).
/// Creates the file when it does not exist yet (env-only configurations).
pub fn persist_start_height(path: &Path, height: u64) -> Result<(), String> {
    let describe = |e: String| format!("cannot record start_height in {}: {e}", path.display());
    let mut table: toml::Table = if path.exists() {
        let text = std::fs::read_to_string(path).map_err(|e| describe(e.to_string()))?;
        toml::from_str(&text).map_err(|e| describe(e.to_string()))?
    } else {
        toml::Table::new()
    };
    let height = i64::try_from(height).map_err(|e| describe(e.to_string()))?;
    table.insert("start_height".to_string(), toml::Value::Integer(height));
    table.remove("start_at_tip");
    let text = toml::to_string_pretty(&table).map_err(|e| describe(e.to_string()))?;
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent).map_err(|e| describe(e.to_string()))?;
    }
    let tmp = path.with_extension("toml.tmp");
    std::fs::write(&tmp, text).map_err(|e| describe(e.to_string()))?;
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
        let line = key_file_line(&contents)
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
        friglet_ipc::write_key_file(key_file, &hex_str, false)?;
        tracing::info!(path = %key_file.display(), "scan secret written to key file");
    }

    Ok(secret)
}

/// The scan secret / spend pubkey hex a scanner state file was written for.
fn state_file_keys(path: &Path) -> Option<(String, String)> {
    let json = std::fs::read_to_string(path).ok()?;
    let value: serde_json::Value = serde_json::from_str(&json).ok()?;
    let scan = value.get("secret_scan_hex")?.as_str()?.to_ascii_lowercase();
    let spend = value
        .get("public_spend_hex")?
        .as_str()?
        .to_ascii_lowercase();
    Some((scan, spend))
}

fn same_wallet(path: &Path, scan_secret: &SecretKey, spend_pubkey: &PublicKey) -> Option<bool> {
    let (scan, spend) = state_file_keys(path)?;
    Some(
        scan == hex::encode(scan_secret.secret_bytes())
            && spend == hex::encode(spend_pubkey.serialize()),
    )
}

/// The scanner state file actually used for this wallet.
///
/// blindbit-lib restores the keys embedded in the state file, so one state
/// file must never be shared between wallets:
///
/// - The default location (`<config dir>/friglet/scanner_state.json`) is
///   keyed by wallet: `scanner_state-<network>-<id>.json` next to it, `id`
///   being a hash of the scan and spend public keys. Changing keys therefore
///   starts a fresh state, and switching back finds the old one again. A
///   legacy unkeyed default file of this same wallet is renamed into place.
/// - An explicitly configured path is used as is, but refused when it holds
///   another wallet's state (instead of silently scanning the old keys).
pub fn wallet_state_file(
    configured: &Path,
    network: &str,
    scan_secret: &SecretKey,
    spend_pubkey: &PublicKey,
) -> Result<PathBuf, String> {
    let is_default = friglet_ipc::default_state_file().as_deref() == Some(configured)
        || configured.as_os_str() == "scanner_state.json";
    if !is_default {
        if same_wallet(configured, scan_secret, spend_pubkey) == Some(false) {
            return Err(format!(
                "state file {} belongs to a different wallet; point state_file at a new path \
                 (or remove it) — or drop the state_file setting so friglet keeps one state \
                 file per wallet",
                configured.display()
            ));
        }
        return Ok(configured.to_path_buf());
    }

    use bitcoin::hashes::{Hash, sha256};
    let scan_pubkey =
        PublicKey::from_secret_key(&bitcoin::secp256k1::Secp256k1::new(), scan_secret);
    let mut engine = sha256::Hash::engine();
    bitcoin::hashes::HashEngine::input(&mut engine, &scan_pubkey.serialize());
    bitcoin::hashes::HashEngine::input(&mut engine, &spend_pubkey.serialize());
    let id = hex::encode(&sha256::Hash::from_engine(engine).to_byte_array()[..4]);
    let keyed = configured.with_file_name(format!("scanner_state-{network}-{id}.json"));

    if !keyed.exists() && same_wallet(configured, scan_secret, spend_pubkey) == Some(true) {
        std::fs::rename(configured, &keyed).map_err(|e| {
            format!(
                "cannot move {} to {}: {e}",
                configured.display(),
                keyed.display()
            )
        })?;
        let legacy_headers = crate::blockheader::sidecar_path(configured);
        if legacy_headers.exists() {
            let _ = std::fs::rename(&legacy_headers, crate::blockheader::sidecar_path(&keyed));
        }
        // Unconfirmed broadcasts belong to this wallet too.
        let legacy_pending = crate::blockheader::pending_path(configured);
        if legacy_pending.exists() {
            let _ = std::fs::rename(&legacy_pending, crate::blockheader::pending_path(&keyed));
        }
        tracing::info!(from = %configured.display(), to = %keyed.display(), "moved scanner state to its per-wallet file");
    }
    Ok(keyed)
}

/// Sidecar recording the lowest start height `state_file` has scanned from.
fn birthday_sidecar(state_file: &Path) -> PathBuf {
    state_file.with_extension("birthday.json")
}

/// Rescan when the wallet birthday moved back: if `start_height` is below
/// the height the existing state was scanned from, the state is moved aside
/// (`*.json.bak`) so scanning starts over from the new birthday. Returns the
/// previous birthday when that happened. Moving the birthday forward keeps
/// the state (it already covers the later range).
pub fn reconcile_birthday(state_file: &Path, start_height: u64) -> Result<Option<u64>, String> {
    let sidecar = birthday_sidecar(state_file);
    let recorded = std::fs::read_to_string(&sidecar)
        .ok()
        .and_then(|t| serde_json::from_str::<serde_json::Value>(&t).ok())
        .and_then(|v| v.get("start_height")?.as_u64());
    let record = |height: u64| {
        std::fs::write(
            &sidecar,
            serde_json::json!({ "start_height": height }).to_string(),
        )
        .map_err(|e| format!("cannot write {}: {e}", sidecar.display()))
    };
    match recorded {
        Some(previous) if start_height < previous => {
            if state_file.exists() {
                let backup = state_file.with_extension("json.bak");
                std::fs::rename(state_file, &backup).map_err(|e| {
                    format!(
                        "cannot move {} aside for a rescan: {e}",
                        state_file.display()
                    )
                })?;
            }
            record(start_height)?;
            Ok(Some(previous))
        }
        Some(_) => Ok(None),
        None => {
            if let Some(parent) = sidecar.parent()
                && !parent.as_os_str().is_empty()
            {
                std::fs::create_dir_all(parent)
                    .map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
            }
            record(start_height)?;
            Ok(None)
        }
    }
}

/// Restrict the state file to owner read/write.
///
/// Limitation: blindbit-lib's `save_to_file` unconditionally embeds
/// `secret_scan_hex` in the state JSON and `from_changeset` requires it on
/// restore, so friglet cannot stop the secret from being persisted there
/// without modifying blindbit-lib. Tightening permissions is the best we can
/// do at this layer. Also used for a config file holding a `descriptor`
/// (which contains the scan secret).
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

    /// Watch-only descriptor for scan key 0f69…, spend pubkey 025c…
    /// (drongo's test keys), with a birth height annotation.
    const MAINNET_DESCRIPTOR: &str = "sp([deadbeef/352h/0h/0h]spscan1qpa55up5q9zn30790dw2pr7dpx0wn2ef9su2vcgn9jje5mwgvrukqyhxfs4kklqm4x58pywtcm2kzqrpxpj6mtt5rzpk2hyzgfhxclnekj2vrpm)?bh=850000#ssufct9p";
    const MAINNET_DESCRIPTOR_SPEND: &str =
        "025cc9856d6f8375350e123978daac200c260cb5b5ae83106cab90484dcd8fcf36";
    const MAINNET_DESCRIPTOR_SCAN: &str =
        "0f694e068028a717f8af6b9411f9a133dd3565258714cc226594b34db90c1f2c";
    /// Sparrow's testnet fixture (no birth height).
    const TEST_DESCRIPTOR: &str = "sp([0f056943/352h/1h/0h]tspscan1q05wxw5wc7wqmkf8cnfc6ry76qej8vhr3a3mmxmwgv35s0tlw24fs82k0npv2hv6p97s8sd9t7vpf44kluka9w863zjwxzfrym2ay9ccfzt06c4)#7eve6al9";

    fn load_from(jail: &figment::Jail, toml: &str) -> Result<Loaded, String> {
        jail.create_file("config.toml", toml).unwrap();
        load(&ScanArgs {
            config: Some(jail.directory().join("config.toml")),
            ..ScanArgs::default()
        })
    }

    #[test]
    fn descriptor_supplies_spend_key_and_birthday() {
        figment::Jail::expect_with(|jail| {
            let loaded = load_from(
                jail,
                &format!(
                    "descriptor = \"{MAINNET_DESCRIPTOR}\"\np2p_node_addr = \"127.0.0.1:8333\"\n"
                ),
            )
            .unwrap();
            assert_eq!(
                loaded.config.spend_pubkey.as_deref(),
                Some(MAINNET_DESCRIPTOR_SPEND)
            );
            assert_eq!(loaded.config.start_height, Some(850_000));
            let d = loaded.descriptor.expect("descriptor loaded");
            assert_eq!(d.scan_secret_hex(), MAINNET_DESCRIPTOR_SCAN);
            // The secret never reaches the shared settings struct.
            let toml = toml::to_string(&loaded.config).unwrap();
            assert!(!toml.contains("spscan") && !toml.contains(MAINNET_DESCRIPTOR_SCAN));

            // The address friglet serves matches the descriptor's.
            let scan_pk =
                PublicKey::from_secret_key(&bitcoin::secp256k1::Secp256k1::new(), &d.scan_secret);
            let code = bdk_sp::encoding::SilentPaymentCode::new_v0(
                scan_pk,
                d.spend_pubkey,
                bitcoin::Network::Bitcoin,
            );
            assert_eq!(code.to_string(), d.sp_address("bitcoin"));

            // Explicit start_height wins over the annotation.
            let loaded = load_from(
                jail,
                &format!("descriptor = \"{MAINNET_DESCRIPTOR}\"\nstart_height = 900000\n"),
            )
            .unwrap();
            assert_eq!(loaded.config.start_height, Some(900_000));
            Ok(())
        });
    }

    #[test]
    fn descriptor_from_env() {
        figment::Jail::expect_with(|jail| {
            jail.set_env("FRIGLET_DESCRIPTOR", TEST_DESCRIPTOR);
            let loaded = load_from(jail, "network = \"signet\"\n").unwrap();
            assert!(loaded.descriptor.is_some());
            assert_eq!(
                loaded.config.spend_pubkey.as_deref(),
                Some("03aacf9858abb3412fa07834abf3029ad6dfe5ba571f51149c612464daba42e309")
            );
            Ok(())
        });
    }

    #[test]
    fn descriptor_errors_are_actionable() {
        figment::Jail::expect_with(|jail| {
            // Test-network key, default network bitcoin.
            let err = load_from(jail, &format!("descriptor = \"{TEST_DESCRIPTOR}\"\n"))
                .err()
                .unwrap();
            assert!(
                err.contains("test-network") && err.contains("network"),
                "{err}"
            );

            // Conflicting explicit spend_pubkey.
            let err = load_from(
                jail,
                &format!(
                    "descriptor = \"{MAINNET_DESCRIPTOR}\"\nspend_pubkey = \"02e6642fd69bd211f93f7f1f36ca51a26a5290eb2dd1b0d8279a87bb0d480c8443\"\n"
                ),
            )
            .err()
            .unwrap();
            assert!(err.contains("differs from spend_pubkey"), "{err}");

            // Spend private key on disk is refused.
            let err = load_from(
                jail,
                "descriptor = \"sp(spspend1qpa55up5q9zn30790dw2pr7dpx0wn2ef9su2vcgn9jje5mwgvrukf66kc2h8rg9l0sn5rdzfwtftrj2lm5p06tktue63sufn02s8q3vch3lrh8)\"\n",
            )
            .err()
            .unwrap();
            assert!(
                err.contains("spend PRIVATE key") && err.contains("Copy Output Descriptor"),
                "{err}"
            );

            // Garbage.
            let err = load_from(jail, "descriptor = \"sp(nope)\"\n")
                .err()
                .unwrap();
            assert!(err.contains("invalid descriptor"), "{err}");
            Ok(())
        });
    }

    #[test]
    fn descriptor_scan_key_moves_into_key_file() {
        figment::Jail::expect_with(|jail| {
            let d = SpDescriptor::parse(MAINNET_DESCRIPTOR).unwrap();
            let key_path = jail.directory().join("keys").join("scan.key");
            store_descriptor_scan_key(&d, &key_path).unwrap();
            assert_eq!(
                std::fs::read_to_string(&key_path).unwrap().trim(),
                MAINNET_DESCRIPTOR_SCAN
            );
            // A different key in the file is replaced by the descriptor's.
            std::fs::write(&key_path, format!("{SECRET_HEX}\n")).unwrap();
            store_descriptor_scan_key(&d, &key_path).unwrap();
            assert_eq!(resolve_scan_secret(None, &key_path).unwrap(), d.scan_secret);
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = std::fs::metadata(&key_path).unwrap().permissions().mode();
                assert_eq!(mode & 0o777, 0o600);
            }
            Ok(())
        });
    }

    #[test]
    fn oracle_url_follows_network_unless_set() {
        figment::Jail::expect_with(|jail| {
            let loaded = load_from(jail, "network = \"signet\"\n").unwrap();
            assert_eq!(loaded.config.oracle_url, "https://signet.oracle.setor.dev");

            let loaded = load_from(jail, "network = \"bitcoin\"\n").unwrap();
            assert_eq!(loaded.config.oracle_url, "https://oracle.setor.dev");

            let loaded = load_from(
                jail,
                "network = \"signet\"\noracle_url = \"http://127.0.0.1:7000\"\n",
            )
            .unwrap();
            assert_eq!(loaded.config.oracle_url, "http://127.0.0.1:7000");
            Ok(())
        });
    }

    fn resolvable(network: &str, oracle_url: &str, p2p: &str) -> DaemonConfig {
        DaemonConfig {
            network: network.to_string(),
            oracle_url: oracle_url.to_string(),
            p2p_node_addr: Some(p2p.to_string()),
            start_height: Some(1),
            spend_pubkey: Some(
                "02e6642fd69bd211f93f7f1f36ca51a26a5290eb2dd1b0d8279a87bb0d480c8443".to_string(),
            ),
            ..DaemonConfig::default()
        }
    }

    #[test]
    fn hosted_oracle_for_another_network_is_rejected() {
        let err = resolve(resolvable(
            "signet",
            "https://oracle.setor.dev",
            "127.0.0.1",
        ))
        .unwrap_err();
        assert!(
            err.contains("hosted bitcoin oracle") && err.contains("signet.oracle.setor.dev"),
            "{err}"
        );
        let err = resolve(resolvable(
            "testnet4",
            "https://oracle.setor.dev/",
            "127.0.0.1",
        ))
        .unwrap_err();
        assert!(err.contains("no hosted oracle for testnet4"), "{err}");
        assert!(
            resolve(resolvable(
                "signet",
                "https://signet.oracle.setor.dev",
                "127.0.0.1"
            ))
            .is_ok()
        );
    }

    #[test]
    fn p2p_peer_accepts_hostnames_and_default_ports() {
        let r = resolve(resolvable("signet", "http://127.0.0.1:1", "127.0.0.1")).unwrap();
        assert_eq!(r.p2p_addr, "127.0.0.1:38333".parse().unwrap());
        let r = resolve(resolvable(
            "regtest",
            "http://127.0.0.1:1",
            "localhost:18444",
        ))
        .unwrap();
        assert!(r.p2p_addr.ip().is_loopback());
        assert_eq!(r.p2p_addr.port(), 18444);
        let err = resolve(resolvable("signet", "http://127.0.0.1:1", "host:notaport")).unwrap_err();
        assert!(err.contains("p2p_node_addr"), "{err}");
    }

    #[test]
    fn start_at_tip_needs_resolution_and_explicit_height_wins() {
        let mut cfg = resolvable("signet", "http://127.0.0.1:1", "127.0.0.1");
        cfg.start_height = None;
        cfg.start_at_tip = true;
        let err = resolve(cfg.clone()).unwrap_err();
        assert!(err.contains("start_at_tip"), "{err}");

        // An explicit height needs no oracle round trip and clears the flag.
        cfg.start_height = Some(5);
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        assert_eq!(rt.block_on(resolve_start_at_tip(&mut cfg)), Ok(None));
        assert!(!cfg.start_at_tip);
    }

    #[test]
    fn persist_start_height_keeps_other_keys_and_drops_the_flag() {
        figment::Jail::expect_with(|jail| {
            jail.create_file(
                "config.toml",
                "network = \"signet\"\nstart_at_tip = true\np2p_node_addr = \"node.example\"\n",
            )?;
            let path = jail.directory().join("config.toml");
            persist_start_height(&path, 270_123).unwrap();
            let cfg = friglet_ipc::read_config_toml(&path).unwrap();
            assert_eq!(cfg.start_height, Some(270_123));
            assert!(!cfg.start_at_tip);
            assert_eq!(cfg.network, "signet");
            assert_eq!(cfg.p2p_node_addr.as_deref(), Some("node.example"));
            // No defaults were materialised (oracle_url still follows network).
            let text = std::fs::read_to_string(&path).unwrap();
            assert!(!text.contains("oracle_url"), "{text}");

            // Env-only setups get a minimal file.
            let fresh = jail.directory().join("new").join("config.toml");
            persist_start_height(&fresh, 7).unwrap();
            assert_eq!(
                std::fs::read_to_string(&fresh).unwrap().trim(),
                "start_height = 7"
            );
            Ok(())
        });
    }

    fn keys(secret_hex: &str, spend_hex: &str) -> (SecretKey, PublicKey) {
        (
            SecretKey::from_str(secret_hex).unwrap(),
            PublicKey::from_str(spend_hex).unwrap(),
        )
    }

    fn write_state(path: &Path, secret: &SecretKey, spend: &PublicKey) {
        std::fs::write(
            path,
            serde_json::json!({
                "secret_scan_hex": hex::encode(secret.secret_bytes()),
                "public_spend_hex": hex::encode(spend.serialize()),
                "last_scanned_block_height": 7,
            })
            .to_string(),
        )
        .unwrap();
    }

    /// Point the platform config dir into the jail; returns the default
    /// state file path there.
    fn jailed_default_state_file(jail: &mut figment::Jail) -> PathBuf {
        let dir = jail.directory().to_path_buf();
        jail.set_env("XDG_CONFIG_HOME", dir.display());
        let base = friglet_ipc::default_state_file().unwrap();
        assert!(base.starts_with(jail.directory()));
        std::fs::create_dir_all(base.parent().unwrap()).unwrap();
        base
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn default_state_file_is_keyed_by_wallet() {
        figment::Jail::expect_with(|jail| {
            let base = jailed_default_state_file(jail);
            let (a_scan, a_spend) = keys(SECRET_HEX, MAINNET_DESCRIPTOR_SPEND);
            let (b_scan, b_spend) = keys(MAINNET_DESCRIPTOR_SCAN, MAINNET_DESCRIPTOR_SPEND);

            // The bare default name is treated as the default location.
            let a = wallet_state_file(Path::new("scanner_state.json"), "signet", &a_scan, &a_spend)
                .unwrap();
            assert!(a.to_string_lossy().starts_with("scanner_state-signet-"));
            let a = base.with_file_name(a);
            let b = wallet_state_file(&base, "signet", &b_scan, &b_spend).unwrap();
            assert_ne!(
                a.file_name(),
                b.file_name(),
                "new keys get a fresh state file"
            );
            assert_eq!(
                wallet_state_file(&base, "signet", &a_scan, &a_spend).unwrap(),
                a,
                "stable per wallet"
            );
            let b_main = wallet_state_file(&base, "bitcoin", &b_scan, &b_spend).unwrap();
            assert_ne!(b, b_main, "and per network");
            Ok(())
        });
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn legacy_default_state_of_the_same_wallet_is_moved_into_place() {
        figment::Jail::expect_with(|jail| {
            let base = jailed_default_state_file(jail);
            let (scan, spend) = keys(SECRET_HEX, MAINNET_DESCRIPTOR_SPEND);
            write_state(&base, &scan, &spend);
            std::fs::write(crate::blockheader::sidecar_path(&base), "{}").unwrap();
            std::fs::write(crate::blockheader::pending_path(&base), "{}").unwrap();

            // Another wallet leaves the legacy file alone ...
            let (other, other_spend) = keys(MAINNET_DESCRIPTOR_SCAN, MAINNET_DESCRIPTOR_SPEND);
            let keyed_other = wallet_state_file(&base, "signet", &other, &other_spend).unwrap();
            assert!(base.exists() && !keyed_other.exists());

            // ... the wallet it belongs to adopts it.
            let keyed = wallet_state_file(&base, "signet", &scan, &spend).unwrap();
            assert!(!base.exists());
            assert!(keyed.exists());
            assert!(crate::blockheader::sidecar_path(&keyed).exists());
            assert!(crate::blockheader::pending_path(&keyed).exists());
            Ok(())
        });
    }

    #[test]
    fn explicit_state_file_of_another_wallet_is_refused() {
        figment::Jail::expect_with(|jail| {
            let path = jail.directory().join("custom.json");
            let (scan, spend) = keys(SECRET_HEX, MAINNET_DESCRIPTOR_SPEND);
            assert_eq!(
                wallet_state_file(&path, "signet", &scan, &spend).unwrap(),
                path
            );
            write_state(&path, &scan, &spend);
            assert_eq!(
                wallet_state_file(&path, "signet", &scan, &spend).unwrap(),
                path
            );

            let (other, other_spend) = keys(MAINNET_DESCRIPTOR_SCAN, MAINNET_DESCRIPTOR_SPEND);
            let err = wallet_state_file(&path, "signet", &other, &other_spend).unwrap_err();
            assert!(err.contains("different wallet"), "{err}");
            Ok(())
        });
    }

    #[test]
    fn birthday_moving_back_triggers_a_rescan() {
        figment::Jail::expect_with(|jail| {
            let state = jail.directory().join("w.json");
            std::fs::write(&state, "{}").unwrap();

            // First sight: record, keep state.
            assert_eq!(reconcile_birthday(&state, 1000).unwrap(), None);
            assert!(state.exists());
            // Forward: the state already covers it.
            assert_eq!(reconcile_birthday(&state, 1500).unwrap(), None);
            assert!(state.exists());
            // Backwards: state moved aside, new birthday recorded.
            assert_eq!(reconcile_birthday(&state, 900).unwrap(), Some(1000));
            assert!(!state.exists());
            assert!(state.with_extension("json.bak").exists());
            assert_eq!(reconcile_birthday(&state, 900).unwrap(), None);
            assert_eq!(reconcile_birthday(&state, 950).unwrap(), None);
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
