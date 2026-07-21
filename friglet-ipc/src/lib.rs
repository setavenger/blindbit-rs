//! IPC protocol shared between the friglet daemon and its clients (tray UI,
//! `frigletctl`-style tools, tests).
//!
//! # Wire format
//!
//! Newline-delimited JSON: each message is one JSON document (externally
//! tagged serde enum) serialized on a single line and terminated by `\n`.
//! A connection carries any number of request/response pairs; the daemon
//! answers each request with exactly one response.
//!
//! # Transport
//!
//! Cross-platform local sockets via the `interprocess` crate: Unix domain
//! sockets on Unix, named pipes on Windows.

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::io;
use std::io::Write;
use std::path::{Path, PathBuf};

use interprocess::local_socket::tokio::prelude::*;
use interprocess::local_socket::tokio::{RecvHalf, SendHalf, Stream};
use interprocess::local_socket::{ListenerOptions, Name};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

pub use interprocess::local_socket::tokio::Listener;

/// Daemon configuration as exchanged over IPC and layered from
/// file / environment / CLI. Field names double as TOML keys and
/// `FRIGLET_*` environment variable suffixes.
///
/// The scan secret is deliberately not part of this struct: it lives in the
/// key file (see the daemon docs) and is never *returned* over the control
/// socket. Replacing it is a separate write-only verb ([`Request::SetScanKey`]).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct DaemonConfig {
    /// Bitcoin network: bitcoin | signet | testnet | testnet4 | regtest.
    pub network: String,
    /// BlindBit oracle URL.
    pub oracle_url: String,
    /// Bitcoin P2P node address (`host:port`). Required to start scanning.
    pub p2p_node_addr: Option<String>,
    /// Wallet birthday block height. Required to start scanning.
    pub start_height: Option<u64>,
    /// Spend public key (33-byte hex). Required to start scanning.
    pub spend_pubkey: Option<String>,
    /// Maximum Silent Payments label number.
    pub max_label_num: u32,
    /// HTTP server bind address.
    pub http_addr: String,
    /// Electrum TCP server bind address.
    pub electrum_addr: String,
    /// Path for scanner state persistence. Defaults to
    /// [`default_state_file`] (`<platform config dir>/friglet/scanner_state.json`)
    /// when a config dir exists, else the relative `scanner_state.json`.
    pub state_file: PathBuf,
    /// Default log level when RUST_LOG is not set.
    pub log_level: String,
    /// Path to the scan secret key file. Defaults to
    /// `<platform config dir>/friglet/scan.key` when unset.
    pub key_file: Option<PathBuf>,
    /// Control socket path override. Defaults to [`default_socket_path`].
    pub control_socket: Option<String>,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            network: "bitcoin".to_string(),
            oracle_url: "https://oracle.setor.dev".to_string(),
            p2p_node_addr: None,
            start_height: None,
            spend_pubkey: None,
            max_label_num: 0,
            http_addr: "127.0.0.1:8080".to_string(),
            electrum_addr: "127.0.0.1:50001".to_string(),
            state_file: default_state_file().unwrap_or_else(|| PathBuf::from("scanner_state.json")),
            log_level: "info".to_string(),
            key_file: None,
            control_socket: None,
        }
    }
}

/// Requests a client can send to the daemon.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Request {
    GetStatus,
    /// Start the scan task (no-op if already running).
    Start,
    /// Stop the scan task (no-op if not running).
    Stop,
    /// Current effective configuration (never contains the scan secret).
    GetConfig,
    /// Replace the daemon configuration: the daemon validates it, persists
    /// it to its config file (TOML) and applies it. Scanner-affecting fields
    /// restart the scan task; bind addresses (`http_addr`, `electrum_addr`)
    /// only take effect after a daemon restart (reported via
    /// [`Response::OkWithNote`]).
    SetConfig(Box<DaemonConfig>),
    /// Replace the scan secret: a hex-encoded 32-byte secp256k1 secret key.
    /// The daemon validates it and writes it to its key file (0600 on Unix).
    /// The secret is deliberately not part of [`DaemonConfig`], so this is a
    /// separate verb; `GetConfig` never returns it.
    SetScanKey(String),
    /// Gracefully shut down the whole daemon process.
    Shutdown,
}

/// Responses the daemon sends back; exactly one per request.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Response {
    Status(StatusInfo),
    Ok,
    /// Success, plus a human-readable note the client should surface (e.g.
    /// which changed settings need a daemon restart to take effect).
    OkWithNote(String),
    Config(DaemonConfig),
    Error(String),
}

/// Snapshot of the daemon's state, returned for [`Request::GetStatus`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StatusInfo {
    /// Whether the scan task is currently running.
    pub scanning: bool,
    /// Height of the last block processed by the scanner.
    pub scanned_height: u64,
    /// Oracle chain tip when known, else last scanned (Electrum index tip).
    pub tip_height: Option<u64>,
    /// Scan progress in the current catch-up range, 0.0–1.0.
    pub scan_progress: f32,
    pub network: String,
    /// Number of currently connected Electrum clients.
    pub electrum_clients: u64,
    /// True when an oracle tip was fetched successfully within the cache TTL.
    pub oracle_connected: bool,
    pub last_error: Option<String>,
    /// Silent Payments address of the wallet, once known.
    pub sp_address: Option<String>,
    /// Number of confirmed Silent Payments receive transactions found.
    #[serde(default)]
    pub tx_count: u64,
    /// Number of wallet-owned outputs found, including persisted results.
    #[serde(default)]
    pub outputs_found: u64,
    /// Silent Payments addresses for every configured label.
    #[serde(default)]
    pub label_addresses: Vec<LabelAddress>,
    /// Daemon crate version.
    pub version: String,
}

/// A configured Silent Payments label and its receive address.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LabelAddress {
    pub label: u32,
    pub address: String,
}

/// Default control socket path for the current platform.
///
/// - Linux/BSD: `$XDG_RUNTIME_DIR/friglet.sock`, falling back to
///   `~/.local/share/friglet/friglet.sock`, then `/tmp/friglet.sock`
/// - macOS: `~/Library/Application Support/friglet/friglet.sock`
/// - Windows: named pipe `\\.\pipe\friglet`
///
/// The `FRIGLET_CONTROL_SOCKET` environment variable overrides all of these.
pub fn default_socket_path() -> String {
    if let Ok(path) = std::env::var("FRIGLET_CONTROL_SOCKET")
        && !path.is_empty()
    {
        return path;
    }

    #[cfg(windows)]
    {
        r"\\.\pipe\friglet".to_string()
    }

    #[cfg(not(windows))]
    {
        #[cfg(not(target_os = "macos"))]
        if let Some(dir) = dirs::runtime_dir() {
            return dir.join("friglet.sock").to_string_lossy().into_owned();
        }
        if let Some(dir) = dirs::data_dir() {
            return dir
                .join("friglet")
                .join("friglet.sock")
                .to_string_lossy()
                .into_owned();
        }
        "/tmp/friglet.sock".to_string()
    }
}

/// Default daemon config file path:
/// `<platform config dir>/friglet/config.toml`. Shared by the daemon (which
/// loads it) and the tray (which writes it during first-run setup).
pub fn default_config_path() -> Option<PathBuf> {
    dirs::config_dir().map(|d| d.join("friglet").join("config.toml"))
}

/// Default scan-secret key file path:
/// `<platform config dir>/friglet/scan.key`.
pub fn default_key_file() -> Option<PathBuf> {
    dirs::config_dir().map(|d| d.join("friglet").join("scan.key"))
}

/// Default scanner state file path:
/// `<platform config dir>/friglet/scanner_state.json` (same directory as
/// `config.toml` / `scan.key`).
pub fn default_state_file() -> Option<PathBuf> {
    dirs::config_dir().map(|d| d.join("friglet").join("scanner_state.json"))
}

/// Read and parse a TOML config file into a [`DaemonConfig`]. Missing keys
/// take their defaults (the struct is `#[serde(default)]`).
pub fn read_config_toml(path: &Path) -> Result<DaemonConfig, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read config file {}: {e}", path.display()))?;
    toml::from_str(&text).map_err(|e| format!("invalid config file {}: {e}", path.display()))
}

/// Persist `cfg` as pretty TOML to `path` (atomically: temp file + rename),
/// creating parent directories as needed. Shared by the daemon's `SetConfig`
/// handler and the tray's first-run setup.
pub fn write_config_toml(path: &Path, cfg: &DaemonConfig) -> Result<(), String> {
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

/// Write the scan-secret key file at `path` (0600 on Unix), creating parent
/// directories as needed. With `overwrite = false` the call fails if the
/// file already exists. Performs no validation of `secret_hex` itself —
/// callers validate the key material.
pub fn write_key_file(path: &Path, secret_hex: &str, overwrite: bool) -> Result<(), String> {
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

fn socket_name(path: &str) -> io::Result<Name<'_>> {
    #[cfg(windows)]
    {
        use interprocess::local_socket::{GenericNamespaced, ToNsName};
        let pipe_name = path.strip_prefix(r"\\.\pipe\").unwrap_or(path);
        pipe_name.to_ns_name::<GenericNamespaced>()
    }
    #[cfg(not(windows))]
    {
        use interprocess::local_socket::{GenericFilePath, ToFsName};
        path.to_fs_name::<GenericFilePath>()
    }
}

/// Bind a local socket listener at `path`, creating parent directories for
/// filesystem-based socket paths. Does not handle stale socket files; the
/// daemon does that itself (see `friglet`'s control module).
pub fn listen(path: &str) -> io::Result<Listener> {
    #[cfg(not(windows))]
    if let Some(parent) = std::path::Path::new(path).parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }
    ListenerOptions::new()
        .name(socket_name(path)?)
        .create_tokio()
}

/// Connect to the daemon's control socket at `path`.
pub async fn connect_stream(path: &str) -> io::Result<Stream> {
    Stream::connect(socket_name(path)?).await
}

/// Serialize `msg` as one JSON line and write it to `writer`.
pub async fn write_message<W, T>(writer: &mut W, msg: &T) -> io::Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
    T: Serialize,
{
    let mut line = serde_json::to_vec(msg)?;
    line.push(b'\n');
    writer.write_all(&line).await
}

/// Read one JSON-line message from `reader`. Returns `None` on clean EOF.
pub async fn read_message<R, T>(reader: &mut R) -> io::Result<Option<T>>
where
    R: tokio::io::AsyncBufRead + Unpin,
    T: DeserializeOwned,
{
    let mut line = String::new();
    if reader.read_line(&mut line).await? == 0 {
        return Ok(None);
    }
    Ok(Some(serde_json::from_str(&line)?))
}

/// Accept one incoming connection on a listener created by [`listen`].
pub async fn accept(listener: &Listener) -> io::Result<Connection> {
    let (recv, send) = listener.accept().await?.split();
    Ok(Connection {
        reader: BufReader::new(recv),
        writer: send,
    })
}

/// Server side of one accepted control-socket connection.
pub struct Connection {
    reader: BufReader<RecvHalf>,
    writer: SendHalf,
}

impl Connection {
    /// Read the next request; `None` when the client disconnects.
    pub async fn next_request(&mut self) -> io::Result<Option<Request>> {
        read_message(&mut self.reader).await
    }

    pub async fn respond(&mut self, resp: &Response) -> io::Result<()> {
        write_message(&mut self.writer, resp).await
    }
}

/// Minimal async control-socket client, shared by the tray UI and tests.
pub struct Client {
    reader: BufReader<RecvHalf>,
    writer: SendHalf,
}

impl Client {
    pub async fn connect(socket_path: &str) -> io::Result<Self> {
        let (recv, send) = connect_stream(socket_path).await?.split();
        Ok(Self {
            reader: BufReader::new(recv),
            writer: send,
        })
    }

    /// Send one request and wait for the daemon's response.
    pub async fn request(&mut self, req: &Request) -> io::Result<Response> {
        write_message(&mut self.writer, req).await?;
        read_message(&mut self.reader).await?.ok_or_else(|| {
            io::Error::new(io::ErrorKind::UnexpectedEof, "daemon closed the connection")
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_state_file_is_under_config_dir() {
        let cfg = DaemonConfig::default();
        if let Some(expected) = default_state_file() {
            assert_eq!(cfg.state_file, expected);
            assert!(cfg.state_file.is_absolute());
            assert!(
                cfg.state_file
                    .file_name()
                    .is_some_and(|n| n == "scanner_state.json")
            );
        } else {
            assert_eq!(cfg.state_file, PathBuf::from("scanner_state.json"));
        }
    }

    #[test]
    fn request_roundtrip() {
        let req = Request::SetConfig(Box::new(DaemonConfig {
            start_height: Some(1000),
            ..DaemonConfig::default()
        }));
        let json = serde_json::to_string(&req).unwrap();
        assert_eq!(serde_json::from_str::<Request>(&json).unwrap(), req);
    }

    #[test]
    fn set_scan_key_roundtrip() {
        let req = Request::SetScanKey("aa".repeat(32));
        let json = serde_json::to_string(&req).unwrap();
        assert_eq!(serde_json::from_str::<Request>(&json).unwrap(), req);

        let resp = Response::OkWithNote("restart required".to_string());
        let json = serde_json::to_string(&resp).unwrap();
        assert_eq!(serde_json::from_str::<Response>(&json).unwrap(), resp);
    }

    #[test]
    fn status_roundtrip_includes_wallet_fields() {
        let status = StatusInfo {
            scanning: true,
            scanned_height: 100,
            tip_height: Some(101),
            scan_progress: 0.5,
            network: "signet".to_string(),
            electrum_clients: 1,
            oracle_connected: true,
            last_error: None,
            sp_address: Some("sp1qbase".to_string()),
            tx_count: 2,
            outputs_found: 3,
            label_addresses: vec![LabelAddress {
                label: 0,
                address: "tsp1qlabel".to_string(),
            }],
            version: "test".to_string(),
        };
        let json = serde_json::to_string(&status).unwrap();
        assert_eq!(serde_json::from_str::<StatusInfo>(&json).unwrap(), status);
    }

    #[test]
    fn status_old_json_defaults_wallet_fields() {
        let json = r#"{
            "scanning": false,
            "scanned_height": 42,
            "tip_height": null,
            "scan_progress": 0.0,
            "network": "regtest",
            "electrum_clients": 0,
            "oracle_connected": false,
            "last_error": null,
            "sp_address": null,
            "version": "old"
        }"#;
        let status: StatusInfo = serde_json::from_str(json).unwrap();
        assert_eq!(status.tx_count, 0);
        assert_eq!(status.outputs_found, 0);
        assert!(status.label_addresses.is_empty());
    }

    #[test]
    fn config_deserializes_from_partial_json() {
        let cfg: DaemonConfig = serde_json::from_str(r#"{"oracle_url":"http://x"}"#).unwrap();
        assert_eq!(cfg.oracle_url, "http://x");
        assert_eq!(cfg.network, "bitcoin");
    }

    fn temp_dir(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("friglet-ipc-test-{}-{tag}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn config_toml_roundtrip_is_atomic() {
        let dir = temp_dir("config-toml");
        let path = dir.join("sub").join("config.toml");
        let cfg = DaemonConfig {
            p2p_node_addr: Some("127.0.0.1:38333".to_string()),
            start_height: Some(1234),
            spend_pubkey: Some("02".repeat(33)),
            ..DaemonConfig::default()
        };
        write_config_toml(&path, &cfg).unwrap();
        assert_eq!(read_config_toml(&path).unwrap(), cfg);
        assert!(
            !path.with_extension("toml.tmp").exists(),
            "temp file must be renamed away"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn key_file_written_0600_and_overwrite_flag_respected() {
        let dir = temp_dir("key-file");
        let path = dir.join("sub").join("scan.key");
        write_key_file(&path, "aa", false).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "aa\n");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        // create_new fails on an existing file; overwrite replaces it.
        assert!(write_key_file(&path, "bb", false).is_err());
        write_key_file(&path, "bb", true).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "bb\n");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
