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
use std::path::PathBuf;

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
    /// Path for scanner state persistence.
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
            state_file: PathBuf::from("scanner_state.json"),
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
    /// Best chain tip height known to the scanner, if any.
    pub tip_height: Option<u64>,
    /// Scan progress in the current catch-up range, 0.0–1.0.
    pub scan_progress: f32,
    pub network: String,
    /// Number of currently connected Electrum clients.
    pub electrum_clients: u64,
    /// Best effort: scan task alive and no recorded error.
    pub oracle_connected: bool,
    pub last_error: Option<String>,
    /// Silent Payments address of the wallet, once known.
    pub sp_address: Option<String>,
    /// Daemon crate version.
    pub version: String,
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
    fn config_deserializes_from_partial_json() {
        let cfg: DaemonConfig = serde_json::from_str(r#"{"oracle_url":"http://x"}"#).unwrap();
        assert_eq!(cfg.oracle_url, "http://x");
        assert_eq!(cfg.network, "bitcoin");
    }
}
