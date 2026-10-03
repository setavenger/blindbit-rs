//! Control socket: serves `friglet-ipc` requests over a local socket
//! (Unix domain socket / Windows named pipe, newline-delimited JSON).
//!
//! # `SetConfig` / `SetScanKey` / `ApplySettings` semantics
//!
//! - The new config (and scan key, if any) is validated first; on any
//!   validation error nothing is persisted and nothing changes.
//! - Valid input is persisted — the config to the daemon's config file (the
//!   file it loaded at startup, or the default path when none existed) as
//!   TOML, the scan key to the 0600 key file.
//! - If anything changed, the daemon answers `OkWithNote` and then restarts
//!   in-process (see `main.rs`): every setting takes full effect, including
//!   bind addresses and log level, and Electrum clients such as Sparrow are
//!   disconnected so they reconnect to the new wallet view. New keys get
//!   their own state file (`config::wallet_state_file`), so switching
//!   wallets starts a fresh scan without manual cleanup.
//! - Unchanged input answers `Ok` without a restart.

use std::io;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use bdk_sp::encoding::SilentPaymentCode;
use bitcoin::Network as BitcoinNetwork;
use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use blindbit_lib::scanner::{self, Scanner, WalletElectrumIndex};
use friglet_ipc::{DaemonConfig, LabelAddress, Listener, Request, Response, StatusInfo};
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

use crate::config;
use crate::supervisor::{ScanSupervisor, StartOutcome};

/// How often the background poller asks the oracle for its tip.
const ORACLE_POLL_INTERVAL: Duration = Duration::from_secs(10);
/// Cap on one oracle tip poll (connect + `GetInfo`).
const ORACLE_POLL_TIMEOUT: Duration = Duration::from_secs(5);
/// The oracle counts as connected while its last good answer is this recent.
const ORACLE_STALE_AFTER: Duration = Duration::from_secs(30);
/// How long `Stop` waits for the scan task to end before answering that it
/// is still stopping (it then finishes in the background). The scan stops
/// within milliseconds, and is dropped after the supervisor's
/// `CANCEL_GRACE` at the latest, so this only covers a task that blocks a
/// worker thread.
const STOP_WAIT: Duration = Duration::from_secs(3);

/// The oracle's reachability and chain tip, kept current by
/// [`spawn_oracle_poller`] so `GetStatus` never waits on the network (a slow
/// or unreachable oracle used to make every status request take ~2 s, longer
/// than the tray's poll timeout, so the tray took the daemon for dead).
#[derive(Debug, Default, Clone)]
pub struct OracleStatus {
    tip: Option<u64>,
    last_ok: Option<Instant>,
    error: Option<String>,
    down_since_unix: Option<u64>,
}

impl OracleStatus {
    pub fn record_ok(&mut self, tip: u64) {
        self.tip = Some(tip);
        self.last_ok = Some(Instant::now());
        self.error = None;
        self.down_since_unix = None;
    }

    pub fn record_error(&mut self, error: String) {
        self.error = Some(error);
        self.down_since_unix
            .get_or_insert_with(crate::electrum::now_secs);
    }

    fn connected(&self) -> bool {
        self.error.is_none()
            && self
                .last_ok
                .is_some_and(|at| at.elapsed() < ORACLE_STALE_AFTER)
    }
}

/// Poll the oracle's tip every [`ORACLE_POLL_INTERVAL`] into `status`,
/// logging when it becomes unreachable and when it recovers.
pub fn spawn_oracle_poller(url: String, status: Arc<std::sync::Mutex<OracleStatus>>) {
    tokio::spawn(async move {
        let mut client: Option<blindbit_lib::OracleServiceClient<tonic::transport::Channel>> = None;
        loop {
            let poll = async {
                if client.is_none() {
                    client = Some(
                        blindbit_lib::OracleServiceClient::connect(url.clone())
                            .await
                            .map_err(|e| format!("cannot connect: {e}"))?,
                    );
                }
                let response = client
                    .as_mut()
                    .expect("connected above")
                    .get_info(tonic::Request::new(()))
                    .await
                    .map_err(|e| format!("GetInfo failed: {}", e.message()))?;
                Ok::<u64, String>(response.into_inner().height)
            };
            let result = match tokio::time::timeout(ORACLE_POLL_TIMEOUT, poll).await {
                Ok(result) => result,
                Err(_) => Err(format!(
                    "no answer within {}s",
                    ORACLE_POLL_TIMEOUT.as_secs()
                )),
            };
            match result {
                Ok(tip) => {
                    let mut s = status.lock().unwrap();
                    if s.error.is_some() {
                        tracing::info!(tip, "oracle reachable again");
                    }
                    s.record_ok(tip);
                }
                Err(e) => {
                    client = None;
                    let mut s = status.lock().unwrap();
                    if s.error.is_none() {
                        tracing::warn!(url = %url, error = %e, "oracle unreachable; retrying");
                    }
                    s.record_error(format!("oracle {url}: {e}"));
                }
            }
            tokio::time::sleep(ORACLE_POLL_INTERVAL).await;
        }
    });
}

/// Count persisted wallet-owned outputs without making daemon startup depend
/// on the state file being present or valid.
pub(crate) fn owned_outputs_count(state_file: &std::path::Path) -> u64 {
    std::fs::read(state_file)
        .ok()
        .and_then(|json| serde_json::from_slice::<serde_json::Value>(&json).ok())
        .and_then(|value| {
            value
                .get("owned_outputs")?
                .as_array()
                .map(|a| a.len() as u64)
        })
        .unwrap_or(0)
}

/// Derive every configured label address. Label 0 is included because the
/// scanner indexes the inclusive range `0..=max_label_num`.
pub(crate) fn derive_label_addresses(
    scan_secret: SecretKey,
    spend_pubkey: PublicKey,
    network: BitcoinNetwork,
    max_label_num: u32,
) -> Vec<LabelAddress> {
    let scan_pubkey = PublicKey::from_secret_key(&Secp256k1::new(), &scan_secret);
    let base = SilentPaymentCode::new_v0(scan_pubkey, spend_pubkey, network);
    (0..=max_label_num)
        .map(|label| {
            let tweak = SilentPaymentCode::get_label(scan_secret, label);
            let address = base
                .add_label(tweak)
                .expect("hash-derived label tweak is a valid curve scalar")
                .to_string();
            LabelAddress { label, address }
        })
        .collect()
}

pub(crate) fn wallet_network(network: bitcoin_rev::Network) -> BitcoinNetwork {
    use bitcoin_rev::network::TestnetVersion;
    match network {
        bitcoin_rev::Network::Bitcoin => BitcoinNetwork::Bitcoin,
        bitcoin_rev::Network::Signet => BitcoinNetwork::Signet,
        bitcoin_rev::Network::Regtest => BitcoinNetwork::Regtest,
        bitcoin_rev::Network::Testnet(TestnetVersion::V4) => BitcoinNetwork::Testnet4,
        bitcoin_rev::Network::Testnet(_) => BitcoinNetwork::Testnet,
    }
}

/// The scanner's published health as sent over the control socket.
fn scan_health_info(health: &scanner::ScanHealth) -> friglet_ipc::ScanHealthInfo {
    friglet_ipc::ScanHealthInfo {
        stall: health
            .stall
            .as_ref()
            .map(|stall| friglet_ipc::ScanStallInfo {
                height: stall.height,
                reason: stall.reason.clone(),
                since_unix: stall.since_unix,
            }),
        start_adjusted: health
            .oracle_floor_start
            .map(|start| friglet_ipc::StartAdjustedInfo {
                requested_height: start.requested_height,
                oracle_floor: start.floor_height,
            }),
        state_rescan: health
            .state_rescan
            .map(|rescan| friglet_ipc::StateRescanInfo {
                from_height: rescan.from_height,
                until_height: rescan.until_height,
            }),
        state_reset: health
            .state_file_reset
            .as_ref()
            .map(|reset| friglet_ipc::StateResetInfo {
                backup_path: reset.backup_path.display().to_string(),
                error: reset.error.clone(),
            }),
    }
}

/// Everything the request handler needs from the daemon.
pub struct ControlCtx {
    pub supervisor: Arc<ScanSupervisor>,
    pub scanner: Arc<Mutex<Scanner>>,
    /// The scanner's Electrum index, used for status reporting.
    pub electrum_index: Arc<Mutex<WalletElectrumIndex>>,
    pub electrum_clients: Arc<AtomicU64>,
    /// Cumulative wallet-owned output count, seeded from persisted state and
    /// updated from scanner notifications.
    pub outputs_found: Arc<AtomicU64>,
    /// Label addresses derived from the scan secret. Never sent separately
    /// from the status snapshot.
    pub label_addresses: Vec<LabelAddress>,
    /// Current effective configuration, updated by `SetConfig`.
    pub settings: std::sync::Mutex<DaemonConfig>,
    /// The wallet's state file this run uses (`settings.state_file` is the
    /// configured base path; see `config::wallet_state_file`).
    pub state_file: PathBuf,
    /// Where `SetConfig` persists the config; `None` when no location could
    /// be determined (no config dir on this platform).
    pub config_path: Option<PathBuf>,
    /// Serializes `SetConfig` / `SetScanKey` / `Start` / `Stop` so lifecycle
    /// verbs cannot interleave with persisting new settings.
    pub apply_lock: Mutex<()>,
    /// Oracle tip and reachability, updated by [`spawn_oracle_poller`].
    pub oracle: Arc<std::sync::Mutex<OracleStatus>>,
    /// The log file this daemon writes, if any.
    pub log_file: Option<PathBuf>,
    pub shutdown: CancellationToken,
    /// Set (together with cancelling `shutdown`) when new settings were
    /// saved: the run ends and `main` starts the next one.
    pub restart_requested: AtomicBool,
    /// Whether this process was launched by a tray (`FRIGLET_SPAWNED_BY_TRAY`),
    /// reported back in `GetStatus` so ownership survives a tray restart —
    /// see [`StatusInfo::spawned_by_tray`].
    pub spawned_by_tray: bool,
}

impl ControlCtx {
    pub async fn handle(&self, req: Request) -> Response {
        match req {
            Request::GetStatus => Response::Status(self.status().await),
            Request::Start => {
                // Serialized with persisting new settings (see `apply_lock`).
                let _guard = self.apply_lock.lock().await;
                match self.supervisor.start() {
                    StartOutcome::Started => {
                        tracing::info!("scanning started via control socket");
                        Response::Ok
                    }
                    StartOutcome::AlreadyRunning => Response::Ok,
                    StartOutcome::StillStopping => {
                        let message = "scanning is still stopping: the scanner pauses as soon \
                                       as its current step returns; start it again once the \
                                       status says paused";
                        tracing::warn!("start refused: {message}");
                        Response::Error(message.to_string())
                    }
                }
            }
            Request::Stop => self.pause_scanning().await,
            Request::GetConfig => Response::Config(self.settings.lock().unwrap().clone()),
            Request::SetConfig(new_cfg) => self.apply(Some(*new_cfg), None).await,
            Request::SetScanKey(hex) => self.apply(None, Some(&hex)).await,
            Request::ApplySettings { config, scan_key } => {
                self.apply(Some(*config), scan_key.as_deref()).await
            }
            Request::Shutdown => {
                tracing::info!("shutdown requested via control socket");
                self.stop_soon();
                Response::Ok
            }
        }
    }

    /// `Stop`: pause scanning. The scan task ends within milliseconds, also
    /// in the middle of a P2P block download (the download is cancelled and
    /// the block is scanned again on the next start). Should it not have
    /// ended within [`STOP_WAIT`], the answer says it is still stopping and
    /// the status reports `stopping` until the task has really ended, then
    /// `paused`.
    async fn pause_scanning(&self) -> Response {
        let _guard = self.apply_lock.lock().await;
        if !self.supervisor.request_stop() {
            return Response::Ok;
        }
        tracing::info!("stop requested via control socket");
        if self.supervisor.wait_stopped(Some(STOP_WAIT)).await {
            tracing::info!("scanning paused");
            save_scanner_state(&self.scanner, &self.state_file).await;
            return Response::Ok;
        }
        tracing::warn!(
            "scan task has not stopped yet; scanning pauses as soon as its current step returns"
        );
        let supervisor = self.supervisor.clone();
        let scanner = self.scanner.clone();
        let state_file = self.state_file.clone();
        tokio::spawn(async move {
            supervisor.wait_stopped(None).await;
            tracing::info!("scanning paused");
            save_scanner_state(&scanner, &state_file).await;
        });
        Response::OkWithNote(
            "stopping: the scanner pauses as soon as its current step returns".to_string(),
        )
    }

    async fn status(&self) -> StatusInfo {
        let index = &self.electrum_index;
        let (electrum_tip, scan_progress, sp_address, tx_count, start_height) = {
            let idx = index.lock().await;
            let tip = idx.tip.as_ref().map(|(h, _)| u64::from(*h));
            let addr = (!idx.sp_address.is_empty()).then(|| idx.sp_address.clone());
            (
                tip,
                idx.scan_progress,
                addr,
                idx.sp_history.len() as u64,
                idx.sp_start_height,
            )
        };
        let mut scan_health = scan_health_info(&index.lock().await.scan_health);
        let scan_state = self.supervisor.state();
        // A stall describes the scan loop retrying; a paused or stopping
        // scan is not retrying anything.
        if scan_state != friglet_ipc::ScanState::Running {
            scan_health.stall = None;
        }

        // While the scan task runs it holds the scanner mutex, so fall back
        // to the electrum index tip (which the scanner advances per scanned
        // block) when the lock is unavailable — and before the first block
        // of a new wallet is scanned, to the block below its start height
        // rather than 0.
        let scanned_height = match self.scanner.try_lock() {
            Ok(s) => s.get_last_scanned_block_height(),
            Err(_) => electrum_tip.unwrap_or(start_height.saturating_sub(1)),
        };

        // Prefer the oracle tip when known; else the last scanned tip.
        let oracle = self.oracle.lock().unwrap().clone();
        let tip_height = oracle.tip.or(electrum_tip);

        let scanning = self.supervisor.is_running();
        let last_error = self.supervisor.last_error();
        let network = self.settings.lock().unwrap().network.clone();

        StatusInfo {
            scanning,
            scanned_height,
            tip_height,
            scan_progress,
            network,
            electrum_clients: self.electrum_clients.load(Ordering::Relaxed),
            oracle_connected: oracle.connected(),
            last_error,
            sp_address,
            tx_count,
            outputs_found: self.outputs_found.load(Ordering::Relaxed),
            label_addresses: self.label_addresses.clone(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            spawned_by_tray: self.spawned_by_tray,
            scan_health,
            scan_state: Some(scan_state),
            pid: Some(std::process::id()),
            log_file: self.log_file.as_ref().map(|p| p.display().to_string()),
            oracle_error: oracle.error,
            oracle_down_since_unix: oracle.down_since_unix,
        }
    }

    /// Read `FRIGLET_SPAWNED_BY_TRAY` from the process environment (set by
    /// the tray on the child it spawns).
    pub fn spawned_by_tray_from_env() -> bool {
        std::env::var("FRIGLET_SPAWNED_BY_TRAY").is_ok_and(|v| v == "1")
    }

    /// Whether the run is ending for a restart rather than a shutdown.
    pub fn restart_requested(&self) -> bool {
        self.restart_requested.load(Ordering::SeqCst)
    }

    /// End the run shortly — after the current response reached the client,
    /// before the listener is torn down.
    fn stop_soon(&self) {
        let shutdown = self.shutdown.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(100)).await;
            shutdown.cancel();
        });
    }

    pub async fn save_state(&self) {
        save_scanner_state(&self.scanner, &self.state_file).await;
    }

    /// Validate → persist → restart. `new_cfg = None` keeps the current
    /// settings; `scan_key = None` keeps the current key.
    async fn apply(&self, new_cfg: Option<DaemonConfig>, scan_key: Option<&str>) -> Response {
        let _guard = self.apply_lock.lock().await;
        let old_cfg = self.settings.lock().unwrap().clone();
        let mut new_cfg = new_cfg.unwrap_or_else(|| old_cfg.clone());
        // New wallet → pin the birthday to the oracle tip before persisting.
        if let Err(e) = config::resolve_start_at_tip(&mut new_cfg).await {
            return Response::Error(e);
        }
        let resolved = match config::validate_daemon_config(&new_cfg) {
            Ok(r) => r,
            Err(e) => return Response::Error(e),
        };
        let new_secret = match scan_key.map(|k| SecretKey::from_str(k.trim())).transpose() {
            Ok(s) => s,
            Err(e) => {
                return Response::Error(format!(
                    "invalid scan key: {e}. Must be a valid 32-byte hex string representing a secp256k1 secret key"
                ));
            }
        };
        let Some(config_path) = &self.config_path else {
            return Response::Error(
                "cannot determine a config file location on this system; \
                 start the daemon with --config"
                    .to_string(),
            );
        };

        let config_changed = new_cfg != old_cfg;
        let key_changed = new_secret.is_some_and(|secret| {
            config::resolve_scan_secret(None, &resolved.key_file).ok() != Some(secret)
        });
        if !config_changed && !key_changed {
            return Response::Ok;
        }

        if config_changed {
            if let Err(e) = friglet_ipc::write_config_toml(config_path, &new_cfg) {
                return Response::Error(e);
            }
            tracing::info!(path = %config_path.display(), "configuration persisted via control socket");
            *self.settings.lock().unwrap() = new_cfg;
        }
        let mut notes = vec![
            "saved; the daemon restarts to apply it (Electrum clients such as Sparrow \
             reconnect automatically)"
                .to_string(),
        ];
        if let Some(secret) = new_secret.filter(|_| key_changed) {
            let hex = hex::encode(secret.secret_bytes());
            if let Err(e) = friglet_ipc::write_key_file(&resolved.key_file, &hex, true) {
                return Response::Error(if config_changed {
                    format!("config saved, but writing the scan key failed: {e}")
                } else {
                    e
                });
            }
            tracing::info!(path = %resolved.key_file.display(), "scan key replaced via control socket");
            if let Some(note) = scan_secret_env_shadows(&secret) {
                notes.push(note);
            }
        }

        tracing::info!("new settings saved; restarting");
        self.restart_requested.store(true, Ordering::SeqCst);
        self.stop_soon();
        Response::OkWithNote(notes.join(". "))
    }
}

/// Save the scanner's state to `state_file` (waits for the scanner lock).
async fn save_scanner_state(scanner: &Mutex<Scanner>, state_file: &Path) {
    let scanner = scanner.lock().await;
    if let Err(e) = scanner.save_to_file(state_file) {
        tracing::warn!(error = %e, "failed to save scanner state");
    } else {
        tracing::debug!("scanner state saved");
    }
    // The state JSON contains the scan secret (written by blindbit-lib);
    // keep it owner-only. Files created by the scan loop's own
    // checkpoints get tightened here and on the next startup.
    crate::config::tighten_state_file_perms(state_file);
}

/// A warning note when `FRIGLET_SCAN_SECRET` is set to a key other than
/// `new_secret`: [`config::resolve_scan_secret`] prefers the env var over the
/// key file, so the restarted daemon keeps using the env key.
fn scan_secret_env_shadows(new_secret: &SecretKey) -> Option<String> {
    let env = std::env::var("FRIGLET_SCAN_SECRET").ok()?;
    let env = env.trim();
    if env.is_empty() {
        return None;
    }
    if SecretKey::from_str(env).is_ok_and(|k| k == *new_secret) {
        return None;
    }
    Some(
        "FRIGLET_SCAN_SECRET is set in the daemon's environment and overrides the key \
         file: the daemon keeps using that key unless the variable is unset"
            .to_string(),
    )
}

/// Serve control requests on `socket_path` until the future is dropped.
pub async fn run(socket_path: String, ctx: Arc<ControlCtx>) -> io::Result<()> {
    let listener = bind_with_stale_cleanup(&socket_path).await?;
    tracing::info!(path = %socket_path, "control socket listening");

    loop {
        match friglet_ipc::accept(&listener).await {
            Ok(mut conn) => {
                let ctx = ctx.clone();
                tokio::spawn(async move {
                    while let Ok(Some(req)) = conn.next_request().await {
                        let resp = ctx.handle(req).await;
                        if conn.respond(&resp).await.is_err() {
                            break;
                        }
                    }
                });
            }
            Err(e) => tracing::error!(error = %e, "control socket accept error"),
        }
    }
}

/// Bind the control socket, removing a stale socket file left behind by a
/// crashed daemon (detected by the bind failing while nothing answers a
/// connection attempt).
async fn bind_with_stale_cleanup(path: &str) -> io::Result<Listener> {
    match friglet_ipc::listen(path) {
        Err(e) if e.kind() == io::ErrorKind::AddrInUse => {
            if friglet_ipc::connect_stream(path).await.is_ok() {
                return Err(io::Error::new(
                    io::ErrorKind::AddrInUse,
                    format!("another friglet daemon is already listening on {path}"),
                ));
            }
            tracing::warn!(path = %path, "removing stale control socket");
            #[cfg(unix)]
            std::fs::remove_file(path)?;
            friglet_ipc::listen(path)
        }
        result => result,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use friglet_ipc::Client;
    use std::path::Path;
    use std::time::Duration;

    const SECRET_HEX: &str = "0000000000000000000000000000000000000000000000000000000000000001";
    const OTHER_SECRET_HEX: &str =
        "0000000000000000000000000000000000000000000000000000000000000002";
    const SPEND_PK: &str = "02e6642fd69bd211f93f7f1f36ca51a26a5290eb2dd1b0d8279a87bb0d480c8443";

    #[test]
    fn owned_outputs_count_tolerates_state_file_variants() {
        let dir = temp_dir("owned-outputs");
        let path = dir.join("state.json");

        assert_eq!(owned_outputs_count(&path), 0);
        std::fs::write(&path, b"not json").unwrap();
        assert_eq!(owned_outputs_count(&path), 0);
        std::fs::write(&path, br#"{"other":[]}"#).unwrap();
        assert_eq!(owned_outputs_count(&path), 0);
        std::fs::write(&path, br#"{"owned_outputs":["02aa","02bb"]}"#).unwrap();
        assert_eq!(owned_outputs_count(&path), 2);
    }

    #[test]
    fn label_address_derivation_is_deterministic_and_unique() {
        use std::str::FromStr;

        let scan_secret = SecretKey::from_str(SECRET_HEX).unwrap();
        let spend_pubkey = PublicKey::from_str(SPEND_PK).unwrap();
        let first = derive_label_addresses(scan_secret, spend_pubkey, BitcoinNetwork::Signet, 2);
        let second = derive_label_addresses(scan_secret, spend_pubkey, BitcoinNetwork::Signet, 2);

        assert_eq!(first, second);
        assert_eq!(first.iter().map(|a| a.label).collect::<Vec<_>>(), [0, 1, 2]);
        assert_ne!(first[0].address, first[1].address);
        assert_ne!(first[1].address, first[2].address);
    }

    /// Serializes the test that sets `FRIGLET_SCAN_SECRET` (process-global)
    /// with tests whose assertions depend on it being unset.
    static SCAN_SECRET_ENV_LOCK: Mutex<()> = Mutex::const_new(());

    /// Removes an env var on drop, so a panicking test cannot leak it.
    struct EnvVarGuard(&'static str);
    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            // SAFETY: only used under SCAN_SECRET_ENV_LOCK; no other thread
            // mutates the environment concurrently.
            unsafe { std::env::remove_var(self.0) };
        }
    }

    fn temp_dir(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("friglet-control-test-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Oracle client on a lazy channel: no connection is made until an RPC
    /// is issued, which these tests never do.
    fn lazy_oracle_client() -> blindbit_lib::OracleServiceClient<tonic::transport::Channel> {
        let channel = tonic::transport::Endpoint::from_static("http://127.0.0.1:1").connect_lazy();
        blindbit_lib::OracleServiceClient::new(channel)
    }

    fn offline_scanner(cfg: &scanner::ScannerConfig) -> Scanner {
        Scanner::new(
            lazy_oracle_client(),
            cfg.p2p_socket_addr,
            cfg.secret_scan,
            cfg.public_spend,
            cfg.max_label_num,
            cfg.state_file.clone(),
            cfg.network,
        )
    }

    fn test_config(dir: &Path) -> DaemonConfig {
        DaemonConfig {
            network: "regtest".to_string(),
            oracle_url: "http://127.0.0.1:1".to_string(),
            p2p_node_addr: Some("127.0.0.1:18444".to_string()),
            start_height: Some(100),
            start_at_tip: false,
            spend_pubkey: Some(SPEND_PK.to_string()),
            max_label_num: 0,
            http_addr: "127.0.0.1:0".to_string(),
            electrum_addr: "127.0.0.1:0".to_string(),
            state_file: dir.join("state.json"),
            log_level: "info".to_string(),
            key_file: Some(dir.join("scan.key")),
            control_socket: None,
        }
    }

    /// A full `ControlCtx` wired against a temp dir, with an offline scanner.
    fn test_ctx(dir: &Path) -> Arc<ControlCtx> {
        test_ctx_with_scan(dir, |cancel| {
            Box::pin(async move {
                cancel.cancelled().await;
                Ok(())
            })
        })
    }

    /// [`test_ctx`] with a custom scan task, given the token that stops it.
    fn test_ctx_with_scan(
        dir: &Path,
        scan: impl Fn(
            CancellationToken,
        ) -> std::pin::Pin<Box<dyn Future<Output = Result<(), String>> + Send>>
        + Send
        + Sync
        + 'static,
    ) -> Arc<ControlCtx> {
        let cfg = test_config(dir);
        friglet_ipc::write_key_file(&dir.join("scan.key"), SECRET_HEX, true).unwrap();
        let config_path = dir.join("config.toml");
        friglet_ipc::write_config_toml(&config_path, &cfg).unwrap();

        let resolved = config::validate_daemon_config(&cfg).unwrap();
        let secret = config::resolve_scan_secret(None, &resolved.key_file).unwrap();
        let scanner_config = scanner::ScannerConfig::new(
            resolved.raw.oracle_url.clone(),
            resolved.p2p_addr,
            secret,
            resolved.spend_pubkey,
            resolved.raw.max_label_num,
            resolved.state_file.clone(),
            resolved.network,
        );
        let scanner_instance = offline_scanner(&scanner_config);
        let electrum_index = scanner_instance.electrum_index();
        let scanner_arc = Arc::new(Mutex::new(scanner_instance));

        let supervisor = Arc::new(ScanSupervisor::new(scan, Arc::default()));

        Arc::new(ControlCtx {
            supervisor,
            scanner: scanner_arc,
            electrum_index,
            electrum_clients: Arc::new(AtomicU64::new(0)),
            outputs_found: Arc::new(AtomicU64::new(0)),
            label_addresses: derive_label_addresses(
                secret,
                resolved.spend_pubkey,
                wallet_network(resolved.network),
                resolved.raw.max_label_num,
            ),
            state_file: resolved.state_file.clone(),
            settings: std::sync::Mutex::new(cfg),
            config_path: Some(config_path),
            apply_lock: Mutex::new(()),
            oracle: Arc::default(),
            log_file: None,
            shutdown: CancellationToken::new(),
            restart_requested: AtomicBool::new(false),
            spawned_by_tray: false,
        })
    }

    /// Whether `ctx` ended its run for a restart within a second.
    async fn restarted(ctx: &ControlCtx) -> bool {
        tokio::time::timeout(Duration::from_secs(1), ctx.shutdown.cancelled())
            .await
            .is_ok()
            && ctx.restart_requested()
    }

    async fn connect_with_retry(path: &str) -> Client {
        for _ in 0..50 {
            match Client::connect(path).await {
                Ok(c) => return c,
                Err(_) => tokio::time::sleep(Duration::from_millis(20)).await,
            }
        }
        panic!("control socket did not come up at {path}");
    }

    #[tokio::test]
    async fn status_reports_silent_payment_transaction_count() {
        let dir = temp_dir("status-tx-count");
        let ctx = test_ctx(&dir);
        let index = ctx.electrum_index.clone();
        index.lock().await.sp_history.extend([
            blindbit_lib::scanner::SpHistoryEntry {
                tx_hash: "11".repeat(32),
                height: 1,
                tweak_hex: "02".repeat(33),
            },
            blindbit_lib::scanner::SpHistoryEntry {
                tx_hash: "22".repeat(32),
                height: 2,
                tweak_hex: "03".repeat(33),
            },
        ]);
        ctx.oracle.lock().unwrap().record_ok(10);

        assert_eq!(ctx.status().await.tx_count, 2);
    }

    #[tokio::test]
    async fn status_reports_a_stalled_scan_and_an_adjusted_start() {
        let dir = temp_dir("status-scan-health");
        let ctx = test_ctx(&dir);
        ctx.supervisor.start();
        assert_eq!(
            ctx.status().await.scan_health,
            friglet_ipc::ScanHealthInfo::default()
        );

        let index = ctx.electrum_index.clone();
        {
            let mut idx = index.lock().await;
            idx.scan_health.stall = Some(scanner::ScanStall {
                height: 100_002,
                reason: "scan stopped at height 100002: the oracle sent no valid block hash"
                    .to_string(),
                since_unix: 1_790_000_000,
            });
            idx.scan_health.oracle_floor_start = Some(scanner::OracleFloorStart {
                requested_height: 50_000,
                floor_height: 100_000,
            });
            idx.scan_health.state_rescan = Some(scanner::StateRescan {
                from_height: 100_500,
                until_height: 101_000,
            });
            idx.scan_health.state_file_reset = Some(scanner::StateFileReset {
                backup_path: "/data/scanner_state.json.unreadable-1".into(),
                error: "Failed to parse JSON".to_string(),
            });
        }

        let health = ctx.status().await.scan_health;
        let stall = health.stall.expect("stall is reported");
        assert_eq!(stall.height, 100_002);
        assert_eq!(stall.since_unix, 1_790_000_000);
        assert!(stall.reason.contains("no valid block hash"));
        assert_eq!(
            health.start_adjusted,
            Some(friglet_ipc::StartAdjustedInfo {
                requested_height: 50_000,
                oracle_floor: 100_000,
            })
        );
        assert_eq!(
            health.state_rescan,
            Some(friglet_ipc::StateRescanInfo {
                from_height: 100_500,
                until_height: 101_000,
            })
        );
        assert_eq!(
            health.state_reset,
            Some(friglet_ipc::StateResetInfo {
                backup_path: "/data/scanner_state.json.unreadable-1".to_string(),
                error: "Failed to parse JSON".to_string(),
            })
        );

        // Paused, nothing is retrying: the stall is not reported.
        assert_eq!(ctx.handle(Request::Stop).await, Response::Ok);
        let status = ctx.status().await;
        assert_eq!(status.scan_state, Some(friglet_ipc::ScanState::Paused));
        assert!(status.scan_health.stall.is_none());
        assert!(status.scan_health.start_adjusted.is_some());
    }

    #[tokio::test]
    async fn stop_pauses_and_start_resumes_in_status() {
        let dir = temp_dir("status-pause");
        let ctx = test_ctx(&dir);
        assert_eq!(ctx.handle(Request::Start).await, Response::Ok);
        let status = ctx.status().await;
        assert!(status.scanning);
        assert_eq!(status.scan_state, Some(friglet_ipc::ScanState::Running));
        assert_eq!(status.pid, Some(std::process::id()));

        assert_eq!(ctx.handle(Request::Stop).await, Response::Ok);
        let status = ctx.status().await;
        assert!(!status.scanning);
        assert_eq!(status.scan_state, Some(friglet_ipc::ScanState::Paused));
        assert!(ctx.supervisor.is_paused());

        assert_eq!(ctx.handle(Request::Start).await, Response::Ok);
        assert_eq!(
            ctx.status().await.scan_state,
            Some(friglet_ipc::ScanState::Running)
        );
    }

    /// A step that blocks a worker thread cannot be interrupted (the scan
    /// has none left; this covers one that slips in): Stop answers within
    /// its wait budget with a note, the status says `stopping` (not
    /// stopped) until the task really ended, Start is refused meanwhile,
    /// and the pause lands afterwards.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn stop_during_a_blocking_scan_step_reports_stopping_then_paused() {
        let dir = temp_dir("status-stopping");
        let ctx = test_ctx_with_scan(&dir, |cancel| {
            Box::pin(async move {
                while !cancel.is_cancelled() {
                    std::thread::sleep(Duration::from_millis(4500));
                    tokio::task::yield_now().await;
                }
                Ok(())
            })
        });
        ctx.supervisor.start();
        tokio::time::sleep(Duration::from_millis(100)).await;

        let began = Instant::now();
        let answer = ctx.handle(Request::Stop).await;
        assert!(
            matches!(&answer, Response::OkWithNote(note) if note.starts_with("stopping")),
            "{answer:?}"
        );
        assert!(began.elapsed() < STOP_WAIT + Duration::from_secs(1));
        let status = ctx.status().await;
        assert_eq!(status.scan_state, Some(friglet_ipc::ScanState::Stopping));
        assert!(status.scanning, "the task is still alive");
        assert!(matches!(
            ctx.handle(Request::Start).await,
            Response::Error(e) if e.contains("still stopping")
        ));

        assert!(
            ctx.supervisor
                .wait_stopped(Some(Duration::from_secs(10)))
                .await
        );
        assert_eq!(
            ctx.status().await.scan_state,
            Some(friglet_ipc::ScanState::Paused)
        );
    }

    /// Stop while the scan downloads a block from a P2P node that has gone
    /// silent (it accepted the connection and sends nothing; blindbit-lib
    /// would wait 30 s per read and retry 5 times): the real
    /// `BlockFetcher`, under the real supervisor, gives way to the stop
    /// token, so Stop answers plainly and the status is `paused` well
    /// within a second.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn stop_during_a_stalled_p2p_download_pauses_within_a_second() {
        use bitcoin::hashes::Hash;
        use blindbit_lib::scanner::{BlockFetcher, FetchFailure};

        let node = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let node_addr = node.local_addr().unwrap();
        let (accepted_tx, accepted) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut held = Vec::new();
            while let Ok((stream, _)) = node.accept() {
                held.push(stream); // never answers, never closes
                let _ = accepted_tx.send(());
            }
        });
        let dir = temp_dir("status-stalled-download");
        let ctx = test_ctx_with_scan(&dir, move |cancel| {
            Box::pin(async move {
                let hash = bitcoin::BlockHash::from_byte_array([7; 32]);
                let fetched = BlockFetcher::new(node_addr, bitcoin_rev::Network::Regtest)
                    .with_cancel(cancel)
                    .fetch(hash, 1)
                    .await;
                match fetched {
                    Err(e) if e.failure == FetchFailure::Cancelled => Ok(()),
                    other => Err(format!("download ended without a stop: {other:?}")),
                }
            })
        });
        ctx.supervisor.start();
        tokio::task::spawn_blocking(move || accepted.recv_timeout(Duration::from_secs(5)))
            .await
            .unwrap()
            .expect("the scan connected to the node");
        tokio::time::sleep(Duration::from_millis(200)).await; // waiting on the node

        let began = Instant::now();
        assert_eq!(ctx.handle(Request::Stop).await, Response::Ok);
        let status = ctx.status().await;
        let took = began.elapsed();
        assert!(took < Duration::from_secs(1), "Stop took {took:?}");
        assert_eq!(status.scan_state, Some(friglet_ipc::ScanState::Paused));
        assert!(!status.scanning);
        assert_eq!(ctx.supervisor.last_error(), None);
        assert_eq!(ctx.handle(Request::Start).await, Response::Ok);
    }

    #[tokio::test]
    async fn status_reports_an_unreachable_oracle_without_waiting_for_it() {
        let dir = temp_dir("status-oracle-down");
        let ctx = test_ctx(&dir);
        ctx.oracle
            .lock()
            .unwrap()
            .record_error("oracle http://127.0.0.1:9: no answer within 5s".to_string());
        let began = Instant::now();
        let status = ctx.status().await;
        assert!(began.elapsed() < Duration::from_millis(500));
        assert!(!status.oracle_connected);
        assert!(status.oracle_error.unwrap().contains("no answer"));
        assert!(status.oracle_down_since_unix.is_some());

        ctx.oracle.lock().unwrap().record_ok(1234);
        let status = ctx.status().await;
        assert!(status.oracle_connected);
        assert_eq!(status.tip_height, Some(1234));
        assert_eq!(status.oracle_error, None);
        assert_eq!(status.oracle_down_since_unix, None);
    }

    fn test_socket_path(tag: &str) -> String {
        #[cfg(windows)]
        {
            format!(
                r"\\.\pipe\friglet-control-test-{tag}-{}",
                std::process::id()
            )
        }
        #[cfg(not(windows))]
        {
            std::env::temp_dir()
                .join(format!(
                    "friglet-control-test-{tag}-{}.sock",
                    std::process::id()
                ))
                .to_string_lossy()
                .into_owned()
        }
    }

    /// Serve `ctx` on a fresh socket and return a connected client.
    async fn serve_ctx(tag: &str, ctx: Arc<ControlCtx>) -> Client {
        let path = test_socket_path(tag);
        #[cfg(not(windows))]
        let _ = std::fs::remove_file(&path);
        tokio::spawn(run(path.clone(), ctx));
        connect_with_retry(&path).await
    }

    fn read_config_file(dir: &Path) -> DaemonConfig {
        let toml = std::fs::read_to_string(dir.join("config.toml")).unwrap();
        toml::from_str(&toml).unwrap()
    }

    #[tokio::test]
    async fn set_config_persists_and_restarts() {
        let dir = temp_dir("setconfig-ok");
        let ctx = test_ctx(&dir);
        let mut client = serve_ctx("setconfig-ok", ctx.clone()).await;

        let new_cfg = DaemonConfig {
            start_height: Some(250),
            oracle_url: "http://oracle.changed.example".to_string(),
            http_addr: "127.0.0.1:9999".to_string(),
            max_label_num: 3,
            ..test_config(&dir)
        };
        let resp = client
            .request(&Request::SetConfig(Box::new(new_cfg.clone())))
            .await
            .unwrap();
        match &resp {
            Response::OkWithNote(note) => assert!(note.contains("restarts"), "note: {note}"),
            other => panic!("expected OkWithNote, got {other:?}"),
        }

        // GetConfig reflects the new values until the restart happens.
        let resp = client.request(&Request::GetConfig).await.unwrap();
        assert_eq!(resp, Response::Config(new_cfg.clone()));
        // The config file was rewritten as TOML with the new values.
        assert_eq!(read_config_file(&dir), new_cfg);
        // ... and the run ends for a restart (not a shutdown).
        assert!(restarted(&ctx).await, "SetConfig must restart the daemon");
    }

    #[tokio::test]
    async fn unchanged_settings_do_not_restart() {
        let _env_lock = SCAN_SECRET_ENV_LOCK.lock().await;
        let dir = temp_dir("setconfig-same");
        let ctx = test_ctx(&dir);
        let mut client = serve_ctx("setconfig-same", ctx.clone()).await;

        let resp = client
            .request(&Request::ApplySettings {
                config: Box::new(test_config(&dir)),
                scan_key: Some(SECRET_HEX.to_string()),
            })
            .await
            .unwrap();
        assert_eq!(resp, Response::Ok);
        assert!(!restarted(&ctx).await);
    }

    #[tokio::test]
    async fn set_config_invalid_rejected_and_nothing_persisted() {
        let dir = temp_dir("setconfig-invalid");
        let ctx = test_ctx(&dir);
        let mut client = serve_ctx("setconfig-invalid", ctx).await;

        let file_before = std::fs::read_to_string(dir.join("config.toml")).unwrap();

        for (broken, expected_msg) in [
            (
                DaemonConfig {
                    network: "flarkchain".to_string(),
                    ..test_config(&dir)
                },
                "invalid network",
            ),
            (
                DaemonConfig {
                    oracle_url: "gopher://oracle.example".to_string(),
                    ..test_config(&dir)
                },
                "oracle_url",
            ),
            (
                DaemonConfig {
                    p2p_node_addr: Some("not-an-addr".to_string()),
                    ..test_config(&dir)
                },
                "p2p_node_addr",
            ),
            (
                DaemonConfig {
                    start_height: Some(0),
                    ..test_config(&dir)
                },
                "start_height",
            ),
            (
                DaemonConfig {
                    http_addr: "localhost:notaport".to_string(),
                    ..test_config(&dir)
                },
                "http_addr",
            ),
        ] {
            let resp = client
                .request(&Request::SetConfig(Box::new(broken)))
                .await
                .unwrap();
            match &resp {
                Response::Error(msg) => {
                    assert!(msg.contains(expected_msg), "unexpected error: {msg}")
                }
                other => panic!("expected Error containing {expected_msg:?}, got {other:?}"),
            }
        }

        // Nothing persisted, effective config unchanged.
        let file_after = std::fs::read_to_string(dir.join("config.toml")).unwrap();
        assert_eq!(file_before, file_after);
        let resp = client.request(&Request::GetConfig).await.unwrap();
        assert_eq!(resp, Response::Config(test_config(&dir)));
    }

    #[tokio::test]
    async fn set_scan_key_writes_0600_key_file_and_restarts() {
        // A note-free outcome requires FRIGLET_SCAN_SECRET to be unset, so
        // exclude the test that sets it.
        let _env_lock = SCAN_SECRET_ENV_LOCK.lock().await;
        let dir = temp_dir("setkey-ok");
        let ctx = test_ctx(&dir);
        let mut client = serve_ctx("setkey-ok", ctx.clone()).await;

        let resp = client
            .request(&Request::SetScanKey(OTHER_SECRET_HEX.to_string()))
            .await
            .unwrap();
        match &resp {
            Response::OkWithNote(note) => {
                assert!(note.contains("restarts"), "note: {note}");
                assert!(!note.contains("FRIGLET_SCAN_SECRET"), "note: {note}");
            }
            other => panic!("expected OkWithNote, got {other:?}"),
        }

        let key_path = dir.join("scan.key");
        assert_eq!(
            std::fs::read_to_string(&key_path).unwrap().trim(),
            OTHER_SECRET_HEX
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&key_path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        assert!(restarted(&ctx).await);
    }

    #[tokio::test]
    async fn apply_settings_switches_wallet_in_one_restart() {
        let _env_lock = SCAN_SECRET_ENV_LOCK.lock().await;
        let dir = temp_dir("apply-wallet");
        let ctx = test_ctx(&dir);
        let mut client = serve_ctx("apply-wallet", ctx.clone()).await;

        let new_cfg = DaemonConfig {
            spend_pubkey: Some(
                "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798".to_string(),
            ),
            start_height: Some(50),
            ..test_config(&dir)
        };
        let resp = client
            .request(&Request::ApplySettings {
                config: Box::new(new_cfg.clone()),
                scan_key: Some(OTHER_SECRET_HEX.to_string()),
            })
            .await
            .unwrap();
        assert!(matches!(resp, Response::OkWithNote(_)), "got {resp:?}");
        assert_eq!(read_config_file(&dir), new_cfg);
        assert_eq!(
            std::fs::read_to_string(dir.join("scan.key"))
                .unwrap()
                .trim(),
            OTHER_SECRET_HEX
        );
        assert!(restarted(&ctx).await);
    }

    #[tokio::test]
    async fn apply_settings_rejects_bad_key_before_persisting_anything() {
        let dir = temp_dir("apply-badkey");
        let ctx = test_ctx(&dir);
        let mut client = serve_ctx("apply-badkey", ctx.clone()).await;
        let file_before = std::fs::read_to_string(dir.join("config.toml")).unwrap();

        let resp = client
            .request(&Request::ApplySettings {
                config: Box::new(DaemonConfig {
                    start_height: Some(50),
                    ..test_config(&dir)
                }),
                scan_key: Some("zz".to_string()),
            })
            .await
            .unwrap();
        assert!(
            matches!(&resp, Response::Error(msg) if msg.contains("invalid scan key")),
            "got {resp:?}"
        );
        assert_eq!(
            std::fs::read_to_string(dir.join("config.toml")).unwrap(),
            file_before
        );
        assert!(!restarted(&ctx).await);
    }

    #[tokio::test]
    async fn set_scan_key_rejects_bad_hex_without_touching_key_file() {
        let dir = temp_dir("setkey-bad");
        let ctx = test_ctx(&dir);
        let mut client = serve_ctx("setkey-bad", ctx).await;

        for bad in ["not-hex", "abcd", &"ff".repeat(31), &"00".repeat(32)] {
            let resp = client
                .request(&Request::SetScanKey(bad.to_string()))
                .await
                .unwrap();
            match &resp {
                Response::Error(msg) => {
                    assert!(msg.contains("invalid scan key"), "unexpected error: {msg}")
                }
                other => panic!("expected Error for {bad:?}, got {other:?}"),
            }
        }

        assert_eq!(
            std::fs::read_to_string(dir.join("scan.key"))
                .unwrap()
                .trim(),
            SECRET_HEX,
            "key file must be untouched after rejected updates"
        );
    }

    #[tokio::test]
    async fn set_scan_key_warns_when_env_secret_overrides_it() {
        let _env_lock = SCAN_SECRET_ENV_LOCK.lock().await;
        // SAFETY: guarded by SCAN_SECRET_ENV_LOCK; the value equals the key
        // file content every test ctx starts with, so concurrent tests that
        // resolve the secret via the env var see no difference.
        unsafe { std::env::set_var("FRIGLET_SCAN_SECRET", SECRET_HEX) };
        let _env_guard = EnvVarGuard("FRIGLET_SCAN_SECRET");

        let dir = temp_dir("setkey-env");
        let ctx = test_ctx(&dir);
        let mut client = serve_ctx("setkey-env", ctx).await;

        let resp = client
            .request(&Request::SetScanKey(OTHER_SECRET_HEX.to_string()))
            .await
            .unwrap();
        match &resp {
            Response::OkWithNote(note) => {
                assert!(note.contains("FRIGLET_SCAN_SECRET"), "note: {note}")
            }
            other => panic!("expected OkWithNote, got {other:?}"),
        }
        assert_eq!(
            std::fs::read_to_string(dir.join("scan.key"))
                .unwrap()
                .trim(),
            OTHER_SECRET_HEX
        );
    }

    #[tokio::test]
    async fn start_and_stop_wait_for_the_apply_lock() {
        let dir = temp_dir("start-lock");
        let ctx = test_ctx(&dir);

        // Simulate a config apply in progress.
        let guard = ctx.apply_lock.lock().await;
        let ctx2 = ctx.clone();
        let start = tokio::spawn(async move { ctx2.handle(Request::Start).await });
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            !ctx.supervisor.is_running(),
            "Start must block while the apply lock is held"
        );
        drop(guard);
        assert_eq!(start.await.unwrap(), Response::Ok);
        assert!(ctx.supervisor.is_running());

        let guard = ctx.apply_lock.lock().await;
        let ctx2 = ctx.clone();
        let stop = tokio::spawn(async move { ctx2.handle(Request::Stop).await });
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            ctx.supervisor.is_running(),
            "Stop must block while the apply lock is held"
        );
        drop(guard);
        assert_eq!(stop.await.unwrap(), Response::Ok);
        assert!(!ctx.supervisor.is_running());
    }
}
