//! Control socket: serves `friglet-ipc` requests over a local socket
//! (Unix domain socket / Windows named pipe, newline-delimited JSON).
//!
//! # `SetConfig` / `SetScanKey` apply semantics (v1)
//!
//! - The new config is validated first; on any validation error nothing is
//!   persisted and nothing changes.
//! - Valid configs are persisted to the daemon's config file (the file it
//!   loaded at startup, or the default path when none existed) as TOML.
//! - Scanner-affecting fields (`network`, `oracle_url`, `p2p_node_addr`,
//!   `start_height`, `spend_pubkey`, `max_label_num`, `state_file`,
//!   `key_file`) are applied live: the scan task is stopped, state is saved,
//!   a fresh scanner is built from the new settings and swapped in, and the
//!   scan task is restarted if it was running. The Electrum server keeps
//!   serving the pre-change wallet view (its index and notification channel
//!   belong to the old scanner) until the daemon restarts — reported to the
//!   client via `Response::OkWithNote`.
//! - `http_addr` / `electrum_addr` / `control_socket` / `log_level` changes
//!   are persisted but only take effect after a daemon restart (live
//!   rebinding is out of scope); also reported via `OkWithNote`.

use std::io;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use blindbit_lib::scanner::{self, Scanner, WalletElectrumIndex};
use friglet_ipc::{DaemonConfig, Listener, Request, Response, StatusInfo};
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

use crate::config::{self, ResolvedConfig};
use crate::supervisor::ScanSupervisor;

/// How long a cached oracle tip is considered fresh.
const ORACLE_TIP_TTL: Duration = Duration::from_secs(10);
/// Cap how long `GetStatus` waits on a slow/unreachable oracle.
const ORACLE_TIP_FETCH_TIMEOUT: Duration = Duration::from_secs(2);

/// Builds a fresh [`Scanner`] for a new configuration. In the daemon this is
/// `blindbit_lib::scanner::load_scanner` (which connects to the oracle);
/// tests inject a builder that needs no network.
pub type ScannerBuilder = Box<
    dyn Fn(scanner::ScannerConfig) -> Pin<Box<dyn Future<Output = Result<Scanner, String>> + Send>>
        + Send
        + Sync,
>;

/// Cached BlindBit oracle chain tip for [`ControlCtx::status`].
#[derive(Debug, Default, Clone)]
pub struct OracleTipCache {
    tip: Option<u64>,
    fetched_at: Option<Instant>,
}

impl OracleTipCache {
    fn is_fresh(&self) -> bool {
        self.fetched_at
            .is_some_and(|at| at.elapsed() < ORACLE_TIP_TTL)
    }
}

/// Prefer the oracle tip when known; else the last scanned (electrum) tip.
fn pick_tip(oracle: Option<u64>, electrum: Option<u64>) -> Option<u64> {
    oracle.or(electrum)
}

/// Everything the request handler needs from the daemon.
pub struct ControlCtx {
    pub supervisor: Arc<ScanSupervisor>,
    /// The scanner is swapped in place when `SetConfig` changes
    /// scanner-affecting settings; the supervisor's task factory locks this
    /// same `Arc`, so a restart picks up the new instance.
    pub scanner: Arc<Mutex<Scanner>>,
    /// Index of the *current* scanner, used for status reporting. Replaced
    /// together with the scanner. The Electrum server holds its own clone of
    /// the startup index and is not rewired (see module docs).
    pub electrum_index: std::sync::Mutex<Arc<Mutex<WalletElectrumIndex>>>,
    pub electrum_clients: Arc<AtomicU64>,
    /// Current effective configuration, updated by `SetConfig`.
    pub settings: std::sync::Mutex<DaemonConfig>,
    /// Where `SetConfig` persists the config; `None` when no location could
    /// be determined (no config dir on this platform).
    pub config_path: Option<PathBuf>,
    /// Serializes `SetConfig` / `SetScanKey` / `Start` / `Stop` so lifecycle
    /// verbs cannot interleave with persist + scanner rebuild (e.g. starting
    /// the outgoing scanner in the middle of a swap).
    pub apply_lock: Mutex<()>,
    /// How to construct a scanner when new settings are applied.
    pub scanner_builder: ScannerBuilder,
    /// Cached oracle chain tip so `GetStatus` does not hit the network every
    /// poll (TTL ≈ 10s).
    pub oracle_tip_cache: std::sync::Mutex<OracleTipCache>,
    pub shutdown: CancellationToken,
}

impl ControlCtx {
    pub async fn handle(&self, req: Request) -> Response {
        match req {
            Request::GetStatus => Response::Status(self.status().await),
            Request::Start => {
                // Serialize with SetConfig/SetScanKey so the old scanner
                // cannot be started in the middle of a rebuild + swap.
                let _guard = self.apply_lock.lock().await;
                if self.supervisor.start() {
                    tracing::info!("scan task started via control socket");
                }
                Response::Ok
            }
            Request::Stop => {
                let _guard = self.apply_lock.lock().await;
                if self.supervisor.stop().await {
                    tracing::info!("scan task stopped via control socket");
                    self.save_state().await;
                }
                Response::Ok
            }
            Request::GetConfig => Response::Config(self.settings.lock().unwrap().clone()),
            Request::SetConfig(new_cfg) => self.set_config(*new_cfg).await,
            Request::SetScanKey(hex) => self.set_scan_key(&hex).await,
            Request::Shutdown => {
                tracing::info!("shutdown requested via control socket");
                // Delay the cancel slightly so the Ok response reaches the
                // client before the listener is torn down.
                let shutdown = self.shutdown.clone();
                tokio::spawn(async move {
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    shutdown.cancel();
                });
                Response::Ok
            }
        }
    }

    /// Poll the BlindBit oracle for the real chain tip, with a short TTL
    /// cache. Failures return the stale cache (if any) and never break
    /// `GetStatus`.
    async fn fetch_oracle_tip(&self) -> Option<u64> {
        {
            let cache = self.oracle_tip_cache.lock().unwrap();
            if cache.is_fresh() {
                return cache.tip;
            }
        }

        let url = self.settings.lock().unwrap().oracle_url.clone();
        let stale = self.oracle_tip_cache.lock().unwrap().tip;

        let fetch = async {
            let mut client = blindbit_lib::OracleServiceClient::connect(url).await.ok()?;
            let resp = client.get_info(tonic::Request::new(())).await.ok()?;
            Some(resp.into_inner().height)
        };

        match tokio::time::timeout(ORACLE_TIP_FETCH_TIMEOUT, fetch).await {
            Ok(Some(height)) => {
                let mut cache = self.oracle_tip_cache.lock().unwrap();
                cache.tip = Some(height);
                cache.fetched_at = Some(Instant::now());
                Some(height)
            }
            _ => stale,
        }
    }

    async fn status(&self) -> StatusInfo {
        let index = self.electrum_index.lock().unwrap().clone();
        let (electrum_tip, scan_progress, sp_address) = {
            let idx = index.lock().await;
            let tip = idx.tip.as_ref().map(|(h, _)| u64::from(*h));
            let addr = (!idx.sp_address.is_empty()).then(|| idx.sp_address.clone());
            (tip, idx.scan_progress, addr)
        };

        // While the scan task runs it holds the scanner mutex, so fall back
        // to the electrum index tip (which the scanner advances per scanned
        // block) when the lock is unavailable.
        let scanned_height = match self.scanner.try_lock() {
            Ok(s) => s.get_last_scanned_block_height(),
            Err(_) => electrum_tip.unwrap_or(0),
        };

        let oracle_tip = self.fetch_oracle_tip().await;
        let tip_height = pick_tip(oracle_tip, electrum_tip);

        let scanning = self.supervisor.is_running();
        let last_error = self.supervisor.last_error();
        let network = self.settings.lock().unwrap().network.clone();
        let oracle_connected = self.oracle_tip_cache.lock().unwrap().is_fresh();

        StatusInfo {
            scanning,
            scanned_height,
            tip_height,
            scan_progress,
            network,
            electrum_clients: self.electrum_clients.load(Ordering::Relaxed),
            oracle_connected,
            last_error,
            sp_address,
            version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }

    pub async fn save_state(&self) {
        let state_file = self.settings.lock().unwrap().state_file.clone();
        let scanner = self.scanner.lock().await;
        if let Err(e) = scanner.save_to_file(&state_file) {
            tracing::warn!(error = %e, "failed to save scanner state");
        } else {
            tracing::debug!("scanner state saved");
        }
        // The state JSON contains the scan secret (written by blindbit-lib);
        // keep it owner-only. Files created by the scan loop's own
        // checkpoints get tightened here and on the next startup.
        crate::config::tighten_state_file_perms(&state_file);
    }

    /// Validate → persist → apply a full config replacement.
    async fn set_config(&self, new_cfg: DaemonConfig) -> Response {
        let _guard = self.apply_lock.lock().await;
        let resolved = match config::validate_daemon_config(&new_cfg) {
            Ok(r) => r,
            Err(e) => return Response::Error(e),
        };
        let Some(config_path) = &self.config_path else {
            return Response::Error(
                "cannot determine a config file location on this system; \
                 start the daemon with --config"
                    .to_string(),
            );
        };

        let old_cfg = self.settings.lock().unwrap().clone();

        if let Err(e) = config::write_config_file(config_path, &new_cfg) {
            return Response::Error(e);
        }
        tracing::info!(path = %config_path.display(), "configuration persisted via control socket");
        // Update the effective settings as soon as the file is written so
        // `GetConfig` matches the on-disk config even when applying fails
        // below (the error tells the client it was saved but not applied).
        *self.settings.lock().unwrap() = new_cfg.clone();

        let mut notes: Vec<String> = Vec::new();
        let restart_only: Vec<&str> = [
            ("http_addr", new_cfg.http_addr != old_cfg.http_addr),
            (
                "electrum_addr",
                new_cfg.electrum_addr != old_cfg.electrum_addr,
            ),
            (
                "control_socket",
                new_cfg.control_socket != old_cfg.control_socket,
            ),
            ("log_level", new_cfg.log_level != old_cfg.log_level),
        ]
        .into_iter()
        .filter_map(|(name, changed)| changed.then_some(name))
        .collect();
        if !restart_only.is_empty() {
            notes.push(format!(
                "changes to {} are saved but only take effect after a daemon restart",
                restart_only.join(", ")
            ));
        }

        if scanner_settings_changed(&old_cfg, &new_cfg) {
            if let Err(e) = self.rebuild_scanner(&resolved, None).await {
                return Response::Error(format!(
                    "config saved to {}, but applying it failed: {e}; \
                     a daemon restart may be required",
                    config_path.display()
                ));
            }
            notes.push(
                "scan settings applied; the Electrum server keeps serving the previous \
                 wallet view until the daemon restarts"
                    .to_string(),
            );
        }

        if notes.is_empty() {
            Response::Ok
        } else {
            Response::OkWithNote(notes.join(". "))
        }
    }

    /// Validate and write the scan secret to the key file, then restart the
    /// scanner so the new key takes effect (unless an existing state file
    /// pins the old key — see the note below).
    async fn set_scan_key(&self, hex: &str) -> Response {
        let _guard = self.apply_lock.lock().await;
        let settings = self.settings.lock().unwrap().clone();
        let resolved = match config::validate_daemon_config(&settings) {
            Ok(r) => r,
            Err(e) => return Response::Error(format!("current configuration is unusable: {e}")),
        };

        let secret = match config::replace_scan_key(&resolved.key_file, hex) {
            Ok(s) => s,
            Err(e) => return Response::Error(e),
        };
        tracing::info!(path = %resolved.key_file.display(), "scan key replaced via control socket");

        // blindbit-lib restores the scan secret embedded in the state file,
        // ignoring the key file, so rebuilding against a state file created
        // with a different key would silently keep the old key.
        if state_file_key_mismatch(&resolved.state_file, &secret) {
            return Response::OkWithNote(format!(
                "scan key file updated, but the existing state file {} was created with a \
                 different key and the daemon keeps scanning with that key. Point state_file \
                 at a fresh path (or remove the old state file) for the new key to take effect",
                resolved.state_file.display()
            ));
        }

        // Rebuild with the just-written key explicitly: `resolve_scan_secret`
        // prefers FRIGLET_SCAN_SECRET over the key file, which would silently
        // ignore the rotation while that env var is set.
        match self.rebuild_scanner(&resolved, Some(secret)).await {
            Ok(()) => match scan_secret_env_shadows(&secret) {
                Some(note) => Response::OkWithNote(note),
                None => Response::Ok,
            },
            Err(e) => Response::Error(format!(
                "scan key file updated, but restarting the scanner failed: {e}; \
                 a daemon restart may be required"
            )),
        }
    }

    /// Stop the scan task, save state, build a fresh scanner from `resolved`
    /// and swap it into the shared `Arc`, then restart the scan task if it
    /// was running.
    ///
    /// `secret` overrides the usual secret resolution (env var, then key
    /// file); `SetScanKey` passes the key it just wrote so a lingering
    /// `FRIGLET_SCAN_SECRET` cannot undo the rotation.
    async fn rebuild_scanner(
        &self,
        resolved: &ResolvedConfig,
        secret: Option<bitcoin::secp256k1::SecretKey>,
    ) -> Result<(), String> {
        let was_running = self.supervisor.is_running();
        self.supervisor.stop().await;
        // Persist the outgoing scanner's progress to the *old* state file.
        self.save_state().await;

        let secret = match secret {
            Some(s) => s,
            None => config::resolve_scan_secret(None, &resolved.key_file)?,
        };
        let scanner_config = scanner::ScannerConfig::new(
            resolved.oracle_url.clone(),
            resolved.p2p_addr,
            secret,
            resolved.spend_pubkey,
            resolved.max_label_num,
            resolved.state_file.clone(),
            resolved.network,
        );
        let mut new_scanner = (self.scanner_builder)(scanner_config)
            .await
            .map_err(|e| format!("failed to load scanner with the new settings: {e}"))?;
        new_scanner
            .rebuild_electrum_index_from_graph(resolved.start_height)
            .await;
        let new_index = new_scanner.electrum_index();
        {
            let mut idx = new_index.lock().await;
            idx.sp_start_height = resolved.start_height;
        }
        if new_scanner.get_last_scanned_block_height() < resolved.start_height {
            new_scanner.update_last_scanned_block_height(resolved.start_height.saturating_sub(1));
        }
        config::tighten_state_file_perms(&resolved.state_file);

        *self.scanner.lock().await = new_scanner;
        *self.electrum_index.lock().unwrap() = new_index;

        if was_running {
            self.supervisor.start();
            tracing::info!("scan task restarted with new settings");
        }
        Ok(())
    }
}

/// A warning note when `FRIGLET_SCAN_SECRET` is set to a key other than
/// `new_secret`: the running scanner uses the new key, but
/// [`config::resolve_scan_secret`] prefers the env var over the key file, so
/// the next daemon restart would revert to the env key.
fn scan_secret_env_shadows(new_secret: &bitcoin::secp256k1::SecretKey) -> Option<String> {
    use std::str::FromStr;
    let env = std::env::var("FRIGLET_SCAN_SECRET").ok()?;
    let env = env.trim();
    if env.is_empty() {
        return None;
    }
    if bitcoin::secp256k1::SecretKey::from_str(env).is_ok_and(|k| k == *new_secret) {
        return None;
    }
    Some(
        "scan key applied, but FRIGLET_SCAN_SECRET is set in the daemon's environment and \
         overrides the key file: the old key comes back on the next daemon restart unless \
         the variable is unset"
            .to_string(),
    )
}

/// Whether any field that is baked into the scanner differs.
fn scanner_settings_changed(old: &DaemonConfig, new: &DaemonConfig) -> bool {
    old.network != new.network
        || old.oracle_url != new.oracle_url
        || old.p2p_node_addr != new.p2p_node_addr
        || old.start_height != new.start_height
        || old.spend_pubkey != new.spend_pubkey
        || old.max_label_num != new.max_label_num
        || old.state_file != new.state_file
        || old.key_file != new.key_file
}

/// Whether `state_file` exists and embeds a scan secret other than `secret`
/// (blindbit-lib persists the secret inside the state JSON).
fn state_file_key_mismatch(
    state_file: &std::path::Path,
    secret: &bitcoin::secp256k1::SecretKey,
) -> bool {
    let Ok(json) = std::fs::read_to_string(state_file) else {
        return false;
    };
    let Ok(value) = serde_json::from_str::<serde_json::Value>(&json) else {
        return false;
    };
    match value.get("secret_scan_hex").and_then(|v| v.as_str()) {
        Some(embedded) => !embedded.eq_ignore_ascii_case(&hex::encode(secret.secret_bytes())),
        None => false,
    }
}

/// Serve control requests on `socket_path` until the future is dropped.
///
/// Generic over the handler so tests can use a stub instead of a full
/// [`ControlCtx`].
pub async fn run<H, Fut>(socket_path: String, handler: H) -> io::Result<()>
where
    H: Fn(Request) -> Fut + Clone + Send + Sync + 'static,
    Fut: Future<Output = Response> + Send,
{
    let listener = bind_with_stale_cleanup(&socket_path).await?;
    tracing::info!(path = %socket_path, "control socket listening");

    loop {
        match friglet_ipc::accept(&listener).await {
            Ok(mut conn) => {
                let handler = handler.clone();
                tokio::spawn(async move {
                    while let Ok(Some(req)) = conn.next_request().await {
                        let resp = handler(req).await;
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
    fn pick_tip_prefers_oracle_then_electrum() {
        assert_eq!(pick_tip(Some(300), Some(200)), Some(300));
        assert_eq!(pick_tip(None, Some(200)), Some(200));
        assert_eq!(pick_tip(None, None), None);
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

    /// A full `ControlCtx` wired against a temp dir, with an offline scanner
    /// and a scanner builder that needs no network.
    fn test_ctx(dir: &Path) -> Arc<ControlCtx> {
        test_ctx_with_builder(
            dir,
            Box::new(|cfg| Box::pin(async move { Ok(offline_scanner(&cfg)) })),
        )
    }

    /// [`test_ctx`] with a custom scanner builder (failure injection,
    /// recording the config the rebuild uses, ...).
    fn test_ctx_with_builder(dir: &Path, scanner_builder: ScannerBuilder) -> Arc<ControlCtx> {
        let cfg = test_config(dir);
        config::replace_scan_key(&dir.join("scan.key"), SECRET_HEX).unwrap();
        let config_path = dir.join("config.toml");
        config::write_config_file(&config_path, &cfg).unwrap();

        let resolved = config::validate_daemon_config(&cfg).unwrap();
        let secret = config::resolve_scan_secret(None, &resolved.key_file).unwrap();
        let scanner_config = scanner::ScannerConfig::new(
            resolved.oracle_url.clone(),
            resolved.p2p_addr,
            secret,
            resolved.spend_pubkey,
            resolved.max_label_num,
            resolved.state_file.clone(),
            resolved.network,
        );
        let scanner_instance = offline_scanner(&scanner_config);
        let electrum_index = scanner_instance.electrum_index();
        let scanner_arc = Arc::new(Mutex::new(scanner_instance));

        let supervisor = Arc::new(ScanSupervisor::new(|| {
            Box::pin(async {
                std::future::pending::<()>().await;
                Ok(())
            })
        }));

        Arc::new(ControlCtx {
            supervisor,
            scanner: scanner_arc,
            electrum_index: std::sync::Mutex::new(electrum_index),
            electrum_clients: Arc::new(AtomicU64::new(0)),
            settings: std::sync::Mutex::new(cfg),
            config_path: Some(config_path),
            apply_lock: Mutex::new(()),
            scanner_builder,
            oracle_tip_cache: std::sync::Mutex::new(OracleTipCache::default()),
            shutdown: CancellationToken::new(),
        })
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

    fn dummy_status() -> StatusInfo {
        StatusInfo {
            scanning: false,
            scanned_height: 42,
            tip_height: None,
            scan_progress: 0.0,
            network: "regtest".to_string(),
            electrum_clients: 0,
            oracle_connected: false,
            last_error: None,
            sp_address: None,
            version: "test".to_string(),
        }
    }

    #[tokio::test]
    async fn get_status_roundtrip_over_control_socket() {
        #[cfg(windows)]
        let path = format!(r"\\.\pipe\friglet-control-test-{}", std::process::id());
        #[cfg(not(windows))]
        let path = std::env::temp_dir()
            .join(format!("friglet-control-test-{}.sock", std::process::id()))
            .to_string_lossy()
            .into_owned();

        let server_path = path.clone();
        tokio::spawn(run(server_path, |req| async move {
            match req {
                Request::GetStatus => Response::Status(dummy_status()),
                _ => Response::Ok,
            }
        }));

        let mut client = None;
        for _ in 0..50 {
            match Client::connect(&path).await {
                Ok(c) => {
                    client = Some(c);
                    break;
                }
                Err(_) => tokio::time::sleep(Duration::from_millis(20)).await,
            }
        }
        let mut client = client.expect("control socket did not come up");

        let resp = client.request(&Request::GetStatus).await.unwrap();
        assert_eq!(resp, Response::Status(dummy_status()));

        #[cfg(not(windows))]
        let _ = std::fs::remove_file(&path);
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
        tokio::spawn(run(path.clone(), move |req| {
            let ctx = ctx.clone();
            async move { ctx.handle(req).await }
        }));
        connect_with_retry(&path).await
    }

    fn read_config_file(dir: &Path) -> DaemonConfig {
        let toml = std::fs::read_to_string(dir.join("config.toml")).unwrap();
        toml::from_str(&toml).unwrap()
    }

    #[tokio::test]
    async fn set_config_roundtrip_persists_and_applies() {
        let dir = temp_dir("setconfig-ok");
        let ctx = test_ctx(&dir);
        let mut client = serve_ctx("setconfig-ok", ctx.clone()).await;

        let new_cfg = DaemonConfig {
            start_height: Some(250),
            oracle_url: "http://oracle.changed.example".to_string(),
            max_label_num: 3,
            ..test_config(&dir)
        };
        let resp = client
            .request(&Request::SetConfig(Box::new(new_cfg.clone())))
            .await
            .unwrap();
        // Scanner-affecting fields changed → rebuild happened → the response
        // carries the Electrum-restart note.
        match &resp {
            Response::OkWithNote(note) => assert!(note.contains("Electrum"), "note: {note}"),
            other => panic!("expected OkWithNote, got {other:?}"),
        }

        // GetConfig reflects the new values.
        let resp = client.request(&Request::GetConfig).await.unwrap();
        assert_eq!(resp, Response::Config(new_cfg.clone()));

        // The config file was rewritten as TOML with the new values.
        assert_eq!(read_config_file(&dir), new_cfg);

        // The swapped-in scanner starts from the new start height.
        assert_eq!(
            ctx.scanner.lock().await.get_last_scanned_block_height(),
            249
        );
    }

    #[tokio::test]
    async fn set_config_bind_addr_change_needs_daemon_restart() {
        let dir = temp_dir("setconfig-bind");
        let ctx = test_ctx(&dir);
        let mut client = serve_ctx("setconfig-bind", ctx).await;

        let new_cfg = DaemonConfig {
            http_addr: "127.0.0.1:9999".to_string(),
            ..test_config(&dir)
        };
        let resp = client
            .request(&Request::SetConfig(Box::new(new_cfg.clone())))
            .await
            .unwrap();
        match &resp {
            Response::OkWithNote(note) => {
                assert!(note.contains("http_addr"), "note: {note}");
                assert!(note.contains("daemon restart"), "note: {note}");
            }
            other => panic!("expected OkWithNote, got {other:?}"),
        }
        assert_eq!(read_config_file(&dir).http_addr, "127.0.0.1:9999");
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
    async fn set_scan_key_writes_0600_key_file() {
        // `Response::Ok` (note-less) requires FRIGLET_SCAN_SECRET to be
        // unset, so exclude the test that sets it.
        let _env_lock = SCAN_SECRET_ENV_LOCK.lock().await;
        let dir = temp_dir("setkey-ok");
        let ctx = test_ctx(&dir);
        let mut client = serve_ctx("setkey-ok", ctx).await;

        let resp = client
            .request(&Request::SetScanKey(OTHER_SECRET_HEX.to_string()))
            .await
            .unwrap();
        assert_eq!(resp, Response::Ok);

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
    async fn set_scan_key_warns_when_state_file_pins_old_key() {
        let dir = temp_dir("setkey-mismatch");
        let ctx = test_ctx(&dir);
        // Persist state embedding the current (old) secret.
        ctx.save_state().await;
        let mut client = serve_ctx("setkey-mismatch", ctx).await;

        let resp = client
            .request(&Request::SetScanKey(OTHER_SECRET_HEX.to_string()))
            .await
            .unwrap();
        match &resp {
            Response::OkWithNote(note) => {
                assert!(note.contains("state file"), "note: {note}");
            }
            other => panic!("expected OkWithNote, got {other:?}"),
        }
        // The key file itself was still updated.
        assert_eq!(
            std::fs::read_to_string(dir.join("scan.key"))
                .unwrap()
                .trim(),
            OTHER_SECRET_HEX
        );
    }

    #[tokio::test]
    async fn set_scan_key_rebuilds_with_new_key_despite_env_override() {
        use std::str::FromStr;

        let _env_lock = SCAN_SECRET_ENV_LOCK.lock().await;
        // SAFETY: guarded by SCAN_SECRET_ENV_LOCK; the value equals the key
        // file content every test ctx starts with, so concurrent tests that
        // resolve the secret via the env var see no difference.
        unsafe { std::env::set_var("FRIGLET_SCAN_SECRET", SECRET_HEX) };
        let _env_guard = EnvVarGuard("FRIGLET_SCAN_SECRET");

        let dir = temp_dir("setkey-env");
        let seen_secret = Arc::new(std::sync::Mutex::new(None));
        let recorder = seen_secret.clone();
        let ctx = test_ctx_with_builder(
            &dir,
            Box::new(move |cfg| {
                *recorder.lock().unwrap() = Some(cfg.secret_scan);
                Box::pin(async move { Ok(offline_scanner(&cfg)) })
            }),
        );
        let mut client = serve_ctx("setkey-env", ctx).await;

        let resp = client
            .request(&Request::SetScanKey(OTHER_SECRET_HEX.to_string()))
            .await
            .unwrap();
        // Rotation succeeds but warns that the env var wins after a restart.
        match &resp {
            Response::OkWithNote(note) => {
                assert!(note.contains("FRIGLET_SCAN_SECRET"), "note: {note}")
            }
            other => panic!("expected OkWithNote, got {other:?}"),
        }
        // The rebuilt scanner uses the just-written key, not the env secret.
        assert_eq!(
            *seen_secret.lock().unwrap(),
            Some(bitcoin::secp256k1::SecretKey::from_str(OTHER_SECRET_HEX).unwrap()),
            "rebuild must use the rotated key, not FRIGLET_SCAN_SECRET"
        );
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

    #[tokio::test]
    async fn failed_apply_keeps_get_config_matching_disk() {
        let dir = temp_dir("setconfig-applyfail");
        let ctx = test_ctx_with_builder(
            &dir,
            Box::new(|_cfg| Box::pin(async { Err("injected scanner build failure".to_string()) })),
        );
        let mut client = serve_ctx("setconfig-applyfail", ctx).await;

        let new_cfg = DaemonConfig {
            start_height: Some(777),
            ..test_config(&dir)
        };
        let resp = client
            .request(&Request::SetConfig(Box::new(new_cfg.clone())))
            .await
            .unwrap();
        match &resp {
            Response::Error(msg) => {
                assert!(msg.contains("config saved"), "error: {msg}");
                assert!(msg.contains("applying it failed"), "error: {msg}");
            }
            other => panic!("expected Error, got {other:?}"),
        }

        // Disk has the new config and GetConfig agrees with it.
        assert_eq!(read_config_file(&dir), new_cfg);
        let resp = client.request(&Request::GetConfig).await.unwrap();
        assert_eq!(resp, Response::Config(new_cfg));
    }

    #[tokio::test]
    async fn set_config_restarts_running_scan_task() {
        let dir = temp_dir("setconfig-restart");
        let ctx = test_ctx(&dir);
        assert!(ctx.supervisor.start());
        assert!(ctx.supervisor.is_running());
        let mut client = serve_ctx("setconfig-restart", ctx.clone()).await;

        let new_cfg = DaemonConfig {
            start_height: Some(300),
            ..test_config(&dir)
        };
        let resp = client
            .request(&Request::SetConfig(Box::new(new_cfg)))
            .await
            .unwrap();
        assert!(matches!(resp, Response::OkWithNote(_)), "got {resp:?}");
        assert!(
            ctx.supervisor.is_running(),
            "scan task must be restarted after apply"
        );
    }
}
