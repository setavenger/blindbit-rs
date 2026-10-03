//! Friglet tray app: a Tauri v2 tray-only companion for the `friglet`
//! daemon. Talks to the daemon over the `friglet-ipc` control socket,
//! shows live status in the tray menu and a hidden-by-default status
//! window, and manages the daemon lifecycle (attach or spawn, quit rule).

pub mod lifecycle;
pub mod popup;
pub mod setup;
pub mod view;

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use friglet_ipc::{Client, DaemonConfig, Request, Response, StatusInfo};
use serde::Serialize;
use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIcon, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Manager, State, WindowEvent};
use tauri_plugin_autostart::ManagerExt;
use tokio::process::Child;

use lifecycle::{Attachment, ExitReport, RecentOutput, StopOutcome, Supervision};
use view::{
    Condition, DaemonFacts, DaemonView, ErrorBook, ErrorEntry, Ownership, ScanView, Stopped,
};

/// How often the background task polls `GetStatus`.
const POLL_INTERVAL: Duration = Duration::from_secs(1);
/// Per-poll probe timeout. A status answer never waits on the network in
/// current daemons; older ones fetched the oracle tip inline (up to 2 s), so
/// leave room for that rather than calling the daemon unreachable.
const POLL_TIMEOUT: Duration = Duration::from_millis(2500);
/// A tray-owned daemon we hold no process handle for (spawned by an earlier
/// tray session) is presumed dead after this long without answering.
const UNHANDLED_DAEMON_DEAD_AFTER: Duration = Duration::from_secs(15);
/// A spawned daemon that is alive but has not answered for this long is
/// presumed wedged and replaced (generous: a restart may wait on the oracle).
const WEDGED_DAEMON_AFTER: Duration = Duration::from_secs(120);

/// Last known daemon status, shared between the poller, tray menu and the
/// `get_status` command.
#[derive(Default)]
struct StatusState {
    reachable: bool,
    /// Kept even while unreachable so the window can show the last snapshot.
    last: Option<StatusInfo>,
    /// Who started the daemon, refreshed by the poller.
    ownership: Option<Ownership>,
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Who owns the daemon. Single boolean policy, no PID files.
#[derive(Default)]
struct LifecycleState {
    spawned_by_tray: bool,
    child: Option<Child>,
    /// The spawned child's recent output, for crash reports.
    recent_output: Option<RecentOutput>,
}

struct AppState {
    socket_path: String,
    status: Mutex<StatusState>,
    lifecycle: tokio::sync::Mutex<LifecycleState>,
    /// First-run setup mode: the daemon is unreachable and not plausibly
    /// configured, so spawning is pointless until the user saves a config.
    setup_needed: AtomicBool,
    /// The tray keeps the daemon running: it spawned it (or tried to), or
    /// attached to one a tray spawned. Off for an externally managed daemon
    /// and in setup mode.
    supervise: AtomicBool,
    /// Quit in progress: never restart.
    quitting: AtomicBool,
    supervision: Mutex<Supervision>,
    /// Since when the daemon has not answered polls.
    unreachable_since: Mutex<Option<Instant>>,
    /// An attach/spawn is in progress (the window says "starting…").
    starting: AtomicBool,
    /// Stop daemon is in progress.
    stopping: AtomicBool,
    /// The daemon was stopped on purpose (Stop daemon, or it exited
    /// normally): the supervisor leaves it stopped until Start daemon.
    stopped: Mutex<Option<Stopped>>,
    /// Errors shown in the window: active conditions and recent ones.
    errors: Mutex<ErrorBook>,
    /// The tray's own log file, when it could be opened.
    tray_log: Option<PathBuf>,
}

impl AppState {
    fn new(socket_path: String) -> Self {
        Self {
            socket_path,
            status: Mutex::new(StatusState::default()),
            lifecycle: tokio::sync::Mutex::new(LifecycleState::default()),
            setup_needed: AtomicBool::new(false),
            supervise: AtomicBool::new(false),
            quitting: AtomicBool::new(false),
            supervision: Mutex::new(Supervision::default()),
            unreachable_since: Mutex::new(None),
            starting: AtomicBool::new(false),
            stopping: AtomicBool::new(false),
            stopped: Mutex::new(None),
            errors: Mutex::new(ErrorBook::default()),
            tray_log: None,
        }
    }

    /// Record a one-off error for the window, and log it.
    fn error_event(&self, key: &str, message: String) {
        tracing::error!(kind = key, "{message}");
        self.errors.lock().unwrap().event(key, message, unix_now());
    }

    /// Everything the views are computed from.
    fn daemon_facts(&self) -> DaemonFacts {
        let (reachable, pid, ownership) = {
            let s = self.status.lock().unwrap();
            (
                s.reachable,
                s.last.as_ref().and_then(|l| l.pid),
                s.ownership,
            )
        };
        let now = Instant::now();
        let sup = self.supervision.lock().unwrap();
        DaemonFacts {
            reachable,
            unreachable_for_secs: self
                .unreachable_since
                .lock()
                .unwrap()
                .map(|since| now.duration_since(since).as_secs()),
            setup_needed: self.setup_needed.load(Ordering::SeqCst),
            starting: self.starting.load(Ordering::SeqCst),
            stopping: self.stopping.load(Ordering::SeqCst),
            stopped: self.stopped.lock().unwrap().clone(),
            restart_in_secs: sup
                .next_restart_at
                .filter(|_| self.supervise.load(Ordering::SeqCst))
                .map(|at| at.saturating_duration_since(now).as_secs_f64().ceil() as u64),
            ownership: reachable.then_some(ownership).flatten(),
            pid: reachable.then_some(pid).flatten(),
            quit_stops_daemon: ownership.is_some_and(|o| o != Ownership::External),
        }
    }

    fn views(&self) -> (DaemonView, ScanView) {
        let facts = self.daemon_facts();
        let s = self.status.lock().unwrap();
        (
            view::daemon_view(&facts),
            view::scan_view(s.last.as_ref(), s.reachable, unix_now()),
        )
    }
}

/// Holds an [`AtomicBool`] raised for the guard's lifetime.
struct Flag<'a>(&'a AtomicBool);
impl<'a> Flag<'a> {
    fn raise(flag: &'a AtomicBool) -> Self {
        flag.store(true, Ordering::SeqCst);
        Self(flag)
    }
}
impl Drop for Flag<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

/// Crash / restart state of a tray-supervised daemon, for the status window.
#[derive(Serialize, Default, Debug, PartialEq)]
struct DaemonHealth {
    /// The tray restarts this daemon when it dies.
    supervised: bool,
    /// Automatic restarts this tray session.
    restarts: u32,
    /// How the daemon last ended unexpectedly, e.g. `signal: 9 (SIGKILL)`.
    last_exit: Option<String>,
    /// Unix seconds of `last_exit`.
    last_exit_at: Option<u64>,
    /// The daemon's last output lines before it ended.
    last_output: Option<String>,
    /// Seconds until the next automatic restart attempt, if one is pending.
    restart_in_secs: Option<u64>,
    /// Why the latest restart attempt failed.
    last_error: Option<String>,
}

fn daemon_health(state: &AppState) -> DaemonHealth {
    let sup = state.supervision.lock().unwrap();
    let now = Instant::now();
    DaemonHealth {
        supervised: state.supervise.load(Ordering::SeqCst),
        restarts: sup.restarts,
        last_exit: sup.last_exit.as_ref().map(|r| r.status.clone()),
        last_exit_at: sup.last_exit.as_ref().and_then(|r| {
            r.at.duration_since(SystemTime::UNIX_EPOCH)
                .ok()
                .map(|d| d.as_secs())
        }),
        last_output: sup
            .last_exit
            .as_ref()
            .map(|r| r.output.clone())
            .filter(|o| !o.is_empty()),
        restart_in_secs: sup
            .next_restart_at
            .map(|at| at.saturating_duration_since(now).as_secs_f64().ceil() as u64),
        last_error: sup.last_spawn_error.clone(),
    }
}

/// Where the logs are, for the Status tab.
#[derive(Serialize)]
struct LogsInfo {
    /// The daemon's log file (as the daemon reports it, else the default).
    daemon_log: Option<String>,
    /// The tray's own log file.
    tray_log: Option<String>,
}

/// Payload for the `get_status` command.
#[derive(Serialize)]
struct StatusPayload {
    reachable: bool,
    status: Option<StatusInfo>,
    daemon: DaemonHealth,
    daemon_view: DaemonView,
    scan_view: ScanView,
    /// Active errors first, then recent ones; newest first.
    errors: Vec<ErrorEntry>,
    logs: LogsInfo,
}

fn daemon_log_path(state: &AppState) -> Option<PathBuf> {
    let reported = state
        .status
        .lock()
        .unwrap()
        .last
        .as_ref()
        .and_then(|s| s.log_file.clone());
    reported
        .map(PathBuf::from)
        .or_else(friglet_ipc::logfile::daemon_log_file)
}

#[tauri::command]
async fn get_status(state: State<'_, Arc<AppState>>) -> Result<StatusPayload, String> {
    let daemon = daemon_health(&state);
    let (daemon_view, scan_view) = state.views();
    let mut errors = state.errors.lock().unwrap().entries();
    errors.sort_by_key(|e| !e.active);
    let logs = LogsInfo {
        daemon_log: daemon_log_path(&state).map(|p| p.display().to_string()),
        tray_log: state.tray_log.as_ref().map(|p| p.display().to_string()),
    };
    let s = state.status.lock().unwrap();
    Ok(StatusPayload {
        reachable: s.reachable,
        status: s.last.clone(),
        daemon,
        daemon_view,
        scan_view,
        errors,
        logs,
    })
}

/// Start/Stop scanning (window buttons and tray menu). A failure is logged
/// and kept in the window's error list. `Ok(Some(note))`: e.g. "stopping:
/// ..." while the scanner finishes a blocking step.
async fn scan_control(state: &AppState, req: Request) -> Result<Option<String>, String> {
    let what = if req == Request::Start {
        "Start scanning"
    } else {
        "Stop scanning"
    };
    tracing::info!("{what} requested");
    let result = send_with_note(&state.socket_path, req).await;
    match &result {
        Ok(Some(note)) => tracing::info!("{what}: {note}"),
        Ok(None) => {}
        Err(e) => state.error_event("action", format!("{what} failed: {e}")),
    }
    result
}

#[tauri::command]
async fn start_scanning(state: State<'_, Arc<AppState>>) -> Result<Option<String>, String> {
    scan_control(&state, Request::Start).await
}

#[tauri::command]
async fn stop_scanning(state: State<'_, Arc<AppState>>) -> Result<Option<String>, String> {
    scan_control(&state, Request::Stop).await
}

/// Stop the daemon, whoever started it, and keep it stopped: the
/// supervisor does not restart it until Start daemon. Returns what happened.
async fn stop_daemon_now(state: &AppState) -> Result<String, String> {
    let _flag = Flag::raise(&state.stopping);
    let mut lc = state.lifecycle.lock().await;
    // From here on the supervisor must not undo the stop.
    state.supervise.store(false, Ordering::SeqCst);
    state.supervision.lock().unwrap().reset();
    let pid = state
        .status
        .lock()
        .unwrap()
        .last
        .as_ref()
        .and_then(|s| s.pid);
    *state.stopped.lock().unwrap() = Some(Stopped {
        at_unix: unix_now(),
        by_user: true,
        detail: String::new(),
        pid,
    });
    tracing::info!(?pid, "Stop daemon requested");
    let outcome = lifecycle::stop_daemon(&state.socket_path, lc.child.take(), pid).await;
    lc.spawned_by_tray = false;
    lc.recent_output = None;
    drop(lc);
    match outcome {
        StopOutcome::Stopped(how) => {
            tracing::info!(%how, "daemon stopped");
            Ok(format!("Daemon stopped ({how})."))
        }
        StopOutcome::Killed => {
            let msg = format!(
                "The daemon did not exit within {}s after the shutdown request and was killed.",
                lifecycle::STOP_DAEMON_TIMEOUT.as_secs()
            );
            tracing::warn!("{msg}");
            Ok(msg)
        }
        StopOutcome::NotRunning => Ok("No daemon was running.".to_string()),
        StopOutcome::StillRunning(why) => {
            *state.stopped.lock().unwrap() = None;
            let msg = format!("Stop daemon: {why}");
            state.error_event("action", msg.clone());
            Err(msg)
        }
    }
}

/// Start the daemon (or attach to one that is already running) and let the
/// supervisor keep a tray-started one running again.
async fn start_daemon_now(state: &AppState) -> Result<(), String> {
    tracing::info!("Start daemon requested");
    *state.stopped.lock().unwrap() = None;
    state.supervision.lock().unwrap().reset();
    match attach_and_record(state).await {
        None => Ok(()),
        Some(reason) => Err(reason),
    }
}

#[tauri::command]
async fn stop_daemon(state: State<'_, Arc<AppState>>) -> Result<String, String> {
    stop_daemon_now(&state).await
}

#[tauri::command]
async fn start_daemon(app: AppHandle, state: State<'_, Arc<AppState>>) -> Result<(), String> {
    let result = start_daemon_now(&state).await;
    if state.setup_needed.load(Ordering::SeqCst) {
        show_window_tab(&app, "settings");
    }
    result
}

/// Open the folder holding the daemon's log in the file manager.
#[tauri::command]
fn open_log_folder(state: State<'_, Arc<AppState>>) -> Result<String, String> {
    let dir = daemon_log_path(&state)
        .and_then(|p| p.parent().map(PathBuf::from))
        .or_else(friglet_ipc::logfile::default_log_dir)
        .ok_or("cannot determine the log folder on this system")?;
    let _ = std::fs::create_dir_all(&dir);
    let opener = if cfg!(target_os = "macos") {
        "open"
    } else if cfg!(windows) {
        "explorer"
    } else {
        "xdg-open"
    };
    match std::process::Command::new(opener)
        .arg(&dir)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
    {
        Ok(mut child) => {
            // Reap it in the background; the file manager outlives it.
            std::thread::spawn(move || {
                let _ = child.wait();
            });
            tracing::info!(dir = %dir.display(), "opened the log folder");
            Ok(dir.display().to_string())
        }
        Err(e) => {
            let msg = format!("cannot open {} with {opener}: {e}", dir.display());
            state.error_event("action", msg.clone());
            Err(msg)
        }
    }
}

/// Fetch the daemon's effective configuration (never contains the scan
/// secret). Errors when the daemon is unreachable so the settings form can
/// disable itself.
#[tauri::command]
async fn get_config(state: State<'_, Arc<AppState>>) -> Result<DaemonConfig, String> {
    match daemon_request(&state.socket_path, &Request::GetConfig).await? {
        Response::Config(cfg) => Ok(cfg),
        other => Err(format!("unexpected response: {other:?}")),
    }
}

/// Per-network defaults for the settings form.
#[derive(Serialize)]
struct NetworkDefaults {
    hosted_oracles: std::collections::BTreeMap<&'static str, &'static str>,
    default_ports: std::collections::BTreeMap<&'static str, u16>,
}

#[tauri::command]
fn network_defaults() -> NetworkDefaults {
    use friglet_ipc::network::{NETWORKS, default_p2p_port, hosted_oracle_url};
    NetworkDefaults {
        hosted_oracles: NETWORKS
            .into_iter()
            .filter_map(|n| hosted_oracle_url(n).map(|u| (n, u)))
            .collect(),
        default_ports: NETWORKS
            .into_iter()
            .filter_map(|n| default_p2p_port(n).map(|p| (n, p)))
            .collect(),
    }
}

/// Parse a pasted SP descriptor for the settings form. Returns everything
/// the form needs except the scan secret, which stays on the Rust side.
#[tauri::command]
fn inspect_descriptor(
    descriptor: String,
    network: String,
) -> Result<setup::DescriptorSummary, String> {
    setup::summarize_descriptor(&descriptor, &network)
}

/// Settings-mode save: config plus an optional new scan key — from a pasted
/// descriptor (which also sets the spend key) or the manual hex field — in
/// one `ApplySettings` request, so the daemon validates once and restarts
/// once. The note says the daemon is restarting.
#[tauri::command]
async fn apply_settings(
    state: State<'_, Arc<AppState>>,
    mut config: DaemonConfig,
    scan_key: Option<String>,
    descriptor: Option<String>,
) -> Result<Option<String>, String> {
    let scan_key = match descriptor.as_deref().map(str::trim) {
        Some(d) if !d.is_empty() => Some(setup::keys_from_descriptor(&mut config, d)?),
        _ => scan_key.filter(|k| !k.trim().is_empty()),
    };
    send_with_note(
        &state.socket_path,
        Request::ApplySettings {
            config: Box::new(config),
            scan_key,
        },
    )
    .await
}

/// Whether the tray starts at login.
#[tauri::command]
fn get_autostart(app: AppHandle) -> Result<bool, String> {
    app.autolaunch().is_enabled().map_err(|e| e.to_string())
}

/// Enable/disable starting the tray (and with it the daemon) at login.
#[tauri::command]
fn set_autostart(app: AppHandle, enabled: bool) -> Result<(), String> {
    apply_autostart(&app, enabled)
}

fn apply_autostart(app: &AppHandle, enabled: bool) -> Result<(), String> {
    let launcher = app.autolaunch();
    let result = if enabled {
        launcher.enable()
    } else {
        launcher.disable()
    };
    result.map_err(|e| format!("cannot change start at login: {e}"))?;
    tracing::info!(enabled, "start at login updated");
    Ok(())
}

/// Payload for the `get_setup_state` command.
#[derive(Serialize)]
struct SetupStatePayload {
    /// Whether first-run setup mode is active (daemon unreachable and not
    /// plausibly configured).
    active: bool,
    /// Where the config file will be written, for display.
    config_path: Option<String>,
    /// Where the scan key file will be written, for display.
    key_file: Option<String>,
    /// Prefill for the settings form: a partially written config file (if
    /// any) merged over the built-in defaults.
    config: DaemonConfig,
}

/// Report whether first-run setup mode is active, plus the default paths
/// and a config prefill so the UI can enable the form without a daemon.
#[tauri::command]
async fn get_setup_state(state: State<'_, Arc<AppState>>) -> Result<SetupStatePayload, String> {
    let config_path = friglet_ipc::default_config_path();
    let mut config = config_path
        .as_deref()
        .filter(|p| p.exists())
        .and_then(|p| friglet_ipc::read_config_toml(p).ok())
        .unwrap_or_default();
    // Show the absolute platform default in the first-run form when the
    // loaded/default config still has a relative state_file.
    if !config.state_file.is_absolute()
        && let Some(absolute) = friglet_ipc::default_state_file()
    {
        config.state_file = absolute;
    }
    let key_file = config
        .key_file
        .clone()
        .or_else(friglet_ipc::default_key_file);
    Ok(SetupStatePayload {
        active: state.setup_needed.load(Ordering::SeqCst),
        config_path: config_path.map(|p| p.display().to_string()),
        key_file: key_file.map(|p| p.display().to_string()),
        config,
    })
}

/// First-run setup save: validate tray-side, write the scan key file (0600)
/// and the config file (atomic TOML) locally, then run the normal
/// attach-or-spawn flow — which now finds a configured daemon to start.
///
/// `Ok(None)`: saved and the daemon came up. `Ok(Some(reason))`: files were
/// saved but the daemon still failed to start (the reason is the spawn
/// diagnostic). `Err(msg)`: validation or write failed, nothing spawned.
///
/// A non-empty `descriptor` supplies the keys (scan key + spend public key)
/// and takes precedence over `scan_key` / `config.spend_pubkey`.
#[tauri::command]
async fn save_local_config(
    app: AppHandle,
    state: State<'_, Arc<AppState>>,
    mut config: DaemonConfig,
    scan_key: String,
    descriptor: Option<String>,
    autostart: Option<bool>,
) -> Result<Option<String>, String> {
    let scan_key = match descriptor.as_deref().map(str::trim) {
        Some(d) if !d.is_empty() => setup::keys_from_descriptor(&mut config, d)?,
        _ => scan_key,
    };
    setup::validate_setup(&config, &scan_key)?;
    setup::resolve_peer(&config).await?;
    let config_path = friglet_ipc::default_config_path()
        .ok_or("cannot determine the platform config directory")?;
    let key_file = setup::write_local_config(&config_path, &config, &scan_key)?;
    tracing::info!(
        config = %config_path.display(),
        key_file = %key_file.display(),
        "first-run setup: wrote local config and key file"
    );
    // Best effort: a failed login-item registration must not undo setup.
    if let Some(enabled) = autostart
        && let Err(e) = apply_autostart(&app, enabled)
    {
        tracing::warn!(error = %e, "first-run setup: start at login not applied");
    }
    Ok(attach_and_record(&state).await)
}

/// Send one request to the daemon. Connection and protocol failures, and
/// the daemon's own `Error` answer, become the `Err` message.
async fn daemon_request(socket_path: &str, req: &Request) -> Result<Response, String> {
    let mut client = Client::connect(socket_path)
        .await
        .map_err(|e| format!("daemon unreachable: {e}"))?;
    match client
        .request(req)
        .await
        .map_err(|e| format!("request failed: {e}"))?
    {
        Response::Error(e) => Err(e),
        other => Ok(other),
    }
}

/// Send a request answering `Ok` or `OkWithNote`; the note is passed through
/// so the UI can surface it.
async fn send_with_note(socket_path: &str, req: Request) -> Result<Option<String>, String> {
    match daemon_request(socket_path, &req).await? {
        Response::Ok => Ok(None),
        Response::OkWithNote(note) => Ok(Some(note)),
        other => Err(format!("unexpected response: {other:?}")),
    }
}

/// Probe-spawn-or-setup, recording the outcome in [`LifecycleState`] and the
/// `setup_needed` flag. Returns the failure reason when the daemon stayed
/// unreachable despite being configured (spawn failed / socket never came up).
///
/// Runs at startup, from Start daemon (menu and window) and after a
/// first-run setup save. Holds the lifecycle lock for the whole attempt so
/// concurrent retriggers queue up instead of spawning multiple daemons.
async fn attach_and_record(state: &AppState) -> Option<String> {
    attach_and_record_with(state, lifecycle::locate_daemon_binary_from_env, || {
        !setup::is_configured_from_env()
    })
    .await
}

/// [`attach_and_record`] with an injectable daemon-binary locator and
/// setup-needed check (tests pass stubs so no real binary search or config
/// file inspection happens).
async fn attach_and_record_with<F, C>(state: &AppState, locate: F, needs_setup: C) -> Option<String>
where
    F: FnOnce() -> Option<std::path::PathBuf>,
    C: FnOnce() -> bool,
{
    let mut lc = state.lifecycle.lock().await;
    let _starting = Flag::raise(&state.starting);

    // Reap a previously spawned child that has exited.
    if let Some((report, _)) = reap_exited(&mut lc) {
        tracing::warn!(status = %report.status, "previously spawned daemon exited");
    }

    // Our own daemon is still alive: verify it answers on the socket rather
    // than returning early, so a retry can recover from a wedged daemon.
    if lc.child.is_some() {
        if lifecycle::probe(&state.socket_path, lifecycle::PROBE_TIMEOUT)
            .await
            .is_some()
        {
            tracing::debug!("spawned daemon is alive and reachable; nothing to do");
            return None;
        }
        // Alive but its control socket is unreachable. The child is
        // tray-spawned, so killing it and starting over is ours to do.
        tracing::warn!(
            "spawned daemon is alive but its control socket is unreachable; \
             killing it and starting over"
        );
        if let Some(mut child) = lc.child.take() {
            // tokio's `Child::kill` is `start_kill` + `wait`: it resolves
            // only after the child has fully exited and been reaped, so the
            // attach-or-spawn below can never run concurrently with the old
            // daemon (they share config/key/state paths).
            if child.kill().await.is_err() {
                // `start_kill` fails when the child exited in the meantime;
                // reap it so the exit is still complete before proceeding.
                let _ = child.wait().await;
            }
        }
        lc.spawned_by_tray = false;
    }

    match lifecycle::attach_spawn_or_setup_with(&state.socket_path, locate, needs_setup).await {
        Attachment::Attached(status) => {
            tracing::info!(
                spawned_by_tray = status.spawned_by_tray,
                "attached to already-running daemon"
            );
            // Trust the daemon's own self-report, not an assumption: a
            // daemon spawned by a tray that has since crashed/restarted
            // still answers `spawned_by_tray = true`, so Quit here can
            // still shut it down instead of orphaning it forever.
            lc.spawned_by_tray = status.spawned_by_tray;
            // Keep a daemon a tray started running; leave an external one
            // to whoever manages it.
            state
                .supervise
                .store(status.spawned_by_tray, Ordering::SeqCst);
            state.setup_needed.store(false, Ordering::SeqCst);
            *state.stopped.lock().unwrap() = None;
            record_reachable(state, *status);
            None
        }
        Attachment::Spawned(child, recent_output) => {
            tracing::info!("spawned daemon and connected");
            *state.stopped.lock().unwrap() = None;
            lc.spawned_by_tray = true;
            lc.child = Some(child);
            lc.recent_output = Some(recent_output);
            state.supervise.store(true, Ordering::SeqCst);
            state.setup_needed.store(false, Ordering::SeqCst);
            {
                let mut sup = state.supervision.lock().unwrap();
                sup.next_restart_at = None;
                sup.last_spawn_error = None;
            }
            if let Some(status) =
                lifecycle::probe(&state.socket_path, lifecycle::PROBE_TIMEOUT).await
            {
                record_reachable(state, status);
            }
            None
        }
        Attachment::SetupRequired => {
            tracing::info!("daemon not configured yet; entering first-run setup mode");
            state.supervise.store(false, Ordering::SeqCst);
            state.setup_needed.store(true, Ordering::SeqCst);
            None
        }
        Attachment::Unreachable { reason } => {
            state.error_event("start", format!("Starting the daemon failed: {reason}"));
            // The tray tried to start a configured daemon: keep trying,
            // with backoff (whether this was startup, Save, Retry or an
            // automatic restart).
            state.supervise.store(true, Ordering::SeqCst);
            state.setup_needed.store(false, Ordering::SeqCst);
            state
                .supervision
                .lock()
                .unwrap()
                .on_restart_failed(reason.clone(), Instant::now());
            Some(reason)
        }
    }
}

/// Publish a status answer right away instead of on the next poll: the
/// window refreshes as soon as an attach/spawn returns, and a stale
/// "unreachable" from before (e.g. the whole first-run setup) would flash an
/// error at the user although the daemon is up.
fn record_reachable(state: &AppState, status: StatusInfo) {
    {
        let mut s = state.status.lock().unwrap();
        s.reachable = true;
        s.last = Some(status);
    }
    *state.unreachable_since.lock().unwrap() = None;
}

/// Store one poll's answer: whether the daemon answered and, when it did, its
/// status (the last snapshot is kept while it does not answer).
fn record_poll(state: &AppState, info: Option<&StatusInfo>) {
    let mut s = state.status.lock().unwrap();
    s.reachable = info.is_some();
    if let Some(info) = info {
        s.last = Some(info.clone());
    }
}

/// Reap the spawned child if it has exited, returning how it ended and
/// whether it exited normally (status 0: it was asked to stop — a Shutdown
/// request or SIGTERM — since a failing daemon exits non-zero).
fn reap_exited(lc: &mut LifecycleState) -> Option<(ExitReport, bool)> {
    let (status, success) = match lc.child.as_mut()?.try_wait() {
        Ok(None) => return None,
        Ok(Some(status)) => (status.to_string(), status.success()),
        Err(e) => (format!("unknown ({e})"), false),
    };
    lc.child = None;
    lc.spawned_by_tray = false;
    let output = lc
        .recent_output
        .take()
        .map(|o| lifecycle::recent_output_tail(&o))
        .unwrap_or_default();
    Some((
        ExitReport {
            at: SystemTime::now(),
            status,
            output,
        },
        success,
    ))
}

/// One supervision step, run by the poller after each status probe: notice
/// a dead (or wedged) tray-owned daemon and restart it with exponential
/// backoff. Never runs while quitting, in setup mode, or for an externally
/// managed daemon.
async fn supervise_tick(state: &AppState, reachable: bool) {
    supervise_tick_with(
        state,
        reachable,
        lifecycle::locate_daemon_binary_from_env,
        || !setup::is_configured_from_env(),
    )
    .await
}

/// [`supervise_tick`] with the binary locator and setup check injected
/// (tests pass stubs).
async fn supervise_tick_with<F, C>(state: &AppState, reachable: bool, locate: F, needs_setup: C)
where
    F: FnOnce() -> Option<std::path::PathBuf>,
    C: FnOnce() -> bool,
{
    if state.quitting.load(Ordering::SeqCst) {
        return;
    }
    let now = Instant::now();
    let unreachable_for = {
        let mut since = state.unreachable_since.lock().unwrap();
        if reachable {
            *since = None;
        } else if since.is_none() {
            *since = Some(now);
        }
        since.map(|s| now.duration_since(s))
    };
    {
        let mut sup = state.supervision.lock().unwrap();
        if reachable {
            sup.on_reachable(now);
        } else {
            sup.on_unreachable();
        }
    }
    if !state.supervise.load(Ordering::SeqCst)
        || state.setup_needed.load(Ordering::SeqCst)
        || state.stopped.lock().unwrap().is_some()
    {
        return;
    }

    // Skip the tick while an attach/spawn/stop/quit holds the lifecycle lock.
    let Ok(mut lc) = state.lifecycle.try_lock() else {
        return;
    };
    if let Some((report, success)) = reap_exited(&mut lc) {
        if success {
            // Asked to stop from outside the tray: respect that.
            tracing::info!(status = %report.status, "daemon exited normally; not restarting it");
            *state.stopped.lock().unwrap() = Some(Stopped {
                at_unix: unix_now(),
                by_user: false,
                detail: "It exited normally (a shutdown request or SIGTERM from outside the \
                         tray), so it is not restarted."
                    .to_string(),
                pid: None,
            });
            return;
        }
        let mut message = format!("The daemon exited unexpectedly ({})", report.status);
        if !report.output.is_empty() {
            message.push_str(&format!(". Last output: {}", report.output));
        }
        state.error_event("crash", format!("{message}. Restarting it."));
        state.supervision.lock().unwrap().on_exit(report, now);
    } else if !reachable {
        let unreachable_for = unreachable_for.unwrap_or_default();
        let pending = state.supervision.lock().unwrap().next_restart_at.is_some();
        let presumed = match lc.child {
            // Ours, alive, silent for long: wedged (attach_and_record kills it).
            Some(_) if unreachable_for >= WEDGED_DAEMON_AFTER => {
                Some("stopped answering (killed and restarted)")
            }
            // Owned but spawned by an earlier tray session: no exit status.
            None if lc.spawned_by_tray && unreachable_for >= UNHANDLED_DAEMON_DEAD_AFTER => {
                Some("stopped answering (started by an earlier tray session)")
            }
            _ => None,
        };
        if let Some(status) = presumed
            && !pending
        {
            state.error_event("crash", format!("The daemon {status}."));
            lc.spawned_by_tray = false;
            state.supervision.lock().unwrap().on_exit(
                ExitReport {
                    at: SystemTime::now(),
                    status: status.to_string(),
                    output: String::new(),
                },
                now,
            );
        }
    }
    drop(lc);

    if !state.supervision.lock().unwrap().restart_due(now) {
        return;
    }
    tracing::info!("restarting the daemon");
    // A failure is recorded (and the next attempt scheduled) by
    // attach_and_record itself.
    if attach_and_record_with(state, locate, needs_setup)
        .await
        .is_none()
        && !state.setup_needed.load(Ordering::SeqCst)
    {
        state.supervision.lock().unwrap().on_restarted();
    }
}

/// Apply the quit rule, then exit the process.
fn quit(app: &AppHandle) {
    let state = app.state::<Arc<AppState>>().inner().clone();
    state.quitting.store(true, Ordering::SeqCst);
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        let (spawned_by_tray, child) = {
            let mut lc = state.lifecycle.lock().await;
            (lc.spawned_by_tray, lc.child.take())
        };
        lifecycle::perform_quit(&state.socket_path, spawned_by_tray, child).await;
        // Popup mode: give hover focus back to the other windows.
        let popup = app.state::<Arc<popup::Popup>>().inner().clone();
        let _ = tauri::async_runtime::spawn_blocking(move || popup.release()).await;
        app.exit(0);
    });
}

/// Show the main window: under Hyprland as the top-bar popup, elsewhere as
/// the ordinary window.
fn show_status_window(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        app.state::<Arc<popup::Popup>>().show(&window);
    }
}

/// Left click on the tray icon: toggle the popup under Hyprland, open the
/// window elsewhere.
fn tray_left_click(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        app.state::<Arc<popup::Popup>>().toggle(&window);
    }
}

/// Esc in the window: closes the popup (no-op outside popup mode).
#[tauri::command]
fn dismiss_window(window: tauri::WebviewWindow, popup: State<'_, Arc<popup::Popup>>) {
    popup.dismiss(&window);
}

/// Show the main window and switch it to `tab` (`settings` or `wallet`) once
/// the UI has had a chance to load. Used for first-run setup mode (Settings)
/// and for `FRIGLET_TRAY_SHOW_ON_START`. (Synthetic X11 clicks do not reach
/// WebKitGTK reliably under Xvfb, so this eval is the supported headless path
/// to the Settings form.)
fn show_window_tab(app: &AppHandle, tab: &'static str) {
    show_status_window(app);
    let handle = app.clone();
    tauri::async_runtime::spawn(async move {
        tokio::time::sleep(Duration::from_millis(800)).await;
        if let Some(w) = handle.get_webview_window("main") {
            let _ = w.eval(format!("document.getElementById('tab-{tab}')?.click()"));
        }
    });
}

/// Which tab a `FRIGLET_TRAY_SHOW_ON_START` value opens on startup:
/// - unset / falsy → none, the window stays hidden (default)
/// - `1` / `true` / `yes` / `on` / `status` → the Status tab
/// - `settings` → the Settings tab (after the UI loads)
/// - `wallet` → the Wallet tab (after the UI loads)
fn show_on_start(value: Option<&str>) -> Option<&'static str> {
    match value?.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" | "status" => Some("status"),
        "settings" => Some("settings"),
        "wallet" => Some("wallet"),
        _ => None,
    }
}

fn tray_label(daemon: &DaemonView, scan: &ScanView, status: Option<&StatusInfo>) -> String {
    match (daemon.state, status) {
        ("running", Some(s)) => format!("Scan: {} (height {})", scan.label, s.scanned_height),
        ("setup", _) => "Setup required — open window".to_string(),
        _ => format!("Daemon: {}", daemon.label),
    }
}

/// Label for the Quit menu item, so its consequence (shuts the daemon down
/// vs. leaves it running) is visible without reading the README.
fn quit_label(daemon_running: bool, spawned_by_tray: bool) -> &'static str {
    match (daemon_running, spawned_by_tray) {
        (false, _) => "Quit",
        (true, true) => "Quit (stops daemon)",
        (true, false) => "Quit (keeps daemon running)",
    }
}

fn tray_tooltip(daemon: &DaemonView, scan: &ScanView, status: Option<&StatusInfo>) -> String {
    match (daemon.state, status) {
        ("running", Some(s)) => {
            let tip = s
                .tip_height
                .map(|t| t.to_string())
                .unwrap_or_else(|| "?".to_string());
            format!("Friglet: {}, height {}/{tip}", scan.label, s.scanned_height)
        }
        ("setup", _) => "Friglet: first-time setup required".to_string(),
        _ => format!("Friglet: daemon {}", daemon.label),
    }
}

/// Error conditions that hold right now, from the current views.
fn conditions(
    state: &AppState,
    daemon: &DaemonView,
    scan: &ScanView,
    now_unix: u64,
) -> Vec<Condition> {
    let mut out = Vec::new();
    if scan.state == "error" {
        out.push(Condition {
            key: "scan".to_string(),
            message: scan.problem.clone().unwrap_or_else(|| scan.label.clone()),
            since_unix: scan.since_unix.unwrap_or(now_unix),
        });
    }
    // A crash shows at once in the crash card and the Recent errors list;
    // "the daemon is down" becomes an active problem only after the grace.
    let down_for = state
        .unreachable_since
        .lock()
        .unwrap()
        .map(|since| since.elapsed().as_secs());
    if matches!(daemon.state, "unreachable" | "restarting")
        && down_for.is_some_and(|secs| secs >= view::UNREACHABLE_GRACE_SECS)
    {
        let mut message = format!(
            "The daemon is not running or not answering on {}",
            state.socket_path
        );
        if let Some(reason) = state
            .supervision
            .lock()
            .unwrap()
            .last_spawn_error
            .as_deref()
        {
            message.push_str(&format!(" — last start attempt: {reason}"));
        }
        out.push(Condition {
            key: "daemon".to_string(),
            message,
            since_unix: now_unix,
        });
    }
    out
}

/// One poll's bookkeeping: who owns the daemon, the error book (logging
/// what was raised or resolved), and the views.
fn refresh(state: &AppState, info: Option<&StatusInfo>) -> (DaemonView, ScanView, bool) {
    if let Some(info) = info {
        // A daemon answers again: whatever stopped it is over — unless it
        // is the stopped daemon itself, answering while it shuts down.
        let mut stopped = state.stopped.lock().unwrap();
        let shutting_down = state.stopping.load(Ordering::SeqCst)
            || stopped
                .as_ref()
                .is_some_and(|s| s.pid.is_some() && s.pid == info.pid);
        if !shutting_down {
            *stopped = None;
        }
    }
    let spawned_by_tray = match state.lifecycle.try_lock() {
        Ok(lc) => {
            let ownership = info.map(|i| {
                if lc.child.is_some() {
                    Ownership::ThisTray
                } else if i.spawned_by_tray {
                    Ownership::EarlierTray
                } else {
                    Ownership::External
                }
            });
            state.status.lock().unwrap().ownership = ownership;
            Some(lc.spawned_by_tray)
        }
        Err(_) => None,
    };
    let (daemon, scan) = state.views();
    let now = unix_now();
    let changes = state
        .errors
        .lock()
        .unwrap()
        .update(&conditions(state, &daemon, &scan, now), now);
    for raised in changes.raised {
        tracing::error!(kind = %raised.key, "{}", raised.message);
    }
    for resolved in changes.resolved {
        tracing::info!(kind = %resolved.key, "resolved: {}", resolved.message);
    }
    (daemon, scan, spawned_by_tray.unwrap_or(false))
}

const TRAY_ID: &str = "friglet-tray";
/// Wait before the first retry to register the tray icon; it doubles up to
/// `TRAY_RETRY_MAX`.
const TRAY_RETRY_FIRST: Duration = Duration::from_secs(2);
const TRAY_RETRY_MAX: Duration = Duration::from_secs(30);

/// Create the tray icon. A left click opens the window (on Hyprland it
/// toggles the top-bar popup, see [`popup`]); the menu is on right click.
/// On Linux the icon is a KSNI StatusNotifierItem (`ItemIsMenu=false`), so
/// SNI hosts send left clicks as `Activate` instead of opening the menu.
fn build_tray(app: &AppHandle, menu: &Menu<tauri::Wry>) -> tauri::Result<TrayIcon> {
    TrayIconBuilder::with_id(TRAY_ID)
        .icon(
            app.default_window_icon()
                .cloned()
                .expect("bundled window icon"),
        )
        .menu(menu)
        // macOS / Windows: menu on right click only, like the Linux hosts.
        .show_menu_on_left_click(false)
        .tooltip("Friglet")
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                tray_left_click(tray.app_handle());
            }
        })
        .on_menu_event(|app, event| {
            let state = app.state::<Arc<AppState>>().inner().clone();
            match event.id().as_ref() {
                "open-window" => show_status_window(app),
                "start-scan" => {
                    tauri::async_runtime::spawn(async move {
                        let _ = scan_control(&state, Request::Start).await;
                    });
                }
                "stop-scan" => {
                    tauri::async_runtime::spawn(async move {
                        let _ = scan_control(&state, Request::Stop).await;
                    });
                }
                "start-daemon" => {
                    let app = app.clone();
                    tauri::async_runtime::spawn(async move {
                        let _ = start_daemon_now(&state).await;
                        // An unconfigured daemon lands in setup mode
                        // instead of a spawn-fail loop; take the user there.
                        if state.setup_needed.load(Ordering::SeqCst) {
                            show_window_tab(&app, "settings");
                        }
                    });
                }
                "stop-daemon" => {
                    tauri::async_runtime::spawn(async move {
                        let _ = stop_daemon_now(&state).await;
                    });
                }
                "quit" => quit(app),
                _ => {}
            }
        })
        .build(app)
}

fn setup_tray(app: &tauri::App) -> tauri::Result<()> {
    let handle = app.handle();

    let status_item = MenuItem::with_id(
        handle,
        "status-label",
        "Daemon: starting…",
        false,
        None::<&str>,
    )?;
    let open_item = MenuItem::with_id(
        handle,
        "open-window",
        "Open Status Window",
        true,
        None::<&str>,
    )?;
    let start_item =
        MenuItem::with_id(handle, "start-scan", "Start scanning", false, None::<&str>)?;
    let stop_item = MenuItem::with_id(handle, "stop-scan", "Stop scanning", false, None::<&str>)?;
    let start_daemon_item =
        MenuItem::with_id(handle, "start-daemon", "Start daemon", false, None::<&str>)?;
    let stop_daemon_item =
        MenuItem::with_id(handle, "stop-daemon", "Stop daemon", false, None::<&str>)?;
    let quit_item =
        MenuItem::with_id(handle, "quit", quit_label(false, false), true, None::<&str>)?;

    let menu = Menu::with_items(
        handle,
        &[
            &status_item,
            &open_item,
            &PredefinedMenuItem::separator(handle)?,
            &start_item,
            &stop_item,
            &PredefinedMenuItem::separator(handle)?,
            &start_daemon_item,
            &stop_daemon_item,
            &PredefinedMenuItem::separator(handle)?,
            &quit_item,
        ],
    )?;

    // Without a StatusNotifierWatcher (the bar is not up yet at login, or
    // the desktop has no SNI tray) the KSNI backend cannot register the icon
    // and the build fails. Keep running without it and retry: the window,
    // the daemon supervision and first-run setup do not need the icon.
    if let Err(e) = build_tray(handle, &menu) {
        tracing::warn!(error = %e, "tray icon unavailable; retrying in the background");
        let handle = handle.clone();
        let menu = menu.clone();
        tauri::async_runtime::spawn(async move {
            let mut delay = TRAY_RETRY_FIRST;
            loop {
                tokio::time::sleep(delay).await;
                match build_tray(&handle, &menu) {
                    Ok(_) => {
                        tracing::info!("tray icon registered");
                        break;
                    }
                    Err(e) => tracing::debug!(error = %e, "tray icon still unavailable"),
                }
                delay = (delay * 2).min(TRAY_RETRY_MAX);
            }
        });
    }

    // Background poller: refresh shared status every second and update the
    // tray label / tooltip / item enablement when something changed.
    let state = app.state::<Arc<AppState>>().inner().clone();
    let handle = handle.clone();
    tauri::async_runtime::spawn(async move {
        let mut last_label = String::new();
        let mut had_tray = false;
        let mut last_enablement: Option<[bool; 4]> = None;
        let mut last_quit_label: Option<&'static str> = None;
        loop {
            let info = lifecycle::probe(&state.socket_path, POLL_TIMEOUT).await;
            record_poll(&state, info.as_ref());
            // A reachable daemon ends setup mode, whoever configured it.
            if info.is_some() {
                state.setup_needed.store(false, Ordering::SeqCst);
            }
            supervise_tick(&state, info.is_some()).await;
            let (daemon, scan, spawned_by_tray) = refresh(&state, info.as_ref());

            let label = tray_label(&daemon, &scan, info.as_ref());
            let tray = handle.tray_by_id(TRAY_ID);
            // A tray icon that appeared late (see the retry above) gets the
            // current tooltip too.
            let new_tray = tray.is_some() && !had_tray;
            had_tray = tray.is_some();
            if label != last_label || new_tray {
                if label != last_label {
                    tracing::info!(%label, "tray status label updated");
                    let _ = status_item.set_text(&label);
                }
                if let Some(tray) = tray {
                    let _ = tray.set_tooltip(Some(tray_tooltip(&daemon, &scan, info.as_ref())));
                }
                last_label = label;
            }

            let enablement = [
                scan.can_start,
                scan.can_stop,
                daemon.can_start,
                daemon.can_stop,
            ];
            if last_enablement != Some(enablement) {
                let _ = start_item.set_enabled(enablement[0]);
                let _ = stop_item.set_enabled(enablement[1]);
                let _ = start_daemon_item.set_enabled(enablement[2]);
                let _ = stop_daemon_item.set_enabled(enablement[3]);
                last_enablement = Some(enablement);
            }

            let label = quit_label(info.is_some(), spawned_by_tray);
            if last_quit_label != Some(label) {
                let _ = quit_item.set_text(label);
                last_quit_label = Some(label);
            }

            tokio::time::sleep(POLL_INTERVAL).await;
        }
    });

    Ok(())
}

/// Log to stderr and to the tray's log file
/// (`friglet_ipc::logfile::tray_log_file`). The daemon's forwarded output
/// (target `friglet-daemon`) goes to stderr only: the daemon writes its own
/// log file. Returns the tray log's path when it could be opened.
fn init_logging() -> Option<PathBuf> {
    use tracing_subscriber::Layer;
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;

    let path = friglet_ipc::logfile::tray_log_file();
    let opened = path.as_deref().map(friglet_ipc::logfile::RotatingLog::open);
    let (file, file_error) = match opened {
        Some(Ok(log)) => (Some(log), None),
        Some(Err(e)) => (None, Some(e)),
        None => (None, None),
    };
    let file_layer = file.clone().map(|log| {
        tracing_subscriber::fmt::layer()
            .with_ansi(false)
            .with_writer(move || log.clone())
            .with_filter(tracing_subscriber::filter::filter_fn(|meta| {
                meta.target() != "friglet-daemon"
            }))
    });
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .with(file_layer)
        .init();
    if let (Some(path), Some(e)) = (&path, file_error) {
        tracing::warn!(path = %path.display(), error = %e, "cannot write the tray log file");
    }
    file.map(|log| log.path())
}

pub fn run() {
    let tray_log = init_logging();
    if let Some(path) = &tray_log {
        tracing::info!(path = %path.display(), "friglet-tray starting; logging to file");
    }

    let mut state = AppState::new(friglet_ipc::default_socket_path());
    state.tray_log = tray_log;
    let state = Arc::new(state);

    tauri::Builder::default()
        // Must be the first plugin registered (tauri-plugin-single-instance
        // requirement). Without this, two tray instances can each probe the
        // socket, find nothing, and both spawn a `friglet` daemon — the
        // loser's process dies almost immediately (its control socket bind
        // fails), but if its tray quits before reaping that exit, Quit would
        // send Shutdown down the *shared* socket path and kill the winner's
        // daemon out from under the other tray. A second launch here just
        // surfaces the already-running tray's window instead.
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            show_status_window(app);
        }))
        .plugin(tauri_plugin_clipboard_manager::init())
        // Start at login: XDG autostart entry (Linux), LaunchAgent (macOS),
        // Run key (Windows); points at the AppImage when run from one.
        .plugin(tauri_plugin_autostart::init(
            tauri_plugin_autostart::MacosLauncher::LaunchAgent,
            None,
        ))
        .manage(state)
        .manage(Arc::new(popup::Popup::detect()))
        .invoke_handler(tauri::generate_handler![
            get_status,
            start_scanning,
            stop_scanning,
            get_config,
            get_setup_state,
            save_local_config,
            inspect_descriptor,
            apply_settings,
            network_defaults,
            get_autostart,
            set_autostart,
            start_daemon,
            stop_daemon,
            open_log_folder,
            dismiss_window
        ])
        .on_window_event(|window, event| match event {
            // Tray-only app: closing the status window hides it.
            WindowEvent::CloseRequested { api, .. } => {
                api.prevent_close();
                match window.app_handle().get_webview_window(window.label()) {
                    Some(webview) => window
                        .app_handle()
                        .state::<Arc<popup::Popup>>()
                        .hide(&webview),
                    None => {
                        let _ = window.hide();
                    }
                }
            }
            // The popup closes when another window takes the focus.
            WindowEvent::Focused(focused) => {
                if let Some(webview) = window.app_handle().get_webview_window(window.label()) {
                    window
                        .app_handle()
                        .state::<Arc<popup::Popup>>()
                        .focus_changed(&webview, *focused);
                }
            }
            _ => {}
        })
        .setup(|app| {
            #[cfg(target_os = "macos")]
            app.set_activation_policy(tauri::ActivationPolicy::Accessory);

            if let Some(window) = app.get_webview_window("main") {
                app.state::<Arc<popup::Popup>>().prepare(&window);
            }
            setup_tray(app)?;

            let show_on_start_value = std::env::var("FRIGLET_TRAY_SHOW_ON_START").ok();
            match show_on_start(show_on_start_value.as_deref()) {
                Some("status") => show_status_window(app.handle()),
                Some(tab) => show_window_tab(app.handle(), tab),
                None => {}
            }

            // Attach to a running daemon, spawn one, or detect that
            // first-run setup is needed — in the background so the tray
            // appears immediately. When setup is needed, bring the window
            // up on the Settings tab so the user isn't stuck staring at an
            // inert tray icon.
            let state = app.state::<Arc<AppState>>().inner().clone();
            let handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                let _ = attach_and_record(&state).await;
                if state.setup_needed.load(Ordering::SeqCst) {
                    show_window_tab(&handle, "settings");
                }
            });
            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("error while building friglet-tray")
        .run(|_app, event| {
            // Keep running tray-only; only an explicit `app.exit(code)`
            // (which carries `Some(code)`) is allowed through.
            if let tauri::RunEvent::ExitRequested {
                api, code: None, ..
            } = event
            {
                api.prevent_exit();
            }
        });
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    fn test_socket_path(tag: &str) -> String {
        std::env::temp_dir()
            .join(format!(
                "friglet-tray-lib-{}-{tag}.sock",
                std::process::id()
            ))
            .to_string_lossy()
            .into_owned()
    }

    fn test_state(socket_path: String) -> AppState {
        AppState::new(socket_path)
    }

    /// Serve GetStatus on `path`, like a healthy daemon that was not
    /// tray-spawned.
    fn spawn_fake_daemon(path: String) {
        spawn_fake_daemon_owned(path, false);
    }

    /// [`spawn_fake_daemon`] with a caller-chosen `spawned_by_tray` answer,
    /// so tests can simulate re-attaching to a daemon that self-reports
    /// having been tray-spawned (e.g. by a now-crashed/restarted tray).
    fn spawn_fake_daemon_owned(path: String, spawned_by_tray: bool) {
        tokio::spawn(async move {
            let _ = std::fs::remove_file(&path);
            let listener = friglet_ipc::listen(&path).expect("bind fake daemon socket");
            loop {
                let Ok(mut conn) = friglet_ipc::accept(&listener).await else {
                    break;
                };
                tokio::spawn(async move {
                    while let Ok(Some(req)) = conn.next_request().await {
                        let resp = match req {
                            Request::GetStatus => Response::Status(StatusInfo {
                                scanning: false,
                                scanned_height: 1,
                                tip_height: None,
                                scan_progress: 0.0,
                                network: "regtest".to_string(),
                                electrum_clients: 0,
                                oracle_connected: false,
                                last_error: None,
                                sp_address: None,
                                tx_count: 0,
                                outputs_found: 0,
                                label_addresses: Vec::new(),
                                version: "test".to_string(),
                                spawned_by_tray,
                                scan_health: Default::default(),
                                ..Default::default()
                            }),
                            _ => Response::Ok,
                        };
                        if conn.respond(&resp).await.is_err() {
                            break;
                        }
                    }
                });
            }
        });
    }

    fn spawn_sleeper() -> Child {
        tokio::process::Command::new("sleep")
            .arg("30")
            .kill_on_drop(true)
            .spawn()
            .expect("spawn sleep")
    }

    fn process_alive(pid: u32) -> bool {
        std::process::Command::new("kill")
            .args(["-0", &pid.to_string()])
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    }

    #[test]
    fn show_on_start_values() {
        assert_eq!(show_on_start(None), None);
        for v in ["1", "true", "TRUE", "yes", "on", " Yes ", "status"] {
            assert_eq!(
                show_on_start(Some(v)),
                Some("status"),
                "expected status for {v:?}"
            );
        }
        assert_eq!(show_on_start(Some("settings")), Some("settings"));
        assert_eq!(show_on_start(Some("wallet")), Some("wallet"));
        for v in ["0", "false", "no", "off", "", "maybe"] {
            assert_eq!(show_on_start(Some(v)), None, "expected unset for {v:?}");
        }
    }

    #[tokio::test]
    async fn retry_keeps_child_when_socket_reachable() {
        let path = test_socket_path("retry-reachable");
        spawn_fake_daemon(path.clone());
        tokio::time::sleep(Duration::from_millis(100)).await;

        let state = test_state(path.clone());
        {
            let mut lc = state.lifecycle.lock().await;
            lc.child = Some(spawn_sleeper());
            lc.spawned_by_tray = true;
        }

        attach_and_record_with(
            &state,
            || panic!("must not look for a binary when the spawned daemon answers"),
            || false,
        )
        .await;

        let mut lc = state.lifecycle.lock().await;
        assert!(lc.spawned_by_tray, "ownership must be kept");
        let mut child = lc.child.take().expect("child must be kept");
        let _ = child.kill().await;
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn retry_replaces_alive_child_when_socket_unreachable() {
        // No listener at this path: the spawned daemon is "alive but wedged".
        let path = test_socket_path("retry-wedged");
        let _ = std::fs::remove_file(&path);

        let state = test_state(path);
        let pid = {
            let mut lc = state.lifecycle.lock().await;
            let child = spawn_sleeper();
            let pid = child.id().expect("child pid");
            lc.child = Some(child);
            lc.spawned_by_tray = true;
            pid
        };
        assert!(process_alive(pid));

        // Locator finds nothing, so the re-run ends Unreachable — the point
        // here is that the wedged child is killed and cleared first. The
        // locator runs right before a new daemon would be spawned, so the
        // old child must already be fully exited by then (no overlap on
        // shared config/key/state paths).
        attach_and_record_with(
            &state,
            move || {
                assert!(
                    !process_alive(pid),
                    "old daemon must be fully exited before a new spawn attempt"
                );
                None
            },
            || false,
        )
        .await;

        let lc = state.lifecycle.lock().await;
        assert!(lc.child.is_none(), "wedged child must be cleared");
        assert!(!lc.spawned_by_tray);
        assert!(!process_alive(pid), "wedged child must be killed");
    }

    #[tokio::test]
    async fn retry_reattaches_after_child_exited() {
        let path = test_socket_path("retry-exited");
        spawn_fake_daemon(path.clone());
        tokio::time::sleep(Duration::from_millis(100)).await;

        let state = test_state(path.clone());
        {
            let mut lc = state.lifecycle.lock().await;
            let mut child = tokio::process::Command::new("true").spawn().expect("spawn");
            let _ = child.wait().await;
            lc.child = Some(child);
            lc.spawned_by_tray = true;
        }

        attach_and_record_with(&state, || None, || false).await;

        let lc = state.lifecycle.lock().await;
        assert!(lc.child.is_none(), "exited child must be reaped");
        assert!(
            !lc.spawned_by_tray,
            "re-attach to the reachable daemon must drop ownership"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// A fresh tray (no in-memory ownership yet) that attaches to a daemon
    /// self-reporting `spawned_by_tray: true` — as one spawned by a tray
    /// that has since crashed or restarted would — must adopt that
    /// ownership, so its own later Quit can still shut the daemon down
    /// instead of orphaning it.
    #[tokio::test]
    async fn attach_adopts_daemons_self_reported_ownership() {
        let path = test_socket_path("adopt-ownership");
        spawn_fake_daemon_owned(path.clone(), true);
        tokio::time::sleep(Duration::from_millis(100)).await;

        let state = test_state(path.clone());
        attach_and_record_with(
            &state,
            || panic!("must not spawn when attach succeeds"),
            || false,
        )
        .await;

        let lc = state.lifecycle.lock().await;
        assert!(
            lc.spawned_by_tray,
            "ownership must be adopted from the daemon's self-report"
        );
        assert!(lc.child.is_none(), "no child handle for an attached daemon");
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn unreachable_and_unconfigured_sets_setup_mode_without_spawn() {
        // No listener at this path and setup needed: the locator must never
        // run (no spawn attempt) and the setup flag must be raised.
        let path = test_socket_path("setup-mode");
        let _ = std::fs::remove_file(&path);

        let state = test_state(path);
        let reason = attach_and_record_with(
            &state,
            || panic!("must not look for a binary when setup is needed"),
            || true,
        )
        .await;
        assert_eq!(reason, None, "setup mode is not a spawn failure");
        assert!(state.setup_needed.load(Ordering::SeqCst));

        // Once configured (files written), the same flow proceeds to the
        // normal locate/spawn path and clears the flag on failure.
        let reason = attach_and_record_with(&state, || None, || false).await;
        assert!(
            reason.is_some_and(|r| r.contains("not found")),
            "expected the binary-not-found reason"
        );
        assert!(!state.setup_needed.load(Ordering::SeqCst));
    }

    #[test]
    fn tray_labels_reflect_daemon_and_scan_state() {
        let label = |facts: DaemonFacts, status: Option<&StatusInfo>| {
            let daemon = view::daemon_view(&facts);
            let scan = view::scan_view(status, facts.reachable, unix_now());
            (
                tray_label(&daemon, &scan, status),
                tray_tooltip(&daemon, &scan, status),
            )
        };
        let gone = DaemonFacts {
            unreachable_for_secs: Some(60),
            ..Default::default()
        };
        assert_eq!(label(gone.clone(), None).0, "Daemon: not running");
        let (setup, setup_tip) = label(
            DaemonFacts {
                setup_needed: true,
                ..gone.clone()
            },
            None,
        );
        assert_eq!(setup, "Setup required — open window");
        assert!(setup_tip.contains("setup required"));
        let (crashed, crashed_tip) = label(
            DaemonFacts {
                restart_in_secs: Some(2),
                ..gone.clone()
            },
            None,
        );
        assert_eq!(crashed, "Daemon: crashed — restarting");
        assert!(crashed_tip.contains("restarting"));
        let paused = StatusInfo {
            scanned_height: 7,
            tip_height: Some(7),
            scan_state: Some(friglet_ipc::ScanState::Paused),
            ..Default::default()
        };
        let (running, _) = label(
            DaemonFacts {
                reachable: true,
                ..Default::default()
            },
            Some(&paused),
        );
        assert_eq!(running, "Scan: paused (height 7)");
    }

    /// A fake daemon that answers GetStatus with `pid` and stops listening
    /// (removing its socket) on Shutdown, like the real one.
    fn spawn_stoppable_fake_daemon(path: String, spawned_by_tray: bool, pid: u32) {
        tokio::spawn(async move {
            let _ = std::fs::remove_file(&path);
            let listener = friglet_ipc::listen(&path).expect("bind fake daemon socket");
            let (stop_tx, mut stop_rx) = tokio::sync::watch::channel(false);
            loop {
                let mut conn = tokio::select! {
                    conn = friglet_ipc::accept(&listener) => match conn {
                        Ok(conn) => conn,
                        Err(_) => break,
                    },
                    _ = stop_rx.changed() => break,
                };
                let stop_tx = stop_tx.clone();
                tokio::spawn(async move {
                    while let Ok(Some(req)) = conn.next_request().await {
                        let shutdown = req == Request::Shutdown;
                        let resp = match req {
                            Request::GetStatus => Response::Status(StatusInfo {
                                spawned_by_tray,
                                pid: Some(pid),
                                scan_state: Some(friglet_ipc::ScanState::Running),
                                ..Default::default()
                            }),
                            _ => Response::Ok,
                        };
                        if conn.respond(&resp).await.is_err() {
                            break;
                        }
                        if shutdown {
                            let _ = stop_tx.send(true);
                        }
                    }
                });
            }
            let _ = std::fs::remove_file(&path);
        });
    }

    /// The poller's view of the daemon, without the poller.
    async fn poll_once(state: &AppState) -> (DaemonView, ScanView) {
        let info = lifecycle::probe(&state.socket_path, lifecycle::PROBE_TIMEOUT).await;
        record_poll(state, info.as_ref());
        let (daemon, scan, _) = refresh(state, info.as_ref());
        (daemon, scan)
    }

    /// A poll that still reaches the daemon being stopped (it answers while
    /// it shuts down) must not cancel the stop; another daemon answering
    /// (started from a terminal, say) does end it.
    #[tokio::test]
    async fn a_poll_of_the_stopping_daemon_keeps_it_stopped() {
        let path = test_socket_path("stop-race");
        spawn_stoppable_fake_daemon(path.clone(), false, 5000);
        tokio::time::sleep(Duration::from_millis(100)).await;
        let state = test_state(path.clone());
        *state.stopped.lock().unwrap() = Some(Stopped {
            at_unix: unix_now(),
            by_user: true,
            detail: String::new(),
            pid: Some(5000),
        });
        poll_once(&state).await;
        assert!(
            state.stopped.lock().unwrap().is_some(),
            "same PID: still stopping"
        );

        state.stopped.lock().unwrap().as_mut().unwrap().pid = Some(4999);
        let (daemon, _) = poll_once(&state).await;
        assert!(state.stopped.lock().unwrap().is_none(), "a new daemon runs");
        assert_eq!(daemon.state, "running");
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn stop_daemon_stops_an_attached_external_daemon_for_good() {
        let path = test_socket_path("stop-external");
        spawn_stoppable_fake_daemon(path.clone(), false, 4711);
        tokio::time::sleep(Duration::from_millis(100)).await;
        let state = test_state(path.clone());
        attach_and_record_with(&state, || panic!("must attach"), || false).await;
        let (daemon, _) = poll_once(&state).await;
        assert_eq!(daemon.state, "running");
        assert_eq!(daemon.ownership, Some(Ownership::External));
        assert!(
            daemon.detail.contains("Started outside the tray"),
            "{}",
            daemon.detail
        );
        assert!(daemon.detail.contains("PID 4711"));
        assert!(daemon.can_stop);

        let message = stop_daemon_now(&state).await.expect("stopped");
        assert!(message.contains("PID 4711 exited"), "{message}");
        assert!(
            lifecycle::probe(&path, lifecycle::PROBE_TIMEOUT)
                .await
                .is_none()
        );

        // Even with supervision on and the daemon silent for long, nothing
        // restarts it, and nothing counts as an error.
        state.supervise.store(true, Ordering::SeqCst);
        *state.unreachable_since.lock().unwrap() = Some(Instant::now() - Duration::from_secs(600));
        for _ in 0..3 {
            supervise_tick_with(
                &state,
                false,
                || panic!("must not restart a stopped daemon"),
                || false,
            )
            .await;
        }
        let (daemon, _) = poll_once(&state).await;
        assert_eq!((daemon.state, daemon.can_start), ("stopped", true));
        assert!(
            daemon.detail.starts_with("Stopped by you"),
            "{}",
            daemon.detail
        );
        assert!(
            state.errors.lock().unwrap().entries().is_empty(),
            "a stop on request is not an error"
        );

        // Start daemon brings one back (here: attaches to a new one).
        spawn_stoppable_fake_daemon(path.clone(), false, 4712);
        tokio::time::sleep(Duration::from_millis(100)).await;
        start_daemon_now(&state).await.expect("started");
        assert!(state.stopped.lock().unwrap().is_none());
        let (daemon, _) = poll_once(&state).await;
        assert_eq!(daemon.state, "running");
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn stop_daemon_on_a_tray_spawned_daemon_is_not_undone_by_the_supervisor() {
        let path = test_socket_path("stop-spawned");
        spawn_stoppable_fake_daemon(path.clone(), true, 4800);
        tokio::time::sleep(Duration::from_millis(100)).await;
        let state = test_state(path.clone());
        state.supervise.store(true, Ordering::SeqCst);
        {
            // Stands in for the spawned daemon process: exits by itself
            // shortly, like the real one after the Shutdown request.
            let mut lc = state.lifecycle.lock().await;
            lc.child = Some(
                tokio::process::Command::new("sleep")
                    .arg("0.3")
                    .spawn()
                    .expect("spawn"),
            );
            lc.spawned_by_tray = true;
        }
        let (daemon, _) = poll_once(&state).await;
        assert_eq!(daemon.ownership, Some(Ownership::ThisTray));
        assert!(daemon.detail.contains("Quit stops it"));

        let message = stop_daemon_now(&state).await.expect("stopped");
        assert!(message.contains("exit status: 0"), "{message}");
        assert!(!state.supervise.load(Ordering::SeqCst));
        state.supervise.store(true, Ordering::SeqCst); // even if re-enabled
        supervise_tick_with(&state, false, || panic!("must not restart"), || false).await;
        assert_eq!(daemon_health(&state).restart_in_secs, None);
        let (daemon, _) = poll_once(&state).await;
        assert_eq!(daemon.state, "stopped");
    }

    #[tokio::test]
    async fn a_daemon_exiting_normally_is_left_stopped() {
        let path = test_socket_path("clean-exit");
        let _ = std::fs::remove_file(&path);
        let state = test_state(path);
        state.supervise.store(true, Ordering::SeqCst);
        {
            let mut lc = state.lifecycle.lock().await;
            let mut child = tokio::process::Command::new("true").spawn().expect("spawn");
            let _ = child.wait().await;
            lc.child = Some(child);
            lc.spawned_by_tray = true;
        }
        supervise_tick_with(&state, false, || panic!("must not restart"), || false).await;
        assert_eq!(daemon_health(&state).restart_in_secs, None);
        let stopped = state
            .stopped
            .lock()
            .unwrap()
            .clone()
            .expect("recorded as stopped");
        assert!(!stopped.by_user);
        assert!(state.errors.lock().unwrap().entries().is_empty());
    }

    #[tokio::test]
    async fn a_dead_daemon_becomes_an_error_only_after_the_grace_and_is_logged_in_the_book() {
        let path = test_socket_path("grace");
        let _ = std::fs::remove_file(&path);
        let state = test_state(path);
        *state.unreachable_since.lock().unwrap() = Some(Instant::now());
        let (daemon, _) = poll_once(&state).await;
        assert_eq!(daemon.state, "reconnecting");
        assert!(state.errors.lock().unwrap().entries().is_empty());

        *state.unreachable_since.lock().unwrap() =
            Some(Instant::now() - Duration::from_secs(view::UNREACHABLE_GRACE_SECS));
        let (daemon, _) = poll_once(&state).await;
        assert_eq!(daemon.state, "unreachable");
        let entries = state.errors.lock().unwrap().entries();
        assert_eq!(entries.len(), 1);
        assert!(entries[0].active);
        assert!(entries[0].message.contains("not running or not answering"));
    }

    #[tokio::test]
    async fn supervisor_records_crash_and_schedules_restart() {
        let path = test_socket_path("supervise-crash");
        let _ = std::fs::remove_file(&path);
        let state = test_state(path.clone());
        state.supervise.store(true, Ordering::SeqCst);
        {
            let mut lc = state.lifecycle.lock().await;
            let mut child = tokio::process::Command::new("sh")
                .args(["-c", "exit 3"])
                .spawn()
                .expect("spawn");
            let _ = child.wait().await;
            lc.child = Some(child);
            lc.spawned_by_tray = true;
            let output: RecentOutput = Default::default();
            output
                .lock()
                .unwrap()
                .push_back("Error: oracle unreachable".to_string());
            lc.recent_output = Some(output);
        }

        supervise_tick_with(&state, false, || panic!("not due yet"), || false).await;

        let health = daemon_health(&state);
        assert_eq!(health.last_exit.as_deref(), Some("exit status: 3"));
        assert_eq!(
            health.last_output.as_deref(),
            Some("Error: oracle unreachable")
        );
        assert_eq!(health.restart_in_secs, Some(1), "first restart after 1s");
        assert!(
            state.lifecycle.lock().await.child.is_none(),
            "dead child reaped"
        );

        // Once due, the restart attaches to whatever answers now (here a fake
        // daemon), clearing the pending restart.
        spawn_fake_daemon(path.clone());
        tokio::time::sleep(Duration::from_millis(100)).await;
        state.supervision.lock().unwrap().next_restart_at = Some(Instant::now());
        supervise_tick_with(&state, false, || panic!("must attach, not spawn"), || false).await;
        let health = daemon_health(&state);
        assert_eq!(health.restarts, 1);
        assert_eq!(health.restart_in_secs, None);
        assert_eq!(
            health.last_exit.as_deref(),
            Some("exit status: 3"),
            "report kept"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn supervisor_leaves_external_daemons_and_quit_alone() {
        for (supervise, quitting) in [(false, false), (true, true)] {
            let state = test_state(test_socket_path("supervise-off"));
            state.supervise.store(supervise, Ordering::SeqCst);
            state.quitting.store(quitting, Ordering::SeqCst);
            {
                let mut lc = state.lifecycle.lock().await;
                let mut child = tokio::process::Command::new("true").spawn().expect("spawn");
                let _ = child.wait().await;
                lc.child = Some(child);
            }
            supervise_tick_with(&state, false, || panic!("no restart"), || false).await;
            assert_eq!(daemon_health(&state).last_exit, None);
            assert!(state.lifecycle.lock().await.child.is_some(), "untouched");
        }
    }

    #[tokio::test]
    async fn failed_restart_backs_off_with_the_reason() {
        let path = test_socket_path("supervise-fail");
        let _ = std::fs::remove_file(&path);
        let state = test_state(path);
        state.supervise.store(true, Ordering::SeqCst);
        state.supervision.lock().unwrap().on_exit(
            ExitReport {
                at: SystemTime::now(),
                status: "signal: 9 (SIGKILL)".to_string(),
                output: String::new(),
            },
            Instant::now() - Duration::from_secs(5),
        );
        // Nothing answers, so the restart tries to spawn — and finds no
        // binary.
        supervise_tick_with(&state, false, || None, || false).await;
        let health = daemon_health(&state);
        assert!(health.supervised);
        assert!(
            health
                .last_error
                .is_some_and(|e| e.contains("binary not found")),
            "spawn failure reason surfaced"
        );
        assert_eq!(health.restart_in_secs, Some(2), "second attempt after 2s");
        assert_eq!(health.restarts, 0);
    }

    #[tokio::test]
    async fn failed_first_start_is_retried_with_backoff() {
        let path = test_socket_path("first-start-fail");
        let _ = std::fs::remove_file(&path);
        let state = test_state(path);
        let reason = attach_and_record_with(&state, || None, || false).await;
        assert!(reason.is_some());
        let health = daemon_health(&state);
        assert!(health.supervised);
        assert_eq!(health.restart_in_secs, Some(1), "retried after 1s");
        assert!(
            health
                .last_error
                .is_some_and(|e| e.contains("binary not found"))
        );
    }

    #[test]
    fn quit_label_reflects_ownership() {
        assert_eq!(quit_label(true, true), "Quit (stops daemon)");
        assert_eq!(quit_label(true, false), "Quit (keeps daemon running)");
        assert_eq!(quit_label(false, true), "Quit", "nothing to stop or keep");
    }
}
