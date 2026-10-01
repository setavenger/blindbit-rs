//! Friglet tray app: a Tauri v2 tray-only companion for the `friglet`
//! daemon. Talks to the daemon over the `friglet-ipc` control socket,
//! shows live status in the tray menu and a hidden-by-default status
//! window, and manages the daemon lifecycle (attach or spawn, quit rule).

pub mod lifecycle;
pub mod setup;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use friglet_ipc::{Client, DaemonConfig, Request, Response, StatusInfo};
use serde::Serialize;
use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::TrayIconBuilder;
use tauri::{AppHandle, Manager, State, WindowEvent};
use tauri_plugin_autostart::ManagerExt;
use tokio::process::Child;

use lifecycle::{Attachment, ExitReport, RecentOutput, Supervision};

/// How often the background task polls `GetStatus`.
const POLL_INTERVAL: Duration = Duration::from_secs(1);
/// Per-poll probe timeout; shorter than the interval so polls don't pile up.
const POLL_TIMEOUT: Duration = Duration::from_millis(900);
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
        }
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

/// Payload for the `get_status` command.
#[derive(Serialize)]
struct StatusPayload {
    reachable: bool,
    status: Option<StatusInfo>,
    daemon: DaemonHealth,
}

#[tauri::command]
async fn get_status(state: State<'_, Arc<AppState>>) -> Result<StatusPayload, String> {
    let daemon = daemon_health(&state);
    let s = state.status.lock().unwrap();
    Ok(StatusPayload {
        reachable: s.reachable,
        status: s.last.clone(),
        daemon,
    })
}

#[tauri::command]
async fn start_scanning(state: State<'_, Arc<AppState>>) -> Result<(), String> {
    send_simple(&state.socket_path, Request::Start).await
}

#[tauri::command]
async fn stop_scanning(state: State<'_, Arc<AppState>>) -> Result<(), String> {
    send_simple(&state.socket_path, Request::Stop).await
}

/// Fetch the daemon's effective configuration (never contains the scan
/// secret). Errors when the daemon is unreachable so the settings form can
/// disable itself.
#[tauri::command]
async fn get_config(state: State<'_, Arc<AppState>>) -> Result<DaemonConfig, String> {
    let mut client = Client::connect(&state.socket_path)
        .await
        .map_err(|e| format!("daemon unreachable: {e}"))?;
    match client
        .request(&Request::GetConfig)
        .await
        .map_err(|e| format!("request failed: {e}"))?
    {
        Response::Config(cfg) => Ok(cfg),
        Response::Error(e) => Err(e),
        other => Err(format!("unexpected response: {other:?}")),
    }
}

/// Send the full configuration to the daemon (validate → persist → apply).
/// `Ok(None)` on plain success; `Ok(Some(note))` when the daemon reports a
/// note (e.g. bind-address changes needing a daemon restart).
#[tauri::command]
async fn set_config(
    state: State<'_, Arc<AppState>>,
    config: DaemonConfig,
) -> Result<Option<String>, String> {
    send_with_note(&state.socket_path, Request::SetConfig(Box::new(config))).await
}

/// Replace the scan secret (hex 32 bytes); the daemon writes its key file.
#[tauri::command]
async fn set_scan_key(
    state: State<'_, Arc<AppState>>,
    key: String,
) -> Result<Option<String>, String> {
    send_with_note(&state.socket_path, Request::SetScanKey(key)).await
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

/// Send a request that is expected to answer `Ok`.
async fn send_simple(socket_path: &str, req: Request) -> Result<(), String> {
    send_with_note(socket_path, req).await.map(|_| ())
}

/// Send a request answering `Ok` or `OkWithNote`; the note is passed through
/// so the UI can surface it.
async fn send_with_note(socket_path: &str, req: Request) -> Result<Option<String>, String> {
    let mut client = Client::connect(socket_path)
        .await
        .map_err(|e| format!("daemon unreachable: {e}"))?;
    match client
        .request(&req)
        .await
        .map_err(|e| format!("request failed: {e}"))?
    {
        Response::Ok => Ok(None),
        Response::OkWithNote(note) => Ok(Some(note)),
        Response::Error(e) => Err(e),
        other => Err(format!("unexpected response: {other:?}")),
    }
}

/// Probe-spawn-or-setup, recording the outcome in [`LifecycleState`] and the
/// `setup_needed` flag. Returns the failure reason when the daemon stayed
/// unreachable despite being configured (spawn failed / socket never came up).
///
/// Runs at startup, from the "Retry / Start daemon" menu item and after a
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

    // Reap a previously spawned child that has exited.
    if let Some(report) = reap_exited(&mut lc) {
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
            None
        }
        Attachment::Spawned(child, recent_output) => {
            tracing::info!("spawned daemon and connected");
            lc.spawned_by_tray = true;
            lc.child = Some(child);
            lc.recent_output = Some(recent_output);
            state.supervise.store(true, Ordering::SeqCst);
            state.setup_needed.store(false, Ordering::SeqCst);
            let mut sup = state.supervision.lock().unwrap();
            sup.next_restart_at = None;
            sup.last_spawn_error = None;
            None
        }
        Attachment::SetupRequired => {
            tracing::info!("daemon not configured yet; entering first-run setup mode");
            state.supervise.store(false, Ordering::SeqCst);
            state.setup_needed.store(true, Ordering::SeqCst);
            None
        }
        Attachment::Unreachable { reason } => {
            tracing::warn!(%reason, "daemon unreachable");
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

/// Reap the spawned child if it has exited, returning how it ended.
fn reap_exited(lc: &mut LifecycleState) -> Option<ExitReport> {
    let status = match lc.child.as_mut()?.try_wait() {
        Ok(None) => return None,
        Ok(Some(status)) => status.to_string(),
        Err(e) => format!("unknown ({e})"),
    };
    lc.child = None;
    lc.spawned_by_tray = false;
    let output = lc
        .recent_output
        .take()
        .map(|o| lifecycle::recent_output_tail(&o))
        .unwrap_or_default();
    Some(ExitReport {
        at: SystemTime::now(),
        status,
        output,
    })
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
    if !state.supervise.load(Ordering::SeqCst) || state.setup_needed.load(Ordering::SeqCst) {
        return;
    }

    // Skip the tick while an attach/spawn/quit holds the lifecycle lock.
    let Ok(mut lc) = state.lifecycle.try_lock() else {
        return;
    };
    if let Some(report) = reap_exited(&mut lc) {
        tracing::warn!(
            status = %report.status,
            output = %report.output,
            "daemon exited unexpectedly; restarting it"
        );
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
            tracing::warn!(status, "daemon presumed dead; restarting it");
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
        app.exit(0);
    });
}

fn show_status_window(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.set_focus();
    }
}

/// Show the main window and switch it to the Settings tab once the UI has
/// had a chance to load. Used for `FRIGLET_TRAY_SHOW_ON_START=settings` and
/// for first-run setup mode. (Synthetic X11 clicks do not reach WebKitGTK
/// reliably under Xvfb, so this eval is the supported headless path to the
/// Settings form.)
fn show_settings_window(app: &AppHandle) {
    show_status_window(app);
    let handle = app.clone();
    tauri::async_runtime::spawn(async move {
        tokio::time::sleep(Duration::from_millis(800)).await;
        if let Some(w) = handle.get_webview_window("main") {
            let _ = w.eval("document.getElementById('tab-settings')?.click()");
        }
    });
}

/// Show the main window on the Wallet tab for screenshot testing.
fn show_wallet_window(app: &AppHandle) {
    show_status_window(app);
    let handle = app.clone();
    tauri::async_runtime::spawn(async move {
        tokio::time::sleep(Duration::from_millis(800)).await;
        if let Some(w) = handle.get_webview_window("main") {
            let _ = w.eval("document.getElementById('tab-wallet')?.click()");
        }
    });
}

/// Parse `FRIGLET_TRAY_SHOW_ON_START`:
/// - unset / falsy → hide window (default)
/// - `1` / `true` / `yes` / `on` / `status` → show status window
/// - `settings` → show window and switch to the Settings tab (after the UI loads)
/// - `wallet` → show window and switch to the Wallet tab (after the UI loads)
fn show_on_start_env() -> Option<&'static str> {
    match std::env::var("FRIGLET_TRAY_SHOW_ON_START") {
        Ok(v) => match v.trim().to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" | "status" => Some("status"),
            "settings" => Some("settings"),
            "wallet" => Some("wallet"),
            _ => None,
        },
        Err(_) => None,
    }
}

fn tray_label(status: Option<&StatusInfo>, setup_needed: bool, restarting: bool) -> String {
    match status {
        Some(s) => format!("Daemon: reachable (height {})", s.scanned_height),
        None if setup_needed => "Setup required — open window".to_string(),
        None if restarting => "Daemon: crashed — restarting".to_string(),
        None => "Daemon: unreachable".to_string(),
    }
}

/// Label for the Quit menu item, so its consequence (shuts the daemon down
/// vs. leaves it running) is visible without reading the README.
fn quit_label(spawned_by_tray: bool) -> &'static str {
    if spawned_by_tray {
        "Quit (stops daemon)"
    } else {
        "Quit (keeps daemon running)"
    }
}

fn tray_tooltip(status: Option<&StatusInfo>, setup_needed: bool, restarting: bool) -> String {
    match status {
        Some(s) => {
            let tip = s
                .tip_height
                .map(|t| t.to_string())
                .unwrap_or_else(|| "?".to_string());
            let activity = if s.scanning { "scanning" } else { "idle" };
            format!("Friglet: {activity}, height {}/{tip}", s.scanned_height)
        }
        None if setup_needed => "Friglet: first-time setup required".to_string(),
        None if restarting => "Friglet: daemon crashed, restarting".to_string(),
        None => "Friglet: daemon unreachable".to_string(),
    }
}

fn setup_tray(app: &tauri::App) -> tauri::Result<()> {
    let handle = app.handle();

    let status_item = MenuItem::with_id(
        handle,
        "status-label",
        tray_label(None, false, false),
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
    let start_item = MenuItem::with_id(handle, "start-scan", "Start scanning", true, None::<&str>)?;
    let stop_item = MenuItem::with_id(handle, "stop-scan", "Stop scanning", true, None::<&str>)?;
    let retry_item = MenuItem::with_id(
        handle,
        "retry-daemon",
        "Retry / Start daemon",
        true,
        None::<&str>,
    )?;
    let quit_item = MenuItem::with_id(handle, "quit", quit_label(false), true, None::<&str>)?;

    let menu = Menu::with_items(
        handle,
        &[
            &status_item,
            &open_item,
            &PredefinedMenuItem::separator(handle)?,
            &start_item,
            &stop_item,
            &PredefinedMenuItem::separator(handle)?,
            &retry_item,
            &PredefinedMenuItem::separator(handle)?,
            &quit_item,
        ],
    )?;

    let tray = TrayIconBuilder::with_id("friglet-tray")
        .icon(
            app.default_window_icon()
                .cloned()
                .expect("bundled window icon"),
        )
        .menu(&menu)
        .show_menu_on_left_click(true)
        .tooltip("Friglet")
        .on_menu_event(|app, event| match event.id().as_ref() {
            "open-window" => show_status_window(app),
            "start-scan" | "stop-scan" => {
                let req = if event.id().as_ref() == "start-scan" {
                    Request::Start
                } else {
                    Request::Stop
                };
                let state = app.state::<Arc<AppState>>().inner().clone();
                tauri::async_runtime::spawn(async move {
                    if let Err(e) = send_simple(&state.socket_path, req).await {
                        tracing::warn!(error = %e, "start/stop via tray menu failed");
                    }
                });
            }
            "retry-daemon" => {
                let state = app.state::<Arc<AppState>>().inner().clone();
                let app = app.clone();
                tauri::async_runtime::spawn(async move {
                    // Manual retry: now, with a fresh backoff.
                    state.supervision.lock().unwrap().reset();
                    let _ = attach_and_record(&state).await;
                    // Retry with an unconfigured daemon lands in setup mode
                    // instead of a spawn-fail loop; take the user there.
                    if state.setup_needed.load(Ordering::SeqCst) {
                        show_settings_window(&app);
                    }
                });
            }
            "quit" => quit(app),
            _ => {}
        })
        .build(app)?;

    // Background poller: refresh shared status every second and update the
    // tray label / tooltip / start-stop enablement when something changed.
    let state = app.state::<Arc<AppState>>().inner().clone();
    tauri::async_runtime::spawn(async move {
        let mut last_label = String::new();
        let mut last_enablement: Option<(bool, bool)> = None;
        let mut last_quit_label: Option<&'static str> = None;
        loop {
            let info = lifecycle::probe(&state.socket_path, POLL_TIMEOUT).await;
            {
                let mut s = state.status.lock().unwrap();
                s.reachable = info.is_some();
                if info.is_some() {
                    s.last = info.clone();
                }
            }
            // A reachable daemon ends setup mode, whoever configured it.
            if info.is_some() {
                state.setup_needed.store(false, Ordering::SeqCst);
            }
            supervise_tick(&state, info.is_some()).await;
            let setup_needed = state.setup_needed.load(Ordering::SeqCst);
            let restarting = state.supervision.lock().unwrap().next_restart_at.is_some();

            let label = tray_label(info.as_ref(), setup_needed, restarting);
            if label != last_label {
                tracing::info!(%label, "tray status label updated");
                let _ = status_item.set_text(&label);
                let _ =
                    tray.set_tooltip(Some(tray_tooltip(info.as_ref(), setup_needed, restarting)));
                last_label = label;
            }

            let enablement = (
                info.is_some() && !info.as_ref().is_some_and(|i| i.scanning),
                info.as_ref().is_some_and(|i| i.scanning),
            );
            if last_enablement != Some(enablement) {
                let _ = start_item.set_enabled(enablement.0);
                let _ = stop_item.set_enabled(enablement.1);
                last_enablement = Some(enablement);
            }

            // Non-blocking: the lifecycle lock is only briefly held during
            // attach/spawn/quit, so a lock held elsewhere just skips this
            // poll tick's Quit-label refresh rather than stalling the poller.
            if let Ok(lc) = state.lifecycle.try_lock() {
                let label = quit_label(lc.spawned_by_tray);
                if last_quit_label != Some(label) {
                    let _ = quit_item.set_text(label);
                    last_quit_label = Some(label);
                }
            }

            tokio::time::sleep(POLL_INTERVAL).await;
        }
    });

    Ok(())
}

pub fn run() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let state = Arc::new(AppState::new(friglet_ipc::default_socket_path()));

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
        .invoke_handler(tauri::generate_handler![
            get_status,
            start_scanning,
            stop_scanning,
            get_config,
            set_config,
            set_scan_key,
            get_setup_state,
            save_local_config,
            inspect_descriptor,
            apply_settings,
            network_defaults,
            get_autostart,
            set_autostart
        ])
        .on_window_event(|window, event| {
            // Tray-only app: closing the status window hides it.
            if let WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let _ = window.hide();
            }
        })
        .setup(|app| {
            #[cfg(target_os = "macos")]
            app.set_activation_policy(tauri::ActivationPolicy::Accessory);

            setup_tray(app)?;

            if let Some(tab) = show_on_start_env() {
                match tab {
                    "settings" => show_settings_window(app.handle()),
                    "wallet" => show_wallet_window(app.handle()),
                    _ => show_status_window(app.handle()),
                }
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
                    show_settings_window(&handle);
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
    fn show_on_start_env_values() {
        // SAFETY: tests in this module run single-threaded on the env for
        // this key; we restore afterward.
        unsafe {
            std::env::remove_var("FRIGLET_TRAY_SHOW_ON_START");
        }
        assert_eq!(show_on_start_env(), None);
        for v in ["1", "true", "TRUE", "yes", "on", " Yes ", "status"] {
            unsafe {
                std::env::set_var("FRIGLET_TRAY_SHOW_ON_START", v);
            }
            assert_eq!(
                show_on_start_env(),
                Some("status"),
                "expected status for {v:?}"
            );
        }
        unsafe {
            std::env::set_var("FRIGLET_TRAY_SHOW_ON_START", "settings");
        }
        assert_eq!(show_on_start_env(), Some("settings"));
        unsafe {
            std::env::set_var("FRIGLET_TRAY_SHOW_ON_START", "wallet");
        }
        assert_eq!(show_on_start_env(), Some("wallet"));
        for v in ["0", "false", "no", "off", "", "maybe"] {
            unsafe {
                std::env::set_var("FRIGLET_TRAY_SHOW_ON_START", v);
            }
            assert_eq!(show_on_start_env(), None, "expected unset for {v:?}");
        }
        unsafe {
            std::env::remove_var("FRIGLET_TRAY_SHOW_ON_START");
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
    fn tray_labels_reflect_setup_mode() {
        assert_eq!(tray_label(None, false, false), "Daemon: unreachable");
        assert_eq!(
            tray_label(None, true, false),
            "Setup required — open window"
        );
        assert_eq!(
            tray_label(None, false, true),
            "Daemon: crashed — restarting"
        );
        assert!(tray_tooltip(None, true, false).contains("setup required"));
        assert!(tray_tooltip(None, false, true).contains("restarting"));
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
        assert_eq!(quit_label(true), "Quit (stops daemon)");
        assert_eq!(quit_label(false), "Quit (keeps daemon running)");
    }
}
