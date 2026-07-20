//! Friglet tray app: a Tauri v2 tray-only companion for the `friglet`
//! daemon. Talks to the daemon over the `friglet-ipc` control socket,
//! shows live status in the tray menu and a hidden-by-default status
//! window, and manages the daemon lifecycle (attach or spawn, quit rule).

pub mod lifecycle;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use friglet_ipc::{Client, DaemonConfig, Request, Response, StatusInfo};
use serde::Serialize;
use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::TrayIconBuilder;
use tauri::{AppHandle, Manager, State, WindowEvent};
use tokio::process::Child;

use lifecycle::Attachment;

/// How often the background task polls `GetStatus`.
const POLL_INTERVAL: Duration = Duration::from_secs(1);
/// Per-poll probe timeout; shorter than the interval so polls don't pile up.
const POLL_TIMEOUT: Duration = Duration::from_millis(900);

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
}

struct AppState {
    socket_path: String,
    status: Mutex<StatusState>,
    lifecycle: tokio::sync::Mutex<LifecycleState>,
}

/// Payload for the `get_status` command.
#[derive(Serialize)]
struct StatusPayload {
    reachable: bool,
    status: Option<StatusInfo>,
}

#[tauri::command]
async fn get_status(state: State<'_, Arc<AppState>>) -> Result<StatusPayload, String> {
    let s = state.status.lock().unwrap();
    Ok(StatusPayload {
        reachable: s.reachable,
        status: s.last.clone(),
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

/// Probe-or-spawn, recording the outcome in [`LifecycleState`].
///
/// Runs at startup and again from the "Retry / Start daemon" menu item.
/// Holds the lifecycle lock for the whole attempt so concurrent retriggers
/// queue up instead of spawning multiple daemons.
async fn attach_and_record(state: &AppState) {
    attach_and_record_with(state, lifecycle::locate_daemon_binary_from_env).await
}

/// [`attach_and_record`] with an injectable daemon-binary locator (tests
/// pass a stub so no real binary search happens).
async fn attach_and_record_with<F>(state: &AppState, locate: F)
where
    F: FnOnce() -> Option<std::path::PathBuf>,
{
    let mut lc = state.lifecycle.lock().await;

    // Reap a previously spawned child that has exited.
    if let Some(child) = lc.child.as_mut()
        && !matches!(child.try_wait(), Ok(None))
    {
        tracing::warn!("previously spawned daemon exited");
        lc.child = None;
        lc.spawned_by_tray = false;
    }

    // Our own daemon is still alive: verify it answers on the socket rather
    // than returning early, so a retry can recover from a wedged daemon.
    if lc.child.is_some() {
        if lifecycle::probe(&state.socket_path, lifecycle::PROBE_TIMEOUT)
            .await
            .is_some()
        {
            tracing::debug!("spawned daemon is alive and reachable; nothing to do");
            return;
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

    match lifecycle::attach_or_spawn_with(&state.socket_path, locate).await {
        Attachment::Attached => {
            tracing::info!("attached to already-running daemon");
            lc.spawned_by_tray = false;
        }
        Attachment::Spawned(child) => {
            tracing::info!("spawned daemon and connected");
            lc.spawned_by_tray = true;
            lc.child = Some(child);
        }
        Attachment::Unreachable { reason } => {
            tracing::warn!(%reason, "daemon unreachable");
        }
    }
}

/// Apply the quit rule, then exit the process.
fn quit(app: &AppHandle) {
    let state = app.state::<Arc<AppState>>().inner().clone();
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

fn tray_label(status: Option<&StatusInfo>) -> String {
    match status {
        Some(s) => format!("Daemon: reachable (height {})", s.scanned_height),
        None => "Daemon: unreachable".to_string(),
    }
}

fn tray_tooltip(status: Option<&StatusInfo>) -> String {
    match status {
        Some(s) => {
            let tip = s
                .tip_height
                .map(|t| t.to_string())
                .unwrap_or_else(|| "?".to_string());
            let activity = if s.scanning { "scanning" } else { "idle" };
            format!("Friglet: {activity}, height {}/{tip}", s.scanned_height)
        }
        None => "Friglet: daemon unreachable".to_string(),
    }
}

fn setup_tray(app: &tauri::App) -> tauri::Result<()> {
    let handle = app.handle();

    let status_item = MenuItem::with_id(
        handle,
        "status-label",
        tray_label(None),
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
    let quit_item = MenuItem::with_id(handle, "quit", "Quit", true, None::<&str>)?;

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
                tauri::async_runtime::spawn(async move { attach_and_record(&state).await });
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
        loop {
            let info = lifecycle::probe(&state.socket_path, POLL_TIMEOUT).await;
            {
                let mut s = state.status.lock().unwrap();
                s.reachable = info.is_some();
                if info.is_some() {
                    s.last = info.clone();
                }
            }

            let label = tray_label(info.as_ref());
            if label != last_label {
                tracing::info!(%label, "tray status label updated");
                let _ = status_item.set_text(&label);
                let _ = tray.set_tooltip(Some(tray_tooltip(info.as_ref())));
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

    let state = Arc::new(AppState {
        socket_path: friglet_ipc::default_socket_path(),
        status: Mutex::new(StatusState::default()),
        lifecycle: tokio::sync::Mutex::new(LifecycleState::default()),
    });

    tauri::Builder::default()
        .manage(state)
        .invoke_handler(tauri::generate_handler![
            get_status,
            start_scanning,
            stop_scanning,
            get_config,
            set_config,
            set_scan_key
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

            // Attach to a running daemon or spawn one, in the background so
            // the tray appears immediately.
            let state = app.state::<Arc<AppState>>().inner().clone();
            tauri::async_runtime::spawn(async move { attach_and_record(&state).await });
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
        AppState {
            socket_path,
            status: Mutex::new(StatusState::default()),
            lifecycle: tokio::sync::Mutex::new(LifecycleState::default()),
        }
    }

    /// Serve GetStatus on `path`, like a healthy daemon.
    fn spawn_fake_daemon(path: String) {
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
                                version: "test".to_string(),
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

        attach_and_record_with(&state, || {
            panic!("must not look for a binary when the spawned daemon answers")
        })
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
        attach_and_record_with(&state, move || {
            assert!(
                !process_alive(pid),
                "old daemon must be fully exited before a new spawn attempt"
            );
            None
        })
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

        attach_and_record_with(&state, || None).await;

        let lc = state.lifecycle.lock().await;
        assert!(lc.child.is_none(), "exited child must be reaped");
        assert!(
            !lc.spawned_by_tray,
            "re-attach to the reachable daemon must drop ownership"
        );
        let _ = std::fs::remove_file(&path);
    }
}
