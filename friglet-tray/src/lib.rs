//! Friglet tray app: a Tauri v2 tray-only companion for the `friglet`
//! daemon. Talks to the daemon over the `friglet-ipc` control socket,
//! shows live status in the tray menu and a hidden-by-default status
//! window, and manages the daemon lifecycle (attach or spawn, quit rule).

pub mod lifecycle;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use friglet_ipc::{Client, Request, Response, StatusInfo};
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

/// Send a request that is expected to answer `Ok`.
async fn send_simple(socket_path: &str, req: Request) -> Result<(), String> {
    let mut client = Client::connect(socket_path)
        .await
        .map_err(|e| format!("daemon unreachable: {e}"))?;
    match client
        .request(&req)
        .await
        .map_err(|e| format!("request failed: {e}"))?
    {
        Response::Ok => Ok(()),
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
    let mut lc = state.lifecycle.lock().await;

    // Reap a previously spawned child that has exited.
    if let Some(child) = lc.child.as_mut()
        && !matches!(child.try_wait(), Ok(None))
    {
        tracing::warn!("previously spawned daemon exited");
        lc.child = None;
        lc.spawned_by_tray = false;
    }

    if lc.child.is_some() {
        // Our own daemon is alive (maybe still starting up); never stack a
        // second spawn on top of it.
        return;
    }

    match lifecycle::attach_or_spawn(&state.socket_path).await {
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
            stop_scanning
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
