//! E2E-ish tests for the tray's daemon lifecycle logic, using an in-process
//! fake daemon speaking the `friglet-ipc` protocol. No tauri involved.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use friglet_ipc::{Request, Response, StatusInfo};
use friglet_tray::lifecycle::{self, Attachment};

fn test_socket_path(tag: &str) -> String {
    #[cfg(windows)]
    {
        format!(r"\\.\pipe\friglet-tray-e2e-{}-{tag}", std::process::id())
    }
    #[cfg(not(windows))]
    {
        std::env::temp_dir()
            .join(format!(
                "friglet-tray-e2e-{}-{tag}.sock",
                std::process::id()
            ))
            .to_string_lossy()
            .into_owned()
    }
}

fn dummy_status() -> StatusInfo {
    StatusInfo {
        scanning: false,
        scanned_height: 123,
        tip_height: Some(456),
        scan_progress: 0.5,
        network: "regtest".to_string(),
        electrum_clients: 0,
        oracle_connected: false,
        last_error: None,
        sp_address: None,
        version: "test".to_string(),
    }
}

/// Serve GetStatus/Shutdown on `path`; sets `saw_shutdown` when a Shutdown
/// request arrives.
fn spawn_fake_daemon(path: String, saw_shutdown: Arc<AtomicBool>) {
    tokio::spawn(async move {
        #[cfg(unix)]
        let _ = std::fs::remove_file(&path);
        let listener = friglet_ipc::listen(&path).expect("bind fake daemon socket");
        loop {
            let Ok(mut conn) = friglet_ipc::accept(&listener).await else {
                break;
            };
            let saw_shutdown = saw_shutdown.clone();
            tokio::spawn(async move {
                while let Ok(Some(req)) = conn.next_request().await {
                    let resp = match req {
                        Request::GetStatus => Response::Status(dummy_status()),
                        Request::Shutdown => {
                            saw_shutdown.store(true, Ordering::SeqCst);
                            Response::Ok
                        }
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

#[tokio::test]
async fn attaches_when_daemon_already_running() {
    let path = test_socket_path("attach");
    spawn_fake_daemon(path.clone(), Arc::new(AtomicBool::new(false)));
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Locator must not be consulted when a daemon is reachable.
    let att = lifecycle::attach_or_spawn_with(&path, || {
        panic!("should not look for a binary when attach succeeds")
    })
    .await;
    assert!(matches!(att, Attachment::Attached), "got {att:?}");

    #[cfg(unix)]
    let _ = std::fs::remove_file(&path);
}

#[tokio::test]
async fn unreachable_when_no_daemon_and_no_binary() {
    let path = test_socket_path("nobin");
    let att = lifecycle::attach_or_spawn_with(&path, || None).await;
    match att {
        Attachment::Unreachable { reason } => {
            assert!(reason.contains("not found"), "unexpected reason: {reason}")
        }
        other => panic!("expected Unreachable, got {other:?}"),
    }
}

/// Spawn path: the "daemon binary" is an inert script; the socket is brought
/// up by an in-test listener shortly after, simulating daemon startup time.
#[cfg(unix)]
#[tokio::test]
async fn spawns_and_connects_when_socket_comes_up() {
    use std::os::unix::fs::PermissionsExt;

    let path = test_socket_path("spawn");
    let bin_dir = std::env::temp_dir().join(format!("friglet-tray-e2e-bin-{}", std::process::id()));
    std::fs::create_dir_all(&bin_dir).unwrap();
    let bin = bin_dir.join("fake-friglet.sh");
    std::fs::write(&bin, "#!/bin/sh\nsleep 30\n").unwrap();
    std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();

    let socket = path.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(500)).await;
        spawn_fake_daemon(socket, Arc::new(AtomicBool::new(false)));
    });

    let bin_for_locator: PathBuf = bin.clone();
    let att = lifecycle::attach_or_spawn_with(&path, move || Some(bin_for_locator)).await;
    match att {
        Attachment::Spawned(mut child) => {
            let _ = child.kill().await;
        }
        other => panic!("expected Spawned, got {other:?}"),
    }

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_dir_all(&bin_dir);
}

#[tokio::test]
async fn quit_shuts_daemon_down_only_when_spawned_by_tray() {
    let path = test_socket_path("quit");
    let saw_shutdown = Arc::new(AtomicBool::new(false));
    spawn_fake_daemon(path.clone(), saw_shutdown.clone());
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Attached daemon: quit must leave it alone.
    lifecycle::perform_quit(&path, false, None).await;
    assert!(!saw_shutdown.load(Ordering::SeqCst));

    // Tray-spawned daemon: quit must send Shutdown.
    lifecycle::perform_quit(&path, true, None).await;
    assert!(saw_shutdown.load(Ordering::SeqCst));

    #[cfg(unix)]
    let _ = std::fs::remove_file(&path);
}
