//! Minimal fake friglet daemon for manual tray testing.
//!
//! Serves the `friglet-ipc` control protocol on the default socket path
//! (override with `FRIGLET_CONTROL_SOCKET`), answering `GetStatus` with a
//! canned snapshot and exiting on `Shutdown`.
//!
//! Usage: `cargo run -p friglet-tray --example fake-daemon`

use friglet_ipc::{DaemonConfig, Request, Response, StatusInfo};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

#[tokio::main(flavor = "current_thread")]
async fn main() -> std::io::Result<()> {
    let path = friglet_ipc::default_socket_path();
    #[cfg(unix)]
    let _ = std::fs::remove_file(&path);
    let listener = friglet_ipc::listen(&path)?;
    eprintln!("fake daemon listening on {path}");

    let scanning = Arc::new(AtomicBool::new(false));
    loop {
        let mut conn = friglet_ipc::accept(&listener).await?;
        let scanning = scanning.clone();
        tokio::spawn(async move {
            while let Ok(Some(req)) = conn.next_request().await {
                let resp = match req {
                    Request::GetStatus => Response::Status(StatusInfo {
                        scanning: scanning.load(Ordering::Relaxed),
                        scanned_height: 899_000,
                        tip_height: Some(900_000),
                        scan_progress: 0.42,
                        network: "signet".to_string(),
                        electrum_clients: 1,
                        oracle_connected: scanning.load(Ordering::Relaxed),
                        last_error: None,
                        sp_address: Some("sp1qfake...".to_string()),
                        version: "fake-0.0.0".to_string(),
                    }),
                    Request::Start => {
                        scanning.store(true, Ordering::Relaxed);
                        Response::Ok
                    }
                    Request::Stop => {
                        scanning.store(false, Ordering::Relaxed);
                        Response::Ok
                    }
                    Request::GetConfig => Response::Config(DaemonConfig::default()),
                    Request::SetConfig(_) => Response::Error("not supported".to_string()),
                    Request::Shutdown => {
                        let _ = conn.respond(&Response::Ok).await;
                        eprintln!("fake daemon shutting down");
                        std::process::exit(0);
                    }
                };
                if conn.respond(&resp).await.is_err() {
                    break;
                }
            }
        });
    }
}
