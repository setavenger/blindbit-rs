//! Minimal fake friglet daemon for manual tray testing.
//!
//! Serves the `friglet-ipc` control protocol on the default socket path
//! (override with `FRIGLET_CONTROL_SOCKET`), answering `GetStatus` with a
//! canned snapshot, keeping a `GetConfig`/`SetConfig`/`SetScanKey`-editable
//! in-memory config (nothing is written to disk) and exiting on `Shutdown`.
//!
//! Usage: `cargo run -p friglet-tray --example fake-daemon`

use friglet_ipc::{DaemonConfig, Request, Response, StatusInfo};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

/// Rough imitation of the real daemon's SetConfig validation, so the tray's
/// error surfacing can be exercised without a real daemon.
fn check_config(cfg: &DaemonConfig) -> Result<(), String> {
    const NETWORKS: [&str; 5] = ["bitcoin", "signet", "testnet", "testnet4", "regtest"];
    if !NETWORKS.contains(&cfg.network.as_str()) {
        return Err(format!("invalid network `{}`", cfg.network));
    }
    if !cfg.oracle_url.starts_with("http://") && !cfg.oracle_url.starts_with("https://") {
        return Err(format!(
            "invalid oracle_url `{}`: must start with http:// or https://",
            cfg.oracle_url
        ));
    }
    if cfg.start_height == Some(0) {
        return Err("invalid start_height 0: must be at least 1".to_string());
    }
    Ok(())
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> std::io::Result<()> {
    let path = friglet_ipc::default_socket_path();
    #[cfg(unix)]
    let _ = std::fs::remove_file(&path);
    let listener = friglet_ipc::listen(&path)?;
    eprintln!("fake daemon listening on {path}");

    let scanning = Arc::new(AtomicBool::new(false));
    let config = Arc::new(Mutex::new(DaemonConfig {
        p2p_node_addr: Some("127.0.0.1:38333".to_string()),
        start_height: Some(890_000),
        network: "signet".to_string(),
        ..DaemonConfig::default()
    }));
    loop {
        let mut conn = friglet_ipc::accept(&listener).await?;
        let scanning = scanning.clone();
        let config = config.clone();
        tokio::spawn(async move {
            while let Ok(Some(req)) = conn.next_request().await {
                let resp = match req {
                    Request::GetStatus => Response::Status(StatusInfo {
                        scanning: scanning.load(Ordering::Relaxed),
                        scanned_height: 899_000,
                        tip_height: Some(900_000),
                        scan_progress: 0.42,
                        network: config.lock().unwrap().network.clone(),
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
                    Request::GetConfig => Response::Config(config.lock().unwrap().clone()),
                    Request::SetConfig(new_cfg) => match check_config(&new_cfg) {
                        Ok(()) => {
                            let mut cfg = config.lock().unwrap();
                            let bind_changed = new_cfg.http_addr != cfg.http_addr
                                || new_cfg.electrum_addr != cfg.electrum_addr;
                            *cfg = *new_cfg;
                            eprintln!("fake daemon config updated");
                            if bind_changed {
                                Response::OkWithNote(
                                    "changes to http_addr, electrum_addr are saved but only \
                                     take effect after a daemon restart"
                                        .to_string(),
                                )
                            } else {
                                Response::Ok
                            }
                        }
                        Err(e) => Response::Error(e),
                    },
                    Request::SetScanKey(key) => {
                        let key = key.trim();
                        if key.len() == 64 && key.bytes().all(|b| b.is_ascii_hexdigit()) {
                            eprintln!("fake daemon scan key updated");
                            Response::Ok
                        } else {
                            Response::Error(
                                "invalid scan key: must be a 32-byte hex string".to_string(),
                            )
                        }
                    }
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
