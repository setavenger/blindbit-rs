//! Control socket: serves `friglet-ipc` requests over a local socket
//! (Unix domain socket / Windows named pipe, newline-delimited JSON).

use std::io;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use blindbit_lib::scanner::{Scanner, WalletElectrumIndex};
use friglet_ipc::{DaemonConfig, Listener, Request, Response, StatusInfo};
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

use crate::supervisor::ScanSupervisor;

/// Everything the request handler needs from the daemon.
pub struct ControlCtx {
    pub supervisor: Arc<ScanSupervisor>,
    pub scanner: Arc<Mutex<Scanner>>,
    pub electrum_index: Arc<Mutex<WalletElectrumIndex>>,
    pub electrum_clients: Arc<AtomicU64>,
    pub config: DaemonConfig,
    pub network: String,
    pub state_file: PathBuf,
    pub shutdown: CancellationToken,
}

impl ControlCtx {
    pub async fn handle(&self, req: Request) -> Response {
        match req {
            Request::GetStatus => Response::Status(self.status().await),
            Request::Start => {
                if self.supervisor.start() {
                    tracing::info!("scan task started via control socket");
                }
                Response::Ok
            }
            Request::Stop => {
                if self.supervisor.stop().await {
                    tracing::info!("scan task stopped via control socket");
                    self.save_state().await;
                }
                Response::Ok
            }
            Request::GetConfig => Response::Config(self.config.clone()),
            Request::SetConfig(_) => Response::Error(
                "SetConfig is not supported yet; edit the config file and restart".to_string(),
            ),
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

    async fn status(&self) -> StatusInfo {
        let (tip_height, scan_progress, sp_address) = {
            let idx = self.electrum_index.lock().await;
            let tip = idx.tip.as_ref().map(|(h, _)| u64::from(*h));
            let addr = (!idx.sp_address.is_empty()).then(|| idx.sp_address.clone());
            (tip, idx.scan_progress, addr)
        };

        // While the scan task runs it holds the scanner mutex, so fall back
        // to the electrum index tip (which the scanner advances per scanned
        // block) when the lock is unavailable.
        let scanned_height = match self.scanner.try_lock() {
            Ok(s) => s.get_last_scanned_block_height(),
            Err(_) => tip_height.unwrap_or(0),
        };

        let scanning = self.supervisor.is_running();
        let last_error = self.supervisor.last_error();

        StatusInfo {
            scanning,
            scanned_height,
            tip_height,
            scan_progress,
            network: self.network.clone(),
            electrum_clients: self.electrum_clients.load(Ordering::Relaxed),
            oracle_connected: scanning && last_error.is_none(),
            last_error,
            sp_address,
            version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }

    pub async fn save_state(&self) {
        let scanner = self.scanner.lock().await;
        if let Err(e) = scanner.save_to_file(&self.state_file) {
            tracing::warn!(error = %e, "failed to save scanner state");
        } else {
            tracing::debug!("scanner state saved");
        }
        // The state JSON contains the scan secret (written by blindbit-lib);
        // keep it owner-only. Files created by the scan loop's own
        // checkpoints get tightened here and on the next startup.
        crate::config::tighten_state_file_perms(&self.state_file);
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
    use std::time::Duration;

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
}
