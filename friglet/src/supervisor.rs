//! Owns the background scan task and allows starting/stopping it at runtime.
//!
//! `watch_chain(&mut self)` holds the scanner's tokio mutex for its entire
//! run and is not cancellation-aware internally, so stopping works by
//! dropping the future: the spawned task `select!`s between the cancellation
//! token and the scan future, and cancelling drops the future along with the
//! mutex guard it owns, releasing the scanner lock. In-memory scan progress
//! is persisted by the scan loop itself (blindbit-lib checkpoints during
//! scanning); callers additionally save state after `stop()` returns.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

type TaskFuture = Pin<Box<dyn Future<Output = Result<(), String>> + Send>>;
type TaskFactory = Box<dyn Fn() -> TaskFuture + Send + Sync>;

pub struct ScanSupervisor {
    factory: TaskFactory,
    running: Mutex<Option<Running>>,
    last_error: Arc<Mutex<Option<String>>>,
}

struct Running {
    token: CancellationToken,
    handle: JoinHandle<()>,
}

impl ScanSupervisor {
    /// `factory` produces a fresh scan future for each `start()`. The future
    /// must tolerate being dropped at any await point (that is how it gets
    /// cancelled).
    pub fn new(factory: impl Fn() -> TaskFuture + Send + Sync + 'static) -> Self {
        Self {
            factory: Box::new(factory),
            running: Mutex::new(None),
            last_error: Arc::new(Mutex::new(None)),
        }
    }

    /// Start the scan task. Returns `false` (no-op) if it is already running.
    pub fn start(&self) -> bool {
        let mut slot = self.running.lock().unwrap();
        if slot.as_ref().is_some_and(|r| !r.handle.is_finished()) {
            return false;
        }

        *self.last_error.lock().unwrap() = None;
        let token = CancellationToken::new();
        let task_token = token.clone();
        let future = (self.factory)();
        let last_error = self.last_error.clone();
        let handle = tokio::spawn(async move {
            tokio::select! {
                _ = task_token.cancelled() => {
                    tracing::info!("scan task cancelled");
                }
                result = future => {
                    if let Err(e) = result {
                        tracing::error!(error = %e, "scan task terminated with error");
                        *last_error.lock().unwrap() = Some(e);
                    }
                }
            }
        });
        *slot = Some(Running { token, handle });
        true
    }

    /// Cancel the scan task and wait for it to finish. Returns `false`
    /// (no-op) if it was not running.
    pub async fn stop(&self) -> bool {
        let running = self.running.lock().unwrap().take();
        let Some(running) = running else {
            return false;
        };
        running.token.cancel();
        let _ = running.handle.await;
        true
    }

    pub fn is_running(&self) -> bool {
        self.running
            .lock()
            .unwrap()
            .as_ref()
            .is_some_and(|r| !r.handle.is_finished())
    }

    /// Error from the most recent scan task run, if it failed.
    pub fn last_error(&self) -> Option<String> {
        self.last_error.lock().unwrap().clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct ActiveGuard(Arc<AtomicUsize>);
    impl Drop for ActiveGuard {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::SeqCst);
        }
    }

    fn pending_task_supervisor() -> (ScanSupervisor, Arc<AtomicUsize>) {
        let active = Arc::new(AtomicUsize::new(0));
        let counter = active.clone();
        let supervisor = ScanSupervisor::new(move || {
            counter.fetch_add(1, Ordering::SeqCst);
            let guard = ActiveGuard(counter.clone());
            Box::pin(async move {
                let _guard = guard;
                std::future::pending::<()>().await;
                Ok(())
            })
        });
        (supervisor, active)
    }

    #[tokio::test]
    async fn start_stop_restart_without_leaking_task() {
        let (supervisor, active) = pending_task_supervisor();

        assert!(!supervisor.is_running());
        assert!(!supervisor.stop().await, "stop while stopped is a no-op");

        assert!(supervisor.start());
        assert!(supervisor.is_running());
        assert_eq!(active.load(Ordering::SeqCst), 1);
        assert!(!supervisor.start(), "start while running is a no-op");
        assert_eq!(active.load(Ordering::SeqCst), 1);

        assert!(supervisor.stop().await);
        assert!(!supervisor.is_running());
        assert_eq!(
            active.load(Ordering::SeqCst),
            0,
            "task future must be dropped"
        );

        assert!(supervisor.start());
        assert!(supervisor.is_running());
        assert_eq!(active.load(Ordering::SeqCst), 1);
        assert!(supervisor.stop().await);
        assert_eq!(active.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn failed_task_reports_last_error() {
        let supervisor =
            ScanSupervisor::new(|| Box::pin(async { Err("oracle unreachable".to_string()) }));
        supervisor.start();
        // Let the task run to completion.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(!supervisor.is_running());
        assert!(supervisor.stop().await);
        assert_eq!(
            supervisor.last_error(),
            Some("oracle unreachable".to_string())
        );
    }
}
