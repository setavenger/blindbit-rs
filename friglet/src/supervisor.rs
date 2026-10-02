//! Owns the background scan task and allows starting/stopping it at runtime.
//!
//! `watch_chain(&mut self)` holds the scanner's tokio mutex for its entire
//! run and is not cancellation-aware internally, so stopping works by
//! dropping the future: the spawned task `select!`s between the cancellation
//! token and the scan future, and cancelling drops the future along with the
//! mutex guard it owns, releasing the scanner lock. In-memory scan progress
//! is persisted by the scan loop itself (blindbit-lib checkpoints during
//! scanning); callers additionally save state once the task has ended.
//!
//! A dropped future only stops at its next `.await`. blindbit-lib downloads
//! matching blocks from the P2P node with blocking socket I/O inside the scan
//! future (up to 90 s per attempt), so a stop requested during a download
//! takes effect only when the download returns. Until then the task is
//! reported as [`ScanState::Stopping`], never as stopped: the status must not
//! claim the scan has ended (and offer Start) while it still runs.

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use friglet_ipc::ScanState;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

type TaskFuture = Pin<Box<dyn Future<Output = Result<(), String>> + Send>>;
type TaskFactory = Box<dyn Fn() -> TaskFuture + Send + Sync>;

pub struct ScanSupervisor {
    factory: TaskFactory,
    running: Mutex<Option<Running>>,
    last_error: Arc<Mutex<Option<String>>>,
    /// Scanning was stopped on request. Shared with `main` so the pause
    /// survives an in-process restart (a settings change); cleared by
    /// [`ScanSupervisor::start`].
    paused: Arc<AtomicBool>,
}

struct Running {
    token: CancellationToken,
    handle: JoinHandle<()>,
    /// Becomes `true` when the task has ended (the sender is dropped too if
    /// the task panicked).
    done: watch::Receiver<bool>,
}

impl Running {
    fn alive(&self) -> bool {
        !self.handle.is_finished()
    }
}

/// Result of [`ScanSupervisor::start`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartOutcome {
    Started,
    AlreadyRunning,
    /// A stop is still in progress; the old task has not ended yet.
    StillStopping,
}

impl ScanSupervisor {
    /// `factory` produces a fresh scan future for each `start()`. The future
    /// must tolerate being dropped at any await point (that is how it gets
    /// cancelled). `paused` carries a requested pause across in-process
    /// restarts.
    pub fn new(
        factory: impl Fn() -> TaskFuture + Send + Sync + 'static,
        paused: Arc<AtomicBool>,
    ) -> Self {
        Self {
            factory: Box::new(factory),
            running: Mutex::new(None),
            last_error: Arc::new(Mutex::new(None)),
            paused,
        }
    }

    /// Start the scan task (and end a pause).
    pub fn start(&self) -> StartOutcome {
        let mut slot = self.running.lock().unwrap();
        if let Some(running) = slot.as_ref().filter(|r| r.alive()) {
            return if running.token.is_cancelled() {
                StartOutcome::StillStopping
            } else {
                StartOutcome::AlreadyRunning
            };
        }

        self.paused.store(false, Ordering::SeqCst);
        *self.last_error.lock().unwrap() = None;
        let token = CancellationToken::new();
        let task_token = token.clone();
        let future = (self.factory)();
        let last_error = self.last_error.clone();
        let (done_tx, done) = watch::channel(false);
        let handle = tokio::spawn(async move {
            tokio::select! {
                // Check the token first on every wake-up: unbiased, the scan
                // future may be polled first and run on into its next
                // blocking step although a stop is pending.
                biased;
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
            let _ = done_tx.send(true);
        });
        *slot = Some(Running {
            token,
            handle,
            done,
        });
        StartOutcome::Started
    }

    /// Pause scanning: remember the pause and cancel the task. Returns
    /// `false` when no task was running. The task ends at its next await
    /// point; see [`ScanSupervisor::wait_stopped`].
    pub fn request_stop(&self) -> bool {
        self.paused.store(true, Ordering::SeqCst);
        self.cancel()
    }

    /// Cancel the task without recording a pause (daemon shutdown/restart).
    /// Returns `false` when no task was running.
    pub fn cancel(&self) -> bool {
        match self.running.lock().unwrap().as_ref().filter(|r| r.alive()) {
            Some(running) => {
                running.token.cancel();
                true
            }
            None => false,
        }
    }

    /// Wait until the task has ended, at most `timeout` (`None`: no limit).
    /// Returns whether no task is alive anymore.
    pub async fn wait_stopped(&self, timeout: Option<Duration>) -> bool {
        let done = match self.running.lock().unwrap().as_ref() {
            Some(running) => running.done.clone(),
            None => return true,
        };
        let wait = async move {
            let mut done = done;
            // An error means the sender is gone: the task ended (panicked).
            let _ = done.wait_for(|ended| *ended).await;
        };
        match timeout {
            Some(limit) => tokio::time::timeout(limit, wait).await.is_ok(),
            None => {
                wait.await;
                true
            }
        }
    }

    /// Cancel the task and wait for it to end (no time limit). Returns
    /// `false` (no-op) if it was not running.
    #[cfg(test)]
    pub async fn stop(&self) -> bool {
        if !self.request_stop() {
            return false;
        }
        self.wait_stopped(None).await;
        true
    }

    /// Whether the scan task is alive: running, or stopping but not ended.
    pub fn is_running(&self) -> bool {
        self.running
            .lock()
            .unwrap()
            .as_ref()
            .is_some_and(Running::alive)
    }

    pub fn is_paused(&self) -> bool {
        self.paused.load(Ordering::SeqCst)
    }

    pub fn state(&self) -> ScanState {
        if let Some(running) = self.running.lock().unwrap().as_ref().filter(|r| r.alive()) {
            return if running.token.is_cancelled() {
                ScanState::Stopping
            } else {
                ScanState::Running
            };
        }
        if !self.is_paused() && self.last_error().is_some() {
            ScanState::Failed
        } else {
            ScanState::Paused
        }
    }

    /// Error from the most recent scan task run, if it failed.
    pub fn last_error(&self) -> Option<String> {
        self.last_error.lock().unwrap().clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    struct ActiveGuard(Arc<AtomicUsize>);
    impl Drop for ActiveGuard {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::SeqCst);
        }
    }

    fn pending_task_supervisor() -> (ScanSupervisor, Arc<AtomicUsize>) {
        let active = Arc::new(AtomicUsize::new(0));
        let counter = active.clone();
        let supervisor = ScanSupervisor::new(
            move || {
                counter.fetch_add(1, Ordering::SeqCst);
                let guard = ActiveGuard(counter.clone());
                Box::pin(async move {
                    let _guard = guard;
                    std::future::pending::<()>().await;
                    Ok(())
                })
            },
            Arc::default(),
        );
        (supervisor, active)
    }

    #[tokio::test]
    async fn start_stop_restart_without_leaking_task() {
        let (supervisor, active) = pending_task_supervisor();

        assert!(!supervisor.is_running());
        assert!(!supervisor.stop().await, "stop while stopped is a no-op");

        assert_eq!(supervisor.start(), StartOutcome::Started);
        assert!(supervisor.is_running());
        assert_eq!(supervisor.state(), ScanState::Running);
        assert_eq!(active.load(Ordering::SeqCst), 1);
        assert_eq!(
            supervisor.start(),
            StartOutcome::AlreadyRunning,
            "start while running is a no-op"
        );
        assert_eq!(active.load(Ordering::SeqCst), 1);

        assert!(supervisor.stop().await);
        assert!(!supervisor.is_running());
        assert_eq!(supervisor.state(), ScanState::Paused);
        assert_eq!(
            active.load(Ordering::SeqCst),
            0,
            "task future must be dropped"
        );

        assert_eq!(supervisor.start(), StartOutcome::Started);
        assert!(supervisor.is_running());
        assert!(!supervisor.is_paused(), "start ends the pause");
        assert_eq!(active.load(Ordering::SeqCst), 1);
        assert!(supervisor.stop().await);
        assert_eq!(active.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn failed_task_reports_last_error() {
        let supervisor = ScanSupervisor::new(
            || Box::pin(async { Err("oracle unreachable".to_string()) }),
            Arc::default(),
        );
        supervisor.start();
        assert!(supervisor.wait_stopped(Some(Duration::from_secs(5))).await);
        assert!(!supervisor.is_running());
        assert_eq!(supervisor.state(), ScanState::Failed);
        assert_eq!(
            supervisor.last_error(),
            Some("oracle unreachable".to_string())
        );
    }

    /// blindbit-lib downloads blocks from the P2P node with blocking I/O
    /// inside the scan future, so cancellation waits for the download.
    /// Modelled with a blocking sleep: until the task really ends, the state
    /// is Stopping (never Paused), Start is refused, and the task makes no
    /// further progress once it reaches an await.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn stop_during_a_blocking_download_reports_stopping_until_it_returns() {
        let blocks = Arc::new(AtomicUsize::new(0));
        let counter = blocks.clone();
        let supervisor = ScanSupervisor::new(
            move || {
                let counter = counter.clone();
                Box::pin(async move {
                    loop {
                        std::thread::sleep(Duration::from_millis(800));
                        counter.fetch_add(1, Ordering::SeqCst);
                        tokio::task::yield_now().await;
                    }
                })
            },
            Arc::default(),
        );
        supervisor.start();
        tokio::time::sleep(Duration::from_millis(100)).await; // inside the "download"

        assert!(supervisor.request_stop());
        assert!(supervisor.is_paused());
        assert!(
            !supervisor
                .wait_stopped(Some(Duration::from_millis(200)))
                .await,
            "the blocking call has not returned yet"
        );
        assert_eq!(supervisor.state(), ScanState::Stopping);
        assert!(supervisor.is_running(), "the task is still alive");
        assert_eq!(supervisor.start(), StartOutcome::StillStopping);

        assert!(supervisor.wait_stopped(Some(Duration::from_secs(5))).await);
        assert_eq!(supervisor.state(), ScanState::Paused);
        let after_stop = blocks.load(Ordering::SeqCst);
        assert_eq!(after_stop, 1, "only the download in flight completed");
        tokio::time::sleep(Duration::from_millis(1000)).await;
        assert_eq!(
            blocks.load(Ordering::SeqCst),
            after_stop,
            "nothing is scanned while paused"
        );
        assert_eq!(supervisor.start(), StartOutcome::Started);
        supervisor.cancel();
    }

    #[tokio::test]
    async fn cancel_for_shutdown_does_not_record_a_pause() {
        let paused = Arc::new(AtomicBool::new(false));
        let supervisor = ScanSupervisor::new(
            || Box::pin(std::future::pending::<Result<(), String>>()),
            paused.clone(),
        );
        supervisor.start();
        assert!(supervisor.cancel());
        assert!(supervisor.wait_stopped(Some(Duration::from_secs(5))).await);
        assert!(!paused.load(Ordering::SeqCst));

        // A pause is shared with the owner so it outlives this supervisor.
        supervisor.start();
        assert!(supervisor.request_stop());
        assert!(paused.load(Ordering::SeqCst));
    }
}
