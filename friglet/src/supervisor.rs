//! Owns the background scan task and allows starting/stopping it at runtime.
//!
//! Each run gets a fresh [`CancellationToken`], which the task factory hands
//! to the scan (`Scanner::watch_chain_until`). Cancelling it stops the scan
//! at its next safe point: between blocks, or wherever it waits (the poll
//! interval, a retry wait, an oracle request, a P2P block download), all of
//! which give way to the token at once. A stop therefore takes effect within
//! milliseconds, even in the middle of a block download from a stalled
//! node, and never leaves a block half applied: the scanned height stays
//! below a block whose download was cut short, and the next start resumes
//! there. The task then ends, releasing the scanner lock it holds; callers
//! save the state once it has ended.
//!
//! As a safety net, a task still running [`CANCEL_GRACE`] after its token
//! was cancelled is dropped at its next `.await` (that drops the scanner
//! lock too). Until the task has really ended it is reported as
//! [`ScanState::Stopping`], never as stopped: the status must not claim the
//! scan has ended (and offer Start) while it still runs.

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use friglet_ipc::ScanState;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

/// How long a cancelled scan task may take to stop by itself before it is
/// dropped. The scan stops within milliseconds; this only bounds a task
/// stuck in a step that does not watch the token.
pub const CANCEL_GRACE: Duration = Duration::from_secs(2);

type TaskFuture = Pin<Box<dyn Future<Output = Result<(), String>> + Send>>;
type TaskFactory = Box<dyn Fn(CancellationToken) -> TaskFuture + Send + Sync>;

pub struct ScanSupervisor {
    factory: TaskFactory,
    running: Mutex<Option<Running>>,
    last_error: Arc<Mutex<Option<String>>>,
    /// Scanning was stopped on request. Shared with `main` so the pause
    /// survives an in-process restart (a settings change); cleared by
    /// [`ScanSupervisor::start`].
    paused: Arc<AtomicBool>,
    /// See [`CANCEL_GRACE`].
    grace: Duration,
}

struct Running {
    token: CancellationToken,
    handle: JoinHandle<()>,
    /// Becomes `true` when the task has ended (the sender is dropped too if
    /// the task panicked).
    done: watch::Receiver<bool>,
}

impl Running {
    /// The task has not ended. `done` is set as its last step, just before
    /// the task finishes, so checking it too means a caller woken by
    /// [`ScanSupervisor::wait_stopped`] never still sees the task alive.
    fn alive(&self) -> bool {
        !self.handle.is_finished() && !*self.done.borrow()
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
    /// `factory` produces a fresh scan future for each `start()`, given the
    /// token that stops it: once the token is cancelled the future should
    /// return at its next safe point. It must also tolerate being dropped
    /// at any await point (the fallback after [`CANCEL_GRACE`]). `paused`
    /// carries a requested pause across in-process restarts.
    pub fn new(
        factory: impl Fn(CancellationToken) -> TaskFuture + Send + Sync + 'static,
        paused: Arc<AtomicBool>,
    ) -> Self {
        Self {
            factory: Box::new(factory),
            running: Mutex::new(None),
            last_error: Arc::new(Mutex::new(None)),
            paused,
            grace: CANCEL_GRACE,
        }
    }

    #[cfg(test)]
    fn with_grace(mut self, grace: Duration) -> Self {
        self.grace = grace;
        self
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
        let mut future = (self.factory)(token.clone());
        let grace = self.grace;
        let last_error = self.last_error.clone();
        let (done_tx, done) = watch::channel(false);
        let handle = tokio::spawn(async move {
            let overdue = async {
                task_token.cancelled().await;
                tokio::time::sleep(grace).await;
            };
            let result = tokio::select! {
                biased;
                result = &mut future => Some(result),
                () = overdue => None,
            };
            // Release whatever the task holds (the scanner lock) before
            // reporting it ended.
            drop(future);
            let stopping = task_token.is_cancelled();
            match result {
                Some(Ok(())) if stopping => tracing::info!("scan task stopped"),
                Some(Ok(())) => tracing::info!("scan task ended"),
                // Most likely a consequence of the stop; not a scan failure.
                Some(Err(e)) if stopping => {
                    tracing::warn!(error = %e, "scan task ended with an error while stopping");
                }
                Some(Err(e)) => {
                    tracing::error!(error = %e, "scan task terminated with error");
                    *last_error.lock().unwrap() = Some(e);
                }
                None => tracing::warn!(
                    grace_ms = grace.as_millis() as u64,
                    "scan task did not stop by itself after it was cancelled; dropped it"
                ),
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
    /// `false` when no task was running. The task ends at its next safe
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
    use std::time::Instant;

    struct ActiveGuard(Arc<AtomicUsize>);
    impl Drop for ActiveGuard {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::SeqCst);
        }
    }

    /// Tasks that run until their token is cancelled, counting how many are
    /// alive.
    fn cooperative_task_supervisor() -> (ScanSupervisor, Arc<AtomicUsize>) {
        let active = Arc::new(AtomicUsize::new(0));
        let counter = active.clone();
        let supervisor = ScanSupervisor::new(
            move |token| {
                counter.fetch_add(1, Ordering::SeqCst);
                let guard = ActiveGuard(counter.clone());
                Box::pin(async move {
                    let _guard = guard;
                    token.cancelled().await;
                    Ok(())
                })
            },
            Arc::default(),
        );
        (supervisor, active)
    }

    #[tokio::test]
    async fn start_stop_restart_without_leaking_task() {
        let (supervisor, active) = cooperative_task_supervisor();

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
            |_| Box::pin(async { Err("oracle unreachable".to_string()) }),
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

    /// A step that blocks a worker thread cannot be interrupted: until the
    /// task really ends the state is Stopping (never Paused), Start is
    /// refused, and the task makes no further progress once it returns.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn stop_during_a_blocking_step_reports_stopping_until_it_returns() {
        let blocks = Arc::new(AtomicUsize::new(0));
        let counter = blocks.clone();
        let supervisor = ScanSupervisor::new(
            move |token| {
                let counter = counter.clone();
                Box::pin(async move {
                    while !token.is_cancelled() {
                        std::thread::sleep(Duration::from_millis(800));
                        counter.fetch_add(1, Ordering::SeqCst);
                        tokio::task::yield_now().await;
                    }
                    Ok(())
                })
            },
            Arc::default(),
        );
        supervisor.start();
        tokio::time::sleep(Duration::from_millis(100)).await; // inside the step

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
        assert_eq!(after_stop, 1, "only the step in flight completed");
        tokio::time::sleep(Duration::from_millis(1000)).await;
        assert_eq!(
            blocks.load(Ordering::SeqCst),
            after_stop,
            "nothing is scanned while paused"
        );
        assert_eq!(supervisor.start(), StartOutcome::Started);
        supervisor.cancel();
    }

    /// A task that never looks at its token is dropped once the grace
    /// period is over.
    #[tokio::test]
    async fn a_task_that_ignores_the_token_is_dropped_after_the_grace_period() {
        let active = Arc::new(AtomicUsize::new(0));
        let counter = active.clone();
        let supervisor = ScanSupervisor::new(
            move |_| {
                counter.fetch_add(1, Ordering::SeqCst);
                let guard = ActiveGuard(counter.clone());
                Box::pin(async move {
                    let _guard = guard;
                    std::future::pending::<()>().await;
                    Ok(())
                })
            },
            Arc::default(),
        )
        .with_grace(Duration::from_millis(300));
        supervisor.start();
        let began = Instant::now();
        assert!(supervisor.request_stop());
        assert!(
            !supervisor
                .wait_stopped(Some(Duration::from_millis(150)))
                .await
        );
        assert_eq!(supervisor.state(), ScanState::Stopping);
        assert!(supervisor.wait_stopped(Some(Duration::from_secs(2))).await);
        assert!(began.elapsed() >= Duration::from_millis(300));
        assert_eq!(active.load(Ordering::SeqCst), 0, "dropped");
        assert_eq!(supervisor.state(), ScanState::Paused);
    }

    /// An error a task returns because it was stopped is not a scan
    /// failure.
    #[tokio::test]
    async fn an_error_while_stopping_is_not_recorded() {
        let supervisor = ScanSupervisor::new(
            |token| {
                Box::pin(async move {
                    token.cancelled().await;
                    Err("connection reset".to_string())
                })
            },
            Arc::default(),
        );
        supervisor.start();
        assert!(supervisor.cancel());
        assert!(supervisor.wait_stopped(Some(Duration::from_secs(1))).await);
        assert_eq!(supervisor.last_error(), None);
        assert_eq!(supervisor.state(), ScanState::Paused);
    }

    #[tokio::test]
    async fn cancel_for_shutdown_does_not_record_a_pause() {
        let paused = Arc::new(AtomicBool::new(false));
        let supervisor = ScanSupervisor::new(
            |token| {
                Box::pin(async move {
                    token.cancelled().await;
                    Ok(())
                })
            },
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
