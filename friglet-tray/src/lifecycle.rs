//! Daemon lifecycle for the tray app: probe the control socket, attach to an
//! already-running daemon or spawn one, and apply the quit rule.
//!
//! Deliberately decoupled from tauri so the logic is testable with plain
//! tokio tests (see `tests/lifecycle_e2e.rs`).
//!
//! Policy is a single boolean, `spawned_by_tray` — no PID files:
//! - probe succeeds at startup → attach, `spawned_by_tray` comes from the
//!   daemon's own `GetStatus` answer (it self-reports whether *it* was
//!   launched with `FRIGLET_SPAWNED_BY_TRAY=1`), not assumed false — so
//!   ownership survives a tray crash/restart instead of being forgotten
//! - probe fails → spawn the `friglet` binary with that env var set,
//!   `spawned_by_tray = true`
//! - Quit → if `spawned_by_tray`, ask the daemon to shut down over the
//!   socket (fall back to killing the child if the socket is dead); if
//!   attached to a daemon that reports it was not tray-spawned, leave it
//!   running.

use std::collections::VecDeque;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use friglet_ipc::{Client, Request, Response, StatusInfo};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};

/// How many of the daemon's most recent stdout/stderr lines to keep around
/// for diagnostics if it exits unexpectedly right after spawning.
const RECENT_OUTPUT_LINES: usize = 20;

/// Timeout for a single connect + GetStatus probe.
pub const PROBE_TIMEOUT: Duration = Duration::from_millis(1500);
/// How often / how long to retry the socket after spawning the daemon.
const SPAWN_CONNECT_INTERVAL: Duration = Duration::from_millis(250);
const SPAWN_CONNECT_ATTEMPTS: u32 = 20;

const DAEMON_EXE: &str = if cfg!(windows) {
    "friglet.exe"
} else {
    "friglet"
};

/// Outcome of [`attach_or_spawn`].
#[derive(Debug)]
pub enum Attachment {
    /// A daemon was already listening on the control socket; carries its
    /// `GetStatus` answer so the caller can read `spawned_by_tray` from the
    /// daemon's own self-report instead of assuming it.
    Attached(StatusInfo),
    /// No daemon was reachable; we spawned one and it came up.
    Spawned(Child),
    /// No daemon was reachable and it is not configured yet: spawning would
    /// only fail with `missing required setting ...`, so first-run setup is
    /// needed instead (see `setup::is_configured`).
    SetupRequired,
    /// No daemon was reachable and we could not bring one up.
    Unreachable { reason: String },
}

/// The attach-vs-spawn decision, factored out for unit tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Attach,
    Spawn,
}

pub fn decide(probe_succeeded: bool) -> Action {
    if probe_succeeded {
        Action::Attach
    } else {
        Action::Spawn
    }
}

/// What Quit should do, given who started the daemon.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuitAction {
    /// Tray spawned the daemon → shut it down before exiting.
    ShutdownDaemon,
    /// Tray attached to an externally started daemon → leave it running.
    LeaveRunning,
}

pub fn quit_action(spawned_by_tray: bool) -> QuitAction {
    if spawned_by_tray {
        QuitAction::ShutdownDaemon
    } else {
        QuitAction::LeaveRunning
    }
}

/// Try to connect to `socket_path` and get a `GetStatus` answer within
/// `timeout`. `None` means the daemon is unreachable.
pub async fn probe(socket_path: &str, timeout: Duration) -> Option<StatusInfo> {
    let attempt = async {
        let mut client = Client::connect(socket_path).await.ok()?;
        match client.request(&Request::GetStatus).await.ok()? {
            Response::Status(info) => Some(info),
            _ => None,
        }
    };
    tokio::time::timeout(timeout, attempt).await.ok().flatten()
}

/// Locate the `friglet` daemon binary. Search order:
/// 1. `env_bin` (`FRIGLET_DAEMON_BIN`) — an explicit override always wins,
///    even if the path does not exist, so a misconfiguration surfaces as a
///    spawn error instead of silently using a different binary;
/// 2. `DAEMON_EXE` next to the tray executable (`exe_dir`);
/// 3. `DAEMON_EXE` in `path_var` (the `PATH` environment variable).
pub fn locate_daemon_binary(
    env_bin: Option<PathBuf>,
    exe_dir: Option<&Path>,
    path_var: Option<&std::ffi::OsStr>,
) -> Option<PathBuf> {
    if let Some(bin) = env_bin.filter(|p| !p.as_os_str().is_empty()) {
        return Some(bin);
    }
    if let Some(dir) = exe_dir {
        let candidate = dir.join(DAEMON_EXE);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    if let Some(paths) = path_var {
        for dir in std::env::split_paths(paths) {
            let candidate = dir.join(DAEMON_EXE);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

/// [`locate_daemon_binary`] fed from the real process environment.
pub fn locate_daemon_binary_from_env() -> Option<PathBuf> {
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(Path::to_path_buf));
    locate_daemon_binary(
        std::env::var_os("FRIGLET_DAEMON_BIN").map(PathBuf::from),
        exe_dir.as_deref(),
        std::env::var_os("PATH").as_deref(),
    )
}

/// Spawn `bin` and continuously drain its stdout/stderr in the background.
///
/// Draining (rather than `Stdio::null()`) matters for two reasons: it keeps
/// the daemon's own log lines visible (at debug level, prefixed
/// `friglet-daemon`), and — the important part — it prevents the daemon
/// from blocking on a full pipe buffer once it starts logging heavily during
/// a long scan. The last [`RECENT_OUTPUT_LINES`] lines are kept so a daemon
/// that exits immediately after spawning (bad config, missing key file,
/// stale/incompatible binary, ...) surfaces an actual reason instead of just
/// an opaque exit code.
fn spawn_daemon(bin: &Path) -> io::Result<(Child, Arc<StdMutex<VecDeque<String>>>)> {
    let mut cmd = Command::new(bin);
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(false);
    // Do not inherit the tray's RUST_LOG (often `trace` during debugging) —
    // that floods the pipe with h2/tonic TRACE noise. Prefer
    // FRIGLET_DAEMON_RUST_LOG when set; otherwise clear RUST_LOG so the
    // daemon falls back to its config `log_level` (info by default).
    if let Ok(level) = std::env::var("FRIGLET_DAEMON_RUST_LOG") {
        cmd.env("RUST_LOG", level);
    } else {
        cmd.env_remove("RUST_LOG");
    }
    // Own process group so terminal signals aimed at the tray don't take the
    // daemon down with it.
    #[cfg(unix)]
    cmd.process_group(0);
    // The daemon echoes this back in GetStatus so a *future* tray (after
    // this one crashes/restarts) can learn it was tray-spawned without a
    // PID file.
    cmd.env("FRIGLET_SPAWNED_BY_TRAY", "1");
    let mut child = cmd.spawn()?;

    let recent_output = Arc::new(StdMutex::new(VecDeque::with_capacity(RECENT_OUTPUT_LINES)));
    if let Some(stdout) = child.stdout.take() {
        drain_lines(stdout, recent_output.clone());
    }
    if let Some(stderr) = child.stderr.take() {
        drain_lines(stderr, recent_output.clone());
    }
    Ok((child, recent_output))
}

/// Strip ANSI CSI sequences (`ESC [ ... letter`) so piped daemon logs stay
/// readable when re-logged or stored for spawn-failure diagnostics.
fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            if chars.next() == Some('[') {
                for c2 in chars.by_ref() {
                    if c2.is_ascii_alphabetic() {
                        break;
                    }
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

fn drain_lines<R>(reader: R, recent_output: Arc<StdMutex<VecDeque<String>>>)
where
    R: tokio::io::AsyncRead + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        let mut lines = BufReader::new(reader).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            let stripped = strip_ansi(&line);
            tracing::debug!(target: "friglet-daemon", "{stripped}");
            let mut buf = recent_output.lock().unwrap();
            if buf.len() >= RECENT_OUTPUT_LINES {
                buf.pop_front();
            }
            buf.push_back(stripped);
        }
    });
}

/// Join the captured output into a single diagnostic string, empty if
/// nothing was captured before the daemon exited.
fn recent_output_tail(recent_output: &StdMutex<VecDeque<String>>) -> String {
    recent_output
        .lock()
        .unwrap()
        .iter()
        .cloned()
        .collect::<Vec<_>>()
        .join(" | ")
}

/// Attach to a running daemon, or spawn one and wait for its socket.
///
/// Uses the real environment to locate the binary; `attach_or_spawn_with`
/// takes the locator as a parameter for tests.
pub async fn attach_or_spawn(socket_path: &str) -> Attachment {
    attach_or_spawn_with(socket_path, locate_daemon_binary_from_env).await
}

pub async fn attach_or_spawn_with<F>(socket_path: &str, locate: F) -> Attachment
where
    F: FnOnce() -> Option<PathBuf>,
{
    attach_spawn_or_setup_with(socket_path, locate, || false).await
}

/// [`attach_or_spawn_with`] plus a first-run gate: when the daemon is
/// unreachable AND `needs_setup()` says it is not plausibly configured,
/// return [`Attachment::SetupRequired`] without any spawn attempt (a spawn
/// could only fail with `missing required setting ...`). The check runs
/// only after the probe fails, so an externally configured, reachable
/// daemon attaches exactly as before.
pub async fn attach_spawn_or_setup_with<F, C>(
    socket_path: &str,
    locate: F,
    needs_setup: C,
) -> Attachment
where
    F: FnOnce() -> Option<PathBuf>,
    C: FnOnce() -> bool,
{
    if let Some(status) = probe(socket_path, PROBE_TIMEOUT).await {
        return Attachment::Attached(status);
    }

    if needs_setup() {
        return Attachment::SetupRequired;
    }

    let Some(bin) = locate() else {
        return Attachment::Unreachable {
            reason: "friglet binary not found (set FRIGLET_DAEMON_BIN, place friglet next to \
                     the tray executable, or add it to PATH)"
                .to_string(),
        };
    };

    let (mut child, recent_output) = match spawn_daemon(&bin) {
        Ok(pair) => pair,
        Err(e) => {
            return Attachment::Unreachable {
                reason: format!("failed to spawn {}: {e}", bin.display()),
            };
        }
    };
    tracing::info!(bin = %bin.display(), pid = ?child.id(), "spawned friglet daemon");

    for _ in 0..SPAWN_CONNECT_ATTEMPTS {
        tokio::time::sleep(SPAWN_CONNECT_INTERVAL).await;
        // Spawned daemon died already (e.g. bad config)? Stop waiting.
        if let Ok(Some(status)) = child.try_wait() {
            let tail = recent_output_tail(&recent_output);
            let mut reason = if tail.is_empty() {
                format!("spawned daemon exited immediately ({status})")
            } else {
                format!("spawned daemon exited immediately ({status}): {tail}")
            };
            // A clap usage dump means the binary rejected our zero-arg
            // invocation — i.e. it's an outdated friglet that still requires
            // the `scan` subcommand and CLI flags.
            if tail.contains("Usage:") && tail.contains("<COMMAND>") {
                reason.push_str(&format!(
                    " — the daemon binary at {} is an outdated build that requires CLI \
                     arguments; rebuild it (`cargo build --release -p friglet`) or point \
                     FRIGLET_DAEMON_BIN at a current one",
                    bin.display()
                ));
            }
            return Attachment::Unreachable { reason };
        }
        if probe(socket_path, PROBE_TIMEOUT).await.is_some() {
            return Attachment::Spawned(child);
        }
    }

    // The socket never came up; kill the child so we don't leave an
    // untracked daemon behind.
    let _ = child.kill().await;
    let tail = recent_output_tail(&recent_output);
    let reason = if tail.is_empty() {
        format!("spawned daemon but its control socket never came up at {socket_path}")
    } else {
        format!("spawned daemon but its control socket never came up at {socket_path}: {tail}")
    };
    Attachment::Unreachable { reason }
}

/// Ask the daemon at `socket_path` to shut down. Returns `true` if the
/// daemon acknowledged the request.
pub async fn shutdown_via_socket(socket_path: &str, timeout: Duration) -> bool {
    let attempt = async {
        let mut client = Client::connect(socket_path).await.ok()?;
        match client.request(&Request::Shutdown).await.ok()? {
            Response::Ok => Some(()),
            _ => None,
        }
    };
    tokio::time::timeout(timeout, attempt)
        .await
        .ok()
        .flatten()
        .is_some()
}

/// Apply the quit rule: shut the daemon down only if the tray spawned it.
///
/// Prefers a graceful `Shutdown` over the socket; falls back to killing the
/// child process when the socket is dead but a child handle is still held.
pub async fn perform_quit(socket_path: &str, spawned_by_tray: bool, child: Option<Child>) {
    if quit_action(spawned_by_tray) == QuitAction::LeaveRunning {
        return;
    }
    let acked = shutdown_via_socket(socket_path, PROBE_TIMEOUT).await;
    if let Some(mut child) = child {
        if acked {
            // Give the daemon a moment to exit cleanly, then make sure.
            if tokio::time::timeout(Duration::from_secs(5), child.wait())
                .await
                .is_err()
            {
                let _ = child.kill().await;
            }
        } else {
            let _ = child.kill().await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn temp_dir(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("friglet-tray-test-{}-{tag}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn decide_attaches_when_probe_succeeds() {
        assert_eq!(decide(true), Action::Attach);
        assert_eq!(decide(false), Action::Spawn);
    }

    #[test]
    fn quit_rule_single_boolean() {
        assert_eq!(quit_action(true), QuitAction::ShutdownDaemon);
        assert_eq!(quit_action(false), QuitAction::LeaveRunning);
    }

    #[test]
    fn locate_env_override_wins_even_if_missing() {
        let dir = temp_dir("locate-env");
        fs::write(dir.join(DAEMON_EXE), b"").unwrap();
        let got = locate_daemon_binary(
            Some(PathBuf::from("/does/not/exist/friglet")),
            Some(&dir),
            None,
        );
        assert_eq!(got, Some(PathBuf::from("/does/not/exist/friglet")));
    }

    #[test]
    fn locate_prefers_exe_dir_over_path() {
        let exe_dir = temp_dir("locate-exedir");
        let path_dir = temp_dir("locate-pathdir");
        fs::write(exe_dir.join(DAEMON_EXE), b"").unwrap();
        fs::write(path_dir.join(DAEMON_EXE), b"").unwrap();
        let path_var = std::env::join_paths([&path_dir]).unwrap();
        let got = locate_daemon_binary(None, Some(&exe_dir), Some(&path_var));
        assert_eq!(got, Some(exe_dir.join(DAEMON_EXE)));
    }

    #[test]
    fn locate_falls_back_to_path_search() {
        let empty = temp_dir("locate-empty");
        let path_dir = temp_dir("locate-path");
        fs::write(path_dir.join(DAEMON_EXE), b"").unwrap();
        let path_var = std::env::join_paths([&empty, &path_dir]).unwrap();
        let got = locate_daemon_binary(None, Some(&empty), Some(&path_var));
        assert_eq!(got, Some(path_dir.join(DAEMON_EXE)));
    }

    #[test]
    fn locate_none_when_nothing_found() {
        let empty = temp_dir("locate-none");
        let path_var = std::env::join_paths([&empty]).unwrap();
        assert_eq!(
            locate_daemon_binary(None, Some(&empty), Some(&path_var)),
            None
        );
    }

    #[test]
    fn strip_ansi_removes_csi_sequences() {
        assert_eq!(strip_ansi("plain"), "plain");
        assert_eq!(strip_ansi("\x1b[32minfo\x1b[0m: hello"), "info: hello");
        assert_eq!(strip_ansi("\x1b[1;31mERROR\x1b[0m boom"), "ERROR boom");
        assert_eq!(strip_ansi("a\x1b[2Kb"), "ab");
    }
}
