//! What the tray shows, derived from the daemon's status and the tray's own
//! lifecycle state: pure functions (time passed in) so the wording and the
//! waiting-versus-error decisions are unit-testable.
//!
//! Transient conditions — the oracle has not indexed the newest block yet, a
//! short oracle or daemon reconnect — are shown as a neutral "waiting" state.
//! They become errors only when they last longer than a grace period
//! ([`STALL_GRACE_SECS`], [`UNREACHABLE_GRACE_SECS`]). Errors are kept in an
//! [`ErrorBook`]: active ones stay on screen with the time they began until
//! they are resolved, and the most recent ones stay in a list afterwards.

use std::collections::VecDeque;

use friglet_ipc::{ScanState, StatusInfo};
use serde::Serialize;

/// A scan stall or an unreachable oracle is "waiting" this long, then an
/// error.
pub const STALL_GRACE_SECS: u64 = 120;
/// The daemon not answering is "reconnecting" this long, then an error (a
/// settings restart or a slow status answer is not an outage).
pub const UNREACHABLE_GRACE_SECS: u64 = 10;
/// Entries kept in the recent-errors list.
pub const RECENT_ERRORS: usize = 20;

/// Colour of a state pill.
#[derive(Serialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Tone {
    Good,
    Neutral,
    Bad,
}

/// The scan, as shown in the Status tab and the tray menu.
#[derive(Serialize, Debug, Clone, PartialEq)]
pub struct ScanView {
    /// `scanning` | `synced` | `waiting` | `stopping` | `paused` | `error` | `unknown`
    pub state: &'static str,
    pub label: String,
    pub tone: Tone,
    pub detail: Option<String>,
    /// Unix seconds the current waiting / error condition began.
    pub since_unix: Option<u64>,
    /// The full error, for the error list and the log (state `error`).
    pub problem: Option<String>,
    pub can_start: bool,
    pub can_stop: bool,
}

/// One-line, user-facing reading of a stall reason from blindbit-lib.
fn stall_summary(height: u64, reason: &str) -> String {
    let lower = reason.to_ascii_lowercase();
    if lower.contains("not indexed") {
        format!("The oracle has not indexed block {height} yet.")
    } else if lower.contains("cannot reach the oracle")
        || (lower.contains("oracle") && lower.contains("unavailable"))
    {
        "Reconnecting to the oracle.".to_string()
    } else if lower.contains("p2p") || lower.contains("peer") || lower.contains("block fetch") {
        format!("Waiting for block {height} from the P2P node.")
    } else {
        format!("Block {height} could not be scanned yet: {reason}")
    }
}

/// The scan's state. `status` is the last snapshot; `reachable` whether the
/// latest poll got it.
pub fn scan_view(status: Option<&StatusInfo>, reachable: bool, now_unix: u64) -> ScanView {
    let Some(status) = status.filter(|_| reachable) else {
        return ScanView {
            state: "unknown",
            label: "–".to_string(),
            tone: Tone::Neutral,
            detail: None,
            since_unix: None,
            problem: None,
            can_start: false,
            can_stop: false,
        };
    };
    let state = status.scan_state.unwrap_or(if status.scanning {
        ScanState::Running
    } else {
        ScanState::Paused
    });
    let view = |state, label: &str, tone, detail: Option<String>, since| ScanView {
        state,
        label: label.to_string(),
        tone,
        detail,
        since_unix: since,
        problem: None,
        can_start: false,
        can_stop: false,
    };
    let mut out = match state {
        ScanState::Stopping => view(
            "stopping",
            "stopping…",
            Tone::Neutral,
            Some(
                "Finishing the current step (such as a block download from the P2P node); \
                 scanning pauses when it returns."
                    .to_string(),
            ),
            None,
        ),
        ScanState::Paused => view(
            "paused",
            "paused",
            Tone::Neutral,
            Some(
                "Stopped on request. Nothing is scanned until you press Start scanning."
                    .to_string(),
            ),
            None,
        ),
        ScanState::Failed => {
            let problem = format!(
                "The scan task ended: {}",
                status.last_error.as_deref().unwrap_or("unknown error")
            );
            ScanView {
                problem: Some(problem.clone()),
                ..view("error", "failed", Tone::Bad, Some(problem), None)
            }
        }
        ScanState::Running => running_view(status, now_unix),
    };
    out.can_start = matches!(state, ScanState::Paused | ScanState::Failed);
    out.can_stop = state == ScanState::Running;
    out
}

fn running_view(status: &StatusInfo, now_unix: u64) -> ScanView {
    let base = |state, label: &str, tone, detail: String, since| ScanView {
        state,
        label: label.to_string(),
        tone,
        detail: Some(detail),
        since_unix: since,
        problem: None,
        can_start: false,
        can_stop: false,
    };
    if let Some(stall) = &status.scan_health.stall {
        let age = now_unix.saturating_sub(stall.since_unix);
        let summary = stall_summary(stall.height, &stall.reason);
        return if age < STALL_GRACE_SECS {
            base(
                "waiting",
                "waiting",
                Tone::Neutral,
                format!("{summary} Retrying automatically."),
                Some(stall.since_unix),
            )
        } else {
            ScanView {
                problem: Some(format!(
                    "Scan stuck at block {}: {}",
                    stall.height, stall.reason
                )),
                ..base(
                    "error",
                    "stuck",
                    Tone::Bad,
                    format!("{summary} Still retrying; details above."),
                    Some(stall.since_unix),
                )
            }
        };
    }
    if let (Some(error), Some(since)) = (&status.oracle_error, status.oracle_down_since_unix) {
        let age = now_unix.saturating_sub(since);
        return if age < STALL_GRACE_SECS {
            base(
                "waiting",
                "waiting",
                Tone::Neutral,
                "Reconnecting to the oracle. Retrying automatically.".to_string(),
                Some(since),
            )
        } else {
            ScanView {
                problem: Some(format!("Cannot reach the oracle: {error}")),
                ..base(
                    "error",
                    "oracle unreachable",
                    Tone::Bad,
                    "Cannot reach the oracle. Still retrying; details above.".to_string(),
                    Some(since),
                )
            }
        };
    }
    match status.tip_height {
        Some(tip) if status.scanned_height < tip => base(
            "scanning",
            "scanning",
            Tone::Good,
            format!("Catching up: {} blocks to go.", tip - status.scanned_height),
            None,
        ),
        _ => base(
            "synced",
            "up to date",
            Tone::Good,
            "Watching for new blocks.".to_string(),
            None,
        ),
    }
}

/// Who started the daemon the tray is talking to.
#[derive(Serialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Ownership {
    /// This tray spawned it and holds its process handle.
    ThisTray,
    /// A tray spawned it in an earlier session (it says so in GetStatus).
    EarlierTray,
    /// Started outside any tray: a terminal, a service, an autostart entry.
    External,
}

/// Why the daemon is not running although the tray could start it.
#[derive(Debug, Clone, PartialEq)]
pub struct Stopped {
    pub at_unix: u64,
    pub by_user: bool,
    pub detail: String,
    /// The process that was stopped: while it still answers (it is shutting
    /// down) the stop is not over.
    pub pid: Option<u32>,
}

/// Inputs for [`daemon_view`] (the tray's lifecycle state).
#[derive(Debug, Clone, Default)]
pub struct DaemonFacts {
    pub reachable: bool,
    /// Seconds since the daemon last answered (while unreachable).
    pub unreachable_for_secs: Option<u64>,
    pub setup_needed: bool,
    pub starting: bool,
    pub stopping: bool,
    pub stopped: Option<Stopped>,
    /// Seconds until the supervisor's next restart attempt.
    pub restart_in_secs: Option<u64>,
    pub ownership: Option<Ownership>,
    pub pid: Option<u32>,
    /// What Quit does to this daemon.
    pub quit_stops_daemon: bool,
}

/// The daemon, as shown in the header pill, the daemon card and the menu.
#[derive(Serialize, Debug, Clone, PartialEq)]
pub struct DaemonView {
    /// `running` | `starting` | `stopping` | `stopped` | `reconnecting` |
    /// `unreachable` | `restarting` | `setup`
    pub state: &'static str,
    pub label: String,
    pub tone: Tone,
    pub ownership: Option<Ownership>,
    /// Who started it, and what Quit does.
    pub detail: String,
    /// Unix seconds of the stop, while stopped (the window shows it in
    /// local time).
    pub since_unix: Option<u64>,
    pub pid: Option<u32>,
    pub can_start: bool,
    pub can_stop: bool,
}

pub fn daemon_view(f: &DaemonFacts) -> DaemonView {
    let quit = if f.quit_stops_daemon {
        "Quit stops it."
    } else {
        "Quit leaves it running."
    };
    let owner = match f.ownership {
        Some(Ownership::ThisTray) => "Started by this tray",
        Some(Ownership::EarlierTray) => "Started by an earlier tray session",
        Some(Ownership::External) => {
            "Started outside the tray (terminal, service or autostart); attached"
        }
        None => "",
    };
    let pid = f.pid.map(|p| format!(" (PID {p})")).unwrap_or_default();
    let v = |state, label: &str, tone, detail: String, can_start, can_stop| DaemonView {
        state,
        label: label.to_string(),
        tone,
        ownership: f.ownership,
        detail,
        since_unix: f.stopped.as_ref().map(|s| s.at_unix),
        pid: f.pid,
        can_start,
        can_stop,
    };
    if f.stopping {
        return v(
            "stopping",
            "stopping…",
            Tone::Neutral,
            "Stopping the daemon.".into(),
            false,
            false,
        );
    }
    if f.starting {
        return v(
            "starting",
            "starting…",
            Tone::Neutral,
            "Starting the daemon and waiting for it to answer.".into(),
            false,
            false,
        );
    }
    if f.reachable {
        let label = if f.ownership == Some(Ownership::External) {
            "running (attached)"
        } else {
            "running"
        };
        return v(
            "running",
            label,
            Tone::Good,
            format!("{owner}{pid}. {quit}"),
            false,
            true,
        );
    }
    if f.setup_needed {
        return v(
            "setup",
            "setup required",
            Tone::Neutral,
            "Finish the setup in the Settings tab to start the daemon.".into(),
            false,
            false,
        );
    }
    if let Some(stopped) = &f.stopped {
        let who = if stopped.by_user {
            "Stopped by you."
        } else {
            "Stopped."
        };
        let detail = [
            who,
            stopped.detail.as_str(),
            "Start daemon starts it again.",
        ]
        .into_iter()
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
        return v("stopped", "stopped", Tone::Neutral, detail, true, false);
    }
    if let Some(secs) = f.restart_in_secs {
        return v(
            "restarting",
            "crashed — restarting",
            Tone::Bad,
            format!("Restarting automatically in {secs}s. Stop daemon ends the restart attempts."),
            true,
            true,
        );
    }
    match f.unreachable_for_secs {
        Some(secs) if secs < UNREACHABLE_GRACE_SECS => v(
            "reconnecting",
            "reconnecting…",
            Tone::Neutral,
            "The daemon did not answer the last status request; retrying.".into(),
            false,
            false,
        ),
        _ => v(
            "unreachable",
            "not running",
            Tone::Bad,
            "No daemon answers on the control socket.".into(),
            true,
            false,
        ),
    }
}

/// One error the window shows.
#[derive(Serialize, Debug, Clone, PartialEq)]
pub struct ErrorEntry {
    /// Stable identity of a condition (`stall`, `oracle`, ...) or an event.
    pub key: String,
    pub message: String,
    /// Unix seconds it began / was first seen.
    pub since_unix: u64,
    /// Unix seconds it was last seen.
    pub last_unix: u64,
    /// Times an event repeated (1 for a single occurrence).
    pub count: u32,
    /// Still going on (conditions only; events are never active).
    pub active: bool,
    pub resolved_unix: Option<u64>,
}

/// An error condition that holds right now.
#[derive(Debug, Clone, PartialEq)]
pub struct Condition {
    pub key: String,
    pub message: String,
    pub since_unix: u64,
}

/// Active error conditions plus recent errors, newest first.
#[derive(Debug, Default)]
pub struct ErrorBook {
    entries: VecDeque<ErrorEntry>,
}

/// What changed in an [`ErrorBook::update`], for logging.
#[derive(Debug, Default, PartialEq)]
pub struct Changes {
    pub raised: Vec<ErrorEntry>,
    pub resolved: Vec<ErrorEntry>,
}

impl ErrorBook {
    /// Replace the set of active conditions: new ones are raised, missing
    /// ones resolved, continuing ones refreshed.
    pub fn update(&mut self, conditions: &[Condition], now_unix: u64) -> Changes {
        let mut changes = Changes::default();
        for entry in self.entries.iter_mut().filter(|e| e.active) {
            if !conditions.iter().any(|c| c.key == entry.key) {
                entry.active = false;
                entry.resolved_unix = Some(now_unix);
                changes.resolved.push(entry.clone());
            }
        }
        for c in conditions {
            if let Some(entry) = self.entries.iter_mut().find(|e| e.active && e.key == c.key) {
                entry.message = c.message.clone();
                entry.last_unix = now_unix;
                continue;
            }
            let entry = ErrorEntry {
                key: c.key.clone(),
                message: c.message.clone(),
                since_unix: c.since_unix,
                last_unix: now_unix,
                count: 1,
                active: true,
                resolved_unix: None,
            };
            changes.raised.push(entry.clone());
            self.push(entry);
        }
        changes
    }

    /// Record a one-off error (a failed action, a crash). A repeat of the
    /// newest entry's message only bumps its count.
    pub fn event(&mut self, key: &str, message: String, now_unix: u64) {
        if let Some(entry) = self
            .entries
            .iter_mut()
            .find(|e| !e.active && e.key == key && e.resolved_unix.is_none())
            .filter(|e| e.message == message)
        {
            entry.count += 1;
            entry.last_unix = now_unix;
            return;
        }
        self.push(ErrorEntry {
            key: key.to_string(),
            message,
            since_unix: now_unix,
            last_unix: now_unix,
            count: 1,
            active: false,
            resolved_unix: None,
        });
    }

    fn push(&mut self, entry: ErrorEntry) {
        self.entries.push_front(entry);
        // Drop the oldest inactive entries beyond the cap; active ones stay.
        while self.entries.len() > RECENT_ERRORS {
            match self.entries.iter().rposition(|e| !e.active) {
                Some(i) => {
                    self.entries.remove(i);
                }
                None => break,
            }
        }
    }

    /// Everything, newest first.
    pub fn entries(&self) -> Vec<ErrorEntry> {
        self.entries.iter().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use friglet_ipc::{ScanHealthInfo, ScanStallInfo};

    const NOW: u64 = 1_790_000_000;

    fn status(state: ScanState) -> StatusInfo {
        StatusInfo {
            scanning: matches!(state, ScanState::Running | ScanState::Stopping),
            scanned_height: 100,
            tip_height: Some(100),
            scan_state: Some(state),
            ..Default::default()
        }
    }

    fn stalled(reason: &str, since: u64) -> StatusInfo {
        StatusInfo {
            scan_health: ScanHealthInfo {
                stall: Some(ScanStallInfo {
                    height: 101,
                    reason: reason.to_string(),
                    since_unix: since,
                }),
                ..Default::default()
            },
            ..status(ScanState::Running)
        }
    }

    const NOT_INDEXED: &str = "scan stopped at height 101: the oracle sent no valid block hash \
        (0 bytes); the height is probably not indexed; nothing from height 101 on was scanned";

    #[test]
    fn new_tip_not_indexed_yet_is_waiting_then_an_error_after_the_grace() {
        let fresh = scan_view(Some(&stalled(NOT_INDEXED, NOW - 5)), true, NOW);
        assert_eq!(fresh.state, "waiting");
        assert_eq!(fresh.tone, Tone::Neutral);
        assert_eq!(
            fresh.detail.as_deref(),
            Some("The oracle has not indexed block 101 yet. Retrying automatically.")
        );
        assert_eq!(fresh.since_unix, Some(NOW - 5));
        assert!(fresh.can_stop && !fresh.can_start);

        let old = scan_view(
            Some(&stalled(NOT_INDEXED, NOW - STALL_GRACE_SECS)),
            true,
            NOW,
        );
        assert_eq!(old.state, "error");
        assert_eq!(old.tone, Tone::Bad);
        assert!(
            old.problem
                .unwrap()
                .starts_with("Scan stuck at block 101: scan stopped")
        );
        assert!(old.detail.unwrap().contains("has not indexed block 101"));
    }

    #[test]
    fn scan_states_and_buttons() {
        let paused = scan_view(Some(&status(ScanState::Paused)), true, NOW);
        assert_eq!(
            (paused.state, paused.can_start, paused.can_stop),
            ("paused", true, false)
        );
        let stopping = scan_view(Some(&status(ScanState::Stopping)), true, NOW);
        assert_eq!(
            (stopping.state, stopping.can_start, stopping.can_stop),
            ("stopping", false, false),
            "neither button while the task winds down"
        );
        let synced = scan_view(Some(&status(ScanState::Running)), true, NOW);
        assert_eq!(
            (synced.state, synced.can_start, synced.can_stop),
            ("synced", false, true)
        );
        let catching_up = StatusInfo {
            scanned_height: 90,
            ..status(ScanState::Running)
        };
        assert_eq!(scan_view(Some(&catching_up), true, NOW).state, "scanning");
        let failed = StatusInfo {
            last_error: Some("boom".into()),
            ..status(ScanState::Failed)
        };
        let failed = scan_view(Some(&failed), true, NOW);
        assert_eq!((failed.state, failed.can_start), ("error", true));
        // Unreachable: no buttons, whatever the last snapshot said.
        let gone = scan_view(Some(&status(ScanState::Running)), false, NOW);
        assert_eq!(
            (gone.state, gone.can_start, gone.can_stop),
            ("unknown", false, false)
        );
    }

    #[test]
    fn older_daemons_without_scan_state_fall_back_to_scanning() {
        let mut old = status(ScanState::Running);
        old.scan_state = None;
        assert_eq!(scan_view(Some(&old), true, NOW).state, "synced");
        old.scanning = false;
        assert_eq!(scan_view(Some(&old), true, NOW).state, "paused");
    }

    #[test]
    fn oracle_outage_is_waiting_then_an_error() {
        let mut s = status(ScanState::Running);
        s.oracle_error = Some("oracle https://o: no answer within 5s".into());
        s.oracle_down_since_unix = Some(NOW - 30);
        assert_eq!(scan_view(Some(&s), true, NOW).state, "waiting");
        s.oracle_down_since_unix = Some(NOW - 200);
        let v = scan_view(Some(&s), true, NOW);
        assert_eq!((v.state, v.label.as_str()), ("error", "oracle unreachable"));
    }

    #[test]
    fn daemon_view_states() {
        let running = daemon_view(&DaemonFacts {
            reachable: true,
            ownership: Some(Ownership::External),
            pid: Some(42),
            ..Default::default()
        });
        assert_eq!(
            (running.state, running.can_stop, running.can_start),
            ("running", true, false)
        );
        assert!(running.detail.contains("Started outside the tray"));
        assert!(running.detail.contains("PID 42"));
        assert!(running.detail.contains("Quit leaves it running"));

        let stopped = daemon_view(&DaemonFacts {
            stopped: Some(Stopped {
                at_unix: NOW,
                by_user: true,
                detail: String::new(),
                pid: Some(42),
            }),
            unreachable_for_secs: Some(500),
            ..Default::default()
        });
        assert_eq!(
            (stopped.state, stopped.tone, stopped.can_start),
            ("stopped", Tone::Neutral, true)
        );

        let blip = daemon_view(&DaemonFacts {
            unreachable_for_secs: Some(2),
            ..Default::default()
        });
        assert_eq!((blip.state, blip.tone), ("reconnecting", Tone::Neutral));
        let down = daemon_view(&DaemonFacts {
            unreachable_for_secs: Some(UNREACHABLE_GRACE_SECS),
            ..Default::default()
        });
        assert_eq!(
            (down.state, down.tone, down.can_start),
            ("unreachable", Tone::Bad, true)
        );
        let starting = daemon_view(&DaemonFacts {
            starting: true,
            unreachable_for_secs: Some(30),
            ..Default::default()
        });
        assert_eq!(starting.state, "starting");
        let crash_loop = daemon_view(&DaemonFacts {
            restart_in_secs: Some(4),
            unreachable_for_secs: Some(30),
            ..Default::default()
        });
        assert_eq!(
            (crash_loop.state, crash_loop.can_start, crash_loop.can_stop),
            ("restarting", true, true),
            "Stop daemon ends a crash loop"
        );
    }

    fn cond(key: &str, message: &str, since: u64) -> Condition {
        Condition {
            key: key.into(),
            message: message.into(),
            since_unix: since,
        }
    }

    #[test]
    fn error_book_keeps_active_errors_until_resolved_and_remembers_them() {
        let mut book = ErrorBook::default();
        let changes = book.update(&[cond("stall", "stuck at 101", NOW - 130)], NOW);
        assert_eq!(changes.raised.len(), 1);
        assert_eq!(changes.raised[0].since_unix, NOW - 130);

        // Still there next poll: not raised again.
        let changes = book.update(&[cond("stall", "stuck at 101", NOW - 130)], NOW + 1);
        assert_eq!(changes, Changes::default());
        assert!(book.entries()[0].active);

        let changes = book.update(&[], NOW + 60);
        assert_eq!(changes.resolved.len(), 1);
        let entry = &book.entries()[0];
        assert!(!entry.active);
        assert_eq!(entry.resolved_unix, Some(NOW + 60));
        assert_eq!(entry.since_unix, NOW - 130, "keeps when it began");
    }

    #[test]
    fn error_book_events_dedupe_and_cap() {
        let mut book = ErrorBook::default();
        book.event("spawn", "socket never came up".into(), NOW);
        book.event("spawn", "socket never came up".into(), NOW + 5);
        assert_eq!(book.entries().len(), 1, "a repeat is not a new entry");
        assert_eq!(book.entries()[0].count, 2);
        book.event("spawn", "exited immediately".into(), NOW + 6);
        assert_eq!(book.entries().len(), 2, "another message is a new entry");

        book.update(&[cond("stall", "stuck", NOW)], NOW);
        for i in 0..(RECENT_ERRORS as u64 + 5) {
            book.event("action", format!("failure {i}"), NOW + 10 + i);
        }
        let entries = book.entries();
        assert_eq!(entries.len(), RECENT_ERRORS);
        assert!(
            entries.iter().any(|e| e.active && e.key == "stall"),
            "active entries are never dropped"
        );
    }
}
