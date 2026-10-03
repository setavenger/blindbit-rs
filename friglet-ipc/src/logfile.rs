//! Log files of the daemon and the tray: where they live and a small
//! size-capped writer, shared so both processes agree on the location.
//!
//! Default directory (see [`default_log_dir`]):
//! - Linux/BSD: `$XDG_STATE_HOME/friglet`, i.e. `~/.local/state/friglet`
//! - macOS: `~/Library/Logs/friglet`
//! - Windows: `%LOCALAPPDATA%\friglet\logs`
//!
//! The daemon writes `friglet.log` there (`FRIGLET_LOG_FILE` overrides the
//! path, `FRIGLET_LOG_FILE=off` turns the file off) and the tray writes
//! `friglet-tray.log`. Each file is capped at 10 MiB: when a write would
//! exceed it, the file is renamed to `<name>.1` (the previous `.1` becomes
//! `.2`, and an older `.2` is dropped) and a fresh file is started.

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

/// Size at which a log file is rotated.
const MAX_LOG_BYTES: u64 = 10 * 1024 * 1024;
/// Rotated files kept besides the live one (`.1`, `.2`).
const KEPT_ROTATIONS: u32 = 2;

/// File name of the daemon's log in [`default_log_dir`].
const DAEMON_LOG_NAME: &str = "friglet.log";
/// File name of the tray's log in [`default_log_dir`].
const TRAY_LOG_NAME: &str = "friglet-tray.log";

/// The platform's directory for friglet's log files.
pub fn default_log_dir() -> Option<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        dirs::home_dir().map(|h| h.join("Library").join("Logs").join("friglet"))
    }
    #[cfg(windows)]
    {
        dirs::data_local_dir().map(|d| d.join("friglet").join("logs"))
    }
    #[cfg(not(any(target_os = "macos", windows)))]
    {
        // `dirs::state_dir` is `$XDG_STATE_HOME` or `~/.local/state`.
        dirs::state_dir().map(|d| d.join("friglet"))
    }
}

/// Where the daemon writes its log: `FRIGLET_LOG_FILE` when set (`None`
/// when it is `off`/`none`/empty), else `<log dir>/friglet.log`.
pub fn daemon_log_file() -> Option<PathBuf> {
    match std::env::var_os("FRIGLET_LOG_FILE") {
        Some(value) => {
            let text = value.to_string_lossy();
            let off = matches!(
                text.trim().to_ascii_lowercase().as_str(),
                "" | "off" | "none"
            );
            (!off).then(|| PathBuf::from(value))
        }
        None => default_log_dir().map(|d| d.join(DAEMON_LOG_NAME)),
    }
}

/// Where the tray writes its own log: `<log dir>/friglet-tray.log`.
pub fn tray_log_file() -> Option<PathBuf> {
    default_log_dir().map(|d| d.join(TRAY_LOG_NAME))
}

/// An append-only log file that rotates itself at a size cap. Cheap to
/// clone (all clones share the file), and every clone is an [`io::Write`],
/// so `move || writer.clone()` serves as a `tracing_subscriber` writer.
#[derive(Clone)]
pub struct RotatingLog {
    inner: Arc<Mutex<Inner>>,
}

struct Inner {
    path: PathBuf,
    file: Option<File>,
    written: u64,
    max_bytes: u64,
}

impl RotatingLog {
    /// Open (append to) `path` with the default cap, creating its directory.
    pub fn open(path: &Path) -> io::Result<Self> {
        Self::with_limit(path, MAX_LOG_BYTES)
    }

    /// [`RotatingLog::open`] with a custom size cap (tests).
    fn with_limit(path: &Path, max_bytes: u64) -> io::Result<Self> {
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            create_private_dir(parent)?;
        }
        let file = open_append(path)?;
        let written = file.metadata()?.len();
        let log = Self {
            inner: Arc::new(Mutex::new(Inner {
                path: path.to_path_buf(),
                file: Some(file),
                written,
                max_bytes,
            })),
        };
        // A file left over-size by an earlier run starts out rotated.
        log.inner.lock().unwrap().rotate_if_needed(0)?;
        Ok(log)
    }

    pub fn path(&self) -> PathBuf {
        self.inner.lock().unwrap().path.clone()
    }
}

impl Inner {
    fn rotate_if_needed(&mut self, incoming: u64) -> io::Result<()> {
        if self.written == 0 || self.written + incoming <= self.max_bytes {
            return Ok(());
        }
        self.file = None;
        for n in (1..KEPT_ROTATIONS).rev() {
            let _ = std::fs::rename(rotated(&self.path, n), rotated(&self.path, n + 1));
        }
        std::fs::rename(&self.path, rotated(&self.path, 1))?;
        self.file = Some(open_append(&self.path)?);
        self.written = 0;
        Ok(())
    }
}

impl Write for RotatingLog {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut inner = self.inner.lock().unwrap();
        // A failed rotation (e.g. the directory became read-only) keeps
        // appending rather than losing lines.
        let _ = inner.rotate_if_needed(buf.len() as u64);
        if inner.file.is_none() {
            let path = inner.path.clone();
            inner.file = Some(open_append(&path)?);
        }
        let written = inner.file.as_mut().expect("opened above").write(buf)?;
        inner.written += written as u64;
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        match self.inner.lock().unwrap().file.as_mut() {
            Some(file) => file.flush(),
            None => Ok(()),
        }
    }
}

fn rotated(path: &Path, n: u32) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(format!(".{n}"));
    PathBuf::from(name)
}

/// Logs name wallet addresses and transactions: keep them owner-only.
fn open_append(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}

fn create_private_dir(dir: &Path) -> io::Result<()> {
    if dir.is_dir() {
        return Ok(());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(dir)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("friglet-logfile-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn appends_and_rotates_at_the_cap() {
        let dir = temp_dir("rotate");
        let path = dir.join("friglet.log");
        let mut log = RotatingLog::with_limit(&path, 20).unwrap();
        log.write_all(b"0123456789\n").unwrap(); // 11 bytes
        log.write_all(b"abcdefghi\n").unwrap(); // 21 > 20: rotates first
        assert_eq!(
            std::fs::read_to_string(rotated(&path, 1)).unwrap(),
            "0123456789\n"
        );
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "abcdefghi\n");

        log.write_all(b"ABCDEFGHIJKL\n").unwrap();
        log.write_all(b"second-rotation\n").unwrap();
        log.write_all(b"third-rotation!\n").unwrap();
        // Only KEPT_ROTATIONS old files survive.
        assert_eq!(
            std::fs::read_to_string(rotated(&path, 1)).unwrap(),
            "second-rotation\n"
        );
        assert_eq!(
            std::fs::read_to_string(rotated(&path, 2)).unwrap(),
            "ABCDEFGHIJKL\n"
        );
        assert!(!rotated(&path, 3).exists());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "third-rotation!\n");
    }

    #[test]
    fn reopening_appends_and_rotates_an_oversized_leftover() {
        let dir = temp_dir("reopen");
        let path = dir.join("friglet.log");
        RotatingLog::with_limit(&path, 1000)
            .unwrap()
            .write_all(b"first run\n")
            .unwrap();
        RotatingLog::with_limit(&path, 1000)
            .unwrap()
            .write_all(b"second run\n")
            .unwrap();
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "first run\nsecond run\n"
        );
        // A smaller cap than the file already is: rotated on open.
        let mut log = RotatingLog::with_limit(&path, 5).unwrap();
        assert!(rotated(&path, 1).exists());
        log.write_all(b"x\n").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "x\n");
    }

    #[cfg(unix)]
    #[test]
    fn log_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = temp_dir("perms");
        let path = dir.join("nested").join("friglet.log");
        let mut log = RotatingLog::open(&path).unwrap();
        log.write_all(b"line\n").unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let dir_mode = std::fs::metadata(path.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(dir_mode, 0o700);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_log_dir_follows_xdg_state_home() {
        // dirs reads XDG_STATE_HOME directly; only check the suffix so the
        // test does not depend on (or mutate) the environment.
        let dir = default_log_dir().unwrap();
        assert!(dir.ends_with("friglet"), "{}", dir.display());
        assert_eq!(tray_log_file().unwrap().file_name().unwrap(), TRAY_LOG_NAME);
    }
}
