//! Crash-safe handling of the scanner state file.
//!
//! The state is written to a temporary file next to the real one, flushed to
//! disk, and renamed over it, so a crash or power loss leaves the old state
//! or the new one, never a truncated mix. A state file that cannot be parsed
//! is never overwritten: it is moved aside first (see `load_scanner`).

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Replace `path` with `contents` atomically: temporary file, `fsync`,
/// rename, then `fsync` of the directory (Unix) so the rename itself is
/// durable. The file is created owner-only: it holds the scan secret.
///
/// On failure the previous file at `path` is untouched and the temporary
/// file is removed.
pub(crate) fn write_atomically(path: &Path, contents: &[u8]) -> io::Result<()> {
    let tmp = sibling(path, ".tmp");
    // A leftover from a crash may have other permissions; start clean.
    let _ = std::fs::remove_file(&tmp);
    let result = (|| {
        let mut file = create_owner_only(&tmp)?;
        file.write_all(contents)?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&tmp, path)?;
        sync_parent_dir(path);
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

/// Move a state file that cannot be restored out of the way, so a new
/// scanner never overwrites it, and return where it went
/// (`<name>.unreadable-<unix time>`, numbered if that exists).
pub(crate) fn move_aside(path: &Path) -> io::Result<PathBuf> {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut backup = sibling(path, &format!(".unreadable-{stamp}"));
    let mut n = 1;
    while backup.exists() {
        backup = sibling(path, &format!(".unreadable-{stamp}-{n}"));
        n += 1;
    }
    std::fs::rename(path, &backup)?;
    sync_parent_dir(path);
    Ok(backup)
}

fn sibling(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(suffix);
    path.with_file_name(name)
}

#[cfg(unix)]
fn create_owner_only(path: &Path) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}

#[cfg(not(unix))]
fn create_owner_only(path: &Path) -> io::Result<File> {
    OpenOptions::new().write(true).create_new(true).open(path)
}

/// Make a rename in `path`'s directory durable. Best effort: the data is
/// already on disk, and some platforms cannot open a directory for this.
fn sync_parent_dir(path: &Path) {
    #[cfg(unix)]
    {
        let parent = match path.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => parent,
            _ => Path::new("."),
        };
        if let Ok(dir) = File::open(parent) {
            let _ = dir.sync_all();
        }
    }
    #[cfg(not(unix))]
    let _ = path;
}
