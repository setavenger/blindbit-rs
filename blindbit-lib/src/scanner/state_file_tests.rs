//! The state file is written atomically, and a state file that cannot be
//! restored is moved aside and reported, never silently replaced.

use std::path::{Path, PathBuf};

use bitcoin_rev::Network;

use super::Scanner;
use super::config::ScannerConfig;
use super::load::restore_or_create;
use super::test_support::{keys, oracle_client, run, scanner_at};

struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let dir =
            std::env::temp_dir().join(format!("blindbit-state-file-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        Self(dir)
    }

    fn entries(&self) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(&self.0)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn config(state_file: &Path) -> ScannerConfig {
    let (secret, spend) = keys();
    ScannerConfig::new(
        "http://127.0.0.1:1".to_string(),
        "127.0.0.1:1".parse().unwrap(),
        secret,
        spend,
        0,
        state_file.to_path_buf(),
        Network::Regtest,
    )
}

#[test]
fn save_replaces_the_file_atomically_and_owner_only() {
    run(async {
        let dir = TempDir::new("atomic");
        let path = dir.0.join("scanner_state.json");
        // An old world-readable file, and a temporary file left by a crash.
        std::fs::write(&path, "{}").unwrap();
        std::fs::write(dir.0.join("scanner_state.json.tmp"), "torn").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for name in ["scanner_state.json", "scanner_state.json.tmp"] {
                std::fs::set_permissions(dir.0.join(name), PermissionsExt::from_mode(0o644))
                    .unwrap();
            }
        }

        let mut scanner = scanner_at(path.clone(), 0);
        scanner.update_last_scanned_block_height(4_242);
        scanner.save_to_file(&path).expect("save");

        assert_eq!(
            dir.entries(),
            vec!["scanner_state.json".to_string()],
            "no temporary file is left behind"
        );
        let restored = Scanner::load_from_file(&path).expect("the saved file parses");
        assert_eq!(restored.last_scanned_block_height, 4_242);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "the state file holds the scan secret");
        }
    });
}

/// If the new state cannot be written, the previous file stays as it was.
#[test]
fn failed_save_leaves_the_previous_file_intact() {
    run(async {
        let dir = TempDir::new("failed-save");
        let path = dir.0.join("scanner_state.json");
        let mut scanner = scanner_at(path.clone(), 0);
        scanner.update_last_scanned_block_height(100);
        scanner.save_to_file(&path).expect("first save");
        let before = std::fs::read(&path).unwrap();

        // The temporary file's path is taken by a directory: the write fails.
        std::fs::create_dir(dir.0.join("scanner_state.json.tmp")).unwrap();
        std::fs::write(dir.0.join("scanner_state.json.tmp/x"), "").unwrap();
        scanner.update_last_scanned_block_height(200);
        scanner
            .save_to_file(&path)
            .expect_err("the temporary file cannot be created");
        assert_eq!(std::fs::read(&path).unwrap(), before, "old state untouched");
    });
}

/// A state file that is not valid JSON used to be replaced by a fresh
/// scanner's state on its first save, without a trace. It is now moved
/// aside, byte for byte, and the status says where it went.
#[test]
fn unparseable_state_file_is_moved_aside_and_reported() {
    run(async {
        let dir = TempDir::new("corrupt");
        let path = dir.0.join("scanner_state.json");
        let garbage = b"{\"block_checkpoints\": {\"0\": \"00";
        std::fs::write(&path, garbage).unwrap();

        let scanner = restore_or_create(&config(&path), oracle_client()).expect("starts over");
        assert_eq!(scanner.get_last_scanned_block_height(), 0, "a new scan");
        let reset = scanner
            .scan_health()
            .await
            .state_file_reset
            .expect("the reset is reported");
        assert!(reset.error.contains("JSON"), "{}", reset.error);
        assert_eq!(std::fs::read(&reset.backup_path).unwrap(), garbage);
        assert!(
            !path.exists(),
            "nothing is left at the old path to overwrite"
        );

        scanner.save_to_file(&path).expect("save the new state");
        assert_eq!(std::fs::read(&reset.backup_path).unwrap(), garbage);
        let names = dir.entries();
        assert_eq!(names.len(), 2, "{names:?}");
        assert!(names[1].starts_with("scanner_state.json.unreadable-"));
    });
}

/// A file from a newer build parses, but this build would drop what it does
/// not know on its next save: it is moved aside too.
#[test]
fn state_file_from_a_newer_build_is_moved_aside() {
    run(async {
        let dir = TempDir::new("newer");
        let path = dir.0.join("scanner_state.json");
        let mut scanner = scanner_at(path.clone(), 0);
        scanner.update_last_scanned_block_height(500);
        scanner.save_to_file(&path).unwrap();
        let mut json: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        json["format_version"] = serde_json::json!(super::STATE_FORMAT_VERSION + 1);
        std::fs::write(&path, json.to_string()).unwrap();

        let scanner = restore_or_create(&config(&path), oracle_client()).expect("starts over");
        assert_eq!(scanner.get_last_scanned_block_height(), 0);
        let reset = scanner.scan_health().await.state_file_reset.unwrap();
        assert!(reset.error.contains("newer build"), "{}", reset.error);
        assert!(reset.backup_path.exists());
    });
}

/// A state file that cannot be read at all is an error: nothing is moved,
/// nothing new is created.
#[test]
fn unreadable_state_path_is_an_error_and_nothing_moves() {
    run(async {
        let dir = TempDir::new("unreadable");
        let path = dir.0.join("scanner_state.json");
        std::fs::create_dir(&path).unwrap();
        let err = restore_or_create(&config(&path), oracle_client())
            .err()
            .expect("cannot read a directory as the state file");
        assert!(err.to_string().contains("cannot read state file"), "{err}");
        assert_eq!(dir.entries(), vec!["scanner_state.json".to_string()]);
    });
}

#[test]
fn valid_and_missing_state_files_behave_as_before() {
    run(async {
        let dir = TempDir::new("valid");
        let path = dir.0.join("scanner_state.json");
        let fresh = restore_or_create(&config(&path), oracle_client()).expect("no file: new");
        assert_eq!(fresh.scan_health().await.state_file_reset, None);
        let mut fresh = fresh;
        fresh.update_last_scanned_block_height(321);
        fresh.save_to_file(&path).unwrap();

        let restored = restore_or_create(&config(&path), oracle_client()).expect("restores");
        assert_eq!(restored.get_last_scanned_block_height(), 321);
        assert_eq!(restored.scan_health().await.state_file_reset, None);
        assert_eq!(dir.entries(), vec!["scanner_state.json".to_string()]);
    });
}
