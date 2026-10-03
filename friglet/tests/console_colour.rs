//! The console log goes to stdout, so stdout decides whether it is coloured:
//! redirected to a file it must carry no ANSI escapes, even when stderr is a
//! terminal.

/// Run `friglet` with a config error (one log line, then exit 1) inside a
/// pseudo-terminal from util-linux `script`; `redirect` is appended to the
/// command line. Returns the typescript (what reached the terminal), or
/// `None` when `script` is not available.
#[cfg(target_os = "linux")]
fn run_in_pty(dir: &std::path::Path, redirect: &str) -> Option<String> {
    let typescript = dir.join("typescript");
    let command = format!(
        "'{}' scan --network flarkchain {redirect}",
        env!("CARGO_BIN_EXE_friglet")
    );
    let status = std::process::Command::new("script")
        .args(["-q", "-e", "-c", &command])
        .arg(&typescript)
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("SHELL", "/bin/sh")
        .env("HOME", dir)
        .env("XDG_CONFIG_HOME", dir.join("config"))
        .env("FRIGLET_LOG_FILE", "off")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .status();
    match status {
        Ok(status) => assert_eq!(status.code(), Some(1), "friglet exits on the bad network"),
        Err(e) => {
            eprintln!("skipped: util-linux `script` not available: {e}");
            return None;
        }
    }
    Some(std::fs::read_to_string(typescript).unwrap())
}

#[cfg(target_os = "linux")]
#[test]
fn console_log_is_coloured_only_when_stdout_is_a_terminal() {
    let dir = std::env::temp_dir().join(format!("friglet-console-colour-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    // stdout and stderr on the terminal: coloured.
    let Some(terminal) = run_in_pty(&dir, "") else {
        return;
    };
    assert!(terminal.contains("invalid network"), "{terminal}");
    assert!(
        terminal.contains('\x1b'),
        "a terminal gets colour: {terminal:?}"
    );

    // stdout redirected to a file, stderr still on the terminal: plain text.
    let file = dir.join("out.log");
    run_in_pty(&dir, &format!("> '{}'", file.display())).unwrap();
    let log = std::fs::read_to_string(&file).unwrap();
    assert!(log.contains("invalid network"), "{log}");
    assert!(!log.contains('\x1b'), "no ANSI escapes in a file: {log:?}");

    std::fs::remove_dir_all(&dir).unwrap();
}
