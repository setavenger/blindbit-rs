# Agent notes for blindbit-rs

## Build & test

```bash
cargo build --workspace            # all crates, incl. friglet-tray (Tauri v2)
cargo test --workspace
cargo clippy -p friglet-tray --all-targets
cargo fmt -p friglet-tray -p friglet-ipc   # see fmt caveat below
```

Linux system deps for `friglet-tray` (Tauri v2): `libwebkit2gtk-4.1-dev`,
`libayatana-appindicator3-dev`, `librsvg2-dev`, `libgtk-3-dev`, `patchelf`,
`xdotool`, `libxdo-dev`.

## Running friglet-tray

- `cargo run -p friglet-tray` — no npm/frontend build step; the UI is plain
  static HTML/CSS/JS in `friglet-tray/ui/` (tauri.conf.json `frontendDist`).
- Fake daemon for manual testing (speaks the `friglet-ipc` protocol on the
  default control socket): `cargo run -p friglet-tray --example fake-daemon`.
- Useful env vars: `FRIGLET_CONTROL_SOCKET` (socket path override),
  `FRIGLET_DAEMON_BIN` (daemon binary the tray spawns when none is running).
- Tray icons are generated placeholders; regenerate with
  `python3 friglet-tray/icons/generate.py` (stdlib only).

## Tray testing under headless / computer-use environments

Verified in this repo's cloud VM (Xvfb available, no desktop environment):

- `xvfb-run -a dbus-run-session -- ./target/debug/friglet-tray` starts and
  runs without crashing; logs show the status poller round-trip
  ("tray status label updated label=Daemon: reachable (height N)") for both
  the attach path (daemon already running) and the spawn path
  (`FRIGLET_DAEMON_BIN` pointing at the fake daemon).
- A D-Bus session is required (`dbus-run-session`); without one, GTK/portal
  init is flaky.
- The tray ICON itself cannot be verified headless: on Linux it goes through
  StatusNotifier/ayatana-appindicator, and a bare Xvfb session has no
  StatusNotifierWatcher host, so nothing renders the icon (no error is
  raised — there is just nowhere to see or click it). Menu interaction
  therefore cannot be exercised with xdotool in this environment; rely on the
  `friglet-tray/tests/` integration tests and unit tests for the lifecycle
  and IPC logic instead.

## Rules

- Do NOT modify `blindbit-lib` (or `blindbit-cli` / HTTP / Electrum behavior)
  in tray-project work; the tray talks to the daemon only via `friglet-ipc`.
- Workspace-wide `cargo fmt` reformats `blindbit-lib` files that are not
  fmt-clean; run fmt scoped with `-p` to avoid unrelated diffs.
