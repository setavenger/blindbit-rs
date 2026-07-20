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
  The status window has a Settings tab (GetConfig/SetConfig/SetScanKey over
  the control socket); the fake daemon answers all of these in memory.
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

## Packaging (M4)

- Desktop bundles: `scripts/prepare-sidecar.sh` (stages
  `target/release/friglet` as `friglet-tray/binaries/friglet-<triple>`,
  gitignored), then from `friglet-tray/`:
  `npx @tauri-apps/cli build --bundles deb,appimage --config
  tauri.sidecar.conf.json` (Linux) or `--bundles dmg --config
  tauri.sidecar.conf.json` (macOS host only — dmg cannot be cross-built
  from Linux). Artifacts: `target/release/bundle/{deb,appimage,dmg}/`.
- The daemon is a Tauri sidecar (`bundle.externalBin`), but it lives in the
  `tauri.sidecar.conf.json` overlay, NOT the base `tauri.conf.json`:
  tauri-build errors at compile time when an externalBin file is missing,
  which would break plain `cargo build/test --workspace` on fresh clones.
  The sidecar file needs the target-triple suffix or the build fails with
  "resource path ... doesn't exist". Both deb and AppImage place `friglet`
  next to `friglet-tray` in `usr/bin/`, which the existing lifecycle search
  order (env → exe dir → PATH) already covers — no lifecycle changes were
  needed.
- Verified in this repo's cloud VM: the installed `.deb`'s tray, run under
  `xvfb-run -a dbus-run-session`, attaches to a fake daemon AND spawns the
  bundled `/usr/bin/friglet` sidecar (which scanned signet blocks live).
  Same attach smoke test passes for the AppImage with
  `--appimage-extract-and-run` (plain AppImage mount needs FUSE).
- AppImage bundling downloads linuxdeploy/appimagetool at build time —
  needs network; the deb target has no such dependency.
- Docker: root `Dockerfile` (multi-stage; builder needs `protobuf-compiler`
  AND `libprotobuf-dev` — the latter provides the `google/protobuf/*.proto`
  well-known types blindbit-lib's protos import) + `docs/docker.md`. All
  state under a `/data` volume; image presets
  `FRIGLET_HTTP_ADDR`/`FRIGLET_ELECTRUM_ADDR` to `0.0.0.0` binds (env beats
  config file, loses to flags). Verified in this VM (dockerd with
  `--storage-driver=vfs`; overlayfs fails in the nested container): image
  builds (~91 MB), container scans signet, control socket works. Note a
  pre-existing daemon behavior: the scan task holds the scanner mutex, so
  HTTP `/height`/`/subscribe` block while a scan is actively running.
- Windows status: `cargo check -p friglet-ipc -p friglet -p friglet-tray
  --target x86_64-pc-windows-gnu` passes cleanly (mingw-w64 installed).
  The `x86_64-pc-windows-msvc` target cannot be checked from Linux — the
  `ring` and `secp256k1-sys` build scripts need MSVC's `lib.exe` — that is
  an environment limitation, not a code problem. No real Windows
  build/run has been exercised; linking + runtime remain unverified.

## SetConfig / SetScanKey semantics (v1)

- The daemon validates a `SetConfig` payload fully before touching anything;
  invalid input → `Response::Error`, nothing persisted. Valid configs are
  written as TOML to the config file the daemon loaded (or the default path)
  and applied: scanner-affecting fields rebuild + restart the scan task;
  `http_addr`/`electrum_addr`/`control_socket`/`log_level` need a daemon
  restart (reported via `Response::OkWithNote` — no live rebinding).
- Known v1 limitation: the Electrum server keeps the index/notification
  channel of the scanner it was started with, so after a scanner-affecting
  `SetConfig` it serves the pre-change wallet view until the daemon restarts
  (the `OkWithNote` message says so). Same for the HTTP `/subscribe` start
  height.
- `SetScanKey` writes the key file (0600) but blindbit-lib restores the
  secret embedded in the state file, so a stale state file pins the old key —
  the daemon detects this and answers `OkWithNote` telling the user to move
  the state file.
- Control-socket integration tests live in `friglet/src/control/mod.rs`
  (friglet is a bin crate, so no `tests/` dir); they build offline `Scanner`s
  via a lazy tonic channel (`tonic` is a friglet dev-dependency pinned to
  blindbit-lib's version) and inject a no-network `scanner_builder`.

## Rules

- Do NOT modify `blindbit-lib` (or `blindbit-cli` / HTTP / Electrum behavior)
  in tray-project work; the tray talks to the daemon only via `friglet-ipc`.
- Workspace-wide `cargo fmt` reformats `blindbit-lib` files that are not
  fmt-clean; run fmt scoped with `-p` to avoid unrelated diffs.
