# AGENTS.md

## Cursor Cloud specific instructions

Rust Cargo workspace (edition 2024) for BlindBit BIP-352 Silent Payments. Crates: `blindbit-lib` (core scanner + gRPC oracle client), `friglet` (daemon: scanner + HTTP + Electrum + control socket), `friglet-ipc` (control-socket protocol, shared by daemon and tray), `friglet-tray` (Tauri v2 tray UI), `blindbit-cli` (one-shot range scan, no servers). See `README.md` for full flags/usage.

### Toolchain / build
- Needs Rust **stable >= 1.85** (edition 2024). Default toolchain is set to `stable`; the preinstalled `1.83.0` is too old and fails to compile.
- `protoc` is a hard build requirement: `blindbit-lib/build.rs` compiles `blindbit-lib/proto/*.proto` via `tonic-prost-build`. Build fails with no protoc on PATH.

### System dependencies (baked into the VM snapshot)
This env needs heavy system setup beyond the current tree because the repo also has a **Tauri v2 tray app** (`friglet-tray`) that requires GTK/WebKit/appindicator to build, plus Windows cross-compile + headless-GUI test tooling. These are already installed in the VM snapshot from a setup session, so future agents should NOT need to reinstall them; if a fresh env is missing them, install via apt (needs `sudo`):

- Tauri build: `libwebkit2gtk-4.1-dev libayatana-appindicator3-dev librsvg2-dev libgtk-3-dev libssl-dev pkg-config patchelf`
- Proto codegen: `protobuf-compiler libprotobuf-dev`
- Headless GUI test / automation: `xvfb xdotool libxdo-dev`
- Windows cross-compile: `mingw-w64` + `rustup target add x86_64-pc-windows-gnu`
- Containers: `docker.io`
- Rust components: `clippy` + `rustfmt`

If a future env keeps losing these, regenerate the environment config via the env setup agent at `cursor.com/onboard` rather than relying on the startup update script (which is kept minimal to `cargo fetch`).
- Standard commands from repo root: `cargo build --workspace`, `cargo clippy --workspace`, `cargo fmt --all -- --check`, `cargo test --workspace`.
- `blindbit-lib`/`blindbit-cli` have no in-repo tests and no committed clippy/rustfmt config; their clippy warnings (e.g. `collapsible_if`) and `cargo fmt --check` diffs are pre-existing — do not "fix" pre-existing style in those crates unless asked. `friglet`, `friglet-ipc`, and `friglet-tray` DO have real test suites (unit + integration) — see below; scope `cargo fmt` with `-p` to those crates to avoid touching `blindbit-lib`.

### Running / end-to-end
- Run commands are in `README.md`. E2E needs two **external** services: a BlindBit Oracle (signet: `https://signet.oracle.setor.dev`) and a Bitcoin P2P peer (signet example `152.53.151.148:38333`). Both are reachable from the VM. No DB.
- Keys are BIP-352 hex: `--scan-secret` (32-byte secp256k1 secret), `--spend-pubkey` (33-byte compressed pubkey). For smoke tests any valid keypair works, e.g. secret `0000...0001` and pubkey `0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798` (finds no UTXOs, balance 0).
- `friglet scan` from `--start-height 274010` to signet tip is ~40k blocks (~10 min at ~100 blk/s). For a fast check use `blindbit-cli` with a small `--end-height` range (e.g. 274010..274060 finishes in ~1s).
- State persists to a JSON file (`--state-file`); tests use the gitignored `blindbit-test/` dir.

### Non-obvious gotcha (friglet HTTP)
- `friglet`'s HTTP endpoints `/height` and `/subscribe` **block while a scan is actively running**: `watch_chain()` holds the scanner `Mutex` while scanning, so the HTTP handlers can't acquire it until the scan supervisor is stopped (or between scan iterations). This is pre-existing app behavior, not an env issue.
- The **Electrum TCP server works** (it uses a separate index mutex). To verify a running scanner, query Electrum, e.g. send `{"id":1,"method":"server.version","params":["x","1.4"]}` and `{"id":2,"method":"blockchain.headers.subscribe","params":[]}` to `127.0.0.1:50001`; it returns `["Friglet","1.4"]` and the latest scanned height. The control socket's `GetStatus` (see below) is unaffected by the lock and is the preferred way to check status while scanning.

## Build & test

```bash
cargo build --workspace            # all crates, incl. friglet-tray (Tauri v2)
cargo test --workspace
cargo clippy -p friglet -p friglet-ipc -p friglet-tray --all-targets
cargo fmt -p friglet -p friglet-ipc -p friglet-tray   # see fmt caveat above
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
  `FRIGLET_DAEMON_BIN` (daemon binary the tray spawns when none is running),
  `FRIGLET_TRAY_SHOW_ON_START` (show the status window on startup:
  `1`/`true`/`yes`/`on`/`status` → Status tab;
  `settings` → Settings tab after the UI loads — useful for headless /
  screenshot testing; synthetic X11 clicks do not reach WebKitGTK reliably).

### First-run setup mode (no config file yet)

- On startup (and on "Retry / Start daemon") the tray probes the socket;
  when unreachable it checks whether the daemon is plausibly configured
  BEFORE spawning (`friglet-tray/src/setup.rs::is_configured`): the default
  config file (`friglet_ipc::default_config_path()`, i.e.
  `<config dir>/friglet/config.toml`) must supply `p2p_node_addr`,
  `start_height` and `spend_pubkey` (each satisfiable via
  `FRIGLET_P2P_NODE_ADDR`/`FRIGLET_START_HEIGHT`/`FRIGLET_SPEND_PUBKEY`
  env instead), and a scan secret must exist (key file from the config's
  `key_file` or `<config dir>/friglet/scan.key`, or `FRIGLET_SCAN_SECRET`).
  A config file that exists but fails to parse counts as configured, so the
  spawn attempt surfaces the daemon's own parse error instead of setup mode
  silently overwriting a hand-written file.
- Not configured → NO spawn (it could only fail with `missing required
  setting ...`); the tray enters setup mode instead: tray label "Setup
  required — open window", the main window auto-opens on the Settings tab
  with a first-time-setup banner and the form ENABLED in local mode
  (prefilled from defaults + any partial config file via `get_setup_state`).
- Save in setup mode goes through the `save_local_config` tauri command:
  tray-side validation (mirrors the daemon's rules; scan key REQUIRED
  here), then the tray writes the key file (0600) first and the config file
  (atomic TOML) second — shared helpers in `friglet-ipc`
  (`default_config_path`/`default_key_file`/`read_config_toml`/
  `write_config_toml`/`write_key_file`, which `friglet/src/config.rs` also
  delegates to) — then reruns attach-or-spawn, which now starts the daemon
  and flips the UI to the normal daemon-backed mode.
- Headless test: run the tray under the Xvfb recipe below but with a fresh
  `HOME` (and `XDG_CONFIG_HOME`/`XDG_DATA_HOME`/`XDG_RUNTIME_DIR` unset)
  and no `FRIGLET_*` env — no fake daemon, no
  `FRIGLET_TRAY_SHOW_ON_START`. The window must appear by itself on the
  Settings tab with the banner (verified in this VM; window screenshot via
  `import -window "$(xdotool search --name "Friglet Status" | head -1)"`).
  Unit/e2e coverage: `friglet-tray/src/setup.rs` tests, the
  `setup_required_*` cases in `friglet-tray/tests/lifecycle_e2e.rs`, and
  the setup-mode tests in `friglet-tray/src/lib.rs`.
- Tray icons are generated placeholders; regenerate with
  `python3 friglet-tray/icons/generate.py` (stdlib only).

## Tray testing under headless / computer-use environments

Verified in this repo's cloud VM (Xvfb + fluxbox + StatusNotifier host):

### Screenshot the status/settings window (and tray icon)

```bash
# deps: fluxbox x11-apps imagemagick xdotool
#       haskell-gtk-sni-tray-utils (gtk-sni-tray-standalone) for the tray icon
SOCKET=/tmp/friglet-tray-shot.sock
rm -f "$SOCKET"

Xvfb :99 -screen 0 1280x800x24 -ac +extension GLX +render -noreset &
export DISPLAY=:99
sleep 1

dbus-run-session -- bash -c '
  fluxbox &
  sleep 1
  # StatusNotifierWatcher + tray bar (renders ayatana-appindicator / SNI icons)
  gtk-sni-tray-standalone --top --end -w -s 28 -c "#222222" &
  sleep 1

  FRIGLET_CONTROL_SOCKET='"$SOCKET"' ./target/debug/examples/fake-daemon &
  sleep 1

  # SHOW_ON_START=1 → Status tab; =settings → Settings tab (eval after load)
  FRIGLET_CONTROL_SOCKET='"$SOCKET"' FRIGLET_TRAY_SHOW_ON_START=1 \
    ./target/debug/friglet-tray &
  sleep 4

  import -window root /tmp/shot-desktop.png
  WID=$(xdotool search --name "Friglet Status" | head -1)
  import -window "$WID" /tmp/shot-status.png
'
# For Settings without relying on xdotool→WebKit clicks, relaunch with
# FRIGLET_TRAY_SHOW_ON_START=settings instead.
```

- `FRIGLET_TRAY_SHOW_ON_START` is the supported way to force the status
  window visible without clicking the tray menu (main window starts with
  `visible: false` in `tauri.conf.json`).
- A D-Bus session is required (`dbus-run-session`); without one, GTK/portal
  init is flaky. The tray and `gtk-sni-tray-standalone` must share that bus.
- Tray icon: bare Xvfb has no StatusNotifierWatcher. With
  `gtk-sni-tray-standalone -w` (package `haskell-gtk-sni-tray-utils`) under
  fluxbox the friglet SNI icon renders (ayatana path
  `/org/ayatana/NotificationItem/tray_icon_tray_app_friglet_tray`).
  `snixembed` is not in Ubuntu apt; `trayer` alone only hosts legacy XEmbed
  icons, not StatusNotifierItem. xdotool clicks do not reach WebKitGTK under
  Xvfb — use `FRIGLET_TRAY_SHOW_ON_START=settings` for the Settings form.

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

## Daemon spawn diagnostics (tray lifecycle)

`friglet-tray/src/lifecycle.rs`'s `spawn_daemon` pipes (rather than
`Stdio::null()`s) the spawned `friglet` child's stdout/stderr and drains them
continuously in a background task — both to avoid the daemon blocking once
it logs enough to fill an unread pipe buffer, and so that a daemon that
exits immediately after spawning (stale binary predating the current CLI,
missing config/key file, bad address, ...) surfaces its actual error message
in the "Daemon: unreachable" reason instead of a bare, undiagnosable exit
code. If you see `spawned daemon exited immediately (exit status: 2)` with
no further detail, you're looking at a build that predates this fix, or a
release binary with stdio still swallowed — rebuild `friglet-tray` and check
the captured reason text (also logged at `debug` level, target
`friglet-daemon`) before guessing at the cause. Exit code 2 from a Rust CLI
built with `clap` almost always means clap itself rejected the arguments
(rare here, since the daemon runs with zero args) or — far more likely in
practice — a stale `target/release/friglet` predating this branch's
optional-subcommand/config-file support; run `cargo build --release
--workspace` (or at least `-p friglet`) after pulling changes that touch the
daemon's CLI.

## Rules

- Do NOT modify `blindbit-lib` (or `blindbit-cli` / HTTP / Electrum behavior)
  in tray-project work; the tray talks to the daemon only via `friglet-ipc`.
- Workspace-wide `cargo fmt` reformats `blindbit-lib` files that are not
  fmt-clean; run fmt scoped with `-p` to avoid unrelated diffs.

## Linear — no hardcoded links, always update issue status

This repo is public. **Never write a `linear.app` URL into anything that
ends up in the repo or on GitHub** — commit messages, PR titles/bodies, PR
comments, code comments, README, this file. Linear's GitHub integration
auto-detects plain issue identifiers (e.g. `SNB-42`, or `Fixes SNB-42`)
anywhere in a branch name, commit message, or PR title/body and links them
up on its own — that's the only mechanism to use. Writing a markdown link
like `[SNB-42](https://linear.app/...)` or `[Friglet Tray UI
App](https://linear.app/...)` leaks an internal workspace URL onto a public
page for no benefit (the plain-text ID already does the linking) and is
never correct here.

Doing Linear-tracked work is not done until the Linear issues reflect it:
- When you open a PR that implements one or more issues, move those issues
  to **"In Review"** (not left in Backlog/Todo) and post a short comment on
  each with a plain-text mention of the PR (e.g. "Implemented in PR #10
  (`cursor/friglet-tray-ui-a38a`)") — GitHub PR URLs are fine to put in
  Linear (it's not public), just never put Linear URLs in GitHub.
- After the PR merges, move the issues to **"Done"**.
- If an issue was only partially done, or a review found it doesn't fully
  meet its acceptance criteria, say so explicitly in the issue comment and
  leave/return it in **"In Progress"** rather than marking it reviewed.
- Don't stop at "the code type-checks" — actually reflect real status.
  Silently leaving every issue in Backlog while the branch/PR claims the
  project is "done" is exactly the failure mode to avoid.

## Testing is not optional — prove it, don't just build it

"Compiles + unit tests pass" is not the same as "verified it works." For any
UI-facing or runtime-behavior change (the tray app, the daemon's runtime
behavior), actually run it and capture evidence:
- Run the real binary (not just `cargo test`) and observe/log its behavior.
- For the tray app specifically: take an actual **screenshot** of the
  running UI (window contents at minimum) and say so explicitly in the PR
  and in your summary to the user — don't just assert "should work" or
  silently skip because it's inconvenient in a headless VM.
- If something genuinely cannot be verified in this environment (e.g. the
  native tray icon needs a StatusNotifierWatcher host that bare Xvfb
  doesn't provide), say that explicitly, explain *why*, and record exactly
  what alternative verification you did instead (e.g. forced the window
  visible and screenshotted it, or ran a systray host like `snixembed` +
  `trayer` under a lightweight WM to prove the icon itself renders).
- Never let a summary go out implying full verification happened when it
  didn't. Missing/partial verification is fine to report; silently omitting
  it is not.

## Use varied subagent models for review, not just the implementer's model

When spawning subagents for independent review or verification passes,
don't default every subagent to the orchestrator's own model. Deliberately
vary the model (e.g. a different frontier model than the one doing the
main-thread orchestration) for review/verification subagents — this is
usually both cheaper and gives a genuinely independent second opinion
instead of the same model reviewing its own work.
