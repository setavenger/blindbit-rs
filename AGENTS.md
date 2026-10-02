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
  `settings` → Settings tab, `wallet` → Wallet tab after the UI loads — useful for headless /
  screenshot testing; synthetic X11 clicks do not reach WebKitGTK reliably).

### First-run setup mode (no config file yet)

- On startup (and on "Start daemon") the tray probes the socket;
  when unreachable it checks whether the daemon is plausibly configured
  BEFORE spawning (`friglet-tray/src/setup.rs::is_configured`): the default
  config file (`friglet_ipc::default_config_path()`, i.e.
  `<config dir>/friglet/config.toml`) must supply `p2p_node_addr`,
  `start_height` and `spend_pubkey` (each satisfiable via
  `FRIGLET_P2P_NODE_ADDR`/`FRIGLET_START_HEIGHT`/`FRIGLET_SPEND_PUBKEY`
  env instead), and a scan secret must exist (key file from the config's
  `key_file` or `<config dir>/friglet/scan.key`, or `FRIGLET_SCAN_SECRET`).
  `start_at_tip = true` satisfies `start_height`; a `descriptor` key (or
  `FRIGLET_DESCRIPTOR`) satisfies `spend_pubkey` + the scan secret, and its
  `bh=` annotation `start_height`.
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
  fluxbox the friglet SNI icon renders. Since SNB-656 the Linux tray is
  tray-icon's KSNI backend (feature `ksni` in `friglet-tray/Cargo.toml`), not
  libayatana: bus name `org.kde.StatusNotifierItem-<pid>-<n>`, object
  `/StatusNotifierItem`, `ItemIsMenu=false`, menu at `/MenuBar`. A host's
  left click is `Activate` (toggles the window), right click opens the menu;
  e.g. `gdbus call --session -d <name> -o /StatusNotifierItem -m
  org.kde.StatusNotifierItem.Activate 0 0`. Without a watcher the tray keeps
  running and retries the icon (2 s, doubling to 30 s).
  `snixembed` is not in Ubuntu apt; `trayer` alone only hosts legacy XEmbed
  icons, not StatusNotifierItem. xdotool clicks do not reach WebKitGTK under
  Xvfb — use `FRIGLET_TRAY_SHOW_ON_START=settings` for the Settings form.
- Hyprland popup mode (`friglet-tray/src/popup.rs`) is on whenever
  `HYPRLAND_INSTANCE_SIGNATURE` is set; its socket logic is unit-tested
  against a fake `.socket.sock` in that file. Keep the socket path under
  108 bytes (`sun_path`) when faking `XDG_RUNTIME_DIR`.

## Packaging (M4)

- Desktop bundles: `scripts/prepare-sidecar.sh` (stages
  `target/release/friglet` as `friglet-tray/binaries/friglet-<triple>`,
  gitignored), then from `friglet-tray/`:
  `npx @tauri-apps/cli@2 build --bundles deb,appimage --config
  tauri.sidecar.conf.json` (Linux) or `--bundles dmg --config
  tauri.sidecar.conf.json` (macOS host only — dmg cannot be cross-built
  from Linux). Artifacts: `target/release/bundle/{deb,appimage,dmg}/`.
- CI packaging: `.github/workflows/release.yml` (packaging only, not a
  second ci.yml). Linux deb+AppImage on `ubuntu-22.04` (glibc floor),
  macOS universal dmg on `macos-15` (`prepare-sidecar.sh
  universal-apple-darwin` lipo's both daemon slices; Tauri requires the
  sidecar to be universal too), Windows msi+nsis best effort
  (`continue-on-error`). Each job checks the daemon is inside the bundle.
  Triggers: `v*` tags and `workflow_dispatch` → DRAFT release only (tag must
  match `tauri.conf.json` version); `pull_request` is path-filtered to
  packaging files and only uploads artifacts. `TAURI_CLI_VERSION` there is
  pinned to the locked `tauri` crate version — bump both together.
- macOS bundles are ad-hoc signed (`bundle.macOS.signingIdentity: "-"`):
  arm64 needs at least an ad-hoc signature, and it turns Gatekeeper's
  "damaged" error into the bypassable "Open Anyway" prompt. User steps for
  unsigned builds: README "Opening unsigned builds".
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
  an environment limitation, not a code problem. On a real MSVC host
  (`windows-2025` in release.yml) the daemon and tray compile, link and
  bundle (msi + nsis), and the MSI's `friglet.exe --help` runs; the tray
  itself (named-pipe control, tray icon, spawning) is still unverified.

## SP descriptor onboarding (SNB-623)

- Parser: `friglet-ipc/src/descriptor.rs` (BIP-392 `sp(...)` + BIP-393 `?bh=`
  + BIP-380 checksum), shared by daemon and tray; test vectors are Sparrow
  2.5.5 / drongo fixtures. Sparrow's *Copy Output Descriptor* yields
  `sp([fp/352h/0h/0h]spscan1q…)?bh=N#cs` (`bh` only once the wallet has a
  confirmed tx). `tspscan` covers every test network, so the tray defaults
  test keys to signet.
- The scan secret never enters `DaemonConfig`: the daemon reads `descriptor`
  from the raw figment layers, folds the spend key/birthday into the
  settings and copies the scan key into the key file; the tray parses the
  descriptor in Rust and only hands the UI a summary without the secret.
- Spend-secret (`spspend`) descriptors: tray paste → public key derived,
  secret dropped, field replaced with the watch-only form; config file →
  refused (the secret would sit on disk).
- `start_at_tip`: resolved from the oracle tip at daemon start (and in
  `SetConfig`), then persisted as `start_height` by patching only that key
  in the config file (`config::persist_start_height`).
- `oracle_url` follows `network` when no layer sets it; a hosted oracle URL
  of another network is rejected. `p2p_node_addr` accepts hostnames (DNS at
  start, IPv4 preferred) and bare hosts (network default port).

## SetConfig / SetScanKey / ApplySettings semantics (SNB-624)

- The daemon validates the payload (config and/or scan key) fully before
  touching anything; invalid input → `Response::Error`, nothing persisted.
  Valid input is written (config as TOML to the file the daemon loaded or
  the default path; scan key to the 0600 key file) and, if anything
  changed, answered with `OkWithNote` and followed ~100 ms later by an
  **in-process restart**: `main` runs each daemon run on its own tokio
  runtime and drops it, so every task of the old run dies (Electrum client
  connections, the startup-time found-output/reorg subscriptions, listeners,
  scan task) and the next run re-reads the config. Same PID → the tray's
  child handle stays valid. Unchanged input → plain `Ok`, no restart.
- `ApplySettings { config, scan_key }` = SetConfig + SetScanKey with one
  validation and one restart; the tray's settings save uses it.
- Wallet-keyed state (`config::wallet_state_file`): the default state path
  becomes `scanner_state-<network>-<sha256(scan_pub‖spend_pub)[..4]>.json`
  (a legacy `scanner_state.json` of the same wallet is renamed into place);
  an explicit `state_file` holding another wallet's keys is refused at
  startup (blindbit-lib would otherwise silently restore the old keys).
- Birthday rescans (`config::reconcile_birthday`): `<state>.birthday.json`
  records the lowest start height the state covers; a lower `start_height`
  moves the state to `*.json.bak` and scans from scratch.
- A server dying (HTTP/Electrum/control bind failure) now ends the process
  with exit code 1 instead of 0, and a control socket that failed to bind
  (another daemon) is no longer deleted on the way out.
- Control-socket tests live in `friglet/src/control/mod.rs` (friglet is a
  bin crate); they build offline `Scanner`s via a lazy tonic channel and
  assert the restart via `ControlCtx::restart_requested` + the cancelled
  shutdown token. `GetStatus` uses tonic to poll the oracle tip (cached
  ~10s) for `tip_height`.

## Tray supervision + autostart (SNB-624, SNB-52)

- `lifecycle::Supervision` is a pure state machine (backoff 1 s doubling to
  60 s, reset after 60 s healthy); `lib.rs::supervise_tick` runs it from
  the 1 s poller: reaps an exited child (exit status + last output lines →
  `ExitReport`), presumes a no-handle owned daemon dead after 15 s silence
  and a wedged child after 120 s, and restarts via `attach_and_record`.
  `AppState.supervise` is off for external daemons and in setup mode;
  `quitting` stops it during Quit. `get_status` carries `daemon`
  (`DaemonHealth`) for the Status tab's crash card.
- Stop daemon / Start daemon (SNB-658): `stop_daemon_now` sets
  `AppState.stopped` and turns supervision off *before* sending `Shutdown`,
  so the supervisor never undoes it; a reaped child with exit status 0 is
  recorded as stopped too (not restarted). Works for attached external
  daemons (waits for the socket to go quiet, then checks no service manager
  started a new one). `start_daemon_now` clears `stopped` and reruns
  attach-or-spawn.
- What the window and menu show is computed in `friglet-tray/src/view.rs`
  (pure, unit-tested): `scan_view` (scanning / up to date / waiting /
  stopping / paused / error), `daemon_view` (running / starting / stopping /
  stopped / reconnecting / unreachable / restarting / setup, plus who started
  it) and the `ErrorBook` (active errors until resolved + recent list, each
  raised/resolved error logged). Stalls and oracle outages are "waiting" for
  `STALL_GRACE_SECS` (120 s), an unanswering daemon "reconnecting" for
  `UNREACHABLE_GRACE_SECS` (10 s), then errors.
- Daemon scan pause (SNB-658): `ScanSupervisor` keeps the task entry until
  the task has really ended (`ScanState::Stopping` while blindbit-lib's
  blocking P2P block download finishes), `Stop` answers within 3 s
  (`OkWithNote("stopping: ...")` when still winding down), `Start` during
  stopping is refused, and the pause flag survives an in-process restart.
  `GetStatus` never touches the network: the oracle tip comes from a
  background poller (`control::spawn_oracle_poller`).
- Logs: `friglet_ipc::logfile` (`RotatingLog`, 10 MiB cap, 2 rotations);
  daemon `friglet.log` (`FRIGLET_LOG_FILE` override / `off`), tray
  `friglet-tray.log`, both in `$XDG_STATE_HOME/friglet` (macOS
  `~/Library/Logs/friglet`, Windows `%LOCALAPPDATA%\friglet\logs`).
- Autostart: `tauri-plugin-autostart` (XDG autostart `.desktop` /
  LaunchAgent / Run key), commands `get_autostart`/`set_autostart`; first-run
  setup passes `autostart` to `save_local_config` (default ticked).

## Wallet status fields

- `StatusInfo` includes restart-safe `tx_count`, `outputs_found`, and
  `label_addresses`; the tray's Wallet tab also uses the existing
  `sp_address`. New fields use serde defaults for older daemon payloads.
- `tx_count` comes from the rebuilt Electrum index's `sp_history`.
  `outputs_found` is seeded from the persisted state JSON's `owned_outputs`
  array and then updated from an independent scanner broadcast receiver.
- Label addresses are derived in `friglet` from the scan secret with the
  `bdk_sp` encoding crate pinned to the same git revision already locked for
  `blindbit-lib`. Labels are the scanner's inclusive `0..=max_label_num`
  range and are recomputed whenever the scanner is rebuilt.

## Daemon spawn diagnostics (tray lifecycle)

`friglet-tray/src/lifecycle.rs`'s `spawn_daemon` pipes (rather than
`Stdio::null()`s) the spawned `friglet` child's stdout/stderr and drains them
continuously in a background task — both to avoid the daemon blocking once
it logs enough to fill an unread pipe buffer, and so that a daemon that
exits immediately after spawning (stale binary predating the current CLI,
missing config/key file, bad address, ...) surfaces its actual error message
in the "Daemon: unreachable" reason instead of a bare, undiagnosable exit
code. Captured lines are ANSI-stripped before logging (`friglet-daemon`
target) and before inclusion in spawn-failure reasons. The tray does **not**
inherit its own `RUST_LOG` into the child: set `FRIGLET_DAEMON_RUST_LOG` to
control daemon verbosity when spawned by the tray; otherwise `RUST_LOG` is
cleared so the daemon uses its config `log_level` (info by default). The
daemon itself only emits ANSI when stderr is a TTY. If you see
`spawned daemon exited immediately (exit status: 2)` with no further detail,
you're looking at a build that predates this fix, or a release binary with
stdio still swallowed — rebuild `friglet-tray` and check the captured reason
text (the daemon's lines are forwarded to the tray's stderr at their own
level, target `friglet-daemon`, and the daemon also writes
`~/.local/state/friglet/friglet.log`) before guessing
at the cause. Exit code 2 from a Rust CLI built with `clap` almost always
means clap itself rejected the arguments (rare here, since the daemon runs
with zero args) or — far more likely in practice — a stale
`target/release/friglet` predating this branch's optional-subcommand/config-file
support; run `cargo build --release --workspace` (or at least `-p friglet`)
after pulling changes that touch the daemon's CLI.

### Default state file

Scanner state defaults to `<platform config dir>/friglet/scanner_state.json`
(same directory as `config.toml` / `scan.key`), not a CWD-relative path:
- Linux: `~/.config/friglet/scanner_state.json` (or `$XDG_CONFIG_HOME/...`)
- macOS: `~/Library/Application Support/friglet/scanner_state.json`
- Windows: `%APPDATA%\friglet\scanner_state.json`

Override with `--state-file` / `FRIGLET_STATE_FILE` / `state_file` in the
config TOML.

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
