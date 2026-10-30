# AGENTS.md

Rust Cargo workspace (edition 2024) for BlindBit BIP-352 Silent Payments. Crates: `blindbit-lib` (core scanner + gRPC oracle client), `friglet` (daemon: scanner + Electrum + control socket), `friglet-ipc` (control-socket protocol, shared by daemon and tray), `friglet-tray` (Tauri v2 tray UI), `blindbit-cli` (one-shot range scan, no servers). See `README.md` for full flags/usage.

## Toolchain and system packages

- Rust **stable >= 1.90**: friglet-tray's Tauri crates declare `rust-version = "1.90"`, and friglet uses let-chains (stable since 1.88). In the Cursor VM the default toolchain is `stable`; its preinstalled `1.83.0` cannot build this.
- `protoc` is required: `blindbit-lib/build.rs` compiles `blindbit-lib/proto/*.proto` with `tonic-prost-build`; `libprotobuf-dev` provides the `google/protobuf/*.proto` files they import.
- apt packages (need `sudo`; the Cursor VM snapshot already has them):
  - Build and test the workspace: `libwebkit2gtk-4.1-dev libgtk-3-dev pkg-config protobuf-compiler libprotobuf-dev`
  - Release bundles (`tauri build`, see Packaging): `release.yml` additionally installs `libayatana-appindicator3-dev librsvg2-dev libssl-dev patchelf xdg-utils`
  - Headless tray screenshots: `xvfb xdotool` (plus the tools listed in the recipe below)
  - Windows cross-check: `mingw-w64` + `rustup target add x86_64-pc-windows-gnu`
  - Containers: `docker.io`; Rust components: `clippy`, `rustfmt`
- If a fresh Cursor env lacks these, regenerate its environment config via the env setup agent at `cursor.com/onboard`; the startup update script only runs `cargo fetch`.

## Build & test

```bash
cargo build --workspace            # all crates, incl. friglet-tray (Tauri v2)
cargo test --workspace
cargo clippy --no-deps -p friglet -p friglet-ipc -p friglet-tray --all-targets -- -D warnings   # CI's lint
cargo fmt --all -- --check
```

- CI (`.github/workflows/ci.yml`) runs the test and clippy lines.
- `blindbit-lib` has unit tests in `src/scanner/` (some need its `serde` feature, which `cargo test --workspace` turns on through friglet). `blindbit-cli` has none. `friglet`, `friglet-ipc` and `friglet-tray` have unit and integration tests.
- `blindbit-lib` is not clippy-clean and there is no clippy config: do not fix its pre-existing clippy warnings unless asked; scope `clippy` with `-p` as above. The whole workspace is fmt-clean, so `cargo fmt --all` is safe.

## Running against signet

- E2E needs two **external** services: a BlindBit Oracle (signet: `https://signet.oracle.setor.dev`) and Bitcoin P2P: an own node (signet: `152.53.151.148:38333`) or, with `p2p_node_addr` empty, random peers found through the network's DNS seeds (signet seeds resolve from the VM; the VM has no IPv6 route, so IPv6 peers are skipped after the first try). Both are reachable from the VM. No DB.
- Keys are BIP-352 hex: `--scan-secret` (32-byte secp256k1 secret), `--spend-pubkey` (33-byte compressed pubkey). For smoke tests any valid pair works, e.g. secret `0000...0001` and pubkey `0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798` (no outputs, balance 0).
- Fast check, ~1 s for 50 blocks:
  ```bash
  cargo run -p blindbit-cli -- scan --network signet \
    --scan-secret 0000000000000000000000000000000000000000000000000000000000000001 \
    --spend-pubkey 0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798 \
    --start-height 274010 --end-height 274060 \
    --p2p-node-addr 152.53.151.148:38333 \
    --oracle-url https://signet.oracle.setor.dev \
    --state-file blindbit-test/cli-state.json
  ```
  `--end-height` is required; `--p2p-node-addr` must be `ip:port` (hostnames only with `--p2p-proxy`) and may be left out (random peers; not on regtest); the state file defaults to `scanner_state.json` in the working directory; it is loaded at start and saved at the end, and the given range is scanned either way.
- `friglet scan` from `--start-height 274010` to the signet tip is ~50k blocks (minutes); use blindbit-cli for quick checks.
- State persists to a JSON file (`--state-file`).

### Checking a running daemon

- Control socket (preferred; newline-delimited JSON, `friglet-ipc` protocol): set `FRIGLET_SOCKET="${FRIGLET_CONTROL_SOCKET:-${XDG_RUNTIME_DIR:-${XDG_DATA_HOME:-$HOME/.local/share}/friglet}/friglet.sock}"`, then `printf '"GetStatus"\n' | nc -U -w 2 "$FRIGLET_SOCKET"`. This honors the environment override and selects the usual Linux default even without `XDG_RUNTIME_DIR`; when the config's `control_socket` key overrides that path, set `FRIGLET_SOCKET` to its value instead. `GetStatus` never waits on the network.
- Electrum (`127.0.0.1:50001` by default): `printf '{"id":1,"method":"server.version","params":["x","1.4"]}\n' | nc -w 2 127.0.0.1 50001` returns `["Friglet","1.4"]`; `blockchain.headers.subscribe` returns the latest scanned height.

## Running friglet-tray

- `cargo run -p friglet-tray` — no npm/frontend build step; the UI is plain
  static HTML/CSS/JS in `friglet-tray/ui/` (tauri.conf.json `frontendDist`).
  The status window's Settings tab loads with `GetConfig` and saves with
  `ApplySettings` (config and optional scan key in one request) over the
  control socket; the fake daemon answers `GetConfig`, `SetConfig`,
  `SetScanKey` and `ApplySettings` in memory.
- Fake daemon for manual testing (speaks the `friglet-ipc` protocol on the
  default control socket): `cargo run -p friglet-tray --example fake-daemon`.
- Useful env vars: `FRIGLET_CONTROL_SOCKET` (socket path override; the
  config-file equivalent is `control_socket`),
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
  `<config dir>/friglet/config.toml`) must supply `start_height` and
  `spend_pubkey`, plus `p2p_node_addr` only on regtest (network from
  `FRIGLET_NETWORK` or the file, default bitcoin;
  `friglet_ipc::network::needs_own_node`) (each satisfiable via
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
  Settings tab with the banner (window screenshot via
  `import -window "$(xdotool search --name "Friglet Status" | head -1)"`).
  Unit/e2e coverage: `friglet-tray/src/setup.rs` tests, the
  `setup_required_*` cases in `friglet-tray/tests/lifecycle_e2e.rs`, and
  the setup-mode tests in `friglet-tray/src/lib.rs`.
- Tray/bundle icons are a small sailing ship (friglet is a little Frigate),
  drawn by `friglet-tray/icons/generate.py`; regenerate with
  `python3 friglet-tray/icons/generate.py` (stdlib only).

## Tray testing under headless / computer-use environments

Works in this repo's cloud VM (Xvfb + fluxbox + StatusNotifier host):

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
  fluxbox the friglet SNI icon renders. The Linux tray uses tray-icon's KSNI
  backend (feature `ksni` in `friglet-tray/Cargo.toml`), not
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
  second ci.yml). Linux deb+rpm+AppImage for x86_64 on `ubuntu-22.04` and
  arm64 on `ubuntu-22.04-arm` (glibc floor; native, no QEMU), then
  `linux-install` installs each bundle in clean distro containers
  (Ubuntu 22.04/24.04, Debian 12/13, Fedora, openSUSE Tumbleweed, Arch via
  AppImage; arm64: Ubuntu 24.04, Fedora) and waits for the first-run
  setup window under Xvfb (`scripts/linux-install-check.sh`). macOS universal dmg on `macos-15` (`prepare-sidecar.sh
  universal-apple-darwin` lipo's both daemon slices; Tauri requires the
  sidecar to be universal too), Windows msi+nsis best effort
  (`continue-on-error`). Each job checks the daemon is inside the bundle.
  Triggers: only `vX.Y.Z` tags (must equal the `tauri.conf.json` version)
  → DRAFT release, and manual `workflow_dispatch` → build + checks only,
  bundles left as run artifacts; no push or pull_request triggers (the
  user's rule). Manual runs used to draft a `friglet-tray-dev-<sha>`
  release, but the GITHUB_TOKEN got HTTP 403 creating that new tag on a
  branch commit. `TAURI_CLI_VERSION` there is
  pinned to the locked `tauri` crate version — bump both together.
- macOS signing (README "macOS signing"): with all five `APPLE_*` repo
  secrets set, the build step exports them for Tauri, which imports the
  Developer ID cert into a throwaway keychain, signs sidecar + app with the
  hardened runtime, notarizes + staples the app and signs the dmg; the
  next step notarizes + staples the dmg (Tauri doesn't), and the check
  step requires `spctl` "Notarized Developer ID" for app and dmg. With
  none set: ad-hoc (`bundle.macOS.signingIdentity: "-"`; arm64 needs at
  least an ad-hoc signature, and it turns Gatekeeper's "damaged" error into
  the bypassable "Open Anyway"); some set: the job fails. Tauri treats a
  set-but-empty `APPLE_*` var as set, so never map secrets straight into
  `APPLE_*` env. `APPLE_SIGNING_IDENTITY="Developer ID Application"` is a
  substring match that overrides the config's `"-"`. User install steps:
  README "Installing a release".
- The daemon is a Tauri sidecar (`bundle.externalBin`), but it lives in the
  `tauri.sidecar.conf.json` overlay, NOT the base `tauri.conf.json`:
  tauri-build errors at compile time when an externalBin file is missing,
  which would break plain `cargo build/test --workspace` on fresh clones.
  The sidecar file needs the target-triple suffix or the build fails with
  "resource path ... doesn't exist". Both deb and AppImage place `friglet`
  next to `friglet-tray` in `usr/bin/`, which the lifecycle search order
  (env → exe dir → PATH) covers.
- Smoke-testing a bundle headless: run the installed `.deb`'s tray under
  `xvfb-run -a dbus-run-session`; run the AppImage with
  `--appimage-extract-and-run` (a plain AppImage mount needs FUSE).
- AppImage bundling downloads linuxdeploy/appimagetool at build time —
  needs network; the deb target has no such dependency.
- Docker: root `Dockerfile` (multi-stage; builder needs `protobuf-compiler`
  AND `libprotobuf-dev`) + `docs/docker.md`. The image presets
  `FRIGLET_ELECTRUM_ADDR` to a `0.0.0.0` bind (env beats config file, loses
  to flags) and puts the config, key file, control socket and log under the
  `/data` volume. The scanner state is NOT under
  `/data` by default (SNB-635): the default lands in
  `/home/friglet/.config/friglet/` inside the container. Workaround: an
  absolute `state_file = "/data/scanner_state.json"` in `config.toml`.
  Building images in the nested VM container needs dockerd with
  `--storage-driver=vfs` (overlayfs fails there).
- Windows: `cargo check -p friglet-ipc -p friglet -p friglet-tray
  --target x86_64-pc-windows-gnu` (needs mingw-w64) is the compile check
  from Linux. The `x86_64-pc-windows-msvc` target cannot be checked from
  Linux — the `ring` and `secp256k1-sys` build scripts need MSVC's
  `lib.exe`. On a real MSVC host (`windows-2025` in release.yml) the daemon
  and tray compile, link and bundle (msi + nsis), and the MSI's
  `friglet.exe --help` runs; the tray itself (named-pipe control, tray
  icon, spawning) is unverified.

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
- `start_at_tip`: resolved from the oracle tip at daemon start (and when
  `SetConfig`/`ApplySettings` is applied), then persisted as `start_height`
  by patching only that key in the config file (`config::persist_start_height`).
- `oracle_url` follows `network` when no layer sets it; a hosted oracle URL
  of another network is rejected. `p2p_node_addr` accepts hostnames (DNS at
  start, IPv4 preferred) and bare hosts (network default port); empty or
  unset = random peers (refused on regtest).

## P2P peers: own node or discovery (SNB-855)

- `blindbit-lib/src/net/`: `PeerSource` (`OwnNode` | `Discovered(PeerPool)`)
  decides every P2P connection; `Dialer` opens the TCP stream (the seam for a
  proxy); `Seeds::for_network` = kernel-node's DNS seed lists (`x9.` first),
  regtest none. friglet `main.rs` builds one `Arc<PeerSource>` and hands it
  to the scanner (`ScannerConfig.peers`), the Electrum server and `GetStatus`
  (`StatusInfo.p2p`, the tray's "Blocks from" row).
- Own node: every connection goes to it; no DNS, no `getaddr`; retries,
  timeouts and error wording are the pre-855 ones.
- Discovered: `bitcoin-address-book` new/tried tables (Kyoto's sizes). A
  block fetch asks up to 8 different peers (`RetryPolicy::discovered`),
  requires `NETWORK|WITNESS`, skips peers below the block height, ignores a
  peer that sends a bad/stripped block for the session, prefers the peer
  that served the last block, and asks for addresses while < 200 are known.
  Headers try up to 3 peers; `blockchain.relayfee` is the median of fresh
  feefilters from >= 3 (up to 5) peers, sampled at Electrum start, the lowest
  until then. Broadcast (SNB-856, `friglet/src/electrum/net_broadcast.rs`):
  3 observers (relay=true, settled, their version relays txs) first, then 2
  senders (relay=false, inv → getdata → tx → ping/pong, then listen), all in
  distinct netgroups (`PeerAddr::netgroup`: /16, /32); success only when an
  observer serves the tx, rejection only when every sender gave the same
  signal; rechecks ask 2 peers outside `PendingTx.sent_to` and hand a lost tx
  to one of them. Own node: `relay::broadcast`/`recheck`, unchanged. DNS seed
  answers must be public IPs; gossip may name local IPs only when it comes
  from a local peer, and only the network's port or ports >= 1024.
- Tests: `blindbit-lib/src/net/pool_tests.rs` (pure),
  `scanner/discovery_tests.rs` (fake nodes on 127.0.0.x; not on macOS),
  broadcast scenarios in `friglet/src/electrum/net_broadcast.rs` and
  `electrum::tests::discovered` (`FakeNet` peers on 127.N.0.1, one /16 each;
  the address book hashes deterministically, so a slot collision fails
  `known() == n` every time: move the addresses),
  `blindbit-lib/tests/thread_soak.rs` (Linux; thread count after 50
  fetches). `fetch_block` example: peer `dns` = discovery.
- Address book on disk (daemon only): `PeerSource::keep_book_in(<state file
  dir>)` loads `peers-<network>-{new,tried}.book` (`bitcoin-address-book`
  `io::FileExt` format, read back record by record because `Table` cannot
  list them); saved every 10 min when changed and at exit; unreadable file
  → warning, ignored. `start()` seeds only while < 50 addresses are known.

## Tor / SOCKS5 (`p2p_proxy`, SNB-857)

- `p2p_proxy` (`--p2p-proxy`, `FRIGLET_P2P_PROXY`, TOML, tray field "Tor
  proxy"): `ip:port` or `localhost:port` (`friglet_ipc::network::
  parse_proxy_addr`; other host names refused, so finding the proxy needs no
  DNS). Set → `Dialer::Socks5 { proxy }` for every P2P connection (scanner,
  Electrum headers/relay/broadcast); fail-closed: never a direct connection,
  also when the proxy is down. The oracle (gRPC) is not proxied.
- `blindbit-lib/src/net/socks5.rs`: blocking RFC 1928/1929 client; offers
  NOAUTH + USERPASS with random credentials per connection (Tor stream
  isolation); host names go as `ATYP` domain. `net::is_proxy_down(&io::Error)`
  tells the proxy failing (unreachable, not SOCKS5, login refused) from the
  peer failing (reply codes → readable `io::ErrorKind`s). Proxy down →
  `FetchFailure::Proxy`: the round ends at once, no peer is blamed, and the
  message names `p2p_proxy`; Electrum header requests do the same.
- No local DNS through the proxy: `ResolvedConfig.p2p_node` is a `PeerAddr`
  whose host name stays a name (resolved locally only without a proxy; an
  `.onion` node without a proxy is a config error); `Seeds::resolve` with a
  proxy connects to `x9.<seed>` (then the bare name) of 3 random seeds
  through it, handshakes with `getaddr` and keeps the `addr`/`addrv2` answer
  (≤ 20 s). The tray's Save does a 2 s TCP check of the proxy instead of a
  DNS lookup of the node.
- Through a proxy: connect ≥ 20 s (`PROXY_CONNECT_TIMEOUT`, enforced in the
  dialer), block deadline ≥ 60 s (`RetryPolicy::through_proxy`). Tor keeps
  trying a dead address for the whole connect timeout, so a discovered-peer
  fetch races `PROXY_RACE` (3) connects at once and uses the first to open
  (the losers finish on blocking threads within the timeout), and a seed
  node's addresses enter the book most recently seen first (half of a
  signet node's `getaddr` answer is > 5 days old).
- Broadcast through a proxy (`net_broadcast.rs` `Timing::PROXIED`): 6
  observer connects at the start (3 directly), observer window 15 s, limit
  30 s, 12 observer tries; budget `PROXIED_BROADCAST_BUDGET` 45 s
  (`electrum/mod.rs`; Sparrow's requests end at ~3, 12, 29, 64, 99 s, so
  the answer lands in the fourth). Each sender/observer is its own SOCKS
  login (own circuit). Proxy down → `Event::ProxyDown`, no peer blamed,
  error names `p2p_proxy`. `ask_mempools` races 2 extra connects through a
  proxy. Senders keep listening after the pong (bounded by the budget).
- An older tray drops `p2p_proxy` on Save (unknown field); the daemon logs a
  warning when an apply clears it.
- Tests: `net/socks5.rs` (reply codes, credentials per connection, proxy
  down / not SOCKS5), `net/proxy_tests.rs` (seeding by name, no local
  lookup), `scanner/proxy_tests.rs` (own node `node.invalid` through the
  proxy, proxy down/refusing → no direct connection), `electrum/chain.rs`
  (headers through the proxy); `scanner/proxy_tests.rs` also races past
  stalled peers. `net::testing::FakeSocks5` (feature
  `test-util`, on in friglet's dev-dependencies) routes names to local
  listeners and records methods, credentials and targets. Closed-proxy tests
  use 127.0.0.1:1 (a port freed by dropping a listener can be taken by a
  parallel test).
- Live: no system Tor on the VM; run it in Docker (`debian:stable-slim` +
  `apt-get install tor`, `SocksPort 0.0.0.0:9050`, published as
  `-p 127.0.0.1:9050:9050`), then `fetch_block … signet --proxy
  127.0.0.1:9050`.

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
- State file (`config::wallet_state_file`): the default is
  `<config dir>/friglet/scanner_state-<network>-<sha256(scan_pub‖spend_pub)[..4]>.json`
  (config dir: Linux `~/.config` or `$XDG_CONFIG_HOME`, macOS
  `~/Library/Application Support`, Windows `%APPDATA%`); a legacy
  `scanner_state.json` of the same wallet is renamed into place. A bare
  `state_file = "scanner_state.json"` counts as the default. Override with
  `--state-file` / `FRIGLET_STATE_FILE` / `state_file`; an explicit path is
  used as given, and one holding another wallet's keys is refused at
  startup (blindbit-lib would otherwise silently restore the old keys).
- Birthday rescans (`config::reconcile_birthday`): `<state>.birthday.json`
  records the lowest start height the state covers; a lower `start_height`
  moves the state to `*.json.bak` and scans from scratch.
- A dead Electrum or control-socket server (e.g. bind failure) ends the
  process with exit code 1; a control socket that failed to bind (another
  daemon owns it) is left in place.
- Control-socket tests live in `friglet/src/control/mod.rs` (friglet is a
  bin crate); they build offline `Scanner`s via a lazy tonic channel and
  assert the restart via `ControlCtx::restart_requested` + the cancelled
  shutdown token.

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
  background poller (`control::spawn_oracle_poller`, every 10 s).
- Logs: `friglet_ipc::logfile` (`RotatingLog`, 10 MiB cap, 2 rotations);
  daemon `friglet.log` (`FRIGLET_LOG_FILE` override / `off`), tray
  `friglet-tray.log`, both in `$XDG_STATE_HOME/friglet` (macOS
  `~/Library/Logs/friglet`, Windows `%LOCALAPPDATA%\friglet\logs`).
  Console output goes to stdout for both: the daemon colours it when stdout
  is a terminal; the tray also prints the daemon output it forwards
  (target `friglet-daemon`), which is not written to `friglet-tray.log`.
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

- `friglet-tray/src/lifecycle.rs`'s `spawn_daemon` pipes the child's
  stdout/stderr and drains them continuously, so the daemon never blocks on
  a full pipe and a daemon that exits right after spawning shows its own
  error in the "Daemon: unreachable" reason. Lines are ANSI-stripped and
  re-logged at their own level under target `friglet-daemon`; the daemon
  also writes its own `friglet.log`.
- The tray does **not** pass its `RUST_LOG` to the child: set
  `FRIGLET_DAEMON_RUST_LOG` to control daemon verbosity; otherwise the
  daemon uses its config `log_level` (info by default).
- An immediate exit with status 2 is clap rejecting the arguments, most
  likely a stale `friglet` binary (search order: `FRIGLET_DAEMON_BIN` →
  next to the tray → `PATH`); rebuild it after pulling changes to the
  daemon's CLI.

## Rules

- Do NOT modify `blindbit-lib` (or `blindbit-cli` / Electrum behavior)
  in tray-project work; the tray talks to the daemon only via `friglet-ipc`.

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
