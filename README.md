# BlindBit Rust

A Rust implementation of the BlindBit suite for Bitcoin BIP-352 Silent Payments.

## Overview

BlindBit is a comprehensive software suite for Bitcoin BIP-352 Silent Payments. This Rust implementation provides the core libraries and tools for scanning Bitcoin blocks to detect silent payments, integrating with the broader BlindBit ecosystem that includes indexers, scanners, and wallets.

## Features

- **Silent Payments Scanning**: Detects BIP-352 silent payments in Bitcoin transactions
- **BlindBit Oracle Integration**: Connects to BlindBit Oracle services for efficient blockchain data access
- **State Persistence**: Saves and restores scanner state for incremental scanning
- **Electrum Server**: Exposes a local Electrum TCP interface for wallet compatibility (e.g. Sparrow)
- **HTTP API**: Lightweight HTTP server exposing scanner state and subscription endpoints
- **Multi-Network Support**: Works with Bitcoin mainnet, signet, testnet, testnet4, and regtest
- **Privacy-Preserving**: Scanner queries reveal only general interest in Silent Payments, not specific keys or transactions

## Workspace Structure

This is a Cargo workspace containing the following crates:

- **blindbit-lib**: Core library containing the scanning logic and gRPC client
- **friglet**: Lightweight scanner compatible with Frigate's Silent Payments endpoints, with built-in Electrum and HTTP servers
- **friglet-ipc**: Shared IPC protocol (control socket) between the friglet daemon and its clients
- **friglet-tray**: System tray companion app for the friglet daemon (Tauri v2)
- **blindbit-cli**: Minimal command-line interface for scanning (no server functionality)

## Usage

### friglet (Recommended)

`friglet` is the recommended tool. It scans Bitcoin blocks for Silent Payments and exposes both an Electrum TCP server and an HTTP API, making it compatible with wallets like Sparrow via Frigate.

```bash
cargo run --release --package friglet scan \
  --network signet \
  --scan-secret <SCAN_SECRET_KEY> \
  --spend-pubkey <SPEND_PUB_KEY> \
  --start-height 274010 \
  --p2p-node-addr 152.53.151.148:38333 \
  --oracle-url 'https://signet.oracle.setor.dev' \
  --max-label-num <NUM_OF_LABELS> \
  --state-file <PATH_TO_STORE_SCANNER_DATA>
```

#### Parameters

| Flag | Description | Default |
|------|-------------|---------|
| `--scan-secret` | Scan secret key (32-byte hex, secp256k1) | required |
| `--spend-pubkey` | Spend public key (33-byte hex, secp256k1) | required |
| `--start-height` | Wallet birthday block height | required (or `--start-at-tip`) |
| `--start-at-tip` | New wallet: use the oracle's current tip as the birthday (recorded as `start_height` in the config file on first start) | off |
| `--p2p-node-addr` | Bitcoin P2P node: `host:port`, `ip:port`, or a bare host (network default port); hostnames are resolved at every start | required |
| `--oracle-url` | BlindBit Oracle URL | hosted oracle of `--network` (mainnet `https://oracle.setor.dev`, signet `https://signet.oracle.setor.dev`; none for other networks) |
| `--network` | Bitcoin network: `bitcoin\|signet\|testnet\|testnet4\|regtest` | `bitcoin` |
| `--max-label-num` | Maximum number of Silent Payment labels | `0` |
| `--state-file` | Path to persist scanner state | `<config dir>/friglet/scanner_state.json` |
| `--http-addr` | HTTP server bind address | `127.0.0.1:8080` |
| `--electrum-addr` | Electrum TCP server bind address | `127.0.0.1:50001` |

#### Configuration

Every flag above can also come from a TOML config file or environment
variables. Precedence: **CLI flags > `FRIGLET_*` env vars > config file >
defaults**. With a complete config file, `friglet` (or `friglet scan`) starts
with no flags at all.

- Config file: `~/.config/friglet/config.toml` (Linux),
  `~/Library/Application Support/friglet/config.toml` (macOS), or `--config <path>`.
  Keys match the flag names (`oracle_url`, `p2p_node_addr`, `start_height`, ...).
- Env vars: flag name upper-cased with the `FRIGLET_` prefix, e.g.
  `FRIGLET_ORACLE_URL`, `FRIGLET_START_HEIGHT`.
- `--print-config` prints the merged configuration as TOML and exits.

Instead of the hex keys, the config can name the wallet by its Silent
Payments descriptor as Sparrow exports it (BIP-392; in Sparrow: wallet
**Settings** tab → right-click **Descriptor** → **Copy Output Descriptor**):

```toml
network = "signet"            # spscan… = mainnet, tspscan… = a test network
descriptor = "sp([0f056943/352h/1h/0h]tspscan1q…)#7eve6al9"
p2p_node_addr = "signet-node.example:38333"
```

`descriptor` (or `FRIGLET_DESCRIPTOR`) supplies `spend_pubkey`, the scan key
(copied into the key file on startup) and, via its `?bh=` annotation,
`start_height` when that is unset. It is never echoed back by `GetConfig` or
`--print-config`. A descriptor holding the spend **private** key
(`spspend…`) is refused — friglet is watch-only and will not keep that key
on disk.

The scan secret is kept out of the config file. It is read from, in order:
`--scan-secret` (deprecated), `FRIGLET_SCAN_SECRET`, or the key file at
`<config dir>/friglet/scan.key` (override with `key_file` / `--key-file`).
When the secret is supplied via flag or env and no key file exists yet, it is
written there with `0600` permissions so subsequent runs need no secret on
the command line. Note: the scanner state file also contains the secret
(required for restore); friglet keeps it at `0600`.

While running, the daemon serves a control socket (newline-delimited JSON,
see the `friglet-ipc` crate) for status, start/stop scanning, and shutdown.
Default socket: `$XDG_RUNTIME_DIR/friglet.sock` (Linux),
`~/Library/Application Support/friglet/friglet.sock` (macOS),
`\\.\pipe\friglet` (Windows); override with `FRIGLET_CONTROL_SOCKET`.

#### HTTP API

Once running, `friglet` exposes the following endpoints on `--http-addr`:

| Endpoint | Description |
|----------|-------------|
| `GET /height` | Returns the last scanned block height as `{"height": <n>}` |
| `GET /subscribe` | Returns the current scanner state in Frigate-compatible format |

#### Electrum Server

The built-in Electrum server (bound to `--electrum-addr`) allows wallets such as Sparrow to connect directly and query Silent Payment UTXOs without any additional infrastructure.

What to expect from it:

- **New blocks** are announced with the real header of the tip block. friglet
  asks the oracle which block is at the scanned height and fetches that
  block's 80-byte header from the P2P peer.
- **Broadcasting** succeeds only once the P2P peer (`--p2p-node-addr`) has the
  transaction in its mempool, which usually takes 5–10 seconds. Otherwise
  Sparrow shows an error. The P2P protocol does not say why a peer refuses a
  transaction. friglet reports what it can tell: missing or spent inputs, a
  fee below the peer's mempool minimum, or a dropped connection, which means
  the transaction is invalid. Broadcasts that have not confirmed are kept in
  `<state file>.pending.json`. While they are pending, friglet re-announces
  them whenever the peer's mempool loses them, including after a restart. It
  stops when they confirm or when a conflicting transaction confirms.
- **Fees**: friglet has no fee estimator. It answers `blockchain.estimatefee`
  with `-1`, the Electrum protocol's "no estimate". Its relay fee is the
  minimum fee rate that the P2P peer's mempool currently accepts. Keep
  Sparrow's fee rate source on an external service (mempool.space by
  default), or set fee rates by hand.

---

### Tray app (friglet-tray)

`friglet-tray` is a small Tauri v2 system tray app that supervises and
monitors the `friglet` daemon over its control socket. It shows live status
(scan height, progress, network, Electrum clients, oracle connectivity, SP
address, errors) in the tray menu and in a status window (hidden by default,
opened via the tray menu; closing it hides it again). The tray menu also
offers Start/Stop scanning and Quit.

The window's **Settings** tab lets you view and edit all daemon settings —
network, oracle URL, P2P node address, start height, scan key, spend pubkey,
max labels, HTTP/Electrum bind addresses, state and key file paths. Saving
sends the config to the daemon, which validates it, persists it to its config
file (and the scan key to the 0600 key file) and applies it: scan settings
restart the scan task immediately, while bind-address changes take effect on
the next daemon restart (the UI surfaces the daemon's note about this). The
scan key is write-only — it is never displayed and only sent when you type a
new one.

The **Wallet** tab is a read-only convenience view, not a spending wallet. It
shows found transaction/output counts plus copyable base and per-label Silent
Payments addresses.

```bash
# build (Linux needs the Tauri v2 system deps: libwebkit2gtk-4.1-dev,
# libayatana-appindicator3-dev, librsvg2-dev, libgtk-3-dev)
cargo build --release -p friglet-tray

# run
./target/release/friglet-tray

# optional: show the status window immediately (normally hidden until
# opened from the tray menu — useful for headless / screenshot testing).
# Values: 1/true/yes/on/status → Status tab; settings → Settings tab;
# wallet → Wallet tab.
FRIGLET_TRAY_SHOW_ON_START=1 ./target/release/friglet-tray
```

**First run** — no manual config file needed: launch the tray, and if no
daemon is running and none is configured yet (no `config.toml`, no
`FRIGLET_*` env), the window opens automatically on the Settings tab with a
first-time-setup banner. Then:

1. In Sparrow, open the Silent Payments wallet, go to its **Settings** tab,
   right-click the **Descriptor** field and choose **Copy Output
   Descriptor**. Paste it into *Sparrow wallet descriptor*. The tray picks
   the network (mainnet for `spscan…`, signet for `tspscan…` unless another
   test network is selected) and the matching hosted oracle, and shows the
   wallet's SP address to compare with Sparrow's Receive tab. A pasted
   `spspend…` descriptor (spend private key) is reduced to its watch-only
   form on the spot; the private key is never stored.
2. *Wallet birthday*: **New wallet** starts at the current chain tip
   (nothing to rescan; the daemon records the tip as `start_height` on
   first start). **Existing wallet** scans from the block height you enter
   (pre-filled when the descriptor carries Sparrow's `?bh=` birth height).
3. *Bitcoin node*: any reachable node of that network, `host:port` or just
   `host`.

Save validates the form (including a DNS lookup of the node), writes the
config file (atomic TOML at the platform default path, e.g.
`~/.config/friglet/config.toml` on Linux or
`~/Library/Application Support/friglet/config.toml` on macOS) and the scan
key file (0600), then starts the daemon with it. The hex key fields are
still available under *Advanced*.

Lifecycle behavior:

- **Attach, spawn, or set up**: on startup the tray probes the control
  socket. If a daemon answers, the tray attaches to it. If not, and the
  daemon is not plausibly configured (required settings missing from the
  config file / `FRIGLET_*` env, or no scan key), it enters the first-run
  setup mode described above instead of spawn-failing. Otherwise it spawns
  the `friglet` binary (search order: `FRIGLET_DAEMON_BIN` env var, then
  `friglet` next to the tray executable, then `friglet` on `PATH`) and
  retries the socket for a few seconds. If nothing comes up the tray keeps
  running, shows "Daemon: unreachable" (or "Setup required — open window"),
  and a "Retry / Start daemon" menu item retriggers the whole logic.
- **Quit rule**: if the tray spawned the daemon, Quit sends `Shutdown` over
  the control socket (killing the child as a fallback) before exiting. If the
  tray merely attached to a daemon it did not spawn, Quit leaves the daemon
  running. The Quit menu item's label ("Quit (stops daemon)" vs. "Quit
  (keeps daemon running)") always reflects which applies. Ownership is
  self-reported by the daemon (it echoes back whether it was launched with
  `FRIGLET_SPAWNED_BY_TRAY=1`) rather than tracked only in the tray's own
  memory, so a tray that crashes or is relaunched still correctly shuts down
  a daemon it (or an earlier instance of it) spawned, instead of orphaning it.
- **Single instance**: launching the tray while one is already running just
  brings the existing status window to front instead of starting a second
  tray process — this avoids two trays racing to spawn a daemon on a cold
  start (only one would win the control-socket bind; without this guard the
  loser could still send `Shutdown` for the other's daemon at Quit).
- **Scanning start/stop is not sticky across a daemon restart**: `Stop`
  pauses only the scan task, not the process. If the tray-spawned daemon is
  later shut down (Quit) and a new one is spawned, the new daemon starts
  scanning again by default, same as any fresh launch.

For manual testing without a real daemon there is a fake daemon that speaks
the control protocol: `cargo run -p friglet-tray --example fake-daemon`.

---

## Packaging

### Desktop bundles (friglet-tray + bundled daemon)

The tray app ships as a Tauri bundle — `.deb` and `.AppImage` on Linux,
`.dmg` on macOS — with the `friglet` daemon included as a sidecar binary
(Tauri `bundle.externalBin`), so the installed tray always finds a daemon
right next to its own executable.

```bash
# 1. stage the daemon sidecar (builds friglet --release and copies it to
#    friglet-tray/binaries/friglet-<target-triple>)
scripts/prepare-sidecar.sh

# 2. build the bundles (tauri-cli v2 via npx; `cargo install tauri-cli --locked`
#    works too — then use `cargo tauri build ...`)
cd friglet-tray
npx @tauri-apps/cli@2 build --bundles deb,appimage --config tauri.sidecar.conf.json  # Linux
npx @tauri-apps/cli@2 build --bundles dmg --config tauri.sidecar.conf.json           # macOS
```

The `--config tauri.sidecar.conf.json` overlay adds the daemon sidecar
(`bundle.externalBin`). It is kept out of the base `tauri.conf.json` so that
plain `cargo build`/`cargo test` on the workspace never require the staged
sidecar binary.

Artifacts land under `target/release/bundle/`:

- `deb/friglet-tray_<version>_amd64.deb` — installs `friglet-tray` **and**
  `friglet` into `/usr/bin/`; declares `libwebkit2gtk-4.1-0` and
  `libayatana-appindicator3-1` as dependencies.
- `appimage/friglet-tray_<version>_amd64.AppImage` — self-contained; both
  binaries in the embedded `usr/bin/`.
- `dmg/` / `macos/` — on a macOS host (cannot be cross-built from Linux).
  Run `scripts/prepare-sidecar.sh` there first; it picks up the host triple
  (e.g. `aarch64-apple-darwin`) automatically. For one dmg that runs on
  both Apple Silicon and Intel, stage a fat sidecar with
  `scripts/prepare-sidecar.sh universal-apple-darwin` and add
  `--target universal-apple-darwin` to the build (output under
  `target/universal-apple-darwin/release/bundle/`). The app is ad-hoc
  signed (`bundle.macOS.signingIdentity: "-"`), not notarized.

### Prebuilt bundles (GitHub Actions)

`.github/workflows/release.yml` runs the same steps on GitHub-hosted
runners. It only does packaging; tests and lints stay in `ci.yml`.

| Platform | Runner | Bundles |
|----------|--------|---------|
| Linux x86_64 | `ubuntu-22.04` (glibc 2.35 minimum) | `.deb`, `.AppImage` |
| macOS, Apple Silicon + Intel | `macos-15` | universal `.dmg` |
| Windows x86_64 (best effort, untested) | `windows-2025` | `.msi`, NSIS `-setup.exe` |

It runs on `v*` tag pushes, on manual `workflow_dispatch`, and on pull
requests that touch packaging files (the workflow, `friglet-tray/tauri*.conf.json`,
`friglet-tray/icons/`, `friglet-tray/Cargo.toml`/`build.rs`,
`scripts/prepare-sidecar.sh`). Pull request runs only upload workflow
artifacts. The Windows job is `continue-on-error`.

To cut a release: set the version in `friglet-tray/tauri.conf.json` (and
`friglet-tray/Cargo.toml`), then push a matching tag, e.g.
`git tag v0.1.0 && git push origin v0.1.0`. The workflow attaches the bundles
and a `SHA256SUMS` file to a **draft** release for that tag; review it and
publish it by hand. A manual `workflow_dispatch` run creates or updates the
draft `friglet-tray-dev-<commit>` instead; delete it when you're done.
Nothing is ever published automatically.

### Opening unsigned builds

The bundles are not code-signed or notarized yet, so each OS warns on first
launch. Check the download against `SHA256SUMS` first
(`sha256sum -c SHA256SUMS --ignore-missing`).

- **macOS:** open the dmg and drag `friglet-tray` to Applications. On first
  launch macOS blocks it; go to System Settings → Privacy & Security and click
  **Open Anyway** (on macOS 14 and older, right-click the app → Open also
  works). Or clear the quarantine flag in a terminal:
  `xattr -dr com.apple.quarantine /Applications/friglet-tray.app`.
- **Windows:** SmartScreen shows "Windows protected your PC"; click
  **More info** → **Run anyway**.
- **Linux:** `sudo apt install ./friglet-tray_<version>_amd64.deb`, or
  `chmod +x friglet-tray_<version>_amd64.AppImage` and run it (AppImages need
  FUSE 2, package `libfuse2`/`libfuse2t64`; without it, run with
  `--appimage-extract-and-run`). On GNOME the tray icon needs the
  AppIndicator extension (Ubuntu ships it enabled).

### Standalone daemon

```bash
cargo build --release -p friglet   # -> target/release/friglet
```

Copy `target/release/friglet` wherever you like; it is self-contained. Run
it with a config file (see [Configuration](#configuration)):
`friglet scan --config /path/to/config.toml`, or just `friglet` to use
`~/.config/friglet/config.toml`.

### Docker (headless daemon)

A multi-stage `Dockerfile` at the repo root builds a slim headless daemon
image. Config, key file, scanner state, and the control socket all live in a
`/data` volume:

```bash
docker build -t friglet .
docker run -d -p 8080:8080 -p 50001:50001 -v "$PWD/friglet-data:/data" friglet
curl http://127.0.0.1:8080/height
```

See [docs/docker.md](docs/docker.md) for the config layout and details.

---

### blindbit-cli

The `blindbit-cli` provides a minimal command-line interface for scanning blocks without a server:

```bash
cargo run --release --package blindbit-cli scan \
  --scan-secret <32-byte-hex> \
  --spend-pubkey <33-byte-hex> \
  --start-height <height> \
  --p2p-node-addr <address> \
  --oracle-url <url> \
  --state-file <path>
```

#### Parameters

- `--scan-secret`: 32-byte hex string representing the scan secret key
- `--spend-pubkey`: 33-byte hex string representing the spend public key
- `--start-height`: Block height to begin scanning from (wallet birthday)
- `--p2p-node-addr`: Bitcoin P2P node address (`host:port`)
- `--oracle-url`: Oracle service URL (default: `https://oracle.setor.dev`)
- `--state-file`: Path for scanner state persistence (default: `<config dir>/friglet/scanner_state.json`)
- `--network`: Bitcoin network `bitcoin|signet|testnet|testnet4|regtest` (default: `bitcoin`)
- `--max-label-num`: Maximum label number (default: `0`)

