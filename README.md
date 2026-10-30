# BlindBit Rust

A Rust implementation of the BlindBit suite for Bitcoin BIP-352 Silent Payments.

## Overview

BlindBit is a comprehensive software suite for Bitcoin BIP-352 Silent Payments. This Rust implementation provides the core libraries and tools for scanning Bitcoin blocks to detect silent payments, integrating with the broader BlindBit ecosystem that includes indexers, scanners, and wallets.

## Features

- **Silent Payments Scanning**: Detects BIP-352 silent payments in Bitcoin transactions
- **BlindBit Oracle Integration**: Connects to BlindBit Oracle services for efficient blockchain data access
- **State Persistence**: Saves and restores scanner state for incremental scanning
- **Electrum Server**: Exposes a local Electrum TCP interface for wallet compatibility (e.g. Sparrow)
- **Multi-Network Support**: Works with Bitcoin mainnet, signet, testnet, testnet4, and regtest
- **Privacy-Preserving**: Scanner queries reveal only general interest in Silent Payments, not specific keys or transactions (full blocks come from your own node, or from random peers who see which blocks you fetch: see [Privacy](#privacy-your-node-or-random-peers))

## Workspace Structure

This is a Cargo workspace containing the following crates:

- **blindbit-lib**: Core library containing the scanning logic and gRPC client
- **friglet**: Lightweight scanner compatible with Frigate's Silent Payments endpoints, with a built-in Electrum server
- **friglet-ipc**: Shared IPC protocol (control socket) between the friglet daemon and its clients
- **friglet-tray**: System tray companion app for the friglet daemon (Tauri v2)
- **blindbit-cli**: Minimal command-line interface for scanning (no server functionality)

## Usage

### friglet (Recommended)

`friglet` is the recommended tool. It scans Bitcoin blocks for Silent Payments and exposes an Electrum TCP server, making it compatible with wallets like Sparrow via Frigate.

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
| `--p2p-node-addr` | Your Bitcoin node's P2P address: `host:port`, `ip:port`, or a bare host (network default port); hostnames are resolved at every start (by the proxy when `--p2p-proxy` is set, which also reaches `.onion` nodes). When set, friglet talks only to this node. Empty: random peers of the network (see [Privacy: your node or random peers](#privacy-your-node-or-random-peers)) | empty (random peers); required on regtest |
| `--p2p-proxy` | SOCKS5 proxy for every Bitcoin P2P connection, usually Tor: `ip:port` or `localhost:port` (see [Tor](#tor)). While set, no P2P connection goes out directly, even when the proxy is down | empty (direct) |
| `--oracle-url` | BlindBit Oracle URL | hosted oracle of `--network` (mainnet `https://oracle.setor.dev`, signet `https://signet.oracle.setor.dev`; none for other networks) |
| `--network` | Bitcoin network: `bitcoin\|signet\|testnet\|testnet4\|regtest` | `bitcoin` |
| `--max-label-num` | Maximum number of Silent Payment labels | `0` |
| `--state-file` | Path to persist scanner state. The default is kept per wallet (`scanner_state-<network>-<id>.json` next to it), so new keys start a fresh scan; an explicit path holding another wallet's state is refused | `<config dir>/friglet/scanner_state.json` |
| `--electrum-addr` | Electrum TCP server bind address | `127.0.0.1:50001` |
| `--log-level` | `trace\|debug\|info\|warn\|error`; `RUST_LOG` overrides it | `info` |

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
- `http_addr` (`--http-addr`, `FRIGLET_HTTP_ADDR`) is obsolete: friglet no
  longer has an HTTP API. The key is still accepted, and still written to
  config files for compatibility with older trays, but nothing listens on it.

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
Default socket: `$XDG_RUNTIME_DIR/friglet.sock` (Linux), falling back to
`${XDG_DATA_HOME:-$HOME/.local/share}/friglet/friglet.sock`, then `/tmp/friglet.sock`,
`~/Library/Application Support/friglet/friglet.sock` (macOS),
`\\.\pipe\friglet` (Windows); override with the config key
`control_socket` or `FRIGLET_CONTROL_SOCKET` (the environment wins).

To check on a running daemon, ask the control socket for `GetStatus` or
send the Electrum server a `server.version` request:

For the control query, set `FRIGLET_SOCKET` to the daemon's socket path.
This example honors `FRIGLET_CONTROL_SOCKET` and selects the usual Linux
default, including the data-directory fallback. If `control_socket` in the
config file overrides that path, set `FRIGLET_SOCKET` to its value instead.

```bash
FRIGLET_SOCKET="${FRIGLET_CONTROL_SOCKET:-${XDG_RUNTIME_DIR:-${XDG_DATA_HOME:-$HOME/.local/share}/friglet}/friglet.sock}"
printf '"GetStatus"\n' | nc -U -w 2 "$FRIGLET_SOCKET"
printf '{"id":1,"method":"server.version","params":["x","1.4"]}\n' | nc -w 2 127.0.0.1 50001
# -> {"jsonrpc":"2.0","id":1,"result":["Friglet","1.4"]}
```

#### Electrum Server

The built-in Electrum server (bound to `--electrum-addr`) allows wallets such as Sparrow to connect directly and query Silent Payment UTXOs without any additional infrastructure.

What to expect from it:

- **New blocks** are announced with the real header of the tip block. friglet
  asks the oracle which block is at the scanned height and fetches that
  block's 80-byte header from the P2P peer.
- **Broadcasting** succeeds only once the P2P peer (your node, or without
  one a random peer of the network) has the transaction in its mempool,
  which usually takes 5–10 seconds. With random peers this is one peer's
  word for now; a stronger check (another peer must announce it) is planned. Otherwise
  Sparrow shows an error. The P2P protocol does not say why a peer refuses a
  transaction. friglet reports what it can tell: missing or spent inputs, a
  fee below the peer's mempool minimum, or a dropped connection, which means
  the transaction is invalid. Broadcasts that have not confirmed are kept in
  `<state file>.pending.json`. While they are pending, friglet re-announces
  them whenever the peer's mempool loses them, including after a restart. It
  stops when they confirm or when a conflicting transaction confirms.
- **Fees**: friglet has no fee estimator. It answers `blockchain.estimatefee`
  with `-1`, the Electrum protocol's "no estimate". Its relay fee is the
  minimum fee rate that the P2P peer's mempool currently accepts (with
  random peers: the median of at least three peers' minimums, so one peer
  cannot raise it). Keep
  Sparrow's fee rate source on an external service (mempool.space by
  default), or set fee rates by hand.

#### Privacy: your node or random peers

friglet downloads full blocks (only those that probably hold a payment to
or from the wallet), block headers, and broadcasts over Bitcoin P2P.

- **Your own node** (`p2p_node_addr`) is the recommended setup. friglet then
  talks only to it: no other peer learns anything.
- **Without a node**, friglet finds peers of the network through its DNS
  seeds and the addresses peers share, and asks them one after another. It
  checks every block against its header and witness commitment, skips peers
  that are behind, pruned or unreachable, and ignores a peer that sends a bad
  block for the rest of the session. The cost is privacy: those peers see
  this computer's IP address and which blocks it downloads, and those blocks
  probably pay or spend from your wallet. friglet keeps asking the peer that
  served the last block first, so that peer sees most of them. Use your own
  node, or [Tor](#tor), if that matters to you.
- Regtest has no public peers: it needs `p2p_node_addr`.
- The addresses friglet learns are kept beside the wallet state
  (`peers-<network>-new.book`, `peers-<network>-tried.book`; saved every
  10 minutes and at exit), so a restart asks the seeds only when it knows
  fewer than 50 peers.

#### Tor

With `p2p_proxy` set to Tor's SOCKS port, every Bitcoin P2P connection
(block downloads, headers, mempool checks, broadcasts) goes through Tor.
Peers then see a Tor exit's address instead of this computer's.

- Run Tor: install it from your package manager (`apt install tor`,
  `brew install tor`) and start it; it listens on `127.0.0.1:9050`. The Tor
  Browser's Tor listens on `127.0.0.1:9150` while it runs. Then set
  `p2p_proxy = "127.0.0.1:9050"` (or `--p2p-proxy`, `FRIGLET_P2P_PROXY`, or
  the tray's *Tor proxy* field, whose Save checks that the proxy answers).
- Fail-closed: while `p2p_proxy` is set, friglet never connects to a peer
  directly. If Tor is down, block downloads and broadcasts fail with an
  error that names `p2p_proxy`, and the scan retries until Tor is back.
- Nothing is looked up locally: your node's host name (also an `.onion`
  address, which needs the proxy) goes to Tor unresolved, and instead of
  DNS seed lookups friglet connects through Tor to three of the network's
  seed names, asks the node there for addresses and disconnects.
- Each connection logs in to Tor with random credentials, so Tor gives it a
  circuit of its own and no single exit sees all of friglet's peers.
- Not proxied: the BlindBit oracle (gRPC over HTTPS to `oracle_url`; the
  oracle sees this computer's IP, but the requests do not depend on your
  keys), and the Electrum server, which only listens locally.
- Your own node on this computer or your local network does not need Tor;
  Tor cannot reach it either (its exits only connect to public addresses).
  Leave `p2p_proxy` empty for it, or give the node's onion address.
- Through Tor a block takes longer (connections get 20 s, a block 60 s),
  and the first download waits for the seeds' answers through Tor.
- An older friglet-tray does not know `p2p_proxy` and drops it when it saves
  settings; the daemon then logs a warning. Update the tray with the
  daemon.

---

### Tray app (friglet-tray)

`friglet-tray` is a small Tauri v2 system tray app that supervises and
monitors the `friglet` daemon over its control socket. It shows live status
(scan height, progress, network, Electrum clients, oracle connectivity, SP
address, errors) in the tray menu and in a status window (hidden by default;
a left click on the tray icon opens it, and so does **Open Status Window** in
the icon's right-click menu; closing it hides it again). The tray menu and the
Status tab offer Start/Stop scanning, Start/Stop daemon and Quit; a button
or menu item is only enabled when it does what it says (Start scanning is
greyed out while a scan runs, Stop daemon while none is running).

**Scanning and daemon controls**

- **Stop scanning** pauses the scan loop; the status says *paused* and the
  height stays where it is until **Start scanning**. The pause lasts until
  you press Start (it also survives a settings save, which restarts the
  daemon in-process), but not a restart of the daemon process. The scan
  stops within about a second, also in the middle of downloading a block
  from the P2P node: the download is abandoned, nothing of that block is
  kept, and Start scanning picks it up again. The status says *stopping…*
  until the scan has really ended, never *paused* early.
- **Stop daemon** stops the daemon process whoever started it — this tray,
  an earlier tray session, or something else (a terminal, a service, an
  autostart entry); the Status tab says which one it is and what Quit will
  do. A stopped daemon stays stopped: the tray's automatic restart never
  undoes it, and neither does a daemon that exits normally (exit status 0,
  e.g. `kill`/SIGTERM from outside the tray). **Start daemon** starts it
  again (or attaches to one that is running). If a service manager such as
  systemd restarts the daemon right away, Stop daemon says so — stop it
  there.

**Waiting vs. errors.** Some conditions are normal for a few moments: the
oracle announces a new block before it has indexed it, the oracle or the
daemon does not answer for a moment (a restart after saving settings, a
reconnect). The Status tab shows these as a neutral *waiting* /
*reconnecting…* state. Only when a stall or an unreachable oracle lasts
2 minutes, or the daemon stays unreachable for 10 seconds, does it become an
error. Errors are shown under **Needs attention** with the time they began
and stay there until they are resolved; every error of the session is also
listed under **Recent errors** (with a count when it repeats), and written
to the log.

**Logs.** The daemon writes its log to a file as well as to stdout, and the
tray writes its own:

| Platform | Folder | Files |
| --- | --- | --- |
| Linux | `$XDG_STATE_HOME/friglet`, i.e. `~/.local/state/friglet` | `friglet.log`, `friglet-tray.log` |
| macOS | `~/Library/Logs/friglet` | `friglet.log`, `friglet-tray.log` |
| Windows | `%LOCALAPPDATA%\friglet\logs` | `friglet.log`, `friglet-tray.log` |

Each file is capped at 10 MiB: it is then renamed to `*.log.1` (the previous
`.1` becomes `.2`, an older `.2` is dropped). `FRIGLET_LOG_FILE=<path>`
moves the daemon's log, `FRIGLET_LOG_FILE=off` turns the file off. The
Status tab shows both paths and has an **Open log folder** button; a daemon
started by the tray also has its output forwarded to the tray's own
stdout (`friglet-daemon` lines) when the tray runs in a terminal.

The window's **Settings** tab lets you view and edit all daemon settings —
wallet descriptor, network, wallet birthday, Bitcoin node, oracle URL, and
under *Advanced* the scan key, spend pubkey, max labels, Electrum bind
address, state and key file paths. Saving sends the config (and a new
scan key, if a descriptor was pasted) to the daemon in one request; it
validates it, persists it to its config file (the scan key to the 0600 key
file) and then **restarts itself in-process** so every setting takes full
effect — Electrum clients such as Sparrow are disconnected, reconnect on
their own and see the new wallet. New keys get their own state file, so
switching wallets starts a fresh scan; moving the birthday back rescans from
the new height (the old state is kept as `*.json.bak`). The scan key is
write-only — it is never displayed and only sent when you paste a
descriptor or type a new key.

**Start at login**: a checkbox on the Settings tab registers the tray as a
login item (XDG autostart entry on Linux, LaunchAgent on macOS, Run key on
Windows; the AppImage path when run from one); the tray then starts the
daemon. It is ticked by default in first-time setup and applied on Save.

The **Wallet** tab is a read-only convenience view, not a spending wallet. It
shows found transaction/output counts plus copyable base and per-label Silent
Payments addresses.

**Tray icon on Linux.** The icon is a StatusNotifierItem (KSNI over D-Bus), so
it needs a desktop with an SNI tray: Omarchy's bar, KDE Plasma, GNOME with
the AppIndicator extension, Waybar's `tray` module and the like. Trays that
only host legacy XEmbed icons do not show it. When no tray is up yet (the
tray app started before the bar at login) the app keeps running and
registers the icon as soon as one appears.

**Omarchy / Hyprland: top-bar popup.** Under Hyprland (detected by
`HYPRLAND_INSTANCE_SIGNATURE`; Omarchy 4 runs it) the window opens like
Omarchy's own Wi-Fi and Bluetooth panels: floating, right-aligned just under
the top bar, without a title bar, at a fixed 420×600 (smaller on a short
screen). A left click on the tray icon opens it and a second one closes it;
Esc closes it, and so does focusing another window (clicking it, or a
keybinding). Merely moving the pointer over another window does not, although
Omarchy focuses windows on hover. The right-click menu is unchanged.

How: before each show the tray asks Hyprland, over its IPC socket, for the
monitor under the pointer, the bar height (the monitor's reserved top) and
`general:gaps_out`, and registers a window rule for its own window with the
Lua API (`hl.window_rule`, Hyprland 0.55+): float, size, and a position
`gaps_out / 2` below the bar and from the right edge. While the popup is open
a second rule sets `no_follow_mouse` on every other window, so hovering them
does not take the focus; hiding the popup turns it off. After the show the
tray checks where the window landed (`hyprctl clients`) and moves it with
dispatchers if it is off, which is also the only placement on a Hyprland
without the Lua API. Nothing is written to your config files. Everywhere
else (GNOME, KDE, other compositors, macOS, Windows) the window is the
ordinary one: a left click on the icon opens it, the menu is on right click.

If the tray runs without Hyprland's environment (say from a service that
lacks `HYPRLAND_INSTANCE_SIGNATURE`) it opens the ordinary window. A static
rule at the end of `~/.config/hypr/hyprland.lua` still floats it under the
bar (Omarchy 4 syntax, as in Omarchy's own rules; `31` is Omarchy's default
26 px bar plus a 5 px gap). The class is expected to be `friglet-tray`; the
tray logs the one Hyprland reports in popup mode (`Hyprland window class of
the status window` in `friglet-tray.log`), and `hyprctl clients` shows it:

```lua
o.window({ class = "^friglet-tray$", title = "^Friglet Status$" }, {
  float = true,
  size = { 420, 600 },
  move = { "(monitor_w-window_w-5)", 31 },
})
```

```bash
# build (Linux needs libwebkit2gtk-4.1-dev, libgtk-3-dev, pkg-config,
# protobuf-compiler and libprotobuf-dev)
cargo build --release -p friglet-tray

# run
./target/release/friglet-tray

# optional: show the status window immediately (normally hidden until
# opened from the tray icon — useful for headless / screenshot testing).
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
   first start). **From block height** scans from the height you enter
   (pre-filled when the descriptor carries Sparrow's `?bh=` birth height).
3. *Your Bitcoin node* (optional): your own node of that network,
   `host:port` or just `host`. Left empty, friglet downloads blocks from
   random peers of the network (see
   [Privacy](#privacy-your-node-or-random-peers)); regtest needs a node.
   *Tor proxy* (optional): Tor's SOCKS port, e.g. `127.0.0.1:9050` (see
   [Tor](#tor)).

Save validates the form (including a DNS lookup of the node, if one is set
and no proxy is; with a proxy, a 2 s connection check to it instead), writes the
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
  waits for its socket (up to ~30 s, less if the daemon exits). If nothing
  comes up the tray keeps running, shows why, and **Start daemon** retriggers
  the whole logic.
- **Quit rule**: if the tray spawned the daemon, Quit sends `Shutdown` over
  the control socket (killing the child as a fallback) before exiting. If the
  tray merely attached to a daemon it did not spawn, Quit leaves the daemon
  running. The Quit menu item's label ("Quit (stops daemon)" vs. "Quit
  (keeps daemon running)", or plain "Quit" when no daemon runs) always
  reflects which applies. To stop a daemon the tray did not start, use
  **Stop daemon** before Quit. Ownership is
  self-reported by the daemon (it echoes back whether it was launched with
  `FRIGLET_SPAWNED_BY_TRAY=1`) rather than tracked only in the tray's own
  memory, so a tray that crashes or is relaunched still correctly shuts down
  a daemon it (or an earlier instance of it) spawned, instead of orphaning it.
- **Single instance**: launching the tray while one is already running just
  brings the existing status window to front instead of starting a second
  tray process — this avoids two trays racing to spawn a daemon on a cold
  start (only one would win the control-socket bind; without this guard the
  loser could still send `Shutdown` for the other's daemon at Quit).
- **Supervision**: a daemon the tray spawned (or one an earlier tray
  session spawned) is restarted automatically when it dies — crash, kill,
  `panic = "abort"` in release builds — with exponential backoff (1 s, 2 s,
  4 s … capped at 60 s; reset after a healthy minute). The Status tab shows
  the crash (exit status/signal, time, the daemon's last output lines),
  the restart count and the countdown to the next attempt; the tray label
  reads "Daemon: crashed — restarting". A daemon that is alive but silent
  for 2 minutes is replaced. **Start daemon** restarts immediately; **Stop
  daemon** or Quit stop it for good. A daemon that exits normally (status
  0) is not restarted, and an externally started daemon is never restarted
  by the tray.

For manual testing without a real daemon there is a fake daemon that speaks
the control protocol: `cargo run -p friglet-tray --example fake-daemon`.

---

## Packaging

### Desktop bundles (friglet-tray + bundled daemon)

The tray app ships as a Tauri bundle — `.deb`, `.rpm` and `.AppImage` on
Linux, `.dmg` on macOS, `.msi`/`-setup.exe` on Windows — with the `friglet` daemon included as a sidecar binary
(Tauri `bundle.externalBin`), so the installed tray always finds a daemon
right next to its own executable.

```bash
# 1. stage the daemon sidecar (builds friglet --release and copies it to
#    friglet-tray/binaries/friglet-<target-triple>)
scripts/prepare-sidecar.sh

# 2. build the bundles (tauri-cli v2 via npx; `cargo install tauri-cli --locked`
#    works too — then use `cargo tauri build ...`)
cd friglet-tray
npx @tauri-apps/cli@2 build --bundles deb,rpm,appimage --config tauri.sidecar.conf.json  # Linux
npx @tauri-apps/cli@2 build --bundles dmg --config tauri.sidecar.conf.json           # macOS
```

The `--config tauri.sidecar.conf.json` overlay adds the daemon sidecar
(`bundle.externalBin`). It is kept out of the base `tauri.conf.json` so that
plain `cargo build`/`cargo test` on the workspace never require the staged
sidecar binary.

Artifacts land under `target/release/bundle/`:

- `deb/friglet-tray_<version>_amd64.deb` — installs `friglet-tray` **and**
  `friglet` into `/usr/bin/`; declares `libayatana-appindicator3-1`,
  `libwebkit2gtk-4.1-0` and `libgtk-3-0` as dependencies.
- `rpm/friglet-tray-<version>-1.x86_64.rpm` — same layout as the deb;
  requires the same libraries by soname, so it resolves on Fedora and
  openSUSE alike.
- `appimage/friglet-tray_<version>_amd64.AppImage` — self-contained; both
  binaries in the embedded `usr/bin/`.
- `dmg/` / `macos/` — on a macOS host (cannot be cross-built from Linux).
  Run `scripts/prepare-sidecar.sh` there first; it picks up the host triple
  (e.g. `aarch64-apple-darwin`) automatically. For one dmg that runs on
  both Apple Silicon and Intel, stage a fat sidecar with
  `scripts/prepare-sidecar.sh universal-apple-darwin` and add
  `--target universal-apple-darwin` to the build (output under
  `target/universal-apple-darwin/release/bundle/`). Local builds are ad-hoc
  signed (`bundle.macOS.signingIdentity: "-"`), not notarized; CI signs
  and notarizes (see [macOS signing](#macos-signing)).

### Prebuilt bundles (GitHub Actions)

`.github/workflows/release.yml` runs the same steps on GitHub-hosted
runners. It only does packaging; tests and lints stay in `ci.yml`.

| Platform | Runner | Bundles |
|----------|--------|---------|
| Linux x86_64 | `ubuntu-22.04` (glibc 2.35 minimum) | `.deb`, `.rpm`, `.AppImage` |
| Linux arm64 | `ubuntu-22.04-arm` (glibc 2.35 minimum) | `.deb`, `.rpm`, `.AppImage` |
| macOS, Apple Silicon + Intel | `macos-15` | universal `.dmg`, Developer ID signed and notarized |
| Windows x86_64 (best effort, untested) | `windows-2025` | `.msi`, NSIS `-setup.exe`, not code-signed |

Each Linux bundle is then installed the way a user would, in a clean
container of Ubuntu 22.04 and 24.04, Debian 12 and 13, Fedora, openSUSE
Tumbleweed and Arch (arm64: Ubuntu 24.04 and Fedora), and started there on
a virtual display until its first-run setup window opens
(`scripts/linux-install-check.sh`). A release is only drafted when all of
those pass.

It runs only when a release tag `vX.Y.Z` is pushed, or when started by hand
(Actions → Release bundles → Run workflow); never on ordinary pushes or pull
requests. A manual run builds and checks everything but releases nothing:
the bundles are in the run's Artifacts. The Windows job is
`continue-on-error`.

To cut a release: set the version in `friglet-tray/tauri.conf.json` (and
`friglet-tray/Cargo.toml`), then push a matching tag, e.g.
`git tag v0.1.0 && git push origin v0.1.0`. The workflow attaches the bundles
and a `SHA256SUMS` file to a **draft** release for that tag; review it and
publish it by hand. Nothing is ever published automatically.

### Installing a release

Download the file for your system from the release page and check it
against `SHA256SUMS` (`sha256sum -c SHA256SUMS --ignore-missing`).

- **macOS (Apple Silicon or Intel):** open the `.dmg` and drag
  `friglet-tray` to Applications. Release builds are signed and notarized,
  so it opens like any other app. A build without a signature (a dev build,
  or one made before the signing secrets were set; its release notes say
  "ad-hoc signed") is blocked on first launch: go to System Settings →
  Privacy & Security and click **Open Anyway**, or run
  `xattr -dr com.apple.quarantine /Applications/friglet-tray.app`.
- **Debian, Ubuntu and derivatives:**
  `sudo apt install ./friglet-tray_<version>_<amd64|arm64>.deb`
- **Fedora:** `sudo dnf install ./friglet-tray-<version>-1.<x86_64|aarch64>.rpm`
- **openSUSE:** `sudo zypper install --allow-unsigned-rpm ./friglet-tray-<version>-1.<x86_64|aarch64>.rpm`
  (the rpm is not GPG-signed).
- **Any other distro (Arch, …):** `chmod +x friglet-tray_<version>_<amd64|aarch64>.AppImage`
  and run it. AppImages need FUSE 2 (package `fuse2`, `libfuse2` or
  `libfuse2t64`); without it, run it with `--appimage-extract-and-run`.
- **Windows:** run the `-setup.exe` (or the `.msi`). The installer is not
  code-signed, so SmartScreen shows "Windows protected your PC"; click
  **More info** → **Run anyway**.

On GNOME the tray icon needs the AppIndicator extension (Ubuntu ships it
enabled).

### macOS signing

The macOS job signs with a Developer ID certificate and notarizes when all
five of these repository secrets are set (Settings → Secrets and variables
→ Actions); with none set it falls back to an ad-hoc signed dmg, and with
only some set it fails. To test signing before a release, run the workflow
by hand on the branch and take the dmg from the run's Artifacts.

| Secret | Value |
|--------|-------|
| `APPLE_CERTIFICATE` | the "Developer ID Application" certificate with its private key, exported as `.p12` and base64-encoded (`base64 -i friglet.p12`) |
| `APPLE_CERTIFICATE_PASSWORD` | the password chosen when exporting the `.p12` |
| `APPLE_ID` | the Apple account email of the developer account |
| `APPLE_PASSWORD` | an app-specific password for that account (account.apple.com → Sign-In and Security → App-Specific Passwords) |
| `APPLE_TEAM_ID` | the 10-character Team ID (developer.apple.com → Account → Membership details) |

To make the certificate on a Mac: Xcode → Settings → Accounts → the team →
Manage Certificates → **+** → Developer ID Application, then in Keychain
Access (login → My Certificates) right-click it → Export as `.p12`.
Creating a Developer ID certificate needs the Account Holder role.

Tauri signs the bundled daemon and the app with the hardened runtime and
notarizes and staples the app; the workflow then notarizes and staples the
dmg too, and checks that Gatekeeper accepts both as "Notarized Developer
ID". The certificate is valid for five years.

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
image. Config, key file, control socket and log live in a `/data` volume.
The scanner state does not by default: set `state_file =
"/data/scanner_state.json"` in `config.toml`, or it is lost when the
container is recreated.

```bash
docker build -t friglet .
docker run -d -p 50001:50001 -v "$PWD/friglet-data:/data" friglet
printf '{"id":1,"method":"server.version","params":["x","1.4"]}\n' | nc -w 2 127.0.0.1 50001
```

See [docs/docker.md](docs/docker.md) for the config layout and details.

---

### blindbit-cli

The `blindbit-cli` provides a minimal command-line interface for scanning blocks without a server:

```bash
cargo run --release --package blindbit-cli scan \
  --network signet \
  --scan-secret <32-byte-hex> \
  --spend-pubkey <33-byte-hex> \
  --start-height 274010 \
  --end-height 274060 \
  --p2p-node-addr 152.53.151.148:38333 \
  --oracle-url 'https://signet.oracle.setor.dev' \
  --state-file <path>
```

#### Parameters

- `--scan-secret`: 32-byte hex string representing the scan secret key (required)
- `--spend-pubkey`: 33-byte hex string representing the spend public key (required)
- `--start-height`: Block height to begin scanning from (wallet birthday; required)
- `--end-height`: Last block height to scan (required)
- `--p2p-node-addr`: your Bitcoin node's P2P address as `ip:port`; hostnames only with `--p2p-proxy` (default: random peers of the network, found through its DNS seeds; required on regtest)
- `--p2p-proxy`: SOCKS5 proxy (Tor) for every P2P connection, `ip:port` (see [Tor](#tor); default: none)
- `--oracle-url`: Oracle service URL (default: `https://oracle.setor.dev`)
- `--state-file`: Path for scanner state, loaded at start and saved at the end; the given range is scanned either way (default: `scanner_state.json` in the working directory)
- `--network`: Bitcoin network `bitcoin|signet|testnet|testnet4|regtest` (default: `bitcoin`)
- `--max-label-num`: Maximum label number (default: `0`)
- `--log-level`: `trace|debug|info|warn|error`; `RUST_LOG` overrides it (default: `info`)
