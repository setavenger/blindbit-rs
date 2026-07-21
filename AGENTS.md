# AGENTS.md

## Cursor Cloud specific instructions

Rust Cargo workspace (edition 2024) for BlindBit BIP-352 Silent Payments. Three crates: `blindbit-lib` (core scanner + gRPC oracle client), `friglet` (scanner + HTTP + Electrum servers, recommended binary), `blindbit-cli` (one-shot range scan, no servers). See `README.md` for full flags/usage.

### Toolchain / build
- Needs Rust **stable >= 1.85** (edition 2024). Default toolchain is set to `stable`; the preinstalled `1.83.0` is too old and fails to compile.
- `protoc` is a hard build requirement: `blindbit-lib/build.rs` compiles `blindbit-lib/proto/*.proto` via `tonic-prost-build`. Build fails with no protoc on PATH.

### System dependencies (baked into the VM snapshot)
This env needs heavy system setup beyond the current tree because the repo also has a **Tauri v2 tray app** (on branch `cursor/friglet-tray-ui-a38a`) that requires GTK/WebKit/appindicator to build, plus Windows cross-compile + headless-GUI test tooling. These are already installed in the VM snapshot from a setup session, so future agents should NOT need to reinstall them; if a fresh env is missing them, install via apt (needs `sudo`):

- Tauri build: `libwebkit2gtk-4.1-dev libayatana-appindicator3-dev librsvg2-dev libgtk-3-dev libssl-dev pkg-config patchelf`
- Proto codegen: `protobuf-compiler libprotobuf-dev`
- Headless GUI test / automation: `xvfb xdotool libxdo-dev`
- Windows cross-compile: `mingw-w64` + `rustup target add x86_64-pc-windows-gnu`
- Containers: `docker.io`
- Rust components: `clippy` + `rustfmt`

If a future env keeps losing these, regenerate the environment config via the env setup agent at `cursor.com/onboard` rather than relying on the startup update script (which is kept minimal to `cargo fetch`).
- Standard commands from repo root: `cargo build --workspace`, `cargo clippy --workspace`, `cargo fmt --all -- --check`, `cargo test --workspace`.
- There are **no in-repo tests** (`cargo test` reports 0 tests) and **no committed clippy/rustfmt config**. Clippy emits warnings only (e.g. `collapsible_if`) and `cargo fmt --check` reports pre-existing diffs — neither is an error; do not "fix" pre-existing style unless asked.

### Running / end-to-end
- Run commands are in `README.md`. E2E needs two **external** services: a BlindBit Oracle (signet: `https://signet.oracle.setor.dev`) and a Bitcoin P2P peer (signet example `152.53.151.148:38333`). Both are reachable from the VM. No DB.
- Keys are BIP-352 hex: `--scan-secret` (32-byte secp256k1 secret), `--spend-pubkey` (33-byte compressed pubkey). For smoke tests any valid keypair works, e.g. secret `0000...0001` and pubkey `0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798` (finds no UTXOs, balance 0).
- `friglet scan` from `--start-height 274010` to signet tip is ~40k blocks (~10 min at ~100 blk/s). For a fast check use `blindbit-cli` with a small `--end-height` range (e.g. 274010..274060 finishes in ~1s).
- State persists to a JSON file (`--state-file`); tests use the gitignored `blindbit-test/` dir.

### Non-obvious gotcha (friglet HTTP)
- `friglet`'s HTTP endpoints `/height` and `/subscribe` **hang indefinitely**: the background `watch_chain()` task holds the scanner `Mutex` for its entire (infinite) lifetime in `friglet/src/main.rs`, so the HTTP handlers can never acquire the lock. This is pre-existing app behavior, not an env issue.
- The **Electrum TCP server works** (it uses a separate index mutex). To verify a running scanner, query Electrum, e.g. send `{"id":1,"method":"server.version","params":["x","1.4"]}` and `{"id":2,"method":"blockchain.headers.subscribe","params":[]}` to `127.0.0.1:50001`; it returns `["Friglet","1.4"]` and the latest scanned height.
