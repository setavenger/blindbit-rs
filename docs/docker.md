# Running the friglet daemon in Docker

The repository root `Dockerfile` builds a headless `friglet` daemon image
(multi-stage: `rust:1.97-slim` builder with `protobuf-compiler`, then a
`debian:trixie-slim` runtime running as a non-root `friglet` user).

## Build

```bash
docker build -t friglet .
```

## Configuration layout

Everything mutable lives in a single volume mounted at `/data`:

| Path | Purpose |
|------|---------|
| `/data/config.toml` | daemon configuration (TOML, keys match the CLI flags) |
| `/data/scan.key` | scan secret key file (`0600`) |
| `/data/scanner_state.json` | scanner state (default `state_file`; relative paths resolve against `/data`) |
| `/data/friglet.sock` | control socket (`FRIGLET_CONTROL_SOCKET` is preset to this) |

The image's default command is
`friglet scan --config /data/config.toml --key-file /data/scan.key`, and the
image presets `FRIGLET_HTTP_ADDR=0.0.0.0:8080` and
`FRIGLET_ELECTRUM_ADDR=0.0.0.0:50001` so the servers are reachable from
outside the container (env vars still lose to CLI flags but beat the config
file, so don't set `http_addr`/`electrum_addr` in `config.toml` unless you
want to fight the presets — override the env vars with `-e` instead).

Minimal `config.toml`:

```toml
network = "signet"
spend_pubkey = "<33-byte hex spend public key>"
start_height = 274010
p2p_node_addr = "152.53.151.148:38333"
oracle_url = "https://signet.oracle.setor.dev"
```

The scan secret goes into `scan.key` (a single line of 32-byte hex), not into
the config file. Alternatively pass it once as `-e FRIGLET_SCAN_SECRET=<hex>`
— the daemon then writes `/data/scan.key` itself with `0600` permissions.

## Run

```bash
mkdir -p ./friglet-data
printf '<32-byte hex scan secret>' > ./friglet-data/scan.key && chmod 600 ./friglet-data/scan.key
$EDITOR ./friglet-data/config.toml

docker run -d --name friglet \
  -p 8080:8080 -p 50001:50001 \
  -v "$PWD/friglet-data:/data" \
  friglet
```

Note: the container runs as UID 1000; make sure the mounted directory is
writable for that UID (or use a named volume: `-v friglet-data:/data`).

Check it:

```bash
curl http://127.0.0.1:8080/height     # -> {"height": <n>}
docker logs friglet
docker stop friglet
```

Caveat: while a scan is actively running (including the initial catch-up),
the scan task holds the scanner lock, so `/height` and `/subscribe` block
until the scan pauses. Use `docker logs` (scan progress lines) or the
control socket (`/data/friglet.sock`, `friglet-ipc` protocol) for status
during a scan.

Port `8080` is the HTTP API (`/height`, `/subscribe`), `50001` the Electrum
TCP server (point Sparrow at `127.0.0.1:50001`).
