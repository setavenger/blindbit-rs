# Running the friglet daemon in Docker

The repository root `Dockerfile` builds a headless `friglet` daemon image
(multi-stage: `rust:1.97-slim` builder with `protobuf-compiler`, then a
`debian:trixie-slim` runtime running as a non-root `friglet` user).

## Build

```bash
docker build -t friglet .
```

## Configuration layout

The image keeps its files in a volume mounted at `/data`:

| Path | Purpose |
|------|---------|
| `/data/config.toml` | daemon configuration (TOML, keys match the CLI flags) |
| `/data/scan.key` | scan secret key file (`0600`) |
| `/data/scanner_state.json` | scanner state, **only if `config.toml` sets `state_file = "/data/scanner_state.json"`** (see below) |
| `/data/friglet.sock` | control socket (`FRIGLET_CONTROL_SOCKET` is preset to this) |
| `/data/friglet.log` | daemon log (`FRIGLET_LOG_FILE` is preset to this) |

**Set `state_file`.** Without it, friglet uses its default per-wallet state
file in the container's home directory,
`/home/friglet/.config/friglet/scanner_state-<network>-<id>.json`, and keeps
the files that belong to it (`.birthday.json`, `.headers.json`,
`.pending.json`) next to it. That is outside the volume: when the container
is recreated (an image update, `docker rm`) they are lost and the next start
scans again from the wallet birthday. A relative `state_file =
"scanner_state.json"` does not help, because friglet treats that name as the
default. Use the absolute path `/data/scanner_state.json`. (Tracked as
SNB-635.)

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
state_file = "/data/scanner_state.json"
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
printf '{"id":1,"method":"server.version","params":["x","1.4"]}\n' | nc -w 2 127.0.0.1 50001
# -> {"jsonrpc":"2.0","id":1,"result":["Friglet","1.4"]}
printf '"GetStatus"\n' | nc -U -w 2 ./friglet-data/friglet.sock   # height, tip, errors
docker logs friglet
docker stop friglet
```

The daemon also writes its log to `/data/friglet.log` in the volume
(`FRIGLET_LOG_FILE` in the image; capped at 10 MiB, rotated to
`friglet.log.1`/`.2`). Set `-e FRIGLET_LOG_FILE=off` to log to stdout only.

The HTTP endpoints `/height` and `/subscribe` do not answer while scanning
is enabled, and that includes the whole time the daemon is caught up and
waiting for new blocks: the scan holds the scanner for as long as it runs.
They answer only while scanning is stopped (`Stop` over the control socket).
Do not use them as a health check; use the Electrum `server.version` call or
`GetStatus` on the control socket (`friglet-ipc` protocol) as above, or
`docker logs` (scan progress lines).

Port `8080` is the HTTP API (`/height`, `/subscribe`), `50001` the Electrum
TCP server (point Sparrow at `127.0.0.1:50001`).
