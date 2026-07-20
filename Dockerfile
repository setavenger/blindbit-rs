# Headless friglet daemon image.
#
#   docker build -t friglet .
#   docker run -d -p 8080:8080 -p 50001:50001 -v friglet-data:/data friglet
#
# See docs/docker.md for configuration details.

FROM rust:1.97-slim AS builder
# protobuf-compiler: blindbit-lib's build.rs compiles gRPC protos;
# libprotobuf-dev provides the google/protobuf well-known-type imports.
RUN apt-get update \
    && apt-get install -y --no-install-recommends protobuf-compiler libprotobuf-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
RUN cargo build --release -p friglet

FROM debian:trixie-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 1000 --create-home friglet \
    && mkdir -p /data \
    && chown friglet:friglet /data
COPY --from=builder /src/target/release/friglet /usr/local/bin/friglet

USER friglet
# All mutable state (config.toml, scan.key, scanner state file, control
# socket) lives under /data; WORKDIR makes the relative state_file default
# ("scanner_state.json") land there too.
WORKDIR /data
VOLUME /data
ENV FRIGLET_CONTROL_SOCKET=/data/friglet.sock \
    FRIGLET_HTTP_ADDR=0.0.0.0:8080 \
    FRIGLET_ELECTRUM_ADDR=0.0.0.0:50001

# HTTP API / Electrum TCP
EXPOSE 8080 50001

ENTRYPOINT ["friglet"]
CMD ["scan", "--config", "/data/config.toml", "--key-file", "/data/scan.key"]
