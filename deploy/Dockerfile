# syntax=docker/dockerfile:1
FROM node:22-bookworm-slim AS console
WORKDIR /src/console
COPY console/package*.json ./
RUN --mount=type=cache,target=/root/.npm npm ci
COPY console/index.html console/tsconfig.json console/vite.config.ts ./
COPY console/src ./src
RUN npm run build
FROM rust:1.90-bookworm AS rust
WORKDIR /src
# BuildKit caches are shared across builds and do not become image layers.
ENV CARGO_TARGET_DIR=/src/target CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0
COPY Cargo.toml Cargo.lock LICENSE ./
COPY .cargo ./.cargo
COPY crates ./crates
COPY migrations ./migrations
COPY ops/backup.py ops/restore.py ./ops/
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --locked --release -p forgeflow-server -p forgeflow-worker -p forgeflow-cli -p forgeflow-runtime --bins \
    && mkdir /out \
    && cp /src/target/release/forgeflow-server /src/target/release/forgeflow-worker /src/target/release/forgeflow-sandbox-guard /src/target/release/forgeflow /out/
FROM postgres:16.15-bookworm AS postgres-tools
RUN mkdir -p /forgeflow-pg-client/bin /forgeflow-pg-client/lib \
    && cp /usr/lib/postgresql/16/bin/pg_dump /usr/lib/postgresql/16/bin/pg_restore /usr/lib/postgresql/16/bin/psql /forgeflow-pg-client/bin/ \
    && cp -L /usr/lib/*/libpq.so.5 /forgeflow-pg-client/lib/libpq.so.5
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates git tini python3 libpq5 libreadline8 liblz4-1 libzstd1 tar gzip && rm -rf /var/lib/apt/lists/* && useradd --uid 10001 --create-home forgeflow \
    && mkdir -p /var/lib/forgeflow && chown 10001:10001 /var/lib/forgeflow
# Bookworm's default pg_dump is older than the PostgreSQL 16 database. Copy
# only the matching client programs and libpq, rather than a second DB server.
COPY --from=postgres-tools /forgeflow-pg-client/bin/ /usr/local/bin/
COPY --from=postgres-tools /forgeflow-pg-client/lib/ /usr/local/lib/
RUN ldconfig && pg_dump --version && pg_restore --version && psql --version
COPY --from=rust /out/ /usr/local/bin/
COPY --from=console /src/console/dist /opt/forgeflow/console
USER 10001:10001
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["forgeflow-server"]
