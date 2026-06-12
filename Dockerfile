# Haechi reference Dockerfile — a hardened, zero-runtime-dependency AI context
# enforcement gateway. NOT published to npm (the repo-root Dockerfile is not in
# the package.json "files" allowlist). See docs/current/operations-runbook.md.
#
# Hardening posture:
#   - Pinned Node 22 slim base (matches engines ">=22"; zero runtime deps means a
#     slim base is enough — no native build toolchain needed).
#   - Runs as the non-root `node` user that the official image already ships.
#   - Copies ONLY the runtime files (no .haechi keys, no tests, no docs sources)
#     — the .dockerignore keeps secrets and dev cruft out of the build context.
#   - Declares a writable /app/.haechi volume for the audit log / key file / token
#     vault; the rest of the tree can run read-only (compose sets read_only: true).
#   - A HEALTHCHECK hits the cheap /__haechi/live liveness route.
#
# Pin to a digest in production. The tag below is the floor; resolve + pin the
# digest in your registry mirror (e.g. node:22-bookworm-slim@sha256:...).
FROM node:22-bookworm-slim

# Tini-free: Node handles SIGTERM/SIGINT itself (the CLI installs a graceful
# shutdown handler that drains in-flight requests — see the runbook).
ENV NODE_ENV=production \
    HAECHI_PROXY_HOST=0.0.0.0 \
    HAECHI_PROXY_PORT=11016

WORKDIR /app

# Copy only what the runtime needs. Core has ZERO runtime dependencies, so there
# is no `npm install` step — the package IS its own node:-only source tree.
# .dockerignore excludes .haechi, tests, satellites, .git, etc.
COPY package.json ./
COPY packages ./packages
COPY haechi.config.example.json ./

# Provide a default config unless one is mounted. An operator mounts their own
# haechi.config.json over this (and supplies secrets via the mounted file /
# injected providers, NEVER via env — see the env-overlay table in the runbook).
RUN cp haechi.config.example.json haechi.config.json \
    && chown -R node:node /app

# A writable state dir for the audit chain, local key file, and token vault.
# Declared a VOLUME so it is not baked into the image layer and survives as a
# mounted, writable path even under a read-only root filesystem.
RUN mkdir -p /app/.haechi && chown node:node /app/.haechi
VOLUME ["/app/.haechi"]

# Drop privileges: run as the unprivileged `node` user (uid 1000) the base ships.
USER node

EXPOSE 11016

# Liveness probe against the cheap process-liveness route. Uses Node (no curl in
# the slim base) so the healthcheck has no extra dependency.
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["node", "-e", "fetch('http://127.0.0.1:'+(process.env.HAECHI_PROXY_PORT||11016)+'/__haechi/live').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"]

# Bind beyond loopback (0.0.0.0) is required INSIDE the container so the mapped
# port is reachable; --allow-remote-bind acknowledges that. Front Haechi with a
# TLS/auth reverse proxy and restrict the published port — see the runbook and
# docker-compose.yml.
CMD ["node", "packages/cli/bin/haechi.mjs", "proxy", "--allow-remote-bind"]
