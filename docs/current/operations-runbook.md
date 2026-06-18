# Haechi Operations Runbook (Day-2)

- Status: Living document (tracks core 1.5.x)

A practical guide to running Haechi in production: deploy, configure via the
env-var overlay, monitor with health/readiness/metrics, shut down gracefully,
tune backpressure, and rotate the audit log without breaking its hash chain.

This is an operability guide, not a compliance guarantee. See
[`configuration.md`](./configuration.md) for the full config reference and
[`threat-model.md`](./threat-model.md) for the trust boundary.

## 1. Deploy

Haechi is a zero-runtime-dependency Node `>=22` package. The reference
[`Dockerfile`](../../Dockerfile), [`docker-compose.yml`](../../docker-compose.yml),
and [`.dockerignore`](../../.dockerignore) at the repo root build a hardened
image (these files are **not** shipped in the npm tarball — they are repo deploy
assets). The image:

- pins a Node 22 slim base (matches `engines: ">=22"`),
- runs as the non-root `node` user,
- copies only the runtime files (no `.haechi` secrets, no tests, no docs sources),
- declares a writable `/app/.haechi` volume for the audit chain / key file / token
  vault and runs the rest of the tree read-only,
- ships a `HEALTHCHECK` against `/__haechi/live`.

```bash
docker compose up -d        # build + run the reference stack
docker compose logs -f haechi
```

**Pre-built image (GHCR).** Each `v<semver>` release publishes a cosign-signed
image to `ghcr.io/<owner>/haechi` (tags `<major>.<minor>.<patch>`, `<major>.<minor>`,
`<major>`, `latest`). Verify it before running — the signature and provenance bind
the image to this repo's release workflow:

```bash
cosign verify ghcr.io/<owner>/haechi:1.3.3 \
  --certificate-identity-regexp '^https://github.com/<owner>/haechi/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
gh attestation verify oci://ghcr.io/<owner>/haechi:1.3.3 --repo <owner>/haechi
```

The image bakes `proxy.trustForwardedProto: true` (it binds `0.0.0.0` behind a
TLS-terminating reverse proxy — see below), so Haechi requires `X-Forwarded-Proto:
https` on every protected request; mount your own config with `proxy.tls` set
instead if you want Haechi to terminate TLS itself.

**Front it with TLS + auth.** Haechi has no TLS of its own. Publish its port only
to a TLS-terminating, authenticating reverse proxy (nginx / Caddy / Traefik / an
API gateway); never expose the raw Haechi port on a public interface. The compose
example publishes to host loopback (`127.0.0.1:11016`) for exactly this reason.

**Binding beyond loopback.** Inside a container Haechi must bind `0.0.0.0` for the
mapped port to be reachable, which requires `--allow-remote-bind` (the reference
`CMD` passes it). On a host, prefer the default loopback bind and reach Haechi
through the reverse proxy. See [Binding beyond loopback](./configuration.md#binding-beyond-loopback).

## 2. Configuration via the env-var overlay

For container / 12-factor deploys, a **fixed allowlist of NON-SECRET operational
keys** may be overridden from the environment. The env value **wins over the
config file** and is validated fail-closed — an invalid value (bad port, unknown
mode) makes the process **fail to start** rather than degrade silently.

| Env var | Config key | Type / values | Example |
|---|---|---|---|
| `HAECHI_PROXY_PORT` | `proxy.port` | integer 0–65535 | `11016` |
| `HAECHI_PROXY_HOST` | `proxy.host` | non-empty string | `0.0.0.0` |
| `HAECHI_UPSTREAM` | `target.upstream` | URL string | `http://llm:8000` |
| `HAECHI_MODE` | `mode` | `dry-run` \| `report-only` \| `enforce` | `enforce` |
| `HAECHI_LOG_FORMAT` | `logging.format` | `text` \| `json` | `json` |

**Secrets are NOT overlayable — by design.** There is **no** `HAECHI_*` variable
for `keys.*` (the local key file or an external key path), the auth token store,
or any token/secret. Secrets stay in the mounted config file or are supplied via
**injected providers** (`createRuntime(config, { cryptoProvider, authProvider, … })`).
Putting a secret in a process environment invites leaking it through `/proc`,
crash dumps, orchestrator inspect output, and child processes — so the overlay
allowlist excludes them outright.

The overlay is applied in `loadConfig()` after reading the file and before
`normalizeConfig()`, so an overlaid value passes the same validation as a
file-set one.

## 3. Health, readiness, and metrics scraping

Four unauthenticated routes under the reserved `/__haechi/*` prefix, checked
before auth/body-read, never proxying upstream (full reference:
[Operability endpoints](./configuration.md#operability-endpoints)):

| Endpoint | Use |
|---|---|
| `GET /__haechi/live` | **Liveness** — restart probe. Cheap; 200 while the event loop serves. |
| `GET /__haechi/ready` | **Readiness** — traffic gate. **503 when the audit sink is not writable** (a gateway that cannot audit is not ready). Point your load balancer / orchestrator readiness probe here. |
| `GET /__haechi/health` | Back-compat (`ok` + `mode` + `version`). |
| `GET /__haechi/metrics` | Prometheus text exposition. `404` when `metrics.enabled: false`. |

**Scrape `/metrics`** with Prometheus (or any OpenMetrics-compatible scraper):

```yaml
scrape_configs:
  - job_name: haechi
    metrics_path: /__haechi/metrics
    static_configs:
      - targets: ["haechi:11016"]
```

Key signals: `haechi_requests_total{route,mode,decision}`, `haechi_blocks_total`,
`haechi_auth_denied_total`, `haechi_rate_limited_total`, `haechi_overloaded_total`
(backpressure 503s), `haechi_upstream_timeout_total`, `haechi_upstream_error_total`,
`haechi_response_unprotected_total`, `haechi_internal_error_total`, and the
`haechi_request_duration_seconds{route}` histogram.

**No-PII-in-telemetry invariant.** Every metric name and **every label value** is
a bounded enum (route id / mode / decision class) — never an identity, token, or
detected value. The same invariant covers structured logs: with
`logging.format: json` (or `HAECHI_LOG_FORMAT=json`), startup/shutdown/error logs
carry a `correlationId` and an error class name only, never a payload. The
`correlationId` also appears on the request's audit events, so you can join a
logged error to its audit trail.

## 4. Graceful shutdown

On `SIGINT`/`SIGTERM` the CLI calls the proxy's `close()`, which **drains
gracefully**:

1. stops accepting new connections (`server.close()`),
2. immediately closes idle keep-alive sockets (`closeIdleConnections()`),
3. waits for in-flight requests to finish,
4. after a grace period (`limits.shutdownGraceMs`, default 10000ms) force-closes
   any lingering socket (`closeAllConnections()`) so a stuck keep-alive cannot
   hold shutdown open forever.

`close()` resolves once in-flight requests drain or the grace elapses. Set your
orchestrator's `terminationGracePeriod` (Kubernetes) / `stop_grace_period`
(compose) **above** `limits.shutdownGraceMs` so the platform does not SIGKILL
mid-drain. Tune `limits.shutdownGraceMs` to your longest acceptable in-flight
request.

## 5. Backpressure tuning

`limits.maxInFlight` is a global ceiling on concurrently-processing requests.

- `0` (default) disables the ceiling — unchanged 1.1 behavior.
- `> 0`: when the live in-flight count is at the ceiling, a **new** request is
  rejected `503` with a `Retry-After` header (seconds, derived from
  `limits.shutdownGraceMs`) and a `{ "error": "haechi_overloaded" }` body, **before**
  auth and body-read. Each rejection increments `haechi_overloaded_total`.
- The `/__haechi/*` observability routes are **exempt** from the ceiling, so
  liveness and `/metrics` stay scrapable under saturation — you can still see
  *why* you are shedding load.

Set `maxInFlight` near the concurrency your upstream + host can sustain (watch
`haechi_request_duration_seconds` and upstream saturation), leaving headroom so
the gateway sheds load with a clean 503 instead of collapsing. Pair it with a
tuned `limits.upstreamTimeoutMs` so a slow upstream cannot pin slots indefinitely.

### Tuned timeouts

`limits.requestTimeoutMs` and `limits.headersTimeoutMs` map to the Node HTTP
server's `requestTimeout` / `headersTimeout`. Both default to `null` = leave
Node's server defaults untouched (behavior unchanged unless you opt in). Set a
number to cap slow-loris-style slow request/header delivery; `0` disables that
specific timeout (Node semantics).

## 6. Chain-aware audit log rotation & retention

The audit log is a **SHA-256 hash chain** (`audit.path`): each event's
`auditIntegrity.previousHash` links to the prior event's hash, so any insert,
delete, edit, or reorder is detectable by `haechi audit-verify` /
`verifyAuditChain`. An optional **anchor stream** (`audit.anchor`) appends the
chain head to separate append-only media so even tail truncation (deleting the
newest events) is caught. See [`audit` concepts](./configuration.md#audit) and the
threat model.

**Never truncate or rewrite a chain mid-stream.** Rotating by truncating
`audit.jsonl` in place, or rewriting earlier lines, **breaks the chain** and makes
verification fail (or, worse, silently destroys tamper evidence). Rotate by
**starting a new segment**, preserving prior segments:

1. **Stop or quiesce** the writer (graceful shutdown, or rotate at a maintenance
   window). The default JSONL sink appends; rotating a file it holds open is what
   you are avoiding.
2. **Move the current segment aside**, keeping it intact:
   `mv .haechi/audit.jsonl .haechi/audit-2026-06-12.jsonl` (and the matching
   anchor: `mv .haechi/audit.anchor.jsonl .haechi/audit-2026-06-12.anchor.jsonl`).
3. **Start a fresh segment** by restarting Haechi (or pointing `audit.path` /
   `audit.anchor.path` at the new files). The new chain begins with
   `previousHash: null` — a fresh, independently-verifiable chain. This is
   expected: each segment is its own verifiable chain; you do **not** chain across
   the rotation boundary.
4. **Verify each retained segment independently** with its own anchor:
   `haechi audit-verify --audit .haechi/audit-2026-06-12.jsonl --anchor .haechi/audit-2026-06-12.anchor.jsonl`.
5. **Retain prior segments** for your retention window so the full history stays
   verifiable. Archive (don't delete) to append-only / WORM storage where you can;
   the anchor's defense assumes the anchor lives on separate, append-only media.

**Retention:** keep each rotated segment (and its anchor) for your required
audit-retention period, then expire whole segments — never partial lines within a
segment. Token-vault retention is independent (`tokenVault.retentionDays`); audit
rotation does not purge tokens.

**Do not** compress/encrypt a segment in a way that prevents later
re-verification unless you keep the verification step in your archival pipeline. A
rotated segment is only useful as evidence if it still verifies.

## 7. Benchmarking proxy throughput

`npm run bench:throughput` (`scripts/bench-throughput.mjs`) measures the proxy's
added per-request overhead under concurrency. It stands up a deterministic local
**stub** OpenAI-compatible upstream (an instant canned reply — no real model) and
the **real** Haechi proxy in front of it, drives a configurable load with a
fixed-size worker pool of in-flight `fetch`es, and reports **req/s** plus
**p50/p95/p99/max** latency (percentiles by nearest-rank over a sorted sample). It
runs three scenarios:

1. **throughput + latency** at a fixed concurrency (a warmup batch is excluded
   from the reported stats — JIT/connection warmup skews the first requests),
2. **enforce vs dry-run overhead** — the same load run in both modes, reporting
   the latency/throughput **delta** so the cost of protection is a measured number,
3. **backpressure** — a low `limits.maxInFlight` saturated by a burst, reporting
   how many requests got `503 + Retry-After` vs `200` (observed live, proving the
   ceiling sheds load).

```bash
npm run bench:throughput
HAECHI_BENCH_REQUESTS=5000 HAECHI_BENCH_CONCURRENCY=64 npm run bench:throughput
```

Knobs (env, printed at the top of every run): `HAECHI_BENCH_REQUESTS` (total,
default 2000), `HAECHI_BENCH_CONCURRENCY` (default 32), `HAECHI_BENCH_WARMUP`
(excluded warmup count, default 100), `HAECHI_BENCH_PAYLOAD_KB` (default 1),
`HAECHI_BENCH_MAXINFLIGHT` (the backpressure scenario's ceiling, default 4).

> **The numbers are machine-relative.** This is a **loopback, single-process,
> stub-upstream micro-benchmark**: the stub, the proxy, and the load generator all
> run in one Node process on `127.0.0.1`, so there is no real network and no real
> model. The numbers measure Haechi's added overhead only, and vary by machine,
> Node version, and load. They are **not** a network/hardware throughput benchmark
> and must **not** be quoted as guarantees. The bench is not run by
> `release:preflight`.

## 8. Live upstream validation (real vLLM / Ollama)

The `local-inference` integration suite proxies a request through to a **real**
OpenAI-compatible (vLLM) and/or Ollama upstream and asserts the proxy round-trips
correctly (adapter routing + request/response protection over a real socket). It
is env-gated, so it **skips** unless you point it at a backend — CI runs it
against a protocol stub (a real vLLM needs a GPU and is not reachable from a
GitHub-hosted runner). To validate against your own backend from a host that can
reach it:

```bash
HAECHI_VLLM_URL=http://VLLM_HOST:8000  HAECHI_VLLM_MODEL=<served-model> \
HAECHI_OLLAMA_URL=http://OLLAMA_HOST:11434  HAECHI_OLLAMA_MODEL=<pulled-model> \
  npm run test:inference:live
```

Set only the backend(s) you have — each test skips when its URL is unset. Use
your own host/IP (do not commit it). For a continuously-exercised real-backend
gate, register a self-hosted runner on that network and trigger the suite there;
GitHub-hosted runners cannot reach a private LAN.

## 9. Key rotation & the AES-256-GCM nonce budget

The local AES-256-GCM crypto provider (`keys.provider: local`) encrypts every
`encrypt`-action segment under a random 96-bit IV. Random IVs stay safe only up
to a bounded number of encryptions per key — by the birthday bound, NIST
SP 800-38D §8.3 caps random-IV invocations at **2^32 per key**. The provider
enforces this automatically:

- It **counts encryptions per key** (`kid`) and persists the count to the key
  file (`keys.keyFile`) in pre-reserved windows, so the budget survives restarts.
- At **50%** of the budget it emits a one-time process warning
  (`code: HAECHI_NONCE_BUDGET`) — your cue to schedule a rotation.
- At the limit it **fails closed**: `encrypt` throws and the proxy returns an
  error rather than risk an IV collision (which would be catastrophic for GCM).

**Rotate before you hit the limit** (and on your normal key-rotation cadence):

```bash
haechi init --force        # mint a fresh active key; prior keys are RETIRED, not deleted
```

`--force` retires the current key (it stays `kid`-addressable so existing
envelopes and token-vault records still decrypt) and starts a new active key
with a fresh budget. No envelopes are orphaned.

**Read-only key file:** if `keys.keyFile` is mounted read-only, the budget cannot
be persisted; the provider warns once (`code: HAECHI_NONCE_BUDGET_NOPERSIST`) and
falls back to a **per-process** limit (cross-restart protection is off). Either
leave the key file writable by the proxy, or rotate keys on a fixed schedule.
**Production custody:** use an external `cryptoProvider` (the `haechi-crypto-kms`
satellite) — a KMS/HSM owns its own nonce discipline and this software budget
does not apply.

## 10. Quick reference

| Task | Command |
|---|---|
| Start (compose) | `docker compose up -d` |
| Liveness | `curl localhost:11016/__haechi/live` |
| Readiness | `curl localhost:11016/__haechi/ready` |
| Metrics | `curl localhost:11016/__haechi/metrics` |
| Throughput bench | `npm run bench:throughput` |
| Verify a segment | `haechi audit-verify --audit <seg>.jsonl --anchor <seg>.anchor.jsonl` |
| Graceful stop | `docker compose stop` (SIGTERM → drain) |

See also: [`config-version.md`](./config-version.md) for the `configVersion`
stamp and upgrade notes.
