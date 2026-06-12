---
updated: 2026-06-12
tags: [operability, proxy, telemetry, deploy, reliability]
---

# Operability / Day-2

The set of controls that let a paying operator *run and monitor* Haechi in
production, added under the reliability-hardening track WS4. Two slices:
**WS4-A** (health split, `/metrics`, structured logs, correlationId — already
merged) and **WS4-B** (resilience + deploy). All additive over the 1.1 line; new
config keys default to prior behavior, and the [[fail-closed]] posture holds for
every new path. Lives mostly in `packages/proxy/index.mjs`,
`packages/metrics/index.mjs`, and `packages/cli/runtime.mjs`.

## Observability surface (WS4-A)

Four unauthenticated routes under the reserved `/__haechi/*` prefix, short-circuited
at the TOP of the request handler (before auth/body):

- `GET /__haechi/live` — process liveness (cheap 200).
- `GET /__haechi/ready` — readiness; **503 when the audit sink is not writable**
  (a gateway that cannot audit is not ready). Probes `auditSink.ready()`/`healthCheck()`.
- `GET /__haechi/health` — back-compat (`ok` + `mode` + `version`).
- `GET /__haechi/metrics` — Prometheus text; `404` when `metrics.enabled: false`.

`runtime.metrics` is an injectable collaborator (default: a zero-dep in-memory
Prometheus-text collector in `packages/metrics/index.mjs`). The metric catalogue
is a fixed enum of counter/histogram names; **every label value is a bounded enum**
(route id / mode / decision class), length-capped + charset-sanitized as defence
in depth — the no-plaintext-in-audit invariant extended to telemetry. A per-request
`correlationId` (UUID) threads into every protect context (so a request's audit
events share it) and into the json error log, but is never a payload/PII value.

## Resilience (WS4-B)

`createHaechiProxy(...).close()` is a **graceful drain**: `server.close()` stops new
connections, `closeIdleConnections()` drops idle keep-alive immediately, in-flight
requests are tracked (a counter incremented on entry to a non-exempt request,
decremented in a `finally`) so close resolves once they drain, and a
`limits.shutdownGraceMs` (default 10000) timer force-closes stragglers via
`closeAllConnections()`. The grace timer is `.unref()`-ed and cleared on clean
drain — no leaked timer (the `node --test` suite must not hang).

**Backpressure:** `limits.maxInFlight` (default `0` = disabled, preserving 1.1).
When `> 0` and at the ceiling, a new request gets `503` + `Retry-After` + a
`{ error: "haechi_overloaded" }` body, before auth/body-read, counted as
`haechi_overloaded_total`. The `/__haechi/*` observability routes are **exempt**
(and uncounted) so liveness + metrics stay scrapable under saturation.

**Tuned timeouts:** `limits.requestTimeoutMs` / `limits.headersTimeoutMs` map to the
Node server's `requestTimeout`/`headersTimeout`; default `null` leaves Node's
defaults untouched (behavior unchanged unless opted in).

## Deploy (WS4-B)

- **Env overlay** in `loadConfig()` (applied after file read, before
  `normalizeConfig`): a FIXED allowlist of NON-SECRET keys — `HAECHI_PROXY_PORT`,
  `HAECHI_PROXY_HOST`, `HAECHI_UPSTREAM`, `HAECHI_MODE`, `HAECHI_LOG_FORMAT`. Env
  wins over the file; an invalid value **throws** naming the var (fail-closed).
  Secrets (`keys.*`, auth tokens) are deliberately NOT overlayable — they stay in
  the config file or injected providers.
- **Reference assets** at the repo root, NOT in the npm `files` allowlist (so they
  never leak into the tarball — verified by `check:packaging`): a hardened
  `Dockerfile` (pinned `node:22-bookworm-slim`, non-root `node` user, runtime files
  only, writable `.haechi` volume, `/__haechi/live` HEALTHCHECK), a
  `docker-compose.yml` (loopback port mapping + front-with-TLS/auth caveat,
  read-only rootfs, dropped caps), a `.dockerignore`, and
  `docs/current/operations-runbook.md` (+`.ko`).
- **`configVersion`** stamp (`CONFIG_VERSION = 1` in `runtime.mjs`): absent =
  current; a newer value **fails closed** at load; non-positive-integer throws.
  Upgrade map in `docs/current/config-version.md` (+`.ko`).

## Chain-aware audit rotation

The runbook's rotation procedure is [[audit-integrity]]-aware: rotate by starting a
NEW audit file + anchor and preserving prior segments — never truncate or rewrite a
chain mid-stream — so each retained segment stays an independently `verifyAuditChain`-able
chain (new chains legitimately start at `previousHash: null`).

## Invariants preserved

- Zero runtime dependency (only `node:` builtins; the metrics collector is in-core,
  the deploy assets are repo files).
- No plaintext/PII in telemetry or logs (extends the audit invariant).
- Additive only: api-contract freeze (`tests/api-contract.test.mjs`, a subset
  check) stays green; new config keys default to 1.1 behavior.

See also: [[runtime-composition]] (the provider-injection seam metrics/rateLimiter
ride on), [[fail-closed]], [[audit-integrity]].

Sources: `packages/proxy/index.mjs`, `packages/metrics/index.mjs`,
`packages/cli/runtime.mjs`, `docs/current/operations-runbook.md`,
`docs/current/config-version.md`, `docs/current/configuration.md`,
`tests/resilience.test.mjs`, `tests/observability.test.mjs`,
`docs/current/reliability-hardening-track.md` §WS4.
