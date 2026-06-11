---
updated: 2026-06-11
tags: [concept, security, observability, dashboard]
---

# Dashboard Audit Viewer

`haechi-dashboard@0.1.0` (`satellites/dashboard/`) is a **zero-dependency, read-only audit viewer**: a `node:http` server that serves the audit JSONL ([[audit-integrity]]) and its hash-chain status read-only, plus a single self-contained static page (vanilla JS, no framework, no build step). Shipped in the 0.9 cut (`docs/current/release-0.9-implementation-scope.md` §2.1; PR #39). It takes **paths** (`auditPath`/`anchorPath`), not a full runtime, and only imports `haechi/audit` (`verifyAuditChain`) and `haechi/proxy` (`assertSafeProxyBind`) from core — no satellite leaks into core, no core change.

Exports `createDashboardServer(options)` + `normalizeDashboardConfig(options)`; ships a `haechi-dashboard` bin.

## Config (fail-closed, parity with `normalizeConfig`)

`normalizeDashboardConfig` mirrors core's [[fail-closed]] discipline: strict, enumerated throws at construction, unknown keys rejected. Fields: `auditPath` (string, required), `anchorPath` (string|null), `host` (default `127.0.0.1`), `port` (integer 0–65535; **0 = OS-ephemeral**, an intentional test affordance), `allowRemoteBind` (bool), `sessionGuard` (object|null), `window` (bounded int, tail bytes, `[4096, 64 MiB]`, default 1 MiB), `tlsContext` (object|null — must carry `(key && cert)` or `pfx`), `trustProxy` (non-empty string|null). Documented in `configuration.md` (EN+KO).

## Security model

The viewer's whole job is to expose audit data without becoming an exfiltration or tamper surface. The controls (each an acceptance criterion, not an option):

- **Loopback bind by default.** Reuses core's exported `assertSafeProxyBind` for the bind-string check (no core relocation), then **catches and rethrows a dashboard-worded message** (it exposes an `allowRemoteBind` option, not the proxy's `--allow-remote-bind` flag). Its own small `isLoopbackHost` predicate drives the precedence decision because proxy's `isLoopbackHost` is private.
- **Remote bind is fail-closed (exact precedence).** (1) non-loopback without `allowRemoteBind` → throw; (2) remote + `allowRemoteBind` but **no `sessionGuard`** → throw `"remote bind requires a sessionGuard"`; (3) remote requires the dashboard itself to **terminate TLS** (a valid `tlsContext`) — `trustProxy` alone never authorizes a non-loopback plaintext listener (a `Secure`/`__Host-` session cookie is never sent over plaintext http, so login would silently break). HSTS is emitted **only** when the server actually serves https.
- **Anti-DNS-rebinding Host-header allowlist** — the **unconditional first gate on every request** (before the method check, so a rebinding page learns nothing from a method-specific status). Distinct from the bind check: `assertSafeProxyBind` validates a bind string, this normalizes an *untrusted* `Host` header (parse host+port, reject duplicate/malformed `Host` via any comma, strip one trailing dot, handle bracketed IPv6 + `::ffff:127.0.0.1`). A non-allowlisted host → `403`. This is necessary because loopback bind alone does not stop a malicious site re-resolving a short-TTL name to `127.0.0.1` and reading the audit JSON same-origin. **CORS is absent** — `Access-Control-Allow-Origin` is never set/reflected; `Cross-Origin-Resource-Policy`/`Cross-Origin-Opener-Policy` `same-origin` are a second layer.
- **Method allowlist:** only `GET`/`HEAD` (anything else → `405`). No `POST`/`DELETE` surface — no reveal, no purge, no policy edit (those stay in the CLI under [[token-vault]] reveal governance). "Read-only" = no audit-data mutation and no privileged action.
- **Recursive key-by-key projection** (defense in depth over [[audit-integrity]]'s `FORBIDDEN_KEYS`). Events are rebuilt field-by-field — never a blind spread of a nested sub-object (`detections`, `identity`, `summary`, `auditIntegrity`), so a future field at any level defaults to dropped. `identity` projects only `id`/`type`/`subjectHash`/`issuerHash`/`provider` — **never** `scopes`/`labels`/a raw subject.
- **XSS containment.** `detections[].path` derives from client-supplied JSON keys (a request key `<img onerror>` reaches the log). The allowlist bounds field *names*; the served page renders values with `createElement` + `textContent` only. The exact CSP (asserted verbatim) is `default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'none'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'; require-trusted-types-for 'script'` — Trusted Types makes any stray `innerHTML` sink throw in-browser. Plus `nosniff`, `Referrer-Policy: no-referrer`, `X-Frame-Options: DENY`, and `Cache-Control: no-store`.
- **Generic errors.** Handler errors return a fixed `{ error: "internal" }` 5xx — never a stack, OS error code, or an absolute path (`auditPath`/`anchorPath` are sensitive; the anchor is the out-of-band truncation defense). The real reason is logged server-side only.
- **Satellite-local rate limiter.** Proxy's `createRateLimiter` is private, so the dashboard ships its own tiny per-source fixed-window (60s) counter (with key-cap eviction) on `/api/*` — a documented deviation that keeps 0.9 with **no core change**.

## API (all GET/HEAD, read-only)

- `GET /api/events?cursor=&limit=` — newest-first bounded-tail page. **Strict query parsing:** `limit` ∈ `[1,200]` (reject `NaN`/negative/non-integer); `cursor` is opaque = `auditIntegrity.sequence` (monotonic), **never an fs offset**, `400` if malformed. Events are projected; a page older than the retained tail window returns a `windowExceeded` marker (not an error); a torn trailing line from a concurrent append is skipped, never a `500` (mirrors `readAnchors`).
- `GET /api/chain` — wraps `verifyAuditChain(auditPath, { anchorPath })`'s **real** output: success `{ valid:true, records, headHash, anchored?:{count,lastSequence} }`; failure `{ valid:false, records, truncationDetected }` where **`truncationDetected` is derived** by the dashboard as `reason.startsWith("tail truncation")` — **the raw `reason` is never surfaced** (it can embed an `eventHash`/sequence). Bounded compute: a single serialized in-process job, `mtime+size`-keyed cache (no concurrent re-walk); above a hard size cap → `413`/`{valid:null}`; `HEAD` returns the cached status, never forcing a walk.
- `GET /api/summary` — aggregates the window's `summary.byType`/`byAction`/`detectionCount`.
- `GET /healthz` — liveness only, no audit data/paths; **intentionally reachable without a session even off-loopback** (a guarded remote dashboard must still answer probes).

## sessionGuard seam ([[identity-and-auth]])

The dashboard defines a `sessionGuard` contract `{ authenticate(req) -> session|null, handlers: { "/auth/login", "/auth/callback", "/auth/logout" } }` and injects it (like `cryptoProvider`) — **no peer dependency** on an auth package; either satellite is usable alone. [[oidc-session-broker]] satisfies it.

- An unauthenticated `/api/*` request on a guarded dashboard returns **`401` (never `302`** — a redirected fetch leaks the login URL or loops; the static shell performs the redirect).
- The auth-exempt set is the **intersection** of a **fixed** broker-path allowlist `{/auth/login, /auth/callback, /auth/logout}` and the declared handlers, matched **exactly**. `normalizeDashboardConfig` also rejects any handler key outside that fixed list. So a guard can **never** exempt `/api/chain`, `/healthz`, or `/` from `authenticate()` — a future broker route can't become an unauthenticated bypass.

## Packaging

`peerDependencies: { haechi: ">=0.8.0 <1.0.0" }` + `devDependencies: { haechi: "*" }`, **zero runtime dependency** (`node:` builtins only), own bin, `publishConfig: { access: "public", provenance: true }`. Publishes via `.github/workflows/dashboard-publish.yml` on a `dashboard-v<semver>` tag (`if: startsWith(tag,'dashboard-v')` + regex `^dashboard-v[0-9]+\.[0-9]+\.[0-9]+$`). See [[packaging-and-distribution]].
