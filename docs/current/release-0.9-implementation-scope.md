# Haechi 0.9 Implementation Scope

- Status: Draft 0.2 (design — not yet implemented; hardened after an adversarial security review, 2026-06-11)
- Date: 2026-06-11
- Target version: 0.9.0 (after 0.8.0)
- Type: observability + interactive auth

## 1. Release Goal

Deliver the **observability + interactive-auth** pair that 0.8 deliberately deferred to stay code-light:

- **`haechi-dashboard`** — a zero-dependency, read-only **audit viewer**: a `node:http` server that serves a single self-contained static page (vanilla JS, no framework, no build step) plus a read-only JSON API over the audit log and its hash-chain status.
- **`haechi-auth-oidc`** — an **interactive session broker**: the OIDC authorization-code + PKCE flow that lets a human log in through a browser and obtain a server-side session. This is the dashboard's login mechanism — a different concern from `haechi-auth-jwt` (which validates a *pre-obtained* bearer JWT per request).

Both are new **unscoped satellites** (`haechi-dashboard`, `haechi-auth-oidc`) following the 0.8 packaging model: peer-dep on core, zero-dep where the protocol allows, optional-peer for any heavy SDK, OIDC trusted publishing with provenance + sigstore.

**Scope decision (2026-06-11).** Confirmed with the maintainer:

1. **Release unit:** `haechi-dashboard` + `haechi-auth-oidc` ship **paired** as the 0.9.0 theme (the dashboard needs human login; auth-oidc provides it). The **`haechi-crypto-kms` Vault/GCP/Azure backends ship independently** as `haechi-crypto-kms@0.2.0` — that satellite is versioned on its own and is **not gated on the core 0.9.0 cut**. This doc specifies all three but treats crypto-kms 0.2.0 as a parallel, decoupled track (§2.4).
2. **Dashboard stack:** **zero-dependency vanilla** — `node:http` + a static HTML/JS/CSS page, no framework, no build step. Consistent with core's `node:`-builtins-only ethos and the satellites' dependency-light posture.
3. **`haechi-auth-oidc` shape:** **interactive session broker** (authorization-code + PKCE + `/callback` + server-side sessions). Not a per-request token validator — that overlap stays with `haechi-auth-jwt`.
4. **Dashboard data scope:** **audit viewer only** — the audit event stream + `verifyAuditChain` chain status + decision/action aggregates. Token-vault and policy visualization are out of scope for 0.9 (avoids brushing against reveal governance).

Core (`haechi`, unscoped) stays **zero runtime dependency** and is **not modified for behavior** in 0.9. The only existing-package change is an *additive, behavior-preserving* refactor of the `haechi-auth-jwt` satellite to export a reusable JWS verifier (§2.2) — **no `packages/*` (core) code change is required**. The dashboard's loopback guard reuses the already-exported `assertSafeProxyBind` from `haechi/proxy` (no core relocation — §2.1).

### Version preconditions (live state as of 2026-06-11)

| Package | Current | 0.9 target | Why |
|---|---|---|---|
| `haechi` (core) | `0.8.0` (published) | `0.9.0` | release cut; behavior unchanged |
| `haechi-auth-jwt` | `0.1.1` (published) | **`0.2.0`** | additive verifier export (§2.2) — the publish workflow's tag==package-version gate requires the explicit bump |
| `haechi-crypto-kms` | `0.1.1` (published) | **`0.2.0`** | additive GCP/Azure/Vault backends (§2.4); also reconcile the hard-coded provider `version` field (§2.4) |
| `haechi-dashboard` | — (new) | `0.1.0` | first publish claims the unscoped name |
| `haechi-auth-oidc` | — (new) | `0.1.0` | first publish claims the unscoped name |

Per the workspace-lockfile rule (it has bitten us before), adding the two **new** `satellites/*` directories requires an `npm install` to regenerate `package-lock.json` with their workspace entries, committed in the same PR, or CI `npm ci` fails.

## 2. Scope

### 2.1 `haechi-dashboard` — zero-dep read-only audit viewer

A satellite exposing `createDashboardServer(options)` plus an optional bin (`haechi-dashboard`). It reads the existing audit JSONL (and anchor stream) and serves them read-only. **It never imports a framework, never has a build step, and ships exactly three static assets** (one HTML, one JS, one CSS) served from a **fixed in-code asset map** — never an `fs` path derived from the request URL (no path traversal).

**Config + fail-closed validation (config invariant parity).** Because satellites are wired by explicit injection rather than the core config file, the dashboard ships an exported **`normalizeDashboardConfig(options)`** that mirrors `normalizeConfig`'s discipline: **strict, fail-closed, enumerated throws at construction** (every option type-checked; unknown keys rejected). Fields: `auditPath` (string, required), `anchorPath` (string|null), `host` (default `127.0.0.1`), `port` (integer 1–65535), `allowRemoteBind` (bool), `sessionGuard` (object|null), `window` (bounded int), `tlsContext`/`trustProxy` (§ remote-bind). Each invalid option throws a stable error; `configuration.md` (+ `.ko.md`) gets a dashboard section enumerating every option, type, default, and throw condition. `createDashboardServer` calls `normalizeDashboardConfig` first.

**Construction-time bind/guard precedence (fail-closed, exact order):**

1. `!isLoopback(host) && !allowRemoteBind` → **throw** (the loopback guard; see below).
2. `!isLoopback(host) && allowRemoteBind && !sessionGuard` → **throw** `"remote bind requires a sessionGuard"`.
3. `!isLoopback(host)` (remote, guarded) → **require confirmed HTTPS termination** (a `tlsContext`, or `trustProxy` honoring `X-Forwarded-Proto` only from a configured trusted-proxy address) — otherwise **throw** (a Secure/`__Host-` session cookie is never sent over plaintext http, so a non-TLS remote bind silently breaks login; fail closed). `Strict-Transport-Security` is added on the remote path.

**Loopback bind** reuses core's exported `assertSafeProxyBind` (`import { assertSafeProxyBind } from "haechi/proxy"` — already exported, **no core relocation**, no new `haechi/net` export). Its thrown text is proxy-worded and names `--allow-remote-bind`; the dashboard **catches and rethrows its own message** (it exposes an `allowRemoteBind` option, not that CLI flag) so the error points at the right component.

**Anti-DNS-rebinding Host-header allowlist (mandatory, distinct from the bind check).** Loopback bind does **not** by itself protect an unauthenticated localhost viewer: any site the operator browses can publish a short-TTL DNS name that re-resolves to `127.0.0.1`, and the victim's browser will then make same-origin requests to the dashboard, letting the attacker's JS read the audit JSON. Therefore **every** request (incl. `/api/*` and `/healthz`) is rejected with `403` unless the **`Host` header** host-portion is in the allowlist `{localhost, 127.0.0.1, [::1], ::1, ::ffff:127.0.0.1, the configured bind host}`. This is a **separate request-header function from the bind-string check** (`assertSafeProxyBind` validates a bind string, not an untrusted header), with its own normalization: parse `Host` into host+port, reject malformed/duplicate `Host` headers, strip a single trailing dot (`localhost.`), handle IPv4-mapped IPv6 and bracketed IPv6. CORS is **absent** — `Access-Control-Allow-Origin` is never set/reflected.

**API (all GET/HEAD, read-only):**

- `GET /api/events?cursor=&limit=` — newest-first, **bounded-window** page of audit events. **Strict query parsing:** `limit` must be an integer in `[1,200]` (reject `NaN`/negative/non-integer); `cursor` is an opaque server-issued token = the `auditIntegrity.sequence` (monotonic, stable), `400` if malformed — **never used directly as an fs offset**. Events pass through a **recursive, key-by-key field allowlist projection** built against the **real** audit schema (below) — the server **never spreads or passes a nested sub-object (`detections`, `identity`, `summary`, `auditIntegrity`) through blind**, so a future field at any level can't leak (defense in depth over core's `FORBIDDEN_KEYS`). Pages older than the bounded tail window return empty with a `"window exceeded"` marker (not an error); a torn trailing line from a concurrent append is tolerated and skipped (as `readAnchors` already does), never a `500`.
- `GET /api/chain` — derived from `verifyAuditChain(auditPath, { anchorPath })`'s **real** output: success `{ valid:true, records, headHash, anchored?:{count,lastSequence} }`, failure `{ valid:false, records }`. **`truncationDetected` is derived** by the dashboard as `valid===false && reason.startsWith("tail truncation")`; **the raw `reason` string is NOT surfaced** (it can embed an `eventHash`/sequence — e.g. `"anchor hash mismatch at sequence N"`). `valid===false` is shown prominently (it is the one tamper signal). **Bounded compute:** a single serialized in-process job (no concurrent re-walks), recomputed only when the audit file's `mtime+size` changed (cache key = `mtime+size`); above a hard max file size, return `413`/`{valid:null}` instead of walking. `HEAD /api/chain` returns headers only and never forces a fresh walk.
- `GET /api/summary` — aggregates from the event window's `summary.byType` / `summary.byAction` / `summary.detectionCount`.
- `GET /healthz` — liveness only (no audit data, no paths/version/config); **intentionally reachable without a session even off-loopback** (a guarded remote dashboard must still answer liveness probes).

**Real audit event schema (the projection source of truth).** The on-disk record (built in `packages/core/index.mjs` `buildAuditEvent`, integrity added by `packages/audit/index.mjs`) is:

```
{ id, timestamp, protocol, operation, identity, profile, mode, enforced, blocked,
  payloadShapeHash,
  detections: [ { type, ruleId, path, kind, confidence, action, enforced } ],   // `path` is the former "pathText" — the XSS-bearing, client-key-derived field, NESTED here
  summary: { byType, byAction, detectionCount },
  auditIntegrity: { alg, canonicalization, sequence, previousHash, eventHash } } // proxy-recorded events may also add a top-level `direction`
```

The projection emits, key-by-key: top-level `id, timestamp, protocol, operation, mode, enforced, blocked, direction?`; per-detection `type, ruleId, path, kind, confidence, action, enforced`; `summary.{byType, byAction, detectionCount}`; `auditIntegrity.{sequence, previousHash, eventHash}`; `identity.{id, type, subjectHash, issuerHash, provider}` (**never** `scopes`/`labels`/a raw subject). `payloadShapeHash` may be included (shape-only hash, non-sensitive).

**Web-security spec (acceptance criteria, not options):**

- **XSS.** The allowlisted `detections[].path` derives from client-supplied JSON keys (a request key `<img onerror>` reaches the log). The **allowlist bounds field *names* (leak containment); CSP + `textContent` rendering neutralizes malicious *values*** — both are required and independent. The client builds DOM with `createElement` + `textContent` only (never `innerHTML` with interpolation). CSP (verbatim, every response): `default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'none'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'; require-trusted-types-for 'script'` — Trusted Types makes any stray `innerHTML` sink throw in-browser, turning the convention into an enforced guarantee. No inline scripts/styles (same-origin asset files), no external CDN, no `eval`.
- **Security headers (every response):** `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `X-Frame-Options: DENY` (legacy clickjacking fallback), `Cross-Origin-Resource-Policy: same-origin` and `Cross-Origin-Opener-Policy: same-origin` (CORP same-origin blocks a cross-origin page from reading `/api/*` as a resource — a second layer against the rebinding/no-cors exfil, independent of the Host check). `Cache-Control: no-store` on `/api/*` **and** on the HTML shell (it renders live audit data); JS/CSS get a short validated cache (or `no-store` globally — a localhost tool gains nothing from caching).
- **Method allowlist:** only `GET`/`HEAD`; anything else → `405`. There is **no** `POST`/`DELETE` surface (no reveal, no purge, no policy edit — those stay in the CLI under reveal governance). "Read-only" means **no audit-data mutation and no privileged action**; `/api/chain` does have a bounded compute side effect (acknowledged), which the cache + size cap + (below) rate limit bound.
- **Generic errors (no info disclosure).** Handler errors return a fixed `{ error: "internal" }` 5xx — **never** a stack, message, OS error code, or an absolute path (`auditPath`/`anchorPath` are sensitive; the anchor path is the out-of-band truncation defense). `verifyAuditChain` `reason` text is logged server-side only.
- **Rate limiting / DoS.** Reuse the proxy's exported `createRateLimiter` for a per-source cap on `/api/*` (in addition to the chain-verify `mtime+size` cache), so an unauthenticated loopback caller (or a rebinding page) cannot pin a CPU core via `/api/chain`. Event reads tail a **bounded byte/line window** and stream-parse — never load the whole file.
- **Remote bind requires a session guard *and* TLS** (precedence above): the only unauthenticated mode is **loopback** (and even there, the Host-allowlist + CORP apply).
- **No plaintext, ever.** Only already-sanitized fields, projected; identity shown as `subjectHash`/`issuerHash`/`id` only.

**Packaging:** new satellite `haechi-dashboard`, **zero runtime dependency** (`node:` builtins only), `peerDependencies: { haechi: ">=0.8.0 <1.0.0" }` + `devDependencies: { haechi: "*" }`, its own bin and `publishConfig: { access: "public", provenance: true }`. No core CLI change — the satellite owns its entry point; core never references a satellite.

### 2.2 `haechi-auth-oidc` — interactive OIDC session broker

A satellite exposing `createOidcSessionBroker(options)` (with an exported, fail-closed **`normalizeOidcConfig`** mirroring §2.1's discipline — enumerated throws for `issuer`/`clientId`/`clientSecret`/`redirectUri`/`scopes`/`cookie`/`returnToAllowlist`/`sessionTtlSeconds`/`idleTtlSeconds`/`maxAgeSeconds`/`tokenEndpointAuthMethod`, all documented in `configuration.md`). It implements the **authorization-code flow with PKCE** and produces a **server-side session** consumable by the dashboard (it satisfies the dashboard's `sessionGuard` seam, §2.3). It is **not** an `authProvider` (per-request bearer) — that role stays with `haechi-auth-jwt`.

**Construction-time checks (fail-closed):** `cryptoProvider.hmac` required (no PII-safe identity without it); `issuer` a valid HTTPS URL; `redirectUri` a valid absolute URL, **https (or loopback http under the same carve-out) and same-origin with the broker**, whose **path equals the mounted `/auth/callback`** (the identical `redirect_uri` is sent on both the authorization request and the token exchange, per RFC 6749); `openid` is always force-included in `scopes` (deduped) and `offline_access` is stripped (refresh handling is out of scope, §3); off-loopback without confirmed external HTTPS → reject (cookie hardening keys off the **externally-visible** scheme, not the local socket — provide `secureCookies: true|'auto'`/`trustProxy` so a TLS-terminating reverse proxy forces `Secure` + `__Host-`; default fail-closed).

**Flow handlers (the dashboard mounts these at exact literal paths):**

- `GET /auth/login` — generate CSPRNG `state`, `nonce`, PKCE `code_verifier`; `code_challenge = S256(code_verifier)` (**S256 mandatory, never `plain`**); persist the trio + the **pinned resolved `issuer`/`token_endpoint`/`jwks_uri`** in a server-side **pending-auth** record keyed to a short-TTL **pre-auth cookie**; `302` to the discovered `authorization_endpoint` with the exact `redirect_uri`. When `maxAgeSeconds` is configured, send `max_age` (and require `auth_time` at callback).
- `GET /auth/callback` — **state-first short-circuit** (closes the timing/oracle gap): **atomically `take()`** the pending record by the pre-auth cookie and assert `record.state === query.state` **before any outbound request**; a missing/used/mismatched state or a missing/mismatched pre-auth cookie → deny with **no** IdP round-trip (defeats authorization-code injection / login-CSRF and the replay TOCTOU). Then redeem `code` **only at the pinned `token_endpoint`** with the `code_verifier` (+ client auth, below); **verify the ID token** (shared verifier + ID-token profile, below) including **`nonce` match** and (RFC 9207) any returned `iss` response param equal to the pinned issuer (mix-up defense); **mint a fresh session id** (discard the pre-auth cookie and any prior session — no fixation); set the session cookie; `302` to an **allowlisted relative** return path (default `/`).
- `POST /auth/logout` — **non-GET, CSRF-protected** (a per-session synchronizer token or a same-origin custom-header fetch which `connect-src 'self'` already implies — do **not** rely on `SameSite` alone). **Fully destroys server-side session state** (replaying the old cookie afterward → `401`), clears the cookie. Optional RP-initiated logout: send `id_token_hint` + a fresh `state`; any `post_logout_redirect_uri` must be a pre-registered/allowlisted absolute URL (reuse the `returnToAllowlist` discipline) or be omitted (no logout open-redirect).

**OIDC discovery (SSRF-hardened):**

- Fetch `<issuer>/.well-known/openid-configuration` over **HTTPS only**, bounded body (≤ 1 MiB), strict JSON depth; **reject unless `metadata.issuer` string-equals the configured `issuer`** (OIDC Discovery §4.3 / RFC 8414 — issuer-confusion guard) and pin the verifier's expected `iss` to it.
- **Single-origin only (0.9):** `authorization_endpoint`, `token_endpoint`, `jwks_uri`, `end_session_endpoint` must share the **issuer hostname** — same constraint and rationale as `haechi-auth-jwt` 0.8 (multi-origin/CDN-fronted IdPs remain out of scope). Cross-origin endpoints rejected at discovery/construction.

**Every outbound egress runs the same guard (not just JWKS/discovery).** The authorization-code flow adds a **`token_endpoint` POST** the shared JWKS verifier never makes; a token endpoint that DNS-rebinds to `169.254.169.254` between discovery and exchange is the classic metadata-exfil path. So **discovery GET, JWKS GET (via the shared verifier), the token-exchange POST, and any end-session redirect** each run a **`lookup`-then-`isBlockedAddress` re-check immediately before the request** (post-DNS, rebinding guard — refusing `127/8`, `::1`, `10/8`, `172.16/12`, `192.168/16`, `169.254/16` incl. `169.254.169.254`, `fe80::/10`), with `redirect: "error"`, a **bounded response body**, and a fetch timeout. (Factor this SSRF helper so the Vault backend (§2.4) reuses it instead of a third drifting copy.)

**Shared JWS verifier + ID-token profile.** 0.9 refactors `haechi-auth-jwt@0.2.0` to **additively export** a standalone verifier primitive (e.g. `createJwtVerifier`/`verifyJwt`) carved out of the existing internal `resolveJwk`/`verifySignature`/claim-validation — **behavior-preserving**: the primitive verifies **signature + `alg`/`kid`/RSA-bits + `iss`/`aud`/`exp`/`nbf` only** (the exact 0.8 surface), and **`nonce` is NOT baked into the primitive** (a bearer JWT has none) — it is verified by auth-oidc *after* the primitive returns validated claims (or via an optional `expectedNonce` that is a no-op when omitted). `createJwtAuthProvider` is reimplemented on the primitive and keeps owning Bearer-header parsing, so **all its 0.8 §6.3 tests pass unchanged**. `haechi-auth-oidc` **peer-depends on `haechi-auth-jwt >=0.2.0 <1.0.0`** and uses the primitive, giving exactly **one audited JWS/JWKS verification path**.

The full 0.8 JWT security spec applies to ID-token verification verbatim (server-side `alg` selection, reject `alg:none`, alg-confusion block, `kid` required, RSA ≥ 2048, JWK `use`/`key_ops` intent, `typ`/no-JWE, mandatory `exp`/`nbf`, `clockSkew` ≤ 300 s, SSRF-hardened bounded JWKS, ≤ 1-refetch-per-60 s). **Plus an OIDC ID-token profile distinct from the lenient bearer `aud` check** (the 0.8 `audienceMatches` accepts any array containing the audience — non-compliant for ID tokens): `aud` MUST contain `clientId`; **if `aud` is multi-valued, `azp` MUST be present and `azp === clientId`**; a single-valued `aud` MUST equal `clientId` (OIDC Core §3.1.3.7 — closes cross-client/mix-up). The broker is a **pure-login** consumer: it **discards the access token** (does not store or use it), which both shrinks the server-side secret surface and makes `at_hash`/`c_hash` validation intentionally out of scope (documented).

**Client authentication at the token endpoint:** default **`client_secret_basic`** (HTTP Basic, RFC 6749 §2.3.1), `client_secret_post` as explicit opt-in; on discovery, assert the configured method is in `token_endpoint_auth_methods_supported` and **never downgrade a confidential client to `none`**. The `client_secret` goes in the Basic header or POST body only — **never** the URL/query, **never** logged. Public clients (PKCE-only, no secret) are also supported.

**Session security (acceptance criteria):**

- **Server-side sessions; tokens never reach the browser.** Session id = high-entropy CSPRNG opaque value (≥ 256-bit); the **cookie carries only the id**. ID/access/refresh tokens and the `client_secret` are held server-side only (the access token is discarded; see above) and are **never** sent to the client or written to a log. Default store is in-memory with a documented injectable `sessionStore`/`pendingStore` contract requiring an **atomic `take()`** (consume-and-delete) for single-use semantics under concurrency; TTL + idle eviction.
- **Two distinct cookies, both hardened.** `__Host-haechi_preauth` (login-time, single-use, **cleared at callback**) and `__Host-haechi_session` (post-callback). Both `HttpOnly`, `SameSite=Lax` (Lax — not Strict — so the IdP→`/callback` top-level GET carries the cookie; Strict would drop it and break login), `Path=/`, and `Secure` + the `__Host-` prefix (which forbids `Domain` and forces `Path=/`) **mandatory whenever the externally-visible scheme is https** (keyed off the forwarded/declared scheme, not the local socket — see construction checks).
- **PII-safe identity** via core's `buildExternalIdentity` (keyed-HMAC `subjectHash` from the ID-token `sub`, domain `haechi:identity:hash:v1`; `provider: "oidc"`); raw `sub`/email/name **never** logged or stored.
- **Open-redirect prevention:** post-login `return_to` must be a **relative, same-origin path** validated against `returnToAllowlist`; an absolute/off-origin URL is rejected → falls back to `/`.
- **Rate-limiting / anti-DoS:** a **hard pending-auth cap** with explicit overflow = **reject new `/auth/login` with a generic `429`/`503` (fail-closed; never silently evict a legitimate in-flight auth)**, plus a per-source rate limit on `/auth/login` and `/auth/callback` (reuse `createRateLimiter`) so an attacker can't exhaust the pending store or pin CSPRNG/PKCE CPU.
- **Fail-closed everywhere:** any discovery/exchange/verification/state-mismatch error → no session, a generic deny, **no IdP error detail echoed**, same status+body for all callback failures (state-first short-circuit already prevents distinguishing unknown-state from bad-code by outbound side effect).

**Broker audit trail (PII-safe, the dashboard's reason to exist).** `createOidcSessionBroker` takes an **injectable `auditSink`** and emits `oidc.login.start`, `oidc.login.success`, `oidc.login.failure{ reasonCode }`, `oidc.logout`, `oidc.session.evict` — each carrying **only** `subjectHash`/`issuerHash`/`sessionIdHash` (keyed-HMAC; never the raw session id), `provider:"oidc"`, a coarse `reasonCode` enum (`state_mismatch|nonce_mismatch|token_invalid|exchange_failed|host_blocked|expired`), and a timestamp — so failed-login / brute-force against `/auth/callback` is **visible** (a per-request validator like auth-jwt could omit this; an interactive login can't). The broker projects through its own allowlist (and we **extend core's `FORBIDDEN_KEYS`** to also cover `access_token`/`id_token`/`refresh_token`/`code`/`code_verifier`/`client_secret`/`state`/`nonce`/`sub`/`email`) so a future field can never leak. A test asserts `JSON.stringify` of every emitted event contains none of those token/secret/raw-claim strings. *(Note: extending `FORBIDDEN_KEYS` is the one touch to `packages/audit` — additive set members, no behavior change to existing events.)*

**Packaging:** new satellite `haechi-auth-oidc`, **zero runtime dependency** (`node:` `fetch`/`crypto`/`http` suffice), `peerDependencies: { haechi: ">=0.8.0 <1.0.0", "haechi-auth-jwt": ">=0.2.0 <1.0.0" }` — the **core peer stays `>=0.8.0`** (auth-oidc uses only `buildExternalIdentity`, present since 0.6/0.8; do **not** over-tighten to `>=0.9.0`), while the **auth-jwt peer is `>=0.2.0`** because the verifier export is new. Plus `devDependencies: { haechi: "*" }`, `publishConfig: { access: "public", provenance: true }`, prefixed-tag publish workflow `auth-oidc-v<semver>`.

### 2.3 Dashboard ↔ OIDC integration seam (injection, not a hard dependency)

The two satellites are **paired in the release but decoupled in code**, via injection:

- `haechi-dashboard` defines a `sessionGuard` contract: `{ authenticate(request) -> session | null, handlers: { "/auth/login", "/auth/callback", "/auth/logout" } }`. The dashboard mounts `handlers` and gates every `/api/*` route behind `authenticate`.
- `haechi-auth-oidc`'s `createOidcSessionBroker(...)` returns an object satisfying that contract.
- Wiring is explicit: `createDashboardServer({ ..., sessionGuard: createOidcSessionBroker({ ... }) })`. The dashboard has **no peer dependency on auth-oidc** (the guard is injected, like `cryptoProvider`); either satellite is usable independently. The required pairing is the **fail-closed rule**: remote bind ⇒ a guard must be present (§2.1).
- **Gate precision:** an unauthenticated `/api/*` request on a guarded dashboard returns **`401` (never a `302`** — a redirected XHR/fetch leaks the login URL or loops; the static shell performs the redirect). **Exactly** the three literal handler paths are exempt from the gate via **exact match (not a `/auth/` prefix)** — any other path (incl. unknown `/auth/*`) is gated or `404`, so a future broker route can't become an unauthenticated bypass. `/healthz` is reachable without a session even off-loopback (liveness only).

### 2.4 `haechi-crypto-kms` Vault / GCP / Azure backends (independent `0.2.0`)

A parallel, decoupled track: additive backends shipped as **`haechi-crypto-kms@0.2.0`** (additive minor — new subpath exports, no change to AWS or the in-memory client), **not gated on core 0.9.0**. Each implements the **same `kms` interface** (`keyId`/`wrap(Buffer)->string`/`unwrap(string)->Buffer`/`deriveHmacKey`) the AWS client established in 0.8, with the same **optional-peer + lazy-import + injected-client** model and the same **faithful-mock conformance** bar (cross-key rejection, corrupted-blob rejection, HMAC determinism/domain-separation — no SDK, no network in CI).

- **`./gcp`** — Google Cloud KMS, optional peer `@google-cloud/kms` (lazy). `wrap` = `encrypt` of a CSPRNG 32-byte data key; `unwrap` = `decrypt`; `deriveHmacKey(domain)` = HKDF-SHA256 over one decrypted 32-byte root (`hmacRootCiphertext`, cached), domain-separated — identical shape to `aws.mjs`.
- **`./azure`** — Azure Key Vault, optional peers `@azure/keyvault-keys` + `@azure/identity` (lazy). Native `wrapKey`/`unwrapKey` to envelope the data key; `deriveHmacKey` = HKDF over an unwrapped root.
- **`./vault`** — HashiCorp Vault Transit, **zero optional-peer** (the Transit engine is a plain HTTP API reachable with `node:` `fetch` — the dependency-lightest backend). Precise wire shapes (load-bearing): `wrap` = `POST {addr}/v1/transit/encrypt/{key}` with `plaintext = base64(dataKey)`, return `data.ciphertext` (`vault:v1:…`); `unwrap` = `POST .../decrypt/{key}` then **`Buffer.from(data.plaintext, "base64")`** (the base64 decode back to the 32-byte Buffer is mandatory or the HKDF root is garbage); require a **non-derived** transit key (or a fixed `context`) so determinism holds; `hmacRootCiphertext` is a transit-encrypted 32-byte root decrypted once and cached, identical to `aws.mjs` `hmacRoot()`. The Vault `fetch` egress runs the **same `lookup`→`isBlockedAddress` guard + `redirect:"error"` + bounded body + timeout** as the auth egress (an operator-supplied `VAULT_ADDR` can rebind to metadata in cloud) — reusing the shared SSRF helper (§2.2), not a third copy.

All backends **map provider errors to a generic fail-closed error** and **never write KMS/provider error detail** (which can echo key ARNs/paths) to audit. Each lands behind its own subpath export + `files` entry, with `peerDependenciesMeta.optional` for the SDK-backed ones; the **`haechi` tarball stays zero-dep** (the 0.8 packaging gate is unaffected). **Reconcile the hard-coded provider `version` field** (`satellites/crypto-kms/index.mjs` returns `version: "0.1.0"`, already stale vs package `0.1.1`) — remove/derive it so `0.2.0` doesn't misreport. The `0.2.0` release reuses the `crypto-kms-v<semver>` tag + Trusted Publisher bootstrapped in 0.8.

## 3. Explicit non-scope (deferred to 0.9.x / 1.0)

- **Dashboard write actions** (reveal, purge, policy edits) — read-only only; mutation stays in the CLI under reveal governance. No `POST`/`DELETE` surface exists.
- **Dashboard token-vault / policy visualization** — audit-only in 0.9.
- **Framework SPA / build step** — vanilla zero-dep only.
- **Multi-origin / CDN-fronted IdP** (issuer host ≠ JWKS/endpoint host) — single-origin only, same as `haechi-auth-jwt` 0.8.
- **Refresh-token rotation / silent renewal / long-lived sessions** — 0.9 sessions are absolute-TTL + idle-timeout only; `offline_access` is stripped; the access token is discarded.
- **`at_hash`/`c_hash` validation** — out of scope precisely because the broker never uses the access token.
- **Non-OIDC interactive auth** (SAML, LDAP).
- **Dynamic loading of satellites** — banned until the 1.0 plugin sandbox; the dashboard and broker are wired by **explicit injection**, never a dynamic `import()` of a configured package name.

## 4. Backward compatibility

Core behavior is **unchanged** — zero-dep posture intact, existing config/APIs untouched. The two touches to existing packages are both **additive, behavior-preserving**: (a) `haechi-auth-jwt@0.2.0` exports a verifier primitive and reimplements `createJwtAuthProvider` on it (all 0.8 tests stay green); (b) `packages/audit` adds members to `FORBIDDEN_KEYS` (broker token/claim keys) — no change to existing event shapes. `assertSafeProxyBind` is **reused from `haechi/proxy` as already exported** (no relocation, no new core export). All 0.9 deliverables are new, additive, opt-in satellites.

## 5. 1.0 relationship

0.9 does not itself close a 1.0 blocker but advances two 1.0 stories: **operational observability** (the dashboard makes the [[audit-integrity]] hash-chain status + decision stream inspectable, supporting the real-environment-validation exit criterion) and **interactive auth** (the broker completes the human-login half `haechi-auth-jwt` left open). The remaining 1.0 gates are unchanged: API-stability freeze and the plugin sandbox + dynamic-loading story.

## 6. Threat-model & risk-register deltas (concrete, not "TBD")

The release cut updates `threat-model.md` (+ `.ko`) §3 Threats-and-Controls with these rows, and adds risk-register IDs (the register's target-version header bumps `0.7.0 → 0.9.0` with a new gate row):

| New threat / surface | Control | Residual |
|---|---|---|
| Dashboard audit-viewer **XSS** via attacker-controlled `detections[].path` | CSP (`require-trusted-types-for`) + `textContent`-only rendering | none material |
| **Audit field leak** via the viewer (future field) | recursive key-by-key allowlist projection (+ `FORBIDDEN_KEYS`) | new nested field defaults to dropped |
| **DNS-rebinding** read of audit JSON from a localhost-bound viewer | Host-header allowlist (per-request) + CORP/COOP same-origin | none material |
| Unauthenticated audit read on **remote** bind | fail-closed: remote ⇒ `sessionGuard` **and** TLS required | operator must terminate TLS |
| OIDC **login CSRF / authorization-code injection / open-redirect / session fixation** | state↔pre-auth-cookie binding, atomic `take()`, PKCE S256, fresh session id at callback, `returnToAllowlist`, CSRF token on logout | none material for single-IdP |
| OIDC **mix-up** (wrong IdP / wrong RP) | issuer/endpoint pinned to the pending record, RFC 9207 `iss` check, ID-token `aud`/`azp` profile, `metadata.issuer` == config | multi-origin IdP out of scope |
| Broker **SSRF to cloud metadata** via the token-endpoint POST (and Vault `fetch`) | per-egress post-DNS `isBlockedAddress` re-check + bounded body + timeout + `redirect:"error"` | operator-trusted endpoints only |
| **Token/secret leak** into audit/logs | broker allowlist projection + extended `FORBIDDEN_KEYS`; access token discarded | none material |
| KMS backend egress (Vault HTTP, GCP/Azure SDK) | optional-peer + injected-client conformance, generic fail-closed errors, no provider detail in audit | live-backend validation is out-of-CI |

Proposed risk IDs: **P1-SEC-009** (broker session/login security), **P1-OPS-005** (dashboard audit exposure / rebinding / remote bind), **P2-CRYPTO-00x** (KMS backend egress). New §4 exclusions: multi-origin IdP, refresh rotation, dashboard write actions, `at_hash` validation.

## 7. Test criteria (mapped to the PR breakdown)

### 7.1 PR1 — `haechi-auth-jwt@0.2.0` verifier extraction (additive, behavior-preserving)

- **Bump `satellites/auth-jwt/package.json` `0.1.1 → 0.2.0`** (the publish workflow's tag==package-version gate requires it).
- The new `createJwtVerifier`/`verifyJwt` primitive passes the full 0.8 §6.3 security-gate suite (every deny case); **`nonce` is not part of the primitive** (a no-op `expectedNonce` when omitted).
- `createJwtAuthProvider` reimplemented on the primitive passes its existing 0.8 tests **unchanged** (behavior-preserving regression guard); it still owns Bearer-header parsing.
- Satellite tarball stays `dependencies: {}`; core tarball stays zero-dep.

### 7.2 PR2 — `haechi-dashboard` (zero-dep read-only viewer)

- Binds loopback by default; non-loopback without `allowRemoteBind` → refused (rethrown dashboard-worded message); `allowRemoteBind:true` without `sessionGuard` → throws; remote without confirmed TLS/trusted-proxy → throws. `normalizeDashboardConfig` rejects each invalid option with a stable error.
- **Anti-rebinding:** `Host: evil.example` to a loopback dashboard → `403`; the Host matrix (`localhost.`, `127.0.0.1:PORT`, `::ffff:127.0.0.1`, an unexpected FQDN, duplicate `Host`) behaves correctly; no `Access-Control-Allow-Origin` is ever emitted.
- `GET /api/events`: capped `limit` (reject `-1`/`abc`/`1e9`), opaque `cursor` (malformed → `400`), **recursive allowlist** drops a synthetic extra field injected at **each** level (top, `detections[]`, `identity`, `summary`, `auditIntegrity`); a window-exceeded page returns the marker not an error; a torn trailing line doesn't `500`.
- `GET /api/chain`: shape matches the **real** `verifyAuditChain` output; a truncated-with-anchor fixture surfaces `valid:false` + a derived `truncationDetected` **without** leaking the raw `reason`/`eventHash`; concurrent polls trigger **one** walk (mtime+size cache); an oversized fixture → `413`; `HEAD` forces no walk.
- **XSS:** an event whose `detections[].path` contains `<script>`/`<img onerror>` renders inert (served JS uses `textContent`); the exact CSP header string (incl. `object-src 'none'`, `require-trusted-types-for 'script'`) + `nosniff` + `XFO:DENY` + `CORP/COOP same-origin` + `no-store` are asserted.
- **Method/asset/errors:** `POST`/`DELETE` → `405`; `/../../etc/passwd` cannot escape the fixed asset map (`404`, no fs read); a forced fs error yields `{error:"internal"}` with **no** path substring/stack; `/healthz` leaks nothing.
- **DoS:** a multi-MB audit fixture is served via a bounded tail window; `/api/*` is rate-limited.
- Tarball `dependencies: {}`; publishes with provenance.

### 7.3 PR3 — `haechi-auth-oidc` (interactive broker, security gates)

- **Happy path** (stubbed discovery + token endpoint + JWKS, RS256 ID token): `/auth/login` → `302` with `state`+`nonce`+`code_challenge` (S256) + the registered `redirect_uri`; `/auth/callback` with matching state + valid code exchanges, verifies, mints a **fresh** session id unrelated to any pre-login cookie; cookies are `__Host-`-named, `HttpOnly`, `SameSite=Lax`, `Secure` under a non-loopback config; the pre-auth cookie is cleared.
- **Each denied** (no session, generic identical response, nothing echoed, no outbound request for a state failure): mismatched/replayed/expired `state` (atomic `take()` so a concurrent replay finds no record); missing/mismatched pre-auth cookie (login-CSRF/code-injection); `nonce` mismatch; `alg:none`/alg-confusion; expired/`nbf`/wrong-`aud`/wrong-`iss` ID token; **multi-`aud` without `azp`**, **`azp !== clientId`**; `metadata.issuer` ≠ config; RFC 9207 `iss` ≠ pinned; a code-exchange failure; a discovery doc with a **cross-origin** `token_endpoint`/`jwks_uri`; a discovery/JWKS/**token_endpoint** host resolving to a private/metadata range **at request time** (post-DNS); an oversized token-endpoint response.
- **No token leakage:** post-login, the browser-visible cookie is the opaque id only; `JSON.stringify` of every client-bound response **and** the audit log contain **no** ID/access/refresh token, `client_secret`, `code`, `state`, `nonce`, or raw `sub`. The access token is **discarded** (asserted not stored).
- **Sessions/logout:** after `POST /auth/logout`, replaying the old cookie → `401` and the server-side record is gone; logout requires the CSRF token (a forged cross-site POST is rejected); `post_logout_redirect_uri` off-allowlist is refused.
- **Open-redirect:** `return_to=https://evil.example` (or any off-origin/absolute) → falls back to `/`; an allowlisted relative path is honored.
- **Rate/DoS:** N rapid `/auth/login` hit the pending cap and return a generic `429`/`503` without exhausting memory; `/auth/login` + `/auth/callback` are rate-limited.
- **Audit:** `oidc.login.{start,success,failure}` / `oidc.logout` / `oidc.session.evict` are emitted with only `*Hash`/`reasonCode`/`provider`/timestamp; the extended `FORBIDDEN_KEYS` test passes.
- **Construction fail-closed:** missing `cryptoProvider.hmac`; non-https/cross-origin `issuer`/`redirectUri`; `redirectUri` path ≠ `/auth/callback`; off-loopback without TLS/Secure; `normalizeOidcConfig` rejects each bad option.
- **Seam:** the broker satisfies the dashboard `sessionGuard`; mounted, an unauthenticated `/api/events` on a remote-bound dashboard → **`401`** (not `302`); `/auth/anything-else` is not an unauthenticated bypass; `/healthz` is `200` unauthenticated off-loopback while `/api/events` is `401`.

### 7.4 PR4 — `haechi-crypto-kms@0.2.0` (GCP / Azure / Vault backends)

- Each of GCP/Azure/Vault passes `assertCryptoProviderConformance` via a **faithful injected mock** (no SDK, no network), incl. cross-key + corrupted-blob **rejection** and HMAC determinism/domain-separation; end-to-end through `createRuntime` (encrypt + tokenization round-trip).
- The **Vault** backend uses **`node:` `fetch` only** (no optional peer), exercises the **base64 round-trip** (encrypt `plaintext=base64(dataKey)` → decrypt → `Buffer.from(...,"base64")`), a non-derived key, and the SSRF guard on `VAULT_ADDR`; GCP/Azure declare SDKs under `peerDependenciesMeta.optional`, lazily imported only when no client is injected.
- Provider errors map to a generic fail-closed error; no provider/key-ARN detail reaches audit.
- The hard-coded provider `version` field is reconciled (no longer `"0.1.0"`).
- Published `haechi-crypto-kms@0.2.0` tarball `dependencies: {}`; core tarball stays zero-dep; publishes on the existing `crypto-kms-v<semver>` tag with provenance.

### 7.5 All satellites

- Each new/updated satellite publishes with provenance + sigstore attestation, verified post-release like 0.7/0.8.

## 8. Suggested PR breakdown (stacked)

1. **`haechi-auth-jwt@0.2.0` verifier extraction** — additive `createJwtVerifier`/`verifyJwt` (nonce kept outside), reimplement `createJwtAuthProvider`, **bump to 0.2.0**, all 0.8 tests green. → §7.1
2. **`haechi-dashboard`** — zero-dep `node:http` viewer: `normalizeDashboardConfig` + bind/guard/TLS precedence, anti-rebinding Host allowlist, read-only event/chain/summary API with strict query parsing + bounded reads + recursive allowlist + mtime-cached chain, static page with strict CSP/Trusted Types + `textContent`, security headers, generic errors, rate limit, the `sessionGuard` seam, publish workflow `dashboard-publish.yml` (guard `startsWith(tag,'dashboard-v')`, regex `^dashboard-v[0-9]+\.[0-9]+\.[0-9]+$`). Regenerate the lockfile for the new dir. → §7.2
3. **`haechi-auth-oidc`** — interactive authorization-code + PKCE broker: `normalizeOidcConfig`, SSRF-hardened discovery + per-egress guard, ID-token profile via the §2.2 shared verifier (nonce outside), atomic `take()` pending store, hardened two-cookie sessions + fresh-id rotation, open-redirect/CSRF/logout defenses, broker audit events + extended `FORBIDDEN_KEYS`, the `sessionGuard` implementation, publish workflow `auth-oidc-publish.yml`. Regenerate the lockfile for the new dir. → §7.3
4. **`haechi-crypto-kms@0.2.0`** — GCP/Azure (optional-peer) + Vault (zero-dep, shared SSRF helper) backends, faithful-mock conformance, version-field reconcile; bump + publish on the existing tag. → §7.4
5. **0.9.0 release cut** — docs EN/KO (dashboard/broker config in `configuration.md`, the §6 threat-model + risk-register deltas with concrete IDs + target-version bump, this scope doc), roadmap row, api-stability, wiki ingest (new `haechi-dashboard`/`haechi-auth-oidc` pages + `packaging-and-distribution`/`identity-and-auth` updates), and the per-package Trusted Publisher runbook rows (both new workflow filenames + tag globs + the configure-TP-**before**-first-tag bootstrap that claims each unscoped name).
