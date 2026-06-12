# Haechi Risk Register and Release Gates

- Status: Living document (tracks core 1.2.x)
- Date: 2026-06-11
- Target version: 1.2.x
- Branch: `main`

## 1. Current Assessment

Haechi has shipped its `1.x` stable line. The developer-preview gate (G2, `haechi@0.3.2`) and every gate through G6 (1.1.0 plugin capability enforcement) are passed; the gate history below is retained as the audit trail. 1.0.0 declared the frozen API contract under strict semver (with a documented deprecation policy and `tests/api-contract.test.mjs` as the freeze guard) and narrowly lifted the dynamic-loading ban for a signed, sandboxed `authProvider` plugin; 1.1.0 added the opt-in `process-isolated` plugin runtime with kernel-enforced capability denial. The previously distribution-blocking conditions for the stable label — 1.0 API stability, the external `cryptoProvider`/KMS reference adapter (`haechi-crypto-kms`), and stream-aware enforcement (`streaming.requestMode: "inspect"`) — are all in place. Haechi remains a self-hosted security toolkit, not a compliance guarantee, and production deployments still own network access control, upstream authentication, and key custody (see §5 of the threat model).

| Category | Judgment | Rationale |
|---|---|---|
| GitHub public | Allowed | Security limitations, threat model, and shared responsibility are documented |
| GitHub release/tag | Allowed | Stable `1.x` line; release notes track each gate (G0–G6) |
| npm stable | Allowed | The 1.0 stable label conditions — frozen API contract, external KMS reference adapter, and stream-aware enforcement — are met; core publishes with provenance |
| Production use | Operator-gated | Supported as a self-hosted gateway when the operator supplies network access control, authentication/authorization, and production key custody; Haechi is not a compliance guarantee |

## 2. Release Gates

| Gate | Target | Criteria | Current Status |
|---|---|---|---|
| G0 | GitHub source publication | Tests pass, security limitations documented, no plaintext audit leak | Pass |
| G1 | GitHub pre-release | P0 code risks resolved, no production-ready language | Pass |
| G2 | npm developer preview | P0 resolved, preflight/SBOM/provenance paths ready, npm auth confirmed | Pass (`haechi@0.3.2` published 2026-06-10) |
| G3 | npm stable | P1 production reference, stream-aware enforcement, API stability hardened | Pass (achieved at the 1.0.0 stable cut — streaming inspection shipped in 0.5, the API freeze in 1.0.0; see G5. Superseded by G5–G7.) |
| G4 | 0.9.0 observability + interactive-auth satellite cut | P1-SEC-026 / P1-OPS-009 mitigated and P2-CRYPTO-001 accepted; `haechi-dashboard` + `haechi-auth-oidc` + `haechi-crypto-kms@0.2.0` tests green; satellite tarballs zero-dep; core bumped to 0.9.0 (only an additive FORBIDDEN_KEYS audit hardening) | Pass |
| G5 | 1.0.0 stable API contract + signed-plugin sandbox | P1-SEC-024 / P1-SEC-025 mitigated, P2-API-001 / P2-OPS-006 resolved; the API freeze + deprecation policy + `tests/api-contract.test.mjs` green; the Ed25519 signed-plugin contract + `assertAuthProviderConformance` + the worker-isolated `authProvider` sandbox tests green; PR0 satellite peer-ranges widened to `>=0.8.0 <2.0.0` and the `check-satellite-peer-ranges.mjs` preflight gate green; core stays zero runtime dependency; core bumped to 1.0.0 | Pass |
| G6 | 1.1.0 plugin capability enforcement (`process-isolated`) | P1-SEC-027 / P1-SEC-028 mitigated; the `process-isolated` runtime (child under `--permission`, zero grants, `data:`-URL load, stdio-ignored, JSON-string IPC) + the fail-closed `--allow-net` feature detection (`netEnforcement:"require-permission"`) + the core `haechi/ssrf` guard + host-mediated key material + the spawn-storm circuit breaker; the fs/net/stdio red-team + SSRF + config tests green (the behavioral suite runs on a `--allow-net` Node and skips fail-closed otherwise); the API freeze stays green (additive `./ssrf` export + additive config keys); core stays zero runtime dependency; core bumped to 1.1.0 (additive + opt-in minor) | Pass |
| G7 | 1.2.0 Reliability Hardening Track (WS1–WS6) | Detection quality measured + tightened (WS2: a labeled-corpus precision/recall `bench:detection` gate, credential + international-PII coverage, `filters.minConfidence` / `filters.allowlist` with the hard-block-types invariant, NFKC unicode-evasion folding with offset-integrity); WS3 injectable `rateLimiter` seam + bounded fixed-window map; WS4 operability (`/__haechi/live`+`/ready` split, injectable `/metrics`, structured logs + per-request `correlationId`, graceful drain, max-in-flight backpressure, env overlay, hardened Dockerfile/compose/runbook, `configVersion`); WS6 proxy TLS / remote-bind hardening (`proxy.tls` / `proxy.trustForwardedProto`, fail-closed `assertSafeProxyTransport`) + OWASP-LLM/NIST control-mapping whitepaper + RFC 9116 `security.txt` + vulnerability-disclosure path. Every change is additive behind 1.1-preserving defaults (`tests/api-contract.test.mjs` green); the no-plaintext-in-audit invariant extends to telemetry; core stays zero runtime dependency; core bumped to 1.2.0 (additive minor) | Pass |

## 3. P0 Distribution-Blocking Risk Status

| ID | Risk | Status | Resolution evidence |
|---|---|---|---|
| P0-REL-001 | npm authentication/authorization unresolved | Resolved | `haechi@0.3.2` published via local passkey authentication on 2026-06-10; npm authentication and package ownership confirmed |
| P0-REL-002 | Proxy exposed to external network | Resolved | Non-loopback bind fails by default; `--allow-remote-bind` must be specified explicitly |
| P0-REL-003 | Streaming request handling unclear | Resolved | `stream: true` defaults to 501 fail-closed; `streaming.requestMode: "pass-through"` must be set explicitly |
| P0-REL-004 | `responseProtection` failure mode unclear | Resolved | Non-JSON, invalid JSON, compressed, and oversized responses are fail-closed; explicit allow policies are separated |
| P0-REL-005 | Local dev key misunderstood as production key | Resolved | `init`, README, and SECURITY warn that the dev-only key is not a production key provider |
| P0-REL-006 | npm package trust overstated | Resolved | package description, README, and SECURITY updated to reflect experimental developer preview status |

## 4. P1 Security Design Risk Status

| ID | Risk | Status | Resolution evidence |
|---|---|---|---|
| P1-SEC-001 | KMS/HSM/Vault not supported | Resolved for OSS core | `createRuntime(config, { cryptoProvider })` external crypto provider injection; fails closed if no external provider is supplied |
| P1-SEC-002 | TokenVault permission model insufficient | Resolved | `revealPolicy: "disabled"` is the default; `--allow-dev-reveal`, metadata export, retention/purge timestamps added |
| P1-SEC-003 | Audit integrity insufficient | Resolved | JSONL audit SHA-256 hash chain and `verifyAuditChain` |
| P1-SEC-004 | No plugin runtime | Resolved by gating (superseded by P1-SEC-024) | Dynamic runtime is rejected; only `manifest-only` plugins pass. **Superseded in 1.0 by P1-SEC-024 (§5.4):** 1.0 deliberately lifts the manifest-only-only stance, enabling dynamic loading **narrowly** for a signed, capability-gated, worker-isolated, audited `authProvider` plugin under the new trust controls |
| P1-SEC-005 | Policy conflict handling insufficient | Resolved | Downgrading a stronger action (e.g., preset block) to a weaker one fails closed on conflict |
| P1-SEC-006 | Regex-based filter accuracy limited | Resolved for preview | KR RRN checksum, Luhn, and unsafe custom regex restrictions added. ML/classifier plugin is in the stable backlog |
| P1-SEC-007 | AAD/replay/stream extension insufficient | Resolved for preview | AAD hash mismatch is explicit; streaming is blocked by default. Stream sequence/replay cache required when stream support is introduced |
| P1-SEC-008 | MCP security contract incomplete | Resolved for preview | JSON-RPC 2.0 required, method allowlist, params/result protection toggles. OAuth resource binding is the responsibility of the external MCP layer |

## 5. P1 Operational/Deployment Risk Status

| ID | Risk | Status | Resolution evidence |
|---|---|---|---|
| P1-OPS-001 | No CI | Resolved | `.github/workflows/ci.yml` |
| P1-OPS-002 | No SBOM/provenance | Resolved | `npm run sbom`, `.github/workflows/npm-publish.yml`, `publishConfig.provenance` |
| P1-OPS-003 | No real vLLM/Ollama/llama.cpp integration tests | Resolved for preview | Env-gated optional local inference integration tests added. CI skips when no external model server is present |
| P1-OPS-004 | Performance/large payload not measured | Resolved for preview | Request/response byte limits, `npm run bench:payload` |
| P1-OPS-005 | npm ownership unconfirmed | Resolved | `npm view haechi version` returns `0.3.2`; ownership confirmed by the first successful publish |

## 5.1 Additional Security Review Risk Resolution Status

| ID | Risk | Status | Resolution evidence |
|---|---|---|---|
| P1-SEC-009 | Proxy absolute-form request target could bypass upstream or enable SSRF | Resolved | Absolute/protocol-relative request targets are rejected as `haechi_invalid_proxy_target`; upstream URL combines only path and search with the fixed upstream |
| P1-SEC-010 | `responseProtection.maxBytes` checked after full buffering, enabling memory DoS | Resolved | Upstream body is read via stream reader with a byte cap; excess immediately triggers cancel/fail-closed. `failureMode: "allow"` cannot bypass the hard byte cap |
| P1-SEC-011 | Concurrent writes to audit hash chain could cause sequence/previousHash collision | Resolved | JSONL audit sink serializes hash-chain record building and append via per-sink write queue and lock file |
| P1-SEC-012 | PII/secrets in JSON object keys could be exposed in audit paths or token metadata | Resolved | Detection `pathText` records `key_<hash>` structured paths instead of raw key names |
| P1-SEC-013 | Concurrent tokenization/purge in local TokenVault could cause lost updates | Resolved | Vault mutation queue, lock file, and atomic write via temp-file-then-rename applied |
| P1-SEC-014 | No audit record for `streaming.requestMode: "pass-through"` and `responseProtection.failureMode: "allow"` bypass decisions | Resolved | Decision audit records `streaming_request_pass_through` and `response_unprotected_allowed/blocked` without raw payload |
| P1-SEC-015 | MCP `allowedMethods` element type validation insufficient | Resolved | Config validation strengthened to allow only non-empty strings |
| P1-OPS-006 | GitHub Actions major-tag pinning could allow supply-chain drift | Resolved | `checkout`, `setup-node`, and `upload-artifact` pinned to verified commit SHAs |

## 5.2 Second Full Code Review Risk Resolution Status (0.3.2)

| ID | Risk | Status | Resolution evidence |
|---|---|---|---|
| P0-SEC-016 | Ollama `/api/chat` and `/api/generate` default to streaming when `stream` is omitted, allowing streaming block bypass | Resolved | `streamingDefault` introduced in protocol adapter; requests without explicit `stream: false` are treated as streaming and default to 501 fail-closed |
| P1-SEC-017 | Token reveal/purge not recorded in audit | Resolved | `auditSink` injected into local TokenVault; `reveal_allowed/denied/failed`, `purge`, and `purge_expired` decision audits recorded (no plaintext) |
| P1-SEC-018 | Privacy profile could silently weaken user-specified policies | Resolved | `applyPrivacyProfile` compares ACTION_STRENGTH and only allows strengthening |
| P1-SEC-019 | Decrypt ignores envelope `kid`; `init --force` destroys existing keys, permanently losing vault/ciphertext | Resolved | Key selection based on `kid`; `--force` now performs rotation that preserves existing keys as `retired` |
| P1-SEC-020 | Policy bundle signing reuses the AES encryption key as an HMAC key, violating key separation | Resolved | Domain-separated signing key derived with `haechi:policy-bundle:signing:v1` |
| P1-SEC-021 | `retentionDays` only blocks reveal but does not delete expired data | Resolved | Expired tokens are automatically pruned on vault mutation; `purgeExpired()` and `haechi token-purge --expired` added |
| P1-SEC-022 | No upstream fetch timeout, enabling connection exhaustion | Resolved | `limits.upstreamTimeoutMs` (default 120000) and `504 haechi_upstream_timeout` |
| P1-SEC-023 | JSON numbers (card numbers) and PII/secrets in object keys not detected or transformed | Resolved | Number leaves and object keys included in detection/transform scope (keys are renamed on enforce) |
| P1-OPS-007 | Stale lock file causes permanent audit/vault write failure | Resolved | Stale locks older than 30 seconds are automatically stolen and reacquired |
| P1-OPS-008 | Audit append re-reads the entire file on every write (O(n²)) | Resolved | File tail-chunk read for O(1) append |
| P2-SEC-024 | Unknown `target.type` silently falls back to openai-compatible | Resolved | Unknown type fails closed at config validation |
| P2-SEC-025 | Short-value masking exposes most of the value (4 of 5 characters) | Resolved | Values of 8 characters or fewer are fully masked |
| P2-SEC-026 | Assignment-secret redaction removes the key name as well | Resolved | Lookbehind pattern replaces only the secret value |
| P2-SEC-027 | MCP notifications receive error responses in violation of the JSON-RPC spec; batch handling unspecified | Resolved | Notifications are dropped; batch is explicitly rejected fail-closed |
| P2-SEC-028 | Proxy internal error messages exposed to clients | Resolved | Unexpected errors return a generic message; details go to stderr |
| P2-DOC-005 | Default dry-run + responseProtection off could be mistaken for "protection active" | Resolved | Proxy startup and `protect` output explicitly warn when enforcement is inactive |

Base64/encoded-value decode inspection, query-string inspection, and audit tail truncation detection are explicitly excluded and documented in the threat model (0.4+ backlog).

## 5.3 0.9.0 Observability + Interactive-Auth Risk Status

These IDs are scoped to the 0.9.0 satellite cut (`haechi-dashboard`, `haechi-auth-oidc`, `haechi-crypto-kms@0.2.0`); they are namespaced by the 0.9.0 section and are distinct from the like-numbered P0/P1 rows above. Evidence is the satellite source, its test suite, and the adversarial security review captured in `docs/current/release-0.9-implementation-scope.md` §6.

| ID | Risk | Status | Resolution evidence |
|---|---|---|---|
| P1-SEC-026 | OIDC broker session/login security: login CSRF, authorization-code injection, open-redirect, session fixation, and mix-up (wrong IdP/RP) in `haechi-auth-oidc` | Mitigated | `satellites/auth-oidc/index.mjs`: state-first `/auth/callback` (atomic `take()` of a pre-auth-cookie-bound pending record + constant-time `state` compare before any egress), PKCE S256, fresh session id minted at callback (no fixation), `returnToAllowlist` (no open-redirect), issuer/endpoint pinning + RFC 9207 `iss` check + ID-token `aud`/`azp` profile via the shared `createJwtVerifier` (mix-up), CSRF-gated non-GET logout. `satellites/auth-oidc/auth-oidc.test.mjs` exercises each deny case; adversarial review in scope §6. **Residual:** multi-origin IdP out of scope |
| P1-OPS-009 | Dashboard audit exposure: stored XSS via `detections[].path`, future-field audit leak, DNS-rebinding read of a localhost viewer, and unauthenticated read on remote bind in `haechi-dashboard` | Mitigated | `satellites/dashboard/index.mjs` + `assets.mjs`: strict CSP (`require-trusted-types-for 'script'`) + `textContent`-only rendering (XSS), recursive key-by-key allowlist projection over `FORBIDDEN_KEYS` (field leak), per-request anti-rebinding `Host` allowlist + CORP/COOP same-origin (rebinding), fail-closed remote bind requiring `sessionGuard` **and** TLS termination (unauthenticated remote read). `satellites/dashboard/dashboard.test.mjs`; adversarial review in scope §6. **Residual:** operator must terminate TLS for remote bind |
| P2-CRYPTO-001 | KMS backend egress: the `haechi-crypto-kms@0.2.0` Vault/GCP/Azure backends could leak key material or provider/key-path detail or reach an unintended (metadata) endpoint | Accepted | `satellites/crypto-kms/{vault,gcp,azure}.mjs`: optional-peer + injected-client model with faithful-mock `assertCryptoProviderConformance` (cross-key + corrupted-blob rejection, HMAC determinism/domain-separation), satellite-local `isBlockedAddress` SSRF guard on the Vault `fetch` (kept honest by the dev-only `satellites/crypto-kms/ssrf-parity.test.mjs` vs auth-jwt), generic fail-closed provider-error mapping (no provider/key-ARN in audit). `{vault,gcp,azure}.test.mjs` + `crypto-kms.test.mjs`; adversarial review in scope §6. **Residual accepted:** live-backend (real Vault/GCP/Azure) validation is out of CI; the published tarball stays zero runtime dependency |

## 5.4 1.0.0 Stable API Contract + Signed-Plugin Sandbox Risk Status

These IDs are scoped to the 1.0.0 stable cut (the API freeze + the Ed25519 signed, worker-isolated `authProvider` plugin sandbox). The authoritative threat rows and scope are `docs/current/release-1.0-implementation-scope.md` §6; evidence is the PRs (#46–#49), the core source, and the test suites.

| ID | Risk | Status | Resolution evidence |
|---|---|---|---|
| P1-SEC-024 | Dynamic plugin execution / sandbox trust model: a signed `authProvider` plugin loaded into the worker sandbox could abuse the host (`fs`/`net`/`process.env`) or exfiltrate the credential it receives. **Supersedes P1-SEC-004's manifest-only stance** — 1.0 deliberately lifts it, enabling dynamic loading narrowly under new controls | Mitigated | `packages/plugin/sandbox.mjs` `createSandboxedAuthProvider` (PR #49): `node:worker_threads` memory/crash isolation, in-memory verified spawn (no path re-resolution / TOCTOU), data-minimized JSON-string wire (only the credential slice crosses; the host builds the keyed-HMAC identity), null-proto claims sanitizer, single-occupancy + correlation-id concurrency, required `timeoutMs` terminate + `resourceLimits`/`maxPendingCalls`/`maxMessageBytes`, kill-switch (`plugins.enabled:false`), and the full gate re-run on every respawn. Lifecycle audit (`plugin.load.*`/`authenticate.deny`/`worker.terminated`) + extended `FORBIDDEN_KEYS`; the audit identity is projected to the frozen 5 keys `{id,type,subjectHash,issuerHash,provider}`. Tests: the §7.4 fail-closed + isolation matrix, the `auth.provider:"plugin"` `normalizeConfig` fail-closed tests, and the `createRuntime` + proxy auth end-to-end. **Residual:** `node:worker_threads` is memory/crash isolation + data-minimization, NOT a capability sandbox — a malicious signed plugin's `fs`/`net`/`process.env` is not blocked and it CAN exfiltrate the credential it receives; gated only by the signing/vetting trust model. True enforcement (child-process + Node permission model) is **delivered in 1.1 for the opt-in `process-isolated` runtime** (P1-SEC-027, §5.5) on a `--allow-net` Node; the `worker_threads` (1.0) mode is unchanged and keeps this residual |
| P1-SEC-025 | Plugin signing / trust-anchor / revocation lifecycle: signer-key confusion/downgrade/rollback, a swapped (TOCTOU) entry, or a revoked/expired signer loading code | Mitigated | `packages/plugin/signing.mjs` `verifySignedPlugin` (PR #48): Ed25519 (asymmetric, `node:crypto`) signature over `canonicalize({pluginId, kind, version, capabilities, coreVersionRange, entrySha256, notBefore, notAfter})` — binding `entrySha256` (anti-swap), **trust-anchor-only** key resolution (refuse before verify if `signerKeyId` ∉ allowlist; algorithm pinned to Ed25519; signer set is separate from the AES rotation key file), pin + per-`pluginId` version-floor (anti-rollback/malicious-update) + `revokedSignerKeyIds`/`revokedEntrySha256` denylists + `notBefore`/`notAfter` window, all fail-closed at load and re-verified on every respawn. `assertAuthProviderConformance` (`haechi/auth`, the auth analog of `assertCryptoProviderConformance`) is a correctness gate with per-load randomized vectors; the host re-validates PII-safety per call. Tests: the §7.3 per-reason refusal matrix (each emits `plugin.load.refused{reason}`), the conformance negative tests, and the `FORBIDDEN_KEYS`-extension `sanitizeAudit` test. **Residual:** the operator must curate trust anchors/pins; a live revocation feed / CRL is 1.x (revocation takes effect at next load; the kill-switch force-drops a live plugin) |
| P2-API-001 (1.0) | Stable-contract freeze + deprecation policy: an unstable public API / audit-schema drift that breaks consumers without a major bump or a migration path | Resolved | `docs/current/api-stability.md`(+ko) (PR #47): the IN/OUT surface table, strict semver from 1.0, the deprecation policy (≥1-minor retention + `HAECHI_DEPRECATION_*` runtime-warning contract + the disclosed-vulnerability in-minor security exception), the frozen audit event schema including nested sub-schemas + an additive `schemaVersion`, and the config-schema freeze unit (key presence/shape frozen; safer defaults still allowed). `tests/api-contract.test.mjs` is the freeze guard: it pins the per-subpath exports + a full audit event (non-null `identity` + a `detections[]` entry) + the config key set + `schemaVersion`; an additive field passes, a removed/renamed field (top-level OR nested) fails, and `verifyAuditChain` still verifies a frozen-schema fixture with a synthetic additive field. **Residual:** a major bump can break by design (documented migration); the disclosed-vulnerability security exception permits a sanctioned in-minor break with an advisory + migration path |
| P2-OPS-006 (1.0) | Satellite peer-range / major-tracking gate: bumping core to 1.0.0 makes every satellite's `>=0.8.0 <1.0.0` peer unsatisfiable (ERESOLVE), breaking satellite installs | Resolved | PR0 (#46) widened all four satellites' `haechi` peer range to `>=0.8.0 <2.0.0` (versions auth-jwt 0.2.1, crypto-kms 0.2.1, dashboard 0.1.2, auth-oidc 0.1.2; auth-oidc's `haechi-auth-jwt` likewise to `<2.0.0`) and regenerated the lockfile (the workspace-lockfile gotcha). `scripts/check-satellite-peer-ranges.mjs` is a `release:preflight` gate that asserts `semver.satisfies(coreVersionToPublish, range)` for every satellite, simulating core `1.0.0`. `api-stability.md §5` documents that the satellite peer upper bound tracks the core MAJOR. **Residual:** the satellites must be republished before core 1.0.0 ships so they install against it |

## 5.5 1.1.0 Plugin Capability Enforcement Risk Status

| ID | Risk | Status | Resolution evidence |
|---|---|---|---|
| P1-SEC-027 | Plugin capability *enforcement*: the 1.0 `worker_threads` sandbox is memory/crash isolation only, so a malicious signed plugin can use `fs`/`net` and exfiltrate the credential. **Strengthens P1-SEC-024's accepted worker residual** — 1.1 adds real enforcement for a new opt-in runtime | Mitigated | `packages/plugin/process-sandbox.mjs` `createProcessIsolatedAuthProvider`/`…Sync` (PR #54): a signed `authProvider` runs in a child `node` under `--permission` with **zero grants** (no fs/child-process/worker/addons/wasi, no `--allow-net`), loaded from a `data:` URL (no fs grant → no TOCTOU/symlink surface), `stdio:['ignore','ignore','ignore','ipc']` (no stdout/stderr/fd leak channel), scrubbed env, JSON-string-only IPC + the shared null-proto sanitizer + host-side keyed-HMAC identity. **Empirically validated on Node 26**: the plugin's `fs`/`net`/`fetch`/`dns`/`child_process`/`worker` and the `process.binding('tcp_wrap')` bypass are all `ERR_ACCESS_DENIED`. Network containment is the **kernel `--allow-net` denial**, not a deletable JS harness; the default `netEnforcement:"require-permission"` **fails closed** (behavior-probed feature detection; PR #54) on a Node that cannot enforce it. A spawn-storm circuit breaker (PR #56) bounds respawns. Lifecycle audit gains host-computed/enum-only `isolation`/`grants`/`netEnforcement` (PR #56). Config: `auth.plugin.isolation:"process"` wired fail-closed (PR #56). Tests: the fs/net/stdio red-team (skipped on a Node without `--allow-net`, where the runtime fails closed instead) + the always-run fail-closed contract + the config matrix. **Residual:** a Node without `--allow-net` (fail-closed, not contained); a `networkEgress`-granted plugin; credential/key material in child memory (core-dump/swap); a V8/Node escape (a runtime control, not an OS sandbox) |
| P1-SEC-028 | Host-mediated key material + SSRF: a custom-credential plugin needing key material could be a plugin-driven SSRF vector, and core had no SSRF guard (the satellites' copies are unreachable from core) | Mitigated | A new node:-only, zero-dependency **`haechi/ssrf`** core module (PR #55): `isBlockedAddress` (private/loopback/link-local/metadata), `guardedFetch` (https-only, post-DNS re-check, `redirect:"error"`, bounded body + timeout), `createGuardedKeyFetcher` (TTL cache + cooldown). The `process-isolated` runtime's optional `keyMaterial:{url}` is fetched by the **host** from the **operator-declared** URL through this guard and injected over the IPC — the plugin never names a URL (no plugin-driven SSRF), and the kid-refetch cooldown bounds the outbound rate; a blocked-address URL fails closed. Tests: the canonical `isBlockedAddress` vector table + a core-vs-`auth-jwt` parity guard, `guardedFetch` SSRF refusal/bounding, the cooldown fail-closed, and the runtime key-injection + no-SSRF tests. **Residual:** the satellites keep their DELIBERATE local copies (a crypto/auth package must not runtime-depend on core-ssrf; `crypto-kms/ssrf-parity.test.mjs`) — the core re-import is deferred and the drift is guarded by parity, not eliminated; the guard's DNS-rebinding window (resolve-then-connect) is accepted for an operator-declared URL |

## 5.6 Reliability Hardening Track — Horizontal-scale & State Safety (WS3)

Additive, accumulating on `main` toward a later `1.2.0` minor; the seam + honest docs, never a built-in distributed store (track §3 non-goal).

| ID | Risk | Status | Resolution evidence |
|---|---|---|---|
| P1-OPS-010 | Proxy rate limiter is single-process and **not injectable**, and its fixed-window `Map` is **never pruned** — a one-shot identity's slot lingers forever, so a high-cardinality identity stream is unbounded memory growth keyed by identity; and a multi-replica deployment silently weakens the limit (per-process throughput multiplies by the replica count) with no replaceable seam | Mitigated | The rate limiter is now an **injectable collaborator** mirroring `cryptoProvider`/`auditSink`/`tokenVault`: `createRuntime(config, { rateLimiter })` (`packages/cli/runtime.mjs`) supplies it, `assertProvider("rateLimiter", …, ["allow"])` fails closed at construction if it lacks `allow()`, and it is exposed on the returned runtime object; the proxy consults `runtime.rateLimiter` (`packages/proxy/index.mjs`, with a backward-compatible local-default fallback for a hand-built runtime). The default per-process in-memory fixed-window limiter (the documented default; `allow(key, limit) -> boolean`, 429 semantics unchanged) is **self-bounding**: a lazy, amortized sweep evicts fully-expired window slots once the `Map` crosses a size threshold — **no background timer** (so `node --test` does not hang). A multi-replica operator injects a shared-store implementation (e.g. Redis) satisfying the same contract, or enforces the limit at a shared front door. Docs: `configuration.md`(+ko) "Rate limiter injection" seam, `shared-responsibility.md`(+ko) §4. Tests: `tests/rate-limiter.test.mjs` — an injected limiter is the one consulted (deny→429, allow→pass-through), fail-closed on a missing `allow()`, the default limiter prunes aged-out one-shot identities (bounded `Map` via `_size()`), and the fixed-window limit/isolation semantics are unchanged; the existing `tests/proxy-auth.test.mjs` 429 test stays green. **Residual:** core ships **no** built-in distributed limiter (track non-goal §5) — a shared-store implementation is the operator's injection or a future satellite; the default's per-process scope is the documented honest default |

## 6. P2 Product/Documentation Risk Status

| ID | Risk | Status | Resolution evidence |
|---|---|---|---|
| P2-DOC-001 | Separate threat model document missing | Resolved | `docs/current/threat-model.md` |
| P2-DOC-002 | Shared responsibility documentation insufficient | Resolved | `docs/current/shared-responsibility.md` |
| P2-DOC-003 | Region/privacy profile not implemented | Resolved for baseline | `haechi/privacy-profiles`, `privacy.profile` applied at runtime |
| P2-DOC-004 | No API stability policy | Resolved | `docs/current/api-stability.md` |

## 7. npm Release Pre-Distribution Checklist

This checklist is the standing pre-distribution template for every release on the `1.x` stable line; it was first exercised for the `0.3.2` developer preview, whose results are retained below as the reference record.

External npm gate check results (`0.3.2` developer preview, 2026-06-10, post-publish):

- `npm whoami`: `raeseoklee`
- `npm view haechi version`: `0.3.2`

All checklist items below were completed for 0.3.2 on 2026-06-10 except the provenance publish path, which was deferred to GitHub Actions trusted publishing (`v0.3.2` tag and GitHub pre-release were completed). Subsequent stable releases publish through the trusted-publishing path with provenance.

1. `npm run release:preflight`
2. `npm run sbom`
3. `npm run bench:payload`
4. `npm run release:preflight:npm`
5. Create GitHub release
6. GitHub Actions `Publish npm Developer Preview` succeeds
7. Confirm actual published version with `npm view haechi version`

## 8. Remaining Non-Blocking Backlog

| Version | Goal | Remaining scope |
|---|---|---|
| 0.4.0 ✅ | Token round-trip and adoption | Shipped 2026-06-10: request-scoped response detokenization, deterministic tokenization (derived key), `haechi mcp-wrap`, `haechi audit-verify`/`haechi status`, injection detection type (default allow), `identity`/`authProvider` contracts reserved. See `docs/current/release-0.4-implementation-scope.md` |
| 0.5.0 ✅ | Streaming hardening | Shipped 2026-06-10: SSE/NDJSON streaming response inspection with bounded cross-frame buffer (`streaming.requestMode: inspect`). Stream sequence AAD, replay cache, stronger remote deployment guide deferred to 0.6+. See `docs/current/release-0.5-implementation-scope.md` |
| 0.6.0 ✅ | Auth and per-client controls | Shipped 2026-06-10 (PRs #17–#19): built-in bearer auth, named policy profiles, model allowlist, request rate limit, PII-safe identity in audit. See `docs/current/release-0.6-implementation-scope.md` |
| 0.7.0 ✅ | Ops hardening | Shipped 2026-06-10 (PRs #22–#24): audit head-hash anchoring + external sink contract, cryptoProvider contract hardening + `assertCryptoProviderConformance` + reference KMS adapter, signed/checksummed release artifacts. See `docs/current/release-0.7-implementation-scope.md` |
| 0.8.0 ✅ | Ecosystem foundation + satellites | Shipped 2026-06-10 (PRs #27–#32): npm workspaces monorepo (root self-member `["."]` + `satellites/*`); **published** `haechi@0.8.0` (attested), `haechi-crypto-kms` and `haechi-auth-jwt` (unscoped — the `@haechi` scope was taken). Core stays zero runtime dependency (CI no-leak + zero-dep + satellite-packaging gates). Satellite `0.1.0` was a manual bootstrap publish (unattested, `--provenance=false`, mirroring the `0.3.2` gap) to create the names so per-name Trusted Publishers could be configured; `0.1.1` is the first attested CI release (SLSA provenance + sigstore, `gh attestation verify` passes). See `docs/current/release-0.8-implementation-scope.md` |
| 0.9.0 | Observability + interactive auth | `haechi-auth-oidc` full authorization-code flow, `haechi-dashboard` read-only audit viewer (hash-chain integrity display, summary/search/timeline), additional `haechi-crypto-kms` backends (Vault/GCP/Azure) |
| 1.0.0 | Stable API contract | Migration policy, long-term audit schema, plugin sandbox/runtime conformance, and dynamic loading of external auth/classifier packages that pass allowlist/manifest |

Dynamic npm package loading is prohibited until the 1.0 plugin sandbox. External providers in 0.4–0.7 are supported only via `createRuntime(config, providers)` programmatic injection.

## 9. Current Permitted Use

The `1.x` stable line is intended for use in the following contexts:

- Local development environments
- Sample payload validation
- OpenAI-compatible/vLLM/Ollama/llama.cpp proxy PoC and self-hosted gateway
- Policy/filter/audit pipeline review
- GitHub code review and security design discussion
- A self-hosted production gateway **when** the operator supplies network access control, authentication/authorization, and production key custody in front (see §1)

Haechi is still not intended for the following uses:

- A proxy directly exposed to the internet without the operator's own network controls and authentication
- Compliance evidence or legal conformance proof (Haechi is not a compliance guarantee)
