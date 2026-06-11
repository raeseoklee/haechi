# Haechi 1.0 Implementation Scope

- Status: Draft 0.2 (design — not yet implemented; hardened after a 3-lens adversarial security review, 2026-06-11)
- Date: 2026-06-11
- Target version: 1.0.0 (after 0.9.0)
- Type: stable API contract + plugin sandbox (the first stable release)

## 1. Release Goal

1.0 is the **first stable release**: it (a) **freezes a stable public API contract** with a deprecation/migration policy and a long-term audit schema, and (b) crosses the line the project has deliberately held since 0.1 — **dynamic loading of external plugin code** — but only through an **asymmetrically-signed, capability-gated, `worker_threads`-isolated, audited** sandbox, and only for the **`authProvider`** contract to start.

**Scope decisions (2026-06-11, confirmed with the maintainer):**

1. **Sandbox/loading model:** dynamic loading is enabled **only** for plugins that are **signed (Ed25519, asymmetric)**, pass a **capability-manifest allowlist + operator pin/revocation checks**, and run in a **`node:worker_threads` isolation** boundary with full **lifecycle auditing**. `createRuntime(config, providers)` **injection remains the default and recommended path**.
2. **Plugin scope:** **`authProvider` only** in 1.0. Classifier/filter and crypto plugins stay injection-only until 1.x.
3. **API freeze:** **strict** — the core public API, the **provider contracts**, the **audit event schema** (including nested sub-schemas), and the **config schema** are frozen under strict semver with a deprecation policy.
4. **Release shape:** **staged** — 1.0.0 ships the API freeze + the signed-plugin contract/conformance/signing + the worker-isolated `authProvider` sandbox MVP. Stronger capability **enforcement** (child-process + the Node permission model), more plugin kinds, a live revocation feed, and a registry are 1.x.

Core stays **zero runtime dependency** — the sandbox is built on `node:worker_threads` + `node:crypto` (Ed25519 sign/verify is a `node:crypto` builtin). It does **not** reuse `packages/policy-bundle` (that is symmetric HMAC — see §2.2).

### The honest security model (read this first)

**`node:worker_threads` is NOT a security sandbox against malicious code.** A worker shares the process and can still touch the filesystem, the network, and `process.env`; isolation is **V8-heap-only** (Node's permission model is process-wide, not per-worker; `SharedArrayBuffer`/transferables would even reopen a shared-memory channel, so the wire format is a plain JSON string — §2.3). The 1.0 sandbox therefore provides:

- **Memory isolation** — separate V8 heap; the plugin cannot read/corrupt host memory, the crypto keys, the token vault, or the audit sink (only the typed message channel crosses).
- **Crash/hang isolation + resource limits** — `resourceLimits` (heap cap) + a per-call **timeout that terminates the worker** contain a buggy/runaway plugin; a hang fails closed (deny).
- **Data minimization** — the host sends the worker **only the credential slice** (the `Authorization` header / bearer token), **never the request body** and **never the crypto key**; the worker returns **raw claims**, and the **host** builds the PII-safe identity via `buildExternalIdentity` (the keyed-HMAC key never leaves the host).
- **A narrow, audited, typed contract** — the worker speaks only the `authProvider` message protocol; every load/deny/terminate decision is audited (§2.4).

What the worker boundary does **NOT** give you in 1.0 — these are **accepted residuals, gated only by the signing/vetting trust model**, not by the worker (§6):

- **A malicious *signed* plugin can still use the OS** — `fetch`, `fs`, `process.env` are not blocked. `networkEgress: false` in the manifest is a *declaration*, not an enforced control in 1.0.
- **A malicious *signed* auth plugin can exfiltrate the live credential** it legitimately receives (the bearer token), because it has de-facto network egress. There is **no technical barrier** in 1.0 — only the trust gate.

True per-plugin capability **enforcement** (block fs/net, contain the credential) requires **child-process isolation under the Node permission model** (`--permission --allow-fs-read=…`), the documented **1.x** path. This is why injection stays the default and why the trust gate (asymmetric signature + operator allowlist + pin + revocation) is load-bearing.

## 2. Scope

### 2.1 API stability freeze (the 1.0 contract)

**Frozen public surface (an explicit IN/OUT table replaces today's vague "0.x is preview").** Every `package.json` `exports` subpath and the CLI is classed:

| Surface | 1.0 status |
|---|---|
| `haechi` / `haechi/core` (`createRuntime`, `createHaechi().protectJson`, `collectStringEntries`), `haechi/auth` (`authProvider` contract, `buildExternalIdentity`, `buildIdentity`, `validateLabels`), `haechi/crypto` (`cryptoProvider` contract, `assertCryptoProviderConformance`, `canonicalize`), `haechi/audit` (event schema, `verifyAuditChain`, `sanitizeAudit`, `FORBIDDEN_KEYS`), `haechi/policy`, `haechi/filter` (rule shape), `haechi/token-vault`, `haechi/runtime` (`normalizeConfig` shape), `haechi/protocol-adapters`, `haechi/plugin` (manifest + the new sandbox) | **FROZEN** (breaking change = major) |
| `haechi/proxy`, `haechi/mcp-stdio`, `haechi/stream-filter`, `haechi/policy-bundle`, `haechi/privacy-profiles`, and the **CLI** (`bin/haechi.mjs`) | **FROZEN BEHAVIOR + wire/contract**; human-readable CLI/log **text** may still change (not part of the contract) |
| anything still marked experimental in `api-stability.md §3` | must be **graduated** (and removed from §3) or **explicitly kept preview past 1.0** with a stated reason — no silent ambiguity |

- **Strict semver from 1.0** (breaking→major, additive→minor, fix→patch). The "0.x minor may break" latitude ends for core.
- **Deprecation policy.** A deprecated export/field/option is kept **≥1 minor**, emits a documented migration note and a one-time runtime `process.emitWarning` with a **stable `code` prefix `HAECHI_DEPRECATION_*`** (the code/text are themselves part of the contract), and is removed only at the **next major**. **Security exception (the one sanctioned in-minor break):** a change required to close a *disclosed* vulnerability may break/remove within a **minor**, shipped with a security advisory + a migration path (mirroring the existing "blocking unsafe config may tighten in a patch" latitude).
- **Audit event schema — frozen including nested sub-schemas**, enumerated (not just the top level): top-level `{id, timestamp, protocol, operation, identity, profile, mode, enforced, blocked, payloadShapeHash, detections, summary, auditIntegrity}`; `detections[].{type, ruleId, path, kind, confidence, action, enforced}`; **`identity.{id, type, subjectHash, issuerHash, provider}`** (the PII-safe projection — `scopes`/`labels`/raw subject are **NOT** part of the audit identity); `summary.{byType, byAction, detectionCount}`; `auditIntegrity.{alg, canonicalization, sequence, previousHash, eventHash}`. **New fields are additive-only and never change the canonicalization of existing fields**, so a 1.x event still verifies under a 1.0 `verifyAuditChain` (this holds because `canonicalize` hashes the literal object and the verifier recomputes over the *same* stored object — the guarantee is "a future-additive field doesn't break an old verifier reading a new record", which is sound; the doc states this precisely rather than the earlier hand-wave). A canonicalization change is a **major** event-schema bump with a new `canonicalization` tag + a reader-migration path. An explicit top-level **`schemaVersion`** is added (reader-facing; additive) so consumers branch on it without parsing `auditIntegrity`.
- **Config schema freeze unit:** config **key presence + shape** is frozen; **default values may still be hardened** (a safer default is not a breaking change). Unknown keys still throw (fail-closed).

### 2.1a Satellite compatibility prerequisite (must land BEFORE the core 1.0.0 bump)

All four satellites pin `"haechi": ">=0.8.0 <1.0.0"` — and `<1.0.0` **excludes `1.0.0`** (and even `1.0.0-rc.x`). Bumping core to 1.0.0 makes **every satellite's peer dependency unsatisfiable** (ERESOLVE / unmet peer). `haechi-auth-oidc` has the same problem cross-satellite (`"haechi-auth-jwt": ">=0.2.0 <1.0.0"`). So **PR0** (before any core bump):

- Widen every satellite peer range to track the core **major**, not the next minor: `"haechi": ">=0.8.0 <2.0.0"` (valid by definition of the freeze — a satellite built against ≥0.8 works through the whole 1.x line), and `haechi-auth-oidc`'s `"haechi-auth-jwt": ">=0.2.0 <2.0.0"`. Patch-release all four (`auth-jwt 0.2.x`, `crypto-kms 0.2.x`, `dashboard 0.1.x`, `auth-oidc 0.1.x`) + regenerate the lockfile (the workspace-lockfile gotcha applies).
- Add a **`release:preflight` gate** that parses every `satellites/*/package.json` peer range and asserts `semver.satisfies(coreVersion, range)` for the core version about to publish — so a future core major can never ship while a satellite still excludes it.
- Document in `api-stability.md §5`: the satellite peer **upper bound tracks the core MAJOR**, never pinned below the next minor.

### 2.2 Asymmetric signed-plugin contract (Ed25519) + pinning + revocation + conformance

**Signing is asymmetric (Ed25519), NOT the symmetric `policy-bundle` HMAC.** `policy-bundle` signs with HMAC keyed off the local AES key file — the verifier holds the same secret that signs, so it cannot express "a third-party author signed; the operator verifies with a public key." 1.0 adds a **`node:crypto` Ed25519** signed-manifest primitive (zero new dependency): the **author holds the Ed25519 private key**; the **operator allowlists the Ed25519 public key** as a trust anchor. (Do not reuse `policy-bundle` for plugin signing.)

- **The signed envelope covers content, not a path.** The signed bytes are `canonicalize({ pluginId, kind, version, capabilities, coreVersionRange, entrySha256, notBefore, notAfter })` — i.e. the signature binds the **sha256 of the exact entry bytes**, the **kind**, the **declared capabilities**, the **compatible core range**, and a **validity window**. Signing a path (or omitting `entrySha256`/`kind`/`capabilities`) is a swap / capability-downgrade attack and is rejected.
- **Trust-anchor-only key resolution (no kid-by-claim).** The verification key is resolved **only** from the operator's `trustAnchors` allowlist; if `manifest.signerKeyId` is not an allowlisted anchor, **refuse before any verify**. The algorithm is pinned to Ed25519 per anchor (no alg agility, no HS/RS confusion). The plugin trust-anchor set is a **separate curated list**, never the AES rotation key file (retired/rotated AES kids must not become signer anchors).
- **Pinning (anti malicious-update / rollback).** Operator config `plugin.pin = { version?, entrySha256?, manifestSha256? }`: the loader fails closed if the loaded manifest version / entry hash does not match the pin. A **per-`pluginId` version floor** rejects rollback to an older signed artifact. So a *trusted signer* cannot silently ship a new (or old-vulnerable) entry under the same anchor without tripping the pin/floor.
- **Revocation + freshness.** Operator denylists `plugin.revokedSignerKeyIds` + `plugin.revokedEntrySha256` checked at load (fail-closed: a revoked signer or hash never loads). The signed `notBefore`/`notAfter` window is enforced at load. **In-memory behavior on revocation** (1.0, stated honestly): revocation takes effect at the **next load/restart**; a **global kill-switch** (`plugins.enabled: false`, and a per-plugin disable) lets an operator **force-drop a live plugin** immediately. A live CRL/feed is 1.x.
- **Re-verify on every respawn.** Because workers are lazily respawned after a timeout-terminate, the **full gate (signature + anchor + pin + revocation + capability allowlist) re-runs on every spawn**, not only at first construction.
- **Capability allowlist (operator-side).** `plugins.allowCapabilities`; a manifest requesting a capability outside it → refused. `readsCredentials` is **required** for `kind: authProvider` (it sees the bearer token). `networkEgress`/`readsPlaintext` are **declared and audited but not enforced** by the worker in 1.0 (the §1 residual — surfaced, not trusted).
- **Conformance is a CORRECTNESS gate, not a malice screen.** `assertAuthProviderConformance(provider, { now, vectors })` runs the **sandboxed** plugin through enumerated security behaviors: missing credential → `null`; malformed credential → `null`; expired / not-yet-valid (clock injected via `now`) → `null`; an internal **throw surfaces as `null`** to the caller (never propagates); a returned identity **MUST** carry `subjectHash`/`issuerHash` and **MUST NOT** contain a field equal to the raw input subject/issuer (PII-safety); deny is **deterministic** for identical input; a valid credential → a well-formed PII-safe identity. The loader **refuses to wire a plugin that fails**. But a signed plugin can detect a fixed test and behave, so: conformance uses **unpredictable per-load randomized vectors**, and — load-bearing — the **host re-validates PII-safety on every call** (`buildExternalIdentity` + the sanitizer below run per request), not just at load. **Conformance-pass does not imply trustworthiness** (that is the signing+vetting gate); test/prod divergence is an accepted residual (§6).

### 2.3 The `worker-isolated` `authProvider` sandbox (the MVP)

`createSandboxedAuthProvider({ manifestPath, trustAnchors, allowCapabilities, pin, revoked, cryptoProvider, auditSink, timeoutMs, maxPendingCalls, maxMessageBytes, resourceLimits, now })` returns a **host-side `authProvider`** satisfying the frozen contract — so it wires through the **existing** injection seam and the new `auth.provider: "plugin"` config path.

- **Load sequence (fail-closed at every step, each step audited):** validate manifest (`worker-isolated` + `kind: authProvider`) → resolve the anchor by `signerKeyId` **from `trustAnchors` only** (else refuse) → read the **entry bytes into memory**, sha256, and **verify the Ed25519 signature over the canonical envelope incl. `entrySha256`** → check `notBefore/notAfter`, the revocation denylists, the pin/version-floor, and capabilities ⊆ allowlist → spawn the Worker **from the in-memory verified source** (`new Worker(code, { eval: true, resourceLimits, workerData: <no secrets> })`), **never re-resolving the path** after verification (no TOCTOU; refuse a symlinked entry) → run `assertAuthProviderConformance` against the sandboxed provider → only then return the live provider. Any failure throws at construction and emits `plugin.load.refused{reason}` (§2.4).
- **Per-request protocol (data-minimized, correlation-id'd):** `authenticate(request)` extracts **only** the credential slice (the `Authorization` header / token — never the body), wraps it with a **unique correlation id**, and posts it as a **JSON string over the MessagePort** (no structured-clone objects, no `SharedArrayBuffer`/transferables → no shared-memory or object-graph smuggling). `maxMessageBytes` bounds the wire. The worker validates the credential (JWKS egress is inherent to an auth plugin) and returns **raw claims** `{ subject, issuer, type, scopes, labels }` or a deny.
- **Host-side claims sanitizer (before `buildExternalIdentity`):** the JSON reply is parsed into a **null-prototype object** (`JSON.parse` + reconstruct onto `Object.create(null)`); only a **fixed allowlist of own-enumerable keys** is accepted; `__proto__`/`constructor`/`prototype` are stripped; array sizes and total identity size are bounded; every value is type-validated/coerced at the boundary. Then the **host** builds the PII-safe identity (`buildExternalIdentity({ provider: "plugin:<pluginId>", subject, issuer, type, scopes, labels }, cryptoProvider)`) — the keyed-HMAC key never enters the worker, and a hostile claims object cannot pollute the prototype or smuggle a raw value.
- **Concurrency model (no cross-caller leakage / no terminate races):** each in-flight call is matched to its reply **by correlation id**; unmatched / duplicate / late replies are **dropped**. The worker is **single-occupancy** (one in-flight call) — a per-call timeout-terminate can therefore never kill a *sibling* call; a pending-call **cap (`maxPendingCalls`)** bounds concurrency (excess → deny). Respawn after terminate is guarded **single-flight**. Plugins are required to be **stateless across calls**; any residual cross-request state risk is a §6 residual.
- **Timeout + resource bound (fail-closed):** each call is bounded by `timeoutMs` (a **required positive integer — no unbounded default**); on timeout the host **terminates the worker** (`plugin.worker.terminated{cause: timeout}`) and returns `null`, respawning lazily (re-running the full gate). `resourceLimits` caps the heap. (CPU/fd/socket are *not* bounded in 1.0 — §6 residual.)
- **Config (`auth.provider: "plugin"`) — enumerated fail-closed `normalizeConfig` rules** (matching the keys/tokenVault rigor): require `plugin.manifestPath` (non-empty local path); `plugin.trustAnchors` a non-empty array of `{ keyId: string, publicKey: string (Ed25519) }`; `plugin.allowCapabilities` an array ⊆ `CAPABILITY_KEYS ∪ {readsCredentials}` (reject unknown); `readsCredentials` present for `kind: authProvider`; `plugin.timeoutMs` a positive integer; `resourceLimits.maxOldGenerationSizeMb` a positive integer; optional `plugin.pin`/`plugin.revoked*`/version-floor well-formed; `plugins.enabled` honored (kill-switch). Any violation throws at load. `createRuntime` still requires the injected `cryptoProvider` for the host-side identity build.

### 2.4 Audit of the plugin lifecycle (a security product MUST record loading third-party code)

Reusing the existing hash-chained `auditSink` (the same seam `recordProxyDecision`/`auth_denied` already uses), the sandbox emits **PII-safe** events — ids/hashes/counts only:

- `plugin.load.accepted` `{ pluginId, version, entrySha256, signerKeyId, capabilitiesGranted }`
- `plugin.load.refused` `{ reason ∈ missing-signature | unknown-signer | tampered-entry | revoked | below-version-floor | pin-mismatch | expired-window | capability-not-allowlisted | conformance-failed | manifest-invalid, pluginId?, signerKeyId? }`
- `plugin.authenticate.deny` `{ pluginId, reason ∈ invalid-claims | throw | non-pii-safe-identity | timeout }`
- `plugin.worker.terminated` `{ pluginId, cause ∈ timeout | oom | crash }`

`FORBIDDEN_KEYS` is **extended** with the plugin/claims surface (`claims`, `subject`, `issuer`, `credential`, `authorization`, `signature`, `entry`) as defense-in-depth so a future plugin event can never leak a raw claim/token/signer secret into the chained log (the events above already carry only ids/hashes). Tests assert a refused load and a worker timeout each emit exactly one chained event, and that a synthetic plugin event with raw claims is stripped by `sanitizeAudit`.

### 2.5 Real-environment validation exit criterion

- **Met:** the 2026-06-11 live validation against real self-hosted vLLM + Ollama ([[2026-06-11-real-environment-validation]]) + `haechi-dashboard` observability.
- **Residuals (documented, not gating 1.0):** (1) **live KMS-backend validation** (real AWS/GCP/Azure/Vault) is out-of-CI; (2) **the worker plugin sandbox itself is unproven against a real hostile plugin** — its security rests on the trust gate + the §6 residuals, validated by the fail-closed/data-minimization tests, not by an adversarial third-party-plugin red-team (a 1.x exercise, ideally alongside the child-process+permission enforcement).

## 3. Explicit non-scope (deferred to 1.x)

- **Capability *enforcement*** against a malicious signed plugin (block fs/net, contain the credential) — needs child-process isolation under the Node permission model.
- **Classifier/filter and crypto plugin loading** — `authProvider` only in 1.0.
- **A live revocation feed / CRL**, a plugin **registry / marketplace**, multi-origin, hot-reload, and an **unsigned dev loader** (which would undermine the trust gate — development uses injection).
- **Python SDK.**

## 4. Backward compatibility & the 1.0 stability contract

Existing behavior is **unchanged** — every provider contract, the config and (now nested-enumerated) audit schemas, and the zero-dependency posture are exactly as in 0.9; they are **declared frozen**. The plugin sandbox is **purely additive and opt-in** (`auth.provider: "plugin"`; default stays `none`/`bearer`/`external`). The one behavioral core change is the **additive `FORBIDDEN_KEYS` extension** (§2.4) and the **`schemaVersion`** field (additive). The **satellite peer-range widening (§2.1a) is a prerequisite** so the four satellites keep installing against core 1.0.0.

## 5. 1.0 relationship / what 1.0 closes

1.0 closes the two long-standing 1.0 gates — **API-stability freeze** (§2.1) and the **plugin sandbox + dynamic-loading story** (§2.2–2.4: asymmetric-signed + isolated + audited + auth-only) — and records the **real-environment-validation** exit criterion as met with documented residuals (§2.5). It graduates Haechi from developer preview to a stable self-hosted security gateway while keeping the core promise: a small zero-dependency core, fail-closed everywhere, and "the same security tests pass when you swap a component."

## 6. Threat-model & risk-register deltas (concrete)

| New surface (1.0) | Control | Residual |
|---|---|---|
| **Malicious/compromised signed plugin** loaded dynamically | Ed25519 signature over `entrySha256`+kind+capabilities, trust-anchor-only key resolution, pin + version-floor + revocation denylist, conformance gate, worker memory/crash isolation, full lifecycle audit | **A signed plugin's own fs/net/`process.env` is NOT blocked, and it CAN exfiltrate the credential it receives** — gated only by the signing/vetting trust model; true enforcement is the 1.x child-process+permission path |
| **PII/secret leak to a plugin** | Only the credential slice crosses (never the body/keys); JSON-string wire; null-proto sanitizer; host builds the keyed-HMAC identity | the credential the auth plugin legitimately validates is visible to it (see row above) |
| **Cross-boundary object/proto smuggling** | JSON-string wire (no structured clone / SAB / transferables) + null-proto allowlist sanitizer before `buildExternalIdentity` | none material |
| **Swap / TOCTOU on the entry** | Sign `entrySha256`; read-into-memory + hash + verify + spawn from in-memory source; no path re-resolution; reject symlinks | none material |
| **Signer-key confusion / downgrade / rollback / malicious update** | Trust-anchor-only resolution, pinned algorithm, pin/version-floor, revocation | operator must curate anchors/pins |
| **Plugin DoS** | Per-call `timeoutMs` terminate, heap `resourceLimits`, `maxPendingCalls`, `maxMessageBytes`, single-occupancy worker | a signed plugin can burn its allotted CPU within the timeout (CPU/fd not bounded in 1.0) |
| **Unaudited code-load** | `plugin.load.*` / `authenticate.deny` / `worker.terminated` audit events; extended `FORBIDDEN_KEYS` | — |
| **Conformance test/prod divergence** | Randomized per-load vectors + per-call host re-validation of PII-safety | a malicious plugin can pass conformance then misbehave (covered by signing+vetting, not conformance) |
| **API/audit-schema drift** | Strict semver + deprecation windows (+ security exception) + additive-only nested-enumerated audit schema + `schemaVersion` | a major bump can break by design (documented migration) |

Proposed risk IDs: **P1-SEC-010** (dynamic plugin execution / sandbox trust model — supersedes P1-SEC-004's manifest-only stance, lifted under the new controls), **P1-SEC-011** (plugin signing/trust-anchor/revocation lifecycle), **P2-API-001** (stable-contract freeze + deprecation policy), **P2-OPS-006** (satellite peer-range / major-tracking gate). New §4 exclusions: capability enforcement vs a malicious signed plugin, credential containment, classifier/crypto plugin loading, unsigned dev loader, live CRL.

## 7. Test criteria (mapped to the PR breakdown)

### 7.1 PR0 — satellite peer-range widening + the preflight gate
- All four satellites' `haechi` peer range widened to `>=0.8.0 <2.0.0` (and auth-oidc's `haechi-auth-jwt` to `<2.0.0`); lockfile regenerated; `release:preflight` fails if `!semver.satisfies(coreVersionToPublish, satelliteRange)` for any satellite. A test simulates core `1.0.0` and asserts every satellite range is satisfied.

### 7.2 PR1 — API stability freeze (docs + contract test)
- `api-stability.md`(+ko) carries the IN/OUT table, strict-semver + deprecation policy (incl. the `HAECHI_DEPRECATION_*` runtime-warning contract and the security exception), and the satellite major-tracking rule.
- A **contract/snapshot test** pins the frozen exports per subpath + a **full audit event including a non-null `identity` and one `detections[]` entry** (so the nested sub-schemas are guarded, not just the top level) + the config-schema key set + `schemaVersion`. An additive field passes; a removed/renamed field (top-level OR nested) fails. `verifyAuditChain` verifies a frozen-schema fixture and still verifies it with a synthetic additive field.

### 7.3 PR2 — Ed25519 signed-plugin contract + pinning/revocation + conformance harness
- `packages/plugin` accepts a `worker-isolated`+`authProvider` manifest with the Ed25519 envelope; **refuses** (distinct fail-closed tests, each emitting `plugin.load.refused{reason}`): missing/invalid signature; signer not in `trustAnchors` (kid-not-allowlisted, resolved **before** verify); **entry bytes mutated after signing, path unchanged**; revoked signer / revoked entryHash; below version-floor; pin mismatch; outside `notBefore/notAfter`; capability not allowlisted; alg ≠ Ed25519.
- `assertAuthProviderConformance` exists; a reference provider passes; a broken one (throws / returns a raw-subject identity / accepts an expired credential / non-deterministic) **fails** each case (negative tests). Vectors are randomized per run.
- `FORBIDDEN_KEYS` extension test: a synthetic plugin event with `claims`/`credential`/`signature` is stripped by `sanitizeAudit`; the chain stays valid.

### 7.4 PR3 — the `worker-isolated` authProvider sandbox
- A reference **signed** auth plugin loads, passes conformance in the worker, authenticates a valid bearer/JWT into a **host-built PII-safe identity**; assertions: the worker received **only** the credential slice (an instrumented echo-plugin proves it never got the body / audit sink / token vault / key), the raw subject never appears in the audit, `plugin.load.accepted` is emitted with the resolved `entrySha256`/`signerKeyId`.
- **Fail-closed + isolation matrix:** unsigned/wrong-signer/tampered/revoked/pin-mismatch/capability-not-allowlisted → construction throws + `load.refused`; **timeout → `null` + worker terminated + `worker.terminated{timeout}`**; throw → `null`; a claims object with `__proto__`/extra keys → sanitized (no prototype pollution, extras dropped) and PII-safe; two concurrent calls with distinct correlation ids never cross responses; a terminate of one call cannot kill a sibling (single-occupancy); `maxPendingCalls`/`maxMessageBytes` enforced; `plugins.enabled:false` (kill-switch) refuses load.
- `normalizeConfig` `auth.provider:"plugin"` enumerated fail-closed tests (each bad option throws); end-to-end through `createRuntime` + the proxy auth gate (a request authenticates via the plugin; identity keyed-HMAC; audit carries no raw subject/credential).

### 7.5 All
- Core stays zero runtime dependency (`node:` only — Ed25519 is `node:crypto`); `check:packaging` + `check:satellite-packaging` green; the frozen-contract snapshot test + the peer-range preflight gate guard future PRs.

## 8. Suggested PR breakdown (stacked)
1. **PR0 — satellite peer-range widening + preflight gate** (prerequisite; patch-release the four satellites). → §7.1
2. **API freeze** — `api-stability.md`(+ko) IN/OUT table + deprecation/security-exception policy + the nested-schema contract/snapshot test + `schemaVersion`. → §7.2
3. **Ed25519 signed-plugin contract + conformance** — the asymmetric primitive (`node:crypto`), the signed envelope (entryHash/kind/capabilities/window), trust-anchor-only resolution, pin/version-floor/revocation, `assertAuthProviderConformance`, the `FORBIDDEN_KEYS` extension. → §7.3
4. **Worker-isolated authProvider sandbox** — `createSandboxedAuthProvider` (in-memory verified spawn, JSON-string wire, null-proto sanitizer, correlation-id single-occupancy concurrency, timeout/terminate, kill-switch), the `auth.provider:"plugin"` config branch + lifecycle audit, a reference signed plugin + the §7.4 matrix. → §7.4
5. **1.0.0 release cut** — bump core to **1.0.0**; docs EN/KO (this scope doc, threat-model + risk-register deltas with the §6 IDs + target bump, the real-env exit criterion + residuals); wiki ingest (a `[[plugin-sandbox]]` page + `[[packaging-and-distribution]]`/`[[identity-and-auth]]`/`release-roadmap` updates); README "Current Scope". Core reuses the `v*` tag; the first stable `haechi@1.0.0` publishes attested. (PR0 must already be merged + the satellites republished so they install against 1.0.0.)
