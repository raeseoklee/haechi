---
updated: 2026-06-12
tags: [concept, security, plugin, sandbox, auth]
---

# Plugin Sandbox

The **signed-plugin sandbox** is the narrow lifting of Haechi's long-standing dynamic-loading ban: it dynamically loads a third-party **`authProvider` only**, under an Ed25519 signed-manifest trust gate, fully audited. **1.0** ships the `worker_threads`-isolated worker (trust-based; the honest residual below); **1.1** adds the opt-in **`process-isolated`** runtime — real capability enforcement via a child process under the Node permission model (jump to [§ process-isolated](#capability-enforcement-the-process-isolated-runtime-11)). Everything else still loads only by injection through `createRuntime(config, providers)` — injection stays the default, and the manifest-only `validatePluginManifest` path is untouched. Sources: `packages/plugin/signing.mjs` (the trust gate), `packages/plugin/sandbox.mjs` (the worker), `packages/plugin/index.mjs` (`runtime: "worker-isolated"` manifest validation). Design + authoritative threat rows: `docs/current/release-1.0-implementation-scope.md` §2.2–2.4/§6. Risk IDs: **P1-SEC-024** (dynamic plugin execution / sandbox trust model — supersedes P1-SEC-004's manifest-only stance, lifted under the new controls), **P1-SEC-025** (plugin signing / trust-anchor / revocation lifecycle).

## The honest security model (read this first)

`worker_threads` is **NOT a capability sandbox.** A worker shares the process; a malicious *signed* plugin can still call `fs`/`net`/`process.env` and **exfiltrate the credential it receives** (an `authProvider` legitimately sees the bearer token it validates). That residual is **accepted** and gated **only** by the trust gate, never by the worker. What the worker actually provides (design §1, the comment at the head of `sandbox.mjs`):

- **V8-heap memory isolation** — the plugin cannot read the host's crypto key, token vault, or audit sink; only a typed JSON-string message crosses.
- **Crash/hang containment** — `resourceLimits` + a per-call timeout that terminates the worker; a hang fails closed (deny).
- **Data minimization** — the worker receives **only** the credential slice (never the request body / key / sink); the **host** builds the keyed-HMAC identity.
- **A narrow, audited, correlation-id'd contract.**

For the `worker_threads` mode the **load-bearing** defense is the trust gate (Ed25519 signature + operator allowlist + pin + revocation + window), not the worker boundary. **1.1 closes this residual** with the opt-in **`process-isolated`** runtime (below) — real capability enforcement via a child process under the Node permission model. The worker mode stays the default and is unchanged.

## Capability enforcement: the `process-isolated` runtime (1.1)

`packages/plugin/process-sandbox.mjs` `createProcessIsolatedAuthProvider`/`…Sync` is the **1.1** answer to the worker residual — manifest `runtime: "process-isolated"`, `auth.plugin.isolation: "process"`. It runs the **same** signed `authProvider` (the trust gate + claims sanitizer + host keyed-HMAC identity are shared via `packages/plugin/sandbox-common.mjs`) but in a **child `node` process** with **kernel-enforced** capability denial. Risk IDs **P1-SEC-027** (enforcement) / **P1-SEC-028** (host-mediated key material + the core SSRF guard). Design: `docs/current/release-1.1-implementation-scope.md`.

What is enforced (empirically validated on Node 26):

- **Zero OS grants** — spawned `node --permission --disable-proto=delete -e <harness>` with **no** `--allow-fs-read`/`--allow-child-process`/`--allow-worker`/`--allow-addons`/`--allow-wasi`/`--allow-net`. The kernel denies the plugin's `fs`/`child_process`/`worker` and (on a `--allow-net` Node) `net`/`fetch`/`dns` **and the `process.binding('tcp_wrap')` bypass** — all `ERR_ACCESS_DENIED`.
- **Network = the kernel `--allow-net` denial, never a JS harness.** A "delete `node:net`/fetch" harness is NOT containment: `process.binding('tcp_wrap')` opens a live socket and a fresh `import('node:net')` re-resolves the builtin past any cache deletion. So the default **`netEnforcement: "require-permission"` fails closed** — `netEnforcementSupported()` behavior-probes (a `--permission` child must see `net.connect` denied) and `createProcessIsolatedAuthProvider` **throws at construction** on a Node that can't enforce it (Node 22 LTS). The fail-closed detection shipped in PR1 because CI on Node 22 proved net is ungated there.
- **stdio fully closed** — `stdio: ['ignore','ignore','ignore','ipc']`: no stdout/stderr/inheritable fd, so a plugin writing the credential to stderr reaches no host sink (a leak channel `--allow-net` does not gate). The only channel is the dedicated IPC.
- **No fs grant at load** — the verified plugin bytes cross over IPC and load from a `data:` URL (the mechanism the worker uses), so there is no temp-dir / realpath / symlink / TOCTOU surface and no fs grant at all.
- **env scrubbed** to `{}` (no inherited host secrets, no `NODE_OPTIONS` flag injection); **JSON-string-only IPC** (`serialization: "json"`) + the shared null-proto claims sanitizer; single-occupancy serialization; timeout→kill→lazy re-verify-on-respawn; a **spawn-storm circuit breaker** (N kills within a window → permanent fail-closed deny, exponential backoff); a close-during-spawn guard that cannot resurrect a child after `close()`.

**Host-mediated key material** (P1-SEC-028): a custom-credential plugin that needs a key document does not fetch it (net is denied) — the **host** fetches the **operator-declared** URL through the new core node:-only **`haechi/ssrf`** module (`isBlockedAddress` + `guardedFetch`: https-only, post-DNS re-check, `redirect:"error"`, bounded body; `createGuardedKeyFetcher`: TTL cache + cooldown) and injects it over the IPC as the plugin's second `authenticate(credential, { keyMaterial })` argument. The plugin **never names a URL** (no plugin-driven SSRF). The satellites keep their **deliberate** local `isBlockedAddress` copies (a crypto/auth package must not runtime-depend on core-ssrf; `crypto-kms/ssrf-parity.test.mjs`) — the core re-import is **deferred**, drift guarded by a core-vs-`auth-jwt` parity test.

**Audit:** process lifecycle events carry **host-computed/enum-only** `isolation: "process"` (a discriminator, never child-supplied), and `load.accepted` adds `netEnforcement` + `grants: []` (zero OS grants). All outside the frozen protect-event schema.

**Residual (process-isolated):** a Node without `--allow-net` (fail-closed, not contained); a `networkEgress`-granted plugin; the host-fetch DNS-rebinding window; credential + injected key material in child memory (core-dump/swap); a V8/Node escape (`--permission` is a runtime control, not an OS sandbox).

## The Ed25519 signed-manifest trust gate (`verifySignedPlugin`)

`packages/plugin/signing.mjs` is **asymmetric** signing: the plugin author holds the Ed25519 private key and signs offline; the operator allowlists the **public** key as a trust anchor and verifies. It deliberately does **not** reuse `packages/policy-bundle` — that is symmetric HMAC keyed off the local AES key file (the verifier holds the same secret that signs, so it cannot express third-party authorship). Zero new runtime dependency: `node:crypto` (Ed25519 is a builtin) + core `canonicalize()` so sign and verify agree byte-for-byte.

The signature covers the canonical **payload** `{ pluginId, kind, version, capabilities, coreVersionRange, entrySha256, notBefore, notAfter }` — binding the **sha256 of the exact entry bytes** plus kind/capabilities/range/window. Signing a *path* (rather than the bytes), or omitting `entrySha256`/kind/capabilities, is a swap / capability-downgrade attack and is rejected.

`verifySignedPlugin({ signed, entryBytes, trustAnchors, revoked, pin, versionFloor, allowCapabilities, coreVersion, now })` runs a **security-critical, ordered** check sequence (must not be reordered), each refusal throwing a typed `PluginLoadError` whose `.reason` is a member of the frozen `PLUGIN_LOAD_REASONS` enum (`manifest-invalid`, `alg-not-ed25519`, `unknown-signer`, `revoked`, `tampered-entry`, `invalid-signature`, `expired-window`, `below-version-floor`, `pin-mismatch`, `capability-not-allowlisted`):

1. **Structural** envelope/payload validity.
2. **`alg === "ed25519"`** pinned — no alg agility, no HS/RS confusion.
3. **Trust-anchor-only key resolution.** The verification key is resolved **only** from the operator's `trustAnchors` allowlist, keyed by `signed.signerKeyId`; an unknown kid refuses (`unknown-signer`) **before any verify** — it never selects a key by the object's own claim against a broader keyring. The resolved anchor must itself be an `ed25519` public key.
4. **Revocation** denylist (`signerKeyIds`) before the expensive verify.
5. **`entrySha256` binding.** Recompute the hash of `entryBytes` and **constant-time** compare; a mutated entry (path unchanged) trips here **before** the signature check, so a swap is `tampered-entry`, not `invalid-signature`. A revoked `entrySha256` also refuses.
6. **Ed25519 signature** over `canonicalize(payload)` (algorithm arg `null`).
7. **Validity window** (`notBefore`/`notAfter`, epoch-ms or null).
8. **Version floor** — reject rollback to an older signed artifact per `pluginId`.
9. **Pin** — `version` / `entrySha256` / `manifestSha256` must match the operator pin exactly (anti malicious-update / rollback).
10. **Capability allowlist** — every capability value MUST be a **strict boolean** (`1`/`"true"`/`{}` are rejected at the boundary, not treated as truthy); a `true` capability not in `allowCapabilities` refuses; an `authProvider` MUST declare `readsCredentials`.
11. **`coreVersionRange`** — when `coreVersion` is supplied, it must satisfy the signed range (a node:-only `semver.satisfies` inlined because the `scripts/` peer-range checker is not in the published `files` allowlist).

The returned validated payload is **frozen** so a downstream consumer cannot mutate the attested facts.

A `worker-isolated` manifest is additionally shape-checked by `validateWorkerIsolatedManifest` in `index.mjs`: `kind: "authProvider"` only, a non-empty base64 `signature`, a `signerKeyId`, a 64-char lowercase-hex `entrySha256`, a **mandatory validity window**, and `capabilities.readsCredentials === true`. The historical `manifest-only` path is unchanged.

## The worker-isolated provider (`createSandboxedAuthProvider`)

`packages/plugin/sandbox.mjs` exposes `createSandboxedAuthProvider` (async, resolves to the live provider after conformance) and `createSandboxedAuthProviderSync` (for the `createRuntime` composition root — the trust gate runs eagerly so a refused load throws at construction; conformance is gated lazily behind `provider.ready`, and `authenticate()` fails closed to `null` if conformance rejected). Zero runtime dependency: `node:worker_threads` + `node:crypto` + `node:fs` + in-repo `haechi/plugin` (verify) and `haechi/auth` (identity + conformance).

- **In-memory verified spawn.** `loadAndVerify()` reads+validates the manifest, **confines the entrypoint inside the manifest directory** (an absolute/`../`-escaping path is an arbitrary-file-read primitive — checked before any I/O), **rejects a symlinked entry** (anti-TOCTOU), bounds the entry at 4 MiB, reads the bytes **into memory exactly once**, then runs the full `verifySignedPlugin` gate over those exact bytes. The worker is spawned from the **in-memory verified source** via a string `workerHarness` (an inlined harness, not a path import — the worker has no module graph back to the repo, and the entry loads from a `data:` URL of its own bytes). There is **no path re-resolution** between hash and spawn.
- **JSON-string wire + null-proto sanitizer.** Only JSON strings cross (no structured clone / SharedArrayBuffer / transferables). The plugin's reply is parsed, then **only** the allowlisted own-enumerable claim keys (`subject`, `issuer`, `type`, `scopes`, `labels`) are copied onto a **null-prototype** object — `__proto__`/`constructor`/`prototype` can never reach `buildExternalIdentity` — with each value type-validated and size-bounded (`MAX_SCOPES`/`MAX_LABELS`/`MAX_STRING_LEN`).
- **Host-side keyed-HMAC identity.** The crypto key never crosses to the worker; the **host** calls `buildExternalIdentity({ provider: "plugin:<id>", subject, issuer, ... }, cryptoProvider)` ([[identity-and-auth]]) on every call, so PII-safety is re-enforced per request, not trusted from the plugin.
- **Single-occupancy + DoS bounds.** Worker round-trips run **one at a time** through a serialization chain (a per-call timeout-terminate can never kill a sibling); distinct `cid`s mean replies never cross; `maxPendingCalls` bounds queue depth (`over-capacity` → deny), `maxMessageBytes` bounds the request (`oversized` → deny), `timeoutMs` terminates a hung worker (deny + respawn lazily), and `resourceLimits` bounds the heap.
- **Kill-switch / fail-closed.** A missing credential, a plugin throw (never propagates — surfaces as deny), a crash, a timeout, an oversized message, invalid claims, or a failed identity build all return `null`. `authenticate()` **never throws into the caller** (catch-all → `null`). Re-spawn **re-runs the full trust gate** (it is not a one-time check).

## Lifecycle audit events

A security product MUST record loading third-party code (§2.4). The sandbox emits PII-safe lifecycle events through the injected `auditSink` (fire-and-forget — auditing never makes the auth path throw): `plugin.load.refused{reason}` (the reason is the `PluginLoadError` enum or `conformance-failed`), `plugin.load.accepted` (with `version`, `entrySha256`, `signerKeyId`, and the granted capability list), `plugin.authenticate.deny{reason}` (`over-capacity`/`oversized`/`timeout`/`deny`/`invalid-claims`), and `plugin.worker.terminated{cause}` (`timeout`/`crash`). [[audit-integrity]]'s `FORBIDDEN_KEYS` is extended (1.0) to also strip `claims`/`subject`/`issuer`/`credential`/`authorization`/`signature`/`entry` **and** `scopes`/`labels`. The audit-event identity is **projected** to the frozen 5 keys `{id, type, subjectHash, issuerHash, provider}` — scopes/labels (which can carry attacker-controlled plugin output) are NOT persisted.

## Conformance as a correctness gate (not a malice screen)

`assertAuthProviderConformance` (`packages/auth`, the auth analog of `assertCryptoProviderConformance`) runs once at load through the **same worker wire**: on pass it emits `plugin.load.accepted` and returns the provider; on fail it emits `plugin.load.refused{conformance-failed}`, closes the worker, and rejects. It is explicitly a **correctness gate, not a malice screen** — a malicious plugin can pass conformance and then misbehave (covered by signing + vetting, not conformance). Randomized per-load vectors + per-call host re-validation of PII-safety narrow test/prod divergence; the real containment guarantee remains the trust gate.

## Relation to other invariants

The sandbox is the dynamic-loading exception that keeps [[fail-closed]] coherent: every refusal/error/timeout denies, the trust gate is fail-closed by construction (unknown signer / bad signature / out-of-window / capability-not-allowlisted all throw), and the data-minimization boundary means a worker crash can never leak host secrets. It is purely additive and opt-in (`auth.provider: "plugin"`; default stays `none`/`bearer`/`external`). See [[identity-and-auth]] (the frozen `authProvider` contract this plugin satisfies), [[fail-closed]], and [[audit-integrity]].
