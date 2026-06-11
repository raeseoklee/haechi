# Haechi 1.1 Implementation Scope

- Status: **Implemented + shipped** (2026-06-12; PRs #54/#55/#56 + this release cut, core 1.0.0 → 1.1.0). Design hardened after a 3-lens adversarial review with empirical Node-26 testing.
- Implementation notes (deltas from this design as written):
  - The **fail-closed `--allow-net` feature detection** (`netEnforcementSupported` + `netEnforcement: "require-permission"` default) shipped in **PR1**, not PR3 — it is intrinsic to the runtime's safety: CI on Node 22 (no `--allow-net`) proved that without it the runtime would run net-uncontained, the exact "pretend to contain" failure this design rejects. Detection probes BEHAVIOR (a `--permission` child must see `net.connect` denied), immune to a flag-listed-but-unenforced Node.
  - The **satellite re-import** of the promoted SSRF guard (§2.3) was **deferred**: forcing `haechi-auth-jwt`/`haechi-auth-oidc`/`haechi-crypto-kms` to import `haechi/ssrf` would raise their `haechi` peer floor to 1.1 and reverse their deliberate "no cross-package SSRF coupling" decision (`crypto-kms/ssrf-parity.test.mjs`). The core copy is kept honest by a core-vs-`auth-jwt` parity test instead; the drift is guarded, not yet eliminated.
  - Risk IDs renumbered **P1-SEC-026/027 → P1-SEC-027/028** (the proposed P1-SEC-026 collided with the existing 0.9 OIDC-broker risk).
- Date: 2026-06-11
- Target version: 1.1.0 (after 1.0.0)
- Type: capability **enforcement** for the plugin sandbox (closes the 1.0 honest residual)

## 1. Release Goal

1.1 closes the headline **honest residual** of the 1.0 plugin sandbox: 1.0 was explicit that `node:worker_threads` is **memory/crash isolation only, not a capability sandbox** — a malicious *signed* plugin could still use `fs`/`net` and exfiltrate the credential it receives. 1.1 adds a **stronger, opt-in `process-isolated` runtime** that runs a signed `authProvider` plugin in a **child process under the Node permission model (`--permission`)**, with **network containment that fail-closed requires `--allow-net`**, **all stdio ignored** (no stdout/stderr/fd leak channel), and the plugin loaded **from a `data:` URL with no filesystem grant at all** — so a malicious signed plugin **cannot read the host filesystem, spawn, reach the network, or write to any host-visible sink**, and therefore **cannot exfiltrate the credential**.

The adversarial review of Draft 0.1 (empirically, on Node 26) reshaped this design — those corrections are baked in below:

- **A "delete `node:net`/fetch" harness is NOT containment.** `process.binding('tcp_wrap')` opens a live socket and `import('node:net')` re-resolves a fresh builtin regardless of cache deletion. So network containment **must** be the kernel-enforced `--allow-net` denial, not a JS harness. On a Node without `--allow-net` (Node 22 LTS has none), `process-isolated` **fails closed** rather than pretending to contain.
- **A child process adds stdout/stderr/inherited-fd write channels** that `--allow-net` does not gate. These are closed explicitly (stdio ignored + a dedicated IPC channel), or the credential leaks via a log.
- **`--allow-fs-read` on a temp dir invites TOCTOU + a macOS realpath/symlink failure + a hidden bundling requirement.** Loading the verified bytes from a **`data:` URL** (as the 1.0 worker already does) needs **zero fs grant**, removes the whole TOCTOU/symlink surface, and structurally enforces a self-contained single-file plugin.

**Scope decisions (2026-06-11, maintainer-confirmed; the network/mode/credential/scope choices below are the four recommended answers, refined by the review):**

1. **Isolation:** `process-isolated` = a child `node` process under `--permission`, granting **nothing by default** (no fs, no child-process, no worker, no addons, no wasi), loading the plugin from a `data:` URL, with `stdio: ['ignore','ignore','ignore','ipc']` and a scrubbed `env`.
2. **Network = fail-closed `--allow-net`.** Network containment is the permission model's `--allow-net` denial, **feature-detected and fail-closed**: if the running Node cannot prove `--allow-net` enforcement, `process-isolated` **refuses to construct** (the default `netEnforcement: "require-permission"`). A best-effort non-containing fallback exists only behind an explicit `allow-harness` opt-in with a loud warning that **it does not contain a malicious plugin**.
3. **Credential handling:** for a **standard JWT/JWKS** credential the **host** runs the audited `createJwtVerifier` (reusing the satellite path) and the plugin is **not needed**; the `process-isolated` plugin is for **custom/opaque credentials** a plugin must parse — there the plugin sees the raw credential but is contained by **net + stdio + fs denial** (it cannot exfiltrate). Any key material a custom plugin needs is **host-fetched and injected** (no plugin-chosen URLs → no plugin-driven SSRF).
4. **Mode + scope:** `process-isolated` is a **new, stronger, opt-in** runtime *alongside* the unchanged 1.0 `worker-isolated`; 1.1 is **focused** on this capability-enforcement runtime. Classifier/crypto plugins, a live CRL, and a registry stay in later minors.

Core stays **zero runtime dependency** (`node:child_process` + `--permission` + `node:crypto`/`node:dns`). 1.1 is additive and opt-in; the only core change beyond the new module is **promoting the SSRF `isBlockedAddress` guard into a core node:-only helper** (§2.3) so the host-mediated fetch can use it (core cannot import from a satellite).

## 2. Scope

### 2.1 The `process-isolated` authProvider runtime (kernel-enforced capabilities, no fs, no stdio)

A new manifest `runtime: "process-isolated"` (for `kind: "authProvider"`, alongside `worker-isolated`). `createProcessIsolatedAuthProvider(options)` returns a host-side `authProvider` (frozen contract) that proxies `authenticate()` into a child `node` process.

- **Load gate first (the PR2 gate, fail-closed, audited):** `verifySignedPlugin` (Ed25519 over `entrySha256` + kind/capabilities/window, trust-anchor-only resolution, pin/version-floor/revocation) over the entry bytes held **in memory**.
- **Load via `data:` URL — no fs grant, no TOCTOU.** The child imports the verified bytes as a `data:text/javascript;base64,…` URL (the mechanism the 1.0 worker already uses). The child is spawned with **no `--allow-fs-read`** at all → it cannot read the host filesystem. This removes the temp-dir / realpath / symlink / TOCTOU surface entirely, and structurally requires a **self-contained single-file plugin** (no runtime `import`/`require` of host files); the load gate additionally rejects an entry whose source statically references a non-`data:` specifier.
- **Spawn under `--permission` granting only the allowlisted capabilities:** `process.execPath` + `--permission` with **no** `--allow-fs-read`/`--allow-fs-write`/`--allow-child-process`/`--allow-worker`/`--allow-addons`/`--allow-wasi`. `env` is **scrubbed** to a minimal fixed set (no inherited host secrets — `--permission` does not protect inherited env; env-scrubbing does). `--disable-proto=delete`.
- **stdio fully closed (a new, load-bearing control the review surfaced):** `stdio: ['ignore','ignore','ignore','ipc']` — **no stdout, no stderr, no extra inheritable fd**; the only channel is the dedicated IPC. The host **never** forwards, logs, or audits child stdout/stderr (a plugin writing the credential to stderr would otherwise leak it into operator logs). No `sendHandle`/fd passing.
- **JSON-string-only IPC (no structured clone, no fd passing).** `child_process` IPC supports advanced (structured-clone) serialization + handle passing, which would reopen the object/proto/transferable smuggling the 1.0 sanitizer was built to stop. The runtime sends/receives **only JSON strings** over the IPC (`serialization: "json"`), with the correlation-id + null-proto allowlist sanitizer + host-side `buildExternalIdentity` exactly as the 1.0 worker path.
- **Single-occupancy + the fail-closed matrix** (timeout → kill, `maxPendingCalls`, `maxMessageBytes`, kill-switch) carry over, with the process-lifecycle additions in §2.4.
- **Conformance at load** runs `assertAuthProviderConformance` against the sandboxed child (randomized vectors).

### 2.2 Network containment = fail-closed `--allow-net` (the harness is not containment)

- **`--allow-net` is the only real network control.** For a `process-isolated` plugin that does not need network, the child is spawned **without** `--allow-net`; on a Node that enforces it, `net.connect`/`fetch`/`dns` → `ERR_ACCESS_DENIED` (kernel-enforced). This is what actually prevents credential exfiltration.
- **Feature-detected, fail-closed, no version parsing.** At construction the runtime detects `--allow-net` support via `process.allowedNodeEnvironmentFlags.has('--allow-net')`, **confirmed once by a spawn-probe** (`node --permission --allow-net -e 0` → exit 0 = supported, exit 9 = not), cached for the runtime lifetime. The default **`netEnforcement: "require-permission"`**: if support is not proven, `createRuntime`/`normalizeConfig` **throws** (refuses to start) rather than silently degrading. So the credential-containment guarantee requires a `--allow-net` Node (Node ≥ the version that ships it); Node 22 LTS without it → fail closed.
- **The harness is best-effort-only and labeled as such.** A portable `allow-harness` opt-in may exist for *naive/accidental* egress, but the design states plainly — in the doc, the audit (`netEnforcement: "harness"` + a startup **warning**), and the threat model — that **it does NOT contain a malicious signed plugin** (`process.binding('tcp_wrap')` and a fresh `import('node:net')` both reach the network). It must additionally stub `process.binding`/`internalBinding`, but even then is not robust. High-assurance operators use `require-permission` (the default).

### 2.3 Credential handling — host-side JWT, host-mediated key material, the SSRF guard in core

- **Standard JWT/JWKS: the host verifies; no plugin sees the raw credential.** For the common JWT case, the **host** runs the audited `createJwtVerifier` (the satellite path) and a `process-isolated` plugin is **redundant** — use the host verifier directly (`auth.provider: "external"`/the satellite). 1.1 does not route a raw JWT through a child.
- **Custom/opaque credentials: the plugin sees the raw credential, contained by egress denial.** The `process-isolated` plugin exists for non-standard credentials a plugin must parse. It receives the raw credential over the IPC (it must, to validate it), but with **net + stdio + fs all denied** it **cannot exfiltrate** it. It returns raw claims; the host sanitizes + builds the keyed-HMAC identity (the crypto key never crosses).
- **Host-mediated key material (no plugin-driven SSRF).** Any key material a custom plugin needs (e.g. a JWKS-like document) is fetched by the **host** from an **operator-declared** URL — never a plugin-chosen one — through an **SSRF-hardened guarded fetch**, and injected over the IPC. The kid-driven refetch is **rate-limited/cooldown-bounded** (as the bearer satellite already does) so an attacker's credential cannot pump the host's outbound requests.
- **The SSRF guard moves into core.** `isBlockedAddress` + the guarded-fetch pattern (post-DNS re-check, HTTPS-only, bounded body, fetch timeout, `redirect:"error"`) live today only in the `haechi-auth-jwt` satellite, which core cannot import. 1.1 **promotes a node:-only `isBlockedAddress`/`guardedFetch` into a core module** (core stays zero-dependency); the satellites (`auth-jwt`, `auth-oidc`, and the `crypto-kms` Vault copy) and the host-fetch all import the one core helper, ending the drift. The known DNS-rebinding window (resolve-then-connect) is documented as a residual; the single-origin/issuer coupling is relaxed for the operator-declared host-JWKS case.

### 2.4 Process lifecycle (anti-DoS) — circuit breaker + warm child

A fresh `node --permission` spawn per call is ~tens of ms; a timing-out plugin could turn every auth attempt into a cold spawn (amplification DoS). So:

- A **warmed, long-lived child** reused across calls (single-occupancy serialization preserved), spawned once and kept ready.
- On a timeout/crash, respawn is governed by a **circuit breaker**: N kills within T seconds **trips to permanent fail-closed deny** (`plugin.worker.terminated{cause:"respawn-storm"}`, operator reset required) with **exponential backoff** between respawns — so a flapping plugin cannot become a spawn storm.
- `maxPendingCalls`/`maxMessageBytes` and the kill-switch (`plugins.enabled:false`) apply.

### 2.5 Config + audit (host-computed fields only)

- `auth.provider:"plugin"` gains `plugin.isolation: "worker" | "process"` and `plugin.netEnforcement: "require-permission" | "allow-harness"` (default `"require-permission"`). `normalizeConfig` validates fail-closed: `process` requires the `process-isolated` manifest + the capability allowlist; `require-permission` on a Node without `--allow-net` **throws**; the host-fetch URL (when a custom plugin needs key material) must be operator-declared. The `worker`-vs-`process` default stays `worker` for 1.0 back-compat **but the docs steer new high-assurance operators to `process` + `require-permission`**, and the chosen mode is recorded in the audit.
- **Audit fields are host-computed/enum-only (never child-supplied).** The lifecycle events gain additive `isolation`, `grants` (the **host-computed** granted permission set, not echoed plugin input), and `netEnforcement` — all fixed-enum/host values. Child crash/permission-denial diagnostics map to a **fixed reason enum** (extending `PLUGIN_LOAD_REASONS`), never `error.message`/child output (the core audit sanitizer filters by key *name*, not value, so a free-text field could write a credential into the hash chain — every new field is allowlist/enum). These are on `plugin.*` lifecycle events, **outside** the frozen core protect-event schema, so the 1.0 `api-contract.test.mjs` freeze guard is unaffected (the doc states *why*, so a future maintainer doesn't mistakenly freeze lifecycle events).

### 2.6 The honest model — what 1.1 closes and what it does not

For **`process-isolated` + `require-permission` on a `--allow-net` Node**, a malicious signed plugin is contained:

- **fs / exec / worker / addons:** kernel-**enforced** denied (`--permission`, no grants); the plugin loads from a `data:` URL with no fs at all.
- **network:** kernel-**enforced** denied (`--allow-net` absent) → **no credential exfiltration over the network**.
- **stdio / fd:** **closed** (`ignore` + dedicated IPC, no inheritable fd) → no log/stderr exfil.
- **env secrets:** scrubbed.

**Residual surface (do NOT over-trust beyond this):** (a) a Node **without `--allow-net`** gets **no network containment** — `process-isolated` fails closed there unless the operator explicitly accepts the non-containing `allow-harness`; (b) a plugin that legitimately needs **`networkEgress:true`** is not contained; (c) the host-fetch SSRF guard has a **DNS-rebinding** window; (d) the **credential + injected key material live in child memory** — core-dump/swap exposure is out of scope; (e) `--permission` is a Node runtime control, not an OS sandbox — a Node/V8 escape would defeat it. The `worker-isolated` (1.0) mode is **unchanged** — its trust-only residual stands.

## 3. Explicit non-scope (later minors)
- Classifier/filter and crypto plugin loading (authProvider only).
- A live revocation feed / CRL; a plugin registry.
- Hardening the `allow-harness` fallback to real containment (it can't be, on Node without `--allow-net` — the answer is `require-permission`).
- OS-level sandboxing (seccomp/namespaces/sandbox-exec) beyond the Node permission model.
- Replacing `worker-isolated`.

## 4. Backward compatibility
Additive and opt-in. `worker-isolated`, injection, every provider contract, and the frozen 1.0 API/audit/config schemas are unchanged. `process-isolated` is a new manifest runtime + new `plugin.isolation`/`plugin.netEnforcement` config (defaults preserve 1.0 behavior). The `plugin.*` lifecycle audit events gain additive host-computed fields (outside the frozen protect-event schema — the contract test is unaffected). Promoting `isBlockedAddress` into a core node:-only module is additive (the satellites re-import it; core stays zero runtime dependency). Per strict 1.0 semver, 1.1 is a **minor**.

## 5. 1.1 relationship
1.1 strengthens the plugin sandbox from **trust-based** (1.0 worker: trust the signer) to **capability-enforced** (1.1 process: the OS/runtime bounds the signed code) for the new opt-in mode, closing the most-cited 1.0 residual *honestly* — including the parts the first draft got wrong (the harness is not containment; stdio is a leak channel; fail-closed feature detection). It keeps the zero-dependency, fail-closed core promise.

## 6. Threat-model & risk-register deltas

| Surface (1.1) | Control | Residual |
|---|---|---|
| Malicious signed plugin abusing host fs/exec/worker/addons | `--permission` child, **zero grants**, `data:`-URL load (no fs) | none on a `--permission` Node; a V8/Node escape defeats any runtime control |
| Credential exfil over the network | `--allow-net` **denied**, **fail-closed feature detection** (`require-permission` → throw if unsupported) | a Node without `--allow-net` → fail closed (or the explicit non-containing `allow-harness`); a `networkEgress:true` plugin |
| Credential exfil via **stdout/stderr/fd** | `stdio:['ignore','ignore','ignore','ipc']`, no inheritable fd, host never logs child output | none material |
| Object/proto/fd smuggling over `child_process` IPC | JSON-string-only IPC (`serialization:"json"`), null-proto allowlist sanitizer | none material |
| Plugin-driven SSRF / outbound pump | host-fetched **operator-declared** URLs only (core SSRF guard), kid-refetch cooldown | DNS-rebinding window on the guard |
| Audit plaintext leak via new fields | host-computed/enum-only fields, fixed reason enum, no child free-text | none material |
| Spawn-storm DoS | warm child + circuit breaker + backoff | a tripped breaker denies (fail-closed) until operator reset |

Risk IDs (final): **P1-SEC-027** (process-isolated capability **enforcement** — strengthens P1-SEC-024's worker residual: fs/exec/net/stdio now enforced), **P1-SEC-028** (host-mediated key material + the core SSRF guard). *(Renumbered from the proposed 026/027 — P1-SEC-026 is the existing 0.9 OIDC-broker risk.)* The 1.0 P1-SEC-024 row is annotated "enforced in 1.1 for `process-isolated` on a `--allow-net` Node." New §4 exclusions: network containment on `--allow-net`-less Node (fail-closed), `networkEgress:true` plugins, core-dump/swap, OS-level escape.

## 7. Test criteria (mapped to the PR breakdown)

### 7.1 PR1 — the `process-isolated` runtime (capability + stdio + data-URL + fail-closed net)
- An instrumented signed plugin in `process-isolated` mode is **denied** `fs.readFileSync('/etc/hosts')` (`ERR_ACCESS_DENIED`), cannot spawn a child/worker, and has **no fs grant** (loads from a `data:` URL).
- **Net red-team:** on a `--allow-net` Node, the plugin's `net.connect` / `fetch` / `dns` and a `process.binding('tcp_wrap')` socket all **fail** (kernel-denied); `createRuntime` with `require-permission` on a Node **without** `--allow-net` **throws at construction** (fail-closed) — not a silent harness downgrade.
- **stdio/fd red-team:** a plugin writing the credential to `stdout`/`stderr`/`console.error`/fd3 reaches **no host-visible sink** (stdio ignored; the host captures nothing).
- IPC is JSON-string-only (an attempt to pass a handle/structured-clone object is refused); the load gate + conformance + the fail-closed matrix (timeout→kill, sanitizer, single-occupancy, kill-switch) hold for the process mode; macOS-included cross-platform run.

### 7.2 PR2 — credential containment + host-mediated key material + the core SSRF guard
- A custom-credential plugin authenticates with the raw credential but, with net+stdio+fs denied, an instrumented exfil attempt (network AND stderr AND fd) reaches **no sink** (assert the credential never leaves).
- The host-mediated fetch uses the **promoted core** `isBlockedAddress` (a `jwksUri` resolving to a private/metadata range is refused; the plugin never names a URL); the kid-refetch cooldown bounds the outbound rate; the satellites still pass their suites importing the core guard.

### 7.3 PR3 — feature detection + lifecycle + audit + the 1.1.0 release cut
- `--allow-net` detection via `process.allowedNodeEnvironmentFlags` + the spawn-probe is correct on the dev Node and fail-closed when unsupported; `netEnforcement` audited; the spawn circuit-breaker trips on a respawn storm (and audits it); `normalizeConfig` `plugin.isolation`/`netEnforcement` fail-closed tests.
- Lifecycle audit additive fields are host-computed/enum-only (a plugin cannot smuggle a value into them); the 1.0 `api-contract.test.mjs` still passes (additive, outside the frozen protect-event schema). Threat-model/risk-register deltas (P1-SEC-026/027), wiki, README; bump core to **1.1.0**; attested publish.

## 8. Suggested PR breakdown (stacked)
1. **`process-isolated` runtime** — `createProcessIsolatedAuthProvider`: `data:`-URL load (no fs), `--permission` zero-grant spawn, `stdio:['ignore','ignore','ignore','ipc']` + scrubbed env, JSON-string IPC, the data-minimized wire + host identity, the fail-closed + stdio/net red-team tests. → §7.1
2. **Credential containment + core SSRF guard** — promote `isBlockedAddress`/`guardedFetch` into a core node:-only module (satellites re-import it); host-mediated operator-declared key fetch + IPC injection + kid cooldown; the exfil-blocked + no-SSRF tests. → §7.2
3. **Feature detection + lifecycle + audit + 1.1.0 cut** — `--allow-net` detect + `netEnforcement` (fail-closed `require-permission` default), warm child + circuit breaker, host-computed audit fields; `plugin.isolation`/`netEnforcement` config; docs EN/KO (this doc, threat-model + risk-register P1-SEC-026/027, the honest-model update), wiki, README; core → 1.1.0, attested publish. → §7.3
