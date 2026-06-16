# 2026-06-16 Code Review Risk Register — Round 2 (CR2)

Status: remediation complete and shipped in `haechi@1.3.2` (no P0/P1; CR2-001..008 Resolved; CR2-009 won't-fix, CR2-010 accepted; G10 Pass, 2026-06-16)  
Scope: `main` at `36af9fd1eef2b1e19b19b2e0344faab0a7a3e83d` (post-1.3.1)  
Review date: 2026-06-16  
Source: a second deep review after the 1.3.1 remediation cut, with per-finding adversarial verification against the current code

This is a **second round** kept separate from `code-review-risk-register-2026-06-16.md` (round 1, all Resolved + shipped in 1.3.1), which is a frozen resolution record cited by the threat model and code. Round 2 captures findings raised after 1.3.1 and re-verified against the current tree; a few of them extend or qualify round-1 claims, so they are cross-referenced rather than written back into the frozen record.

## Release Decision

The round-1 P0/P1 are all Resolved and shipped in `haechi@1.3.1`. Round 2 found **no P0 and no P1**: the two findings raised as P1 in the external review both verified down to **P2** (neither is a stored-plaintext leak or an auth/SSRF bypass). The confirmed P2s are an availability/resource leak on the proxy data path, an audit-hygiene gap that reflects caller-supplied input, and an unbounded plugin IPC reply. The three P2s and the P3 cluster (`CR2-001..008`) are now **Resolved and shipped in `haechi@1.3.2`** (2026-06-16, attested OIDC publish); `CR2-009` stays won't-fix (false positive) and `CR2-010` stays accepted (documented residual). **G10 is Pass.** Operators should upgrade from `1.3.1` to `1.3.2` to pick up the CR2 fixes.

## Severity Policy

- `P0`: direct credential/data leak across a trust boundary, or a bypass that defeats the core security promise.
- `P1`: SSRF, protection bypass, denial-of-service, or protocol behavior that can break protected deployments.
- `P2`: operational, correctness, availability, or hygiene gaps that should be resolved before broad adoption.
- `P3`: low-impact hardening, finite-bound robustness, or documentation accuracy.

## Verification note

Every finding below was traced against the current code by an independent reviewer (not taken on the reporter's word). Two reported P1s were downgraded to P2 after verification (no inflation); one reported finding was a **false positive** and one is an **already-documented accepted residual** — both are recorded here for the audit trail and require no code change.

## Summary

| ID | Severity | Area | Risk | Status |
| --- | --- | --- | --- | --- |
| CR2-001 | P2 | Proxy availability | Pass-through streaming never cancels the upstream reader on downstream client disconnect — `await once(response,"drain")` parks forever, leaking the upstream connection/task; an unauthenticated client can disconnect repeatedly to accumulate dangling upstream connections. | Resolved |
| CR2-002 | P2 | Audit hygiene | Token-vault reveal/purge failures write the raw caller-supplied `token` and `error.message` (which interpolates the token) into the audit event; `FORBIDDEN_KEYS` strips by key name only, so a secret passed where a `tok_` id is expected lands raw in the hash-chained log. Reflects caller input, not stored vault plaintext. | Resolved |
| CR2-003 | P2 | Plugin sandbox DoS | `maxMessageBytes` bounds only the host→plugin credential message; the plugin→host reply is received and `JSON.parse`d unbounded. The process-isolated child has no heap cap, so a hostile/buggy signed plugin can return an oversized reply → synchronous host parse stalls the event loop + memory spike. | Resolved |
| CR2-004 | P3 | Proxy headers | `sanitizeResponseHeaders` keeps body-coupled validators (`etag`/`content-md5`/`digest`/`last-modified`) when the body is transformed, so they become stale; no `cache-control: no-store` on a mutated response. | Resolved |
| CR2-005 | P3 | Proxy robustness | On a body over `maxBytes`, `readBody` rejects but does not stop reading/teardown the socket, so an upload is read-and-discarded until the (finite) Node `requestTimeout`. | Resolved |
| CR2-006 | P3 | MCP wrap | `mcp-wrap --stderr filter` protects per complete line, so a secret an adversarial child deliberately splits across a newline evades the anchored regex. Inherent to line-oriented filtering of a trusted local child's diagnostic output; a single-line secret IS caught and `--stderr drop` exists. Doc-only. | Resolved |
| CR2-007 | P3 | Docs | README says MCP wrap "stderr and exit codes pass through", but the default is now `--stderr filter` (round-1 P2-CR-006). | Resolved |
| CR2-008 | P3 | Docs | README's streaming "split match" claim is unscoped; cross-frame buffering applies to the JSON delta channel only, not arbitrary non-JSON frames. | Resolved |
| CR2-009 | — | Plugin sandbox | (Reported P2) `keyMaterial` is appended after the `maxMessageBytes` check on the base credential message. **FALSE POSITIVE:** `keyMaterial` is operator-controlled and hard-bounded by the fetcher's `maxBytes`; no attacker amplification. No fix required (optional cosmetic re-assert only). | Won't fix |
| CR2-010 | — | Streaming | (Reported P2) A secret split across two NON-JSON SSE/NDJSON frames is not caught (per-frame inspection). **ACCEPTED RESIDUAL — already documented** in round-1 P1-CR-005 resolution, `threat-model.md` exclusions, and an in-code comment. No change. | Accepted |

## Detailed Findings

### CR2-001: Upstream Reader Not Cancelled On Downstream Disconnect

Severity: P2 (the most urgent CR2 item)  
Status: Resolved (shipped in `haechi@1.3.2`, PR #96)  
Affected code: `packages/proxy/index.mjs` `pipeUpstreamBodyBounded` / `forward`  
Verified: in the pass-through streaming path there is no `close`/`aborted` listener on the client connection; `await once(response, "drain")` parks indefinitely after the client socket dies (neither `drain` nor `error` fires), so the async task and the upstream connection leak. Reachable by an **unauthenticated** client with no preconditions; repeated mid-stream disconnects accumulate dangling upstream connections against the proxy and its upstream LLM endpoint.

Resolution: pass a per-request `AbortController` into `forward()` (aborting the upstream fetch) and register a one-shot client `close`/`aborted` listener that cancels the upstream reader; race the `drain` wait against `close` so backpressure waits unpark on disconnect; cover the no-backpressure `reader.read()` parked case too. Regression test: disconnect mid-stream and assert prompt reader cancellation / upstream abort.

### CR2-002: Token-Vault Reveal/Purge Writes Raw Token + Error Text To Audit

Severity: P2 (downgraded from a reported P1 — it reflects caller-supplied input, not stored vault plaintext)  
Status: Resolved (shipped in `haechi@1.3.2`, PR #97)  
Affected code: `packages/token-vault/index.mjs` (reveal/purge throw + record), `packages/audit/index.mjs` (`FORBIDDEN_KEYS` / `sanitizeAudit`)  
Verified: reveal throws `Unknown token: ${token}` / `Token expired: ${token}` and the catch records `reason: error.message`; the raw `token` argument is also written verbatim on `reveal_failed`/`reveal_denied`/`purge`. `sanitizeAudit` filters by key name and `FORBIDDEN_KEYS` contains neither `reason` nor `token`, so both survive into the written, hash-chained record. In legitimate flows the `token` argument is a non-sensitive `tok_<type>_<hash>` id, so the leak only fires when a caller/operator passes a raw secret where a token id is expected — but it still contradicts the "no plaintext / keyed-HMAC only" wording in round-1 `P1-SEC-017` and `threat-model.md`.

Resolution: (1) generic error messages (no raw token interpolation); (2) stop writing the raw `token` verbatim — keyed-HMAC it (as `subjectHash`/`issuerHash` are) or validate the argument against the `tok_<type>_<hash>` shape and redact otherwise, before reveal/purge records; (3) replace free-text `reason: error.message` with an enum `reasonCode`; (4) regression test that a `reveal_failed`/`purge` event never contains a raw caller-supplied token in `reason`/`token`; reconcile the invariant wording in the docs.

### CR2-003: Plugin IPC Reply Not Size-Bounded; Process Child Has No Heap Cap

Severity: P2  
Status: Resolved (shipped in `haechi@1.3.2`, PR #98)  
Affected code: `packages/plugin/sandbox.mjs`, `packages/plugin/process-sandbox.mjs`, `packages/cli/runtime.mjs`  
Verified: `maxMessageBytes` is enforced only on the outbound host→plugin credential message; the inbound reply is received and `JSON.parse`d with no size check in both sandboxes. The worker has an implicit bound (a required `resourceLimits` heap cap OOMs a runaway worker first), but the process child sets no `--max-old-space-size`, so a hostile/buggy signed plugin can build a reply up to the child's default V8 heap and `process.send` it; the host's synchronous `JSON.parse` stalls the event loop (the per-call timeout cannot fire mid-parse). Requires a signed/semi-trusted-but-hostile plugin.

Resolution: bound the reply BEFORE parsing in both sandboxes (check byte length against `maxMessageBytes` or a dedicated `maxReplyBytes` in the worker/child `message` handler, drop oversized as a deny before `JSON.parse`); give the process child a heap cap via `--max-old-space-size` derived from a new `resourceLimits`/`processMaxOldGenerationSizeMb` knob. Regression test: a fixture plugin returning an oversized claims object → deny without unbounded host work. Update the 1.0/1.1 scope docs to state the bound applies in BOTH directions.

### CR2-004: Stale Body-Coupled Validator Headers On Transformed Responses

Severity: P3  
Status: Resolved (shipped in `haechi@1.3.2`, PR #96)  
Affected code: `packages/proxy/index.mjs` `sanitizeResponseHeaders` / `transformedJsonHeaders`  
Verified: only hop-by-hop headers are stripped; when `protectJson` mutates and re-serializes the body, upstream `etag`/`content-md5`/`digest`/`last-modified` survive unchanged and no `cache-control: no-store` is set. Real-world impact is small for the documented inference-upstream target set (POST responses, no strong validators, not cacheable by default per RFC 9111; `content-length` IS recomputed), but it is not recorded as an accepted residual.

Resolution: add `etag`/`content-md5`/`digest`/`last-modified` to the dropped set on every body-mutating path; set `cache-control: no-store` on a transformed response. Test: a mutated response no longer carries the upstream `ETag`.

### CR2-005: Over-Limit Request Body Not Drained/Torn Down

Severity: P3  
Status: Resolved (shipped in `haechi@1.3.2`, PR #96)  
Affected code: `packages/proxy/index.mjs` `readBody`  
Verified: on exceeding `maxBytes`, `readBody` sets a flag and rejects but does not `pause()`/`destroy()` the request, and the 413 response sends no `Connection: close`, so Node reads-and-discards the rest of the upload until the built-in `requestTimeout` (Node ≥22 default 300000 ms). The hold is finite; `maxInFlight: 0` (default) does not bound simultaneous held connections.

Resolution: on 413, `request.pause()`/`request.destroy()` (or `Connection: close` before the response) so the socket releases promptly. Lower priority: ship non-null default `requestTimeoutMs`/`headersTimeoutMs` and document that `maxInFlight: 0` leaves concurrency unbounded.

### CR2-006: mcp-wrap `--stderr filter` Cannot Catch A Newline-Split Secret

Severity: P3 (doc)  
Status: Resolved (shipped in `haechi@1.3.2`, PR #99)  
Affected code: `packages/cli/bin/haechi.mjs` `pipeFilteredStderr` / `protectStderrLine`  
Verified: `filter` splits child stderr on `\n` and protects each complete line with a fresh single-shot protector, so a secret an adversarial child deliberately emits split across a newline evades the anchored full-secret regex. Narrow: the child is the operator's trusted local MCP server, a single-line secret IS caught, and `--stderr drop` exists. This is an inherent property of line-oriented text filtering, not an exploitable bypass of the request/response protection path.

Resolution (doc): one sentence in `COMMAND_HELP` and this register noting `filter` protects per complete line and cannot catch a secret split across a newline; recommend `--stderr drop` for high-sensitivity tools. Optional later code hardening: route stderr through the push/flush sliding-buffer channel (`maxMatchBytes`) instead of per-line `protectText`.

### CR2-007: README mcp-wrap stderr Passthrough Is Stale

Severity: P3 (doc)  
Status: Resolved (shipped in `haechi@1.3.2`, PR #99)  
Affected code: `README.md`  
Verified: README says "stderr and exit codes pass through", but the default is now `--stderr filter` (round-1 P2-CR-006); raw passthrough is only the opt-in `inherit` mode. Exit codes do pass through, so only the stderr clause is stale; `COMMAND_HELP` is already accurate.

Resolution (doc): correct the README line to reflect the `filter` default (`inherit` for raw, `drop` to discard; `filter` transforms only under `policy.mode: enforce`); update the `README.ko.md` sibling.

### CR2-008: README Streaming Split-Match Claim Is Unscoped

Severity: P3 (doc)  
Status: Resolved (shipped in `haechi@1.3.2`, PR #99)  
Affected code: `README.md`  
Verified: the README claims PII split across frames is caught without scoping it to the JSON delta channel; non-JSON CONTENT frames get single-shot per-frame `protectText` (no cross-frame buffer). The claim overstates the guarantee relative to `threat-model.md` and the scope docs.

Resolution (doc): scope both README passages to the delta channel (delta-text PII split across frames up to `maxMatchBytes`; non-delta leaves and non-JSON frames inspected within-frame); update `README.ko.md`.

### CR2-009: keyMaterial After the maxMessageBytes Check — FALSE POSITIVE

Severity: — (reported P2; verified not a vulnerability)  
Status: Won't fix  
Affected code: `packages/plugin/process-sandbox.mjs`, `packages/cli/runtime.mjs`  
Verified: the structural observation (the combined message is not re-checked after `keyMaterial` is appended) is accurate, but it is not attacker-exploitable. `keyMaterial` is operator-controlled (fetched by the host from an operator-declared HTTPS URL, TTL-cached, independent of the attacker-influenced credential) and hard-bounded by the guarded fetcher's `maxBytes` (default 1 MiB); the credential stays bounded by the base check. The combined wire is bounded by two operator-set constants with no attacker amplification; "`maxBytes` arbitrarily large" is operator self-misconfiguration. Optional cosmetic defense-in-depth only (re-assert the combined size); no security fix required.

### CR2-010: Non-JSON Cross-Frame Split — ACCEPTED RESIDUAL (documented)

Severity: — (reported P2; an already-documented residual)  
Status: Accepted  
Affected code: `packages/core/index.mjs` / `packages/stream-filter/index.mjs`  
Verified: real in 1.3.1 (non-JSON CONTENT frames get per-frame `protectText` with no cross-frame buffer), but it is explicitly documented as out-of-scope in round-1 `P1-CR-005` resolution, the `threat-model.md` exclusions, and an in-code comment. The JSON delta channel DOES cross-frame buffer up to `maxMatchBytes`. No code change required; at most a documentation-polish sibling exclusion bullet (folded into CR2-008's README scoping).

## Remediation Order

1. `CR2-001` first — the only finding reachable by an unauthenticated client with no preconditions (availability).
2. `CR2-002` and `CR2-003` in parallel — file-disjoint (token-vault+audit vs plugin sandbox).
3. `CR2-004` + `CR2-005` together (both `proxy/index.mjs`; land after / rebased on CR2-001).
4. `CR2-006` + `CR2-007` + `CR2-008` — documentation/help-text cluster, anytime.
5. `CR2-009` / `CR2-010` need no code change (recorded for the audit trail).

## Closure Rules

An item moves to `Resolved` only when the code/doc remediation is merged, a focused regression test or explicit non-test rationale is recorded, and the release-gate register (`G10`) links the evidence. The 1.3.2 cut flips the resolved items and `G10` together.

## Traceability

Linked from `docs/current/risk-register-release-gate.md` (§5.8 + `G10`) and `docs/current/risk-register-release-gate.ko.md`.
