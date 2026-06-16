# 2026-06-16 Full Code Review Risk Register

Status: open remediation register  
Scope: `main` at `a47a6a79c380db412b6a464a2798b7df61f3b68d`  
Review date: 2026-06-16  
Source: full repository code review with focused security, protocol, packaging, and regression-test passes

This register captures risks discovered after the 0.3.2 and 1.3.x hardening work. It is intentionally separate from the historical release-gate register so future remediation can update each item without rewriting the earlier release record.

## Release Decision

Until the P0/P1 items below are fixed or explicitly accepted with a documented owner decision, new release tags and npm publishes should be blocked.

Public source availability can continue because the repository is already public and these findings are tracked openly. The client-credential forwarding risk (P0-CR-001) is now Resolved — the proxy applies a default-drop upstream header allowlist and never forwards the gateway `Authorization`/`Cookie`/`Proxy-Authorization` to the model upstream. The remaining open items below (P1-CR-002, P1-CR-005, and the P2s) still gate new release tags / npm publishes.

## Severity Policy

- `P0`: direct credential/data leak across a trust boundary, or a bypass that defeats the core security promise.
- `P1`: SSRF, protection bypass, denial-of-service, or protocol behavior that can break protected deployments.
- `P2`: operational, packaging, correctness, or regression-test gaps that should be resolved before broad adoption.

## Summary

| ID | Severity | Area | Risk | Status | Release impact |
| --- | --- | --- | --- | --- | --- |
| P0-CR-001 | P0 | Proxy headers | Client `Authorization`, `Cookie`, proxy-auth, and similar ambient credentials can be forwarded to the model upstream. | Resolved | Was blocking release |
| P1-CR-002 | P1 | SSRF guard | Hex-form IPv4-mapped IPv6 addresses such as `::ffff:7f00:1` are not classified as private loopback. | Open | Blocks release |
| P1-CR-003 | P1 | Proxy responses | Auto-decompressed upstream bodies can be returned with original compressed `content-encoding` / `content-length` headers. | Resolved | Was blocking release |
| P1-CR-004 | P1 | Streaming | `streaming.requestMode: "pass-through"` buffers the full upstream body and has no response-size cap. | Resolved | Was blocking release |
| P1-CR-005 | P1 | Streaming inspection | Non-JSON SSE/NDJSON frames are passed raw, so plain-text PII can bypass protection. | Open | Blocks release |
| P2-CR-006 | P2 | MCP wrap | Child process `stderr` is inherited and unfiltered. | Open | Requires remediation or explicit boundary documentation |
| P2-CR-007 | P2 | Key custody | `initLocalKeyFile()` reports success for existing files without validating key-file shape. | Open | Should fix before next publish |
| P2-CR-008 | P2 | Satellite packaging | Satellite packaging checks do not validate `manifest.bin` targets. | Open | Should fix before next publish |
| P2-CR-009 | P2 | Auth tests | `authProvider.authenticate()` throw path lacks a focused regression test. | Open | Test gap |
| P2-CR-010 | P2 | Plugin sandbox tests | Process-isolated quota and oversize branches lack parity with worker sandbox tests. | Open | Test gap |
| P2-CR-011 | P2 | Audit tests | Middle-record audit-chain tamper paths lack focused regression coverage. | Open | Test gap |
| P2-CR-012 | P2 | Vault tests | KMS vault IPv6 loopback carve-out has only IPv4 coverage. | Open | Test gap |
| P2-CR-013 | P2 | SSE correctness | Multi-line SSE `data:` fields are joined without the spec-required newline. | Open | Correctness gap |

## Detailed Findings

### P0-CR-001: Proxy Forwards Client Credentials Upstream

Status: Resolved (2026-06-16, toward 1.3.1)  
Affected code: `packages/proxy/index.mjs` `forward()` and `filteredHeaders()`  
Evidence:

- `forward()` sends `filteredHeaders(request.headers)` into upstream `fetch()`.
- `filteredHeaders()` currently drops only `host` and `content-length`, then rewrites JSON `content-type`.
- A local upstream repro received the same Haechi bearer token that the client used for gateway authentication.

Impact:

Client credentials cross from the local gateway trust boundary into the model provider boundary. This can leak Haechi bearer tokens, cookies, `Proxy-Authorization`, browser-origin headers, or other ambient client secrets. It also makes it hard to reason about future auth modules because client identity and upstream provider credentials are not separated.

Required remediation:

- Replace the current header pass-through with an explicit upstream header allowlist.
- Separate gateway-client auth from upstream-provider auth.
- Preserve provider-required headers only through explicit adapter or config rules, for example Anthropic/Gemini API-key headers when intentionally configured as upstream credentials.
- Drop hop-by-hop, cookie, proxy-auth, and gateway-client authorization headers by default.

Minimum verification:

- Regression test proving gateway bearer tokens are not visible to a local upstream.
- Regression test for intentionally configured upstream credentials.
- README and release-process wording updated so users do not assume client auth is forwarded safely.

Resolution evidence:

- `filteredHeaders()` (`packages/proxy/index.mjs`) is now a DEFAULT-DROP allowlist: a `FORWARD_HEADER_ALLOWLIST` (provider/adapter headers `x-api-key`, `anthropic-version`, `anthropic-beta`, `x-goog-api-key`, `openai-organization`, `openai-beta`, `accept`, `accept-language`, `user-agent`; `content-type` rewritten to `application/json`), an always-drop `FORWARD_HEADER_DENYLIST` (`host`, `content-length`, `cookie`, `set-cookie`, `proxy-authorization`, and hop-by-hop `connection`/`keep-alive`/`te`/`trailer`/`transfer-encoding`/`upgrade`), and a conditional `authorization` rule.
- `createHaechiProxy` derives a `forwardPolicy` once and threads it through every `forward()` callsite (protected path, streaming pass-through, inspected stream). `gatewayConsumedAuthorization` is `auth.provider !== "none"`: when the gateway authenticated the client the request `Authorization` (the gateway credential) is DROPPED; with `auth.provider: none` it is FORWARDED (the upstream provider key, OpenAI-compatible pass-through pattern).
- Additive config escape hatch `target.forwardHeaders` (array of lowercase header names), validated fail-closed in `normalizeConfig` (`validateForwardHeaders`): non-array, non-lowercase, or always-dropped credential/hop-by-hop names throw at load; it can only widen, never re-enable a dropped header.
- Regression tests in `tests/proxy-header-allowlist.test.mjs`: a gateway bearer token (`auth.provider: bearer`) is NOT in the headers a stub upstream receives while provider headers ARE; cookie/proxy-authorization/hop-by-hop and unlisted headers are dropped; `auth.provider: none` forwards the client `Authorization`; `target.forwardHeaders` widens additively; the config validator is fail-closed. The existing `tests/proxy-auth.test.mjs` 401/profile/rate suites stay green.
- Docs: README.md(+ko) "Gateway auth vs upstream auth (header forwarding)" + config-table row; `threat-model.md`(+ko) "Gateway credential forwarded upstream" control row; `shared-responsibility.md`(+ko) §5 + matrix row; `configuration.md`(+ko) `target.forwardHeaders` + the fail-closed throws list.

Release decision: blocks any new release or npm publish until fixed or formally accepted. Resolved.

### P1-CR-002: SSRF Guard Misses Hex IPv4-Mapped IPv6

Status: Open  
Affected code: `packages/ssrf/index.mjs`, `satellites/auth-jwt/index.mjs`  
Evidence:

Manual classification check:

| Input | Current result | Expected |
| --- | --- | --- |
| `::ffff:127.0.0.1` | Private | Private |
| `::ffff:7f00:1` | Public | Private |
| `[::ffff:7f00:1]` | Public | Private |
| `::ffff:10.0.0.1` | Private | Private |
| `::ffff:a00:1` | Public | Private |

Impact:

Guarded fetch paths can misclassify private loopback or RFC1918 IPv4 targets when they are represented as hexadecimal IPv4-mapped IPv6. This affects core guarded fetch behavior and the auth-jwt JWKS/OIDC fetch guard. The KMS vault code appears to contain a more complete variant, so the current state also creates parity drift between security-sensitive URL guards.

Required remediation:

- Normalize IPv4-mapped IPv6 forms before private-range checks.
- Reuse one shared parser/checker across core SSRF, auth-jwt, and KMS vault paths.
- Add tests for dotted and hex mapped loopback/RFC1918/link-local forms, bracketed host syntax, and allowed public IPv6.

Release decision: blocks release until fixed.

### P1-CR-003: Decompressed Body Returned With Compressed Headers

Status: Resolved (2026-06-16, toward 1.3.1)  
Affected code: `packages/proxy/index.mjs` unprotected response paths  
Evidence:

- Node `fetch()` auto-decompresses gzip/br/deflate bodies.
- Unprotected and allow/pass-through response paths return the decoded body while preserving original upstream headers.
- A local gzip upstream repro caused downstream fetch to fail with `incorrect header check`.

Impact:

The proxy can emit protocol-inconsistent responses. Clients can fail, retry, or mis-handle protected responses. This also complicates any future response-protection decision because safe and unsafe paths differ in header sanitation.

Required remediation:

- Strip or recompute `content-encoding`, `content-length`, transfer, and compression metadata whenever the body has been read or transformed by Node.
- Centralize response-header sanitation so protected, unprotected, and allow paths share the same invariant.
- Add gzip/br response tests for protected and unprotected paths.

Resolution evidence:

- A single centralized `sanitizeResponseHeaders(upstreamResponse)` (`packages/proxy/index.mjs`, generalizing the former `streamingResponseHeaders`) strips `content-encoding`, `content-length`, `transfer-encoding`, and hop-by-hop headers (`connection`/`keep-alive`/`te`/`trailer`/`upgrade`/`proxy-authenticate`). It is applied on EVERY response path: streaming pass-through, the inspected-stream `writeHead`, the unprotected/forwarded path, the protected JSON path (`transformedJsonHeaders` now strips the full set), and the `failureMode: allow` path. A correct `content-length` is re-set only for a fully-buffered body.
- Regression tests in `tests/proxy-header-allowlist.test.mjs`: a gzip upstream response (Node fetch auto-decompresses) returns with no `content-encoding` and a downstream fetch reads the plain body on BOTH the pass-through and the unprotected/forwarded paths.

Release decision: blocks release until fixed. Resolved.

### P1-CR-004: Streaming Pass-Through Is Buffered And Unbounded

Status: Resolved (2026-06-16, toward 1.3.1)  
Affected code: `packages/proxy/index.mjs` streaming `pass-through` branch  
Evidence:

- The pass-through branch reads `await readUpstreamBody(upstreamResponse)` and then writes `response.end(rawBody)`.
- No response `maxBytes` limit is applied in that path.
- True SSE/NDJSON streaming is delayed until the upstream closes.

Impact:

The setting name promises pass-through streaming, but the implementation creates full-response buffering. A long-lived or malicious stream can hold memory and connection resources indefinitely.

Required remediation:

- Either implement true bounded streaming pass-through or rename/fail-closed the mode until implemented.
- Apply byte and duration limits to all raw upstream-body reads.
- Add tests for long-lived stream behavior, response-size overrun, and cancellation on client disconnect.

Resolution evidence:

- The pass-through branch now does TRUE bounded streaming (`pipeUpstreamBodyBounded` in `packages/proxy/index.mjs`): the upstream body is piped to the client response as it arrives, with a running byte count against `streamingPassThroughMaxBytes(config)` (reuses `responseProtection.maxBytes`). Exceeding the cap cancels the upstream reader and destroys the client response (fail-closed on size); downstream backpressure is respected via `response.write` + `drain`. The former `readUpstreamBody(...)` + `response.end(rawBody)` full-buffering is removed from this path.
- The unprotected/forwarded raw-body read in `maybeProtectResponse` now also passes the same byte cap to `readUpstreamBody({ maxBytes })` and fails closed (502 `haechi_response_too_large`) on `tooLarge`, so no raw upstream-body read lacks a cap.
- Regression tests in `tests/proxy-header-allowlist.test.mjs`: an oversize pass-through stream (no content-length, > 8× the cap) is bounded/aborted near the cap and never delivers the full stream; the unprotected/forwarded path returns 502 `response_body_too_large` on an oversize buffered body.

Release decision: blocks release until fixed or the mode is disabled by default and documented as unavailable. Resolved.

### P1-CR-005: Streaming Inspect Raw-Passes Non-JSON Frames

Status: Open  
Affected code: `packages/stream-filter/index.mjs`  
Evidence:

- SSE parser returns non-JSON `data:` frames with `ok: false`.
- Current inspect flow passes failed-parse frames through raw.
- A local repro with `data: minji.kim@example.com\n\n` produced `blocked: false` and leaked the email.

Impact:

When streaming inspection is enabled, plain-text SSE or NDJSON-like frames can bypass PII/secret protection. This weakens the value of streaming hardening because malformed, non-JSON, or provider-specific frames may carry sensitive text.

Required remediation:

- Treat parse-failed content frames as inspectable text, not automatic raw pass-through.
- Preserve protocol control frames such as `[DONE]` through an explicit allowlist.
- Add tests for plain-text SSE, partial JSON, malformed JSON with PII, and provider control messages.

Release decision: blocks release until fixed.

### P2-CR-006: MCP Wrap Inherits Child `stderr`

Status: Open  
Affected code: `packages/cli/bin/haechi.mjs` `mcpWrapCommand()`  
Evidence:

- Child MCP server is spawned with `stdio: ["pipe", "pipe", "inherit"]`.
- `stderr` is not filtered, audited, redacted, or tokenized.

Impact:

Sensitive values printed by an MCP server can bypass Haechi controls and appear in the parent terminal, editor logs, or process supervisor logs. This may be acceptable as an explicit local-process boundary, but it is currently not called out strongly enough.

Required remediation:

- Prefer piping child `stderr` through the same protection path, or provide an explicit `--stderr=inherit|filter|drop` mode with safe default.
- Document the boundary if inherit remains available.
- Add tests for stderr filtering or explicit default behavior.

Release decision: should be fixed or documented before the next publish.

### P2-CR-007: Existing Key File Not Validated During Init

Status: Open  
Affected code: `packages/crypto/index.mjs` `initLocalKeyFile()`  
Evidence:

- Existing key-file path returns success without validating that active/retired keys are parseable and usable.

Impact:

`haechi init` can report success for corrupted-but-parseable key material. Users discover the problem later when encryption, decryption, token vault, or bundle verification fails.

Required remediation:

- Validate existing key file shape and active key usability before returning success.
- Preserve the non-destructive behavior for existing valid keys.
- Add tests for corrupted JSON, missing active key, wrong key length, and valid retired-key migration.

Release decision: should be fixed before the next publish.

### P2-CR-008: Satellite Packaging Check Misses `manifest.bin`

Status: Open  
Affected code: `scripts/check-satellite-packaging.mjs`  
Evidence:

- Package checks validate exported files but do not prove that `manifest.bin` points to present executable files.

Impact:

A satellite package can pass the local packaging check while shipping a broken CLI entrypoint. This is a release quality risk, especially as auth/KMS/dashboard satellites expand.

Required remediation:

- Validate every `manifest.bin` value against the packed file list.
- Add negative fixture coverage for missing bin targets.

Release decision: should be fixed before the next publish.

### P2-CR-009: Auth Provider Throw Path Test Gap

Status: Open  
Affected code: `packages/proxy/index.mjs` auth handling, `tests/proxy-auth.test.mjs`  
Evidence:

- Runtime wraps `authProvider.authenticate()` errors as fail-closed `haechi_auth_provider_error`.
- Existing tests cover several auth outcomes but not provider exceptions.

Impact:

Future auth-provider changes can accidentally leak raw errors, fail open, or return inconsistent audit status without tests catching it.

Required remediation:

- Add a provider exception regression test.
- Assert fail-closed status, generic client response, and audit event shape.

Release decision: test gap, not a standalone release blocker after P0/P1 fixes.

### P2-CR-010: Process-Isolated Sandbox Quota Test Gap

Status: Open  
Affected code: `packages/plugin/process-sandbox.mjs`  
Evidence:

- Oversized result and over-capacity branches are not mirrored with the same focused coverage as worker sandbox tests.

Impact:

Process isolation is a security boundary for future plugin work. Missing parity tests increase the chance of regressions in denial-of-service controls.

Required remediation:

- Add isolated-process tests for result-size excess, queue capacity, timeout, and worker exit behavior.

Release decision: test gap.

### P2-CR-011: Audit Chain Middle-Tamper Test Gap

Status: Open  
Affected code: `packages/audit/index.mjs` `verifyAuditChain()`  
Evidence:

- Existing coverage does not focus on middle-record tampering branches.

Impact:

Audit integrity is a core claim. The chain-verification code is present, but branch-specific tests should prove it rejects middle-record tampering, missing previous hashes, and hash mismatches.

Required remediation:

- Add tests for middle-record content mutation, missing `prev`, wrong `prev`, and wrong `integrity.hash`.
- Keep the documented tail-truncation limitation explicit.

Release decision: test gap.

### P2-CR-012: KMS Vault IPv6 Loopback Test Gap

Status: Open  
Affected code: `satellites/crypto-kms/vault.mjs`  
Evidence:

- Localhost carve-out coverage currently proves IPv4 loopback behavior but not IPv6 loopback variants.

Impact:

The vault guard is security-sensitive and has slightly different URL parsing logic from the core SSRF guard. IPv6-specific tests are needed to prevent future divergence.

Required remediation:

- Add tests for `::1`, `[::1]`, dotted IPv4-mapped IPv6, and hex IPv4-mapped IPv6 forms according to the intended vault policy.

Release decision: test gap.

### P2-CR-013: SSE Multi-Line `data:` Join Semantics

Status: Open  
Affected code: `packages/stream-filter/index.mjs`  
Evidence:

- The SSE parser joins multiple `data:` lines with `join("")`.
- The SSE processing model joins multiple data lines with newline separators.

Impact:

Valid multi-line SSE events can be mutated before parsing or inspection. This can cause false negatives, false positives, or malformed forwarded events.

Required remediation:

- Join multi-line `data:` values with `\n`.
- Add tests for multi-line JSON and multi-line plain-text events.

Release decision: should be fixed with the streaming remediation group.

## Remediation Order

1. Fix `P0-CR-001` first because it is a direct credential-boundary leak.
2. Fix `P1-CR-002` before adding new URL-fetching surfaces such as auth-provider discovery or KMS integrations.
3. Fix `P1-CR-003` and `P1-CR-004` together because they share response-forwarding invariants.
4. Fix `P1-CR-005` and `P2-CR-013` together as the streaming-inspection group.
5. Resolve `P2-CR-006` before recommending MCP wrap for sensitive local tools.
6. Finish P2 key, packaging, and regression-test gaps before the next npm publish.

## Closure Rules

An item can move to `Resolved` only when all of the following are true:

- Code or documentation remediation is merged.
- A focused regression test or explicit non-test rationale is recorded.
- The release-gate register links the remediation evidence.
- Any accepted residual risk is moved into the threat model or shared-responsibility documentation with operator guidance.

## Traceability

This document is linked from:

- `docs/current/risk-register-release-gate.md`
- `docs/current/risk-register-release-gate.ko.md`

