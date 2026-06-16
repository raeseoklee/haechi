# 2026-06-16 Full Code Review Risk Register

Status: remediation complete and shipped in `haechi@1.3.1` (all 13 findings Resolved; G9 Pass, 2026-06-16)  
Scope: `main` at `a47a6a79c380db412b6a464a2798b7df61f3b68d`  
Review date: 2026-06-16  
Source: full repository code review with focused security, protocol, packaging, and regression-test passes

This register captures risks discovered after the 0.3.2 and 1.3.x hardening work. It is intentionally separate from the historical release-gate register so future remediation can update each item without rewriting the earlier release record.

## Release Decision

Until the P0/P1 items below are fixed or explicitly accepted with a documented owner decision, new release tags and npm publishes should be blocked.

Public source availability can continue because the repository is already public and these findings are tracked openly. The client-credential forwarding risk (P0-CR-001) is now Resolved — the proxy applies a default-drop upstream header allowlist and never forwards the gateway `Authorization`/`Cookie`/`Proxy-Authorization` to the model upstream. The hex IPv4-mapped IPv6 SSRF gap (P1-CR-002) and its vault test gap (P2-CR-012) are also now Resolved — every `isBlockedAddress` copy normalizes an IPv4-mapped IPv6 address to its embedded IPv4 before the private-range check. The streaming-inspection bypass (P1-CR-005) and the SSE multi-line `data:` correctness gap (P2-CR-013) are also now Resolved — a parse-failed non-JSON CONTENT frame is inspected as text and multi-line `data:` lines are joined with the spec-required newline. The final six P2s (P2-CR-006 mcp-wrap stderr, P2-CR-007 init key-file validation, P2-CR-008 satellite `manifest.bin` check, P2-CR-009 auth-throw test, P2-CR-010 process-sandbox quota tests, P2-CR-011 audit middle-tamper tests) are now Resolved as well. **All 13 findings are Resolved and shipped in `haechi@1.3.1`** (2026-06-16, attested OIDC publish; core bumped 1.3.0 → 1.3.1, a remediation-only patch). The **G9** release-block gate is **Pass**. Operators should upgrade from `1.3.0` to `1.3.1` to pick up the fixes.

## Severity Policy

- `P0`: direct credential/data leak across a trust boundary, or a bypass that defeats the core security promise.
- `P1`: SSRF, protection bypass, denial-of-service, or protocol behavior that can break protected deployments.
- `P2`: operational, packaging, correctness, or regression-test gaps that should be resolved before broad adoption.

## Summary

| ID | Severity | Area | Risk | Status | Release impact |
| --- | --- | --- | --- | --- | --- |
| P0-CR-001 | P0 | Proxy headers | Client `Authorization`, `Cookie`, proxy-auth, and similar ambient credentials can be forwarded to the model upstream. | Resolved | Was blocking release |
| P1-CR-002 | P1 | SSRF guard | Hex-form IPv4-mapped IPv6 addresses such as `::ffff:7f00:1` are not classified as private loopback. | Resolved | Was blocking release |
| P1-CR-003 | P1 | Proxy responses | Auto-decompressed upstream bodies can be returned with original compressed `content-encoding` / `content-length` headers. | Resolved | Was blocking release |
| P1-CR-004 | P1 | Streaming | `streaming.requestMode: "pass-through"` buffers the full upstream body and has no response-size cap. | Resolved | Was blocking release |
| P1-CR-005 | P1 | Streaming inspection | Non-JSON SSE/NDJSON frames are passed raw, so plain-text PII can bypass protection. | Resolved | Was blocking release |
| P2-CR-006 | P2 | MCP wrap | Child process `stderr` is inherited and unfiltered. | Resolved | Was a hardening gap |
| P2-CR-007 | P2 | Key custody | `initLocalKeyFile()` reports success for existing files without validating key-file shape. | Resolved | Was a hardening gap |
| P2-CR-008 | P2 | Satellite packaging | Satellite packaging checks do not validate `manifest.bin` targets. | Resolved | Was a hardening gap |
| P2-CR-009 | P2 | Auth tests | `authProvider.authenticate()` throw path lacks a focused regression test. | Resolved | Was a test gap |
| P2-CR-010 | P2 | Plugin sandbox tests | Process-isolated quota and oversize branches lack parity with worker sandbox tests. | Resolved | Was a test gap |
| P2-CR-011 | P2 | Audit tests | Middle-record audit-chain tamper paths lack focused regression coverage. | Resolved | Was a test gap |
| P2-CR-012 | P2 | Vault tests | KMS vault IPv6 loopback carve-out has only IPv4 coverage. | Resolved | Was a test gap |
| P2-CR-013 | P2 | SSE correctness | Multi-line SSE `data:` fields are joined without the spec-required newline. | Resolved | Was a correctness gap |

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

Status: Resolved (2026-06-16, toward 1.3.1)  
Affected code: `packages/ssrf/index.mjs`, `satellites/auth-jwt/index.mjs` (and `satellites/crypto-kms/vault.mjs`, which had a related over-block)  
Evidence:

Manual classification check (after the fix — the formerly-misclassified rows are now correct):

| Input | Result | Expected |
| --- | --- | --- |
| `::ffff:127.0.0.1` | Private | Private |
| `::ffff:7f00:1` | Private | Private |
| `[::ffff:7f00:1]` | Private | Private |
| `::ffff:10.0.0.1` | Private | Private |
| `::ffff:a00:1` | Private | Private |
| `::ffff:8.8.8.8` / `::ffff:808:808` | Public | Public (not over-blocked) |

Impact (was):

Guarded fetch paths could misclassify private loopback or RFC1918 IPv4 targets when they were represented as hexadecimal IPv4-mapped IPv6. This affected core guarded fetch behavior and the auth-jwt JWKS/OIDC fetch guard. The KMS vault copy had a related defect in the opposite direction: any `::ffff:` form it did not recognize fell through to a "blocked" first hextet, over-blocking a public mapped address such as `::ffff:808:808`.

Resolution:

- Each `isBlockedAddress` copy now parses an IPv4-mapped IPv6 address into its 16 octets and normalizes the embedded IPv4 (last 32 bits, recognized only when bytes 0..9 are zero and bytes 10..11 are `0xffff`) before the private/loopback/link-local/metadata check. This handles every textual form: dotted (`::ffff:127.0.0.1`), hex (`::ffff:7f00:1`), bracketed (`[::ffff:7f00:1]`), leading-zero (`::ffff:7f00:0001`), mixed `::` compression, and case-insensitive `ffff`. A genuinely public mapped address (`::ffff:8.8.8.8` == `::ffff:808:808`) classifies as its public v4 and stays allowed.
- The DELIBERATE 1.1 decoupling is preserved: no satellite imports `haechi/ssrf` (that would raise their `haechi` peer floor and republish them). The SAME normalization is applied to EACH independent copy and the agreement is locked by the parity tests, so the copies stay independent-but-consistent.

Closure evidence (new/extended tests):

- `tests/ssrf.test.mjs` — the canonical vector table gains hex/dotted/bracketed IPv4-mapped loopback, RFC1918, and metadata vectors plus an allowed public mapped pair, all also asserted equal to the auth-jwt copy (core-vs-auth-jwt parity).
- `satellites/auth-jwt/auth-jwt.test.mjs` — `createJwtAuthProvider` construction now rejects dotted AND hex IPv4-mapped IPv6 private/metadata hosts, and does NOT SSRF-block a public mapped host.
- `satellites/crypto-kms/vault.test.mjs` — the documented range table adds the hex mapped private/metadata forms and the public mapped allow cases.
- `satellites/crypto-kms/ssrf-parity.test.mjs` — a new "IPv4-mapped IPv6 (dotted + hex)" group pins auth-jwt ⇄ crypto-kms agreement; the parity test stays green.

Release decision: resolved; this finding no longer blocks release.

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

Status: Resolved (2026-06-16, toward 1.3.1)  
Affected code: `packages/stream-filter/index.mjs`, `packages/core/index.mjs`  
Evidence (was):

- SSE parser returned non-JSON `data:` frames with `ok: false`.
- The inspect flow passed failed-parse frames through raw (`if (!parsed.ok) { sink.write(frame.raw); return; }`).
- A local repro with `data: minji.kim@example.com\n\n` produced `blocked: false` and leaked the email.

Impact (was):

When streaming inspection was enabled, plain-text SSE or NDJSON-like frames could bypass PII/secret protection. This weakened the value of streaming hardening because malformed, non-JSON, or provider-specific frames may carry sensitive text.

Resolution:

- `parseFrame` (`packages/stream-filter/index.mjs`) now distinguishes a CONTROL frame from a non-JSON CONTENT frame. CONTROL is an explicit allowlist with no inspectable text: the SSE `[DONE]` sentinel, a comment-only frame (only `:`/field lines, no `data:`), and an empty/whitespace/keepalive frame. It returns `{ ok:false, control:true, text:null }` for those and `{ ok:false, control:false, text }` (the reconstructed `data:` payload) for a non-JSON CONTENT frame.
- `handleFrame`'s parse-failed branch passes CONTROL frames through raw (unchanged), but INSPECTS a non-JSON CONTENT frame as text: it calls a new `protector.protectText(text)` (single-shot detect → decide → tally → transform), re-emits `data: <protected text>` via `serializeTextFrame` (preserving `event:`/`id:`/`:` lines and re-emitting a multi-line payload as multiple `data:` lines), and fails the stream closed (`blocked = true`) on a block-action detection.
- `createStreamProtector` (`packages/core/index.mjs`) gains `protectText(text)`, which reuses the existing `transformSegment` logic. It is DISTINCT from the delta-channel `push`/`flush` cross-frame buffer — it never touches `pending` — so inspecting a non-JSON frame's text cannot corrupt the JSON delta sliding-buffer state. Per-frame text inspection closes the bypass; cross-frame buffering of arbitrary non-JSON frames is out of scope (the delta channel keeps its own buffer; noted in code).
- The response-direction marker skip and the audit tally are preserved because `protectText` runs the same `transformSegment` with the protector's response-direction `context`, so a tokenized round-trip (`[REDACTED:…]`, `[TOKEN:…]`) echoed by the model is not re-flagged. The JSON path (delta channel, `protectFrameExtras`, cross-frame sliding buffer, `event:`-line preservation) is unchanged.

Closure evidence:

- `tests/stream-filter.test.mjs` adds: a plain-text SSE `data: <email>` frame is redacted (not leaked); a plain-text frame with a `card: block` action BLOCKS the stream; malformed/partial JSON with PII is inspected as text; an NDJSON non-JSON content frame with PII is inspected; comment-only/keepalive/`event:` control frames pass untouched; a tokenized-round-trip marker is not re-flagged. The existing within-frame and cross-frame JSON delta tests, `[DONE]`/keepalive pass-through, and report-only tests stay green.
- `tests/proxy-streaming.test.mjs` adds an end-to-end repro: an upstream emitting `data: minji.kim@example.com\n\n` (plain text) is redacted to `[REDACTED:email]` through the proxy, `stream_inspected` is audited, and the audit chain verifies with no plaintext.
- Follow-up (adversarial verify caught a residual leak in the first cut): a **trim-mismatch** let a leading-whitespace `data:` line (` data: <pii>`) be parsed+redacted but then re-emitted VERBATIM by the serializers (which used a stricter `startsWith("data:")` on the untrimmed raw line), leaking the original — and the same class affected the JSON `serializeFrame`. Fixed by a single shared lenient matcher `SSE_DATA_LINE` / `sseDataPayload` used by `parseFrame` AND both serializers, so a `  data:`/`\tdata:` line is always recognized and replaced, never emitted verbatim. Also hardened `handleFrame` to route a bare PRIMITIVE JSON frame (e.g. `data: "<pii>"`) to text inspection instead of the object delta path (which would throw an uncaught `setByPath`-on-string-root TypeError). Regression tests added in `tests/stream-filter.test.mjs` (leading-space/tab `data:` plaintext, leading-space JSON non-delta field, bare-primitive JSON).

Release decision: blocks release until fixed. Resolved.

### P2-CR-006: MCP Wrap Inherits Child `stderr`

Status: Resolved (2026-06-16, toward 1.3.1)  
Affected code: `packages/cli/bin/haechi.mjs` `mcpWrapCommand()`  
Evidence:

- Child MCP server is spawned with `stdio: ["pipe", "pipe", "inherit"]`.
- `stderr` is not filtered, audited, redacted, or tokenized.

Impact:

Sensitive values printed by an MCP server can bypass Haechi controls and appear in the parent terminal, editor logs, or process supervisor logs. This may be acceptable as an explicit local-process boundary, but it is currently not called out strongly enough.

Resolution / closure evidence:

- `haechi mcp-wrap` gains an explicit `--stderr filter|drop|inherit` flag (default `filter`). `filter` pipes the child's stderr and runs each complete line through the same protection (`runtime.haechi.createStreamProtector().protectText`) before re-emitting to the parent's stderr — redact/mask detected secrets/PII in place, drop a line entirely on a block-action detection — with partial lines buffered across chunk boundaries (split on `\n`, trailing partial flushed on end) and re-emitted in source order. `drop` discards child stderr (consumed via `resume()` so the child never stalls); `inherit` keeps the prior raw passthrough as an explicit, documented opt-in local-process boundary; an unknown `--stderr` value throws a clear fail-closed error before any child is spawned. The stderr filter path records nothing to the audit sink (no plaintext reaches the audit log), and the stdin/stdout JSON-RPC wrap behavior is byte-identical. `COMMAND_HELP` documents the flag, including that `filter` follows the configured policy mode (dry-run/report-only detects but does not transform).
- `tests/mcp-wrap.test.mjs` adds four cases (filter redacts/masks/drops so the parent never sees a raw secret/PII/card/phone value; drop emits nothing; inherit passes raw; unknown value exits non-zero). Adversarial verify confirmed the default is now `filter` (was the vulnerable `inherit`), chunk-split secrets are reassembled and protected, and block-action lines are dropped not leaked.

Release decision: resolved.

### P2-CR-007: Existing Key File Not Validated During Init

Status: Resolved (2026-06-16, toward 1.3.1)  
Affected code: `packages/crypto/index.mjs` `initLocalKeyFile()`  
Evidence:

- Existing key-file path returns success without validating that active/retired keys are parseable and usable.

Impact:

`haechi init` can report success for corrupted-but-parseable key material. Users discover the problem later when encryption, decryption, token vault, or bundle verification fails.

Resolution / closure evidence:

- The provider's existing key-load/validation logic (JSON parse, per-key base64url + 32-byte check, active-key resolution) was extracted into a shared module-level `loadKeyFile(keyFile, { requireActive })` that the private `loadKeys()` now delegates to (preserving its historical `keys[0]` fallback). `initLocalKeyFile`'s existing-file non-force path now calls `loadKeyFile` with `requireActive: true` before returning, throwing a specific error per defect (corrupted JSON; "No active key found in local key file"; "AES-256-GCM local key must be 32 bytes" for an active or retired key). A valid existing file stays non-destructive and returns the same `{ created: false, keyFile }` shape; `--force` rotation (retire-not-delete) is unchanged.
- `tests/crypto.test.mjs` adds four cases: corrupted JSON throws; missing active key throws; wrong-length active key throws; a valid file with retired keys succeeds byte-for-byte unchanged. Adversarial verify confirmed each defect is caught and the valid path is non-destructive.

Release decision: resolved.

### P2-CR-008: Satellite Packaging Check Misses `manifest.bin`

Status: Resolved (2026-06-16, toward 1.3.1)  
Affected code: `scripts/check-satellite-packaging.mjs`  
Evidence:

- Package checks validate exported files but do not prove that `manifest.bin` points to present executable files.

Impact:

A satellite package can pass the local packaging check while shipping a broken CLI entrypoint. This is a release quality risk, especially as auth/KMS/dashboard satellites expand.

Resolution / closure evidence:

- `evaluateSatellitePackaging()` in `scripts/check-satellite-packaging.mjs` now validates every `manifest.bin` target against the packed-file set: both the string form (`bin: "bin/x.mjs"`) and the object-map form (`bin: { name: "bin/x.mjs" }`) are normalized the same way as `files`/`exports`, and a clear problem is reported for any bin target not present in the tarball. Existing checks are unchanged.
- `tests/satellite-packaging-gate.test.mjs` adds positive (present bin → no problem) and negative (missing bin, string + object-map forms → bin-specific problem) cases. Adversarial verify confirmed a mutation removing the bin-check block fails the negative test.

Release decision: resolved.

### P2-CR-009: Auth Provider Throw Path Test Gap

Status: Resolved (2026-06-16, toward 1.3.1)  
Affected code: `packages/proxy/index.mjs` auth handling, `tests/proxy-auth.test.mjs`  
Evidence:

- Runtime wraps `authProvider.authenticate()` errors as fail-closed `haechi_auth_provider_error`.
- Existing tests cover several auth outcomes but not provider exceptions.

Impact:

Future auth-provider changes can accidentally leak raw errors, fail open, or return inconsistent audit status without tests catching it.

Resolution / closure evidence:

- `tests/proxy-auth.test.mjs` adds a regression test that injects an `authProvider` whose `authenticate()` throws and asserts the proxy fails closed: the request is rejected (not forwarded upstream) with a generic client error, the audit event records the fail-closed status `haechi_auth_provider_error`, and no raw error/stack and no raw subject/issuer leak into the audit event. Adversarial verify confirmed a fail-open mutant (forwards upstream / returns 200) and an audit-leak mutant both make the test fail.

Release decision: resolved.

### P2-CR-010: Process-Isolated Sandbox Quota Test Gap

Status: Resolved (2026-06-16, toward 1.3.1)  
Affected code: `packages/plugin/process-sandbox.mjs`  
Evidence:

- Oversized result and over-capacity branches are not mirrored with the same focused coverage as worker sandbox tests.

Impact:

Process isolation is a security boundary for future plugin work. Missing parity tests increase the chance of regressions in denial-of-service controls.

Resolution / closure evidence:

- `tests/plugin-process-sandbox.test.mjs` (with a crash fixture added to `tests/helpers/sandbox-fixtures.mjs`) adds isolated-process parity tests mirroring the worker-sandbox DoS-control coverage: oversized result denied, queue/over-capacity rejected, timeout terminated, and child-crash fail-closed (a crash mid-call surfaces as a `crash`-caused denial without killing sibling calls). Adversarial verify confirmed mutations disabling the oversize / capacity / timeout / crash guards each fail the corresponding test (the crash boundary is pinned by the mid-call crash test).

Release decision: resolved.

### P2-CR-011: Audit Chain Middle-Tamper Test Gap

Status: Resolved (2026-06-16, toward 1.3.1)  
Affected code: `packages/audit/index.mjs` `verifyAuditChain()`  
Evidence:

- Existing coverage does not focus on middle-record tampering branches.

Impact:

Audit integrity is a core claim. The chain-verification code is present, but branch-specific tests should prove it rejects middle-record tampering, missing previous hashes, and hash mismatches.

Resolution / closure evidence:

- `tests/audit-chain-tamper.test.mjs` writes a real multi-record audit log via the sink, then tampers a MIDDLE record and asserts `verifyAuditChain` returns `{ valid: false }` with the correct reason for each branch: middle-record content mutation (stale `eventHash`), missing `previousHash`, wrong `previousHash`, and wrong `integrity` hash. The known tail-truncation limitation (trailing-record removal is detectable only via the separate append-only anchor stream, not the chain alone) is kept explicit. Adversarial verify confirmed the logs are produced by the real sink and the assertions pin each tamper branch.

Release decision: resolved.

### P2-CR-012: KMS Vault IPv6 Loopback Test Gap

Status: Resolved (2026-06-16, toward 1.3.1)  
Affected code: `satellites/crypto-kms/vault.mjs`  
Evidence (was):

- Localhost carve-out coverage proved IPv4 loopback behavior but not IPv6 loopback variants.

Impact (was):

The vault guard is security-sensitive and has slightly different URL parsing logic from the core SSRF guard. IPv6-specific tests were needed to prevent future divergence.

Resolution / closure evidence:

- `satellites/crypto-kms/vault.test.mjs` adds a dedicated test, "isBlockedAddress enforces the IPv6 loopback policy (::1, [::1], dotted + hex mapped) — P2-CR-012", covering bare `::1`, bracketed `[::1]`, dotted `::ffff:127.0.0.1` (and its bracketed form), and hex `::ffff:7f00:1` / `::ffff:7f00:0001` (and its bracketed form), all per the intended vault policy (blocked), and asserting that a public IPv4-mapped address (`::ffff:8.8.8.8` / `::ffff:808:808`) is NOT over-blocked.
- The vault range table is extended with the hex mapped private/metadata forms and the public mapped allow cases, and `satellites/crypto-kms/ssrf-parity.test.mjs` pins the dotted+hex agreement with the auth-jwt copy — the intentional non-IP fail-closed divergence stays explicitly pinned, so future divergence is caught.

Release decision: resolved; the test gap is closed.

### P2-CR-013: SSE Multi-Line `data:` Join Semantics

Status: Resolved (2026-06-16, toward 1.3.1)  
Affected code: `packages/stream-filter/index.mjs`  
Evidence (was):

- The SSE parser joined multiple `data:` lines with `join("")`.
- The SSE processing model joins multiple data lines with newline separators.

Impact (was):

Valid multi-line SSE events could be mutated before parsing or inspection. This can cause false negatives, false positives, or malformed forwarded events.

Resolution:

- `parseFrame` now joins multiple `data:` lines with `join("\n")` (the SSE spec separator) and strips only the single spec-defined leading space per line (`replace(/^ /, "")` instead of `trim()`, so interior/trailing text whitespace is not corrupted). A multi-line JSON event still `JSON.parse`s because newlines are valid JSON whitespace between tokens / inside the reconstructed value; a multi-line plain-text event is reconstructed with its newlines before text inspection. The non-JSON CONTENT re-serializer (`serializeTextFrame`) re-emits a multi-line protected payload as multiple `data:` lines, so the newline survives the round-trip.

Closure evidence:

- `tests/stream-filter.test.mjs` adds a multi-line `data:` JSON event (split across two `data:` lines) that still parses and is protected, and a multi-line plain-text `data:` event whose PII (on the second line) is caught and re-emitted with two `data:` lines preserved.

Release decision: should be fixed with the streaming remediation group. Resolved.

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

