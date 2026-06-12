# Haechi Security Whitepaper

- Status: Living document (WS6 — reliability-hardening-track §WS6)
- Scope of this document: a **control mapping + structured self-assessment**, not a certification or an independent audit.
- Source of truth: the code under `packages/*`, `docs/current/threat-model.md`, and `docs/current/risk-register-release-gate.md`. This whitepaper *maps* those; it does not restate them wholesale, and it cites repo paths and risk IDs rather than duplicating their content.

## 0. What this is — and is not

Haechi is an **AI context enforcement layer**: it inspects and protects OpenAI-compatible / MCP / vLLM / Ollama / llama.cpp JSON payloads (detecting PII and secrets, then redacting / masking / tokenizing / encrypting / blocking them) before they reach models, tools, or logs.

This document maps the controls Haechi **actually ships** to two frameworks already cited across the repo — the **OWASP Top 10 for LLM Applications (2025)** and the **NIST AI Risk Management Framework (AI RMF 1.0)** — and records a **structured self-pentest** of the adversarial findings the reliability-hardening track caught and fixed.

It is explicitly **NOT**:
- a compliance certification, attestation, or assurance report (see the reliability-hardening-track §5 non-goal and `SECURITY.md` Scope);
- an independent third-party penetration test;
- a claim that every OWASP-LLM / NIST-AI-RMF item is *fully* mitigated. Several are **shared responsibility** (`docs/current/shared-responsibility.md`) or out of scope (`docs/current/threat-model.md` §4). Only controls that exist in the shipped code are mapped below; nothing here is aspirational.

## 1. Control inventory (the shipped surface)

Every control mapped below is load-bearing, test-backed behavior. The authority for each is the code path and the threat-model / risk-register row, not this table.

| # | Control | Where it lives | Authority |
|---|---|---|---|
| C1 | Detection + redaction/mask/tokenize/encrypt/block pipeline | `packages/core` (`protectJson`), `packages/filter`, `packages/policy` | threat-model §3 |
| C2 | Fail-closed enforcement (unknown policy/config/`target.type` throws; non-JSON/invalid/compressed/oversized responses fail closed) | `packages/cli/runtime.mjs` (`normalizeConfig`), `packages/proxy` (`maybeProtectResponse`) | CLAUDE.md invariants; P1-SEC-010 |
| C3 | Audit SHA-256 hash chain + head anchoring (tamper + tail-truncation evidence) | `packages/audit` (`verifyAuditChain`, `audit.anchor`) | P1-SEC-003 |
| C4 | No plaintext/PII in audit (`FORBIDDEN_KEYS`); keyed-HMAC identity hashes; structured-path key hashing | `packages/audit`, `packages/auth` (`buildIdentity`) | P1-SEC-012 |
| C5 | Streaming blocked by default; bounded, opt-in inspection with a cross-frame sliding buffer | `packages/proxy`, `packages/stream-filter`, `core` (`createStreamProtector`) | P1-SEC-007 |
| C6 | Client auth gate before body-read; named policy-profile resolution; per-identity rate limit | `packages/proxy` (`authorizeRequest`), `packages/auth` | SECURITY.md; threat-model §3 |
| C7 | Signed, sandboxed `authProvider` plugin (Ed25519 + trust anchors + pin/floor/revocation + worker/process isolation) | `packages/plugin`, `packages/cli/runtime.mjs` | P1-SEC-024 / P1-SEC-027 |
| C8 | SSRF guard on host-mediated fetches; absolute-form proxy target rejection | `packages/ssrf`, `packages/proxy` (`assertRelativeProxyTarget`) | P1-SEC-009 / P1-SEC-028 |
| C9 | Token-vault reveal governance (`revealPolicy`), retention, audited reveal/purge by token id | `packages/token-vault` | P1-SEC-002 |
| C10 | Policies only get stronger (`ACTION_STRENGTH`); privacy profiles may strengthen, never weaken | `packages/policy`, `packages/privacy-profiles` | P1-SEC-005 |
| C11 | Detection precision controls (`filters.minConfidence`, `filters.allowlist`) that **cannot** suppress hard-block types | `packages/filter`, `packages/core` | WS2c |
| C12 | NFKC normalization of string leaves before matching (full-width/confusable evasion) | `packages/core` / `packages/filter` | WS2d |
| C13 | **Proxy TLS / remote-bind hardening (this WS):** a remote bind requires Haechi to terminate TLS (`proxy.tls`) or an explicit trusted-hop acknowledgement (`proxy.trustForwardedProto`, enforcing `X-Forwarded-Proto: https`); otherwise it throws at startup | `packages/proxy` (`assertSafeProxyTransport`, server selection, forwarded-proto gate), `packages/cli/runtime.mjs` (`proxy.tls` resolution) | this document §3 |
| C14 | Loopback bind by default; non-loopback refused without `--allow-remote-bind` | `packages/proxy` (`assertSafeProxyBind`) | SECURITY.md |
| C15 | Bounded recursion-depth + byte/encoding guards (fail-closed 4xx; non-UTF-8 rejected) | `packages/core`, `packages/proxy` (`readBody`) | WS5 |
| C16 | Operability fail-closed signals (`/__haechi/ready` 503 when audit not writable; metrics carry no PII) | `packages/proxy` (`handleReady`), `packages/metrics` | WS4 |

## 2. OWASP Top 10 for LLM Applications (2025) mapping

Each row maps an OWASP-LLM risk to the Haechi control(s) that address it, with the honest residual. Where a risk is primarily the operator's / model's responsibility, it is marked **Shared / Out of scope** rather than claimed as mitigated.

| OWASP-LLM (2025) | Haechi control(s) | Coverage & honest residual |
|---|---|---|
| **LLM01 Prompt Injection** | C5 (response/tool-result injection detection is report-only by default), C1 | **Partial / by design.** Injection detection runs on the response/tool-result direction and is report-only unless explicitly escalated (CLAUDE.md invariant). Haechi does not "solve" prompt injection — `threat-model.md` §4 lists prompt-injection *prevention* as a non-goal. It reduces blast radius by detecting secrets/PII in tool results before they re-enter context. |
| **LLM02 Sensitive Information Disclosure** | C1, C2, C9, C4 | **Primary use case.** The detect→redact/mask/tokenize/encrypt/block pipeline plus response protection is exactly this control. Residual: detection is regex+validator, not ML (non-goal); documented exclusions (base64/URL-query) stand (threat-model §4). |
| **LLM03 Supply Chain** | C7, plus SBOM + SHA-pinned CI (P1-OPS-002/006) | **Addressed for the plugin path.** Dynamic code is admitted only as a signed, trust-anchored, pinned/floored/revocable `authProvider` plugin. Core stays zero-runtime-dependency, shrinking the dependency attack surface. |
| **LLM04 Data & Model Poisoning** | — | **Out of scope.** Haechi is an inline context filter, not a training/data-pipeline control. Marked out of scope, not mitigated. |
| **LLM05 Improper Output Handling** | C5, C2, C1 | **Addressed.** Response/stream protection inspects model output before it reaches the caller/tools; fail-closed for non-JSON/invalid/compressed/oversized responses. Residual: streaming bytes already emitted before a block cannot be retracted (documented). |
| **LLM06 Excessive Agency** | C6, C7, C9 | **Partial.** The auth gate + named policy profiles + model allowlist constrain who can drive the gateway and which models/operations are reachable; token reveal is governed. Agent-level authorization beyond the gateway is the operator's. |
| **LLM07 System Prompt Leakage** | C1, C5, C4 | **Partial.** Secrets/PII embedded in prompts/responses are detected and protected; audit never stores raw prompt text (C4). Haechi does not prevent a model from emitting its own system prompt text. |
| **LLM08 Vector & Embedding Weaknesses** | — | **Out of scope.** No RAG/vector-store component. |
| **LLM09 Misinformation** | — | **Out of scope.** Not a factuality control. |
| **LLM10 Unbounded Consumption** | C6 (rate limit), C15 (byte/depth limits), C16 (backpressure/timeouts) | **Addressed at the gateway.** Per-identity rate limit, request byte + nesting-depth caps, max-in-flight backpressure (503 + `Retry-After`), tuned timeouts. Residual: the built-in rate limiter is single-process (multi-replica needs an injected shared limiter — shared-responsibility.md). |

## 3. NIST AI RMF (AI RMF 1.0) mapping

Mapped to the four AI RMF functions. Haechi is a *technical control surface* an operator uses inside their own AI-RMF program; it does not implement governance for them.

| AI RMF function | Haechi control(s) | What Haechi contributes (and the boundary) |
|---|---|---|
| **GOVERN** | C2, C10, C14, the documented threat-model + shared-responsibility split | Fail-closed defaults, a stronger-only policy lattice, loopback-by-default, and explicit documentation of what Haechi does vs. what the operator owns. Governance *policy* remains the operator's. |
| **MAP** | C1, the detection-type matrix (`configuration.md`), threat-model §1–2 | Surfaces *where* sensitive data flows through prompts/responses/tool calls and *which* categories are detected, helping an operator map AI-system data risks at the gateway boundary. |
| **MEASURE** | C3, C4, C11, the `bench:detection` precision/recall gate, `/__haechi/metrics` | Tamper-evident audit, a precision/recall measurement harness wired as a CI gate, and PII-free operational metrics give an operator measurable signals. Residual: detection metrics measure regex/validator rules only. |
| **MANAGE** | C2, C5, C6, C9, C13, C16, the operations-runbook | Inline enforcement, streaming containment, the auth gate, token-vault governance, TLS-hardened remote binding, readiness/backpressure, and a Day-2 runbook (rotation/retention) let an operator manage risk in production. |

## 4. Structured self-pentest

This is a **self-assessment** — Haechi's own adversarial testing of its own controls — not an independent pentest. Each finding below was reproduced as a test, fixed, and is now regression-guarded.

### 4.1 Methodology
- **Real-environment validation.** The proxy + protection pipeline is exercised against real OpenAI-compatible (vLLM) and Ollama native endpoints via the env-gated integration suite (`tests/local-inference.integration.test.mjs`; P1-OPS-003). CI skips these when no model server is present, so they are opt-in rather than mocked-only.
- **Adversarial regression corpus.** A labeled positive/hard-negative detection corpus drives `npm run bench:detection`, wired as a CI gate (`scan:detection`) so a precision/recall regression fails the build (WS2a).
- **Fail-closed assertion as a test discipline.** Every new path (depth guard, readiness, backpressure, env overlay, and the TLS remote-bind guard in §3) ships a test that asserts the *throw/deny* direction, not only the happy path.

### 4.2 Findings caught and fixed (selected)

| Finding | Class | What broke | Fix + guard |
|---|---|---|---|
| **WS2d — Unicode evasion** | Detection bypass | Full-width / confusable code points slipped a secret/PII value past every regex rule (string leaves were matched pre-normalization). | NFKC-normalize string leaves before matching (C12); covered by the evasion fixtures in the detection corpus. |
| **WS2c — bearer-recall regression** | Detection precision | A context anchor added to cut "Bearer …"-in-prose false positives also suppressed *real* bearer-token secrets (a recall regression the corpus caught). | The anchor was re-scoped so the hard-block `secret` type is never suppressed by an allowlist/anchor (C11 invariant); the precision-control tests pin both the FP cut **and** the recall floor. |
| **WS5 — deep-nesting stack overflow** | Availability (DoS) | A deeply nested JSON within `maxRequestBytes` overflowed the recursion stack → uncaught crash. | Configurable `limits.maxNestingDepth` fail-closed 4xx (C15); a deep-nesting test. |
| **P1-SEC-009 — proxy SSRF / absolute target** | SSRF | An absolute/protocol-relative request target could redirect the upstream. | Origin-form-only targets; the upstream URL combines only path+search with the fixed upstream (C8). |
| **WS6 — remote bind in plaintext (this WS)** | Confidentiality | A non-loopback bind served plain HTTP, exposing bearer tokens + payloads in cleartext. | A remote bind now requires Haechi-terminated TLS or an explicit `trustForwardedProto` hop enforcing `X-Forwarded-Proto: https`; otherwise it throws at startup (C13). Guarded by `tests/proxy-tls.test.mjs` (throw-without-TLS, https-over-TLS smoke, forwarded-proto rejection, fail-closed config). |

### 4.3 Accepted residuals (honest)
- A signed plugin's own `fs`/`fetch` is not blocked in the 1.0 `worker_threads` mode (memory/crash isolation only); enforced only in the opt-in 1.1 `process-isolated` runtime (threat-model §3, P1-SEC-027).
- Single-process rate limiter / audit chain / token vault: multi-replica safety needs an injected shared store (shared-responsibility.md; reliability-hardening-track §3).
- Detection stays regex + validators (no ML); documented base64 / URL-query exclusions stand (threat-model §4).

## 5. Disclosure

Report suspected vulnerabilities via GitHub **private vulnerability reporting** (Security Advisories) at <https://github.com/raeseoklee/haechi/security/advisories>, per `SECURITY.md` and `/.well-known/security.txt`. Do not include real secrets, production prompts, customer data, or personal information in a report.

## 6. Cross-references
- `docs/current/threat-model.md` — the authoritative threat model and exclusions.
- `docs/current/risk-register-release-gate.md` — the per-risk resolution status and release gates.
- `docs/current/compliance-mapping.md` — the control-to-obligation mapping + DSAR/retention workflow.
- `docs/current/shared-responsibility.md` — what Haechi owns vs. the operator.
- `docs/current/operations-runbook.md` — Day-2 operations, rotation, and retention.
