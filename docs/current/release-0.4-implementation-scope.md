# Haechi 0.4 Implementation Scope

- Status: Final
- Date: 2026-06-10
- Target version: 0.4.0 (after 0.3.2)
- Type: token round-trip and adoption
- Shipped: 2026-06-10 — PRs #7 (round-trip), #8 (audit-verify/status), #9 (mcp-wrap), #10 (injection + identity reservation)

## 1. Release Goals

0.4 accomplishes two things.

1. **Token round-trip**: the model sees only tokens while the user sees plaintext. This makes the tokenize action meaningful in real use.
2. **Reducing adoption friction**: MCP wrap mode plus audit verify/status commands provide plug-in UX and operational visibility.

Additionally, the `identity` schema and `authProvider` contract — prerequisites for the 0.6 (auth) and 0.7 (dashboard) expansions — are **reserved as contracts only, without implementation**.

## 2. Scope

### 2.1 Deterministic Tokenization

- Opt-in mode where the same (type, value) pair always produces the same token: `tokenVault.deterministic: true` (default: false)
- Token generation: `HMAC(derivedKey, type || value)` using a `haechi:token-vault:deterministic:v1` domain-separated derived key — not reversible or dictionary-attackable without the key file
- If a matching record already exists, it is reused and its expiry is refreshed
- **Trade-off documentation required**: determinism introduces linkability for identical values. Per-type opt-in is supported via `tokenVault.deterministicTypes`

### 2.2 Response Detokenization (Request-Scoped)

- New config: `tokenVault.detokenizeResponses: true` (default: false, explicit opt-in)
- **Request-scope principle**: only the token set issued or reused during the protect phase of a given request is restored in that request's response. No session storage or session ID required.
- Multi-turn is handled by deterministic tokenization: conversation history sent by the client each turn is re-tokenized, so prior-turn tokens are automatically included in the current request's token set.
- **Decoupled from revealPolicy**: `revealPolicy: disabled` controls CLI/manual reveal and is unrelated to response restoration. Restoration is recorded as a vault audit event (`detokenize` decision, token count only — no plaintext).
- Only active when responseProtection is enabled (restoration only runs on paths that already parse the response body).

### 2.3 `haechi mcp-wrap`

- Usage: `haechi mcp-wrap --config haechi.config.json -- <command> [args...]`
- Spawns a child process and filters stdio in both directions:
  - Client → server: method allowlist + params protection
  - Server → client: result protection (+ 2.6 injection detection)
- stderr passes through transparently; exit codes and SIGINT/SIGTERM are propagated
- Notification drop and batch fail-closed semantics are identical to 0.3.2

### 2.4 `haechi audit-verify`

- `haechi audit-verify [--audit .haechi/audit.jsonl]`
- Outputs the `verifyAuditChain()` result (valid/records/reason) and the chain head hash
- The head hash serves as the foundation for external anchoring (defense against tail truncation). Periodic anchor automation is deferred to 0.6+.

### 2.5 `haechi status`

- Prints an at-a-glance view of the effective state of the current config: effective policy mode (enforce/dry-run/report-only), responseProtection on/off, streaming mode, revealPolicy, detokenization on/off, privacy profile, adapter/upstream, key file existence and permissions, audit chain verification summary
- Answers the question "am I protected right now?" for products that default to dry-run. JSON output supported.

### 2.6 Injection Detection Type (Preview)

- New detection type `injection`: a heuristic ruleset applied only on the tool result/response direction (instruction patterns, role-switch attempts, tool-call induction)
- **Default action is `allow`** — detection is recorded in audit regardless of action, making this effectively report-only. Users can escalate to `actions.injection: "redact" | "block"` once confidence grows.
- Default blocking is prohibited: false positives erode trust in a security product.

### 2.7 `identity` Schema Reservation (No Implementation)

PII-safe identity fields are reserved in audit events and the protect context. In 0.4 these are always `null`.

```js
identity: {
  id: "...",            // opaque id issued by provider, or same as subjectHash
  type: "anonymous" | "user" | "service" | "agent",
  subjectHash: "...",   // HMAC("haechi:identity:hash:v1" derived key, subject) — bare sha256 prohibited
  issuerHash: "...",    // same approach
  provider: "none" | "bearer" | "oidc" | "external",
  scopes: ["..."],
  labels: {}            // allowlisted keys only (declared in config), value length limited, PII prohibited
}
```

- Raw subject/email values are **prohibited in every field**. Bare hashes of low-entropy identifiers are recoverable by dictionary attack — keyed HMAC only.
- `labels` is not freeform: only allowlist keys declared in config are accepted, and values are length-limited.
- Display names are an opt-in dashboard-side setting, not part of the audit schema.

### 2.8 `authProvider` Contract Reservation (No Implementation)

- Contract: `authenticate(request) → identity | null` (null = deny); failure is fail-closed
- Proxy execution order (implemented in 0.6):

```text
request target validation (assertRelativeProxyTarget)
route classify
authProvider.authenticate()        ← before reading body. Blocks large-body DoS from failed-auth requests
policy scope determination (identity-based)
body read
protect/enforce
forward
```

- Authentication failures are recorded in audit as `auth_denied` decision (attempted provider only, no raw identity)
- On 401 response, the request stream is not consumed; the connection is closed after responding
- `/__haechi/health` is intentionally kept unauthenticated (exposes mode only); documented in the contract
- Only `createRuntime(config, { authProvider })` injection is supported. **Dynamic npm loading is prohibited until the 1.0 plugin sandbox.**

## 3. Explicit Out-of-Scope (Not in 0.4)

- Auth implementation (including bearer) — 0.6
- SSE/NDJSON stream inspection — 0.5
- Proxy auth, model allowlist, rate/budget limits, hot reload, metrics — 0.6
- Dashboard, npm workspaces migration — 0.7
- Dynamic external package loading — 1.0

## 4. Test Criteria

- Detokenization: tokens not issued during a request are not restored in that request's response (scope isolation)
- Deterministic: same value → same token; different derived key → different token
- mcp-wrap: bidirectional protection, allowlist rejection, child exit code propagation
- audit-verify: correct output for valid/tampered/truncated cases
- status: correct warnings under enforce and dry-run respectively
- injection: with default allow, only audit record is written and payload is unchanged

## 5. Documentation Impact

- README: usage for detokenization, mcp-wrap, and status; deterministic linkability trade-off
- threat-model: maintain explicit statement of injection heuristic limitations (not a complete defense); add identity hash approach
- api-stability: authProvider/identity contract marked experimental in 0.4
