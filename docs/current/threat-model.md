# Haechi Threat Model

- Status: Draft 0.1
- Date: 2026-06-10
- Target version: 0.4.0

## 1. Assets Under Protection

The primary assets Haechi protects are:

| Asset | Examples | Protection Goal |
|---|---|---|
| Prompt/context payload | chat messages, tool arguments, MCP params | Policy enforcement before data reaches model/tool/logs |
| Tool/resource result | MCP result, local inference response | Prevent re-leakage of PII/secrets in responses |
| TokenVault record | tokenized PII mapping | Encrypted at rest, reveal blocked by default |
| Audit event | detection metadata, decision summary | No plaintext content, hash chain integrity |
| Crypto envelope | encrypted segments | Canonical AAD binding, swappable key provider |
| Plugin manifest | custom provider/filter declaration | Capability disclosure, dynamic runtime blocked |

## 2. Trust Boundaries

| Boundary | Trust Level | Default Controls |
|---|---|---|
| CLI local process | Developer local trust | Dev key warning, dry-run default |
| HTTP proxy listener | Untrusted client input | Loopback bind by default, remote bind requires explicit flag |
| Upstream model/tool server | Untrusted or partially trusted | Request/response protection, uninspectable response fail-closed |
| Streaming response | Currently uninspected | `stream: true` blocked by default |
| MCP stdio peer | Partially trusted | JSON-RPC 2.0 required, method allowlist |
| Local filesystem | Partially trusted | Local key/token vault at 0600, audit hash chain |
| External provider/plugin | Untrusted | Provider method contract, plugin manifest-only gate |

## 3. Key Threats and Controls

| Threat | Impact | Current Control |
|---|---|---|
| Internet-exposed proxy | Unauthenticated LLM gateway | Non-loopback bind fails by default |
| Streaming bypass | SSE/NDJSON plaintext leak | Streaming requests fail by default |
| Ollama implicit streaming bypass | NDJSON plaintext leak when `stream` is omitted | `/api/chat` and `/api/generate` are treated as streaming unless `stream: false` is explicit; blocked by default |
| Non-JSON / compressed / oversized response | responseProtection bypass | Fail-closed response policy |
| Token reveal abuse | Restoration of tokenized PII | `revealPolicy` disabled by default; reveal/purge decisions recorded in audit |
| Audit tampering | Degraded trust in audit evidence | SHA-256 hash chain |
| Policy-weakening override | Neutralizing block presets | Unsafe downgrade conflicts blocked; privacy profile can only strengthen |
| ReDoS via custom regex | CPU exhaustion | Nested quantifier/backreference restrictions |
| Plugin runtime confusion | Dynamic code execution risk | Manifest-only runtime permitted |
| MCP tool method misuse | Unexpected tool/resource access | Rejected based on `allowedMethods` |
| Key custody misunderstanding | Local dev key used in production | External crypto provider injection, dev key warning |
| Hung upstream | Proxy connection exhaustion | `limits.upstreamTimeoutMs` default 120 s; 504 fail on timeout |
| Signing/encryption key conflation | Key separation violation | Policy bundle signing key isolated as a domain-separated derived key |
| JSON number / object key concealment | Undetected non-string leaves such as card numbers | Number leaves and object keys included in detection/transform scope |
| Token round-trip restoring foreign tokens | Cross-client/request plaintext recovery | Detokenization is opt-in (`detokenizeResponses`) and request-scoped: only tokens issued while protecting the same request are restored |
| Indirect prompt injection in tool results/responses | Agent manipulation via planted instructions | Response-direction heuristics, report-only by default (`injection` action `allow`); escalation is an explicit policy choice. Not a complete defense |

## 4. Explicit Exclusions

0.3.2 does not guarantee:

- A production KMS/HSM/Vault adapter
- Authentication/authorization for internet-facing gateways
- SSE/NDJSON stream inspection
- Legal compliance certification
- Complete defense against model hallucination or prompt injection
- OAuth/resource binding validation for external MCP servers
- Inspection of base64/URL-encoded values or unicode-obfuscated values after decoding
- Detection of sensitive values in URL query strings (JSON body only)
- Audit hash chain tail truncation detection — the chain detects tampering and reordering, but deletion of the last N records cannot be detected without an externally preserved copy
- JSON-RPC batch message processing (the MCP stdio filter rejects batches fail-closed)

## 5. Remaining Operational Assumptions

Production users are responsible for the following outside of Haechi: network access control, upstream authentication, secret injection, key custody, log retention, handling DSAR/deletion requests, and establishing a legal transfer basis.
