# MVP 0.1 Implementation Scope

- Status: Draft 0.1
- Date: 2026-06-09
- Target version: Haechi

## 1. Summary

MVP 0.1 focuses on delivering a local security layer that is easy to attach and immediately verifiable, rather than broad protocol coverage.

The success criteria for 0.1 are:

1. The user runs `haechi init` to generate a local key, sample policy, and audit path.
2. The user runs `haechi protect` to protect an OpenAI-compatible JSON payload.
3. The user runs `haechi proxy` to route an existing LLM HTTP call through a local proxy.
4. The user runs `haechi report` to view an audit summary containing no plaintext.
5. Tests verify PII/secret detection, redaction, blocking, encryption, and prevention of plaintext leakage in the audit log.

## 2. 0.1 Included Scope

| Area | Included |
|---|---|
| Runtime | Node.js ESM, no external runtime dependency |
| Config | JSON config, preset policy |
| CLI | `init`, `protect`, `report`, `proxy` |
| Core | security context, filter -> policy -> transform -> audit pipeline |
| Filter | email, phone, Korean RRN-like id, card-like number, API key/secret, custom regex |
| Policy | dry-run, redact, mask, encrypt, block |
| Crypto | local AES-256-GCM envelope encryption using Node `crypto` |
| Key | local software key file |
| Audit | JSON Lines audit event without raw payload |
| Adapter | OpenAI-compatible request body traversal |
| Proxy | local HTTP JSON proxy with upstream forwarding |
| Tests | Node built-in test runner |

## 3. 0.1 Excluded Scope

| Excluded | Reason | Next Step |
|---|---|---|
| Python SDK | Node CLI alone is sufficient for the 0.1 quickstart | 0.2 |
| Vault/AWS KMS | Requires external setup, which breaks the 5-minute demo | 0.2 adapter |
| MCP stdio wrapper | process/env handling requires a separate security review | 0.2 |
| Full MCP protocol proxy | 0.1 prioritizes validating HTTP JSON payload protection | 0.2 |
| A2A/gRPC production adapter | Requires prior protocol contract definition | 0.3 |
| TokenVault | reveal/purge governance requires separate design | 0.2 |
| Signed policy bundle | 0.1 prioritizes local config validation | 0.2 |
| SBOM/signing | Release-phase work | 0.2 |

## 4. Quickstart Flow

```bash
npm test
node packages/cli/bin/haechi.mjs init --force
node packages/cli/bin/haechi.mjs protect examples/llm-prompt-filtering/input.json --config haechi.config.json
node packages/cli/bin/haechi.mjs report --audit .haechi/audit.jsonl
node packages/cli/bin/haechi.mjs proxy --config haechi.config.json
```

## 5. Implementation Principles

- Start with no external dependencies.
- Use JSON configuration. Defer YAML support to 0.2 or later.
- Do not implement crypto primitives directly; use AES-256-GCM from Node `crypto`.
- Default mode is `dry-run`.
- Even in enforcement mode, do not write raw input to the audit log.
- On processing failure, prefer blocking the request over leaking plaintext.
- Preserve provider boundaries in the code structure, but do not build an elaborate plugin loader in 0.1.

## 6. 0.1 Completion Criteria

| Criterion | Done When |
|---|---|
| CLI | `init`, `protect`, `report`, and `proxy` are functional |
| Security | No sentinel plaintext remains in the audit JSONL |
| PII | email/phone/secret/card-like/RRN-like fixtures are detected |
| Policy | dry-run/redact/mask/encrypt/block fixtures pass |
| Crypto | Decryption fails when AAD is tampered with |
| Applicability | Example payload can be protected via CLI and verified in the audit report |
| Verification | `npm test` passes |
