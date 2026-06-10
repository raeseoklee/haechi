---
updated: 2026-06-10
tags: [review, security]
---

# 2026-06-10 Full Security Review → 0.3.2

Full-codebase review (all 13 packages, ~2,800 lines, tests, CI, threat docs) that produced the 0.3.2 hardening release. Authoritative finding list: risk register §5.2 (P0-SEC-016 … P2-DOC-005, 16 findings, all resolved).

## Highest-impact findings (worth remembering)

- **P0-SEC-016 Ollama implicit streaming** — `stream` omitted ⇒ Ollama streams ⇒ block bypassed. The class of bug: *protocol semantics that differ per adapter*. Any new adapter must declare `streamingDefault` ([[streaming-protection-gap]]).
- **P1-SEC-017 reveal without audit** — the most sensitive operation (plaintext recovery) left no trace. Class: *governance without audit is not governance* ([[token-vault]]).
- **P1-SEC-018 profile weakening** — privacy profiles spread over user actions, silently downgrading `block`→`redact`. Class: *every policy-merge path must respect `ACTION_STRENGTH`* ([[fail-closed]]).
- **P1-SEC-019 key loss on `init --force`** — re-running the demo destroyed all decryptability. Class: *rotation must retire, never delete* ([[key-management]]).
- **P1-SEC-020 key-separation violation** — AES key reused as HMAC key for bundle signing. Fixed with domain-separated derivation.

## Verified as solid (don't re-litigate)

Random 12-byte GCM IVs per call; canonical AAD binding; SSRF defense via origin-form-only targets; streamed response byte caps with hard deny; audit write serialization; actions pinned to commit SHAs; risk-register claims cross-checked against code and found accurate.

## Process note

The review ran as parallel scoped passes (proxy/adapters, crypto/vault/bundles, core/filter/policy, audit/MCP/CLI/docs) with findings verified against actual code before reporting. Re-run this shape before each release gate.
