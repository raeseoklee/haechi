---
updated: 2026-06-10
tags: [decision, roadmap]
---

# Release Roadmap

Agreed 2026-06-10 between maintainer and assistant; recorded in `risk-register-release-gate.md` §8 and `release-0.4-implementation-scope.md`.

| Version | Theme | Why this cut |
|---|---|---|
| 0.3.2 ✅ | Hardening + **first npm publish** | Separate name-claim risk from feature risk. Published 2026-06-10 via local passkey with `--provenance=false`; trusted publishing (npm Trusted Publisher link + OIDC workflow) was configured later the same day — the first attested release lands with 0.4.0 ([[packaging-and-distribution]]) |
| 0.4.0 ✅ | Token round-trip and adoption | Shipped 2026-06-10 (PRs #7–#10). [[token-vault]] round-trip, `mcp-wrap`, `audit-verify`/`status`, report-only injection heuristics, `identity`/`authProvider` reserved. Its GitHub release is the first attested (trusted-publishing) npm publish |
| 0.5.0 ✅ | Streaming hardening | Shipped 2026-06-10 (PR #14): SSE/NDJSON [[streaming-protection-gap|streaming inspection]] with bounded cross-frame buffer. Stream sequence AAD / replay cache deferred to 0.6+ |
| 0.6.0 ✅ | Auth + per-client controls | Shipped 2026-06-10 (PRs #17–#19): bearer auth, named policy profiles, model allowlist, request rate limit, PII-safe identity in audit ([[identity-and-auth]]). Heavier ops items in 0.7 |
| 0.7.0 ✅ | Ops hardening | Shipped 2026-06-10 (PRs #22–#24): audit head-hash anchoring ([[audit-integrity]]) + external sink contract, cryptoProvider contract hardening + `assertCryptoProviderConformance` + reference KMS adapter, signed/checksummed release artifacts |
| 0.8.0 ✅ | Ecosystem foundation + satellites | Shipped 2026-06-10 (PRs #27–#32): npm workspaces monorepo (root self-member `["."]` + satellite peer/dev dual core dep); **published** `haechi@0.8.0` (attested), `haechi-crypto-kms` + `haechi-auth-jwt` (unscoped — `@haechi` scope taken). Core zero-dep via packed-manifest + satellite-packaging gates. Satellite `0.1.0` = manual bootstrap (unattested, to create the name for TP setup); `0.1.1` = first attested CI release (provenance + sigstore verified). ([[packaging-and-distribution]]) |
| 0.9.0 | Observability + interactive auth | `haechi-auth-oidc` full authorization-code flow, `haechi-dashboard` read-only audit viewer ([[audit-integrity]] chain status), `haechi-crypto-kms` Vault/GCP/Azure backends — split out of 0.8 to keep that release code-light |
| 1.0.0 | Stable API + plugin sandbox | Only then: dynamic loading of external packages |

## Principles behind the ordering

1. **Product credibility before operational controls** — for a personal/self-hosted preview, token round-trip and MCP plug-in UX persuade more than rate limits.
2. **First publish small** — name ownership decoupled from feature risk; the provenance/trusted-publishing pipeline remains an open pre-0.4-release task.
3. **Injection heuristics ship report-only** (default action `allow`; detections still audit) — false-positive blocks would burn trust in a security product.
4. **No dynamic provider loading before the sandbox** — keeps P1-SEC-004's manifest-only stance coherent.
