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
| 0.6.0 | Auth + operational controls | Built-in bearer auth, per-client policy scope, model allowlist/rate budget, KMS reference adapter, npm org `@haechi/*` |
| 0.7.0 | Observability | npm workspaces + `@haechi/dashboard` ([[packaging-and-distribution]]) |
| 1.0.0 | Stable API + plugin sandbox | Only then: dynamic loading of external packages |

## Principles behind the ordering

1. **Product credibility before operational controls** — for a personal/self-hosted preview, token round-trip and MCP plug-in UX persuade more than rate limits.
2. **First publish small** — name ownership decoupled from feature risk; the provenance/trusted-publishing pipeline remains an open pre-0.4-release task.
3. **Injection heuristics ship report-only** (default action `allow`; detections still audit) — false-positive blocks would burn trust in a security product.
4. **No dynamic provider loading before the sandbox** — keeps P1-SEC-004's manifest-only stance coherent.
