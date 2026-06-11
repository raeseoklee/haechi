---
updated: 2026-06-11
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
| 0.9.0 ✅ | Observability + interactive auth | **Shipped 2026-06-11 (PRs #38–#41)** (`docs/current/release-0.9-implementation-scope.md`, hardened after an adversarial security review). The 0.9.0 cut is `haechi-dashboard` + `haechi-auth-oidc` **paired**: a **zero-dep vanilla** (`node:http`, no framework/build) read-only audit viewer ([[dashboard-audit-viewer]], [[audit-integrity]] chain status) gated by an **interactive OIDC session broker** ([[oidc-session-broker]] — authorization-code + PKCE, server-side sessions). PR #38 bumped `haechi-auth-jwt` to **0.2.0** (additive `createJwtVerifier` + `isBlockedAddress` export, behavior-preserving); #39 `haechi-dashboard@0.1.0`; #40 `haechi-auth-oidc@0.1.0`; #41 `haechi-crypto-kms@0.2.0` (Vault/GCP/Azure backends, shipped **independently** of the core cut — Vault is zero-peer via `node:` fetch). Four satellites total now, each zero runtime dependency ([[packaging-and-distribution]]). Split out of 0.8 to keep that release code-light |
| 1.0.0 | Stable API + plugin sandbox | **Design pinned 2026-06-11** (`docs/current/release-1.0-implementation-scope.md`, hardened after a 3-lens adversarial review — 7 critical findings fixed). The first **stable** release: (a) a **strict API freeze** (core API + provider contracts + nested audit schema + config schema, strict semver + deprecation policy with a disclosed-vuln security exception); (b) lifts the long-held dynamic-loading ban **narrowly** — an **`authProvider`-only**, **Ed25519-signed** (asymmetric; NOT the symmetric policy-bundle HMAC), capability-gated, pin/revocation-checked, **`worker_threads`-isolated**, fully-audited plugin sandbox. `worker_threads` gives memory/crash isolation + data-minimization (only the credential slice crosses, host builds the keyed-HMAC identity) but is honestly NOT a capability sandbox — a malicious *signed* plugin can still use fs/net and exfiltrate the credential; true enforcement (child-process + Node permission model) is **1.x**. Injection (`createRuntime(config, providers)`) stays the default. **Prerequisite (PR0):** widen all four satellites' `haechi` peer range `<1.0.0 → <2.0.0` (else core 1.0.0 breaks every satellite install) + a preflight `semver.satisfies` gate. real-environment-validation exit criterion recorded met (live vLLM/Ollama + dashboard) with live-KMS + hostile-plugin-red-team residuals. ([[packaging-and-distribution]], [[identity-and-auth]]) |

## Principles behind the ordering

1. **Product credibility before operational controls** — for a personal/self-hosted preview, token round-trip and MCP plug-in UX persuade more than rate limits.
2. **First publish small** — name ownership decoupled from feature risk; the provenance/trusted-publishing pipeline remains an open pre-0.4-release task.
3. **Injection heuristics ship report-only** (default action `allow`; detections still audit) — false-positive blocks would burn trust in a security product.
4. **No dynamic provider loading before the sandbox** — keeps P1-SEC-004's manifest-only stance coherent.
