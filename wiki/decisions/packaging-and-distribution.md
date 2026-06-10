---
updated: 2026-06-10
tags: [decision, distribution]
---

# Packaging and Distribution

## Current (0.3.2)

Single npm package `haechi` (unscoped), zero runtime dependencies, subpath exports per module (`haechi/proxy`, `haechi/audit`, …). First published 2026-06-10 via local passkey authentication (0.3.2, unattested); from 0.4.0 onward releases publish through GitHub Actions trusted publishing with SLSA provenance attestations (verified on npm). SBOM omits dev dependencies so it describes the shipped artifact only.

## Satellite package strategy (0.6–0.7)

- Create npm org **`@haechi/*`** (also defends the namespace against squatting — a registered concern in the risk register).
- Core keeps the unscoped `haechi` name; satellites: `@haechi/dashboard`, `@haechi/auth-oidc`, `@haechi/auth-jwt`, `@haechi/classifier-*`.
- **Auth: contract in core, implementations as satellites** ([[identity-and-auth]]) — security-critical interfaces must be core-owned.
- **Dashboard: fully separate.** Read-only consumer of the audit JSONL (reads files directly; no audit query API on the proxy — don't grow its attack surface). UI dependencies must not contaminate core's zero-dep posture. Shows [[audit-integrity]] chain status as a feature.
- Monorepo conversion to npm workspaces happens when the second package actually ships (0.7), not before.

## Rejected: curl|sh installer (2026-06-10)

For a security product whose pitch is provenance and supply-chain hygiene, `curl | sh` sends exactly the wrong signal, and a Node CLI gains nothing from it (Node must exist anyway; `npx haechi` covers no-install use). Revisit at 0.6 alongside signed release artifacts as a **checksum/signature-verifying** installer for standalone (Node SEA) binaries. Nearer-term alternative: a container image on GHCR (fits the sidecar/gateway deployment shape, cosign-signable).
