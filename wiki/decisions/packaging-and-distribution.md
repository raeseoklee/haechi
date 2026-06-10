---
updated: 2026-06-10
tags: [decision, distribution]
---

# Packaging and Distribution

## Current (0.3.2)

Single npm package `haechi` (unscoped), zero runtime dependencies, subpath exports per module (`haechi/proxy`, `haechi/audit`, …). First published 2026-06-10 via local passkey authentication (0.3.2, unattested); from 0.4.0 onward releases publish through GitHub Actions trusted publishing with SLSA provenance attestations (verified on npm). SBOM omits dev dependencies so it describes the shipped artifact only.

## Satellite package strategy

- Create npm org **`@haechi/*`** (also defends the namespace against squatting — a registered concern in the risk register).
- Core keeps the unscoped `haechi` name; satellites: `@haechi/crypto-kms`, `@haechi/dashboard`, `@haechi/auth-oidc`, `@haechi/auth-jwt`, `@haechi/classifier-*`.
- **Reference-then-publish:** a satellite ships first as a repo example/source (e.g. `examples/crypto-kms-reference/` in 0.7), then is promoted to a published `@haechi/*` package once the org + workspaces land (0.8). This keeps core zero-dep while the adapter exists and is testable.
- **Auth: contract in core, implementations as satellites** ([[identity-and-auth]]) — security-critical interfaces must be core-owned.
- **Dashboard: fully separate.** Read-only consumer of the audit JSONL (reads files directly; no audit query API on the proxy — don't grow its attack surface). UI dependencies must not contaminate core's zero-dep posture. Shows [[audit-integrity]] chain status as a feature.
- **First two published satellites are 0.8:** `@haechi/crypto-kms` (real AWS KMS client) and `@haechi/auth-jwt` (headless JWKS). `@haechi/auth-oidc` + `@haechi/dashboard` moved to 0.9 to keep 0.8 code-light ([[release-roadmap]]).

## npm workspaces mechanic (verified 2026-06-10, design 0.8)

The monorepo conversion is a **0.8** step (earlier wiki text said 0.7 — corrected; no second package actually shipped before 0.8). The "least-invasive" layout was validated empirically because the obvious approach silently fails:

- ❌ `workspaces: ["satellites/*"]` + satellite `peerDependencies: { haechi: ">=0.8.0" }` → npm resolves the peer range from the **registry** (`ETARGET`), never symlinks root, satellite `import "haechi/crypto"` throws `ERR_MODULE_NOT_FOUND`. The root project is **not** a workspace member by default.
- ✅ Root lists **itself**: `workspaces: [".", "satellites/*"]` (the `"."` is what creates `node_modules/haechi → ..`). Satellites declare **both** `peerDependencies: { haechi: ">=0.8.0 <1.0.0" }` (consumer contract) **and** `devDependencies: { haechi: "*" }` (links the local workspace in dev; `npm pack` strips devDeps so consumers never see it).
- Zero-dep is defended by inspecting the **packed** `package.json` (not the installed-tree SBOM, which passes vacuously): assert the tarball manifest's `dependencies` is empty, and that no `satellites/` paths appear. Negatively tested so the gate isn't a vacuous pass.
- Consequence: the satellite imports `canonicalize` from `haechi/crypto` (the pre-0.8 reference inlined it only because nested-package self-resolution failed); a conformance test asserts byte-for-byte AAD-canonicalization parity.

## Rejected: curl|sh installer (2026-06-10)

For a security product whose pitch is provenance and supply-chain hygiene, `curl | sh` sends exactly the wrong signal, and a Node CLI gains nothing from it (Node must exist anyway; `npx haechi` covers no-install use). Revisit at 0.6 alongside signed release artifacts as a **checksum/signature-verifying** installer for standalone (Node SEA) binaries. Nearer-term alternative: a container image on GHCR (fits the sidecar/gateway deployment shape, cosign-signable).
