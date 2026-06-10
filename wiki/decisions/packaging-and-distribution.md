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

**Shipped — PR1 (workspaces conversion) + PR2 (`@haechi/crypto-kms` AWS client):**

- `@haechi/crypto-kms` (`satellites/crypto-kms/`) is the first satellite: in-memory client + a real AWS KMS client at `@haechi/crypto-kms/aws` (`wrap`=KMS `Encrypt`, `unwrap`=`Decrypt`, `deriveHmacKey`=HKDF-SHA256 over a KMS-decrypted root). Both clients use **HKDF-SHA256** with the same domain-separated info, so they derive identical HMAC keys from the same root (cross-backend parity, tested).
- **`@aws-sdk/client-kms` is an OPTIONAL peer dependency** (decided 2026-06-10, overriding the design draft's "satellite's own dependency"): imported lazily only when no `client` is injected. The monorepo `npm ci` never pulls the AWS SDK; the 8+ AWS tests run SDK-free by injecting a faithful keyId-aware KMS-ops mock. Consumers add the SDK only for the AWS path.
- **Two packaging gates** in `release:preflight`: `check-core-packaging` (core tarball: no `satellites/` leak, zero runtime deps) and `check-satellite-packaging` (each satellite tarball: zero runtime deps so the optional peer never becomes a hard dep, all `files`/`exports` present, no `*.test.mjs` leak). Both inspect the **packed** manifest and are negatively unit-tested.
- **Per-package publish** ([[release-roadmap]]): core publishes on `v<semver>` (`npm-publish.yml`), the satellite on `crypto-kms-v<semver>` (`crypto-kms-publish.yml`), each guarded by an `if: startsWith(tag, …)` + strict regex + (satellite) tag-version-must-equal-package-version, so the two workflows never cross-fire. Each binds to its own npmjs.com Trusted Publisher (workflow filename). Bootstrap order (reserve name → configure TP → tag) is in `release-process.md`.

## Rejected: curl|sh installer (2026-06-10)

For a security product whose pitch is provenance and supply-chain hygiene, `curl | sh` sends exactly the wrong signal, and a Node CLI gains nothing from it (Node must exist anyway; `npx haechi` covers no-install use). Revisit at 0.6 alongside signed release artifacts as a **checksum/signature-verifying** installer for standalone (Node SEA) binaries. Nearer-term alternative: a container image on GHCR (fits the sidecar/gateway deployment shape, cosign-signable).
