---
updated: 2026-06-11
tags: [decision, distribution]
---

# Packaging and Distribution

## Current (1.0.0 — first stable)

Single npm package `haechi` (unscoped), zero runtime dependencies, subpath exports per module (`haechi/proxy`, `haechi/audit`, `haechi/plugin`, …). **Core bumps to `1.0.0` in the 1.0 cut — the first stable release** ([[release-roadmap]]); behavior is additive (the opt-in [[plugin-sandbox]] + a `schemaVersion`/`FORBIDDEN_KEYS` extension), the rest declared frozen. First published 2026-06-10 via local passkey authentication (0.3.2, unattested); from 0.4.0 onward releases publish through GitHub Actions trusted publishing with SLSA provenance attestations (verified on npm). SBOM omits dev dependencies so it describes the shipped artifact only.

**PR0 prerequisite for 1.0:** core `1.0.0` violated every satellite's old `<1.0.0` peer range, so PR #46 widened all four satellites' `haechi` peer range to `>=0.8.0 <2.0.0` (and auth-oidc's `haechi-auth-jwt` peer likewise to `<2.0.0`), bumping versions to auth-jwt `0.2.1` / crypto-kms `0.2.1` / dashboard `0.1.2` / auth-oidc `0.1.2`. A new `scripts/check-satellite-peer-ranges.mjs` preflight gate fails `release:preflight` if `!semver.satisfies(coreVersionToPublish, satelliteRange)` for any satellite (risk **P2-OPS-006** — satellite peer-range / major-tracking). Satellites now track core by **major** rather than pinning a minor, so a core minor bump never breaks a satellite install again.

## Satellite package strategy

- **Naming (corrected 2026-06-10):** the original plan was an npm org/scope `@haechi/*`, but **`@haechi` is already taken by a third party** — so satellites are **unscoped `haechi-*`** instead (`haechi-crypto-kms`, `haechi-auth-jwt`, and future `haechi-dashboard`, `haechi-auth-oidc`, `haechi-classifier-*`). No org needed; each name is reserved + Trusted-Publisher-bound individually. The trade-off vs a scope is the loss of namespace grouping/squat-defence; the `haechi-` prefix is the convention.
- Core keeps the unscoped `haechi` name.
- **Reference-then-publish:** a satellite ships first as a repo example/source (e.g. `examples/crypto-kms-reference/` in 0.7), then is promoted to a published `haechi-*` package once workspaces land (0.8). This keeps core zero-dep while the adapter exists and is testable.
- **Auth: contract in core, implementations as satellites** ([[identity-and-auth]]) — security-critical interfaces must be core-owned.
- **Dashboard: fully separate.** Read-only consumer of the audit JSONL (reads files directly; no audit query API on the proxy — don't grow its attack surface). UI dependencies must not contaminate core's zero-dep posture. Shows [[audit-integrity]] chain status as a feature. Shipped 0.9 as [[dashboard-audit-viewer]] — verified zero-dep (`node:http` + a static page, no framework/build).
- **First two published satellites are 0.8:** `haechi-crypto-kms` (real AWS KMS client) and `haechi-auth-jwt` (headless JWKS). `haechi-auth-oidc` + `haechi-dashboard` moved to 0.9 to keep 0.8 code-light ([[release-roadmap]]).

## The four satellites (after 1.0 / PR0)

| Satellite | Version | Core peer range | Runtime deps | Concept | Tag glob |
|---|---|---|---|---|---|
| `haechi-crypto-kms` | `0.3.0` | `>=1.7.0 <2.0.0` | zero (optional peers for AWS/GCP/Azure SDKs) | [[key-management]] | `crypto-kms-v<semver>` |
| `haechi-auth-jwt` | `0.3.0` | `>=0.8.0 <2.0.0` | zero | [[identity-and-auth]] | `auth-jwt-v<semver>` |
| `haechi-auth-oidc` | `0.2.0` | `>=0.8.0 <2.0.0` (+ `haechi-auth-jwt >=0.3.0 <2.0.0`) | zero | [[oidc-session-broker]] | `auth-oidc-v<semver>` |
| `haechi-dashboard` | `0.2.0` | `>=0.8.0 <2.0.0` | zero | [[dashboard-audit-viewer]] | `dashboard-v<semver>` |

All four peer upper bounds widened to `<2.0.0` in PR0 (#46) so core `1.0.0` keeps installing against them; later satellites may raise their lower bound when they import a newer frozen core export (for example `haechi-crypto-kms@0.3.0` requires core 1.7.0 for `canonicalizeCryptoAad`). The `check-satellite-peer-ranges.mjs` preflight gate enforces that the in-repo core version satisfies every satellite range. Each satellite has its own per-package publish workflow (`.github/workflows/<name>-publish.yml`), guarded `if: startsWith(tag, '<prefix>-v')` + a strict `^<prefix>-v[0-9]+\.[0-9]+\.[0-9]+$` regex + tag-version-must-equal-package-version, so the four workflows (and core's `v*`) never cross-fire.

### 0.9 satellite additions

- **`haechi-auth-jwt` 0.1.1 → 0.2.0** — *additive, behavior-preserving*: exports a reusable JWS verifier `createJwtVerifier` (carved out of `createJwtAuthProvider`'s internals) and `isBlockedAddress`. `createJwtAuthProvider` is reimplemented on the verifier and unchanged externally (all 0.8 tests green). The minor bump is mandatory because the publish workflow's tag==package-version gate requires it.
- **`haechi-auth-oidc` 0.1.0** (new) — interactive OIDC session broker ([[oidc-session-broker]]). Dual peer `{ haechi: ">=0.8.0 <1.0.0", "haechi-auth-jwt": ">=0.2.0 <1.0.0" }` — core peer stays `>=0.8.0` (uses only `buildExternalIdentity`; not over-tightened), auth-jwt peer is `>=0.2.0` for the verifier export. Reuses auth-jwt's `isBlockedAddress` (the auth ecosystem shares **one** SSRF predicate).
- **`haechi-dashboard` 0.1.0** (new) — zero-dep read-only audit viewer ([[dashboard-audit-viewer]]). Peer `{ haechi: ">=0.8.0 <1.0.0" }`, own `haechi-dashboard` bin. Imports only `haechi/audit` + `haechi/proxy` from core; no peer dependency on auth-oidc (the `sessionGuard` is injected). Ships its own tiny rate limiter and loopback predicate because proxy's `createRateLimiter`/`isLoopbackHost` are private — a documented deviation that keeps 0.9 with **no core change**.
- **`haechi-crypto-kms` 0.1.1 → 0.2.0** — additive GCP/Azure/Vault backends (see [[key-management]]). New subpath exports `./gcp` (optional peer `@google-cloud/kms`), `./azure` (optional peers `@azure/keyvault-keys` + `@azure/identity`), `./vault` (**zero optional-peer** — Vault Transit over `node:` `fetch`). The Vault backend keeps its **own** satellite-local `isBlockedAddress` rather than runtime-depend on `haechi-auth-jwt` — a key-custody package must not pull in the auth ecosystem just for an IP predicate; a **dev-only cross-package parity test** (auth-jwt as a `devDependency`) asserts the two copies agree on the range table so they can't drift, while the published tarball stays zero runtime dependency. The stale hard-coded provider `version` field was removed (it reported `"0.1.0"` while the package was `0.1.1`). Reuses the existing `crypto-kms-v<semver>` tag + Trusted Publisher.

The two core touches are both additive, behavior-preserving: auth-jwt's verifier export and `packages/audit` adding broker token/claim keys to `FORBIDDEN_KEYS`. `assertSafeProxyBind` is reused from `haechi/proxy` as already exported (no relocation). Core stays zero runtime dependency; the packed-manifest + satellite-packaging gates are unaffected.

## npm workspaces mechanic (verified 2026-06-10, design 0.8)

The monorepo conversion is a **0.8** step (earlier wiki text said 0.7 — corrected; no second package actually shipped before 0.8). The "least-invasive" layout was validated empirically because the obvious approach silently fails:

- ❌ `workspaces: ["satellites/*"]` + satellite `peerDependencies: { haechi: ">=0.8.0" }` → npm resolves the peer range from the **registry** (`ETARGET`), never symlinks root, satellite `import "haechi/crypto"` throws `ERR_MODULE_NOT_FOUND`. The root project is **not** a workspace member by default.
- ✅ Root lists **itself**: `workspaces: [".", "satellites/*"]` (the `"."` is what creates `node_modules/haechi → ..`). Satellites declare **both** `peerDependencies: { haechi: ">=0.8.0 <1.0.0" }` (consumer contract) **and** `devDependencies: { haechi: "*" }` (links the local workspace in dev; `npm pack` strips devDeps so consumers never see it).
- Zero-dep is defended by inspecting the **packed** `package.json` (not the installed-tree SBOM, which passes vacuously): assert the tarball manifest's `dependencies` is empty, and that no `satellites/` paths appear. Negatively tested so the gate isn't a vacuous pass.
- Consequence: the satellite imports `canonicalize` from `haechi/crypto` (the pre-0.8 reference inlined it only because nested-package self-resolution failed); a conformance test asserts byte-for-byte AAD-canonicalization parity.

**Shipped — PR1 (workspaces conversion) + PR2 (`haechi-crypto-kms` AWS client):**

- `haechi-crypto-kms` (`satellites/crypto-kms/`) is the first satellite: in-memory client + a real AWS KMS client at `haechi-crypto-kms/aws` (`wrap`=KMS `Encrypt`, `unwrap`=`Decrypt`, `deriveHmacKey`=HKDF-SHA256 over a KMS-decrypted root). Both clients use **HKDF-SHA256** with the same domain-separated info, so they derive identical HMAC keys from the same root (cross-backend parity, tested).
- **`@aws-sdk/client-kms` is an OPTIONAL peer dependency** (decided 2026-06-10, overriding the design draft's "satellite's own dependency"): imported lazily only when no `client` is injected. The monorepo `npm ci` never pulls the AWS SDK; the 8+ AWS tests run SDK-free by injecting a faithful keyId-aware KMS-ops mock. Consumers add the SDK only for the AWS path.
- **Two packaging gates** in `release:preflight`: `check-core-packaging` (core tarball: no `satellites/` leak, zero runtime deps) and `check-satellite-packaging` (each satellite tarball: zero runtime deps so the optional peer never becomes a hard dep, all `files`/`exports` present, no `*.test.mjs` leak). Both inspect the **packed** manifest and are negatively unit-tested.
- **Per-package publish** ([[release-roadmap]]): core publishes on `v<semver>` (`npm-publish.yml`), the satellite on `crypto-kms-v<semver>` (`crypto-kms-publish.yml`), each guarded by an `if: startsWith(tag, …)` + strict regex + (satellite) tag-version-must-equal-package-version, so the two workflows never cross-fire. Each binds to its own npmjs.com Trusted Publisher (workflow filename). Bootstrap order (reserve name → configure TP → tag) is in `release-process.md`.

## Rejected: curl|sh installer (2026-06-10)

For a security product whose pitch is provenance and supply-chain hygiene, `curl | sh` sends exactly the wrong signal, and a Node CLI gains nothing from it (Node must exist anyway; `npx haechi` covers no-install use). Revisit at 0.6 alongside signed release artifacts as a **checksum/signature-verifying** installer for standalone (Node SEA) binaries. Nearer-term alternative: a container image on GHCR (fits the sidecar/gateway deployment shape, cosign-signable).
