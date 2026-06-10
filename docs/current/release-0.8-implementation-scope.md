# Haechi 0.8 Implementation Scope

- Status: Draft 0.3 (design — not yet implemented)
- Date: 2026-06-10
- Target version: 0.8.0 (after 0.7.0)
- Type: ecosystem foundation

## 1. Release Goal

Stand up the `haechi-*` package ecosystem: convert the repo to an npm workspaces monorepo and publish the first two satellites — `haechi-crypto-kms` (promoting the 0.7 reference) and `haechi-auth-jwt` (JWKS bearer verification), both unscoped (the `@haechi` scope is taken; no org needed). This realizes operational key custody as an installable package and grows the auth ecosystem without touching core's zero-dependency posture.

**Scope decision (2026-06-10):** 0.8 is the **packaging foundation + satellites**. The `haechi-dashboard` read-only audit viewer (a UI build) and full interactive `haechi-auth-oidc` move to **0.9** so 0.8 stays code-light and focused on the monorepo + two headless-friendly adapters.

Core (`haechi`, unscoped) stays **zero runtime dependency**. Satellite dependencies (e.g. an AWS SDK) live in the satellite's own `package.json` only and never enter core's tarball or SBOM.

## 2. Scope

### 2.1 npm workspaces monorepo (verified resolution mechanic)

The naive layout (`"workspaces": ["satellites/*"]` + a satellite peer range `"haechi": ">=0.8.0"`) **does not work** and was rejected after empirical testing: npm treats the unmet peer range as a registry lookup (`ETARGET: no matching version for haechi@>=0.8.0`), never symlinks the root project into `node_modules/haechi`, and the satellite's `import "haechi/crypto"` throws `ERR_MODULE_NOT_FOUND`. The root project is **not** a workspace member by default, so npm never links it.

The verified working layout:

- **Root lists itself as a workspace member:** `"workspaces": [".", "satellites/*"]`. The `"."` entry is what makes npm create the `node_modules/haechi → ..` symlink so satellites resolve core. Without it, satellites fall back to the registry.
- **The repo root remains the published `haechi` package** — its `exports`, `bin`, and `files` allowlist are unchanged. The only `package.json` delta is the added `workspaces` field and the version bump. Satellites are **not** in core's `files`, so they never ship inside the `haechi` tarball (verified: a root `npm pack --dry-run` lists only the `files` allowlist; `satellites/` is excluded).
- **Satellites declare a dual dependency on core:**
  - `"peerDependencies": { "haechi": ">=0.8.0 <1.0.0" }` — the contract a *consumer* installs against, so the satellite reuses the consumer's single `haechi` instance (one crypto/identity surface, no duplicate copies).
  - `"devDependencies": { "haechi": "*" }` — the mechanism that makes npm link the **local workspace** during monorepo development/CI instead of resolving the peer range from the registry. `npm pack` strips devDependencies from the published tarball, so the consumer-facing manifest carries only the peer range — the `*` devDep is invisible downstream. (A repo/source scanner reading `satellites/*/package.json` will still see it; that source-vs-artifact difference is expected and harmless.)
  - **Consumer peer-mismatch behavior:** installing a published satellite against an *incompatible* `haechi` (e.g. `haechi@0.7.0` already present) yields an npm `ERESOLVE` **warning**, not a hard failure; the consumer must upgrade `haechi` (or `--legacy-peer-deps` at their own risk). The satellite does not function correctly against an out-of-range core.
- Satellites import core by subpath (`haechi/crypto`, `haechi/auth`, `haechi/runtime`); these resolve through the workspace symlink in dev and through the consumer's installed `haechi` in production.
- `examples/crypto-kms-reference/` is **promoted** to `satellites/crypto-kms/`. The reference example inlined `canonicalize` because its nested `package.json` could not self-resolve `haechi/crypto` pre-workspaces; **under workspaces that import resolves**, so the satellite imports `canonicalize` from `haechi/crypto` rather than carrying a copy (avoiding AAD-canonicalization drift between core and satellite). The old `examples/` directory keeps a short README pointing at the published package. A conformance test asserts the satellite's AAD canonicalization is **byte-for-byte identical** to `haechi/crypto` (not merely semantically equivalent).
- **Lock file:** converting to workspaces regenerates `package-lock.json` with workspace-resolved entries (including the root self-member). The regenerated lock file is committed; CI uses `npm ci` (which fails on a stale/missing lock), so the conversion PR must commit the fresh lock.

**CI strategy (avoid double-runs):** root CI runs `node --test` directly from the root, which discovers `satellites/**/*.test.mjs` automatically (workspace symlinks make their `haechi/*` imports resolve). CI does **not** use `npm test --workspaces` (which would recurse into the root self-member and re-run the suite). Each satellite keeps its own `test` script for isolated local runs (`npm test -w haechi-crypto-kms`) only. Verified: root `node --test` runs core + satellite tests once, and the `node_modules/haechi → ..` symlink cycle does not hang the runner (node skips `node_modules`).

**Honest packaging note (was a "byte-stable" claim):** the root tarball is **not** byte-identical to 0.7.0 — `package.json` gains the `workspaces` field and the version bumps, which is expected for any release. The defensible, tested claim is narrower and is enforced by a CI gate (see §6.1): **(a) no satellite files appear in the `haechi` tarball, and (b) the `haechi` tarball's own `package.json` declares zero runtime `dependencies`.** The gate inspects the **packed manifest** (extract `package.json` from `npm pack` output and assert `dependencies` is empty/undefined) — not the installed `node_modules` SBOM, which would pass vacuously today and miss a future runtime-dep leak.

### 2.2 Unscoped `haechi-*` names + per-package trusted publishing

- **Naming (decision 2026-06-10):** the `@haechi` npm org/scope is already taken by a third party, so satellites are published as **unscoped `haechi-*`** names — `haechi-crypto-kms`, `haechi-auth-jwt` (both verified free on npm). This needs **no npm org**, matches the unscoped core `haechi`, and each name is reserved + Trusted-Publisher-bound individually. (Trade-off vs a scope: no namespace grouping/defence; the `haechi-` prefix is the convention.)
- Each satellite is published with the **same OIDC trusted-publishing + sigstore + SHA256SUMS** path proven in 0.7 — its own npmjs.com Trusted Publisher link and a tag-triggered publish workflow.
- **Satellite `package.json` requirements (do not inherit from root):** each satellite still sets its own `"publishConfig": { "access": "public", "provenance": true }`. Unscoped packages are public by default, so `access: public` is belt-and-suspenders; `provenance: true` and not inheriting the root's `publishConfig` are the load-bearing parts. Post-publish, the runbook verifies `npm view haechi-<pkg> access` reports `public`.
- **Tag namespacing + workflow guards (avoid mis-triggers and collisions):**
  - Core release tags: `v<semver>` (e.g. `v0.8.0`). The root publish workflow triggers on `push: tags: ['v[0-9]*.[0-9]*.[0-9]*']`. Because GitHub's tag glob treats `.` literally and `[0-9]*` loosely (it would also match `v1.2.3.4` or `v1a.2.3`), the workflow **re-validates** the tag against a strict `^v[0-9]+\.[0-9]+\.[0-9]+$` regex in a pre-publish step and fails closed on a non-match.
  - Satellite tags are **prefixed**: `crypto-kms-v<semver>`, `auth-jwt-v<semver>`. Each satellite workflow triggers only on its own prefix glob and likewise re-validates against `^<prefix>-v[0-9]+\.[0-9]+\.[0-9]+$`.
  - Each workflow re-asserts the package directory it publishes (`npm publish -w <dir>`) so a mistagged push can't publish the wrong package. The Trusted Publisher on npmjs.com is bound to a **specific workflow filename** — renaming the workflow without updating the npm config breaks OIDC auth (documented as a failure mode in the runbook, with a package→workflow-filename→tag-glob mapping table).
- **Independent semver** per satellite (a satellite patch never bumps core). Satellites start at `0.1.0`. **Pre-1.0 contract:** satellites follow standard npm semver where a `0.x` **minor** bump may carry breaking changes; consumers should pin `major.minor` (e.g. `haechi-crypto-kms@~0.1`). Satellites are pre-stable until their own `1.0.0`.
- **Bootstrapping the first publish (no org needed):** order per satellite — (1) on npmjs.com, **configure the Trusted Publisher** for the (not-yet-published) unscoped name, linking the repo + exact workflow filename; (2) push the satellite's first tag → the workflow's OIDC publish creates `0.1.0` with provenance and **claims the name** on first publish. No manual `npm publish` from a laptop is required (matches the 0.7 trusted-publishing posture). Because the names are unscoped and currently free, there is no org-membership prerequisite.

### 2.3 `haechi-crypto-kms` (publish + real KMS client)

- Promote the 0.7 reference (`createKmsCryptoProvider` envelope encryption + `createInMemoryKms`) into the published package, switching its inlined `canonicalize` to `import { canonicalize } from "haechi/crypto"` (§2.1). The existing `kms` client interface (`keyId` / `wrap` / `unwrap` / `deriveHmacKey`) is **unchanged**, so the promoted provider and in-memory client stay byte-for-byte and their 0.7 tests carry over.
- Add a **real AWS KMS client** at `haechi-crypto-kms/aws`: `createAwsKmsClient({ keyId, region, client, hmacRootCiphertext })`. It implements the same `kms` interface: `wrap` = KMS `Encrypt` of a CSPRNG-generated 32-byte data key, `unwrap` = KMS `Decrypt` (envelope encryption — the master key never leaves KMS); `deriveHmacKey(domain)` = **HKDF-SHA256** over a single KMS-`Decrypt`ed 32-byte root (`hmacRootCiphertext`, cached), domain-separated — deterministic with no per-token network call. With no `hmacRootCiphertext`, `deriveHmacKey` throws and the provider is encrypt-only (valid via `requireHmac:false`).
- **`@aws-sdk/client-kms` is an OPTIONAL peer dependency, not a hard dependency** (decision 2026-06-10, revising the earlier "satellite's own dependency" wording). It is imported **lazily** only when no `client` is injected, so: the monorepo `npm ci`/CI never pulls the (large) AWS SDK; consumers on the in-memory or an injected client never install it; and `core` is trivially unaffected. The published satellite declares it under `peerDependencies` + `peerDependenciesMeta.optional`. This keeps the satellite dependency-light while still offering a real backend.
- The satellite's CI runs `assertCryptoProviderConformance` (imported from `haechi/crypto` via the workspace symlink) against the in-memory client **and** the AWS client driven by an **injected mock** of the two KMS ops (`encrypt`/`decrypt`) — **no SDK, no network**. The mock is a faithful envelope (AES-256-GCM under a per-mock master key): `Decrypt` returns the plaintext only for a blob this key wrapped and **rejects** a blob wrapped by a different key (cross-key isolation) or a corrupted blob. A trivial always-succeeds stub is insufficient; the suite exercises these rejection paths plus HMAC determinism/domain-separation. Live `createAwsKmsClient` validation against a sandbox KMS key is an **out-of-CI integration test** (documented, not gating).

### 2.4 `haechi-auth-jwt` (JWKS bearer verification, dependency-light)

`createJwtAuthProvider({ issuer, audience, jwksUri, cryptoProvider, algorithms, clockSkewSeconds, claimMappings })` implements the `authProvider` contract for a **headless** gateway. It is implementable with `node:` builtins only (no `jose`): JWKS fetched via global `fetch`, JWK→key via `crypto.createPublicKey({ key: jwk, format: "jwk" })`, signatures verified via `crypto.verify`.

**Implementation note — ES256 signature encoding (verified):** a JWS ES256 signature is raw `R‖S` (IEEE-P1363, 64 bytes for P-256), but `node:crypto.verify` defaults to **DER** for EC keys and returns `false` for a raw signature — silently rejecting every valid ES256 token. The verifier MUST pass `dsaEncoding: "ieee-p1363"` for the EC algorithms. (Empirically confirmed: default DER ⇒ `false`; `ieee-p1363` ⇒ `true`.) This is an acceptance criterion, not an option.

**Security spec (mandatory — these are acceptance criteria, not options).** Concrete constants below are *decisions*, not implementation discretion.

- **Algorithm selection is server-side, never from the token.** The verifier picks the algorithm from the configured `algorithms` allowlist (default `["RS256","ES256"]`) and the JWK's `kty`/`crv`. The token's `alg` header is checked for *membership* in the allowlist **before** key selection; it never selects the verification routine.
  - **Reject `alg: "none"`** unconditionally.
  - **Block alg-confusion:** never feed an RSA public key into an HMAC verify. HMAC family (`HS*`) is **not allowed** by default; a JWKS-sourced public key is only ever used with its matching asymmetric algorithm.
  - **`kid` is required**; the signing key is selected by `kid` from the JWKS, not by trying every key.
  - **RSA key-strength floor:** an RSA JWK with modulus `< 2048` bits is rejected as invalid.
  - **JWK usage intent:** if a JWK carries `use`, it must be `sig`; if it carries `key_ops`, it must include `verify`/`sign` and must not include `encrypt`/`decrypt`. Otherwise reject.
  - **Header `typ` / no JWE:** if `typ` is present it must be `JWT`; encrypted (JWE) tokens are rejected unconditionally — only JWS is accepted.
- **Claims are mandatory and fully validated:**
  - `iss` must equal the configured `issuer`.
  - `aud` (token) may be a string or an array of strings (RFC 7519); the configured `audience` must equal the string or be a member of the array — exact, case-sensitive match.
  - `sub` is required and must be a non-empty string (it is the input to `subjectHash`).
  - `exp` and `nbf` are **required**. `exp`: reject when `now > exp + clockSkewSeconds`. `nbf`: reject when `now < nbf - clockSkewSeconds`. A token missing `exp` is rejected. `iat` is sanity-checked if present.
  - **`clockSkewSeconds`** default `60`, **maximum `300`** — construction rejects a value `> 300` (a larger skew would gut expiry validation).
- **JWKS fetching is SSRF-hardened:**
  - `issuer` must be a valid **HTTPS URL**; `jwksUri` must be HTTPS and its **hostname must exactly equal the `issuer` hostname** (port excluded). 0.8 supports **single-origin issuers only** — IdPs that serve JWKS from a different host than the issuer identifier (some CDN-fronted setups) are explicitly out of scope for 0.8 and rejected at construction. A non-URL issuer (URN-style) is rejected at construction with a clear error.
  - Requests to private/loopback/link-local ranges and cloud-metadata endpoints are refused: `127.0.0.0/8`, `::1`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16` (incl. `169.254.169.254`), `fe80::/10`. Refusal is at fetch time after DNS resolution (guard against rebinding), with a fetch timeout.
  - **JWKS response bounds:** reject a response body `> 1 MiB`; `JSON.parse` is guarded against pathological nesting (depth bound). JWT segments are decoded as **strict base64url** (`[A-Za-z0-9_-]`, no padding) before `JSON.parse`.
- **JWKS cache is bounded and DoS-resistant:** keys are cached with a TTL; an **unknown `kid` does not trigger an unbounded refetch** — at most one full JWKS refresh per **60 s cooldown**, so a flood of forged `kid`s can't become a fetch storm against the IdP.
- **Identity is PII-safe (fail-closed):** `cryptoProvider` is **required** and must expose `hmac`; if absent, the provider constructor throws (it cannot produce a PII-safe identity). `subjectHash` / `issuerHash` are keyed **HMAC-SHA-256** (`haechi:identity:hash:v1`), hex-encoded (64 chars) — raw `sub` / `iss` are never stored or logged. `scopes` come from a configured scope claim (`scp` / `scope`); `labels` from an allowlisted claim mapping only.
- **Fail-closed everywhere:** any verification error → `authenticate` returns `null` (deny), never throws into the request path; no token detail is echoed to the client.

Wired via **injection** (`createRuntime(config, { authProvider: createJwtAuthProvider(...) })`); `auth.provider: external`. Dynamic loading stays banned until the 1.0 plugin sandbox.

### 2.5 Release process for the monorepo

- The existing root workflow keeps publishing `haechi` (guarded to the `v*` tag glob + strict regex re-validation).
- Each satellite has its own prefixed-tag publish workflow reusing the 0.7 signed-artifacts steps (pack → checksum → attest → publish → upload), scoped to its own directory, each bound to its own Trusted Publisher (specific workflow filename).
- The per-package release runbook (`release-process.md`) documents: tag conventions + the package→workflow-filename→tag-glob mapping table, the Trusted Publisher bootstrap order (reserve → configure → tag), the workflow-rename failure mode, and post-publish verification (provenance, `npm view ... access`).

## 3. Explicit non-scope (deferred to 0.9+)

- `haechi-dashboard` read-only audit viewer (UI build, its own tech-stack decision).
- `haechi-auth-oidc` full interactive OIDC (authorization-code flow) — `haechi-auth-jwt` covers the headless case first.
- `haechi-auth-jwt` multi-origin/CDN-fronted JWKS (issuer host ≠ JWKS host).
- `haechi-classifier-*` ML/heuristic classifier plugins.
- `haechi-crypto-kms` Vault/GCP/Azure backends (AWS only in 0.8).
- Dynamic loading of satellites (1.0 plugin sandbox).

The risk-register and roadmap are updated to move `haechi-auth-oidc` and `haechi-dashboard` out of the 0.8 row and into a new **0.9** row, so the public docs match this scope.

## 4. Backward compatibility

Core behavior is unchanged: the root package's `exports`, `bin`, `files`, and zero-dep runtime posture are identical. Adding `workspaces` (including the `"."` self-entry) to the root `package.json` is inert for anyone installing `haechi` as a single dependency. Existing config and APIs are untouched; satellites are purely additive and opt-in.

## 5. 1.0 relationship

0.8 does not itself close a 1.0 blocker, but it **realizes operational key custody as an installable, attested package** (`haechi-crypto-kms`) and proves the satellite model end-to-end. The remaining 1.0 gates stay: API-stability freeze and plugin sandbox + real-environment validation.

## 6. Test criteria (mapped to the PR breakdown)

### 6.1 PR1 — workspaces conversion (no new published package)

- Root `npm install` exits 0 with **no ERESOLVE/ETARGET**; `node_modules/haechi` is the workspace symlink; the committed `package-lock.json` makes `npm ci` succeed on a fresh checkout.
- A satellite test that does `import { ... } from "haechi/crypto"` runs green under root `node --test`.
- **No-leak + zero-dep gate:** core `npm pack --dry-run` contains **no `satellites/` paths**; the **packed** `haechi` `package.json` (extracted from the tarball) has empty/undefined `dependencies`. The gate is **negatively tested**: temporarily adding `satellites/` to core's `files`, or a runtime dep to core's `package.json`, makes the gate fail with a clear error (so the gate isn't a vacuous pass).
- In-memory crypto provider (promoted 0.7 code) passes `assertCryptoProviderConformance` through the workspace symlink, including the byte-for-byte `canonicalize` parity check vs `haechi/crypto`.

### 6.2 PR2 — `haechi-crypto-kms` (real AWS client)

- In-memory **and AWS** clients (the AWS one driven by an **injected mock** of the KMS `encrypt`/`decrypt` ops — no SDK, no network) pass `assertCryptoProviderConformance`, including the cross-key/corrupted-blob **rejection** paths and HMAC determinism/domain-separation; end-to-end through `createRuntime` (encrypt + tokenization round-trip).
- `createAwsKmsClient` without a `keyId` throws; with no `hmacRootCiphertext`, `deriveHmacKey` throws and the provider passes conformance as encrypt-only (`requireHmac:false`).
- The published manifest sets `publishConfig.access: public` and declares `@aws-sdk/client-kms` under `peerDependencies` + `peerDependenciesMeta.optional` (NOT a runtime `dependency`); the published satellite tarball has `dependencies: {}`, and core's tarball stays zero-dep (the §6.1 gate still passes).
- A satellite publish workflow (`crypto-kms-v<semver>`) exists with the 0.7 signed-artifacts path; the core workflow is guarded so a satellite release tag never publishes `haechi`.

### 6.3 PR3 — `haechi-auth-jwt` (security gates)

- A valid RS256/ES256 JWT (test-key-signed, stub JWKS) authenticates into a PII-safe identity with **no raw `sub` in the audit**; `subjectHash`/`issuerHash` are 64-hex-char HMAC-SHA-256.
- Each of the following is **denied**: `alg:"none"`; an `HS256` token forged with the RSA public key (alg-confusion); a JWE/`typ` mismatch; expired (`exp`); not-yet-valid (`nbf`); missing `exp`; missing/empty `sub`; wrong-`aud` (string and array forms); wrong-`iss`; unknown-`kid`; bad-signature; an RSA JWK `< 2048` bits; a JWK with `use:"enc"`/`key_ops:["encrypt"]`.
- Construction rejects: a non-HTTPS or cross-origin `jwksUri`; a non-URL `issuer`; `clockSkewSeconds > 300`; a missing `cryptoProvider.hmac`. A `jwksUri` resolving to `127.0.0.1`, `169.254.169.254`, `::1`, or any RFC1918 CIDR is rejected.
- An unknown-`kid` flood triggers **exactly one** JWKS refetch within the 60 s cooldown; a JWKS response `> 1 MiB` is rejected.

### 6.4 All satellites

- Each publishes with provenance + sigstore attestation, verified post-release like 0.7.

## 7. Suggested PR breakdown (stacked)

1. **Workspaces conversion** (no new published package): root `workspaces: [".", "satellites/*"]`, bump root to **0.8.0**, move `crypto-kms` to `satellites/crypto-kms/` with `peer + dev` core deps, switch the inlined `canonicalize` to `haechi/crypto` (+ parity test), repoint tests, commit the regenerated `package-lock.json`, add the **no-leak + zero-dep CI gate** (with negative tests), root CI runs all workspace tests via root `node --test`. → §6.1
2. **`haechi-crypto-kms`:** real AWS KMS client (satellite-only `@aws-sdk/client-kms` dep) + faithful mocked-AWS conformance CI + `publishConfig` + prefixed-tag publish workflow (strict regex guard) + Trusted Publisher bootstrap. → §6.2
3. **`haechi-auth-jwt`:** JWKS verification provider implementing the full §2.4 security spec + identity mapping + the §6.3 security-gate tests + `publishConfig` + prefixed-tag publish workflow. → §6.3
4. **0.8.0 release cut:** docs EN/KO, packaging/roadmap/risk-register (move OIDC+dashboard to 0.9)/api-stability, wiki, npm org / Trusted Publisher runbook (mapping table + bootstrap order + failure modes).
