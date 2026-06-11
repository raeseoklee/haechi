# Haechi API Stability Policy

- Status: Draft 0.1
- Date: 2026-06-10
- Target version: 0.7.0

## 1. Version Interpretation

0.x releases are developer previews. Public exports are available for use but are not considered stable API.

| Version range | Meaning |
|---|---|
| `0.3.x` | local inference/proxy safety patch line |
| `0.4.x` | token round-trip and adoption line |
| `0.5.x` | streaming hardening target |
| `0.6.x` | auth and operational controls target |
| `1.0.0` | First stable candidate at which an API compatibility contract may be declared |

## 2. Change Policy

| Change type | 0.x handling |
|---|---|
| Strengthening security defaults | Allowed in patch |
| Blocking unsafe config | Allowed in patch |
| Removing or renaming exports | Allowed in minor; migration note required in README |
| Changing policy action semantics | Requires minor or higher |
| Changing audit schema | Requires minor or higher |
| Changing crypto envelope format | Requires minor or higher; backward handling required |

## 3. Experimental exports

The following exports are treated as preview in 0.4.0.

- `haechi/runtime`
- `haechi/proxy`
- `haechi/protocol-adapters`
- `haechi/privacy-profiles`
- `haechi/plugin`
- `haechi/mcp-stdio` `wrapMcpChild`
- `haechi/token-vault` `detokenize`, deterministic tokenization options
- `injection` detection type and its heuristic rules
- `identity` audit field and the `authProvider` contract (reserved in 0.4, implemented in 0.6 — shape may change until then)
- `status` / `audit-verify` CLI output shapes
- `haechi/stream-filter` (`inspectResponseStream`, path helpers) and `createStreamProtector` (streaming inspection internals)
- `haechi/auth` (`createBearerAuthProvider`, token store, `buildIdentity`, `buildExternalIdentity`) and the `authProvider` contract
- `assertCryptoProviderConformance` and the hardened cryptoProvider contract (envelope base shape + provider extensions)
- `audit.anchor` config and `verifyAuditChain(path, { anchorPath })`
- `scripts/release-checksums.mjs` (SHA256SUMS generate/verify)
- `policy.profiles`/`policy.profileBinding`/`modelAllowlist`/`rate` and the `identity`/`profile` audit fields

## 4. Migration note criteria

A migration note is added to `docs/current/release-*.md` or the README whenever any of the following changes occur.

- Adding or removing a config key
- Changing default enforcement behavior
- Adding or removing a CLI flag
- Changing an audit event field
- Changing the token format
- Changing the plugin manifest schema

## 5. Satellite packages (`haechi-*`)

Satellites (e.g. `haechi-crypto-kms`, `haechi-auth-jwt`, `haechi-dashboard`, `haechi-auth-oidc`) version **independently** of core — a satellite release never bumps `haechi`, and vice versa.

- **Pre-1.0:** satellites follow npm semver where a `0.x` **minor** bump may carry breaking changes; pin `major.minor` (e.g. `haechi-crypto-kms@~0.2`). Each is pre-stable until its own `1.0.0`.
- **Core compatibility** is expressed as a `peerDependencies` range (`"haechi": ">=0.8.0 <1.0.0"`) — a satellite reuses the consumer's single installed `haechi`, so there is one crypto/identity surface. `haechi-auth-oidc` additionally peer-depends on `haechi-auth-jwt` (`">=0.2.0 <1.0.0"`) so the two share one audited JWS/JWKS verification path.
- **Heavy backends are optional peers.** `haechi-crypto-kms` declares its SDK backends (`@aws-sdk/client-kms`, and in 0.2.0 `@google-cloud/kms`, `@azure/keyvault-keys`, `@azure/identity`) under `peerDependencies` + `peerDependenciesMeta.optional` and imports them lazily, so consumers who do not use a given path never install it and core stays zero-dependency. The `./vault` backend uses `node:` `fetch` only (no optional peer). A satellite's published tarball always declares **zero runtime `dependencies`** (CI-gated by `check-satellite-packaging`).
- **Pre-1.0 satellite exports** are preview and may change before each satellite's own `1.0.0`:
  - `haechi-crypto-kms` (0.8 → 0.2.0): `createKmsCryptoProvider`, `createInMemoryKms`, the `./aws` `createAwsKmsClient`, and the new 0.2.0 subpaths `./gcp` (`createGcpKmsClient`), `./azure` (`createAzureKmsClient`), `./vault` (`createVaultKmsClient`).
  - `haechi-auth-jwt` (0.2.0): `createJwtAuthProvider` (0.8, behavior-preserving) plus the additive `createJwtVerifier` (reusable JWS verifier primitive) and `isBlockedAddress` (SSRF range predicate, reused by `haechi-auth-oidc`).
  - `haechi-dashboard` (0.1.0, new): `createDashboardServer`, `normalizeDashboardConfig`.
  - `haechi-auth-oidc` (0.1.0, new): `createOidcSessionBroker`, `normalizeOidcConfig`.
