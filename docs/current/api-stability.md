# Haechi API Stability Policy

- Status: Draft 0.2 (1.0 contract — the API freeze)
- Date: 2026-06-11
- Target version: 1.0.0

## 1. Version Interpretation

0.x releases were developer previews: public exports were usable but **not** a stable API. **1.0.0 is the first stable release** — it declares the contract below and adopts **strict semver** (see §2). The `tests/api-contract.test.mjs` freeze guard pins the frozen surface; a removed/renamed frozen export, audit field, or config key fails CI (the conscious signal of a breaking change).

| Version range | Meaning |
|---|---|
| `0.3.x` | local inference/proxy safety patch line (preview) |
| `0.4.x` | token round-trip and adoption line (preview) |
| `0.5.x` | streaming hardening target (preview) |
| `0.6.x` | auth and operational controls target (preview) |
| `0.7.x` – `0.9.x` | dashboard / KMS / OIDC satellites + pre-1.0 hardening (preview) |
| `1.0.0` | **First stable release.** The API contract in §2 is declared frozen under strict semver. |

## 2. The 1.0 stability contract

### 2.1 Frozen public surface (IN / OUT)

Every `package.json` `exports` subpath and the CLI is classed. There is no silent "0.x is preview" latitude anymore.

| Surface | 1.0 status |
|---|---|
| `haechi` / `haechi/core` — `createHaechi().protectJson`, `createHaechi().createStreamProtector`, `collectStringEntries`, `pathToString`, `safePathToString`, `shapeOnly`, `summarize` | **FROZEN** (breaking change = major) |
| `haechi/runtime` — `createRuntime`, `normalizeConfig` (config shape), `defaultConfig`, `loadConfig`, `writeDefaultConfig`, `isValidPort`, `DEFAULT_CONFIG_PATH` | **FROZEN** |
| `haechi/auth` — the `authProvider` contract, `buildIdentity`, `buildExternalIdentity`, `validateLabels`, `createBearerAuthProvider`, the token store (`readAuthStore`, `addToken`, `listTokens`, `revokeToken`), `DEFAULT_ALLOWED_LABEL_KEYS` | **FROZEN** |
| `haechi/crypto` — the `cryptoProvider` contract, `assertCryptoProviderConformance`, `canonicalize`, `createLocalCryptoProvider`, `initLocalKeyFile` | **FROZEN** |
| `haechi/audit` — the audit **event schema** (§2.3), `verifyAuditChain`, `sanitizeAudit`, `createJsonlAuditSink`, `readAuditSummary`, `FORBIDDEN_KEYS` | **FROZEN** |
| `haechi/policy` — `buildPolicy`, `createPolicyEngine`, `createPolicyProfiles`, `validatePolicy`, `ACTION_STRENGTH` (action ordering) | **FROZEN** |
| `haechi/filter` — `createDefaultFilterEngine`, `detectEntry`, and the **rule/detection shape** | **FROZEN** |
| `haechi/token-vault` — `createLocalTokenVault`, `readVault`, the token format, and the reveal-governance contract | **FROZEN** |
| `haechi/protocol-adapters` — `createProtocolAdapter`, `knownProtocolAdapters`, and the adapter classification contract | **FROZEN** |
| `haechi/plugin` — `validatePluginManifest`, `validatePluginManifestFile`, the manifest schema, and the 1.0 signed-plugin sandbox surface | **FROZEN** |
| `haechi/proxy` — `createHaechiProxy`, `assertSafeProxyBind`, `DEFAULT_PROXY_PORT` | **FROZEN BEHAVIOR + wire/contract** (human-readable log/error **text** may change) |
| `haechi/mcp-stdio` — `protectMcpJsonRpcMessage`, `runMcpStdioFilter`, `wrapMcpChild` | **FROZEN BEHAVIOR + wire/contract** |
| `haechi/stream-filter` — `inspectResponseStream`, `getByPath`, `setByPath`, `buildPathObject` | **FROZEN BEHAVIOR + wire/contract** |
| `haechi/policy-bundle` — `signPolicyBundle(File)`, `verifyPolicyBundle(File)`, `loadVerifiedPolicyBundleFileSync` | **FROZEN BEHAVIOR + wire/contract** (the signed-bundle format is frozen) |
| `haechi/privacy-profiles` — `listPrivacyProfiles`, `getPrivacyProfile`, `applyPrivacyProfile` | **FROZEN BEHAVIOR + wire/contract** |
| **CLI** — `bin/haechi.mjs` command names, flags, **exit codes**, and machine-readable (JSON) output | **FROZEN BEHAVIOR + wire/contract**; human-readable help/log/status **text** may still change (not part of the contract) |

**FROZEN** = the export name, signature, and behavior are part of the major-versioned contract. **FROZEN BEHAVIOR + wire/contract** = the wire format, exit codes, machine-readable output, and security behavior are frozen, but the human-readable CLI/log **text** is explicitly *not* part of the contract and may change in a minor/patch.

### 2.2 Strict semver + deprecation policy

From 1.0 the "0.x minor may break" latitude **ends**. Versioning is strict semver:

| Change type | Release |
|---|---|
| Breaking change (remove/rename a frozen export, field, or config key; change a frozen signature or wire format) | **major** |
| Additive change (new export, new optional config key, new additive audit field) | **minor** |
| Bug fix / hardening a default value (no shape change) | **patch** |

**Deprecation policy.** A deprecated export / audit field / config option is:

1. **kept for ≥ 1 minor** after deprecation,
2. shipped with a **documented migration note** (in `docs/current/release-*.md` or the README), and
3. wired to emit a **one-time runtime `process.emitWarning`** with a **stable `code` prefix `HAECHI_DEPRECATION_*`** (e.g. `HAECHI_DEPRECATION_CONFIG_<key>`, `HAECHI_DEPRECATION_EXPORT_<name>`). **The warning `code` and its text are themselves part of the contract** — they are stable identifiers a consumer may match, and they only change at the next major.

The deprecated surface is **removed only at the next major**.

**Security exception (the one sanctioned in-minor break).** A change required to close a **disclosed** vulnerability may break or remove a frozen surface **within a minor**, shipped with a **security advisory + a migration path**. This mirrors the long-standing "blocking unsafe config may tighten in a patch" latitude — the security posture is allowed to harden faster than the deprecation window.

### 2.3 Frozen audit event schema (including nested sub-schemas)

The audit event (built in `packages/core/index.mjs` `buildAuditEvent`, integrity-stamped by `packages/audit`) is frozen **including its nested sub-schemas**, not just the top level:

- **top-level**: `{ schemaVersion, id, timestamp, protocol, operation, identity, profile, mode, enforced, blocked, payloadShapeHash, detections, summary, auditIntegrity }`
- `detections[]`: `{ type, ruleId, path, kind, confidence, action, enforced }`
- `identity` (the **PII-safe** projection): `{ id, type, subjectHash, issuerHash, provider }` — `scopes` / `labels` / a raw subject are **NOT** part of the frozen audit identity (the keyed-HMAC `subjectHash`/`issuerHash` are the only subject/issuer surface). Note: the on-disk `identity` object MAY also carry `scopes` and `labels` (7 keys total), but those fields are **not** part of the frozen contract — a consumer of the audit log must not depend on their presence. `identity` is `null` when no auth is configured.
- `summary`: `{ byType, byAction, detectionCount }`
- `auditIntegrity`: `{ alg, canonicalization, sequence, previousHash, eventHash }`

Rules:

- **`schemaVersion`** is an explicit top-level reader-facing field (value `"1"` in the 1.0 line) so consumers branch on it without parsing `auditIntegrity`. It is **additive** and is part of the canonicalized object.
- **New fields are additive-only and never change the canonicalization of existing fields.** Because `canonicalize` hashes the literal object and `verifyAuditChain` recomputes `eventHash` over the *same* stored object, a 1.x event carrying a future-additive field still verifies under a 1.0 `verifyAuditChain` reading that record — the guarantee is "a future-additive field doesn't break an old verifier reading a new record."
- A **canonicalization change** is a **major** event-schema bump: it ships a **new `canonicalization` tag** (the current value is `json-stable-v1`) **plus a reader-migration path**. It is the only way the hash basis of existing fields may change.

### 2.4 Config schema freeze unit

The **config key presence + shape** is frozen (the top-level keys `mode`, `target`, `proxy`, `responseProtection`, `streaming`, `limits`, `policy`, `filters`, `keys`, `audit`, `tokenVault`, `privacy`, `auth`, `mcp`, and their nested shapes). **Default *values* may still be hardened** — a safer default (e.g. a stricter `failureMode`) is **not** a breaking change. **Unknown keys still throw** (fail-closed): `normalizeConfig` performs strict, enumerated validation, and that fail-closed posture is part of the contract.

## 3. Graduated / remaining-preview exports

The 0.x "experimental exports" list is **resolved** at 1.0 — every entry is either **graduated** (now part of the §2.1 FROZEN / FROZEN-BEHAVIOR surface) or explicitly **kept preview past 1.0** with a stated reason. There is no silent ambiguity.

**Graduated (now FROZEN per §2.1):** `haechi/runtime`, `haechi/proxy`, `haechi/protocol-adapters`, `haechi/privacy-profiles`, `haechi/plugin`, `haechi/mcp-stdio` (`wrapMcpChild`), `haechi/token-vault` (`detokenize` / deterministic tokenization options), the `identity` audit field and the `authProvider` contract, `haechi/stream-filter` and `createStreamProtector`, `haechi/auth` (`createBearerAuthProvider`, token store, `buildIdentity`, `buildExternalIdentity`), `assertCryptoProviderConformance` and the hardened `cryptoProvider` contract, `audit.anchor` + `verifyAuditChain(path, { anchorPath })`, `scripts/release-checksums.mjs`, and `policy.profiles` / `policy.profileBinding` / `modelAllowlist` / `rate` with the `identity` / `profile` audit fields. The machine-readable shape of `status` / `audit-verify` CLI output is frozen (FROZEN BEHAVIOR — the human-readable text is not).

**Kept preview past 1.0 (with reason):**

- The **`injection` detection type and its heuristic rules** — the heuristic set is expected to keep evolving and is **report-only by default** (it pins action `allow` on the response direction unless explicitly escalated), so its *rule membership / confidence* is not frozen, though the detection *shape* it produces is the frozen `detections[]` shape. New/changed `injection` rules are not a breaking change.

## 4. Migration note criteria

A migration note is added to `docs/current/release-*.md` or the README whenever any of the following changes occur. From 1.0, a change in this list to a **FROZEN** surface is a **major** event (or a security-exception minor per §2.2), carries the `HAECHI_DEPRECATION_*` runtime warning where a deprecation window applies, and updates `tests/api-contract.test.mjs`.

- Adding or removing a config key
- Changing default enforcement behavior
- Adding or removing a CLI flag
- Changing an audit event field (top-level OR nested)
- Changing the token format
- Changing the plugin manifest schema

## 5. Satellite packages (`haechi-*`)

Satellites (e.g. `haechi-crypto-kms`, `haechi-auth-jwt`, `haechi-dashboard`, `haechi-auth-oidc`) version **independently** of core — a satellite release never bumps `haechi`, and vice versa.

- **Pre-1.0:** satellites follow npm semver where a `0.x` **minor** bump may carry breaking changes; pin `major.minor` (e.g. `haechi-crypto-kms@~0.2`). Each is pre-stable until its own `1.0.0`.
- **Core compatibility** is expressed as a `peerDependencies` range (`"haechi": ">=0.8.0 <2.0.0"`) — a satellite reuses the consumer's single installed `haechi`, so there is one crypto/identity surface. `haechi-auth-oidc` additionally peer-depends on `haechi-auth-jwt` (`">=0.2.0 <2.0.0"`) so the two share one audited JWS/JWKS verification path. The satellite `haechi` peer-dependency **upper bound must track the core MAJOR** (`<2.0.0`), never be pinned below the next minor, so a core minor- or major-compatible bump never breaks satellite installs; the `release:preflight` gate (`scripts/check-satellite-peer-ranges.mjs`) enforces this automatically.
- **Heavy backends are optional peers.** `haechi-crypto-kms` declares its SDK backends (`@aws-sdk/client-kms`, and in 0.2.0 `@google-cloud/kms`, `@azure/keyvault-keys`, `@azure/identity`) under `peerDependencies` + `peerDependenciesMeta.optional` and imports them lazily, so consumers who do not use a given path never install it and core stays zero-dependency. The `./vault` backend uses `node:` `fetch` only (no optional peer). A satellite's published tarball always declares **zero runtime `dependencies`** (CI-gated by `check-satellite-packaging`).
- **Pre-1.0 satellite exports** are preview and may change before each satellite's own `1.0.0`:
  - `haechi-crypto-kms` (0.8 → 0.2.0): `createKmsCryptoProvider`, `createInMemoryKms`, the `./aws` `createAwsKmsClient`, and the new 0.2.0 subpaths `./gcp` (`createGcpKmsClient`), `./azure` (`createAzureKmsClient`), `./vault` (`createVaultKmsClient`).
  - `haechi-auth-jwt` (0.2.0): `createJwtAuthProvider` (0.8, behavior-preserving) plus the additive `createJwtVerifier` (reusable JWS verifier primitive) and `isBlockedAddress` (SSRF range predicate, reused by `haechi-auth-oidc`).
  - `haechi-dashboard` (0.1.0, new): `createDashboardServer`, `normalizeDashboardConfig`.
  - `haechi-auth-oidc` (0.1.0, new): `createOidcSessionBroker`, `normalizeOidcConfig`.
