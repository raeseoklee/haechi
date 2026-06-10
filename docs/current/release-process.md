# Haechi Release Process

- Status: Draft 0.1
- Date: 2026-06-10
- Target version: 0.3.2

## 1. Local Release Verification

```bash
npm run release:preflight
npm run sbom
npm run bench:payload
```

`release:preflight` runs tests, a type check, a stale-name scan, and a pack dry-run. To also verify npm account authentication and package ownership, use:

```bash
npm run release:preflight:npm
```

Before the first publish, it is normal for `npm view <package> version` to return `E404 Not Found`. In that case, preflight passes with the package name ready to be claimed from an authenticated account. However, if `npm view <package>@<version> version` succeeds, the same version cannot be published again and preflight will fail.

## 2. npm provenance and trusted publishing

The intended publish path is GitHub Actions trusted publishing: npm authenticates the release workflow via OIDC and generates a provenance statement automatically. Per the official npm requirements this needs a GitHub-hosted runner, `id-token: write`, and a publish from the linked workflow.

**Current state: trusted publishing is configured and verified.** `haechi@0.3.2` was published from a local machine using passkey authentication with `--provenance=false`, so no provenance attestation exists for that version. The enablement runbook and its status:

1. ✅ On npmjs.com: package settings → Trusted Publisher → linked the `raeseoklee/haechi` repository and the `npm-publish.yml` workflow (2026-06-10).
2. ✅ `.github/workflows/npm-publish.yml` authenticates via OIDC (2026-06-10): `NODE_AUTH_TOKEN` and `registry-url` removed, npm CLI upgraded to `>= 11.5.1` in the runner.
3. ✅ Verified with `haechi@0.4.0` (2026-06-10): `npm view haechi --json` shows `dist.attestations` with a SLSA provenance v1 predicate. Only `haechi@0.3.2` remains unattested (published via local passkey).

Any publish performed without provenance must record the gap explicitly in the release notes (see `CONTRIBUTING.md`).

References:

- https://docs.npmjs.com/generating-provenance-statements/
- https://docs.npmjs.com/trusted-publishers/
- https://docs.github.com/actions/publishing-packages/publishing-nodejs-packages

## 3. Signed release artifacts

The **cryptographic** trust anchors are the **npm provenance attestation** (registry artifact) and the **sigstore attestation** (release tarball) — both bind the artifact to this repository's release workflow identity via GitHub OIDC. `SHA256SUMS` is a **tooling-compatible convenience** for offline checksumming (`sha256sum -c`); on its own it is not a trust anchor, since the same workflow produces and uploads it. Beyond provenance, the publish workflow attaches these assets so a downloaded tarball can be verified before install:

- It runs `npm pack`, then `node scripts/release-checksums.mjs <tarball>` to emit a `SHA256SUMS` manifest (standard `<sha256-hex>  <name>` format).
- It produces a **keyless sigstore attestation** of the tarball via `actions/attest-build-provenance` (GitHub OIDC, no signing keys).
- It uploads the tarball + `SHA256SUMS` to the GitHub release.

Verify a downloaded release:

```bash
# checksum (cross-platform: sha256sum -c, or the bundled script)
node scripts/release-checksums.mjs --check SHA256SUMS
sha256sum -c SHA256SUMS            # GNU
shasum -a 256 -c SHA256SUMS        # macOS

# sigstore attestation (tarball was built by this repo's release workflow)
gh attestation verify haechi-<version>.tgz --repo raeseoklee/haechi

# npm provenance (registry artifact)
npm audit signatures
```

## 4. GitHub Actions

| Workflow | Publishes | Fires on tag | Purpose |
|---|---|---|---|
| `.github/workflows/ci.yml` | — | any push/PR | Tests, release preflight, SBOM artifact |
| `.github/workflows/npm-publish.yml` | `haechi` | `v<semver>` | npm provenance publish + checksummed/attested release assets |
| `.github/workflows/crypto-kms-publish.yml` | `haechi-crypto-kms` | `crypto-kms-v<semver>` | satellite publish, same signed-artifacts path |
| `.github/workflows/auth-jwt-publish.yml` | `haechi-auth-jwt` | `auth-jwt-v<semver>` | satellite publish, same signed-artifacts path |

Each publish workflow triggers on `release: published` but is **guarded** so the two never cross-fire: the core job runs only for tags starting `v` (and re-validates `^v[0-9]+\.[0-9]+\.[0-9]+$`); the satellite job runs only for `crypto-kms-v…` (and re-validates `^crypto-kms-v[0-9]+\.[0-9]+\.[0-9]+$` **and** that the tag version equals the satellite's `package.json` version). The npmjs.com Trusted Publisher for each package is bound to its **specific workflow filename** — renaming a workflow file breaks its OIDC publish until the npm config is updated.

## 5. Satellite packages (unscoped `haechi-*`)

Satellites live under `satellites/*` in the npm workspaces monorepo and publish **independently** of core (their own semver; a satellite patch never bumps `haechi`). They reuse the exact signed-artifacts path as core (pack → checksum → sigstore attest → OIDC publish → upload). They are published as **unscoped** `haechi-*` names (the `@haechi` org/scope is taken by a third party), so **no npm org is required**.

**Per-satellite bootstrap order (first publish, no org needed):**

1. On npmjs.com, **configure a Trusted Publisher** for the (not-yet-published) unscoped name (e.g. `haechi-crypto-kms`): link the `raeseoklee/haechi` repository and the satellite's **exact workflow filename** (e.g. `crypto-kms-publish.yml`). npm allows configuring a Trusted Publisher for a name you have not published yet.
2. Push the prefixed tag and publish a GitHub Release (e.g. `crypto-kms-v0.1.0`) → the workflow's OIDC publish creates `0.1.0` with provenance and claims the name on first publish.

No manual `npm publish` from a laptop is needed. Because the names are unscoped and free, there is no org-membership prerequisite.

**Tag → workflow → package mapping:**

| Package | Tag pattern | Workflow file | npm version source |
|---|---|---|---|
| `haechi-crypto-kms` | `crypto-kms-v<semver>` | `crypto-kms-publish.yml` | `satellites/crypto-kms/package.json` |
| `haechi-auth-jwt` | `auth-jwt-v<semver>` | `auth-jwt-publish.yml` | `satellites/auth-jwt/package.json` |

**Verify a satellite release** (same anchors as core):

```bash
gh attestation verify haechi-crypto-kms-<version>.tgz --repo raeseoklee/haechi
npm view haechi-crypto-kms --json   # dist.attestations present; access "public"
```

**Dependency note:** `haechi-crypto-kms` keeps core zero-dependency — `@aws-sdk/client-kms` is an **optional peer dependency**, imported lazily only when a real AWS client is used and not injected. Consumers who use the in-memory or an injected client never install the SDK.

## 6. Deployment block conditions

npm publish is not performed if any of the following fail.

- `npm run release:preflight` fails
- `npm run release:preflight:npm` fails
- GitHub Actions CI fails
- SBOM generation fails
- npm package name ownership is uncertain
- README/SECURITY does not explicitly state developer preview and production restrictions
- Trusted publishing/provenance is not configured and the release notes do not explicitly record the provenance gap
