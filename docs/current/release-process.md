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

**Current state: trusted publishing is configured; first attested release pending.** `haechi@0.3.2` was published from a local machine using passkey authentication with `--provenance=false`, so no provenance attestation exists for that version. The enablement runbook and its status:

1. ✅ On npmjs.com: package settings → Trusted Publisher → linked the `raeseoklee/haechi` repository and the `npm-publish.yml` workflow (2026-06-10).
2. ✅ `.github/workflows/npm-publish.yml` authenticates via OIDC (2026-06-10): `NODE_AUTH_TOKEN` and `registry-url` removed, npm CLI upgraded to `>= 11.5.1` in the runner.
3. ⏳ After the next release, verify the attestation with `npm view haechi --json` (`dist.attestations`). The OIDC path has not carried a real publish yet; if misconfigured it fails closed at publish time.

Any publish performed without provenance must record the gap explicitly in the release notes (see `CONTRIBUTING.md`).

References:

- https://docs.npmjs.com/generating-provenance-statements/
- https://docs.npmjs.com/trusted-publishers/
- https://docs.github.com/actions/publishing-packages/publishing-nodejs-packages

## 3. GitHub Actions

| Workflow | Purpose |
|---|---|
| `.github/workflows/ci.yml` | Tests, release preflight, SBOM artifact |
| `.github/workflows/npm-publish.yml` | npm publish on GitHub release published event (provenance path once trusted publishing is configured) |

## 4. Deployment block conditions

npm publish is not performed if any of the following fail.

- `npm run release:preflight` fails
- `npm run release:preflight:npm` fails
- GitHub Actions CI fails
- SBOM generation fails
- npm package name ownership is uncertain
- README/SECURITY does not explicitly state developer preview and production restrictions
- Trusted publishing/provenance is not configured and the release notes do not explicitly record the provenance gap
