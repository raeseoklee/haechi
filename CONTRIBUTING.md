# Contributing to Haechi

English is the primary language for code, commits, pull requests, and documentation. Korean translations of documents live alongside as `*.ko.md`.

## Branching Model

`main` is the only long-lived branch. It must always be releasable, and changes land only through pull requests. There is no `develop` branch: releases are tag-driven, so a full Gitflow staging branch adds no value at this project size.

All work branches off `main` using a type prefix:

| Branch | Purpose | Example |
|---|---|---|
| `feature/<topic>` | New functionality | `feature/mcp-wrap` |
| `fix/<topic>` | Bug fixes | `fix/ollama-stream-detect` |
| `docs/<topic>` | Documentation only | `docs/threat-model-update` |
| `chore/<topic>` | Tooling, CI, dependencies, maintenance | `chore/lsp-typecheck` |
| `release/<version>` | Release preparation (version bump, scope doc) | `release/0.4.0` |
| `hotfix/<version>` | Urgent patch on a published release | `hotfix/0.3.3` |

Do not use personal-name prefixes (e.g. `irae/...`).

## Commits

- One-line imperative English subject, no body, no attribution trailers.
  - Good: `Make local proxy port configurable before preview publish`
  - Bad: `fixed stuff`, `WIP`, subjects with `Co-Authored-By` trailers
- Keep each commit a single logical change.

## Pull Requests

- Target `main`. Title matches the (squashed) commit subject style.
- Body in English with `## Summary` and `## Verification` sections.
- Before opening a PR, the following must pass locally:

```bash
npm test
npm run release:preflight   # tests + type check + stale-name scan + pack dry-run
```

## Releases

1. Branch `release/<version>` from `main`; bump `package.json`, add/update `docs/current/release-<version>-*.md` (and `.ko.md`), update the risk register gates.
2. Merge via PR, then tag `v<version>` on `main`.
3. Create a GitHub release (pre-release while in `0.x`). The `Publish npm Developer Preview` workflow publishes to npm with provenance.
4. Verify with `npm view haechi version`.

See `docs/current/release-process.md` for gate details.

## Development

- Node `>= 22`. The package has **zero runtime dependencies** (only `node:` builtins); dev-only tooling dependencies are allowed but must not leak into the published artifact (the SBOM omits dev dependencies).
- Tests use the built-in `node:test` runner: `npm test`, or `node --test tests/<file>.test.mjs` for one file.
- Editor language support (completion, go-to-definition, hover, diagnostics) is configured via `jsconfig.json`; `npm run check:types` runs the same project through `tsc --noEmit`. `checkJs` is currently off — opt files in incrementally with `// @ts-check`.
- Documentation changes must update both the English main file and its `.ko.md` sibling.
- Security-sensitive changes must respect the invariants in `SECURITY.md` and `docs/current/threat-model.md` (fail-closed defaults, no plaintext in audit logs, loopback-only bind, governed token reveal).
