# Wiki Log

Append-only changelog. Format: `## [YYYY-MM-DD] operation | Title`.

## [2026-06-10] ingest | Initial wiki seeded

Created the wiki layer with 11 pages compiled from the 0.3.2 hardening cycle: architecture (protect pipeline, runtime composition), concepts (fail-closed, token vault, audit integrity, key management, streaming gap), decisions (release roadmap, identity/auth contract, packaging), and the 2026-06-10 full security review record. Sources: packages/*, docs/current/*, risk register 5.1–5.2, PR #1–#3 discussions.

## [2026-06-10] lint | Correct 0.3.2 provenance memory

Corrected `[[packaging-and-distribution]]` to record that `haechi@0.3.2` was published through local passkey authentication with npm provenance deferred to the trusted-publishing workflow.

## [2026-06-10] lint | Sweep remaining provenance claims and record the trusted-publishing gate

Fixed `[[release-roadmap]]` ("validate provenance publish" → local passkey, `--provenance=false`) and rewrote `docs/current/release-process.md` §2 (EN/KO) to document the actual state, the npmjs.com Trusted Publisher + workflow runbook, and a new deployment block condition: no npm publish without trusted publishing configured or an explicit provenance-gap note in the release notes.
