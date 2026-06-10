# Wiki Log

Append-only changelog. Format: `## [YYYY-MM-DD] operation | Title`.

## [2026-06-10] ingest | Initial wiki seeded

Created the wiki layer with 11 pages compiled from the 0.3.2 hardening cycle: architecture (protect pipeline, runtime composition), concepts (fail-closed, token vault, audit integrity, key management, streaming gap), decisions (release roadmap, identity/auth contract, packaging), and the 2026-06-10 full security review record. Sources: packages/*, docs/current/*, risk register 5.1–5.2, PR #1–#3 discussions.

## [2026-06-10] lint | Correct 0.3.2 provenance memory

Corrected `[[packaging-and-distribution]]` to record that `haechi@0.3.2` was published through local passkey authentication with npm provenance deferred to the trusted-publishing workflow.

## [2026-06-10] lint | Sweep remaining provenance claims and record the trusted-publishing gate

Fixed `[[release-roadmap]]` ("validate provenance publish" → local passkey, `--provenance=false`) and rewrote `docs/current/release-process.md` §2 (EN/KO) to document the actual state, the npmjs.com Trusted Publisher + workflow runbook, and a new deployment block condition: no npm publish without trusted publishing configured or an explicit provenance-gap note in the release notes.

## [2026-06-10] ingest | Trusted publishing configured

Maintainer linked the npm Trusted Publisher for `raeseoklee/haechi` + `npm-publish.yml`; the workflow now authenticates via OIDC (no `NODE_AUTH_TOKEN`, no `registry-url` npmrc placeholder, npm CLI `>= 11.5.1` in the runner). Runbook steps 1–2 complete; step 3 (attestation verification) waits for the next release. Updated `[[release-roadmap]]` and `release-process.md` §2 accordingly.

## [2026-06-10] ingest | 0.4.0 shipped

All four 0.4.0 features landed (PRs #7–#10) and the release branch cut: deterministic tokenization + request-scoped detokenization ([[token-vault]]), `audit-verify`/`status`, `mcp-wrap` (bidirectional, server-initiated requests exempt from the client allowlist), report-only injection heuristics (direction-scoped rules), and `identity: null` reserved across all audit event kinds. README gained a full configuration reference including remote-bind/container guidance. The 0.4.0 GitHub release will be the first OIDC trusted-publishing publish — verify `dist.attestations` after.

## [2026-06-10] ingest | First attested publish verified

`haechi@0.4.0` published through the OIDC trusted-publishing workflow; `dist.attestations` (SLSA provenance v1) confirmed on the registry. The provenance gap is closed for all future releases — only 0.3.2 remains unattested. Updated `[[packaging-and-distribution]]` and `release-process.md` runbook step 3.

## [2026-06-10] ingest | Configuration reference and CLI help

Added `docs/current/configuration.md` (+`.ko.md`): full per-key reference, presets, action strength, validation cheatsheet, common setups, and remote-bind guidance. Restructured `haechi help` (command list + `help <command>`) and added `haechi config` (condensed guide). Four-place config coupling is now five: defaultConfig, normalizeConfig, example json, configuration.md, and `haechi config`/COMMAND_HELP.

## [2026-06-10] ingest | 0.5.0 streaming inspection shipped

PR #14 added SSE/NDJSON streaming response inspection (`streaming.requestMode: "inspect"`): new `packages/stream-filter`, `core.createStreamProtector` with a bounded sliding buffer for cross-frame matches, per-adapter `{ format, deltaPath }`, and a fix where a specific `target.type` now beats a default-merged `target.adapter`. Rewrote `[[streaming-protection-gap]]` from gap to shipped design, marked the roadmap row, and recorded the bounded limits (`maxMatchBytes`, emitted-bytes-on-block, n>1 choices) as threat-model exclusions.

## [2026-06-10] design | 0.6 auth design finalized

Detailed-design pass for 0.6 (no code). Decisions: auth-core-focused scope (KMS/audit-sink/signed-artifacts/npm-org -> 0.7), named policy profiles for per-client policy (byScope->byLabel->default, fail-closed), bearer tokens in a separate `.haechi/auth.json` + `haechi auth` CLI with keyed-HMAC hashes. Wrote `release-0.6-implementation-scope.md` (+KO), updated `[[identity-and-auth]]`, split the roadmap into 0.6 (auth core) and a new 0.7 (ops hardening + ecosystem).

## [2026-06-10] ingest | 0.6.0 auth shipped

PRs #17–#19 implemented the 0.6 design: `packages/auth` (authProvider contract, bearer provider, keyed-HMAC token store, PII-safe buildIdentity), `haechi auth` CLI, `createPolicyProfiles` (scope→label→default resolution) with a per-request policyEngine threaded through `protectJson`/`createStreamProtector`, and proxy enforcement (authenticate→profile→rate→body→model-allowlist→protect) with `auth_denied`/`model_not_allowed`/`rate_limited` audit decisions and identity+profile on every event. Evaluation caught a real regression: the per-request policyEngine in the protect context polluted the tokenize AAD (functions dropped on JSON store → AAD mismatch → silent detokenize failure); fixed by stripping the control object from the data context. Updated `[[identity-and-auth]]` and `[[release-roadmap]]` to shipped.

## [2026-06-10] design | 0.7 ops-hardening design finalized

Detailed-design pass for 0.7 (no code). Decisions: ops-hardening-focused scope (ecosystem — npm org, satellite publishes, dashboard, workspaces — moved to a deduplicated 0.8); key custody as the `@haechi/crypto-kms` satellite with a 0.7 repo reference example (core keeps zero-dep, owns the cryptoProvider contract); tail-truncation closed by built-in head-hash anchoring (`audit.anchor`) + verify-with-anchor, plus an external sink contract. Wrote `release-0.7-implementation-scope.md` (+KO), updated `[[audit-integrity]]` and `[[packaging-and-distribution]]`, deduped the roadmap into 0.7 (ops) and 0.8 (ecosystem).

## [2026-06-10] ingest | 0.7.0 ops hardening shipped

PRs #22-#24 implemented the 0.7 design: audit head-hash anchoring (audit.anchor + verifyAuditChain anchor cross-check; honest separate-media boundary), a hardened cryptoProvider contract with assertCryptoProviderConformance + a dependency-free reference KMS adapter (examples/crypto-kms-reference, envelope encryption), and signed/checksummed release artifacts (scripts/release-checksums.mjs + sigstore attestation in the publish workflow, pack/attest before the irreversible publish). Three adversarial-review workflows (43 + 34 + 32 agents) caught real meta-defects each round: the anchor 0644/overclaim, the conformance helper not checking hmac data-dependency, and the publish-before-attest ordering + scripts/ missing from files. Advances 3 of the 5 1.0 exit criteria.

## [2026-06-10] design | 0.8 ecosystem-foundation design finalized

Detailed-design pass for 0.8 (no code), hardened by two adversarial-review workflows (43 + 38 agents) and empirical testing of the linchpin assumptions. Scope: npm workspaces monorepo + first two published satellites `@haechi/crypto-kms` (real AWS KMS) and `@haechi/auth-jwt` (headless JWKS); `@haechi/auth-oidc` + `@haechi/dashboard` split to a new 0.9 row. Key empirical findings that reshaped the draft: (1) the obvious workspaces layout (`["satellites/*"]` + satellite peer range) silently fails — npm resolves the peer from the registry (`ETARGET`) and never links root; the working layout is root self-member `["."]` + satellite peer+dev dual core dep (verified: clean install, symlink, no satellite leak, `node --test` traverses satellites without a symlink-cycle hang). (2) JWS ES256 signatures are raw R‖S but `node:crypto.verify` defaults to DER and returns `false` — silently rejecting every valid ES256 token; spec now mandates `dsaEncoding: "ieee-p1363"`. The auth-jwt §2.4 security spec pins concrete constants (RSA ≥2048, clock-skew cap 300s, kid-flood cooldown 60s, HMAC-SHA-256 identity, 1 MiB JWKS bound, single-origin issuer SSRF guard). The zero-dep gate inspects the packed manifest (not the installed-tree SBOM, which passes vacuously) and is negatively tested. Wrote `release-0.8-implementation-scope.md` (+KO), updated `[[release-roadmap]]` (new 0.9 row), `[[packaging-and-distribution]]` (verified workspaces mechanic), and the risk-register §8 (EN+KO). Evaluation: 154 tests / 152 pass / 0 fail, check:types clean (docs-only change).

## [2026-06-10] ingest | 0.8 PR1+PR2 shipped (workspaces + @haechi/crypto-kms AWS)

PR1 converted the repo to an npm workspaces monorepo (root self-member `["."]` + `satellites/*`; satellite `peer + dev` core deps) and promoted `examples/crypto-kms-reference/` → `satellites/crypto-kms/` (`@haechi/crypto-kms`), dropping the inlined `canonicalize` for `haechi/crypto`. Added the `check-core-packaging` gate (packed-manifest zero-dep + no satellite leak, negatively tested) and the SBOM satellite-strip. PR2 added the real AWS KMS client at `@haechi/crypto-kms/aws` (envelope via KMS Encrypt/Decrypt + HKDF-SHA256 hmac root) with `@aws-sdk/client-kms` as an OPTIONAL peer dependency (lazy import; tests inject a keyId-aware mock, SDK-free), the `check-satellite-packaging` gate, and per-package publish workflows (`crypto-kms-v*`) with the core workflow now tag-guarded to `v*`. Two adversarial reviews (20-agent PR1 → 4 confirmed; 36-agent PR2 → 13 confirmed) drove fixes: SBOM boundary-exact match, cross-impl AAD parity, packed-manifest gate hardening (PR1); HKDF alignment of the in-memory client to the AWS client (cross-backend parity), a faithful keyId-isolating KMS mock (the old cross-key test passed for the wrong reason), the satellite packaging gate, no-cache-on-rejection for the lazy SDK/hmac-root promises, and README/optional-peer wording (PR2). Evaluation: 183 tests / 181 pass / 0 fail, check:types clean, release:preflight green (both packaging gates), core stays zero-dep + npm install never pulls the AWS SDK. Updated `[[packaging-and-distribution]]`. Roadmap 0.8 row stays open until the release cut (PR4).

## [2026-06-10] ingest | 0.8 PR3 shipped (@haechi/auth-jwt JWKS verifier)

PR3 added @haechi/auth-jwt — a headless JWKS bearer authProvider (node: builtins only) implementing the §2.4 security spec, plus the core-owned buildExternalIdentity (PII-safe identity for external providers; keyed-HMAC subject/issuer over haechi:identity:hash:v1) and a third per-package publish workflow (auth-jwt-v*). A 5-dimension / 48-agent adversarial review confirmed 13 findings (most "correct as built"); the real fixes: resolveJwk unified to a single cooldown-gated refetch (was a double-refetch on stale-cache+unknown-kid, a spec-violating DoS amplifier), IPv6 fe80::/10 + ULA + multicast range checks (was a fe80-prefix-only match), bracketed-IPv6-literal hosts now stripped before blocklist classification (a real SSRF guard gap the new construction test caught), whitespace-only sub rejected, heterogeneous aud arrays rejected, and the JWKS body-size fallback bounded by content-length. Evaluation: 200 tests / 198 pass / 0 fail, check:types clean, release:preflight green (core + both satellite packaging gates); npm install still 7 packages (auth-jwt is node:-only). Updated [[identity-and-auth]] and [[packaging-and-distribution]]. 0.8 implementation PRs done (PR1 workspaces, PR2 crypto-kms, PR3 auth-jwt); next is the 0.8.0 release cut (PR4).
