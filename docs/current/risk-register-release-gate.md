# Haechi Risk Register and Release Gates

- Status: Draft 0.4
- Date: 2026-06-11
- Target version: 0.9.0
- Branch: `main`

## 1. Current Assessment

0.3.2 resolves the additional security and operational risks identified during the full 0.3.1 code review, meeting the bar for developer preview. The external operator gates (npm account authentication, package ownership, GitHub tag/release) were passed on 2026-06-10: `haechi@0.3.2` is published to npm via local passkey authentication, tagged `v0.3.2`, and released as a GitHub pre-release. npm provenance remains deferred to the GitHub Actions trusted publishing path.

| Category | Judgment | Rationale |
|---|---|---|
| GitHub public | Allowed | Security limitations, threat model, shared responsibility, and developer preview language are documented |
| GitHub release/tag | Allowed | Must be presented as developer preview, not production-ready |
| npm developer preview | Allowed (published) | `haechi@0.3.2` published from an authenticated account on 2026-06-10; provenance deferred to trusted publishing |
| npm stable | On hold | Stable label prohibited until 1.0 API stability, production KMS/HSM/Vault reference adapter, and stream-aware enforcement are in place |
| Production use | Prohibited | 0.3.2 is a self-hosted developer preview; production auth/authz/key custody is the user's responsibility |

## 2. Release Gates

| Gate | Target | Criteria | Current Status |
|---|---|---|---|
| G0 | GitHub source publication | Tests pass, security limitations documented, no plaintext audit leak | Pass |
| G1 | GitHub pre-release | P0 code risks resolved, no production-ready language | Pass |
| G2 | npm developer preview | P0 resolved, preflight/SBOM/provenance paths ready, npm auth confirmed | Pass (`haechi@0.3.2` published 2026-06-10) |
| G3 | npm stable | P1 production reference, stream-aware enforcement, API stability hardened | Blocked |
| G4 | 0.9.0 observability + interactive-auth satellite cut | P1-SEC-009 (0.9) / P1-OPS-005 (0.9) mitigated and P2-CRYPTO-001 (0.9) accepted; `haechi-dashboard` + `haechi-auth-oidc` + `haechi-crypto-kms@0.2.0` tests green; satellite tarballs zero-dep; core bumped to 0.9.0 (only an additive FORBIDDEN_KEYS audit hardening) | Pass |

## 3. P0 Distribution-Blocking Risk Status

| ID | Risk | Status | Resolution evidence |
|---|---|---|---|
| P0-REL-001 | npm authentication/authorization unresolved | Resolved | `haechi@0.3.2` published via local passkey authentication on 2026-06-10; npm authentication and package ownership confirmed |
| P0-REL-002 | Proxy exposed to external network | Resolved | Non-loopback bind fails by default; `--allow-remote-bind` must be specified explicitly |
| P0-REL-003 | Streaming request handling unclear | Resolved | `stream: true` defaults to 501 fail-closed; `streaming.requestMode: "pass-through"` must be set explicitly |
| P0-REL-004 | `responseProtection` failure mode unclear | Resolved | Non-JSON, invalid JSON, compressed, and oversized responses are fail-closed; explicit allow policies are separated |
| P0-REL-005 | Local dev key misunderstood as production key | Resolved | `init`, README, and SECURITY warn that the dev-only key is not a production key provider |
| P0-REL-006 | npm package trust overstated | Resolved | package description, README, and SECURITY updated to reflect experimental developer preview status |

## 4. P1 Security Design Risk Status

| ID | Risk | Status | Resolution evidence |
|---|---|---|---|
| P1-SEC-001 | KMS/HSM/Vault not supported | Resolved for OSS core | `createRuntime(config, { cryptoProvider })` external crypto provider injection; fails closed if no external provider is supplied |
| P1-SEC-002 | TokenVault permission model insufficient | Resolved | `revealPolicy: "disabled"` is the default; `--allow-dev-reveal`, metadata export, retention/purge timestamps added |
| P1-SEC-003 | Audit integrity insufficient | Resolved | JSONL audit SHA-256 hash chain and `verifyAuditChain` |
| P1-SEC-004 | No plugin runtime | Resolved by gating | Dynamic runtime is rejected; only `manifest-only` plugins pass |
| P1-SEC-005 | Policy conflict handling insufficient | Resolved | Downgrading a stronger action (e.g., preset block) to a weaker one fails closed on conflict |
| P1-SEC-006 | Regex-based filter accuracy limited | Resolved for preview | KR RRN checksum, Luhn, and unsafe custom regex restrictions added. ML/classifier plugin is in the stable backlog |
| P1-SEC-007 | AAD/replay/stream extension insufficient | Resolved for preview | AAD hash mismatch is explicit; streaming is blocked by default. Stream sequence/replay cache required when stream support is introduced |
| P1-SEC-008 | MCP security contract incomplete | Resolved for preview | JSON-RPC 2.0 required, method allowlist, params/result protection toggles. OAuth resource binding is the responsibility of the external MCP layer |

## 5. P1 Operational/Deployment Risk Status

| ID | Risk | Status | Resolution evidence |
|---|---|---|---|
| P1-OPS-001 | No CI | Resolved | `.github/workflows/ci.yml` |
| P1-OPS-002 | No SBOM/provenance | Resolved | `npm run sbom`, `.github/workflows/npm-publish.yml`, `publishConfig.provenance` |
| P1-OPS-003 | No real vLLM/Ollama/llama.cpp integration tests | Resolved for preview | Env-gated optional local inference integration tests added. CI skips when no external model server is present |
| P1-OPS-004 | Performance/large payload not measured | Resolved for preview | Request/response byte limits, `npm run bench:payload` |
| P1-OPS-005 | npm ownership unconfirmed | Resolved | `npm view haechi version` returns `0.3.2`; ownership confirmed by the first successful publish |

## 5.1 Additional Security Review Risk Resolution Status

| ID | Risk | Status | Resolution evidence |
|---|---|---|---|
| P1-SEC-009 | Proxy absolute-form request target could bypass upstream or enable SSRF | Resolved | Absolute/protocol-relative request targets are rejected as `haechi_invalid_proxy_target`; upstream URL combines only path and search with the fixed upstream |
| P1-SEC-010 | `responseProtection.maxBytes` checked after full buffering, enabling memory DoS | Resolved | Upstream body is read via stream reader with a byte cap; excess immediately triggers cancel/fail-closed. `failureMode: "allow"` cannot bypass the hard byte cap |
| P1-SEC-011 | Concurrent writes to audit hash chain could cause sequence/previousHash collision | Resolved | JSONL audit sink serializes hash-chain record building and append via per-sink write queue and lock file |
| P1-SEC-012 | PII/secrets in JSON object keys could be exposed in audit paths or token metadata | Resolved | Detection `pathText` records `key_<hash>` structured paths instead of raw key names |
| P1-SEC-013 | Concurrent tokenization/purge in local TokenVault could cause lost updates | Resolved | Vault mutation queue, lock file, and atomic write via temp-file-then-rename applied |
| P1-SEC-014 | No audit record for `streaming.requestMode: "pass-through"` and `responseProtection.failureMode: "allow"` bypass decisions | Resolved | Decision audit records `streaming_request_pass_through` and `response_unprotected_allowed/blocked` without raw payload |
| P1-SEC-015 | MCP `allowedMethods` element type validation insufficient | Resolved | Config validation strengthened to allow only non-empty strings |
| P1-OPS-006 | GitHub Actions major-tag pinning could allow supply-chain drift | Resolved | `checkout`, `setup-node`, and `upload-artifact` pinned to verified commit SHAs |

## 5.2 Second Full Code Review Risk Resolution Status (0.3.2)

| ID | Risk | Status | Resolution evidence |
|---|---|---|---|
| P0-SEC-016 | Ollama `/api/chat` and `/api/generate` default to streaming when `stream` is omitted, allowing streaming block bypass | Resolved | `streamingDefault` introduced in protocol adapter; requests without explicit `stream: false` are treated as streaming and default to 501 fail-closed |
| P1-SEC-017 | Token reveal/purge not recorded in audit | Resolved | `auditSink` injected into local TokenVault; `reveal_allowed/denied/failed`, `purge`, and `purge_expired` decision audits recorded (no plaintext) |
| P1-SEC-018 | Privacy profile could silently weaken user-specified policies | Resolved | `applyPrivacyProfile` compares ACTION_STRENGTH and only allows strengthening |
| P1-SEC-019 | Decrypt ignores envelope `kid`; `init --force` destroys existing keys, permanently losing vault/ciphertext | Resolved | Key selection based on `kid`; `--force` now performs rotation that preserves existing keys as `retired` |
| P1-SEC-020 | Policy bundle signing reuses the AES encryption key as an HMAC key, violating key separation | Resolved | Domain-separated signing key derived with `haechi:policy-bundle:signing:v1` |
| P1-SEC-021 | `retentionDays` only blocks reveal but does not delete expired data | Resolved | Expired tokens are automatically pruned on vault mutation; `purgeExpired()` and `haechi token-purge --expired` added |
| P1-SEC-022 | No upstream fetch timeout, enabling connection exhaustion | Resolved | `limits.upstreamTimeoutMs` (default 120000) and `504 haechi_upstream_timeout` |
| P1-SEC-023 | JSON numbers (card numbers) and PII/secrets in object keys not detected or transformed | Resolved | Number leaves and object keys included in detection/transform scope (keys are renamed on enforce) |
| P1-OPS-007 | Stale lock file causes permanent audit/vault write failure | Resolved | Stale locks older than 30 seconds are automatically stolen and reacquired |
| P1-OPS-008 | Audit append re-reads the entire file on every write (O(n²)) | Resolved | File tail-chunk read for O(1) append |
| P2-SEC-024 | Unknown `target.type` silently falls back to openai-compatible | Resolved | Unknown type fails closed at config validation |
| P2-SEC-025 | Short-value masking exposes most of the value (4 of 5 characters) | Resolved | Values of 8 characters or fewer are fully masked |
| P2-SEC-026 | Assignment-secret redaction removes the key name as well | Resolved | Lookbehind pattern replaces only the secret value |
| P2-SEC-027 | MCP notifications receive error responses in violation of the JSON-RPC spec; batch handling unspecified | Resolved | Notifications are dropped; batch is explicitly rejected fail-closed |
| P2-SEC-028 | Proxy internal error messages exposed to clients | Resolved | Unexpected errors return a generic message; details go to stderr |
| P2-DOC-005 | Default dry-run + responseProtection off could be mistaken for "protection active" | Resolved | Proxy startup and `protect` output explicitly warn when enforcement is inactive |

Base64/encoded-value decode inspection, query-string inspection, and audit tail truncation detection are explicitly excluded and documented in the threat model (0.4+ backlog).

## 5.3 0.9.0 Observability + Interactive-Auth Risk Status

These IDs are scoped to the 0.9.0 satellite cut (`haechi-dashboard`, `haechi-auth-oidc`, `haechi-crypto-kms@0.2.0`); they are namespaced by the 0.9.0 section and are distinct from the like-numbered P0/P1 rows above. Evidence is the satellite source, its test suite, and the adversarial security review captured in `docs/current/release-0.9-implementation-scope.md` §6.

| ID | Risk | Status | Resolution evidence |
|---|---|---|---|
| P1-SEC-009 (0.9) | OIDC broker session/login security: login CSRF, authorization-code injection, open-redirect, session fixation, and mix-up (wrong IdP/RP) in `haechi-auth-oidc` | Mitigated | `satellites/auth-oidc/index.mjs`: state-first `/auth/callback` (atomic `take()` of a pre-auth-cookie-bound pending record + constant-time `state` compare before any egress), PKCE S256, fresh session id minted at callback (no fixation), `returnToAllowlist` (no open-redirect), issuer/endpoint pinning + RFC 9207 `iss` check + ID-token `aud`/`azp` profile via the shared `createJwtVerifier` (mix-up), CSRF-gated non-GET logout. `satellites/auth-oidc/auth-oidc.test.mjs` exercises each deny case; adversarial review in scope §6. **Residual:** multi-origin IdP out of scope |
| P1-OPS-005 (0.9) | Dashboard audit exposure: stored XSS via `detections[].path`, future-field audit leak, DNS-rebinding read of a localhost viewer, and unauthenticated read on remote bind in `haechi-dashboard` | Mitigated | `satellites/dashboard/index.mjs` + `assets.mjs`: strict CSP (`require-trusted-types-for 'script'`) + `textContent`-only rendering (XSS), recursive key-by-key allowlist projection over `FORBIDDEN_KEYS` (field leak), per-request anti-rebinding `Host` allowlist + CORP/COOP same-origin (rebinding), fail-closed remote bind requiring `sessionGuard` **and** TLS termination (unauthenticated remote read). `satellites/dashboard/dashboard.test.mjs`; adversarial review in scope §6. **Residual:** operator must terminate TLS for remote bind |
| P2-CRYPTO-001 (0.9) | KMS backend egress: the `haechi-crypto-kms@0.2.0` Vault/GCP/Azure backends could leak key material or provider/key-path detail or reach an unintended (metadata) endpoint | Accepted | `satellites/crypto-kms/{vault,gcp,azure}.mjs`: optional-peer + injected-client model with faithful-mock `assertCryptoProviderConformance` (cross-key + corrupted-blob rejection, HMAC determinism/domain-separation), satellite-local `isBlockedAddress` SSRF guard on the Vault `fetch` (kept honest by the dev-only `satellites/crypto-kms/ssrf-parity.test.mjs` vs auth-jwt), generic fail-closed provider-error mapping (no provider/key-ARN in audit). `{vault,gcp,azure}.test.mjs` + `crypto-kms.test.mjs`; adversarial review in scope §6. **Residual accepted:** live-backend (real Vault/GCP/Azure) validation is out of CI; the published tarball stays zero runtime dependency |

## 6. P2 Product/Documentation Risk Status

| ID | Risk | Status | Resolution evidence |
|---|---|---|---|
| P2-DOC-001 | Separate threat model document missing | Resolved | `docs/current/threat-model.md` |
| P2-DOC-002 | Shared responsibility documentation insufficient | Resolved | `docs/current/shared-responsibility.md` |
| P2-DOC-003 | Region/privacy profile not implemented | Resolved for baseline | `haechi/privacy-profiles`, `privacy.profile` applied at runtime |
| P2-DOC-004 | No API stability policy | Resolved | `docs/current/api-stability.md` |

## 7. npm Developer Preview Pre-Distribution Checklist

External npm gate check results (2026-06-10, post-publish):

- `npm whoami`: `raeseoklee`
- `npm view haechi version`: `0.3.2`

All checklist items below were completed for 0.3.2 on 2026-06-10 except the provenance publish path, which is deferred to GitHub Actions trusted publishing (`v0.3.2` tag and GitHub pre-release were completed). The checklist remains the template for future releases.

1. `npm run release:preflight`
2. `npm run sbom`
3. `npm run bench:payload`
4. `npm run release:preflight:npm`
5. Create GitHub release
6. GitHub Actions `Publish npm Developer Preview` succeeds
7. Confirm actual published version with `npm view haechi version`

## 8. Remaining Non-Blocking Backlog

| Version | Goal | Remaining scope |
|---|---|---|
| 0.4.0 ✅ | Token round-trip and adoption | Shipped 2026-06-10: request-scoped response detokenization, deterministic tokenization (derived key), `haechi mcp-wrap`, `haechi audit-verify`/`haechi status`, injection detection type (default allow), `identity`/`authProvider` contracts reserved. See `docs/current/release-0.4-implementation-scope.md` |
| 0.5.0 ✅ | Streaming hardening | Shipped 2026-06-10: SSE/NDJSON streaming response inspection with bounded cross-frame buffer (`streaming.requestMode: inspect`). Stream sequence AAD, replay cache, stronger remote deployment guide deferred to 0.6+. See `docs/current/release-0.5-implementation-scope.md` |
| 0.6.0 ✅ | Auth and per-client controls | Shipped 2026-06-10 (PRs #17–#19): built-in bearer auth, named policy profiles, model allowlist, request rate limit, PII-safe identity in audit. See `docs/current/release-0.6-implementation-scope.md` |
| 0.7.0 ✅ | Ops hardening | Shipped 2026-06-10 (PRs #22–#24): audit head-hash anchoring + external sink contract, cryptoProvider contract hardening + `assertCryptoProviderConformance` + reference KMS adapter, signed/checksummed release artifacts. See `docs/current/release-0.7-implementation-scope.md` |
| 0.8.0 ✅ | Ecosystem foundation + satellites | Shipped 2026-06-10 (PRs #27–#32): npm workspaces monorepo (root self-member `["."]` + `satellites/*`); **published** `haechi@0.8.0` (attested), `haechi-crypto-kms` and `haechi-auth-jwt` (unscoped — the `@haechi` scope was taken). Core stays zero runtime dependency (CI no-leak + zero-dep + satellite-packaging gates). Satellite `0.1.0` was a manual bootstrap publish (unattested, `--provenance=false`, mirroring the `0.3.2` gap) to create the names so per-name Trusted Publishers could be configured; `0.1.1` is the first attested CI release (SLSA provenance + sigstore, `gh attestation verify` passes). See `docs/current/release-0.8-implementation-scope.md` |
| 0.9.0 | Observability + interactive auth | `haechi-auth-oidc` full authorization-code flow, `haechi-dashboard` read-only audit viewer (hash-chain integrity display, summary/search/timeline), additional `haechi-crypto-kms` backends (Vault/GCP/Azure) |
| 1.0.0 | Stable API contract | Migration policy, long-term audit schema, plugin sandbox/runtime conformance, and dynamic loading of external auth/classifier packages that pass allowlist/manifest |

Dynamic npm package loading is prohibited until the 1.0 plugin sandbox. External providers in 0.4–0.7 are supported only via `createRuntime(config, providers)` programmatic injection.

## 9. Current Permitted Use

0.3.2 is intended for use in the following contexts:

- Local development environments
- Sample payload validation
- OpenAI-compatible/vLLM/Ollama/llama.cpp proxy PoC
- Policy/filter/audit pipeline review
- GitHub code review and security design discussion
- npm developer preview

0.3.2 is not intended for the following uses:

- Production LLM gateway
- Proxy directly exposed to the internet
- Processing real customer/patient/payment/authentication data
- Compliance evidence or legal conformance proof
- npm stable package
