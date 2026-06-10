# Haechi 0.3.2 Hardening Scope

- Status: Final
- Date: 2026-06-10
- Target version: 0.3.2
- Type: Security hardening release; first npm developer preview distribution target
- Published: 2026-06-10 — `haechi@0.3.2` on npm (local passkey publish; provenance deferred), tag `v0.3.2`, GitHub pre-release

## 1. Background

This release resolves the 16 risks identified during the full 0.3.1 code review. The detailed risk list and closure evidence follow `risk-register-release-gate.md` section 5.2 (P0-SEC-016 through P2-DOC-005).

Because no version had ever been published to npm before 0.3.2, this is the first published version. Separating the first publication from a feature release (0.4.0) confirmed package-name ownership in a low-risk release while leaving the provenance-backed GitHub Actions publish path as a follow-up hardening item.

## 2. Change Summary

### Blocking / Enforcement Path
- Ollama `/api/chat` and `/api/generate` are treated as streaming unless `stream: false` is explicitly set; default behavior is 501 fail-closed (protocol adapter `streamingDefault`)
- Unknown `target.type` values are rejected fail-closed at config validation time (only the `llm-http` alias is accepted as openai-compatible)
- Upstream fetch respects `limits.upstreamTimeoutMs` (default: 120000 ms); timeout returns `504 haechi_upstream_timeout`, connection failure returns `502 haechi_upstream_unreachable`
- Proxy internal error messages are generalized (details go to stderr)

### Detection / Transform
- JSON number leaves (e.g., card numbers) and object key names are now included in detection/transform scope (enforce mode renames keys; conflicts get a `#n` suffix)
- Masks of 8 characters or fewer are fully masked
- `assignment-secret` pattern converted to lookbehind — key name is preserved, only the value is replaced
- Privacy profile can only strengthen user-declared policy, never weaken it (`ACTION_STRENGTH` comparison)

### Keys / Cryptography
- `decrypt` selects the key by envelope `kid` (maintains decryption of legacy envelopes)
- `initLocalKeyFile --force` now performs a rotation that preserves the existing key as `retired` rather than overwriting it
- Policy bundle signing key is separated as a `haechi:policy-bundle:signing:v1` domain-separated derived key

### TokenVault / Audit
- reveal and purge decisions are recorded in audit (`reveal_allowed/denied/failed`, `purge`, `purge_expired` — token id only, no plaintext)
- Expired tokens are automatically deleted on vault mutation; `purgeExpired()` and `haechi token-purge --expired` are added
- Audit append is O(1) via tail-chunk read
- Audit/vault lock files older than 30 seconds are considered stale and automatically reclaimed

### UX / Visibility
- Non-enforcement mode (dry-run/report-only) and disabled responseProtection warnings are shown at proxy startup and in `protect` output
- `protect` output now includes `mode`, `enforced`, and `warnings` fields

### MCP
- Notifications (messages without an id) are dropped with no error response, per the JSON-RPC spec
- Batch arrays are explicitly rejected fail-closed

## 3. Compatibility Notes (vs. 0.3.1)

No users have received a published release, so no migration path is provided — this is recorded for reference only.

- Policy bundles signed with a 0.3.1 key will fail verification due to the signing key separation. Re-sign with `haechi policy-sign`.
- The expanded detection scope (numbers/keys) and changed mask behavior may produce different enforce-mode output compared to 0.3.1.
- A `kind` field has been added to `detection` entries in audit events.

## 4. Explicit Exclusions (0.4+ Backlog)

- Inspection of base64/URL-encoded values after decoding
- URL query string inspection
- Audit hash chain tail truncation detection (requires external anchoring)
- SSE/NDJSON stream inspection (0.5.0)

## 5. Release Gate

Follow the checklist in `risk-register-release-gate.md` section 7. After `npm run release:preflight` passes, publish from an authenticated account using `release:preflight:npm` and the GitHub release workflow.
