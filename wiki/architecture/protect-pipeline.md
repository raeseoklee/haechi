---
updated: 2026-06-12
tags: [architecture, core]
---

# Protect Pipeline

Everything in Haechi funnels through `createHaechi(...).protectJson(payload, context)` in `packages/core/index.mjs`:

1. `collectStringEntries` walks the JSON tree and yields entries for **string leaves, finite number leaves (stringified), and object key names** — numbers and keys were added in 0.3.2 after the review found card-numbers-as-JSON-numbers and PII-as-map-keys passing through undetected ([[2026-06-10-full-security-review]], P1-SEC-023).
2. `filterEngine.detect` runs regex rules with optional validators (Luhn, KR RRN checksum). Custom rules are ReDoS-screened (length cap, nested-quantifier and backreference bans).
2.5. `applyPrecisionControls` (WS2c, after detect / before decide) applies the operator precision dials: `filters.minConfidence` drops a sub-threshold detection and `filters.allowlist` suppresses a value/path-matched detection. **Hard-block invariant ([[fail-closed]]):** a `HARD_BLOCK_TYPES` detection (`secret`/`api_key`/`kr_rrn`/`card`, exported from `packages/filter`) is NEVER removed — minConfidence trims only soft types and an allowlist entry for a hard-block type is ignored. Suppressions/drops are audited by count+type only (`summary.suppressedByType`/`droppedByType`), never the raw value. Defaults (`minConfidence:0`, `allowlist:[]`) preserve pre-WS2c behavior.
3. `policyEngine.decide` maps detection type → action via presets merged under `ACTION_STRENGTH` ordering (allow=0 … block=3); merges may strengthen but never weaken ([[fail-closed]]).
4. `transformPayload` applies `redact`/`mask`/`tokenize`/`encrypt` per group; `block` short-circuits to a null payload. Value/number groups transform before key groups (key renames would invalidate child paths); key renames go deepest-first, collisions get `#n` suffixes.
5. `auditSink.record` writes a sanitized event ([[audit-integrity]]).

## Enforcement modes

`dry-run` and `report-only` (`NO_ENFORCE_MODES`) detect and audit but never mutate or block — the default config ships in `dry-run`, which is why the proxy and `protect` CLI print loud non-enforcement warnings (P2-DOC-005). Mode can come from `config.mode`, `policy.mode`, or per-call `context.mode`; `policy.mode ?? config.mode` is the effective resolution everywhere.

## Known detection exclusions (documented, not bugs)

Base64/URL-encoded values, unicode obfuscation, URL query strings, and SSE/NDJSON streams ([[streaming-protection-gap]]). Listed in `docs/current/threat-model.md` §4.
