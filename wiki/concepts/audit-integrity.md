---
updated: 2026-06-16
tags: [concept, security, audit]
---

# Audit Integrity

JSONL sink (`packages/audit/index.mjs`) with three guarantees and one documented limitation.

## Guarantees

1. **No plaintext.** `sanitizeAudit` strips `FORBIDDEN_KEYS` (value, plaintext, payload, content, message, prompt, secret) recursively; detection paths hash key names (`key_<hash>` via `safePathToString`); detections carry type/rule/confidence but never the matched value.
2. **Tamper evidence.** Each record embeds `auditIntegrity` (sequence, previousHash, eventHash over canonicalized JSON) — a SHA-256 hash chain verifiable with `verifyAuditChain()` (detects modification, reordering, sequence gaps). A `haechi audit-verify` CLI is planned for 0.4. Focused **middle-record** tamper regressions (P2-CR-011, `tests/audit-chain-tamper.test.mjs`) pin that a real multi-record log is rejected on content mutation (stale `eventHash`), a missing or wrong `previousHash`, and a wrong `eventHash`.
3. **Concurrent safety.** Per-sink write queue + lock file serialize chain building; appends read only the file tail (O(1), P1-OPS-008); stale locks are stolen after 30s.

## Tail truncation (mitigated in 0.7)

Deleting the last N records is undetectable from the chain alone — the shortened chain still verifies. **0.7 closes this** with built-in head-hash anchoring (`audit.anchor.mode: file|stdout`): each record's chain head is appended to a separate append-only stream, and `verifyAuditChain(path, { anchorPath })` flags a chain shorter than the last anchor as truncated. Bounded: detection reaches back only to the last anchor (one record with `everyRecords: 1`). Design: `release-0.7-implementation-scope.md`.

## Event vocabulary

Beyond protect events: proxy bypass decisions (`streaming_request_pass_through`, `response_unprotected_allowed/blocked`), vault governance ([[token-vault]]), and reserved `identity: null` for 0.4+ ([[identity-and-auth]]).
