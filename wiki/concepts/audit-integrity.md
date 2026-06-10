---
updated: 2026-06-10
tags: [concept, security, audit]
---

# Audit Integrity

JSONL sink (`packages/audit/index.mjs`) with three guarantees and one documented limitation.

## Guarantees

1. **No plaintext.** `sanitizeAudit` strips `FORBIDDEN_KEYS` (value, plaintext, payload, content, message, prompt, secret) recursively; detection paths hash key names (`key_<hash>` via `safePathToString`); detections carry type/rule/confidence but never the matched value.
2. **Tamper evidence.** Each record embeds `auditIntegrity` (sequence, previousHash, eventHash over canonicalized JSON) — a SHA-256 hash chain verifiable with `verifyAuditChain()` (detects modification, reordering, sequence gaps). A `haechi audit-verify` CLI is planned for 0.4.
3. **Concurrent safety.** Per-sink write queue + lock file serialize chain building; appends read only the file tail (O(1), P1-OPS-008); stale locks are stolen after 30s.

## Known limitation: tail truncation

Deleting the last N records is undetectable from the file alone — the shortened chain still verifies. Documented in `threat-model.md` §4. Mitigation path: anchor the chain head hash externally (`audit-verify` outputs it; periodic anchoring is 0.6+ [[release-roadmap]]).

## Event vocabulary

Beyond protect events: proxy bypass decisions (`streaming_request_pass_through`, `response_unprotected_allowed/blocked`), vault governance ([[token-vault]]), and reserved `identity: null` for 0.4+ ([[identity-and-auth]]).
