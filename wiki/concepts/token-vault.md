---
updated: 2026-06-10
tags: [concept, security, tokenization]
---

# Token Vault

Local tokenization store (`packages/token-vault/index.mjs`): `tokenize` replaces a detected value with `[TOKEN:tok_<type>_<hash>]` and stores the plaintext **encrypted** (AES-256-GCM envelope, AAD-bound to token+type+context) in `.haechi/token-vault.json`.

## Governance model

- `revealPolicy: "disabled"` (default) — reveal throws; `"local-dev"` only via explicit config or CLI `--allow-dev-reveal`.
- Since 0.3.2 every reveal/purge decision is audited: `reveal_allowed/denied/failed`, `purge`, `purge_expired` — token ids only, never plaintext (P1-SEC-017).
- `retentionDays` actually deletes: expired tokens are pruned on every vault mutation, plus `purgeExpired()` / `haechi token-purge --expired` (P1-SEC-021). Before 0.3.2 retention only blocked reveal.

## Concurrency

Mutations serialize through an in-process queue + a `.lock` file (cross-process), with atomic temp-file-then-rename writes. Stale locks (>30s mtime) are stolen automatically (P1-OPS-007).

## Shipped in 0.4.0 ([[release-roadmap]])

- **Deterministic tokenization** (opt-in): HMAC over a `haechi:token-vault:deterministic:v1` derived key ([[key-management]]) so equal values get equal tokens. Trade-off: linkability.
- **Request-scoped response detokenization**: only tokens issued/reused during a request's protect phase are restored in its response — no session store; multi-turn works because resent history re-tokenizes deterministically. Decoupled from `revealPolicy` via a separate `detokenizeResponses` switch.
