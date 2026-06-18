---
updated: 2026-06-18
tags: [concept, security, crypto]
---

# Key Management

Local software keys only (`packages/crypto/index.mjs`); production KMS/HSM/Vault custody is explicitly out of scope for core and composes in via provider injection ([[runtime-composition]]).

## Key file

`.haechi/dev.keys.json`, mode 0600, JWK-ish entries `{kid, kty, alg, status, k}`. One `active` key; others `retired`.

## Rotation (0.3.2 redesign, P1-SEC-019)

- `initLocalKeyFile --force` **retires** prior keys instead of overwriting them — before this fix, `npm run demo:init` run twice permanently orphaned every envelope and vault record.
- `encrypt` uses the active key and stamps `kid` into the envelope; `decrypt` selects by `envelope.kid` so retired-key data stays readable.

## Init validates an existing key file (P2-CR-007, toward 1.3.1)

`initLocalKeyFile` no longer reports success for a present-but-corrupt key file. On the existing-file (non-`--force`) path it now validates via a shared `loadKeyFile(keyFile, { requireActive: true })` (the same loader `loadKeys()` delegates to): corrupted JSON, a missing active key, or a wrong-length (non-32-byte) active **or retired** key all **throw** before success is reported. A valid file stays non-destructive (not rewritten/rotated). Without this, a corrupted file passed `init` and only failed later during encrypt/decrypt/token/bundle ops.

## Domain separation (one stored key, many derived keys)

The raw stored key is an AES-256-GCM key and must never be used directly for anything else. Derived keys via `HMAC(rawKey, domainString)`:

| Domain string | Use |
|---|---|
| `haechi:policy-bundle:signing:v1` | Policy bundle HS256 signing (P1-SEC-020) |
| `haechi:token-vault:deterministic:v1` | Deterministic tokens, 0.4 ([[token-vault]]) |
| `haechi:identity:hash:v1` | Identity subject/issuer hashing, 0.4+ ([[identity-and-auth]]) |

Rule for new features: never bare-SHA256 a low-entropy identifier (dictionary-reversible) and never reuse the raw key — add a new versioned domain string.

## AEAD discipline

Every envelope binds canonicalized AAD (sorted-key JSON, `canonicalize` in `packages/crypto/index.mjs`) and stores `aadHash`; decrypt verifies AAD before attempting GCM. `canonicalize` sorts object keys recursively, so JSON key reordering yields identical AAD (this is why a chunk of the gap review's "AAD canonicalization" concern, GAP-P0-001, was already closed). The encrypt-action AAD binds `{context, path, type, ruleId}` (`packages/core/index.mjs`), pinning an envelope to its leaf.

## Nonce budget (GCM random-IV invocation limit, GAP-P0-002 / nonce half)

`encrypt` uses a fresh random 96-bit IV per call (`randomBytes(12)`) — no deterministic (key, IV) reuse on retries, streaming, or deterministic tokenization (deterministic tokens are HMAC-derived **ids**; the stored ciphertext is still a random-IV envelope). Random 96-bit IVs are only safe up to ~2^32 encryptions per key (birthday bound; NIST SP 800-38D §8.3). So the local provider **counts encryptions per `kid` and fails closed at 2^32**:

- The count is persisted to the key file (`usage` per key entry, additive/back-compat) in **pre-reserved windows** (`NONCE_RESERVE_WINDOW`, default 2^20) — the window is written *before* it is consumed, so a crash/restart can only over-count (skip an unused tail), never under-count into reuse. ~one key-file write per million encryptions.
- A one-time `process.emitWarning` at 50% (`code: HAECHI_NONCE_BUDGET`); a fail-closed throw at the limit instructing `init --force` rotation. Rotation mints a fresh active key with `usage: 0` (the old key's frozen count only matters for decrypt, which generates no IV).
- **Residuals (documented in [[fail-closed]] / threat-model §3):** a read-only key file degrades to a per-PROCESS limit (`HAECHI_NONCE_BUDGET_NOPERSIST`, warned); multiple processes sharing one key file are out of scope (single-writer reference provider; production custody = KMS satellite). Enforced by `tests/nonce-budget.test.mjs` and the `gate:security` CI job.
