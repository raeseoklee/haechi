---
updated: 2026-06-10
tags: [concept, security, crypto]
---

# Key Management

Local software keys only (`packages/crypto/index.mjs`); production KMS/HSM/Vault custody is explicitly out of scope for core and composes in via provider injection ([[runtime-composition]]).

## Key file

`.haechi/dev.keys.json`, mode 0600, JWK-ish entries `{kid, kty, alg, status, k}`. One `active` key; others `retired`.

## Rotation (0.3.2 redesign, P1-SEC-019)

- `initLocalKeyFile --force` **retires** prior keys instead of overwriting them — before this fix, `npm run demo:init` run twice permanently orphaned every envelope and vault record.
- `encrypt` uses the active key and stamps `kid` into the envelope; `decrypt` selects by `envelope.kid` so retired-key data stays readable.

## Domain separation (one stored key, many derived keys)

The raw stored key is an AES-256-GCM key and must never be used directly for anything else. Derived keys via `HMAC(rawKey, domainString)`:

| Domain string | Use |
|---|---|
| `haechi:policy-bundle:signing:v1` | Policy bundle HS256 signing (P1-SEC-020) |
| `haechi:token-vault:deterministic:v1` | Deterministic tokens, 0.4 ([[token-vault]]) |
| `haechi:identity:hash:v1` | Identity subject/issuer hashing, 0.4+ ([[identity-and-auth]]) |

Rule for new features: never bare-SHA256 a low-entropy identifier (dictionary-reversible) and never reuse the raw key — add a new versioned domain string.

## AEAD discipline

Every envelope binds canonicalized AAD (sorted-key JSON) and stores `aadHash`; decrypt verifies AAD before attempting GCM.
