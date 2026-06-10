---
updated: 2026-06-10
tags: [decision, security, auth]
---

# Identity and Auth

Contracts reserved in 0.4 (§2.7–2.8), designed and **shipped in 0.6** (`release-0.6-implementation-scope.md`, PRs #17–#19) ([[release-roadmap]]). Core owns the contract; OIDC/JWT implementations are 0.7+ satellites ([[packaging-and-distribution]]).

## Identity schema (PII-safe by construction)

`identity` is a first-class field in audit events and protect context (always `null` until 0.6). Hard rules:

- `subjectHash`/`issuerHash` are **keyed HMACs** over the `haechi:identity:hash:v1` derived key ([[key-management]]) — bare SHA-256 of emails/usernames is dictionary-reversible and prohibited.
- `labels` is allowlist-only (keys declared in config, length-limited values, no PII). A freeform labels map would be a plaintext leak hole through [[audit-integrity]].
- Display names are a dashboard-side opt-in, never part of the audit schema.

## authProvider contract

`authenticate(request) → identity | null`, fail-closed. Proxy ordering is load-bearing:

```
target validation → route classify → authenticate → policy scope → body read → protect → forward
```

Auth runs **before** body read so failed-auth requests cannot DoS with large bodies; on 401 the request stream is not consumed. Auth denials audit as `auth_denied` (attempted provider only). `/__haechi/health` stays intentionally unauthenticated (exposes mode only).

## Why identity was reserved early

It threads through everything later: audit attribution (dashboard), per-client policy scope (0.6), and vault token binding for detokenization. Adding it to the audit schema in 0.4 costs nothing; adding it later is a schema migration.

## 0.6 design (finalized 2026-06-10)

Three decisions set the shape (`release-0.6-implementation-scope.md`):

1. **Scope = auth core only.** bearer auth + named policy profiles + model allowlist + rate limit. KMS adapter / external audit sink / signed artifacts / npm org pushed to 0.7.
2. **Per-client policy = named profiles.** `policy.profiles` + `policy.profileBinding` (byScope → byLabel → required `default`); resolution is fail-closed to the default profile for unmatched/anonymous identities. A per-request `policyEngine` is threaded into `protectJson`.
3. **Bearer tokens = separate file + CLI.** `.haechi/auth.json` (0600) stores keyed-HMAC token hashes (`haechi:auth:token:v1`); `haechi auth add/list/revoke`; plaintext shown once. Never in `haechi.config.json`.

Proxy order (load-bearing): authenticate → resolve profile → rate-limit (pre-body) → body read → model allowlist → protect → forward. New audit decisions: `auth_denied`, `model_not_allowed`, `rate_limited`; every event gains a non-sensitive `profile` field. Default `auth.provider: none` keeps 0.5 behavior (identity null).
## 0.8: `haechi-auth-jwt` (shipped, PR3)

The first external auth satellite — headless JWKS bearer verification ([[packaging-and-distribution]]). `createJwtAuthProvider({ issuer, audience, jwksUri, cryptoProvider, ... })` implements the `authProvider` contract with `node:` builtins only (no `jose`).

- **Identity construction is core-owned.** New core export `buildExternalIdentity({ provider, subject, issuer, type, scopes, labels }, cryptoProvider)` builds the PII-safe identity (keyed-HMAC `subjectHash`/`issuerHash` over `haechi:identity:hash:v1`, the same domain as bearer); the satellite supplies raw claims and never sees the domain. A non-PII `id` (`jwt:<first16 of subjectHash>`) replaces any raw subject.
- **Security is decision, not discretion** (`release-0.8-implementation-scope.md` §2.4): server-side `algorithms` allowlist (reject `alg:none` and `HS*` alg-confusion; ES256 needs `dsaEncoding: "ieee-p1363"`); `kid` required; RSA ≥ 2048; JWK `use`/`key_ops` checked; JWE rejected; `iss`/`aud`(string|array of strings)/`sub`(non-empty, trimmed)/`exp`/`nbf` all mandatory with a clock-skew **cap of 300 s**; SSRF-guarded JWKS (HTTPS + issuer-host match + private/loopback/link-local(fe80::/10)/ULA/multicast/metadata refusal on literal host **and** resolved IPs; brackets stripped before classification); 1 MiB body + depth-bounded JSON; JWKS cache TTL with **one refetch per cooldown** governing all triggers (stale, empty, unknown-kid) — `lastRefetchAt` set before the await so a failing IdP can't be stormed.
- **Scope:** single-origin issuers only (issuer host == JWKS host); multi-origin/CDN JWKS and full interactive `haechi-auth-oidc` are 0.9.

Two adversarial reviews drove fixes: the resolveJwk double-refetch (stale + unknown kid → 2 fetches; the old two-gate state machine wasn't unified), the IPv6 `fe80::/10` partial match (only `fe80` prefix), the bracketed-IPv6-literal host bypassing the blocklist, whitespace-only `sub`, heterogeneous `aud` arrays, and the JWKS body-size check ordering.
