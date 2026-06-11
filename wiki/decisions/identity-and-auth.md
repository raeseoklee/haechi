---
updated: 2026-06-11
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

## 0.9: per-request vs interactive — two halves of auth

0.8's `haechi-auth-jwt` validates a *pre-obtained* bearer JWT per request. 0.9 adds the **interactive** half — a human logging in through a browser — and refactors auth-jwt so both share one verification path.

### `haechi-auth-jwt@0.2.0`: extracted JWS verifier (additive, behavior-preserving)

The satellite now **exports `createJwtVerifier`** (and `isBlockedAddress`), a standalone primitive carved out of the existing internal `resolveJwk`/`verifySignature`/claim-validation. It verifies signature + `alg`/`kid`/RSA-bits + `iss`/`aud`/`exp`/`nbf` — the exact 0.8 surface. **`nonce` is deliberately NOT baked in** (a bearer JWT has none): `verify(jwt, { expectedNonce })` checks it only when the caller passes it. `createJwtAuthProvider` is reimplemented on the primitive, still owns Bearer-header parsing, and keeps all its 0.8 tests green. The result: the whole auth ecosystem has exactly **one** audited JWS/JWKS verification path.

### `haechi-auth-oidc@0.1.0`: interactive session broker

The interactive-auth satellite ([[oidc-session-broker]]) — `createOidcSessionBroker(...)` implements the OIDC authorization-code + PKCE flow, produces an opaque server-side session, and satisfies the [[dashboard-audit-viewer]]'s `sessionGuard` contract by injection. It is **not** an `authProvider` (the per-request role stays with `createJwtAuthProvider`). It **reuses this page's `buildExternalIdentity`** to build the PII-safe identity (keyed-HMAC `subjectHash`, domain `haechi:identity:hash:v1`, `provider: "oidc"`) and the auth-jwt `createJwtVerifier` for ID-token validation — layering an OIDC `aud`/`azp` profile on top (stricter than the lenient bearer `aud`: multi-valued `aud` requires `azp === clientId`). It peer-depends on `haechi-auth-jwt >=0.2.0` for the verifier; the core peer stays `>=0.8.0` (only `buildExternalIdentity` is used).

Broker login security is concentrated at `/auth/callback`: a **state-first short-circuit** (atomic `take()` of a pre-auth-cookie-bound pending record, constant-time state compare **before any IdP egress**), PKCE S256, `nonce` binding, RFC 9207 `iss` pinning (mix-up defense), a fresh session id at callback (no fixation), and PII-safe audit events (`oidc.login.*`/`logout`/`session.evict`) carrying only `*Hash`/`reasonCode`/`provider`/timestamp. The one core touch is additive: `packages/audit` `FORBIDDEN_KEYS` gains the broker token/claim keys.

## 1.0: the `authProvider` contract is frozen + a signed-plugin loader

1.0 (`docs/current/release-1.0-implementation-scope.md`; PRs #46–#49) does two things to auth.

**The `authProvider` contract is now FROZEN** as part of the 1.0 API-stability freeze (risk **P2-API-001**): `authenticate(request) → identity | null`, fail-closed, and the **5-key audit-identity projection** `{ id, type, subjectHash, issuerHash, provider }` are stable-contract. `assertAuthProviderConformance` (new in `packages/auth`, the auth analog of `assertCryptoProviderConformance`) is the contract's correctness gate. `FORBIDDEN_KEYS` ([[audit-integrity]]) is extended to also strip `claims`/`subject`/`issuer`/`credential`/`authorization`/`signature`/`entry` **and** `scopes`/`labels` — so even an un-projected identity object can't leak attacker-controlled plugin output; scopes/labels are deliberately NOT part of the persisted identity.

**The sandbox loads a *signed* `authProvider` plugin** ([[plugin-sandbox]]). 1.0 lifts the dynamic-loading ban **narrowly** — `authProvider`-only, Ed25519-signed, capability-gated, `worker_threads`-isolated, fully audited (`packages/plugin/signing.mjs` + `sandbox.mjs`, risks **P1-SEC-024**/**P1-SEC-025**). The host builds the keyed-HMAC identity via this page's `buildExternalIdentity` (`provider: "plugin:<id>"`) from the claims the worker returns; the crypto key never crosses to the worker. Honest residual: the worker is memory/crash isolation + data-minimization, **not** capability enforcement — a malicious signed plugin can still use fs/net and exfiltrate the credential it validates; the trust gate (signature + operator allowlist + pin + revocation) is the load-bearing control, with child-process+permission enforcement deferred to 1.x. **Injection (`createRuntime(config, providers)`) stays the default** — the sandbox is opt-in (`auth.provider: "plugin"`); `none`/`bearer`/`external` are unchanged.
