---
updated: 2026-06-10
tags: [decision, security, auth]
---

# Identity and Auth

Contracts reserved in 0.4 (`release-0.4-implementation-scope.md` §2.7–2.8); **0.6 design finalized** in `release-0.6-implementation-scope.md` ([[release-roadmap]]). Core owns the contract; OIDC/JWT implementations are 0.7+ satellites ([[packaging-and-distribution]]).

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