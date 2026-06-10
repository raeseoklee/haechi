---
updated: 2026-06-10
tags: [decision, security, auth]
---

# Identity and Auth

Contracts reserved in 0.4 (`release-0.4-implementation-scope.md` §2.7–2.8), implemented in 0.6 ([[release-roadmap]]). Core owns the contract; implementations live in satellite packages ([[packaging-and-distribution]]).

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
