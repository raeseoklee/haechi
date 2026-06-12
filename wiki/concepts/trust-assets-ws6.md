---
updated: 2026-06-12
tags: [concept, security, proxy, tls, disclosure, compliance, ws6]
---

# Trust Assets (WS6)

The reliability-hardening-track's last workstream before the 1.2.0 cut. One **code control** (proxy TLS / remote-bind hardening) plus a set of **disclosure/trust documents**. Additive, no version bump — accumulates on `main` for 1.2.0.

## The code control — proxy TLS / remote-bind hardening

The load-bearing piece. Before WS6, `assertSafeProxyBind` refused a non-loopback host unless `--allow-remote-bind`, but when remote-bind *was* set the proxy served **plain HTTP** — so a remote bind exposed bearer tokens + payloads in cleartext.

The fix mirrors the [[dashboard-audit-viewer]] satellite's already-solved pattern (`hasUsableTlsMaterial` + https-when-tls-present + fail-closed remote bind):

- `hasUsableTlsMaterial(ctx)` (exported from `packages/proxy`) = `(ctx.key && ctx.cert) || ctx.pfx` — the single source of truth shared by config validation, the bind guard, and server selection. Same shape the dashboard uses.
- Config keys (additive, defaults preserve 1.1): `proxy.tls` (null, or `{ keyFile, certFile }` / `{ pfxFile, passphrase? }` — file **paths** loaded at startup by `normalizeConfig` via `node:fs.readFileSync` into a `{ key, cert }`/`{ pfx }` tlsContext, fail-closed validated) and `proxy.trustForwardedProto` (boolean) — the operator's explicit acknowledgement that a trusted reverse proxy terminates TLS in front of Haechi.
- Two-layer bind guard: `assertSafeProxyBind` keeps its **original** `{ host, allowRemoteBind }` contract (so the dashboard's reuse is unaffected). A **new** `assertSafeProxyTransport({ host, allowRemoteBind, hasUsableTls, trustForwardedProto })` adds the WS6 rule: a remote bind requires a usable tlsContext OR `trustForwardedProto`, else it throws at startup.
- Server selection in `createHaechiProxy`: usable tlsContext → `https.createServer(tlsContext, handler)`; else `http.createServer(handler)` (unchanged for loopback/dev). `servesHttps` + `listen().tls` reflect the scheme; the CLI log line shows `https`/`http`.
- When the remote bind rests on `trustForwardedProto` (plain http behind a trusted TLS hop), every protected request whose `X-Forwarded-Proto` is not `https` is rejected 403 fail-closed, checked **before auth/body**. The `/__haechi/*` liveness/metrics routes are exempt (they leak nothing).

This is [[fail-closed]] confidentiality-in-transit: a remote bind can NEVER serve tokens/payloads in plaintext. Tests: `tests/proxy-tls.test.mjs` (throw-without-TLS, https-over-TLS smoke using a committed self-signed cert fixture at `tests/fixtures/tls/`, forwarded-proto rejection, loopback-stays-http, fail-closed malformed config).

## The disclosure / trust documents

- `docs/current/security-whitepaper.md` (+`.ko`): maps SHIPPED controls (C1–C16) to OWASP LLM Top 10 (2025) and NIST AI RMF (GOVERN/MAP/MEASURE/MANAGE), plus a structured self-pentest referencing the real-environment validation ([[2026-06-11-real-environment-validation]]) and the adversarial findings the track fixed (WS2d Unicode evasion, WS2c bearer-recall regression, WS5 deep-nesting, P1-SEC-009 SSRF, this WS6 plaintext remote-bind). Honest framing: a control mapping + self-assessment, NOT a certification or independent audit. Only controls that exist are mapped.
- `.well-known/security.txt` + repo-root `security.txt` (RFC 9116): `Contact` → the GitHub security-advisory URL, `Expires`, `Preferred-Languages: en, ko`, `Policy` → SECURITY.md, `Canonical`. Repo/disclosure assets — NOT in the npm `files` allowlist (deliberately absent from the tarball).
- `SECURITY.md` (+`.ko`) Reporting update: GitHub private vulnerability reporting (Security Advisories), a best-effort triage target (ack within 3 business days, assessment within 10), and a pointer to `security.txt`.
- `docs/current/compliance-mapping.md` (+`.ko`): control → obligation-category table (data minimization, access logging, retention, subject rights, …) + a DSAR/retention operational workflow (access/erasure → token-vault reveal/purge governance + the WS4-B chain-aware audit rotation/retention). A MAPPING, not a certification (track non-goal §5). Cross-links shared-responsibility + operations-runbook.

## Why this shape

`assertSafeProxyBind` stays a separate primitive from `assertSafeProxyTransport` precisely because the dashboard satellite imports `assertSafeProxyBind` and layers its own tlsContext precedence after it — changing that signature broke the satellite mid-implementation, so the TLS rule was lifted into a new, additive export instead. This is the same "satellite reuses a core primitive; don't change its contract" discipline as [[runtime-composition]].
