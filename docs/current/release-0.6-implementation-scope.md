# Haechi 0.6 Implementation Scope

- Status: Draft 0.1 (design — not yet implemented)
- Date: 2026-06-10
- Target version: 0.6.0 (after 0.5.0)
- Type: auth and per-client controls

## 1. Release Goal

Implement the `authProvider`/`identity` contracts reserved in 0.4 and turn identity into real per-client controls: built-in bearer authentication, named per-client policy profiles, model allowlisting, and request rate limiting. This makes Haechi safe(r) to put in front of multiple clients/agents on one host.

**Scope decision (2026-06-10):** 0.6 is focused on the auth core. The heavier operational items originally grouped under 0.6 — Vault/AWS KMS reference adapter, external append-only audit sink, signed release artifacts, npm org (`@haechi/*`) acquisition — move to **0.7** so each gets its own security design instead of bloating one release.

## 2. Scope

### 2.1 `authProvider` contract (core-owned)

- `authenticate(request) → identity | null` (null = deny). `request` is the Node `IncomingMessage`; only headers are available — the body is **not** read yet.
- Fail-closed: a throwing provider is treated as deny. Injected via `createRuntime(config, { authProvider })`.
- Selected by `auth.provider`:
  - `none` (default) — no authentication; `identity` stays `null` (byte-identical audit shape to 0.5). Per-client policy resolves to the default profile / base policy.
  - `bearer` — built-in token auth (§2.2).
  - `external` — requires an injected `authProvider`; fail-closed if absent (mirrors `keys.provider: external`). The OIDC/JWT providers remain **0.7+ satellite packages** (`@haechi/auth-oidc`); 0.6 ships no network IdP code.

### 2.2 Built-in bearer auth + token store

- Credentials live in a **separate file** `.haechi/auth.json` (mode `0600`), never in `haechi.config.json`:
  ```json
  {
    "version": 1,
    "tokens": [
      { "id": "tok_auth_ab12cd", "tokenHash": "...", "type": "service",
        "scopes": ["team:eng"], "labels": { "env": "prod" },
        "createdAt": "...", "disabled": false }
    ]
  }
  ```
- `tokenHash` = `HMAC(derive("haechi:auth:token:v1"), token)` — keyed, domain-separated ([[key-management]] discipline), never a bare hash. Lookup uses a timing-safe comparison.
- Tokens are high-entropy `hae_<base64url(32 bytes)>`. The **plaintext is shown once at creation and never stored.**
- CLI:
  - `haechi auth add --type user|service|agent [--scope k:v ...] [--label k=v ...]` → mints a token, stores its hash + metadata, prints the plaintext once.
  - `haechi auth list` → ids, type, scopes, labels, createdAt, disabled — never the token or its hash.
  - `haechi auth revoke <id>` → sets `disabled: true`.
- Label keys are validated against `auth.allowedLabelKeys` (default `["team", "env", "tier", "role"]`); values are length-limited. PII in labels is rejected at `add` time.

### 2.3 Identity construction (PII-safe)

On a bearer match, build the reserved `identity` object:
- `id`: the token record id (opaque).
- `type`: from the record.
- `subjectHash`: `HMAC(derive("haechi:identity:hash:v1"), record.id)`; `issuerHash`: HMAC of `"bearer-local"`. Bare SHA-256 of any identifier is prohibited.
- `provider`: `"bearer"`.
- `scopes`, `labels`: from the record (already allowlist-validated).

The same identity is attached to every audit event for the request (protect events, decisions). `identity` remains `null` under `auth.provider: none`.

### 2.4 Named policy profiles (per-client policy)

`policy` gains profiles and a binding map:
```json
"policy": {
  "mode": "enforce", "presets": ["..."], "actions": { },          // base / fallback policy
  "profiles": {
    "strict":   { "presets": ["strict-block"] },
    "internal": { "presets": ["llm-redact"], "actions": { "email": "allow" },
                  "modelAllowlist": ["llama3"], "rate": { "requestsPerMinute": 120 } }
  },
  "profileBinding": {
    "byScope": { "team:eng": "internal" },
    "byLabel": { "tier=trusted": "internal" },
    "default": "strict"
  }
}
```
- A profile compiles through the existing `buildPolicy` (presets + actions, strengthen-only merges preserved). `modelAllowlist` and `rate` are optional per-profile, falling back to base-level values.
- Resolution order per request: **scope match → label match → `profileBinding.default`**. First match wins; scope precedes label. `profileBinding.default` is **required** when `profiles` is set, and should be the most restrictive profile (fail-closed for unmatched/anonymous identities).
- With `auth.provider: none` or no `profiles`, the base `policy` applies unchanged (full backward compatibility).
- Implementation: `createRuntime` compiles a `{ name → policyEngine }` map at startup (all profiles validated up front). `protectJson(payload, context)` accepts `context.policyEngine` and uses it over the default. The proxy resolves the profile after `authenticate` and threads the selected engine through.

### 2.5 Model allowlist

- Per-profile `modelAllowlist` (and base-level `policy.modelAllowlist`): if set and the request body's `model` is not listed → `403 haechi_model_not_allowed` (audited, model name included — model names are not secret). Empty/absent = allow all.
- Runs **after** body read (the `model` field lives in the JSON body).

### 2.6 Rate limiting

- In-memory, per-process fixed-window counter keyed by `identity.id` (or `"anonymous"`). **Documented limits:** resets on restart, not shared across replicas — acceptable for a single-process self-hosted preview.
- Per-profile / base `rate.requestsPerMinute`. Over the limit → `429 haechi_rate_limited` (audited with identity + limit).
- Runs **before body read** (cheap, by identity) so a throttled-but-authenticated client cannot DoS with large bodies.
- LLM **token budget** (tokens-per-window) is deferred — it requires counting model tokens; noted as 0.7+ backlog.

### 2.7 Proxy execution order (the reserved contract, finalized)

```
GET /__haechi/health                      (always unauthenticated; exposes mode only)
assertRelativeProxyTarget(request.url)
route classify
authProvider.authenticate(request)        → 401 haechi_auth_denied on deny; request stream NOT consumed
resolve policy profile from identity
rate limit by identity                    → 429 haechi_rate_limited
body read (bounded by limits.maxRequestBytes)
model allowlist check                     → 403 haechi_model_not_allowed
protect / enforce  (selected profile's policyEngine)
forward
```

### 2.8 Audit additions

- Successful auth attaches the PII-safe `identity` to every event; events also carry the resolved `profile` name (`null` when no profiles). Both are non-sensitive.
- New decisions: `auth_denied` (reason: `no_token` | `invalid_token` | `provider_error`; no raw token), `model_not_allowed`, `rate_limited`. All carry the attempted/resolved identity where known, never plaintext credentials.

## 3. Config schema summary

```json
"auth": {
  "provider": "none",                     // none | bearer | external
  "store": ".haechi/auth.json",
  "allowedLabelKeys": ["team", "env", "tier", "role"]
}
```
Plus `policy.profiles`, `policy.profileBinding`, `policy.modelAllowlist`, `policy.rate` (§2.4–2.6). All validated fail-closed (unknown provider, missing `profileBinding.default` when profiles set, unknown profile names in bindings, non-positive `rate`, etc.).

## 4. Explicit non-scope (deferred to 0.7+)

- OIDC/JWT providers (`@haechi/auth-oidc`, `@haechi/auth-jwt`) — 0.6 ships bearer + external-injection only.
- Vault/AWS KMS reference adapter; external append-only audit sink; signed release artifacts; npm org `@haechi/*`.
- LLM token-budget limiting; distributed/shared rate state.
- Dynamic npm loading of auth providers (1.0 plugin sandbox).

## 5. Backward compatibility

`auth.provider` defaults to `none`; with no `profiles`, 0.6 behaves exactly like 0.5 (identity `null`, single base policy). The only audit-shape change is the always-present `profile` field (mirrors how `identity` was introduced) — documented, no migration needed for an unpublished-consumer preview.

## 6. Test criteria (for implementation)

- bearer: valid token → identity; missing/invalid → 401 `auth_denied`, body not consumed, timing-safe lookup; revoked token denied.
- external provider injected → used; absent → fail-closed.
- profile resolution: scope match, label match, default fallback; missing default fails validation; different profiles apply different actions/allowlists.
- model allowlist: allowed passes, disallowed → 403.
- rate limit: N pass / N+1 → 429 within a window; window reset; per-identity isolation; pre-body enforcement.
- auth CLI: `add` prints token once; `list` never reveals token/hash; `revoke` disables.
- `/__haechi/health` unauthenticated.
- audit: identity PII-safe (no raw token/subject), `profile` recorded, chain valid; `auth_denied`/`model_not_allowed`/`rate_limited` decisions present.

## 7. Suggested PR breakdown (stacked)

1. `authProvider` contract + bearer store + `haechi auth` CLI + identity construction.
2. Named policy profiles + per-request policy engine selection.
3. Model allowlist + rate limiting + proxy execution-order wiring.
4. 0.6.0 release cut (version, docs EN/KO, threat-model/risk-register/api-stability, wiki).
