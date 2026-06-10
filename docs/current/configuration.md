# Haechi Configuration Reference

- Status: Living document
- Target version: 0.6.0

`haechi init` writes `haechi.config.json`; a non-secret template is at `haechi.config.example.json`. Every command reads it with `--config <path>` (default `haechi.config.json`). Configuration is **validated fail-closed**: unknown providers, out-of-range numbers, and malformed values throw at load time rather than degrading silently. `haechi config` prints this reference; `haechi status` prints the *effective* state of a given config.

## Full default

```json
{
  "mode": "dry-run",
  "target": { "type": "llm-http", "adapter": "openai-compatible", "upstream": "http://127.0.0.1:9999" },
  "proxy": { "host": "127.0.0.1", "port": 1016 },
  "responseProtection": { "enabled": false, "mode": "enforce", "failureMode": "fail-closed", "allowNonJson": false, "allowCompressed": false, "maxBytes": 1048576 },
  "streaming": { "requestMode": "block" },
  "limits": { "maxRequestBytes": 1048576, "upstreamTimeoutMs": 120000 },
  "policy": { "mode": "dry-run", "presets": ["korean-pii", "secrets-only", "llm-redact"], "defaultAction": "redact", "actions": { "card": "block" } },
  "filters": { "customRules": [] },
  "keys": { "provider": "local", "keyFile": ".haechi/dev.keys.json" },
  "audit": { "sink": "jsonl", "path": ".haechi/audit.jsonl" },
  "tokenVault": { "provider": "local", "path": ".haechi/token-vault.json", "revealPolicy": "disabled", "retentionDays": 30, "deterministic": false, "deterministicTypes": null, "detokenizeResponses": false },
  "privacy": { "profile": null },
  "mcp": { "allowedMethods": ["initialize", "tools/call", "resources/read", "prompts/get"], "protectParams": true, "protectResults": true, "requireJsonRpc": true }
}
```

## Top level

| Key | Type / values | Default | Notes |
|---|---|---|---|
| `mode` | `dry-run` \| `report-only` \| `enforce` | `dry-run` | Global enforcement mode. `dry-run`/`report-only` detect + audit only; `enforce` transforms/blocks. Overridden by `policy.mode` when set. |

## `target`

| Key | Type / values | Default | Notes |
|---|---|---|---|
| `target.type` | `llm-http` \| `openai-compatible` \| `vllm-openai` \| `ollama` \| `llama-cpp` | `llm-http` | Selects the protocol adapter. `llm-http` aliases `openai-compatible`. Unknown values **fail closed** at load. |
| `target.adapter` | same set | `openai-compatible` | Explicit adapter override; usually leave unset and let `type` decide. |
| `target.upstream` | URL string | `http://127.0.0.1:9999` | The only upstream the proxy forwards to. Request targets must be origin-form paths; absolute-URL targets are rejected (SSRF guard). |

## `proxy`

| Key | Type / values | Default | Notes |
|---|---|---|---|
| `proxy.host` | non-empty string | `127.0.0.1` | Bind address. Non-loopback hosts require the `--allow-remote-bind` CLI flag — config alone will not start (see [Binding beyond loopback](#binding-beyond-loopback)). |
| `proxy.port` | integer 0–65535 | `1016` | Listen port (`0` = ephemeral). Override per-run with `--port`. |

## `responseProtection`

Inspects upstream JSON responses (off by default — turn on to protect what comes *back* from the model).

| Key | Type / values | Default | Notes |
|---|---|---|---|
| `responseProtection.enabled` | boolean | `false` | Master switch. Required for `detokenizeResponses` to do anything. |
| `responseProtection.mode` | `dry-run` \| `report-only` \| `enforce` | `enforce` | Enforcement mode for the response direction. |
| `responseProtection.failureMode` | `fail-closed` \| `allow` | `fail-closed` | What to do with an *uninspectable* response (non-JSON, invalid JSON, compressed). `fail-closed` returns 502; `allow` passes it through (audited). |
| `responseProtection.allowNonJson` | boolean | `false` | Permit non-JSON responses through without inspection. |
| `responseProtection.allowCompressed` | boolean | `false` | Permit compressed responses through without inspection. |
| `responseProtection.maxBytes` | positive integer | `1048576` | Hard response size cap. Enforced even under `failureMode: allow` — oversized responses are always denied. |

## `streaming`

| Key | Type / values | Default | Notes |
|---|---|---|---|
| `streaming.requestMode` | `block` \| `pass-through` \| `inspect` | `block` | `block` → `501` for streaming; `inspect` → stream-filter SSE/NDJSON responses (bounded cross-frame buffer); `pass-through` → forward uninspected (audited). Ollama `/api/chat` and `/api/generate` are treated as streaming unless `stream: false` is set. |
| `streaming.responseMode` | `dry-run` \| `report-only` \| `enforce` | `enforce` | Enforcement mode applied to inspected streams (independent of the request direction). |
| `streaming.maxMatchBytes` | positive integer | `256` | Cross-frame match window for `inspect`. A held tail of this size lets a detection spanning frames be caught before emission; a single match longer than this may still split across frames. |

## `limits`

| Key | Type / values | Default | Notes |
|---|---|---|---|
| `limits.maxRequestBytes` | positive integer | `1048576` | Request body cap; over the limit returns `413`. Enforced incrementally (the body is not fully buffered first). |
| `limits.upstreamTimeoutMs` | positive integer | `120000` | Upstream request timeout; on expiry returns `504 haechi_upstream_timeout`. Connection failure returns `502 haechi_upstream_unreachable`. |

## `policy`

The detect→decide core. See [Detection types & actions](#detection-types--actions).

| Key | Type / values | Default | Notes |
|---|---|---|---|
| `policy.mode` | `dry-run` \| `report-only` \| `enforce` | `dry-run` | Effective enforcement mode (`policy.mode ?? mode`). |
| `policy.presets` | array of preset names | `["korean-pii", "secrets-only", "llm-redact"]` | Bundled action sets, merged in order. See [Presets](#presets). |
| `policy.defaultAction` | an action | `redact` | Action for a detected type with no explicit mapping. |
| `policy.actions` | `{ <type>: <action> }` | `{ "card": "block" }` | Per-type overrides. Merges may **strengthen** but never weaken (see [Action strength](#action-strength)); `injection` defaults to `allow` unless set. |
| `policy.allowUnsafeOverrides` | boolean | `false` | Permit a weaker action to override a stronger one. Off by default; turning it on removes a safety guard. |
| `policy.bundlePath` | path | unset | Load a signed policy bundle instead of inline policy (verified against `keys.keyFile`). |

## `filters`

| Key | Type / values | Default | Notes |
|---|---|---|---|
| `filters.customRules` | array of rule objects | `[]` | Extra detection rules: `{ id, type, pattern, flags?, confidence? }`. Patterns are ReDoS-screened (≤500 chars, no nested quantifiers, no backreferences) and rejected at load if unsafe. |

## `keys`

| Key | Type / values | Default | Notes |
|---|---|---|---|
| `keys.provider` | `local` \| `external` | `local` | `local` uses a software AES-256-GCM key file (dev only). `external` ships no key material and **requires** injecting a crypto provider via `createRuntime(config, { cryptoProvider })`. |
| `keys.keyFile` | path | `.haechi/dev.keys.json` | Local key file (mode `0600`). `haechi init --force` rotates it, retiring prior keys so existing ciphertext/tokens stay decryptable by `kid`. |

## `audit`

| Key | Type / values | Default | Notes |
|---|---|---|---|
| `audit.sink` | `jsonl` | `jsonl` | Only `jsonl` is supported. |
| `audit.path` | path | `.haechi/audit.jsonl` | SHA-256 hash-chained log; verify with `haechi audit-verify`. Never contains plaintext/PII. |

## `tokenVault`

| Key | Type / values | Default | Notes |
|---|---|---|---|
| `tokenVault.provider` | `local` | `local` | Only `local` is supported. |
| `tokenVault.path` | path | `.haechi/token-vault.json` | Encrypted token store (atomic writes, file-locked). |
| `tokenVault.revealPolicy` | `disabled` \| `local-dev` | `disabled` | Gates **manual** reveal (`token-reveal`). Every reveal/purge decision is audited. Independent of detokenization. |
| `tokenVault.retentionDays` | positive number | `30` | Token TTL. Expired tokens are deleted on vault writes or via `token-purge --expired`. |
| `tokenVault.deterministic` | boolean | `false` | Equal `(type, value)` → equal token (HMAC over a domain-separated derived key). Needed for multi-turn. **Trade-off:** equal values become linkable. |
| `tokenVault.deterministicTypes` | `null` \| non-empty string array | `null` | `null` = all types when deterministic; otherwise limit determinism to listed types (e.g. `["email"]`). |
| `tokenVault.detokenizeResponses` | boolean | `false` | Restore request-issued tokens in that request's response. Only the tokens issued while protecting the same request are restored; requires `responseProtection.enabled`. Audited by count. |

## `privacy`

| Key | Type / values | Default | Notes |
|---|---|---|---|
| `privacy.profile` | `null` \| `kr-pipa` \| `eu-gdpr` \| `us-general` | `null` | Applies a regional baseline action set before enforcement. Profiles may **strengthen** but never weaken your explicit actions. Engineering defaults, not legal advice. |

## `mcp`

Applies to `mcp-stdio` and `mcp-wrap`.

| Key | Type / values | Default | Notes |
|---|---|---|---|
| `mcp.allowedMethods` | non-empty string array | `["initialize", "tools/call", "resources/read", "prompts/get"]` | Client-callable method allowlist (`"*"` allows all). Server-initiated requests bypass the allowlist but are still params-protected. |
| `mcp.protectParams` | boolean | `true` | Protect request `params`. |
| `mcp.protectResults` | boolean | `true` | Protect response `result` (and run injection heuristics on it). |
| `mcp.requireJsonRpc` | boolean | `true` | Require `jsonrpc: "2.0"`; non-conforming messages are rejected. |

## `auth`

| Key | Type / values | Default | Notes |
|---|---|---|---|
| `auth.provider` | `none` \| `bearer` \| `external` | `none` | `none` = no auth (identity null). `bearer` = built-in token auth. `external` requires injecting an `authProvider` via `createRuntime(config, { authProvider })`. |
| `auth.store` | path | `.haechi/auth.json` | Bearer token store (mode `0600`). Tokens are kept only as keyed-HMAC hashes; the plaintext is shown once by `haechi auth add`. |
| `auth.allowedLabelKeys` | string array | `["team", "env", "tier", "role"]` | Label keys a token may carry; values are length-limited and must not contain PII. |

## `policy` profiles & limits

Per-client controls layered on top of the base `policy`. See [Named profiles](#named-profiles).

| Key | Type / values | Default | Notes |
|---|---|---|---|
| `policy.profiles` | `{ <name>: { presets?, actions?, modelAllowlist?, rate? } }` | `{}` | Named profiles; each overrides the base policy. |
| `policy.profileBinding` | `{ byScope?, byLabel?, default }` | unset | Maps identity scopes/labels (`"k=v"` for labels) to profile names. `default` is **required** when `profiles` is set and should be the strictest profile (fail-closed). |
| `policy.modelAllowlist` | string array | unset | Allowed `model` values (base level; also settable per profile). A disallowed model → `403`. Empty/absent = allow all. |
| `policy.rate` | `{ requestsPerMinute }` | unset | Per-identity request rate limit (base level or per profile). Over the limit → `429`. In-memory, per-process. |

### Named profiles

When an identity authenticates, its profile resolves in order **scope → label → `default`**; scope precedes label and the first match wins. Without `profiles`, or under `auth.provider: none`, the base policy applies. The resolved profile's policy engine, `modelAllowlist`, and `rate` govern that request.

## Detection types & actions

Built-in detection `type` values: `email`, `phone`, `kr_rrn`, `card`, `api_key`, `secret`, and `injection` (response-direction heuristic, report-only by default). Custom rules may introduce new types.

Actions (weakest → strongest):

| Action | Effect |
|---|---|
| `allow` | No change (still detected and audited). |
| `redact` | Replace with `[REDACTED:<type>]`. |
| `mask` | Partially mask (values ≤8 chars are fully masked). |
| `tokenize` | Replace with a vault token; reversible via the token vault. |
| `encrypt` | Replace with an inline AES-256-GCM envelope. |
| `block` | Reject the whole payload (`403`/`-32001`/exit 3). |

### Action strength

When a preset and an override (or a privacy profile) disagree, the **stronger** action wins, and trying to weaken a stronger action throws unless `policy.allowUnsafeOverrides` is `true`. Strength: `allow`(0) < `redact`/`mask`(1) < `tokenize`/`encrypt`(2) < `block`(3).

### Presets

| Preset | Effect |
|---|---|
| `llm-redact` | default `redact`; `email: redact`, `phone: mask` |
| `korean-pii` | `kr_rrn: block`, `phone: mask`, `email: redact` |
| `secrets-only` | `api_key: block`, `secret: block` |
| `strict-block` | default `block` |
| `mcp-basic` | default `redact`; `api_key`/`secret`/`kr_rrn: block` |
| `local-inference` | default `redact`; `email: tokenize`, `phone: mask`, secrets/`kr_rrn: block` |
| `local-only` | marks transfer as non-external (metadata) |

## Common setups

**Protect requests in enforce mode (minimal):**
```json
{ "mode": "enforce", "policy": { "mode": "enforce" } }
```

**Local inference with response protection + token round-trip:**
```json
{
  "mode": "enforce",
  "target": { "type": "vllm-openai", "upstream": "http://127.0.0.1:8000" },
  "policy": { "mode": "enforce", "presets": ["local-inference"] },
  "responseProtection": { "enabled": true, "mode": "enforce" },
  "tokenVault": { "deterministic": true, "detokenizeResponses": true }
}
```

**EU profile, secrets blocked, injection flagged:**
```json
{
  "mode": "enforce",
  "privacy": { "profile": "eu-gdpr" },
  "policy": { "mode": "enforce", "actions": { "injection": "redact" } },
  "responseProtection": { "enabled": true }
}
```

## Binding beyond loopback

The proxy refuses non-loopback hosts unless the CLI flag is passed explicitly — `proxy.host: "0.0.0.0"` in config alone will not start, by design:

```bash
haechi proxy --config haechi.config.json --host 0.0.0.0 --allow-remote-bind
```

**The proxy has no client authentication yet** (planned for 0.6): anyone who can reach the port can use your upstream and the token round-trip path. Use `--allow-remote-bind` only behind explicit network controls — bind `0.0.0.0` inside a container and restrict the host port mapping (`-p 127.0.0.1:1016:1016`), or front it with a firewall/VPN/authenticating reverse proxy.

## Validation cheatsheet

These throw at load (fail-closed): unknown `keys.provider`; empty `proxy.host`; out-of-range `proxy.port`; non-`jsonl` `audit.sink`; non-`local` `tokenVault.provider`; bad `revealPolicy`; non-positive `retentionDays`; non-boolean `deterministic`/`detokenizeResponses`; empty/non-string `deterministicTypes`; empty/non-string `mcp.allowedMethods`; non-boolean `mcp.*` flags; unknown `privacy.profile`; bad `responseProtection.failureMode`; non-positive `responseProtection.maxBytes`; bad `streaming.requestMode`/`streaming.responseMode`; non-positive `streaming.maxMatchBytes`; bad `auth.provider`; empty `auth.store`; non-string `auth.allowedLabelKeys`; non-object `policy.profiles`; `policy.profileBinding` without a valid `default`; non-string `policy.modelAllowlist`; non-positive `policy.rate.requestsPerMinute`; non-positive `limits.*`; unknown `target.type`/`adapter`; unsafe custom regex; weakening action without `allowUnsafeOverrides`.
