# Haechi Configuration Reference

- Status: Living document (tracks core 1.3.x)

`haechi init` writes `haechi.config.json`; a non-secret template is at `haechi.config.example.json`. Every command reads it with `--config <path>` (default `haechi.config.json`). Configuration is **validated fail-closed**: unknown providers, out-of-range numbers, and malformed values throw at load time rather than degrading silently. `haechi config` prints this reference; `haechi status` prints the *effective* state of a given config.

## Full default

```json
{
  "configVersion": 1,
  "mode": "dry-run",
  "target": { "type": "llm-http", "adapter": "openai-compatible", "upstream": "http://127.0.0.1:9999" },
  "proxy": { "host": "127.0.0.1", "port": 11016, "tls": null, "trustForwardedProto": false },
  "responseProtection": { "enabled": false, "mode": "enforce", "failureMode": "fail-closed", "allowNonJson": false, "allowCompressed": false, "maxBytes": 1048576 },
  "streaming": { "requestMode": "block" },
  "limits": { "maxRequestBytes": 1048576, "upstreamTimeoutMs": 120000, "maxNestingDepth": 256, "maxInFlight": 0, "shutdownGraceMs": 10000, "requestTimeoutMs": null, "headersTimeoutMs": null },
  "policy": { "mode": "dry-run", "presets": ["korean-pii", "secrets-only", "llm-redact"], "defaultAction": "redact", "actions": { "card": "block" } },
  "filters": { "customRules": [] },
  "keys": { "provider": "local", "keyFile": ".haechi/dev.keys.json" },
  "audit": { "sink": "jsonl", "path": ".haechi/audit.jsonl" },
  "tokenVault": { "provider": "local", "path": ".haechi/token-vault.json", "revealPolicy": "disabled", "retentionDays": 30, "deterministic": false, "deterministicTypes": null, "detokenizeResponses": false },
  "privacy": { "profile": null },
  "logging": { "format": "text" },
  "metrics": { "enabled": true },
  "mcp": { "allowedMethods": ["initialize", "tools/call", "resources/read", "prompts/get"], "protectParams": true, "protectResults": true, "requireJsonRpc": true }
}
```

## Top level

| Key | Type / values | Default | Notes |
|---|---|---|---|
| `configVersion` | positive integer | `1` | Config schema version stamp. Absent = treated as the current version. A value **newer** than this build understands **fails closed** at load; a non-positive/non-integer value throws. See [`config-version.md`](./config-version.md). |
| `mode` | `dry-run` \| `report-only` \| `enforce` | `dry-run` | Global enforcement mode. `dry-run`/`report-only` detect + audit only; `enforce` transforms/blocks. Overridden by `policy.mode` when set. |

## `target`

| Key | Type / values | Default | Notes |
|---|---|---|---|
| `target.type` | `llm-http` \| `openai-compatible` \| `vllm-openai` \| `ollama` \| `llama-cpp` \| `anthropic` \| `gemini` | `llm-http` | Selects the protocol adapter. `llm-http` aliases `openai-compatible`. `anthropic` targets the Anthropic Messages API (`/v1/messages`, `/v1/messages/count_tokens`, `/v1/complete`); the client supplies Anthropic's `x-api-key`/`anthropic-version` headers and the proxy forwards them. `gemini` targets the Google Gemini API, whose endpoints are model-in-path with a `:method` suffix (`/v1beta/models/{model}:generateContent`, `:streamGenerateContent` (SSE), `:countTokens`, `:embedContent`, `:batchEmbedContents`; `/v1` or `/v1beta` prefix, arbitrary `{model}`); the client supplies Gemini's `x-goog-api-key` (or `?key=`) and the proxy forwards it. Unknown values **fail closed** at load. |
| `target.adapter` | same set | `openai-compatible` | Explicit adapter override; usually leave unset and let `type` decide. |
| `target.upstream` | URL string | `http://127.0.0.1:9999` | The only upstream the proxy forwards to. Request targets must be origin-form paths; absolute-URL targets are rejected (SSRF guard). |
| `target.forwardHeaders` | array of lowercase header names | unset (`[]`) | **Additive** extension of the built-in upstream header allowlist. The proxy forwards only an explicit allowlist to the upstream (provider/adapter headers: `x-api-key`, `anthropic-version`, `anthropic-beta`, `x-goog-api-key`, `openai-organization`, `openai-beta`, `accept`, `accept-language`, `user-agent`, and `content-type` rewritten to `application/json`); the client `Authorization` is forwarded only when `auth.provider: none` (it is the upstream provider key) and dropped otherwise (it is the gateway credential); `Cookie`/`Set-Cookie`/`Proxy-Authorization` and hop-by-hop headers are always dropped. List extra lowercase names here for an unusual upstream. **Fail-closed:** must be an array of lowercase non-empty strings and may NOT name an always-dropped credential/hop-by-hop header. |

## `proxy`

| Key | Type / values | Default | Notes |
|---|---|---|---|
| `proxy.host` | non-empty string | `127.0.0.1` | Bind address. Non-loopback hosts require the `--allow-remote-bind` CLI flag — config alone will not start (see [Binding beyond loopback](#binding-beyond-loopback)). |
| `proxy.port` | integer 0–65535 | `11016` | Listen port (`0` = ephemeral). Override per-run with `--port`. |
| `proxy.tls` | `null` or `{ keyFile, certFile }` / `{ pfxFile, passphrase? }` | `null` | TLS material loaded from **file paths** at startup into a TLS context. When present, Haechi terminates TLS itself (serves `https`). Required (or `trustForwardedProto`) for a remote bind — see [Binding beyond loopback](#binding-beyond-loopback). Fail-closed: a non-null value that does not resolve to usable material `((key && cert) or pfx)`, mixes `pfxFile` with `keyFile`/`certFile`, or names an unreadable file throws at load. |
| `proxy.trustForwardedProto` | boolean | `false` | Operator acknowledgement that a **trusted reverse proxy terminates TLS** in front of Haechi. When `true`, a remote bind may stay plain `http`, but Haechi then **refuses any request whose `X-Forwarded-Proto` is not `https`** (checked before auth/body; the `/__haechi/*` liveness routes are exempt). Never a substitute for real TLS when Haechi is itself internet-facing. |

## `responseProtection`

Inspects upstream JSON responses (off by default — turn on to protect what comes *back* from the model).

| Key | Type / values | Default | Notes |
|---|---|---|---|
| `responseProtection.enabled` | boolean | `false` | Master switch. Required for `detokenizeResponses` to do anything. |
| `responseProtection.mode` | `dry-run` \| `report-only` \| `enforce` | `enforce` | Enforcement mode for the response direction. **For real LLM upstreams, prefer `report-only`:** envelope metadata (ids, a unix-timestamp `created`, long numeric fields) can look PII/secret-shaped, and `enforce` would 502 a legitimate completion. `report-only` still detects, audits, and runs `detokenizeResponses`. (Haechi already skips its own `[TOKEN:…]`/`[HAECHI_ENC:…]` markers on the response, the phone rule ignores bare timestamps, and bare JSON number leaves aren't scanned on the response — so real vLLM/Ollama responses scan clean. `enforce` remains stricter if you also want the response *text* policed.) |
| `responseProtection.failureMode` | `fail-closed` \| `allow` | `fail-closed` | What to do with an *uninspectable* response (non-JSON, invalid JSON, compressed). `fail-closed` returns 502; `allow` passes it through (audited). |
| `responseProtection.allowNonJson` | boolean | `false` | Permit non-JSON responses through without inspection. |
| `responseProtection.allowCompressed` | boolean | `false` | Permit compressed responses through without inspection. |
| `responseProtection.maxBytes` | positive integer | `1048576` | Hard response size cap. Enforced even under `failureMode: allow` — oversized responses are always denied. |
| `responseProtection.scanNumbers` | boolean | `false` | Whether to run detection on **bare JSON number leaves** of the response. Off by default — response numbers are inference-server metadata (`*_duration`, counts, timestamps) and scanning them only false-positives (`card`/`kr_rrn`). Set `true` only for a strict threat model (a model assumed able to exfiltrate via a numeric field); pair with `mode: report-only` to audit without blocking on metadata. Request-direction always scans numbers regardless. |

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
| `limits.maxNestingDepth` | positive integer | `256` | Max JSON nesting depth walked during detection. A more deeply nested body is rejected `413 haechi_request_too_deeply_nested` (fail-closed, before upstream), guarding the recursive payload walk against a stack overflow. Bounds container descent; leaves at the limit are still inspected. (Separately, a non-UTF-8 request body is rejected fail-closed: `400 haechi_request_body_not_utf8`.) |
| `limits.maxInFlight` | non-negative integer | `0` | Global max-in-flight backpressure ceiling. `0` disables it (no ceiling — 1.1 behavior). When `> 0` and the live in-flight count is at the ceiling, a **new** request is rejected `503` with a `Retry-After` header and `{ "error": "haechi_overloaded" }`, **before** auth/body-read. The `/__haechi/*` observability routes are **exempt** (liveness + metrics stay scrapable under saturation). Each rejection increments `haechi_overloaded_total`. See the [operations runbook](./operations-runbook.md#5-backpressure-tuning). |
| `limits.shutdownGraceMs` | non-negative integer (ms) | `10000` | Graceful-shutdown grace period. On `SIGINT`/`SIGTERM` the proxy stops accepting connections, closes idle keep-alive sockets immediately, waits for in-flight requests to drain, then after this grace force-closes any lingering socket so a stuck keep-alive cannot hold shutdown open forever. Also seeds the backpressure `Retry-After` seconds. Set your orchestrator's termination grace **above** this value. |
| `limits.requestTimeoutMs` | `null` \| non-negative integer (ms) | `null` | Maps to the Node HTTP server `requestTimeout`. `null` leaves Node's default untouched (behavior unchanged). Set a number to cap slow whole-request delivery; `0` disables the timeout (Node semantics). |
| `limits.headersTimeoutMs` | `null` \| non-negative integer (ms) | `null` | Maps to the Node HTTP server `headersTimeout`. `null` leaves Node's default untouched. Set a number to cap slow header delivery (slow-loris); `0` disables it. |

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
| `filters.minConfidence` | number in `[0, 1]` | `0` | Precision dial. Each rule carries a `confidence` (0.6–0.95); a detection whose confidence is **below** this threshold is dropped before the policy decides. `0` (the default) gates nothing, preserving prior behavior. **Hard-block exemption:** a hard-block type (`secret`, `api_key`, `kr_rrn`, `card`, and the strong-anchored national IDs `fr_nir`, `es_dni`, `it_codice_fiscale`, `sg_nric`) is **never** dropped on confidence — `minConfidence` trims only the precision-risky soft/dial-eligible types (e.g. `phone`, `email`, `jp_mynumber`, `uk_nino`, `in_aadhaar`, `de_steuer_id`, `nl_bsn`, `injection`), so a low-confidence credential/PII leak is still acted on (fail-closed). |
| `filters.allowlist` | array of strings and/or `{ value?, path? }` | `[]` | Operator false-positive exceptions. A detection whose matched **value** equals a string/`value` entry, or whose PII-safe JSON **path** (the hashed `pathText`, as shown in the audit) equals a `path` entry, is suppressed before the policy decides (when an entry sets both `value` and `path`, **both** must match). **Hard-block exemption:** an entry that would suppress a hard-block type (`secret`/`api_key`/`kr_rrn`/`card`/`fr_nir`/`es_dni`/`it_codice_fiscale`/`sg_nric`) is **ignored** and the detection still fires — the allowlist can only clear a benign **soft / dial-eligible** FP (e.g. a `jp_mynumber`/`in_aadhaar` 12-digit-id FP, a `de_steuer_id` 11-digit-id FP, a `nl_bsn` 9-digit-id FP, or a format-only `uk_nino`), never silence a credential/strong-anchored-PII leak. Every suppression and every `minConfidence` drop is **audited** by count and type (`summary.suppressedByType` / `summary.droppedByType` / `suppressedCount` / `droppedCount`) — never the raw value. Use this to clear one benign FP without deleting a whole rule. |
| `filters.decodeAndRescan` | boolean | `false` | Opt-in base64/percent **decode-and-rescan** (the WS2d residual). With the default `false`, detection is byte-identical to before — a base64- or percent-encoded value is **not** decoded. When `true`, after the normal NFKC scan a string leaf that **looks** base64/base64url (anchored alphabet, valid length, `16…8192` bytes, round-trips to the same leaf, decodes to **valid UTF-8**) or contains a `%XX` escape (`decodeURIComponent`) is decoded and rescanned with the same rules + validators. A decoded hit has no offset in the encoded leaf, so it fails closed to a **whole-leaf** detection (`start:0,end:leaf.length`, value = the whole encoded leaf) — the transform redacts/blocks the entire leaf. **Precision guard:** a decoded hit fires **only** when it is validator-backed or a hard-block type (a Luhn-passing `card`, a checksum `kr_rrn`/`us_ssn`, an IBAN mod-97, or a `secret`/`api_key` on its anchored rule); a decoded soft-type-without-validator match (a bare phone-shaped run) does not fire, so random base64 does not false-positive. No new runtime dependency (`node:buffer` Buffer + the `decodeURIComponent` builtin). Other encodings (gzip/hex/nested/custom-alphabet) stay out of scope. |

### Detection benchmark

Detection precision/recall is measured, not assumed. A labeled corpus of synthetic test fixtures (`tests/fixtures/detection-corpus.json` — positive samples per type plus benign hard-negatives) drives a per-type scorer:

```bash
npm run bench:detection   # print the per-type TP/FP/FN + precision/recall table
npm run scan:detection    # CI regression gate: fail if any type regresses below baseline
```

`bench:detection` (`scripts/bench-detection.mjs`) runs the default filter engine over each corpus case and reports true/false positives and false negatives per type. `scan:detection` compares the live scores against the pinned baseline (`scripts/detection-baseline.json`) and **fails only on a regression** — a precision or recall drop below the recorded numbers. The baseline deliberately bakes in the current imperfect state (the audit-reproduced false positives on `phone`/`card`/`secret`, and the known coverage-gap misses for AWS/GitHub/Google/Slack keys, JWT, and PEM headers), so the gate passes today and trips only when a change makes detection worse. It runs in `release:preflight` after the doc-freshness gate. Regenerate the baseline after an intentional rule change with `node scripts/bench-detection.mjs --write-baseline` and review the diff. Closing the recorded gaps and false positives is WS2b/WS2c of the reliability-hardening track.

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
| `privacy.profile` | `null` \| `kr-pipa` \| `eu-gdpr` \| `asia-pdpa` \| `us-general` \| `jp-appi` | `null` | Applies a regional baseline action set before enforcement. Profiles may **strengthen** but never weaken your explicit actions. `eu-gdpr` blocks the EU national IDs (`fr_nir`/`es_dni`/`uk_nino`/`it_codice_fiscale`/`de_steuer_id`/`nl_bsn`); `asia-pdpa` (Singapore PDPA / India DPDP) blocks `sg_nric`/`in_aadhaar` (plus the other checksummed national IDs for mixed-region payloads); `jp-appi` blocks `jp_mynumber`; every profile blocks `jp_mynumber` (a checksummed national-ID leak). Engineering defaults, not legal advice. |

## `logging`

| Key | Type / values | Default | Notes |
|---|---|---|---|
| `logging.format` | `text` \| `json` | `text` | `text` keeps the human-readable startup/shutdown/error lines (unchanged). `json` emits one single-line JSON object per event. Fail-closed: any other value throws. |

In `json` mode the proxy's internal-error log is a single line `{ "level": "error", "event": "proxy_internal_error", "correlationId", "errorName", "statusCode" }`, and startup/shutdown emit `proxy_listening` / `proxy_shutdown` (plus `*_warn` events for remote-bind / non-enforce-mode / response-protection-disabled). **No log field ever carries a request/response payload, header, token, or any PII** — error logs carry the error *class name* and the request `correlationId` only.

## `metrics`

| Key | Type / values | Default | Notes |
|---|---|---|---|
| `metrics.enabled` | boolean | `true` | Gates the `GET /__haechi/metrics` route. When `false`, that route returns `404`. Fail-closed: a non-boolean throws. |

The metrics collector is also an **injectable collaborator** (`createRuntime(config, { metrics })`); see [Operability endpoints](#operability-endpoints) for the contract and the no-PII guarantee.

## Operability endpoints

The proxy serves four unauthenticated endpoints under the reserved `/__haechi/*` prefix, checked **before** auth and body-read. They never proxy upstream.

| Endpoint | Status | Body | Purpose |
|---|---|---|---|
| `GET /__haechi/live` | `200` | `{ ok: true, version }` | Cheap process liveness. |
| `GET /__haechi/ready` | `200` / `503` | `{ ready, version, checks }` | Readiness. **Fail-closed**: a gateway that cannot append to its audit log is **not** ready (`503`). The default JSONL sink's `checks.auditWritable` confirms its audit directory/file is writable without writing an event; a sink lacking a `ready()`/`healthCheck()` method is treated as ready. |
| `GET /__haechi/health` | `200` | `{ ok: true, mode, version }` | Back-compat (the original health endpoint, now with `version`). |
| `GET /__haechi/metrics` | `200` / `404` | Prometheus text | Telemetry (see below). `404` when `metrics.enabled: false`. |

`version` is the running package version (`package.json`).

### Telemetry (`/__haechi/metrics`)

The endpoint renders the **Prometheus text exposition format** (`# HELP` / `# TYPE` + `name{label="..."} value`), `Content-Type: text/plain`. Counters: `haechi_requests_total{route,mode,decision}` plus `haechi_blocks_total`, `haechi_auth_denied_total`, `haechi_rate_limited_total`, `haechi_upstream_timeout_total`, `haechi_upstream_error_total`, `haechi_response_unprotected_total`, `haechi_internal_error_total`; one histogram `haechi_request_duration_seconds{route}`.

**No-PII-in-telemetry invariant.** Every metric name and **every label value** is a bounded enum — a route id, a policy mode, or a fixed decision class (`forwarded` / `blocked` / `auth_denied` / `rate_limited` / `model_not_allowed` / …). A metric label is **never** an identity id/subject, a token, or a detected value: there is no per-identity or per-value label cardinality. This is the no-plaintext-in-audit invariant extended to telemetry; the metrics module additionally length-caps and charset-sanitizes label values as defence in depth.

### `providers.metrics` injection seam

The metrics collector is supplied programmatically through `createRuntime(config, providers)` — the same seam as `cryptoProvider`/`authProvider`/`rateLimiter`. It is **not** a JSON config key.

```js
const runtime = createRuntime(config, { metrics });
```

An injected `metrics` must implement `increment(name, labels?, amount?)`, `observe(name, value, labels?)`, and `render() -> string`; `createRuntime` fails closed at construction if it does not. The **default** is a zero-dependency in-memory collector that renders the Prometheus text above. A multi-replica operator injects a shared/remote collector satisfying the same contract.

### `correlationId` (audit + logs)

The proxy generates a per-**request** `correlationId` (a UUID). It is threaded into the protect context, so each request's request- and response-direction audit events carry the same additive top-level `correlationId` field, and into the proxy's internal-error log line — letting an operator join a logged error to its audit trail. It is `null` for non-proxy `protectJson()` calls (preserving prior behavior). The id is a UUID and is **never** a payload/identity/PII value.

## Env-var configuration overlay (deploy)

For container / 12-factor deploys, a **fixed allowlist of NON-SECRET operational keys** can be overridden from the environment. The env value **wins over the config file** and is validated **fail-closed** — an invalid value makes the process fail to start. Applied in `loadConfig()` after reading the file and before validation.

| Env var | Config key | Type / values |
|---|---|---|
| `HAECHI_PROXY_PORT` | `proxy.port` | integer 0–65535 |
| `HAECHI_PROXY_HOST` | `proxy.host` | non-empty string |
| `HAECHI_UPSTREAM` | `target.upstream` | URL string |
| `HAECHI_MODE` | `mode` | `dry-run` \| `report-only` \| `enforce` |
| `HAECHI_LOG_FORMAT` | `logging.format` | `text` \| `json` |

**Secrets are NOT overlayable — by design.** There is **no** `HAECHI_*` variable for `keys.*`, the auth token store, or any token/secret. Secrets stay in the config file or are supplied via injected providers (`createRuntime(config, { cryptoProvider, authProvider, … })`). Putting a secret in a process environment risks leaking it through `/proc`, crash dumps, and orchestrator inspect output, so the overlay allowlist excludes them. See the [operations runbook](./operations-runbook.md#2-configuration-via-the-env-var-overlay).

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
| `auth.provider` | `none` \| `bearer` \| `external` \| `plugin` | `none` | `none` = no auth (identity null). `bearer` = built-in token auth. `external` requires injecting an `authProvider` via `createRuntime(config, { authProvider })`. `plugin` = a signed `authProvider` sandbox (see [`auth.plugin`](#authplugin-signed-authprovider-sandbox)). |
| `auth.store` | path | `.haechi/auth.json` | Bearer token store (mode `0600`). Tokens are kept only as keyed-HMAC hashes; the plaintext is shown once by `haechi auth add`. |
| `auth.allowedLabelKeys` | string array | `["team", "env", "tier", "role"]` | Label keys a token may carry; values are length-limited and must not contain PII. |

### `auth.plugin` (signed authProvider sandbox)

Required when `auth.provider: "plugin"`. The sandbox loads a **signed** `authProvider` plugin under a capability-gated, audited runtime. The top-level `plugins.enabled` (default `true`) is a kill-switch — `false` refuses to construct any plugin. Dynamic loading is opt-in; the default is dependency injection. See `docs/current/release-1.0-implementation-scope.md` (worker) and `release-1.1-implementation-scope.md` (process).

| Key | Type / values | Default | Notes |
|---|---|---|---|
| `auth.plugin.manifestPath` | path | — | The signed plugin manifest (`haechi.plugin.json`). |
| `auth.plugin.trustAnchors` | `[{keyId, publicKey}]` or `{ keyId: publicKey }` | — | Operator-allowlisted Ed25519 **public** keys. Key resolution is trust-anchor-only. |
| `auth.plugin.allowCapabilities` | string array | — | Capability allowlist; must include `readsCredentials`. A requested capability not listed → load refused. |
| `auth.plugin.isolation` | `worker` \| `process` | `worker` | `worker` = `worker_threads` (memory/crash isolation, **1.0**). `process` = a child under the Node permission model with **kernel-enforced** capability denial (**1.1**); requires a Node that enforces `--allow-net`. |
| `auth.plugin.timeoutMs` | positive int | — | Per-call timeout; on timeout the runtime terminates the child/worker and denies. |
| `auth.plugin.resourceLimits` | `{ maxOldGenerationSizeMb }` | — | **`worker` only** — `worker_threads` heap bound. N/A for `process`. |
| `auth.plugin.netEnforcement` | `require-permission` | `require-permission` | **`process` only** — network-containment policy. `require-permission` **fails closed** (refuses to construct) on a Node without `--allow-net`. |
| `auth.plugin.keyMaterial` | `{ url (https), ttlMs?, cooldownMs? }` | unset | **`process` only** — optional operator-declared key document the **host** fetches (SSRF-guarded, TTL+cooldown) and injects to a custom-credential plugin. The plugin never names a URL. |
| `auth.plugin.pin` | `{ version?, entrySha256?, manifestSha256? }` | unset | Exact-match pin (anti malicious-update / rollback). |
| `auth.plugin.revoked` | `{ signerKeyIds?, entrySha256? }` | unset | Revocation denylists (fail-closed at load). |
| `auth.plugin.versionFloor` | `{ <pluginId>: version }` | unset | Per-plugin minimum version (anti-rollback). |
| `auth.plugin.maxPendingCalls` / `maxMessageBytes` | positive int | `8` / `16384` | Concurrency + wire bounds (excess/oversized → deny). |

## `policy` profiles & limits

Per-client controls layered on top of the base `policy`. See [Named profiles](#named-profiles).

| Key | Type / values | Default | Notes |
|---|---|---|---|
| `policy.profiles` | `{ <name>: { presets?, actions?, modelAllowlist?, rate? } }` | `{}` | Named profiles; each overrides the base policy. |
| `policy.profileBinding` | `{ byScope?, byLabel?, default }` | unset | Maps identity scopes/labels (`"k=v"` for labels) to profile names. `default` is **required** when `profiles` is set and should be the strictest profile (fail-closed). |
| `policy.modelAllowlist` | string array | unset | Allowed `model` values (base level; also settable per profile). A disallowed model → `403`. Empty/absent = allow all. |
| `policy.rate` | `{ requestsPerMinute }` | unset | Per-identity request rate limit (base level or per profile). Over the limit → `429`. In-memory, per-process; see [Rate limiter injection](#rate-limiter-injection) for the multi-replica seam. |

### Named profiles

When an identity authenticates, its profile resolves in order **scope → label → `default`**; scope precedes label and the first match wins. Without `profiles`, or under `auth.provider: none`, the base policy applies. The resolved profile's policy engine, `modelAllowlist`, and `rate` govern that request.

### Rate limiter injection

The rate limiter is an **injectable collaborator**, supplied programmatically through the `providers` argument of `createRuntime(config, providers)` — the same seam as the external `cryptoProvider`/`authProvider`. It is **not** a JSON config key.

```js
const runtime = createRuntime(config, { rateLimiter });
```

An injected `rateLimiter` must implement `allow(key, limit)` returning either a `boolean` **or** a `Promise<boolean>` (where `key` is the per-identity bucket and `limit` is the resolved `requestsPerMinute`); `createRuntime` fails closed at construction if it does not. The proxy `await`s the result, so a synchronous boolean and an async shared-store limiter behave identically — the built-in default stays synchronous, while a Redis-backed limiter that resolves asynchronously gates correctly. The proxy consults `runtime.rateLimiter` for every rate-governed request.

The **default** is a per-process, in-memory fixed-window counter: it resets on restart and is **not shared across replicas**, so total throughput multiplies by the replica count behind a load balancer. Its window map is self-bounding (a lazy, amortized sweep evicts aged-out one-shot identities — no background timer). For a multi-replica deployment, enforce a per-identity limit at a shared front door **or** inject a shared-store implementation (e.g. Redis-backed) that satisfies the same `allow(key, limit)` contract — the [`haechi-ratelimit-redis`](./shared-responsibility.md#4-horizontal-scale--multiple-replicas) satellite is the reference implementation. See [Shared responsibility §4](./shared-responsibility.md#4-horizontal-scale--multiple-replicas).

## Detection types & actions

Built-in detection `type` values: `email`, `phone`, `kr_rrn`, `card`, `api_key`, `secret`, `us_ssn`, `iban`, `jp_mynumber`, `fr_nir`, `es_dni`, `uk_nino`, `it_codice_fiscale`, `sg_nric`, `in_aadhaar`, `de_steuer_id`, `nl_bsn`, and `injection` (response-direction heuristic, report-only by default). Custom rules may introduce new types.

### Supported credential & PII matrix

Detection is regex + optional validator (no ML). Every rule is **anchored tightly** to keep precision high; precision is prioritized over recall, and the corpus (`tests/fixtures/detection-corpus.json`) carries a hard-negative for each rule. The KR phone rule and the US SSN/IBAN validators reject look-alike ids/timestamps.

| Type | Detects | Anchor / validator | Notes |
|---|---|---|---|
| `email` | RFC-style addresses | local + domain + TLD | — |
| `phone` | KR mobile (`01[016789]`, `+82`) | bare separator-less runs must be `0`-led | KR landlines out of scope. |
| `phone` | E.164 international | **leading `+` required** (`+[1-9]` + 6–14 digits) | A bare digit run is never matched (collides with ids/timestamps). |
| `phone` | US/NANP national | **separators required** (`(NXX) NXX-XXXX` or `NXX-NXX-XXXX`) | A separator-less 10-digit run is not matched. |
| `kr_rrn` | KR resident registration number | check-digit validator | Shape-valid but checksum-invalid → rejected. |
| `card` | Payment card (PAN) | Luhn validator, 13–19 digits | — |
| `us_ssn` | US Social Security Number | `AAA-GG-SSSS` + SSA-range validator (rejects area `000`/`666`/`900-999`, group `00`, serial `0000`) | Separators required; a bare 9-digit id is not an SSN. |
| `iban` | International Bank Account Number | **mod-97 checksum** validator | The checksum is the precision guard — IBAN-shaped non-97-valid strings are rejected. |
| `jp_mynumber` | Japan My Number (個人番号) | 12 digits + **mod-11 weighted check digit** | The check digit is the precision guard; a wrong-check 12-digit run is rejected. **Hard-block.** |
| `fr_nir` | France NIR / INSEE social-security | 15 chars + **`97 - (first13 mod 97)` control key** (Corsica `2A`→19, `2B`→18) | A wrong control key is rejected. **Hard-block.** |
| `es_dni` | Spain DNI / NIE | 8 digits (DNI) or `X/Y/Z`+7 digits (NIE) + **mod-23 check letter** (NIE `X/Y/Z`→`0/1/2`) | A wrong check letter is rejected. **Hard-block.** |
| `uk_nino` | UK National Insurance Number | `[A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z]\d{6}[A-D]` + documented invalid-prefix exclusions (`BG`/`GB`/`NK`/`KN`/`TN`/`NT`/`ZZ`, `O`-as-2nd-letter) | **Format-only — no checksum exists**, so it is NOT a hard-block type (dial-eligible: an operator can allowlist a benign FP). |
| `it_codice_fiscale` | Italy codice fiscale | `[A-Z]{6}\d{2}[A-Z]\d{2}[A-Z]\d{3}[A-Z]` + **mod-26 check character** (odd/even position tables over the first 15 chars) | A wrong check character is rejected. **Hard-block** — a rare 16-char mixed alpha+digit shape with a non-numeric structural anchor (measured ~3.8% collision over the shape). |
| `sg_nric` | Singapore NRIC / FIN | `[STFGM]\d{7}[A-Z]` + **weighted-sum check letter** (weights 2,7,6,5,4,3,2; per-prefix offset; per-series letter table) | A wrong check letter is rejected. **Hard-block** — two non-numeric anchors (prefix letter + check letter) over a rare shape (measured ~3.9% collision). |
| `in_aadhaar` | India Aadhaar | 12 digits (never starting `0`/`1`) + **Verhoeff checksum** | A wrong Verhoeff check digit is rejected. **NOT a hard-block type (dial-eligible)** — Verhoeff over the common 12-digit shape passes ~1/10 of random runs (measured ~9.9%, the `jp_mynumber` footgun), so an operator can allowlist a benign 12-digit-id FP. |
| `de_steuer_id` | Germany tax ID (Steuer-ID) | 11 digits + **ISO 7064 MOD 11,10** check digit + an "exactly one repeated digit in the first 10" structural test | A wrong check digit or wrong repeat structure is rejected. **NOT a hard-block type (dial-eligible)** — a bare 11-digit run with no non-numeric anchor over a common length (measured ~0.37% collision, but the bare-digit shape keeps it allowlist-clearable per the `jp_mynumber` discipline). |
| `nl_bsn` | Netherlands BSN | 9 digits + the **"11-proef"** weighted mod-11 | A run that fails the 11-proef is rejected. **NOT a hard-block type (dial-eligible)** — 9 bare digits is very common and the 11-proef passes ~1/11 of random runs (measured ~9.1%), the clearest dial-eligible case. |
| `api_key` | OpenAI-style / Stripe (`sk_`/`rk_`/`pk_`) | prefix + ≥24 chars | Underscore form — covers Stripe `sk_live_`/`rk_live_`/`sk_test_`/`rk_test_`. |
| `api_key` | AWS access key id | `AKIA`/`ASIA` + exactly 16 uppercase-alnum | — |
| `api_key` | Google API key | `AIza` + 35 URL-safe chars | — |
| `api_key` | SendGrid API key | `SG.` + 22 URL-safe + `.` + 43 URL-safe | The two fixed-length dotted segments are the anchor. |
| `api_key` | Twilio Account/API SID | `AC`/`SK` + exactly 32 **hex** | Hex-only body rejects random base62; the bare 32-hex AUTH TOKEN is caught via the assignment form (`auth_token`). |
| `secret` | OpenAI API key | `sk-` (and `sk-proj-`) + ≥20 base62-ish chars | **Hyphen** form, distinct from the underscore Stripe `sk_`; the two prefixes never overlap. |
| `secret` | Anthropic API key | `sk-ant-` + ≥16 chars | Stricter sibling of the OpenAI `sk-` rule (runs first for attribution). |
| `secret` | Google OAuth client secret | `GOCSPX-` + exactly 28 URL-safe chars | Distinct from the `AIza` API key. |
| `secret` | npm token | `npm_` + exactly 36 base62 chars | — |
| `secret` | `Bearer <token>` | `Bearer` + ≥16 chars | — |
| `secret` | Assignment `<key> = <value>` | key vocabulary: `api_key`, `api_secret`, `secret`, `secret_key`, `aws_secret_access_key`, `client_secret`, `private_key`, `access_token`, `refresh_token`, `auth_token`, `accountkey`, `token`, `password` | Catches bare-base64 secrets (AWS secret access key, **Azure Storage `AccountKey=`**, **Twilio auth token**) via the assignment form — an un-anchored 88-char-base64 Azure rule would false-fire on any blob, so `AccountKey=` context is the anchor. |
| `secret` | GitHub token | `gh[pousr]_` + ≥36 base64-ish chars | pat/oauth/user/server/refresh variants. |
| `secret` | Slack token | `xox[baprs]-` + ≥10-char body | bot/user/refresh/legacy variants. |
| `secret` | JWT | three base64url segments, first starts `eyJ` (the base64 of `{"`) | The `eyJ` anchor rejects arbitrary dotted tokens. |
| `secret` | PEM private key | `-----BEGIN … PRIVATE KEY-----` armor header | The header presence is the signal; prose mentioning "private key" is not matched. |
| `injection` | prompt-injection heuristics | response-direction only, `allow` by default | See [Action strength](#action-strength); report-only. |

Detection covers string values, JSON number leaves (request direction), and object keys. Each **string leaf is NFKC-normalized before matching**, so Unicode-evasion forms (full-width digits `４２４２…`, full-width `＠`, mathematical/enclosed alphanumerics) are folded to their ASCII compatibility form and still detected. When the fold preserves UTF-16 length the exact evaded span is redacted/blocked; when it changes length (e.g. mathematical digits, ligatures) detection fails closed and the whole leaf is redacted/blocked. Base64/percent-encoded values (after decoding) and URL query strings remain documented exclusions (see `docs/current/threat-model.md`). On the response direction, Haechi's own transform markers and bare JSON number leaves are skipped (request direction is always full-scan).

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

The proxy refuses non-loopback hosts unless the CLI flag is passed explicitly — `proxy.host: "0.0.0.0"` in config alone will not start, by design. A remote bind **additionally requires TLS**: either Haechi terminates TLS itself (`proxy.tls`), or you explicitly acknowledge a fronting TLS terminator (`proxy.trustForwardedProto`). A remote bind with neither **throws at startup** — Haechi will not serve bearer tokens and payloads in plaintext on a non-loopback listener.

**Option A — Haechi terminates TLS** (serves `https`):

```jsonc
// haechi.config.json
"proxy": { "host": "0.0.0.0", "tls": { "keyFile": "/etc/haechi/tls/key.pem", "certFile": "/etc/haechi/tls/cert.pem" } }
// or PKCS#12: "tls": { "pfxFile": "/etc/haechi/tls/server.pfx", "passphrase": "…" }
```
```bash
haechi proxy --config haechi.config.json --host 0.0.0.0 --allow-remote-bind
# → Haechi proxy listening on https://0.0.0.0:11016
```

**Option B — a trusted reverse proxy terminates TLS** in front of Haechi (Haechi stays plain `http` on a private network behind the hop):

```jsonc
"proxy": { "host": "0.0.0.0", "trustForwardedProto": true }
```
With `trustForwardedProto: true`, Haechi **refuses any request whose `X-Forwarded-Proto` is not `https`** (a plaintext request that bypassed the hop) with a fail-closed `403`, checked before auth and body-read. The `/__haechi/*` liveness/metrics routes are exempt so a loopback sidecar can still scrape them. Only the trusted terminator may set `X-Forwarded-Proto` — do not enable this if untrusted clients can reach the Haechi port directly.

**The proxy ships bearer client authentication** (`auth.provider: bearer`, shipped in 0.6): a hashed token store, per-identity policy profiles, a model allowlist, and a per-identity rate limit (see [`auth`](#auth) and [Named profiles](#named-profiles)). The default `auth.provider: none` leaves the proxy unauthenticated — with `none`, anyone who can reach the port can use your upstream and the token round-trip path. The built-in rate limit is single-process (in-memory, per-process); front multiple replicas with a shared limiter. Use `--allow-remote-bind` only behind explicit network controls regardless — bind `0.0.0.0` inside a container and restrict the host port mapping (`-p 127.0.0.1:11016:11016`), or front it with a firewall/VPN/authenticating reverse proxy.

## Validation cheatsheet

These throw at load (fail-closed): unknown `keys.provider`; empty `proxy.host`; out-of-range `proxy.port`; non-boolean `proxy.trustForwardedProto`; a `proxy.tls` that is non-`null` but not an object, sets `keyFile` without `certFile` (or vice-versa), mixes `pfxFile` with `keyFile`/`certFile`, names an unreadable file, or does not resolve to usable material `((key && cert) or pfx)`; non-`jsonl` `audit.sink`; non-`local` `tokenVault.provider`; bad `revealPolicy`; non-positive `retentionDays`; non-boolean `deterministic`/`detokenizeResponses`; empty/non-string `deterministicTypes`; empty/non-string `mcp.allowedMethods`; non-boolean `mcp.*` flags; unknown `privacy.profile`; bad `responseProtection.failureMode`; non-positive `responseProtection.maxBytes`; non-boolean `responseProtection.scanNumbers`; bad `streaming.requestMode`/`streaming.responseMode`; non-positive `streaming.maxMatchBytes`; bad `auth.provider`; empty `auth.store`; non-string `auth.allowedLabelKeys`; non-object `policy.profiles`; `policy.profileBinding` without a valid `default`; non-string `policy.modelAllowlist`; non-positive `policy.rate.requestsPerMinute`; non-positive `limits.maxRequestBytes`/`limits.upstreamTimeoutMs`/`limits.maxNestingDepth`; negative or non-integer `limits.maxInFlight`/`limits.shutdownGraceMs`; non-`null`/negative/non-integer `limits.requestTimeoutMs`/`limits.headersTimeoutMs`; non-positive-integer or **newer-than-supported** `configVersion`; unknown `target.type`/`adapter`; a `target.forwardHeaders` that is not an array of lowercase non-empty strings or that names an always-dropped credential/hop-by-hop header; unsafe custom regex; weakening action without `allowUnsafeOverrides`; non-`text`/`json` `logging.format`; non-boolean `metrics.enabled`; an invalid `HAECHI_*` env overlay value (bad `HAECHI_PROXY_PORT`, unknown `HAECHI_MODE`, malformed `HAECHI_UPSTREAM`, …).

# Satellite operator configuration (0.9)

The two sections below document the **independently published satellite packages** introduced in 0.9 — `haechi-dashboard` and `haechi-auth-oidc`. **These are not keys of the core `haechi.config.json` / `normalizeConfig` schema.** Each satellite is configured by passing an **options object** to its factory function (`createDashboardServer(options)` / `createOidcSessionBroker(options)`), validated by its own `normalizeDashboardConfig` / `normalizeOidcConfig`. Validation is the same **strict, fail-closed** discipline as core: an unknown option key throws, and every field below lists its fail-closed throw condition. Source: `satellites/dashboard/index.mjs`, `satellites/auth-oidc/index.mjs`. Threat-model coverage: **P1-OPS-005** (dashboard audit exposure / DNS-rebinding / remote bind) and **P1-SEC-009** (broker session/login security), per `docs/current/release-0.9-implementation-scope.md` §6.

## `haechi-dashboard` (satellite)

A zero-dependency, **read-only** audit viewer (`node:http`) that serves the audit JSONL and its hash-chain status. It takes **paths**, not a runtime. Configured via `createDashboardServer(options)`; `normalizeDashboardConfig(options)` validates and returns the effective config. Source: `satellites/dashboard/index.mjs`.

| Option | Type / values | Default | Notes / fail-closed throw |
|---|---|---|---|
| `auditPath` | non-empty string | **required** | Path to the audit JSONL. Throws if missing or not a non-empty string. |
| `anchorPath` | string \| `null` | `null` | Anchor stream path passed to `verifyAuditChain` for tail-truncation detection. Throws if present but not a non-empty string. |
| `host` | non-empty string | `127.0.0.1` | Bind address. Non-loopback requires `allowRemoteBind` **and** the remote-bind preconditions below. Throws if present but empty/non-string. |
| `port` | integer 0–65535 | `1018` | Listen port; `0` = OS-assigned ephemeral (intentional affordance). Throws if not an integer in `[0,65535]`. |
| `allowRemoteBind` | boolean | `false` | Permit a non-loopback `host`. Throws if non-boolean. Config alone is not enough — see remote-bind preconditions. |
| `sessionGuard` | object \| `null` | `null` | A guard implementing `authenticate(req) -> session\|null` and an optional `handlers` map. Throws if non-object or `authenticate` is not a function. `handlers` keys may **only** be the fixed broker paths `/auth/login`, `/auth/callback`, `/auth/logout` — any other key (notably `/api/*`, `/healthz`, `/`) throws, closing the auth-bypass where a guard exempts an audit route from the gate. Satisfied by injecting a `haechi-auth-oidc` broker (see below). |
| `window` | integer 4096–67108864 | `1048576` | Tail-read window (max bytes) for `/api/events` and `/api/summary`. Throws if not an integer in `[4096, 67108864]` (4 KiB–64 MiB). |
| `tlsContext` | object \| `null` | `null` | TLS material for the dashboard to terminate HTTPS itself. Throws if non-object, or if non-null but lacking **usable material** — it must carry `(key && cert)` or `pfx` (an empty `{}` is rejected so it can't green-light a non-loopback plaintext listener). |
| `trustProxy` | string \| `null` | `null` | Names a trusted fronting-proxy address/CIDR. Throws if non-string, empty, or a falsy-looking string (`"false"`/`"0"`). **`trustProxy` alone never authorizes a non-loopback bind** — only a real `tlsContext` does. |

### Routes

All routes are **GET/HEAD only** (any other method → `405`); the asset map is fixed in-code (no filesystem traversal):

- `/api/events` — bounded tail read of the audit JSONL, newest-first. `limit` is an integer in `[1,200]` (default 50); `cursor` is the opaque `auditIntegrity.sequence` (never a filesystem offset). Each event is rebuilt by a **recursive key-by-key allowlist projection** (no blind spread; identity carries only `subjectHash`/`issuerHash`, never scopes/labels/raw subject). Returns `windowExceeded` when a requested page predates the retained window.
- `/api/chain` — wraps `verifyAuditChain`; surfaces a derived `truncationDetected` boolean (the raw failure reason is **never** returned). mtime+size cached (no concurrent re-walk); over the 32 MiB cap returns `413` with `{valid:null}`; `HEAD` returns headers only without forcing a walk.
- `/api/summary` — aggregated detection counts (`byType`/`byAction`/`detectionCount`) over the tail window.
- `/healthz` — liveness only (`{status:"ok"}`); no session required even off-loopback.

### Security defaults

- **Loopback bind by default.** `host` defaults to `127.0.0.1`; binding a non-loopback host reuses core's `assertSafeProxyBind` (re-worded) and requires `allowRemoteBind`.
- **Remote bind is fail-closed.** A non-loopback bind requires **all** of: `allowRemoteBind: true`, a `sessionGuard`, **and** a valid `tlsContext` (the dashboard terminates TLS itself). `trustProxy` does not satisfy this — a non-loopback plaintext listener would serve audit data in cleartext while emitting HSTS, so it is refused. HSTS is emitted **only** when the server actually serves HTTPS.
- **Anti-DNS-rebinding Host allowlist** is the unconditional first gate on every request (including `/api/*`, `/healthz`, and any method); a bad/duplicate `Host` header → `403` before the method check.
- **Strict CSP + Trusted Types** (`require-trusted-types-for 'script'`, `textContent` rendering) plus `X-Frame-Options: DENY`, `Cross-Origin-Resource-Policy`/`-Opener-Policy: same-origin`, `X-Content-Type-Options: nosniff`, and `Cache-Control: no-store`; CORS headers are intentionally never set.
- **sessionGuard seam.** When a guard is present, every `/api/*` route is gated behind `authenticate()`; an unauthenticated request gets `401` (never a `302` redirect). The auth-exempt set is the **intersection** of the fixed broker-path allowlist and the guard's declared handlers (exact match) — a guard can never exempt an audit-data route.
- **Generic errors.** A 5xx returns `{error:"internal"}` only — never a stack, OS code, or filesystem path. A satellite-local fixed-window rate limiter (120 req/60s per source) fronts `/api/*`.

The bin `haechi-dashboard` (workspace) launches the server; the publish workflow is `.github/workflows/dashboard-publish.yml` (tag `dashboard-v<semver>`). `peerDependencies: { haechi: ">=0.8.0 <1.0.0" }`.

## `haechi-auth-oidc` (satellite)

A zero-dependency **interactive OIDC session broker** (authorization-code + PKCE) — the dashboard's human-login mechanism. It produces an opaque server-side session and **satisfies the dashboard `sessionGuard` contract by injection** (`{ authenticate(req), handlers: { "/auth/login", "/auth/callback", "/auth/logout" } }`). It is **not** a per-request bearer validator (that role stays with `haechi-auth-jwt`). Configured via `createOidcSessionBroker(options)`; `normalizeOidcConfig(options)` validates. Source: `satellites/auth-oidc/index.mjs`. `peerDependencies: { haechi: ">=0.8.0 <1.0.0", haechi-auth-jwt: ">=0.2.0 <1.0.0" }`.

| Option | Type / values | Default | Notes / fail-closed throw |
|---|---|---|---|
| `cryptoProvider` | object with `hmac()` | **required** | Supplies the keyed-HMAC for PII-safe identity hashes and `sessionIdHash`. Throws if `hmac` is not a function. |
| `issuer` | HTTPS URL string | **required** | OIDC issuer; pinned for exact string-equal discovery and single-origin endpoint checks. Throws if missing or not `https`. |
| `clientId` | non-empty string | **required** | OAuth client id (also the expected ID-token `aud`). Throws if missing/empty. |
| `clientSecret` | string \| omitted | omitted | Present ⇒ confidential client; omitted ⇒ public (PKCE-only) client. Throws if present but empty. |
| `redirectUri` | absolute URL string | **required** | Must be `https` (or **loopback** `http` under the carve-out), **same-origin** with the broker, and path exactly `/auth/callback`. Throws otherwise. |
| `scopes` | string array | `["openid"]` | `openid` is force-included (deduped); `offline_access` is stripped (refresh rotation is out of scope for 0.9). Throws if not an array of non-empty strings. |
| `returnToAllowlist` | string array | `["/"]` | Allowlist of **relative same-origin** return paths (must start with a single `/`, no scheme/host/`//`/backslash). Throws on a non-array or any non-conforming entry. |
| `sessionTtlSeconds` | integer 1–2592000 | `28800` (8h) | Absolute session lifetime. Throws if out of `[1, 2592000]` (30d ceiling). |
| `idleTtlSeconds` | integer 1–2592000 | `1800` (30m) | Idle timeout (sliding `lastSeen`). Throws if out of range. |
| `maxAgeSeconds` | integer 1–2592000 \| `null` | `null` | If set, sends OIDC `max_age` and requires `auth_time` within `maxAge + skew`. Throws if present but out of range. |
| `tokenEndpointAuthMethod` | `client_secret_basic` \| `client_secret_post` | `client_secret_basic` | Token-endpoint auth method. Throws on an unknown value, **or** if set without a `clientSecret` (only valid for a confidential client). |
| `secureCookies` | `true` \| `false` \| `"auto"` | `"auto"` | Forces or auto-derives the cookie `Secure`/`__Host-` hardening from the externally-visible scheme. Throws on any other value. |
| `trustProxy` | string \| `null` | `null` | Names a TLS-terminating fronting proxy; treats the browser-facing scheme as HTTPS (folds into cookie hardening). Throws if non-string or empty. |
| `algorithms` | non-empty string array | `["RS256","ES256"]` | Allowed JWS algorithms (passed to the verifier). Throws if not a non-empty array. |
| `clockSkewSeconds` | number 0–300 | (verifier default) | Leeway for ID-token time claims. Throws if out of `[0,300]`. |
| `prompt` | string \| `null` | `null` | Optional OIDC `prompt`. Throws if present but empty/non-string. |
| `pendingTtlSeconds` | integer 1–3600 | `600` (10m) | Time to complete a login (pre-auth record TTL). Throws if out of `[1,3600]`. |
| `pendingCap` | integer 1–1000000 | `1024` | Hard cap on concurrent in-flight logins; a full store rejects **new** logins and never evicts an in-flight auth (fail-closed). Throws if out of range. |
| `rateLimitMax` | integer 1–1000000 | `60` | `/auth/login`+`/auth/callback` per source per 60s window. Throws if out of range. |
| `fetchTimeoutMs` | integer 1–120000 | `5000` | Per-egress timeout (discovery / token / JWKS). Throws if out of range. |
| `fetchImpl` / `lookupImpl` / `now` | function | injected/global | Injectable `fetch` / DNS `lookup` / clock seams. Throws if present but not a function. |
| `sessionStore` | object | in-memory | Opaque-id → session store; must implement `get`/`set`/`delete`. Throws if present but non-conforming. |
| `pendingStore` | object | in-memory | Pre-auth record store; must implement `set`/`take` (atomic single-use `take`). Throws if present but non-conforming. |
| `auditSink` | function \| object with `record()` | none | PII-safe event sink. Throws if present but neither a function nor an object with `record()`. |

### Cookie hardening semantics

Sessions are **server-side only** — the cookie carries only an opaque id, never claims or tokens. Two cookies are used (a pre-auth cookie binding the pending record, and the session cookie). When the externally-visible scheme is HTTPS (an `https` `redirectUri`, `secureCookies: true`, or a non-null `trustProxy`), cookies use the **`__Host-` prefix + `Secure` + `HttpOnly` + `SameSite=Lax`** (`Path=/`, no `Domain`); `SameSite=Lax` lets the IdP top-level GET to `/auth/callback` carry the cookie. Under the documented **loopback-`http` carve-out** the `__Host-`/`Secure` attributes are dropped (a plaintext listener cannot set `Secure`), using the bare cookie names. An **off-loopback broker without confirmed HTTPS fails closed at construction** — a `Secure`/`__Host-` cookie is never sent over plaintext, so login would silently break. At `/auth/callback` a **fresh** session id is minted (no fixation); `/auth/logout` is non-GET, CSRF-header gated (`x-haechi-csrf`), and destroys server-side state. The access token is discarded (never stored). Audit events (`oidc.login.start`/`success`/`failure{reasonCode}`/`logout`/`session.evict`) carry only keyed-HMAC `subjectHash`/`issuerHash`/`sessionIdHash` + `provider` + a coarse `reasonCode` + timestamp.

### Wiring into the dashboard

Inject the broker as the dashboard's `sessionGuard`:

```js
import { createDashboardServer } from "haechi-dashboard";
import { createOidcSessionBroker } from "haechi-auth-oidc";

const broker = createOidcSessionBroker({
  cryptoProvider,
  issuer: "https://idp.example.com",
  clientId: "haechi-dashboard",
  clientSecret: "…",
  redirectUri: "https://dash.example.com/auth/callback",
  returnToAllowlist: ["/"]
});

const dashboard = createDashboardServer({
  auditPath: ".haechi/audit.jsonl",
  host: "0.0.0.0",
  allowRemoteBind: true,
  tlsContext: { key, cert },   // remote bind: dashboard terminates TLS itself
  sessionGuard: broker         // gates /api/* behind authenticate(); mounts /auth/* handlers
});
```

The broker's `handlers` map mounts only at the fixed broker paths the dashboard exempts from its auth gate; every `/api/*` route is gated behind `broker.authenticate(req)`. Publish workflow: `.github/workflows/auth-oidc-publish.yml` (tag `auth-oidc-v<semver>`).
