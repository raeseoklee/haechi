# Haechi

<p align="center">
  <img src="https://raw.githubusercontent.com/raeseoklee/haechi/main/docs/assets/haechi.jpg" alt="Haechi — a guardian haechi warding a gateway with a digital shield" width="820">
</p>

[![npm](https://img.shields.io/npm/v/haechi)](https://www.npmjs.com/package/haechi)
[![CI](https://github.com/raeseoklee/haechi/actions/workflows/ci.yml/badge.svg)](https://github.com/raeseoklee/haechi/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![node](https://img.shields.io/node/v/haechi)](https://nodejs.org)
[![status](https://img.shields.io/badge/status-stable%201.3-brightgreen)](docs/current/api-stability.md)

**English** | [한국어](README.ko.md)

Haechi is a self-hosted AI context enforcement layer for protecting LLM, MCP, vLLM, Ollama, and agent payloads before they reach models, tools, logs, or proxies.

The name comes from Haechi, a Korean guardian figure associated with discernment and protection.

**What it is:** a local, self-hosted **gateway and library you run yourself**. It inspects OpenAI-compatible / MCP / vLLM / Ollama / agent JSON and redacts, masks, tokenizes, encrypts, or blocks PII and secrets before they reach models, tools, or logs.

**What it is *not*:** a turnkey **production appliance**, a managed/hosted service, or a compliance guarantee. Core ships no production KMS/HSM, no built-in TLS, and no internet-facing hardening — **you** bring the network controls, authentication, key custody, and a TLS-terminating reverse proxy. See [Known limitations](#known-limitations) before deploying.

This repository is intended for local development, security design review, and self-hosted integration. It is not a compliance guarantee.

**1.0.0 is the first stable release.** From 1.0 the public API is a frozen contract under strict semver: the `package.json` `exports` surface, the CLI's machine-readable behavior, the audit event schema, and the config key shape are all part of the major-versioned contract, with a documented deprecation policy and a one in-minor security exception. See [`docs/current/api-stability.md`](docs/current/api-stability.md). The `haechi-*` satellites stay pre-1.0 and version independently of core (see [Satellite packages](#satellite-packages)).

The current scope focuses on local adoption:

- `haechi init`: create a local key, sample config, and audit path
- `haechi protect`: inspect and protect an OpenAI-compatible JSON payload
- `haechi report`: summarize audit events without raw payloads
- `haechi proxy`: run a local HTTP JSON proxy for existing LLM calls
- `haechi status`: show what is and is not protected under the current config
- `haechi audit-verify`: verify the audit hash chain and print its head hash
- `haechi mcp-wrap -- <command>`: wrap an MCP server with bidirectional stdio protection
- `haechi plugin-keygen` / `plugin-sign` / `plugin-verify`: author and verify a signed `authProvider` plugin (Ed25519 trust gate)

## Demo

<p align="center">
  <img src="https://raw.githubusercontent.com/raeseoklee/haechi/main/docs/assets/haechi-demo.gif" alt="Haechi live end-to-end demo against a real model: detection then tokenize/mask/redact, the masked phone the model can only repeat, a no-plaintext audit, live readiness + Prometheus metrics, and a blocked card" width="900">
</p>

The recording above is a **live** end-to-end run against a real self-hosted model (Qwen3.6-35B on vLLM) in `enforce` mode. The model is asked to repeat the phone number it was given — and it can only return the **masked** form, because the real number never reached it. It also shows the no-plaintext audit, the live `/__haechi/ready` + `/__haechi/metrics` surface, and a card blocked fail-closed before any upstream call.

Run it yourself — a no-backend, reproducible version with a stub upstream:

```bash
npm run demo
```

…or against your own OpenAI-compatible server:

```bash
HAECHI_LIVE_UPSTREAM=http://127.0.0.1:8000 node examples/local-proxy-demo/live-demo.mjs
```

See [`examples/local-proxy-demo/`](examples/local-proxy-demo/).

## Install

### npm

```bash
npm install -g haechi      # or: npx haechi init  (run without installing)
haechi init
```

Verify the published package's supply chain (every release after `0.3.2` is attested):

```bash
npm audit signatures       # npm SLSA provenance attestation
```

### Docker (GHCR)

Each release publishes a **cosign-signed** image to `ghcr.io/raeseoklee/haechi` (tags `1.3.3`, `1.3`, `1`, `latest`). Verify it, then run **behind a TLS-terminating reverse proxy** (the image binds `0.0.0.0` with `proxy.trustForwardedProto: true`):

```bash
cosign verify ghcr.io/raeseoklee/haechi:1.3.3 \
  --certificate-identity-regexp '^https://github.com/raeseoklee/haechi/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
docker run --rm -p 127.0.0.1:11016:11016 ghcr.io/raeseoklee/haechi:1.3.3
```

See [`docs/current/operations-runbook.md`](docs/current/operations-runbook.md) for the hardened compose stack and day-2 operations.

## Quickstart

From a clone of this repository:

```bash
npm test
npm run demo:init
npm run demo:protect
npm run demo:report
```

The default config runs in `dry-run` mode. It detects sensitive values and writes audit metadata, but it does not modify outbound payloads until policy mode is changed.

`npm run demo:init` writes `haechi.config.json` and `.haechi/dev.keys.json` locally. The generated key file is for local development only. Core ships no production KMS/HSM/Vault key provider; KMS- and Vault-backed key custody is available through the `haechi-crypto-kms` satellite, injected via the external `cryptoProvider` contract. A non-secret template is available at `haechi.config.example.json`.

## Local Proxy

```bash
node packages/cli/bin/haechi.mjs proxy --config haechi.config.json
```

Point an existing HTTP JSON client at `http://localhost:11016` and set `target.upstream` in `haechi.config.json`. Change `proxy.port` in the config or pass `--port` to use a different local port.

The proxy binds to loopback by default. Binding to `0.0.0.0`, `::`, or another non-loopback host fails unless `--allow-remote-bind` is provided. Use that flag only behind explicit network access controls.

Streaming requests with `stream: true` are blocked by default. Set `streaming.requestMode` to `inspect` to stream-filter SSE/NDJSON responses (a bounded sliding buffer over the JSON **delta channel** catches PII split across delta frames, up to `streaming.maxMatchBytes`; non-delta leaves and non-JSON frames are inspected within each frame), or to `pass-through` only when the caller explicitly accepts unprotected streaming.

Ollama `/api/chat` and `/api/generate` stream by default when the `stream` field is omitted, so the proxy treats those requests as streaming unless `stream: false` is explicitly set.

Upstream requests time out after `limits.upstreamTimeoutMs` (default 120000) and fail with `504 haechi_upstream_timeout`.

## Local Inference Servers

Haechi includes protocol adapter presets for OpenAI-compatible servers, vLLM, Ollama, llama.cpp, the Anthropic Messages API, and the Google Gemini API.

```json
{
  "target": {
    "type": "vllm-openai",
    "upstream": "http://127.0.0.1:8000"
  },
  "policy": {
    "mode": "enforce",
    "presets": ["local-inference"]
  },
  "responseProtection": {
    "enabled": true,
    "mode": "enforce",
    "failureMode": "fail-closed"
  }
}
```

Then point an OpenAI-compatible client at `http://127.0.0.1:11016/v1`. For Ollama native APIs, use `target.adapter: "ollama"` and call `/api/chat` or `/api/generate` through the proxy. For Claude, set `target.type: "anthropic"` and call `/v1/messages` (or `/v1/messages/count_tokens`, `/v1/complete`); the client's `x-api-key`/`anthropic-version` headers are forwarded to the upstream (they are on the upstream header allowlist). For Gemini, set `target.type: "gemini"` and call the model-in-path endpoints `/v1beta/models/{model}:generateContent` (or `:streamGenerateContent`, `:countTokens`, `:embedContent`, `:batchEmbedContents`); the client's `x-goog-api-key` (or `?key=`) is forwarded to the upstream. The proxy forwards only an explicit allowlist of headers and never forwards ambient client credentials — see [Gateway auth vs upstream auth](#gateway-auth-vs-upstream-auth-header-forwarding).

## Token Round-Trip

With tokenization the model sees stable tokens while the caller gets plaintext back:

```json
{
  "policy": { "mode": "enforce", "actions": { "email": "tokenize" } },
  "responseProtection": { "enabled": true, "mode": "enforce" },
  "tokenVault": {
    "deterministic": true,
    "detokenizeResponses": true
  }
}
```

- `tokenVault.deterministic` (default `false`): the same value always maps to the same token (HMAC over a domain-separated key derived from the local key — never the raw AES key). Required for multi-turn chats, since resent history re-tokenizes into the same tokens. **Trade-off:** equal values become linkable across requests. `deterministicTypes` (e.g. `["email"]`) limits determinism to selected types.
- `tokenVault.detokenizeResponses` (default `false`): restores **only the tokens issued while protecting the same request** in that request's response. Tokens from other clients or requests are never restored. Independent of `revealPolicy`; every restoration is audited by count, never by value. Requires `responseProtection.enabled`.

## MCP Wrap

Wrap any stdio MCP server so its traffic is filtered in both directions — change only the command in your MCP client config:

```json
{
  "mcpServers": {
    "some-server": {
      "command": "npx",
      "args": ["-y", "haechi", "mcp-wrap", "--config", "/path/haechi.config.json", "--", "npx", "some-mcp-server"]
    }
  }
}
```

Client→server requests pass the `mcp.allowedMethods` allowlist and params protection; server→client results get params/result protection plus injection heuristics (see below). Rejections are answered to the client and never reach the server. Exit codes pass through; the child's stderr is **filtered** through the same protection per line by default (`--stderr filter`) — use `--stderr inherit` for raw passthrough or `--stderr drop` to discard (recommended for high-sensitivity tools, since a per-line filter cannot catch a secret a child splits across a newline). `filter` transforms only under `policy.mode: enforce`.

## Injection Detection (Preview)

Response and tool-result text is screened with heuristic rules for indirect prompt injection (instruction overrides, role reassignment, prompt markers, conceal-from-user phrasing, covert tool induction). The `injection` type is **report-only by default**: detections are written to the audit log but nothing is modified or blocked. Escalate explicitly once you trust the signal:

```json
{ "policy": { "actions": { "injection": "block" } } }
```

These heuristics are not a complete defense against prompt injection; see `docs/current/threat-model.md`.

## Authentication & Per-Client Controls

With multiple clients/agents in front of one host, turn on bearer auth and bind each client to a policy profile. Tokens live in a separate `.haechi/auth.json` (0600), stored only as keyed-HMAC hashes:

```bash
haechi auth add --type service --scope team:eng --label env=prod   # prints the token ONCE
haechi auth list                                                   # never shows tokens
haechi auth revoke <id>
```

```json
{
  "auth": { "provider": "bearer" },
  "policy": {
    "mode": "enforce", "presets": ["llm-redact"],
    "profiles": {
      "strict":   { "presets": ["strict-block"] },
      "internal": { "presets": ["llm-redact"], "modelAllowlist": ["llama3"], "rate": { "requestsPerMinute": 120 } }
    },
    "profileBinding": { "byScope": { "team:eng": "internal" }, "default": "strict" }
  }
}
```

- **Bearer auth** (`auth.provider: bearer`): clients send `Authorization: Bearer <token>`. Missing/invalid/revoked → `401` (the body is never read, upstream is never reached). `provider: none` (default) keeps behavior unchanged; `external` requires an injected `authProvider`.
- **Named profiles**: each authenticated identity resolves to a profile by **scope → label → required `default`** (fail-closed to `default` for unmatched/anonymous). A profile overrides the base policy and may carry its own `modelAllowlist` and `rate`.
- **Model allowlist**: a request whose `model` is not allowed → `403`.
- **Rate limit**: per-identity requests-per-minute → `429` (in-memory, per-process).
- Audit events carry the **PII-safe** `identity` (keyed-HMAC subject/issuer, never raw values) and the resolved `profile`; `auth_denied` / `model_not_allowed` / `rate_limited` decisions never include credentials. `/__haechi/health` stays unauthenticated.

### Gateway auth vs upstream auth (header forwarding)

Haechi separates **gateway-client authentication** from **upstream-provider authentication**, and does **not** blindly forward your request headers to the model upstream. The proxy applies a **default-drop allowlist**: only a known-safe set of headers crosses the trust boundary into the model provider, and ambient client credentials are dropped.

- **`auth.provider: bearer` / `external` / `plugin` (the gateway authenticates the client).** The client's `Authorization` header is the **gateway credential** Haechi consumed to authenticate the client, so it is **dropped** — it is never forwarded to the upstream. This prevents leaking a gateway token across the trust boundary into the model provider.
- **`auth.provider: none` (no gateway auth).** The client's `Authorization` header is treated as the **upstream provider key** and **is forwarded** (the OpenAI-compatible pass-through pattern, where the client puts the model API key in `Authorization`).
- **Always dropped, regardless of mode:** `Cookie`, `Set-Cookie`, `Proxy-Authorization`, and hop-by-hop headers (`Connection`, `Keep-Alive`, `TE`, `Trailer`, `Transfer-Encoding`, `Upgrade`), plus any header not on the allowlist.
- **Always forwarded (the provider/adapter headers):** `x-api-key`, `anthropic-version`, `anthropic-beta`, `x-goog-api-key`, `openai-organization`, `openai-beta`, `accept`, `accept-language`, `user-agent`, and `content-type` (rewritten to `application/json`).
- **Escape hatch:** if an unusual upstream needs an extra header, list its lowercase name in `target.forwardHeaders` (e.g. `"forwardHeaders": ["x-tenant-id"]`). This can only **widen** the allowlist additively — it can never re-enable an always-dropped credential or hop-by-hop header (those names are rejected fail-closed at config time).

JWT/JWKS auth and KMS-backed key custody (and other optional capabilities) ship as the **`haechi-*` satellite packages** — see [Satellite packages](#satellite-packages) below.

## Satellite packages

Optional capabilities ship as independently-published **`haechi-*` packages on npm** — each versioned separately from core, `node:`-only by default (heavy SDKs like a KMS or Redis client are optional peers), and each declaring a `haechi` peer range of `>=0.8.0 <2.0.0` (the upper bound tracks the core major, so a core minor never breaks a satellite install).

**Install the core alongside any satellite** — `haechi` is a **peer dependency, not bundled**, so a satellite does nothing on its own:

```bash
npm install haechi haechi-<satellite>
```

| Package | What it adds |
|---|---|
| [`haechi-auth-jwt`](satellites/auth-jwt/) | Headless JWKS bearer (JWT) `authProvider`; additively exports a reusable JWS verifier (`createJwtVerifier`). |
| [`haechi-auth-oidc`](satellites/auth-oidc/) | Interactive OIDC session broker (authorization-code + PKCE) — the dashboard's human login. Reuses `haechi-auth-jwt`. |
| [`haechi-crypto-kms`](satellites/crypto-kms/) | Envelope-encryption `cryptoProvider` for `keys.provider: external` — AWS, GCP (`./gcp`), Azure (`./azure`), and HashiCorp Vault Transit (`./vault`, `node:`-only) backends. |
| [`haechi-dashboard`](satellites/dashboard/) | Zero-dependency, read-only audit viewer (`node:http`) over the audit log and its hash-chain status. |
| [`haechi-ratelimit-redis`](satellites/ratelimit-redis/) | Shared-store (Redis-backed) `rateLimiter` for multi-replica deployments, via the `providers.rateLimiter` injection seam. |

Each package's README covers its usage and exact peer requirements. The satellites keep core zero-dependency: their heavy SDKs are optional peers installed only when you use that backend.

## Configuration

`haechi init` writes `haechi.config.json`; a non-secret template lives at `haechi.config.example.json`. All keys validate fail-closed — unknown or malformed values refuse to start.

| Key | Default | Meaning |
|---|---|---|
| `mode` / `policy.mode` | `dry-run` | `dry-run` and `report-only` detect + audit only; `enforce` transforms/blocks. `policy.mode` wins over `mode` |
| `target.type` / `target.adapter` | `llm-http` / `openai-compatible` | Upstream protocol: `openai-compatible`, `vllm-openai`, `ollama`, `llama-cpp`, `anthropic`, `gemini`. Unknown types fail closed |
| `target.upstream` | `http://127.0.0.1:9999` | The only upstream the proxy will forward to (absolute-URL request targets are rejected) |
| `target.forwardHeaders` | `[]` (unset) | Extra lowercase header names to forward upstream, beyond the built-in allowlist. Additive only; cannot re-enable always-dropped credential/hop-by-hop headers |
| `proxy.host` / `proxy.port` | `127.0.0.1` / `11016` | Proxy bind address. See remote binding below |
| `responseProtection.enabled` | `false` | Inspect upstream JSON responses. `failureMode: fail-closed` rejects non-JSON/compressed/oversized responses |
| `responseProtection.maxBytes` | `1048576` | Hard response size cap — enforced even in `failureMode: allow` |
| `streaming.requestMode` | `block` | `block` 501s streaming; `inspect` stream-filters SSE/NDJSON responses; `pass-through` forwards uninspected (audited). Ollama chat/generate count as streaming unless `stream: false` |
| `streaming.responseMode` | `enforce` | Enforcement mode for inspected streams (`dry-run`/`report-only`/`enforce`) |
| `streaming.maxMatchBytes` | `256` | Cross-frame match window; a single match longer than this may split across frames |
| `limits.maxRequestBytes` | `1048576` | Request body cap (413 over the limit) |
| `limits.upstreamTimeoutMs` | `120000` | Upstream timeout (504 on expiry) |
| `policy.presets` | `korean-pii`, `secrets-only`, `llm-redact` | Merged preset actions; merges can strengthen but never weaken |
| `policy.actions` | `card: block` | Per-type action: `allow`/`redact`/`mask`/`tokenize`/`encrypt`/`block` |
| `filters.customRules` | `[]` | Extra regex rules (ReDoS-screened: no nested quantifiers/backreferences) |
| `keys.provider` / `keys.keyFile` | `local` / `.haechi/dev.keys.json` | Dev-only software keys (0600). `external` requires injecting a crypto provider programmatically |
| `audit.path` | `.haechi/audit.jsonl` | Hash-chained JSONL audit log; verify with `haechi audit-verify` |
| `tokenVault.revealPolicy` | `disabled` | Manual reveal gate (`local-dev` to enable; every decision is audited) |
| `tokenVault.retentionDays` | `30` | Expired tokens are deleted on vault writes or `haechi token-purge --expired` |
| `tokenVault.deterministic` / `deterministicTypes` / `detokenizeResponses` | `false` / `null` / `false` | Token round-trip (see above) |
| `privacy.profile` | `null` | `kr-pipa`, `eu-gdpr`, `us-general` baseline actions (strengthen-only) |
| `mcp.allowedMethods` | `initialize`, `tools/call`, `resources/read`, `prompts/get` | Client-callable method allowlist for `mcp-stdio`/`mcp-wrap` |
| `auth.provider` / `auth.store` | `none` / `.haechi/auth.json` | `none`/`bearer`/`external`. Bearer tokens stored as keyed-HMAC hashes (0600) |
| `policy.profiles` / `policy.profileBinding` | — | Named per-client policy profiles bound by scope → label → required `default` |
| `policy.modelAllowlist` / `policy.rate` | — | Allowed model names (403 otherwise); requests-per-minute rate limit (429) — also settable per profile |

The table above is a quick reference. The full per-key reference — types, validation rules, presets, action strength, and common setups — is in [`docs/current/configuration.md`](docs/current/configuration.md), and the CLI prints a condensed version:

```bash
haechi config        # configuration guide
haechi help          # all commands
haechi help proxy    # one command
haechi status        # effective state of the current config
```

### Binding beyond loopback (0.0.0.0)

The proxy refuses non-loopback hosts unless the CLI flag is given explicitly — setting `proxy.host: "0.0.0.0"` in config alone will not start, by design (copying a config file must not silently expose the gateway):

```bash
haechi proxy --config haechi.config.json --host 0.0.0.0 --allow-remote-bind
```

**The proxy ships bearer client authentication** (`auth.provider: bearer`, shipped in 0.6): a hashed token store, per-identity policy profiles, a model allowlist, and a per-identity rate limit (see [Authentication & Per-Client Controls](#authentication--per-client-controls)). The default `auth.provider: none` leaves the proxy unauthenticated, so with `none` anyone who can reach the port can use your upstream and the token round-trip path. The built-in rate limit is single-process (in-memory, per-process) — front multiple replicas with a shared limiter. Use `--allow-remote-bind` only behind explicit network controls regardless:

- **Containers**: binding `0.0.0.0` inside a container is the normal pattern — restrict exposure at the port mapping, e.g. `-p 127.0.0.1:11016:11016`
- **LAN/remote**: put a firewall, VPN (e.g. Tailscale), or an authenticating reverse proxy in front

## Privacy Profiles

Haechi includes baseline regional privacy profiles for local policy bootstrapping:

- `kr-pipa`
- `eu-gdpr`
- `us-general`

Set `privacy.profile` in `haechi.config.json` to apply the profile's default actions before enforcement. These profiles are engineering defaults, not legal advice.

## Known limitations

Haechi is deliberately scoped. These are real, current limitations — listed openly, not hidden:

- **Detection is regex + validators, not ML.** Rules are anchored on prefix/charclass/length with checksum validators (Luhn, KR RRN, IBAN mod-97, national-ID checks) — strong precision on known shapes, but a novel or obfuscated secret can be missed. Tune with `filters.minConfidence` / `filters.allowlist`; an ML/classifier layer is backlog, not shipped.
- **Streaming match window is bounded.** Cross-frame PII is caught on the JSON **delta channel** up to `streaming.maxMatchBytes` (default 256). A match split across **non-JSON** SSE/NDJSON frames is inspected per-frame only (documented residual).
- **Response inspection is a secondary defense.** The response direction does not scan bare JSON **number** leaves by default (they are inference-server metadata and only false-positive); opt in with `responseProtection.scanNumbers: true` for a strict threat model.
- **MCP `--stderr filter` is line-oriented.** It protects each complete stderr line; a secret a child splits across a newline is not caught (an anchored regex cannot match across `\n`). Use `--stderr drop` for high-sensitivity local tools.
- **Audit tail-truncation needs separate media.** `haechi audit-verify` detects modification, reordering, and middle tampering; deletion of *trailing* records is only detectable via `audit.anchor` written to append-only / separate storage.
- **Rate limiting is per-process by default.** Behind N replicas the built-in limiter counts independently — inject a shared store (the `haechi-ratelimit-redis` satellite) for a fleet-wide budget.
- **Plugin sandbox: the default `worker_threads` mode is not a capability sandbox** (it is memory/crash isolation + data-minimization, gated by the Ed25519 trust gate). Real kernel-enforced containment is the opt-in `process-isolated` runtime, which requires a Node that enforces `--allow-net`.
- **No production key custody in core.** The local AES-256-GCM software-key file is **dev-only**; use the `haechi-crypto-kms` satellite for KMS/HSM/Vault-backed custody.
- **CI note:** the GHCR image-publish workflow's `docker/*` actions still run on Node 20 (a GitHub deprecation warning, non-blocking) — pinned and scheduled for a Node-24 bump.

**Deliberately out of scope (won't fix):** URL query-string scanning; always-on base64/encoded-value decoding (opt-in only via `filters.decodeAndRescan`); dashboard write actions (the audit viewer is read-only by design); OS-level (seccomp) plugin sandboxing; and any compliance certification. **Haechi is not a compliance guarantee.**

## Security Notes

- This project is not a compliance guarantee.
- The local crypto provider uses Node `crypto` with AES-256-GCM and a local software-key file.
- Audit events must not contain raw prompt, tool result, secret, or PII values.
- Unknown or invalid policy/config errors should fail closed in enforcement paths.
- Response protection fails closed for non-JSON, invalid JSON, compressed, or oversized responses unless an explicit allow policy is configured.
- Token reveal and purge decisions are written to the audit log (token ids and decisions only, never plaintext). Expired tokens are removed on vault mutations or via `haechi token-purge --expired`.
- `haechi init --force` rotates the local key: prior keys are kept as `retired` so existing envelopes and token vault records stay decryptable by `kid`.
- Privacy profiles can strengthen but never weaken an explicitly stricter user action.
- Detection scans string values, JSON numbers (e.g. card numbers), and object key names. Base64/URL-encoded values and URL query strings are NOT inspected.
- Audit tail truncation: set `audit.anchor.mode: file` (on append-only/separate media) so `haechi audit-verify --anchor` detects deletion of trailing records back to the last anchor. On the same writable filesystem an attacker can truncate both files together.
- Key custody: `keys.provider: external` accepts an injected `cryptoProvider`; validate adapters with `assertCryptoProviderConformance`. The `haechi-crypto-kms` satellite (`satellites/crypto-kms/`) provides an envelope-encryption KMS adapter.
- Release integrity: published tarballs carry an npm provenance attestation; GitHub release assets add a sigstore attestation and `SHA256SUMS` (verify with `gh attestation verify` and `node scripts/release-checksums.mjs --check`).
- The 1.0 authProvider plugin sandbox runs a signed plugin in a `worker_threads` worker. This is memory/crash isolation and data-minimization (only the credential slice crosses; the host builds the keyed-HMAC identity), **not** a capability sandbox: a malicious *signed* plugin can still use `fs`/`net` and exfiltrate the credential it receives. The load-bearing control is the trust gate (Ed25519 signature + operator allowlist + version pin/floor + revocation). **1.1 closes this residual** with an opt-in `process-isolated` runtime (`auth.plugin.isolation: "process"`): the signed plugin runs in a child process under the Node permission model (`--permission`, zero grants) with kernel-denied fs/net/exec/worker, all stdio ignored, and a `data:`-URL load (no fs grant) — real capability enforcement. It requires a Node that enforces `--allow-net` and **fails closed** otherwise; the unchanged `worker_threads` mode stays the default. Default wiring stays dependency injection (`createRuntime(config, providers)`).
- Do not expose Haechi as an internet-facing production LLM gateway without your own network controls and authentication in front.

## Current Scope

0.1 quickstart scope is described in `docs/current/mvp-0.1-implementation-scope.md`.

0.2 adds local TokenVault, signed policy bundle commands, plugin manifest validation, and an MCP stdio JSON-RPC line filter skeleton. See `docs/current/release-0.2-implementation-scope.md`.

0.3 adds local inference protocol adapters, optional JSON response protection, npm package metadata, and publish-ready exports. See `docs/current/release-0.3-implementation-scope.md`.

0.3.1 adds release safety gates, response fail-closed behavior, audit hash chaining, token reveal governance, provider injection, privacy profiles, CI/SBOM/provenance workflow scaffolding, and dedicated threat/shared-responsibility/API-stability docs.

0.3.2 is a security-hardening release and the first npm developer preview target: Ollama implicit-streaming fail-closed handling, audited token reveal/purge, retention purge, kid-based key rotation, domain-separated policy bundle signing, JSON number/object key detection, upstream timeouts, stale lock recovery, and non-enforcing-mode warnings. See `docs/current/release-0.3.2-hardening-scope.md`.

0.4.0 adds the token round-trip (deterministic tokenization + request-scoped response detokenization), the `mcp-wrap` bidirectional MCP filter, `status` and `audit-verify` commands, report-only injection detection heuristics, and reserves the PII-safe `identity`/`authProvider` contracts for 0.6 auth. See `docs/current/release-0.4-implementation-scope.md`.

0.5.0 adds SSE/NDJSON streaming response inspection: `streaming.requestMode: "inspect"` stream-filters responses with a bounded sliding buffer over the JSON **delta channel** that catches PII split across delta frames (`streaming.maxMatchBytes`); non-delta leaves and non-JSON content frames are inspected within each frame. See `docs/current/release-0.5-implementation-scope.md`.

0.6.0 adds authentication and per-client controls: built-in bearer auth with a hashed token store and `haechi auth` CLI, named policy profiles bound by identity scope/label, model allowlisting, and per-identity rate limiting — with PII-safe identity in the audit log. See `docs/current/release-0.6-implementation-scope.md`.

0.7.0 is operational hardening: audit head-hash anchoring (`audit.anchor`) that detects tail truncation, a hardened external `cryptoProvider` contract with `assertCryptoProviderConformance` and a reference KMS adapter, and signed/checksummed GitHub release artifacts. See `docs/current/release-0.7-implementation-scope.md`.

0.8.0 stands up the `haechi-*` ecosystem: an npm workspaces monorepo (core stays the unscoped `haechi`, zero runtime dependency, gated by a packed-manifest CI check) plus the first two satellites — [`haechi-crypto-kms`](satellites/crypto-kms/) (envelope encryption with a real AWS KMS client; the AWS SDK is an optional peer) and [`haechi-auth-jwt`](satellites/auth-jwt/) (headless JWKS bearer verification, `node:`-only). Each publishes independently with its own provenance + sigstore-attested workflow. See `docs/current/release-0.8-implementation-scope.md`.

0.9.0 is the observability + interactive-auth theme: two new satellites — [`haechi-dashboard`](satellites/dashboard/) (a zero-dependency, read-only `node:http` audit viewer over the audit log and its hash-chain status, with an anti-DNS-rebinding Host allowlist, strict CSP/Trusted Types, and fail-closed loopback/remote-bind guards) and [`haechi-auth-oidc`](satellites/auth-oidc/) (an interactive OIDC session broker — authorization-code + PKCE + server-side sessions — that provides the dashboard's human login). Existing satellites also ship additive minors: `haechi-auth-jwt@0.2.0` exports a reusable JWS verifier (`createJwtVerifier`) and `haechi-crypto-kms@0.2.0` adds GCP/Azure/Vault backends. Core bumps to `0.9.0`, carrying only an additive `FORBIDDEN_KEYS` audit-sanitization hardening — defense-in-depth that changes no current event output. See `docs/current/release-0.9-implementation-scope.md`.

1.0.0 is the **first stable release**. It declares a frozen API contract under strict semver: the `package.json` `exports` surface, the CLI's machine-readable behavior, the audit event schema (including its nested sub-schemas and `schemaVersion`), and the config key shape are all part of the major-versioned contract, guarded by `tests/api-contract.test.mjs` and governed by a documented deprecation policy (`HAECHI_DEPRECATION_*` runtime warnings, removal only at the next major) with a single in-minor security exception for disclosed vulnerabilities (see [`docs/current/api-stability.md`](docs/current/api-stability.md)). 1.0 also lifts the dynamic-loading ban **narrowly**, for `authProvider` plugins only: an Ed25519-signed (asymmetric `node:crypto` verification with trust-anchor-only key resolution, entry-hash binding, version pin/floor, revocation, and a signing window), capability-gated, `worker_threads`-isolated, fully audited plugin sandbox. Dependency injection (`createRuntime(config, providers)`) stays the default. **Honest residual:** the worker is memory/crash isolation and data-minimization, not a capability sandbox — a malicious *signed* plugin can still use `fs`/`net` and exfiltrate the credential slice it receives, so the load-bearing control is the trust gate; true capability enforcement (child-process + Node permission model) is a 1.x target. The four `haechi-*` satellites (`haechi-auth-jwt@0.2.1`, `haechi-crypto-kms@0.2.1`, `haechi-dashboard@0.1.2`, `haechi-auth-oidc@0.1.2`) stay pre-1.0, version independently, and widen their `haechi` peer range to `>=0.8.0 <2.0.0` so core 1.0.0 does not break their installs. See `docs/current/release-1.0-implementation-scope.md`.

1.1.0 closes the most-cited 1.0 honest residual with **real plugin capability enforcement**: a new opt-in `process-isolated` authProvider runtime (`auth.plugin.isolation: "process"`) runs the signed plugin in a child process under the Node permission model (`--permission`, **zero grants**), loaded from a `data:` URL (no filesystem grant), with `stdio: ['ignore','ignore','ignore','ipc']` and a scrubbed env. On a Node that enforces `--allow-net`, the kernel denies the plugin's `fs`/`net`/`fetch`/`dns`/`child_process`/`worker` *and* the `process.binding('tcp_wrap')` bypass, so a malicious signed plugin cannot exfiltrate the credential it receives. Network containment is the kernel `--allow-net` denial (not a deletable JS harness); the default `netEnforcement: "require-permission"` **fails closed** (refuses to construct) on a Node without `--allow-net`. For a custom-credential plugin, the **host** fetches operator-declared key material through an SSRF-hardened core guard (`haechi/ssrf`) and injects it over the IPC — the plugin never names a URL. A spawn-storm circuit breaker bounds respawns. The unchanged 1.0 `worker_threads` mode stays the default; `process-isolated` is additive and opt-in (a **minor** under strict semver). See `docs/current/release-1.1-implementation-scope.md`.

1.2.0 is the Reliability Hardening Track (WS1–WS6, additive behind 1.1-preserving defaults): a labeled-corpus detection precision/recall benchmark + regression gate; `filters.minConfidence` / `filters.allowlist` with a non-suppressible hard-block-types invariant; NFKC unicode-evasion folding; an injectable rate-limiter seam; operability (`/__haechi/live`+`/ready`, injectable `/metrics`, structured logs + per-request `correlationId`, graceful drain, env overlay, hardened Dockerfile/compose); and proxy TLS / remote-bind hardening plus an OWASP-LLM / NIST control-mapping whitepaper. See `docs/current/reliability-hardening-track.md`.

1.3.0 expands backends and detection: protocol adapters for the **Anthropic Messages API** and **Google Gemini API**; cloud/SaaS provider-key detection and international PII (FR/ES/JP/IT/SG/IN/DE/NL national IDs, checksum-validated, each hard-block-vs-allowlist-clearable decision driven by measured collision rates); a proxy throughput benchmark; and the `haechi-ratelimit-redis` shared-store rate-limiter satellite. All additive (new `target.type`/detection-type/profile *values*, `configVersion` stays `1`).

1.3.1 → 1.3.3 are security-remediation and hardening **patches** (no API/config change). 1.3.1 and 1.3.2 close two external code-review rounds — proxy header-boundary credential leak, hex IPv4-mapped IPv6 SSRF, response-header/streaming bounds, and non-JSON streaming inspection (1.3.1); proxy upstream-reader cancel-on-disconnect, token-vault audit-log hygiene, and plugin IPC reply bounds (1.3.2). 1.3.3 tightens the response-direction marker skip (a model can't wrap a secret in a fake `[TOKEN:…]` to evade scanning) and adds the cosign-signed GHCR container image.
