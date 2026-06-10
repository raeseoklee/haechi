# Haechi

[![npm](https://img.shields.io/npm/v/haechi)](https://www.npmjs.com/package/haechi)
[![CI](https://github.com/raeseoklee/haechi/actions/workflows/ci.yml/badge.svg)](https://github.com/raeseoklee/haechi/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![node](https://img.shields.io/node/v/haechi)](https://nodejs.org)
[![status](https://img.shields.io/badge/status-developer%20preview-orange)](docs/current/risk-register-release-gate.md)

**English** | [한국어](README.ko.md)

Haechi is an experimental developer preview of a self-hosted AI context enforcement layer for protecting LLM, MCP, vLLM, Ollama, and agent payloads before they reach models, tools, logs, or proxies.

The name comes from Haechi, a Korean guardian figure associated with discernment and protection.

This repository is intended for local development, security design review, and self-hosted integration experiments. It is not production-ready and is not a compliance guarantee.

The current developer-preview scope focuses on local adoption:

- `haechi init`: create a local key, sample config, and audit path
- `haechi protect`: inspect and protect an OpenAI-compatible JSON payload
- `haechi report`: summarize audit events without raw payloads
- `haechi proxy`: run a local HTTP JSON proxy for existing LLM calls
- `haechi status`: show what is and is not protected under the current config
- `haechi audit-verify`: verify the audit hash chain and print its head hash
- `haechi mcp-wrap -- <command>`: wrap an MCP server with bidirectional stdio protection

## Install

```bash
npm install -g haechi
haechi init
```

Or run without installing:

```bash
npx haechi init
```

## Quickstart

From a clone of this repository:

```bash
npm test
npm run demo:init
npm run demo:protect
npm run demo:report
```

The default config runs in `dry-run` mode. It detects sensitive values and writes audit metadata, but it does not modify outbound payloads until policy mode is changed.

`npm run demo:init` writes `haechi.config.json` and `.haechi/dev.keys.json` locally. The generated key file is for local development only. Haechi 0.3.x does not include a production KMS/HSM/Vault key provider. A non-secret template is available at `haechi.config.example.json`.

## Local Proxy

```bash
node packages/cli/bin/haechi.mjs proxy --config haechi.config.json
```

Point an existing HTTP JSON client at `http://localhost:1016` and set `target.upstream` in `haechi.config.json`. Change `proxy.port` in the config or pass `--port` to use a different local port.

The proxy binds to loopback by default. Binding to `0.0.0.0`, `::`, or another non-loopback host fails unless `--allow-remote-bind` is provided. Use that flag only behind explicit network access controls.

Streaming requests with `stream: true` are blocked by default. Set `streaming.requestMode` to `inspect` to stream-filter SSE/NDJSON responses (a bounded sliding buffer catches PII split across frames; see `streaming.maxMatchBytes`), or to `pass-through` only when the caller explicitly accepts unprotected streaming.

Ollama `/api/chat` and `/api/generate` stream by default when the `stream` field is omitted, so the proxy treats those requests as streaming unless `stream: false` is explicitly set.

Upstream requests time out after `limits.upstreamTimeoutMs` (default 120000) and fail with `504 haechi_upstream_timeout`.

## Local Inference Servers

Haechi 0.3 includes protocol adapter presets for OpenAI-compatible servers, vLLM, Ollama, and llama.cpp.

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

Then point an OpenAI-compatible client at `http://127.0.0.1:1016/v1`. For Ollama native APIs, use `target.adapter: "ollama"` and call `/api/chat` or `/api/generate` through the proxy.

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

Client→server requests pass the `mcp.allowedMethods` allowlist and params protection; server→client results get params/result protection plus injection heuristics (see below). Rejections are answered to the client and never reach the server; stderr and exit codes pass through.

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

OIDC/JWT providers and KMS-backed key custody are 0.7+ satellite packages.

## Configuration

`haechi init` writes `haechi.config.json`; a non-secret template lives at `haechi.config.example.json`. All keys validate fail-closed — unknown or malformed values refuse to start.

| Key | Default | Meaning |
|---|---|---|
| `mode` / `policy.mode` | `dry-run` | `dry-run` and `report-only` detect + audit only; `enforce` transforms/blocks. `policy.mode` wins over `mode` |
| `target.type` / `target.adapter` | `llm-http` / `openai-compatible` | Upstream protocol: `openai-compatible`, `vllm-openai`, `ollama`, `llama-cpp`. Unknown types fail closed |
| `target.upstream` | `http://127.0.0.1:9999` | The only upstream the proxy will forward to (absolute-URL request targets are rejected) |
| `proxy.host` / `proxy.port` | `127.0.0.1` / `1016` | Proxy bind address. See remote binding below |
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

**The proxy has no client authentication yet** (planned for 0.6): anyone who can reach the port can use your upstream and the token round-trip path. Use `--allow-remote-bind` only behind explicit network controls:

- **Containers**: binding `0.0.0.0` inside a container is the normal pattern — restrict exposure at the port mapping, e.g. `-p 127.0.0.1:1016:1016`
- **LAN/remote**: put a firewall, VPN (e.g. Tailscale), or an authenticating reverse proxy in front

## Privacy Profiles

Haechi includes baseline regional privacy profiles for local policy bootstrapping:

- `kr-pipa`
- `eu-gdpr`
- `us-general`

Set `privacy.profile` in `haechi.config.json` to apply the profile's default actions before enforcement. These profiles are engineering defaults, not legal advice.

## Security Notes

- This project is not a compliance guarantee.
- The 0.1 crypto provider uses Node `crypto` with AES-256-GCM and local software keys.
- Audit events must not contain raw prompt, tool result, secret, or PII values.
- Unknown or invalid policy/config errors should fail closed in enforcement paths.
- Response protection fails closed for non-JSON, invalid JSON, compressed, or oversized responses unless an explicit allow policy is configured.
- Token reveal and purge decisions are written to the audit log (token ids and decisions only, never plaintext). Expired tokens are removed on vault mutations or via `haechi token-purge --expired`.
- `haechi init --force` rotates the local key: prior keys are kept as `retired` so existing envelopes and token vault records stay decryptable by `kid`.
- Privacy profiles can strengthen but never weaken an explicitly stricter user action.
- Detection scans string values, JSON numbers (e.g. card numbers), and object key names. Base64/URL-encoded values and URL query strings are NOT inspected.
- Audit tail truncation: set `audit.anchor.mode: file` (on append-only/separate media) so `haechi audit-verify --anchor` detects deletion of trailing records back to the last anchor. On the same writable filesystem an attacker can truncate both files together.
- Key custody: `keys.provider: external` accepts an injected `cryptoProvider`; validate adapters with `assertCryptoProviderConformance`. See `examples/crypto-kms-reference/` for an envelope-encryption KMS adapter.
- Release integrity: published tarballs carry an npm provenance attestation; GitHub release assets add a sigstore attestation and `SHA256SUMS` (verify with `gh attestation verify` and `node scripts/release-checksums.mjs --check`).
- The package is a developer preview. Do not expose it as an internet-facing production LLM gateway.

## Current Scope

0.1 quickstart scope is described in `docs/current/mvp-0.1-implementation-scope.md`.

0.2 adds local TokenVault, signed policy bundle commands, plugin manifest validation, and an MCP stdio JSON-RPC line filter skeleton. See `docs/current/release-0.2-implementation-scope.md`.

0.3 adds local inference protocol adapters, optional JSON response protection, npm package metadata, and publish-ready exports. See `docs/current/release-0.3-implementation-scope.md`.

0.3.1 adds release safety gates, response fail-closed behavior, audit hash chaining, token reveal governance, provider injection, privacy profiles, CI/SBOM/provenance workflow scaffolding, and dedicated threat/shared-responsibility/API-stability docs.

0.3.2 is a security-hardening release and the first npm developer preview target: Ollama implicit-streaming fail-closed handling, audited token reveal/purge, retention purge, kid-based key rotation, domain-separated policy bundle signing, JSON number/object key detection, upstream timeouts, stale lock recovery, and non-enforcing-mode warnings. See `docs/current/release-0.3.2-hardening-scope.md`.

0.4.0 adds the token round-trip (deterministic tokenization + request-scoped response detokenization), the `mcp-wrap` bidirectional MCP filter, `status` and `audit-verify` commands, report-only injection detection heuristics, and reserves the PII-safe `identity`/`authProvider` contracts for 0.6 auth. See `docs/current/release-0.4-implementation-scope.md`.

0.5.0 adds SSE/NDJSON streaming response inspection: `streaming.requestMode: "inspect"` stream-filters responses with a bounded sliding buffer that catches PII split across frames (`streaming.maxMatchBytes`). See `docs/current/release-0.5-implementation-scope.md`.

0.6.0 adds authentication and per-client controls: built-in bearer auth with a hashed token store and `haechi auth` CLI, named policy profiles bound by identity scope/label, model allowlisting, and per-identity rate limiting — with PII-safe identity in the audit log. See `docs/current/release-0.6-implementation-scope.md`.

0.7.0 is operational hardening: audit head-hash anchoring (`audit.anchor`) that detects tail truncation, a hardened external `cryptoProvider` contract with `assertCryptoProviderConformance` and a reference KMS adapter, and signed/checksummed GitHub release artifacts. See `docs/current/release-0.7-implementation-scope.md`.
