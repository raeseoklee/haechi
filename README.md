# Haechi

Haechi is an experimental developer preview of a self-hosted AI context enforcement layer for protecting LLM, MCP, vLLM, Ollama, and agent payloads before they reach models, tools, logs, or proxies.

The name comes from Haechi, a Korean guardian figure associated with discernment and protection.

This repository is intended for local development, security design review, and self-hosted integration experiments. It is not production-ready and is not a compliance guarantee.

The current developer-preview scope focuses on local adoption:

- `haechi init`: create a local key, sample config, and audit path
- `haechi protect`: inspect and protect an OpenAI-compatible JSON payload
- `haechi report`: summarize audit events without raw payloads
- `haechi proxy`: run a local HTTP JSON proxy for existing LLM calls

## Quickstart

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
node packages/cli/bin/haechi.mjs proxy --config haechi.config.json --port 8787
```

Point an existing HTTP JSON client at `http://localhost:8787` and set `target.upstream` in `haechi.config.json`.

The proxy binds to loopback by default. Binding to `0.0.0.0`, `::`, or another non-loopback host fails unless `--allow-remote-bind` is provided. Use that flag only behind explicit network access controls.

Streaming requests with `stream: true` are blocked by default. Haechi 0.3.x does not inspect SSE or NDJSON streams. Set `streaming.requestMode` to `pass-through` only when the caller explicitly accepts that streaming payloads are not protected by Haechi.

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

Then point an OpenAI-compatible client at `http://127.0.0.1:8787/v1`. For Ollama native APIs, use `target.adapter: "ollama"` and call `/api/chat` or `/api/generate` through the proxy.

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
- The package is a developer preview. Do not expose it as an internet-facing production LLM gateway.

## Current Scope

0.1 quickstart scope is described in `docs/current/mvp-0.1-implementation-scope.md`.

0.2 adds local TokenVault, signed policy bundle commands, plugin manifest validation, and an MCP stdio JSON-RPC line filter skeleton. See `docs/current/release-0.2-implementation-scope.md`.

0.3 adds local inference protocol adapters, optional JSON response protection, npm package metadata, and publish-ready exports. See `docs/current/release-0.3-implementation-scope.md`.

0.3.1 adds release safety gates, response fail-closed behavior, audit hash chaining, token reveal governance, provider injection, privacy profiles, CI/SBOM/provenance workflow scaffolding, and dedicated threat/shared-responsibility/API-stability docs.
