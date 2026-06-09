# Haechi

Haechi is a self-hosted AI context enforcement layer for protecting LLM, MCP, vLLM, Ollama, and agent payloads before they reach models, tools, logs, or proxies.

The name comes from Haechi, a Korean guardian figure associated with discernment and protection.

The 0.1 MVP focuses on local adoption:

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

`npm run demo:init` writes `haechi.config.json` and `.haechi/dev.keys.json` locally. A non-secret template is available at `haechi.config.example.json`.

## Local Proxy

```bash
node packages/cli/bin/haechi.mjs proxy --config haechi.config.json --port 8787
```

Point an existing HTTP JSON client at `http://localhost:8787` and set `target.upstream` in `haechi.config.json`.

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
    "mode": "enforce"
  }
}
```

Then point an OpenAI-compatible client at `http://127.0.0.1:8787/v1`. For Ollama native APIs, use `target.adapter: "ollama"` and call `/api/chat` or `/api/generate` through the proxy.

## Security Notes

- This project is not a compliance guarantee.
- The 0.1 crypto provider uses Node `crypto` with AES-256-GCM and local software keys.
- Audit events must not contain raw prompt, tool result, secret, or PII values.
- Unknown or invalid policy/config errors should fail closed in enforcement paths.

## Current Scope

0.1 quickstart scope is described in `docs/current/mvp-0.1-implementation-scope.md`.

0.2 adds local TokenVault, signed policy bundle commands, plugin manifest validation, and an MCP stdio JSON-RPC line filter skeleton. See `docs/current/release-0.2-implementation-scope.md`.

0.3 adds local inference protocol adapters, optional JSON response protection, npm package metadata, and publish-ready exports. See `docs/current/release-0.3-implementation-scope.md`.
