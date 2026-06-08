# AICEL

AI Context Encryption Layer is a self-hosted toolkit for protecting AI/LLM/MCP payloads before they reach models, tools, logs, or proxies.

The 0.1 MVP focuses on local adoption:

- `aicel init`: create a local key, sample config, and audit path
- `aicel protect`: inspect and protect an OpenAI-compatible JSON payload
- `aicel report`: summarize audit events without raw payloads
- `aicel proxy`: run a local HTTP JSON proxy for existing LLM calls

## Quickstart

```bash
npm test
npm run demo:init
npm run demo:protect
npm run demo:report
```

The default config runs in `dry-run` mode. It detects sensitive values and writes audit metadata, but it does not modify outbound payloads until policy mode is changed.

`npm run demo:init` writes `aicel.config.json` and `.aicel/dev.keys.json` locally. A non-secret template is available at `aicel.config.example.json`.

## Local Proxy

```bash
node packages/cli/bin/aicel.mjs proxy --config aicel.config.json --port 8787
```

Point an existing HTTP JSON client at `http://localhost:8787` and set `target.upstream` in `aicel.config.json`.

## Security Notes

- This project is not a compliance guarantee.
- The 0.1 crypto provider uses Node `crypto` with AES-256-GCM and local software keys.
- Audit events must not contain raw prompt, tool result, secret, or PII values.
- Unknown or invalid policy/config errors should fail closed in enforcement paths.

## Current Scope

See `docs/current/mvp-0.1-implementation-scope.md`.
