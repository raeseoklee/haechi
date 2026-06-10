# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Haechi is an experimental developer-preview **AI context enforcement layer**: it inspects and protects OpenAI-compatible / MCP / vLLM / Ollama / llama.cpp JSON payloads (detecting PII and secrets, then redacting/masking/tokenizing/encrypting/blocking them) before they reach models, tools, or logs. It is not production-ready and is not a compliance guarantee. Package name `haechi`, current version `0.3.2`.

## Commands

```bash
npm test                              # run all tests (node --test)
node --test tests/proxy.test.mjs      # run a single test file
node --test tests/proxy-0.3.test.mjs  # version-suffixed files target a specific release's scope

npm run demo:init                     # haechi init --force (writes haechi.config.json + .haechi/dev.keys.json)
npm run demo:protect                  # protect a sample payload
npm run demo:report                   # summarize audit events

npm run haechi -- <cmd>               # run the CLI (e.g. npm run haechi -- proxy)
npm run release:preflight             # pre-release gate checks
npm run scan:stale-names              # guard against stale naming in publishable files
npm run sbom                          # regenerate sbom.cdx.json
npm run pack:dry                      # npm pack --dry-run (verify published file set)
```

There is **no build step and no lint step** — this is plain ESM (`"type": "module"`) targeting Node `>=22` with **zero runtime dependencies** (only `node:` builtins). The `node:test` runner is the only test framework.

## Architecture

### The pipeline (the thing to understand first)

Everything funnels through `createHaechi(...).protectJson(payload, context)` in `packages/core/index.mjs`. The flow:

1. `collectStringEntries` walks the JSON tree and extracts every string leaf with its path.
2. `filterEngine.detect` runs regex rules (with optional validators like Luhn / Korean RRN checksums) → detections.
3. `policyEngine.decide` maps each detection's type to an action via presets + per-type overrides.
4. `transformPayload` applies the action (`redact` / `mask` / `tokenize` / `encrypt` / `block`).
5. `auditSink.record` writes a sanitized audit event.

**Modes matter for enforcement.** `dry-run` and `report-only` (the `NO_ENFORCE_MODES` set in core) detect and audit but do **not** mutate the payload or block. Any other mode (`enforce`) actually transforms/blocks. The default config ships in `dry-run`.

### Wiring: `createRuntime` (packages/cli/runtime.mjs)

`createRuntime(config, providers)` is the composition root. It reads a normalized config and instantiates the five collaborators — `filterEngine`, `policyEngine`, `cryptoProvider`, `auditSink`, `tokenVault` — plus a `protocolAdapter`, then hands them to `createHaechi`. Each collaborator can be **dependency-injected** via the `providers` argument; this is how tests and the `keys.provider: "external"` path supply their own crypto provider (external keys *require* injecting `cryptoProvider`, since there is no production KMS/HSM provider).

`normalizeConfig` deep-merges user config over `defaultConfig()` and performs **strict, fail-closed validation** — unknown providers, invalid reveal policies, bad failure modes, etc. all throw rather than silently degrading. When touching config shape, update `defaultConfig`, `normalizeConfig`, AND `haechi.config.example.json` together.

### Packages (directory modules, not npm workspaces)

`packages/*/index.mjs` are wired together purely through the `exports` map in `package.json` and direct relative imports. There is no workspace tooling.

- `core` — `protectJson` orchestrator + payload tree walk/transform.
- `cli` — `bin/haechi.mjs` (command dispatch) and `runtime.mjs` (composition root, config schema).
- `filter` — default detection rules (email, KR phone, KR RRN, card/Luhn, API keys, bearer tokens) + custom rule support.
- `policy` — `PRESETS`, action validation, and `ACTION_STRENGTH` ordering (the strongest action wins when multiple apply).
- `crypto` — local AES-256-GCM provider over a software key file. No production key provider exists.
- `audit` — JSONL sink with **sha256 hash chaining** for tamper evidence. `FORBIDDEN_KEYS` enforces that raw plaintext/prompt/secret values never get written.
- `token-vault` — local tokenization store with reveal **governance** (`revealPolicy: disabled | local-dev`) and retention.
- `proxy` — local HTTP JSON proxy fronting an upstream LLM endpoint.
- `protocol-adapters` — request classification per `target.type` (`openai-compatible`, `vllm-openai`, `ollama`, llama.cpp).
- `mcp-stdio` — JSON-RPC 2.0 line filter for MCP stdio traffic (method allowlist + param/result protection).
- `policy-bundle` — sign/verify signed policy bundles.
- `plugin` — plugin manifest validation.
- `privacy-profiles` — regional default-action profiles (`kr-pipa`, `eu-gdpr`, `us-general`) applied before enforcement.

### CLI surface

`packages/cli/bin/haechi.mjs` dispatches: `init`, `protect`, `report`, `proxy`, `policy-sign`, `policy-verify`, `token-reveal`, `token-purge`, `token-export`, `plugin-validate`, `mcp-stdio`.

## Security invariants (do not regress these)

These are load-bearing behaviors enforced by tests and documented in `docs/current/threat-model.md` / `risk-register-release-gate.md`:

- **Fail closed.** Unknown/invalid policy or config throws in enforcement paths (including unknown `target.type`). Response protection fails closed for non-JSON, invalid JSON, compressed, or oversized responses unless explicitly allowed.
- **No plaintext in audit.** Audit events must never contain raw prompt, tool-result, secret, or PII values — `FORBIDDEN_KEYS` in `packages/audit/index.mjs` guards this.
- **Loopback bind by default.** The proxy refuses to bind `0.0.0.0` / `::` / non-loopback hosts unless `--allow-remote-bind` is passed (`assertSafeProxyBind`).
- **Streaming is blocked by default.** `stream: true` requests return 501 unless `streaming.requestMode` is explicitly `pass-through`. Ollama `/api/chat` and `/api/generate` default to streaming, so they are treated as streaming unless the request sets `stream: false` (`streamingDefault` in protocol adapters).
- **Token reveal is governed and audited.** Revealing tokenized values is gated by `tokenVault.revealPolicy`, and reveal/purge decisions are written to the audit log (token ids only, never plaintext). Expired tokens are pruned on vault mutations.
- **Policies only get stronger.** Preset/action merges reject weakening (`ACTION_STRENGTH`), and privacy profiles may strengthen but never weaken an explicit user action.
- **Key rotation preserves old keys.** `initLocalKeyFile --force` retires (not deletes) prior keys; `decrypt` selects keys by envelope `kid`. Policy-bundle signing uses a domain-separated key derived from the stored key, never the raw AES key.
- **Detection covers values, JSON numbers, and object keys.** Base64/encoded values and URL query strings are documented exclusions (see threat model).

When changing publishable behavior, keep `docs/current/` scope docs and the README's "Current Scope" section in sync; release gating lives in `docs/current/risk-register-release-gate.md` and `scripts/release-preflight.mjs`.
