# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Haechi is an **AI context enforcement layer**: it inspects and protects OpenAI-compatible / MCP / vLLM / Ollama / llama.cpp JSON payloads (detecting PII and secrets, then redacting/masking/tokenizing/encrypting/blocking them) before they reach models, tools, or logs. It is not a compliance guarantee. Package name `haechi`, current version `1.0.0`.

## Commands

```bash
npm test                              # run all tests (node --test)
node --test tests/proxy.test.mjs      # run a single test file
node --test tests/proxy-0.3.test.mjs  # version-suffixed files target a specific release's scope

npm run demo:init                     # haechi init --force (writes haechi.config.json + .haechi/dev.keys.json)
npm run demo:protect                  # protect a sample payload
npm run demo:report                   # summarize audit events

npm run haechi -- <cmd>               # run the CLI (e.g. npm run haechi -- proxy)
npm run check:types                   # tsc --noEmit over jsconfig.json (LSP/type sanity)
npm run release:preflight             # pre-release gate checks (tests + types + stale-names + pack)
npm run scan:stale-names              # guard against stale naming in publishable files
npm run sbom                          # regenerate sbom.cdx.json (omits dev deps)
npm run pack:dry                      # npm pack --dry-run (verify published file set)
```

There is **no build step and no lint step** — this is plain ESM (`"type": "module"`) targeting Node `>=22` with **zero runtime dependencies** (only `node:` builtins; `typescript`/`@types/node` are dev-only for LSP and `check:types`). The `node:test` runner is the only test framework. Editor LSP is configured by `jsconfig.json`; `checkJs` is off — opt files in with `// @ts-check`.

## LLM Wiki (`wiki/`)

`wiki/` is an LLM-maintained knowledge base following [Karpathy's LLM Wiki pattern](https://gist.github.com/karpathy/442a6bf555914893e9891c11519de94f). Three layers: **raw sources** (the code, `docs/current/`, git/PR history — never restate them wholesale), **the wiki** (synthesized pages you own and maintain), and **this schema**.

Operations:
- **Ingest** — after significant work (a review, a design decision, a release), update the affected pages in one pass: revise content, fix cross-references, add new pages if a concept earned one. Always update `wiki/index.md` (every page must be listed with a one-line summary) and append to `wiki/log.md` (`## [YYYY-MM-DD] operation | Title`).
- **Query** — when researching project history or rationale, consult `wiki/index.md` first before grepping the codebase.
- **Lint** — periodically check for contradictions with current code, stale claims, orphaned pages, and missing cross-references.

Conventions: English only (the wiki is working memory, exempt from the `.ko.md` pairing rule); Obsidian-style `[[page-name]]` wikilinks; one concept per page; frontmatter with `updated` and `tags`; cite repo paths and risk IDs rather than duplicating their content; never store secrets, PII, or payload values. The wiki is not published to npm (not in the `files` allowlist).

## Git workflow

Follow `CONTRIBUTING.md`: branch off `main` with a type prefix (`feature/`, `fix/`, `docs/`, `chore/`, `release/`, `hotfix/`) — never personal-name prefixes. Commits use one-line imperative English subjects; non-trivial changes include Lore-style decision trailers when useful. Do not add attribution or generated-by footers (no `Co-Authored-By`). PRs target `main`, English body with Summary/Verification sections, no generated-with footers. Documentation is English-main with Korean `*.ko.md` siblings — update both.

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

### Packages (core directory modules) and satellites (workspaces)

`packages/*/index.mjs` are the **core** `haechi` package — wired together purely through the `exports` map in `package.json` and direct relative imports, not as separate npm packages. **Satellites** under `satellites/*` (e.g. `haechi-crypto-kms`) ARE separate published packages: the repo is an npm workspaces monorepo (`"workspaces": [".", "satellites/*"]` — the `"."` self-entry symlinks `node_modules/haechi → repo root` so satellites resolve core by name like `haechi/crypto`). Satellites declare `peerDependencies: { haechi: ">=0.8.0 <1.0.0" }` (consumer contract) plus `devDependencies: { haechi: "*" }` (local-workspace link). Core stays zero runtime dependency; `npm run check:packaging` gates that no satellite file or runtime dep leaks into the `haechi` tarball.

- `core` — `protectJson` orchestrator + payload tree walk/transform.
- `cli` — `bin/haechi.mjs` (command dispatch) and `runtime.mjs` (composition root, config schema).
- `filter` — default detection rules (email, KR phone, KR RRN, card/Luhn, US SSN, IBAN, JP My Number, FR NIR, ES DNI/NIE, UK NINO, IT codice fiscale, SG NRIC/FIN, IN Aadhaar, DE Steuer-ID, NL BSN, bearer tokens, plus a broad cloud/SaaS credential set: AWS access-key id (AKIA/ASIA), GitHub (gh[pousr]_), Google API key (AIza) + Google OAuth client secret (GOCSPX-), Slack (xox[baprs]-), OpenAI (`sk-`/`sk-proj-`, **hyphen**) + Anthropic (`sk-ant-`), Stripe/OpenAI-platform (`sk_`/`rk_`/`pk_`, **underscore**), SendGrid (`SG.<22>.<43>`), Twilio (`AC`/`SK`+32 hex), npm (`npm_`+36), JWT, PEM private-key armor, and an assignment-secret vocab whose `accountkey`/`auth_token` entries catch the Azure Storage `AccountKey=` connection-string segment and the bare Twilio auth token — each provider is anchored on prefix + charclass + length so random base62 never false-fires; an un-anchored 88-char-base64 Azure rule is deliberately NOT added) + custom rule support. `HARD_BLOCK_TYPES` (the precision dials `filters.minConfidence`/`filters.allowlist` can never suppress these) = `secret`, `api_key`, `kr_rrn`, `card`, plus the **strong-anchored national IDs** `fr_nir` (97-control key over a 15-digit structured run, Corsica 2A/2B→19/18), `es_dni` (mod-23 check letter + required letter suffix, NIE X/Y/Z→0/1/2), `it_codice_fiscale` (16-char mixed alpha+digit + mod-26 check char) and `sg_nric` (letter prefix + weighted-sum check letter) — strong NON-numeric anchors over rare shapes, so a match is effectively a true positive. The **hard-block decision is DATA-DRIVEN** (collision rate brute-forced over ~200k random same-shaped values): a type joins `HARD_BLOCK_TYPES` only when it has a non-numeric structural anchor OR a very low collision rate over a rare shape. `jp_mynumber` (mod-11, ~9% collision over a common 12-digit shape), `uk_nino` (no checksum), `in_aadhaar` (Verhoeff, ~9.9% over 12 digits — the same jp_mynumber footgun), `de_steuer_id` (MOD 11,10 + structural test, ~0.37% but a bare 11-digit run with NO non-numeric anchor over a common length) and `nl_bsn` (11-proef, ~9.1% over 9 very-common digits) are deliberately **dial-eligible** (a bare-digit shape over a common length carries enough FP surface that an operator needs the allowlist escape hatch; they still detect + block by default).
- `policy` — `PRESETS`, action validation, and `ACTION_STRENGTH` ordering (the strongest action wins when multiple apply).
- `crypto` — local AES-256-GCM provider over a software key file. No production key provider exists.
- `audit` — JSONL sink with **sha256 hash chaining** for tamper evidence. `FORBIDDEN_KEYS` enforces that raw plaintext/prompt/secret values never get written. `audit.anchor` writes the chain head to a separate append-only stream so `verifyAuditChain(path,{anchorPath})` detects tail truncation (real defense needs separate/append-only media).
- `token-vault` — local tokenization store with reveal **governance** (`revealPolicy: disabled | local-dev`) and retention.
- `proxy` — local HTTP JSON proxy fronting an upstream LLM endpoint.
- `protocol-adapters` — request classification per `target.type` (`openai-compatible`, `vllm-openai`, `ollama`, llama.cpp, `anthropic`, `gemini`); a specific type wins over a default-merged `adapter`. Streaming routes carry `{ format, deltaPath }`. `matchRoute` tries EXACT pathname match first (unchanged for openai/anthropic/ollama/llama-cpp), then ADDITIVELY tries `:method`-SUFFIX routes (a route with `methodSuffix:"generateContent"` matches when the pathname ends with `:generateContent`). The `anthropic` adapter routes the Messages API (`/v1/messages` → `messages`, streaming `delta.text` in `content_block_delta` frames; `/v1/messages/count_tokens`; `/v1/complete` → legacy `completion` delta). The `gemini` adapter routes the Google Gemini API by `:method` suffix (model-in-path, `/v1` or `/v1beta` prefix, arbitrary `{model}`): `:generateContent` → `generate-content`; `:streamGenerateContent` → `stream-generate-content` (data-only SSE, `streamingDefault:true` since the endpoint always streams, deltaPath `candidates[0].content.parts[0].text`, no flushOnType); `:countTokens`; `:embedContent`/`:batchEmbedContents`. The client supplies Gemini's `x-goog-api-key` (or `?key=`) and the proxy forwards it.
- `stream-filter` — SSE/NDJSON frame parsing + bounded sliding-buffer inspection of streaming responses (`createStreamProtector` lives in `core`).
- `auth` — `authProvider` contract + built-in bearer provider + token store (keyed-HMAC hashes) + PII-safe `buildIdentity`.
- `mcp-stdio` — JSON-RPC 2.0 line filter for MCP stdio traffic (method allowlist + param/result protection).
- `policy-bundle` — sign/verify signed policy bundles.
- `plugin` — plugin manifest validation.
- `privacy-profiles` — regional default-action profiles (`kr-pipa`, `eu-gdpr`, `asia-pdpa`, `us-general`, `jp-appi`) applied before enforcement (strengthen-only). `eu-gdpr` blocks the EU national IDs (`fr_nir`/`es_dni`/`uk_nino`/`it_codice_fiscale`/`de_steuer_id`/`nl_bsn`); `asia-pdpa` (Singapore PDPA / India DPDP) blocks `sg_nric`/`in_aadhaar` (plus the other checksummed national IDs for mixed-region payloads); `jp-appi` is the JP home for `jp_mynumber`, which every profile blocks.

### CLI surface

`packages/cli/bin/haechi.mjs` dispatches: `init`, `protect`, `report`, `status`, `audit-verify`, `proxy`, `policy-sign`, `policy-verify`, `token-reveal`, `token-purge`, `token-export`, `plugin-validate`, `mcp-stdio`, `mcp-wrap`, `auth`, `config`. `help [command]`/`config` print usage; per-command metadata lives in `COMMAND_HELP`. The full config reference is `docs/current/configuration.md` (keep in sync with the `normalizeConfig` schema and `haechi config` output).

## Security invariants (do not regress these)

These are load-bearing behaviors enforced by tests and documented in `docs/current/threat-model.md` / `risk-register-release-gate.md`:

- **Fail closed.** Unknown/invalid policy or config throws in enforcement paths (including unknown `target.type`). Response protection fails closed for non-JSON, invalid JSON, compressed, or oversized responses unless explicitly allowed.
- **No plaintext in audit.** Audit events must never contain raw prompt, tool-result, secret, or PII values — `FORBIDDEN_KEYS` in `packages/audit/index.mjs` guards this.
- **Loopback bind by default.** The proxy refuses to bind `0.0.0.0` / `::` / non-loopback hosts unless `--allow-remote-bind` is passed (`assertSafeProxyBind`).
- **Streaming is blocked by default.** `stream: true` requests return 501 unless `streaming.requestMode` is explicitly `pass-through`. Ollama `/api/chat` and `/api/generate` default to streaming, so they are treated as streaming unless the request sets `stream: false` (`streamingDefault` in protocol adapters).
- **Token reveal is governed and audited.** Revealing tokenized values is gated by `tokenVault.revealPolicy`, and reveal/purge decisions are written to the audit log (token ids only, never plaintext). Expired tokens are pruned on vault mutations.
- **Policies only get stronger.** Preset/action merges reject weakening (`ACTION_STRENGTH`), and privacy profiles may strengthen but never weaken an explicit user action.
- **Key rotation preserves old keys.** `initLocalKeyFile --force` retires (not deletes) prior keys; `decrypt` selects keys by envelope `kid`. Policy-bundle signing uses a domain-separated key derived from the stored key, never the raw AES key.
- **Detection covers values, JSON numbers, and object keys, and folds Unicode evasion (NFKC).** Each string leaf is NFKC-normalized before matching (`detectEntry`, WS2d), so full-width/mathematical/confusable forms (`４２４２…`, full-width `＠`) can't slip past the regex rules. Offset integrity is load-bearing: detections carry `{start,end}` into `entry.value` but `transformString` slices the ORIGINAL string, so the three cases are (1) **NFKC no-op** → detect on the original, byte-identical to before; (2) **position-stable fold** (every codepoint folds to the same UTF-16 length AND the per-codepoint folds reconstruct the whole normalization) → detect on the normalized copy, offsets stay valid on the original (exact-span redaction; the recorded `value` is the ORIGINAL slice, never the fold); (3) **offset-shifting fold** — a length change (mathematical digits/ligatures) OR a compensating contraction+expansion that keeps total length equal but shifts interior offsets — → offsets can't map back, so **fail closed** to ONE whole-leaf detection (`start:0,end:value.length`) that redacts/blocks the entire leaf. A bare total-length check is unsound (the compensating case redacts the wrong bytes), so the gate is per-codepoint. Validators (Luhn/RRN) run on the normalized match text. Base64/percent-encoded values are decoded-and-rescanned only behind the opt-in `filters.decodeAndRescan` (default off; `decodeAndRescanEntry` in `packages/filter`): when on, a leaf that looks base64/base64url (anchored alphabet, valid length, round-trips, decodes to valid UTF-8 via `node:buffer` `isUtf8`) or carries a `%XX` escape (`decodeURIComponent`) is decoded and rescanned, and a decoded hit fails closed to a WHOLE-LEAF detection (it has no offset in the encoded leaf) — gated by a precision guard so only a validator-backed / hard-block hit fires (random base64 never false-positives). URL query strings remain a documented exclusion (see threat model). On the **response direction only**, two metadata-shaped false-positive sources are skipped (request-direction is always full-scan, so neither weakens inbound protection): (1) Haechi's own transform markers (`[TOKEN:…]`, `[HAECHI_ENC:…]`, `[REDACTED:…]`) — ASCII/NFKC-stable, computed on the original — so a tokenized round-trip echoed by the model isn't re-flagged as a secret; (2) bare JSON **number** leaves (`entry.kind === "number"`) — an inference-server `*_duration`/count/numeric-id/timestamp is never a model-leaked card/RRN, and a model leak lands in generated *text* (string leaves), which are still inspected. The KR phone rule also rejects a bare, separator-less digit run that doesn't start with the trunk `0` (so a unix timestamp / id isn't a "phone").
- **External key custody is contract-only in core.** `keys.provider: external` requires an injected `cryptoProvider` (encrypt/decrypt always; hmac for tokens/auth — `createRuntime` fails closed when a needing feature is set without it). Validate adapters with `assertCryptoProviderConformance`; the `haechi-crypto-kms` satellite lives at `satellites/crypto-kms/` (a workspace package published independently, importing `canonicalize` from `haechi/crypto`). Heavy KMS deps stay out of core.
- **Auth gates before the body is read.** When `auth.provider` is bearer/external the proxy authenticates, resolves a named policy profile (scope→label→fail-closed default), and rate-limits before reading the body; `none` keeps identity null. Tokens are stored only as keyed-HMAC hashes; identity subject/issuer are keyed HMAC — never raw values in the audit log. The per-request `policyEngine` is a control object and must never enter the protect *context* (it pollutes tokenize AAD).
- **Streaming inspection is bounded and opt-in.** `streaming.requestMode: "inspect"` stream-filters SSE/NDJSON with a sliding buffer; cross-frame matches are caught up to `streaming.maxMatchBytes`. Bytes already emitted before a `block` cannot be retracted. New adapter streaming routes must declare `{ format, deltaPath }`. SSE re-serialization PRESERVES each frame's non-`data:` field lines (`event:`/`id:`/`retry:`/comments) so event-typed streams (Anthropic Messages, which dispatch on `event:`) stay consumable — OpenAI data-only frames are byte-identical. The held sliding-buffer tail is flushed as a clone of the last delta-bearing frame (valid structure + `event:` line), not a bare object; a descriptor may set `flushOnType: { path, values }` to flush that tail BEFORE a delta-terminating frame (Anthropic's `content_block_stop`/`message_delta`/`message_stop`) so the residual is ordered correctly — keepalives (`ping`) are deliberately omitted so a match split across one is still caught.
- **Detokenization is request-scoped and opt-in.** `detokenizeResponses` restores only tokens issued while protecting the same request; it is independent of `revealPolicy` and audited by count. Deterministic tokens use the `haechi:token-vault:deterministic:v1` derived key.
- **Injection detection is report-only by default.** The `injection` type runs only on the response/tool-result direction and pins action `allow` unless explicitly escalated — never make it block by default.
- **Caller-supplied identity is keyed-hashed, never raw (historical: `identity` was hard null until 0.6).** Audit events carry `subjectHash`/`issuerHash` (keyed HMAC, `haechi:identity:hash:v1`), never raw subject/issuer. Bearer auth builds it via `buildIdentity`; external providers (the `haechi-auth-jwt` satellite, 0.8+) build it via the core-owned `buildExternalIdentity` — satellites supply raw claims but the keyed-hash construction and domain stay in `packages/auth`.

When changing publishable behavior, keep `docs/current/` scope docs and the README's "Current Scope" section in sync; release gating lives in `docs/current/risk-register-release-gate.md` and `scripts/release-preflight.mjs`.
