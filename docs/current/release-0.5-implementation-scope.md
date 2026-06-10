# Haechi 0.5 Implementation Scope

- Status: Final
- Date: 2026-06-10
- Target version: 0.5.0 (after 0.4.0)
- Type: streaming hardening
- Shipped: 2026-06-10 — PR #14 (streaming inspection)

## 1. Release Goal

Close the streaming protection gap: inspect SSE/NDJSON response streams instead of only blocking them or passing them through unprotected. Streaming is the common transport for real LLM usage, so "use streaming and give up protection" was the main remaining hole.

## 2. Scope

### 2.1 Streaming response inspection

- New `streaming.requestMode: "inspect"` (alongside `block` and `pass-through`).
- `packages/stream-filter`: incremental frame parser for two wire formats — SSE (`data: …\n\n`) and NDJSON (`{…}\n`). `[DONE]`, keep-alive comments, and non-JSON frames pass through verbatim.
- Each protocol-adapter streaming route declares `{ format, deltaPath }`: the primary incremental-text channel.
  - OpenAI-compatible / vLLM / llama.cpp chat-completions: SSE, `choices[0].delta.content`
  - completions: SSE, `choices[0].text`
  - llama.cpp `/completion`: SSE, `content`
  - Ollama `/api/chat`: NDJSON, `message.content`
  - Ollama `/api/generate`: NDJSON, `response`
  - OpenAI `/v1/responses`: SSE, no fixed delta path (whole-frame protection only)

### 2.2 Cross-frame correctness (sliding buffer)

Streamed bytes cannot be retracted, so detection must happen before a value is emitted. `core` gains `createStreamProtector`, a stateful protector that:

- Holds a bounded **raw tail** of the delta channel. On each push it detects on the accumulated pending text, computes a commit point of `len - maxMatchBytes`, and pulls the commit point back before any detection that straddles it. Only the committed prefix is transformed and emitted; the tail is held for the next frame.
- Flushes the held tail as a synthesized final frame at end of stream.
- Runs `protectFrameExtras` for all other string leaves of a frame (tool-call arguments, etc.) with within-frame protection.
- `streaming.maxMatchBytes` (default 256) **bounds the guarantee**: a single match longer than the window may still split across frames. Documented limitation.

### 2.3 Enforcement and audit

- The request body of a streaming call is ordinary JSON and is protected like any request before forwarding.
- `block` actions stop the stream before the offending value is emitted (held in the buffer, never committed); the connection is ended. Bytes already emitted cannot be retracted — a documented limit of streaming.
- The whole stream is audited once: `stream_inspected` or `stream_blocked`, with aggregate detection counts only (no plaintext). `identity: null` reserved as elsewhere.
- New `streaming.responseMode` (`dry-run` | `report-only` | `enforce`, default `enforce`) controls the response-direction enforcement mode independently.

### 2.4 Adapter routing fix

A specific `target.type` (`ollama`, `vllm-openai`, `llama-cpp`) now takes precedence over a deep-merged default `target.adapter` (`openai-compatible`). Previously a config that set only `target.type: "ollama"` was silently routed to OpenAI paths because the default adapter survived the merge — which also defeated streaming classification.

## 3. Explicit non-scope (not in 0.5)

- Stream sequence AAD and replay cache (deferred; relevant once encryption-on-stream is needed).
- Per-choice (`n > 1`) cross-frame buffering — secondary choices get within-frame protection only.
- Decoding base64/encoded values inside streams (same exclusion as non-streaming).
- Bidirectional streaming for MCP (the stdio filter is line-framed JSON-RPC, already handled).

## 4. Test criteria

- Within-frame and cross-frame (including byte-by-byte split) PII caught in both SSE and NDJSON.
- `[DONE]` / keep-alive / non-JSON frames preserved.
- Non-delta PII (tool-call args) protected within-frame.
- `block` stops the stream before emitting the value; `report-only` detects without transforming.
- Proxy e2e: request protected, response stream-filtered, audit chain valid, no plaintext in audit.
- Uninspectable route under `inspect` fails closed (501).
- Config validation for `requestMode: inspect`, `responseMode`, `maxMatchBytes`.

## 5. Documentation impact

- README: streaming inspection section, config reference rows, `configuration.md` updates.
- threat-model: streaming moves from "uninspectable, blocked" to "inspected (bounded)"; the `maxMatchBytes` limit and emitted-bytes-on-block limit are documented exclusions.
- risk-register: 0.5.0 backlog row checked off.
- api-stability: `haechi/stream-filter` and `createStreamProtector` marked experimental.
