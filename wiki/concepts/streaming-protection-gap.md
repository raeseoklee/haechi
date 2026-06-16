---
updated: 2026-06-16
tags: [concept, security, gap]
---

# Streaming Protection (0.5 — was a gap)

Through 0.4 Haechi could not inspect SSE/NDJSON streams, so streaming was treated as uninspectable and blocked by default. **0.5.0 closed this** with `streaming.requestMode: "inspect"` ([[release-roadmap]]). This page now records the design that shipped.

## Current behavior

- `stream: true` requests → 501 `haechi_streaming_unsupported` unless `streaming.requestMode: "pass-through"` is explicitly set (bypass is audited).
- **The Ollama trap (P0-SEC-016):** Ollama `/api/chat` and `/api/generate` stream *by default* when `stream` is omitted. Before 0.3.2 this silently bypassed the block. Protocol adapters now carry `streamingDefault: true` for those routes, and the proxy treats `stream !== false` as streaming there. Any new adapter route must declare its streaming default — this is the regression to watch for.

## How 0.5 inspection works

`packages/stream-filter` parses SSE (`data: …\n\n`) and NDJSON (`{…}\n`) frames incrementally. Each adapter streaming route declares `{ format, deltaPath }` (the incremental-text channel). `core`'s `createStreamProtector` holds a bounded raw tail of the delta channel (`streaming.maxMatchBytes`, default 256): on each push it detects on the pending text, commits everything up to `len - maxMatchBytes` (pulled back before any straddling detection), transforms and emits the committed prefix, and holds the rest — so a match split across frames (even byte-by-byte) is caught before the leading part leaves. Non-delta string leaves (tool-call args) get within-frame protection; the stream is audited once (`stream_inspected`/`stream_blocked`).

### Non-JSON CONTENT frames (P1-CR-005, toward 1.3.1)

A frame whose `data:` payload does not `JSON.parse` is NOT raw-passed. `parseFrame` splits parse-failures into a **CONTROL allowlist** (the `[DONE]` sentinel, comment-only `:` frames, empty/whitespace/keepalive — no inspectable text, passed raw) and a **non-JSON CONTENT frame** (plain text, partial/malformed JSON, provider-specific text). A CONTENT frame is inspected as text via `protector.protectText` (a single-shot reuse of `transformSegment`, **distinct from** the `push`/`flush` cross-frame buffer so it never corrupts the JSON delta sliding-buffer state), re-emitted as `data: <protected text>` (`serializeTextFrame`, preserving `event:`/`id:`/`:` lines and multi-line `data:` shape), and fails the stream closed on a block-action detection. The response-direction marker skip is preserved, so a tokenized round-trip echoed by the model is not re-flagged. Per-frame text inspection closes the bypass; cross-frame buffering of *arbitrary* non-JSON frames is out of scope (the JSON delta channel keeps its own buffer). P2-CR-013 fixed the SSE multi-line `data:` join to `\n` (spec separator), so multi-line JSON still parses and multi-line text keeps its newlines.

## Remaining limits (documented exclusions)

- A single match longer than `maxMatchBytes` may still split across frames.
- Bytes already emitted before a `block` fires cannot be retracted (the blocked value itself is held in the buffer, so it does not leak — but earlier frames are already gone).
- `n > 1` streaming choices: only the primary channel gets cross-frame buffering; others get within-frame protection.
- Stream sequence AAD and replay cache are deferred to 0.6+ (relevant when encrypting stream segments).
