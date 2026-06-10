---
updated: 2026-06-10
tags: [concept, security, gap]
---

# Streaming Protection (0.5 — was a gap)

Through 0.4 Haechi could not inspect SSE/NDJSON streams, so streaming was treated as uninspectable and blocked by default. **0.5.0 closed this** with `streaming.requestMode: "inspect"` ([[release-roadmap]]). This page now records the design that shipped.

## Current behavior

- `stream: true` requests → 501 `haechi_streaming_unsupported` unless `streaming.requestMode: "pass-through"` is explicitly set (bypass is audited).
- **The Ollama trap (P0-SEC-016):** Ollama `/api/chat` and `/api/generate` stream *by default* when `stream` is omitted. Before 0.3.2 this silently bypassed the block. Protocol adapters now carry `streamingDefault: true` for those routes, and the proxy treats `stream !== false` as streaming there. Any new adapter route must declare its streaming default — this is the regression to watch for.

## How 0.5 inspection works

`packages/stream-filter` parses SSE (`data: …\n\n`) and NDJSON (`{…}\n`) frames incrementally. Each adapter streaming route declares `{ format, deltaPath }` (the incremental-text channel). `core`'s `createStreamProtector` holds a bounded raw tail of the delta channel (`streaming.maxMatchBytes`, default 256): on each push it detects on the pending text, commits everything up to `len - maxMatchBytes` (pulled back before any straddling detection), transforms and emits the committed prefix, and holds the rest — so a match split across frames (even byte-by-byte) is caught before the leading part leaves. Non-delta string leaves (tool-call args) get within-frame protection; the stream is audited once (`stream_inspected`/`stream_blocked`).

## Remaining limits (documented exclusions)

- A single match longer than `maxMatchBytes` may still split across frames.
- Bytes already emitted before a `block` fires cannot be retracted (the blocked value itself is held in the buffer, so it does not leak — but earlier frames are already gone).
- `n > 1` streaming choices: only the primary channel gets cross-frame buffering; others get within-frame protection.
- Stream sequence AAD and replay cache are deferred to 0.6+ (relevant when encrypting stream segments).
