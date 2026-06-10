---
updated: 2026-06-10
tags: [concept, security, gap]
---

# Streaming Protection Gap

Haechi 0.3.x cannot inspect SSE/NDJSON streams, so streaming is treated as an uninspectable channel and blocked by default ([[fail-closed]]).

## Current behavior

- `stream: true` requests → 501 `haechi_streaming_unsupported` unless `streaming.requestMode: "pass-through"` is explicitly set (bypass is audited).
- **The Ollama trap (P0-SEC-016):** Ollama `/api/chat` and `/api/generate` stream *by default* when `stream` is omitted. Before 0.3.2 this silently bypassed the block. Protocol adapters now carry `streamingDefault: true` for those routes, and the proxy treats `stream !== false` as streaming there. Any new adapter route must declare its streaming default — this is the regression to watch for.

## Why not inspect streams now

Chunk-boundary matching, partial-JSON deltas, tool-call fragments, and backpressure make stream inspection a release-sized feature, not a patch. It was deliberately cut from 0.4 and is the headline feature of 0.5 ([[release-roadmap]]).

## 0.5 sketch

Sliding-overlap buffer scanning over SSE/NDJSON frames (reusing the string-level detect/transform from [[protect-pipeline]]), stream sequence AAD, and a replay cache. Until then, the honest options are: block (default), or pass-through with the caller accepting unprotected streaming.
