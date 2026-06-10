---
updated: 2026-06-11
tags: [review, validation, real-environment]
---

# Real-Environment Validation (2026-06-11)

First validation of the proxy against **real self-hosted inference backends** (advances the 1.0 "real-environment validation" exit criterion). Two adapters exercised live.

## Backends

- **vLLM** `Qwen/Qwen3.6-35B-A3B-FP8` @ `10.0.0.50:8000` — adapter `vllm-openai`, OpenAI-compatible `/v1/chat/completions`.
- **Ollama** (`qwen-fast`, `qwen3.6:35b`, …) @ `10.0.1.55:11434` — adapter `ollama`, native `/api/chat`.

## What passed

| Behaviour | vLLM | Ollama |
|---|---|---|
| Protect-then-forward (email → tokenize) | ✅ 200, model receives `[TOKEN:…]` (echo-proven) | ✅ 200, audit `email:tokenize` |
| Block action (card) | ✅ 403 `haechi_policy_block`, not forwarded | ✅ 403 |
| Implicit-streaming fail-closed | n/a | ✅ `/api/chat` without `stream:false` → **501** (the Ollama-streaming invariant, live) |
| No plaintext in audit | ✅ | ✅ |
| Transparent token round-trip (`detokenizeResponses`) | ✅ model sees token, **caller gets the original back** | (echo refused by model; pipeline proven by audit) |

Echo proof (vLLM): with thinking disabled, the model returned `please email [TOKEN:tok_email_…] today` — it never saw the raw address.

## Findings (and what shipped)

1. **Response-direction false positives (FIXED).** With `responseProtection: enforce`, real responses were 502-blocked because (a) the unix-timestamp `created` (10-digit) matched the **phone** rule, and (b) the echoed `[TOKEN:…]` matched the **secret** rule (`TOKEN:` reads like a `token:<secret>` assignment) — Haechi blocking its own token. Fixes in `packages/filter/index.mjs`: the KR phone rule rejects bare separator-less non-`0`-led digit runs; detection skips Haechi's own markers **on the response direction only** (request-side stays full-scan so a fake marker can't smuggle a secret). After the fix the round-trip works under `enforce` (verified live: caller gets the restored email, no 502). See [[protect-pipeline]].
2. **Config ergonomics.** `detokenizeResponses` / `deterministic` live under `tokenVault` and `detokenizeResponses` needs `responseProtection.enabled` (already documented; mis-nesting them silently no-ops). For real upstreams, `responseProtection.mode: report-only` avoids the metadata false-positive class while still detecting/auditing/detokenizing — now recommended in `configuration.md` and the threat model.
3. **Residual.** A Luhn-passing long numeric field can still match `card` on the response (documented limitation; `report-only` sidesteps it).
4. **Test-harness notes (not Haechi):** Qwen3.6 thinking spends the token budget on reasoning → empty `content` at low `max_tokens` (disable thinking / raise the budget for echo checks); some Ollama models refuse verbatim-repeat prompts → the audit log is the authoritative proof.

## Status

Core security behaviours validated on both real adapters. The false-positive fix is committed with unit tests (`tests/filter.test.mjs`: marker-not-re-detected, request-side-no-bypass, phone-ignores-timestamps).
