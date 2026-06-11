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

## Auth + per-client controls (2026-06-11, live vs real vLLM)

The 0.6 auth stack and the `haechi-auth-jwt` satellite, validated end-to-end in front of the real vLLM. (Auth/profile/allowlist/rate run in the proxy gate *before* forwarding, so they are upstream-agnostic — Ollama takes the identical path.)

| Behaviour | Result |
|---|---|
| Bearer auth gate (built-in) | no token / bad token → **401** before body read; valid token → **200** forwarded |
| Named policy profile (`profileBinding` scope→profile) | `team:eng`→`eng`, `tier:limited`→`limited` resolved per identity |
| Model allowlist | `eng` allows only the real model → a `gpt-4` request → **403** `model_not_allowed` |
| Per-identity rate limit (`rate.requestsPerMinute: 2`) | req 1–2 → 200, req 3–4 → **429** `rate_limited` (exactly bounded) |
| KR-PII | KR phone+email → **tokenize**+forward (200); a checksum-valid KR **RRN** → **403** block |
| Audit decisions | `auth_denied`, `model_not_allowed`, `rate_limited` recorded; **no raw phone/email/RRN/subject** in the log |
| **`haechi-auth-jwt`** (RS256, stubbed JWKS, external injection) | no/garbage/expired JWT → **401**; a valid RS256 JWT → **200** forwarded to vLLM, with a **PII-safe identity** (`provider:"jwt"`, keyed-HMAC `subjectHash`, non-PII `id`, raw `sub` never in audit) |

## Findings (and what shipped)

1. **Response-direction false positives (FIXED).** With `responseProtection: enforce`, real responses were 502-blocked because (a) the unix-timestamp `created` (10-digit) matched the **phone** rule, and (b) the echoed `[TOKEN:…]` matched the **secret** rule (`TOKEN:` reads like a `token:<secret>` assignment) — Haechi blocking its own token. Fixes in `packages/filter/index.mjs`: the KR phone rule rejects bare separator-less non-`0`-led digit runs; detection skips Haechi's own markers **on the response direction only** (request-side stays full-scan so a fake marker can't smuggle a secret). After the fix the round-trip works under `enforce` (verified live: caller gets the restored email, no 502). See [[protect-pipeline]].
2. **Config ergonomics.** `detokenizeResponses` / `deterministic` live under `tokenVault` and `detokenizeResponses` needs `responseProtection.enabled` (already documented; mis-nesting them silently no-ops). For real upstreams, `responseProtection.mode: report-only` avoids the metadata false-positive class while still detecting/auditing/detokenizing — now recommended in `configuration.md` and the threat model.
3. **Card/RRN on response number leaves (FIXED, follow-up).** A long Luhn-passing `*_duration`/count (Ollama emits nanosecond durations) could match `card` (or a 13-digit one `kr_rrn`). The **response direction no longer scans bare JSON number leaves** (`entry.kind === "number"`) — they are inference-server metadata; a model leak lands in generated *text* (string leaves, still scanned), including stringified-JSON. Request-direction number scanning is unchanged. A strict deployment can opt back in with `responseProtection.scanNumbers: true` (threaded as `context.scanNumbers`); the accepted residual is a hostile model exfiltrating a value as a bare response number (secondary defense). Validated by running the **captured real** vLLM + Ollama responses through detection (**zero** detections) and the live round-trip (200 under `enforce`).
4. **Test-harness notes (not Haechi):** Qwen3.6 thinking spends the token budget on reasoning → empty `content` at low `max_tokens` (disable thinking / raise the budget for echo checks); some Ollama models refuse verbatim-repeat prompts → the audit log is the authoritative proof.

## Status

Core security behaviours validated on both real adapters; the auth stack (bearer + named profiles + model allowlist + per-identity rate limit) and the `haechi-auth-jwt` satellite validated end-to-end in front of the real vLLM. The false-positive fix is committed with unit tests (`tests/filter.test.mjs`). No bugs found in the auth/JWT/KR-PII pass — those tests passed as-is, so this section is a validation record (no code change).
