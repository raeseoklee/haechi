# Local end-to-end demo

A self-contained, **reproducible** walkthrough of Haechi — no remote model required.
It stands up a tiny OpenAI-compatible *stub* upstream and the **real** Haechi proxy
in front of it (in `enforce` mode), then narrates what happens to a payload carrying
an email, a phone number, an API key, and a card number.

```bash
node examples/local-proxy-demo/demo.mjs
# or, from the repo root:
npm run demo
```

What it shows, in order:

1. **The model only sees protected values** — the proxy detects and transforms the
   payload *before* forwarding, so the stub (standing in for the model) receives
   `[TOKEN:…]` for the email, a masked phone, and `[REDACTED:api_key]` for the key.
2. **The token round-trip** — because the email was *tokenized* (reversible), the
   caller gets `minji.kim@example.com` back, while the masked phone and redacted
   secret stay protected. The model's own leaked secret in its reply is
   response-protected too.
3. **The audit log** carries detection metadata and is hash-chained — and never any
   plaintext email/phone/key.
4. **Day-2 operability** — the live `/__haechi/ready` readiness probe and the
   Prometheus `/__haechi/metrics` surface.
5. **A card number is blocked outright** (`403`, fail-closed) — it never reaches the
   model.

Zero dependencies (only `node:` builtins + the in-repo `haechi` packages). The demo
is programmatic for reproducibility; for the real CLI invocation see the
[Quickstart](../../README.md#quickstart) and
[`docs/current/configuration.md`](../../docs/current/configuration.md).

## Live demo against a real model

`live-demo.mjs` runs the same flow against a **real** upstream (vLLM / Ollama / any
OpenAI-compatible server) instead of the stub. It asks the model to repeat the phone
number it was given — and the model can only return the *masked* form, because the
real number never reached it. This is the run recorded in the README GIF
(`demo.tape` records the stub demo; `live-demo.tape` records this one).

```bash
HAECHI_LIVE_UPSTREAM=http://127.0.0.1:8000 \
HAECHI_LIVE_MODEL="Qwen/Qwen3.6-35B-A3B-FP8" \
node examples/local-proxy-demo/live-demo.mjs
```

`HAECHI_LIVE_TYPE` (default `vllm-openai`) and `HAECHI_LIVE_MODEL` override the target.
For Qwen3-style reasoning servers the request sets `chat_template_kwargs.enable_thinking
= false` so the reply is a terse line; non-reasoning servers ignore it.
