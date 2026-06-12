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
