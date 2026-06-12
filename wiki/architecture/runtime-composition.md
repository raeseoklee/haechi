---
updated: 2026-06-10
tags: [architecture, extensibility]
---

# Runtime Composition

`createRuntime(config, providers)` in `packages/cli/runtime.mjs` is the composition root. It normalizes config (deep-merge over `defaultConfig()` + strict fail-closed validation) and wires six collaborators: `filterEngine`, `policyEngine`, `cryptoProvider`, `auditSink`, `tokenVault`, `protocolAdapter`.

## Provider injection is THE extension seam

Every collaborator can be replaced via the `providers` argument. This is deliberate strategy, not convenience:

- `keys.provider: "external"` **requires** injecting a `cryptoProvider` — there is no production KMS/HSM adapter in core, so external key custody composes in rather than ships in.
- The future `authProvider` ([[identity-and-auth]]) follows the same pattern.
- **Dynamic npm loading of providers is prohibited until the 1.0 plugin sandbox** ([[release-roadmap]]); only programmatic injection is allowed. This keeps the manifest-only plugin gate (P1-SEC-004) honest.

## Ordering constraint

`auditSink` is constructed **before** `tokenVault` because the vault records reveal/purge decisions to the audit log (added in 0.3.2, P1-SEC-017).

## Config coupling

When changing config shape, three places must move together: `defaultConfig()`, `normalizeConfig()` validation, and `haechi.config.example.json`. The proxy port default (11016, `DEFAULT_PROXY_PORT`) lives in `packages/proxy/index.mjs` and is imported by runtime.
