# Haechi LLM Wiki — Index

LLM-maintained knowledge base for the Haechi project, following the [LLM Wiki pattern](https://gist.github.com/karpathy/442a6bf555914893e9891c11519de94f). Raw sources are the codebase, `docs/current/`, and git/PR history; this wiki is the synthesized layer on top. Schema and operations are defined in `CLAUDE.md` (section "LLM Wiki").

Every page must be listed here with a one-line summary. Update this index on every ingest.

## Architecture

- [[protect-pipeline]] — the `protectJson` detect→decide→transform→audit flow and how enforcement modes gate it
- [[runtime-composition]] — `createRuntime` as composition root; provider injection as the extension seam

## Concepts

- [[fail-closed]] — the project's central design philosophy and every place it is enforced
- [[token-vault]] — tokenization storage, reveal governance, retention, and audit trail
- [[audit-integrity]] — JSONL hash chain, sanitization, locking, and the tail-truncation limitation
- [[key-management]] — key file format, kid-based rotation, and domain-separated key derivation
- [[streaming-protection-gap]] — streaming inspection (0.5), the Ollama implicit-streaming trap, and non-JSON CONTENT-frame text inspection (P1-CR-005)
- [[dashboard-audit-viewer]] — the zero-dep read-only audit viewer satellite and its security model (loopback/Host-allowlist/CSP/sessionGuard seam)
- [[oidc-session-broker]] — the interactive OIDC session broker satellite (authorization-code + PKCE, state-first callback, shared JWS verifier, PII-safe audit)
- [[plugin-sandbox]] — the 1.0 signed `authProvider` plugin sandbox: Ed25519 trust gate, worker_threads isolation (honest residual), lifecycle audit, conformance gate
- [[operability-day2]] — WS4 operability: health split + `/metrics` + structured logs/correlationId (WS4-A) and graceful drain + backpressure + tuned timeouts + env overlay + Docker/compose/runbook + configVersion (WS4-B)
- [[trust-assets-ws6]] — WS6 trust assets: proxy TLS / remote-bind hardening (`proxy.tls`/`trustForwardedProto`, fail-closed `assertSafeProxyTransport`, https-vs-http selection, `X-Forwarded-Proto` enforcement) + the security whitepaper, security.txt, SECURITY.md disclosure, and compliance/DSAR mapping

## Decisions

- [[release-roadmap]] — agreed version sequence 0.3.2 → 1.0 with the rationale for each cut
- [[identity-and-auth]] — reserved identity schema, authProvider contract, and the dynamic-loading gate
- [[packaging-and-distribution]] — npm-first distribution, `haechi-*` satellite packages, rejected curl|sh installer

## Reviews

- [[2026-06-10-full-security-review]] — full-codebase security review that produced the 0.3.2 hardening release (16 findings)
- [[2026-06-11-real-environment-validation]] — live proxy validation against real vLLM + Ollama: pipeline, auth (bearer + JWT) + per-client controls + KR-PII; fixed response-direction detection false positives
