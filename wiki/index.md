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
- [[streaming-protection-gap]] — why streaming is blocked today, the Ollama implicit-streaming trap, and the 0.5 plan

## Decisions

- [[release-roadmap]] — agreed version sequence 0.3.2 → 1.0 with the rationale for each cut
- [[identity-and-auth]] — reserved identity schema, authProvider contract, and the dynamic-loading gate
- [[packaging-and-distribution]] — npm-first distribution, `@haechi/*` satellite packages, rejected curl|sh installer

## Reviews

- [[2026-06-10-full-security-review]] — full-codebase security review that produced the 0.3.2 hardening release (16 findings)
