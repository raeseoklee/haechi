# Haechi Documentation Index

English is the primary documentation language. Korean translations are maintained alongside each document as `*.ko.md`.

## Current

- `docs/current/prd-ai-llm-mcp-encryption.md`: PRD draft for the AI/LLM/MCP-focused encryption solution
- `docs/current/initial-plan-ai-llm-mcp-encryption.md`: initial execution plan and technical hypotheses
- `docs/current/privacy-filtering-policy-draft.md`: privacy filtering policy draft
- `docs/current/global-privacy-compliance-review.md`: global privacy / AI compliance review
- `docs/current/expert-gap-review-ai-llm-mcp-encryption.md`: missing requirements and hardening backlog from parallel expert review
- `docs/current/open-source-modular-architecture.md`: OSS/self-hosted modular architecture with replaceable provider/plugin boundaries (not SaaS)
- `docs/current/mvp-0.1-implementation-scope.md`: MVP 0.1 implementation scope, exclusions, quickstart completion criteria
- `docs/current/release-0.2-implementation-scope.md`: 0.2 TokenVault, signed policy, plugin manifest, MCP stdio scope
- `docs/current/release-0.3-implementation-scope.md`: 0.3 vLLM/Ollama/llama.cpp adapters, response protection, npm publish readiness scope
- `docs/current/release-0.3.2-hardening-scope.md`: 0.3.2 security hardening release; first npm developer preview target
- `docs/current/release-0.4-implementation-scope.md`: 0.4 token round-trip, mcp-wrap, audit-verify/status, identity/authProvider contract reservation
- `docs/current/release-0.5-implementation-scope.md`: 0.5 SSE/NDJSON streaming response inspection with bounded cross-frame buffer
- `docs/current/release-0.6-implementation-scope.md`: 0.6 bearer auth, named policy profiles, model allowlist, rate limiting
- `docs/current/release-0.7-implementation-scope.md`: 0.7 audit anchoring, cryptoProvider contract + reference KMS adapter, signed release artifacts
- `docs/current/configuration.md`: full configuration reference (every key, defaults, validation, presets, common setups)
- `docs/current/risk-register-release-gate.md`: release-blocking risks, security/operational risk status, npm release gates (0.3.2 baseline)
- `docs/current/threat-model.md`: Haechi 0.3.2 trust boundaries, protected assets, key threats and controls
- `docs/current/shared-responsibility.md`: responsibility split between Haechi and users/operators in self-hosted deployments
- `docs/current/api-stability.md`: developer preview API stability and migration note criteria
- `docs/current/release-process.md`: release preflight, SBOM, npm provenance publish procedure

## Direction Change Record

Early drafts (now removed; see git history before this commit) covered a general-purpose modular segment-encryption layer spanning HTTP/HTTPS/socket/gRPC/A2A. The current direction is a specialized protection solution for prompts, context, tool calls, resources, artifacts, and streaming messages across AI, LLM, MCP, A2A, and agent platforms.

Open-source/self-hosted security infrastructure takes priority over commercial SaaS. Current documents therefore center on the self-hosted SDK/CLI/proxy, replaceable `CryptoProvider`, `PolicyEngine`, `FilterEngine`, `KeyProvider`, `AuditSink`, and plugin conformance tests, rather than a hosted control plane.

Adoptability is a core requirement. The targets are a 5-minute local demo, a 30-minute MCP/LLM PoC, and a 1-day custom filter PoC; users should be able to start with whichever integration has the lowest change cost: proxy, middleware, SDK wrapper, or sidecar.
