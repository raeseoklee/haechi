# Initial Plan: AI/LLM/MCP-Specific Encryption Solution

- Status: Draft 0.1
- Date: 2026-06-08
- Product: Haechi

## 1. Strategic Direction

An encryption solution purpose-built for AI, LLM, and MCP occupies a sharper market position than generic transport encryption. Most general-purpose API encryption products stop at HTTP payload protection, but AI systems introduce new categories of sensitive data: prompts, contexts, tool calls, resources, retrieval snippets, artifacts, and streaming events.

MCP and A2A in particular blur security boundaries as the agent and tool ecosystem expands. Haechi can step into that boundary and become the product that turns "what information can be revealed in plaintext to which agent, tool, model, or provider" into an enforceable policy.

The initial direction is an open-source / self-hosted security project, not a SaaS offering. The primary goal is therefore not a sellable control plane, but rather a clearly designed core interface, a replaceable reference engine, conformance tests, and published real-world MCP/LLM usage examples.

## 2. Core Hypotheses

| ID | Hypothesis | Validation Method |
|---|---|---|
| HYP-001 | Enterprises want to reduce plaintext prompt/tool output in LLM gateway logs. | AI gateway PoC |
| HYP-002 | MCP server developers want a common module for safely exposing tool input/output and resource content. | MCP server sample |
| HYP-003 | Agent-to-agent systems require per-task/context/artifact decryption authorization. | A2A adapter PoC |
| HYP-004 | Separating "information the model must see" from "information the system only stores or forwards" increases the value of an encryption product. | Selective reveal demo |
| HYP-005 | Security teams and OSS adopters want to control KMS/HSM, audit, policy, and redaction outside the agent framework. | OSS adopter / security reviewer interview |
| HYP-006 | Enterprises treat PII filtering as a fundamental control on par with encryption when adopting LLM/MCP. | Korean PII filtering PoC |
| HYP-007 | Global customers require per-region privacy profiles and control over data residency / model provider region. | Regional profile PoC |
| HYP-008 | Customers require custom filtering that lets them register internal identifiers and confidential terms. | Custom rule DSL PoC |
| HYP-009 | OSS adopters prefer a small, composable core where crypto, policy, filtering, and audit implementations are swappable over a fully integrated SaaS. | Plugin API PoC + conformance tests |
| HYP-010 | Even a security tool will not spread if adoption is painful. A 5-minute local demo, 30-minute MCP/LLM PoC, and 1-day custom filter PoC must all be achievable. | Quickstart usability test |

## 3. Priority Use Cases

### 3.1 MCP Tool-Call Protection

- The MCP client creates a tool call.
- The Haechi policy evaluates tool name, arguments schema, tenant, user, and agent ID.
- Sensitive arguments are protected via tokenization or envelope encryption.
- The MCP server decrypts only in an authorized context.
- Tool results are returned to the agent after default redaction.

### 3.2 MCP Resource Protection

- Resource URIs and content classifications are mapped to policy.
- Resource content is encrypted with a tenant/resource scope key.
- The LLM receives a redacted summary or reference token instead of the original content.
- The audit log retains only the resource URI hash, policy ID, key ID, and decision ID.

### 3.3 LLM Gateway Prompt Protection

- System, developer, user, and tool messages are extracted from the HTTP request.
- PII, secrets, credentials, source code, and customer data are detected.
- A decision of reveal, redact, tokenize, or block is made before forwarding to the provider.
- The plaintext exposure scope per provider and the audit events are recorded.

### 3.4 PII Filtering

- Filtering targets include prompts, MCP tool arguments, resource content, RAG snippets, and generated artifacts.
- Structured identifiers such as Korean national ID numbers, alien registration numbers, and card numbers are detected first using deterministic rules and checksums.
- Email addresses, phone numbers, postal addresses, account numbers, API keys, access tokens, and secrets are detected using rules and a pattern library.
- Names, organizations, medical/health information, biometric data, and sensitive inferred information are detected using dictionary lookups, NER, and pluggable classifiers.
- Detection results are handled according to policy: mask, redact, tokenize, encrypt, block, or human review.
- Filtering audit logs retain only entity type, rule ID, confidence, action, and decision ID — never the original text.

### 3.5 A2A Task/Artifact Protection

- AgentCard discovery results are verified.
- Task ID, context ID, source agent, and target agent are included in AAD.
- Artifacts are encrypted with a task-scoped key.
- Decryption attempts on an artifact from a different task, context, or agent are rejected.

### 3.6 gRPC Streaming Protection

- Service, method, and message type are used as policy context.
- Stream/session keys and chunk nonces are kept separate.
- Cancellation, retry, redelivery, and partial delivery are recorded as audit events.
- Metadata leakage is checked separately.

## 4. Architecture Draft

```text
AI App / Agent Runtime / MCP Host
        |
        v
Haechi SDK / CLI / Local Proxy / Sidecar
        |
        +-- Core Pipeline
        |      +-- normalize protocol message
        |      +-- classify/filter
        |      +-- decide policy
        |      +-- encrypt/tokenize/redact
        |      +-- emit safe audit
        |
        +-- Pluggable Providers
        |      +-- CryptoProvider
        |      +-- KeyProvider
        |      +-- PolicyEngine
        |      +-- FilterEngine
        |      +-- TokenVault
        |      +-- AuditSink
        |
        +-- Reference Engines
        |      +-- JSON/YAML policy
        |      +-- local key provider
        |      +-- envelope crypto
        |      +-- Korean/global PII filters
        |      +-- JSONL audit
        |
        +-- MCP Adapter
        +-- LLM HTTP Adapter
        +-- gRPC Adapter
        +-- A2A Adapter
        |
        v
MCP Server / LLM Provider / Remote Agent / Tool API
```

## 5. Design Principles

- **Protocol-aware**: Understands MCP methods, A2A tasks, gRPC methods, and LLM message roles — not just raw byte streams.
- **Context-bound**: Ciphertext is bound to tenant, user, agent, model, task, context, tool, and resource.
- **Selective reveal**: Only the minimum information the model needs is exposed in plaintext.
- **Observability-safe**: Traces and replays contain no sensitive data by default.
- **Provider-neutral**: Not locked into any specific LLM vendor.
- **Fail-closed**: Payloads with a sensitive classification are blocked if policy evaluation fails.
- **OSS-first**: Operates as a library, CLI, local proxy, or self-hosted sidecar — no hosted SaaS required.
- **Pluggable by default**: The interface and test contract for crypto, key, policy, filtering, and audit matter more than the default implementation.
- **Reference implementation is replaceable**: The default implementation is a baseline for learning and PoC; it must be replaceable to fit any user environment.
- **Test fixtures as API**: Plugin authors must be able to verify compatibility using fixtures and conformance tests.
- **Easy adoption**: Attachable to existing applications with minimal change cost via proxy, middleware, SDK wrapper, sidecar, or preset policy.
- **Progressive hardening**: Start with dry-run / report-only to review detection results, then enforce redact / tokenize / encrypt / block incrementally.

## 6. Initial Technology Stack Proposal

| Area | Proposal |
|---|---|
| SDK | TypeScript/Node, Python |
| Policy | JSON/YAML + JSON Schema |
| Crypto format | JWE JSON Serialization or compact envelope |
| KMS | Vault or AWS KMS |
| MCP | Streamable HTTP proxy, stdio wrapper |
| LLM adapter | OpenAI-compatible HTTP schema first |
| Redaction | Deterministic detector + pluggable classifier |
| Privacy filtering | Korean PII rules + checksum validators + custom entity rules |
| Audit | JSON Lines + optional hash chain |
| Tests | Golden fixtures, tamper/replay/cross-context negative tests |
| Plugin contract | TypeScript interface + JSON Schema manifest + conformance test |
| Distribution | GitHub repository, package examples, local CLI, SECURITY.md |
| Developer UX | `haechi init`, preset policy, dry-run/report-only, copy-paste middleware |

## 7. MVP Milestones

| Phase | Deliverable | Completion Criteria |
|---|---|---|
| M0 | Developer quickstart | `haechi init`, local key, sample policy, dry-run, and MCP/LLM demo run in under 5 minutes |
| M1 | MCP proxy skeleton | initialize/tools/call/resource read flow observable |
| M2 | Policy engine | Per-method/tool/resource allow/block/redact/encrypt decisions |
| M3 | PII filtering | Korean PII fixtures and secret fixtures detected and handled |
| M4 | Global privacy profiles | EU-GDPR, US-CCPA-CPRA, US-HIPAA/PCI fixtures and region-deny |
| M5 | Custom filter DSL | regex/dictionary/path-scope/action override with fixture tests |
| M6 | Envelope crypto | Context-bound encrypt/decrypt with tamper tests |
| M7 | KMS adapter | Local provider + one of Vault/AWS KMS |
| M8 | LLM HTTP adapter | Chat/completion message redaction/encryption policy |
| M9 | Audit | Verified no plaintext exposure of prompt/tool/resource/PII |
| M10 | Security negative tests | Replay, wrong context, wrong agent, wrong tool, log leakage |
| M11 | Crypto envelope hardening | Canonical AAD, nonce/replay cache, key lifecycle, signed policy |
| M12 | Protocol security contracts | Per-adapter auth/lifecycle/metadata scrub contracts for MCP/A2A/gRPC/LLM |
| M13 | OSS modular packages | `core`, `crypto`, `policy`, `filter`, `mcp`, `llm`, `audit`, `examples` package boundaries |
| M14 | Plugin examples | Custom `PolicyEngine`, `FilterEngine`, and `AuditSink` examples with conformance tests |
| M15 | Build-blocking QA gate | Plaintext leak, policy conflict, KMS fault, region-deny, DSL fuzzing, and plugin capability violation all fail CI |

## 8. Top Risks

| Risk | Description | Mitigation |
|---|---|---|
| Models cannot process ciphertext | Semantic information the LLM must act on ultimately requires reveal. | Selective reveal, tokenization, TEE roadmap |
| MCP/A2A spec churn | The protocols are still evolving rapidly. | Adapter isolation, spec version field |
| Tool-call log leakage | Agent frameworks may write separate logs. | Framework-specific log hook, redaction test |
| Confusion with prompt injection | Encryption does not replace prompt injection defense. | Separate prompt security gate |
| Difficulty protecting embeddings | Encrypting embeddings breaks similarity search. | Prioritize source text protection; separate embedding policy |
| PII filter false positives/negatives | False positives degrade work quality; false negatives cause PII leakage. | Confidence threshold, human review, fixture tests |
| PII exposure within the filter itself | Using an external classifier may re-expose PII during filtering. | Local-first detector, classifier privacy policy |
| Global regulatory divergence | GDPR, CCPA, HIPAA, APPI, PDPA, and LGPD differ in definitions, rights, and transfer conditions. | Regional profile abstraction |
| Cross-border transfer violations | External LLM provider regions may cause EU/UK/BR transfer restriction violations. | Region-aware provider allowlist |
| Custom rule malfunction | Incorrect regex or allowlist can cause missed blocks or operational outages. | Validate/test/approve/rollback lifecycle |
| Custom dictionary leakage | A customer's dictionary may itself be a trade secret. | Dictionary encryption, access audit |
| Adoption difficulty | If installation and configuration are painful, OSS adoption and real-world use both fail. | 5-minute quickstart, dry-run, preset, minimal config, copy-paste examples |
| AAD/nonce/replay vulnerabilities | Context-bound encryption can be bypassed without canonicalization and a replay cache. | Crypto envelope spec, stream sequencing tests |
| Policy distribution tampering | Stale policy, client-supplied source labels, or unsigned rule packages can bypass hard-blocks. | Signed policy bundle, fail-closed validation |
| Observability leakage | Plaintext prompt/tool output may appear in trace baggage, metric labels, exceptions, or crash dumps. | Telemetry sentinel tests |
| Over-abstraction | Too many interfaces too early delays a working demo. | Implement core pipeline, MCP proxy, and filter/crypto reference first |
| Plugin safety | A user-written plugin could send plaintext externally or bypass audit. | Capability manifest, fail-closed loading, conformance/negative tests |
| OSS maintenance burden | More documentation and examples make security updates and compatibility management harder. | Narrow MVP, semantic versioning, compatibility matrix |
| Compliance misrepresentation | OSS documentation may be mistaken for regulatory compliance assurance. | Non-compliance disclaimer in README and SECURITY.md |

## 9. Next Documentation Work

- AI threat model
- MCP adapter SRS
- LLM gateway policy schema
- A2A task/artifact encryption design
- Redaction/tokenization policy spec
- Privacy filtering policy spec
- Custom filtering DSL spec
- Global privacy compliance matrix
- Crypto envelope spec
- Audit event schema
- Expert gap review backlog
- OSS modular architecture
- Easy adoption guide and quickstart
- Plugin API and conformance test spec
- Protocol security contract spec
- Self-hosted usage and shared responsibility note
- Optional enterprise procurement evidence pack
- Security test spec and red-team corpus
- RAG/vector and agent memory protection design
