# PRD: AI/LLM/MCP Encryption Solution

- Status: Draft 0.1
- Date: 2026-06-08
- Product: Haechi
- Target version: Realignment of the initial PRD/SRS/security-review archive toward AI/LLM/MCP-specific requirements

## 1. Purpose

Haechi is an encryption solution that protects prompts, contexts, tool calls, resources, retrieval snippets, artifacts, and streaming events flowing through AI applications, LLM gateways, MCP clients/servers, agent runtimes, and A2A agent networks.

The core objective is not merely transport-layer protection. Instead, it elevates the semantic units of AI workflows — `message`, `tool call`, `resource`, `task`, `context`, `artifact`, and `agent identity` — to first-class subjects of encryption policy and key management.

The initial product form is open-source/self-hosted security infrastructure, not SaaS. Users attach Haechi to their AI applications as a library, CLI, sidecar proxy, or MCP wrapper, and must be able to swap out the encryption scheme, policy evaluation, privacy filtering, and audit store to fit their own environment.

## 2. Background

Standard TLS protects the transport channel between client and server. In LLM/agent systems, however, plaintext exposure recurs at the following points:

- LLM gateways, prompt routers, and observability pipelines
- JSON-RPC messages between MCP clients and servers
- MCP tool inputs/outputs, resource content, and prompt templates
- RAG retrieval snippets and vector metadata
- A2A agent messages, task state, and artifacts
- gRPC streaming chunks and metadata
- Agent tool-call logs, traces, and replay records
- Prompt/context transformation points before and after model provider transmission

Haechi is the layer that encrypts, tokenizes, redacts, evaluates permissions, and audits these AI-native data units based on policy.

Privacy filtering is a core capability of Haechi. Encryption protects data, but the moment it is exposed in plaintext to a model or tool, separate controls are required. Haechi detects PII in prompts, contexts, MCP tool inputs/outputs, resources, retrieval snippets, and generated artifacts, then handles each finding with one of: `allow`, `redact`, `mask`, `tokenize`, `encrypt`, `block`, or `human-review`.

## 3. Product Positioning

Haechi does not replace general-purpose security solutions, LLM gateways, MCP frameworks, or agent frameworks. It is an encryption and context protection module that augments existing AI/LLM/MCP-targeted solutions.

Commercialization and a SaaS control plane are not initial goals. The initial positioning is: "a small but verifiable OSS core + swappable reference engines + deployment-oriented AI/MCP examples." The default implementation Haechi ships is a reference, not a prescription — users must be able to inject their own implementations through boundaries such as `CryptoProvider`, `PolicyEngine`, `FilterEngine`, `KeyProvider`, and `AuditSink`.

| Target Solution | Integration Approach |
|---|---|
| LLM gateway | OpenAI-compatible/Anthropic-compatible HTTP adapter or middleware |
| MCP host/client | MCP client proxy, SDK wrapper, policy interceptor |
| MCP server | tool/resource/prompt response encryption wrapper |
| Agent runtime | task/context/artifact scoped encryption |
| A2A server/client | AgentCard verification, message/task/artifact encryption adapter |
| gRPC AI service | protobuf field encryption, streaming message protection |
| RAG pipeline | retrieval snippet, source metadata, artifact encryption |
| Observability platform | prompt/tool/result redaction, sealed audit events |

## 4. Key Differentiators

- **AI semantic unit protection**: prompt, system message, tool args, tool result, MCP resource, and A2A artifact are treated as distinct protection subjects.
- **Context-bound encryption**: tenant, user, agent, model, task, context, tool, and resource URI are included in AAD and decryption authorization evaluation.
- **Policy before model**: policy determines what information may be exposed in plaintext to a model.
- **Selective reveal**: only the portions a model strictly needs to see are exposed in plaintext; the rest is kept tokenized or as ciphertext.
- **MCP/A2A native**: JSON-RPC id, method, session id, task id, artifact id, AgentCard, and streaming events are used as policy context.
- **Observability-safe**: prompts and tool outputs are not retained in plaintext in logs, traces, metrics, or replay artifacts.
- **Privacy filtering first**: PII is detected and policy is applied before data is passed to a model, agent, tool, or log.
- **Easy adoption**: attachable to existing AI applications with minimal changes via proxy, middleware, SDK wrapper, sidecar, or config preset.

## 5. Non-Goals

- General-purpose cryptography that enables LLMs to directly understand ciphertext is not a goal.
- Fully homomorphic encryption-based LLM inference is out of MVP scope.
- End-to-end invisibility to all external LLM providers is not claimed.
- Complete prevention of prompt injection is not claimed.
- MCP or A2A protocols themselves are not replaced.
- The initial version does not provide hosted SaaS, multi-tenant control planes, billing, SLAs, or commercial compliance packs.
- No novel cryptographic primitives are invented. Validated standards and libraries are composed, and implementation boundaries are tested.

## 6. User Segments

| User Segment | Need |
|---|---|
| AI platform security owner | Minimize plaintext exposure of prompts/contexts/tool calls |
| LLM gateway operator | Per-provider policy, redaction, encryption, and audit |
| MCP server developer | Protect tool inputs/outputs and resource content |
| Agent framework developer | Task/context/artifact-level encryption |
| RAG operator | Protect retrieval snippets and source metadata |
| Compliance/audit officer | Track who exposed which context to which model/agent/tool |
| Privacy officer | Filter and control the exposure scope of PII, unique identifiers, and sensitive data before AI processing |
| Open-source adopter | Reference the default implementation while easily replacing crypto, policy, filtering, and audit components |
| OSS contributor/reviewer | Verify a project with proven security design, testing, and documentation quality even within a narrow scope |

## 7. Business Requirements

| ID | Requirement | Priority | Verification |
|---|---|---:|---|
| BR-AI-001 | The product must be delivered as an encryption module that can be added to AI/LLM/MCP-targeted solutions. | Must | PoC |
| BR-AI-002 | The product must reduce plaintext exposure points for prompts, contexts, tool calls, resources, and artifacts. | Must | threat model |
| BR-AI-003 | The product must provide an adapter strategy that covers both MCP stdio and Streamable HTTP. | Must | MCP PoC |
| BR-AI-004 | The product should support gRPC streaming and A2A message/task/artifact protection. | Should | protocol PoC |
| BR-AI-005 | The product must enforce policy-based control over the plaintext exposure scope when using external LLM providers. | Must | policy test |
| BR-AI-006 | The product must remove or seal AI sensitive data from logs, traces, replays, and metrics. | Must | observability test |
| BR-AI-007 | The product must support KMS/HSM/Vault-based key management and per-tenant/agent/task key separation. | Must | key test |
| BR-AI-008 | The product must detect PII, unique identifiers, sensitive data, credentials, and secrets, and apply policy before exposing them to models/tools/agents. | Must | privacy filtering test |
| BR-AI-009 | The product should support detection rules adapted to the Korean privacy environment and customer-specific custom entity rules. | Should | Korean PII fixture test |
| BR-AI-010 | The product must support selecting privacy regulatory profiles for major markets — Korea, EU/UK, US, Japan, Singapore, Canada, and Brazil — as policy. | Must | regional profile test |
| BR-AI-011 | The product must include cross-border transfer, data residency, subprocessors, and model provider region in the policy decision context. | Must | transfer policy test |
| BR-AI-012 | The product should produce decision records and data flow evidence sufficient to support data subject rights responses, audits, DPIA/PIA, and DSAR exports. | Should | audit evidence review |
| BR-AI-013 | The product must support per-customer/tenant custom filtering rules, dictionaries, classifiers, and action overrides. | Must | custom filter test |
| BR-AI-014 | The product must provide AAD canonicalization, nonce/replay defense, key lifecycle, and signed policy distribution as first-class cryptographic security requirements. | Must | crypto negative test |
| BR-AI-015 | The product must define security contracts covering transport, auth, lifecycle, and metadata scrubbing for each MCP, A2A, gRPC, and LLM gateway adapter. | Must | protocol contract test |
| BR-AI-016 | The product must be usable as a library, CLI, local proxy, or self-hosted sidecar without depending on hosted SaaS, and must explicitly state key custody and telemetry boundaries. | Must | deployment review |
| BR-AI-017 | The product must prioritize OSS trust artifacts over commercial evidence packs: `SECURITY.md`, threat model, conformance tests, SBOM, signed release artifacts, and security test results. | Must | OSS trust review |
| BR-AI-018 | The product must verify plaintext leak, policy conflict, KMS fault, replay, region-deny, and custom DSL bypass as build-blocking security tests. | Must | CI gate test |
| BR-AI-019 | The product must separate encryption, key management, policy evaluation, privacy filtering, token vault, audit, and protocol adapters into swappable provider interfaces. | Must | plugin boundary review |
| BR-AI-020 | The product must provide a default reference implementation while offering dependency injection, plugin manifests, and compatibility contracts so users can inject their own implementations. | Must | plugin conformance test |
| BR-AI-021 | The product must require plugins to declare capabilities such as plaintext access, network egress, file writes, and audit logging, and evaluate them under a fail-closed policy. | Must | plugin security test |
| BR-AI-022 | The product must apply to existing AI/LLM/MCP solutions with low change cost, targeting a 5-minute local demo, 30-minute MCP/LLM PoC, and same-day custom filter PoC. | Must | adoption test |
| BR-AI-023 | The product must lower the adoption barrier through `init`, preset policies, dry-run, report-only mode, and copy-paste middleware examples while maintaining secure defaults. | Must | quickstart review |

## 8. Product Requirements

| ID | Requirement | Priority |
|---|---|---:|
| PRD-AI-001 | The product must support per-role encryption, redaction, and tokenization policies for prompt messages. | Must |
| PRD-AI-002 | The product must support per-method policies for MCP JSON-RPC. | Must |
| PRD-AI-003 | The product must classify MCP tool inputs/outputs, resource content, and prompt templates as protection subjects. | Must |
| PRD-AI-004 | The product should include A2A agent id, task id, context id, and artifact id in encryption AAD and decryption authorization evaluation. | Should |
| PRD-AI-005 | The product should have an architecture capable of supporting both gRPC protobuf field encryption and opaque message encryption. | Should |
| PRD-AI-006 | The product should support per-chunk nonces and stream/session binding for streaming chunks. | Should |
| PRD-AI-007 | The product must produce a policy decision record before sending plaintext to a model provider. | Must |
| PRD-AI-008 | The product must apply redaction by default to prompt/tool/resource/artifact logs. | Must |
| PRD-AI-009 | The product must distinguish between customer-managed keys and provider-managed keys. | Must |
| PRD-AI-010 | The product should support trust verification and allowlisting for MCP/A2A discovery metadata. | Should |
| PRD-AI-011 | The product must provide a privacy filtering pipeline that combines deterministic rules, checksum validation, dictionary/NER, and pluggable classifiers. | Must |
| PRD-AI-012 | The product must include as default detection targets: resident registration numbers, alien registration numbers, passport numbers, driver's license numbers, mobile phone numbers, email addresses, physical addresses, bank account numbers, card numbers, health information, biometric data, authentication credentials, and API keys/secrets. | Must |
| PRD-AI-013 | The product must support specifying the handling action for each detected PII finding as one of: `redact`, `mask`, `tokenize`, `encrypt`, `block`, or `human-review`. | Must |
| PRD-AI-014 | The product must support both pre-filter (before model invocation) and post-filter (after model/tool response). | Must |
| PRD-AI-015 | The product must not retain the original text of filtered findings in logs; it must audit only entity type, confidence, rule id, action, and decision id. | Must |
| PRD-AI-016 | The product must support switching the detection catalog, default action, transfer rules, retention rules, and audit fields through regional privacy profiles. | Must |
| PRD-AI-017 | The product must be able to express GDPR/UK GDPR requirements for personal data, special category data, pseudonymisation, and international transfer as policy items. | Must |
| PRD-AI-018 | The product should be able to express CCPA/CPRA requirements for sensitive personal information and limit-use as policy items. | Should |
| PRD-AI-019 | The product should apply detection, redaction, tokenization, and logging-prohibition policies to HIPAA PHI and PCI cardholder data as separate sector profiles. | Should |
| PRD-AI-020 | The product must be able to enforce per-tenant data residency and model provider region allowlists in global deployments. | Must |
| PRD-AI-021 | The product must provide a custom filter DSL combining regex, checksum validators, keyword dictionaries, deny/allow lists, JSONPath/protobuf path, and semantic classifiers. | Must |
| PRD-AI-022 | The product must support a draft, validate, test, approve, publish, and rollback lifecycle for custom filter rules. | Must |
| PRD-AI-023 | The product must apply a clear priority order on custom filter rule conflicts: global profile, sector profile, tenant rule, app rule, emergency rule. | Must |
| PRD-AI-024 | The product should encrypt customer-supplied custom dictionaries and fixtures at rest and enforce auditable access control. | Should |
| PRD-AI-025 | The product should support deploying custom classifier plugins as one of: local-only, customer-managed endpoint, or external endpoint. | Should |
| PRD-AI-026 | The product must fix encryption AAD using canonical JSON, Unicode normalization, and tenant/user/agent/model/task/tool/resource/policy version. | Must |
| PRD-AI-027 | The product must enforce nonce uniqueness, stream sequence integrity, and replay cache across streaming chunks, retries, cancellations, and partial deliveries. | Must |
| PRD-AI-028 | The product must manage key generation, rotation, rewrap, retirement, destruction evidence, and backup/restore drills as a key lifecycle. | Must |
| PRD-AI-029 | The product must support token vault retention, deletion, DSAR export, re-identification approval, and access audit. | Must |
| PRD-AI-030 | The product must support policy bundle signing, version pinning, emergency block, fail-closed validation, and stale policy rejection. | Must |
| PRD-AI-031 | The product must enforce MCP authorization, token passthrough prohibition, per-client consent, stdio credential handling, and protocol version negotiation. | Must |
| PRD-AI-032 | The product should verify A2A AgentCard signatures, authenticated extended cards, transport parity, and push notification security. | Should |
| PRD-AI-033 | The product must remove original sensitive data from OpenTelemetry baggage, span attributes, metric labels, exceptions, crash dumps, and replay artifacts. | Must |
| PRD-AI-034 | The product should have a provider-neutral LLM message schema and provider adapter mapping. | Should |
| PRD-AI-035 | The product should support RAG/vector namespace, embedding/source metadata, citation, and index deletion propagation policies. | Should |
| PRD-AI-036 | The product should classify agent memory as ephemeral or durable and support TTL, purge, export, and cross-task recall blocking. | Should |
| PRD-AI-037 | The product must provide per-tenant config store, audit sink, quota, admin RBAC, and blast-radius limits. | Must |
| PRD-AI-038 | The product should provide SBOM, artifact signing, provenance, dependency vulnerability policy, and classifier/plugin trust policy. | Should |
| PRD-AI-039 | The product must provide envelope encryption, decrypt, rewrap, and key id resolution as swappable operations through the `CryptoProvider` interface. | Must |
| PRD-AI-040 | The product must allow connecting local key, Vault, KMS, HSM, and test key providers under the same contract through the `KeyProvider` interface. | Must |
| PRD-AI-041 | The product must allow connecting CEL, OPA/Rego, and user-supplied policy engines — in addition to JSON/YAML reference policies — through the `PolicyEngine` interface. | Must |
| PRD-AI-042 | The product must allow replacing the rule/checksum/dictionary-based reference filter and user-supplied classifiers through the `FilterEngine` interface. | Must |
| PRD-AI-043 | The product should allow replacing local encrypted vault, DB-backed vault, and external vault through the `TokenVault` interface. | Should |
| PRD-AI-044 | The product must allow replacing JSONL, OpenTelemetry-safe exporter, SIEM webhook, and custom sinks through the `AuditSink` interface. | Must |
| PRD-AI-045 | The product must ensure that MCP, LLM HTTP, gRPC, and A2A adapters all use the same protect/reveal pipeline through the `ProtocolAdapter` interface. | Must |
| PRD-AI-046 | The product must provide golden fixtures, negative fixtures, capability manifests, and compatibility version tests for all providers/plugins. | Must |
| PRD-AI-047 | The product must provide a local proxy mode that requires minimal changes to existing code. Users must be able to reroute LLM/MCP requests by specifying only a target base URL and a policy file. | Must |
| PRD-AI-048 | The product must be applicable to Node and Python AI applications with SDK wrapper/middleware examples of ten lines or fewer. | Must |
| PRD-AI-049 | The product must generate a sample policy, local key, audit path, and MCP/LLM presets via `haechi init` or an equivalent CLI command. | Must |
| PRD-AI-050 | The product must provide a `dry-run` or `report-only` mode to inspect which prompts/tools/resources would be detected before actual blocking or encryption takes effect. | Must |
| PRD-AI-051 | The product must provide the following default presets: `mcp-basic`, `llm-redact`, `korean-pii`, `secrets-only`, `local-only`, `strict-block`. | Must |
| PRD-AI-052 | The product should provide a path for users to swap `CryptoProvider`, `PolicyEngine`, `FilterEngine`, and `AuditSink` from config without code changes. | Should |
| PRD-AI-053 | The product must prefer blocking requests over leaking plaintext on application failure, and must explain the cause and remediation in development mode without including plaintext data. | Must |

## 9. MVP Scope

The MVP starts narrow.

The actual 0.1 implementation scope is governed by `docs/current/mvp-0.1-implementation-scope.md`. Among the items below, the Python SDK, Vault/KMS adapter, MCP stdio wrapper, and RAG sample may be deferred beyond 0.1.

Included:

- TypeScript/Node SDK
- Python SDK
- core provider interface package
- plugin manifest schema
- provider conformance test harness
- local CLI demo
- one-command `init` quickstart
- dry-run/report-only mode
- copy-paste Node/Python middleware examples
- MCP/LLM preset policy files
- MCP Streamable HTTP proxy
- MCP stdio wrapper
- OpenAI-compatible HTTP request/response adapter
- prompt/tool/resource redaction and envelope encryption
- privacy filtering pipeline
- Korean PII default detection rules
- one of: Vault or AWS KMS adapter
- local software key provider
- JSON policy file
- audit event JSON Lines
- MCP tool-call sample
- RAG snippet protection sample
- reference `CryptoProvider`, `PolicyEngine`, `FilterEngine`, `KeyProvider`, `AuditSink`

Excluded from MVP:

- Fully homomorphic encryption or ciphertext LLM inference
- Native SDK support for all LLM providers
- Built-in KCMVP provider
- Full A2A server implementation
- gRPC bidirectional streaming production adapter
- GUI management console
- Hosted SaaS control plane
- Billing, tenant admin portal, SLA
- SOC 2/ISO commercial evidence pack

## 10. Core Security Principles

- Separate values the model must process from values the model does not need to see.
- Classify PII before exposing it to a model; apply default blocking or tokenization when the purpose of exposure is not clear.
- Explicitly state that data sent in plaintext to a model provider can no longer be guaranteed invisible by Haechi alone.
- Treat tool-call and resource results as sensitive by default.
- Include agent/task/context boundaries in AAD and decryption authorization.
- Treat the observability pipeline as a first-class security boundary of the product.
- Prompt injection defense and encryption are separate controls; neither substitutes for the other.
- Swappable providers/plugins are trust boundaries. Expose and test capabilities such as plaintext access, network egress, file writes, and audit manipulation.
- The reference implementation must be replaceable by users, but conformance tests and security negative tests remain as a fixed baseline that is not replaced.

## 11. Open Questions

- Decide whether the MCP adapter should be proxy-first or SDK wrapper-first.
- Decide whether to use an OpenAI-compatible API as the primary LLM adapter or to define a provider-agnostic schema first.
- Decide whether to protect embeddings themselves in RAG vector search or focus on protecting source text and metadata.
- Decide whether A2A remains at the adapter level or evolves into a full protocol gateway.
- Decide whether to include confidential computing/TEE in the secondary roadmap.
- Decide whether an ML/LLM classifier used for PII detection may receive plaintext PII at that classifier itself.
- Decide whether high-risk identifiers such as resident registration numbers default to block, or whether tokenization may be permitted under customer policy.
- Decide whether the product supports EU/UK data transfer mechanisms (SCC/IDTA) as evidence only or enforces them as policy.
- Decide whether HIPAA/PCI sector profiles are included in the MVP or deferred as later examples.
- Decide whether the custom filter DSL uses a product-specific syntax or partially adopts an existing policy language such as OPA/Rego or CEL.
- Decide whether external endpoint calls by custom classifier plugins default to prohibiting PII transmission or require customer opt-in.
- Decide whether to stabilize the provider/plugin API TypeScript-first and then align Python, or to define a language-neutral IDL first.
- Decide whether the open-source license is Apache-2.0 or MIT.

## 12. References

- Model Context Protocol Specification, latest: https://modelcontextprotocol.io/specification/
- Model Context Protocol Authorization: https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization
- Model Context Protocol Security Best Practices: https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices
- Model Context Protocol official repository: https://github.com/modelcontextprotocol/modelcontextprotocol
- NSA MCP Security Design Considerations: https://www.nsa.gov/Portals/75/documents/Cybersecurity/CSI_MCP_SECURITY.pdf
- NSA/Five Eyes Careful Adoption of Agentic AI Services: https://media.defense.gov/2026/Apr/30/2003922823/-1/-1/0/CAREFUL%20ADOPTION%20OF%20AGENTIC%20AI%20SERVICES_FINAL.PDF
- A2A Agent2Agent Protocol: https://a2a-protocol.org/latest/specification/
- gRPC Core Concepts: https://grpc.io/docs/what-is-grpc/core-concepts/
- Korean Personal Information Safety Measures Standard: https://law.go.kr/LSW/admRulInfoP.do?admRulSeq=2100000192069&chrClsCd=010201
- KISA Cryptography FAQ: https://seed.kisa.or.kr/kisa/bbs/faq.do
- European Commission GDPR overview: https://commission.europa.eu/law/law-topic/data-protection/reform/what-does-general-data-protection-regulation-gdpr-govern_en
- European Commission Standard Contractual Clauses: https://commission.europa.eu/law/law-topic/data-protection/international-dimension-data-protection/standard-contractual-clauses-scc_en
- California CCPA: https://www.oag.ca.gov/privacy/ccpa
- HHS HIPAA Privacy Rule: https://www.hhs.gov/hipaa/for-professionals/privacy/index.html
- NIST Privacy Framework: https://www.nist.gov/privacy-framework
- RFC 8446, TLS 1.3
- RFC 7516, JSON Web Encryption
- RFC 9180, Hybrid Public Key Encryption
