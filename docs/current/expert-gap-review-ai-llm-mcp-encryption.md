# Expert Parallel Gap Review: AI/LLM/MCP-Specific Encryption Solution

- Status: Draft 0.1
- Date: 2026-06-08
- Product: Haechi
- Review method: Parallel review across security/crypto, AI/MCP/A2A architecture, global compliance, product/business, and test strategy personas

## 1. Summary

The current document has a solid grasp of `what to protect`. However, the latest direction is an open-source / self-hosted security infrastructure, not a SaaS offering. The gaps below should therefore be read in two categories: "security gaps that are mandatory for the initial OSS core" and "an optional backlog for commercialization or enterprise adoption."

Even for the initial OSS core, the following five axes are required.

1. Crypto/policy bypass-resistance: canonical AAD, nonce/replay, key lifecycle, signed policy, fail-closed.
2. Per-protocol operational contracts: MCP stdio/Streamable HTTP, A2A, gRPC, LLM gateway, RAG/vector, agent memory.
3. OSS distribution/trust model: self-hosted mode, key custody, telemetry boundary, SECURITY.md, conformance tests, SBOM, signed release.
4. Global AI/privacy governance: EU AI Act, NIST AI RMF/CSF, OWASP LLM/Agentic, US state privacy, sector profiles.
5. Adoptability: 5-minute local demo, 30-minute MCP/LLM PoC, 1-day custom filter PoC, proxy/middleware/SDK/sidecar adoption paths.
6. Verification automation: per-surface plaintext leak sentinel, policy conflict matrix, KMS fault injection, streaming chaos, red-team corpus.

## 2. P0: Must Address Before Requirements Freeze

| ID | Missing / Needs Strengthening | Why It Matters | Acceptance Criteria |
|---|---|---|---|
| GAP-P0-001 | AAD canonicalization | JSON reordering, Unicode variants, role/source spoofing, and policy version changes can destabilize the decryption context. | AAD schema, canonical JSON, Unicode normalization, policy version, and tenant/user/agent/model/task/tool/resource bindings are fixed; malformed inputs fail decryption. |
| GAP-P0-002 | nonce/replay/stream sequencing | Nonce reuse or replay in streaming chunks, retries, partial delivery, and duplicate requests is catastrophic. | Identical nonce, cross-session replay, cross-tenant replay, out-of-order chunks, and duplicate chunks are all rejected. |
| GAP-P0-003 | Key lifecycle | Using KMS/HSM/Vault alone does not define key creation, rotation, revocation, rewrap, backup/restore, or blast radius. | Tenant key rotation, retired key rejection, plaintext key non-export, rewrap job, restore drill, and destruction evidence are all tested. |
| GAP-P0-004 | Token vault governance | Tokenization must be connected to a DSAR, deletion, retention, and re-identification authorization model. | Token mapping purge, dual-control re-identification, DSAR export, retention expiry, and decision record linkage are verified. |
| GAP-P0-005 | Signed policy distribution | Client-supplied metadata, stale policy cache, and allowlist misuse can bypass hard-blocks. | Signed policy bundle, version pinning, server-side source classification, emergency rule precedence, and fail-closed validation are enforced. |
| GAP-P0-006 | MCP transport security contract | The latest MCP spec is actively evolving authorization, lifecycle, protocol version, and security best practices. | `initialize`/`initialized`, `MCP-Protocol-Version`, OAuth resource binding, stdio env allowlist, token passthrough prohibition, and per-client consent are tested. |
| GAP-P0-007 | A2A discovery/auth parity | Weak AgentCard, authenticated extended card, SSE/gRPC/REST binding, or push notification boundaries enable agent impersonation. | AgentCard signature/verification, security scheme parity, authenticated extended card, and streaming/resubscribe/push security are consistent across all adapters. |
| GAP-P0-008 | Observability boundary | Plaintext leaks not only through logs but also through trace baggage, headers, URL query strings, stack traces, crash dumps, metric labels, and replay artifacts. | No sentinel PII/secret plaintext appears in any telemetry sink; only hashes, IDs, and redaction metadata are retained. |
| GAP-P0-009 | OSS/self-hosted deployment modes | Library, CLI, local proxy, sidecar, and self-hosted service each have different key custody, egress, update, telemetry, and failure boundaries. | Per-mode key custody, network egress, telemetry path, upgrade/rollback, and local-only behavior are documented. |
| GAP-P0-010 | Open-source shared responsibility note | OSS users must know the scope of their own responsibility for legal decisions, transfer evidence, key custody, DSAR, and incident response. | README/SECURITY/docs explicitly state maintainer responsibility, user responsibility, and a non-compliance disclaimer. |
| GAP-P0-011 | EU AI Act / AI governance mapping | When Haechi is used as an AI system or AI governance component, interpretations around transparency, role determination, and incidents may be required. | A provider/deployer/GPAI role decision table, transparency note, incident log, and AI risk register template are provided as reference materials. |
| GAP-P0-012 | Build-blocking security tests | Current acceptance criteria are declarative. A security product must be explicit about which failures block the build. | Plaintext leak, policy conflict, KMS fault, replay, global profile violations, and hard-block bypass failures all become CI gates. |
| GAP-P0-013 | Easy adoption path | High security is irrelevant if adoption is too difficult for OSS spread and real-world use. | `haechi init`, dry-run/report-only, preset policy, local proxy, copy-paste middleware, and 5-minute/30-minute/1-day adoption targets are validated through documentation and examples. |

## 3. P1: Address Before OSS Adoption and Production Use

| ID | Missing / Needs Strengthening | Why It Matters | Acceptance Criteria |
|---|---|---|---|
| GAP-P1-001 | Provider-neutral LLM message model | An OpenAI-compatible schema alone cannot uniformly govern Anthropic, multimodal, structured output, tool/function calls, and streaming chunks. | An internal canonical message schema, provider adapter mapping, pre/post policy hooks, and chunk-level decision records exist. |
| GAP-P1-002 | MCP registry/provenance/cache invalidation | A stale or poisoned tools/resources/prompts listing or `listChanged` event results in incorrect tool policy being applied. | Registry entry owner, version, hash, scope, cache invalidation, discovery auth, and deterministic ordering are verified. |
| GAP-P1-003 | gRPC streaming semantics | Field encryption alone cannot handle deadline, cancellation, retry, ordering, and metadata leakage. | Deadline propagation, cancel audit, retry idempotency, metadata scrub, and partial delivery semantics are tested. |
| GAP-P1-004 | RAG/vector DB protection | Protecting snippets alone leaves embedding, vector namespace, citation, and deletion propagation unaddressed. | Tenant-scoped namespace, embedding/source metadata policy, index deletion propagation, and citation redaction are verified. |
| GAP-P1-005 | Agent memory lifecycle | Long-term memory and recall cannot be governed by task/context encryption alone. | Ephemeral/durable memory distinction, TTL/purge/export, per-tenant/agent namespace, and cross-task recall denial all function correctly. |
| GAP-P1-006 | Multi-tenant isolation | Key separation alone is insufficient to isolate policy, audit, memory, rate limits, and the admin plane. | Tenant config store, audit sink, quota, provider allowlist, admin RBAC, and blast-radius limits are isolated per tenant. |
| GAP-P1-007 | SDK/proxy/plugin deployment model | Customers must be able to decide whether to adopt in-process SDK, sidecar, gateway plugin, or server middleware. | Compatibility, failure boundaries, performance cost, rollback, and upgrade policy for each mode are documented. |
| GAP-P1-008 | Custom DSL safety | Custom filters are an attack surface for parser bugs, regex DoS, allowlist bypass, and external classifier leakage. | DSL fuzzing, regex resource limits, conflict golden tests, and classifier egress tests run in CI. |
| GAP-P1-009 | Supply chain integrity | A compromised SDK, connector, classifier plugin, or policy package turns the security product into an attack vector. | SBOM, provenance, artifact signing, dependency vulnerability policy, and plugin trust policy are required. |
| GAP-P1-010 | AI red-team corpus | Treating prompt injection as a non-goal leaves tool-output injection, resource poisoning, and exfiltration unaddressed. | A red-team corpus mapped to OWASP LLM/Agentic threats exists, and block rationale is recorded in decision records. |
| GAP-P1-011 | US privacy expansion | CCPA/CPRA alone is insufficient for full US market coverage. | Profiles or exclusion rationale for Colorado, Connecticut, Virginia, Texas, and Washington My Health My Data Act are defined. |
| GAP-P1-012 | Sector operational controls | HIPAA/PCI require more than identifier detection. | BAA, ePHI audit, breach workflow, SAD storage prohibition, retention/disposal, and MFA evidence are verified. |
| GAP-P1-013 | OSS trust evidence | Commercial certifications are a lower priority, but a security OSS project requires threat model, security policy, SBOM, release provenance, and test results as prerequisites for trust. | SECURITY.md, threat model, SBOM, signed release, and conformance results are publicly available. |
| GAP-P1-014 | Adoption packaging | No commercial SKUs are needed, but users must have the information to decide which modules to integrate and how. | A core/filter/policy/crypto/mcp/llm/audit package matrix and a per-example integration guide are provided. |

## 4. P2: Roadmap / Hardening

| ID | Item | Rationale | Completion Criteria |
|---|---|---|---|
| GAP-P2-001 | Crypto agility / PQC migration | The envelope format may handle long-retention data, so algorithm deprecation and a PQC migration plan are needed. | Envelope versioning, deprecation window, rewrap, and an HPKE/PQC review note exist. |
| GAP-P2-002 | STPA/CAST-based system-theoretic risk analysis | Agentic AI is more vulnerable to structural failures and cascading failures than to individual vulnerabilities. | STPA-Sec or CAST format hazard/control loop analysis is performed for high-risk use cases. |
| GAP-P2-003 | China/India/Australia market matrix | A global product must decide whether to support major markets with profiles or explicitly exclude them. | A profile or exclusion rationale for PIPL, DPDP Act, and Australia Privacy Act is documented. |
| GAP-P2-004 | Optional commercialization path | OSS/self-hosted is the current priority, but commercial support, consulting, and managed offerings may be chosen long-term. | Partner/channel, support policy, SLA, and pricing/SKU are documented separately only when commercialization is revisited. |
| GAP-P2-005 | Performance/soak budget | Filtering and encryption directly affect latency and cost. | p95/p99 latency, throughput, memory, regex CPU limits, and telemetry overhead budget are verified through CI/soak tests. |

## 5. Key Findings by Expert Persona

| Persona | Key Findings |
|---|---|
| Security/Crypto | AAD canonicalization, nonce/replay, key lifecycle, token vault, and signed policy are all P0. |
| AI/MCP/A2A Architecture | Per-protocol transport/auth/lifecycle contracts, observability boundaries, RAG/vector, agent memory, and multi-tenancy are all underdefined. |
| Global Compliance | EU AI Act, ISO 27001/27701/42001, NIST AI RMF/CSF, OWASP GenAI/Agentic, and US state privacy expansions require reference profiles and exclusion rationale. |
| Product/Business | Adoption is the priority over sales for now. Quickstart, package boundaries, examples, README, SECURITY.md, and plugin conformance are the key deliverables. |
| Test Strategy | Security requirements must be enforced as build-blocking CI gates. Plaintext leak, policy conflict, KMS fault, replay, global profile violations, and DSL fuzzing are the critical test areas. |

## 6. Documents to Add Immediately

| Priority | Document | Purpose |
|---|---|---|
| 1 | `crypto-envelope-spec.md` | Define AAD canonicalization, envelope version, nonce, replay, and key lifecycle |
| 2 | `security-test-spec-ai-llm-mcp.md` | Define build-blocking negative tests and red-team corpus |
| 3 | `protocol-security-contract-mcp-a2a-grpc.md` | Per-adapter transport, auth, lifecycle, and metadata scrub contracts for MCP/A2A/gRPC/LLM |
| 4 | `open-source-modular-architecture.md` | OSS/self-hosted package boundaries, provider/plugin API, conformance tests |
| 5 | `self-hosted-shared-responsibility.md` | Per-mode key custody, telemetry, and user/maintainer responsibility for library/CLI/proxy/sidecar |
| 6 | `rag-agent-memory-protection-design.md` | Protection for RAG/vector DB, source metadata, citations, and agent memory lifecycle |
| 7 | `optional-enterprise-evidence-pack.md` | SOC 2, ISO, DPA, SCC/IDTA, and BAA evidence for when commercialization is revisited |

## 7. Official References

- Model Context Protocol latest specification: https://modelcontextprotocol.io/specification/
- MCP authorization: https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization
- MCP security best practices: https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices
- NSA, Model Context Protocol Security Design Considerations, May 2026: https://www.nsa.gov/Portals/75/documents/Cybersecurity/CSI_MCP_SECURITY.pdf
- NSA/Five Eyes, Careful Adoption of Agentic AI Services, April 2026: https://media.defense.gov/2026/Apr/30/2003922823/-1/-1/0/CAREFUL%20ADOPTION%20OF%20AGENTIC%20AI%20SERVICES_FINAL.PDF
- A2A Protocol latest specification: https://a2a-protocol.org/latest/specification/
- NIST AI Risk Management Framework: https://www.nist.gov/itl/ai-risk-management-framework
- NIST Cybersecurity Framework 2.0: https://www.nist.gov/cyberframework
- NIST Generative AI Profile, AI 600-1: https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf
- European Commission, AI Act enters into force: https://commission.europa.eu/news-and-media/news/ai-act-enters-force-2024-08-01_en
- OWASP Top 10 for LLM Applications 2025: https://genai.owasp.org/resource/owasp-top-10-for-llm-applications-2025/
- OWASP Top 10 for Agentic Applications 2026: https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/
- ISO/IEC 27001:2022: https://www.iso.org/standard/27001
- ISO/IEC 27701:2025: https://www.iso.org/standard/27701
- ISO/IEC 42001:2023: https://www.iso.org/standard/42001
- AICPA SOC Suite of Services: https://www.aicpa-cima.com/resources/landing/system-and-organization-controls-soc-suite-of-services
