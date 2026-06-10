# 전문가 병렬 Gap Review: AI/LLM/MCP 특화 암호화 솔루션

- 문서 상태: Draft 0.1
- 작성일: 2026-06-08
- 관련 제품: Haechi
- 검토 방식: 보안/암호, AI/MCP/A2A 아키텍처, 글로벌 컴플라이언스, 제품/사업, 테스트 전략 페르소나 병렬 검토

## 1. 결론

현재 문서는 `무엇을 보호할 것인가`는 잘 잡고 있다. 다만 최신 방향은 SaaS 판매가 아니라 오픈소스/self-hosted 보안 인프라다. 따라서 아래 gap은 "초기 OSS core에 반드시 필요한 보안 gap"과 "상용화 또는 엔터프라이즈 도입을 고려할 때의 선택 backlog"로 나누어 해석한다.

초기 OSS core라도 다음 5개 축은 필요하다.

1. 암호/정책의 우회 불가능성: canonical AAD, nonce/replay, key lifecycle, signed policy, fail-closed.
2. 프로토콜별 운영 계약: MCP stdio/Streamable HTTP, A2A, gRPC, LLM gateway, RAG/vector, agent memory.
3. OSS 배포/신뢰 모델: self-hosted mode, key custody, telemetry boundary, SECURITY.md, conformance test, SBOM, signed release.
4. 글로벌 AI/개인정보 거버넌스: EU AI Act, NIST AI RMF/CSF, OWASP LLM/Agentic, US state privacy, sector profiles.
5. 적용성: 5분 local demo, 30분 MCP/LLM PoC, 1일 custom filter PoC, proxy/middleware/SDK/sidecar 적용 경로.
6. 검증 자동화: 표면별 plaintext leak sentinel, policy conflict matrix, KMS fault injection, streaming chaos, red-team corpus.

## 2. P0: 요구사항 Freeze 전 반드시 보강

| ID | 누락/보강 항목 | 왜 필요한가 | 수용 기준 |
|---|---|---|---|
| GAP-P0-001 | AAD canonicalization | JSON 재정렬, Unicode 변형, role/source spoofing, policy version 변경으로 복호화 context가 흔들릴 수 있다. | AAD schema, canonical JSON, Unicode normalization, policy version, tenant/user/agent/model/task/tool/resource binding이 고정되고 변형 입력은 복호화 실패한다. |
| GAP-P0-002 | nonce/replay/stream sequencing | streaming chunk, retry, partial delivery, duplicate request에서 nonce 재사용 또는 replay가 치명적이다. | 동일 nonce, cross-session replay, cross-tenant replay, out-of-order chunk, duplicate chunk가 모두 거부된다. |
| GAP-P0-003 | key lifecycle | KMS/HSM/Vault 사용만으로는 생성, 회전, 폐기, rewrap, backup/restore, blast radius가 정의되지 않는다. | tenant key rotation, retired key rejection, plaintext key non-export, rewrap job, restore drill, destruction evidence가 테스트된다. |
| GAP-P0-004 | token vault governance | 토큰화는 DSAR, deletion, retention, re-identification 권한 모델과 연결돼야 한다. | token mapping purge, dual control re-identification, DSAR export, retention expiry, decision record linkage가 검증된다. |
| GAP-P0-005 | signed policy distribution | client-supplied metadata, stale policy cache, allowlist 오남용으로 hard-block이 우회될 수 있다. | signed policy bundle, version pinning, server-side source classification, emergency rule precedence, fail-closed validation을 강제한다. |
| GAP-P0-006 | MCP transport security contract | MCP는 최신 스펙에서 authorization, lifecycle, protocol version, security best practices가 명시적으로 진화하고 있다. | `initialize`/`initialized`, `MCP-Protocol-Version`, OAuth resource binding, stdio env allowlist, token passthrough 금지, per-client consent가 테스트된다. |
| GAP-P0-007 | A2A discovery/auth parity | AgentCard, authenticated extended card, SSE/gRPC/REST binding, push notification 경계가 약하면 agent impersonation이 가능하다. | AgentCard signature/verification, security scheme parity, authenticated extended card, streaming/resubscribe/push security가 adapter별로 동일하다. |
| GAP-P0-008 | observability boundary | 로그뿐 아니라 trace baggage, headers, URL query, stack trace, crash dump, metric label, replay artifact에서 평문이 샌다. | 모든 telemetry sink에 sentinel PII/secret 원문이 남지 않고 hash/id/redaction metadata만 남는다. |
| GAP-P0-009 | OSS/self-hosted deployment modes | library, CLI, local proxy, sidecar, self-hosted service는 키 위치, egress, update, telemetry, 장애 경계가 다르다. | mode별 key custody, network egress, telemetry path, upgrade/rollback, local-only 동작이 명시된다. |
| GAP-P0-010 | open-source shared responsibility note | OSS 사용자는 법적 판단, transfer evidence, key custody, DSAR, incident response를 스스로 책임지는 범위를 알아야 한다. | README/SECURITY/docs에 maintainer responsibility, user responsibility, non-compliance disclaimer가 명시된다. |
| GAP-P0-011 | EU AI Act / AI governance mapping | Haechi가 AI 시스템 또는 AI governance component로 쓰이면 투명성, role 판정, incident 관련 해석이 필요할 수 있다. | provider/deployer/GPAI role 판단표, transparency note, incident log, AI risk register template을 참고 자료로 제공한다. |
| GAP-P0-012 | build-blocking security tests | 현재 검증 기준은 선언형이다. 보안 제품은 어떤 실패가 빌드를 막는지 명확해야 한다. | plaintext leak, policy conflict, KMS fault, replay, global profile, hard-block bypass 실패가 CI gate가 된다. |
| GAP-P0-013 | easy adoption path | 보안성이 높아도 적용이 어렵다면 OSS 확산과 실제 사용이 어렵다. | `haechi init`, dry-run/report-only, preset policy, local proxy, copy-paste middleware, 5분/30분/1일 적용 목표가 문서와 예제로 검증된다. |

## 3. P1: OSS 확산과 실사용 전 보강

| ID | 누락/보강 항목 | 왜 필요한가 | 수용 기준 |
|---|---|---|---|
| GAP-P1-001 | provider-neutral LLM message model | OpenAI-compatible schema만으로는 Anthropic, multimodal, structured output, tool/function call, streaming chunk를 일관되게 통제하기 어렵다. | 내부 canonical message schema와 provider adapter mapping, pre/post policy hook, chunk-level decision record가 존재한다. |
| GAP-P1-002 | MCP registry/provenance/cache invalidation | tools/resources/prompts 목록과 `listChanged` 이벤트가 오염되거나 stale하면 잘못된 tool 정책이 적용된다. | registry entry owner/version/hash/scope, cache invalidation, discovery auth, deterministic ordering을 검증한다. |
| GAP-P1-003 | gRPC streaming semantics | field encryption만으로 deadline, cancel, retry, ordering, metadata leakage를 다룰 수 없다. | deadline propagation, cancel audit, retry idempotency, metadata scrub, partial delivery semantics를 테스트한다. |
| GAP-P1-004 | RAG/vector DB protection | snippet 보호만으로는 embedding, vector namespace, citation, deletion propagation이 남는다. | tenant-scoped namespace, embedding/source metadata policy, index deletion propagation, citation redaction을 검증한다. |
| GAP-P1-005 | agent memory lifecycle | 장기 memory와 recall은 task/context 암호화만으로 통제되지 않는다. | ephemeral/durable memory 구분, TTL/purge/export, per-tenant/agent namespace, cross-task recall denial이 동작한다. |
| GAP-P1-006 | multi-tenant isolation | key separation만으로는 policy, audit, memory, rate limit, admin plane 격리가 부족하다. | tenant config store, audit sink, quota, provider allowlist, admin RBAC, blast-radius 제한이 분리된다. |
| GAP-P1-007 | SDK/proxy/plugin deployment model | 고객은 in-process SDK, sidecar, gateway plugin, server middleware 중 어떤 방식으로 적용할지 판단해야 한다. | 각 모드의 호환성, 장애 경계, 성능 비용, rollback, upgrade 정책이 명시된다. |
| GAP-P1-008 | custom DSL safety | 커스텀 필터는 parser bug, regex DoS, allowlist bypass, external classifier leakage의 공격 표면이다. | DSL fuzzing, regex resource limit, conflict golden test, classifier egress test가 CI에서 돈다. |
| GAP-P1-009 | supply chain integrity | SDK, connector, classifier plugin, policy package가 오염되면 보안 제품이 공격 경로가 된다. | SBOM, provenance, artifact signing, dependency vulnerability policy, plugin trust policy가 필요하다. |
| GAP-P1-010 | AI red-team corpus | prompt injection을 비목표로만 두면 tool-output injection, resource poisoning, exfiltration을 놓친다. | OWASP LLM/Agentic 위협과 매핑된 red-team corpus가 있고 차단 근거가 decision record에 남는다. |
| GAP-P1-011 | US privacy 확장 | CCPA/CPRA만으로 미국 전체 판매 대응은 부족하다. | Colorado, Connecticut, Virginia, Texas, Washington My Health My Data Act profile 또는 제외 사유가 정의된다. |
| GAP-P1-012 | sector operational controls | HIPAA/PCI는 식별자 탐지만으로 부족하다. | BAA, ePHI audit, breach workflow, SAD storage prohibition, retention/disposal, MFA evidence를 검증한다. |
| GAP-P1-013 | OSS trust evidence | 상용 인증은 후순위지만, 보안 OSS는 threat model, security policy, SBOM, release provenance, test result가 신뢰의 전제다. | SECURITY.md, threat model, SBOM, signed release, conformance 결과가 공개된다. |
| GAP-P1-014 | adoption packaging | 판매용 SKU는 필요 없지만 사용자가 어떤 모듈을 어떻게 붙일지 판단할 정보가 필요하다. | core/filter/policy/crypto/mcp/llm/audit package matrix와 example별 적용 가이드가 제공된다. |

## 4. P2: Roadmap / Hardening

| ID | 항목 | 이유 | 완료 기준 |
|---|---|---|---|
| GAP-P2-001 | crypto agility / PQC migration | envelope format은 장기 보존 데이터를 다룰 수 있으므로 알고리즘 폐기와 PQC 전환 계획이 필요하다. | envelope versioning, deprecation window, rewrap, HPKE/PQC 검토 메모가 존재한다. |
| GAP-P2-002 | STPA/CAST 기반 system-theoretic risk analysis | agentic AI는 단일 취약점보다 구조적 실패와 cascading failure가 중요하다. | high-risk use case에 STPA-Sec 또는 CAST 형식의 hazard/control loop 분석을 수행한다. |
| GAP-P2-003 | China/India/Australia market matrix | 글로벌 제품이라면 대형 시장을 profile로 지원할지 제외할지 결정해야 한다. | PIPL, DPDP Act, Australia Privacy Act에 대한 profile 또는 exclusion rationale을 남긴다. |
| GAP-P2-004 | optional commercialization path | 현재는 OSS/self-hosted가 우선이지만 장기적으로 상용 지원, 컨설팅, managed offering을 선택할 수 있다. | 상용화를 다시 검토할 때만 partner/channel, support policy, SLA, pricing/SKU를 별도 문서화한다. |
| GAP-P2-005 | performance/soak budget | 필터링과 암호화는 latency와 cost를 직접 만든다. | p95/p99 latency, throughput, memory, regex CPU limit, telemetry overhead budget을 CI/soak test로 검증한다. |

## 5. 전문가 페르소나별 핵심 발견

| 페르소나 | 핵심 발견 |
|---|---|
| 보안/암호 | AAD canonicalization, nonce/replay, key lifecycle, token vault, signed policy가 P0다. |
| AI/MCP/A2A 아키텍처 | 프로토콜별 transport/auth/lifecycle 계약, observability 경계, RAG/vector, agent memory, multi-tenancy가 부족하다. |
| 글로벌 컴플라이언스 | EU AI Act, ISO 27001/27701/42001, NIST AI RMF/CSF, OWASP GenAI/Agentic, 미국 주 privacy 확장은 참고 profile과 제외 사유가 필요하다. |
| 제품/사업 | 현재는 판매보다 adoption이 우선이다. quickstart, package boundary, examples, README, SECURITY.md, plugin conformance가 핵심이다. |
| 테스트 전략 | 보안 요구사항을 build-blocking CI gate로 내려야 한다. plaintext leak, policy conflict, KMS fault, replay, global profile, DSL fuzzing이 핵심이다. |

## 6. 즉시 추가해야 할 문서

| 우선순위 | 문서 | 목적 |
|---|---|---|
| 1 | `crypto-envelope-spec.md` | AAD canonicalization, envelope version, nonce, replay, key lifecycle 정의 |
| 2 | `security-test-spec-ai-llm-mcp.md` | build-blocking negative test와 red-team corpus 정의 |
| 3 | `protocol-security-contract-mcp-a2a-grpc.md` | MCP/A2A/gRPC/LLM adapter별 transport, auth, lifecycle, metadata scrub 계약 |
| 4 | `open-source-modular-architecture.md` | OSS/self-hosted package boundary, provider/plugin API, conformance test |
| 5 | `self-hosted-shared-responsibility.md` | library/CLI/proxy/sidecar mode별 key custody, telemetry, user/maintainer responsibility |
| 6 | `rag-agent-memory-protection-design.md` | RAG/vector DB, source metadata, citation, agent memory lifecycle 보호 |
| 7 | `optional-enterprise-evidence-pack.md` | 장기 상용화를 다시 검토할 때 SOC 2, ISO, DPA, SCC/IDTA, BAA 증빙 |

## 7. 공식 참고 자료

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
