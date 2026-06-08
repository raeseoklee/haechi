# PRD: AI/LLM/MCP 특화 암호화 솔루션

- 문서 상태: Draft 0.1
- 작성일: 2026-06-08
- 제품 가칭: AI Context Encryption Layer, AICEL
- 기준: 초기 PRD/SRS/보안검토 아카이브를 AI/LLM/MCP 특화 방향으로 재정렬

## 1. 목적

AICEL은 AI 애플리케이션, LLM gateway, MCP client/server, agent runtime, A2A agent network에서 오가는 prompt, context, tool-call, resource, retrieval snippet, artifact, streaming event를 보호하는 암호화 솔루션이다.

핵심 목적은 단순 전송구간 보호가 아니라, AI 워크플로우의 의미 단위인 `message`, `tool call`, `resource`, `task`, `context`, `artifact`, `agent identity`를 암호화 정책과 키 관리의 단위로 끌어올리는 것이다.

초기 제품 형태는 SaaS가 아니라 오픈소스/self-hosted 보안 인프라다. 사용자는 AICEL을 라이브러리, CLI, sidecar proxy, MCP wrapper 형태로 자기 AI 애플리케이션에 붙이고, 암호화 방식, 정책 평가, 개인정보 필터링, 감사 저장소를 자기 환경에 맞게 갈아끼울 수 있어야 한다.

## 2. 배경

일반 TLS는 client와 server 사이의 전송 채널을 보호한다. 그러나 LLM/agent 시스템에서는 다음 지점에서 평문 노출이 반복된다.

- LLM gateway, prompt router, observability pipeline
- MCP client와 server 사이의 JSON-RPC message
- MCP tool input/output, resource content, prompt template
- RAG retrieval snippet과 vector metadata
- A2A agent message, task state, artifact
- gRPC streaming chunk와 metadata
- agent tool-call 로그, trace, replay record
- model provider 전송 전후의 prompt/context 변환 지점

AICEL은 이런 AI-native 데이터 단위를 정책 기반으로 암호화, 토큰화, redaction, 권한 평가, 감사하는 계층이다.

개인정보 필터링은 AICEL의 핵심 기능이다. 암호화는 데이터를 보호하지만, 모델이나 tool에 평문으로 공개되는 순간에는 별도 통제가 필요하다. AICEL은 prompt, context, MCP tool input/output, resource, retrieval snippet, generated artifact에서 개인정보를 탐지하고 `allow`, `redact`, `mask`, `tokenize`, `encrypt`, `block`, `human-review` 중 하나로 처리한다.

## 3. 제품 포지셔닝

AICEL은 범용 보안솔루션, LLM gateway, MCP framework, agent framework를 대체하지 않는다. AI/LLM/MCP 대상 솔루션에 추가 장착되는 암호화 및 context protection module이다.

상용화나 SaaS control plane은 초기 목표가 아니다. 초기 포지셔닝은 "작지만 검증 가능한 OSS core + 교체 가능한 reference engine + 실사용 가능한 AI/MCP 예제"다. AICEL이 제공하는 기본 구현은 정답이 아니라 기준 구현이며, 사용자는 `CryptoProvider`, `PolicyEngine`, `FilterEngine`, `KeyProvider`, `AuditSink` 같은 경계를 통해 자체 구현을 주입할 수 있어야 한다.

| 대상 솔루션 | 적용 방식 |
|---|---|
| LLM gateway | OpenAI-compatible/Anthropic-compatible HTTP adapter 또는 middleware |
| MCP host/client | MCP client proxy, SDK wrapper, policy interceptor |
| MCP server | tool/resource/prompt response encryption wrapper |
| Agent runtime | task/context/artifact scoped encryption |
| A2A server/client | AgentCard 검증, message/task/artifact 암호화 adapter |
| gRPC AI service | protobuf field encryption, streaming message protection |
| RAG pipeline | retrieval snippet, source metadata, artifact encryption |
| Observability platform | prompt/tool/result redaction, sealed audit event |

## 4. 핵심 차별점

- AI 의미 단위 보호: prompt, system message, tool args, tool result, MCP resource, A2A artifact를 별도 보호 대상으로 취급한다.
- Context-bound encryption: tenant, user, agent, model, task, context, tool, resource URI를 AAD와 복호화 권한 평가에 포함한다.
- Policy before model: 어떤 정보가 모델에 평문으로 공개될 수 있는지 정책으로 결정한다.
- Selective reveal: 모델이 반드시 알아야 하는 부분만 평문으로 공개하고 나머지는 토큰화 또는 암호문으로 유지한다.
- MCP/A2A native: JSON-RPC id, method, session id, task id, artifact id, AgentCard, streaming event를 정책 context로 사용한다.
- Observability-safe: 로그, trace, metric, replay artifact에 prompt와 tool output이 평문으로 남지 않도록 한다.
- Privacy filtering first: 모델, agent, tool, 로그로 전달되기 전에 개인정보를 먼저 탐지하고 정책을 적용한다.
- Easy adoption: 기존 AI 애플리케이션을 크게 수정하지 않고 proxy, middleware, SDK wrapper, sidecar, config preset으로 붙일 수 있어야 한다.

## 5. 비목표

- LLM이 암호문을 직접 이해하게 만드는 범용 암호기법은 목표가 아니다.
- 완전동형암호 기반 LLM 추론은 MVP 범위가 아니다.
- 모든 외부 LLM provider에 대해 종단간 비가시성을 보장한다고 주장하지 않는다.
- prompt injection 자체를 완전히 방지한다고 주장하지 않는다.
- MCP 또는 A2A protocol 자체를 대체하지 않는다.
- 초기 버전에서 hosted SaaS, multi-tenant control plane, 과금, SLA, 영업용 compliance pack을 제공하지 않는다.
- 자체 암호 primitive를 발명하지 않는다. 검증된 표준과 라이브러리를 조합하고, 구현 경계를 테스트한다.

## 6. 사용자군

| 사용자군 | 요구 |
|---|---|
| AI 플랫폼 보안책임자 | prompt/context/tool-call 평문 노출 최소화 |
| LLM gateway 운영자 | provider별 policy, redaction, encryption, audit |
| MCP 서버 개발자 | tool input/output과 resource content 보호 |
| Agent framework 개발자 | task/context/artifact 단위 암호화 |
| RAG 운영자 | retrieval snippet과 source metadata 보호 |
| 준법/감사 담당자 | 누가 어떤 context를 어떤 모델/agent/tool에 공개했는지 추적 |
| 개인정보보호 책임자 | 개인정보, 고유식별정보, 민감정보의 AI 처리 전 필터링과 공개 범위 통제 |
| 오픈소스 도입 개발자 | 기본 구현을 참고하되 crypto, policy, filtering, audit 구현을 쉽게 교체 |
| OSS 기여자/리뷰어 | 작은 범위에서도 보안 설계, 테스트, 문서화 수준이 검증된 프로젝트 확인 |

## 7. 비즈니스 요구사항

| ID | 요구사항 | 우선순위 | 검증 |
|---|---|---:|---|
| BR-AI-001 | 제품은 AI/LLM/MCP 대상 솔루션에 추가 장착 가능한 암호화 모듈로 제공되어야 한다. | Must | PoC |
| BR-AI-002 | 제품은 prompt, context, tool-call, resource, artifact의 평문 노출 지점을 줄여야 한다. | Must | threat model |
| BR-AI-003 | 제품은 MCP stdio와 Streamable HTTP를 모두 고려한 adapter 전략을 제공해야 한다. | Must | MCP PoC |
| BR-AI-004 | 제품은 gRPC streaming과 A2A message/task/artifact 보호를 지원해야 한다. | Should | protocol PoC |
| BR-AI-005 | 제품은 외부 LLM provider 사용 시 평문 공개 범위를 정책적으로 제어해야 한다. | Must | policy test |
| BR-AI-006 | 제품은 로그, trace, replay, metric에서 AI 민감정보를 제거하거나 봉인해야 한다. | Must | observability test |
| BR-AI-007 | 제품은 KMS/HSM/Vault 기반 키 관리와 tenant/agent/task 단위 key separation을 지원해야 한다. | Must | key test |
| BR-AI-008 | 제품은 개인정보, 고유식별정보, 민감정보, credential, secret을 모델/tool/agent 공개 전에 탐지하고 정책적으로 처리해야 한다. | Must | privacy filtering test |
| BR-AI-009 | 제품은 한국 개인정보 환경을 고려한 탐지 규칙과 고객별 custom entity rule을 지원해야 한다. | Should | Korean PII fixture test |
| BR-AI-010 | 제품은 한국, EU/UK, 미국, 일본, 싱가포르, 캐나다, 브라질 등 주요 시장의 개인정보 규제 프로파일을 정책으로 선택할 수 있어야 한다. | Must | regional profile test |
| BR-AI-011 | 제품은 cross-border transfer, data residency, subprocessors, model provider region을 정책 결정 context에 포함해야 한다. | Must | transfer policy test |
| BR-AI-012 | 제품은 정보주체 권리 대응, 감사, DPIA/PIA, DSAR export를 지원할 수 있는 decision record와 data flow evidence를 남겨야 한다. | Should | audit evidence review |
| BR-AI-013 | 제품은 고객/tenant별 커스텀 필터링 규칙, dictionary, classifier, action override를 지원해야 한다. | Must | custom filter test |
| BR-AI-014 | 제품은 AAD canonicalization, nonce/replay 방어, key lifecycle, signed policy distribution을 암호 보안의 1급 요구사항으로 제공해야 한다. | Must | crypto negative test |
| BR-AI-015 | 제품은 MCP, A2A, gRPC, LLM gateway adapter별 transport, auth, lifecycle, metadata scrub 보안 계약을 정의해야 한다. | Must | protocol contract test |
| BR-AI-016 | 제품은 hosted SaaS 의존 없이 library, CLI, local proxy, self-hosted sidecar로 사용할 수 있어야 하며 key custody와 telemetry 경계를 명시해야 한다. | Must | deployment review |
| BR-AI-017 | 제품은 상용 evidence pack보다 OSS 신뢰 자료를 우선 제공해야 한다: `SECURITY.md`, threat model, conformance test, SBOM, signed release artifact, 보안 테스트 결과. | Must | OSS trust review |
| BR-AI-018 | 제품은 plaintext leak, policy conflict, KMS fault, replay, region-deny, custom DSL bypass를 build-blocking security test로 검증해야 한다. | Must | CI gate test |
| BR-AI-019 | 제품은 암호화, 키 관리, 정책 평가, 개인정보 필터링, token vault, audit, protocol adapter를 교체 가능한 provider interface로 분리해야 한다. | Must | plugin boundary review |
| BR-AI-020 | 제품은 기본 reference implementation을 제공하되 사용자가 자체 구현을 주입할 수 있는 dependency injection, plugin manifest, compatibility contract를 제공해야 한다. | Must | plugin conformance test |
| BR-AI-021 | 제품은 plugin이 평문 접근, 네트워크 송신, 파일 쓰기, audit 기록 같은 capability를 명시하고 fail-closed 정책으로 평가되도록 해야 한다. | Must | plugin security test |
| BR-AI-022 | 제품은 기존 AI/LLM/MCP 대상 솔루션에 낮은 변경 비용으로 적용되어야 하며, 5분 local demo, 30분 MCP/LLM PoC, 1일 내 custom filter PoC를 목표로 해야 한다. | Must | adoption test |
| BR-AI-023 | 제품은 보안 기본값을 유지하면서도 `init`, preset policy, dry-run, report-only mode, copy-paste middleware 예제로 적용 장벽을 낮춰야 한다. | Must | quickstart review |

## 8. 제품 요구사항

| ID | 요구사항 | 우선순위 |
|---|---|---:|
| PRD-AI-001 | 제품은 prompt message role별 암호화, redaction, tokenization 정책을 지원해야 한다. | Must |
| PRD-AI-002 | 제품은 MCP JSON-RPC method별 정책을 지원해야 한다. | Must |
| PRD-AI-003 | 제품은 MCP tool input/output, resource content, prompt template을 보호 대상으로 분류해야 한다. | Must |
| PRD-AI-004 | 제품은 A2A agent id, task id, context id, artifact id를 암호화 AAD와 복호화 권한 평가에 포함해야 한다. | Should |
| PRD-AI-005 | 제품은 gRPC protobuf field encryption과 opaque message encryption을 모두 지원 가능한 구조를 가져야 한다. | Should |
| PRD-AI-006 | 제품은 streaming chunk별 nonce와 stream/session binding을 지원해야 한다. | Should |
| PRD-AI-007 | 제품은 모델 provider로 평문을 보내기 전 policy decision record를 남겨야 한다. | Must |
| PRD-AI-008 | 제품은 prompt/tool/resource/artifact 로그를 기본 redaction 처리해야 한다. | Must |
| PRD-AI-009 | 제품은 customer-managed key와 provider-managed key를 구분해야 한다. | Must |
| PRD-AI-010 | 제품은 MCP/A2A discovery metadata의 신뢰 검증과 allowlist를 지원해야 한다. | Should |
| PRD-AI-011 | 제품은 deterministic rule, checksum validation, dictionary/NER, pluggable classifier를 조합한 개인정보 필터링 pipeline을 제공해야 한다. | Must |
| PRD-AI-012 | 제품은 주민등록번호, 외국인등록번호, 여권번호, 운전면허번호, 휴대전화번호, 이메일, 주소, 계좌번호, 카드번호, 건강정보, 생체정보, 인증정보, API key/secret을 기본 탐지 대상으로 포함해야 한다. | Must |
| PRD-AI-013 | 제품은 개인정보 탐지 결과별 처리방식을 `redact`, `mask`, `tokenize`, `encrypt`, `block`, `human-review`로 지정할 수 있어야 한다. | Must |
| PRD-AI-014 | 제품은 모델 호출 전 pre-filter와 모델/tool 응답 후 post-filter를 모두 지원해야 한다. | Must |
| PRD-AI-015 | 제품은 필터링 결과의 원문을 로그에 남기지 않고 entity type, confidence, rule id, action, decision id만 감사해야 한다. | Must |
| PRD-AI-016 | 제품은 regional privacy profile을 통해 탐지 카탈로그, 기본 action, transfer rule, retention rule, audit field를 전환할 수 있어야 한다. | Must |
| PRD-AI-017 | 제품은 GDPR/UK GDPR의 personal data, special category data, pseudonymisation, international transfer 요구를 정책 항목으로 표현할 수 있어야 한다. | Must |
| PRD-AI-018 | 제품은 CCPA/CPRA의 sensitive personal information과 limit-use 요구를 정책 항목으로 표현할 수 있어야 한다. | Should |
| PRD-AI-019 | 제품은 HIPAA PHI와 PCI cardholder data를 sector profile로 분리해 탐지, redaction, tokenization, logging 금지 정책을 적용할 수 있어야 한다. | Should |
| PRD-AI-020 | 제품은 global deployment에서 tenant별 data residency와 model provider region allowlist를 강제할 수 있어야 한다. | Must |
| PRD-AI-021 | 제품은 regex, checksum validator, keyword dictionary, deny/allow list, JSONPath/protobuf path, semantic classifier를 조합한 custom filter DSL을 제공해야 한다. | Must |
| PRD-AI-022 | 제품은 custom filter rule의 draft, validate, test, approve, publish, rollback lifecycle을 지원해야 한다. | Must |
| PRD-AI-023 | 제품은 custom filter rule 충돌 시 global profile, sector profile, tenant rule, app rule, emergency rule의 우선순위를 명확히 적용해야 한다. | Must |
| PRD-AI-024 | 제품은 고객이 제공한 custom dictionary와 fixture를 암호화 저장하고 audit 가능한 접근통제를 적용해야 한다. | Should |
| PRD-AI-025 | 제품은 custom classifier plugin을 local-only, customer-managed endpoint, external endpoint 중 하나로 배포할 수 있어야 한다. | Should |
| PRD-AI-026 | 제품은 암호화 AAD를 canonical JSON, Unicode normalization, tenant/user/agent/model/task/tool/resource/policy version으로 고정해야 한다. | Must |
| PRD-AI-027 | 제품은 streaming chunk, retry, cancellation, partial delivery에서 nonce uniqueness, stream sequence, replay cache를 강제해야 한다. | Must |
| PRD-AI-028 | 제품은 key 생성, rotation, rewrap, retirement, destruction evidence, backup/restore drill을 key lifecycle로 관리해야 한다. | Must |
| PRD-AI-029 | 제품은 token vault의 retention, deletion, DSAR export, re-identification approval, access audit을 지원해야 한다. | Must |
| PRD-AI-030 | 제품은 policy bundle 서명, version pinning, emergency block, fail-closed validation, stale policy rejection을 지원해야 한다. | Must |
| PRD-AI-031 | 제품은 MCP authorization, token passthrough 금지, per-client consent, stdio credential handling, protocol version negotiation을 검증해야 한다. | Must |
| PRD-AI-032 | 제품은 A2A AgentCard signature, authenticated extended card, transport parity, push notification security를 검증해야 한다. | Should |
| PRD-AI-033 | 제품은 OpenTelemetry baggage, span attribute, metric label, exception, crash dump, replay artifact에서 원문 민감정보를 제거해야 한다. | Must |
| PRD-AI-034 | 제품은 provider-neutral LLM message schema와 provider adapter mapping을 가져야 한다. | Should |
| PRD-AI-035 | 제품은 RAG/vector namespace, embedding/source metadata, citation, index deletion propagation 정책을 지원해야 한다. | Should |
| PRD-AI-036 | 제품은 agent memory를 ephemeral/durable로 구분하고 TTL, purge, export, cross-task recall 차단을 지원해야 한다. | Should |
| PRD-AI-037 | 제품은 tenant별 config store, audit sink, quota, admin RBAC, blast-radius 제한을 제공해야 한다. | Must |
| PRD-AI-038 | 제품은 SBOM, artifact signing, provenance, dependency vulnerability policy, classifier/plugin trust policy를 제공해야 한다. | Should |
| PRD-AI-039 | 제품은 `CryptoProvider` interface를 통해 envelope encryption, decrypt, rewrap, key id resolution을 교체 가능하게 제공해야 한다. | Must |
| PRD-AI-040 | 제품은 `KeyProvider` interface를 통해 local key, Vault, KMS, HSM, test key provider를 동일 계약으로 연결할 수 있어야 한다. | Must |
| PRD-AI-041 | 제품은 `PolicyEngine` interface를 통해 JSON/YAML reference policy 외에 CEL, OPA/Rego, 사용자 자체 정책 엔진을 연결할 수 있어야 한다. | Must |
| PRD-AI-042 | 제품은 `FilterEngine` interface를 통해 rule/checksum/dictionary 기반 reference filter와 사용자 자체 classifier를 교체할 수 있어야 한다. | Must |
| PRD-AI-043 | 제품은 `TokenVault` interface를 통해 local encrypted vault, DB-backed vault, external vault를 교체할 수 있어야 한다. | Should |
| PRD-AI-044 | 제품은 `AuditSink` interface를 통해 JSONL, OpenTelemetry-safe exporter, SIEM webhook, custom sink를 교체할 수 있어야 한다. | Must |
| PRD-AI-045 | 제품은 `ProtocolAdapter` interface를 통해 MCP, LLM HTTP, gRPC, A2A adapter가 같은 protect/reveal pipeline을 사용하도록 해야 한다. | Must |
| PRD-AI-046 | 제품은 모든 provider/plugin에 대해 golden fixture, negative fixture, capability manifest, compatibility version test를 제공해야 한다. | Must |
| PRD-AI-047 | 제품은 기존 코드를 거의 수정하지 않는 local proxy mode를 제공해야 한다. 사용자는 target base URL과 policy file만 지정해 LLM/MCP 요청을 우회시킬 수 있어야 한다. | Must |
| PRD-AI-048 | 제품은 10줄 이내의 SDK wrapper/middleware 예제로 Node와 Python AI 앱에 적용할 수 있어야 한다. | Must |
| PRD-AI-049 | 제품은 `aicel init` 또는 동등한 CLI로 sample policy, local key, audit path, MCP/LLM preset을 생성해야 한다. | Must |
| PRD-AI-050 | 제품은 `dry-run` 또는 `report-only` mode를 제공해 실제 차단/암호화 전에 어떤 prompt/tool/resource가 탐지될지 확인할 수 있어야 한다. | Must |
| PRD-AI-051 | 제품은 기본 preset을 제공해야 한다: `mcp-basic`, `llm-redact`, `korean-pii`, `secrets-only`, `local-only`, `strict-block`. | Must |
| PRD-AI-052 | 제품은 사용자가 `CryptoProvider`, `PolicyEngine`, `FilterEngine`, `AuditSink`를 코드 수정 없이 config에서 교체할 수 있는 경로를 제공해야 한다. | Should |
| PRD-AI-053 | 제품은 적용 실패 시 원문 유출보다 요청 차단을 우선하되, 개발 모드에서는 원인과 수정 방법을 평문 데이터 없이 설명해야 한다. | Must |

## 9. MVP 범위

MVP는 좁게 시작한다.

실제 0.1 구현 범위는 `docs/current/mvp-0.1-implementation-scope.md`를 기준으로 한다. 아래 항목 중 Python SDK, Vault/KMS adapter, MCP stdio wrapper, RAG sample은 0.1 이후로 넘길 수 있다.

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
- 개인정보 필터링 pipeline
- 한국 개인정보 기본 탐지 규칙
- Vault 또는 AWS KMS adapter 중 1개
- local software key provider
- JSON policy file
- audit event JSON Lines
- MCP tool-call sample
- RAG snippet protection sample
- reference `CryptoProvider`, `PolicyEngine`, `FilterEngine`, `KeyProvider`, `AuditSink`

MVP에서 제외한다.

- 완전동형암호 또는 암호문 LLM 추론
- 모든 LLM provider native SDK 지원
- KCMVP provider 내장
- A2A full server implementation
- gRPC bidirectional streaming production adapter
- GUI 관리 콘솔
- hosted SaaS control plane
- 과금, tenant admin portal, SLA
- SOC 2/ISO 상용 evidence pack

## 10. 핵심 보안 원칙

- 모델이 처리해야 하는 값과 모델이 볼 필요가 없는 값을 분리한다.
- 개인정보는 모델 공개 전에 먼저 분류하고, 공개 목적이 명확하지 않으면 기본 차단 또는 tokenization한다.
- 모델 provider에 평문으로 공개한 데이터는 더 이상 AICEL만으로 비가시성을 보장할 수 없다고 명시한다.
- tool-call과 resource 결과는 기본적으로 민감정보로 취급한다.
- agent/task/context 경계를 AAD와 복호화 권한에 포함한다.
- observability pipeline은 제품의 1급 보안 경계로 취급한다.
- prompt injection 방어와 암호화는 별도 통제이며, 어느 하나가 다른 하나를 대체하지 않는다.
- 교체 가능한 provider/plugin은 신뢰 경계다. 평문 접근, 네트워크 송신, 파일 쓰기, audit 조작 가능성을 capability로 드러내고 테스트한다.
- reference implementation은 사용자가 바꿀 수 있어야 하지만, conformance test와 보안 negative test는 바꾸지 않는 기준선으로 유지한다.

## 11. 미결정 사항

- MCP adapter를 proxy 우선으로 만들지 SDK wrapper 우선으로 만들지 결정해야 한다.
- OpenAI-compatible API를 1차 LLM adapter로 둘지 provider-agnostic schema를 먼저 만들지 결정해야 한다.
- RAG vector search에서 embedding 자체를 보호할지, source text와 metadata 보호에 집중할지 결정해야 한다.
- A2A는 adapter 수준으로 둘지 full protocol gateway로 갈지 결정해야 한다.
- confidential computing/TEE를 2차 로드맵에 포함할지 결정해야 한다.
- 개인정보 탐지에서 ML/LLM classifier를 사용할 경우 그 classifier 자체에 개인정보를 평문 전송할지 여부를 결정해야 한다.
- 주민등록번호 등 고위험 식별자는 기본 block으로 둘지, 고객 정책에 따라 tokenization을 허용할지 결정해야 한다.
- EU/UK 데이터에 대해 SCC/IDTA 등 transfer mechanism 검증을 제품이 evidence로만 지원할지, policy enforcement까지 할지 결정해야 한다.
- HIPAA/PCI 같은 sector profile을 MVP에 포함할지 후순위 예제로 둘지 결정해야 한다.
- custom filter DSL을 제품 자체 문법으로 만들지, OPA/Rego 또는 CEL 같은 기존 정책 언어를 부분 채택할지 결정해야 한다.
- custom classifier plugin이 외부 endpoint를 호출할 때 개인정보 전송을 기본 금지할지 customer opt-in으로 둘지 결정해야 한다.
- provider/plugin API를 TypeScript 우선으로 안정화한 뒤 Python에 맞출지, 언어 중립 IDL을 먼저 둘지 결정해야 한다.
- 오픈소스 라이선스를 Apache-2.0으로 둘지 MIT로 둘지 결정해야 한다.

## 12. 참고

- Model Context Protocol Specification, latest: https://modelcontextprotocol.io/specification/
- Model Context Protocol Authorization: https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization
- Model Context Protocol Security Best Practices: https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices
- Model Context Protocol official repository: https://github.com/modelcontextprotocol/modelcontextprotocol
- NSA MCP Security Design Considerations: https://www.nsa.gov/Portals/75/documents/Cybersecurity/CSI_MCP_SECURITY.pdf
- NSA/Five Eyes Careful Adoption of Agentic AI Services: https://media.defense.gov/2026/Apr/30/2003922823/-1/-1/0/CAREFUL%20ADOPTION%20OF%20AGENTIC%20AI%20SERVICES_FINAL.PDF
- A2A Agent2Agent Protocol: https://a2a-protocol.org/latest/specification/
- gRPC Core Concepts: https://grpc.io/docs/what-is-grpc/core-concepts/
- 개인정보의 안전성 확보조치 기준: https://law.go.kr/LSW/admRulInfoP.do?admRulSeq=2100000192069&chrClsCd=010201
- KISA 암호이용 FAQ: https://seed.kisa.or.kr/kisa/bbs/faq.do
- European Commission GDPR overview: https://commission.europa.eu/law/law-topic/data-protection/reform/what-does-general-data-protection-regulation-gdpr-govern_en
- European Commission Standard Contractual Clauses: https://commission.europa.eu/law/law-topic/data-protection/international-dimension-data-protection/standard-contractual-clauses-scc_en
- California CCPA: https://www.oag.ca.gov/privacy/ccpa
- HHS HIPAA Privacy Rule: https://www.hhs.gov/hipaa/for-professionals/privacy/index.html
- NIST Privacy Framework: https://www.nist.gov/privacy-framework
- RFC 8446, TLS 1.3
- RFC 7516, JSON Web Encryption
- RFC 9180, Hybrid Public Key Encryption
