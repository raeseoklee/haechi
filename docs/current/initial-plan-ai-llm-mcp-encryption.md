# 초기 계획: AI/LLM/MCP 특화 암호화 솔루션

- 문서 상태: Draft 0.1
- 작성일: 2026-06-08
- 제품 가칭: AI Context Encryption Layer, AICEL

## 1. 방향성 판단

AI, LLM, MCP에 특화한 암호화 솔루션은 범용 구간암호화보다 더 선명한 시장 포지션을 가진다. 일반 API 암호화 제품은 HTTP payload 보호에 머무는 경우가 많지만, AI 시스템은 prompt, context, tool-call, resource, retrieval snippet, artifact, streaming event라는 새로운 민감 데이터 단위를 가진다.

특히 MCP와 A2A는 agent와 tool 생태계가 확장될수록 보안 경계가 흐려진다. AICEL은 이 경계에 들어가서 "무엇을 어떤 agent, tool, model, provider에게 평문으로 보여줄 수 있는가"를 정책화하는 제품이 될 수 있다.

초기 방향은 SaaS가 아니라 오픈소스/self-hosted 보안 프로젝트다. 따라서 1차 목표는 판매 가능한 control plane이 아니라, 보안 설계가 선명한 core interface, 교체 가능한 reference engine, conformance test, MCP/LLM 실사용 예제를 공개하는 것이다.

## 2. 핵심 가설

| ID | 가설 | 검증 방법 |
|---|---|---|
| HYP-001 | 기업은 LLM gateway 로그에 prompt/tool output이 평문으로 남는 것을 줄이고 싶어 한다. | AI gateway PoC |
| HYP-002 | MCP server 개발자는 tool input/output과 resource content를 안전하게 노출하는 공통 모듈을 원한다. | MCP server sample |
| HYP-003 | agent-to-agent 시스템에서는 task/context/artifact 단위 복호화 권한이 필요하다. | A2A adapter PoC |
| HYP-004 | "모델이 꼭 봐야 하는 정보"와 "시스템이 보관/전달만 해야 하는 정보"를 분리하면 암호화 제품 가치가 커진다. | selective reveal demo |
| HYP-005 | 보안팀과 OSS 도입자는 KMS/HSM, audit, policy, redaction을 agent framework 바깥에서 통제하고 싶어 한다. | OSS adopter / security reviewer interview |
| HYP-006 | 기업은 LLM/MCP 도입 시 개인정보 필터링을 암호화만큼 중요한 기본 통제로 요구한다. | Korean PII filtering PoC |
| HYP-007 | 글로벌 고객은 지역별 privacy profile과 data residency/model provider region 통제를 요구한다. | regional profile PoC |
| HYP-008 | 고객은 내부 식별자와 기밀명칭을 직접 등록하는 custom filtering 기능을 요구한다. | custom rule DSL PoC |
| HYP-009 | OSS 도입자는 완성형 SaaS보다 자기 환경에 맞게 crypto, policy, filtering, audit 구현을 갈아끼울 수 있는 작은 core를 선호한다. | plugin API PoC + conformance tests |
| HYP-010 | 보안 도구라도 적용이 어렵다면 확산되지 않는다. 5분 local demo, 30분 MCP/LLM PoC, 1일 custom filter PoC가 가능해야 한다. | quickstart usability test |

## 3. 우선순위 유스케이스

### 3.1 MCP Tool-call 보호

- MCP client가 tool call을 생성한다.
- AICEL policy가 tool name, arguments schema, tenant, user, agent id를 평가한다.
- 민감 argument는 tokenization 또는 envelope encryption으로 보호한다.
- MCP server는 허용된 context에서만 복호화한다.
- tool result는 기본 redaction 후 agent에게 반환한다.

### 3.2 MCP Resource 보호

- resource URI와 content classification을 policy에 매핑한다.
- resource content는 tenant/resource scope key로 암호화한다.
- LLM에게는 원문 대신 redacted summary 또는 reference token을 제공한다.
- 감사로그에는 resource URI hash, policy id, key id, decision id만 남긴다.

### 3.3 LLM Gateway Prompt 보호

- HTTP request에서 system/developer/user/tool message를 분리한다.
- PII, secret, credential, source code, customer data를 탐지한다.
- provider 전송 전 reveal, redact, tokenize, block 중 하나로 결정한다.
- provider별 평문 공개 범위와 audit event를 기록한다.

### 3.4 개인정보 필터링

- prompt, MCP tool argument, resource content, RAG snippet, generated artifact를 필터링 대상으로 수집한다.
- deterministic rule과 checksum으로 주민등록번호, 외국인등록번호, 카드번호 등 구조화 식별자를 우선 탐지한다.
- 이메일, 전화번호, 주소, 계좌번호, API key, access token, secret은 rule과 pattern library로 탐지한다.
- 이름, 조직, 의료/건강정보, 생체정보, 민감 추론 정보는 dictionary/NER/pluggable classifier로 탐지한다.
- 탐지 결과는 정책에 따라 mask, redact, tokenize, encrypt, block, human-review 중 하나로 처리한다.
- 필터링 감사로그에는 원문을 남기지 않고 entity type, rule id, confidence, action, decision id만 남긴다.

### 3.5 A2A Task/Artifact 보호

- AgentCard discovery 결과를 검증한다.
- task id, context id, source agent, target agent를 AAD에 포함한다.
- artifact는 task-scoped key로 암호화한다.
- 다른 task/context/agent에서 artifact 복호화를 시도하면 거부한다.

### 3.6 gRPC Streaming 보호

- service/method/message type을 policy context로 사용한다.
- stream/session key와 chunk nonce를 분리한다.
- cancellation, retry, redelivery, partial delivery를 audit event로 남긴다.
- metadata leakage를 별도 검사한다.

## 4. 아키텍처 초안

```text
AI App / Agent Runtime / MCP Host
        |
        v
AICEL SDK / CLI / Local Proxy / Sidecar
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

## 5. 설계 원칙

- Protocol-aware: 단순 byte stream이 아니라 MCP method, A2A task, gRPC method, LLM message role을 이해한다.
- Context-bound: 암호문은 tenant, user, agent, model, task, context, tool, resource에 바인딩된다.
- Selective reveal: 모델에게 필요한 최소 정보만 평문으로 공개한다.
- Observability-safe: trace와 replay는 기본적으로 민감정보를 담지 않는다.
- Provider-neutral: 특정 LLM vendor에 종속되지 않는다.
- Fail-closed: 민감정보 분류가 있는 payload는 정책 실패 시 차단한다.
- OSS-first: hosted SaaS 없이 라이브러리, CLI, local proxy, self-hosted sidecar로 작동한다.
- Pluggable by default: crypto, key, policy, filtering, audit은 기본 구현보다 interface와 test contract가 더 중요하다.
- Reference implementation is replaceable: 기본 구현은 학습과 PoC를 위한 기준이며 사용자 환경에 맞게 교체 가능해야 한다.
- Test fixtures as API: plugin 작성자가 fixture와 conformance test로 호환성을 검증할 수 있어야 한다.
- Easy adoption: proxy, middleware, SDK wrapper, sidecar, preset policy 중 하나로 기존 앱에 낮은 변경 비용으로 붙을 수 있어야 한다.
- Progressive hardening: 처음에는 dry-run/report-only로 탐지 결과를 확인하고, 이후 redact/tokenize/encrypt/block을 단계적으로 강제한다.

## 6. 1차 기술 스택 제안

| 영역 | 제안 |
|---|---|
| SDK | TypeScript/Node, Python |
| Policy | JSON/YAML + JSON Schema |
| Crypto format | JWE JSON serialization 또는 compact envelope |
| KMS | Vault 또는 AWS KMS |
| MCP | Streamable HTTP proxy, stdio wrapper |
| LLM adapter | OpenAI-compatible HTTP schema 우선 |
| Redaction | deterministic detector + pluggable classifier |
| Privacy filtering | Korean PII rules + checksum validators + custom entity rules |
| Audit | JSON Lines + hash chain option |
| Tests | golden fixtures, tamper/replay/cross-context negative tests |
| Plugin contract | TypeScript interface + JSON Schema manifest + conformance test |
| Distribution | GitHub repository, package examples, local CLI, SECURITY.md |
| Developer UX | `aicel init`, preset policy, dry-run/report-only, copy-paste middleware |

## 7. MVP 마일스톤

| 단계 | 산출물 | 완료 기준 |
|---|---|---|
| M0 | Developer quickstart | `aicel init`, local key, sample policy, dry-run, MCP/LLM demo가 5분 안에 실행 |
| M1 | MCP proxy skeleton | initialize/tools/call/resource read 흐름 관측 |
| M2 | Policy engine | method/tool/resource별 allow/block/redact/encrypt 결정 |
| M3 | 개인정보 필터링 | 한국 PII fixture와 secret fixture 탐지/처리 |
| M4 | 글로벌 privacy profile | EU-GDPR, US-CCPA-CPRA, US-HIPAA/PCI fixture와 region-deny |
| M5 | Custom filter DSL | regex/dictionary/path-scope/action override와 fixture test |
| M6 | Envelope crypto | context-bound encrypt/decrypt와 tamper test |
| M7 | KMS adapter | local provider + Vault/AWS KMS 중 1개 |
| M8 | LLM HTTP adapter | chat/completion message redaction/encryption policy |
| M9 | Audit | prompt/tool/resource/PII 평문 미노출 검증 |
| M10 | Security negative tests | replay, wrong context, wrong agent, wrong tool, log leakage |
| M11 | Crypto envelope hardening | canonical AAD, nonce/replay cache, key lifecycle, signed policy |
| M12 | Protocol security contracts | MCP/A2A/gRPC/LLM adapter별 auth/lifecycle/metadata scrub 계약 |
| M13 | OSS modular package | `core`, `crypto`, `policy`, `filter`, `mcp`, `llm`, `audit`, `examples` package boundary |
| M14 | Plugin examples | custom `PolicyEngine`, custom `FilterEngine`, custom `AuditSink` 예제와 conformance test |
| M15 | Build-blocking QA gate | plaintext leak, policy conflict, KMS fault, region-deny, DSL fuzzing, plugin capability violation |

## 8. 가장 큰 리스크

| 리스크 | 설명 | 대응 |
|---|---|---|
| 모델은 암호문을 이해하지 못한다 | LLM이 처리해야 하는 의미 정보는 결국 reveal이 필요하다. | selective reveal, tokenization, TEE 로드맵 |
| MCP/A2A 스펙 변화 | protocol이 아직 빠르게 변한다. | adapter isolation, spec version field |
| tool-call 로그 유출 | agent framework가 별도 로그를 남길 수 있다. | framework-specific log hook, redaction test |
| prompt injection과 혼동 | 암호화가 prompt injection 방어를 대체하지 않는다. | 별도 prompt security gate |
| embedding 보호 난이도 | 암호화하면 similarity search가 어렵다. | source text 보호 우선, embedding policy 별도 |
| 개인정보 필터링 오탐/미탐 | 오탐은 업무 품질을 떨어뜨리고 미탐은 개인정보 유출로 이어진다. | confidence threshold, human-review, fixture test |
| 필터 자체의 개인정보 처리 | 외부 classifier를 쓰면 필터링 과정에서 개인정보가 재노출될 수 있다. | local-first detector, classifier privacy policy |
| 글로벌 규제 차이 | GDPR, CCPA, HIPAA, APPI, PDPA, LGPD는 정의와 권리, 전송 조건이 다르다. | regional profile abstraction |
| Cross-border transfer 실패 | 외부 LLM provider region 때문에 EU/UK/BR 등에서 전송 제한을 위반할 수 있다. | region-aware provider allowlist |
| 커스텀 규칙 오작동 | 잘못된 regex나 allowlist가 차단 누락 또는 업무 중단을 만들 수 있다. | validate/test/approve/rollback lifecycle |
| 커스텀 사전 유출 | 고객 dictionary 자체가 영업비밀일 수 있다. | dictionary encryption, access audit |
| 적용 난이도 | 설치와 설정이 어렵다면 OSS 확산과 실제 사용이 모두 실패한다. | 5분 quickstart, dry-run, preset, minimal config, copy-paste examples |
| AAD/nonce/replay 취약점 | context-bound 암호화가 canonicalization과 replay cache 없이 구현되면 우회될 수 있다. | crypto envelope spec, stream sequencing test |
| 정책 배포 오염 | stale policy, client-supplied source label, unsigned rule package가 hard-block을 우회할 수 있다. | signed policy bundle, fail-closed validation |
| 관측성 유출 | trace baggage, metric label, exception, crash dump에 평문 prompt/tool output이 남을 수 있다. | telemetry sentinel test |
| 추상화 과잉 | 프로젝트가 초반부터 너무 많은 interface를 만들면 동작하는 데모가 늦어진다. | core pipeline, MCP proxy, filter/crypto reference를 먼저 구현 |
| plugin 안전성 | 사용자가 작성한 plugin이 평문을 외부로 전송하거나 audit을 우회할 수 있다. | capability manifest, fail-closed loading, conformance/negative test |
| OSS 유지보수 부담 | 문서와 예제가 늘수록 보안 업데이트와 호환성 관리가 어려워진다. | 좁은 MVP, semantic versioning, compatibility matrix |
| 상용/준법 오해 | OSS 문서를 규제 준수 보증으로 오해할 수 있다. | README와 SECURITY.md에 non-compliance disclaimer 명시 |

## 9. 다음 문서화 작업

- AI threat model
- MCP adapter SRS
- LLM gateway policy schema
- A2A task/artifact encryption design
- redaction/tokenization policy spec
- privacy filtering policy spec
- custom filtering DSL spec
- global privacy compliance matrix
- crypto envelope spec
- audit event schema
- expert gap review backlog
- OSS modular architecture
- easy adoption guide and quickstart
- plugin API and conformance test spec
- protocol security contract spec
- self-hosted usage and shared responsibility note
- optional enterprise procurement evidence pack
- security test spec and red-team corpus
- RAG/vector and agent memory protection design
