# SRS: 모듈형 구간암호화 레이어

- 문서 상태: Draft 0.1
- 작성일: 2026-06-08
- 기준: ISO/IEC/IEEE 29148:2018 요구사항 공학 원칙 적용
- 제품 가칭: Modular Segment Encryption Layer, MSEL
- 관련 PRD: docs/prd-modular-segment-encryption.md

## 1. 소개

### 1.1 목적

본 문서는 대상 업무/상용 솔루션에 장착되는 MSEL의 소프트웨어 요구사항을 정의한다. 모든 요구사항은 가능한 한 단일하고, 필요하며, 구현 가능하고, 검증 가능하도록 작성한다.

### 1.2 시스템 범위

MSEL은 대상 솔루션의 애플리케이션 코드, API Gateway, proxy, sidecar, KMS/HSM 사이에서 민감 데이터의 필드 단위 또는 payload 단위 암복호화를 수행하는 소프트웨어 시스템이다. MSEL은 대상 솔루션의 기존 인증, 권한, 세션, 업무 기능, 보안솔루션을 대체하지 않고 보완한다.

### 1.3 정의

| 용어 | 정의 |
|---|---|
| DEK | Data Encryption Key. 데이터 암호화에 사용하는 단기 키 |
| KEK | Key Encryption Key. DEK를 감싸는 장기 또는 관리형 키 |
| Envelope | 암호문, 알고리즘, key id, policy id, nonce, metadata를 포함하는 구조 |
| CryptoProvider | 암복호화 알고리즘을 제공하는 교체 가능한 모듈 |
| KMS Adapter | 외부 KMS/HSM/Vault와 통신하는 모듈 |
| Policy | 어떤 데이터에 어떤 암호화 규칙을 적용할지 정의하는 설정 |
| AAD | Additional Authenticated Data. AEAD 무결성 검증에 포함되지만 암호화하지 않는 데이터 |
| 대상 솔루션 | MSEL이 추가 장착되는 업무 애플리케이션, 상용 패키지, SaaS, 제휴 API, 레거시 시스템, 모바일 앱 |
| Integration Manifest | 대상 솔루션의 암호화 삽입 지점, 평문 경계, adapter, 정책, 책임 범위를 기술하는 문서 또는 설정 |
| Protocol Adapter | HTTP/HTTPS, WebSocket, raw TCP socket, gRPC, A2A 등 전송/응용 프로토콜별 message boundary와 metadata를 MSEL envelope에 매핑하는 모듈 |
| A2A | Agent2Agent protocol. AI agent 간 message, task, artifact, streaming, push notification, agent discovery를 다루는 protocol family |
| Agent Context | agent id, user delegation, task id, context id, skill/tool name, artifact id, model/provider, tenant 정보를 포함하는 정책 평가 context |

### 1.4 참고 문서

- ISO/IEC/IEEE 29148:2018, Systems and software engineering -- Life cycle processes -- Requirements engineering
- RFC 8446, TLS 1.3
- RFC 7516, JSON Web Encryption
- RFC 9180, Hybrid Public Key Encryption
- gRPC Core Concepts
- A2A Agent2Agent Protocol Specification
- OWASP ASVS
- OWASP Cryptographic Storage Cheat Sheet
- NIST SP 800-57, Key Management

## 2. 전체 설명

### 2.1 제품 관점

MSEL은 다음 배포 형태를 지원하는 모듈형 암호화 시스템이다.

- Library mode: 애플리케이션 코드에서 SDK를 호출한다.
- Target-solution adapter mode: 대상 솔루션의 extension point, middleware, interceptor, plugin, hook에서 SDK를 호출한다.
- Gateway mode: API Gateway plugin 또는 middleware가 요청/응답을 처리한다.
- Sidecar mode: 서비스 옆의 proxy가 암복호화 처리를 수행한다.
- Protocol adapter mode: HTTP/HTTPS, WebSocket, raw TCP, gRPC, A2A의 message/frame/task/artifact 단위로 암복호화한다.
- Partner mode: 외부 제휴 API와 표준 envelope를 교환한다.

### 2.2 주요 컴포넌트

| 컴포넌트 | 책임 |
|---|---|
| Client SDK | 클라이언트 측 암호화, envelope 생성, 정책 적용 |
| Server SDK | 복호화, 검증, envelope parsing, audit event 생성 |
| Policy Engine | 요청 경로, 필드, tenant, partner 기준 정책 결정 |
| CryptoProvider SPI | 암호 알고리즘 provider 추상화 |
| KMS Adapter SPI | KMS/HSM/Vault provider 추상화 |
| Nonce Store | replay 방지를 위한 nonce 사용 이력 관리 |
| Audit Logger | 키 사용, 암복호화, 정책 거부, 실패 이벤트 기록 |
| Admin CLI | 정책 검증, 키 상태 점검, dry-run |
| Integration Adapter | 대상 솔루션의 인증/권한/context를 MSEL policy input으로 변환 |
| Integration Manifest | 대상 솔루션별 암호화 경계와 삽입 지점 선언 |
| Protocol Adapter | 프로토콜별 message boundary, metadata, streaming semantics를 암호화 정책에 매핑 |
| AI Agent Adapter | A2A/gRPC 기반 agent message, task, context, artifact 보호 |

### 2.3 운영 환경

- Linux x86_64 및 arm64 서버
- Kubernetes 또는 VM 기반 배포
- Java 17 이상 서버 SDK
- Node.js 20 이상 또는 evergreen browser용 TypeScript SDK
- HTTPS/TLS 1.2 이상, 권장 TLS 1.3

## 3. 외부 인터페이스 요구사항

| ID | 요구사항 | 우선순위 | 검증 |
|---|---|---:|---|
| SIR-001 | 시스템은 Java 17 이상에서 사용할 수 있는 서버 SDK API를 제공해야 한다. | Must | 빌드/단위 테스트 |
| SIR-002 | 시스템은 TypeScript SDK를 제공해야 한다. | Must | 빌드/단위 테스트 |
| SIR-003 | 시스템은 JSON object의 지정 필드를 암호화하고 동일 구조로 복호화할 수 있어야 한다. | Must | 통합 테스트 |
| SIR-004 | 시스템은 HTTP header 또는 envelope metadata에 policy id와 key id를 포함할 수 있어야 한다. | Must | 통합 테스트 |
| SIR-005 | 시스템은 KMS Adapter 인터페이스를 통해 외부 KMS/HSM provider를 교체할 수 있어야 한다. | Must | mock adapter 테스트 |
| SIR-006 | 시스템은 CryptoProvider 인터페이스를 통해 암호 provider를 교체할 수 있어야 한다. | Must | provider 호환 테스트 |
| SIR-007 | 시스템은 audit event를 JSON Lines 또는 structured log 형식으로 출력해야 한다. | Must | 로그 검사 |
| SIR-008 | 시스템은 Prometheus 호환 메트릭 export 방식을 제공해야 한다. | Should | 메트릭 scrape 테스트 |
| SIR-009 | 시스템은 대상 솔루션의 인증, 세션, 권한 context를 변경하지 않고 policy input으로 받을 수 있는 Integration Adapter 인터페이스를 제공해야 한다. | Must | adapter contract 테스트 |
| SIR-010 | 시스템은 대상 솔루션별 Integration Manifest를 로드하고 검증할 수 있어야 한다. | Must | manifest validation 테스트 |
| SIR-011 | 시스템은 HTTP/HTTPS adapter에서 header, method, path, query, body, status code를 정책 context로 사용할 수 있어야 한다. | Must | HTTP 통합 테스트 |
| SIR-012 | 시스템은 WebSocket 및 raw TCP socket adapter에서 message/frame boundary와 connection/session id를 정책 context로 사용할 수 있어야 한다. | Should | socket 통합 테스트 |
| SIR-013 | 시스템은 gRPC adapter에서 service, method, metadata, protobuf message type, unary/server-stream/client-stream/bidirectional-stream 유형을 정책 context로 사용할 수 있어야 한다. | Should | gRPC 통합 테스트 |
| SIR-014 | 시스템은 A2A adapter에서 AgentCard, agent id, task id, context id, message role, part, artifact, streaming event, push notification metadata를 정책 context로 사용할 수 있어야 한다. | Should | A2A 통합 테스트 |

## 4. 기능 요구사항

### 4.1 정책 처리

| ID | 요구사항 | 우선순위 | 검증 |
|---|---|---:|---|
| SFR-POL-001 | 시스템은 API route, HTTP method, tenant id, partner id, field path를 조건으로 암호화 정책을 선택해야 한다. | Must | 정책 테스트 |
| SFR-POL-002 | 시스템은 정책 파일을 로드할 때 schema validation을 수행해야 한다. | Must | 부정 테스트 |
| SFR-POL-003 | 시스템은 정책 충돌을 감지하고 우선순위 규칙에 따라 하나의 정책만 선택해야 한다. | Must | 정책 테스트 |
| SFR-POL-004 | 시스템은 정책 dry-run 결과를 출력해야 한다. | Should | CLI 테스트 |
| SFR-POL-005 | 시스템은 정책 변경 시 버전과 변경자를 audit event로 기록해야 한다. | Should | 로그 검사 |
| SFR-POL-006 | 시스템은 대상 솔루션의 route, operation, domain object, integration event를 MSEL policy 대상에 매핑해야 한다. | Must | manifest-policy 매핑 테스트 |
| SFR-POL-007 | 시스템은 protocol adapter별 canonical policy context를 생성하고 동일 의미의 요청이 transport별로 다른 정책 결과를 만들지 않도록 해야 한다. | Must | protocol equivalence 테스트 |

### 4.2 암호화

| ID | 요구사항 | 우선순위 | 검증 |
|---|---|---:|---|
| SFR-ENC-001 | 시스템은 선택된 JSON field value를 envelope ciphertext로 대체해야 한다. | Must | 단위/통합 테스트 |
| SFR-ENC-002 | 시스템은 전체 request 또는 response body를 envelope ciphertext로 대체할 수 있어야 한다. | Must | 통합 테스트 |
| SFR-ENC-003 | 시스템은 암호화마다 고유 nonce 또는 IV를 사용해야 한다. | Must | 단위/속성 테스트 |
| SFR-ENC-004 | 시스템은 AAD에 route, method, tenant id, policy id 중 정책에서 지정한 값을 포함할 수 있어야 한다. | Must | 변조 테스트 |
| SFR-ENC-005 | 시스템은 암호화 결과에 algorithm id, key id, policy id, envelope version을 포함해야 한다. | Must | envelope 검사 |
| SFR-ENC-006 | 시스템은 기본 AEAD provider로 AES-256-GCM을 지원해야 한다. | Must | known-answer test |
| SFR-ENC-007 | 시스템은 ChaCha20-Poly1305 provider를 선택 가능하게 제공해야 한다. | Should | known-answer test |
| SFR-ENC-008 | 시스템은 KCMVP provider 장착 시 외부 provider의 알고리즘 목록을 policy에서 참조할 수 있어야 한다. | Should | provider contract test |
| SFR-ENC-009 | 시스템은 streaming 프로토콜에서 stream/session 키와 message/frame/chunk nonce를 분리해 암호화해야 한다. | Should | streaming 암호화 테스트 |
| SFR-ENC-010 | 시스템은 gRPC protobuf message를 암호화할 때 schema-aware field encryption과 opaque binary payload encryption 중 하나를 정책으로 선택할 수 있어야 한다. | Should | protobuf 테스트 |
| SFR-ENC-011 | 시스템은 A2A message part와 artifact payload를 암호화할 때 task id, context id, agent identity를 AAD에 포함할 수 있어야 한다. | Should | A2A 변조 테스트 |

### 4.3 복호화와 검증

| ID | 요구사항 | 우선순위 | 검증 |
|---|---|---:|---|
| SFR-DEC-001 | 시스템은 envelope version을 검증하고 지원하지 않는 version을 거부해야 한다. | Must | 부정 테스트 |
| SFR-DEC-002 | 시스템은 key id로 KEK 또는 wrapped DEK를 조회해야 한다. | Must | 통합 테스트 |
| SFR-DEC-003 | 시스템은 AAD 불일치 시 복호화를 거부해야 한다. | Must | 변조 테스트 |
| SFR-DEC-004 | 시스템은 nonce 재사용 또는 replay 감지 시 요청을 거부해야 한다. | Must | replay 테스트 |
| SFR-DEC-005 | 시스템은 복호화 실패 시 평문 또는 키 재료를 로그에 남기지 않아야 한다. | Must | 로그 검사 |
| SFR-DEC-006 | 시스템은 복호화 결과를 호출자에게 반환하기 전에 policy가 허용한 context인지 확인해야 한다. | Must | 권한 테스트 |
| SFR-DEC-007 | 시스템은 streaming 메시지 복호화에서 stream order, message sequence, cancellation, retry, partial delivery를 검증해야 한다. | Should | streaming 부정 테스트 |
| SFR-DEC-008 | 시스템은 A2A task/context가 다른 agent message 또는 artifact를 복호화하려는 시도를 거부해야 한다. | Should | cross-agent 권한 테스트 |

### 4.4 키 관리

| ID | 요구사항 | 우선순위 | 검증 |
|---|---|---:|---|
| SFR-KEY-001 | 시스템은 데이터 암호화에 DEK를 사용하고 DEK를 KEK로 wrapping해야 한다. | Must | 통합 테스트 |
| SFR-KEY-002 | 시스템은 장기 키를 애플리케이션 설정 파일에 평문으로 저장하지 않아야 한다. | Must | 정적 검사 |
| SFR-KEY-003 | 시스템은 key rotation 후 신규 암호화에는 새 key version을 사용해야 한다. | Must | 회전 테스트 |
| SFR-KEY-004 | 시스템은 기존 암호문 복호화를 위해 활성 기간 내 이전 key version을 조회할 수 있어야 한다. | Must | 회귀 테스트 |
| SFR-KEY-005 | 시스템은 key disabled 상태에서 신규 암호화를 거부해야 한다. | Must | 상태 테스트 |
| SFR-KEY-006 | 시스템은 key deletion 또는 destroy 동작을 명시적 승인 절차 없이는 수행하지 않아야 한다. | Must | CLI/API 테스트 |
| SFR-KEY-007 | 시스템은 DEK cache TTL과 최대 항목 수를 설정할 수 있어야 한다. | Should | 성능/설정 테스트 |

### 4.5 감사와 관측성

| ID | 요구사항 | 우선순위 | 검증 |
|---|---|---:|---|
| SFR-AUD-001 | 시스템은 암호화 성공, 복호화 성공, 정책 거부, KMS 실패, replay 거부 이벤트를 기록해야 한다. | Must | 로그 검사 |
| SFR-AUD-002 | 시스템은 audit event에 correlation id를 포함해야 한다. | Must | 통합 테스트 |
| SFR-AUD-003 | 시스템은 audit event에 평문 민감정보, DEK, KEK, raw nonce secret을 포함하지 않아야 한다. | Must | 로그 검사 |
| SFR-AUD-004 | 시스템은 암복호화 latency, error count, KMS latency, cache hit ratio 메트릭을 제공해야 한다. | Should | 메트릭 테스트 |
| SFR-AUD-005 | 시스템은 보안상 세부 오류를 외부 응답에 노출하지 않고 내부 audit event에는 분류 코드를 기록해야 한다. | Must | 부정 테스트 |

## 5. 비기능 요구사항

### 5.1 보안

| ID | 요구사항 | 우선순위 | 검증 |
|---|---|---:|---|
| SNFR-SEC-001 | 시스템은 기본 통신 채널로 TLS 1.2 이상을 요구하고 TLS 1.3을 권장해야 한다. | Must | 설정 검사 |
| SNFR-SEC-002 | 시스템은 서버-서버 연동에서 mTLS를 사용할 수 있어야 한다. | Should | 통합 테스트 |
| SNFR-SEC-003 | 시스템은 모든 random value 생성에 CSPRNG를 사용해야 한다. | Must | 코드 리뷰/테스트 |
| SNFR-SEC-004 | 시스템은 암호화 실패 시 fail-closed를 기본값으로 사용해야 한다. | Must | 장애 테스트 |
| SNFR-SEC-005 | 시스템은 policy 단위로 fail-open 예외를 지정할 수 있으나 audit event를 반드시 남겨야 한다. | Should | 정책 테스트 |
| SNFR-SEC-006 | 시스템은 secret zeroization을 지원하는 provider에서는 사용 후 민감 버퍼 삭제를 호출해야 한다. | Should | 코드 리뷰 |
| SNFR-SEC-007 | 시스템은 dependency vulnerability scan을 릴리스 게이트에 포함해야 한다. | Must | CI 검사 |
| SNFR-SEC-008 | 시스템은 sensitive classification이 지정된 route, field, policy에서 fail-open 설정을 거부해야 한다. | Must | 정책 부정 테스트 |
| SNFR-SEC-009 | 시스템은 복호화 시 envelope header의 algorithm, key id, policy id를 그대로 신뢰하지 않고 서버 측 allowlist와 policy binding을 검증해야 한다. | Must | header tampering 테스트 |
| SNFR-SEC-010 | 시스템은 JWE 또는 유사 envelope 사용 시 `jku`, `jwk`, `x5u` 같은 동적 key reference를 기본적으로 금지해야 한다. | Must | 부정 테스트 |
| SNFR-SEC-011 | 시스템은 JSON field encryption 수행 전 duplicate key, 비정상 Unicode, 지원하지 않는 content type, 모호한 field path를 거부해야 한다. | Must | parser 부정 테스트 |
| SNFR-SEC-012 | 시스템은 distributed deployment에서 key별 nonce/IV 유일성을 보장하는 nonce generation strategy를 문서화하고 테스트해야 한다. | Must | 속성/대량 생성 테스트 |
| SNFR-SEC-013 | 시스템은 decrypt operation마다 caller service identity, tenant, route, purpose, key id를 권한 평가에 포함해야 한다. | Must | 권한 테스트 |
| SNFR-SEC-014 | 시스템은 key disabled, revoked, rotated 이벤트 발생 시 관련 DEK cache entry를 purge해야 한다. | Must | 회전/폐기 테스트 |
| SNFR-SEC-015 | 시스템은 browser SDK 배포 시 SRI, CSP, package signature, version pinning 가이드를 제공해야 한다. | Should | 문서/샘플 검사 |
| SNFR-SEC-016 | 시스템은 audit log를 append-only sink 또는 hash chain 등으로 변조 탐지 가능하게 만들 수 있어야 한다. | Should | 무결성 테스트 |
| SNFR-SEC-017 | 시스템은 release artifact signing, SBOM, dependency lockfile, provenance attestation을 릴리스 게이트에 포함해야 한다. | Should | 릴리스 검사 |
| SNFR-SEC-018 | 시스템은 KCMVP mode에서 검증필 provider, 검증효력, 형상 해시, 동작모드가 정책과 일치하지 않으면 시작 또는 암호 연산을 거부해야 한다. | Should | KCMVP mode 테스트 |
| SNFR-SEC-019 | 시스템은 대상 솔루션별 Integration Manifest에 암호화 삽입 지점, 복호화 지점, 평문 존재 지점, bypass 가능 경로, 책임 주체를 명시해야 한다. | Must | manifest 보안 리뷰 |
| SNFR-SEC-020 | 시스템은 대상 솔루션의 기존 인증/권한 결정을 우회하는 독자 권한 상승 경로를 만들지 않아야 한다. | Must | 권한/통합 테스트 |
| SNFR-SEC-021 | 시스템은 gRPC metadata, HTTP header, WebSocket subprotocol, A2A AgentCard에 포함되는 민감정보를 기본적으로 암호화 대상 또는 redaction 대상으로 분류해야 한다. | Must | metadata leakage 테스트 |
| SNFR-SEC-022 | 시스템은 AI agent 통신에서 user delegation, agent identity, tool-call authorization, task/context boundary를 복호화 권한 평가에 포함해야 한다. | Should | agent authorization 테스트 |
| SNFR-SEC-023 | 시스템은 A2A AgentCard와 protocol capability discovery 결과를 신뢰하기 전 서명, origin, TLS/mTLS, allowlist 중 정책이 요구하는 검증을 수행해야 한다. | Should | discovery tampering 테스트 |
| SNFR-SEC-024 | 시스템은 AI prompt, tool input/output, retrieval snippet, generated artifact에 대한 로그/메트릭 평문 유출 방지 규칙을 제공해야 한다. | Must | AI log redaction 테스트 |

### 5.2 성능

| ID | 요구사항 | 우선순위 | 검증 |
|---|---|---:|---|
| SNFR-PERF-001 | 시스템은 1KB JSON payload field encryption에서 P95 추가 latency 10ms 이하를 목표로 해야 한다. | Should | 벤치마크 |
| SNFR-PERF-002 | 시스템은 KMS 호출 장애 또는 지연 시 timeout과 circuit breaker를 적용해야 한다. | Must | 장애 테스트 |
| SNFR-PERF-003 | 시스템은 KMS Adapter timeout 기본값을 500ms 이하로 설정 가능해야 한다. | Should | 설정 테스트 |
| SNFR-PERF-004 | 시스템은 high-throughput 환경에서 object allocation을 제한하기 위한 streaming 또는 buffer 재사용 전략을 제공해야 한다. | Could | 프로파일링 |

### 5.3 신뢰성

| ID | 요구사항 | 우선순위 | 검증 |
|---|---|---:|---|
| SNFR-REL-001 | 시스템은 KMS 일시 장애 시 재시도 정책을 exponential backoff로 수행해야 한다. | Should | 장애 테스트 |
| SNFR-REL-002 | 시스템은 nonce store 장애 시 fail-closed를 기본 동작으로 해야 한다. | Must | 장애 테스트 |
| SNFR-REL-003 | 시스템은 rolling deployment 중 구버전 envelope를 복호화할 수 있어야 한다. | Must | 호환성 테스트 |
| SNFR-REL-004 | 시스템은 envelope major version 변경 시 명시적 migration guide를 제공해야 한다. | Should | 문서 검사 |

### 5.4 사용성

| ID | 요구사항 | 우선순위 | 검증 |
|---|---|---:|---|
| SNFR-USE-001 | SDK는 기본 사용 사례를 30줄 이하의 샘플 코드로 설명할 수 있어야 한다. | Should | 문서 리뷰 |
| SNFR-USE-002 | 오류 코드는 개발자가 원인과 조치 방향을 구분할 수 있게 안정적인 enum으로 제공되어야 한다. | Must | API 테스트 |
| SNFR-USE-003 | CLI는 policy validate, encrypt sample, decrypt sample, key status 명령을 제공해야 한다. | Should | CLI 테스트 |

### 5.5 유지보수성과 확장성

| ID | 요구사항 | 우선순위 | 검증 |
|---|---|---:|---|
| SNFR-MNT-001 | CryptoProvider와 KMS Adapter는 stable interface로 분리되어야 한다. | Must | 아키텍처 테스트 |
| SNFR-MNT-002 | provider 추가가 core policy engine 변경 없이 가능해야 한다. | Must | provider contract test |
| SNFR-MNT-003 | envelope schema는 backward compatibility rule을 문서화해야 한다. | Must | 문서 검사 |
| SNFR-MNT-004 | 시스템은 SBOM을 릴리스 산출물에 포함해야 한다. | Should | 릴리스 검사 |

## 6. 데이터 요구사항

### 6.1 Envelope 필드

| 필드 | 필수 | 설명 |
|---|---|---|
| version | 예 | envelope schema version |
| alg | 예 | content encryption algorithm id |
| kid | 예 | key id 또는 key version |
| policy_id | 예 | 적용 정책 id |
| nonce | 예 | AEAD nonce 또는 IV |
| aad_hash | 선택 | AAD 검증 보조값 |
| wrapped_dek | 조건부 | envelope encryption 사용 시 wrapped DEK |
| ciphertext | 예 | 암호문 |
| tag | 조건부 | 포맷이 tag를 분리할 경우 AEAD tag |

### 6.2 Audit Event 필드

| 필드 | 필수 | 설명 |
|---|---|---|
| timestamp | 예 | 이벤트 발생 시각 |
| correlation_id | 예 | 요청 추적 id |
| event_type | 예 | encrypt, decrypt, reject, kms_error 등 |
| policy_id | 예 | 정책 id |
| kid | 조건부 | key id |
| tenant_id | 조건부 | tenant id |
| result | 예 | success, failure, denied |
| reason_code | 조건부 | 실패 또는 거부 원인 |
| latency_ms | 선택 | 처리 시간 |

## 7. 제약사항

- 시스템은 독자 암호 알고리즘을 구현하지 않아야 한다.
- 시스템은 검증되지 않은 random source를 사용하지 않아야 한다.
- 시스템은 client-side encryption만으로 XSS 또는 공급망 공격을 완전히 방어한다고 주장하지 않아야 한다.
- 시스템은 KMS/HSM 장애 시 평문 우회 전송을 기본 동작으로 제공하지 않아야 한다.
- 시스템은 로그, metric label, exception message에 평문 민감정보를 포함하지 않아야 한다.

## 8. 검증 계획

| 검증 유형 | 대상 |
|---|---|
| 단위 테스트 | envelope parsing, policy selection, crypto provider contract |
| Known-answer test | AES-GCM, ChaCha20-Poly1305, provider-specific algorithms |
| 통합 테스트 | SDK-KMS-policy-audit end-to-end |
| 부정 테스트 | tampered ciphertext, wrong AAD, wrong key, replay nonce |
| 성능 테스트 | payload 크기별 latency, KMS cache hit/miss |
| 보안 리뷰 | threat model, key lifecycle, logging, dependency |
| 설계 보안 부정 테스트 | algorithm confusion, key confusion, duplicate JSON key, cross-tenant decrypt, fail-open rejection |
| 프로토콜 테스트 | HTTP/HTTPS, WebSocket/raw TCP, gRPC unary/streaming, A2A message/task/artifact 암복호화 |
| AI agent 보안 테스트 | agent identity spoofing, task/context confusion, artifact substitution, prompt/tool-call leakage |
| 호환성 테스트 | envelope version, rolling deployment, provider replacement |
| 운영 테스트 | key rotation, KMS outage, nonce store outage, policy rollback |

## 9. 요구사항 추적성

| PRD 요구 | SRS 요구 |
|---|---|
| PRD-F-001 | SFR-ENC-001, SFR-DEC-001, SFR-DEC-003 |
| PRD-F-002 | SFR-ENC-002 |
| PRD-F-004 | SFR-DEC-004, SNFR-REL-002 |
| PRD-F-005 | SFR-ENC-005, 데이터 요구사항 6.1 |
| PRD-F-006 | SFR-ENC-006 |
| PRD-F-007 | SFR-ENC-008, SIR-006 |
| PRD-I-001 | SIR-001 |
| PRD-I-002 | SIR-002 |
| PRD-I-003 | SIR-003, SIR-004 |
| PRD-I-004 | SIR-013, SFR-ENC-010 |
| PRD-I-005 | SIR-011, SIR-013, SIR-014 |
| PRD-I-006 | SIR-009, SFR-POL-006, SNFR-SEC-020 |
| PRD-I-007 | SIR-010, SNFR-SEC-019 |
| PRD-I-008 | SIR-011, SIR-012, SIR-013, SIR-014, SFR-POL-007 |
| PRD-I-009 | SIR-014, SFR-ENC-011, SFR-DEC-008, SNFR-SEC-022, SNFR-SEC-023, SNFR-SEC-024 |
| PRD-I-010 | SFR-ENC-009, SFR-DEC-007 |
| PRD-K-001 | SFR-KEY-001 |
| PRD-K-002 | SFR-KEY-002, SIR-005 |
| PRD-K-003 | SFR-KEY-003, SFR-KEY-004, SFR-KEY-005 |
| PRD-O-001 | SFR-AUD-001, SFR-AUD-002 |
| PRD-O-002 | SFR-DEC-005, SFR-AUD-003 |
| PRD-O-003 | SIR-008, SFR-AUD-004 |
| PRD-O-004 | SNFR-SEC-004, SNFR-SEC-005 |

## 10. 미결정 사항

- MVP의 canonical envelope를 JWE compact, JWE JSON serialization, 또는 자체 JSON envelope 중 무엇으로 할지 결정해야 한다.
- nonce store의 MVP 구현을 in-memory, Redis, database 중 무엇으로 할지 결정해야 한다.
- KMS Adapter 1차 구현 대상을 AWS KMS, HashiCorp Vault, 또는 국내 KMS/HSM 중 무엇으로 할지 결정해야 한다.
- TypeScript SDK의 브라우저 암호 provider를 Web Crypto API 전용으로 할지, fallback provider를 허용할지 결정해야 한다.
- KCMVP provider 연동 범위를 interface 수준으로 둘지, 검증필 모듈 연동 샘플까지 포함할지 결정해야 한다.

## 11. 승인 기준

SRS Draft 0.1은 다음 조건을 충족하면 PRD Draft 0.1에 대한 초기 시스템 요구사항 초안으로 승인할 수 있다.

- 모든 Must 요구사항이 하나 이상의 검증 방법을 가진다.
- PRD 주요 요구사항이 SRS 요구사항으로 추적된다.
- MVP 제외 범위가 PRD와 충돌하지 않는다.
- 키 관리, 암호화, replay 방지, 감사로그 요구사항이 누락되지 않는다.
- 미결정 사항이 별도 의사결정 항목으로 식별된다.
