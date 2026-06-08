# PRD: 모듈형 구간암호화 레이어

- 문서 상태: Draft 0.1
- 작성일: 2026-06-08
- 기준: ISO/IEC/IEEE 29148:2018 요구사항 공학 원칙을 PRD 목적에 맞게 적용
- 제품 가칭: Modular Segment Encryption Layer, MSEL
- 대상 시장: 대한민국 금융, 공공, 대기업, SaaS/API 사업자, 제휴 연동 사업자, 업무/상용 솔루션 공급사

## 1. 목적

본 문서는 이미 인증, 키보드보안, WAF, API Gateway, VPN, KMS, HSM, SIEM 등 보안솔루션을 사용하는 대상 업무/상용 솔루션에 추가 장착할 수 있는 모듈형 구간암호화 제품의 제품 요구사항을 정의한다.

제품의 핵심 목적은 대상 솔루션의 기존 기능과 보안 구성을 교체하지 않고, 그 솔루션 내부 또는 연동 구간에서 발생하는 평문 노출 구간을 줄이며, 민감 필드 또는 payload 단위의 암호화 통제를 대상 솔루션에 삽입 가능한 모듈 형태로 제공하는 것이다.

## 2. 범위

### 2.1 포함 범위

- 브라우저, 모바일 앱, 서버 애플리케이션, API Gateway, sidecar, proxy에서 사용할 수 있는 암호화 모듈
- HTTP, HTTPS, WebSocket, raw TCP socket, gRPC, A2A Agent2Agent 통신에 적용 가능한 protocol adapter
- 대상 솔루션의 request/response, domain object, integration event, batch payload에 장착 가능한 adapter contract
- 필드 단위, payload 단위, 메시지 단위 암복호화
- TLS/mTLS와 병행 가능한 application-level encryption
- KMS/HSM/Vault/Cloud KMS 연동
- 정책 기반 암호화 대상 지정
- 감사로그, 키 사용 이력, 오류 추적
- 국내 KCMVP 검증 암호모듈 또는 외부 crypto provider를 교체 장착할 수 있는 구조
- 향후 PQC provider 확장을 고려한 crypto agility

### 2.2 제외 범위

- 자체 공동인증서 발급기관 또는 전자서명 인증사업자 역할
- 대상 솔루션의 업무 기능, 인증 체계, 권한 체계, 데이터 모델 대체
- 범용 EDR, 백신, DLP, WAF, SIEM 대체
- 전체 네트워크 VPN 대체
- 키보드보안, 가상키패드, 보안키패드의 직접 구현
- 독자 암호 알고리즘 개발

## 3. 제품 배경

국내 구간암호화 시장은 금융 및 공공 조달 환경의 영향으로 PKI, 공동인증서, 전자서명, 키보드보안, 가상키패드, KCMVP 중심으로 발전했다. 그러나 실제 고객은 이런 보안솔루션을 이미 사용하는 업무 솔루션, 상용 패키지, SaaS, 제휴 API, 레거시 WAS, 모바일 앱을 운영한다. 이 대상 솔루션들은 외부 보안솔루션을 갖고 있어도 내부 API, API Gateway 이후, batch/queue, 제휴 연동, 로그/관측성 구간에서 평문 노출이 남을 수 있다.

MSEL은 보안솔루션과 직접 경쟁하는 제품이 아니라, 보안솔루션을 이미 사용하는 대상 솔루션에 삽입되는 암호화 add-on/module로 포지셔닝한다.

## 4. 이해관계자와 사용자군

| 사용자군 | 주요 관심사 |
|---|---|
| CISO/보안 책임자 | 평문 노출 최소화, 감사 대응, 규제 대응, 사고 영향도 축소 |
| 보안 아키텍트 | 암호화 경계, 키 관리, KMS/HSM 연동, 대상 솔루션 통합 경계, 기존 보안 구성 보존 |
| 대상 솔루션 제품책임자/개발사 | 기존 업무 기능 영향 최소화, adapter 제공, 릴리스 영향도, 고객별 설정 |
| 백엔드 개발자 | SDK 사용성, API 안정성, 예외 처리, 성능 영향 |
| 프론트엔드/모바일 개발자 | 클라이언트 SDK 크기, 브라우저/OS 호환성, 보안 저장소 |
| 인프라/SRE | 배포 방식, 관측성, 장애 격리, autoscaling, HA |
| 준법/감사 담당자 | 요구사항 추적성, 키 사용 감사, 로그 무결성, 문서화 |
| 제휴사/외부 API 소비자 | 표준 포맷, 명확한 계약, 키 교환 절차, 장애 대응 |
| AI/agent 플랫폼 운영자 | agent identity, task/context 보호, tool-call/artifact 암호화, agent 간 위임 추적 |

## 5. 제품 비전

MSEL은 "대상 솔루션에 장착되는 composable encryption module"이 된다. 사용자는 업무 애플리케이션 코드, 상용 솔루션 adapter, API Gateway, sidecar, proxy 중 적절한 지점에 MSEL을 삽입하여 민감 데이터의 암호화 정책을 일관되게 적용한다.

## 6. 제품 원칙

- 표준 우선: JWE, COSE, CMS/PKCS#7, HPKE, TLS/mTLS 등 검증된 표준을 우선한다.
- 독자 암호 금지: 자체 암호 알고리즘을 만들지 않는다.
- 키 외부화: 장기 키는 애플리케이션 코드, 환경변수, 설정 파일에 보관하지 않는다.
- 모듈 교체성: crypto provider, KMS adapter, policy engine, transport adapter를 분리한다.
- 평문 최소화: 복호화 지점과 메모리 내 평문 생존 시간을 최소화한다.
- 대상 솔루션 비침습성: 대상 솔루션의 인증, 권한, 세션, 업무 데이터 모델을 교체하지 않고 암호화 경계를 추가한다.
- 기존 보안 구성 보존: 대상 솔루션이 이미 사용하는 WAF, API Gateway, 인증, 키보드보안, SIEM, KMS와 충돌하지 않는다.
- 검증 가능성: 모든 요구사항은 테스트, 분석, 검사, 시연 중 하나 이상의 방식으로 검증 가능해야 한다.

## 7. 비즈니스 요구사항

| ID | 요구사항 | 우선순위 | 검증 |
|---|---|---:|---|
| BR-001 | 제품은 기존 보안솔루션을 이미 사용하는 대상 솔루션에 추가 장착 가능한 암호화 모듈로 제공되어야 한다. | Must | 고객 아키텍처 PoC |
| BR-002 | 제품은 금융, 공공, 대기업 환경에서 평문 노출 구간을 줄이는 명확한 보안 가치를 제공해야 한다. | Must | 위협모델 리뷰 |
| BR-003 | 제품은 SDK, gateway plugin, sidecar, proxy 중 최소 2개 이상의 적용 방식을 제공해야 한다. | Must | 릴리스 산출물 검사 |
| BR-004 | 제품은 KMS/HSM 연동을 핵심 기능으로 제공해야 한다. | Must | 연동 테스트 |
| BR-005 | 제품은 국내 KCMVP crypto provider를 사용할 수 있는 확장점을 가져야 한다. | Should | 설계 리뷰 |
| BR-006 | 제품은 cloud-native 배포 환경을 지원해야 한다. | Should | Kubernetes PoC |
| BR-007 | 제품은 표준 포맷 기반 연동을 통해 제휴사와의 벤더 락인을 줄여야 한다. | Should | 상호운용 테스트 |
| BR-008 | 제품은 PQC 전환 시 crypto provider 교체로 대응 가능한 구조를 가져야 한다. | Could | 아키텍처 리뷰 |
| BR-009 | 제품은 AI/agent 대상 솔루션의 gRPC, A2A, streaming 통신에서 agent 간 민감 context와 artifact를 보호할 수 있어야 한다. | Should | AI protocol PoC |

## 8. 제품 요구사항

### 8.1 암호화 기능

| ID | 요구사항 | 우선순위 |
|---|---|---:|
| PRD-F-001 | 제품은 민감 필드 단위 암호화를 지원해야 한다. | Must |
| PRD-F-002 | 제품은 전체 payload 단위 암호화를 지원해야 한다. | Must |
| PRD-F-003 | 제품은 요청과 응답 양방향 암호화를 지원해야 한다. | Must |
| PRD-F-004 | 제품은 replay 공격 방지를 위한 nonce, timestamp, sequence 또는 equivalent mechanism을 제공해야 한다. | Must |
| PRD-F-005 | 제품은 암호문 envelope에 key id, algorithm id, policy id, version을 포함해야 한다. | Must |
| PRD-F-006 | 제품은 AES-GCM 또는 ChaCha20-Poly1305와 같은 AEAD 기반 암호화를 지원해야 한다. | Must |
| PRD-F-007 | 제품은 고객 요구에 따라 ARIA, SEED, LEA 등 국내 알고리즘 provider를 장착할 수 있어야 한다. | Should |

### 8.2 통합 방식

| ID | 요구사항 | 우선순위 |
|---|---|---:|
| PRD-I-001 | 제품은 Java 또는 JVM 기반 서버 SDK를 제공해야 한다. | Must |
| PRD-I-002 | 제품은 JavaScript/TypeScript SDK를 제공해야 한다. | Must |
| PRD-I-003 | 제품은 REST/JSON API에 적용 가능해야 한다. | Must |
| PRD-I-004 | 제품은 gRPC 또는 binary payload에 적용 가능한 확장점을 제공해야 한다. | Should |
| PRD-I-005 | 제품은 Envoy, NGINX, Kong, Spring Cloud Gateway 중 하나 이상의 gateway/proxy 연동을 제공해야 한다. | Should |
| PRD-I-006 | 제품은 대상 솔루션이 이미 사용하는 입력보안, 인증, 세션, 권한 결과를 훼손하지 않고 pass-through 또는 context binding 방식으로 활용할 수 있어야 한다. | Should |
| PRD-I-007 | 제품은 대상 솔루션별 integration manifest를 통해 암호화 삽입 지점, 평문 존재 지점, 암복호화 책임 경계를 문서화해야 한다. | Must |
| PRD-I-008 | 제품은 HTTP/HTTPS request-response, WebSocket message, raw TCP socket frame, gRPC unary/streaming message, A2A message/task/artifact에 적용 가능한 protocol adapter 모델을 제공해야 한다. | Must |
| PRD-I-009 | 제품은 AI agent 대상 솔루션에서 agent identity, user delegation, task id, context id, tool call, artifact metadata를 암호화 정책의 context로 사용할 수 있어야 한다. | Should |
| PRD-I-010 | 제품은 streaming 프로토콜에서 message/frame/chunk 단위 암호화와 stream/session 단위 replay 방지를 지원해야 한다. | Should |

### 8.3 키 관리

| ID | 요구사항 | 우선순위 |
|---|---|---:|
| PRD-K-001 | 제품은 DEK/KEK 기반 envelope encryption 모델을 지원해야 한다. | Must |
| PRD-K-002 | 제품은 KMS/HSM에서 KEK를 관리하고 애플리케이션이 장기 키를 직접 보유하지 않도록 해야 한다. | Must |
| PRD-K-003 | 제품은 키 회전, 폐기, 비활성화, 롤백 절차를 지원해야 한다. | Must |
| PRD-K-004 | 제품은 key id별 사용 이력과 정책 변경 이력을 감사로그로 남겨야 한다. | Must |
| PRD-K-005 | 제품은 tenant, environment, application, partner 단위 키 분리를 지원해야 한다. | Should |

### 8.4 운영과 관측성

| ID | 요구사항 | 우선순위 |
|---|---|---:|
| PRD-O-001 | 제품은 암복호화 성공, 실패, 정책 거부, 키 조회 실패를 관측 가능한 이벤트로 기록해야 한다. | Must |
| PRD-O-002 | 제품은 로그에 평문 민감정보를 기록하지 않아야 한다. | Must |
| PRD-O-003 | 제품은 메트릭을 통해 latency, error rate, KMS call count, cache hit rate를 제공해야 한다. | Should |
| PRD-O-004 | 제품은 장애 시 fail-closed와 fail-open 정책을 API/정책 단위로 지정할 수 있어야 한다. | Should |

## 9. MVP 범위

MVP는 다음으로 한정한다.

- Java 서버 SDK
- TypeScript SDK
- JSON field-level encryption
- JWE 호환 envelope
- AWS KMS 또는 HashiCorp Vault 중 1개 연동
- 로컬 개발용 software key provider
- policy YAML/JSON
- audit log JSON line output
- replay 방지 nonce store 기본 구현
- 샘플 Spring Boot API
- 기본 성능 벤치마크

MVP에서 제외한다.

- KCMVP 검증 provider 내장
- PQC provider
- 모바일 네이티브 SDK
- GUI 관리 콘솔
- 고가용성 KMS proxy
- 키보드보안 직접 구현

## 10. 성공 지표

| 지표 | 목표 |
|---|---|
| 통합 시간 | 샘플 API 기준 1일 이내 field encryption 적용 |
| 성능 | 1KB payload 기준 P95 암복호화 오버헤드 10ms 이하 |
| 신뢰성 | 암복호화 오류 시 원인 코드와 감사 이벤트 100% 기록 |
| 보안 | 로그 내 민감 평문 0건 |
| 운영 | 키 회전 절차를 무중단 또는 제한적 영향으로 수행 |
| 호환성 | 최소 2개 KMS provider 또는 key provider 연동 |

## 11. 주요 리스크

| 리스크 | 영향 | 완화 |
|---|---|---|
| 브라우저 JavaScript 변조 | 클라이언트 암호화 우회 | CSP, SRI, 서명된 SDK, 서버 측 정책 검증 |
| KMS 지연 | API latency 증가 | DEK cache, envelope cache, circuit breaker |
| 제품 책임 경계 불명확 | 보안 사고 시 원인 분석 곤란 | 암복호화 경계 문서화, threat model 제공 |
| 독자 포맷 남발 | 제휴 연동 어려움 | JWE/COSE/CMS/HPKE 우선 |
| KCMVP 요구 | 공공/금융 납품 지연 | CryptoProvider SPI와 검증필 모듈 교체 구조 |
| 운영자 오설정 | 평문 노출 또는 복호화 장애 | policy validation, dry-run, staged rollout |

## 12. 추적성 매트릭스

| 비즈니스 요구 | 관련 제품 요구 |
|---|---|
| BR-001 | PRD-I-001, PRD-I-002, PRD-I-005, PRD-I-006, PRD-I-007 |
| BR-002 | PRD-F-001, PRD-F-002, PRD-O-002 |
| BR-003 | PRD-I-001, PRD-I-002, PRD-I-005, PRD-I-006, PRD-I-007, PRD-I-008, PRD-I-010 |
| BR-004 | PRD-K-001, PRD-K-002, PRD-K-003 |
| BR-005 | PRD-F-007, PRD-K-002 |
| BR-006 | PRD-O-003, PRD-O-004 |
| BR-007 | PRD-F-005, PRD-I-003, PRD-I-004 |
| BR-008 | PRD-F-005, PRD-K-001 |
| BR-009 | PRD-I-008, PRD-I-009, PRD-I-010 |

## 13. 미결정 사항

- 1차 표준 envelope 포맷: JWE 우선 또는 CMS/PKCS#7 우선
- 1차 서버 SDK 언어: Java 우선 또는 Node.js 우선
- 1차 KMS provider: AWS KMS, HashiCorp Vault, 국내 HSM/KMS 중 선택
- KCMVP provider 연동을 MVP에 포함할지 여부
- 관리 콘솔을 제품 핵심으로 볼지, enterprise add-on으로 둘지 여부

## 14. 참고

- ISO/IEC/IEEE 29148:2018, Systems and software engineering -- Life cycle processes -- Requirements engineering
- RFC 8446, The Transport Layer Security Protocol Version 1.3
- RFC 7516, JSON Web Encryption
- RFC 9180, Hybrid Public Key Encryption
- gRPC Core Concepts
- A2A Agent2Agent Protocol Specification
- NIST FIPS 203, ML-KEM
- NIST FIPS 204, ML-DSA
- NIST FIPS 205, SLH-DSA
