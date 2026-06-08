# Security Review: 모듈형 구간암호화 레이어

- 문서 상태: Draft 0.1
- 작성일: 2026-06-08
- 검토 대상:
  - `docs/prd-modular-segment-encryption.md`
  - `docs/srs-modular-segment-encryption.md`
- 검토 유형: 설계 보안검토, 위협모델, 요구사항 갭 분석
- 검토 기준:
  - OWASP ASVS
  - OWASP Cryptographic Storage Cheat Sheet
  - OWASP Key Management Cheat Sheet
  - NIST SP 800-57 Part 1 Rev. 5
  - NIST SP 800-38D
  - RFC 8446, TLS 1.3
  - RFC 7516, JSON Web Encryption
  - RFC 9180, Hybrid Public Key Encryption
  - KISA KCMVP 암호모듈검증 안내

## 1. 총평

현재 PRD/SRS는 구간암호화 제품의 핵심 방향을 잘 잡고 있다. 단, 제품의 통합 대상은 기존 보안솔루션 자체가 아니라, 기존 보안솔루션을 이미 사용하는 업무/상용/SaaS/제휴 API 대상 솔루션이다. 따라서 보안검토의 중심은 대상 솔루션의 기능을 대체하지 않으면서 어떤 지점에 암호화 경계를 삽입하고, 어디에 평문이 남는지를 증명하는 것이다.

다만 이 제품은 보안 기능이 부가 기능이 아니라 제품 자체의 본질이므로, 일반 SaaS 수준의 보안 요구사항으로는 부족하다. 다음 영역은 제품 신뢰성을 좌우하는 고위험 설계 영역이다.

- 클라이언트 SDK 신뢰 경계
- HTTP/HTTPS, WebSocket/socket, gRPC, A2A protocol adapter별 message boundary
- AI agent identity, task/context, tool-call, artifact 경계
- AEAD nonce/IV 유일성
- envelope algorithm/key confusion 방지
- 복호화 권한과 key-policy binding
- fail-open에 의한 평문 누출
- KMS/HSM 장애와 DEK cache 보안
- JSON canonicalization과 field path ambiguity
- audit log 무결성
- KCMVP 적용 범위와 검증필 동작모드
- 공급망 보안과 release provenance

## 2. 심각도 요약

| 심각도 | 건수 | 판단 |
|---|---:|---|
| Critical | 0 | 현재는 구현 코드가 없어 즉시 악용 가능한 취약점은 확인되지 않았다. |
| High | 12 | 설계 단계에서 반드시 요구사항으로 승격해야 하는 보안 갭이 있다. |
| Medium | 12 | 구현 전에 상세 설계와 테스트 기준을 확정해야 하는 약점이 있다. |
| Low | 6 | 문서화, 운영 가이드, 품질 게이트 강화 항목이다. |

## 3. 보호 자산

| 자산 | 보호 목표 | 손상 영향 |
|---|---|---|
| 원문 민감 데이터 | 기밀성, 무결성 | 개인정보/금융정보 유출, 규제 위반 |
| DEK | 기밀성, 수명 제한 | 해당 암호문 대량 복호화 |
| KEK/HSM key | 기밀성, 접근통제 | 전체 tenant 또는 전체 서비스 영향 |
| Envelope metadata | 무결성, 제한적 기밀성 | 정책 우회, key enumeration, traffic analysis |
| Policy | 무결성, 변경 통제 | 암호화 누락, 복호화 권한 오남용 |
| Nonce/replay state | 무결성, 가용성 | replay 허용 또는 서비스 거부 |
| Audit log | 무결성, 기밀성, 부인방지 | 사고 조사 실패, 감사 대응 실패 |
| SDK/package | 무결성, 출처 보장 | 공급망 공격, client-side 암호화 우회 |
| Admin CLI/API | 인증, 권한, 감사 | 키 파괴, 정책 조작, 복호화 우회 |
| 대상 솔루션 integration point | 무결성, 비침습성 | 업무 기능 장애, 권한 우회, 암호화 누락 |
| gRPC protobuf message | 기밀성, 무결성, 순서성 | binary payload 평문 노출, schema confusion, streaming replay |
| A2A agent message/task/artifact | 기밀성, 무결성, 출처 검증 | agent 위장, task/context 혼동, artifact 탈취, prompt/tool-call 유출 |

## 4. 신뢰 경계

| 경계 | 신뢰 수준 | 주요 위협 |
|---|---|---|
| Browser JavaScript SDK | 낮음 | XSS, SDK 변조, 확장 프로그램, 공급망 공격 |
| Mobile SDK | 중간 | 탈옥/루팅, hook, reverse engineering, local secret extraction |
| Server SDK | 높음 | RCE, 로그 누출, memory dump, dependency compromise |
| Gateway/Sidecar | 중간~높음 | route misclassification, bypass path, plaintext upstream |
| KMS/HSM Adapter | 높음 | 과권한 grant, stale key, network MITM, timeout-induced bypass |
| Policy Store | 높음 | unauthorized policy update, rollback, drift |
| Nonce Store | 중간 | race condition, eviction, replay acceptance |
| SIEM/Log Pipeline | 중간 | 민감정보 label leakage, log tampering, delayed detection |
| Partner Boundary | 낮음~중간 | key exchange error, weak verification, replay, partner compromise |
| Target Solution Boundary | 중간 | extension point 오용, bypass route, 권한 context 손실 |
| Protocol Adapter Boundary | 중간 | message boundary 오판, metadata leakage, stream replay |
| AI Agent Boundary | 낮음~중간 | agent identity spoofing, delegated authority confusion, prompt/tool-call leakage |

## 5. 주요 발견사항

### H-001 Client-side encryption trust boundary is under-specified

- 심각도: High
- 관련 요구사항: PRD-I-002, SIR-002, SFR-ENC-001
- 문제: TypeScript SDK와 브라우저 암호화를 제공하지만, JS 실행 환경은 기본적으로 신뢰할 수 없다. XSS, CDN 변조, 악성 브라우저 확장, compromised dependency가 있으면 암호화 전 평문을 탈취하거나 암호화를 우회할 수 있다.
- 영향: 고객이 "브라우저에서 암호화하므로 서버까지 안전하다"고 오해할 수 있고, 실제 침해 시 제품 책임 경계가 무너진다.
- 보완 요구:
  - 브라우저 SDK는 XSS 방어를 대체하지 않는다고 명시해야 한다.
  - SDK 배포에는 Subresource Integrity, package signature, CSP 가이드, version pinning을 요구해야 한다.
  - 서버는 plaintext fallback을 허용하지 않고 encrypted-required field가 평문이면 거부해야 한다.
  - sensitive route에서는 client-provided policy id를 신뢰하지 않고 서버 정책으로 재평가해야 한다.
- 검증:
  - XSS simulation에서 SDK 우회 가능성을 threat model에 기록한다.
  - encrypted-required field에 평문을 보냈을 때 서버가 거부하는 통합 테스트를 작성한다.

### H-002 AEAD nonce/IV uniqueness is not sufficiently defined

- 심각도: High
- 관련 요구사항: SFR-ENC-003, SFR-DEC-004
- 문제: "고유 nonce 또는 IV" 요구는 있으나 distributed SDK, gateway, sidecar, multi-tenant 환경에서 키별 nonce 유일성을 어떻게 보장할지 정의되어 있지 않다. AES-GCM은 같은 key에서 IV가 재사용되면 치명적이다.
- 영향: nonce 재사용은 암호문 기밀성 및 인증 보장을 붕괴시킬 수 있다.
- 보완 요구:
  - 각 AEAD key별 nonce generation strategy를 명세해야 한다.
  - AES-GCM provider는 96-bit nonce를 기본으로 하고, random 방식이면 collision budget과 key rotation threshold를 명시해야 한다.
  - deterministic 방식이면 node/device id와 counter field의 충돌 방지 절차를 명시해야 한다.
  - nonce uniqueness property test와 대량 생성 collision test를 릴리스 게이트에 넣어야 한다.
- 검증:
  - 동일 key에서 10M nonce 생성 시 중복 없음 테스트.
  - multi-instance deterministic nonce에서 node id 충돌 시 startup fail-closed 테스트.

### H-003 Envelope algorithm and key confusion risk

- 심각도: High
- 관련 요구사항: SFR-ENC-005, SFR-DEC-001, SFR-DEC-002
- 문제: envelope에 `alg`, `kid`, `policy_id`가 포함되지만, 복호화 시 이 값들을 어떻게 신뢰할지 정의되어 있지 않다. 공격자가 `alg`, `kid`, `jku`, `jwk`, `x5u` 등 동적 key reference를 조작하면 algorithm confusion, key confusion, downgrade가 발생할 수 있다.
- 영향: 약한 알고리즘 선택, 잘못된 tenant key 사용, 임의 key 주입, 정책 우회가 가능해질 수 있다.
- 보완 요구:
  - 복호화는 envelope header가 아니라 서버 정책의 allowlist에서 algorithm과 key를 결정해야 한다.
  - `kid`는 policy와 tenant에 바인딩되어야 하며, 다른 tenant 또는 다른 policy의 key를 참조하면 거부해야 한다.
  - JWE 사용 시 `jku`, `jwk`, `x5u`, embedded key reference는 기본 금지해야 한다.
  - `alg=none`, deprecated algorithm, RSA1_5 등 금지 알고리즘 allowlist 테스트를 추가해야 한다.
- 검증:
  - header tampering, kid substitution, cross-tenant key substitution 부정 테스트.

### H-004 Decryption authorization is incomplete

- 심각도: High
- 관련 요구사항: SFR-DEC-006, SFR-KEY-002
- 문제: "policy가 허용한 context인지 확인" 요구는 있으나, 누가 어떤 목적으로 복호화할 수 있는지에 대한 권한 모델이 부족하다. 암호화 제품에서 복호화 권한은 가장 중요한 보안 경계다.
- 영향: 내부 서비스, gateway, batch job, 운영자 도구가 과도한 복호화 권한을 가질 수 있다.
- 보완 요구:
  - decrypt permission은 service identity, tenant, route, purpose, environment, key id 단위로 제한해야 한다.
  - KMS grant와 MSEL policy가 서로 불일치하면 더 좁은 권한을 적용해야 한다.
  - decrypt API는 caller identity가 없으면 동작하지 않아야 한다.
  - 운영자 break-glass decrypt는 별도 승인, 이중통제, 감사 이벤트를 요구해야 한다.
- 검증:
  - service identity가 다른 tenant ciphertext를 복호화하려 할 때 거부.
  - admin role만으로는 bulk decrypt가 불가능함을 테스트.

### H-005 Fail-open can become plaintext exfiltration

- 심각도: High
- 관련 요구사항: PRD-O-004, SNFR-SEC-004, SNFR-SEC-005
- 문제: fail-open을 policy 단위로 허용하는 요구가 있다. 암호화 솔루션에서 fail-open은 장애 완화가 아니라 평문 누출 경로가 될 수 있다.
- 영향: KMS 장애, policy load 실패, SDK 오류 상황에서 민감 데이터가 평문으로 지나갈 수 있다.
- 보완 요구:
  - sensitive classification이 있는 route/field는 fail-open을 금지해야 한다.
  - fail-open은 non-sensitive telemetry 또는 명시적 low-risk route에만 허용해야 한다.
  - fail-open activation은 break-glass event로 기록하고 알림을 발생시켜야 한다.
  - fail-open 중에는 암호화 보장 배지나 compliance claim을 비활성화해야 한다.
- 검증:
  - 민감 policy에서 fail-open 설정 시 policy validation 실패.
  - fail-open 발생 시 SIEM event와 alert 생성.

### H-006 KMS/HSM failure and DEK cache security are underspecified

- 심각도: High
- 관련 요구사항: SFR-KEY-007, SNFR-PERF-002, SNFR-REL-001
- 문제: KMS 지연 완화를 위해 cache를 언급하지만, cache에 저장되는 DEK/wrapped DEK의 범위, TTL, memory protection, revocation semantics가 부족하다.
- 영향: 메모리 덤프 또는 RCE가 발생하면 cache key가 대량 유출될 수 있고, disabled key가 cache 때문에 계속 사용될 수 있다.
- 보완 요구:
  - DEK cache는 기본 비활성 또는 짧은 TTL로 시작해야 한다.
  - cache key는 tenant, key version, policy, purpose에 바인딩해야 한다.
  - key disabled/revoked event 수신 시 cache를 즉시 purge해야 한다.
  - memory dump에서 key 노출을 줄이기 위해 provider가 지원하는 경우 zeroization과 off-heap/secure memory를 사용해야 한다.
- 검증:
  - key revocation 후 신규 암호화와 복호화 동작 정책 테스트.
  - cache TTL 초과 후 key 재조회 테스트.

### H-007 JSON canonicalization and field path ambiguity

- 심각도: High
- 관련 요구사항: SIR-003, SFR-POL-001, SFR-ENC-004
- 문제: JSON field-level encryption은 duplicate key, Unicode normalization, numeric representation, array path, case sensitivity, content-type spoofing 문제에 취약하다. 같은 데이터라도 parser마다 다르게 해석될 수 있다.
- 영향: 어떤 parser에서는 암호화된 것으로 보이고 다른 parser에서는 평문 필드가 살아남거나, AAD 검증이 우회될 수 있다.
- 보완 요구:
  - JSON parser는 duplicate keys를 거부해야 한다.
  - field path grammar를 명확히 정의해야 한다.
  - canonicalization 방식을 정하고 AAD 계산 전 동일한 normalization을 적용해야 한다.
  - 지원하지 않는 content type은 fail-closed해야 한다.
- 검증:
  - duplicate key, mixed Unicode, numeric edge case, nested array path 부정 테스트.

### H-008 Replay protection at scale is incomplete

- 심각도: High
- 관련 요구사항: SFR-DEC-004, SNFR-REL-002
- 문제: nonce store가 언급되어 있지만, TTL, atomic insert, idempotent retry 처리, cluster consistency, partition failure 동작이 정의되어 있지 않다.
- 영향: replay 공격을 허용하거나 정상 재시도를 오탐으로 거부할 수 있다.
- 보완 요구:
  - replay key는 tenant, sender identity, key id, nonce, policy id, direction을 포함해야 한다.
  - nonce store insert는 atomic check-and-set이어야 한다.
  - store 장애 시 sensitive route는 fail-closed해야 한다.
  - idempotency key와 replay nonce의 역할을 분리해야 한다.
- 검증:
  - 동시 요청 race에서 하나만 성공.
  - Redis/network partition에서 sensitive route fail-closed.

### H-009 Audit log integrity is insufficient

- 심각도: High
- 관련 요구사항: SFR-AUD-001, SFR-AUD-003
- 문제: audit event 기록 요구는 있으나 변조 방지, 보존, 순서성, 누락 감지, 관리자 행위 추적이 부족하다.
- 영향: 사고 발생 시 복호화 오남용, policy 변경, key 사용 이력을 입증하기 어렵다.
- 보완 요구:
  - audit event에는 actor, service identity, policy version, decision id, key version, result code를 포함해야 한다.
  - audit log는 hash chain 또는 external append-only sink로 무결성 검증 가능해야 한다.
  - admin/break-glass 행위는 별도 high-severity event로 분류해야 한다.
  - audit logging 실패 시 sensitive operation을 fail-closed할지 정책화해야 한다.
- 검증:
  - audit sink down 시 sensitive decrypt 거부 또는 queueing 동작 테스트.
  - log redaction snapshot test.

### H-010 Supply-chain and certification assurance are not release gates

- 심각도: High
- 관련 요구사항: SNFR-SEC-007, SNFR-MNT-004, PRD-F-007
- 문제: dependency scan과 SBOM은 있지만, 보안 제품에 필요한 release signing, provenance, reproducible build, KCMVP 적용 범위 증명이 부족하다.
- 영향: SDK/package 변조, 검증필 모듈이 아닌 경로 사용, 고객 감사 실패.
- 보완 요구:
  - 모든 release artifact는 서명되어야 한다.
  - SBOM, dependency lockfile, provenance attestation을 릴리스 산출물로 제공해야 한다.
  - KCMVP 모드에서는 검증필 암호모듈, 형상 해시, 보안정책문서, 동작모드 검증을 고객이 확인할 수 있어야 한다.
  - crypto provider 변경은 보안 리뷰와 호환성 테스트 없이는 릴리스할 수 없어야 한다.
- 검증:
  - release artifact signature verification.
  - KCMVP mode에서 non-validated provider 사용 시 startup fail.

### H-011 Protocol boundary confusion can bypass encryption

- 심각도: High
- 관련 요구사항: SIR-011, SIR-012, SIR-013, SIR-014, SFR-POL-007
- 문제: HTTP/HTTPS, WebSocket, raw TCP socket, gRPC, A2A는 각각 message boundary와 metadata 위치가 다르다. 같은 업무 의미의 요청이라도 REST body, gRPC protobuf field, WebSocket frame, A2A message part에 놓이면 정책이 다르게 적용될 수 있다.
- 영향: 일부 transport에서 암호화가 누락되거나, metadata에 남은 민감정보가 로그와 proxy에 노출될 수 있다.
- 보완 요구:
  - protocol adapter는 canonical policy context를 생성해야 한다.
  - adapter별로 암호화 대상 payload, metadata, routing field, trace field를 명시해야 한다.
  - HTTP header, gRPC metadata, WebSocket subprotocol, A2A AgentCard/metadata는 별도 leakage review 대상이어야 한다.
- 검증:
  - 동일 업무 operation을 HTTP, gRPC, A2A로 보냈을 때 동일 암호화 정책이 적용되는 equivalence test.
  - metadata 평문 노출 snapshot test.

### H-012 AI agent task/context confusion can expose delegated data

- 심각도: High
- 관련 요구사항: SFR-ENC-011, SFR-DEC-008, SNFR-SEC-022, SNFR-SEC-023, SNFR-SEC-024
- 문제: A2A와 gRPC 기반 AI agent 통신은 user delegation, agent identity, task id, context id, tool-call authorization, artifact exchange가 결합된다. 암호화가 payload에만 적용되고 agent/task/context 경계가 AAD와 권한 평가에 들어가지 않으면 다른 agent 또는 다른 task가 암호문을 재사용하거나 artifact를 탈취할 수 있다.
- 영향: prompt, tool output, retrieval snippet, 생성 artifact, 사용자 위임 데이터가 다른 agent나 tenant로 노출될 수 있다.
- 보완 요구:
  - agent id, user delegation id, task id, context id, artifact id를 AAD와 decrypt authorization에 포함해야 한다.
  - AgentCard discovery 결과는 서명, origin, TLS/mTLS, allowlist 등으로 검증해야 한다.
  - tool-call input/output과 generated artifact는 로그/메트릭 redaction의 기본 보호 대상으로 둬야 한다.
  - A2A streaming event와 push notification은 원 task/context와 sender identity에 바인딩해야 한다.
- 검증:
  - cross-agent, cross-task, cross-context ciphertext replay 부정 테스트.
  - AgentCard tampering과 artifact substitution 테스트.

## 6. Medium 발견사항

| ID | 발견사항 | 영향 | 보완 |
|---|---|---|---|
| M-001 | Plaintext memory lifetime이 구체적이지 않다. | memory dump/RCE 시 평문 노출 증가 | mutable buffer, scope 제한, zeroization best effort, log guard |
| M-002 | Envelope metadata leakage 분석이 없다. | tenant/key/policy enumeration, traffic analysis | opaque key alias, metadata minimization, length padding option |
| M-003 | Rate limiting과 abuse detection이 없다. | decrypt oracle, KMS cost DoS | caller별 quota, anomaly detection |
| M-004 | Error classification이 oracle이 될 수 있다. | key 존재 여부, policy 존재 여부 추론 | 외부 오류 통합, 내부 reason code 분리 |
| M-005 | Partner onboarding/key exchange 절차가 없다. | 잘못된 recipient key 또는 stale key 사용 | partner verification, key rollover ceremony |
| M-006 | Gateway/sidecar bypass path가 정의되지 않았다. | 암호화 미적용 우회 route | mandatory ingress policy, bypass detection |
| M-007 | PQC 표현이 marketing claim으로 오해될 수 있다. | 과장된 보안 주장, 호환성 문제 | experimental/validated status 분리 |
| M-008 | Multi-tenant isolation test가 부족하다. | cross-tenant decrypt | tenant isolation test matrix |
| M-009 | Metric label에 민감정보가 들어갈 수 있다. | observability leakage | label allowlist |
| M-010 | Admin CLI 권한 모델이 없다. | 키 삭제/정책 변경 오남용 | RBAC, MFA, approval workflow |
| M-011 | gRPC cancellation/deadline 처리 중 부분 처리된 평문 상태가 정의되지 않았다. | cancellation 후 평문 잔존 또는 감사 누락 | cancellation cleanup과 audit event |
| M-012 | A2A streaming/push notification의 disconnected delivery 보호가 부족하다. | push endpoint 탈취, stale task update | signed event, task binding, TTL |

## 7. Low 발견사항

| ID | 발견사항 | 보완 |
|---|---|---|
| L-001 | 보안 아키텍처 다이어그램이 없다. | trust boundary diagram 추가 |
| L-002 | 암호화하지 않는 항목의 명시가 부족하다. | non-goals와 residual risk 표 추가 |
| L-003 | 고객 통합 가이드 보안 체크리스트가 없다. | deployment hardening guide 추가 |
| L-004 | 테스트 데이터 정책이 없다. | synthetic PII와 fixture redaction 정책 추가 |
| L-005 | incident response 요구가 없다. | key compromise playbook 추가 |
| L-006 | 데이터 분류 기준이 없다. | sensitive classification taxonomy 추가 |

## 8. STRIDE 위협모델 요약

| STRIDE | 위협 | 통제 |
|---|---|---|
| Spoofing | partner 또는 service identity 위조 | mTLS, SPIFFE/OIDC binding, certificate pinning |
| Tampering | envelope header/policy 조작 | AEAD AAD, policy signature, allowlist |
| Repudiation | 운영자가 복호화 후 부인 | tamper-evident audit, break-glass approval |
| Information Disclosure | 평문, DEK, metadata 유출 | KMS/HSM, memory hygiene, redaction, metadata minimization |
| Denial of Service | KMS/nonce store 장애 유발 | circuit breaker, quotas, graceful fail-closed |
| Elevation of Privilege | decrypt permission escalation | least privilege grants, policy binding, admin RBAC |

## 9. OWASP Top 10 관점

| 항목 | 관련 리스크 | 상태 |
|---|---|---|
| A01 Broken Access Control | decrypt 권한, admin CLI, tenant isolation | 보강 필요 |
| A02 Cryptographic Failures | nonce uniqueness, key cache, algorithm confusion | 보강 필요 |
| A03 Injection | JSON parser ambiguity, policy injection, header manipulation | 보강 필요 |
| A04 Insecure Design | fail-open, client trust boundary, replay design | 보강 필요 |
| A05 Security Misconfiguration | weak provider, non-KCMVP mode, bypass route | 보강 필요 |
| A06 Vulnerable Components | dependency, SBOM, release signing | 일부 반영 |
| A07 Identification/Auth Failures | service identity, partner identity | 보강 필요 |
| A08 Software/Data Integrity Failures | SDK/package integrity, policy integrity | 보강 필요 |
| A09 Logging/Monitoring Failures | audit integrity, alerting | 보강 필요 |
| A10 SSRF | KMS/metadata endpoint, dynamic JWK URL | 동적 URL 금지 필요 |
| Agentic AI Risks | agent identity spoofing, task/context confusion, artifact substitution, prompt/tool-call leakage | 보강 필요 |

## 10. 보안 게이트

다음 조건을 만족하기 전에는 production-ready로 분류하지 않는다.

| Gate | 통과 기준 |
|---|---|
| G-001 Threat Model | trust boundary, abuse case, STRIDE, residual risk 문서화 |
| G-002 Crypto Design Review | nonce strategy, provider allowlist, key lifecycle, envelope schema 승인 |
| G-003 Key Management Review | KMS/HSM grants, rotation, revocation, cache, break-glass 검증 |
| G-004 Negative Test Suite | tamper, replay, wrong AAD, wrong tenant, wrong kid, duplicate JSON key 통과 |
| G-005 Logging Review | 평문/키 미노출, tamper-evident audit, alert route 검증 |
| G-006 Supply-chain Gate | SBOM, dependency scan, signed artifact, provenance 생성 |
| G-007 KCMVP Readiness | 검증필 provider 적용 범위, 동작모드, 형상 해시, 보안정책문서 확인 절차 |
| G-008 External Security Assessment | 독립 보안 리뷰 또는 모의해킹 완료 |
| G-009 Protocol Adapter Security | HTTP/HTTPS, socket, gRPC, A2A adapter별 boundary, metadata, streaming 부정 테스트 통과 |
| G-010 AI Agent Security | agent identity, user delegation, task/context, tool-call, artifact 보호 검증 |

## 11. SRS 반영 권고

다음 요구사항은 SRS에 직접 반영해야 한다.

- sensitive policy에서 fail-open 금지
- algorithm/key/policy allowlist와 binding
- JWE dynamic key reference 금지
- JSON duplicate key와 canonicalization 규칙
- distributed nonce strategy
- decrypt authorization model
- DEK cache TTL, revocation purge, zeroization
- audit log tamper evidence
- SDK/release artifact signing
- KCMVP mode startup validation

## 12. 참고 링크

- OWASP ASVS: https://owasp.org/www-project-application-security-verification-standard/
- OWASP Cryptographic Storage Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html
- OWASP Key Management Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Key_Management_Cheat_Sheet.html
- NIST SP 800-57 Part 1 Rev. 5: https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final
- NIST SP 800-38D: https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-38d.pdf
- RFC 8446 TLS 1.3: https://datatracker.ietf.org/doc/html/rfc8446
- RFC 7516 JWE: https://datatracker.ietf.org/doc/rfc7516/
- RFC 9180 HPKE: https://www.ietf.org/rfc/rfc9180.html
- gRPC Core Concepts: https://grpc.io/docs/what-is-grpc/core-concepts/
- A2A Agent2Agent Protocol: https://a2a-protocol.org/latest/specification/
- KISA KCMVP 개요: https://seed.kisa.or.kr/kisa/kcmvp/EgovSummary.do
- KISA KCMVP 검증대상 암호알고리즘: https://seed.kisa.or.kr/kisa/kcmvp/EgovVerification.do
