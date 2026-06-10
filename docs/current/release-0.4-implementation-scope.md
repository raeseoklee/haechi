# Haechi 0.4 Implementation Scope

- 문서 상태: Draft 0.1
- 작성일: 2026-06-10
- 기준 버전: 0.4.0 (0.3.2 이후)
- 주제: token round-trip and adoption

## 1. 릴리스 목표

0.4는 두 가지를 완성한다.

1. **토큰 왕복(token round-trip)**: 모델은 토큰만 보고 사용자는 평문을 보는 구조. tokenize action이 실사용 의미를 갖게 한다.
2. **채택 장벽 축소**: MCP wrap 모드, audit 검증/status 명령으로 끼워넣기 UX와 운영 가시성을 확보한다.

추가로 0.6(auth)·0.7(dashboard) 확장의 전제가 되는 `identity` 스키마와 `authProvider` 계약을 **구현 없이 계약만** 예약한다.

## 2. 범위

### 2.1 결정적 토큰화 (deterministic tokenization)

- 동일 (type, value)는 동일 토큰으로 토큰화하는 opt-in 모드: `tokenVault.deterministic: true` (기본 false)
- 토큰 생성: `haechi:token-vault:deterministic:v1` domain-separated 파생 키로 `HMAC(derivedKey, type || value)` — 키 파일 없이는 역산/사전 공격 불가
- 기존 레코드가 있으면 재사용하고 expiry를 갱신한다
- **트레이드오프 문서화 필수**: 결정성은 동일값 연결성(linkability)을 만든다. 타입별 opt-in(`tokenVault.deterministicTypes`)을 지원한다

### 2.2 응답 detokenization (요청 스코프)

- 새 config: `tokenVault.detokenizeResponses: true` (기본 false, 명시 opt-in)
- **요청 스코프 원칙**: 요청 보호 단계에서 발급/재사용된 토큰 집합만 그 요청의 응답에서 복원한다. 세션 저장소·세션 ID 불필요
- 멀티턴은 결정적 토큰화로 해결된다: 클라이언트가 매 턴 보내는 대화 이력이 재토큰화되며 이전 턴 토큰이 현재 요청의 토큰 집합에 자동 포함된다
- **revealPolicy와 분리**: `revealPolicy: disabled`는 CLI/수동 reveal 통제이며 응답 복원과 무관하다. 복원 행위는 vault audit 이벤트(`detokenize` decision, 토큰 수만 기록)로 남긴다
- responseProtection이 활성일 때만 동작한다 (응답 본문을 이미 파싱하는 경로에서만 복원)

### 2.3 `haechi mcp-wrap`

- 형태: `haechi mcp-wrap --config haechi.config.json -- <command> [args...]`
- 자식 프로세스를 spawn하고 stdio 양방향을 필터링한다
  - 클라이언트→서버: method allowlist + params 보호
  - 서버→클라이언트: result 보호 (+ 2.6 injection 탐지)
- stderr는 투명 통과, 종료 코드·SIGINT/SIGTERM 전파
- notification drop·batch fail-closed 의미론은 0.3.2와 동일

### 2.4 `haechi audit-verify`

- `haechi audit-verify [--audit .haechi/audit.jsonl]`
- `verifyAuditChain()` 결과(valid/records/reason)와 chain head hash를 출력한다
- head hash는 외부 앵커링(tail truncation 대응)의 기초 자료다. 주기적 앵커 자동화는 0.6+ 범위

### 2.5 `haechi status`

- 현재 config의 유효 상태를 한눈에 출력: 유효 policy mode(enforce/dry-run/report-only), responseProtection on/off, streaming mode, revealPolicy, detokenization on/off, privacy profile, adapter/upstream, key file 존재·권한, audit chain 검증 요약
- dry-run 기본값 제품에서 "지금 보호되고 있는가"에 답하는 명령이다. JSON 출력 지원

### 2.6 injection detection type (preview)

- 새 detection type `injection`: tool result/응답 방향에 한정 적용하는 휴리스틱 룰셋 (지시문 패턴, 역할 전환 시도, 도구 호출 유도)
- **기본 action은 `allow`** — detection은 action과 무관하게 audit에 기록되므로 이것이 곧 report-only다. 신뢰가 쌓이면 사용자가 `actions.injection: "redact" | "block"`으로 격상한다
- 기본 block은 금지: 오탐이 보안 제품 신뢰를 깎는다

### 2.7 `identity` 스키마 예약 (구현 없음)

audit 이벤트와 protect context에 PII-safe identity 필드를 예약한다. 0.4에서는 항상 `null`이다.

```js
identity: {
  id: "...",            // provider 발급 opaque id 또는 subjectHash와 동일
  type: "anonymous" | "user" | "service" | "agent",
  subjectHash: "...",   // HMAC("haechi:identity:hash:v1" 파생 키, subject) — bare sha256 금지
  issuerHash: "...",    // 동일 방식
  provider: "none" | "bearer" | "oidc" | "external",
  scopes: ["..."],
  labels: {}            // allowlist된 키만 (config 선언), 값 길이 제한, PII 금지
}
```

- subject/email 등 **원문은 어떤 필드에도 금지**. 저엔트로피 식별자의 bare hash는 사전 공격으로 복원 가능하므로 keyed HMAC만 허용한다
- `labels`는 자유 형식 금지: config에 선언된 allowlist 키만 통과시키고 값 길이를 제한한다
- 표시용 이름은 audit 스키마가 아니라 dashboard 측 opt-in 설정이다

### 2.8 `authProvider` 계약 예약 (구현 없음)

- 계약: `authenticate(request) → identity | null` (null = 거부), 실패는 fail-closed
- 프록시 실행 순서 (0.6 구현 시):

```text
request target 검증 (assertRelativeProxyTarget)
route classify
authProvider.authenticate()        ← body 읽기 전. 인증 실패 요청의 대용량 body DoS 차단
policy scope 결정 (identity 기반)
body read
protect/enforce
forward
```

- 인증 실패는 `auth_denied` decision으로 audit 기록 (시도된 provider만, identity 원문 없음)
- 401 응답 시 request stream을 소비하지 않고 응답 후 연결을 닫는다
- `/__haechi/health`는 의도적으로 무인증 유지 (mode만 노출), 계약 문서에 명시
- `createRuntime(config, { authProvider })` 주입만 지원. **동적 npm 로딩은 1.0 plugin sandbox 이전까지 금지**

## 3. 명시적 비범위 (0.4에서 하지 않음)

- auth 구현 (bearer 포함) — 0.6
- SSE/NDJSON stream inspection — 0.5
- proxy auth, model allowlist, rate/budget, hot reload, metrics — 0.6
- dashboard, npm workspaces 전환 — 0.7
- 외부 package 동적 로딩 — 1.0

## 4. 테스트 기준

- detokenization: 요청에 없던 토큰은 응답에서 복원되지 않는다 (스코프 격리)
- deterministic: 동일 값 → 동일 토큰, 파생 키 변경 시 다른 토큰
- mcp-wrap: 양방향 보호, allowlist 거부, 자식 종료 코드 전파
- audit-verify: 정상/변조/절단 케이스 출력
- status: enforce/dry-run 각각에서 경고 정확성
- injection: 기본 allow에서 audit 기록만 되고 payload 불변

## 5. 문서 영향

- README: detokenization·mcp-wrap·status 사용법, deterministic linkability 트레이드오프
- threat-model: injection 휴리스틱의 한계(완전 방어 아님) 명시 유지, identity hash 방식 추가
- api-stability: authProvider/identity 계약은 0.4에서 experimental 표기
