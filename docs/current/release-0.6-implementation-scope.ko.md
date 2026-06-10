# Haechi 0.6 Implementation Scope

- 문서 상태: Final
- 작성일: 2026-06-10
- 기준 버전: 0.6.0 (0.5.0 이후)
- 성격: auth and per-client controls
- 구현 완료: 2026-06-10 — PR #17 (계약 + bearer store + CLI), #18 (named profiles), #19 (proxy enforcement)

## 1. 릴리스 목표

0.4에서 예약해 둔 `authProvider`/`identity` 계약을 구현하고, identity를 실질적인 per-client 제어로 전환한다: 내장 bearer 인증, 명명된 per-client policy profile, model allowlist, request rate limiting. 이로써 Haechi를 단일 호스트에서 복수의 클라이언트/에이전트 앞에 안전하게 배치할 수 있게 된다.

**범위 결정 (2026-06-10):** 0.6은 auth 핵심에 집중한다. 원래 0.6으로 묶였던 무거운 운영 항목들 — Vault/AWS KMS 레퍼런스 어댑터, 외부 append-only audit 싱크, 서명된 릴리스 아티팩트, `haechi-*` 패키지 패밀리 — 은 각각 별도의 보안 설계를 받을 수 있도록 **0.7**로 이월한다.

## 2. 범위

### 2.1 `authProvider` 계약 (core 소유)

- `authenticate(request) → identity | null` (null = 거부). `request`는 Node `IncomingMessage`이며 헤더만 사용 가능 — body는 **아직 읽지 않는다**.
- Fail-closed: 예외를 던지는 provider는 거부로 처리한다. `createRuntime(config, { authProvider })`를 통해 주입한다.
- `auth.provider`로 선택한다:
  - `none` (기본값) — 인증 없음; `identity`는 `null`로 유지 (0.5와 byte 단위로 동일한 audit 형태). Per-client policy는 default profile / base policy로 결정된다.
  - `bearer` — 내장 token auth (§2.2).
  - `external` — 주입된 `authProvider` 필요; 없으면 fail-closed (`keys.provider: external`과 동일한 방식). OIDC/JWT provider는 **0.7+ 위성 패키지** (`haechi-auth-oidc`)로 남긴다; 0.6은 네트워크 IdP 코드를 포함하지 않는다.

### 2.2 내장 bearer auth + token store

- 자격 증명은 **별도 파일** `.haechi/auth.json` (mode `0600`)에 저장한다. `haechi.config.json`에는 절대 두지 않는다:
  ```json
  {
    "version": 1,
    "tokens": [
      { "id": "tok_auth_ab12cd", "tokenHash": "...", "type": "service",
        "scopes": ["team:eng"], "labels": { "env": "prod" },
        "createdAt": "...", "disabled": false }
    ]
  }
  ```
- `tokenHash` = `HMAC(derive("haechi:auth:token:v1"), token)` — 키 기반, domain-separated ([[key-management]] 규범 적용), bare hash 금지. 조회 시 timing-safe 비교를 사용한다.
- 토큰은 고엔트로피 `hae_<base64url(32 bytes)>` 형식이다. **평문은 생성 시 한 번만 출력하고 절대 저장하지 않는다.**
- CLI:
  - `haechi auth add --type user|service|agent [--scope k:v ...] [--label k=v ...]` → 토큰을 발급하고, 해시와 메타데이터를 저장하며, 평문을 한 번만 출력한다.
  - `haechi auth list` → id, type, scopes, labels, createdAt, disabled만 출력 — 토큰이나 해시는 절대 노출하지 않는다.
  - `haechi auth revoke <id>` → `disabled: true`로 설정한다.
- 라벨 키는 `auth.allowedLabelKeys` (기본값 `["team", "env", "tier", "role"]`)에 대해 검증하며; 값은 길이를 제한한다. `add` 시점에 라벨의 PII는 거부된다.

### 2.3 Identity 구성 (PII-safe)

bearer 매칭 성공 시 예약된 `identity` 객체를 구성한다:
- `id`: token 레코드 id (불투명).
- `type`: 레코드에서 가져온다.
- `subjectHash`: `HMAC(derive("haechi:identity:hash:v1"), record.id)`; `issuerHash`: `"bearer-local"`의 HMAC. 식별자의 bare SHA-256은 금지한다.
- `provider`: `"bearer"`.
- `scopes`, `labels`: 레코드에서 가져온다 (이미 allowlist 검증 완료).

동일한 identity가 해당 요청의 모든 audit 이벤트(protect 이벤트, decision)에 첨부된다. `identity`는 `auth.provider: none` 하에서 `null`로 유지된다.

### 2.4 명명된 policy profile (per-client policy)

`policy`에 profile과 binding 맵이 추가된다:
```json
"policy": {
  "mode": "enforce", "presets": ["..."], "actions": { },          // base / fallback policy
  "profiles": {
    "strict":   { "presets": ["strict-block"] },
    "internal": { "presets": ["llm-redact"], "actions": { "email": "allow" },
                  "modelAllowlist": ["llama3"], "rate": { "requestsPerMinute": 120 } }
  },
  "profileBinding": {
    "byScope": { "team:eng": "internal" },
    "byLabel": { "tier=trusted": "internal" },
    "default": "strict"
  }
}
```
- profile은 기존 `buildPolicy`를 통해 컴파일된다 (presets + actions, strengthen-only 병합 유지). `modelAllowlist`와 `rate`는 profile별 선택 사항이며, 없으면 base 레벨 값으로 fallback한다.
- 요청별 결정 순서: **scope 일치 → label 일치 → `profileBinding.default`**. 첫 번째 일치가 우선하며, scope가 label보다 앞선다. `profiles`가 설정된 경우 `profileBinding.default`는 **필수**이며, 가장 제한적인 profile이어야 한다 (미일치/익명 identity에 대한 fail-closed).
- `auth.provider: none`이거나 `profiles`가 없으면 base `policy`가 변경 없이 적용된다 (완전한 하위 호환성).
- 구현: `createRuntime`은 시작 시 `{ name → policyEngine }` 맵을 컴파일한다 (모든 profile을 미리 검증). `protectJson(payload, context)`는 `context.policyEngine`을 받아 기본 엔진 대신 사용한다. proxy는 `authenticate` 후 profile을 결정하고, 선택된 엔진을 전체 경로에 전달한다.

### 2.5 Model allowlist

- Profile별 `modelAllowlist` (및 base 레벨 `policy.modelAllowlist`): 설정된 경우 요청 body의 `model`이 목록에 없으면 → `403 haechi_model_not_allowed` (audit 기록, 모델 이름 포함 — 모델 이름은 비밀이 아님). 비어 있거나 없으면 모두 허용.
- body 읽기 **이후** 실행된다 (`model` 필드는 JSON body 안에 있음).

### 2.6 Rate limiting

- 인메모리, 프로세스 단위 fixed-window 카운터. 키는 `identity.id` (또는 `"anonymous"`). **문서화된 제한사항:** 재시작 시 초기화되며, 레플리카 간 공유 없음 — 단일 프로세스 self-hosted preview 환경에서 허용 가능한 수준.
- Profile별 / base `rate.requestsPerMinute`. 한도 초과 시 → `429 haechi_rate_limited` (identity + 한도 포함 audit 기록).
- body 읽기 **이전** 실행된다 (identity 기반으로 저렴함). throttle된 인증 클라이언트가 대용량 body로 DoS를 가할 수 없도록 한다.
- LLM **token budget** (tokens-per-window)은 이월 — 모델 토큰 계산이 필요하며; 0.7+ 백로그로 기재.

### 2.7 Proxy 실행 순서 (예약된 계약, 확정)

```
GET /__haechi/health                      (항상 무인증; mode만 노출)
assertRelativeProxyTarget(request.url)
route classify
authProvider.authenticate(request)        → 거부 시 401 haechi_auth_denied; request stream 미소비
resolve policy profile from identity
rate limit by identity                    → 429 haechi_rate_limited
body read (bounded by limits.maxRequestBytes)
model allowlist check                     → 403 haechi_model_not_allowed
protect / enforce  (selected profile's policyEngine)
forward
```

### 2.8 Audit 추가 사항

- 인증 성공 시 PII-safe `identity`를 모든 이벤트에 첨부; 이벤트에는 결정된 `profile` 이름도 포함 (profile 없으면 `null`). 둘 다 비민감 정보.
- 새로운 decision: `auth_denied` (reason: `no_token` | `invalid_token` | `provider_error`; raw token 없음), `model_not_allowed`, `rate_limited`. 가능한 경우 시도/결정된 identity를 포함하며, 평문 자격 증명은 절대 포함하지 않는다.

## 3. Config 스키마 요약

```json
"auth": {
  "provider": "none",                     // none | bearer | external
  "store": ".haechi/auth.json",
  "allowedLabelKeys": ["team", "env", "tier", "role"]
}
```
`policy.profiles`, `policy.profileBinding`, `policy.modelAllowlist`, `policy.rate` (§2.4–2.6) 추가. 모두 fail-closed로 검증한다 (알 수 없는 provider, profiles 설정 시 `profileBinding.default` 누락, binding의 알 수 없는 profile 이름, 비양수 `rate` 등).

## 4. 명시적 비범위 (0.7+로 이월)

- OIDC/JWT provider (`haechi-auth-oidc`, `haechi-auth-jwt`) — 0.6은 bearer + external 주입만 포함.
- Vault/AWS KMS 레퍼런스 어댑터; 외부 append-only audit 싱크; 서명된 릴리스 아티팩트; the `haechi-*` package family.
- LLM token-budget limiting; 분산/공유 rate 상태.
- auth provider의 동적 npm 로딩 (1.0 plugin sandbox).

## 5. 하위 호환성

`auth.provider`는 `none`이 기본값이며, `profiles`가 없으면 0.6은 0.5와 완전히 동일하게 동작한다 (identity `null`, 단일 base policy). 유일한 audit 형태 변경은 항상 존재하는 `profile` 필드(identity 도입 방식과 동일) — 문서화되어 있으며, 미공개 소비자 preview에 대한 마이그레이션은 불필요하다.

## 6. 테스트 기준 (구현 시)

- bearer: 유효 token → identity; 누락/유효하지 않은 token → 401 `auth_denied`, body 미소비, timing-safe 조회; 폐기된 token 거부.
- 주입된 external provider → 사용됨; 없으면 fail-closed.
- profile 결정: scope 일치, label 일치, default fallback; default 누락 시 검증 실패; 서로 다른 profile이 서로 다른 action/allowlist 적용.
- model allowlist: 허용된 model 통과, 허용되지 않은 model → 403.
- rate limit: 윈도 내 N개 통과 / N+1 → 429; 윈도 초기화; per-identity 격리; body 이전 적용.
- auth CLI: `add`는 token을 한 번만 출력; `list`는 token/hash 비노출; `revoke`는 비활성화.
- `/__haechi/health` 무인증.
- audit: identity PII-safe (raw token/subject 없음), `profile` 기록됨, chain 유효; `auth_denied`/`model_not_allowed`/`rate_limited` decision 존재.

## 7. 권장 PR 분할 (스택)

1. `authProvider` 계약 + bearer store + `haechi auth` CLI + identity 구성.
2. 명명된 policy profile + 요청별 policy engine 선택.
3. Model allowlist + rate limiting + proxy 실행 순서 배선.
4. 0.6.0 릴리스 컷 (버전, 문서 EN/KO, threat-model/risk-register/api-stability, wiki).
