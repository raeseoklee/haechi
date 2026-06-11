# Haechi 0.9 구현 범위

- 상태: Draft 0.2 (설계 — 아직 미구현; 2026-06-11 적대적 보안 리뷰 후 강화)
- 날짜: 2026-06-11
- 목표 버전: 0.9.0 (0.8.0 다음)
- 유형: 관측가능성(observability) + 인터랙티브 인증

## 1. 릴리스 목표

0.8을 code-light하게 유지하려고 의도적으로 미뤘던 **관측가능성 + 인터랙티브 인증** 쌍을 전달한다:

- **`haechi-dashboard`** — zero-dependency, 읽기 전용 **감사 뷰어**: `node:http` 서버가 자체완결형 정적 페이지 한 장(바닐라 JS, 프레임워크 없음, 빌드 스텝 없음)과 감사 로그 + 해시체인 상태에 대한 읽기 전용 JSON API를 서빙한다.
- **`haechi-auth-oidc`** — **인터랙티브 세션 브로커**: 사람이 브라우저로 로그인해 서버측 세션을 얻는 OIDC authorization-code + PKCE 플로우. 이는 대시보드의 로그인 메커니즘이며 — 요청마다 *사전취득* bearer JWT를 검증하는 `haechi-auth-jwt`와는 별개의 관심사다.

둘 다 0.8 패키징 모델을 따르는 신규 **언스코프드 위성**(`haechi-dashboard`, `haechi-auth-oidc`)이다: core에 peer-dep, 프로토콜이 허용하는 곳은 zero-dep, 무거운 SDK는 optional-peer, provenance + sigstore가 붙는 OIDC trusted publishing.

**범위 결정 (2026-06-11).** 메인테이너와 확정:

1. **릴리스 단위:** `haechi-dashboard` + `haechi-auth-oidc`를 0.9.0 테마로 **짝지어** 출시한다(대시보드는 사람 로그인이 필요하고 auth-oidc가 이를 제공). **`haechi-crypto-kms` Vault/GCP/Azure 백엔드는 독립적으로** `haechi-crypto-kms@0.2.0`으로 출시한다 — 이 위성은 자체 버전 관리되며 core 0.9.0 컷과 **무관**하다. 본 문서는 셋 다 명세하되 crypto-kms 0.2.0은 병렬·분리 트랙으로 다룬다(§2.4).
2. **대시보드 스택:** **zero-dependency 바닐라** — `node:http` + 정적 HTML/JS/CSS, 프레임워크/빌드 스텝 없음. core의 `node:`-빌트인-only 기풍과 위성의 의존성-경량 자세와 일관.
3. **`haechi-auth-oidc` 형태:** **인터랙티브 세션 브로커**(authorization-code + PKCE + `/callback` + 서버측 세션). 요청별 토큰 검증기가 아님 — 그 역할은 `haechi-auth-jwt`가 유지.
4. **대시보드 데이터 범위:** **감사 뷰어만** — 감사 이벤트 스트림 + `verifyAuditChain` 체인 상태 + decision/action 집계. 토큰볼트/정책 시각화는 0.9 범위 밖(reveal governance 경계를 건드리지 않도록).

core(`haechi`, 언스코프드)는 **zero runtime dependency**를 유지하고 0.9에서 **동작이 변경되지 않는다**. 기존 패키지에 대한 유일한 변경은 `haechi-auth-jwt` 위성을 *가산적·동작보존* 리팩터하여 재사용 가능한 JWS 검증기를 export하는 것(§2.2)뿐 — **`packages/*`(core) 코드 변경은 불필요**하다. 대시보드의 loopback 가드는 이미 export된 `haechi/proxy`의 `assertSafeProxyBind`를 재사용한다(core 재배치 없음 — §2.1).

### 버전 전제 (2026-06-11 기준 라이브 상태)

| 패키지 | 현재 | 0.9 목표 | 이유 |
|---|---|---|---|
| `haechi` (core) | `0.8.0` (발행됨) | `0.9.0` | 릴리스 컷; 동작 불변 |
| `haechi-auth-jwt` | `0.1.1` (발행됨) | **`0.2.0`** | 가산적 검증기 export(§2.2) — 발행 워크플로의 tag==package-version 게이트가 명시적 bump를 요구 |
| `haechi-crypto-kms` | `0.1.1` (발행됨) | **`0.2.0`** | 가산적 GCP/Azure/Vault 백엔드(§2.4); 하드코딩된 provider `version` 필드도 정합(§2.4) |
| `haechi-dashboard` | — (신규) | `0.1.0` | 첫 발행이 언스코프드 이름을 선점 |
| `haechi-auth-oidc` | — (신규) | `0.1.0` | 첫 발행이 언스코프드 이름을 선점 |

workspace-lockfile 규칙(이전에 물린 적 있음)대로, **신규** `satellites/*` 디렉터리 두 개를 추가하면 그 workspace 엔트리를 포함하도록 `npm install`로 `package-lock.json`을 재생성해 같은 PR에 커밋해야 하며, 아니면 CI `npm ci`가 실패한다.

## 2. 범위

### 2.1 `haechi-dashboard` — zero-dep 읽기 전용 감사 뷰어

`createDashboardServer(options)`와 선택적 bin(`haechi-dashboard`)을 노출하는 위성. 기존 감사 JSONL(과 anchor 스트림)을 읽어 읽기 전용으로 서빙한다. **프레임워크를 import하지 않고, 빌드 스텝이 없으며, 정확히 세 개의 정적 자산**(HTML 1, JS 1, CSS 1)을 **코드 내 고정 자산 맵**에서 서빙한다 — 요청 URL에서 파생한 `fs` 경로는 절대 사용하지 않는다(path traversal 없음).

**구성 + fail-closed 검증 (config 불변식 동등성).** 위성은 core 설정 파일이 아니라 명시적 주입으로 연결되므로, 대시보드는 `normalizeConfig`의 규율을 그대로 따르는 export형 **`normalizeDashboardConfig(options)`**를 제공한다: **생성 시점에 strict·fail-closed·열거형 throw**(모든 옵션 타입 체크; 알 수 없는 키 거부). 필드: `auditPath`(문자열, 필수), `anchorPath`(문자열|null), `host`(기본 `127.0.0.1`), `port`(정수 1–65535), `allowRemoteBind`(불리언), `sessionGuard`(객체|null), `window`(bounded int), `tlsContext`/`trustProxy`(§ remote-bind). 잘못된 옵션마다 안정적 에러를 throw하고, `configuration.md`(+ `.ko.md`)에 모든 옵션·타입·기본값·throw 조건을 열거하는 대시보드 섹션을 추가한다. `createDashboardServer`는 먼저 `normalizeDashboardConfig`를 호출한다.

**생성 시점 bind/guard 우선순위 (fail-closed, 정확한 순서):**

1. `!isLoopback(host) && !allowRemoteBind` → **throw** (loopback 가드; 아래 참조).
2. `!isLoopback(host) && allowRemoteBind && !sessionGuard` → **throw** `"remote bind requires a sessionGuard"`.
3. `!isLoopback(host)` (원격, 가드 있음) → **확인된 HTTPS 종단을 요구**(`tlsContext`, 또는 구성된 신뢰 프록시 주소에서 온 `X-Forwarded-Proto`만 신뢰하는 `trustProxy`) — 아니면 **throw**(Secure/`__Host-` 세션 쿠키는 평문 http로는 전송되지 않으므로 비-TLS 원격 bind는 로그인을 조용히 깨뜨림; fail closed). 원격 경로에는 `Strict-Transport-Security`를 추가한다.

**Loopback bind**은 core가 이미 export한 `assertSafeProxyBind`를 재사용한다(`import { assertSafeProxyBind } from "haechi/proxy"` — **core 재배치 없음**, 신규 `haechi/net` export 없음). 그 throw 텍스트는 proxy 문구이고 `--allow-remote-bind`를 언급하므로, 대시보드는 이를 **catch 후 자체 메시지로 rethrow**한다(대시보드는 그 CLI 플래그가 아니라 `allowRemoteBind` 옵션을 노출).

**Anti-DNS-rebinding Host 헤더 allowlist (필수, bind 체크와 구분).** loopback bind만으로는 미인증 localhost 뷰어를 보호하지 못한다: 운영자가 방문하는 임의 사이트가 짧은 TTL DNS 이름을 `127.0.0.1`로 재해석시키면, 피해자 브라우저가 대시보드로 동일출처 요청을 보내 공격자 JS가 감사 JSON을 읽을 수 있다. 따라서 **모든** 요청(`/api/*`·`/healthz` 포함)은 **`Host` 헤더** 호스트 부분이 allowlist `{localhost, 127.0.0.1, [::1], ::1, ::ffff:127.0.0.1, 구성된 bind host}`에 없으면 `403`으로 거부된다. 이는 **bind-string 체크와 별개의 요청-헤더 함수**이며(`assertSafeProxyBind`는 신뢰 못 할 헤더가 아니라 bind 문자열을 검증), 자체 정규화를 갖는다: `Host`를 host+port로 파싱, 변형/중복 `Host` 거부, 단일 후행 점(`localhost.`) 제거, IPv4-mapped IPv6·대괄호 IPv6 처리. CORS는 **부재** — `Access-Control-Allow-Origin`을 설정/반사하지 않는다.

**API (전부 GET/HEAD, 읽기 전용):**

- `GET /api/events?cursor=&limit=` — 최신순, **bounded-window** 감사 이벤트 페이지. **엄격한 쿼리 파싱:** `limit`은 `[1,200]` 정수(NaN/음수/비정수 거부); `cursor`는 서버 발급 불투명 토큰 = `auditIntegrity.sequence`(단조·안정), 변형 시 `400`, **fs offset으로 직접 쓰지 않음**. 이벤트는 **실제** 감사 스키마(아래)에 맞춘 **재귀적·키별 필드 allowlist projection**을 통과한다 — 서버는 중첩 하위 객체(`detections`, `identity`, `summary`, `auditIntegrity`)를 **통째로 spread/통과시키지 않으므로** 어느 계층의 미래 필드도 새지 않는다(core `FORBIDDEN_KEYS` 위의 심층 방어). bounded tail 윈도보다 오래된 페이지는 에러가 아니라 `"window exceeded"` 마커로 빈 응답; 동시 append로 인한 찢어진 후행 줄은 (`readAnchors`처럼) 허용·스킵하고 `500`을 내지 않는다.
- `GET /api/chain` — `verifyAuditChain(auditPath, { anchorPath })`의 **실제** 출력에서 파생: 성공 `{ valid:true, records, headHash, anchored?:{count,lastSequence} }`, 실패 `{ valid:false, records }`. **`truncationDetected`는** 대시보드가 `valid===false && reason.startsWith("tail truncation")`로 **파생**하고, **원문 `reason`은 노출하지 않는다**(`eventHash`/sequence가 박힐 수 있음 — 예: `"anchor hash mismatch at sequence N"`). `valid===false`는 눈에 띄게 표시(유일한 변조 신호). **bounded compute:** 단일 직렬화 in-process 작업(동시 재-walk 없음), 감사 파일 `mtime+size` 변경 시에만 재계산(캐시 키 = `mtime+size`); 하드 최대 파일 크기 초과 시 walk 대신 `413`/`{valid:null}`. `HEAD /api/chain`은 헤더만 반환하고 새 walk를 강제하지 않는다.
- `GET /api/summary` — 이벤트 윈도의 `summary.byType`/`summary.byAction`/`summary.detectionCount` 집계.
- `GET /healthz` — liveness만(감사 데이터·경로·버전·config 없음); **세션 없이도, loopback 밖에서도 의도적으로 도달 가능**(가드된 원격 대시보드도 liveness probe에 응답해야 함).

**실제 감사 이벤트 스키마 (projection의 진실 원천).** 디스크 레코드(`packages/core/index.mjs` `buildAuditEvent`에서 생성, integrity는 `packages/audit/index.mjs`가 추가):

```
{ id, timestamp, protocol, operation, identity, profile, mode, enforced, blocked,
  payloadShapeHash,
  detections: [ { type, ruleId, path, kind, confidence, action, enforced } ],   // `path`는 옛 "pathText" — XSS 위험·클라이언트 키 파생 필드, 여기 NESTED
  summary: { byType, byAction, detectionCount },
  auditIntegrity: { alg, canonicalization, sequence, previousHash, eventHash } } // proxy 기록 이벤트는 top-level `direction`을 추가할 수 있음
```

projection은 키별로 다음을 방출: top-level `id, timestamp, protocol, operation, mode, enforced, blocked, direction?`; detection별 `type, ruleId, path, kind, confidence, action, enforced`; `summary.{byType, byAction, detectionCount}`; `auditIntegrity.{sequence, previousHash, eventHash}`; `identity.{id, type, subjectHash, issuerHash, provider}`(`scopes`/`labels`/원본 subject는 **절대** 아님). `payloadShapeHash`는 포함 가능(shape-only 해시, 비민감).

**웹 보안 명세 (선택지 아닌 합격 기준):**

- **XSS.** allowlist된 `detections[].path`는 클라이언트 JSON 키에서 파생됨(요청 키 `<img onerror>`가 로그에 도달). **allowlist는 필드 *이름*을 한정(누출 봉쇄); CSP + `textContent` 렌더링이 악성 *값*을 무력화** — 둘 다 필수이며 독립적. 클라이언트는 `createElement` + `textContent`만으로 DOM 구성(보간 `innerHTML` 금지). CSP(모든 응답, 그대로): `default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'none'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'; require-trusted-types-for 'script'` — Trusted Types가 잔류 `innerHTML` 싱크를 브라우저에서 throw시켜 관례를 강제 보장으로 전환. 인라인 스크립트/스타일 없음(동일출처 자산 파일), 외부 CDN 없음, `eval` 없음.
- **보안 헤더 (모든 응답):** `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `X-Frame-Options: DENY`(레거시 clickjacking 폴백), `Cross-Origin-Resource-Policy: same-origin` 및 `Cross-Origin-Opener-Policy: same-origin`(CORP same-origin은 교차출처 페이지가 `/api/*`를 리소스로 읽는 것을 차단 — Host 체크와 독립인 rebinding/no-cors 유출 2차 방어). `Cache-Control: no-store`를 `/api/*` **및** HTML 셸(라이브 감사 데이터 렌더)에; JS/CSS는 짧은 validated cache(또는 전역 `no-store` — localhost 도구는 캐시 이득 없음).
- **메서드 allowlist:** `GET`/`HEAD`만; 그 외 → `405`. `POST`/`DELETE` 표면 **없음**(reveal·purge·정책 편집 없음 — CLI에서 reveal governance 하에 유지). "읽기 전용"은 **감사 데이터 변경 없음 + 특권 동작 없음**을 뜻하며, `/api/chain`은 bounded compute 부작용이 있음(인정) — 캐시 + 크기 상한 + (아래) rate limit으로 한정.
- **일반화된 에러 (정보 노출 없음).** 핸들러 에러는 고정 `{ error: "internal" }` 5xx 반환 — 스택·메시지·OS 에러코드·절대 경로(`auditPath`/`anchorPath`는 민감; anchor 경로는 out-of-band truncation 방어) **절대 금지**. `verifyAuditChain` `reason`은 서버측 로그만.
- **Rate limiting / DoS.** proxy의 export된 `createRateLimiter`를 재사용해 `/api/*`에 source별 상한(체인 검증 `mtime+size` 캐시에 추가), 미인증 loopback 호출자(또는 rebinding 페이지)가 `/api/chain`으로 CPU 코어를 점유 못 하게. 이벤트 읽기는 **bounded 바이트/줄 윈도**를 tail·stream-parse — 전체 파일 미적재.
- **원격 bind은 세션 가드 *와* TLS 요구**(위 우선순위): 유일한 미인증 모드는 **loopback**(거기서도 Host-allowlist + CORP 적용).
- **plaintext 절대 없음.** 이미 정제된 필드만, projection; identity는 `subjectHash`/`issuerHash`/`id`만 표시.

**패키징:** 신규 위성 `haechi-dashboard`, **zero runtime dependency**(`node:` 빌트인만), `peerDependencies: { haechi: ">=0.8.0 <1.0.0" }` + `devDependencies: { haechi: "*" }`, 자체 bin과 `publishConfig: { access: "public", provenance: true }`. core CLI 변경 없음 — 위성이 자체 진입점 소유; core는 위성을 참조하지 않음.

### 2.2 `haechi-auth-oidc` — 인터랙티브 OIDC 세션 브로커

`createOidcSessionBroker(options)`를 노출(§2.1 규율을 미러링하는 export형 fail-closed **`normalizeOidcConfig`** 포함 — `issuer`/`clientId`/`clientSecret`/`redirectUri`/`scopes`/`cookie`/`returnToAllowlist`/`sessionTtlSeconds`/`idleTtlSeconds`/`maxAgeSeconds`/`tokenEndpointAuthMethod`에 대한 열거형 throw, 모두 `configuration.md`에 문서화). **PKCE를 동반한 authorization-code 플로우**를 구현하고 대시보드가 소비할 **서버측 세션**을 생성한다(대시보드 `sessionGuard` seam을 충족 — §2.3). `authProvider`(요청별 bearer)가 **아니다** — 그 역할은 `haechi-auth-jwt`.

**생성 시점 체크 (fail-closed):** `cryptoProvider.hmac` 필수(없으면 PII-safe identity 불가); `issuer`는 유효 HTTPS URL; `redirectUri`는 유효 절대 URL, **https(또는 동일 carve-out 하 loopback http)·브로커와 동일출처**, 그 **path가 마운트된 `/auth/callback`과 동일**(동일한 `redirect_uri`를 인가 요청과 토큰 교환 양쪽에 전송, RFC 6749); `openid`는 항상 `scopes`에 강제 포함(dedup)·`offline_access`는 제거(refresh 처리는 범위 밖, §3); loopback 밖에서 외부 HTTPS 미확인 시 거부(쿠키 강화는 로컬 소켓이 아니라 **외부 가시** 스킴 기준 — `secureCookies: true|'auto'`/`trustProxy` 제공으로 TLS 종단 역프록시가 `Secure` + `__Host-` 강제; 기본 fail-closed).

**플로우 핸들러 (대시보드가 정확한 리터럴 경로로 마운트):**

- `GET /auth/login` — CSPRNG `state`·`nonce`·PKCE `code_verifier` 생성; `code_challenge = S256(code_verifier)`(**S256 필수, `plain` 절대 금지**); 트리오 + **고정(pinned)된 resolved `issuer`/`token_endpoint`/`jwks_uri`**를 짧은 TTL **pre-auth 쿠키**에 키된 서버측 **pending-auth** 레코드에 저장; 정확한 `redirect_uri`로 discovered `authorization_endpoint`에 `302`. `maxAgeSeconds` 구성 시 `max_age` 전송(콜백에서 `auth_time` 요구).
- `GET /auth/callback` — **state-first 단락**(타이밍/오라클 갭 차단): pre-auth 쿠키로 pending 레코드를 **원자적 `take()`**하고 `record.state === query.state`를 **모든 아웃바운드 요청 전**에 단언; 누락/사용됨/불일치 state 또는 누락/불일치 pre-auth 쿠키 → IdP 왕복 **없이** deny(authorization-code injection / login-CSRF·replay TOCTOU 격퇴). 이후 **고정된 `token_endpoint`에서만** `code_verifier`(+ 아래 클라이언트 인증)로 `code` 교환; ID 토큰 **검증**(아래 공유 검증기 + ID-token 프로필) — **`nonce` 일치**와 (RFC 9207) 반환된 `iss` 응답 파라미터가 고정 issuer와 동일(mix-up 방어) 포함; **새 세션 id 발급**(pre-auth 쿠키와 기존 세션 폐기 — fixation 없음); 세션 쿠키 설정; **allowlist된 상대** 반환 경로(기본 `/`)로 `302`.
- `POST /auth/logout` — **비-GET, CSRF 보호**(세션별 synchronizer 토큰 또는 `connect-src 'self'`가 이미 함의하는 동일출처 커스텀 헤더 fetch — `SameSite`에만 의존 금지). **서버측 세션 상태 완전 파기**(이후 옛 쿠키 재생 → `401`), 쿠키 제거. 선택적 RP-initiated logout: `id_token_hint` + 새 `state` 전송; `post_logout_redirect_uri`는 사전 등록/allowlist된 절대 URL(`returnToAllowlist` 규율 재사용)이거나 생략(logout open-redirect 없음).

**OIDC discovery (SSRF-강화):**

- `<issuer>/.well-known/openid-configuration`를 **HTTPS만**으로 fetch, body 한정(≤ 1 MiB), 엄격 JSON depth; **`metadata.issuer`가 구성 `issuer`와 문자열 동일하지 않으면 거부**(OIDC Discovery §4.3 / RFC 8414 — issuer-confusion 가드)하고 검증기의 기대 `iss`를 거기에 고정.
- **single-origin만 (0.9):** `authorization_endpoint`·`token_endpoint`·`jwks_uri`·`end_session_endpoint`가 **issuer 호스트명**을 공유해야 함 — `haechi-auth-jwt` 0.8과 동일 제약·근거(multi-origin/CDN-fronted IdP는 범위 밖). 교차출처 엔드포인트는 discovery/생성 시 거부.

**모든 아웃바운드 egress가 동일 가드를 실행(JWKS/discovery뿐 아님).** authorization-code 플로우는 공유 JWKS 검증기가 절대 만들지 않는 **`token_endpoint` POST**를 추가한다; discovery와 교환 사이에 `169.254.169.254`로 DNS-rebind하는 token endpoint가 전형적 메타데이터 유출 경로다. 그래서 **discovery GET·JWKS GET(공유 검증기)·토큰 교환 POST·end-session 리다이렉트**가 각각 **요청 직전에 `lookup`→`isBlockedAddress` 재확인**(post-DNS, rebinding 가드 — `127/8`, `::1`, `10/8`, `172.16/12`, `192.168/16`, `169.254/16` 포함 `169.254.169.254`, `fe80::/10` 거부)을 `redirect: "error"`·**한정된 응답 body**·fetch 타임아웃과 함께 실행. (이 SSRF 헬퍼를 분리해 Vault 백엔드(§2.4)가 세 번째 drift 사본 대신 재사용.)

**공유 JWS 검증기 + ID-token 프로필.** 0.9는 `haechi-auth-jwt@0.2.0`을 리팩터해 기존 내부 `resolveJwk`/`verifySignature`/클레임 검증에서 떼어낸 독립 검증기 프리미티브(예: `createJwtVerifier`/`verifyJwt`)를 **가산적으로 export** — **동작 보존**: 프리미티브는 **서명 + `alg`/`kid`/RSA-bits + `iss`/`aud`/`exp`/`nbf`만** 검증(정확히 0.8 표면)하며, **`nonce`는 프리미티브에 넣지 않는다**(bearer JWT엔 nonce 없음) — auth-oidc가 프리미티브가 검증된 클레임을 반환한 *뒤*에 검증(또는 생략 시 no-op인 선택적 `expectedNonce`). `createJwtAuthProvider`는 프리미티브 위에 재구현되고 Bearer-헤더 파싱을 계속 소유하므로 **0.8 §6.3 테스트가 전부 그대로 통과**. `haechi-auth-oidc`는 **`haechi-auth-jwt >=0.2.0 <1.0.0`에 peer-depend**하고 프리미티브를 사용해 **단일 감사 JWS/JWKS 검증 경로**를 만든다.

0.8 JWT 보안 명세 전체가 ID-token 검증에 그대로 적용(서버측 `alg` 선택, `alg:none` 거부, alg-confusion 차단, `kid` 필수, RSA ≥ 2048, JWK `use`/`key_ops` 의도, `typ`/no-JWE, `exp`/`nbf` 필수, `clockSkew` ≤ 300 s, SSRF-강화 bounded JWKS, 60s당 ≤ 1 refetch). **여기에 lenient bearer `aud` 체크와 구분되는 OIDC ID-token 프로필**(0.8 `audienceMatches`는 audience를 포함하는 임의 배열을 허용 — ID token엔 비준수): `aud`는 `clientId`를 포함해야 하고; **`aud`가 다중값이면 `azp`가 있어야 하며 `azp === clientId`**; 단일값 `aud`는 `clientId`와 동일(OIDC Core §3.1.3.7 — cross-client/mix-up 차단). 브로커는 **순수 로그인** 소비자: access token을 **폐기**(저장·사용 안 함)하여 서버측 비밀 표면을 줄이고 `at_hash`/`c_hash` 검증을 의도적 범위 밖으로(문서화).

**토큰 엔드포인트 클라이언트 인증:** 기본 **`client_secret_basic`**(HTTP Basic, RFC 6749 §2.3.1), `client_secret_post`는 명시적 opt-in; discovery에서 구성 메서드가 `token_endpoint_auth_methods_supported`에 있는지 단언하고 **confidential 클라이언트를 `none`으로 다운그레이드 금지**. `client_secret`은 Basic 헤더 또는 POST body에만 — URL/query **절대 금지**, 로깅 **절대 금지**. public 클라이언트(PKCE-only, 비밀 없음)도 지원.

**세션 보안 (합격 기준):**

- **서버측 세션; 토큰은 브라우저에 절대 도달 안 함.** 세션 id = 고엔트로피 CSPRNG 불투명 값(≥ 256-bit); **쿠키는 id만** 운반. ID/access/refresh 토큰·`client_secret`은 서버측에만(access 토큰은 폐기) 보관되고 클라이언트로 전송/로깅 **절대 안 함**. 기본 저장소는 in-memory이며, 동시성 하 단일사용 의미를 위해 **원자적 `take()`**(consume-and-delete)를 요구하는 주입형 `sessionStore`/`pendingStore` 계약 문서화; TTL + idle eviction.
- **구분된 두 쿠키, 둘 다 강화.** `__Host-haechi_preauth`(로그인 시, 단일사용, **콜백에서 제거**)와 `__Host-haechi_session`(콜백 후). 둘 다 `HttpOnly`, `SameSite=Lax`(Lax — Strict 아님 — IdP→`/callback` top-level GET이 쿠키를 운반하도록; Strict면 누락되어 로그인 깨짐), `Path=/`, 외부 가시 스킴이 https일 때 **`Secure` + `__Host-` 접두사(Domain 금지·`Path=/` 강제) 필수**(로컬 소켓 아닌 forwarded/선언 스킴 기준 — 생성 체크 참조).
- **PII-safe identity**는 core `buildExternalIdentity` 경유(ID-token `sub`에서 키드-HMAC `subjectHash`, 도메인 `haechi:identity:hash:v1`; `provider: "oidc"`); 원본 `sub`/email/name은 **절대** 로깅/저장 안 함.
- **Open-redirect 방어:** 로그인 후 `return_to`는 **상대·동일출처 경로**여야 하며 `returnToAllowlist`로 검증; 절대/교차출처 URL은 거부 → `/`로 폴백.
- **Rate-limiting / anti-DoS:** **하드 pending-auth 상한** + 명시적 오버플로 = **새 `/auth/login`을 일반화된 `429`/`503`으로 거부(fail-closed; in-flight 인증을 조용히 evict 금지)**, 그리고 `/auth/login`·`/auth/callback`에 source별 rate limit(`createRateLimiter` 재사용)으로 pending 저장소 고갈·CSPRNG/PKCE CPU 점유 차단.
- **fail-closed 전반:** discovery/교환/검증/state-불일치 에러 → 세션 없음, 일반화된 deny, **IdP 에러 detail 미반향**, 모든 콜백 실패에 동일 status+body(state-first 단락이 이미 아웃바운드 부작용으로 unknown-state와 bad-code를 구분 못 하게 함).

**브로커 감사 추적 (PII-safe, 대시보드의 존재 이유).** `createOidcSessionBroker`는 주입형 **`auditSink`**를 받아 `oidc.login.start`·`oidc.login.success`·`oidc.login.failure{ reasonCode }`·`oidc.logout`·`oidc.session.evict`를 방출 — 각각 **오직** `subjectHash`/`issuerHash`/`sessionIdHash`(키드-HMAC; 원본 세션 id 절대 아님)·`provider:"oidc"`·coarse `reasonCode` enum(`state_mismatch|nonce_mismatch|token_invalid|exchange_failed|host_blocked|expired`)·timestamp를 운반 — `/auth/callback` 대상 실패-로그인/브루트포스가 **가시화**된다(auth-jwt 같은 요청별 검증기는 생략 가능하지만 인터랙티브 로그인은 불가). 브로커는 자체 allowlist로 projection하며(그리고 core `FORBIDDEN_KEYS`를 `access_token`/`id_token`/`refresh_token`/`code`/`code_verifier`/`client_secret`/`state`/`nonce`/`sub`/`email`까지 **확장**) 미래 필드가 절대 새지 않게 한다. 방출 이벤트마다 `JSON.stringify`에 그 토큰/비밀/원본-클레임 문자열이 없음을 테스트로 단언. *(주: `FORBIDDEN_KEYS` 확장이 `packages/audit`에 대한 유일한 touch — 가산적 set 멤버, 기존 이벤트 동작 불변.)*

**패키징:** 신규 위성 `haechi-auth-oidc`, **zero runtime dependency**(`node:` `fetch`/`crypto`/`http`로 충분), `peerDependencies: { haechi: ">=0.8.0 <1.0.0", "haechi-auth-jwt": ">=0.2.0 <1.0.0" }` — **core peer는 `>=0.8.0` 유지**(auth-oidc는 0.6/0.8부터 있는 `buildExternalIdentity`만 사용; `>=0.9.0`으로 **과도 강화 금지**), **auth-jwt peer는 `>=0.2.0`**(검증기 export가 신규이므로). 추가로 `devDependencies: { haechi: "*" }`, `publishConfig: { access: "public", provenance: true }`, 접두 태그 발행 워크플로 `auth-oidc-v<semver>`.

### 2.3 대시보드 ↔ OIDC 통합 seam (주입, 하드 의존 아님)

두 위성은 **릴리스에서 짝지어지되 코드에서 분리** — 주입으로:

- `haechi-dashboard`는 `sessionGuard` 계약을 정의: `{ authenticate(request) -> session | null, handlers: { "/auth/login", "/auth/callback", "/auth/logout" } }`. 대시보드가 `handlers`를 마운트하고 모든 `/api/*`를 `authenticate` 뒤로 게이트.
- `haechi-auth-oidc`의 `createOidcSessionBroker(...)`가 그 계약을 충족하는 객체를 반환.
- 연결은 명시적: `createDashboardServer({ ..., sessionGuard: createOidcSessionBroker({ ... }) })`. 대시보드는 auth-oidc에 **peer 의존 없음**(가드는 `cryptoProvider`처럼 주입); 어느 위성이든 독립 사용 가능. 필요한 짝지음은 **fail-closed 규칙**: 원격 bind ⇒ 가드 존재 필수(§2.1).
- **게이트 정밀도:** 가드된 대시보드의 미인증 `/api/*` 요청은 **`401` 반환(`302` 절대 아님** — 리다이렉트된 XHR/fetch는 로그인 URL 누출·루프; 정적 셸이 리다이렉트 수행). **정확히** 세 리터럴 핸들러 경로만 **정확 일치(`/auth/` 접두 아님)**로 게이트 면제 — 그 외 경로(미지 `/auth/*` 포함)는 게이트 또는 `404`, 미래 브로커 경로가 미인증 우회가 되지 못함. `/healthz`는 loopback 밖에서도 세션 없이 도달 가능(liveness만).

### 2.4 `haechi-crypto-kms` Vault / GCP / Azure 백엔드 (독립 `0.2.0`)

병렬·분리 트랙: 가산적 백엔드를 **`haechi-crypto-kms@0.2.0`**(가산적 minor — 새 subpath export, AWS·in-memory 클라이언트 불변)으로 출시, core 0.9.0 컷과 **무관**. 각각 AWS 클라이언트가 0.8에서 정립한 **동일 `kms` 인터페이스**(`keyId`/`wrap(Buffer)->string`/`unwrap(string)->Buffer`/`deriveHmacKey`)를 구현하며, 동일한 **optional-peer + lazy-import + injected-client** 모델과 동일한 **faithful-mock conformance** 기준(cross-key 거부, corrupted-blob 거부, HMAC 결정성/도메인 분리 — CI에 SDK·네트워크 없음).

- **`./gcp`** — Google Cloud KMS, optional peer `@google-cloud/kms`(lazy). `wrap` = CSPRNG 32바이트 데이터키의 `encrypt`; `unwrap` = `decrypt`; `deriveHmacKey(domain)` = 복호화된 32바이트 root 1개(`hmacRootCiphertext`, 캐시)에 대한 HKDF-SHA256, 도메인 분리 — `aws.mjs`와 동일 형태.
- **`./azure`** — Azure Key Vault, optional peer `@azure/keyvault-keys` + `@azure/identity`(lazy). 네이티브 `wrapKey`/`unwrapKey`로 데이터키 envelope; `deriveHmacKey` = unwrap된 root에 대한 HKDF.
- **`./vault`** — HashiCorp Vault Transit, **optional-peer 없음**(Transit 엔진은 `node:` `fetch`로 닿는 평범한 HTTP API — 가장 의존성-경량 백엔드). 정확한 wire 형태(load-bearing): `wrap` = `POST {addr}/v1/transit/encrypt/{key}` with `plaintext = base64(dataKey)`, `data.ciphertext`(`vault:v1:…`) 반환; `unwrap` = `POST .../decrypt/{key}` 후 **`Buffer.from(data.plaintext, "base64")`**(32바이트 Buffer로 base64 디코드는 필수, 아니면 HKDF root가 쓰레기); 결정성을 위해 **non-derived** transit 키(또는 고정 `context`) 요구; `hmacRootCiphertext`는 transit-암호화된 32바이트 root를 한 번 복호·캐시, `aws.mjs` `hmacRoot()`와 동일. Vault `fetch` egress는 auth egress와 **동일 `lookup`→`isBlockedAddress` 가드 + `redirect:"error"` + bounded body + timeout** 실행(운영자 공급 `VAULT_ADDR`가 클라우드에서 메타데이터로 rebind 가능) — 세 번째 사본이 아닌 공유 SSRF 헬퍼(§2.2) 재사용.

모든 백엔드는 **provider 에러를 일반화된 fail-closed 에러로 매핑**하고 (키 ARN/경로를 반향할 수 있는) **KMS/provider 에러 detail을 audit에 절대 기록 안 함**. 각각 자체 subpath export + `files` 엔트리, SDK 기반은 `peerDependenciesMeta.optional`; **`haechi` tarball은 zero-dep 유지**(0.8 패키징 게이트 무영향). **하드코딩된 provider `version` 필드 정합**(`satellites/crypto-kms/index.mjs`가 `version: "0.1.0"` 반환, 이미 패키지 `0.1.1`과 stale) — 제거/파생해 `0.2.0`이 오보하지 않도록. `0.2.0` 릴리스는 0.8에서 부트스트랩한 `crypto-kms-v<semver>` 태그 + Trusted Publisher 재사용.

## 3. 명시적 비범위 (0.9.x / 1.0으로 연기)

- **대시보드 쓰기 동작**(reveal·purge·정책 편집) — 읽기 전용만; 변경은 CLI에서 reveal governance 하에. `POST`/`DELETE` 표면 없음.
- **대시보드 토큰볼트/정책 시각화** — 0.9는 감사만.
- **프레임워크 SPA / 빌드 스텝** — 바닐라 zero-dep만.
- **multi-origin / CDN-fronted IdP**(issuer 호스트 ≠ JWKS/엔드포인트 호스트) — single-origin만, `haechi-auth-jwt` 0.8과 동일.
- **Refresh-token 회전 / 무음 갱신 / 장수명 세션** — 0.9 세션은 절대-TTL + idle-timeout만; `offline_access` 제거; access token 폐기.
- **`at_hash`/`c_hash` 검증** — 브로커가 access token을 쓰지 않으므로 정확히 범위 밖.
- **비-OIDC 인터랙티브 인증**(SAML, LDAP).
- **위성 동적 로딩** — 1.0 plugin sandbox까지 금지; 대시보드·브로커는 **명시적 주입**으로 연결, 구성된 패키지명의 동적 `import()` 절대 아님.

## 4. 하위 호환

core 동작 **불변** — zero-dep 자세 유지, 기존 config/API 불변. 기존 패키지에 대한 두 touch는 둘 다 **가산적·동작보존**: (a) `haechi-auth-jwt@0.2.0`이 검증기 프리미티브를 export하고 그 위에 `createJwtAuthProvider` 재구현(0.8 테스트 그대로); (b) `packages/audit`가 `FORBIDDEN_KEYS`에 멤버 추가(브로커 토큰/클레임 키) — 기존 이벤트 형태 불변. `assertSafeProxyBind`는 **이미 export된 `haechi/proxy`에서 재사용**(재배치·신규 core export 없음). 모든 0.9 산출물은 신규·가산적·opt-in 위성.

## 5. 1.0 관계

0.9 자체가 1.0 블로커를 닫지는 않지만 두 1.0 스토리를 진전시킨다: **운영 관측가능성**(대시보드가 [[audit-integrity]] 해시체인 상태 + decision 스트림을 점검 가능하게 — real-environment-validation 종료 기준 지원)과 **인터랙티브 인증**(브로커가 `haechi-auth-jwt`가 남긴 사람-로그인 절반을 완성). 남은 1.0 게이트는 불변: API-stability freeze와 plugin sandbox + 동적 로딩 스토리.

## 6. 위협 모델 & 리스크 레지스터 델타 (구체적, "TBD" 아님)

릴리스 컷에서 `threat-model.md`(+ `.ko`) §3 Threats-and-Controls에 다음 행을 추가하고, 리스크 레지스터 ID를 추가한다(레지스터 목표 버전 헤더 `0.7.0 → 0.9.0`, 새 게이트 행):

| 신규 위협 / 표면 | 통제 | 잔여 |
|---|---|---|
| 공격자 제어 `detections[].path` 통한 대시보드 감사 뷰어 **XSS** | CSP(`require-trusted-types-for`) + `textContent`-only 렌더 | 실질 없음 |
| 뷰어 통한 **감사 필드 누출**(미래 필드) | 재귀 키별 allowlist projection(+ `FORBIDDEN_KEYS`) | 새 중첩 필드는 기본 drop |
| localhost-bound 뷰어에서 **DNS-rebinding** 감사 JSON 읽기 | Host 헤더 allowlist(요청별) + CORP/COOP same-origin | 실질 없음 |
| **원격** bind에서 미인증 감사 읽기 | fail-closed: 원격 ⇒ `sessionGuard` **및** TLS 필수 | 운영자 TLS 종단 필요 |
| OIDC **login CSRF / authorization-code injection / open-redirect / session fixation** | state↔pre-auth-cookie 바인딩, 원자적 `take()`, PKCE S256, 콜백 시 새 세션 id, `returnToAllowlist`, logout CSRF 토큰 | 단일 IdP엔 실질 없음 |
| OIDC **mix-up**(잘못된 IdP / 잘못된 RP) | issuer/엔드포인트를 pending 레코드에 고정, RFC 9207 `iss` 체크, ID-token `aud`/`azp` 프로필, `metadata.issuer` == config | multi-origin IdP 범위 밖 |
| token-endpoint POST(및 Vault `fetch`) 통한 브로커 **클라우드 메타데이터 SSRF** | egress별 post-DNS `isBlockedAddress` 재확인 + bounded body + timeout + `redirect:"error"` | 운영자-신뢰 엔드포인트만 |
| audit/logs로 **토큰/비밀 누출** | 브로커 allowlist projection + 확장 `FORBIDDEN_KEYS`; access token 폐기 | 실질 없음 |
| KMS 백엔드 egress(Vault HTTP, GCP/Azure SDK) | optional-peer + injected-client conformance, 일반화 fail-closed 에러, audit에 provider detail 없음 | 라이브 백엔드 검증은 CI 밖 |

제안 리스크 ID: **P1-SEC-009**(브로커 세션/로그인 보안), **P1-OPS-005**(대시보드 감사 노출 / rebinding / 원격 bind), **P2-CRYPTO-00x**(KMS 백엔드 egress). 신규 §4 제외: multi-origin IdP, refresh 회전, 대시보드 쓰기 동작, `at_hash` 검증.

## 7. 테스트 기준 (PR 분해에 매핑)

### 7.1 PR1 — `haechi-auth-jwt@0.2.0` 검증기 추출 (가산적, 동작보존)

- **`satellites/auth-jwt/package.json` `0.1.1 → 0.2.0` bump**(발행 워크플로 tag==package-version 게이트 요구).
- 신규 `createJwtVerifier`/`verifyJwt` 프리미티브가 0.8 §6.3 보안 게이트 스위트 전체 통과(모든 deny 케이스); **`nonce`는 프리미티브 일부가 아님**(생략 시 no-op `expectedNonce`).
- 프리미티브 위에 재구현된 `createJwtAuthProvider`가 기존 0.8 테스트를 **그대로** 통과(동작보존 회귀 가드); Bearer-헤더 파싱 계속 소유.
- 위성 tarball `dependencies: {}` 유지; core tarball zero-dep 유지.

### 7.2 PR2 — `haechi-dashboard` (zero-dep 읽기 전용 뷰어)

- 기본 loopback bind; `allowRemoteBind` 없는 non-loopback → 거부(대시보드 문구로 rethrow); `sessionGuard` 없는 `allowRemoteBind:true` → throw; TLS/trusted-proxy 미확인 원격 → throw. `normalizeDashboardConfig`가 잘못된 옵션마다 안정적 에러로 거부.
- **anti-rebinding:** loopback 대시보드에 `Host: evil.example` → `403`; Host 매트릭스(`localhost.`, `127.0.0.1:PORT`, `::ffff:127.0.0.1`, 예상 외 FQDN, 중복 `Host`)가 올바르게 동작; `Access-Control-Allow-Origin` 절대 방출 안 함.
- `GET /api/events`: 상한 `limit`(`-1`/`abc`/`1e9` 거부), 불투명 `cursor`(변형 → `400`), **재귀 allowlist**가 **각** 계층(top, `detections[]`, `identity`, `summary`, `auditIntegrity`)에 주입된 합성 추가 필드를 drop; window-exceeded 페이지는 에러 아닌 마커; 찢어진 후행 줄 `500` 안 남.
- `GET /api/chain`: 형태가 **실제** `verifyAuditChain` 출력과 일치; truncated-with-anchor 픽스처가 `valid:false` + 파생 `truncationDetected`를 원문 `reason`/`eventHash` **누출 없이** 표면화; 동시 폴이 **1회** walk(mtime+size 캐시) 유발; 초과 크기 픽스처 → `413`; `HEAD`는 walk 미강제.
- **XSS:** `detections[].path`에 `<script>`/`<img onerror>` 있는 이벤트가 inert 렌더(서빙 JS가 `textContent` 사용); 정확한 CSP 헤더 문자열(`object-src 'none'`, `require-trusted-types-for 'script'` 포함) + `nosniff` + `XFO:DENY` + `CORP/COOP same-origin` + `no-store` 단언.
- **메서드/자산/에러:** `POST`/`DELETE` → `405`; `/../../etc/passwd`가 고정 자산 맵 탈출 불가(`404`, fs 읽기 없음); 강제 fs 에러가 경로 부분문자열/스택 **없는** `{error:"internal"}` 산출; `/healthz`는 아무것도 누출 안 함.
- **DoS:** 다수-MB 감사 픽스처가 bounded tail 윈도로 서빙; `/api/*` rate-limited.
- tarball `dependencies: {}`; provenance로 발행.

### 7.3 PR3 — `haechi-auth-oidc` (인터랙티브 브로커, 보안 게이트)

- **정상 경로**(stub discovery + token endpoint + JWKS, RS256 ID token): `/auth/login` → `state`+`nonce`+`code_challenge`(S256) + 등록된 `redirect_uri` 있는 `302`; 일치 state + 유효 code의 `/auth/callback`이 교환·검증·로그인 전 쿠키와 무관한 **새** 세션 id 발급; 쿠키는 `__Host-` 네임·`HttpOnly`·`SameSite=Lax`, non-loopback 구성 하 `Secure`; pre-auth 쿠키 제거됨.
- **각각 deny**(세션 없음, 일반화된 동일 응답, 미반향, state 실패 시 아웃바운드 없음): 불일치/재생/만료 `state`(원자적 `take()`로 동시 재생이 레코드 못 찾음); 누락/불일치 pre-auth 쿠키(login-CSRF/code-injection); `nonce` 불일치; `alg:none`/alg-confusion; 만료/`nbf`/잘못된 `aud`/잘못된 `iss` ID token; **`azp` 없는 다중 `aud`**, **`azp !== clientId`**; `metadata.issuer` ≠ config; RFC 9207 `iss` ≠ pinned; code 교환 실패; **교차출처** `token_endpoint`/`jwks_uri` discovery doc; discovery/JWKS/**token_endpoint** 호스트가 **요청 시점**(post-DNS) private/metadata 범위로 해석; 초과 크기 token-endpoint 응답.
- **토큰 무누출:** 로그인 후 브라우저 가시 쿠키는 불투명 id만; 모든 클라이언트 응답 **및** audit 로그의 `JSON.stringify`에 ID/access/refresh 토큰·`client_secret`·`code`·`state`·`nonce`·원본 `sub` **없음**. access token **폐기**(저장 안 됨 단언).
- **세션/로그아웃:** `POST /auth/logout` 후 옛 쿠키 재생 → `401`·서버측 레코드 소멸; logout이 CSRF 토큰 요구(위조 교차출처 POST 거부); allowlist 밖 `post_logout_redirect_uri` 거부.
- **Open-redirect:** `return_to=https://evil.example`(또는 교차출처/절대) → `/`로 폴백; allowlist된 상대 경로 존중.
- **Rate/DoS:** N회 빠른 `/auth/login`이 pending 상한에 닿아 메모리 고갈 없이 일반 `429`/`503` 반환; `/auth/login` + `/auth/callback` rate-limited.
- **감사:** `oidc.login.{start,success,failure}` / `oidc.logout` / `oidc.session.evict`가 `*Hash`/`reasonCode`/`provider`/timestamp만으로 방출; 확장 `FORBIDDEN_KEYS` 테스트 통과.
- **생성 fail-closed:** `cryptoProvider.hmac` 누락; non-https/교차출처 `issuer`/`redirectUri`; `redirectUri` path ≠ `/auth/callback`; TLS/Secure 없는 loopback 밖; `normalizeOidcConfig`가 잘못된 옵션마다 거부.
- **seam:** 브로커가 대시보드 `sessionGuard` 충족; 마운트 시 원격-bound 대시보드의 미인증 `/api/events` → **`401`**(`302` 아님); `/auth/anything-else`는 미인증 우회 아님; `/healthz`는 loopback 밖 미인증 `200`인데 `/api/events`는 `401`.

### 7.4 PR4 — `haechi-crypto-kms@0.2.0` (GCP / Azure / Vault 백엔드)

- GCP/Azure/Vault 각각 **faithful injected mock**(SDK·네트워크 없음)으로 `assertCryptoProviderConformance` 통과, cross-key + corrupted-blob **거부**·HMAC 결정성/도메인 분리 포함; `createRuntime` end-to-end(encrypt + tokenization 왕복).
- **Vault** 백엔드는 **`node:` `fetch`만**(optional peer 없음), **base64 왕복**(encrypt `plaintext=base64(dataKey)` → decrypt → `Buffer.from(...,"base64")`)·non-derived 키·`VAULT_ADDR` SSRF 가드 행사; GCP/Azure는 SDK를 `peerDependenciesMeta.optional`로 선언, 클라이언트 미주입 시에만 lazy import.
- provider 에러가 일반화 fail-closed 에러로 매핑; provider/키-ARN detail이 audit에 안 닿음.
- 하드코딩 provider `version` 필드 정합(`"0.1.0"` 아님).
- 발행된 `haechi-crypto-kms@0.2.0` tarball `dependencies: {}`; core tarball zero-dep 유지; 기존 `crypto-kms-v<semver>` 태그로 provenance 발행.

### 7.5 모든 위성

- 신규/갱신 위성 각각 provenance + sigstore attestation으로 발행, 0.7/0.8처럼 릴리스 후 검증.

## 8. 제안 PR 분해 (스택)

1. **`haechi-auth-jwt@0.2.0` 검증기 추출** — 가산적 `createJwtVerifier`/`verifyJwt`(nonce는 외부 유지), `createJwtAuthProvider` 재구현, **0.2.0으로 bump**, 0.8 테스트 그대로. → §7.1
2. **`haechi-dashboard`** — zero-dep `node:http` 뷰어: `normalizeDashboardConfig` + bind/guard/TLS 우선순위, anti-rebinding Host allowlist, 엄격 쿼리 파싱 + bounded reads + 재귀 allowlist + mtime-캐시 체인의 읽기 전용 event/chain/summary API, 엄격 CSP/Trusted Types + `textContent` 정적 페이지, 보안 헤더, 일반화 에러, rate limit, `sessionGuard` seam, 발행 워크플로 `dashboard-publish.yml`(guard `startsWith(tag,'dashboard-v')`, regex `^dashboard-v[0-9]+\.[0-9]+\.[0-9]+$`). 신규 dir용 lockfile 재생성. → §7.2
3. **`haechi-auth-oidc`** — 인터랙티브 authorization-code + PKCE 브로커: `normalizeOidcConfig`, SSRF-강화 discovery + egress별 가드, §2.2 공유 검증기 통한 ID-token 프로필(nonce 외부), 원자적 `take()` pending 저장소, 강화 두-쿠키 세션 + 새-id 회전, open-redirect/CSRF/logout 방어, 브로커 감사 이벤트 + 확장 `FORBIDDEN_KEYS`, `sessionGuard` 구현, 발행 워크플로 `auth-oidc-publish.yml`. 신규 dir용 lockfile 재생성. → §7.3
4. **`haechi-crypto-kms@0.2.0`** — GCP/Azure(optional-peer) + Vault(zero-dep, 공유 SSRF 헬퍼) 백엔드, faithful-mock conformance, version 필드 정합; 기존 태그로 bump + 발행. → §7.4
5. **0.9.0 릴리스 컷** — docs EN/KO(`configuration.md`의 대시보드/브로커 config, §6 위협모델 + 리스크 레지스터 델타와 구체 ID + 목표 버전 bump, 본 scope doc), 로드맵 행, api-stability, wiki ingest(신규 `haechi-dashboard`/`haechi-auth-oidc` 페이지 + `packaging-and-distribution`/`identity-and-auth` 갱신), 패키지별 Trusted Publisher 런북 행(신규 워크플로 파일명 둘 + 태그 글롭 + 각 언스코프드 이름을 선점하는 configure-TP-**before**-first-tag 부트스트랩).
