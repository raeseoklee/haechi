# Haechi Threat Model

- 문서 상태: Draft 0.1
- 작성일: 2026-06-10
- 기준 버전: 0.9.0

## 1. 보호 대상

Haechi가 보호하려는 주요 자산은 다음이다.

| 자산 | 예시 | 보호 목표 |
|---|---|---|
| Prompt/context payload | chat messages, tool arguments, MCP params | 모델/도구/로그로 이동하기 전 정책 집행 |
| Tool/resource result | MCP result, local inference response | 응답 내 PII/secret 재유출 차단 |
| TokenVault record | tokenized PII mapping | 저장 시 암호화, reveal 기본 차단 |
| Audit event | detection metadata, decision summary | 평문 비포함, hash chain 무결성 |
| Crypto envelope | encrypted segments | canonical AAD binding, key provider 교체성 |
| Plugin manifest | custom provider/filter declaration | capability disclosure, dynamic runtime 차단 |

## 2. 신뢰 경계

| 경계 | 신뢰 수준 | 기본 통제 |
|---|---|---|
| CLI local process | 개발자 로컬 신뢰 | dev key 경고, dry-run 기본값 |
| HTTP proxy listener | 비신뢰 client 입력 | loopback bind 기본, remote bind 명시 플래그 |
| Upstream model/tool server | 비신뢰 또는 부분 신뢰 | request/response protection, uninspectable response fail-closed |
| Streaming response | 검사(bounded) 또는 차단 | `inspect` 모드는 bounded cross-frame 버퍼로 SSE/NDJSON을 stream-filter함; `block`(기본값)은 거부 |
| MCP stdio peer | 부분 신뢰 | JSON-RPC 2.0 요구, method allowlist |
| Local filesystem | 부분 신뢰 | local key/token vault 0600, audit hash chain |
| External provider/plugin | 비신뢰 | provider method contract, plugin manifest-only gate |

## 3. 주요 위협과 통제

| 위협 | 영향 | 현재 통제 |
|---|---|---|
| 인터넷 노출 proxy | 인증 없는 LLM gateway | non-loopback bind 기본 실패 |
| streaming 우회 | SSE/NDJSON 평문 유출 | `inspect` 모드는 SSE/NDJSON을 stream-filter함; `block`(기본값)은 거부; `pass-through`는 명시적으로 감사된 opt-out |
| Ollama 암묵 streaming 우회 | `stream` 생략 시 NDJSON 평문 유출 | `/api/chat`·`/api/generate`는 `stream: false` 명시 없으면 streaming으로 간주해 기본 차단 |
| 비JSON/압축/대용량 응답 | responseProtection 우회 | fail-closed response policy |
| token reveal 남용 | tokenized PII 복원 | revealPolicy 기본 disabled, reveal/purge 결정 audit 기록 |
| audit 변조 | 감사 증거 신뢰 저하 | SHA-256 hash chain |
| policy 약화 override | block preset 무력화 | unsafe downgrade conflict 차단, privacy profile은 강화만 가능 |
| ReDoS custom regex | CPU 고갈 | nested quantifier/backreference 제한 |
| plugin runtime 착각 | 동적 코드 실행 위험 | manifest-only runtime만 허용 |
| MCP tool method 오남용 | 예상 밖 tool/resource 접근 | allowedMethods 기반 거부 |
| key custody 오해 | local dev key 운영 사용 | external crypto provider injection, dev key 경고 |
| 행 걸린 upstream | proxy 연결 고갈 | `limits.upstreamTimeoutMs` 기본 120s, 초과 시 504 fail |
| signing/encryption 키 혼용 | key separation 위반 | policy bundle 서명 키를 domain-separated 파생 키로 분리 |
| JSON number/object key 은닉 | 카드번호 등 비문자열 leaf 미탐지 | number leaf와 object key도 detection/transform 대상 |
| 인증 없는 멀티 클라이언트 접근 | 로컬 프로세스가 upstream / token round-trip 경로를 무단 사용 | 선택적 bearer auth (`auth.provider: bearer`); 없거나 잘못된 경우 → 바디 읽기 전 401; identity별 rate limit 및 model allowlist |
| Audit tail truncation | 꼬리 audit 레코드의 무음 삭제 | 추가 전용/별도 미디어의 `audit.anchor` head-hash anchoring으로 마지막 anchor까지의 절단 탐지 (0.7) |
| Local dev key in production | 소프트웨어 키의 운영 custody 오용 | `assertCryptoProviderConformance`를 통한 외부 `cryptoProvider` 주입; reference KMS adapter (envelope 암호화) |
| Tampered release artifact | 변조된 tarball 설치 | npm provenance + GitHub release tarball의 sigstore attestation + `SHA256SUMS` (0.7) |
| audit에 원시 credentials/identity 노출 | audit 로그를 통한 token 또는 subject 유출 | Token은 keyed-HMAC 해시로만 저장; identity subject/issuer는 keyed HMAC 처리; `auth_denied` 레코드에 token 미포함 |
| token round-trip의 타 토큰 복원 | 클라이언트/요청 간 평문 복구 | detokenization은 opt-in(`detokenizeResponses`)이며 요청 스코프: 같은 요청을 보호하며 발급된 토큰만 복원 |
| tool result/응답 내 간접 prompt injection | 심어진 지시문에 의한 agent 조작 | 응답 방향 휴리스틱, 기본 report-only(`injection` action `allow`), 격상은 명시적 정책 선택. 완전 방어 아님 |
| Haechi 자체 변환 마커 재탐지 | 모델이 echo한 토큰 왕복이 재탐지됨(예: `[TOKEN:…]`가 `secret`으로 차단) → response-enforce에서 `detokenizeResponses` 깨짐 | **응답 방향에서만** Haechi 마커(`[TOKEN:…]`, `[HAECHI_ENC:…]`, `[REDACTED:…]`) 탐지 제외. 요청 방향은 영향 없으므로 요청에 마커 모양 문자열로 secret을 숨겨 우회할 수 없음. **수용된 잔여:** 악의적 *upstream*이 누출 값을 가짜 응답 마커로 감싸 응답 방향 탐지를 회피할 수 있음 — 응답 검사는 2차 방어(모델은 semi-trusted)이고 제외는 positional(마커 구간만 건너뜀; 인접 값은 여전히 탐지됨) |
| 응답 메타데이터 오탐 | `enforce` 응답 검사가 envelope 메타데이터를 PII/secret으로 오인해 정상 응답을 차단(예: unix 타임스탬프 `created`가 phone 규칙에, 나노초 `*_duration`이 `card`에 매치) | KR phone 규칙이 구분자·`0` 없는 맨 숫자열을 무시; `chatcmpl-…` 같은 id는 secret 모양 아님; **응답 방향은 bare JSON number leaf를 검사하지 않음**(`*_duration`/count/timestamp/numeric-id — 모델 누출 card/RRN이 아님; 실제 누출은 생성 *텍스트*에 나타나 여전히 검사됨). **수용된 잔여:** 악의적 모델이 bare 응답 숫자로 인코딩해 유출 가능(응답 검사는 2차 방어) — 엄격 운영자는 `responseProtection.scanNumbers: true`로 재활성화 가능. 실제 vLLM·Ollama 응답은 이제 clean; 추가 주의 시 `responseProtection.mode: report-only`(탐지·감사만, 차단 없음) |
| Dashboard audit 뷰어 XSS — attacker-controlled `detections[].path` (0.9) | `haechi-dashboard`의 stored XSS: `<img onerror>` 같은 요청 JSON key가 client-key 파생 `detections[].path` 필드를 통해 audit 로그에 도달한 뒤 뷰어에서 렌더됨 | 제공 페이지는 DOM을 `createElement` + `textContent`로만 구성(`innerHTML` 보간 사용 안 함)하고, 모든 응답에 `require-trusted-types-for 'script'`를 포함한 엄격 CSP를 부여(잔여 `innerHTML` sink는 브라우저에서 throw). allowlist는 필드 *이름*을, CSP + `textContent`는 악의적 *값*을 각각 독립적으로 무력화. 실질적 잔여 없음 |
| 뷰어를 통한 audit 필드 leak (미래 필드) (0.9) | 이후 audit 스키마에 추가된 필드가 dashboard API에 그대로 노출되어 의도치 않은 메타데이터 유출 | `/api/events`는 실제 audit 스키마에 대해 **재귀적 key-by-key 필드 allowlist projection**을 수행(`detections`/`identity`/`summary`/`auditIntegrity` 같은 중첩 sub-object를 blind하게 spread하지 않음)하며 core의 `FORBIDDEN_KEYS` 위에 적층됨. 어떤 레벨의 새 중첩 필드든 기본적으로 drop |
| localhost bind 뷰어에 대한 DNS-rebinding audit JSON 읽기 (0.9) | 운영자가 방문한 사이트가 `127.0.0.1`로 재해석되는 단기 TTL DNS 이름을 게시하면 피해자 브라우저가 same-origin 요청을 보내 공격자 JS가 인증 없는 loopback dashboard에서 audit JSON을 읽음 | 요청별 **anti-rebinding `Host` 헤더 allowlist**(bind 검사와 구분되는 first gate; IPv4-mapped IPv6·trailing-dot·bracketed IPv6 정규화, malformed/중복 `Host` 거부) + `Cross-Origin-Resource-Policy`/`Cross-Origin-Opener-Policy: same-origin`; CORS 헤더는 결코 방출하지 않음. 실질적 잔여 없음 |
| remote bind 시 인증 없는 audit 읽기 (0.9) | non-loopback host에 bind된 dashboard가 로그인 없이 audit 스트림 노출 | fail-closed precedence: `allowRemoteBind` **및** `sessionGuard`가 있고 **확인된 HTTPS 종단**(`tlsContext`, 또는 신뢰 proxy에서만 `X-Forwarded-Proto`를 신뢰하는 `trustProxy`)이 아니면 remote bind는 throw; Secure/`__Host-` 세션 쿠키는 평문 http로 전송되지 않음. 운영자가 TLS 종단을 책임 |
| OIDC login CSRF / authorization-code injection / open-redirect / session fixation (0.9) | 공격자가 피해자 broker 세션을 공격자 제어 로그인에 강제하거나, 탈취한 code를 주입하거나, 로그인 후 off-origin으로 redirect하거나, 사전 인지된 세션 id를 고정 | `/auth/callback`은 **state-first**: pre-auth 쿠키 바인딩된 pending record를 atomic `take()`하고 **모든 IdP egress 이전에** constant-time `state` 비교; PKCE S256 필수; callback에서 **새 세션 id 발급**(fixation 없음, pre-auth 쿠키 폐기); 로그인 후 `return_to`는 상대 경로 `returnToAllowlist`로 검증; logout은 non-GET + CSRF-header gated. 단일 IdP 기준 실질적 잔여 없음 |
| OIDC mix-up (잘못된 IdP / 잘못된 RP) (0.9) | confused-deputy 공격으로 IdP를 바꾸거나 다른 client용으로 발급된 code/token을 재생 | issuer/`token_endpoint`/`jwks_uri`를 `/auth/login`에서 pending record에 pin; RFC 9207 `iss` 응답 파라미터가 pinned issuer와 일치해야 함; `metadata.issuer`가 설정 issuer와 string-equal해야 함; OIDC ID-token `aud`/`azp` 프로파일(`aud`는 `clientId` 포함; multi-valued `aud`는 `azp === clientId` 필요)로 cross-client 차단. multi-origin IdP는 범위 외 |
| 토큰 엔드포인트 POST(및 Vault `fetch`)를 통한 broker SSRF — cloud metadata (0.9) | discovery와 request 사이에 `169.254.169.254`로 DNS-rebind되는 `token_endpoint`(또는 운영자 제공 `VAULT_ADDR`)가 instance-metadata 자격증명을 유출 | 모든 egress(discovery GET, 공유 verifier 경유 JWKS GET, token-exchange POST, end-session redirect, `haechi-crypto-kms` Vault `fetch`)가 **request 직전**(post-DNS) `lookup` 후 `isBlockedAddress` 재검사를 `redirect: "error"`·bounded body·timeout과 함께 수행. 운영자 신뢰 엔드포인트에 한함 |
| audit/로그로의 token/secret leak (broker) (0.9) | ID/access/refresh token, `client_secret`, `code`, `state`, `nonce`, raw `sub`가 audit 로그나 client 응답에 기록됨 | broker는 모든 audit 이벤트를 자체 allowlist로 projection해 `subjectHash`/`issuerHash`/`sessionIdHash`(keyed-HMAC) + `provider`/`reasonCode`/timestamp만 방출; core `FORBIDDEN_KEYS`를 broker token/claim key까지 확장; access token은 **폐기**(저장·사용 안 함). 실질적 잔여 없음 |
| KMS backend egress (Vault HTTP, GCP/Azure SDK) (0.9) | `haechi-crypto-kms` Vault/GCP/Azure backend가 key material이나 provider/key-path 상세를 유출하거나 의도치 않은 엔드포인트에 도달 | optional-peer + injected-client 모델과 **faithful-mock conformance**(cross-key·corrupted-blob 거부, HMAC determinism/domain-separation); Vault `fetch`는 위 satellite-local SSRF 가드 수행; 모든 backend는 provider 오류를 generic fail-closed 오류로 매핑하고 provider/key-ARN 상세를 audit에 기록하지 않음. live-backend 검증은 CI 외부 |

## 4. 명시적 제외

0.3.2는 다음을 보장하지 않는다.

- 운영 KMS/HSM/Vault adapter 자체 제공
- internet-facing gateway 인증/인가
- `streaming.maxMatchBytes`보다 긴 cross-frame 매칭(스트림 프레임에 걸쳐 분할될 수 있음)
- `block`이 발동되기 전에 이미 방출된 스트림 바이트의 회수
- 스트림에서 choice별(`n > 1`) cross-frame 버퍼링(보조 choice는 프레임 내 보호만 적용)
- 법적 컴플라이언스 인증
- 모델 hallucination, prompt injection 완전 방어
- 외부 MCP server의 OAuth/resource binding 검증
- base64/URL-encoded 값, 유니코드 난독화 값의 디코딩 후 검사
- URL query string 내 민감값 검사 (JSON body만 검사)
- 마지막 anchor 이후의 audit tail truncation — `audit.anchor`(0.7)는 anchor가 추가 전용/별도 미디어에 있을 때 마지막 anchor까지의 레코드 삭제를 탐지한다; 마지막 anchor 이후 기록된 레코드와 동일 파일시스템 anchor는 대상에서 제외된다
- JSON-RPC batch 메시지 처리 (MCP stdio filter는 batch를 fail-closed로 거부)
- `haechi-auth-oidc`의 multi-origin / CDN-fronted IdP(issuer host ≠ `token_endpoint`/`jwks_uri` host) — single-origin만 지원, `haechi-auth-jwt`와 동일 제약 (0.9)
- refresh-token rotation / silent renewal / 장수명 broker 세션 — 0.9 세션은 absolute-TTL + idle-timeout만; `offline_access`는 제거되고 access token은 폐기 (0.9)
- Dashboard write action(reveal, purge, policy edit) — `haechi-dashboard`는 읽기 전용으로 `POST`/`DELETE` surface 없음; mutation은 reveal governance 하의 CLI에 유지 (0.9)
- OIDC broker의 `at_hash`/`c_hash` 검증 — broker가 access token을 사용하지 않으므로 정확히 범위 외 (0.9)

## 5. 남은 운영 전제

운영 사용자는 Haechi 외부에서 네트워크 접근 제어, upstream 인증, secret injection, key custody, 로그 보존, DSAR/삭제 요청 처리, 법적 transfer 근거를 책임져야 한다.
