# Haechi Threat Model

- 문서 상태: Living document(core 1.7.x 추적)
- 작성일: 2026-06-10

## 1. 보호 대상

Haechi가 보호하려는 주요 자산은 다음과 같습니다.

| 자산 | 예시 | 보호 목표 |
|---|---|---|
| Prompt/context payload | chat messages, tool arguments, MCP params | 모델/도구/로그로 이동하기 전 정책 집행 |
| Tool/resource result | MCP result, local inference response | 응답 내 PII/secret 재유출 차단 |
| TokenVault record | tokenized PII mapping | 저장 시 암호화, reveal 기본 차단 |
| Audit event | detection metadata, decision summary | 평문 비포함, hash chain 무결성 |
| Crypto envelope | encrypted segments | versioned NFKC AAD binding, 제공된 경우 freshness, key provider 교체성 |
| Plugin manifest | custom provider/filter declaration | capability disclosure, dynamic runtime 차단 |

## 2. 신뢰 경계

| 경계 | 신뢰 수준 | 기본 통제 |
|---|---|---|
| CLI local process | 개발자 로컬 신뢰 | dev key 경고, dry-run 기본값 |
| HTTP proxy listener | 비신뢰 client 입력 | loopback bind 기본, remote bind 명시 플래그 |
| Upstream model/tool server | 비신뢰 또는 부분 신뢰 | request/response protection, uninspectable response fail-closed |
| Streaming response | 검사(bounded) 또는 차단 | `inspect` 모드는 bounded cross-frame 버퍼로 SSE/NDJSON을 stream-filter합니다. `block`(기본값)은 거부합니다 |
| MCP stdio peer | 부분 신뢰 | JSON-RPC 2.0 요구, method allowlist |
| Local filesystem | 부분 신뢰 | local key/token vault 0600, audit hash chain |
| External provider/plugin | 비신뢰 | provider method contract, plugin manifest-only gate |

## 3. 주요 위협과 통제

| 위협 | 영향 | 현재 통제 |
|---|---|---|
| 인터넷 노출 proxy | 인증 없는 LLM gateway | non-loopback bind 기본 실패 |
| gateway credential의 upstream 전달 | Haechi가 소비한 gateway 토큰인 클라이언트 `Authorization`, `Cookie`, `Proxy-Authorization`가 모델 제공자로 전달되어 gateway 비밀이 신뢰 경계를 넘어 유출됩니다 (P0-CR-001) | **기본 차단 upstream 헤더 허용목록.** proxy는 명시적인 제공자/어댑터 헤더 집합(`x-api-key`, `anthropic-version`, `anthropic-beta`, `x-goog-api-key`, `openai-organization`, `openai-beta`, `accept`, `accept-language`, `user-agent`, `content-type`)만 전달합니다. `Cookie`/`Set-Cookie`/`Proxy-Authorization`와 hop-by-hop 헤더는 항상 폐기됩니다. `Authorization`은 `auth.provider !== none`이면(gateway credential이므로) 폐기되고, `auth.provider: none`일 때만(upstream 제공자 키이므로) 전달됩니다. `target.forwardHeaders`는 허용목록을 추가로 넓히지만 항상 폐기되는 헤더를 다시 켤 수는 없습니다(설정 시점 fail-closed) |
| 압축 해제된 바디에 잔존하는 압축 헤더 | Node `fetch()`가 gzip/br/deflate를 자동 해제하지만, upstream의 `content-encoding`/`content-length`를 유지한 채 전달하면 downstream 클라이언트가 평문 바이트에 `content-encoding: gzip`을 보고 "incorrect header check"로 실패합니다 (P1-CR-003) | **모든 응답 경로에서 중앙화된 `sanitizeResponseHeaders`**(pass-through, 전달/미보호, 보호, streaming): `content-encoding`, `content-length`, `transfer-encoding`, hop-by-hop 헤더를 제거하고, 완전 버퍼링된 바디에 한해 올바른 `content-length`만 다시 설정합니다 |
| 무제한 streaming pass-through | `streaming.requestMode: "pass-through"`가 크기 제한 없이 전체 upstream 바디를 버퍼링해, 장수명·악의적 스트림이 메모리/연결 자원을 무한정 점유할 수 있었습니다 (P1-CR-004) | **진정한 경계 streaming pass-through**: upstream 바디를 도착하는 대로 실행 바이트 카운트(`responseProtection.maxBytes`)와 함께 클라이언트로 파이핑하며, 한도를 초과하면 upstream 읽기를 취소하고 클라이언트 쓰기를 종료합니다(크기 기준 fail-closed). 동일한 한도가 미보호/전달 버퍼링 읽기에도 적용됩니다(한도 초과 시 502) |
| streaming 우회 | SSE/NDJSON 평문 유출 | `inspect` 모드는 SSE/NDJSON을 stream-filter합니다. `block`(기본값)은 거부하고, `pass-through`는 명시적으로 감사된 opt-out입니다 |
| Ollama 암묵 streaming 우회 | `stream` 생략 시 NDJSON 평문 유출 | `/api/chat`·`/api/generate`는 `stream: false`를 명시하지 않으면 streaming으로 간주해 기본 차단합니다 |
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
| 모든 정규식 규칙을 우회하는 유니코드 난독화 | card/RRN/phone/email/secret을 시각·의미상 동등한 비ASCII 유니코드 형태(전각 숫자 `４２４２…`, 전각 `＠`, 수학·원문자 영숫자)로 보내 모든 탐지 규칙을 무력화 | **매칭 전 각 string leaf의 NFKC 정규화**(WS2d)입니다. 정규화가 무변환인 경우(leaf의 약 99%) 탐지는 이전과 바이트 단위로 동일합니다. 접힘이 **위치 안정적**인 경우(모든 코드포인트가 같은 UTF-16 길이로 접히고 코드포인트별 접힘이 전체 정규화를 그대로 재구성) 정규화 사본에서 탐지하고 원본의 정확한 구간을 redact/block하며, 기록되는 값은 접힌 형태가 아니라 원본 바이트입니다. 그 외 — 길이가 달라지거나(수학 숫자·합자) 총 길이는 같지만 내부 offset을 이동시키는 수축+확장 보상 — 의 경우 offset을 원본에 매핑할 수 없으므로 탐지가 **fail closed**되어 leaf 전체를 덮는 단일 탐지로 처리합니다(leaf 전체 redact/block — 우회 시도를 과도 redact하는 것이 안전한 실패입니다). `String.prototype.normalize` 빌트인을 사용하므로 새 의존성은 없습니다. **잔여는 이제 opt-in 통제입니다:** base64/percent-encoded 페이로드는 `filters.decodeAndRescan`이 활성화된 경우에만 디코딩 후 재검사합니다(다음 행 및 §4 참조) |
| 모든 정규식 규칙을 우회하는 base64/percent-encoded 페이로드 | 전송 전 base64·percent로 인코딩된 card/RRN/secret은 모든 규칙을 통과합니다(Haechi는 NFKC 텍스트에서 매칭하지만 디코딩하지 않습니다) | **opt-in `filters.decodeAndRescan`**입니다(기본 OFF → 이전과 바이트 단위로 동일). ON일 때, 일반 NFKC 스캔 이후 base64/base64url로 **보이는** string leaf(고정 알파벳, 유효한 길이, `16…8192` 바이트 범위, 같은 leaf로 round-trip, `node:buffer` `isUtf8`로 **유효한 UTF-8** 디코딩)이거나 `%XX` 이스케이프를 포함하는 leaf(try/catch 안의 `decodeURIComponent`)를 디코딩하여 같은 규칙·validator로 재검사합니다. **offset 처리는 fail closed입니다:** 디코딩된 매칭은 인코딩된 leaf에 유효한 offset이 없으므로, 원본 인코딩 leaf 전체를 덮는 **WHOLE-LEAF** 탐지(`start:0, end:leaf.length`)를 발생시킵니다 — transform이 leaf 전체를 redact/block하며, 디코딩된 offset을 원본으로 되돌려 매핑하지 않습니다. **정밀도 가드:** 디코딩된 매칭은 **validator 기반이거나 하드 블록 타입**일 때만 발생합니다(Luhn 통과 `card`, 체크섬 `kr_rrn`/`us_ssn`, IBAN mod-97, 또는 앵커된 규칙의 `secret`/`api_key`). validator 없는 디코딩된 소프트 타입 매칭(맨 전화번호 형태 등)은 발생하지 **않으므로** 무작위 base64는 오탐하지 않습니다. 새 의존성은 없습니다(`node:buffer` Buffer + `decodeURIComponent` 빌트인). **수용된 잔여:** Haechi가 디코딩하지 않는 인코딩(gzip, hex, 중첩/이중 인코딩, 커스텀 알파벳), 그리고 양성 텍스트 안에 Luhn-유효 16자리 런으로 디코딩되도록 의도적으로 조작된 평문(이에 발생하는 것은 오탐이 아니라 올바른 동작) |
| 인증 없는 멀티 클라이언트 접근 | 로컬 프로세스가 upstream / token round-trip 경로를 무단 사용 | 선택적 bearer auth (`auth.provider: bearer`); 없거나 잘못된 경우 → 바디 읽기 전 401; identity별 rate limit 및 model allowlist |
| Audit tail truncation | 꼬리 audit 레코드의 무음 삭제 | 추가 전용/별도 미디어의 `audit.anchor` head-hash anchoring으로 마지막 anchor까지의 절단 탐지 (0.7) |
| Local dev key in production | 소프트웨어 키의 운영 custody 오용 | `assertCryptoProviderConformance`를 통한 외부 `cryptoProvider` 주입; reference KMS adapter (envelope 암호화) |
| 단일 키의 GCM nonce 고갈 | 로컬 AES-256-GCM provider는 랜덤 96-bit IV를 쓰며, 한 키로 ~2^32회 암호화를 넘기면 birthday bound로 IV 충돌(GCM에 치명적 — 평문 XOR 누출 + 위조 가능) 확률이 무시할 수 없게 됨 | 로컬 provider는 **키당 2^32회 암호화에서 fail-closed**(NIST SP 800-38D §8.3) — 암호화를 거부하고 `haechi init --force` 회전을 안내. 호출 수는 kid별로 카운트되어 미리 예약한 윈도우 단위로 키 파일에 영속화되므로 재시작을 넘겨도 유지됨(과대집계는 가능, 재사용으로의 과소집계는 불가). 50%에서 1회 경고. **수용된 잔여 위험:** 읽기 전용 키 파일은 **프로세스 단위** 한도로 degrade(경고 `HAECHI_NONCE_BUDGET_NOPERSIST`)되고, 하나의 키 파일을 여러 프로세스가 공유하는 경우는 범위 밖(로컬 provider는 단일 writer 레퍼런스이며, 운영 custody는 자체 nonce 규율을 갖는 KMS 위성 사용) |
| Unicode AAD spoofing 또는 stale ciphertext replay | full-width key/value, compatibility 문자 등 시각적으로 동등한 Unicode AAD로 복호화 context를 흔들거나, retention 이후에도 stale token-vault ciphertext가 복호화될 수 있음 | 새 crypto envelope는 `v:2`, `aadEncoding:"nfkc-json-v2"`를 사용합니다. `canonicalizeCryptoAad()`가 string value와 object key를 NFKC 정규화한 뒤 정렬 canonical JSON으로 해시하며, legacy v1 envelope는 하위호환을 위해 기존 canonicalization으로 계속 복호화됩니다. 같은 object level의 NFKC key collision은 조용히 합치지 않고 fail-closed합니다. Envelope는 `expiresAt`를 가질 수 있고 local/KMS provider가 만료 envelope를 거부합니다. Token-vault ciphertext는 token `expiresAt`를 envelope에 묶어 vault retention check에 더한 방어층을 둡니다. **잔여:** streaming transform은 아직 독립 복호화 가능한 stream envelope를 만들지 않으므로 stream sequence AAD / replay cache는 후속입니다 |
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
| audit/로그로의 token/secret leak (broker) (0.9) | ID/access/refresh token, `client_secret`, `code`, `state`, `nonce`, raw `sub`가 audit 로그나 client 응답에 기록됨 | broker는 모든 audit 이벤트를 자체 allowlist로 projection해 `subjectHash`/`issuerHash`/`sessionIdHash`(keyed-HMAC) + `provider`/`reasonCode`/timestamp만 방출; core `FORBIDDEN_KEYS`를 broker token/claim key까지 확장; access token은 **폐기**(저장·사용 안 함). auth-oidc 0.2.0 opt-in refresh에서 `refresh_token`은 AEAD 봉투(도메인 분리 AAD)로만 저장되고, pinned token-endpoint refresh grant를 위해서만 복호화되며, audit/로그에 기록되거나 client에 반환되지 않습니다. 실질적 잔여 없음 |
| KMS backend egress (Vault HTTP, GCP/Azure SDK) (0.9) | `haechi-crypto-kms` Vault/GCP/Azure backend가 key material이나 provider/key-path 상세를 유출하거나 의도치 않은 엔드포인트에 도달 | optional-peer + injected-client 모델과 **faithful-mock conformance**(cross-key·corrupted-blob 거부, HMAC determinism/domain-separation); Vault `fetch`는 위 satellite-local SSRF 가드 수행; 모든 backend는 provider 오류를 generic fail-closed 오류로 매핑하고 provider/key-ARN 상세를 audit에 기록하지 않음. live-backend 검증은 CI 외부 |
| 동적 로딩된 악의적/침해된 signed plugin (1.0) | signed `authProvider` plugin이 worker sandbox에 로딩된 뒤 실행 중 host를 악용 | `canonicalize({pluginId, kind, version, capabilities, coreVersionRange, entrySha256, notBefore, notAfter})`에 대한 Ed25519 서명, **trust-anchor-only** 키 해석(`signerKeyId`가 allowlist된 anchor가 아니면 verify 이전 거부; 알고리즘은 Ed25519로 고정), pin + `pluginId`별 version-floor + revocation denylist(`revokedSignerKeyIds`/`revokedEntrySha256`) + validity-window 집행, `assertAuthProviderConformance` 정합성 게이트, `node:worker_threads` memory/crash 격리 + per-call timeout-terminate, 전체 lifecycle audit(`plugin.load.*`/`authenticate.deny`/`worker.terminated`). 전체 게이트는 매 respawn마다 재실행. **수용된 잔여:** signed plugin 자신의 `fs`/`fetch`/`process.env`는 차단되지 않으며(`networkEgress: false`는 선언일 뿐 1.0에서 집행 통제 아님) 정당하게 받은 credential을 exfiltrate할 수 있음 — 오직 signing/vetting 신뢰 모델로만 통제됨. **1.1이 새 opt-in `process-isolated` 런타임에 대해 이 잔여를 닫음**(다음 행, P1-SEC-027); `worker_threads`(1.0) 모드는 불변이며 이 수용된 잔여를 유지 |
| plugin으로의 PII/secret leak (1.0) | request body·crypto 키·token vault·raw claim이 worker 경계를 넘어 유출 | host는 worker에 **credential slice만** 전달(`Authorization` 헤더 / bearer token — request body 절대 안 보냄, crypto 키 절대 안 보냄); wire는 MessagePort 위 평문 JSON 문자열; **null-prototype, own-key-allowlist claims sanitizer**가 `__proto__`/`constructor`/`prototype`을 제거하고 크기를 bound한 뒤 **host**가 `buildExternalIdentity`로 keyed-HMAC identity를 구성(HMAC 키는 worker에 들어가지 않음). **수용된 잔여:** auth plugin이 정당하게 검증하는 credential은 그 plugin에 보임(위 행 참조) |
| 경계 간 object/proto smuggling (1.0) | 악의적 claims object가 host prototype을 오염시키거나 raw 값을 경계 너머로 밀반입 | JSON-string wire만 사용(structured-clone 없음, `SharedArrayBuffer`/transferables 없음 → shared-memory·object-graph 채널 없음) + `buildExternalIdentity` 이전 null-proto own-key-allowlist sanitizer. 실질적 잔여 없음 |
| plugin entry의 swap / TOCTOU (1.0) | 서명 검사 후 실행 전에 검증된 entry 바이트가 swap됨(예: symlink 경로 재해석) | 서명이 `entrySha256`을 바인딩; loader는 entry를 **메모리로** 읽어 hash·verify하고 **메모리 내 검증된 소스에서** Worker를 spawn(`eval: true`)하며 검증 후 경로를 재해석하지 않고 symlink entry를 거부. 실질적 잔여 없음 |
| signer-key confusion / downgrade / rollback / malicious update (1.0) | confused-deputy가 검증 키/알고리즘을 바꾸거나, 신뢰 signer가 같은 anchor로 새/old-vulnerable entry를 조용히 배포 | trust-anchor-only 해석 + Ed25519 알고리즘 고정(alg agility 없음, HS/RS confusion 없음; signer 집합은 별도 curated 목록이며 AES rotation 키 파일이 아님) + pin(`version`/`entrySha256`/`manifestSha256`) + `pluginId`별 version-floor + revocation denylist. **잔여:** 운영자가 anchor/pin을 curate해야 함 |
| Plugin DoS (1.0) | 버그 있거나 악의적인 signed plugin이 hang/runaway하거나 host를 flood | call별 필수 양의 `timeoutMs`(timeout 시 host가 **worker를 terminate**하고 `null` 반환, lazily respawn), heap `resourceLimits`, `maxPendingCalls`(초과 → deny), `maxMessageBytes`(초과 → deny), single-occupancy worker(per-call terminate가 sibling을 죽일 수 없음). **잔여:** signed plugin이 timeout 내에서 할당된 CPU를 소진할 수 있음(CPU/fd/socket은 1.0에서 bound 안 됨) |
| 감사되지 않는 code-load (1.0) | tamper-evident 기록 없이 third-party 코드를 로딩/실행 | 모든 load/deny/terminate 결정이 chained audit 이벤트 — `plugin.load.accepted`/`plugin.load.refused{reason}`/`plugin.authenticate.deny{reason}`/`plugin.worker.terminated{cause}`(ids/hashes/counts만); `FORBIDDEN_KEYS`를 확장(`claims`, `subject`, `issuer`, `credential`, `authorization`, `signature`, `entry`, 추가로 `scopes`/`labels`)해 defense-in-depth 적용, audit identity는 frozen 5 키 `{id, type, subjectHash, issuerHash, provider}`로 projection. — |
| conformance test/prod 괴리 (1.0) | signed plugin이 고정된 conformance 테스트를 감지해 정상 행동한 뒤 운영에서 오작동 | `assertAuthProviderConformance`는 **load별 예측 불가 randomized vectors**를 사용하고, load-bearing하게 **host가 매 call마다 PII-safety를 재검증**(`buildExternalIdentity` + sanitizer가 요청별 실행)하며 load 시점에만 검증하지 않음. **잔여:** conformance-pass가 신뢰성을 함의하지 않음 — 악의적 plugin이 통과 후 오작동 가능(conformance가 아니라 signing+vetting 게이트로 통제) |
| **`process-isolated`(1.1)** 하에서 host capability를 악용하는 악의적 signed plugin | signed `authProvider` plugin이 host 파일시스템 읽기, spawn, 네트워크 도달, 로그/fd 쓰기로 받은 credential을 exfiltrate 시도 | **커널 강제** capability 거부: plugin이 `--permission` 하의 자식 `node`에서 **부여 0**(fs/child-process/worker/addons/wasi 없음)으로, **`--allow-net` 없이** 실행되며 `data:` URL로 로드(fs 권한 없음 → TOCTOU/symlink 표면 없음). `--allow-net` Node에서 커널이 `net`/`fetch`/`dns`와 `process.binding('tcp_wrap')` 우회까지 거부; `stdio:['ignore','ignore','ignore','ipc']`가 stdout/stderr/fd 유출 채널을 차단; env 정화; IPC는 JSON-문자열 전용. 네트워크 봉쇄는 **fail-closed 기능 탐지** — 기본값 `netEnforcement:"require-permission"`은 `--allow-net`을 강제 못 하는 Node에서 생성 거부. 호스트 중개 키 자료는 호스트가 코어 SSRF 가드로 가져옴(plugin은 URL 명명 안 함). spawn-storm 서킷 브레이커가 재spawn 제한(P1-SEC-027 / P1-SEC-028). **잔여:** `--allow-net` 없는 Node(fail-closed, 미봉쇄); `networkEgress`를 정당하게 부여받은 plugin; 호스트 fetch DNS-rebinding 창; 자식 메모리의 credential + 주입된 키 자료(core-dump/swap 범위 밖); V8/Node 탈출은 모든 런타임 통제를 무력화 |

## 4. 명시적 제외

Haechi는 다음을 보장하지 않습니다.

- 코어 자체의 운영 KMS/HSM/Vault adapter 제공(`haechi-crypto-kms` satellite가 외부 `cryptoProvider` 계약을 통해 AWS/GCP/Azure/Vault adapter를 제공합니다)
- internet-facing gateway 인증/인가
- `streaming.maxMatchBytes`보다 긴 cross-frame 매칭(스트림 프레임에 걸쳐 분할될 수 있음)
- `block`이 발동되기 전에 이미 방출된 스트림 바이트의 회수
- 스트림에서 choice별(`n > 1`) cross-frame 버퍼링(보조 choice는 프레임 내 보호만 적용)
- 법적 컴플라이언스 인증
- 모델 hallucination, prompt injection 완전 방어
- 외부 MCP server의 OAuth/resource binding 검증
- base64/percent-encoded 값의 **기본** 디코딩 후 검사 — Haechi는 NFKC 정규화 텍스트에서 매칭하며(§3의 유니코드 난독화 행 참조) opt-in `filters.decodeAndRescan`(기본 OFF)을 활성화하지 않는 한 base64/URL 디코딩 후 재검사는 하지 **않습니다**. OFF이면 전송 전 base64·percent로 인코딩된 값은 검사되지 않습니다. ON이면 §3에 설명된 정밀도 가드(validator 기반 / 하드 블록 매칭만, WHOLE-LEAF fail-closed)와 함께 디코딩-후-재검사 패스가 동작합니다. WS2d는 *상시* 디코딩을 보류했고(오탐이 많고 범위 내에서 precision-neutral하지 않음), opt-in 통제는 트레이드오프를 수용하는 운영자를 위해 그 잔여를 닫습니다. 다른 인코딩(gzip/hex/중첩/커스텀 알파벳)은 여전히 범위 밖입니다.
- URL query string 내 민감값 검사 (JSON body만 검사)
- 마지막 anchor 이후의 audit tail truncation — `audit.anchor`(0.7)는 anchor가 추가 전용/별도 미디어에 있을 때 마지막 anchor까지의 레코드 삭제를 탐지합니다. 마지막 anchor 이후 기록된 레코드와 동일 파일시스템 anchor는 대상에서 제외됩니다
- JSON-RPC batch 메시지 처리 (MCP stdio filter는 batch를 fail-closed로 거부)
- ~~`haechi-auth-oidc`의 multi-origin / CDN-fronted IdP~~ — **auth-jwt 0.3.0 / auth-oidc 0.2.0부터 지원**: 운영자-핀 `trustedEndpointHosts` allowlist를 통해 지원됩니다(엔드포인트/JWKS 호스트는 issuer 호스트와 같거나 운영자 allowlist에 포함될 때만 허용; allowlist는 설정 전용으로 discovery에서 유도되지 않으며 `https`/`isBlockedAddress`/`metadata.issuer`/RFC 9207 가드는 모두 무조건 실행). 남은 제외: 운영자가 선언한 호스트 집합만 신뢰합니다 — Haechi는 discovery 문서가 주장하는 임의 호스트를 절대 신뢰하지 않습니다.
- ~~refresh-token rotation / silent renewal~~ — **auth-oidc 0.2.0부터 지원**: opt-in `enableRefresh`(기본 off)를 통해 지원됩니다 — refresh token은 AEAD 봉투로만 저장되고(평문/audit 없음), silent renewal은 하드 `refreshMaxLifetimeSeconds` 상한으로 제한되며, 갱신된 ID token은 완전 재검증 + subject-pin되고, refresh 실패는 fail-closed입니다. 여전히 범위 외: 무제한 세션(하드 상한이 항상 총 수명을 제한).
- Dashboard write action(reveal, purge, policy edit) — `haechi-dashboard`는 읽기 전용으로 `POST`/`DELETE` surface 없음; mutation은 reveal governance 하의 CLI에 유지 (0.9)
- OIDC broker의 `at_hash`/`c_hash` 검증 — broker가 access token을 사용하지 않으므로 정확히 범위 외 (0.9; auth-oidc 0.2.0 refresh에서도 여전히 유효 — 갱신은 access token이 아닌 `refresh_token`을 소비)
- **`worker_threads`(1.0)** 모드에서 악의적 signed plugin에 대한 capability *집행*(`fs`/`net`/`process.env` 차단) — worker 격리는 memory/crash 격리 + data-minimization만 제공. **1.1의 opt-in `process-isolated` 런타임에서 집행됨**(`--permission` 하 자식 프로세스, 부여 0, `--allow-net` Node에서 — P1-SEC-027)
- `worker_threads`(1.0) signed plugin이 정당하게 받는 credential의 봉쇄 — de-facto network egress가 있어 exfiltrate 가능; 오직 signing/vetting 신뢰 모델로만 통제. **1.1 `process-isolated`에서 봉쇄됨**(net+stdio+fs 거부, `--allow-net` Node)
- `--allow-net` **없는** Node에서 `process-isolated` plugin의 네트워크 봉쇄 — 런타임이 거기서 **fail closed**(생성 거부)하며 미봉쇄로 실행하지 않음; `worker_threads` 또는 `--allow-net` Node 사용 (1.1)
- `networkEgress`를 명시적으로 부여받은 `process-isolated` plugin의 봉쇄 — net egress를 허용한 운영자는 그 채널의 exfiltration에 대해 봉쇄되지 않음 (1.1)
- 운영자 선언 키 URL에 대한 호스트 중개 키 fetch의 DNS-rebinding 창(resolve-then-connect) — bearer satellite와 동일 입장으로 수용 (1.1)
- 자식 프로세스 메모리에 상주하는 credential + 호스트 주입 키 자료 — core-dump/swap 노출은 범위 밖 (1.1)
- V8/Node 샌드박스 탈출 — `--permission`은 OS 수준 샌드박스(seccomp/namespaces)가 아니라 Node 런타임 통제; 런타임 탈출은 이를 무력화 (1.1)
- classifier/filter 및 crypto plugin 로딩 — 1.0에서 동적 로딩 가능한 plugin kind는 `authProvider`뿐; 다른 kind는 injection-only 유지 (1.0)
- unsigned dev/loader 경로 — unsigned plugin loader는 없음; 개발은 `createRuntime(config, providers)` 주입 사용 (1.0)
- live revocation feed / CRL — revocation은 다음 load/restart에 적용(global/per-plugin kill-switch가 live plugin을 즉시 force-drop); live CRL은 1.x (1.0)

## 5. 남은 운영 전제

운영 사용자는 Haechi 외부에서 네트워크 접근 제어, upstream 인증, secret injection, key custody, 로그 보존, DSAR/삭제 요청 처리, 법적 transfer 근거를 책임져야 합니다.
