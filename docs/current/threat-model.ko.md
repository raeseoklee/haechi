# Haechi Threat Model

- 문서 상태: Draft 0.1
- 작성일: 2026-06-10
- 기준 버전: 1.0.0

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
| 동적 로딩된 악의적/침해된 signed plugin (1.0) | signed `authProvider` plugin이 worker sandbox에 로딩된 뒤 실행 중 host를 악용 | `canonicalize({pluginId, kind, version, capabilities, coreVersionRange, entrySha256, notBefore, notAfter})`에 대한 Ed25519 서명, **trust-anchor-only** 키 해석(`signerKeyId`가 allowlist된 anchor가 아니면 verify 이전 거부; 알고리즘은 Ed25519로 고정), pin + `pluginId`별 version-floor + revocation denylist(`revokedSignerKeyIds`/`revokedEntrySha256`) + validity-window 집행, `assertAuthProviderConformance` 정합성 게이트, `node:worker_threads` memory/crash 격리 + per-call timeout-terminate, 전체 lifecycle audit(`plugin.load.*`/`authenticate.deny`/`worker.terminated`). 전체 게이트는 매 respawn마다 재실행. **수용된 잔여:** signed plugin 자신의 `fs`/`fetch`/`process.env`는 차단되지 않으며(`networkEgress: false`는 선언일 뿐 1.0에서 집행 통제 아님) 정당하게 받은 credential을 exfiltrate할 수 있음 — 오직 signing/vetting 신뢰 모델로만 통제됨. **1.1이 새 opt-in `process-isolated` 런타임에 대해 이 잔여를 닫는다**(다음 행, P1-SEC-027); `worker_threads`(1.0) 모드는 불변이며 이 수용된 잔여를 유지 |
| plugin으로의 PII/secret leak (1.0) | request body·crypto 키·token vault·raw claim이 worker 경계를 넘어 유출 | host는 worker에 **credential slice만** 전달(`Authorization` 헤더 / bearer token — request body 절대 안 보냄, crypto 키 절대 안 보냄); wire는 MessagePort 위 평문 JSON 문자열; **null-prototype, own-key-allowlist claims sanitizer**가 `__proto__`/`constructor`/`prototype`을 제거하고 크기를 bound한 뒤 **host**가 `buildExternalIdentity`로 keyed-HMAC identity를 구성(HMAC 키는 worker에 들어가지 않음). **수용된 잔여:** auth plugin이 정당하게 검증하는 credential은 그 plugin에 보임(위 행 참조) |
| 경계 간 object/proto smuggling (1.0) | 악의적 claims object가 host prototype을 오염시키거나 raw 값을 경계 너머로 밀반입 | JSON-string wire만 사용(structured-clone 없음, `SharedArrayBuffer`/transferables 없음 → shared-memory·object-graph 채널 없음) + `buildExternalIdentity` 이전 null-proto own-key-allowlist sanitizer. 실질적 잔여 없음 |
| plugin entry의 swap / TOCTOU (1.0) | 서명 검사 후 실행 전에 검증된 entry 바이트가 swap됨(예: symlink 경로 재해석) | 서명이 `entrySha256`을 바인딩; loader는 entry를 **메모리로** 읽어 hash·verify하고 **메모리 내 검증된 소스에서** Worker를 spawn(`eval: true`)하며 검증 후 경로를 재해석하지 않고 symlink entry를 거부. 실질적 잔여 없음 |
| signer-key confusion / downgrade / rollback / malicious update (1.0) | confused-deputy가 검증 키/알고리즘을 바꾸거나, 신뢰 signer가 같은 anchor로 새/old-vulnerable entry를 조용히 배포 | trust-anchor-only 해석 + Ed25519 알고리즘 고정(alg agility 없음, HS/RS confusion 없음; signer 집합은 별도 curated 목록이며 AES rotation 키 파일이 아님) + pin(`version`/`entrySha256`/`manifestSha256`) + `pluginId`별 version-floor + revocation denylist. **잔여:** 운영자가 anchor/pin을 curate해야 함 |
| Plugin DoS (1.0) | 버그 있거나 악의적인 signed plugin이 hang/runaway하거나 host를 flood | call별 필수 양의 `timeoutMs`(timeout 시 host가 **worker를 terminate**하고 `null` 반환, lazily respawn), heap `resourceLimits`, `maxPendingCalls`(초과 → deny), `maxMessageBytes`(초과 → deny), single-occupancy worker(per-call terminate가 sibling을 죽일 수 없음). **잔여:** signed plugin이 timeout 내에서 할당된 CPU를 소진할 수 있음(CPU/fd/socket은 1.0에서 bound 안 됨) |
| 감사되지 않는 code-load (1.0) | tamper-evident 기록 없이 third-party 코드를 로딩/실행 | 모든 load/deny/terminate 결정이 chained audit 이벤트 — `plugin.load.accepted`/`plugin.load.refused{reason}`/`plugin.authenticate.deny{reason}`/`plugin.worker.terminated{cause}`(ids/hashes/counts만); `FORBIDDEN_KEYS`를 확장(`claims`, `subject`, `issuer`, `credential`, `authorization`, `signature`, `entry`, 추가로 `scopes`/`labels`)해 defense-in-depth 적용, audit identity는 frozen 5 키 `{id, type, subjectHash, issuerHash, provider}`로 projection. — |
| conformance test/prod 괴리 (1.0) | signed plugin이 고정된 conformance 테스트를 감지해 정상 행동한 뒤 운영에서 오작동 | `assertAuthProviderConformance`는 **load별 예측 불가 randomized vectors**를 사용하고, load-bearing하게 **host가 매 call마다 PII-safety를 재검증**(`buildExternalIdentity` + sanitizer가 요청별 실행)하며 load 시점에만 검증하지 않음. **잔여:** conformance-pass가 신뢰성을 함의하지 않음 — 악의적 plugin이 통과 후 오작동 가능(conformance가 아니라 signing+vetting 게이트로 통제) |
| **`process-isolated`(1.1)** 하에서 host capability를 악용하는 악의적 signed plugin | signed `authProvider` plugin이 host 파일시스템 읽기, spawn, 네트워크 도달, 로그/fd 쓰기로 받은 credential을 exfiltrate 시도 | **커널 강제** capability 거부: plugin이 `--permission` 하의 자식 `node`에서 **부여 0**(fs/child-process/worker/addons/wasi 없음)으로, **`--allow-net` 없이** 실행되며 `data:` URL로 로드(fs 권한 없음 → TOCTOU/symlink 표면 없음). `--allow-net` Node에서 커널이 `net`/`fetch`/`dns`와 `process.binding('tcp_wrap')` 우회까지 거부; `stdio:['ignore','ignore','ignore','ipc']`가 stdout/stderr/fd 유출 채널을 차단; env 정화; IPC는 JSON-문자열 전용. 네트워크 봉쇄는 **fail-closed 기능 탐지** — 기본값 `netEnforcement:"require-permission"`은 `--allow-net`을 강제 못 하는 Node에서 생성 거부. 호스트 중개 키 자료는 호스트가 코어 SSRF 가드로 가져옴(plugin은 URL 명명 안 함). spawn-storm 서킷 브레이커가 재spawn 제한(P1-SEC-027 / P1-SEC-028). **잔여:** `--allow-net` 없는 Node(fail-closed, 미봉쇄); `networkEgress`를 정당하게 부여받은 plugin; 호스트 fetch DNS-rebinding 창; 자식 메모리의 credential + 주입된 키 자료(core-dump/swap 범위 밖); V8/Node 탈출은 모든 런타임 통제를 무력화 |

## 4. 명시적 제외

Haechi는 다음을 보장하지 않는다.

- 코어 자체의 운영 KMS/HSM/Vault adapter 제공(`haechi-crypto-kms` satellite가 외부 `cryptoProvider` 계약을 통해 AWS/GCP/Azure/Vault adapter를 제공한다)
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

운영 사용자는 Haechi 외부에서 네트워크 접근 제어, upstream 인증, secret injection, key custody, 로그 보존, DSAR/삭제 요청 처리, 법적 transfer 근거를 책임져야 한다.
