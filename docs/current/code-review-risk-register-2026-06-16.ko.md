# 2026-06-16 전체 코드리뷰 리스크 등록부

상태: 보완 완료 및 `haechi@1.3.1`로 발행(13개 항목 모두 Resolved; G9 Pass, 2026-06-16)  
범위: `main`의 `a47a6a79c380db412b6a464a2798b7df61f3b68d`  
검토일: 2026-06-16  
출처: 저장소 전체 코드리뷰, 보안/프로토콜/패키징/회귀 테스트 관점의 추가 검토

이 문서는 0.3.2 및 1.3.x 하드닝 이후 새로 발견된 리스크를 추적한다. 과거 릴리스 게이트 기록과 분리해 둔 이유는, 이후 보완 커밋이 각 항목을 독립적으로 `Open`에서 `Resolved` 또는 `Accepted`로 갱신할 수 있게 하기 위해서다.

## 릴리스 판단

아래 P0/P1 항목이 수정되거나 책임자 판단으로 명시 수용되기 전까지 새 릴리스 태그와 npm publish는 차단한다.

저장소는 이미 공개 상태이므로 public source 공개는 유지할 수 있다. 클라이언트 인증 헤더 전달 리스크(P0-CR-001)는 이제 Resolved다 — 프록시는 기본 차단 업스트림 헤더 허용목록을 적용하며 게이트웨이 `Authorization`/`Cookie`/`Proxy-Authorization`를 모델 업스트림으로 전달하지 않는다. hex IPv4-mapped IPv6 SSRF 공백(P1-CR-002)과 그 vault 테스트 공백(P2-CR-012)도 이제 Resolved다 — 모든 `isBlockedAddress` 복사본이 private range 검사 전에 IPv4-mapped IPv6 주소를 임베드된 IPv4로 정규화한다. streaming inspection 우회(P1-CR-005)와 SSE multi-line `data:` 정확성 공백(P2-CR-013)도 이제 Resolved다 — parse 실패한 non-JSON CONTENT frame을 텍스트로 검사하고 multi-line `data:` line을 스펙이 요구하는 newline으로 합친다. 마지막 여섯 개 P2(P2-CR-006 mcp-wrap stderr, P2-CR-007 init key-file 검증, P2-CR-008 satellite `manifest.bin` check, P2-CR-009 auth-throw 테스트, P2-CR-010 process-sandbox quota 테스트, P2-CR-011 audit middle-tamper 테스트)도 이제 Resolved다. **13개 항목이 모두 Resolved이며 `haechi@1.3.1`로 발행되었다**(2026-06-16, attested OIDC publish; core가 1.3.0 → 1.3.1로 bump된 보완 전용 patch). **G9** 릴리스 차단 게이트는 **Pass**다. 운영자는 수정 사항을 반영하려면 `1.3.0`에서 `1.3.1`로 업그레이드해야 한다.

## 심각도 기준

- `P0`: 신뢰 경계를 넘어가는 직접적인 자격증명/데이터 유출, 또는 핵심 보안 약속을 깨는 우회.
- `P1`: SSRF, 보호 우회, 서비스 거부, 보호 배포를 깨뜨릴 수 있는 프로토콜 동작.
- `P2`: 운영, 패키징, 정확성, 회귀 테스트 공백. 넓은 채택 전 보완해야 하는 항목.

## 요약

| ID | 심각도 | 영역 | 리스크 | 상태 | 릴리스 영향 |
| --- | --- | --- | --- | --- | --- |
| P0-CR-001 | P0 | 프록시 헤더 | 클라이언트 `Authorization`, `Cookie`, proxy-auth 등 주변 자격증명이 모델 업스트림으로 전달될 수 있다. | Resolved | 릴리스 차단이었음 |
| P1-CR-002 | P1 | SSRF 가드 | `::ffff:7f00:1` 같은 hex 형식 IPv4-mapped IPv6 주소가 private loopback으로 분류되지 않는다. | Resolved | 릴리스 차단이었음 |
| P1-CR-003 | P1 | 프록시 응답 | 자동 압축 해제된 업스트림 본문이 기존 압축 `content-encoding` / `content-length` 헤더와 함께 반환될 수 있다. | Resolved | 릴리스 차단이었음 |
| P1-CR-004 | P1 | 스트리밍 | `streaming.requestMode: "pass-through"`가 실제 스트리밍이 아니라 전체 본문을 무제한 버퍼링한다. | Resolved | 릴리스 차단이었음 |
| P1-CR-005 | P1 | 스트리밍 검사 | JSON이 아닌 SSE/NDJSON 프레임이 원문 통과되어 plain-text PII가 보호를 우회할 수 있다. | Resolved | 릴리스 차단이었음 |
| P2-CR-006 | P2 | MCP wrap | 자식 프로세스 `stderr`가 상속되어 필터링되지 않는다. | Resolved | 보완 공백이었음 |
| P2-CR-007 | P2 | 키 관리 | `initLocalKeyFile()`이 기존 파일의 키 구조를 검증하지 않고 성공을 보고한다. | Resolved | 보완 공백이었음 |
| P2-CR-008 | P2 | 위성 패키징 | satellite packaging check가 `manifest.bin` 타깃 존재를 검증하지 않는다. | Resolved | 보완 공백이었음 |
| P2-CR-009 | P2 | 인증 테스트 | `authProvider.authenticate()` 예외 경로 회귀 테스트가 없다. | Resolved | 테스트 공백이었음 |
| P2-CR-010 | P2 | 플러그인 샌드박스 테스트 | process-isolated quota/oversize 분기 테스트가 worker sandbox와 동등하지 않다. | Resolved | 테스트 공백이었음 |
| P2-CR-011 | P2 | 감사 테스트 | audit chain 중간 레코드 변조 분기 테스트가 부족하다. | Resolved | 테스트 공백이었음 |
| P2-CR-012 | P2 | Vault 테스트 | KMS vault IPv6 loopback carve-out 테스트가 IPv4 중심이다. | Resolved | 테스트 공백이었음 |
| P2-CR-013 | P2 | SSE 정확성 | multi-line SSE `data:` 필드를 스펙과 다르게 newline 없이 합친다. | Resolved | 정확성 공백이었음 |

## 상세 항목

### P0-CR-001: 프록시가 클라이언트 자격증명을 업스트림으로 전달

상태: Resolved (2026-06-16, 1.3.1 대상)  
영향 코드: `packages/proxy/index.mjs`의 `forward()`, `filteredHeaders()`  
증거:

- `forward()`가 `filteredHeaders(request.headers)`를 업스트림 `fetch()`에 그대로 사용한다.
- `filteredHeaders()`는 현재 `host`, `content-length`만 제거하고 JSON `content-type`을 재설정한다.
- 로컬 업스트림 재현에서 Haechi 게이트웨이 인증에 사용한 bearer 토큰이 업스트림에 도착했다.

영향:

로컬 게이트웨이 신뢰 경계의 클라이언트 자격증명이 모델 공급자 경계로 넘어간다. Haechi bearer 토큰, 쿠키, `Proxy-Authorization`, 브라우저 origin 계열 헤더, 기타 주변 비밀값이 유출될 수 있다. 향후 auth 모듈에서도 client identity와 upstream provider credential을 분리하기 어려워진다.

필수 보완:

- 현재 헤더 pass-through를 명시적 업스트림 헤더 allowlist로 교체한다.
- 게이트웨이 클라이언트 인증과 업스트림 공급자 인증을 분리한다.
- Anthropic/Gemini API-key 헤더처럼 공급자에 필요한 헤더는 adapter 또는 설정 기반의 명시적 upstream credential로만 보존한다.
- hop-by-hop, cookie, proxy-auth, 게이트웨이 클라이언트 authorization 헤더는 기본 제거한다.

최소 검증:

- 게이트웨이 bearer 토큰이 로컬 업스트림에서 관측되지 않는 회귀 테스트.
- 명시적으로 설정한 업스트림 credential은 전달되는 회귀 테스트.
- README와 release-process 문서의 헤더 전달 설명 갱신.

해결 증거:

- `filteredHeaders()`(`packages/proxy/index.mjs`)가 기본 차단 허용목록이 됐다: `FORWARD_HEADER_ALLOWLIST`(제공자/어댑터 헤더 `x-api-key`, `anthropic-version`, `anthropic-beta`, `x-goog-api-key`, `openai-organization`, `openai-beta`, `accept`, `accept-language`, `user-agent`; `content-type`는 `application/json`으로 재작성), 항상 차단하는 `FORWARD_HEADER_DENYLIST`(`host`, `content-length`, `cookie`, `set-cookie`, `proxy-authorization`, hop-by-hop `connection`/`keep-alive`/`te`/`trailer`/`transfer-encoding`/`upgrade`), 조건부 `authorization` 규칙.
- `createHaechiProxy`가 `forwardPolicy`를 한 번 도출해 모든 `forward()` 호출부(보호 경로, streaming pass-through, inspected stream)에 전달한다. `gatewayConsumedAuthorization`은 `auth.provider !== "none"`이며, 게이트웨이가 클라이언트를 인증했으면 요청 `Authorization`(게이트웨이 credential)은 폐기되고, `auth.provider: none`이면 전달된다(업스트림 제공자 키, OpenAI 호환 pass-through 패턴).
- 추가 설정 예외 통로 `target.forwardHeaders`(소문자 헤더 이름 배열)는 `normalizeConfig`(`validateForwardHeaders`)에서 fail-closed로 검증된다: 배열이 아니거나, 소문자가 아니거나, 항상 폐기되는 credential/hop-by-hop 이름이면 로드 시 throw하며, 넓히기만 할 뿐 폐기 헤더를 다시 켤 수 없다.
- 회귀 테스트 `tests/proxy-header-allowlist.test.mjs`: 게이트웨이 bearer 토큰(`auth.provider: bearer`)은 stub 업스트림이 받는 헤더에 없고 제공자 헤더는 있다; cookie/proxy-authorization/hop-by-hop·미등록 헤더는 폐기된다; `auth.provider: none`은 클라이언트 `Authorization`을 전달한다; `target.forwardHeaders`는 추가로 넓힌다; 설정 검증은 fail-closed다. 기존 `tests/proxy-auth.test.mjs`는 여전히 통과한다.
- 문서: README.md(+ko) "Gateway 인증과 upstream 인증의 분리" + 설정 표 행; `threat-model.md`(+ko) "gateway credential의 upstream 전달" 통제 행; `shared-responsibility.md`(+ko) §5 + 매트릭스 행; `configuration.md`(+ko) `target.forwardHeaders` + fail-closed 목록.

릴리스 판단: 수정 또는 명시 수용 전까지 새 릴리스와 npm publish를 차단한다. Resolved.

### P1-CR-002: SSRF 가드가 Hex IPv4-Mapped IPv6를 놓침

상태: Resolved (2026-06-16, 1.3.1 대상)  
영향 코드: `packages/ssrf/index.mjs`, `satellites/auth-jwt/index.mjs` (그리고 관련 과차단이 있던 `satellites/crypto-kms/vault.mjs`)  
증거:

수동 분류 결과(수정 후 — 과거에 오분류되던 행이 이제 올바릅니다):

| 입력 | 결과 | 기대 결과 |
| --- | --- | --- |
| `::ffff:127.0.0.1` | Private | Private |
| `::ffff:7f00:1` | Private | Private |
| `[::ffff:7f00:1]` | Private | Private |
| `::ffff:10.0.0.1` | Private | Private |
| `::ffff:a00:1` | Private | Private |
| `::ffff:8.8.8.8` / `::ffff:808:808` | Public | Public(과차단 아님) |

영향(과거):

guarded fetch 경로가 hexadecimal IPv4-mapped IPv6로 표현된 loopback 또는 RFC1918 주소를 public으로 오분류할 수 있었습니다. core guarded fetch와 auth-jwt JWKS/OIDC fetch guard에 영향을 줬습니다. KMS vault 복사본은 반대 방향의 결함이 있어, 인식하지 못한 모든 `::ffff:` 형식이 "차단" 첫 hextet으로 빠져 `::ffff:808:808` 같은 공인 mapped 주소를 과차단했습니다.

해결:

- 각 `isBlockedAddress` 복사본이 IPv4-mapped IPv6 주소를 16바이트로 파싱해, private/loopback/link-local/metadata 검사 전에 임베드된 IPv4(마지막 32비트, 바이트 0..9가 0이고 바이트 10..11이 `0xffff`일 때만 인식)를 정규화합니다. 이로써 모든 텍스트 형식을 처리합니다: dotted(`::ffff:127.0.0.1`), hex(`::ffff:7f00:1`), bracketed(`[::ffff:7f00:1]`), leading-zero(`::ffff:7f00:0001`), 혼합 `::` 압축, 대소문자 무시 `ffff`. 공인 mapped 주소(`::ffff:8.8.8.8` == `::ffff:808:808`)는 공인 v4로 분류되어 허용 유지됩니다.
- 의도된 1.1 디커플링을 유지합니다: 어떤 위성도 `haechi/ssrf`를 import하지 않습니다(그러면 `haechi` peer floor가 올라가 재배포가 필요). 동일한 정규화를 각 독립 복사본에 적용하고 parity 테스트로 일치를 고정해, 복사본은 독립적이면서도 일관됩니다.

종료 증거(신규/확장 테스트):

- `tests/ssrf.test.mjs` — 표준 벡터 테이블에 hex/dotted/bracketed IPv4-mapped loopback, RFC1918, metadata 벡터와 허용 public mapped 쌍을 추가하고, 모두 auth-jwt 복사본과 같음을 단언(core-vs-auth-jwt parity).
- `satellites/auth-jwt/auth-jwt.test.mjs` — `createJwtAuthProvider` 생성이 dotted 및 hex IPv4-mapped IPv6 private/metadata 호스트를 거부하고, public mapped 호스트는 SSRF 차단하지 않음을 확인.
- `satellites/crypto-kms/vault.test.mjs` — 문서화된 range table에 hex mapped private/metadata 형식과 public mapped 허용 케이스를 추가.
- `satellites/crypto-kms/ssrf-parity.test.mjs` — 새 "IPv4-mapped IPv6 (dotted + hex)" 그룹이 auth-jwt ⇄ crypto-kms 일치를 고정하며 parity 테스트는 계속 green.

릴리스 판단: 해결됨; 이 항목은 더 이상 릴리스를 차단하지 않습니다.

### P1-CR-003: 압축 해제 본문과 압축 헤더 불일치

상태: Resolved (2026-06-16, 1.3.1 대상)  
영향 코드: `packages/proxy/index.mjs`의 unprotected response 경로  
증거:

- Node `fetch()`는 gzip/br/deflate 본문을 자동 압축 해제한다.
- unprotected 및 allow/pass-through 경로는 decoded body를 반환하면서 원래 업스트림 헤더를 보존한다.
- 로컬 gzip 업스트림 재현에서 downstream fetch가 `incorrect header check`로 실패했다.

영향:

프록시가 프로토콜상 일관되지 않은 응답을 낼 수 있다. 클라이언트 실패, 재시도, 응답 오해석을 유발하고 response protection 경로와 비보호 경로의 안전 불변식이 달라진다.

필수 보완:

- Node가 본문을 읽거나 변환한 경우 `content-encoding`, `content-length`, transfer, compression metadata를 제거하거나 재계산한다.
- protected, unprotected, allow 경로가 같은 response-header sanitation 불변식을 공유하도록 중앙화한다.
- gzip/br protected/unprotected 응답 테스트를 추가한다.

해결 증거:

- 단일 중앙화 `sanitizeResponseHeaders(upstreamResponse)`(`packages/proxy/index.mjs`, 기존 `streamingResponseHeaders`를 일반화)가 `content-encoding`, `content-length`, `transfer-encoding`, hop-by-hop 헤더(`connection`/`keep-alive`/`te`/`trailer`/`upgrade`/`proxy-authenticate`)를 제거한다. 모든 응답 경로(streaming pass-through, inspected-stream `writeHead`, 미보호/전달 경로, 보호 JSON 경로의 `transformedJsonHeaders`, `failureMode: allow` 경로)에 적용된다. 올바른 `content-length`는 완전 버퍼링된 바디에만 다시 설정된다.
- 회귀 테스트 `tests/proxy-header-allowlist.test.mjs`: gzip 업스트림 응답(Node fetch 자동 압축 해제)이 `content-encoding` 없이 반환되고, downstream fetch가 pass-through 경로와 미보호/전달 경로 모두에서 평문 본문을 읽는다.

릴리스 판단: 수정 전까지 릴리스 차단. Resolved.

### P1-CR-004: Streaming Pass-Through가 버퍼링 및 무제한

상태: Resolved (2026-06-16, 1.3.1 대상)  
영향 코드: `packages/proxy/index.mjs` streaming `pass-through` 분기  
증거:

- pass-through 분기가 `await readUpstreamBody(upstreamResponse)` 이후 `response.end(rawBody)`를 호출한다.
- 해당 경로에는 response `maxBytes` 제한이 적용되지 않는다.
- 실제 SSE/NDJSON 스트리밍은 업스트림 연결이 닫힐 때까지 지연된다.

영향:

설정 이름은 pass-through streaming을 기대하게 하지만 구현은 전체 응답 버퍼링이다. 길게 유지되는 스트림이나 악의적 스트림이 메모리와 연결 자원을 무기한 점유할 수 있다.

필수 보완:

- 진짜 bounded streaming pass-through를 구현하거나, 구현 전까지 해당 모드를 명확히 비활성/실패 처리한다.
- 모든 raw upstream body read에 byte/duration limit을 적용한다.
- long-lived stream, response-size overrun, client disconnect cancellation 테스트를 추가한다.

해결 증거:

- pass-through 분기가 이제 진정한 경계 스트리밍을 한다(`pipeUpstreamBodyBounded`, `packages/proxy/index.mjs`): 업스트림 본문을 도착하는 대로 클라이언트 응답으로 파이핑하며 `streamingPassThroughMaxBytes(config)`(= `responseProtection.maxBytes`)에 대한 실행 바이트 카운트를 유지한다. 한도 초과 시 업스트림 reader를 취소하고 클라이언트 응답을 destroy한다(크기 기준 fail-closed). `response.write` + `drain`으로 downstream backpressure를 존중한다. 기존 `readUpstreamBody(...)` + `response.end(rawBody)` 전체 버퍼링은 제거됐다.
- `maybeProtectResponse`의 미보호/전달 raw-body read도 동일한 바이트 한도를 `readUpstreamBody({ maxBytes })`에 전달하고 `tooLarge` 시 fail-closed(502 `haechi_response_too_large`)하므로, 한도 없는 raw 업스트림 본문 읽기가 없다.
- 회귀 테스트 `tests/proxy-header-allowlist.test.mjs`: content-length 없이 한도의 8배가 넘는 oversize pass-through 스트림이 한도 근처에서 경계/중단되고 전체 스트림을 전달하지 않는다; 미보호/전달 경로는 oversize 버퍼링 바디에 502 `response_body_too_large`를 반환한다.

릴리스 판단: 수정 전까지 차단. 대안으로 모드를 기본 비활성화하고 unavailable로 문서화해야 한다. Resolved.

### P1-CR-005: Streaming Inspect가 Non-JSON 프레임을 원문 통과

상태: Resolved (2026-06-16, 1.3.1 대상)  
영향 코드: `packages/stream-filter/index.mjs`, `packages/core/index.mjs`  
증거(과거):

- SSE parser가 JSON이 아닌 `data:` 프레임을 `ok: false`로 반환했다.
- inspect 흐름이 parse 실패 프레임을 원문 통과시켰다(`if (!parsed.ok) { sink.write(frame.raw); return; }`).
- `data: minji.kim@example.com\n\n` 재현에서 `blocked: false`이며 이메일이 유출됐다.

영향(과거):

streaming inspection이 켜져 있어도 plain-text SSE 또는 NDJSON 유사 프레임이 PII/secret 보호를 우회할 수 있었다. malformed, non-JSON, provider-specific 프레임에 민감값이 담길 경우 streaming hardening의 가치가 약해졌다.

해결:

- `parseFrame`(`packages/stream-filter/index.mjs`)이 이제 CONTROL frame과 non-JSON CONTENT frame을 구분한다. CONTROL은 검사 가능한 텍스트가 없는 명시 allowlist다 — SSE `[DONE]` sentinel, comment-only frame(`:`/field line만 있고 `data:` 없음), empty/whitespace/keepalive frame. 이들은 `{ ok:false, control:true, text:null }`을, non-JSON CONTENT frame은 `{ ok:false, control:false, text }`(재구성된 `data:` payload)를 반환한다.
- `handleFrame`의 parse 실패 분기는 CONTROL frame을 원문 통과시키되(기존 동작), non-JSON CONTENT frame은 텍스트로 검사한다 — 새 `protector.protectText(text)`(single-shot detect → decide → tally → transform)를 호출하고, `serializeTextFrame`로 `data: <protected text>`를 재방출하며(`event:`/`id:`/`:` line 보존, multi-line payload는 여러 `data:` line으로 재방출), block-action 탐지 시 stream을 fail-closed로 차단한다(`blocked = true`).
- `createStreamProtector`(`packages/core/index.mjs`)에 `protectText(text)`를 추가했고, 기존 `transformSegment` 로직을 재사용한다. delta 채널의 `push`/`flush` cross-frame 버퍼와 DISTINCT하며 — `pending`을 절대 건드리지 않으므로 — non-JSON frame 텍스트 검사가 JSON delta sliding-buffer 상태를 오염시킬 수 없다. per-frame 텍스트 검사로 우회를 막으며, 임의 non-JSON frame의 cross-frame 버퍼링은 범위 밖이다(delta 채널은 자체 버퍼 유지; 코드에 명시).
- response-direction marker skip과 audit tally는 보존된다 — `protectText`가 protector의 response-direction `context`로 동일한 `transformSegment`를 실행하므로 모델이 되돌려준 tokenized round-trip(`[REDACTED:…]`, `[TOKEN:…]`)은 재플래그되지 않는다. JSON 경로(delta 채널, `protectFrameExtras`, cross-frame sliding buffer, `event:`-line 보존)는 변경 없음.

종결 증거:

- `tests/stream-filter.test.mjs`에 추가: plain-text SSE `data: <email>` frame이 redact됨(유출 아님); `card: block` action이 있는 plain-text frame이 stream을 BLOCK; PII가 든 malformed/partial JSON이 텍스트로 검사됨; PII가 든 NDJSON non-JSON content frame이 검사됨; comment-only/keepalive/`event:` control frame이 그대로 통과; tokenized-round-trip marker가 재플래그 안 됨. 기존 within-frame/cross-frame JSON delta 테스트, `[DONE]`/keepalive 통과, report-only 테스트는 그대로 통과.
- `tests/proxy-streaming.test.mjs`에 end-to-end 재현 추가: `data: minji.kim@example.com\n\n`(plain text)을 방출하는 upstream이 프록시를 통해 `[REDACTED:email]`로 redact되고 `stream_inspected`가 audit되며 plaintext 없이 audit chain이 검증된다.
- 후속(적대적 검증이 1차 수정의 잔여 누출을 포착): **trim 불일치**로 선행 공백이 있는 `data:` 라인(` data: <pii>`)이 파싱·redact되었지만, serializer가 untrimmed 원본 라인에 더 엄격한 `startsWith("data:")`를 써서 그 라인을 **그대로 재방출**해 원본을 누출했고(JSON `serializeFrame`에도 동일 클래스), 단일 공유 lenient 매처 `SSE_DATA_LINE`/`sseDataPayload`를 `parseFrame`과 두 serializer가 함께 쓰도록 고쳐 `  data:`/`\tdata:` 라인이 항상 인식·교체되고 그대로 방출되지 않게 했습니다. 또한 `handleFrame`이 bare PRIMITIVE JSON 프레임(예: `data: "<pii>"`)을 객체 delta 경로(문자열 root에 `setByPath` → uncaught TypeError) 대신 텍스트 검사로 라우팅하도록 강화했습니다. `tests/stream-filter.test.mjs`에 회귀 테스트 추가(선행 공백/탭 `data:` 평문, 선행 공백 JSON non-delta 필드, bare-primitive JSON).

릴리스 판단: 수정 전까지 릴리스 차단. Resolved.

### P2-CR-006: MCP Wrap 자식 `stderr` 상속

상태: Resolved (2026-06-16, 1.3.1 대상)  
영향 코드: `packages/cli/bin/haechi.mjs`의 `mcpWrapCommand()`  
증거:

- MCP server child process가 `stdio: ["pipe", "pipe", "inherit"]`로 실행된다.
- `stderr`는 필터링, 감사, redact, tokenize 대상이 아니다.

영향:

MCP 서버가 출력한 민감값이 Haechi 통제 없이 터미널, 에디터 로그, 프로세스 supervisor 로그에 남을 수 있다. 로컬 프로세스 경계로 명시 수용할 수도 있지만 현재 문서화가 충분하지 않다.

해결 / 종료 증거:

- `haechi mcp-wrap`에 명시적 `--stderr filter|drop|inherit` 플래그(기본 `filter`)를 추가했습니다. `filter`는 자식의 stderr를 pipe하고, 각 완성된 라인을 동일한 보호 경로(`runtime.haechi.createStreamProtector().protectText`)로 통과시킨 뒤 부모의 stderr로 재방출합니다 — 탐지된 secret/PII는 그 자리에서 redact/mask하고, block-action 탐지 시 그 라인을 통째로 drop하며 — partial line은 chunk 경계를 넘어 버퍼링하고(`\n`으로 분할, 종료 시 말미 partial flush) source 순서대로 재방출합니다. `drop`은 자식 stderr를 폐기하고(`resume()`로 소비해 자식이 멈추지 않게 함), `inherit`은 기존 raw passthrough를 명시적·문서화된 opt-in 로컬 프로세스 경계로 유지하며, 알 수 없는 `--stderr` 값은 자식을 spawn하기 전에 명확한 fail-closed 오류를 throw합니다. stderr filter 경로는 audit sink에 아무것도 기록하지 않고(평문이 audit 로그에 도달하지 않음), stdin/stdout JSON-RPC wrap 동작은 바이트 동일합니다. `COMMAND_HELP`가 이 플래그를 문서화하며, `filter`가 설정된 정책 모드를 따른다는 점(dry-run/report-only는 탐지하되 변환하지 않음)도 포함합니다.
- `tests/mcp-wrap.test.mjs`에 네 가지 케이스를 추가했습니다(filter는 redact/mask/drop하여 부모가 raw secret/PII/card/phone 값을 절대 보지 못함; drop은 아무것도 방출하지 않음; inherit은 raw 통과; 알 수 없는 값은 non-zero로 종료). 적대적 검증으로 기본값이 이제 `filter`(과거에는 취약한 `inherit`)이고, chunk로 분할된 secret이 재조립되어 보호되며, block-action 라인이 누출되지 않고 drop됨을 확인했습니다.

릴리스 판단: 해결됨.

### P2-CR-007: Init 시 기존 키 파일 미검증

상태: Resolved (2026-06-16, 1.3.1 대상)  
영향 코드: `packages/crypto/index.mjs`의 `initLocalKeyFile()`  
증거:

- 기존 key-file 경로는 active/retired key가 parse 및 사용 가능한지 검증하지 않고 성공을 반환한다.

영향:

`haechi init`이 손상됐지만 JSON으로는 읽히는 키 자료에 대해 성공을 보고할 수 있다. 사용자는 암호화, 복호화, token vault, bundle verification 시점에야 문제를 발견한다.

해결 / 종료 증거:

- provider의 기존 key-load/validation 로직(JSON parse, 키별 base64url + 32바이트 검사, active-key 해석)을 공유 모듈 수준 `loadKeyFile(keyFile, { requireActive })`로 추출했고, private `loadKeys()`가 이제 여기에 위임합니다(과거의 `keys[0]` fallback 보존). `initLocalKeyFile`의 기존 파일 non-force 경로는 이제 반환 전에 `loadKeyFile`을 `requireActive: true`로 호출하며, 결함별로 특정 오류를 throw합니다(corrupted JSON; "No active key found in local key file"; active 또는 retired key에 대한 "AES-256-GCM local key must be 32 bytes"). 유효한 기존 파일은 비파괴로 유지되어 동일한 `{ created: false, keyFile }` 형태를 반환하며, `--force` rotation(삭제가 아닌 retire)은 불변입니다.
- `tests/crypto.test.mjs`에 네 가지 케이스를 추가했습니다: corrupted JSON throw; active key 부재 throw; 잘못된 길이의 active key throw; retired key가 있는 유효한 파일은 바이트 단위로 변경 없이 성공. 적대적 검증으로 각 결함이 포착되고 유효 경로가 비파괴임을 확인했습니다.

릴리스 판단: 해결됨.

### P2-CR-008: Satellite Packaging Check가 `manifest.bin` 누락을 놓침

상태: Resolved (2026-06-16, 1.3.1 대상)  
영향 코드: `scripts/check-satellite-packaging.mjs`  
증거:

- package check가 export 파일은 검증하지만 `manifest.bin`이 가리키는 executable file 존재를 증명하지 않는다.

영향:

satellite package가 로컬 packaging check를 통과해도 CLI entrypoint가 깨진 상태로 배포될 수 있다. auth/KMS/dashboard satellite가 늘어날수록 릴리스 품질 리스크가 커진다.

해결 / 종료 증거:

- `scripts/check-satellite-packaging.mjs`의 `evaluateSatellitePackaging()`이 이제 모든 `manifest.bin` 타깃을 packed-file 집합과 대조해 검증합니다: string 형식(`bin: "bin/x.mjs"`)과 object-map 형식(`bin: { name: "bin/x.mjs" }`)을 모두 `files`/`exports`와 동일하게 정규화하며, tarball에 없는 bin 타깃에 대해서는 명확한 문제를 보고합니다. 기존 검사는 불변입니다.
- `tests/satellite-packaging-gate.test.mjs`에 positive(bin 존재 → 문제 없음)와 negative(bin 누락, string + object-map 형식 → bin 전용 문제) 케이스를 추가했습니다. 적대적 검증으로 bin-check 블록을 제거하는 mutation이 negative 테스트를 실패시킴을 확인했습니다.

릴리스 판단: 해결됨.

### P2-CR-009: Auth Provider 예외 경로 테스트 공백

상태: Resolved (2026-06-16, 1.3.1 대상)  
영향 코드: `packages/proxy/index.mjs` auth 처리, `tests/proxy-auth.test.mjs`  
증거:

- runtime은 `authProvider.authenticate()` 예외를 fail-closed `haechi_auth_provider_error`로 감싼다.
- 기존 테스트는 여러 auth 결과를 다루지만 provider exception을 직접 검증하지 않는다.

영향:

향후 auth-provider 변경이 raw error 유출, fail-open, audit status 불일치를 만들더라도 테스트가 잡지 못할 수 있다.

해결 / 종료 증거:

- `tests/proxy-auth.test.mjs`에 `authenticate()`가 throw하는 `authProvider`를 주입해 프록시가 fail-closed임을 단언하는 회귀 테스트를 추가했습니다: 요청은 거부되고(업스트림으로 전달되지 않음) generic client error를 반환하며, audit event는 fail-closed status `haechi_auth_provider_error`를 기록하고, raw error/stack과 raw subject/issuer가 audit event에 누출되지 않습니다. 적대적 검증으로 fail-open mutant(업스트림 전달 / 200 반환)와 audit-leak mutant가 모두 테스트를 실패시킴을 확인했습니다.

릴리스 판단: 해결됨.

### P2-CR-010: Process-Isolated Sandbox Quota 테스트 공백

상태: Resolved (2026-06-16, 1.3.1 대상)  
영향 코드: `packages/plugin/process-sandbox.mjs`  
증거:

- oversized result 및 over-capacity 분기가 worker sandbox 테스트와 같은 수준으로 보장되지 않는다.

영향:

process isolation은 향후 plugin 작업의 보안 경계다. denial-of-service control 회귀 가능성을 줄이려면 worker sandbox와 동등한 테스트가 필요하다.

해결 / 종료 증거:

- `tests/plugin-process-sandbox.test.mjs`(`tests/helpers/sandbox-fixtures.mjs`에 crash fixture 추가)에 worker-sandbox DoS-control 커버리지를 미러링하는 isolated-process parity 테스트를 추가했습니다: oversized result 거부, queue/over-capacity 거부, timeout 종료, child-crash fail-closed(call 도중 crash가 sibling call을 죽이지 않고 `crash` 원인의 거부로 드러남). 적대적 검증으로 oversize / capacity / timeout / crash 가드를 비활성화하는 mutation이 각각 해당 테스트를 실패시킴을 확인했습니다(crash 경계는 call 도중 crash 테스트로 고정).

릴리스 판단: 해결됨.

### P2-CR-011: Audit Chain 중간 변조 테스트 공백

상태: Resolved (2026-06-16, 1.3.1 대상)  
영향 코드: `packages/audit/index.mjs`의 `verifyAuditChain()`  
증거:

- 기존 커버리지가 middle-record tampering 분기를 직접 검증하지 않는다.

영향:

감사 무결성은 핵심 주장이다. chain verification 코드는 존재하지만 중간 레코드 변조, prev 누락, prev 불일치, hash 불일치를 거부한다는 테스트 증거가 필요하다.

해결 / 종료 증거:

- `tests/audit-chain-tamper.test.mjs`가 sink로 실제 multi-record audit 로그를 기록한 뒤 MIDDLE 레코드를 변조해, `verifyAuditChain`이 각 분기마다 올바른 사유와 함께 `{ valid: false }`를 반환함을 단언합니다: middle-record content mutation(stale `eventHash`), `previousHash` 누락, 잘못된 `previousHash`, 잘못된 `integrity` hash. 알려진 tail-truncation 한계(말미 레코드 제거는 chain만으로는 안 되고 별도 append-only anchor 스트림으로만 탐지 가능)는 계속 명시합니다. 적대적 검증으로 로그가 실제 sink로 생성되고 단언이 각 변조 분기를 고정함을 확인했습니다.

릴리스 판단: 해결됨.

### P2-CR-012: KMS Vault IPv6 Loopback 테스트 공백

상태: Resolved (2026-06-16, 1.3.1 대상)  
영향 코드: `satellites/crypto-kms/vault.mjs`  
증거(과거):

- localhost carve-out 테스트가 IPv4 loopback 중심이었습니다.

영향(과거):

vault guard는 보안 민감 경로이며 core SSRF guard와 URL parsing logic이 약간 달랐습니다. 향후 불일치를 막으려면 IPv6 전용 테스트가 필요했습니다.

해결 / 종료 증거:

- `satellites/crypto-kms/vault.test.mjs`에 전용 테스트 "isBlockedAddress enforces the IPv6 loopback policy (::1, [::1], dotted + hex mapped) — P2-CR-012"를 추가해, bare `::1`, bracketed `[::1]`, dotted `::ffff:127.0.0.1`(및 bracketed 형), hex `::ffff:7f00:1` / `::ffff:7f00:0001`(및 bracketed 형)을 의도된 vault policy(차단)에 맞춰 검증하고, 공인 IPv4-mapped 주소(`::ffff:8.8.8.8` / `::ffff:808:808`)가 과차단되지 않음을 단언합니다.
- vault range table을 hex mapped private/metadata 형식과 public mapped 허용 케이스로 확장하고, `satellites/crypto-kms/ssrf-parity.test.mjs`가 auth-jwt 복사본과의 dotted+hex 일치를 고정합니다 — 의도된 non-IP fail-closed 불일치는 명시적으로 고정되어 향후 drift를 잡아냅니다.

릴리스 판단: 해결됨; 테스트 공백이 닫혔습니다.

### P2-CR-013: SSE Multi-Line `data:` Join Semantics

상태: Resolved (2026-06-16, 1.3.1 대상)  
영향 코드: `packages/stream-filter/index.mjs`  
증거(과거):

- SSE parser가 여러 `data:` line을 `join("")`으로 합쳤다.
- SSE 처리 모델은 여러 data line을 newline separator로 결합한다.

영향(과거):

정상 multi-line SSE event가 parsing 또는 inspection 전에 변형될 수 있었다. false negative, false positive, malformed forwarded event를 만들 수 있었다.

해결:

- `parseFrame`이 이제 여러 `data:` line을 `join("\n")`(SSE 스펙 separator)으로 합치고, line별로 스펙이 정의한 선행 공백 1개만 제거한다(`trim()` 대신 `replace(/^ /, "")` — 텍스트의 내부/말미 공백을 손상시키지 않음). multi-line JSON event는 newline이 토큰 사이/값 내부의 유효한 JSON whitespace이므로 여전히 `JSON.parse`되고, multi-line plain-text event는 텍스트 검사 전에 newline과 함께 재구성된다. non-JSON CONTENT 재직렬화기(`serializeTextFrame`)가 multi-line protected payload를 여러 `data:` line으로 재방출하므로 newline이 round-trip에서 보존된다.

종결 증거:

- `tests/stream-filter.test.mjs`에 multi-line `data:` JSON event(두 `data:` line으로 분할)가 여전히 parse되고 보호되는 테스트와, PII(둘째 line)가 잡혀 두 `data:` line이 보존된 채 재방출되는 multi-line plain-text `data:` event 테스트를 추가했다.

릴리스 판단: streaming 보완 묶음에서 함께 수정 권장. Resolved.

## 보완 순서

1. `P0-CR-001`을 최우선으로 수정한다. 직접 credential boundary leak이다.
2. auth-provider discovery 또는 KMS integration 같은 새 URL fetch surface를 늘리기 전에 `P1-CR-002`를 수정한다.
3. response-forwarding invariant를 공유하므로 `P1-CR-003`과 `P1-CR-004`를 함께 수정한다.
4. streaming inspection 묶음으로 `P1-CR-005`와 `P2-CR-013`을 함께 수정한다.
5. 민감한 로컬 도구에 MCP wrap을 권장하기 전에 `P2-CR-006`을 해결한다.
6. 다음 npm publish 전 P2 key, packaging, regression-test 공백을 마무리한다.

## 종료 규칙

항목을 `Resolved`로 옮기려면 아래 조건을 모두 만족해야 한다.

- 코드 또는 문서 보완이 merge되어 있다.
- 집중 회귀 테스트 또는 명시적 non-test rationale이 기록되어 있다.
- 릴리스 게이트 등록부가 보완 증거를 링크한다.
- 수용된 잔여 리스크는 threat model 또는 shared-responsibility 문서로 이동하고 운영자 가이드를 포함한다.

## 추적 링크

이 문서는 아래에서 참조한다.

- `docs/current/risk-register-release-gate.md`
- `docs/current/risk-register-release-gate.ko.md`

