# 2026-06-16 전체 코드리뷰 리스크 등록부

상태: 공개 보완 등록부  
범위: `main`의 `a47a6a79c380db412b6a464a2798b7df61f3b68d`  
검토일: 2026-06-16  
출처: 저장소 전체 코드리뷰, 보안/프로토콜/패키징/회귀 테스트 관점의 추가 검토

이 문서는 0.3.2 및 1.3.x 하드닝 이후 새로 발견된 리스크를 추적한다. 과거 릴리스 게이트 기록과 분리해 둔 이유는, 이후 보완 커밋이 각 항목을 독립적으로 `Open`에서 `Resolved` 또는 `Accepted`로 갱신할 수 있게 하기 위해서다.

## 릴리스 판단

아래 P0/P1 항목이 수정되거나 책임자 판단으로 명시 수용되기 전까지 새 릴리스 태그와 npm publish는 차단한다.

저장소는 이미 공개 상태이므로 public source 공개는 유지할 수 있다. 다만 클라이언트 인증 헤더가 업스트림으로 전달되는 리스크가 해결되기 전까지는 민감한 운영 트래픽을 이 프록시 뒤에 두지 않는다.

## 심각도 기준

- `P0`: 신뢰 경계를 넘어가는 직접적인 자격증명/데이터 유출, 또는 핵심 보안 약속을 깨는 우회.
- `P1`: SSRF, 보호 우회, 서비스 거부, 보호 배포를 깨뜨릴 수 있는 프로토콜 동작.
- `P2`: 운영, 패키징, 정확성, 회귀 테스트 공백. 넓은 채택 전 보완해야 하는 항목.

## 요약

| ID | 심각도 | 영역 | 리스크 | 상태 | 릴리스 영향 |
| --- | --- | --- | --- | --- | --- |
| P0-CR-001 | P0 | 프록시 헤더 | 클라이언트 `Authorization`, `Cookie`, proxy-auth 등 주변 자격증명이 모델 업스트림으로 전달될 수 있다. | Open | 릴리스 차단 |
| P1-CR-002 | P1 | SSRF 가드 | `::ffff:7f00:1` 같은 hex 형식 IPv4-mapped IPv6 주소가 private loopback으로 분류되지 않는다. | Open | 릴리스 차단 |
| P1-CR-003 | P1 | 프록시 응답 | 자동 압축 해제된 업스트림 본문이 기존 압축 `content-encoding` / `content-length` 헤더와 함께 반환될 수 있다. | Open | 릴리스 차단 |
| P1-CR-004 | P1 | 스트리밍 | `streaming.requestMode: "pass-through"`가 실제 스트리밍이 아니라 전체 본문을 무제한 버퍼링한다. | Open | 릴리스 차단 |
| P1-CR-005 | P1 | 스트리밍 검사 | JSON이 아닌 SSE/NDJSON 프레임이 원문 통과되어 plain-text PII가 보호를 우회할 수 있다. | Open | 릴리스 차단 |
| P2-CR-006 | P2 | MCP wrap | 자식 프로세스 `stderr`가 상속되어 필터링되지 않는다. | Open | 보완 또는 경계 문서화 필요 |
| P2-CR-007 | P2 | 키 관리 | `initLocalKeyFile()`이 기존 파일의 키 구조를 검증하지 않고 성공을 보고한다. | Open | 다음 publish 전 보완 권장 |
| P2-CR-008 | P2 | 위성 패키징 | satellite packaging check가 `manifest.bin` 타깃 존재를 검증하지 않는다. | Open | 다음 publish 전 보완 권장 |
| P2-CR-009 | P2 | 인증 테스트 | `authProvider.authenticate()` 예외 경로 회귀 테스트가 없다. | Open | 테스트 공백 |
| P2-CR-010 | P2 | 플러그인 샌드박스 테스트 | process-isolated quota/oversize 분기 테스트가 worker sandbox와 동등하지 않다. | Open | 테스트 공백 |
| P2-CR-011 | P2 | 감사 테스트 | audit chain 중간 레코드 변조 분기 테스트가 부족하다. | Open | 테스트 공백 |
| P2-CR-012 | P2 | Vault 테스트 | KMS vault IPv6 loopback carve-out 테스트가 IPv4 중심이다. | Open | 테스트 공백 |
| P2-CR-013 | P2 | SSE 정확성 | multi-line SSE `data:` 필드를 스펙과 다르게 newline 없이 합친다. | Open | 정확성 공백 |

## 상세 항목

### P0-CR-001: 프록시가 클라이언트 자격증명을 업스트림으로 전달

상태: Open  
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

릴리스 판단: 수정 또는 명시 수용 전까지 새 릴리스와 npm publish를 차단한다.

### P1-CR-002: SSRF 가드가 Hex IPv4-Mapped IPv6를 놓침

상태: Open  
영향 코드: `packages/ssrf/index.mjs`, `satellites/auth-jwt/index.mjs`  
증거:

수동 분류 결과:

| 입력 | 현재 결과 | 기대 결과 |
| --- | --- | --- |
| `::ffff:127.0.0.1` | Private | Private |
| `::ffff:7f00:1` | Public | Private |
| `[::ffff:7f00:1]` | Public | Private |
| `::ffff:10.0.0.1` | Private | Private |
| `::ffff:a00:1` | Public | Private |

영향:

guarded fetch 경로가 hexadecimal IPv4-mapped IPv6로 표현된 loopback 또는 RFC1918 주소를 public으로 오분류할 수 있다. core guarded fetch와 auth-jwt JWKS/OIDC fetch guard에 영향을 준다. KMS vault 코드에는 더 완전한 변형이 있는 것으로 보이므로 보안 URL 가드 간 동작 불일치도 발생한다.

필수 보완:

- private range 검사 전에 IPv4-mapped IPv6 형식을 정규화한다.
- core SSRF, auth-jwt, KMS vault에서 하나의 공유 parser/checker를 사용한다.
- dotted/hex mapped loopback, RFC1918, link-local, bracketed host, 허용 public IPv6 테스트를 추가한다.

릴리스 판단: 수정 전까지 릴리스 차단.

### P1-CR-003: 압축 해제 본문과 압축 헤더 불일치

상태: Open  
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

릴리스 판단: 수정 전까지 릴리스 차단.

### P1-CR-004: Streaming Pass-Through가 버퍼링 및 무제한

상태: Open  
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

릴리스 판단: 수정 전까지 차단. 대안으로 모드를 기본 비활성화하고 unavailable로 문서화해야 한다.

### P1-CR-005: Streaming Inspect가 Non-JSON 프레임을 원문 통과

상태: Open  
영향 코드: `packages/stream-filter/index.mjs`  
증거:

- SSE parser가 JSON이 아닌 `data:` 프레임을 `ok: false`로 반환한다.
- 현재 inspect 흐름은 parse 실패 프레임을 원문 통과시킨다.
- `data: minji.kim@example.com\n\n` 재현에서 `blocked: false`이며 이메일이 유출됐다.

영향:

streaming inspection이 켜져 있어도 plain-text SSE 또는 NDJSON 유사 프레임이 PII/secret 보호를 우회할 수 있다. malformed, non-JSON, provider-specific 프레임에 민감값이 담길 경우 streaming hardening의 가치가 약해진다.

필수 보완:

- parse 실패 content frame을 자동 원문 통과가 아니라 검사 가능한 텍스트로 취급한다.
- `[DONE]` 같은 protocol control frame은 명시 allowlist로 보존한다.
- plain-text SSE, partial JSON, PII가 든 malformed JSON, provider control message 테스트를 추가한다.

릴리스 판단: 수정 전까지 릴리스 차단.

### P2-CR-006: MCP Wrap 자식 `stderr` 상속

상태: Open  
영향 코드: `packages/cli/bin/haechi.mjs`의 `mcpWrapCommand()`  
증거:

- MCP server child process가 `stdio: ["pipe", "pipe", "inherit"]`로 실행된다.
- `stderr`는 필터링, 감사, redact, tokenize 대상이 아니다.

영향:

MCP 서버가 출력한 민감값이 Haechi 통제 없이 터미널, 에디터 로그, 프로세스 supervisor 로그에 남을 수 있다. 로컬 프로세스 경계로 명시 수용할 수도 있지만 현재 문서화가 충분하지 않다.

필수 보완:

- child `stderr`도 같은 보호 경로로 pipe하거나 `--stderr=inherit|filter|drop` 모드를 제공하고 안전한 기본값을 둔다.
- inherit 모드를 유지한다면 경계를 명시 문서화한다.
- stderr filtering 또는 기본 동작 테스트를 추가한다.

릴리스 판단: 다음 publish 전 수정 또는 명시 문서화 권장.

### P2-CR-007: Init 시 기존 키 파일 미검증

상태: Open  
영향 코드: `packages/crypto/index.mjs`의 `initLocalKeyFile()`  
증거:

- 기존 key-file 경로는 active/retired key가 parse 및 사용 가능한지 검증하지 않고 성공을 반환한다.

영향:

`haechi init`이 손상됐지만 JSON으로는 읽히는 키 자료에 대해 성공을 보고할 수 있다. 사용자는 암호화, 복호화, token vault, bundle verification 시점에야 문제를 발견한다.

필수 보완:

- 기존 키 파일의 구조와 active key 사용 가능성을 검증한 뒤 성공을 반환한다.
- 유효한 기존 키에 대해서는 비파괴 동작을 유지한다.
- corrupted JSON, missing active key, wrong key length, valid retired-key migration 테스트를 추가한다.

릴리스 판단: 다음 publish 전 보완 권장.

### P2-CR-008: Satellite Packaging Check가 `manifest.bin` 누락을 놓침

상태: Open  
영향 코드: `scripts/check-satellite-packaging.mjs`  
증거:

- package check가 export 파일은 검증하지만 `manifest.bin`이 가리키는 executable file 존재를 증명하지 않는다.

영향:

satellite package가 로컬 packaging check를 통과해도 CLI entrypoint가 깨진 상태로 배포될 수 있다. auth/KMS/dashboard satellite가 늘어날수록 릴리스 품질 리스크가 커진다.

필수 보완:

- 모든 `manifest.bin` 값을 packed file list와 대조한다.
- 누락된 bin target negative fixture 테스트를 추가한다.

릴리스 판단: 다음 publish 전 보완 권장.

### P2-CR-009: Auth Provider 예외 경로 테스트 공백

상태: Open  
영향 코드: `packages/proxy/index.mjs` auth 처리, `tests/proxy-auth.test.mjs`  
증거:

- runtime은 `authProvider.authenticate()` 예외를 fail-closed `haechi_auth_provider_error`로 감싼다.
- 기존 테스트는 여러 auth 결과를 다루지만 provider exception을 직접 검증하지 않는다.

영향:

향후 auth-provider 변경이 raw error 유출, fail-open, audit status 불일치를 만들더라도 테스트가 잡지 못할 수 있다.

필수 보완:

- provider exception 회귀 테스트를 추가한다.
- fail-closed status, 일반화된 client response, audit event shape를 검증한다.

릴리스 판단: P0/P1 수정 이후에는 독립 릴리스 차단 항목은 아니다.

### P2-CR-010: Process-Isolated Sandbox Quota 테스트 공백

상태: Open  
영향 코드: `packages/plugin/process-sandbox.mjs`  
증거:

- oversized result 및 over-capacity 분기가 worker sandbox 테스트와 같은 수준으로 보장되지 않는다.

영향:

process isolation은 향후 plugin 작업의 보안 경계다. denial-of-service control 회귀 가능성을 줄이려면 worker sandbox와 동등한 테스트가 필요하다.

필수 보완:

- result-size excess, queue capacity, timeout, worker exit behavior에 대한 isolated-process 테스트를 추가한다.

릴리스 판단: 테스트 공백.

### P2-CR-011: Audit Chain 중간 변조 테스트 공백

상태: Open  
영향 코드: `packages/audit/index.mjs`의 `verifyAuditChain()`  
증거:

- 기존 커버리지가 middle-record tampering 분기를 직접 검증하지 않는다.

영향:

감사 무결성은 핵심 주장이다. chain verification 코드는 존재하지만 중간 레코드 변조, prev 누락, prev 불일치, hash 불일치를 거부한다는 테스트 증거가 필요하다.

필수 보완:

- middle-record content mutation, missing `prev`, wrong `prev`, wrong `integrity.hash` 테스트를 추가한다.
- tail truncation 한계는 계속 명시한다.

릴리스 판단: 테스트 공백.

### P2-CR-012: KMS Vault IPv6 Loopback 테스트 공백

상태: Open  
영향 코드: `satellites/crypto-kms/vault.mjs`  
증거:

- localhost carve-out 테스트가 현재 IPv4 loopback 중심이다.

영향:

vault guard는 보안 민감 경로이며 core SSRF guard와 URL parsing logic이 약간 다르다. 향후 불일치를 막으려면 IPv6 전용 테스트가 필요하다.

필수 보완:

- 의도된 vault policy에 따라 `::1`, `[::1]`, dotted IPv4-mapped IPv6, hex IPv4-mapped IPv6 테스트를 추가한다.

릴리스 판단: 테스트 공백.

### P2-CR-013: SSE Multi-Line `data:` Join Semantics

상태: Open  
영향 코드: `packages/stream-filter/index.mjs`  
증거:

- SSE parser가 여러 `data:` line을 `join("")`으로 합친다.
- SSE 처리 모델은 여러 data line을 newline separator로 결합한다.

영향:

정상 multi-line SSE event가 parsing 또는 inspection 전에 변형될 수 있다. false negative, false positive, malformed forwarded event를 만들 수 있다.

필수 보완:

- multi-line `data:` 값을 `\n`으로 합친다.
- multi-line JSON 및 multi-line plain-text event 테스트를 추가한다.

릴리스 판단: streaming 보완 묶음에서 함께 수정 권장.

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

