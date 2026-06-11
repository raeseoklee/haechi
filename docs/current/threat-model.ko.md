# Haechi Threat Model

- 문서 상태: Draft 0.1
- 작성일: 2026-06-10
- 기준 버전: 0.7.0

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

## 5. 남은 운영 전제

운영 사용자는 Haechi 외부에서 네트워크 접근 제어, upstream 인증, secret injection, key custody, 로그 보존, DSAR/삭제 요청 처리, 법적 transfer 근거를 책임져야 한다.
