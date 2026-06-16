# 2026-06-16 코드리뷰 리스크 등록부 — Round 2 (CR2)

상태: open 보완 등록부(1.3.2 대상)  
범위: `main`의 `36af9fd1eef2b1e19b19b2e0344faab0a7a3e83d`(post-1.3.1)  
검토일: 2026-06-16  
출처: 1.3.1 보완 컷 이후 진행한 2차 심층 리뷰, 각 항목을 현재 코드에 대해 적대적으로 검증

이 문서는 `code-review-risk-register-2026-06-16.md`(round 1, 모두 Resolved이며 1.3.1로 발행)와 분리해 둔 **2차 라운드**다. round 1은 threat model과 코드가 인용하는 frozen resolution 기록이다. Round 2는 1.3.1 이후 제기되어 현재 트리에 대해 재검증된 항목을 담는다. 일부는 round-1 주장을 확장하거나 한정하므로, frozen 기록에 되쓰지 않고 상호 참조한다.

## 릴리스 판단

round-1 P0/P1은 모두 Resolved이며 `haechi@1.3.1`로 발행되었다. Round 2는 **P0도 P1도 발견하지 못했다**: 외부 리뷰에서 P1로 제기된 두 항목은 모두 검증 결과 **P2**로 내려갔다(둘 다 stored-plaintext leak도, auth/SSRF 우회도 아니다). 확인된 P2는 프록시 데이터 경로의 availability/resource leak, 호출자 제공 입력을 반영하는 audit-hygiene 공백, 그리고 무제한 plugin IPC reply다. 이들은 발행된 `1.3.1`에 대한 비상사태는 아니지만, **G10** 하에서 **1.3.2** 컷을 게이팅한다: 새 릴리스 태그 / npm publish는 CR2 P2 항목이 Resolved될 때까지 대기한다(1.3.2 컷이 그것들을 해결하는 수단이다).

## 심각도 기준

- `P0`: 신뢰 경계를 넘어가는 직접적인 자격증명/데이터 유출, 또는 핵심 보안 약속을 깨는 우회.
- `P1`: SSRF, 보호 우회, 서비스 거부, 보호 배포를 깨뜨릴 수 있는 프로토콜 동작.
- `P2`: 넓은 채택 전 해결해야 하는 운영, 정확성, availability, hygiene 공백.
- `P3`: 영향이 작은 하드닝, 유한 경계 robustness, 또는 문서 정확성.

## 검증 노트

아래 모든 항목은 독립 리뷰어가 보고자 진술을 그대로 믿지 않고 현재 코드에 대해 추적했다. 보고된 P1 두 건은 검증 후 P2로 하향됐다(부풀림 없음). 보고된 한 항목은 **false positive**였고 한 항목은 **이미 문서화된 수용 잔여 리스크**였다 — 둘 다 audit trail을 위해 여기 기록하며 코드 변경은 필요 없다.

## 요약

| ID | 심각도 | 영역 | 리스크 | 상태 |
| --- | --- | --- | --- | --- |
| CR2-001 | P2 | 프록시 availability | pass-through streaming이 downstream 클라이언트 disconnect 시 upstream reader를 절대 취소하지 않는다 — `await once(response,"drain")`이 영원히 park되어 upstream connection/task가 leak되고, 인증되지 않은 클라이언트가 반복적으로 disconnect해 dangling upstream connection을 누적할 수 있다. | Open |
| CR2-002 | P2 | audit hygiene | token-vault reveal/purge 실패가 호출자 제공 raw `token`과 `error.message`(token을 interpolate함)를 audit event에 기록한다; `FORBIDDEN_KEYS`는 key 이름으로만 제거하므로, `tok_` id가 기대되는 자리에 secret을 넘기면 hash-chained 로그에 raw로 남는다. stored vault plaintext가 아니라 호출자 입력을 반영한다. | Open |
| CR2-003 | P2 | plugin sandbox DoS | `maxMessageBytes`는 host→plugin credential 메시지만 제한한다; plugin→host reply는 무제한으로 수신·`JSON.parse`된다. process-isolated child에 heap cap이 없어, 적대적/버그 있는 signed plugin이 oversized reply를 반환 → host의 동기 parse가 event loop를 정지시키고 메모리가 급증한다. | Open |
| CR2-004 | P3 | 프록시 헤더 | `sanitizeResponseHeaders`가 body가 변환됐을 때 body-coupled validator(`etag`/`content-md5`/`digest`/`last-modified`)를 유지해 stale 상태가 된다; 변경된 응답에 `cache-control: no-store`가 없다. | Open |
| CR2-005 | P3 | 프록시 robustness | `maxBytes`를 초과하는 body에 대해 `readBody`는 reject하지만 socket 읽기/teardown을 멈추지 않아, 업로드가 (유한한) Node `requestTimeout`까지 read-and-discard된다. | Open |
| CR2-006 | P3 | MCP wrap | `mcp-wrap --stderr filter`는 완성된 라인 단위로 보호하므로, 적대적 child가 의도적으로 newline에 걸쳐 분할한 secret은 anchored regex를 회피한다. 신뢰된 로컬 child의 진단 출력에 대한 라인 지향 필터링의 본질적 한계다; single-line secret은 잡히고 `--stderr drop`이 있다. 문서 전용. | Open |
| CR2-007 | P3 | Docs | README는 MCP wrap이 "stderr and exit codes pass through"라고 하지만, 기본값은 이제 `--stderr filter`다(round-1 P2-CR-006). | Open |
| CR2-008 | P3 | Docs | README의 streaming "split match" 주장이 범위 한정이 없다; cross-frame buffering은 JSON delta 채널에만 적용되며 임의의 non-JSON frame에는 적용되지 않는다. | Open |
| CR2-009 | — | plugin sandbox | (보고된 P2) `keyMaterial`이 base credential 메시지의 `maxMessageBytes` 검사 이후에 append된다. **FALSE POSITIVE:** `keyMaterial`은 운영자 통제이며 fetcher의 `maxBytes`로 hard-bound된다; 공격자 증폭 없음. 수정 불필요(선택적 cosmetic re-assert만). | Won't fix |
| CR2-010 | — | Streaming | (보고된 P2) 두 개의 NON-JSON SSE/NDJSON frame에 걸쳐 분할된 secret은 잡히지 않는다(per-frame 검사). **수용 잔여 리스크 — 이미 문서화됨**: round-1 P1-CR-005 resolution, `threat-model.md` exclusions, 그리고 in-code comment. 변경 없음. | Accepted |

## 상세 항목

### CR2-001: downstream disconnect 시 upstream reader 미취소

심각도: P2(가장 시급한 CR2 항목)  
상태: Open  
영향 코드: `packages/proxy/index.mjs`의 `pipeUpstreamBodyBounded` / `forward`  
검증: pass-through streaming 경로에는 클라이언트 연결의 `close`/`aborted` listener가 없다; 클라이언트 socket이 죽은 뒤 `await once(response, "drain")`이 무기한 park된다(`drain`도 `error`도 발생하지 않음). 그래서 async task와 upstream connection이 leak된다. 전제 조건 없이 **인증되지 않은** 클라이언트가 도달 가능하다; 스트림 도중 반복 disconnect는 프록시와 그 upstream LLM 엔드포인트에 대한 dangling upstream connection을 누적한다.

필수 보완: per-request `AbortController`를 `forward()`에 전달하고(upstream fetch를 abort) upstream reader를 취소하는 one-shot 클라이언트 `close`/`aborted` listener를 등록한다; `drain` 대기를 `close`와 race시켜 backpressure 대기가 disconnect 시 unpark되게 한다; no-backpressure `reader.read()` parked 케이스도 다룬다. 회귀 테스트: 스트림 도중 disconnect하고 reader가 즉시 취소되는지 / upstream이 abort되는지 단언.

### CR2-002: Token-Vault Reveal/Purge가 Raw Token + Error Text를 Audit에 기록

심각도: P2(보고된 P1에서 하향 — stored vault plaintext가 아니라 호출자 제공 입력을 반영함)  
상태: Open  
영향 코드: `packages/token-vault/index.mjs`(reveal/purge throw + record), `packages/audit/index.mjs`(`FORBIDDEN_KEYS` / `sanitizeAudit`)  
검증: reveal은 `Unknown token: ${token}` / `Token expired: ${token}`을 throw하고 catch가 `reason: error.message`를 기록한다; raw `token` 인자도 `reveal_failed`/`reveal_denied`/`purge`에 그대로 기록된다. `sanitizeAudit`는 key 이름으로 필터링하고 `FORBIDDEN_KEYS`는 `reason`도 `token`도 포함하지 않으므로, 둘 다 기록된 hash-chained 레코드로 살아남는다. 정상 흐름에서 `token` 인자는 비민감 `tok_<type>_<hash>` id이므로, 누출은 호출자/운영자가 token id가 기대되는 자리에 raw secret을 넘길 때만 발생한다 — 그래도 round-1 `P1-SEC-017`과 `threat-model.md`의 "no plaintext / keyed-HMAC only" 표현과 모순된다.

필수 보완: (1) 일반화된 오류 메시지(raw token interpolation 없음); (2) raw `token`을 그대로 기록하는 것을 중단 — reveal/purge 레코드 이전에 (`subjectHash`/`issuerHash`처럼) keyed-HMAC하거나 인자를 `tok_<type>_<hash>` 형태에 대해 검증하고 아니면 redact; (3) free-text `reason: error.message`를 enum `reasonCode`로 교체; (4) `reveal_failed`/`purge` event가 `reason`/`token`에 호출자 제공 raw token을 절대 포함하지 않는다는 회귀 테스트; 문서의 불변식 표현을 정합화.

### CR2-003: Plugin IPC Reply가 Size-Bound되지 않음; Process Child에 Heap Cap 없음

심각도: P2  
상태: Open  
영향 코드: `packages/plugin/sandbox.mjs`, `packages/plugin/process-sandbox.mjs`, `packages/cli/runtime.mjs`  
검증: `maxMessageBytes`는 outbound host→plugin credential 메시지에만 강제된다; inbound reply는 두 sandbox 모두에서 size 검사 없이 수신·`JSON.parse`된다. worker에는 암묵적 경계가 있지만(필수 `resourceLimits` heap cap이 폭주 worker를 먼저 OOM시킴), process child는 `--max-old-space-size`를 설정하지 않으므로, 적대적/버그 있는 signed plugin이 child의 기본 V8 heap까지 reply를 만들어 `process.send`할 수 있고, host의 동기 `JSON.parse`가 event loop를 정지시킨다(per-call timeout이 parse 도중 발생할 수 없음). signed/semi-trusted-but-hostile plugin이 필요하다.

필수 보완: 두 sandbox 모두에서 parse 이전에 reply를 경계화한다(worker/child `message` 핸들러에서 byte length를 `maxMessageBytes` 또는 전용 `maxReplyBytes`와 대조하고, oversized를 `JSON.parse` 이전에 deny로 drop); 새 `resourceLimits`/`processMaxOldGenerationSizeMb` knob에서 파생한 `--max-old-space-size`로 process child에 heap cap을 부여한다. 회귀 테스트: oversized claims 객체를 반환하는 fixture plugin → 무제한 host 작업 없이 deny. 1.0/1.1 scope 문서에 경계가 BOTH 방향에 적용됨을 명시.

### CR2-004: 변환된 응답의 Stale Body-Coupled Validator 헤더

심각도: P3  
상태: Open  
영향 코드: `packages/proxy/index.mjs`의 `sanitizeResponseHeaders` / `transformedJsonHeaders`  
검증: hop-by-hop 헤더만 제거된다; `protectJson`이 body를 변경·재직렬화할 때 upstream `etag`/`content-md5`/`digest`/`last-modified`가 그대로 살아남고 `cache-control: no-store`가 설정되지 않는다. 문서화된 inference-upstream 타깃 집합(POST 응답, strong validator 없음, RFC 9111상 기본 비캐시; `content-length`는 재계산됨)에서는 실세계 영향이 작지만, 수용 잔여 리스크로 기록되어 있지 않다.

필수 보완: 모든 body-mutating 경로의 drop 집합에 `etag`/`content-md5`/`digest`/`last-modified`를 추가한다; 변환된 응답에 `cache-control: no-store`를 설정한다. 테스트: 변경된 응답이 upstream `ETag`를 더 이상 담지 않음.

### CR2-005: 한도 초과 Request Body가 Drain/Teardown되지 않음

심각도: P3  
상태: Open  
영향 코드: `packages/proxy/index.mjs`의 `readBody`  
검증: `maxBytes` 초과 시 `readBody`는 플래그를 세우고 reject하지만 request를 `pause()`/`destroy()`하지 않으며, 413 응답이 `Connection: close`를 보내지 않으므로 Node가 built-in `requestTimeout`(Node ≥22 기본 300000 ms)까지 업로드의 나머지를 read-and-discard한다. hold는 유한하다; `maxInFlight: 0`(기본값)은 동시에 hold되는 connection 수를 경계화하지 않는다.

필수 보완: 413 시 `request.pause()`/`request.destroy()`(또는 응답 이전에 `Connection: close`)로 socket을 즉시 해제한다. 낮은 우선순위: non-null 기본 `requestTimeoutMs`/`headersTimeoutMs`를 출하하고 `maxInFlight: 0`이 동시성을 무제한으로 둔다는 점을 문서화.

### CR2-006: mcp-wrap `--stderr filter`가 Newline-Split Secret을 잡지 못함

심각도: P3(doc)  
상태: Open  
영향 코드: `packages/cli/bin/haechi.mjs`의 `pipeFilteredStderr` / `protectStderrLine`  
검증: `filter`는 child stderr를 `\n`으로 분할하고 매 완성된 라인을 fresh single-shot protector로 보호하므로, 적대적 child가 의도적으로 newline에 걸쳐 분할 방출한 secret은 anchored full-secret regex를 회피한다. 좁은 범위: child는 운영자의 신뢰된 로컬 MCP server이고, single-line secret은 잡히며, `--stderr drop`이 있다. 이것은 라인 지향 텍스트 필터링의 본질적 속성이지 request/response 보호 경로의 익스플로잇 가능한 우회가 아니다.

필수 보완(doc): `COMMAND_HELP`와 이 등록부에 `filter`가 완성된 라인 단위로 보호하며 newline에 걸쳐 분할된 secret을 잡지 못한다는 한 문장을 명시; 고민감 도구에는 `--stderr drop`을 권장. 선택적 후속 코드 하드닝: stderr를 per-line `protectText` 대신 push/flush sliding-buffer 채널(`maxMatchBytes`)로 라우팅.

### CR2-007: README mcp-wrap stderr Passthrough가 Stale

심각도: P3(doc)  
상태: Open  
영향 코드: `README.md`  
검증: README는 "stderr and exit codes pass through"라고 하지만, 기본값은 이제 `--stderr filter`다(round-1 P2-CR-006); raw passthrough는 opt-in `inherit` 모드뿐이다. exit code는 실제로 pass through되므로 stderr 절만 stale하다; `COMMAND_HELP`는 이미 정확하다.

필수 보완(doc): README 줄을 `filter` 기본값을 반영하도록 수정(`inherit`은 raw, `drop`은 폐기; `filter`는 `policy.mode: enforce`에서만 변환); `README.ko.md` sibling 갱신.

### CR2-008: README Streaming Split-Match 주장이 범위 한정 없음

심각도: P3(doc)  
상태: Open  
영향 코드: `README.md`  
검증: README는 frame에 걸쳐 분할된 PII가 잡힌다고 주장하면서 이를 JSON delta 채널로 한정하지 않는다; non-JSON CONTENT frame은 single-shot per-frame `protectText`를 받는다(cross-frame buffer 없음). 이 주장은 `threat-model.md`와 scope 문서 대비 보장을 과장한다.

필수 보완(doc): README 두 구절을 모두 delta 채널로 한정(`maxMatchBytes`까지 frame에 걸쳐 분할된 delta-text PII; non-delta leaf와 non-JSON frame은 within-frame 검사); `README.ko.md` 갱신.

### CR2-009: maxMessageBytes 검사 이후의 keyMaterial — FALSE POSITIVE

심각도: —(보고된 P2; 취약점이 아님으로 검증)  
상태: Won't fix  
영향 코드: `packages/plugin/process-sandbox.mjs`, `packages/cli/runtime.mjs`  
검증: 구조적 관찰(`keyMaterial` append 이후 결합 메시지가 재검사되지 않음)은 정확하지만, 공격자가 익스플로잇할 수 없다. `keyMaterial`은 운영자 통제이고(host가 운영자 선언 HTTPS URL에서 fetch, TTL 캐시, 공격자 영향 credential과 독립) guarded fetcher의 `maxBytes`(기본 1 MiB)로 hard-bound된다; credential은 base 검사로 경계가 유지된다. 결합 wire는 두 운영자 설정 상수로 경계화되며 공격자 증폭이 없다; "`maxBytes`를 임의로 크게"는 운영자 자체 오설정이다. 선택적 cosmetic defense-in-depth만 가능(결합 size re-assert); 보안 수정 불필요.

### CR2-010: Non-JSON Cross-Frame Split — 수용 잔여 리스크(문서화됨)

심각도: —(보고된 P2; 이미 문서화된 잔여 리스크)  
상태: Accepted  
영향 코드: `packages/core/index.mjs` / `packages/stream-filter/index.mjs`  
검증: 1.3.1에서 실재한다(non-JSON CONTENT frame은 cross-frame buffer 없이 per-frame `protectText`를 받음). 하지만 round-1 `P1-CR-005` resolution, `threat-model.md` exclusions, in-code comment에 범위 외로 명시 문서화되어 있다. JSON delta 채널은 `maxMatchBytes`까지 cross-frame buffering을 한다. 코드 변경 불필요; 기껏해야 문서 다듬기 차원의 sibling exclusion 항목(CR2-008의 README scoping에 흡수).

## 보완 순서

1. `CR2-001`을 최우선으로 — 전제 조건 없이 인증되지 않은 클라이언트가 도달 가능한 유일한 항목(availability).
2. `CR2-002`와 `CR2-003`을 병렬로 — 파일이 disjoint하다(token-vault+audit vs plugin sandbox).
3. `CR2-004` + `CR2-005`를 함께(둘 다 `proxy/index.mjs`; CR2-001 이후 / 그 위에 rebase해 착륙).
4. `CR2-006` + `CR2-007` + `CR2-008` — 문서/help-text 묶음, 아무 때나.
5. `CR2-009` / `CR2-010`은 코드 변경 불필요(audit trail용 기록).

## 종료 규칙

항목은 코드/문서 보완이 merge되고, 집중 회귀 테스트 또는 명시적 non-test rationale이 기록되며, 릴리스 게이트 등록부(`G10`)가 증거를 링크할 때만 `Resolved`로 옮긴다. 1.3.2 컷이 resolved 항목과 `G10`을 함께 뒤집는다.

## 추적 링크

`docs/current/risk-register-release-gate.md`(§5.8 + `G10`)와 `docs/current/risk-register-release-gate.ko.md`에서 참조한다.
