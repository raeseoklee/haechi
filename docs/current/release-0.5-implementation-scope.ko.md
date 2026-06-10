# Haechi 0.5 Implementation Scope

- 문서 상태: Final
- 작성일: 2026-06-10
- 기준 버전: 0.5.0 (0.4.0 이후)
- 성격: streaming hardening
- 구현 완료: 2026-06-10 — PR #14 (streaming inspection)

## 1. 릴리스 목표

streaming 보호 공백을 메운다: SSE/NDJSON 응답 stream을 차단하거나 무보호로 통과시키는 대신 직접 검사(inspect)한다. Streaming은 실제 LLM 사용에서 가장 흔한 전송 방식이므로 "streaming을 쓰면 보호를 포기해야 한다"는 구조가 핵심 잔여 취약점이었다.

## 2. 범위

### 2.1 Streaming 응답 검사

- 새 `streaming.requestMode: "inspect"` (`block` 및 `pass-through`와 병존).
- `packages/stream-filter`: 두 가지 wire format에 대한 점진적 frame parser — SSE (`data: …\n\n`)와 NDJSON (`{…}\n`). `[DONE]`, keep-alive comment, 비-JSON frame은 원문 그대로 통과한다.
- 각 protocol-adapter streaming 라우트는 `{ format, deltaPath }` — 주 점진적 텍스트 채널 — 을 선언한다.
  - OpenAI-compatible / vLLM / llama.cpp chat-completions: SSE, `choices[0].delta.content`
  - completions: SSE, `choices[0].text`
  - llama.cpp `/completion`: SSE, `content`
  - Ollama `/api/chat`: NDJSON, `message.content`
  - Ollama `/api/generate`: NDJSON, `response`
  - OpenAI `/v1/responses`: SSE, 고정 delta path 없음 (frame 전체 보호만)

### 2.2 Cross-frame 정확성 (sliding buffer)

Stream으로 전송된 바이트는 회수할 수 없으므로 탐지는 값이 방출되기 전에 이루어져야 한다. `core`에 `createStreamProtector`가 추가된다. 이 상태 유지(stateful) protector는 다음과 같이 동작한다.

- delta 채널의 bounded **raw tail**을 보관한다. push가 들어올 때마다 누적된 pending 텍스트에 대해 탐지를 수행하고, `len - maxMatchBytes`를 commit point로 계산하며, 이를 가로지르는 탐지가 발생하기 전에 commit point를 후퇴시킨다. committed prefix만 변환하여 방출하고 tail은 다음 frame을 위해 보관한다.
- stream 끝에서 보관 중인 tail을 합성된 최종 frame으로 flush한다.
- frame의 그 밖의 모든 문자열 리프(tool-call argument 등)에 대해 `protectFrameExtras`를 실행하며, within-frame 보호를 적용한다.
- `streaming.maxMatchBytes` (기본값 256)는 **보장 범위의 경계**다: window보다 긴 단일 match는 여전히 frame 사이에서 분할될 수 있다. 문서화된 한계 사항.

### 2.3 Enforcement와 audit

- Streaming 호출의 request body는 일반 JSON이며 포워딩 전에 일반 요청과 동일하게 보호된다.
- `block` action은 문제가 되는 값이 방출되기 전에 stream을 중단한다(buffer에 보관 중이며 commit되지 않은 상태). 연결은 종료된다. 이미 방출된 바이트는 회수할 수 없다 — streaming의 문서화된 한계.
- stream 전체에 대해 한 번 audit 기록: `stream_inspected` 또는 `stream_blocked`, 집계 탐지 횟수만 기록(평문 없음). `identity: null`은 다른 곳과 동일하게 예약.
- 새 `streaming.responseMode` (`dry-run` | `report-only` | `enforce`, 기본값 `enforce`)로 응답 방향 enforcement 모드를 독립적으로 제어한다.

### 2.4 Adapter 라우팅 수정

특정 `target.type` (`ollama`, `vllm-openai`, `llama-cpp`)이 이제 deep-merge된 기본 `target.adapter` (`openai-compatible`)보다 우선된다. 기존에는 `target.type: "ollama"`만 설정한 config가 기본 adapter가 merge 후에도 살아남아 OpenAI 경로로 조용히 라우팅되었다 — 이로 인해 streaming 분류도 무력화되었다.

## 3. 명시적 비범위 (0.5에서 하지 않음)

- Stream sequence AAD 및 replay cache (보류; encryption-on-stream 필요 시점에 해당).
- Per-choice (`n > 1`) cross-frame buffering — secondary choice는 within-frame 보호만 적용.
- Stream 내부의 base64/인코딩 값 디코딩 (비-streaming과 동일한 제외 항목).
- MCP의 양방향 streaming (stdio filter는 line-framed JSON-RPC로 이미 처리됨).

## 4. 테스트 기준

- Within-frame 및 cross-frame (byte 단위 분할 포함) PII를 SSE와 NDJSON 모두에서 탐지.
- `[DONE]` / keep-alive / 비-JSON frame 보존.
- delta 외 PII (tool-call argument) within-frame 보호.
- `block`은 값 방출 전에 stream 중단; `report-only`는 변환 없이 탐지.
- Proxy e2e: 요청 보호, 응답 stream-filter, audit chain 유효, audit에 평문 없음.
- `inspect` 하에서 검사 불가 라우트는 fail-closed (501).
- `requestMode: inspect`, `responseMode`, `maxMatchBytes`에 대한 config 검증.

## 5. 문서 영향

- README: streaming inspection 섹션, config 참조 행, `configuration.md` 업데이트.
- threat-model: streaming이 "검사 불가, 차단됨"에서 "검사됨(bounded)"으로 이동; `maxMatchBytes` 한계와 block 시 방출된 바이트 한계를 문서화된 제외 항목으로 기재.
- risk-register: 0.5.0 백로그 행 완료 처리.
- api-stability: `haechi/stream-filter`와 `createStreamProtector`를 experimental로 표기.
