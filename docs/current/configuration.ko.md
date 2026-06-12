# Haechi 설정 레퍼런스

- 문서 상태: Living document(core 1.2.x 추적)

`haechi init`은 `haechi.config.json`을 생성하며, 비밀 정보를 포함하지 않는 템플릿은 `haechi.config.example.json`에 있습니다. 모든 커맨드는 `--config <path>`로 설정 파일을 읽습니다(기본값: `haechi.config.json`). 설정은 **fail-closed 방식으로 검증**됩니다. 알 수 없는 provider, 범위를 벗어난 숫자, 잘못된 형식의 값은 자동으로 무시되지 않고 로드 시점에 오류를 발생시킵니다. `haechi config`는 이 레퍼런스를 출력하며, `haechi status`는 특정 설정 파일의 *실제 적용* 상태를 출력합니다.

## 전체 기본값

```json
{
  "configVersion": 1,
  "mode": "dry-run",
  "target": { "type": "llm-http", "adapter": "openai-compatible", "upstream": "http://127.0.0.1:9999" },
  "proxy": { "host": "127.0.0.1", "port": 11016, "tls": null, "trustForwardedProto": false },
  "responseProtection": { "enabled": false, "mode": "enforce", "failureMode": "fail-closed", "allowNonJson": false, "allowCompressed": false, "maxBytes": 1048576 },
  "streaming": { "requestMode": "block" },
  "limits": { "maxRequestBytes": 1048576, "upstreamTimeoutMs": 120000, "maxNestingDepth": 256, "maxInFlight": 0, "shutdownGraceMs": 10000, "requestTimeoutMs": null, "headersTimeoutMs": null },
  "policy": { "mode": "dry-run", "presets": ["korean-pii", "secrets-only", "llm-redact"], "defaultAction": "redact", "actions": { "card": "block" } },
  "filters": { "customRules": [] },
  "keys": { "provider": "local", "keyFile": ".haechi/dev.keys.json" },
  "audit": { "sink": "jsonl", "path": ".haechi/audit.jsonl" },
  "tokenVault": { "provider": "local", "path": ".haechi/token-vault.json", "revealPolicy": "disabled", "retentionDays": 30, "deterministic": false, "deterministicTypes": null, "detokenizeResponses": false },
  "privacy": { "profile": null },
  "logging": { "format": "text" },
  "metrics": { "enabled": true },
  "mcp": { "allowedMethods": ["initialize", "tools/call", "resources/read", "prompts/get"], "protectParams": true, "protectResults": true, "requireJsonRpc": true }
}
```

## 최상위

| 키 | 타입 / 값 | 기본값 | 설명 |
|---|---|---|---|
| `configVersion` | 양의 정수 | `1` | 설정 스키마 버전 스탬프입니다. 값이 없으면 현재 버전으로 간주합니다. 이 빌드가 이해하는 값보다 **더 높은** 값은 로드 시 **fail-closed**로 실패하며, 양수 정수가 아닌 값은 오류를 발생시킵니다. [`config-version.md`](./config-version.md)를 참고하십시오. |
| `mode` | `dry-run` \| `report-only` \| `enforce` | `dry-run` | 전역 집행 모드입니다. `dry-run`/`report-only`는 탐지와 audit만 수행하며, `enforce`는 변환/차단을 적용합니다. `policy.mode`가 설정된 경우 해당 값이 우선합니다. |

## `target`

| 키 | 타입 / 값 | 기본값 | 설명 |
|---|---|---|---|
| `target.type` | `llm-http` \| `openai-compatible` \| `vllm-openai` \| `ollama` \| `llama-cpp` | `llm-http` | 프로토콜 adapter를 선택합니다. `llm-http`는 `openai-compatible`의 별칭입니다. 알 수 없는 값은 로드 시 **fail-closed**로 처리됩니다. |
| `target.adapter` | 동일한 값 집합 | `openai-compatible` | adapter를 명시적으로 지정합니다. 보통은 설정하지 않고 `type`이 결정하도록 두면 됩니다. |
| `target.upstream` | URL 문자열 | `http://127.0.0.1:9999` | proxy가 요청을 전달하는 유일한 upstream입니다. 요청 대상은 origin-form 경로여야 하며, 절대 URL 대상은 거부됩니다(SSRF 방어). |

## `proxy`

| 키 | 타입 / 값 | 기본값 | 설명 |
|---|---|---|---|
| `proxy.host` | 비어 있지 않은 문자열 | `127.0.0.1` | 바인드 주소입니다. loopback이 아닌 host를 사용하려면 `--allow-remote-bind` CLI 플래그가 필요합니다. 설정 파일만으로는 시작되지 않습니다([loopback 밖으로 바인딩](#binding-beyond-loopback) 참고). |
| `proxy.port` | 정수 0–65535 | `11016` | 리슨 포트입니다(`0` = 임시 포트). `--port`로 실행할 때마다 덮어쓸 수 있습니다. |
| `proxy.tls` | `null` 또는 `{ keyFile, certFile }` / `{ pfxFile, passphrase? }` | `null` | 기동 시 **파일 경로**에서 읽어들이는 TLS 자료입니다. 설정되면 Haechi가 직접 TLS를 종단합니다(`https` 제공). remote bind에는 `trustForwardedProto`와 함께 둘 중 하나가 필요합니다([loopback 밖으로 바인딩](#binding-beyond-loopback) 참고). fail-closed: non-null이지만 사용 가능한 자료 `((key && cert) 또는 pfx)`로 해석되지 않거나, `pfxFile`을 `keyFile`/`certFile`과 함께 쓰거나, 읽을 수 없는 파일을 지정하면 로드 시 throw합니다. |
| `proxy.trustForwardedProto` | boolean | `false` | **신뢰하는 reverse proxy가 Haechi 앞단에서 TLS를 종단함**을 운영자가 명시적으로 확인하는 값입니다. `true`이면 remote bind가 plain `http`로 유지될 수 있으나, Haechi는 **`X-Forwarded-Proto`가 `https`가 아닌 모든 요청을 거부**합니다(auth/body 이전에 검사하며, `/__haechi/*` liveness 라우트는 예외입니다). Haechi 자체가 인터넷에 직접 노출될 때는 실제 TLS를 대체하지 못합니다. |

## `responseProtection`

upstream JSON 응답을 검사합니다(기본적으로 꺼져 있습니다 — 모델로부터 *돌아오는* 내용을 보호하려면 활성화하세요).

| 키 | 타입 / 값 | 기본값 | 설명 |
|---|---|---|---|
| `responseProtection.enabled` | boolean | `false` | 마스터 스위치입니다. `detokenizeResponses`가 작동하려면 반드시 활성화되어 있어야 합니다. |
| `responseProtection.mode` | `dry-run` \| `report-only` \| `enforce` | `enforce` | 응답 방향의 집행 모드입니다. **실제 LLM upstream에는 `report-only`를 권장합니다.** envelope 메타데이터(id, unix 타임스탬프 `created`, 긴 숫자 필드)가 PII/secret 모양으로 보일 수 있어, `enforce`이면 정상 완성 응답을 502로 막습니다. `report-only`에서도 탐지·감사·`detokenizeResponses`는 그대로 동작합니다. (Haechi는 응답에서 자체 `[TOKEN:…]`/`[HAECHI_ENC:…]` 마커를 제외하고, phone 규칙도 맨 타임스탬프를 무시하며, 응답의 bare JSON number leaf는 검사하지 않으므로 실제 vLLM/Ollama 응답은 clean합니다. 응답 *텍스트*까지 검사하려면 `enforce`가 더 엄격합니다.) |
| `responseProtection.failureMode` | `fail-closed` \| `allow` | `fail-closed` | *검사 불가능한* 응답(비JSON, 잘못된 JSON, 압축)에 대한 처리 방식입니다. `fail-closed`는 502를 반환하고, `allow`는 통과시킵니다(audit에 기록됩니다). |
| `responseProtection.allowNonJson` | boolean | `false` | 비JSON 응답을 검사 없이 통과시킵니다. |
| `responseProtection.allowCompressed` | boolean | `false` | 압축 응답을 검사 없이 통과시킵니다. |
| `responseProtection.maxBytes` | 양의 정수 | `1048576` | 응답 크기의 상한입니다. `failureMode: allow` 상태에서도 적용되며, 크기를 초과한 응답은 항상 거부됩니다. |
| `responseProtection.scanNumbers` | boolean | `false` | 응답의 **bare JSON number leaf**에 탐지를 돌릴지 여부입니다. 기본은 off입니다 — 응답 숫자는 추론서버 메타데이터(`*_duration`, count, timestamp)라 검사하면 `card`/`kr_rrn` 오탐만 발생합니다. 모델이 숫자 필드로 유출할 수 있다고 보는 엄격 위협모델에서만 `true`로 두며, `mode: report-only`와 함께 써서 차단 없이 감사만 하세요. 요청 방향은 항상 숫자를 검사합니다. |

## `streaming`

| 키 | 타입 / 값 | 기본값 | 설명 |
|---|---|---|---|
| `streaming.requestMode` | `block` \| `pass-through` \| `inspect` | `block` | `block`은 스트리밍 요청에 `501`을 반환합니다. `inspect`는 bounded cross-frame 버퍼로 SSE/NDJSON 응답을 stream-filter합니다. `pass-through`는 검사 없이 전달합니다(감사됩니다). Ollama의 `/api/chat`과 `/api/generate`는 `stream: false`가 명시되지 않으면 streaming으로 간주됩니다. |
| `streaming.responseMode` | `dry-run` \| `report-only` \| `enforce` | `enforce` | 검사된 스트림에 적용되는 집행 모드입니다(요청 방향과 독립적입니다). |
| `streaming.maxMatchBytes` | 양의 정수 | `256` | inspect 시 cross-frame 매칭 윈도우입니다. 이 크기의 tail을 보유하여 프레임에 걸친 탐지를 방출 전에 포착할 수 있습니다. 이 값보다 긴 단일 매칭은 프레임에 걸쳐 분할될 수 있습니다. |

## `limits`

| 키 | 타입 / 값 | 기본값 | 설명 |
|---|---|---|---|
| `limits.maxRequestBytes` | 양의 정수 | `1048576` | 요청 바디 크기 상한입니다. 초과 시 `413`을 반환합니다. 바디를 전부 버퍼링하지 않고 증분 방식으로 적용됩니다. |
| `limits.upstreamTimeoutMs` | 양의 정수 | `120000` | upstream 요청 타임아웃입니다. 만료 시 `504 haechi_upstream_timeout`을 반환합니다. 연결 실패 시에는 `502 haechi_upstream_unreachable`을 반환합니다. |
| `limits.maxNestingDepth` | 양의 정수 | `256` | 탐지 시 walk하는 JSON 최대 중첩 깊이입니다. 이보다 깊게 중첩된 바디는 `413 haechi_request_too_deeply_nested`로 거부되어(upstream 이전, fail-closed), 재귀적 payload walk를 스택 오버플로로부터 보호합니다. 컨테이너 하강을 제한하며, 한도에 있는 leaf는 여전히 검사됩니다. (별도로, 비UTF-8 요청 바디는 fail-closed로 거부됩니다: `400 haechi_request_body_not_utf8`.) |
| `limits.maxInFlight` | 음이 아닌 정수 | `0` | 전역 max-in-flight 백프레셔 상한입니다. `0`은 비활성화이며(상한 없음 — 1.1 동작), `> 0`이고 현재 in-flight 수가 상한에 도달하면 **새** 요청은 인증/바디 읽기 **이전에** `Retry-After` 헤더와 `{ "error": "haechi_overloaded" }`와 함께 `503`으로 거부됩니다. `/__haechi/*` 관측 라우트는 **예외**입니다(포화 상태에서도 liveness·metrics 스크레이프 가능). 거부마다 `haechi_overloaded_total`이 증가합니다. [운영 런북](./operations-runbook.md#5-backpressure-tuning)을 참고하십시오. |
| `limits.shutdownGraceMs` | 음이 아닌 정수(ms) | `10000` | 우아한 종료(graceful shutdown) 유예 기간입니다. `SIGINT`/`SIGTERM` 시 프록시는 새 연결 수락을 멈추고, idle keep-alive 소켓을 즉시 닫고, in-flight 요청이 빠질 때까지 기다린 뒤, 이 유예가 지나면 남은 소켓을 강제 종료하여 멈춘 keep-alive가 종료를 무한정 붙잡지 못하게 합니다. 백프레셔 `Retry-After` 초 값의 기준이기도 합니다. 오케스트레이터의 종료 유예를 이 값보다 **크게** 설정하십시오. |
| `limits.requestTimeoutMs` | `null` \| 음이 아닌 정수(ms) | `null` | Node HTTP 서버의 `requestTimeout`에 매핑됩니다. `null`은 Node 기본값을 그대로 둡니다(동작 불변). 느린 전체 요청 전달을 제한하려면 숫자를 설정하고, `0`은 타임아웃 비활성화입니다(Node 의미). |
| `limits.headersTimeoutMs` | `null` \| 음이 아닌 정수(ms) | `null` | Node HTTP 서버의 `headersTimeout`에 매핑됩니다. `null`은 Node 기본값을 그대로 둡니다. 느린 헤더 전달(slow-loris)을 제한하려면 숫자를 설정하고, `0`은 비활성화입니다. |

## `policy`

탐지→결정의 핵심입니다. [Detection type과 action](#detection-types--actions)을 참고하세요.

| 키 | 타입 / 값 | 기본값 | 설명 |
|---|---|---|---|
| `policy.mode` | `dry-run` \| `report-only` \| `enforce` | `dry-run` | 실제 적용되는 집행 모드입니다(`policy.mode ?? mode`). |
| `policy.presets` | preset 이름 배열 | `["korean-pii", "secrets-only", "llm-redact"]` | 순서대로 병합되는 내장 action 집합입니다. [Presets](#presets)를 참고하세요. |
| `policy.defaultAction` | action | `redact` | 명시적 매핑이 없는 탐지 type에 적용되는 action입니다. |
| `policy.actions` | `{ <type>: <action> }` | `{ "card": "block" }` | type별 개별 재정의입니다. 병합 시 **강화**는 가능하지만 약화는 불가합니다([Action strength](#action-strength) 참고). `injection`은 설정하지 않으면 기본적으로 `allow`입니다. |
| `policy.allowUnsafeOverrides` | boolean | `false` | 더 약한 action이 더 강한 action을 덮어쓰는 것을 허용합니다. 기본적으로 꺼져 있으며, 활성화하면 안전 장치가 제거됩니다. |
| `policy.bundlePath` | 경로 | 미설정 | 인라인 정책 대신 서명된 policy bundle을 로드합니다(`keys.keyFile`에 대해 검증됩니다). |

## `filters`

| 키 | 타입 / 값 | 기본값 | 설명 |
|---|---|---|---|
| `filters.customRules` | 규칙 객체 배열 | `[]` | 추가 탐지 규칙입니다: `{ id, type, pattern, flags?, confidence? }`. 패턴은 ReDoS 검사를 통과해야 하며(≤500자, 중첩 한정자 없음, 역참조 없음), 안전하지 않으면 로드 시 거부됩니다. |
| `filters.minConfidence` | `[0, 1]` 범위의 숫자 | `0` | 정밀도 다이얼입니다. 각 규칙은 `confidence`(0.6~0.95)를 가지며, confidence가 이 임계값 **미만**인 탐지는 policy 결정 전에 버려집니다. 기본값 `0`은 아무것도 게이트하지 않아 기존 동작을 보존합니다. **하드 블록 예외:** 하드 블록 타입(`secret`, `api_key`, `kr_rrn`, `card`)은 confidence만으로는 **절대** 버려지지 않습니다 — `minConfidence`는 정밀도 위험이 큰 소프트 타입(예: `phone`, `email`, `injection`)만 다듬으므로, confidence가 낮은 자격증명/PII 누출도 여전히 조치됩니다(fail-closed). |
| `filters.allowlist` | 문자열 및/또는 `{ value?, path? }` 의 배열 | `[]` | 운영자 false-positive 예외입니다. 매칭된 **value**가 문자열/`value` 항목과 같거나, PII-safe JSON **path**(audit에 표시되는 해시된 `pathText`)가 `path` 항목과 같은 탐지는 policy 결정 전에 억제됩니다(항목이 `value`와 `path`를 모두 설정하면 **둘 다** 일치해야 합니다). **하드 블록 예외:** 하드 블록 타입(`secret`/`api_key`/`kr_rrn`/`card`)을 억제하려는 항목은 **무시되며** 탐지는 그대로 발생합니다 — allowlist는 양성(benign) **소프트 타입** FP만 정리할 수 있고, 자격증명/PII 누출은 절대 침묵시킬 수 없습니다. 모든 억제와 모든 `minConfidence` 드롭은 개수와 타입으로 **감사 로그에 기록됩니다**(`summary.suppressedByType` / `summary.droppedByType` / `suppressedCount` / `droppedCount`) — 원시 값은 절대 기록하지 않습니다. 규칙 전체를 삭제하지 않고 양성 FP 하나만 정리할 때 사용하십시오. |

### 탐지 벤치마크

탐지 정밀도(precision)/재현율(recall)은 가정하지 않고 측정합니다. 합성 테스트 픽스처로 구성된 라벨링 코퍼스(`tests/fixtures/detection-corpus.json` — type별 양성 샘플과 양성처럼 보이는 hard-negative)를 기반으로 type별 채점기를 돌립니다.

```bash
npm run bench:detection   # type별 TP/FP/FN + precision/recall 표를 출력합니다
npm run scan:detection    # CI 회귀 게이트: 어떤 type이라도 baseline 아래로 떨어지면 실패합니다
```

`bench:detection`(`scripts/bench-detection.mjs`)은 기본 필터 엔진을 각 코퍼스 케이스에 적용하여 type별 true/false positive와 false negative를 보고합니다. `scan:detection`은 실측 점수를 고정된 baseline(`scripts/detection-baseline.json`)과 비교하며 **회귀일 때만 실패합니다** — 즉 precision 또는 recall이 기록된 수치 아래로 떨어진 경우입니다. baseline에는 현재의 불완전한 상태(`phone`/`card`/`secret`에서 audit이 재현한 오탐, 그리고 AWS/GitHub/Google/Slack 키·JWT·PEM 헤더에 대한 알려진 커버리지 공백 누락)가 의도적으로 포함되어 있으므로, 게이트는 오늘은 통과하고 변경이 탐지를 악화시킬 때만 실패합니다. 이 게이트는 `release:preflight`에서 doc-freshness 게이트 다음에 실행됩니다. 의도적인 규칙 변경 후에는 `node scripts/bench-detection.mjs --write-baseline`으로 baseline을 재생성하고 diff를 검토하십시오. 기록된 공백과 오탐을 닫는 작업은 reliability-hardening 트랙의 WS2b/WS2c입니다.

## `keys`

| 키 | 타입 / 값 | 기본값 | 설명 |
|---|---|---|---|
| `keys.provider` | `local` \| `external` | `local` | `local`은 소프트웨어 AES-256-GCM 키 파일을 사용합니다(개발 전용). `external`은 키 자료를 포함하지 않으며, `createRuntime(config, { cryptoProvider })`를 통해 crypto provider를 주입해야 합니다. |
| `keys.keyFile` | 경로 | `.haechi/dev.keys.json` | 로컬 키 파일입니다(모드 `0600`). `haechi init --force`는 키를 교체하며, 기존 키는 `kid`로 기존 암호문/token이 복호화 가능하도록 퇴역 상태로 보관됩니다. |

## `audit`

| 키 | 타입 / 값 | 기본값 | 설명 |
|---|---|---|---|
| `audit.sink` | `jsonl` | `jsonl` | `jsonl`만 지원됩니다. |
| `audit.path` | 경로 | `.haechi/audit.jsonl` | SHA-256 hash chain 로그입니다. `haechi audit-verify`로 검증합니다. 평문/PII를 포함하지 않습니다. |

## `tokenVault`

| 키 | 타입 / 값 | 기본값 | 설명 |
|---|---|---|---|
| `tokenVault.provider` | `local` | `local` | `local`만 지원됩니다. |
| `tokenVault.path` | 경로 | `.haechi/token-vault.json` | 암호화된 token 저장소입니다(원자적 쓰기, 파일 락). |
| `tokenVault.revealPolicy` | `disabled` \| `local-dev` | `disabled` | **수동** reveal(`token-reveal`)을 허용할지 결정합니다. 모든 reveal/purge 결정은 audit에 기록됩니다. detokenization과는 독립적입니다. |
| `tokenVault.retentionDays` | 양의 수 | `30` | Token TTL입니다. 만료된 token은 vault 쓰기 시 또는 `token-purge --expired`로 삭제됩니다. |
| `tokenVault.deterministic` | boolean | `false` | 동일한 `(type, value)` → 동일한 token입니다(도메인 분리된 파생 키로 HMAC합니다). 멀티턴에 필요합니다. **트레이드오프:** 동일한 값이 연결 가능해집니다. |
| `tokenVault.deterministicTypes` | `null` \| 비어 있지 않은 문자열 배열 | `null` | `null`이면 deterministic 활성화 시 모든 type에 적용됩니다. 그렇지 않으면 열거된 type에만 determinism을 제한합니다(예: `["email"]`). |
| `tokenVault.detokenizeResponses` | boolean | `false` | 해당 요청을 처리하며 발급한 token을 응답에서 복원합니다. 동일 요청을 보호하며 발급된 token만 복원되며, `responseProtection.enabled`가 필요합니다. 개수 단위로 audit에 기록됩니다. |

## `privacy`

| 키 | 타입 / 값 | 기본값 | 설명 |
|---|---|---|---|
| `privacy.profile` | `null` \| `kr-pipa` \| `eu-gdpr` \| `us-general` | `null` | 집행 전에 지역별 기준 action 집합을 적용합니다. 프로필은 명시적 action을 **강화**할 수는 있지만 약화할 수는 없습니다. 엔지니어링 기본값이며, 법적 자문이 아닙니다. |

## `logging`

| 키 | 타입 / 값 | 기본값 | 설명 |
|---|---|---|---|
| `logging.format` | `text` \| `json` | `text` | `text`는 사람이 읽는 기동/종료/오류 로그 줄을 그대로 유지합니다(변경 없음). `json`은 이벤트마다 한 줄짜리 JSON 객체를 출력합니다. fail-closed이며, 다른 값은 예외를 던집니다. |

`json` 모드에서 프록시 내부 오류 로그는 `{ "level": "error", "event": "proxy_internal_error", "correlationId", "errorName", "statusCode" }` 한 줄이며, 기동/종료는 `proxy_listening` / `proxy_shutdown`을 출력합니다(원격 바인드/비-enforce 모드/응답 보호 비활성화에 대한 `*_warn` 이벤트도 함께). **어떤 로그 필드도 요청/응답 페이로드, 헤더, 토큰, PII를 절대 담지 않습니다.** 오류 로그는 오류 *클래스 이름*과 요청 `correlationId`만 담습니다.

## `metrics`

| 키 | 타입 / 값 | 기본값 | 설명 |
|---|---|---|---|
| `metrics.enabled` | boolean | `true` | `GET /__haechi/metrics` 라우트를 제어합니다. `false`이면 해당 라우트는 `404`를 반환합니다. fail-closed이며, boolean이 아니면 예외를 던집니다. |

메트릭 수집기는 **주입 가능한 협력 객체**이기도 합니다(`createRuntime(config, { metrics })`). 계약과 no-PII 보장은 [운영 엔드포인트](#운영-엔드포인트)를 참고하십시오.

## 운영 엔드포인트

프록시는 예약된 `/__haechi/*` 접두어 아래에 네 개의 인증 없는 엔드포인트를 제공하며, 이들은 인증과 본문 읽기 **이전**에 처리되고 업스트림으로 프록시되지 않습니다.

| 엔드포인트 | 상태 코드 | 본문 | 용도 |
|---|---|---|---|
| `GET /__haechi/live` | `200` | `{ ok: true, version }` | 저비용 프로세스 liveness. |
| `GET /__haechi/ready` | `200` / `503` | `{ ready, version, checks }` | readiness. **fail-closed**: audit 로그에 append할 수 없는 게이트웨이는 ready가 **아닙니다**(`503`). 기본 JSONL sink의 `checks.auditWritable`는 이벤트를 쓰지 않고 audit 디렉터리/파일의 쓰기 가능 여부를 확인하며, `ready()`/`healthCheck()` 메서드가 없는 sink는 ready로 간주합니다. |
| `GET /__haechi/health` | `200` | `{ ok: true, mode, version }` | back-compat(기존 health 엔드포인트이며 이제 `version`을 포함). |
| `GET /__haechi/metrics` | `200` / `404` | Prometheus 텍스트 | 텔레메트리(아래 참고). `metrics.enabled: false`이면 `404`. |

`version`은 실행 중인 패키지 버전(`package.json`)입니다.

### 텔레메트리 (`/__haechi/metrics`)

이 엔드포인트는 **Prometheus 텍스트 노출 형식**(`# HELP` / `# TYPE` + `name{label="..."} value`)을 `Content-Type: text/plain`으로 렌더링합니다. 카운터: `haechi_requests_total{route,mode,decision}`와 `haechi_blocks_total`, `haechi_auth_denied_total`, `haechi_rate_limited_total`, `haechi_upstream_timeout_total`, `haechi_upstream_error_total`, `haechi_response_unprotected_total`, `haechi_internal_error_total`. 히스토그램 하나: `haechi_request_duration_seconds{route}`.

**텔레메트리 no-PII 불변식.** 모든 메트릭 이름과 **모든 라벨 값**은 경계가 정해진 enum입니다 — 라우트 id, 정책 모드, 고정된 decision 클래스(`forwarded` / `blocked` / `auth_denied` / `rate_limited` / `model_not_allowed` / …)입니다. 메트릭 라벨은 identity id/subject, 토큰, 탐지된 값을 **절대** 담지 않습니다. identity별·값별 라벨 카디널리티가 존재하지 않습니다. 이는 audit에 평문을 남기지 않는 불변식을 텔레메트리로 확장한 것이며, 메트릭 모듈은 방어적으로 라벨 값의 길이를 제한하고 문자셋을 정제합니다.

### `providers.metrics` 주입 seam

메트릭 수집기는 `createRuntime(config, providers)`를 통해 프로그램적으로 공급됩니다 — `cryptoProvider`/`authProvider`/`rateLimiter`와 동일한 seam이며, JSON 설정 키가 **아닙니다**.

```js
const runtime = createRuntime(config, { metrics });
```

주입된 `metrics`는 `increment(name, labels?, amount?)`, `observe(name, value, labels?)`, `render() -> string`을 구현해야 하며, 그렇지 않으면 `createRuntime`은 생성 시점에 fail-closed로 실패합니다. **기본값**은 위 Prometheus 텍스트를 렌더링하는 무의존성 인메모리 수집기입니다. 다중 레플리카 운영자는 동일한 계약을 만족하는 공유/원격 수집기를 주입합니다.

### `correlationId` (audit + 로그)

프록시는 요청마다 `correlationId`(UUID)를 생성합니다. 이 값은 protect 컨텍스트로 전달되어 한 요청의 request·response 방향 audit 이벤트가 동일한 추가(additive) 최상위 `correlationId` 필드를 갖게 하며, 프록시 내부 오류 로그 줄에도 전달되어 운영자가 기록된 오류를 그 audit 추적과 연결할 수 있게 합니다. 프록시가 아닌 `protectJson()` 호출에서는 `null`입니다(기존 동작 보존). 이 id는 UUID이며 페이로드/identity/PII 값을 **절대** 담지 않습니다.

## 환경변수 설정 오버레이 (배포)

컨테이너 / 12-factor 배포를 위해, **비밀이 아닌 운영 키의 고정 allowlist**를 환경변수로 덮어쓸 수 있습니다. 환경변수 값은 **설정 파일보다 우선**하며 **fail-closed**로 검증됩니다 — 잘못된 값은 프로세스를 기동 실패시킵니다. `loadConfig()`에서 파일을 읽은 뒤 검증 이전에 적용됩니다.

| 환경변수 | 설정 키 | 타입 / 값 |
|---|---|---|
| `HAECHI_PROXY_PORT` | `proxy.port` | 정수 0–65535 |
| `HAECHI_PROXY_HOST` | `proxy.host` | 비어 있지 않은 문자열 |
| `HAECHI_UPSTREAM` | `target.upstream` | URL 문자열 |
| `HAECHI_MODE` | `mode` | `dry-run` \| `report-only` \| `enforce` |
| `HAECHI_LOG_FORMAT` | `logging.format` | `text` \| `json` |

**비밀은 설계상 오버레이 대상이 아닙니다.** `keys.*`, auth 토큰 저장소, 토큰/비밀에 대한 `HAECHI_*` 변수는 **없습니다**. 비밀은 설정 파일에 두거나 주입된 provider(`createRuntime(config, { cryptoProvider, authProvider, … })`)로 공급합니다. 비밀을 프로세스 환경에 두면 `/proc`, 크래시 덤프, 오케스트레이터 inspect 출력으로 누출될 위험이 있으므로 오버레이 allowlist에서 제외합니다. [운영 런북](./operations-runbook.md#2-configuration-via-the-env-var-overlay)을 참고하십시오.

## `mcp`

`mcp-stdio`와 `mcp-wrap`에 적용됩니다.

| 키 | 타입 / 값 | 기본값 | 설명 |
|---|---|---|---|
| `mcp.allowedMethods` | 비어 있지 않은 문자열 배열 | `["initialize", "tools/call", "resources/read", "prompts/get"]` | 클라이언트가 호출할 수 있는 method allowlist입니다(`"*"`는 전체 허용). 서버가 먼저 시작하는 요청은 allowlist를 우회하지만 params는 여전히 보호됩니다. |
| `mcp.protectParams` | boolean | `true` | 요청 `params`를 보호합니다. |
| `mcp.protectResults` | boolean | `true` | 응답 `result`를 보호합니다(injection 휴리스틱도 실행합니다). |
| `mcp.requireJsonRpc` | boolean | `true` | `jsonrpc: "2.0"`을 요구하며, 규격에 맞지 않는 메시지는 거부됩니다. |

## `auth`

| 키 | 타입 / 값 | 기본값 | 설명 |
|---|---|---|---|
| `auth.provider` | `none` \| `bearer` \| `external` \| `plugin` | `none` | `none` = 인증 없음(identity null). `bearer` = 내장 token auth. `external`은 `createRuntime(config, { authProvider })`를 통해 `authProvider`를 주입해야 합니다. `plugin` = 서명된 `authProvider` 샌드박스([`auth.plugin`](#authplugin-signed-authprovider-sandbox) 참고). |
| `auth.store` | 경로 | `.haechi/auth.json` | Bearer token 저장소입니다(모드 `0600`). Token은 keyed-HMAC 해시로만 보관되며, 평문은 `haechi auth add` 실행 시 한 번만 표시됩니다. |
| `auth.allowedLabelKeys` | 문자열 배열 | `["team", "env", "tier", "role"]` | Token이 가질 수 있는 label 키입니다. 값은 길이가 제한되며 PII를 포함하면 안 됩니다. |

### `auth.plugin` (signed authProvider sandbox)

`auth.provider: "plugin"`일 때 필요합니다. 샌드박스는 **서명된** `authProvider` 플러그인을 capability-gated, 감사되는 런타임에서 로드합니다. 최상위 `plugins.enabled`(기본 `true`)는 kill-switch입니다 — `false`이면 어떤 플러그인 생성도 거부합니다. 동적 로딩은 opt-in이며 기본은 dependency injection입니다. `docs/current/release-1.0-implementation-scope.md`(worker) 및 `release-1.1-implementation-scope.md`(process)를 참고하세요.

| Key | Type / values | Default | Notes |
|---|---|---|---|
| `auth.plugin.manifestPath` | 경로 | — | 서명된 플러그인 매니페스트(`haechi.plugin.json`). |
| `auth.plugin.trustAnchors` | `[{keyId, publicKey}]` 또는 `{ keyId: publicKey }` | — | 운영자 allowlist된 Ed25519 **공개** 키. 키 해석은 trust-anchor 전용. |
| `auth.plugin.allowCapabilities` | 문자열 배열 | — | capability 허용 목록; `readsCredentials` 포함 필수. 목록에 없는 요청 capability → 로드 거부. |
| `auth.plugin.isolation` | `worker` \| `process` | `worker` | `worker` = `worker_threads`(memory/crash 격리, **1.0**). `process` = Node 권한 모델 하 자식으로 **커널 강제** capability 거부(**1.1**); `--allow-net`을 강제하는 Node 필요. |
| `auth.plugin.timeoutMs` | 양의 정수 | — | call별 timeout; timeout 시 런타임이 자식/worker를 terminate하고 deny. |
| `auth.plugin.resourceLimits` | `{ maxOldGenerationSizeMb }` | — | **`worker` 전용** — `worker_threads` heap bound. `process`에는 N/A. |
| `auth.plugin.netEnforcement` | `require-permission` | `require-permission` | **`process` 전용** — 네트워크 봉쇄 정책. `require-permission`은 `--allow-net` 없는 Node에서 **fail closed**(생성 거부). |
| `auth.plugin.keyMaterial` | `{ url (https), ttlMs?, cooldownMs? }` | unset | **`process` 전용** — **호스트**가 가져와(SSRF 가드 + TTL+cooldown) 커스텀 자격증명 플러그인에 주입하는 선택적 운영자 선언 키 문서. 플러그인은 URL을 명명하지 않음. |
| `auth.plugin.pin` | `{ version?, entrySha256?, manifestSha256? }` | unset | 정확 일치 pin(악성 업데이트/rollback 방지). |
| `auth.plugin.revoked` | `{ signerKeyIds?, entrySha256? }` | unset | revocation denylist(로드 시 fail-closed). |
| `auth.plugin.versionFloor` | `{ <pluginId>: version }` | unset | 플러그인별 최소 버전(rollback 방지). |
| `auth.plugin.maxPendingCalls` / `maxMessageBytes` | 양의 정수 | `8` / `16384` | 동시성 + wire 한계(초과/oversized → deny). |

## `policy` profiles & limits

기본 `policy` 위에 클라이언트별 통제를 레이어로 추가합니다. [Named profiles](#named-profiles)를 참고하세요.

| 키 | 타입 / 값 | 기본값 | 설명 |
|---|---|---|---|
| `policy.profiles` | `{ <name>: { presets?, actions?, modelAllowlist?, rate? } }` | `{}` | Named profile입니다. 각각 기본 policy를 재정의합니다. |
| `policy.profileBinding` | `{ byScope?, byLabel?, default }` | 미설정 | identity scope/label(`"k=v"` 형태)을 profile 이름으로 매핑합니다. `profiles`가 설정된 경우 `default`는 **필수**이며 가장 엄격한 profile이어야 합니다(fail-closed). |
| `policy.modelAllowlist` | 문자열 배열 | 미설정 | 허용된 `model` 값입니다(기본 레벨; profile별로도 설정 가능). 허용되지 않은 모델 → `403`. 비어 있거나 없으면 모두 허용합니다. |
| `policy.rate` | `{ requestsPerMinute }` | 미설정 | identity별 요청 rate limit입니다(기본 레벨 또는 profile별). 초과 시 → `429`. 인메모리, 프로세스별입니다. 다중 replica 시임은 [Rate limiter 주입](#rate-limiter-주입)을 참고하십시오. |

### Named profiles

identity가 인증되면 **scope → label → `default`** 순으로 profile이 resolve됩니다. scope가 label보다 우선하며 첫 번째 매칭이 적용됩니다. `profiles`가 없거나 `auth.provider: none`인 경우 기본 policy가 적용됩니다. Resolve된 profile의 policy 엔진, `modelAllowlist`, `rate`가 해당 요청을 처리합니다.

### Rate limiter 주입

rate limiter는 **주입 가능한 collaborator**이며, `createRuntime(config, providers)`의 `providers` 인자를 통해 프로그래밍 방식으로 공급됩니다 — 외부 `cryptoProvider`/`authProvider`와 동일한 시임입니다. JSON config 키가 **아닙니다**.

```js
const runtime = createRuntime(config, { rateLimiter });
```

주입된 `rateLimiter`는 `allow(key, limit) -> boolean`을 구현해야 합니다(`key`는 identity별 버킷, `limit`은 resolve된 `requestsPerMinute`입니다). 구현하지 않으면 `createRuntime`이 construction 시점에 fail-closed로 throw합니다. proxy는 rate 통제 대상 요청마다 `runtime.rateLimiter`를 참조합니다.

**기본값**은 프로세스별 인메모리 fixed-window 카운터입니다. 재시작 시 초기화되며 **replica 간에 공유되지 않으므로**, load balancer 뒤에서 총 처리량은 replica 수만큼 곱해집니다. window map은 self-bounding입니다(lazy, amortized sweep로 만료된 one-shot identity를 제거합니다 — 백그라운드 timer 없음). 다중 replica 배포에서는 공유 front door에서 identity별 limit을 강제하거나, 동일한 `allow(key, limit)` 계약을 만족하는 공유 저장소 구현(예: Redis 기반)을 주입하십시오. [Shared responsibility §4](./shared-responsibility.ko.md#4-수평-확장--다중-복제)를 참고하십시오.

## Detection type과 action

내장 탐지 `type` 값은 다음과 같습니다: `email`, `phone`, `kr_rrn`, `card`, `api_key`, `secret`, `us_ssn`, `iban`, `injection`(응답 방향 휴리스틱, 기본 report-only). 커스텀 규칙으로 새로운 type을 추가할 수 있습니다.

### 지원하는 자격증명·PII 매트릭스

탐지는 정규식 + 선택적 validator로 동작합니다(ML 미사용). 모든 규칙은 정밀도를 높게 유지하기 위해 **단단히 anchoring**되어 있으며, recall보다 precision을 우선합니다. 코퍼스(`tests/fixtures/detection-corpus.json`)에는 규칙마다 hard-negative가 포함됩니다. KR phone 규칙과 US SSN/IBAN validator는 유사 형태의 id·timestamp를 거부합니다.

| Type | 탐지 대상 | Anchor / validator | 비고 |
|---|---|---|---|
| `email` | RFC 형식 주소 | local + domain + TLD | — |
| `phone` | KR 휴대폰(`01[016789]`, `+82`) | 구분자 없는 bare run은 `0`으로 시작해야 함 | KR 유선번호는 범위 외입니다. |
| `phone` | E.164 국제번호 | **선행 `+` 필수**(`+[1-9]` + 6–14자리) | bare 숫자열은 절대 매칭하지 않습니다(id·timestamp와 충돌). |
| `phone` | US/NANP 국내번호 | **구분자 필수**(`(NXX) NXX-XXXX` 또는 `NXX-NXX-XXXX`) | 구분자 없는 10자리 숫자열은 매칭하지 않습니다. |
| `kr_rrn` | 주민등록번호 | 검증 숫자 validator | 형식은 맞으나 checksum 불일치 → 거부. |
| `card` | 결제 카드(PAN) | Luhn validator, 13–19자리 | — |
| `us_ssn` | 미국 사회보장번호 | `AAA-GG-SSSS` + SSA 범위 validator(area `000`/`666`/`900-999`, group `00`, serial `0000` 거부) | 구분자 필수이며, bare 9자리 id는 SSN이 아닙니다. |
| `iban` | 국제 은행계좌번호 | **mod-97 checksum** validator | checksum이 정밀도 가드입니다 — IBAN 형태이지만 97 비검증 문자열은 거부됩니다. |
| `api_key` | OpenAI 형식(`sk_`/`rk_`/`pk_`) | prefix + 24자 이상 | — |
| `api_key` | AWS access key id | `AKIA`/`ASIA` + 정확히 16자 대문자-alnum | — |
| `api_key` | Google API key | `AIza` + 35자 URL-safe 문자 | — |
| `secret` | `Bearer <token>` | `Bearer` + 16자 이상 | — |
| `secret` | 할당식 `<key> = <value>` | 키 어휘: `api_key`, `api_secret`, `secret`, `secret_key`, `aws_secret_access_key`, `client_secret`, `private_key`, `access_token`, `refresh_token`, `token`, `password` | bare-base64 시크릿(예: AWS secret access key)을 할당식 형태로 포착합니다. |
| `secret` | GitHub token | `gh[pousr]_` + 36자 이상 base64 유사 문자 | pat/oauth/user/server/refresh 변형. |
| `secret` | Slack token | `xox[baprs]-` + 10자 이상 본문 | bot/user/refresh/legacy 변형. |
| `secret` | JWT | 점으로 구분된 3개 base64url 세그먼트, 첫 세그먼트가 `eyJ`(즉 `{"`의 base64)로 시작 | `eyJ` anchor가 임의의 점-구분 토큰을 거부합니다. |
| `secret` | PEM private key | `-----BEGIN … PRIVATE KEY-----` armor 헤더 | 헤더 존재가 신호이며, "private key"를 언급한 산문은 매칭하지 않습니다. |
| `injection` | 프롬프트 인젝션 휴리스틱 | 응답 방향 전용, 기본 `allow` | [Action strength](#action-strength) 참고; report-only. |

탐지는 문자열 값, JSON number leaf(요청 방향), object key를 대상으로 합니다. 각 **string leaf는 매칭 전 NFKC 정규화**되므로, 유니코드 난독화 형태(전각 숫자 `４２４２…`, 전각 `＠`, 수학·원문자 영숫자)도 ASCII 호환 형태로 접혀 탐지됩니다. 접힘이 UTF-16 길이를 보존하면 우회된 정확한 구간을 redact/block하고, 길이가 달라지면(예: 수학 숫자·합자) 탐지가 fail closed되어 leaf 전체를 redact/block합니다. base64/percent-encoded 값(디코딩 후)과 URL query 문자열은 문서화된 제외 항목으로 남습니다(`docs/current/threat-model.md` 참고). 응답 방향에서는 Haechi 자체 transform marker와 bare JSON number leaf를 건너뜁니다(요청 방향은 항상 전체 스캔).

Action(약한 것 → 강한 것 순):

| Action | 효과 |
|---|---|
| `allow` | 변경 없음(탐지와 audit은 기록됩니다). |
| `redact` | `[REDACTED:<type>]`으로 교체합니다. |
| `mask` | 부분 마스킹합니다(값이 8자 이하이면 전체 마스킹). |
| `tokenize` | vault token으로 교체합니다. token vault를 통해 복원 가능합니다. |
| `encrypt` | 인라인 AES-256-GCM 봉투로 교체합니다. |
| `block` | 전체 payload를 거부합니다(`403`/`-32001`/exit 3). |

### Action strength

preset과 override(또는 privacy profile)가 충돌할 경우 **강한** action이 우선하며, `policy.allowUnsafeOverrides`가 `true`가 아니면 더 강한 action을 약화하려 할 경우 오류가 발생합니다. 강도 순: `allow`(0) < `redact`/`mask`(1) < `tokenize`/`encrypt`(2) < `block`(3).

### Presets

| Preset | 효과 |
|---|---|
| `llm-redact` | 기본 `redact`; `email: redact`, `phone: mask` |
| `korean-pii` | `kr_rrn: block`, `phone: mask`, `email: redact` |
| `secrets-only` | `api_key: block`, `secret: block` |
| `strict-block` | 기본 `block` |
| `mcp-basic` | 기본 `redact`; `api_key`/`secret`/`kr_rrn: block` |
| `local-inference` | 기본 `redact`; `email: tokenize`, `phone: mask`, secrets/`kr_rrn: block` |
| `local-only` | 전송을 외부 전송이 아닌 것으로 표시(메타데이터) |

## 자주 쓰는 설정

**enforce 모드에서 요청 보호(최소 설정):**
```json
{ "mode": "enforce", "policy": { "mode": "enforce" } }
```

**로컬 inference, response protection + token round-trip:**
```json
{
  "mode": "enforce",
  "target": { "type": "vllm-openai", "upstream": "http://127.0.0.1:8000" },
  "policy": { "mode": "enforce", "presets": ["local-inference"] },
  "responseProtection": { "enabled": true, "mode": "enforce" },
  "tokenVault": { "deterministic": true, "detokenizeResponses": true }
}
```

**EU 프로필, secret 차단, injection 플래그:**
```json
{
  "mode": "enforce",
  "privacy": { "profile": "eu-gdpr" },
  "policy": { "mode": "enforce", "actions": { "injection": "redact" } },
  "responseProtection": { "enabled": true }
}
```

## loopback 밖으로 바인딩

proxy는 CLI 플래그를 명시적으로 전달하지 않으면 loopback이 아닌 host를 거부합니다 — 설정 파일에 `proxy.host: "0.0.0.0"`을 지정해도 의도적으로 시작되지 않습니다. remote bind에는 **TLS가 추가로 필요합니다**: Haechi가 직접 TLS를 종단하거나(`proxy.tls`), 앞단의 TLS 종단기를 명시적으로 확인해야 합니다(`proxy.trustForwardedProto`). 둘 다 없는 remote bind는 **기동 시 throw**합니다 — Haechi는 loopback이 아닌 리스너에서 bearer token과 payload를 평문으로 제공하지 않습니다.

**옵션 A — Haechi가 직접 TLS를 종단**(`https` 제공):

```jsonc
// haechi.config.json
"proxy": { "host": "0.0.0.0", "tls": { "keyFile": "/etc/haechi/tls/key.pem", "certFile": "/etc/haechi/tls/cert.pem" } }
// 또는 PKCS#12: "tls": { "pfxFile": "/etc/haechi/tls/server.pfx", "passphrase": "…" }
```
```bash
haechi proxy --config haechi.config.json --host 0.0.0.0 --allow-remote-bind
# → Haechi proxy listening on https://0.0.0.0:11016
```

**옵션 B — 신뢰하는 reverse proxy가 앞단에서 TLS를 종단**(Haechi는 그 뒤 사설망에서 plain `http`로 유지):

```jsonc
"proxy": { "host": "0.0.0.0", "trustForwardedProto": true }
```
`trustForwardedProto: true`이면 Haechi는 **`X-Forwarded-Proto`가 `https`가 아닌 모든 요청을**(TLS hop을 우회한 평문 요청을) auth/body 이전에 fail-closed `403`으로 거부합니다. `/__haechi/*` liveness/metrics 라우트는 loopback sidecar가 스크레이프할 수 있도록 예외입니다. 오직 신뢰하는 종단기만 `X-Forwarded-Proto`를 설정해야 합니다 — 신뢰할 수 없는 클라이언트가 Haechi 포트에 직접 도달할 수 있다면 이 옵션을 켜지 마십시오.

**proxy는 bearer 클라이언트 인증을 제공합니다**(`auth.provider: bearer`, 0.6에서 출시). 해시 기반 token 저장소, identity별 policy profile, model allowlist, identity별 rate limit을 함께 제공합니다([`auth`](#auth)와 [Named profiles](#named-profiles) 참고). 기본값 `auth.provider: none`은 proxy를 인증 없이 둡니다 — `none`에서는 포트에 접근할 수 있는 누구든 upstream과 token round-trip 경로를 사용할 수 있습니다. 내장 rate limit은 단일 프로세스(인메모리, 프로세스별)이므로, 여러 replica는 공유 limiter를 앞에 두어야 합니다. `--allow-remote-bind`는 어느 경우에도 명시적인 네트워크 통제 하에서만 사용해야 합니다 — 컨테이너 안에서 `0.0.0.0`으로 바인드하고 host 포트 매핑을 제한하거나(`-p 127.0.0.1:11016:11016`), 방화벽/VPN/인증 reverse proxy 뒤에 두어야 합니다.

## 검증 요약

다음은 로드 시 오류(fail-closed)를 발생시킵니다: 알 수 없는 `keys.provider`; 빈 `proxy.host`; 범위를 벗어난 `proxy.port`; boolean이 아닌 `proxy.trustForwardedProto`; non-`null`이지만 object가 아니거나, `keyFile`만 있고 `certFile`이 없거나(또는 그 반대), `pfxFile`을 `keyFile`/`certFile`과 함께 쓰거나, 읽을 수 없는 파일을 지정하거나, 사용 가능한 자료 `((key && cert) 또는 pfx)`로 해석되지 않는 `proxy.tls`; `jsonl`이 아닌 `audit.sink`; `local`이 아닌 `tokenVault.provider`; 잘못된 `revealPolicy`; 양수가 아닌 `retentionDays`; boolean이 아닌 `deterministic`/`detokenizeResponses`; 비어 있거나 문자열이 아닌 `deterministicTypes`; 비어 있거나 문자열이 아닌 `mcp.allowedMethods`; boolean이 아닌 `mcp.*` 플래그; 알 수 없는 `privacy.profile`; 잘못된 `responseProtection.failureMode`; 양수가 아닌 `responseProtection.maxBytes`; boolean이 아닌 `responseProtection.scanNumbers`; 잘못된 `streaming.requestMode`; 잘못된 `streaming.responseMode`; 양수가 아닌 `streaming.maxMatchBytes`; 잘못된 `auth.provider`; 빈 `auth.store`; 문자열이 아닌 `auth.allowedLabelKeys`; 객체가 아닌 `policy.profiles`; 유효한 `default` 없는 `policy.profileBinding`; 문자열이 아닌 `policy.modelAllowlist`; 양수가 아닌 `policy.rate.requestsPerMinute`; 양수가 아닌 `limits.maxRequestBytes`/`limits.upstreamTimeoutMs`/`limits.maxNestingDepth`; 음수이거나 정수가 아닌 `limits.maxInFlight`/`limits.shutdownGraceMs`; `null`이 아니면서 음수이거나 정수가 아닌 `limits.requestTimeoutMs`/`limits.headersTimeoutMs`; 양수 정수가 아니거나 **지원 범위를 넘는** `configVersion`; 알 수 없는 `target.type`/`adapter`; 안전하지 않은 커스텀 정규식; `allowUnsafeOverrides` 없이 action을 약화하려는 시도; `text`/`json`이 아닌 `logging.format`; boolean이 아닌 `metrics.enabled`; 잘못된 `HAECHI_*` 환경변수 오버레이 값(잘못된 `HAECHI_PROXY_PORT`, 알 수 없는 `HAECHI_MODE`, 형식이 잘못된 `HAECHI_UPSTREAM` 등).

# Satellite 운영자 설정 (0.9)

아래 두 섹션은 0.9에서 도입된 **독립적으로 배포되는 satellite 패키지** — `haechi-dashboard`와 `haechi-auth-oidc`의 설정을 다룹니다. **이들은 코어 `haechi.config.json` / `normalizeConfig` 스키마의 키가 아닙니다.** 각 satellite는 팩토리 함수(`createDashboardServer(options)` / `createOidcSessionBroker(options)`)에 **옵션 객체**를 전달해 설정하며, 각자의 `normalizeDashboardConfig` / `normalizeOidcConfig`가 검증합니다. 검증은 코어와 동일한 **strict, fail-closed** 원칙을 따릅니다. 알 수 없는 옵션 키는 오류를 발생시키고, 아래의 모든 필드는 fail-closed throw 조건을 명시합니다. 소스: `satellites/dashboard/index.mjs`, `satellites/auth-oidc/index.mjs`. 위협 모델 커버리지: **P1-OPS-005**(dashboard audit 노출 / DNS-rebinding / remote bind), **P1-SEC-009**(broker session/login 보안), `docs/current/release-0.9-implementation-scope.md` §6 참고.

## `haechi-dashboard` (satellite)

audit JSONL과 그 hash-chain 상태를 제공하는 zero-dependency **read-only** audit 뷰어(`node:http`)입니다. 런타임이 아닌 **경로**를 받습니다. `createDashboardServer(options)`로 설정하며, `normalizeDashboardConfig(options)`가 검증 후 실제 적용 설정을 반환합니다. 소스: `satellites/dashboard/index.mjs`.

| 옵션 | 타입 / 값 | 기본값 | 설명 / fail-closed throw |
|---|---|---|---|
| `auditPath` | 비어 있지 않은 문자열 | **필수** | audit JSONL 경로. 누락되거나 비어 있지 않은 문자열이 아니면 throw. |
| `anchorPath` | string \| `null` | `null` | tail 절단 탐지를 위해 `verifyAuditChain`에 전달되는 anchor 스트림 경로. 존재하지만 비어 있지 않은 문자열이 아니면 throw. |
| `host` | 비어 있지 않은 문자열 | `127.0.0.1` | 바인드 주소. loopback이 아니면 `allowRemoteBind`와 아래 remote-bind 전제 조건을 모두 충족해야 합니다. 존재하지만 비어 있거나 문자열이 아니면 throw. |
| `port` | 정수 0–65535 | `1018` | 리슨 포트; `0` = OS 할당 임시 포트(의도된 affordance). `[0,65535]` 정수가 아니면 throw. |
| `allowRemoteBind` | boolean | `false` | loopback이 아닌 `host`를 허용합니다. boolean이 아니면 throw. 설정만으로는 충분하지 않습니다 — remote-bind 전제 조건 참고. |
| `sessionGuard` | object \| `null` | `null` | `authenticate(req) -> session\|null`과 선택적 `handlers` 맵을 구현하는 guard. object가 아니거나 `authenticate`가 함수가 아니면 throw. `handlers` 키는 고정된 broker 경로 `/auth/login`, `/auth/callback`, `/auth/logout`만 허용되며, 다른 키(특히 `/api/*`, `/healthz`, `/`)는 throw — guard가 audit 경로를 게이트에서 면제시키는 auth-bypass를 차단합니다. `haechi-auth-oidc` broker를 주입하면 충족됩니다(아래 참고). |
| `window` | 정수 4096–67108864 | `1048576` | `/api/events`와 `/api/summary`의 tail-read 윈도우(최대 바이트). `[4096, 67108864]`(4 KiB–64 MiB) 정수가 아니면 throw. |
| `tlsContext` | object \| `null` | `null` | dashboard가 직접 HTTPS를 종단하기 위한 TLS 자료. object가 아니거나, non-null인데 **사용 가능한 자료**가 없으면 throw — `(key && cert)` 또는 `pfx`를 반드시 포함해야 합니다(빈 `{}`는 거부되어 loopback이 아닌 plaintext 리스너를 green-light하지 못하게 합니다). |
| `trustProxy` | string \| `null` | `null` | 신뢰하는 fronting-proxy 주소/CIDR를 명시합니다. 문자열이 아니거나, 비어 있거나, falsy 모양 문자열(`"false"`/`"0"`)이면 throw. **`trustProxy`만으로는 loopback이 아닌 바인드를 절대 인가하지 못합니다** — 실제 `tlsContext`만 가능합니다. |

### 라우트

모든 라우트는 **GET/HEAD 전용**(그 외 method → `405`)이며, asset 맵은 in-code로 고정되어 있습니다(파일시스템 traversal 없음):

- `/api/events` — audit JSONL의 bounded tail read, 최신순. `limit`은 `[1,200]` 정수(기본 50); `cursor`는 opaque `auditIntegrity.sequence`(파일시스템 오프셋이 아님). 각 이벤트는 **recursive key-by-key allowlist projection**으로 재구성됩니다(blind spread 없음; identity는 scope/label/raw subject 없이 `subjectHash`/`issuerHash`만 보유). 요청된 페이지가 유지된 윈도우보다 오래되면 `windowExceeded`를 반환합니다.
- `/api/chain` — `verifyAuditChain`을 감싸며, 파생된 `truncationDetected` boolean을 노출합니다(raw 실패 reason은 **절대** 반환하지 않습니다). mtime+size 캐시(동시 재-walk 없음); 32 MiB 상한 초과 시 `{valid:null}`과 함께 `413`; `HEAD`는 walk를 강제하지 않고 헤더만 반환합니다.
- `/api/summary` — tail 윈도우에 대한 집계 탐지 카운트(`byType`/`byAction`/`detectionCount`).
- `/healthz` — liveness 전용(`{status:"ok"}`); loopback 밖에서도 session이 필요 없습니다.

### 보안 기본값

- **기본 loopback 바인드.** `host` 기본값은 `127.0.0.1`이며, loopback이 아닌 host 바인드는 코어의 `assertSafeProxyBind`(재-표현)를 재사용하고 `allowRemoteBind`를 요구합니다.
- **Remote bind는 fail-closed.** loopback이 아닌 바인드는 `allowRemoteBind: true`, `sessionGuard`, **그리고** 유효한 `tlsContext`(dashboard가 직접 TLS 종단)를 **모두** 요구합니다. `trustProxy`는 이를 충족하지 못합니다 — loopback이 아닌 plaintext 리스너는 audit 데이터를 평문으로 제공하면서 HSTS를 방출하므로 거부됩니다. HSTS는 서버가 실제로 HTTPS를 제공할 때**만** 방출됩니다.
- **anti-DNS-rebinding Host allowlist**가 모든 요청(`/api/*`, `/healthz`, 모든 method 포함)의 무조건적 첫 게이트입니다. 잘못되거나 중복된 `Host` 헤더 → method 검사 이전에 `403`.
- **strict CSP + Trusted Types**(`require-trusted-types-for 'script'`, `textContent` 렌더링) 및 `X-Frame-Options: DENY`, `Cross-Origin-Resource-Policy`/`-Opener-Policy: same-origin`, `X-Content-Type-Options: nosniff`, `Cache-Control: no-store`; CORS 헤더는 의도적으로 절대 설정하지 않습니다.
- **sessionGuard seam.** guard가 존재하면 모든 `/api/*` 라우트는 `authenticate()` 뒤에 게이트됩니다. 미인증 요청은 `401`(`302` 리다이렉트가 아닙니다). auth-면제 집합은 고정된 broker-path allowlist와 guard가 선언한 handlers의 **교집합**(exact match)입니다 — guard는 audit-data 라우트를 절대 면제시킬 수 없습니다.
- **generic 오류.** 5xx는 `{error:"internal"}`만 반환합니다 — stack, OS code, 파일시스템 경로는 절대 없습니다. satellite-local fixed-window rate limiter(소스별 120 req/60s)가 `/api/*` 앞단을 막습니다.

bin `haechi-dashboard`(workspace)가 서버를 구동하며, publish 워크플로는 `.github/workflows/dashboard-publish.yml`(태그 `dashboard-v<semver>`)입니다. `peerDependencies: { haechi: ">=0.8.0 <1.0.0" }`.

## `haechi-auth-oidc` (satellite)

zero-dependency **interactive OIDC session broker**(authorization-code + PKCE)이며, dashboard의 사람-로그인 메커니즘입니다. opaque server-side session을 생성하고, **주입을 통해 dashboard `sessionGuard` 계약을 충족합니다**(`{ authenticate(req), handlers: { "/auth/login", "/auth/callback", "/auth/logout" } }`). per-request bearer validator가 **아닙니다**(그 역할은 `haechi-auth-jwt`에 남습니다). `createOidcSessionBroker(options)`로 설정하며 `normalizeOidcConfig(options)`가 검증합니다. 소스: `satellites/auth-oidc/index.mjs`. `peerDependencies: { haechi: ">=0.8.0 <1.0.0", haechi-auth-jwt: ">=0.2.0 <1.0.0" }`.

| 옵션 | 타입 / 값 | 기본값 | 설명 / fail-closed throw |
|---|---|---|---|
| `cryptoProvider` | `hmac()`를 가진 object | **필수** | PII-safe identity 해시와 `sessionIdHash`를 위한 keyed-HMAC를 제공합니다. `hmac`이 함수가 아니면 throw. |
| `issuer` | HTTPS URL 문자열 | **필수** | OIDC issuer; 정확한 string-equal discovery와 single-origin endpoint 검사를 위해 pin됩니다. 누락되거나 `https`가 아니면 throw. |
| `clientId` | 비어 있지 않은 문자열 | **필수** | OAuth client id(ID-token의 기대 `aud`이기도 함). 누락/비어 있으면 throw. |
| `clientSecret` | string \| 생략 | 생략 | 존재 ⇒ confidential client; 생략 ⇒ public(PKCE 전용) client. 존재하지만 비어 있으면 throw. |
| `redirectUri` | 절대 URL 문자열 | **필수** | `https`(또는 carve-out 하의 **loopback** `http`)여야 하고, broker와 **same-origin**이며, path가 정확히 `/auth/callback`이어야 합니다. 그 외에는 throw. |
| `scopes` | 문자열 배열 | `["openid"]` | `openid`는 강제 포함(dedup)되고, `offline_access`는 제거됩니다(refresh rotation은 0.9 범위 밖). 비어 있지 않은 문자열 배열이 아니면 throw. |
| `returnToAllowlist` | 문자열 배열 | `["/"]` | **relative same-origin** 복귀 경로의 allowlist(단일 `/`로 시작, scheme/host/`//`/백슬래시 없음). 배열이 아니거나 비적합 항목이 있으면 throw. |
| `sessionTtlSeconds` | 정수 1–2592000 | `28800`(8h) | 절대 session 수명. `[1, 2592000]`(30d 상한)을 벗어나면 throw. |
| `idleTtlSeconds` | 정수 1–2592000 | `1800`(30m) | idle 타임아웃(sliding `lastSeen`). 범위를 벗어나면 throw. |
| `maxAgeSeconds` | 정수 1–2592000 \| `null` | `null` | 설정 시 OIDC `max_age`를 보내고 `auth_time`이 `maxAge + skew` 이내일 것을 요구합니다. 존재하지만 범위를 벗어나면 throw. |
| `tokenEndpointAuthMethod` | `client_secret_basic` \| `client_secret_post` | `client_secret_basic` | token-endpoint 인증 방식. 알 수 없는 값이거나, `clientSecret` 없이 설정되면 throw(confidential client에서만 유효). |
| `secureCookies` | `true` \| `false` \| `"auto"` | `"auto"` | externally-visible scheme로부터 쿠키 `Secure`/`__Host-` 하드닝을 강제하거나 자동 도출합니다. 그 외 값이면 throw. |
| `trustProxy` | string \| `null` | `null` | TLS를 종단하는 fronting proxy를 명시합니다; browser-facing scheme를 HTTPS로 간주합니다(쿠키 하드닝에 반영). 문자열이 아니거나 비어 있으면 throw. |
| `algorithms` | 비어 있지 않은 문자열 배열 | `["RS256","ES256"]` | 허용된 JWS 알고리즘(verifier로 전달). 비어 있지 않은 배열이 아니면 throw. |
| `clockSkewSeconds` | 수 0–300 | (verifier 기본값) | ID-token 시간 클레임의 여유. `[0,300]`을 벗어나면 throw. |
| `prompt` | string \| `null` | `null` | 선택적 OIDC `prompt`. 존재하지만 비어 있거나 문자열이 아니면 throw. |
| `pendingTtlSeconds` | 정수 1–3600 | `600`(10m) | 로그인 완료 제한 시간(pre-auth 레코드 TTL). `[1,3600]`을 벗어나면 throw. |
| `pendingCap` | 정수 1–1000000 | `1024` | 동시 진행 중 로그인의 hard cap; store가 가득 차면 **새** 로그인을 거부하고 진행 중 auth는 절대 evict하지 않습니다(fail-closed). 범위를 벗어나면 throw. |
| `rateLimitMax` | 정수 1–1000000 | `60` | 소스별 60s 윈도우당 `/auth/login`+`/auth/callback`. 범위를 벗어나면 throw. |
| `fetchTimeoutMs` | 정수 1–120000 | `5000` | egress별 타임아웃(discovery / token / JWKS). 범위를 벗어나면 throw. |
| `fetchImpl` / `lookupImpl` / `now` | 함수 | 주입/전역 | `fetch` / DNS `lookup` / clock seam 주입. 존재하지만 함수가 아니면 throw. |
| `sessionStore` | object | in-memory | opaque-id → session store; `get`/`set`/`delete`를 구현해야 합니다. 존재하지만 비적합하면 throw. |
| `pendingStore` | object | in-memory | pre-auth 레코드 store; `set`/`take`(원자적 단일-사용 `take`)를 구현해야 합니다. 존재하지만 비적합하면 throw. |
| `auditSink` | 함수 \| `record()`를 가진 object | 없음 | PII-safe 이벤트 sink. 존재하지만 함수도 `record()` 가진 object도 아니면 throw. |

### 쿠키 하드닝 의미

session은 **server-side 전용**입니다 — 쿠키는 클레임/토큰이 아닌 opaque id만 보유합니다. 두 개의 쿠키를 사용합니다(pending 레코드를 바인딩하는 pre-auth 쿠키, 그리고 session 쿠키). externally-visible scheme가 HTTPS이면(`https` `redirectUri`, `secureCookies: true`, 또는 non-null `trustProxy`) 쿠키는 **`__Host-` prefix + `Secure` + `HttpOnly` + `SameSite=Lax`**(`Path=/`, `Domain` 없음)를 사용합니다. `SameSite=Lax`는 IdP의 top-level GET이 `/auth/callback`으로 쿠키를 실어 보내게 합니다. 문서화된 **loopback-`http` carve-out** 하에서는 `__Host-`/`Secure` 속성이 제거되고(plaintext 리스너는 `Secure`를 설정할 수 없습니다) bare 쿠키 이름을 사용합니다. **HTTPS가 확인되지 않은 off-loopback broker는 construction에서 fail-closed됩니다** — `Secure`/`__Host-` 쿠키는 평문으로 전송되지 않으므로 로그인이 조용히 깨질 것이기 때문입니다. `/auth/callback`에서 **새** session id가 발급됩니다(fixation 없음). `/auth/logout`은 non-GET, CSRF-헤더 게이트(`x-haechi-csrf`)이며 server-side 상태를 파괴합니다. access token은 폐기됩니다(절대 저장하지 않습니다). audit 이벤트(`oidc.login.start`/`success`/`failure{reasonCode}`/`logout`/`session.evict`)는 keyed-HMAC `subjectHash`/`issuerHash`/`sessionIdHash` + `provider` + 거친 `reasonCode` + timestamp만 보유합니다.

### dashboard와의 연결

broker를 dashboard의 `sessionGuard`로 주입합니다:

```js
import { createDashboardServer } from "haechi-dashboard";
import { createOidcSessionBroker } from "haechi-auth-oidc";

const broker = createOidcSessionBroker({
  cryptoProvider,
  issuer: "https://idp.example.com",
  clientId: "haechi-dashboard",
  clientSecret: "…",
  redirectUri: "https://dash.example.com/auth/callback",
  returnToAllowlist: ["/"]
});

const dashboard = createDashboardServer({
  auditPath: ".haechi/audit.jsonl",
  host: "0.0.0.0",
  allowRemoteBind: true,
  tlsContext: { key, cert },   // remote bind: dashboard가 직접 TLS 종단
  sessionGuard: broker         // /api/*를 authenticate() 뒤로 게이트; /auth/* handlers 마운트
});
```

broker의 `handlers` 맵은 dashboard가 auth 게이트에서 면제하는 고정 broker 경로에서만 마운트되며, 모든 `/api/*` 라우트는 `broker.authenticate(req)` 뒤에 게이트됩니다. publish 워크플로: `.github/workflows/auth-oidc-publish.yml`(태그 `auth-oidc-v<semver>`).
