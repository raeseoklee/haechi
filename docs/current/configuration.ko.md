# Haechi 설정 레퍼런스

- 문서 상태: Living document
- 기준 버전: 0.4.0

`haechi init`은 `haechi.config.json`을 생성하며, 비밀 정보를 포함하지 않는 템플릿은 `haechi.config.example.json`에 있다. 모든 커맨드는 `--config <path>`로 설정 파일을 읽는다(기본값: `haechi.config.json`). 설정은 **fail-closed 방식으로 검증**된다: 알 수 없는 provider, 범위를 벗어난 숫자, 잘못된 형식의 값은 자동으로 무시되지 않고 로드 시점에 오류를 발생시킨다. `haechi config`는 이 레퍼런스를 출력하며, `haechi status`는 특정 설정 파일의 *실제 적용* 상태를 출력한다.

## 전체 기본값

```json
{
  "mode": "dry-run",
  "target": { "type": "llm-http", "adapter": "openai-compatible", "upstream": "http://127.0.0.1:9999" },
  "proxy": { "host": "127.0.0.1", "port": 1016 },
  "responseProtection": { "enabled": false, "mode": "enforce", "failureMode": "fail-closed", "allowNonJson": false, "allowCompressed": false, "maxBytes": 1048576 },
  "streaming": { "requestMode": "block" },
  "limits": { "maxRequestBytes": 1048576, "upstreamTimeoutMs": 120000 },
  "policy": { "mode": "dry-run", "presets": ["korean-pii", "secrets-only", "llm-redact"], "defaultAction": "redact", "actions": { "card": "block" } },
  "filters": { "customRules": [] },
  "keys": { "provider": "local", "keyFile": ".haechi/dev.keys.json" },
  "audit": { "sink": "jsonl", "path": ".haechi/audit.jsonl" },
  "tokenVault": { "provider": "local", "path": ".haechi/token-vault.json", "revealPolicy": "disabled", "retentionDays": 30, "deterministic": false, "deterministicTypes": null, "detokenizeResponses": false },
  "privacy": { "profile": null },
  "mcp": { "allowedMethods": ["initialize", "tools/call", "resources/read", "prompts/get"], "protectParams": true, "protectResults": true, "requireJsonRpc": true }
}
```

## 최상위

| 키 | 타입 / 값 | 기본값 | 설명 |
|---|---|---|---|
| `mode` | `dry-run` \| `report-only` \| `enforce` | `dry-run` | 전역 집행 모드. `dry-run`/`report-only`는 탐지 및 audit만 수행하며, `enforce`는 변환/차단을 적용한다. `policy.mode`가 설정된 경우 해당 값이 우선한다. |

## `target`

| 키 | 타입 / 값 | 기본값 | 설명 |
|---|---|---|---|
| `target.type` | `llm-http` \| `openai-compatible` \| `vllm-openai` \| `ollama` \| `llama-cpp` | `llm-http` | 프로토콜 adapter를 선택한다. `llm-http`는 `openai-compatible`의 별칭이다. 알 수 없는 값은 로드 시 **fail-closed**로 처리된다. |
| `target.adapter` | 동일한 값 집합 | `openai-compatible` | adapter를 명시적으로 지정한다. 보통은 설정하지 않고 `type`이 결정하도록 두면 된다. |
| `target.upstream` | URL 문자열 | `http://127.0.0.1:9999` | proxy가 요청을 전달하는 유일한 upstream. 요청 대상은 origin-form 경로여야 하며, 절대 URL 대상은 거부된다(SSRF 방어). |

## `proxy`

| 키 | 타입 / 값 | 기본값 | 설명 |
|---|---|---|---|
| `proxy.host` | 비어 있지 않은 문자열 | `127.0.0.1` | 바인드 주소. loopback이 아닌 host를 사용하려면 `--allow-remote-bind` CLI 플래그가 필요하다 — 설정 파일만으로는 시작되지 않는다([loopback 밖으로 바인딩](#binding-beyond-loopback) 참고). |
| `proxy.port` | 정수 0–65535 | `1016` | 리슨 포트(`0` = 임시 포트). `--port`로 실행 시마다 덮어쓸 수 있다. |

## `responseProtection`

upstream JSON 응답을 검사한다(기본적으로 꺼져 있음 — 모델로부터 *돌아오는* 내용을 보호하려면 활성화한다).

| 키 | 타입 / 값 | 기본값 | 설명 |
|---|---|---|---|
| `responseProtection.enabled` | boolean | `false` | 마스터 스위치. `detokenizeResponses`가 작동하려면 반드시 활성화되어 있어야 한다. |
| `responseProtection.mode` | `dry-run` \| `report-only` \| `enforce` | `enforce` | 응답 방향의 집행 모드. |
| `responseProtection.failureMode` | `fail-closed` \| `allow` | `fail-closed` | *검사 불가능한* 응답(비JSON, 잘못된 JSON, 압축)에 대한 처리 방식. `fail-closed`는 502를 반환하고, `allow`는 통과시킨다(audit 기록됨). |
| `responseProtection.allowNonJson` | boolean | `false` | 비JSON 응답을 검사 없이 통과시킨다. |
| `responseProtection.allowCompressed` | boolean | `false` | 압축 응답을 검사 없이 통과시킨다. |
| `responseProtection.maxBytes` | 양의 정수 | `1048576` | 응답 크기의 상한. `failureMode: allow` 상태에서도 적용되며, 크기를 초과한 응답은 항상 거부된다. |

## `streaming`

| 키 | 타입 / 값 | 기본값 | 설명 |
|---|---|---|---|
| `streaming.requestMode` | `block` \| `pass-through` | `block` | `stream: true` 요청은 `pass-through`가 아닌 경우 `501`을 반환한다(pass-through 시 검사 없이 전달되며 audit 결정이 기록된다). Ollama의 `/api/chat`과 `/api/generate`는 `stream: false`가 명시되지 않으면 streaming으로 간주된다. Haechi는 현재 SSE/NDJSON을 검사하지 않는다(0.5 계획). |

## `limits`

| 키 | 타입 / 값 | 기본값 | 설명 |
|---|---|---|---|
| `limits.maxRequestBytes` | 양의 정수 | `1048576` | 요청 바디 크기 상한. 초과 시 `413`을 반환한다. 바디를 전부 버퍼링하지 않고 증분 방식으로 적용된다. |
| `limits.upstreamTimeoutMs` | 양의 정수 | `120000` | upstream 요청 타임아웃. 만료 시 `504 haechi_upstream_timeout`을 반환한다. 연결 실패 시에는 `502 haechi_upstream_unreachable`을 반환한다. |

## `policy`

탐지→결정의 핵심. [Detection type과 action](#detection-types--actions) 참고.

| 키 | 타입 / 값 | 기본값 | 설명 |
|---|---|---|---|
| `policy.mode` | `dry-run` \| `report-only` \| `enforce` | `dry-run` | 실제 적용되는 집행 모드(`policy.mode ?? mode`). |
| `policy.presets` | preset 이름 배열 | `["korean-pii", "secrets-only", "llm-redact"]` | 순서대로 병합되는 내장 action 집합. [Presets](#presets) 참고. |
| `policy.defaultAction` | action | `redact` | 명시적 매핑이 없는 탐지 type에 적용되는 action. |
| `policy.actions` | `{ <type>: <action> }` | `{ "card": "block" }` | type별 개별 재정의. 병합 시 **강화**는 가능하지만 약화는 불가([Action strength](#action-strength) 참고). `injection`은 설정하지 않으면 기본적으로 `allow`이다. |
| `policy.allowUnsafeOverrides` | boolean | `false` | 더 약한 action이 더 강한 action을 덮어쓰는 것을 허용한다. 기본적으로 꺼져 있으며, 활성화하면 안전 장치가 제거된다. |
| `policy.bundlePath` | 경로 | 미설정 | 인라인 정책 대신 서명된 policy bundle을 로드한다(`keys.keyFile`에 대해 검증됨). |

## `filters`

| 키 | 타입 / 값 | 기본값 | 설명 |
|---|---|---|---|
| `filters.customRules` | 규칙 객체 배열 | `[]` | 추가 탐지 규칙: `{ id, type, pattern, flags?, confidence? }`. 패턴은 ReDoS 검사를 통과해야 하며(≤500자, 중첩 한정자 없음, 역참조 없음), 안전하지 않으면 로드 시 거부된다. |

## `keys`

| 키 | 타입 / 값 | 기본값 | 설명 |
|---|---|---|---|
| `keys.provider` | `local` \| `external` | `local` | `local`은 소프트웨어 AES-256-GCM 키 파일을 사용한다(개발 전용). `external`은 키 자료를 포함하지 않으며, `createRuntime(config, { cryptoProvider })`를 통해 crypto provider를 주입해야 한다. |
| `keys.keyFile` | 경로 | `.haechi/dev.keys.json` | 로컬 키 파일(모드 `0600`). `haechi init --force`는 키를 교체하며, 기존 키는 `kid`로 기존 암호문/token이 복호화 가능하도록 퇴역 상태로 보관된다. |

## `audit`

| 키 | 타입 / 값 | 기본값 | 설명 |
|---|---|---|---|
| `audit.sink` | `jsonl` | `jsonl` | `jsonl`만 지원된다. |
| `audit.path` | 경로 | `.haechi/audit.jsonl` | SHA-256 hash chain 로그. `haechi audit-verify`로 검증한다. 평문/PII를 포함하지 않는다. |

## `tokenVault`

| 키 | 타입 / 값 | 기본값 | 설명 |
|---|---|---|---|
| `tokenVault.provider` | `local` | `local` | `local`만 지원된다. |
| `tokenVault.path` | 경로 | `.haechi/token-vault.json` | 암호화된 token 저장소(원자적 쓰기, 파일 락). |
| `tokenVault.revealPolicy` | `disabled` \| `local-dev` | `disabled` | **수동** reveal(`token-reveal`)을 허용할지 결정한다. 모든 reveal/purge 결정은 audit 기록된다. detokenization과는 독립적이다. |
| `tokenVault.retentionDays` | 양의 수 | `30` | Token TTL. 만료된 token은 vault 쓰기 시 또는 `token-purge --expired`로 삭제된다. |
| `tokenVault.deterministic` | boolean | `false` | 동일한 `(type, value)` → 동일한 token(도메인 분리된 파생 키로 HMAC). 멀티턴에 필요하다. **트레이드오프:** 동일한 값이 연결 가능해진다. |
| `tokenVault.deterministicTypes` | `null` \| 비어 있지 않은 문자열 배열 | `null` | `null`이면 deterministic 활성화 시 모든 type에 적용. 그렇지 않으면 열거된 type에만 determinism을 제한한다(예: `["email"]`). |
| `tokenVault.detokenizeResponses` | boolean | `false` | 해당 요청을 처리하며 발급한 token을 응답에서 복원한다. 동일 요청을 보호하며 발급된 token만 복원되며, `responseProtection.enabled`가 필요하다. 개수 단위로 audit 기록된다. |

## `privacy`

| 키 | 타입 / 값 | 기본값 | 설명 |
|---|---|---|---|
| `privacy.profile` | `null` \| `kr-pipa` \| `eu-gdpr` \| `us-general` | `null` | 집행 전에 지역별 기준 action 집합을 적용한다. 프로필은 명시적 action을 **강화**할 수는 있지만 약화할 수는 없다. 엔지니어링 기본값이며, 법적 자문이 아니다. |

## `mcp`

`mcp-stdio`와 `mcp-wrap`에 적용된다.

| 키 | 타입 / 값 | 기본값 | 설명 |
|---|---|---|---|
| `mcp.allowedMethods` | 비어 있지 않은 문자열 배열 | `["initialize", "tools/call", "resources/read", "prompts/get"]` | 클라이언트가 호출할 수 있는 method allowlist(`"*"`는 전체 허용). 서버가 먼저 시작하는 요청은 allowlist를 우회하지만 params는 여전히 보호된다. |
| `mcp.protectParams` | boolean | `true` | 요청 `params`를 보호한다. |
| `mcp.protectResults` | boolean | `true` | 응답 `result`를 보호한다(injection 휴리스틱도 실행). |
| `mcp.requireJsonRpc` | boolean | `true` | `jsonrpc: "2.0"`을 요구하며, 규격에 맞지 않는 메시지는 거부된다. |

## Detection type과 action

내장 탐지 `type` 값: `email`, `phone`, `kr_rrn`, `card`, `api_key`, `secret`, `injection`(응답 방향 휴리스틱, 기본 report-only). 커스텀 규칙으로 새로운 type을 추가할 수 있다.

Action(약한 것 → 강한 것 순):

| Action | 효과 |
|---|---|
| `allow` | 변경 없음(탐지 및 audit은 기록됨). |
| `redact` | `[REDACTED:<type>]`으로 교체한다. |
| `mask` | 부분 마스킹한다(값이 8자 이하이면 전체 마스킹). |
| `tokenize` | vault token으로 교체한다. token vault를 통해 복원 가능하다. |
| `encrypt` | 인라인 AES-256-GCM 봉투로 교체한다. |
| `block` | 전체 payload를 거부한다(`403`/`-32001`/exit 3). |

### Action strength

preset과 override(또는 privacy profile)가 충돌할 경우 **강한** action이 우선하며, `policy.allowUnsafeOverrides`가 `true`가 아니면 더 강한 action을 약화하려 할 경우 오류가 발생한다. 강도 순: `allow`(0) < `redact`/`mask`(1) < `tokenize`/`encrypt`(2) < `block`(3).

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

proxy는 CLI 플래그를 명시적으로 전달하지 않으면 loopback이 아닌 host를 거부한다 — 설정 파일에 `proxy.host: "0.0.0.0"`을 지정해도 의도적으로 시작되지 않는다:

```bash
haechi proxy --config haechi.config.json --host 0.0.0.0 --allow-remote-bind
```

**proxy는 아직 클라이언트 인증을 제공하지 않는다**(0.6 계획): 포트에 접근할 수 있는 누구든 upstream과 token round-trip 경로를 사용할 수 있다. `--allow-remote-bind`는 명시적인 네트워크 통제 하에서만 사용해야 한다 — 컨테이너 내에서 `0.0.0.0`으로 바인드하고 host 포트 매핑을 제한하거나(`-p 127.0.0.1:1016:1016`), 방화벽/VPN/인증 reverse proxy 뒤에 두어야 한다.

## 검증 요약

다음은 로드 시 오류(fail-closed)를 발생시킨다: 알 수 없는 `keys.provider`; 빈 `proxy.host`; 범위를 벗어난 `proxy.port`; `jsonl`이 아닌 `audit.sink`; `local`이 아닌 `tokenVault.provider`; 잘못된 `revealPolicy`; 양수가 아닌 `retentionDays`; boolean이 아닌 `deterministic`/`detokenizeResponses`; 비어 있거나 문자열이 아닌 `deterministicTypes`; 비어 있거나 문자열이 아닌 `mcp.allowedMethods`; boolean이 아닌 `mcp.*` 플래그; 알 수 없는 `privacy.profile`; 잘못된 `responseProtection.failureMode`; 양수가 아닌 `responseProtection.maxBytes`; 잘못된 `streaming.requestMode`; 양수가 아닌 `limits.*`; 알 수 없는 `target.type`/`adapter`; 안전하지 않은 커스텀 정규식; `allowUnsafeOverrides` 없이 action을 약화하려는 시도.
