# Haechi 설정 레퍼런스

- 문서 상태: Living document
- 기준 버전: 0.6.0

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
| `responseProtection.mode` | `dry-run` \| `report-only` \| `enforce` | `enforce` | 응답 방향의 집행 모드. **실제 LLM upstream엔 `report-only` 권장:** envelope 메타데이터(id, unix 타임스탬프 `created`, 긴 숫자 필드)가 PII/secret 모양으로 보일 수 있어 `enforce`면 정상 완성 응답을 502로 막는다. `report-only`도 탐지·감사·`detokenizeResponses`는 그대로 동작. (Haechi는 응답에서 자체 `[TOKEN:…]`/`[HAECHI_ENC:…]` 마커를 제외하고, phone 규칙도 맨 타임스탬프를 무시하며, 응답의 bare JSON number leaf는 검사하지 않으므로 실제 vLLM/Ollama 응답은 clean. 응답 *텍스트*까지 검사하려면 `enforce`가 더 엄격.) |
| `responseProtection.failureMode` | `fail-closed` \| `allow` | `fail-closed` | *검사 불가능한* 응답(비JSON, 잘못된 JSON, 압축)에 대한 처리 방식. `fail-closed`는 502를 반환하고, `allow`는 통과시킨다(audit 기록됨). |
| `responseProtection.allowNonJson` | boolean | `false` | 비JSON 응답을 검사 없이 통과시킨다. |
| `responseProtection.allowCompressed` | boolean | `false` | 압축 응답을 검사 없이 통과시킨다. |
| `responseProtection.maxBytes` | 양의 정수 | `1048576` | 응답 크기의 상한. `failureMode: allow` 상태에서도 적용되며, 크기를 초과한 응답은 항상 거부된다. |
| `responseProtection.scanNumbers` | boolean | `false` | 응답의 **bare JSON number leaf**에 탐지를 돌릴지 여부. 기본 off — 응답 숫자는 추론서버 메타데이터(`*_duration`, count, timestamp)라 검사하면 `card`/`kr_rrn` 오탐만 발생. 모델이 숫자 필드로 유출할 수 있다고 보는 엄격 위협모델에서만 `true`; `mode: report-only`와 함께 써서 차단 없이 감사만. 요청 방향은 항상 숫자 검사. |

## `streaming`

| 키 | 타입 / 값 | 기본값 | 설명 |
|---|---|---|---|
| `streaming.requestMode` | `block` \| `pass-through` \| `inspect` | `block` | `block`은 스트리밍 요청에 `501`을 반환한다; `inspect`는 bounded cross-frame 버퍼로 SSE/NDJSON 응답을 stream-filter한다; `pass-through`는 검사 없이 전달한다(감사됨). Ollama의 `/api/chat`과 `/api/generate`는 `stream: false`가 명시되지 않으면 streaming으로 간주된다. |
| `streaming.responseMode` | `dry-run` \| `report-only` \| `enforce` | `enforce` | 검사된 스트림에 적용되는 집행 모드(요청 방향과 독립적). |
| `streaming.maxMatchBytes` | 양의 정수 | `256` | inspect 시 cross-frame 매칭 윈도우. 이 크기의 tail을 보유하여 프레임에 걸친 탐지를 방출 전에 포착할 수 있다; 이 값보다 긴 단일 매칭은 프레임에 걸쳐 분할될 수 있다. |

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

## `auth`

| 키 | 타입 / 값 | 기본값 | 설명 |
|---|---|---|---|
| `auth.provider` | `none` \| `bearer` \| `external` | `none` | `none` = 인증 없음(identity null). `bearer` = 내장 token auth. `external`은 `createRuntime(config, { authProvider })`를 통해 `authProvider`를 주입해야 한다. |
| `auth.store` | 경로 | `.haechi/auth.json` | Bearer token 저장소(모드 `0600`). Token은 keyed-HMAC 해시로만 보관되며, 평문은 `haechi auth add` 실행 시 한 번만 표시된다. |
| `auth.allowedLabelKeys` | 문자열 배열 | `["team", "env", "tier", "role"]` | Token이 가질 수 있는 label 키; 값은 길이가 제한되며 PII를 포함하면 안 된다. |

## `policy` profiles & limits

기본 `policy` 위에 클라이언트별 통제를 레이어로 추가한다. [Named profiles](#named-profiles) 참고.

| 키 | 타입 / 값 | 기본값 | 설명 |
|---|---|---|---|
| `policy.profiles` | `{ <name>: { presets?, actions?, modelAllowlist?, rate? } }` | `{}` | Named profile; 각각 기본 policy를 재정의한다. |
| `policy.profileBinding` | `{ byScope?, byLabel?, default }` | 미설정 | identity scope/label(`"k=v"` 형태)을 profile 이름으로 매핑한다. `profiles`가 설정된 경우 `default`는 **필수**이며 가장 엄격한 profile이어야 한다(fail-closed). |
| `policy.modelAllowlist` | 문자열 배열 | 미설정 | 허용된 `model` 값(기본 레벨; profile별로도 설정 가능). 허용되지 않은 모델 → `403`. 비어 있거나 없으면 모두 허용. |
| `policy.rate` | `{ requestsPerMinute }` | 미설정 | identity별 요청 rate limit(기본 레벨 또는 profile별). 초과 시 → `429`. 인메모리, 프로세스별. |

### Named profiles

identity가 인증되면 **scope → label → `default`** 순으로 profile이 resolve된다; scope가 label보다 우선하며 첫 번째 매칭이 적용된다. `profiles`가 없거나 `auth.provider: none`인 경우 기본 policy가 적용된다. Resolve된 profile의 policy 엔진, `modelAllowlist`, `rate`가 해당 요청을 처리한다.

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

다음은 로드 시 오류(fail-closed)를 발생시킨다: 알 수 없는 `keys.provider`; 빈 `proxy.host`; 범위를 벗어난 `proxy.port`; `jsonl`이 아닌 `audit.sink`; `local`이 아닌 `tokenVault.provider`; 잘못된 `revealPolicy`; 양수가 아닌 `retentionDays`; boolean이 아닌 `deterministic`/`detokenizeResponses`; 비어 있거나 문자열이 아닌 `deterministicTypes`; 비어 있거나 문자열이 아닌 `mcp.allowedMethods`; boolean이 아닌 `mcp.*` 플래그; 알 수 없는 `privacy.profile`; 잘못된 `responseProtection.failureMode`; 양수가 아닌 `responseProtection.maxBytes`; boolean이 아닌 `responseProtection.scanNumbers`; 잘못된 `streaming.requestMode`; 잘못된 `streaming.responseMode`; 양수가 아닌 `streaming.maxMatchBytes`; 잘못된 `auth.provider`; 빈 `auth.store`; 문자열이 아닌 `auth.allowedLabelKeys`; 객체가 아닌 `policy.profiles`; 유효한 `default` 없는 `policy.profileBinding`; 문자열이 아닌 `policy.modelAllowlist`; 양수가 아닌 `policy.rate.requestsPerMinute`; 양수가 아닌 `limits.*`; 알 수 없는 `target.type`/`adapter`; 안전하지 않은 커스텀 정규식; `allowUnsafeOverrides` 없이 action을 약화하려는 시도.

# Satellite 운영자 설정 (0.9)

아래 두 섹션은 0.9에서 도입된 **독립적으로 배포되는 satellite 패키지** — `haechi-dashboard`와 `haechi-auth-oidc`의 설정을 다룬다. **이들은 코어 `haechi.config.json` / `normalizeConfig` 스키마의 키가 아니다.** 각 satellite는 팩토리 함수(`createDashboardServer(options)` / `createOidcSessionBroker(options)`)에 **옵션 객체**를 전달해 설정하며, 각자의 `normalizeDashboardConfig` / `normalizeOidcConfig`가 검증한다. 검증은 코어와 동일한 **strict, fail-closed** 원칙을 따른다: 알 수 없는 옵션 키는 오류를 발생시키고, 아래의 모든 필드는 fail-closed throw 조건을 명시한다. 소스: `satellites/dashboard/index.mjs`, `satellites/auth-oidc/index.mjs`. 위협 모델 커버리지: **P1-OPS-005**(dashboard audit 노출 / DNS-rebinding / remote bind), **P1-SEC-009**(broker session/login 보안), `docs/current/release-0.9-implementation-scope.md` §6 참고.

## `haechi-dashboard` (satellite)

audit JSONL과 그 hash-chain 상태를 제공하는 zero-dependency **read-only** audit 뷰어(`node:http`)다. 런타임이 아닌 **경로**를 받는다. `createDashboardServer(options)`로 설정하며, `normalizeDashboardConfig(options)`가 검증 후 실제 적용 설정을 반환한다. 소스: `satellites/dashboard/index.mjs`.

| 옵션 | 타입 / 값 | 기본값 | 설명 / fail-closed throw |
|---|---|---|---|
| `auditPath` | 비어 있지 않은 문자열 | **필수** | audit JSONL 경로. 누락되거나 비어 있지 않은 문자열이 아니면 throw. |
| `anchorPath` | string \| `null` | `null` | tail 절단 탐지를 위해 `verifyAuditChain`에 전달되는 anchor 스트림 경로. 존재하지만 비어 있지 않은 문자열이 아니면 throw. |
| `host` | 비어 있지 않은 문자열 | `127.0.0.1` | 바인드 주소. loopback이 아니면 `allowRemoteBind`와 아래 remote-bind 전제 조건을 모두 충족해야 한다. 존재하지만 비어 있거나 문자열이 아니면 throw. |
| `port` | 정수 0–65535 | `1018` | 리슨 포트; `0` = OS 할당 임시 포트(의도된 affordance). `[0,65535]` 정수가 아니면 throw. |
| `allowRemoteBind` | boolean | `false` | loopback이 아닌 `host`를 허용한다. boolean이 아니면 throw. 설정만으로는 충분하지 않다 — remote-bind 전제 조건 참고. |
| `sessionGuard` | object \| `null` | `null` | `authenticate(req) -> session\|null`과 선택적 `handlers` 맵을 구현하는 guard. object가 아니거나 `authenticate`가 함수가 아니면 throw. `handlers` 키는 고정된 broker 경로 `/auth/login`, `/auth/callback`, `/auth/logout`만 허용되며, 다른 키(특히 `/api/*`, `/healthz`, `/`)는 throw — guard가 audit 경로를 게이트에서 면제시키는 auth-bypass를 차단한다. `haechi-auth-oidc` broker를 주입하면 충족된다(아래 참고). |
| `window` | 정수 4096–67108864 | `1048576` | `/api/events`와 `/api/summary`의 tail-read 윈도우(최대 바이트). `[4096, 67108864]`(4 KiB–64 MiB) 정수가 아니면 throw. |
| `tlsContext` | object \| `null` | `null` | dashboard가 직접 HTTPS를 종단하기 위한 TLS 자료. object가 아니거나, non-null인데 **사용 가능한 자료**가 없으면 throw — `(key && cert)` 또는 `pfx`를 반드시 포함해야 한다(빈 `{}`는 거부되어 loopback이 아닌 plaintext 리스너를 green-light하지 못하게 한다). |
| `trustProxy` | string \| `null` | `null` | 신뢰하는 fronting-proxy 주소/CIDR를 명시한다. 문자열이 아니거나, 비어 있거나, falsy 모양 문자열(`"false"`/`"0"`)이면 throw. **`trustProxy`만으로는 loopback이 아닌 바인드를 절대 인가하지 못한다** — 실제 `tlsContext`만 가능하다. |

### 라우트

모든 라우트는 **GET/HEAD 전용**(그 외 method → `405`)이며, asset 맵은 in-code로 고정되어 있다(파일시스템 traversal 없음):

- `/api/events` — audit JSONL의 bounded tail read, 최신순. `limit`은 `[1,200]` 정수(기본 50); `cursor`는 opaque `auditIntegrity.sequence`(파일시스템 오프셋이 아님). 각 이벤트는 **recursive key-by-key allowlist projection**으로 재구성된다(blind spread 없음; identity는 scope/label/raw subject 없이 `subjectHash`/`issuerHash`만 보유). 요청된 페이지가 유지된 윈도우보다 오래되면 `windowExceeded`를 반환한다.
- `/api/chain` — `verifyAuditChain`을 감싸며, 파생된 `truncationDetected` boolean을 노출한다(raw 실패 reason은 **절대** 반환하지 않음). mtime+size 캐시(동시 재-walk 없음); 32 MiB 상한 초과 시 `{valid:null}`과 함께 `413`; `HEAD`는 walk를 강제하지 않고 헤더만 반환한다.
- `/api/summary` — tail 윈도우에 대한 집계 탐지 카운트(`byType`/`byAction`/`detectionCount`).
- `/healthz` — liveness 전용(`{status:"ok"}`); loopback 밖에서도 session 불필요.

### 보안 기본값

- **기본 loopback 바인드.** `host` 기본값은 `127.0.0.1`이며, loopback이 아닌 host 바인드는 코어의 `assertSafeProxyBind`(재-표현)를 재사용하고 `allowRemoteBind`를 요구한다.
- **Remote bind는 fail-closed.** loopback이 아닌 바인드는 `allowRemoteBind: true`, `sessionGuard`, **그리고** 유효한 `tlsContext`(dashboard가 직접 TLS 종단)를 **모두** 요구한다. `trustProxy`는 이를 충족하지 못한다 — loopback이 아닌 plaintext 리스너는 audit 데이터를 평문으로 제공하면서 HSTS를 방출하므로 거부된다. HSTS는 서버가 실제로 HTTPS를 제공할 때**만** 방출된다.
- **anti-DNS-rebinding Host allowlist**가 모든 요청(`/api/*`, `/healthz`, 모든 method 포함)의 무조건적 첫 게이트다; 잘못되거나 중복된 `Host` 헤더 → method 검사 이전에 `403`.
- **strict CSP + Trusted Types**(`require-trusted-types-for 'script'`, `textContent` 렌더링) 및 `X-Frame-Options: DENY`, `Cross-Origin-Resource-Policy`/`-Opener-Policy: same-origin`, `X-Content-Type-Options: nosniff`, `Cache-Control: no-store`; CORS 헤더는 의도적으로 절대 설정하지 않는다.
- **sessionGuard seam.** guard가 존재하면 모든 `/api/*` 라우트는 `authenticate()` 뒤에 게이트된다; 미인증 요청은 `401`(`302` 리다이렉트가 아님). auth-면제 집합은 고정된 broker-path allowlist와 guard가 선언한 handlers의 **교집합**(exact match)이다 — guard는 audit-data 라우트를 절대 면제시킬 수 없다.
- **generic 오류.** 5xx는 `{error:"internal"}`만 반환한다 — stack, OS code, 파일시스템 경로는 절대 없음. satellite-local fixed-window rate limiter(소스별 120 req/60s)가 `/api/*` 앞단을 막는다.

bin `haechi-dashboard`(workspace)가 서버를 구동하며, publish 워크플로는 `.github/workflows/dashboard-publish.yml`(태그 `dashboard-v<semver>`)이다. `peerDependencies: { haechi: ">=0.8.0 <1.0.0" }`.

## `haechi-auth-oidc` (satellite)

zero-dependency **interactive OIDC session broker**(authorization-code + PKCE) — dashboard의 사람-로그인 메커니즘이다. opaque server-side session을 생성하고, **주입을 통해 dashboard `sessionGuard` 계약을 충족한다**(`{ authenticate(req), handlers: { "/auth/login", "/auth/callback", "/auth/logout" } }`). per-request bearer validator가 **아니다**(그 역할은 `haechi-auth-jwt`에 남는다). `createOidcSessionBroker(options)`로 설정하며 `normalizeOidcConfig(options)`가 검증한다. 소스: `satellites/auth-oidc/index.mjs`. `peerDependencies: { haechi: ">=0.8.0 <1.0.0", haechi-auth-jwt: ">=0.2.0 <1.0.0" }`.

| 옵션 | 타입 / 값 | 기본값 | 설명 / fail-closed throw |
|---|---|---|---|
| `cryptoProvider` | `hmac()`를 가진 object | **필수** | PII-safe identity 해시와 `sessionIdHash`를 위한 keyed-HMAC를 제공한다. `hmac`이 함수가 아니면 throw. |
| `issuer` | HTTPS URL 문자열 | **필수** | OIDC issuer; 정확한 string-equal discovery와 single-origin endpoint 검사를 위해 pin된다. 누락되거나 `https`가 아니면 throw. |
| `clientId` | 비어 있지 않은 문자열 | **필수** | OAuth client id(ID-token의 기대 `aud`이기도 함). 누락/비어 있으면 throw. |
| `clientSecret` | string \| 생략 | 생략 | 존재 ⇒ confidential client; 생략 ⇒ public(PKCE 전용) client. 존재하지만 비어 있으면 throw. |
| `redirectUri` | 절대 URL 문자열 | **필수** | `https`(또는 carve-out 하의 **loopback** `http`)여야 하고, broker와 **same-origin**이며, path가 정확히 `/auth/callback`이어야 한다. 그 외에는 throw. |
| `scopes` | 문자열 배열 | `["openid"]` | `openid`는 강제 포함(dedup)되고, `offline_access`는 제거된다(refresh rotation은 0.9 범위 밖). 비어 있지 않은 문자열 배열이 아니면 throw. |
| `returnToAllowlist` | 문자열 배열 | `["/"]` | **relative same-origin** 복귀 경로의 allowlist(단일 `/`로 시작, scheme/host/`//`/백슬래시 없음). 배열이 아니거나 비적합 항목이 있으면 throw. |
| `sessionTtlSeconds` | 정수 1–2592000 | `28800`(8h) | 절대 session 수명. `[1, 2592000]`(30d 상한)을 벗어나면 throw. |
| `idleTtlSeconds` | 정수 1–2592000 | `1800`(30m) | idle 타임아웃(sliding `lastSeen`). 범위를 벗어나면 throw. |
| `maxAgeSeconds` | 정수 1–2592000 \| `null` | `null` | 설정 시 OIDC `max_age`를 보내고 `auth_time`이 `maxAge + skew` 이내일 것을 요구한다. 존재하지만 범위를 벗어나면 throw. |
| `tokenEndpointAuthMethod` | `client_secret_basic` \| `client_secret_post` | `client_secret_basic` | token-endpoint 인증 방식. 알 수 없는 값이거나, `clientSecret` 없이 설정되면 throw(confidential client에서만 유효). |
| `secureCookies` | `true` \| `false` \| `"auto"` | `"auto"` | externally-visible scheme로부터 쿠키 `Secure`/`__Host-` 하드닝을 강제하거나 자동 도출한다. 그 외 값이면 throw. |
| `trustProxy` | string \| `null` | `null` | TLS를 종단하는 fronting proxy를 명시한다; browser-facing scheme를 HTTPS로 간주한다(쿠키 하드닝에 반영). 문자열이 아니거나 비어 있으면 throw. |
| `algorithms` | 비어 있지 않은 문자열 배열 | `["RS256","ES256"]` | 허용된 JWS 알고리즘(verifier로 전달). 비어 있지 않은 배열이 아니면 throw. |
| `clockSkewSeconds` | 수 0–300 | (verifier 기본값) | ID-token 시간 클레임의 여유. `[0,300]`을 벗어나면 throw. |
| `prompt` | string \| `null` | `null` | 선택적 OIDC `prompt`. 존재하지만 비어 있거나 문자열이 아니면 throw. |
| `pendingTtlSeconds` | 정수 1–3600 | `600`(10m) | 로그인 완료 제한 시간(pre-auth 레코드 TTL). `[1,3600]`을 벗어나면 throw. |
| `pendingCap` | 정수 1–1000000 | `1024` | 동시 진행 중 로그인의 hard cap; store가 가득 차면 **새** 로그인을 거부하고 진행 중 auth는 절대 evict하지 않는다(fail-closed). 범위를 벗어나면 throw. |
| `rateLimitMax` | 정수 1–1000000 | `60` | 소스별 60s 윈도우당 `/auth/login`+`/auth/callback`. 범위를 벗어나면 throw. |
| `fetchTimeoutMs` | 정수 1–120000 | `5000` | egress별 타임아웃(discovery / token / JWKS). 범위를 벗어나면 throw. |
| `fetchImpl` / `lookupImpl` / `now` | 함수 | 주입/전역 | `fetch` / DNS `lookup` / clock seam 주입. 존재하지만 함수가 아니면 throw. |
| `sessionStore` | object | in-memory | opaque-id → session store; `get`/`set`/`delete`를 구현해야 한다. 존재하지만 비적합하면 throw. |
| `pendingStore` | object | in-memory | pre-auth 레코드 store; `set`/`take`(원자적 단일-사용 `take`)를 구현해야 한다. 존재하지만 비적합하면 throw. |
| `auditSink` | 함수 \| `record()`를 가진 object | 없음 | PII-safe 이벤트 sink. 존재하지만 함수도 `record()` 가진 object도 아니면 throw. |

### 쿠키 하드닝 의미

session은 **server-side 전용**이다 — 쿠키는 클레임/토큰이 아닌 opaque id만 보유한다. 두 개의 쿠키를 사용한다(pending 레코드를 바인딩하는 pre-auth 쿠키, 그리고 session 쿠키). externally-visible scheme가 HTTPS이면(`https` `redirectUri`, `secureCookies: true`, 또는 non-null `trustProxy`) 쿠키는 **`__Host-` prefix + `Secure` + `HttpOnly` + `SameSite=Lax`**(`Path=/`, `Domain` 없음)를 사용한다; `SameSite=Lax`는 IdP의 top-level GET이 `/auth/callback`으로 쿠키를 실어 보내게 한다. 문서화된 **loopback-`http` carve-out** 하에서는 `__Host-`/`Secure` 속성이 제거되고(plaintext 리스너는 `Secure`를 설정할 수 없음) bare 쿠키 이름을 사용한다. **HTTPS가 확인되지 않은 off-loopback broker는 construction에서 fail-closed**된다 — `Secure`/`__Host-` 쿠키는 평문으로 전송되지 않으므로 로그인이 조용히 깨질 것이다. `/auth/callback`에서 **새** session id가 발급된다(fixation 없음); `/auth/logout`은 non-GET, CSRF-헤더 게이트(`x-haechi-csrf`)이며 server-side 상태를 파괴한다. access token은 폐기된다(절대 저장하지 않음). audit 이벤트(`oidc.login.start`/`success`/`failure{reasonCode}`/`logout`/`session.evict`)는 keyed-HMAC `subjectHash`/`issuerHash`/`sessionIdHash` + `provider` + 거친 `reasonCode` + timestamp만 보유한다.

### dashboard와의 연결

broker를 dashboard의 `sessionGuard`로 주입한다:

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

broker의 `handlers` 맵은 dashboard가 auth 게이트에서 면제하는 고정 broker 경로에서만 마운트되며, 모든 `/api/*` 라우트는 `broker.authenticate(req)` 뒤에 게이트된다. publish 워크플로: `.github/workflows/auth-oidc-publish.yml`(태그 `auth-oidc-v<semver>`).
