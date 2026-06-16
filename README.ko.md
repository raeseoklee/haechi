# Haechi

<p align="center">
  <img src="https://raw.githubusercontent.com/raeseoklee/haechi/main/docs/assets/haechi.jpg" alt="해치 — 게이트를 지키며 디지털 방패로 검문하는 수호 영물" width="820">
</p>

[![npm](https://img.shields.io/npm/v/haechi)](https://www.npmjs.com/package/haechi)
[![CI](https://github.com/raeseoklee/haechi/actions/workflows/ci.yml/badge.svg)](https://github.com/raeseoklee/haechi/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![node](https://img.shields.io/node/v/haechi)](https://nodejs.org)
[![status](https://img.shields.io/badge/status-stable%201.2-brightgreen)](docs/current/api-stability.md)

[English](README.md) | **한국어**

Haechi는 LLM·MCP·vLLM·Ollama 및 에이전트 payload가 모델, 도구, 로그, proxy에 도달하기 전에 보호하는 자체 호스팅 AI 컨텍스트 집행 레이어입니다.

이름은 분별과 보호를 상징하는 한국의 수호 신수 해치에서 따왔습니다.

이 저장소는 로컬 개발, 보안 설계 검토, 자체 호스팅 통합 실험을 위한 것입니다. 컴플라이언스를 보장하지는 않습니다.

**1.0.0이 첫 stable 릴리스입니다.** 1.0부터 public API는 strict semver 하의 frozen 계약입니다. `package.json`의 `exports` 표면, CLI의 기계 판독 동작, audit event schema, config key shape이 모두 major 버전 계약의 일부이며, 문서화된 deprecation 정책과 in-minor 보안 예외 하나가 함께 적용됩니다. [`docs/current/api-stability.md`](docs/current/api-stability.md)를 참고하세요. `haechi-*` 위성은 pre-1.0으로 유지되며 core와 독립적으로 버저닝됩니다([위성 패키지](#위성-패키지) 참고).

현재 범위는 로컬 도입에 초점을 맞춥니다.

- `haechi init`: 로컬 키, 샘플 설정, audit 경로를 생성합니다
- `haechi protect`: OpenAI 호환 JSON payload를 검사하고 보호합니다
- `haechi report`: 원시 payload 없이 audit 이벤트를 요약합니다
- `haechi proxy`: 기존 LLM 호출 앞에 두는 로컬 HTTP JSON proxy를 실행합니다
- `haechi status`: 현재 설정에서 무엇이 보호되고 무엇이 보호되지 않는지 보여 줍니다
- `haechi audit-verify`: audit hash chain을 검증하고 head hash를 출력합니다
- `haechi mcp-wrap -- <command>`: MCP 서버를 양방향 stdio 보호로 감쌉니다

## 데모

<p align="center">
  <img src="https://raw.githubusercontent.com/raeseoklee/haechi/main/docs/assets/haechi-demo.gif" alt="Haechi 라이브 end-to-end 데모(실제 모델): 탐지 후 tokenize/mask/redact, 모델은 마스킹된 전화만 반복, 무평문 감사, 라이브 readiness + Prometheus metrics, 카드 차단" width="900">
</p>

위 녹화는 실제 self-hosted 모델(vLLM의 Qwen3.6-35B)에 붙인 **라이브** end-to-end 실행입니다(`enforce` 모드). 모델에게 받은 전화번호를 그대로 반복하라고 시키면 — 진짜 번호는 모델에 도달조차 하지 않았으므로 **마스킹된** 형태만 돌려줄 수 있습니다. 무평문 감사, 라이브 `/__haechi/ready` + `/__haechi/metrics`, upstream 호출 전에 fail-closed로 차단되는 카드도 함께 보여줍니다.

직접 실행해 보십시오 — 백엔드 없이 재현 가능한 스텁 버전:

```bash
npm run demo
```

…또는 본인의 OpenAI-호환 서버 상대로:

```bash
HAECHI_LIVE_UPSTREAM=http://127.0.0.1:8000 node examples/local-proxy-demo/live-demo.mjs
```

[`examples/local-proxy-demo/`](examples/local-proxy-demo/)를 참고하십시오.

## 설치

```bash
npm install -g haechi
haechi init
```

설치 없이 실행하려면:

```bash
npx haechi init
```

## 빠른 시작

이 저장소를 클론한 뒤:

```bash
npm test
npm run demo:init
npm run demo:protect
npm run demo:report
```

기본 설정은 `dry-run` 모드로 실행됩니다. 민감한 값을 탐지하고 audit 메타데이터를 기록하지만, 정책 모드를 바꾸기 전까지는 아웃바운드 payload를 수정하지 않습니다.

`npm run demo:init`은 `haechi.config.json`과 `.haechi/dev.keys.json`을 로컬에 생성합니다. 생성된 키 파일은 로컬 개발 전용입니다. 코어 자체에는 운영용 KMS/HSM/Vault 키 provider가 없으며, KMS·Vault 기반 키 custody는 `haechi-crypto-kms` 위성이 외부 `cryptoProvider` 계약을 통해 제공합니다. 비밀 값이 없는 템플릿은 `haechi.config.example.json`에서 확인할 수 있습니다.

## Local Proxy

```bash
node packages/cli/bin/haechi.mjs proxy --config haechi.config.json
```

기존 HTTP JSON 클라이언트를 `http://localhost:11016`으로 향하게 하고, `haechi.config.json`에서 `target.upstream`을 설정합니다. 다른 로컬 포트를 쓰려면 설정의 `proxy.port`를 바꾸거나 `--port`를 전달하세요.

proxy는 기본적으로 loopback에 바인딩됩니다. `0.0.0.0`, `::`, 또는 그 밖의 non-loopback 호스트에 바인딩하려면 `--allow-remote-bind`를 명시적으로 전달해야 합니다. 이 플래그는 명시적인 네트워크 접근 통제가 있을 때만 사용하세요.

`stream: true`인 스트리밍 요청은 기본적으로 차단됩니다. `streaming.requestMode`를 `inspect`로 설정하면 SSE/NDJSON 응답을 stream-filter합니다(bounded sliding buffer가 프레임에 걸쳐 나뉜 PII도 잡아냅니다. `streaming.maxMatchBytes` 참고). 호출자가 보호되지 않는 스트리밍을 명시적으로 감수하는 경우에만 `pass-through`로 설정하세요.

Ollama의 `/api/chat`과 `/api/generate`는 `stream` 필드가 없으면 기본적으로 스트리밍하므로, proxy는 `stream: false`가 명시되지 않는 한 이 요청들을 스트리밍으로 간주합니다.

upstream 요청은 `limits.upstreamTimeoutMs`(기본값 120000) 이후 타임아웃되며 `504 haechi_upstream_timeout`으로 실패합니다.

## Local Inference Servers

Haechi는 OpenAI 호환 서버, vLLM, Ollama, llama.cpp, Anthropic Messages API, 그리고 Google Gemini API용 프로토콜 adapter 프리셋을 제공합니다.

```json
{
  "target": {
    "type": "vllm-openai",
    "upstream": "http://127.0.0.1:8000"
  },
  "policy": {
    "mode": "enforce",
    "presets": ["local-inference"]
  },
  "responseProtection": {
    "enabled": true,
    "mode": "enforce",
    "failureMode": "fail-closed"
  }
}
```

그런 다음 OpenAI 호환 클라이언트를 `http://127.0.0.1:11016/v1`으로 향하게 합니다. Ollama 네이티브 API는 `target.adapter: "ollama"`를 사용하고 proxy를 통해 `/api/chat` 또는 `/api/generate`를 호출하세요. Claude는 `target.type: "anthropic"`을 설정하고 `/v1/messages`(또는 `/v1/messages/count_tokens`, `/v1/complete`)를 호출하세요. 클라이언트의 `x-api-key`/`anthropic-version` 헤더는 upstream으로 전달됩니다(upstream 헤더 허용목록에 포함되어 있습니다). Gemini는 `target.type: "gemini"`를 설정하고 모델이 경로에 포함된 엔드포인트 `/v1beta/models/{model}:generateContent`(또는 `:streamGenerateContent`, `:countTokens`, `:embedContent`, `:batchEmbedContents`)를 호출하세요. 클라이언트의 `x-goog-api-key`(또는 `?key=`)는 upstream으로 전달됩니다. proxy는 명시적 허용목록의 헤더만 전달하고 클라이언트의 주변 credential은 절대 전달하지 않습니다 — [Gateway 인증과 upstream 인증의 분리](#gateway-인증과-upstream-인증의-분리-헤더-전달)를 참고하세요.

## 토큰 왕복

tokenization을 쓰면 모델은 안정적인 token을 받고 호출자는 평문을 돌려받습니다.

```json
{
  "policy": { "mode": "enforce", "actions": { "email": "tokenize" } },
  "responseProtection": { "enabled": true, "mode": "enforce" },
  "tokenVault": {
    "deterministic": true,
    "detokenizeResponses": true
  }
}
```

- `tokenVault.deterministic`(기본값 `false`): 같은 값이 항상 같은 token으로 매핑됩니다(로컬 키에서 파생한 도메인 분리 키로 HMAC하며, 원시 AES 키는 쓰지 않습니다). 다시 전송된 대화 기록이 같은 token으로 재tokenize되므로 멀티턴 채팅에 필요합니다. **트레이드오프:** 같은 값을 요청 간에 연결할 수 있게 됩니다. `deterministicTypes`(예: `["email"]`)로 determinism을 선택한 type으로만 제한할 수 있습니다.
- `tokenVault.detokenizeResponses`(기본값 `false`): 같은 요청을 보호하는 동안 발급된 token**만** 그 요청의 응답에서 복원합니다. 다른 클라이언트나 요청의 token은 복원하지 않습니다. `revealPolicy`와는 독립적이며, 모든 복원은 개수만 audit에 기록하고 값은 기록하지 않습니다. `responseProtection.enabled`가 필요합니다.

## MCP Wrap

stdio MCP 서버를 감싸 양방향 트래픽을 필터링합니다. MCP 클라이언트 설정에서 커맨드만 바꾸면 됩니다.

```json
{
  "mcpServers": {
    "some-server": {
      "command": "npx",
      "args": ["-y", "haechi", "mcp-wrap", "--config", "/path/haechi.config.json", "--", "npx", "some-mcp-server"]
    }
  }
}
```

클라이언트→서버 요청은 `mcp.allowedMethods` allowlist와 params 보호를 거치고, 서버→클라이언트 결과는 params/result 보호와 injection 휴리스틱(아래 참고)을 적용받습니다. 거부된 요청은 클라이언트에 응답되고 서버에는 도달하지 않습니다. stderr과 exit code는 그대로 전달됩니다.

## Injection Detection (Preview)

응답과 tool result 텍스트는 간접 prompt injection(지시문 재정의, 역할 재할당, prompt 마커, 사용자에게 숨기기, 은밀한 tool 유도)을 찾는 휴리스틱 규칙으로 검사됩니다. `injection` type은 **기본적으로 report-only**입니다. 탐지 결과는 audit 로그에 기록하지만 수정하거나 차단하지는 않습니다. 신호를 신뢰할 수 있다고 판단되면 명시적으로 격상하세요.

```json
{ "policy": { "actions": { "injection": "block" } } }
```

이 휴리스틱은 prompt injection을 완전히 막아 주지는 않습니다. `docs/current/threat-model.md`를 참고하세요.

## 인증 및 클라이언트별 통제

하나의 host 앞에 여러 클라이언트/에이전트를 두는 경우, bearer auth를 켜고 각 클라이언트를 policy profile에 바인딩합니다. Token은 별도의 `.haechi/auth.json`(0600)에 keyed-HMAC 해시로만 저장됩니다.

```bash
haechi auth add --type service --scope team:eng --label env=prod   # 토큰을 한 번만 출력
haechi auth list                                                   # 토큰은 표시하지 않음
haechi auth revoke <id>
```

```json
{
  "auth": { "provider": "bearer" },
  "policy": {
    "mode": "enforce", "presets": ["llm-redact"],
    "profiles": {
      "strict":   { "presets": ["strict-block"] },
      "internal": { "presets": ["llm-redact"], "modelAllowlist": ["llama3"], "rate": { "requestsPerMinute": 120 } }
    },
    "profileBinding": { "byScope": { "team:eng": "internal" }, "default": "strict" }
  }
}
```

- **Bearer auth**(`auth.provider: bearer`): 클라이언트가 `Authorization: Bearer <token>`을 보냅니다. 없거나 잘못되었거나 revoke된 경우 → `401`(바디를 읽지 않고 upstream에도 도달하지 않습니다). `provider: none`(기본값)은 동작을 그대로 두며, `external`은 주입된 `authProvider`가 필요합니다.
- **Named profiles**: 인증된 identity는 **scope → label → 필수 `default`** 순으로 profile에 매핑됩니다(매칭이 없거나 익명이면 `default`로 fail-closed). Profile은 기본 policy를 덮어쓰며 자체 `modelAllowlist`와 `rate`를 가질 수 있습니다.
- **Model allowlist**: 허용되지 않은 `model`을 가진 요청 → `403`.
- **Rate limit**: identity별 분당 요청 수 → `429`(인메모리, 프로세스별).
- Audit 이벤트에는 **PII-safe** `identity`(keyed-HMAC subject/issuer이며 원시 값이 아닙니다)와 매핑된 `profile`이 들어가고, `auth_denied`/`model_not_allowed`/`rate_limited` 결정에는 credential이 포함되지 않습니다. `/__haechi/health`는 인증 없이 접근할 수 있습니다.

### Gateway 인증과 upstream 인증의 분리 (헤더 전달)

Haechi는 **gateway-클라이언트 인증**과 **upstream-제공자 인증**을 분리하며, 요청 헤더를 모델 upstream으로 무조건 전달하지 않습니다. proxy는 **기본 차단(default-drop) 허용목록**을 적용합니다. 알려진 안전한 헤더 집합만 모델 제공자 경계로 넘어가고, 클라이언트의 주변(ambient) credential은 폐기됩니다.

- **`auth.provider: bearer` / `external` / `plugin` (gateway가 클라이언트를 인증).** 클라이언트의 `Authorization` 헤더는 Haechi가 클라이언트 인증에 사용한 **gateway credential**이므로 **폐기됩니다** — upstream으로 절대 전달되지 않습니다. 이로써 gateway 토큰이 신뢰 경계를 넘어 모델 제공자로 유출되는 것을 막습니다.
- **`auth.provider: none` (gateway 인증 없음).** 클라이언트의 `Authorization` 헤더는 **upstream 제공자 키**로 간주되어 **전달됩니다**(클라이언트가 `Authorization`에 모델 API 키를 넣는 OpenAI 호환 pass-through 패턴).
- **모드와 무관하게 항상 폐기:** `Cookie`, `Set-Cookie`, `Proxy-Authorization`, hop-by-hop 헤더(`Connection`, `Keep-Alive`, `TE`, `Trailer`, `Transfer-Encoding`, `Upgrade`), 그리고 허용목록에 없는 모든 헤더.
- **항상 전달(제공자/어댑터 헤더):** `x-api-key`, `anthropic-version`, `anthropic-beta`, `x-goog-api-key`, `openai-organization`, `openai-beta`, `accept`, `accept-language`, `user-agent`, 그리고 `content-type`(`application/json`으로 재작성).
- **예외 통로:** 특이한 upstream이 추가 헤더를 요구하면 그 소문자 이름을 `target.forwardHeaders`에 나열하십시오(예: `"forwardHeaders": ["x-tenant-id"]`). 이는 허용목록을 **추가로 넓히기만** 할 수 있으며, 항상 폐기되는 credential/hop-by-hop 헤더를 다시 켤 수는 없습니다(해당 이름은 설정 시점에 fail-closed로 거부됩니다).

JWT/JWKS 인증과 KMS 기반 key custody(및 기타 선택 기능)는 **`haechi-*` 위성 패키지**로 제공됩니다 — 아래 [위성 패키지](#위성-패키지)를 참고하세요.

## 위성 패키지

선택 기능은 **npm에 독립 발행되는 `haechi-*` 패키지**로 제공됩니다 — 각각 core와 별도로 버저닝되고, 기본적으로 `node:` 전용이며(KMS나 Redis 클라이언트 같은 무거운 SDK는 optional peer), `haechi` peer 범위를 `>=0.8.0 <2.0.0`으로 선언합니다(상한이 core major를 따라가므로 core minor가 위성 설치를 깨뜨리지 않습니다).

**위성과 함께 core를 반드시 설치하세요** — `haechi`는 **번들되지 않은 peer dependency**이므로, 위성만으로는 동작하지 않습니다:

```bash
npm install haechi haechi-<satellite>
```

| 패키지 | 추가하는 기능 |
|---|---|
| [`haechi-auth-jwt`](satellites/auth-jwt/) | 헤드리스 JWKS bearer(JWT) `authProvider`. 재사용 가능한 JWS 검증기(`createJwtVerifier`)를 추가로 export합니다. |
| [`haechi-auth-oidc`](satellites/auth-oidc/) | 대화형 OIDC 세션 브로커(authorization-code + PKCE) — 대시보드의 사람 로그인. `haechi-auth-jwt`를 재사용합니다. |
| [`haechi-crypto-kms`](satellites/crypto-kms/) | `keys.provider: external`용 envelope 암호화 `cryptoProvider` — AWS, GCP(`./gcp`), Azure(`./azure`), HashiCorp Vault Transit(`./vault`, `node:` 전용) 백엔드. |
| [`haechi-dashboard`](satellites/dashboard/) | audit 로그와 hash chain 상태를 보는 zero-dependency 읽기 전용 audit 뷰어(`node:http`). |
| [`haechi-ratelimit-redis`](satellites/ratelimit-redis/) | `providers.rateLimiter` 주입 시임을 통한 다중 복제용 공유 저장소(Redis 기반) `rateLimiter`. |

각 패키지의 README가 사용법과 정확한 peer 요구사항을 다룹니다. 위성의 무거운 SDK는 해당 백엔드를 쓸 때만 설치되는 optional peer라 core는 zero-dependency로 유지됩니다.

## 설정

`haechi init`은 `haechi.config.json`을 생성하며, 비밀 값이 없는 템플릿은 `haechi.config.example.json`에 있습니다. 모든 키는 fail-closed로 검증되어, 알 수 없거나 형식이 잘못된 값은 시작을 거부합니다.

| 키 | 기본값 | 설명 |
|---|---|---|
| `mode` / `policy.mode` | `dry-run` | `dry-run`과 `report-only`는 탐지와 audit만 하고, `enforce`는 변환/차단을 적용합니다. `policy.mode`가 `mode`보다 우선합니다 |
| `target.type` / `target.adapter` | `llm-http` / `openai-compatible` | upstream 프로토콜: `openai-compatible`, `vllm-openai`, `ollama`, `llama-cpp`, `anthropic`, `gemini`. 알 수 없는 type은 fail-closed로 처리됩니다 |
| `target.upstream` | `http://127.0.0.1:9999` | proxy가 요청을 전달하는 유일한 upstream(절대 URL 요청 대상은 거부됩니다) |
| `target.forwardHeaders` | `[]`(미설정) | 내장 허용목록 외에 upstream으로 전달할 추가 소문자 헤더 이름. 추가만 가능하며, 항상 폐기되는 credential/hop-by-hop 헤더를 다시 켤 수는 없습니다 |
| `proxy.host` / `proxy.port` | `127.0.0.1` / `11016` | proxy 바인드 주소. 아래 remote 바인딩 참고 |
| `responseProtection.enabled` | `false` | upstream JSON 응답을 검사합니다. `failureMode: fail-closed`는 비JSON/압축/대용량 응답을 거부합니다 |
| `responseProtection.maxBytes` | `1048576` | 응답 크기 상한 — `failureMode: allow`에서도 적용됩니다 |
| `streaming.requestMode` | `block` | `block`은 스트리밍을 501로 차단하고, `inspect`는 SSE/NDJSON 응답을 stream-filter하며, `pass-through`는 검사 없이 전달합니다(audit 기록). Ollama chat/generate는 `stream: false`가 없으면 스트리밍으로 간주됩니다 |
| `streaming.responseMode` | `enforce` | 검사된 스트림에 적용되는 enforcement 모드(`dry-run`/`report-only`/`enforce`) |
| `streaming.maxMatchBytes` | `256` | cross-frame 매칭 윈도우. 이보다 긴 단일 매치는 프레임에 걸쳐 나뉠 수 있습니다 |
| `limits.maxRequestBytes` | `1048576` | 요청 바디 상한(초과 시 413) |
| `limits.upstreamTimeoutMs` | `120000` | upstream 타임아웃(만료 시 504) |
| `policy.presets` | `korean-pii`, `secrets-only`, `llm-redact` | 병합되는 프리셋 action. 강화는 가능하지만 약화는 불가합니다 |
| `policy.actions` | `card: block` | type별 action: `allow`/`redact`/`mask`/`tokenize`/`encrypt`/`block` |
| `filters.customRules` | `[]` | 추가 정규식 규칙(ReDoS 검사: 중첩 한정자/역참조 불가) |
| `keys.provider` / `keys.keyFile` | `local` / `.haechi/dev.keys.json` | 개발 전용 소프트웨어 키(0600). `external`은 프로그래밍 방식으로 crypto provider를 주입해야 합니다 |
| `audit.path` | `.haechi/audit.jsonl` | hash chain JSONL audit 로그. `haechi audit-verify`로 검증합니다 |
| `tokenVault.revealPolicy` | `disabled` | 수동 reveal 게이트(`local-dev`로 활성화하며, 모든 결정이 audit에 기록됩니다) |
| `tokenVault.retentionDays` | `30` | 만료된 token은 vault 쓰기 시 또는 `haechi token-purge --expired`로 삭제됩니다 |
| `tokenVault.deterministic` / `deterministicTypes` / `detokenizeResponses` | `false` / `null` / `false` | 토큰 왕복(위 참고) |
| `privacy.profile` | `null` | `kr-pipa`, `eu-gdpr`, `us-general` 기준 action(강화 전용) |
| `mcp.allowedMethods` | `initialize`, `tools/call`, `resources/read`, `prompts/get` | `mcp-stdio`/`mcp-wrap`에서 클라이언트가 호출할 수 있는 method allowlist |
| `auth.provider` / `auth.store` | `none` / `.haechi/auth.json` | `none`/`bearer`/`external`. Bearer token은 keyed-HMAC 해시로 저장됩니다(0600) |
| `policy.profiles` / `policy.profileBinding` | — | 클라이언트별 named policy profile. scope → label → 필수 `default` 순으로 바인딩됩니다 |
| `policy.modelAllowlist` / `policy.rate` | — | 허용된 모델 이름(그 외 403), identity별 분당 요청 rate limit(429). profile별로도 설정할 수 있습니다 |

위 표는 빠른 참고용입니다. 키별 전체 레퍼런스(타입, 검증 규칙, 프리셋, action 강도, 자주 쓰는 설정)는 [`docs/current/configuration.md`](docs/current/configuration.md)에 있으며, CLI에서도 축약본을 출력합니다.

```bash
haechi config        # 설정 가이드
haechi help          # 모든 커맨드
haechi help proxy    # 특정 커맨드
haechi status        # 현재 설정의 실제 적용 상태
```

### loopback 밖으로 바인딩 (0.0.0.0)

proxy는 CLI 플래그를 명시적으로 전달하지 않으면 non-loopback 호스트를 거부합니다. 설정 파일에 `proxy.host: "0.0.0.0"`만 지정해도 의도적으로 시작되지 않습니다(설정 파일을 복사하더라도 게이트웨이가 저절로 노출되지 않도록 하기 위함입니다).

```bash
haechi proxy --config haechi.config.json --host 0.0.0.0 --allow-remote-bind
```

**proxy는 bearer 클라이언트 인증을 제공합니다**(`auth.provider: bearer`, 0.6에서 출시). 해시 기반 token 저장소, identity별 policy profile, model allowlist, identity별 rate limit을 함께 제공합니다([인증 및 클라이언트별 통제](#인증-및-클라이언트별-통제) 참고). 기본값 `auth.provider: none`은 proxy를 인증 없이 두므로, `none`에서는 포트에 접근할 수 있는 사람은 누구나 upstream과 token round-trip 경로를 쓸 수 있습니다. 내장 rate limit은 단일 프로세스(인메모리, 프로세스별)이므로, 여러 replica는 공유 limiter를 앞에 두어야 합니다. `--allow-remote-bind`는 어느 경우에도 명시적인 네트워크 통제가 있을 때만 사용하십시오.

- **컨테이너**: 컨테이너 안에서 `0.0.0.0`으로 바인딩하는 것은 일반적인 패턴입니다 — 포트 매핑에서 노출을 제한하세요(예: `-p 127.0.0.1:11016:11016`)
- **LAN/원격**: 방화벽, VPN(예: Tailscale), 또는 인증 reverse proxy를 앞에 두세요

## Privacy Profiles

Haechi는 로컬 정책 부트스트래핑을 위한 지역별 기본 Privacy Profiles를 제공합니다.

- `kr-pipa`
- `eu-gdpr`
- `us-general`

`haechi.config.json`에서 `privacy.profile`을 설정하면 집행 전에 해당 프로필의 기본 action이 적용됩니다. 이 프로필은 엔지니어링 기본값이며, 법적 자문이 아닙니다.

## 보안 노트

- 이 프로젝트는 컴플라이언스를 보장하지 않습니다.
- 로컬 crypto provider는 Node `crypto`의 AES-256-GCM과 로컬 소프트웨어 키 파일을 사용합니다.
- Audit 이벤트에는 원시 prompt, tool result, secret, PII 값이 들어가서는 안 됩니다.
- 알 수 없거나 잘못된 정책/설정 오류는 집행 경로에서 fail-closed로 처리됩니다.
- Response protection은 명시적인 allow 정책이 없으면 비JSON, 잘못된 JSON, 압축, 대용량 응답에 대해 fail-closed로 처리됩니다.
- Token reveal과 purge 결정은 audit 로그에 기록됩니다(token id와 결정만 기록하고 평문은 기록하지 않습니다). 만료된 token은 vault 변경 시 또는 `haechi token-purge --expired`로 제거됩니다.
- `haechi init --force`는 로컬 키를 교체합니다. 기존 키는 `retired` 상태로 보관되어, 기존 암호문과 token vault 레코드를 `kid`로 복호화할 수 있습니다.
- Privacy profile은 명시적으로 더 엄격한 사용자 action을 강화할 수는 있어도 약화할 수는 없습니다.
- 탐지는 문자열 값, JSON 숫자(예: 카드 번호), 객체 키 이름을 검사합니다. Base64/URL 인코딩된 값과 URL 쿼리 스트링은 검사하지 않습니다.
- Audit tail truncation: `audit.anchor.mode: file`을 설정하면(추가 전용/별도 미디어에서) `haechi audit-verify --anchor`가 마지막 anchor 이후의 꼬리 레코드 삭제를 탐지합니다. 같은 쓰기 가능 파일시스템에서는 공격자가 두 파일을 함께 잘라낼 수 있습니다.
- Key custody: `keys.provider: external`은 주입된 `cryptoProvider`를 허용하며, `assertCryptoProviderConformance`로 adapter를 검증합니다. envelope 암호화 KMS adapter는 `haechi-crypto-kms` 위성(`satellites/crypto-kms/`)이 제공합니다.
- Release integrity: 배포된 tarball에는 npm provenance attestation이 포함되고, GitHub release asset에는 sigstore attestation과 `SHA256SUMS`가 추가됩니다(`gh attestation verify`와 `node scripts/release-checksums.mjs --check`로 검증합니다).
- 1.0 authProvider 플러그인 샌드박스는 서명된 플러그인을 `worker_threads` worker에서 실행합니다. 이는 메모리/크래시 격리와 데이터 최소화(credential 슬라이스만 넘어가고, host가 keyed-HMAC identity를 만듭니다)일 뿐 capability 샌드박스가 **아닙니다**. 악의적인 *서명된* 플러그인은 여전히 `fs`/`net`을 써서 받은 credential을 유출할 수 있습니다. load-bearing 통제는 trust gate(Ed25519 서명 + 운영자 allowlist + 버전 pin/floor + revocation)입니다. **1.1이 이 잔존 위험을 닫습니다.** opt-in `process-isolated` 런타임(`auth.plugin.isolation: "process"`)은 서명된 플러그인을 Node 권한 모델(`--permission`, 부여 0) 하의 자식 프로세스에서 실행하며, fs/net/exec/worker가 커널 수준에서 거부되고, 모든 stdio가 무시되며, `data:` URL로 로드(파일시스템 권한 없음)됩니다 — 진정한 capability 강제입니다. `--allow-net`을 강제하는 Node가 필요하고 그렇지 않으면 **fail closed**합니다. 변경되지 않은 `worker_threads` 모드가 기본으로 유지됩니다. 기본 배선은 dependency injection(`createRuntime(config, providers)`)으로 유지됩니다.
- 자체 네트워크 통제와 인증을 앞에 두지 않은 채 Haechi를 인터넷에 노출된 운영 LLM 게이트웨이로 사용하지 마세요.

## 현재 범위

0.1 빠른 시작 범위는 `docs/current/mvp-0.1-implementation-scope.md`에 설명되어 있습니다.

0.2는 로컬 TokenVault, 서명된 policy bundle 커맨드, 플러그인 매니페스트 검증, MCP stdio JSON-RPC 라인 필터 스켈레톤을 추가합니다. `docs/current/release-0.2-implementation-scope.md` 참고.

0.3은 로컬 inference 프로토콜 adapter, 선택적 JSON 응답 보호, npm 패키지 메타데이터, 배포 준비 export를 추가합니다. `docs/current/release-0.3-implementation-scope.md` 참고.

0.3.1은 릴리스 안전 게이트, 응답 fail-closed 동작, audit hash chaining, token reveal 거버넌스, provider injection, privacy profile, CI/SBOM/provenance 워크플로 스캐폴딩, 그리고 전용 위협/공유 책임/API 안정성 문서를 추가합니다.

0.3.2는 보안 강화 릴리스이자 첫 npm 개발자 프리뷰 대상입니다. Ollama 암묵적 스트리밍 fail-closed 처리, 감사된 token reveal/purge, 보존 기간 purge, kid 기반 키 교체, 도메인 분리 policy bundle 서명, JSON 숫자/객체 키 탐지, upstream 타임아웃, stale lock 복구, non-enforcing 모드 경고를 담았습니다. `docs/current/release-0.3.2-hardening-scope.md` 참고.

0.4.0은 token round-trip(deterministic tokenization + 요청 스코프 응답 detokenization), `mcp-wrap` 양방향 MCP 필터, `status` 및 `audit-verify` 커맨드, report-only injection detection 휴리스틱을 추가하고, 0.6 인증을 위한 PII-safe `identity`/`authProvider` 계약을 예약합니다. `docs/current/release-0.4-implementation-scope.md` 참고.

0.5.0은 SSE/NDJSON 스트리밍 응답 검사를 추가합니다. `streaming.requestMode: "inspect"`가 bounded sliding buffer로 응답을 stream-filter하여 프레임에 걸쳐 나뉜 PII도 잡아냅니다(`streaming.maxMatchBytes`). `docs/current/release-0.5-implementation-scope.md` 참고.

0.6.0은 인증과 클라이언트별 통제를 추가합니다. 해시 기반 token 저장소와 `haechi auth` CLI를 갖춘 내장 bearer auth, identity scope/label로 바인딩되는 named policy profile, model allowlisting, identity별 rate limiting을 제공하며, audit 로그에는 PII-safe identity가 기록됩니다. `docs/current/release-0.6-implementation-scope.md` 참고.

0.7.0은 운영 강화(ops-hardening) 릴리스입니다. 꼬리 절단을 탐지하는 audit head-hash anchoring(`audit.anchor`), `assertCryptoProviderConformance`와 reference KMS adapter를 포함한 강화된 외부 `cryptoProvider` 계약, 서명·체크섬된 GitHub release artifact를 담았습니다. `docs/current/release-0.7-implementation-scope.md` 참고.

0.8.0은 `haechi-*` 에코시스템을 세웁니다. npm workspaces 모노레포(core는 unscoped `haechi`를 유지하고, zero runtime dependency를 패킹 매니페스트 CI 게이트로 강제)와 첫 두 위성 — [`haechi-crypto-kms`](satellites/crypto-kms/)(실제 AWS KMS 클라이언트 기반 envelope 암호화. AWS SDK는 optional peer)와 [`haechi-auth-jwt`](satellites/auth-jwt/)(헤드리스 JWKS bearer 검증, `node:` 전용)를 추가합니다. 각각 자체 provenance + sigstore attest 워크플로로 독립 발행합니다. `docs/current/release-0.8-implementation-scope.md` 참고.

0.9.0은 관측성(observability) + 대화형 인증 테마입니다. 두 개의 새 위성 — [`haechi-dashboard`](satellites/dashboard/)(audit 로그와 hash chain 상태를 보는 zero-dependency 읽기 전용 `node:http` audit 뷰어. anti-DNS-rebinding Host allowlist, 엄격한 CSP/Trusted Types, fail-closed loopback/remote-bind 가드 포함)와 [`haechi-auth-oidc`](satellites/auth-oidc/)(대시보드의 사람 로그인을 담당하는 대화형 OIDC 세션 브로커 — authorization-code + PKCE + 서버측 세션)를 추가합니다. 기존 위성도 additive minor를 발행합니다. `haechi-auth-jwt@0.2.0`은 재사용 가능한 JWS 검증기(`createJwtVerifier`)를 export하고, `haechi-crypto-kms@0.2.0`은 GCP/Azure/Vault 백엔드를 추가합니다. core는 `0.9.0`으로 bump되며, 현재 이벤트 출력을 바꾸지 않는 심층 방어인 `FORBIDDEN_KEYS` audit 새니타이즈 강화만 포함합니다. `docs/current/release-0.9-implementation-scope.md` 참고.

1.0.0은 **첫 stable 릴리스**입니다. strict semver 하의 frozen API 계약을 선언합니다. `package.json`의 `exports` 표면, CLI의 기계 판독 동작, audit event schema(중첩 sub-schema와 `schemaVersion` 포함), config key shape이 모두 major 버전 계약의 일부이며, `tests/api-contract.test.mjs`가 이를 가드하고, 문서화된 deprecation 정책(`HAECHI_DEPRECATION_*` 런타임 경고, 제거는 다음 major에서만)과 공개된 취약점에 대한 in-minor 보안 예외 하나가 이를 규율합니다([`docs/current/api-stability.md`](docs/current/api-stability.md) 참고). 1.0은 또한 dynamic-loading 금지를 **좁게** 해제합니다 — `authProvider` 플러그인에 한해, Ed25519 서명(trust-anchor 전용 키 해석, entry-hash 바인딩, 버전 pin/floor, revocation, 서명 윈도우를 갖춘 비대칭 `node:crypto` 검증)에 capability-gated, `worker_threads` 격리, 완전 감사되는 플러그인 샌드박스를 허용합니다. dependency injection(`createRuntime(config, providers)`)이 기본으로 유지됩니다. **정직한 잔존 위험:** worker는 메모리/크래시 격리와 데이터 최소화일 뿐 capability 샌드박스가 아니므로, 악의적인 *서명된* 플러그인은 여전히 `fs`/`net`을 써서 받은 credential 슬라이스를 유출할 수 있습니다. 따라서 load-bearing 통제는 trust gate이며, 진정한 capability 강제(child-process + Node permission model)는 1.x 목표입니다. 네 개의 `haechi-*` 위성(`haechi-auth-jwt@0.2.1`, `haechi-crypto-kms@0.2.1`, `haechi-dashboard@0.1.2`, `haechi-auth-oidc@0.1.2`)은 pre-1.0으로 유지되고 독립적으로 버저닝하며, `haechi` peer 범위를 `>=0.8.0 <2.0.0`으로 넓혀 core 1.0.0이 그 설치를 깨뜨리지 않게 합니다. `docs/current/release-1.0-implementation-scope.md` 참고.

1.1.0은 가장 많이 거론되던 1.0의 정직한 잔존 위험을 **진정한 플러그인 capability 강제**로 닫습니다. 새 opt-in `process-isolated` authProvider 런타임(`auth.plugin.isolation: "process"`)은 서명된 플러그인을 Node 권한 모델(`--permission`, **부여 0**) 하의 자식 프로세스에서 실행합니다 — `data:` URL 로드(파일시스템 권한 없음), `stdio: ['ignore','ignore','ignore','ipc']`, 정화된 env. `--allow-net`을 강제하는 Node에서 커널이 플러그인의 `fs`/`net`/`fetch`/`dns`/`child_process`/`worker`는 물론 `process.binding('tcp_wrap')` 우회까지 거부하므로, 악의적 서명 플러그인은 받은 credential을 유출할 수 없습니다. 네트워크 봉쇄는 커널의 `--allow-net` 거부이며(삭제 가능한 JS 하니스가 아닙니다), 기본값 `netEnforcement: "require-permission"`은 `--allow-net`이 없는 Node에서 **fail closed**(생성 거부)합니다. 커스텀 자격증명 플러그인의 경우, **호스트**가 운영자 선언 키 자료를 SSRF 강화 코어 가드(`haechi/ssrf`)로 가져와 IPC로 주입하므로 플러그인은 URL을 직접 지정하지 않습니다. spawn-storm 서킷 브레이커가 재spawn을 제한합니다. 변경되지 않은 1.0 `worker_threads` 모드가 기본으로 유지되며, `process-isolated`는 additive + opt-in(strict semver 하의 **마이너**)입니다. `docs/current/release-1.1-implementation-scope.md` 참고.
