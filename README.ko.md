# Haechi

[![npm](https://img.shields.io/npm/v/haechi)](https://www.npmjs.com/package/haechi)
[![CI](https://github.com/raeseoklee/haechi/actions/workflows/ci.yml/badge.svg)](https://github.com/raeseoklee/haechi/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![node](https://img.shields.io/node/v/haechi)](https://nodejs.org)
[![status](https://img.shields.io/badge/status-developer%20preview-orange)](docs/current/risk-register-release-gate.md)

[English](README.md) | **한국어**

Haechi는 LLM, MCP, vLLM, Ollama, 그리고 에이전트 payload가 모델, 도구, 로그, 또는 proxy에 도달하기 전에 보호하기 위한 자체 호스팅 AI 컨텍스트 집행 레이어의 실험적 개발자 프리뷰이다.

이름은 분별력과 보호를 상징하는 한국의 수호 신수 해치에서 유래했다.

이 저장소는 로컬 개발, 보안 설계 검토, 자체 호스팅 통합 실험을 위한 것이다. 운영 환경에 바로 사용할 수 있는 상태가 아니며, 컴플라이언스를 보장하지 않는다.

현재 개발자 프리뷰 범위는 로컬 도입에 초점을 맞추고 있다:

- `haechi init`: 로컬 키, 샘플 설정, audit 경로를 생성한다
- `haechi protect`: OpenAI 호환 JSON payload를 검사하고 보호한다
- `haechi report`: 원시 payload 없이 audit 이벤트를 요약한다
- `haechi proxy`: 기존 LLM 호출을 위한 로컬 HTTP JSON proxy를 실행한다
- `haechi status`: 현재 설정 하에서 보호되는 항목과 그렇지 않은 항목을 표시한다
- `haechi audit-verify`: audit hash chain을 검증하고 head hash를 출력한다
- `haechi mcp-wrap -- <command>`: MCP 서버를 양방향 stdio 보호로 래핑한다

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

이 저장소를 클론한 후:

```bash
npm test
npm run demo:init
npm run demo:protect
npm run demo:report
```

기본 설정은 `dry-run` 모드로 실행된다. 민감한 값을 탐지하고 audit 메타데이터를 기록하지만, 정책 모드를 변경하기 전까지는 아웃바운드 payload를 수정하지 않는다.

`npm run demo:init`은 `haechi.config.json`과 `.haechi/dev.keys.json`을 로컬에 생성한다. 생성된 키 파일은 로컬 개발 전용이다. Haechi 0.3.x는 운영 환경용 KMS/HSM/Vault 키 provider를 포함하지 않는다. 비밀 정보를 포함하지 않는 템플릿은 `haechi.config.example.json`에서 확인할 수 있다.

## Local Proxy

```bash
node packages/cli/bin/haechi.mjs proxy --config haechi.config.json
```

기존 HTTP JSON 클라이언트를 `http://localhost:1016`으로 지정하고, `haechi.config.json`에서 `target.upstream`을 설정한다. 다른 로컬 포트를 사용하려면 설정에서 `proxy.port`를 변경하거나 `--port`를 전달한다.

proxy는 기본적으로 loopback에 바인드된다. `0.0.0.0`, `::`, 또는 다른 non-loopback 호스트에 바인딩하려면 `--allow-remote-bind`를 명시적으로 제공해야 한다. 이 플래그는 명시적인 네트워크 접근 통제 하에서만 사용한다.

`stream: true`인 스트리밍 요청은 기본적으로 차단된다. `streaming.requestMode`를 `inspect`로 설정하면 SSE/NDJSON 응답을 stream-filter한다(bounded sliding buffer가 프레임에 걸쳐 쪼개진 PII도 잡는다; `streaming.maxMatchBytes` 참고). 또는 호출자가 보호되지 않는 스트리밍을 명시적으로 인정하는 경우에만 `pass-through`로 설정한다.

Ollama의 `/api/chat`과 `/api/generate`는 `stream` 필드가 생략되면 기본적으로 스트리밍하므로, proxy는 `stream: false`가 명시적으로 설정되지 않으면 해당 요청을 스트리밍으로 간주한다.

upstream 요청은 `limits.upstreamTimeoutMs`(기본값 120000) 이후 타임아웃되며 `504 haechi_upstream_timeout`으로 실패한다.

## Local Inference Servers

Haechi 0.3은 OpenAI 호환 서버, vLLM, Ollama, llama.cpp를 위한 프로토콜 adapter 프리셋을 포함한다.

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

그런 다음 OpenAI 호환 클라이언트를 `http://127.0.0.1:1016/v1`으로 지정한다. Ollama 네이티브 API의 경우 `target.adapter: "ollama"`를 사용하고 proxy를 통해 `/api/chat` 또는 `/api/generate`를 호출한다.

## 토큰 왕복

tokenization을 사용하면 모델은 안정적인 token을 받고 호출자는 평문을 돌려받는다:

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

- `tokenVault.deterministic` (기본값 `false`): 동일한 값이 항상 동일한 token으로 매핑된다(로컬 키에서 파생된 도메인 분리 키로 HMAC — 원시 AES 키가 아님). 재전송된 히스토리가 동일한 token으로 재tokenize되므로 멀티턴 채팅에 필요하다. **트레이드오프:** 동일한 값이 요청 간에 연결 가능해진다. `deterministicTypes`(예: `["email"]`)는 determinism을 선택한 type에만 제한한다.
- `tokenVault.detokenizeResponses` (기본값 `false`): 해당 요청을 보호하는 동안 발급된 token**만** 해당 요청의 응답에서 복원한다. 다른 클라이언트나 요청의 token은 복원되지 않는다. `revealPolicy`와 독립적이며, 모든 복원은 개수 단위로 audit 기록되고 값은 기록되지 않는다. `responseProtection.enabled`가 필요하다.

## MCP Wrap

stdio MCP 서버를 래핑하여 양방향 트래픽을 필터링한다 — MCP 클라이언트 설정에서 커맨드만 변경하면 된다:

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

클라이언트→서버 요청은 `mcp.allowedMethods` allowlist와 params 보호를 통과하고, 서버→클라이언트 결과는 params/result 보호와 injection 휴리스틱(아래 참고)을 적용받는다. 거부된 요청은 클라이언트에게 응답되며 서버에 도달하지 않는다. stderr과 exit code는 그대로 전달된다.

## Injection Detection (Preview)

응답 및 tool result 텍스트는 간접 prompt injection(지시문 재정의, 역할 재할당, prompt 마커, 사용자에게 숨기기 표현, 은밀한 tool 유도)에 대한 휴리스틱 규칙으로 검사된다. `injection` type은 **기본적으로 report-only**이다: 탐지 결과는 audit 로그에 기록되지만 수정하거나 차단하지 않는다. 신호를 신뢰할 수 있게 되면 명시적으로 격상한다:

```json
{ "policy": { "actions": { "injection": "block" } } }
```

이 휴리스틱은 prompt injection에 대한 완전한 방어책이 아니다. `docs/current/threat-model.md`를 참고하라.

## 인증 및 클라이언트별 통제

하나의 host 앞에 여러 클라이언트/에이전트를 두는 경우, bearer auth를 활성화하고 각 클라이언트를 policy profile에 바인딩한다. Token은 별도의 `.haechi/auth.json`(0600)에 keyed-HMAC 해시로만 저장된다:

```bash
haechi auth add --type service --scope team:eng --label env=prod   # 토큰을 한 번만 출력
haechi auth list                                                   # 토큰을 표시하지 않음
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

- **Bearer auth** (`auth.provider: bearer`): 클라이언트는 `Authorization: Bearer <token>`을 전송한다. 없거나 잘못되었거나 revoke된 경우 → `401` (바디는 읽지 않으며 upstream에 도달하지 않는다). `provider: none`(기본값)은 동작을 그대로 유지하며, `external`은 주입된 `authProvider`가 필요하다.
- **Named profiles**: 인증된 identity는 **scope → label → 필수 `default`** 순으로 profile로 resolve된다(매칭되지 않거나 익명인 경우 `default`로 fail-closed). Profile은 기본 policy를 재정의하며 자체 `modelAllowlist`와 `rate`를 가질 수 있다.
- **Model allowlist**: 허용되지 않은 `model`을 가진 요청 → `403`.
- **Rate limit**: identity별 분당 요청 수 → `429` (인메모리, 프로세스별).
- Audit 이벤트는 **PII-safe** `identity`(keyed-HMAC subject/issuer, 원시 값 아님)와 resolve된 `profile`을 포함하며, `auth_denied` / `model_not_allowed` / `rate_limited` 결정에는 credentials가 포함되지 않는다. `/__haechi/health`는 인증 없이 접근 가능하다.

JWT/JWKS 인증과 KMS 기반 key custody는 `haechi-*` 위성 패키지로 제공되며, 각각 core와 독립적으로 버저닝·발행된다:

- [`haechi-auth-jwt`](satellites/auth-jwt/) (0.8) — 헤드리스 JWKS bearer 검증; 0.2.0은 재사용 가능한 JWS 검증기(`createJwtVerifier`)를 추가 export한다.
- [`haechi-crypto-kms`](satellites/crypto-kms/) (0.8) — 실제 KMS 클라이언트 기반 envelope 암호화; 0.2.0은 AWS에 더해 GCP(`./gcp`), Azure(`./azure`), HashiCorp Vault Transit(`./vault`, `node:` 전용) 백엔드를 추가한다.
- [`haechi-dashboard`](satellites/dashboard/) (0.9, 신규) — audit 로그와 hash chain 상태에 대한 zero-dependency 읽기 전용 audit 뷰어(`node:http`).
- [`haechi-auth-oidc`](satellites/auth-oidc/) (0.9, 신규) — 대시보드의 사람 로그인을 제공하는 대화형 OIDC 세션 브로커(authorization-code + PKCE).

위성들은 기본 `node:` 전용이며(무거운 SDK는 optional peer) core를 zero-dependency로 유지한다.

## 설정

`haechi init`은 `haechi.config.json`을 생성하며, 비밀 정보를 포함하지 않는 템플릿은 `haechi.config.example.json`에 있다. 모든 키는 fail-closed 방식으로 검증된다 — 알 수 없거나 잘못된 형식의 값은 시작을 거부한다.

| 키 | 기본값 | 설명 |
|---|---|---|
| `mode` / `policy.mode` | `dry-run` | `dry-run`과 `report-only`는 탐지 및 audit만 수행하고, `enforce`는 변환/차단을 적용한다. `policy.mode`가 `mode`보다 우선한다 |
| `target.type` / `target.adapter` | `llm-http` / `openai-compatible` | upstream 프로토콜: `openai-compatible`, `vllm-openai`, `ollama`, `llama-cpp`. 알 수 없는 type은 fail-closed로 처리된다 |
| `target.upstream` | `http://127.0.0.1:9999` | proxy가 요청을 전달하는 유일한 upstream (절대 URL 요청 대상은 거부된다) |
| `proxy.host` / `proxy.port` | `127.0.0.1` / `1016` | proxy 바인드 주소. 아래의 remote 바인딩 참고 |
| `responseProtection.enabled` | `false` | upstream JSON 응답을 검사한다. `failureMode: fail-closed`는 비JSON/압축/대용량 응답을 거부한다 |
| `responseProtection.maxBytes` | `1048576` | 응답 크기의 상한 — `failureMode: allow` 상태에서도 적용된다 |
| `streaming.requestMode` | `block` | `block`은 스트리밍을 501 차단; `inspect`는 SSE/NDJSON 응답을 stream-filter; `pass-through`는 검사 없이 전달(audit 기록). Ollama chat/generate는 `stream: false`가 없으면 스트리밍으로 간주된다 |
| `streaming.responseMode` | `enforce` | 검사된 스트림에 적용되는 enforcement 모드(`dry-run`/`report-only`/`enforce`) |
| `streaming.maxMatchBytes` | `256` | cross-frame 매칭 윈도우; 이보다 긴 단일 매치는 프레임에 걸쳐 쪼개질 수 있음 |
| `limits.maxRequestBytes` | `1048576` | 요청 바디 상한 (한도 초과 시 413) |
| `limits.upstreamTimeoutMs` | `120000` | upstream 타임아웃 (만료 시 504) |
| `policy.presets` | `korean-pii`, `secrets-only`, `llm-redact` | 병합되는 프리셋 action; 병합은 강화는 가능하지만 약화는 불가 |
| `policy.actions` | `card: block` | type별 action: `allow`/`redact`/`mask`/`tokenize`/`encrypt`/`block` |
| `filters.customRules` | `[]` | 추가 정규식 규칙 (ReDoS 검사: 중첩 한정자/역참조 없음) |
| `keys.provider` / `keys.keyFile` | `local` / `.haechi/dev.keys.json` | 개발 전용 소프트웨어 키 (0600). `external`은 프로그래밍 방식으로 crypto provider를 주입해야 한다 |
| `audit.path` | `.haechi/audit.jsonl` | hash chain JSONL audit 로그; `haechi audit-verify`로 검증한다 |
| `tokenVault.revealPolicy` | `disabled` | 수동 reveal 게이트 (`local-dev`로 활성화; 모든 결정이 audit 기록됨) |
| `tokenVault.retentionDays` | `30` | 만료된 token은 vault 쓰기 시 또는 `haechi token-purge --expired`로 삭제된다 |
| `tokenVault.deterministic` / `deterministicTypes` / `detokenizeResponses` | `false` / `null` / `false` | 토큰 왕복 (위 참고) |
| `privacy.profile` | `null` | `kr-pipa`, `eu-gdpr`, `us-general` 기준 action (강화 전용) |
| `mcp.allowedMethods` | `initialize`, `tools/call`, `resources/read`, `prompts/get` | `mcp-stdio`/`mcp-wrap`에서 클라이언트가 호출할 수 있는 method allowlist |
| `auth.provider` / `auth.store` | `none` / `.haechi/auth.json` | `none`/`bearer`/`external`. Bearer token은 keyed-HMAC 해시로 저장 (0600) |
| `policy.profiles` / `policy.profileBinding` | — | 클라이언트별 named policy profile; scope → label → 필수 `default` 순으로 바인딩 |
| `policy.modelAllowlist` / `policy.rate` | — | 허용된 모델 이름 (그 외 403); identity별 분당 요청 수 rate limit (429) — profile별로도 설정 가능 |

위 표는 빠른 참고용이다. 키별 전체 레퍼런스 — 타입, 검증 규칙, 프리셋, action 강도, 일반적인 설정 — 는 [`docs/current/configuration.md`](docs/current/configuration.md)에 있으며, CLI에서 축약 버전을 출력한다:

```bash
haechi config        # 설정 가이드
haechi help          # 모든 커맨드
haechi help proxy    # 특정 커맨드
haechi status        # 현재 설정의 실제 적용 상태
```

### loopback 밖으로 바인딩 (0.0.0.0)

proxy는 CLI 플래그를 명시적으로 전달하지 않으면 non-loopback 호스트를 거부한다 — 설정 파일에 `proxy.host: "0.0.0.0"`을 지정해도 의도적으로 시작되지 않는다(설정 파일을 복사해도 게이트웨이가 자동으로 노출되지 않도록):

```bash
haechi proxy --config haechi.config.json --host 0.0.0.0 --allow-remote-bind
```

**proxy는 아직 클라이언트 인증을 제공하지 않는다** (0.6 계획): 포트에 접근할 수 있는 누구든 upstream과 token round-trip 경로를 사용할 수 있다. `--allow-remote-bind`는 명시적인 네트워크 통제 하에서만 사용한다:

- **컨테이너**: 컨테이너 내에서 `0.0.0.0`으로 바인딩하는 것은 일반적인 패턴이다 — 포트 매핑에서 노출을 제한한다(예: `-p 127.0.0.1:1016:1016`)
- **LAN/원격**: 방화벽, VPN(예: Tailscale), 또는 인증 reverse proxy를 앞에 둔다

## Privacy Profiles

Haechi는 로컬 정책 부트스트래핑을 위한 기본 지역별 Privacy Profiles를 포함한다:

- `kr-pipa`
- `eu-gdpr`
- `us-general`

`haechi.config.json`에서 `privacy.profile`을 설정하면 집행 전에 해당 프로필의 기본 action이 적용된다. 이 프로필은 엔지니어링 기본값이며, 법적 자문이 아니다.

## 보안 노트

- 이 프로젝트는 컴플라이언스를 보장하지 않는다.
- 0.1 crypto provider는 Node `crypto`와 AES-256-GCM 및 로컬 소프트웨어 키를 사용한다.
- Audit 이벤트에는 원시 prompt, tool result, secret, 또는 PII 값이 포함되어서는 안 된다.
- 알 수 없거나 잘못된 정책/설정 오류는 집행 경로에서 fail-closed로 처리되어야 한다.
- Response protection은 명시적인 allow 정책이 설정되지 않는 한 비JSON, 잘못된 JSON, 압축, 또는 대용량 응답에 대해 fail-closed로 처리된다.
- Token reveal 및 purge 결정은 audit 로그에 기록된다(token id와 결정만 기록되며, 평문은 기록되지 않는다). 만료된 token은 vault 변경 시 또는 `haechi token-purge --expired`로 제거된다.
- `haechi init --force`는 로컬 키를 교체한다: 기존 키는 `retired` 상태로 보관되어 기존 암호문과 token vault 레코드를 `kid`로 복호화할 수 있다.
- Privacy profile은 명시적으로 더 엄격한 사용자 action을 강화할 수는 있지만 약화할 수는 없다.
- 탐지는 문자열 값, JSON 숫자(예: 카드 번호), 객체 키 이름을 검사한다. Base64/URL 인코딩된 값과 URL 쿼리 스트링은 검사되지 않는다.
- Audit tail truncation: `audit.anchor.mode: file`을 설정하면(추가 전용/별도 미디어에서) `haechi audit-verify --anchor`가 마지막 anchor 이후 꼬리 레코드 삭제를 탐지한다. 동일한 쓰기 가능 파일시스템에서는 공격자가 두 파일을 함께 잘라낼 수 있다.
- Key custody: `keys.provider: external`은 주입된 `cryptoProvider`를 허용한다; `assertCryptoProviderConformance`로 adapter를 검증한다. envelope 암호화 KMS adapter는 `haechi-crypto-kms` satellite(`satellites/crypto-kms/`)가 제공한다.
- Release integrity: 배포된 tarball에는 npm provenance attestation이 포함되며, GitHub release asset에는 sigstore attestation과 `SHA256SUMS`가 추가된다(`gh attestation verify`와 `node scripts/release-checksums.mjs --check`로 검증한다).
- 이 패키지는 개발자 프리뷰이다. 인터넷에 노출된 운영 LLM 게이트웨이로 사용하지 않는다.

## 현재 범위

0.1 빠른 시작 범위는 `docs/current/mvp-0.1-implementation-scope.md`에 설명되어 있다.

0.2는 로컬 TokenVault, 서명된 policy bundle 커맨드, 플러그인 매니페스트 검증, MCP stdio JSON-RPC 라인 필터 스켈레톤을 추가한다. `docs/current/release-0.2-implementation-scope.md` 참고.

0.3은 로컬 inference 프로토콜 adapter, 선택적 JSON 응답 보호, npm 패키지 메타데이터, 배포 준비 export를 추가한다. `docs/current/release-0.3-implementation-scope.md` 참고.

0.3.1은 릴리스 안전 게이트, 응답 fail-closed 동작, audit hash chaining, token reveal 거버넌스, provider injection, privacy profile, CI/SBOM/provenance 워크플로 스캐폴딩, 그리고 전용 위협/공유 책임/API 안정성 문서를 추가한다.

0.3.2는 보안 강화 릴리스이자 첫 번째 npm 개발자 프리뷰 대상이다: Ollama 암묵적 스트리밍 fail-closed 처리, 감사된 token reveal/purge, 보존 기간 purge, kid 기반 키 교체, 도메인 분리 policy bundle 서명, JSON 숫자/객체 키 탐지, upstream 타임아웃, stale lock 복구, 그리고 non-enforcing 모드 경고. `docs/current/release-0.3.2-hardening-scope.md` 참고.

0.4.0은 token round-trip(deterministic tokenization + 요청 스코프 응답 detokenization), `mcp-wrap` 양방향 MCP 필터, `status` 및 `audit-verify` 커맨드, report-only injection detection 휴리스틱을 추가하고, 0.6 인증을 위한 PII-safe `identity`/`authProvider` 계약을 예약한다. `docs/current/release-0.4-implementation-scope.md` 참고.

0.5.0은 SSE/NDJSON 스트리밍 응답 검사를 추가한다: `streaming.requestMode: "inspect"`가 bounded sliding buffer로 응답을 stream-filter하여 프레임에 걸쳐 쪼개진 PII도 잡는다(`streaming.maxMatchBytes`). `docs/current/release-0.5-implementation-scope.md` 참고.

0.6.0은 인증과 클라이언트별 통제를 추가한다: 해시 기반 token 저장소와 `haechi auth` CLI를 갖춘 내장 bearer auth, identity scope/label로 바인딩되는 named policy profile, model allowlisting, 그리고 identity별 rate limiting — audit 로그에는 PII-safe identity가 기록된다. `docs/current/release-0.6-implementation-scope.md` 참고.

0.7.0은 운영 강화(ops-hardening) 릴리스이다: 꼬리 절단을 탐지하는 audit head-hash anchoring(`audit.anchor`), `assertCryptoProviderConformance`와 reference KMS adapter를 포함한 강화된 외부 `cryptoProvider` 계약, 그리고 서명/체크섬된 GitHub release artifact. `docs/current/release-0.7-implementation-scope.md` 참고.

0.8.0은 `haechi-*` 에코시스템을 세운다: npm workspaces 모노레포(core는 unscoped `haechi` 유지, zero runtime dependency, 패킹 매니페스트 CI 게이트로 강제) + 첫 두 위성 — [`haechi-crypto-kms`](satellites/crypto-kms/)(실제 AWS KMS 클라이언트 기반 envelope 암호화; AWS SDK는 optional peer)와 [`haechi-auth-jwt`](satellites/auth-jwt/)(헤드리스 JWKS bearer 검증, `node:` 전용). 각각 자체 provenance + sigstore attest 워크플로로 독립 발행한다. `docs/current/release-0.8-implementation-scope.md` 참고.

0.9.0은 관측성(observability) + 대화형 인증 테마이다: 두 개의 새 위성 — [`haechi-dashboard`](satellites/dashboard/)(audit 로그와 hash chain 상태에 대한 zero-dependency 읽기 전용 `node:http` audit 뷰어; anti-DNS-rebinding Host allowlist, 엄격한 CSP/Trusted Types, fail-closed loopback/remote-bind 가드 포함)와 [`haechi-auth-oidc`](satellites/auth-oidc/)(대시보드의 사람 로그인을 제공하는 대화형 OIDC 세션 브로커 — authorization-code + PKCE + 서버측 세션). 기존 위성도 additive minor를 발행한다: `haechi-auth-jwt@0.2.0`은 재사용 가능한 JWS 검증기(`createJwtVerifier`)를 export하고, `haechi-crypto-kms@0.2.0`은 GCP/Azure/Vault 백엔드를 추가한다. core는 `0.9.0`으로 bump되며, 추가적인 `FORBIDDEN_KEYS` audit 새니타이즈 강화(현재 이벤트 출력은 바뀌지 않는 심층 방어)만 포함한다. `docs/current/release-0.9-implementation-scope.md` 참고.
