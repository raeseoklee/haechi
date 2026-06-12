# Haechi 보안 백서

- 문서 상태: Living document (WS6 — reliability-hardening-track §WS6)
- 이 문서의 성격: **통제 매핑 + 구조화된 자체 평가**이며, 인증이나 독립 감사가 아닙니다.
- 출처: `packages/*` 코드, `docs/current/threat-model.md`, `docs/current/risk-register-release-gate.md`. 이 백서는 그 내용을 *매핑*할 뿐 그대로 재서술하지 않으며, 내용을 복제하는 대신 저장소 경로와 위험 ID를 인용합니다.

## 0. 이 문서가 무엇이고 — 무엇이 아닌가

Haechi는 **AI 컨텍스트 집행 계층**입니다. OpenAI 호환 / MCP / vLLM / Ollama / llama.cpp JSON payload를 검사하여 PII와 비밀 정보를 탐지하고, 모델·도구·로그에 도달하기 전에 redact / mask / tokenize / encrypt / block 합니다.

이 문서는 Haechi가 **실제로 출시한** 통제를, 저장소 전반에서 이미 인용하는 두 프레임워크 — **OWASP Top 10 for LLM Applications (2025)**와 **NIST AI Risk Management Framework (AI RMF 1.0)** — 에 매핑하고, reliability-hardening track이 잡아내고 수정한 적대적 발견을 **구조화된 자체 모의해킹(self-pentest)**으로 기록합니다.

이 문서는 명시적으로 다음이 **아닙니다**:
- 컴플라이언스 인증·확약·보증 보고서(reliability-hardening-track §5 비목표 및 `SECURITY.md` Scope 참고)
- 독립 제3자 침투 시험
- 모든 OWASP-LLM / NIST-AI-RMF 항목이 *완전히* 완화되었다는 주장. 여러 항목은 **책임 공유**(`docs/current/shared-responsibility.md`)이거나 범위 밖(`docs/current/threat-model.md` §4)입니다. 아래에는 출시 코드에 실제로 존재하는 통제만 매핑하며, 희망 사항은 담지 않습니다.

## 1. 통제 목록 (출시된 표면)

아래 매핑된 모든 통제는 load-bearing하며 테스트로 뒷받침되는 동작입니다. 각 통제의 근거는 이 표가 아니라 코드 경로와 threat-model / risk-register 행입니다.

| # | 통제 | 위치 | 근거 |
|---|---|---|---|
| C1 | 탐지 + redact/mask/tokenize/encrypt/block 파이프라인 | `packages/core` (`protectJson`), `packages/filter`, `packages/policy` | threat-model §3 |
| C2 | fail-closed 집행(알 수 없는 policy/config/`target.type`은 throw; non-JSON/무효/압축/초과 응답은 fail-closed) | `packages/cli/runtime.mjs` (`normalizeConfig`), `packages/proxy` (`maybeProtectResponse`) | CLAUDE.md 불변식; P1-SEC-010 |
| C3 | audit SHA-256 hash chain + head anchoring(변조 + tail-truncation 증거) | `packages/audit` (`verifyAuditChain`, `audit.anchor`) | P1-SEC-003 |
| C4 | audit에 평문/PII 없음(`FORBIDDEN_KEYS`); keyed-HMAC identity 해시; 구조화 경로 키 해싱 | `packages/audit`, `packages/auth` (`buildIdentity`) | P1-SEC-012 |
| C5 | streaming 기본 차단; bounded·opt-in 검사(cross-frame sliding buffer) | `packages/proxy`, `packages/stream-filter`, `core` (`createStreamProtector`) | P1-SEC-007 |
| C6 | body 읽기 전 클라이언트 auth gate; named policy-profile 해석; identity별 rate limit | `packages/proxy` (`authorizeRequest`), `packages/auth` | SECURITY.md; threat-model §3 |
| C7 | 서명·sandbox된 `authProvider` 플러그인(Ed25519 + trust anchor + pin/floor/revocation + worker/process 격리) | `packages/plugin`, `packages/cli/runtime.mjs` | P1-SEC-024 / P1-SEC-027 |
| C8 | host-mediated fetch의 SSRF 가드; absolute-form proxy target 거부 | `packages/ssrf`, `packages/proxy` (`assertRelativeProxyTarget`) | P1-SEC-009 / P1-SEC-028 |
| C9 | token-vault reveal 거버넌스(`revealPolicy`), retention, token id 기준 audit된 reveal/purge | `packages/token-vault` | P1-SEC-002 |
| C10 | 정책은 강해지기만 함(`ACTION_STRENGTH`); privacy profile은 강화만 가능, 약화 불가 | `packages/policy`, `packages/privacy-profiles` | P1-SEC-005 |
| C11 | 탐지 정밀도 통제(`filters.minConfidence`, `filters.allowlist`); hard-block 타입은 **억제 불가** | `packages/filter`, `packages/core` | WS2c |
| C12 | 매칭 전 string leaf의 NFKC 정규화(full-width/혼동 문자 회피) | `packages/core` / `packages/filter` | WS2d |
| C13 | **proxy TLS / remote-bind 강화(이 WS):** remote bind는 Haechi가 직접 TLS 종단(`proxy.tls`)하거나, 신뢰 hop을 명시적으로 확인(`proxy.trustForwardedProto`, `X-Forwarded-Proto: https` 강제)해야 하며, 그렇지 않으면 기동 시 throw | `packages/proxy` (`assertSafeProxyTransport`, 서버 선택, forwarded-proto gate), `packages/cli/runtime.mjs` (`proxy.tls` 해석) | 본 문서 §3 |
| C14 | 기본 loopback 바인드; `--allow-remote-bind` 없이는 non-loopback 거부 | `packages/proxy` (`assertSafeProxyBind`) | SECURITY.md |
| C15 | bounded recursion-depth + byte/encoding 가드(fail-closed 4xx; non-UTF-8 거부) | `packages/core`, `packages/proxy` (`readBody`) | WS5 |
| C16 | 운영 fail-closed 신호(audit 쓰기 불가 시 `/__haechi/ready` 503; metrics에 PII 없음) | `packages/proxy` (`handleReady`), `packages/metrics` | WS4 |

## 2. OWASP Top 10 for LLM Applications (2025) 매핑

각 행은 OWASP-LLM 위험을 그 위험을 다루는 Haechi 통제에 매핑하고 정직한 잔여 위험을 기록합니다. 주로 운영자/모델의 책임인 위험은 완화로 주장하지 않고 **책임 공유 / 범위 밖**으로 표기합니다.

| OWASP-LLM (2025) | Haechi 통제 | 커버리지 & 정직한 잔여 위험 |
|---|---|---|
| **LLM01 Prompt Injection** | C5(응답/도구 결과 injection 탐지는 기본 report-only), C1 | **부분 / 설계상.** injection 탐지는 응답/도구 결과 방향에서 동작하며 명시적 격상 전에는 report-only입니다(CLAUDE.md 불변식). Haechi는 prompt injection을 "해결"하지 않습니다 — `threat-model.md` §4는 prompt-injection *예방*을 비목표로 둡니다. 도구 결과가 컨텍스트로 재유입되기 전 비밀/PII를 탐지해 폭발 반경을 줄입니다. |
| **LLM02 Sensitive Information Disclosure** | C1, C2, C9, C4 | **주 사용 사례.** detect→redact/mask/tokenize/encrypt/block 파이프라인과 응답 보호가 바로 이 통제입니다. 잔여: 탐지는 regex+validator이며 ML이 아닙니다(비목표); 문서화된 제외(base64/URL-query)는 유효합니다(threat-model §4). |
| **LLM03 Supply Chain** | C7, SBOM + SHA-pinned CI(P1-OPS-002/006) | **플러그인 경로에 대해 대응.** 동적 코드는 서명·trust-anchor·pin/floor/revocable한 `authProvider` 플러그인으로만 허용됩니다. 코어는 zero-runtime-dependency를 유지해 의존성 공격 표면을 줄입니다. |
| **LLM04 Data & Model Poisoning** | — | **범위 밖.** Haechi는 인라인 컨텍스트 필터이며 학습/데이터 파이프라인 통제가 아닙니다. 완화가 아니라 범위 밖으로 표기합니다. |
| **LLM05 Improper Output Handling** | C5, C2, C1 | **대응.** 응답/stream 보호가 모델 출력을 호출자/도구 도달 전에 검사하며, non-JSON/무효/압축/초과 응답은 fail-closed입니다. 잔여: block 전에 이미 방출된 streaming 바이트는 회수 불가(문서화). |
| **LLM06 Excessive Agency** | C6, C7, C9 | **부분.** auth gate + named policy profile + model allowlist가 누가 게이트웨이를 구동하고 어떤 모델/연산이 도달 가능한지 제약하며, token reveal은 거버넌스됩니다. 게이트웨이 너머의 에이전트 수준 인가는 운영자의 몫입니다. |
| **LLM07 System Prompt Leakage** | C1, C5, C4 | **부분.** prompt/응답에 박힌 비밀/PII는 탐지·보호되며, audit는 원문 prompt를 저장하지 않습니다(C4). 모델이 스스로 system prompt 텍스트를 방출하는 것은 막지 않습니다. |
| **LLM08 Vector & Embedding Weaknesses** | — | **범위 밖.** RAG/vector-store 구성요소 없음. |
| **LLM09 Misinformation** | — | **범위 밖.** 사실성 통제가 아닙니다. |
| **LLM10 Unbounded Consumption** | C6(rate limit), C15(byte/depth 한계), C16(backpressure/timeout) | **게이트웨이에서 대응.** identity별 rate limit, request byte + nesting-depth 상한, max-in-flight backpressure(503 + `Retry-After`), 튜닝된 timeout. 잔여: 내장 rate limiter는 단일 프로세스(다중 replica는 주입된 공유 limiter 필요 — shared-responsibility.md). |

## 3. NIST AI RMF (AI RMF 1.0) 매핑

AI RMF 네 기능에 매핑합니다. Haechi는 운영자가 자신의 AI-RMF 프로그램 안에서 사용하는 *기술 통제 표면*이며, 운영자를 위한 거버넌스를 대신 구현하지 않습니다.

| AI RMF 기능 | Haechi 통제 | Haechi의 기여(그리고 경계) |
|---|---|---|
| **GOVERN** | C2, C10, C14, 문서화된 threat-model + 책임 공유 구분 | fail-closed 기본값, 강화-전용 정책 격자, 기본 loopback, Haechi가 하는 일과 운영자가 소유하는 일의 명시적 문서화. 거버넌스 *정책*은 운영자의 몫입니다. |
| **MAP** | C1, 탐지 타입 행렬(`configuration.md`), threat-model §1–2 | 민감 데이터가 prompt/응답/도구 호출을 통해 *어디로* 흐르고 *어떤* 범주가 탐지되는지 드러내, 운영자가 게이트웨이 경계에서 AI-시스템 데이터 위험을 매핑하도록 돕습니다. |
| **MEASURE** | C3, C4, C11, `bench:detection` precision/recall gate, `/__haechi/metrics` | 변조 증거 audit, CI gate로 묶인 precision/recall 측정 하니스, PII 없는 운영 metrics가 측정 가능한 신호를 제공합니다. 잔여: 탐지 metrics는 regex/validator 규칙만 측정합니다. |
| **MANAGE** | C2, C5, C6, C9, C13, C16, operations-runbook | 인라인 집행, streaming 봉쇄, auth gate, token-vault 거버넌스, TLS 강화 remote bind, readiness/backpressure, Day-2 runbook(rotation/retention)이 운영자가 프로덕션에서 위험을 관리하게 합니다. |

## 4. 구조화된 자체 모의해킹(self-pentest)

이것은 **자체 평가**입니다 — Haechi가 자신의 통제를 스스로 적대적으로 시험한 것이며, 독립 침투 시험이 아닙니다. 아래 각 발견은 테스트로 재현·수정되었고 지금은 회귀로 보호됩니다.

### 4.1 방법론
- **실환경 검증.** proxy + 보호 파이프라인은 env-gated 통합 스위트(`tests/local-inference.integration.test.mjs`; P1-OPS-003)를 통해 실제 OpenAI 호환(vLLM) 및 Ollama 네이티브 엔드포인트에 대해 동작합니다. 모델 서버가 없으면 CI가 이를 건너뛰므로 mock-only가 아니라 opt-in입니다.
- **적대적 회귀 코퍼스.** 라벨링된 positive/hard-negative 탐지 코퍼스가 `npm run bench:detection`을 구동하며 CI gate(`scan:detection`)로 묶여, precision/recall 회귀가 빌드를 실패시킵니다(WS2a).
- **테스트 규율로서의 fail-closed 단언.** 모든 신규 경로(depth guard, readiness, backpressure, env overlay, §3의 TLS remote-bind guard)는 happy path뿐 아니라 *throw/deny* 방향을 단언하는 테스트와 함께 출시됩니다.

### 4.2 잡아내고 수정한 발견 (선별)

| 발견 | 분류 | 무엇이 깨졌나 | 수정 + 가드 |
|---|---|---|---|
| **WS2d — Unicode 회피** | 탐지 우회 | full-width / 혼동 코드포인트가 비밀/PII 값을 모든 regex 규칙 앞에서 통과시켰습니다(string leaf를 정규화 전에 매칭). | 매칭 전 string leaf를 NFKC 정규화(C12); 탐지 코퍼스의 회피 fixture로 커버. |
| **WS2c — bearer-recall 회귀** | 탐지 정밀도 | "Bearer …" 산문 false positive를 줄이려 추가한 context anchor가 *실제* bearer-token 비밀까지 억제했습니다(코퍼스가 잡은 recall 회귀). | anchor를 재범위화해 hard-block `secret` 타입이 allowlist/anchor로 절대 억제되지 않도록 했습니다(C11 불변식); 정밀도 통제 테스트가 FP 절감과 recall 하한을 모두 고정. |
| **WS5 — deep-nesting 스택 오버플로** | 가용성(DoS) | `maxRequestBytes` 안의 깊게 중첩된 JSON이 재귀 스택을 넘쳐 uncaught crash가 났습니다. | 설정 가능한 `limits.maxNestingDepth` fail-closed 4xx(C15); deep-nesting 테스트. |
| **P1-SEC-009 — proxy SSRF / absolute target** | SSRF | absolute/protocol-relative request target이 upstream을 우회시킬 수 있었습니다. | origin-form 전용 target; upstream URL은 고정 upstream에 path+search만 결합(C8). |
| **WS6 — 평문 remote bind(이 WS)** | 기밀성 | non-loopback 바인드가 plain HTTP를 제공해 bearer token + payload를 평문 노출했습니다. | 이제 remote bind는 Haechi 종단 TLS 또는 `X-Forwarded-Proto: https`를 강제하는 명시적 `trustForwardedProto` hop을 요구하며, 그렇지 않으면 기동 시 throw(C13). `tests/proxy-tls.test.mjs`로 가드(TLS 없을 때 throw, https-over-TLS smoke, forwarded-proto 거부, fail-closed config). |

### 4.3 수용된 잔여 위험 (정직하게)
- 서명된 플러그인 자신의 `fs`/`fetch`는 1.0 `worker_threads` 모드에서 차단되지 않습니다(메모리/크래시 격리만); opt-in 1.1 `process-isolated` 런타임에서만 집행됩니다(threat-model §3, P1-SEC-027).
- 단일 프로세스 rate limiter / audit chain / token vault: 다중 replica 안전성은 주입된 공유 저장소가 필요합니다(shared-responsibility.md; reliability-hardening-track §3).
- 탐지는 regex + validator로 유지됩니다(ML 없음); 문서화된 base64 / URL-query 제외는 유효합니다(threat-model §4).

## 5. 공개(Disclosure)

의심되는 취약점은 `SECURITY.md`와 `/.well-known/security.txt`에 따라 GitHub **private vulnerability reporting**(Security Advisories) <https://github.com/raeseoklee/haechi/security/advisories> 으로 신고하십시오. 신고에 실제 비밀, 프로덕션 prompt, 고객 데이터, 개인정보를 포함하지 마십시오.

## 6. 상호 참조
- `docs/current/threat-model.md` — 권위 있는 위협 모델과 제외 항목.
- `docs/current/risk-register-release-gate.md` — 위험별 해결 상태와 release gate.
- `docs/current/compliance-mapping.md` — 통제-의무 매핑 + DSAR/retention 워크플로.
- `docs/current/shared-responsibility.md` — Haechi가 소유하는 것 vs. 운영자.
- `docs/current/operations-runbook.md` — Day-2 운영, rotation, retention.
