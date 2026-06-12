# 신뢰성 하드닝 트랙 (Reliability Hardening Track)

- 상태: 계획 (2026-06-12 확정; 1.1.1 코어에 대한 5-렌즈 읽기 전용 감사에 근거)
- 대상 라인: 1.1.2(patch) → 1.2.0(minor); 신규 제품 표면 없음
- 목적: Haechi를 **상용 솔루션 수준의 신뢰성**으로 끌어올립니다 — 운영 AI 보안 게이트웨이에 기대되는 신뢰·운영성·탐지 품질의 밀도입니다. 이것은 품질 목표이지 상용화 계획이 아닙니다. 모든 항목은 **이미 존재하는 것을 조이거나, 측정하거나, 문서화**하며, 신규 기능을 추가하지 않습니다.

## 1. 이 트랙이 필요한 이유

1.1.1 코어에 대한 5-렌즈 감사(탐지 품질, 수평 확장/상태, 운영성, 보안 잔여, 정합성)는 **47개 발견(High 16 / Medium 20 / Low 11)** 을 반환했으며, 각각 코드·설정 규칙·문서 주장·누락 산출물에 근거합니다. 반복되는 주제는 기능 부재가 아니라 **밀도 부재**입니다. 코어는 단일 자체 호스팅 복제본에서는 올바르지만, 운영 신뢰 측면에서는 측정되지 않았고, 계측이 부족하며, 일부는 문서화가 미흡합니다.

단적인 신호: 프로젝트 자체의 현행 설계 초안(`docs/current/privacy-filtering-policy-draft.md`)이 `minConfidence` 임계값, 오탐 allowlist, FP/FN 측정을 이미 명세했지만, 출시된 코드는 이를 구현하지 **않았습니다**. 따라서 가장 큰 단일 갭은 범위를 넓히는 것이 아니라, *설계된* 코어와 *출시된* 코어 사이의 거리를 좁히는 것입니다.

이 트랙은 신규 기능을 의도적으로 **제외**합니다 — 외부 Redis/DB 공유 상태 구현, ML 기반 탐지, 새 추론 백엔드는 범위 밖입니다. 수평 확장에 운영 상태가 필요한 경우, 이 트랙은 내장 분산 저장소가 아니라 **주입 seam + 정직한 문서**를 추가합니다.

## 2. 워크스트림

각 워크스트림은 기존 동작을 조입니다. 공수는 감사 기준(S/M/L)입니다.

### WS1 — 정직성·정합성 스윕 (1.1.2 patch)
거버닝 문서가 출시된 1.1.1 라인보다 뒤처져 있으며, 이는 보안 제품의 신뢰를 직접 떨어뜨립니다.
- stale 주장 정정: README + `configuration.md`의 "the proxy has no client authentication yet (planned for 0.6)"(bearer auth는 0.6에서 출시됨), `SECURITY.md`(0.3.x 제품을 기술 — 스트리밍 검사 없음, 검증 전용 플러그인), `configuration.md`/`threat-model.md`/`risk-register-release-gate.md`의 `Target version: 0.6.0` / `Draft 0.1 / Target 1.0.0` 헤더, risk-register §1/§7의 성숙도 표현, README 보안 노트의 "0.1 crypto provider" 라벨.
- **doc-freshness preflight 게이트** 추가 — stale-name 스캐너(또는 작은 신규 점검)를 확장해 stale 버전 배너와 알려진 stale 문구(`planned for 0.6`, `Target version: 0.6.0`, `Only the current 0.3.x` 등)를 CI에서 차단합니다. Haechi는 이미 stale 문자열을 세 번 수정했으므로, 이는 재발을 막습니다.
- 정직한 범위를 명문화(EN + KO): 다중 복제 상태 계약(rate/audit/vault는 단일 프로세스), 단일 호스트 동시성 한정, 유니코드/base64 탐지 제외, 비UTF-8 무음 손상 디코드.

### WS2 — 탐지 품질 (1.2.0; 가장 큰 레버리지)
보안 게이트웨이에서 탐지 정밀도/재현율은 **그 자체가 제품**인데, 지금은 측정되지 않습니다.
- **WS2a — 측정 먼저 (L):** 라벨링 fixture 코퍼스(타입별 양성 PII/secret 샘플 + 양성처럼 보이는 hard-negative 집합)와 타입별 precision/recall을 보고하는 `bench:detection` 스크립트를 만들어, `release:preflight`와 함께 CI 회귀 게이트로 연결합니다. WS2의 나머지는 모두 이 베이스라인에 대해 측정합니다.
- **WS2b — 커버리지 (M):** 감사에서 미탐으로 재현된 흔한 자격증명 형식에 대한 고정밀·정밀 앵커 규칙 — AWS(`AKIA`/`ASIA`), GitHub(`ghp_`/`gho_`/`ghs_`), Google(`AIza`), Slack(`xox[baprs]-`), JWT(3-세그먼트), PEM 비밀키 헤더 — 와 `assignment-secret` 키 어휘 확장(`client_secret`, `private_key`, `aws_secret_access_key` 등). 국제 PII(US SSN, IBAN mod-97, E.164)는 검증기와 함께 추가하거나 **KR 로케일 전용임을 명시 문서화**합니다.
- **WS2c — 정밀도 제어 (M):** *이미 설계된* `filters.minConfidence` 게이트를 구현하고(현재 `confidence` 필드는 기록만 되고 아무것도 게이팅하지 않습니다), 하드블록 타입(`secret`/`api_key`/`kr_rrn`/`card`)을 **억제할 수 없다**는 불변식을 명문화한 `filters.allowlist` 예외 메커니즘을 추가합니다. 감사에서 재현된 고오탐 규칙에 컨텍스트 앵커를 추가합니다(Luhn 통과 주문번호 → `card`, 평문 속 "Bearer …" → `secret`).
- **WS2d — 우회 방어 (M):** 매칭 전 문자열 리프의 Unicode NFKC 정규화(현재 full-width/혼동 문자 우회가 모든 규칙을 무력화함). 선택적으로 긴 문자열 리프에 대한 bounded base64/percent 디코드-후-재스캔.

### WS3 — 수평 확장·상태 안전 (1.2.0; 주입 seam + 정직한 문서)
rate limiter, audit 체인, token vault, auth store는 단일 프로세스/로컬 파일 설계이며, 로드밸런서 뒤 2개 이상 복제본에서 **무음으로** 약화됩니다.
- rate limiter를 **주입 가능한 collaborator**(`providers.rateLimiter`, `auditSink`/`cryptoProvider`와 동일 패턴)로 만들어, 공유 저장소 구현을 부재가 아니라 *교체 가능*하게 합니다 — 내장 분산 저장소는 아닙니다.
- rate-limiter 윈도우 `Map`을 prune(현재 identity 키로 무한 메모리 증가).
- 다중 복제 현실을 정직하게 문서화(EN + KO + risk register): 프로세스별 rate limit, 공유 파일에서의 audit hash 체인 분기, whole-file-rewrite vault 확장 한계, NFS 파일락 주의, 단일 작성자 anchor 스트림. `shared-responsibility.md`에 "수평 확장 / 다중 복제" 절을 추가합니다.

### WS4 — 운영성 / Day-2 (1.2.0)
유료 운영자가 지금은 이것을 운영 환경에서 실행·모니터링할 수 없습니다.
- **Health:** `/__haechi/health`를 `/__haechi/live`(프로세스 liveness)와 `/__haechi/ready`(audit sink 쓰기 가능 + provider 로드 + 선택적 캐시 upstream probe → 준비 안 됐으면 503)로 분리하고 버전 필드를 둡니다.
- **Telemetry:** 최소 `/metrics` 표면(결정/라우트/모드별 요청 수, 차단, `auth_denied`, `rate_limited`, `upstream_timeout`, 응답 미보호, 요청/응답 지연 히스토그램)을 주입 seam으로 제공합니다. audit 쓰기 실패 전용 신호(현재는 stderr 1줄과 함께 요청당 500). 시작/종료/오류에 대한 구조화 JSON 로그와, audit 이벤트에도 나타나는 correlation id. **불변식 가드:** 어떤 metric 라벨이나 로그 필드도 평문/PII를 담아서는 안 됩니다(audit 평문 금지 불변식을 telemetry로 확장).
- **Resilience:** in-flight 요청을 grace 기간 내에 비우고 keep-alive 연결을 닫는 graceful shutdown. 초과 시 503 + `Retry-After`를 반환하는 전역 max-in-flight 상한(backpressure). 튜닝된 `requestTimeout`/`headersTimeout`.
- **Deploy:** 비밀이 아닌 운영 키(`HAECHI_PROXY_PORT`/`HAECHI_UPSTREAM`/`HAECHI_MODE` 등)에 대한 fail-closed env-var 오버레이. 하드닝된 레퍼런스 `Dockerfile`(non-root, 고정 Node 22, 읽기 전용 root fs + 쓰기 가능 `.haechi` 볼륨)와 `compose` 예제(전면 TLS/auth proxy) + 운영 runbook. 체인 인식 audit 로그 로테이션/보존 절차. `configVersion` 스탬프 + 업그레이드 노트 맵.

### WS5 — 코어 robustness 버그 (1.1.2 patch)
- **`collectStringEntries` 무한 재귀 (M):** `maxRequestBytes` 이내의 깊게 중첩된 JSON payload가 스택을 오버플로 → 미포착 크래시. 설정 가능한 최대 중첩 깊이 가드(byte-limit 경로와 동일하게 fail-closed 4xx) + 깊은 중첩 테스트를 추가합니다.
- 비UTF-8 요청 바디: 현재 탐지 전에 U+FFFD로 손실 디코드됩니다. fail-closed로 거부(`Buffer`/`isUtf8` 점검)하거나 수용된 제외로 문서화합니다.
- `bench-payload.mjs`에 깊은 중첩 + 높은 fan-out 케이스를 추가하고 P1-OPS-004 행에 정직한 최악 케이스를 반영합니다.

### WS6 — 신뢰 자산 (상용 보안 검토)
- **proxy TLS / remote-bind 하드닝 (M):** 대시보드의 fail-closed remote-bind 패턴을 proxy에 이식합니다 — `--allow-remote-bind`가 설정되면 명시적 TLS 컨텍스트(또는 신뢰 hop의 `X-Forwarded-Proto`)를 요구한 뒤에야 수락하여, remote bind가 bearer 토큰 + payload를 평문으로 노출하지 못하게 합니다. 이것은 문서가 아니라 실질 보안 통제입니다.
- 기존 통제를 OWASP LLM Top 10(2025)과 NIST AI RMF(이미 인용된 프레임워크)에 매핑하는 보안 백서, 그리고 문서화된 구조적 셀프 pen-test.
- 취약점 공개 채널: `SECURITY.md` 보고 경로 + `security.txt` + GitHub private vulnerability reporting + 분류/대응 시간 목표.
- 컴플라이언스 통제 매핑과 DSAR/retention 운영 워크플로 문서.

## 3. 순서

1. **WS1 + WS5 → 1.1.2 (patch).** 저위험, 즉각적 신뢰 상승(정직한 문서 + 실제 크래시 버그 수정 + doc-freshness 게이트). 워밍업.
2. **WS2 → 1.2.0의 핵심.** WS2a(측정)가 게이트로 먼저 안착하고, WS2b/c/d는 *코퍼스에 대해* 개발되어 모든 변경이 precision/recall 신호를 갖습니다.
3. **WS3** (주입 seam + 정직한 다중 복제 문서).
4. **WS4** (운영성: health/metrics/logging/deploy).
5. **WS6** (신뢰 자산).

WS2–WS6은 **1.2.0** 하에 additive·opt-in 조이기로 안착합니다(API freeze 보존: 새 config 키는 additive이며, `minConfidence`/`allowlist`는 정책 *동작*을 바꾸지만 additive하게, 1.1 동작을 보존하는 기본값 뒤에서만 — `tests/api-contract.test.mjs`로 검증).

## 4. 가드레일 (회귀 금지)
- 코어의 **런타임 의존성 0**을 유지합니다. 공유 상태/metrics 구현은 주입 seam이거나 satellite이며, 결코 코어 의존성이 아닙니다.
- **audit 평문/PII 금지**를 모든 신규 telemetry(metric 라벨, 구조화 로그)로 확장합니다.
- 모든 신규 경로(깊이 가드, backpressure, readiness, env 오버레이)에 **fail-closed** 자세를 유지합니다.
- **EN + KO 문서**를 함께 이동하며, 신규 KO 내용은 합쇼체로 작성합니다.
- 각 워크스트림은 워크플로우로 구축하고 머지 전에 적대적으로 검증하며, test + `check:types` + `release:preflight` 증거와 함께 출하합니다.

## 5. 명시적 비목표
- 내장 분산 rate limiter / audit sink / token vault(Redis/DB). 이 트랙은 **seam + 정직한 문서**까지만 추가하며, 운영 공유 저장소는 향후 satellite입니다.
- ML/임베딩 기반 탐지. 탐지는 regex + 검증기를 유지하며, 작업은 측정 + 정밀도 제어 + 잘 알려진 형식 커버리지입니다.
- 새 추론 백엔드나 새 플러그인 종류. 이 트랙은 제품 표면을 넓히지 않습니다.
- 컴플라이언스 *인증*. WS6은 통제 **매핑**과 공개 자산을 산출하며, 인증 주장은 하지 않습니다.
