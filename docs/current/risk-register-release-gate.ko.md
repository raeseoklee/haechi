# Haechi 리스크 레지스터 및 릴리스 게이트

- 문서 상태: Living document(core 1.5.x 추적)
- 작성일: 2026-06-16
- 기준 버전: 1.5.x
- 기준 브랜치: `main`

## 1. 현재 판단

Haechi는 `1.x` stable 라인을 출시했습니다. developer preview 게이트(G2, `haechi@0.3.2`)부터 G8(1.3.0 backend + detection coverage expansion)까지 모든 게이트가 통과되었으며, 아래 게이트 이력은 감사 추적으로 보존합니다. 1.0.0은 strict semver 하의 frozen API 계약을 선언하고(문서화된 deprecation 정책과 freeze 가드 `tests/api-contract.test.mjs` 포함), signed·sandboxed `authProvider` plugin에 한해 dynamic-loading 금지를 좁게 해제했습니다. 1.1.0은 커널 수준 capability 거부를 갖춘 opt-in `process-isolated` plugin 런타임을 추가했습니다. stable 표현을 막던 조건 — 1.0 API 안정성, 외부 `cryptoProvider`/KMS reference adapter(`haechi-crypto-kms`), stream-aware enforcement(`streaming.requestMode: "inspect"`) — 은 모두 갖춰졌습니다. Haechi는 여전히 컴플라이언스를 보장하지 않는 self-hosted 보안 toolkit이며, 운영 배포는 네트워크 접근 통제, upstream 인증, key custody를 직접 책임집니다(threat model §5 참고).

**2026-06-16 코드리뷰 보완 — `haechi@1.3.1`로 발행:** 전체 코드리뷰 결과를 `docs/current/code-review-risk-register-2026-06-16.ko.md`에 등록부로 열었습니다. 이 리뷰에서 P0 credential-boundary leak 1건, P1 릴리스 차단 이슈 4건, P2 하드닝/테스트 공백 8건이 확인됐습니다. **13개 `P*-CR-*` 항목이 모두 Resolved이며(§5.7) `haechi@1.3.1` 보완 컷(2026-06-16, attested OIDC publish)으로 발행되었습니다.** G9은 **Pass**입니다. 운영자는 수정 사항(특히 P0-CR-001 프록시 헤더 경계 패치)을 반영하려면 `haechi@1.3.0`에서 `1.3.1`로 업그레이드해야 합니다.

| 구분 | 판단 | 이유 |
|---|---|---|
| GitHub public | 허용 | 보안 한계, threat model, shared responsibility가 문서화됨 |
| GitHub release/tag | 허용 (`v1.5.0` 릴리스됨) | `v1.5.0`이 현재 릴리스(additive minor — 수평 확장을 위한 주입 가능한 audit/token-vault 저장소 시임); §5.7 / §5.8 항목은 모두 Resolved 유지, G9–G12는 Pass |
| npm stable | `haechi@1.5.0` publish됨 | `1.5.0`은 `1.4.x` 기준 위에 `createAuditSink`/`createTokenVault` 저장소 시임(파일 기본값 바이트 동일)을 더한 attested OIDC publish; config/API 파괴 없음(`configVersion`은 `1` 유지) |
| production use | 운영자 게이트; `1.5.0`로 업그레이드 | 운영자 네트워크 통제, 인가/인증, key custody가 있을 때만 지원; 여러 replica를 운영하는 운영자는 공유 저장소(`haechi-store-redis` 위성)를 주입해 audit 해시 체인과 token vault가 플릿 전체에서 유지되도록 해야 함 |

## 2. 릴리스 게이트

| Gate | 대상 | 기준 | 현재 상태 |
|---|---|---|---|
| G0 | GitHub source 공개 | 테스트 통과, 보안 한계 문서화, 평문 audit leak 없음 | Pass |
| G1 | GitHub pre-release | P0 코드 리스크 해결, production-ready 표현 없음 | Pass |
| G2 | npm developer preview | P0 해결, preflight/SBOM/provenance 경로 준비, npm auth 확인 | Pass (`haechi@0.3.2` 2026-06-10 배포) |
| G3 | npm stable | P1 운영 reference, stream-aware enforcement, API stability 강화 | Pass (1.0.0 stable 컷에서 달성 — streaming inspection은 0.5, API freeze는 1.0.0에서 출시; G5 참조. G5–G7로 대체됨.) |
| G4 | 0.9.0 observability + interactive-auth 위성 컷 | P1-SEC-026 / P1-OPS-009 mitigated 및 P2-CRYPTO-001 accepted; `haechi-dashboard` + `haechi-auth-oidc` + `haechi-crypto-kms@0.2.0` 테스트 통과; 위성 tarball zero-dep; core 0.9.0 bump(추가적 FORBIDDEN_KEYS audit 강화만) | Pass |
| G5 | 1.0.0 stable API contract + signed-plugin sandbox | P1-SEC-024 / P1-SEC-025 mitigated, P2-API-001 / P2-OPS-006 resolved; API freeze + deprecation policy + `tests/api-contract.test.mjs` 통과; Ed25519 signed-plugin contract + `assertAuthProviderConformance` + worker-isolated `authProvider` sandbox 테스트 통과; PR0 위성 peer-range를 `>=0.8.0 <2.0.0`로 확대 및 `check-satellite-peer-ranges.mjs` preflight 게이트 통과; core는 zero runtime dependency 유지; core 1.0.0 bump | Pass |
| G6 | 1.1.0 plugin capability 강제 (`process-isolated`) | P1-SEC-027 / P1-SEC-028 mitigated; `process-isolated` 런타임(`--permission` 하 자식, 부여 0, `data:` URL 로드, stdio 무시, JSON-string IPC) + fail-closed `--allow-net` 기능 탐지(`netEnforcement:"require-permission"`) + 코어 `haechi/ssrf` 가드 + 호스트 중개 키 자료 + spawn-storm 서킷 브레이커; fs/net/stdio 레드팀 + SSRF + config 테스트 통과(행동 스위트는 `--allow-net` Node에서 실행, 아니면 fail-closed로 skip); API freeze 통과 유지(additive `./ssrf` export + additive config 키); core는 zero runtime dependency 유지; core 1.1.0 bump(additive + opt-in 마이너) | Pass |
| G7 | 1.2.0 신뢰성 강화 트랙 (WS1–WS6) | 탐지 품질 측정+강화(WS2: 라벨 코퍼스 precision/recall `bench:detection` 게이트, 자격증명+국제 PII 커버리지, 하드블록 타입 불변식이 적용된 `filters.minConfidence` / `filters.allowlist`, offset 무결성을 갖춘 NFKC 유니코드 회피 폴딩); WS3 주입 가능한 `rateLimiter` 시임 + bounded fixed-window map; WS4 운영성(`/__haechi/live`+`/ready` 분리, 주입 가능한 `/metrics`, 구조적 로그 + 요청별 `correlationId`, graceful drain, max-in-flight backpressure, env overlay, 하드닝 Dockerfile/compose/runbook, `configVersion`); WS6 proxy TLS / remote-bind 하드닝(`proxy.tls` / `proxy.trustForwardedProto`, fail-closed `assertSafeProxyTransport`) + OWASP-LLM/NIST 컨트롤 매핑 백서 + RFC 9116 `security.txt` + 취약점 공개 경로. 모든 변경은 1.1 동작을 보존하는 기본값 뒤의 additive(`tests/api-contract.test.mjs` 통과); no-plaintext-in-audit 불변식이 텔레메트리까지 확장; core는 zero runtime dependency 유지; core 1.2.0 bump(additive 마이너) | Pass |
| G8 | 1.3.0 백엔드 + 탐지 커버리지 확장 | **Anthropic Messages API**(`/v1/messages`, content-block + SSE `delta.text`, `event:` 라인 보존 재직렬화)와 **Google Gemini API**(model-in-path `:generateContent`/`:streamGenerateContent`, 기존 정확-매칭 어댑터를 바이트 동일하게 두는 additive `:method`-suffix 라우트 매처) 프로토콜 어댑터 추가; 탐지 커버리지 확장 — 클라우드/SaaS provider 키(OpenAI/Anthropic/Google-OAuth/SendGrid/Twilio/npm/Azure, anchored)와 국제 PII(FR/ES/JP + IT/SG/IN/DE/NL 국가 ID, 체크섬 validator), 각 하드블록-대-dial-eligible 결정은 측정된 충돌률 기반(하드블록은 비숫자 앵커 또는 비현실적으로 드문 형태가 필요; 흔한 길이의 bare-digit run은 allowlist로 정리 가능 유지); `bench:throughput` proxy 부하 벤치; `haechi-ratelimit-redis` 공유 저장소 rate-limiter 위성(WS3 시임의 운영 소비자; proxy가 이제 `rateLimiter.allow`를 `await`); `haechi-dashboard`가 요청별 `correlationId` 노출. 모든 변경은 additive — 새 `target.type`/탐지타입/`privacy.profile` *값*이며 새 config 키가 아님(`configVersion`은 `1` 유지); `tests/api-contract.test.mjs` 통과; core는 zero runtime dependency 유지; core 1.3.0 bump(additive 마이너) | Pass |
| G9 | 2026-06-16 전체 코드리뷰 보완 게이트 (1.3.1로 발행) | `P0-CR-001` 및 `P1-CR-002`부터 `P1-CR-005`까지 해결 또는 책임자 명시 수용; P2 항목은 해결 또는 명시적 non-blocking 근거와 일정 기록; 연결된 등록부 갱신. **13개 `P*-CR-*` 항목이 모두 Resolved이며(§5.7) `haechi@1.3.1`(2026-06-16, attested OIDC publish)로 발행되었습니다; core가 1.3.0 → 1.3.1로 bump(patch, 보완 전용 — API/config 표면 변경 없음, `configVersion`은 `1` 유지)되었습니다.** | Pass (`haechi@1.3.1`, 2026-06-16) |
| G10 | 2026-06-16 코드리뷰 round 2 (CR2) 보완 게이트 | CR2 등록부(`code-review-risk-register-2026-06-16-round2.md`, §5.8)는 **P0/P1을 발견하지 못했습니다**; 세 개의 P2(`CR2-001` 프록시 upstream-cancel, `CR2-002` token-vault audit hygiene, `CR2-003` plugin IPC reply 경계)와 P3 묶음(`CR2-004..008`)이 모두 **Resolved이며 `haechi@1.3.2`로 발행되었고**(`CR2-009` won't-fix, `CR2-010` accepted) 연결된 등록부가 갱신되었습니다. | Pass (`haechi@1.3.2`, 2026-06-16) |
| G11 | 1.4.0 signed-plugin 저작 CLI | 1.0 Ed25519 trust gate를 위한 1차 저작 CLI — `plugin-keygen`(개인키 `0600`, 공개키 = trust anchor), `plugin-sign`(정확한 entry 바이트 바인딩), `plugin-verify`(런타임 동등 검증, fail-closed, `--allow-capability`); 개인키가 stdout/audit로 유출되지 않음; 적대적 검증 완료; `plugin-signing-and-trust.md` 큐레이션 런북이 P1-SEC-025 "운영자가 앵커를 큐레이션해야 함" 잔여를 해소. additive CLI 표면(config/API 파괴 없음, `configVersion`은 `1` 유지); `tests/api-contract.test.mjs` green; 코어는 zero runtime dependency 유지; 코어 1.3.3 → 1.4.0(additive minor)로 bump. | Pass (`haechi@1.4.0`, 2026-06-17) |
| G12 | 1.5.0 수평 확장 저장소 시임 | audit sink와 token vault가 주입 가능한 **store**를 갖게 되어, 공유 저장소가 sha256 해시 체인 + token vault를 replica 전반에서 뒷받침할 수 있음(프로세스별 / 단일 writer 플릿 한계를 해소). `createAuditSink({store})` / `createTokenVault({store})` + 기본 `createFileAuditStore`/`createFileTokenStore`; 보안에 결정적인 chaining / `sanitizeAudit` / reveal governance / retention은 코어에 남고, store는 배타적 read-previous+persist(audit) / mutate+read(vault) 프리미티브만 추상화. 적대적 검증 완료: 파일 기본값 바이트 동일, chain 연산은 이전과 diff 동일, 비파일 store에서도 시임 동작, 동시 append/tokenize가 비분기·무손실 유지, CR2-002 audit-no-plaintext 유지. 새 export는 `api-stability.md` + `tests/api-contract.test.mjs`에 frozen; `createJsonlAuditSink`/`createLocalTokenVault`는 하위호환 래퍼; 코어는 zero runtime dependency 유지; 코어 1.4.0 → 1.5.0(additive minor)로 bump. `haechi-store-redis` 위성이 운영 소비자. | Pass (`haechi@1.5.0`, 2026-06-17) |

## 3. P0 배포 차단 리스크 상태

| ID | 기존 리스크 | 상태 | 해소 증거 |
|---|---|---|---|
| P0-REL-001 | npm 인증/권한 미해결 | Resolved | 2026-06-10 로컬 패스키 인증으로 `haechi@0.3.2` publish 성공, npm 인증·package ownership 확정 |
| P0-REL-002 | proxy 외부 노출 위험 | Resolved | non-loopback bind는 기본 실패, `--allow-remote-bind` 필요 |
| P0-REL-003 | streaming 요청 처리 불명확 | Resolved | `stream: true` 기본 501 fail-closed, `streaming.requestMode: "pass-through"` 명시 필요 |
| P0-REL-004 | responseProtection 실패 모드 불명확 | Resolved | 비JSON/invalid JSON/압축/대용량 응답 fail-closed, 명시 allow 정책 분리 |
| P0-REL-005 | local dev key의 운영 오해 | Resolved | `init`, README, SECURITY에 dev-only key와 운영 key provider 부재 경고 |
| P0-REL-006 | npm package 신뢰 표현 과다 | Resolved | package description/README/SECURITY를 experimental developer preview로 조정 |

## 4. P1 보안 설계 리스크 상태

| ID | 기존 리스크 | 상태 | 해소 증거 |
|---|---|---|---|
| P1-SEC-001 | KMS/HSM/Vault 미지원 | Resolved for OSS core | `createRuntime(config, { cryptoProvider })` 외부 crypto provider injection, external provider 없으면 fail-closed |
| P1-SEC-002 | TokenVault 권한 모델 부족 | Resolved | `revealPolicy: "disabled"` 기본값, `--allow-dev-reveal`, metadata export, retention/purge timestamp |
| P1-SEC-003 | audit 무결성 부족 | Resolved | JSONL audit SHA-256 hash chain 및 `verifyAuditChain` |
| P1-SEC-004 | plugin runtime 없음 | Resolved by gating (P1-SEC-024이 대체) | dynamic runtime 거부, `manifest-only` plugin만 통과. **1.0에서 P1-SEC-024(§5.4)이 대체합니다.** 1.0은 manifest-only-only 입장을 의도적으로 해제하고, 새 신뢰 통제 하에 signed·capability-gated·worker-isolated·audited `authProvider` plugin에 한해 동적 로딩을 **좁게** 허용합니다 |
| P1-SEC-005 | policy conflict 처리 부족 | Resolved | preset block 등 강한 action을 약한 action으로 낮추면 conflict fail-closed |
| P1-SEC-006 | regex 중심 필터 정확도 한계 | Resolved for preview | KR RRN checksum, Luhn, unsafe custom regex 제한. ML/classifier plugin은 stable backlog |
| P1-SEC-007 | AAD/replay/stream 확장 부족 | Resolved for preview | AAD hash mismatch 명시, streaming 기본 차단. stream sequence/replay cache는 stream support 도입 시 필요 |
| P1-SEC-008 | MCP security contract 미완성 | Resolved for preview | JSON-RPC 2.0 요구, method allowlist, params/result 보호 토글. OAuth resource binding은 외부 MCP layer 책임 |

## 5. P1 운영/배포 리스크 상태

| ID | 기존 리스크 | 상태 | 해소 증거 |
|---|---|---|---|
| P1-OPS-001 | CI 부재 | Resolved | `.github/workflows/ci.yml` |
| P1-OPS-002 | SBOM/provenance 부재 | Resolved | `npm run sbom`, `.github/workflows/npm-publish.yml`, `publishConfig.provenance` |
| P1-OPS-003 | 실제 vLLM/Ollama/llama.cpp 통합 테스트 부재 | Resolved for preview | env-gated optional local inference integration tests 추가. CI는 외부 모델 서버 없이 skip |
| P1-OPS-004 | 성능/대용량 payload 미측정 | Resolved for preview | request/response byte limit, `npm run bench:payload` |
| P1-OPS-005 | npm ownership 미확정 | Resolved | `npm view haechi version`이 `0.3.2` 반환, 최초 publish 성공으로 ownership 확정 |

## 5.1 추가 보안 검토 리스크 해소 상태

| ID | 추가 검출 리스크 | 상태 | 해소 증거 |
|---|---|---|---|
| P1-SEC-009 | proxy absolute-form request target으로 upstream 우회/SSRF 가능 | Resolved | absolute/protocol-relative request target을 `haechi_invalid_proxy_target`으로 거부하고, upstream URL은 path/search만 고정 upstream에 결합 |
| P1-SEC-010 | `responseProtection.maxBytes`가 full buffer 이후 검사되어 메모리 DoS 가능 | Resolved | upstream body를 stream reader로 제한 읽기하고 초과 즉시 cancel/fail-closed. `failureMode: "allow"`도 hard byte cap은 우회 불가 |
| P1-SEC-011 | audit hash chain이 동시 기록에서 sequence/previousHash 충돌 가능 | Resolved | JSONL audit sink 단위 write queue와 lock file로 hash-chain record build와 append를 직렬화 |
| P1-SEC-012 | JSON object key에 포함된 PII/secret이 audit path 또는 token metadata에 노출 가능 | Resolved | detection `pathText`를 raw key 대신 `key_<hash>` 구조 path로 기록 |
| P1-SEC-013 | local TokenVault 동시 tokenization/purge에서 update lost 가능 | Resolved | vault mutation queue, lock file, temp-file 후 rename 방식의 atomic write 적용 |
| P1-SEC-014 | `streaming.requestMode: "pass-through"` 및 `responseProtection.failureMode: "allow"` 우회 결정 audit 부재 | Resolved | raw payload 없이 `streaming_request_pass_through`, `response_unprotected_allowed/blocked` decision audit 기록 |
| P1-SEC-015 | MCP `allowedMethods` 원소 타입 검증 부족 | Resolved | non-empty string만 허용하도록 config validation 강화 |
| P1-OPS-006 | GitHub Actions major tag pinning으로 supply-chain drift 가능 | Resolved | `checkout`, `setup-node`, `upload-artifact`를 확인된 commit SHA로 고정 |

## 5.2 2차 전체 코드 리뷰 리스크 해소 상태 (0.3.2)

| ID | 검출 리스크 | 상태 | 해소 증거 |
|---|---|---|---|
| P0-SEC-016 | Ollama `/api/chat`·`/api/generate`는 `stream` 생략 시 기본 streaming이라 streaming 차단 우회 가능 | Resolved | protocol adapter에 `streamingDefault` 도입, `stream: false` 명시 없으면 streaming으로 간주해 기본 501 fail-closed |
| P1-SEC-017 | token reveal/purge가 audit 미기록 | Resolved | local TokenVault에 auditSink 주입, `reveal_allowed/denied/failed`, `purge`, `purge_expired` decision audit (plaintext 비포함) |
| P1-SEC-018 | privacy profile이 사용자 명시 정책을 조용히 약화 가능 | Resolved | `applyPrivacyProfile`이 ACTION_STRENGTH 비교로 강화만 허용 |
| P1-SEC-019 | decrypt가 envelope `kid` 무시, `init --force` 시 기존 키 파기로 vault/암호문 영구 손실 | Resolved | kid 기반 키 선택, `--force`는 기존 키를 `retired`로 보존하는 rotation으로 변경 |
| P1-SEC-020 | policy bundle 서명이 AES 암호화 키를 HMAC 키로 재사용 (key separation 위반) | Resolved | `haechi:policy-bundle:signing:v1` domain-separated 파생 서명 키 적용 |
| P1-SEC-021 | `retentionDays`가 reveal만 차단하고 만료 데이터 미삭제 | Resolved | vault mutation 시 만료 토큰 자동 prune, `purgeExpired()` 및 `haechi token-purge --expired` 추가 |
| P1-SEC-022 | upstream fetch 타임아웃 부재로 연결 고갈 가능 | Resolved | `limits.upstreamTimeoutMs`(기본 120000) + `504 haechi_upstream_timeout` |
| P1-SEC-023 | JSON number(카드번호)와 object key 내 PII/secret 미탐지 전달 | Resolved | number leaf와 object key를 detection/transform 대상에 포함 (key는 enforce 시 rename) |
| P1-OPS-007 | stale lock file 잔존 시 audit/vault 기록 영구 실패 | Resolved | 30초 초과 stale lock 자동 탈취 후 재획득 |
| P1-OPS-008 | audit append가 매 기록마다 전체 파일 재읽기 (O(n²)) | Resolved | 파일 tail-chunk 읽기로 O(1) append |
| P2-SEC-024 | unknown `target.type`이 openai-compatible로 silent fallback | Resolved | 알 수 없는 type은 config 검증 단계에서 fail-closed |
| P2-SEC-025 | 짧은 값 mask 시 대부분 노출 (5자 중 4자) | Resolved | 8자 이하 전체 마스킹 |
| P2-SEC-026 | assignment-secret redaction이 key 이름까지 제거 | Resolved | lookbehind 패턴으로 secret 값만 치환 |
| P2-SEC-027 | MCP notification에 JSON-RPC 스펙 위반 error 응답, batch 비명시 처리 | Resolved | notification은 drop, batch는 명시적 fail-closed 거부 |
| P2-SEC-028 | proxy 내부 오류 메시지가 클라이언트에 노출 | Resolved | 예기치 못한 오류는 일반화된 메시지 반환, 상세는 stderr |
| P2-DOC-005 | dry-run + responseProtection off 기본값에서 "보호 중" 오인 가능 | Resolved | proxy 기동/`protect` 출력에 비집행 경고 명시 |

base64/인코딩 값 디코딩 검사, query string 검사, audit tail truncation 탐지는 명시적 제외로 threat model에 문서화했습니다 (0.4+ backlog).

## 5.3 0.9.0 Observability + Interactive-Auth 리스크 상태

이 ID들은 0.9.0 위성 컷(`haechi-dashboard`, `haechi-auth-oidc`, `haechi-crypto-kms@0.2.0`)에 한정되며, 0.9.0 섹션으로 namespace되어 위의 동일 번호 P0/P1 행과 구분됩니다. 증거는 위성 소스, 그 테스트 스위트, 그리고 `docs/current/release-0.9-implementation-scope.md` §6에 정리된 adversarial security review입니다.

| ID | 리스크 | 상태 | 해소 증거 |
|---|---|---|---|
| P1-SEC-026 | OIDC broker 세션/로그인 보안: `haechi-auth-oidc`의 login CSRF, authorization-code injection, open-redirect, session fixation, mix-up(잘못된 IdP/RP) | Mitigated | `satellites/auth-oidc/index.mjs`: state-first `/auth/callback`(pre-auth 쿠키 바인딩 pending record를 atomic `take()` + egress 이전 constant-time `state` 비교), PKCE S256, callback에서 새 세션 id 발급(fixation 없음), `returnToAllowlist`(open-redirect 없음), issuer/endpoint pinning + RFC 9207 `iss` 검사 + 공유 `createJwtVerifier` 경유 ID-token `aud`/`azp` 프로파일(mix-up), CSRF-gated non-GET logout. `satellites/auth-oidc/auth-oidc.test.mjs`가 각 deny 케이스 검증; scope §6 adversarial review. **잔여:** multi-origin IdP는 범위 외 |
| P1-OPS-009 | Dashboard audit 노출: `haechi-dashboard`의 `detections[].path` stored XSS, 미래 필드 audit leak, localhost 뷰어 DNS-rebinding 읽기, remote bind 시 인증 없는 읽기 | Mitigated | `satellites/dashboard/index.mjs` + `assets.mjs`: 엄격 CSP(`require-trusted-types-for 'script'`) + `textContent`-only 렌더링(XSS), `FORBIDDEN_KEYS` 위 재귀적 key-by-key allowlist projection(필드 leak), 요청별 anti-rebinding `Host` allowlist + CORP/COOP same-origin(rebinding), `sessionGuard` **및** TLS 종단을 요구하는 fail-closed remote bind(인증 없는 remote 읽기). `satellites/dashboard/dashboard.test.mjs`; scope §6 adversarial review. **잔여:** remote bind 시 운영자가 TLS 종단을 책임 |
| P2-CRYPTO-001 | KMS backend egress: `haechi-crypto-kms@0.2.0` Vault/GCP/Azure backend가 key material이나 provider/key-path 상세를 유출하거나 의도치 않은(metadata) 엔드포인트에 도달 가능 | Accepted | `satellites/crypto-kms/{vault,gcp,azure}.mjs`: optional-peer + injected-client 모델과 faithful-mock `assertCryptoProviderConformance`(cross-key·corrupted-blob 거부, HMAC determinism/domain-separation), Vault `fetch`의 satellite-local `isBlockedAddress` SSRF 가드(dev-only `satellites/crypto-kms/ssrf-parity.test.mjs`로 auth-jwt와 parity 유지), generic fail-closed provider-error 매핑(audit에 provider/key-ARN 없음). `{vault,gcp,azure}.test.mjs` + `crypto-kms.test.mjs`; scope §6 adversarial review. **수용된 잔여:** 실제 Vault/GCP/Azure live-backend 검증은 CI 외부; 발행 tarball은 zero runtime dependency 유지 |

## 5.4 1.0.0 Stable API Contract + Signed-Plugin Sandbox 리스크 상태

이 ID들은 1.0.0 stable 컷(API freeze + Ed25519 signed, worker-isolated `authProvider` plugin sandbox)에 한정됩니다. 권위 있는 threat 행과 범위는 `docs/current/release-1.0-implementation-scope.md` §6이며, 증거는 PR(#46–#49), core 소스, 그리고 테스트 스위트입니다.

| ID | 리스크 | 상태 | 해소 증거 |
|---|---|---|---|
| P1-SEC-024 | 동적 plugin 실행 / sandbox 신뢰 모델: worker sandbox에 로딩된 signed `authProvider` plugin이 host(`fs`/`net`/`process.env`)를 악용하거나 받은 credential을 exfiltrate할 수 있음. **P1-SEC-004의 manifest-only 입장을 대체** — 1.0이 의도적으로 해제하고 새 통제 하에 좁게 동적 로딩 허용 | Mitigated | `packages/plugin/sandbox.mjs` `createSandboxedAuthProvider`(PR #49): `node:worker_threads` memory/crash 격리, 메모리 내 검증된 spawn(경로 재해석/TOCTOU 없음), data-minimized JSON-string wire(credential slice만 전달; host가 keyed-HMAC identity 구성), null-proto claims sanitizer, single-occupancy + correlation-id 동시성, 필수 `timeoutMs` terminate + `resourceLimits`/`maxPendingCalls`/`maxMessageBytes`, kill-switch(`plugins.enabled:false`), 매 respawn마다 전체 게이트 재실행. lifecycle audit(`plugin.load.*`/`authenticate.deny`/`worker.terminated`) + 확장된 `FORBIDDEN_KEYS`; audit identity는 frozen 5 키 `{id,type,subjectHash,issuerHash,provider}`로 projection. 테스트: §7.4 fail-closed + 격리 매트릭스, `auth.provider:"plugin"` `normalizeConfig` fail-closed 테스트, `createRuntime` + proxy auth end-to-end. **잔여:** `node:worker_threads`는 memory/crash 격리 + data-minimization이지 capability sandbox가 아님 — 악의적 signed plugin의 `fs`/`net`/`process.env`는 차단되지 않고 받은 credential을 exfiltrate할 수 있음; 오직 signing/vetting 신뢰 모델로만 통제. 진짜 집행(child-process + Node permission model)은 **1.1의 opt-in `process-isolated` 런타임에서 제공됨**(P1-SEC-027, §5.5) — `--allow-net` Node에서; `worker_threads`(1.0) 모드는 불변이며 이 잔여를 유지 |
| P1-SEC-025 | plugin signing / trust-anchor / revocation lifecycle: signer-key confusion/downgrade/rollback, swap(TOCTOU)된 entry, 또는 revoked/expired signer의 코드 로딩 | Mitigated | `packages/plugin/signing.mjs` `verifySignedPlugin`(PR #48): `canonicalize({pluginId, kind, version, capabilities, coreVersionRange, entrySha256, notBefore, notAfter})`에 대한 Ed25519(asymmetric, `node:crypto`) 서명 — `entrySha256` 바인딩(anti-swap), **trust-anchor-only** 키 해석(`signerKeyId` ∉ allowlist면 verify 이전 거부; 알고리즘 Ed25519 고정; signer 집합은 AES rotation 키 파일과 분리), pin + `pluginId`별 version-floor(anti-rollback/malicious-update) + `revokedSignerKeyIds`/`revokedEntrySha256` denylist + `notBefore`/`notAfter` window, 모두 load 시 fail-closed이며 매 respawn마다 재검증. `assertAuthProviderConformance`(`haechi/auth`, `assertCryptoProviderConformance`의 auth 대응)는 load별 randomized vectors를 쓰는 정합성 게이트; host가 call별 PII-safety 재검증. 테스트: §7.3 reason별 거부 매트릭스(각각 `plugin.load.refused{reason}` 방출), conformance negative 테스트, `FORBIDDEN_KEYS` 확장 `sanitizeAudit` 테스트. **잔여:** 운영자가 trust anchor/pin을 curate해야 함; live revocation feed / CRL은 1.x(revocation은 다음 load에 적용; kill-switch가 live plugin을 force-drop) |
| P2-API-001 (1.0) | stable-contract freeze + deprecation policy: 불안정 public API / audit-schema drift가 major bump이나 마이그레이션 경로 없이 consumer를 깨뜨림 | Resolved | `docs/current/api-stability.md`(+ko)(PR #47): IN/OUT surface 표, 1.0부터 strict semver, deprecation policy(≥1-minor 유지 + `HAECHI_DEPRECATION_*` runtime-warning 계약 + disclosed-vulnerability in-minor security exception), nested sub-schema 포함 frozen audit event schema + additive `schemaVersion`, config-schema freeze unit(key presence/shape 동결; 더 안전한 default는 허용). `tests/api-contract.test.mjs`가 freeze 가드: subpath별 exports + 전체 audit event(non-null `identity` + `detections[]` 1건) + config key set + `schemaVersion`을 pin; additive 필드는 통과, 제거/개명(top-level OR nested)은 실패, `verifyAuditChain`은 synthetic additive 필드가 있어도 frozen-schema fixture를 검증. **잔여:** major bump은 설계상 깨질 수 있음(문서화된 마이그레이션); disclosed-vulnerability security exception은 advisory + 마이그레이션 경로와 함께 sanctioned in-minor break 허용 |
| P2-OPS-006 (1.0) | satellite peer-range / major-tracking 게이트: core를 1.0.0으로 bump하면 모든 위성의 `>=0.8.0 <1.0.0` peer가 unsatisfiable(ERESOLVE)되어 위성 설치가 깨짐 | Resolved | PR0(#46)이 네 위성의 `haechi` peer range를 `>=0.8.0 <2.0.0`로 확대(버전 auth-jwt 0.2.1, crypto-kms 0.2.1, dashboard 0.1.2, auth-oidc 0.1.2; auth-oidc의 `haechi-auth-jwt`도 `<2.0.0`)하고 lockfile 재생성(workspace-lockfile 갭). `scripts/check-satellite-peer-ranges.mjs`는 모든 위성에 대해 `semver.satisfies(coreVersionToPublish, range)`를 단언하는 `release:preflight` 게이트로 core `1.0.0`을 시뮬레이션. `api-stability.md §5`에 위성 peer 상한이 core MAJOR를 추종함을 문서화. **잔여:** core 1.0.0 출시 전에 위성을 재발행해야 1.0.0에 대해 설치됨 |

## 5.5 1.1.0 Plugin Capability 강제 리스크 상태

| ID | Risk | Status | Resolution evidence |
|---|---|---|---|
| P1-SEC-027 | Plugin capability *강제*: 1.0 `worker_threads` sandbox는 memory/crash 격리뿐이라 악의적 signed plugin이 `fs`/`net`을 써서 credential을 exfiltrate할 수 있음. **P1-SEC-024의 수용된 worker 잔여를 강화** — 1.1이 새 opt-in 런타임에 실제 강제 추가 | Mitigated | `packages/plugin/process-sandbox.mjs` `createProcessIsolatedAuthProvider`/`…Sync`(PR #54): signed `authProvider`가 `--permission` 하 자식 `node`에서 **부여 0**(fs/child-process/worker/addons/wasi 없음, `--allow-net` 없음)으로, `data:` URL 로드(fs 권한 없음 → TOCTOU/symlink 표면 없음), `stdio:['ignore','ignore','ignore','ipc']`(stdout/stderr/fd 유출 채널 없음), 정화 env, JSON-string 전용 IPC + 공유 null-proto sanitizer + 호스트측 keyed-HMAC identity로 실행됩니다. **Node 26 실측 검증**: plugin의 `fs`/`net`/`fetch`/`dns`/`child_process`/`worker`와 `process.binding('tcp_wrap')` 우회가 모두 `ERR_ACCESS_DENIED`. 네트워크 봉쇄는 **커널 `--allow-net` 거부**(삭제 가능한 JS 하니스가 아님); 기본값 `netEnforcement:"require-permission"`은 강제 못 하는 Node에서 **fail closed**(동작 probe 기능 탐지; PR #54). spawn-storm 서킷 브레이커(PR #56)가 재spawn 제한. lifecycle audit에 호스트 계산/enum 전용 `isolation`/`grants`/`netEnforcement` 추가(PR #56). config: `auth.plugin.isolation:"process"` fail-closed 배선(PR #56). 테스트: fs/net/stdio 레드팀(`--allow-net` 없는 Node에선 fail-closed라 skip) + 상시 실행 fail-closed 계약 + config 매트릭스. **잔여:** `--allow-net` 없는 Node(fail-closed, 미봉쇄); `networkEgress` 부여 plugin; 자식 메모리의 credential/키 자료(core-dump/swap); V8/Node 탈출(런타임 통제일 뿐 OS 샌드박스 아님) |
| P1-SEC-028 | 호스트 중개 키 자료 + SSRF: 키 자료가 필요한 커스텀 자격증명 plugin이 plugin 주도 SSRF 벡터가 될 수 있고, 코어엔 SSRF 가드가 없었음(위성 복사본은 코어에서 도달 불가) | Mitigated | 새 node:-only, 의존성 0 **`haechi/ssrf`** 코어 모듈(PR #55): `isBlockedAddress`(private/loopback/link-local/metadata), `guardedFetch`(https 전용, DNS 후 재확인, `redirect:"error"`, 본문 제한 + timeout), `createGuardedKeyFetcher`(TTL 캐시 + cooldown). `process-isolated` 런타임의 선택적 `keyMaterial:{url}`은 **호스트**가 **운영자 선언** URL에서 이 가드로 가져와 IPC로 주입하므로, plugin은 URL을 명명하지 않습니다(plugin 주도 SSRF 없음). kid-refetch cooldown이 아웃바운드 비율을 제한하고, blocked-address URL은 fail closed됩니다. 테스트: 표준 `isBlockedAddress` 벡터 테이블 + 코어-대-`auth-jwt` parity 가드, `guardedFetch` SSRF 거부/제한, cooldown fail-closed, 런타임 키 주입 + no-SSRF. **잔여:** 위성은 의도적으로 로컬 복사본을 유지함(crypto/auth 패키지는 core-ssrf에 런타임 의존 금지; `crypto-kms/ssrf-parity.test.mjs`) — 코어 재import는 연기하며, drift는 제거가 아니라 parity로 가드; 가드의 DNS-rebinding 창(resolve-then-connect)은 운영자 선언 URL에 대해 수용 |

## 5.7 2026-06-16 전체 코드리뷰 Open 리스크 상태

권위 있는 항목별 등록부는 `docs/current/code-review-risk-register-2026-06-16.ko.md`입니다. 이 절은 릴리스 게이트 요약입니다. **13개 항목이 모두 Resolved이며 `haechi@1.3.1`로 발행되었습니다**(2026-06-16): P0 + 네 개의 P1(프록시 헤더 경계 패치, SSRF IPv4-mapped 정규화, response-header/streaming 경계, streaming-inspection 텍스트 수정)과 여덟 개의 P2 모두(CR-006 mcp-wrap stderr filter, CR-007 init key-file 검증, CR-008 satellite `manifest.bin` check, CR-009 auth-throw 회귀 테스트, CR-010 process-sandbox quota 테스트, CR-011 audit middle-tamper 테스트, CR-012 vault IPv6 테스트, CR-013 SSE multi-line `data:`). **G9은 Pass입니다.**

| ID | 리스크 | 상태 | 종료에 필요한 증거 |
|---|---|---|---|
| P0-CR-001 | 프록시가 클라이언트 `Authorization`, `Cookie`, proxy-auth 등 주변 자격증명을 모델 업스트림으로 전달 | Resolved | `filteredHeaders()`의 기본 차단 업스트림 헤더 허용목록 + `createHaechiProxy`에서 전달되는 `forwardPolicy`(게이트웨이 클라이언트 인증과 업스트림 공급자 인증 분리: `auth.provider !== none`이면 클라이언트 `Authorization` 폐기, `none`이면 전달); cookie/proxy-auth/hop-by-hop 항상 폐기; 추가 fail-closed `target.forwardHeaders`; `tests/proxy-header-allowlist.test.mjs`가 게이트웨이 bearer는 업스트림에 안 보이고 공급자 헤더(`x-api-key`/`anthropic-version`/`x-goog-api-key`)는 보임을 증명; README/threat-model/shared-responsibility/configuration(+ko) 갱신 |
| P1-CR-002 | SSRF 가드가 `::ffff:7f00:1` 같은 hex IPv4-mapped IPv6 private 주소를 놓침 | Resolved | 각 `isBlockedAddress` 복사본(core `packages/ssrf`, `satellites/auth-jwt`, `satellites/crypto-kms/vault.mjs`)이 IPv4-mapped IPv6 주소를 16바이트로 파싱해 임베드된 IPv4(dotted `::ffff:127.0.0.1` 및 hex `::ffff:7f00:1`, bracketed, leading-zero, 혼합 `::`, 대소문자 무시)를 private/loopback/link-local/metadata 검사 전에 정규화; 공인 mapped 주소(`::ffff:8.8.8.8` == `::ffff:808:808`)는 허용 유지되고 기존 vault 과차단도 제거. 복사본은 의도적으로 독립 유지(어떤 위성도 `haechi/ssrf`를 import하지 않음 — core peer floor가 올라감); drift는 parity 테스트로 보증. 테스트: `tests/ssrf.test.mjs`(hex/dotted/bracketed loopback+RFC1918+metadata+public 벡터, core-vs-auth-jwt parity), `satellites/auth-jwt/auth-jwt.test.mjs`(mapped-IPv6 생성 차단 + public-mapped 미차단), `satellites/crypto-kms/vault.test.mjs`(확장된 range table + P2-CR-012 IPv6 loopback 테스트), `satellites/crypto-kms/ssrf-parity.test.mjs`(dotted+hex mapped parity 벡터) |
| P1-CR-003 | 자동 압축 해제된 업스트림 본문이 기존 압축 응답 헤더와 함께 반환될 수 있음 | Resolved | 중앙화 `sanitizeResponseHeaders()`(content-encoding/content-length/transfer-encoding/hop-by-hop 제거)를 모든 응답 경로(pass-through, 전달/미보호, 보호, streaming)에 적용; 올바른 content-length는 버퍼링된 바디에만 재설정; `tests/proxy-header-allowlist.test.mjs` gzip pass-through + 미보호 응답 테스트가 잔존 content-encoding 없음과 downstream 읽기 가능을 증명 |
| P1-CR-004 | `streaming.requestMode: "pass-through"`가 response-size cap 없이 전체 업스트림 본문을 버퍼링 | Resolved | 실행 바이트 한도(`responseProtection.maxBytes`)를 가진 진정한 경계 streaming pass-through(`pipeUpstreamBodyBounded`); 초과 시 업스트림 취소 + 클라이언트 쓰기 종료; 미보호/전달 raw read도 한도 적용(초과 시 502); `tests/proxy-header-allowlist.test.mjs`가 oversize pass-through 스트림이 경계/중단됨을 증명 |
| P1-CR-005 | streaming inspection이 non-JSON SSE/NDJSON 프레임을 원문 통과시켜 plain-text PII 우회 가능 | Resolved | `parseFrame`(`packages/stream-filter/index.mjs`)이 parse 실패 frame을 CONTROL allowlist(`[DONE]`, comment-only, empty/keepalive → 원문 통과)와 non-JSON CONTENT frame(`data:` 텍스트)으로 구분; `handleFrame`이 CONTENT frame을 새 `protector.protectText`(`packages/core/index.mjs`, single-shot `transformSegment`, delta `push`/`flush` 버퍼와 DISTINCT하여 JSON sliding buffer를 오염시키지 않음)로 텍스트 검사하고 `serializeTextFrame`로 `data: <protected text>` 재방출, block action 시 stream fail-closed; response-direction marker skip + audit tally 보존; JSON delta 경로 불변. 테스트: `tests/stream-filter.test.mjs`(plain-text SSE redact, block action 차단, PII 포함 malformed/partial JSON, NDJSON non-JSON 텍스트, control-frame 통과, marker 미재플래그) + `tests/proxy-streaming.test.mjs` end-to-end plain-text 재현 |
| P2-CR-006 | `mcp-wrap`이 child `stderr`를 filtering/audit 없이 상속 | Resolved | `haechi mcp-wrap`에 `--stderr filter\|drop\|inherit`(기본 `filter`) 추가: 각 완성된 stderr 라인을 재방출 전에 `createStreamProtector().protectText`로 보호(chunk 경계 버퍼링, block-action drop, audit-silent), `drop`은 폐기, `inherit`은 명시적 opt-in 경계, 알 수 없는 값은 fail closed; `tests/mcp-wrap.test.mjs`가 네 가지 모드를 모두 커버 |
| P2-CR-007 | 기존 key file을 `initLocalKeyFile()`이 검증하지 않음 | Resolved | `initLocalKeyFile`의 기존 파일 non-force 경로가 이제 공유 `loadKeyFile({ requireActive:true })`로 검증(corrupted JSON, active key 부재, 잘못된 길이의 active/retired key 모두 throw); 유효한 파일은 비파괴 유지; `tests/crypto.test.mjs`가 네 가지 케이스를 커버 |
| P2-CR-008 | satellite packaging check가 `manifest.bin` target file을 검증하지 않음 | Resolved | `evaluateSatellitePackaging()`이 모든 `manifest.bin` 타깃(string + object-map 형식)을 packed-file 집합과 대조해 검증; `tests/satellite-packaging-gate.test.mjs`가 positive + negative(bin 누락) 케이스를 추가 |
| P2-CR-009 | `authProvider.authenticate()` 예외 경로 회귀 테스트 부재 | Resolved | `tests/proxy-auth.test.mjs`가 throw하는 provider를 주입해 fail-closed(전달 안 됨, generic client error), audit status `haechi_auth_provider_error`, raw error/subject/issuer 미노출을 단언; mutation으로 검증 |
| P2-CR-010 | process-isolated sandbox quota 분기 parity 테스트 부족 | Resolved | `tests/plugin-process-sandbox.test.mjs`(+ crash fixture)가 isolated-process parity를 추가: oversized result 거부, over-capacity 거부, timeout 종료, child-crash fail-closed; 실제 `process-sandbox.mjs`에 대해 mutation으로 검증 |
| P2-CR-011 | audit chain 중간 변조 분기 집중 테스트 부족 | Resolved | `tests/audit-chain-tamper.test.mjs`가 실제 multi-record 로그를 기록하고 `verifyAuditChain`이 middle-record content mutation, `previousHash` 누락/오류, 잘못된 `eventHash`를 거부함을 단언; tail-truncation 한계는 계속 문서화 |
| P2-CR-012 | KMS vault IPv6 loopback carve-out의 IPv6 테스트 부족 | Resolved | `satellites/crypto-kms/vault.test.mjs`에 전용 IPv6 loopback 정책 테스트("…enforces the IPv6 loopback policy (::1, [::1], dotted + hex mapped) — P2-CR-012")를 추가해 bare `::1`, bracketed `[::1]`, dotted `::ffff:127.0.0.1`, hex `::ffff:7f00:1`/`::ffff:7f00:0001`(및 bracketed 변형)을 검증하고, 공인 mapped 주소(`::ffff:8.8.8.8`/`::ffff:808:808`)가 과차단되지 않음을 단언; 확장된 range table과 `ssrf-parity.test.mjs`가 auth-jwt와의 dotted+hex 일치를 고정 |
| P2-CR-013 | SSE multi-line `data:` 필드를 newline separator 없이 합침 | Resolved | `parseFrame`이 여러 `data:` line을 `join("\n")`(스펙 separator)으로 합치고 line별 스펙 선행 공백 1개만 제거; multi-line JSON은 여전히 `JSON.parse`되고 multi-line plain text는 newline과 함께 재구성되어 검사되며 `serializeTextFrame`가 multi-line payload를 여러 `data:` line으로 재방출; `tests/stream-filter.test.mjs`가 multi-line JSON event와 PII 포함 multi-line plain-text event를 커버 |

## 5.8 2026-06-16 코드리뷰 Round 2 (CR2) 상태 — 게이트 G10

권위 있는 항목별 등록부는 `docs/current/code-review-risk-register-2026-06-16-round2.md`입니다; 이 절은 릴리스 게이트 요약입니다. 1.3.1 컷 이후 진행한 2차 심층 리뷰는 **P0도 P1도 발견하지 못했습니다**(외부에서 P1로 보고된 두 항목 모두 검증 결과 P2로 내려갔습니다 — 둘 다 stored-plaintext leak도, auth/SSRF 우회도 아닙니다). 세 개의 P2 + P3 묶음(`CR2-001..008`)은 **Resolved이며 `haechi@1.3.2`로 발행되었습니다**; 보고된 한 항목은 **false positive**(`CR2-009`, won't-fix)였고 한 항목은 **이미 문서화된 수용 잔여 리스크**(`CR2-010`, accepted)였습니다. **G10은 Pass입니다.**

| ID | 리스크 | 상태 | 종료에 필요한 증거 |
|---|---|---|---|
| CR2-001 | pass-through streaming이 downstream disconnect 시 upstream reader를 절대 취소하지 않음(`pipeUpstreamBodyBounded`가 `drain`에서 영원히 park) — 인증되지 않은 resource leak | Resolved | per-request `AbortController` + upstream reader를 취소하고 fetch를 abort하는 클라이언트 `close`/`aborted` listener; `drain` 대기를 `close`와 race; 스트림 도중 disconnect가 reader를 즉시 취소하는 회귀 테스트 |
| CR2-002 | token-vault reveal/purge가 호출자 제공 raw `token` + `error.message`(token interpolate됨)를 audit event에 기록; `FORBIDDEN_KEYS`는 key 이름으로만 제거 | Resolved | 일반화된 오류 메시지; 기록 이전에 `token`을 keyed-HMAC하거나 `tok_` 형태로 검증; `error.message` 대신 enum `reasonCode`; raw token이 `reason`/`token`에 도달하지 않는다는 회귀 테스트; 불변식 표현 정합화 |
| CR2-003 | plugin IPC reply가 `JSON.parse` 이전에 size-bound되지 않음; process child에 heap cap 없음 → 적대적 signed plugin으로 인한 event-loop 정지 + 메모리 급증 | Resolved | 두 sandbox 모두에서 parse 이전 reply byte-length 검사(oversized를 deny로 drop); 새 `resourceLimits` knob을 통한 process child의 `--max-old-space-size` heap cap; oversized-reply fixture 회귀 테스트 |
| CR2-004 | `sanitizeResponseHeaders`가 변환된 응답에 stale body-coupled validator(`etag`/`content-md5`/`digest`/`last-modified`)를 유지 | Resolved | 모든 body-mutating 경로에서 해당 헤더 drop + `cache-control: no-store`; 변경된 응답이 upstream `ETag`를 drop하는 테스트 |
| CR2-005 | `maxBytes` 초과 request body가 (유한한) Node `requestTimeout`까지 read-and-discard됨 — socket teardown 없음 | Resolved | 413 경로에서 `request.pause()`/`destroy()`(또는 `Connection: close`); 선택적으로 non-null 기본 timeout |
| CR2-006 | `mcp-wrap --stderr filter`가 라인 지향이라 newline-split secret이 회피함(본질적; single-line secret은 잡힘, `drop` 사용 가능) | Resolved | `COMMAND_HELP` + 등록부 노트; 고민감 도구에 `--stderr drop` 권장 |
| CR2-007 | README가 mcp-wrap "stderr ... pass through"라고 하지만 기본값은 이제 `--stderr filter` | Resolved | README + `README.ko.md` 수정 |
| CR2-008 | README streaming split-match 주장이 범위 한정 없음(cross-frame buffering은 delta 채널만) | Resolved | README 두 구절 + `README.ko.md`를 delta 채널로 한정 |
| CR2-009 | (보고된 P2) credential `maxMessageBytes` 검사 이후 append된 `keyMaterial` | Won't fix (FALSE POSITIVE) | `keyMaterial`은 운영자 통제 + fetcher `maxBytes`로 hard-bound; 공격자 증폭 없음 — 선택적 cosmetic re-assert만 |
| CR2-010 | (보고된 P2) 두 NON-JSON SSE frame에 걸쳐 분할된 secret 미포착 | Accepted (documented) | round-1 `P1-CR-005`, `threat-model.md`, in-code comment에 이미 범위 외; JSON delta 채널은 `maxMatchBytes`까지 buffering함 |

## 6. P2 제품/문서 리스크 상태

| ID | 기존 리스크 | 상태 | 해소 증거 |
|---|---|---|---|
| P2-DOC-001 | threat model 별도 문서 부족 | Resolved | `docs/current/threat-model.md` |
| P2-DOC-002 | shared responsibility 부족 | Resolved | `docs/current/shared-responsibility.md` |
| P2-DOC-003 | region/privacy profile 미구현 | Resolved for baseline | `haechi/privacy-profiles`, `privacy.profile` runtime 적용 |
| P2-DOC-004 | API stability 정책 없음 | Resolved | `docs/current/api-stability.md` |

## 7. npm 릴리스 배포 전 체크리스트

이 체크리스트는 `1.x` stable 라인의 모든 릴리스에 대한 상시 배포 전 템플릿이며, `0.3.2` developer preview에서 처음 적용되었습니다. 그 결과를 아래에 참조 기록으로 보존합니다.

2026-06-16 현재 상태: G9은 `Pass`입니다(round-1 보완이 `haechi@1.3.1`로 발행됨). 게이트 **G10**(CR2, §5.8)은 이제 `Pass`입니다 — CR2 P2 + P3 묶음(`CR2-001..008`)이 Resolved이며 `haechi@1.3.2`로 발행되었으므로, 그 컷에 대해 이 체크리스트가 해제되었습니다.

외부 npm 게이트 확인 결과(`0.3.2` developer preview, 2026-06-10, 배포 후)는 다음과 같습니다.

- `npm whoami`: `raeseoklee`
- `npm view haechi version`: `0.3.2`

아래 체크리스트는 2026-06-10 0.3.2 배포에서 provenance publish 경로를 제외하고 완료되었습니다(`v0.3.2` 태그와 GitHub pre-release 완료). provenance는 GitHub Actions trusted publishing으로 이월되었으며, 이후 stable 릴리스는 provenance와 함께 trusted-publishing 경로로 발행합니다.

1. `npm run release:preflight`
2. `npm run sbom`
3. `npm run bench:payload`
4. `npm run release:preflight:npm`
5. GitHub release 생성
6. GitHub Actions `Publish npm Developer Preview` 성공
7. `npm view haechi version`으로 실제 배포 버전 확인

## 8. 남은 non-blocking backlog

| 버전 | 목표 | 남은 범위 |
|---|---|---|
| 0.4.0 ✅ | token round-trip and adoption | 2026-06-10 구현 완료: 요청 스코프 response detokenization, deterministic tokenization(파생 키), `haechi mcp-wrap`, `haechi audit-verify`/`haechi status`, injection detection type(기본 allow), `identity`/`authProvider` 계약 예약. `docs/current/release-0.4-implementation-scope.md` 참조 |
| 0.5.0 ✅ | streaming hardening | 2026-06-10 출시: bounded cross-frame 버퍼를 사용한 SSE/NDJSON 스트리밍 응답 검사(`streaming.requestMode: inspect`). stream sequence AAD, replay cache, 강화된 원격 배포 가이드는 0.6+으로 이월. `docs/current/release-0.5-implementation-scope.md` 참조 |
| 0.6.0 ✅ | auth and per-client controls | Shipped 2026-06-10 (PRs #17–#19): built-in bearer auth, named policy profiles, model allowlist, request rate limit, PII-safe identity in audit. `docs/current/release-0.6-implementation-scope.md` 참조 |
| 0.7.0 ✅ | ops hardening | Shipped 2026-06-10 (PRs #22–#24): audit head-hash anchoring + external sink contract, cryptoProvider contract hardening + `assertCryptoProviderConformance` + reference KMS adapter, 서명/체크섬된 release artifact. `docs/current/release-0.7-implementation-scope.md` 참조 |
| 0.8.0 ✅ | ecosystem foundation + satellites | 2026-06-10 출시(PR #27–#32): npm workspaces 모노레포(루트 자기참조 `["."]` + `satellites/*`); `haechi@0.8.0`(attested), `haechi-crypto-kms`, `haechi-auth-jwt`(unscoped — `@haechi` scope 점유됨) **발행 완료**. core는 zero runtime dependency 유지(CI no-leak + zero-dep + satellite-packaging 게이트). 위성 `0.1.0`은 이름 생성을 위한 수동 부트스트랩 발행(unattested, `--provenance=false`, `0.3.2`와 동일한 갭)으로 per-name Trusted Publisher 설정 후, `0.1.1`이 첫 attested CI 릴리스(SLSA provenance + sigstore, `gh attestation verify` 통과). `docs/current/release-0.8-implementation-scope.md` 참조 |
| 0.9.0 | observability + interactive auth | `haechi-auth-oidc` 전체 authorization-code flow, `haechi-dashboard` 읽기 전용 audit 뷰어(hash-chain 무결성 표시, 요약/검색/타임라인), `haechi-crypto-kms` 추가 백엔드(Vault/GCP/Azure) |
| 1.0.0 | stable API contract | migration policy, long-term audit schema, plugin sandbox/runtime conformance 및 allowlist/manifest 통과 외부 auth/classifier package 동적 로딩 |

동적 npm package 로딩은 1.0 plugin sandbox 이전까지 금지합니다. 0.4~0.7의 외부 provider는 `createRuntime(config, providers)` 프로그래매틱 주입만 지원합니다.

## 9. 현재 허용 가능한 사용 범위

`1.x` stable 라인은 다음 범위에서 사용합니다.

- 로컬 개발 환경
- 샘플 payload 검증
- OpenAI-compatible/vLLM/Ollama/llama.cpp proxy PoC 및 self-hosted 게이트웨이
- 정책/필터/감사 pipeline 검토
- GitHub 코드 리뷰와 보안 설계 논의
- 운영자가 네트워크 접근 통제, 인증/인가, 운영 key custody를 앞단에 두는 **경우**의 self-hosted 운영 게이트웨이(§1 참고)

Haechi는 여전히 다음 용도로는 사용하지 않습니다.

- 운영자 자체의 네트워크 통제와 인증 없이 인터넷에 직접 노출되는 proxy
- compliance evidence 또는 법적 준수 증명(Haechi는 컴플라이언스 보장이 아님)
