# Haechi 리스크 레지스터 및 릴리스 게이트

- 문서 상태: Draft 0.3
- 작성일: 2026-06-10
- 기준 버전: 0.7.0
- 기준 브랜치: `main`

## 1. 현재 판단

0.3.2는 0.3.1 전체 코드 리뷰에서 식별된 추가 보안/운영 리스크를 developer preview 기준으로 해소했다. 외부 운영자 게이트(npm 계정 인증, package ownership, GitHub tag/release)는 2026-06-10에 통과했다: `haechi@0.3.2`가 로컬 패스키 인증으로 npm에 배포되었고, `v0.3.2` 태그와 GitHub pre-release가 생성되었다. npm provenance는 GitHub Actions trusted publishing 경로로 이월한다.

| 구분 | 판단 | 이유 |
|---|---|---|
| GitHub public | 허용 | 보안 한계, threat model, shared responsibility, developer preview 문구가 문서화됨 |
| GitHub release/tag | 허용 | production-ready가 아닌 developer preview로 표현해야 함 |
| npm developer preview | 허용 (배포 완료) | 2026-06-10 인증된 계정에서 `haechi@0.3.2` publish 완료, provenance는 trusted publishing으로 이월 |
| npm stable | 보류 | 1.0 API 안정성, 운영 KMS/HSM/Vault reference adapter, stream-aware enforcement 전까지 stable 표현 금지 |
| production use | 금지 | 0.3.2는 self-hosted developer preview이며 운영 인증/인가/key custody는 사용자 책임 |

## 2. 릴리스 게이트

| Gate | 대상 | 기준 | 현재 상태 |
|---|---|---|---|
| G0 | GitHub source 공개 | 테스트 통과, 보안 한계 문서화, 평문 audit leak 없음 | Pass |
| G1 | GitHub pre-release | P0 코드 리스크 해결, production-ready 표현 없음 | Pass |
| G2 | npm developer preview | P0 해결, preflight/SBOM/provenance 경로 준비, npm auth 확인 | Pass (`haechi@0.3.2` 2026-06-10 배포) |
| G3 | npm stable | P1 운영 reference, stream-aware enforcement, API stability 강화 | Blocked |

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
| P1-SEC-004 | plugin runtime 없음 | Resolved by gating | dynamic runtime 거부, `manifest-only` plugin만 통과 |
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

base64/인코딩 값 디코딩 검사, query string 검사, audit tail truncation 탐지는 명시적 제외로 threat model에 문서화했다 (0.4+ backlog).

## 6. P2 제품/문서 리스크 상태

| ID | 기존 리스크 | 상태 | 해소 증거 |
|---|---|---|---|
| P2-DOC-001 | threat model 별도 문서 부족 | Resolved | `docs/current/threat-model.md` |
| P2-DOC-002 | shared responsibility 부족 | Resolved | `docs/current/shared-responsibility.md` |
| P2-DOC-003 | region/privacy profile 미구현 | Resolved for baseline | `haechi/privacy-profiles`, `privacy.profile` runtime 적용 |
| P2-DOC-004 | API stability 정책 없음 | Resolved | `docs/current/api-stability.md` |

## 7. npm developer preview 배포 전 체크리스트

현재 외부 npm 게이트 확인 결과:

- `npm whoami`: `raeseoklee`
- `npm view haechi version`: `0.3.2`

아래 체크리스트는 2026-06-10 0.3.2 배포에서 provenance publish 경로를 제외하고 완료되었다(`v0.3.2` 태그와 GitHub pre-release 완료). provenance는 GitHub Actions trusted publishing으로 이월하며, 체크리스트는 이후 릴리스의 템플릿으로 유지한다.

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
| 0.6.0 ✅ | Shipped 2026-06-10 (PRs #17–#19): built-in bearer auth, named policy profiles, model allowlist, request rate limit, PII-safe identity in audit. `docs/current/release-0.6-implementation-scope.md` 참조 |
| 0.7.0 ✅ | Shipped 2026-06-10 (PRs #22–#24): audit head-hash anchoring + external sink contract, cryptoProvider contract hardening + `assertCryptoProviderConformance` + reference KMS adapter, 서명/체크섬된 release artifact. `docs/current/release-0.7-implementation-scope.md` 참조 |
| 0.8.0 ✅ | ecosystem foundation + satellites | 2026-06-10 출시(PR #27–#32): npm workspaces 모노레포(루트 자기참조 `["."]` + `satellites/*`); `haechi@0.8.0`(attested), `haechi-crypto-kms`, `haechi-auth-jwt`(unscoped — `@haechi` scope 점유됨) **발행 완료**. core는 zero runtime dependency 유지(CI no-leak + zero-dep + satellite-packaging 게이트). 위성 `0.1.0`은 이름 생성을 위한 수동 부트스트랩 발행(unattested, `--provenance=false`, `0.3.2`와 동일한 갭)으로 per-name Trusted Publisher 설정 후, `0.1.1`이 첫 attested CI 릴리스(SLSA provenance + sigstore, `gh attestation verify` 통과). `docs/current/release-0.8-implementation-scope.md` 참조 |
| 0.9.0 | observability + interactive auth | `haechi-auth-oidc` 전체 authorization-code flow, `haechi-dashboard` 읽기 전용 audit 뷰어(hash-chain 무결성 표시, 요약/검색/타임라인), `haechi-crypto-kms` 추가 백엔드(Vault/GCP/Azure) |
| 1.0.0 | stable API contract | migration policy, long-term audit schema, plugin sandbox/runtime conformance 및 allowlist/manifest 통과 외부 auth/classifier package 동적 로딩 |

동적 npm package 로딩은 1.0 plugin sandbox 이전까지 금지한다. 0.4~0.7의 외부 provider는 `createRuntime(config, providers)` 프로그래매틱 주입만 지원한다.

## 9. 현재 허용 가능한 사용 범위

현재 0.3.2는 다음 범위에서 사용한다.

- 로컬 개발 환경
- 샘플 payload 검증
- OpenAI-compatible/vLLM/Ollama/llama.cpp proxy PoC
- 정책/필터/감사 pipeline 검토
- GitHub 코드 리뷰와 보안 설계 논의
- npm developer preview

현재 0.3.2는 다음 용도로 사용하지 않는다.

- production LLM gateway
- 인터넷에 직접 노출되는 proxy
- 실제 고객/환자/결제/인증정보 처리
- compliance evidence 또는 법적 준수 증명
- npm stable package
