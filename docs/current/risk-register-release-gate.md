# Haechi 리스크 레지스터 및 릴리스 게이트

- 문서 상태: Draft 0.2
- 작성일: 2026-06-10
- 기준 버전: 0.3.1
- 기준 브랜치: `irae/risk-resolution`

## 1. 현재 판단

0.3.1은 0.3.0에서 식별된 코드/문서/운영 리스크를 developer preview 기준으로 해소했다. GitHub 공개와 npm developer preview 배포는 허용 가능하다. 단, 실제 npm publish는 npm 계정 인증, package ownership, GitHub release workflow 실행이라는 외부 운영자 게이트를 통과해야 한다.

| 구분 | 판단 | 이유 |
|---|---|---|
| GitHub public | 허용 | 보안 한계, threat model, shared responsibility, developer preview 문구가 문서화됨 |
| GitHub release/tag | 허용 | production-ready가 아닌 developer preview로 표현해야 함 |
| npm developer preview | 조건부 허용 | `npm run release:preflight` 통과 후, 인증된 계정에서 `release:preflight:npm` 및 provenance publish 필요 |
| npm stable | 보류 | 1.0 API 안정성, 운영 KMS/HSM/Vault reference adapter, stream-aware enforcement 전까지 stable 표현 금지 |
| production use | 금지 | 0.3.1은 self-hosted developer preview이며 운영 인증/인가/key custody는 사용자 책임 |

## 2. 릴리스 게이트

| Gate | 대상 | 기준 | 현재 상태 |
|---|---|---|---|
| G0 | GitHub source 공개 | 테스트 통과, 보안 한계 문서화, 평문 audit leak 없음 | Pass |
| G1 | GitHub pre-release | P0 코드 리스크 해결, production-ready 표현 없음 | Pass |
| G2 | npm developer preview | P0 해결, preflight/SBOM/provenance 경로 준비, npm auth 확인 | Conditional Pass |
| G3 | npm stable | P1 운영 reference, stream-aware enforcement, API stability 강화 | Blocked |

## 3. P0 배포 차단 리스크 상태

| ID | 기존 리스크 | 상태 | 해소 증거 |
|---|---|---|---|
| P0-REL-001 | npm 인증/권한 미해결 | External Gate | `release:preflight:npm`, GitHub release workflow, `npm publish --provenance --access public`로 게이트화. 실제 인증은 운영자 필요 |
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
| P1-SEC-006 | regex 중심 필터 정확도 한계 | Partially Resolved | KR RRN checksum, Luhn, unsafe custom regex 제한. ML/classifier plugin은 future |
| P1-SEC-007 | AAD/replay/stream 확장 부족 | Partially Resolved | AAD hash mismatch 명시, streaming 기본 차단. stream sequence/replay cache는 0.4 target |
| P1-SEC-008 | MCP security contract 미완성 | Partially Resolved | JSON-RPC 2.0 요구, method allowlist, params/result 보호 토글. OAuth resource binding은 외부 MCP layer 책임 |

## 5. P1 운영/배포 리스크 상태

| ID | 기존 리스크 | 상태 | 해소 증거 |
|---|---|---|---|
| P1-OPS-001 | CI 부재 | Resolved | `.github/workflows/ci.yml` |
| P1-OPS-002 | SBOM/provenance 부재 | Resolved | `npm run sbom`, `.github/workflows/npm-publish.yml`, `publishConfig.provenance` |
| P1-OPS-003 | 실제 vLLM/Ollama/llama.cpp 통합 테스트 부재 | Partially Resolved | env-gated optional local inference integration tests 추가 |
| P1-OPS-004 | 성능/대용량 payload 미측정 | Resolved for preview | request/response byte limit, `npm run bench:payload` |
| P1-OPS-005 | npm ownership 미확정 | External Gate | 인증된 npm 계정에서 `npm run release:preflight:npm`, publish 후 `npm view haechi version` 필요 |

## 6. P2 제품/문서 리스크 상태

| ID | 기존 리스크 | 상태 | 해소 증거 |
|---|---|---|---|
| P2-DOC-001 | threat model 별도 문서 부족 | Resolved | `docs/current/threat-model.md` |
| P2-DOC-002 | shared responsibility 부족 | Resolved | `docs/current/shared-responsibility.md` |
| P2-DOC-003 | region/privacy profile 미구현 | Resolved for baseline | `haechi/privacy-profiles`, `privacy.profile` runtime 적용 |
| P2-DOC-004 | API stability 정책 없음 | Resolved | `docs/current/api-stability.md` |

## 7. npm developer preview 배포 전 체크리스트

현재 외부 npm 게이트 확인 결과:

- `npm whoami`: `E401 Unauthorized`
- `npm view haechi version`: `E404 Not Found`

`haechi` 이름은 비어 있어 보이나, package ownership은 인증된 계정에서 최초 publish가 성공해야 확정된다.

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
| 0.4.0 | streaming and deployment hardening | SSE/NDJSON stream inspection, stream sequence AAD, replay cache, stronger remote deployment guide |
| 0.5.0 | key custody and audit hardening | Vault/AWS KMS reference adapter, external append-only audit sink, signed release artifacts |
| 1.0.0 | stable API contract | migration policy, long-term audit schema, plugin sandbox/runtime conformance |

## 9. 현재 허용 가능한 사용 범위

현재 0.3.1은 다음 범위에서 사용한다.

- 로컬 개발 환경
- 샘플 payload 검증
- OpenAI-compatible/vLLM/Ollama/llama.cpp proxy PoC
- 정책/필터/감사 pipeline 검토
- GitHub 코드 리뷰와 보안 설계 논의
- npm developer preview

현재 0.3.1은 다음 용도로 사용하지 않는다.

- production LLM gateway
- 인터넷에 직접 노출되는 proxy
- 실제 고객/환자/결제/인증정보 처리
- compliance evidence 또는 법적 준수 증명
- npm stable package
