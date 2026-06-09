# Haechi 리스크 레지스터 및 릴리스 게이트

- 문서 상태: Draft 0.1
- 작성일: 2026-06-10
- 기준 버전: 0.3.0
- 기준 커밋: `5d42852`
- 기준 검증: Codexus `verification_20260609_232055_448f50`

## 1. 현재 판단

GitHub 공개 저장소와 `v0.3.0` 태그는 유지 가능하다. 단, npm 공개 배포는 P0 배포 차단 리스크가 닫히기 전까지 보류한다.

이 판단의 근거는 다음과 같다.

| 구분 | 판단 | 이유 |
|---|---|---|
| GitHub public | 허용 | README와 SECURITY.md가 early/self-hosted toolkit임을 밝히고 있고, 사용자가 직접 코드를 검토할 수 있다. |
| GitHub release/tag | 조건부 허용 | `v0.3.0`은 기능 검증 태그로 유지 가능하나, production-ready release로 표현하면 안 된다. |
| npm publish | 보류 | npm 설치는 사용자에게 더 강한 신뢰 신호를 주며, proxy/streaming/key 경계가 아직 충분히 안전하지 않다. |
| production use | 금지 | local software key, incomplete streaming handling, missing auth boundary 때문에 운영 사용을 권장할 수 없다. |

## 2. 릴리스 게이트

| Gate | 대상 | 기준 | 현재 상태 |
|---|---|---|---|
| G0 | GitHub source 공개 | 테스트 통과, 보안 한계 문서화, 평문 audit leak 없음 | Pass |
| G1 | GitHub pre-release | P0 리스크가 문서화되고 production-ready 표현이 없음 | Conditional Pass |
| G2 | npm developer preview | P0-REL 전체 해결, README에 위험한 기본값 명시 | Blocked |
| G3 | npm stable | P0/P1 주요 항목 해결, CI/security evidence 공개 | Blocked |

0.3.0의 권장 상태는 `GitHub public + tag`, npm은 `not published`다. npm에 올릴 경우 버전은 `0.3.1` 또는 `0.4.0`으로 올리고, 아래 P0 항목을 먼저 닫는다.

## 3. P0 배포 차단 리스크

| ID | 리스크 | 영향 | 현재 증거 | 해소 기준 |
|---|---|---|---|---|
| P0-REL-001 | npm 인증/권한 미해결 | 배포 불가, package ownership 불확실 | `npm whoami`가 `E401 Unauthorized` | npm 로그인 후 `npm publish --access public`, `npm view haechi version` 통과 |
| P0-REL-002 | proxy 외부 노출 위험 | `--host 0.0.0.0` 사용 시 인증 없는 LLM proxy가 될 수 있음 | CLI가 host 값을 제한하지 않음 | non-loopback bind는 명시 플래그와 경고 없이는 실패 |
| P0-REL-003 | streaming 요청 처리 불명확 | `stream: true`, SSE, NDJSON에서 필터링 누락 또는 responseProtection 오해 가능 | 0.3 문서가 streaming 제외를 명시하지만 runtime guard 없음 | streaming 요청은 fail-closed 또는 명시 pass-through mode에서만 허용 |
| P0-REL-004 | responseProtection 실패 모드 불명확 | JSON parse 실패, 비JSON, 압축/대용량 응답에서 평문이 그대로 나갈 수 있음 | content-type JSON만 처리하고 parse 실패는 proxy 500, 비JSON은 pass-through | responseProtection enabled 상태에서는 미처리 응답 유형을 fail-closed 또는 명시 allow policy로 제어 |
| P0-REL-005 | local dev key의 운영 오해 | `.haechi/dev.keys.json`을 운영 키처럼 사용할 수 있음 | 파일명은 dev key이나 CLI 경고가 약함 | `init`/README/SECURITY에 production key provider 부재와 dev-only 경고 명시 |
| P0-REL-006 | npm package 신뢰 표현 과다 | 보안 도구가 완성된 제품처럼 오해될 수 있음 | npm metadata는 publish-ready지만 developer preview 문구가 약함 | package description/README에 experimental/developer preview 명시 |

## 4. P1 보안 설계 리스크

| ID | 리스크 | 영향 | 해소 방향 |
|---|---|---|---|
| P1-SEC-001 | KMS/HSM/Vault 미지원 | 키 custody와 rotation 요구를 충족하지 못함 | `KeyProvider` interface와 Vault 또는 AWS KMS reference adapter |
| P1-SEC-002 | TokenVault 권한 모델 부족 | token reveal이 권한/승인/보존 정책과 분리됨 | reveal authorization, retention, purge audit, DSAR export 설계 |
| P1-SEC-003 | audit 무결성 부족 | 감사 로그 위변조와 삭제를 탐지하기 어려움 | hash chain, signing, rotation, append-only sink |
| P1-SEC-004 | plugin runtime 없음 | manifest 검증만으로 plugin 실행 안전성을 보장할 수 없음 | dynamic loading 전 sandbox, capability gate, conformance test |
| P1-SEC-005 | policy conflict 처리 부족 | custom rule/action 충돌 시 예측 불가능한 결과 가능 | priority, hard-block override, conflict matrix test |
| P1-SEC-006 | regex 중심 필터 정확도 한계 | PII/secret false negative와 false positive 가능 | checksum, dictionary, classifier plugin, red-team corpus |
| P1-SEC-007 | AAD/replay 확장 부족 | streaming/chunk/retry에서 context-bound encryption 약화 가능 | nonce/replay cache, stream sequence, retry idempotency test |
| P1-SEC-008 | MCP security contract 미완성 | MCP auth/token passthrough/resource binding 경계가 약함 | MCP protocol version, OAuth resource binding, env allowlist, consent model |

## 5. P1 운영/배포 리스크

| ID | 리스크 | 영향 | 해소 방향 |
|---|---|---|---|
| P1-OPS-001 | CI 부재 | 로컬 검증에 의존 | GitHub Actions로 `npm test`, stale-name scan, pack dry-run |
| P1-OPS-002 | SBOM/provenance 부재 | OSS 보안 신뢰 자료 부족 | SBOM 생성, npm provenance, signed release artifact |
| P1-OPS-003 | 실제 vLLM/Ollama/llama.cpp 통합 테스트 부재 | adapter가 mock 서버에서만 검증됨 | container 또는 optional local integration test |
| P1-OPS-004 | 성능/대용량 payload 미측정 | proxy memory pressure와 latency를 모름 | payload size limit, benchmark, timeout, body limit |
| P1-OPS-005 | npm ownership 미확정 | 패키지명 선점 또는 권한 문제 가능 | npm 계정 인증 후 실제 publish 또는 이름 변경 판단 |

## 6. P2 제품/문서 리스크

| ID | 리스크 | 영향 | 해소 방향 |
|---|---|---|---|
| P2-DOC-001 | threat model 별도 문서 부족 | 보안 경계 설명이 흩어짐 | `docs/current/threat-model.md` 작성 |
| P2-DOC-002 | shared responsibility 부족 | 사용자가 운영 책임을 오해할 수 있음 | self-hosted mode별 책임 매트릭스 |
| P2-DOC-003 | region/privacy profile 미구현 | 글로벌 적용 메시지가 구현보다 앞설 수 있음 | KR/EU/US profile fixture와 문서 분리 |
| P2-DOC-004 | API stability 정책 없음 | pre-release API 변경 기준이 불명확 | semver, experimental API, migration note |

## 7. npm 배포 전 최소 작업

npm developer preview를 허용하려면 아래 작업을 먼저 완료한다.

1. `haechi proxy --host 0.0.0.0` 기본 차단 또는 `--allow-remote-bind` 요구.
2. request body의 `stream: true` 감지 후 명시 정책 없이는 차단.
3. responseProtection enabled 상태에서 비JSON/parse-fail/압축 응답 처리 정책 추가.
4. `haechi init` 출력과 README에 local dev key 경고 추가.
5. README와 package description에 `experimental developer preview` 명시.
6. `npm test`, `npm pack --dry-run`, stale-name scan, Codexus verification 통과.
7. npm 인증 후 `npm publish --access public`와 `npm view haechi version` 확인.

## 8. 권장 다음 릴리스

| 버전 | 목표 | 포함해야 할 리스크 |
|---|---|---|
| 0.3.1 | npm developer preview safety patch | P0-REL-001부터 P0-REL-006 |
| 0.4.0 | streaming and deployment hardening | P1-SEC-007, P1-OPS-004, actual adapter integration test |
| 0.5.0 | key custody and audit hardening | P1-SEC-001, P1-SEC-003, SBOM/provenance |

## 9. 현재 허용 가능한 사용 범위

현재 0.3.0은 다음 범위에서만 사용한다.

- 로컬 개발 환경
- 샘플 payload 검증
- OpenAI-compatible/vLLM/Ollama/llama.cpp proxy PoC
- 정책/필터/감사 pipeline 검토
- GitHub 코드 리뷰와 보안 설계 논의

현재 0.3.0은 다음 용도로 사용하지 않는다.

- production LLM gateway
- 인터넷에 노출되는 proxy
- 실제 고객/환자/결제/인증정보 처리
- compliance evidence 또는 법적 준수 증명
- npm stable package로 배포
