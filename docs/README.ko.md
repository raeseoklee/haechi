# Haechi 문서 인덱스

기본 문서 언어는 영문이다. 각 문서의 한국어 번역본은 같은 경로의 `*.ko.md`로 관리한다.

## Current

- `docs/current/prd-ai-llm-mcp-encryption.md`: AI/LLM/MCP 특화 암호화 솔루션 PRD 초안
- `docs/current/initial-plan-ai-llm-mcp-encryption.md`: 초기 실행 계획과 기술 가설
- `docs/current/privacy-filtering-policy-draft.md`: 개인정보 필터링 정책 초안
- `docs/current/global-privacy-compliance-review.md`: 글로벌 개인정보/AI 컴플라이언스 검토
- `docs/current/expert-gap-review-ai-llm-mcp-encryption.md`: 전문가 병렬 검토 기반 누락 요구사항 및 보강 백로그
- `docs/current/open-source-modular-architecture.md`: SaaS가 아닌 OSS/self-hosted 모듈형 아키텍처와 교체 가능한 provider/plugin 경계
- `docs/current/mvp-0.1-implementation-scope.md`: MVP 0.1 구현 범위, 제외 범위, quickstart 완료 기준
- `docs/current/release-0.2-implementation-scope.md`: 0.2 TokenVault, signed policy, plugin manifest, MCP stdio 구현 범위
- `docs/current/release-0.3-implementation-scope.md`: 0.3 vLLM/Ollama/llama.cpp adapter, response protection, npm publish readiness 구현 범위
- `docs/current/release-0.3.2-hardening-scope.md`: 0.3.2 보안 하드닝 릴리스, 첫 npm developer preview 배포 대상
- `docs/current/release-0.4-implementation-scope.md`: 0.4 token round-trip, mcp-wrap, audit-verify/status, identity/authProvider 계약 예약
- `docs/current/configuration.md`: 전체 설정 레퍼런스 (모든 키, 기본값, 검증, preset, 자주 쓰는 설정)
- `docs/current/risk-register-release-gate.md`: 0.3.2 기준 배포 차단 리스크, 보안/운영 리스크, npm release gate
- `docs/current/threat-model.md`: Haechi 0.3.2 신뢰 경계, 보호 자산, 주요 위협과 통제
- `docs/current/shared-responsibility.md`: self-hosted 운영에서 Haechi와 사용자/운영자의 책임 분리
- `docs/current/api-stability.md`: developer preview API 안정성 및 migration note 기준
- `docs/current/release-process.md`: release preflight, SBOM, npm provenance publish 절차

## 방향 전환 기록

초기 초안(현재 제거됨; 이 커밋 이전 git 히스토리 참조)은 HTTP/HTTPS/socket/gRPC/A2A까지 포괄하는 범용 모듈형 구간암호화 레이어를 다뤘다. 현재 방향은 AI, LLM, MCP, A2A, agent 플랫폼의 prompt, context, tool-call, resource, artifact, streaming message를 보호하는 특화 암호화 솔루션이다.

상용 SaaS보다 오픈소스/self-hosted 보안 인프라를 우선한다. 따라서 현재 문서는 hosted control plane보다 self-hosted SDK/CLI/proxy, 교체 가능한 `CryptoProvider`, `PolicyEngine`, `FilterEngine`, `KeyProvider`, `AuditSink`, plugin conformance test를 중심으로 정리한다.

적용성은 핵심 요구사항이다. 목표는 5분 local demo, 30분 MCP/LLM PoC, 1일 custom filter PoC이며, 사용자는 proxy, middleware, SDK wrapper, sidecar 중 가장 낮은 변경 비용의 방식으로 시작할 수 있어야 한다.
