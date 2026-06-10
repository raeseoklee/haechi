# Haechi 0.3.2 Hardening Scope

- 문서 상태: Final
- 작성일: 2026-06-10
- 기준 버전: 0.3.2
- 성격: 보안 하드닝 릴리스, 첫 npm developer preview 배포 대상
- 배포: 2026-06-10 — npm `haechi@0.3.2` (로컬 패스키 publish, provenance 이월), `v0.3.2` 태그, GitHub pre-release

## 1. 배경

0.3.1 전체 코드 리뷰에서 식별된 16건의 리스크를 해소한 릴리스다. 상세 리스크 목록과 해소 증거는 `risk-register-release-gate.md` 5.2절(P0-SEC-016 ~ P2-DOC-005)을 따른다.

npm에 한 번도 배포된 적이 없었으므로 0.3.2가 첫 배포 버전이다. 첫 배포를 기능 릴리스(0.4.0)와 분리해 패키지 이름 소유권을 저위험 릴리스에서 확정했고, provenance 기반 GitHub Actions publish 경로는 후속 하드닝 항목으로 이월한다.

## 2. 변경 요약

### 차단/집행 경로
- Ollama `/api/chat`·`/api/generate`는 `stream: false` 명시가 없으면 streaming으로 간주, 기본 501 fail-closed (protocol adapter `streamingDefault`)
- unknown `target.type`은 config 검증 단계에서 fail-closed (`llm-http` alias만 openai-compatible로 허용)
- upstream fetch에 `limits.upstreamTimeoutMs`(기본 120000) 적용, 초과 시 `504 haechi_upstream_timeout`, 연결 실패 시 `502 haechi_upstream_unreachable`
- proxy 내부 오류 메시지 일반화 (상세는 stderr)

### 탐지/변환
- JSON number leaf(카드번호 등)와 object key 이름도 detection/transform 대상 (enforce 시 key rename, 충돌은 `#n` suffix)
- 8자 이하 mask는 전체 마스킹
- `assignment-secret` 패턴 lookbehind 전환 — key 이름 보존, 값만 치환
- privacy profile은 `ACTION_STRENGTH` 비교로 사용자 명시 정책을 강화만 가능

### 키/암호
- `decrypt`가 envelope `kid`로 키 선택 (구버전 envelope 복호 유지)
- `initLocalKeyFile --force`는 기존 키를 `retired`로 보존하는 rotation으로 변경
- policy bundle 서명 키를 `haechi:policy-bundle:signing:v1` domain-separated 파생 키로 분리

### TokenVault/Audit
- reveal/purge 결정을 audit 기록 (`reveal_allowed/denied/failed`, `purge`, `purge_expired` — 토큰 id만, 평문 불포함)
- vault mutation 시 만료 토큰 자동 삭제, `purgeExpired()` 및 `haechi token-purge --expired` 추가
- audit append를 tail-chunk 읽기로 O(1)화
- audit/vault lock 파일 30초 초과 시 stale 판정 후 자동 탈취

### UX/가시성
- proxy 기동 시와 `protect` 출력에 비집행 모드(dry-run/report-only)·responseProtection 비활성 경고
- `protect` 출력에 `mode`/`enforced`/`warnings` 필드 추가

### MCP
- notification(id 없는 메시지)은 JSON-RPC 스펙대로 오류 응답 없이 drop
- batch 배열은 명시적 fail-closed 거부

## 3. 호환성 주의 (0.3.1 대비)

배포된 사용자가 없으므로 마이그레이션 경로는 제공하지 않고 기록만 남긴다.

- 0.3.1 키로 서명한 policy bundle은 서명 키 분리로 검증에 실패한다. `haechi policy-sign`으로 재서명해야 한다.
- detection 범위 확대(number/key)와 mask 동작 변경으로 enforce 모드 출력이 0.3.1과 다를 수 있다.
- audit 이벤트 detection 항목에 `kind` 필드가 추가됐다.

## 4. 명시적 제외 (0.4+ backlog)

- base64/URL-encoded 값 디코딩 후 검사
- URL query string 검사
- audit hash chain tail truncation 탐지 (외부 앵커 필요)
- SSE/NDJSON stream inspection (0.5.0)

## 5. 배포 게이트

`risk-register-release-gate.md` 7절 체크리스트를 따른다. `npm run release:preflight` 통과 후 인증된 계정에서 `release:preflight:npm` 및 GitHub release workflow로 배포한다.
