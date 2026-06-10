# Haechi API Stability Policy

- 문서 상태: Draft 0.1
- 작성일: 2026-06-10
- 기준 버전: 0.5.0

## 1. 버전 해석

0.x 버전은 developer preview다. public exports는 사용 가능하지만, stable API로 간주하지 않는다.

| 버전 범위 | 의미 |
|---|---|
| `0.3.x` | local inference/proxy safety patch line |
| `0.4.x` | token round-trip and adoption line |
| `0.5.x` | streaming hardening target |
| `0.6.x` | auth 및 운영 통제 target |
| `1.0.0` | API compatibility contract를 선언할 수 있는 첫 stable 후보 |

## 2. 변경 정책

| 변경 유형 | 0.x 처리 |
|---|---|
| 보안 기본값 강화 | patch에서 허용 |
| unsafe config 차단 | patch에서 허용 |
| export 제거/이름 변경 | minor에서 허용, README에 migration note 필요 |
| policy action 의미 변경 | minor 이상 필요 |
| audit schema 변경 | minor 이상 필요 |
| crypto envelope format 변경 | minor 이상 필요, backward handling 필요 |

## 3. Experimental exports

다음 export는 0.4.0에서 preview로 취급한다.

- `haechi/runtime`
- `haechi/proxy`
- `haechi/protocol-adapters`
- `haechi/privacy-profiles`
- `haechi/plugin`
- `haechi/mcp-stdio` `wrapMcpChild`
- `haechi/token-vault` `detokenize`, deterministic tokenization 옵션
- `injection` detection type과 휴리스틱 룰
- `identity` audit 필드와 `authProvider` 계약 (0.4 예약, 0.6 구현 — 그 전까지 형태 변경 가능)
- `status` / `audit-verify` CLI 출력 형태
- `haechi/stream-filter` (`inspectResponseStream`, path helpers) 및 `createStreamProtector` (스트리밍 검사 내부 구현)

## 4. Migration note 기준

다음 변경이 있으면 `docs/current/release-*.md` 또는 README에 migration note를 남긴다.

- config key 추가/삭제
- default enforcement 변경
- CLI flag 추가/삭제
- audit event 필드 변경
- token format 변경
- plugin manifest schema 변경
