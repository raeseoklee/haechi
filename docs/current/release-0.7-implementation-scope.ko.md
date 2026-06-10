# Haechi 0.7 Implementation Scope

- 문서 상태: Final
- 작성일: 2026-06-10
- 기준 버전: 0.7.0 (0.6.0 이후)
- 성격: ops hardening
- 구현 완료: 2026-06-10 — PR #22 (audit anchoring), #23 (cryptoProvider 계약 + reference KMS), #24 (signed release artifacts)

## 1. 릴리스 목표

1.0("stable", developer-preview 레이블 제거)이 차단하는 운영 스토리를 강화한다: 단일 로컬 파일을 넘어선 audit 무결성, 외부 key custody, 검증 가능한 릴리스 아티팩트. 두 번의 1.0 차단 릴리스 중 첫 번째다.

**범위 결정 (2026-06-10):** 0.7은 **ops hardening** — audit 무결성, key custody 계약, 서명된 아티팩트에 집중한다. 이전에 여기에 묶였던 **생태계** 항목들(npm org `@haechi/*`, `@haechi/crypto-kms` / `@haechi/auth-oidc` 게시, `@haechi/dashboard`, npm workspaces)은 **0.8**로 이월하며, 0.8에서 중복된 0.7 로드맵 행도 제거한다.

Core의 **zero runtime dependency** 기조는 협상 불가: 0.7의 모든 것은 `node:` 빌트인만으로 제공된다. 무거운 어댑터(AWS KMS, Vault)는 satellite/example이며, 절대 core에 포함되지 않는다.

## 2. 범위

### 2.1 Audit tail-truncation 방어: head-hash anchoring (내장, zero-dep)

audit hash chain은 변조와 재정렬은 탐지하지만, 마지막 N개 레코드의 **삭제**는 탐지하지 못한다 — 단축된 chain도 여전히 검증을 통과하기 때문이다. 0.7은 주기적 anchoring으로 일반적인 경우를 해결한다.

- 추가 이후 JSONL sink는 현재 chain head를 별도의 **append-only anchor 스트림**에 기록한다: JSON 한 줄 `{ sequence, eventHash, timestamp }`.
- Config `audit.anchor`:
  - `mode`: `none` (기본값 — 현재 동작) | `file` | `stdout`.
  - `path`: `mode: file`일 때의 anchor 파일 (다른 매체 / append-only 플래그가 설정된 경로 권장).
  - `everyRecords`: anchor 주기 (기본값 `1` — 레코드마다 anchor; 배치 처리 시 값 증가). Anchor 라인은 매우 작다.
- `verifyAuditChain(path, { anchorPath })`은 교차 검증한다: 최신 anchor의 `sequence`가 chain 길이를 초과해서는 안 되며, 앵커된 `sequence`의 chain 레코드는 앵커된 `eventHash`로 해시되어야 한다. 최신 anchor보다 짧은 chain → **truncation 탐지** (마지막 anchor 이후의 레코드가 제거된 것).
- `haechi audit-verify --anchor <path>`로 확인하며; `haechi status`는 anchor 모드 + 마지막으로 앵커된 sequence를 보고한다.
- **보장 범위의 한계:** truncation은 **마지막 anchor** 이전까지만 탐지된다; 마지막 anchor 이후, truncation 이전에 기록된 레코드는 여전히 조용히 손실될 수 있다. `everyRecords: 1`이면 그 범위는 레코드 하나다. 문서화되어 있다.

### 2.2 외부 append-only audit sink 계약

- 주입된 `auditSink` 계약을 공식화한다 (이미 `createRuntime(config, { auditSink })`를 통해 지원됨): `record(event)`는 append-only이며 순서를 보존한다; 외부 sink는 hash chain을 직접 구현하거나 내장 sink를 래핑한다. 기능 플래그(`writesAudit`, `integrity`, `appendOnly`)가 문서화된다.
- HTTP/syslog/object-lock 전달 레퍼런스 sink는 **0.8 satellite/example**이다; 0.7은 계약 + 내장 anchoring을 zero-dep 해답으로 제공한다.

### 2.3 cryptoProvider 계약 강화 + 레퍼런스 KMS 어댑터

- `keys.provider: external`에 대한 `cryptoProvider` 계약을 강화하고 문서화한다: 외부 provider는 `encrypt`, `decrypt`, **그리고 `hmac`** (토큰/identity를 위해 0.4에서 추가됨)을 구현해야 하며, envelope 형태(`{ v, alg, kid, iv, ct, tag, aadHash }`)를 보존하고, canonical AAD를 바인딩하며, `kid`로 키를 선택해야 한다.
- `assertCryptoProviderConformance(provider)` (익스포트된 테스트 헬퍼)를 제공한다: encrypt→decrypt 왕복, AAD 불일치 거부, `hmac` 결정론 + domain separation. Satellite 어댑터는 이를 통해 자체 테스트한다.
- `examples/crypto-kms-reference/` 아래에 **레퍼런스 어댑터**를 제공한다 (자체 `package.json`, AWS/Vault SDK는 *optional/peer* 의존성으로, core의 `files`에 포함하지 않음): 주입 방법을 시연한다. 이것이 0.8에서(npm org 취득 후) 게시되는 **`@haechi/crypto-kms`** satellite의 소스가 된다.

### 2.4 서명된 릴리스 아티팩트

- npm provenance (SLSA attestation)는 신뢰할 수 있는 퍼블리싱을 통해 이미 제공된다 (0.4부터). 0.7은 **GitHub 릴리스 에셋 무결성**을 추가한다: 릴리스 워크플로가 `npm pack`을 실행하고, `SHA256SUMS`를 생성하며, 타볼 + 체크섬 (그리고 가능한 경우 sigstore/cosign 서명)을 각 GitHub 릴리스에 첨부한다.
- 사용자가 설치 전 다운로드한 타볼을 검증할 수 있게 하고, 릴리스 에셋에 레지스트리 외의 변조 방지 매니페스트를 제공한다.

## 3. 명시적 비범위 (0.8로 이월)

- npm org `@haechi/*` 생성; `@haechi/crypto-kms`, `@haechi/auth-oidc`, `@haechi/auth-jwt` 게시.
- `@haechi/dashboard` (읽기 전용 audit 뷰어) 및 npm workspaces 전환.
- 게시된 패키지로서의 실제 AWS KMS / HashiCorp Vault SDK 연동 (0.7은 계약 + 레퍼런스 example만 제공).
- 분산/공유 audit 또는 rate 상태.

## 4. Config 스키마 요약

```json
"audit": {
  "sink": "jsonl",
  "path": ".haechi/audit.jsonl",
  "anchor": { "mode": "none", "path": ".haechi/audit.anchor.jsonl", "everyRecords": 1 }
}
```
Fail-closed 검증: 알 수 없는 `anchor.mode`; `path` 없이 `mode: file`; 비양수 `everyRecords`.

## 5. 1.0 졸업 기준 진행

0.7은 다섯 개의 1.0("developer-preview 레이블 제거") 차단 조건 중 세 개를 진전시킨다:

| 1.0 차단 조건 | 0.7 기여 |
|---|---|
| 운영 key custody | cryptoProvider 계약 강화 + conformance 테스트 + 레퍼런스 어댑터 (게시 패키지는 0.8) |
| 외부 / tamper-evident audit | 내장 anchoring으로 tail-truncation 해결; 외부 sink 계약 문서화 |
| 검증 가능한 릴리스 아티팩트 | 서명/체크섬된 GitHub 릴리스 에셋 |
| API stability freeze | (1.0) |
| Plugin sandbox + 실환경 검증 | (1.0) |

## 6. 테스트 기준 (구현 시)

- Anchoring: `everyRecords`에 따라 anchor 라인이 기록됨; anchor가 포함된 `verifyAuditChain`이 truncation(최신 anchor보다 짧은 chain)을 탐지하고 온전한 chain은 통과시킴; `mode: none`이면 0.6 동작과 byte 단위로 동일.
- `audit-verify --anchor` 종료 코드 + 출력; `status`가 anchor 모드/마지막 sequence를 보고.
- cryptoProvider conformance 헬퍼가 로컬 provider를 통과시키고, `hmac` 누락 / AAD 불일치 provider를 실패시킴.
- `audit.anchor` 블록에 대한 Config 검증.
- 릴리스 워크플로가 팩된 타볼과 일치하는 `SHA256SUMS`를 생성함 (CI 검증 가능).

## 7. 권장 PR 분할 (스택)

1. Audit anchoring (sink가 anchor 기록) + `verifyAuditChain` anchor 교차 검증 + config + `audit-verify --anchor` / `status`.
2. cryptoProvider 계약 문서 + `assertCryptoProviderConformance` + `examples/crypto-kms-reference/`.
3. 서명된 릴리스 아티팩트 (릴리스 워크플로 + 검증 문서).
4. 0.7.0 릴리스 컷 (버전, 문서 EN/KO, threat-model/risk-register/api-stability, wiki).
