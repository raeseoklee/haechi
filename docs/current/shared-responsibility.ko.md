# Haechi Shared Responsibility

- 문서 상태: Living document (core 1.2.x 추적)
- 작성일: 2026-06-10

## 1. 책임 매트릭스

| 영역 | Haechi 제공 | 사용자/운영자 책임 |
|---|---|---|
| 로컬 개발 | CLI, default config, dev key 생성 | dev key를 운영 환경이나 공유 환경에 재사용하지 않습니다 |
| 정책 집행 | redact/mask/tokenize/encrypt/block pipeline | 규제 정책과 조직 정책에 맞는 action을 선택합니다 |
| HTTP proxy | loopback 기본값, remote bind guard, body/response limit | 인증, TLS termination, firewall, upstream auth를 담당합니다 |
| Streaming | 기본 차단 | pass-through를 사용할 때 보호가 적용되지 않는 위험을 감수합니다 |
| TokenVault | 암호화 저장, reveal 기본 차단, purge | reveal 승인 절차와 DSAR/retention 운영을 담당합니다 |
| Audit | 평문 제거, hash chain | append-only storage, backup, 보존 기간, 외부 서명을 담당합니다 |
| Key custody | local dev key, external crypto provider 계약 | KMS/HSM/Vault adapter 구현, rotation, access review를 담당합니다 |
| Plugin | manifest validation; 서명 + 샌드박스된 `authProvider` 플러그인에 한해 동적 로딩 좁게 허용(worker-isolated 1.0 / process-isolated 1.1) | trust anchor/pin/revocation을 관리하고, `process-isolated`를 우선하며, plugin code review를 수행합니다 |
| MCP | JSON-RPC/method allowlist | MCP server auth, resource consent, env secret allowlist를 담당합니다 |
| Privacy profile | KR/EU/US baseline action | 법률 검토, data residency, cross-border transfer 증빙을 담당합니다 |

## 2. 금지되는 기본 사용

- `--allow-remote-bind`를 네트워크 통제 없이 사용하는 것
- `.haechi/dev.keys.json`을 운영 데이터에 사용하는 것
- `streaming.requestMode: "pass-through"`를 보호가 적용된 것으로 오해하는 것
- `responseProtection.failureMode: "allow"`를 민감 데이터 경로에 사용하는 것
- `token-reveal --allow-dev-reveal`를 운영 복원 절차로 사용하는 것

## 3. 운영 전환 체크리스트

1. 외부 crypto provider 또는 KMS/HSM/Vault adapter를 연결하세요.
2. proxy 앞단에 인증, TLS, firewall, rate limit을 두세요.
3. responseProtection을 켜고 fail-closed를 유지하세요.
4. streaming endpoint는 별도의 stream-aware gateway가 준비되기 전까지 차단하세요.
5. audit sink를 append-only 저장소나 외부 서명 저장소로 보내세요.
6. TokenVault의 reveal 승인, 보존, 삭제 절차를 문서화하세요.
7. privacy profile은 법률 검토 결과로 보정하세요.
8. 복제본이 2개 이상이면 §4의 공유 인프라(front-door rate limit, 복제본별 audit 경로, 공유 token vault)를 제공하세요.

## 4. 수평 확장 / 다중 복제

Haechi의 상태 보유 통제는 설계상 단일 프로세스입니다. 로드밸런서 뒤에서 복제본을 2개 이상 실행하면, 운영자가 공유 인프라를 제공하지 않는 한 이들이 **무음으로 약화**됩니다.

- **Rate limit**은 프로세스별·인메모리이므로 전체 처리량이 복제본 수만큼 배가됩니다. identity별 한도를 공유 front door에서 강제하거나, `createRuntime(config, { rateLimiter })`를 통해 공유 저장소 기반 `rateLimiter`를 주입하세요(이 시임은 `allow(key, limit)` 계약을 만족합니다. [`configuration.md` → Rate limiter 주입](./configuration.ko.md#rate-limiter-주입) 참고). 기본 프로세스별 limiter는 window map도 bounding하므로 identity 기준 무한 메모리 증가가 없습니다.
- **Audit hash chain + anchor**는 단일 작성자입니다. 각 복제본에 **고유한** `audit.path`(및 anchor 경로)를 주세요. 하나의 audit 파일을 복제본 간에 공유하면 체인이 분기되어 검증 불가 상태가 됩니다.
- **TokenVault와 auth store**는 whole-file 로컬 저장소입니다 — 단일 호스트에서는 올바르지만 공유 다중 작성자 저장소는 아닙니다. 다중 복제 토큰화에는 공유 `tokenVault`를 주입하세요.
- 파일 락은 `O_EXCL` + atomic rename에 의존하며 NFS/공유 파일시스템에서는 보장되지 않습니다 — 이 저장소들은 로컬 디스크에 두세요.
