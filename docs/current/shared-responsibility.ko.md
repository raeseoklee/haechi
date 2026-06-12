# Haechi Shared Responsibility

- 문서 상태: Draft 0.1
- 작성일: 2026-06-10
- 기준 버전: 0.3.2

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
| Plugin | manifest validation, dynamic runtime 차단 | plugin code review를 수행하고, sandbox가 제공되기 전에는 실행하지 않습니다 |
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
