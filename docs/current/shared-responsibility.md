# Haechi Shared Responsibility

- 문서 상태: Draft 0.1
- 작성일: 2026-06-10
- 기준 버전: 0.3.2

## 1. 책임 매트릭스

| 영역 | Haechi 제공 | 사용자/운영자 책임 |
|---|---|---|
| 로컬 개발 | CLI, default config, dev key 생성 | dev key를 운영/공유 환경에 재사용하지 않음 |
| 정책 집행 | redact/mask/tokenize/encrypt/block pipeline | 규제/조직 정책에 맞는 action 선택 |
| HTTP proxy | loopback 기본, remote bind guard, body/response limit | 인증, TLS termination, firewall, upstream auth |
| Streaming | 기본 차단 | pass-through 사용 시 보호 미적용 위험 수용 |
| TokenVault | 암호화 저장, reveal 기본 차단, purge | reveal 승인 절차, DSAR/retention 운영 |
| Audit | 평문 제거, hash chain | append-only storage, backup, 보존 기간, 외부 서명 |
| Key custody | local dev key, external crypto provider contract | KMS/HSM/Vault adapter 구현, rotation, access review |
| Plugin | manifest validation, dynamic runtime 차단 | plugin code review, sandbox 제공 전 실행 금지 |
| MCP | JSON-RPC/method allowlist | MCP server auth, resource consent, env secret allowlist |
| Privacy profile | KR/EU/US baseline actions | 법률 검토, data residency, cross-border transfer evidence |

## 2. 금지되는 기본 사용

- `--allow-remote-bind`를 네트워크 통제 없이 사용
- `.haechi/dev.keys.json`을 운영 데이터에 사용
- `streaming.requestMode: "pass-through"`를 보호 적용으로 오해
- `responseProtection.failureMode: "allow"`를 민감 데이터 경로에 사용
- `token-reveal --allow-dev-reveal`를 운영 복원 절차로 사용

## 3. 운영 전환 체크리스트

1. 외부 crypto provider 또는 KMS/HSM/Vault adapter를 연결한다.
2. proxy 앞단에 인증, TLS, firewall, rate limit을 둔다.
3. responseProtection을 켜고 fail-closed를 유지한다.
4. streaming endpoint는 별도 stream-aware gateway가 준비되기 전 차단한다.
5. audit sink를 append-only 또는 외부 서명 저장소로 보낸다.
6. TokenVault reveal 승인/보존/삭제 절차를 문서화한다.
7. privacy profile은 법률 검토 결과로 보정한다.
