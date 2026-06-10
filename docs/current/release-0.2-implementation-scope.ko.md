# Release 0.2 구현 범위

- 문서 상태: Draft 0.1
- 작성일: 2026-06-09
- 관련 제품: Haechi

## 1. 목표

0.2는 0.1 quickstart 위에 보안 신뢰 경계와 교체 가능성을 보강한다.

포함 범위:

- local encrypted TokenVault
- signed policy bundle signing/verification
- plugin manifest validation
- MCP stdio JSON-RPC line filter skeleton
- 관련 CLI와 테스트

## 2. CLI 추가

```bash
node packages/cli/bin/haechi.mjs policy-sign policy.json --out policy.bundle.json
node packages/cli/bin/haechi.mjs policy-verify policy.bundle.json
node packages/cli/bin/haechi.mjs plugin-validate examples/plugins/custom-filter.plugin.json
node packages/cli/bin/haechi.mjs token-reveal <token>
node packages/cli/bin/haechi.mjs token-purge <token>
node packages/cli/bin/haechi.mjs mcp-stdio --config haechi.config.json
```

## 3. 제외 범위

- 외부 Vault/AWS/GCP/Azure KMS 실제 연동
- plugin code dynamic loading
- MCP server child process lifecycle management
- signed release artifact와 SBOM 자동 생성
- Python SDK

## 4. 완료 기준

| 기준 | 완료 조건 |
|---|---|
| TokenVault | `tokenize` action이 encrypted local vault에 mapping 저장 |
| Signed policy | policy bundle 서명 검증 실패 시 runtime load 실패 |
| Plugin manifest | capability와 dataHandling 필드 검증 |
| MCP stdio | JSON-RPC `params`/`result` payload 보호 |
| Tests | token vault, policy bundle, plugin manifest, MCP stdio fixture 통과 |
