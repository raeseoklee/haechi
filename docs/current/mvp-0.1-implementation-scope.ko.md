# MVP 0.1 구현 범위

- 문서 상태: Draft 0.1
- 작성일: 2026-06-09
- 관련 제품: Haechi

## 1. 결론

MVP 0.1은 넓은 protocol coverage보다 "쉽게 붙이고 바로 확인할 수 있는 로컬 보안 레이어"를 완성하는 데 집중한다.

0.1의 성공 기준은 다음이다.

1. 사용자가 `haechi init`으로 local key, sample policy, audit path를 생성한다.
2. 사용자가 `haechi protect`로 OpenAI-compatible JSON payload를 보호해 본다.
3. 사용자가 `haechi proxy`로 기존 LLM HTTP 호출을 local proxy에 붙여 본다.
4. 사용자가 `haechi report`로 평문 없는 audit summary를 확인한다.
5. 테스트가 개인정보/secret 탐지, redaction, block, encryption, audit plaintext leak 방지를 검증한다.

## 2. 0.1 포함 범위

| 영역 | 포함 |
|---|---|
| Runtime | Node.js ESM, no external runtime dependency |
| Config | JSON config, preset policy |
| CLI | `init`, `protect`, `report`, `proxy` |
| Core | security context, filter -> policy -> transform -> audit pipeline |
| Filter | email, phone, Korean RRN-like id, card-like number, API key/secret, custom regex |
| Policy | dry-run, redact, mask, encrypt, block |
| Crypto | local AES-256-GCM envelope encryption using Node `crypto` |
| Key | local software key file |
| Audit | JSON Lines audit event without raw payload |
| Adapter | OpenAI-compatible request body traversal |
| Proxy | local HTTP JSON proxy with upstream forwarding |
| Tests | Node built-in test runner |

## 3. 0.1 제외 범위

| 제외 | 이유 | 다음 단계 |
|---|---|---|
| Python SDK | 0.1 quickstart에는 Node CLI만으로 충분 | 0.2 |
| Vault/AWS KMS | 외부 설정이 필요해 5분 demo를 방해 | 0.2 adapter |
| MCP stdio wrapper | process/env handling이 별도 보안 검토 필요 | 0.2 |
| Full MCP protocol proxy | 0.1은 HTTP JSON payload 보호 검증 우선 | 0.2 |
| A2A/gRPC production adapter | protocol contract 선행 필요 | 0.3 |
| TokenVault | reveal/purge governance가 별도 설계 필요 | 0.2 |
| Signed policy bundle | 0.1은 local config validation 우선 | 0.2 |
| SBOM/signing | release 단계 작업 | 0.2 |

## 4. Quickstart 흐름

```bash
npm test
node packages/cli/bin/haechi.mjs init --force
node packages/cli/bin/haechi.mjs protect examples/llm-prompt-filtering/input.json --config haechi.config.json
node packages/cli/bin/haechi.mjs report --audit .haechi/audit.jsonl
node packages/cli/bin/haechi.mjs proxy --config haechi.config.json --port 8787
```

## 5. 구현 원칙

- 외부 dependency 없이 시작한다.
- JSON 설정을 사용한다. YAML은 0.2 이후로 미룬다.
- 암호 primitive는 직접 만들지 않고 Node `crypto`의 AES-256-GCM을 사용한다.
- default mode는 `dry-run`이다.
- enforcement mode에서도 audit에는 원문을 남기지 않는다.
- 적용 실패 시 원문 유출보다 요청 차단을 우선한다.
- provider boundary는 코드 구조로 남기되, 0.1에서는 과한 plugin loader를 만들지 않는다.

## 6. 0.1 완료 기준

| 기준 | 완료 조건 |
|---|---|
| CLI | `init`, `protect`, `report`, `proxy`가 동작 |
| 보안 | audit JSONL에 sentinel 원문이 남지 않음 |
| 개인정보 | email/phone/secret/card-like/RRN-like fixture 탐지 |
| 정책 | dry-run/redact/mask/encrypt/block fixture 통과 |
| 암호 | AAD 변조 시 복호화 실패 |
| 적용성 | example payload를 CLI로 보호하고 audit report 확인 |
| 검증 | `npm test` 통과 |
