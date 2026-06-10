# Release 0.3 구현 범위

- 문서 상태: Draft 0.1
- 작성일: 2026-06-10
- 관련 제품: Haechi

## 1. 목표

0.3은 Haechi를 vLLM, Ollama, llama.cpp 같은 self-hosted/local inference server 앞단에 더 쉽게 붙일 수 있도록 한다.

포함 범위:

- OpenAI-compatible, vLLM, Ollama, llama.cpp protocol adapter preset
- request path별 operation 분류와 audit correlation
- 선택적 JSON response protection
- `local-inference` policy preset
- npm publish-ready package metadata, exports, files 목록
- 0.3.1 safety patch: remote bind guard, streaming fail-closed, response failure policy, audit hash chain, provider injection, CI/SBOM/provenance workflow

## 2. 적용 예시

### vLLM

```json
{
  "target": {
    "type": "vllm-openai",
    "upstream": "http://127.0.0.1:8000"
  },
  "policy": {
    "mode": "enforce",
    "presets": ["local-inference"]
  },
  "responseProtection": {
    "enabled": true,
    "mode": "enforce"
  }
}
```

### Ollama

```json
{
  "target": {
    "adapter": "ollama",
    "upstream": "http://127.0.0.1:11434"
  },
  "policy": {
    "mode": "enforce",
    "presets": ["local-inference"]
  }
}
```

### llama.cpp

```json
{
  "target": {
    "adapter": "llama-cpp",
    "upstream": "http://127.0.0.1:8080"
  },
  "policy": {
    "mode": "enforce",
    "presets": ["local-inference"]
  }
}
```

## 3. 제외 범위

- SSE/NDJSON streaming response transformation beyond default fail-closed blocking
- 이미지/멀티모달 payload 전용 media scanner
- vendor-specific KMS, Vault, HSM adapter implementation
- production authentication/authorization gateway

## 4. 완료 기준

| 기준 | 완료 조건 |
|---|---|
| Protocol adapters | vLLM, Ollama, llama.cpp route classification test 통과 |
| Response protection | upstream JSON 응답의 민감정보가 정책에 따라 변환되고 audit에 평문이 남지 않음 |
| Package readiness | `npm pack --dry-run` 통과 |
| Release safety | `npm run release:preflight` 통과 |
| Regression | 전체 `npm test` 통과 |
