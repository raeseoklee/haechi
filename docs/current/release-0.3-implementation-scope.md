# Release 0.3 Implementation Scope

- Status: Draft 0.1
- Date: 2026-06-10
- Target version: Haechi

## 1. Goals

0.3 makes it easier to place Haechi in front of self-hosted/local inference servers such as vLLM, Ollama, and llama.cpp.

Included scope:

- OpenAI-compatible, vLLM, Ollama, and llama.cpp protocol adapter presets
- Per-request-path operation classification and audit correlation
- Optional JSON response protection
- `local-inference` policy preset
- npm publish-ready package metadata, exports, and files list
- 0.3.1 safety patch: remote bind guard, streaming fail-closed, response failure policy, audit hash chain, provider injection, CI/SBOM/provenance workflow

## 2. Usage Examples

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

## 3. Excluded Scope

- SSE/NDJSON streaming response transformation beyond default fail-closed blocking
- Dedicated media scanner for image/multimodal payloads
- Vendor-specific KMS, Vault, and HSM adapter implementations
- Production authentication/authorization gateway

## 4. Completion Criteria

| Criterion | Done When |
|---|---|
| Protocol adapters | vLLM, Ollama, and llama.cpp route classification tests pass |
| Response protection | Sensitive data in upstream JSON responses is transformed per policy; no plaintext remains in the audit log |
| Package readiness | `npm pack --dry-run` passes |
| Release safety | `npm run release:preflight` passes |
| Regression | Full `npm test` passes |
