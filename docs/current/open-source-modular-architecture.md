# Open-Source Modular Architecture Draft

- Status: Draft 0.1
- Date: 2026-06-08
- Product: Haechi
- Purpose: Define a structure for open-source/self-hosted security infrastructure — not SaaS — where encryption, policy, and privacy filtering logic can be swapped out easily

## 1. Direction

Haechi's initial goal is not a commercial SaaS product. It is a small, security-auditable open-source module that other developers can attach to their own AI/LLM/MCP applications.

The core idea is not "Haechi provides all the answers" but rather "Haechi provides safe boundaries and test standards; users swap in their own implementations within those boundaries."

Therefore, the priorities for the initial design are:

1. A working MCP/LLM protection demo
2. Replaceable provider interfaces
3. Reference implementations
4. Conformance tests and negative security tests
5. Plugin capability declarations and fail-closed loading

### 1.1 Adoptability Criteria

Even a sound security design is hard to spread as OSS if it is difficult to adopt. Haechi treats the following adoptability criteria as product requirements.

| Criterion | Target |
|---|---|
| 5-minute local demo | Run `haechi init` through local key, sample policy, and dry-run audit |
| 30-minute MCP/LLM PoC | Route an existing MCP host or LLM HTTP call through the local proxy |
| 1-day custom filter PoC | Add a custom dictionary/regex/rule and run fixture tests |
| Minimal code changes | In proxy mode, start by changing only base URL/env vars — no app code changes |
| Incremental enforcement | Start with `dry-run`, then progress to `redact`, `tokenize`, `encrypt`, `block` |
| Easy replacement | Swap providers via config or dependency injection |

The adoption path is divided into three stages:

1. No-code adoption: local proxy, sidecar, env var, target URL change
2. Low-code adoption: middleware or SDK wrapper in 10 lines or fewer
3. Custom adoption: replace `PolicyEngine`, `FilterEngine`, `CryptoProvider`, `AuditSink`

## 2. Non-Goals

- Hosted SaaS control plane
- Billing, subscriptions, tenant admin portal
- Sales-oriented evidence pack targeting SOC 2/ISO certification
- Built-in KCMVP or FIPS certified providers
- Developing custom cryptographic primitives
- Production-grade support for all LLM/MCP/A2A/gRPC protocols in 0.1
- Providing regulatory compliance assurance language

## 3. Proposed Package Structure

```text
packages/
  core/             # pipeline, context model, plugin registry, errors
  crypto/           # reference CryptoProvider, envelope format
  keys/             # local KeyProvider, Vault/KMS adapter skeleton
  policy/           # JSON/YAML reference PolicyEngine
  filter/           # PII/secret reference FilterEngine
  token-vault/      # local encrypted TokenVault reference
  audit/            # JSONL AuditSink, safe event schema
  mcp/              # MCP Streamable HTTP proxy, stdio wrapper
  llm/              # OpenAI-compatible HTTP adapter
  grpc/             # protobuf/gRPC adapter skeleton
  a2a/              # A2A adapter skeleton
  cli/              # local demo and fixture runner
  testing/          # conformance fixtures, negative tests
examples/
  mcp-tool-protection/
  llm-prompt-filtering/
  custom-policy-engine/
  custom-filter-engine/
  custom-audit-sink/
docs/
  current/
  specs/
  threat-model/
```

For the initial public release, `core`, `crypto`, `policy`, `filter`, `audit`, `mcp`, `llm`, `cli`, `testing`, and `examples` are sufficient. `grpc` and `a2a` can remain at the interface and skeleton level.

## 3.1 Adoption Modes

| Mode | Scope of change | When to use | Example |
|---|---|---|---|
| Local proxy | Almost no code changes | Quickly protect LLM HTTP or MCP Streamable HTTP | Change base URL to `http://localhost:8787` |
| SDK wrapper | Small code changes | Pass more precise in-app context | `haechi.protectMessage(...)` |
| Middleware | Insert into web/API server | Gateways like Express/Fastify/FastAPI | request/response hook |
| Sidecar | Deploy alongside self-hosted service | Container/server runtime environments | app -> sidecar -> provider |
| Protocol adapter | Per-protocol integration | MCP stdio, gRPC, A2A | adapter normalize/denormalize |
| Custom provider | Replace specific logic | In-house policy/filter/key management needed | custom `FilterEngine` |

Proxy mode is the top UX priority for the initial release. Requiring users to significantly rewrite existing apps before they can evaluate the value of the security module slows adoption.

The minimal configuration example is as follows:

```yaml
mode: proxy
target:
  type: llm-http
  upstream: https://api.openai.example/v1
policy:
  preset:
    - korean-pii
    - secrets-only
    - llm-redact
  mode: dry-run
keys:
  provider: local
  keyFile: ./.haechi/dev.keys.json
audit:
  sink: jsonl
  path: ./.haechi/audit.jsonl
```

The initial command flow looks like:

```bash
haechi init --preset mcp-basic --profile kr
haechi proxy --config haechi.yaml --dry-run
haechi report --audit ./.haechi/audit.jsonl
haechi test-plugin ./plugins/my-filter
```

## 4. Core Pipeline

```text
ProtocolAdapter
    |
    v
Core Pipeline
    |
    +-- normalize input
    +-- attach security context
    +-- run FilterEngine.detect
    +-- run PolicyEngine.decide
    +-- transform payload
    |      +-- redact
    |      +-- mask
    |      +-- tokenize
    |      +-- encrypt
    |      +-- block
    +-- emit AuditSink event
    |
    v
Protected protocol output
```

The pipeline must sit above protocol-specific implementations. MCP, LLM HTTP, gRPC, and A2A adapters must all share the same `SecurityContext`, `PolicyDecision`, `Detection`, and `AuditEvent` models.

## 5. Replaceable Provider Boundaries

| Provider | Responsibility | Default implementation | Why users replace it |
|---|---|---|---|
| `CryptoProvider` | Encrypt, decrypt, rewrap, envelope metadata validation | XChaCha20-Poly1305 or AES-GCM based envelope | Organization cipher format standards, JWE, HPKE, HSM integration |
| `KeyProvider` | Resolve key IDs, provide data keys/wrapping keys, rotation | Local software key | Vault, AWS KMS, GCP KMS, Azure Key Vault, HSM |
| `PolicyEngine` | Decide how to process payloads | JSON/YAML policy | OPA/Rego, CEL, custom ABAC/RBAC policies |
| `FilterEngine` | Detect PII/secrets and generate transform candidates | regex/checksum/dictionary | Custom privacy rules, NER, local classifier |
| `TokenVault` | Store tokenization originals, reveal, purge | Local encrypted vault | DB, organization vault, zero-retention tokenization |
| `AuditSink` | Record audit events without plaintext | JSON Lines | SIEM, OpenTelemetry-safe exporter, custom log pipeline |
| `ProtocolAdapter` | Normalize/denormalize protocol input/output | MCP/LLM reference adapter | In-house gateway, agent framework, custom socket |
| `ClassifierPlugin` | Semantic classification | None or local-only demo | Domain-specific sensitive data classifiers |

## 6. Interface Draft

Starting with TypeScript interfaces is practical for the initial implementation. A Python SDK sharing the same JSON-compatible request/response model is a realistic approach.

```ts
export interface HaechiProvider {
  id: string;
  version: string;
  capabilities: ProviderCapabilities;
}

export interface CryptoProvider extends HaechiProvider {
  encrypt(request: EncryptRequest): Promise<EnvelopeCiphertext>;
  decrypt(request: DecryptRequest): Promise<PlaintextResult>;
  rewrap?(request: RewrapRequest): Promise<EnvelopeCiphertext>;
}

export interface KeyProvider extends HaechiProvider {
  resolveKey(request: KeyResolveRequest): Promise<KeyDescriptor>;
  rotateKey?(request: KeyRotationRequest): Promise<KeyRotationResult>;
}

export interface PolicyEngine extends HaechiProvider {
  decide(input: PolicyInput): Promise<PolicyDecision>;
  validatePolicy?(bundle: PolicyBundle): Promise<PolicyValidationResult>;
}

export interface FilterEngine extends HaechiProvider {
  detect(input: FilterInput): Promise<Detection[]>;
  transform(input: TransformInput): Promise<TransformResult>;
}

export interface TokenVault extends HaechiProvider {
  tokenize(input: TokenizeInput): Promise<TokenizeResult>;
  reveal(input: RevealInput): Promise<RevealResult>;
  purge(input: PurgeInput): Promise<PurgeResult>;
}

export interface AuditSink extends HaechiProvider {
  record(event: AuditEvent): Promise<void>;
}

export interface ProtocolAdapter extends HaechiProvider {
  normalize(input: ProtocolInput): Promise<NormalizedMessage>;
  denormalize(output: ProtectedMessage): Promise<ProtocolOutput>;
}
```

## 7. Security Context

The context received by providers must be a canonical context, not protocol-specific raw metadata.

```ts
export interface SecurityContext {
  tenantId?: string;
  userId?: string;
  agentId?: string;
  sessionId?: string;
  taskId?: string;
  contextId?: string;
  modelProvider?: string;
  modelId?: string;
  protocol: "mcp" | "llm-http" | "grpc" | "a2a" | "socket" | "custom";
  operation: string;
  resourceUri?: string;
  toolName?: string;
  region?: string;
  policyVersion: string;
  aad: CanonicalAad;
}
```

The key principle is that `SecurityContext` serves as the common basis for cryptographic AAD, policy evaluation, and audit events. The same payload must produce a different security decision and a different ciphertext when the tenant, task, tool, model, or policy version differs.

## 8. Plugin Manifest

A plugin must not merely register code. It must first declare what it is capable of doing.

```yaml
haechiPlugin:
  id: example-custom-filter
  version: 0.1.0
  kind: filter-engine
  runtime: node
  entrypoint: ./dist/index.js
  compatibility:
    haechiCore: ">=0.1.0 <0.2.0"
  capabilities:
    readsPlaintext: true
    writesPlaintext: false
    networkEgress: false
    fileWrite: false
    auditWrite: false
    externalSecrets: false
  dataHandling:
    storesPayload: false
    retention: none
    logsRawPayload: false
  tests:
    conformance: ./fixtures/conformance.json
    negative: ./fixtures/negative.json
```

If a plugin requests a capability not declared in its manifest, loading is rejected. Fail-closed is the default for any plugin that cannot be verified.

## 9. Easy Replacement Usage Examples

Users should be able to keep the default filters as-is and add only a custom filter that catches their organization's internal project names, customer codes, and contract numbers.

```ts
import { createHaechi } from "@haechi/core";
import { referenceCrypto } from "@haechi/crypto";
import { localKeyProvider } from "@haechi/keys";
import { yamlPolicyEngine } from "@haechi/policy";
import { koreanPiiFilter } from "@haechi/filter";
import { jsonlAuditSink } from "@haechi/audit";
import { myInternalCodeFilter } from "./my-filter";

export const haechi = createHaechi({
  crypto: referenceCrypto(),
  keys: localKeyProvider({ keyFile: "./dev.keys.json" }),
  policy: yamlPolicyEngine({ policyFile: "./haechi.policy.yaml" }),
  filters: [
    koreanPiiFilter(),
    myInternalCodeFilter()
  ],
  audit: jsonlAuditSink({ path: "./audit.jsonl" })
});
```

Another user can swap only the policy engine to OPA/Rego while keeping the rest as reference implementations.

```ts
export const haechi = createHaechi({
  crypto: referenceCrypto(),
  keys: localKeyProvider(),
  policy: opaPolicyEngine({ bundlePath: "./policy-bundle" }),
  filters: [koreanPiiFilter()],
  audit: jsonlAuditSink()
});
```

## 10. Plugin Security Review Items

A plugin architecture provides extensibility but also introduces new attack surface. The following items are treated as test requirements starting from MVP.

| Item | Risk | Requirement |
|---|---|---|
| Plaintext access | filter, crypto, policy plugins read prompt/tool results | `readsPlaintext` must be declared in manifest |
| Network egress | classifier sends original content to an external endpoint | Blocked by default; opt-in also requires audit |
| Log leakage | plugin debug logs store original content | Raw payload logging prohibited — fixture test required |
| Policy bypass | custom policy weakens a hard block rule | Global emergency block priority is fixed |
| Audit tampering | plugin omits or alters audit events | Core generates the final audit event directly |
| Key misuse | custom crypto reuses a nonce or omits AAD | Must pass conformance negative tests |
| Supply chain | malicious dependency included | SBOM, dependency policy, signed release |
| Version drift | core and plugin schema mismatch | Compatibility range and schema validation |

## 11. Conformance Tests

To make provider replacement straightforward, tests must be part of the interface contract.

Required test categories:

- `golden`: Verify deterministic result structure for valid inputs
- `tamper`: Fail on AAD, ciphertext, or policy version tampering
- `cross-context`: Fail to decrypt under a different tenant/task/tool/model
- `replay`: Fail on nonce/session/stream sequence reuse
- `privacy-leak`: Audit/log/metric must not contain plaintext
- `policy-conflict`: Hard block takes priority over allow overrides
- `capability`: Fail when a capability outside the manifest is used
- `regional-profile`: Verify action differences across EU/US/KR profiles
- `custom-filter`: User rule conflicts, rollback, fixture-based validation

## 12. OSS Release Strategy

Starting with a small initial repository is preferable.

Recommended initial release artifacts:

- `README.md`: Problem statement, demo, installation, non-compliance disclaimer
- `SECURITY.md`: Vulnerability reporting, supported versions, prohibited claims
- `docs/threat-model/`: AI/MCP threat model
- `docs/specs/`: Envelope, policy, filter, and audit schemas
- `examples/`: MCP tool-call protection and LLM prompt filtering demo
- `packages/testing/`: Plugin conformance tests
- `LICENSE`: Apache-2.0 as the primary candidate

Apache-2.0 is the primary license candidate. The explicit patent grant makes it more favorable for enterprise and developer adoption in open-source security infrastructure. MIT is also viable if simplicity and permissive terms are the top priority.

## 13. Implementation Priorities for 0.1

| Order | Implementation | Reason |
|---:|---|---|
| 1 | `@haechi/core` pipeline and provider registry | The foundation of all replaceable structure |
| 2 | `PolicyEngine`, `FilterEngine`, `CryptoProvider` interfaces | The points users will most want to customize |
| 3 | Reference JSON/YAML policy | Easy-to-understand default policy |
| 4 | Korean PII/secret reference filter | Best demonstrates local adoptability and baseline protection coverage |
| 5 | Envelope crypto reference | Core demo of the encryption solution |
| 6 | MCP Streamable HTTP proxy | Proves the AI/MCP-specific positioning |
| 7 | OpenAI-compatible adapter | Proves LLM gateway adoptability |
| 8 | JSONL audit sink | Enables verification that no plaintext is exposed |
| 9 | Conformance/negative tests | Establishes credibility as a security project |
| 10 | Custom filter/policy examples | Proves in practice that replacement is easy |

## 14. Open Decisions

- Whether to fix interfaces as TypeScript-first, or define JSON Schema/IDL first
- Whether the reference crypto format should be JWE or a compact custom envelope
- Whether to start the policy language as a custom YAML or prioritize CEL/OPA compatibility
- Whether plugin sandboxing should go as far as Node process isolation, or start with manifest and test gates
- Whether to include a Python SDK in 0.1 or defer to 0.2
- Whether to choose Apache-2.0 or MIT

## 15. Conclusion

This direction is better suited to open-source distribution and self-hosted adoption than a SaaS model. Rather than making the feature set look large, a stronger project signal is a small core that actually protects MCP/LLM payloads and ensures that the same security tests pass even when users swap out policy, filter, or crypto components.

An appropriate initial tagline:

```text
AI context protection toolkit for MCP and LLM apps.
Pluggable crypto, policy, privacy filtering, and audit.
Self-hosted by default. No SaaS required.
```
