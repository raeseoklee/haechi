# 오픈소스 모듈형 아키텍처 초안

- 문서 상태: Draft 0.1
- 작성일: 2026-06-08
- 제품 가칭: AI Context Encryption Layer, AICEL
- 목적: SaaS가 아닌 오픈소스/self-hosted 보안 인프라로서, 암호화·정책·개인정보 필터링 로직을 쉽게 교체할 수 있는 구조 정의

## 1. 방향

AICEL의 초기 목표는 상용 SaaS가 아니다. 작고, 보안적으로 설명 가능하며, 다른 개발자가 자기 AI/LLM/MCP 애플리케이션에 붙여 볼 수 있는 오픈소스 모듈이다.

핵심은 "AICEL이 모든 정답을 제공한다"가 아니라 "AICEL이 안전한 경계와 테스트 기준을 제공하고, 사용자는 그 안에서 자기 구현을 갈아끼운다"다.

따라서 초기 설계의 우선순위는 다음이다.

1. 동작하는 MCP/LLM 보호 데모
2. 교체 가능한 provider interface
3. reference implementation
4. conformance test와 negative security test
5. 플러그인 capability 선언과 fail-closed loading

### 1.1 적용성 기준

보안적으로 좋은 설계라도 적용이 어렵다면 OSS로 확산되기 어렵다. AICEL은 다음 적용성 기준을 제품 요구사항으로 둔다.

| 기준 | 목표 |
|---|---|
| 5분 local demo | `aicel init` 후 local key, sample policy, dry-run audit까지 실행 |
| 30분 MCP/LLM PoC | 기존 MCP host 또는 LLM HTTP 호출을 local proxy로 우회 |
| 1일 custom filter PoC | 사용자가 자체 dictionary/regex/rule을 추가하고 fixture test 실행 |
| 최소 코드 변경 | proxy mode에서는 app code 변경 없이 base URL/env var 변경으로 시작 |
| 점진적 강제 | 처음에는 `dry-run`, 이후 `redact`, `tokenize`, `encrypt`, `block` 적용 |
| 쉬운 교체 | config 또는 dependency injection으로 provider 교체 |

적용 경로는 세 단계로 나눈다.

1. No-code adoption: local proxy, sidecar, env var, target URL 변경
2. Low-code adoption: middleware 또는 SDK wrapper 10줄 이내 적용
3. Custom adoption: `PolicyEngine`, `FilterEngine`, `CryptoProvider`, `AuditSink` 교체

## 2. 비목표

- hosted SaaS control plane
- 과금, 구독, tenant admin portal
- SOC 2/ISO 인증을 전제로 한 영업용 evidence pack
- KCMVP 또는 FIPS 인증 provider 내장
- 자체 암호 primitive 개발
- 모든 LLM/MCP/A2A/gRPC protocol을 0.1에서 production 수준으로 지원
- 규제 준수 보증 문구 제공

## 3. 패키지 구조 제안

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

초기 공개 범위는 `core`, `crypto`, `policy`, `filter`, `audit`, `mcp`, `llm`, `cli`, `testing`, `examples`만으로 충분하다. `grpc`와 `a2a`는 interface와 skeleton 수준으로 남겨도 된다.

## 3.1 적용 모드

| Mode | 변경 범위 | 적합한 상황 | 예시 |
|---|---|---|---|
| Local proxy | 코드 변경 거의 없음 | LLM HTTP, MCP Streamable HTTP를 빠르게 보호 | base URL을 `http://localhost:8787`로 변경 |
| SDK wrapper | 작은 코드 변경 | 앱 내부 context를 더 정확히 전달 | `aicel.protectMessage(...)` |
| Middleware | 웹/API 서버에 삽입 | Express/Fastify/FastAPI 같은 gateway | request/response hook |
| Sidecar | self-hosted service 옆 배치 | 컨테이너/서버 운영 환경 | app -> sidecar -> provider |
| Protocol adapter | protocol별 통합 | MCP stdio, gRPC, A2A | adapter가 normalize/denormalize |
| Custom provider | 특정 로직 교체 | 사내 정책/필터/키 관리 필요 | custom `FilterEngine` |

초기 UX는 proxy mode를 최우선으로 둔다. 이유는 사용자가 보안 모듈의 가치를 확인하기 전에 기존 앱을 크게 고치게 만들면 채택이 느려지기 때문이다.

최소 설정 예시는 다음과 같다.

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
  keyFile: ./.aicel/dev.keys.json
audit:
  sink: jsonl
  path: ./.aicel/audit.jsonl
```

초기 명령 흐름은 다음 정도가 적절하다.

```bash
aicel init --preset mcp-basic --profile kr
aicel proxy --config aicel.yaml --dry-run
aicel report --audit ./.aicel/audit.jsonl
aicel test-plugin ./plugins/my-filter
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

Pipeline은 protocol별 구현보다 위에 있어야 한다. MCP, LLM HTTP, gRPC, A2A adapter는 모두 같은 `SecurityContext`, `PolicyDecision`, `Detection`, `AuditEvent` 모델을 사용해야 한다.

## 5. 교체 가능한 Provider 경계

| Provider | 책임 | 기본 구현 | 사용자가 교체하는 이유 |
|---|---|---|---|
| `CryptoProvider` | 암호화, 복호화, rewrap, envelope metadata 검증 | XChaCha20-Poly1305 또는 AES-GCM 기반 envelope | 조직 표준 암호 포맷, JWE, HPKE, HSM 연동 |
| `KeyProvider` | key id 해석, data key/wrapping key 제공, rotation | local software key | Vault, AWS KMS, GCP KMS, Azure Key Vault, HSM |
| `PolicyEngine` | payload 처리 결정 | JSON/YAML policy | OPA/Rego, CEL, 자체 ABAC/RBAC 정책 |
| `FilterEngine` | PII/secret 탐지와 변환 후보 생성 | regex/checksum/dictionary | 자체 개인정보 룰, NER, local classifier |
| `TokenVault` | tokenization 원문 보관, reveal, purge | local encrypted vault | DB, organization vault, zero-retention tokenization |
| `AuditSink` | 평문 없는 감사 이벤트 기록 | JSON Lines | SIEM, OpenTelemetry-safe exporter, custom log pipeline |
| `ProtocolAdapter` | protocol input/output 정규화 | MCP/LLM reference adapter | 사내 gateway, agent framework, custom socket |
| `ClassifierPlugin` | semantic classification | 없음 또는 local-only demo | 도메인별 민감정보 분류기 |

## 6. Interface 초안

초기 구현은 TypeScript interface를 기준으로 시작하고, Python SDK는 같은 JSON-compatible request/response model을 공유하는 방식이 현실적이다.

```ts
export interface AicelProvider {
  id: string;
  version: string;
  capabilities: ProviderCapabilities;
}

export interface CryptoProvider extends AicelProvider {
  encrypt(request: EncryptRequest): Promise<EnvelopeCiphertext>;
  decrypt(request: DecryptRequest): Promise<PlaintextResult>;
  rewrap?(request: RewrapRequest): Promise<EnvelopeCiphertext>;
}

export interface KeyProvider extends AicelProvider {
  resolveKey(request: KeyResolveRequest): Promise<KeyDescriptor>;
  rotateKey?(request: KeyRotationRequest): Promise<KeyRotationResult>;
}

export interface PolicyEngine extends AicelProvider {
  decide(input: PolicyInput): Promise<PolicyDecision>;
  validatePolicy?(bundle: PolicyBundle): Promise<PolicyValidationResult>;
}

export interface FilterEngine extends AicelProvider {
  detect(input: FilterInput): Promise<Detection[]>;
  transform(input: TransformInput): Promise<TransformResult>;
}

export interface TokenVault extends AicelProvider {
  tokenize(input: TokenizeInput): Promise<TokenizeResult>;
  reveal(input: RevealInput): Promise<RevealResult>;
  purge(input: PurgeInput): Promise<PurgeResult>;
}

export interface AuditSink extends AicelProvider {
  record(event: AuditEvent): Promise<void>;
}

export interface ProtocolAdapter extends AicelProvider {
  normalize(input: ProtocolInput): Promise<NormalizedMessage>;
  denormalize(output: ProtectedMessage): Promise<ProtocolOutput>;
}
```

## 7. Security Context

Provider가 받는 context는 protocol별 raw metadata가 아니라 canonical context여야 한다.

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

중요한 원칙은 `SecurityContext`가 암호화 AAD, 정책 평가, 감사 이벤트의 공통 기준이라는 점이다. 같은 payload라도 tenant, task, tool, model, policy version이 다르면 다른 보안 판단과 다른 암호문이 나와야 한다.

## 8. Plugin Manifest

Plugin은 코드만 등록하면 안 된다. 무엇을 할 수 있는지 먼저 선언해야 한다.

```yaml
aicelPlugin:
  id: example-custom-filter
  version: 0.1.0
  kind: filter-engine
  runtime: node
  entrypoint: ./dist/index.js
  compatibility:
    aicelCore: ">=0.1.0 <0.2.0"
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

Manifest에 없는 capability를 plugin이 요구하면 load를 거부한다. 보안상 알 수 없는 plugin은 fail-closed가 기본이다.

## 9. 쉽게 갈아끼우는 사용 예

사용자는 기본 필터를 그대로 쓰다가 자기 조직의 내부 프로젝트명, 고객 코드, 계약번호를 잡는 custom filter만 추가할 수 있어야 한다.

```ts
import { createAicel } from "@aicel/core";
import { referenceCrypto } from "@aicel/crypto";
import { localKeyProvider } from "@aicel/keys";
import { yamlPolicyEngine } from "@aicel/policy";
import { koreanPiiFilter } from "@aicel/filter";
import { jsonlAuditSink } from "@aicel/audit";
import { myInternalCodeFilter } from "./my-filter";

export const aicel = createAicel({
  crypto: referenceCrypto(),
  keys: localKeyProvider({ keyFile: "./dev.keys.json" }),
  policy: yamlPolicyEngine({ policyFile: "./aicel.policy.yaml" }),
  filters: [
    koreanPiiFilter(),
    myInternalCodeFilter()
  ],
  audit: jsonlAuditSink({ path: "./audit.jsonl" })
});
```

다른 사용자는 정책 엔진만 OPA/Rego로 바꾸고 나머지는 reference implementation을 유지할 수 있다.

```ts
export const aicel = createAicel({
  crypto: referenceCrypto(),
  keys: localKeyProvider(),
  policy: opaPolicyEngine({ bundlePath: "./policy-bundle" }),
  filters: [koreanPiiFilter()],
  audit: jsonlAuditSink()
});
```

## 10. Plugin 보안 검토 항목

Plugin architecture는 확장성을 주지만 새로운 공격면도 만든다. 다음 항목은 MVP부터 테스트 기준으로 둔다.

| 항목 | 위험 | 기준 |
|---|---|---|
| 평문 접근 | filter, crypto, policy plugin이 prompt/tool result를 읽음 | manifest `readsPlaintext` 필수 선언 |
| 네트워크 송신 | classifier가 원문을 외부 endpoint로 전송 | 기본 금지, opt-in도 audit 필수 |
| 로그 유출 | plugin debug log에 원문 저장 | raw payload logging 금지 fixture |
| policy bypass | custom policy가 hard block rule을 완화 | global emergency block 우선순위 고정 |
| audit 조작 | plugin이 audit event를 누락하거나 변조 | core가 최종 audit event를 직접 생성 |
| key misuse | custom crypto가 nonce 재사용 또는 AAD 누락 | conformance negative test 통과 필수 |
| supply chain | 악성 dependency 포함 | SBOM, dependency policy, signed release |
| version drift | core와 plugin schema 불일치 | compatibility range와 schema validation |

## 11. Conformance Test

Provider 교체를 쉽게 하려면 테스트가 interface의 일부여야 한다.

필수 test category:

- `golden`: 정상 입력에서 결정적 결과 구조 확인
- `tamper`: AAD, ciphertext, policy version 변조 시 실패
- `cross-context`: 다른 tenant/task/tool/model에서 복호화 실패
- `replay`: nonce/session/stream sequence 재사용 실패
- `privacy-leak`: audit/log/metric에 원문 미포함
- `policy-conflict`: hard block이 allow override보다 우선
- `capability`: manifest 밖 capability 사용 실패
- `regional-profile`: EU/US/KR profile별 action 차이 확인
- `custom-filter`: 사용자 rule 충돌, rollback, fixture 기반 검증

## 12. OSS 공개 전략

초기 repository는 작게 공개하는 편이 낫다.

권장 공개물:

- `README.md`: 문제, 데모, 설치, non-compliance disclaimer
- `SECURITY.md`: 취약점 제보, 지원 버전, 금지 claim
- `docs/threat-model/`: AI/MCP threat model
- `docs/specs/`: envelope, policy, filter, audit schema
- `examples/`: MCP tool-call 보호와 LLM prompt filtering demo
- `packages/testing/`: plugin conformance test
- `LICENSE`: Apache-2.0 우선 검토

라이선스는 Apache-2.0을 우선 검토한다. 이유는 오픈소스 보안 인프라에서 특허 grant가 명시되어 있어 기업/개발자 채택에 더 유리하기 때문이다. 단순성과 permissive simplicity를 최우선으로 두면 MIT도 가능하다.

## 13. 0.1 구현 우선순위

| 순서 | 구현 | 이유 |
|---:|---|---|
| 1 | `@aicel/core` pipeline과 provider registry | 모든 교체 가능 구조의 중심 |
| 2 | `PolicyEngine`, `FilterEngine`, `CryptoProvider` interface | 사용자가 가장 바꾸고 싶어 할 지점 |
| 3 | reference JSON/YAML policy | 이해하기 쉬운 기본 정책 |
| 4 | Korean PII/secret reference filter | 국내 적용성과 기본 보호 범위를 보여주기 좋음 |
| 5 | envelope crypto reference | 암호화 솔루션의 핵심 데모 |
| 6 | MCP Streamable HTTP proxy | AI/MCP 특화 포지션 증명 |
| 7 | OpenAI-compatible adapter | LLM gateway 적용성 증명 |
| 8 | JSONL audit sink | 평문 미노출 검증 가능 |
| 9 | conformance/negative tests | 보안 프로젝트의 신뢰도 확보 |
| 10 | custom filter/policy examples | "갈아끼우기 쉬움"을 실제로 증명 |

## 14. 남은 결정

- TypeScript-first로 interface를 고정할지, JSON Schema/IDL을 먼저 둘지
- reference crypto format을 JWE로 둘지 compact custom envelope로 둘지
- policy 언어를 자체 YAML로 시작할지 CEL/OPA 호환을 우선할지
- plugin sandbox를 Node process isolation까지 할지, manifest와 test gate부터 시작할지
- Python SDK를 0.1에 포함할지, 0.2로 미룰지
- Apache-2.0과 MIT 중 어떤 라이선스를 선택할지

## 15. 결론

이 방향은 SaaS보다 오픈소스 확산과 self-hosted 적용에 더 잘 맞는다. 기능을 크게 보이게 만드는 것보다, 작은 core가 실제로 MCP/LLM payload를 보호하고 사용자가 policy/filter/crypto를 바꿔도 같은 보안 테스트를 통과하게 만드는 것이 더 강한 프로젝트 신호다.

초기 슬로건은 다음 정도가 적절하다.

```text
AI context protection toolkit for MCP and LLM apps.
Pluggable crypto, policy, privacy filtering, and audit.
Self-hosted by default. No SaaS required.
```
