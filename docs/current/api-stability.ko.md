# Haechi API Stability Policy

- 문서 상태: 발효 중 (1.0 계약 — API freeze)
- 작성일: 2026-06-11
- 적용 버전: 1.0.0 (현재 stable)

## 1. 버전 해석

0.x 라인은 developer preview였습니다. public exports는 사용할 수 있었지만 stable API는 **아니었습니다**. **1.0.0이 현재 stable 릴리스**이며, 아래 계약은 **지금 발효 중**입니다 — Haechi는 이 계약을 선언하고 **strict semver**를 채택합니다(§2 참조). §2의 freeze 규칙(frozen `exports`/CLI 표면, audit event schema, config key shape)은 릴리스된 1.0 라인에 적용되며, 더 이상 미래의 약속이 아닙니다. `tests/api-contract.test.mjs` freeze guard가 frozen 표면을 핀합니다. frozen export·audit 필드·config key를 제거하거나 이름을 바꾸면 CI가 실패하는데, 이것이 breaking change임을 의식적으로 알리는 신호입니다.

| 버전 범위 | 의미 |
|---|---|
| `0.3.x` | local inference/proxy safety patch line (former preview) |
| `0.4.x` | token round-trip and adoption line (former preview) |
| `0.5.x` | streaming hardening target (former preview) |
| `0.6.x` | auth 및 운영 통제 target (former preview) |
| `0.7.x` – `0.9.x` | dashboard / KMS / OIDC 위성 + pre-1.0 하드닝 (former preview) |
| `1.0.0` | **현재 stable 릴리스.** §2의 API 계약이 strict semver 하에 frozen이며 발효 중입니다. |

## 2. 1.0 안정성 계약

### 2.1 Frozen public surface (IN / OUT)

모든 `package.json` `exports` subpath과 CLI를 분류합니다. 더 이상 "0.x는 preview"라는 암묵적 latitude는 없습니다.

| 표면 | 1.0 상태 |
|---|---|
| `haechi` / `haechi/core` — `createHaechi().protectJson`, `createHaechi().createStreamProtector`, `collectStringEntries`, `pathToString`, `safePathToString`, `shapeOnly`, `summarize` | **FROZEN** (breaking change = major) |
| `haechi/runtime` — `createRuntime`, `normalizeConfig` (config shape), `defaultConfig`, `loadConfig`, `writeDefaultConfig`, `isValidPort`, `DEFAULT_CONFIG_PATH` | **FROZEN** |
| `haechi/auth` — `authProvider` 계약, `buildIdentity`, `buildExternalIdentity`, `validateLabels`, `createBearerAuthProvider`, token store (`readAuthStore`, `addToken`, `listTokens`, `revokeToken`), `DEFAULT_ALLOWED_LABEL_KEYS` | **FROZEN** |
| `haechi/crypto` — `cryptoProvider` 계약, `assertCryptoProviderConformance`, `canonicalize`, `createLocalCryptoProvider`, `initLocalKeyFile` | **FROZEN** |
| `haechi/audit` — audit **event schema** (§2.3), `verifyAuditChain`, `sanitizeAudit`, `createJsonlAuditSink`, `readAuditSummary`, `FORBIDDEN_KEYS` | **FROZEN** |
| `haechi/policy` — `buildPolicy`, `createPolicyEngine`, `createPolicyProfiles`, `validatePolicy`, `ACTION_STRENGTH` (action ordering) | **FROZEN** |
| `haechi/filter` — `createDefaultFilterEngine`, `detectEntry`, 그리고 **rule/detection shape** | **FROZEN** |
| `haechi/token-vault` — `createLocalTokenVault`, `readVault`, token format, reveal-governance 계약 | **FROZEN** |
| `haechi/protocol-adapters` — `createProtocolAdapter`, `knownProtocolAdapters`, adapter classification 계약 | **FROZEN** |
| `haechi/plugin` — `validatePluginManifest`, `validatePluginManifestFile`, manifest schema, 1.0 signed-plugin sandbox 표면 | **FROZEN** |
| `haechi/proxy` — `createHaechiProxy`, `assertSafeProxyBind`, `DEFAULT_PROXY_PORT` | **FROZEN BEHAVIOR + wire/contract** (사람이 읽는 log/error **텍스트**는 변경 가능) |
| `haechi/mcp-stdio` — `protectMcpJsonRpcMessage`, `runMcpStdioFilter`, `wrapMcpChild` | **FROZEN BEHAVIOR + wire/contract** |
| `haechi/stream-filter` — `inspectResponseStream`, `getByPath`, `setByPath`, `buildPathObject` | **FROZEN BEHAVIOR + wire/contract** |
| `haechi/policy-bundle` — `signPolicyBundle(File)`, `verifyPolicyBundle(File)`, `loadVerifiedPolicyBundleFileSync` | **FROZEN BEHAVIOR + wire/contract** (signed-bundle 포맷 frozen) |
| `haechi/privacy-profiles` — `listPrivacyProfiles`, `getPrivacyProfile`, `applyPrivacyProfile` | **FROZEN BEHAVIOR + wire/contract** |
| **CLI** — `bin/haechi.mjs` 명령 이름, 플래그, **exit code**, 기계가 읽는(JSON) 출력 | **FROZEN BEHAVIOR + wire/contract**. 사람이 읽는 help/log/status **텍스트**는 계약이 아니며 변경 가능 |

**FROZEN** = export 이름·시그니처·동작이 major 버전 계약의 일부입니다. **FROZEN BEHAVIOR + wire/contract** = wire 포맷·exit code·기계가 읽는 출력·보안 동작은 frozen이지만, 사람이 읽는 CLI/log **텍스트**는 명시적으로 계약이 *아니며* minor/patch에서 변경될 수 있습니다.

### 2.2 Strict semver + deprecation 정책

1.0부터 "0.x minor가 깰 수 있다"는 latitude는 **끝납니다**. 버저닝은 strict semver입니다.

| 변경 유형 | 릴리스 |
|---|---|
| Breaking change (frozen export·필드·config key 제거/이름 변경; frozen 시그니처·wire 포맷 변경) | **major** |
| Additive change (새 export, 새 optional config key, 새 additive audit 필드) | **minor** |
| Bug fix / default 값 하드닝 (shape 변경 없음) | **patch** |

**Deprecation 정책.** deprecated된 export / audit 필드 / config 옵션은 다음과 같이 처리됩니다.

1. deprecation 후 **최소 1 minor 동안 유지**되고,
2. **문서화된 migration note**(`docs/current/release-*.md` 또는 README)와 함께 배포되며,
3. **안정 `code` prefix `HAECHI_DEPRECATION_*`**(예: `HAECHI_DEPRECATION_CONFIG_<key>`, `HAECHI_DEPRECATION_EXPORT_<name>`)를 가진 **일회성 런타임 `process.emitWarning`**을 발생시킵니다. **경고 `code`와 그 텍스트 자체가 계약의 일부입니다** — 소비자가 매칭할 수 있는 안정 식별자이며, 다음 major에서만 변경됩니다.

deprecated 표면은 **다음 major에서만 제거됩니다**.

**보안 예외 (허용되는 단 하나의 in-minor break).** **공개된(disclosed)** 취약점을 닫기 위해 필요한 변경은 **minor 안에서** frozen 표면을 깨거나 제거할 수 있으며, **보안 권고(advisory) + migration path**와 함께 배포됩니다. 이는 오래된 "unsafe config 차단은 patch에서 강화 가능" latitude를 그대로 반영합니다 — 보안 태세는 deprecation 창보다 빠르게 강화될 수 있습니다.

### 2.3 Frozen audit event schema (중첩 sub-schema 포함)

audit event(`packages/core/index.mjs`의 `buildAuditEvent`가 생성하고 `packages/audit`가 무결성 스탬프를 찍습니다)는 top-level뿐 아니라 **중첩 sub-schema까지** frozen입니다.

- **top-level**: `{ schemaVersion, id, timestamp, protocol, operation, identity, profile, mode, enforced, blocked, payloadShapeHash, detections, summary, auditIntegrity }`
- `detections[]`: `{ type, ruleId, path, kind, confidence, action, enforced }`
- `identity` (**PII-safe** 투영): `{ id, type, subjectHash, issuerHash, provider }` — `scopes` / `labels` / raw subject은 frozen audit identity의 **일부가 아닙니다**(keyed-HMAC `subjectHash`/`issuerHash`가 유일한 subject/issuer 표면입니다). 단, 실제 온디스크 `identity` 객체에는 `scopes`와 `labels`가 함께 포함되어 총 7개의 키를 가질 수 있으나, 해당 필드들은 frozen 계약의 **일부가 아닙니다** — audit 로그 소비자는 이 필드들의 존재에 의존해서는 안 됩니다. auth 미설정 시 `identity`는 `null`입니다.
- `summary`: `{ byType, byAction, detectionCount }`
- `auditIntegrity`: `{ alg, canonicalization, sequence, previousHash, eventHash }`

규칙은 다음과 같습니다.

- **`schemaVersion`**은 명시적 top-level reader-facing 필드(1.0 라인에서 값 `"1"`)로, 소비자가 `auditIntegrity`를 파싱하지 않고도 분기할 수 있게 합니다. **additive**이며 canonicalize 대상 객체의 일부입니다.
- **새 필드는 additive-only이고 기존 필드의 canonicalization을 절대 바꾸지 않습니다.** `canonicalize`는 리터럴 객체를 해싱하고 `verifyAuditChain`은 *동일한* 저장 객체로 `eventHash`를 재계산하므로, future-additive 필드를 담은 1.x event도 그 레코드를 읽는 1.0 `verifyAuditChain` 하에서 여전히 검증됩니다 — 보장은 "future-additive 필드가 새 레코드를 읽는 옛 verifier를 깨뜨리지 않는다"입니다.
- **canonicalization 변경**은 **major** event-schema bump입니다. **새 `canonicalization` 태그**(현재 값 `json-stable-v1`)와 **reader-migration path**를 함께 배포합니다. 기존 필드의 해시 기반이 바뀔 수 있는 유일한 방법입니다.

### 2.4 Config schema freeze 단위

**config key 존재 + shape**가 frozen입니다(top-level key `mode`, `target`, `proxy`, `responseProtection`, `streaming`, `limits`, `policy`, `filters`, `keys`, `audit`, `tokenVault`, `privacy`, `auth`, `mcp` 및 그 중첩 shape). **default *값*은 여전히 하드닝될 수 있습니다** — 더 안전한 default(예: 더 엄격한 `failureMode`)는 breaking change가 **아닙니다**. **알 수 없는 key는 여전히 throw합니다**(fail-closed). `normalizeConfig`는 엄격한 enumerated 검증을 수행하며, 그 fail-closed 태세가 계약의 일부입니다.

## 3. Graduated / 잔존 preview exports

0.x "experimental exports" 목록은 1.0에서 **해소됩니다** — 모든 항목은 **graduated**(이제 §2.1 FROZEN / FROZEN-BEHAVIOR 표면의 일부)되거나 명시적 이유와 함께 **1.0 이후에도 preview로 유지**됩니다. 암묵적 모호함은 없습니다.

**Graduated (이제 §2.1에 따라 FROZEN):** `haechi/runtime`, `haechi/proxy`, `haechi/protocol-adapters`, `haechi/privacy-profiles`, `haechi/plugin`, `haechi/mcp-stdio` (`wrapMcpChild`), `haechi/token-vault` (`detokenize` / deterministic tokenization 옵션), `identity` audit 필드와 `authProvider` 계약, `haechi/stream-filter`와 `createStreamProtector`, `haechi/auth` (`createBearerAuthProvider`, token store, `buildIdentity`, `buildExternalIdentity`), `assertCryptoProviderConformance`와 강화된 `cryptoProvider` 계약, `audit.anchor` + `verifyAuditChain(path, { anchorPath })`, `scripts/release-checksums.mjs`, `policy.profiles` / `policy.profileBinding` / `modelAllowlist` / `rate`와 `identity` / `profile` audit 필드. `status` / `audit-verify` CLI 출력의 기계가 읽는 형태는 frozen입니다(FROZEN BEHAVIOR — 사람이 읽는 텍스트는 아닙니다).

**1.0 이후에도 preview로 유지 (이유 명시):**

- **`injection` detection type과 그 휴리스틱 룰** — 휴리스틱 집합은 계속 진화할 것으로 예상되며 **기본 report-only**입니다(명시적 escalate 없이는 response 방향에서 action `allow`로 고정). 따라서 그 *룰 멤버십 / confidence*는 frozen이 아니지만, 그것이 생성하는 detection *shape*는 frozen `detections[]` shape입니다. `injection` 룰을 추가하거나 변경하는 것은 breaking change가 아닙니다.

## 4. Migration note 기준

다음 변경이 있으면 `docs/current/release-*.md` 또는 README에 migration note를 남깁니다. 1.0부터 이 목록의 변경이 **FROZEN** 표면에 가해지면 **major** 이벤트(또는 §2.2의 보안 예외 minor)이며, deprecation 창이 적용되는 경우 `HAECHI_DEPRECATION_*` 런타임 경고를 동반하고 `tests/api-contract.test.mjs`를 갱신합니다.

- config key 추가/삭제
- default enforcement 변경
- CLI flag 추가/삭제
- audit event 필드 변경 (top-level 또는 중첩)
- token format 변경
- plugin manifest schema 변경

## 5. Satellite 패키지 (`haechi-*`)

위성(예: `haechi-crypto-kms`, `haechi-auth-jwt`, `haechi-dashboard`, `haechi-auth-oidc`)은 core와 **독립적으로** 버저닝합니다 — 위성 릴리스가 `haechi`를 bump하지 않고, 그 반대도 마찬가지입니다.

- **pre-1.0:** 위성은 npm semver를 따르며 `0.x` **minor** bump가 breaking change를 담을 수 있습니다. `major.minor`로 핀합니다(예: `haechi-crypto-kms@~0.2`). 각자 자체 `1.0.0`까지 pre-stable입니다.
- **core 호환성**은 `peerDependencies` 범위(`"haechi": ">=0.8.0 <2.0.0"`)로 표현합니다 — 위성은 소비자가 설치한 단일 `haechi`를 재사용하므로 crypto/identity 표면이 하나입니다. `haechi-auth-oidc`는 추가로 `haechi-auth-jwt`(`">=0.2.0 <2.0.0"`)에 peer-depend하여 둘이 audit되는 단일 JWS/JWKS 검증 경로를 공유합니다. 위성의 `haechi` peer-dependency **상한은 반드시 core MAJOR를 추적해야 하며**(`<2.0.0`), 다음 minor 미만으로 고정해서는 안 됩니다 — core의 minor/major 호환 범프가 위성 설치를 깨뜨리지 않도록 하기 위함입니다. `release:preflight` 게이트(`scripts/check-satellite-peer-ranges.mjs`)가 이를 자동으로 강제합니다.
- **무거운 백엔드는 optional peer입니다.** `haechi-crypto-kms`는 SDK 백엔드(`@aws-sdk/client-kms`, 그리고 0.2.0의 `@google-cloud/kms`, `@azure/keyvault-keys`, `@azure/identity`)를 `peerDependencies` + `peerDependenciesMeta.optional`로 선언하고 lazy import하므로, 해당 경로를 쓰지 않는 소비자는 설치하지 않고 core는 zero-dependency를 유지합니다. `./vault` 백엔드는 `node:` `fetch`만 사용합니다(optional peer 없음). 위성의 배포 tarball은 항상 **runtime `dependencies` 0**을 선언합니다(CI `check-satellite-packaging`로 강제).
- **pre-1.0 위성 export**는 preview이며 각 위성의 자체 `1.0.0` 전에 변경될 수 있습니다.
  - `haechi-crypto-kms` (0.8 → 0.2.0): `createKmsCryptoProvider`, `createInMemoryKms`, `./aws`의 `createAwsKmsClient`, 그리고 0.2.0의 새 subpath `./gcp`(`createGcpKmsClient`), `./azure`(`createAzureKmsClient`), `./vault`(`createVaultKmsClient`).
  - `haechi-auth-jwt` (0.2.0): `createJwtAuthProvider`(0.8, behavior-preserving)와 추가된 `createJwtVerifier`(재사용 가능한 JWS 검증 primitive), `isBlockedAddress`(SSRF 범위 술어, `haechi-auth-oidc`가 재사용).
  - `haechi-dashboard` (0.1.0, 신규): `createDashboardServer`, `normalizeDashboardConfig`.
  - `haechi-auth-oidc` (0.1.0, 신규): `createOidcSessionBroker`, `normalizeOidcConfig`.
