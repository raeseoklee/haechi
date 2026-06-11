# Haechi 1.0 구현 범위

- 상태: Draft 0.2 (설계 — 아직 미구현; 2026-06-11 3-렌즈 적대적 보안 리뷰 후 강화)
- 날짜: 2026-06-11
- 목표 버전: 1.0.0 (0.9.0 다음)
- 유형: 안정 API 계약 + 플러그인 샌드박스 (첫 번째 안정 릴리스)

## 1. 릴리스 목표

1.0은 **첫 번째 안정 릴리스**다: (a) 지원 중단(deprecation)/마이그레이션 정책과 장기 감사 스키마를 갖춘 **안정적인 공개 API 계약을 동결**하고, (b) 0.1부터 의도적으로 유지해온 선을 넘는다 — **외부 플러그인 코드의 동적 로딩** — 단, **비대칭 서명, 기능(capability) 게이트, `worker_threads` 격리, 감사**가 갖춰진 샌드박스를 통해서만, 그리고 우선 **`authProvider`** 계약에 한해서만.

**범위 결정 (2026-06-11, 메인테이너 확인):**

1. **샌드박스/로딩 모델:** 동적 로딩은 **서명(Ed25519, 비대칭)**되고, **기능(capability) 매니페스트 allowlist + 운영자 pin/revocation 체크**를 통과하며, **`node:worker_threads` 격리** 경계에서 실행되고, 전체 **라이프사이클 감사**를 갖춘 플러그인에 한해서만 활성화된다. `createRuntime(config, providers)` **주입(injection)은 기본이자 권장 경로로 유지된다**.
2. **플러그인 범위:** 1.0에서는 **`authProvider` 전용**. Classifier/filter 및 crypto 플러그인은 1.x까지 주입 전용으로 유지.
3. **API 동결:** **엄격** — 핵심 공개 API, **provider 계약**, **감사 이벤트 스키마**(중첩 하위 스키마 포함), **config 스키마**가 엄격한 semver와 지원 중단 정책 하에 동결된다.
4. **릴리스 형태:** **단계적** — 1.0.0은 API 동결 + 서명된 플러그인 계약/적합성(conformance)/서명 + worker 격리 `authProvider` 샌드박스 MVP를 출시한다. 더 강력한 기능 **강제(enforcement)**(child-process + Node 권한 모델), 더 많은 플러그인 종류, 라이브 revocation 피드, 레지스트리는 1.x.

Core는 **zero runtime dependency**를 유지한다 — 샌드박스는 `node:worker_threads` + `node:crypto`(Ed25519 sign/verify는 `node:crypto` 내장) 위에 구축된다. `packages/policy-bundle`은 재사용하지 **않는다**(그것은 대칭 HMAC다 — §2.2 참조).

### 정직한 보안 모델 (먼저 읽을 것)

**`node:worker_threads`는 악성 코드에 대한 보안 샌드박스가 아니다.** worker는 프로세스를 공유하며 파일시스템, 네트워크, `process.env`에 여전히 접근할 수 있다; 격리는 **V8 힙 전용**이다(Node의 권한 모델은 프로세스 전체에 걸쳐 적용되며 worker별로 적용되지 않는다; `SharedArrayBuffer`/transferable은 공유 메모리 채널을 다시 열 수도 있으므로 와이어 형식은 일반 JSON 문자열이다 — §2.3). 따라서 1.0 샌드박스는 다음을 제공한다:

- **메모리 격리** — 별도의 V8 힙; 플러그인은 호스트 메모리, 암호화 키, 토큰 볼트, 감사 싱크를 읽거나 오염시킬 수 없다(타입이 지정된 메시지 채널만이 경계를 넘는다).
- **크래시/행(hang) 격리 + 리소스 제한** — `resourceLimits`(힙 상한) + 각 호출에 **worker를 종료시키는 타임아웃**이 버그가 있거나 폭주하는 플러그인을 억제한다; 행(hang)은 fail-closed(거부)로 처리된다.
- **데이터 최소화** — 호스트는 worker에게 **크리덴셜 슬라이스**(`Authorization` 헤더 / bearer 토큰)만 전송하며, **요청 바디와 암호화 키는 절대 전달하지 않는다**; worker는 **raw 클레임**을 반환하고, **호스트**가 `buildExternalIdentity`를 통해 PII-safe identity를 구축한다(keyed-HMAC 키는 호스트를 벗어나지 않는다).
- **좁고 감사된 타입이 지정된 계약** — worker는 `authProvider` 메시지 프로토콜만 사용하며; 모든 로드/거부/종료 결정이 감사된다(§2.4).

1.0에서 worker 경계가 보장하지 **않는** 것 — 이것들은 **수용된 잔여 위험으로, worker가 아닌 서명/검증 신뢰 모델에 의해서만 게이트된다**(§6):

- **악성 *서명된* 플러그인은 여전히 OS를 사용할 수 있다** — `fetch`, `fs`, `process.env`는 차단되지 않는다. 매니페스트의 `networkEgress: false`는 *선언*이며, 1.0에서 강제된 통제가 아니다.
- **악성 *서명된* auth 플러그인은 합법적으로 수신하는 라이브 크리덴셜을 유출할 수 있다**(bearer 토큰), 사실상 네트워크 egress를 갖기 때문이다. 1.0에는 **기술적 장벽이 없다** — 신뢰 게이트만 있을 뿐이다.

진정한 플러그인별 기능 **강제**(fs/net 차단, 크리덴셜 봉쇄)는 **child-process 격리와 Node 권한 모델**(`--permission --allow-fs-read=…`)이 필요하며, 이는 문서화된 **1.x** 경로다. 이것이 주입이 기본으로 유지되고 신뢰 게이트(비대칭 서명 + 운영자 allowlist + pin + revocation)가 핵심인 이유다.

## 2. 범위

### 2.1 API 안정성 동결 (1.0 계약)

**동결된 공개 표면 (명시적 IN/OUT 테이블이 오늘날의 모호한 "0.x는 preview" 표현을 대체한다).** 모든 `package.json` `exports` 서브패스와 CLI가 분류된다:

| 표면 | 1.0 상태 |
|---|---|
| `haechi` / `haechi/core` (`createRuntime`, `createHaechi().protectJson`, `collectStringEntries`), `haechi/auth` (`authProvider` 계약, `buildExternalIdentity`, `buildIdentity`, `validateLabels`), `haechi/crypto` (`cryptoProvider` 계약, `assertCryptoProviderConformance`, `canonicalize`), `haechi/audit` (이벤트 스키마, `verifyAuditChain`, `sanitizeAudit`, `FORBIDDEN_KEYS`), `haechi/policy`, `haechi/filter` (룰 형태), `haechi/token-vault`, `haechi/runtime` (`normalizeConfig` 형태), `haechi/protocol-adapters`, `haechi/plugin` (매니페스트 + 신규 샌드박스) | **동결** (파괴적 변경 = major) |
| `haechi/proxy`, `haechi/mcp-stdio`, `haechi/stream-filter`, `haechi/policy-bundle`, `haechi/privacy-profiles`, 그리고 **CLI** (`bin/haechi.mjs`) | **동작 + wire/계약 동결**; 사람이 읽는 CLI/로그 **텍스트**는 여전히 변경 가능(계약 대상 아님) |
| `api-stability.md §3`에 아직 실험적으로 표시된 항목 | **졸업**(§3에서 제거)되거나 명시된 이유와 함께 **1.0 이후에도 명시적으로 preview로 유지** — 묵시적 모호함 없음 |

- **1.0부터 엄격한 semver** (파괴적 변경→major, 가산적 변경→minor, 수정→patch). core에 대한 "0.x minor는 파괴적 변경 가능" 여유가 끝난다.
- **지원 중단 정책.** 지원 중단된 export/필드/옵션은 **≥1 minor** 동안 유지되며, 문서화된 마이그레이션 노트와 **안정적인 `code` 접두사 `HAECHI_DEPRECATION_*`**가 있는 일회성 런타임 `process.emitWarning`을 방출하고(code/텍스트 자체도 계약의 일부), **다음 major**에서만 제거된다. **보안 예외(허용된 단 하나의 minor 내 파괴적 변경):** *공개된* 취약점을 닫기 위한 변경은 보안 권고문 + 마이그레이션 경로와 함께 **minor 내에서** 파괴적 변경/제거가 가능하다(기존 "안전하지 않은 config 차단은 패치에서 강화될 수 있다" 여유를 반영).
- **감사 이벤트 스키마 — 중첩 하위 스키마를 포함하여 동결**, 열거됨(최상위 레벨만이 아님): 최상위 `{id, timestamp, protocol, operation, identity, profile, mode, enforced, blocked, payloadShapeHash, detections, summary, auditIntegrity}`; `detections[].{type, ruleId, path, kind, confidence, action, enforced}`; **`identity.{id, type, subjectHash, issuerHash, provider}`**(PII-safe 프로젝션 — `scopes`/`labels`/raw subject는 감사 identity에 **포함되지 않음**); `summary.{byType, byAction, detectionCount}`; `auditIntegrity.{alg, canonicalization, sequence, previousHash, eventHash}`. **새 필드는 가산적으로만 추가되며 기존 필드의 정규화에 절대 영향을 미치지 않으므로**, 1.x 이벤트는 1.0 `verifyAuditChain`으로도 검증된다(이는 `canonicalize`가 리터럴 객체를 해시하고 검증기가 *동일하게 저장된 객체*를 재계산하기 때문에 유효하다 — 보장의 의미는 "미래에 가산적으로 추가된 필드가 새 레코드를 읽는 구버전 검증기를 깨뜨리지 않는다"는 것으로, 이전의 두루뭉술한 표현보다 정확하게 명시됨). 정규화 변경은 새 `canonicalization` 태그 + 리더 마이그레이션 경로와 함께 **major** 이벤트 스키마 bump다. 소비자가 파싱 없이 분기할 수 있도록 명시적 최상위 **`schemaVersion`**을 추가한다(리더 대면; 가산적).
- **Config 스키마 동결 단위:** config **키 존재 + 형태**가 동결됨; **기본값은 여전히 강화될 수 있음**(더 안전한 기본값은 파괴적 변경이 아님). 알 수 없는 키는 여전히 throw(fail-closed).

### 2.1a 위성 호환성 전제 조건 (core 1.0.0 bump 전에 반드시 완료)

네 위성 모두 `"haechi": ">=0.8.0 <1.0.0"`을 pin하고 있다 — 그리고 `<1.0.0`은 `1.0.0`을 **제외한다**(심지어 `1.0.0-rc.x`도). core를 1.0.0으로 bump하면 **모든 위성의 peer dependency를 충족 불가 상태로 만든다**(ERESOLVE / unmet peer). `haechi-auth-oidc`도 크로스-위성 동일 문제가 있다(`"haechi-auth-jwt": ">=0.2.0 <1.0.0"`). 따라서 **PR0**(어떤 core bump보다도 먼저):

- 모든 위성의 peer 범위를 다음 minor가 아닌 core **major**를 추적하도록 확장: `"haechi": ">=0.8.0 <2.0.0"`(동결의 정의상 유효 — ≥0.8로 빌드된 위성은 전체 1.x 라인에서 동작함), 그리고 `haechi-auth-oidc`의 `"haechi-auth-jwt": ">=0.2.0 <2.0.0"`. 네 위성 모두 패치 릴리스(`auth-jwt 0.2.x`, `crypto-kms 0.2.x`, `dashboard 0.1.x`, `auth-oidc 0.1.x`) + lockfile 재생성(workspace-lockfile 규칙 적용).
- `release:preflight` **게이트** 추가: 모든 `satellites/*/package.json` peer 범위를 파싱하여 발행할 core 버전에 대해 `semver.satisfies(coreVersion, range)`를 단언 — 미래의 core major가 위성이 여전히 제외하는 상태에서 출시되는 일을 방지.
- `api-stability.md §5`에 문서화: 위성 peer **상한은 core MAJOR를 추적**하며, 다음 minor 미만으로 pin되지 않는다.

### 2.2 비대칭 서명 플러그인 계약 (Ed25519) + 핀닝 + revocation + 적합성(conformance)

**서명은 비대칭(Ed25519)이며, 대칭 `policy-bundle` HMAC이 아니다.** `policy-bundle`은 로컬 AES 키 파일로 keyed된 HMAC으로 서명한다 — 검증기가 서명하는 것과 동일한 비밀을 보유하므로 "제3자 저자가 서명하고 운영자가 공개 키로 검증한다"는 표현을 할 수 없다. 1.0은 **`node:crypto` Ed25519** 서명 매니페스트 프리미티브를 추가한다(새 의존성 없음): **저자가 Ed25519 개인 키를 보유**; **운영자가 Ed25519 공개 키를 신뢰 앵커(trust anchor)로 allowlist**. (플러그인 서명에 `policy-bundle`을 재사용하지 말 것.)

- **서명 봉투는 경로가 아닌 콘텐츠를 커버한다.** 서명 바이트는 `canonicalize({ pluginId, kind, version, capabilities, coreVersionRange, entrySha256, notBefore, notAfter })` — 즉 서명은 **정확한 엔트리 바이트의 sha256**, **kind**, **선언된 capabilities**, **호환 가능한 core 범위**, **유효 기간**을 바인딩한다. 경로에 서명하거나(`entrySha256`/`kind`/`capabilities`를 생략하는 것)는 교체(swap)/capability 다운그레이드 공격이 되므로 거부된다.
- **신뢰 앵커 전용 키 해석 (kid-by-claim 없음).** 검증 키는 **오직** 운영자의 `trustAnchors` allowlist에서만 해석된다; `manifest.signerKeyId`가 allowlist된 앵커에 없으면 **검증 전에 거부**한다. 알고리즘은 앵커별로 Ed25519로 고정된다(alg 민첩성 없음, HS/RS 혼동 없음). 플러그인 신뢰 앵커 세트는 **별도의 큐레이션된 목록**이며, AES 로테이션 키 파일과 절대 혼용하지 않는다(만료/로테이션된 AES kid가 서명자 앵커가 되어서는 안 됨).
- **핀닝 (악성 업데이트 방지 / 롤백 방지).** 운영자 config `plugin.pin = { version?, entrySha256?, manifestSha256? }`: 로더는 로드된 매니페스트 버전/엔트리 해시가 pin과 일치하지 않으면 fail-closed. **`pluginId`별 버전 플로어**는 이전 서명된 아티팩트로의 롤백을 거부한다. 따라서 *신뢰된 서명자*도 pin/플로어를 트리거하지 않고는 동일 앵커 하에 새(또는 구버전 취약한) 엔트리를 조용히 출시할 수 없다.
- **Revocation + 최신성.** 운영자 denylist `plugin.revokedSignerKeyIds` + `plugin.revokedEntrySha256`은 로드 시 확인됨(fail-closed: 취소된 서명자 또는 해시는 절대 로드되지 않음). 서명된 `notBefore`/`notAfter` 기간은 로드 시 강제됨. **메모리 내 revocation 동작 (1.0, 솔직하게 명시):** revocation은 **다음 로드/재시작 시**에 적용된다; **전역 kill-switch** (`plugins.enabled: false` 및 플러그인별 disable)로 운영자가 **라이브 플러그인을 즉시 강제 제거**할 수 있다. 라이브 CRL/피드는 1.x.
- **매 재시작(respawn)마다 재검증.** worker는 타임아웃-종료 후 지연 재시작되므로, **전체 게이트(서명 + 앵커 + pin + revocation + capability allowlist)가 최초 생성뿐 아니라 매 spawn마다 재실행**된다.
- **Capability allowlist (운영자 측).** `plugins.allowCapabilities`; 그 밖의 capability를 요청하는 매니페스트는 거부됨. `readsCredentials`는 `kind: authProvider`에서 **필수**다(bearer 토큰을 봄). `networkEgress`/`readsPlaintext`는 1.0에서 **선언되고 감사되지만 worker에 의해 강제되지 않는다**(§1 잔여 — 노출됨, 신뢰됨 아님).
- **적합성(conformance)은 정확성 게이트이지 악의 스크린이 아니다.** `assertAuthProviderConformance(provider, { now, vectors })`는 **샌드박스된** 플러그인을 열거된 보안 동작으로 실행한다: 크리덴셜 없음 → `null`; 형식 불량 크리덴셜 → `null`; 만료/아직 유효하지 않음(`now`를 통해 주입된 시각) → `null`; 내부 **throw는 호출자에게 `null`로 표면화**(절대 전파하지 않음); 반환된 identity는 반드시 `subjectHash`/`issuerHash`를 가져야 하며 raw 입력 subject/issuer와 동일한 필드를 **포함해서는 안 된다**(PII 안전성); 거부는 동일 입력에 대해 **결정론적**; 유효 크리덴셜 → 올바르게 형성된 PII-safe identity. 로더는 **이에 실패하는 플러그인의 연결을 거부한다**. 그러나 서명된 플러그인은 고정된 테스트를 감지하고 동작을 바꿀 수 있으므로: 적합성은 **로드마다 예측 불가능한 무작위 벡터**를 사용하며, — 핵심 — **호스트는 매 호출마다 PII 안전성을 재검증**한다(`buildExternalIdentity` + 아래 sanitizer가 요청별로 실행됨, 로드 시에만이 아님). **적합성 통과가 신뢰성을 의미하지 않는다**(그것은 서명+검증 게이트다); 테스트/프로덕션 분기는 수용된 잔여 위험이다(§6).

### 2.3 `worker-isolated` `authProvider` 샌드박스 (MVP)

`createSandboxedAuthProvider({ manifestPath, trustAnchors, allowCapabilities, pin, revoked, cryptoProvider, auditSink, timeoutMs, maxPendingCalls, maxMessageBytes, resourceLimits, now })`는 동결된 계약을 만족하는 **호스트 측 `authProvider`**를 반환한다 — 따라서 **기존** 주입 심(seam)과 새 `auth.provider: "plugin"` config 경로를 통해 연결된다.

- **로드 시퀀스 (모든 단계에서 fail-closed, 각 단계 감사됨):** 매니페스트 검증(`worker-isolated` + `kind: authProvider`) → `signerKeyId`를 **`trustAnchors`에서만** 앵커 해석(아니면 거부) → **엔트리 바이트를 메모리로 읽어** sha256하고 **`entrySha256`을 포함하는 정규 봉투에 대해 Ed25519 서명 검증** → `notBefore/notAfter`, revocation denylist, pin/version-floor, capabilities ⊆ allowlist 확인 → **검증된 인메모리 소스에서** Worker를 spawn(`new Worker(code, { eval: true, resourceLimits, workerData: <비밀 없음> })`), **검증 후 경로를 재해석하지 않음**(TOCTOU 없음; symlink된 엔트리 거부) → 샌드박스된 provider에 대해 `assertAuthProviderConformance` 실행 → 그 이후에만 라이브 provider 반환. 실패 시 생성에서 throw하고 `plugin.load.refused{reason}`을 방출함(§2.4).
- **요청별 프로토콜 (데이터 최소화, correlation-id 적용):** `authenticate(request)`는 **크리덴셜 슬라이스**(`Authorization` 헤더/토큰 — 바디 절대 아님)만 추출하고, **고유한 correlation id**로 래핑하여 **MessagePort를 통해 JSON 문자열**로 post한다(structured-clone 객체 없음, `SharedArrayBuffer`/transferable 없음 → 공유 메모리 또는 객체 그래프 밀수 없음). `maxMessageBytes`가 와이어를 제한한다. worker는 크리덴셜을 검증하고(JWKS egress는 auth 플러그인에 고유) **raw 클레임** `{ subject, issuer, type, scopes, labels }` 또는 거부를 반환한다.
- **호스트 측 클레임 sanitizer (`buildExternalIdentity` 전에):** JSON 응답은 **null-prototype 객체**로 파싱된다(`JSON.parse` + `Object.create(null)`로 재구성); **고정된 own-enumerable 키 allowlist**만 허용됨; `__proto__`/`constructor`/`prototype` 제거됨; 배열 크기와 전체 identity 크기 제한됨; 모든 값은 경계에서 타입 검증/강제됨. 이후 **호스트**가 PII-safe identity를 구축한다(`buildExternalIdentity({ provider: "plugin:<pluginId>", subject, issuer, type, scopes, labels }, cryptoProvider)`) — keyed-HMAC 키는 worker에 진입하지 않으며, 적대적 클레임 객체가 prototype을 오염시키거나 raw 값을 밀수할 수 없다.
- **동시성 모델 (호출자 간 누출 없음 / 종료 경쟁 없음):** 각 in-flight 호출은 **correlation id**로 응답과 매칭됨; 일치하지 않는/중복된/늦은 응답은 **삭제됨**. worker는 **단일 점유(single-occupancy)**(하나의 in-flight 호출) — 따라서 호출별 타임아웃-종료는 *형제* 호출을 절대 죽이지 않음; 대기 호출 **상한(`maxPendingCalls`)**이 동시성을 제한함(초과 → 거부). 종료 후 재시작은 **single-flight**으로 보호됨. 플러그인은 **호출 간 무상태(stateless)**여야 하며; 잔여 크로스-요청 상태 위험은 §6 잔여다.
- **타임아웃 + 리소스 제한 (fail-closed):** 각 호출은 `timeoutMs`(필수 양의 정수 — 무한 기본값 없음)로 제한됨; 타임아웃 시 호스트는 worker를 **종료**(`plugin.worker.terminated{cause: timeout}`)하고 `null`을 반환하며 지연 재시작함(전체 게이트 재실행). `resourceLimits`가 힙을 제한함. (CPU/fd/소켓은 1.0에서 제한되지 않음 — §6 잔여.)
- **Config (`auth.provider: "plugin"`) — 열거형 fail-closed `normalizeConfig` 규칙** (`keys`/`tokenVault` 엄격함과 일치): `plugin.manifestPath`(비어 있지 않은 로컬 경로) 필수; `plugin.trustAnchors` 비어 있지 않은 `{ keyId: string, publicKey: string (Ed25519) }` 배열; `plugin.allowCapabilities` `CAPABILITY_KEYS ∪ {readsCredentials}` 부분집합인 배열(알 수 없는 것 거부); `kind: authProvider`에 `readsCredentials` 존재; `plugin.timeoutMs` 양의 정수; `resourceLimits.maxOldGenerationSizeMb` 양의 정수; 선택적 `plugin.pin`/`plugin.revoked*`/version-floor 올바르게 형성됨; `plugins.enabled` 준수(kill-switch). 모든 위반은 로드 시 throw. `createRuntime`은 호스트 측 identity 구축을 위해 주입된 `cryptoProvider`를 여전히 필요로 한다.

### 2.4 플러그인 라이프사이클 감사 (보안 제품은 서드파티 코드 로딩을 반드시 기록해야 함)

기존 해시-체인 `auditSink`를 재사용하여(`recordProxyDecision`/`auth_denied`가 이미 사용하는 동일 심), 샌드박스는 **PII-safe** 이벤트를 방출한다 — id/해시/카운트만:

- `plugin.load.accepted` `{ pluginId, version, entrySha256, signerKeyId, capabilitiesGranted }`
- `plugin.load.refused` `{ reason ∈ missing-signature | unknown-signer | tampered-entry | revoked | below-version-floor | pin-mismatch | expired-window | capability-not-allowlisted | conformance-failed | manifest-invalid, pluginId?, signerKeyId? }`
- `plugin.authenticate.deny` `{ pluginId, reason ∈ invalid-claims | throw | non-pii-safe-identity | timeout }`
- `plugin.worker.terminated` `{ pluginId, cause ∈ timeout | oom | crash }`

`FORBIDDEN_KEYS`는 플러그인/클레임 표면(`claims`, `subject`, `issuer`, `credential`, `authorization`, `signature`, `entry`)으로 **확장**된다 — 심층 방어로서, 미래의 플러그인 이벤트가 raw 클레임/토큰/서명자 비밀을 체인 로그에 절대 누출하지 못하도록(위의 이벤트는 이미 id/해시만 운반함). 테스트는 거부된 로드와 worker 타임아웃이 각각 정확히 하나의 체인 이벤트를 방출함을 단언하고, raw 클레임이 있는 합성 플러그인 이벤트가 `sanitizeAudit`에 의해 제거됨을 단언한다.

### 2.5 실제 환경 검증 종료 기준

- **충족됨:** 2026-06-11 실제 자체 호스팅 vLLM + Ollama([[2026-06-11-real-environment-validation]]) + `haechi-dashboard` 관측가능성에 대한 라이브 검증.
- **잔여 (문서화됨, 1.0 게이팅 아님):** (1) **라이브 KMS 백엔드 검증** (실제 AWS/GCP/Azure/Vault)은 CI 밖; (2) **worker 플러그인 샌드박스 자체는 실제 적대적 플러그인에 대해 미검증** — 보안은 신뢰 게이트 + §6 잔여에 기반하며, fail-closed/데이터 최소화 테스트로 검증됨(적대적 서드파티 플러그인 레드팀이 아닌 — 이상적으로는 child-process+permission 강제와 함께 1.x 과제).

## 3. 명시적 비범위 (1.x로 연기)

- 악성 서명된 플러그인에 대한 **Capability *강제*** (fs/net 차단, 크리덴셜 봉쇄) — child-process 격리와 Node 권한 모델이 필요.
- **Classifier/filter 및 crypto 플러그인 로딩** — 1.0에서는 `authProvider`만.
- **라이브 revocation 피드 / CRL**, 플러그인 **레지스트리 / 마켓플레이스**, multi-origin, 핫 리로드, **미서명 dev 로더** (신뢰 게이트를 훼손하게 됨 — 개발은 주입을 사용).
- **Python SDK.**

## 4. 하위 호환 & 1.0 안정성 계약

기존 동작은 **불변** — 모든 provider 계약, config와 (이제 중첩 열거된) 감사 스키마, zero-dependency 자세가 0.9와 정확히 동일하다; 이것들이 **동결로 선언된다**. 플러그인 샌드박스는 **순수 가산적이며 opt-in**이다(`auth.provider: "plugin"`; 기본값은 `none`/`bearer`/`external`로 유지). 하나의 동작적 core 변경은 **가산적 `FORBIDDEN_KEYS` 확장**(§2.4)과 **`schemaVersion`** 필드(가산적)다. **위성 peer 범위 확장(§2.1a)은 전제 조건**으로, 네 위성이 core 1.0.0에 대해 설치를 유지하도록 한다.

## 5. 1.0 관계 / 1.0이 닫는 것

1.0은 두 오랜 1.0 게이트를 닫는다 — **API 안정성 동결**(§2.1)과 **플러그인 샌드박스 + 동적 로딩 스토리**(§2.2–2.4: 비대칭 서명 + 격리 + 감사 + auth 전용) — 그리고 **실제 환경 검증** 종료 기준이 문서화된 잔여와 함께 충족됨을 기록한다(§2.5). Haechi를 개발자 preview에서 안정적인 자체 호스팅 보안 게이트웨이로 졸업시키면서 core 약속을 유지한다: 작고 zero-dependency인 core, 모든 곳에서 fail-closed, "컴포넌트를 교체해도 동일한 보안 테스트가 통과된다."

## 6. 위협 모델 & 리스크 레지스터 델타 (구체적)

| 신규 표면 (1.0) | 통제 | 잔여 |
|---|---|---|
| **악성/손상된 서명된 플러그인** 동적 로딩 | `entrySha256`+kind+capabilities에 대한 Ed25519 서명, 신뢰 앵커 전용 키 해석, pin + version-floor + revocation denylist, conformance 게이트, worker 메모리/크래시 격리, 전체 라이프사이클 감사 | **서명된 플러그인 자체의 fs/net/`process.env`는 차단되지 않으며, 수신하는 크리덴셜을 유출할 수 있다** — 서명/검증 신뢰 모델에 의해서만 게이트됨; 진정한 강제는 1.x child-process+permission 경로 |
| **플러그인으로의 PII/비밀 누출** | 크리덴셜 슬라이스만 전달됨(바디/키 절대 아님); JSON-string 와이어; null-proto sanitizer; 호스트가 keyed-HMAC identity 구축 | auth 플러그인이 합법적으로 검증하는 크리덴셜은 그것에 가시적임(위 행 참조) |
| **경계 간 객체/proto 밀수** | JSON-string 와이어(structured clone / SAB / transferable 없음) + `buildExternalIdentity` 전 null-proto allowlist sanitizer | 실질적 잔여 없음 |
| **엔트리 교체 / TOCTOU** | `entrySha256` 서명; 인메모리 읽기 + 해시 + 검증 + 인메모리 소스에서 spawn; 경로 재해석 없음; symlink 거부 | 실질적 잔여 없음 |
| **서명자 키 혼동 / 다운그레이드 / 롤백 / 악성 업데이트** | 신뢰 앵커 전용 해석, 알고리즘 고정, pin/version-floor, revocation | 운영자가 앵커/pin을 큐레이션해야 함 |
| **플러그인 DoS** | 호출별 `timeoutMs` 종료, 힙 `resourceLimits`, `maxPendingCalls`, `maxMessageBytes`, 단일 점유 worker | 서명된 플러그인이 타임아웃 내 할당된 CPU를 소진할 수 있음(CPU/fd는 1.0에서 제한되지 않음) |
| **미감사 코드 로드** | `plugin.load.*` / `authenticate.deny` / `worker.terminated` 감사 이벤트; 확장된 `FORBIDDEN_KEYS` | — |
| **적합성 테스트/프로덕션 분기** | 로드마다 무작위화된 벡터 + 호출별 호스트 PII 안전성 재검증 | 악성 플러그인이 적합성을 통과한 후 오동작 가능(서명+검증으로 커버되며 적합성으로 아님) |
| **API/감사 스키마 드리프트** | 엄격한 semver + 지원 중단 기간(+ 보안 예외) + 가산적 전용 중첩 열거 감사 스키마 + `schemaVersion` | major bump는 설계상 파괴적 변경 가능(문서화된 마이그레이션) |

제안 리스크 ID: **P1-SEC-010**(동적 플러그인 실행 / 샌드박스 신뢰 모델 — P1-SEC-004의 매니페스트 전용 입장을 새 통제 하에 수퍼세드, 해제됨), **P1-SEC-011**(플러그인 서명/신뢰 앵커/revocation 라이프사이클), **P2-API-001**(안정적 계약 동결 + 지원 중단 정책), **P2-OPS-006**(위성 peer 범위 / major 추적 게이트). 신규 §4 제외: 악성 서명된 플러그인에 대한 capability 강제, 크리덴셜 봉쇄, classifier/crypto 플러그인 로딩, 미서명 dev 로더, 라이브 CRL.

## 7. 테스트 기준 (PR 분해에 매핑)

### 7.1 PR0 — 위성 peer 범위 확장 + preflight 게이트

- 네 위성의 `haechi` peer 범위가 `>=0.8.0 <2.0.0`으로 확장됨(그리고 auth-oidc의 `haechi-auth-jwt`는 `<2.0.0`); lockfile 재생성; `release:preflight`가 위성의 범위가 `!semver.satisfies(coreVersionToPublish, satelliteRange)`이면 실패. 테스트가 core `1.0.0`을 시뮬레이션하고 모든 위성 범위가 충족됨을 단언.

### 7.2 PR1 — API 안정성 동결 (문서 + 계약 테스트)

- `api-stability.md`(+ko)가 IN/OUT 테이블, 엄격한 semver + 지원 중단 정책(`HAECHI_DEPRECATION_*` 런타임 경고 계약 및 보안 예외 포함), 위성 major 추적 규칙을 담음.
- **계약/스냅샷 테스트**가 서브패스별 동결된 export + **non-null `identity`와 하나의 `detections[]` 항목을 포함하는 전체 감사 이벤트**(중첩 하위 스키마가 최상위 레벨만이 아닌 것으로 보호됨) + config 스키마 키 세트 + `schemaVersion`을 pin함. 가산적 필드는 통과; 제거/이름 변경된 필드(최상위 또는 중첩)는 실패. `verifyAuditChain`이 동결 스키마 픽스처를 검증하고 합성 가산 필드가 있어도 여전히 검증함.

### 7.3 PR2 — Ed25519 서명 플러그인 계약 + 핀닝/revocation + 적합성 하네스

- `packages/plugin`이 Ed25519 봉투와 함께 `worker-isolated`+`authProvider` 매니페스트를 수락; **거부**(각각 `plugin.load.refused{reason}`를 방출하는 별개의 fail-closed 테스트): 누락/무효 서명; `trustAnchors`에 없는 서명자(kid-not-allowlisted, **검증 전**에 해석됨); **서명 후 엔트리 바이트 변조, 경로 변경 없음**; revoked 서명자 / revoked entryHash; version-floor 미달; pin 불일치; `notBefore/notAfter` 외부; capability allowlist에 없음; alg ≠ Ed25519.
- `assertAuthProviderConformance` 존재; 참조 provider 통과; 깨진 것(throw / raw-subject identity 반환 / 만료 크리덴셜 수락 / 비결정론적)이 각 경우마다 **실패**(네거티브 테스트). 벡터는 실행마다 무작위화됨.
- `FORBIDDEN_KEYS` 확장 테스트: `claims`/`credential`/`signature`가 있는 합성 플러그인 이벤트가 `sanitizeAudit`에 의해 제거됨; 체인이 유효한 상태로 유지됨.

### 7.4 PR3 — `worker-isolated` authProvider 샌드박스

- 참조 **서명된** auth 플러그인이 로드되어 worker 내에서 적합성 통과, 유효 bearer/JWT를 **호스트가 구축한 PII-safe identity**로 인증함; 단언: worker는 **크리덴셜 슬라이스만** 수신함(계측된 echo-plugin이 바디/감사 싱크/토큰 볼트/키를 절대 받지 못했음을 증명), raw subject가 감사에 나타나지 않음, `plugin.load.accepted`가 해석된 `entrySha256`/`signerKeyId`와 함께 방출됨.
- **Fail-closed + 격리 매트릭스:** 미서명/잘못된 서명자/변조/revoked/pin 불일치/capability-not-allowlisted → 생성 throw + `load.refused`; **타임아웃 → `null` + worker 종료 + `worker.terminated{timeout}`**; throw → `null`; `__proto__`/추가 키가 있는 클레임 객체 → sanitize됨(prototype 오염 없음, 추가 키 제거됨) 및 PII-safe; 별개의 correlation id를 가진 두 동시 호출이 절대 응답을 교차하지 않음; 하나의 호출 종료가 형제를 죽이지 않음(단일 점유); `maxPendingCalls`/`maxMessageBytes` 강제됨; `plugins.enabled:false`(kill-switch)가 로드를 거부함.
- `normalizeConfig` `auth.provider:"plugin"` 열거형 fail-closed 테스트(각 잘못된 옵션이 throw); `createRuntime` + proxy auth 게이트를 통한 end-to-end(요청이 플러그인을 통해 인증됨; identity keyed-HMAC; 감사에 raw subject/크리덴셜 없음).

### 7.5 전체

- Core가 zero runtime dependency를 유지함(`node:`만 — Ed25519는 `node:crypto`); `check:packaging` + `check:satellite-packaging` 통과; 동결된 계약 스냅샷 테스트 + peer 범위 preflight 게이트가 미래 PR을 보호함.

## 8. 제안 PR 분해 (스택)

1. **PR0 — 위성 peer 범위 확장 + preflight 게이트** (전제 조건; 네 위성 패치 릴리스). → §7.1
2. **API 동결** — `api-stability.md`(+ko) IN/OUT 테이블 + 지원 중단/보안 예외 정책 + 중첩 스키마 계약/스냅샷 테스트 + `schemaVersion`. → §7.2
3. **Ed25519 서명 플러그인 계약 + 적합성** — 비대칭 프리미티브(`node:crypto`), 서명 봉투(entryHash/kind/capabilities/기간), 신뢰 앵커 전용 해석, pin/version-floor/revocation, `assertAuthProviderConformance`, `FORBIDDEN_KEYS` 확장. → §7.3
4. **Worker 격리 authProvider 샌드박스** — `createSandboxedAuthProvider`(인메모리 검증 spawn, JSON-string 와이어, null-proto sanitizer, correlation-id 단일 점유 동시성, 타임아웃/종료, kill-switch), `auth.provider:"plugin"` config 분기 + 라이프사이클 감사, 참조 서명된 플러그인 + §7.4 매트릭스. → §7.4
5. **1.0.0 릴리스 컷** — core를 **1.0.0**으로 bump; docs EN/KO (이 범위 문서, 위협 모델 + §6 ID + 목표 버전 bump와 함께 리스크 레지스터 델타, 실제 환경 종료 기준 + 잔여); wiki ingest(`[[plugin-sandbox]]` 페이지 + `[[packaging-and-distribution]]`/`[[identity-and-auth]]`/`release-roadmap` 업데이트); README "Current Scope". Core는 `v*` 태그를 재사용; 첫 번째 안정 `haechi@1.0.0`이 증명(attested)과 함께 발행됨. (PR0이 이미 머지되고 위성이 재발행되어 1.0.0에 대해 설치 가능해야 함.)
