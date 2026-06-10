# Haechi 0.8 구현 범위

- 상태: Draft 0.3 (설계 — 아직 미구현)
- 작성일: 2026-06-10
- 대상 버전: 0.8.0 (0.7.0 이후)
- 유형: 에코시스템 기반

## 1. 릴리스 목표

`@haechi/*` 패키지 에코시스템을 띄운다: 저장소를 npm workspaces 모노레포로 전환하고, npm org를 만들고, 첫 두 satellite를 배포한다 — `@haechi/crypto-kms`(0.7 reference 승격)와 `@haechi/auth-jwt`(JWKS bearer 검증). 이로써 운영 키 custody를 설치 가능한 패키지로 실현하고, core의 zero-dependency 자세를 건드리지 않으면서 auth 에코시스템을 키운다.

**범위 결정(2026-06-10):** 0.8은 **패키징 기반 + satellite**다. `@haechi/dashboard` 읽기 전용 audit 뷰어(UI 빌드)와 완전한 대화형 `@haechi/auth-oidc`는 **0.9**로 이동하여, 0.8은 코드가 가볍고 모노레포 + 두 개의 헤드리스 친화적 어댑터에 집중한다.

Core(`haechi`, unscoped)는 **zero runtime dependency**를 유지한다. satellite 의존성(예: AWS SDK)은 해당 satellite의 `package.json`에만 존재하며 core의 tarball이나 SBOM에 절대 들어가지 않는다.

## 2. 범위

### 2.1 npm workspaces 모노레포 (검증된 resolution 메커니즘)

순진한 레이아웃(`"workspaces": ["satellites/*"]` + satellite peer 범위 `"haechi": ">=0.8.0"`)은 **동작하지 않으며** 경험적 테스트 후 기각했다: npm은 충족되지 않은 peer 범위를 레지스트리 조회로 취급하고(`ETARGET: no matching version for haechi@>=0.8.0`), 루트 프로젝트를 `node_modules/haechi`로 심링크하지 않으며, satellite의 `import "haechi/crypto"`가 `ERR_MODULE_NOT_FOUND`로 던진다. 루트 프로젝트는 기본적으로 workspace 멤버가 **아니므로** npm이 절대 링크하지 않는다.

검증된 동작 레이아웃:

- **루트가 자기 자신을 workspace 멤버로 등록한다:** `"workspaces": [".", "satellites/*"]`. `"."` 항목이 npm으로 하여금 `node_modules/haechi → ..` 심링크를 만들게 해 satellite가 core를 resolve한다. 이게 없으면 satellite는 레지스트리로 fallback한다.
- **저장소 루트는 배포되는 `haechi` 패키지로 그대로 남는다** — `exports`, `bin`, `files` 허용목록은 변하지 않는다. `package.json` 변경은 추가된 `workspaces` 필드와 버전 bump뿐이다. satellite는 core의 `files`에 없으므로 `haechi` tarball 안으로 절대 실리지 않는다(검증됨: 루트 `npm pack --dry-run`은 `files` 허용목록만 나열하고 `satellites/`는 제외된다).
- **satellite는 core에 대한 이중 의존성을 선언한다:**
  - `"peerDependencies": { "haechi": ">=0.8.0 <1.0.0" }` — *소비자*가 설치할 때의 계약. satellite는 소비자의 단일 `haechi` 인스턴스를 재사용한다(crypto/identity 표면 하나, 중복 사본 없음).
  - `"devDependencies": { "haechi": "*" }` — 모노레포 개발/CI 중에 npm이 peer 범위를 레지스트리에서 resolve하지 않고 **로컬 workspace**를 링크하게 만드는 메커니즘. `npm pack`은 배포 tarball에서 devDependencies를 제거하므로 소비자 매니페스트에는 peer 범위만 남고 `*` devDep은 다운스트림에서 보이지 않는다. (`satellites/*/package.json`을 읽는 저장소/소스 스캐너는 여전히 그것을 본다. 이 source-vs-artifact 차이는 예상된 것이고 무해하다.)
  - **소비자 peer-mismatch 동작:** 배포된 satellite를 *비호환* `haechi`(예: 이미 설치된 `haechi@0.7.0`)에 설치하면 hard failure가 아니라 npm `ERESOLVE` **경고**가 난다; 소비자는 `haechi`를 올리거나(자기 책임으로 `--legacy-peer-deps`) 해야 한다. satellite는 범위를 벗어난 core에서 올바르게 동작하지 않는다.
- satellite는 core를 subpath로 import한다(`haechi/crypto`, `haechi/auth`, `haechi/runtime`). 개발 중에는 workspace 심링크로, 프로덕션에서는 소비자가 설치한 `haechi`로 resolve된다.
- `examples/crypto-kms-reference/`는 `satellites/crypto-kms/`로 **승격**한다. reference 예제는 workspaces 이전에 중첩 `package.json`이 `haechi/crypto`를 self-resolve하지 못해 `canonicalize`를 인라인했었다; **workspaces 하에서는 그 import가 resolve되므로** satellite는 사본을 들고 다니지 않고 `haechi/crypto`에서 `canonicalize`를 import한다(core와 satellite 간 AAD 정규화 drift 방지). 기존 `examples/` 디렉터리는 배포된 패키지를 가리키는 짧은 README만 남긴다. conformance 테스트가 satellite의 AAD 정규화가 `haechi/crypto`와 **byte-for-byte 동일**함을 검증한다(의미적 동등이 아니라).
- **lock 파일:** workspaces 전환은 `package-lock.json`을 workspace-resolve된 항목(루트 자기 멤버 포함)으로 재생성한다. 재생성된 lock 파일을 커밋한다; CI는 `npm ci`(stale/누락 lock이면 실패)를 쓰므로, 전환 PR이 새 lock을 커밋해야 한다.

**CI 전략(중복 실행 방지):** 루트 CI는 루트에서 `node --test`를 직접 돌리며, 이는 `satellites/**/*.test.mjs`를 자동 발견한다(workspace 심링크 덕에 그들의 `haechi/*` import가 resolve됨). CI는 `npm test --workspaces`를 **쓰지 않는다**(루트 자기 멤버로 재귀해 스위트를 다시 돌릴 것이다). 각 satellite는 로컬 단독 실행용(`npm test -w @haechi/crypto-kms`) 자체 `test` 스크립트만 유지한다. 검증됨: 루트 `node --test`가 core + satellite 테스트를 한 번 실행하고, `node_modules/haechi → ..` 심링크 순환에도 runner가 hang하지 않는다(node는 `node_modules`를 건너뜀).

**정직한 패키징 노트(기존 "byte-stable" 주장 대체):** 루트 tarball은 0.7.0과 byte-identical이 **아니다** — `package.json`이 `workspaces` 필드를 얻고 버전이 bump되며, 이는 어떤 릴리스에서도 예상되는 일이다. 방어 가능하고 테스트된 더 좁은 주장이며 CI 게이트(§6.1)로 강제한다: **(a) satellite 파일이 `haechi` tarball에 나타나지 않고, (b) `haechi` tarball 자체의 `package.json`이 runtime `dependencies`를 0으로 선언한다.** 게이트는 **패킹된 매니페스트**를 검사한다(`npm pack` 출력에서 `package.json`을 추출해 `dependencies`가 비어있음/undefined임을 단언) — 오늘은 공허하게 통과하고 미래의 runtime-dep 누수를 놓칠 설치된 `node_modules` SBOM이 아니라.

### 2.2 npm org `@haechi/*` + 패키지별 trusted publishing

- npm org **`@haechi`**를 만든다(네임스페이스 방어도 겸함).
- 각 satellite는 0.7에서 증명한 **동일한 OIDC trusted-publishing + sigstore + SHA256SUMS** 경로로 배포한다 — 자체 npmjs.com Trusted Publisher 링크와 태그 트리거 배포 워크플로.
- **satellite `package.json` 요구사항(루트에서 상속 안 됨):** 각 satellite는 자체 `"publishConfig": { "access": "public", "provenance": true }`를 설정해야 한다 — scoped 패키지는 기본이 restricted access이고, workspace 멤버는 루트의 `publishConfig`를 상속하지 않는다. 누락하면 의도치 않은 private 배포 위험이 있다. 배포 후 런북은 `npm view @haechi/<pkg> access`가 `public`을 보고하는지 검증한다.
- **태그 네임스페이싱 + 워크플로 가드(오트리거·충돌 방지):**
  - core 릴리스 태그: `v<semver>`(예: `v0.8.0`). 루트 배포 워크플로는 `push: tags: ['v[0-9]*.[0-9]*.[0-9]*']`에서 트리거된다. GitHub 태그 glob은 `.`을 리터럴로, `[0-9]*`를 느슨하게 취급하므로(`v1.2.3.4`나 `v1a.2.3`도 매칭됨), 워크플로는 pre-publish 단계에서 엄격한 `^v[0-9]+\.[0-9]+\.[0-9]+$` 정규식으로 **재검증**하고 불일치 시 fail-closed한다.
  - satellite 태그는 **접두사**가 붙는다: `crypto-kms-v<semver>`, `auth-jwt-v<semver>`. 각 satellite 워크플로는 자기 접두사 glob에서만 트리거되고 마찬가지로 `^<prefix>-v[0-9]+\.[0-9]+\.[0-9]+$`로 재검증한다.
  - 각 워크플로는 배포할 패키지 디렉터리를 재확인한다(`npm publish -w <dir>`)므로 잘못 태깅된 push가 엉뚱한 패키지를 배포할 수 없다. npmjs.com의 Trusted Publisher는 **특정 워크플로 파일명**에 바인딩된다 — npm 설정 갱신 없이 워크플로를 rename하면 OIDC auth가 깨진다(런북에 패키지→워크플로-파일명→태그-glob 매핑 표와 함께 실패 모드로 문서화).
- satellite별 **독립 semver**(satellite patch가 core를 bump하지 않음). satellite는 `0.1.0`에서 시작한다. **pre-1.0 계약:** satellite는 표준 npm semver를 따르며 `0.x` **minor** bump가 breaking change를 담을 수 있다; 소비자는 `major.minor`로 핀해야 한다(예: `@haechi/crypto-kms@~0.1`). satellite는 자체 `1.0.0`까지 pre-stable이다.
- **첫 배포 부트스트랩(chicken-and-egg):** satellite별 순서 — (1) `@haechi` org 생성/소유; (2) npmjs.com에서 org 내 패키지 이름 **예약**(버전 배포 없이 네임스페이스 확보); (3) repo + 정확한 워크플로 파일명을 예약된 이름에 연결하는 Trusted Publisher **설정**; (4) satellite 첫 태그 push → 워크플로의 OIDC 배포가 provenance와 함께 `0.1.0` 생성. 노트북에서의 수동 `npm publish`는 필요 없다(0.7 trusted-publishing 자세와 동일). (2)·(3)단계는 (1)의 org-owner 권한이 필요하다.

### 2.3 `@haechi/crypto-kms` (배포 + 실제 KMS 클라이언트)

- 0.7 reference(`createKmsCryptoProvider` envelope 암호화 + `createInMemoryKms`)를 배포 패키지로 승격하며, 인라인 `canonicalize`를 `import { canonicalize } from "haechi/crypto"`(§2.1)로 전환한다. 기존 `kms` 클라이언트 인터페이스(`keyId`/`wrap`/`unwrap`/`deriveHmacKey`)는 **변경하지 않으므로** 승격된 provider와 in-memory 클라이언트는 byte-for-byte 동일하고 0.7 테스트가 그대로 넘어온다.
- **실제 AWS KMS 클라이언트**를 `@haechi/crypto-kms/aws`에 추가한다: `createAwsKmsClient({ keyId, region, client, hmacRootCiphertext })`. 동일한 `kms` 인터페이스를 구현한다: `wrap` = CSPRNG로 생성한 32바이트 data key를 KMS `Encrypt`, `unwrap` = KMS `Decrypt`(envelope 암호화 — master key는 KMS를 떠나지 않음); `deriveHmacKey(domain)` = 단일 KMS-`Decrypt`된 32바이트 root(`hmacRootCiphertext`, 캐시)에 대한 **HKDF-SHA256**, domain-separated — 결정적이고 토큰당 네트워크 호출 없음. `hmacRootCiphertext`가 없으면 `deriveHmacKey`는 throw하고 provider는 encrypt-only가 된다(`requireHmac:false`로 유효).
- **`@aws-sdk/client-kms`는 hard dependency가 아니라 OPTIONAL peer dependency다**(2026-06-10 결정, 기존 "satellite 자체 의존성" 표현을 수정). `client` 미주입 시에만 **lazy import**되므로: 모노레포 `npm ci`/CI는 (대용량) AWS SDK를 절대 받지 않고; in-memory 또는 주입형 클라이언트를 쓰는 소비자는 설치하지 않으며; core는 자명하게 영향받지 않는다. 배포 satellite는 `peerDependencies` + `peerDependenciesMeta.optional`로 선언한다. 이로써 실제 백엔드를 제공하면서도 satellite를 의존성 가볍게 유지한다.
- satellite CI는 in-memory 클라이언트 **그리고** KMS `encrypt`/`decrypt` ops의 **주입된 mock**(SDK·네트워크 없음)으로 구동되는 AWS 클라이언트에 대해 `assertCryptoProviderConformance`(workspace 심링크로 `haechi/crypto`에서 import)를 실행한다. mock은 충실한 envelope(per-mock master key의 AES-256-GCM)여야 한다: `Decrypt`는 이 키가 wrap한 blob에 대해서만 plaintext를 반환하고, 다른 키가 wrap한 blob(cross-key 격리)과 손상된 blob은 **거부**한다. 항상 성공하는 trivial stub은 불충분하며 스위트가 이 거부 경로와 HMAC 결정성/domain-separation을 실행한다. sandbox KMS 키에 대한 실제 `createAwsKmsClient` 검증은 **CI 밖 통합 테스트**다(문서화, 게이팅 아님).

### 2.4 `@haechi/auth-jwt` (JWKS bearer 검증, 의존성 최소)

`createJwtAuthProvider({ issuer, audience, jwksUri, cryptoProvider, algorithms, clockSkewSeconds, claimMappings })`는 **헤드리스** 게이트웨이를 위한 `authProvider` 계약을 구현한다. `node:` 빌트인만으로 구현 가능하다(`jose` 없음): JWKS는 전역 `fetch`로, JWK→키는 `crypto.createPublicKey({ key: jwk, format: "jwk" })`, 서명은 `crypto.verify`로 검증한다.

**구현 노트 — ES256 서명 인코딩(검증됨):** JWS ES256 서명은 raw `R‖S`(IEEE-P1363, P-256은 64바이트)이지만, `node:crypto.verify`는 EC 키에 대해 기본이 **DER**이고 raw 서명에 `false`를 반환한다 — 유효한 ES256 토큰을 전부 조용히 거부한다. 검증기는 EC 알고리즘에 대해 반드시 `dsaEncoding: "ieee-p1363"`을 넘겨야 한다. (경험적 확인: 기본 DER ⇒ `false`; `ieee-p1363` ⇒ `true`.) 이는 옵션이 아니라 수용 기준이다.

**보안 명세(필수 — 옵션이 아니라 수용 기준).** 아래 구체 상수는 구현 재량이 아니라 *결정*이다.

- **알고리즘 선택은 서버 측이며, 토큰에서 가져오지 않는다.** 검증기는 설정된 `algorithms` 허용목록(기본 `["RS256","ES256"]`)과 JWK의 `kty`/`crv`에서 알고리즘을 고른다. 토큰의 `alg` 헤더는 키 선택 **전에** 허용목록 *멤버십*만 확인하고, 검증 루틴을 선택하지 않는다.
  - **`alg: "none"`을 무조건 거부**한다.
  - **alg-confusion 차단:** RSA 공개키를 HMAC verify에 절대 넣지 않는다. HMAC 계열(`HS*`)은 기본적으로 **허용하지 않는다**; JWKS에서 온 공개키는 오직 그에 맞는 비대칭 알고리즘과만 쓰인다.
  - **`kid`는 필수**다; 서명 키는 JWKS에서 `kid`로 선택하며, 모든 키를 시도하지 않는다.
  - **RSA 키 강도 하한:** modulus `< 2048` 비트인 RSA JWK는 invalid로 거부한다.
  - **JWK 사용 의도:** JWK에 `use`가 있으면 `sig`여야 하고, `key_ops`가 있으면 `verify`/`sign`을 포함하고 `encrypt`/`decrypt`를 포함하지 않아야 한다. 아니면 거부.
  - **헤더 `typ` / JWE 금지:** `typ`가 있으면 `JWT`여야 한다; 암호화된(JWE) 토큰은 무조건 거부 — JWS만 수용.
- **클레임은 필수이며 완전 검증한다:**
  - `iss`는 설정된 `issuer`와 같아야 한다.
  - `aud`(토큰)는 문자열 또는 문자열 배열일 수 있다(RFC 7519); 설정된 `audience`는 그 문자열과 같거나 배열의 멤버여야 한다 — 정확, 대소문자 구분 일치.
  - `sub`는 필수이며 비어있지 않은 문자열이어야 한다(`subjectHash`의 입력).
  - `exp`와 `nbf`는 **필수**다. `exp`: `now > exp + clockSkewSeconds`이면 거부. `nbf`: `now < nbf - clockSkewSeconds`이면 거부. `exp`가 없는 토큰은 거부. `iat`가 있으면 sanity-check.
  - **`clockSkewSeconds`** 기본 `60`, **최대 `300`** — `> 300` 값은 생성 시 거부(더 큰 skew는 만료 검증을 무력화).
- **JWKS fetch는 SSRF-하드닝:**
  - `issuer`는 유효한 **HTTPS URL**이어야 하고; `jwksUri`는 HTTPS이며 그 **hostname이 `issuer` hostname과 정확히 일치**해야 한다(포트 제외). 0.8은 **단일 origin issuer만** 지원한다 — issuer 식별자와 다른 host에서 JWKS를 서빙하는 IdP(일부 CDN-fronted 구성)는 0.8 범위 밖이며 생성 시 거부한다. 비-URL issuer(URN 형태)는 명확한 오류로 생성 시 거부한다.
  - private/loopback/link-local 대역과 클라우드 메타데이터 엔드포인트로의 요청은 거부한다: `127.0.0.0/8`, `::1`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16`(`169.254.169.254` 포함), `fe80::/10`. 거부는 DNS resolve 후 fetch 시점에 한다(rebinding 방어), fetch 타임아웃 포함.
  - **JWKS 응답 경계:** 응답 본문 `> 1 MiB`는 거부; `JSON.parse`는 병적 중첩(depth 한계)에 대해 가드한다. JWT 세그먼트는 `JSON.parse` 전에 **엄격한 base64url**(`[A-Za-z0-9_-]`, 패딩 없음)로 디코드한다.
- **JWKS 캐시는 경계가 있고 DoS 저항적:** 키는 TTL로 캐시한다; 알 수 없는 `kid`가 **무제한 refetch를 트리거하지 않는다** — **60초 cooldown**당 최대 1회 전체 JWKS 갱신이므로, 위조된 `kid` 폭주가 IdP에 대한 fetch storm으로 바뀌지 않는다.
- **identity는 PII-safe(fail-closed):** `cryptoProvider`는 **필수**이며 `hmac`을 노출해야 한다; 없으면 provider 생성자가 throw한다(PII-safe identity를 만들 수 없음). `subjectHash`/`issuerHash`는 keyed **HMAC-SHA-256**(`haechi:identity:hash:v1`), hex 인코딩(64자) — raw `sub`/`iss`는 절대 저장·로깅하지 않는다. `scopes`는 설정된 scope 클레임(`scp`/`scope`)에서, `labels`는 허용목록 클레임 매핑에서만 온다.
- **모든 곳에서 fail-closed:** 검증 오류 → `authenticate`는 `null`(거부)을 반환하고 요청 경로로 throw하지 않으며, 토큰 세부정보를 클라이언트로 echo하지 않는다.

**주입**으로 연결한다(`createRuntime(config, { authProvider: createJwtAuthProvider(...) })`); `auth.provider: external`. 동적 로딩은 1.0 plugin sandbox까지 금지를 유지한다.

### 2.5 모노레포 릴리스 프로세스

- 기존 루트 워크플로가 `haechi`를 계속 배포한다(`v*` 태그 glob + 엄격한 정규식 재검증으로 가드).
- 각 satellite는 0.7의 서명 아티팩트 단계(pack → checksum → attest → publish → upload)를 자기 디렉터리로 스코프하여 재사용하는 자체 접두사 태그 배포 워크플로를 가지며, 각각 자체 Trusted Publisher(특정 워크플로 파일명)에 바인딩된다.
- 패키지별 릴리스 런북(`release-process.md`)은 다음을 문서화한다: 태그 규칙 + 패키지→워크플로-파일명→태그-glob 매핑 표, Trusted Publisher 부트스트랩 순서(예약 → 설정 → 태그), 워크플로-rename 실패 모드, 배포 후 검증(provenance, `npm view ... access`).

## 3. 명시적 비범위 (0.9+로 이월)

- `@haechi/dashboard` 읽기 전용 audit 뷰어(UI 빌드, 자체 기술스택 결정).
- `@haechi/auth-oidc` 완전 대화형 OIDC(authorization-code flow) — `@haechi/auth-jwt`가 헤드리스 케이스를 먼저 다룬다.
- `@haechi/auth-jwt` multi-origin/CDN-fronted JWKS(issuer host ≠ JWKS host).
- `@haechi/classifier-*` ML/휴리스틱 classifier 플러그인.
- `@haechi/crypto-kms` Vault/GCP/Azure 백엔드(0.8은 AWS만).
- satellite의 동적 로딩(1.0 plugin sandbox).

risk-register와 로드맵은 `@haechi/auth-oidc`와 `@haechi/dashboard`를 0.8 행에서 빼 새 **0.9** 행으로 옮겨, 공개 문서가 이 범위와 일치하도록 갱신한다.

## 4. 하위 호환성

Core 동작은 불변이다: 루트 패키지의 `exports`, `bin`, `files`, zero-dep runtime 자세는 동일하다. 루트 `package.json`에 `workspaces`(`"."` 자기 항목 포함)를 추가하는 것은 `haechi`를 단일 의존성으로 설치하는 누구에게도 무해(inert)하다. 기존 config와 API는 손대지 않으며, satellite는 순수하게 부가적이고 opt-in이다.

## 5. 1.0 관계

0.8 자체는 1.0 blocker를 닫지 않지만, **운영 키 custody를 설치 가능하고 attest된 패키지로 실현**하고(`@haechi/crypto-kms`) satellite 모델을 end-to-end로 증명한다. 남은 1.0 게이트는 유지된다: API 안정성 freeze와 plugin sandbox + 실환경 검증.

## 6. 테스트 기준 (PR 분해에 매핑)

### 6.1 PR1 — workspaces 전환 (새 배포 패키지 없음)

- 루트 `npm install`이 **ERESOLVE/ETARGET 없이** exit 0; `node_modules/haechi`가 workspace 심링크; 커밋된 `package-lock.json`으로 fresh checkout에서 `npm ci` 성공.
- `import { ... } from "haechi/crypto"`를 하는 satellite 테스트가 루트 `node --test`에서 green.
- **no-leak + zero-dep 게이트:** core `npm pack --dry-run`에 **`satellites/` 경로 없음**; **패킹된** `haechi` `package.json`(tarball에서 추출)의 `dependencies`가 비어있음/undefined. 게이트는 **음성 테스트**된다: core의 `files`에 `satellites/`를 임시로 추가하거나 core `package.json`에 runtime dep를 추가하면 게이트가 명확한 오류로 실패한다(공허한 통과 방지).
- in-memory crypto provider(승격된 0.7 코드)가 workspace 심링크로 `assertCryptoProviderConformance`를 통과하며, `haechi/crypto` 대비 byte-for-byte `canonicalize` parity 검사를 포함한다.

### 6.2 PR2 — `@haechi/crypto-kms` (실제 AWS 클라이언트)

- in-memory **및 AWS** 클라이언트(AWS는 KMS `encrypt`/`decrypt` ops의 **주입된 mock**으로 구동 — SDK·네트워크 없음)가 cross-key/손상-blob **거부** 경로와 HMAC 결정성/domain-separation을 포함해 `assertCryptoProviderConformance`를 통과; `createRuntime`을 통한 end-to-end(암호화 + 토큰화 round-trip).
- `createAwsKmsClient`는 `keyId` 없으면 throw; `hmacRootCiphertext` 없으면 `deriveHmacKey`가 throw하고 provider는 encrypt-only로 conformance 통과(`requireHmac:false`).
- 배포 매니페스트가 `publishConfig.access: public`을 설정하고 `@aws-sdk/client-kms`를 `peerDependencies` + `peerDependenciesMeta.optional`로 선언(runtime `dependency` 아님); 배포 satellite tarball은 `dependencies: {}`이고 core tarball은 zero-dep 유지(§6.1 게이트 계속 통과).
- satellite publish 워크플로(`crypto-kms-v<semver>`)가 0.7 서명 아티팩트 경로로 존재; core 워크플로는 satellite 릴리스 태그가 `haechi`를 발행하지 않도록 가드.

### 6.3 PR3 — `@haechi/auth-jwt` (보안 게이트)

- 유효한 RS256/ES256 JWT(테스트 키 서명, stub JWKS)가 **audit에 raw `sub` 없이** PII-safe identity로 인증; `subjectHash`/`issuerHash`는 64-hex자 HMAC-SHA-256.
- 다음이 각각 **거부**됨: `alg:"none"`; RSA 공개키로 위조한 `HS256` 토큰(alg-confusion); JWE/`typ` 불일치; 만료(`exp`); 아직 유효하지 않음(`nbf`); `exp` 누락; `sub` 누락/빈 값; 잘못된 `aud`(문자열·배열 형태); 잘못된 `iss`; 알 수 없는 `kid`; 잘못된 서명; `< 2048` 비트 RSA JWK; `use:"enc"`/`key_ops:["encrypt"]` JWK.
- 생성이 거부함: non-HTTPS 또는 cross-origin `jwksUri`; 비-URL `issuer`; `clockSkewSeconds > 300`; `cryptoProvider.hmac` 누락. `127.0.0.1`, `169.254.169.254`, `::1`, 또는 RFC1918 CIDR로 resolve되는 `jwksUri`는 거부.
- 알 수 없는 `kid` 폭주가 60초 cooldown 내 **정확히 1회** JWKS refetch를 트리거; `> 1 MiB` JWKS 응답은 거부.

### 6.4 모든 satellite

- 각각 provenance + sigstore attestation으로 배포(0.7처럼 배포 후 검증).

## 7. 제안 PR 분해 (스택)

1. **Workspaces 전환**(새 배포 패키지 없음): 루트 `workspaces: [".", "satellites/*"]`, 루트를 **0.8.0**으로 bump, `crypto-kms`를 `satellites/crypto-kms/`로 이동(core `peer + dev` 의존성), 인라인 `canonicalize`를 `haechi/crypto`로 전환(+ parity 테스트), 테스트 재지정, 재생성된 `package-lock.json` 커밋, **no-leak + zero-dep CI 게이트** 추가(음성 테스트 포함), 루트 CI가 루트 `node --test`로 모든 workspace 테스트 실행. → §6.1
2. **`@haechi/crypto-kms`:** 실제 AWS KMS 클라이언트(satellite만의 `@aws-sdk/client-kms` 의존성) + 충실한 mocked-AWS conformance CI + `publishConfig` + 접두사 태그 배포 워크플로(엄격한 정규식 가드) + Trusted Publisher 부트스트랩. → §6.2
3. **`@haechi/auth-jwt`:** §2.4 전체 보안 명세를 구현하는 JWKS 검증 provider + identity 매핑 + §6.3 보안 게이트 테스트 + `publishConfig` + 접두사 태그 배포 워크플로. → §6.3
4. **0.8.0 릴리스 컷:** EN/KO 문서, packaging/roadmap/risk-register(OIDC+dashboard를 0.9로 이동)/api-stability, wiki, npm org / Trusted Publisher 런북(매핑 표 + 부트스트랩 순서 + 실패 모드).
