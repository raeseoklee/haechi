# Haechi Release Process

- 문서 상태: Living document (core 1.3.x 추적)
- 작성일: 2026-06-10

## 1. 로컬 릴리즈 검증

```bash
npm run release:preflight
npm run sbom
npm run bench:payload
```

`release:preflight`는 테스트, 타입 체크, stale-name scan, pack dry-run을 실행합니다. npm 계정 인증과 package ownership 확인까지 포함하려면 다음을 사용하세요.

```bash
npm run release:preflight:npm
```

첫 publish 전에는 `npm view <package> version`이 `E404 Not Found`를 반환하는 것이 정상입니다. 이 경우 preflight는 인증된 계정에서 이름을 claim할 준비가 된 상태로 통과합니다. 단, `npm view <package>@<version> version`이 성공하면 같은 버전을 다시 배포할 수 없으므로 실패합니다.

## 2. npm provenance와 trusted publishing

의도된 publish 경로는 GitHub Actions trusted publishing입니다. npm이 release workflow를 OIDC로 인증하고 provenance 증명을 자동 생성합니다. 공식 npm 요구사항에 따라 GitHub-hosted runner, `id-token: write`, 연결된 workflow에서의 publish가 필요합니다.

**현재 상태: trusted publishing 구성 및 검증 완료.** `haechi@0.3.2`는 로컬 머신에서 패스키 인증과 `--provenance=false`로 배포되어 해당 버전의 provenance 증명이 존재하지 않습니다. 활성화 runbook과 진행 상태는 다음과 같습니다.

1. ✅ npmjs.com에서: package settings → Trusted Publisher → `raeseoklee/haechi` 저장소와 `npm-publish.yml` workflow 연결 (2026-06-10).
2. ✅ `.github/workflows/npm-publish.yml` OIDC 인증 전환 (2026-06-10): `NODE_AUTH_TOKEN`과 `registry-url` 제거, runner의 npm CLI를 `>= 11.5.1`로 업그레이드.
3. ✅ `haechi@0.4.0`으로 검증 완료 (2026-06-10): `npm view haechi --json`에서 SLSA provenance v1 predicate를 가진 `dist.attestations` 확인.

**비증명 버전(로컬 패스키 첫 발행):** `haechi@0.3.2`와 `haechi-ratelimit-redis@0.1.0`(2026-06-16)은 각각 로컬 머신에서 `--provenance=false`로 배포되어 두 버전의 provenance 증명이 존재하지 않습니다 — 둘 다 아직 존재하지 않던 패키지의 **이름을 확보하는 첫 발행**이었기 때문입니다(Trusted Publisher가 완전히 새로운 이름을 부트스트랩할 수 없는 이유는 §5 참조). 각 패키지의 이후 모든 버전은 OIDC workflow로 증명됩니다.

provenance 없이 수행한 publish는 release note에 갭을 명시적으로 기록해야 합니다(`CONTRIBUTING.md` 참조).

참고:

- https://docs.npmjs.com/generating-provenance-statements/
- https://docs.npmjs.com/trusted-publishers/
- https://docs.github.com/actions/publishing-packages/publishing-nodejs-packages

## 3. 서명된 릴리스 아티팩트

**암호학적** 신뢰 앵커는 **npm provenance 증명**(레지스트리 아티팩트)과 **sigstore 증명**(release tarball)이며, 둘 다 GitHub OIDC로 아티팩트를 이 repo의 release workflow 신원에 묶습니다. `SHA256SUMS`는 오프라인 체크섬(`sha256sum -c`)을 위한 **도구 호환 편의 수단**이고, 같은 workflow가 생성·업로드하므로 그 자체로는 신뢰 앵커가 아닙니다. provenance에 더해, publish workflow는 다운로드한 tarball을 설치 전에 검증할 수 있도록 다음 자산을 첨부합니다.

- `npm pack` 후 `node scripts/release-checksums.mjs <tarball>`로 `SHA256SUMS` 매니페스트(표준 `<sha256-hex>  <name>` 형식)를 생성합니다.
- `actions/attest-build-provenance`로 tarball의 **keyless sigstore 증명**(GitHub OIDC, 서명 키 없음)을 만듭니다.
- tarball + `SHA256SUMS`를 GitHub release에 업로드합니다.

다운로드한 릴리스 검증:

```bash
# 체크섬 (크로스플랫폼: sha256sum -c, 또는 내장 스크립트)
node scripts/release-checksums.mjs --check SHA256SUMS
sha256sum -c SHA256SUMS            # GNU
shasum -a 256 -c SHA256SUMS        # macOS

# sigstore 증명 (이 repo의 release workflow가 빌드한 tarball)
gh attestation verify haechi-<version>.tgz --repo raeseoklee/haechi

# npm provenance (레지스트리 아티팩트)
npm audit signatures
```

## 4. GitHub Actions

| Workflow | 배포 대상 | 트리거 태그 | 목적 |
|---|---|---|---|
| `.github/workflows/ci.yml` | — | 모든 push/PR | test, release preflight, SBOM artifact |
| `.github/workflows/npm-publish.yml` | `haechi` | `v<semver>` | npm provenance publish + 체크섬/증명 release 자산 |
| `.github/workflows/crypto-kms-publish.yml` | `haechi-crypto-kms` | `crypto-kms-v<semver>` | satellite publish, 동일한 서명 아티팩트 경로 |
| `.github/workflows/auth-jwt-publish.yml` | `haechi-auth-jwt` | `auth-jwt-v<semver>` | satellite publish, 동일한 서명 아티팩트 경로 |
| `.github/workflows/dashboard-publish.yml` | `haechi-dashboard` | `dashboard-v<semver>` | satellite publish, 동일한 서명 아티팩트 경로 |
| `.github/workflows/auth-oidc-publish.yml` | `haechi-auth-oidc` | `auth-oidc-v<semver>` | satellite publish, 동일한 서명 아티팩트 경로 |
| `.github/workflows/ratelimit-redis-publish.yml` | `haechi-ratelimit-redis` | `ratelimit-redis-v<semver>` | satellite publish, 동일한 서명 아티팩트 경로 |

각 publish 워크플로는 `release: published`에서 트리거되지만 **가드**되어 둘이 교차 발화하지 않습니다. core job은 `v`로 시작하는 태그에서만 실행되고(그리고 `^v[0-9]+\.[0-9]+\.[0-9]+$` 재검증), satellite job은 `crypto-kms-v…`에서만 실행됩니다(그리고 `^crypto-kms-v[0-9]+\.[0-9]+\.[0-9]+$` 재검증 **및** 태그 버전이 satellite `package.json` 버전과 일치하는지 검증). npmjs.com Trusted Publisher는 각 패키지의 **특정 워크플로 파일명**에 바인딩됩니다 — 워크플로 파일 rename은 npm 설정을 갱신할 때까지 OIDC publish를 깨뜨립니다.

## 5. Satellite 패키지 (unscoped `haechi-*`)

Satellite는 npm workspaces 모노레포의 `satellites/*`에 살며 core와 **독립적으로** 발행됩니다(자체 semver이며, satellite patch가 `haechi`를 bump하지 않습니다). core와 동일한 서명 아티팩트 경로를 재사용합니다(pack → checksum → sigstore attest → OIDC publish → upload). **unscoped** `haechi-*` 이름으로 발행하므로(`@haechi` org/scope는 제3자가 점유) **npm org가 필요 없습니다**.

**satellite별 부트스트랩 순서(첫 발행, org 불필요):**

아직 존재하지 않는 이름에는 Trusted Publisher를 설정할 **수 없습니다** — npm은 **이미 존재하는** 패키지의 설정 페이지에서만 Trusted Publisher 설정을 노출합니다. 따라서 완전히 새로운 unscoped 이름은 두 단계 부트스트랩을 거칩니다: 먼저 수동 첫 발행으로 이름을 *생성하고 확보*한 뒤, Trusted Publisher를 설정하여 이후 모든 버전이 OIDC로 증명되게 합니다.

1. **수동 첫 발행(이름 확보; 로컬, provenance 없음).** satellite 디렉터리에서, 패스키/WebAuthn 계정이 터미널 OTP 없이 인증되도록 브라우저로 인증한 뒤 provenance를 끄고 발행합니다(로컬 머신에는 OIDC id-token이 없어 증명할 수 없습니다).
   ```bash
   npm login --auth-type=web
   cd satellites/<name> && npm publish --auth-type=web --provenance=false
   ```
   각 satellite `package.json`의 `publishConfig.access: "public"`이 unscoped 패키지를 public으로 만듭니다. 이 첫 버전은 **비증명**입니다 — §2 / `CONTRIBUTING.md`에 따라 갭을 기록하세요.
2. **이제 패키지가 존재하므로 → Trusted Publisher 설정**: npmjs.com에서 package settings → Trusted Publisher → `raeseoklee/haechi` 저장소와 satellite의 **정확한 워크플로 파일명**(예: `crypto-kms-publish.yml`)을 연결합니다.
3. **이후 모든 버전은 OIDC로 증명됩니다.** satellite `package.json`을 bump하고, 접두사 태그를 push한 뒤, GitHub Release를 발행하면(예: `crypto-kms-v0.1.1`) 워크플로의 OIDC publish가 provenance와 함께 해당 버전을 발행합니다. 이 시점부터는 노트북도 OTP도 필요 없습니다. 이름이 unscoped이고 비어있으므로 org-membership 선행 요건이 없습니다.

**태그 → 워크플로 → 패키지 매핑:**

| 패키지 | 태그 패턴 | 워크플로 파일 | npm 버전 소스 |
|---|---|---|---|
| `haechi-crypto-kms` | `crypto-kms-v<semver>` | `crypto-kms-publish.yml` | `satellites/crypto-kms/package.json` |
| `haechi-auth-jwt` | `auth-jwt-v<semver>` | `auth-jwt-publish.yml` | `satellites/auth-jwt/package.json` |
| `haechi-dashboard` | `dashboard-v<semver>` | `dashboard-publish.yml` | `satellites/dashboard/package.json` |
| `haechi-auth-oidc` | `auth-oidc-v<semver>` | `auth-oidc-publish.yml` | `satellites/auth-oidc/package.json` |
| `haechi-ratelimit-redis` | `ratelimit-redis-v<semver>` | `ratelimit-redis-publish.yml` | `satellites/ratelimit-redis/package.json` |

**satellite 릴리스 검증** (core와 동일한 신뢰 앵커):

```bash
gh attestation verify haechi-crypto-kms-<version>.tgz --repo raeseoklee/haechi
npm view haechi-crypto-kms --json   # dist.attestations 존재 확인; access "public"
```

**의존성 노트:** `haechi-crypto-kms`는 core를 zero-dependency로 유지합니다 — `@aws-sdk/client-kms`는 **optional peer dependency**이며, 실제 AWS 클라이언트를 쓰고 주입하지 않을 때만 lazy import됩니다. in-memory 또는 주입형 클라이언트를 쓰는 소비자는 SDK를 설치하지 않습니다. 0.2.0의 `./gcp`(`@google-cloud/kms`)와 `./azure`(`@azure/keyvault-keys` + `@azure/identity`) 백엔드도 동일한 optional-peer/lazy-import 모델을 따르며, `./vault` 백엔드는 optional peer가 없습니다(`node:` `fetch` 전용).

**0.9 satellite(새 unscoped 이름):** `haechi-dashboard`와 `haechi-auth-oidc`는 0.9에서 위의 두 단계 부트스트랩으로 첫 발행되었습니다 — 수동 첫 발행으로 각 이름을 확보한 뒤 Trusted Publisher를 설정했고, 그 이후 태그 릴리스(`dashboard-v<semver>`, `auth-oidc-v<semver>`)는 OIDC로 발행됩니다. 0.8 satellite 두 개는 이미 존재하므로 이미 부트스트랩된 태그/워크플로를 그대로 사용합니다: `haechi-auth-jwt`는 `auth-jwt-v<semver>`(`auth-jwt-publish.yml`), `haechi-crypto-kms`는 `crypto-kms-v<semver>`(`crypto-kms-publish.yml`) — 이 둘은 새 Trusted Publisher 설정이 필요 없습니다.

**`haechi-ratelimit-redis`(부트스트랩 2026-06-16):** 공유 저장소 rate-limiter satellite는 위의 두 단계 부트스트랩을 따랐습니다. `0.1.0`은 이름을 확보한 **수동 첫 발행**(로컬 패스키 web 인증, `--provenance=false`)이므로 **비증명**입니다(§2에 기록). 이후 Trusted Publisher(`ratelimit-redis-publish.yml`)를 설정했고, `0.1.1`부터의 모든 버전은 `ratelimit-redis-v<semver>` 태그 → 워크플로로 provenance와 함께 발행됩니다. `redis` 클라이언트는 **optional peer dependency**이며 번들된 Redis 어댑터를 쓰는 소비자만 import합니다(store/client는 주입됩니다). 따라서 core는 zero-dependency로 유지됩니다.

## 6. 배포 차단 조건

다음 중 하나라도 실패하면 npm publish를 하지 않습니다.

- `npm run release:preflight` 실패
- `npm run release:preflight:npm` 실패
- GitHub Actions CI 실패
- SBOM 생성 실패
- npm package name ownership 불확실
- README/SECURITY가 developer preview와 production 제한을 명시하지 않음
- trusted publishing/provenance가 미구성인데 release note에 provenance 갭을 명시하지 않음
