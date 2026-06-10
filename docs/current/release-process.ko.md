# Haechi Release Process

- 문서 상태: Draft 0.1
- 작성일: 2026-06-10
- 기준 버전: 0.3.2

## 1. 로컬 릴리즈 검증

```bash
npm run release:preflight
npm run sbom
npm run bench:payload
```

`release:preflight`는 테스트, 타입 체크, stale-name scan, pack dry-run을 실행한다. npm 계정 인증과 package ownership 확인까지 포함하려면 다음을 사용한다.

```bash
npm run release:preflight:npm
```

첫 publish 전에는 `npm view <package> version`이 `E404 Not Found`를 반환하는 것이 정상이다. 이 경우 preflight는 인증된 계정에서 이름을 claim할 준비가 된 상태로 통과한다. 단, `npm view <package>@<version> version`이 성공하면 같은 버전을 다시 배포할 수 없으므로 실패한다.

## 2. npm provenance와 trusted publishing

의도된 publish 경로는 GitHub Actions trusted publishing이다: npm이 release workflow를 OIDC로 인증하고 provenance 증명을 자동 생성한다. 공식 npm 요구사항에 따라 GitHub-hosted runner, `id-token: write`, 연결된 workflow에서의 publish가 필요하다.

**현재 상태: trusted publishing 구성 및 검증 완료.** `haechi@0.3.2`는 로컬 머신에서 패스키 인증과 `--provenance=false`로 배포되어 해당 버전의 provenance 증명이 존재하지 않는다. 활성화 runbook과 진행 상태:

1. ✅ npmjs.com에서: package settings → Trusted Publisher → `raeseoklee/haechi` 저장소와 `npm-publish.yml` workflow 연결 (2026-06-10).
2. ✅ `.github/workflows/npm-publish.yml` OIDC 인증 전환 (2026-06-10): `NODE_AUTH_TOKEN`과 `registry-url` 제거, runner의 npm CLI를 `>= 11.5.1`로 업그레이드.
3. ✅ `haechi@0.4.0`으로 검증 완료 (2026-06-10): `npm view haechi --json`에서 SLSA provenance v1 predicate를 가진 `dist.attestations` 확인. 로컬 패스키로 배포한 `haechi@0.3.2`만 비증명 상태로 남는다.

provenance 없이 수행한 publish는 release note에 갭을 명시적으로 기록해야 한다(`CONTRIBUTING.md` 참조).

참고:

- https://docs.npmjs.com/generating-provenance-statements/
- https://docs.npmjs.com/trusted-publishers/
- https://docs.github.com/actions/publishing-packages/publishing-nodejs-packages

## 3. 서명된 릴리스 아티팩트

**암호학적** 신뢰 앵커는 **npm provenance 증명**(레지스트리 아티팩트)과 **sigstore 증명**(release tarball)이며, 둘 다 GitHub OIDC로 아티팩트를 이 repo의 release workflow 신원에 묶는다. `SHA256SUMS`는 오프라인 체크섬(`sha256sum -c`)을 위한 **도구 호환 편의 수단**이고, 같은 workflow가 생성·업로드하므로 그 자체로는 신뢰 앵커가 아니다. provenance에 더해, publish workflow는 다운로드한 tarball을 설치 전에 검증할 수 있도록 다음 자산을 첨부한다.

- `npm pack` 후 `node scripts/release-checksums.mjs <tarball>`로 `SHA256SUMS` 매니페스트(표준 `<sha256-hex>  <name>` 형식)를 생성한다.
- `actions/attest-build-provenance`로 tarball의 **keyless sigstore 증명**(GitHub OIDC, 서명 키 없음)을 만든다.
- tarball + `SHA256SUMS`를 GitHub release에 업로드한다.

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
| `.github/workflows/crypto-kms-publish.yml` | `@haechi/crypto-kms` | `crypto-kms-v<semver>` | satellite publish, 동일한 서명 아티팩트 경로 |

각 publish 워크플로는 `release: published`에서 트리거되지만 **가드**되어 둘이 교차 발화하지 않는다: core job은 `v`로 시작하는 태그에서만 실행되고(그리고 `^v[0-9]+\.[0-9]+\.[0-9]+$` 재검증), satellite job은 `crypto-kms-v…`에서만 실행된다(그리고 `^crypto-kms-v[0-9]+\.[0-9]+\.[0-9]+$` 재검증 **및** 태그 버전이 satellite `package.json` 버전과 일치하는지 검증). npmjs.com Trusted Publisher는 각 패키지의 **특정 워크플로 파일명**에 바인딩된다 — 워크플로 파일 rename은 npm 설정을 갱신할 때까지 OIDC publish를 깨뜨린다.

## 5. Satellite 패키지 (`@haechi/*`)

Satellite는 npm workspaces 모노레포의 `satellites/*`에 살며 core와 **독립적으로** 발행된다(자체 semver; satellite patch가 `haechi`를 bump하지 않음). core와 동일한 서명 아티팩트 경로를 재사용한다(pack → checksum → sigstore attest → OIDC publish → upload).

**satellite별 부트스트랩 순서(첫 발행, chicken-and-egg):**

1. npm org **`@haechi`** 생성/소유(네임스페이스 방어; scoped publish 전에 필요).
2. npmjs.com에서 org 내 패키지 이름 **예약** — 버전 발행 없이 네임스페이스 확보.
3. 예약된 패키지에 Trusted Publisher **설정**: `raeseoklee/haechi` 저장소와 satellite의 **정확한 워크플로 파일명**(예: `crypto-kms-publish.yml`) 연결.
4. 접두사 태그를 push하고 GitHub Release 발행(예: `crypto-kms-v0.1.0`) → 워크플로의 OIDC publish가 provenance와 함께 `0.1.0` 생성.

2–3단계는 1단계의 org-owner 권한이 필요하다. 노트북에서의 수동 `npm publish`는 필요 없다.

| 패키지 | 태그 패턴 | 워크플로 파일 | npm 버전 소스 |
|---|---|---|---|
| `@haechi/crypto-kms` | `crypto-kms-v<semver>` | `crypto-kms-publish.yml` | `satellites/crypto-kms/package.json` |

**의존성 노트:** `@haechi/crypto-kms`는 core를 zero-dependency로 유지한다 — `@aws-sdk/client-kms`는 **optional peer dependency**이며, 실제 AWS 클라이언트를 쓰고 주입하지 않을 때만 lazy import된다. in-memory 또는 주입형 클라이언트를 쓰는 소비자는 SDK를 설치하지 않는다.

## 6. 배포 차단 조건

다음 중 하나라도 실패하면 npm publish를 하지 않는다.

- `npm run release:preflight` 실패
- `npm run release:preflight:npm` 실패
- GitHub Actions CI 실패
- SBOM 생성 실패
- npm package name ownership 불확실
- README/SECURITY가 developer preview와 production 제한을 명시하지 않음
- trusted publishing/provenance가 미구성인데 release note에 provenance 갭을 명시하지 않음
