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

## 3. GitHub Actions

| Workflow | 목적 |
|---|---|
| `.github/workflows/ci.yml` | test, release preflight, SBOM artifact |
| `.github/workflows/npm-publish.yml` | GitHub release published 이벤트에서 npm publish (trusted publishing 구성 후 provenance 경로) |

## 4. 배포 차단 조건

다음 중 하나라도 실패하면 npm publish를 하지 않는다.

- `npm run release:preflight` 실패
- `npm run release:preflight:npm` 실패
- GitHub Actions CI 실패
- SBOM 생성 실패
- npm package name ownership 불확실
- README/SECURITY가 developer preview와 production 제한을 명시하지 않음
- trusted publishing/provenance가 미구성인데 release note에 provenance 갭을 명시하지 않음
