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

`release:preflight`는 테스트, stale-name scan, pack dry-run을 실행한다. npm 계정 인증과 package ownership 확인까지 포함하려면 다음을 사용한다.

```bash
npm run release:preflight:npm
```

첫 publish 전에는 `npm view <package> version`이 `E404 Not Found`를 반환하는 것이 정상이다. 이 경우 preflight는 인증된 계정에서 이름을 claim할 준비가 된 상태로 통과한다. 단, `npm view <package>@<version> version`이 성공하면 같은 버전을 다시 배포할 수 없으므로 실패한다.

## 2. npm provenance

npm provenance는 GitHub Actions release workflow에서 생성한다. 공식 npm 문서의 요구사항에 맞춰 GitHub-hosted runner, `id-token: write`, `npm publish --provenance --access public`을 사용한다.

참고:

- https://docs.npmjs.com/generating-provenance-statements/
- https://docs.github.com/actions/publishing-packages/publishing-nodejs-packages

## 3. GitHub Actions

| Workflow | 목적 |
|---|---|
| `.github/workflows/ci.yml` | test, release preflight, SBOM artifact |
| `.github/workflows/npm-publish.yml` | GitHub release published 이벤트에서 npm provenance publish |

## 4. 배포 차단 조건

다음 중 하나라도 실패하면 npm publish를 하지 않는다.

- `npm run release:preflight` 실패
- `npm run release:preflight:npm` 실패
- GitHub Actions CI 실패
- SBOM 생성 실패
- npm package name ownership 불확실
- README/SECURITY가 developer preview와 production 제한을 명시하지 않음
