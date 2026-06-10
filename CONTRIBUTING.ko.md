# Haechi 기여 가이드

코드, 커밋, PR, 문서의 기본 언어는 영문이다. 문서의 한국어 번역본은 같은 경로의 `*.ko.md`로 관리한다.

## 브랜치 모델

`main`이 유일한 장수 브랜치다. 항상 릴리스 가능한 상태를 유지하고, 변경은 PR로만 반영한다. `develop` 브랜치는 두지 않는다: 릴리스가 태그 기반이라 이 프로젝트 규모에서 Gitflow의 스테이징 브랜치는 가치가 없다.

모든 작업은 타입 prefix를 붙여 `main`에서 분기한다.

| 브랜치 | 용도 | 예시 |
|---|---|---|
| `feature/<topic>` | 신규 기능 | `feature/mcp-wrap` |
| `fix/<topic>` | 버그 수정 | `fix/ollama-stream-detect` |
| `docs/<topic>` | 문서 전용 | `docs/threat-model-update` |
| `chore/<topic>` | 툴링, CI, 의존성, 유지보수 | `chore/lsp-typecheck` |
| `release/<version>` | 릴리스 준비 (버전 범프, 스코프 문서) | `release/0.4.0` |
| `hotfix/<version>` | 배포된 릴리스의 긴급 패치 | `hotfix/0.3.3` |

개인 이름 prefix(`irae/...` 등)는 사용하지 않는다.

## 커밋

- 영문 한 줄 명령형 제목을 사용한다.
  - 좋은 예: `Make local proxy port configurable before preview publish`
  - 나쁜 예: `fixed stuff`, `WIP`
- 커밋 하나는 하나의 논리적 변경만 담는다.
- 중요 변경은 짧은 본문에 Lore 스타일 git trailer를 남긴다. 유용할 때 `Constraint:`, `Rejected:`, `Confidence:`, `Scope-risk:`, `Directive:`, `Tested:`, `Not-tested:` 등을 사용한다.
- `Co-Authored-By` 같은 attribution 또는 generated-by footer는 추가하지 않는다.

## Pull Request

- `main`을 대상으로 한다. 제목은 커밋 제목 스타일을 따른다.
- 본문은 영문으로 `## Summary`, `## Verification` 섹션을 갖춘다.
- PR 생성 전 로컬에서 다음이 통과해야 한다.

```bash
npm test
npm run release:preflight   # 테스트 + 타입 체크 + stale-name 스캔 + pack dry-run
```

## 릴리스

1. `main`에서 `release/<version>` 분기; `package.json` 버전 범프, `docs/current/release-<version>-*.md`(및 `.ko.md`) 추가/갱신, 리스크 레지스터 게이트 갱신.
2. PR로 머지 후 `main`에 `v<version>` 태그.
3. GitHub release 생성(`0.x` 동안은 pre-release). `Publish npm Developer Preview` workflow는 trusted publishing이 구성된 뒤 provenance 경로로 사용한다. 로컬 publish를 수행한 경우 release note에 provenance gap을 기록해야 한다.
4. `npm view haechi version`으로 확인.

게이트 상세는 `docs/current/release-process.md`를 따른다.

## 개발

- Node `>= 22`. 패키지는 **런타임 의존성 0개**(`node:` 내장만)를 유지한다. 개발 전용 툴링 의존성은 허용하되 배포 산출물에 새지 않아야 한다(SBOM은 dev 의존성을 제외한다).
- 테스트는 내장 `node:test` 러너 사용: `npm test`, 단일 파일은 `node --test tests/<file>.test.mjs`.
- 에디터 언어 지원(자동완성, 정의 이동, hover, 진단)은 `jsconfig.json`으로 구성되며, `npm run check:types`가 같은 프로젝트를 `tsc --noEmit`으로 검사한다. `checkJs`는 현재 꺼져 있다 — `// @ts-check`로 파일 단위 점진 도입한다.
- 문서 변경은 영문 메인 파일과 `.ko.md` 번역본을 함께 갱신해야 한다.
- 보안 관련 변경은 `SECURITY.md`와 `docs/current/threat-model.md`의 불변식(fail-closed 기본값, audit 평문 금지, loopback 전용 bind, 통제된 token reveal)을 지켜야 한다.
