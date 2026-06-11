# Haechi 1.1 구현 범위

- 상태: Draft 0.2 (설계 — 아직 미구현; Node 26 실측을 동반한 3-렌즈 적대적 검토 후 강화, 2026-06-11)
- 날짜: 2026-06-11
- 대상 버전: 1.1.0 (1.0.0 이후)
- 유형: 플러그인 샌드박스의 capability **강제(enforcement)** (1.0의 정직한 잔여 위험을 닫음)

## 1. 릴리스 목표

1.1은 1.0 플러그인 샌드박스의 대표적인 **정직한 잔여 위험(honest residual)** 을 닫는다. 1.0은 `node:worker_threads`가 **메모리/크래시 격리일 뿐 capability 샌드박스가 아니다** 라고 명시했다 — 악성 *서명된* 플러그인이 여전히 `fs`/`net`을 사용해 전달받은 자격증명을 유출할 수 있었다. 1.1은 **더 강한 opt-in `process-isolated` 런타임**을 추가한다. 이 런타임은 서명된 `authProvider` 플러그인을 **Node 권한 모델(`--permission`) 하의 자식 프로세스**에서 실행하며, **`--allow-net`을 fail-closed로 요구하는 네트워크 봉쇄**, **모든 stdio 무시**(stdout/stderr/fd 유출 채널 없음), 그리고 플러그인을 **파일시스템 권한이 전혀 없는 `data:` URL에서 로드**한다 — 따라서 악성 서명 플러그인은 **호스트 파일시스템을 읽을 수도, 프로세스를 spawn할 수도, 네트워크에 도달할 수도, 호스트가 볼 수 있는 어떤 sink에 쓸 수도 없고**, 그러므로 **자격증명을 유출할 수 없다**.

Draft 0.1에 대한 적대적 검토(Node 26 실측)가 이 설계를 재구성했고, 그 교정 사항은 아래에 반영되어 있다:

- **"`node:net`/fetch를 삭제하는" 하니스는 봉쇄가 아니다.** `process.binding('tcp_wrap')`은 살아있는 소켓을 열고, `import('node:net')`은 캐시 삭제와 무관하게 새 builtin을 재해석한다. 따라서 네트워크 봉쇄는 JS 하니스가 아니라 **커널이 강제하는 `--allow-net` 거부**여야 한다. `--allow-net`이 없는 Node(Node 22 LTS에는 없음)에서는 `process-isolated`가 봉쇄하는 척하지 않고 **fail-closed로 동작**한다.
- **자식 프로세스는 `--allow-net`이 막지 못하는 stdout/stderr/상속 fd 쓰기 채널을 추가한다.** 이들을 명시적으로 닫지 않으면(stdio 무시 + 전용 IPC 채널) 자격증명이 로그로 유출된다.
- **임시 디렉터리에 `--allow-fs-read`를 주는 것은 TOCTOU + macOS realpath/symlink 실패 + 숨은 번들링 요구를 부른다.** 검증된 바이트를 **`data:` URL**(1.0 worker가 이미 쓰는 방식)에서 로드하면 **fs 권한이 전혀 필요 없고**, TOCTOU/symlink 표면 전체가 사라지며, 자족적 단일 파일 플러그인을 구조적으로 강제한다.

**범위 결정(2026-06-11, 메인테이너 확정; 아래 network/mode/credential/scope 선택은 검토로 다듬은 네 가지 권장 답변이다):**

1. **격리:** `process-isolated` = `--permission` 하의 자식 `node` 프로세스로, **기본적으로 아무것도 부여하지 않으며**(fs 없음, child-process 없음, worker 없음, addons 없음, wasi 없음), 플러그인을 `data:` URL에서 로드하고, `stdio: ['ignore','ignore','ignore','ipc']` + 정화된 `env`로 spawn한다.
2. **네트워크 = fail-closed `--allow-net`.** 네트워크 봉쇄는 권한 모델의 `--allow-net` 거부이며 **기능 탐지 + fail-closed**이다: 실행 중인 Node가 `--allow-net` 강제를 입증하지 못하면 `process-isolated`는 **생성을 거부**한다(기본값 `netEnforcement: "require-permission"`). 비-봉쇄 best-effort 대체는 오직 명시적 `allow-harness` opt-in 뒤에서, **악성 플러그인을 봉쇄하지 못한다**는 요란한 경고와 함께만 존재한다.
3. **자격증명 처리:** **표준 JWT/JWKS** 자격증명은 **호스트**가 감사되는 `createJwtVerifier`(satellite 경로 재사용)를 실행하므로 플러그인이 **필요 없다**; `process-isolated` 플러그인은 플러그인이 직접 파싱해야 하는 **커스텀/불투명 자격증명**용이며, 거기서 플러그인은 원본 자격증명을 보지만 **net + stdio + fs 거부**로 봉쇄된다(유출 불가). 커스텀 플러그인이 필요로 하는 키 자료는 **호스트가 fetch해 주입**한다(플러그인이 URL을 고르지 않음 → 플러그인 주도 SSRF 없음).
4. **모드 + 범위:** `process-isolated`는 변경되지 않은 1.0 `worker-isolated`와 **나란히 존재하는 새롭고 더 강한 opt-in** 런타임이다; 1.1은 이 capability 강제 런타임에 **집중**한다. Classifier/crypto 플러그인, 라이브 CRL, 레지스트리는 이후 마이너에 남긴다.

코어는 **런타임 의존성 0**(`node:child_process` + `--permission` + `node:crypto`/`node:dns`)을 유지한다. 1.1은 additive + opt-in이며, 새 모듈 외 유일한 코어 변경은 **SSRF `isBlockedAddress` 가드를 코어의 node:-only 헬퍼로 승격**하는 것이다(§2.3) — 호스트 중개 fetch가 그것을 쓸 수 있도록(코어는 satellite를 import할 수 없음).

## 2. 범위

### 2.1 `process-isolated` authProvider 런타임 (커널 강제 capability, fs 없음, stdio 없음)

새 매니페스트 `runtime: "process-isolated"`(`kind: "authProvider"`용, `worker-isolated`와 나란히). `createProcessIsolatedAuthProvider(options)`는 `authenticate()`를 자식 `node` 프로세스로 프록시하는 호스트측 `authProvider`(frozen 계약)를 반환한다.

- **로드 게이트 우선(PR2 게이트, fail-closed, 감사됨):** 엔트리 바이트를 **메모리에서** 두고 `verifySignedPlugin`(`entrySha256` + kind/capabilities/window에 대한 Ed25519, trust-anchor 전용 해석, pin/version-floor/revocation).
- **`data:` URL로 로드 — fs 권한 없음, TOCTOU 없음.** 자식은 검증된 바이트를 `data:text/javascript;base64,…` URL로 import한다(1.0 worker가 이미 쓰는 메커니즘). 자식은 **`--allow-fs-read`가 전혀 없이** spawn된다 → 호스트 파일시스템을 읽을 수 없다. 이로써 temp-dir / realpath / symlink / TOCTOU 표면이 통째로 사라지고, **자족적 단일 파일 플러그인**(런타임 `import`/`require`로 호스트 파일을 끌어오지 않음)을 구조적으로 요구한다; 로드 게이트는 소스가 정적으로 비-`data:` specifier를 참조하는 엔트리를 추가로 거부한다.
- **허용 목록 capability만 부여하는 `--permission` spawn:** `process.execPath` + `--permission`, **`--allow-fs-read`/`--allow-fs-write`/`--allow-child-process`/`--allow-worker`/`--allow-addons`/`--allow-wasi` 없음**. `env`는 최소 고정 집합으로 **정화**된다(상속된 호스트 비밀 없음 — `--permission`은 상속 env를 보호하지 않음; env 정화가 한다). `--disable-proto=delete`.
- **stdio 완전 차단(검토가 드러낸 새롭고 핵심적인 통제):** `stdio: ['ignore','ignore','ignore','ipc']` — **stdout 없음, stderr 없음, 추가 상속 fd 없음**; 유일한 채널은 전용 IPC다. 호스트는 자식 stdout/stderr를 **결코** 전달/로깅/감사하지 않는다(자격증명을 stderr에 쓰는 플러그인은 그렇지 않으면 운영자 로그로 유출된다). `sendHandle`/fd 전달 없음.
- **JSON-문자열 전용 IPC(structured clone 없음, fd 전달 없음).** `child_process` IPC는 advanced(structured-clone) 직렬화 + 핸들 전달을 지원하는데, 이는 1.0 sanitizer가 막으려 했던 object/proto/transferable 밀반입을 다시 연다. 런타임은 IPC로 **JSON 문자열만** 송수신하며(`serialization: "json"`), correlation-id + null-proto 허용 목록 sanitizer + 호스트측 `buildExternalIdentity`는 1.0 worker 경로와 정확히 동일하다.
- **단일 점유 + fail-closed 매트릭스**(timeout → kill, `maxPendingCalls`, `maxMessageBytes`, kill-switch)는 §2.4의 프로세스 수명주기 추가와 함께 그대로 이어진다.
- **로드 시 적합성**은 샌드박스 자식에 대해 `assertAuthProviderConformance`(무작위 벡터)를 실행한다.

### 2.2 네트워크 봉쇄 = fail-closed `--allow-net` (하니스는 봉쇄가 아니다)

- **`--allow-net`만이 진짜 네트워크 통제다.** 네트워크가 필요 없는 `process-isolated` 플러그인은 자식이 **`--allow-net` 없이** spawn된다; 이를 강제하는 Node에서 `net.connect`/`fetch`/`dns` → `ERR_ACCESS_DENIED`(커널 강제). 이것이 실제로 자격증명 유출을 막는다.
- **기능 탐지 + fail-closed, 버전 파싱 없음.** 생성 시 런타임은 `process.allowedNodeEnvironmentFlags.has('--allow-net')`로 `--allow-net` 지원을 탐지하고, **spawn-probe로 한 번 확인**(`node --permission --allow-net -e 0` → exit 0 = 지원, exit 9 = 미지원)한 뒤 런타임 수명 동안 캐시한다. 기본값 **`netEnforcement: "require-permission"`**: 지원이 입증되지 않으면 `createRuntime`/`normalizeConfig`가 **throw**(시작 거부)하며 조용히 격하되지 않는다. 따라서 자격증명 봉쇄 보장은 `--allow-net` Node(그것을 탑재한 버전 이상)를 요구한다; 그것이 없는 Node 22 LTS → fail closed.
- **하니스는 best-effort 전용이며 그렇게 라벨된다.** *순진한/우발적* egress를 위한 이식성 있는 `allow-harness` opt-in이 존재할 수 있지만, 설계는 문서·감사(`netEnforcement: "harness"` + 시작 **경고**)·위협 모델에서 평이하게 명시한다 — **악성 서명 플러그인을 봉쇄하지 못한다**(`process.binding('tcp_wrap')`와 새 `import('node:net')`이 모두 네트워크에 도달). 추가로 `process.binding`/`internalBinding`을 stub해야 하지만, 그래도 견고하지 않다. 고확신 운영자는 `require-permission`(기본값)을 쓴다.

### 2.3 자격증명 처리 — 호스트측 JWT, 호스트 중개 키 자료, 코어의 SSRF 가드

- **표준 JWT/JWKS: 호스트가 검증하고, 어떤 플러그인도 원본 자격증명을 보지 않는다.** 흔한 JWT의 경우 **호스트**가 감사되는 `createJwtVerifier`(satellite 경로)를 실행하므로 `process-isolated` 플러그인은 **불필요**하다 — 호스트 검증기를 직접 쓴다(`auth.provider: "external"`/satellite). 1.1은 원본 JWT를 자식으로 라우팅하지 않는다.
- **커스텀/불투명 자격증명: 플러그인이 원본을 보지만 egress 거부로 봉쇄된다.** `process-isolated` 플러그인은 플러그인이 파싱해야 하는 비표준 자격증명을 위해 존재한다. 검증을 위해 IPC로 원본 자격증명을 받지만(받아야만 한다), **net + stdio + fs가 모두 거부**되므로 그것을 **유출할 수 없다**. 플러그인은 원본 claims를 반환하고, 호스트가 정화 + keyed-HMAC 신원을 구축한다(crypto 키는 결코 넘어가지 않음).
- **호스트 중개 키 자료(플러그인 주도 SSRF 없음).** 커스텀 플러그인이 필요로 하는 키 자료(예: JWKS 유사 문서)는 **운영자가 선언한** URL에서 — 플러그인이 고른 URL이 아니라 — **호스트**가 **SSRF 강화된 가드 fetch**로 가져와 IPC로 주입한다. kid 기반 재fetch는 **rate-limit/cooldown으로 제한**(bearer satellite가 이미 하듯)되어 공격자의 자격증명이 호스트의 아웃바운드 요청을 펌프질할 수 없다.
- **SSRF 가드가 코어로 이동한다.** `isBlockedAddress` + 가드 fetch 패턴(DNS 후 재확인, HTTPS 전용, 본문 제한, fetch timeout, `redirect:"error"`)은 현재 `haechi-auth-jwt` satellite에만 있고 코어는 그것을 import할 수 없다. 1.1은 **node:-only `isBlockedAddress`/`guardedFetch`를 코어 모듈로 승격**(코어는 의존성 0 유지)하며, satellite들(`auth-jwt`, `auth-oidc`, `crypto-kms`의 Vault 복사본)과 호스트 fetch가 그 하나의 코어 헬퍼를 import해 drift를 끝낸다. 알려진 DNS-rebinding 창(resolve-then-connect)은 잔여로 문서화하며, 운영자 선언 host-JWKS의 경우 single-origin/issuer 결합은 완화한다.

### 2.4 프로세스 수명주기(anti-DoS) — 서킷 브레이커 + 워밍된 자식

호출마다 새 `node --permission` spawn은 수십 ms이며, timeout이 나는 플러그인은 모든 인증 시도를 콜드 spawn으로 바꿔 증폭 DoS를 만들 수 있다. 그래서:

- 호출 전반에 재사용되는 **워밍된 장수 자식**(단일 점유 직렬화 유지), 한 번 spawn해 준비 상태로 유지.
- timeout/크래시 시 재spawn은 **서킷 브레이커**로 통제된다: T초 내 N회 kill이면 **영구 fail-closed deny로 trip**(`plugin.worker.terminated{cause:"respawn-storm"}`, 운영자 reset 필요)하고 재spawn 사이에 **지수 백오프**를 둔다 — 플래핑하는 플러그인이 spawn 폭풍이 될 수 없다.
- `maxPendingCalls`/`maxMessageBytes`와 kill-switch(`plugins.enabled:false`)가 적용된다.

### 2.5 설정 + 감사(호스트 계산 필드만)

- `auth.provider:"plugin"`에 `plugin.isolation: "worker" | "process"`와 `plugin.netEnforcement: "require-permission" | "allow-harness"`(기본 `"require-permission"`)가 추가된다. `normalizeConfig`는 fail-closed로 검증한다: `process`는 `process-isolated` 매니페스트 + capability 허용 목록을 요구하고; `--allow-net` 없는 Node에서의 `require-permission`은 **throw**하며; 호스트 fetch URL(커스텀 플러그인이 키 자료를 필요로 할 때)은 운영자 선언이어야 한다. `worker`-vs-`process` 기본값은 1.0 하위호환을 위해 `worker`로 남지만 **문서는 새 고확신 운영자를 `process` + `require-permission`으로 안내**하며, 선택된 모드는 감사에 기록된다.
- **감사 필드는 호스트 계산/enum 전용(결코 자식 공급 아님).** 수명주기 이벤트에 additive `isolation`, `grants`(**호스트가 계산한** 부여 권한 집합, 플러그인 입력의 에코가 아님), `netEnforcement`가 추가된다 — 모두 고정 enum/호스트 값. 자식 크래시/권한 거부 진단은 `error.message`/자식 출력이 아니라 **고정 reason enum**(`PLUGIN_LOAD_REASONS` 확장)으로 매핑된다(코어 감사 sanitizer는 값이 아니라 키 *이름*으로 거른다 — 자유 텍스트 필드는 자격증명을 해시 체인에 쓸 수 있으므로 모든 새 필드는 허용 목록/enum). 이들은 `plugin.*` 수명주기 이벤트에 있고 frozen 코어 protect-event 스키마 **밖**이므로 1.0 `api-contract.test.mjs` freeze 가드는 영향받지 않는다(이 문서가 *이유*를 명시해 미래 메인테이너가 수명주기 이벤트를 잘못 freeze하지 않도록 한다).

### 2.6 정직한 모델 — 1.1이 닫는 것과 닫지 않는 것

**`--allow-net` Node에서 `process-isolated` + `require-permission`** 의 경우, 악성 서명 플러그인은 봉쇄된다:

- **fs / exec / worker / addons:** 커널 **강제** 거부(`--permission`, 부여 없음); 플러그인은 fs가 전혀 없는 `data:` URL에서 로드된다.
- **network:** 커널 **강제** 거부(`--allow-net` 부재) → **네트워크 통한 자격증명 유출 없음**.
- **stdio / fd:** **차단**(`ignore` + 전용 IPC, 상속 fd 없음) → 로그/stderr 유출 없음.
- **env 비밀:** 정화됨.

**잔여 표면(이 이상으로 과신 금지):** (a) **`--allow-net`이 없는** Node는 **네트워크 봉쇄가 없다** — 운영자가 비-봉쇄 `allow-harness`를 명시 수용하지 않는 한 `process-isolated`는 거기서 fail closed; (b) 정당하게 **`networkEgress:true`** 가 필요한 플러그인은 봉쇄되지 않음; (c) 호스트 fetch SSRF 가드에 **DNS-rebinding** 창이 있음; (d) **자격증명 + 주입된 키 자료가 자식 메모리에** 존재 — core-dump/swap 노출은 범위 밖; (e) `--permission`은 OS 샌드박스가 아니라 Node 런타임 통제 — Node/V8 탈출은 이를 무력화한다. `worker-isolated`(1.0) 모드는 **불변** — 그 trust-only 잔여는 그대로다.

## 3. 명시적 비범위(이후 마이너)
- Classifier/filter 및 crypto 플러그인 로딩(authProvider 전용).
- 라이브 revocation 피드 / CRL; 플러그인 레지스트리.
- `allow-harness` 대체를 실제 봉쇄로 강화(불가능 — `--allow-net` 없는 Node에서는; 답은 `require-permission`).
- Node 권한 모델을 넘는 OS 수준 샌드박싱(seccomp/namespaces/sandbox-exec).
- `worker-isolated` 대체.

## 4. 하위 호환성
Additive + opt-in. `worker-isolated`, injection, 모든 provider 계약, frozen 1.0 API/audit/config 스키마는 불변. `process-isolated`는 새 매니페스트 런타임 + 새 `plugin.isolation`/`plugin.netEnforcement` 설정(기본값은 1.0 동작 보존). `plugin.*` 수명주기 감사 이벤트는 additive 호스트 계산 필드를 얻는다(frozen protect-event 스키마 밖 — 계약 테스트는 영향 없음). `isBlockedAddress`를 코어 node:-only 모듈로 승격하는 것은 additive(satellite들이 재import; 코어는 런타임 의존성 0 유지). 엄격한 1.0 semver상 1.1은 **마이너**.

## 5. 1.1 관계
1.1은 플러그인 샌드박스를 **신뢰 기반**(1.0 worker: 서명자를 신뢰)에서 **capability 강제**(1.1 process: OS/런타임이 서명된 코드를 제한)로, 새 opt-in 모드에 대해 강화하여 가장 많이 인용된 1.0 잔여를 *정직하게* 닫는다 — 첫 초안이 틀렸던 부분(하니스는 봉쇄가 아니다; stdio는 유출 채널이다; fail-closed 기능 탐지) 포함. 의존성 0, fail-closed 코어 약속을 유지한다.

## 6. 위협 모델 & 리스크 레지스터 델타

| 표면(1.1) | 통제 | 잔여 |
|---|---|---|
| 악성 서명 플러그인의 호스트 fs/exec/worker/addons 남용 | `--permission` 자식, **부여 0**, `data:`-URL 로드(fs 없음) | `--permission` Node에서는 없음; V8/Node 탈출은 모든 런타임 통제를 무력화 |
| 네트워크 통한 자격증명 유출 | `--allow-net` **거부**, **fail-closed 기능 탐지**(`require-permission` → 미지원 시 throw) | `--allow-net` 없는 Node → fail closed(또는 명시적 비-봉쇄 `allow-harness`); `networkEgress:true` 플러그인 |
| **stdout/stderr/fd** 통한 자격증명 유출 | `stdio:['ignore','ignore','ignore','ipc']`, 상속 fd 없음, 호스트가 자식 출력을 로깅 안 함 | 실질적으로 없음 |
| `child_process` IPC 통한 object/proto/fd 밀반입 | JSON-문자열 전용 IPC(`serialization:"json"`), null-proto 허용 목록 sanitizer | 실질적으로 없음 |
| 플러그인 주도 SSRF / 아웃바운드 펌프 | 호스트가 가져오는 **운영자 선언** URL만(코어 SSRF 가드), kid-refetch cooldown | 가드의 DNS-rebinding 창 |
| 새 필드 통한 감사 평문 유출 | 호스트 계산/enum 전용 필드, 고정 reason enum, 자식 자유 텍스트 없음 | 실질적으로 없음 |
| Spawn-storm DoS | 워밍 자식 + 서킷 브레이커 + 백오프 | trip된 브레이커는 운영자 reset까지 거부(fail-closed) |

제안 리스크 ID: **P1-SEC-026**(process-isolated capability **강제** — P1-SEC-024의 worker 잔여를 강화: fs/exec/net/stdio가 이제 강제됨), **P1-SEC-027**(호스트 중개 키 자료 + 코어 SSRF 가드). 1.0 P1-SEC-024 행에 "`--allow-net` Node의 `process-isolated`에 대해 1.1에서 강제됨" 주석. 새 §4 제외: `--allow-net` 없는 Node에서의 네트워크 봉쇄(fail-closed), `networkEgress:true` 플러그인, core-dump/swap, OS 수준 탈출.

## 7. 테스트 기준(PR 분해에 매핑)

### 7.1 PR1 — `process-isolated` 런타임(capability + stdio + data-URL + fail-closed net)
- `process-isolated` 모드의 계측된 서명 플러그인은 `fs.readFileSync('/etc/hosts')`가 **거부**되고(`ERR_ACCESS_DENIED`), 자식/worker를 spawn할 수 없으며, **fs 권한이 없다**(`data:` URL에서 로드).
- **Net 레드팀:** `--allow-net` Node에서 플러그인의 `net.connect` / `fetch` / `dns`와 `process.binding('tcp_wrap')` 소켓이 모두 **실패**(커널 거부); `--allow-net`이 **없는** Node에서 `require-permission`인 `createRuntime`는 **생성 시 throw**(fail-closed) — 조용한 하니스 격하가 아님.
- **stdio/fd 레드팀:** 자격증명을 `stdout`/`stderr`/`console.error`/fd3에 쓰는 플러그인은 **호스트가 볼 수 있는 어떤 sink에도 도달하지 못함**(stdio 무시; 호스트는 아무것도 캡처 안 함).
- IPC는 JSON-문자열 전용(핸들/structured-clone 객체 전달 시도는 거부); 로드 게이트 + 적합성 + fail-closed 매트릭스(timeout→kill, sanitizer, 단일 점유, kill-switch)가 프로세스 모드에서 유지; macOS 포함 크로스 플랫폼 실행.

### 7.2 PR2 — 자격증명 봉쇄 + 호스트 중개 키 자료 + 코어 SSRF 가드
- 커스텀 자격증명 플러그인이 원본 자격증명으로 인증하되, net+stdio+fs 거부 하에서 계측된 유출 시도(네트워크 AND stderr AND fd)가 **어떤 sink에도 도달하지 못함**(자격증명이 결코 떠나지 않음을 단언).
- 호스트 중개 fetch가 **승격된 코어** `isBlockedAddress`를 사용(사설/메타데이터 범위로 resolve되는 `jwksUri`는 거부; 플러그인은 URL을 명명하지 않음); kid-refetch cooldown이 아웃바운드 비율을 제한; satellite들은 코어 가드를 import하며 자신의 스위트를 여전히 통과.

### 7.3 PR3 — 기능 탐지 + 수명주기 + 감사 + 1.1.0 릴리스 컷
- `process.allowedNodeEnvironmentFlags` + spawn-probe를 통한 `--allow-net` 탐지가 dev Node에서 정확하고 미지원 시 fail-closed; `netEnforcement` 감사됨; spawn 서킷 브레이커가 respawn 폭풍에 trip(감사함); `normalizeConfig` `plugin.isolation`/`netEnforcement` fail-closed 테스트.
- 수명주기 감사 additive 필드가 호스트 계산/enum 전용(플러그인이 값을 밀반입할 수 없음); 1.0 `api-contract.test.mjs`가 여전히 통과(additive, frozen protect-event 스키마 밖). 위협 모델/리스크 레지스터 델타(P1-SEC-026/027), wiki, README; 코어를 **1.1.0**으로 bump; 검증 게시.

## 8. 제안 PR 분해(스택)
1. **`process-isolated` 런타임** — `createProcessIsolatedAuthProvider`: `data:`-URL 로드(fs 없음), `--permission` 부여-0 spawn, `stdio:['ignore','ignore','ignore','ipc']` + 정화 env, JSON-문자열 IPC, 데이터 최소화 wire + 호스트 신원, fail-closed + stdio/net 레드팀 테스트. → §7.1
2. **자격증명 봉쇄 + 코어 SSRF 가드** — `isBlockedAddress`/`guardedFetch`를 코어 node:-only 모듈로 승격(satellite들이 재import); 호스트 중개 운영자 선언 키 fetch + IPC 주입 + kid cooldown; exfil-blocked + no-SSRF 테스트. → §7.2
3. **기능 탐지 + 수명주기 + 감사 + 1.1.0 컷** — `--allow-net` 탐지 + `netEnforcement`(fail-closed `require-permission` 기본값), 워밍 자식 + 서킷 브레이커, 호스트 계산 감사 필드; `plugin.isolation`/`netEnforcement` 설정; 문서 EN/KO(이 문서, 위협 모델 + 리스크 레지스터 P1-SEC-026/027, 정직한 모델 갱신), wiki, README; 코어 → 1.1.0, 검증 게시. → §7.3
