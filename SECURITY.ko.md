# 보안 정책 (Security Policy)

## 범위

이 저장소는 자체 호스팅 보안 툴킷입니다. 컴플라이언스 인증, 법률 의견, 보증 보고서가 아닙니다.

릴리스 리스크 추적은 `docs/current/risk-register-release-gate.md`에서 관리합니다. npm 릴리스 점검은 `npm run release:preflight`를 통과해야 하며, 실제 npm 발행에는 인증된 npm 계정에서의 `npm run release:preflight:npm`이 추가로 필요합니다.

## 지원 버전

현재 `1.x` stable 라인만 범위에 포함됩니다. 1.0부터 public API는 strict semver 하의 frozen 계약이며, 문서화된 deprecation 정책과 공개된 취약점에 대한 in-minor 보안 예외 하나가 함께 적용됩니다(`docs/current/api-stability.md` 참고). 네 개의 `haechi-*` 위성은 pre-1.0으로 유지되며 core와 독립적으로 버저닝됩니다.

## 보고

의심되는 취약점은 저장소 메인테이너에게 비공개로 보고하세요. 보고에는 실제 비밀, 운영 prompt, 고객 데이터, 개인정보를 포함하지 마세요.

## 보안 불변식

- audit 출력에는 원시 민감 payload 값이 들어가서는 안 됩니다. `FORBIDDEN_KEYS`가 원시 prompt, tool-result, secret, PII 값이 audit 로그에 도달하는 것을 방지합니다.
- audit 출력은 로컬 변조 탐지를 위해 SHA-256 hash chain을 가져야 합니다. append-only/별도 미디어에서의 `audit.anchor` head-hash anchoring은 마지막 anchor 이후의 꼬리 절단을 탐지합니다.
- 암호화는 ciphertext를 정규 AAD에 바인딩해야 합니다. 로컬 crypto provider는 소프트웨어 키 파일 위에서 AES-256-GCM을 사용하며, `keys.provider: external`은 주입된 `cryptoProvider`를 요구합니다.
- 정책 집행은 설정이 잘못되었을 때(알 수 없는 `target.type` 포함) 평문 누출보다 차단을 우선해야 합니다(fail-closed).
- 정책은 강해지기만 합니다. preset/action 병합과 privacy profile은 명시적 action을 강화할 수는 있어도 약화할 수는 없습니다(`ACTION_STRENGTH`).
- proxy 리스너는 remote 바인딩이 명시적으로 활성화(`--allow-remote-bind`)되고 배포 환경이 네트워크 접근 통제를 제공하지 않는 한 loopback 전용으로 유지되어야 합니다.
- 스트리밍 응답은 bounded·opt-in으로만 검사됩니다. `streaming.requestMode: "inspect"`는 bounded cross-frame sliding buffer로 SSE/NDJSON을 stream-filter하며, 기본값 `block`은 스트리밍을 fail-closed로 거부하고, `pass-through`는 명시적이고 감사되는 opt-out입니다.
- response protection은 명시적 allow 정책이 설정되지 않는 한 비JSON, 잘못된 JSON, 압축, 대용량 응답에 대해 fail-closed로 처리됩니다.
- 클라이언트 인증을 사용할 수 있습니다. `auth.provider`는 `bearer`(내장 해시 토큰 저장소), `external`(주입된 `authProvider`), `plugin`(서명 + 샌드박스된 `authProvider`) 중 하나입니다. audit 로그의 identity는 keyed-HMAC이며 원시 subject/issuer가 아닙니다. 기본값 `none`은 proxy를 인증 없이 둡니다. 내장 rate limit은 단일 프로세스(프로세스별)입니다.
- token reveal은 기본적으로 비활성화되어야 하며 명시적인 로컬 개발 워크플로에서만 활성화됩니다. reveal/purge 결정은 token id로 감사되며 평문은 기록되지 않습니다.
- 동적 플러그인 실행은 `authProvider` 플러그인에 한해 **좁게** 허용되며, Ed25519 서명, 운영자 trust-anchor allowlist, 버전 pin/floor, revocation, 유효 윈도우로 게이트됩니다. 플러그인은 샌드박스에서 실행됩니다 — `worker_threads` 격리(1.0, 메모리/크래시 격리 + 데이터 최소화) 또는 opt-in `process-isolated`(1.1, `--allow-net` Node에서 fs/net/exec/worker를 커널 거부하는 Node `--permission` 모델 하의 자식, 그렇지 않으면 fail-closed). 플러그인 매니페스트는 capability(예: credential 읽기, 네트워크 egress)를 선언합니다. 그 외 모든 플러그인/provider 종류는 dependency-injection 전용으로 유지됩니다.

## 로컬 개발 키

`haechi init`은 로컬 개발용 `.haechi/dev.keys.json`을 생성합니다. 이 파일은 폐기 가능한 개발 비밀로 취급하세요. 운영 데이터, 공유 환경, 컴플라이언스 증빙, 인터넷 노출 게이트웨이에 재사용하지 마세요.
