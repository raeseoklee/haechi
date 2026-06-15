# Haechi 운영 런북 (Day-2)

- 상태: Living document (코어 1.3.x 추적)

Haechi를 프로덕션에서 운영하기 위한 실무 가이드입니다: 배포, 환경변수 오버레이를 통한 설정, health/readiness/metrics 모니터링, 우아한 종료, 백프레셔 튜닝, 그리고 해시 체인을 깨지 않는 audit 로그 회전입니다.

이 문서는 운영 가이드이며 컴플라이언스 보증이 아닙니다. 전체 설정 레퍼런스는 [`configuration.ko.md`](./configuration.ko.md)를, 신뢰 경계는 [`threat-model.ko.md`](./threat-model.ko.md)를 참고하십시오.

## 1. 배포

Haechi는 런타임 의존성이 0인 Node `>=22` 패키지입니다. 리포지토리 루트의 참조용 [`Dockerfile`](../../Dockerfile), [`docker-compose.yml`](../../docker-compose.yml), [`.dockerignore`](../../.dockerignore)가 하드닝된 이미지를 빌드합니다(이 파일들은 npm 타르볼에 포함되지 **않는** 리포지토리 배포 자산입니다). 이미지는:

- Node 22 slim 베이스를 핀으로 고정하고(`engines: ">=22"`와 일치),
- 비루트 `node` 사용자로 실행하며,
- 런타임 파일만 복사하고(`.haechi` 비밀, 테스트, 문서 소스 제외),
- audit 체인 / 키 파일 / 토큰 볼트를 위한 쓰기 가능 `/app/.haechi` 볼륨을 선언하고 나머지 트리는 읽기 전용으로 실행하며,
- `/__haechi/live`에 대한 `HEALTHCHECK`를 제공합니다.

```bash
docker compose up -d        # 참조 스택 빌드 + 실행
docker compose logs -f haechi
```

**TLS + 인증으로 앞단을 보호하십시오.** Haechi는 자체 TLS가 없습니다. 포트는 TLS를 종단하고 인증하는 리버스 프록시(nginx / Caddy / Traefik / API 게이트웨이)에만 공개하고, 원시 Haechi 포트를 공개 인터페이스에 절대 노출하지 마십시오. compose 예제는 바로 이 이유로 호스트 loopback(`127.0.0.1:11016`)에만 공개합니다.

**Loopback 너머 바인딩.** 컨테이너 내부에서는 매핑된 포트가 도달 가능하도록 Haechi가 `0.0.0.0`에 바인딩해야 하며, 이는 `--allow-remote-bind`를 요구합니다(참조 `CMD`가 전달합니다). 호스트에서는 기본 loopback 바인딩을 선호하고 리버스 프록시를 통해 Haechi에 접근하십시오. [Loopback 너머 바인딩](./configuration.ko.md)을 참고하십시오.

## 2. 환경변수 오버레이를 통한 설정

컨테이너 / 12-factor 배포를 위해 **비밀이 아닌 운영 키의 고정 allowlist**를 환경변수로 덮어쓸 수 있습니다. 환경변수 값은 **설정 파일보다 우선**하며 fail-closed로 검증됩니다 — 잘못된 값(잘못된 포트, 알 수 없는 모드)은 프로세스를 조용히 약화시키지 않고 **기동 실패**시킵니다.

| 환경변수 | 설정 키 | 타입 / 값 | 예시 |
|---|---|---|---|
| `HAECHI_PROXY_PORT` | `proxy.port` | 정수 0–65535 | `11016` |
| `HAECHI_PROXY_HOST` | `proxy.host` | 비어 있지 않은 문자열 | `0.0.0.0` |
| `HAECHI_UPSTREAM` | `target.upstream` | URL 문자열 | `http://llm:8000` |
| `HAECHI_MODE` | `mode` | `dry-run` \| `report-only` \| `enforce` | `enforce` |
| `HAECHI_LOG_FORMAT` | `logging.format` | `text` \| `json` | `json` |

**비밀은 설계상 오버레이 대상이 아닙니다.** `keys.*`(로컬 키 파일이나 외부 키 경로), auth 토큰 저장소, 어떤 토큰/비밀에 대한 `HAECHI_*` 변수도 **없습니다**. 비밀은 마운트된 설정 파일에 두거나 **주입된 provider**(`createRuntime(config, { cryptoProvider, authProvider, … })`)로 공급합니다. 비밀을 프로세스 환경에 두면 `/proc`, 크래시 덤프, 오케스트레이터 inspect 출력, 자식 프로세스를 통해 누출될 위험이 있으므로 오버레이 allowlist에서 완전히 제외합니다.

오버레이는 `loadConfig()`에서 파일을 읽은 뒤 `normalizeConfig()` 이전에 적용되므로, 오버레이된 값도 파일에 설정된 값과 동일한 검증을 거칩니다.

## 3. Health, readiness, metrics 스크레이핑

예약된 `/__haechi/*` 프리픽스 아래 인증이 필요 없는 네 개의 라우트로, 인증/바디 읽기 이전에 검사되며 upstream을 절대 프록시하지 않습니다(전체 레퍼런스: [운영 엔드포인트](./configuration.ko.md#운영-엔드포인트)):

| 엔드포인트 | 용도 |
|---|---|
| `GET /__haechi/live` | **Liveness** — 재시작 프로브. 가볍고, 이벤트 루프가 서비스하는 동안 200. |
| `GET /__haechi/ready` | **Readiness** — 트래픽 게이트. **audit sink에 쓸 수 없으면 503**(감사를 못 하는 게이트웨이는 ready가 아님). 로드밸런서/오케스트레이터 readiness 프로브를 여기로 지정하십시오. |
| `GET /__haechi/health` | 하위 호환(`ok` + `mode` + `version`). |
| `GET /__haechi/metrics` | Prometheus 텍스트 노출. `metrics.enabled: false`이면 `404`. |

Prometheus(또는 OpenMetrics 호환 스크레이퍼)로 **`/metrics`를 스크레이프**하십시오:

```yaml
scrape_configs:
  - job_name: haechi
    metrics_path: /__haechi/metrics
    static_configs:
      - targets: ["haechi:11016"]
```

주요 신호: `haechi_requests_total{route,mode,decision}`, `haechi_blocks_total`, `haechi_auth_denied_total`, `haechi_rate_limited_total`, `haechi_overloaded_total`(백프레셔 503), `haechi_upstream_timeout_total`, `haechi_upstream_error_total`, `haechi_response_unprotected_total`, `haechi_internal_error_total`, 그리고 `haechi_request_duration_seconds{route}` 히스토그램.

**텔레메트리 no-PII 불변식.** 모든 메트릭 이름과 **모든 라벨 값**은 경계가 있는 enum(route id / mode / decision class)이며, identity·토큰·탐지 값이 절대 아닙니다. 동일한 불변식이 구조화 로그에도 적용됩니다: `logging.format: json`(또는 `HAECHI_LOG_FORMAT=json`)에서 기동/종료/오류 로그는 `correlationId`와 오류 클래스 이름만 담고 페이로드는 절대 담지 않습니다. `correlationId`는 해당 요청의 audit 이벤트에도 나타나므로, 기록된 오류를 그 audit 추적과 연결할 수 있습니다.

## 4. 우아한 종료

`SIGINT`/`SIGTERM` 시 CLI는 프록시의 `close()`를 호출하고, 이는 **우아하게 드레인**합니다:

1. 새 연결 수락을 멈추고(`server.close()`),
2. idle keep-alive 소켓을 즉시 닫고(`closeIdleConnections()`),
3. in-flight 요청이 끝날 때까지 기다리고,
4. 유예 기간(`limits.shutdownGraceMs`, 기본 10000ms) 후 남은 소켓을 강제 종료하여(`closeAllConnections()`) 멈춘 keep-alive가 종료를 무한정 붙잡지 못하게 합니다.

`close()`는 in-flight 요청이 빠지거나 유예가 지나면 resolve합니다. 오케스트레이터의 `terminationGracePeriod`(쿠버네티스) / `stop_grace_period`(compose)를 `limits.shutdownGraceMs`보다 **크게** 설정하여 플랫폼이 드레인 도중 SIGKILL하지 않게 하십시오. 가장 긴 허용 in-flight 요청에 맞춰 `limits.shutdownGraceMs`를 튜닝하십시오.

## 5. 백프레셔 튜닝

`limits.maxInFlight`는 동시에 처리되는 요청 수의 전역 상한입니다.

- `0`(기본)은 상한을 비활성화합니다 — 1.1 동작 그대로.
- `> 0`: 현재 in-flight 수가 상한에 도달하면 **새** 요청은 `Retry-After` 헤더(`limits.shutdownGraceMs`에서 유도한 초)와 `{ "error": "haechi_overloaded" }` 바디와 함께, 인증/바디 읽기 **이전에** `503`으로 거부됩니다. 거부마다 `haechi_overloaded_total`이 증가합니다.
- `/__haechi/*` 관측 라우트는 상한에서 **예외**이므로, 포화 상태에서도 liveness와 `/metrics`를 스크레이프할 수 있습니다 — 부하를 떨어내는 *이유*를 여전히 볼 수 있습니다.

`maxInFlight`를 upstream + 호스트가 감당할 수 있는 동시성 근처로 설정하고(`haechi_request_duration_seconds`와 upstream 포화를 관찰), 게이트웨이가 붕괴 대신 깔끔한 503으로 부하를 떨어내도록 여유를 두십시오. 느린 upstream이 슬롯을 무한정 점유하지 못하도록 튜닝된 `limits.upstreamTimeoutMs`와 함께 사용하십시오.

### 튜닝된 타임아웃

`limits.requestTimeoutMs`와 `limits.headersTimeoutMs`는 Node HTTP 서버의 `requestTimeout` / `headersTimeout`에 매핑됩니다. 둘 다 기본값 `null` = Node 서버 기본값을 그대로 둠(옵트인하지 않으면 동작 불변)입니다. slow-loris 류의 느린 요청/헤더 전달을 제한하려면 숫자를 설정하고, `0`은 해당 타임아웃을 비활성화합니다(Node 의미).

## 6. 체인 인지 audit 로그 회전 & 보존

audit 로그는 **SHA-256 해시 체인**입니다(`audit.path`): 각 이벤트의 `auditIntegrity.previousHash`가 이전 이벤트 해시에 연결되므로, 삽입·삭제·수정·재정렬은 `haechi audit-verify` / `verifyAuditChain`로 탐지됩니다. 선택적 **anchor 스트림**(`audit.anchor`)은 체인 헤드를 별도의 append-only 매체에 기록하여 tail truncation(최신 이벤트 삭제)까지 잡아냅니다. [`audit` 개념](./configuration.ko.md#audit)과 위협 모델을 참고하십시오.

**체인을 중간에서 잘라내거나 다시 쓰지 마십시오.** `audit.jsonl`을 제자리에서 truncate하거나 이전 줄을 다시 쓰면 **체인이 깨지고** 검증이 실패합니다(더 나쁘게는 변조 증거가 조용히 사라집니다). **새 세그먼트를 시작**하고 이전 세그먼트를 보존하는 방식으로 회전하십시오:

1. writer를 **멈추거나 정지**시킵니다(우아한 종료, 또는 점검 시간대에 회전). 기본 JSONL sink는 append 방식이므로, 열려 있는 파일을 회전하는 일을 피하는 것입니다.
2. 현재 세그먼트를 **그대로 보존한 채 옆으로 옮깁니다**: `mv .haechi/audit.jsonl .haechi/audit-2026-06-12.jsonl`(대응하는 anchor도: `mv .haechi/audit.anchor.jsonl .haechi/audit-2026-06-12.anchor.jsonl`).
3. Haechi를 재시작하여(또는 `audit.path` / `audit.anchor.path`를 새 파일로 지정하여) **새 세그먼트를 시작**합니다. 새 체인은 `previousHash: null`로 시작합니다 — 독립적으로 검증 가능한 새 체인입니다. 이는 의도된 동작입니다: 각 세그먼트가 자체적으로 검증 가능한 체인이며, 회전 경계를 넘어 체인을 잇지 **않습니다**.
4. 보존된 각 세그먼트를 자체 anchor로 **독립 검증**합니다: `haechi audit-verify --audit .haechi/audit-2026-06-12.jsonl --anchor .haechi/audit-2026-06-12.anchor.jsonl`.
5. 전체 이력이 검증 가능하도록 보존 기간 동안 **이전 세그먼트를 보관**합니다. 가능하면 삭제 대신 append-only / WORM 저장소로 아카이브하십시오. anchor의 방어는 anchor가 별도의 append-only 매체에 존재한다는 전제에 기반합니다.

**보존:** 회전된 각 세그먼트(및 그 anchor)를 요구되는 audit 보존 기간 동안 유지한 뒤 세그먼트 단위로 만료시키십시오 — 세그먼트 내 일부 줄을 절대 부분 삭제하지 마십시오. 토큰 볼트 보존은 독립적이며(`tokenVault.retentionDays`), audit 회전은 토큰을 정리하지 않습니다.

아카이브 파이프라인에 검증 단계를 유지하지 않는 한, 나중에 재검증이 불가능한 방식으로 세그먼트를 압축/암호화하지 **마십시오**. 회전된 세그먼트는 여전히 검증될 때에만 증거로서 유용합니다.

## 7. 프록시 처리량 벤치마크

`npm run bench:throughput`(`scripts/bench-throughput.mjs`)는 동시성 부하에서
프록시가 더하는 요청당 오버헤드를 측정합니다. 결정적인 로컬 **스텁**
OpenAI 호환 업스트림(즉시 응답하는 정해진 답변 — 실제 모델 없음)과 그 앞단의
**실제** Haechi 프록시를 세우고, 고정 크기 워커 풀의 동시 `fetch`로 부하를
구동하여 **req/s**와 **p50/p95/p99/max** 지연(정렬된 표본에 대한 nearest-rank
백분위수)을 보고합니다. 세 가지 시나리오를 실행합니다:

1. 고정 동시성에서의 **처리량 + 지연**(워밍업 배치는 보고 통계에서 제외합니다 —
   JIT/연결 워밍업이 초기 요청을 왜곡하기 때문입니다),
2. **enforce 대 dry-run 오버헤드** — 동일한 부하를 두 모드로 실행하여 지연/처리량
   **델타**를 보고하므로, 보호 비용이 추측이 아닌 측정된 수치가 됩니다,
3. **백프레셔** — 낮은 `limits.maxInFlight`를 버스트로 포화시켜 `503 + Retry-After`와
   `200`의 비율을 보고합니다(실제 응답을 관찰하여 천장이 부하를 흘려보냄을 증명).

```bash
npm run bench:throughput
HAECHI_BENCH_REQUESTS=5000 HAECHI_BENCH_CONCURRENCY=64 npm run bench:throughput
```

노브(env, 매 실행 상단에 출력됨): `HAECHI_BENCH_REQUESTS`(총 요청 수, 기본 2000),
`HAECHI_BENCH_CONCURRENCY`(기본 32), `HAECHI_BENCH_WARMUP`(제외할 워밍업 수, 기본
100), `HAECHI_BENCH_PAYLOAD_KB`(기본 1), `HAECHI_BENCH_MAXINFLIGHT`(백프레셔
시나리오의 천장, 기본 4).

> **수치는 머신 상대적입니다.** 이것은 **루프백, 단일 프로세스, 스텁 업스트림
> 마이크로 벤치마크**입니다: 스텁, 프록시, 부하 생성기가 모두 `127.0.0.1`의 한
> Node 프로세스에서 실행되므로 실제 네트워크도 실제 모델도 없습니다. 수치는 오직
> Haechi가 더하는 오버헤드만 측정하며 머신·Node 버전·부하에 따라 달라집니다.
> 네트워크/하드웨어 처리량 벤치마크가 **아니며** 보장 수치로 인용해서는 **안
> 됩니다**. 이 벤치는 `release:preflight`에서 실행되지 않습니다.

## 8. 빠른 참조

| 작업 | 커맨드 |
|---|---|
| 시작(compose) | `docker compose up -d` |
| Liveness | `curl localhost:11016/__haechi/live` |
| Readiness | `curl localhost:11016/__haechi/ready` |
| Metrics | `curl localhost:11016/__haechi/metrics` |
| 처리량 벤치 | `npm run bench:throughput` |
| 세그먼트 검증 | `haechi audit-verify --audit <seg>.jsonl --anchor <seg>.anchor.jsonl` |
| 우아한 정지 | `docker compose stop` (SIGTERM → 드레인) |

참고: `configVersion` 스탬프와 업그레이드 노트는 [`config-version.ko.md`](./config-version.ko.md)를 참고하십시오.
