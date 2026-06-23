# Haechi `configVersion` & 업그레이드 노트

- 상태: Living document (코어 1.7.x 추적)

`configVersion`는 `haechi.config.json`(및 `haechi.config.example.json`) 최상위에 찍히는 단일 정수입니다. 향후 호환성을 깨는 설정 스키마 변경이 구체적으로 게이트할 수 있는 **버전 앵커**로서, 다른 Haechi 빌드가 쓴 설정을 조용히 잘못 읽는 일을 막습니다.

## 동작

- **기본값 / 없음:** `configVersion`를 생략한 설정(예: 스탬프가 생기기 전의 1.1 파일)은 **현재** 버전으로 간주합니다. 필드 추가는 기존 설정에 아무 영향이 없었습니다.
- **현재 버전:** `1`.
- **더 높은/알 수 없는 값은 fail-closed:** 빌드가 이해하는 값보다 **큰** `configVersion`는 로드 시 throw합니다 — *더 새로운* Haechi가 쓴 설정은 이 빌드가 구현하지 않은 의미에 의존할 수 있으므로, 추측 대신 거부합니다. Haechi를 업그레이드하거나, 호환성을 확인한 뒤 스탬프를 낮추십시오.
- **형식이 잘못되면 fail-closed:** 양수 정수가 아닌 `configVersion`는 throw합니다(`configVersion must be a positive integer`).

이는 `normalizeConfig`의 나머지와 동일한 fail-closed 자세입니다: 모호하거나 미래 시점의 설정은 게이트웨이를 약화시키는 대신 멈춥니다.

## 더 높은 버전에 fail-closed인 이유

알 수 없는 설정을 조용히 실행하는 보안 게이트웨이는, 예를 들어 인식하지 못한 미래의 집행 키를 무시하고 운영자 의도보다 약하게 동작할 수 있습니다. 기동을 거부하면 불일치가 즉시 드러나며 "정책은 더 강해질 뿐 / fail closed" 불변식이 유지됩니다.

## 버전 맵

| `configVersion` | 코어 라인 | 노트 |
|---|---|---|
| `1` | 1.0 – 1.7.x | 최초 스탬프. 모든 키는 1.0 frozen 설정 표면(`api-stability.md` §2.4)에 대해 additive입니다. 1.1.x의 additive 키(`logging`, `metrics`, WS4-B의 `limits.maxInFlight` / `limits.shutdownGraceMs` / `limits.requestTimeoutMs` / `limits.headersTimeoutMs`, 그리고 `configVersion` 자체)와 1.2.0 신뢰성 강화 키(`filters.minConfidence` / `filters.allowlist`, `proxy.tls` / `proxy.trustForwardedProto`)는 모두 이전 동작을 기본값으로 합니다. 1.3.0의 추가는 새 키가 아니라 새 *값*입니다 — `target.type`의 `anthropic`/`gemini`, 추가 탐지 타입, `asia-pdpa`/`jp-appi` `privacy.profile` 값입니다. 1.4.0 plugin-signing CLI, 1.5.0 store 시임, 1.6.0 nonce-budget 가시성, 1.7.0 v2 crypto-AAD/freshness 변경은 모두 CLI/API/envelope 동작이며 config key가 아닙니다. 따라서 설정 스키마(및 `configVersion`)는 변경되지 않습니다. 마이그레이션 불필요. |

## 업그레이드

향후 마이너가 설정 키를 추가할 때, 그 키들은 **additive**(이전 동작 기본값)로 유지되고 `configVersion`는 `1`에 머뭅니다 — 조치 불필요. `configVersion`는 의도적인 호환성 파괴 스키마 변경과 함께서만 **올라가며**, 그 변경은 `api-stability.md` §2.2에 따라 메이저 버전 상승과 deprecation 노트도 동반합니다. 그 시점에 이 표에 마이그레이션을 설명하는 행이 추가되며, 더 낮은 버전으로 찍힌 설정은 조용히가 아니라 명시적으로 마이그레이션(또는 호환 규칙으로 읽기)됩니다.

핀 고정: 설정 최상위에 `"configVersion": 1`을 설정하십시오(예제 설정은 이미 그렇게 합니다). 향후 스키마 상승을 넘어 Haechi를 업그레이드하려면, 스탬프를 올리기 전에 대상 버전의 마이그레이션 행을 따르십시오.
