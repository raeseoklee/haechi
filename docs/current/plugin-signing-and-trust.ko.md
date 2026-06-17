# 플러그인 서명 & 신뢰 앵커 큐레이션

- 상태: Living document (코어 1.5.x 추적)
- 날짜: 2026-06-17

Haechi의 기본은 **dependency injection**입니다 — `createRuntime(config, providers)`에
`authProvider`를 전달하며, 어떤 코드도 동적으로 로드되지 않습니다. 서명된 플러그인
샌드박스(`auth.provider: "plugin"`)는 그 **opt-in** 예외입니다: 운영자가 자신이 통제하는
키로 서명하고 그 키를 **신뢰 앵커(trust anchor)**로 allowlist한 경우에만 서드파티
`authProvider`를 로드합니다. 이 핵심 통제는 그 신뢰 게이트(Ed25519 서명 + 운영자
allowlist + pin/floor/revocation)이지 샌드박스 격리가 아닙니다 —
[`api-stability.md`](api-stability.md)와 [위협 모델](threat-model.md)을 참고하십시오.

이 런북은 `haechi plugin-*` CLI를 사용한 종단 간 저작 + 큐레이션 흐름입니다. 전체
`auth.plugin.*` 키 레퍼런스는
[`configuration.md`](configuration.md#authplugin-signed-authprovider-sandbox)를
참고하십시오.

## 1. 서명 키쌍 생성

```bash
haechi plugin-keygen --key-id acme-signer --out-dir ./keys
```

- `./keys/acme-signer.key`를 기록합니다 — **개인** 서명 키(PKCS8 PEM, 모드 `0600`).
  오프라인 / 본인의 비밀 저장소에 보관하십시오; Haechi는 런타임에 이를 절대 읽지 않으며
  게이트웨이 호스트에 둘 필요도 없습니다.
- `./keys/acme-signer.pub`를 기록합니다 — **공개** 키(SPKI PEM). 운영자에게 전달하는
  **신뢰 앵커**이며, 커밋/배포해도 안전합니다.
- JSON 출력은 경로와 공개 PEM만 담습니다 — 개인 키 자료는 **절대** 담지 않습니다.

안정적이고 의미 있는 `keyId`를 사용하십시오(설정과 audit 로그에서 앵커를 라벨링합니다).
하나의 서명 키로 여러 플러그인에 서명할 수 있습니다.

## 2. 플러그인 서명

**정확한** entry 파일 바이트에 서명하십시오 — 서명은 `sha256(entry bytes)`에 바인딩되므로,
이후 플러그인 소스에 어떤 편집을 가하든 무효화됩니다.

```bash
haechi plugin-sign ./acme-auth.mjs \
  --key ./keys/acme-signer.key \
  --signer-key-id acme-signer \
  --plugin-id acme-auth \
  --kind authProvider \
  --plugin-version 1.0.0 \
  --core-range ">=1.0.0 <2.0.0" \
  --capabilities '{"readsCredentials":true}' \
  --out acme-auth.signed.json
```

- `authProvider` 플러그인은 **반드시** `readsCredentials: true`를 선언해야 합니다(선언하지
  않으면 코어가 거부합니다). `--capabilities`는 JSON 파일을 읽는 `@path` 형식도 받습니다.
- 개인 키는 `--key` **파일**에서 읽으며, 커맨드 라인에서는 절대 읽지 않습니다(argv의 키는
  셸 히스토리와 프로세스 테이블로 누출됩니다).
- 선택적 `--not-before` / `--not-after`(epoch ms)는 서명 윈도우를 한정합니다.
- 서명된 envelope `{ payload, signerKeyId, alg, signature }`를 `--out`(기본
  `<pluginId>.signed.json`)에 기록합니다.

## 3. 신뢰하기 전에 검증

`plugin-verify`는 런타임이 로드 시점에 수행하는 검증과 **동일한** 검증을 실행하므로,
envelope를 연결하기 전에 그것이 정상인지 확인할 수 있습니다. 이는 **fail closed**입니다: 어떤
거부든 안정적인 `PluginLoadError` 사유(게이트 신호)와 함께 non-zero로 종료합니다; 잘못된
envelope에 대해 `valid:true`를 절대 출력하지 않습니다.

```bash
haechi plugin-verify acme-auth.signed.json \
  --entry ./acme-auth.mjs \
  --anchor ./keys/acme-signer.pub \
  --allow-capability readsCredentials \
  --core-version 1.3.3
```

- `--allow-capability <name>`(반복 가능)는 verifier의 capability allowlist입니다.
  `authProvider`를 검증하려면 **필수**입니다(그 필수 `readsCredentials`는 기본적으로
  allowlist되지 않습니다) — 없으면 fail-closed `capability-not-allowlisted`를 받습니다.
- 앵커는 명시적 `--anchor <pub.pem>`(`--anchor-key-id`와 함께, 기본은 envelope의
  `signerKeyId`)에서 해석하거나, 실행 중인 설정에서
  `--config haechi.config.json`(`auth.plugin.trustAnchors`를 읽음)으로 해석합니다.
- `--pin <entrySha256>`와 `--core-version <v>`는 pin / range 검사를 실행합니다.

흔한 거부 사유: `tampered-entry`(서명 후 entry 편집), `invalid-signature`(잘못된 키 /
변형된 서명), `unknown-signer`(앵커가 allowlist되지 않음), `alg-not-ed25519`,
`expired-window`, `below-version-floor`, `revoked`, `pin-mismatch`,
`capability-not-allowlisted`.

## 4. 신뢰 앵커를 설정에 연결

**공개** 키를 신뢰 앵커로 붙여 넣고 플러그인이 필요로 하는 capability만(그 이상은 안 됨)
정확히 allowlist하십시오:

```jsonc
{
  "auth": {
    "provider": "plugin",
    "plugin": {
      "manifestPath": "acme-auth.signed.json",
      "trustAnchors": [
        { "keyId": "acme-signer", "publicKey": "-----BEGIN PUBLIC KEY-----\n…\n-----END PUBLIC KEY-----\n" }
      ],
      "allowCapabilities": ["readsCredentials"],
      "isolation": "process"
    }
  }
}
```

- `trustAnchors`는 위의 `{keyId, publicKey}` 배열 형식 또는 `{ keyId: publicKey }` 맵을
  받습니다. 키 해석은 **trust-anchor 전용**입니다 — 여기에 나열되지 않은 서명 키는
  `unknown-signer`이며 fail-closed입니다.
- 가능한 곳에서는 기본 `worker`보다 `isolation: "process"`(커널 강제 capability 거부;
  `--allow-net`을 강제하는 Node 필요)를 선호하십시오.
- `plugins.enabled: false`는 어떤 플러그인 생성도 거부하는 전역 kill-switch입니다.

## 5. Rotate, pin, revoke (큐레이션 라이프사이클)

신뢰 앵커는 운영자가 소유합니다 — 의도적으로 큐레이션하십시오:

- **서명 키 rotate.** 새 키를 `plugin-keygen`하고, 그 키로 플러그인을 다시 서명하고, 기존
  앵커와 함께 새 앵커를 `trustAnchors`에 **추가**하십시오. 배포된 모든 플러그인을 다시 서명한
  뒤에 기존 앵커를 제거하십시오. 살아 있는 envelope가 여전히 의존하는 앵커를 조용히
  떨어뜨리지 마십시오(그것은 fail-closed 장애입니다).
- **정확한 빌드를 pin.** `auth.plugin.pin: { version?, entrySha256?, manifestSha256? }`은
  pin된 빌드 외에는 모두 거부합니다 — 악성 업데이트나 rollback에 대한 방어입니다.
  `plugin-sign`이 출력한 `entrySha256`을 사용하십시오.
- **버전 floor 설정.** `auth.plugin.versionFloor: { "<pluginId>": "<min>" }`은 floor
  미만의 어떤 버전도 거부합니다(anti-rollback). 정확한 빌드를 pin하지 않고도 동작합니다.
- **Revoke.** `auth.plugin.revoked: { signerKeyIds?: [...], entrySha256?: [...] }`은
  손상된 서명 키나 특정 불량 빌드를 denylist합니다; revocation은 로드 시점에 fail-closed입니다.
  Revocation은 **다음 로드**(재시작, 또는 살아 있는 플러그인을 강제로 떨어뜨리는 kill-switch)에
  적용됩니다 — 실시간 revocation 피드는 향후 작업입니다(P1-SEC-025 residual).

## 6. 운영자 체크리스트

- [ ] 개인 서명 키는 오프라인 / 비밀 저장소에 보관하고, 게이트웨이 호스트에는 절대 두지 않음.
- [ ] `trustAnchors`에는 공개 키만 있음; `allowCapabilities`는 최소 집합임.
- [ ] 배포 전 `plugin-verify`(일치하는 `--core-version`)로 envelope를 검증함.
- [ ] rotation 계획(add-new-then-remove-old)이 존재하고 프로덕션에는 `pin`/`versionFloor`가 설정됨.
- [ ] 가능한 곳에서는 `--allow-net`을 강제하는 Node에서 `isolation: "process"`.

참고: [`configuration.md`](configuration.md#authplugin-signed-authprovider-sandbox),
[`threat-model.md`](threat-model.md), [`api-stability.md`](api-stability.md).
