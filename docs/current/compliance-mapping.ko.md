# 컴플라이언스 통제 매핑 & DSAR/Retention 워크플로

- 문서 상태: Living document (WS6 — reliability-hardening-track §WS6)
- 이 문서의 성격: **통제 매핑**이며 컴플라이언스 **인증**이 아닙니다. reliability-hardening-track §5는 인증을 명시적 비목표로 두며, `SECURITY.md` Scope는 이 저장소가 컴플라이언스 인증·법률 의견·보증 보고서가 아님을 밝힙니다. 이 문서는 Haechi 통제를, 운영자가 충족하도록 돕는 *의무 범주*에 매핑합니다 — Haechi를 배포하면 어떤 규제를 준수하게 된다고 주장하지 않습니다.

## 0. 읽는 법

규제 의무(예: "데이터 최소화", "접근 로깅", "정보주체 권리")는 *프로그램* — 사람·프로세스·기술 — 으로 충족됩니다. Haechi는 운영자가 그 프로그램의 LLM/MCP 게이트웨이 경계에 배선하는 하나의 **기술 통제**입니다. 아래에서는 각 의무 **범주**를 이를 지원하는 Haechi 통제에 매핑하며, Haechi가 하는 일과 하지 않는 일의 경계를 기록합니다. 권위 있는 통제 정의는 코드와 `docs/current/threat-model.md`에 있으며, 이 문서는 그것을 매핑할 뿐 재서술하지 않습니다.

## 1. 통제 → 의무 범주 매핑

| 의무 범주 | Haechi 통제 | Haechi의 기여 | 운영자가 여전히 소유 |
|---|---|---|---|
| **데이터 최소화** | 탐지 + redact/mask/tokenize/encrypt/block 파이프라인(`packages/core`, `packages/filter`, `packages/policy`); privacy profile(`kr-pipa`/`eu-gdpr`/`us-general`) | PII/비밀이 모델·도구·로그에 도달하기 전에 제거하거나 가명화하여 최소 필요 데이터만 하류로 흐르게 합니다. tokenization은 값을 vault에만 보관되는 가역 참조로 대체합니다. | 적법 근거 정책, 지역 profile, 어떤 필드가 실제로 필요한지의 선택. |
| **접근 로깅 / 감사성** | SHA-256 hash chain + head anchoring을 가진 audit JSONL(`packages/audit`); request별 `correlationId`; PII 없는 이벤트(`FORBIDDEN_KEYS`) | *어떤 범주*가 탐지되었고, *어떤 action*이 집행되었으며, *어떤*(keyed-hashed) identity인지, *언제*인지를 — 민감 값 자체는 저장하지 않고 — 변조 증거와 함께 기록합니다. | append-only/불변 저장 매체, 로그 전송, retention 일정(§3). |
| **목적 제한 / 접근 통제** | body 읽기 전 auth gate; named policy profile; model allowlist; identity별 rate limit(`packages/proxy`, `packages/auth`) | 누가 게이트웨이를 사용할 수 있고 각 identity가 어떤 모델/연산/쿼터를 받는지를, payload를 읽기 전에 제약합니다. | identity 수명주기, token 발급/폐기 정책, 게이트웨이 너머의 인가 모델. |
| **보관 제한 / retention** | token-vault retention(`tokenVault.retentionDays`, mutation 시 만료 정리); chain-aware audit rotation/retention 절차(`operations-runbook.md` §6) | bounded token 수명과, hash-chain을 보존하는 문서화된 audit rotation/retention 절차. | 법적 요구에 따른 retention 윈도 설정과 rotation 일정 운영. |
| **정보주체 권리(열람 / 삭제)** | token-vault reveal 거버넌스(`revealPolicy`) + purge, 둘 다 token id 기준 audit; §2의 DSAR 워크플로 | reveal/purge 프리미티브와 그 거버넌스/audit이 DSAR 대응의 기술적 빌딩 블록입니다(§2 참고). | 각 요청의 법적 접수, 신원 확인, 결정, 기록 보존. |
| **전송 중 기밀성** | proxy TLS / remote-bind 강화(`proxy.tls` / `proxy.trustForwardedProto`); 기본 loopback(`packages/proxy`) | remote bind는 bearer token + payload를 평문으로 제공할 수 없습니다 — TLS를 종단하거나 검증된 `X-Forwarded-Proto: https` hop 뒤에 있어야 하며, 아니면 기동 시 fail-closed. | 인증서 발급/회전과 네트워크 경계. |
| **무결성 & 변조 증거** | audit hash chain + anchoring; canonical-AAD 결합 암호화(`packages/crypto`); 강화-전용 정책(`ACTION_STRENGTH`) | 변조 증거 audit, AEAD 결합 ciphertext, 조용히 약화될 수 없는 정책 격자. | 키 보관(프로덕션 KMS/HSM은 주입된 `cryptoProvider`이며 절대 코어 아님)과 사고 대응. |
| **처리의 안전성 / 복원력** | fail-closed 집행; depth/byte/encoding 가드; readiness(`/__haechi/ready`) + backpressure(`packages/proxy`, `packages/core`) | 인라인 집행과 fail-closed 가용성 통제가 미보호 payload나 unbounded-consumption 사건의 가능성을 줄입니다. | 용량 계획, 모니터링, 더 넓은 보안 프로그램. |

## 2. DSAR / retention 운영 워크플로

**정보주체 열람/삭제 요청(DSAR)**은 법적/프로세스 워크플로이며, Haechi는 그것이 귀결되는 기술 연산을 제공합니다. 아래 흐름은 요청을 구체적 Haechi 프리미티브에 매핑합니다. **모든 reveal/purge 연산은 token id 기준으로 audit되며(평문 아님)**, `tokenVault.revealPolicy`로 거버넌스됩니다.

### 2.1 열람 요청 (정보주체가 "내 데이터를 무엇을 보유/처리하는가?"라고 물을 때)
1. **위치 파악.** audit 로그로 정보주체에 관련된 이벤트를 찾습니다 — keyed-HMAC `subjectHash`(audit는 원문 subject를 저장하지 않음), `correlationId`, 시간 윈도, 탐지 summary로 매칭합니다. audit는 *어떤 범주*가 처리되고 *어떤 action*이 취해졌는지를 값 없이 알려줍니다.
2. **거버넌스될 때에 한해 token 해석.** 값이 **tokenize**되었다면 가역 참조가 token vault에 있습니다. reveal은 `tokenVault.revealPolicy`로 게이트됩니다:
   - `disabled`(기본): reveal 거부. 이것이 프로덕션 안전 자세입니다 — DSAR 열람 응답은 live reveal이 아니라 audit 메타데이터 + 운영자의 upstream 기록으로 구성합니다.
   - `local-dev`: 명시적 로컬 개발 워크플로에서만 reveal 허용(`haechi token-reveal <token> --allow-dev-reveal`). `--allow-dev-reveal`을 프로덕션 DSAR 절차로 **사용하지 마십시오**(`shared-responsibility.md` §2 참고).
   모든 reveal 결정은 token id 기준으로 audit 로그에 기록됩니다.
3. **응답.** 법적/프로세스 채널을 통해 응답합니다. Haechi는 기술 증거를 제공하고, 운영자가 신원 확인과 응답을 소유합니다.

### 2.2 삭제 요청 (정보주체가 "내 데이터를 삭제하라"고 할 때)
1. **token 매핑 purge.** `haechi token-purge`가 vault 매핑을 제거해 tokenize된 값을 더 이상 reveal할 수 없게 합니다; 만료된 token도 vault mutation 시 자동 정리됩니다. purge 결정은 token id 기준으로 audit됩니다.
2. **retention 윈도 밖의 audit 세그먼트 만료.** `operations-runbook.md` §6에 따라 audit 로그는 세그먼트로 rotation되며, retention은 **세그먼트 전체를 만료**합니다(부분 라인은 hash chain을 깨므로 절대 아님). audit는 의도적으로 **평문 PII를 보유하지 않으므로** — *내용*에 대한 삭제 의무는 대체로 upstream/운영자 저장소에서 충족되며, audit는 keyed-hashed 식별자와 범주 메타데이터만 보유합니다.
3. **upstream 복사본 삭제.** 모델 제공자의 로그, 애플리케이션 DB, 백업은 **Haechi 밖**입니다 — 운영자가 자신의 데이터 맵에 따라 삭제해야 합니다.

### 2.3 retention 운영 (상시)
- **token vault:** `tokenVault.retentionDays` 설정; 만료는 vault mutation 시 정리됩니다.
- **audit 로그:** `operations-runbook.md` §6의 chain-aware rotation 운영 — 유지보수 경계에서 rotation하고, 각 rotation된 세그먼트 **와 그 anchor**를 retention 윈도 동안 보관해 이력이 여전히 검증되게 한 뒤, 세그먼트 전체를 만료합니다. token-vault retention과 audit retention은 독립이며, audit rotation이 token을 purge하지 않습니다.

## 3. 경계 & 비목표 (정직하게)
- 이것은 **매핑**이며, 인증이나 법률 자문이 아닙니다. Haechi 배포가 시스템을 "GDPR/PIPA 등 준수"로 만들지 않습니다.
- Haechi는 **게이트웨이 경계**만 통제합니다. 모델 제공자의 retention, 애플리케이션 저장소, 백업은 운영자 책임입니다(`shared-responsibility.md`).
- 탐지는 regex + validator(ML 없음)이며 문서화된 제외는 유효합니다(`threat-model.md` §4). DSAR/삭제 프로그램은 Haechi가 어떤 값의 *모든* 인스턴스를 잡았다고 가정해서는 안 됩니다.

## 4. 상호 참조
- `docs/current/shared-responsibility.md` — Haechi 대 운영자 책임 매트릭스(DSAR/retention 구분이 거기에 명시됨).
- `docs/current/operations-runbook.md` — §6 chain-aware audit rotation & retention.
- `docs/current/security-whitepaper.md` — OWASP-LLM / NIST-AI-RMF 통제 매핑 + self-pentest.
- `docs/current/threat-model.md` — 제외 항목과 수용된 잔여 위험.
