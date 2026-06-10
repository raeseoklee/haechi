# 개인정보 필터링 정책 초안

- 문서 상태: Draft 0.1
- 작성일: 2026-06-08
- 관련 제품: Haechi

## 1. 목적

본 문서는 AI/LLM/MCP 환경에서 개인정보와 고위험 민감 데이터를 모델, tool, agent, 로그, trace, replay artifact로 전달하기 전에 탐지하고 처리하는 정책 초안을 정의한다.

개인정보 필터링은 암호화의 대체물이 아니다. 필터링은 평문 공개 여부를 결정하고, 암호화는 저장·전송·권한 경계를 보호한다. Haechi는 두 기능을 함께 적용한다.

## 2. 필터링 지점

| 지점 | 설명 | 기본 정책 |
|---|---|---|
| Pre-model | LLM provider 호출 전 prompt/message 필터링 | Must |
| Post-model | LLM 응답을 사용자, agent, tool에 전달하기 전 필터링 | Must |
| MCP tool input | MCP tools/call arguments 필터링 | Must |
| MCP tool output | tool result와 resource content 필터링 | Must |
| RAG input | retrieval query, snippet, source metadata 필터링 | Should |
| A2A message | agent message, task, artifact 필터링 | Should |
| Observability | log, trace, replay, metric label 필터링 | Must |

## 3. 기본 탐지 카탈로그

| 분류 | 예시 | 기본 액션 |
|---|---|---|
| 고유식별정보 | 주민등록번호, 외국인등록번호, 여권번호, 운전면허번호 | block 또는 tokenize |
| 민감정보 | 건강정보, 생체정보, 유전정보, 범죄경력, 정치/노조/종교 관련 정보 | block 또는 human-review |
| 연락처 | 휴대전화번호, 전화번호, 이메일, 주소 | mask 또는 tokenize |
| 금융정보 | 계좌번호, 카드번호, 카드 유효기간, CVC 유사값 | tokenize 또는 block |
| 인증정보 | 비밀번호, access token, refresh token, API key, private key | block |
| 고객 데이터 | 고객번호, 계약번호, 주문번호, 내부 식별자 | tokenize 또는 encrypt |
| AI 특화 민감정보 | prompt 내 secret, tool output 내 개인정보, RAG snippet 내 개인정보 | redact, tokenize, encrypt |

## 4. 글로벌 규제 프로파일

지역별 기본 프로파일은 탐지 카탈로그, 기본 액션, 전송 제한, 감사 필드, 보존 정책을 바꾼다. 이 표는 제품 정책 설계를 위한 출발점이며 법률 자문을 대체하지 않는다.

| Profile | 주요 기준 | 기본 강화 항목 |
|---|---|---|
| KR-PIPA | 개인정보, 고유식별정보, 민감정보, 안전성 확보조치 | 고유식별정보 block/tokenize, 암호키 관리, 접속기록 |
| EU-GDPR | personal data, special categories, pseudonymisation, data minimisation, international transfer | special category 기본 block/human-review, SCC/adequacy evidence, DPIA evidence |
| UK-GDPR | UK GDPR, IDTA/Addendum, special category data | UK transfer mechanism evidence, special category 강화 |
| US-CCPA-CPRA | personal information, sensitive personal information, limit use/disclosure | SPI limit-use flag, consumer request evidence |
| US-HIPAA | PHI, covered entity/business associate, de-identification | PHI default block/tokenize, Safe Harbor style identifier catalog, BAA evidence |
| PCI-DSS | cardholder data, sensitive authentication data | PAN tokenize/mask, CVC block, payment data logging 금지 |
| JP-APPI | personal information, special care-required personal information, anonymized/pseudonymized information | special care-required 정보 human-review, cross-border consent/evidence |
| SG-PDPA | consent, purpose limitation, protection, retention, transfer limitation | purpose binding, transfer limitation evidence |
| CA-PIPEDA | consent, limiting collection/use/disclosure, safeguards, cross-border handling | consent/purpose evidence, safeguard audit |
| BR-LGPD | personal data, sensitive personal data, international transfer | sensitive data 강화, ANPD transfer mechanism evidence |

## 5. 글로벌 정책 결정 context

| Context | 설명 |
|---|---|
| data_subject_region | 정보주체의 추정 또는 명시 지역 |
| controller_region | 고객/controller 지역 |
| processor_region | Haechi/processor 처리 지역 |
| model_provider_region | LLM provider 처리 지역 |
| transfer_mechanism | SCC, IDTA, adequacy, BCR, consent, local-only 등 |
| sector_profile | healthcare, payment, finance, education, public sector 등 |
| lawful_basis_or_purpose | 처리 목적 또는 법적 근거를 표현하는 고객 정의 값 |
| residency_policy | local-only, region-locked, allowed-regions |
| retention_policy | audit와 token vault 보존 정책 |

## 6. 탐지 방식

| 방식 | 적용 대상 | 요구사항 |
|---|---|---|
| Deterministic rule | 주민등록번호, 카드번호, 이메일, 전화번호, API key | 규칙 ID와 버전을 관리해야 한다. |
| Checksum validation | 주민등록번호 후보, 카드번호 후보 | 유효성 검증 실패 후보는 confidence를 낮춘다. |
| Dictionary | 조직명, 내부 시스템명, 금칙어 | tenant별 dictionary를 지원한다. |
| NER/classifier | 이름, 주소, 의료/건강 문맥, 민감 추론 | local-first를 기본으로 하고 외부 전송 시 별도 동의/정책이 필요하다. |
| Custom entity rule | 고객별 식별자, 계약번호, 티켓번호 | policy에서 schema와 action을 정의한다. |

## 7. 커스텀 필터링

기본 규제 프로파일은 고객 내부 데이터를 충분히 알 수 없다. Haechi는 tenant별 custom filter를 1급 기능으로 제공해야 한다.

### 7.1 커스텀 탐지 대상

| 대상 | 예시 |
|---|---|
| 내부 식별자 | 고객번호, 사번, 멤버십 ID, 계약번호, 주문번호, 티켓번호 |
| 제품/프로젝트 기밀 | 코드명, 제품 출시명, 내부 roadmap keyword |
| 사내 시스템 정보 | internal hostname, repository name, table name, service name |
| 산업 특화 데이터 | 의료 chart id, 보험 증권번호, 송장번호, 계좌 별칭 |
| AI 특화 데이터 | prompt template secret, tool name, private skill name, vector collection name |
| 보안정보 | internal API key prefix, service account, private endpoint, secret naming pattern |

### 7.2 Custom filter DSL 요구사항

| 기능 | 설명 |
|---|---|
| regex | 정규식 기반 탐지 |
| checksum | 고객 정의 checksum 또는 validator 함수 |
| dictionary | tenant별 단어/구문 사전 |
| allowlist | 오탐 예외 처리 |
| denylist | 즉시 차단 대상 |
| path scope | JSONPath, protobuf field path, MCP method, A2A part type 범위 지정 |
| context condition | tenant, app, environment, model provider, region, purpose 조건 |
| action override | 기본 profile action보다 강한 조치 적용 |
| confidence override | rule별 confidence 계산 또는 고정 |
| test fixture | positive/negative sample과 expected action |

### 7.3 Rule lifecycle

| 단계 | 요구사항 |
|---|---|
| draft | rule 작성자는 production traffic에 영향을 주지 않고 초안을 만들 수 있어야 한다. |
| validate | schema, regex safety, catastrophic backtracking, action 충돌을 검사해야 한다. |
| test | fixture와 shadow traffic으로 false positive/negative를 측정해야 한다. |
| approve | 고위험 action, 예: block, external classifier, region override는 승인 절차가 필요하다. |
| publish | versioned rollout과 tenant/app/environment scope가 필요하다. |
| monitor | hit rate, action rate, override rate를 관측해야 한다. |
| rollback | 이전 rule version으로 즉시 되돌릴 수 있어야 한다. |

### 7.4 우선순위

강한 보호가 약한 보호보다 우선한다.

1. Emergency global block rule
2. Legal/regional profile mandatory rule
3. Sector profile mandatory rule
4. Tenant custom rule
5. Application custom rule
6. Allowlist exception
7. Default profile rule

Allowlist는 고유식별정보, PHI, card security code, secret 같은 hard-block entity를 우회할 수 없어야 한다.

### 7.5 커스텀 규칙 예시

```yaml
customRules:
  - id: tenant-contract-id
    version: 3
    owner: privacy-team
    match:
      regex: "\\bCTR-[0-9]{4}-[A-Z0-9]{8}\\b"
      entityType: TENANT_CONTRACT_ID
      scope:
        sources:
          - pre_model
          - mcp_tool_input
          - a2a_artifact
    action: tokenize
    tests:
      positive:
        - input: "계약번호는 CTR-2026-AB12CD34 입니다"
          expectedEntity: TENANT_CONTRACT_ID
          expectedAction: tokenize
      negative:
        - input: "CTR-ABCD는 제품 코드입니다"
          expectedEntity: null

  - id: internal-project-codename
    version: 1
    match:
      dictionaryRef: dict://tenant-a/project-codenames
      caseSensitive: false
    action: block
    appliesTo:
      modelProviderRegionNotIn:
        - local
        - private-cloud
```

## 8. 처리 액션

| 액션 | 의미 |
|---|---|
| allow | 탐지 결과를 허용한다. audit event는 남긴다. |
| mask | 일부 문자만 유지하고 나머지를 마스킹한다. |
| redact | 값을 제거하고 placeholder로 대체한다. |
| tokenize | 복원 가능한 token으로 대체한다. 복원은 권한 평가 후 수행한다. |
| encrypt | envelope ciphertext로 대체한다. |
| block | 요청, 응답, tool-call 또는 artifact 전달을 차단한다. |
| human-review | 승인 workflow로 보낸다. 자동 전달하지 않는다. |
| region-deny | 지역/전송 정책 위반으로 차단한다. |
| local-only | 외부 provider 호출 없이 로컬 처리만 허용한다. |

## 9. 정책 예시

```yaml
profiles:
  active:
    - KR-PIPA
    - EU-GDPR
    - US-CCPA-CPRA

rules:
  - id: kr-unique-id-default
    match:
      entityTypes:
        - KR_RRN
        - KR_ALIEN_REG_NO
        - PASSPORT_NO
        - DRIVER_LICENSE_NO
    action: block
    appliesTo:
      - pre_model
      - mcp_tool_input
      - observability

  - id: contact-info-tokenize
    match:
      entityTypes:
        - EMAIL
        - PHONE
        - ADDRESS
    action: tokenize
    reveal:
      allowedPurposes:
        - customer_support
      requireAudit: true

  - id: tool-output-redact
    match:
      source: mcp_tool_output
      minConfidence: 0.65
    action: redact

  - id: eu-special-category-transfer-guard
    match:
      profiles:
        - EU-GDPR
      entityTypes:
        - HEALTH_DATA
        - BIOMETRIC_ID
        - POLITICAL_OPINION
        - UNION_MEMBERSHIP
      destination:
        modelProviderRegionNotIn:
          - EU
          - EEA
    action: region-deny
    require:
      transferMechanism:
        - adequacy
        - SCC
        - BCR
```

## 10. 감사 이벤트

감사 이벤트는 원문을 포함하지 않아야 한다.

| 필드 | 설명 |
|---|---|
| decision_id | 정책 결정 ID |
| entity_type | 탐지된 entity type |
| rule_id | 적용된 rule |
| confidence | 탐지 confidence |
| action | 적용한 처리 |
| source | pre_model, mcp_tool_input 등 |
| tenant_id_hash | tenant 식별자 hash |
| agent_id_hash | agent 식별자 hash |
| request_id | correlation id |
| profile | 적용된 regional/sector profile |
| transfer_mechanism | 적용된 전송 메커니즘 |
| residency_decision | 지역 정책 결정 |
| custom_rule_id | 커스텀 규칙이 적용된 경우 rule id |
| custom_rule_version | 커스텀 규칙 버전 |

## 11. 테스트 기준

- 한국 개인정보 fixture를 유지한다.
- EU special category, US sensitive personal information, HIPAA PHI, PCI card data, Japan/Singapore/Brazil/Canada fixture를 유지한다.
- 주민등록번호, 외국인등록번호, 카드번호는 checksum positive/negative fixture를 모두 포함한다.
- custom rule별 positive/negative fixture를 필수로 요구한다.
- regex catastrophic backtracking과 과도한 CPU/memory 사용을 검사한다.
- allowlist가 hard-block entity를 우회하지 못하는지 테스트한다.
- prompt, MCP tool input/output, resource, artifact, log line별 fixture를 둔다.
- false positive와 false negative를 별도 측정한다.
- 필터링 전후 결과에 원문이 남지 않는 snapshot test를 수행한다.
- 외부 classifier를 사용할 경우 classifier 요청 payload에 개인정보가 전송되는지 별도 검사한다.
- region-deny, local-only, allowed-regions, transfer-mechanism missing 부정 테스트를 수행한다.

## 12. 미결정 사항

- 주민등록번호 등 고위험 식별자를 모든 환경에서 block할지, 폐쇄망/customer-managed-key 환경에서 tokenization을 허용할지 결정해야 한다.
- 이름/주소 탐지를 deterministic rule 위주로 할지 NER classifier를 포함할지 결정해야 한다.
- 개인정보 필터링 confidence threshold를 global default로 둘지 tenant별로 둘지 결정해야 한다.
- 필터링 결과를 LLM에게 placeholder로 설명할지, 완전히 삭제할지 결정해야 한다.
- GDPR/UK GDPR transfer mechanism을 제품이 hard enforcement할지, customer-provided evidence validation으로 둘지 결정해야 한다.
- HIPAA/PCI sector profile을 MVP에 포함할지 결정해야 한다.
- custom filter DSL을 자체 YAML 스키마로 유지할지, CEL/OPA/Rego 등 기존 표현식을 제한적으로 채택할지 결정해야 한다.
- 고객 제공 dictionary를 제품 관리 KMS로 암호화할지 customer-managed key만 허용할지 결정해야 한다.

## 13. 참고

- 개인정보의 안전성 확보조치 기준: https://law.go.kr/LSW/admRulInfoP.do?admRulSeq=2100000192069&chrClsCd=010201
- 개인정보보호위원회 개인정보보호지침: https://law.go.kr/LSW/admRulLsInfoP.do?admRulSeq=2100000240116
- KISA 암호이용 FAQ: https://seed.kisa.or.kr/kisa/bbs/faq.do
- European Commission GDPR overview: https://commission.europa.eu/law/law-topic/data-protection/reform/what-does-general-data-protection-regulation-gdpr-govern_en
- European Commission SCC: https://commission.europa.eu/law/law-topic/data-protection/international-dimension-data-protection/standard-contractual-clauses-scc_en
- California CCPA: https://www.oag.ca.gov/privacy/ccpa
- HHS HIPAA Privacy Rule: https://www.hhs.gov/hipaa/for-professionals/privacy/index.html
- NIST Privacy Framework: https://www.nist.gov/privacy-framework
- Japan PPC APPI: https://www.ppc.go.jp/en/legal/
- Singapore PDPC: https://www.imda.gov.sg/About-IMDA/Data-Protection/personal-data-protection
- Canada PIPEDA: https://www.priv.gc.ca/en/privacy-topics/privacy-laws-in-canada/the-personal-information-protection-and-electronic-documents-act-pipeda/pipeda_brief
- Brazil LGPD: https://www.gov.br/anpd/pt-br/centrais-de-conteudo/outros-documentos-e-publicacoes-institucionais/lgpd-en-lei-no-13-709-capa.pdf/view
- PCI DSS: https://www.pcisecuritystandards.org/standards/pci-dss/
