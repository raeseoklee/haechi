# Privacy Filtering Policy Draft

- Status: Draft 0.1
- Date: 2026-06-08
- Related product: Haechi

## 1. Purpose

This document defines a draft policy for detecting and handling personal information and high-risk sensitive data before it is passed to models, tools, agents, logs, traces, and replay artifacts in AI/LLM/MCP environments.

Privacy filtering is not a substitute for encryption. Filtering determines whether data is exposed in plaintext; encryption protects data at rest, in transit, and across authorization boundaries. Haechi applies both mechanisms together.

## 2. Filtering Points

| Point | Description | Default Policy |
|---|---|---|
| Pre-model | Filter prompts/messages before calling an LLM provider | Must |
| Post-model | Filter LLM responses before delivering them to users, agents, or tools | Must |
| MCP tool input | Filter MCP tools/call arguments | Must |
| MCP tool output | Filter tool results and resource content | Must |
| RAG input | Filter retrieval queries, snippets, and source metadata | Should |
| A2A message | Filter agent messages, tasks, and artifacts | Should |
| Observability | Filter logs, traces, replays, and metric labels | Must |

## 3. Default Detection Catalog

| Category | Examples | Default Action |
|---|---|---|
| Unique identifiers | Korean RRN, alien registration number, passport number, driver's license number | block or tokenize |
| Sensitive data | Health information, biometric data, genetic data, criminal records, political/union/religious information | block or human-review |
| Contact information | Mobile phone number, telephone number, email, address | mask or tokenize |
| Financial information | Bank account number, card number, card expiry date, CVC-like values | tokenize or block |
| Credentials | Passwords, access tokens, refresh tokens, API keys, private keys | block |
| Customer data | Customer ID, contract number, order number, internal identifiers | tokenize or encrypt |
| AI-specific sensitive data | Secrets in prompts, personal information in tool outputs, personal information in RAG snippets | redact, tokenize, or encrypt |

## 4. Global Regulatory Profiles

Regional default profiles alter the detection catalog, default actions, transfer restrictions, audit fields, and retention policies. This table is a starting point for product policy design and does not substitute for legal counsel.

| Profile | Key Standards | Default Enhancements |
|---|---|---|
| KR-PIPA | Personal information, unique identifiers, sensitive information, security measures | Unique identifier block/tokenize, encryption key management, access logging |
| EU-GDPR | personal data, special categories, pseudonymisation, data minimisation, international transfer | Special category default block/human-review, SCC/adequacy evidence, DPIA evidence |
| UK-GDPR | UK GDPR, IDTA/Addendum, special category data | UK transfer mechanism evidence, enhanced special category handling |
| US-CCPA-CPRA | personal information, sensitive personal information, limit use/disclosure | SPI limit-use flag, consumer request evidence |
| US-HIPAA | PHI, covered entity/business associate, de-identification | PHI default block/tokenize, Safe Harbor style identifier catalog, BAA evidence |
| PCI-DSS | cardholder data, sensitive authentication data | PAN tokenize/mask, CVC block, prohibition on logging payment data |
| JP-APPI | personal information, special care-required personal information, anonymized/pseudonymized information | Special care-required information human-review, cross-border consent/evidence |
| SG-PDPA | consent, purpose limitation, protection, retention, transfer limitation | Purpose binding, transfer limitation evidence |
| CA-PIPEDA | consent, limiting collection/use/disclosure, safeguards, cross-border handling | Consent/purpose evidence, safeguard audit |
| BR-LGPD | personal data, sensitive personal data, international transfer | Enhanced sensitive data handling, ANPD transfer mechanism evidence |

## 5. Global Policy Decision Context

| Context | Description |
|---|---|
| data_subject_region | Inferred or declared region of the data subject |
| controller_region | Region of the customer/controller |
| processor_region | Region where Haechi/processor processes data |
| model_provider_region | Region where the LLM provider processes data |
| transfer_mechanism | SCC, IDTA, adequacy, BCR, consent, local-only, etc. |
| sector_profile | healthcare, payment, finance, education, public sector, etc. |
| lawful_basis_or_purpose | Customer-defined value expressing the processing purpose or legal basis |
| residency_policy | local-only, region-locked, allowed-regions |
| retention_policy | Retention policy for audit and token vault |

## 6. Detection Methods

| Method | Applies To | Requirements |
|---|---|---|
| Deterministic rule | Korean RRN, card number, email, phone number, API key | Rule IDs and versions must be managed. |
| Checksum validation | Korean RRN candidates, card number candidates | Candidates that fail validation receive a lower confidence score. |
| Dictionary | Organization names, internal system names, prohibited terms | Per-tenant dictionaries must be supported. |
| NER/classifier | Names, addresses, medical/health context, sensitive inference | Local-first by default; external transmission requires separate consent or policy. |
| Custom entity rule | Customer-specific identifiers, contract numbers, ticket numbers | Schema and action are defined in policy. |

## 7. Custom Filtering

Default regulatory profiles cannot have full knowledge of a customer's internal data. Haechi must provide per-tenant custom filters as a first-class feature.

### 7.1 Custom Detection Targets

| Target | Examples |
|---|---|
| Internal identifiers | Customer ID, employee ID, membership ID, contract number, order number, ticket number |
| Product/project confidential data | Code names, product launch names, internal roadmap keywords |
| Internal system information | internal hostname, repository name, table name, service name |
| Industry-specific data | Medical chart ID, insurance policy number, invoice number, account alias |
| AI-specific data | prompt template secret, tool name, private skill name, vector collection name |
| Security information | internal API key prefix, service account, private endpoint, secret naming pattern |

### 7.2 Custom Filter DSL Requirements

| Feature | Description |
|---|---|
| regex | Regex-based detection |
| checksum | Customer-defined checksum or validator function |
| dictionary | Per-tenant word/phrase dictionary |
| allowlist | False positive exception handling |
| denylist | Immediate block targets |
| path scope | Scope specification by JSONPath, protobuf field path, MCP method, or A2A part type |
| context condition | Conditions on tenant, app, environment, model provider, region, or purpose |
| action override | Apply a stricter action than the default profile action |
| confidence override | Per-rule confidence calculation or fixed confidence value |
| test fixture | Positive/negative samples with expected actions |

### 7.3 Rule Lifecycle

| Stage | Requirements |
|---|---|
| draft | Rule authors must be able to create drafts without affecting production traffic. |
| validate | Must check schema, regex safety, catastrophic backtracking, and action conflicts. |
| test | False positive/negative rates must be measured using fixtures and shadow traffic. |
| approve | High-risk actions — e.g., block, external classifier, region override — require an approval workflow. |
| publish | Versioned rollout and tenant/app/environment scope are required. |
| monitor | Hit rate, action rate, and override rate must be observable. |
| rollback | Must be able to immediately revert to a previous rule version. |

### 7.4 Priority

Stronger protection takes precedence over weaker protection.

1. Emergency global block rule
2. Legal/regional profile mandatory rule
3. Sector profile mandatory rule
4. Tenant custom rule
5. Application custom rule
6. Allowlist exception
7. Default profile rule

An allowlist must not be able to bypass hard-block entities such as unique identifiers, PHI, card security codes, and secrets.

### 7.5 Custom Rule Examples

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
        - input: "Contract number is CTR-2026-AB12CD34."
          expectedEntity: TENANT_CONTRACT_ID
          expectedAction: tokenize
      negative:
        - input: "CTR-ABCD is a product code."
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

## 8. Processing Actions

| Action | Meaning |
|---|---|
| allow | Permit the detected result. An audit event is still recorded. |
| mask | Retain only some characters and mask the rest. |
| redact | Remove the value and replace it with a placeholder. |
| tokenize | Replace with a recoverable token. Recovery is performed after authorization evaluation. |
| encrypt | Replace with an envelope ciphertext. |
| block | Block the request, response, tool-call, or artifact delivery. |
| human-review | Send to an approval workflow. Do not forward automatically. |
| region-deny | Block due to a regional/transfer policy violation. |
| local-only | Allow local processing only; no calls to external providers. |

## 9. Policy Examples

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

## 10. Audit Events

Audit events must not contain the original plaintext values.

| Field | Description |
|---|---|
| decision_id | Policy decision ID |
| entity_type | Detected entity type |
| rule_id | Rule that was applied |
| confidence | Detection confidence |
| action | Processing action applied |
| source | pre_model, mcp_tool_input, etc. |
| tenant_id_hash | Hash of the tenant identifier |
| agent_id_hash | Hash of the agent identifier |
| request_id | Correlation ID |
| profile | Regional/sector profile applied |
| transfer_mechanism | Transfer mechanism applied |
| residency_decision | Residency policy decision |
| custom_rule_id | Rule ID if a custom rule was applied |
| custom_rule_version | Custom rule version |

## 11. Test Requirements

- Maintain Korean personal information fixtures.
- Maintain fixtures for EU special categories, US sensitive personal information, HIPAA PHI, PCI card data, and Japan/Singapore/Brazil/Canada data.
- Korean RRN, alien registration number, and card number fixtures must include both checksum-positive and checksum-negative cases.
- Positive and negative fixtures are mandatory for each custom rule.
- Check for regex catastrophic backtracking and excessive CPU/memory usage.
- Test that allowlists cannot bypass hard-block entities.
- Maintain fixtures per source: prompt, MCP tool input/output, resource, artifact, and log line.
- Measure false positives and false negatives separately.
- Perform snapshot tests to verify that no original plaintext remains in pre- and post-filtering results.
- When using an external classifier, separately verify that personal information is not transmitted in the classifier request payload.
- Perform negative tests for region-deny, local-only, allowed-regions, and missing transfer-mechanism scenarios.

## 12. Open Questions

- Decide whether high-risk identifiers such as Korean RRNs should be blocked in all environments, or whether tokenization should be permitted in air-gapped or customer-managed-key environments.
- Decide whether name/address detection should rely primarily on deterministic rules or also include NER classifiers.
- Decide whether the privacy filtering confidence threshold should be a global default or configurable per tenant.
- Decide whether filtering results should be described to the LLM via placeholders or removed entirely.
- Decide whether GDPR/UK GDPR transfer mechanisms should be hard-enforced by the product or left to customer-provided evidence validation.
- Decide whether HIPAA/PCI sector profiles should be included in the MVP.
- Decide whether the custom filter DSL should be maintained as a proprietary YAML schema or adopt a limited subset of an existing expression language such as CEL, OPA, or Rego.
- Decide whether customer-provided dictionaries should be encrypted with a product-managed KMS or only with customer-managed keys.

## 13. References

- Korea Personal Information Safety Measures Standards: https://law.go.kr/LSW/admRulInfoP.do?admRulSeq=2100000192069&chrClsCd=010201
- Korea Personal Information Protection Commission Guidelines: https://law.go.kr/LSW/admRulLsInfoP.do?admRulSeq=2100000240116
- KISA Cryptography Usage FAQ: https://seed.kisa.or.kr/kisa/bbs/faq.do
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
