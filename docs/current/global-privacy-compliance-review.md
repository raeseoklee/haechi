# Global Privacy and AI Compliance Review

- Status: Draft 0.1
- Date: 2026-06-08
- Product: Haechi

## 1. Summary

Haechi can launch as a Korea-first product, but designing it as a global product requires implementing privacy filtering not as a single ruleset but as `regional privacy profiles`. Global customers care less about which specific data items are detected and more about the following questions:

- Which region's data subjects are involved?
- To which region's model provider, MCP server, agent, or subprocessor is data being sent?
- Is plaintext disclosure required, or is tokenization sufficient?
- Can DSAR, deletion, audit, and DPIA/PIA evidence be produced?
- Does the data include sector-specific data such as PHI, cardholder data, or education/financial data?

## 2. Priority Profiles to Support

| Priority | Profile | Rationale |
|---|---|---|
| P0 | KR-PIPA | Core requirement for the domestic market |
| P0 | EU-GDPR / UK-GDPR | Global privacy benchmark; cross-border transfer requirements |
| P0 | US-CCPA-CPRA | US consumer privacy and sensitive personal information coverage |
| P1 | US-HIPAA | PHI protection for healthcare AI/MCP adoption |
| P1 | PCI-DSS | Card data protection for payment/commerce agents |
| P1 | JP-APPI | Adoption by Japanese users and enterprises |
| P1 | SG-PDPA | APAC regional hub and self-hosted deployments |
| P2 | CA-PIPEDA | Canadian commercial customers |
| P2 | BR-LGPD | Brazil/Latin America market entry |

## 3. Product Requirements Impact

| Area | Globalization impact |
|---|---|
| Privacy detection | Per-country identifier, sensitive category, and sector data fixtures required |
| Custom filtering | Per-customer internal identifiers, internal code names, and proprietary data rules required |
| Policy engine | Region, data subject, provider region, and transfer mechanism used as policy context |
| Encryption | Per-tenant/region/profile key separation required |
| Token vault | DSAR, deletion, retention, and re-identification permission model required |
| MCP/A2A | Region and provider allowlists included in AAD/permissions alongside agent/task/context |
| Logging/audit | Decision records without raw content required, including profile, transfer mechanism, and residency decision |
| Deployment | Local-only, region-locked, and allowed-regions modes required |
| AI governance | EU AI Act role determination, transparency notice, incident log, and AI risk register required |
| Governance/certification | At OSS stage, SECURITY.md, threat model, SBOM, and signed releases are the priority; ISO 27001/27701/42001 and SOC 2 readiness are secondary reference material |
| US expansion | State privacy laws beyond CCPA/CPRA, Washington consumer health data, and HIPAA/PCI operational requirements needed |

## 4. Cross-Border Transfer Design

Haechi does not replace legal contracts. However, it must be able to technically enforce or produce evidence for the following:

| Requirement | Product behavior |
|---|---|
| Region allowlist | Only call model providers/MCP servers/agents in allowed regions |
| Transfer mechanism evidence | Customer-supplied values (SCC, IDTA, adequacy, BCR, consent, etc.) included in decision records |
| Local-only | Block external provider calls for certain profiles |
| Tokenization before transfer | Tokenize direct identifiers before cross-border transmission |
| Encrypted artifact transfer | A2A/MCP artifacts encrypted with task/context-scoped keys before transmission |

## 5. Global Data Categories

| Category | Examples | Default handling |
|---|---|---|
| Direct identifiers | National ID, SSN, passport, driver's license, alien registration | block/tokenize |
| Contact identifiers | Email, phone, address | mask/tokenize |
| Online identifiers | IP, cookie ID, device ID, advertising ID | tokenize/redact |
| Financial data | Bank account, card number, payment token | tokenize/block |
| Health/biometric/genetic | PHI, biometric template, genetic data | block/human-review |
| Children's data | Minor/child-related data | block/human-review |
| Sensitive beliefs/status | Religion, union membership, politics, ethnicity, immigration/citizenship | block/human-review |
| AI-specific | Prompt secrets, tool output PII, RAG snippets, generated artifacts | redact/tokenize/encrypt |

## 6. Global Validation Criteria

- Maintain positive/negative fixtures per region.
- Maintain tenant custom rule positive/negative fixtures and rule lifecycle audits.
- Keep GDPR special category, CCPA sensitive personal information, HIPAA PHI, and PCI card data fixtures separate.
- Test that calls are blocked when the model provider region is outside the allowlist.
- Test that EU/UK/BR profiles deny the region when a transfer mechanism is missing.
- Test that token vault deletion and DSAR export are linked to decision records.
- Run snapshot tests to verify that raw personal data is absent from audit logs.
- Validate EU AI Act role determination table, transparency notice, synthetic content label, and incident records.
- Review whether OSS trust evidence includes SECURITY.md, threat model, SBOM, signed release, and conformance test results.
- Defer ISO/SOC 2 evidence pack to when commercialization or enterprise support is revisited.
- Record US state privacy and Washington consumer health data fixtures or exclusion rationale in the market-expansion matrix.
- HIPAA/PCI sector profiles must include BAA, ePHI audit, SAD storage prohibition, and retention/disposal evidence.

## 7. Official References

- European Commission GDPR overview: https://commission.europa.eu/law/law-topic/data-protection/reform/what-does-general-data-protection-regulation-gdpr-govern_en
- European Commission SCC: https://commission.europa.eu/law/law-topic/data-protection/international-dimension-data-protection/standard-contractual-clauses-scc_en
- EU AI Act: https://eur-lex.europa.eu/eli/reg/2024/1689/oj/eng
- European Commission AI Act overview: https://commission.europa.eu/news-and-media/news/ai-act-enters-force-2024-08-01_en
- NIST AI Risk Management Framework: https://www.nist.gov/itl/ai-risk-management-framework
- NIST Cybersecurity Framework 2.0: https://www.nist.gov/cyberframework
- OWASP Top 10 for LLM Applications 2025: https://genai.owasp.org/resource/owasp-top-10-for-llm-applications-2025/
- OWASP Top 10 for Agentic Applications 2026: https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/
- ISO/IEC 27001:2022: https://www.iso.org/standard/27001
- ISO/IEC 27701:2025: https://www.iso.org/standard/27701
- ISO/IEC 42001:2023: https://www.iso.org/standard/42001
- AICPA SOC Suite of Services: https://www.aicpa-cima.com/resources/landing/system-and-organization-controls-soc-suite-of-services
- California CCPA: https://www.oag.ca.gov/privacy/ccpa
- California CPPA FAQ: https://cppa.ca.gov/faq
- HHS HIPAA Privacy Rule: https://www.hhs.gov/hipaa/for-professionals/privacy/index.html
- HHS HIPAA De-identification: https://www.hhs.gov/hipaa/for-professionals/privacy/special-topics/de-identification/index.html
- NIST Privacy Framework: https://www.nist.gov/privacy-framework
- Japan PPC APPI: https://www.ppc.go.jp/en/legal/
- Singapore PDPC: https://www.imda.gov.sg/About-IMDA/Data-Protection/personal-data-protection
- Canada PIPEDA: https://www.priv.gc.ca/en/privacy-topics/privacy-laws-in-canada/the-personal-information-protection-and-electronic-documents-act-pipeda/pipeda_brief
- Brazil LGPD: https://www.gov.br/anpd/pt-br/centrais-de-conteudo/outros-documentos-e-publicacoes-institucionais/lgpd-en-lei-no-13-709-capa.pdf/view
- PCI DSS: https://www.pcisecuritystandards.org/standards/pci-dss/
