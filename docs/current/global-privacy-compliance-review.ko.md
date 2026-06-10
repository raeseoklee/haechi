# 글로벌 개인정보/AI 컴플라이언스 검토

- 문서 상태: Draft 0.1
- 작성일: 2026-06-08
- 관련 제품: Haechi

## 1. 결론

Haechi는 한국용 제품으로 시작할 수 있지만, 글로벌 제품으로 설계하려면 개인정보 필터링을 단일 규칙 세트가 아니라 `regional privacy profile`로 구현해야 한다. 글로벌 고객은 어떤 정보가 탐지되었는지보다 더 중요하게 다음 질문을 한다.

- 어느 지역 정보주체의 데이터인가?
- 어느 지역의 model provider, MCP server, agent, subprocessor로 전송되는가?
- 평문 공개가 필요한가, tokenization으로 충분한가?
- DSAR, deletion, audit, DPIA/PIA evidence를 남길 수 있는가?
- sector data, 예: PHI, cardholder data, 교육/금융 데이터가 포함되는가?

## 2. 우선 지원해야 할 프로파일

| 우선순위 | Profile | 이유 |
|---|---|---|
| P0 | KR-PIPA | 국내 시장 기본 요구 |
| P0 | EU-GDPR / UK-GDPR | 글로벌 privacy benchmark, cross-border transfer 요구 |
| P0 | US-CCPA-CPRA | 미국 소비자 privacy와 sensitive personal information 대응 |
| P1 | US-HIPAA | healthcare AI/MCP 도입 시 PHI 보호 |
| P1 | PCI-DSS | 결제/커머스 agent와 card data 보호 |
| P1 | JP-APPI | 일본 사용자/기업 도입 |
| P1 | SG-PDPA | APAC regional hub와 self-hosted 도입 |
| P2 | CA-PIPEDA | 캐나다 상용 고객 |
| P2 | BR-LGPD | 브라질/라틴아메리카 진입 |

## 3. 제품 요구사항 영향

| 영역 | 글로벌화 영향 |
|---|---|
| 개인정보 탐지 | 국가별 identifier, sensitive category, sector data fixture 필요 |
| 커스텀 필터링 | 고객별 내부 식별자, 사내 코드명, proprietary data rule 필요 |
| 정책 엔진 | region, data subject, provider region, transfer mechanism을 context로 사용 |
| 암호화 | tenant/region/profile별 key separation 필요 |
| token vault | DSAR, deletion, retention, re-identification 권한 모델 필요 |
| MCP/A2A | agent/task/context뿐 아니라 region과 provider allowlist를 AAD/권한에 포함 |
| 로그/감사 | 원문 없는 decision record, profile, transfer mechanism, residency decision 필요 |
| 배포 | local-only, region-locked, allowed-regions 모드 필요 |
| AI governance | EU AI Act role 판단, transparency notice, incident log, AI risk register 필요 |
| 관리체계/인증 | OSS 단계에서는 SECURITY.md, threat model, SBOM, signed release가 우선이고 ISO 27001/27701/42001, SOC 2 readiness는 후순위 참고 자료 |
| 미국 확장 | CCPA/CPRA 외 state privacy, Washington consumer health data, HIPAA/PCI 운영요건 필요 |

## 4. Cross-border transfer 설계

Haechi는 법적 계약을 대체하지 않는다. 다만 기술적으로 다음을 강제하거나 증거화할 수 있어야 한다.

| 요구 | 제품 동작 |
|---|---|
| region allowlist | 허용된 model provider/MCP server/agent region만 호출 |
| transfer mechanism evidence | SCC, IDTA, adequacy, BCR, consent 등 고객 제공 값을 decision record에 포함 |
| local-only | 특정 profile에서는 외부 provider 호출 차단 |
| tokenization before transfer | 해외 전송 전 직접식별자 tokenization |
| encrypted artifact transfer | A2A/MCP artifact는 task/context scoped key로 암호화 후 전송 |

## 5. 글로벌 데이터 카테고리

| Category | 예시 | 기본 처리 |
|---|---|---|
| Direct identifiers | national ID, SSN, passport, driver's license, alien registration | block/tokenize |
| Contact identifiers | email, phone, address | mask/tokenize |
| Online identifiers | IP, cookie id, device id, advertising id | tokenize/redact |
| Financial data | bank account, card number, payment token | tokenize/block |
| Health/biometric/genetic | PHI, biometric template, genetic data | block/human-review |
| Children data | minor/child related data | block/human-review |
| Sensitive beliefs/status | religion, union, politics, ethnicity, immigration/citizenship | block/human-review |
| AI-specific | prompt secrets, tool output PII, RAG snippets, generated artifact | redact/tokenize/encrypt |

## 6. 글로벌 검증 기준

- Region별 positive/negative fixture를 유지한다.
- Tenant custom rule positive/negative fixture와 rule lifecycle audit을 유지한다.
- GDPR special category, CCPA sensitive personal information, HIPAA PHI, PCI card data fixture를 분리한다.
- model provider region이 allowlist 밖이면 호출이 차단되는지 테스트한다.
- transfer mechanism 누락 시 EU/UK/BR profile에서 region-deny되는지 테스트한다.
- token vault deletion과 DSAR export가 decision record와 연결되는지 테스트한다.
- audit log에 원문 개인정보가 없는지 snapshot test를 수행한다.
- EU AI Act role 판단표, transparency notice, synthetic content label, incident record를 검증한다.
- OSS trust evidence에 SECURITY.md, threat model, SBOM, signed release, conformance test result가 포함되는지 검토한다.
- ISO/SOC 2 evidence pack은 상용화 또는 enterprise support를 다시 검토할 때 후순위로 작성한다.
- US state privacy와 Washington consumer health data fixture 또는 제외 사유를 market-expansion matrix에 남긴다.
- HIPAA/PCI sector profile은 BAA, ePHI audit, SAD storage prohibition, retention/disposal evidence를 포함한다.

## 7. 공식 참고 자료

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
