# 초기 리서치 요약: 범용 모듈형 구간암호화

- 문서 상태: Archived summary
- 작성일: 2026-06-08
- 범위: 대한민국 구간암호화 시장, 해외/오픈소스 대조군, 모듈형 구간암호화 초기 아이디어

## 1. 초기 문제의식

대한민국 시장의 구간암호화는 금융, 공공, 인증, 키보드보안, PKI, KCMVP 요구와 밀접하게 발전했다. 초기 아이디어는 기존 보안 구성을 이미 사용하는 대상 솔루션에 추가 장착 가능한 모듈형 구간암호화 레이어였다.

이후 방향은 AI, LLM, MCP, A2A, agent 시스템에 특화된 context-aware encryption으로 전환했다. 본 문서는 전환 전 리서치와 판단을 보존하기 위한 아카이브다.

## 2. 국내 솔루션 관찰

| 영역 | 예시 | 관찰 |
|---|---|---|
| PKI/웹 구간암호화 | 한컴위드 AnySign, INILINE CrossWeb, 펜타 iSIGN PKI, 위즈베라 Delfino | 공동인증, 전자서명, 브라우저-서버 구간 암호화, 보안키패드 연동 중심 |
| 모바일/PC E2E | 라온시큐어 Key# Wireless/Biz, TouchEn 계열 | 모바일 PKI, 키보드보안, E2E, PQC 메시지 강조 |
| 서버-서버/전용선 대체 | 이니텍 INISAFE Net, 한컴 xConnect, 드림 SecuTX/TLS for PQC | 금융권 S2S, PKI, HSM/KMS, PQC/TLS 변형 또는 proxy/API 형태 |
| 입력단 보안 | nProtect, TouchEn, ATON Quantum SafePAD | 키 입력, 가상키패드, 모바일 입력 보호 중심 |
| PQC 지향 | 한컴 xConnect PQC, 드림 Magic TLS for PQC, ATON Quantum SafeLine | 국내 시장에서 PQC 메시지가 빠르게 등장 중이나 표준/호환/성능 검증이 핵심 |

## 3. 해외/오픈소스 대조군

| 구분 | 예시 | 관찰 |
|---|---|---|
| ZTNA/SASE | Zscaler, Palo Alto Prisma Access, Cloudflare Zero Trust | 앱 접근 제어와 네트워크 세그멘테이션에 강점 |
| 고속 네트워크 암호화 | Thales High Speed Encryptors | WAN/DC 구간 저지연 암호화 장비 중심 |
| TLS/mTLS/API | Envoy, NGINX, HAProxy, Cloudflare mTLS | 표준 TLS/mTLS 운영 자동화에 강점 |
| VPN/터널 | WireGuard, strongSwan, OpenVPN | 네트워크 레벨 보호에 적합하나 앱 의미 단위 보호는 별도 필요 |
| 서비스 메시 | Istio, Linkerd, SPIFFE/SPIRE | workload identity와 service-to-service mTLS에 적합 |
| KMS/PKI | Vault/OpenBao, EJBCA, Smallstep CA, cloud KMS | 키·인증서 수명주기 자동화에 유리 |

## 4. 초기 모듈형 구간암호화 판단

초기 제품 포지션은 "기존 보안솔루션과 경쟁하지 않고, 보안솔루션을 이미 쓰는 대상 업무/상용 솔루션에 추가 장착되는 암호화 add-on"이었다.

핵심 모듈은 다음으로 정리했다.

- Client/Server SDK
- Gateway/sidecar/proxy adapter
- Protocol adapter
- Policy engine
- CryptoProvider SPI
- KMS/HSM adapter
- Nonce/replay store
- Audit logger
- Integration manifest

## 5. 보안검토에서 도출된 핵심 리스크

- 브라우저 SDK 신뢰 경계
- AEAD nonce/IV 유일성
- envelope algorithm/key confusion
- 복호화 권한과 key-policy binding
- fail-open 평문 누출
- KMS/HSM 장애와 DEK cache
- JSON canonicalization과 field path ambiguity
- replay protection at scale
- audit log integrity
- release signing, SBOM, KCMVP assurance
- protocol boundary confusion
- AI agent task/context confusion

## 6. 방향 전환 이유

AI/LLM/MCP 특화 방향이 더 선명하다고 판단한 이유는 다음과 같다.

- 일반 구간암호화 시장은 국내 기존 벤더와 조달/인증 장벽이 높다.
- AI/agent 시스템은 prompt, tool-call, resource, artifact, context 같은 새로운 민감 데이터 단위를 만든다.
- MCP와 A2A는 JSON-RPC, streaming, task, artifact, agent discovery를 포함해 기존 HTTP field encryption보다 더 특화된 보호 모델이 필요하다.
- LLM observability, replay, trace, RAG, tool-call 로그에서 평문 누출 문제가 크다.
- "모델에게 무엇을 평문으로 공개할지"를 정책화하는 제품은 범용 구간암호화보다 차별화가 쉽다.

## 7. 보존된 초기 산출물

- `prd-modular-segment-encryption.md`
- `srs-modular-segment-encryption.md`
- `security-review-modular-segment-encryption.md`

## 8. 참고 링크

- Hancom AnySign: https://www.hancomwith.com/authentication/pki02.php
- Hancom xConnect: https://www.hancomwith.com/secure/data03.php
- Raon Key# Wireless: https://www.ncloud.com/marketplace/KeyWireless
- Dream Security SecuTX: https://www.dreamsecurity.com/product/data/SecuTX
- INITECH INISAFE Net: https://www.initech.com/html/sub/solu/solu_net.html
- Penta iSIGN PKI: https://www.pentasecurity.co.kr/isign-pki/
- ATON Quantum SafeLine: https://www.atoncorp.com/business/quantum/quantum_safeline
- Model Context Protocol: https://modelcontextprotocol.io/specification/2025-06-18/basic/transports
- A2A Agent2Agent Protocol: https://a2a-protocol.org/latest/specification/
