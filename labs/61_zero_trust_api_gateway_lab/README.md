# Lab 61: Zero Trust API Gateway & SPIFFE/SPIRE Workload Defense Lab
(제로 트러스트 API 게이트웨이 & SPIFFE/SPIRE 워크로드 방어 실습 랩)

## 📌 개요 (Overview)
본 랩은 엔터프라이즈 마이크로서비스 및 서비스 메시(Service Mesh) 환경에서 API 게이트웨이와 워크로드 신원 증명을 보호하는 차세대 **Zero Trust Architecture (NIST SP 800-207)** 실전 공방 환경입니다.
Envoy Proxy 기반의 인가 헤더 스푸핑, 비인가 워크로드의 SPIFFE SVID 위조, 토큰 가로채기 기반 Bearer Replay, 그리고 GraphQL AST 복잡도 폭탄(DoW/DoS) 공격을 실시간으로 시뮬레이션하고 이를 완벽하게 차단하는 4단계 심층 방어 체계를 실습합니다.

- **포트:** `8061` (127.0.0.1 바인딩)
- **주요 표준:** NIST SP 800-207 Zero Trust Architecture, RFC 9449 OAuth 2.0 DPoP, SPIFFE/SPIRE Workload API Specification, OWASP API Security Top 10 2023 (API1:2023, API4:2023, API8:2023)

---

## 🏗️ 4단계 실습 구조 (Attack & Defense Stages)

### Stage 1: Envoy WASM Header Smuggling vs Strict mTLS SAN Enforcement
- **공격 (Attack):** 상위 리버스 프록시 또는 미흡한 게이트웨이 필터에서 `X-Authenticated-User: admin` 등 클라이언트가 조작한 식별 헤더를 신뢰하여 권한 상승.
- **방어 (Defense):** Envoy WASM 필터에서 비신뢰 상위 헤더 전면 스트리핑, TCP 연결단에서 클라이언트 인증서의 `SAN URI`(`spiffe://vibe.corp/ns/prod/sa/payment-service`)를 내부 CA 루트와 대조하여 암호학적 상호 인증 강제.
- **플래그:** `FLAG{ENVOY_WASM_MTLS_SAN_VERIFIED_7491}`

### Stage 2: SPIFFE SVID Token Forgery vs SPIRE Workload Attestation
- **공격 (Attack):** 공격자가 임의의 신뢰 도메인(`spiffe://attacker.corp/...`)이나 위조된 클레임으로 SVID 토큰을 생성하여 비인가 서비스로 위장 호출.
- **방어 (Defense):** SPIRE Agent의 커널 cgroup/k8s 네임스페이스 워크로드 증명(Workload Attestation) 검증 및 도메인 일치성(`vibe.corp`) 엄격 검증.
- **플래그:** `FLAG{SPIFFE_SPIRE_SVID_WORKLOAD_ATTESTED_8302}`

### Stage 3: Stolen Bearer Token Replay vs RFC 9449 DPoP Binding
- **공격 (Attack):** 네트워크 도청 또는 로그 유출로 획득한 고권한 Bearer 액세스 토큰을 다른 서비스 엔드포인트에 재사용(Replay).
- **방어 (Defense):** OAuth 2.0 DPoP (Demonstrating Proof-of-Possession, RFC 9449) 강제 적용. HTTP 요청 메서드/URI, 개인키 서명 증명(`dpop_proof`), `jti` 단일 사용 논스 캐시 및 토큰 해시(`ath`) 상호 검증으로 재전송 차단.
- **플래그:** `FLAG{DPOP_RFC9449_PROOF_OF_POSSESSION_BOUND_9154}`

### Stage 4: GraphQL AST Complexity Bomb vs Query Depth & Complexity Limiting
- **공격 (Attack):** 순환 참조 필드 및 깊게 중첩된 객체 트리 질의를 반복하여 게이트웨이 파서 CPU 고갈 및 워커 스레드 풀 마비 (Denial of Wallet).
- **방어 (Defense):** 정적 AST 쿼리 분석기를 통한 최대 중첩 심도 제한 (Depth ≤ 5) 및 토큰/필드 복잡도 예산 제한 (Complexity Score ≤ 100), 클라이언트 SPIFFE ID별 적응형 레이트 리미팅.
- **플래그:** `FLAG{GRAPHQL_AST_DEPTH_COMPLEXITY_CONTAINED_6283}`

---

## 🚀 빠른 시작 (Quick Start)

```bash
# 1. 랩 기동
python3 vhack.py lab start 61

# 2. 웹 콘솔 접속
# 브라우저에서 http://localhost:8061 접속

# 3. 자동 솔버 실행 및 취약점 검증
python3 vhack.py solve 61

# 4. 단위 테스트 실행
pytest labs/61_zero_trust_api_gateway_lab/tests/
```
