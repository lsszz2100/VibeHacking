# Lab 61: Zero Trust API Gateway & SPIFFE/SPIRE Workload Defense Lab

## 📌 Overview
This lab simulates enterprise microservice and service mesh defenses adhering to **NIST SP 800-207 Zero Trust Architecture**.
Practice defending against Envoy Proxy header spoofing, forged SPIFFE SVID workload identities, stolen Bearer token replay attacks, and GraphQL AST complexity bombs across 4 progressive stages.

- **Port:** `8061` (Bound strictly to 127.0.0.1)
- **Standards:** NIST SP 800-207, RFC 9449 OAuth 2.0 DPoP, SPIFFE/SPIRE Workload API Specification, OWASP API Security Top 10 2023

---

## 🏗️ 4-Stage Attack & Defense Architecture

### Stage 1: Envoy WASM Header Smuggling vs Strict mTLS SAN Enforcement
- **Attack:** Spoofed upstream identification headers (e.g., `X-Authenticated-User: admin`) bypass poorly configured proxy filters.
- **Defense:** Envoy WASM filter strips untrusted upstream headers and validates client certificate `SAN URI` against the internal trusted root CA.
- **Flag:** `FLAG{ENVOY_WASM_MTLS_SAN_VERIFIED_7491}`

### Stage 2: SPIFFE SVID Token Forgery vs SPIRE Workload Attestation
- **Attack:** Malicious workloads inject unverified or forged SPIFFE SVID credentials from untrusted domains.
- **Defense:** SPIRE Workload API validates kernel cgroup/Kubernetes pod attestation and enforces trust domain `vibe.corp`.
- **Flag:** `FLAG{SPIFFE_SPIRE_SVID_WORKLOAD_ATTESTED_8302}`

### Stage 3: Stolen Bearer Token Replay vs RFC 9449 DPoP Binding
- **Attack:** Intercepted high-privilege bearer tokens are replayed across lateral microservices.
- **Defense:** RFC 9449 OAuth 2.0 DPoP cryptographically binds the request HTTP method, URI, single-use `jti` nonce, and access token hash (`ath`).
- **Flag:** `FLAG{DPOP_RFC9449_PROOF_OF_POSSESSION_BOUND_9154}`

### Stage 4: GraphQL AST Complexity Bomb vs Query Depth & Complexity Limiting
- **Attack:** Deeply nested recursive queries exhaust gateway parser threads and CPU resources (Denial of Wallet).
- **Defense:** AST static inspection enforces Max Query Depth (≤ 5) and Max Complexity Budget (≤ 100) alongside SPIFFE-based rate limiting.
- **Flag:** `FLAG{GRAPHQL_AST_DEPTH_COMPLEXITY_CONTAINED_6283}`

---

## 🚀 Quick Start

```bash
# 1. Start Lab 61
python3 vhack.py lab start 61

# 2. Access Web Console
# Open http://localhost:8061 in your browser

# 3. Run Automated Solver
python3 vhack.py solve 61

# 4. Run Pytest Suite
pytest labs/61_zero_trust_api_gateway_lab/tests/
```
