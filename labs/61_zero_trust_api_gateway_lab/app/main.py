import hashlib
import time
import re
from typing import Dict, Any, List, Optional
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

app = FastAPI(
    title="ZeroTrustApiGatewayLab",
    description="Enterprise Zero Trust API Gateway & SPIFFE/SPIRE Workload Defense Lab",
    version="1.0.0"
)

# In-memory single-use jti cache for DPoP replay defense
DPOP_JTI_CACHE: set = set()
SPIFFE_TRUST_DOMAIN = "vibe.corp"
TRUSTED_SPIFFE_PREFIX = f"spiffe://{SPIFFE_TRUST_DOMAIN}/"

class Stage1Request(BaseModel):
    proxy_header: str = Field(..., description="Upstream proxy header, e.g. 'X-Authenticated-User: admin'")
    client_cert_san: str = Field("spiffe://vibe.corp/ns/prod/sa/payment-service", description="Client certificate SAN URI")
    mtls_verified: bool = Field(False, description="Whether transport layer mTLS is cryptographically verified")
    use_wasm_mtls_shield: bool = Field(False, description="Enable Envoy WASM mTLS SAN validation and header strip shield")

class Stage2Request(BaseModel):
    spiffe_id: str = Field(..., description="SPIFFE ID, e.g. spiffe://vibe.corp/ns/prod/sa/payment-service")
    workload_token: str = Field(..., description="Workload SVID JWT or secret token")
    use_spire_attestation: bool = Field(False, description="Enable SPIRE Workload API attestation and trust domain verification")

class Stage3Request(BaseModel):
    access_token: str = Field(..., description="Bearer access token")
    dpop_proof: Dict[str, Any] = Field(..., description="DPoP Proof JWT payload: jti, htm, htu, iat")
    http_method: str = Field(..., description="HTTP Method e.g. POST")
    http_uri: str = Field(..., description="HTTP Request URI e.g. /api/v1/transfer")
    use_dpop_enforcement: bool = Field(False, description="Enable RFC 9449 DPoP cryptographic binding and replay check")

class Stage4Request(BaseModel):
    query: str = Field(..., description="GraphQL query string")
    client_spiffe_id: str = Field("spiffe://vibe.corp/ns/prod/sa/frontend", description="Client SPIFFE ID")
    use_ast_complexity_limiter: bool = Field(False, description="Enable GraphQL AST depth and complexity limit defense")


@app.get("/api/status")
def get_status():
    return {
        "lab_id": 61,
        "name": "ZeroTrustApiGatewayLab",
        "service": "Envoy Zero Trust API Gateway & SPIFFE/SPIRE Workload Attestor",
        "port": 8061,
        "trust_domain": SPIFFE_TRUST_DOMAIN,
        "status": "operational",
        "stages": [
            "1. Envoy WASM Header Smuggling vs mTLS SAN Enforcement",
            "2. SPIFFE SVID Token Forgery vs SPIRE Workload Attestation",
            "3. Stolen Bearer Token Replay vs RFC 9449 DPoP Binding",
            "4. GraphQL AST Complexity Bomb vs Query Depth & Rate Limiter"
        ]
    }


@app.post("/api/stage1/envoy-wasm-bypass")
def stage1_envoy_wasm_bypass(req: Stage1Request):
    """
    Stage 1: Envoy WASM Header Injection vs Strict mTLS SAN Enforcement
    """
    if not req.use_wasm_mtls_shield:
        if "admin" in req.proxy_header.lower() or "x-authenticated-user" in req.proxy_header.lower():
            return {
                "status": "vulnerable",
                "breached": True,
                "message": "Envoy WASM filter bypassed: upstream untrusted proxy header blindly accepted.",
                "compromised_role": "admin",
                "attack_vector": "Header Injection / Spoofing (CVE-like upstream header trust)"
            }
        return {
            "status": "unauthorized",
            "breached": False,
            "message": "Header rejected by baseline proxy rules."
        }

    # Shield active: Strip untrusted upstream identity headers, enforce mTLS SAN URI
    if not req.mtls_verified:
        return {
            "status": "blocked",
            "message": "mTLS handshake not verified. Unauthenticated TCP connection terminated at gateway."
        }

    if not req.client_cert_san.startswith(TRUSTED_SPIFFE_PREFIX):
        return {
            "status": "blocked",
            "message": f"Client certificate SAN '{req.client_cert_san}' does not belong to trusted domain '{SPIFFE_TRUST_DOMAIN}'."
        }

    return {
        "status": "defended",
        "breached": False,
        "flag": "FLAG{ENVOY_WASM_MTLS_SAN_VERIFIED_7491}",
        "message": "Untrusted upstream headers stripped. Client authenticated via mTLS X.509 SVID SAN URI.",
        "authenticated_spiffe_id": req.client_cert_san
    }


@app.post("/api/stage2/spiffe-svid-forgery")
def stage2_spiffe_svid_forgery(req: Stage2Request):
    """
    Stage 2: SPIFFE SVID Forgery vs SPIRE Workload Attestation
    """
    if not req.use_spire_attestation:
        if "attacker" in req.spiffe_id or "forged" in req.workload_token.lower():
            return {
                "status": "vulnerable",
                "breached": True,
                "message": "Gateway accepted unverified SPIFFE SVID token without SPIRE attestation.",
                "forged_spiffe_id": req.spiffe_id,
                "attack_vector": "Workload Identity Spoofing"
            }
        return {
            "status": "unauthorized",
            "breached": False,
            "message": "Token rejected by basic format parser."
        }

    # Defense active: Validate SPIFFE ID structure, domain, and token authenticity
    if not req.spiffe_id.startswith(TRUSTED_SPIFFE_PREFIX):
        return {
            "status": "blocked",
            "message": f"Attestation rejected: SPIFFE ID '{req.spiffe_id}' outside trusted domain."
        }

    # Ensure token is valid attested credential (not forged)
    if "forged" in req.workload_token.lower() or "attacker" in req.workload_token.lower() or len(req.workload_token) < 16:
        return {
            "status": "blocked",
            "message": "SPIRE Workload API attestation failed: invalid cryptographic signature or expired token."
        }

    return {
        "status": "defended",
        "breached": False,
        "flag": "FLAG{SPIFFE_SPIRE_SVID_WORKLOAD_ATTESTED_8302}",
        "message": f"Workload attested successfully via SPIRE. Identity: {req.spiffe_id}",
        "verified_claims": {
            "spiffe_id": req.spiffe_id,
            "trust_domain": SPIFFE_TRUST_DOMAIN,
            "attestor": "SPIRE Agent Kernel cgroup & k8s pod validator"
        }
    }


@app.post("/api/stage3/dpop-replay-attack")
def stage3_dpop_replay(req: Stage3Request):
    """
    Stage 3: Stolen Bearer Token Replay vs RFC 9449 DPoP Binding
    """
    if not req.use_dpop_enforcement:
        if len(req.access_token) >= 8:
            return {
                "status": "vulnerable",
                "breached": True,
                "message": "Stolen Bearer token replayed successfully. Gateway has no Proof-of-Possession binding.",
                "attack_vector": "Bearer Token Replay & Man-in-the-Middle Forwarding"
            }
        return {
            "status": "unauthorized",
            "breached": False,
            "message": "Empty or malformed access token."
        }

    # Defense: Enforce RFC 9449 DPoP Proof
    proof = req.dpop_proof
    jti = proof.get("jti")
    htm = proof.get("htm")
    htu = proof.get("htu")
    iat = proof.get("iat", 0)

    if not jti or not htm or not htu:
        return {
            "status": "blocked",
            "message": "Invalid DPoP proof: missing required claims (jti, htm, htu)."
        }

    # Method & URI binding verification
    if htm.upper() != req.http_method.upper():
        return {
            "status": "blocked",
            "message": f"DPoP HTTP method mismatch: proof specifies '{htm}' but request is '{req.http_method}'."
        }

    if htu != req.http_uri:
        return {
            "status": "blocked",
            "message": f"DPoP target URI mismatch: proof specifies '{htu}' but request is '{req.http_uri}'."
        }

    # Freshness check (within 300 seconds)
    now = time.time()
    if abs(now - iat) > 300:
        return {
            "status": "blocked",
            "message": "DPoP proof expired: timestamp outside acceptable 300-second window."
        }

    # Single-use jti replay defense
    if jti in DPOP_JTI_CACHE:
        return {
            "status": "blocked",
            "message": f"DPoP proof replay detected: jti '{jti}' has already been consumed."
        }

    DPOP_JTI_CACHE.add(jti)
    token_ath = hashlib.sha256(req.access_token.encode("utf-8")).hexdigest()[:24]

    return {
        "status": "defended",
        "breached": False,
        "flag": "FLAG{DPOP_RFC9449_PROOF_OF_POSSESSION_BOUND_9154}",
        "message": "DPoP Proof-of-Possession verified and cryptographically bound to request context.",
        "ath_thumbprint": token_ath,
        "consumed_jti": jti
    }


def calculate_graphql_metrics(query: str):
    """
    Calculate nested curly brace depth and field selection complexity
    """
    max_depth = 0
    current_depth = 0
    for ch in query:
        if ch == "{":
            current_depth += 1
            if current_depth > max_depth:
                max_depth = current_depth
        elif ch == "}":
            current_depth = max(0, current_depth - 1)
    
    # Token count estimation for complexity
    tokens = re.findall(r'[a-zA-Z0-9_]+', query)
    complexity_score = len(tokens) * 3 + (max_depth ** 2) * 5
    return max_depth, complexity_score


@app.post("/api/stage4/graphql-ast-bomb")
def stage4_graphql_ast_bomb(req: Stage4Request):
    """
    Stage 4: GraphQL AST Complexity Bomb vs Query Depth & Complexity Limiting
    """
    depth, complexity = calculate_graphql_metrics(req.query)

    if not req.use_ast_complexity_limiter:
        if depth >= 6 or complexity >= 120:
            return {
                "status": "vulnerable",
                "breached": True,
                "message": f"Gateway thread pool exhausted by GraphQL AST complexity bomb (Depth: {depth}, Score: {complexity}).",
                "attack_vector": "Denial of Wallet / Parser CPU Exhaustion"
            }
        return {
            "status": "processed",
            "breached": False,
            "message": "Simple query executed."
        }

    # Defense: Strict Depth Limit <= 5, Complexity <= 100
    if depth > 5:
        return {
            "status": "blocked",
            "message": f"GraphQL query rejected: Depth {depth} exceeds max allowed threshold (5)."
        }

    if complexity > 100:
        return {
            "status": "blocked",
            "message": f"GraphQL query rejected: Complexity score {complexity} exceeds max budget (100)."
        }

    return {
        "status": "defended",
        "breached": False,
        "flag": "FLAG{GRAPHQL_AST_DEPTH_COMPLEXITY_CONTAINED_6283}",
        "message": f"Query inspected and approved within Zero Trust budget (Depth: {depth}, Complexity: {complexity}).",
        "client_spiffe_id": req.client_spiffe_id
    }


@app.get("/", response_class=HTMLResponse)
def index_page():
    return """<!DOCTYPE html>
<html lang="ko">
<head>
  <meta charset="UTF-8">
  <title>Lab 61 — Zero Trust API Gateway & SPIFFE/SPIRE Workload Defense</title>
  <style>
    :root {
      --bg: #0a0e17;
      --card-bg: #111927;
      --border: #1e293b;
      --accent: #00f0ff;
      --accent-hover: #00c8d7;
      --green: #10b981;
      --red: #ef4444;
      --text: #e2e8f0;
      --text-muted: #94a3b8;
    }
    body {
      background: var(--bg);
      color: var(--text);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, monospace;
      margin: 0;
      padding: 24px;
    }
    .header {
      border-bottom: 1px solid var(--border);
      padding-bottom: 16px;
      margin-bottom: 24px;
    }
    .badge {
      display: inline-block;
      padding: 4px 10px;
      border-radius: 4px;
      font-size: 12px;
      font-weight: 700;
      background: rgba(0, 240, 255, 0.15);
      color: var(--accent);
      border: 1px solid var(--accent);
    }
    .grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(360px, 1fr));
      gap: 20px;
    }
    .card {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 20px;
      box-shadow: 0 4px 20px rgba(0,0,0,0.5);
    }
    .card h3 {
      margin-top: 0;
      color: var(--accent);
      font-size: 16px;
    }
    button {
      background: var(--accent);
      color: #000;
      border: none;
      padding: 8px 16px;
      border-radius: 4px;
      font-weight: 700;
      cursor: pointer;
      margin-top: 10px;
    }
    button:hover {
      background: var(--accent-hover);
    }
    .output {
      background: #000;
      border: 1px solid var(--border);
      padding: 10px;
      border-radius: 4px;
      margin-top: 10px;
      font-size: 12px;
      min-height: 48px;
      word-break: break-all;
    }
  </style>
</head>
<body>
  <div class="header">
    <span class="badge">LAB 61</span>
    <h1>🌐 Zero Trust API Gateway & SPIFFE/SPIRE Workload Defense</h1>
    <p style="color: var(--text-muted);">
      Envoy Proxy WASM Header Smuggling · SPIFFE/SPIRE SVID Attestation · RFC 9449 DPoP Replay Defense · GraphQL AST Complexity Bomb
    </p>
  </div>

  <div class="grid">
    <div class="card">
      <h3>Stage 1: Envoy WASM Header Smuggling</h3>
      <p style="font-size: 13px; color: var(--text-muted);">
        Upstream header injection vs Strict mTLS SAN URI Verification
      </p>
      <button onclick="runStage1(false)">공격 실행 (헤더 스푸핑)</button>
      <button onclick="runStage1(true)" style="background: var(--green); color: #fff;">방어 검증 (mTLS SAN 강제)</button>
      <div id="out1" class="output">결과 대기 중...</div>
    </div>

    <div class="card">
      <h3>Stage 2: SPIFFE SVID Token Forgery</h3>
      <p style="font-size: 13px; color: var(--text-muted);">
        Forged Workload Token vs SPIRE Workload API Attestation
      </p>
      <button onclick="runStage2(false)">공격 실행 (위조 SVID 주입)</button>
      <button onclick="runStage2(true)" style="background: var(--green); color: #fff;">방어 검증 (SPIRE 검증)</button>
      <div id="out2" class="output">결과 대기 중...</div>
    </div>

    <div class="card">
      <h3>Stage 3: Stolen Bearer Token Replay</h3>
      <p style="font-size: 13px; color: var(--text-muted);">
        Microservice Token Replay vs RFC 9449 DPoP Cryptographic Binding
      </p>
      <button onclick="runStage3(false)">공격 실행 (토큰 리플레이)</button>
      <button onclick="runStage3(true)" style="background: var(--green); color: #fff;">방어 검증 (DPoP 증명 바인딩)</button>
      <div id="out3" class="output">결과 대기 중...</div>
    </div>

    <div class="card">
      <h3>Stage 4: GraphQL AST Complexity Bomb</h3>
      <p style="font-size: 13px; color: var(--text-muted);">
        Nested Query DoW vs AST Query Depth & Budget Limiting
      </p>
      <button onclick="runStage4(false)">공격 실행 (복잡도 폭탄 주입)</button>
      <button onclick="runStage4(true)" style="background: var(--green); color: #fff;">방어 검증 (AST 심도 제한)</button>
      <div id="out4" class="output">결과 대기 중...</div>
    </div>
  </div>

  <script>
    async function post(url, data) {
      const res = await fetch(url, {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(data)
      });
      return await res.json();
    }

    async function runStage1(shield) {
      const out = document.getElementById('out1');
      out.textContent = "테스트 실행 중...";
      const res = await post('/api/stage1/envoy-wasm-bypass', {
        proxy_header: shield ? "X-Forwarded-For: 10.0.0.1" : "X-Authenticated-User: admin",
        client_cert_san: "spiffe://vibe.corp/ns/prod/sa/payment-service",
        mtls_verified: shield,
        use_wasm_mtls_shield: shield
      });
      out.textContent = JSON.stringify(res, null, 2);
    }

    async function runStage2(shield) {
      const out = document.getElementById('out2');
      out.textContent = "테스트 실행 중...";
      const res = await post('/api/stage2/spiffe-svid-forgery', {
        spiffe_id: shield ? "spiffe://vibe.corp/ns/prod/sa/payment-service" : "spiffe://attacker.corp/ns/evil/sa/exploit",
        workload_token: shield ? "valid_spire_attested_jwt_token_signature_9901" : "forged_malicious_workload_token",
        use_spire_attestation: shield
      });
      out.textContent = JSON.stringify(res, null, 2);
    }

    async function runStage3(shield) {
      const out = document.getElementById('out3');
      out.textContent = "테스트 실행 중...";
      const now = Math.floor(Date.now() / 1000);
      const res = await post('/api/stage3/dpop-replay-attack', {
        access_token: "stolen_bearer_token_xyz_998822",
        dpop_proof: {
          jti: "nonce_unique_" + Math.random().toString(36).substring(2),
          htm: "POST",
          htu: "/api/v1/transfer",
          iat: now
        },
        http_method: "POST",
        http_uri: "/api/v1/transfer",
        use_dpop_enforcement: shield
      });
      out.textContent = JSON.stringify(res, null, 2);
    }

    async function runStage4(shield) {
      const out = document.getElementById('out4');
      out.textContent = "테스트 실행 중...";
      const deepQuery = shield ? "{ user { id name } }" : "{ user { orders { items { product { supplier { warehouse { manager { phone } } } } } } } }";
      const res = await post('/api/stage4/graphql-ast-bomb', {
        query: deepQuery,
        client_spiffe_id: "spiffe://vibe.corp/ns/prod/sa/frontend",
        use_ast_complexity_limiter: shield
      });
      out.textContent = JSON.stringify(res, null, 2);
    }
  </script>
</body>
</html>
"""

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8061, reload=True)
