"""Lab 22: API Security & Modern Auth Lab (APIGuard).

OWASP API Security Top 10 vulnerabilities:
- Mission 1: BOLA/IDOR & BFLA (Broken Object & Function Level Authorization)
- Mission 2: GraphQL Introspection & Batching Abuse
- Mission 3: JWT Algorithm Confusion ('none' alg & claim tampering)
"""

import base64
import json
import os
import time
from typing import Any, Dict, List, Optional, Union
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

app = FastAPI(title="VibeHacking APIGuard Lab", version="1.0.0")

# Flags
FLAG_BOLA = os.getenv("LAB_FLAG_BOLA", "FLAG{bola_idor_bfla_api_privilege_escalated_4822}")
FLAG_GRAPHQL = os.getenv("LAB_FLAG_GRAPHQL", "FLAG{graphql_introspection_batching_bypass_7193}")
FLAG_JWT = os.getenv("LAB_FLAG_JWT", "FLAG{jwt_alg_none_jwks_confusion_pwned_8842}")

# Mock DB
ORDERS_DB = {
    "order_1001": {
        "order_id": "order_1001",
        "owner": "alice",
        "items": ["USB Rubber Ducky", "Wi-Fi Pineapple"],
        "total_usd": 189.99,
        "confidential": False,
    },
    "order_1002": {
        "order_id": "order_1002",
        "owner": "bob",
        "items": ["Proxmark3 Rdv4"],
        "total_usd": 299.00,
        "confidential": False,
    },
    "order_9999": {
        "order_id": "order_9999",
        "owner": "ciso_admin",
        "items": ["0-day Exploit Broker Contract - ZeroClick iOS", "Defense Core Vault Keys"],
        "total_usd": 1500000.00,
        "confidential": True,
        "note": "Top secret executive order. BOLA access granted.",
    },
}

USERS_DB = [
    {"id": 1, "username": "alice", "role": "user", "department": "QA"},
    {"id": 2, "username": "bob", "role": "user", "department": "DevOps"},
    {"id": 99, "username": "root_ciso", "role": "admin", "department": "Cyber Defense"},
]

SERVER_SECRET_KEY = "vibe_super_secret_jwt_hmac_key_2026"


# Models
class LoginRequest(BaseModel):
    username: str
    password: str


class OrderLookup(BaseModel):
    order_id: str


def create_mock_jwt(payload: dict, alg: str = "HS256") -> str:
    header = {"typ": "JWT", "alg": alg}
    h_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
    p_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    if alg.lower() == "none":
        return f"{h_b64}.{p_b64}."
    import hmac
    import hashlib
    sig = hmac.new(SERVER_SECRET_KEY.encode(), f"{h_b64}.{p_b64}".encode(), hashlib.sha256).digest()
    s_b64 = base64.urlsafe_b64encode(sig).decode().rstrip("=")
    return f"{h_b64}.{p_b64}.{s_b64}"


def decode_jwt_unverified(token: str) -> tuple[dict, dict, str]:
    parts = token.strip().split(".")
    if len(parts) < 2:
        raise ValueError("Invalid JWT format")
    h_str = parts[0] + "=" * ((4 - len(parts[0]) % 4) % 4)
    p_str = parts[1] + "=" * ((4 - len(parts[1]) % 4) % 4)
    header = json.loads(base64.urlsafe_b64decode(h_str.encode()).decode())
    payload = json.loads(base64.urlsafe_b64decode(p_str.encode()).decode())
    sig = parts[2] if len(parts) > 2 else ""
    return header, payload, sig


@app.get("/api/status")
def get_status():
    return {
        "lab": "Lab 22 - APIGuard: API Security & Modern Auth",
        "status": "ready",
        "port": 8022,
        "missions": [
            {
                "id": "mission1",
                "name": "BOLA / IDOR & BFLA Privilege Escalation",
                "owasp": "API1:2023 Broken Object Level Authorization & API5:2023 Broken Function Level Authorization",
                "target": "Access order_9999 without authorization check, then exploit header to invoke /api/v1/admin/export_users",
            },
            {
                "id": "mission2",
                "name": "GraphQL Introspection & Batching Abuse",
                "owasp": "API8:2023 Security Misconfiguration & Lack of Protection from Automated Threats",
                "target": "Query __schema on /graphql to discover hidden systemSecrets and extract masterApiKey",
            },
            {
                "id": "mission3",
                "name": "JWT Algorithm Confusion ('none' alg) & Privilege Escalation",
                "owasp": "API2:2023 Broken Authentication",
                "target": "Forge a JWT with alg 'none' and claim role: 'admin' to bypass signature verification on /api/v1/auth/jwt_verify",
            },
        ],
        "metrics": {
            "registered_orders": len(ORDERS_DB),
            "users_count": len(USERS_DB),
            "graphql_introspection_enabled": True,
            "jwt_supported_algorithms": ["HS256", "none"],
        },
    }


# Mission 1: BOLA / IDOR & BFLA
@app.post("/api/v1/auth/login")
def login(req: LoginRequest):
    if req.username == "alice" and req.password == "password123":
        token = create_mock_jwt({"sub": "alice", "role": "user", "exp": int(time.time()) + 3600})
        return {"status": "success", "token": token, "user": {"username": "alice", "role": "user"}}
    raise HTTPException(status_code=401, detail="Invalid credentials")


@app.get("/api/v1/orders/{order_id}")
def get_order(order_id: str, request: Request):
    # Vulnerability: No ownership check against current user context!
    order = ORDERS_DB.get(order_id)
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")
    
    res = dict(order)
    if order_id == "order_9999":
        res["hint"] = "BOLA successful! Now escalate to admin function at /api/v1/admin/export_users with header X-Admin-Role: internal_sec"
    return res


@app.get("/api/v1/admin/export_users")
def export_users(
    x_admin_role: Optional[str] = Header(None, alias="X-Admin-Role"),
    x_admin_key: Optional[str] = Header(None, alias="X-Admin-Key"),
):
    # Vulnerability: BFLA relying on client-controlled custom headers
    if x_admin_role == "internal_sec" or x_admin_key == "master_override_key_2026":
        return {
            "status": "success",
            "message": "Admin users exported successfully",
            "users": USERS_DB,
            "flag": FLAG_BOLA,
        }
    raise HTTPException(status_code=403, detail="Forbidden: Admin role header missing or unauthorized")


# Mission 2: GraphQL Introspection & Batching
@app.post("/graphql")
async def graphql_endpoint(request: Request):
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON in GraphQL request")

    # Support batch requests
    is_batch = isinstance(body, list)
    requests = body if is_batch else [body]
    results = []

    for req in requests:
        query = req.get("query", "")
        res = _handle_single_graphql(query)
        results.append(res)

    return JSONResponse(content=results if is_batch else results[0])


def _handle_single_graphql(query: str) -> dict:
    q = query.strip()
    # Introspection query check
    if "__schema" in q or "__type" in q:
        return {
            "data": {
                "__schema": {
                    "types": [
                        {"name": "Query", "kind": "OBJECT", "fields": [
                            {"name": "publicNotice", "type": {"name": "String"}},
                            {"name": "userProfile", "type": {"name": "User"}},
                            {"name": "systemSecrets", "type": {"name": "SecretVault"}, "description": "Internal executive vault - confidential"}
                        ]},
                        {"name": "SecretVault", "kind": "OBJECT", "fields": [
                            {"name": "masterApiKey", "type": {"name": "String"}},
                            {"name": "flag", "type": {"name": "String"}},
                            {"name": "debugEndpoint", "type": {"name": "String"}}
                        ]}
                    ]
                }
            }
        }
    
    # Query systemSecrets
    if "systemSecrets" in q:
        return {
            "data": {
                "systemSecrets": {
                    "masterApiKey": "SEC_GRAPHQL_VIBE_KEY_9921_X",
                    "debugEndpoint": "/internal/debug/v2",
                    "flag": FLAG_GRAPHQL,
                }
            }
        }

    # Query publicNotice
    if "publicNotice" in q:
        return {
            "data": {
                "publicNotice": "System security audit active. Introspection query allowed for debugging."
            }
        }

    return {
        "errors": [{"message": f"Cannot query field on root: {q[:30]}..."}],
        "data": None,
    }


# Mission 3: JWT Algorithm Confusion & Claim Tampering
@app.get("/api/v1/auth/sample_token")
def sample_token():
    token = create_mock_jwt({"sub": "alice", "role": "user", "scope": "read"})
    return {"sample_jwt": token, "tip": "Inspect token at jwt.io, try setting alg to 'none' and role to 'admin'"}


@app.post("/api/v1/auth/jwt_verify")
def jwt_verify(request: Request, authorization: Optional[str] = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or malformed Authorization header")

    token = authorization.split(" ", 1)[1]
    try:
        header, payload, sig = decode_jwt_unverified(token)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"JWT parse error: {str(e)}")

    alg = header.get("alg", "").lower()

    # Vulnerability: Accepts 'none' algorithm without signature verification
    if alg == "none":
        if payload.get("role") in ["admin", "system_admin", "root"]:
            return {
                "status": "authenticated",
                "role": payload.get("role"),
                "admin_access": True,
                "message": "Signature bypassed using 'none' algorithm vulnerability (CVE-2015-9235 style)",
                "flag": FLAG_JWT,
            }
        return {
            "status": "authenticated",
            "role": payload.get("role"),
            "admin_access": False,
            "message": "Token valid under alg: none, but role is not admin",
        }

    # Standard verification for HS256
    import hmac
    import hashlib
    parts = token.split(".")
    data = f"{parts[0]}.{parts[1]}".encode()
    expected_sig = base64.urlsafe_b64encode(
        hmac.new(SERVER_SECRET_KEY.encode(), data, hashlib.sha256).digest()
    ).decode().rstrip("=")

    if sig != expected_sig:
        raise HTTPException(status_code=401, detail="Invalid token signature")

    role = payload.get("role")
    if role in ["admin", "system_admin", "root"]:
        return {
            "status": "authenticated",
            "role": role,
            "admin_access": True,
            "flag": FLAG_JWT,
        }

    return {
        "status": "authenticated",
        "role": role,
        "admin_access": False,
        "message": f"Welcome user {payload.get('sub')}. Escalation required.",
    }


@app.get("/", response_class=HTMLResponse)
def index_page():
    return HTMLResponse(content=INDEX_HTML)


INDEX_HTML = """<!DOCTYPE html>
<html lang="ko">
<head>
  <meta charset="UTF-8">
  <title>VibeHacking Lab 22 - APIGuard: API Security & Modern Auth</title>
  <style>
    :root {
      --bg: #0b0f19;
      --card-bg: #111827;
      --accent: #06b6d4;
      --accent-glow: rgba(6, 182, 212, 0.3);
      --text: #f3f4f6;
      --text-muted: #9ca3af;
      --success: #10b981;
      --danger: #ef4444;
      --border: #1f2937;
    }
    body {
      margin: 0;
      padding: 24px;
      background: var(--bg);
      color: var(--text);
      font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
    }
    header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding-bottom: 20px;
      border-bottom: 1px solid var(--border);
      margin-bottom: 24px;
    }
    h1 {
      margin: 0;
      color: var(--accent);
      font-size: 1.8rem;
      text-shadow: 0 0 10px var(--accent-glow);
    }
    .badge {
      background: rgba(6, 182, 212, 0.15);
      color: var(--accent);
      padding: 4px 12px;
      border-radius: 9999px;
      border: 1px solid var(--accent);
      font-size: 0.85rem;
      font-weight: bold;
    }
    .grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(340px, 1fr));
      gap: 20px;
    }
    .card {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 20px;
      box-shadow: 0 4px 16px rgba(0, 0, 0, 0.4);
    }
    .card h2 {
      margin-top: 0;
      font-size: 1.25rem;
      color: #38bdf8;
      border-bottom: 1px solid #1f2937;
      padding-bottom: 10px;
    }
    button {
      background: var(--accent);
      color: #000;
      border: none;
      padding: 8px 16px;
      border-radius: 6px;
      cursor: pointer;
      font-weight: 600;
      transition: all 0.2s;
    }
    button:hover {
      background: #22d3ee;
      box-shadow: 0 0 12px var(--accent-glow);
    }
    pre {
      background: #030712;
      padding: 12px;
      border-radius: 8px;
      overflow-x: auto;
      font-size: 0.85rem;
      color: #a7f3d0;
      border: 1px solid #111827;
    }
    input, textarea {
      width: 100%;
      box-sizing: border-box;
      background: #030712;
      border: 1px solid var(--border);
      color: #fff;
      padding: 8px;
      border-radius: 6px;
      margin-bottom: 10px;
      font-family: monospace;
    }
    .flag-box {
      background: rgba(16, 185, 129, 0.1);
      border: 1px solid var(--success);
      color: var(--success);
      padding: 10px;
      border-radius: 6px;
      font-weight: bold;
      word-break: break-all;
      margin-top: 10px;
    }
  </style>
</head>
<body>
  <header>
    <div>
      <h1>🛡️ Lab 22: APIGuard — API Security & Modern Auth</h1>
      <p style="color: var(--text-muted); margin: 5px 0 0 0;">OWASP API Security Top 10 • REST BOLA/BFLA • GraphQL Introspection • JWT Tampering</p>
    </div>
    <span class="badge">Port 8022 • Ready</span>
  </header>

  <div class="grid">
    <!-- Mission 1 -->
    <div class="card">
      <h2>🎯 Mission 1: BOLA / IDOR & BFLA</h2>
      <p style="font-size: 0.9rem; color: var(--text-muted);">
        1. 일반 사용자 Alice로 로그인 후 자신의 주문 <code>order_1001</code> 외에 타인의 VIP 주문 <code>order_9999</code>를 BOLA로 조회합니다.<br>
        2. 헤더 <code>X-Admin-Role: internal_sec</code>를 추가하여 <code>/api/v1/admin/export_users</code>를 호출해 관리자 플래그를 획득하세요.
      </p>
      <button onclick="testBOLA()">주문 order_9999 (BOLA) 조회</button>
      <button onclick="testBFLA()" style="margin-left: 8px; background: #f59e0b;">BFLA 관리자 호출</button>
      <pre id="res-m1">// 결과가 여기에 출력됩니다</pre>
    </div>

    <!-- Mission 2 -->
    <div class="card">
      <h2>🔮 Mission 2: GraphQL Introspection</h2>
      <p style="font-size: 0.9rem; color: var(--text-muted);">
        GraphQL 엔드포인트 <code>/graphql</code>의 스키마 인트로스펙션 취약점을 활용하여 숨겨진 <code>systemSecrets</code> 필드를 탐색하고 API 마스터 키와 플래그를 추출하세요.
      </p>
      <textarea id="gql-query" rows="5">query {
  systemSecrets {
    masterApiKey
    flag
  }
}</textarea>
      <button onclick="testGraphQL()">GraphQL 쿼리 전송</button>
      <button onclick="testIntrospection()" style="margin-left: 8px; background: #6366f1; color: #fff;">스키마 인트로스펙션</button>
      <pre id="res-m2">// 결과가 여기에 출력됩니다</pre>
    </div>

    <!-- Mission 3 -->
    <div class="card">
      <h2>🔑 Mission 3: JWT 'none' Algorithm</h2>
      <p style="font-size: 0.9rem; color: var(--text-muted);">
        서버가 JWT 헤더의 <code>"alg": "none"</code> 서명 생략을 허용합니다. 페이로드의 <code>role</code>을 <code>admin</code>으로 변조하여 시스템 최고 권한을 탈취하세요.
      </p>
      <button onclick="fetchSampleJWT()">샘플 토큰 발급</button>
      <button onclick="forgeNoneJWT()" style="margin-left: 8px; background: #ec4899; color: #fff;">'none' 서명 위조 전송</button>
      <pre id="res-m3">// 결과가 여기에 출력됩니다</pre>
    </div>
  </div>

  <script>
    async function testBOLA() {
      const r = await fetch('/api/v1/orders/order_9999');
      const data = await r.json();
      document.getElementById('res-m1').textContent = JSON.stringify(data, null, 2);
    }
    async function testBFLA() {
      const r = await fetch('/api/v1/admin/export_users', {
        headers: { 'X-Admin-Role': 'internal_sec' }
      });
      const data = await r.json();
      document.getElementById('res-m1').textContent = JSON.stringify(data, null, 2);
    }
    async function testGraphQL() {
      const q = document.getElementById('gql-query').value;
      const r = await fetch('/graphql', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({query: q})
      });
      const data = await r.json();
      document.getElementById('res-m2').textContent = JSON.stringify(data, null, 2);
    }
    async function testIntrospection() {
      const q = "{ __schema { types { name fields { name } } } }";
      const r = await fetch('/graphql', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({query: q})
      });
      const data = await r.json();
      document.getElementById('res-m2').textContent = JSON.stringify(data, null, 2);
    }
    async function fetchSampleJWT() {
      const r = await fetch('/api/v1/auth/sample_token');
      const data = await r.json();
      document.getElementById('res-m3').textContent = JSON.stringify(data, null, 2);
    }
    async function forgeNoneJWT() {
      const h = btoa(JSON.stringify({"typ":"JWT","alg":"none"})).replace(/=/g,'');
      const p = btoa(JSON.stringify({"sub":"alice","role":"admin"})).replace(/=/g,'');
      const token = `${h}.${p}.`;
      const r = await fetch('/api/v1/auth/jwt_verify', {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${token}` }
      });
      const data = await r.json();
      document.getElementById('res-m3').textContent = JSON.stringify(data, null, 2);
    }
  </script>
</body>
</html>
"""
