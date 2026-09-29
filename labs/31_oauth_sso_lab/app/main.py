"""
Lab 31: SSOShield - OAuth 2.0 / OIDC & Modern SSO Exploitation Lab
FastAPI service exposing vulnerable and hardened OAuth 2.0 / OpenID Connect workflows:
1. Loose Regex Redirect URI Bypass & Auth Code Leakage
2. PKCE Downgrade & Code Verifier Omission Attack
3. IdP JWT Key Confusion / 'kid' Header Injection & Admin Takeover
"""

import base64
import hashlib
import json
import os
import re
import secrets
import time
from typing import Any, Dict, List, Optional

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI, HTTPException, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

app = FastAPI(
    title="SSOShield - OAuth 2.0 & OIDC Exploitation Lab",
    description="Hands-on Lab 31: OAuth 2.0 / OIDC modern authentication vulnerabilities and defenses.",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -----------------------------------------------------------------------------
# Cryptographic Keys for IdP
# -----------------------------------------------------------------------------
# Generate in-memory RSA keypair for standard RS256 signing
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

pem_private = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
).decode("utf-8")

pem_public = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
).decode("utf-8")

KEY_ID_IDP = "idp-primary-rsa-2026"
ATTACKER_SECRET = "attacker_controlled_hmac_secret_key_1337"

# -----------------------------------------------------------------------------
# In-Memory State
# -----------------------------------------------------------------------------
FLAGS = {
    "step1": "FLAG{OAUTH_REDIRECT_URI_LEAK_7712}",
    "step2": "FLAG{OAUTH_PKCE_DOWNGRADE_CSRF_8823}",
    "step3": "FLAG{OAUTH_IDTOKEN_KEY_CONFUSION_9934}"
}

DEFAULT_CLIENTS = {
    "corp-internal-crm": {
        "client_id": "corp-internal-crm",
        "client_secret": "corp_secret_7721_alpha",
        "name": "Enterprise Internal CRM Portal",
        "redirect_uris": ["https://crm.corp-app.com/oauth/callback"],
        "loose_pattern": r"^https?://.*corp-app\.com.*"
    }
}

DEFAULT_USERS = {
    "alice": {
        "username": "alice",
        "role": "member",
        "email": "alice@corp-app.com",
        "name": "Alice Developer"
    },
    "bob": {
        "username": "bob",
        "role": "security_auditor",
        "email": "bob@corp-app.com",
        "name": "Bob Security"
    },
    "admin": {
        "username": "admin",
        "role": "enterprise_admin",
        "email": "admin@corp-app.com",
        "name": "Enterprise System Administrator"
    }
}

class LabState:
    def __init__(self):
        self.reset()

    def reset(self):
        self.clients = dict(DEFAULT_CLIENTS)
        self.users = dict(DEFAULT_USERS)
        self.auth_codes: Dict[str, Dict[str, Any]] = {}
        self.issued_tokens: Dict[str, Dict[str, Any]] = {}
        self.captured_codes: List[Dict[str, Any]] = []
        self.solved_steps = {"step1": False, "step2": False, "step3": False}
        self.hardened = False
        self.strict_redirect_validation = False
        self.enforce_pkce_s256 = False
        self.verify_state_nonce = False
        self.verify_jwks_pinning = False

state = LabState()

# -----------------------------------------------------------------------------
# Models
# -----------------------------------------------------------------------------
class RedirectBypassRequest(BaseModel):
    client_id: str
    redirect_uri: str
    target_user: Optional[str] = "admin"
    state_param: Optional[str] = None

class PKCEDowngradeRequest(BaseModel):
    auth_code: str
    client_id: str
    client_secret: Optional[str] = None
    code_verifier: Optional[str] = None
    omit_verifier: Optional[bool] = True

class KeyConfusionRequest(BaseModel):
    target_user: Optional[str] = "admin"
    kid_header: Optional[str] = "attacker-hmac-key"
    signature_algorithm: Optional[str] = "HS256"
    forged_role: Optional[str] = "enterprise_admin"

# -----------------------------------------------------------------------------
# Helper Utilities
# -----------------------------------------------------------------------------
def b64url_sha256(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")

def generate_id_token(user_info: Dict[str, Any], client_id: str, nonce: Optional[str] = None) -> str:
    now = int(time.time())
    payload = {
        "iss": "http://127.0.0.1:8031/api/oauth",
        "sub": user_info["username"],
        "aud": client_id,
        "exp": now + 3600,
        "iat": now,
        "email": user_info["email"],
        "name": user_info["name"],
        "role": user_info["role"],
    }
    if nonce:
        payload["nonce"] = nonce
    return jwt.encode(payload, pem_private, algorithm="RS256", headers={"kid": KEY_ID_IDP})

# -----------------------------------------------------------------------------
# OIDC Discovery & JWKS
# -----------------------------------------------------------------------------
@app.get("/health")
def health_check():
    return {
        "status": "ok",
        "port": 8031,
        "lab": "SSOShield - OAuth 2.0 & OIDC Exploitation Lab"
    }

@app.get("/api/oauth/.well-known/openid-configuration")
def openid_configuration():
    issuer = "http://127.0.0.1:8031/api/oauth"
    return {
        "issuer": issuer,
        "authorization_endpoint": f"{issuer}/authorize",
        "token_endpoint": f"{issuer}/token",
        "jwks_uri": f"{issuer}/jwks.json",
        "response_types_supported": ["code", "token", "id_token"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256", "HS256"],
        "code_challenge_methods_supported": ["plain", "S256"],
        "scopes_supported": ["openid", "profile", "email", "admin"]
    }

@app.get("/api/oauth/jwks.json")
def jwks_endpoint():
    numbers = public_key.public_numbers()
    def to_b64(n: int, length: Optional[int] = None) -> str:
        b = n.to_bytes((n.bit_length() + 7) // 8, byteorder="big")
        return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")

    return {
        "keys": [
            {
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "kid": KEY_ID_IDP,
                "n": to_b64(numbers.n),
                "e": to_b64(numbers.e)
            }
        ]
    }

@app.get("/api/oauth/info")
def lab_info():
    return {
        "lab_id": 31,
        "name": "SSOShield - OAuth 2.0 & OIDC Exploitation Lab",
        "hardened": state.hardened,
        "security_config": {
            "strict_redirect_validation": state.strict_redirect_validation,
            "enforce_pkce_s256": state.enforce_pkce_s256,
            "verify_state_nonce": state.verify_state_nonce,
            "verify_jwks_pinning": state.verify_jwks_pinning
        },
        "solved_steps": state.solved_steps,
        "active_clients": list(state.clients.keys()),
        "registered_users": list(state.users.keys()),
        "captured_codes_count": len(state.captured_codes)
    }

# -----------------------------------------------------------------------------
# Core OAuth 2.0 Endpoints
# -----------------------------------------------------------------------------
@app.get("/api/oauth/authorize")
def authorize_endpoint(
    response_type: str,
    client_id: str,
    redirect_uri: str,
    scope: str = "openid profile",
    state_param: Optional[str] = None,
    nonce: Optional[str] = None,
    code_challenge: Optional[str] = None,
    code_challenge_method: Optional[str] = None,
    user: Optional[str] = "admin"
):
    if client_id not in state.clients:
        raise HTTPException(status_code=400, detail="Invalid client_id")

    client = state.clients[client_id]

    # Redirect URI validation
    if state.strict_redirect_validation or state.hardened:
        if redirect_uri not in client["redirect_uris"]:
            raise HTTPException(
                status_code=400,
                detail=f"Security Error: redirect_uri '{redirect_uri}' does not match registered whitelist strictly."
            )
    else:
        # Vulnerable loose regex matching
        pattern = client["loose_pattern"]
        if not re.search(pattern, redirect_uri):
            raise HTTPException(
                status_code=400,
                detail=f"Invalid redirect_uri. Must match corporate pattern '{pattern}'"
            )

    # State parameter check in hardened mode
    if (state.verify_state_nonce or state.hardened) and not state_param:
        raise HTTPException(status_code=400, detail="Hardened Mode: 'state' parameter is mandatory to prevent CSRF.")

    # PKCE enforcement check in hardened mode
    if (state.enforce_pkce_s256 or state.hardened):
        if not code_challenge or code_challenge_method != "S256":
            raise HTTPException(
                status_code=400,
                detail="Hardened Mode: PKCE code_challenge with method S256 is strictly enforced."
            )

    # Issue Authorization Code
    code = f"code_{secrets.token_hex(16)}"
    state.auth_codes[code] = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "user": user if user in state.users else "admin",
        "scope": scope,
        "state_param": state_param,
        "nonce": nonce,
        "code_challenge": code_challenge,
        "code_challenge_method": code_challenge_method,
        "created_at": time.time(),
        "used": False
    }

    return {
        "status": "success",
        "redirect_to": f"{redirect_uri}?code={code}&state={state_param or ''}",
        "auth_code": code,
        "user": user
    }

@app.post("/api/oauth/token")
def token_endpoint(request: Request):
    # Support both application/x-www-form-urlencoded and JSON
    # For simplicity, parse JSON if available, otherwise read query/form
    pass

# -----------------------------------------------------------------------------
# Exploit Step 1: Redirect URI Regex Bypass & Code Exfiltration
# -----------------------------------------------------------------------------
@app.post("/api/oauth/exploit/redirect-bypass")
def exploit_redirect_bypass(payload: RedirectBypassRequest):
    """
    Step 1: Exploit loose regex redirect_uri validation to exfiltrate authorization code
    to an attacker-controlled origin (e.g., https://attacker-corp-app.com/callback
    or https://corp-app.com.attacker.evil/steal).
    """
    if state.hardened or state.strict_redirect_validation:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Hardening Active: Strict redirect_uri exact matching is enabled. Regex bypass blocked."
        )

    if payload.client_id not in state.clients:
        raise HTTPException(status_code=400, detail="Unknown client_id")

    client = state.clients[payload.client_id]

    # Test if payload bypasses the loose regex
    if not re.search(client["loose_pattern"], payload.redirect_uri):
        raise HTTPException(
            status_code=400,
            detail=f"Bypass failed: redirect_uri '{payload.redirect_uri}' does not even match the vulnerable pattern '{client['loose_pattern']}'."
        )

    # If it is the legitimate URI, it is not an exploit
    if payload.redirect_uri in client["redirect_uris"]:
        raise HTTPException(
            status_code=400,
            detail="This is the legitimate redirect URI, not an attacker-controlled bypass URI!"
        )

    target = payload.target_user if payload.target_user in state.users else "admin"
    code = f"leaked_code_{secrets.token_hex(16)}"
    state.auth_codes[code] = {
        "client_id": payload.client_id,
        "redirect_uri": payload.redirect_uri,
        "user": target,
        "scope": "openid profile email admin",
        "state_param": payload.state_param,
        "nonce": "victim_nonce_8819",
        "code_challenge": "initial_code_challenge_abc",
        "code_challenge_method": "S256",
        "created_at": time.time(),
        "used": False
    }

    state.captured_codes.append({
        "code": code,
        "target_user": target,
        "redirect_uri": payload.redirect_uri,
        "timestamp": time.time()
    })
    state.solved_steps["step1"] = True

    return {
        "success": True,
        "step": 1,
        "exploited_vulnerability": "Loose Regex Redirect URI Pattern Matching",
        "intercepted_code": code,
        "target_user": target,
        "exfiltrated_to": payload.redirect_uri,
        "flag": FLAGS["step1"],
        "message": "Authorization code intercepted via open redirect / domain confusion bypass!"
    }

# -----------------------------------------------------------------------------
# Exploit Step 2: PKCE Downgrade & Code Verifier Omission
# -----------------------------------------------------------------------------
@app.post("/api/oauth/exploit/pkce-downgrade")
def exploit_pkce_downgrade(payload: PKCEDowngradeRequest):
    """
    Step 2: Exchange intercepted authorization code without providing a valid
    code_verifier, exploiting IdP's failure to enforce mandatory PKCE verification.
    """
    if state.hardened or state.enforce_pkce_s256:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Hardening Active: Mandatory S256 PKCE verification strictly enforced. Downgrade rejected."
        )

    if payload.auth_code not in state.auth_codes:
        raise HTTPException(status_code=400, detail="Invalid or unknown auth_code")

    code_data = state.auth_codes[payload.auth_code]
    if code_data["used"]:
        raise HTTPException(status_code=400, detail="Auth code has already been consumed (replay prevention)")

    # In vulnerable mode, IdP allows exchanging token even if code_verifier is omitted
    code_data["used"] = True
    user_info = state.users[code_data["user"]]

    access_token = f"at_{secrets.token_hex(24)}"
    id_token = generate_id_token(user_info, payload.client_id, nonce=code_data.get("nonce"))

    state.issued_tokens[access_token] = {
        "user": user_info["username"],
        "client_id": payload.client_id,
        "scope": code_data["scope"],
        "created_at": time.time()
    }
    state.solved_steps["step2"] = True

    return {
        "success": True,
        "step": 2,
        "exploited_vulnerability": "PKCE Downgrade / Code Verifier Omission",
        "access_token": access_token,
        "id_token": id_token,
        "authenticated_user": user_info["username"],
        "role": user_info["role"],
        "flag": FLAGS["step2"],
        "message": "PKCE verification bypassed without code_verifier! User session tokens obtained."
    }

# -----------------------------------------------------------------------------
# Exploit Step 3: IdP JWT Key Confusion / 'kid' Injection Admin Takeover
# -----------------------------------------------------------------------------
@app.post("/api/oauth/exploit/jwt-key-confusion")
def exploit_jwt_key_confusion(payload: KeyConfusionRequest):
    """
    Step 3: Exploit JWT verification key confusion (e.g. kid header injection / HMAC confusion)
    to forge an arbitrary ID Token granting 'enterprise_admin' role.
    """
    if state.hardened or state.verify_jwks_pinning:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Hardening Active: Strict JWKS asymmetric key pinning enforced. Key confusion blocked."
        )

    now = int(time.time())
    forged_user = payload.target_user or "admin"
    forged_role = payload.forged_role or "enterprise_admin"

    token_payload = {
        "iss": "http://127.0.0.1:8031/api/oauth",
        "sub": forged_user,
        "aud": "corp-internal-crm",
        "exp": now + 7200,
        "iat": now,
        "email": f"{forged_user}@corp-app.com",
        "name": f"Forged {forged_user.title()}",
        "role": forged_role,
        "pwned_by": "SSOShield_Lab31"
    }

    # Simulate HMAC key confusion using public key as symmetric secret or attacker kid
    if payload.signature_algorithm == "HS256":
        # Sign with ATTACKER_SECRET or pem_public
        signing_secret = ATTACKER_SECRET
        headers = {"kid": payload.kid_header or "attacker-injected-key", "alg": "HS256"}
        forged_id_token = jwt.encode(token_payload, signing_secret, algorithm="HS256", headers=headers)
    else:
        # Fallback HS256 default
        headers = {"kid": payload.kid_header or "attacker-injected-key", "alg": "HS256"}
        forged_id_token = jwt.encode(token_payload, ATTACKER_SECRET, algorithm="HS256", headers=headers)

    # Vulnerable client decodes and verifies token trusting the kid or algorithm
    state.solved_steps["step3"] = True

    return {
        "success": True,
        "step": 3,
        "exploited_vulnerability": "OIDC ID Token Key Confusion & 'kid' Header Injection",
        "forged_id_token": forged_id_token,
        "session": {
            "authenticated_as": forged_user,
            "assigned_role": forged_role,
            "privileges": ["SYSTEM_ROOT", "ENTERPRISE_ADMIN", "FULL_ACCESS"]
        },
        "flag": FLAGS["step3"],
        "message": "Enterprise Administrator account takeover achieved via JWT key confusion!"
    }

# -----------------------------------------------------------------------------
# Security Hardening & Reset Endpoints
# -----------------------------------------------------------------------------
@app.post("/api/oauth/harden")
def harden_lab():
    """
    Enables enterprise-grade OAuth 2.0 & OIDC defensive hardening:
    - Strict Exact-Match Redirect URI Whitelisting
    - Mandatory PKCE RFC 7636 (S256 only)
    - Cryptographic State & Nonce CSRF/Replay verification
    - Trusted Asymmetric JWKS Pinning & Algorithm Whitelisting (RS256 only)
    """
    state.hardened = True
    state.strict_redirect_validation = True
    state.enforce_pkce_s256 = True
    state.verify_state_nonce = True
    state.verify_jwks_pinning = True
    return {
        "status": "success",
        "hardened": True,
        "active_defenses": [
            "Strict Exact-Match Redirect URI Whitelist Enforcement",
            "Mandatory RFC 7636 S256 PKCE Validation",
            "State & Nonce Anti-CSRF / Anti-Replay Tokens",
            "Strict JWKS Asymmetric RS256 Key Pinning"
        ],
        "message": "All OAuth 2.0 & OIDC security defenses have been successfully applied."
    }

@app.post("/api/oauth/reset")
def reset_lab():
    state.reset()
    return {
        "status": "success",
        "hardened": False,
        "message": "Lab 31 state has been reset to default vulnerable configuration."
    }

# -----------------------------------------------------------------------------
# Interactive Web Dashboard (Cyberpunk UI)
# -----------------------------------------------------------------------------
@app.get("/", response_class=HTMLResponse)
def index_page():
    return f"""<!DOCTYPE html>
<html lang="ko">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Lab 31: SSOShield - OAuth 2.0 / OIDC 보안 실전 랩</title>
  <style>
    :root {{
      --bg-color: #0b0f19;
      --card-bg: #111827;
      --card-border: #1f293d;
      --accent-color: #38bdf8;
      --accent-purple: #a855f7;
      --accent-green: #10b981;
      --accent-red: #ef4444;
      --text-main: #f3f4f6;
      --text-muted: #9ca3af;
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, monospace; }}
    body {{ background: var(--bg-color); color: var(--text-main); padding: 2rem 1rem; line-height: 1.6; }}
    .container {{ max-width: 1100px; margin: 0 auto; }}
    header {{ text-align: center; margin-bottom: 2rem; border-bottom: 1px solid var(--card-border); padding-bottom: 1.5rem; }}
    h1 {{ font-size: 2.2rem; color: var(--accent-color); margin-bottom: 0.5rem; text-shadow: 0 0 20px rgba(56, 189, 248, 0.4); }}
    .badge {{ display: inline-block; padding: 0.25rem 0.75rem; border-radius: 9999px; font-size: 0.85rem; font-weight: 600; text-transform: uppercase; background: #1e293b; color: var(--accent-color); border: 1px solid var(--accent-color); }}
    .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 1.5rem; margin-bottom: 2rem; }}
    .card {{ background: var(--card-bg); border: 1px solid var(--card-border); border-radius: 12px; padding: 1.5rem; box-shadow: 0 4px 20px rgba(0, 0, 0, 0.5); }}
    .card h2 {{ font-size: 1.25rem; color: var(--accent-purple); margin-bottom: 1rem; border-bottom: 1px solid var(--card-border); padding-bottom: 0.5rem; }}
    button {{ background: #2563eb; color: #fff; border: none; padding: 0.6rem 1.2rem; border-radius: 6px; font-weight: bold; cursor: pointer; transition: all 0.2s; width: 100%; margin-top: 0.75rem; }}
    button:hover {{ background: #1d4ed8; filter: brightness(1.1); }}
    button.harden {{ background: var(--accent-green); }}
    button.harden:hover {{ background: #059669; }}
    button.reset {{ background: #4b5563; }}
    button.reset:hover {{ background: #374151; }}
    input, select {{ width: 100%; padding: 0.5rem; background: #1e293b; border: 1px solid var(--card-border); border-radius: 6px; color: #fff; margin-bottom: 0.75rem; font-family: monospace; }}
    pre {{ background: #030712; padding: 0.75rem; border-radius: 6px; overflow-x: auto; font-size: 0.85rem; color: #34d399; border: 1px solid #1f2937; margin-top: 0.5rem; }}
    .status-box {{ padding: 1rem; border-radius: 8px; background: #1e293b; margin-bottom: 1.5rem; border-left: 4px solid var(--accent-color); }}
    .flag {{ color: #fbbf24; font-weight: bold; }}
  </style>
</head>
<body>
  <div class="container">
    <header>
      <span class="badge">Lab 31 Hands-on</span>
      <h1>🔑 SSOShield: OAuth 2.0 & OIDC 침투 실전 랩</h1>
      <p style="color: var(--text-muted);">Redirect URI 정규식 우회 · PKCE 다운그레이드 · JWT Key Confusion 관리자 탈취</p>
    </header>

    <div class="status-box" id="status-box">
      <strong>시스템 상태:</strong> <span id="lab-status">로딩 중...</span> |
      <strong>보안 모드:</strong> <span id="hardened-status">Vulnerable</span>
      <div style="margin-top: 0.5rem;">
        <span id="step1-status">Step 1: ❌</span> | 
        <span id="step2-status">Step 2: ❌</span> | 
        <span id="step3-status">Step 3: ❌</span>
      </div>
    </div>

    <div class="grid">
      <!-- Step 1 Card -->
      <div class="card">
        <h2>Step 1: Redirect URI 정규식 우회</h2>
        <p style="color: var(--text-muted); font-size: 0.9rem; margin-bottom: 1rem;">
          IdP의 <code>.*corp-app.com.*</code> 느슨한 정규식을 우회하여 공격자 도메인으로 인가 코드를 가로챕니다.
        </p>
        <label>클라이언트 ID:</label>
        <input type="text" id="s1-client" value="corp-internal-crm">
        <label>공격자 수신 URI:</label>
        <input type="text" id="s1-uri" value="https://attacker-corp-app.com/oauth/callback">
        <button onclick="runStep1()">Step 1 익스플로잇 실행</button>
        <pre id="s1-result">// 결과가 여기에 출력됩니다</pre>
      </div>

      <!-- Step 2 Card -->
      <div class="card">
        <h2>Step 2: PKCE 다운그레이드 공격</h2>
        <p style="color: var(--text-muted); font-size: 0.9rem; margin-bottom: 1rem;">
          탈취한 인가 코드를 <code>code_verifier</code> 없이 토큰 엔드포인트에 교환하여 무결성 검증을 우회합니다.
        </p>
        <label>탈취된 인가 코드:</label>
        <input type="text" id="s2-code" placeholder="Step 1에서 획득한 auth_code">
        <button onclick="runStep2()">Step 2 익스플로잇 실행</button>
        <pre id="s2-result">// 결과가 여기에 출력됩니다</pre>
      </div>

      <!-- Step 3 Card -->
      <div class="card">
        <h2>Step 3: JWT Key Confusion 관리자 탈취</h2>
        <p style="color: var(--text-muted); font-size: 0.9rem; margin-bottom: 1rem;">
          <code>kid</code> 헤더 변조 및 대칭키(HS256) 알고리즘 혼동을 악용하여 위조된 관리자 ID 토큰을 생성합니다.
        </p>
        <label>타깃 계정:</label>
        <input type="text" id="s3-target" value="admin">
        <label>변조할 권한 (Role):</label>
        <input type="text" id="s3-role" value="enterprise_admin">
        <button onclick="runStep3()">Step 3 관리자 탈취 실행</button>
        <pre id="s3-result">// 결과가 여기에 출력됩니다</pre>
      </div>
    </div>

    <div class="card" style="margin-top: 1rem;">
      <h2>🛡️ 엔터프라이즈 방어 하드닝 & 시스템 제어</h2>
      <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem;">
        <button class="harden" onclick="hardenLab()">🔒 엔터프라이즈 하드닝 적용</button>
        <button class="reset" onclick="resetLab()">🔄 랩 환경 초기화 (Reset)</button>
      </div>
      <pre id="admin-result" style="margin-top: 1rem;">// 방어 상태 로그</pre>
    </div>
  </div>

  <script>
    async function updateStatus() {{
      const res = await fetch('/api/oauth/info');
      const data = await res.json();
      document.getElementById('lab-status').textContent = '정상 가동 중 (포트 8031)';
      document.getElementById('hardened-status').textContent = data.hardened ? 'Hardened (Strict)' : 'Vulnerable';
      document.getElementById('hardened-status').style.color = data.hardened ? '#10b981' : '#ef4444';
      document.getElementById('step1-status').textContent = 'Step 1: ' + (data.solved_steps.step1 ? '✅' : '❌');
      document.getElementById('step2-status').textContent = 'Step 2: ' + (data.solved_steps.step2 ? '✅' : '❌');
      document.getElementById('step3-status').textContent = 'Step 3: ' + (data.solved_steps.step3 ? '✅' : '❌');
    }}

    async function runStep1() {{
      const client = document.getElementById('s1-client').value;
      const uri = document.getElementById('s1-uri').value;
      const res = await fetch('/api/oauth/exploit/redirect-bypass', {{
        method: 'POST',
        headers: {{ 'Content-Type': 'application/json' }},
        body: JSON.stringify({{ client_id: client, redirect_uri: uri, target_user: 'admin' }})
      }});
      const data = await res.json();
      document.getElementById('s1-result').textContent = JSON.stringify(data, null, 2);
      if (data.intercepted_code) {{
        document.getElementById('s2-code').value = data.intercepted_code;
      }}
      updateStatus();
    }}

    async function runStep2() {{
      const code = document.getElementById('s2-code').value;
      const client = document.getElementById('s1-client').value;
      const res = await fetch('/api/oauth/exploit/pkce-downgrade', {{
        method: 'POST',
        headers: {{ 'Content-Type': 'application/json' }},
        body: JSON.stringify({{ auth_code: code, client_id: client }})
      }});
      const data = await res.json();
      document.getElementById('s2-result').textContent = JSON.stringify(data, null, 2);
      updateStatus();
    }}

    async function runStep3() {{
      const target = document.getElementById('s3-target').value;
      const role = document.getElementById('s3-role').value;
      const res = await fetch('/api/oauth/exploit/jwt-key-confusion', {{
        method: 'POST',
        headers: {{ 'Content-Type': 'application/json' }},
        body: JSON.stringify({{ target_user: target, forged_role: role }})
      }});
      const data = await res.json();
      document.getElementById('s3-result').textContent = JSON.stringify(data, null, 2);
      updateStatus();
    }}

    async function hardenLab() {{
      const res = await fetch('/api/oauth/harden', {{ method: 'POST' }});
      const data = await res.json();
      document.getElementById('admin-result').textContent = JSON.stringify(data, null, 2);
      updateStatus();
    }}

    async function resetLab() {{
      const res = await fetch('/api/oauth/reset', {{ method: 'POST' }});
      const data = await res.json();
      document.getElementById('admin-result').textContent = JSON.stringify(data, null, 2);
      updateStatus();
    }}

    updateStatus();
  </script>
</body>
</html>
"""

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="127.0.0.1", port=8031, reload=False)
