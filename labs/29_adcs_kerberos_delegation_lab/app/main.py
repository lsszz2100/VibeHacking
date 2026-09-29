"""Lab 29: CertPwn - AD CS & Kerberos Delegation Security Lab (FastAPI)."""

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
import hashlib
import html
import base64
import time

app = FastAPI(title="CertPwn - AD CS & Kerberos Delegation Security Lab", version="1.0.0")

# ── CTF 플래그 정의 ──────────────────────────────────────────────────────────
FLAGS = {
    "step1": "FLAG{adcs_esc1_enrollee_supplies_san_admin_cert_issued_8029}",
    "step2": "FLAG{pkinit_tgt_acquired_pass_the_certificate_domain_admin_5921}",
    "step3": "FLAG{kerberos_delegation_s4u_rbcd_hardened_protected_users_9312}",
}

# ── AD CS & Kerberos 초기 상태 ───────────────────────────────────────────────
DEFAULT_TEMPLATES = [
    {
        "name": "ESC1_WebAuth",
        "display_name": "Corporate Web & Client Authentication",
        "schema_version": 2,
        "enrollee_supplies_subject": True,
        "requires_manager_approval": False,
        "authorized_signatures_required": 0,
        "ekus": [
            {"oid": "1.3.6.1.5.5.7.3.2", "name": "Client Authentication"},
            {"oid": "1.3.6.1.4.1.311.20.2.2", "name": "Smart Card Logon"},
            {"oid": "1.3.6.1.5.5.7.3.1", "name": "Server Authentication"}
        ],
        "enrollment_permissions": ["Domain Users", "Authenticated Users"],
        "vulnerable": True,
        "vulnerability_type": "ESC1 (Enrollee Supplies SAN + Client Auth EKU)"
    },
    {
        "name": "User",
        "display_name": "Standard User Certificate",
        "schema_version": 2,
        "enrollee_supplies_subject": False,
        "requires_manager_approval": False,
        "authorized_signatures_required": 0,
        "ekus": [
            {"oid": "1.3.6.1.5.5.7.3.2", "name": "Client Authentication"},
            {"oid": "1.3.6.1.4.1.311.10.3.4", "name": "Encrypting File System"}
        ],
        "enrollment_permissions": ["Domain Users"],
        "vulnerable": False,
        "vulnerability_type": "None (Safe - Subject Built from Active Directory)"
    },
    {
        "name": "Machine",
        "display_name": "Computer Authentication",
        "schema_version": 2,
        "enrollee_supplies_subject": False,
        "requires_manager_approval": False,
        "authorized_signatures_required": 0,
        "ekus": [
            {"oid": "1.3.6.1.5.5.7.3.2", "name": "Client Authentication"},
            {"oid": "1.3.6.1.5.5.7.3.1", "name": "Server Authentication"}
        ],
        "enrollment_permissions": ["Domain Computers"],
        "vulnerable": False,
        "vulnerability_type": "None (Safe)"
    }
]

state: Dict[str, Any] = {
    "domain": "CORP.LOCAL",
    "ca_name": "CORP-DC-CA\\corp-DC-CA",
    "kdc_ip": "10.0.0.10",
    "templates": [dict(t) for t in DEFAULT_TEMPLATES],
    "issued_certificates": [],
    "cached_tickets": [],
    "hardened": {
        "protect_admin_accounts": False,
        "protected_users_group": False,
        "template_harden": False,
        "disable_esc8_ntlm_relay": False
    },
    "history": []
}


def log_event(event: str, detail: str = ""):
    state["history"].append({
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "event": event,
        "detail": detail
    })


# ── Pydantic 요청 모델 ───────────────────────────────────────────────────────
class CertRequestPayload(BaseModel):
    template: str
    target_user: str
    san_upn: Optional[str] = None
    csr_pem: Optional[str] = None


class PKINITAuthPayload(BaseModel):
    pfx_data: str
    kdc_ip: str = "10.0.0.10"
    realm: str = "CORP.LOCAL"
    request_ntlm: bool = True


class DelegationSimulatePayload(BaseModel):
    service_account: str = "svc_web$"
    target_service: str = "cifs/fileserver.corp.local"
    impersonate_user: str = "administrator@corp.local"


class HardeningPayload(BaseModel):
    protect_admin_accounts: bool
    protected_users_group: bool
    template_harden: bool
    disable_esc8_ntlm_relay: bool


# ── API 엔드포인트 ───────────────────────────────────────────────────────────
@app.get("/health")
def health():
    return {
        "status": "ok",
        "port": 8029,
        "lab": "CertPwn - AD CS & Kerberos Delegation Security Lab"
    }


@app.get("/api/adcs/templates")
def list_templates():
    return {
        "domain": state["domain"],
        "ca_name": state["ca_name"],
        "count": len(state["templates"]),
        "templates": state["templates"]
    }


@app.post("/api/adcs/cert/request")
def request_certificate(payload: CertRequestPayload):
    tpl = next((t for t in state["templates"] if t["name"] == payload.template), None)
    if not tpl:
        raise HTTPException(status_code=404, detail=f"Certificate template '{payload.template}' not found on CA.")

    # Check if template has been hardened
    if not tpl["enrollee_supplies_subject"]:
        log_event("CERT_DENIED", f"Template '{payload.template}' does not allow enrollee to supply SAN.")
        return JSONResponse(status_code=400, content={
            "success": False,
            "error": "Template does not permit CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT. SAN injection rejected."
        })

    target_san = (payload.san_upn or payload.target_user).strip().lower()
    is_admin = target_san in ["administrator@corp.local", "admin@corp.local", "administrator"]

    # Generate synthetic certificate
    serial = f"0x{hashlib.sha256(f'{target_san}:{time.time()}'.encode()).hexdigest()[:16]}"
    thumbprint = hashlib.sha1(f"CERT:{serial}".encode()).hexdigest().upper()
    simulated_pfx = base64.b64encode(f"PFX_KEY_DATA:{serial}:{target_san}:{thumbprint}".encode()).decode()

    cert_info = {
        "serial": serial,
        "subject": f"CN={target_san.split('@')[0]}",
        "san_upn": target_san,
        "issuer": state["ca_name"],
        "template": payload.template,
        "ekus": [e["name"] for e in tpl["ekus"]],
        "thumbprint": thumbprint,
        "pfx_base64": simulated_pfx,
        "issued_at": time.strftime("%Y-%m-%d %H:%M:%S")
    }
    state["issued_certificates"].append(cert_info)

    log_event("CERT_ISSUED", f"Certificate issued for {target_san} via template {payload.template}")

    resp: Dict[str, Any] = {
        "success": True,
        "message": f"Certificate successfully signed and issued for {target_san}.",
        "certificate": cert_info,
        "pfx_data": simulated_pfx
    }

    if is_admin:
        resp["flag"] = FLAGS["step1"]
        resp["note"] = "🎯 ESC1 Exploited! Domain Administrator certificate acquired with Client Authentication EKU."

    return resp


@app.post("/api/adcs/pkinit/auth")
def pkinit_authenticate(payload: PKINITAuthPayload):
    # Verify PFX payload
    try:
        decoded = base64.b64decode(payload.pfx_data).decode()
        if not decoded.startswith("PFX_KEY_DATA:"):
            raise ValueError("Invalid PFX format")
        parts = decoded.split(":")
        serial = parts[1]
        target_san = parts[2]
        thumbprint = parts[3]
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid or corrupted PKCS#12 (.pfx) certificate payload.")

    if payload.realm.upper() != "CORP.LOCAL" or payload.kdc_ip != state["kdc_ip"]:
        raise HTTPException(status_code=400, detail="KDC IP or Kerberos Realm mismatch.")

    is_admin = target_san in ["administrator@corp.local", "admin@corp.local", "administrator"]

    # Check if target account is protected under hardened policy
    if is_admin and state["hardened"]["protected_users_group"]:
        log_event("PKINIT_BLOCKED", f"Account {target_san} is in Protected Users group. PKINIT/NTLM restricted.")
        return JSONResponse(status_code=403, content={
            "success": False,
            "error": "KDC_ERR_POLICY: Account is a member of Protected Users. Kerberos pre-authentication policy enforced."
        })

    # Generate Kerberos TGT
    tgt_session_key = hashlib.md5(f"TGT_KEY:{serial}".encode()).hexdigest()
    tgt_ticket = base64.b64encode(f"KRB_TGT:krbtgt/CORP.LOCAL@{target_san}:{tgt_session_key}".encode()).decode()
    admin_ntlm = "b4d29a5342a344933a39e3381e4b9f29" if is_admin else "8846f7eaee8fb117ad06bdd830b7586c"

    pac_data = {
        "account_name": target_san.split("@")[0].capitalize(),
        "account_sid": "S-1-5-21-13371337-24682468-369369-500" if is_admin else "S-1-5-21-13371337-24682468-369369-1104",
        "rid": 500 if is_admin else 1104,
        "group_sids": [
            "S-1-5-21-13371337-24682468-369369-512 (Domain Admins)",
            "S-1-5-21-13371337-24682468-369369-519 (Enterprise Admins)"
        ] if is_admin else ["S-1-5-21-13371337-24682468-369369-513 (Domain Users)"]
    }

    ticket_entry = {
        "client": f"{target_san}@{payload.realm.upper()}",
        "server": f"krbtgt/{payload.realm.upper()}@{payload.realm.upper()}",
        "ticket_base64": tgt_ticket,
        "pac": pac_data,
        "ntlm_hash": admin_ntlm if payload.request_ntlm else None,
        "valid_until": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time() + 36000))
    }
    state["cached_tickets"].append(ticket_entry)
    log_event("PKINIT_SUCCESS", f"PKINIT TGT granted for {target_san}")

    resp: Dict[str, Any] = {
        "success": True,
        "message": f"PKINIT (RFC 4556) initial authentication succeeded for {target_san}.",
        "tgt_ticket": tgt_ticket,
        "pac": pac_data
    }

    if payload.request_ntlm:
        resp["ntlm_hash"] = admin_ntlm

    if is_admin:
        resp["flag"] = FLAGS["step2"]
        resp["note"] = "⚡ Pass-the-Certificate Success! Domain Administrator TGT & NTLM Hash extracted."

    return resp


@app.post("/api/adcs/delegation/simulate")
def simulate_delegation(payload: DelegationSimulatePayload):
    is_admin = "admin" in payload.impersonate_user.lower()

    if is_admin and (state["hardened"]["protect_admin_accounts"] or state["hardened"]["protected_users_group"]):
        log_event("DELEGATION_BLOCKED", f"Delegation blocked for {payload.impersonate_user} by security controls.")
        return {
            "success": False,
            "error": "KDC_ERR_BADOPTION: Target account is flagged as USER_NOT_DELEGATED (Account is sensitive and cannot be delegated). Impersonation rejected by KDC."
        }

    # Simulate S4U2Self & S4U2Proxy
    s4u_ticket = base64.b64encode(f"S4U2PROXY:{payload.service_account}->{payload.target_service} FOR {payload.impersonate_user}".encode()).decode()
    log_event("DELEGATION_EXPLOITED", f"S4U2Proxy impersonation successful: {payload.service_account} accessed {payload.target_service} as {payload.impersonate_user}")

    return {
        "success": True,
        "service_ticket": s4u_ticket,
        "impersonated_user": payload.impersonate_user,
        "target_service": payload.target_service,
        "privilege_level": "SYSTEM / Enterprise Domain Admin" if is_admin else "Domain User",
        "message": f"Successfully forged S4U2Proxy ticket to access {payload.target_service} impersonating {payload.impersonate_user}."
    }


@app.post("/api/adcs/delegation/harden")
def apply_hardening(payload: HardeningPayload):
    state["hardened"]["protect_admin_accounts"] = payload.protect_admin_accounts
    state["hardened"]["protected_users_group"] = payload.protected_users_group
    state["hardened"]["template_harden"] = payload.template_harden
    state["hardened"]["disable_esc8_ntlm_relay"] = payload.disable_esc8_ntlm_relay

    if payload.template_harden:
        for t in state["templates"]:
            if t["name"] == "ESC1_WebAuth":
                t["enrollee_supplies_subject"] = False
                t["requires_manager_approval"] = True
                t["vulnerable"] = False
                t["vulnerability_type"] = "Hardened (Enrollee Supplies SAN disabled, Manager Approval enforced)"

    log_event("HARDENING_APPLIED", "Enterprise AD CS & Kerberos Delegation Hardening Controls Applied.")

    all_enforced = (
        payload.protect_admin_accounts and
        payload.protected_users_group and
        payload.template_harden and
        payload.disable_esc8_ntlm_relay
    )

    resp: Dict[str, Any] = {
        "success": True,
        "hardened_state": state["hardened"],
        "all_enforced": all_enforced
    }

    if all_enforced:
        resp["flag"] = FLAGS["step3"]
        resp["message"] = "🛡️ Enterprise AD CS & Kerberos Hardening Complete! Protected Users, Non-Delegated Admin, and CA Approval Active."

    return resp


@app.post("/api/adcs/reset")
def reset_lab():
    state["templates"] = [dict(t) for t in DEFAULT_TEMPLATES]
    state["issued_certificates"] = []
    state["cached_tickets"] = []
    state["hardened"] = {
        "protect_admin_accounts": False,
        "protected_users_group": False,
        "template_harden": False,
        "disable_esc8_ntlm_relay": False
    }
    state["history"] = []
    log_event("LAB_RESET", "Lab 29 reset to initial vulnerable state.")
    return {"success": True, "message": "Lab state successfully reset."}


# ── 인터랙티브 웹 대시보드 ───────────────────────────────────────────────────
@app.get("/", response_class=HTMLResponse)
def index_view():
    return """<!DOCTYPE html>
<html lang="ko">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Lab 29: CertPwn - AD CS & Kerberos Delegation Lab</title>
  <style>
    :root {
      --bg: #0b0f19;
      --card-bg: #111827;
      --border: #1f293d;
      --cyan: #06b6d4;
      --purple: #a855f7;
      --green: #10b981;
      --red: #ef4444;
      --amber: #f59e0b;
      --text: #e2e8f0;
      --dim: #94a3b8;
    }
    body {
      margin: 0;
      padding: 20px;
      background: var(--bg);
      color: var(--text);
      font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
    }
    .header {
      border-bottom: 1px solid var(--border);
      padding-bottom: 15px;
      margin-bottom: 20px;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    .badge {
      display: inline-block;
      padding: 3px 8px;
      border-radius: 4px;
      font-size: 11px;
      font-weight: 700;
    }
    .badge-red { background: rgba(239, 68, 68, 0.2); color: var(--red); border: 1px solid var(--red); }
    .badge-green { background: rgba(16, 185, 129, 0.2); color: var(--green); border: 1px solid var(--green); }
    .badge-cyan { background: rgba(6, 182, 212, 0.2); color: var(--cyan); border: 1px solid var(--cyan); }
    .badge-amber { background: rgba(245, 158, 11, 0.2); color: var(--amber); border: 1px solid var(--amber); }

    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(420px, 1fr)); gap: 20px; }
    .card { background: var(--card-bg); border: 1px solid var(--border); border-radius: 8px; padding: 18px; }
    .card h3 { margin-top: 0; color: var(--cyan); display: flex; align-items: center; justify-content: space-between; }
    table { width: 100%; border-collapse: collapse; margin-top: 10px; font-size: 13px; }
    th, td { text-align: left; padding: 8px; border-bottom: 1px solid var(--border); }
    th { color: var(--dim); }
    
    .btn {
      background: #1e293b;
      color: var(--cyan);
      border: 1px solid var(--cyan);
      padding: 8px 14px;
      border-radius: 4px;
      cursor: pointer;
      font-weight: 600;
      transition: all 0.2s;
    }
    .btn:hover { background: var(--cyan); color: #000; }
    .btn-green { border-color: var(--green); color: var(--green); }
    .btn-green:hover { background: var(--green); color: #000; }
    .btn-red { border-color: var(--red); color: var(--red); }
    .btn-red:hover { background: var(--red); color: #000; }

    input, select {
      background: #0f172a;
      border: 1px solid var(--border);
      color: var(--text);
      padding: 8px;
      border-radius: 4px;
      width: 100%;
      box-sizing: border-box;
      margin-bottom: 10px;
    }
    .output-box {
      background: #000;
      color: #38bdf8;
      border: 1px solid var(--border);
      border-radius: 4px;
      padding: 12px;
      font-family: monospace;
      font-size: 12px;
      min-height: 80px;
      max-height: 180px;
      overflow-y: auto;
      white-space: pre-wrap;
      word-break: break-all;
    }
    .flag-banner {
      background: rgba(16, 185, 129, 0.15);
      border: 1px solid var(--green);
      color: var(--green);
      padding: 10px;
      border-radius: 6px;
      margin-top: 10px;
      font-weight: 700;
      display: none;
    }
  </style>
</head>
<body>
  <div class="header">
    <div>
      <h1 style="margin: 0; color: var(--cyan); font-size: 24px;">🪪 Lab 29: CertPwn - AD CS & Kerberos Delegation Security Lab</h1>
      <p style="margin: 5px 0 0; color: var(--dim); font-size: 14px;">Active Directory Certificate Services ESC1 Exploitation, PKINIT Pass-the-Certificate, and S4U Delegation Hardening</p>
    </div>
    <div>
      <span class="badge badge-green">PORT 8029</span>
      <span class="badge badge-cyan">DOMAIN: CORP.LOCAL</span>
      <button class="btn btn-red" onclick="resetLab()" style="margin-left: 10px;">🔄 초기화</button>
    </div>
  </div>

  <div class="grid">
    <!-- 1. AD CS 템플릿 목록 & ESC1 신청 -->
    <div class="card">
      <h3>
        <span>1. AD CS ESC1 SAN 인증서 발급</span>
        <span class="badge badge-red">ESC1 VULNERABLE</span>
      </h3>
      <p style="font-size: 13px; color: var(--dim);">
        <code>ESC1_WebAuth</code> 템플릿에 <code>CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT</code>가 켜져 있어 신청자가 임의의 Domain Admin SAN을 지정할 수 있습니다.
      </p>
      <label style="font-size: 12px; color: var(--dim);">인증서 템플릿 선택</label>
      <select id="cert-template">
        <option value="ESC1_WebAuth">ESC1_WebAuth (취약: Enrollee Supplies SAN)</option>
        <option value="User">User (정상: AD 정보 기반 빌드)</option>
      </select>
      <label style="font-size: 12px; color: var(--dim);">요청자 SAN UPN</label>
      <input type="text" id="cert-upn" value="administrator@corp.local" placeholder="administrator@corp.local" />
      <button class="btn" onclick="requestCert()">⚡ 인증서 서명 요청 (CSR & Issue)</button>
      <div class="flag-banner" id="flag1-banner"></div>
      <div class="output-box" id="cert-output" style="margin-top: 10px;">대기 중...</div>
    </div>

    <!-- 2. PKINIT Kerberos TGT 획득 -->
    <div class="card">
      <h3>
        <span>2. PKINIT Pass-the-Certificate TGT</span>
        <span class="badge badge-amber">RFC 4556 PKINIT</span>
      </h3>
      <p style="font-size: 13px; color: var(--dim);">
        발급받은 Domain Admin PFX 인증서로 KDC(10.0.0.10:88)에 PKINIT AS-REQ 인증을 요청하여 Kerberos TGT 및 NTLM 해시를 획득합니다.
      </p>
      <label style="font-size: 12px; color: var(--dim);">PFX 데이터 (Step 1에서 자동 로드)</label>
      <input type="text" id="pfx-input" placeholder="PFX base64 데이터 입력" />
      <button class="btn btn-green" onclick="authPKINIT()">🔑 PKINIT 인증 수행 & TGT 추출</button>
      <div class="flag-banner" id="flag2-banner"></div>
      <div class="output-box" id="pkinit-output" style="margin-top: 10px;">대기 중...</div>
    </div>

    <!-- 3. S4U2Self/S4U2Proxy 위임 시뮬레이션 -->
    <div class="card">
      <h3>
        <span>3. Kerberos Constrained Delegation (S4U)</span>
        <span class="badge badge-cyan">S4U2Self / S4U2Proxy</span>
      </h3>
      <p style="font-size: 13px; color: var(--dim);">
        제약 위임이 허용된 서비스 계정(<code>svc_web$</code>)이 Administrator 권한을 사칭하여 타깃 서비스(<code>cifs/fileserver</code>) 티켓을 위조하는 과정을 테스트합니다.
      </p>
      <label style="font-size: 12px; color: var(--dim);">서비스 계정</label>
      <input type="text" id="deleg-svc" value="svc_web$" readonly />
      <label style="font-size: 12px; color: var(--dim);">타깃 서비스 SPN</label>
      <input type="text" id="deleg-target" value="cifs/fileserver.corp.local" />
      <button class="btn" onclick="simulateDelegation()">🎯 S4U Impersonation 공격 실행</button>
      <div class="output-box" id="deleg-output" style="margin-top: 10px;">대기 중...</div>
    </div>

    <!-- 4. 엔터프라이즈 하드닝 (Hardening) -->
    <div class="card">
      <h3>
        <span>4. AD CS & Kerberos 엔터프라이즈 하드닝</span>
        <span class="badge badge-green">Zero-Trust AD</span>
      </h3>
      <p style="font-size: 13px; color: var(--dim);">
        도메인 관리자 계정 위임 차단, Protected Users 등록, 템플릿 SAN 제한 및 ESC8 NTLM Relay 차단을 적용하여 L3 도메인을 전면 방어합니다.
      </p>
      <div style="margin-bottom: 12px; font-size: 13px;">
        <label><input type="checkbox" id="h-protect" checked style="width: auto;"> 관리자 계정 <code>USER_NOT_DELEGATED</code> 플래그 활성화</label><br>
        <label><input type="checkbox" id="h-group" checked style="width: auto;"> Domain Admins를 <code>Protected Users</code> 그룹에 강제 등록</label><br>
        <label><input type="checkbox" id="h-template" checked style="width: auto;"> AD CS 템플릿 <code>CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT</code> 비활성화 & 관리자 승인</label><br>
        <label><input type="checkbox" id="h-esc8" checked style="width: auto;"> 웹 등록(CES/NDES) EPA 강제 & HTTP 차단 (ESC8 NTLM Relay 방어)</label>
      </div>
      <button class="btn btn-green" onclick="applyHardening()">🛡️ 엔터프라이즈 하드닝 일괄 적용</button>
      <div class="flag-banner" id="flag3-banner"></div>
      <div class="output-box" id="harden-output" style="margin-top: 10px;">대기 중...</div>
    </div>
  </div>

  <script>
    let lastPfx = "";

    async function requestCert() {
      const template = document.getElementById("cert-template").value;
      const san_upn = document.getElementById("cert-upn").value;
      const res = await fetch("/api/adcs/cert/request", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ template, target_user: san_upn, san_upn })
      });
      const data = await res.json();
      document.getElementById("cert-output").innerText = JSON.stringify(data, null, 2);
      if (data.pfx_data) {
        lastPfx = data.pfx_data;
        document.getElementById("pfx-input").value = lastPfx;
      }
      if (data.flag) {
        const b = document.getElementById("flag1-banner");
        b.style.display = "block";
        b.innerText = "🚩 Step 1 Flag: " + data.flag;
      }
    }

    async function authPKINIT() {
      const pfx_data = document.getElementById("pfx-input").value || lastPfx;
      const res = await fetch("/api/adcs/pkinit/auth", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ pfx_data, kdc_ip: "10.0.0.10", realm: "CORP.LOCAL", request_ntlm: true })
      });
      const data = await res.json();
      document.getElementById("pkinit-output").innerText = JSON.stringify(data, null, 2);
      if (data.flag) {
        const b = document.getElementById("flag2-banner");
        b.style.display = "block";
        b.innerText = "🚩 Step 2 Flag: " + data.flag;
      }
    }

    async function simulateDelegation() {
      const res = await fetch("/api/adcs/delegation/simulate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          service_account: document.getElementById("deleg-svc").value,
          target_service: document.getElementById("deleg-target").value,
          impersonate_user: "administrator@corp.local"
        })
      });
      const data = await res.json();
      document.getElementById("deleg-output").innerText = JSON.stringify(data, null, 2);
    }

    async function applyHardening() {
      const payload = {
        protect_admin_accounts: document.getElementById("h-protect").checked,
        protected_users_group: document.getElementById("h-group").checked,
        template_harden: document.getElementById("h-template").checked,
        disable_esc8_ntlm_relay: document.getElementById("h-esc8").checked
      };
      const res = await fetch("/api/adcs/delegation/harden", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
      });
      const data = await res.json();
      document.getElementById("harden-output").innerText = JSON.stringify(data, null, 2);
      if (data.flag) {
        const b = document.getElementById("flag3-banner");
        b.style.display = "block";
        b.innerText = "🚩 Step 3 Flag: " + data.flag;
      }
    }

    async function resetLab() {
      await fetch("/api/adcs/reset", { method: "POST" });
      location.reload();
    }
  </script>
</body>
</html>
"""
