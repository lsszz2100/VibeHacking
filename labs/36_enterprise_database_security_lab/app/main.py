"""
Lab 36: Enterprise Database Security & Privilege Escalation Lab (DBShield)
VibeHacking Security Engineering Platform
Port: 8036
"""

import os
import re
import time
from typing import Dict, Any, Optional, List
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

app = FastAPI(
    title="Lab 36: Enterprise Database Security Lab",
    description="Second-Order SQLi, UDF Dynamic Library Injection RCE, and FGA Audit Hardening",
    version="1.0.0"
)

# Step Flags
STEP1_FLAG = "FLAG{DB_SECOND_ORDER_SQLI_METADATA_EXFIL_8831}"
STEP2_FLAG = "FLAG{DB_UDF_LIBRARY_INJECTION_ROOT_RCE_7492}"
STEP3_FLAG = "FLAG{DB_AUDIT_LOG_TDE_LEAST_PRIVILEGE_SECURED_3914}"

# In-Memory State
state = {
    "step1_completed": False,
    "step2_completed": False,
    "step3_completed": False,
    "harden_applied": False,
    "registered_users": [
        {"id": 1, "username": "dbadmin", "role": "DBA", "password_hash": "$6$rounds=5000$dbroot5542$v9XyZ1.DbMasterKey"},
        {"id": 2, "username": "appuser", "role": "USER", "password_hash": "$6$rounds=5000$salt7721$NormalUserPasswd"},
    ],
    "pending_profiles": {},
    "installed_udf_functions": [],
    "audit_logs": [],
    "secure_file_priv": "",  # Empty = unrestricted by default
}

def reset_lab():
    """Reset in-memory state to defaults."""
    state["step1_completed"] = False
    state["step2_completed"] = False
    state["step3_completed"] = False
    state["harden_applied"] = False
    state["pending_profiles"] = {}
    state["installed_udf_functions"] = []
    state["audit_logs"] = []
    state["secure_file_priv"] = ""

class RegisterProfileRequest(BaseModel):
    username: str
    nickname_payload: str
    email: Optional[str] = "tester@vibe.local"

class PasswordResetRequest(BaseModel):
    username: str

class UDFInstallRequest(BaseModel):
    function_name: str = "sys_eval"
    library_name: str = "raptor_udf2.so"
    hex_payload: Optional[str] = "7f454c46020101000000000000000000"

class UDFExecRequest(BaseModel):
    function_name: str = "sys_eval"
    cmd: str = "whoami"

class HardenRequest(BaseModel):
    enable_prepared_statements: bool = True
    enforce_secure_file_priv: bool = True
    isolate_least_privilege: bool = True
    enable_fga_audit: bool = True


@app.get("/health")
def health() -> Dict[str, Any]:
    return {
        "status": "ok",
        "lab": "36_enterprise_database_security_lab",
        "port": 8036,
        "step1_completed": state["step1_completed"],
        "step2_completed": state["step2_completed"],
        "step3_completed": state["step3_completed"],
        "harden_applied": state["harden_applied"]
    }


@app.get("/api/db/status")
def get_db_status() -> Dict[str, Any]:
    return {
        "engine": "MySQL Enterprise Server 8.0.36-vibe / Oracle Compatibility Mode",
        "secure_file_priv": state["secure_file_priv"] if state["harden_applied"] else "/tmp (Unrestricted File Writes Allowed)",
        "query_mode": "Prepared Statements Enforced" if state["harden_applied"] else "Dynamic String Concatenation Active",
        "privilege_level": "Least Privilege Restricted (SELECT only)" if state["harden_applied"] else "DBA (FILE, SUPER, GRANT ALL PRIVILEGES)",
        "udf_enabled": not state["harden_applied"],
        "installed_udfs": state["installed_udf_functions"],
        "audit_enabled": state["harden_applied"],
        "step1_completed": state["step1_completed"],
        "step2_completed": state["step2_completed"],
        "step3_completed": state["step3_completed"]
    }


@app.post("/api/db/register")
def register_profile(req: RegisterProfileRequest) -> Dict[str, Any]:
    """
    1차 저장 단계: 프로필 닉네임에 잠재적 SQL 페이로드가 안전하게(또는 그대로) 저장됨.
    """
    state["pending_profiles"][req.username] = {
        "username": req.username,
        "nickname": req.nickname_payload,
        "email": req.email,
        "created_at": time.strftime("%Y-%m-%d %H:%M:%S")
    }
    
    # Audit log
    state["audit_logs"].append({
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "action": "INSERT_PROFILE",
        "user": req.username,
        "detail": f"Profile created with nickname: {req.nickname_payload[:30]}..."
    })

    return {
        "status": "success",
        "message": f"User profile [{req.username}] registered successfully in pending verification table.",
        "stored_nickname": req.nickname_payload
    }


@app.post("/api/db/password-reset")
def trigger_password_reset(req: PasswordResetRequest) -> Dict[str, Any]:
    """
    2차 실행 단계 (Second-Order SQL Injection):
    비밀번호 재설정 모듈이 저장된 닉네임을 조회하여 동적 UPDATE/SELECT 쿼리에 결합할 때 인젝션 발생.
    """
    if req.username not in state["pending_profiles"]:
        raise HTTPException(status_code=404, detail="Username not found in pending profiles.")

    profile = state["pending_profiles"][req.username]
    stored_nickname = profile["nickname"]

    # 만약 하드닝이 적용된 경우
    if state["harden_applied"]:
        state["audit_logs"].append({
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "action": "SAFE_PARAMETRIZED_RESET",
            "user": req.username,
            "detail": "Password reset executed using strictly prepared statement."
        })
        return {
            "status": "success",
            "message": "Password reset email sent safely via parameterized statement. Injection mitigated.",
            "target": req.username
        }

    # 취약한 레거시 동적 쿼리 시뮬레이션
    simulated_query = f"SELECT id, username, role, password_hash FROM accounts WHERE nickname = '{stored_nickname}'"

    # 인젝션 구문 패턴 판정: 따옴표 탈출 및 OR / UNION / 주석 기호 포함 여부
    is_sqli = any(pattern in stored_nickname.upper() for pattern in ["' OR ", "' UNION ", "--", "#", "/*", "admin'"])

    if is_sqli:
        state["step1_completed"] = True
        exfiltrated_hashes = [u["password_hash"] for u in state["registered_users"] if u["role"] == "DBA"]
        
        state["audit_logs"].append({
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "action": "ALERT_SECOND_ORDER_SQLI",
            "user": req.username,
            "detail": f"Second-order injection triggered via query: {simulated_query}"
        })

        return {
            "status": "exploited",
            "message": "Second-order SQL injection successfully executed! Extracted DBA metadata and password hash.",
            "executed_query": simulated_query,
            "extracted_dba_hash": exfiltrated_hashes[0] if exfiltrated_hashes else "$6$rounds=5000$dbroot5542$v9XyZ1.DbMasterKey",
            "flag": STEP1_FLAG
        }
    else:
        return {
            "status": "normal",
            "message": "Query executed but no injection syntax detected in stored nickname.",
            "executed_query": simulated_query
        }


@app.post("/api/db/udf-install")
def install_udf(req: UDFInstallRequest) -> Dict[str, Any]:
    """
    MySQL UDF (User-Defined Function) 악성 라이브러리 등록
    """
    if state["harden_applied"]:
        raise HTTPException(
            status_code=403, 
            detail="Forbidden: secure_file_priv is enforced to NULL and SUPER/FILE privileges are revoked."
        )

    if req.function_name not in state["installed_udf_functions"]:
        state["installed_udf_functions"].append(req.function_name)

    state["audit_logs"].append({
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "action": "CREATE_UDF_FUNCTION",
        "user": "root@localhost",
        "detail": f"Installed function {req.function_name} from {req.library_name}"
    })

    return {
        "status": "installed",
        "message": f"UDF function [{req.function_name}] successfully registered in MySQL plugin space.",
        "plugin_path": f"/usr/lib/mysql/plugin/{req.library_name}"
    }


@app.post("/api/db/udf-exec")
def execute_udf(req: UDFExecRequest) -> Dict[str, Any]:
    """
    등록된 UDF를 통한 호스트 OS 커맨드 실행 (RCE)
    """
    if state["harden_applied"]:
        raise HTTPException(
            status_code=403,
            detail="Forbidden: UDF execution disabled by AppArmor/SELinux and DB privilege restriction."
        )

    if req.function_name not in state["installed_udf_functions"]:
        raise HTTPException(status_code=400, detail=f"Function [{req.function_name}] is not installed.")

    # OS 명령 실행 시뮬레이션
    cmd = req.cmd.strip()
    simulated_output = ""

    if "whoami" in cmd or "id" in cmd:
        simulated_output = "uid=0(root) gid=0(root) groups=0(root) context=system_u:system_r:mysqld_t"
        state["step2_completed"] = True
    elif "shadow" in cmd or "passwd" in cmd:
        simulated_output = "root:$6$vibe$GzR4yL23k9/RootShadowHash:19800:0:99999:7:::\nmysql:*:19800:0:99999:7:::"
        state["step2_completed"] = True
    elif "uname" in cmd:
        simulated_output = "Linux db-enterprise-node01 5.15.0-generic x86_64 GNU/Linux"
    else:
        simulated_output = f"Executed: {cmd} [Exit code: 0]"
        state["step2_completed"] = True

    response_data: Dict[str, Any] = {
        "status": "success",
        "function": req.function_name,
        "command": cmd,
        "stdout": simulated_output
    }

    if state["step2_completed"]:
        response_data["flag"] = STEP2_FLAG

    state["audit_logs"].append({
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "action": "UDF_COMMAND_EXECUTION",
        "user": "root@localhost",
        "detail": f"sys_eval('{cmd}') executed with root privileges"
    })

    return response_data


@app.post("/api/db/harden")
def apply_hardening(req: HardenRequest) -> Dict[str, Any]:
    """
    Step 3: 엔터프라이즈 DB 보안 하드닝 적용
    """
    if not (req.enable_prepared_statements and req.enforce_secure_file_priv and req.isolate_least_privilege and req.enable_fga_audit):
        raise HTTPException(status_code=400, detail="All 4 hardening controls must be enabled.")

    state["harden_applied"] = True
    state["secure_file_priv"] = "NULL (File exports & UDF loading completely blocked)"
    state["installed_udf_functions"] = []
    state["step3_completed"] = True

    state["audit_logs"].append({
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "action": "ENFORCE_ENTERPRISE_HARDENING",
        "user": "security_admin",
        "detail": "Activated FGA audit, TDE encryption, prepared statements, and revoked SUPER/FILE privileges."
    })

    return {
        "status": "hardened",
        "message": "Enterprise database security posture successfully hardened! All injection and UDF vectors mitigated.",
        "controls": {
            "prepared_statements": "Enforced",
            "secure_file_priv": "NULL",
            "least_privilege_rbac": "Active",
            "fga_unified_auditing": "Active"
        },
        "flag": STEP3_FLAG
    }


@app.get("/api/db/audit-logs")
def get_audit_logs() -> Dict[str, Any]:
    return {
        "total_events": len(state["audit_logs"]),
        "events": state["audit_logs"][-20:]
    }


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    return """
<!DOCTYPE html>
<html lang="ko">
<head>
  <meta charset="UTF-8">
  <title>Lab 36: Enterprise Database Security Lab (DBShield)</title>
  <style>
    body { background-color: #0b0f19; color: #e2e8f0; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; }
    .container { max-width: 1100px; margin: 0 auto; }
    header { border-bottom: 2px solid #3b82f6; padding-bottom: 15px; margin-bottom: 25px; display: flex; justify-content: space-between; align-items: center; }
    h1 { color: #60a5fa; margin: 0; font-size: 24px; }
    .badge { background: #1e3a8a; color: #93c5fd; padding: 4px 10px; border-radius: 4px; font-weight: bold; font-size: 13px; }
    .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
    .card { background: #1e293b; border-radius: 8px; padding: 20px; border: 1px solid #334155; }
    .card h2 { color: #38bdf8; font-size: 18px; margin-top: 0; border-bottom: 1px solid #334155; padding-bottom: 8px; }
    pre { background: #0f172a; padding: 12px; border-radius: 6px; overflow-x: auto; color: #a7f3d0; font-size: 13px; border: 1px solid #1e293b; }
    button { background: #2563eb; color: #fff; border: none; padding: 8px 16px; border-radius: 4px; cursor: pointer; font-weight: bold; transition: background 0.2s; }
    button:hover { background: #1d4ed8; }
    .step-box { background: #0f172a; border-left: 4px solid #3b82f6; padding: 12px; margin-bottom: 15px; }
    .flag-box { background: #064e3b; color: #6ee7b7; padding: 10px; border-radius: 4px; font-family: monospace; font-weight: bold; margin-top: 10px; }
  </style>
</head>
<body>
<div class="container">
  <header>
    <div>
      <h1>🗄️ Lab 36: Enterprise Database Security Lab (DBShield)</h1>
      <p style="margin: 5px 0 0 0; color: #94a3b8; font-size: 14px;">Second-Order SQLi, UDF Binary Injection RCE, and FGA Audit Hardening</p>
    </div>
    <span class="badge">PORT: 8036</span>
  </header>

  <div class="grid">
    <div class="card">
      <h2>🎯 실습 단계 안내 (Attack & Defense)</h2>
      
      <div class="step-box">
        <strong>Step 1: 2차 SQL 인젝션 (Second-Order SQLi)</strong>
        <p style="font-size: 13px; color: #cbd5e1; margin: 5px 0;">
          사용자 등록 시 닉네임에 SQL 인젝션 페이로드를 저장한 후 비밀번호 리셋 로직을 호출하여 DBA 해시를 탈취합니다.
        </p>
      </div>

      <div class="step-box">
        <strong>Step 2: UDF 동적 라이브러리 인젝션 & RCE</strong>
        <p style="font-size: 13px; color: #cbd5e1; margin: 5px 0;">
          DB의 SUPER/FILE 권한을 이용해 <code>sys_eval</code> UDF 라이브러리를 로드하고 호스트 시스템 root 권한을 획득합니다.
        </p>
      </div>

      <div class="step-box">
        <strong>Step 3: 엔터프라이즈 RDBMS 다계층 하드닝</strong>
        <p style="font-size: 13px; color: #cbd5e1; margin: 5px 0;">
          파라미터화 쿼리 강제, <code>secure_file_priv=NULL</code>, 최소 권한 분리 및 FGA 감사 로깅을 활성화합니다.
        </p>
      </div>
    </div>

    <div class="card">
      <h2>📡 실시간 DB 보안 관제 (Database Posture)</h2>
      <pre id="dbStatus">Loading database telemetry...</pre>
      <button onclick="fetchStatus()">상태 새로고침</button>
      <div id="flagOutput"></div>
    </div>
  </div>
</div>

<script>
async function fetchStatus() {
  try {
    const res = await fetch('/api/db/status');
    const data = await res.json();
    document.getElementById('dbStatus').textContent = JSON.stringify(data, null, 2);
  } catch (err) {
    document.getElementById('dbStatus').textContent = 'Error loading status: ' + err;
  }
}
fetchStatus();
</script>
</body>
</html>
"""
