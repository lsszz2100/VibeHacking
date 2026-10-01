#!/usr/bin/env python3
"""
VibeHacking Lab 33 — KisaAuditLab: KISA 주요정보통신기반시설 취약점 분석·평가 자동 진단 & 하드닝 랩
Enterprise Linux Server Vulnerability Assessment & Compliance Hardening Engine
"""

from typing import List, Dict, Any, Optional
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

app = FastAPI(
    title="KisaAuditLab — KISA 주요정보통신기반시설 취약점 평가 실전 랩",
    description="Automated Linux Infrastructure Assessment according to KISA Technical Standards and One-Click Compliance Hardening",
    version="1.0.0"
)

# -----------------------------------------------------------------------------
# Data Models & Standards Definitions
# -----------------------------------------------------------------------------
class AuditItem(BaseModel):
    code: str
    category: str
    title: str
    severity: str  # 상 (High), 중 (Medium), 하 (Low)
    standard_good: str
    standard_vuln: str
    current_setting: str
    status: str  # 취약 (Vulnerable) vs 양호 (Good)
    evidence: str

class AccountAuditRequest(BaseModel):
    check_u01_root_remote: bool = True
    check_u02_password_complexity: bool = True
    check_u03_lockout_threshold: bool = True
    check_u04_shadow_permission: bool = True

class ServiceExploitRequest(BaseModel):
    target_service: str = Field(default="ftp", description="ftp (U-20) or ssh (U-44)")
    action: str = Field(default="anonymous_download", description="anonymous_download or cipher_probe")

class HardenRequest(BaseModel):
    remediate_u01: bool = True
    remediate_u02: bool = True
    remediate_u03: bool = True
    remediate_u04: bool = True
    remediate_u20: bool = True
    remediate_u44: bool = True

# -----------------------------------------------------------------------------
# Default Lab State
# -----------------------------------------------------------------------------
def init_default_items() -> Dict[str, AuditItem]:
    return {
        "U-01": AuditItem(
            code="U-01",
            category="계정 관리",
            title="root 계정 원격 접속 제한",
            severity="상",
            standard_good="원격 터미널 서비스를 사용하는 경우 /etc/securetty 파일에 pts/x 미설정 및 sshd_config PermitRootLogin no",
            standard_vuln="원격 터미널 서비스 사용 시 root 직접 접속 허용",
            current_setting="sshd_config: PermitRootLogin yes / /etc/securetty: pts/0~pts/9 등록",
            status="취약",
            evidence="/etc/ssh/sshd_config 파일에 PermitRootLogin yes로 설정되어 외부에서 root 직접 로그인이 가능함."
        ),
        "U-02": AuditItem(
            code="U-02",
            category="계정 관리",
            title="패스워드 복잡도 관리",
            severity="상",
            standard_good="영문, 숫자, 특수문자 조합 8자리 이상, 복잡도 설정 적용 (minlen=8, dcredit=-1, ucredit=-1, ocredit=-1)",
            standard_vuln="패스워드 최소 길이 미달(8자 미만) 또는 문자 조합 정책 미적용",
            current_setting="login.defs: PASS_MIN_LEN 4 / pwquality.conf: minlen=4, 복잡도 비활성화",
            status="취약",
            evidence="/etc/security/pwquality.conf 설정 미흡으로 단순 패스워드('admin1') 설정이 허용됨."
        ),
        "U-03": AuditItem(
            code="U-03",
            category="계정 관리",
            title="계정 잠금 임계값 설정",
            severity="상",
            standard_good="로그인 실패 5회 이하 시 계정 잠금 임계값(deny=5, unlock_time=600) 설정 적용",
            standard_vuln="계정 잠금 정책이 설정되어 있지 않거나 5회를 초과하는 경우",
            current_setting="pam.d/system-auth: pam_faillock 모듈 미적용 (무차별 대입 공격 허용)",
            status="취약",
            evidence="로그인 실패 시 계정 잠금 모듈이 적용되지 않아 무제한 브루트포스 사전 공격이 가능함."
        ),
        "U-04": AuditItem(
            code="U-04",
            category="계정 관리",
            title="패스워드 파일 보호",
            severity="상",
            standard_good="/etc/shadow 파일의 소유자가 root이고 권한이 400 또는 000인 경우",
            standard_vuln="/etc/shadow 파일에 일반 사용자 읽기 권한이 부여된 경우",
            current_setting="/etc/shadow 권한 0644 (모든 일반 사용자 읽기 가능)",
            status="취약",
            evidence="/etc/shadow 파일 권한이 0644로 설정되어 일반 계정이 NTLM/SHA512 해시를 덤프할 수 있음."
        ),
        "U-20": AuditItem(
            code="U-20",
            category="서비스 관리",
            title="Anonymous FTP 비활성화",
            severity="상",
            standard_good="FTP 서비스(vsftpd, proftpd)에서 익명 접속이 비활성화(anonymous_enable=NO)된 경우",
            standard_vuln="익명 접속(anonymous/ftp)이 허용되어 파일 다운로드/업로드가 가능한 경우",
            current_setting="vsftpd.conf: anonymous_enable=YES / 익명 pub 디렉터리 접근 가능",
            status="취약",
            evidence="ftp anonymous:anonymous 로그인으로 /var/ftp/pub 내 내부 시스템 백업 아카이브 열람 가능."
        ),
        "U-44": AuditItem(
            code="U-44",
            category="서비스 관리",
            title="SSH 원격 접속 프로토콜 취약 알고리즘 비활성화",
            severity="중",
            standard_good="SSH 프로토콜 버전 2 사용 및 취약 암호화 알고리즘(3DES, RC4, diffie-hellman-group1-sha1) 차단",
            standard_vuln="취약한 대칭 암호(CBC 모드) 및 SSH 버전 정보 배너가 외부에 여과 없이 노출된 경우",
            current_setting="sshd_config: Ciphers aes128-cbc,3des-cbc / Banner /etc/issue.net OS 커널 노출",
            status="취약",
            evidence="SSH 서비스가 취약한 CBC 모드 암호 및 레거시 키 교환 알고리즘을 수락하며 OS 상세 정보를 배너로 반환함."
        )
    }

STATE: Dict[str, Any] = {
    "items": init_default_items(),
    "step1_completed": False,
    "step2_completed": False,
    "step3_completed": False,
    "ftp_exploited": False,
    "ssh_exploited": False,
}

# -----------------------------------------------------------------------------
# REST API Endpoints
# -----------------------------------------------------------------------------
@app.get("/health")
def healthcheck():
    return {
        "status": "ok",
        "service": "KisaAuditLab",
        "port": 8033,
        "items_count": len(STATE["items"])
    }

@app.get("/api/kisa/items")
def get_kisa_items():
    """모든 KISA 주요정보통신기반시설 점검 항목 목록 및 상태 반환"""
    items_list = list(STATE["items"].values())
    vuln_count = sum(1 for item in items_list if item.status == "취약")
    good_count = sum(1 for item in items_list if item.status == "양호")
    return {
        "items": items_list,
        "summary": {
            "total": len(items_list),
            "vulnerable": vuln_count,
            "good": good_count,
            "compliance_rate": f"{(good_count / len(items_list)) * 100:.1f}%"
        },
        "step_progress": {
            "step1_account_audit": STATE["step1_completed"],
            "step2_service_exploit": STATE["step2_completed"],
            "step3_compliance_hardened": STATE["step3_completed"]
        }
    }

@app.post("/api/kisa/audit/accounts")
def audit_accounts(req: AccountAuditRequest):
    """Step 1: KISA U-01 ~ U-04 계정 관리 취약점 전수 진단"""
    results = []
    required_checks = [
        req.check_u01_root_remote,
        req.check_u02_password_complexity,
        req.check_u03_lockout_threshold,
        req.check_u04_shadow_permission
    ]
    if not all(required_checks):
        raise HTTPException(
            status_code=400,
            detail="모든 계정 관리 항목(U-01, U-02, U-03, U-04)을 전수 진단해야 침투 플래그를 획득할 수 있습니다."
        )

    for code in ["U-01", "U-02", "U-03", "U-04"]:
        item = STATE["items"][code]
        results.append({
            "code": item.code,
            "title": item.title,
            "status": item.status,
            "evidence": item.evidence,
            "recommendation": item.standard_good
        })

    STATE["step1_completed"] = True
    flag = "FLAG{KISA_U01_U04_ACCOUNT_AUDIT_PWNED_1109}"

    return {
        "message": "계정 관리 보안 점검(U-01 ~ U-04) 완료: 4개 항목 전체 [취약] 판정!",
        "step": 1,
        "flag": flag,
        "results": results
    }

@app.post("/api/kisa/exploit/services")
def exploit_services(req: ServiceExploitRequest):
    """Step 2: U-20 (Anonymous FTP) 및 U-44 (취약 SSH 배너/암호) 익스플로잇"""
    target = req.target_service.lower().strip()
    action = req.action.lower().strip()

    if target == "ftp":
        if STATE["items"]["U-20"].status == "양호":
            raise HTTPException(status_code=403, detail="Anonymous FTP가 비활성화되어 파일에 접근할 수 없습니다.")
        STATE["ftp_exploited"] = True
        loot = {
            "service": "vsftpd 3.0.3",
            "anonymous_access": "GRANTED",
            "retrieved_files": [
                "/var/ftp/pub/server_backup_info.txt",
                "/var/ftp/pub/database_connect_credentials.enc"
            ],
            "details": "익명 FTP 로그인 성공! 백업 정보 및 암호화된 DB 크리덴셜 파일을 유출했습니다."
        }
    elif target == "ssh":
        if STATE["items"]["U-44"].status == "양호":
            raise HTTPException(status_code=403, detail="SSH 서비스가 보안 하드닝되어 취약 암호 및 배너가 차단되었습니다.")
        STATE["ssh_exploited"] = True
        loot = {
            "service": "OpenSSH 7.4p1",
            "banner_leak": "Linux target-prod-host 3.10.0-1160.el7.x86_64",
            "weak_ciphers_accepted": ["3des-cbc", "aes128-cbc"],
            "kex_accepted": ["diffie-hellman-group1-sha1"],
            "details": "취약 암호화 알고리즘 핸드셰이크 성공 및 OS 버전 정보 획득 완료."
        }
    else:
        raise HTTPException(status_code=400, detail="유효하지 않은 target_service입니다. 'ftp' 또는 'ssh'를 지정하세요.")

    flag = None
    if STATE["ftp_exploited"] and STATE["ssh_exploited"]:
        STATE["step2_completed"] = True
        flag = "FLAG{KISA_U20_U44_VULN_SERVICE_EXPLOITED_2241}"

    return {
        "message": f"{target.upper()} 취약 서비스 분석 및 공격 모의 완료!",
        "target": target,
        "loot": loot,
        "ftp_exploited": STATE["ftp_exploited"],
        "ssh_exploited": STATE["ssh_exploited"],
        "step2_completed": STATE["step2_completed"],
        "flag": flag
    }

@app.post("/api/kisa/harden")
def harden_infrastructure(req: HardenRequest):
    """Step 3: KISA 가이드라인 기반 6대 주요 점검 항목 전면 하드닝 및 컴플라이언스 통과"""
    items = STATE["items"]

    if req.remediate_u01:
        items["U-01"].status = "양호"
        items["U-01"].current_setting = "sshd_config: PermitRootLogin no / securetty: 콘솔 tty1만 허용"
        items["U-01"].evidence = "root 원격 직접 접속이 차단되었으며 일반 계정 경유 sudo 사용이 강제됨."

    if req.remediate_u02:
        items["U-02"].status = "양호"
        items["U-02"].current_setting = "pwquality.conf: minlen=8, dcredit=-1, ucredit=-1, ocredit=-1, lcredit=-1"
        items["U-02"].evidence = "영문 대/소문자, 숫자, 특수문자 3종 이상 조합 8자리 이상 복잡도 강제 적용."

    if req.remediate_u03:
        items["U-03"].status = "양호"
        items["U-03"].current_setting = "system-auth: pam_faillock.so deny=5 unlock_time=600 fail_interval=900"
        items["U-03"].evidence = "5회 연속 로그인 실패 시 10분간 계정 자동 잠금 방어 체계 가동."

    if req.remediate_u04:
        items["U-04"].status = "양호"
        items["U-04"].current_setting = "/etc/shadow 권한 0400 (root 읽기 전용) / 소유자 root"
        items["U-04"].evidence = "일반 사용자의 shadow 해시 접근 차단 완료."

    if req.remediate_u20:
        items["U-20"].status = "양호"
        items["U-20"].current_setting = "vsftpd.conf: anonymous_enable=NO / pub 디렉터리 제거"
        items["U-20"].evidence = "익명 FTP 접근 차단 및 허가된 사내 계정만 SFTP로 접근 제한."

    if req.remediate_u44:
        items["U-44"].status = "양호"
        items["U-44"].current_setting = "sshd_config: Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com / Banner none"
        items["U-44"].evidence = "CBC 취약 암호 전면 제거, 안전한 GCM/Poly1305만 허용 및 버전 배너 은닉."

    all_good = all(item.status == "양호" for item in items.values())
    if all_good:
        STATE["step3_completed"] = True
        flag = "FLAG{KISA_HARDENING_COMPLIANCE_PASSED_3378}"
        return {
            "message": "KISA 주요정보통신기반시설 기술적 취약점 평가 전 항목 [양호] 달성! 컴플라이언스 적합 인증 완료.",
            "step": 3,
            "compliance_status": "COMPLIANT (100% PASS)",
            "flag": flag,
            "hardened_items": [item.code for item in items.values()]
        }
    else:
        return {
            "message": "일부 항목만 하드닝되었습니다. 모든 항목을 조치하여 양호 상태를 달성하세요.",
            "compliance_status": "PARTIAL",
            "flag": None
        }

@app.post("/api/kisa/reset")
def reset_lab():
    """랩 상태 초기화"""
    STATE["items"] = init_default_items()
    STATE["step1_completed"] = False
    STATE["step2_completed"] = False
    STATE["step3_completed"] = False
    STATE["ftp_exploited"] = False
    STATE["ssh_exploited"] = False
    return {"message": "KisaAuditLab 상태가 취약 기본값으로 초기화되었습니다."}

# -----------------------------------------------------------------------------
# Frontend Dashboard (HTML / CSS / JS)
# -----------------------------------------------------------------------------
@app.get("/", response_class=HTMLResponse)
def index_page():
    return """<!DOCTYPE html>
<html lang="ko">
<head>
  <meta charset="UTF-8">
  <title>VibeHacking Lab 33 — KisaAuditLab</title>
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <style>
    :root {
      --bg: #0b0f19;
      --card: #151d2f;
      --border: #23314f;
      --text: #e2e8f0;
      --muted: #94a3b8;
      --primary: #38bdf8;
      --danger: #f43f5e;
      --success: #10b981;
      --warning: #f59e0b;
      --code-bg: #030712;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, monospace; }
    body { background: var(--bg); color: var(--text); padding: 24px; line-height: 1.5; }
    .container { max-width: 1200px; margin: 0 auto; }
    header { display: flex; justify-content: space-between; align-items: center; border-b: 1px solid var(--border); padding-bottom: 16px; margin-bottom: 24px; }
    h1 { font-size: 1.5rem; color: var(--primary); display: flex; align-items: center; gap: 8px; }
    .badge { background: #1e293b; padding: 4px 10px; border-radius: 9999px; font-size: 0.8rem; border: 1px solid var(--border); }
    .grid { display: grid; grid-template-columns: 2fr 1fr; gap: 20px; }
    .card { background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 20px; margin-bottom: 20px; }
    .card h2 { font-size: 1.15rem; color: #fff; margin-bottom: 12px; display: flex; align-items: center; gap: 6px; }
    .stats { display: flex; gap: 16px; margin-bottom: 16px; }
    .stat-box { flex: 1; background: var(--code-bg); padding: 12px; border-radius: 6px; border: 1px solid var(--border); text-align: center; }
    .stat-num { font-size: 1.4rem; font-weight: bold; }
    .stat-vuln { color: var(--danger); }
    .stat-good { color: var(--success); }
    table { width: 100%; border-collapse: collapse; margin-top: 10px; font-size: 0.88rem; }
    th, td { padding: 10px 12px; text-align: left; border-bottom: 1px solid var(--border); }
    th { background: #0f172a; color: var(--muted); }
    .tag-vuln { background: rgba(244, 63, 94, 0.2); color: var(--danger); padding: 2px 8px; border-radius: 4px; font-weight: bold; }
    .tag-good { background: rgba(16, 185, 129, 0.2); color: var(--success); padding: 2px 8px; border-radius: 4px; font-weight: bold; }
    .btn { background: #2563eb; color: #fff; border: none; padding: 10px 16px; border-radius: 6px; cursor: pointer; font-weight: bold; font-size: 0.9rem; transition: 0.2s; }
    .btn:hover { background: #1d4ed8; }
    .btn-danger { background: #be123c; }
    .btn-danger:hover { background: #9f1239; }
    .btn-success { background: #059669; }
    .btn-success:hover { background: #047857; }
    .actions { display: flex; flex-direction: column; gap: 12px; }
    pre { background: var(--code-bg); padding: 12px; border-radius: 6px; overflow-x: auto; font-size: 0.82rem; color: #a5f3fc; border: 1px solid var(--border); }
    .flag-banner { background: #064e3b; border: 1px solid #059669; padding: 12px; border-radius: 6px; color: #6ee7b7; font-weight: bold; margin-top: 12px; word-break: break-all; }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <h1>🛡️ Lab 33 — KisaAuditLab</h1>
      <div>
        <span class="badge">Port: 8033</span>
        <span class="badge">KISA 기반시설 기술적 취약점 평가 표준</span>
      </div>
    </header>

    <div class="grid">
      <div>
        <div class="card">
          <h2>📋 KISA 점검 항목 현황 (Unix/Linux 기준)</h2>
          <div class="stats">
            <div class="stat-box"><div>전체 항목</div><div class="stat-num" id="stat-total">6</div></div>
            <div class="stat-box"><div>취약 (Vulnerable)</div><div class="stat-num stat-vuln" id="stat-vuln">-</div></div>
            <div class="stat-box"><div>양호 (Good)</div><div class="stat-num stat-good" id="stat-good">-</div></div>
            <div class="stat-box"><div>컴플라이언스 달성률</div><div class="stat-num" id="stat-rate">0%</div></div>
          </div>
          <table>
            <thead>
              <tr>
                <th>코드</th>
                <th>구분</th>
                <th>항목명</th>
                <th>중요도</th>
                <th>상태</th>
              </tr>
            </thead>
            <tbody id="items-tbody"></tbody>
          </table>
        </div>

        <div class="card">
          <h2>💻 시스템 진단 및 침투 터미널 로그</h2>
          <pre id="log-output">// KisaAuditLab 진단 콘솔 대기 중...</pre>
          <div id="flag-display" style="display:none;" class="flag-banner"></div>
        </div>
      </div>

      <div>
        <div class="card">
          <h2>🎯 실습 단계별 액션 (Step 1~3)</h2>
          <div class="actions">
            <div>
              <h3>Step 1. 계정 관리 전수 진단 (U-01~U-04)</h3>
              <p style="font-size:0.82rem; color:var(--muted); margin-bottom:8px;">root 원격접속, 패스워드 복잡도/잠금/shadow 권한 진단</p>
              <button class="btn" onclick="runAccountAudit()">🔍 계정 보안 전수 진단 실행</button>
            </div>
            <hr style="border:0; border-top:1px solid var(--border); margin:12px 0;">
            <div>
              <h3>Step 2. 취약 서비스 공격 모의 (U-20, U-44)</h3>
              <p style="font-size:0.82rem; color:var(--muted); margin-bottom:8px;">익명 FTP 파일 탈취 및 SSH 취약 알고리즘 프로브</p>
              <div style="display:flex; gap:8px;">
                <button class="btn btn-danger" onclick="exploitService('ftp')">🔓 U-20 익명 FTP 침투</button>
                <button class="btn btn-danger" onclick="exploitService('ssh')">🔓 U-44 SSH 암호 프로브</button>
              </div>
            </div>
            <hr style="border:0; border-top:1px solid var(--border); margin:12px 0;">
            <div>
              <h3>Step 3. 원클릭 KISA 보안 하드닝</h3>
              <p style="font-size:0.82rem; color:var(--muted); margin-bottom:8px;">6대 점검 항목을 즉시 '양호' 기준으로 일괄 하드닝</p>
              <button class="btn btn-success" onclick="applyHardening()">🛡️ 원클릭 컴플라이언스 하드닝 적용</button>
            </div>
            <hr style="border:0; border-top:1px solid var(--border); margin:12px 0;">
            <div>
              <button class="btn" style="background:#475569;" onclick="resetLab()">🔄 랩 상태 초기화</button>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>

  <script>
    async function loadStatus() {
      const res = await fetch('/api/kisa/items');
      const data = await res.json();
      document.getElementById('stat-total').innerText = data.summary.total;
      document.getElementById('stat-vuln').innerText = data.summary.vulnerable;
      document.getElementById('stat-good').innerText = data.summary.good;
      document.getElementById('stat-rate').innerText = data.summary.compliance_rate;

      const tbody = document.getElementById('items-tbody');
      tbody.innerHTML = '';
      data.items.forEach(item => {
        const tr = document.createElement('tr');
        const tagClass = item.status === '양호' ? 'tag-good' : 'tag-vuln';
        tr.innerHTML = `
          <td><strong>${item.code}</strong></td>
          <td>${item.category}</td>
          <td>${item.title}</td>
          <td>${item.severity}</td>
          <td><span class="${tagClass}">${item.status}</span></td>
        `;
        tbody.appendChild(tr);
      });
    }

    function showFlag(flag) {
      if (!flag) return;
      const el = document.getElementById('flag-display');
      el.style.display = 'block';
      el.innerText = '🎉 획득 플래그: ' + flag;
    }

    async function runAccountAudit() {
      const res = await fetch('/api/kisa/audit/accounts', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({
          check_u01_root_remote: true,
          check_u02_password_complexity: true,
          check_u03_lockout_threshold: true,
          check_u04_shadow_permission: true
        })
      });
      const data = await res.json();
      document.getElementById('log-output').innerText = JSON.stringify(data, null, 2);
      if (data.flag) showFlag(data.flag);
      loadStatus();
    }

    async function exploitService(svc) {
      const action = svc === 'ftp' ? 'anonymous_download' : 'cipher_probe';
      const res = await fetch('/api/kisa/exploit/services', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({target_service: svc, action: action})
      });
      const data = await res.json();
      document.getElementById('log-output').innerText = JSON.stringify(data, null, 2);
      if (data.flag) showFlag(data.flag);
      loadStatus();
    }

    async function applyHardening() {
      const res = await fetch('/api/kisa/harden', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({
          remediate_u01: true,
          remediate_u02: true,
          remediate_u03: true,
          remediate_u04: true,
          remediate_u20: true,
          remediate_u44: true
        })
      });
      const data = await res.json();
      document.getElementById('log-output').innerText = JSON.stringify(data, null, 2);
      if (data.flag) showFlag(data.flag);
      loadStatus();
    }

    async function resetLab() {
      const res = await fetch('/api/kisa/reset', {method: 'POST'});
      const data = await res.json();
      document.getElementById('log-output').innerText = data.message;
      document.getElementById('flag-display').style.display = 'none';
      loadStatus();
    }

    loadStatus();
  </script>
</body>
</html>
"""

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8033, reload=True)
