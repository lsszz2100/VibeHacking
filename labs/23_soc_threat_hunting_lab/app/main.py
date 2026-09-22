"""Lab 23: SOC Threat Hunting & SIEM/Incident Response Lab (SOCHunter).

Enterprise SOC Telemetry, Threat Hunting, and Automated SOAR Remediation:
- Mission 1: Sysmon Process Injection & Parent PID Spoofing Hunt
- Mission 2: Suricata NIDS Alert & DNS C2 Beaconing Correlation
- Mission 3: SIEM Pass-the-Hash & LSASS Access Hunt to Automated SOAR Remediation
"""

import json
import os
import time
from typing import Any, Dict, List, Optional
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

app = FastAPI(title="VibeHacking SOCHunter Lab", version="1.0.0")

# Flags
FLAG_SYSMON = os.getenv("LAB_FLAG_SYSMON", "FLAG{sysmon_parent_pid_spoofing_remote_thread_injected_3821}")
FLAG_SURICATA = os.getenv("LAB_FLAG_SURICATA", "FLAG{suricata_dns_tunnel_ja3_c2_beacon_correlated_9482}")
FLAG_SIEM = os.getenv("LAB_FLAG_SIEM", "FLAG{siem_lsass_mimikatz_pass_the_hash_soar_contained_7129}")

# Mock Telemetry Datasets
SYSMON_EVENTS = [
    {
        "EventId": 1,
        "UtcTime": "2026-09-22 03:10:14.218",
        "ProcessId": 1044,
        "Image": "C:\\Windows\\System32\\svchost.exe",
        "CommandLine": "C:\\Windows\\system32\\svchost.exe -k DcomLaunch -p",
        "ParentProcessId": 640,
        "ParentImage": "C:\\Windows\\System32\\services.exe",
        "User": "NT AUTHORITY\\SYSTEM",
        "Status": "Normal",
    },
    {
        "EventId": 1,
        "UtcTime": "2026-09-22 03:14:02.105",
        "ProcessId": 3412,
        "Image": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
        "CommandLine": '"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE" /n "Q3_Financial_Audit.docm"',
        "ParentProcessId": 2840,
        "ParentImage": "C:\\Windows\\explorer.exe",
        "User": "FINCORP\\jdoe",
        "Status": "Normal",
    },
    {
        "EventId": 1,
        "UtcTime": "2026-09-22 03:14:05.892",
        "ProcessId": 3980,
        "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "CommandLine": "powershell.exe -nop -w hidden -enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAE0AZQBtAG8AcgB5AFMAdAByAGUAYQBtAA==",
        "ParentProcessId": 3412,
        "ParentImage": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
        "User": "FINCORP\\jdoe",
        "Status": "Malicious Child Execution",
    },
    {
        "EventId": 8,
        "UtcTime": "2026-09-22 03:14:08.450",
        "SourceProcessId": 3980,
        "SourceImage": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "TargetProcessId": 4892,
        "TargetImage": "C:\\Windows\\System32\\spoolsv.exe",
        "StartAddress": "0x00007FFB32014000",
        "User": "FINCORP\\jdoe",
        "Status": "CreateRemoteThread Injection",
    },
    {
        "EventId": 1,
        "UtcTime": "2026-09-22 03:14:09.112",
        "ProcessId": 4892,
        "Image": "C:\\Windows\\System32\\spoolsv.exe",
        "CommandLine": "C:\\Windows\\System32\\spoolsv.exe",
        "ParentProcessId": 640,
        "ParentImage": "C:\\Windows\\System32\\services.exe",
        "User": "NT AUTHORITY\\SYSTEM",
        "Status": "Injected / Compromised Host Process",
    },
]

NETWORK_EVENTS = [
    {
        "timestamp": "2026-09-22T03:12:00.000Z",
        "proto": "TCP",
        "src_ip": "10.0.4.15",
        "src_port": 54120,
        "dest_ip": "142.250.190.46",
        "dest_port": 443,
        "ja3": "b32309a26951912be7dba376398abc3b",
        "alert": "Normal HTTPS TLS Handshake",
        "severity": 1,
    },
    {
        "timestamp": "2026-09-22T03:14:15.000Z",
        "proto": "UDP",
        "src_ip": "10.0.4.15",
        "src_port": 58912,
        "dest_ip": "198.51.100.88",
        "dest_port": 53,
        "query": "a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1.c2-exfil-gate.darkmesh.org",
        "alert": "ET MALWARE High Entropy Long Subdomain DNS Tunneling",
        "severity": 3,
    },
    {
        "timestamp": "2026-09-22T03:14:20.000Z",
        "proto": "TCP",
        "src_ip": "10.0.4.15",
        "src_port": 49201,
        "dest_ip": "198.51.100.88",
        "dest_port": 8443,
        "ja3": "72a589da586844d7f0818ce684948eea",
        "alert": "SURICATA Cobalt Strike Default TLS JA3 Fingerprint Match",
        "severity": 4,
    },
    {
        "timestamp": "2026-09-22T03:15:00.000Z",
        "proto": "TCP",
        "src_ip": "10.0.4.15",
        "src_port": 49205,
        "dest_ip": "198.51.100.88",
        "dest_port": 8443,
        "ja3": "72a589da586844d7f0818ce684948eea",
        "alert": "SURICATA Periodic HTTPS C2 Beaconing (Interval 40s Jitter 5%)",
        "severity": 4,
    },
]

WINEVENT_LOGS = [
    {
        "EventID": 4624,
        "TimeCreated": "2026-09-22 03:00:00",
        "Computer": "WKSTN-FIN-04",
        "TargetUserName": "jdoe",
        "LogonType": 2,
        "LogonProcessName": "User32",
        "Description": "An account was successfully logged on locally.",
    },
    {
        "EventID": 10,
        "TimeCreated": "2026-09-22 03:16:30",
        "Computer": "WKSTN-FIN-04",
        "SourceImage": "C:\\Windows\\System32\\spoolsv.exe",
        "TargetImage": "C:\\Windows\\System32\\lsass.exe",
        "GrantedAccess": "0x1010",
        "CallTrace": "C:\\Windows\\SYSTEM32\\ntdll.dll+9d4f4|C:\\Windows\\System32\\KERNELBASE.dll+2c38e",
        "Description": "Sysmon ProcessAccess: Suspicious memory read permission requested on LSASS.",
    },
    {
        "EventID": 4624,
        "TimeCreated": "2026-09-22 03:17:10",
        "Computer": "DC01.fincorp.local",
        "TargetUserName": "FIN_ADMIN",
        "WorkstationName": "WKSTN-FIN-04",
        "LogonType": 9,
        "AuthenticationPackage": "Negotiate",
        "Description": "Logon Type 9 (NewCredentials) Pass-the-Hash / Overpass-the-Hash detected.",
    },
    {
        "EventID": 4672,
        "TimeCreated": "2026-09-22 03:17:11",
        "Computer": "DC01.fincorp.local",
        "SubjectUserName": "FIN_ADMIN",
        "Description": "Special privileges assigned to new logon (SeDebugPrivilege, SeTcbPrivilege).",
    },
]

# Track actions
CONTAINED_PROCESSES: List[int] = []
BLOCKED_IPS: List[str] = []
ISOLATED_HOSTS: List[str] = []


class QueryModel(BaseModel):
    query: str
    source: Optional[str] = "all"


class ProcessContainModel(BaseModel):
    process_id: int


class BlockIpModel(BaseModel):
    ip: str


class IsolateEndpointModel(BaseModel):
    hostname: str
    compromised_user: str


@app.get("/api/status")
def get_status() -> Dict[str, Any]:
    return {
        "status": "ready",
        "lab": "Lab 23: SOCHunter (SOC Threat Hunting & SIEM/IR)",
        "port": 8023,
        "missions": [
            {
                "id": 1,
                "name": "Sysmon Process Injection Hunt",
                "status": "contained" if 4892 in CONTAINED_PROCESSES else "hunting",
            },
            {
                "id": 2,
                "name": "Suricata & DNS C2 Beaconing Correlation",
                "status": "blocked" if "198.51.100.88" in BLOCKED_IPS else "analyzing",
            },
            {
                "id": 3,
                "name": "SIEM Pass-the-Hash & Automated SOAR Remediation",
                "status": "isolated" if "WKSTN-FIN-04" in ISOLATED_HOSTS else "active_threat",
            },
        ],
    }


@app.get("/api/v1/telemetry/sysmon")
def get_sysmon_telemetry() -> List[Dict[str, Any]]:
    return SYSMON_EVENTS


@app.get("/api/v1/telemetry/network")
def get_network_telemetry() -> List[Dict[str, Any]]:
    return NETWORK_EVENTS


@app.get("/api/v1/telemetry/winevent")
def get_winevent_telemetry() -> List[Dict[str, Any]]:
    return WINEVENT_LOGS


@app.post("/api/v1/hunting/query")
def execute_hunting_query(req: QueryModel) -> Dict[str, Any]:
    q = req.query.strip().lower()
    source = (req.source or "all").lower()

    results = []
    pool = []
    if source in ("all", "sysmon"):
        pool.extend([{"_source": "sysmon", **e} for e in SYSMON_EVENTS])
    if source in ("all", "network", "suricata"):
        pool.extend([{"_source": "network", **e} for e in NETWORK_EVENTS])
    if source in ("all", "winevent", "siem"):
        pool.extend([{"_source": "winevent", **e} for e in WINEVENT_LOGS])

    for item in pool:
        serialized = json.dumps(item).lower()
        if not q or q in serialized:
            results.append(item)

    return {
        "status": "success",
        "query": req.query,
        "source": req.source,
        "total_hits": len(results),
        "results": results,
    }


@app.post("/api/v1/hunting/contain_process")
def contain_process(req: ProcessContainModel) -> Dict[str, Any]:
    pid = req.process_id
    if pid == 4892:
        if pid not in CONTAINED_PROCESSES:
            CONTAINED_PROCESSES.append(pid)
        return {
            "status": "success",
            "message": f"Malicious injected target process PID {pid} (spoolsv.exe) successfully terminated and memory dumped.",
            "target": "spoolsv.exe",
            "flag": FLAG_SYSMON,
        }
    raise HTTPException(
        status_code=400,
        detail=f"PID {pid} is not the malicious injected target process. Investigate CreateRemoteThread (EventCode 8) TargetProcessId.",
    )


@app.post("/api/v1/firewall/block_ip")
def block_ip(req: BlockIpModel) -> Dict[str, Any]:
    ip = req.ip.strip()
    if ip == "198.51.100.88":
        if ip not in BLOCKED_IPS:
            BLOCKED_IPS.append(ip)
        return {
            "status": "success",
            "message": f"C2 malicious infrastructure IP {ip} successfully added to enterprise edge firewall blocklist.",
            "blocked_ip": ip,
            "flag": FLAG_SURICATA,
        }
    raise HTTPException(
        status_code=400,
        detail=f"IP {ip} is not the active C2 beacon or DNS tunnel destination. Review high-severity Suricata JA3 alerts.",
    )


@app.post("/api/v1/soar/isolate_endpoint")
def isolate_endpoint(req: IsolateEndpointModel) -> Dict[str, Any]:
    host = req.hostname.strip().upper()
    user = req.compromised_user.strip().upper()

    if host == "WKSTN-FIN-04" and user == "FIN_ADMIN":
        if host not in ISOLATED_HOSTS:
            ISOLATED_HOSTS.append(host)
        return {
            "status": "success",
            "action": "SOAR Automated Incident Remediation Playbook Triggered",
            "details": {
                "isolated_host": host,
                "revoked_user_tokens": user,
                "quarantine_vlan": "VLAN-999-REMEDIATION",
                "krbtgt_ticket_flushed": True,
            },
            "flag": FLAG_SIEM,
        }
    raise HTTPException(
        status_code=400,
        detail="Invalid target host or compromised account name. Review EventCode 4624 LogonType 9 in winevent telemetry.",
    )


@app.get("/", response_class=HTMLResponse)
def get_dashboard() -> str:
    return f"""<!DOCTYPE html>
<html lang="ko">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>VibeHacking — Lab 23: SOCHunter Dashboard</title>
  <style>
    :root {{
      --bg: #090d16;
      --card-bg: #131a29;
      --accent: #00e5ff;
      --danger: #ff3366;
      --success: #00ff88;
      --warning: #ffb703;
      --text: #e2e8f0;
      --text-muted: #8892b0;
      --border: #1e293b;
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; font-family: 'Segoe UI', -apple-system, sans-serif; }}
    body {{ background: var(--bg); color: var(--text); padding: 24px; }}
    .header {{ display: flex; justify-content: space-between; align-items: center; border-bottom: 2px solid var(--border); padding-bottom: 16px; margin-bottom: 24px; }}
    .title {{ font-size: 24px; font-weight: bold; color: var(--accent); display: flex; align-items: center; gap: 10px; }}
    .badge {{ background: #1e293b; color: var(--accent); padding: 4px 10px; border-radius: 6px; font-size: 12px; border: 1px solid var(--accent); }}
    .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 20px; margin-bottom: 24px; }}
    .card {{ background: var(--card-bg); border: 1px solid var(--border); border-radius: 10px; padding: 20px; }}
    .card h3 {{ color: var(--accent); margin-bottom: 12px; font-size: 16px; display: flex; align-items: center; gap: 8px; }}
    .status-tag {{ font-size: 11px; padding: 3px 8px; border-radius: 4px; font-weight: bold; }}
    .tag-danger {{ background: rgba(255, 51, 102, 0.2); color: var(--danger); border: 1px solid var(--danger); }}
    .tag-success {{ background: rgba(0, 255, 136, 0.2); color: var(--success); border: 1px solid var(--success); }}
    .tag-warn {{ background: rgba(255, 183, 3, 0.2); color: var(--warning); border: 1px solid var(--warning); }}
    .code-box {{ background: #050811; border: 1px solid var(--border); border-radius: 6px; padding: 10px; font-family: monospace; font-size: 12px; overflow-x: auto; color: #38bdf8; margin: 10px 0; }}
    input, button, select {{ background: #0f172a; border: 1px solid var(--border); color: var(--text); padding: 8px 12px; border-radius: 6px; font-size: 13px; }}
    input {{ width: 100%; margin-bottom: 10px; }}
    button {{ background: var(--accent); color: #000; font-weight: bold; cursor: pointer; border: none; transition: 0.2s; }}
    button:hover {{ opacity: 0.9; }}
    .btn-danger {{ background: var(--danger); color: #fff; }}
    .flag-box {{ background: rgba(0, 229, 255, 0.1); border: 1px dashed var(--accent); padding: 10px; border-radius: 6px; color: var(--accent); font-family: monospace; font-size: 12px; margin-top: 10px; word-break: break-all; }}
  </style>
</head>
<body>
  <div class="header">
    <div class="title">
      <span>🛡️ SOCHunter: Enterprise SOC Threat Hunting Lab</span>
      <span class="badge">Port 8023</span>
    </div>
    <div>
      <span class="status-tag tag-success">SIEM PIPELINE ACTIVE</span>
    </div>
  </div>

  <div class="grid">
    <!-- Mission 1 -->
    <div class="card">
      <h3><span>🎯 Mission 1: Sysmon Process Injection</span></h3>
      <p style="font-size:13px; color:var(--text-muted); margin-bottom:10px;">
        Sysmon EventCode 8(CreateRemoteThread) 로그를 분석하여 <code>powershell.exe</code>로부터 주입당한 피해 프로세스(spoolsv.exe)의 PID를 격리 처치하십시오.
      </p>
      <div class="code-box">Detection: Sysmon Event 8 (Source: powershell.exe -> Target: spoolsv.exe)</div>
      <input type="number" id="pidInput" placeholder="타깃 프로세스 PID 입력 (예: 4892)" value="4892" />
      <button class="btn-danger" style="width:100%;" onclick="containProcess()">⚡ 프로세스 강제 종료 및 격리</button>
      <div id="m1Flag" class="flag-box" style="display:none;"></div>
    </div>

    <!-- Mission 2 -->
    <div class="card">
      <h3><span>🌐 Mission 2: Suricata NIDS & C2 비콘 상관분석</span></h3>
      <p style="font-size:13px; color:var(--text-muted); margin-bottom:10px;">
        DNS 터널링 및 Cobalt Strike TLS JA3 지문(<code>72a589da5868...</code>)이 감지된 C2 IP를 특정하여 경계 방화벽 차단 정책에 등록하십시오.
      </p>
      <div class="code-box">Alert: High Entropy DNS Tunneling & Cobalt Strike JA3</div>
      <input type="text" id="ipInput" placeholder="차단할 C2 IP 입력 (예: 198.51.100.88)" value="198.51.100.88" />
      <button style="width:100%;" onclick="blockIp()">🚫 방화벽 C2 차단 배포</button>
      <div id="m2Flag" class="flag-box" style="display:none;"></div>
    </div>

    <!-- Mission 3 -->
    <div class="card">
      <h3><span>🤖 Mission 3: SIEM Pass-the-Hash & SOAR 격리</span></h3>
      <p style="font-size:13px; color:var(--text-muted); margin-bottom:10px;">
        LSASS 덤프(Event 10) 및 Pass-the-Hash(Event 4624 Type 9)를 감행한 침해 호스트와 계정을 지정하여 SOAR 자동 격리 플레이북을 트리거하십시오.
      </p>
      <input type="text" id="hostInput" placeholder="호스트명 (예: WKSTN-FIN-04)" value="WKSTN-FIN-04" />
      <input type="text" id="userInput" placeholder="침해 계정명 (예: FIN_ADMIN)" value="FIN_ADMIN" />
      <button class="btn-danger" style="width:100%;" onclick="isolateEndpoint()">⚡ SOAR 자동 격리 플레이북 실행</button>
      <div id="m3Flag" class="flag-box" style="display:none;"></div>
    </div>
  </div>

  <!-- Interactive Hunting Console -->
  <div class="card">
    <h3><span>🔍 실시간 SIEM 통합 텔레메트리 헌팅 콘솔</span></h3>
    <div style="display:flex; gap:10px; margin-bottom:12px;">
      <select id="querySource" style="width:160px;">
        <option value="all">전체 (All Telemetry)</option>
        <option value="sysmon">Sysmon (Endpoint)</option>
        <option value="network">Suricata (Network/DNS)</option>
        <option value="winevent">Security.evtx (Auth)</option>
      </select>
      <input type="text" id="searchQuery" placeholder="검색 키워드 (예: powershell, 198.51, lsass, spoolsv)" style="margin-bottom:0;" />
      <button style="width:120px;" onclick="runQuery()">헌팅 검색</button>
    </div>
    <div id="queryResults" class="code-box" style="height: 180px; overflow-y: auto;">
      데이터 로딩 중...
    </div>
  </div>

  <script>
    async function runQuery() {{
      const source = document.getElementById('querySource').value;
      const query = document.getElementById('searchQuery').value;
      const box = document.getElementById('queryResults');
      try {{
        const res = await fetch('/api/v1/hunting/query', {{
          method: 'POST',
          headers: {{ 'Content-Type': 'application/json' }},
          body: JSON.stringify({{ query, source }})
        }});
        const data = await res.json();
        box.textContent = JSON.stringify(data.results, null, 2);
      }} catch (e) {{
        box.textContent = '쿼리 에러: ' + e.message;
      }}
    }}

    async function containProcess() {{
      const pid = parseInt(document.getElementById('pidInput').value);
      const res = await fetch('/api/v1/hunting/contain_process', {{
        method: 'POST',
        headers: {{ 'Content-Type': 'application/json' }},
        body: JSON.stringify({{ process_id: pid }})
      }});
      const data = await res.json();
      const flagDiv = document.getElementById('m1Flag');
      if (res.ok) {{
        flagDiv.style.display = 'block';
        flagDiv.textContent = '✅ 성공! ' + data.flag;
      }} else {{
        alert(data.detail);
      }}
    }}

    async function blockIp() {{
      const ip = document.getElementById('ipInput').value;
      const res = await fetch('/api/v1/firewall/block_ip', {{
        method: 'POST',
        headers: {{ 'Content-Type': 'application/json' }},
        body: JSON.stringify({{ ip }})
      }});
      const data = await res.json();
      const flagDiv = document.getElementById('m2Flag');
      if (res.ok) {{
        flagDiv.style.display = 'block';
        flagDiv.textContent = '✅ 차단 완료! ' + data.flag;
      }} else {{
        alert(data.detail);
      }}
    }}

    async function isolateEndpoint() {{
      const hostname = document.getElementById('hostInput').value;
      const compromised_user = document.getElementById('userInput').value;
      const res = await fetch('/api/v1/soar/isolate_endpoint', {{
        method: 'POST',
        headers: {{ 'Content-Type': 'application/json' }},
        body: JSON.stringify({{ hostname, compromised_user }})
      }});
      const data = await res.json();
      const flagDiv = document.getElementById('m3Flag');
      if (res.ok) {{
        flagDiv.style.display = 'block';
        flagDiv.textContent = '✅ SOAR 실행 성공! ' + data.flag;
      }} else {{
        alert(data.detail);
      }}
    }}

    runQuery();
  </script>
</body>
</html>
"""
