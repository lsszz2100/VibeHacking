"""Lab 28: NetShield - Cisco & Network Device Security Lab (FastAPI)."""

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
import hashlib
import html
import re

app = FastAPI(title="NetShield - Cisco & Network Device Security Lab", version="1.0.0")

# ── CTF 플래그 정의 ──────────────────────────────────────────────────────────
FLAGS = {
    "step1": "FLAG{cisco_snmpv2c_rw_community_running_config_dumped_8028}",
    "step2": "FLAG{dtp_vlan_hopping_and_stp_bpdu_root_bridge_hijacked_4192}",
    "step3": "FLAG{cisco_ios_l2_hardened_portsec_dai_bpduguard_copp_secured_7731}",
}

# ── Cisco Type 7 암호화/복호화 테이블 ─────────────────────────────────────────
CISCO_KEY = [
    0x64, 0x73, 0x66, 0x64, 0x3B, 0x6B, 0x66, 0x6F,
    0x41, 0x2C, 0x2E, 0x69, 0x79, 0x65, 0x77, 0x72,
    0x6B, 0x6C, 0x64, 0x4A, 0x4B, 0x44, 0x48, 0x53,
    0x55, 0x42
]


def decrypt_cisco_type7(ciphertext: str) -> str:
    """Cisco IOS Type 7 비밀번호 복호화 (XOR 역산)"""
    if len(ciphertext) < 4 or len(ciphertext) % 2 != 0:
        return ""
    try:
        start_idx = int(ciphertext[:2])
        plaintext = []
        for i in range(2, len(ciphertext), 2):
            val = int(ciphertext[i:i+2], 16)
            key_byte = CISCO_KEY[(start_idx + (i - 2) // 2) % len(CISCO_KEY)]
            plaintext.append(chr(val ^ key_byte))
        return "".join(plaintext)
    except Exception:
        return ""


def encrypt_cisco_type7(plaintext: str, start_idx: int = 8) -> str:
    """Cisco IOS Type 7 비밀번호 생성"""
    out = [f"{start_idx:02d}"]
    for i, ch in enumerate(plaintext):
        key_byte = CISCO_KEY[(start_idx + i) % len(CISCO_KEY)]
        out.append(f"{ord(ch) ^ key_byte:02X}")
    return "".join(out)


# ── 모의 Catalyst 3850 스위치 환경 상태 ───────────────────────────────────────
INITIAL_SWITCH_STATE: Dict[str, Any] = {
    "hostname": "SW-CORE-CATALYST-3850",
    "ios_version": "16.12.4 EnterpriseK9",
    "ip_address": "192.168.100.1",
    "snmp": {
        "version": "v2c",
        "communities": {
            "public": "read-only",
            "private": "read-write",
        },
        "snmpv3_enabled": False,
        "config_dump_triggered": False,
    },
    "vlans": [
        {"id": 1, "name": "default", "status": "active"},
        {"id": 10, "name": "CORP-STAFF", "status": "active"},
        {"id": 20, "name": "FINANCE-DEV", "status": "active"},
        {"id": 100, "name": "MGMT-SECURE-VAULT", "status": "isolated"},
    ],
    "ports": {
        "GigabitEthernet1/0/1": {
            "mode": "dynamic desirable",
            "status": "connected",
            "access_vlan": 10,
            "trunk_encapsulation": "dot1q",
            "dtp_negotiated_trunk": False,
            "port_security": False,
            "max_mac": 1,
            "violation": "protect",
        },
        "GigabitEthernet1/0/2": {
            "mode": "access",
            "status": "connected",
            "access_vlan": 20,
            "port_security": False,
        },
    },
    "stp": {
        "protocol": "IEEE 802.1D Spanning Tree",
        "bridge_priority": 32768,
        "root_bridge_mac": "00:1a:2b:3c:4d:01",
        "root_bridge_hijacked": False,
        "bpdu_guard": False,
        "root_guard": False,
    },
    "l2_security": {
        "dtp_disabled": False,
        "port_security": False,
        "dhcp_snooping": False,
        "dynamic_arp_inspection": False,
        "bpdu_guard": False,
        "copp_enabled": False,
    },
    "passwords": {
        "enable_secret_type7": encrypt_cisco_type7("cisco123!pwn", start_idx=8),
        "enable_secret_plaintext": "cisco123!pwn",
    }
}

switch_state: Dict[str, Any] = dict(INITIAL_SWITCH_STATE)


# ── 요청 모델 ─────────────────────────────────────────────────────────────────
class SNMPBruteRequest(BaseModel):
    target_ip: str
    community_string: str
    port: int = 161


class DTPAttackRequest(BaseModel):
    interface: str
    attack_type: str  # dtp_trunk_spoof | stp_root_hijack | vlan_hop_double_tag
    target_vlan: int = 100
    bpdu_priority: int = 0


class SwitchHardeningRequest(BaseModel):
    disable_dtp: bool
    enable_port_security: bool
    enable_dhcp_snooping: bool
    enable_dai: bool
    enable_bpduguard: bool
    enable_snmpv3: bool
    enable_copp: bool


# ── API 엔드포인트 ────────────────────────────────────────────────────────────
@app.get("/health")
def health_check():
    return {
        "status": "ok",
        "port": 8028,
        "lab": "Lab 28: NetShield - Cisco & Network Device Security Lab",
        "hostname": switch_state["hostname"],
    }


@app.get("/api/cisco/status")
def get_switch_status():
    """스위치 전체 인터페이스, VLAN, STP, 보안 상태 반환"""
    return {
        "hostname": switch_state["hostname"],
        "ios_version": switch_state["ios_version"],
        "ip_address": switch_state["ip_address"],
        "snmp_version": switch_state["snmp"]["version"],
        "snmpv3_active": switch_state["snmp"]["snmpv3_enabled"],
        "vlans": switch_state["vlans"],
        "ports": switch_state["ports"],
        "stp": switch_state["stp"],
        "l2_security": switch_state["l2_security"],
    }


@app.post("/api/cisco/snmp/bruteforce")
def snmp_bruteforce(req: SNMPBruteRequest):
    """Step 1: SNMPv2c 커뮤니티 무차별 대입 및 Running-Config 추출"""
    comm = req.community_string.strip()
    valid_comms = switch_state["snmp"]["communities"]

    if comm not in valid_comms:
        return JSONResponse(
            status_code=401,
            content={
                "status": "auth_failure",
                "message": f"SNMPv2c-Error: Community string '{comm}' rejected by agent at {req.target_ip}:161",
                "community": comm,
                "access": "none",
            }
        )

    access = valid_comms[comm]
    if access == "read-only":
        return {
            "status": "readonly_success",
            "community": comm,
            "access": "read-only",
            "message": f"SNMP GET OK: MIB sysDescr.0 = 'Cisco IOS Software, Catalyst 3850 Software (CAT3K_CAA-UNIVERSALK9-M), Version {switch_state['ios_version']}'",
            "hint": "Read-Only 커뮤니티로는 config 추출 불가. R/W (Read-Write) 커뮤니티를 공략하세요.",
        }

    # read-write 성공 (e.g. 'private')
    switch_state["snmp"]["config_dump_triggered"] = True
    type7_pass = switch_state["passwords"]["enable_secret_type7"]
    plain_pass = switch_state["passwords"]["enable_secret_plaintext"]

    simulated_config = f"""! Cisco IOS Running-Configuration Dumped via SNMP ccCopyTable (ciscoConfigCopyMIB)
! Device: {switch_state['hostname']}
version 16.12
service password-encryption
!
hostname {switch_state['hostname']}
!
enable secret 7 {type7_pass}
!
username netadmin privilege 15 password 7 {encrypt_cisco_type7("NetAdmin#2026", start_idx=4)}
!
snmp-server community public RO
snmp-server community private RW
!
interface GigabitEthernet1/0/1
 description Trunk-Uplink-Candidate
 switchport mode dynamic desirable
!
interface GigabitEthernet1/0/2
 description Finance-Workstations
 switchport access vlan 20
 switchport mode access
!
vlan 100
 name MGMT-SECURE-VAULT
!
line vty 0 4
 transport input ssh
 login local
!
end
"""

    return {
        "status": "rw_success",
        "community": comm,
        "access": "read-write",
        "oid_triggered": "1.3.6.1.4.1.9.9.96.1.1.1.1.3 (ccCopySourceFileType=runningConfig)",
        "running_config": simulated_config,
        "type7_hash": type7_pass,
        "decrypted_enable_secret": plain_pass,
        "flag": FLAGS["step1"],
        "message": "⚡ SNMPv2c R/W 커뮤니티 장악 성공! ciscoConfigCopyMIB를 통해 running-config가 덤프되었으며 Type 7 암호가 해독되었습니다.",
    }


@app.post("/api/cisco/vlan/dtp-attack")
def dtp_vlan_attack(req: DTPAttackRequest):
    """Step 2: DTP Dynamic Trunking 스푸핑 및 STP Root Bridge 탈취"""
    port = req.interface
    if port not in switch_state["ports"]:
        raise HTTPException(status_code=404, detail=f"Port '{port}' not found on switch")

    port_meta = switch_state["ports"][port]

    # 하드닝 정책 점검
    if switch_state["l2_security"]["dtp_disabled"]:
        return JSONResponse(
            status_code=403,
            content={
                "status": "blocked",
                "message": f"DTP Attack Blocked: Interface {port} has 'switchport nonegotiate' enabled.",
                "mitigation": "DTP 협상이 비활성화되어 트렁크 전환이 거부되었습니다.",
            }
        )

    if req.attack_type == "dtp_trunk_spoof":
        # DTP 협상 -> Trunk 전환
        port_meta["dtp_negotiated_trunk"] = True
        port_meta["mode"] = "trunk (DTP Spoofed)"
        return {
            "status": "dtp_pwned",
            "interface": port,
            "negotiated_mode": "802.1Q Trunk",
            "vlan_hopping_access": [1, 10, 20, 100],
            "message": f"🎯 DTP 트렁크 스푸핑 성공! {port} 포트가 802.1Q 트렁크로 협상되어 격리된 VLAN {req.target_vlan}에 패킷을 주입할 수 있습니다.",
            "next_step": "STP BPDU를 우선순위 0으로 전송하여 Root Bridge 장악을 시도하세요.",
        }

    elif req.attack_type == "stp_root_hijack":
        if switch_state["l2_security"]["bpdu_guard"]:
            return JSONResponse(
                status_code=403,
                content={
                    "status": "blocked",
                    "message": f"STP Attack Blocked: BPDU Guard triggered on {port}! Port transitioned to err-disabled.",
                }
            )

        if req.bpdu_priority == 0:
            switch_state["stp"]["root_bridge_hijacked"] = True
            switch_state["stp"]["root_bridge_mac"] = "00:de:ad:be:ef:13:37 (Attacker Kali)"
            switch_state["stp"]["bridge_priority"] = 0
            return {
                "status": "stp_pwned",
                "interface": port,
                "new_root_bridge": "00:de:ad:be:ef:13:37",
                "root_priority": 0,
                "mitm_active": True,
                "flag": FLAGS["step2"],
                "message": "🔥 802.1D STP Root Bridge 탈취 완료! 공격자 노드가 Spanning Tree 트리의 루트가 되어 모든 스위치 간 L2 트래픽이 공격자를 경유합니다.",
            }
        else:
            return {
                "status": "stp_ignored",
                "message": f"BPDU priority {req.bpdu_priority} is higher or equal to current root. Use priority 0.",
            }

    else:
        raise HTTPException(status_code=400, detail="Invalid attack_type. Supported: 'dtp_trunk_spoof', 'stp_root_hijack'")


@app.post("/api/cisco/defense/hardening")
def apply_switch_hardening(req: SwitchHardeningRequest):
    """Step 3: 스위치 L2 보안 하드닝 및 CoPP 적용"""
    switch_state["l2_security"]["dtp_disabled"] = req.disable_dtp
    switch_state["l2_security"]["port_security"] = req.enable_port_security
    switch_state["l2_security"]["dhcp_snooping"] = req.enable_dhcp_snooping
    switch_state["l2_security"]["dynamic_arp_inspection"] = req.enable_dai
    switch_state["l2_security"]["bpdu_guard"] = req.enable_bpduguard
    switch_state["l2_security"]["snmpv3_enabled"] = req.enable_snmpv3
    switch_state["l2_security"]["copp_enabled"] = req.enable_copp

    # 하드닝 정책 적용에 따른 상태 변경
    if req.disable_dtp:
        for p in switch_state["ports"].values():
            p["mode"] = "access (nonegotiate)"
            p["dtp_negotiated_trunk"] = False

    if req.enable_snmpv3:
        switch_state["snmp"]["version"] = "v3 (AuthPriv: SHA-256 + AES-256)"
        switch_state["snmp"]["communities"] = {}  # v1/v2c 폐기

    if req.enable_bpduguard:
        switch_state["stp"]["bpdu_guard"] = True
        switch_state["stp"]["root_bridge_hijacked"] = False
        switch_state["stp"]["root_bridge_mac"] = "00:1a:2b:3c:4d:01 (Legit Core)"
        switch_state["stp"]["bridge_priority"] = 32768

    all_hardened = (
        req.disable_dtp
        and req.enable_port_security
        and req.enable_dhcp_snooping
        and req.enable_dai
        and req.enable_bpduguard
        and req.enable_snmpv3
        and req.enable_copp
    )

    if all_hardened:
        return {
            "status": "hardened_success",
            "flag": FLAGS["step3"],
            "hardening_score": "100%",
            "applied_controls": [
                "switchport mode access & switchport nonegotiate (DTP 무력화)",
                "switchport port-security maximum 1 & violation shutdown",
                "ip dhcp snooping & trust port verification",
                "ip arp inspection vlan 1-100 (DAI 위조 ARP 차단)",
                "spanning-tree portfast bpduguard default (BPDU Guard)",
                "snmp-server group SECGROUP v3 priv & snmp-server user (SNMPv3 AuthPriv)",
                "control-plane policing (CoPP DoS 방어)",
            ],
            "message": "🛡️ 축하합니다! 기업급 Cisco L2 스위치 및 관리 플레인 전 영역에 대한 완벽한 하드닝 정책이 수립되었습니다.",
        }
    else:
        return {
            "status": "partial_hardening",
            "message": "일부 보안 정책이 누락되었습니다. 7대 필수 하드닝 옵션을 모두 활성화하세요.",
            "current_state": switch_state["l2_security"],
        }


@app.post("/api/cisco/reset")
def reset_lab():
    """랩 환경 초기화"""
    global switch_state
    switch_state = dict(INITIAL_SWITCH_STATE)
    return {"status": "reset", "message": "스위치 상태가 초기 공장 출하 기본값으로 복원되었습니다."}


# ── 대시보드 웹 UI ────────────────────────────────────────────────────────────
@app.get("/", response_class=HTMLResponse)
def index_view():
    return f"""<!DOCTYPE html>
<html lang="ko">
<head>
  <meta charset="UTF-8">
  <title>NetShield - Cisco & Network Device Security Lab (Port 8028)</title>
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <style>
    :root {{
      --bg: #0a0f1d;
      --card-bg: #111827;
      --border: #1f293d;
      --accent: #00f0ff;
      --accent-glow: rgba(0, 240, 255, 0.25);
      --red: #ff3366;
      --green: #00ff99;
      --yellow: #ffd200;
      --text: #e2e8f0;
      --text-dim: #94a3b8;
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; font-family: 'Consolas', 'Courier New', monospace; }}
    body {{ background: var(--bg); color: var(--text); padding: 24px; }}
    header {{ border-bottom: 2px solid var(--accent); padding-bottom: 16px; margin-bottom: 24px; display: flex; justify-content: space-between; align-items: center; }}
    h1 {{ color: var(--accent); font-size: 1.6rem; letter-spacing: 1px; }}
    .badge {{ background: var(--card-bg); border: 1px solid var(--accent); color: var(--accent); padding: 4px 10px; border-radius: 4px; font-size: 0.85rem; }}
    .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(350px, 1fr)); gap: 20px; }}
    .card {{ background: var(--card-bg); border: 1px solid var(--border); border-radius: 8px; padding: 18px; }}
    .card h2 {{ color: var(--green); font-size: 1.15rem; margin-bottom: 12px; border-bottom: 1px solid var(--border); padding-bottom: 6px; }}
    .status-line {{ display: flex; justify-content: space-between; margin-bottom: 8px; font-size: 0.9rem; }}
    .status-line span:first-child {{ color: var(--text-dim); }}
    .btn {{ background: transparent; border: 1px solid var(--accent); color: var(--accent); padding: 8px 14px; border-radius: 4px; cursor: pointer; transition: 0.2s; font-size: 0.9rem; margin-top: 10px; }}
    .btn:hover {{ background: var(--accent); color: #000; box-shadow: 0 0 10px var(--accent-glow); }}
    .btn-red {{ border-color: var(--red); color: var(--red); }}
    .btn-red:hover {{ background: var(--red); color: #fff; }}
    .btn-green {{ border-color: var(--green); color: var(--green); }}
    .btn-green:hover {{ background: var(--green); color: #000; }}
    pre {{ background: #050811; border: 1px solid var(--border); padding: 12px; border-radius: 4px; font-size: 0.85rem; overflow-x: auto; color: #a5f3fc; max-height: 220px; }}
    input, select {{ background: #050811; border: 1px solid var(--border); color: #fff; padding: 6px 10px; border-radius: 4px; width: 100%; margin-top: 4px; margin-bottom: 8px; font-family: inherit; }}
    .flag-box {{ background: rgba(0, 255, 153, 0.1); border: 1px solid var(--green); color: var(--green); padding: 10px; border-radius: 4px; margin-top: 12px; font-weight: bold; word-break: break-all; }}
  </style>
</head>
<body>
  <header>
    <div>
      <h1>⚡ NETSHIELD: CISCO & NETWORK INFRASTRUCTURE LAB</h1>
      <p style="color: var(--text-dim); font-size: 0.9rem; margin-top: 4px;">Cisco Catalyst 3850 Virtual Stack & L2/L3 Network Security (Port 8028)</p>
    </div>
    <div>
      <span class="badge">VIBEHACKING LAB 28</span>
      <button class="btn btn-red" onclick="resetSwitch()">🔄 리셋</button>
    </div>
  </header>

  <div class="grid">
    <!-- Card 1: Switch Telemetry -->
    <div class="card">
      <h2>📡 Catalyst 3850 가상 스위치 텔레메트리</h2>
      <div id="telemetry-info">
        <div class="status-line"><span>Hostname:</span><span id="tel-host">SW-CORE-CATALYST-3850</span></div>
        <div class="status-line"><span>IOS Version:</span><span id="tel-ios">16.12.4 EnterpriseK9</span></div>
        <div class="status-line"><span>Management IP:</span><span>192.168.100.1</span></div>
        <div class="status-line"><span>SNMP Daemon:</span><span id="tel-snmp">v2c Active</span></div>
        <div class="status-line"><span>Port Gi1/0/1 Mode:</span><span id="tel-port1">dynamic desirable</span></div>
        <div class="status-line"><span>STP Root Bridge:</span><span id="tel-stp">00:1a:2b:3c:4d:01</span></div>
      </div>
      <button class="btn" onclick="fetchStatus()">📊 텔레메트리 갱신</button>
    </div>

    <!-- Card 2: Step 1 SNMP Exploit -->
    <div class="card">
      <h2>🔥 Step 1: SNMPv2c 커뮤니티 브루트포스</h2>
      <p style="color: var(--text-dim); font-size: 0.85rem; margin-bottom: 8px;">
        기본 커뮤니티(public/private) 무차별 대입 후 ciscoConfigCopyMIB로 running-config를 추출합니다.
      </p>
      <label style="font-size:0.85rem;">커뮤니티 사전 후보:</label>
      <select id="snmp-word">
        <option value="test">test (Invalid)</option>
        <option value="cisco">cisco (Invalid)</option>
        <option value="public">public (Read-Only)</option>
        <option value="private">private (Read-Write - Target)</option>
      </select>
      <button class="btn btn-red" onclick="runSNMPAttack()">⚡ 커뮤니티 대입 & Config 덤프</button>
      <div id="snmp-res" style="margin-top: 10px;"></div>
    </div>

    <!-- Card 3: Step 2 DTP & STP Hijacking -->
    <div class="card">
      <h2>⚔️ Step 2: DTP 트렁크 스푸핑 & STP 탈취</h2>
      <p style="color: var(--text-dim); font-size: 0.85rem; margin-bottom: 8px;">
        Gi1/0/1의 DTP 취약점을 악용해 트렁크를 협상하고 Priority 0 BPDU로 Root Bridge를 장악합니다.
      </p>
      <label style="font-size:0.85rem;">공격 벡터:</label>
      <select id="dtp-vector">
        <option value="dtp_trunk_spoof">1. DTP 패킷 주입 (Trunk 모드 강제 협상)</option>
        <option value="stp_root_hijack">2. STP BPDU 주입 (Priority 0 Root Bridge 탈취)</option>
      </select>
      <button class="btn btn-red" onclick="runDTPAttack()">🚀 L2 침투 프레임 주입</button>
      <div id="dtp-res" style="margin-top: 10px;"></div>
    </div>

    <!-- Card 4: Step 3 Hardening -->
    <div class="card">
      <h2>🛡️ Step 3: 엔터프라이즈 L2 스위치 하드닝</h2>
      <p style="color: var(--text-dim); font-size: 0.85rem; margin-bottom: 8px;">
        스위치 포트 고정, Port-Security, BPDU Guard, SNMPv3, CoPP 정책을 일괄 적용합니다.
      </p>
      <div style="font-size:0.85rem;">
        <label><input type="checkbox" id="chk-dtp" checked> DTP 비활성화 (switchport nonegotiate)</label><br>
        <label><input type="checkbox" id="chk-psec" checked> Port Security (Max MAC 1 + Violation Shutdown)</label><br>
        <label><input type="checkbox" id="chk-dhcp" checked> DHCP Snooping & Trust Port</label><br>
        <label><input type="checkbox" id="chk-dai" checked> Dynamic ARP Inspection (DAI)</label><br>
        <label><input type="checkbox" id="chk-bpdu" checked> Spanning Tree BPDU Guard</label><br>
        <label><input type="checkbox" id="chk-snmp3" checked> SNMPv3 전환 (AuthPriv SHA-256/AES)</label><br>
        <label><input type="checkbox" id="chk-copp" checked> Control Plane Policing (CoPP)</label>
      </div>
      <button class="btn btn-green" onclick="applyHardening()">🔒 전사 L2 하드닝 정책 적용</button>
      <div id="harden-res" style="margin-top: 10px;"></div>
    </div>
  </div>

  <script>
    async function fetchStatus() {{
      const res = await fetch('/api/cisco/status');
      const data = await res.json();
      document.getElementById('tel-host').innerText = data.hostname;
      document.getElementById('tel-ios').innerText = data.ios_version;
      document.getElementById('tel-snmp').innerText = data.snmp_version;
      document.getElementById('tel-port1').innerText = data.ports['GigabitEthernet1/0/1'].mode;
      document.getElementById('tel-stp').innerText = data.stp.root_bridge_mac;
    }}

    async function runSNMPAttack() {{
      const word = document.getElementById('snmp-word').value;
      const res = await fetch('/api/cisco/snmp/bruteforce', {{
        method: 'POST',
        headers: {{ 'Content-Type': 'application/json' }},
        body: JSON.stringify({{ target_ip: '192.168.100.1', community_string: word }})
      }});
      const data = await res.json();
      const div = document.getElementById('snmp-res');
      if (data.status === 'rw_success') {{
        div.innerHTML = `<div class="flag-box">${{data.flag}}</div>
          <p style="color:var(--green);font-size:0.85rem;margin-top:6px;">Type 7 Password: ${{data.type7_hash}} -> Decrypted: <b>${{data.decrypted_enable_secret}}</b></p>
          <pre>${{data.running_config}}</pre>`;
      }} else {{
        div.innerHTML = `<p style="color:var(--yellow);font-size:0.85rem;">${{data.message}}</p>`;
      }}
      fetchStatus();
    }}

    async function runDTPAttack() {{
      const vector = document.getElementById('dtp-vector').value;
      const res = await fetch('/api/cisco/vlan/dtp-attack', {{
        method: 'POST',
        headers: {{ 'Content-Type': 'application/json' }},
        body: JSON.stringify({{ interface: 'GigabitEthernet1/0/1', attack_type: vector, bpdu_priority: 0 }})
      }});
      const data = await res.json();
      const div = document.getElementById('dtp-res');
      if (data.flag) {{
        div.innerHTML = `<div class="flag-box">${{data.flag}}</div><p style="color:var(--green);font-size:0.85rem;margin-top:6px;">${{data.message}}</p>`;
      }} else {{
        div.innerHTML = `<p style="color:var(--yellow);font-size:0.85rem;">${{data.message || data.detail}}</p>`;
      }}
      fetchStatus();
    }}

    async function applyHardening() {{
      const body = {{
        disable_dtp: document.getElementById('chk-dtp').checked,
        enable_port_security: document.getElementById('chk-psec').checked,
        enable_dhcp_snooping: document.getElementById('chk-dhcp').checked,
        enable_dai: document.getElementById('chk-dai').checked,
        enable_bpduguard: document.getElementById('chk-bpdu').checked,
        enable_snmpv3: document.getElementById('chk-snmp3').checked,
        enable_copp: document.getElementById('chk-copp').checked,
      }};
      const res = await fetch('/api/cisco/defense/hardening', {{
        method: 'POST',
        headers: {{ 'Content-Type': 'application/json' }},
        body: JSON.stringify(body)
      }});
      const data = await res.json();
      const div = document.getElementById('harden-res');
      if (data.flag) {{
        div.innerHTML = `<div class="flag-box">${{data.flag}}</div><p style="color:var(--green);font-size:0.85rem;margin-top:6px;">${{data.message}}</p>`;
      }} else {{
        div.innerHTML = `<p style="color:var(--yellow);font-size:0.85rem;">${{data.message}}</p>`;
      }}
      fetchStatus();
    }}

    async function resetSwitch() {{
      await fetch('/api/cisco/reset', {{ method: 'POST' }});
      document.getElementById('snmp-res').innerHTML = '';
      document.getElementById('dtp-res').innerHTML = '';
      document.getElementById('harden-res').innerHTML = '';
      fetchStatus();
    }}

    fetchStatus();
  </script>
</body>
</html>
"""
