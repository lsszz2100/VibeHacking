"""Lab 21: Automotive CAN Bus & UDS Diagnostic Security Lab (CarCanLab)."""

import os
import time
import random
from typing import Dict, List, Optional
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

app = FastAPI(title="VibeHacking CarCanLab", version="1.0.0")

# Flags
FLAG_CAN = os.getenv("LAB_FLAG_CAN", "FLAG{can_bus_arbitration_speed_spoof_8821}")
FLAG_UDS = os.getenv("LAB_FLAG_UDS", "FLAG{uds_security_access_seed_key_unlocked_3714}")
FLAG_RESET = os.getenv("LAB_FLAG_RESET", "FLAG{uds_ecu_reset_hard_failsafe_pwned_9021}")


class VehicleState:
    def __init__(self):
        self.speed: float = 60.0
        self.rpm: int = 2400
        self.gear: str = "D"
        self.brake_pressed: bool = False
        self.uds_session: str = "DEFAULT"  # DEFAULT(0x01), EXTENDED(0x03), PROGRAMMING(0x02)
        self.security_unlocked: bool = False
        self.pending_seed: Optional[int] = None
        self.ecu_status: str = "OPERATIONAL"
        self.failsafe_triggered: bool = False
        self.can_logs: List[dict] = []
        self._init_logs()

    def _init_logs(self):
        # Seed initial CAN traffic
        base_time = time.time() - 5
        self.can_logs = [
            {"time": base_time + 1, "can_id": "0x120", "dlc": 8, "data": "00003C0000000000", "desc": "Speed: 60 km/h"},
            {"time": base_time + 2, "can_id": "0x240", "dlc": 8, "data": "0960000000000000", "desc": "Engine RPM: 2400"},
            {"time": base_time + 3, "can_id": "0x320", "dlc": 8, "data": "0000000000000000", "desc": "Brake: Released"},
            {"time": base_time + 4, "can_id": "0x120", "dlc": 8, "data": "00003C0000000000", "desc": "Speed: 60 km/h"},
        ]

    def log_frame(self, can_id: str, dlc: int, data: str, desc: str = ""):
        self.can_logs.append({
            "time": time.time(),
            "can_id": can_id.upper(),
            "dlc": dlc,
            "data": data.upper(),
            "desc": desc,
        })
        if len(self.can_logs) > 60:
            self.can_logs.pop(0)


state = VehicleState()


# ── Pydantic Request Models ──────────────────────────────────────────────────
class CANInjectRequest(BaseModel):
    can_id: str
    dlc: int
    payload_hex: str


class UDSSessionRequest(BaseModel):
    session_type: str  # "0x01", "0x03", "extended", "default"


class UDSKeyRequest(BaseModel):
    key_hex: str


class UDSResetRequest(BaseModel):
    reset_type: str  # "0x01", "hardReset", "softReset"


class UDSDownloadRequest(BaseModel):
    memory_address_hex: str
    memory_size_hex: str


# ── REST API Endpoints ───────────────────────────────────────────────────────
@app.get("/api/status")
def get_status():
    """차량 계기판 및 ECU 실시간 상태 반환"""
    return {
        "status": "ready",
        "lab": "Lab 21: Automotive CAN Bus & UDS Diagnostic Security (CarCanLab)",
        "telemetry": {
            "speed_kmh": state.speed,
            "engine_rpm": state.rpm,
            "gear": state.gear,
            "brake": state.brake_pressed,
            "uds_session": state.uds_session,
            "security_unlocked": state.security_unlocked,
            "ecu_status": state.ecu_status,
            "failsafe": state.failsafe_triggered,
        },
        "missions": [
            {
                "id": 1,
                "name": "CAN 패킷 스니핑 & 속도계 조작 주입 (Speedometer Spoofing)",
                "target": "POST /api/mission1/can_inject",
                "desc": "CAN ID 0x120 프레임을 주입하여 계기판 속도를 200 km/h 이상으로 스푸핑하세요.",
                "solved": state.speed >= 200.0,
            },
            {
                "id": 2,
                "name": "UDS 진단 시드-키 역연산 및 SecurityAccess 언락 (Seed-Key Bypass)",
                "target": "POST /api/mission2/uds_security_unlock",
                "desc": "Extended 진단 세션(0x03) 진입 후 Mode 0x27 시드(Seed)를 요청하고 대칭 상수(0x5A5A5A5A) XOR 키를 계산하여 언락하세요.",
                "solved": state.security_unlocked,
            },
            {
                "id": 3,
                "name": "ECU 펌웨어 블록 덤프 & 하드 리셋 DoS (ECU Reset & Flash Dump)",
                "target": "POST /api/mission3/uds_ecu_reset",
                "desc": "SecurityAccess 획득 상태에서 펌웨어 다운로드(0x34)를 요청하고 Mode 0x11 하드 리셋을 유발하여 페일세이프를 격발시키세요.",
                "solved": state.failsafe_triggered,
            },
        ],
    }


@app.get("/api/can/traffic")
def get_can_traffic():
    """실시간 가상 CAN 버스 패킷 버퍼 반환"""
    return {"traffic": state.can_logs[-30:]}


@app.post("/api/mission1/can_inject")
def inject_can_frame(req: CANInjectRequest):
    """Mission 1: CAN 프레임 수동 주입 & 속도 스푸핑"""
    can_id = req.can_id.strip().lower()
    payload = req.payload_hex.strip().replace(" ", "").lower()

    if req.dlc != 8 or len(payload) != 16:
        raise HTTPException(status_code=400, detail="CAN frame must have DLC=8 and 16 hex chars payload (8 bytes)")

    try:
        raw_bytes = bytes.fromhex(payload)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid hexadecimal payload")

    # Log injected frame
    state.log_frame(can_id, req.dlc, payload, "INJECTED ATTACK FRAME")

    # If targeting speed frame 0x120
    if can_id in ["0x120", "120"]:
        # Speed byte at offset 2 (0-indexed byte 2)
        spoofed_speed = raw_bytes[2]
        state.speed = float(spoofed_speed)
        state.rpm = min(7500, int(spoofed_speed * 32))
        
        if spoofed_speed >= 200:
            return {
                "status": "success",
                "message": f"🚨 Overdrive Alert! 계기판 속도가 {spoofed_speed} km/h 로 급상승하여 클러스터 경고가 격발되었습니다!",
                "speed_kmh": spoofed_speed,
                "flag": FLAG_CAN,
            }
        return {
            "status": "injected",
            "message": f"CAN ID 0x120 주입 완료. 현재 계기판 속도: {spoofed_speed} km/h (목표: >= 200 km/h)",
            "speed_kmh": spoofed_speed,
        }

    return {
        "status": "injected",
        "message": f"CAN ID {can_id} 프레임이 가상 버스에 주입되었습니다.",
    }


@app.post("/api/mission2/uds_session")
def change_uds_session(req: UDSSessionRequest):
    """Mission 2-A: UDS Mode 0x10 DiagnosticSessionControl 세션 전환"""
    st = req.session_type.strip().lower()
    if st in ["0x03", "3", "extended"]:
        state.uds_session = "EXTENDED"
        state.log_frame("0x7DF", 8, "0210030000000000", "UDS Req: SessionControl Extended (0x10 0x03)")
        state.log_frame("0x7E8", 8, "065003003201F400", "UDS PosResp: Extended Session Active")
        return {
            "status": "session_changed",
            "session": "EXTENDED",
            "message": "UDS 진단 세션이 EXTENDED (0x03) 모드로 성공적으로 전환되었습니다. 이제 SecurityAccess 진입이 가능합니다.",
        }
    elif st in ["0x01", "1", "default"]:
        state.uds_session = "DEFAULT"
        state.security_unlocked = False
        return {"status": "session_changed", "session": "DEFAULT", "message": "기본 진단 세션으로 복귀하였습니다."}
    else:
        raise HTTPException(status_code=400, detail="Unsupported session type. Use 'extended' or '0x03'")


@app.post("/api/mission2/uds_security_seed")
def request_security_seed():
    """Mission 2-B: UDS Mode 0x27 Subfunction 0x01 SecurityAccess Seed 요청"""
    if state.uds_session != "EXTENDED":
        state.log_frame("0x7E8", 8, "037F272200000000", "UDS NegResp: ConditionsNotCorrect (0x22)")
        raise HTTPException(status_code=403, detail="NRC 0x22: Extended Diagnostic Session required before requesting seed.")

    seed_val = random.randint(0x10000000, 0xEFFFFFFF)
    state.pending_seed = seed_val
    seed_hex = f"{seed_val:08X}"
    state.log_frame("0x7DF", 8, "0227010000000000", "UDS Req: SecurityAccess RequestSeed (0x27 0x01)")
    state.log_frame("0x7E8", 8, f"066701{seed_hex[:4]}0000", f"UDS PosResp: Seed={seed_hex}")

    return {
        "status": "seed_issued",
        "subfunction": "0x01 (RequestSeed)",
        "seed_hex": seed_hex,
        "hint": "알고리즘: key = seed ^ 0x5A5A5A5A (대칭키 연산 후 hex 제출)",
    }


@app.post("/api/mission2/uds_security_unlock")
def unlock_security_access(req: UDSKeyRequest):
    """Mission 2-C: UDS Mode 0x27 Subfunction 0x02 SecurityAccess Key 검증 및 언락"""
    if state.pending_seed is None:
        raise HTTPException(status_code=400, detail="No pending seed found. Request seed first with POST /api/mission2/uds_security_seed")

    expected_key = state.pending_seed ^ 0x5A5A5A5A
    expected_hex = f"{expected_key:08X}"

    submitted_hex = req.key_hex.strip().replace("0x", "").upper()
    state.log_frame("0x7DF", 8, f"062702{submitted_hex[:4]}0000", f"UDS Req: SendKey={submitted_hex}")

    if submitted_hex != expected_hex:
        state.log_frame("0x7E8", 8, "037F273500000000", "UDS NegResp: InvalidKey (0x35)")
        return {
            "status": "failed",
            "message": f"NRC 0x35: Invalid Key! 제출된 키 {submitted_hex} 가 올바르지 않습니다.",
        }

    state.security_unlocked = True
    state.pending_seed = None
    state.log_frame("0x7E8", 8, "0267020000000000", "UDS PosResp: SecurityAccess Unlocked!")

    return {
        "status": "unlocked",
        "security_level": "UNLOCKED (0x01)",
        "message": "🎉 SecurityAccess 인증 성공! 파워트레인 ECU 제어 권한을 획득하였습니다.",
        "flag": FLAG_UDS,
    }


@app.post("/api/mission3/uds_download_firmware")
def download_firmware(req: UDSDownloadRequest):
    """Mission 3-A: UDS Mode 0x34 RequestDownload 펌웨어 블록 덤프"""
    if not state.security_unlocked:
        state.log_frame("0x7E8", 8, "037F343300000000", "UDS NegResp: SecurityAccessDenied (0x33)")
        raise HTTPException(status_code=403, detail="NRC 0x33: SecurityAccess Denied. Unlock ECU first.")

    addr = req.memory_address_hex.strip().lower()
    state.log_frame("0x7DF", 8, "0534000800000000", f"UDS Req: RequestDownload addr={addr}")
    state.log_frame("0x7E8", 8, "0474200080000000", "UDS PosResp: MaxBlockLength=0x0080")

    return {
        "status": "ready_to_transfer",
        "service": "0x34 RequestDownload",
        "address": addr,
        "max_block_length": "0x0080",
        "firmware_header": "S19_ECU_CAN_FIRMWARE_V2.1_AUTOSAR_BOOTLOADER",
    }


@app.post("/api/mission3/uds_ecu_reset")
def reset_ecu(req: UDSResetRequest):
    """Mission 3-B: UDS Mode 0x11 ECUReset 강제 리셋 DoS"""
    rt = req.reset_type.strip().lower()
    if rt in ["0x01", "1", "hardreset"]:
        state.failsafe_triggered = True
        state.ecu_status = "FAILSAFE_OFFLINE"
        state.speed = 0.0
        state.rpm = 0
        state.security_unlocked = False
        state.uds_session = "DEFAULT"
        state.log_frame("0x7DF", 8, "0211010000000000", "UDS Req: ECUReset hardReset (0x11 0x01)")
        state.log_frame("0x7E8", 8, "0251010000000000", "UDS PosResp: hardReset Executed! Engine Stopped.")

        return {
            "status": "ecu_reset",
            "message": "💥 CRITICAL: 파워트레인 ECU 강제 하드 리셋(hardReset)으로 인해 차량 주행 제어가 중단되고 페일세이프가 격발되었습니다!",
            "ecu_status": "FAILSAFE_OFFLINE",
            "flag": FLAG_RESET,
        }
    else:
        raise HTTPException(status_code=400, detail="Invalid reset type. Use 'hardReset' or '0x01'")


# ── Web UI Dashboard ─────────────────────────────────────────────────────────
@app.get("/", response_class=HTMLResponse)
def dashboard():
    return """<!DOCTYPE html>
<html lang="ko">
<head>
  <meta charset="UTF-8">
  <title>VibeHacking Lab 21: Automotive CAN Bus & UDS Lab (CarCanLab)</title>
  <style>
    :root {
      --bg: #070b14;
      --card: #0f172a;
      --border: #1e293b;
      --accent: #38bdf8;
      --danger: #ef4444;
      --success: #10b981;
      --warning: #f59e0b;
      --text: #f8fafc;
      --muted: #94a3b8;
    }
    body {
      background: var(--bg);
      color: var(--text);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, monospace;
      margin: 0;
      padding: 1.5rem;
    }
    .container { max-width: 1200px; margin: 0 auto; }
    h1 { color: var(--accent); margin-bottom: 0.25rem; display: flex; align-items: center; gap: 10px; }
    .header-desc { color: var(--muted); margin-top: 0; margin-bottom: 1.5rem; }
    .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
    .card {
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 1.25rem;
      box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.3);
    }
    .card-title { font-size: 1.1rem; font-weight: bold; margin-bottom: 1rem; color: #e2e8f0; display: flex; align-items: center; gap: 8px; }
    
    /* Cluster Gauges */
    .cluster {
      display: flex;
      justify-content: space-around;
      background: #020617;
      border: 2px solid #334155;
      border-radius: 12px;
      padding: 1.5rem;
      margin-bottom: 1.5rem;
    }
    .gauge-box { text-align: center; }
    .gauge-val { font-size: 2.5rem; font-weight: 900; font-family: monospace; color: var(--accent); }
    .gauge-label { color: var(--muted); font-size: 0.85rem; text-transform: uppercase; margin-top: 4px; }
    .danger-val { color: var(--danger) !important; animation: pulse 1s infinite; }
    @keyframes pulse { 0% { opacity: 1; } 50% { opacity: 0.4; } 100% { opacity: 1; } }

    /* Inputs & Buttons */
    .input-row { display: flex; gap: 8px; margin-bottom: 10px; }
    input, select {
      background: #090d16;
      border: 1px solid #334155;
      color: white;
      padding: 8px 12px;
      border-radius: 6px;
      font-family: monospace;
      font-size: 0.9rem;
    }
    button {
      background: var(--accent);
      color: #070b14;
      border: none;
      padding: 8px 16px;
      border-radius: 6px;
      font-weight: bold;
      cursor: pointer;
      transition: all 0.2s;
    }
    button:hover { filter: brightness(1.15); }
    button.btn-danger { background: var(--danger); color: white; }
    button.btn-warn { background: var(--warning); color: black; }

    /* Console Terminal */
    .terminal {
      background: #020617;
      border: 1px solid #1e293b;
      border-radius: 6px;
      padding: 10px;
      font-family: monospace;
      font-size: 0.82rem;
      height: 220px;
      overflow-y: auto;
      color: #34d399;
    }
    .log-line { margin-bottom: 4px; border-bottom: 1px solid #0f172a; padding-bottom: 2px; }
    .badge { padding: 3px 8px; border-radius: 4px; font-size: 0.75rem; font-weight: bold; }
    .badge-ok { background: #065f46; color: #34d399; }
    .badge-lock { background: #991b1b; color: #fca5a5; }
    .res-box { margin-top: 10px; padding: 10px; border-radius: 6px; font-family: monospace; font-size: 0.9rem; display: none; }
  </style>
</head>
<body>
  <div class="container">
    <h1>🚗 VibeHacking Lab 21: Automotive CAN & UDS Security (CarCanLab)</h1>
    <p class="header-desc">차량용 CAN 버스 패킷 스니핑/주입, UDS Diagnostic 세션 제어, SecurityAccess 시드-키 역연산 및 ECU DoS 실습</p>

    <!-- Virtual Instrument Cluster -->
    <div class="cluster">
      <div class="gauge-box">
        <div id="dispSpeed" class="gauge-val">60</div>
        <div class="gauge-label">Vehicle Speed (km/h)</div>
      </div>
      <div class="gauge-box">
        <div id="dispRpm" class="gauge-val" style="color: #a855f7;">2400</div>
        <div class="gauge-label">Engine RPM</div>
      </div>
      <div class="gauge-box">
        <div id="dispSession" class="gauge-val" style="font-size: 1.8rem; color: #38bdf8;">DEFAULT</div>
        <div class="gauge-label">UDS Session (0x10)</div>
      </div>
      <div class="gauge-box">
        <div id="dispSecurity" class="gauge-val" style="font-size: 1.8rem; color: var(--danger);">LOCKED</div>
        <div class="gauge-label">SecurityAccess (0x27)</div>
      </div>
    </div>

    <div class="grid">
      <!-- Mission 1: CAN Injection -->
      <div class="card">
        <div class="card-title">⚡ Mission 1: CAN 프레임 주입 (Speed Spoofing)</div>
        <p style="color: var(--muted); font-size: 0.85rem;">
          CAN ID <code>0x120</code>의 2번째 바이트를 변조하여 계기판 속도를 200 km/h 이상으로 스푸핑하세요.
        </p>
        <div class="input-row">
          <input id="canIdInput" style="width: 90px;" value="0x120" placeholder="CAN ID">
          <input id="canDlcInput" style="width: 50px;" value="8" placeholder="DLC">
          <input id="canPayloadInput" style="flex: 1;" value="0000C80000000000" placeholder="Payload Hex (16 chars)">
          <button onclick="injectCAN()">CAN 주입</button>
        </div>
        <div id="resM1" class="res-box"></div>
      </div>

      <!-- Mission 2: UDS SecurityAccess -->
      <div class="card">
        <div class="card-title">🔐 Mission 2: UDS SecurityAccess 시드-키 인증 우회</div>
        <p style="color: var(--muted); font-size: 0.85rem;">
          1) 세션을 <code>extended(0x03)</code>로 전환 ➔ 2) Seed 요청 ➔ 3) <code>key = seed ^ 0x5A5A5A5A</code> 계산 후 제출.
        </p>
        <div class="input-row">
          <button onclick="changeSession('extended')">세션 전환 (0x03)</button>
          <button onclick="requestSeed()" class="btn-warn">Seed 요청 (0x27 01)</button>
        </div>
        <div class="input-row">
          <input id="seedDisp" style="width: 140px;" placeholder="Seed: ??" readonly>
          <input id="keyInput" style="flex: 1;" placeholder="계산된 Key Hex (8자리)">
          <button onclick="sendKey()">Key 검증 (0x27 02)</button>
        </div>
        <div id="resM2" class="res-box"></div>
      </div>

      <!-- Mission 3: ECU Download & Reset -->
      <div class="card">
        <div class="card-title">💥 Mission 3: ECU 펌웨어 블록 덤프 & 하드 리셋</div>
        <p style="color: var(--muted); font-size: 0.85rem;">
          보안 언락 후 펌웨어 다운로드(0x34) 요청 및 ECU hardReset(0x11)을 트리거하여 페일세이프를 유발하세요.
        </p>
        <div class="input-row">
          <button onclick="downloadFirmware()">펌웨어 블록 덤프 (0x34)</button>
          <button onclick="resetECU()" class="btn-danger">ECU hardReset DoS (0x11)</button>
        </div>
        <div id="resM3" class="res-box"></div>
      </div>

      <!-- Realtime CAN Traffic Sniffer -->
      <div class="card">
        <div class="card-title">📡 가상 CAN 버스 트래픽 모니터 (candump vcan0)</div>
        <div class="terminal" id="canTrafficTerm"></div>
      </div>
    </div>
  </div>

  <script>
    let currentSeedHex = null;

    async function updateDashboard() {
      try {
        const res = await fetch('/api/status');
        const data = await res.json();
        const tel = data.telemetry;

        const spdElem = document.getElementById('dispSpeed');
        spdElem.innerText = Math.round(tel.speed_kmh);
        if (tel.speed_kmh >= 200) spdElem.classList.add('danger-val');
        else spdElem.classList.remove('danger-val');

        document.getElementById('dispRpm').innerText = tel.engine_rpm;
        document.getElementById('dispSession').innerText = tel.uds_session;
        
        const secElem = document.getElementById('dispSecurity');
        if (tel.security_unlocked) {
          secElem.innerText = 'UNLOCKED';
          secElem.style.color = '#10b981';
        } else {
          secElem.innerText = 'LOCKED';
          secElem.style.color = '#ef4444';
        }

        // Fetch CAN Traffic
        const cRes = await fetch('/api/can/traffic');
        const cData = await cRes.json();
        const term = document.getElementById('canTrafficTerm');
        term.innerHTML = cData.traffic.map(f => `
          <div class="log-line">
            <span style="color:#64748b;">${new Date(f.time * 1000).toISOString().substr(11, 8)}</span>
            <b style="color:#38bdf8;">${f.can_id}</b> [${f.dlc}] <span style="color:#f1f5f9;">${f.data}</span>
            <span style="color:#a855f7; font-size: 0.78rem;"># ${f.desc}</span>
          </div>
        `).reverse().join('');
      } catch (e) {
        console.error(e);
      }
    }

    async function injectCAN() {
      const cid = document.getElementById('canIdInput').value;
      const dlc = parseInt(document.getElementById('canDlcInput').value);
      const payload = document.getElementById('canPayloadInput').value;
      const rBox = document.getElementById('resM1');

      const res = await fetch('/api/mission1/can_inject', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({can_id: cid, dlc: dlc, payload_hex: payload})
      });
      const d = await res.json();
      rBox.style.display = 'block';
      rBox.style.background = d.flag ? 'rgba(16, 185, 129, 0.2)' : 'rgba(30, 41, 59, 0.7)';
      rBox.innerHTML = `<b>${d.message}</b> ${d.flag ? '<br><span style="color:#10b981; font-weight:bold;">🚩 ' + d.flag + '</span>' : ''}`;
      updateDashboard();
    }

    async function changeSession(type) {
      const res = await fetch('/api/mission2/uds_session', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({session_type: type})
      });
      const d = await res.json();
      alert(d.message);
      updateDashboard();
    }

    async function requestSeed() {
      const res = await fetch('/api/mission2/uds_security_seed', {method: 'POST'});
      const d = await res.json();
      if (res.status === 200) {
        currentSeedHex = d.seed_hex;
        document.getElementById('seedDisp').value = 'Seed: ' + d.seed_hex;
        // Auto-calculate hint for convenience
        const seedInt = parseInt(d.seed_hex, 16);
        const keyInt = (seedInt ^ 0x5A5A5A5A) >>> 0;
        document.getElementById('keyInput').value = keyInt.toString(16).toUpperCase().padStart(8, '0');
      } else {
        alert(d.detail || 'Seed 요청 실패');
      }
      updateDashboard();
    }

    async function sendKey() {
      const key = document.getElementById('keyInput').value;
      const rBox = document.getElementById('resM2');
      const res = await fetch('/api/mission2/uds_security_unlock', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({key_hex: key})
      });
      const d = await res.json();
      rBox.style.display = 'block';
      rBox.style.background = d.flag ? 'rgba(16, 185, 129, 0.2)' : 'rgba(239, 68, 68, 0.2)';
      rBox.innerHTML = `<b>${d.message}</b> ${d.flag ? '<br><span style="color:#10b981; font-weight:bold;">🚩 ' + d.flag + '</span>' : ''}`;
      updateDashboard();
    }

    async function downloadFirmware() {
      const rBox = document.getElementById('resM3');
      const res = await fetch('/api/mission3/uds_download_firmware', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({memory_address_hex: '0x08000000', memory_size_hex: '0x00010000'})
      });
      const d = await res.json();
      rBox.style.display = 'block';
      rBox.style.background = 'rgba(30, 41, 59, 0.7)';
      rBox.innerHTML = `<b>Firmware Block Read:</b> ${d.firmware_header || d.detail}`;
      updateDashboard();
    }

    async function resetECU() {
      const rBox = document.getElementById('resM3');
      const res = await fetch('/api/mission3/uds_ecu_reset', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({reset_type: 'hardReset'})
      });
      const d = await res.json();
      rBox.style.display = 'block';
      rBox.style.background = 'rgba(239, 68, 68, 0.2)';
      rBox.innerHTML = `<b>${d.message}</b> ${d.flag ? '<br><span style="color:#10b981; font-weight:bold;">🚩 ' + d.flag + '</span>' : ''}`;
      updateDashboard();
    }

    setInterval(updateDashboard, 2500);
    updateDashboard();
  </script>
</body>
</html>
"""
