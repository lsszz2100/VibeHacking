"""
Lab 37: BLEShield — Bluetooth Low Energy & SDR Wireless Security Lab
VibeHacking Security Engineering Platform
Port: 8037
"""

import os
import re
import hashlib
from typing import Dict, Any, Optional, List
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

app = FastAPI(
    title="Lab 37: BLEShield - Bluetooth LE & SDR Wireless Security Lab",
    description="GATT Recon, Unauthenticated Characteristic Write, Legacy Pairing Cracking & LESC ECDH Hardening",
    version="1.0.0"
)

# Step Flags
STEP1_FLAG = "FLAG{BLE_GATT_SERVICE_RECON_HANDLE_EXPOSED_8841}"
STEP2_FLAG = "FLAG{BLE_UNAUTH_GATT_WRITE_DOORLOCK_OPENED_7732}"
STEP3_FLAG = "FLAG{BLE_LEGACY_JUSTWORKS_REPLAY_MITM_CRACKED_5519}"
STEP4_FLAG = "FLAG{BLE_LESC_ECDH_SECURE_CONNECTIONS_HARDENED_9921}"

# In-Memory State
state = {
    "step1_completed": False,
    "step2_completed": False,
    "step3_completed": False,
    "step4_completed": False,
    "harden_applied": False,
    "doorlock_status": "LOCKED",
    "pairing_mode": "Just Works (Legacy BLE 4.0/4.1)",
    "lesc_enabled": False,
    "auth_write_required": False,
    "anti_replay_enabled": False,
    "used_nonces": set(),
    "audit_logs": [],
}

def reset_lab():
    """Reset lab state to vulnerable defaults."""
    state["step1_completed"] = False
    state["step2_completed"] = False
    state["step3_completed"] = False
    state["step4_completed"] = False
    state["harden_applied"] = False
    state["doorlock_status"] = "LOCKED"
    state["pairing_mode"] = "Just Works (Legacy BLE 4.0/4.1)"
    state["lesc_enabled"] = False
    state["auth_write_required"] = False
    state["anti_replay_enabled"] = False
    state["used_nonces"] = set()
    state["audit_logs"] = []

# Mock BLE Device Profile
TARGET_MAC = "AA:BB:CC:11:22:33"
TARGET_NAME = "SmartLock-BLE-v4"

BLE_PERIPHERALS = [
    {
        "mac": TARGET_MAC,
        "name": TARGET_NAME,
        "rssi": -52,
        "adv_data": {
            "flags": "0x06 (LE General Discoverable, BR/EDR Not Supported)",
            "services": ["0xFFE0", "0x180A"],
            "tx_power": "0 dBm",
            "manufacturer_id": "0x004C (Apple/iBeacon compatible)"
        }
    },
    {
        "mac": "DE:AD:BE:EF:88:99",
        "name": "BLE-Beacon-BeaconSense",
        "rssi": -78,
        "adv_data": {
            "flags": "0x04",
            "services": ["0x1800"],
            "tx_power": "-4 dBm"
        }
    }
]

GATT_DATABASE = {
    TARGET_MAC: {
        "services": [
            {
                "uuid": "0x180A",
                "name": "Device Information Service",
                "characteristics": [
                    {
                        "uuid": "0x2A24",
                        "handle": "0x0002",
                        "name": "Model Number String",
                        "properties": ["READ"],
                        "value": "SL-400-PRO"
                    },
                    {
                        "uuid": "0x2A26",
                        "handle": "0x0004",
                        "name": "Firmware Revision String",
                        "properties": ["READ"],
                        "value": "v1.0.4-vulnerable"
                    }
                ]
            },
            {
                "uuid": "0xFFE0",
                "name": "SmartLock Actuator & Auth Service",
                "characteristics": [
                    {
                        "uuid": "0000ffe1-0000-1000-8000-00805f9b34fb",
                        "handle": "0x0012",
                        "name": "Telemetry & Lock Status",
                        "properties": ["READ", "NOTIFY"],
                        "value": "STATUS:LOCKED|BATTERY:94%"
                    },
                    {
                        "uuid": "0000ffe2-0000-1000-8000-00805f9b34fb",
                        "handle": "0x0014",
                        "name": "Actuator Direct Command",
                        "properties": ["READ", "WRITE_NO_RESP", "WRITE"],
                        "value": "0x00"
                    },
                    {
                        "uuid": "0000ffe3-0000-1000-8000-00805f9b34fb",
                        "handle": "0x0016",
                        "name": "Auth Challenge & Legacy PIN",
                        "properties": ["READ", "WRITE"],
                        "value": "0x000000"
                    }
                ]
            }
        ]
    }
}

CAPTURED_SNOOP_PACKET = {
    "frame_id": 412,
    "timestamp": "2026-10-06 22:15:30.104",
    "initiator_mac": "11:22:33:44:55:66",
    "responder_mac": TARGET_MAC,
    "protocol": "SMP (Security Manager Protocol)",
    "opcode": "0x01 (Pairing Request) / 0x02 (Pairing Response)",
    "io_capability": "NoInputNoOutput (0x03)",
    "oob_data_flag": "0x00 (Not Present)",
    "auth_req": "0x01 (Bonding, No MITM)",
    "derived_method": "Just Works (Temporary Key TK = 0x00000000)",
    "mrand": "4b7f8c1092a4de315f6208a1c93e44d0",
    "srand": "91e2b58830cf4417b120f04e8ac5b128",
    "mconfirm": "7c98b21a0f4439c18f1a238e55cb4701",
    "sconfirm": "6a14389df0b712c9b4e1809d43ac7712",
    "valid_auth_token": "BLE_AUTH_REPLAY_TKN_9942FA"
}

# Request Models
class BleWriteRequest(BaseModel):
    mac: str
    handle: str
    value: str

class BleCrackRequest(BaseModel):
    mac: str
    tk_guess: str = "000000"
    mrand: Optional[str] = None
    mconfirm: Optional[str] = None

class BleReplayRequest(BaseModel):
    mac: str
    auth_token: str
    nonce: Optional[str] = "NONCE_STATIC_001"

class BleHardenRequest(BaseModel):
    enforce_lesc_ecdh: bool = True
    require_gatt_auth: bool = True
    enable_anti_replay: bool = True


@app.get("/health")
def health() -> Dict[str, Any]:
    return {
        "status": "ok",
        "lab": "37_bluetooth_sdr_security_lab",
        "port": 8037,
        "step1_completed": state["step1_completed"],
        "step2_completed": state["step2_completed"],
        "step3_completed": state["step3_completed"],
        "step4_completed": state["step4_completed"],
        "harden_applied": state["harden_applied"]
    }


@app.get("/api/ble/status")
def get_ble_status() -> Dict[str, Any]:
    return {
        "target_mac": TARGET_MAC,
        "target_name": TARGET_NAME,
        "doorlock_status": state["doorlock_status"],
        "pairing_mode": state["pairing_mode"],
        "lesc_enabled": state["lesc_enabled"],
        "auth_write_required": state["auth_write_required"],
        "anti_replay_enabled": state["anti_replay_enabled"],
        "step1_completed": state["step1_completed"],
        "step2_completed": state["step2_completed"],
        "step3_completed": state["step3_completed"],
        "step4_completed": state["step4_completed"],
        "harden_applied": state["harden_applied"]
    }


@app.get("/api/ble/scan")
def scan_peripherals() -> Dict[str, Any]:
    """Scan and return discovered BLE peripherals."""
    state["step1_completed"] = True
    return {
        "status": "success",
        "peripherals_found": len(BLE_PERIPHERALS),
        "devices": BLE_PERIPHERALS,
        "step1_flag": STEP1_FLAG
    }


@app.get("/api/ble/services")
def get_services(mac: str) -> Dict[str, Any]:
    """Inspect GATT Primary Services and Characteristic Handles."""
    mac_upper = mac.upper()
    if mac_upper not in GATT_DATABASE:
        raise HTTPException(status_code=404, detail=f"Device with MAC {mac} not found in GATT cache.")
    
    state["step1_completed"] = True
    return {
        "status": "success",
        "mac": mac_upper,
        "services": GATT_DATABASE[mac_upper]["services"],
        "flag": STEP1_FLAG
    }


@app.post("/api/ble/write")
def write_characteristic(req: BleWriteRequest) -> Dict[str, Any]:
    """Write value to specified characteristic handle."""
    mac_upper = req.mac.upper()
    handle_lower = req.handle.lower().strip()
    val_clean = req.value.strip().upper()

    if mac_upper != TARGET_MAC:
        raise HTTPException(status_code=404, detail="Device not found.")

    # Check hardening security rules
    if state["auth_write_required"]:
        raise HTTPException(
            status_code=403,
            detail="[ATT_ERR_INSUFFICIENT_AUTHENTICATION] Characteristic requires authenticated link with LESC ECDH."
        )

    # Actuator control handle is 0x0014 (Char 0xFFE2)
    if handle_lower in ["0x0014", "14", "0x14"]:
        if val_clean in ["01", "0X01", "UNLOCK", "OPEN", "1"]:
            state["doorlock_status"] = "UNLOCKED"
            state["step2_completed"] = True
            log_entry = f"Handle 0x0014 Write {val_clean} -> Doorlock UNLOCKED (Unauthenticated)"
            state["audit_logs"].append(log_entry)
            return {
                "status": "success",
                "handle": "0x0014",
                "action": "DOORLOCK_UNLOCKED",
                "doorlock_status": state["doorlock_status"],
                "flag": STEP2_FLAG,
                "message": "Unauthenticated GATT write succeeded! Actuator triggered."
            }
        elif val_clean in ["00", "0X00", "LOCK", "CLOSE", "0"]:
            state["doorlock_status"] = "LOCKED"
            return {"status": "success", "handle": "0x0014", "action": "DOORLOCK_LOCKED"}
        else:
            return {"status": "success", "handle": "0x0014", "value_written": req.value}

    return {"status": "success", "handle": req.handle, "value_written": req.value}


@app.get("/api/ble/snoop_traffic")
def snoop_traffic() -> Dict[str, Any]:
    """Dump captured SMP pairing exchange frames for offline analysis."""
    return {
        "status": "success",
        "description": "Captured BLE Security Manager Protocol (SMP) packet capture",
        "packet": CAPTURED_SNOOP_PACKET
    }


@app.post("/api/ble/crack_pairing")
def crack_pairing(req: BleCrackRequest) -> Dict[str, Any]:
    """Verify cracked TK from Just Works or PIN and compute STK."""
    if req.mac.upper() != TARGET_MAC:
        raise HTTPException(status_code=404, detail="Target device not found.")

    tk_clean = req.tk_guess.strip()
    # Just Works pairing TK is 000000 (all zeros)
    if tk_clean in ["0", "000000", "0x0", "0x000000", "JUSTWORKS"]:
        # STK = c1(TK, Srand, Mrand, ...)
        stk_hash = hashlib.sha256(f"STK_{tk_clean}_{CAPTURED_SNOOP_PACKET['mrand']}".encode()).hexdigest()[:16]
        state["step3_completed"] = True
        return {
            "status": "success",
            "derived_tk": "000000 (Just Works)",
            "short_term_key_stk": f"0x{stk_hash}",
            "flag": STEP3_FLAG,
            "message": "Legacy Just Works TK cracked! STK successfully derived."
        }
    else:
        raise HTTPException(status_code=400, detail="Invalid TK guess. Legacy Just Works uses default zero key.")


@app.post("/api/ble/replay_auth")
def replay_auth(req: BleReplayRequest) -> Dict[str, Any]:
    """Replay captured authentication token."""
    if req.mac.upper() != TARGET_MAC:
        raise HTTPException(status_code=404, detail="Target device not found.")

    if state["anti_replay_enabled"]:
        nonce = req.nonce or "NONCE_STATIC_001"
        if nonce in state["used_nonces"]:
            raise HTTPException(
                status_code=403,
                detail="[REPLAY_DETECTED] Nonce has already been consumed. Anti-replay counter rejected duplicate request."
            )
        state["used_nonces"].add(nonce)

    if req.auth_token.strip() == CAPTURED_SNOOP_PACKET["valid_auth_token"]:
        state["doorlock_status"] = "UNLOCKED"
        state["step3_completed"] = True
        return {
            "status": "success",
            "action": "AUTH_REPLAY_ACCEPTED",
            "doorlock_status": state["doorlock_status"],
            "flag": STEP3_FLAG,
            "message": "Captured authentication token replayed successfully!"
        }
    else:
        raise HTTPException(status_code=401, detail="Invalid authentication token provided.")


@app.post("/api/ble/harden")
def harden_ble(req: BleHardenRequest) -> Dict[str, Any]:
    """Apply LE Secure Connections (LESC ECDH) and GATT security policies."""
    state["lesc_enabled"] = req.enforce_lesc_ecdh
    state["auth_write_required"] = req.require_gatt_auth
    state["anti_replay_enabled"] = req.enable_anti_replay
    state["harden_applied"] = req.enforce_lesc_ecdh and req.require_gatt_auth and req.enable_anti_replay

    if state["harden_applied"]:
        state["pairing_mode"] = "LE Secure Connections (P-256 ECDH Numeric Comparison)"
        state["step4_completed"] = True
        return {
            "status": "success",
            "lesc_enabled": True,
            "auth_write_required": True,
            "anti_replay_enabled": True,
            "pairing_mode": state["pairing_mode"],
            "flag": STEP4_FLAG,
            "message": "BLE security hardening applied! Unauthenticated writes blocked and ECDH key exchange enforced."
        }
    return {
        "status": "partial",
        "message": "Hardening settings updated partially."
    }


@app.post("/api/ble/reset")
def reset_endpoint() -> Dict[str, Any]:
    reset_lab()
    return {"status": "success", "message": "Lab 37 state reset to default."}


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    return """<!DOCTYPE html>
<html lang="ko">
<head>
  <meta charset="UTF-8">
  <title>Lab 37: BLEShield — Bluetooth LE & SDR Wireless Security Lab</title>
  <style>
    :root {
      --bg: #0d1117;
      --card: #161b22;
      --border: #30363d;
      --accent: #58a6ff;
      --success: #238636;
      --warning: #d29922;
      --danger: #f85149;
      --text: #c9d1d9;
      --code-bg: #090d13;
    }
    body {
      margin: 0;
      padding: 24px;
      background: var(--bg);
      color: var(--text);
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
    }
    h1, h2, h3 { color: #f0f6fc; }
    .header {
      border-bottom: 1px solid var(--border);
      padding-bottom: 16px;
      margin-bottom: 24px;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    .badge {
      display: inline-block;
      padding: 4px 10px;
      border-radius: 12px;
      font-size: 0.82rem;
      font-weight: 600;
    }
    .badge-port { background: rgba(88, 166, 255, 0.2); color: var(--accent); }
    .badge-locked { background: rgba(248, 81, 73, 0.2); color: var(--danger); }
    .badge-unlocked { background: rgba(35, 134, 54, 0.2); color: #3fb950; }
    .grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 20px;
    }
    .card {
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 20px;
    }
    .btn {
      background: #238636;
      color: #fff;
      border: none;
      padding: 8px 16px;
      border-radius: 6px;
      cursor: pointer;
      font-weight: 600;
      font-size: 0.9rem;
      transition: background 0.2s;
    }
    .btn:hover { background: #2ea043; }
    .btn-warn { background: #d29922; }
    .btn-warn:hover { background: #bb8019; }
    .btn-danger { background: #da3633; }
    .btn-danger:hover { background: #f85149; }
    pre {
      background: var(--code-bg);
      padding: 12px;
      border-radius: 6px;
      overflow-x: auto;
      font-size: 0.85rem;
      border: 1px solid var(--border);
      color: #58a6ff;
    }
    .flag-box {
      background: rgba(35, 134, 54, 0.15);
      border: 1px solid var(--success);
      padding: 10px;
      border-radius: 6px;
      margin: 10px 0;
      font-family: monospace;
      font-size: 0.9rem;
      color: #3fb950;
    }
    input, select {
      background: var(--code-bg);
      border: 1px solid var(--border);
      color: var(--text);
      padding: 6px 10px;
      border-radius: 4px;
      margin-right: 8px;
    }
  </style>
</head>
<body>
  <div class="header">
    <div>
      <h1>📡 Lab 37: BLEShield — Bluetooth LE & SDR 무선 보안 실전 랩</h1>
      <p style="margin: 4px 0; color: #8b949e;">GATT 프로파일 정찰 · 비인가 특성 쓰기 · 레거시 Just Works 스니핑/크래킹 · LESC ECDH 하드닝</p>
    </div>
    <div>
      <span class="badge badge-port">포트: 8037</span>
      <button class="btn btn-danger" onclick="resetLab()">상태 리셋</button>
    </div>
  </div>

  <div class="grid">
    <div class="card">
      <h2>🎯 실습 현황 및 타깃 디바이스</h2>
      <p><strong>타깃 기기:</strong> SmartLock-BLE-v4 (<code>AA:BB:CC:11:22:33</code>)</p>
      <p><strong>도어락 상태:</strong> <span id="lock-badge" class="badge badge-locked">LOCKED</span></p>
      <p><strong>페어링 프로토콜:</strong> <span id="pairing-mode">Just Works (Legacy BLE 4.0/4.1)</span></p>
      <hr style="border: 0; border-top: 1px solid var(--border); margin: 16px 0;">
      
      <h3>1단계: BLE 스니핑 & GATT 프로파일 정찰</h3>
      <button class="btn" onclick="scanBle()">BLE 기기 및 서비스 스캔</button>
      <div id="step1-res" style="margin-top: 10px;"></div>

      <h3 style="margin-top: 20px;">2단계: 비인가 Characteristic 쓰기 (도어락 언락)</h3>
      <p style="font-size: 0.85rem; color: #8b949e;">Handle <code>0x0014</code> (Char 0xFFE2)에 인증 없이 UNLOCK(01) 커맨드 전송</p>
      <input type="text" id="write-handle" value="0x0014" style="width: 80px;">
      <input type="text" id="write-val" value="01" style="width: 80px;">
      <button class="btn btn-warn" onclick="writeChar()">명령어 쓰기 전송</button>
      <div id="step2-res" style="margin-top: 10px;"></div>
    </div>

    <div class="card">
      <h2>⚔️ 고급 공격 & 방어</h2>
      <h3>3단계: 레거시 Just Works TK 크래킹 & Replay 공격</h3>
      <button class="btn" onclick="snoopTraffic()">스니핑된 SMP 패킷 확인</button>
      <button class="btn btn-warn" onclick="crackTK()">Just Works TK 크래킹</button>
      <button class="btn btn-warn" onclick="replayAuth()">인증 토큰 재생</button>
      <div id="step3-res" style="margin-top: 10px;"></div>

      <h3 style="margin-top: 20px;">4단계: LE Secure Connections (LESC ECDH) 하드닝</h3>
      <p style="font-size: 0.85rem; color: #8b949e;">ECDH P-256 키 교환 강제 · Authenticated Write 강제 · Anti-Replay 토큰 적용</p>
      <button class="btn btn-danger" onclick="hardenBle()">보안 하드닝 적용</button>
      <div id="step4-res" style="margin-top: 10px;"></div>

      <h3 style="margin-top: 20px;">📜 터미널 응답 콘솔</h3>
      <pre id="console-log">// API 호출 결과 및 텔레메트리 로그가 여기에 표시됩니다.</pre>
    </div>
  </div>

  <script>
    async function updateStatus() {
      const res = await fetch('/api/ble/status');
      const data = await res.json();
      const badge = document.getElementById('lock-badge');
      badge.textContent = data.doorlock_status;
      badge.className = 'badge ' + (data.doorlock_status === 'UNLOCKED' ? 'badge-unlocked' : 'badge-locked');
      document.getElementById('pairing-mode').textContent = data.pairing_mode;
    }

    async function scanBle() {
      const res = await fetch('/api/ble/scan');
      const data = await res.json();
      document.getElementById('console-log').textContent = JSON.stringify(data, null, 2);
      if (data.step1_flag) {
        document.getElementById('step1-res').innerHTML = `<div class="flag-box">🚩 Step 1 플래그: ${data.step1_flag}</div>`;
      }
      updateStatus();
    }

    async function writeChar() {
      const handle = document.getElementById('write-handle').value;
      const value = document.getElementById('write-val').value;
      const res = await fetch('/api/ble/write', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({mac: 'AA:BB:CC:11:22:33', handle, value})
      });
      const data = await res.json();
      document.getElementById('console-log').textContent = JSON.stringify(data, null, 2);
      if (data.flag) {
        document.getElementById('step2-res').innerHTML = `<div class="flag-box">🚩 Step 2 플래그: ${data.flag}</div>`;
      }
      updateStatus();
    }

    async function snoopTraffic() {
      const res = await fetch('/api/ble/snoop_traffic');
      const data = await res.json();
      document.getElementById('console-log').textContent = JSON.stringify(data, null, 2);
    }

    async function crackTK() {
      const res = await fetch('/api/ble/crack_pairing', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({mac: 'AA:BB:CC:11:22:33', tk_guess: '000000'})
      });
      const data = await res.json();
      document.getElementById('console-log').textContent = JSON.stringify(data, null, 2);
      if (data.flag) {
        document.getElementById('step3-res').innerHTML = `<div class="flag-box">🚩 Step 3 플래그: ${data.flag}</div>`;
      }
      updateStatus();
    }

    async function replayAuth() {
      const res = await fetch('/api/ble/replay_auth', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({mac: 'AA:BB:CC:11:22:33', auth_token: 'BLE_AUTH_REPLAY_TKN_9942FA'})
      });
      const data = await res.json();
      document.getElementById('console-log').textContent = JSON.stringify(data, null, 2);
      if (data.flag) {
        document.getElementById('step3-res').innerHTML = `<div class="flag-box">🚩 Step 3 플래그: ${data.flag}</div>`;
      }
      updateStatus();
    }

    async function hardenBle() {
      const res = await fetch('/api/ble/harden', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({enforce_lesc_ecdh: true, require_gatt_auth: true, enable_anti_replay: true})
      });
      const data = await res.json();
      document.getElementById('console-log').textContent = JSON.stringify(data, null, 2);
      if (data.flag) {
        document.getElementById('step4-res').innerHTML = `<div class="flag-box">🚩 Step 4 플래그: ${data.flag}</div>`;
      }
      updateStatus();
    }

    async function resetLab() {
      await fetch('/api/ble/reset', {method: 'POST'});
      document.getElementById('step1-res').innerHTML = '';
      document.getElementById('step2-res').innerHTML = '';
      document.getElementById('step3-res').innerHTML = '';
      document.getElementById('step4-res').innerHTML = '';
      document.getElementById('console-log').textContent = '// 리셋 완료.';
      updateStatus();
    }

    updateStatus();
  </script>
</body>
</html>
"""
