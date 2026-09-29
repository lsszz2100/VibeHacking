"""Lab 30: GhidraRev - Binary Analysis & Advanced Deobfuscation Security Lab (FastAPI)."""

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
import hashlib
import html
import base64
import time

app = FastAPI(title="GhidraRev - Binary Analysis & Deobfuscation Lab", version="1.0.0")

# ── CTF 플래그 정의 ──────────────────────────────────────────────────────────
FLAGS = {
    "step1": "FLAG{ghidra_headless_symbol_analysis_recovered_8030}",
    "step2": "FLAG{control_flow_flattening_state_machine_defused_3921}",
    "step3": "FLAG{binary_patch_integrity_hash_bypassed_9942}",
}

# ── 바이너리 시뮬레이션 기본 데이터 ──────────────────────────────────────────
MOCK_BINARY = {
    "filename": "firmware_auth_daemon.elf",
    "architecture": "x86_64",
    "file_type": "ELF 64-bit LSB pie executable",
    "stripped": True,
    "entry_point": "0x00401080",
    "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "text_section": {
        "vaddr": "0x00401000",
        "size": 4096,
        "hash": "7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069"
    },
    "strings": [
        {"addr": "0x00402010", "value": "LICENSE_VERIFY_INIT: v3.4.1-rc2"},
        {"addr": "0x00402038", "value": "CRITICAL: Integrity tamper detected! Terminating."},
        {"addr": "0x00402070", "value": "SUCCESS: Enterprise license authenticated."},
        {"addr": "0x004020A0", "value": "FLAG_TOKEN_SEED_GHIDRA_8030"}
    ]
}

# ── 초기 상태 관리 ───────────────────────────────────────────────────────────
state: Dict[str, Any] = {
    "symbols_recovered": False,
    "cff_deobfuscated": False,
    "binary_patched": False,
    "tamper_detected": False,
    "hardened": {
        "cfi_enabled": False,
        "sig_verification": False,
        "anti_patch_sentinel": False
    },
    "history": []
}


def log_event(action: str, detail: str, success: bool = True):
    state["history"].append({
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "action": action,
        "detail": detail,
        "success": success
    })


# ── Pydantic Request Models ──────────────────────────────────────────────────
class SymbolAnalysisRequest(BaseModel):
    script_name: str
    target_function_vaddr: Optional[str] = "0x00401200"
    match_prologue: Optional[bool] = True
    rename_symbol: Optional[str] = "validate_license_core"


class CFFDeobfuscateRequest(BaseModel):
    state_variable_reg: str = "eax"
    dispatcher_vaddr: str = "0x00401240"
    block_transitions: List[int]
    defuse_opaque_predicates: bool = True


class BinaryPatchRequest(BaseModel):
    patch_vaddr: str = "0x00401337"
    original_hex: str = "74 18"
    replacement_hex: str = "90 90"
    bypass_integrity_check: bool = True


class HardenRequest(BaseModel):
    cfi_enabled: bool = False
    sig_verification: bool = False
    anti_patch_sentinel: bool = False


# ── REST API Endpoints ───────────────────────────────────────────────────────
@app.get("/health")
def health():
    return {
        "status": "ok",
        "port": 8030,
        "lab": "Lab 30: GhidraRev - Binary Analysis & Advanced Deobfuscation Security Lab"
    }


@app.get("/api/ghidra/binary/info")
def get_binary_info():
    """바이너리 메타데이터, 섹션 헤더 및 스트링 테이블 열람"""
    return {
        "binary": MOCK_BINARY,
        "symbols_recovered": state["symbols_recovered"],
        "cff_deobfuscated": state["cff_deobfuscated"],
        "binary_patched": state["binary_patched"],
        "hardened": state["hardened"]
    }


@app.get("/api/ghidra/status")
def get_lab_status():
    """랩 진행 상태 및 로그 확인"""
    return {
        "symbols_recovered": state["symbols_recovered"],
        "cff_deobfuscated": state["cff_deobfuscated"],
        "binary_patched": state["binary_patched"],
        "tamper_detected": state["tamper_detected"],
        "hardened": state["hardened"],
        "history": state["history"][-15:]
    }


@app.post("/api/ghidra/analyze/symbols")
def analyze_symbols(req: SymbolAnalysisRequest):
    """Step 1: Ghidra Headless 스크립트를 통한 스트립트 심볼 복원 및 함수 XREF 분석"""
    if "headless" not in req.script_name.lower() and "symbol" not in req.script_name.lower():
        log_event("SYMBOL_ANALYSIS", f"Invalid script name: {req.script_name}", success=False)
        raise HTTPException(
            status_code=400,
            detail="Ghidra Headless 분석 스크립트 파일명을 지정해야 합니다 (예: recover_headless_symbols.py)."
        )

    if not req.match_prologue:
        log_event("SYMBOL_ANALYSIS", "Function prologue pattern matching disabled", success=False)
        raise HTTPException(
            status_code=400,
            detail="x86_64 함수 프롤로그 시그니처 (55 48 89 E5 - push rbp; mov rbp, rsp) 매칭이 필요합니다."
        )

    state["symbols_recovered"] = True
    flag = FLAGS["step1"]
    log_event("SYMBOL_ANALYSIS", f"Recovered symbol '{req.rename_symbol}' at {req.target_function_vaddr}")

    return {
        "success": True,
        "message": f"Ghidra Headless 분석 완료: 스트립트된 함수 {req.target_function_vaddr}의 심볼이 '{req.rename_symbol}'로 복원되었습니다.",
        "recovered_functions": [
            {"vaddr": "0x00401080", "name": "_start", "signature": "void _start()"},
            {"vaddr": "0x00401140", "name": "verify_text_section_checksum", "signature": "int verify_text_section_checksum()"},
            {"vaddr": "0x00401200", "name": req.rename_symbol, "signature": "int validate_license_core(char *key, int len)"},
            {"vaddr": "0x00401390", "name": "display_success_banner", "signature": "void display_success_banner()"}
        ],
        "flag": flag
    }


@app.post("/api/ghidra/deobfuscate/cff")
def deobfuscate_cff(req: CFFDeobfuscateRequest):
    """Step 2: Control Flow Flattening (CFF) 상태 머신 해체 및 불투명 술어 제거"""
    if not state["symbols_recovered"]:
        log_event("CFF_DEOBFUSCATE", "Attempted CFF deobfuscation before symbol recovery", success=False)
        raise HTTPException(
            status_code=400,
            detail="Step 1 심볼 복원 분석을 먼저 수행해야 대상 함수의 제어 흐름 그래프(CFG)를 추출할 수 있습니다."
        )

    # 유효한 상태 전이 경로: [10, 40, 25, 90] (시작 -> 라이선스 헤더 검증 -> 토큰 연산 -> 성공 상태)
    expected_transitions = [10, 40, 25, 90]
    if req.block_transitions != expected_transitions:
        log_event("CFF_DEOBFUSCATE", f"Incorrect transition sequence: {req.block_transitions}", success=False)
        raise HTTPException(
            status_code=400,
            detail=f"상태 변수 {req.state_variable_reg}의 디스패처 전이 시퀀스가 올바르지 않습니다. 예상 전이: [10, 40, 25, 90]"
        )

    if not req.defuse_opaque_predicates:
        log_event("CFF_DEOBFUSCATE", "Opaque predicates not removed", success=False)
        raise HTTPException(
            status_code=400,
            detail="항상 참인 불투명 술어 (Opaque Predicates: (y*(y+1)) % 2 == 0)를 제거(NOP화)해야 평탄화된 AST가 온전히 복원됩니다."
        )

    state["cff_deobfuscated"] = True
    flag = FLAGS["step2"]
    log_event("CFF_DEOBFUSCATE", f"Defused CFF state machine at {req.dispatcher_vaddr} with sequence {req.block_transitions}")

    return {
        "success": True,
        "message": "Control Flow Flattening 디스패처 해체 완료! 정상 제어 흐름 그래프(CFG) 및 라이선스 키 검증 로직이 복원되었습니다.",
        "recovered_logic": (
            "int validate_license_core(char *key, int len) {\n"
            "    if (len != 24) return 0;\n"
            "    if (strncmp(key, \"VIBE-\", 5) != 0) return 0;\n"
            "    int sum = 0;\n"
            "    for (int i=5; i<20; i++) sum ^= key[i];\n"
            "    if (sum != 0x5F) return 0;\n"
            "    return (compute_crc32(key) == 0xA92D1F7B); /* 0x00401337 jz loc_fail */\n"
            "}"
        ),
        "critical_jump": {
            "vaddr": "0x00401337",
            "instruction": "jz loc_license_fail",
            "opcodes": "74 18",
            "condition": "라이선스 해시 불일치 시 0x00401351(실패)로 점프"
        },
        "flag": flag
    }


@app.post("/api/ghidra/patch/binary")
def patch_binary(req: BinaryPatchRequest):
    """Step 3: 안티 탬퍼 무결성 체크 우회 및 분기 명령어 패치 (jz -> nop/jmp)"""
    if not state["cff_deobfuscated"]:
        log_event("BINARY_PATCH", "Attempted binary patch before CFF deobfuscation", success=False)
        raise HTTPException(
            status_code=400,
            detail="Step 2 제어 흐름 난독화 해제를 먼저 완료하여 정확한 패치 대상 가상 주소를 특정해야 합니다."
        )

    if req.patch_vaddr != "0x00401337":
        log_event("BINARY_PATCH", f"Invalid patch target vaddr: {req.patch_vaddr}", success=False)
        raise HTTPException(
            status_code=400,
            detail="패치 대상 가상 주소는 조건부 분기점 0x00401337 이어야 합니다."
        )

    # 74 18 (jz) -> 90 90 (nop nop) 또는 eb 18 (jmp short)
    valid_replacements = ["90 90", "9090", "eb 18", "eb18"]
    normalized_rep = req.replacement_hex.strip().lower()
    if normalized_rep not in valid_replacements:
        log_event("BINARY_PATCH", f"Invalid replacement opcodes: {req.replacement_hex}", success=False)
        raise HTTPException(
            status_code=400,
            detail="대체 바이트는 '90 90' (NOP sled) 또는 'eb 18' (무조건 점프 jmp short) 이어야 합니다."
        )

    # 방어 메커니즘 점검
    if state["hardened"]["anti_patch_sentinel"] and not req.bypass_integrity_check:
        state["tamper_detected"] = True
        log_event("BINARY_PATCH", "Tamper detected: Self-checksum mismatch triggered panic", success=False)
        raise HTTPException(
            status_code=403,
            detail="안티 탬퍼 센티넬 발동: .text 섹션 SHA-256 체크섬 불일치가 감지되어 바이너리가 즉시 중단(abort)되었습니다."
        )

    if state["hardened"]["sig_verification"]:
        log_event("BINARY_PATCH", "Digital signature verification failed", success=False)
        raise HTTPException(
            status_code=403,
            detail="하드닝 적용 중: PKCS#7 / Authenticode 디지털 서명 검증 실패로 패치된 바이너리 실행이 거부되었습니다."
        )

    state["binary_patched"] = True
    flag = FLAGS["step3"]
    log_event("BINARY_PATCH", f"Successfully patched {req.patch_vaddr} ({req.original_hex} -> {req.replacement_hex})")

    return {
        "success": True,
        "message": "바이너리 패치 및 안티 탬퍼 우회 성공! 라이선스 검증 루틴이 무조건 참(True)으로 평가되어 관리자 권한으로 실행됩니다.",
        "patch_result": {
            "vaddr": req.patch_vaddr,
            "original_asm": "jz 0x00401351 (74 18)",
            "patched_asm": "nop; nop (90 90)" if "90" in normalized_rep else "jmp 0x00401351 (eb 18)",
            "execution_status": "SUCCESS: Enterprise license authenticated.",
            "integrity_bypassed": req.bypass_integrity_check
        },
        "flag": flag
    }


@app.post("/api/ghidra/harden")
def toggle_harden(req: HardenRequest):
    """방어자 모드: Control Flow Integrity(CFI) 및 디지털 서명 검증 활성화"""
    state["hardened"] = {
        "cfi_enabled": req.cfi_enabled,
        "sig_verification": req.sig_verification,
        "anti_patch_sentinel": req.anti_patch_sentinel
    }
    log_event("HARDEN_CONFIG", f"Updated hardening config: {state['hardened']}")
    return {
        "success": True,
        "message": "바이너리 방어 및 하드닝 설정이 갱신되었습니다.",
        "hardened": state["hardened"]
    }


@app.post("/api/ghidra/reset")
def reset_lab():
    """랩 상태 초기화"""
    state["symbols_recovered"] = False
    state["cff_deobfuscated"] = False
    state["binary_patched"] = False
    state["tamper_detected"] = False
    state["hardened"] = {
        "cfi_enabled": False,
        "sig_verification": False,
        "anti_patch_sentinel": False
    }
    state["history"].clear()
    log_event("LAB_RESET", "Lab 30 GhidraRev state reset to initial factory values")
    return {
        "success": True,
        "message": "Lab 30 GhidraRev 상태가 성공적으로 초기화되었습니다."
    }


# ── Web UI Template ──────────────────────────────────────────────────────────
@app.get("/", response_class=HTMLResponse)
def index_view():
    return """<!DOCTYPE html>
<html lang="ko">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Lab 30: GhidraRev - Binary Analysis &amp; Deobfuscation</title>
  <style>
    :root {
      --bg: #0a0d14;
      --card-bg: #111726;
      --border: #1e293b;
      --accent: #38bdf8;
      --green: #4ade80;
      --yellow: #facc15;
      --red: #f87171;
      --text: #f1f5f9;
      --muted: #94a3b8;
      --code-bg: #0f172a;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background: var(--bg);
      color: var(--text);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, monospace;
      padding: 24px;
      line-height: 1.5;
    }
    .header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      border-bottom: 1px solid var(--border);
      padding-bottom: 16px;
      margin-bottom: 24px;
    }
    .header h1 { font-size: 20px; color: var(--accent); display: flex; align-items: center; gap: 8px; }
    .badge {
      font-size: 11px;
      padding: 3px 8px;
      border-radius: 4px;
      background: #0369a1;
      color: #e0f2fe;
      font-weight: 700;
    }
    .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
    @media (max-width: 900px) { .grid { grid-template-columns: 1fr; } }
    .card {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 18px;
    }
    .card h2 { font-size: 15px; margin-bottom: 12px; color: var(--accent); border-bottom: 1px solid var(--border); padding-bottom: 6px; }
    pre, code { font-family: "Fira Code", monospace; font-size: 12px; background: var(--code-bg); color: #cbd5e1; }
    pre { padding: 12px; border-radius: 6px; overflow-x: auto; margin: 8px 0; border: 1px solid var(--border); }
    .btn {
      background: #0284c7;
      color: #fff;
      border: none;
      padding: 8px 14px;
      border-radius: 4px;
      cursor: pointer;
      font-size: 12px;
      font-weight: 600;
      transition: background 0.2s;
    }
    .btn:hover { background: #0369a1; }
    .btn-danger { background: #dc2626; }
    .btn-danger:hover { background: #b91c1c; }
    .btn-success { background: #16a34a; }
    .btn-success:hover { background: #15803d; }
    .status-pill {
      display: inline-block;
      padding: 2px 8px;
      border-radius: 12px;
      font-size: 11px;
      font-weight: 700;
      margin-bottom: 8px;
    }
    .status-ok { background: #064e3b; color: var(--green); }
    .status-pending { background: #78350f; color: var(--yellow); }
    .log-box {
      background: var(--code-bg);
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 10px;
      height: 180px;
      overflow-y: auto;
      font-size: 11px;
      color: #94a3b8;
    }
    .step-box {
      border: 1px dashed var(--border);
      padding: 12px;
      border-radius: 6px;
      margin-bottom: 14px;
    }
    .step-title { font-size: 13px; font-weight: 700; color: #e2e8f0; margin-bottom: 4px; }
    .flag-banner {
      background: #1e1b4b;
      border: 1px solid #4338ca;
      color: #a5b4fc;
      padding: 8px;
      border-radius: 4px;
      margin-top: 8px;
      font-weight: 700;
      display: none;
    }
  </style>
</head>
<body>
  <div class="header">
    <h1>🔬 Lab 30: GhidraRev <span class="badge">Port 8030</span></h1>
    <div>
      <button class="btn btn-danger" onclick="resetLab()">Reset Lab</button>
    </div>
  </div>

  <div class="grid">
    <!-- 왼쪽 칼럼: 실습 단계별 워크벤치 -->
    <div class="card">
      <h2>🎯 취약 바이너리 분석 및 단계별 익스플로잇</h2>

      <!-- Step 1 -->
      <div class="step-box">
        <div class="step-title">Step 1: Ghidra Headless 심볼 &amp; 함수 XREF 복원</div>
        <p style="font-size:12px;color:var(--muted);margin-bottom:8px;">
          스트립트된 바이너리의 프롤로그 바이트 시그니처를 스캔하고 핵심 라이선스 검증 함수의 심볼을 복원합니다.
        </p>
        <button class="btn" onclick="runStep1()">Run Ghidra Headless Analyzer</button>
        <div id="flag1" class="flag-banner"></div>
      </div>

      <!-- Step 2 -->
      <div class="step-box">
        <div class="step-title">Step 2: Control Flow Flattening (CFF) 상태 머신 해체</div>
        <p style="font-size:12px;color:var(--muted);margin-bottom:8px;">
          Goron/OLLVM CFF 루프의 상태 전이 시퀀스 [10, 40, 25, 90]를 분석하고 불투명 술어를 제거하여 평탄화된 AST를 디플래트닝합니다.
        </p>
        <button class="btn" onclick="runStep2()">Defuse CFF Dispatcher</button>
        <div id="flag2" class="flag-banner"></div>
      </div>

      <!-- Step 3 -->
      <div class="step-box">
        <div class="step-title">Step 3: 안티 탬퍼 우회 &amp; 바이너리 인라인 패치</div>
        <p style="font-size:12px;color:var(--muted);margin-bottom:8px;">
          가상 주소 <code>0x00401337</code>의 조건부 점프(<code>74 18 jz</code>)를 <code>90 90 nop</code>로 패치하고 자체 체크섬 검증을 우회합니다.
        </p>
        <button class="btn btn-success" onclick="runStep3()">Apply Binary Patch &amp; Bypass Integrity</button>
        <div id="flag3" class="flag-banner"></div>
      </div>
    </div>

    <!-- 오른쪽 칼럼: 역공학 텔레메트리 & 디스어셈블리 뷰어 -->
    <div class="card">
      <h2>📜 바이너리 디스어셈블리 &amp; 텔레메트리 콘솔</h2>
      <pre><code>[0x00401320]  mov    eax, dword ptr [rbp-0x4]
[0x00401323]  cmp    eax, 0xa92d1f7b            ; License Hash Check
[0x00401328]  sete   al
[0x0040132b]  movzx  eax, al
[0x0040132e]  test   eax, eax
[0x00401330]  jz     0x00401351                 ; <-- [CRITICAL VULN] 74 18
[0x00401332]  call   display_success_banner     ; FLAG Revealed
[0x00401337]  jmp    0x00401360</code></pre>

      <h3 style="font-size:13px;color:var(--accent);margin:12px 0 6px;">실시간 감사 로그</h3>
      <div id="logBox" class="log-box"></div>
    </div>
  </div>

  <script>
    async function updateStatus() {
      try {
        const res = await fetch('/api/ghidra/status');
        const data = await res.json();
        const box = document.getElementById('logBox');
        box.innerHTML = data.history.map(h => 
          `<div>[${h.timestamp}] <span style="color:${h.success ? 'var(--green)' : 'var(--red)'}">${h.action}</span>: ${h.detail}</div>`
        ).join('') || '<div>No audit logs yet.</div>';
      } catch (e) {
        console.error(e);
      }
    }

    async function runStep1() {
      const res = await fetch('/api/ghidra/analyze/symbols', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({
          script_name: "recover_headless_symbols.py",
          target_function_vaddr: "0x00401200",
          match_prologue: true,
          rename_symbol: "validate_license_core"
        })
      });
      const data = await res.json();
      if (res.ok) {
        document.getElementById('flag1').style.display = 'block';
        document.getElementById('flag1').innerText = "🚩 Step 1 Flag: " + data.flag;
      } else {
        alert(data.detail);
      }
      updateStatus();
    }

    async function runStep2() {
      const res = await fetch('/api/ghidra/deobfuscate/cff', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({
          state_variable_reg: "eax",
          dispatcher_vaddr: "0x00401240",
          block_transitions: [10, 40, 25, 90],
          defuse_opaque_predicates: true
        })
      });
      const data = await res.json();
      if (res.ok) {
        document.getElementById('flag2').style.display = 'block';
        document.getElementById('flag2').innerText = "🚩 Step 2 Flag: " + data.flag;
      } else {
        alert(data.detail);
      }
      updateStatus();
    }

    async function runStep3() {
      const res = await fetch('/api/ghidra/patch/binary', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({
          patch_vaddr: "0x00401337",
          original_hex: "74 18",
          replacement_hex: "90 90",
          bypass_integrity_check: true
        })
      });
      const data = await res.json();
      if (res.ok) {
        document.getElementById('flag3').style.display = 'block';
        document.getElementById('flag3').innerText = "🚩 Step 3 Flag: " + data.flag;
      } else {
        alert(data.detail);
      }
      updateStatus();
    }

    async function resetLab() {
      await fetch('/api/ghidra/reset', {method: 'POST'});
      document.getElementById('flag1').style.display = 'none';
      document.getElementById('flag2').style.display = 'none';
      document.getElementById('flag3').style.display = 'none';
      updateStatus();
    }

    setInterval(updateStatus, 3000);
    updateStatus();
  </script>
</body>
</html>
"""
