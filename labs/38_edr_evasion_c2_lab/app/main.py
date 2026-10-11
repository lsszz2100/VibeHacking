#!/usr/bin/env python3
"""
Lab 38: EDRShield — EDR Evasion & Next-Gen C2 Lab
Interactive FastAPI service simulating modern EDR architecture, userland hooking,
AMSI/ETW patching, ntdll disk unhooking, dynamic SSN extraction (Hell's/Halo's Gate),
indirect syscall dispatching, and sleep obfuscation (Ekko timer queue ROP).
"""

from typing import Dict, Any, List, Optional
import os
import re
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field

app = FastAPI(
    title="Lab 38: EDRShield — EDR Evasion & Next-Gen C2 Lab",
    description="Hands-on security simulation for modern EDR userland hooking, indirect syscalls, and sleep obfuscation.",
    version="1.0.0",
)

# Flags
STEP1_FLAG = "FLAG{AMSI_ETW_INLINE_PATCH_MEMORY_BYPASS_8819}"
STEP2_FLAG = "FLAG{NTDLL_DISK_UNHOOKING_FRESH_COPY_RESTORED_7721}"
STEP3_FLAG = "FLAG{INDIRECT_SYSCALL_HELLS_GATE_STACK_CLEAN_9934}"
STEP4_FLAG = "FLAG{EKKO_SLEEP_OBFUSCATION_TIMER_QUEUE_ROP_4412}"

# State store
state: Dict[str, Any] = {}


def reset_lab() -> None:
    """Reset the simulated EDR environment to initial hooked baseline."""
    global state
    state = {
        "step1_completed": False,
        "step2_completed": False,
        "step3_completed": False,
        "step4_completed": False,
        "amsi_status": {
            "hooked": True,
            "patched": False,
            "patch_bytes": "None",
            "return_code": "0x00000000 (S_OK - Scanned)",
            "protection": "PAGE_EXECUTE_READ",
        },
        "etw_status": {
            "hooked": True,
            "patched": False,
            "patch_bytes": "None",
            "events_logged": 142,
            "protection": "PAGE_EXECUTE_READ",
        },
        "ntdll_hooks": {
            "NtAllocateVirtualMemory": {
                "rva": "0x00051280",
                "original_bytes": "4c 8b d1 b8 18 00 00 00 0f 05 c3",
                "hooked_bytes": "e9 4b c2 81 7f 90 90 90 0f 05 c3",
                "target": "edrhook.dll!Trampoline_NtAllocate",
                "hooked": True,
                "ssn": 0x0018,
            },
            "NtProtectVirtualMemory": {
                "rva": "0x00051390",
                "original_bytes": "4c 8b d1 b8 50 00 00 00 0f 05 c3",
                "hooked_bytes": "e9 9b d1 81 7f 90 90 90 0f 05 c3",
                "target": "edrhook.dll!Trampoline_NtProtect",
                "hooked": True,
                "ssn": 0x0050,
            },
            "NtWriteVirtualMemory": {
                "rva": "0x00051420",
                "original_bytes": "4c 8b d1 b8 3a 00 00 00 0f 05 c3",
                "hooked_bytes": "e9 22 a0 81 7f 90 90 90 0f 05 c3",
                "target": "edrhook.dll!Trampoline_NtWrite",
                "hooked": True,
                "ssn": 0x003A,
            },
            "NtCreateThreadEx": {
                "rva": "0x00051510",
                "original_bytes": "4c 8b d1 b8 c1 00 00 00 0f 05 c3",
                "hooked_bytes": "e9 77 b4 81 7f 90 90 90 0f 05 c3",
                "target": "edrhook.dll!Trampoline_NtCreateThread",
                "hooked": True,
                "ssn": 0x00C1,
            },
        },
        "unhook_status": {
            "disk_mapped": False,
            "text_section_overwritten": False,
            "active_hooks_count": 4,
        },
        "syscall_invocations": [],
        "c2_beacon": {
            "state": "ACTIVE",
            "memory_protection": "PAGE_EXECUTE_READWRITE",
            "encrypted": False,
            "sleep_mask_technique": "NONE",
            "timer_queue_configured": False,
            "yara_scan_result": "ALERT: Suspicious Beacon Shellcode Detected in RWX region",
        },
    }


# Initial setup
reset_lab()


# Pydantic models for API validation
class AmsiEtwPatchRequest(BaseModel):
    target: str = Field(..., description="'amsi', 'etw', or 'both'")
    patch_hex: str = Field(..., description="Hex string of patch bytes")
    verify_bypass: bool = Field(True, description="Verify whether signature scanning is suppressed")


class UnhookRequest(BaseModel):
    method: str = Field(..., description="'disk_mapping' or 'knowndlls'")
    target_section: str = Field(".text", description="Target PE section to restore")
    restore_bytes: bool = Field(True, description="Overwrite hooked text section with fresh bytes")


class SyscallInvokeRequest(BaseModel):
    function_name: str = Field(..., description="Target Nt API, e.g., NtAllocateVirtualMemory")
    ssn_extraction: str = Field(..., description="'hells_gate', 'halos_gate', or 'hardcoded'")
    execution_mode: str = Field(..., description="'indirect_syscall' or 'direct_syscall'")
    allocation_size: int = Field(4096, description="Memory allocation size in bytes")


class SleepObfuscateRequest(BaseModel):
    technique: str = Field(..., description="'ekko_rop_timer', 'cronos', or 'standard_sleep'")
    sleep_seconds: int = Field(5, ge=1, le=60, description="Beacon sleep duration")
    mask_protection: str = Field("PAGE_READWRITE", description="Memory protection during sleep")
    encryption_algo: str = Field("SystemFunction032_XOR", description="RC4 or XOR memory masking")


@app.get("/health")
def health() -> Dict[str, Any]:
    return {
        "status": "ok",
        "lab": "38_edr_evasion_c2_lab",
        "port": 8038,
        "step1_completed": state["step1_completed"],
        "step2_completed": state["step2_completed"],
        "step3_completed": state["step3_completed"],
        "step4_completed": state["step4_completed"],
    }


@app.post("/api/reset")
def api_reset() -> Dict[str, Any]:
    reset_lab()
    return {"status": "ok", "message": "EDR environment reset to initial hooked state"}


# -------------------------------------------------------------------------
# Step 1: AMSI & ETW In-Memory Patching
# -------------------------------------------------------------------------
@app.get("/api/edr/amsi-etw/status")
def get_amsi_etw_status() -> Dict[str, Any]:
    return {
        "amsi": state["amsi_status"],
        "etw": state["etw_status"],
        "step1_completed": state["step1_completed"],
    }


@app.post("/api/edr/amsi-etw/patch")
def patch_amsi_etw(req: AmsiEtwPatchRequest) -> Dict[str, Any]:
    clean_hex = re.sub(r"[^0-9a-fA-F]", "", req.patch_hex).lower()
    target = req.target.lower()

    if target not in ["amsi", "etw", "both"]:
        raise HTTPException(status_code=400, detail="Invalid target. Must be 'amsi', 'etw', or 'both'")

    # Recognized valid patch bytes:
    # AmsiScanBuffer: b857000780c3 (mov eax, 0x80070057; ret), 31c0c3 (xor eax, eax; ret), c3 (ret)
    # EtwEventWrite: c3 (ret), 31c0c3 (xor eax, eax; ret), 4831c0c3 (xor rax, rax; ret)
    valid_amsi = clean_hex in ["b857000780c3", "31c0c3", "c3", "b800000000c3"]
    valid_etw = clean_hex in ["c3", "31c0c3", "4831c0c3", "b800000000c3"]

    if target in ["amsi", "both"]:
        if valid_amsi or clean_hex.startswith("b8"):
            state["amsi_status"]["patched"] = True
            state["amsi_status"]["patch_bytes"] = req.patch_hex
            state["amsi_status"]["return_code"] = "0x80070057 (E_INVALIDARG - Scan Bypassed)"
            state["amsi_status"]["hooked"] = False
        elif target == "amsi":
            raise HTTPException(
                status_code=400,
                detail="Invalid AMSI patch. Expected 'b8 57 00 07 80 c3' (E_INVALIDARG) or '31 c0 c3' (S_OK; ret).",
            )

    if target in ["etw", "both"]:
        if valid_etw or clean_hex in ["c3", "31c0c3"]:
            state["etw_status"]["patched"] = True
            state["etw_status"]["patch_bytes"] = req.patch_hex
            state["etw_status"]["events_logged"] = 0
            state["etw_status"]["hooked"] = False
        elif target == "both" and state["amsi_status"]["patched"]:
            # If target is 'both' and valid AMSI patch was provided, apply standard ret to ETW as well
            state["etw_status"]["patched"] = True
            state["etw_status"]["patch_bytes"] = "c3"
            state["etw_status"]["events_logged"] = 0
            state["etw_status"]["hooked"] = False
        elif target == "etw":
            raise HTTPException(
                status_code=400,
                detail="Invalid ETW patch. Expected 'c3' (RET) or '31 c0 c3' (XOR EAX, EAX; RET).",
            )

    if not state["amsi_status"]["patched"] and not state["etw_status"]["patched"]:
        raise HTTPException(
            status_code=400,
            detail="Invalid patch bytes. Provide valid AMSI ('b8 57 00 07 80 c3') or ETW ('c3') patch.",
        )

    # Check overall step 1 pass
    if (state["amsi_status"]["patched"] or state["etw_status"]["patched"]) and req.verify_bypass:
        state["step1_completed"] = True
        return {
            "status": "success",
            "message": "Memory patch applied! In-memory scanning and telemetry silenced.",
            "amsi_patched": state["amsi_status"]["patched"],
            "etw_patched": state["etw_status"]["patched"],
            "flag": STEP1_FLAG,
        }

    return {
        "status": "partial",
        "message": f"Patch applied to {target}, but verification was not confirmed.",
        "amsi_patched": state["amsi_status"]["patched"],
        "etw_patched": state["etw_status"]["patched"],
    }


# -------------------------------------------------------------------------
# Step 2: ntdll.dll Disk Unhooking
# -------------------------------------------------------------------------
@app.get("/api/edr/ntdll/hooks")
def get_ntdll_hooks() -> Dict[str, Any]:
    return {
        "hooks": state["ntdll_hooks"],
        "unhook_status": state["unhook_status"],
        "step2_completed": state["step2_completed"],
    }


@app.post("/api/edr/ntdll/unhook")
def unhook_ntdll(req: UnhookRequest) -> Dict[str, Any]:
    method = req.method.lower()
    if method not in ["disk_mapping", "knowndlls"]:
        raise HTTPException(
            status_code=400,
            detail="Supported unhooking methods: 'disk_mapping' (Fresh ntdll from disk) or 'knowndlls'.",
        )

    if req.target_section != ".text":
        raise HTTPException(status_code=400, detail="Target section must be '.text'.")

    if not req.restore_bytes:
        raise HTTPException(status_code=400, detail="restore_bytes must be True to overwrite in-memory hooks.")

    # Execute simulated unhooking: restore original bytes
    for func_name, data in state["ntdll_hooks"].items():
        data["hooked"] = False
        data["hooked_bytes"] = data["original_bytes"]

    state["unhook_status"]["disk_mapped"] = True
    state["unhook_status"]["text_section_overwritten"] = True
    state["unhook_status"]["active_hooks_count"] = 0
    state["step2_completed"] = True

    return {
        "status": "success",
        "method": method,
        "restored_section": ".text",
        "hooks_removed": 4,
        "message": "ntdll.dll .text section successfully restored from clean image! EDR trampolines removed.",
        "flag": STEP2_FLAG,
    }


# -------------------------------------------------------------------------
# Step 3: Dynamic SSN Extraction & Indirect Syscalls
# -------------------------------------------------------------------------
@app.get("/api/edr/syscalls/map")
def get_syscall_map() -> Dict[str, Any]:
    return {
        "syscalls": {
            func: {
                "ssn": f"0x{data['ssn']:04X}",
                "hooked": data["hooked"],
                "gadget_address": "ntdll!syscall+0x12 (0x7FFF50201205)",
            }
            for func, data in state["ntdll_hooks"].items()
        },
        "step3_completed": state["step3_completed"],
    }


@app.post("/api/edr/syscalls/invoke")
def invoke_syscall(req: SyscallInvokeRequest) -> Dict[str, Any]:
    func = req.function_name
    if func not in state["ntdll_hooks"]:
        raise HTTPException(
            status_code=404,
            detail=f"Function {func} not recognized. Available: {list(state['ntdll_hooks'].keys())}",
        )

    ssn_mode = req.ssn_extraction.lower()
    if ssn_mode not in ["hells_gate", "halos_gate", "hardcoded"]:
        raise HTTPException(
            status_code=400,
            detail="ssn_extraction must be 'hells_gate', 'halos_gate', or 'hardcoded'.",
        )

    # In hooked state, Hell's Gate might fail if bytes are clobbered, but Halo's Gate scans neighbors
    is_hooked = state["ntdll_hooks"][func]["hooked"]
    if is_hooked and ssn_mode == "hells_gate":
        raise HTTPException(
            status_code=422,
            detail="Hell's Gate failed: function starts with 'jmp' hook (0xE9). Use Halo's Gate to inspect neighbor stubs!",
        )

    exec_mode = req.execution_mode.lower()
    if exec_mode == "direct_syscall":
        # Direct Syscall will trigger EDR Call Stack anomaly inspection
        return {
            "status": "blocked",
            "detection": "EDR_CALL_STACK_ANOMALY",
            "details": "Direct Syscall detected: RIP is outside ntdll.dll code bounds. Memory allocation quarantined.",
            "stack_trace": [
                "0x00007FF710201040 [payload.exe!DirectSyscallStub+0x10] -> UNVERIFIED",
                "0x00007FFF50100000 [kernel32.dll]",
            ],
        }

    if exec_mode != "indirect_syscall":
        raise HTTPException(status_code=400, detail="execution_mode must be 'indirect_syscall' or 'direct_syscall'")

    # Indirect syscall successfully mimics benign call stack
    ssn_val = state["ntdll_hooks"][func]["ssn"]
    record = {
        "function": func,
        "ssn": f"0x{ssn_val:04X}",
        "ssn_mode": ssn_mode,
        "gadget": "ntdll.dll!syscall; ret",
        "call_stack_status": "CLEAN (RIP inside ntdll.dll bounds)",
        "allocated_bytes": req.allocation_size,
    }
    state["syscall_invocations"].append(record)
    state["step3_completed"] = True

    return {
        "status": "success",
        "message": f"Indirect syscall for {func} executed through ntdll gadget. Call stack clean and EDR bypassed!",
        "ssn": f"0x{ssn_val:04X}",
        "call_stack": "Clean: [ntdll.dll!syscall] -> [payload.exe!main]",
        "flag": STEP3_FLAG,
    }


# -------------------------------------------------------------------------
# Step 4: Sleep Obfuscation (Ekko Timer Queue ROP)
# -------------------------------------------------------------------------
@app.get("/api/edr/c2/beacon-status")
def get_beacon_status() -> Dict[str, Any]:
    return {
        "beacon": state["c2_beacon"],
        "step4_completed": state["step4_completed"],
    }


@app.post("/api/edr/c2/sleep-obfuscate")
def sleep_obfuscate(req: SleepObfuscateRequest) -> Dict[str, Any]:
    tech = req.technique.lower()
    if tech not in ["ekko_rop_timer", "cronos", "standard_sleep"]:
        raise HTTPException(
            status_code=400,
            detail="Technique must be 'ekko_rop_timer', 'cronos', or 'standard_sleep'",
        )

    if tech == "standard_sleep":
        state["c2_beacon"]["state"] = "SLEEPING_PLAINTEXT"
        state["c2_beacon"]["memory_protection"] = "PAGE_EXECUTE_READWRITE"
        state["c2_beacon"]["encrypted"] = False
        state["c2_beacon"]["yara_scan_result"] = "ALERT: Beacon signature detected during memory scan in RX region!"
        return {
            "status": "detected",
            "yara_result": state["c2_beacon"]["yara_scan_result"],
            "recommendation": "Use 'ekko_rop_timer' with memory masking to evade active EDR memory scanners.",
        }

    # Ekko or Cronos timer queue ROP chain
    valid_protections = ["PAGE_READWRITE", "PAGE_NOACCESS"]
    if req.mask_protection not in valid_protections:
        raise HTTPException(
            status_code=400,
            detail=f"mask_protection during sleep must be one of {valid_protections}",
        )

    state["c2_beacon"]["state"] = "DORMANT_ENCRYPTED"
    state["c2_beacon"]["memory_protection"] = req.mask_protection
    state["c2_beacon"]["encrypted"] = True
    state["c2_beacon"]["sleep_mask_technique"] = tech.upper()
    state["c2_beacon"]["timer_queue_configured"] = True
    state["c2_beacon"]["yara_scan_result"] = "CLEAN: 0 signatures matched. Encrypted RW memory page ignored."
    state["step4_completed"] = True

    return {
        "status": "success",
        "technique": req.technique,
        "sleep_duration": req.sleep_seconds,
        "mask_protection": req.mask_protection,
        "encryption_applied": req.encryption_algo,
        "memory_scanner_verdict": state["c2_beacon"]["yara_scan_result"],
        "message": "Timer Queue ROP chain registered. Beacon encrypted in memory during sleep. EDR scanner defeated!",
        "flag": STEP4_FLAG,
    }


# -------------------------------------------------------------------------
# Front-end Interactive Web Console
# -------------------------------------------------------------------------
@app.get("/", response_class=HTMLResponse)
def index() -> str:
    return r"""<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Lab 38: EDRShield — EDR Evasion & Next-Gen C2 Lab</title>
    <style>
        :root {
            --bg: #090d16;
            --surface: #111827;
            --surface-hover: #1f2937;
            --primary: #ef4444;
            --primary-glow: rgba(239, 68, 68, 0.25);
            --cyan: #06b6d4;
            --green: #10b981;
            --yellow: #f59e0b;
            --text: #f3f4f6;
            --text-dim: #9ca3af;
            --border: #374151;
            --font-mono: 'JetBrains Mono', 'Fira Code', Consolas, monospace;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            background-color: var(--bg);
            color: var(--text);
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            padding: 24px;
            line-height: 1.5;
        }
        header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 2px solid var(--border);
            padding-bottom: 16px;
            margin-bottom: 24px;
        }
        .title-group h1 {
            font-size: 1.6rem;
            color: #fff;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .badge {
            background: #ef444422;
            color: #ef4444;
            border: 1px solid #ef444488;
            font-size: 0.8rem;
            padding: 4px 10px;
            border-radius: 9999px;
            font-weight: 600;
        }
        .port-badge {
            background: #06b6d422;
            color: var(--cyan);
            border: 1px solid #06b6d488;
            font-family: var(--font-mono);
            padding: 4px 10px;
            border-radius: 6px;
            font-size: 0.85rem;
        }
        .btn-reset {
            background: #374151;
            color: #fff;
            border: 1px solid var(--border);
            padding: 8px 16px;
            border-radius: 6px;
            cursor: pointer;
            transition: all 0.2s;
        }
        .btn-reset:hover { background: #4b5563; }
        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(540px, 1fr));
            gap: 20px;
        }
        .card {
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 20px;
            display: flex;
            flex-direction: column;
            gap: 16px;
        }
        .card h2 {
            font-size: 1.15rem;
            color: var(--cyan);
            display: flex;
            align-items: center;
            gap: 8px;
            border-bottom: 1px solid var(--border);
            padding-bottom: 8px;
        }
        .terminal {
            background: #030712;
            border: 1px solid #1f2937;
            border-radius: 6px;
            padding: 12px;
            font-family: var(--font-mono);
            font-size: 0.85rem;
            color: #10b981;
            min-height: 120px;
            max-height: 220px;
            overflow-y: auto;
            white-space: pre-wrap;
            word-break: break-all;
        }
        .form-row {
            display: flex;
            gap: 10px;
            align-items: center;
        }
        input, select {
            background: #1f2937;
            border: 1px solid var(--border);
            color: #fff;
            padding: 8px 12px;
            border-radius: 6px;
            font-family: var(--font-mono);
            font-size: 0.85rem;
            flex: 1;
        }
        .btn-action {
            background: #ef4444;
            color: #fff;
            border: none;
            padding: 8px 16px;
            border-radius: 6px;
            font-weight: 600;
            cursor: pointer;
            transition: opacity 0.2s;
        }
        .btn-action:hover { opacity: 0.9; }
        .flag-box {
            background: #10b98115;
            border: 1px solid #10b98188;
            color: #10b981;
            padding: 10px 14px;
            border-radius: 6px;
            font-family: var(--font-mono);
            font-size: 0.88rem;
            display: none;
        }
    </style>
</head>
<body>
    <header>
        <div class="title-group">
            <h1>🛡️ Lab 38: EDRShield <span class="badge">EDR Evasion & C2</span></h1>
        </div>
        <div style="display:flex; gap:12px; align-items:center;">
            <span class="port-badge">PORT: 8038</span>
            <button class="btn-reset" onclick="resetLab()">🔄 Reset Lab</button>
        </div>
    </header>

    <div class="grid">
        <!-- Stage 1 -->
        <div class="card">
            <h2>1️⃣ AMSI & ETW In-Memory Patching</h2>
            <p style="color:var(--text-dim); font-size:0.9rem;">
                PowerShell / .NET 메모리 스캔 엔진과 ETW 보안 이벤트 로깅을 인라인 패치(AmsiScanBuffer E_INVALIDARG / EtwEventWrite RET)로 무력화합니다.
            </p>
            <div class="form-row">
                <select id="stage1-target">
                    <option value="both">Both (AMSI + ETW)</option>
                    <option value="amsi">AMSI Only</option>
                    <option value="etw">ETW Only</option>
                </select>
                <input id="stage1-hex" type="text" value="b8 57 00 07 80 c3" placeholder="Patch Hex, e.g. b8 57 00 07 80 c3">
                <button class="btn-action" onclick="runStage1()">Apply Patch</button>
            </div>
            <div class="terminal" id="term-stage1">[*] Ready. Click 'Apply Patch' to overwrite scanning stubs.</div>
            <div class="flag-box" id="flag-stage1"></div>
        </div>

        <!-- Stage 2 -->
        <div class="card">
            <h2>2️⃣ ntdll.dll Disk Unhooking</h2>
            <p style="color:var(--text-dim); font-size:0.9rem;">
                메모리 상에 EDR 인라인 훅(5-byte JMP)이 설치된 ntdll .text 섹션을 디스크 원본 이미지에서 읽어와 클린 바이트로 복원합니다.
            </p>
            <div class="form-row">
                <select id="stage2-method">
                    <option value="disk_mapping">Fresh ntdll from Disk (CreateFileMapping)</option>
                    <option value="knowndlls">\KnownDlls\ntdll.dll Section Object</option>
                </select>
                <button class="btn-action" onclick="runStage2()">Restore .text</button>
            </div>
            <div class="terminal" id="term-stage2">[*] EDR Hooks present: NtAllocate, NtProtect, NtWrite, NtCreateThread (0xE9 JMP)</div>
            <div class="flag-box" id="flag-stage2"></div>
        </div>

        <!-- Stage 3 -->
        <div class="card">
            <h2>3️⃣ Dynamic SSN & Indirect Syscalls</h2>
            <p style="color:var(--text-dim); font-size:0.9rem;">
                Hell's / Halo's Gate로 동적 SSN을 추출하고, ntdll 내부의 'syscall; ret' 가젯으로 간접 점프하여 정상 호출 스택을 유지합니다.
            </p>
            <div class="form-row">
                <select id="stage3-func">
                    <option value="NtAllocateVirtualMemory">NtAllocateVirtualMemory</option>
                    <option value="NtProtectVirtualMemory">NtProtectVirtualMemory</option>
                    <option value="NtWriteVirtualMemory">NtWriteVirtualMemory</option>
                </select>
                <select id="stage3-ssn">
                    <option value="halos_gate">Halo's Gate (Neighbor Scan)</option>
                    <option value="hells_gate">Hell's Gate</option>
                </select>
                <select id="stage3-mode">
                    <option value="indirect_syscall">Indirect Syscall (Clean RIP)</option>
                    <option value="direct_syscall">Direct Syscall (Anomaly RIP)</option>
                </select>
                <button class="btn-action" onclick="runStage3()">Invoke Syscall</button>
            </div>
            <div class="terminal" id="term-stage3">[*] Select function and dispatch method.</div>
            <div class="flag-box" id="flag-stage3"></div>
        </div>

        <!-- Stage 4 -->
        <div class="card">
            <h2>4️⃣ Sleep Obfuscation (Ekko Timer Queue ROP)</h2>
            <p style="color:var(--text-dim); font-size:0.9rem;">
                C2 비컨이 대기(Sleep)하는 동안 타이머 큐 ROP 체인으로 메모리를 암호화(RW/NOACCESS)하여 EDR YARA 메모리 스캐너를 무력화합니다.
            </p>
            <div class="form-row">
                <select id="stage4-tech">
                    <option value="ekko_rop_timer">Ekko ROP Timer Queue</option>
                    <option value="cronos">Cronos Event Masking</option>
                    <option value="standard_sleep">Standard Sleep (Plaintext RX)</option>
                </select>
                <select id="stage4-prot">
                    <option value="PAGE_READWRITE">Mask Protection: PAGE_READWRITE</option>
                    <option value="PAGE_NOACCESS">Mask Protection: PAGE_NOACCESS</option>
                </select>
                <button class="btn-action" onclick="runStage4()">Arm Sleep Mask</button>
            </div>
            <div class="terminal" id="term-stage4">[*] Beacon state: ACTIVE (PAGE_EXECUTE_READWRITE, Unmasked).</div>
            <div class="flag-box" id="flag-stage4"></div>
        </div>
    </div>

    <script>
        async function runStage1() {
            const target = document.getElementById("stage1-target").value;
            const hex = document.getElementById("stage1-hex").value;
            const res = await fetch("/api/edr/amsi-etw/patch", {
                method: "POST",
                headers: {"Content-Type": "application/json"},
                body: JSON.stringify({target: target, patch_hex: hex, verify_bypass: true})
            });
            const data = await res.json();
            const term = document.getElementById("term-stage1");
            term.textContent = JSON.stringify(data, null, 2);
            if (data.flag) {
                const box = document.getElementById("flag-stage1");
                box.textContent = "🚩 Flag: " + data.flag;
                box.style.display = "block";
            }
        }

        async function runStage2() {
            const method = document.getElementById("stage2-method").value;
            const res = await fetch("/api/edr/ntdll/unhook", {
                method: "POST",
                headers: {"Content-Type": "application/json"},
                body: JSON.stringify({method: method, target_section: ".text", restore_bytes: true})
            });
            const data = await res.json();
            const term = document.getElementById("term-stage2");
            term.textContent = JSON.stringify(data, null, 2);
            if (data.flag) {
                const box = document.getElementById("flag-stage2");
                box.textContent = "🚩 Flag: " + data.flag;
                box.style.display = "block";
            }
        }

        async function runStage3() {
            const func = document.getElementById("stage3-func").value;
            const ssn = document.getElementById("stage3-ssn").value;
            const mode = document.getElementById("stage3-mode").value;
            const res = await fetch("/api/edr/syscalls/invoke", {
                method: "POST",
                headers: {"Content-Type": "application/json"},
                body: JSON.stringify({function_name: func, ssn_extraction: ssn, execution_mode: mode})
            });
            const data = await res.json();
            const term = document.getElementById("term-stage3");
            term.textContent = JSON.stringify(data, null, 2);
            if (data.flag) {
                const box = document.getElementById("flag-stage3");
                box.textContent = "🚩 Flag: " + data.flag;
                box.style.display = "block";
            }
        }

        async function runStage4() {
            const tech = document.getElementById("stage4-tech").value;
            const prot = document.getElementById("stage4-prot").value;
            const res = await fetch("/api/edr/c2/sleep-obfuscate", {
                method: "POST",
                headers: {"Content-Type": "application/json"},
                body: JSON.stringify({technique: tech, sleep_seconds: 5, mask_protection: prot, encryption_algo: "SystemFunction032_XOR"})
            });
            const data = await res.json();
            const term = document.getElementById("term-stage4");
            term.textContent = JSON.stringify(data, null, 2);
            if (data.flag) {
                const box = document.getElementById("flag-stage4");
                box.textContent = "🚩 Flag: " + data.flag;
                box.style.display = "block";
            }
        }

        async function resetLab() {
            await fetch("/api/reset", {method: "POST"});
            location.reload();
        }
    </script>
</body>
</html>
"""


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8038, reload=True)
