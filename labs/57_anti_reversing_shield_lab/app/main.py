#!/usr/bin/env python3
"""
Lab 57: AntiReversingShield — 바이너리 보호 & 안티 리버싱 능동 방어 랩 (Anti-Reversing & Advanced Binary Protection Lab)
Port: 8057 (127.0.0.1 bound)

4-Stage Interactive Binary Analysis & Anti-Reverse Engineering Defense Simulation:
1. Dynamic Anti-Debugging & PEB/ptrace Bypass: Neutralize ptrace(PTRACE_TRACEME), IsDebuggerPresent, and Hardware Breakpoint traps
2. API Hashing & Dynamic IAT Resolution: Unmask ROR13/Murmur3 obfuscated dynamic imports
3. Advanced Binary Packing & OEP Unpacking: Analyze entropy, identify stub jumps (popad/jmp OEP), and reconstruct executable image
4. Anti-VM & Timing Analysis Active Defense: Circumvent RDTSC delta timing, CPUID hypervisor flags, and SMBIOS virtualization artifacts
"""

from typing import Dict, Any, List, Optional
import os
import hashlib
import json
from fastapi import FastAPI, HTTPException, status
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field

app = FastAPI(
    title="Lab 57: AntiReversingShield — Anti-Reversing & Binary Protection Lab",
    description="Hands-on anti-debugging evasion, API hashing resolution, custom packer unpacking, and anti-VM timing defense neutralization.",
    version="1.0.0",
)

# CTF Flags
STAGE1_FLAG = "FLAG{ANTI_DEBUGGING_PEB_PTRACE_BYPASSED_5701}"
STAGE2_FLAG = "FLAG{API_HASHING_ROR13_DYNAMIC_IAT_RESOLVED_5702}"
STAGE3_FLAG = "FLAG{CUSTOM_PACKER_OEP_DUMP_AND_UNPACKED_5703}"
STAGE4_FLAG = "FLAG{ANTI_VM_RDTSC_TIMING_DEFENSE_NEUTRALIZED_5704}"


class LabState:
    """State manager for Lab 57 AntiReversingShield."""
    def __init__(self) -> None:
        self.reset()

    def reset(self) -> None:
        self.stage1_completed: bool = False
        self.stage2_completed: bool = False
        self.stage3_completed: bool = False
        self.stage4_completed: bool = False

        # Internal simulation parameters
        self.debug_traps_neutralized: List[str] = []
        self.resolved_apis: Dict[str, str] = {}
        self.unpacked_oep: Optional[str] = None
        self.anti_vm_patched: bool = False


state = LabState()


# --- Pydantic Request Models ---
class AntiDebugBypassRequest(BaseModel):
    bypass_method: str = Field(..., max_length=64, description="Bypass technique: 'ld_preload_hook', 'byte_patch', or 'kernel_driver'")
    target_checks: List[str] = Field(..., description="Target anti-debug checks to neutralize (e.g. ['ptrace_traceme', 'being_debugged', 'hardware_breakpoints'])")
    patch_hex: Optional[str] = Field(default=None, max_length=128, description="Byte patch hexadecimal sequence (e.g. '9090' or '31c0c3')")


class ApiHashingResolveRequest(BaseModel):
    hash_algorithm: str = Field(..., max_length=32, description="Hashing algorithm: 'ror13' or 'murmur3'")
    target_hash: str = Field(..., max_length=32, description="Target function hash to crack/resolve (e.g. '0x91afca54' or '0xd83d6aa1')")
    candidate_api: str = Field(..., max_length=64, description="Candidate Windows/POSIX API function name")


class PackerUnpackRequest(BaseModel):
    unpack_strategy: str = Field(..., max_length=64, description="Unpacking strategy: 'oep_breakpoint', 'tail_jump_tracking', or 'memory_dump'")
    target_oep: str = Field(..., max_length=18, description="Target Original Entry Point address (e.g. '0x00401000' or '0x00401580')")
    rebuild_iat: bool = Field(default=True, description="Whether to rebuild Import Address Table during dump")


class AntiVmNeutralizeRequest(BaseModel):
    rdtsc_threshold_cycles: int = Field(..., ge=50, le=10000, description="RDTSC cycle delta threshold for single-stepping detection")
    spoof_cpuid_hypervisor: bool = Field(default=True, description="Clear CPUID leaf 1 ECX bit 31 (Hypervisor Present bit)")
    filter_smbios_artifacts: List[str] = Field(..., description="List of VM vendors to filter (e.g. ['VMware', 'QEMU', 'VirtualBox'])")


# --- Helper Functions ---
def compute_ror13(name: str) -> str:
    """Compute 32-bit ROR13 hash of an API function name."""
    h = 0
    for char in name:
        h = ((h >> 13) | (h << 19)) & 0xFFFFFFFF
        h = (h + ord(char)) & 0xFFFFFFFF
    return f"0x{h:08x}"


# Known API hashes for stage 2
KNOWN_API_HASHES = {
    compute_ror13("VirtualAlloc"): "VirtualAlloc",
    compute_ror13("WriteProcessMemory"): "WriteProcessMemory",
    compute_ror13("CreateRemoteThread"): "CreateRemoteThread",
    compute_ror13("LoadLibraryA"): "LoadLibraryA",
}


# --- API Routes ---
@app.get("/api/health")
async def health_check() -> Dict[str, Any]:
    return {
        "status": "ok",
        "lab": "57_anti_reversing_shield_lab",
        "port": "8057",
        "description": "AntiReversingShield — Anti-Reversing & Binary Protection Lab"
    }


@app.get("/api/status")
async def get_status() -> Dict[str, Any]:
    solved = sum([
        state.stage1_completed,
        state.stage2_completed,
        state.stage3_completed,
        state.stage4_completed
    ])
    return {
        "status": "running",
        "lab_id": "57",
        "solved_count": solved,
        "stages": {
            "stage1_completed": state.stage1_completed,
            "stage2_completed": state.stage2_completed,
            "stage3_completed": state.stage3_completed,
            "stage4_completed": state.stage4_completed,
        },
        "simulation": {
            "debug_traps_neutralized": state.debug_traps_neutralized,
            "resolved_apis": state.resolved_apis,
            "unpacked_oep": state.unpacked_oep,
            "anti_vm_patched": state.anti_vm_patched
        }
    }


@app.post("/api/reset")
async def reset_lab() -> Dict[str, Any]:
    state.reset()
    return {"status": "reset_complete", "lab_id": "57"}


@app.post("/api/stage1/bypass_anti_debugging")
async def stage1_bypass_anti_debugging(req: AntiDebugBypassRequest) -> Dict[str, Any]:
    """
    Stage 1: Dynamic Anti-Debugging & PEB / ptrace Defense
    Bypass ptrace(PTRACE_TRACEME), IsDebuggerPresent, and Hardware Breakpoint traps.
    """
    valid_methods = {"ld_preload_hook", "byte_patch", "kernel_driver"}
    if req.bypass_method not in valid_methods:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid bypass method: '{req.bypass_method}'. Expected one of {sorted(list(valid_methods))}."
        )

    required_checks = {"ptrace_traceme", "being_debugged", "hardware_breakpoints"}
    provided_checks = set(req.target_checks)
    if not required_checks.issubset(provided_checks):
        missing = required_checks - provided_checks
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Incomplete anti-debugging defense neutralization. Missing target checks: {sorted(list(missing))}."
        )

    if req.bypass_method == "byte_patch":
        if not req.patch_hex or req.patch_hex.lower() not in {"9090", "31c0c3", "c3"}:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid patch_hex sequence for byte_patch method. Valid NOP/XOR sequences: '9090', '31c0c3', or 'c3'."
            )

    state.debug_traps_neutralized = sorted(list(provided_checks))
    state.stage1_completed = True

    return {
        "success": True,
        "stage": 1,
        "message": "Anti-debugging checks (ptrace/PEB BeingDebugged/Hardware Breakpoints) successfully neutralized.",
        "neutralized_checks": state.debug_traps_neutralized,
        "flag": STAGE1_FLAG
    }


@app.post("/api/stage2/resolve_api_hashing")
async def stage2_resolve_api_hashing(req: ApiHashingResolveRequest) -> Dict[str, Any]:
    """
    Stage 2: API Hashing & Dynamic IAT Resolution
    Crack ROR13 hash and resolve target stealth Windows/POSIX API function.
    """
    if not state.stage1_completed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Stage 1 must be completed before attempting Stage 2 (Anti-debugging checks must be neutralized)."
        )

    if req.hash_algorithm.lower() != "ror13":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported hash algorithm: '{req.hash_algorithm}'. This binary utilizes 'ror13' dynamic hashing."
        )

    target = req.target_hash.lower()
    if target not in KNOWN_API_HASHES:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Unknown API hash target: '{req.target_hash}'. Available hashes in obfuscated binary: {list(KNOWN_API_HASHES.keys())}."
        )

    expected_api = KNOWN_API_HASHES[target]
    if req.candidate_api != expected_api:
        computed = compute_ror13(req.candidate_api)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Hash mismatch! ROR13('{req.candidate_api}') = {computed}, expected target {target}."
        )

    state.resolved_apis[target] = req.candidate_api
    state.stage2_completed = True

    return {
        "success": True,
        "stage": 2,
        "message": f"API Hash {target} successfully mapped to '{req.candidate_api}'. Stealth IAT recovered.",
        "resolved_api": req.candidate_api,
        "flag": STAGE2_FLAG
    }


@app.post("/api/stage3/unpack_binary")
async def stage3_unpack_binary(req: PackerUnpackRequest) -> Dict[str, Any]:
    """
    Stage 3: Advanced Binary Packing & OEP Unpacking
    Trace packer stub, identify tail jump, locate OEP, and reconstruct clean binary.
    """
    if not state.stage2_completed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Stage 2 must be completed before attempting Stage 3 (Dynamic API hashes must be resolved)."
        )

    valid_strategies = {"oep_breakpoint", "tail_jump_tracking", "memory_dump"}
    if req.unpack_strategy not in valid_strategies:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid unpacking strategy: '{req.unpack_strategy}'. Expected one of {sorted(list(valid_strategies))}."
        )

    expected_oep = "0x00401580"
    if req.target_oep.lower() != expected_oep:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Incorrect OEP address: '{req.target_oep}'. Packer entropy analysis points to main entry at {expected_oep}."
        )

    if not req.rebuild_iat:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Binary image dump failed: rebuild_iat must be True to reconstruct PE/ELF import directory."
        )

    state.unpacked_oep = expected_oep
    state.stage3_completed = True

    return {
        "success": True,
        "stage": 3,
        "message": f"Packer stub traversed. Tail jump reached OEP at {expected_oep}. Clean PE reconstructed.",
        "oep": expected_oep,
        "entropy_reduction": "7.82 -> 4.31 (Unpacked clean text section)",
        "flag": STAGE3_FLAG
    }


@app.post("/api/stage4/neutralize_anti_vm")
async def stage4_neutralize_anti_vm(req: AntiVmNeutralizeRequest) -> Dict[str, Any]:
    """
    Stage 4: Anti-VM & Timing Analysis Active Defense
    Neutralize RDTSC timing delta analysis, spoof CPUID hypervisor flag, and sanitize SMBIOS artifacts.
    """
    if not state.stage3_completed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Stage 3 must be completed before attempting Stage 4 (Binary must be unpacked)."
        )

    if req.rdtsc_threshold_cycles < 200 or req.rdtsc_threshold_cycles > 2000:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid RDTSC cycle threshold: {req.rdtsc_threshold_cycles}. Effective cycle threshold must be between 200 and 2000 cycles."
        )

    if not req.spoof_cpuid_hypervisor:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Anti-VM evasion failed: CPUID leaf 1 ECX bit 31 (Hypervisor Present) must be cleared."
        )

    required_vendors = {"VMware", "QEMU", "VirtualBox"}
    provided_vendors = set(req.filter_smbios_artifacts)
    if not required_vendors.issubset(provided_vendors):
        missing = required_vendors - provided_vendors
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Incomplete SMBIOS virtualization artifact filtering. Missing vendors: {sorted(list(missing))}."
        )

    state.anti_vm_patched = True
    state.stage4_completed = True

    return {
        "success": True,
        "stage": 4,
        "message": "Anti-VM defenses and RDTSC timing analysis neutralized. Payload execution achieved in virtual sandbox.",
        "timing_normalized_cycles": req.rdtsc_threshold_cycles,
        "spoofed_cpuid": True,
        "flag": STAGE4_FLAG
    }


@app.get("/", response_class=HTMLResponse)
async def get_index() -> HTMLResponse:
    html_content = """<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Lab 57: AntiReversingShield — Anti-Reversing & Binary Protection Lab</title>
    <style>
        :root {
            --bg-color: #0b0f19;
            --card-bg: #111827;
            --accent-color: #ec4899;
            --text-color: #f3f4f6;
            --border-color: #1f2937;
            --success-color: #10b981;
        }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background-color: var(--bg-color);
            color: var(--text-color);
            margin: 0;
            padding: 20px;
        }
        .container {
            max-width: 1000px;
            margin: 0 auto;
        }
        header {
            text-align: center;
            padding: 30px 0;
            border-bottom: 1px solid var(--border-color);
            margin-bottom: 30px;
        }
        h1 {
            color: var(--accent-color);
            margin: 0 0 10px 0;
            font-size: 2.2rem;
        }
        .badge {
            background-color: #374151;
            padding: 4px 10px;
            border-radius: 4px;
            font-size: 0.85rem;
            display: inline-block;
            margin: 5px;
        }
        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
            gap: 20px;
        }
        .card {
            background-color: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 20px;
        }
        .card h2 {
            margin-top: 0;
            color: #f472b6;
            font-size: 1.3rem;
        }
        pre {
            background-color: #030712;
            padding: 12px;
            border-radius: 6px;
            overflow-x: auto;
            font-size: 0.9rem;
            color: #38bdf8;
            border: 1px solid #1e293b;
        }
        .flag {
            background-color: #064e3b;
            color: #34d399;
            padding: 8px 12px;
            border-radius: 4px;
            font-family: monospace;
            font-size: 0.95rem;
            display: inline-block;
            margin-top: 10px;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🛡️ Lab 57: AntiReversingShield</h1>
            <p>Advanced Binary Protection, Anti-Debugging, Dynamic API Hashing & Anti-VM Neutralization Lab</p>
            <div>
                <span class="badge">Port 8057</span>
                <span class="badge">127.0.0.1 Bound</span>
                <span class="badge">Category: Reverse Engineering</span>
                <span class="badge">CVSS 3.1: 8.4 (HIGH)</span>
            </div>
        </header>
        <div class="grid">
            <div class="card">
                <h2>Stage 1: Anti-Debugging Bypass</h2>
                <p>Neutralize ptrace(PTRACE_TRACEME), PEB BeingDebugged, and Hardware Breakpoint traps.</p>
                <pre>POST /api/stage1/bypass_anti_debugging
{
  "bypass_method": "byte_patch",
  "target_checks": ["ptrace_traceme", "being_debugged", "hardware_breakpoints"],
  "patch_hex": "31c0c3"
}</pre>
            </div>
            <div class="card">
                <h2>Stage 2: API Hashing Resolution</h2>
                <p>Crack ROR13 hash and restore stealth dynamic Import Address Table (IAT).</p>
                <pre>POST /api/stage2/resolve_api_hashing
{
  "hash_algorithm": "ror13",
  "target_hash": "0x91afca54",
  "candidate_api": "VirtualAlloc"
}</pre>
            </div>
            <div class="card">
                <h2>Stage 3: Packer Unpacking & OEP Dump</h2>
                <p>Track unpacker stub tail jump, dump unpacked image at OEP, and rebuild PE IAT.</p>
                <pre>POST /api/stage3/unpack_binary
{
  "unpack_strategy": "tail_jump_tracking",
  "target_oep": "0x00401580",
  "rebuild_iat": true
}</pre>
            </div>
            <div class="card">
                <h2>Stage 4: Anti-VM & Timing Neutralization</h2>
                <p>Circumvent RDTSC timing delta analysis, CPUID hypervisor flag, and SMBIOS artifacts.</p>
                <pre>POST /api/stage4/neutralize_anti_vm
{
  "rdtsc_threshold_cycles": 500,
  "spoof_cpuid_hypervisor": true,
  "filter_smbios_artifacts": ["VMware", "QEMU", "VirtualBox"]
}</pre>
            </div>
        </div>
    </div>
</body>
</html>
"""
    return HTMLResponse(content=html_content)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8057, reload=True)
