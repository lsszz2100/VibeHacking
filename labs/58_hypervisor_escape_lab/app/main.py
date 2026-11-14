#!/usr/bin/env python3
"""
Lab 58: MicrovmHypervisorEscapeLab — 하이퍼바이저 탈출 & MicroVM 격리 방어 실습
Port: 8058 (127.0.0.1 bound)

4-Stage Interactive MicroVM & Hypervisor Escape Defense Simulation:
1. VM-Exit Interception & MMIO Emulation Flaw: Inducing EPT violation & exploiting HPET/APIC MMIO handler
2. Virtio-Net Shared Memory Ring Buffer (vring) Corruption: Out-of-Bounds heap manipulation
3. KVM vCPU Register State Smuggling & Host Address Leak: MSR_LSTAR / CR3 host base extraction
4. Seccomp BPF & Landlock LSM MicroVM Confinement: Strict hypervisor hardening & capability dropping
"""

from typing import Dict, Any, List, Optional
import os
import hashlib
import json
from fastapi import FastAPI, HTTPException, status
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field

app = FastAPI(
    title="Lab 58: MicrovmHypervisorEscapeLab — MicroVM & Hypervisor Escape Defense Lab",
    description="Hands-on virtualization escape evasion, MMIO emulation flaw, virtio-net shared memory corruption, and MicroVM confinement hardening.",
    version="1.0.0",
)

# CTF Flags
STAGE1_FLAG = "FLAG{VM_EXIT_MMIO_EMULATION_INTERCEPTED_5801}"
STAGE2_FLAG = "FLAG{VIRTIO_VRING_SHARED_MEMORY_CORRUPTED_5802}"
STAGE3_FLAG = "FLAG{KVM_VCPU_REGISTER_STATE_HOST_LEAKED_5803}"
STAGE4_FLAG = "FLAG{MICROVM_HYPERVISOR_CONFINEMENT_ENFORCED_5804}"


class LabState:
    """State manager for Lab 58 HypervisorEscapeLab."""
    def __init__(self) -> None:
        self.reset()

    def reset(self) -> None:
        self.stage1_completed: bool = False
        self.stage2_completed: bool = False
        self.stage3_completed: bool = False
        self.stage4_completed: bool = False

        # Internal simulation parameters
        self.intercepted_exits: List[str] = []
        self.corrupted_vrings: List[int] = []
        self.leaked_host_base: Optional[str] = None
        self.hardening_enforced: bool = False


state = LabState()


# --- Pydantic Request Models with Strict Bounds ---
class VmExitInterceptRequest(BaseModel):
    exit_reason: str = Field(..., max_length=64, description="VM-Exit reason: 'EXIT_REASON_EPT_VIOLATION', 'EXIT_REASON_CR_ACCESS', or 'EXIT_REASON_IO_INSTRUCTION'")
    mmio_address: str = Field(..., max_length=18, description="Target MMIO physical address (e.g. '0xFED00000' or '0xFEE00000')")
    emulation_handler: str = Field(..., max_length=64, description="Vulnerable emulated device handler (e.g. 'hpet_mmio_read' or 'apic_mmio_write')")


class VirtioVringOverflowRequest(BaseModel):
    vring_idx: int = Field(..., ge=0, le=128, description="Virtqueue index (e.g. 0 to 7)")
    descriptor_len: int = Field(..., ge=64, le=65536, description="Descriptor buffer length in bytes")
    corrupt_next_offset: str = Field(..., max_length=18, description="Hex offset to corrupt next descriptor (e.g. '0x1000')")
    payload_type: str = Field(default="scatter_gather_oob", max_length=64, description="Payload delivery mechanism: 'scatter_gather_oob' or 'desc_chain_loop'")


class KvmVcpuSmuggleRequest(BaseModel):
    vcpu_id: int = Field(..., ge=0, le=64, description="vCPU identifier")
    smuggle_register: str = Field(..., max_length=64, description="Target privileged register: 'CR3_AND_MSR_LSTAR' or 'MSR_STAR'")
    target_msr: str = Field(..., max_length=18, description="MSR index hex: '0xC0000082' (IA32_LSTAR)")
    leak_host_kernel_base: bool = Field(default=True, description="Attempt host kernel base address calculation")


class HypervisorHardeningRequest(BaseModel):
    seccomp_bpf_policy: str = Field(..., max_length=64, description="Seccomp policy: 'strict_kvm_ioctl_whitelist'")
    landlock_fs_confinement: bool = Field(default=True, description="Enforce unprivileged Landlock LSM filesystem restriction")
    drop_caps: List[str] = Field(..., description="Capabilities to drop (e.g. ['CAP_SYS_ADMIN', 'CAP_SYS_PTRACE'])")
    enforce_memory_tagging: bool = Field(default=True, description="Enable ARM MTE / Intel LAM hardware memory protection")


# --- API Endpoints ---
@app.get("/api/health")
async def health_check() -> Dict[str, Any]:
    return {
        "status": "ok",
        "lab": "58_hypervisor_escape_lab",
        "port": "8058",
        "description": "MicrovmHypervisorEscapeLab — MicroVM & Hypervisor Escape Defense Lab"
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
        "lab_id": "58",
        "title": "Lab 58: MicrovmHypervisorEscapeLab — MicroVM & Hypervisor Escape Defense Lab",
        "solved_count": solved,
        "total_stages": 4,
        "stage1_completed": state.stage1_completed,
        "stage2_completed": state.stage2_completed,
        "stage3_completed": state.stage3_completed,
        "stage4_completed": state.stage4_completed,
        "hardening_enforced": state.hardening_enforced,
    }


@app.post("/api/reset")
async def reset_state() -> Dict[str, Any]:
    state.reset()
    return {"status": "reset", "message": "Hypervisor simulation state reset successfully"}


@app.post("/api/stage1/intercept_vm_exit")
async def stage1_intercept_vm_exit(req: VmExitInterceptRequest) -> Dict[str, Any]:
    """Stage 1: VM-Exit Interception & MMIO Emulation Vulnerability."""
    valid_exits = ["EXIT_REASON_EPT_VIOLATION", "EXIT_REASON_IO_INSTRUCTION", "EXIT_REASON_CR_ACCESS"]
    if req.exit_reason not in valid_exits:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid VM-Exit reason: '{req.exit_reason}'. Valid options: {valid_exits}"
        )

    # MMIO address validation (e.g. HPET 0xFED00000 or APIC 0xFEE00000)
    addr = req.mmio_address.strip().upper()
    if addr not in ["0XFED00000", "0XFEE00000", "0XFED00010"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Target MMIO address '{req.mmio_address}' is not mapped to an emulated MMIO peripheral."
        )

    if req.emulation_handler not in ["hpet_mmio_read", "apic_mmio_write", "e1000_mmio_handler"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unknown emulated handler: '{req.emulation_handler}'. Target HPET or APIC handlers."
        )

    state.stage1_completed = True
    state.intercepted_exits.append(req.exit_reason)

    return {
        "status": "success",
        "stage": 1,
        "message": f"⚡ VM-Exit intercepted successfully via {req.exit_reason} at {addr} ({req.emulation_handler}). Hypervisor host context trapped.",
        "intercepted_exit": req.exit_reason,
        "emulation_handler": req.emulation_handler,
        "flag": STAGE1_FLAG,
    }


@app.post("/api/stage2/virtio_vring_overflow")
async def stage2_virtio_vring_overflow(req: VirtioVringOverflowRequest) -> Dict[str, Any]:
    """Stage 2: Virtio-Net Shared Memory Ring Buffer (vring) Corruption."""
    if not state.stage1_completed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Stage 1 must be completed before triggering virtio shared memory corruption."
        )

    if req.descriptor_len < 2048:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Descriptor length {req.descriptor_len} is too small to overflow the vring chunk boundary (minimum: 2048 bytes)."
        )

    offset_str = req.corrupt_next_offset.strip().lower()
    if not offset_str.startswith("0x"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Corrupt offset must be a valid hex address/offset (e.g. '0x1000')."
        )

    state.stage2_completed = True
    state.corrupted_vrings.append(req.vring_idx)

    return {
        "status": "success",
        "stage": 2,
        "message": f"💥 Virtio-Net vring[{req.vring_idx}] corrupted! Shared descriptor chain exceeded host boundary at offset {req.corrupt_next_offset}.",
        "vring_idx": req.vring_idx,
        "descriptor_len": req.descriptor_len,
        "overflow_type": req.payload_type,
        "flag": STAGE2_FLAG,
    }


@app.post("/api/stage3/kvm_vcpu_smuggling")
async def stage3_kvm_vcpu_smuggling(req: KvmVcpuSmuggleRequest) -> Dict[str, Any]:
    """Stage 3: KVM vCPU Register State Smuggling & Host Kernel Base Leak."""
    if not state.stage2_completed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Stage 2 must be completed before extracting host register telemetry."
        )

    if "MSR_LSTAR" not in req.smuggle_register:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Register state '{req.smuggle_register}' does not contain kernel syscall entrypoint. Must include MSR_LSTAR."
        )

    msr_idx = req.target_msr.strip().upper()
    if msr_idx not in ["0XC0000082", "0XC0000080"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid MSR target index: '{req.target_msr}'. IA32_LSTAR is 0xC0000082."
        )

    # Simulated host kernel base calculation
    simulated_host_base = "0xffffffff81000000"
    state.stage3_completed = True
    state.leaked_host_base = simulated_host_base

    return {
        "status": "success",
        "stage": 3,
        "message": f"🔓 KVM vCPU[{req.vcpu_id}] register context smuggled! IA32_LSTAR leaked host syscall handler -> Host Kernel Base: {simulated_host_base}.",
        "vcpu_id": req.vcpu_id,
        "msr": msr_idx,
        "leaked_host_kernel_base": simulated_host_base,
        "flag": STAGE3_FLAG,
    }


@app.post("/api/stage4/enforce_hypervisor_hardening")
async def stage4_enforce_hypervisor_hardening(req: HypervisorHardeningRequest) -> Dict[str, Any]:
    """Stage 4: Seccomp/Landlock MicroVM Confinement & Hypervisor Hardening."""
    if not state.stage3_completed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Stage 3 must be completed before applying hypervisor active hardening policies."
        )

    if req.seccomp_bpf_policy != "strict_kvm_ioctl_whitelist":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Seccomp policy must be 'strict_kvm_ioctl_whitelist' to prevent unvalidated ioctl smuggling."
        )

    if not req.landlock_fs_confinement:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Landlock filesystem confinement must be enabled to prevent host file tampering."
        )

    required_caps = ["CAP_SYS_ADMIN", "CAP_SYS_PTRACE"]
    if not all(cap in req.drop_caps for cap in required_caps):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Both CAP_SYS_ADMIN and CAP_SYS_PTRACE must be dropped. Provided: {req.drop_caps}"
        )

    state.stage4_completed = True
    state.hardening_enforced = True

    return {
        "status": "success",
        "stage": 4,
        "message": "🛡️ MicroVM & Hypervisor Confinement enforced! Seccomp BPF ioctl filter locked down, Landlock LSM fs isolated, root capabilities dropped.",
        "seccomp_bpf": req.seccomp_bpf_policy,
        "landlock_confinement": req.landlock_fs_confinement,
        "dropped_caps": req.drop_caps,
        "memory_tagging": req.enforce_memory_tagging,
        "flag": STAGE4_FLAG,
    }


@app.get("/", response_class=HTMLResponse)
async def get_index() -> HTMLResponse:
    """Web Dashboard for Lab 58."""
    return HTMLResponse(content="""<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <title>Lab 58: MicrovmHypervisorEscapeLab</title>
    <style>
        body { background: #0b0f19; color: #f3f4f6; font-family: -apple-system, monospace; padding: 2rem; }
        .container { max-width: 1000px; margin: 0 auto; }
        header { border-bottom: 1px solid #1f2937; padding-bottom: 1rem; margin-bottom: 1.5rem; }
        h1 { color: #38bdf8; }
        .badge { background: #1e293b; color: #38bdf8; padding: 4px 8px; border-radius: 4px; font-size: 0.8rem; margin-right: 6px; }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(400px, 1fr)); gap: 1rem; }
        .card { background: #111827; border: 1px solid #1f2937; border-radius: 8px; padding: 1rem; }
        pre { background: #030712; padding: 10px; border-radius: 6px; color: #4ade80; overflow-x: auto; font-size: 0.85rem; }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>📦 Lab 58: MicrovmHypervisorEscapeLab</h1>
            <p>MicroVM & Hypervisor Escape Defense Lab (KVM, Virtio-Net, MMIO & Landlock Confinement)</p>
            <span class="badge">Port 8058</span>
            <span class="badge">127.0.0.1 Bound</span>
            <span class="badge">CVSS 8.8 (HIGH)</span>
            <span class="badge">Category: Cloud Security</span>
        </header>
        <div class="grid">
            <div class="card">
                <h3>Stage 1: VM-Exit & MMIO Emulation Flaw</h3>
                <p>Induce EPT violation & exploit emulated HPET handler.</p>
                <pre>POST /api/stage1/intercept_vm_exit
{
  "exit_reason": "EXIT_REASON_EPT_VIOLATION",
  "mmio_address": "0xFED00000",
  "emulation_handler": "hpet_mmio_read"
}</pre>
            </div>
            <div class="card">
                <h3>Stage 2: Virtio Shared Memory vring Corruption</h3>
                <p>Cause out-of-bounds heap corruption across guest/host memory.</p>
                <pre>POST /api/stage2/virtio_vring_overflow
{
  "vring_idx": 3,
  "descriptor_len": 4096,
  "corrupt_next_offset": "0x1000",
  "payload_type": "scatter_gather_oob"
}</pre>
            </div>
            <div class="card">
                <h3>Stage 3: KVM vCPU Register Smuggling & Base Leak</h3>
                <p>Leak IA32_LSTAR syscall address & calculate host kernel base.</p>
                <pre>POST /api/stage3/kvm_vcpu_smuggling
{
  "vcpu_id": 0,
  "smuggle_register": "CR3_AND_MSR_LSTAR",
  "target_msr": "0xC0000082",
  "leak_host_kernel_base": true
}</pre>
            </div>
            <div class="card">
                <h3>Stage 4: MicroVM Confinement & Hardening</h3>
                <p>Enforce Seccomp ioctl filter, Landlock LSM fs, drop caps.</p>
                <pre>POST /api/stage4/enforce_hypervisor_hardening
{
  "seccomp_bpf_policy": "strict_kvm_ioctl_whitelist",
  "landlock_fs_confinement": true,
  "drop_caps": ["CAP_SYS_ADMIN", "CAP_SYS_PTRACE"],
  "enforce_memory_tagging": true
}</pre>
            </div>
        </div>
    </div>
</body>
</html>""")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="127.0.0.1", port=8058, reload=True)
