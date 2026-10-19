#!/usr/bin/env python3
"""
Lab 46: KernelGuard — Linux Kernel Hardening & Runtime Defense Lab
Interactive FastAPI service demonstrating Linux kernel security mechanisms:
1. Seccomp-BPF System Call Filter Triage (Architecture pinning & syscall elimination)
2. Landlock LSM Unprivileged Sandboxing (Path-beneath ruleset & no_new_privs lockdown)
3. IMA & EVM Integrity Appraisal (Runtime measurement log audit & digital signature enforcement)
4. KSPP Kernel Memory Mitigation Hardening (kCFI, SLAB_FREELIST, init_on_alloc, KPTI)
"""

from typing import Dict, Any, List, Optional
import os
import re
import hashlib
import json
import time
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field

app = FastAPI(
    title="Lab 46: KernelGuard — Linux Kernel Hardening Lab",
    description="Interactive kernel runtime defense simulation covering Seccomp-BPF, Landlock LSM, IMA/EVM, and KSPP mitigations.",
    version="1.0.0",
)

# Flags
STAGE1_FLAG = "FLAG{seccomp_bpf_arch_pinned_filter_enforced_8046}"
STAGE2_FLAG = "FLAG{landlock_lsm_unprivileged_sandbox_locked_8046}"
STAGE3_FLAG = "FLAG{ima_appraisal_evm_signature_verified_8046}"
STAGE4_FLAG = "FLAG{kspp_kernel_memory_mitigation_cfi_hardened_8046}"

# ============================================================================
# Simulation Data & State
# ============================================================================

AUTHENTIC_WORKER_HASH = "a4f8b92c10de57e841209348b6c8f14a5d89e7c3b21045a987ef632145bcde89"
TAMPERED_WORKER_HASH = "deadbeef99887766554433221100ffeeddccbbaa0123456789abcdef99887766"

class LabState:
    def __init__(self):
        self.reset()

    def reset(self):
        self.stage1_completed = False
        self.stage2_completed = False
        self.stage3_completed = False
        self.stage4_completed = False

        # Stage 1 state
        self.seccomp_policy = {
            "arch": "UNSET",
            "blocked_syscalls": [],
            "action": "SECCOMP_RET_ALLOW",
            "active": False,
        }

        # Stage 2 state
        self.landlock_rules = []
        self.landlock_locked = False

        # Stage 3 state
        self.ima_policy = {
            "appraise_enforced": False,
            "current_worker_hash": TAMPERED_WORKER_HASH,
            "signature_valid": False,
        }

        # Stage 4 state
        self.kspp_config = {
            "init_on_alloc": False,
            "slab_nomerge": False,
            "kcfi_enforce": False,
            "kpti": False,
        }

state = LabState()

# ============================================================================
# Pydantic Schemas with strict bounds
# ============================================================================

class SeccompRequest(BaseModel):
    arch: str = Field(..., max_length=64, description="Target architecture, e.g., AUDIT_ARCH_X86_64")
    blocked_syscalls: List[str] = Field(..., max_length=16, description="List of syscall names to filter/kill")
    action_on_blocked: str = Field(default="SECCOMP_RET_KILL_PROCESS", max_length=64)
    default_action: str = Field(default="SECCOMP_RET_ALLOW", max_length=64)

class LandlockRequest(BaseModel):
    target_path: str = Field(..., max_length=128, description="Directory path beneath which access is allowed")
    allowed_actions: List[str] = Field(..., max_length=8, description="Allowed FS access rights")
    lock_no_new_privs: bool = Field(default=True, description="Enforce PR_SET_NO_NEW_PRIVS before lockdown")

class IMARequest(BaseModel):
    target_binary: str = Field(..., max_length=128, description="Binary path to inspect")
    remedy_action: str = Field(..., max_length=64, description="'restore_authentic' or 'ignore'")
    enforce_signature_check: bool = Field(default=True, description="Enable IMA appraisal with xattr signature verification")

class KSPPRequest(BaseModel):
    init_on_alloc: bool = Field(default=False)
    slab_nomerge: bool = Field(default=False)
    kcfi_enforce: bool = Field(default=False)
    kpti: bool = Field(default=False)

# ============================================================================
# API Endpoints
# ============================================================================

@app.get("/health")
def health():
    return {"status": "ok", "service": "KernelGuard Lab 46", "port": 8046}

@app.get("/api/status")
def get_status():
    return {
        "stage1": {
            "completed": state.stage1_completed,
            "title": "Seccomp-BPF Syscall Filter",
            "policy": state.seccomp_policy,
        },
        "stage2": {
            "completed": state.stage2_completed,
            "title": "Landlock LSM Process Sandbox",
            "locked": state.landlock_locked,
            "rules": state.landlock_rules,
        },
        "stage3": {
            "completed": state.stage3_completed,
            "title": "IMA & EVM Integrity Appraisal",
            "ima_policy": state.ima_policy,
        },
        "stage4": {
            "completed": state.stage4_completed,
            "title": "KSPP Kernel Memory Mitigations",
            "kspp_config": state.kspp_config,
        },
    }

@app.post("/api/reset")
def reset_lab():
    state.reset()
    return {"message": "Lab state successfully reset."}

# Stage 1: Seccomp-BPF
@app.get("/api/stage1/telemetry")
def get_stage1_telemetry():
    """Returns syscall attempts made by a compromised child process."""
    return {
        "host_architecture": "AUDIT_ARCH_X86_64",
        "recent_syscall_attempts": [
            {"syscall": "read", "nr": 0, "status": "executed", "risk": "low"},
            {"syscall": "write", "nr": 1, "status": "executed", "risk": "low"},
            {"syscall": "ptrace", "nr": 101, "status": "attempted", "risk": "critical", "args": "PTRACE_POKETEXT on PID 1"},
            {"syscall": "process_vm_writev", "nr": 311, "status": "attempted", "risk": "critical", "args": "Inject shellcode into victim PID"},
            {"syscall": "kexec_load", "nr": 246, "status": "attempted", "risk": "critical", "args": "Replace host kernel image"},
            {"syscall": "getpid", "nr": 39, "status": "executed", "risk": "low"},
        ],
        "vulnerability": "Process has unrestricted syscall access; ptrace and process_vm_writev allow cross-process code injection.",
    }

@app.post("/api/stage1/apply_seccomp")
def apply_seccomp(req: SeccompRequest):
    arch_clean = req.arch.strip().upper()
    if arch_clean != "AUDIT_ARCH_X86_64":
        raise HTTPException(
            status_code=400,
            detail=f"Architecture validation failed. Must bind explicitly to 'AUDIT_ARCH_X86_64' to prevent ABI downgrade attacks (received: {arch_clean}).",
        )

    blocked = [s.strip().lower() for s in req.blocked_syscalls]
    critical_syscalls = {"ptrace", "process_vm_writev"}
    if not critical_syscalls.issubset(set(blocked)):
        missing = critical_syscalls - set(blocked)
        raise HTTPException(
            status_code=400,
            detail=f"Policy incomplete. Critical dangerous syscalls not blocked: {list(missing)}.",
        )

    action_clean = req.action_on_blocked.strip().upper()
    if action_clean not in ["SECCOMP_RET_KILL_PROCESS", "SECCOMP_RET_KILL_THREAD", "SECCOMP_RET_ERRNO"]:
        raise HTTPException(
            status_code=400,
            detail="Action on blocked syscalls must be terminating (e.g. SECCOMP_RET_KILL_PROCESS) or SECCOMP_RET_ERRNO.",
        )

    state.seccomp_policy = {
        "arch": arch_clean,
        "blocked_syscalls": blocked,
        "action": action_clean,
        "default_action": req.default_action,
        "active": True,
    }
    state.stage1_completed = True

    return {
        "status": "success",
        "message": "Seccomp-BPF filter verified and attached successfully. PTRACE and VM write attacks neutralized.",
        "flag": STAGE1_FLAG,
        "policy": state.seccomp_policy,
    }

# Stage 2: Landlock LSM
@app.get("/api/stage2/profile")
def get_stage2_profile():
    return {
        "process_name": "worker_daemon",
        "pid": 4821,
        "uid": 1001,
        "current_confinement": "unconfined",
        "attempted_accesses": [
            {"path": "/srv/app/data/items.db", "access": "READ/WRITE", "legitimate": True},
            {"path": "/tmp/worker_scratch.log", "access": "WRITE", "legitimate": True},
            {"path": "/etc/shadow", "access": "READ", "legitimate": False, "threat": "Credential dump"},
            {"path": "/root/.ssh/id_rsa", "access": "READ", "legitimate": False, "threat": "Root private key theft"},
        ],
    }

@app.post("/api/stage2/restrict_landlock")
def restrict_landlock(req: LandlockRequest):
    if not req.lock_no_new_privs:
        raise HTTPException(
            status_code=400,
            detail="Landlock requires prctl(PR_SET_NO_NEW_PRIVS, 1) before lockdown to prevent privilege escalation bypass.",
        )

    path_clean = req.target_path.strip()
    if path_clean in ["/", "/etc", "/root", "/var", "/usr"]:
        raise HTTPException(
            status_code=400,
            detail=f"Target path '{path_clean}' is overly permissive. Restrict sandbox to application directories like '/srv/app/data' or '/tmp'.",
        )

    valid_paths = ["/srv/app/data", "/srv/app", "/tmp"]
    if not any(path_clean.startswith(vp) for vp in valid_paths):
        raise HTTPException(
            status_code=400,
            detail=f"Invalid target path '{path_clean}'. Must be a designated application workspace path (e.g. '/srv/app/data').",
        )

    allowed = [a.strip().upper() for a in req.allowed_actions]
    if not any("READ" in a for a in allowed):
        raise HTTPException(status_code=400, detail="Allowed actions must grant at least read rights to application data.")

    state.landlock_rules = [{
        "path": path_clean,
        "allowed_access": allowed,
    }]
    state.landlock_locked = True
    state.stage2_completed = True

    return {
        "status": "success",
        "message": f"Landlock LSM ruleset locked for path {path_clean}. Arbitrary filesystem traversal to /etc and /root blocked.",
        "flag": STAGE2_FLAG,
        "rules": state.landlock_rules,
    }

# Stage 3: IMA & EVM
@app.get("/api/stage3/ima_log")
def get_stage3_ima_log():
    return {
        "ima_measurement_file": "/sys/kernel/security/ima/ascii_runtime_measurements",
        "entries": [
            {
                "pcr": 10,
                "template_hash": "b2c3d4e5...",
                "template_name": "ima-ng",
                "file_hash_algo": "sha256",
                "measured_hash": state.ima_policy["current_worker_hash"],
                "file_path": "/usr/bin/daemon_worker",
                "signature_status": "VALID_SIGNATURE" if state.ima_policy["signature_valid"] else "MISSING_OR_CORRUPT_XATTR",
            }
        ],
        "expected_authentic_hash": AUTHENTIC_WORKER_HASH,
        "is_tampered": state.ima_policy["current_worker_hash"] != AUTHENTIC_WORKER_HASH,
    }

@app.post("/api/stage3/appraise")
def appraise_ima(req: IMARequest):
    if req.target_binary.strip() != "/usr/bin/daemon_worker":
        raise HTTPException(
            status_code=400,
            detail="Target binary must specify the audited file '/usr/bin/daemon_worker'.",
        )

    action = req.remedy_action.strip().lower()
    if action != "restore_authentic":
        raise HTTPException(
            status_code=400,
            detail="You must specify remedy_action='restore_authentic' to replace the backdoored ELF executable.",
        )

    if not req.enforce_signature_check:
        raise HTTPException(
            status_code=400,
            detail="IMA appraisal must enforce cryptographic xattr signature verification (appraise_type=imasig).",
        )

    state.ima_policy["current_worker_hash"] = AUTHENTIC_WORKER_HASH
    state.ima_policy["signature_valid"] = True
    state.ima_policy["appraise_enforced"] = True
    state.stage3_completed = True

    return {
        "status": "success",
        "message": "Authentic worker binary restored and IMA appraisal policy (xattr security.ima) enforced. Unsigned binaries blocked.",
        "flag": STAGE3_FLAG,
        "hash": AUTHENTIC_WORKER_HASH,
    }

# Stage 4: KSPP Mitigations
@app.get("/api/stage4/kernel_posture")
def get_stage4_kernel_posture():
    return {
        "kernel_release": "6.6.50-hardened-kspp",
        "current_mitigations": state.kspp_config,
        "vulnerabilities_detected": [
            "init_on_alloc disabled: sensitive crypto keys linger in free kernel pages",
            "slab_nomerge disabled: kernel slab cache coalescing facilitates heap cross-cache attacks",
            "kCFI disabled: indirect function pointers susceptible to forward-edge ROP/JOP hijacking",
            "kpti disabled: kernel page table shared with userspace, vulnerable to Meltdown memory leakage",
        ],
    }

@app.post("/api/stage4/harden")
def harden_kspp(req: KSPPRequest):
    missing = []
    if not req.init_on_alloc:
        missing.append("init_on_alloc=1 (zero memory upon allocation)")
    if not req.slab_nomerge:
        missing.append("slab_nomerge=1 (isolate slab caches)")
    if not req.kcfi_enforce:
        missing.append("kcfi_enforce=1 (Clang Control Flow Integrity)")
    if not req.kpti:
        missing.append("kpti=1 (Kernel Page Table Isolation)")

    if missing:
        raise HTTPException(
            status_code=400,
            detail=f"Incomplete KSPP hardening configuration. Missing settings: {missing}.",
        )

    state.kspp_config = {
        "init_on_alloc": True,
        "slab_nomerge": True,
        "kcfi_enforce": True,
        "kpti": True,
    }
    state.stage4_completed = True

    return {
        "status": "success",
        "message": "All KSPP kernel memory mitigations activated. Forward-edge CFI, page zeroing, SLAB isolation, and KPTI verified.",
        "flag": STAGE4_FLAG,
        "kspp_config": state.kspp_config,
    }

# ============================================================================
# Web UI Dashboard
# ============================================================================

@app.get("/", response_class=HTMLResponse)
def index():
    return """<!DOCTYPE html>
<html lang="ko">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Lab 46: KernelGuard — Linux Kernel Hardening & Defense Lab</title>
  <style>
    :root {
      --bg: #0d1117;
      --card-bg: #161b22;
      --border: #30363d;
      --text: #c9d1d9;
      --accent: #58a6ff;
      --green: #238636;
      --red: #da3633;
      --yellow: #d29922;
    }
    body {
      background: var(--bg);
      color: var(--text);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      margin: 0;
      padding: 24px;
    }
    .header {
      border-bottom: 1px solid var(--border);
      padding-bottom: 16px;
      margin-bottom: 24px;
    }
    h1 { color: var(--accent); margin: 0 0 8px 0; font-size: 24px; }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 16px; }
    .card {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 16px;
    }
    .badge {
      display: inline-block;
      padding: 2px 8px;
      border-radius: 12px;
      font-size: 12px;
      font-weight: 600;
      margin-bottom: 8px;
    }
    .badge-pending { background: #383216; color: var(--yellow); }
    .badge-done { background: #132a1c; color: #3fb950; }
    button {
      background: var(--green);
      color: #fff;
      border: none;
      padding: 8px 14px;
      border-radius: 6px;
      font-weight: 600;
      cursor: pointer;
      margin-top: 10px;
    }
    button:hover { background: #2ea043; }
    pre {
      background: #090d13;
      border: 1px solid var(--border);
      border-radius: 4px;
      padding: 10px;
      font-size: 13px;
      overflow-x: auto;
    }
  </style>
</head>
<body>
  <div class="header">
    <h1>🐧 Lab 46: KernelGuard — Linux Kernel Hardening & Runtime Defense</h1>
    <p>포트 8046 | Seccomp-BPF 시스템콜 필터링, Landlock LSM 샌드박싱, IMA/EVM 무결성 측정, KSPP 커널 완화 기법 실전 실습</p>
  </div>
  <div class="grid">
    <div class="card" id="card-stage1">
      <span class="badge badge-pending">Stage 1</span>
      <h3>1. Seccomp-BPF 필터링</h3>
      <p>아키텍처 고정(AUDIT_ARCH_X86_64) 검증 및 악성 ptrace/VM 메모리 쓰기 차단.</p>
      <pre id="st1-res">상태 대기 중...</pre>
    </div>
    <div class="card" id="card-stage2">
      <span class="badge badge-pending">Stage 2</span>
      <h3>2. Landlock LSM 샌드박싱</h3>
      <p>비특권 프로세스 파일시스템 경로 격리 및 no_new_privs 잠금 적용.</p>
      <pre id="st2-res">상태 대기 중...</pre>
    </div>
    <div class="card" id="card-stage3">
      <span class="badge badge-pending">Stage 3</span>
      <h3>3. IMA / EVM 무결성 측정</h3>
      <p>변조된 바이너리 탐지 및 xattr security.ima 서명 검증 정책 강제.</p>
      <pre id="st3-res">상태 대기 중...</pre>
    </div>
    <div class="card" id="card-stage4">
      <span class="badge badge-pending">Stage 4</span>
      <h3>4. KSPP 커널 메모리 완화</h3>
      <p>Clang kCFI 제어 흐름 보호, SLAB 격리 및 메모리 0화(init_on_alloc) 설정.</p>
      <pre id="st4-res">상태 대기 중...</pre>
    </div>
  </div>
</body>
</html>
"""

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8046, reload=True)
