#!/usr/bin/env python3
"""
Lab 51: eBPFRuntimeGuard — Cloud Native eBPF Kernel Observability & Runtime Security Lab
Interactive simulation based on Cilium Tetragon and Falco runtime security architecture:
1. Kernel Syscall Tracing: kprobe & tracepoint telemetry (sys_enter_execve)
2. eBPF LSM Policy: bpf_lsm_file_open blocking container namespace escape
3. Tetragon TracingPolicy: CRD manifest enforcement with in-kernel SIGKILL
4. BPF Rootkit Triage: bpftool memory audit, shadow hook carving & map remediation
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
    title="Lab 51: eBPFRuntimeGuard — eBPF Kernel Runtime Security Lab",
    description="Cloud-native eBPF kernel observability and synchronous runtime threat defense.",
    version="1.0.0",
)

# CTF Flags
STAGE1_FLAG = "FLAG{EBPF_KPROBE_EXECVE_TELEMETRY_9182}"
STAGE2_FLAG = "FLAG{EBPF_LSM_FILE_OPEN_BLOCK_ESCAPED_7231}"
STAGE3_FLAG = "FLAG{EBPF_TETRAGON_TRACING_POLICY_SIGKILL_5549}"
STAGE4_FLAG = "FLAG{EBPF_SHADOW_ROOTKIT_CARVED_VERIFIED_3310}"


class LabState:
    def __init__(self):
        self.reset()

    def reset(self):
        self.stage1_completed = False
        self.stage2_completed = False
        self.stage3_completed = False
        self.stage4_completed = False

        self.rootkit_neutralized = False
        self.active_policies: List[str] = []


state = LabState()


class SyscallTraceRequest(BaseModel):
    probe_type: str = Field(..., description="kprobe, tracepoint, raw_tracepoint, uretprobe")
    target_syscall: str = Field(..., description="sys_enter_execve, sys_enter_openat, sys_enter_connect")
    filter_expression: str = Field(..., description="eBPF filter expression (e.g. comm == 'bash' || filename == '/bin/sh')")


class LSMEnforceRequest(BaseModel):
    lsm_hook: str = Field(..., description="bpf_lsm_file_open, bpf_lsm_task_fix_setuid, bpf_lsm_bprm_check_security")
    target_path: str = Field(..., description="Target file path to protect (e.g. /etc/shadow)")
    action: str = Field(..., description="BLOCK_EPERM, AUDIT_LOG")


class TracingPolicyRequest(BaseModel):
    policy_name: str = Field(..., description="Kubernetes TracingPolicy CRD name")
    kprobe_symbol: str = Field(..., description="Kernel function symbol (e.g. commit_creds, sys_setuid)")
    enforcement_action: str = Field(..., description="Sigkill, Override, Signal")
    namespace_selector: str = Field(..., description="Kubernetes namespace (e.g. default, production)")


class BPFAuditRequest(BaseModel):
    audit_command: str = Field(..., description="bpftool prog dump, bpftool map dump, bpftool btf dump")
    target_hooked_syscall: str = Field(..., description="Syscall hijacked by shadow rootkit (e.g. sys_enter_getdents64)")
    remediation_action: str = Field(..., description="DETACH_PROG_UNPIN_MAP, RELOAD_KERNEL")


@app.get("/", response_class=HTMLResponse)
async def get_index():
    return """
    <!DOCTYPE html>
    <html lang="ko">
    <head>
        <meta charset="UTF-8">
        <title>Lab 51: eBPFRuntimeGuard Console</title>
        <style>
            body { background: #0b0f19; color: #d1d5db; font-family: 'Fira Code', monospace; padding: 20px; }
            h1 { color: #38bdf8; border-bottom: 2px solid #1e293b; padding-bottom: 10px; }
            .card { background: #111827; border: 1px solid #1f2937; border-radius: 8px; padding: 16px; margin-bottom: 16px; }
            .badge { display: inline-block; padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; }
            .badge-ready { background: #065f46; color: #34d399; }
            .badge-active { background: #1e3a8a; color: #60a5fa; }
            pre { background: #030712; padding: 12px; border-radius: 6px; overflow-x: auto; color: #a7f3d0; }
            button { background: #0284c7; color: white; border: none; padding: 8px 16px; border-radius: 4px; cursor: pointer; }
            button:hover { background: #0369a1; }
        </style>
    </head>
    <body>
        <h1>🛡️ Lab 51: eBPFRuntimeGuard Console</h1>
        <div class="card">
            <p><strong>상태:</strong> <span class="badge badge-ready">ONLINE</span> | <strong>커널 옵저버빌리티 포트:</strong> 8051</p>
            <p>eBPF kprobe/tracepoint 텔레메트리, LSM 실시간 차단, Cilium Tetragon TracingPolicy, BPF Shadow Rootkit 무결성 감사를 수행하십시오.</p>
        </div>
        <div class="card">
            <h3>진행 단계 (Stages)</h3>
            <ul>
                <li><strong>Stage 1:</strong> 커널 시스템콜 추적 & 비인가 실행 탐지 (kprobe:sys_execve)</li>
                <li><strong>Stage 2:</strong> eBPF LSM 기반 네임스페이스 탈출 차단 (bpf_lsm_file_open)</li>
                <li><strong>Stage 3:</strong> Cilium Tetragon TracingPolicy 실시간 SIGKILL 차단</li>
                <li><strong>Stage 4:</strong> eBPF 맵 변조 & Shadow Rootkit 무결성 복원 (bpftool audit)</li>
            </ul>
        </div>
    </body>
    </html>
    """


@app.get("/status")
async def get_status():
    return {
        "lab": "51_ebpf_runtime_security_lab",
        "title": "eBPFRuntimeGuard — Cloud Native eBPF Kernel Observability & Runtime Security Lab",
        "port": 8051,
        "stages": {
            "stage1_syscall_tracing": state.stage1_completed,
            "stage2_lsm_namespace_escape": state.stage2_completed,
            "stage3_tetragon_tracing_policy": state.stage3_completed,
            "stage4_bpf_rootkit_audit": state.stage4_completed,
        },
        "rootkit_neutralized": state.rootkit_neutralized,
        "active_policies_count": len(state.active_policies),
    }


@app.post("/api/reset")
async def reset_lab():
    state.reset()
    return {"status": "success", "message": "Lab 51 state has been reset."}


@app.post("/api/stage1/trace_syscall")
async def stage1_trace_syscall(req: SyscallTraceRequest):
    valid_probes = ["kprobe", "tracepoint", "raw_tracepoint", "uretprobe"]
    if req.probe_type.lower() not in valid_probes:
        raise HTTPException(status_code=400, detail=f"Invalid probe type: {req.probe_type}. Valid: {valid_probes}")

    if req.target_syscall != "sys_enter_execve":
        return {
            "status": "inconclusive",
            "message": f"Syscall {req.target_syscall} captured, but no unauthorized reverse shell spawn detected.",
        }

    # Check filter expression
    filt = req.filter_expression.lower()
    if not ("sh" in filt or "bash" in filt or "exec" in filt or "nc" in filt):
        return {
            "status": "inconclusive",
            "message": "Filter expression too narrow; failed to triangulate unauthorized interactive shell spawn.",
        }

    state.stage1_completed = True
    return {
        "status": "success",
        "message": "eBPF probe attached! Reverse shell binary execution intercepted via sys_enter_execve telemetry.",
        "captured_event": {
            "pid": 4192,
            "comm": "sh",
            "parent_pid": 1042,
            "parent_comm": "python3",
            "filename": "/bin/sh",
            "args": ["/bin/sh", "-i"],
            "container_id": "c4b189a022f",
        },
        "flag": STAGE1_FLAG,
    }


@app.post("/api/stage2/enforce_lsm_hook")
async def stage2_enforce_lsm(req: LSMEnforceRequest):
    valid_hooks = ["bpf_lsm_file_open", "bpf_lsm_task_fix_setuid", "bpf_lsm_bprm_check_security"]
    if req.lsm_hook not in valid_hooks:
        raise HTTPException(status_code=400, detail=f"Invalid LSM hook: {req.lsm_hook}. Valid: {valid_hooks}")

    if "/etc/shadow" not in req.target_path and "/root/.ssh" not in req.target_path:
        raise HTTPException(status_code=400, detail="Target path is not a critical credential asset requiring kernel protection.")

    if req.action != "BLOCK_EPERM":
        return {
            "status": "audited_only",
            "message": "LSM hook in audit mode: access was logged but container namespace escape successfully read host file!",
        }

    state.stage2_completed = True
    return {
        "status": "success",
        "message": f"eBPF LSM hook {req.lsm_hook} enforced! Container file access to {req.target_path} blocked with -EPERM.",
        "lsm_audit": {
            "hook": req.lsm_hook,
            "target": req.target_path,
            "ret_code": -1,  # -EPERM
            "containment": "Namespace escape blocked synchronously at kernel VFS boundary.",
        },
        "flag": STAGE2_FLAG,
    }


@app.post("/api/stage3/apply_tracing_policy")
async def stage3_apply_policy(req: TracingPolicyRequest):
    if not req.policy_name or len(req.policy_name.strip()) < 3:
        raise HTTPException(status_code=400, detail="Invalid TracingPolicy name.")

    valid_symbols = ["commit_creds", "sys_setuid", "do_init_module"]
    if req.kprobe_symbol not in valid_symbols:
        raise HTTPException(status_code=400, detail=f"Invalid kprobe symbol: {req.kprobe_symbol}. Valid: {valid_symbols}")

    if req.enforcement_action != "Sigkill":
        raise HTTPException(status_code=400, detail="Enforcement action must be 'Sigkill' to terminate malicious credential modification synchronously.")

    state.stage3_completed = True
    state.active_policies.append(req.policy_name)

    return {
        "status": "success",
        "message": f"Tetragon TracingPolicy '{req.policy_name}' successfully applied. In-kernel Sigkill active for {req.kprobe_symbol}.",
        "kernel_verdict": {
            "hook": f"kprobe/{req.kprobe_symbol}",
            "action": "Sigkill",
            "process_terminated": "pkexec (PID 5912)",
            "mitigation": "Privilege escalation thwarted before root credentials committed.",
        },
        "flag": STAGE3_FLAG,
    }


@app.post("/api/stage4/audit_bpf_rootkit")
async def stage4_audit_rootkit(req: BPFAuditRequest):
    valid_cmds = ["bpftool prog dump", "bpftool map dump", "bpftool btf dump"]
    if req.audit_command not in valid_cmds:
        raise HTTPException(status_code=400, detail=f"Invalid audit command: {req.audit_command}. Valid: {valid_cmds}")

    if req.target_hooked_syscall != "sys_enter_getdents64":
        raise HTTPException(status_code=400, detail="Incorrect hooked syscall. Shadow rootkit hijacks directory listing via sys_enter_getdents64.")

    if req.remediation_action != "DETACH_PROG_UNPIN_MAP":
        raise HTTPException(status_code=400, detail="Remediation must be 'DETACH_PROG_UNPIN_MAP' to cleanse kernel memory without node reboot.")

    state.stage4_completed = True
    state.rootkit_neutralized = True

    return {
        "status": "success",
        "message": "Shadow BPF Rootkit identified and unpinned! Kernel syscall dispatch restored to benign state.",
        "rootkit_triage": {
            "prog_id": 9942,
            "prog_name": "bpf_stealth_dirent",
            "hooked_syscall": req.target_hooked_syscall,
            "map_id": 4810,
            "hidden_prefix": "rootkit_",
            "action_taken": "Prog detached from tracepoint, map unpinned from /sys/fs/bpf, memory scrubbed.",
        },
        "flag": STAGE4_FLAG,
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="127.0.0.1", port=8051, reload=True)
