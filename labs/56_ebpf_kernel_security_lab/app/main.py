#!/usr/bin/env python3
"""
Lab 56: eBPFShield — eBPF 런타임 보안 & 커널 루트킷 능동 방어 랩 (eBPF Kernel Security & Runtime Threat Defense Lab)
Port: 8056 (127.0.0.1 bound)

4-Stage Interactive Kernel Telemetry & Active Defense Simulation:
1. Syscall Telemetry & kprobe/tracepoint Attachment: Intercepting stealthy execve via BPF tracepoints
2. eBPF Ring Buffer & Process Hollowing Detection: Unmasking task_struct->comm masquerading
3. Malicious eBPF Rootkit & BPF Map Audit: Detecting bpf_override_return & purging rogue hooks
4. eBPF LSM (Linux Security Module) Zero-Trust Policy: Active syscall blocking and runtime containment
"""

from typing import Dict, Any, List, Optional
import os
import hashlib
import json
from fastapi import FastAPI, HTTPException, status
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field

app = FastAPI(
    title="Lab 56: eBPFShield — eBPF Kernel Security & Active Defense Lab",
    description="Hands-on eBPF tracepoints, ring buffer analysis, eBPF rootkit hunting, and BPF LSM zero-trust policies.",
    version="1.0.0",
)

# CTF Flags
STAGE1_FLAG = "FLAG{EBPF_TRACEPOINT_EXECVE_TELEMETRY_ACQUIRED_5601}"
STAGE2_FLAG = "FLAG{RING_BUFFER_PROCESS_HOLLOWING_UNMASKED_5602}"
STAGE3_FLAG = "FLAG{MALICIOUS_EBPF_ROOTKIT_HOOK_PURGED_5603}"
STAGE4_FLAG = "FLAG{EBPF_LSM_RUNTIME_ZERO_TRUST_ENFORCED_5604}"


class LabState:
    """State manager for Lab 56 eBPFShield."""
    def __init__(self) -> None:
        self.reset()

    def reset(self) -> None:
        self.stage1_completed: bool = False
        self.stage2_completed: bool = False
        self.stage3_completed: bool = False
        self.stage4_completed: bool = False

        # Simulated kernel eBPF state
        self.active_probes: List[str] = []
        self.ring_buffer_ready: bool = False
        self.rogue_ebpf_purged: bool = False
        self.lsm_policy_active: bool = False


state = LabState()


# --- Pydantic Request Models ---
class TelemetryAttachRequest(BaseModel):
    hook_target: str = Field(..., max_length=64, description="BPF hook target (e.g. tracepoint/syscalls/sys_enter_execve)")
    filter_expression: str = Field(..., max_length=128, description="BPF in-kernel filter expression")
    ring_buffer_size_kb: int = Field(default=64, ge=32, le=1024, description="Ring buffer allocation in KB")


class ProcessHollowingAuditRequest(BaseModel):
    target_pid: int = Field(..., ge=1, le=65535, description="Target process PID to inspect")
    cross_check_inode: bool = Field(default=True, description="Correlate task_struct->comm with mm->exe_file inode")
    scan_vad_permissions: bool = Field(default=True, description="Scan Virtual Address Descriptor for PROT_WRITE|PROT_EXEC")


class RootkitAuditRequest(BaseModel):
    scan_bpf_progs: bool = Field(default=True, description="Perform kernel BPF program inventory audit")
    rogue_prog_id: int = Field(default=404, ge=1, description="Target rogue eBPF program ID to inspect/detach")
    action: str = Field(..., max_length=32, description="Action to execute: 'inspect' or 'detach_and_purge'")


class LSMPolicyEnforceRequest(BaseModel):
    policy_mode: str = Field(..., max_length=32, description="LSM policy mode: 'permissive' or 'enforcing'")
    allowed_binary_roots: List[str] = Field(..., description="Whitelisted directory prefixes for executable binaries")
    block_unverified_mprotect: bool = Field(default=True, description="Intercept mprotect PROT_EXEC on non-file-backed memory")
    action_on_violation: str = Field(default="SIGKILL", max_length=16, description="LSM enforcement action: -EPERM or SIGKILL")


# --- General Endpoints ---
@app.get("/health")
@app.get("/api/health")
async def health_check() -> Dict[str, str]:
    return {"status": "ok", "lab": "Lab 56: eBPFShield", "port": "8056"}


@app.get("/api/status")
async def get_status() -> Dict[str, Any]:
    stages_solved = sum([
        state.stage1_completed,
        state.stage2_completed,
        state.stage3_completed,
        state.stage4_completed,
    ])
    return {
        "lab_id": "56",
        "name": "eBPF Kernel Security & Runtime Threat Defense Lab",
        "port": 8056,
        "status": "running",
        "total_stages": 4,
        "solved_count": stages_solved,
        "stages": {
            "stage1_completed": state.stage1_completed,
            "stage2_completed": state.stage2_completed,
            "stage3_completed": state.stage3_completed,
            "stage4_completed": state.stage4_completed,
        },
        "ebpf_telemetry": {
            "active_probes": state.active_probes,
            "ring_buffer_ready": state.ring_buffer_ready,
            "rogue_ebpf_purged": state.rogue_ebpf_purged,
            "lsm_policy_active": state.lsm_policy_active,
        },
    }


@app.post("/api/reset")
async def reset_lab() -> Dict[str, str]:
    state.reset()
    return {"status": "success", "message": "Lab 56 environment reset to initial state."}


# --- Stage 1: Syscall Telemetry & Tracepoint Hooking ---
@app.post("/api/stage1/attach_telemetry")
async def stage1_attach_telemetry(req: TelemetryAttachRequest) -> Dict[str, Any]:
    target = req.hook_target.strip().lower()
    valid_targets = [
        "tracepoint/syscalls/sys_enter_execve",
        "tracepoint/syscalls/sys_enter_execveat",
        "kprobe/do_sys_openat2",
        "kprobe/__x64_sys_execve",
    ]

    if target not in valid_targets:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid hook target '{req.hook_target}'. Valid targets: {valid_targets}",
        )

    if req.ring_buffer_size_kb < 64:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Ring buffer size must be at least 64 KB to avoid dropped telemetry events under kernel load.",
        )

    # Attach probe to telemetry pipeline
    if target not in state.active_probes:
        state.active_probes.append(target)
    state.ring_buffer_ready = True
    state.stage1_completed = True

    intercepted_event = {
        "timestamp_ns": 1731542400000000000,
        "pid": 1337,
        "ppid": 1,
        "uid": 0,
        "comm": "kworker/0:1",
        "hook": target,
        "filter": req.filter_expression,
        "raw_syscall": "sys_enter_execve",
        "filename": "/proc/self/fd/3 (memfd:hidden_loader)",
        "argv": ["kworker/0:1", "--beacon", "c2.darknet.internal:443"],
        "anomaly": "CRITICAL: Kernel worker process executing out of anonymous file descriptor memfd_create!",
    }

    return {
        "success": True,
        "stage": 1,
        "message": f"eBPF probe successfully attached to {target} with zero-overhead telemetry.",
        "ring_buffer_event": intercepted_event,
        "flag": STAGE1_FLAG,
    }


# --- Stage 2: eBPF Ring Buffer & Process Hollowing Detection ---
@app.post("/api/stage2/detect_process_hollowing")
async def stage2_detect_process_hollowing(req: ProcessHollowingAuditRequest) -> Dict[str, Any]:
    if not state.stage1_completed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Stage 1 must be completed: Attach eBPF telemetry probe first.",
        )

    if req.target_pid != 1337:
        return {
            "success": False,
            "message": f"PID {req.target_pid} verified benign (standard system daemon). Target the anomalous process identified in Stage 1 (PID 1337).",
        }

    if not req.cross_check_inode or not req.scan_vad_permissions:
        return {
            "success": False,
            "message": "Detection failed: Both cross_check_inode and scan_vad_permissions must be enabled to confirm process hollowing.",
        }

    hollowed_profile = {
        "pid": 1337,
        "reported_comm": "kworker/0:1",
        "task_struct_flags": "PF_KTHREAD (spoofed in userland)",
        "actual_exe_inode": 982144,
        "exe_path": "/tmp/.hidden_stealth_rootkit.elf (deleted)",
        "vad_regions": [
            {"base": "0x400000", "size_kb": 128, "prot": "R-X", "backed": "/tmp/.hidden_stealth_rootkit.elf"},
            {"base": "0x7fff0000", "size_kb": 64, "prot": "RWX", "backed": "ANONYMOUS (Injected Shellcode)"},
        ],
        "anomaly_classification": "MITRE ATT&CK T1055.012: Process Hollowing & Masquerading",
    }

    state.stage2_completed = True
    return {
        "success": True,
        "stage": 2,
        "message": "Process hollowing detected: Disguised userland binary masquerading as kernel thread kworker/0:1.",
        "audit_evidence": hollowed_profile,
        "flag": STAGE2_FLAG,
    }


# --- Stage 3: Malicious eBPF Rootkit & BPF Map Audit ---
@app.post("/api/stage3/audit_ebpf_rootkit")
async def stage3_audit_ebpf_rootkit(req: RootkitAuditRequest) -> Dict[str, Any]:
    if not state.stage2_completed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Stage 2 must be completed before performing kernel BPF rootkit audits.",
        )

    if not req.scan_bpf_progs:
        return {"success": False, "message": "scan_bpf_progs must be True to inspect kernel BPF subsystem."}

    rogue_inventory = {
        "prog_id": 404,
        "name": "bpf_stealth_hook",
        "type": "BPF_PROG_TYPE_KPROBE",
        "attach_func": "__x64_sys_getdents64",
        "license": "GPL",
        "verified_insns": 142,
        "helper_calls": ["bpf_probe_write_user", "bpf_override_return", "bpf_map_lookup_elem"],
        "threat_rating": "CRITICAL (Adversary eBPF Rootkit altering directory entries and return codes)",
        "associated_map_id": 909,
        "map_name": "hidden_files_map",
        "map_type": "BPF_MAP_TYPE_HASH",
        "entries": ["/tmp/.hidden_stealth_rootkit.elf", "rootkit.ko", "c2_beacon"],
    }

    if req.action == "inspect":
        return {
            "success": True,
            "message": "Rogue eBPF rootkit detected hooking __x64_sys_getdents64 with bpf_override_return.",
            "prog_inventory": rogue_inventory,
            "next_step": "Invoke action='detach_and_purge' to eradicate the rogue hook from kernel.",
        }
    elif req.action == "detach_and_purge":
        if req.rogue_prog_id != 404:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid rogue_prog_id {req.rogue_prog_id}. Identified rogue BPF ID is 404.",
            )

        state.rogue_ebpf_purged = True
        state.stage3_completed = True
        return {
            "success": True,
            "stage": 3,
            "message": "Malicious eBPF rootkit hook 404 successfully detached and BPF map 909 sanitized.",
            "purged_program": rogue_inventory,
            "flag": STAGE3_FLAG,
        }
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unknown action '{req.action}'. Expected 'inspect' or 'detach_and_purge'.",
        )


# --- Stage 4: eBPF LSM Policy Enforcement & Zero-Trust Sandboxing ---
@app.post("/api/stage4/enforce_lsm_policy")
async def stage4_enforce_lsm_policy(req: LSMPolicyEnforceRequest) -> Dict[str, Any]:
    if not state.stage3_completed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Stage 3 must be completed before applying proactive LSM security policies.",
        )

    mode = req.policy_mode.strip().lower()
    if mode != "enforcing":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="policy_mode must be 'enforcing' to activate zero-trust kernel execution barriers.",
        )

    required_roots = ["/usr/bin", "/bin"]
    for r in required_roots:
        if not any(r in root for root in req.allowed_binary_roots):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Missing essential system binary prefix '{r}' in allowed_binary_roots whitelist.",
            )

    if not req.block_unverified_mprotect:
        return {
            "success": False,
            "message": "Policy weakness: block_unverified_mprotect must be enabled to prevent runtime shellcode staging.",
        }

    # Simulate blocked adversary attack attempt
    blocked_test_execution = {
        "attempted_binary": "/dev/shm/c2_payload",
        "caller_uid": 1000,
        "lsm_hook": "bpf_lsm_bprm_check_security",
        "verdict": "DENIED (-EPERM)",
        "containment_action": req.action_on_violation,
        "audit_event": "eBPF LSM blocked untrusted binary execution outside whitelisted prefixes.",
    }

    state.lsm_policy_active = True
    state.stage4_completed = True

    return {
        "success": True,
        "stage": 4,
        "status": "eBPF LSM Zero-Trust Runtime Sandboxing Active",
        "policy": {
            "mode": mode,
            "allowed_roots": req.allowed_binary_roots,
            "mprotect_sanitizer": "ENABLED",
            "enforcement_action": req.action_on_violation,
        },
        "simulation_result": blocked_test_execution,
        "flag": STAGE4_FLAG,
    }


# --- UI Web Console ---
@app.get("/", response_class=HTMLResponse)
async def index_page() -> str:
    status_data = await get_status()
    solved = status_data["solved_count"]
    return f"""
    <!DOCTYPE html>
    <html lang="ko">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Lab 56: eBPFShield — eBPF Kernel Security & Active Defense</title>
        <style>
            :root {{
                --bg: #0b0f19;
                --surface: #111827;
                --border: #1f2937;
                --accent: #10b981;
                --accent-dim: #065f46;
                --text: #f3f4f6;
                --text-muted: #9ca3af;
                --cyan: #06b6d4;
                --red: #ef4444;
            }}
            * {{ box-sizing: border-box; margin: 0; padding: 0; }}
            body {{
                font-family: 'JetBrains Mono', 'Fira Code', monospace;
                background-color: var(--bg);
                color: var(--text);
                padding: 2rem;
                line-height: 1.6;
            }}
            .container {{ max-width: 1000px; margin: 0 auto; }}
            header {{
                border-bottom: 2px solid var(--border);
                padding-bottom: 1.5rem;
                margin-bottom: 2rem;
            }}
            h1 {{ font-size: 1.8rem; color: var(--accent); margin-bottom: 0.5rem; }}
            .subtitle {{ color: var(--cyan); font-size: 0.95rem; }}
            .badge {{
                display: inline-block;
                padding: 0.25rem 0.6rem;
                border-radius: 4px;
                font-size: 0.8rem;
                font-weight: bold;
                background: var(--accent-dim);
                color: var(--accent);
                border: 1px solid var(--accent);
            }}
            .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 1rem; margin: 1.5rem 0; }}
            .card {{
                background: var(--surface);
                border: 1px solid var(--border);
                border-radius: 8px;
                padding: 1.2rem;
            }}
            .card h3 {{ font-size: 1rem; color: var(--cyan); margin-bottom: 0.5rem; }}
            .status-val {{ font-size: 1.4rem; font-weight: bold; }}
            .stage-box {{
                background: var(--surface);
                border: 1px solid var(--border);
                border-radius: 8px;
                padding: 1.5rem;
                margin-bottom: 1.5rem;
            }}
            .stage-box h2 {{ font-size: 1.2rem; color: var(--text); margin-bottom: 0.5rem; }}
            .stage-box p {{ color: var(--text-muted); font-size: 0.9rem; margin-bottom: 1rem; }}
            .code-sample {{
                background: #000;
                padding: 0.8rem;
                border-radius: 6px;
                font-size: 0.85rem;
                color: #38bdf8;
                overflow-x: auto;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <header>
                <h1>🛡️ Lab 56: eBPFShield</h1>
                <div class="subtitle">eBPF 런타임 보안 & 커널 루트킷 능동 방어 실습 랩 (eBPF Kernel Security & Runtime Threat Defense)</div>
                <div style="margin-top: 1rem;">
                    <span class="badge">Port 8056 (127.0.0.1)</span>
                    <span class="badge">Linux eBPF / LSM Engine</span>
                    <span class="badge">NIST CSF 2.0 DE.CM-01</span>
                </div>
            </header>

            <div class="grid">
                <div class="card">
                    <h3>총 진행 단계</h3>
                    <div class="status-val">{solved} / 4 완료</div>
                </div>
                <div class="card">
                    <h3>Ring Buffer 상태</h3>
                    <div class="status-val" style="color: {'var(--accent)' if state.ring_buffer_ready else 'var(--text-muted)'};">
                        {'ONLINE' if state.ring_buffer_ready else 'OFFLINE'}
                    </div>
                </div>
                <div class="card">
                    <h3>루트킷 훅 제거</h3>
                    <div class="status-val" style="color: {'var(--accent)' if state.rogue_ebpf_purged else 'var(--red)'};">
                        {'PURGED' if state.rogue_ebpf_purged else 'INFECTED'}
                    </div>
                </div>
                <div class="card">
                    <h3>eBPF LSM 모드</h3>
                    <div class="status-val" style="color: {'var(--accent)' if state.lsm_policy_active else 'var(--text-muted)'};">
                        {'ENFORCING' if state.lsm_policy_active else 'DISABLED'}
                    </div>
                </div>
            </div>

            <div class="stage-box">
                <h2>Stage 1: eBPF 커널 시스콜 텔레메트리 파이프라인 수립</h2>
                <p>tracepoint/syscalls/sys_enter_execve에 무오버헤드 BPF 프로브를 연동하여 memfd 익명 실행 및 은닉 프로세스를 실시간 포착합니다.</p>
                <div class="code-sample">curl -X POST http://127.0.0.1:8056/api/stage1/attach_telemetry -H "Content-Type: application/json" -d '{{"hook_target":"tracepoint/syscalls/sys_enter_execve", "filter_expression":"pid != 0", "ring_buffer_size_kb":64}}'</div>
            </div>

            <div class="stage-box">
                <h2>Stage 2: 프로세스 할로잉 & task_struct->comm 위장 탐지</h2>
                <p>kworker 커널 스레드로 위장한 불법 바이너리의 실제 mm->exe_file inode 및 W^X 메모리 VAD 구역을 교차 검증합니다.</p>
                <div class="code-sample">curl -X POST http://127.0.0.1:8056/api/stage2/detect_process_hollowing -H "Content-Type: application/json" -d '{{"target_pid":1337, "cross_check_inode":true, "scan_vad_permissions":true}}'</div>
            </div>

            <div class="stage-box">
                <h2>Stage 3: 악성 eBPF 루트킷(bpf_override_return) 식별 및 강제 제거</h2>
                <p>__x64_sys_getdents64 디렉터리 시스콜을 후킹하여 백도어를 은닉하는 rogue BPF 프로그램(ID 404)을 색출 및 언링크합니다.</p>
                <div class="code-sample">curl -X POST http://127.0.0.1:8056/api/stage3/audit_ebpf_rootkit -H "Content-Type: application/json" -d '{{"scan_bpf_progs":true, "rogue_prog_id":404, "action":"detach_and_purge"}}'</div>
            </div>

            <div class="stage-box">
                <h2>Stage 4: eBPF LSM 기반 제로 트러스트 런타임 능동 차단 정책 적용</h2>
                <p>bpf_lsm_bprm_check_security 훅을 통해 비인가 바이너리 실행 시스콜을 커널 레벨에서 즉각 차단(-EPERM / SIGKILL)합니다.</p>
                <div class="code-sample">curl -X POST http://127.0.0.1:8056/api/stage4/enforce_lsm_policy -H "Content-Type: application/json" -d '{{"policy_mode":"enforcing", "allowed_binary_roots":["/usr/bin", "/bin"], "block_unverified_mprotect":true, "action_on_violation":"SIGKILL"}}'</div>
            </div>
        </div>
    </body>
    </html>
    """
