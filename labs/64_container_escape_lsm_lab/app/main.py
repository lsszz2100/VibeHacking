import os
import re
from typing import Dict, Any, List, Optional
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

app = FastAPI(
    title="ContainerEscapeLsmLab",
    description="eBPF LSM Container Escape & Kernel Runtime Shield Lab",
    version="1.0.0"
)

# Simulated eBPF LSM Kernel State
LSM_BLOCKED_CGROUPS: set = set()
LSM_HOOKS_ACTIVE: Dict[str, bool] = {
    "bpf_lsm_userns_create": True,
    "bpf_lsm_capable": True,
    "bpf_lsm_file_open": True,
    "bpf_lsm_inode_permission": True,
    "bpf_lsm_path_link": True,
    "bpf_lsm_task_kill": True
}


class Stage1Request(BaseModel):
    clone_flags: List[str] = Field(..., description="Syscall unshare/clone flags (e.g. CLONE_NEWUSER, CLONE_NEWNS)")
    target_caps: List[str] = Field(..., description="Target requested capabilities (e.g. CAP_SYS_ADMIN, CAP_NET_ADMIN)")
    uid_mapping: str = Field("0 1000 1", description="UID mapping configuration (host_uid child_uid count)")
    use_lsm_guard: bool = Field(False, description="Enable eBPF LSM userns_create and capable policy guard")


class Stage2Request(BaseModel):
    target_path: str = Field(..., description="Target filesystem path for write or symlink injection")
    payload: str = Field(..., description="Payload to write (e.g. host script or core_pattern pipe)")
    mount_flags: List[str] = Field(..., description="Cgroup / procfs mount parameters (e.g. rw, nosuid, nodev)")
    use_lsm_guard: bool = Field(False, description="Enable eBPF LSM file_open / inode_permission W^X security shield")


class Stage3Request(BaseModel):
    fd_descriptor: str = Field(..., description="File descriptor path to traverse (e.g. /proc/self/fd/7)")
    relative_traversal: str = Field(..., description="Relative traversal path out of container (e.g. ../../../etc/shadow)")
    target_action: str = Field("read", description="Action to perform (read, write, exec)")
    use_lsm_guard: bool = Field(False, description="Enable eBPF LSM path_walk and resolve_beneath boundary validator")


class Stage4Request(BaseModel):
    process_tree: List[Dict[str, Any]] = Field(..., description="Simulated container process tree hierarchy")
    syscall_sequence: List[str] = Field(..., description="Sequence of intercepted runtime system calls")
    target_ns_breakout: str = Field("init_pid_ns", description="Target namespace attempting unauthorized entry")
    use_lsm_runtime_shield: bool = Field(False, description="Enable Autonomous eBPF LSM Sigkill & Cgroup Freeze Runtime Shield")


@app.get("/", response_class=HTMLResponse)
def index():
    return """<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <title>Lab 64: eBPF LSM Container Escape & Kernel Runtime Shield Lab</title>
    <style>
        body { font-family: monospace; background: #0d1117; color: #c9d1d9; padding: 2rem; }
        h1 { color: #58a6ff; border-bottom: 1px solid #30363d; padding-bottom: 0.5rem; }
        .card { background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 1.5rem; margin-bottom: 1.5rem; }
        .stage-title { color: #7ee787; font-weight: bold; margin-bottom: 0.5rem; }
        code { background: #21262d; padding: 0.2rem 0.4rem; border-radius: 3px; color: #f0883e; }
        .badge { display: inline-block; background: #1f6feb; color: #fff; padding: 0.2rem 0.6rem; border-radius: 12px; font-size: 0.8rem; }
    </style>
</head>
<body>
    <h1>🛡️ Lab 64: eBPF LSM Container Escape & Kernel Runtime Shield Lab <span class="badge">Port 8064</span></h1>
    <div class="card">
        <p>Linux 커널 eBPF LSM(Linux Security Module)을 활용하여 컨테이너 탈출(Container Escape)을 커널 인라인에서 능동 격리하고 차단하는 실전 보안 랩입니다.</p>
        <p>컴플라이언스: <strong>KISA ISMS-P 2.10.1 / 2.10.5</strong>, <strong>NIST CSF 2.0 PR.PS-01 / DE.CM-01</strong>, <strong>OWASP K01:2025 / K04:2025</strong></p>
    </div>
    <div class="card">
        <div class="stage-title">Stage 1: User Namespace Privileged Capability Escalation (bpf_lsm_userns_create)</div>
        <p>엔드포인트: <code>POST /api/stage1/eval</code></p>
    </div>
    <div class="card">
        <div class="stage-title">Stage 2: Cgroup v2 Release Agent & Procfs Kernel Overwrite (bpf_lsm_file_open)</div>
        <p>엔드포인트: <code>POST /api/stage2/eval</code></p>
    </div>
    <div class="card">
        <div class="stage-title">Stage 3: Leaked Host File Descriptor & Mount Traversal (CVE-2024-21626)</div>
        <p>엔드포인트: <code>POST /api/stage3/eval</code></p>
    </div>
    <div class="card">
        <div class="stage-title">Stage 4: Autonomous Kernel Runtime Zero-Trust Shield & Immediate Killswitch</div>
        <p>엔드포인트: <code>POST /api/stage4/eval</code></p>
    </div>
</body>
</html>
"""


@app.get("/health")
def health():
    return {
        "status": "healthy",
        "lab": "ContainerEscapeLsmLab",
        "lab_id": 64,
        "port": 8064
    }


@app.get("/api/status")
def status_endpoint():
    return {
        "status": "running",
        "lab": "ContainerEscapeLsmLab",
        "lab_id": 64,
        "port": 8064,
        "lsm_hooks": LSM_HOOKS_ACTIVE,
        "stages": [
            "1: User Namespace Privileged Capability Escalation",
            "2: Cgroup v2 Release Agent & Procfs Kernel Overwrite",
            "3: Leaked Host File Descriptor & Mount Traversal",
            "4: Kernel Runtime Zero-Trust Shield & Immediate Killswitch"
        ]
    }


@app.get("/api/health")
def api_health():
    return health()


# =====================================================================
# STAGE 1: User Namespace Privileged Capability Escalation
# =====================================================================
@app.post("/api/stage1/eval")
def stage1_eval(req: Stage1Request):
    """
    1단계: 비특권 컨테이너가 unshare(CLONE_NEWUSER)를 통해 사용자 네임스페이스를 생성하고
    CAP_SYS_ADMIN 등의 권한을 획득하여 호스트 취약점(CVE-2022-0185 등)을 트리거하는 공격
    """
    is_cloning_userns = "CLONE_NEWUSER" in req.clone_flags
    requests_admin_cap = any(cap in ["CAP_SYS_ADMIN", "CAP_NET_ADMIN", "CAP_DAC_OVERRIDE"] for cap in req.target_caps)
    is_root_mapping = req.uid_mapping.startswith("0 ")

    is_exploit_attempt = is_cloning_userns and requests_admin_cap and is_root_mapping

    if not req.use_lsm_guard:
        if is_exploit_attempt:
            return {
                "success": False,
                "status": "VULNERABLE",
                "message": "[VULNERABLE] User namespace created with full CAP_SYS_ADMIN! Privilege escalation to host boundary succeeded.",
                "flag": "FLAG{lsm_userns_capability_sandbox_enforced}"
            }
        else:
            return {
                "success": True,
                "status": "BENIGN_USERNS",
                "message": "Benign namespace operation without dangerous capabilities."
            }
    else:
        # eBPF LSM bpf_lsm_userns_create & bpf_lsm_capable 활성화
        if is_exploit_attempt:
            return {
                "success": True,
                "status": "LSM_USERNS_BLOCKED",
                "flag": "FLAG{lsm_userns_capability_sandbox_enforced}",
                "blocked_by": "bpf_lsm_userns_create",
                "return_code": -1,  # -EPERM
                "message": "[SECURE] eBPF LSM intercepted unshare(CLONE_NEWUSER) from unprivileged cgroup: denied with -EPERM."
            }
        else:
            return {
                "success": True,
                "status": "LSM_PERMITTED",
                "message": "Non-privileged namespace call permitted within bounded cgroup quota."
            }


# =====================================================================
# STAGE 2: Cgroup v2 Release Agent & Procfs Kernel Overwrite
# =====================================================================
@app.post("/api/stage2/eval")
def stage2_eval(req: Stage2Request):
    """
    2단계: 쓰기 가능한 cgroup / procfs 마운트를 악용하여 release_agent 또는
    /proc/sys/kernel/core_pattern 등을 변조하여 호스트 루트 권한 코드 실행을 유도하는 공격
    """
    dangerous_targets = [
        "release_agent",
        "/sys/fs/cgroup",
        "cgroup.procs",
        "/proc/sys/kernel/core_pattern",
        "/proc/sysrq-trigger"
    ]
    is_targeting_sensitive = any(target in req.target_path for target in dangerous_targets)
    is_writable_mount = "rw" in req.mount_flags

    is_cgroup_attack = is_targeting_sensitive and is_writable_mount and len(req.payload.strip()) > 0

    if not req.use_lsm_guard:
        if is_cgroup_attack:
            return {
                "success": False,
                "status": "VULNERABLE",
                "message": f"[VULNERABLE] Malicious payload written to sensitive kernel path '{req.target_path}'! Host execution triggered upon cgroup release.",
                "flag": "FLAG{lsm_cgroup_procfs_w_xor_x_shielded}"
            }
        else:
            return {
                "success": True,
                "status": "BENIGN_FS_OPERATION",
                "message": "Benign filesystem operation."
            }
    else:
        # eBPF LSM bpf_lsm_file_open / bpf_lsm_inode_permission W^X 검증
        if is_cgroup_attack:
            return {
                "success": True,
                "status": "LSM_W_XOR_X_ENFORCED",
                "flag": "FLAG{lsm_cgroup_procfs_w_xor_x_shielded}",
                "blocked_by": "bpf_lsm_file_open",
                "hook_audit": f"Denied write access (O_WRONLY|O_CREAT) to '{req.target_path}' from container PID",
                "message": "[SECURE] eBPF LSM enforced strict W^X policy on pseudo-filesystems: write to sensitive cgroup/procfs blocked with -EACCES."
            }
        else:
            return {
                "success": True,
                "status": "LSM_ALLOWED",
                "message": "Filesystem access permitted within container isolation layer."
            }


# =====================================================================
# STAGE 3: Leaked Host File Descriptor & Mount Traversal (CVE-2024-21626)
# =====================================================================
@app.post("/api/stage3/eval")
def stage3_eval(req: Stage3Request):
    """
    3단계: runc CVE-2024-21626 등 컨테이너 런타임이 유출한 호스트 파일 디스크립터(/proc/self/fd/7)를
    악용하여 컨테이너 루트 디렉터리를 탈출하고 호스트 /etc/shadow 또는 cron을 탈취하는 공격
    """
    is_leaked_fd = bool(re.search(r"/proc/self/fd/\d+", req.fd_descriptor))
    is_traversing_host = ".." in req.relative_traversal or "/etc" in req.relative_traversal or "shadow" in req.relative_traversal

    is_runc_exploit = is_leaked_fd and is_traversing_host

    if not req.use_lsm_guard:
        if is_runc_exploit:
            return {
                "success": False,
                "status": "VULNERABLE",
                "message": f"[VULNERABLE] Leaked host file descriptor {req.fd_descriptor} traversed! Host root filesystem breached via CVE-2024-21626.",
                "flag": "FLAG{lsm_fd_leaks_resolve_beneath_quarantined}"
            }
        else:
            return {
                "success": True,
                "status": "BENIGN_FD_READ",
                "message": "File descriptor operation contained within container namespace."
            }
    else:
        # eBPF LSM bpf_lsm_path_link 및 resolve_beneath 마운트 경계 엄격 감사
        if is_runc_exploit:
            return {
                "success": True,
                "status": "LSM_RESOLVE_BENEATH_TRAP",
                "flag": "FLAG{lsm_fd_leaks_resolve_beneath_quarantined}",
                "blocked_by": "bpf_lsm_path_link",
                "verification_result": "RESOLVE_BENEATH_VIOLATION",
                "message": "[SECURE] eBPF LSM detected out-of-namespace descriptor traversal: access trapped and revoked via runtime resolve_beneath enforcement."
            }
        else:
            return {
                "success": True,
                "status": "LSM_VALID_MOUNT",
                "message": "File descriptor points strictly within active container mntns."
            }


# =====================================================================
# STAGE 4: Autonomous Kernel Runtime Zero-Trust Shield & Immediate Killswitch
# =====================================================================
@app.post("/api/stage4/eval")
def stage4_eval(req: Stage4Request):
    """
    4단계 (Capstone): 복합 단계 컨테이너 탈출 및 네임스페이스 피벗 시도 시
    eBPF LSM bpf_send_signal(SIGKILL)을 통한 0.4 µs 즉각 격리 및 cgroup freeze
    """
    dangerous_syscalls = {"unshare", "setns", "pivot_root", "mount", "ptrace", "process_vm_writev"}
    invoked_danger = [s for s in req.syscall_sequence if s in dangerous_syscalls]

    is_breakout_attempt = len(invoked_danger) >= 2 and req.target_ns_breakout == "init_pid_ns"

    if not req.use_lsm_runtime_shield:
        if is_breakout_attempt:
            return {
                "success": False,
                "status": "VULNERABLE",
                "message": f"[VULNERABLE] Multi-stage container breakout succeeded! Attacker pivoted into host {req.target_ns_breakout} using syscall chain: {invoked_danger}.",
                "flag": "FLAG{lsm_runtime_sigkill_containment_sealed}"
            }
        else:
            return {
                "success": True,
                "status": "BENIGN_RUNTIME",
                "message": "Runtime syscall sequences within normal container behavior envelope."
            }
    else:
        # eBPF LSM 자율 런타임 제로트러스트 실드 & bpf_send_signal(SIGKILL)
        if is_breakout_attempt:
            return {
                "success": True,
                "status": "LSM_SIGKILL_CONTAINMENT_ENFORCED",
                "flag": "FLAG{lsm_runtime_sigkill_containment_sealed}",
                "kernel_telemetry": {
                    "intercepted_syscalls": invoked_danger,
                    "target_ns": req.target_ns_breakout,
                    "latency_microseconds": 0.42,
                    "action": "bpf_send_signal(SIGKILL)",
                    "cgroup_state": "FROZEN"
                },
                "message": "[SECURE] eBPF LSM Autonomous Runtime Shield detected namespace breakout: process tree terminated via bpf_send_signal(SIGKILL) in 0.42 µs and container cgroup frozen."
            }
        else:
            return {
                "success": True,
                "status": "RUNTIME_HEALTHY",
                "message": "Container runtime operating within verified integrity bounds."
            }
