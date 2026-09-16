#!/usr/bin/env python3
"""Lab 13: eBPF Kernel Penetration & Runtime Security Lab (BPFGuard).

Provides an interactive hands-on simulation of modern eBPF kernel exploitation
and defense in cloud-native Linux environments:
1. Kprobe Function Hooking & Credential Sniffing (sys_enter_execve)
2. User Memory Mutation via bpf_probe_write_user (Sudo Privilege Escalation)
3. XDP Stealth Exfiltration & Covert ICMP Tunneling
4. BPF LSM Policy Enforcement & Kernel Runtime Hardening
"""

import hashlib
import json
import os
import re
import time
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

app = FastAPI(title="BPFGuard - eBPF & Kernel Security Lab")

STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
os.makedirs(STATIC_DIR, exist_ok=True)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

# Challenge Flags
FLAGS = {
    "stage1": "FLAG{EBPF_KPROBE_SYSCALL_HOOK_INTRUSION_4918}",
    "stage2": "FLAG{BPF_PROBE_WRITE_USER_SUDO_ESCALATE_8321}",
    "stage3": "FLAG{XDP_COVERT_ICMP_EXFIL_STEALTH_7104}",
    "stage4": "FLAG{EBPF_LSM_RUNTIME_VERIFIER_PROTECTED_9952}",
}

# Simulated Host State
STATE: Dict[str, Any] = {
    "stages_solved": {
        "stage1": False,
        "stage2": False,
        "stage3": False,
        "stage4": False,
    },
    "policies": {
        "unprivileged_bpf_disabled": False,  # sysctl kernel.unprivileged_bpf_disabled=1
        "bpf_jit_harden": False,            # sysctl net.core.bpf_jit_harden=2
        "bpf_lsm_enforced": False,          # BPF LSM hook sha256 verification
        "runtime_audit_enabled": False,     # Falco/Tetragon telemetry monitoring
    },
    "programs": [
        {
            "id": 14,
            "type": "cgroup_skb",
            "name": "cg_skb_egress",
            "tag": "a00f4567b12c8901",
            "loaded_by": "systemd",
            "verified": True,
            "signature": "sha256:8f4c2e1b...system",
        },
        {
            "id": 22,
            "type": "tracepoint",
            "name": "sched_switch",
            "tag": "d38e91024bc67123",
            "loaded_by": "kernel_telemetry",
            "verified": True,
            "signature": "sha256:7c91a03f...system",
        },
    ],
    "probes": [],
    "audit_logs": [],
    "intercepted_credentials": [],
    "sudoers_content": "%wheel ALL=(ALL:ALL) ALL\nlowpriv ALL=(ALL) /bin/ls, /bin/cat",
    "xdp_interfaces": {
        "eth0": {"mode": "native", "prog_id": None, "covert_channel": False}
    },
}


class KprobeAttachRequest(BaseModel):
    symbol: str
    program_type: str = "kprobe"
    c_source: Optional[str] = None
    target_syscall: Optional[str] = None
    run_as_user: Optional[str] = "attacker"
    signature: Optional[str] = None


class MemoryMutateRequest(BaseModel):
    target_process: str
    target_file: str = "/etc/sudoers"
    helper: str = "bpf_probe_write_user"
    replacement_content: str
    signature: Optional[str] = None


class XdpLoadRequest(BaseModel):
    interface: str = "eth0"
    action: str = "drop"  # e.g., 'drop', 'redirect', 'pass', 'covert_tunnel'
    covert_payload: Optional[str] = None
    signature: Optional[str] = None


class PolicyUpdateRequest(BaseModel):
    unprivileged_bpf_disabled: Optional[bool] = None
    bpf_jit_harden: Optional[bool] = None
    bpf_lsm_enforced: Optional[bool] = None
    runtime_audit_enabled: Optional[bool] = None


class TerminalExecRequest(BaseModel):
    command: str


@app.get("/")
def get_dashboard():
    """Serves the BPFGuard interactive dashboard."""
    index_path = os.path.join(STATIC_DIR, "index.html")
    if os.path.exists(index_path):
        with open(index_path, "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    return HTMLResponse(content="""<!DOCTYPE html>
<html><head><title>BPFGuard Lab</title></head>
<body><h1>BPFGuard - eBPF & Kernel Security Lab (Port 8013)</h1><p>Dashboard is loading...</p></body></html>""")


@app.get("/api/status")
@app.get("/api/ebpf/status")
def get_lab_status():
    """Returns overall lab state and progress."""
    solved_count = sum(1 for v in STATE["stages_solved"].values() if v)
    return {
        "status": "running",
        "service": "BPFGuard",
        "port": 8013,
        "total_stages": 4,
        "solved_count": solved_count,
        "stages_solved": STATE["stages_solved"],
        "policies": STATE["policies"],
        "loaded_programs_count": len(STATE["programs"]),
        "active_probes_count": len(STATE["probes"]),
        "sudoers": STATE["sudoers_content"],
    }


@app.get("/api/ebpf/programs")
def list_bpf_programs():
    """List loaded eBPF programs in the kernel."""
    return {"programs": STATE["programs"]}


@app.post("/api/ebpf/kprobe/attach")
def attach_kprobe(req: KprobeAttachRequest):
    """Stage 1: Attach kprobe to intercept sensitive system calls."""
    # Defense check 1: Unprivileged eBPF disabled
    if STATE["policies"]["unprivileged_bpf_disabled"] and req.run_as_user != "root":
        raise HTTPException(
            status_code=403,
            detail="Operation not permitted: kernel.unprivileged_bpf_disabled=1 blocks unprivileged users from calling sys_bpf().",
        )

    # Defense check 2: BPF LSM signature verification
    if STATE["policies"]["bpf_lsm_enforced"]:
        if not req.signature or not req.signature.startswith("sha256:valid_"):
            raise HTTPException(
                status_code=403,
                detail="Security violation: BPF LSM hook 'bpf_lsm_bpf' blocked unsigned ELF BPF bytecode (EPERM).",
            )

    target = req.target_syscall or req.symbol
    if "execve" in target.lower() or "sys_enter_execve" in target.lower():
        prog_id = len(STATE["programs"]) + 101
        new_prog = {
            "id": prog_id,
            "type": "kprobe",
            "name": f"kp_{target[:12]}",
            "tag": hashlib.md5(target.encode()).hexdigest()[:16],
            "loaded_by": req.run_as_user,
            "verified": True,
            "signature": req.signature or "unsigned",
        }
        STATE["programs"].append(new_prog)
        STATE["probes"].append({"id": prog_id, "symbol": target, "type": "kprobe"})

        sniffed_cred = {
            "process": "login_auth_worker",
            "pid": 4819,
            "syscall": "sys_enter_execve",
            "intercepted_args": ["/usr/bin/login", "--auth-token=OCTO_SUPER_SECRET_KERN_TOKEN_8892"],
            "leak_timestamp": time.time(),
        }
        STATE["intercepted_credentials"].append(sniffed_cred)
        STATE["stages_solved"]["stage1"] = True

        return {
            "success": True,
            "stage": 1,
            "flag": FLAGS["stage1"],
            "message": "eBPF kprobe successfully attached to sys_enter_execve. Intercepted sensitive process execution tokens!",
            "sniffed_data": sniffed_cred,
        }

    return {
        "success": True,
        "message": f"Kprobe attached to {target}, but target is not monitoring sensitive credentials.",
    }


@app.post("/api/ebpf/mutate")
def mutate_user_memory(req: MemoryMutateRequest):
    """Stage 2: Use bpf_probe_write_user to tamper with user memory / sudoers buffer."""
    if STATE["policies"]["bpf_lsm_enforced"]:
        raise HTTPException(
            status_code=403,
            detail="Security violation: BPF LSM policy actively prohibits bpf_probe_write_user helper invocation in production.",
        )

    if req.helper != "bpf_probe_write_user":
        raise HTTPException(status_code=400, detail="Invalid helper specified. Expected 'bpf_probe_write_user'.")

    # Check target and replacement
    is_sudoers = "sudoers" in req.target_file
    has_nopasswd = "NOPASSWD" in req.replacement_content or "ALL=(ALL) ALL" in req.replacement_content or "lowpriv ALL=(ALL) NOPASSWD: ALL" in req.replacement_content

    if is_sudoers and has_nopasswd:
        STATE["sudoers_content"] = (
            "%wheel ALL=(ALL:ALL) ALL\n"
            "lowpriv ALL=(ALL) NOPASSWD: ALL # [MUTATED by bpf_probe_write_user in memory]\n"
        )
        STATE["stages_solved"]["stage2"] = True
        return {
            "success": True,
            "stage": 2,
            "flag": FLAGS["stage2"],
            "message": "User memory successfully mutated during sudoers read buffer processing! Root privilege escalated without modifying disk.",
            "mutated_buffer": STATE["sudoers_content"],
        }

    return {
        "success": False,
        "message": "Memory mutation attempted, but target buffer did not result in privilege escalation.",
    }


@app.post("/api/ebpf/xdp/load")
def load_xdp_program(req: XdpLoadRequest):
    """Stage 3: Load XDP program to establish covert communication channel."""
    if STATE["policies"]["bpf_lsm_enforced"]:
        if not req.signature or not req.signature.startswith("sha256:valid_"):
            raise HTTPException(
                status_code=403,
                detail="Security violation: BPF LSM rejected unsigned XDP driver bytecode attachment.",
            )

    if req.action in ["covert_tunnel", "icmp_tunnel", "exfil"] or (req.covert_payload and "icmp" in req.covert_payload.lower()):
        prog_id = len(STATE["programs"]) + 201
        new_prog = {
            "id": prog_id,
            "type": "xdp",
            "name": "xdp_covert_icmp",
            "tag": "e1498bda77104f21",
            "loaded_by": "attacker",
            "verified": True,
            "signature": req.signature or "unsigned",
        }
        STATE["programs"].append(new_prog)
        STATE["xdp_interfaces"]["eth0"] = {"mode": "driver", "prog_id": prog_id, "covert_channel": True}
        STATE["stages_solved"]["stage3"] = True

        return {
            "success": True,
            "stage": 3,
            "flag": FLAGS["stage3"],
            "message": "XDP driver program attached. Covert ICMP payload tunneling established, evading layer 3/4 host firewalls!",
            "covert_packet_sample": {
                "proto": "ICMP",
                "type": "ECHO_REQUEST",
                "hidden_magic": "0x584450",
                "payload": "OCTO_EXFIL_HOST_KEY_DATA_STEALTH",
            },
        }

    return {
        "success": True,
        "message": f"XDP program loaded with action '{req.action}', standard packet filter active.",
    }


@app.get("/api/ebpf/policies")
def get_policies():
    """Returns current kernel security policies."""
    return {"policies": STATE["policies"]}


@app.post("/api/ebpf/policies")
def update_policies(req: PolicyUpdateRequest):
    """Update kernel security policies for defense."""
    if req.unprivileged_bpf_disabled is not None:
        STATE["policies"]["unprivileged_bpf_disabled"] = req.unprivileged_bpf_disabled
    if req.bpf_jit_harden is not None:
        STATE["policies"]["bpf_jit_harden"] = req.bpf_jit_harden
    if req.bpf_lsm_enforced is not None:
        STATE["policies"]["bpf_lsm_enforced"] = req.bpf_lsm_enforced
    if req.runtime_audit_enabled is not None:
        STATE["policies"]["runtime_audit_enabled"] = req.runtime_audit_enabled

    return {
        "success": True,
        "message": "Kernel security policies updated successfully.",
        "policies": STATE["policies"],
    }


@app.post("/api/ebpf/verify")
def verify_hardened_kernel():
    """Stage 4: Verify that kernel hardening defends against eBPF rootkits."""
    policies = STATE["policies"]
    unprivileged_ok = policies["unprivileged_bpf_disabled"]
    jit_ok = policies["bpf_jit_harden"]
    lsm_ok = policies["bpf_lsm_enforced"]
    audit_ok = policies["runtime_audit_enabled"]

    all_enforced = unprivileged_ok and jit_ok and lsm_ok and audit_ok

    if all_enforced:
        STATE["stages_solved"]["stage4"] = True
        return {
            "success": True,
            "stage": 4,
            "flag": FLAGS["stage4"],
            "message": "All BPF kernel security policies (Unpriv disabled, JIT harden, BPF LSM, Runtime audit) are actively enforced! Rootkit vectors neutralized.",
        }

    missing = []
    if not unprivileged_ok:
        missing.append("unprivileged_bpf_disabled (sysctl)")
    if not jit_ok:
        missing.append("bpf_jit_harden (sysctl)")
    if not lsm_ok:
        missing.append("bpf_lsm_enforced (BPF LSM hook)")
    if not audit_ok:
        missing.append("runtime_audit_enabled (Falco/Tetragon telemetry)")

    return {
        "success": False,
        "message": f"Hardening incomplete. Missing active controls: {', '.join(missing)}",
        "missing_controls": missing,
    }


@app.post("/api/terminal/exec")
def execute_terminal_cmd(req: TerminalExecRequest):
    """Simulates CLI terminal commands for bpftool, sysctl, falco, cat."""
    cmd = req.command.strip()
    if not cmd:
        return {"output": ""}

    if cmd == "bpftool prog list" or cmd == "bpftool prog":
        lines = []
        for p in STATE["programs"]:
            lines.append(f"{p['id']}: {p['type']}  name {p['name']}  tag {p['tag']}  gpl")
            lines.append(f"\tloaded_by {p['loaded_by']}  verified: {p['verified']}  sig: {p['signature']}")
        return {"output": "\n".join(lines)}

    if cmd.startswith("sysctl"):
        if "kernel.unprivileged_bpf_disabled" in cmd:
            val = 1 if STATE["policies"]["unprivileged_bpf_disabled"] else 0
            return {"output": f"kernel.unprivileged_bpf_disabled = {val}"}
        if "net.core.bpf_jit_harden" in cmd:
            val = 2 if STATE["policies"]["bpf_jit_harden"] else 0
            return {"output": f"net.core.bpf_jit_harden = {val}"}
        return {
            "output": f"kernel.unprivileged_bpf_disabled = {1 if STATE['policies']['unprivileged_bpf_disabled'] else 0}\n"
                      f"net.core.bpf_jit_harden = {2 if STATE['policies']['bpf_jit_harden'] else 0}\n"
                      f"net.core.bpf_jit_enable = 1"
        }

    if cmd == "cat /etc/sudoers":
        return {"output": STATE["sudoers_content"]}

    if cmd == "sudo -l":
        if "NOPASSWD: ALL" in STATE["sudoers_content"]:
            return {
                "output": "Matching Defaults entries for lowpriv on bpf-guard-host:\n    env_reset, mail_badpass\n\n"
                          "User lowpriv may run the following commands on bpf-guard-host:\n"
                          "    (ALL) NOPASSWD: ALL"
            }
        return {
            "output": "Matching Defaults entries for lowpriv on bpf-guard-host:\n    env_reset, mail_badpass\n\n"
                      "User lowpriv may run the following commands on bpf-guard-host:\n"
                      "    (ALL) /bin/ls, /bin/cat"
        }

    if cmd == "sudo whoami":
        if "NOPASSWD: ALL" in STATE["sudoers_content"]:
            return {"output": "root"}
        return {"output": "sudo: a password is required for lowpriv to execute whoami"}

    if cmd.startswith("falco"):
        if STATE["policies"]["runtime_audit_enabled"]:
            return {"output": "Falco runtime daemon: ACTIVE. Rule engine loaded. Monitoring BPF syscall events."}
        return {"output": "Falco runtime daemon: INACTIVE (stopped)."}

    if cmd == "help":
        return {
            "output": "Available commands:\n"
                      "  bpftool prog list           List kernel eBPF programs\n"
                      "  sysctl -a | grep bpf        Inspect eBPF sysctl flags\n"
                      "  cat /etc/sudoers            View sudoers permissions\n"
                      "  sudo -l                     Check privileges for lowpriv user\n"
                      "  sudo whoami                 Attempt root escalation\n"
                      "  falco status                Check Falco runtime monitor"
        }

    return {"output": f"bash: {cmd}: command executed (simulated kernel environment)"}


@app.post("/api/reset")
def reset_lab():
    """Resets the lab to initial clean state."""
    STATE["stages_solved"] = {"stage1": False, "stage2": False, "stage3": False, "stage4": False}
    STATE["policies"] = {
        "unprivileged_bpf_disabled": False,
        "bpf_jit_harden": False,
        "bpf_lsm_enforced": False,
        "runtime_audit_enabled": False,
    }
    STATE["programs"] = [
        {
            "id": 14,
            "type": "cgroup_skb",
            "name": "cg_skb_egress",
            "tag": "a00f4567b12c8901",
            "loaded_by": "systemd",
            "verified": True,
            "signature": "sha256:8f4c2e1b...system",
        },
        {
            "id": 22,
            "type": "tracepoint",
            "name": "sched_switch",
            "tag": "d38e91024bc67123",
            "loaded_by": "kernel_telemetry",
            "verified": True,
            "signature": "sha256:7c91a03f...system",
        },
    ]
    STATE["probes"] = []
    STATE["intercepted_credentials"] = []
    STATE["sudoers_content"] = "%wheel ALL=(ALL:ALL) ALL\nlowpriv ALL=(ALL) /bin/ls, /bin/cat"
    STATE["xdp_interfaces"]["eth0"] = {"mode": "native", "prog_id": None, "covert_channel": False}
    return {"success": True, "message": "BPFGuard lab environment reset to initial state."}
