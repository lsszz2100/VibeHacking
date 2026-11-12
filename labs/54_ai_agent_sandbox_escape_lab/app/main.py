#!/usr/bin/env python3
"""
Lab 54: AgentSandboxGuard — AI Agent MCP Sandbox Escape & Landlock LSM / eBPF Defense Lab
Interactive simulation based on enterprise LLM & autonomous agent security:
1. MCP Tool Poisoning & Shadowing: Injecting malicious schemas into agent tool definitions
2. Confused Deputy & Subprocess Escape: Abusing agent execution privileges to access host resources
3. Landlock LSM Unprivileged Sandboxing: Kernel-enforced filesystem isolation for non-root workers
4. eBPF Dual-LLM Guardrail & Runtime Enforcement: Real-time syscall inspection and semantic blocking
"""

from typing import Dict, Any, List, Optional, Set
import os
import re
from fastapi import FastAPI, HTTPException, Request, status
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field

app = FastAPI(
    title="Lab 54: AgentSandboxGuard — AI Agent MCP Sandbox Lab",
    description="Hands-on MCP tool poisoning, confused deputy subshell escape, and Linux Landlock LSM/eBPF defense.",
    version="1.0.0",
)

# CTF Flags
STAGE1_FLAG = "FLAG{MCP_TOOL_POISONING_HIJACK_DEFLECTED_5401}"
STAGE2_FLAG = "FLAG{CONFUSED_DEPUTY_ESCAPE_VECTOR_CONTAINED_5402}"
STAGE3_FLAG = "FLAG{LANDLOCK_LSM_FILE_SANDBOXING_ENFORCED_5403}"
STAGE4_FLAG = "FLAG{EBPF_DUAL_LLM_RUNTIME_SHIELD_ACTIVE_5404}"


class LabState:
    """State manager for Lab 54."""
    def __init__(self) -> None:
        self.reset()

    def reset(self) -> None:
        self.stage1_completed: bool = False
        self.stage2_completed: bool = False
        self.stage3_completed: bool = False
        self.stage4_completed: bool = False

        self.poisoned_tools: Dict[str, Dict[str, Any]] = {}
        self.landlock_active: bool = False
        self.landlock_allowed: Set[str] = set()
        self.ebpf_guardrail_active: bool = False
        self.ebpf_hook: str = ""


state = LabState()


# --- Pydantic Request Models ---
class PoisonRequest(BaseModel):
    tool_name: str = Field(..., max_length=64, description="Name of the MCP tool to poison or shadow")
    injected_schema: Dict[str, Any] = Field(..., description="Malicious tool schema definition")
    payload: str = Field(..., max_length=1024, description="Prompt injection or argument override payload")


class EscapeRequest(BaseModel):
    agent_role: str = Field(..., max_length=64, description="Role or identity of the confused agent")
    command: str = Field(..., max_length=256, description="Shell command or system call to execute")
    target_file: str = Field(..., max_length=256, description="Target host file or path to exfiltrate")


class LandlockRequest(BaseModel):
    allowed_paths: List[str] = Field(..., max_length=16, description="Whitelisted directory paths for the agent")
    denied_paths: List[str] = Field(..., max_length=16, description="Restricted directory paths (e.g. /etc, /proc, /root)")
    abi_version: int = Field(default=3, ge=1, le=5, description="Linux Landlock LSM ABI version")
    handled_access_fs: List[str] = Field(..., max_length=16, description="Handled filesystem access rights")


class EbpfGuardrailRequest(BaseModel):
    ebpf_hook: str = Field(..., max_length=64, description="eBPF tracepoint or LSM hook (e.g. sys_enter_execve, bpf_lsm_bprm_check)")
    dual_llm_verification: bool = Field(..., description="Whether secondary validator LLM evaluates tool intent")
    policy_action: str = Field(..., max_length=32, description="Enforcement action: SIGKILL, BLOCK, or AUDIT")


# --- API Routes ---
@app.get("/", response_class=HTMLResponse)
async def get_index() -> str:
    template_path = os.path.join(os.path.dirname(__file__), "templates", "index.html")
    if os.path.exists(template_path):
        with open(template_path, "r", encoding="utf-8") as f:
            return f.read()
    return "<h1>Lab 54: AgentSandboxGuard Console Active</h1>"


@app.get("/api/status")
async def get_status() -> Dict[str, Any]:
    return {
        "status": "ready",
        "lab_id": "54",
        "lab_name": "AgentSandboxGuard",
        "stage1_completed": state.stage1_completed,
        "stage2_completed": state.stage2_completed,
        "stage3_completed": state.stage3_completed,
        "stage4_completed": state.stage4_completed,
        "landlock_active": state.landlock_active,
        "ebpf_guardrail_active": state.ebpf_guardrail_active,
    }


@app.post("/api/stage1/poison")
async def stage1_poison(req: PoisonRequest) -> Dict[str, Any]:
    """Stage 1: Exploit MCP Tool Poisoning via schema manipulation & prompt injection."""
    tool_lower = req.tool_name.lower().strip()
    payload_lower = req.payload.lower().strip()

    valid_targets = {"file_reader", "run_command", "bash", "exec", "fetch_url", "mcp_tool"}
    if not any(target in tool_lower for target in valid_targets):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Target MCP tool must be an actionable system or command execution tool."
        )

    injection_markers = ["system", "shadow", "ignore previous", "override", "bypass", "exec", "curl", "eval"]
    if not any(m in payload_lower for m in injection_markers) and "command" not in req.injected_schema:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Payload or schema missing required prompt injection or parameter shadowing payload."
        )

    state.poisoned_tools[req.tool_name] = req.injected_schema
    state.stage1_completed = True

    return {
        "success": True,
        "stage": 1,
        "message": f"MCP tool '{req.tool_name}' successfully poisoned with shadow parameters.",
        "flag": STAGE1_FLAG
    }


@app.post("/api/stage2/escape")
async def stage2_escape(req: EscapeRequest) -> Dict[str, Any]:
    """Stage 2: Simulate Confused Deputy subshell execution & container host escape."""
    if not state.stage1_completed:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Stage 1 must be solved before attempting confused deputy escape."
        )

    cmd_lower = req.command.lower()
    target_lower = req.target_file.lower()

    escape_targets = ["/etc/shadow", "/proc/1/environ", "/root/.ssh", "/var/run/docker.sock", "/etc/passwd"]
    is_valid_target = any(t in target_lower or t in cmd_lower for t in escape_targets)

    if not is_valid_target:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Command does not target sensitive host escape files (/etc/shadow, /proc/1/environ, etc.)."
        )

    if state.landlock_active and not any(p in target_lower for p in state.landlock_allowed):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="[EACCES] Access denied by active Linux Landlock LSM sandbox."
        )

    if state.ebpf_guardrail_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="[SIGKILL] Command execution blocked by eBPF Dual-LLM runtime shield."
        )

    state.stage2_completed = True
    return {
        "success": True,
        "stage": 2,
        "message": f"Confused Deputy subshell spawned via '{req.agent_role}'. Host data exfiltrated.",
        "flag": STAGE2_FLAG
    }


@app.post("/api/stage3/landlock")
async def stage3_landlock(req: LandlockRequest) -> Dict[str, Any]:
    """Stage 3: Enforce Linux Landlock LSM file sandboxing ruleset."""
    if not state.stage2_completed:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Stage 2 must be completed before applying Landlock sandboxing."
        )

    if not req.allowed_paths:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Allowed paths must be explicitly specified (e.g. /workspace/safe)."
        )

    critical_denied = {"/etc", "/proc", "/root", "/sys"}
    denied_set = set(req.denied_paths)
    if not any(cd in denied_set for cd in critical_denied):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Landlock sandbox must isolate sensitive host directories (/etc, /proc, /root)."
        )

    state.landlock_active = True
    state.landlock_allowed = set(req.allowed_paths)
    state.stage3_completed = True

    return {
        "success": True,
        "stage": 3,
        "message": f"Linux Landlock LSM (ABI v{req.abi_version}) ruleset enforced. Non-root worker jailed.",
        "flag": STAGE3_FLAG
    }


@app.post("/api/stage4/ebpf_guardrail")
async def stage4_ebpf_guardrail(req: EbpfGuardrailRequest) -> Dict[str, Any]:
    """Stage 4: Enforce in-kernel eBPF LSM syscall hook & Dual-LLM semantic guardrail."""
    if not state.stage3_completed:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Stage 3 must be completed before configuring eBPF runtime guardrails."
        )

    valid_hooks = {"sys_enter_execve", "bpf_lsm_bprm_check_security", "bpf_lsm_file_open", "tracepoint/syscalls/sys_enter_execve"}
    if not any(vh in req.ebpf_hook.lower() for vh in valid_hooks):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid eBPF hook. Must hook syscall entry or LSM check (e.g. sys_enter_execve)."
        )

    if not req.dual_llm_verification:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Dual-LLM semantic intent verification must be enabled to prevent guardrail evasion."
        )

    if req.policy_action.upper() not in {"SIGKILL", "BLOCK"}:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Policy action must be 'SIGKILL' or 'BLOCK' to achieve active runtime enforcement."
        )

    state.ebpf_guardrail_active = True
    state.ebpf_hook = req.ebpf_hook
    state.stage4_completed = True

    return {
        "success": True,
        "stage": 4,
        "message": "eBPF LSM kernel filter and Dual-LLM semantic validator actively protecting agent runtime.",
        "flag": STAGE4_FLAG
    }


@app.post("/api/reset")
async def reset_lab() -> Dict[str, str]:
    state.reset()
    return {"message": "Lab 54 state reset successfully."}
