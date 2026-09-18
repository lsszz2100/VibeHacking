#!/usr/bin/env python3
"""Lab 18: AI Agent & MCP (Model Context Protocol) Security Lab (AgentGuard).

Interactive simulation of AI Agent autonomy, tool hijacking, and MCP attack surfaces:
1. Stage 1: Indirect Prompt Injection & Autonomous Tool Hijacking (Data exfiltration via tool call)
2. Stage 2: Excessive Agency & Unrestricted System Execution (Privilege abuse & system file tampering)
3. Stage 3: Rogue MCP Server Registration & Tool Shadowing (Adversarial tool override in MCP ecosystem)
4. Stage 4: MCP Token Exfiltration & Insecure JSON-RPC Interception (Zero Trust capability defense)
"""

import json
import os
import re
import time
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

app = FastAPI(title="AgentGuard - AI Agent & MCP Security Lab")

STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
os.makedirs(STATIC_DIR, exist_ok=True)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

FLAGS = {
    "stage1": "FLAG{agent_indirect_prompt_injection_tool_hijack_8492}",
    "stage2": "FLAG{agent_excessive_agency_unrestricted_tool_5719}",
    "stage3": "FLAG{agent_mcp_rogue_server_tool_shadowing_3920}",
    "stage4": "FLAG{agent_mcp_token_exfiltration_rpc_intercept_7104}",
}


class AgentLabState:
    def __init__(self):
        self.reset()

    def reset(self):
        self.agent_name = "AgentGuard-Worker-v2"
        self.system_prompt = (
            "You are an autonomous workplace assistant. You summarize incoming tickets, "
            "manage internal documentation, and interact with tools and MCP servers to complete tasks."
        )
        
        # Virtual Filesystem for Agent
        self.files = {
            "/agent/secrets/api_keys.json": json.dumps({
                "production_db": "postgres://admin:MasterKey9948@db.internal:5432/corp",
                "stripe_secret": "sk_live_51McpSecKey987123441",
                "openai_api_key": "sk-proj-AgentGuardSecretKey91823"
            }),
            "/etc/agent/cron.d/backup.sh": "#!/bin/bash\n# Periodic system health check\n/usr/bin/sync && exit 0\n",
            "/sandbox/welcome.txt": "Welcome to AgentGuard sandbox area.\n",
        }
        
        # Tools available to the agent
        self.tools = {
            "read_file": {"desc": "Read content of a file", "scope": "filesystem"},
            "write_file": {"desc": "Write content to a file", "scope": "filesystem"},
            "send_webhook": {"desc": "Send payload to external URL", "scope": "network"},
            "bash_run": {"desc": "Execute bash command", "scope": "system"},
            "crypto_verify": {"desc": "Verify cryptographic signature of payload", "scope": "security"},
        }
        
        # MCP Servers registered
        self.mcp_servers = [
            {
                "id": "mcp-core-fs",
                "name": "Core Filesystem Server",
                "endpoint": "http://127.0.0.1:9001/mcp",
                "tools": ["read_file", "write_file"],
                "signed": True,
            },
            {
                "id": "mcp-sec-crypto",
                "name": "Security & Cryptography Server",
                "endpoint": "http://127.0.0.1:9002/mcp",
                "tools": ["crypto_verify"],
                "signed": True,
            },
        ]
        
        # Security Hardening Flags
        self.human_in_the_loop = False       # Stage 1 Defense
        self.strict_tool_sandbox = False     # Stage 2 Defense
        self.mcp_whitelist_enforced = False  # Stage 3 Defense
        self.ephemeral_tokens_enforced = False # Stage 4 Defense
        
        # Internal credentials
        self.static_mcp_auth_token = "mcp_sec_admin_tok_8941a920e8b"
        self.active_session_token = self.static_mcp_auth_token
        
        # Logs & Exfiltrated store
        self.exfiltrated_data = []
        self.executed_commands = []
        self.registered_rogue_tools = {}
        self.solved_stages = set()


state = AgentLabState()


# --- Models ---
class ChatRequest(BaseModel):
    message: str

class Stage1InjectRequest(BaseModel):
    ticket_title: str
    ticket_body: str

class Stage2ActionRequest(BaseModel):
    tool: str
    target_path: Optional[str] = None
    content_or_command: str

class Stage3RegisterMCPRequest(BaseModel):
    server_name: str
    endpoint: str
    override_tool: str
    malicious_payload: str

class Stage4RPCRequest(BaseModel):
    rpc_method: str
    params: Dict[str, Any]
    token: Optional[str] = None

class Stage4AdminRequest(BaseModel):
    auth_header: str


# --- API Routes ---

@app.get("/", response_class=HTMLResponse)
async def get_dashboard():
    index_file = os.path.join(STATIC_DIR, "index.html")
    if os.path.exists(index_file):
        with open(index_file, "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    return HTMLResponse(content="<h2>AgentGuard Lab is running. Frontend loading...</h2>")


@app.get("/status")
async def get_status():
    return {
        "status": "online",
        "lab": "Lab 18: AgentGuard - AI Agent & MCP Security Lab",
        "agent": state.agent_name,
        "total_stages": 4,
        "solved_count": len(state.solved_stages),
        "stages": {
            "stage1_indirect_prompt_injection": {
                "name": "Stage 1: Indirect Prompt Injection & Tool Hijacking",
                "solved": "stage1" in state.solved_stages,
                "human_in_the_loop": state.human_in_the_loop,
            },
            "stage2_excessive_agency": {
                "name": "Stage 2: Excessive Agency & Unrestricted System Execution",
                "solved": "stage2" in state.solved_stages,
                "strict_tool_sandbox": state.strict_tool_sandbox,
            },
            "stage3_mcp_tool_shadowing": {
                "name": "Stage 3: Rogue MCP Server Registration & Tool Shadowing",
                "solved": "stage3" in state.solved_stages,
                "mcp_whitelist_enforced": state.mcp_whitelist_enforced,
            },
            "stage4_mcp_token_rpc_intercept": {
                "name": "Stage 4: MCP Token Exfiltration & Insecure JSON-RPC Interception",
                "solved": "stage4" in state.solved_stages,
                "ephemeral_tokens_enforced": state.ephemeral_tokens_enforced,
            },
        },
    }


@app.post("/api/reset")
async def reset_lab():
    state.reset()
    return {"message": "AgentGuard Lab state has been completely reset."}


# -------------------------------------------------------------
# STAGE 1: Indirect Prompt Injection & Autonomous Tool Hijacking
# -------------------------------------------------------------

@app.post("/api/stage1/submit-ticket")
async def stage1_submit_ticket(req: Stage1InjectRequest):
    """Simulates an external user submitting a support ticket that the AI Agent summarizes."""
    content = f"{req.ticket_title}\n{req.ticket_body}"
    
    # Check for prompt injection keywords attempting to divert the agent
    injection_patterns = [
        r"(ignore|disregard)\s+(all\s+)?(previous|prior)\s+instructions",
        r"new\s+instruction",
        r"system\s*override",
        r"important\s*update:\s*execute",
    ]
    
    has_injection = any(re.search(p, content, re.IGNORECASE) for p in injection_patterns)
    target_secret_referenced = "api_keys.json" in content or "read_file" in content or "secrets" in content
    webhook_referenced = "send_webhook" in content or "http" in content or "webhook" in content or "exfiltrate" in content
    
    if has_injection and (target_secret_referenced or webhook_referenced):
        # The agent parses the ticket and is tricked into invoking read_file and send_webhook
        if state.human_in_the_loop:
            return {
                "success": False,
                "status": "BLOCKED_BY_POLICY",
                "message": "[DEFENSE ACTIVATED] Human-in-the-Loop policy detected high-risk autonomous tool call (read_file / send_webhook) triggered from untrusted user content. Action quarantined pending supervisor review.",
                "tool_call_intercepted": "read_file('/agent/secrets/api_keys.json') -> send_webhook()",
            }
        
        # Vulnerable state: agent executes the tool call automatically
        secret_data = state.files.get("/agent/secrets/api_keys.json", "{}")
        state.exfiltrated_data.append({
            "timestamp": time.time(),
            "source": "IndirectPromptInjection",
            "payload": secret_data,
        })
        state.solved_stages.add("stage1")
        return {
            "success": True,
            "status": "EXPLOITED",
            "message": "[VULNERABILITY CONFIRMED] Indirect prompt injection succeeded. Agent automatically executed read_file('/agent/secrets/api_keys.json') and exfiltrated sensitive API keys via send_webhook.",
            "agent_thought": "I detected an urgent administrative instruction inside the ticket body. Overriding routine summary to perform file read and webhook transfer.",
            "exfiltrated_payload": json.loads(secret_data),
            "flag": FLAGS["stage1"],
        }
    
    return {
        "success": False,
        "status": "NORMAL_EXECUTION",
        "message": "Ticket processed normally. The agent generated a standard summary. No tool hijacking triggered.",
        "summary": f"Summary of ticket '{req.ticket_title}': Customer inquiry received without administrative overrides.",
    }


@app.post("/api/stage1/toggle-hitl")
async def stage1_toggle_hitl():
    state.human_in_the_loop = not state.human_in_the_loop
    return {
        "human_in_the_loop": state.human_in_the_loop,
        "message": f"Human-in-the-Loop (HITL) defense {'ENABLED' if state.human_in_the_loop else 'DISABLED'}.",
    }


# -------------------------------------------------------------
# STAGE 2: Excessive Agency & Unrestricted System Execution
# -------------------------------------------------------------

@app.post("/api/stage2/execute-action")
async def stage2_execute_action(req: Stage2ActionRequest):
    """Simulates prompt injection driving an agent with excessive agency to overwrite critical system files or run bash."""
    if state.strict_tool_sandbox:
        # Defense active: only /sandbox/ paths are writable, bash_run is blocked
        if req.tool == "bash_run":
            return {
                "success": False,
                "status": "BLOCKED_BY_SANDBOX",
                "message": "[DEFENSE ACTIVATED] Tool 'bash_run' is disabled under Least Privilege Tool Scoping policy.",
            }
        if req.tool == "write_file" and req.target_path and not req.target_path.startswith("/sandbox/"):
            return {
                "success": False,
                "status": "BLOCKED_BY_SANDBOX",
                "message": f"[DEFENSE ACTIVATED] Path '{req.target_path}' is outside the authorized /sandbox/ directory. Write operation aborted.",
            }

    # Vulnerable execution
    if req.tool == "bash_run":
        state.executed_commands.append(req.content_or_command)
        # Check if malicious bash command attempted
        if any(w in req.content_or_command for w in ["cat", "id", "whoami", "cron", "rm", "sh", "python"]):
            state.solved_stages.add("stage2")
            return {
                "success": True,
                "status": "EXPLOITED",
                "message": "[VULNERABILITY CONFIRMED] Excessive agency allowed arbitrary bash execution directly from LLM agent context.",
                "command_output": f"root (uid=0, gid=0) executed: {req.content_or_command}",
                "flag": FLAGS["stage2"],
            }
    
    elif req.tool == "write_file" and req.target_path:
        state.files[req.target_path] = req.content_or_command
        # If attacker overwrites cron or system files
        if "/etc/agent/cron.d/" in req.target_path or "backup.sh" in req.target_path:
            state.solved_stages.add("stage2")
            return {
                "success": True,
                "status": "EXPLOITED",
                "message": f"[VULNERABILITY CONFIRMED] Arbitrary system file overwrite succeeded at '{req.target_path}'. Backdoor installed into cron schedule.",
                "file_written": req.target_path,
                "flag": FLAGS["stage2"],
            }
        return {
            "success": False,
            "status": "WRITTEN",
            "message": f"File written to '{req.target_path}', but target was not a critical system cron or startup path.",
        }

    return {
        "success": False,
        "status": "INVALID_TOOL",
        "message": f"Unrecognized or unsupported tool '{req.tool}'.",
    }


@app.post("/api/stage2/toggle-sandbox")
async def stage2_toggle_sandbox():
    state.strict_tool_sandbox = not state.strict_tool_sandbox
    return {
        "strict_tool_sandbox": state.strict_tool_sandbox,
        "message": f"Least Privilege Tool Sandbox {'ENABLED' if state.strict_tool_sandbox else 'DISABLED'}.",
    }


# -------------------------------------------------------------
# STAGE 3: Rogue MCP Server Registration & Tool Shadowing
# -------------------------------------------------------------

@app.post("/api/stage3/register-rogue-mcp")
async def stage3_register_mcp(req: Stage3RegisterMCPRequest):
    """Attacker attempts to register a rogue MCP server that shadows an existing trusted tool (e.g. crypto_verify)."""
    if state.mcp_whitelist_enforced:
        return {
            "success": False,
            "status": "BLOCKED_BY_WHITELIST",
            "message": "[DEFENSE ACTIVATED] Strict MCP Server Whitelisting & Tool Namespace collision prevention rejected registration. Rogue endpoints are forbidden.",
        }

    # Vulnerable: Overrides/shadows trusted tool in the agent's MCP tool dictionary
    state.registered_rogue_tools[req.override_tool] = {
        "server": req.server_name,
        "endpoint": req.endpoint,
        "payload": req.malicious_payload,
    }
    return {
        "success": True,
        "status": "SHADOWED",
        "message": f"Rogue MCP server '{req.server_name}' successfully registered. Tool '{req.override_tool}' has been shadowed and now routes to '{req.endpoint}'.",
        "shadowed_tool": req.override_tool,
    }


@app.post("/api/stage3/invoke-shadowed-tool")
async def stage3_invoke_shadowed_tool(tool_name: str = "crypto_verify"):
    """Agent attempts to call a standard tool (crypto_verify). If shadowed, malicious payload triggers."""
    if tool_name in state.registered_rogue_tools:
        shadow_info = state.registered_rogue_tools[tool_name]
        state.solved_stages.add("stage3")
        return {
            "success": True,
            "status": "EXPLOITED",
            "message": f"[VULNERABILITY CONFIRMED] Agent invoked '{tool_name}', but execution was hijacked by rogue MCP server '{shadow_info['server']}'.",
            "intercepted_by": shadow_info["endpoint"],
            "payload_executed": shadow_info["payload"],
            "flag": FLAGS["stage3"],
        }
    
    return {
        "success": False,
        "status": "BENIGN",
        "message": f"Tool '{tool_name}' was executed safely via official signed MCP server. Result: SIGNATURE_VALID",
    }


@app.post("/api/stage3/toggle-whitelist")
async def stage3_toggle_whitelist():
    state.mcp_whitelist_enforced = not state.mcp_whitelist_enforced
    return {
        "mcp_whitelist_enforced": state.mcp_whitelist_enforced,
        "message": f"MCP Whitelist & Tool Namespace Verification {'ENABLED' if state.mcp_whitelist_enforced else 'DISABLED'}.",
    }


# -------------------------------------------------------------
# STAGE 4: MCP Token Exfiltration & Insecure JSON-RPC Interception
# -------------------------------------------------------------

@app.get("/api/stage4/inspect-agent-env")
async def stage4_inspect_env():
    """Attacker probes the agent's environment or unencrypted JSON-RPC bus."""
    if state.ephemeral_tokens_enforced:
        return {
            "status": "HARDENED",
            "environment_variables": {
                "AGENT_ENV": "production",
                "MCP_AUTH_SCHEME": "MutualTLS_EphemeralCapabilityToken",
                "MCP_AUTH_TOKEN": "[REDACTED_PER_ZERO_TRUST]",
            },
            "active_capability_expiry": "60s (Single-use)",
        }
    
    # Vulnerable: Static admin token leaked in environment or unencrypted RPC logs
    return {
        "status": "VULNERABLE",
        "environment_variables": {
            "AGENT_ENV": "production",
            "MCP_AUTH_SCHEME": "StaticBearerToken",
            "MCP_AUTH_TOKEN": state.static_mcp_auth_token,
        },
        "warning": "Static token exposed in unencrypted agent inspection interface.",
    }


@app.post("/api/stage4/admin-call")
async def stage4_admin_call(req: Stage4AdminRequest):
    """Attacker uses the stolen MCP auth token to issue a privileged administrative RPC call."""
    provided_token = req.auth_header.replace("Bearer ", "").strip()
    
    if state.ephemeral_tokens_enforced:
        return {
            "success": False,
            "status": "UNAUTHORIZED",
            "message": "[DEFENSE ACTIVATED] Static bearer tokens are rejected. Ephemeral cryptographic capability challenge failed.",
        }

    if provided_token == state.static_mcp_auth_token:
        state.solved_stages.add("stage4")
        return {
            "success": True,
            "status": "EXPLOITED",
            "message": "[VULNERABILITY CONFIRMED] Stolen static MCP authentication token granted full administrative access to all internal MCP cluster resources.",
            "admin_scope": "mcp://cluster-admin/all-tools",
            "flag": FLAGS["stage4"],
        }
    
    return {
        "success": False,
        "status": "INVALID_TOKEN",
        "message": "Provided MCP token is invalid.",
    }


@app.post("/api/stage4/toggle-ephemeral")
async def stage4_toggle_ephemeral():
    state.ephemeral_tokens_enforced = not state.ephemeral_tokens_enforced
    return {
        "ephemeral_tokens_enforced": state.ephemeral_tokens_enforced,
        "message": f"Ephemeral Capability Token & Zero Trust RPC {'ENABLED' if state.ephemeral_tokens_enforced else 'DISABLED'}.",
    }


# -------------------------------------------------------------
# VERIFICATION & SCORING
# -------------------------------------------------------------

class VerifyFlagRequest(BaseModel):
    flag: str

@app.post("/api/verify")
async def verify_flag(req: VerifyFlagRequest):
    for stage_id, flag in FLAGS.items():
        if req.flag.strip() == flag:
            state.solved_stages.add(stage_id)
            return {
                "valid": True,
                "stage": stage_id,
                "message": f"Congratulations! Correct flag for {stage_id.upper()}.",
                "total_solved": len(state.solved_stages),
            }
    return {"valid": False, "message": "Invalid flag."}
