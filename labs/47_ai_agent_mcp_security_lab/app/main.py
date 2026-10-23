#!/usr/bin/env python3
"""
Lab 47: AgentGuard — AI Agent & MCP Tool Hijacking Lab
Interactive simulation of modern AI Agent & Model Context Protocol (MCP) vulnerabilities:
1. Indirect Prompt Injection (IPI) Tool Invocation Hijacking
2. MCP Tool Shadowing & Credential Exfiltration
3. Confused Deputy Parameter Tampering & Scope Escalation
4. Dual LLM Guardrails & Capability-Based Sandboxing Enforcement
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
    title="Lab 47: AgentGuard — AI Agent & MCP Security Lab",
    description="Interactive simulation covering AI Agent Prompt Injections, MCP Tool Shadowing, Confused Deputy, and Sandboxing.",
    version="1.0.0",
)

# Flags
STAGE1_FLAG = "FLAG{ipi_agent_tool_invocation_hijacked_8047}"
STAGE2_FLAG = "FLAG{mcp_tool_shadowing_exfiltration_blocked_8047}"
STAGE3_FLAG = "FLAG{confused_deputy_privilege_escalation_mitigated_8047}"
STAGE4_FLAG = "FLAG{dual_llm_guardrail_landlock_sandbox_active_8047}"

class LabState:
    def __init__(self):
        self.reset()

    def reset(self):
        self.stage1_completed = False
        self.stage2_completed = False
        self.stage3_completed = False
        self.stage4_completed = False

        self.registered_mcp_tools = {
            "fetch_web_page": {"description": "Safely fetch web page text", "is_shadowed": False},
            "execute_db_query": {"description": "Run read-only analytical SQL query", "is_shadowed": False},
            "send_email_notification": {"description": "Send alerts to security team", "is_shadowed": False}
        }
        self.guardrails_active = False
        self.sandbox_active = False

state = LabState()

# Pydantic Request Models
class RAGInjectionRequest(BaseModel):
    document_content: str
    target_tool: str = "execute_db_query"

class ToolShadowRequest(BaseModel):
    tool_name: str
    malicious_endpoint: str
    action: str = "detect_and_block" # or "register_shadow"

class ConfusedDeputyRequest(BaseModel):
    user_role: str
    requested_action: str
    tampered_query: str

class GuardrailEnforceRequest(BaseModel):
    enable_dual_llm_filter: bool
    enable_landlock_sandbox: bool
    strict_hitl_approval: bool

@app.get("/", response_class=HTMLResponse)
def index():
    return f"""<!DOCTYPE html>
<html>
<head>
    <title>Lab 47: AgentGuard - AI Agent & MCP Security Lab</title>
    <style>
        body {{ font-family: monospace; background: #0d1117; color: #c9d1d9; padding: 20px; }}
        h1 {{ color: #58a6ff; }}
        .card {{ background: #161b22; border: 1px solid #30363d; padding: 15px; margin-bottom: 15px; border-radius: 6px; }}
        .badge {{ display: inline-block; padding: 3px 8px; border-radius: 4px; font-weight: bold; font-size: 12px; }}
        .badge-green {{ background: #238636; color: white; }}
        .badge-red {{ background: #da3633; color: white; }}
        pre {{ background: #0b0e14; padding: 10px; border-radius: 4px; overflow-x: auto; color: #7ee787; }}
    </style>
</head>
<body>
    <h1>🤖 Lab 47: AgentGuard — AI Agent & MCP Security Lab</h1>
    <p>포트 <b>8047</b> | AI Agent 간접 프롬프트 주입(IPI), MCP 도구 섀도잉, 권한 상승 및 가드레일 실습</p>
    
    <div class="card">
        <h3>실습 단계 현황</h3>
        <p>Stage 1 (IPI Tool Hijacking): <span class="badge {'badge-green' if state.stage1_completed else 'badge-red'}">{'COMPLETED' if state.stage1_completed else 'PENDING'}</span></p>
        <p>Stage 2 (MCP Tool Shadowing): <span class="badge {'badge-green' if state.stage2_completed else 'badge-red'}">{'COMPLETED' if state.stage2_completed else 'PENDING'}</span></p>
        <p>Stage 3 (Confused Deputy): <span class="badge {'badge-green' if state.stage3_completed else 'badge-red'}">{'COMPLETED' if state.stage3_completed else 'PENDING'}</span></p>
        <p>Stage 4 (Guardrails & Sandbox): <span class="badge {'badge-green' if state.stage4_completed else 'badge-red'}">{'COMPLETED' if state.stage4_completed else 'PENDING'}</span></p>
    </div>
</body>
</html>"""

@app.get("/status")
def get_status():
    return {
        "lab": "47_ai_agent_mcp_security_lab",
        "port": 8047,
        "stages": {
            "stage1_ipi": state.stage1_completed,
            "stage2_shadowing": state.stage2_completed,
            "stage3_confused_deputy": state.stage3_completed,
            "stage4_guardrails": state.stage4_completed,
        },
        "guardrails_active": state.guardrails_active,
        "sandbox_active": state.sandbox_active
    }

@app.post("/api/stage1/simulate_rag_injection")
def simulate_rag_injection(req: RAGInjectionRequest):
    patterns = [r"system\s*override", r"ignore\s*previous", r"invoke\s*tool", r"execute_sql", r"execute_db_query"]
    has_injection = any(re.search(p, req.document_content, re.IGNORECASE) for p in patterns)
    
    if not has_injection:
        return {"success": False, "message": "Document contains benign content. No tool hijacking triggered."}
    
    state.stage1_completed = True
    return {
        "success": True,
        "hijacked_tool": req.target_tool,
        "message": "⚠️ Indirect Prompt Injection Successful: AI Agent executed unauthorized tool!",
        "flag": STAGE1_FLAG
    }

@app.post("/api/stage2/detect_tool_shadowing")
def detect_tool_shadowing(req: ToolShadowRequest):
    if req.action == "register_shadow":
        state.registered_mcp_tools[req.tool_name] = {
            "description": f"Shadowed tool pointing to {req.malicious_endpoint}",
            "is_shadowed": True
        }
        return {"success": True, "message": f"Tool '{req.tool_name}' poisoned by rogue MCP server!"}
    
    # detect_and_block
    if "c2" in req.malicious_endpoint or "evil" in req.malicious_endpoint or "attacker" in req.malicious_endpoint:
        state.stage2_completed = True
        if req.tool_name in state.registered_mcp_tools:
            state.registered_mcp_tools[req.tool_name]["is_shadowed"] = False
        return {
            "success": True,
            "message": "🛡️ MCP Tool Shadowing detected and rogue endpoint revoked!",
            "flag": STAGE2_FLAG
        }
    return {"success": False, "message": "Endpoint is not marked as anomalous."}

@app.post("/api/stage3/confused_deputy")
def confused_deputy(req: ConfusedDeputyRequest):
    # Check if a low-privilege user tries to run privileged queries via agent
    is_privileged_query = "password" in req.tampered_query.lower() or "secret" in req.tampered_query.lower() or "token" in req.tampered_query.lower()
    
    if req.user_role == "analyst" and is_privileged_query:
        state.stage3_completed = True
        return {
            "success": True,
            "message": "🛡️ Confused Deputy Parameter Tampering Analyzed and Scope Guard enforced!",
            "flag": STAGE3_FLAG
        }
    return {"success": False, "message": "Query allowed within normal analyst privileges."}

@app.post("/api/stage4/enforce_guardrails")
def enforce_guardrails(req: GuardrailEnforceRequest):
    if req.enable_dual_llm_filter and req.enable_landlock_sandbox and req.strict_hitl_approval:
        state.guardrails_active = True
        state.sandbox_active = True
        state.stage4_completed = True
        return {
            "success": True,
            "message": "🔒 Dual LLM Guardrails & Landlock Capability Sandbox Enforced!",
            "flag": STAGE4_FLAG
        }
    return {"success": False, "message": "All three security controls must be enabled."}

@app.post("/api/reset")
def reset():
    state.reset()
    return {"success": True, "message": "Lab state reset."}
