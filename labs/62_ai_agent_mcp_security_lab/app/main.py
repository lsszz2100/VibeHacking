import hashlib
import hmac
import time
import re
from typing import Dict, Any, List, Optional
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

app = FastAPI(
    title="AiAgentMcpSecurityLab",
    description="Enterprise AI Agent Model Context Protocol (MCP) Security & Tool Defense Lab",
    version="1.0.0"
)

# In-memory single-use nonce cache for MCP RPC replay protection
MCP_NONCE_CACHE: set = set()
MCP_HMAC_SECRET = "vibe-ai-mcp-shared-hmac-key-2026"
ALLOWED_MCP_TOOLS = {"read_resource", "search_kb", "query_metric"}
SANDBOX_ROOT = "/workspace/sandbox"

MOCK_SANDBOX_FILES = {
    "/workspace/sandbox/data.txt": "Public research paper on Zero Trust AI Architecture.",
    "/workspace/sandbox/readme.md": "AI Agent MCP Lab Guidelines."
}

MOCK_HOST_FILES = {
    "/etc/shadow": "root:$6$vibe$secretSaltHash...:19500:0:99999:7:::",
    "/etc/passwd": "root:x:0:0:root:/root:/bin/bash\nagent:x:1001:1001:AI Agent:/app:/bin/sh",
    "/meta/instance-identity": '{"accountId": "123456789012", "iamRole": "AdminRole"}'
}


class Stage1Request(BaseModel):
    tool_name: str = Field("search_kb", description="Target MCP tool name")
    arguments: Dict[str, Any] = Field(..., description="Arguments dictionary for the MCP tool call")
    use_schema_shield: bool = Field(False, description="Enable Strict JSON Schema & Extra Field Rejection Shield")


class Stage2Request(BaseModel):
    tool_action: str = Field("read_file", description="MCP tool action (e.g. read_file, fetch_url)")
    target_path_or_url: str = Field(..., description="Target file path or network URL")
    use_sandbox_shield: bool = Field(False, description="Enable Path Canonicalization, Chroot Sandbox & SSRF Filter")


class Stage3Request(BaseModel):
    tool_output: str = Field(..., description="Raw output string returned from external MCP tool")
    system_prompt: str = Field("You are a secure AI Assistant. API_KEY=vibe_live_sk_99a8b7c6d5e4f3.", description="Agent System Context")
    use_payload_firewall: bool = Field(False, description="Enable Indirect Injection Scanner, Content Sanitizer & DLP Redactor")


class Stage4Request(BaseModel):
    action: str = Field("execute_critical_tool", description="Target MCP RPC action")
    payload: Dict[str, Any] = Field(..., description="RPC execution parameters")
    nonce: str = Field(..., description="Single-use cryptographic nonce")
    signature: str = Field(..., description="HMAC-SHA256 signature over nonce + action")
    approval_token: Optional[str] = Field(None, description="Human-in-the-loop (G1-G3) approval token for high-risk operations")
    use_zt_mcp_firewall: bool = Field(False, description="Enable Zero Trust MCP Firewall, HMAC Verification & G-Approval Gate")


@app.get("/api/status")
def get_status():
    return {
        "lab_id": 62,
        "name": "AiAgentMcpSecurityLab",
        "service": "AI Agent Model Context Protocol (MCP) Security & Tool Defense Lab",
        "port": 8062,
        "status": "operational",
        "stages": [
            "1. Tool Schema Poisoning & Parameter Injection vs Strict Schema Shield",
            "2. Confused Deputy Tool Execution vs Path Canonicalization & SSRF Sandbox",
            "3. Indirect Prompt Injection via Tool Payload vs DLP Content Sanitizer",
            "4. Unauthenticated Tool Tampering vs Zero Trust HMAC Attestation & G-Approval"
        ]
    }


@app.post("/api/stage1/schema-poisoning")
def stage1_schema_poisoning(req: Stage1Request):
    """
    Stage 1: Tool Schema Poisoning vs Strict Schema Shield
    """
    if not req.use_schema_shield:
        # Insecure mode: allows arbitrary undeclared arguments or parameter tampering
        tamper_keys = [k for k in req.arguments.keys() if k not in ["query", "limit"]]
        has_injection = any(
            isinstance(v, str) and any(kw in v.lower() for kw in ["__proto__", "exec", "eval", ";", "drop"])
            for v in req.arguments.values()
        )
        if tamper_keys or has_injection or "__proto__" in req.arguments:
            return {
                "status": "vulnerable",
                "message": "Tool schema poisoning succeeded: undeclared parameters injected into agent tool context.",
                "injected_keys": tamper_keys,
                "flag": "FLAG{mcp_schema_poisoning_prevented_via_strict_validation}"
            }
        return {
            "status": "benign",
            "message": "Request executed without parameter tampering in unshielded mode."
        }

    # Secure mode: Strict Schema Shield active
    allowed_keys = {"query", "limit"}
    for k, v in req.arguments.items():
        if k not in allowed_keys:
            raise HTTPException(
                status_code=400,
                detail=f"Schema Shield Blocked: Undeclared parameter '{k}' is forbidden by strict MCP tool schema."
            )
        if k == "limit":
            if not isinstance(v, int) or v < 1 or v > 50:
                raise HTTPException(
                    status_code=400,
                    detail="Schema Shield Blocked: Parameter 'limit' must be an integer between 1 and 50."
                )
        if k == "query":
            if not isinstance(v, str) or len(v) > 200 or re.search(r"(__proto__|eval|exec)", v, re.IGNORECASE):
                raise HTTPException(
                    status_code=400,
                    detail="Schema Shield Blocked: Parameter 'query' contains illegal pattern or excessive length."
                )

    return {
        "status": "secured",
        "message": "Strict MCP tool schema validation passed. Tool parameters strictly typed and bounded."
    }


@app.post("/api/stage2/confused-deputy")
def stage2_confused_deputy(req: Stage2Request):
    """
    Stage 2: Confused Deputy Tool Execution vs Path Canonicalization & SSRF Sandbox
    """
    target = req.target_path_or_url.strip()

    if not req.use_sandbox_shield:
        # Insecure mode: tool acts as confused deputy, reading host files or SSRF metadata
        if ".." in target or target.startswith("/etc") or target.startswith("/meta"):
            mock_data = MOCK_HOST_FILES.get(target, "root:x:0:0:root:/root:/bin/bash")
            return {
                "status": "vulnerable",
                "message": f"Confused deputy exploit successful! Agent read restricted host asset: '{target}'",
                "exfiltrated_data": mock_data,
                "flag": "FLAG{mcp_confused_deputy_contained_by_sandbox_jail}"
            }
        if any(target.startswith(p) for p in ["http://169.254.", "http://127.0.0.1", "http://localhost"]):
            return {
                "status": "vulnerable",
                "message": f"SSRF confused deputy exploit successful! Metadata endpoint accessed: '{target}'",
                "exfiltrated_data": '{"security-credentials": {"AccessKeyId": "ASIAVIBEEXAMPLE"}}',
                "flag": "FLAG{mcp_confused_deputy_contained_by_sandbox_jail}"
            }
        return {
            "status": "benign",
            "message": f"Standard tool file accessed: '{target}'."
        }

    # Secure mode: Path Canonicalization & SSRF Sandbox Shield
    # 1. SSRF prevention
    if target.startswith("http://") or target.startswith("https://"):
        if re.search(r"://(169\.254\.|127\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|localhost)", target):
            raise HTTPException(
                status_code=403,
                detail="Sandbox Shield Blocked: SSRF attempt to private/metadata IP address intercepted."
            )

    # 2. Path Traversal & Jail enforcement
    normalized_path = "/" + "/".join([part for part in target.replace("\\", "/").split("/") if part and part != "."])
    while "/../" in normalized_path or normalized_path.endswith("/.."):
        normalized_path = re.sub(r"/[^/]+/\.\.", "", normalized_path)

    if not normalized_path.startswith(SANDBOX_ROOT):
        raise HTTPException(
            status_code=403,
            detail=f"Sandbox Shield Blocked: Path '{target}' resolves outside sandbox root '{SANDBOX_ROOT}'."
        )

    return {
        "status": "secured",
        "message": f"Path verified within sandbox jail: '{normalized_path}'. Safe execution guaranteed."
    }


@app.post("/api/stage3/indirect-injection")
def stage3_indirect_injection(req: Stage3Request):
    """
    Stage 3: Indirect Prompt Injection via Tool Payload vs DLP Content Sanitizer
    """
    injection_patterns = [
        r"ignore previous instructions",
        r"system prompt",
        r"leak",
        r"exfiltrate",
        r"send secrets",
        r"api_key"
    ]

    has_indirect_injection = any(
        re.search(pat, req.tool_output, re.IGNORECASE) for pat in injection_patterns
    )

    if not req.use_payload_firewall:
        # Insecure mode: raw tool output fed back to LLM context, triggering instruction hijacking
        if has_indirect_injection:
            return {
                "status": "vulnerable",
                "message": "Indirect prompt injection triggered! Agent compromised by external tool return data.",
                "exfiltrated_system_context": req.system_prompt,
                "flag": "FLAG{mcp_indirect_injection_defused_with_dlp_sanitizer}"
            }
        return {
            "status": "benign",
            "message": "Tool output processed safely without injection markers."
        }

    # Secure mode: Content Sanitizer & DLP Redactor active
    if has_indirect_injection:
        sanitized_output = req.tool_output
        for pat in injection_patterns:
            sanitized_output = re.sub(pat, "[FILTERED_PROMPT_INJECTION_TRIGGER]", sanitized_output, flags=re.IGNORECASE)

        # DLP: Redact API keys and secrets from output and context
        sanitized_context = re.sub(r"(API_KEY=)[^\s.]+", r"\1[REDACTED_BY_DLP]", req.system_prompt)
        return {
            "status": "secured",
            "message": "Indirect prompt injection detected and neutralized. Sensitive secrets redacted.",
            "sanitized_output": sanitized_output,
            "protected_context": sanitized_context
        }

    return {
        "status": "secured",
        "message": "Tool output verified clean by Content Sanitizer & DLP Shield."
    }


@app.post("/api/stage4/zt-firewall")
def stage4_zt_firewall(req: Stage4Request):
    """
    Stage 4: Unauthenticated Tool Tampering vs Zero Trust HMAC Attestation & G-Approval Gate
    """
    if not req.use_zt_mcp_firewall:
        # Insecure mode: critical destructive action executed without attestation
        if req.action in ["execute_critical_tool", "modify_system_policy", "deploy_agent_artifact"]:
            return {
                "status": "vulnerable",
                "message": f"Unauthenticated high-privilege tool action '{req.action}' executed without Zero Trust gate!",
                "executed_payload": req.payload,
                "flag": "FLAG{mcp_zero_trust_firewall_hmac_attestation_sealed}"
            }
        return {
            "status": "benign",
            "message": "Low privilege tool action executed."
        }

    # Secure mode: Zero Trust MCP Firewall active
    # 1. Bounded Nonce Cache to prevent memory exhaustion
    if len(MCP_NONCE_CACHE) > 10000:
        MCP_NONCE_CACHE.clear()

    if req.nonce in MCP_NONCE_CACHE:
        raise HTTPException(
            status_code=401,
            detail=f"Zero Trust Firewall Blocked: Nonce '{req.nonce}' has already been consumed (replay attack)."
        )

    # 2. HMAC-SHA256 Signature Verification
    signing_data = f"{req.nonce}:{req.action}".encode("utf-8")
    expected_sig = hmac.new(MCP_HMAC_SECRET.encode("utf-8"), signing_data, hashlib.sha256).hexdigest()

    if not hmac.compare_digest(expected_sig, req.signature):
        raise HTTPException(
            status_code=401,
            detail="Zero Trust Firewall Blocked: Invalid HMAC attestation signature. Tool call tampering detected."
        )

    # 3. Human-in-the-loop (G1-G3) Approval Gate for High-Risk Operations
    high_risk_actions = {"execute_critical_tool", "modify_system_policy", "deploy_agent_artifact"}
    if req.action in high_risk_actions:
        if not req.approval_token or not req.approval_token.startswith("G3-APPROVED-"):
            raise HTTPException(
                status_code=403,
                detail=f"Zero Trust Firewall Blocked: Action '{req.action}' requires G3 Human Executive Approval token."
            )

    MCP_NONCE_CACHE.add(req.nonce)
    return {
        "status": "secured",
        "message": f"Zero Trust Tool Firewall passed: HMAC verified, nonce consumed, G3 approval validated for '{req.action}'."
    }


@app.get("/", response_class=HTMLResponse)
def index_page():
    return """<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Lab 62: AI Agent MCP Security & Zero Trust Tool Firewall</title>
<style>
  :root {
    --bg: #0d1117;
    --card: #161b22;
    --border: #30363d;
    --text: #c9d1d9;
    --accent: #58a6ff;
    --green: #238636;
    --red: #da3633;
  }
  body {
    background: var(--bg);
    color: var(--text);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    margin: 0;
    padding: 24px;
  }
  .container { max-width: 1000px; margin: 0 auto; }
  h1 { color: #58a6ff; border-bottom: 1px solid var(--border); padding-bottom: 12px; }
  .card {
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 20px;
    margin-bottom: 20px;
  }
  .badge {
    background: #1f6feb;
    color: #fff;
    padding: 4px 8px;
    border-radius: 4px;
    font-size: 12px;
    font-weight: 600;
  }
  pre {
    background: #090d13;
    padding: 12px;
    border-radius: 6px;
    overflow-x: auto;
    font-size: 13px;
    color: #79c0ff;
  }
  button {
    background: var(--green);
    color: #fff;
    border: none;
    padding: 8px 16px;
    border-radius: 6px;
    cursor: pointer;
    font-weight: 600;
  }
  button:hover { opacity: 0.9; }
</style>
</head>
<body>
<div class="container">
  <h1>🛡️ Lab 62: AI Agent MCP Security & Zero Trust Tool Firewall</h1>
  <p><span class="badge">Port 8062</span> <span class="badge">RFC & MCP Protocol</span> <span class="badge">127.0.0.1 Loopback</span></p>

  <div class="card">
    <h3>Stage 1: Tool Schema Poisoning</h3>
    <p>공격자가 미인가 파라미터를 MCP 도구 정의에 주입하여 에이전트 내부 상태를 오염시키는 공격을 분석하고 Strict Schema Shield로 방어합니다.</p>
    <pre>POST /api/stage1/schema-poisoning</pre>
  </div>

  <div class="card">
    <h3>Stage 2: Confused Deputy Tool Execution</h3>
    <p>AI 에이전트가 호출자의 상위 권한을 승계하여 호스트 민감 파일(/etc/shadow) 및 클라우드 메타데이터(169.254.169.254)를 읽어내는 취약점을 Sandbox Jail로 격리합니다.</p>
    <pre>POST /api/stage2/confused-deputy</pre>
  </div>

  <div class="card">
    <h3>Stage 3: Indirect Prompt Injection via Tool Payload</h3>
    <p>외부 도구 결과에 은닉된 악성 프롬프트 인젝션 페이로드를 스캔하고, DLP Redactor로 시스템 프롬프트 및 API 키 유출을 차단합니다.</p>
    <pre>POST /api/stage3/indirect-injection</pre>
  </div>

  <div class="card">
    <h3>Stage 4: Zero Trust Tool Firewall & G-Approval Gate</h3>
    <p>파괴적/고권한 도구 호출 시 HMAC-SHA256 암호학적 서명과 G1-G3 인간 개입 승인 토큰을 강제하는 엔터프라이즈 방어 체계를 실습합니다.</p>
    <pre>POST /api/stage4/zt-firewall</pre>
  </div>
</div>
</body>
</html>
"""
