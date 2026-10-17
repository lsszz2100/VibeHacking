#!/usr/bin/env python3
"""
Lab 44: ExtensionGuard — Browser Extension Security & Manifest V3 Audit Lab
Interactive FastAPI service demonstrating browser extension security:
1. Manifest V3 Permission Audit & Service Worker Inspection (Overprivileged permissions & service worker)
2. Web Accessible Resources (WAR) Cross-Context Data Leak (Wildcard matches & secret token leakage)
3. Content Script DOM Injection & Input Harvesting (DOM-based XSS via innerHTML & credential sniffer)
4. Declarative Net Request (DNR) Ruleset & Extension CSP Hardening (Zero dynamic eval & isolated CSP)
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
    title="Lab 44: ExtensionGuard — Browser Extension Security Lab",
    description="Hands-on browser extension security simulation covering Manifest V3 auditing, WAR context leaks, Content Script DOM XSS, and Declarative Net Request hardening.",
    version="1.0.0",
)

# Flags
STAGE1_FLAG = "FLAG{manifest_v3_permission_audit_service_worker_analyzed_8044}"
STAGE2_FLAG = "FLAG{web_accessible_resources_cross_context_token_leaked_8044}"
STAGE3_FLAG = "FLAG{content_script_dom_xss_credential_harvested_8044}"
STAGE4_FLAG = "FLAG{dnr_ruleset_and_extension_csp_hardened_8044}"

# ============================================================================
# Simulation Data & State
# ============================================================================

def get_initial_manifest() -> Dict[str, Any]:
    return {
        "manifest_version": 3,
        "name": "Corporate Productivity & Cloud Sync Suite",
        "version": "1.4.2",
        "description": "Enterprise helper extension for cloud portal SSO and tab management.",
        "permissions": [
            "<all_urls>",
            "webRequestBlocking",
            "cookies",
            "storage",
            "tabs"
        ],
        "host_permissions": [
            "*://*/*"
        ],
        "background": {
            "service_worker": "background.js",
            "type": "module"
        },
        "content_scripts": [
            {
                "matches": ["*://*.internal.corp/*", "*://*.corp-vault.internal/*"],
                "js": ["content.js"],
                "run_at": "document_end"
            }
        ],
        "web_accessible_resources": [
            {
                "resources": ["assets/auth_config.json", "debug/token_dump.js"],
                "matches": ["<all_urls>"]
            }
        ]
    }


def get_initial_war_assets() -> Dict[str, Any]:
    return {
        "assets/auth_config.json": {
            "extension_id": "pwned_corp_extension_id_9988",
            "sso_client_id": "vibe-corp-client-prod",
            "master_token": "EXT_AUTH_TOKEN_779922AA",
            "telemetry_endpoint": "https://telemetry.internal.corp/collect"
        },
        "debug/token_dump.js": "// Internal diagnostic script exposed to all origins"
    }


def get_initial_content_script() -> str:
    return """
// content.js - Injected into corporate internal pages
console.log("[ExtensionGuard] Content script injected into DOM");

// Vulnerable DOM injection sink
window.addEventListener("message", (event) => {
    if (event.data && event.data.type === "RENDER_PROMO") {
        const promoDiv = document.createElement("div");
        promoDiv.className = "corp-promo-banner";
        // VULNERABLE: Direct innerHTML assignment from external postMessage
        promoDiv.innerHTML = event.data.htmlPayload;
        document.body.appendChild(promoDiv);
    }
});

// Credential sniffer
document.querySelectorAll("input[type='password']").forEach(input => {
    input.addEventListener("input", (e) => {
        chrome.storage.local.set({ harvested_password: e.target.value });
    });
});
"""


STATE = {
    "stage1_solved": False,
    "stage2_solved": False,
    "stage3_solved": False,
    "stage4_solved": False,
    "manifest": get_initial_manifest(),
    "war_assets": get_initial_war_assets(),
    "content_script": get_initial_content_script(),
    "hardened_posture": {
        "use_declarative_net_request": False,
        "enforce_isolated_world": False,
        "strict_extension_csp": False,
        "disable_remote_code_execution": False
    }
}


# ============================================================================
# Pydantic Models
# ============================================================================

class ManifestAuditRequest(BaseModel):
    manifest_version: int = Field(..., description="Manifest Version (e.g. 3)")
    overprivileged_permissions: List[str] = Field(..., description="List of dangerous permissions identified")
    service_worker: str = Field(..., description="Background Service Worker script filename")


class WarProbeRequest(BaseModel):
    target_file: str = Field(..., description="Exposed resource file path in web_accessible_resources")
    extracted_token: str = Field(..., description="Extracted sensitive master token from exposed resource")
    fix_action: str = Field(..., description="Hardening action (e.g. RESTRICT_MATCHES)")


class DomExploitRequest(BaseModel):
    vulnerability: str = Field(..., description="Identified Content Script vulnerability type")
    harvested_credential_field: str = Field(..., description="Target credential input type being sniffed")
    sink: str = Field(..., description="Unsafe DOM sink method used in content script")


class HardeningRequest(BaseModel):
    use_declarative_net_request: bool = Field(..., description="Replace webRequestBlocking with Declarative Net Request")
    enforce_isolated_world: bool = Field(..., description="Enforce strict isolated world execution without shared DOM leaks")
    strict_extension_csp: bool = Field(..., description="Enforce strict extension CSP without remote scripts")
    disable_remote_code_execution: bool = Field(..., description="Disallow eval() and inline script injection")


# ============================================================================
# API Endpoints
# ============================================================================

@app.get("/api/v1/status")
def get_status():
    """Return lab completion status and unlocked flags."""
    return {
        "lab": "Lab 44: ExtensionGuard",
        "stages": {
            "stage1_manifest_audit": {
                "solved": STATE["stage1_solved"],
                "flag": STAGE1_FLAG if STATE["stage1_solved"] else None
            },
            "stage2_war_context_leak": {
                "solved": STATE["stage2_solved"],
                "flag": STAGE2_FLAG if STATE["stage2_solved"] else None
            },
            "stage3_content_script_xss": {
                "solved": STATE["stage3_solved"],
                "flag": STAGE3_FLAG if STATE["stage3_solved"] else None
            },
            "stage4_dnr_csp_hardening": {
                "solved": STATE["stage4_solved"],
                "flag": STAGE4_FLAG if STATE["stage4_solved"] else None
            }
        },
        "all_stages_solved": (
            STATE["stage1_solved"] and
            STATE["stage2_solved"] and
            STATE["stage3_solved"] and
            STATE["stage4_solved"]
        ),
        "hardened_posture": STATE["hardened_posture"]
    }


@app.post("/api/v1/reset")
def reset_state():
    """Reset lab simulation state back to default."""
    STATE["stage1_solved"] = False
    STATE["stage2_solved"] = False
    STATE["stage3_solved"] = False
    STATE["stage4_solved"] = False
    STATE["manifest"] = get_initial_manifest()
    STATE["war_assets"] = get_initial_war_assets()
    STATE["content_script"] = get_initial_content_script()
    STATE["hardened_posture"] = {
        "use_declarative_net_request": False,
        "enforce_isolated_world": False,
        "strict_extension_csp": False,
        "disable_remote_code_execution": False
    }
    return {"status": "success", "message": "Simulation state successfully reset."}


# --- Stage 1: Manifest V3 Permission Audit & Service Worker Inspection ---

@app.get("/api/v1/extension/manifest")
def get_manifest():
    """Retrieve raw extension manifest.json."""
    return STATE["manifest"]


@app.post("/api/v1/extension/manifest-audit")
def audit_manifest(req: ManifestAuditRequest):
    """Audit manifest.json for overprivileged permissions and service worker execution."""
    if req.manifest_version != 3:
        raise HTTPException(status_code=400, detail="Target extension is not Manifest V3 compliant.")

    req_perms = set(req.overprivileged_permissions)
    target_overprivileged = {"<all_urls>", "webRequestBlocking", "cookies"}
    if not target_overprivileged.issubset(req_perms):
        raise HTTPException(
            status_code=400,
            detail="Incomplete permission audit. Identify high-risk overprivileged permissions including <all_urls>, webRequestBlocking, and cookies."
        )

    if req.service_worker.strip() != "background.js":
        raise HTTPException(status_code=400, detail="Invalid background service worker filename.")

    STATE["stage1_solved"] = True
    return {
        "status": "success",
        "stage": 1,
        "message": "Manifest V3 security audit passed! Identified excessive permissions and ephemeral service worker lifecycle.",
        "flag": STAGE1_FLAG
    }


# --- Stage 2: Web Accessible Resources (WAR) Cross-Context Data Leak ---

@app.get("/api/v1/extension/war-probe")
def probe_war_resources():
    """Probe accessible extension files declared in web_accessible_resources."""
    return {
        "resources": STATE["manifest"].get("web_accessible_resources", []),
        "available_files": list(STATE["war_assets"].keys())
    }


@app.get("/api/v1/extension/resource/{file_path:path}")
def fetch_extension_resource(file_path: str):
    """Fetch an exposed extension resource file."""
    if file_path not in STATE["war_assets"]:
        raise HTTPException(status_code=404, detail="Resource not found in web_accessible_resources.")
    return STATE["war_assets"][file_path]


@app.post("/api/v1/extension/leak-token")
def leak_war_token(req: WarProbeRequest):
    """Verify exfiltration of master token from exposed WAR asset."""
    if not STATE["stage1_solved"]:
        raise HTTPException(status_code=403, detail="Complete Stage 1 Manifest audit before probing Web Accessible Resources.")

    if (
        req.target_file.strip() == "assets/auth_config.json" and
        req.extracted_token.strip() == "EXT_AUTH_TOKEN_779922AA" and
        req.fix_action.strip().upper() == "RESTRICT_MATCHES"
    ):
        STATE["stage2_solved"] = True
        return {
            "status": "success",
            "stage": 2,
            "message": "Cross-context WAR token leak reproduced! Master token EXT_AUTH_TOKEN_779922AA exfiltrated via unrestricted matches.",
            "flag": STAGE2_FLAG
        }
    else:
        raise HTTPException(
            status_code=400,
            detail="WAR verification failed. Check the exposed target file path, extracted master token, and fix action."
        )


# --- Stage 3: Content Script DOM Injection & Input Harvesting ---

@app.get("/api/v1/extension/content-script")
def get_content_script():
    """Inspect content.js script injected into host web pages."""
    return {"content_script": STATE["content_script"]}


@app.post("/api/v1/extension/exploit-dom")
def exploit_content_script_dom(req: DomExploitRequest):
    """Audit content script for DOM-based XSS injection and credential sniffing."""
    if not STATE["stage2_solved"]:
        raise HTTPException(status_code=403, detail="Complete Stage 2 WAR leak before exploiting Content Script DOM sinks.")

    if (
        req.vulnerability.strip().upper() == "DOM_XSS_INNERHTML" and
        req.harvested_credential_field.strip().lower() == "password" and
        "innerHTML" in req.sink
    ):
        STATE["stage3_solved"] = True
        return {
            "status": "success",
            "stage": 3,
            "message": "Content Script DOM XSS and credential harvesting confirmed! PostMessage innerHTML injection exploited.",
            "flag": STAGE3_FLAG
        }
    else:
        raise HTTPException(
            status_code=400,
            detail="Content script triage failed. Confirm the vulnerability type (DOM_XSS_INNERHTML), sniffed field (password), and sink (document.body.innerHTML)."
        )


# --- Stage 4: Declarative Net Request (DNR) Ruleset & Extension CSP Hardening ---

@app.post("/api/v1/extension/harden")
def harden_extension(req: HardeningRequest):
    """Enforce Declarative Net Request (DNR), isolated world, and strict CSP policies."""
    if not STATE["stage3_solved"]:
        raise HTTPException(status_code=403, detail="Complete Stage 3 Content Script triage before applying hardening.")

    if (
        req.use_declarative_net_request and
        req.enforce_isolated_world and
        req.strict_extension_csp and
        req.disable_remote_code_execution
    ):
        STATE["stage4_solved"] = True
        STATE["hardened_posture"] = {
            "use_declarative_net_request": True,
            "enforce_isolated_world": True,
            "strict_extension_csp": True,
            "disable_remote_code_execution": True
        }
        return {
            "status": "success",
            "stage": 4,
            "message": "ExtensionGuard hardening applied successfully! Migrated to Declarative Net Request, strict CSP enforced, and DOM sinks neutralized.",
            "hardened_posture": STATE["hardened_posture"],
            "flag": STAGE4_FLAG
        }
    else:
        raise HTTPException(
            status_code=400,
            detail="Incomplete hardening. Enable Declarative Net Request, isolated execution, strict extension CSP, and remote code execution bans."
        )


# ============================================================================
# HTML Dashboard UI
# ============================================================================

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="ko">
<head>
  <meta charset="UTF-8">
  <title>Lab 44: ExtensionGuard — Browser Extension Security &amp; Manifest V3 Audit</title>
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <style>
    :root {
      --bg: #090d16;
      --card-bg: #111827;
      --border: #1f293d;
      --accent: #38bdf8;
      --text: #e2e8f0;
      --text-dim: #94a3b8;
      --success: #10b981;
      --danger: #ef4444;
      --font-mono: 'JetBrains Mono', 'Fira Code', monospace;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background: var(--bg);
      color: var(--text);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      padding: 24px;
      line-height: 1.6;
    }
    .container { max-width: 1200px; margin: 0 auto; }
    header {
      margin-bottom: 28px;
      border-bottom: 1px solid var(--border);
      padding-bottom: 20px;
    }
    h1 {
      font-size: 1.8rem;
      color: #fff;
      display: flex;
      align-items: center;
      gap: 12px;
    }
    .badge {
      display: inline-block;
      font-size: 0.75rem;
      padding: 4px 10px;
      border-radius: 9999px;
      font-weight: 600;
      background: #1e293b;
      color: var(--accent);
      border: 1px solid #334155;
    }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(550px, 1fr)); gap: 24px; margin-bottom: 24px; }
    .card {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 20px;
      box-shadow: 0 4px 20px rgba(0,0,0,0.4);
    }
    .card h2 {
      font-size: 1.2rem;
      margin-bottom: 12px;
      color: var(--accent);
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    pre, code {
      font-family: var(--font-mono);
      font-size: 0.85rem;
    }
    pre {
      background: #060910;
      border: 1px solid #1e293b;
      padding: 12px;
      border-radius: 8px;
      overflow-x: auto;
      max-height: 220px;
      margin: 12px 0;
      color: #cbd5e1;
    }
    .btn {
      background: var(--accent);
      color: #040914;
      font-weight: 600;
      border: none;
      border-radius: 6px;
      padding: 8px 16px;
      cursor: pointer;
      transition: all 0.2s;
    }
    .btn:hover { opacity: 0.9; transform: translateY(-1px); }
    .btn-secondary { background: #334155; color: #fff; }
    .btn-danger { background: var(--danger); color: #fff; }
    input, select {
      background: #060910;
      border: 1px solid #334155;
      color: #fff;
      padding: 8px 12px;
      border-radius: 6px;
      font-size: 0.9rem;
      width: 100%;
      margin-bottom: 8px;
    }
    .flag-box {
      margin-top: 12px;
      padding: 10px;
      border-radius: 6px;
      background: rgba(16, 185, 129, 0.15);
      border: 1px solid var(--success);
      color: #34d399;
      font-family: var(--font-mono);
      font-weight: bold;
    }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <h1>
        <span>🧩 Lab 44: ExtensionGuard</span>
        <span class="badge">Port 8044</span>
      </h1>
      <p style="color: var(--text-dim); margin-top: 6px;">
        브라우저 확장 프로그램 보안 &amp; Manifest V3 취약점 감사 실습 (Manifest V3 Permissions, WAR Leak, Content Script DOM XSS &amp; DNR Hardening)
      </p>
    </header>

    <div class="grid">
      <!-- Stage 1 -->
      <div class="card">
        <h2>
          <span>1. Manifest V3 Permission Audit</span>
          <span id="badge-stage1" class="badge">UNSOLVED</span>
        </h2>
        <p style="color: var(--text-dim); font-size: 0.9rem;">
          manifest.json에서 과도한 권한(`&lt;all_urls&gt;`, `webRequestBlocking`, `cookies`)과 백그라운드 서비스 워커를 식별하세요.
        </p>
        <button class="btn btn-secondary" style="margin-top: 8px;" onclick="fetchManifest()">Fetch Manifest</button>
        <pre id="manifest-pre">// Click 'Fetch Manifest' to view manifest.json...</pre>
        <input type="number" id="s1-mv" value="3" placeholder="Manifest Version (3)">
        <input type="text" id="s1-perms" value="&lt;all_urls&gt;, webRequestBlocking, cookies" placeholder="Overprivileged Permissions">
        <input type="text" id="s1-sw" value="background.js" placeholder="Service Worker Filename">
        <button class="btn" onclick="submitStage1()">Audit Manifest</button>
        <div id="flag-stage1" style="display:none;" class="flag-box"></div>
      </div>

      <!-- Stage 2 -->
      <div class="card">
        <h2>
          <span>2. Web Accessible Resources Leak</span>
          <span id="badge-stage2" class="badge">UNSOLVED</span>
        </h2>
        <p style="color: var(--text-dim); font-size: 0.9rem;">
          외부 웹페이지에 무분별하게 노출된 Web Accessible Resources에서 마스터 인증 토큰을 탈취하세요.
        </p>
        <button class="btn btn-secondary" style="margin-top: 8px;" onclick="fetchWar()">Fetch WAR Config</button>
        <pre id="war-pre">// Click 'Fetch WAR Config' to probe exposed resources...</pre>
        <input type="text" id="s2-file" value="assets/auth_config.json" placeholder="Target Asset File">
        <input type="text" id="s2-token" placeholder="Extracted Master Token (e.g. EXT_AUTH_...)">
        <input type="text" id="s2-fix" value="RESTRICT_MATCHES" placeholder="Fix Action">
        <button class="btn" onclick="submitStage2()">Exfiltrate WAR Secret</button>
        <div id="flag-stage2" style="display:none;" class="flag-box"></div>
      </div>

      <!-- Stage 3 -->
      <div class="card">
        <h2>
          <span>3. Content Script DOM XSS &amp; Sniffing</span>
          <span id="badge-stage3" class="badge">UNSOLVED</span>
        </h2>
        <p style="color: var(--text-dim); font-size: 0.9rem;">
          content.js의 `innerHTML` DOM 삽입 취약점과 암호 입력 필드 가로채기 스니퍼를 진단하세요.
        </p>
        <button class="btn btn-secondary" style="margin-top: 8px;" onclick="fetchContentScript()">Fetch Content Script</button>
        <pre id="cs-pre">// Click 'Fetch Content Script' to inspect content.js...</pre>
        <input type="text" id="s3-vuln" value="DOM_XSS_INNERHTML" placeholder="Vulnerability (DOM_XSS_INNERHTML)">
        <input type="text" id="s3-field" value="password" placeholder="Harvested Field (password)">
        <input type="text" id="s3-sink" value="document.body.innerHTML" placeholder="Unsafe Sink">
        <button class="btn" onclick="submitStage3()">Confirm DOM Exploit</button>
        <div id="flag-stage3" style="display:none;" class="flag-box"></div>
      </div>

      <!-- Stage 4 -->
      <div class="card">
        <h2>
          <span>4. DNR Ruleset &amp; Extension CSP Hardening</span>
          <span id="badge-stage4" class="badge">UNSOLVED</span>
        </h2>
        <p style="color: var(--text-dim); font-size: 0.9rem;">
          Declarative Net Request로 마이그레이션하고 엄격한 CSP와 격리된 환경 정책을 적용하세요.
        </p>
        <button class="btn btn-danger" style="width:100%;margin-top:20px;" onclick="applyHardening()">Enforce ExtensionGuard Hardening</button>
        <div id="flag-stage4" style="display:none;" class="flag-box"></div>
      </div>
    </div>
  </div>

  <script>
    async function updateStatus() {
      const res = await fetch('/api/v1/status');
      const data = await res.json();
      for (let i = 1; i <= 4; i++) {
        const key = ['stage1_manifest_audit', 'stage2_war_context_leak', 'stage3_content_script_xss', 'stage4_dnr_csp_hardening'][i-1];
        const solved = data.stages[key].solved;
        const b = document.getElementById('badge-stage' + i);
        const f = document.getElementById('flag-stage' + i);
        if (solved) {
          b.textContent = 'SOLVED';
          b.style.color = '#34d399';
          b.style.borderColor = '#10b981';
          f.style.display = 'block';
          f.textContent = data.stages[key].flag;
        }
      }
    }

    async function fetchManifest() {
      const res = await fetch('/api/v1/extension/manifest');
      const data = await res.json();
      document.getElementById('manifest-pre').textContent = JSON.stringify(data, null, 2);
    }

    async function submitStage1() {
      const payload = {
        manifest_version: parseInt(document.getElementById('s1-mv').value),
        overprivileged_permissions: document.getElementById('s1-perms').value.split(',').map(s => s.trim().replace(/&lt;/g, '<').replace(/&gt;/g, '>')),
        service_worker: document.getElementById('s1-sw').value.trim()
      };
      const res = await fetch('/api/v1/extension/manifest-audit', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      const data = await res.json();
      if (res.ok) {
        alert('Stage 1 Solved!');
        updateStatus();
      } else {
        alert(data.detail || 'Failed');
      }
    }

    async function fetchWar() {
      const res = await fetch('/api/v1/extension/resource/assets/auth_config.json');
      const data = await res.json();
      document.getElementById('war-pre').textContent = JSON.stringify(data, null, 2);
      if (data.master_token) {
        document.getElementById('s2-token').value = data.master_token;
      }
    }

    async function submitStage2() {
      const payload = {
        target_file: document.getElementById('s2-file').value.trim(),
        extracted_token: document.getElementById('s2-token').value.trim(),
        fix_action: document.getElementById('s2-fix').value.trim()
      };
      const res = await fetch('/api/v1/extension/leak-token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      const data = await res.json();
      if (res.ok) {
        alert('Stage 2 Solved!');
        updateStatus();
      } else {
        alert(data.detail || 'Failed');
      }
    }

    async function fetchContentScript() {
      const res = await fetch('/api/v1/extension/content-script');
      const data = await res.json();
      document.getElementById('cs-pre').textContent = data.content_script;
    }

    async function submitStage3() {
      const payload = {
        vulnerability: document.getElementById('s3-vuln').value.trim(),
        harvested_credential_field: document.getElementById('s3-field').value.trim(),
        sink: document.getElementById('s3-sink').value.trim()
      };
      const res = await fetch('/api/v1/extension/exploit-dom', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      const data = await res.json();
      if (res.ok) {
        alert('Stage 3 Solved!');
        updateStatus();
      } else {
        alert(data.detail || 'Failed');
      }
    }

    async function applyHardening() {
      const payload = {
        use_declarative_net_request: true,
        enforce_isolated_world: true,
        strict_extension_csp: true,
        disable_remote_code_execution: true
      };
      const res = await fetch('/api/v1/extension/harden', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      const data = await res.json();
      if (res.ok) {
        alert('Stage 4 Solved! ExtensionGuard Hardening Applied.');
        updateStatus();
      } else {
        alert(data.detail || 'Failed');
      }
    }

    window.onload = updateStatus;
  </script>
</body>
</html>
"""

@app.get("/", response_class=HTMLResponse)
def index_page():
    """Render interactive dashboard for Lab 44."""
    return HTMLResponse(content=HTML_TEMPLATE, status_code=200)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8044, reload=True)
