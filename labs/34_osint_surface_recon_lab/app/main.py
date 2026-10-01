"""
Lab 34: OSINT Surface Recon & Shadow IT Hunter (OsintHunterLab)
VibeHacking Security Engineering Platform
Port: 8034
"""

import os
from typing import Dict, Any, Optional
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

app = FastAPI(
    title="Lab 34: OSINT Surface Recon Lab",
    description="Automated Internet Attack Surface Reconnaissance & Leaked Secret Extraction",
    version="1.0.0"
)

# Step Flags
STEP1_FLAG = "FLAG{OSINT_SHODAN_EXPOSED_SERVICES_RECON_7712}"
STEP2_FLAG = "FLAG{OSINT_ELASTIC_REDIS_UNAUTH_DUMP_PWNED_8823}"
STEP3_FLAG = "FLAG{OSINT_GIT_LEAKED_SECRET_RECONSTRUCTED_9934}"

# In-Memory State
state = {
    "step1_completed": False,
    "step2_completed": False,
    "step3_completed": False,
    "scanned_queries": [],
    "dumped_targets": [],
    "git_reconstructed": False
}

class ShodanScanRequest(BaseModel):
    query: str

class DatabaseQueryRequest(BaseModel):
    target: str
    command: Optional[str] = "KEYS *"

class GitReconstructRequest(BaseModel):
    target: str
    action: Optional[str] = "log"


@app.get("/health")
def health() -> Dict[str, Any]:
    return {
        "status": "ok",
        "lab": "34_osint_surface_recon_lab",
        "port": 8034,
        "step1_completed": state["step1_completed"],
        "step2_completed": state["step2_completed"],
        "step3_completed": state["step3_completed"],
    }


@app.get("/api/osint/targets")
def get_targets() -> Dict[str, Any]:
    return {
        "organization": "Megacorp Logistics Global",
        "primary_domain": "megacorp-logistics.internal.io",
        "allocated_cidrs": ["198.51.100.0/24", "203.0.113.0/24"],
        "known_asns": ["AS64512"],
        "target_keywords": ["megacorp", "redis", "elastic", "git", "portal"]
    }


@app.get("/api/osint/status")
def get_status() -> Dict[str, Any]:
    return {
        "step1_completed": state["step1_completed"],
        "step2_completed": state["step2_completed"],
        "step3_completed": state["step3_completed"],
        "scanned_queries_count": len(state["scanned_queries"]),
        "dumped_targets_count": len(state["dumped_targets"]),
        "git_reconstructed": state["git_reconstructed"],
    }


@app.post("/api/osint/scan/shodan")
def scan_shodan(req: ShodanScanRequest) -> Dict[str, Any]:
    q = req.query.strip().lower()
    state["scanned_queries"].append(req.query)

    valid_terms = ["megacorp", "corp", "redis", "elastic", "6379", "9200", "org:", "port:"]
    matched = any(t in q for t in valid_terms)

    if not matched:
        return {
            "query": req.query,
            "total_results": 0,
            "results": [],
            "message": "No matching shadow IT assets found for this search filter. Try dorking for organization names, ASNs, or ports (e.g., org:'Megacorp' port:6379,9200)."
        }

    results = [
        {
            "ip": "198.51.100.42",
            "port": 6379,
            "service": "Redis 6.2.6",
            "auth_required": False,
            "banner": "role:master;connected_clients:3;db0:keys=142,expires=12",
            "risk": "CRITICAL - Unauthenticated Database exposed to internet"
        },
        {
            "ip": "198.51.100.43",
            "port": 9200,
            "service": "Elasticsearch 7.17.0",
            "auth_required": False,
            "cluster_name": "megacorp-analytics-cluster",
            "indices": ["corp_audit_logs", "customer_pii", "api_tokens"],
            "risk": "CRITICAL - Open REST endpoint without basic auth"
        },
        {
            "ip": "198.51.100.44",
            "port": 80,
            "service": "Nginx/1.18.0",
            "exposed_path": "/.git/HEAD",
            "git_status": "ref: refs/heads/main",
            "risk": "HIGH - Publicly accessible .git metadata directory"
        }
    ]

    state["step1_completed"] = True
    return {
        "query": req.query,
        "total_results": len(results),
        "results": results,
        "flag": STEP1_FLAG,
        "message": "Step 1 Completed: Shadow IT assets and exposed endpoints mapped via OSINT query."
    }


@app.post("/api/osint/leak/database")
def leak_database(req: DatabaseQueryRequest) -> Dict[str, Any]:
    t = req.target.strip().lower()
    cmd = (req.command or "").strip().upper()

    valid_target = any(k in t for k in ["redis", "elastic", "198.51.100.42", "198.51.100.43", "6379", "9200"])
    if not valid_target:
        raise HTTPException(
            status_code=400,
            detail="Unknown target. Target must point to discovered Redis (198.51.100.42:6379) or Elasticsearch (198.51.100.43:9200)."
        )

    state["dumped_targets"].append(req.target)
    state["step2_completed"] = True

    if "redis" in t or "6379" in t or "198.51.100.42" in t:
        dump_data = {
            "service": "Redis",
            "endpoint": "198.51.100.42:6379",
            "keys_extracted": [
                "sess:user:9912 -> {'email': 'admin@megacorp-logistics.io', 'role': 'superadmin', 'mfa': False}",
                "cfg:jwt_secret -> 'k8s-sec-prod-token-9948271'",
                "api:stripe_key -> 'sk_live_51M7XXXXXXXXXXXXX'"
            ],
            "records_carved": 142
        }
    else:
        dump_data = {
            "service": "Elasticsearch",
            "endpoint": "198.51.100.43:9200",
            "indices_dumped": ["corp_audit_logs", "customer_pii"],
            "records_carved": 5890,
            "sample": {
                "_index": "corp_audit_logs",
                "_source": {
                    "timestamp": "2026-09-30T09:00:00Z",
                    "user": "sec_devops",
                    "action": "DEPLOY_PIPELINE",
                    "target_env": "production"
                }
            }
        }

    return {
        "status": "success",
        "data": dump_data,
        "flag": STEP2_FLAG,
        "message": "Step 2 Completed: Extracted sensitive credential records and shadow keys from unauthenticated database."
    }


@app.post("/api/osint/git/reconstruct")
def reconstruct_git(req: GitReconstructRequest) -> Dict[str, Any]:
    t = req.target.strip().lower()
    action = (req.action or "log").strip().lower()

    valid_target = any(k in t for k in ["git", "198.51.100.44", "portal", "80"])
    if not valid_target:
        raise HTTPException(
            status_code=400,
            detail="Unknown target. Target must specify the exposed Git server at 198.51.100.44:80/.git"
        )

    state["git_reconstructed"] = True
    state["step3_completed"] = True

    git_history = [
        {
            "commit": "8f3b2a9e1d4c5b6a7e8f90123456789abcdef01",
            "author": "devops_intern <intern@megacorp-logistics.io>",
            "message": "Security fix: remove hardcoded AWS credentials from deployment script",
            "diff": (
                "--- a/config/aws_creds.env\n"
                "+++ /dev/null\n"
                "@@ -1,3 +0,0 @@\n"
                "-AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
                "-AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
                "-AWS_DEFAULT_REGION=ap-northeast-2\n"
            )
        },
        {
            "commit": "a1b2c3d4e5f67890123456789abcdef01234567",
            "author": "lead_architect <lead@megacorp-logistics.io>",
            "message": "Initial commit: Production deployment configuration",
            "diff": "+++ b/config/aws_creds.env (added)"
        }
    ]

    return {
        "status": "success",
        "action": action,
        "recovered_commits": len(git_history),
        "history": git_history,
        "recovered_secrets": {
            "AWS_ACCESS_KEY_ID": "AKIAIOSFODNN7EXAMPLE",
            "AWS_SECRET_ACCESS_KEY": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "AWS_DEFAULT_REGION": "ap-northeast-2"
        },
        "flag": STEP3_FLAG,
        "message": "Step 3 Completed: Traversed detached commit objects in .git repository and reconstructed deleted high-privilege credentials."
    }


@app.post("/api/osint/reset")
def reset_lab() -> Dict[str, Any]:
    state["step1_completed"] = False
    state["step2_completed"] = False
    state["step3_completed"] = False
    state["scanned_queries"] = []
    state["dumped_targets"] = []
    state["git_reconstructed"] = False
    return {"status": "reset_complete", "message": "Lab 34 state has been reset."}


@app.get("/", response_class=HTMLResponse)
def index_page() -> str:
    return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Lab 34: OSINT Surface Recon & Shadow IT Hunter</title>
    <style>
        :root {
            --bg: #0a0d14;
            --surface: #121824;
            --border: #1e293b;
            --primary: #00f0ff;
            --accent: #ff0055;
            --warning: #ffb800;
            --success: #00ff88;
            --text: #e2e8f0;
            --text-dim: #94a3b8;
            --code-bg: #05070a;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, monospace;
            background: var(--bg);
            color: var(--text);
            line-height: 1.6;
            padding: 24px;
        }
        .header {
            max-width: 1200px;
            margin: 0 auto 24px;
            border-bottom: 1px solid var(--border);
            padding-bottom: 16px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .header h1 {
            font-size: 1.5rem;
            color: var(--primary);
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .badge {
            background: rgba(0, 240, 255, 0.15);
            color: var(--primary);
            border: 1px solid var(--primary);
            padding: 4px 10px;
            border-radius: 4px;
            font-size: 0.8rem;
            font-weight: bold;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 24px;
        }
        @media (max-width: 900px) {
            .container { grid-template-columns: 1fr; }
        }
        .card {
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 20px;
        }
        .card h2 {
            font-size: 1.15rem;
            color: #fff;
            margin-bottom: 12px;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .btn {
            background: var(--primary);
            color: #000;
            border: none;
            padding: 8px 16px;
            border-radius: 4px;
            font-weight: 600;
            cursor: pointer;
            transition: opacity 0.2s;
        }
        .btn:hover { opacity: 0.9; }
        .btn-danger { background: var(--accent); color: #fff; }
        .btn-sec { background: var(--border); color: var(--text); }
        .input-group {
            margin-bottom: 16px;
        }
        .input-group label {
            display: block;
            font-size: 0.85rem;
            color: var(--text-dim);
            margin-bottom: 6px;
        }
        input, select, textarea {
            width: 100%;
            background: var(--code-bg);
            border: 1px solid var(--border);
            color: var(--text);
            padding: 8px 12px;
            border-radius: 4px;
            font-family: monospace;
            font-size: 0.9rem;
        }
        pre {
            background: var(--code-bg);
            border: 1px solid var(--border);
            padding: 12px;
            border-radius: 4px;
            font-family: monospace;
            font-size: 0.85rem;
            overflow-x: auto;
            max-height: 280px;
            color: #38bdf8;
        }
        .flag-box {
            background: rgba(0, 255, 136, 0.1);
            border: 1px dashed var(--success);
            padding: 12px;
            border-radius: 4px;
            margin-top: 12px;
            color: var(--success);
            font-family: monospace;
            font-weight: bold;
            word-break: break-all;
        }
        .step-tag {
            display: inline-block;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: bold;
            margin-right: 6px;
        }
        .tag-1 { background: rgba(0, 240, 255, 0.2); color: var(--primary); }
        .tag-2 { background: rgba(255, 184, 0, 0.2); color: var(--warning); }
        .tag-3 { background: rgba(255, 0, 85, 0.2); color: var(--accent); }
    </style>
</head>
<body>
    <div class="header">
        <h1>🛰️ Lab 34: OSINT Surface Recon & Shadow IT Hunter</h1>
        <div style="display: flex; gap: 8px; align-items: center;">
            <span class="badge">PORT 8034</span>
            <button class="btn btn-sec" onclick="resetLab()">Reset Lab</button>
        </div>
    </div>

    <div class="container">
        <!-- Target Info & Step 1: Shodan Recon -->
        <div class="card">
            <h2><span class="step-tag tag-1">STEP 1</span> Internet Attack Surface Discovery (Shodan/Censys)</h2>
            <p style="color: var(--text-dim); font-size: 0.85rem; margin-bottom: 14px;">
                Execute search queries against global scanner databases to map exposed infrastructure, open databases, and unauthenticated endpoints.
            </p>
            <div class="input-group">
                <label>Shodan Search Dork / Query:</label>
                <input type="text" id="shodanQuery" value="org:'Megacorp' port:6379,9200">
            </div>
            <button class="btn" onclick="executeShodan()">Search Shodan Assets</button>
            <div id="step1Output" style="margin-top: 14px;"></div>
        </div>

        <!-- Step 2: Database Dump -->
        <div class="card">
            <h2><span class="step-tag tag-2">STEP 2</span> Unauthenticated Database Carving (Redis / Elastic)</h2>
            <p style="color: var(--text-dim); font-size: 0.85rem; margin-bottom: 14px;">
                Interact with the discovered shadow Redis or Elasticsearch instances to dump internal database records and extract master credentials.
            </p>
            <div class="input-group">
                <label>Target Database Endpoint:</label>
                <input type="text" id="dbTarget" value="198.51.100.42:6379 (Redis)">
            </div>
            <div class="input-group">
                <label>Command / Query Payload:</label>
                <input type="text" id="dbCommand" value="KEYS *">
            </div>
            <button class="btn" onclick="dumpDatabase()">Extract Database Records</button>
            <div id="step2Output" style="margin-top: 14px;"></div>
        </div>

        <!-- Step 3: Git Repo Reconstruction -->
        <div class="card" style="grid-column: 1 / -1;">
            <h2><span class="step-tag tag-3">STEP 3</span> Exposed .git Tree & Secret Carving (Git Reconstructor)</h2>
            <p style="color: var(--text-dim); font-size: 0.85rem; margin-bottom: 14px;">
                Crawl the exposed <code>/.git</code> folder on <code>198.51.100.44:80</code>, unpack git object blobs, and trace detached commit diffs to recover discarded cloud production tokens.
            </p>
            <div style="display: flex; gap: 12px; margin-bottom: 12px;">
                <input type="text" id="gitTarget" value="198.51.100.44:80/.git" style="flex: 2;">
                <select id="gitAction" style="flex: 1;">
                    <option value="log">git log -p (Commit Diffs)</option>
                    <option value="cat-file">git cat-file -p HEAD</option>
                    <option value="dump">dump objects</option>
                </select>
                <button class="btn btn-danger" onclick="reconstructGit()">Reconstruct Leaked Commits</button>
            </div>
            <div id="step3Output"></div>
        </div>
    </div>

    <script>
        async function executeShodan() {
            const query = document.getElementById('shodanQuery').value;
            const res = await fetch('/api/osint/scan/shodan', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({query})
            });
            const data = await res.json();
            let html = '<pre>' + JSON.stringify(data.results || data.message, null, 2) + '</pre>';
            if (data.flag) {
                html += '<div class="flag-box">🚩 STEP 1 FLAG: ' + data.flag + '</div>';
            }
            document.getElementById('step1Output').innerHTML = html;
        }

        async function dumpDatabase() {
            const target = document.getElementById('dbTarget').value;
            const command = document.getElementById('dbCommand').value;
            const res = await fetch('/api/osint/leak/database', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({target, command})
            });
            const data = await res.json();
            let html = '<pre>' + JSON.stringify(data.data || data.detail, null, 2) + '</pre>';
            if (data.flag) {
                html += '<div class="flag-box">🚩 STEP 2 FLAG: ' + data.flag + '</div>';
            }
            document.getElementById('step2Output').innerHTML = html;
        }

        async function reconstructGit() {
            const target = document.getElementById('gitTarget').value;
            const action = document.getElementById('gitAction').value;
            const res = await fetch('/api/osint/git/reconstruct', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({target, action})
            });
            const data = await res.json();
            let html = '<pre>' + JSON.stringify(data.history || data.detail, null, 2) + '</pre>';
            if (data.flag) {
                html += '<div class="flag-box">🚩 STEP 3 FLAG: ' + data.flag + '</div>';
            }
            document.getElementById('step3Output').innerHTML = html;
        }

        async function resetLab() {
            await fetch('/api/osint/reset', {method: 'POST'});
            document.getElementById('step1Output').innerHTML = '';
            document.getElementById('step2Output').innerHTML = '';
            document.getElementById('step3Output').innerHTML = '';
            alert('Lab 34 reset completed.');
        }
    </script>
</body>
</html>
"""
