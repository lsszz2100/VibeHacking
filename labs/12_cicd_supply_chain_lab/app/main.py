#!/usr/bin/env python3
"""Lab 12: CI/CD Pipeline Infiltration & Software Supply Chain Security Lab (PipePoison).

Provides an interactive simulation of an enterprise CI/CD platform (OctoCorp DevOps),
covering 4 core software supply chain attack stages:
1. Poisoned Pipeline Execution (PPE) / PR Workflow Injection
2. Dependency Confusion & Typosquatting (Malicious Package Resolution)
3. CI/CD Secrets Exfiltration & Runner Environment Harvesting
4. Software Release Artifact Backdooring & SLSA Provenance Tampering
"""

import base64
import hashlib
import hmac
import json
import os
import re
import shlex
import time
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

app = FastAPI(title="PipePoison - CI/CD & Software Supply Chain Security Lab")

STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
os.makedirs(STATIC_DIR, exist_ok=True)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

# Challenge Flags
FLAGS = {
    "stage1": "FLAG{PPE_WORKFLOW_INJECTION_RUNNER_ESCAPE_9182}",
    "stage2": "FLAG{DEPENDENCY_CONFUSION_PREINSTALL_TAKEOVER_4821}",
    "stage3": "FLAG{RUNNER_SECRETS_EXFIL_VAULT_TOKEN_7394}",
    "stage4": "FLAG{SUPPLY_CHAIN_BACKDOOR_SLSA_BYPASS_8841}",
}

# Production Secrets stored in CI/CD runner vault
VAULT_SECRETS = {
    "VAULT_ADDR": "https://vault.octocorp.internal:8200",
    "VAULT_TOKEN": "s.k8s_octo_prod_master_9921",
    "AWS_ACCESS_KEY_ID": "AKIAOCTOPROD8823419",
    "AWS_SECRET_ACCESS_KEY": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYOCTOKEY",
    "DOCKER_REGISTRY_TOKEN": "dckr_pat_prod_release_8829102",
    "PROD_DEPLOY_KEY": "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA09kOctoProdKey...\n-----END RSA PRIVATE KEY-----",
}

# In-Memory State
STATE: Dict[str, Any] = {
    "stages_solved": {
        "stage1": False,
        "stage2": False,
        "stage3": False,
        "stage4": False,
    },
    "policies": {
        "sanitize_pr_inputs": False,         # Mitigate Stage 1
        "scoped_registries_only": False,     # Mitigate Stage 2
        "oidc_short_lived_tokens": False,    # Mitigate Stage 3
        "enforce_slsa_signatures": False,    # Mitigate Stage 4
    },
    "pull_requests": [
        {
            "id": 101,
            "title": "Fix memory leak in JWT parser",
            "author": "dev-alice",
            "branch": "fix/jwt-parser",
            "status": "merged",
            "workflow_code": "# Clean standard workflow\nmake test",
            "created_at": "2026-09-10 10:20:00",
        },
        {
            "id": 102,
            "title": "Add Prometheus metrics endpoint",
            "author": "dev-bob",
            "branch": "feature/metrics",
            "status": "open",
            "workflow_code": "# Feature branch workflow\npytest tests/test_metrics.py",
            "created_at": "2026-09-12 14:35:00",
        },
    ],
    "pipeline_runs": [],
    "registry_packages": {
        "internal": {
            "octocorp-auth-core": {"version": "2.1.0", "author": "OctoCorp Security", "verified": True},
            "octocorp-db-connector": {"version": "1.4.2", "author": "OctoCorp Infra", "verified": True},
            "octocorp-crypto-vault": {"version": "1.0.0", "author": "OctoCorp Security", "verified": True},
        },
        "public": {
            "requests": {"version": "2.31.0", "author": "PSF", "verified": True},
            "cryptography": {"version": "42.0.5", "author": "PyCA", "verified": True},
            "fastapi": {"version": "0.109.0", "author": "tiangolo", "verified": True},
        },
    },
    "exfiltration_log": [],
    "releases": [
        {
            "id": "rel-2.3.9",
            "name": "auth-service-v2.3.9.tar.gz",
            "content": "OctoCorp AuthService v2.3.9 Initial Release Binary.",
            "sha256": "3a8f6d21e89b4c09d845e2193e98127394182937482910482910384729102834",
            "slsa_level": 1,
            "signed": False,
            "backdoored": False,
            "status": "deployed_stable",
        }
    ],
}


# --- Request Models ---
class PRCreateRequest(BaseModel):
    title: str
    author: str = "attacker"
    branch: str = "patch-1"
    script_injection: Optional[str] = None


class PipelineTriggerRequest(BaseModel):
    pr_id: int


class DependencyPublishRequest(BaseModel):
    package_name: str
    version: str
    install_hook_script: str
    author: str = "evil-maintainer"


class DependencyInstallRequest(BaseModel):
    package_name: str


class ExfilRequest(BaseModel):
    source: str
    data: str


class ReleaseTamperRequest(BaseModel):
    release_id: str
    injected_payload: str
    tamper_checksum: bool = True


class FlagSubmitRequest(BaseModel):
    stage: str
    flag: str


class PolicyToggleRequest(BaseModel):
    policy: str
    enabled: bool


# --- Helper Simulation Logic ---
def execute_simulated_runner(command: str, env_vars: Dict[str, str]) -> Dict[str, Any]:
    """Simulates pipeline command execution inside self-hosted CI/CD runner."""
    logs: List[str] = []
    logs.append(f"[runner@octo-worker-01] Executing: {command}")
    
    # Masking secrets helper
    masked_env = {}
    for k, v in env_vars.items():
        if "TOKEN" in k or "SECRET" in k or "KEY" in k:
            masked_env[k] = "***"
        else:
            masked_env[k] = v

    logs.append(f"[runner@octo-worker-01] Loaded environment: {list(masked_env.keys())}")
    
    # Detection of command injection patterns:
    # e.g. ; | & ` $() || &&
    injection_patterns = [r";\s*", r"\|\s*", r"\$\(", r"`", r"&&\s*", r"\|\|\s*"]
    has_injection = any(re.search(pat, command) for pat in injection_patterns)
    
    rce_detected = False
    exfil_data = None

    if has_injection:
        logs.append("[runner@octo-worker-01] WARNING: Command chaining or dynamic subshell evaluation detected!")
        # Check if attacker executes commands or dumps environment
        if re.search(r"(env|printenv|set|echo|cat|whoami|id|curl|wget)", command, re.IGNORECASE):
            rce_detected = True
            logs.append("[runner@octo-worker-01] Subshell stdout: uid=1001(runner) gid=1001(docker) groups=1001(docker)")
            logs.append("[runner@octo-worker-01] Infiltration successful: Runner command execution established!")
            
    return {
        "logs": "\n".join(logs),
        "rce_detected": rce_detected,
    }


# --- API Endpoints ---
@app.get("/", response_class=HTMLResponse)
async def get_index():
    index_path = os.path.join(STATIC_DIR, "index.html")
    if os.path.exists(index_path):
        with open(index_path, "r", encoding="utf-8") as f:
            return f.read()
    return HTMLResponse("<h1>PipePoison CI/CD Lab</h1><p>Static UI loading...</p>")


@app.get("/api/status")
async def get_status():
    """Return overall lab status and progress."""
    solved_count = sum(1 for v in STATE["stages_solved"].values() if v)
    return {
        "status": "running",
        "service": "PipePoison CI/CD & Software Supply Chain Lab",
        "port": 8012,
        "solved_count": solved_count,
        "total_stages": 4,
        "stages": STATE["stages_solved"],
        "policies": STATE["policies"],
        "pull_requests_count": len(STATE["pull_requests"]),
        "pipeline_runs_count": len(STATE["pipeline_runs"]),
        "releases_count": len(STATE["releases"]),
    }


# ── STAGE 1: Poisoned Pipeline Execution (PPE) ────────────────────────────────
@app.get("/api/vcs/pull-requests")
async def list_prs():
    return {"pull_requests": STATE["pull_requests"]}


@app.post("/api/vcs/pull-requests")
async def create_pr(req: PRCreateRequest):
    new_id = 100 + len(STATE["pull_requests"]) + 1
    pr_item = {
        "id": new_id,
        "title": req.title,
        "author": req.author,
        "branch": req.branch,
        "status": "open",
        "workflow_code": req.script_injection or "pytest tests/",
        "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    STATE["pull_requests"].append(pr_item)
    return {"message": "Pull Request created successfully", "pull_request": pr_item}


@app.post("/api/pipelines/trigger")
async def trigger_pipeline(req: PipelineTriggerRequest):
    """Triggers the automated CI pipeline on pull_request_target."""
    pr = next((p for p in STATE["pull_requests"] if p["id"] == req.pr_id), None)
    if not pr:
        raise HTTPException(status_code=404, detail="Pull Request not found")

    run_id = f"run-{int(time.time())}-{len(STATE['pipeline_runs']) + 1}"
    
    # Check defense policy
    if STATE["policies"]["sanitize_pr_inputs"]:
        # Hardened workflow uses environment variable safely without shell expansion
        safe_title = re.sub(r"[^\w\s\-\.\/]", "", pr["title"])
        runner_cmd = f"echo 'Processing PR title securely' && python -c 'import sys; print(sys.argv[1])' {shlex.quote(safe_title)}"
    else:
        # Vulnerable workflow: direct string interpolation into bash run step
        # ${{ github.event.pull_request.title }}
        runner_cmd = f"echo 'Processing PR title: {pr['title']}' && {pr['workflow_code']}"

    execution = execute_simulated_runner(runner_cmd, VAULT_SECRETS)

    stage1_success = False
    flag_awarded = None
    if execution["rce_detected"] and not STATE["policies"]["sanitize_pr_inputs"]:
        stage1_success = True
        flag_awarded = FLAGS["stage1"]
        execution["logs"] += f"\n[VCS Security Alert] Pipeline Hijack Confirmed! Arbitrary code executed on runner!\n[FLAG] {flag_awarded}"

    pipeline_run = {
        "run_id": run_id,
        "pr_id": pr["id"],
        "pr_title": pr["title"],
        "command": runner_cmd,
        "logs": execution["logs"],
        "status": "success" if not execution["rce_detected"] else "compromised",
        "stage1_solved": stage1_success,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    STATE["pipeline_runs"].append(pipeline_run)

    return {
        "run_id": run_id,
        "status": pipeline_run["status"],
        "stage1_exploited": stage1_success,
        "flag": flag_awarded,
        "logs": execution["logs"],
    }


@app.get("/api/pipelines/runs")
async def get_runs():
    return {"runs": STATE["pipeline_runs"][-10:]}


# ── STAGE 2: Dependency Confusion & Typosquatting ─────────────────────────────
@app.get("/api/registry/packages")
async def list_registry_packages():
    return {
        "internal_registry": "https://packages.octocorp.internal/pypi/simple/",
        "public_mirror": "https://pypi.org/simple/",
        "packages": STATE["registry_packages"],
    }


@app.post("/api/registry/publish-public")
async def publish_public_dependency(req: DependencyPublishRequest):
    """Allows an attacker to publish a package to the public PyPI index with install hooks."""
    pkg_entry = {
        "version": req.version,
        "author": req.author,
        "install_hook": req.install_hook_script,
        "verified": False,
        "published_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    STATE["registry_packages"]["public"][req.package_name] = pkg_entry
    return {
        "message": f"Package '{req.package_name}=={req.version}' published to public PyPI mirror.",
        "package": pkg_entry,
    }


@app.post("/api/pipelines/build-deps")
async def build_dependencies(req: DependencyInstallRequest):
    """Simulates `pip install --extra-index-url` resolving dependencies during build."""
    pkg_name = req.package_name
    logs = [f"[pip] Resolving dependency: {pkg_name}..."]
    
    internal_pkg = STATE["registry_packages"]["internal"].get(pkg_name)
    public_pkg = STATE["registry_packages"]["public"].get(pkg_name)

    chosen_source = None
    chosen_pkg = None

    if STATE["policies"]["scoped_registries_only"]:
        # Hardened: only internal scoped repository allowed for internal names
        if pkg_name.startswith("octocorp-"):
            chosen_source = "internal"
            chosen_pkg = internal_pkg
            logs.append(f"[pip-safe] Namespace 'octocorp-*' locked to internal private index.")
        else:
            chosen_source = "public"
            chosen_pkg = public_pkg
    else:
        # Vulnerable resolver: picks highest version across both repositories
        if internal_pkg and public_pkg:
            # Semantic version compare simulation (if public version > internal, pick public)
            pub_ver = [int(x) for x in re.findall(r"\d+", public_pkg["version"])]
            int_ver = [int(x) for x in re.findall(r"\d+", internal_pkg["version"])]
            if pub_ver > int_ver:
                chosen_source = "public"
                chosen_pkg = public_pkg
                logs.append(f"[pip-vuln] Higher version found on public index ({public_pkg['version']} > {internal_pkg['version']})!")
            else:
                chosen_source = "internal"
                chosen_pkg = internal_pkg
        elif public_pkg:
            chosen_source = "public"
            chosen_pkg = public_pkg
        elif internal_pkg:
            chosen_source = "internal"
            chosen_pkg = internal_pkg

    if not chosen_pkg:
        raise HTTPException(status_code=404, detail=f"Package '{pkg_name}' not found on any index.")

    logs.append(f"[pip] Fetching {pkg_name}=={chosen_pkg['version']} from {chosen_source} index...")
    
    stage2_success = False
    flag_awarded = None

    # Check for malicious install hook
    if chosen_source == "public" and "install_hook" in chosen_pkg:
        logs.append(f"[setup.py] Running setup.py bdist_wheel / preinstall hook...")
        hook = chosen_pkg["install_hook"]
        logs.append(f"[setup.py stdout] {hook}")
        
        if "os.system" in hook or "subprocess" in hook or "sh" in hook or "curl" in hook or "token" in hook:
            stage2_success = True
            flag_awarded = FLAGS["stage2"]
            logs.append(f"[Security Monitor] Malicious package install hook executed in build environment!")
            logs.append(f"[FLAG] {flag_awarded}")

    return {
        "package": pkg_name,
        "resolved_version": chosen_pkg["version"],
        "source": chosen_source,
        "logs": "\n".join(logs),
        "stage2_exploited": stage2_success,
        "flag": flag_awarded,
    }


# ── STAGE 3: CI/CD Secrets Exfiltration ───────────────────────────────────────
@app.post("/api/exfil/collector")
async def exfil_collector(req: ExfilRequest):
    """External attacker listening post for exfiltrated pipeline runner secrets."""
    entry = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "source": req.source,
        "data": req.data,
    }
    STATE["exfiltration_log"].append(entry)

    stage3_success = False
    flag_awarded = None

    # Check if the exfiltrated data contains the master vault token or AWS secrets
    raw_data = req.data
    # Attacker might send encoded base64 or plaintext
    decoded_attempts = [raw_data]
    try:
        decoded_attempts.append(base64.b64decode(raw_data).decode("utf-8", errors="ignore"))
    except Exception:
        pass

    for content in decoded_attempts:
        if VAULT_SECRETS["VAULT_TOKEN"] in content or (
            VAULT_SECRETS["AWS_ACCESS_KEY_ID"] in content and VAULT_SECRETS["AWS_SECRET_ACCESS_KEY"] in content
        ):
            stage3_success = True
            flag_awarded = FLAGS["stage3"]
            break

    return {
        "status": "received",
        "logged_entries": len(STATE["exfiltration_log"]),
        "secrets_harvested": stage3_success,
        "flag": flag_awarded,
    }


@app.get("/api/exfil/logs")
async def get_exfil_logs():
    return {"exfiltration_logs": STATE["exfiltration_log"][-15:]}


@app.post("/api/vault/verify-token")
async def verify_vault_token(request: Request):
    """Simulates authenticating to internal HashiCorp Vault using exfiltrated token."""
    auth_header = request.headers.get("X-Vault-Token", "")
    if auth_header == VAULT_SECRETS["VAULT_TOKEN"]:
        if STATE["policies"]["oidc_short_lived_tokens"]:
            return JSONResponse(
                status_code=403,
                content={"error": "Permission Denied: Static Vault token disabled. OIDC federation required."},
            )
        return {
            "authenticated": True,
            "role": "production-infrastructure-root",
            "capabilities": ["create", "read", "update", "delete", "sudo"],
            "flag": FLAGS["stage3"],
            "message": "Full Vault root access granted! Production secrets unlocked.",
        }
    raise HTTPException(status_code=401, detail="Invalid Vault Token")


# ── STAGE 4: Software Release Artifact Backdooring & SLSA Tampering ───────────
@app.get("/api/release/artifacts")
async def list_release_artifacts():
    return {"releases": STATE["releases"]}


@app.post("/api/release/build")
async def build_release_artifact():
    """Builds a new release candidate from master."""
    ver = f"2.4.{len(STATE['releases'])}"
    art_name = f"auth-service-v{ver}.tar.gz"
    initial_content = f"OctoCorp AuthService v{ver} Build Binary. Secure Code Signed."
    art_hash = hashlib.sha256(initial_content.encode()).hexdigest()

    release_obj = {
        "id": f"rel-{ver}",
        "name": art_name,
        "content": initial_content,
        "sha256": art_hash,
        "slsa_level": 3 if STATE["policies"]["enforce_slsa_signatures"] else 1,
        "signed": STATE["policies"]["enforce_slsa_signatures"],
        "backdoored": False,
        "status": "built",
    }
    STATE["releases"].append(release_obj)
    return {"message": "Release candidate built", "release": release_obj}


@app.post("/api/release/tamper")
async def tamper_release_artifact(req: ReleaseTamperRequest):
    """Injects a backdoor payload into the built artifact (SolarWinds style supply chain injection)."""
    rel = next((r for r in STATE["releases"] if r["id"] == req.release_id), None)
    if not rel:
        raise HTTPException(status_code=404, detail="Release artifact not found")

    if STATE["policies"]["enforce_slsa_signatures"]:
        raise HTTPException(
            status_code=403,
            detail="SLSA Attestation & Sigstore Cosign signature verification failed! Artifact mutation rejected by policy engine.",
        )

    # SolarWinds/XZ style insertion into artifact
    rel["content"] = rel.get("content", "") + f"\n[BACKDOOR_INJECTED]: {req.injected_payload}"
    rel["backdoored"] = True
    if req.tamper_checksum:
        rel["sha256"] = hashlib.sha256(rel["content"].encode()).hexdigest()

    return {
        "message": f"Artifact {rel['name']} successfully backdoored!",
        "release": rel,
    }


@app.post("/api/release/deploy-test")
async def deploy_test_release(release_id: str):
    """Simulates deploying the release to the staging cluster and testing admin login."""
    rel = next((r for r in STATE["releases"] if r["id"] == release_id), None)
    if not rel:
        raise HTTPException(status_code=404, detail="Release artifact not found")

    logs = [
        f"[CD Deployer] Deploying {rel['name']} (SHA256: {rel['sha256'][:12]}...) to Staging...",
        f"[CD Deployer] Checking SLSA provenance: Level {rel['slsa_level']} (Signed: {rel['signed']})",
    ]

    if STATE["policies"]["enforce_slsa_signatures"] and not rel["signed"]:
        logs.append("[CD Deployer] ERROR: Deployment blocked by admission controller: Unsigned release!")
        return {"status": "rejected", "logs": "\n".join(logs)}

    logs.append("[CD Deployer] Deployment completed. Service live on staging.octocorp.internal.")
    
    stage4_success = False
    flag_awarded = None

    if rel["backdoored"]:
        logs.append("[Security Audit] Backdoor signature triggered! Master admin bypass detected!")
        logs.append(f"[Auth Log] User 'backdoor_admin' successfully logged in with root token.")
        stage4_success = True
        flag_awarded = FLAGS["stage4"]
        logs.append(f"[FLAG] {flag_awarded}")
    else:
        logs.append("[Security Audit] Standard clean release operating normally.")

    return {
        "status": "deployed",
        "stage4_exploited": stage4_success,
        "flag": flag_awarded,
        "logs": "\n".join(logs),
    }


# ── Defense Policies & Flag Verification ──────────────────────────────────────
@app.get("/api/security/policies")
async def get_policies():
    return {"policies": STATE["policies"]}


@app.post("/api/security/policies")
async def toggle_policy(req: PolicyToggleRequest):
    if req.policy not in STATE["policies"]:
        raise HTTPException(status_code=400, detail="Unknown policy name")
    STATE["policies"][req.policy] = req.enabled
    return {
        "message": f"Policy '{req.policy}' set to {req.enabled}",
        "policies": STATE["policies"],
    }


@app.post("/api/submit-flag")
async def submit_flag(req: FlagSubmitRequest):
    st = req.stage.lower()
    if st not in FLAGS:
        raise HTTPException(status_code=400, detail="Invalid stage name. Use: stage1, stage2, stage3, stage4")

    expected_flag = FLAGS[st]
    if req.flag.strip() == expected_flag:
        STATE["stages_solved"][st] = True
        solved_count = sum(1 for v in STATE["stages_solved"].values() if v)
        return {
            "correct": True,
            "stage": st,
            "message": f"Congratulations! {st.upper()} verified successfully.",
            "solved_count": solved_count,
            "total_stages": 4,
            "all_cleared": solved_count == 4,
        }
    return {
        "correct": False,
        "stage": st,
        "message": "Incorrect flag. Review your attack telemetry and try again.",
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8012, reload=False)
