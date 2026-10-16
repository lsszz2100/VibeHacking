"""
Test suite for Lab 41: SupplyChainShield — Software Supply Chain Security & SBOM Lab.
"""

import sys
import importlib.util
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

APP_PATH = Path(__file__).resolve().parent.parent / "app" / "main.py"
spec = importlib.util.spec_from_file_location("lab41_app", str(APP_PATH))
lab41_module = importlib.util.module_from_spec(spec)
sys.modules["lab41_app"] = lab41_module
spec.loader.exec_module(lab41_module)

app = lab41_module.app
STAGE1_FLAG = lab41_module.STAGE1_FLAG
STAGE2_FLAG = lab41_module.STAGE2_FLAG
STAGE3_FLAG = lab41_module.STAGE3_FLAG
STAGE4_FLAG = lab41_module.STAGE4_FLAG

client = TestClient(app)

@pytest.fixture(autouse=True)
def reset_state():
    """Ensure clean state before each test."""
    client.post("/api/reset")
    yield
    client.post("/api/reset")

def test_index_dashboard():
    response = client.get("/")
    assert response.status_code == 200
    assert "Lab 41: SupplyChainShield" in response.text
    assert "Port: 8041" in response.text

def test_initial_status():
    response = client.get("/api/status")
    assert response.status_code == 200
    data = response.json()
    assert data["lab"] == "41"
    assert data["all_stages_completed"] is False
    assert data["stages"]["stage1_dependency_confusion"] is False
    assert data["stages"]["stage2_ci_pipeline_audit"] is False
    assert data["stages"]["stage3_sbom_triage"] is False
    assert data["stages"]["stage4_slsa_attestation"] is False

def test_stage1_get_packages():
    response = client.get("/api/stage1/packages")
    assert response.status_code == 200
    data = response.json()
    assert "packages" in data
    assert len(data["packages"]) >= 3
    names = [p["name"] for p in data["packages"]]
    assert "corp-auth-core" in names
    assert "requsts" in names

def test_stage1_resolve_wrong_package():
    response = client.post(
        "/api/stage1/resolve",
        json={
            "target_package": "non-existent-pkg",
            "vulnerability_type": "dependency_confusion",
            "defense_strategy": "scoped_registry_or_pinning",
        },
    )
    assert response.status_code == 400
    assert "not found" in response.json()["detail"].lower()

def test_stage1_resolve_wrong_vuln_type():
    response = client.post(
        "/api/stage1/resolve",
        json={
            "target_package": "corp-auth-core",
            "vulnerability_type": "sql_injection",
            "defense_strategy": "scoped_registry_or_pinning",
        },
    )
    assert response.status_code == 400
    assert "incorrect vulnerability type" in response.json()["detail"].lower()

def test_stage1_resolve_wrong_defense():
    response = client.post(
        "/api/stage1/resolve",
        json={
            "target_package": "corp-auth-core",
            "vulnerability_type": "dependency_confusion",
            "defense_strategy": "no_defense",
        },
    )
    assert response.status_code == 400
    assert "defense strategy must be" in response.json()["detail"].lower()

def test_stage1_resolve_typosquatting_info():
    response = client.post(
        "/api/stage1/resolve",
        json={
            "target_package": "requsts",
            "vulnerability_type": "typosquatting",
            "defense_strategy": "name_typo_inspection",
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "info"
    assert "corp-auth-core" in data["message"]

def test_stage1_resolve_success():
    response = client.post(
        "/api/stage1/resolve",
        json={
            "target_package": "corp-auth-core",
            "vulnerability_type": "dependency_confusion",
            "defense_strategy": "scoped_registry_or_pinning",
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert data["flag"] == STAGE1_FLAG

def test_stage2_get_workflow():
    response = client.get("/api/stage2/workflow")
    assert response.status_code == 200
    data = response.json()
    assert "pull_request_target" in data["yaml_content"]
    assert data["high_privilege"] is True

def test_stage2_audit_wrong_hazard():
    response = client.post(
        "/api/stage2/audit-pipeline",
        json={
            "trigger_hazard": "push",
            "leaked_secret": "AWS_SECRET_ACCESS_KEY",
            "recommended_fix": "pull_request_read_only",
        },
    )
    assert response.status_code == 400
    assert "trigger hazard" in response.json()["detail"].lower()

def test_stage2_audit_wrong_secret():
    response = client.post(
        "/api/stage2/audit-pipeline",
        json={
            "trigger_hazard": "pull_request_target",
            "leaked_secret": "SSH_PRIVATE_KEY",
            "recommended_fix": "pull_request_read_only",
        },
    )
    assert response.status_code == 400
    assert "not the primary" in response.json()["detail"].lower()

def test_stage2_audit_wrong_fix():
    response = client.post(
        "/api/stage2/audit-pipeline",
        json={
            "trigger_hazard": "pull_request_target",
            "leaked_secret": "AWS_SECRET_ACCESS_KEY",
            "recommended_fix": "ignore_pull_request",
        },
    )
    assert response.status_code == 400
    assert "recommended fix must be" in response.json()["detail"].lower()

def test_stage2_audit_success():
    response = client.post(
        "/api/stage2/audit-pipeline",
        json={
            "trigger_hazard": "pull_request_target",
            "leaked_secret": "AWS_SECRET_ACCESS_KEY",
            "recommended_fix": "pull_request_read_only",
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert data["flag"] == STAGE2_FLAG

def test_stage3_get_sbom():
    response = client.get("/api/stage3/sbom")
    assert response.status_code == 200
    data = response.json()
    assert "sbom" in data
    assert data["sbom"]["bomFormat"] == "CycloneDX"
    assert "components" in data["sbom"]

def test_stage3_triage_wrong_component():
    response = client.post(
        "/api/stage3/triage-sbom",
        json={
            "compromised_component": "openssl",
            "cve_id": "CVE-2024-3094",
            "hash_mismatch": True,
            "action": "isolate_component",
        },
    )
    assert response.status_code == 400
    assert "not the backdoored" in response.json()["detail"].lower()

def test_stage3_triage_wrong_cve():
    response = client.post(
        "/api/stage3/triage-sbom",
        json={
            "compromised_component": "liblzma-build-hook",
            "cve_id": "CVE-2021-44228",
            "hash_mismatch": True,
            "action": "isolate_component",
        },
    )
    assert response.status_code == 400
    assert "cve identifier" in response.json()["detail"].lower()

def test_stage3_triage_no_hash_mismatch():
    response = client.post(
        "/api/stage3/triage-sbom",
        json={
            "compromised_component": "liblzma-build-hook",
            "cve_id": "CVE-2024-3094",
            "hash_mismatch": False,
            "action": "isolate_component",
        },
    )
    assert response.status_code == 400
    assert "hash mismatch must be confirmed" in response.json()["detail"].lower()

def test_stage3_triage_wrong_action():
    response = client.post(
        "/api/stage3/triage-sbom",
        json={
            "compromised_component": "liblzma-build-hook",
            "cve_id": "CVE-2024-3094",
            "hash_mismatch": True,
            "action": "ignore_component",
        },
    )
    assert response.status_code == 400
    assert "action must be" in response.json()["detail"].lower()

def test_stage3_triage_success():
    response = client.post(
        "/api/stage3/triage-sbom",
        json={
            "compromised_component": "liblzma-build-hook",
            "cve_id": "CVE-2024-3094",
            "hash_mismatch": True,
            "action": "isolate_component",
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert data["flag"] == STAGE3_FLAG

def test_stage4_get_attestation():
    response = client.get("/api/stage4/attestation")
    assert response.status_code == 200
    data = response.json()
    assert "attestation" in data
    assert "cosign" in data["attestation"]
    assert "slsa_provenance" in data["attestation"]

def test_stage4_verify_digest_mismatch():
    response = client.post(
        "/api/stage4/verify-provenance",
        json={
            "image_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            "issuer_oidc": "https://token.actions.githubusercontent.com",
            "slsa_level": "SLSA_BUILD_LEVEL_3",
            "enforce_policy": True,
        },
    )
    assert response.status_code == 400
    assert "digest mismatch" in response.json()["detail"].lower()

def test_stage4_verify_wrong_issuer():
    response = client.post(
        "/api/stage4/verify-provenance",
        json={
            "image_digest": "sha256:4a8f9c12b7e53d0684a1e90f2b6c7d1e8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f",
            "issuer_oidc": "https://untrusted.issuer.com",
            "slsa_level": "SLSA_BUILD_LEVEL_3",
            "enforce_policy": True,
        },
    )
    assert response.status_code == 400
    assert "untrusted oidc issuer" in response.json()["detail"].lower()

def test_stage4_verify_wrong_slsa_level():
    response = client.post(
        "/api/stage4/verify-provenance",
        json={
            "image_digest": "sha256:4a8f9c12b7e53d0684a1e90f2b6c7d1e8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f",
            "issuer_oidc": "https://token.actions.githubusercontent.com",
            "slsa_level": "SLSA_BUILD_LEVEL_1",
            "enforce_policy": True,
        },
    )
    assert response.status_code == 400
    assert "slsa build requirement" in response.json()["detail"].lower()

def test_stage4_verify_no_enforce():
    response = client.post(
        "/api/stage4/verify-provenance",
        json={
            "image_digest": "sha256:4a8f9c12b7e53d0684a1e90f2b6c7d1e8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f",
            "issuer_oidc": "https://token.actions.githubusercontent.com",
            "slsa_level": "SLSA_BUILD_LEVEL_3",
            "enforce_policy": False,
        },
    )
    assert response.status_code == 400
    assert "strict admission policy enforcement" in response.json()["detail"].lower()

def test_stage4_verify_success():
    response = client.post(
        "/api/stage4/verify-provenance",
        json={
            "image_digest": "sha256:4a8f9c12b7e53d0684a1e90f2b6c7d1e8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f",
            "issuer_oidc": "https://token.actions.githubusercontent.com",
            "slsa_level": "SLSA_BUILD_LEVEL_3",
            "enforce_policy": True,
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert data["flag"] == STAGE4_FLAG

def test_all_stages_completed_status():
    client.post(
        "/api/stage1/resolve",
        json={
            "target_package": "corp-auth-core",
            "vulnerability_type": "dependency_confusion",
            "defense_strategy": "scoped_registry_or_pinning",
        },
    )
    client.post(
        "/api/stage2/audit-pipeline",
        json={
            "trigger_hazard": "pull_request_target",
            "leaked_secret": "AWS_SECRET_ACCESS_KEY",
            "recommended_fix": "pull_request_read_only",
        },
    )
    client.post(
        "/api/stage3/triage-sbom",
        json={
            "compromised_component": "liblzma-build-hook",
            "cve_id": "CVE-2024-3094",
            "hash_mismatch": True,
            "action": "isolate_component",
        },
    )
    client.post(
        "/api/stage4/verify-provenance",
        json={
            "image_digest": "sha256:4a8f9c12b7e53d0684a1e90f2b6c7d1e8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f",
            "issuer_oidc": "https://token.actions.githubusercontent.com",
            "slsa_level": "SLSA_BUILD_LEVEL_3",
            "enforce_policy": True,
        },
    )
    res = client.get("/api/status")
    assert res.status_code == 200
    data = res.json()
    assert data["all_stages_completed"] is True
    assert data["stages"]["stage1_dependency_confusion"] is True
    assert data["stages"]["stage2_ci_pipeline_audit"] is True
    assert data["stages"]["stage3_sbom_triage"] is True
    assert data["stages"]["stage4_slsa_attestation"] is True
