#!/usr/bin/env python3
"""
Unit tests for Lab 35: CloudPwnLab — Cloud IAM Privilege Escalation & Governance Lab
Tests PassRole escalation, cross-account AssumeRole, SCP enforcement, and state reset.
"""

import sys
import importlib.util
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

# Dynamic import to avoid collision with other labs' app packages
APP_PATH = Path(__file__).resolve().parent.parent / "app" / "main.py"
spec = importlib.util.spec_from_file_location("lab35_app", str(APP_PATH))
lab35_module = importlib.util.module_from_spec(spec)
sys.modules["lab35_app"] = lab35_module
spec.loader.exec_module(lab35_module)

app = lab35_module.app
reset_lab = lab35_module.reset_lab

@pytest.fixture(autouse=True)
def run_reset():
    """Ensure each test runs with a fresh default baseline."""
    reset_lab()
    yield
    reset_lab()

@pytest.fixture
def client():
    return TestClient(app)

def test_health(client):
    res = client.get("/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "ok"
    assert data["lab"] == "35_cloud_iam_privilege_escalation_lab"
    assert data["port"] == 8035
    assert data["step1_completed"] is False

def test_index_html(client):
    res = client.get("/")
    assert res.status_code == 200
    assert "text/html" in res.headers["content-type"]
    assert "Lab 35: Cloud IAM" in res.text
    assert "8035" in res.text

def test_get_iam_roles(client):
    res = client.get("/api/cloud/iam/roles")
    assert res.status_code == 200
    data = res.json()
    assert "CloudSecAdminRole" in [r["role_name"] for r in data["available_roles"]]
    assert "CrossAccountAuditRole" in [r["role_name"] for r in data["available_roles"]]
    assert data["governance"]["scp_applied"] is False

def test_get_status(client):
    res = client.get("/api/cloud/iam/status")
    assert res.status_code == 200
    data = res.json()
    assert data["step1_completed"] is False
    assert data["scp_applied"] is False

def test_passrole_invalid_role(client):
    res = client.post("/api/cloud/iam/passrole", json={"target_role": "UnprivilegedRole"})
    assert res.status_code == 400
    assert "Target role must be a privileged role" in res.json()["detail"]

def test_passrole_success(client):
    res = client.post("/api/cloud/iam/passrole", json={"target_role": "CloudSecAdminRole", "service_type": "ec2"})
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "success"
    assert data["flag"] == "FLAG{CLOUD_IAM_PASSROLE_EC2_PRIV_ESCALATED_1120}"
    assert "ASIA" in data["carved_credentials"]["AccessKeyId"]
    st = client.get("/api/cloud/iam/status").json()
    assert st["step1_completed"] is True
    assert "AdministratorAccess" in st["effective_permissions"]

def test_assumerole_invalid_role(client):
    res = client.post("/api/cloud/iam/assumerole", json={"role_arn": "arn:aws:iam::123:role/nonexistent"})
    assert res.status_code == 400
    assert "Target role must specify the vulnerable cross-account role" in res.json()["detail"]

def test_assumerole_success(client):
    res = client.post("/api/cloud/iam/assumerole", json={"role_arn": "arn:aws:iam::123456789012:role/CrossAccountAuditRole"})
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "success"
    assert data["flag"] == "FLAG{CLOUD_STS_ASSUMEROLE_TRUST_POLICY_PWNED_2231}"
    assert "ASIA" in data["credentials"]["AccessKeyId"]
    st = client.get("/api/cloud/iam/status").json()
    assert st["step2_completed"] is True

def test_scp_harden_incomplete(client):
    res = client.post("/api/cloud/iam/scp/harden", json={"enforce_scp": True, "enforce_permission_boundary": False})
    assert res.status_code == 400
    assert "All hardening policies must be enabled" in res.json()["detail"]

def test_scp_harden_success_and_blocking(client):
    res = client.post("/api/cloud/iam/scp/harden", json={
        "enforce_scp": True,
        "enforce_permission_boundary": True,
        "restrict_passrole_resources": True
    })
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "success"
    assert data["flag"] == "FLAG{CLOUD_ORG_SCP_PERMISSION_BOUNDARY_ENFORCED_3342}"
    assert len(data["enforced_controls"]) >= 3

    # Verify passrole is blocked by SCP
    res_pass = client.post("/api/cloud/iam/passrole", json={"target_role": "CloudSecAdminRole"})
    assert res_pass.status_code == 403
    assert "AccessDeniedException" in res_pass.json()["detail"]

    # Verify assumerole is blocked by SCP
    res_assume = client.post("/api/cloud/iam/assumerole", json={"role_arn": "arn:aws:iam::123456789012:role/CrossAccountAuditRole"})
    assert res_assume.status_code == 403
    assert "AccessDeniedException" in res_assume.json()["detail"]

def test_reset_lab(client):
    client.post("/api/cloud/iam/passrole", json={"target_role": "CloudSecAdminRole"})
    st = client.get("/api/cloud/iam/status").json()
    assert st["step1_completed"] is True

    res = client.post("/api/cloud/iam/reset")
    assert res.status_code == 200
    st2 = client.get("/api/cloud/iam/status").json()
    assert st2["step1_completed"] is False
    assert st2["effective_permissions"] == "ReadOnlyAccess"
