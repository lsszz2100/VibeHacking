#!/usr/bin/env python3
"""
Unit tests for Lab 33: KisaAuditLab — KISA 주요정보통신기반시설 취약점 분석·평가 자동 진단 & 하드닝 랩
Tests account audit, service exploit, compliance hardening, and state reset.
"""

import sys
import importlib.util
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

# Dynamic import to avoid collision with other labs' app packages
APP_PATH = Path(__file__).resolve().parent.parent / "app" / "main.py"
spec = importlib.util.spec_from_file_location("lab33_app", str(APP_PATH))
lab33_module = importlib.util.module_from_spec(spec)
sys.modules["lab33_app"] = lab33_module
spec.loader.exec_module(lab33_module)

app = lab33_module.app
reset_lab = lab33_module.reset_lab

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
    assert data["service"] == "KisaAuditLab"
    assert data["port"] == 8033
    assert data["items_count"] == 6

def test_index_html(client):
    res = client.get("/")
    assert res.status_code == 200
    assert "text/html" in res.headers["content-type"]
    assert "KisaAuditLab" in res.text
    assert "8033" in res.text

def test_get_items(client):
    res = client.get("/api/kisa/items")
    assert res.status_code == 200
    data = res.json()
    assert data["summary"]["total"] == 6
    assert data["summary"]["vulnerable"] == 6
    assert data["summary"]["good"] == 0
    assert "U-01" in [i["code"] for i in data["items"]]
    assert "U-20" in [i["code"] for i in data["items"]]

def test_account_audit_partial_fails(client):
    payload = {
        "check_u01_root_remote": True,
        "check_u02_password_complexity": False,
        "check_u03_lockout_threshold": True,
        "check_u04_shadow_permission": True
    }
    res = client.post("/api/kisa/audit/accounts", json=payload)
    assert res.status_code == 400
    assert "전수 진단" in res.json()["detail"]

def test_account_audit_success(client):
    payload = {
        "check_u01_root_remote": True,
        "check_u02_password_complexity": True,
        "check_u03_lockout_threshold": True,
        "check_u04_shadow_permission": True
    }
    res = client.post("/api/kisa/audit/accounts", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["step"] == 1
    assert data["flag"] == "FLAG{KISA_U01_U04_ACCOUNT_AUDIT_PWNED_1109}"
    assert len(data["results"]) == 4

def test_exploit_invalid_service(client):
    res = client.post("/api/kisa/exploit/services", json={"target_service": "telnet", "action": "probe"})
    assert res.status_code == 400
    assert "유효하지 않은" in res.json()["detail"]

def test_exploit_ftp_and_ssh_step2(client):
    # Exploit FTP first
    res_ftp = client.post("/api/kisa/exploit/services", json={"target_service": "ftp", "action": "anonymous_download"})
    assert res_ftp.status_code == 200
    assert res_ftp.json()["ftp_exploited"] is True
    assert res_ftp.json()["flag"] is None

    # Exploit SSH next to trigger flag
    res_ssh = client.post("/api/kisa/exploit/services", json={"target_service": "ssh", "action": "cipher_probe"})
    assert res_ssh.status_code == 200
    data = res_ssh.json()
    assert data["ssh_exploited"] is True
    assert data["step2_completed"] is True
    assert data["flag"] == "FLAG{KISA_U20_U44_VULN_SERVICE_EXPLOITED_2241}"
    assert "3des-cbc" in data["loot"]["weak_ciphers_accepted"]

def test_harden_partial(client):
    payload = {
        "remediate_u01": True,
        "remediate_u02": False,
        "remediate_u03": True,
        "remediate_u04": True,
        "remediate_u20": True,
        "remediate_u44": True
    }
    res = client.post("/api/kisa/harden", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["compliance_status"] == "PARTIAL"
    assert data["flag"] is None

def test_harden_full_compliance(client):
    payload = {
        "remediate_u01": True,
        "remediate_u02": True,
        "remediate_u03": True,
        "remediate_u04": True,
        "remediate_u20": True,
        "remediate_u44": True
    }
    res = client.post("/api/kisa/harden", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["step"] == 3
    assert data["compliance_status"] == "COMPLIANT (100% PASS)"
    assert data["flag"] == "FLAG{KISA_HARDENING_COMPLIANCE_PASSED_3378}"
    assert len(data["hardened_items"]) == 6

    # Verify state via items API
    res_items = client.get("/api/kisa/items")
    assert res_items.json()["summary"]["good"] == 6
    assert res_items.json()["summary"]["vulnerable"] == 0

def test_exploit_blocked_after_hardening(client):
    # First harden
    client.post("/api/kisa/harden", json={
        "remediate_u01": True, "remediate_u02": True, "remediate_u03": True,
        "remediate_u04": True, "remediate_u20": True, "remediate_u44": True
    })

    # FTP exploit should now be rejected with 403
    res_ftp = client.post("/api/kisa/exploit/services", json={"target_service": "ftp", "action": "anonymous_download"})
    assert res_ftp.status_code == 403

    # SSH exploit should also be rejected with 403
    res_ssh = client.post("/api/kisa/exploit/services", json={"target_service": "ssh", "action": "cipher_probe"})
    assert res_ssh.status_code == 403

def test_reset_lab(client):
    # Harden first
    client.post("/api/kisa/harden", json={
        "remediate_u01": True, "remediate_u02": True, "remediate_u03": True,
        "remediate_u04": True, "remediate_u20": True, "remediate_u44": True
    })
    # Reset
    res = client.post("/api/kisa/reset")
    assert res.status_code == 200

    # Verify items are back to vulnerable
    res_items = client.get("/api/kisa/items")
    assert res_items.json()["summary"]["vulnerable"] == 6
    assert res_items.json()["summary"]["good"] == 0
