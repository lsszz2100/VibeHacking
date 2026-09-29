"""Unit tests for Lab 29: CertPwn - AD CS & Kerberos Delegation Security Lab."""

import importlib.util
import os
import sys
from pathlib import Path
import pytest
from starlette.testclient import TestClient

LAB_DIR = Path(__file__).resolve().parent.parent
APP_PATH = LAB_DIR / "app" / "main.py"


@pytest.fixture(scope="module")
def app_module():
    spec = importlib.util.spec_from_file_location("lab29_app", str(APP_PATH))
    module = importlib.util.module_from_spec(spec)
    sys.modules["lab29_app"] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def client(app_module):
    # Reset state before each test
    client_instance = TestClient(app_module.app)
    client_instance.post("/api/adcs/reset")
    return client_instance


def test_health_check(client):
    res = client.get("/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "ok"
    assert data["port"] == 8029
    assert "CertPwn" in data["lab"]


def test_index_view(client):
    res = client.get("/")
    assert res.status_code == 200
    assert "CertPwn" in res.text
    assert "8029" in res.text
    assert "ESC1" in res.text
    assert "Kerberos" in res.text


def test_list_templates(client):
    res = client.get("/api/adcs/templates")
    assert res.status_code == 200
    data = res.json()
    assert data["domain"] == "CORP.LOCAL"
    assert data["ca_name"] == "CORP-DC-CA\\corp-DC-CA"
    assert data["count"] == 3
    tpl_names = [t["name"] for t in data["templates"]]
    assert "ESC1_WebAuth" in tpl_names
    assert "User" in tpl_names
    assert "Machine" in tpl_names


def test_step1_cert_request_non_admin(client):
    res = client.post("/api/adcs/cert/request", json={
        "template": "ESC1_WebAuth",
        "target_user": "alice@corp.local",
        "san_upn": "alice@corp.local"
    })
    assert res.status_code == 200
    data = res.json()
    assert data["success"] is True
    assert "certificate" in data
    assert data["certificate"]["san_upn"] == "alice@corp.local"
    assert "flag" not in data


def test_step1_cert_request_admin_esc1_exploit(client, app_module):
    res = client.post("/api/adcs/cert/request", json={
        "template": "ESC1_WebAuth",
        "target_user": "bob@corp.local",
        "san_upn": "administrator@corp.local"
    })
    assert res.status_code == 200
    data = res.json()
    assert data["success"] is True
    assert data["flag"] == app_module.FLAGS["step1"]
    assert "ESC1 Exploited" in data["note"]
    assert data["certificate"]["san_upn"] == "administrator@corp.local"
    assert "Client Authentication" in data["certificate"]["ekus"]


def test_step1_cert_request_nonexistent_template(client):
    res = client.post("/api/adcs/cert/request", json={
        "template": "GhostTemplate",
        "target_user": "alice@corp.local"
    })
    assert res.status_code == 404
    assert "not found" in res.json()["detail"].lower()


def test_step1_cert_request_safe_template_san_rejected(client):
    res = client.post("/api/adcs/cert/request", json={
        "template": "User",
        "target_user": "alice@corp.local",
        "san_upn": "administrator@corp.local"
    })
    assert res.status_code == 400
    data = res.json()
    assert data["success"] is False
    assert "CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT" in data["error"]


def test_step2_pkinit_invalid_pfx(client):
    res = client.post("/api/adcs/pkinit/auth", json={
        "pfx_data": "not-a-valid-base64-or-pfx",
        "realm": "CORP.LOCAL",
        "kdc_ip": "10.0.0.10"
    })
    assert res.status_code == 400


def test_step2_pkinit_realm_mismatch(client):
    res_cert = client.post("/api/adcs/cert/request", json={
        "template": "ESC1_WebAuth",
        "target_user": "alice@corp.local"
    })
    pfx_data = res_cert.json()["pfx_data"]

    res = client.post("/api/adcs/pkinit/auth", json={
        "pfx_data": pfx_data,
        "realm": "WRONG.REALM",
        "kdc_ip": "10.0.0.10"
    })
    assert res.status_code == 400
    assert "mismatch" in res.json()["detail"].lower()


def test_step2_pkinit_success_admin(client, app_module):
    # Request admin cert
    res_cert = client.post("/api/adcs/cert/request", json={
        "template": "ESC1_WebAuth",
        "target_user": "bob@corp.local",
        "san_upn": "administrator@corp.local"
    })
    pfx_data = res_cert.json()["pfx_data"]

    # Authenticate via PKINIT
    res_auth = client.post("/api/adcs/pkinit/auth", json={
        "pfx_data": pfx_data,
        "realm": "CORP.LOCAL",
        "kdc_ip": "10.0.0.10",
        "request_ntlm": True
    })
    assert res_auth.status_code == 200
    data = res_auth.json()
    assert data["success"] is True
    assert data["flag"] == app_module.FLAGS["step2"]
    assert "Pass-the-Certificate Success" in data["note"]
    assert "tgt_ticket" in data
    assert data["ntlm_hash"] == "b4d29a5342a344933a39e3381e4b9f29"
    assert data["pac"]["rid"] == 500
    assert any("Domain Admins" in g for g in data["pac"]["group_sids"])


def test_step2_pkinit_success_normal_user(client):
    res_cert = client.post("/api/adcs/cert/request", json={
        "template": "ESC1_WebAuth",
        "target_user": "alice@corp.local",
        "san_upn": "alice@corp.local"
    })
    pfx_data = res_cert.json()["pfx_data"]

    res_auth = client.post("/api/adcs/pkinit/auth", json={
        "pfx_data": pfx_data,
        "realm": "CORP.LOCAL",
        "kdc_ip": "10.0.0.10",
        "request_ntlm": True
    })
    assert res_auth.status_code == 200
    data = res_auth.json()
    assert data["success"] is True
    assert "flag" not in data
    assert data["pac"]["rid"] == 1104
    assert any("Domain Users" in g for g in data["pac"]["group_sids"])


def test_step3_delegation_simulate_unhardened(client):
    res = client.post("/api/adcs/delegation/simulate", json={
        "service_account": "svc_web$",
        "target_service": "cifs/fileserver.corp.local",
        "impersonate_user": "administrator@corp.local"
    })
    assert res.status_code == 200
    data = res.json()
    assert data["success"] is True
    assert "service_ticket" in data
    assert "SYSTEM / Enterprise Domain Admin" in data["privilege_level"]


def test_step3_hardening_partial(client):
    res = client.post("/api/adcs/delegation/harden", json={
        "protect_admin_accounts": True,
        "protected_users_group": False,
        "template_harden": True,
        "disable_esc8_ntlm_relay": False
    })
    assert res.status_code == 200
    data = res.json()
    assert data["success"] is True
    assert data["all_enforced"] is False
    assert "flag" not in data


def test_step3_hardening_all_enforced(client, app_module):
    res = client.post("/api/adcs/delegation/harden", json={
        "protect_admin_accounts": True,
        "protected_users_group": True,
        "template_harden": True,
        "disable_esc8_ntlm_relay": True
    })
    assert res.status_code == 200
    data = res.json()
    assert data["success"] is True
    assert data["all_enforced"] is True
    assert data["flag"] == app_module.FLAGS["step3"]
    assert "Hardening Complete" in data["message"]


def test_step3_delegation_blocked_after_hardening(client):
    # Enforce hardening
    client.post("/api/adcs/delegation/harden", json={
        "protect_admin_accounts": True,
        "protected_users_group": True,
        "template_harden": True,
        "disable_esc8_ntlm_relay": True
    })

    # Try impersonation
    res = client.post("/api/adcs/delegation/simulate", json={
        "service_account": "svc_web$",
        "target_service": "cifs/fileserver.corp.local",
        "impersonate_user": "administrator@corp.local"
    })
    assert res.status_code == 200
    data = res.json()
    assert data["success"] is False
    assert "USER_NOT_DELEGATED" in data["error"]


def test_step2_pkinit_blocked_under_protected_users(client):
    # First get admin certificate
    res_cert = client.post("/api/adcs/cert/request", json={
        "template": "ESC1_WebAuth",
        "target_user": "alice@corp.local",
        "san_upn": "administrator@corp.local"
    })
    pfx_data = res_cert.json()["pfx_data"]

    # Harden with Protected Users
    client.post("/api/adcs/delegation/harden", json={
        "protect_admin_accounts": True,
        "protected_users_group": True,
        "template_harden": True,
        "disable_esc8_ntlm_relay": True
    })

    # Attempt PKINIT
    res_auth = client.post("/api/adcs/pkinit/auth", json={
        "pfx_data": pfx_data,
        "realm": "CORP.LOCAL",
        "kdc_ip": "10.0.0.10"
    })
    assert res_auth.status_code == 403
    data = res_auth.json()
    assert data["success"] is False
    assert "Protected Users" in data["error"]


def test_reset_lab(client):
    # Harden lab
    client.post("/api/adcs/delegation/harden", json={
        "protect_admin_accounts": True,
        "protected_users_group": True,
        "template_harden": True,
        "disable_esc8_ntlm_relay": True
    })

    # Reset
    res_reset = client.post("/api/adcs/reset")
    assert res_reset.status_code == 200
    assert res_reset.json()["success"] is True

    # Template ESC1 should be vulnerable again
    res_tpl = client.get("/api/adcs/templates")
    esc1_tpl = next(t for t in res_tpl.json()["templates"] if t["name"] == "ESC1_WebAuth")
    assert esc1_tpl["enrollee_supplies_subject"] is True
    assert esc1_tpl["vulnerable"] is True
