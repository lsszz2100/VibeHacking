#!/usr/bin/env python3
"""
Unit tests for Lab 36: DBShield — Enterprise Database Security Lab
Tests Second-Order SQLi, UDF Dynamic Library Injection, Enterprise Hardening, and State Reset.
"""

import sys
import importlib.util
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

# Dynamic import to avoid collision with other labs' app packages
APP_PATH = Path(__file__).resolve().parent.parent / "app" / "main.py"
spec = importlib.util.spec_from_file_location("lab36_app", str(APP_PATH))
lab36_module = importlib.util.module_from_spec(spec)
sys.modules["lab36_app"] = lab36_module
spec.loader.exec_module(lab36_module)

app = lab36_module.app
reset_lab = lab36_module.reset_lab

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
    assert data["lab"] == "36_enterprise_database_security_lab"
    assert data["port"] == 8036
    assert data["step1_completed"] is False
    assert data["step2_completed"] is False
    assert data["step3_completed"] is False

def test_index_html(client):
    res = client.get("/")
    assert res.status_code == 200
    assert "text/html" in res.headers["content-type"]
    assert "Lab 36: Enterprise Database Security" in res.text
    assert "8036" in res.text

def test_get_db_status(client):
    res = client.get("/api/db/status")
    assert res.status_code == 200
    data = res.json()
    assert "MySQL" in data["engine"]
    assert data["udf_enabled"] is True
    assert data["audit_enabled"] is False

def test_register_profile(client):
    res = client.post("/api/db/register", json={
        "username": "tester01",
        "nickname_payload": "alice",
        "email": "alice@vibe.local"
    })
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "success"
    assert data["stored_nickname"] == "alice"

def test_password_reset_user_not_found(client):
    res = client.post("/api/db/password-reset", json={
        "username": "non_existent_user"
    })
    assert res.status_code == 404

def test_password_reset_normal_no_sqli(client):
    client.post("/api/db/register", json={
        "username": "bob",
        "nickname_payload": "regular_bob"
    })
    res = client.post("/api/db/password-reset", json={"username": "bob"})
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "normal"
    assert "regular_bob" in data["executed_query"]

def test_second_order_sqli_exploit_step1(client):
    # Phase 1: Store malicious nickname
    client.post("/api/db/register", json={
        "username": "sqli_attacker",
        "nickname_payload": "admin' OR 1=1 --",
        "email": "attacker@vibe.local"
    })
    # Phase 2: Trigger reset query
    res = client.post("/api/db/password-reset", json={"username": "sqli_attacker"})
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "exploited"
    assert "FLAG{DB_SECOND_ORDER_SQLI_METADATA_EXFIL_8831}" in data["flag"]
    assert "extracted_dba_hash" in data

    # Verify state
    health = client.get("/health").json()
    assert health["step1_completed"] is True

def test_udf_install(client):
    res = client.post("/api/db/udf-install", json={
        "function_name": "sys_eval",
        "library_name": "raptor_udf2.so"
    })
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "installed"
    assert "sys_eval" in data["message"]

def test_udf_exec_not_installed_error(client):
    res = client.post("/api/db/udf-exec", json={
        "function_name": "non_existent_udf",
        "cmd": "whoami"
    })
    assert res.status_code == 400

def test_udf_exec_whoami_root_step2(client):
    # Install first
    client.post("/api/db/udf-install", json={"function_name": "sys_eval"})
    # Execute root cmd
    res = client.post("/api/db/udf-exec", json={
        "function_name": "sys_eval",
        "cmd": "whoami"
    })
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "success"
    assert "root" in data["stdout"]
    assert "FLAG{DB_UDF_LIBRARY_INJECTION_ROOT_RCE_7492}" in data["flag"]

    health = client.get("/health").json()
    assert health["step2_completed"] is True

def test_udf_exec_shadow_dump(client):
    client.post("/api/db/udf-install", json={"function_name": "sys_eval"})
    res = client.post("/api/db/udf-exec", json={
        "function_name": "sys_eval",
        "cmd": "cat /etc/shadow"
    })
    assert res.status_code == 200
    assert "RootShadowHash" in res.json()["stdout"]

def test_harden_incomplete_error(client):
    res = client.post("/api/db/harden", json={
        "enable_prepared_statements": True,
        "enforce_secure_file_priv": False,
        "isolate_least_privilege": True,
        "enable_fga_audit": True
    })
    assert res.status_code == 400

def test_harden_enforce_all_step3(client):
    res = client.post("/api/db/harden", json={
        "enable_prepared_statements": True,
        "enforce_secure_file_priv": True,
        "isolate_least_privilege": True,
        "enable_fga_audit": True
    })
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "hardened"
    assert "FLAG{DB_AUDIT_LOG_TDE_LEAST_PRIVILEGE_SECURED_3914}" in data["flag"]

    health = client.get("/health").json()
    assert health["step3_completed"] is True
    assert health["harden_applied"] is True

def test_post_hardening_blocks_attacks(client):
    # Apply hardening
    client.post("/api/db/harden", json={
        "enable_prepared_statements": True,
        "enforce_secure_file_priv": True,
        "isolate_least_privilege": True,
        "enable_fga_audit": True
    })
    # Attempt UDF install -> should fail with 403
    udf_res = client.post("/api/db/udf-install", json={"function_name": "sys_eval"})
    assert udf_res.status_code == 403

    # Attempt Second-order SQLi -> should be safely handled
    client.post("/api/db/register", json={
        "username": "evil",
        "nickname_payload": "admin' OR 1=1 --"
    })
    reset_res = client.post("/api/db/password-reset", json={"username": "evil"})
    assert reset_res.status_code == 200
    assert reset_res.json()["status"] == "success"
    assert "safely via parameterized" in reset_res.json()["message"]

def test_audit_logs(client):
    client.post("/api/db/register", json={"username": "audited_user", "nickname_payload": "test"})
    res = client.get("/api/db/audit-logs")
    assert res.status_code == 200
    data = res.json()
    assert data["total_events"] >= 1
    assert any("audited_user" in e["user"] for e in data["events"])
