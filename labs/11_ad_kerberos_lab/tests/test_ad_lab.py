#!/usr/bin/env python3
"""Comprehensive Unit Tests for Lab 11 (KeroShield Active Directory & Kerberos Lab)."""

import sys
import os
import pytest
from fastapi.testclient import TestClient

# Add app dir to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "app")))

from main import app, DOMAIN_NAME, DOMAIN_SID, FLAGS, ACCOUNTS_DB

client = TestClient(app)


def test_health_check():
    """Verify health endpoint returns domain configuration."""
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "online"
    assert data["domain"] == DOMAIN_NAME
    assert data["domain_sid"] == DOMAIN_SID
    assert data["dc"] == "DC01.CORP.LOCAL"


def test_ad_objects_recon():
    """Verify directory object enumeration returns all required accounts."""
    response = client.get("/api/ad/objects")
    assert response.status_code == 200
    data = response.json()
    accounts = data["accounts"]
    assert len(accounts) >= 5

    usernames = [a["sAMAccountName"] for a in accounts]
    assert "Administrator" in usernames
    assert "krbtgt" in usernames
    assert "j.smith" in usernames
    assert "mssql_svc" in usernames
    assert "backup_svc" in usernames

    # Check vulnerability flags
    jsmith = next(a for a in accounts if a["sAMAccountName"] == "j.smith")
    assert jsmith["dont_req_preauth"] is True

    mssql = next(a for a in accounts if a["sAMAccountName"] == "mssql_svc")
    assert mssql["spn"] == "MSSQLSvc/db01.corp.local:1433"

    backup = next(a for a in accounts if a["sAMAccountName"] == "backup_svc")
    assert backup["has_replication_rights"] is True


def test_as_req_roasting_success():
    """Stage 1: AS-REQ against j.smith succeeds without pre-auth."""
    payload = {"username": "j.smith", "domain": DOMAIN_NAME}
    response = client.post("/api/kerberos/as_req", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert "$krb5asrep$23$j.smith@CORP.LOCAL:" in data["asrep_hash"]
    assert data["enc_type"] == "rc4-hmac (0x17)"
    assert "tgt_token" in data


def test_as_req_preauth_required():
    """Accounts with pre-auth required reject request without PA-DATA."""
    payload = {"username": "administrator", "domain": DOMAIN_NAME}
    response = client.post("/api/kerberos/as_req", json=payload)
    assert response.status_code == 401
    data = response.json()
    assert data["error"] == "KDC_ERR_PREAUTH_REQUIRED"
    assert data["vulnerable"] is False


def test_as_req_nonexistent_user():
    """Non-existent user triggers KDC_ERR_C_PRINCIPAL_UNKNOWN."""
    payload = {"username": "unknown_hacker_99", "domain": DOMAIN_NAME}
    response = client.post("/api/kerberos/as_req", json=payload)
    assert response.status_code == 404


def test_kerberoasting_success():
    """Stage 2: Requesting TGS for mssql_svc returns crackable TGS ticket."""
    # Obtain TGT first
    asrep_res = client.post("/api/kerberos/as_req", json={"username": "j.smith"})
    tgt_token = asrep_res.json()["tgt_token"]

    # Request TGS
    tgs_payload = {
        "tgt_token": tgt_token,
        "spn": "MSSQLSvc/db01.corp.local:1433"
    }
    response = client.post("/api/kerberos/tgs_req", json=tgs_payload)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert "$krb5tgs$23$*mssql_svc*CORP.LOCAL*" in data["tgs_hash"]
    assert data["service_account"] == "mssql_svc"


def test_kerberoasting_invalid_tgt():
    """Invalid TGT token should be rejected."""
    tgs_payload = {
        "tgt_token": "INVALID_CORRUPTED_TOKEN",
        "spn": "MSSQLSvc/db01.corp.local:1433"
    }
    response = client.post("/api/kerberos/tgs_req", json=tgs_payload)
    assert response.status_code == 400


def test_kerberoasting_unknown_spn():
    """Unknown SPN should return 404."""
    asrep_res = client.post("/api/kerberos/as_req", json={"username": "j.smith"})
    tgt_token = asrep_res.json()["tgt_token"]

    tgs_payload = {
        "tgt_token": tgt_token,
        "spn": "HTTP/fake-portal.corp.local"
    }
    response = client.post("/api/kerberos/tgs_req", json=tgs_payload)
    assert response.status_code == 404


def test_dcsync_success():
    """Stage 3: backup_svc successfully executes DCSync to dump krbtgt hash."""
    payload = {
        "username": "backup_svc",
        "password_or_hash": "BackupOperator2026!",
        "target_user": "all"
    }
    response = client.post("/api/ad/dcsync", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert "krbtgt" in data["hashes"]
    krbtgt_info = data["hashes"]["krbtgt"]
    assert krbtgt_info["ntlm"] == ACCOUNTS_DB["krbtgt"]["ntlm"]
    assert data["flag"] == FLAGS["stage3"]


def test_dcsync_insufficient_rights():
    """Account without replication ACL is denied DCSync."""
    payload = {
        "username": "j.smith",
        "password_or_hash": "Summer2025!",
        "target_user": "krbtgt"
    }
    response = client.post("/api/ad/dcsync", json=payload)
    assert response.status_code == 403


def test_dcsync_bad_password():
    """Invalid password for replication account is rejected."""
    payload = {
        "username": "backup_svc",
        "password_or_hash": "WrongPassword123!",
        "target_user": "krbtgt"
    }
    response = client.post("/api/ad/dcsync", json=payload)
    assert response.status_code == 401


def test_golden_ticket_forgery_and_admin_exec():
    """Stage 4: Forge Golden Ticket with krbtgt key and execute admin command."""
    krbtgt_hash = ACCOUNTS_DB["krbtgt"]["ntlm"]
    payload = {
        "domain": DOMAIN_NAME,
        "domain_sid": DOMAIN_SID,
        "krbtgt_hash": krbtgt_hash,
        "user_to_impersonate": "Administrator",
        "group_rid": 512
    }
    response = client.post("/api/kerberos/golden_ticket", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert data["flag"] == FLAGS["stage4"]
    ticket_blob = data["golden_ticket_ccache"]

    # Remote execution on DC01 using ticket
    exec_res = client.post(
        "/api/ad/domain_admin_exec",
        json={"command": "whoami"},
        headers={"Authorization": f"Bearer {ticket_blob}"}
    )
    assert exec_res.status_code == 200
    exec_data = exec_res.json()
    assert exec_data["status"] == "success"
    assert "Administrator" in exec_data["executed_as"]
    assert "CORP\\Administrator" in exec_data["output"]


def test_golden_ticket_invalid_krbtgt_hash():
    """Forgery with wrong krbtgt hash must fail."""
    payload = {
        "domain": DOMAIN_NAME,
        "domain_sid": DOMAIN_SID,
        "krbtgt_hash": "00000000000000000000000000000000",
        "user_to_impersonate": "Administrator"
    }
    response = client.post("/api/kerberos/golden_ticket", json=payload)
    assert response.status_code == 401


def test_domain_admin_exec_no_auth():
    """Admin execution without authorization header is rejected."""
    response = client.post("/api/ad/domain_admin_exec", json={"command": "whoami"})
    assert response.status_code == 401


def test_flag_submissions():
    """Verify all 4 stage flags pass validation and invalid flags fail."""
    for stage, flag in FLAGS.items():
        res = client.post("/api/flags/submit", json={"flag": flag})
        assert res.status_code == 200
        assert res.json()["correct"] is True
        assert res.json()["stage"] == stage

    bad_res = client.post("/api/flags/submit", json={"flag": "FLAG{FAKE_FLAG_1234}"})
    assert bad_res.status_code == 200
    assert bad_res.json()["correct"] is False


def test_terminal_simulator_tools():
    """Verify interactive command emulator returns appropriate tool output."""
    tools = [
        ("help", "KeroShield Simulated AD Pentest Toolkit"),
        ("users", "j.smith"),
        ("spns", "MSSQLSvc/db01.corp.local:1433"),
        ("GetNPUsers.py -no-pass", "$krb5asrep$23$"),
        ("GetUserSPNs.py -request", "$krb5tgs$23$"),
        ("secretsdump.py -just-dc-ntlm backup_svc:BackupOperator2026!", "krbtgt:502:"),
        (f"ticketer.py -nthash {ACCOUNTS_DB['krbtgt']['ntlm']} -domain-sid {DOMAIN_SID}", "Golden Ticket"),
        ("psexec.py -k", "CORP\\Administrator"),
        ("john asrep.hash", "Summer2025!"),
        ("hashcat -m 13100 tgs.hash", "Password123!"),
        ("bloodhound", "Attack Graph"),
        ("audit", "EventID")
    ]
    for cmd, expected_substring in tools:
        res = client.post("/api/terminal/execute", json={"command": cmd})
        assert res.status_code == 200
        out = res.json()["output"]
        assert expected_substring in out, f"Command '{cmd}' did not contain '{expected_substring}' in '{out}'"
