#!/usr/bin/env python3
"""
Unit and integration test suite for Lab 44: ExtensionGuard — Browser Extension Security Lab
Verifies:
- HTML dashboard serving
- Manifest V3 permission audit & service worker verification
- Web Accessible Resources (WAR) cross-context leakage and extraction
- Content script DOM-based XSS & password harvesting triage
- Declarative Net Request (DNR) migration & extension CSP hardening
- Stage gating, security validation, and state reset
"""

import sys
import importlib.util
from pathlib import Path
import pytest
from starlette.testclient import TestClient

APP_PATH = Path(__file__).resolve().parent.parent / "app" / "main.py"
spec = importlib.util.spec_from_file_location("lab44_app", str(APP_PATH))
lab44_module = importlib.util.module_from_spec(spec)
sys.modules["lab44_app"] = lab44_module
spec.loader.exec_module(lab44_module)

app = lab44_module.app
STAGE1_FLAG = lab44_module.STAGE1_FLAG
STAGE2_FLAG = lab44_module.STAGE2_FLAG
STAGE3_FLAG = lab44_module.STAGE3_FLAG
STAGE4_FLAG = lab44_module.STAGE4_FLAG

client = TestClient(app)


@pytest.fixture(autouse=True)
def reset_simulation_state():
    """Reset simulation state before each test run."""
    client.post("/api/v1/reset")
    yield
    client.post("/api/v1/reset")


def test_root_html_page():
    res = client.get("/")
    assert res.status_code == 200
    assert "Lab 44: ExtensionGuard" in res.text
    assert "Manifest V3" in res.text
    assert "Web Accessible Resources" in res.text


def test_status_endpoint_initial():
    res = client.get("/api/v1/status")
    assert res.status_code == 200
    data = res.json()
    assert data["lab"] == "Lab 44: ExtensionGuard"
    assert not data["all_stages_solved"]
    assert not data["stages"]["stage1_manifest_audit"]["solved"]
    assert not data["stages"]["stage2_war_context_leak"]["solved"]
    assert not data["stages"]["stage3_content_script_xss"]["solved"]
    assert not data["stages"]["stage4_dnr_csp_hardening"]["solved"]
    assert data["hardened_posture"]["use_declarative_net_request"] is False


def test_manifest_fetch():
    res = client.get("/api/v1/extension/manifest")
    assert res.status_code == 200
    manifest = res.json()
    assert manifest["manifest_version"] == 3
    assert "webRequestBlocking" in manifest["permissions"]
    assert manifest["background"]["service_worker"] == "background.js"


def test_manifest_audit_invalid_version():
    res = client.post("/api/v1/extension/manifest-audit", json={
        "manifest_version": 2,
        "overprivileged_permissions": ["<all_urls>", "webRequestBlocking", "cookies"],
        "service_worker": "background.js"
    })
    assert res.status_code == 400
    assert "Manifest V3" in res.json()["detail"]


def test_manifest_audit_missing_permissions():
    res = client.post("/api/v1/extension/manifest-audit", json={
        "manifest_version": 3,
        "overprivileged_permissions": ["tabs"],
        "service_worker": "background.js"
    })
    assert res.status_code == 400
    assert "Incomplete permission audit" in res.json()["detail"]


def test_manifest_audit_invalid_service_worker():
    res = client.post("/api/v1/extension/manifest-audit", json={
        "manifest_version": 3,
        "overprivileged_permissions": ["<all_urls>", "webRequestBlocking", "cookies"],
        "service_worker": "wrong_worker.js"
    })
    assert res.status_code == 400
    assert "Invalid background service worker" in res.json()["detail"]


def test_manifest_audit_success():
    res = client.post("/api/v1/extension/manifest-audit", json={
        "manifest_version": 3,
        "overprivileged_permissions": ["<all_urls>", "webRequestBlocking", "cookies", "storage"],
        "service_worker": "background.js"
    })
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "success"
    assert data["stage"] == 1
    assert data["flag"] == STAGE1_FLAG


def test_war_probe_and_fetch_resource():
    res = client.get("/api/v1/extension/war-probe")
    assert res.status_code == 200
    assert "assets/auth_config.json" in res.json()["available_files"]

    res_asset = client.get("/api/v1/extension/resource/assets/auth_config.json")
    assert res_asset.status_code == 200
    assert res_asset.json()["master_token"] == "EXT_AUTH_TOKEN_779922AA"


def test_war_fetch_nonexistent_resource():
    res = client.get("/api/v1/extension/resource/assets/non_existent.json")
    assert res.status_code == 404


def test_war_leak_gating_without_stage1():
    res = client.post("/api/v1/extension/leak-token", json={
        "target_file": "assets/auth_config.json",
        "extracted_token": "EXT_AUTH_TOKEN_779922AA",
        "fix_action": "RESTRICT_MATCHES"
    })
    assert res.status_code == 403
    assert "Complete Stage 1" in res.json()["detail"]


def test_war_leak_invalid_token():
    # Pass stage 1
    client.post("/api/v1/extension/manifest-audit", json={
        "manifest_version": 3,
        "overprivileged_permissions": ["<all_urls>", "webRequestBlocking", "cookies"],
        "service_worker": "background.js"
    })
    res = client.post("/api/v1/extension/leak-token", json={
        "target_file": "assets/auth_config.json",
        "extracted_token": "WRONG_TOKEN",
        "fix_action": "RESTRICT_MATCHES"
    })
    assert res.status_code == 400
    assert "WAR verification failed" in res.json()["detail"]


def test_war_leak_success():
    # Pass stage 1
    client.post("/api/v1/extension/manifest-audit", json={
        "manifest_version": 3,
        "overprivileged_permissions": ["<all_urls>", "webRequestBlocking", "cookies"],
        "service_worker": "background.js"
    })
    res = client.post("/api/v1/extension/leak-token", json={
        "target_file": "assets/auth_config.json",
        "extracted_token": "EXT_AUTH_TOKEN_779922AA",
        "fix_action": "RESTRICT_MATCHES"
    })
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "success"
    assert data["stage"] == 2
    assert data["flag"] == STAGE2_FLAG


def test_content_script_fetch():
    res = client.get("/api/v1/extension/content-script")
    assert res.status_code == 200
    content = res.json()["content_script"]
    assert "promoDiv.innerHTML" in content
    assert "harvested_password" in content


def test_content_script_gating_without_stage2():
    res = client.post("/api/v1/extension/exploit-dom", json={
        "vulnerability": "DOM_XSS_INNERHTML",
        "harvested_credential_field": "password",
        "sink": "document.body.innerHTML"
    })
    assert res.status_code == 403
    assert "Complete Stage 2" in res.json()["detail"]


def test_content_script_exploit_failure():
    # Pass stage 1 & 2
    client.post("/api/v1/extension/manifest-audit", json={
        "manifest_version": 3,
        "overprivileged_permissions": ["<all_urls>", "webRequestBlocking", "cookies"],
        "service_worker": "background.js"
    })
    client.post("/api/v1/extension/leak-token", json={
        "target_file": "assets/auth_config.json",
        "extracted_token": "EXT_AUTH_TOKEN_779922AA",
        "fix_action": "RESTRICT_MATCHES"
    })
    res = client.post("/api/v1/extension/exploit-dom", json={
        "vulnerability": "SQL_INJECTION",
        "harvested_credential_field": "password",
        "sink": "document.body.innerHTML"
    })
    assert res.status_code == 400


def test_content_script_exploit_success():
    # Pass stage 1 & 2
    client.post("/api/v1/extension/manifest-audit", json={
        "manifest_version": 3,
        "overprivileged_permissions": ["<all_urls>", "webRequestBlocking", "cookies"],
        "service_worker": "background.js"
    })
    client.post("/api/v1/extension/leak-token", json={
        "target_file": "assets/auth_config.json",
        "extracted_token": "EXT_AUTH_TOKEN_779922AA",
        "fix_action": "RESTRICT_MATCHES"
    })
    res = client.post("/api/v1/extension/exploit-dom", json={
        "vulnerability": "DOM_XSS_INNERHTML",
        "harvested_credential_field": "password",
        "sink": "promoDiv.innerHTML"
    })
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "success"
    assert data["stage"] == 3
    assert data["flag"] == STAGE3_FLAG


def test_hardening_gating_without_stage3():
    res = client.post("/api/v1/extension/harden", json={
        "use_declarative_net_request": True,
        "enforce_isolated_world": True,
        "strict_extension_csp": True,
        "disable_remote_code_execution": True
    })
    assert res.status_code == 403
    assert "Complete Stage 3" in res.json()["detail"]


def test_hardening_incomplete():
    # Pass stage 1, 2, 3
    client.post("/api/v1/extension/manifest-audit", json={
        "manifest_version": 3,
        "overprivileged_permissions": ["<all_urls>", "webRequestBlocking", "cookies"],
        "service_worker": "background.js"
    })
    client.post("/api/v1/extension/leak-token", json={
        "target_file": "assets/auth_config.json",
        "extracted_token": "EXT_AUTH_TOKEN_779922AA",
        "fix_action": "RESTRICT_MATCHES"
    })
    client.post("/api/v1/extension/exploit-dom", json={
        "vulnerability": "DOM_XSS_INNERHTML",
        "harvested_credential_field": "password",
        "sink": "promoDiv.innerHTML"
    })
    res = client.post("/api/v1/extension/harden", json={
        "use_declarative_net_request": False,
        "enforce_isolated_world": True,
        "strict_extension_csp": True,
        "disable_remote_code_execution": True
    })
    assert res.status_code == 400


def test_hardening_success():
    # Pass stage 1, 2, 3
    client.post("/api/v1/extension/manifest-audit", json={
        "manifest_version": 3,
        "overprivileged_permissions": ["<all_urls>", "webRequestBlocking", "cookies"],
        "service_worker": "background.js"
    })
    client.post("/api/v1/extension/leak-token", json={
        "target_file": "assets/auth_config.json",
        "extracted_token": "EXT_AUTH_TOKEN_779922AA",
        "fix_action": "RESTRICT_MATCHES"
    })
    client.post("/api/v1/extension/exploit-dom", json={
        "vulnerability": "DOM_XSS_INNERHTML",
        "harvested_credential_field": "password",
        "sink": "promoDiv.innerHTML"
    })
    res = client.post("/api/v1/extension/harden", json={
        "use_declarative_net_request": True,
        "enforce_isolated_world": True,
        "strict_extension_csp": True,
        "disable_remote_code_execution": True
    })
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "success"
    assert data["stage"] == 4
    assert data["flag"] == STAGE4_FLAG


def test_full_chain_and_status():
    # 1. Audit
    client.post("/api/v1/extension/manifest-audit", json={
        "manifest_version": 3,
        "overprivileged_permissions": ["<all_urls>", "webRequestBlocking", "cookies"],
        "service_worker": "background.js"
    })
    # 2. WAR Leak
    client.post("/api/v1/extension/leak-token", json={
        "target_file": "assets/auth_config.json",
        "extracted_token": "EXT_AUTH_TOKEN_779922AA",
        "fix_action": "RESTRICT_MATCHES"
    })
    # 3. DOM Exploit
    client.post("/api/v1/extension/exploit-dom", json={
        "vulnerability": "DOM_XSS_INNERHTML",
        "harvested_credential_field": "password",
        "sink": "promoDiv.innerHTML"
    })
    # 4. Harden
    client.post("/api/v1/extension/harden", json={
        "use_declarative_net_request": True,
        "enforce_isolated_world": True,
        "strict_extension_csp": True,
        "disable_remote_code_execution": True
    })

    # Verify status
    res = client.get("/api/v1/status")
    assert res.status_code == 200
    status_data = res.json()
    assert status_data["all_stages_solved"] is True
    assert status_data["stages"]["stage1_manifest_audit"]["flag"] == STAGE1_FLAG
    assert status_data["stages"]["stage2_war_context_leak"]["flag"] == STAGE2_FLAG
    assert status_data["stages"]["stage3_content_script_xss"]["flag"] == STAGE3_FLAG
    assert status_data["stages"]["stage4_dnr_csp_hardening"]["flag"] == STAGE4_FLAG


def test_reset_endpoint():
    # Solve stage 1
    client.post("/api/v1/extension/manifest-audit", json={
        "manifest_version": 3,
        "overprivileged_permissions": ["<all_urls>", "webRequestBlocking", "cookies"],
        "service_worker": "background.js"
    })
    res = client.get("/api/v1/status")
    assert res.json()["stages"]["stage1_manifest_audit"]["solved"] is True

    # Reset
    res_reset = client.post("/api/v1/reset")
    assert res_reset.status_code == 200
    res_after = client.get("/api/v1/status")
    assert res_after.json()["stages"]["stage1_manifest_audit"]["solved"] is False
