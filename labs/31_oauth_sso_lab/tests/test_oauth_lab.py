"""
Unit and integration tests for Lab 31: SSOShield (OAuth 2.0 & OIDC Exploitation)
"""

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
    spec = importlib.util.spec_from_file_location("lab31_app", str(APP_PATH))
    module = importlib.util.module_from_spec(spec)
    sys.modules["lab31_app"] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def client(app_module):
    client_instance = TestClient(app_module.app)
    client_instance.post("/api/oauth/reset")
    return client_instance


def test_health_check(client):
    res = client.get("/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "ok"
    assert data["port"] == 8031
    assert "SSOShield" in data["lab"]


def test_openid_configuration_discovery(client):
    res = client.get("/api/oauth/.well-known/openid-configuration")
    assert res.status_code == 200
    data = res.json()
    assert "issuer" in data
    assert "authorization_endpoint" in data
    assert "token_endpoint" in data
    assert "jwks_uri" in data
    assert "RS256" in data["id_token_signing_alg_values_supported"]


def test_jwks_endpoint(client):
    res = client.get("/api/oauth/jwks.json")
    assert res.status_code == 200
    data = res.json()
    assert "keys" in data
    assert len(data["keys"]) >= 1
    key = data["keys"][0]
    assert key["kty"] == "RSA"
    assert key["kid"] == "idp-primary-rsa-2026"
    assert "n" in key and "e" in key


def test_lab_info_endpoint(client):
    res = client.get("/api/oauth/info")
    assert res.status_code == 200
    data = res.json()
    assert data["lab_id"] == 31
    assert data["hardened"] is False
    assert "corp-internal-crm" in data["active_clients"]
    assert "admin" in data["registered_users"]


def test_html_index_page(client):
    res = client.get("/")
    assert res.status_code == 200
    assert "text/html" in res.headers["content-type"]
    assert "SSOShield" in res.text
    assert "OAuth 2.0" in res.text


def test_authorize_endpoint_valid_flow(client):
    params = {
        "response_type": "code",
        "client_id": "corp-internal-crm",
        "redirect_uri": "https://crm.corp-app.com/oauth/callback",
        "scope": "openid profile",
        "state_param": "csrf_token_xyz"
    }
    res = client.get("/api/oauth/authorize", params=params)
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "success"
    assert "code_" in data["auth_code"]
    assert "code=" in data["redirect_to"]


def test_authorize_endpoint_invalid_client(client):
    params = {
        "response_type": "code",
        "client_id": "nonexistent-client",
        "redirect_uri": "https://crm.corp-app.com/oauth/callback"
    }
    res = client.get("/api/oauth/authorize", params=params)
    assert res.status_code == 400
    assert "Invalid client_id" in res.json()["detail"]


def test_authorize_endpoint_invalid_redirect(client):
    params = {
        "response_type": "code",
        "client_id": "corp-internal-crm",
        "redirect_uri": "https://completely-unrelated-evil.com/callback"
    }
    res = client.get("/api/oauth/authorize", params=params)
    assert res.status_code == 400
    assert "Invalid redirect_uri" in res.json()["detail"]


def test_step1_redirect_bypass_success(client, app_module):
    payload = {
        "client_id": "corp-internal-crm",
        "redirect_uri": "https://attacker-corp-app.com/leak/callback",
        "target_user": "admin"
    }
    res = client.post("/api/oauth/exploit/redirect-bypass", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["success"] is True
    assert data["step"] == 1
    assert "leaked_code_" in data["intercepted_code"]
    assert data["flag"] == "FLAG{OAUTH_REDIRECT_URI_LEAK_7712}"
    assert app_module.state.solved_steps["step1"] is True


def test_step1_redirect_bypass_legitimate_fails(client):
    payload = {
        "client_id": "corp-internal-crm",
        "redirect_uri": "https://crm.corp-app.com/oauth/callback",
        "target_user": "admin"
    }
    res = client.post("/api/oauth/exploit/redirect-bypass", json=payload)
    assert res.status_code == 400
    assert "legitimate redirect URI" in res.json()["detail"]


def test_step1_redirect_bypass_unmatched_domain_fails(client):
    payload = {
        "client_id": "corp-internal-crm",
        "redirect_uri": "https://hacker.com/stolen",
        "target_user": "admin"
    }
    res = client.post("/api/oauth/exploit/redirect-bypass", json=payload)
    assert res.status_code == 400
    assert "Bypass failed" in res.json()["detail"]


def test_step2_pkce_downgrade_success(client, app_module):
    # First get an intercepted code from Step 1
    s1_res = client.post("/api/oauth/exploit/redirect-bypass", json={
        "client_id": "corp-internal-crm",
        "redirect_uri": "https://attacker-corp-app.com/callback",
        "target_user": "admin"
    })
    auth_code = s1_res.json()["intercepted_code"]

    # Now perform PKCE downgrade
    s2_res = client.post("/api/oauth/exploit/pkce-downgrade", json={
        "auth_code": auth_code,
        "client_id": "corp-internal-crm",
        "omit_verifier": True
    })
    assert s2_res.status_code == 200
    data = s2_res.json()
    assert data["success"] is True
    assert data["step"] == 2
    assert "at_" in data["access_token"]
    assert "id_token" in data
    assert data["authenticated_user"] == "admin"
    assert data["flag"] == "FLAG{OAUTH_PKCE_DOWNGRADE_CSRF_8823}"
    assert app_module.state.solved_steps["step2"] is True


def test_step2_pkce_downgrade_replay_prevention(client):
    s1_res = client.post("/api/oauth/exploit/redirect-bypass", json={
        "client_id": "corp-internal-crm",
        "redirect_uri": "https://attacker-corp-app.com/callback"
    })
    auth_code = s1_res.json()["intercepted_code"]

    # First exchange succeeds
    res1 = client.post("/api/oauth/exploit/pkce-downgrade", json={
        "auth_code": auth_code,
        "client_id": "corp-internal-crm"
    })
    assert res1.status_code == 200

    # Second exchange with same code must fail
    res2 = client.post("/api/oauth/exploit/pkce-downgrade", json={
        "auth_code": auth_code,
        "client_id": "corp-internal-crm"
    })
    assert res2.status_code == 400
    assert "already been consumed" in res2.json()["detail"]


def test_step2_pkce_downgrade_invalid_code(client):
    res = client.post("/api/oauth/exploit/pkce-downgrade", json={
        "auth_code": "fake_invalid_code",
        "client_id": "corp-internal-crm"
    })
    assert res.status_code == 400
    assert "Invalid or unknown auth_code" in res.json()["detail"]


def test_step3_jwt_key_confusion_admin_takeover(client, app_module):
    payload = {
        "target_user": "admin",
        "kid_header": "attacker-injected-key-1337",
        "signature_algorithm": "HS256",
        "forged_role": "enterprise_admin"
    }
    res = client.post("/api/oauth/exploit/jwt-key-confusion", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["success"] is True
    assert data["step"] == 3
    assert "forged_id_token" in data
    assert data["session"]["authenticated_as"] == "admin"
    assert data["session"]["assigned_role"] == "enterprise_admin"
    assert "ENTERPRISE_ADMIN" in data["session"]["privileges"]
    assert data["flag"] == "FLAG{OAUTH_IDTOKEN_KEY_CONFUSION_9934}"
    assert app_module.state.solved_steps["step3"] is True


def test_harden_endpoint(client):
    res = client.post("/api/oauth/harden")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "success"
    assert data["hardened"] is True
    assert len(data["active_defenses"]) == 4

    info = client.get("/api/oauth/info").json()
    assert info["hardened"] is True
    assert info["security_config"]["strict_redirect_validation"] is True
    assert info["security_config"]["enforce_pkce_s256"] is True


def test_hardened_blocks_all_exploits(client):
    # Harden first
    client.post("/api/oauth/harden")

    # Step 1 must be blocked
    s1 = client.post("/api/oauth/exploit/redirect-bypass", json={
        "client_id": "corp-internal-crm",
        "redirect_uri": "https://attacker-corp-app.com/callback"
    })
    assert s1.status_code == 403
    assert "Strict redirect_uri exact matching is enabled" in s1.json()["detail"]

    # Step 2 must be blocked
    s2 = client.post("/api/oauth/exploit/pkce-downgrade", json={
        "auth_code": "dummy_code",
        "client_id": "corp-internal-crm"
    })
    assert s2.status_code == 403
    assert "Mandatory S256 PKCE verification strictly enforced" in s2.json()["detail"]

    # Step 3 must be blocked
    s3 = client.post("/api/oauth/exploit/jwt-key-confusion", json={
        "target_user": "admin"
    })
    assert s3.status_code == 403
    assert "Strict JWKS asymmetric key pinning enforced" in s3.json()["detail"]


def test_hardened_authorize_enforces_strict_matching_and_pkce(client):
    client.post("/api/oauth/harden")

    # Loose redirect fails
    res1 = client.get("/api/oauth/authorize", params={
        "response_type": "code",
        "client_id": "corp-internal-crm",
        "redirect_uri": "https://attacker-corp-app.com/callback"
    })
    assert res1.status_code == 400
    assert "does not match registered whitelist strictly" in res1.json()["detail"]

    # Missing state parameter fails
    res2 = client.get("/api/oauth/authorize", params={
        "response_type": "code",
        "client_id": "corp-internal-crm",
        "redirect_uri": "https://crm.corp-app.com/oauth/callback"
    })
    assert res2.status_code == 400
    assert "'state' parameter is mandatory" in res2.json()["detail"]

    # Missing S256 PKCE fails
    res3 = client.get("/api/oauth/authorize", params={
        "response_type": "code",
        "client_id": "corp-internal-crm",
        "redirect_uri": "https://crm.corp-app.com/oauth/callback",
        "state_param": "valid_csrf_state"
    })
    assert res3.status_code == 400
    assert "PKCE code_challenge with method S256 is strictly enforced" in res3.json()["detail"]


def test_reset_endpoint(client):
    client.post("/api/oauth/harden")
    assert client.get("/api/oauth/info").json()["hardened"] is True

    res = client.post("/api/oauth/reset")
    assert res.status_code == 200
    assert res.json()["hardened"] is False

    info = client.get("/api/oauth/info").json()
    assert info["hardened"] is False
    assert info["security_config"]["strict_redirect_validation"] is False
