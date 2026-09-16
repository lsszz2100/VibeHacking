#!/usr/bin/env python3
"""Tests for Lab 05 (Full Scenario APT Integration Lab - Internal API)."""

import importlib.util
import os
import sys
import pytest

_app_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "internal-api", "app.py"))
_spec = importlib.util.spec_from_file_location("scenario_internal_mod", _app_path)
_mod = importlib.util.module_from_spec(_spec)
sys.modules["scenario_internal_mod"] = _mod
_spec.loader.exec_module(_mod)

app = _mod.app


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


def test_health_check(client):
    res = client.get("/health")
    assert res.status_code == 200
    data = res.get_json()
    assert data["status"] == "ok"
    assert "db_host" in data


def test_users_leak_flag(client):
    res = client.get("/users")
    assert res.status_code == 200
    data = res.get_json()
    assert len(data["users"]) >= 4
    assert data["flag"] == _mod.SECRET_FLAG


def test_config_credentials_leak(client):
    res = client.get("/config")
    assert res.status_code == 200
    data = res.get_json()
    assert "database" in data
    assert "ldap" in data
    assert data["database"]["password"] == _mod.DB_PASS
