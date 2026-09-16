#!/usr/bin/env python3
"""Tests for Lab 06 (Firmware Hacking Lab - Web Panel)."""

import importlib.util
import os
import sys
import pytest

_app_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "firmware_panel.py"))
_spec = importlib.util.spec_from_file_location("firmware_panel_mod", _app_path)
_mod = importlib.util.module_from_spec(_spec)
sys.modules["firmware_panel_mod"] = _mod
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
    assert "Firmware Update Panel" in res.data.decode("utf-8")


def test_login_invalid_creds(client):
    res = client.post("/login", json={"user": "admin", "pass": "wrongpassword"})
    assert res.status_code == 401
    assert res.get_json()["status"] == "fail"


def test_login_valid_hardcoded_creds(client):
    res = client.post("/login", json={"user": "admin", "pass": "firmware_admin_2024"})
    assert res.status_code == 200
    data = res.get_json()
    assert data["status"] == "ok"
    assert data["flag"] == _mod.FLAG


def test_upload_endpoint(client):
    res = client.post("/upload")
    assert res.status_code == 200
    assert res.get_json()["status"] == "uploaded"
