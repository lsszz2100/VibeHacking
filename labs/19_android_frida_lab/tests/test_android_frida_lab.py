#!/usr/bin/env python3
"""Tests for Lab 19: Android Security & Frida Dynamic Hooking Lab (DroidShield)."""

import importlib.util
import os
import sys
import pytest
from starlette.testclient import TestClient

_app_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "app", "main.py"))
_spec = importlib.util.spec_from_file_location("droidshield_lab_main", _app_path)
_mod = importlib.util.module_from_spec(_spec)
sys.modules["droidshield_lab_main"] = _mod
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
    assert len(data["missions"]) == 4
    assert "DroidShield" in data["lab"]
    assert "c2_hint" in data


def test_dashboard_served(client):
    res = client.get("/")
    assert res.status_code == 200
    assert "text/html" in res.headers["content-type"]
    assert "DroidShield" in res.text
    assert "Mission 1" in res.text


def test_mission1_root_detection_blocked(client):
    res = client.post("/api/mission1/verify_device", json={
        "build_tags": "test-keys",
        "su_binary_present": True,
        "installed_packages": ["com.topjohnwu.magisk"],
        "frida_hook_applied": False,
    })
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "blocked"
    assert data["is_rooted"] is True
    assert "detected_triggers" in data


def test_mission1_root_detection_bypassed(client):
    res = client.post("/api/mission1/verify_device", json={
        "build_tags": "test-keys",
        "su_binary_present": True,
        "installed_packages": ["com.topjohnwu.magisk"],
        "frida_hook_applied": True,
    })
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "success"
    assert data["is_rooted"] is False
    assert "FLAG{dr01d_r00t_byp4ss" in data["flag"]


def test_mission2_ssl_pinning(client):
    # 1. Invalid certificate without unpinning hook
    res = client.post("/api/mission2/verify_ssl", json={
        "server_hostname": "api.bankshield.internal",
        "cert_sha256": "INVALID_PROXY_BURP_CERT",
        "frida_unpin_hook": False,
    })
    assert res.status_code == 200
    assert res.json()["status"] == "error"

    # 2. Frida unpinning activated
    res_bypassed = client.post("/api/mission2/verify_ssl", json={
        "server_hostname": "api.bankshield.internal",
        "cert_sha256": "INVALID_PROXY_BURP_CERT",
        "frida_unpin_hook": True,
    })
    assert res_bypassed.status_code == 200
    data = res_bypassed.json()
    assert data["status"] == "success"
    assert "FLAG{ss1_p1nn1ng_fr1da" in data["flag"]


def test_mission3_native_license(client):
    # 1. Invalid key, no hook
    res_fail = client.post("/api/mission3/native_license", json={
        "license_key": "WRONG_KEY",
        "hook_native_return": False,
    })
    assert res_fail.status_code == 200
    assert res_fail.json()["status"] == "unauthorized"

    # 2. Native Interceptor hook applied
    res_hook = client.post("/api/mission3/native_license", json={
        "license_key": "ANY_KEY",
        "hook_native_return": True,
    })
    assert res_hook.status_code == 200
    assert res_hook.json()["status"] == "success"
    assert "FLAG{jn1_n4t1v3_h00k" in res_hook.json()["flag"]


def test_mission4_c2_deobfuscation(client):
    # 1. Incorrect command
    res_fail = client.post("/api/mission4/c2_command", json={"command": "HELP"})
    assert res_fail.status_code == 200
    assert res_fail.json()["status"] == "rejected"

    # 2. Deobfuscated valid command
    res_ok = client.post("/api/mission4/c2_command", json={"command": "STOP_EXFILTRATION_OVERRIDE"})
    assert res_ok.status_code == 200
    data = res_ok.json()
    assert data["status"] == "success"
    assert "FLAG{c2_d30bfusc4t3d" in data["flag"]
