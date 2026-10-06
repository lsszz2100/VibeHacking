#!/usr/bin/env python3
"""
Unit tests for Lab 37: BLEShield — Bluetooth LE & SDR Wireless Security Lab
Tests BLE Advertising Scan, GATT Recon, Unauthenticated Characteristic Write,
Legacy Pairing TK Cracking, Token Replay, and LESC ECDH Hardening.
"""

import sys
import importlib.util
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

# Dynamic import to avoid collision with other labs' app packages
APP_PATH = Path(__file__).resolve().parent.parent / "app" / "main.py"
spec = importlib.util.spec_from_file_location("lab37_app", str(APP_PATH))
lab37_module = importlib.util.module_from_spec(spec)
sys.modules["lab37_app"] = lab37_module
spec.loader.exec_module(lab37_module)

app = lab37_module.app
reset_lab = lab37_module.reset_lab
STEP1_FLAG = lab37_module.STEP1_FLAG
STEP2_FLAG = lab37_module.STEP2_FLAG
STEP3_FLAG = lab37_module.STEP3_FLAG
STEP4_FLAG = lab37_module.STEP4_FLAG


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
    assert data["lab"] == "37_bluetooth_sdr_security_lab"
    assert data["port"] == 8037
    assert data["step1_completed"] is False
    assert data["step2_completed"] is False
    assert data["step3_completed"] is False
    assert data["step4_completed"] is False


def test_index_html(client):
    res = client.get("/")
    assert res.status_code == 200
    assert "text/html" in res.headers["content-type"]
    assert "Lab 37: BLEShield" in res.text
    assert "8037" in res.text


def test_get_ble_status(client):
    res = client.get("/api/ble/status")
    assert res.status_code == 200
    data = res.json()
    assert data["target_mac"] == "AA:BB:CC:11:22:33"
    assert data["doorlock_status"] == "LOCKED"
    assert "Just Works" in data["pairing_mode"]
    assert data["lesc_enabled"] is False
    assert data["auth_write_required"] is False


def test_scan_peripherals(client):
    res = client.get("/api/ble/scan")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "success"
    assert data["peripherals_found"] >= 2
    assert data["step1_flag"] == STEP1_FLAG


def test_get_services_valid(client):
    res = client.get("/api/ble/services?mac=AA:BB:CC:11:22:33")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "success"
    assert len(data["services"]) >= 2
    # Check that service 0xFFE0 contains handle 0x0014
    smartlock_svc = next((s for s in data["services"] if s["uuid"] == "0xFFE0"), None)
    assert smartlock_svc is not None
    handles = [c["handle"] for c in smartlock_svc["characteristics"]]
    assert "0x0014" in handles
    assert data["flag"] == STEP1_FLAG


def test_get_services_not_found(client):
    res = client.get("/api/ble/services?mac=FF:FF:FF:00:00:00")
    assert res.status_code == 404


def test_write_characteristic_unlock_success(client):
    # Before write, door is locked
    assert client.get("/api/ble/status").json()["doorlock_status"] == "LOCKED"

    res = client.post("/api/ble/write", json={
        "mac": "AA:BB:CC:11:22:33",
        "handle": "0x0014",
        "value": "01"
    })
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "success"
    assert data["action"] == "DOORLOCK_UNLOCKED"
    assert data["doorlock_status"] == "UNLOCKED"
    assert data["flag"] == STEP2_FLAG


def test_write_characteristic_lock(client):
    # Set to unlocked first
    client.post("/api/ble/write", json={"mac": "AA:BB:CC:11:22:33", "handle": "0x0014", "value": "01"})
    assert client.get("/api/ble/status").json()["doorlock_status"] == "UNLOCKED"

    # Now lock
    res = client.post("/api/ble/write", json={"mac": "AA:BB:CC:11:22:33", "handle": "0x0014", "value": "00"})
    assert res.status_code == 200
    assert res.json()["action"] == "DOORLOCK_LOCKED"
    assert client.get("/api/ble/status").json()["doorlock_status"] == "LOCKED"


def test_write_characteristic_invalid_device(client):
    res = client.post("/api/ble/write", json={"mac": "00:00:00:00:00:00", "handle": "0x0014", "value": "01"})
    assert res.status_code == 404


def test_snoop_traffic(client):
    res = client.get("/api/ble/snoop_traffic")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "success"
    packet = data["packet"]
    assert "SMP" in packet["protocol"]
    assert "Just Works" in packet["derived_method"]
    assert "mrand" in packet
    assert packet["valid_auth_token"] == "BLE_AUTH_REPLAY_TKN_9942FA"


def test_crack_pairing_justworks_success(client):
    res = client.post("/api/ble/crack_pairing", json={
        "mac": "AA:BB:CC:11:22:33",
        "tk_guess": "000000"
    })
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "success"
    assert "Just Works" in data["derived_tk"]
    assert "short_term_key_stk" in data
    assert data["flag"] == STEP3_FLAG


def test_crack_pairing_invalid_guess(client):
    res = client.post("/api/ble/crack_pairing", json={
        "mac": "AA:BB:CC:11:22:33",
        "tk_guess": "999999"
    })
    assert res.status_code == 400


def test_replay_auth_success(client):
    res = client.post("/api/ble/replay_auth", json={
        "mac": "AA:BB:CC:11:22:33",
        "auth_token": "BLE_AUTH_REPLAY_TKN_9942FA"
    })
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "success"
    assert data["action"] == "AUTH_REPLAY_ACCEPTED"
    assert data["flag"] == STEP3_FLAG


def test_replay_auth_invalid_token(client):
    res = client.post("/api/ble/replay_auth", json={
        "mac": "AA:BB:CC:11:22:33",
        "auth_token": "INVALID_TOKEN_RANDOM"
    })
    assert res.status_code == 401


def test_harden_ble_success(client):
    res = client.post("/api/ble/harden", json={
        "enforce_lesc_ecdh": True,
        "require_gatt_auth": True,
        "enable_anti_replay": True
    })
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "success"
    assert data["lesc_enabled"] is True
    assert data["auth_write_required"] is True
    assert "LE Secure Connections" in data["pairing_mode"]
    assert data["flag"] == STEP4_FLAG


def test_unauthenticated_write_blocked_after_harden(client):
    # Apply hardening
    client.post("/api/ble/harden", json={
        "enforce_lesc_ecdh": True,
        "require_gatt_auth": True,
        "enable_anti_replay": True
    })

    # Try unauthenticated write -> Should return 403 Forbidden
    res = client.post("/api/ble/write", json={
        "mac": "AA:BB:CC:11:22:33",
        "handle": "0x0014",
        "value": "01"
    })
    assert res.status_code == 403
    assert "INSUFFICIENT_AUTHENTICATION" in res.json()["detail"]


def test_replay_blocked_after_harden(client):
    # Apply hardening
    client.post("/api/ble/harden", json={
        "enforce_lesc_ecdh": True,
        "require_gatt_auth": True,
        "enable_anti_replay": True
    })

    # First replay with nonce -> success
    res1 = client.post("/api/ble/replay_auth", json={
        "mac": "AA:BB:CC:11:22:33",
        "auth_token": "BLE_AUTH_REPLAY_TKN_9942FA",
        "nonce": "NONCE_TEST_101"
    })
    assert res1.status_code == 200

    # Second replay with identical nonce -> 403 Replay detected
    res2 = client.post("/api/ble/replay_auth", json={
        "mac": "AA:BB:CC:11:22:33",
        "auth_token": "BLE_AUTH_REPLAY_TKN_9942FA",
        "nonce": "NONCE_TEST_101"
    })
    assert res2.status_code == 403
    assert "REPLAY_DETECTED" in res2.json()["detail"]


def test_reset_lab(client):
    # Alter states
    client.post("/api/ble/write", json={"mac": "AA:BB:CC:11:22:33", "handle": "0x0014", "value": "01"})
    client.post("/api/ble/harden", json={"enforce_lesc_ecdh": True, "require_gatt_auth": True, "enable_anti_replay": True})
    status = client.get("/api/ble/status").json()
    assert status["doorlock_status"] == "UNLOCKED"
    assert status["lesc_enabled"] is True

    # Call reset
    res = client.post("/api/ble/reset")
    assert res.status_code == 200

    # Check reset state
    status_after = client.get("/api/ble/status").json()
    assert status_after["doorlock_status"] == "LOCKED"
    assert status_after["lesc_enabled"] is False
    assert status_after["step1_completed"] is False
    assert status_after["harden_applied"] is False
