#!/usr/bin/env python3
"""Tests for Lab 21: Automotive CAN Bus & UDS Diagnostic Security Lab (CarCanLab)."""

import importlib.util
import os
import sys
import pytest
from starlette.testclient import TestClient

_app_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "app", "main.py"))
_spec = importlib.util.spec_from_file_location("carcan_lab_main", _app_path)
_mod = importlib.util.module_from_spec(_spec)
sys.modules["carcan_lab_main"] = _mod
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
    assert "CarCanLab" in data["lab"]
    assert len(data["missions"]) == 3
    assert "telemetry" in data
    assert data["telemetry"]["speed_kmh"] > 0


def test_dashboard_served(client):
    res = client.get("/")
    assert res.status_code == 200
    assert "text/html" in res.headers["content-type"]
    assert "CarCan" in res.text
    assert "Speedometer" in res.text or "Speed" in res.text


def test_can_traffic_endpoint(client):
    res = client.get("/api/can/traffic")
    assert res.status_code == 200
    data = res.json()
    assert "traffic" in data
    assert len(data["traffic"]) > 0
    assert any("0x120" in f["can_id"].lower() for f in data["traffic"])


def test_mission1_can_injection(client):
    # 1. Invalid payload
    bad_res = client.post("/api/mission1/can_inject", json={
        "can_id": "0x120",
        "dlc": 4,
        "payload_hex": "1234",
    })
    assert bad_res.status_code == 400

    # 2. Normal speed injection
    norm_res = client.post("/api/mission1/can_inject", json={
        "can_id": "0x120",
        "dlc": 8,
        "payload_hex": "0000500000000000",  # 0x50 = 80 km/h
    })
    assert norm_res.status_code == 200
    assert norm_res.json()["speed_kmh"] == 80.0
    assert "flag" not in norm_res.json()

    # 3. Spoofed speed >= 200 km/h (0xC8 = 200)
    spoof_res = client.post("/api/mission1/can_inject", json={
        "can_id": "0x120",
        "dlc": 8,
        "payload_hex": "0000C80000000000",
    })
    assert spoof_res.status_code == 200
    d = spoof_res.json()
    assert d["status"] == "success"
    assert d["speed_kmh"] == 200.0
    assert "FLAG{can_bus_arbitration_speed_spoof_8821}" in d["flag"]


def test_mission2_uds_security_access(client):
    # 1. Request seed in DEFAULT session -> 403
    fail_seed = client.post("/api/mission2/uds_security_seed")
    assert fail_seed.status_code == 403

    # 2. Transition session to EXTENDED
    sess_res = client.post("/api/mission2/uds_session", json={"session_type": "extended"})
    assert sess_res.status_code == 200
    assert sess_res.json()["session"] == "EXTENDED"

    # 3. Request seed in EXTENDED session
    seed_res = client.post("/api/mission2/uds_security_seed")
    assert seed_res.status_code == 200
    seed_hex = seed_res.json()["seed_hex"]
    assert len(seed_hex) == 8

    # 4. Wrong key submission
    wrong_key_res = client.post("/api/mission2/uds_security_unlock", json={"key_hex": "00000000"})
    assert wrong_key_res.status_code == 200
    assert wrong_key_res.json()["status"] == "failed"

    # 5. Correct key computation: seed ^ 0x5A5A5A5A
    seed_int = int(seed_hex, 16)
    expected_key_int = seed_int ^ 0x5A5A5A5A
    expected_key_hex = f"{expected_key_int:08X}"

    unlock_res = client.post("/api/mission2/uds_security_unlock", json={"key_hex": expected_key_hex})
    assert unlock_res.status_code == 200
    d = unlock_res.json()
    assert d["status"] == "unlocked"
    assert "FLAG{uds_security_access_seed_key_unlocked_3714}" in d["flag"]


def test_mission3_uds_download_and_reset(client):
    # 1. Firmware download in unlocked state
    fw_res = client.post("/api/mission3/uds_download_firmware", json={
        "memory_address_hex": "0x08000000",
        "memory_size_hex": "0x00010000",
    })
    assert fw_res.status_code == 200
    assert "S19" in fw_res.json()["firmware_header"]

    # 2. ECU hardReset DoS
    reset_res = client.post("/api/mission3/uds_ecu_reset", json={"reset_type": "hardReset"})
    assert reset_res.status_code == 200
    d = reset_res.json()
    assert d["status"] == "ecu_reset"
    assert "FAILSAFE_OFFLINE" in d["ecu_status"]
    assert "FLAG{uds_ecu_reset_hard_failsafe_pwned_9021}" in d["flag"]

    # Verify telemetry shows failsafe
    status_res = client.get("/api/status")
    tel = status_res.json()["telemetry"]
    assert tel["failsafe"] is True
    assert tel["speed_kmh"] == 0.0
