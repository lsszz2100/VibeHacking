#!/usr/bin/env python3
"""Tests for Lab 09 (ICS/SCADA Modbus & HMI Supervisory Lab)."""

import importlib.util
import os
import sys
import pytest
from fastapi.testclient import TestClient

_app_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "app", "main.py"))
_spec = importlib.util.spec_from_file_location("ics_lab_mod", _app_path)
_mod = importlib.util.module_from_spec(_spec)
sys.modules["ics_lab_mod"] = _mod
_spec.loader.exec_module(_mod)

app = _mod.app
plc = _mod.plc
client = TestClient(app)


@pytest.fixture(autouse=True)
def reset_plc():
    plc.reset()


def test_telemetry_endpoint():
    res = client.get("/api/telemetry")
    assert res.status_code == 200
    data = res.json()
    assert "coils" in data
    assert "registers" in data
    assert data["registers"]["0_temperature"] == 75
    assert data["registers"]["100_secret"] == 54321


def test_reset_endpoint():
    plc.coils[1] = 0
    res = client.post("/api/reset")
    assert res.status_code == 200
    assert plc.coils[1] == 1


def test_flag_access_control():
    # Unsolved challenge should not return flag
    res_unsolved = client.get("/api/flag/ch1")
    assert res_unsolved.status_code == 200
    assert res_unsolved.json()["solved"] is False

    # Solved challenge returns flag
    plc.solved["ch1"] = True
    res_solved = client.get("/api/flag/ch1")
    assert res_solved.status_code == 200
    data = res_solved.json()
    assert data["solved"] is True
    assert data["flag"] == plc.challenge_flags["ch1"]


def test_esd_trip_flag():
    plc.coils[0] = 1  # ESD triggered
    plc.is_tripped = True
    plc.solved["ch4"] = True

    res = client.get("/api/flag/ch4")
    assert res.status_code == 200
    assert res.json()["solved"] is True
    assert res.json()["flag"] == plc.challenge_flags["ch4"]
