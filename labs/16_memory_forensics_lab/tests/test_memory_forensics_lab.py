#!/usr/bin/env python3
"""Tests for Lab 16: Memory Forensics & Volatility 3 Analysis Lab (MemShield)."""

import importlib.util
import os
import sys
import pytest
from starlette.testclient import TestClient

_app_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "app", "main.py"))
_spec = importlib.util.spec_from_file_location("memory_lab_main", _app_path)
_mod = importlib.util.module_from_spec(_spec)
sys.modules["memory_lab_main"] = _mod
_spec.loader.exec_module(_mod)

app = _mod.app
FLAGS = _mod.FLAGS
state = _mod.state


@pytest.fixture(autouse=True)
def reset_state():
    state.reset()
    yield
    state.reset()


@pytest.fixture
def client():
    return TestClient(app)


def test_status_endpoint(client):
    res = client.get("/status")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "online"
    assert data["total_stages"] == 4
    assert "victim_win10_enterprise_x64.dmp" in data["dump_file"]
    assert "stage1_dkom" in data["stages"]
    assert "stage2_malfind" in data["stages"]
    assert "stage3_netscan" in data["stages"]
    assert "stage4_lsass" in data["stages"]


def test_dashboard_served(client):
    res = client.get("/")
    assert res.status_code == 200
    assert "text/html" in res.headers["content-type"]
    assert "MemShield" in res.text
    assert "Volatility 3" in res.text


def test_stage1_dkom_detection(client):
    res = client.post("/api/stage1/detect-hidden")
    assert res.status_code == 200
    data = res.json()
    assert data["success"] is True
    assert data["flag"] == FLAGS["stage1"]
    assert data["unlinked_process"]["pid"] == 4820
    assert data["unlinked_process"]["name"] == "svch0st.exe"
    assert state.stage1_solved is True


def test_stage2_vad_analysis_valid(client):
    res = client.post("/api/stage2/analyze-injected-vad", json={"pid": 2440})
    assert res.status_code == 200
    data = res.json()
    assert data["success"] is True
    assert data["flag"] == FLAGS["stage2"]
    assert data["vad_info"]["protection"] == "PAGE_EXECUTE_READWRITE"
    assert "MZ" in data["vad_info"]["hexdump"]
    assert state.stage2_solved is True


def test_stage2_vad_analysis_clean_pid(client):
    res = client.post("/api/stage2/analyze-injected-vad", json={"pid": 1120})
    assert res.status_code == 400
    assert "클린한 VAD" in res.json()["detail"]


def test_stage3_c2_reconstruction(client):
    res = client.post("/api/stage3/reconstruct-c2")
    assert res.status_code == 200
    data = res.json()
    assert data["success"] is True
    assert data["flag"] == FLAGS["stage3"]
    assert "198.51.100.89:8443" in data["c2_artifact"]["foreign"]
    assert data["c2_artifact"]["pid"] == 4820
    assert state.stage3_solved is True


def test_stage4_lsass_dump_vulnerable(client):
    assert state.lsa_ppl_enabled is False
    res = client.post("/api/stage4/dump-credentials")
    assert res.status_code == 200
    data = res.json()
    assert data["success"] is True
    assert data["flag"] == FLAGS["stage4"]
    assert len(data["credentials"]) >= 3
    assert any(c["user"] == "Administrator" for c in data["credentials"])
    assert state.stage4_solved is True


def test_stage4_lsass_dump_blocked_when_ppl(client):
    # Enable PPL defense
    toggle_res = client.post("/api/stage4/toggle-ppl")
    assert toggle_res.status_code == 200
    assert state.lsa_ppl_enabled is True

    # Attempt dump
    dump_res = client.post("/api/stage4/dump-credentials")
    assert dump_res.status_code == 403
    assert "ACCESS_DENIED" in dump_res.json()["detail"]


def test_terminal_volatility_plugins(client):
    cmds = [
        "help",
        "status",
        "vol -f memory.raw windows.pslist",
        "vol -f memory.raw windows.psscan",
        "vol -f memory.raw windows.pstree",
        "vol -f memory.raw windows.malfind",
        "vol -f memory.raw windows.netscan",
        "vol -f memory.raw windows.lsadump",
        "vol -f memory.raw windows.cmdline",
        "flags",
    ]
    for cmd in cmds:
        res = client.post("/api/terminal", json={"command": cmd})
        assert res.status_code == 200
        assert "output" in res.json()
        assert len(res.json()["output"]) > 0


def test_flag_submission_lifecycle(client):
    # Invalid flag
    res = client.post("/api/submit-flag", json={"flag": "FLAG{invalid_fake_flag}"})
    assert res.status_code == 200
    assert res.json()["success"] is False

    # Valid flags
    for stage_key in ["stage1", "stage2", "stage3", "stage4"]:
        res = client.post("/api/submit-flag", json={"flag": FLAGS[stage_key]})
        assert res.status_code == 200
        assert res.json()["success"] is True
        assert res.json()["stage"] == stage_key

    assert len(state.solved_stages) == 4


def test_reset_endpoint(client):
    client.post("/api/stage1/detect-hidden")
    assert state.stage1_solved is True
    res = client.post("/api/reset")
    assert res.status_code == 200
    assert state.stage1_solved is False
    assert len(state.solved_stages) == 0
