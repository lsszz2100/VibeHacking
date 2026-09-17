#!/usr/bin/env python3
"""Comprehensive Unit and Integration Tests for Lab 14 (DocArmor MalDoc Lab)."""

import importlib.util
import os
import sys
import pytest
from fastapi.testclient import TestClient

_main_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "app", "main.py"))
_spec = importlib.util.spec_from_file_location("maldoc_lab_main", _main_path)
_mod = importlib.util.module_from_spec(_spec)
sys.modules["maldoc_lab_main"] = _mod
_spec.loader.exec_module(_mod)

app = _mod.app
FLAGS = _mod.FLAGS
STATE = _mod.STATE

client = TestClient(app)


@pytest.fixture(autouse=True)
def reset_lab_state():
    """Reset the in-memory state before each test."""
    client.post("/api/reset")


def test_status_endpoint():
    """Verify lab status, port configuration, and metadata."""
    res = client.get("/api/maldoc/status")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "running"
    assert data["service"] == "DocArmor"
    assert data["port"] == 8014
    assert data["total_stages"] == 4
    assert data["solved_count"] == 0


def test_dashboard_served():
    """Verify that root endpoint serves the HTML dashboard."""
    res = client.get("/")
    assert res.status_code == 200
    assert "DocArmor" in res.text
    assert "text/html" in res.headers.get("content-type", "")


def test_stage1_vba_deobfuscation_success():
    """Test Stage 1: Correct XOR key and reversed payload clears stage."""
    payload = {
        "sample_id": "SAMPLE_OLE_MACRO_01",
        "xor_key": 90,
        "reversed_payload": "powershell.exe -enc c2.apt-group.corp"
    }
    res = client.post("/api/maldoc/vba/deobfuscate", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["success"] is True
    assert data["flag"] == FLAGS["stage1"]


def test_stage1_vba_deobfuscation_failure():
    """Test Stage 1: Incorrect XOR key fails to solve."""
    payload = {
        "sample_id": "SAMPLE_OLE_MACRO_01",
        "xor_key": 42,
        "reversed_payload": "powershell.exe"
    }
    res = client.post("/api/maldoc/vba/deobfuscate", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["success"] is False
    assert data["flag"] is None


def test_stage2_pdf_stream_analysis_success():
    """Test Stage 2: FlateDecode stream parsing on object 7 clears stage."""
    payload = {
        "object_id": 7,
        "filter_type": "/FlateDecode",
        "trigger_action": "/OpenAction"
    }
    res = client.post("/api/maldoc/pdf/analyze", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["success"] is True
    assert data["flag"] == FLAGS["stage2"]


def test_stage2_pdf_stream_analysis_failure():
    """Test Stage 2: Wrong object id or filter fails."""
    payload = {
        "object_id": 2,
        "filter_type": "/ASCIIHexDecode",
        "trigger_action": "/OpenAction"
    }
    res = client.post("/api/maldoc/pdf/analyze", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["success"] is False
    assert data["flag"] is None


def test_stage3_equation_exploit_success():
    """Test Stage 3: Overflowing font name buffer triggers CVE-2017-11882 RCE."""
    payload = {
        "font_name_length": 48,
        "target_api": "WinExec",
        "command_payload": "cmd.exe /c calc.exe"
    }
    res = client.post("/api/maldoc/cve/equation", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["success"] is True
    assert data["flag"] == FLAGS["stage3"]


def test_stage3_equation_exploit_failure():
    """Test Stage 3: Short font name buffer does not cause overflow."""
    payload = {
        "font_name_length": 20,
        "target_api": "WinExec",
        "command_payload": "calc.exe"
    }
    res = client.post("/api/maldoc/cve/equation", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["success"] is False
    assert data["flag"] is None


def test_stage4_mshtml_defense_success():
    """Test Stage 4: Enforcing external relationship blocking prevents CVE-2021-40444."""
    payload = {
        "target_mode": "External",
        "block_external_relations": True,
        "quarantine_cab": True
    }
    res = client.post("/api/maldoc/cve/mshtml", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["success"] is True
    assert data["flag"] == FLAGS["stage4"]


def test_stage4_mshtml_defense_failure():
    """Test Stage 4: Incomplete policy fails defense."""
    payload = {
        "target_mode": "Internal",
        "block_external_relations": False,
        "quarantine_cab": False
    }
    res = client.post("/api/maldoc/cve/mshtml", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["success"] is False
    assert data["flag"] is None


def test_full_chain_solve_and_flags():
    """Test complete 4-stage pipeline and flag retrieval."""
    # Solve 1
    client.post("/api/maldoc/vba/deobfuscate", json={
        "sample_id": "SAMPLE_OLE_MACRO_01",
        "xor_key": 90,
        "reversed_payload": "powershell.exe -enc c2.apt-group.corp"
    })
    # Solve 2
    client.post("/api/maldoc/pdf/analyze", json={
        "object_id": 7,
        "filter_type": "/FlateDecode",
        "trigger_action": "/OpenAction"
    })
    # Solve 3
    client.post("/api/maldoc/cve/equation", json={
        "font_name_length": 50,
        "target_api": "WinExec",
        "command_payload": "cmd.exe"
    })
    # Solve 4
    client.post("/api/maldoc/cve/mshtml", json={
        "target_mode": "External",
        "block_external_relations": True,
        "quarantine_cab": True
    })

    flags_res = client.get("/api/flags")
    assert flags_res.status_code == 200
    flags = flags_res.json()
    assert flags["stage1"] == FLAGS["stage1"]
    assert flags["stage2"] == FLAGS["stage2"]
    assert flags["stage3"] == FLAGS["stage3"]
    assert flags["stage4"] == FLAGS["stage4"]

    status_res = client.get("/api/maldoc/status")
    status = status_res.json()
    assert status["solved_count"] == 4
