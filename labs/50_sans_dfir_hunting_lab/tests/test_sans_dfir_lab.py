#!/usr/bin/env python3
"""Tests for Lab 50: ArtifactHunter — SANS DFIR Threat Hunting Lab."""

import sys
import importlib.util
from pathlib import Path
import pytest
from starlette.testclient import TestClient

APP_PATH = Path(__file__).resolve().parent.parent / "app" / "main.py"
spec = importlib.util.spec_from_file_location("lab50_app", str(APP_PATH))
lab50_module = importlib.util.module_from_spec(spec)
sys.modules["lab50_app"] = lab50_module
spec.loader.exec_module(lab50_module)

app = lab50_module.app
state = lab50_module.state
STAGE1_FLAG = lab50_module.STAGE1_FLAG
STAGE2_FLAG = lab50_module.STAGE2_FLAG
STAGE3_FLAG = lab50_module.STAGE3_FLAG
STAGE4_FLAG = lab50_module.STAGE4_FLAG

client = TestClient(app)


@pytest.fixture(autouse=True)
def reset_lab():
    client.post("/api/reset")
    yield
    client.post("/api/reset")


def test_index_and_status():
    res = client.get("/")
    assert res.status_code == 200
    assert "Lab 50" in res.text

    status_res = client.get("/status")
    assert status_res.status_code == 200
    data = status_res.json()
    assert data["lab"] == "50_sans_dfir_hunting_lab"
    assert data["port"] == 8050
    assert data["stages"]["stage1_execution_evidence"] is False


def test_stage1_execution_evidence():
    # Invalid artifact type
    res_bad = client.post("/api/stage1/analyze_execution", json={
        "artifact_type": "invalid_type",
        "target_evidence": "MIMIKATZ.EXE-B7A21F8C.pf"
    })
    assert res_bad.status_code == 400

    # Inconclusive evidence
    res_inc = client.post("/api/stage1/analyze_execution", json={
        "artifact_type": "prefetch",
        "target_evidence": "NOTEPAD.EXE-11223344.pf"
    })
    assert res_inc.status_code == 200
    assert res_inc.json()["status"] == "inconclusive"

    # Successful triage
    res_ok = client.post("/api/stage1/analyze_execution", json={
        "artifact_type": "prefetch",
        "target_evidence": "MIMIKATZ.EXE-B7A21F8C.pf"
    })
    assert res_ok.status_code == 200
    data = res_ok.json()
    assert data["status"] == "success"
    assert STAGE1_FLAG in data["flag"]
    assert state.stage1_completed is True


def test_stage2_filesystem_carving():
    # Negative record number
    res_bad = client.post("/api/stage2/carve_filesystem", json={
        "mft_record_number": -1,
        "usn_reason_flag": "USN_REASON_FILE_DELETE"
    })
    assert res_bad.status_code == 400

    # Invalid USN flag
    res_bad_flag = client.post("/api/stage2/carve_filesystem", json={
        "mft_record_number": 41289,
        "usn_reason_flag": "USN_REASON_DATA_OVERWRITE"
    })
    assert res_bad_flag.status_code == 400

    # Success
    res_ok = client.post("/api/stage2/carve_filesystem", json={
        "mft_record_number": 41289,
        "usn_reason_flag": "USN_REASON_FILE_DELETE"
    })
    assert res_ok.status_code == 200
    data = res_ok.json()
    assert data["status"] == "success"
    assert STAGE2_FLAG in data["flag"]
    assert state.stage2_completed is True


def test_stage3_memory_injection():
    # Bad protection
    res_bad = client.post("/api/stage3/triage_memory_injection", json={
        "target_pid": 2840,
        "vad_protection": "PAGE_READONLY",
        "unhook_dkom": True
    })
    assert res_bad.status_code == 400

    # Success
    res_ok = client.post("/api/stage3/triage_memory_injection", json={
        "target_pid": 2840,
        "vad_protection": "PAGE_EXECUTE_READWRITE",
        "unhook_dkom": True
    })
    assert res_ok.status_code == 200
    data = res_ok.json()
    assert data["status"] == "success"
    assert STAGE3_FLAG in data["flag"]
    assert state.stage3_completed is True


def test_stage4_supertimeline_and_quarantine():
    # Bad filter
    res_bad = client.post("/api/stage4/supertimeline_isolate", json={
        "tshark_display_filter": "arp",
        "isolate_host": True
    })
    assert res_bad.status_code == 400

    # False isolate
    res_no_iso = client.post("/api/stage4/supertimeline_isolate", json={
        "tshark_display_filter": "dns.flags.response == 0",
        "isolate_host": False
    })
    assert res_no_iso.status_code == 400

    # Success
    res_ok = client.post("/api/stage4/supertimeline_isolate", json={
        "tshark_display_filter": "dns.qry.name contains c2",
        "isolate_host": True
    })
    assert res_ok.status_code == 200
    data = res_ok.json()
    assert data["status"] == "success"
    assert STAGE4_FLAG in data["flag"]
    assert state.stage4_completed is True
    assert state.host_isolated is True
