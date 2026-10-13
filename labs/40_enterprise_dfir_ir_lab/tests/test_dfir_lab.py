"""
Test suite for Lab 40: IRShield — Enterprise DFIR & Incident Response Lab.
"""

import sys
import importlib.util
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

APP_PATH = Path(__file__).resolve().parent.parent / "app" / "main.py"
spec = importlib.util.spec_from_file_location("lab40_app", str(APP_PATH))
lab40_module = importlib.util.module_from_spec(spec)
sys.modules["lab40_app"] = lab40_module
spec.loader.exec_module(lab40_module)

app = lab40_module.app
STAGE1_FLAG = lab40_module.STAGE1_FLAG
STAGE2_FLAG = lab40_module.STAGE2_FLAG
STAGE3_FLAG = lab40_module.STAGE3_FLAG
STAGE4_FLAG = lab40_module.STAGE4_FLAG

client = TestClient(app)

@pytest.fixture(autouse=True)
def reset_state():
    """Ensure clean state before each test."""
    client.post("/api/reset")
    yield
    client.post("/api/reset")

def test_index_dashboard():
    response = client.get("/")
    assert response.status_code == 200
    assert "Lab 40: IRShield" in response.text
    assert "Port: 8040" in response.text

def test_initial_status():
    response = client.get("/api/status")
    assert response.status_code == 200
    data = response.json()
    assert data["all_stages_completed"] is False
    assert data["stages"]["stage1_process_triage"] is False
    assert data["stages"]["stage2_mft_timeline"] is False
    assert data["stages"]["stage3_c2_containment"] is False
    assert data["stages"]["stage4_soar_remediation"] is False

def test_stage1_get_processes():
    response = client.get("/api/stage1/processes")
    assert response.status_code == 200
    data = response.json()
    assert "processes" in data
    assert len(data["processes"]) >= 5
    pids = [p["pid"] for p in data["processes"]]
    assert 4920 in pids

def test_stage1_triage_wrong_pid():
    response = client.post(
        "/api/stage1/triage",
        json={"suspect_pid": 1024, "detection_reason": "ppid_spoofing"},
    )
    assert response.status_code == 400
    assert "legitimate" in response.json()["detail"].lower()

def test_stage1_triage_invalid_reason():
    response = client.post(
        "/api/stage1/triage",
        json={"suspect_pid": 4920, "detection_reason": "wrong_reason"},
    )
    assert response.status_code == 400
    assert "detection reason must pinpoint" in response.json()["detail"].lower()

def test_stage1_triage_success():
    response = client.post(
        "/api/stage1/triage",
        json={"suspect_pid": 4920, "detection_reason": "ppid_spoofing"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert data["flag"] == STAGE1_FLAG

def test_stage2_get_mft_events():
    response = client.get("/api/stage2/mft-events")
    assert response.status_code == 200
    data = response.json()
    assert "journal_events" in data
    assert len(data["journal_events"]) >= 5

def test_stage2_mft_invalid_command():
    response = client.post(
        "/api/stage2/mft-analyze",
        json={
            "shadow_deletion_cmd": "rm -rf /",
            "ransom_extension": ".locked",
            "mft_record": 84912,
        },
    )
    assert response.status_code == 400
    assert "shadow deletion" in response.json()["detail"].lower()

def test_stage2_mft_invalid_extension():
    response = client.post(
        "/api/stage2/mft-analyze",
        json={
            "shadow_deletion_cmd": "vssadmin.exe delete shadows /all /quiet",
            "ransom_extension": ".xyz",
            "mft_record": 84912,
        },
    )
    assert response.status_code == 400
    assert "extension" in response.json()["detail"].lower()

def test_stage2_mft_invalid_record():
    response = client.post(
        "/api/stage2/mft-analyze",
        json={
            "shadow_deletion_cmd": "vssadmin.exe delete shadows /all /quiet",
            "ransom_extension": ".locked",
            "mft_record": 11111,
        },
    )
    assert response.status_code == 400
    assert "initial encrypted" in response.json()["detail"].lower()

def test_stage2_mft_success():
    response = client.post(
        "/api/stage2/mft-analyze",
        json={
            "shadow_deletion_cmd": "vssadmin.exe delete shadows /all /quiet",
            "ransom_extension": ".locked",
            "mft_record": 84912,
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert data["flag"] == STAGE2_FLAG

def test_stage3_get_network_connections():
    response = client.get("/api/stage3/network-connections")
    assert response.status_code == 200
    data = response.json()
    assert "telemetry" in data
    assert len(data["telemetry"]) >= 3

def test_stage3_contain_wrong_ip():
    response = client.post(
        "/api/stage3/contain",
        json={
            "c2_ip": "1.1.1.1",
            "c2_port": 8443,
            "isolation_mode": "isolate_host",
            "block_firewall": True,
        },
    )
    assert response.status_code == 400
    assert "not the malicious c2" in response.json()["detail"].lower()

def test_stage3_contain_wrong_port():
    response = client.post(
        "/api/stage3/contain",
        json={
            "c2_ip": "198.51.100.77",
            "c2_port": 443,
            "isolation_mode": "isolate_host",
            "block_firewall": True,
        },
    )
    assert response.status_code == 400
    assert "port" in response.json()["detail"].lower()

def test_stage3_contain_missing_firewall():
    response = client.post(
        "/api/stage3/contain",
        json={
            "c2_ip": "198.51.100.77",
            "c2_port": 8443,
            "isolation_mode": "isolate_host",
            "block_firewall": False,
        },
    )
    assert response.status_code == 400
    assert "firewall" in response.json()["detail"].lower()

def test_stage3_contain_success():
    response = client.post(
        "/api/stage3/contain",
        json={
            "c2_ip": "198.51.100.77",
            "c2_port": 8443,
            "isolation_mode": "isolate_host",
            "block_firewall": True,
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert data["flag"] == STAGE3_FLAG

def test_stage4_get_persistence_audit():
    response = client.get("/api/stage4/persistence-audit")
    assert response.status_code == 200
    data = response.json()
    assert "persistence_items" in data
    assert len(data["persistence_items"]) >= 4

def test_stage4_remediate_incomplete():
    response = client.post(
        "/api/stage4/remediate",
        json={"remediation_actions": ["remove_scheduled_task"]},
    )
    assert response.status_code == 400
    assert "missing required actions" in response.json()["detail"].lower()

def test_stage4_remediate_success():
    response = client.post(
        "/api/stage4/remediate",
        json={
            "remediation_actions": [
                "remove_scheduled_task",
                "kill_suspect_process",
                "clean_wmi_subscription",
                "restore_immutable_snapshot",
            ]
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert data["flag"] == STAGE4_FLAG

def test_full_chain_all_stages():
    # 1. Stage 1
    r1 = client.post(
        "/api/stage1/triage",
        json={"suspect_pid": 4920, "detection_reason": "ppid_spoofing"},
    )
    assert r1.status_code == 200

    # 2. Stage 2
    r2 = client.post(
        "/api/stage2/mft-analyze",
        json={
            "shadow_deletion_cmd": "vssadmin.exe delete shadows /all /quiet",
            "ransom_extension": ".locked",
            "mft_record": 84912,
        },
    )
    assert r2.status_code == 200

    # 3. Stage 3
    r3 = client.post(
        "/api/stage3/contain",
        json={
            "c2_ip": "198.51.100.77",
            "c2_port": 8443,
            "isolation_mode": "isolate_host",
            "block_firewall": True,
        },
    )
    assert r3.status_code == 200

    # 4. Stage 4
    r4 = client.post(
        "/api/stage4/remediate",
        json={
            "remediation_actions": [
                "remove_scheduled_task",
                "kill_suspect_process",
                "clean_wmi_subscription",
                "restore_immutable_snapshot",
            ]
        },
    )
    assert r4.status_code == 200

    # Verify all completed
    status_resp = client.get("/api/status")
    assert status_resp.status_code == 200
    assert status_resp.json()["all_stages_completed"] is True
