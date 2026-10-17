#!/usr/bin/env python3
"""
Unit and integration test suite for Lab 43: CloudIRShield
Verifies:
- HTML dashboard serving
- CloudTrail log querying & anomaly triage
- STS token carving & S3 exfiltration forensics
- VPC Flow Logs correlation & C2 beacon extraction
- GuardDuty triage & automated SOAR containment playbook
- Stage gating, security validation, and state reset
"""

import sys
import importlib.util
from pathlib import Path
import pytest
from starlette.testclient import TestClient

APP_PATH = Path(__file__).resolve().parent.parent / "app" / "main.py"
spec = importlib.util.spec_from_file_location("lab43_app", str(APP_PATH))
lab43_module = importlib.util.module_from_spec(spec)
sys.modules["lab43_app"] = lab43_module
spec.loader.exec_module(lab43_module)

app = lab43_module.app
STAGE1_FLAG = lab43_module.STAGE1_FLAG
STAGE2_FLAG = lab43_module.STAGE2_FLAG
STAGE3_FLAG = lab43_module.STAGE3_FLAG
STAGE4_FLAG = lab43_module.STAGE4_FLAG

client = TestClient(app)


@pytest.fixture(autouse=True)
def reset_simulation_state():
    """Reset simulation state before each test run."""
    client.post("/api/v1/reset")
    yield
    client.post("/api/v1/reset")


def test_root_html_page():
    res = client.get("/")
    assert res.status_code == 200
    assert "Lab 43: CloudIRShield" in res.text
    assert "CloudTrail Anomaly Audit" in res.text


def test_status_endpoint_initial():
    res = client.get("/api/v1/status")
    assert res.status_code == 200
    data = res.json()
    assert data["lab"] == "Lab 43: CloudIRShield"
    assert not data["all_stages_solved"]
    assert data["containment_status"] == "UNCONTAINED"
    assert not data["stages"]["stage1_cloudtrail_audit"]["solved"]


def test_cloudtrail_events_fetch():
    res = client.get("/api/v1/cloudtrail/events")
    assert res.status_code == 200
    data = res.json()
    assert data["total"] >= 4
    event_names = [e["eventName"] for e in data["events"]]
    assert "AttachUserPolicy" in event_names
    assert "DescribeInstances" in event_names


def test_cloudtrail_detect_anomaly_success():
    payload = {
        "event_id": "evt-99482-admin-escalation",
        "source_ip": "198.51.100.77",
        "action": "AttachUserPolicy"
    }
    res = client.post("/api/v1/cloudtrail/detect-anomaly", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "success"
    assert data["stage"] == 1
    assert data["flag"] == STAGE1_FLAG

    # Check status
    st = client.get("/api/v1/status").json()
    assert st["stages"]["stage1_cloudtrail_audit"]["solved"]


def test_cloudtrail_detect_anomaly_invalid_event():
    payload = {
        "event_id": "evt-non-existent-999",
        "source_ip": "198.51.100.77",
        "action": "AttachUserPolicy"
    }
    res = client.post("/api/v1/cloudtrail/detect-anomaly", json=payload)
    assert res.status_code == 404
    assert "not found" in res.json()["detail"].lower()


def test_cloudtrail_detect_anomaly_wrong_ip():
    payload = {
        "event_id": "evt-99482-admin-escalation",
        "source_ip": "10.0.0.1",
        "action": "AttachUserPolicy"
    }
    res = client.post("/api/v1/cloudtrail/detect-anomaly", json=payload)
    assert res.status_code == 400
    assert "verification failed" in res.json()["detail"].lower()


def test_s3_exfil_stage2_blocked_if_stage1_not_solved():
    payload = {
        "session_name": "exfil-session-shadow-ops",
        "compromised_token": "ASIA99CLOUDEXFIL2026",
        "target_bucket": "corp-customer-pii-vault"
    }
    res = client.post("/api/v1/forensics/verify-exfil", json=payload)
    assert res.status_code == 403
    assert "Complete Stage 1" in res.json()["detail"]


def test_s3_exfil_logs_fetch():
    res = client.get("/api/v1/forensics/s3-exfil-logs")
    assert res.status_code == 200
    data = res.json()
    assert data["total"] >= 3
    keys = [log["objectKey"] for log in data["logs"]]
    assert "customer_ssn_2026.parquet" in keys


def test_s3_exfil_verify_success():
    # Solve Stage 1
    client.post("/api/v1/cloudtrail/detect-anomaly", json={
        "event_id": "evt-99482-admin-escalation",
        "source_ip": "198.51.100.77",
        "action": "AttachUserPolicy"
    })
    # Solve Stage 2
    payload = {
        "session_name": "exfil-session-shadow-ops",
        "compromised_token": "ASIA99CLOUDEXFIL2026",
        "target_bucket": "corp-customer-pii-vault"
    }
    res = client.post("/api/v1/forensics/verify-exfil", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "success"
    assert data["stage"] == 2
    assert data["flag"] == STAGE2_FLAG


def test_s3_exfil_verify_invalid_token():
    client.post("/api/v1/cloudtrail/detect-anomaly", json={
        "event_id": "evt-99482-admin-escalation",
        "source_ip": "198.51.100.77",
        "action": "AttachUserPolicy"
    })
    payload = {
        "session_name": "exfil-session-shadow-ops",
        "compromised_token": "ASIA_WRONG_TOKEN",
        "target_bucket": "corp-customer-pii-vault"
    }
    res = client.post("/api/v1/forensics/verify-exfil", json=payload)
    assert res.status_code == 400


def test_vpc_stage3_blocked_if_stage2_not_solved():
    payload = {
        "compromised_ip": "10.0.4.15",
        "c2_ip": "203.0.113.89",
        "c2_port": 8443,
        "protocol": "TCP"
    }
    res = client.post("/api/v1/vpc/correlate-c2", json=payload)
    assert res.status_code == 403
    assert "Complete Stage 2" in res.json()["detail"]


def test_vpc_flow_logs_fetch():
    res = client.get("/api/v1/vpc/flow-logs")
    assert res.status_code == 200
    data = res.json()
    assert data["total"] > 5
    dests = [f["dstaddr"] for f in data["flow_logs"]]
    assert "203.0.113.89" in dests


def test_vpc_correlate_c2_success():
    # Stage 1
    client.post("/api/v1/cloudtrail/detect-anomaly", json={
        "event_id": "evt-99482-admin-escalation",
        "source_ip": "198.51.100.77",
        "action": "AttachUserPolicy"
    })
    # Stage 2
    client.post("/api/v1/forensics/verify-exfil", json={
        "session_name": "exfil-session-shadow-ops",
        "compromised_token": "ASIA99CLOUDEXFIL2026",
        "target_bucket": "corp-customer-pii-vault"
    })
    # Stage 3
    payload = {
        "compromised_ip": "10.0.4.15",
        "c2_ip": "203.0.113.89",
        "c2_port": 8443,
        "protocol": "TCP"
    }
    res = client.post("/api/v1/vpc/correlate-c2", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "success"
    assert data["stage"] == 3
    assert data["flag"] == STAGE3_FLAG


def test_vpc_correlate_c2_wrong_port():
    client.post("/api/v1/cloudtrail/detect-anomaly", json={
        "event_id": "evt-99482-admin-escalation",
        "source_ip": "198.51.100.77",
        "action": "AttachUserPolicy"
    })
    client.post("/api/v1/forensics/verify-exfil", json={
        "session_name": "exfil-session-shadow-ops",
        "compromised_token": "ASIA99CLOUDEXFIL2026",
        "target_bucket": "corp-customer-pii-vault"
    })
    payload = {
        "compromised_ip": "10.0.4.15",
        "c2_ip": "203.0.113.89",
        "c2_port": 443,  # wrong port
        "protocol": "TCP"
    }
    res = client.post("/api/v1/vpc/correlate-c2", json=payload)
    assert res.status_code == 400


def test_guardduty_stage4_blocked_if_stage3_not_solved():
    payload = {
        "revoke_iam_sessions": True,
        "apply_deny_boundary": True,
        "quarantine_security_group": True,
        "snapshot_ebs_volume": True
    }
    res = client.post("/api/v1/soar/contain-incident", json=payload)
    assert res.status_code == 403
    assert "Complete Stage 3" in res.json()["detail"]


def test_guardduty_findings_fetch():
    res = client.get("/api/v1/guardduty/findings")
    assert res.status_code == 200
    data = res.json()
    assert len(data["findings"]) >= 2
    types = [f["type"] for f in data["findings"]]
    assert any("CredentialExfiltration" in t for t in types)


def test_soar_containment_success():
    # Stage 1
    client.post("/api/v1/cloudtrail/detect-anomaly", json={
        "event_id": "evt-99482-admin-escalation",
        "source_ip": "198.51.100.77",
        "action": "AttachUserPolicy"
    })
    # Stage 2
    client.post("/api/v1/forensics/verify-exfil", json={
        "session_name": "exfil-session-shadow-ops",
        "compromised_token": "ASIA99CLOUDEXFIL2026",
        "target_bucket": "corp-customer-pii-vault"
    })
    # Stage 3
    client.post("/api/v1/vpc/correlate-c2", json={
        "compromised_ip": "10.0.4.15",
        "c2_ip": "203.0.113.89",
        "c2_port": 8443,
        "protocol": "TCP"
    })
    # Stage 4
    payload = {
        "revoke_iam_sessions": True,
        "apply_deny_boundary": True,
        "quarantine_security_group": True,
        "snapshot_ebs_volume": True
    }
    res = client.post("/api/v1/soar/contain-incident", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "success"
    assert data["stage"] == 4
    assert data["containment_status"] == "CONTAINED"
    assert data["flag"] == STAGE4_FLAG


def test_soar_containment_incomplete():
    # Stage 1-3
    client.post("/api/v1/cloudtrail/detect-anomaly", json={
        "event_id": "evt-99482-admin-escalation",
        "source_ip": "198.51.100.77",
        "action": "AttachUserPolicy"
    })
    client.post("/api/v1/forensics/verify-exfil", json={
        "session_name": "exfil-session-shadow-ops",
        "compromised_token": "ASIA99CLOUDEXFIL2026",
        "target_bucket": "corp-customer-pii-vault"
    })
    client.post("/api/v1/vpc/correlate-c2", json={
        "compromised_ip": "10.0.4.15",
        "c2_ip": "203.0.113.89",
        "c2_port": 8443,
        "protocol": "TCP"
    })
    # Incomplete payload
    payload = {
        "revoke_iam_sessions": True,
        "apply_deny_boundary": True,
        "quarantine_security_group": False,  # Missing
        "snapshot_ebs_volume": True
    }
    res = client.post("/api/v1/soar/contain-incident", json=payload)
    assert res.status_code == 400
    assert "Incomplete containment" in res.json()["detail"]


def test_full_chain_solve_and_reset():
    # 1. Check initial
    status = client.get("/api/v1/status").json()
    assert not status["all_stages_solved"]

    # 2. Stage 1
    r1 = client.post("/api/v1/cloudtrail/detect-anomaly", json={
        "event_id": "evt-99482-admin-escalation",
        "source_ip": "198.51.100.77",
        "action": "AttachUserPolicy"
    }).json()
    assert r1["flag"] == STAGE1_FLAG

    # 3. Stage 2
    r2 = client.post("/api/v1/forensics/verify-exfil", json={
        "session_name": "exfil-session-shadow-ops",
        "compromised_token": "ASIA99CLOUDEXFIL2026",
        "target_bucket": "corp-customer-pii-vault"
    }).json()
    assert r2["flag"] == STAGE2_FLAG

    # 4. Stage 3
    r3 = client.post("/api/v1/vpc/correlate-c2", json={
        "compromised_ip": "10.0.4.15",
        "c2_ip": "203.0.113.89",
        "c2_port": 8443,
        "protocol": "TCP"
    }).json()
    assert r3["flag"] == STAGE3_FLAG

    # 5. Stage 4
    r4 = client.post("/api/v1/soar/contain-incident", json={
        "revoke_iam_sessions": True,
        "apply_deny_boundary": True,
        "quarantine_security_group": True,
        "snapshot_ebs_volume": True
    }).json()
    assert r4["flag"] == STAGE4_FLAG

    # 6. Verify all solved
    status = client.get("/api/v1/status").json()
    assert status["all_stages_solved"]
    assert status["containment_status"] == "CONTAINED"

    # 7. Reset and verify
    client.post("/api/v1/reset")
    status_after = client.get("/api/v1/status").json()
    assert not status_after["all_stages_solved"]
    assert status_after["containment_status"] == "UNCONTAINED"
