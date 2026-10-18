#!/usr/bin/env python3
"""
Unit and integration test suite for Lab 45: PQCShield — Quantum Cryptography Lab
Verifies:
- HTML dashboard serving
- Classical PKI & HNDL Risk Analysis (Stage 1)
- Hybrid KEM Downgrade Attack & MitM exploitation (Stage 2)
- Lattice Side-Channel & Fault Injection Triage (Stage 3)
- FIPS 203 ML-KEM & FIPS 204 ML-DSA Hardening (Stage 4)
- Strict PQC Policy enforcement preventing downgrade attacks
- Stage gating, security validation, and state reset
"""

import sys
import importlib.util
from pathlib import Path
import pytest
from starlette.testclient import TestClient

APP_PATH = Path(__file__).resolve().parent.parent / "app" / "main.py"
spec = importlib.util.spec_from_file_location("lab45_app", str(APP_PATH))
lab45_module = importlib.util.module_from_spec(spec)
sys.modules["lab45_app"] = lab45_module
spec.loader.exec_module(lab45_module)

app = lab45_module.app
STAGE1_FLAG = lab45_module.STAGE1_FLAG
STAGE2_FLAG = lab45_module.STAGE2_FLAG
STAGE3_FLAG = lab45_module.STAGE3_FLAG
STAGE4_FLAG = lab45_module.STAGE4_FLAG

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
    assert "Lab 45: PQCShield" in res.text
    assert "FIPS 203" in res.text
    assert "Stage 1" in res.text


def test_status_endpoint_initial():
    res = client.get("/api/v1/status")
    assert res.status_code == 200
    data = res.json()
    assert data["lab"] == "Lab 45: PQCShield"
    assert not data["all_stages_solved"]
    assert not data["stages"]["stage1_hndl_shor_audit"]["solved"]
    assert not data["stages"]["stage2_hybrid_downgrade"]["solved"]
    assert not data["stages"]["stage3_lattice_fault_audit"]["solved"]
    assert not data["stages"]["stage4_pqc_hardening"]["solved"]
    assert data["hardened_posture"]["strict_pqc_required"] is False


def test_traffic_listing():
    res = client.get("/api/v1/pqc/traffic")
    assert res.status_code == 200
    data = res.json()
    assert data["total"] >= 3
    sessions = data["sessions"]
    assert any(s["key_exchange"] == "RSA-2048" for s in sessions)
    assert any(s["key_exchange"] == "X25519MLKEM768" for s in sessions)


def test_stage1_analyze_vulnerable_traffic():
    res = client.post("/api/v1/pqc/traffic/analyze", json={
        "session_id": "sess-tls-001",
        "analysis_type": "shor_factorization"
    })
    assert res.status_code == 200
    data = res.json()
    assert data["vulnerable_to_shor"] is True
    assert data["hndl_exposure"] == "CRITICAL"
    assert data["flag"] == STAGE1_FLAG

    # Check status updated
    status = client.get("/api/v1/status").json()
    assert status["stages"]["stage1_hndl_shor_audit"]["solved"] is True


def test_stage1_analyze_safe_traffic():
    res = client.post("/api/v1/pqc/traffic/analyze", json={
        "session_id": "sess-tls-003",
        "analysis_type": "shor_factorization"
    })
    assert res.status_code == 200
    data = res.json()
    assert data["vulnerable_to_shor"] is False
    assert data["hndl_exposure"] == "SAFE"


def test_stage1_session_not_found():
    res = client.post("/api/v1/pqc/traffic/analyze", json={
        "session_id": "non-existent-session",
        "analysis_type": "shor_factorization"
    })
    assert res.status_code == 404


def test_stage2_handshake_and_downgrade():
    res = client.get("/api/v1/pqc/hybrid/handshake")
    assert res.status_code == 200
    data = res.json()
    assert "x25519_kyber768" in data["client_hello"]["supported_groups"]

    # Execute downgrade exploit
    exploit_res = client.post("/api/v1/pqc/hybrid/downgrade-exploit", json={
        "strip_extension": "x25519_kyber768",
        "target_group": "x25519"
    })
    assert exploit_res.status_code == 200
    exp_data = exploit_res.json()
    assert exp_data["downgrade_successful"] is True
    assert exp_data["flag"] == STAGE2_FLAG

    # Verify status
    status = client.get("/api/v1/status").json()
    assert status["stages"]["stage2_hybrid_downgrade"]["solved"] is True


def test_stage3_oracle_and_fault_triage():
    res = client.get("/api/v1/pqc/lattice/oracle")
    assert res.status_code == 200
    logs = res.json()["logs"]
    assert len(logs) >= 3

    # Audit timing anomaly
    audit_res = client.post("/api/v1/pqc/lattice/fault-audit", json={
        "audit_target": "timing_skew",
        "remediation_proposal": "constant_time_ntt"
    })
    assert audit_res.status_code == 200
    data = audit_res.json()
    assert data["status"] == "TRIAGE_COMPLETE"
    assert data["flag"] == STAGE3_FLAG

    # Verify status
    status = client.get("/api/v1/status").json()
    assert status["stages"]["stage3_lattice_fault_audit"]["solved"] is True


def test_stage3_invalid_proposal():
    res = client.post("/api/v1/pqc/lattice/fault-audit", json={
        "audit_target": "timing_skew",
        "remediation_proposal": "invalid_remediation"
    })
    assert res.status_code == 400


def test_stage4_hardening_and_downgrade_prevention():
    # Deploy hardening
    res = client.post("/api/v1/pqc/harden", json={
        "strict_pqc_required": True,
        "kem_standard": "FIPS 203 (ML-KEM-768)",
        "signature_standard": "FIPS 204 (ML-DSA-65)",
        "dual_kdf_binding": True,
        "constant_time_ntt": True
    })
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "HARDENED"
    assert data["flag"] == STAGE4_FLAG

    # Verify status is hardened
    status = client.get("/api/v1/status").json()
    assert status["stages"]["stage4_pqc_hardening"]["solved"] is True
    assert status["hardened_posture"]["strict_pqc_required"] is True

    # Test that downgrade attack is now strictly blocked
    downgrade_res = client.post("/api/v1/pqc/hybrid/downgrade-exploit", json={
        "strip_extension": "x25519_kyber768",
        "target_group": "x25519"
    })
    assert downgrade_res.status_code == 403
    assert "Strict PQC Policy" in downgrade_res.json()["detail"]


def test_certificate_verification():
    res = client.get("/api/v1/pqc/certificate/verify")
    assert res.status_code == 200
    data = res.json()
    assert "FIPS 204" in data["root_ca"]["algorithm"]
    assert data["server_leaf"]["status"] == "VALID_POST_QUANTUM_TRUST_ANCHOR"


def test_full_scenario_progression():
    # Step 1
    res1 = client.post("/api/v1/pqc/traffic/analyze", json={
        "session_id": "sess-tls-001",
        "analysis_type": "shor_factorization"
    })
    assert res1.json()["flag"] == STAGE1_FLAG

    # Step 2
    res2 = client.post("/api/v1/pqc/hybrid/downgrade-exploit", json={
        "strip_extension": "x25519_kyber768",
        "target_group": "x25519"
    })
    assert res2.json()["flag"] == STAGE2_FLAG

    # Step 3
    res3 = client.post("/api/v1/pqc/lattice/fault-audit", json={
        "audit_target": "rejection_sampling_fault",
        "remediation_proposal": "strict_norm_bound_assertion"
    })
    assert res3.json()["flag"] == STAGE3_FLAG

    # Step 4
    res4 = client.post("/api/v1/pqc/harden", json={
        "strict_pqc_required": True,
        "kem_standard": "FIPS 203 (ML-KEM-768)",
        "signature_standard": "FIPS 204 (ML-DSA-65)",
        "dual_kdf_binding": True,
        "constant_time_ntt": True
    })
    assert res4.json()["flag"] == STAGE4_FLAG

    # Final status: All solved
    final_status = client.get("/api/v1/status").json()
    assert final_status["all_stages_solved"] is True
