import hashlib
import hmac
import importlib.util
import os
import sys
from fastapi.testclient import TestClient

_app_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "app", "main.py"))
_spec = importlib.util.spec_from_file_location("lab_79_main", _app_path)
_mod = importlib.util.module_from_spec(_spec)
sys.modules["lab_79_main"] = _mod
_spec.loader.exec_module(_mod)

app = _mod.app
ORAN_SHARED_SECRET = _mod.ORAN_SHARED_SECRET
client = TestClient(app)


def test_health_status_and_root():
    r1 = client.get("/")
    assert r1.status_code == 200
    assert r1.json()["status"] == "ready"
    assert r1.json()["port"] == 8079

    r2 = client.get("/api/health")
    assert r2.status_code == 200
    assert r2.json()["status"] == "ok"
    assert r2.json()["lab_id"] == 79
    assert r2.json()["stages"] == 4

    r3 = client.get("/api/status")
    assert r3.status_code == 200
    assert r3.json()["lab_id"] == "79"
    assert r3.json()["total_stages"] == 4


def test_stage1_success_and_failure():
    ok = client.post("/api/stage1/eval", json={
        "xapp_id": "xapp_oran_2026_kpm_guard",
        "spiffe_svid_uri": "spiffe://oran.vibe.local/ns/ric/sa/kpm-guard",
        "e2_mtls_verified": True,
        "e2sm_kpm_schema_allowlisted": True,
    })
    assert ok.status_code == 200
    assert "FLAG{v229_s1_oran_e2_spiffe_mtls_xapp_verified}" in ok.json()["flag"]

    bad = client.post("/api/stage1/eval", json={
        "xapp_id": "rogue_xapp",
        "spiffe_svid_uri": "spiffe://evil.local/sa/x",
        "e2_mtls_verified": False,
        "e2sm_kpm_schema_allowlisted": False,
    })
    assert bad.status_code == 400


def test_stage2_success_and_invalid_hmac():
    sid = "ecpri_fh_2026_79_alpha"
    mac = hmac.new(ORAN_SHARED_SECRET, f"ecpri_session:{sid}".encode(), hashlib.sha256).hexdigest()
    ok = client.post("/api/stage2/eval", json={
        "fronthaul_protocol": "ecpri_split_7_2x",
        "macsec_cipher": "AES-256-GCM",
        "ptp_nts_authenticated": True,
        "ptp_clock_drift_ns": 24.5,
        "ecpri_session_id": sid,
        "ecpri_frame_hmac": mac,
    })
    assert ok.status_code == 200
    assert "FLAG{v229_s2_ecpri_macsec_ptp_sync_hardened}" in ok.json()["flag"]

    bad = client.post("/api/stage2/eval", json={
        "fronthaul_protocol": "ecpri_split_7_2x",
        "macsec_cipher": "AES-256-GCM",
        "ptp_nts_authenticated": True,
        "ptp_clock_drift_ns": 24.5,
        "ecpri_session_id": sid,
        "ecpri_frame_hmac": "deadbeef",
    })
    assert bad.status_code == 403


def test_stage3_success_and_failure():
    ok = client.post("/api/stage3/eval", json={
        "slice_sst": 1,
        "a1_policy_signed_rbac": True,
        "sla_bandwidth_guarantees_pct": 99.5,
        "upf_teid_isolation_active": True,
    })
    assert ok.status_code == 200
    assert "FLAG{v229_s3_oran_a1_slice_teid_isolation_enforced}" in ok.json()["flag"]

    bad = client.post("/api/stage3/eval", json={
        "slice_sst": 99,
        "a1_policy_signed_rbac": False,
        "sla_bandwidth_guarantees_pct": 12.0,
        "upf_teid_isolation_active": False,
    })
    assert bad.status_code == 400


def test_stage4_success_and_failure():
    ho_hash = hashlib.sha256(b"leo_handover_2026_79").hexdigest()
    ho_hmac = hmac.new(ORAN_SHARED_SECRET, f"ntn_handover:{ho_hash}".encode(), hashlib.sha256).hexdigest()
    ok = client.post("/api/stage4/eval", json={
        "pqc_kem_suite": "X25519_MLKEM768",
        "fips204_mldsa65_ric_attestation": "sig_oran_mldsa65_ric_enclave_attested",
        "ntn_handover_quorum_nodes": 4,
        "handover_token_hash": ho_hash,
        "oran_audit_hmac": ho_hmac,
    })
    assert ok.status_code == 200
    assert "FLAG{v229_s4_6g_ntn_pqc_handover_attested}" in ok.json()["flag"]

    bad = client.post("/api/stage4/eval", json={
        "pqc_kem_suite": "X25519_MLKEM768",
        "fips204_mldsa65_ric_attestation": "forged_sig",
        "ntn_handover_quorum_nodes": 4,
        "handover_token_hash": ho_hash,
        "oran_audit_hmac": ho_hmac,
    })
    assert bad.status_code == 403
