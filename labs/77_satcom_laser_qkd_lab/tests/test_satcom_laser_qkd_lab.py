import os
import sys
import importlib.util
import pytest
import hmac
import hashlib
from fastapi.testclient import TestClient

_app_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "app", "main.py"))
_spec = importlib.util.spec_from_file_location("lab_77_main", _app_path)
_mod = importlib.util.module_from_spec(_spec)
sys.modules["lab_77_main"] = _mod
_spec.loader.exec_module(_mod)

app = _mod.app
SATCOM_SHARED_SECRET = _mod.SATCOM_SHARED_SECRET
client = TestClient(app)


def test_health_and_root():
    r1 = client.get("/")
    assert r1.status_code == 200
    assert r1.json()["status"] == "ready"
    assert r1.json()["port"] == 8077

    r2 = client.get("/api/health")
    assert r2.status_code == 200
    assert r2.json()["status"] == "ok"
    assert r2.json()["lab_id"] == 77
    assert r2.json()["stages"] == 4


def test_stage1_success():
    payload = {
        "satellite_constellation_id": "sat_leo_star_2026_node_primary",
        "laser_beam_divergence_urad": 10.5,
        "doppler_frequency_shift_mhz": 42.8,
        "pointing_accuracy_mas": 12.0
    }
    r = client.post("/api/stage1/eval", json=payload)
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "success"
    assert "FLAG{v227_s1_satcom_laser_isl_doppler_tracking_locked}" in data["flag"]


def test_stage1_failure():
    payload = {
        "satellite_constellation_id": "invalid_sat_id",
        "laser_beam_divergence_urad": 1.0,
        "doppler_frequency_shift_mhz": 999.0,
        "pointing_accuracy_mas": 120.0
    }
    r = client.post("/api/stage1/eval", json=payload)
    assert r.status_code == 400


def test_stage2_success():
    sess_id = "orbit_ephemeris_epoch_2026_77"
    sess_hmac = hmac.new(
        SATCOM_SHARED_SECRET,
        f"orbit_state:{sess_id}".encode(),
        hashlib.sha256
    ).hexdigest()
    payload = {
        "ephemeris_drift_detector_active": True,
        "semi_major_axis_variance_km": 0.018,
        "eccentricity_error_pct": 0.005,
        "orbit_session_id": sess_id,
        "orbit_session_hmac": sess_hmac
    }
    r = client.post("/api/stage2/eval", json=payload)
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "success"
    assert "FLAG{v227_s2_satellite_ephemeris_kalman_drift_shielded}" in data["flag"]


def test_stage2_invalid_hmac():
    payload = {
        "ephemeris_drift_detector_active": True,
        "semi_major_axis_variance_km": 0.018,
        "eccentricity_error_pct": 0.005,
        "orbit_session_id": "orbit_ephemeris_epoch_2026_77",
        "orbit_session_hmac": "invalid_hmac_hex"
    }
    r = client.post("/api/stage2/eval", json=payload)
    assert r.status_code == 403


def test_stage3_success():
    payload = {
        "ttc_replay_defense_active": True,
        "telemetry_command_counter": 2048,
        "ttc_mldsa87_signature": "sig_satcom_ttc_mldsa87_uplink_auth_ok",
        "zero_trust_uplink_isolation": True
    }
    r = client.post("/api/stage3/eval", json=payload)
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "success"
    assert "FLAG{v227_s3_ttc_uplink_mldsa87_command_authenticated}" in data["flag"]


def test_stage4_success():
    kem_hash = hashlib.sha256(b"vibe-satcom-fips203-mlkem1024-shared-key-v227").hexdigest()
    qkd_hmac = hmac.new(
        SATCOM_SHARED_SECRET,
        f"cv_qkd:{kem_hash}".encode(),
        hashlib.sha256
    ).hexdigest()
    payload = {
        "quantum_optical_ber_pct": 0.018,
        "decoy_state_intensity_ratio": 0.45,
        "fips203_ml_kem_shared_key_hash": kem_hash,
        "space_ground_qkd_audit_hmac": qkd_hmac
    }
    r = client.post("/api/stage4/eval", json=payload)
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "success"
    assert "FLAG{v227_s4_space_ground_cv_qkd_decoy_state_secured}" in data["flag"]
