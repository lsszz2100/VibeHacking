import os
import sys
import importlib.util
from pathlib import Path
import pytest
import hmac
import hashlib
from fastapi.testclient import TestClient

_app_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "app", "main.py"))
_spec = importlib.util.spec_from_file_location("lab_73_main", _app_path)
_mod = importlib.util.module_from_spec(_spec)
sys.modules["lab_73_main"] = _mod
_spec.loader.exec_module(_mod)

app = _mod.app
PHOTONICS_SHARED_SECRET = _mod.PHOTONICS_SHARED_SECRET
client = TestClient(app)

def test_health_and_root():
    res = client.get("/api/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "ok"
    assert data["lab_id"] == 73
    assert data["stages"] == 4

    res = client.get("/")
    assert res.status_code == 200
    data = res.json()
    assert data["port"] == 8073
    assert data["status"] == "ready"

def test_stage1_success():
    payload = {
        "scrambling_policy": "optical_line_rate_pseudo_random_scramble",
        "optical_dummy_padding_active": True,
        "line_rate_jitter_enabled": True,
        "scramble_polynomials": ["poly_prbs31_cpo", "poly_fibonacci_optical"]
    }
    res = client.post("/api/stage1/eval", json=payload)
    assert res.status_code == 200
    assert "FLAG{v223_s1_optical_bus_scrambling_line_padded}" == res.json()["flag"]

def test_stage1_failure():
    payload = {
        "scrambling_policy": "unscrambled_raw_optical_stream",
        "optical_dummy_padding_active": False,
        "line_rate_jitter_enabled": False,
        "scramble_polynomials": []
    }
    res = client.post("/api/stage1/eval", json=payload)
    assert res.status_code == 400

def test_stage2_success():
    qkd_proto = "bb84_decoy_state"
    key_id = "qkd_test_key_01"
    audit_hmac = hmac.new(
        PHOTONICS_SHARED_SECRET,
        f"{qkd_proto}:{key_id}".encode(),
        hashlib.sha256
    ).hexdigest()
    payload = {
        "qkd_protocol": qkd_proto,
        "qber_threshold_pct": 3.8,
        "quantum_channel_active": True,
        "session_key_id": key_id,
        "qkd_audit_hmac": audit_hmac
    }
    res = client.post("/api/stage2/eval", json=payload)
    assert res.status_code == 200
    assert "FLAG{v223_s2_qkd_continuous_quantum_key_rotated}" == res.json()["flag"]

def test_stage2_invalid_hmac():
    payload = {
        "qkd_protocol": "bb84_decoy_state",
        "qber_threshold_pct": 3.8,
        "quantum_channel_active": True,
        "session_key_id": "key_fake",
        "qkd_audit_hmac": "deadbeef" * 8
    }
    res = client.post("/api/stage2/eval", json=payload)
    assert res.status_code == 403

def test_stage3_success():
    payload = {
        "waveguide_isolation_mode": "dielectric_cladding_shield",
        "wdm_channel_spacing_ghz": 200,
        "cross_talk_quarantine_enforced": True,
        "adjacent_wavelength_leak_blocked": True
    }
    res = client.post("/api/stage3/eval", json=payload)
    assert res.status_code == 200
    assert "FLAG{v223_s3_wdm_waveguide_cross_talk_isolated}" == res.json()["flag"]

def test_stage4_success():
    firmware_sha256 = hashlib.sha256(b"vibe-cpo-test-fw").hexdigest()
    merkle_root = hashlib.sha256(b"vibe-photonics-merkle-test").hexdigest()
    transceiver_hmac = hmac.new(
        PHOTONICS_SHARED_SECRET,
        f"{firmware_sha256}:{merkle_root}".encode(),
        hashlib.sha256
    ).hexdigest()
    payload = {
        "transceiver_firmware_sha256": firmware_sha256,
        "photonics_merkle_root": merkle_root,
        "attestation_sig": "sig_cpo_transceiver_v223_test_ok",
        "transceiver_audit_hmac": transceiver_hmac
    }
    res = client.post("/api/stage4/eval", json=payload)
    assert res.status_code == 200
    assert "FLAG{v223_s4_optical_transceiver_merkle_attested}" == res.json()["flag"]
