import os
import sys
import importlib.util
from pathlib import Path
import pytest
import hmac
import hashlib
from fastapi.testclient import TestClient

_app_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "app", "main.py"))
_spec = importlib.util.spec_from_file_location("lab_75_main", _app_path)
_mod = importlib.util.module_from_spec(_spec)
sys.modules["lab_75_main"] = _mod
_spec.loader.exec_module(_mod)

app = _mod.app
PHOTONIC_PUF_SHARED_SECRET = _mod.PHOTONIC_PUF_SHARED_SECRET
client = TestClient(app)

def test_health_and_root():
    r1 = client.get("/")
    assert r1.status_code == 200
    assert r1.json()["status"] == "ready"
    assert r1.json()["port"] == 8075

    r2 = client.get("/api/health")
    assert r2.status_code == 200
    assert r2.json()["status"] == "ok"
    assert r2.json()["lab_id"] == 75
    assert r2.json()["stages"] == 4

def test_stage1_success():
    payload = {
        "silicon_die_id": "die_sp_die_2026_chiplet_a01",
        "optical_speckle_phase_rad": 1.95,
        "mrr_resonance_q_factor": 25000.0,
        "speckle_entropy_bits": 256.0
    }
    r = client.post("/api/stage1/eval", json=payload)
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "success"
    assert "FLAG{v225_s1_photonic_puf_speckle_key_derived_ok}" in data["flag"]

def test_stage1_failure():
    payload = {
        "silicon_die_id": "invalid_die_id",
        "optical_speckle_phase_rad": 0.5,
        "mrr_resonance_q_factor": 500.0,
        "speckle_entropy_bits": 16.0
    }
    r = client.post("/api/stage1/eval", json=payload)
    assert r.status_code == 400

def test_stage2_success():
    sess_id = "puf_sess_epoch_2026_01"
    sess_hmac = hmac.new(
        PHOTONIC_PUF_SHARED_SECRET,
        f"crp_defense:{sess_id}".encode(),
        hashlib.sha256
    ).hexdigest()
    payload = {
        "crp_modeling_defense_active": True,
        "phase_scrambler_rate_ghz": 12.5,
        "cmaes_prediction_resistance": 0.9999,
        "puf_session_id": sess_id,
        "puf_session_hmac": sess_hmac
    }
    r = client.post("/api/stage2/eval", json=payload)
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "success"
    assert "FLAG{v225_s2_mrr_crp_modeling_attack_scrambled}" in data["flag"]

def test_stage2_invalid_hmac():
    payload = {
        "crp_modeling_defense_active": True,
        "phase_scrambler_rate_ghz": 12.5,
        "cmaes_prediction_resistance": 0.9999,
        "puf_session_id": "puf_sess_epoch_2026_01",
        "puf_session_hmac": "invalid_hmac_hex"
    }
    r = client.post("/api/stage2/eval", json=payload)
    assert r.status_code == 403

def test_stage3_success():
    payload = {
        "anti_tamper_optical_monitor": True,
        "chiplet_disconnection_threshold_db": 4.5,
        "optical_erasure_latency_ns": 15.0,
        "hardware_rot_binding_active": True
    }
    r = client.post("/api/stage3/eval", json=payload)
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "success"
    assert "FLAG{v225_s3_chiplet_optical_erasure_rot_secured}" in data["flag"]

def test_stage4_success():
    fw_sha = hashlib.sha256(b"vibe-photonic-puf-firmware-v225").hexdigest()
    merkle_root = hashlib.sha256(b"vibe-waveguide-merkle-tree-root-v225").hexdigest()
    audit_hmac = hmac.new(
        PHOTONIC_PUF_SHARED_SECRET,
        f"{fw_sha}:{merkle_root}".encode(),
        hashlib.sha256
    ).hexdigest()
    payload = {
        "chiplet_firmware_sha256": fw_sha,
        "photonic_waveguide_merkle_root": merkle_root,
        "ml_dsa_attestation_sig": "sig_photonic_puf_v225_verified_ok",
        "hardware_puf_audit_hmac": audit_hmac
    }
    r = client.post("/api/stage4/eval", json=payload)
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "success"
    assert "FLAG{v225_s4_mldsa87_chiplet_remote_attestation_passed}" in data["flag"]
