import os
import sys
import importlib.util
from pathlib import Path
import pytest
import hmac
import hashlib
from fastapi.testclient import TestClient

_app_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "app", "main.py"))
_spec = importlib.util.spec_from_file_location("lab_76_main", _app_path)
_mod = importlib.util.module_from_spec(_spec)
sys.modules["lab_76_main"] = _mod
_spec.loader.exec_module(_mod)

app = _mod.app
NEUROMORPHIC_SHARED_SECRET = _mod.NEUROMORPHIC_SHARED_SECRET
client = TestClient(app)


def test_health_and_root():
    r1 = client.get("/")
    assert r1.status_code == 200
    assert r1.json()["status"] == "ready"
    assert r1.json()["port"] == 8076

    r2 = client.get("/api/health")
    assert r2.status_code == 200
    assert r2.json()["status"] == "ok"
    assert r2.json()["lab_id"] == 76
    assert r2.json()["stages"] == 4


def test_stage1_success():
    payload = {
        "neuromorphic_chip_id": "nchip_loihi_2026_core_node_alpha",
        "spike_inter_arrival_time_ns": 12.5,
        "lif_membrane_threshold_mv": -48.0,
        "aer_bus_bandwidth_gbps": 16.0
    }
    r = client.post("/api/stage1/eval", json=payload)
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "success"
    assert "FLAG{v226_s1_snn_aer_spike_timing_fingerprint_ok}" in data["flag"]


def test_stage1_failure():
    payload = {
        "neuromorphic_chip_id": "invalid_chip_id",
        "spike_inter_arrival_time_ns": 1.0,
        "lif_membrane_threshold_mv": -10.0,
        "aer_bus_bandwidth_gbps": 2.0
    }
    r = client.post("/api/stage1/eval", json=payload)
    assert r.status_code == 400


def test_stage2_success():
    sess_id = "snn_sess_epoch_2026_01"
    sess_hmac = hmac.new(
        NEUROMORPHIC_SHARED_SECRET,
        f"glitch_defense:{sess_id}".encode(),
        hashlib.sha256
    ).hexdigest()
    payload = {
        "crossbar_glitch_detector_active": True,
        "memristor_conductance_drift_pct": 0.015,
        "voltage_glitch_threshold_mv": 15.0,
        "snn_session_id": sess_id,
        "snn_session_hmac": sess_hmac
    }
    r = client.post("/api/stage2/eval", json=payload)
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "success"
    assert "FLAG{v226_s2_memristor_voltage_glitch_shield_active}" in data["flag"]


def test_stage2_invalid_hmac():
    payload = {
        "crossbar_glitch_detector_active": True,
        "memristor_conductance_drift_pct": 0.015,
        "voltage_glitch_threshold_mv": 15.0,
        "snn_session_id": "snn_sess_epoch_2026_01",
        "snn_session_hmac": "invalid_hmac_hex"
    }
    r = client.post("/api/stage2/eval", json=payload)
    assert r.status_code == 403


def test_stage3_success():
    payload = {
        "stdp_weight_poisoning_monitor": True,
        "synapse_conductance_variance": 0.008,
        "hardware_rot_binding_active": True,
        "synaptic_circuit_zeroization_latency_ns": 12.0
    }
    r = client.post("/api/stage3/eval", json=payload)
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "success"
    assert "FLAG{v226_s3_stdp_synapse_tamper_rot_secured}" in data["flag"]


def test_stage4_success():
    fw_sha = hashlib.sha256(b"vibe-neuromorphic-snn-firmware-v226").hexdigest()
    merkle_root = hashlib.sha256(b"vibe-memristor-crossbar-merkle-root-v226").hexdigest()
    audit_hmac = hmac.new(
        NEUROMORPHIC_SHARED_SECRET,
        f"{fw_sha}:{merkle_root}".encode(),
        hashlib.sha256
    ).hexdigest()
    payload = {
        "neuromorphic_fw_sha256": fw_sha,
        "memristor_crossbar_merkle_root": merkle_root,
        "ml_dsa_attestation_sig": "sig_neuromorphic_snn_v226_verified_ok",
        "hardware_snn_audit_hmac": audit_hmac
    }
    r = client.post("/api/stage4/eval", json=payload)
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "success"
    assert "FLAG{v226_s4_neuromorphic_snn_mldsa87_attestation_verified}" in data["flag"]
