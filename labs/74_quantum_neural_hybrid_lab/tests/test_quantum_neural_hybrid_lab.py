import os
import sys
import importlib.util
from pathlib import Path
import pytest
import hmac
import hashlib
from fastapi.testclient import TestClient

_app_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "app", "main.py"))
_spec = importlib.util.spec_from_file_location("lab_74_main", _app_path)
_mod = importlib.util.module_from_spec(_spec)
sys.modules["lab_74_main"] = _mod
_spec.loader.exec_module(_mod)

app = _mod.app
QUANTUM_NN_SHARED_SECRET = _mod.QUANTUM_NN_SHARED_SECRET
client = TestClient(app)

def test_health_and_root():
    res = client.get("/api/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "ok"
    assert data["lab_id"] == 74
    assert data["stages"] == 4

    res = client.get("/")
    assert res.status_code == 200
    data = res.json()
    assert data["port"] == 8074
    assert data["status"] == "ready"

def test_stage1_success():
    payload = {
        "qnn_ansatz": "parameterized_quantum_circuit_hardware_efficient",
        "adversarial_epsilon": 0.02,
        "qfi_divergence_threshold": 1.85,
        "entanglement_depth": 6
    }
    res = client.post("/api/stage1/eval", json=payload)
    assert res.status_code == 200
    assert "FLAG{v224_s1_qnn_fisher_information_filter_secured}" == res.json()["flag"]

def test_stage1_failure():
    payload = {
        "qnn_ansatz": "uncalibrated_raw_variational_layer",
        "adversarial_epsilon": 0.25,
        "qfi_divergence_threshold": 0.5,
        "entanglement_depth": 1
    }
    res = client.post("/api/stage1/eval", json=payload)
    assert res.status_code == 400

def test_stage2_success():
    zero_proto = "active_reset_pauli_twirling"
    session_id = "test_qpu_sess_01"
    zero_hmac = hmac.new(
        QUANTUM_NN_SHARED_SECRET,
        f"{zero_proto}:{session_id}".encode(),
        hashlib.sha256
    ).hexdigest()
    payload = {
        "zeroization_protocol": zero_proto,
        "pauli_twirling_rounds": 128,
        "residual_state_fidelity": 0.0005,
        "qpu_session_id": session_id,
        "zeroization_hmac": zero_hmac
    }
    res = client.post("/api/stage2/eval", json=payload)
    assert res.status_code == 200
    assert "FLAG{v224_s2_qpu_memory_zeroization_coherence_reset}" == res.json()["flag"]

def test_stage2_invalid_hmac():
    payload = {
        "zeroization_protocol": "active_reset_pauli_twirling",
        "pauli_twirling_rounds": 128,
        "residual_state_fidelity": 0.0005,
        "qpu_session_id": "fake_sess",
        "zeroization_hmac": "deadbeef" * 8
    }
    res = client.post("/api/stage2/eval", json=payload)
    assert res.status_code == 403

def test_stage3_success():
    payload = {
        "pqc_kem_scheme": "ml_kem_1024",
        "gradient_noise_snr_db": 28.5,
        "cross_domain_attestation_active": True,
        "parameter_tampering_blocked": True
    }
    res = client.post("/api/stage3/eval", json=payload)
    assert res.status_code == 200
    assert "FLAG{v224_s3_hybrid_pqc_gradient_shield_isolated}" == res.json()["flag"]

def test_stage4_success():
    microcode_sha256 = hashlib.sha256(b"vibe-qpu-test-microcode").hexdigest()
    circuit_merkle = hashlib.sha256(b"vibe-qnn-circuit-test").hexdigest()
    qpu_hmac = hmac.new(
        QUANTUM_NN_SHARED_SECRET,
        f"{microcode_sha256}:{circuit_merkle}".encode(),
        hashlib.sha256
    ).hexdigest()
    payload = {
        "qpu_microcode_sha256": microcode_sha256,
        "qnn_circuit_merkle_root": circuit_merkle,
        "attestation_sig": "sig_qnn_hybrid_v224_test_ok",
        "qpu_audit_hmac": qpu_hmac
    }
    res = client.post("/api/stage4/eval", json=payload)
    assert res.status_code == 200
    assert "FLAG{v224_s4_qnn_circuit_merkle_provenance_attested}" == res.json()["flag"]
