import os
import sys
import importlib.util
import pytest
import hmac
import hashlib
from fastapi.testclient import TestClient

_app_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "app", "main.py"))
_spec = importlib.util.spec_from_file_location("lab_78_main", _app_path)
_mod = importlib.util.module_from_spec(_spec)
sys.modules["lab_78_main"] = _mod
_spec.loader.exec_module(_mod)

app = _mod.app
FEDAI_SHARED_SECRET = _mod.FEDAI_SHARED_SECRET
client = TestClient(app)


def test_health_and_root():
    r1 = client.get("/")
    assert r1.status_code == 200
    assert r1.json()["status"] == "ready"
    assert r1.json()["port"] == 8078

    r2 = client.get("/api/health")
    assert r2.status_code == 200
    assert r2.json()["status"] == "ok"
    assert r2.json()["lab_id"] == 78
    assert r2.json()["stages"] == 4


def test_stage1_success():
    payload = {
        "client_node_id": "fed_worker_fl_2026_node_alpha",
        "gradient_l2_norm": 0.45,
        "cosine_similarity_to_global": 0.94,
        "gradient_explosion_clipping_active": True
    }
    r = client.post("/api/stage1/eval", json=payload)
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "success"
    assert "FLAG{v228_s1_fedai_byzantine_norm_clipping_secured}" in data["flag"]


def test_stage1_failure():
    payload = {
        "client_node_id": "invalid_worker_id",
        "gradient_l2_norm": 99.0,
        "cosine_similarity_to_global": 0.20,
        "gradient_explosion_clipping_active": False
    }
    r = client.post("/api/stage1/eval", json=payload)
    assert r.status_code == 400


def test_stage2_success():
    round_id = "fl_epoch_round_2026_78_beta"
    round_hmac = hmac.new(
        FEDAI_SHARED_SECRET,
        f"round_epoch:{round_id}".encode(),
        hashlib.sha256
    ).hexdigest()
    payload = {
        "aggregation_protocol": "multi_krum",
        "byzantine_participants_f": 3,
        "multi_krum_selected_count": 8,
        "federated_round_id": round_id,
        "round_token_hmac": round_hmac
    }
    r = client.post("/api/stage2/eval", json=payload)
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "success"
    assert "FLAG{v228_s2_multikrum_byzantine_aggregation_resilient}" in data["flag"]


def test_stage2_invalid_hmac():
    payload = {
        "aggregation_protocol": "multi_krum",
        "byzantine_participants_f": 3,
        "multi_krum_selected_count": 8,
        "federated_round_id": "fl_epoch_round_2026_78_beta",
        "round_token_hmac": "invalid_round_hmac_hex"
    }
    r = client.post("/api/stage2/eval", json=payload)
    assert r.status_code == 403


def test_stage3_success():
    payload = {
        "dp_sgd_gaussian_noise_sigma": 1.45,
        "privacy_budget_epsilon": 2.4,
        "delta_bound": 1e-6,
        "membership_inference_defense_active": True
    }
    r = client.post("/api/stage3/eval", json=payload)
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "success"
    assert "FLAG{v228_s3_differential_privacy_dpsgd_epsilon_shielded}" in data["flag"]


def test_stage4_success():
    mpc_hash = hashlib.sha256(b"vibe-fedai-secure-aggregation-secret-sharing-v228").hexdigest()
    mpc_hmac = hmac.new(
        FEDAI_SHARED_SECRET,
        f"mpc_session:{mpc_hash}".encode(),
        hashlib.sha256
    ).hexdigest()
    payload = {
        "secret_sharing_mask_verified": True,
        "fips204_mldsa87_node_attestation": "sig_fedai_mldsa87_hardware_enclave_attested",
        "secure_mpc_quorum_count": 9,
        "mpc_session_token_hash": mpc_hash,
        "federated_audit_hmac": mpc_hmac
    }
    r = client.post("/api/stage4/eval", json=payload)
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "success"
    assert "FLAG{v228_s4_secure_mpc_federated_mldsa87_attested}" in data["flag"]
