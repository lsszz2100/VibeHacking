import os
import sys
import importlib.util
from pathlib import Path
import pytest
import hmac
import hashlib
from fastapi.testclient import TestClient

_app_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "app", "main.py"))
_spec = importlib.util.spec_from_file_location("lab_69_main", _app_path)
_mod = importlib.util.module_from_spec(_spec)
sys.modules["lab_69_main"] = _mod
_spec.loader.exec_module(_mod)

app = _mod.app
WEIGHT_SHARED_SECRET = _mod.WEIGHT_SHARED_SECRET
client = TestClient(app)

def test_health_and_root():
    r = client.get("/api/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"
    assert r.json()["lab_id"] == 69

    res = client.get("/")
    assert res.status_code == 200
    data = res.json()
    assert data["port"] == 8069
    assert data["stages"] == 4
    assert data["status"] == "ready"

def test_stage1_success():
    p = {
        "model_format": "safetensors",
        "magic_header": "safetensors-v1",
        "reject_pickle_opcodes": True,
        "header_metadata_json": {
            "__metadata__": {"framework": "pt"},
            "tensor": {"dtype": "F32", "shape": [10, 10]}
        }
    }
    res = client.post("/api/stage1/eval", json=p)
    assert res.status_code == 200
    assert "FLAG{v219_s1_safetensors_pickle_deserialization_blocked}" in res.json()["flag"]

def test_stage1_pickle_rejection():
    p = {
        "model_format": "pytorch_pickle",
        "magic_header": "bad-header",
        "reject_pickle_opcodes": False,
        "header_metadata_json": {}
    }
    res = client.post("/api/stage1/eval", json=p)
    assert res.status_code == 400

def test_stage2_success():
    p = {
        "layer_name": "transformer.encoder.layer.0.attention.weight",
        "weight_precision": "float32",
        "lsb_bitmask_sanitization": True,
        "quantization_clipping": True
    }
    res = client.post("/api/stage2/eval", json=p)
    assert res.status_code == 200
    assert "FLAG{v219_s2_neural_weight_lsb_stego_neutralized}" in res.json()["flag"]

def test_stage3_success():
    p = {
        "chi_square_p_value": 0.35,
        "shannon_entropy": 7.42,
        "variance_threshold": 0.02,
        "statistical_anomaly_detected": True
    }
    res = client.post("/api/stage3/eval", json=p)
    assert res.status_code == 200
    assert "FLAG{v219_s3_statistical_chi_square_weight_anomaly_detected}" in res.json()["flag"]

def test_stage3_entropy_exceeded():
    p = {
        "chi_square_p_value": 0.35,
        "shannon_entropy": 7.99,
        "variance_threshold": 0.02,
        "statistical_anomaly_detected": True
    }
    res = client.post("/api/stage3/eval", json=p)
    assert res.status_code == 400

def test_stage4_success():
    model_hash = "f" * 64
    rekor_idx = 10042
    audit_hmac = hmac.new(
        WEIGHT_SHARED_SECRET,
        f"{model_hash}:{rekor_idx}".encode(),
        hashlib.sha256
    ).hexdigest()
    p = {
        "model_sha256": model_hash,
        "sigstore_rekor_log_index": rekor_idx,
        "ed25519_signature": "valid-sig",
        "merkle_root_audit_hmac": audit_hmac
    }
    res = client.post("/api/stage4/eval", json=p)
    assert res.status_code == 200
    assert "FLAG{v219_s4_sigstore_model_provenance_merkle_verified}" in res.json()["flag"]

def test_stage4_invalid_hmac():
    p = {
        "model_sha256": "f" * 64,
        "sigstore_rekor_log_index": 10042,
        "ed25519_signature": "valid-sig",
        "merkle_root_audit_hmac": "bad_hmac"
    }
    res = client.post("/api/stage4/eval", json=p)
    assert res.status_code == 401
