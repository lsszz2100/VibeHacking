"""Unit & Integration Tests for Lab 55: PQCMigrationGuard."""

import sys
import importlib.util
from pathlib import Path
import pytest
from starlette.testclient import TestClient

APP_PATH = Path(__file__).resolve().parent.parent / "app" / "main.py"
spec = importlib.util.spec_from_file_location("lab55_app", str(APP_PATH))
lab55_module = importlib.util.module_from_spec(spec)
sys.modules["lab55_app"] = lab55_module
spec.loader.exec_module(lab55_module)

app = lab55_module.app
state = lab55_module.state
STAGE1_FLAG = lab55_module.STAGE1_FLAG
STAGE2_FLAG = lab55_module.STAGE2_FLAG
STAGE3_FLAG = lab55_module.STAGE3_FLAG
STAGE4_FLAG = lab55_module.STAGE4_FLAG

client = TestClient(app)


@pytest.fixture(autouse=True)
def reset_state():
    client.post("/api/reset")
    yield
    client.post("/api/reset")


def test_status_endpoint():
    res = client.get("/api/status")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "ready"
    assert data["lab_id"] == "55"
    assert data["stage1_completed"] is False


def test_health_endpoint():
    res = client.get("/api/health")
    assert res.status_code == 200
    assert res.json()["status"] == "ok"


def test_index_page():
    res = client.get("/")
    assert res.status_code == 200
    assert "PQCMigrationGuard" in res.text


def test_stage1_shor_attack():
    # Unsupported algorithm
    res_bad = client.post("/api/stage1/intercept_shor", json={
        "target_algorithm": "DES-56",
        "captured_ciphertext": "abcdef",
        "shor_qubit_count": 4096,
    })
    assert res_bad.status_code == 400

    # Insufficient qubits
    res_low = client.post("/api/stage1/intercept_shor", json={
        "target_algorithm": "RSA-2048",
        "captured_ciphertext": "abcdef",
        "shor_qubit_count": 2048,
    })
    assert res_low.status_code == 200
    assert res_low.json()["success"] is False

    # Successful Shor factoring simulation
    res_ok = client.post("/api/stage1/intercept_shor", json={
        "target_algorithm": "RSA-2048",
        "captured_ciphertext": "a4f91c98e21bc087f912e84c17b8a923",
        "shor_qubit_count": 4096,
    })
    assert res_ok.status_code == 200
    data = res_ok.json()
    assert data["success"] is True
    assert data["flag"] == STAGE1_FLAG


def test_stage2_ml_kem_encapsulate():
    # Invalid dimension k
    res_bad = client.post("/api/stage2/ml_kem_encapsulate", json={
        "recipient_pubkey": "test_pk_123",
        "encapsulation_entropy": "secure_random_seed_16bytes",
        "matrix_dimension_k": 2,
    })
    assert res_bad.status_code == 400

    # Valid encapsulation
    res_ok = client.post("/api/stage2/ml_kem_encapsulate", json={
        "recipient_pubkey": "fips203_ml_kem_768_seed_pk_v1",
        "encapsulation_entropy": "secure_entropy_seed_2026_q3329",
        "matrix_dimension_k": 3,
    })
    assert res_ok.status_code == 200
    data = res_ok.json()
    assert data["success"] is True
    assert "ciphertext_vector_c" in data
    assert data["flag"] == STAGE2_FLAG


def test_stage3_ml_dsa_verify():
    import hashlib
    doc_hash = hashlib.sha256(b"confidential_enterprise_document").hexdigest()
    signer_pk = "signer_mldsa65_pk_2026_enterprise"
    valid_sig = hashlib.sha256(f"mldsa_sig_{doc_hash}_{signer_pk}".encode()).hexdigest()

    # Tampered signature detection
    res_tamper = client.post("/api/stage3/ml_dsa_verify", json={
        "document_hash": doc_hash,
        "signature_hex": valid_sig,
        "signer_pubkey": signer_pk,
        "tamper_test": True,
    })
    assert res_tamper.status_code == 200
    assert res_tamper.json()["verified"] is False

    # Valid signature
    res_ok = client.post("/api/stage3/ml_dsa_verify", json={
        "document_hash": doc_hash,
        "signature_hex": valid_sig,
        "signer_pubkey": signer_pk,
        "tamper_test": False,
    })
    assert res_ok.status_code == 200
    data = res_ok.json()
    assert data["verified"] is True
    assert data["flag"] == STAGE3_FLAG


def test_stage4_hybrid_key_exchange():
    # Downgrade vulnerability triggered when prevention is disabled
    res_downgrade = client.post("/api/stage4/hybrid_key_exchange", json={
        "classical_curve": "X25519",
        "pqc_algorithm": "ML-KEM-768",
        "enable_downgrade_prevention": False,
        "tls_negotiated_group": "secp256r1",
    })
    assert res_downgrade.status_code == 200
    assert res_downgrade.json()["success"] is False

    # Non-hybrid group rejected
    res_reject = client.post("/api/stage4/hybrid_key_exchange", json={
        "classical_curve": "X25519",
        "pqc_algorithm": "ML-KEM-768",
        "enable_downgrade_prevention": True,
        "tls_negotiated_group": "x25519_only",
    })
    assert res_reject.status_code == 200
    assert res_reject.json()["success"] is False

    # Successful hybrid key exchange with anti-downgrade shield
    res_ok = client.post("/api/stage4/hybrid_key_exchange", json={
        "classical_curve": "X25519",
        "pqc_algorithm": "ML-KEM-768",
        "enable_downgrade_prevention": True,
        "tls_negotiated_group": "x25519mlkem768",
    })
    assert res_ok.status_code == 200
    data = res_ok.json()
    assert data["success"] is True
    assert "hybrid_session_key" in data
    assert data["flag"] == STAGE4_FLAG
