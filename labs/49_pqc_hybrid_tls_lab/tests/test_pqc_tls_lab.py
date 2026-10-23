#!/usr/bin/env python3
"""
Unit and regression tests for Lab 49: PQCTLSGuard
"""

import sys
import importlib.util
from pathlib import Path
import pytest
from starlette.testclient import TestClient

APP_PATH = Path(__file__).resolve().parent.parent / "app" / "main.py"
spec = importlib.util.spec_from_file_location("lab49_app", str(APP_PATH))
lab49_module = importlib.util.module_from_spec(spec)
sys.modules["lab49_app"] = lab49_module
spec.loader.exec_module(lab49_module)

app = lab49_module.app
state = lab49_module.state
STAGE1_FLAG = lab49_module.STAGE1_FLAG
STAGE2_FLAG = lab49_module.STAGE2_FLAG
STAGE3_FLAG = lab49_module.STAGE3_FLAG
STAGE4_FLAG = lab49_module.STAGE4_FLAG

client = TestClient(app)

@pytest.fixture(autouse=True)
def reset_lab():
    client.post("/api/reset")
    yield
    client.post("/api/reset")

def test_status():
    res = client.get("/status")
    assert res.status_code == 200
    data = res.json()
    assert data["lab"] == "49_pqc_hybrid_tls_lab"
    assert data["port"] == 8049

def test_stage1_hndl_audit():
    res = client.post("/api/stage1/audit_hndl", json={
        "capture_file": "traffic_session.pcap",
        "target_cipher": "ECDHE-RSA-AES256-GCM-SHA384"
    })
    assert res.status_code == 200
    data = res.json()
    assert data["success"] is True
    assert data["flag"] == STAGE1_FLAG

def test_stage2_hybrid_handshake():
    res = client.post("/api/stage2/hybrid_handshake", json={
        "client_named_groups": ["secp256r1", "x25519_mlkem768"],
        "enforce_hybrid_kdf": True
    })
    assert res.status_code == 200
    data = res.json()
    assert data["success"] is True
    assert data["flag"] == STAGE2_FLAG

def test_stage3_mldsa_verify():
    sample_key = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0MLKEMQW908ABCDEFG1234567890\nQWERTYUIOPASDFGHJKLZXCVBNM1234567890QWERTYUIOP\n-----END PUBLIC KEY-----"
    res = client.post("/api/stage3/verify_mldsa", json={
        "algorithm": "ML-DSA-65",
        "public_key_pem": sample_key,
        "signature_bytes": "deadbeefcafebabe01020304"
    })
    assert res.status_code == 200
    data = res.json()
    assert data["success"] is True
    assert data["flag"] == STAGE3_FLAG

def test_stage4_downgrade_prevention():
    res = client.post("/api/stage4/prevent_downgrade", json={
        "allow_classical_rsa_fallback": False,
        "strict_fips203_enforcement": True
    })
    assert res.status_code == 200
    data = res.json()
    assert data["success"] is True
    assert data["flag"] == STAGE4_FLAG
