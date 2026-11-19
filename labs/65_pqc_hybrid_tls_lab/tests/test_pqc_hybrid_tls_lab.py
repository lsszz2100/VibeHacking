import os
import sys
import importlib.util
from pathlib import Path
from starlette.testclient import TestClient

_app_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "app", "main.py"))
_spec = importlib.util.spec_from_file_location("lab_65_main", _app_path)
_mod = importlib.util.module_from_spec(_spec)
sys.modules["lab_65_main"] = _mod
_spec.loader.exec_module(_mod)

app = _mod.app
client = TestClient(app)


def test_index_and_health():
    res = client.get("/")
    assert res.status_code == 200
    assert "Lab 65" in res.text

    h = client.get("/api/health")
    assert h.status_code == 200
    data = h.json()
    assert data["status"] == "healthy"
    assert data["port"] == 8065


def test_stage1_classical_sndl_vulnerable():
    res = client.post("/api/stage1/eval", json={
        "key_exchange_group": "x25519",
        "sndl_intercept_sim": True,
        "use_hybrid_kem": False
    })
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "vulnerable"
    assert "SNDL 취약점" in data["message"]
    assert "flag" not in data


def test_stage1_pqc_hybrid_kem_defense():
    res = client.post("/api/stage1/eval", json={
        "key_exchange_group": "X25519_MLKEM768",
        "sndl_intercept_sim": True,
        "use_hybrid_kem": True
    })
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "defended"
    assert data["flag"] == "FLAG{pqc_hybrid_kem_sndl_resilient_2026}"


def test_stage2_quantum_forgery_vulnerable():
    res = client.post("/api/stage2/eval", json={
        "cert_algorithm": "RSA3072",
        "dual_signature_validation": False,
        "use_mldsa_guard": False
    })
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "vulnerable"
    assert "서명 위조 취약점" in data["message"]


def test_stage2_mldsa_composite_defense():
    res = client.post("/api/stage2/eval", json={
        "cert_algorithm": "COMPOSITE_MLDSA65_ECDSA",
        "dual_signature_validation": True,
        "use_mldsa_guard": True
    })
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "defended"
    assert data["flag"] == "FLAG{pqc_dual_sig_mldsa_composite_certified}"


def test_stage3_active_downgrade_vulnerable():
    res = client.post("/api/stage3/eval", json={
        "offered_versions": ["TLSv1.2", "TLSv1.3"],
        "cipher_suites": ["TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"],
        "supported_groups": ["x25519"],
        "enforce_anti_downgrade": False
    })
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "vulnerable"
    assert "다운그레이드 공격 노출" in data["message"]


def test_stage3_strict_tls13_defense():
    res = client.post("/api/stage3/eval", json={
        "offered_versions": ["TLSv1.3"],
        "cipher_suites": ["TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"],
        "supported_groups": ["X25519_MLKEM768"],
        "enforce_anti_downgrade": True
    })
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "defended"
    assert data["flag"] == "FLAG{pqc_anti_downgrade_strict_handshake_guarded}"


def test_stage4_side_channel_timing_vulnerable():
    res = client.post("/api/stage4/eval", json={
        "ntt_algorithm": "unmasked_standard_ntt",
        "side_channel_probe": True,
        "use_masked_memory": False
    })
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "vulnerable"
    assert "부채널 타이밍 공격 노출" in data["message"]


def test_stage4_constant_time_ntt_defense():
    res = client.post("/api/stage4/eval", json={
        "ntt_algorithm": "constant_time_masked_ntt",
        "side_channel_probe": True,
        "use_masked_memory": True
    })
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "defended"
    assert data["flag"] == "FLAG{pqc_constant_time_ntt_masked_hardened}"
