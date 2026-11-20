import os
import sys
import importlib.util
from pathlib import Path
import pytest
import hmac
import hashlib
from starlette.testclient import TestClient

_app_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "app", "main.py"))
_spec = importlib.util.spec_from_file_location("lab_67_main", _app_path)
_mod = importlib.util.module_from_spec(_spec)
sys.modules["lab_67_main"] = _mod
_spec.loader.exec_module(_mod)

app = _mod.app
SHARED_TPM_SECRET = _mod.SHARED_TPM_SECRET
client = TestClient(app)

def test_health_and_root():
    r = client.get("/api/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"
    assert r.json()["lab_id"] == 67

    r2 = client.get("/")
    assert r2.status_code == 200
    assert r2.json()["port"] == 8067

    r3 = client.get("/api/stages")
    assert r3.status_code == 200
    assert len(r3.json()["stages"]) == 4

def test_stage1_attestation():
    # Invalid hardware
    r_bad = client.post("/api/stage1/eval", json={
        "hardware_provider": "unknown-cpu",
        "attestation_quote": "41" * 64,
        "measurement_pcr0": "a" * 64,
        "require_snp_vcek": True
    })
    assert r_bad.status_code == 400

    # Short quote
    r_bad_quote = client.post("/api/stage1/eval", json={
        "hardware_provider": "amd-sev-snp",
        "attestation_quote": "short",
        "measurement_pcr0": "a" * 64,
        "require_snp_vcek": True
    })
    assert r_bad_quote.status_code == 400

    # Invalid PCR0 length
    r_bad_pcr0 = client.post("/api/stage1/eval", json={
        "hardware_provider": "intel-tdx",
        "attestation_quote": "41" * 64,
        "measurement_pcr0": "short",
        "require_snp_vcek": True
    })
    assert r_bad_pcr0.status_code == 400

    # Missing VCEK verification
    r_bad_vcek = client.post("/api/stage1/eval", json={
        "hardware_provider": "amd-sev-snp",
        "attestation_quote": "41" * 64,
        "measurement_pcr0": "a" * 64,
        "require_snp_vcek": False
    })
    assert r_bad_vcek.status_code == 400

    # Valid
    r_ok = client.post("/api/stage1/eval", json={
        "hardware_provider": "amd-sev-snp",
        "attestation_quote": "41" * 64,
        "measurement_pcr0": "a" * 64,
        "require_snp_vcek": True
    })
    assert r_ok.status_code == 200
    assert "FLAG{teeai_sev_snp_hardware_attestation_verified_8067}" in r_ok.json()["flag"]

def test_stage2_weight_encryption():
    # Bad key ID
    r_bad = client.post("/api/stage2/eval", json={
        "key_id": "wrong-key",
        "encrypted_model_blob": "00" * 32,
        "memory_encryption_xts": True,
        "prevent_plain_weight_dump": True
    })
    assert r_bad.status_code == 400

    # Missing XTS memory encryption
    r_no_xts = client.post("/api/stage2/eval", json={
        "key_id": "kdf-tee-aes256-xts-v2",
        "encrypted_model_blob": "00" * 32,
        "memory_encryption_xts": False,
        "prevent_plain_weight_dump": True
    })
    assert r_no_xts.status_code == 400

    # Valid
    r_ok = client.post("/api/stage2/eval", json={
        "key_id": "kdf-tee-aes256-xts-v2",
        "encrypted_model_blob": "00" * 32,
        "memory_encryption_xts": True,
        "prevent_plain_weight_dump": True
    })
    assert r_ok.status_code == 200
    assert "FLAG{teeai_in_enclave_xts_model_weights_sealed_8067}" in r_ok.json()["flag"]

def test_stage3_cache_timing_defense():
    # Missing constant-time GEMM
    r_bad = client.post("/api/stage3/eval", json={
        "constant_time_gemm": False,
        "cache_line_flushing_mitigated": True,
        "oblivious_ram_or_shuffling": True,
        "detect_prime_probe": True
    })
    assert r_bad.status_code == 400

    # Valid
    r_ok = client.post("/api/stage3/eval", json={
        "constant_time_gemm": True,
        "cache_line_flushing_mitigated": True,
        "oblivious_ram_or_shuffling": True,
        "detect_prime_probe": True
    })
    assert r_ok.status_code == 200
    assert "FLAG{teeai_cache_timing_sidechannel_flush_reload_mitigated_8067}" in r_ok.json()["flag"]

def test_stage4_inference_signature():
    prompt_hash = hashlib.sha256(b"test prompt").hexdigest()
    output = "Model completion output"
    sig = hmac.new(SHARED_TPM_SECRET, f"{prompt_hash}:{output}".encode(), hashlib.sha256).hexdigest()

    # Bad signature
    r_bad = client.post("/api/stage4/eval", json={
        "prompt_hash": prompt_hash,
        "inference_output": output,
        "tpm_aik_signature": "bad_sig",
        "hardware_root_of_trust": True
    })
    assert r_bad.status_code == 400

    # Valid
    r_ok = client.post("/api/stage4/eval", json={
        "prompt_hash": prompt_hash,
        "inference_output": output,
        "tpm_aik_signature": sig,
        "hardware_root_of_trust": True
    })
    assert r_ok.status_code == 200
    assert "FLAG{teeai_tpm_aik_tamper_evident_inference_signed_8067}" in r_ok.json()["flag"]
