import os
import sys
import importlib.util
from pathlib import Path
import pytest
import hmac
import hashlib
from fastapi.testclient import TestClient

_app_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "app", "main.py"))
_spec = importlib.util.spec_from_file_location("lab_71_main", _app_path)
_mod = importlib.util.module_from_spec(_spec)
sys.modules["lab_71_main"] = _mod
_spec.loader.exec_module(_mod)

app = _mod.app
GPU_SHARED_SECRET = _mod.GPU_SHARED_SECRET
client = TestClient(app)

def test_health_and_root():
    res = client.get("/api/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "ok"
    assert data["lab_id"] == 71
    assert data["stages"] == 4

    res = client.get("/")
    assert res.status_code == 200
    data = res.json()
    assert data["port"] == 8071
    assert data["status"] == "ready"

def test_stage1_success():
    payload = {
        "zeroization_policy": "cuda_mem_zero_on_free",
        "vram_scrub_enabled": True,
        "leak_detection_active": True,
        "scrub_patterns": ["0x00_fill_pattern"]
    }
    res = client.post("/api/stage1/eval", json=payload)
    assert res.status_code == 200
    assert "FLAG{v221_s1_vram_context_zeroization_scrubbed}" in res.json()["flag"]

def test_stage1_failure():
    payload = {
        "zeroization_policy": "none",
        "vram_scrub_enabled": False,
        "leak_detection_active": False,
        "scrub_patterns": []
    }
    res = client.post("/api/stage1/eval", json=payload)
    assert res.status_code == 400

def test_stage2_success():
    payload = {
        "defense_mode": "constant_time_padding",
        "noise_injection_level": 4,
        "pcie_telemetry_obfuscated": True,
        "sub_millisecond_jitter": True
    }
    res = client.post("/api/stage2/eval", json=payload)
    assert res.status_code == 200
    assert "FLAG{v221_s2_pcie_sidechannel_noise_injected}" in res.json()["flag"]

def test_stage3_success():
    payload = {
        "mig_instance_id": "mig_profile_3g_40gb",
        "cross_partition_dma_blocked": True,
        "shared_l2_cache_quarantine": True,
        "hardware_isolation_enforced": True
    }
    res = client.post("/api/stage3/eval", json=payload)
    assert res.status_code == 200
    assert "FLAG{v221_s3_mig_hardware_partition_isolated}" in res.json()["flag"]

def test_stage4_success():
    firmware_sha256 = hashlib.sha256(b"vibe-gpu-firmware-v221-signed-blob").hexdigest()
    merkle_root = hashlib.sha256(b"vibe-gpu-merkle-root-v221").hexdigest()
    audit_hmac = hmac.new(
        GPU_SHARED_SECRET,
        f"{firmware_sha256}:{merkle_root}".encode(),
        hashlib.sha256
    ).hexdigest()
    payload = {
        "firmware_sha256": firmware_sha256,
        "merkle_root_hash": merkle_root,
        "attestation_sig": "sig_gpu_firmware_v221_verified_ok",
        "firmware_audit_hmac": audit_hmac
    }
    res = client.post("/api/stage4/eval", json=payload)
    assert res.status_code == 200
    assert "FLAG{v221_s4_gpu_firmware_merkle_attested}" in res.json()["flag"]

def test_stage4_invalid_hmac():
    payload = {
        "firmware_sha256": "a" * 64,
        "merkle_root_hash": "b" * 64,
        "attestation_sig": "sig_gpu_firmware_v221_verified_ok",
        "firmware_audit_hmac": "invalid_hmac_hash"
    }
    res = client.post("/api/stage4/eval", json=payload)
    assert res.status_code == 403
