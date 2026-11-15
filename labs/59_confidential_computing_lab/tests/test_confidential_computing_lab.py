"""
Unit tests for Lab 59: Confidential Computing & TEE Defense Lab
Tests hardware memory encryption, remote attestation, RMP table and VMSA protection.
"""

import sys
from pathlib import Path
import importlib.util
from fastapi.testclient import TestClient
import pytest

LAB_DIR = Path(__file__).resolve().parent.parent
MAIN_FILE = LAB_DIR / "app" / "main.py"

spec = importlib.util.spec_from_file_location("lab59_main", str(MAIN_FILE))
lab59_module = importlib.util.module_from_spec(spec)
sys.modules["lab59_main"] = lab59_module
spec.loader.exec_module(lab59_module)

app = lab59_module.app
client = TestClient(app)

def test_lab59_dashboard_html():
    res = client.get("/")
    assert res.status_code == 200
    assert "CONFIDENTIAL COMPUTING" in res.text
    assert "SEV-SNP" in res.text

def test_lab59_status_initial():
    res = client.get("/api/status")
    assert res.status_code == 200
    data = res.json()
    assert data["lab_id"] == "59"
    assert "stages" in data

def test_lab59_stage1_memory_probe():
    payload = {
        "physical_address": "0x1000a000",
        "probe_context": "host_root"
    }
    res = client.post("/api/stage1/memory-probe", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["success"] is True
    assert data["plaintext_leak"] is False
    assert "FLAG{sev_snp_hardware_aes_xts_memory_encryption_active}" in data["flag"]

def test_lab59_stage2_remote_attestation_success():
    payload = {
        "measurement_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "report_data_nonce": "test_nonce_7777",
        "chip_id": "AMD-EPYC-SEV-SNP-GEN3"
    }
    res = client.post("/api/stage2/remote-attestation", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["success"] is True
    assert data["attestation_verdict"] == "VERIFIED_GENUINE"
    assert "FLAG{tee_attestation_report_mrenclave_signature_verified}" in data["flag"]

def test_lab59_stage2_remote_attestation_failure():
    payload = {
        "measurement_hash": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "report_data_nonce": "tampered_nonce",
        "chip_id": "AMD-EPYC-SEV-SNP-GEN3"
    }
    res = client.post("/api/stage2/remote-attestation", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["success"] is False
    assert data["attestation_verdict"] == "COUNTERFEIT_IMAGE_REJECTED"

def test_lab59_stage3_rmp_remapping():
    payload = {
        "guest_physical_page": "0x204000",
        "malicious_hpa": "0x884000",
        "operation": "verify_entry"
    }
    res = client.post("/api/stage3/rmp-remapping", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["success"] is True
    assert data["rmp_table_status"] == "ENFORCED"
    assert "FLAG{rmp_table_enforces_page_ownership_and_prevents_remapping}" in data["flag"]

def test_lab59_stage4_vmsa_state_encrypt():
    payload = {
        "action": "encrypt_vmsa",
        "inject_side_channel": False
    }
    res = client.post("/api/stage4/vmsa-state-encrypt", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["success"] is True
    assert data["side_channel_probe_blocked"] is True
    assert "FLAG{vmsa_register_encryption_and_cache_flush_safeguard}" in data["flag"]
