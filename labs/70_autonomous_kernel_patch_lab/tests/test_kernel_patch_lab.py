import os
import sys
import importlib.util
from pathlib import Path
import pytest
import hmac
import hashlib
from fastapi.testclient import TestClient

_app_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "app", "main.py"))
_spec = importlib.util.spec_from_file_location("lab_70_main", _app_path)
_mod = importlib.util.module_from_spec(_spec)
sys.modules["lab_70_main"] = _mod
_spec.loader.exec_module(_mod)

app = _mod.app
KERNEL_SHARED_SECRET = _mod.KERNEL_SHARED_SECRET
client = TestClient(app)

def test_health_and_root():
    r = client.get("/api/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"
    assert r.json()["lab_id"] == 70

    res = client.get("/")
    assert res.status_code == 200
    data = res.json()
    assert data["port"] == 8070
    assert data["stages"] == 4
    assert data["status"] == "ready"

def test_stage1_success():
    p = {
        "hook_type": "security_bprm_check",
        "target_syscall": "execve",
        "signature_block_enabled": True,
        "blocked_signatures": ["\\x48\\x31\\xc0\\x50\\x48\\xbb\\x2f\\x62\\x69\\x6e"]
    }
    res = client.post("/api/stage1/eval", json=p)
    assert res.status_code == 200
    assert "FLAG{v220_s1_bpf_lsm_security_bprm_check_intercepted}" in res.json()["flag"]

def test_stage1_invalid():
    p = {
        "hook_type": "security_file_open",
        "target_syscall": "openat",
        "signature_block_enabled": False,
        "blocked_signatures": []
    }
    res = client.post("/api/stage1/eval", json=p)
    assert res.status_code == 400

def test_stage2_success():
    p = {
        "map_type": "BPF_MAP_TYPE_HASH",
        "max_entries": 65536,
        "ring_buffer_telemetry": True,
        "sub_microsecond_intercept": True
    }
    res = client.post("/api/stage2/eval", json=p)
    assert res.status_code == 200
    assert "FLAG{v220_s2_ebpf_map_runtime_ringbuf_quarantined}" in res.json()["flag"]

def test_stage3_success():
    p = {
        "vulnerable_syscall": "io_uring_enter",
        "seccomp_filter_policy": "SECCOMP_RET_ERRNO",
        "dynamic_hotpatch_applied": True,
        "kernel_panic_prevention": True
    }
    res = client.post("/api/stage3/eval", json=p)
    assert res.status_code == 200
    assert "FLAG{v220_s3_seccomp_bpf_io_uring_hotpatch_neutralized}" in res.json()["flag"]

def test_stage4_success():
    patch_hash = "a" * 64
    root_hash = "b" * 64
    audit_hmac = hmac.new(
        KERNEL_SHARED_SECRET,
        f"{patch_hash}:{root_hash}".encode(),
        hashlib.sha256
    ).hexdigest()
    p = {
        "patch_sha256": patch_hash,
        "merkle_root_hash": root_hash,
        "ed25519_kernel_sig": "sig_ed25519_kernel_v220_verified_ok",
        "patch_audit_hmac": audit_hmac
    }
    res = client.post("/api/stage4/eval", json=p)
    assert res.status_code == 200
    assert "FLAG{v220_s4_kernel_patch_merkle_provenance_attested}" in res.json()["flag"]

def test_stage4_invalid_hmac():
    p = {
        "patch_sha256": "a" * 64,
        "merkle_root_hash": "b" * 64,
        "ed25519_kernel_sig": "sig_ed25519_kernel_v220_verified_ok",
        "patch_audit_hmac": "bad-hmac"
    }
    res = client.post("/api/stage4/eval", json=p)
    assert res.status_code == 403
