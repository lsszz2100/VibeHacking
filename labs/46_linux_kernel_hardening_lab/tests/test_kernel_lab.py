#!/usr/bin/env python3
"""
Unit and regression tests for Lab 46: KernelGuard (Linux Kernel Hardening Lab)
"""

import sys
import importlib.util
from pathlib import Path
import pytest
from starlette.testclient import TestClient

APP_PATH = Path(__file__).resolve().parent.parent / "app" / "main.py"
spec = importlib.util.spec_from_file_location("lab46_app", str(APP_PATH))
lab46_module = importlib.util.module_from_spec(spec)
sys.modules["lab46_app"] = lab46_module
spec.loader.exec_module(lab46_module)

app = lab46_module.app
state = lab46_module.state
STAGE1_FLAG = lab46_module.STAGE1_FLAG
STAGE2_FLAG = lab46_module.STAGE2_FLAG
STAGE3_FLAG = lab46_module.STAGE3_FLAG
STAGE4_FLAG = lab46_module.STAGE4_FLAG
AUTHENTIC_WORKER_HASH = lab46_module.AUTHENTIC_WORKER_HASH
TAMPERED_WORKER_HASH = lab46_module.TAMPERED_WORKER_HASH

client = TestClient(app)

@pytest.fixture(autouse=True)
def reset_state():
    state.reset()
    yield
    state.reset()

def test_health_check():
    res = client.get("/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "ok"
    assert data["port"] == 8046

def test_initial_status():
    res = client.get("/api/status")
    assert res.status_code == 200
    data = res.json()
    assert not data["stage1"]["completed"]
    assert not data["stage2"]["completed"]
    assert not data["stage3"]["completed"]
    assert not data["stage4"]["completed"]

def test_html_index():
    res = client.get("/")
    assert res.status_code == 200
    assert "Lab 46: KernelGuard" in res.text

# ---------------------------------------------------------------------------
# Stage 1: Seccomp-BPF Tests
# ---------------------------------------------------------------------------

def test_stage1_telemetry():
    res = client.get("/api/stage1/telemetry")
    assert res.status_code == 200
    data = res.json()
    assert data["host_architecture"] == "AUDIT_ARCH_X86_64"
    assert any(s["syscall"] == "ptrace" for s in data["recent_syscall_attempts"])
    assert any(s["syscall"] == "process_vm_writev" for s in data["recent_syscall_attempts"])

def test_stage1_arch_mismatch_failure():
    payload = {
        "arch": "AUDIT_ARCH_I386",
        "blocked_syscalls": ["ptrace", "process_vm_writev"],
        "action_on_blocked": "SECCOMP_RET_KILL_PROCESS",
        "default_action": "SECCOMP_RET_ALLOW",
    }
    res = client.post("/api/stage1/apply_seccomp", json=payload)
    assert res.status_code == 400
    assert "Architecture validation failed" in res.json()["detail"]

def test_stage1_missing_critical_syscall_failure():
    payload = {
        "arch": "AUDIT_ARCH_X86_64",
        "blocked_syscalls": ["openat", "unlink"],
        "action_on_blocked": "SECCOMP_RET_KILL_PROCESS",
        "default_action": "SECCOMP_RET_ALLOW",
    }
    res = client.post("/api/stage1/apply_seccomp", json=payload)
    assert res.status_code == 400
    assert "Critical dangerous syscalls not blocked" in res.json()["detail"]

def test_stage1_invalid_action_failure():
    payload = {
        "arch": "AUDIT_ARCH_X86_64",
        "blocked_syscalls": ["ptrace", "process_vm_writev"],
        "action_on_blocked": "SECCOMP_RET_ALLOW",
        "default_action": "SECCOMP_RET_ALLOW",
    }
    res = client.post("/api/stage1/apply_seccomp", json=payload)
    assert res.status_code == 400
    assert "Action on blocked syscalls must be terminating" in res.json()["detail"]

def test_stage1_success():
    payload = {
        "arch": "AUDIT_ARCH_X86_64",
        "blocked_syscalls": ["ptrace", "process_vm_writev", "kexec_load"],
        "action_on_blocked": "SECCOMP_RET_KILL_PROCESS",
        "default_action": "SECCOMP_RET_ALLOW",
    }
    res = client.post("/api/stage1/apply_seccomp", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "success"
    assert data["flag"] == STAGE1_FLAG
    assert state.stage1_completed is True

# ---------------------------------------------------------------------------
# Stage 2: Landlock LSM Tests
# ---------------------------------------------------------------------------

def test_stage2_profile():
    res = client.get("/api/stage2/profile")
    assert res.status_code == 200
    data = res.json()
    assert data["process_name"] == "worker_daemon"
    assert data["current_confinement"] == "unconfined"
    assert any(a["path"] == "/etc/shadow" for a in data["attempted_accesses"])

def test_stage2_missing_no_new_privs_failure():
    payload = {
        "target_path": "/srv/app/data",
        "allowed_actions": ["READ_FILE", "WRITE_FILE"],
        "lock_no_new_privs": False,
    }
    res = client.post("/api/stage2/restrict_landlock", json=payload)
    assert res.status_code == 400
    assert "requires prctl(PR_SET_NO_NEW_PRIVS, 1)" in res.json()["detail"]

def test_stage2_overly_permissive_path_failure():
    payload = {
        "target_path": "/etc",
        "allowed_actions": ["READ_FILE"],
        "lock_no_new_privs": True,
    }
    res = client.post("/api/stage2/restrict_landlock", json=payload)
    assert res.status_code == 400
    assert "overly permissive" in res.json()["detail"]

def test_stage2_missing_read_action_failure():
    payload = {
        "target_path": "/srv/app/data",
        "allowed_actions": ["EXECUTE"],
        "lock_no_new_privs": True,
    }
    res = client.post("/api/stage2/restrict_landlock", json=payload)
    assert res.status_code == 400
    assert "grant at least read rights" in res.json()["detail"]

def test_stage2_success():
    payload = {
        "target_path": "/srv/app/data",
        "allowed_actions": ["READ_FILE", "WRITE_FILE"],
        "lock_no_new_privs": True,
    }
    res = client.post("/api/stage2/restrict_landlock", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "success"
    assert data["flag"] == STAGE2_FLAG
    assert state.stage2_completed is True
    assert state.landlock_locked is True

# ---------------------------------------------------------------------------
# Stage 3: IMA & EVM Tests
# ---------------------------------------------------------------------------

def test_stage3_ima_log():
    res = client.get("/api/stage3/ima_log")
    assert res.status_code == 200
    data = res.json()
    assert data["is_tampered"] is True
    assert data["entries"][0]["measured_hash"] == TAMPERED_WORKER_HASH

def test_stage3_invalid_target_failure():
    payload = {
        "target_binary": "/usr/bin/python3",
        "remedy_action": "restore_authentic",
        "enforce_signature_check": True,
    }
    res = client.post("/api/stage3/appraise", json=payload)
    assert res.status_code == 400
    assert "Target binary must specify" in res.json()["detail"]

def test_stage3_invalid_remedy_failure():
    payload = {
        "target_binary": "/usr/bin/daemon_worker",
        "remedy_action": "ignore",
        "enforce_signature_check": True,
    }
    res = client.post("/api/stage3/appraise", json=payload)
    assert res.status_code == 400
    assert "remedy_action='restore_authentic'" in res.json()["detail"]

def test_stage3_missing_signature_enforcement_failure():
    payload = {
        "target_binary": "/usr/bin/daemon_worker",
        "remedy_action": "restore_authentic",
        "enforce_signature_check": False,
    }
    res = client.post("/api/stage3/appraise", json=payload)
    assert res.status_code == 400
    assert "must enforce cryptographic xattr signature" in res.json()["detail"]

def test_stage3_success():
    payload = {
        "target_binary": "/usr/bin/daemon_worker",
        "remedy_action": "restore_authentic",
        "enforce_signature_check": True,
    }
    res = client.post("/api/stage3/appraise", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "success"
    assert data["flag"] == STAGE3_FLAG
    assert data["hash"] == AUTHENTIC_WORKER_HASH
    assert state.stage3_completed is True

# ---------------------------------------------------------------------------
# Stage 4: KSPP Mitigations Tests
# ---------------------------------------------------------------------------

def test_stage4_posture():
    res = client.get("/api/stage4/kernel_posture")
    assert res.status_code == 200
    data = res.json()
    assert "kCFI disabled" in data["vulnerabilities_detected"][2]

def test_stage4_incomplete_hardening_failure():
    payload = {
        "init_on_alloc": True,
        "slab_nomerge": True,
        "kcfi_enforce": False,
        "kpti": True,
    }
    res = client.post("/api/stage4/harden", json=payload)
    assert res.status_code == 400
    assert "Incomplete KSPP hardening" in res.json()["detail"]

def test_stage4_success():
    payload = {
        "init_on_alloc": True,
        "slab_nomerge": True,
        "kcfi_enforce": True,
        "kpti": True,
    }
    res = client.post("/api/stage4/harden", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "success"
    assert data["flag"] == STAGE4_FLAG
    assert state.stage4_completed is True

# ---------------------------------------------------------------------------
# Regression & Bounds Security Tests
# ---------------------------------------------------------------------------

def test_pydantic_max_length_overflow():
    payload = {
        "arch": "A" * 200,
        "blocked_syscalls": ["ptrace"],
    }
    res = client.post("/api/stage1/apply_seccomp", json=payload)
    assert res.status_code == 422
