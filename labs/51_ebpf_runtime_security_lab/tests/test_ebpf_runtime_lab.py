#!/usr/bin/env python3
"""Tests for Lab 51: eBPFRuntimeGuard — Cloud Native eBPF Kernel Observability & Runtime Security Lab."""

import sys
import importlib.util
from pathlib import Path
import pytest
from starlette.testclient import TestClient

APP_PATH = Path(__file__).resolve().parent.parent / "app" / "main.py"
spec = importlib.util.spec_from_file_location("lab51_app", str(APP_PATH))
lab51_module = importlib.util.module_from_spec(spec)
sys.modules["lab51_app"] = lab51_module
spec.loader.exec_module(lab51_module)

app = lab51_module.app
state = lab51_module.state
STAGE1_FLAG = lab51_module.STAGE1_FLAG
STAGE2_FLAG = lab51_module.STAGE2_FLAG
STAGE3_FLAG = lab51_module.STAGE3_FLAG
STAGE4_FLAG = lab51_module.STAGE4_FLAG

client = TestClient(app)


@pytest.fixture(autouse=True)
def reset_lab():
    client.post("/api/reset")
    yield
    client.post("/api/reset")


def test_index_and_status():
    res = client.get("/")
    assert res.status_code == 200
    assert "Lab 51" in res.text

    status_res = client.get("/status")
    assert status_res.status_code == 200
    data = status_res.json()
    assert data["lab"] == "51_ebpf_runtime_security_lab"
    assert data["port"] == 8051
    assert data["stages"]["stage1_syscall_tracing"] is False


def test_stage1_syscall_tracing():
    # Invalid probe type
    res_bad = client.post("/api/stage1/trace_syscall", json={
        "probe_type": "invalid_probe",
        "target_syscall": "sys_enter_execve",
        "filter_expression": "comm == 'sh'"
    })
    assert res_bad.status_code == 400

    # Inconclusive syscall
    res_inc1 = client.post("/api/stage1/trace_syscall", json={
        "probe_type": "kprobe",
        "target_syscall": "sys_enter_openat",
        "filter_expression": "comm == 'sh'"
    })
    assert res_inc1.status_code == 200
    assert res_inc1.json()["status"] == "inconclusive"

    # Inconclusive filter
    res_inc2 = client.post("/api/stage1/trace_syscall", json={
        "probe_type": "kprobe",
        "target_syscall": "sys_enter_execve",
        "filter_expression": "comm == 'nginx'"
    })
    assert res_inc2.status_code == 200
    assert res_inc2.json()["status"] == "inconclusive"

    # Successful trace
    res_ok = client.post("/api/stage1/trace_syscall", json={
        "probe_type": "kprobe",
        "target_syscall": "sys_enter_execve",
        "filter_expression": "comm == 'sh' || filename == '/bin/sh'"
    })
    assert res_ok.status_code == 200
    data = res_ok.json()
    assert data["status"] == "success"
    assert STAGE1_FLAG in data["flag"]
    assert state.stage1_completed is True


def test_stage2_lsm_namespace_escape():
    # Invalid hook
    res_bad_hook = client.post("/api/stage2/enforce_lsm_hook", json={
        "lsm_hook": "invalid_hook",
        "target_path": "/etc/shadow",
        "action": "BLOCK_EPERM"
    })
    assert res_bad_hook.status_code == 400

    # Non-sensitive path
    res_bad_path = client.post("/api/stage2/enforce_lsm_hook", json={
        "lsm_hook": "bpf_lsm_file_open",
        "target_path": "/tmp/test.txt",
        "action": "BLOCK_EPERM"
    })
    assert res_bad_path.status_code == 400

    # Audited only
    res_audit = client.post("/api/stage2/enforce_lsm_hook", json={
        "lsm_hook": "bpf_lsm_file_open",
        "target_path": "/etc/shadow",
        "action": "AUDIT_LOG"
    })
    assert res_audit.status_code == 200
    assert res_audit.json()["status"] == "audited_only"

    # Success
    res_ok = client.post("/api/stage2/enforce_lsm_hook", json={
        "lsm_hook": "bpf_lsm_file_open",
        "target_path": "/etc/shadow",
        "action": "BLOCK_EPERM"
    })
    assert res_ok.status_code == 200
    data = res_ok.json()
    assert data["status"] == "success"
    assert STAGE2_FLAG in data["flag"]
    assert state.stage2_completed is True


def test_stage3_tetragon_tracing_policy():
    # Invalid policy name
    res_bad_name = client.post("/api/stage3/apply_tracing_policy", json={
        "policy_name": "x",
        "kprobe_symbol": "commit_creds",
        "enforcement_action": "Sigkill",
        "namespace_selector": "default"
    })
    assert res_bad_name.status_code == 400

    # Invalid symbol
    res_bad_sym = client.post("/api/stage3/apply_tracing_policy", json={
        "policy_name": "block-priv-esc",
        "kprobe_symbol": "unknown_symbol",
        "enforcement_action": "Sigkill",
        "namespace_selector": "default"
    })
    assert res_bad_sym.status_code == 400

    # Invalid action
    res_bad_act = client.post("/api/stage3/apply_tracing_policy", json={
        "policy_name": "block-priv-esc",
        "kprobe_symbol": "commit_creds",
        "enforcement_action": "Signal",
        "namespace_selector": "default"
    })
    assert res_bad_act.status_code == 400

    # Success
    res_ok = client.post("/api/stage3/apply_tracing_policy", json={
        "policy_name": "block-priv-esc",
        "kprobe_symbol": "commit_creds",
        "enforcement_action": "Sigkill",
        "namespace_selector": "default"
    })
    assert res_ok.status_code == 200
    data = res_ok.json()
    assert data["status"] == "success"
    assert STAGE3_FLAG in data["flag"]
    assert state.stage3_completed is True


def test_stage4_bpf_rootkit_audit():
    # Invalid audit command
    res_bad_cmd = client.post("/api/stage4/audit_bpf_rootkit", json={
        "audit_command": "invalid_cmd",
        "target_hooked_syscall": "sys_enter_getdents64",
        "remediation_action": "DETACH_PROG_UNPIN_MAP"
    })
    assert res_bad_cmd.status_code == 400

    # Wrong hooked syscall
    res_bad_sys = client.post("/api/stage4/audit_bpf_rootkit", json={
        "audit_command": "bpftool prog dump",
        "target_hooked_syscall": "sys_enter_read",
        "remediation_action": "DETACH_PROG_UNPIN_MAP"
    })
    assert res_bad_sys.status_code == 400

    # Wrong remediation
    res_bad_rem = client.post("/api/stage4/audit_bpf_rootkit", json={
        "audit_command": "bpftool prog dump",
        "target_hooked_syscall": "sys_enter_getdents64",
        "remediation_action": "RELOAD_KERNEL"
    })
    assert res_bad_rem.status_code == 400

    # Success
    res_ok = client.post("/api/stage4/audit_bpf_rootkit", json={
        "audit_command": "bpftool prog dump",
        "target_hooked_syscall": "sys_enter_getdents64",
        "remediation_action": "DETACH_PROG_UNPIN_MAP"
    })
    assert res_ok.status_code == 200
    data = res_ok.json()
    assert data["status"] == "success"
    assert STAGE4_FLAG in data["flag"]
    assert state.stage4_completed is True
    assert state.rootkit_neutralized is True
