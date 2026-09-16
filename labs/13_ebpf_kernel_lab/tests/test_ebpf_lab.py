#!/usr/bin/env python3
"""Comprehensive Unit and Integration Tests for Lab 13 (BPFGuard eBPF Kernel Lab)."""

import importlib.util
import os
import sys
import pytest
from fastapi.testclient import TestClient

_main_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "app", "main.py"))
_spec = importlib.util.spec_from_file_location("ebpf_lab_main", _main_path)
_mod = importlib.util.module_from_spec(_spec)
sys.modules["ebpf_lab_main"] = _mod
_spec.loader.exec_module(_mod)

app = _mod.app
FLAGS = _mod.FLAGS
STATE = _mod.STATE

client = TestClient(app)


@pytest.fixture(autouse=True)
def reset_lab_state():
    """Reset the in-memory state before each test."""
    client.post("/api/reset")


def test_status_endpoint():
    """Verify lab status, port configuration, and metadata."""
    res = client.get("/api/ebpf/status")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "running"
    assert data["service"] == "BPFGuard"
    assert data["port"] == 8013
    assert data["total_stages"] == 4
    assert data["solved_count"] == 0


def test_dashboard_served():
    """Verify that root endpoint serves the HTML dashboard."""
    res = client.get("/")
    assert res.status_code == 200
    assert "BPFGuard" in res.text
    assert "text/html" in res.headers.get("content-type", "")


def test_stage1_kprobe_sniffing():
    """Test Stage 1: Attaching kprobe to sys_enter_execve sniffs credentials."""
    payload = {
        "symbol": "sys_enter_execve",
        "target_syscall": "sys_enter_execve",
        "run_as_user": "attacker",
    }
    res = client.post("/api/ebpf/kprobe/attach", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["success"] is True
    assert data["flag"] == FLAGS["stage1"]
    assert "OCTO_SUPER_SECRET_KERN_TOKEN" in str(data["sniffed_data"])

    # Verify state reflects completion
    st = client.get("/api/ebpf/status").json()
    assert st["stages_solved"]["stage1"] is True


def test_stage1_unprivileged_blocked_when_policy_enabled():
    """Verify unprivileged BPF disable policy prevents non-root probe attach."""
    client.post("/api/ebpf/policies", json={"unprivileged_bpf_disabled": True})
    payload = {
        "symbol": "sys_enter_execve",
        "run_as_user": "attacker",
    }
    res = client.post("/api/ebpf/kprobe/attach", json=payload)
    assert res.status_code == 403
    assert "kernel.unprivileged_bpf_disabled" in res.json()["detail"]


def test_stage2_memory_mutation_sudo_escalation():
    """Test Stage 2: bpf_probe_write_user mutates sudoers buffer for escalation."""
    payload = {
        "target_process": "sudo",
        "target_file": "/etc/sudoers",
        "helper": "bpf_probe_write_user",
        "replacement_content": "lowpriv ALL=(ALL) NOPASSWD: ALL",
    }
    res = client.post("/api/ebpf/mutate", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["success"] is True
    assert data["flag"] == FLAGS["stage2"]

    # Test sudo whoami output
    sh_res = client.post("/api/terminal/exec", json={"command": "sudo whoami"}).json()
    assert sh_res["output"] == "root"


def test_stage3_xdp_covert_tunnel():
    """Test Stage 3: XDP driver hook loads stealth ICMP covert channel."""
    payload = {
        "interface": "eth0",
        "action": "covert_tunnel",
        "covert_payload": "icmp_magic_payload",
    }
    res = client.post("/api/ebpf/xdp/load", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["success"] is True
    assert data["flag"] == FLAGS["stage3"]
    assert "covert_packet_sample" in data


def test_stage4_hardening_verification():
    """Test Stage 4: Verify full defensive posture enforcement."""
    # Incomplete policies should fail Stage 4
    res_fail = client.post("/api/ebpf/verify")
    assert res_fail.status_code == 200
    data_fail = res_fail.json()
    assert data_fail["success"] is False
    assert len(data_fail["missing_controls"]) > 0

    # Enable all 4 defense controls
    client.post("/api/ebpf/policies", json={
        "unprivileged_bpf_disabled": True,
        "bpf_jit_harden": True,
        "bpf_lsm_enforced": True,
        "runtime_audit_enabled": True,
    })

    res_pass = client.post("/api/ebpf/verify")
    assert res_pass.status_code == 200
    data_pass = res_pass.json()
    assert data_pass["success"] is True
    assert data_pass["flag"] == FLAGS["stage4"]


def test_terminal_bpftool_and_sysctl():
    """Test terminal command executions for bpftool and sysctl."""
    res_bpf = client.post("/api/terminal/exec", json={"command": "bpftool prog list"}).json()
    assert "cg_skb_egress" in res_bpf["output"]

    res_sys = client.post("/api/terminal/exec", json={"command": "sysctl kernel.unprivileged_bpf_disabled"}).json()
    assert "kernel.unprivileged_bpf_disabled = 0" in res_sys["output"]
