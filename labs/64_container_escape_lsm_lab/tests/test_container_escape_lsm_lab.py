import os
import sys
import importlib.util
import pytest
from fastapi.testclient import TestClient

_app_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "app", "main.py"))
_spec = importlib.util.spec_from_file_location("lab_64_main", _app_path)
_mod = importlib.util.module_from_spec(_spec)
sys.modules["lab_64_main"] = _mod
_spec.loader.exec_module(_mod)

app = _mod.app
client = TestClient(app)


def test_index_and_health():
    res = client.get("/")
    assert res.status_code == 200
    assert "Lab 64" in res.text

    h_res = client.get("/health")
    assert h_res.status_code == 200
    data = h_res.json()
    assert data["lab_id"] == 64
    assert data["port"] == 8064

    s_res = client.get("/api/status")
    assert s_res.status_code == 200
    s_data = s_res.json()
    assert len(s_data["stages"]) == 4


def test_stage1_userns_vulnerable():
    payload = {
        "clone_flags": ["CLONE_NEWUSER", "CLONE_NEWNS"],
        "target_caps": ["CAP_SYS_ADMIN", "CAP_NET_ADMIN"],
        "uid_mapping": "0 1000 1",
        "use_lsm_guard": False
    }
    res = client.post("/api/stage1/eval", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["success"] is False
    assert data["status"] == "VULNERABLE"
    assert "FLAG{lsm_userns_capability_sandbox_enforced}" in data["flag"]


def test_stage1_userns_lsm_defense():
    payload = {
        "clone_flags": ["CLONE_NEWUSER", "CLONE_NEWNS"],
        "target_caps": ["CAP_SYS_ADMIN"],
        "uid_mapping": "0 1000 1",
        "use_lsm_guard": True
    }
    res = client.post("/api/stage1/eval", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["success"] is True
    assert data["status"] == "LSM_USERNS_BLOCKED"
    assert data["flag"] == "FLAG{lsm_userns_capability_sandbox_enforced}"
    assert data["blocked_by"] == "bpf_lsm_userns_create"


def test_stage2_cgroup_procfs_vulnerable():
    payload = {
        "target_path": "/sys/fs/cgroup/release_agent",
        "payload": "#!/bin/sh\ncat /etc/shadow\n",
        "mount_flags": ["rw"],
        "use_lsm_guard": False
    }
    res = client.post("/api/stage2/eval", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["success"] is False
    assert data["status"] == "VULNERABLE"
    assert "FLAG{lsm_cgroup_procfs_w_xor_x_shielded}" in data["flag"]


def test_stage2_cgroup_procfs_lsm_defense():
    payload = {
        "target_path": "/proc/sys/kernel/core_pattern",
        "payload": "|/tmp/exploit.sh",
        "mount_flags": ["rw"],
        "use_lsm_guard": True
    }
    res = client.post("/api/stage2/eval", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["success"] is True
    assert data["status"] == "LSM_W_XOR_X_ENFORCED"
    assert data["flag"] == "FLAG{lsm_cgroup_procfs_w_xor_x_shielded}"
    assert data["blocked_by"] == "bpf_lsm_file_open"


def test_stage3_runc_leaked_fd_vulnerable():
    payload = {
        "fd_descriptor": "/proc/self/fd/7",
        "relative_traversal": "../../../etc/shadow",
        "target_action": "read",
        "use_lsm_guard": False
    }
    res = client.post("/api/stage3/eval", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["success"] is False
    assert data["status"] == "VULNERABLE"
    assert "FLAG{lsm_fd_leaks_resolve_beneath_quarantined}" in data["flag"]


def test_stage3_runc_leaked_fd_lsm_defense():
    payload = {
        "fd_descriptor": "/proc/self/fd/8",
        "relative_traversal": "../../../../etc/cron.d/backdoor",
        "target_action": "write",
        "use_lsm_guard": True
    }
    res = client.post("/api/stage3/eval", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["success"] is True
    assert data["status"] == "LSM_RESOLVE_BENEATH_TRAP"
    assert data["flag"] == "FLAG{lsm_fd_leaks_resolve_beneath_quarantined}"
    assert data["blocked_by"] == "bpf_lsm_path_link"


def test_stage4_runtime_zero_trust_vulnerable():
    payload = {
        "process_tree": [{"pid": 42, "comm": "exploit"}],
        "syscall_sequence": ["unshare", "setns"],
        "target_ns_breakout": "init_pid_ns",
        "use_lsm_runtime_shield": False
    }
    res = client.post("/api/stage4/eval", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["success"] is False
    assert data["status"] == "VULNERABLE"
    assert "FLAG{lsm_runtime_sigkill_containment_sealed}" in data["flag"]


def test_stage4_runtime_zero_trust_defense():
    payload = {
        "process_tree": [{"pid": 42, "comm": "exploit"}],
        "syscall_sequence": ["unshare", "pivot_root", "setns"],
        "target_ns_breakout": "init_pid_ns",
        "use_lsm_runtime_shield": True
    }
    res = client.post("/api/stage4/eval", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["success"] is True
    assert data["status"] == "LSM_SIGKILL_CONTAINMENT_ENFORCED"
    assert data["flag"] == "FLAG{lsm_runtime_sigkill_containment_sealed}"
    assert data["kernel_telemetry"]["cgroup_state"] == "FROZEN"
    assert data["kernel_telemetry"]["action"] == "bpf_send_signal(SIGKILL)"
