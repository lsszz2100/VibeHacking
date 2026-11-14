"""Unit & Integration Tests for Lab 56: eBPFShield."""

import sys
import importlib.util
from pathlib import Path
import pytest
from starlette.testclient import TestClient

APP_PATH = Path(__file__).resolve().parent.parent / "app" / "main.py"
spec = importlib.util.spec_from_file_location("lab56_app", str(APP_PATH))
lab56_module = importlib.util.module_from_spec(spec)
sys.modules["lab56_app"] = lab56_module
spec.loader.exec_module(lab56_module)

app = lab56_module.app
state = lab56_module.state
STAGE1_FLAG = lab56_module.STAGE1_FLAG
STAGE2_FLAG = lab56_module.STAGE2_FLAG
STAGE3_FLAG = lab56_module.STAGE3_FLAG
STAGE4_FLAG = lab56_module.STAGE4_FLAG

client = TestClient(app)


@pytest.fixture(autouse=True)
def reset_state():
    client.post("/api/reset")
    yield
    client.post("/api/reset")


def test_status_endpoint():
    res = client.get("/api/status")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "running"
    assert data["lab_id"] == "56"
    assert data["solved_count"] == 0
    assert data["stages"]["stage1_completed"] is False


def test_health_endpoint():
    res = client.get("/api/health")
    assert res.status_code == 200
    assert res.json()["status"] == "ok"
    assert res.json()["port"] == "8056"


def test_index_page():
    res = client.get("/")
    assert res.status_code == 200
    assert "eBPFShield" in res.text
    assert "Port 8056" in res.text


def test_stage1_syscall_telemetry():
    # Invalid target
    res_bad = client.post("/api/stage1/attach_telemetry", json={
        "hook_target": "invalid/hook/target",
        "filter_expression": "pid != 0",
        "ring_buffer_size_kb": 64,
    })
    assert res_bad.status_code == 400

    # Insufficient buffer size
    res_low = client.post("/api/stage1/attach_telemetry", json={
        "hook_target": "tracepoint/syscalls/sys_enter_execve",
        "filter_expression": "pid != 0",
        "ring_buffer_size_kb": 16,
    })
    assert res_low.status_code in (400, 422)

    # Successful telemetry hook
    res_ok = client.post("/api/stage1/attach_telemetry", json={
        "hook_target": "tracepoint/syscalls/sys_enter_execve",
        "filter_expression": "pid != 0 && comm == 'kworker/0:1'",
        "ring_buffer_size_kb": 64,
    })
    assert res_ok.status_code == 200
    data = res_ok.json()
    assert data["success"] is True
    assert data["stage"] == 1
    assert data["flag"] == STAGE1_FLAG
    assert data["ring_buffer_event"]["pid"] == 1337


def test_stage2_process_hollowing_detection():
    # Attempt stage 2 before stage 1
    res_premature = client.post("/api/stage2/detect_process_hollowing", json={
        "target_pid": 1337,
        "cross_check_inode": True,
        "scan_vad_permissions": True,
    })
    assert res_premature.status_code == 403

    # Complete Stage 1 first
    client.post("/api/stage1/attach_telemetry", json={
        "hook_target": "tracepoint/syscalls/sys_enter_execve",
        "filter_expression": "pid != 0",
        "ring_buffer_size_kb": 64,
    })

    # Benign target PID
    res_benign = client.post("/api/stage2/detect_process_hollowing", json={
        "target_pid": 1,
        "cross_check_inode": True,
        "scan_vad_permissions": True,
    })
    assert res_benign.status_code == 200
    assert res_benign.json()["success"] is False

    # Incomplete audit flags
    res_missing_flags = client.post("/api/stage2/detect_process_hollowing", json={
        "target_pid": 1337,
        "cross_check_inode": False,
        "scan_vad_permissions": True,
    })
    assert res_missing_flags.status_code == 200
    assert res_missing_flags.json()["success"] is False

    # Successful process hollowing detection
    res_ok = client.post("/api/stage2/detect_process_hollowing", json={
        "target_pid": 1337,
        "cross_check_inode": True,
        "scan_vad_permissions": True,
    })
    assert res_ok.status_code == 200
    data = res_ok.json()
    assert data["success"] is True
    assert data["stage"] == 2
    assert data["flag"] == STAGE2_FLAG
    assert data["audit_evidence"]["reported_comm"] == "kworker/0:1"


def test_stage3_ebpf_rootkit_audit():
    # Attempt before stage 2
    res_premature = client.post("/api/stage3/audit_ebpf_rootkit", json={
        "scan_bpf_progs": True,
        "rogue_prog_id": 404,
        "action": "detach_and_purge",
    })
    assert res_premature.status_code == 403

    # Complete Stage 1 and Stage 2
    client.post("/api/stage1/attach_telemetry", json={
        "hook_target": "tracepoint/syscalls/sys_enter_execve",
        "filter_expression": "pid != 0",
        "ring_buffer_size_kb": 64,
    })
    client.post("/api/stage2/detect_process_hollowing", json={
        "target_pid": 1337,
        "cross_check_inode": True,
        "scan_vad_permissions": True,
    })

    # Inspection action
    res_inspect = client.post("/api/stage3/audit_ebpf_rootkit", json={
        "scan_bpf_progs": True,
        "rogue_prog_id": 404,
        "action": "inspect",
    })
    assert res_inspect.status_code == 200
    assert res_inspect.json()["success"] is True
    assert "prog_inventory" in res_inspect.json()

    # Wrong rogue ID
    res_wrong_id = client.post("/api/stage3/audit_ebpf_rootkit", json={
        "scan_bpf_progs": True,
        "rogue_prog_id": 999,
        "action": "detach_and_purge",
    })
    assert res_wrong_id.status_code == 400

    # Successful rootkit detachment
    res_ok = client.post("/api/stage3/audit_ebpf_rootkit", json={
        "scan_bpf_progs": True,
        "rogue_prog_id": 404,
        "action": "detach_and_purge",
    })
    assert res_ok.status_code == 200
    data = res_ok.json()
    assert data["success"] is True
    assert data["stage"] == 3
    assert data["flag"] == STAGE3_FLAG


def test_stage4_ebpf_lsm_policy():
    # Attempt before stage 3
    res_premature = client.post("/api/stage4/enforce_lsm_policy", json={
        "policy_mode": "enforcing",
        "allowed_binary_roots": ["/usr/bin", "/bin"],
        "block_unverified_mprotect": True,
        "action_on_violation": "SIGKILL",
    })
    assert res_premature.status_code == 403

    # Fast-forward stages 1-3
    client.post("/api/stage1/attach_telemetry", json={
        "hook_target": "tracepoint/syscalls/sys_enter_execve",
        "filter_expression": "pid != 0",
        "ring_buffer_size_kb": 64,
    })
    client.post("/api/stage2/detect_process_hollowing", json={
        "target_pid": 1337,
        "cross_check_inode": True,
        "scan_vad_permissions": True,
    })
    client.post("/api/stage3/audit_ebpf_rootkit", json={
        "scan_bpf_progs": True,
        "rogue_prog_id": 404,
        "action": "detach_and_purge",
    })

    # Permissive mode rejected
    res_permissive = client.post("/api/stage4/enforce_lsm_policy", json={
        "policy_mode": "permissive",
        "allowed_binary_roots": ["/usr/bin", "/bin"],
        "block_unverified_mprotect": True,
        "action_on_violation": "SIGKILL",
    })
    assert res_permissive.status_code == 400

    # Missing essential roots
    res_missing_roots = client.post("/api/stage4/enforce_lsm_policy", json={
        "policy_mode": "enforcing",
        "allowed_binary_roots": ["/opt/mycustomapp"],
        "block_unverified_mprotect": True,
        "action_on_violation": "SIGKILL",
    })
    assert res_missing_roots.status_code == 400

    # Successful LSM Zero-Trust policy enforcement
    res_ok = client.post("/api/stage4/enforce_lsm_policy", json={
        "policy_mode": "enforcing",
        "allowed_binary_roots": ["/usr/bin", "/bin", "/usr/sbin"],
        "block_unverified_mprotect": True,
        "action_on_violation": "SIGKILL",
    })
    assert res_ok.status_code == 200
    data = res_ok.json()
    assert data["success"] is True
    assert data["stage"] == 4
    assert data["flag"] == STAGE4_FLAG
    assert data["policy"]["mode"] == "enforcing"
