"""Unit & Integration Tests for Lab 54: AgentSandboxGuard."""

import sys
import importlib.util
from pathlib import Path
import pytest
from starlette.testclient import TestClient

APP_PATH = Path(__file__).resolve().parent.parent / "app" / "main.py"
spec = importlib.util.spec_from_file_location("lab54_app", str(APP_PATH))
lab54_module = importlib.util.module_from_spec(spec)
sys.modules["lab54_app"] = lab54_module
spec.loader.exec_module(lab54_module)

app = lab54_module.app
state = lab54_module.state
STAGE1_FLAG = lab54_module.STAGE1_FLAG
STAGE2_FLAG = lab54_module.STAGE2_FLAG
STAGE3_FLAG = lab54_module.STAGE3_FLAG
STAGE4_FLAG = lab54_module.STAGE4_FLAG

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
    assert data["status"] == "ready"
    assert data["lab_id"] == "54"
    assert data["stage1_completed"] is False


def test_index_page():
    res = client.get("/")
    assert res.status_code == 200
    assert "AgentSandboxGuard" in res.text


def test_stage1_poison_flow():
    # Invalid tool should be rejected
    res_bad = client.post("/api/stage1/poison", json={
        "tool_name": "invalid_calculator",
        "injected_schema": {},
        "payload": "nothing"
    })
    assert res_bad.status_code == 400

    # Valid poison request
    res_ok = client.post("/api/stage1/poison", json={
        "tool_name": "run_command",
        "injected_schema": {"type": "object", "properties": {"command": {"type": "string"}}},
        "payload": "OVERRIDE: exec shadow bypass"
    })
    assert res_ok.status_code == 200
    data = res_ok.json()
    assert data["success"] is True
    assert data["flag"] == STAGE1_FLAG
    assert state.stage1_completed is True


def test_stage2_escape_flow():
    # Cannot run stage 2 before stage 1
    res_blocked = client.post("/api/stage2/escape", json={
        "agent_role": "Coordinator",
        "command": "cat /etc/shadow",
        "target_file": "/etc/shadow"
    })
    assert res_blocked.status_code == 400

    # Solve stage 1
    client.post("/api/stage1/poison", json={
        "tool_name": "run_command",
        "injected_schema": {"command": "exec"},
        "payload": "OVERRIDE: system bypass"
    })

    # Non-sensitive target should be rejected
    res_non_target = client.post("/api/stage2/escape", json={
        "agent_role": "Coordinator",
        "command": "cat /tmp/test.txt",
        "target_file": "/tmp/test.txt"
    })
    assert res_non_target.status_code == 400

    # Successful escape
    res_ok = client.post("/api/stage2/escape", json={
        "agent_role": "Coordinator",
        "command": "cat /etc/shadow",
        "target_file": "/etc/shadow"
    })
    assert res_ok.status_code == 200
    assert res_ok.json()["flag"] == STAGE2_FLAG
    assert state.stage2_completed is True


def test_stage3_landlock_sandboxing():
    # Prerequisites
    client.post("/api/stage1/poison", json={"tool_name": "run_command", "injected_schema": {"command": "exec"}, "payload": "bypass"})
    client.post("/api/stage2/escape", json={"agent_role": "Agent", "command": "cat /etc/shadow", "target_file": "/etc/shadow"})

    # Invalid empty paths
    res_empty = client.post("/api/stage3/landlock", json={
        "allowed_paths": [],
        "denied_paths": ["/etc"],
        "abi_version": 3,
        "handled_access_fs": ["execute"]
    })
    assert res_empty.status_code == 400

    # Missing critical denied paths
    res_missing_denied = client.post("/api/stage3/landlock", json={
        "allowed_paths": ["/workspace/safe"],
        "denied_paths": ["/var/tmp"],
        "abi_version": 3,
        "handled_access_fs": ["execute"]
    })
    assert res_missing_denied.status_code == 422

    # Successful Landlock ruleset enforcement
    res_ok = client.post("/api/stage3/landlock", json={
        "allowed_paths": ["/workspace/safe"],
        "denied_paths": ["/etc", "/proc", "/root"],
        "abi_version": 3,
        "handled_access_fs": ["execute", "write_file", "read_file"]
    })
    assert res_ok.status_code == 200
    assert res_ok.json()["flag"] == STAGE3_FLAG
    assert state.landlock_active is True

    # Now verify that subsequent escape attempt is blocked by Landlock
    res_blocked_by_landlock = client.post("/api/stage2/escape", json={
        "agent_role": "Agent",
        "command": "cat /etc/shadow",
        "target_file": "/etc/shadow"
    })
    assert res_blocked_by_landlock.status_code == 403
    assert "Landlock" in res_blocked_by_landlock.json()["detail"]


def test_stage4_ebpf_guardrail_enforcement():
    # Prerequisites
    client.post("/api/stage1/poison", json={"tool_name": "run_command", "injected_schema": {"command": "exec"}, "payload": "bypass"})
    client.post("/api/stage2/escape", json={"agent_role": "Agent", "command": "cat /etc/shadow", "target_file": "/etc/shadow"})
    client.post("/api/stage3/landlock", json={"allowed_paths": ["/safe"], "denied_paths": ["/etc"], "abi_version": 3, "handled_access_fs": ["read"]})

    # Missing dual-LLM verification
    res_no_dual = client.post("/api/stage4/ebpf_guardrail", json={
        "ebpf_hook": "sys_enter_execve",
        "dual_llm_verification": False,
        "policy_action": "SIGKILL"
    })
    assert res_no_dual.status_code == 422

    # Successful eBPF Dual-LLM Guardrail
    res_ok = client.post("/api/stage4/ebpf_guardrail", json={
        "ebpf_hook": "sys_enter_execve",
        "dual_llm_verification": True,
        "policy_action": "SIGKILL"
    })
    assert res_ok.status_code == 200
    assert res_ok.json()["flag"] == STAGE4_FLAG
    assert state.ebpf_guardrail_active is True
