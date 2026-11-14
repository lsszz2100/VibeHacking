"""
tests/test_hypervisor_escape_lab.py — Lab 58 HypervisorEscapeLab Unit Tests
"""

import sys
import importlib.util
from pathlib import Path
import pytest
from starlette.testclient import TestClient

APP_PATH = Path(__file__).resolve().parent.parent / "app" / "main.py"
spec = importlib.util.spec_from_file_location("lab58_app", str(APP_PATH))
lab58_module = importlib.util.module_from_spec(spec)
sys.modules["lab58_app"] = lab58_module
spec.loader.exec_module(lab58_module)

app = lab58_module.app
state = lab58_module.state
STAGE1_FLAG = lab58_module.STAGE1_FLAG
STAGE2_FLAG = lab58_module.STAGE2_FLAG
STAGE3_FLAG = lab58_module.STAGE3_FLAG
STAGE4_FLAG = lab58_module.STAGE4_FLAG


@pytest.fixture(autouse=True)
def reset_lab_state():
    state.reset()
    yield
    state.reset()


@pytest.fixture
def client():
    return TestClient(app)


def test_health_and_status(client):
    res_health = client.get("/api/health")
    assert res_health.status_code == 200
    data_health = res_health.json()
    assert data_health["status"] == "ok"
    assert data_health["port"] == "8058"

    res_status = client.get("/api/status")
    assert res_status.status_code == 200
    data_status = res_status.json()
    assert data_status["solved_count"] == 0
    assert data_status["stage1_completed"] is False


def test_stage1_intercept_vm_exit(client):
    # Valid MMIO intercept
    payload = {
        "exit_reason": "EXIT_REASON_EPT_VIOLATION",
        "mmio_address": "0xFED00000",
        "emulation_handler": "hpet_mmio_read",
    }
    res = client.post("/api/stage1/intercept_vm_exit", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "success"
    assert data["flag"] == STAGE1_FLAG
    assert state.stage1_completed is True


def test_stage1_invalid_params(client):
    # Invalid exit reason
    payload = {
        "exit_reason": "INVALID_EXIT_REASON",
        "mmio_address": "0xFED00000",
        "emulation_handler": "hpet_mmio_read",
    }
    res = client.post("/api/stage1/intercept_vm_exit", json=payload)
    assert res.status_code == 400

    # Invalid address
    payload_bad_addr = {
        "exit_reason": "EXIT_REASON_EPT_VIOLATION",
        "mmio_address": "0x12345678",
        "emulation_handler": "hpet_mmio_read",
    }
    res2 = client.post("/api/stage1/intercept_vm_exit", json=payload_bad_addr)
    assert res2.status_code == 400


def test_stage_gating_unauthorized(client):
    # Calling stage 2 without stage 1
    payload_stage2 = {
        "vring_idx": 3,
        "descriptor_len": 4096,
        "corrupt_next_offset": "0x1000",
        "payload_type": "scatter_gather_oob",
    }
    res2 = client.post("/api/stage2/virtio_vring_overflow", json=payload_stage2)
    assert res2.status_code == 403


def test_stage2_virtio_vring_overflow(client):
    # Stage 1 first
    client.post("/api/stage1/intercept_vm_exit", json={
        "exit_reason": "EXIT_REASON_EPT_VIOLATION",
        "mmio_address": "0xFED00000",
        "emulation_handler": "hpet_mmio_read",
    })

    # Stage 2 execution
    payload = {
        "vring_idx": 1,
        "descriptor_len": 4096,
        "corrupt_next_offset": "0x1000",
        "payload_type": "scatter_gather_oob",
    }
    res = client.post("/api/stage2/virtio_vring_overflow", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "success"
    assert data["flag"] == STAGE2_FLAG
    assert state.stage2_completed is True


def test_stage3_kvm_vcpu_smuggling(client):
    # Pass stages 1 & 2
    client.post("/api/stage1/intercept_vm_exit", json={
        "exit_reason": "EXIT_REASON_EPT_VIOLATION",
        "mmio_address": "0xFED00000",
        "emulation_handler": "hpet_mmio_read",
    })
    client.post("/api/stage2/virtio_vring_overflow", json={
        "vring_idx": 1,
        "descriptor_len": 4096,
        "corrupt_next_offset": "0x1000",
    })

    res = client.post("/api/stage3/kvm_vcpu_smuggling", json={
        "vcpu_id": 0,
        "smuggle_register": "CR3_AND_MSR_LSTAR",
        "target_msr": "0xC0000082",
        "leak_host_kernel_base": True,
    })
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "success"
    assert data["flag"] == STAGE3_FLAG
    assert "0xffffffff" in data["leaked_host_kernel_base"]
    assert state.stage3_completed is True


def test_stage4_full_chain_and_hardening(client):
    # Complete stages 1, 2, 3
    client.post("/api/stage1/intercept_vm_exit", json={
        "exit_reason": "EXIT_REASON_EPT_VIOLATION",
        "mmio_address": "0xFED00000",
        "emulation_handler": "hpet_mmio_read",
    })
    client.post("/api/stage2/virtio_vring_overflow", json={
        "vring_idx": 1,
        "descriptor_len": 4096,
        "corrupt_next_offset": "0x1000",
    })
    client.post("/api/stage3/kvm_vcpu_smuggling", json={
        "vcpu_id": 0,
        "smuggle_register": "CR3_AND_MSR_LSTAR",
        "target_msr": "0xC0000082",
        "leak_host_kernel_base": True,
    })

    # Stage 4 execution
    payload = {
        "seccomp_bpf_policy": "strict_kvm_ioctl_whitelist",
        "landlock_fs_confinement": True,
        "drop_caps": ["CAP_SYS_ADMIN", "CAP_SYS_PTRACE"],
        "enforce_memory_tagging": True,
    }
    res = client.post("/api/stage4/enforce_hypervisor_hardening", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "success"
    assert data["flag"] == STAGE4_FLAG
    assert state.stage4_completed is True

    # Check status
    res_status = client.get("/api/status")
    assert res_status.json()["solved_count"] == 4

    # Reset
    res_reset = client.post("/api/reset")
    assert res_reset.status_code == 200
    assert client.get("/api/status").json()["solved_count"] == 0
