"""Unit & Integration Tests for Lab 57: AntiReversingShield."""

import sys
import importlib.util
from pathlib import Path
import pytest
from starlette.testclient import TestClient

APP_PATH = Path(__file__).resolve().parent.parent / "app" / "main.py"
spec = importlib.util.spec_from_file_location("lab57_app", str(APP_PATH))
lab57_module = importlib.util.module_from_spec(spec)
sys.modules["lab57_app"] = lab57_module
spec.loader.exec_module(lab57_module)

app = lab57_module.app
state = lab57_module.state
STAGE1_FLAG = lab57_module.STAGE1_FLAG
STAGE2_FLAG = lab57_module.STAGE2_FLAG
STAGE3_FLAG = lab57_module.STAGE3_FLAG
STAGE4_FLAG = lab57_module.STAGE4_FLAG

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
    assert data["lab_id"] == "57"
    assert data["solved_count"] == 0
    assert data["stages"]["stage1_completed"] is False


def test_health_endpoint():
    res = client.get("/api/health")
    assert res.status_code == 200
    assert res.json()["status"] == "ok"
    assert res.json()["port"] == "8057"


def test_index_page():
    res = client.get("/")
    assert res.status_code == 200
    assert "AntiReversingShield" in res.text
    assert "Port 8057" in res.text


def test_stage1_anti_debugging():
    # Bad method
    res_bad = client.post("/api/stage1/bypass_anti_debugging", json={
        "bypass_method": "invalid_hook",
        "target_checks": ["ptrace_traceme", "being_debugged", "hardware_breakpoints"]
    })
    assert res_bad.status_code == 400

    # Incomplete checks
    res_inc = client.post("/api/stage1/bypass_anti_debugging", json={
        "bypass_method": "byte_patch",
        "target_checks": ["ptrace_traceme"],
        "patch_hex": "9090"
    })
    assert res_inc.status_code == 400

    # Invalid patch hex for byte_patch
    res_patch = client.post("/api/stage1/bypass_anti_debugging", json={
        "bypass_method": "byte_patch",
        "target_checks": ["ptrace_traceme", "being_debugged", "hardware_breakpoints"],
        "patch_hex": "112233"
    })
    assert res_patch.status_code == 400

    # Successful bypass
    res_ok = client.post("/api/stage1/bypass_anti_debugging", json={
        "bypass_method": "byte_patch",
        "target_checks": ["ptrace_traceme", "being_debugged", "hardware_breakpoints"],
        "patch_hex": "31c0c3"
    })
    assert res_ok.status_code == 200
    data = res_ok.json()
    assert data["success"] is True
    assert data["stage"] == 1
    assert data["flag"] == STAGE1_FLAG


def test_stage2_api_hashing():
    # Premature call before Stage 1
    res_premature = client.post("/api/stage2/resolve_api_hashing", json={
        "hash_algorithm": "ror13",
        "target_hash": "0x91afca54",
        "candidate_api": "VirtualAlloc"
    })
    assert res_premature.status_code == 403

    # Complete Stage 1
    client.post("/api/stage1/bypass_anti_debugging", json={
        "bypass_method": "ld_preload_hook",
        "target_checks": ["ptrace_traceme", "being_debugged", "hardware_breakpoints"]
    })

    # Unsupported hash algorithm
    res_algo = client.post("/api/stage2/resolve_api_hashing", json={
        "hash_algorithm": "md5",
        "target_hash": "0x91afca54",
        "candidate_api": "VirtualAlloc"
    })
    assert res_algo.status_code == 400

    # Unknown hash target
    res_unk = client.post("/api/stage2/resolve_api_hashing", json={
        "hash_algorithm": "ror13",
        "target_hash": "0xdeadbeef",
        "candidate_api": "VirtualAlloc"
    })
    assert res_unk.status_code == 404

    # Candidate mismatch
    res_mis = client.post("/api/stage2/resolve_api_hashing", json={
        "hash_algorithm": "ror13",
        "target_hash": "0x91afca54",
        "candidate_api": "CreateRemoteThread"
    })
    assert res_mis.status_code == 400

    # Successful API resolution
    res_ok = client.post("/api/stage2/resolve_api_hashing", json={
        "hash_algorithm": "ror13",
        "target_hash": "0x91afca54",
        "candidate_api": "VirtualAlloc"
    })
    assert res_ok.status_code == 200
    data = res_ok.json()
    assert data["success"] is True
    assert data["stage"] == 2
    assert data["flag"] == STAGE2_FLAG


def test_stage3_packer_unpacking():
    # Premature call before Stage 2
    res_premature = client.post("/api/stage3/unpack_binary", json={
        "unpack_strategy": "tail_jump_tracking",
        "target_oep": "0x00401580",
        "rebuild_iat": True
    })
    assert res_premature.status_code == 403

    # Pass Stages 1 and 2
    client.post("/api/stage1/bypass_anti_debugging", json={
        "bypass_method": "ld_preload_hook",
        "target_checks": ["ptrace_traceme", "being_debugged", "hardware_breakpoints"]
    })
    client.post("/api/stage2/resolve_api_hashing", json={
        "hash_algorithm": "ror13",
        "target_hash": "0x91afca54",
        "candidate_api": "VirtualAlloc"
    })

    # Bad strategy
    res_strat = client.post("/api/stage3/unpack_binary", json={
        "unpack_strategy": "brute_force",
        "target_oep": "0x00401580",
        "rebuild_iat": True
    })
    assert res_strat.status_code == 400

    # Wrong OEP
    res_oep = client.post("/api/stage3/unpack_binary", json={
        "unpack_strategy": "tail_jump_tracking",
        "target_oep": "0x00409999",
        "rebuild_iat": True
    })
    assert res_oep.status_code == 400

    # rebuild_iat False
    res_iat = client.post("/api/stage3/unpack_binary", json={
        "unpack_strategy": "tail_jump_tracking",
        "target_oep": "0x00401580",
        "rebuild_iat": False
    })
    assert res_iat.status_code == 400

    # Successful unpack
    res_ok = client.post("/api/stage3/unpack_binary", json={
        "unpack_strategy": "tail_jump_tracking",
        "target_oep": "0x00401580",
        "rebuild_iat": True
    })
    assert res_ok.status_code == 200
    data = res_ok.json()
    assert data["success"] is True
    assert data["stage"] == 3
    assert data["flag"] == STAGE3_FLAG


def test_stage4_anti_vm_timing():
    # Premature call before Stage 3
    res_premature = client.post("/api/stage4/neutralize_anti_vm", json={
        "rdtsc_threshold_cycles": 500,
        "spoof_cpuid_hypervisor": True,
        "filter_smbios_artifacts": ["VMware", "QEMU", "VirtualBox"]
    })
    assert res_premature.status_code == 403

    # Pass Stages 1, 2, 3
    client.post("/api/stage1/bypass_anti_debugging", json={
        "bypass_method": "ld_preload_hook",
        "target_checks": ["ptrace_traceme", "being_debugged", "hardware_breakpoints"]
    })
    client.post("/api/stage2/resolve_api_hashing", json={
        "hash_algorithm": "ror13",
        "target_hash": "0x91afca54",
        "candidate_api": "VirtualAlloc"
    })
    client.post("/api/stage3/unpack_binary", json={
        "unpack_strategy": "tail_jump_tracking",
        "target_oep": "0x00401580",
        "rebuild_iat": True
    })

    # Out of range threshold
    res_range = client.post("/api/stage4/neutralize_anti_vm", json={
        "rdtsc_threshold_cycles": 50,
        "spoof_cpuid_hypervisor": True,
        "filter_smbios_artifacts": ["VMware", "QEMU", "VirtualBox"]
    })
    assert res_range.status_code == 400

    # CPUID not spoofed
    res_cpuid = client.post("/api/stage4/neutralize_anti_vm", json={
        "rdtsc_threshold_cycles": 500,
        "spoof_cpuid_hypervisor": False,
        "filter_smbios_artifacts": ["VMware", "QEMU", "VirtualBox"]
    })
    assert res_cpuid.status_code == 400

    # Incomplete vendors
    res_vendor = client.post("/api/stage4/neutralize_anti_vm", json={
        "rdtsc_threshold_cycles": 500,
        "spoof_cpuid_hypervisor": True,
        "filter_smbios_artifacts": ["VMware"]
    })
    assert res_vendor.status_code == 400

    # Successful stage 4
    res_ok = client.post("/api/stage4/neutralize_anti_vm", json={
        "rdtsc_threshold_cycles": 500,
        "spoof_cpuid_hypervisor": True,
        "filter_smbios_artifacts": ["VMware", "QEMU", "VirtualBox"]
    })
    assert res_ok.status_code == 200
    data = res_ok.json()
    assert data["success"] is True
    assert data["stage"] == 4
    assert data["flag"] == STAGE4_FLAG

    # Check overall status
    st = client.get("/api/status").json()
    assert st["solved_count"] == 4
    assert st["stages"]["stage4_completed"] is True
