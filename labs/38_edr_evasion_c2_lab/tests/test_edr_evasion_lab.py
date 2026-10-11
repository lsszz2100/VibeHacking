#!/usr/bin/env python3
"""
Unit and integration tests for Lab 38: EDRShield — EDR Evasion & Next-Gen C2 Lab
Tests AMSI/ETW in-memory patching, ntdll disk unhooking, dynamic SSN extraction,
indirect syscalls via ntdll gadget, and Ekko timer-queue sleep obfuscation.
"""

import sys
import importlib.util
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

# Dynamic import to avoid collision with other labs' main modules
APP_PATH = Path(__file__).resolve().parent.parent / "app" / "main.py"
spec = importlib.util.spec_from_file_location("lab38_app", str(APP_PATH))
lab38_module = importlib.util.module_from_spec(spec)
sys.modules["lab38_app"] = lab38_module
spec.loader.exec_module(lab38_module)

app = lab38_module.app
reset_lab = lab38_module.reset_lab
STEP1_FLAG = lab38_module.STEP1_FLAG
STEP2_FLAG = lab38_module.STEP2_FLAG
STEP3_FLAG = lab38_module.STEP3_FLAG
STEP4_FLAG = lab38_module.STEP4_FLAG


@pytest.fixture(autouse=True)
def run_reset():
    """Ensure each test runs with a fresh default baseline."""
    reset_lab()
    yield
    reset_lab()


@pytest.fixture
def client():
    return TestClient(app)


def test_health(client):
    res = client.get("/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "ok"
    assert data["lab"] == "38_edr_evasion_c2_lab"
    assert data["port"] == 8038
    assert data["step1_completed"] is False
    assert data["step2_completed"] is False
    assert data["step3_completed"] is False
    assert data["step4_completed"] is False


def test_index_html(client):
    res = client.get("/")
    assert res.status_code == 200
    assert "text/html" in res.headers["content-type"]
    assert "Lab 38: EDRShield" in res.text
    assert "8038" in res.text


def test_reset_lab(client):
    # Set step1 completed
    client.post(
        "/api/edr/amsi-etw/patch",
        json={"target": "both", "patch_hex": "b8 57 00 07 80 c3", "verify_bypass": True},
    )
    h_before = client.get("/health").json()
    assert h_before["step1_completed"] is True

    # Call reset
    r = client.post("/api/reset")
    assert r.status_code == 200
    h_after = client.get("/health").json()
    assert h_after["step1_completed"] is False


def test_stage1_amsi_patch_success(client):
    res = client.post(
        "/api/edr/amsi-etw/patch",
        json={"target": "amsi", "patch_hex": "b8 57 00 07 80 c3", "verify_bypass": True},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "success"
    assert data["amsi_patched"] is True
    assert data["flag"] == STEP1_FLAG


def test_stage1_etw_patch_success(client):
    res = client.post(
        "/api/edr/amsi-etw/patch",
        json={"target": "etw", "patch_hex": "c3", "verify_bypass": True},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "success"
    assert data["etw_patched"] is True
    assert data["flag"] == STEP1_FLAG


def test_stage1_both_patch(client):
    res = client.post(
        "/api/edr/amsi-etw/patch",
        json={"target": "both", "patch_hex": "b8 57 00 07 80 c3", "verify_bypass": True},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["amsi_patched"] is True
    assert data["etw_patched"] is True
    assert data["flag"] == STEP1_FLAG


def test_stage1_invalid_patch_fail(client):
    res = client.post(
        "/api/edr/amsi-etw/patch",
        json={"target": "amsi", "patch_hex": "90 90 90", "verify_bypass": True},
    )
    assert res.status_code == 400
    assert "Invalid AMSI patch" in res.json()["detail"]


def test_stage2_ntdll_hooks_initial(client):
    res = client.get("/api/edr/ntdll/hooks")
    assert res.status_code == 200
    data = res.json()
    hooks = data["hooks"]
    assert "NtAllocateVirtualMemory" in hooks
    assert hooks["NtAllocateVirtualMemory"]["hooked"] is True
    assert data["unhook_status"]["active_hooks_count"] == 4


def test_stage2_unhook_disk_mapping_success(client):
    res = client.post(
        "/api/edr/ntdll/unhook",
        json={"method": "disk_mapping", "target_section": ".text", "restore_bytes": True},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "success"
    assert data["hooks_removed"] == 4
    assert data["flag"] == STEP2_FLAG

    # Verify hooks removed
    h = client.get("/api/edr/ntdll/hooks").json()
    assert h["unhook_status"]["active_hooks_count"] == 0
    assert h["hooks"]["NtAllocateVirtualMemory"]["hooked"] is False


def test_stage2_unhook_knowndlls_success(client):
    res = client.post(
        "/api/edr/ntdll/unhook",
        json={"method": "knowndlls", "target_section": ".text", "restore_bytes": True},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "success"
    assert data["flag"] == STEP2_FLAG


def test_stage2_invalid_unhook_method(client):
    res = client.post(
        "/api/edr/ntdll/unhook",
        json={"method": "invalid_method", "target_section": ".text", "restore_bytes": True},
    )
    assert res.status_code == 400


def test_stage3_syscall_map(client):
    res = client.get("/api/edr/syscalls/map")
    assert res.status_code == 200
    data = res.json()
    assert "NtAllocateVirtualMemory" in data["syscalls"]
    assert data["syscalls"]["NtAllocateVirtualMemory"]["ssn"] == "0x0018"


def test_stage3_hells_gate_hooked_fail(client):
    # In initial state, functions are hooked (starts with 0xE9), Hell's gate fails
    res = client.post(
        "/api/edr/syscalls/invoke",
        json={
            "function_name": "NtAllocateVirtualMemory",
            "ssn_extraction": "hells_gate",
            "execution_mode": "indirect_syscall",
            "allocation_size": 4096,
        },
    )
    assert res.status_code == 422
    assert "Hell's Gate failed" in res.json()["detail"]


def test_stage3_halos_gate_indirect_syscall_success(client):
    # Halo's Gate inspects neighbor stubs to derive SSN even when hooked
    res = client.post(
        "/api/edr/syscalls/invoke",
        json={
            "function_name": "NtAllocateVirtualMemory",
            "ssn_extraction": "halos_gate",
            "execution_mode": "indirect_syscall",
            "allocation_size": 4096,
        },
    )
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "success"
    assert data["ssn"] == "0x0018"
    assert data["flag"] == STEP3_FLAG


def test_stage3_direct_syscall_blocked_by_call_stack(client):
    res = client.post(
        "/api/edr/syscalls/invoke",
        json={
            "function_name": "NtAllocateVirtualMemory",
            "ssn_extraction": "halos_gate",
            "execution_mode": "direct_syscall",
            "allocation_size": 4096,
        },
    )
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "blocked"
    assert data["detection"] == "EDR_CALL_STACK_ANOMALY"


def test_stage4_beacon_initial_status(client):
    res = client.get("/api/edr/c2/beacon-status")
    assert res.status_code == 200
    data = res.json()
    assert data["beacon"]["state"] == "ACTIVE"
    assert data["beacon"]["encrypted"] is False


def test_stage4_standard_sleep_detected(client):
    res = client.post(
        "/api/edr/c2/sleep-obfuscate",
        json={
            "technique": "standard_sleep",
            "sleep_seconds": 5,
            "mask_protection": "PAGE_READWRITE",
            "encryption_algo": "NONE",
        },
    )
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "detected"
    assert "ALERT" in data["yara_result"]


def test_stage4_ekko_sleep_obfuscation_success(client):
    res = client.post(
        "/api/edr/c2/sleep-obfuscate",
        json={
            "technique": "ekko_rop_timer",
            "sleep_seconds": 10,
            "mask_protection": "PAGE_READWRITE",
            "encryption_algo": "SystemFunction032_XOR",
        },
    )
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "success"
    assert "CLEAN" in data["memory_scanner_verdict"]
    assert data["flag"] == STEP4_FLAG


def test_stage4_cronos_sleep_obfuscation_success(client):
    res = client.post(
        "/api/edr/c2/sleep-obfuscate",
        json={
            "technique": "cronos",
            "sleep_seconds": 15,
            "mask_protection": "PAGE_NOACCESS",
            "encryption_algo": "SystemFunction032_XOR",
        },
    )
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "success"
    assert data["flag"] == STEP4_FLAG


def test_full_chain_solve(client):
    # 1. AMSI Patch
    r1 = client.post(
        "/api/edr/amsi-etw/patch",
        json={"target": "both", "patch_hex": "b8 57 00 07 80 c3", "verify_bypass": True},
    )
    assert r1.status_code == 200 and r1.json()["flag"] == STEP1_FLAG

    # 2. ntdll Unhook
    r2 = client.post(
        "/api/edr/ntdll/unhook",
        json={"method": "disk_mapping", "target_section": ".text", "restore_bytes": True},
    )
    assert r2.status_code == 200 and r2.json()["flag"] == STEP2_FLAG

    # 3. Hell's gate now works because ntdll is unhooked!
    r3 = client.post(
        "/api/edr/syscalls/invoke",
        json={
            "function_name": "NtAllocateVirtualMemory",
            "ssn_extraction": "hells_gate",
            "execution_mode": "indirect_syscall",
            "allocation_size": 4096,
        },
    )
    assert r3.status_code == 200 and r3.json()["flag"] == STEP3_FLAG

    # 4. Ekko Sleep
    r4 = client.post(
        "/api/edr/c2/sleep-obfuscate",
        json={
            "technique": "ekko_rop_timer",
            "sleep_seconds": 5,
            "mask_protection": "PAGE_READWRITE",
            "encryption_algo": "SystemFunction032_XOR",
        },
    )
    assert r4.status_code == 200 and r4.json()["flag"] == STEP4_FLAG

    # Check health 100% complete
    h = client.get("/health").json()
    assert h["step1_completed"] is True
    assert h["step2_completed"] is True
    assert h["step3_completed"] is True
    assert h["step4_completed"] is True
