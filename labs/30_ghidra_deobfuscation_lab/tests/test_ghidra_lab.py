"""Unit tests for Lab 30: GhidraRev - Binary Analysis & Advanced Deobfuscation Security Lab."""

import importlib.util
import os
import sys
from pathlib import Path
import pytest
from starlette.testclient import TestClient

LAB_DIR = Path(__file__).resolve().parent.parent
APP_PATH = LAB_DIR / "app" / "main.py"


@pytest.fixture(scope="module")
def app_module():
    spec = importlib.util.spec_from_file_location("lab30_app", str(APP_PATH))
    module = importlib.util.module_from_spec(spec)
    sys.modules["lab30_app"] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def client(app_module):
    client_instance = TestClient(app_module.app)
    client_instance.post("/api/ghidra/reset")
    return client_instance


def test_health_check(client):
    res = client.get("/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "ok"
    assert data["port"] == 8030
    assert "GhidraRev" in data["lab"]


def test_index_view(client):
    res = client.get("/")
    assert res.status_code == 200
    assert "GhidraRev" in res.text
    assert "8030" in res.text
    assert "Control Flow Flattening" in res.text
    assert "0x00401337" in res.text


def test_binary_info(client):
    res = client.get("/api/ghidra/binary/info")
    assert res.status_code == 200
    data = res.json()
    assert "binary" in data
    assert data["binary"]["filename"] == "firmware_auth_daemon.elf"
    assert data["binary"]["stripped"] is True
    assert data["symbols_recovered"] is False
    assert len(data["binary"]["strings"]) >= 4


def test_lab_status(client):
    res = client.get("/api/ghidra/status")
    assert res.status_code == 200
    data = res.json()
    assert data["symbols_recovered"] is False
    assert data["cff_deobfuscated"] is False
    assert data["binary_patched"] is False
    assert isinstance(data["history"], list)


def test_step1_symbol_analysis_success(client):
    res = client.post("/api/ghidra/analyze/symbols", json={
        "script_name": "recover_headless_symbols.py",
        "target_function_vaddr": "0x00401200",
        "match_prologue": True,
        "rename_symbol": "validate_license_core"
    })
    assert res.status_code == 200
    data = res.json()
    assert data["success"] is True
    assert "validate_license_core" in data["message"]
    assert "FLAG{" in data["flag"]
    assert "8030" in data["flag"]


def test_step1_invalid_script(client):
    res = client.post("/api/ghidra/analyze/symbols", json={
        "script_name": "random_test.py",
        "match_prologue": True
    })
    assert res.status_code == 400
    assert "Ghidra Headless 분석 스크립트" in res.json()["detail"]


def test_step1_no_prologue(client):
    res = client.post("/api/ghidra/analyze/symbols", json={
        "script_name": "recover_headless_symbols.py",
        "match_prologue": False
    })
    assert res.status_code == 400
    assert "함수 프롤로그 시그니처" in res.json()["detail"]


def test_step2_before_step1_fails(client):
    res = client.post("/api/ghidra/deobfuscate/cff", json={
        "state_variable_reg": "eax",
        "dispatcher_vaddr": "0x00401240",
        "block_transitions": [10, 40, 25, 90],
        "defuse_opaque_predicates": True
    })
    assert res.status_code == 400
    assert "Step 1 심볼 복원" in res.json()["detail"]


def test_step2_cff_success(client):
    # Complete Step 1 first
    client.post("/api/ghidra/analyze/symbols", json={
        "script_name": "recover_headless_symbols.py",
        "match_prologue": True
    })
    res = client.post("/api/ghidra/deobfuscate/cff", json={
        "state_variable_reg": "eax",
        "dispatcher_vaddr": "0x00401240",
        "block_transitions": [10, 40, 25, 90],
        "defuse_opaque_predicates": True
    })
    assert res.status_code == 200
    data = res.json()
    assert data["success"] is True
    assert "디스패처 해체 완료" in data["message"]
    assert "0x00401337" in data["critical_jump"]["vaddr"]
    assert "FLAG{" in data["flag"]
    assert "3921" in data["flag"]


def test_step2_incorrect_sequence(client):
    client.post("/api/ghidra/analyze/symbols", json={
        "script_name": "recover_headless_symbols.py",
        "match_prologue": True
    })
    res = client.post("/api/ghidra/deobfuscate/cff", json={
        "state_variable_reg": "eax",
        "dispatcher_vaddr": "0x00401240",
        "block_transitions": [10, 20, 30],
        "defuse_opaque_predicates": True
    })
    assert res.status_code == 400
    assert "올바르지 않습니다" in res.json()["detail"]


def test_step2_opaque_predicates_not_defused(client):
    client.post("/api/ghidra/analyze/symbols", json={
        "script_name": "recover_headless_symbols.py",
        "match_prologue": True
    })
    res = client.post("/api/ghidra/deobfuscate/cff", json={
        "state_variable_reg": "eax",
        "dispatcher_vaddr": "0x00401240",
        "block_transitions": [10, 40, 25, 90],
        "defuse_opaque_predicates": False
    })
    assert res.status_code == 400
    assert "불투명 술어" in res.json()["detail"]


def test_step3_before_step2_fails(client):
    client.post("/api/ghidra/analyze/symbols", json={
        "script_name": "recover_headless_symbols.py",
        "match_prologue": True
    })
    res = client.post("/api/ghidra/patch/binary", json={
        "patch_vaddr": "0x00401337",
        "original_hex": "74 18",
        "replacement_hex": "90 90"
    })
    assert res.status_code == 400
    assert "Step 2" in res.json()["detail"]


def test_step3_patch_success_nop(client):
    # Step 1
    client.post("/api/ghidra/analyze/symbols", json={
        "script_name": "recover_headless_symbols.py",
        "match_prologue": True
    })
    # Step 2
    client.post("/api/ghidra/deobfuscate/cff", json={
        "state_variable_reg": "eax",
        "dispatcher_vaddr": "0x00401240",
        "block_transitions": [10, 40, 25, 90],
        "defuse_opaque_predicates": True
    })
    # Step 3
    res = client.post("/api/ghidra/patch/binary", json={
        "patch_vaddr": "0x00401337",
        "original_hex": "74 18",
        "replacement_hex": "90 90",
        "bypass_integrity_check": True
    })
    assert res.status_code == 200
    data = res.json()
    assert data["success"] is True
    assert "바이너리 패치 및 안티 탬퍼 우회 성공" in data["message"]
    assert "FLAG{" in data["flag"]
    assert "9942" in data["flag"]


def test_step3_patch_success_jmp(client):
    # Step 1 & 2
    client.post("/api/ghidra/analyze/symbols", json={
        "script_name": "recover_headless_symbols.py",
        "match_prologue": True
    })
    client.post("/api/ghidra/deobfuscate/cff", json={
        "state_variable_reg": "eax",
        "dispatcher_vaddr": "0x00401240",
        "block_transitions": [10, 40, 25, 90],
        "defuse_opaque_predicates": True
    })
    # Step 3 with JMP short
    res = client.post("/api/ghidra/patch/binary", json={
        "patch_vaddr": "0x00401337",
        "original_hex": "74 18",
        "replacement_hex": "eb 18",
        "bypass_integrity_check": True
    })
    assert res.status_code == 200
    assert res.json()["success"] is True


def test_step3_patch_invalid_vaddr(client):
    client.post("/api/ghidra/analyze/symbols", json={
        "script_name": "recover_headless_symbols.py",
        "match_prologue": True
    })
    client.post("/api/ghidra/deobfuscate/cff", json={
        "state_variable_reg": "eax",
        "dispatcher_vaddr": "0x00401240",
        "block_transitions": [10, 40, 25, 90],
        "defuse_opaque_predicates": True
    })
    res = client.post("/api/ghidra/patch/binary", json={
        "patch_vaddr": "0x00409999",
        "original_hex": "74 18",
        "replacement_hex": "90 90"
    })
    assert res.status_code == 400
    assert "0x00401337" in res.json()["detail"]


def test_step3_patch_invalid_opcode(client):
    client.post("/api/ghidra/analyze/symbols", json={
        "script_name": "recover_headless_symbols.py",
        "match_prologue": True
    })
    client.post("/api/ghidra/deobfuscate/cff", json={
        "state_variable_reg": "eax",
        "dispatcher_vaddr": "0x00401240",
        "block_transitions": [10, 40, 25, 90],
        "defuse_opaque_predicates": True
    })
    res = client.post("/api/ghidra/patch/binary", json={
        "patch_vaddr": "0x00401337",
        "original_hex": "74 18",
        "replacement_hex": "cc cc"
    })
    assert res.status_code == 400
    assert "대체 바이트" in res.json()["detail"]


def test_step3_defense_anti_patch_sentinel(client):
    client.post("/api/ghidra/harden", json={
        "cfi_enabled": False,
        "sig_verification": False,
        "anti_patch_sentinel": True
    })
    client.post("/api/ghidra/analyze/symbols", json={
        "script_name": "recover_headless_symbols.py",
        "match_prologue": True
    })
    client.post("/api/ghidra/deobfuscate/cff", json={
        "state_variable_reg": "eax",
        "dispatcher_vaddr": "0x00401240",
        "block_transitions": [10, 40, 25, 90],
        "defuse_opaque_predicates": True
    })
    res = client.post("/api/ghidra/patch/binary", json={
        "patch_vaddr": "0x00401337",
        "original_hex": "74 18",
        "replacement_hex": "90 90",
        "bypass_integrity_check": False
    })
    assert res.status_code == 403
    assert "안티 탬퍼 센티넬 발동" in res.json()["detail"]


def test_step3_defense_signature_verification(client):
    client.post("/api/ghidra/harden", json={
        "cfi_enabled": True,
        "sig_verification": True,
        "anti_patch_sentinel": False
    })
    client.post("/api/ghidra/analyze/symbols", json={
        "script_name": "recover_headless_symbols.py",
        "match_prologue": True
    })
    client.post("/api/ghidra/deobfuscate/cff", json={
        "state_variable_reg": "eax",
        "dispatcher_vaddr": "0x00401240",
        "block_transitions": [10, 40, 25, 90],
        "defuse_opaque_predicates": True
    })
    res = client.post("/api/ghidra/patch/binary", json={
        "patch_vaddr": "0x00401337",
        "original_hex": "74 18",
        "replacement_hex": "90 90",
        "bypass_integrity_check": True
    })
    assert res.status_code == 403
    assert "디지털 서명 검증 실패" in res.json()["detail"]


def test_reset_lab(client):
    client.post("/api/ghidra/analyze/symbols", json={
        "script_name": "recover_headless_symbols.py",
        "match_prologue": True
    })
    assert client.get("/api/ghidra/status").json()["symbols_recovered"] is True

    res = client.post("/api/ghidra/reset")
    assert res.status_code == 200
    assert client.get("/api/ghidra/status").json()["symbols_recovered"] is False
