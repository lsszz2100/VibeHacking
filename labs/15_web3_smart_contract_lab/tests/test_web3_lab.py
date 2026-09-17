#!/usr/bin/env python3
"""Tests for Lab 15: Web3 & Smart Contract Security Lab (ChainDefend)."""

import pytest
from starlette.testclient import TestClient

import importlib.util
import os
import sys

_app_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "app", "main.py"))
_spec = importlib.util.spec_from_file_location("web3_lab_main", _app_path)
_mod = importlib.util.module_from_spec(_spec)
sys.modules["web3_lab_main"] = _mod
_spec.loader.exec_module(_mod)

app = _mod.app
FLAGS = _mod.FLAGS
state = _mod.state


@pytest.fixture(autouse=True)
def reset_state():
    state.reset()
    yield
    state.reset()


@pytest.fixture
def client():
    return TestClient(app)


def test_status_endpoint(client):
    res = client.get("/status")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "online"
    assert data["chain_id"] == 31337
    assert data["total_stages"] == 4
    assert "stage1_reentrancy" in data["stages"]
    assert "stage2_overflow" in data["stages"]
    assert "stage3_tx_origin" in data["stages"]
    assert "stage4_flashloan" in data["stages"]


def test_dashboard_served(client):
    res = client.get("/")
    assert res.status_code == 200
    assert "text/html" in res.headers["content-type"]
    assert "ChainDefend" in res.text
    assert "Reentrancy Vault" in res.text


def test_stage1_reentrancy_vulnerable(client):
    # Initial state
    assert state.vault_balance == 10.0
    res = client.post(
        "/api/stage1/reentrancy-attack",
        json={"attacker_contract": True, "iterations": 10},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["success"] is True
    assert data["vault_balance"] == 0.0
    assert data["flag"] == FLAGS["stage1"]
    assert state.stage1_solved is True


def test_stage1_reentrancy_defense(client):
    # Enable ReentrancyGuard
    client.post("/api/stage1/toggle-guard")
    assert state.stage1_guard_enabled is True

    res = client.post(
        "/api/stage1/reentrancy-attack",
        json={"attacker_contract": True, "iterations": 10},
    )
    assert res.status_code == 400
    assert "reentrant call" in res.json()["detail"]


def test_stage2_batch_overflow_vulnerable(client):
    # Value = 2^255 hex = 0x8000000000000000000000000000000000000000000000000000000000000000
    val_hex = "0x8000000000000000000000000000000000000000000000000000000000000000"
    res = client.post(
        "/api/stage2/batch-transfer",
        json={"receivers": ["0xReceiverA", "0xReceiverB"], "value_hex": val_hex},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["success"] is True
    assert data["flag"] == FLAGS["stage2"]
    assert state.stage2_solved is True


def test_stage2_safemath_defense(client):
    # Enable SafeMath
    client.post("/api/stage2/toggle-safemath")
    assert state.stage2_safemath_enabled is True

    val_hex = "0x8000000000000000000000000000000000000000000000000000000000000000"
    res = client.post(
        "/api/stage2/batch-transfer",
        json={"receivers": ["0xReceiverA", "0xReceiverB"], "value_hex": val_hex},
    )
    assert res.status_code == 400
    assert "arithmetic overflow" in res.json()["detail"]


def test_stage3_tx_origin_phishing_vulnerable(client):
    assert state.contract_owner == state.admin_address
    res = client.post(
        "/api/stage3/phishing-attack",
        json={"phishing_contract_deployed": True, "lured_admin_click": True},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["success"] is True
    assert data["new_owner"] == state.attacker_address
    assert data["flag"] == FLAGS["stage3"]
    assert state.stage3_solved is True


def test_stage3_msg_sender_defense(client):
    # Enable msg.sender check
    client.post("/api/stage3/toggle-defense")
    assert state.stage3_check_msgsender is True

    res = client.post(
        "/api/stage3/phishing-attack",
        json={"phishing_contract_deployed": True, "lured_admin_click": True},
    )
    assert res.status_code == 403
    assert "msg.sender is not contract owner" in res.json()["detail"]


def test_stage4_flashloan_oracle_vulnerable(client):
    res = client.post(
        "/api/stage4/flashloan-attack",
        json={"borrow_eth": 400.0, "swap_direction": "eth_to_token", "exploit_oracle": True},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["success"] is True
    assert data["profit_tokens"] > 0
    assert data["flag"] == FLAGS["stage4"]
    assert state.stage4_solved is True


def test_stage4_twap_defense(client):
    # Enable TWAP
    client.post("/api/stage4/toggle-twap")
    assert state.stage4_oracle_twap_enabled is True

    res = client.post(
        "/api/stage4/flashloan-attack",
        json={"borrow_eth": 400.0, "swap_direction": "eth_to_token", "exploit_oracle": True},
    )
    assert res.status_code == 400
    assert "TWAP" in res.json()["detail"]


def test_terminal_commands(client):
    for cmd in ["help", "ls", "solc --version", "forge test", "cast balance 0xVault", "status", "cat ReentrancyVault.sol"]:
        res = client.post("/api/terminal", json={"command": cmd})
        assert res.status_code == 200
        assert "output" in res.json()
        assert len(res.json()["output"]) > 0


def test_flag_submission_lifecycle(client):
    # Invalid flag
    res = client.post("/api/submit-flag", json={"flag": "FLAG{invalid_test}"})
    assert res.status_code == 200
    assert res.json()["success"] is False

    # Valid flags
    for stage_key in ["stage1", "stage2", "stage3", "stage4"]:
        res = client.post("/api/submit-flag", json={"flag": FLAGS[stage_key]})
        assert res.status_code == 200
        assert res.json()["success"] is True
        assert res.json()["stage"] == stage_key

    assert len(state.solved_stages) == 4
