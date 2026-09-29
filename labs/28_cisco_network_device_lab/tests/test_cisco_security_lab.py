"""Unit tests for Lab 28: NetShield - Cisco & Network Device Security Lab."""

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
    spec = importlib.util.spec_from_file_location("lab28_app", str(APP_PATH))
    module = importlib.util.module_from_spec(spec)
    sys.modules["lab28_app"] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def client(app_module):
    # Reset state before each test
    client_instance = TestClient(app_module.app)
    client_instance.post("/api/cisco/reset")
    return client_instance


def test_health_check(client):
    res = client.get("/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "ok"
    assert data["port"] == 8028
    assert "NetShield" in data["lab"]


def test_index_view(client):
    res = client.get("/")
    assert res.status_code == 200
    assert "NETSHIELD" in res.text
    assert "8028" in res.text
    assert "Catalyst 3850" in res.text


def test_switch_status(client):
    res = client.get("/api/cisco/status")
    assert res.status_code == 200
    data = res.json()
    assert data["hostname"] == "SW-CORE-CATALYST-3850"
    assert data["snmp_version"] == "v2c"
    assert len(data["vlans"]) == 4
    assert "GigabitEthernet1/0/1" in data["ports"]


def test_type7_crypto_helpers(app_module):
    test_str = "SuperSecretP@ss2026"
    encrypted = app_module.encrypt_cisco_type7(test_str, start_idx=4)
    decrypted = app_module.decrypt_cisco_type7(encrypted)
    assert decrypted == test_str


def test_step1_snmp_auth_failure(client):
    res = client.post("/api/cisco/snmp/bruteforce", json={
        "target_ip": "192.168.100.1",
        "community_string": "invalid_wrong_string",
    })
    assert res.status_code == 401
    data = res.json()
    assert data["status"] == "auth_failure"


def test_step1_snmp_readonly(client):
    res = client.post("/api/cisco/snmp/bruteforce", json={
        "target_ip": "192.168.100.1",
        "community_string": "public",
    })
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "readonly_success"
    assert "sysDescr" in data["message"]
    assert "flag" not in data


def test_step1_snmp_readwrite_success(client, app_module):
    res = client.post("/api/cisco/snmp/bruteforce", json={
        "target_ip": "192.168.100.1",
        "community_string": "private",
    })
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "rw_success"
    assert data["flag"] == app_module.FLAGS["step1"]
    assert data["decrypted_enable_secret"] == "cisco123!pwn"
    assert "enable secret 7" in data["running_config"]


def test_step2_dtp_trunk_spoof_success(client):
    res = client.post("/api/cisco/vlan/dtp-attack", json={
        "interface": "GigabitEthernet1/0/1",
        "attack_type": "dtp_trunk_spoof",
        "target_vlan": 100,
    })
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "dtp_pwned"
    assert "802.1Q Trunk" in data["negotiated_mode"]
    assert 100 in data["vlan_hopping_access"]


def test_step2_stp_root_hijack_success(client, app_module):
    # First negotiate trunk
    client.post("/api/cisco/vlan/dtp-attack", json={
        "interface": "GigabitEthernet1/0/1",
        "attack_type": "dtp_trunk_spoof",
    })
    # Then hijack root bridge with priority 0
    res = client.post("/api/cisco/vlan/dtp-attack", json={
        "interface": "GigabitEthernet1/0/1",
        "attack_type": "stp_root_hijack",
        "bpdu_priority": 0,
    })
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "stp_pwned"
    assert data["flag"] == app_module.FLAGS["step2"]
    assert data["root_priority"] == 0
    assert data["mitm_active"] is True


def test_step2_stp_root_hijack_high_priority_ignored(client):
    res = client.post("/api/cisco/vlan/dtp-attack", json={
        "interface": "GigabitEthernet1/0/1",
        "attack_type": "stp_root_hijack",
        "bpdu_priority": 32768,
    })
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "stp_ignored"


def test_step3_hardening_partial(client):
    res = client.post("/api/cisco/defense/hardening", json={
        "disable_dtp": True,
        "enable_port_security": False,
        "enable_dhcp_snooping": True,
        "enable_dai": False,
        "enable_bpduguard": False,
        "enable_snmpv3": False,
        "enable_copp": False,
    })
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "partial_hardening"
    assert "flag" not in data


def test_step3_hardening_full_success(client, app_module):
    res = client.post("/api/cisco/defense/hardening", json={
        "disable_dtp": True,
        "enable_port_security": True,
        "enable_dhcp_snooping": True,
        "enable_dai": True,
        "enable_bpduguard": True,
        "enable_snmpv3": True,
        "enable_copp": True,
    })
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "hardened_success"
    assert data["flag"] == app_module.FLAGS["step3"]
    assert len(data["applied_controls"]) == 7


def test_dtp_attack_blocked_after_hardening(client):
    # Apply full hardening
    client.post("/api/cisco/defense/hardening", json={
        "disable_dtp": True,
        "enable_port_security": True,
        "enable_dhcp_snooping": True,
        "enable_dai": True,
        "enable_bpduguard": True,
        "enable_snmpv3": True,
        "enable_copp": True,
    })
    # Attempt DTP attack
    res = client.post("/api/cisco/vlan/dtp-attack", json={
        "interface": "GigabitEthernet1/0/1",
        "attack_type": "dtp_trunk_spoof",
    })
    assert res.status_code == 403
    assert res.json()["status"] == "blocked"


def test_reset_lab(client):
    res = client.post("/api/cisco/reset")
    assert res.status_code == 200
    assert res.json()["status"] == "reset"
