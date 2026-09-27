"""Unit tests for Lab 27: WiFiShield - Wireless Penetration & WPA3 Security Lab."""

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
    spec = importlib.util.spec_from_file_location("lab27_app", str(APP_PATH))
    module = importlib.util.module_from_spec(spec)
    sys.modules["lab27_app"] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def client(app_module):
    return TestClient(app_module.app)


def test_health_check(client):
    res = client.get("/health")
    assert res.status_code == 200
    assert res.json()["status"] == "ok"
    assert res.json()["port"] == 8027


def test_index_view(client):
    res = client.get("/")
    assert res.status_code == 200
    assert "WiFiShield" in res.text
    assert "8027" in res.text


def test_step1_pmkid_crack_success(client, app_module):
    """Step 1: 유효한 사전 단어로 PMKID 오프라인 크래킹 성공 및 플래그 획득"""
    res = client.post("/api/wifi/pmkid/crack", json={
        "bssid": app_module.TARGET_AP["bssid"],
        "client_mac": app_module.TARGET_AP["client_mac"],
        "captured_pmkid": app_module.TARGET_PMKID,
        "dictionary_word": "winter2026!corp",
    })
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "cracked"
    assert data["flag"] == app_module.FLAGS["step1"]
    assert data["psk"] == "winter2026!corp"
    assert "22000" in data["hashcat_mode"]


def test_step1_pmkid_crack_mismatch(client, app_module):
    """Step 1: 잘못된 사전 단어 시 불일치 반환 및 플래그 미발급"""
    res = client.post("/api/wifi/pmkid/crack", json={
        "bssid": app_module.TARGET_AP["bssid"],
        "client_mac": app_module.TARGET_AP["client_mac"],
        "captured_pmkid": app_module.TARGET_PMKID,
        "dictionary_word": "wrong_password_1234",
    })
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "mismatch"
    assert "flag" not in data


def test_step2_sae_transition_downgrade_success(client, app_module):
    """Step 2: WPA3 Transition 모드 다운그레이드 공격 성공"""
    res = client.post("/api/wifi/sae/attack", json={
        "target_ssid": app_module.TARGET_AP["ssid"],
        "attack_vector": "transition_downgrade",
        "sae_group": 19,
        "injection_frames": 100,
    })
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "exploited"
    assert data["flag"] == app_module.FLAGS["step2"]
    assert "WPA2" in data["downgrade_target"]


def test_step2_sae_dragonblood_timing_success(client, app_module):
    """Step 2: Dragonblood 타이밍 부채널 측정 성공"""
    res = client.post("/api/wifi/sae/attack", json={
        "target_ssid": app_module.TARGET_AP["ssid"],
        "attack_vector": "dragonblood_timing_leak",
        "sae_group": 19,
        "injection_frames": 80,
    })
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "exploited"
    assert data["flag"] == app_module.FLAGS["step2"]
    assert "CVE-2019-9494" in data["vector"]


def test_step2_sae_insufficient_frames(client, app_module):
    """Step 2: 프레임 수 부족 시 실패"""
    res = client.post("/api/wifi/sae/attack", json={
        "target_ssid": app_module.TARGET_AP["ssid"],
        "attack_vector": "dragonblood_timing_leak",
        "sae_group": 19,
        "injection_frames": 20,
    })
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "insufficient_frames"
    assert "flag" not in data


def test_step3_mfp_defense_success(client, app_module):
    """Step 3: PMF required 설정 및 Rogue AP 격리 시 방어 완료 및 플래그 획득"""
    res = client.post("/api/wifi/defense/mfp", json={
        "enable_pmf": True,
        "pmf_mode": "required",
        "rogue_bssid": app_module.ROGUE_AP["bssid"],
        "isolate_rogue": True,
    })
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "protected"
    assert data["flag"] == app_module.FLAGS["step3"]
    assert data["rogue_isolated"] is True
    assert "802.11w" in data["pmf_policy"]


def test_step3_mfp_defense_optional_mode_rejected(client, app_module):
    """Step 3: PMF mode optional 시 취약점으로 인한 거부"""
    res = client.post("/api/wifi/defense/mfp", json={
        "enable_pmf": True,
        "pmf_mode": "optional",
        "rogue_bssid": app_module.ROGUE_AP["bssid"],
        "isolate_rogue": True,
    })
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "pmf_not_enforced"
    assert "flag" not in data
