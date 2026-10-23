#!/usr/bin/env python3
"""
Unit and regression tests for Lab 48: FirmwareGuard
"""

import sys
import importlib.util
from pathlib import Path
import pytest
from starlette.testclient import TestClient

APP_PATH = Path(__file__).resolve().parent.parent / "app" / "main.py"
spec = importlib.util.spec_from_file_location("lab48_app", str(APP_PATH))
lab48_module = importlib.util.module_from_spec(spec)
sys.modules["lab48_app"] = lab48_module
spec.loader.exec_module(lab48_module)

app = lab48_module.app
state = lab48_module.state
STAGE1_FLAG = lab48_module.STAGE1_FLAG
STAGE2_FLAG = lab48_module.STAGE2_FLAG
STAGE3_FLAG = lab48_module.STAGE3_FLAG
STAGE4_FLAG = lab48_module.STAGE4_FLAG

client = TestClient(app)

@pytest.fixture(autouse=True)
def reset_lab():
    client.post("/api/reset")
    yield
    client.post("/api/reset")

def test_status():
    res = client.get("/status")
    assert res.status_code == 200
    data = res.json()
    assert data["lab"] == "48_firmware_iot_rce_lab"
    assert data["port"] == 8048

def test_stage1_unpack():
    res = client.post("/api/stage1/unpack_firmware", json={
        "firmware_image": "router_firmware_v2.bin",
        "extract_flag": "-Me"
    })
    assert res.status_code == 200
    data = res.json()
    assert data["success"] is True
    assert data["flag"] == STAGE1_FLAG

def test_stage2_nvram_preload():
    res = client.post("/api/stage2/preload_nvram", json={
        "preload_library": "/lib/libnvram.so",
        "architecture": "mips",
        "default_config": "http_port=8080"
    })
    assert res.status_code == 200
    data = res.json()
    assert data["success"] is True
    assert data["flag"] == STAGE2_FLAG

def test_stage3_cgi_rce():
    # Benign target fails
    res = client.post("/api/stage3/execute_cgi", json={
        "cgi_script": "/cgi-bin/ping.cgi",
        "target_host": "8.8.8.8"
    })
    assert res.json()["success"] is False

    # Command injection succeeds
    res2 = client.post("/api/stage3/execute_cgi", json={
        "cgi_script": "/cgi-bin/ping.cgi",
        "target_host": "127.0.0.1;cat /etc/passwd"
    })
    assert res2.status_code == 200
    data = res2.json()
    assert data["success"] is True
    assert "root:x:0:0" in data["rce_output"]
    assert data["flag"] == STAGE3_FLAG

def test_stage4_secure_boot():
    res = client.post("/api/stage4/harden_secure_boot", json={
        "enable_dm_verity": True,
        "disable_jtag_uart_pins": True,
        "enforce_uboot_rsa_verify": True
    })
    assert res.status_code == 200
    data = res.json()
    assert data["success"] is True
    assert data["flag"] == STAGE4_FLAG
