#!/usr/bin/env python3
"""Tests for Lab 52: C2TunnelGuard — C2 Network Tunneling & Covert Channel Defense Lab."""

import sys
import importlib.util
from pathlib import Path
import pytest
from starlette.testclient import TestClient

APP_PATH = Path(__file__).resolve().parent.parent / "app" / "main.py"
spec = importlib.util.spec_from_file_location("lab52_app", str(APP_PATH))
lab52_module = importlib.util.module_from_spec(spec)
sys.modules["lab52_app"] = lab52_module
spec.loader.exec_module(lab52_module)

app = lab52_module.app
state = lab52_module.state
calculate_shannon_entropy = lab52_module.calculate_shannon_entropy
STAGE1_FLAG = lab52_module.STAGE1_FLAG
STAGE2_FLAG = lab52_module.STAGE2_FLAG
STAGE3_FLAG = lab52_module.STAGE3_FLAG
STAGE4_FLAG = lab52_module.STAGE4_FLAG

client = TestClient(app)


@pytest.fixture(autouse=True)
def reset_lab():
    client.post("/api/reset")
    yield
    client.post("/api/reset")


def test_entropy_helper():
    assert calculate_shannon_entropy("") == 0.0
    assert calculate_shannon_entropy("   ") == 0.0
    assert calculate_shannon_entropy("a") == 0.0
    assert calculate_shannon_entropy("aaaa") == 0.0
    # Higher diversity yields higher entropy
    h = calculate_shannon_entropy("abcdefghijklmnopqrstuvwxyz0123456789")
    assert h > 4.5
    # None or non-string
    assert calculate_shannon_entropy(None) == 0.0  # type: ignore


def test_index_and_status():
    res = client.get("/")
    assert res.status_code == 200
    assert "Lab 52" in res.text

    status_res = client.get("/status")
    assert status_res.status_code == 200
    data = status_res.json()
    assert data["lab"] == "52_c2_tunneling_and_exfiltration_lab"
    assert data["port"] == 8052
    assert data["stages"]["stage1_dns_tunnel_entropy"] is False


def test_stage1_dns_entropy():
    # Invalid record
    res_bad = client.post("/api/stage1/analyze_dns_entropy", json={
        "fqdn_query": "exfil.data.c2.attacker.com",
        "record_type": "INVALID",
        "entropy_threshold": 3.8
    })
    assert res_bad.status_code == 400

    # Insufficient subdomains (< 3 labels)
    res_short = client.post("/api/stage1/analyze_dns_entropy", json={
        "fqdn_query": "attacker.com",
        "record_type": "TXT",
        "entropy_threshold": 3.8
    })
    assert res_short.status_code == 400

    # Low entropy payload
    res_low = client.post("/api/stage1/analyze_dns_entropy", json={
        "fqdn_query": "aaaa.c2.attacker.com",
        "record_type": "TXT",
        "entropy_threshold": 3.8
    })
    assert res_low.status_code == 200
    assert res_low.json()["status"] == "inconclusive"

    # High entropy encoded exfil payload
    res_ok = client.post("/api/stage1/analyze_dns_entropy", json={
        "fqdn_query": "7f8b9c1d2e3a4b5c6d7e8f90a1b2c3d4.tunnel.attacker.com",
        "record_type": "TXT",
        "entropy_threshold": 3.8
    })
    assert res_ok.status_code == 200
    data = res_ok.json()
    assert data["status"] == "success"
    assert STAGE1_FLAG in data["flag"]
    assert state.stage1_completed is True


def test_stage2_block_reverse_socks():
    # Invalid tool
    res_bad = client.post("/api/stage2/block_reverse_socks", json={
        "tunnel_tool": "unknown_tool",
        "remote_host": "198.51.100.42:8443",
        "dynamic_socks_port": 1080,
        "isolation_policy": "EGRESS_FIREWALL_DROP"
    })
    assert res_bad.status_code == 400

    # Disallowed privileged port (< 1024, e.g. 80)
    res_priv = client.post("/api/stage2/block_reverse_socks", json={
        "tunnel_tool": "chisel",
        "remote_host": "198.51.100.42:8443",
        "dynamic_socks_port": 80,
        "isolation_policy": "EGRESS_FIREWALL_DROP"
    })
    assert res_priv.status_code == 400

    # Audited only policy
    res_audit = client.post("/api/stage2/block_reverse_socks", json={
        "tunnel_tool": "chisel",
        "remote_host": "198.51.100.42:8443",
        "dynamic_socks_port": 1080,
        "isolation_policy": "SOCKS_AUTHENTICATION_MANDATE"
    })
    assert res_audit.status_code == 200
    assert res_audit.json()["status"] == "audited_only"

    # Successful blocking
    res_ok = client.post("/api/stage2/block_reverse_socks", json={
        "tunnel_tool": "chisel",
        "remote_host": "198.51.100.42:8443",
        "dynamic_socks_port": 1080,
        "isolation_policy": "EGRESS_FIREWALL_DROP"
    })
    assert res_ok.status_code == 200
    data = res_ok.json()
    assert data["status"] == "success"
    assert STAGE2_FLAG in data["flag"]
    assert state.stage2_completed is True
    assert state.tunnel_isolated is True


def test_stage3_fingerprint_c2_jitter():
    # Invalid framework
    res_bad = client.post("/api/stage3/fingerprint_c2_jitter", json={
        "c2_framework": "invalid_c2",
        "mean_sleep_sec": 30,
        "jitter_percentage": 25,
        "header_watermark": "0xcafe"
    })
    assert res_bad.status_code == 400

    # Out of range sleep duration (< 5)
    res_sleep = client.post("/api/stage3/fingerprint_c2_jitter", json={
        "c2_framework": "cobalt_strike",
        "mean_sleep_sec": 2,
        "jitter_percentage": 25,
        "header_watermark": "0xcafe"
    })
    assert res_sleep.status_code == 400

    # Out of range jitter (< 10)
    res_jitter = client.post("/api/stage3/fingerprint_c2_jitter", json={
        "c2_framework": "cobalt_strike",
        "mean_sleep_sec": 30,
        "jitter_percentage": 5,
        "header_watermark": "0xcafe"
    })
    assert res_jitter.status_code == 400

    # Inconclusive watermark
    res_inc = client.post("/api/stage3/fingerprint_c2_jitter", json={
        "c2_framework": "cobalt_strike",
        "mean_sleep_sec": 30,
        "jitter_percentage": 25,
        "header_watermark": "generic_browser"
    })
    assert res_inc.status_code == 200
    assert res_inc.json()["status"] == "inconclusive"

    # Successful fingerprinting
    res_ok = client.post("/api/stage3/fingerprint_c2_jitter", json={
        "c2_framework": "cobalt_strike",
        "mean_sleep_sec": 30,
        "jitter_percentage": 25,
        "header_watermark": "0xcafe_malleable_http"
    })
    assert res_ok.status_code == 200
    data = res_ok.json()
    assert data["status"] == "success"
    assert STAGE3_FLAG in data["flag"]
    assert state.stage3_completed is True


def test_stage4_enforce_inline_dpi():
    # Invalid engine
    res_bad = client.post("/api/stage4/enforce_inline_dpi", json={
        "sensor_engine": "invalid_engine",
        "rule_signature": "drop tcp any any -> any any (flowbits:set,c2_tunnel; drop;)",
        "flowbits_tag": "c2_tunnel_detected",
        "verdict_action": "INLINE_DROP"
    })
    assert res_bad.status_code == 400

    # Invalid rule (missing flowbits or drop)
    res_bad_rule = client.post("/api/stage4/enforce_inline_dpi", json={
        "sensor_engine": "suricata",
        "rule_signature": "alert tcp any any -> any any (msg:'test');",
        "flowbits_tag": "c2_tunnel_detected",
        "verdict_action": "INLINE_DROP"
    })
    assert res_bad_rule.status_code == 400

    # Invalid verdict
    res_bad_verdict = client.post("/api/stage4/enforce_inline_dpi", json={
        "sensor_engine": "suricata",
        "rule_signature": "drop tcp any any -> any any (flowbits:set,c2_tunnel; drop;)",
        "flowbits_tag": "c2_tunnel_detected",
        "verdict_action": "LOG_ONLY"
    })
    assert res_bad_verdict.status_code == 400

    # Successful DPI enforcement
    rule_str = "drop tcp any any -> any any (msg:'C2 Covert Tunnel Drop'; flowbits:set,c2_tunnel_detected; drop;)"
    res_ok = client.post("/api/stage4/enforce_inline_dpi", json={
        "sensor_engine": "suricata",
        "rule_signature": rule_str,
        "flowbits_tag": "c2_tunnel_detected",
        "verdict_action": "INLINE_DROP"
    })
    assert res_ok.status_code == 200
    data = res_ok.json()
    assert data["status"] == "success"
    assert STAGE4_FLAG in data["flag"]
    assert state.stage4_completed is True

    # Rule deduplication test
    client.post("/api/stage4/enforce_inline_dpi", json={
        "sensor_engine": "suricata",
        "rule_signature": rule_str,
        "flowbits_tag": "c2_tunnel_detected",
        "verdict_action": "INLINE_DROP"
    })
    assert state.active_dpi_rules.count(rule_str) == 1
