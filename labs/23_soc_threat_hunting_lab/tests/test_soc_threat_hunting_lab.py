#!/usr/bin/env python3
"""Tests for Lab 23: SOC Threat Hunting & SIEM/Incident Response Lab (SOCHunter)."""

import importlib.util
import os
import sys
import pytest
from starlette.testclient import TestClient

_app_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "app", "main.py"))
_spec = importlib.util.spec_from_file_location("soc_threat_hunting_lab_main", _app_path)
_mod = importlib.util.module_from_spec(_spec)
sys.modules["soc_threat_hunting_lab_main"] = _mod
_spec.loader.exec_module(_mod)

app = _mod.app


@pytest.fixture
def client():
    return TestClient(app)


def test_status_endpoint(client):
    res = client.get("/api/status")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "ready"
    assert "SOCHunter" in data["lab"]
    assert len(data["missions"]) == 3
    assert data["port"] == 8023


def test_dashboard_served(client):
    res = client.get("/")
    assert res.status_code == 200
    assert "text/html" in res.headers["content-type"]
    assert "SOCHunter" in res.text
    assert "Mission 1: Sysmon" in res.text


def test_telemetry_endpoints(client):
    res1 = client.get("/api/v1/telemetry/sysmon")
    assert res1.status_code == 200
    assert len(res1.json()) >= 4

    res2 = client.get("/api/v1/telemetry/network")
    assert res2.status_code == 200
    assert len(res2.json()) >= 3

    res3 = client.get("/api/v1/telemetry/winevent")
    assert res3.status_code == 200
    assert len(res3.json()) >= 3


def test_hunting_query_engine(client):
    # Query for powershell in sysmon
    res = client.post("/api/v1/hunting/query", json={"query": "powershell", "source": "sysmon"})
    assert res.status_code == 200
    d = res.json()
    assert d["status"] == "success"
    assert d["total_hits"] >= 2
    assert any("powershell.exe" in str(r) for r in d["results"])

    # Query for C2 IP across all
    res2 = client.post("/api/v1/hunting/query", json={"query": "198.51.100.88", "source": "all"})
    assert res2.status_code == 200
    assert res2.json()["total_hits"] >= 3


def test_mission1_contain_process(client):
    # Wrong PID
    err_res = client.post("/api/v1/hunting/contain_process", json={"process_id": 1234})
    assert err_res.status_code == 400

    # Correct target PID (spoolsv.exe PID 4892)
    ok_res = client.post("/api/v1/hunting/contain_process", json={"process_id": 4892})
    assert ok_res.status_code == 200
    d = ok_res.json()
    assert d["status"] == "success"
    assert "FLAG{sysmon_parent_pid_spoofing_remote_thread_injected_3821}" in d["flag"]


def test_mission2_block_c2_ip(client):
    # Wrong IP
    err_res = client.post("/api/v1/firewall/block_ip", json={"ip": "10.0.0.1"})
    assert err_res.status_code == 400

    # Correct C2 IP
    ok_res = client.post("/api/v1/firewall/block_ip", json={"ip": "198.51.100.88"})
    assert ok_res.status_code == 200
    d = ok_res.json()
    assert d["status"] == "success"
    assert "FLAG{suricata_dns_tunnel_ja3_c2_beacon_correlated_9482}" in d["flag"]


def test_mission3_soar_endpoint_isolation(client):
    # Wrong user or host
    err_res = client.post("/api/v1/soar/isolate_endpoint", json={"hostname": "DC01", "compromised_user": "admin"})
    assert err_res.status_code == 400

    # Correct host and user
    ok_res = client.post(
        "/api/v1/soar/isolate_endpoint",
        json={"hostname": "WKSTN-FIN-04", "compromised_user": "FIN_ADMIN"},
    )
    assert ok_res.status_code == 200
    d = ok_res.json()
    assert d["status"] == "success"
    assert d["action"] == "SOAR Automated Incident Remediation Playbook Triggered"
    assert "FLAG{siem_lsass_mimikatz_pass_the_hash_soar_contained_7129}" in d["flag"]
