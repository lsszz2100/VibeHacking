#!/usr/bin/env python3
"""
Unit tests for Lab 34: OsintHunterLab — Automated Internet Attack Surface Reconnaissance & Leaked Secret Extraction
Tests target listing, Shodan queries, database dumps, Git history reconstruction, and reset.
"""

import sys
import importlib.util
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

# Dynamic import to avoid collision with other labs' app packages
APP_PATH = Path(__file__).resolve().parent.parent / "app" / "main.py"
spec = importlib.util.spec_from_file_location("lab34_app", str(APP_PATH))
lab34_module = importlib.util.module_from_spec(spec)
sys.modules["lab34_app"] = lab34_module
spec.loader.exec_module(lab34_module)

app = lab34_module.app
reset_lab = lab34_module.reset_lab

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
    assert data["lab"] == "34_osint_surface_recon_lab"
    assert data["port"] == 8034
    assert data["step1_completed"] is False

def test_index_html(client):
    res = client.get("/")
    assert res.status_code == 200
    assert "text/html" in res.headers["content-type"]
    assert "Lab 34: OSINT Surface Recon" in res.text
    assert "8034" in res.text

def test_get_targets(client):
    res = client.get("/api/osint/targets")
    assert res.status_code == 200
    data = res.json()
    assert "Megacorp" in data["organization"]
    assert "198.51.100.0/24" in data["allocated_cidrs"]
    assert "AS64512" in data["known_asns"]

def test_get_status(client):
    res = client.get("/api/osint/status")
    assert res.status_code == 200
    data = res.json()
    assert data["step1_completed"] is False
    assert data["step2_completed"] is False
    assert data["step3_completed"] is False

def test_shodan_scan_miss(client):
    res = client.post("/api/osint/scan/shodan", json={"query": "random_unknown_nonexistent"})
    assert res.status_code == 200
    data = res.json()
    assert data["total_results"] == 0
    assert "flag" not in data

def test_shodan_scan_hit(client):
    res = client.post("/api/osint/scan/shodan", json={"query": "org:'Megacorp' port:6379,9200"})
    assert res.status_code == 200
    data = res.json()
    assert data["total_results"] == 3
    assert data["flag"] == "FLAG{OSINT_SHODAN_EXPOSED_SERVICES_RECON_7712}"
    assert any(h["port"] == 6379 for h in data["results"])
    assert any(h["port"] == 9200 for h in data["results"])

def test_database_leak_invalid_target(client):
    res = client.post("/api/osint/leak/database", json={"target": "invalid_host_10.0.0.1", "command": "KEYS *"})
    assert res.status_code == 400
    assert "Unknown target" in res.json()["detail"]

def test_database_leak_redis(client):
    res = client.post("/api/osint/leak/database", json={"target": "198.51.100.42:6379", "command": "KEYS *"})
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "success"
    assert data["flag"] == "FLAG{OSINT_ELASTIC_REDIS_UNAUTH_DUMP_PWNED_8823}"
    assert data["data"]["service"] == "Redis"
    assert len(data["data"]["keys_extracted"]) >= 3

def test_database_leak_elastic(client):
    res = client.post("/api/osint/leak/database", json={"target": "198.51.100.43:9200", "command": "/_search"})
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "success"
    assert data["flag"] == "FLAG{OSINT_ELASTIC_REDIS_UNAUTH_DUMP_PWNED_8823}"
    assert data["data"]["service"] == "Elasticsearch"
    assert data["data"]["records_carved"] > 1000

def test_git_reconstruct_invalid_target(client):
    res = client.post("/api/osint/git/reconstruct", json={"target": "unknown", "action": "log"})
    assert res.status_code == 400
    assert "Unknown target" in res.json()["detail"]

def test_git_reconstruct_success(client):
    res = client.post("/api/osint/git/reconstruct", json={"target": "198.51.100.44:80/.git", "action": "log"})
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "success"
    assert data["flag"] == "FLAG{OSINT_GIT_LEAKED_SECRET_RECONSTRUCTED_9934}"
    assert data["recovered_secrets"]["AWS_ACCESS_KEY_ID"] == "AKIAIOSFODNN7EXAMPLE"
    assert data["recovered_commits"] == 2

def test_reset_lab(client):
    # Complete step 1
    client.post("/api/osint/scan/shodan", json={"query": "megacorp"})
    st = client.get("/api/osint/status").json()
    assert st["step1_completed"] is True
    
    # Reset
    res = client.post("/api/osint/reset")
    assert res.status_code == 200
    st2 = client.get("/api/osint/status").json()
    assert st2["step1_completed"] is False
