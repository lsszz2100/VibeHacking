#!/usr/bin/env python3
"""Tests for VibeHacking Unified Web Portal API."""

import sys
from pathlib import Path
REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import pytest
from starlette.testclient import TestClient
from portal.server import app


@pytest.fixture
def client():
    return TestClient(app)


def test_portal_home(client):
    res = client.get("/")
    assert res.status_code == 200
    assert "text/html" in res.headers["content-type"]
    assert "VibeHacking" in res.text or "VIBEHACKING" in res.text


def test_system_status(client):
    res = client.get("/api/system/status")
    assert res.status_code == 200
    data = res.json()
    assert "cpu_usage_percent" in data
    assert "total_labs" in data
    assert data["total_labs"] == 25


def test_list_labs(client):
    res = client.get("/api/labs")
    assert res.status_code == 200
    data = res.json()
    assert data["total"] == 25
    assert len(data["labs"]) == 25
    # Check Lab 19, 20, 21, 22, 23, 24, and 25 presence
    ids = [l["id"] for l in data["labs"]]
    assert "19" in ids
    assert "20" in ids
    assert "21" in ids
    assert "22" in ids
    assert "23" in ids
    assert "24" in ids
    assert "25" in ids


def test_lab_logs(client):
    res = client.get("/api/labs/01/logs")
    assert res.status_code == 200
    data = res.json()
    assert "logs" in data
    assert "status" in data


def test_lab_exec(client):
    res = client.post("/api/labs/01/exec", json={"command": "echo 'VIBE_PORTAL_TEST'"})
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "success"
    assert "VIBE_PORTAL_TEST" in data["output"]


def test_lab_solve(client):
    res = client.get("/api/labs/19/solve?step=1")
    assert res.status_code == 200
    data = res.json()
    assert data["success"] is True
    assert "Frida" in data["name"]
    assert "FLAG{" in data["output"]


def test_lab_exec_blocked_dangerous_command(client):
    res = client.post("/api/labs/01/exec", json={"command": "rm -rf /"})
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "blocked"
    assert "위험한 시스템 파괴 명령어" in data["output"]


def test_lab_logs_bounded_tail(client):
    res = client.get("/api/labs/01/logs?tail=99999")
    assert res.status_code == 200
    data = res.json()
    assert "logs" in data

