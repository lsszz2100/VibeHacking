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
    assert data["total_labs"] == 20


def test_list_labs(client):
    res = client.get("/api/labs")
    assert res.status_code == 200
    data = res.json()
    assert data["total"] == 20
    assert len(data["labs"]) == 20
    # Check Lab 19 and 20 presence
    ids = [l["id"] for l in data["labs"]]
    assert "19" in ids
    assert "20" in ids
