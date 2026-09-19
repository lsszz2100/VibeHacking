#!/usr/bin/env python3
"""Tests for VibeHacking CTF Competition & Scoreboard Engine."""

import sys
from pathlib import Path
REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import pytest
from starlette.testclient import TestClient
from ctf.server import app, state


@pytest.fixture
def client():
    return TestClient(app)


def test_ctf_home(client):
    res = client.get("/")
    assert res.status_code == 200
    assert "text/html" in res.headers["content-type"]
    assert "CTF Arena" in res.text


def test_get_challenges(client):
    res = client.get("/api/ctf/challenges")
    assert res.status_code == 200
    data = res.json()
    assert "challenges" in data
    assert len(data["challenges"]) >= 6
    ids = [c["id"] for c in data["challenges"]]
    assert "LAB19_ROOT" in ids
    assert "LAB20_SEH" in ids


def test_register_and_submit_flag(client):
    team_name = "TestTeam_Apex"
    reg_res = client.post("/api/ctf/register", json={"team_name": team_name})
    assert reg_res.status_code == 200
    assert reg_res.json()["status"] in ["registered", "exists"]

    # Wrong flag submission
    sub_fail = client.post("/api/ctf/submit", json={
        "team_name": team_name,
        "chal_id": "LAB19_ROOT",
        "flag": "FLAG{wrong_flag}",
    })
    assert sub_fail.status_code == 200
    assert sub_fail.json()["status"] == "wrong_flag"

    # Correct flag submission
    sub_ok = client.post("/api/ctf/submit", json={
        "team_name": team_name,
        "chal_id": "LAB19_ROOT",
        "flag": "FLAG{dr01d_r00t_byp4ss_succ3ss_9281}",
    })
    assert sub_ok.status_code == 200
    data = sub_ok.json()
    assert data["status"] == "correct"
    assert data["points_awarded"] > 0

    # Scoreboard update check
    board_res = client.get("/api/ctf/scoreboard")
    assert board_res.status_code == 200
    bdata = board_res.json()
    teams = [item["team"] for item in bdata["scoreboard"]]
    assert team_name in teams
