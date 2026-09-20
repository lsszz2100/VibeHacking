#!/usr/bin/env python3
"""Tests for VibeHacking CTF Competition & Scoreboard Engine."""

import sys
from pathlib import Path
REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import pytest
from starlette.testclient import TestClient
from ctf.server import app, state, compute_dynamic_score


@pytest.fixture
def client():
    return TestClient(app)


def test_dynamic_scoring_algorithm():
    """동적 점수(Dynamic Scoring) 감쇠 및 최저 배점 보장 검증"""
    assert compute_dynamic_score(500, 0) == 500
    assert compute_dynamic_score(500, 1) == 500
    # 2 solves: 500 * 0.85 = 425
    assert compute_dynamic_score(500, 2) == 425
    # 3 solves: 500 * (0.85 ** 2) = 361
    assert compute_dynamic_score(500, 3) == 361
    # 20 solves: 감쇠되더라도 min_points(100) 이하로 떨어지지 않음
    assert compute_dynamic_score(500, 20) == 100


def test_ctf_home(client):
    res = client.get("/")
    assert res.status_code == 200
    assert "text/html" in res.headers["content-type"]
    assert "CTF Arena" in res.text
    assert "First Blood" in res.text


def test_get_challenges(client):
    res = client.get("/api/ctf/challenges")
    assert res.status_code == 200
    data = res.json()
    assert "challenges" in data
    assert len(data["challenges"]) >= 20
    ids = [c["id"] for c in data["challenges"]]
    assert "LAB01_SQLI" in ids
    assert "LAB19_ROOT" in ids
    assert "LAB20_SEH" in ids
    assert "CARCAN_ECU" in ids


def test_register_and_submit_flag_with_first_blood(client):
    team_alpha = "Alpha_Sec"
    team_beta = "Beta_Sec"

    # Register teams
    client.post("/api/ctf/register", json={"team_name": team_alpha})
    client.post("/api/ctf/register", json={"team_name": team_beta})

    # Wrong flag submission
    sub_fail = client.post("/api/ctf/submit", json={
        "team_name": team_alpha,
        "chal_id": "LAB01_SQLI",
        "flag": "FLAG{wrong_flag}",
    })
    assert sub_fail.status_code == 200
    assert sub_fail.json()["status"] == "wrong_flag"

    # First Blood submission by Alpha_Sec
    sub_alpha = client.post("/api/ctf/submit", json={
        "team_name": team_alpha,
        "chal_id": "LAB01_SQLI",
        "flag": "FLAG{sqli_admin_bypass_success_01}",
    })
    assert sub_alpha.status_code == 200
    d_alpha = sub_alpha.json()
    assert d_alpha["status"] == "correct"
    assert d_alpha["first_blood"] is True
    assert d_alpha["first_blood_bonus"] == 50
    assert d_alpha["points_awarded"] == 550  # 500 base + 50 FB bonus

    # Second submission by Beta_Sec (Dynamic score decayed, no First Blood)
    sub_beta = client.post("/api/ctf/submit", json={
        "team_name": team_beta,
        "chal_id": "LAB01_SQLI",
        "flag": "FLAG{sqli_admin_bypass_success_01}",
    })
    assert sub_beta.status_code == 200
    d_beta = sub_beta.json()
    assert d_beta["status"] == "correct"
    assert d_beta["first_blood"] is False
    assert d_beta["first_blood_bonus"] == 0
    assert d_beta["points_awarded"] == 425  # 500 * 0.85 = 425

    # Check first bloods endpoint
    fb_res = client.get("/api/ctf/firstbloods")
    assert fb_res.status_code == 200
    fb_list = fb_res.json()["first_bloods"]
    assert any(fb["chal_id"] == "LAB01_SQLI" and fb["team"] == team_alpha for fb in fb_list)

    # Scoreboard check
    board_res = client.get("/api/ctf/scoreboard")
    assert board_res.status_code == 200
    bdata = board_res.json()
    teams = {item["team"]: item for item in bdata["scoreboard"]}
    assert team_alpha in teams
    assert teams[team_alpha]["first_blood_count"] >= 1
    assert teams[team_alpha]["score"] >= 550
