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
    assert "scoreCanvas" in res.text


def test_get_challenges(client):
    res = client.get("/api/ctf/challenges")
    assert res.status_code == 200
    data = res.json()
    assert "challenges" in data
    assert len(data["challenges"]) >= 22
    ids = [c["id"] for c in data["challenges"]]
    assert "LAB01_SQLI" in ids
    assert "LAB19_ROOT" in ids
    assert "LAB20_SEH" in ids
    assert "LAB21_CAN" in ids
    assert "LAB21_UDS" in ids


def test_timeline_endpoint(client):
    res = client.get("/api/ctf/timeline")
    assert res.status_code == 200
    data = res.json()
    assert "timeline" in data
    assert "teams" in data
    assert len(data["timeline"]) >= 2


def test_sse_stream_handshake(client):
    # Test once=True so it sends handshake and closes without blocking
    res = client.get("/api/ctf/stream?once=true")
    assert res.status_code == 200
    assert "text/event-stream" in res.headers["content-type"]
    assert "handshake" in res.text


def test_register_and_submit_flag_with_first_blood_and_timeline(client):
    team_alpha = "Alpha_Sec_V2"
    team_beta = "Beta_Sec_V2"

    # Register teams
    client.post("/api/ctf/register", json={"team_name": team_alpha})
    client.post("/api/ctf/register", json={"team_name": team_beta})

    # Wrong flag submission
    sub_fail = client.post("/api/ctf/submit", json={
        "team_name": team_alpha,
        "chal_id": "LAB21_CAN",
        "flag": "FLAG{wrong_flag}",
    })
    assert sub_fail.status_code == 200
    assert sub_fail.json()["status"] == "wrong_flag"

    # First Blood submission by Alpha_Sec_V2
    sub_alpha = client.post("/api/ctf/submit", json={
        "team_name": team_alpha,
        "chal_id": "LAB21_CAN",
        "flag": "FLAG{can_bus_arbitration_speed_spoof_8821}",
    })
    assert sub_alpha.status_code == 200
    d_alpha = sub_alpha.json()
    assert d_alpha["status"] == "correct"
    assert d_alpha["first_blood"] is True
    assert d_alpha["first_blood_bonus"] == 50
    assert d_alpha["points_awarded"] == 550  # 500 base + 50 FB bonus

    # Second submission by Beta_Sec_V2 (Dynamic score decayed, no First Blood)
    sub_beta = client.post("/api/ctf/submit", json={
        "team_name": team_beta,
        "chal_id": "LAB21_CAN",
        "flag": "FLAG{can_bus_arbitration_speed_spoof_8821}",
    })
    assert sub_beta.status_code == 200
    d_beta = sub_beta.json()
    assert d_beta["status"] == "correct"
    assert d_beta["first_blood"] is False
    assert d_beta["first_blood_bonus"] == 0
    assert d_beta["points_awarded"] == 425  # 500 * 0.85 = 425

    # Check team profile endpoint
    prof_res = client.get(f"/api/ctf/team/{team_alpha}")
    assert prof_res.status_code == 200
    prof = prof_res.json()
    assert prof["score"] >= 550
    assert any(s["chal_id"] == "LAB21_CAN" and s["first_blood"] is True for s in prof["solves"])

    # Timeline has events recorded
    time_res = client.get("/api/ctf/timeline")
    assert time_res.status_code == 200
    t_events = time_res.json()["timeline"]
    assert any(ev["team"] == team_alpha and ev["chal_id"] == "LAB21_CAN" for ev in t_events)
