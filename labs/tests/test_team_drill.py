"""
labs/tests/test_team_drill.py — 10대 보안 기술팀 공방전 자동 훈련 엔진 단위 테스트
"""

import json
from argparse import Namespace
import pytest

from tools.team_drill_runner import TEAMS, run_drill, run_drill_cli, format_drill_report_terminal


def test_team_registry():
    """10대 보안 기술팀 명세 완비성 검증."""
    expected_teams = [
        "red", "blue", "purple", "white", "yellow",
        "green", "orange", "gold", "re", "antire"
    ]
    assert len(TEAMS) == 10
    for tid in expected_teams:
        assert tid in TEAMS, f"Missing team: {tid}"
        info = TEAMS[tid]
        assert "name" in info and len(info["name"]) > 0
        assert "name_en" in info and len(info["name_en"]) > 0
        assert "mission" in info and len(info["mission"]) > 0
        assert "labs" in info and len(info["labs"]) > 0
        assert "tactics" in info and len(info["tactics"]) > 0
        assert "tools" in info and len(info["tools"]) > 0


def test_team_drill_all():
    """전체 10개 팀 종합 공방전 시뮬레이션 검증."""
    res = run_drill(all_teams=True)
    assert res["status"] == "SUCCESS"
    assert res["total_drills"] >= 50
    assert res["total_attacks_executed"] > 100
    assert res["total_attacks_detected"] == res["total_attacks_executed"]
    assert res["overall_detection_rate"] == 100.0
    assert res["overall_mitigation_rate"] == 100.0
    assert res["overall_composite_score"] == 100.0
    assert len(res["team_breakdown"]) == 10


def test_team_drill_single_team():
    """개별 팀(antire, blue) 전용 드릴 실행 검증."""
    res_antire = run_drill(team_id="antire")
    assert res_antire["status"] == "SUCCESS"
    assert "antire" in res_antire["team_breakdown"]
    assert any(d["lab_id"] == "57" for d in res_antire["drills"])

    res_blue = run_drill(team_id="blue")
    assert res_blue["status"] == "SUCCESS"
    assert "blue" in res_blue["team_breakdown"]
    assert any(d["lab_id"] == "56" for d in res_blue["drills"])


def test_team_drill_single_lab():
    """개별 랩(Lab 57 AntiReversing, Lab 56 eBPF) 지정 드릴 검증."""
    res_57 = run_drill(lab_id="57")
    assert res_57["status"] == "SUCCESS"
    assert len(res_57["drills"]) == 1
    drill_57 = res_57["drills"][0]
    assert drill_57["lab_id"] == "57"
    assert drill_57["detection_rate"] == 100.0
    assert len(drill_57["stages"]) == 4

    res_56 = run_drill(lab_id="56")
    assert res_56["status"] == "SUCCESS"
    assert len(res_56["drills"]) == 1
    drill_56 = res_56["drills"][0]
    assert drill_56["lab_id"] == "56"
    assert drill_56["detection_rate"] == 100.0


def test_team_drill_invalid_team():
    """존재하지 않는 팀 예외 처리 검증."""
    with pytest.raises(ValueError):
        run_drill(team_id="non_existent_team")


def test_team_drill_cli_json(capsys):
    """CLI 핸들러 JSON 출력 검증."""
    args = Namespace(team="antire", lab=None, all=False, json=True, report=False, verbose=False)
    exit_code = run_drill_cli(args)
    assert exit_code == 0
    out = capsys.readouterr().out
    data = json.loads(out)
    assert data["status"] == "SUCCESS"
    assert "team_breakdown" in data


def test_terminal_report_format():
    """터미널 보고서 포맷팅 검증."""
    res = run_drill(team_id="antire")
    rep = format_drill_report_terminal(res)
    assert "VIBEHACKING 10대 보안 기술팀 공방전 자동 훈련 리포트" in rep
    assert "Purple Team 종합 방어 점수" in rep
