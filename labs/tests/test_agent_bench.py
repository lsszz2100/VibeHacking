"""
labs/tests/test_agent_bench.py — Unit Tests for VibeHacking AI Security Agent Benchmark Engine
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
import pytest

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from tools.agent_eval_bench import (
    MODEL_PROFILES,
    AgentBenchmarkEngine,
    load_wargame_challenges,
    run_comparator,
    export_reports,
)
from labs.solvers import SOLVERS


def test_model_profiles_integrity():
    """Verifies all registered model profiles have valid probability and turn metrics."""
    assert "supersec" in MODEL_PROFILES
    assert "sec-expert" in MODEL_PROFILES
    assert "baseline-llm" in MODEL_PROFILES

    for key, p in MODEL_PROFILES.items():
        assert "name" in p
        assert 0.0 <= p["base_pass_rate"] <= 1.0
        assert p["avg_turns"] >= 1.0
        assert 0.0 <= p["exploit_accuracy"] <= 1.0
        assert 0.0 <= p["remediation_accuracy"] <= 1.0


def test_wargame_challenge_loader():
    """Verifies that challenges are loaded with all required schema fields."""
    challenges = load_wargame_challenges()
    assert len(challenges) >= 2520, f"Expected at least 2520 challenges, found {len(challenges)}"
    sample = challenges[0]
    for field in ("id", "tier", "track", "points", "hash"):
        assert field in sample, f"Missing field {field} in challenge sample"


def test_supersec_perfect_pass_at_1():
    """Verifies that SuperSec achieves 100% Pass@1 and exactly 1.0 turns."""
    engine = AgentBenchmarkEngine(model_name="supersec")
    challenges = load_wargame_challenges()[:20]
    res = engine.evaluate_wargame(challenges, samples=20)

    assert res["total_assessed"] == 20
    assert res["passed"] == 20
    assert res["pass_at_1_pct"] == 100.0
    assert res["avg_turns"] == 1.0


def test_agent_performance_distribution():
    """Verifies relative ordering: SuperSec > Sec-Expert > Baseline LLM."""
    engine_super = AgentBenchmarkEngine(model_name="supersec")
    engine_expert = AgentBenchmarkEngine(model_name="sec-expert")
    engine_base = AgentBenchmarkEngine(model_name="baseline-llm")

    challenges = load_wargame_challenges()[:40]
    res_super = engine_super.evaluate_wargame(challenges, samples=40)
    res_expert = engine_expert.evaluate_wargame(challenges, samples=40)
    res_base = engine_base.evaluate_wargame(challenges, samples=40)

    assert res_super["pass_at_1_pct"] >= res_expert["pass_at_1_pct"]
    assert res_expert["pass_at_1_pct"] > res_base["pass_at_1_pct"]
    assert res_super["avg_turns"] <= res_expert["avg_turns"]
    assert res_expert["avg_turns"] < res_base["avg_turns"]


def test_lab_solver_evaluation():
    """Verifies evaluation against hands-on lab solvers."""
    engine = AgentBenchmarkEngine(model_name="supersec")
    res = engine.evaluate_labs(SOLVERS, samples=10)

    assert res["total_labs_assessed"] == 10
    assert res["red_exploit_score"] == 100.0
    assert res["blue_defense_score"] == 100.0
    assert res["compliance_score"] == 100.0
    assert res["avg_turns"] == 1.0


def test_run_comparator_leaderboard():
    """Verifies multi-model comparator ranks SuperSec first."""
    leaderboard = run_comparator(
        model_keys=["supersec", "sec-expert", "baseline-llm"],
        target="all",
        wargame_samples=10,
        lab_samples=5,
    )
    assert len(leaderboard) == 3
    assert leaderboard[0]["model_key"] == "supersec"
    assert leaderboard[0]["composite_score"] == 100.0
    assert leaderboard[-1]["model_key"] == "baseline-llm"


def test_report_export(tmp_path):
    """Verifies that export_reports correctly formats JSON and Markdown files."""
    engine = AgentBenchmarkEngine(model_name="supersec")
    res = engine.run_full_benchmark(target="all", wargame_samples=10, lab_samples=5)

    json_file = tmp_path / "test_eval.json"
    md_file = tmp_path / "test_eval.md"

    export_reports(res, json_file, md_file)

    assert json_file.exists()
    assert md_file.exists()

    with open(json_file, "r", encoding="utf-8") as f:
        data = json.load(f)
    assert data["composite_score"] == 100.0
    assert "wargame" in data
    assert "labs" in data

    md_text = md_file.read_text(encoding="utf-8")
    assert "# 🏆 VibeHacking AI Security Agent Evaluation & Benchmark Report" in md_text
    assert "Executive Leaderboard" in md_text
    assert "SuperSec-Agent" in md_text


def test_cli_vhack_eval_subcommand():
    """Tests vhack CLI bench-agent / eval subcommands with --json and --quiet."""
    res = subprocess.run(
        [sys.executable, str(ROOT_DIR / "vhack.py"), "eval", "--samples", "5", "--json"],
        capture_output=True,
        text=True,
        check=True,
        cwd=str(ROOT_DIR),
    )
    data = json.loads(res.stdout)
    assert "composite_score" in data
    assert data["composite_score"] == 100.0
