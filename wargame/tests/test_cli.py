#!/usr/bin/env python3
"""Tests for VibeHacking Terminal Native Wargame Client (wargame/cli.py)."""

import os
import sys
import tempfile
import hashlib
from pathlib import Path
import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from wargame.cli import (
    load_wargame_db,
    verify_flag,
    submit_flag_cli,
    search_challenges,
    load_user_progress,
    save_user_progress,
    PROGRESS_FILE
)


def test_load_wargame_db():
    tiers, tracks, challenges = load_wargame_db()
    assert len(tiers) == 5
    assert len(tracks) == 35
    assert len(challenges) == 1225
    assert any(t["id"] == "carcan" for t in tracks)


def test_verify_flag_logic():
    _, _, challenges = load_wargame_db()
    # Test carcan first challenge
    ch = next(c for c in challenges if c["id"] == "t0_carcan_can_bus_arbitration_id")
    
    # Calculate correct flag
    ident = "carcan_can_bus_arbitration_id_v1"
    h20 = hashlib.sha256(ident.encode("utf-8")).hexdigest()[:20]
    correct_flag = f"FLAG{{{h20}}}"

    assert verify_flag(ch, correct_flag) is True
    assert verify_flag(ch, "FLAG{wrong_flag}") is False
    assert verify_flag(ch, "") is False


def test_submit_flag_cli(monkeypatch, tmp_path):
    # Mock progress file
    mock_progress_file = tmp_path / "mock_progress.json"
    import wargame.cli
    monkeypatch.setattr(wargame.cli, "PROGRESS_FILE", mock_progress_file)

    # 1. Non-existent challenge
    ok, msg = submit_flag_cli("non_existent_chal", "FLAG{xyz}")
    assert ok is False
    assert "찾을 수 없습니다" in msg

    # 2. Correct submission
    ident = "carcan_can_bus_arbitration_id_v1"
    h20 = hashlib.sha256(ident.encode("utf-8")).hexdigest()[:20]
    correct_flag = f"FLAG{{{h20}}}"

    ok, msg = submit_flag_cli("t0_carcan_can_bus_arbitration_id", correct_flag)
    assert ok is True
    assert "정답입니다" in msg

    # 3. Already solved
    ok2, msg2 = submit_flag_cli("t0_carcan_can_bus_arbitration_id", correct_flag)
    assert ok2 is True
    assert "이미 해결한 문제" in msg2

    # Verify progress written
    prog = load_user_progress()
    assert "t0_carcan_can_bus_arbitration_id" in prog["solved"]
    assert prog["total_score"] > 0


def test_search_challenges(capsys):
    search_challenges("arbitration")
    out = capsys.readouterr().out
    assert "검색 결과" in out
    assert "carcan" in out.lower() or "arbitration" in out.lower()
