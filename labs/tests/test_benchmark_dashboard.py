"""
Unit and integration tests for VibeHacking unified telemetry dashboard (vhack dashboard/status)
and hands-on labs performance benchmark engine (vhack benchmark).
"""

import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent


class TestVhackDashboardCLI:
    """vhack dashboard / status / stats 명령어 검증 테스트 스위트"""

    def test_dashboard_text_output(self):
        cmd = [sys.executable, str(REPO_ROOT / "vhack.py"), "dashboard"]
        proc = subprocess.run(cmd, capture_output=True, text=True, cwd=str(REPO_ROOT))
        assert proc.returncode == 0
        assert "VIBEHACKING UNIFIED TELEMETRY DASHBOARD" in proc.stdout
        assert "시스템 텔레메트리" in proc.stdout
        assert "52개 랩" in proc.stdout
        assert "2,240개 문제" in proc.stdout
        assert "490" in proc.stdout
        assert "20대 웹 콘솔 시뮬레이터" in proc.stdout

    def test_dashboard_json_output(self):
        cmd = [sys.executable, str(REPO_ROOT / "vhack.py"), "dashboard", "--json"]
        proc = subprocess.run(cmd, capture_output=True, text=True, cwd=str(REPO_ROOT))
        assert proc.returncode == 0
        data = json.loads(proc.stdout)
        assert data["version"] == "2.6.0"
        assert "system" in data
        assert "os" in data["system"]
        assert "memory" in data["system"]
        assert "disk" in data["system"]
        assert data["labs"]["total"] == 52
        assert data["wargame"]["total_tracks"] == 64
        assert data["wargame"]["total_challenges"] == 2240
        assert data["knowledge_base"]["sections"] == 75
        assert data["knowledge_base"]["chapters"] == 490
        assert data["knowledge_base"]["simulators"] == 20

    def test_dashboard_aliases(self):
        # test 'status' alias
        cmd_status = [sys.executable, str(REPO_ROOT / "vhack.py"), "status", "--json"]
        proc1 = subprocess.run(cmd_status, capture_output=True, text=True, cwd=str(REPO_ROOT))
        assert proc1.returncode == 0
        data1 = json.loads(proc1.stdout)
        assert data1["version"] == "2.6.0"

        # test 'stats' alias
        cmd_stats = [sys.executable, str(REPO_ROOT / "vhack.py"), "stats", "--json"]
        proc2 = subprocess.run(cmd_stats, capture_output=True, text=True, cwd=str(REPO_ROOT))
        assert proc2.returncode == 0
        data2 = json.loads(proc2.stdout)
        assert data2["labs"]["total"] == 52


class TestVhackBenchmarkCLI:
    """vhack benchmark 명령어 검증 테스트 스위트"""

    def test_benchmark_mock_selected_labs(self):
        cmd = [
            sys.executable,
            str(REPO_ROOT / "vhack.py"),
            "benchmark",
            "--dry-run",
            "--lab-id", "01", "16", "52"
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True, cwd=str(REPO_ROOT))
        assert proc.returncode == 0
        assert "VibeHacking Hands-on Labs Performance Benchmark" in proc.stdout
        assert "01" in proc.stdout
        assert "16" in proc.stdout
        assert "52" in proc.stdout
        assert "OPTIMAL" in proc.stdout or "ACCEPT" in proc.stdout

    def test_benchmark_mock_all_json(self):
        cmd = [
            sys.executable,
            str(REPO_ROOT / "vhack.py"),
            "benchmark",
            "--all",
            "--dry-run",
            "--json"
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True, cwd=str(REPO_ROOT))
        assert proc.returncode == 0
        data = json.loads(proc.stdout)
        assert data["mode"] == "mock"
        assert data["total_labs"] == 52
        assert len(data["results"]) == 52
        assert data["throughput_labs_per_sec"] > 0
        assert "avg_latency_ms" in data
        assert "p95_latency_ms" in data

    def test_benchmark_save_output_file(self, tmp_path):
        out_file = tmp_path / "benchmark_test.json"
        cmd = [
            sys.executable,
            str(REPO_ROOT / "vhack.py"),
            "benchmark",
            "--dry-run",
            "--lab-id", "50", "51", "52",
            "-o", str(out_file)
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True, cwd=str(REPO_ROOT))
        assert proc.returncode == 0
        assert out_file.exists()
        saved = json.loads(out_file.read_text(encoding="utf-8"))
        assert saved["total_labs"] == 3
        assert [r["lab_id"] for r in saved["results"]] == ["50", "51", "52"]

    def test_benchmark_invalid_lab_warning(self):
        cmd = [
            sys.executable,
            str(REPO_ROOT / "vhack.py"),
            "benchmark",
            "--dry-run",
            "--lab-id", "999", "01"
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True, cwd=str(REPO_ROOT))
        assert proc.returncode == 0
        assert "999" in proc.stderr
        assert "01" in proc.stdout
