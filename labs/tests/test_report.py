"""
Unit & Integration Tests for VibeHacking Security Diagnostic Report Generator
- CVSS 3.1 Base Score & Vector Calculation Verification
- 45-Lab Vulnerability Catalog Coverage & MITRE ATT&CK Mapping
- Report Rendering (Markdown, HTML, JSON)
- CLI Integration (vhack report summary / generate / list-templates)
"""

import json
import subprocess
import sys
from pathlib import Path

import pytest

from tools.report_generator import (
    CVSS31Calculator,
    LAB_CATALOG,
    SecurityReportGenerator,
)


class TestCVSS31Calculator:
    """NIST SP 800-30 / FIRST CVSS 3.1 명세 준수 테스트"""

    def test_critical_network_rce(self):
        # Unauthenticated remote code execution
        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        res = CVSS31Calculator.calculate(vector)
        assert res["base_score"] == 9.8
        assert res["severity"] == "Critical"
        assert res["scope"] == "Unchanged"

    def test_scope_changed_cloud_escalation(self):
        # Cloud IAM PassRole escalation across trust boundary
        vector = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H"
        res = CVSS31Calculator.calculate(vector)
        assert res["base_score"] == 9.9
        assert res["severity"] == "Critical"
        assert res["scope"] == "Changed"

    def test_medium_local_bypass(self):
        # Local anti-debugging evasion
        vector = "CVSS:3.1/AV:L/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N"
        res = CVSS31Calculator.calculate(vector)
        assert 6.0 <= res["base_score"] <= 6.5
        assert res["severity"] == "Medium"

    def test_roundup_edge_cases(self):
        assert CVSS31Calculator.roundup(4.0) == 4.0
        assert CVSS31Calculator.roundup(4.00001) == 4.1
        assert CVSS31Calculator.roundup(7.12) == 7.2

    def test_zero_impact_scope_changed(self):
        # Scope Changed with Zero Impact (ISS <= 0 boundary guard)
        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:N"
        res = CVSS31Calculator.calculate(vector)
        assert res["base_score"] == 0.0
        assert res["severity"] == "None"
        assert res["scope"] == "Changed"



class TestLabCatalogCoverage:
    """51개 전 실습 랩의 취약점 데이터베이스 완전성 검증"""

    def test_all_51_labs_present(self):
        expected_ids = {str(i).zfill(2) for i in range(1, 52)}
        catalog_ids = set(LAB_CATALOG.keys())
        missing = expected_ids - catalog_ids
        assert not missing, f"Missing labs in report catalog: {missing}"
        assert len(catalog_ids) == 51

    def test_finding_fields_integrity(self):
        for lid, lab in LAB_CATALOG.items():
            assert "title" in lab and lab["title"], f"Lab {lid} missing title"
            assert "category" in lab and lab["category"], f"Lab {lid} missing category"
            findings = lab.get("findings", [])
            assert len(findings) >= 1, f"Lab {lid} must have at least one vulnerability finding"

            for f in findings:
                assert f["vuln_id"].startswith("VIBE-2026-"), f"Invalid vuln_id: {f['vuln_id']}"
                assert f["name"], "Finding name must not be empty"
                assert f["cvss_vector"].startswith("CVSS:3.1/"), f"Invalid vector in {f['vuln_id']}"
                assert f["mitre_id"].startswith("T"), f"Invalid MITRE ID: {f['mitre_id']}"
                assert f["mitre_technique"], "MITRE technique must not be empty"
                assert f["mitre_tactic"], "MITRE tactic must not be empty"
                assert f["impact"], "Impact description must not be empty"
                assert f["remediation"], "Remediation recommendations must not be empty"


class TestReportGeneratorRendering:
    """Markdown, HTML, JSON 다중 포맷 렌더링 검증"""

    def test_full_catalog_summary(self):
        gen = SecurityReportGenerator()
        stats = gen.get_summary_stats()
        assert stats["total_labs"] == 51
        assert stats["total_findings"] >= 45
        assert stats["average_cvss"] >= 7.0
        assert stats["severity_counts"]["Critical"] > 0
        assert stats["severity_counts"]["High"] > 0

    def test_markdown_rendering(self):
        gen = SecurityReportGenerator(selected_labs=["01", "45"])
        md = gen.to_markdown()
        assert "# 🛡️ VibeHacking Enterprise Security Diagnostic" in md
        assert "VIBE-2026-0101" in md
        assert "VIBE-2026-4501" in md
        assert "T1190" in md
        assert "T1557" in md
        assert "CVSS:3.1/" in md
        assert "조치 우선순위 로드맵" in md

    def test_json_rendering(self):
        gen = SecurityReportGenerator(selected_labs=["42", "43", "44"])
        raw_json = gen.to_json()
        data = json.loads(raw_json)
        assert data["metadata"]["total_labs"] == 3
        assert len(data["findings"]) == 3
        vuln_ids = [f["vuln_id"] for f in data["findings"]]
        assert "VIBE-2026-4201" in vuln_ids
        assert "VIBE-2026-4301" in vuln_ids
        assert "VIBE-2026-4401" in vuln_ids

    def test_html_rendering(self):
        gen = SecurityReportGenerator(selected_labs=["45"])
        html = gen.to_html()
        assert "<!DOCTYPE html>" in html
        assert "<html lang=\"ko\">" in html
        assert "PQCShield Hybrid TLS Service" in html
        assert "FIPS 203 ML-KEM-768" in html
        assert "badge high" in html or "badge critical" in html

    def test_html_xss_escaping(self, monkeypatch):
        # Test XSS protection in HTML output
        mock_catalog = {
            "99": {
                "title": "<script>alert('xss-title')</script>",
                "category": "Web Security",
                "findings": [
                    {
                        "vuln_id": "VIBE-2026-9901",
                        "name": "Injection <img src=x onerror=alert(1)>",
                        "component": "<b>VulnerableComponent</b>",
                        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        "mitre_id": "T1190",
                        "mitre_technique": "Exploit Public-Facing Application",
                        "mitre_tactic": "Initial Access",
                        "impact": "Attack impact with <script>",
                        "remediation": "Mitigation steps with <iframe>"
                    }
                ]
            }
        }
        monkeypatch.setattr("tools.report_generator.LAB_CATALOG", mock_catalog)
        gen = SecurityReportGenerator(selected_labs=["99"])
        html = gen.to_html()
        assert "<script>alert('xss-title')</script>" not in html
        assert "&lt;script&gt;alert(" in html
        assert "<img src=x onerror=alert(1)>" not in html
        assert "&lt;img src=x onerror=alert(1)&gt;" in html
        assert "<b>VulnerableComponent</b>" not in html
        assert "&lt;b&gt;VulnerableComponent&lt;/b&gt;" in html

    def test_csv_rendering(self):
        gen = SecurityReportGenerator(selected_labs=["01", "45"])
        csv_data = gen.to_csv()
        assert csv_data.startswith("\ufeff")  # UTF-8 BOM for Excel
        lines = csv_data.strip().splitlines()
        header = lines[0]
        assert "Finding_ID" in header
        assert "Vulnerability_Name" in header
        assert "Severity" in header
        assert "CVSS_Score" in header
        assert "KISA_ISMSP" in header
        assert "NIST_CSF_2_0" in header
        assert "OWASP_Top_10" in header
        assert len(lines) >= 3

    def test_compliance_mapping_coverage(self):
        gen = SecurityReportGenerator()
        stats = gen.get_summary_stats()
        assert len(stats["kisa_counts"]) >= 5
        assert len(stats["nist_csf_counts"]) >= 5
        assert len(stats["owasp_counts"]) >= 5
        for f in gen.findings:
            assert f.kisa_id, f"Finding {f.vuln_id} missing kisa_id"
            assert f.kisa_name, f"Finding {f.vuln_id} missing kisa_name"
            assert f.nist_csf_id, f"Finding {f.vuln_id} missing nist_csf_id"
            assert f.nist_csf_name, f"Finding {f.vuln_id} missing nist_csf_name"
            assert f.owasp_id, f"Finding {f.vuln_id} missing owasp_id"
            assert f.owasp_name, f"Finding {f.vuln_id} missing owasp_name"

    def test_severity_filtering(self):
        gen = SecurityReportGenerator(severity_filter=["Critical"])
        assert len(gen.findings) > 0
        for f in gen.findings:
            assert f.severity == "Critical"
        stats = gen.get_summary_stats()
        assert stats["severity_counts"]["High"] == 0
        assert stats["severity_counts"]["Critical"] > 0

    def test_live_mode_detection(self):
        gen = SecurityReportGenerator(selected_labs=["01"], live_status=True)
        assert gen.live_status is True
        for f in gen.findings:
            assert hasattr(f, "live_active")
            assert isinstance(f.live_active, bool)



class TestVhackCLIReportIntegration:
    """vhack report CLI 서브커맨드 실행 테스트"""

    REPO_ROOT = Path(__file__).resolve().parent.parent.parent

    def test_vhack_report_summary_cli(self):
        cmd = [sys.executable, str(self.REPO_ROOT / "vhack.py"), "report", "summary"]
        proc = subprocess.run(cmd, capture_output=True, text=True, cwd=str(self.REPO_ROOT))
        assert proc.returncode == 0
        assert "51개 랩 취약점 진단 요약" in proc.stdout
        assert "Critical" in proc.stdout
        assert "High" in proc.stdout
        assert "KISA ISMS-P" in proc.stdout
        assert "NIST CSF 2.0" in proc.stdout
        assert "OWASP Top 10" in proc.stdout

    def test_vhack_report_list_templates_cli(self):
        cmd = [sys.executable, str(self.REPO_ROOT / "vhack.py"), "report", "list-templates"]
        proc = subprocess.run(cmd, capture_output=True, text=True, cwd=str(self.REPO_ROOT))
        assert proc.returncode == 0
        assert "md" in proc.stdout
        assert "html" in proc.stdout
        assert "json" in proc.stdout

    def test_vhack_report_generate_file_cli(self, tmp_path):
        target_file = tmp_path / "custom_report.json"
        cmd = [
            sys.executable,
            str(self.REPO_ROOT / "vhack.py"),
            "report",
            "generate",
            "--lab-id", "01", "45",
            "--format", "json",
            "-o", str(target_file)
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True, cwd=str(self.REPO_ROOT))
        assert proc.returncode == 0
        assert target_file.exists()
        content = json.loads(target_file.read_text(encoding="utf-8"))
        assert content["metadata"]["total_labs"] == 2

    def test_vhack_report_generate_csv_cli(self, tmp_path):
        target_file = tmp_path / "critical_report.csv"
        cmd = [
            sys.executable,
            str(self.REPO_ROOT / "vhack.py"),
            "report",
            "generate",
            "--severity", "Critical",
            "--format", "csv",
            "-o", str(target_file)
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True, cwd=str(self.REPO_ROOT))
        assert proc.returncode == 0
        assert target_file.exists()
        content = target_file.read_text(encoding="utf-8")
        assert content.startswith("\ufeff")
        assert "Finding_ID" in content
        assert "Critical" in content

