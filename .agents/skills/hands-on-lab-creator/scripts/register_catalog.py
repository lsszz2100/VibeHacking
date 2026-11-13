#!/usr/bin/env python3
"""
register_catalog.py — VibeHacking Lab Catalog Registration & Verification Tool
Validates CVSS 3.1 vector, computes Base Score and Severity, and formats
standard entries for tools/report_generator.py and vhack.py.
"""

import argparse
import json
import math
import sys
from typing import Dict, Any

# CVSS 3.1 Calculator
def calculate_cvss(vector_str: str) -> Dict[str, Any]:
    parts = vector_str.strip().split("/")
    metrics = {}
    for p in parts:
        if ":" in p:
            k, v = p.split(":", 1)
            metrics[k.upper()] = v.upper()

    av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}.get(metrics.get("AV", "N"), 0.85)
    ac = {"L": 0.77, "H": 0.44}.get(metrics.get("AC", "L"), 0.77)
    scope = metrics.get("S", "U")
    if scope == "C":
        pr = {"N": 0.85, "L": 0.68, "H": 0.5}.get(metrics.get("PR", "N"), 0.85)
    else:
        pr = {"N": 0.85, "L": 0.62, "H": 0.27}.get(metrics.get("PR", "N"), 0.85)
    ui = {"N": 0.85, "R": 0.62}.get(metrics.get("UI", "N"), 0.85)

    c = {"N": 0.0, "L": 0.22, "H": 0.56}.get(metrics.get("C", "H"), 0.56)
    i = {"N": 0.0, "L": 0.22, "H": 0.56}.get(metrics.get("I", "H"), 0.56)
    a = {"N": 0.0, "L": 0.22, "H": 0.56}.get(metrics.get("A", "H"), 0.56)

    iss = 1.0 - ((1.0 - c) * (1.0 - i) * (1.0 - a))
    if scope == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)

    exploitability = 8.22 * av * ac * pr * ui

    if impact <= 0:
        base_score = 0.0
    else:
        if scope == "U":
            raw = min(impact + exploitability, 10.0)
        else:
            raw = min(1.08 * (impact + exploitability), 10.0)
        # CVSS 3.1 roundup
        int_val = round(raw * 100000)
        if int_val % 10000 == 0:
            base_score = int_val / 100000.0
        else:
            base_score = math.ceil(int_val / 10000.0) / 10.0

    if base_score >= 9.0:
        sev = "Critical"
    elif base_score >= 7.0:
        sev = "High"
    elif base_score >= 4.0:
        sev = "Medium"
    elif base_score > 0.0:
        sev = "Low"
    else:
        sev = "None"

    return {"base_score": base_score, "severity": sev, "scope": "Changed" if scope == "C" else "Unchanged"}

def format_report_generator_snippet(data: dict) -> str:
    lab_id = data["lab_id"]
    vector = data["cvss_vector"]
    cvss = calculate_cvss(vector)

    compliance_snippet = f'''    "{lab_id}": {{
        "kisa_id": "{data.get('kisa_id', '2.10.1')}",
        "kisa_name": "{data.get('kisa_name', '보안 시스템 운영 및 취약점 방어')}",
        "nist_csf_id": "{data.get('nist_csf_id', 'PR.DS-02')}",
        "nist_csf_name": "{data.get('nist_csf_name', 'Data Protection & System Hardening')}",
        "owasp_id": "{data.get('owasp_id', 'A05:2021')}",
        "owasp_name": "{data.get('owasp_name', 'Security Misconfiguration')}",
    }},'''

    catalog_snippet = f'''    "{lab_id}": {{
        "title": "{lab_id} {data['title_en']}",
        "category": "{data.get('category', 'System & Cloud Security')}",
        "findings": [
            {{
                "vuln_id": "VIBE-2026-{lab_id}01",
                "name": "{data.get('vuln_name', data['title_en'])}",
                "cvss_vector": "{vector}",
                "mitre_id": "{data.get('mitre_id', 'T1190')}",
                "mitre_technique": "{data.get('mitre_technique', 'Exploit Public-Facing Application')}",
                "mitre_tactic": "{data.get('mitre_tactic', 'Initial Access')}",
                "impact": "{data.get('impact', 'Potential host or container security boundary compromise.')}",
                "description": "{data.get('description', 'Vulnerability scenario in lab environment.')}",
                "affected_component": "{data.get('affected_component', f'Container port {8000 + int(lab_id)}')}",
                "remediation": "{data.get('remediation', 'Implement least privilege and defense in depth mitigations.')}"
            }}
        ]
    }},'''

    return f"""# ── [1] COMPLIANCE_MAP snippet (insert into tools/report_generator.py) ──
{compliance_snippet}

# ── [2] LAB_CATALOG snippet (insert into tools/report_generator.py) ──
{catalog_snippet}

# ── [3] CVSS 3.1 Verification ──
Score: {cvss['base_score']} ({cvss['severity']}) | Scope: {cvss['scope']}
"""

def main():
    parser = argparse.ArgumentParser(description="Generate catalog entry and verify CVSS for VibeHacking lab.")
    parser.add_argument("--json-input", help="Path to JSON file with lab metadata")
    parser.add_argument("--vector", help="Test standalone CVSS 3.1 vector calculation")
    args = parser.parse_args()

    if args.vector:
        res = calculate_cvss(args.vector)
        print(f"Vector: {args.vector}")
        print(f"Base Score: {res['base_score']}")
        print(f"Severity: {res['severity']}")
        print(f"Scope: {res['scope']}")
        return

    if args.json_input:
        with open(args.json_input, "r", encoding="utf-8") as f:
            data = json.load(f)
        print(format_report_generator_snippet(data))
        return

    parser.print_help()

if __name__ == "__main__":
    main()
