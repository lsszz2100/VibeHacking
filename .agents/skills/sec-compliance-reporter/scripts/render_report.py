#!/usr/bin/env python3
"""
Security Compliance Report CLI Wrapper
======================================
Generates enterprise-grade security compliance and diagnostic reports
mapped to KISA ISMS-P, NIST CSF 2.0, OWASP Top 10, and CVSS 3.1.
Wraps tools/report_generator.py with pre-configured templates and styles.
"""

import sys
import os
import subprocess
import argparse
from pathlib import Path

def find_repo_root():
    curr = Path(__file__).resolve().parent
    for _ in range(6):
        if (curr / "tools" / "report_generator.py").exists():
            return curr
        curr = curr.parent
    raise FileNotFoundError("Could not find repository root containing tools/report_generator.py")

def main():
    parser = argparse.ArgumentParser(description="VibeHacking Compliance & Diagnostic Report Generator")
    parser.add_argument("--format", "-f", choices=["md", "html", "json", "csv"], default="md",
                        help="Output format (default: md)")
    parser.add_argument("--output", "-o", default=None,
                        help="Output file path (default: reports/compliance_report_<timestamp>.<ext>)")
    parser.add_argument("--severity", "-s", nargs="+", choices=["Critical", "High", "Medium", "Low"],
                        help="Filter by severity levels")
    parser.add_argument("--lab-id", "-l", nargs="+",
                        help="Filter by specific lab IDs (e.g. 01 05 55)")
    parser.add_argument("--live", action="store_true",
                        help="Probe running docker containers for active attack surfaces")
    parser.add_argument("--summary", action="store_true",
                        help="Output summary statistics only")
    args = parser.parse_args()

    repo_root = find_repo_root()
    gen_script = repo_root / "tools" / "report_generator.py"
    
    cmd = [sys.executable, str(gen_script), "--format", args.format]
    
    if args.summary:
        cmd.append("--summary")
    if args.live:
        cmd.append("--live")
    if args.severity:
        cmd.extend(["--severity"] + args.severity)
    if args.lab_id:
        cmd.extend(["--lab-id"] + args.lab_id)
        
    if args.output:
        out_path = Path(args.output).resolve()
        out_path.parent.mkdir(parents=True, exist_ok=True)
        cmd.extend(["--output", str(out_path)])
    elif not args.summary:
        # Default output directory
        reports_dir = repo_root / "reports"
        reports_dir.mkdir(parents=True, exist_ok=True)
        from datetime import datetime
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_path = reports_dir / f"compliance_report_{ts}.{args.format}"
        cmd.extend(["--output", str(out_path)])

    print(f"[*] Running command: {' '.join(cmd)}")
    result = subprocess.run(cmd, cwd=str(repo_root))
    
    if result.returncode == 0:
        if not args.summary and ('out_path' in locals()):
            print("\n==================================================")
            print("  [SUCCESS] Enterprise Compliance Report Generated")
            print("==================================================")
            print(f"  Path: {out_path}")
            print("==================================================")
    else:
        print(f"[-] Report generation failed with exit code {result.returncode}", file=sys.stderr)
        sys.exit(result.returncode)

if __name__ == "__main__":
    main()
