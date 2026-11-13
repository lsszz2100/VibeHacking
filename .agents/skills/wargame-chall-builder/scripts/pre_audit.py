#!/usr/bin/env python3
"""
pre_audit.py — One-click runner for VibeHacking 4-stage wargame audit gates:
1. verify.js (structure, counts, no leaks)
2. leakscan.js (cross-challenge answer leak scan)
3. audit.js --strict (format & topic ambiguity audit)
4. solve-derivable.js (automated puzzle verification engine)
"""

import subprocess
import sys
from pathlib import Path

def find_repo_root() -> Path:
    current = Path(__file__).resolve().parent
    for p in [current] + list(current.parents):
        if (p / "wargame" / "scripts" / "verify.js").exists():
            return p
    return Path.cwd()

REPO_ROOT = find_repo_root()
WG_DIR = REPO_ROOT / "wargame"

CHECKS = [
    ("1. verify.js (Structural & Count Invariants)", ["node", "wargame/scripts/verify.js"]),
    ("2. leakscan.js (Cross-Challenge Leak Scan)", ["node", "wargame/scripts/leakscan.js"]),
    ("3. audit.js --strict (Strict Grader & Ambiguity Audit)", ["node", "wargame/scripts/audit.js", "--strict"]),
    ("4. solve-derivable.js (Automated Solvers)", ["node", "wargame/scripts/solve-derivable.js"]),
]

def run_audits() -> bool:
    print("=" * 70)
    print("🛡️  VIBEHACKING WARGAME PRE-COMMIT AUDIT SUITE")
    print("=" * 70)

    all_passed = True
    for title, cmd in CHECKS:
        print(f"\n▶ Running {title}...")
        proc = subprocess.run(cmd, cwd=str(REPO_ROOT), text=True, capture_output=True)
        if proc.returncode == 0:
            print(f"  ✅ PASS: {title}")
            # Print brief summary from stdout
            lines = [line for line in proc.stdout.splitlines() if line.strip()]
            if lines:
                print(f"     Summary: {lines[-1]}")
        else:
            print(f"  ❌ FAIL: {title} (exit code {proc.returncode})")
            if proc.stdout:
                print("--- stdout ---")
                print(proc.stdout[-1000:])
            if proc.stderr:
                print("--- stderr ---")
                print(proc.stderr[-1000:])
            all_passed = False

    print("\n" + "=" * 70)
    if all_passed:
        print("🎉 ALL 4 AUDIT GATES PASSED! 100% 0-DEFECT COMPLIANT.")
        print("=" * 70)
        return True
    else:
        print("⚠️ AUDIT FAILED! Review violations above before committing.")
        print("=" * 70)
        return False

if __name__ == "__main__":
    success = run_audits()
    sys.exit(0 if success else 1)
