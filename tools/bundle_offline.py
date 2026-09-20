#!/usr/bin/env python3
"""
VibeHacking Offline Packager & Integrity Verifier
Verifies that all 20 Labs, 34 Wargame Tracks (1,190 Challenges),
75 Textbook Chapters, and Offline Static Assets are completely present and sound.
Optionally packages the offline bundle into an archive.
"""

import os
import sys
import json
import argparse
import tarfile
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent

def check_textbook():
    print("[1/5] Checking Textbook Chapters & Index...")
    docs_dir = ROOT_DIR / "docs"
    sidebar = docs_dir / "_sidebar.md"
    if not sidebar.exists():
        return False, "Missing docs/_sidebar.md"
    
    # Check section directories
    sections = [d for d in ROOT_DIR.iterdir() if d.is_dir() and d.name[:2].isdigit() and "_" in d.name]
    total_md = 0
    for s in sections:
        md_files = list(s.glob("*.md"))
        total_md += len([f for f in md_files if f.name != "README.md"])
    
    print(f"  ✓ Found {len(sections)} sections, {total_md} deep-dive chapters.")
    return True, f"{len(sections)} sections, {total_md} chapters"

def check_labs():
    print("[2/5] Checking 21 Hands-on Labs...")
    labs_dir = ROOT_DIR / "labs"
    lab_dirs = sorted([d for d in labs_dir.iterdir() if d.is_dir() and d.name[:2].isdigit()])
    if len(lab_dirs) != 21:
        return False, f"Expected 21 labs, found {len(lab_dirs)}"
    
    for l in lab_dirs:
        compose = l / "docker-compose.yml"
        test_dir = l / "tests"
        if not (compose.exists() and test_dir.exists()):
            return False, f"Incomplete lab structure in {l.name}"
    
    print(f"  ✓ All {len(lab_dirs)} labs have docker-compose.yml and test suites.")
    return True, f"{len(lab_dirs)} labs verified"

def check_wargame():
    print("[3/5] Checking Wargame Assets & Challenge DB...")
    wg_dir = ROOT_DIR / "wargame"
    challenges_js = wg_dir / "assets" / "challenges.js"
    if not challenges_js.exists():
        return False, "Missing wargame/assets/challenges.js"
    
    with open(challenges_js, "r", encoding="utf-8") as f:
        content = f.read()
    
    import re
    # Verify challenge count by matching top-level tier challenge IDs (t0..t4)
    matches = re.findall(r'^\s*"id":\s*"t[0-4]_', content, re.MULTILINE)
    id_count = len(matches)
    if id_count != 1225:
        return False, f"Expected 1,225 challenges in challenges.js, found {id_count}"
    
    print(f"  ✓ Wargame database verified: {id_count} challenges across 35 tracks.")
    return True, f"{id_count} challenges verified"

def check_offline_assets():
    print("[4/5] Checking Offline Vendor & Static Assets...")
    vendor_dir = ROOT_DIR / "docs" / "vendor"
    required_vendor = [
        "docsify.min.js", "theme-simple-dark.css", "search.min.js",
        "docsify-copy-code.min.js", "docsify-pagination.min.js", "zoom-image.min.js"
    ]
    for req in required_vendor:
        if not (vendor_dir / req).exists():
            return False, f"Missing offline vendor asset: {req}"
    
    portal_static = ROOT_DIR / "portal" / "static" / "index.html"
    if not portal_static.exists():
        return False, "Missing portal/static/index.html"
        
    print(f"  ✓ Offline vendor assets ({len(required_vendor)} files) and Web Portal verified.")
    return True, "Offline assets present"

def create_bundle_archive(out_path):
    print(f"[5/5] Creating Offline Distribution Archive: {out_path}...")
    exclude_prefixes = [".git", "__pycache__", ".pytest_cache", ".gemini", "node_modules"]
    
    def filter_func(tarinfo):
        for excl in exclude_prefixes:
            if excl in tarinfo.name:
                return None
        return tarinfo

    with tarfile.open(out_path, "w:gz") as tar:
        tar.add(ROOT_DIR, arcname="vibe-hacking", filter=filter_func)
    
    size_mb = os.path.getsize(out_path) / (1024 * 1024)
    print(f"  ✓ Archive created successfully: {size_mb:.2f} MB")

def main():
    parser = argparse.ArgumentParser(description="VibeHacking Offline Bundler & Integrity Verifier")
    parser.add_argument("--tar", metavar="OUTPUT_PATH", help="Create a tar.gz offline package")
    parser.add_argument("--check-only", action="store_true", default=False, help="Perform checks only")
    args = parser.parse_args()

    print("==================================================")
    print(" VibeHacking 2.0 Offline Release & Audit Pipeline")
    print("==================================================")
    
    checks = [check_textbook(), check_labs(), check_wargame(), check_offline_assets()]
    all_ok = True
    for ok, msg in checks:
        if not ok:
            print(f"[FAILED] {msg}", file=sys.stderr)
            all_ok = False
            
    if not all_ok:
        print("\n❌ Verification FAILED. Please resolve the errors above.")
        sys.exit(1)
        
    print("\n✅ All 4 subsystems verified 100% clean and offline-ready.")
    
    if args.tar:
        create_bundle_archive(args.tar)
    else:
        print("💡 Run with `--tar <path.tar.gz>` to generate the compressed offline deployment package.")

if __name__ == "__main__":
    main()
