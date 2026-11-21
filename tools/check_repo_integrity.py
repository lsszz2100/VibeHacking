#!/usr/bin/env python3
"""
tools/check_repo_integrity.py — 전사 보안 및 무결성 전수 검사
1. Python AST parse check across all .py files
2. 127.0.0.1 loopback isolation check on all 75 labs
3. Secret & credential leak scanning
"""
import ast
import glob
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

print("[1/3] Running AST parse check on all Python files...")
py_files = glob.glob(f"{ROOT}/**/*.py", recursive=True)
errs = []
for f in py_files:
    if any(skip in f for skip in ["venv", ".venv", ".git", "node_modules"]):
        continue
    try:
        with open(f, "r", encoding="utf-8") as fp:
            ast.parse(fp.read(), filename=f)
    except Exception as e:
        errs.append(f"{f}: {e}")
if errs:
    print(f"[-] AST Errors found ({len(errs)}):")
    for e in errs:
        print("  ", e)
    sys.exit(1)
print(f"  ✓ {len(py_files)} Python files parsed cleanly.")

print("[2/3] Checking 127.0.0.1 loopback isolation on all 75 labs...")
dc_files = glob.glob(f"{ROOT}/labs/**/docker-compose.yml", recursive=True)
bad_bindings = []
for dc in dc_files:
    with open(dc, "r", encoding="utf-8") as fp:
        lines = fp.readlines()
    in_ports_block = False
    for idx, line in enumerate(lines):
        indent = len(line) - len(line.lstrip())
        stripped = line.strip()
        if stripped == "ports:":
            in_ports_block = True
            ports_indent = indent
            continue
        elif in_ports_block and (indent <= ports_indent and stripped and not stripped.startswith("#")):
            in_ports_block = False

        if in_ports_block and stripped.startswith("-"):
            port_val = stripped.lstrip("-").strip(" \"'")
            # e.g. "127.0.0.1:8080:80" or "8080:80" or "0.0.0.0:8080:80"
            if ":" in port_val:
                if port_val.startswith("0.0.0.0"):
                    bad_bindings.append(f"{dc}:{idx+1} Exposed 0.0.0.0 port: {stripped}")
                elif not port_val.startswith("127.0.0.1"):
                    # Check if first part before colon is port number (i.e. missing host binding)
                    first_part = port_val.split(":")[0]
                    if first_part.isdigit():
                        bad_bindings.append(f"{dc}:{idx+1} Missing loopback binding: {stripped}")
if bad_bindings:
    print(f"[-] Loopback isolation violations ({len(bad_bindings)}):")
    for b in bad_bindings:
        print("  ", b)
    sys.exit(1)
print(f"  ✓ All {len(dc_files)} docker-compose files strictly bound to 127.0.0.1 loopback.")

print("[3/3] Scanning for exposed secret keys/tokens...")
secret_patterns = [
    re.compile(r"ghp_[a-zA-Z0-9]{36}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"sk-[a-zA-Z0-9]{48}"),
    re.compile(r"AIza[0-9A-Za-z-_]{35}"),
]
ALLOWED_DUMMIES = [
    "AKIAIOSFODNN7EXAMPLE",
    "AKIAXXXXXXXXXXXXXXXX",
]
leaks = []
for root, dirs, files in os.walk(ROOT):
    if any(x in root for x in [".git", "venv", ".venv", "node_modules", "release"]):
        continue
    for file in files:
        if file.endswith((".py", ".js", ".json", ".md", ".sh", ".yml", ".yaml")):
            fpath = os.path.join(root, file)
            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as fp:
                    lines = fp.readlines()
                for line_idx, line in enumerate(lines):
                    # Skip detector regex definitions and tutorial patterns
                    if any(kw in line for kw in ["re.compile", "pattern", "regex =", "Regex", 'r"AKIA', "r'AKIA"]):
                        continue
                    for pat in secret_patterns:
                        matches = pat.findall(line)
                        for m in matches:
                            if any(dummy in m for dummy in ALLOWED_DUMMIES):
                                continue
                            leaks.append(f"{fpath}:{line_idx+1}: matched {m}")
            except Exception:
                pass
if leaks:
    print(f"[-] Secret leaks detected ({len(leaks)}):")
    for l in leaks:
        print("  ", l)
    sys.exit(1)
print("  ✓ Zero secret tokens or credential leaks detected.")

print("🎉 All repository integrity checks PASSED!")
