#!/usr/bin/env python3
"""Tests for Lab 02 (Binary Exploitation Lab - Sources & Exploit Templates)."""

import ast
import os
import pytest

_lab_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def test_challenge_sources_exist():
    src_dir = os.path.join(_lab_dir, "pwn-server", "src")
    assert os.path.isdir(src_dir)
    expected_sources = [
        "chal01_bof_basic.c",
        "chal02_ret2libc.c",
        "chal03_rop.c",
        "chal04_fmtstr.c",
        "chal05_heap.c",
    ]
    for src in expected_sources:
        path = os.path.join(src_dir, src)
        assert os.path.exists(path), f"Missing {src}"
        assert os.path.getsize(path) > 0


def test_exploit_templates_syntax():
    templates_dir = os.path.join(_lab_dir, "pwntools-client", "exploit_templates")
    assert os.path.isdir(templates_dir)
    expected_templates = [
        "exploit01_bof.py",
        "exploit02_ret2libc.py",
        "exploit03_rop.py",
        "exploit04_fmtstr.py",
        "exploit05_heap.py",
    ]
    for tmpl in expected_templates:
        path = os.path.join(templates_dir, tmpl)
        assert os.path.exists(path), f"Missing {tmpl}"
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
        # Ensure it compiles as valid Python AST
        parsed = ast.parse(content, filename=tmpl)
        assert parsed is not None
