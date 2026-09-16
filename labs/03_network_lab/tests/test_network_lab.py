#!/usr/bin/env python3
"""Tests for Lab 03 (Network Hacking Lab - DNS & Zone Configuration)."""

import os
import pytest

_lab_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def test_dns_configuration_files():
    conf_path = os.path.join(_lab_dir, "dns", "named.conf")
    assert os.path.exists(conf_path)
    with open(conf_path, "r", encoding="utf-8") as f:
        content = f.read()
    assert "corp.local" in content
    assert "allow-transfer { any; };" in content or "allow-transfer" in content


def test_zone_records_and_secrets():
    zone_path = os.path.join(_lab_dir, "dns", "zones", "corp.local.zone")
    assert os.path.exists(zone_path)
    with open(zone_path, "r", encoding="utf-8") as f:
        content = f.read()
    assert "ns1.corp.local." in content
    assert "admin_password=" in content
    assert "Sup3rS3cr3t!" in content
