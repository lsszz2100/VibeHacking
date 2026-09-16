#!/usr/bin/env python3
"""Tests for Lab 04 (Cloud & Container Security Lab - IMDS Simulator)."""

import importlib.util
import os
import sys
import pytest

_app_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "metadata-server", "app.py"))
_spec = importlib.util.spec_from_file_location("metadata_server_mod", _app_path)
_mod = importlib.util.module_from_spec(_spec)
sys.modules["metadata_server_mod"] = _mod
_spec.loader.exec_module(_mod)

app = _mod.app


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


def test_imds_root(client):
    res = client.get("/latest/meta-data/")
    assert res.status_code == 200
    assert "iam/" in res.data.decode("utf-8")


def test_imds_instance_id(client):
    res = client.get("/latest/meta-data/instance-id")
    assert res.status_code == 200
    assert _mod.INSTANCE_ID in res.data.decode("utf-8")


def test_imds_iam_role_list(client):
    res = client.get("/latest/meta-data/iam/security-credentials/")
    assert res.status_code == 200
    assert _mod.ROLE_NAME in res.data.decode("utf-8")


def test_imds_iam_credentials_exfil(client):
    res = client.get(f"/latest/meta-data/iam/security-credentials/{_mod.ROLE_NAME}")
    assert res.status_code == 200
    data = res.get_json()
    assert data["AccessKeyId"] == _mod.ACCESS_KEY
    assert data["SecretAccessKey"] == _mod.SECRET_KEY
    assert "FLAG" in str(data) or "FAKEKEY" in str(data)
