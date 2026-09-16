#!/usr/bin/env python3
"""Tests for Lab 01 (Web Hacking Lab - SQLi Target)."""

import importlib.util
import os
import sys
import tempfile
import pytest

pytest.importorskip("flask")

_db_file = os.path.join(tempfile.gettempdir(), "test_web_users.db")
os.environ["DB_PATH"] = _db_file

_app_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "sqlmap-target", "app.py"))
_spec = importlib.util.spec_from_file_location("web_lab_app", _app_path)
_mod = importlib.util.module_from_spec(_spec)
sys.modules["web_lab_app"] = _mod
_spec.loader.exec_module(_mod)

app = _mod.app
_mod.init_db()


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


def test_index_page(client):
    res = client.get("/")
    assert res.status_code == 200
    assert "취약한 사용자 검색" in res.data.decode("utf-8")


def test_search_normal(client):
    res = client.get("/search?id=1")
    assert res.status_code == 200
    data = res.get_json()
    assert isinstance(data, list)
    assert len(data) == 1
    assert data[0]["username"] == "admin"


def test_search_sqli_or_bypass(client):
    res = client.get("/search?id=1 OR 1=1")
    assert res.status_code == 200
    data = res.get_json()
    assert isinstance(data, list)
    assert len(data) >= 4


def test_login_sqli_bypass(client):
    res = client.post("/login", data={"username": "admin' --", "password": "any"})
    assert res.status_code == 200
    data = res.get_json()
    assert data["status"] == "success"
    assert data["user"] == "admin"
    assert data["role"] == "admin"
