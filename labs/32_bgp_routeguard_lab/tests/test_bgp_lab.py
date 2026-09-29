#!/usr/bin/env python3
"""
Unit tests for Lab 32: BGPRouteGuard — BGP Routing Hijacking & RPKI ROA Lab
Tests exact prefix hijack, subprefix LPM hijack, AS-path leaks, RPKI validation, and hardening.
"""

import sys
import importlib.util
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

# Dynamic import to avoid collision with other labs' app packages
APP_PATH = Path(__file__).resolve().parent.parent / "app" / "main.py"
spec = importlib.util.spec_from_file_location("lab32_app", str(APP_PATH))
lab32_module = importlib.util.module_from_spec(spec)
sys.modules["lab32_app"] = lab32_module
spec.loader.exec_module(lab32_module)

app = lab32_module.app
validate_rpki = lab32_module.validate_rpki
reset_bgp = lab32_module.reset_bgp

@pytest.fixture(autouse=True)
def run_reset():
    """Ensure each test runs with a fresh default topology baseline."""
    reset_bgp()
    yield
    reset_bgp()

@pytest.fixture
def client():
    return TestClient(app)

def test_health(client):
    res = client.get("/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "healthy"
    assert data["lab"] == "Lab 32 — BGPRouteGuard"
    assert data["local_asn"] == 65001
    assert data["hardened"] is False

def test_index_html(client):
    res = client.get("/")
    assert res.status_code == 200
    assert "text/html" in res.headers["content-type"]
    assert "BGPRouteGuard" in res.text
    assert "AS 65001" in res.text

def test_get_bgp_info(client):
    res = client.get("/api/bgp/info")
    assert res.status_code == 200
    data = res.json()
    assert data["local_asn"] == 65001
    assert "64512" in data["peers"]
    assert "64599" in data["peers"]
    assert len(data["roa_database"]) >= 2

def test_get_routes_initial(client):
    res = client.get("/api/bgp/routes")
    assert res.status_code == 200
    data = res.json()
    assert "rib" in data
    assert "fib" in data
    prefixes = [r["prefix"] for r in data["fib"]]
    assert "198.51.100.0/24" in prefixes
    assert "203.0.113.0/24" in prefixes

def test_rpki_validator_valid():
    # Authorized prefix & matching origin ASN
    assert validate_rpki("198.51.100.0/24", 65001) == "VALID"
    assert validate_rpki("203.0.113.0/24", 65001) == "VALID"

def test_rpki_validator_invalid_asn():
    # Authorized prefix but wrong origin ASN (hijack)
    assert validate_rpki("198.51.100.0/24", 64599) == "INVALID"
    assert validate_rpki("203.0.113.0/24", 12345) == "INVALID"

def test_rpki_validator_invalid_length():
    # Sub-prefix exceeds max_length 24
    assert validate_rpki("198.51.100.0/25", 65001) == "INVALID"
    assert validate_rpki("198.51.100.128/26", 65001) == "INVALID"

def test_rpki_validator_not_found():
    # Arbitrary unallocated prefix
    assert validate_rpki("198.18.0.0/15", 65001) == "NOT_FOUND"

def test_step1_exact_prefix_hijack_success(client):
    payload = {
        "prefix": "198.51.100.0/24",
        "origin_asn": 64599,
        "as_path": [64599],
        "local_pref": 200
    }
    res = client.post("/api/bgp/exploit/prefix-hijack", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "HIJACK_SUCCESSFUL"
    assert "FLAG{BGP_EXACT_PREFIX_HIJACK_4401}" == data["flag"]
    assert data["diverted_to_asn"] == 64599

def test_step1_exact_prefix_hijack_updates_fib(client):
    payload = {
        "prefix": "198.51.100.0/24",
        "origin_asn": 64599,
        "as_path": [64599],
        "local_pref": 200
    }
    client.post("/api/bgp/exploit/prefix-hijack", json=payload)
    res = client.get("/api/bgp/routes")
    fib = res.json()["fib"]
    # Best route for 198.51.100.0/24 should now point to attacker next-hop
    active_route = next(r for r in fib if r["prefix"] == "198.51.100.0/24")
    assert active_route["next_hop"] == "192.0.2.99"
    assert active_route["origin_asn"] == 64599

def test_step2_subprefix_hijack_success(client):
    payload = {
        "subprefix": "198.51.100.0/25",
        "origin_asn": 64599,
        "as_path": [64599, 64512]
    }
    res = client.post("/api/bgp/exploit/subprefix-hijack", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "SUBPREFIX_HIJACK_SUCCESSFUL"
    assert "FLAG{BGP_SUBPREFIX_LPM_HIJACK_5512}" == data["flag"]
    assert "Longest Prefix Match" in data["lpm_advantage"]

def test_step2_subprefix_hijack_lpm_active(client):
    payload = {
        "subprefix": "198.51.100.0/25",
        "origin_asn": 64599,
        "as_path": [64599, 64512]
    }
    client.post("/api/bgp/exploit/subprefix-hijack", json=payload)
    res = client.get("/api/bgp/routes")
    fib = res.json()["fib"]
    sub_route = next((r for r in fib if r["prefix"] == "198.51.100.0/25"), None)
    assert sub_route is not None
    assert sub_route["is_fib_active"] is True
    assert sub_route["next_hop"] == "192.0.2.99"

def test_step3_as_path_leak_success(client):
    payload = {
        "prefix": "198.51.100.0/24",
        "spoofed_as_path": [64599, 65001],
        "leak_type": "transit_to_peer",
        "origin_asn": 65001
    }
    res = client.post("/api/bgp/exploit/as-path-leak", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "ROUTE_LEAK_SUCCESSFUL"
    assert "FLAG{BGP_ASPATH_LEAK_INTERCEPTION_6623}" == data["flag"]
    assert "AS 64599" in data["interception_node"]

def test_step3_as_path_leak_rib_active(client):
    payload = {
        "prefix": "198.51.100.0/24",
        "spoofed_as_path": [64599, 65001],
        "leak_type": "transit_to_peer",
        "origin_asn": 65001
    }
    client.post("/api/bgp/exploit/as-path-leak", json=payload)
    res = client.get("/api/bgp/routes")
    fib = res.json()["fib"]
    leaked_route = next(r for r in fib if r["prefix"] == "198.51.100.0/24")
    assert leaked_route["as_path"] == [64599, 65001]

def test_harden_bgp(client):
    # Perform attacks first
    client.post("/api/bgp/exploit/prefix-hijack", json={"prefix": "198.51.100.0/24", "origin_asn": 64599})
    client.post("/api/bgp/exploit/subprefix-hijack", json={"subprefix": "198.51.100.0/25", "origin_asn": 64599})

    # Harden
    res = client.post("/api/bgp/harden", json={
        "rpki_validation": True,
        "max_prefix_limit": True,
        "peer_filters": True,
        "otc_enforcement": True
    })
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "HARDENED"
    assert data["dropped_malicious_routes"] >= 2

    # FIB must now be restored to legitimate origin
    res_routes = client.get("/api/bgp/routes")
    fib = res_routes.json()["fib"]
    legit_route = next(r for r in fib if r["prefix"] == "198.51.100.0/24")
    assert legit_route["next_hop"] == "198.51.100.1"
    assert legit_route["origin_asn"] == 65001

def test_step1_blocked_after_harden(client):
    client.post("/api/bgp/harden", json={
        "rpki_validation": True,
        "max_prefix_limit": True,
        "peer_filters": True,
        "otc_enforcement": True
    })
    res = client.post("/api/bgp/exploit/prefix-hijack", json={"prefix": "198.51.100.0/24", "origin_asn": 64599})
    assert res.status_code == 403
    assert "RPKI ROA Validation" in res.json()["detail"]["error"]

def test_step2_blocked_after_harden(client):
    client.post("/api/bgp/harden", json={
        "rpki_validation": True,
        "max_prefix_limit": True,
        "peer_filters": True,
        "otc_enforcement": True
    })
    res = client.post("/api/bgp/exploit/subprefix-hijack", json={"subprefix": "198.51.100.0/25", "origin_asn": 64599})
    assert res.status_code == 403
    assert "RPKI MaxLength Validation" in res.json()["detail"]["error"]

def test_step3_blocked_after_harden(client):
    client.post("/api/bgp/harden", json={
        "rpki_validation": True,
        "max_prefix_limit": True,
        "peer_filters": True,
        "otc_enforcement": True
    })
    res = client.post("/api/bgp/exploit/as-path-leak", json={"prefix": "198.51.100.0/24", "spoofed_as_path": [64599, 65001]})
    assert res.status_code == 403
    assert "Route Leak Blocked" in res.json()["detail"]["error"]

def test_reset_bgp(client):
    client.post("/api/bgp/harden", json={"rpki_validation": True})
    res = client.post("/api/bgp/reset")
    assert res.status_code == 200
    assert res.json()["status"] == "RESET"

    info = client.get("/api/bgp/info").json()
    assert info["security_controls"]["hardened"] is False
    assert info["security_controls"]["rpki_validation_enabled"] is False

def test_step1_succeeds_again_after_reset(client):
    client.post("/api/bgp/harden", json={"rpki_validation": True})
    client.post("/api/bgp/reset")
    res = client.post("/api/bgp/exploit/prefix-hijack", json={"prefix": "198.51.100.0/24", "origin_asn": 64599})
    assert res.status_code == 200
    assert "FLAG{BGP_EXACT_PREFIX_HIJACK_4401}" in res.json()["flag"]
