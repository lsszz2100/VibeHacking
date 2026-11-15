import os
import sys
import importlib.util
import time
import pytest
from fastapi.testclient import TestClient

_app_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "app", "main.py"))
_spec = importlib.util.spec_from_file_location("lab_61_main", _app_path)
_mod = importlib.util.module_from_spec(_spec)
sys.modules["lab_61_main"] = _mod
_spec.loader.exec_module(_mod)

app = _mod.app
client = TestClient(app)

def test_status():
    res = client.get("/api/status")
    assert res.status_code == 200
    data = res.json()
    assert data["lab_id"] == 61
    assert data["port"] == 8061
    assert data["trust_domain"] == "vibe.corp"
    assert len(data["stages"]) == 4

def test_stage1_envoy_wasm_bypass_vulnerable():
    res = client.post("/api/stage1/envoy-wasm-bypass", json={
        "proxy_header": "X-Authenticated-User: admin",
        "client_cert_san": "spiffe://attacker.corp/ns/default/sa/rogue",
        "mtls_verified": False,
        "use_wasm_mtls_shield": False
    })
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "vulnerable"
    assert data["breached"] is True
    assert data["compromised_role"] == "admin"

def test_stage1_envoy_wasm_bypass_defended():
    # Valid defense
    res = client.post("/api/stage1/envoy-wasm-bypass", json={
        "proxy_header": "X-Authenticated-User: admin",
        "client_cert_san": "spiffe://vibe.corp/ns/prod/sa/payment-service",
        "mtls_verified": True,
        "use_wasm_mtls_shield": True
    })
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "defended"
    assert "FLAG{ENVOY_WASM_MTLS_SAN_VERIFIED_7491}" in data["flag"]

    # Blocked due to untrusted SAN
    res_blocked = client.post("/api/stage1/envoy-wasm-bypass", json={
        "proxy_header": "X-Authenticated-User: admin",
        "client_cert_san": "spiffe://untrusted.corp/ns/prod/sa/payment-service",
        "mtls_verified": True,
        "use_wasm_mtls_shield": True
    })
    assert res_blocked.status_code == 200
    assert res_blocked.json()["status"] == "blocked"

def test_stage2_spiffe_svid_forgery_vulnerable():
    res = client.post("/api/stage2/spiffe-svid-forgery", json={
        "spiffe_id": "spiffe://attacker.corp/ns/evil/sa/exploit",
        "workload_token": "forged_malicious_token_12345",
        "use_spire_attestation": False
    })
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "vulnerable"
    assert data["breached"] is True

def test_stage2_spiffe_svid_forgery_defended():
    # Defended with valid attested token
    res = client.post("/api/stage2/spiffe-svid-forgery", json={
        "spiffe_id": "spiffe://vibe.corp/ns/prod/sa/payment-service",
        "workload_token": "valid_attested_jwt_token_spire_credentials_99",
        "use_spire_attestation": True
    })
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "defended"
    assert "FLAG{SPIFFE_SPIRE_SVID_WORKLOAD_ATTESTED_8302}" in data["flag"]

    # Blocked with forged token
    res_fail = client.post("/api/stage2/spiffe-svid-forgery", json={
        "spiffe_id": "spiffe://vibe.corp/ns/prod/sa/payment-service",
        "workload_token": "forged_token_evil",
        "use_spire_attestation": True
    })
    assert res_fail.status_code == 200
    assert res_fail.json()["status"] == "blocked"

def test_stage3_dpop_replay_defense():
    now = time.time()
    jti = f"test_jti_nonce_{int(now * 1000)}"

    # First attempt with valid DPoP proof
    res = client.post("/api/stage3/dpop-replay-attack", json={
        "access_token": "valid_bearer_token_string_12345",
        "dpop_proof": {
            "jti": jti,
            "htm": "POST",
            "htu": "/api/v1/transfer",
            "iat": now
        },
        "http_method": "POST",
        "http_uri": "/api/v1/transfer",
        "use_dpop_enforcement": True
    })
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "defended"
    assert "FLAG{DPOP_RFC9449_PROOF_OF_POSSESSION_BOUND_9154}" in data["flag"]

    # Replay attempt with same jti
    res_replay = client.post("/api/stage3/dpop-replay-attack", json={
        "access_token": "valid_bearer_token_string_12345",
        "dpop_proof": {
            "jti": jti,
            "htm": "POST",
            "htu": "/api/v1/transfer",
            "iat": now
        },
        "http_method": "POST",
        "http_uri": "/api/v1/transfer",
        "use_dpop_enforcement": True
    })
    assert res_replay.status_code == 200
    assert res_replay.json()["status"] == "blocked"
    assert "replay detected" in res_replay.json()["message"]

def test_stage4_graphql_ast_bomb_defense():
    nested_bomb = "{ user { orders { items { product { supplier { warehouse { manager { phone } } } } } } } }"
    
    # Vulnerable mode
    res_vuln = client.post("/api/stage4/graphql-ast-bomb", json={
        "query": nested_bomb,
        "client_spiffe_id": "spiffe://vibe.corp/ns/prod/sa/frontend",
        "use_ast_complexity_limiter": False
    })
    assert res_vuln.status_code == 200
    assert res_vuln.json()["status"] == "vulnerable"
    assert res_vuln.json()["breached"] is True

    # Defended mode - Blocked bomb
    res_blocked = client.post("/api/stage4/graphql-ast-bomb", json={
        "query": nested_bomb,
        "client_spiffe_id": "spiffe://vibe.corp/ns/prod/sa/frontend",
        "use_ast_complexity_limiter": True
    })
    assert res_blocked.status_code == 200
    assert res_blocked.json()["status"] == "blocked"

    # Defended mode - Approved safe query
    safe_query = "{ user { id name email } }"
    res_safe = client.post("/api/stage4/graphql-ast-bomb", json={
        "query": safe_query,
        "client_spiffe_id": "spiffe://vibe.corp/ns/prod/sa/frontend",
        "use_ast_complexity_limiter": True
    })
    assert res_safe.status_code == 200
    assert res_safe.json()["status"] == "defended"
    assert "FLAG{GRAPHQL_AST_DEPTH_COMPLEXITY_CONTAINED_6283}" in res_safe.json()["flag"]
