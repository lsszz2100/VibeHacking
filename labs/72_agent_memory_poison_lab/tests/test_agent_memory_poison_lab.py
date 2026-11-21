import os
import sys
import importlib.util
from pathlib import Path
import pytest
import hmac
import hashlib
from fastapi.testclient import TestClient

_app_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "app", "main.py"))
_spec = importlib.util.spec_from_file_location("lab_72_main", _app_path)
_mod = importlib.util.module_from_spec(_spec)
sys.modules["lab_72_main"] = _mod
_spec.loader.exec_module(_mod)

app = _mod.app
MEMORY_SHARED_SECRET = _mod.MEMORY_SHARED_SECRET
client = TestClient(app)

def test_health_and_root():
    res = client.get("/api/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "ok"
    assert data["lab_id"] == 72
    assert data["stages"] == 4

    res = client.get("/")
    assert res.status_code == 200
    data = res.json()
    assert data["port"] == 8072
    assert data["status"] == "ready"

def test_stage1_success():
    payload = {
        "sanitization_policy": "strip_prompt_delimiters_and_quarantine",
        "untrusted_tagging_active": True,
        "quarantine_partition_enabled": True,
        "blocked_directive_patterns": ["ROLE: SYSTEM", "EXEC_CMD:"]
    }
    res = client.post("/api/stage1/eval", json=payload)
    assert res.status_code == 200
    assert "FLAG{v222_s1_episodic_context_sanitized_and_quarantined}" == res.json()["flag"]

def test_stage1_failure():
    payload = {
        "sanitization_policy": "permissive_raw_ingestion",
        "untrusted_tagging_active": False,
        "quarantine_partition_enabled": False,
        "blocked_directive_patterns": []
    }
    res = client.post("/api/stage1/eval", json=payload)
    assert res.status_code == 400

def test_stage2_success():
    session_id = "sess_test_2026"
    ctx_hash = hashlib.sha256(b"context_verified").hexdigest()
    prov_hmac = hmac.new(
        MEMORY_SHARED_SECRET,
        f"{session_id}:{ctx_hash}".encode(),
        hashlib.sha256
    ).hexdigest()
    payload = {
        "memory_node_id": "mem_node_test_01",
        "session_id": session_id,
        "context_hash": ctx_hash,
        "attestation_sig": "sig_agent_mem_v222_test",
        "provenance_hmac": prov_hmac
    }
    res = client.post("/api/stage2/eval", json=payload)
    assert res.status_code == 200
    assert "FLAG{v222_s2_session_provenance_hmac_attested}" == res.json()["flag"]

def test_stage2_invalid_hmac():
    payload = {
        "memory_node_id": "mem_node_test_01",
        "session_id": "sess_bad",
        "context_hash": hashlib.sha256(b"bad").hexdigest(),
        "attestation_sig": "sig_agent_mem_v222_test",
        "provenance_hmac": "00" * 32
    }
    res = client.post("/api/stage2/eval", json=payload)
    assert res.status_code == 403

def test_stage3_success():
    payload = {
        "embedding_model": "vibe-semantic-embed-v222",
        "cosine_drift_threshold": 0.25,
        "adversarial_cluster_filter_active": True,
        "vector_index_isolation_enforced": True
    }
    res = client.post("/api/stage3/eval", json=payload)
    assert res.status_code == 200
    assert "FLAG{v222_s3_cosine_anomaly_adversarial_cluster_filtered}" == res.json()["flag"]

def test_stage4_success():
    admin_hmac = hmac.new(
        MEMORY_SHARED_SECRET,
        b"graphrag_schema_v222:invariant_edges_secured",
        hashlib.sha256
    ).hexdigest()
    payload = {
        "graph_schema_validation": "strict_topological_invariant",
        "unauthorized_edge_pruning": True,
        "admin_relationship_hmac": admin_hmac,
        "sleeper_trigger_neutralized": True
    }
    res = client.post("/api/stage4/eval", json=payload)
    assert res.status_code == 200
    assert "FLAG{v222_s4_graphrag_topological_permission_shielded}" == res.json()["flag"]
