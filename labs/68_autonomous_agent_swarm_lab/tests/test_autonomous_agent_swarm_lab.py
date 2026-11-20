import os
import sys
import importlib.util
from pathlib import Path
import pytest
import hmac
import hashlib
from starlette.testclient import TestClient

_app_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "app", "main.py"))
_spec = importlib.util.spec_from_file_location("lab_68_main", _app_path)
_mod = importlib.util.module_from_spec(_spec)
sys.modules["lab_68_main"] = _mod
_spec.loader.exec_module(_mod)

app = _mod.app
SWARM_SHARED_SECRET = _mod.SWARM_SHARED_SECRET
client = TestClient(app)

def test_health_and_root():
    r = client.get("/api/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"
    assert r.json()["lab_id"] == 68

    res = client.get("/")
    assert res.status_code == 200
    data = res.json()
    assert data["port"] == 8068
    assert data["stages"] == 4
    assert data["status"] == "ready"

def test_stage1_success():
    spiffe_id = "spiffe://vibe.internal/agent/swarm-worker-verified"
    sig = hmac.new(SWARM_SHARED_SECRET, spiffe_id.encode(), hashlib.sha256).hexdigest()
    p = {
        "agent_spiffe_id": spiffe_id,
        "mtls_client_cert_hash": "a" * 64,
        "signature": sig,
        "enforce_identity_pinning": True
    }
    res = client.post("/api/stage1/eval", json=p)
    assert res.status_code == 200
    assert "FLAG{v218_s1_rogue_swarm_agent_mtls_identity_verified}" in res.json()["flag"]

def test_stage1_rogue_agent_rejection():
    p = {
        "agent_spiffe_id": "spiffe://attacker.domain/rogue-agent",
        "mtls_client_cert_hash": "b" * 64,
        "signature": "bad_signature",
        "enforce_identity_pinning": True
    }
    res = client.post("/api/stage1/eval", json=p)
    assert res.status_code == 403

def test_stage2_success():
    p = {
        "quorum_size": 4,
        "byzantine_fault_tolerance": "pbft",
        "consensus_round": 1,
        "worker_votes": ["vote_commit_alpha", "vote_commit_beta", "vote_commit_gamma"],
        "mitigate_outlier_weight": True
    }
    res = client.post("/api/stage2/eval", json=p)
    assert res.status_code == 200
    assert "FLAG{v218_s2_pbft_consensus_byzantine_fault_mitigated}" in res.json()["flag"]

def test_stage3_success():
    p = {
        "context_window_id": "ctx-test-01",
        "enforce_landlock_ro_snapshot": True,
        "ephemeral_memory_namespace": True,
        "prevent_cross_agent_injection": True
    }
    res = client.post("/api/stage3/eval", json=p)
    assert res.status_code == 200
    assert "FLAG{v218_s3_landlock_lsm_swarm_memory_isolated}" in res.json()["flag"]

def test_stage4_success():
    target = "node-alpha"
    audit_hmac = hmac.new(
        SWARM_SHARED_SECRET,
        f"{target}:tetragon-zero-trust-sigkill".encode(),
        hashlib.sha256
    ).hexdigest()
    p = {
        "lateral_target_agent": target,
        "tetragon_tracing_policy": "cilium-tetragon-swarm-ipc-sigkill",
        "sigkill_on_unauthorized_ipc": True,
        "zero_trust_mesh_audit_hmac": audit_hmac
    }
    res = client.post("/api/stage4/eval", json=p)
    assert res.status_code == 200
    assert "FLAG{v218_s4_ebpf_tetragon_swarm_lateral_zero_trust_kill}" in res.json()["flag"]
