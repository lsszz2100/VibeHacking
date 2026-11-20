import os
import sys
import importlib.util
from pathlib import Path
import pytest
import hmac
import hashlib
from starlette.testclient import TestClient

_app_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "app", "main.py"))
_spec = importlib.util.spec_from_file_location("lab_66_main", _app_path)
_mod = importlib.util.module_from_spec(_spec)
sys.modules["lab_66_main"] = _mod
_spec.loader.exec_module(_mod)

app = _mod.app
SHARED_G3_SECRET = _mod.SHARED_G3_SECRET
client = TestClient(app)

def test_health_and_root():
    r = client.get("/api/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"
    assert r.json()["lab_id"] == 66

    r2 = client.get("/")
    assert r2.status_code == 200
    assert r2.json()["port"] == 8066

    r3 = client.get("/api/stages")
    assert r3.status_code == 200
    assert len(r3.json()["stages"]) == 4

def test_stage1_supply_chain():
    # Invalid package
    r_bad = client.post("/api/stage1/eval", json={
        "package_name": "malicious-telemetry",
        "expected_sha256": "a" * 64,
        "sigstore_verified": True,
        "slsa_provenance_level": 3,
        "allow_unpinned_deps": False
    })
    assert r_bad.status_code == 400

    # Low SLSA level
    r_bad_slsa = client.post("/api/stage1/eval", json={
        "package_name": "agent-core-telemetry",
        "expected_sha256": "a" * 64,
        "sigstore_verified": True,
        "slsa_provenance_level": 1,
        "allow_unpinned_deps": False
    })
    assert r_bad_slsa.status_code == 400

    # Unpinned dependencies
    r_bad_unpin = client.post("/api/stage1/eval", json={
        "package_name": "agent-core-telemetry",
        "expected_sha256": "a" * 64,
        "sigstore_verified": True,
        "slsa_provenance_level": 3,
        "allow_unpinned_deps": True
    })
    assert r_bad_unpin.status_code == 400

    # Valid
    r_ok = client.post("/api/stage1/eval", json={
        "package_name": "agent-core-telemetry",
        "expected_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "sigstore_verified": True,
        "slsa_provenance_level": 3,
        "allow_unpinned_deps": False
    })
    assert r_ok.status_code == 200
    assert "FLAG{aisbox_supply_chain_provenance_sealed_8066}" in r_ok.json()["flag"]

def test_stage2_ray_cluster():
    # Insecure deserialization
    r_bad = client.post("/api/stage2/eval", json={
        "cluster_mtls_enabled": True,
        "spiffe_id": "spiffe://prod.enterprise.cluster/ns/ai-agent/sa/runner",
        "safe_deserialization_only": False,
        "block_arbitrary_pickle": False
    })
    assert r_bad.status_code == 400

    # Valid
    r_ok = client.post("/api/stage2/eval", json={
        "cluster_mtls_enabled": True,
        "spiffe_id": "spiffe://prod.enterprise.cluster/ns/ai-agent/sa/runner",
        "safe_deserialization_only": True,
        "block_arbitrary_pickle": True
    })
    assert r_ok.status_code == 200
    assert "FLAG{aisbox_ray_cluster_mtls_spiffe_authenticated_8066}" in r_ok.json()["flag"]

def test_stage3_sandbox_breakout():
    # Proc fd traversal unshielded
    r_bad = client.post("/api/stage3/eval", json={
        "landlock_abi_enforced": True,
        "restrict_proc_fd_traversal": False,
        "block_setns_unshare": True,
        "ebpf_lsm_sigkill_on_escape": True
    })
    assert r_bad.status_code == 400

    # Valid
    r_ok = client.post("/api/stage3/eval", json={
        "landlock_abi_enforced": True,
        "restrict_proc_fd_traversal": True,
        "block_setns_unshare": True,
        "ebpf_lsm_sigkill_on_escape": True
    })
    assert r_ok.status_code == 200
    assert "FLAG{aisbox_landlock_ebpf_sandbox_containment_enforced_8066}" in r_ok.json()["flag"]

def test_stage4_g3_approval():
    # Missing G3 approval
    r_bad = client.post("/api/stage4/eval", json={
        "action_type": "EXECUTE_RESTRICTED_TOOL",
        "g3_approval_required": False,
        "multi_signature_hmac": "fake",
        "prevent_prompt_injection_bypass": True
    })
    assert r_bad.status_code == 400

    # Invalid HMAC
    r_bad_hmac = client.post("/api/stage4/eval", json={
        "action_type": "EXECUTE_RESTRICTED_TOOL",
        "g3_approval_required": True,
        "multi_signature_hmac": "bad_sig",
        "prevent_prompt_injection_bypass": True
    })
    assert r_bad_hmac.status_code == 403

    # Valid HMAC
    action = "EXECUTE_RESTRICTED_TOOL"
    valid_hmac = hmac.new(SHARED_G3_SECRET, action.encode(), hashlib.sha256).hexdigest()
    r_ok = client.post("/api/stage4/eval", json={
        "action_type": action,
        "g3_approval_required": True,
        "multi_signature_hmac": valid_hmac,
        "prevent_prompt_injection_bypass": True
    })
    assert r_ok.status_code == 200
    assert "FLAG{aisbox_g3_multi_party_ledger_governance_active_8066}" in r_ok.json()["flag"]
