#!/usr/bin/env python3
"""Tests for Lab 17: Kubernetes & Cloud Native Security Lab (KubeShield)."""

import importlib.util
import os
import sys
import pytest
from starlette.testclient import TestClient

_app_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "app", "main.py"))
_spec = importlib.util.spec_from_file_location("kube_lab_main", _app_path)
_mod = importlib.util.module_from_spec(_spec)
sys.modules["kube_lab_main"] = _mod
_spec.loader.exec_module(_mod)

app = _mod.app
FLAGS = _mod.FLAGS
state = _mod.state


@pytest.fixture(autouse=True)
def reset_state():
    state.reset()
    yield
    state.reset()


@pytest.fixture
def client():
    return TestClient(app)


def test_status_endpoint(client):
    res = client.get("/status")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "online"
    assert data["total_stages"] == 4
    assert "KubeShield" in data["lab"]
    assert "stage1_container_escape" in data["stages"]
    assert "stage2_rbac_escalation" in data["stages"]
    assert "stage3_cloud_imds" in data["stages"]
    assert "stage4_admission_cosign" in data["stages"]


def test_dashboard_served(client):
    res = client.get("/")
    assert res.status_code == 200
    assert "text/html" in res.headers["content-type"]
    assert "KubeShield" in res.text
    assert "Kubernetes Security" in res.text


def test_stage1_container_escape_and_psa_defense(client):
    # Unhardened: escape succeeds
    res = client.post("/api/stage1/escape-container")
    assert res.status_code == 200
    data = res.json()
    assert data["success"] is True
    assert data["flag"] == FLAGS["stage1"]
    assert "root:" in data["host_compromise"]["leaked_host_root_hash"]
    assert state.stage1_solved is True

    # Apply PSA restricted
    psa_res = client.post("/api/stage1/apply-psa", json={"mode": "restricted"})
    assert psa_res.status_code == 200
    assert state.psa_enforced is True

    # Now escape should be blocked with 403
    blocked_res = client.post("/api/stage1/escape-container")
    assert blocked_res.status_code == 403
    assert "restricted" in blocked_res.json()["detail"]


def test_stage2_rbac_escalation_and_remediation(client):
    # Enumerate permissions
    res_enum = client.post("/api/stage2/enumerate-rbac")
    assert res_enum.status_code == 200
    enum_data = res_enum.json()
    assert enum_data["service_account"] == "app-operator-sa"
    assert enum_data["rules"][0]["verbs"] == ["*"]

    # Escalate to cluster-admin
    res_esc = client.post("/api/stage2/escalate-cluster-admin")
    assert res_esc.status_code == 200
    esc_data = res_esc.json()
    assert esc_data["success"] is True
    assert esc_data["flag"] == FLAGS["stage2"]
    assert state.cluster_admin_bound is True
    assert state.stage2_solved is True

    # Remediate RBAC
    res_fix = client.post("/api/stage2/remediate-rbac")
    assert res_fix.status_code == 200
    assert state.sa_token_mounted is False
    assert state.rbac_cluster_role == "least-privilege-reader"

    # Escalate again should be blocked
    res_esc_blocked = client.post("/api/stage2/escalate-cluster-admin")
    assert res_esc_blocked.status_code == 403


def test_stage3_imds_harvest_and_v2_networkpolicy_defense(client):
    # Query IMDSv1 without token
    res = client.post("/api/stage3/query-imds")
    assert res.status_code == 200
    data = res.json()
    assert data["success"] is True
    assert data["flag"] == FLAGS["stage3"]
    assert data["credentials"]["AccessKeyId"] == "ASIAVIBEHACKING9182"
    assert state.stage3_solved is True

    # Enforce IMDSv2 & NetworkPolicy
    res_v2 = client.post("/api/stage3/enforce-imdsv2")
    assert res_v2.status_code == 200
    assert state.imds_v2_required is True
    assert state.egress_policy_blocking is True

    # Query IMDS should now be blocked by NetworkPolicy
    res_blocked = client.post("/api/stage3/query-imds")
    assert res_blocked.status_code == 408
    assert "NetworkPolicy" in res_blocked.json()["detail"]


def test_stage4_untrusted_deploy_and_cosign_webhook_defense(client):
    # Deploy unsigned/untrusted image
    res = client.post("/api/stage4/deploy-untrusted-image", json={"image_url": "registry.malicious.io/supplychain/backdoor:v1"})
    assert res.status_code == 200
    data = res.json()
    assert data["success"] is True
    assert data["flag"] == FLAGS["stage4"]
    assert state.stage4_solved is True

    # Enable Kyverno / Cosign Webhook
    res_cosign = client.post("/api/stage4/enable-cosign-webhook")
    assert res_cosign.status_code == 200
    assert state.cosign_enforced is True

    # Deploying unsigned image now should be blocked
    res_blocked = client.post("/api/stage4/deploy-untrusted-image", json={"image_url": "registry.malicious.io/supplychain/backdoor:v2"})
    assert res_blocked.status_code == 400
    assert "Kyverno/Cosign" in res_blocked.json()["detail"]


def test_terminal_commands(client):
    cmds = [
        "help",
        "status",
        "kubectl get nodes",
        "kubectl get pods -A",
        "kubectl auth can-i --list",
        "curl http://169.254.169.254/latest/meta-data/",
        "cosign verify registry.malicious.io/supplychain/backdoor:v1",
        "kubectl apply -f psa-restricted.yaml",
        "kubectl apply -f rbac-fix.yaml",
        "flags",
    ]
    for cmd in cmds:
        res = client.post("/api/terminal", json={"command": cmd})
        assert res.status_code == 200
        assert "output" in res.json()
        assert len(res.json()["output"]) > 0


def test_flag_submission_lifecycle(client):
    # Invalid flag
    res = client.post("/api/submit-flag", json={"flag": "FLAG{invalid_flag_xyz}"})
    assert res.status_code == 200
    assert res.json()["success"] is False

    # Valid flags
    for stage_key in ["stage1", "stage2", "stage3", "stage4"]:
        res = client.post("/api/submit-flag", json={"flag": FLAGS[stage_key]})
        assert res.status_code == 200
        assert res.json()["success"] is True
        assert res.json()["stage"] == stage_key

    assert len(state.solved_stages) == 4


def test_stage1_psa_mode_toggle(client):
    res_rest = client.post("/api/stage1/apply-psa", json={"mode": "restricted"})
    assert res_rest.status_code == 200
    assert state.psa_enforced is True

    res_priv = client.post("/api/stage1/apply-psa", json={"mode": "privileged"})
    assert res_priv.status_code == 200
    assert state.psa_enforced is False
    assert state.stage1_pod["privileged"] is True


def test_stage3_imds_v2_direct_blocking(client):
    state.imds_v2_required = True
    state.egress_policy_blocking = False
    res = client.post("/api/stage3/query-imds")
    assert res.status_code == 403
    assert "IMDSv2" in res.json()["detail"]


def test_reset_endpoint(client):
    client.post("/api/stage1/escape-container")
    assert state.stage1_solved is True
    res = client.post("/api/reset")
    assert res.status_code == 200
    assert state.stage1_solved is False
    assert len(state.solved_stages) == 0

