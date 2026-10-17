#!/usr/bin/env python3
"""
Lab 42: ServerlessGuard — Serverless Security & Cloud Event Injection Lab
Interactive FastAPI service demonstrating serverless cloud security:
1. Event Injection & Deserialization Pollution (S3 ObjectCreated event metadata command injection)
2. Warm Container /tmp Persistence & State Leak (Lambda container reuse, /tmp credential carving)
3. Overprivileged Serverless Execution Role & STS Escalation (Least Privilege violation & AssumeRole)
4. Serverless Runtime Hardening & Policy Lockdown (Ephemeral isolation, JSON schema validation, IAM least privilege)
"""

from typing import Dict, Any, List, Optional
import os
import re
import hashlib
import json
import time
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field

app = FastAPI(
    title="Lab 42: ServerlessGuard — Serverless Security & Cloud Event Injection Lab",
    description="Hands-on cloud serverless security simulation covering event injection, warm container /tmp persistence, IAM privilege escalation, and runtime hardening.",
    version="1.0.0",
)

# Flags
STAGE1_FLAG = "FLAG{serverless_event_injection_s3_key_rce_pwned}"
STAGE2_FLAG = "FLAG{serverless_warm_container_tmp_persistence_token_leaked}"
STAGE3_FLAG = "FLAG{serverless_iam_overprivileged_role_escalated}"
STAGE4_FLAG = "FLAG{serverless_hardened_least_privilege_runtime_secured}"

# ============================================================================
# Simulation Data & In-Memory State
# ============================================================================

def get_initial_tmp_files():
    return {
        "/tmp/session_cache.json": {
            "creator": "admin-sync-job",
            "cached_at": "2026-10-17T03:15:00Z",
            "aws_access_key_id": "ASIA2XSERVERLESS9988",
            "aws_secret_access_key": "vibeHackingSecretKeyServerlessWarmLeak2026",
            "aws_session_token": "AQoDYXdzEJr111111111111111111111111111111111111111111111111111111",
            "db_dsn": "postgres://lambda_worker:P@ssw0rd9988@prod-db.internal:5432/corp_finances"
        },
        "/tmp/event_history.log": {
            "entries": [
                "2026-10-17 03:12:01 - Processed s3://corp-invoice-intake/invoice-001.pdf",
                "2026-10-17 03:14:22 - Processed s3://corp-invoice-intake/invoice-002.pdf"
            ]
        }
    }


def get_initial_iam_role():
    return {
        "RoleName": "ServerlessEventProcessorRole",
        "RoleArn": "arn:aws:iam::123456789012:role/ServerlessEventProcessorRole",
        "AttachedPolicies": [
            {
                "PolicyName": "BroadCloudAccessPolicy",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": [
                            "s3:*",
                            "iam:PassRole",
                            "sts:AssumeRole",
                            "secretsmanager:GetSecretValue"
                        ],
                        "Resource": "*"
                    }
                ]
            }
        ]
    }


STATE = {
    "stage1_solved": False,
    "stage2_solved": False,
    "stage3_solved": False,
    "stage4_solved": False,
    "container_invocations": 14,
    "container_state": "WARM",
    "tmp_files": get_initial_tmp_files(),
    "iam_role": get_initial_iam_role(),
    "hardened_config": {
        "readonly_root_fs": False,
        "clean_tmp_per_invocation": False,
        "event_schema_validation": False,
        "iam_least_privilege": False
    }
}


# ============================================================================
# Pydantic Request Models
# ============================================================================

class EventRecord(BaseModel):
    eventSource: str = "aws:s3"
    eventName: str = "ObjectCreated:Put"
    s3: Dict[str, Any]


class S3EventInvocationRequest(BaseModel):
    Records: List[EventRecord]


class TmpPersistenceRequest(BaseModel):
    action: str = Field(..., description="'inspect', 'write_payload', or 'dump_secrets'")
    filename: Optional[str] = "/tmp/session_cache.json"
    content: Optional[str] = None


class AssumeRoleRequest(BaseModel):
    target_role_arn: str = Field(..., description="Target IAM role ARN to assume")
    session_name: str = "PwnSession"


class HardeningConfigRequest(BaseModel):
    readonly_root_fs: bool = Field(..., description="Enforce read-only container root filesystem")
    clean_tmp_per_invocation: bool = Field(..., description="Scrub /tmp ephemeral storage between calls")
    event_schema_validation: bool = Field(..., description="Validate event inputs against strict JSON Schema")
    iam_least_privilege: bool = Field(..., description="Restrict IAM role actions strictly to scoped S3 GetObject")


# ============================================================================
# API Endpoints
# ============================================================================

@app.get("/", response_class=HTMLResponse)
def index_view():
    """Interactive Serverless Security Dashboard"""
    s1_badge = "✅ Solved" if STATE["stage1_solved"] else "⏳ Pending"
    s2_badge = "✅ Solved" if STATE["stage2_solved"] else "⏳ Pending"
    s3_badge = "✅ Solved" if STATE["stage3_solved"] else "⏳ Pending"
    s4_badge = "✅ Solved" if STATE["stage4_solved"] else "⏳ Pending"

    html = f"""<!DOCTYPE html>
<html lang="ko">
<head>
  <meta charset="UTF-8">
  <title>Lab 42: ServerlessGuard — Serverless Security & Cloud Event Injection</title>
  <style>
    body {{ background: #0f172a; color: #f8fafc; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, monospace; margin: 0; padding: 2rem; }}
    h1 {{ color: #38bdf8; border-bottom: 2px solid #334155; padding-bottom: 0.5rem; }}
    .card {{ background: #1e293b; border: 1px solid #334155; border-radius: 8px; padding: 1.5rem; margin-bottom: 1.5rem; }}
    .badge {{ display: inline-block; padding: 0.25rem 0.5rem; border-radius: 4px; font-weight: bold; background: #334155; color: #94a3b8; font-size: 0.85rem; }}
    .badge-ok {{ background: #065f46; color: #34d399; }}
    pre {{ background: #020617; border: 1px solid #1e293b; padding: 1rem; border-radius: 4px; overflow-x: auto; color: #a5f3fc; }}
    .btn {{ background: #0284c7; color: white; border: none; padding: 0.5rem 1rem; border-radius: 4px; cursor: pointer; font-weight: bold; }}
    .btn:hover {{ background: #0369a1; }}
  </style>
</head>
<body>
  <h1>⚡ Lab 42: ServerlessGuard Dashboard</h1>
  <p>AWS Lambda 및 서버리스 클라우드 런타임 보안 실전 시뮬레이션 환경 (Port: 8042)</p>

  <div class="card">
    <h3>📊 실습 진행 현황</h3>
    <p>1단계: S3 이벤트 인젝션 RCE — <span class="badge {'badge-ok' if STATE['stage1_solved'] else ''}">{s1_badge}</span></p>
    <p>2단계: Warm Container /tmp 영속성 & 시크릿 카빙 — <span class="badge {'badge-ok' if STATE['stage2_solved'] else ''}">{s2_badge}</span></p>
    <p>3단계: 과도한 IAM 실행 권한 & STS AssumeRole 탈취 — <span class="badge {'badge-ok' if STATE['stage3_solved'] else ''}">{s3_badge}</span></p>
    <p>4단계: 서버리스 런타임 하드닝 & 최소 권한 정책 강제 — <span class="badge {'badge-ok' if STATE['stage4_solved'] else ''}">{s4_badge}</span></p>
  </div>

  <div class="card">
    <h3>🔬 API Endpoints</h3>
    <pre>
GET  /api/status                       — 실습 랩 전체 상태 조회
POST /api/stage1/invoke-event           — S3 이벤트 인젝션 공격 시뮬레이션
GET  /api/stage2/inspect-tmp            — Warm Container /tmp 영속 파일 목록 조회
POST /api/stage2/dump-secrets          — /tmp 잔존 캐시에서 AWS 세션 토큰 카빙
POST /api/stage3/escalate-iam          — 과도한 권한의 IAM Role 악용 AssumeRole 공격
POST /api/stage4/harden-runtime         — 서버리스 런타임 하드닝 및 IAM 최소 권한 강제
POST /api/reset                        — 상태 초기화
    </pre>
  </div>
</body>
</html>"""
    return HTMLResponse(content=html)


@app.get("/api/status")
def get_status():
    """Returns current completion state of Lab 42 stages."""
    all_completed = all([
        STATE["stage1_solved"],
        STATE["stage2_solved"],
        STATE["stage3_solved"],
        STATE["stage4_solved"]
    ])
    return {
        "lab": "42",
        "codename": "ServerlessGuard",
        "port": 8042,
        "all_stages_completed": all_completed,
        "stages": {
            "stage1_event_injection": STATE["stage1_solved"],
            "stage2_warm_container_tmp": STATE["stage2_solved"],
            "stage3_iam_privilege_escalation": STATE["stage3_solved"],
            "stage4_runtime_hardening": STATE["stage4_solved"]
        },
        "container_metrics": {
            "invocations": STATE["container_invocations"],
            "state": STATE["container_state"],
            "tmp_file_count": len(STATE["tmp_files"])
        }
    }


@app.post("/api/reset")
def reset_state():
    """Resets all simulation states for testing."""
    STATE["stage1_solved"] = False
    STATE["stage2_solved"] = False
    STATE["stage3_solved"] = False
    STATE["stage4_solved"] = False
    STATE["container_invocations"] = 14
    STATE["container_state"] = "WARM"
    STATE["tmp_files"] = get_initial_tmp_files()
    STATE["iam_role"] = get_initial_iam_role()
    STATE["hardened_config"] = {
        "readonly_root_fs": False,
        "clean_tmp_per_invocation": False,
        "event_schema_validation": False,
        "iam_least_privilege": False
    }
    return {"message": "Lab 42 state successfully reset to initial conditions."}


# ============================================================================
# Stage 1: Serverless Event Injection & Deserialization Pollution
# ============================================================================

@app.post("/api/stage1/invoke-event")
def invoke_s3_event(req: S3EventInvocationRequest):
    """
    Simulates AWS Lambda event intake handler:
    Vulnerability: The event handler extracts the s3.object.key and performs an unsanitized
    os.system() / subshell command (e.g. `pdftotext /tmp/{key} /tmp/{key}.txt`) without validation.
    Injecting command separators (;, |, ``, $()) triggers arbitrary command execution.
    """
    if not req.Records:
        raise HTTPException(status_code=400, detail="Invalid Lambda event format: Records array is empty")

    record = req.Records[0]
    s3_meta = record.s3
    bucket = s3_meta.get("bucket", {}).get("name", "")
    key = s3_meta.get("object", {}).get("key", "")

    if not bucket or not key:
        raise HTTPException(status_code=400, detail="Missing bucket name or object key in S3 event payload")

    # Command injection pattern detector
    injection_patterns = [";", "|", "`", "$(", "&&", "||", "\n"]
    has_injection = any(pat in key for pat in injection_patterns)

    STATE["container_invocations"] += 1

    if has_injection:
        STATE["stage1_solved"] = True
        extracted_cmd = key
        for pat in [";", "|", "&&", "$("]:
            if pat in extracted_cmd:
                extracted_cmd = extracted_cmd.split(pat)[-1].strip()
        
        simulated_stdout = (
            f"uid=1001(sbx_user1001) gid=1001(sbx_user1001) groups=1001(sbx_user1001)\n"
            f"AWS_LAMBDA_FUNCTION_NAME=InvoiceProcessor\n"
            f"AWS_REGION=ap-northeast-2\n"
            f"Executed injected command from s3.object.key: {key}"
        )

        return {
            "success": True,
            "message": "🔥 Event Injection Succeeded! Shell Metacharacters Executed in Lambda Subprocess",
            "injected_key": key,
            "simulated_output": simulated_stdout,
            "flag": STAGE1_FLAG
        }
    else:
        return {
            "success": True,
            "message": f"Event processed normally. Safe key '{key}' handled by pdftotext.",
            "stage1_solved": STATE["stage1_solved"],
            "hint": "Try appending shell metacharacters (; cat /etc/passwd or ; id) into the s3.object.key parameter."
        }


# ============================================================================
# Stage 2: Warm Container /tmp Persistence & Environment Secret Leak
# ============================================================================

@app.get("/api/stage2/inspect-tmp")
def inspect_tmp_directory():
    """Lists files remaining in /tmp ephemeral storage from previous container invocations."""
    files_info = []
    for filepath, data in STATE["tmp_files"].items():
        files_info.append({
            "path": filepath,
            "size_bytes": len(json.dumps(data)),
            "keys_present": list(data.keys())
        })
    return {
        "container_execution_mode": STATE["container_state"],
        "invocations_since_cold_start": STATE["container_invocations"],
        "tmp_files": files_info,
        "warning": "Lambda execution environment reuse preserves /tmp across consecutive handler invocations!"
    }


@app.post("/api/stage2/dump-secrets")
def dump_tmp_secrets(req: TmpPersistenceRequest):
    """
    Carves credentials and sensitive session tokens cached in /tmp from prior executions.
    """
    if req.action not in ["inspect", "dump_secrets", "write_payload"]:
        raise HTTPException(status_code=400, detail="Invalid action. Use 'inspect', 'dump_secrets', or 'write_payload'")

    if req.action == "write_payload":
        if not req.filename or not req.content:
            raise HTTPException(status_code=400, detail="filename and content required for write_payload")
        STATE["tmp_files"][req.filename] = {"custom_payload": req.content, "timestamp": time.time()}
        return {
            "success": True,
            "message": f"Backdoor payload written to warm container: {req.filename}",
            "file_count": len(STATE["tmp_files"])
        }

    # Carve credentials from /tmp/session_cache.json
    cache_file = STATE["tmp_files"].get("/tmp/session_cache.json")
    if not cache_file:
        raise HTTPException(status_code=404, detail="Cache file not found in /tmp")

    STATE["stage2_solved"] = True
    return {
        "success": True,
        "message": "🔓 Warm Container /tmp Secret Carved! Sensitive AWS Session Token Leaked across Invocations",
        "leaked_credentials": cache_file,
        "flag": STAGE2_FLAG
    }


# ============================================================================
# Stage 3: Overprivileged IAM Execution Role & STS AssumeRole Escalation
# ============================================================================

@app.get("/api/stage3/iam-policy")
def get_attached_iam_policy():
    """Returns the currently active IAM execution policy attached to the serverless function."""
    return {
        "role": STATE["iam_role"],
        "findings": [
            "Overly permissive wildcard Action: ['s3:*', 'iam:PassRole', 'sts:AssumeRole']",
            "Resource wildcard: '*'",
            "Violation of AWS Least Privilege Best Practices"
        ]
    }


@app.post("/api/stage3/escalate-iam")
def escalate_iam_role(req: AssumeRoleRequest):
    """
    Exploits overprivileged sts:AssumeRole permission in Lambda execution policy
    to assume the high-privilege CorpCloudAdminRole.
    """
    target = req.target_role_arn.strip()
    valid_admin_role = "arn:aws:iam::123456789012:role/CorpCloudAdminRole"

    if target != valid_admin_role:
        raise HTTPException(
            status_code=400,
            detail=f"Target role '{target}' cannot be assumed. Try targeting '{valid_admin_role}'."
        )

    STATE["stage3_solved"] = True
    assumed_credentials = {
        "AssumedRoleUser": {
            "AssumedRoleId": "AROA1234ADMINROLE:PwnSession",
            "Arn": f"{valid_admin_role}/PwnSession"
        },
        "Credentials": {
            "AccessKeyId": "ASIA99ADMINESCALATED123",
            "SecretAccessKey": "topSecretAdminKeyServerlessOverprivilegedIAM2026",
            "SessionToken": "AQoDYXdzEJr999999999999999999999999999999999999999999999999999999",
            "Expiration": "2026-10-17T06:00:00Z"
        },
        "PermissionsGranted": ["AdministratorAccess", "*:*"]
    }

    return {
        "success": True,
        "message": "👑 IAM Privilege Escalation Complete! Successfully assumed CorpCloudAdminRole via STS",
        "assumed_role_result": assumed_credentials,
        "flag": STAGE3_FLAG
    }


# ============================================================================
# Stage 4: Serverless Runtime Hardening & Least Privilege Enforcement
# ============================================================================

@app.post("/api/stage4/harden-runtime")
def harden_serverless_runtime(config: HardeningConfigRequest):
    """
    Applies comprehensive security hardening to the serverless runtime:
    1. Read-only Root Filesystem (prevents malware dropping & persistence)
    2. Ephemeral /tmp Cleaning (scrubs container between invocations)
    3. Strict JSON Schema Validation (blocks event parameter injection)
    4. Least Privilege IAM Role (strictly scoped s3:GetObject only)
    """
    if not (config.readonly_root_fs and config.clean_tmp_per_invocation and config.event_schema_validation and config.iam_least_privilege):
        missing = []
        if not config.readonly_root_fs:
            missing.append("readonly_root_fs (Read-only container filesystem)")
        if not config.clean_tmp_per_invocation:
            missing.append("clean_tmp_per_invocation (Ephemeral /tmp scrubbing)")
        if not config.event_schema_validation:
            missing.append("event_schema_validation (Strict event input schema)")
        if not config.iam_least_privilege:
            missing.append("iam_least_privilege (Scoping down IAM actions to s3:GetObject only)")

        raise HTTPException(
            status_code=400,
            detail=f"Incomplete hardening configuration. All 4 security controls must be True. Missing: {', '.join(missing)}"
        )

    STATE["hardened_config"] = config.model_dump() if hasattr(config, "model_dump") else config.dict()
    STATE["stage4_solved"] = True

    # Apply hardening in runtime
    STATE["tmp_files"] = {}  # Scrubbed
    STATE["iam_role"]["AttachedPolicies"] = [
        {
            "PolicyName": "StrictLeastPrivilegeInvoiceReader",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["s3:GetObject"],
                    "Resource": "arn:aws:s3:::corp-invoice-intake/*.pdf"
                }
            ]
        }
    ]

    return {
        "success": True,
        "message": "🛡️ Serverless Runtime Fully Hardened! Ephemeral isolation and Least Privilege Policy Enforced",
        "applied_policies": STATE["iam_role"]["AttachedPolicies"],
        "runtime_controls": STATE["hardened_config"],
        "flag": STAGE4_FLAG
    }
