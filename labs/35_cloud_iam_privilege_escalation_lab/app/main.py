"""
Lab 35: Cloud IAM Privilege Escalation & Organization Security Lab (CloudPwnLab)
VibeHacking Security Engineering Platform
Port: 8035
"""

import os
from typing import Dict, Any, Optional, List
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

app = FastAPI(
    title="Lab 35: Cloud IAM Privilege Escalation Lab",
    description="AWS IAM Evaluation Logic, PassRole Escalation, Cross-Account AssumeRole, and SCP Governance",
    version="1.0.0"
)

# Step Flags
STEP1_FLAG = "FLAG{CLOUD_IAM_PASSROLE_EC2_PRIV_ESCALATED_1120}"
STEP2_FLAG = "FLAG{CLOUD_STS_ASSUMEROLE_TRUST_POLICY_PWNED_2231}"
STEP3_FLAG = "FLAG{CLOUD_ORG_SCP_PERMISSION_BOUNDARY_ENFORCED_3342}"

# In-Memory State
state = {
    "step1_completed": False,
    "step2_completed": False,
    "step3_completed": False,
    "current_identity": "arn:aws:iam::123456789012:user/intern-developer",
    "effective_permissions": "ReadOnlyAccess",
    "scp_applied": False,
    "permission_boundary_applied": False,
    "assumed_sessions": [],
    "launched_instances": []
}

class PassRoleRequest(BaseModel):
    target_role: str
    service_type: Optional[str] = "ec2"  # ec2, lambda, glue
    user_data_payload: Optional[str] = "curl http://169.254.169.254/latest/meta-data/iam/security-credentials/"

class AssumeRoleRequest(BaseModel):
    role_arn: str
    role_session_name: Optional[str] = "osint-session"
    external_id: Optional[str] = None

class ScpHardenRequest(BaseModel):
    enforce_scp: bool = True
    enforce_permission_boundary: bool = True
    restrict_passrole_resources: bool = True


@app.get("/health")
def health() -> Dict[str, Any]:
    return {
        "status": "ok",
        "lab": "35_cloud_iam_privilege_escalation_lab",
        "port": 8035,
        "step1_completed": state["step1_completed"],
        "step2_completed": state["step2_completed"],
        "step3_completed": state["step3_completed"],
        "scp_applied": state["scp_applied"]
    }


@app.get("/api/cloud/iam/roles")
def get_iam_roles() -> Dict[str, Any]:
    return {
        "account_id": "123456789012",
        "current_user": {
            "arn": state["current_identity"],
            "permissions": state["effective_permissions"],
            "allowed_actions": ["ec2:RunInstances", "iam:PassRole", "sts:AssumeRole"] if not state["scp_applied"] else ["ec2:DescribeInstances"]
        },
        "available_roles": [
            {
                "role_name": "CloudSecAdminRole",
                "arn": "arn:aws:iam::123456789012:role/CloudSecAdminRole",
                "trust_policy": {"Service": "ec2.amazonaws.com"},
                "attached_policies": ["AdministratorAccess"],
                "description": "High-privilege cloud security automation role for EC2 compute"
            },
            {
                "role_name": "CrossAccountAuditRole",
                "arn": "arn:aws:iam::123456789012:role/CrossAccountAuditRole",
                "trust_policy": {"Principal": {"AWS": "*"}, "Action": "sts:AssumeRole"},
                "attached_policies": ["SecurityAudit", "AmazonS3FullAccess"],
                "description": "External third-party compliance audit role with overly permissive wildcard trust"
            },
            {
                "role_name": "AppDevLambdaRole",
                "arn": "arn:aws:iam::123456789012:role/AppDevLambdaRole",
                "trust_policy": {"Service": "lambda.amazonaws.com"},
                "attached_policies": ["AWSLambdaBasicExecutionRole"],
                "description": "Standard serverless developer role"
            }
        ],
        "governance": {
            "scp_applied": state["scp_applied"],
            "permission_boundary_applied": state["permission_boundary_applied"]
        }
    }


@app.get("/api/cloud/iam/status")
def get_status() -> Dict[str, Any]:
    return {
        "step1_completed": state["step1_completed"],
        "step2_completed": state["step2_completed"],
        "step3_completed": state["step3_completed"],
        "current_identity": state["current_identity"],
        "effective_permissions": state["effective_permissions"],
        "scp_applied": state["scp_applied"],
        "permission_boundary_applied": state["permission_boundary_applied"]
    }


@app.post("/api/cloud/iam/passrole")
def exploit_passrole(req: PassRoleRequest) -> Dict[str, Any]:
    if state["scp_applied"]:
        raise HTTPException(
            status_code=403,
            detail="AccessDeniedException: Explicit DENY in Organization SCP (EnforceLeastPrivilegePassRole). iam:PassRole without resource-level tag constraint is strictly prohibited."
        )

    t_role = req.target_role.strip()
    if "admin" not in t_role.lower() and "cloudsec" not in t_role.lower():
        raise HTTPException(
            status_code=400,
            detail="Target role must be a privileged role (e.g. CloudSecAdminRole or arn:aws:iam::123456789012:role/CloudSecAdminRole)."
        )

    instance_id = "i-09f481c8b321a99ef"
    state["launched_instances"].append(instance_id)
    state["current_identity"] = "arn:aws:sts::123456789012:assumed-role/CloudSecAdminRole/instance-session"
    state["effective_permissions"] = "AdministratorAccess"
    state["step1_completed"] = True

    return {
        "status": "success",
        "event": "ec2:RunInstances with iam:PassRole",
        "instance_id": instance_id,
        "passed_role": "arn:aws:iam::123456789012:role/CloudSecAdminRole",
        "carved_credentials": {
            "AccessKeyId": "ASIAVBHACKINGADMINKEY",
            "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYADMINTEMPKEY",
            "Token": "IQoJb3JpZ2luX2VjEAMaCXVzLWVhc3QtMSJHMEUCIQ...",
            "Expiration": "2026-09-30T16:00:00Z"
        },
        "escalated_permissions": "AdministratorAccess (*:*)",
        "flag": STEP1_FLAG,
        "message": "Step 1 Completed: Exploited iam:PassRole to launch an EC2 instance with CloudSecAdminRole and extracted master credentials via IMDS."
    }


@app.post("/api/cloud/iam/assumerole")
def exploit_assumerole(req: AssumeRoleRequest) -> Dict[str, Any]:
    if state["scp_applied"]:
        raise HTTPException(
            status_code=403,
            detail="AccessDeniedException: Explicit DENY in Organization SCP (DenyWildcardAssumeRole). sts:AssumeRole from non-org principal is blocked."
        )

    r_arn = req.role_arn.strip()
    if "audit" not in r_arn.lower() and "crossaccount" not in r_arn.lower():
        raise HTTPException(
            status_code=400,
            detail="Target role must specify the vulnerable cross-account role (CrossAccountAuditRole)."
        )

    session_name = req.role_session_name or "audit-session"
    state["assumed_sessions"].append(session_name)
    state["step2_completed"] = True

    return {
        "status": "success",
        "event": "sts:AssumeRole",
        "assumed_role_user": {
            "AssumedRoleId": f"AROAEXAMPLEAUDITKEY:{session_name}",
            "Arn": f"arn:aws:sts::123456789012:assumed-role/CrossAccountAuditRole/{session_name}"
        },
        "credentials": {
            "AccessKeyId": "ASIAEXAMPLEAUDITKEY99",
            "SecretAccessKey": "K983a/8172dfg+h81jdh12301982736458129034",
            "SessionToken": "AQoDYXdzEJr//////////wEaCXVzLWVhc3QtMS...",
            "Expiration": "2026-09-30T17:00:00Z"
        },
        "granted_policies": ["SecurityAudit", "AmazonS3FullAccess"],
        "flag": STEP2_FLAG,
        "message": "Step 2 Completed: Exploited overly permissive wildcard Principal in trust policy to assume CrossAccountAuditRole across accounts."
    }


@app.post("/api/cloud/iam/scp/harden")
def harden_scp(req: ScpHardenRequest) -> Dict[str, Any]:
    if not (req.enforce_scp and req.enforce_permission_boundary and req.restrict_passrole_resources):
        raise HTTPException(
            status_code=400,
            detail="All hardening policies must be enabled: enforce_scp, enforce_permission_boundary, restrict_passrole_resources."
        )

    state["scp_applied"] = True
    state["permission_boundary_applied"] = True
    state["current_identity"] = "arn:aws:iam::123456789012:user/intern-developer"
    state["effective_permissions"] = "ReadOnlyAccess (Boundary Enforced)"
    state["step3_completed"] = True

    return {
        "status": "success",
        "enforced_controls": [
            "Organization SCP: DenyPassRoleWithoutServiceTag (Resource: arn:aws:iam::*:role/app-scoped-*)",
            "Organization SCP: DenyWildcardAssumeRole (Require aws:PrincipalOrgID condition)",
            "IAM Permission Boundary: DeveloperBoundary (Max allowed: ReadOnly + restricted dev deploy)",
            "AWS CloudTrail & GuardDuty Alarm: Anomaly detection on IAM Policy modification"
        ],
        "compliance_result": "PASSED - AWS CIS Benchmark 2.0 & Cloud Architecture Well-Architected Pillar 100% Satisfied",
        "flag": STEP3_FLAG,
        "message": "Step 3 Completed: Deployed multi-layered Cloud Governance: SCP Deny gates, IAM Permission Boundaries, and Tag-scoped PassRole restrictions."
    }


@app.post("/api/cloud/iam/reset")
def reset_lab() -> Dict[str, Any]:
    state["step1_completed"] = False
    state["step2_completed"] = False
    state["step3_completed"] = False
    state["current_identity"] = "arn:aws:iam::123456789012:user/intern-developer"
    state["effective_permissions"] = "ReadOnlyAccess"
    state["scp_applied"] = False
    state["permission_boundary_applied"] = False
    state["assumed_sessions"] = []
    state["launched_instances"] = []
    return {"status": "reset_complete", "message": "Lab 35 Cloud IAM state has been reset to vulnerable baseline."}


@app.get("/", response_class=HTMLResponse)
def index_page() -> str:
    return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Lab 35: Cloud IAM Privilege Escalation & Governance</title>
    <style>
        :root {
            --bg: #090d16;
            --surface: #111827;
            --border: #1f2937;
            --aws-orange: #ff9900;
            --primary: #38bdf8;
            --accent: #f43f5e;
            --success: #10b981;
            --text: #f3f4f6;
            --text-dim: #9ca3af;
            --code-bg: #030712;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, monospace;
            background: var(--bg);
            color: var(--text);
            line-height: 1.6;
            padding: 24px;
        }
        .header {
            max-width: 1200px;
            margin: 0 auto 24px;
            border-bottom: 1px solid var(--border);
            padding-bottom: 16px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .header h1 {
            font-size: 1.45rem;
            color: var(--aws-orange);
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .badge {
            background: rgba(255, 153, 0, 0.15);
            color: var(--aws-orange);
            border: 1px solid var(--aws-orange);
            padding: 4px 10px;
            border-radius: 4px;
            font-size: 0.8rem;
            font-weight: bold;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 24px;
        }
        @media (max-width: 900px) {
            .container { grid-template-columns: 1fr; }
        }
        .card {
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 20px;
        }
        .card h2 {
            font-size: 1.15rem;
            color: #fff;
            margin-bottom: 12px;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .btn {
            background: var(--aws-orange);
            color: #000;
            border: none;
            padding: 8px 16px;
            border-radius: 4px;
            font-weight: bold;
            cursor: pointer;
            transition: opacity 0.2s;
        }
        .btn:hover { opacity: 0.9; }
        .btn-sec { background: var(--border); color: var(--text); }
        .btn-success { background: var(--success); color: #000; }
        .input-group {
            margin-bottom: 14px;
        }
        .input-group label {
            display: block;
            font-size: 0.85rem;
            color: var(--text-dim);
            margin-bottom: 6px;
        }
        input, select {
            width: 100%;
            background: var(--code-bg);
            border: 1px solid var(--border);
            color: var(--text);
            padding: 8px 12px;
            border-radius: 4px;
            font-family: monospace;
            font-size: 0.9rem;
        }
        pre {
            background: var(--code-bg);
            border: 1px solid var(--border);
            padding: 12px;
            border-radius: 4px;
            font-family: monospace;
            font-size: 0.85rem;
            overflow-x: auto;
            max-height: 260px;
            color: #38bdf8;
        }
        .flag-box {
            background: rgba(16, 185, 129, 0.1);
            border: 1px dashed var(--success);
            padding: 12px;
            border-radius: 4px;
            margin-top: 12px;
            color: var(--success);
            font-family: monospace;
            font-weight: bold;
            word-break: break-all;
        }
        .step-tag {
            display: inline-block;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: bold;
            margin-right: 6px;
        }
        .tag-1 { background: rgba(255, 153, 0, 0.2); color: var(--aws-orange); }
        .tag-2 { background: rgba(56, 189, 248, 0.2); color: var(--primary); }
        .tag-3 { background: rgba(16, 185, 129, 0.2); color: var(--success); }
    </style>
</head>
<body>
    <div class="header">
        <h1>☁️ Lab 35: Cloud IAM Privilege Escalation & Governance (CloudPwnLab)</h1>
        <div style="display: flex; gap: 8px; align-items: center;">
            <span class="badge">PORT 8035</span>
            <button class="btn btn-sec" onclick="resetLab()">Reset Lab</button>
        </div>
    </div>

    <div class="container">
        <!-- Step 1: PassRole Exploitation -->
        <div class="card">
            <h2><span class="step-tag tag-1">STEP 1</span> iam:PassRole & Compute Instance Escalation</h2>
            <p style="color: var(--text-dim); font-size: 0.85rem; margin-bottom: 14px;">
                Low-privilege user passes high-privilege <code>CloudSecAdminRole</code> to a compute launcher without resource boundaries to extract Administrator credentials.
            </p>
            <div class="input-group">
                <label>Target IAM Role to Pass:</label>
                <input type="text" id="passTargetRole" value="CloudSecAdminRole">
            </div>
            <div class="input-group">
                <label>Service Type:</label>
                <select id="passServiceType">
                    <option value="ec2">Amazon EC2 (ec2:RunInstances)</option>
                    <option value="lambda">AWS Lambda (lambda:CreateFunction)</option>
                </select>
            </div>
            <button class="btn" onclick="exploitPassRole()">Trigger iam:PassRole Escalation</button>
            <div id="step1Output" style="margin-top: 14px;"></div>
        </div>

        <!-- Step 2: AssumeRole Wildcard Trust -->
        <div class="card">
            <h2><span class="step-tag tag-2">STEP 2</span> sts:AssumeRole Cross-Account Trust Abuse</h2>
            <p style="color: var(--text-dim); font-size: 0.85rem; margin-bottom: 14px;">
                Exploit overly permissive wildcard Principal (<code>Principal: {"AWS": "*"}</code>) in cross-account trust policies to assume high-privilege audit roles.
            </p>
            <div class="input-group">
                <label>Target Role ARN:</label>
                <input type="text" id="assumeRoleArn" value="arn:aws:iam::123456789012:role/CrossAccountAuditRole">
            </div>
            <div class="input-group">
                <label>Role Session Name:</label>
                <input type="text" id="assumeSessionName" value="vibe-attacker-session">
            </div>
            <button class="btn" onclick="exploitAssumeRole()">Execute sts:AssumeRole</button>
            <div id="step2Output" style="margin-top: 14px;"></div>
        </div>

        <!-- Step 3: SCP Governance & Boundary Hardening -->
        <div class="card" style="grid-column: 1 / -1;">
            <h2><span class="step-tag tag-3">STEP 3</span> Multi-Layered Cloud Governance (SCP & Permission Boundary)</h2>
            <p style="color: var(--text-dim); font-size: 0.85rem; margin-bottom: 14px;">
                Enforce Organization Service Control Policies (SCP), Tag-constrained PassRole limits, and Developer Permission Boundaries to achieve 100% CIS AWS compliance.
            </p>
            <div style="display: flex; gap: 12px; margin-bottom: 14px;">
                <label style="display: flex; align-items: center; gap: 6px; font-size: 0.9rem;">
                    <input type="checkbox" id="chkScp" checked> Enforce Org SCP (Explicit Deny)
                </label>
                <label style="display: flex; align-items: center; gap: 6px; font-size: 0.9rem;">
                    <input type="checkbox" id="chkBoundary" checked> Attach Permission Boundary
                </label>
                <label style="display: flex; align-items: center; gap: 6px; font-size: 0.9rem;">
                    <input type="checkbox" id="chkResourceTag" checked> Tag-scoped PassRole Constraints
                </label>
            </div>
            <button class="btn btn-success" onclick="hardenScp()">Deploy Cloud Governance Architecture</button>
            <div id="step3Output"></div>
        </div>
    </div>

    <script>
        async function exploitPassRole() {
            const target_role = document.getElementById('passTargetRole').value;
            const service_type = document.getElementById('passServiceType').value;
            const res = await fetch('/api/cloud/iam/passrole', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({target_role, service_type})
            });
            const data = await res.json();
            let html = '<pre>' + JSON.stringify(data, null, 2) + '</pre>';
            if (data.flag) {
                html += '<div class="flag-box">🚩 STEP 1 FLAG: ' + data.flag + '</div>';
            }
            document.getElementById('step1Output').innerHTML = html;
        }

        async function exploitAssumeRole() {
            const role_arn = document.getElementById('assumeRoleArn').value;
            const role_session_name = document.getElementById('assumeSessionName').value;
            const res = await fetch('/api/cloud/iam/assumerole', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({role_arn, role_session_name})
            });
            const data = await res.json();
            let html = '<pre>' + JSON.stringify(data, null, 2) + '</pre>';
            if (data.flag) {
                html += '<div class="flag-box">🚩 STEP 2 FLAG: ' + data.flag + '</div>';
            }
            document.getElementById('step2Output').innerHTML = html;
        }

        async function hardenScp() {
            const enforce_scp = document.getElementById('chkScp').checked;
            const enforce_permission_boundary = document.getElementById('chkBoundary').checked;
            const restrict_passrole_resources = document.getElementById('chkResourceTag').checked;
            const res = await fetch('/api/cloud/iam/scp/harden', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({enforce_scp, enforce_permission_boundary, restrict_passrole_resources})
            });
            const data = await res.json();
            let html = '<pre>' + JSON.stringify(data, null, 2) + '</pre>';
            if (data.flag) {
                html += '<div class="flag-box">🚩 STEP 3 FLAG: ' + data.flag + '</div>';
            }
            document.getElementById('step3Output').innerHTML = html;
        }

        async function resetLab() {
            await fetch('/api/cloud/iam/reset', {method: 'POST'});
            document.getElementById('step1Output').innerHTML = '';
            document.getElementById('step2Output').innerHTML = '';
            document.getElementById('step3Output').innerHTML = '';
            alert('Lab 35 reset complete.');
        }
    </script>
</body>
</html>
"""
