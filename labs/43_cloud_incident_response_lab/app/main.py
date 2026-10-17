#!/usr/bin/env python3
"""
Lab 43: CloudIRShield — AWS & Multi-Cloud Incident Response & Threat Hunting Lab
Interactive FastAPI service demonstrating cloud incident response:
1. CloudTrail Log Audit & Anomaly Detection (Privilege escalation via AttachUserPolicy)
2. STS Token Carving & S3 Data Exfiltration Forensics (Compromised session & bulk download)
3. VPC Flow Logs Correlation & C2 Beacon Extraction (Periodic egress beaconing & jitter)
4. GuardDuty Triage & Automated SOAR Containment Playbook (Credential revocation & isolation)
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
    title="Lab 43: CloudIRShield — AWS & Multi-Cloud Incident Response & Threat Hunting Lab",
    description="Hands-on cloud incident response simulation covering CloudTrail auditing, STS exfiltration forensics, VPC flow logs correlation, and automated SOAR containment.",
    version="1.0.0",
)

# Flags
STAGE1_FLAG = "FLAG{cloudtrail_event_log_audit_anomaly_detected_8043}"
STAGE2_FLAG = "FLAG{cloud_sts_token_s3_data_exfiltration_traced_8043}"
STAGE3_FLAG = "FLAG{vpc_flow_logs_c2_beacon_correlation_identified_8043}"
STAGE4_FLAG = "FLAG{guardduty_soar_automated_containment_executed_8043}"

# ============================================================================
# Simulation Data & State
# ============================================================================

def get_initial_cloudtrail_events() -> List[Dict[str, Any]]:
    return [
        {
            "eventId": "evt-10291-normal-describe",
            "eventTime": "2026-10-17T02:10:05Z",
            "eventName": "DescribeInstances",
            "userIdentity": {
                "type": "AssumedRole",
                "arn": "arn:aws:sts::123456789012:assumed-role/MonitoringRole/PrometheusSync"
            },
            "sourceIPAddress": "10.0.1.25",
            "userAgent": "aws-sdk-go/v1.44.0",
            "responseElements": None
        },
        {
            "eventId": "evt-10295-normal-s3list",
            "eventTime": "2026-10-17T02:22:18Z",
            "eventName": "ListBuckets",
            "userIdentity": {
                "type": "IAMUser",
                "arn": "arn:aws:iam::123456789012:user/developer-alice"
            },
            "sourceIPAddress": "192.0.2.45",
            "userAgent": "aws-cli/2.13.0 Python/3.10.8 Darwin/22.4.0",
            "responseElements": None
        },
        {
            "eventId": "evt-99482-admin-escalation",
            "eventTime": "2026-10-17T02:44:19Z",
            "eventName": "AttachUserPolicy",
            "userIdentity": {
                "type": "IAMUser",
                "arn": "arn:aws:iam::123456789012:user/backup-svc-account",
                "userName": "backup-svc-account"
            },
            "sourceIPAddress": "198.51.100.77",
            "userAgent": "aws-cli/2.15.15 Python/3.11.6 Linux/6.5.0-kali3-amd64",
            "requestParameters": {
                "userName": "backup-svc-account",
                "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"
            },
            "responseElements": None,
            "readOnly": False
        },
        {
            "eventId": "evt-10302-normal-sts-getcaller",
            "eventTime": "2026-10-17T03:00:11Z",
            "eventName": "GetCallerIdentity",
            "userIdentity": {
                "type": "AssumedRole",
                "arn": "arn:aws:sts::123456789012:assumed-role/DataSyncRole/exfil-session-shadow-ops"
            },
            "sourceIPAddress": "198.51.100.77",
            "userAgent": "boto3/1.28.0 Python/3.11.6 Linux",
            "responseElements": None
        }
    ]


def get_initial_s3_exfil_logs() -> List[Dict[str, Any]]:
    return [
        {
            "timestamp": "2026-10-17T03:05:12Z",
            "bucketName": "corp-customer-pii-vault",
            "objectKey": "customer_ssn_2026.parquet",
            "requester": "arn:aws:sts::123456789012:assumed-role/DataSyncRole/exfil-session-shadow-ops",
            "sessionName": "exfil-session-shadow-ops",
            "stsTokenHash": hashlib.sha256(b"ASIA99CLOUDEXFIL2026").hexdigest()[:16],
            "stsToken": "ASIA99CLOUDEXFIL2026",
            "bytesSent": 18452100,
            "httpStatus": 200,
            "sourceIP": "198.51.100.77"
        },
        {
            "timestamp": "2026-10-17T03:06:45Z",
            "bucketName": "corp-customer-pii-vault",
            "objectKey": "financial_records_q3.csv",
            "requester": "arn:aws:sts::123456789012:assumed-role/DataSyncRole/exfil-session-shadow-ops",
            "sessionName": "exfil-session-shadow-ops",
            "stsTokenHash": hashlib.sha256(b"ASIA99CLOUDEXFIL2026").hexdigest()[:16],
            "stsToken": "ASIA99CLOUDEXFIL2026",
            "bytesSent": 14210040,
            "httpStatus": 200,
            "sourceIP": "198.51.100.77"
        },
        {
            "timestamp": "2026-10-17T03:07:30Z",
            "bucketName": "corp-customer-pii-vault",
            "objectKey": "private_keys_backup.tar.gz",
            "requester": "arn:aws:sts::123456789012:assumed-role/DataSyncRole/exfil-session-shadow-ops",
            "sessionName": "exfil-session-shadow-ops",
            "stsTokenHash": hashlib.sha256(b"ASIA99CLOUDEXFIL2026").hexdigest()[:16],
            "stsToken": "ASIA99CLOUDEXFIL2026",
            "bytesSent": 14626964,
            "httpStatus": 200,
            "sourceIP": "198.51.100.77"
        }
    ]


def get_initial_vpc_flow_logs() -> List[Dict[str, Any]]:
    logs = []
    base_time = 1760668800  # 2026-10-17 00:00:00
    # Regular internal traffic
    for i in range(5):
        logs.append({
            "version": 2,
            "account_id": "123456789012",
            "interface_id": "eni-0123456789abcdef0",
            "srcaddr": "10.0.1.10",
            "dstaddr": "10.0.2.20",
            "srcport": 54321 + i,
            "dstport": 443,
            "protocol": 6,
            "packets": 12,
            "bytes": 1450,
            "start": base_time + (i * 300),
            "end": base_time + (i * 300) + 15,
            "action": "ACCEPT",
            "log_status": "OK"
        })
    # Suspicious periodic C2 beaconing from 10.0.4.15 to 203.0.113.89:8443
    beacon_intervals = [0, 61, 119, 180, 242, 299, 360]
    for idx, delta in enumerate(beacon_intervals):
        logs.append({
            "version": 2,
            "account_id": "123456789012",
            "interface_id": "eni-0feebda123456789c",
            "srcaddr": "10.0.4.15",
            "dstaddr": "203.0.113.89",
            "srcport": 49152 + idx,
            "dstport": 8443,
            "protocol": 6,
            "packets": 24,
            "bytes": 8192,
            "start": base_time + 1000 + delta,
            "end": base_time + 1000 + delta + 3,
            "action": "ACCEPT",
            "log_status": "OK"
        })
    return logs


def get_initial_guardduty_findings() -> List[Dict[str, Any]]:
    return [
        {
            "id": "gd-find-001-sts-exfil",
            "type": "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS",
            "severity": 8.0,
            "title": "Credentials for EC2 role DataSyncRole were used from external IP 198.51.100.77",
            "description": "IAM session tokens generated by Instance Metadata Service were observed calling S3 GetObject outside the AWS network perimeter.",
            "resource": {
                "resourceType": "AccessKey",
                "accessKeyDetails": {
                    "accessKeyId": "ASIA99CLOUDEXFIL2026",
                    "userName": "DataSyncRole"
                }
            },
            "status": "ACTIVE"
        },
        {
            "id": "gd-find-002-c2-beacon",
            "type": "Trojan:EC2/DNSDataExfiltration",
            "severity": 8.5,
            "title": "EC2 instance i-0abcdef1234567890 is communicating with known C2 host 203.0.113.89",
            "description": "High frequency beaconing detected over port 8443 from private IP 10.0.4.15 matching threat actor infrastructure.",
            "resource": {
                "resourceType": "Instance",
                "instanceDetails": {
                    "instanceId": "i-0abcdef1234567890",
                    "privateIpAddress": "10.0.4.15"
                }
            },
            "status": "ACTIVE"
        }
    ]


STATE = {
    "stage1_solved": False,
    "stage2_solved": False,
    "stage3_solved": False,
    "stage4_solved": False,
    "cloudtrail_events": get_initial_cloudtrail_events(),
    "s3_exfil_logs": get_initial_s3_exfil_logs(),
    "vpc_flow_logs": get_initial_vpc_flow_logs(),
    "guardduty_findings": get_initial_guardduty_findings(),
    "containment_status": "UNCONTAINED",
    "soar_playbook_log": []
}


# ============================================================================
# Pydantic Models
# ============================================================================

class AnomalyAuditRequest(BaseModel):
    event_id: str = Field(..., description="Target CloudTrail event ID")
    source_ip: str = Field(..., description="Attacker Source IP Address")
    action: str = Field(..., description="Malicious API Action name")


class ExfilVerifyRequest(BaseModel):
    session_name: str = Field(..., description="Assumed role session name")
    compromised_token: str = Field(..., description="Leaked STS Access Token")
    target_bucket: str = Field(..., description="Targeted S3 bucket name")


class C2CorrelateRequest(BaseModel):
    compromised_ip: str = Field(..., description="Internal private IP of infected workload")
    c2_ip: str = Field(..., description="External C2 destination IP")
    c2_port: int = Field(..., description="Destination C2 port")
    protocol: str = Field(..., description="Network protocol (TCP or UDP)")


class SoarRemediationRequest(BaseModel):
    revoke_iam_sessions: bool = Field(..., description="Revoke active IAM STS sessions")
    apply_deny_boundary: bool = Field(..., description="Attach explicit deny permission boundary")
    quarantine_security_group: bool = Field(..., description="Isolate EC2 via empty quarantine security group")
    snapshot_ebs_volume: bool = Field(..., description="Snapshot EBS volumes for forensic chain of custody")


# ============================================================================
# API Endpoints
# ============================================================================

@app.get("/api/v1/status")
def get_status():
    """Return overall lab completion status and unlocked flags."""
    return {
        "lab": "Lab 43: CloudIRShield",
        "stages": {
            "stage1_cloudtrail_audit": {
                "solved": STATE["stage1_solved"],
                "flag": STAGE1_FLAG if STATE["stage1_solved"] else None
            },
            "stage2_sts_exfil": {
                "solved": STATE["stage2_solved"],
                "flag": STAGE2_FLAG if STATE["stage2_solved"] else None
            },
            "stage3_vpc_c2": {
                "solved": STATE["stage3_solved"],
                "flag": STAGE3_FLAG if STATE["stage3_solved"] else None
            },
            "stage4_guardduty_soar": {
                "solved": STATE["stage4_solved"],
                "flag": STAGE4_FLAG if STATE["stage4_solved"] else None
            }
        },
        "all_stages_solved": (
            STATE["stage1_solved"] and
            STATE["stage2_solved"] and
            STATE["stage3_solved"] and
            STATE["stage4_solved"]
        ),
        "containment_status": STATE["containment_status"]
    }


@app.post("/api/v1/reset")
def reset_state():
    """Reset lab simulation state back to default."""
    STATE["stage1_solved"] = False
    STATE["stage2_solved"] = False
    STATE["stage3_solved"] = False
    STATE["stage4_solved"] = False
    STATE["cloudtrail_events"] = get_initial_cloudtrail_events()
    STATE["s3_exfil_logs"] = get_initial_s3_exfil_logs()
    STATE["vpc_flow_logs"] = get_initial_vpc_flow_logs()
    STATE["guardduty_findings"] = get_initial_guardduty_findings()
    STATE["containment_status"] = "UNCONTAINED"
    STATE["soar_playbook_log"] = []
    return {"status": "success", "message": "Simulation state successfully reset."}


# --- Stage 1: CloudTrail Log Audit & Anomaly Detection ---

@app.get("/api/v1/cloudtrail/events")
def get_cloudtrail_events():
    """Retrieve raw CloudTrail management events."""
    return {"events": STATE["cloudtrail_events"], "total": len(STATE["cloudtrail_events"])}


@app.post("/api/v1/cloudtrail/detect-anomaly")
def detect_cloudtrail_anomaly(req: AnomalyAuditRequest):
    """Audit CloudTrail events and identify malicious privilege escalation."""
    target_event = None
    for ev in STATE["cloudtrail_events"]:
        if ev.get("eventId") == req.event_id:
            target_event = ev
            break

    if not target_event:
        raise HTTPException(status_code=404, detail="Event ID not found in CloudTrail audit repository.")

    # Validation criteria:
    # Event: evt-99482-admin-escalation
    # IP: 198.51.100.77
    # Action: AttachUserPolicy
    if (
        req.event_id == "evt-99482-admin-escalation" and
        req.source_ip.strip() == "198.51.100.77" and
        req.action.strip() == "AttachUserPolicy"
    ):
        STATE["stage1_solved"] = True
        return {
            "status": "success",
            "stage": 1,
            "message": "Critical CloudTrail privilege escalation anomaly identified! AdministratorAccess policy attached by unauthorized external IP.",
            "flag": STAGE1_FLAG
        }
    else:
        raise HTTPException(
            status_code=400,
            detail="Anomaly verification failed. Ensure event ID, external source IP, and high-risk API action match the malicious attack timeline."
        )


# --- Stage 2: STS Token Carving & S3 Data Exfiltration Forensics ---

@app.get("/api/v1/forensics/s3-exfil-logs")
def get_s3_exfil_logs():
    """Retrieve S3 access logs and STS token metadata."""
    return {"logs": STATE["s3_exfil_logs"], "total": len(STATE["s3_exfil_logs"])}


@app.post("/api/v1/forensics/verify-exfil")
def verify_s3_exfil(req: ExfilVerifyRequest):
    """Verify forensic attribution of STS token compromise and sensitive S3 exfiltration."""
    if not STATE["stage1_solved"]:
        raise HTTPException(status_code=403, detail="Complete Stage 1 CloudTrail audit before conducting deep STS exfiltration forensics.")

    if (
        req.session_name.strip() == "exfil-session-shadow-ops" and
        req.compromised_token.strip() == "ASIA99CLOUDEXFIL2026" and
        req.target_bucket.strip() == "corp-customer-pii-vault"
    ):
        STATE["stage2_solved"] = True
        return {
            "status": "success",
            "stage": 2,
            "message": "S3 data exfiltration traced! Compromised STS token ASIA99CLOUDEXFIL2026 used to exfiltrate 47.3MB of PII and private keys.",
            "flag": STAGE2_FLAG
        }
    else:
        raise HTTPException(
            status_code=400,
            detail="Forensic verification failed. Check the assumed session name, leaked STS token string, and target S3 vault bucket."
        )


# --- Stage 3: VPC Flow Logs Correlation & C2 Beacon Extraction ---

@app.get("/api/v1/vpc/flow-logs")
def get_vpc_flow_logs():
    """Retrieve VPC Flow Logs recorded at the network interface level."""
    return {"flow_logs": STATE["vpc_flow_logs"], "total": len(STATE["vpc_flow_logs"])}


@app.post("/api/v1/vpc/correlate-c2")
def correlate_vpc_c2(req: C2CorrelateRequest):
    """Correlate VPC flow logs to identify outbound C2 beaconing channel."""
    if not STATE["stage2_solved"]:
        raise HTTPException(status_code=403, detail="Complete Stage 2 STS forensics before correlating network VPC flow logs.")

    if (
        req.compromised_ip.strip() == "10.0.4.15" and
        req.c2_ip.strip() == "203.0.113.89" and
        req.c2_port == 8443 and
        req.protocol.strip().upper() == "TCP"
    ):
        STATE["stage3_solved"] = True
        return {
            "status": "success",
            "stage": 3,
            "message": "C2 beaconing channel correlated! Internal workload 10.0.4.15 established periodic 60s jittered TCP beacons to 203.0.113.89:8443.",
            "flag": STAGE3_FLAG
        }
    else:
        raise HTTPException(
            status_code=400,
            detail="C2 correlation failed. Confirm internal host IP, external C2 destination IP, destination port, and protocol."
        )


# --- Stage 4: GuardDuty Triage & Automated SOAR Containment Playbook ---

@app.get("/api/v1/guardduty/findings")
def get_guardduty_findings():
    """Retrieve active GuardDuty threat detection findings."""
    return {"findings": STATE["guardduty_findings"], "containment_status": STATE["containment_status"]}


@app.post("/api/v1/soar/contain-incident")
def trigger_soar_containment(req: SoarRemediationRequest):
    """Execute automated SOAR containment playbook across IAM, EC2, and Network layers."""
    if not STATE["stage3_solved"]:
        raise HTTPException(status_code=403, detail="Complete Stage 3 VPC C2 correlation before initiating active containment.")

    actions_executed = []
    if req.revoke_iam_sessions:
        actions_executed.append("Revoked active IAM STS session tokens for DataSyncRole.")
    if req.apply_deny_boundary:
        actions_executed.append("Applied SCP/Permissions Boundary: Explicit Deny on all outbound API calls.")
    if req.quarantine_security_group:
        actions_executed.append("Detached active SGs and attached sg-quarantine (0.0.0.0/0 ingress/egress blocked).")
    if req.snapshot_ebs_volume:
        actions_executed.append("Triggered automated forensic EBS volume snapshot snap-forensic-20261017.")

    if (
        req.revoke_iam_sessions and
        req.apply_deny_boundary and
        req.quarantine_security_group and
        req.snapshot_ebs_volume
    ):
        STATE["stage4_solved"] = True
        STATE["containment_status"] = "CONTAINED"
        STATE["soar_playbook_log"] = actions_executed
        # Archive findings
        for f in STATE["guardduty_findings"]:
            f["status"] = "ARCHIVED_CONTAINED"

        return {
            "status": "success",
            "stage": 4,
            "message": "SOAR automated containment playbook executed successfully! Workload quarantined, tokens revoked, and forensic snapshots preserved.",
            "executed_actions": actions_executed,
            "containment_status": "CONTAINED",
            "flag": STAGE4_FLAG
        }
    else:
        raise HTTPException(
            status_code=400,
            detail="Incomplete containment. Full remediation requires revoking IAM sessions, applying deny boundaries, quarantining SGs, and taking forensic snapshots."
        )


# ============================================================================
# HTML Dashboard UI
# ============================================================================

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="ko">
<head>
  <meta charset="UTF-8">
  <title>Lab 43: CloudIRShield — AWS & Multi-Cloud Incident Response & Threat Hunting</title>
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <style>
    :root {
      --bg: #090d16;
      --card-bg: #111827;
      --border: #1f293d;
      --accent: #38bdf8;
      --accent-glow: rgba(56, 189, 248, 0.2);
      --text: #e2e8f0;
      --text-dim: #94a3b8;
      --success: #10b981;
      --danger: #ef4444;
      --warning: #f59e0b;
      --font-mono: 'JetBrains Mono', 'Fira Code', monospace;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background: var(--bg);
      color: var(--text);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      padding: 24px;
      line-height: 1.6;
    }
    .container { max-width: 1200px; margin: 0 auto; }
    header {
      margin-bottom: 28px;
      border-bottom: 1px solid var(--border);
      padding-bottom: 20px;
    }
    h1 {
      font-size: 1.8rem;
      color: #fff;
      display: flex;
      align-items: center;
      gap: 12px;
    }
    .badge {
      display: inline-block;
      font-size: 0.75rem;
      padding: 4px 10px;
      border-radius: 9999px;
      font-weight: 600;
      background: #1e293b;
      color: var(--accent);
      border: 1px solid #334155;
    }
    .status-badge {
      padding: 4px 12px;
      border-radius: 6px;
      font-weight: bold;
      font-size: 0.85rem;
    }
    .status-uncontained { background: rgba(239, 68, 68, 0.2); color: var(--danger); border: 1px solid var(--danger); }
    .status-contained { background: rgba(16, 185, 129, 0.2); color: var(--success); border: 1px solid var(--success); }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(550px, 1fr)); gap: 24px; margin-bottom: 24px; }
    .card {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 20px;
      box-shadow: 0 4px 20px rgba(0,0,0,0.4);
    }
    .card h2 {
      font-size: 1.2rem;
      margin-bottom: 12px;
      color: var(--accent);
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    pre, code {
      font-family: var(--font-mono);
      font-size: 0.85rem;
    }
    pre {
      background: #060910;
      border: 1px solid #1e293b;
      padding: 12px;
      border-radius: 8px;
      overflow-x: auto;
      max-height: 240px;
      margin: 12px 0;
      color: #cbd5e1;
    }
    .btn {
      background: var(--accent);
      color: #040914;
      font-weight: 600;
      border: none;
      border-radius: 6px;
      padding: 8px 16px;
      cursor: pointer;
      transition: all 0.2s;
    }
    .btn:hover { opacity: 0.9; transform: translateY(-1px); }
    .btn-secondary { background: #334155; color: #fff; }
    .btn-danger { background: var(--danger); color: #fff; }
    input, select {
      background: #060910;
      border: 1px solid #334155;
      color: #fff;
      padding: 8px 12px;
      border-radius: 6px;
      font-size: 0.9rem;
      width: 100%;
      margin-bottom: 8px;
    }
    .flag-box {
      margin-top: 12px;
      padding: 10px;
      border-radius: 6px;
      background: rgba(16, 185, 129, 0.15);
      border: 1px solid var(--success);
      color: #34d399;
      font-family: var(--font-mono);
      font-weight: bold;
    }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <h1>
        <span>☁️ Lab 43: CloudIRShield</span>
        <span class="badge">Port 8043</span>
        <span id="containmentStatusBadge" class="status-badge status-uncontained">INCIDENT UNCONTAINED</span>
      </h1>
      <p style="color: var(--text-dim); margin-top: 6px;">
        엔터프라이즈 멀티 클라우드 침해사고 대응 &amp; 위협 헌팅 실습 (CloudTrail, STS, S3 Exfil, VPC Flow Logs, GuardDuty &amp; SOAR)
      </p>
    </header>

    <div class="grid">
      <!-- Stage 1 -->
      <div class="card">
        <h2>
          <span>1. CloudTrail Anomaly Audit</span>
          <span id="badge-stage1" class="badge">UNSOLVED</span>
        </h2>
        <p style="color: var(--text-dim); font-size: 0.9rem;">
          CloudTrail 감사 로그에서 비인가 외부 IP를 통한 권한 상승(`AttachUserPolicy`) 이벤트를 식별하세요.
        </p>
        <button class="btn btn-secondary" style="margin-top: 8px;" onclick="fetchCloudTrail()">Logs Fetch</button>
        <pre id="cloudtrail-pre">// Click 'Logs Fetch' to inspect CloudTrail records...</pre>
        <input type="text" id="s1-eventId" placeholder="Event ID (e.g. evt-99482-admin-escalation)">
        <input type="text" id="s1-sourceIp" placeholder="Attacker Source IP (e.g. 198.51.100.77)">
        <input type="text" id="s1-action" placeholder="Malicious Action (e.g. AttachUserPolicy)">
        <button class="btn" onclick="submitStage1()">Submit Anomaly Triage</button>
        <div id="flag-stage1" style="display:none;" class="flag-box"></div>
      </div>

      <!-- Stage 2 -->
      <div class="card">
        <h2>
          <span>2. STS &amp; S3 Exfiltration Forensics</span>
          <span id="badge-stage2" class="badge">UNSOLVED</span>
        </h2>
        <p style="color: var(--text-dim); font-size: 0.9rem;">
          유출된 STS 토큰을 사용해 민감 S3 버킷에서 고객 PII 및 비밀키를 대량 탈취한 정황을 복원하세요.
        </p>
        <button class="btn btn-secondary" style="margin-top: 8px;" onclick="fetchS3Logs()">S3 Logs Fetch</button>
        <pre id="s3-pre">// Click 'S3 Logs Fetch' to inspect S3 Data Access logs...</pre>
        <input type="text" id="s2-session" placeholder="Assumed Session Name (e.g. exfil-session-shadow-ops)">
        <input type="text" id="s2-token" placeholder="Compromised STS Token (e.g. ASIA...)">
        <input type="text" id="s2-bucket" placeholder="Target S3 Vault (e.g. corp-customer-pii-vault)">
        <button class="btn" onclick="submitStage2()">Verify Exfiltration</button>
        <div id="flag-stage2" style="display:none;" class="flag-box"></div>
      </div>

      <!-- Stage 3 -->
      <div class="card">
        <h2>
          <span>3. VPC Flow Logs &amp; C2 Beaconing</span>
          <span id="badge-stage3" class="badge">UNSOLVED</span>
        </h2>
        <p style="color: var(--text-dim); font-size: 0.9rem;">
          서브넷 VPC Flow Logs에서 내부 감염 인스턴스(`10.0.4.15`)가 외부 C2 IP로 발송하는 주기적 비콘 세션을 추출하세요.
        </p>
        <button class="btn btn-secondary" style="margin-top: 8px;" onclick="fetchVpcLogs()">VPC Flows Fetch</button>
        <pre id="vpc-pre">// Click 'VPC Flows Fetch' to inspect VPC NetFlows...</pre>
        <input type="text" id="s3-host" placeholder="Compromised Private Host IP (e.g. 10.0.4.15)">
        <input type="text" id="s3-c2" placeholder="External C2 IP (e.g. 203.0.113.89)">
        <input type="number" id="s3-port" placeholder="Destination C2 Port (e.g. 8443)">
        <input type="text" id="s3-proto" placeholder="Protocol (TCP)">
        <button class="btn" onclick="submitStage3()">Correlate C2 Channel</button>
        <div id="flag-stage3" style="display:none;" class="flag-box"></div>
      </div>

      <!-- Stage 4 -->
      <div class="card">
        <h2>
          <span>4. GuardDuty Triage &amp; SOAR Containment</span>
          <span id="badge-stage4" class="badge">UNSOLVED</span>
        </h2>
        <p style="color: var(--text-dim); font-size: 0.9rem;">
          GuardDuty 보안 경보를 확인하고 IAM 토큰 무효화, Deny 경계 적용, 보안그룹 격리, EBS 스냅샷 수집 SOAR 플레이북을 실행하세요.
        </p>
        <button class="btn btn-secondary" style="margin-top: 8px;" onclick="fetchGuardDuty()">Findings Fetch</button>
        <pre id="gd-pre">// Click 'Findings Fetch' to inspect active GuardDuty detections...</pre>
        <button class="btn btn-danger" style="width:100%;" onclick="executeSoar()">Execute Automated SOAR Containment</button>
        <div id="flag-stage4" style="display:none;" class="flag-box"></div>
      </div>
    </div>
  </div>

  <script>
    async function updateStatus() {
      const res = await fetch('/api/v1/status');
      const data = await res.json();
      const badge = document.getElementById('containmentStatusBadge');
      if (data.containment_status === 'CONTAINED') {
        badge.textContent = 'INCIDENT CONTAINED';
        badge.className = 'status-badge status-contained';
      } else {
        badge.textContent = 'INCIDENT UNCONTAINED';
        badge.className = 'status-badge status-uncontained';
      }
      for (let i = 1; i <= 4; i++) {
        const key = ['stage1_cloudtrail_audit', 'stage2_sts_exfil', 'stage3_vpc_c2', 'stage4_guardduty_soar'][i-1];
        const solved = data.stages[key].solved;
        const b = document.getElementById('badge-stage' + i);
        const f = document.getElementById('flag-stage' + i);
        if (solved) {
          b.textContent = 'SOLVED';
          b.style.color = '#34d399';
          b.style.borderColor = '#10b981';
          f.style.display = 'block';
          f.textContent = data.stages[key].flag;
        }
      }
    }

    async function fetchCloudTrail() {
      const res = await fetch('/api/v1/cloudtrail/events');
      const data = await res.json();
      document.getElementById('cloudtrail-pre').textContent = JSON.stringify(data.events, null, 2);
    }

    async function submitStage1() {
      const payload = {
        event_id: document.getElementById('s1-eventId').value.trim(),
        source_ip: document.getElementById('s1-sourceIp').value.trim(),
        action: document.getElementById('s1-action').value.trim()
      };
      const res = await fetch('/api/v1/cloudtrail/detect-anomaly', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      const data = await res.json();
      if (res.ok) {
        alert('Stage 1 Solved!');
        updateStatus();
      } else {
        alert(data.detail || 'Failed');
      }
    }

    async function fetchS3Logs() {
      const res = await fetch('/api/v1/forensics/s3-exfil-logs');
      const data = await res.json();
      document.getElementById('s3-pre').textContent = JSON.stringify(data.logs, null, 2);
    }

    async function submitStage2() {
      const payload = {
        session_name: document.getElementById('s2-session').value.trim(),
        compromised_token: document.getElementById('s2-token').value.trim(),
        target_bucket: document.getElementById('s2-bucket').value.trim()
      };
      const res = await fetch('/api/v1/forensics/verify-exfil', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      const data = await res.json();
      if (res.ok) {
        alert('Stage 2 Solved!');
        updateStatus();
      } else {
        alert(data.detail || 'Failed');
      }
    }

    async function fetchVpcLogs() {
      const res = await fetch('/api/v1/vpc/flow-logs');
      const data = await res.json();
      document.getElementById('vpc-pre').textContent = JSON.stringify(data.flow_logs, null, 2);
    }

    async function submitStage3() {
      const payload = {
        compromised_ip: document.getElementById('s3-host').value.trim(),
        c2_ip: document.getElementById('s3-c2').value.trim(),
        c2_port: parseInt(document.getElementById('s3-port').value),
        protocol: document.getElementById('s3-proto').value.trim()
      };
      const res = await fetch('/api/v1/vpc/correlate-c2', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      const data = await res.json();
      if (res.ok) {
        alert('Stage 3 Solved!');
        updateStatus();
      } else {
        alert(data.detail || 'Failed');
      }
    }

    async function fetchGuardDuty() {
      const res = await fetch('/api/v1/guardduty/findings');
      const data = await res.json();
      document.getElementById('gd-pre').textContent = JSON.stringify(data.findings, null, 2);
    }

    async function executeSoar() {
      const payload = {
        revoke_iam_sessions: true,
        apply_deny_boundary: true,
        quarantine_security_group: true,
        snapshot_ebs_volume: true
      };
      const res = await fetch('/api/v1/soar/contain-incident', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      const data = await res.json();
      if (res.ok) {
        alert('Stage 4 Solved! SOAR Containment Playbook Executed.');
        updateStatus();
      } else {
        alert(data.detail || 'Failed');
      }
    }

    window.onload = updateStatus;
  </script>
</body>
</html>
"""

@app.get("/", response_class=HTMLResponse)
def index_page():
    """Render interactive dashboard for Lab 43."""
    return HTMLResponse(content=HTML_TEMPLATE, status_code=200)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8043, reload=True)
