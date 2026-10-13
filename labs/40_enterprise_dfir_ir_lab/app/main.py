#!/usr/bin/env python3
"""
Lab 40: IRShield — Enterprise DFIR & Incident Response Lab
Interactive FastAPI service demonstrating enterprise digital forensics & incident response:
1. Live Process & Memory Triage (PPID Spoofing & Reflective DLL Detection)
2. MFT Timeline & Ransomware Artifact Forensics ($MFT, USN Journal, Shadow Copy Deletion)
3. C2 Network Beaconing & Containment Isolation (Beacon Jitter Analysis & Host Isolation)
4. SOAR Automated Remediation & Recovery Verification (Persistence Eradication & Snapshot Integrity)
"""

from typing import Dict, Any, List, Optional
import os
import hashlib
import json
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field

app = FastAPI(
    title="Lab 40: IRShield — Enterprise DFIR & Incident Response Lab",
    description="Hands-on enterprise digital forensics and incident response simulation with memory triage, MFT analysis, network containment, and SOAR remediation.",
    version="1.0.0",
)

# Flags
STAGE1_FLAG = "FLAG{dfir_live_process_triage_pid4920_detected}"
STAGE2_FLAG = "FLAG{dfir_mft_timeline_vssadmin_ransom_unmasked}"
STAGE3_FLAG = "FLAG{dfir_c2_network_isolation_firewall_locked}"
STAGE4_FLAG = "FLAG{dfir_soar_playbook_enterprise_remediated_100}"

# ============================================================================
# Simulation Data & In-Memory State
# ============================================================================

STATE = {
    "stage1_solved": False,
    "stage2_solved": False,
    "stage3_solved": False,
    "stage4_solved": False,
    "contained_host": False,
    "firewall_blocked_ip": None,
    "remediated_items": [],
}

MOCK_PROCESSES = [
    {
        "pid": 4,
        "name": "System",
        "ppid": 0,
        "creator_pid": 0,
        "path": "C:\\Windows\\System32\\ntoskrnl.exe",
        "integrity": "SYSTEM",
        "unbacked_memory": False,
        "suspicious_modules": [],
    },
    {
        "pid": 388,
        "name": "smss.exe",
        "ppid": 4,
        "creator_pid": 4,
        "path": "C:\\Windows\\System32\\smss.exe",
        "integrity": "SYSTEM",
        "unbacked_memory": False,
        "suspicious_modules": [],
    },
    {
        "pid": 584,
        "name": "csrss.exe",
        "ppid": 388,
        "creator_pid": 388,
        "path": "C:\\Windows\\System32\\csrss.exe",
        "integrity": "SYSTEM",
        "unbacked_memory": False,
        "suspicious_modules": [],
    },
    {
        "pid": 788,
        "name": "services.exe",
        "ppid": 584,
        "creator_pid": 584,
        "path": "C:\\Windows\\System32\\services.exe",
        "integrity": "SYSTEM",
        "unbacked_memory": False,
        "suspicious_modules": [],
    },
    {
        "pid": 804,
        "name": "lsass.exe",
        "ppid": 788,
        "creator_pid": 788,
        "path": "C:\\Windows\\System32\\lsass.exe",
        "integrity": "SYSTEM",
        "unbacked_memory": False,
        "suspicious_modules": [],
    },
    {
        "pid": 1024,
        "name": "svchost.exe",
        "ppid": 788,
        "creator_pid": 788,
        "path": "C:\\Windows\\System32\\svchost.exe",
        "integrity": "SYSTEM",
        "unbacked_memory": False,
        "suspicious_modules": [],
    },
    {
        "pid": 3480,
        "name": "powershell.exe",
        "ppid": 1024,
        "creator_pid": 1024,
        "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "integrity": "High",
        "unbacked_memory": False,
        "suspicious_modules": [],
    },
    {
        "pid": 4920,
        "name": "spoolsv.exe",
        "ppid": 788,  # Claimed parent: services.exe via PROC_THREAD_ATTRIBUTE_PARENT_PROCESS spoofing
        "creator_pid": 3480,  # Actual creator process was powershell.exe!
        "path": "C:\\Windows\\System32\\spoolsv.exe",
        "integrity": "SYSTEM",
        "unbacked_memory": True,  # Memory region 0x7ffe0000 has PAGE_EXECUTE_READWRITE without backing file
        "suspicious_modules": ["msvcrt_reflective_loader.dll"],
        "sha256": "4b6e82c5f11079d86a4ea2775f28c279a02936a282f6406dbd0e6d6c4a6b281f",
    },
]

MOCK_MFT_EVENTS = [
    {
        "record_number": 12040,
        "timestamp": "2026-10-13T01:13:40Z",
        "event_type": "PROCESS_SPAWN",
        "filename": "cmd.exe",
        "details": "Spawning administrative CLI for staging",
    },
    {
        "record_number": 31055,
        "timestamp": "2026-10-13T01:14:02Z",
        "event_type": "SHADOW_DELETION",
        "filename": "vssadmin.exe",
        "command_line": "vssadmin.exe delete shadows /all /quiet",
        "details": "Wiping Volume Shadow Copies to prevent system restore",
    },
    {
        "record_number": 31059,
        "timestamp": "2026-10-13T01:14:05Z",
        "event_type": "BACKUP_WIPE",
        "filename": "wbadmin.exe",
        "command_line": "wbadmin.exe DELETE SYSTEMSTATEBACKUP",
        "details": "Catalog deletion executed",
    },
    {
        "record_number": 84912,
        "timestamp": "2026-10-13T01:14:18Z",
        "event_type": "BULK_RENAME_ENCRYPT",
        "filename": "finance_q3.xlsx.locked",
        "original_name": "finance_q3.xlsx",
        "entropy": 7.98,
        "details": "Symmetric AES-256 payload encryption with appended RSA header",
    },
    {
        "record_number": 84913,
        "timestamp": "2026-10-13T01:14:20Z",
        "event_type": "BULK_RENAME_ENCRYPT",
        "filename": "customer_database.db.locked",
        "original_name": "customer_database.db",
        "entropy": 7.99,
        "details": "Database storage encryption",
    },
    {
        "record_number": 84950,
        "timestamp": "2026-10-13T01:14:30Z",
        "event_type": "RANSOM_NOTE_DROP",
        "filename": "HOW_TO_DECRYPT_FILES.txt",
        "details": "Ransom notice dropped. Victim ID: DARKIR-40-RECOVERY, BTC: bc1qdfir40shieldransomwaremasterkey",
    },
]

MOCK_NETWORK_TELEMETRY = [
    {
        "protocol": "TCP",
        "local_address": "10.0.0.45:49810",
        "remote_address": "198.51.100.77:8443",
        "domain": "c2-beacon.darkops.internal",
        "beacon_interval_sec": 60,
        "jitter_percentage": 15,
        "traffic_type": "HTTPS_POST_BEACON",
        "payload_bytes": 512,
        "status": "ESTABLISHED",
    },
    {
        "protocol": "UDP",
        "local_address": "10.0.0.45:53312",
        "remote_address": "8.8.8.8:53",
        "domain": "chunk01.tunnel.darkops.internal",
        "beacon_interval_sec": 0,
        "jitter_percentage": 0,
        "traffic_type": "DNS_TUNNEL_TXT_QUERY",
        "payload_bytes": 128,
        "status": "SENT",
    },
    {
        "protocol": "TCP",
        "local_address": "10.0.0.45:49822",
        "remote_address": "20.190.159.0:443",
        "domain": "login.microsoftonline.com",
        "beacon_interval_sec": 0,
        "jitter_percentage": 0,
        "traffic_type": "LEGITIMATE_O365_SYNC",
        "payload_bytes": 4096,
        "status": "ESTABLISHED",
    },
]

MOCK_PERSISTENCE_AUDIT = [
    {
        "type": "SCHEDULED_TASK",
        "id": "task_cache_update",
        "path": "\\Microsoft\\Windows\\AppId\\CacheUpdate",
        "action": "powershell.exe -WindowStyle Hidden -Enc JABj... (C2 Stage Loader)",
        "status": "ACTIVE",
    },
    {
        "type": "WMI_EVENT_SUBSCRIPTION",
        "id": "wmi_filter_consumer",
        "filter": "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'",
        "consumer": "CommandLineEventConsumer.Name='Win32_ServiceFilter'",
        "status": "ACTIVE",
    },
    {
        "type": "SUSPECT_PROCESS",
        "id": "process_pid4920",
        "name": "spoolsv.exe",
        "pid": 4920,
        "status": "RUNNING",
    },
    {
        "type": "AIRGAPPED_SNAPSHOT",
        "id": "snapshot_clean_gold_v1",
        "status": "AVAILABLE_FOR_RESTORE",
        "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    },
]

# ============================================================================
# Pydantic Request Models
# ============================================================================

class Stage1TriageRequest(BaseModel):
    suspect_pid: int = Field(..., description="Suspect anomalous process PID")
    detection_reason: str = Field(..., description="Detection reason, e.g. 'ppid_spoofing'")

class Stage2MftRequest(BaseModel):
    shadow_deletion_cmd: str = Field(..., description="Exact command line used for shadow deletion")
    ransom_extension: str = Field(..., description="Encrypted file extension")
    mft_record: int = Field(..., description="MFT record number of first encrypted data file")

class Stage3ContainRequest(BaseModel):
    c2_ip: str = Field(..., description="Identified C2 Server IP")
    c2_port: int = Field(..., description="C2 Server Port")
    isolation_mode: str = Field(..., description="Host containment mode, e.g. 'isolate_host'")
    block_firewall: bool = Field(..., description="Whether to enact firewall blocking rule")

class Stage4RemediateRequest(BaseModel):
    remediation_actions: List[str] = Field(..., description="List of remediation actions to execute in order")

# ============================================================================
# API Routes
# ============================================================================

@app.get("/", response_class=HTMLResponse)
async def get_index():
    """Interactive Cyber Forensics Web Dashboard."""
    return """<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="utf-8">
    <title>Lab 40: IRShield — Enterprise DFIR & Incident Response Lab</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, monospace; background: #0b0f19; color: #e2e8f0; margin: 0; padding: 24px; }
        .card { background: #161e2e; border: 1px solid #2d3748; border-radius: 8px; padding: 20px; margin-bottom: 20px; }
        h1, h2, h3 { color: #38bdf8; margin-top: 0; }
        .badge { display: inline-block; padding: 4px 10px; border-radius: 4px; font-weight: bold; font-size: 12px; }
        .badge-green { background: #065f46; color: #34d399; }
        .badge-red { background: #991b1b; color: #f87171; }
        .badge-blue { background: #1e40af; color: #93c5fd; }
        pre { background: #0f172a; border: 1px solid #1e293b; padding: 12px; border-radius: 6px; overflow-x: auto; color: #38bdf8; }
        table { width: 100%; border-collapse: collapse; margin-top: 10px; }
        th, td { border: 1px solid #334155; padding: 8px 12px; text-align: left; }
        th { background: #1e293b; color: #94a3b8; }
    </style>
</head>
<body>
    <div class="card">
        <h1>🛡️ Lab 40: IRShield — Enterprise DFIR & Incident Response</h1>
        <p>침해사고 라이브 메모리 트리아지, MFT 타임라인 분석, C2 네트워크 격리, SOAR 자동 복구 플레이북 실습 랩</p>
        <span class="badge badge-blue">Port: 8040</span>
        <span class="badge badge-green">NIST SP 800-61 / RFC 3227 준수</span>
    </div>

    <div class="card">
        <h2>실습 4단계 안내</h2>
        <ul>
            <li><strong>Stage 1 (라이브 프로세스 & 메모리 트리아지)</strong>: <code>GET /api/stage1/processes</code> & <code>POST /api/stage1/triage</code></li>
            <li><strong>Stage 2 (MFT 타임라인 & 랜섬웨어 아티팩트 분석)</strong>: <code>GET /api/stage2/mft-events</code> & <code>POST /api/stage2/mft-analyze</code></li>
            <li><strong>Stage 3 (C2 비콘 탐지 & 호스트 네트워크 격리)</strong>: <code>GET /api/stage3/network-connections</code> & <code>POST /api/stage3/contain</code></li>
            <li><strong>Stage 4 (SOAR 지속성 제거 & 복구 무결성 검증)</strong>: <code>GET /api/stage4/persistence-audit</code> & <code>POST /api/stage4/remediate</code></li>
        </ul>
        <p>상세 문서는 <a href="/docs" style="color: #38bdf8;">/docs</a> Swagger UI에서 확인하세요.</p>
    </div>
</body>
</html>
"""

@app.get("/api/status")
async def get_lab_status():
    """Return status of all lab stages."""
    return {
        "lab": "Lab 40: IRShield — Enterprise DFIR & Incident Response Lab",
        "stages": {
            "stage1_process_triage": STATE["stage1_solved"],
            "stage2_mft_timeline": STATE["stage2_solved"],
            "stage3_c2_containment": STATE["stage3_solved"],
            "stage4_soar_remediation": STATE["stage4_solved"],
        },
        "all_stages_completed": (
            STATE["stage1_solved"] and
            STATE["stage2_solved"] and
            STATE["stage3_solved"] and
            STATE["stage4_solved"]
        ),
    }

@app.post("/api/reset")
async def reset_lab_state():
    """Reset lab state back to initial."""
    STATE["stage1_solved"] = False
    STATE["stage2_solved"] = False
    STATE["stage3_solved"] = False
    STATE["stage4_solved"] = False
    STATE["contained_host"] = False
    STATE["firewall_blocked_ip"] = None
    STATE["remediated_items"] = []
    return {"status": "success", "message": "Lab 40 simulation state has been reset."}

# ============================================================================
# Stage 1: Live Process & Memory Triage
# ============================================================================

@app.get("/api/stage1/processes")
async def get_stage1_processes():
    """Return live host process telemetry with PPID and memory attributes."""
    return {
        "host": "CORP-WKS-042.internal",
        "os": "Windows Server 2025 Standard",
        "processes": MOCK_PROCESSES,
    }

@app.post("/api/stage1/triage")
async def post_stage1_triage(req: Stage1TriageRequest):
    """
    Triage suspicious process hiding via PPID spoofing or unbacked reflective DLL.
    Expected: PID 4920 (spoolsv.exe) with 'ppid_spoofing' reason.
    """
    if req.suspect_pid != 4920:
        raise HTTPException(
            status_code=400,
            detail=f"PID {req.suspect_pid} is a legitimate process without anomalous lineage.",
        )
    
    clean_reason = req.detection_reason.strip().lower()
    if clean_reason not in ["ppid_spoofing", "ppid spoofing", "unbacked_memory", "reflective_dll"]:
        raise HTTPException(
            status_code=400,
            detail="Detection reason must pinpoint 'ppid_spoofing' or 'unbacked_memory'.",
        )
    
    STATE["stage1_solved"] = True
    return {
        "status": "success",
        "message": "Anomalous process identified: PID 4920 spoofed parent services.exe while actually spawned by powershell.exe with unbacked reflective DLL.",
        "flag": STAGE1_FLAG,
    }

# ============================================================================
# Stage 2: MFT Timeline & Ransomware Artifact Forensics
# ============================================================================

@app.get("/api/stage2/mft-events")
async def get_stage2_mft_events():
    """Return $MFT file record timeline and USN Journal events."""
    return {
        "volume": "C: (NTFS)",
        "journal_events": MOCK_MFT_EVENTS,
    }

@app.post("/api/stage2/mft-analyze")
async def post_stage2_mft_analyze(req: Stage2MftRequest):
    """
    Analyze MFT timeline: shadow deletion command, ransom extension, and encrypted file MFT record.
    Expected:
    - shadow_deletion_cmd: 'vssadmin.exe delete shadows /all /quiet'
    - ransom_extension: '.locked'
    - mft_record: 84912
    """
    norm_cmd = req.shadow_deletion_cmd.strip()
    if "vssadmin" not in norm_cmd.lower() or "delete shadows" not in norm_cmd.lower():
        raise HTTPException(
            status_code=400,
            detail="Invalid shadow deletion command. Check MFT record #31055.",
        )
    
    norm_ext = req.ransom_extension.strip().lower()
    if norm_ext not in [".locked", "locked"]:
        raise HTTPException(
            status_code=400,
            detail="Incorrect ransomware encrypted file extension. Check records #84912-#84913.",
        )
    
    if req.mft_record != 84912:
        raise HTTPException(
            status_code=400,
            detail=f"MFT record {req.mft_record} is not the initial encrypted document.",
        )
    
    STATE["stage2_solved"] = True
    return {
        "status": "success",
        "message": "Forensic reconstruction confirmed: Shadow copy deletion and massive encryption of record 84912 mapped to ransomware campaign.",
        "flag": STAGE2_FLAG,
    }

# ============================================================================
# Stage 3: C2 Network Beaconing & Containment Isolation
# ============================================================================

@app.get("/api/stage3/network-connections")
async def get_stage3_network_connections():
    """Return live network connection telemetry."""
    return {
        "telemetry": MOCK_NETWORK_TELEMETRY,
        "firewall_rules": {
            "blocked_ip": STATE["firewall_blocked_ip"],
            "host_isolated": STATE["contained_host"],
        },
    }

@app.post("/api/stage3/contain")
async def post_stage3_contain(req: Stage3ContainRequest):
    """
    Enact containment: identify C2 destination IP (198.51.100.77), port 8443, and isolate host.
    """
    if req.c2_ip.strip() != "198.51.100.77":
        raise HTTPException(
            status_code=400,
            detail=f"IP {req.c2_ip} is not the malicious C2 beacon destination.",
        )
    
    if req.c2_port != 8443:
        raise HTTPException(
            status_code=400,
            detail=f"Port {req.c2_port} does not match C2 beacon destination port.",
        )
    
    if not req.block_firewall:
        raise HTTPException(
            status_code=400,
            detail="Containment requires blocking firewall rule for C2 communication.",
        )
    
    clean_mode = req.isolation_mode.strip().lower()
    if clean_mode not in ["isolate_host", "network_isolation", "contain"]:
        raise HTTPException(
            status_code=400,
            detail="Isolation mode must be 'isolate_host' or 'network_isolation'.",
        )
    
    STATE["stage3_solved"] = True
    STATE["contained_host"] = True
    STATE["firewall_blocked_ip"] = req.c2_ip
    return {
        "status": "success",
        "message": f"Containment activated: C2 IP {req.c2_ip}:{req.c2_port} blocked, host isolated from enterprise VLAN.",
        "flag": STAGE3_FLAG,
    }

# ============================================================================
# Stage 4: SOAR Automated Remediation & Recovery Verification
# ============================================================================

@app.get("/api/stage4/persistence-audit")
async def get_stage4_persistence_audit():
    """Return persistence artifacts and snapshot recovery options."""
    return {
        "persistence_items": MOCK_PERSISTENCE_AUDIT,
        "remediated_actions": STATE["remediated_items"],
    }

@app.post("/api/stage4/remediate")
async def post_stage4_remediate(req: Stage4RemediateRequest):
    """
    Execute comprehensive SOAR remediation playbook.
    Requires all 4 actions:
    - remove_scheduled_task
    - kill_suspect_process
    - clean_wmi_subscription
    - restore_immutable_snapshot
    """
    req_actions = set(a.strip().lower() for a in req.remediation_actions)
    expected_actions = {
        "remove_scheduled_task",
        "kill_suspect_process",
        "clean_wmi_subscription",
        "restore_immutable_snapshot",
    }
    
    missing = expected_actions - req_actions
    if missing:
        raise HTTPException(
            status_code=400,
            detail=f"Incomplete remediation playbook. Missing required actions: {sorted(list(missing))}",
        )
    
    STATE["stage4_solved"] = True
    STATE["remediated_items"] = list(req_actions)
    
    return {
        "status": "success",
        "message": "SOAR remediation completed: Malicious scheduled task removed, WMI consumer cleaned, suspect PID 4920 terminated, and immutable gold snapshot restored with SHA-256 integrity verified.",
        "flag": STAGE4_FLAG,
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8040)
