#!/usr/bin/env python3
"""
Lab 50: ArtifactHunter — SANS DFIR Enterprise Threat Hunting & Timeline Lab
Interactive simulation based on SANS FOR508 & FOR572 methodologies:
1. Evidence of Execution: Prefetch (PECmd) & ShimCache/Amcache triage
2. File Knowledge & Deletion Carving: $MFT Data Run, $LogFile, USN Journal
3. Memory Forensics & Injection Analysis: Volatility 3, DKOM unlinking, RWX VAD triage
4. Network Carving & Supertimeline: SANS FOR572 tshark analysis, Plaso timeline, SOAR isolation
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
    title="Lab 50: ArtifactHunter — SANS DFIR Threat Hunting Lab",
    description="Interactive simulation of SANS FOR508 & FOR572 enterprise incident response and artifact analysis.",
    version="1.0.0",
)

# Flags
STAGE1_FLAG = "FLAG{SANS_DFIR_EXEC_PREFETCH_SHIMCACHE_8821}"
STAGE2_FLAG = "FLAG{SANS_DFIR_MFT_USN_JOURNAL_CARVED_9932}"
STAGE3_FLAG = "FLAG{SANS_DFIR_MEMORY_VAD_INJECTION_DKOM_7743}"
STAGE4_FLAG = "FLAG{SANS_DFIR_SUPETIMELINE_RECON_ISOLATED_6612}"


class LabState:
    def __init__(self):
        self.reset()

    def reset(self):
        self.stage1_completed = False
        self.stage2_completed = False
        self.stage3_completed = False
        self.stage4_completed = False

        self.last_evidence = None
        self.host_isolated = False


state = LabState()


class ExecutionTriageRequest(BaseModel):
    artifact_type: str = Field(..., description="prefetch, shimcache, amcache, userassist")
    target_evidence: str = Field(..., description="Artifact identifier or file hash/name")


class FileSystemCarveRequest(BaseModel):
    mft_record_number: int = Field(..., description="Target NTFS $MFT entry record number")
    usn_reason_flag: str = Field(..., description="USN Journal operation reason (e.g. USN_REASON_FILE_DELETE)")


class MemoryInjectionTriageRequest(BaseModel):
    target_pid: int = Field(..., description="Suspicious process ID to analyze")
    vad_protection: str = Field(..., description="VAD memory protection flag, e.g. PAGE_EXECUTE_READWRITE")
    unhook_dkom: bool = Field(True, description="Correlate unlinked EPROCESS via psscan")


class SupertimelineIsolateRequest(BaseModel):
    tshark_display_filter: str = Field(..., description="Wireshark/tshark packet filter expression")
    isolate_host: bool = Field(True, description="Trigger automated containment quarantine")


@app.get("/", response_class=HTMLResponse)
def index():
    return f"""<!DOCTYPE html>
<html>
<head>
    <title>Lab 50: ArtifactHunter - SANS DFIR Threat Hunting Lab</title>
    <style>
        body {{ font-family: monospace; background: #0d1117; color: #c9d1d9; padding: 20px; }}
        h1 {{ color: #58a6ff; }}
        .card {{ background: #161b22; border: 1px solid #30363d; padding: 15px; margin-bottom: 15px; border-radius: 6px; }}
        .badge {{ display: inline-block; padding: 3px 8px; border-radius: 4px; font-weight: bold; font-size: 12px; }}
        .badge-green {{ background: #238636; color: white; }}
        .badge-red {{ background: #da3633; color: white; }}
    </style>
</head>
<body>
    <h1>🔍 Lab 50: ArtifactHunter — SANS DFIR Enterprise Threat Hunting Lab</h1>
    <p>포트 <b>8050</b> | SANS FOR508/572: 실행 흔적(PECmd), $MFT/USN 저널, Volatility 3 VAD 인젝션 및 슈퍼타임라인 격리</p>
    
    <div class="card">
        <h3>실습 단계 현황</h3>
        <p>Stage 1 (Evidence of Execution): <span class="badge {'badge-green' if state.stage1_completed else 'badge-red'}">{'COMPLETED' if state.stage1_completed else 'PENDING'}</span></p>
        <p>Stage 2 (MFT & USN Journal Carving): <span class="badge {'badge-green' if state.stage2_completed else 'badge-red'}">{'COMPLETED' if state.stage2_completed else 'PENDING'}</span></p>
        <p>Stage 3 (Memory Injection & DKOM Triage): <span class="badge {'badge-green' if state.stage3_completed else 'badge-red'}">{'COMPLETED' if state.stage3_completed else 'PENDING'}</span></p>
        <p>Stage 4 (Network Carving & Supertimeline): <span class="badge {'badge-green' if state.stage4_completed else 'badge-red'}">{'COMPLETED' if state.stage4_completed else 'PENDING'}</span></p>
    </div>
</body>
</html>"""


@app.get("/status")
def get_status():
    return {
        "lab": "50_sans_dfir_hunting_lab",
        "port": 8050,
        "stages": {
            "stage1_execution_evidence": state.stage1_completed,
            "stage2_filesystem_carving": state.stage2_completed,
            "stage3_memory_injection": state.stage3_completed,
            "stage4_supertimeline_isolation": state.stage4_completed,
        },
        "host_isolated": state.host_isolated,
    }


@app.post("/api/stage1/analyze_execution")
def stage1_analyze_execution(req: ExecutionTriageRequest):
    """
    Stage 1: Evidence of Execution Triage (PECmd, ShimCache, Amcache)
    Target: Detect unauthorized binary execution and reconstruct execution timestamp.
    """
    valid_artifacts = ["prefetch", "shimcache", "amcache", "userassist", "bam"]
    art = req.artifact_type.strip().lower()
    if art not in valid_artifacts:
        raise HTTPException(status_code=400, detail=f"Invalid artifact type: {req.artifact_type}. Expected: {valid_artifacts}")

    evidence = req.target_evidence.strip()
    if not evidence or len(evidence) < 4:
        raise HTTPException(status_code=400, detail="Target evidence identifier must be provided")

    # Match suspicious payload in artifact
    if any(k in evidence.upper() for k in ["MIMIKATZ", "BEACON", "COBALT", "REV.EXE", "B7A21F8C"]):
        state.stage1_completed = True
        state.last_evidence = evidence
        return {
            "status": "success",
            "stage": 1,
            "artifact": art,
            "findings": {
                "executable": evidence,
                "run_count": 4,
                "last_run_utc": "2026-10-24 14:22:18",
                "volume_guid": "7B82-3A19",
                "loaded_dlls": ["ntdll.dll", "kernel32.dll", "advapi32.dll", "crypt32.dll"],
            },
            "flag": STAGE1_FLAG,
            "message": "✓ Evidence of execution confirmed through PECmd parser!",
        }

    return {
        "status": "inconclusive",
        "stage": 1,
        "message": "Evidence did not reveal unauthorized offensive execution artifacts. Inspect malicious staging binaries.",
    }


@app.post("/api/stage2/carve_filesystem")
def stage2_carve_filesystem(req: FileSystemCarveRequest):
    """
    Stage 2: NTFS $MFT & USN Journal Timeline Reconstruction
    Target: Carve deleted evidence and detect timestomping ($STD vs $FN timestamps).
    """
    if req.mft_record_number <= 0:
        raise HTTPException(status_code=400, detail="MFT record number must be a positive integer")

    reason = req.usn_reason_flag.strip().upper()
    if "DELETE" not in reason and "RENAME" not in reason:
        raise HTTPException(status_code=400, detail="USN Journal reason must indicate FILE_DELETE or FILE_RENAME_OLD_NAME")

    state.stage2_completed = True
    return {
        "status": "success",
        "stage": 2,
        "record_number": req.mft_record_number,
        "usn_reason": reason,
        "analysis": {
            "filename": "payload_stager.dll",
            "file_size": 184320,
            "data_runs": "0x32 0x14 0x2A100 (Cluster 172288)",
            "si_timestamp": "2024-01-01 00:00:00 (Timestomped)",
            "fn_timestamp": "2026-10-24 14:21:40 (Authentic Record)",
            "slack_carved": True,
        },
        "flag": STAGE2_FLAG,
        "message": "✓ $MFT Data Run and USN Journal file deletion carved successfully!",
    }


@app.post("/api/stage3/triage_memory_injection")
def stage3_triage_memory_injection(req: MemoryInjectionTriageRequest):
    """
    Stage 3: Memory Injection & DKOM Triage (Volatility 3 / Rekall)
    Target: Unlinked hidden processes via psscan & RWX VAD injection discovery.
    """
    if req.target_pid <= 0:
        raise HTTPException(status_code=400, detail="Target PID must be valid")

    prot = req.vad_protection.strip().upper()
    if "READWRITE" not in prot and "EXECUTE" not in prot:
        raise HTTPException(status_code=400, detail="VAD protection must be PAGE_EXECUTE_READWRITE for reflective DLL injection")

    if not req.unhook_dkom:
        raise HTTPException(status_code=400, detail="DKOM unhook cross-verification must be enabled")

    state.stage3_completed = True
    return {
        "status": "success",
        "stage": 3,
        "pid": req.target_pid,
        "memory_details": {
            "vad_tag": "VadS",
            "vad_range": "0x0000018b2c400000 - 0x0000018b2c450000",
            "protection": prot,
            "hexdump_lead": "4D 5A 90 00 03 00 00 00 (Decrypted Reflective PE Header)",
            "dkom_unlinked": True,
            "eprocess_offset": "0xffff9c80a2b10080",
        },
        "flag": STAGE3_FLAG,
        "message": "✓ Unlinked DKOM process and RWX VAD injection beacon triangulated!",
    }


@app.post("/api/stage4/supertimeline_isolate")
def stage4_supertimeline_isolate(req: SupertimelineIsolateRequest):
    """
    Stage 4: Network Carving & Supertimeline SOAR Containment
    Target: SANS FOR572 packet carving + Plaso supertimeline correlation + host isolation.
    """
    filt = req.tshark_display_filter.strip().lower()
    if not ("dns" in filt or "tcp" in filt or "http" in filt or "ip" in filt):
        raise HTTPException(status_code=400, detail="tshark display filter must query dns, tcp, or ip protocols")

    if not req.isolate_host:
        raise HTTPException(status_code=400, detail="Host isolation must be requested to contain lateral movement")

    state.stage4_completed = True
    state.host_isolated = True
    return {
        "status": "success",
        "stage": 4,
        "tshark_filter": filt,
        "containment": {
            "quarantine_action": "SOAR_HOST_NETWORK_ISOLATE_APPLIED",
            "c2_exfiltration_channel": "DNS_TXT_TUNNEL_RFC1035",
            "supertimeline_events": 14280,
            "root_cause": "Phishing Maldoc -> Macro Execution -> RWX VAD Reflective Injection -> DNS C2 Exfil",
        },
        "flag": STAGE4_FLAG,
        "message": "🔒 SANS DFIR Supertimeline correlation complete and infected host isolated!",
    }


@app.post("/api/reset")
def reset_state():
    state.reset()
    return {"status": "reset", "message": "Lab 50 state has been reset to defaults"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8050, reload=False)
