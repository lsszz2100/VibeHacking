#!/usr/bin/env python3
"""DocArmor: Document and PDF Malware Analysis Interactive Lab Backend (Lab 14)."""

import os
import zlib
import base64
from typing import Dict, Any, List
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

app = FastAPI(
    title="DocArmor: MalDoc & PDF Analysis Lab",
    description="Interactive Hands-on Lab for OLE, VBA, PDF, and Office Exploits",
    version="1.0.0"
)

# In-memory Lab State and Flags
FLAGS = {
    "stage1": "FLAG{VBA-OBFUSCATION-UNPACKED-7712}",
    "stage2": "FLAG{PDF-STREAM-FLATEDECODE-ANALYZED-8931}",
    "stage3": "FLAG{CVE-2017-11882-EQUATION-PWNED-4419}",
    "stage4": "FLAG{MSHTML-CAB-INF-DEFENSE-PASSED-6602}",
}

STATE = {
    "stage1_solved": False,
    "stage2_solved": False,
    "stage3_solved": False,
    "stage4_solved": False,
    "logs": []
}

# Request/Response Models
class VbaDeobfuscateRequest(BaseModel):
    sample_id: str
    xor_key: int
    reversed_payload: str

class PdfAnalyzeRequest(BaseModel):
    object_id: int
    filter_type: str
    trigger_action: str

class EquationExploitRequest(BaseModel):
    font_name_length: int
    target_api: str
    command_payload: str

class MshtmlDefenseRequest(BaseModel):
    target_mode: str
    block_external_relations: bool
    quarantine_cab: bool


@app.get("/", response_class=HTMLResponse)
async def serve_index():
    """Serve the DocArmor interactive frontend."""
    static_file = os.path.join(os.path.dirname(__file__), "static", "index.html")
    if os.path.exists(static_file):
        with open(static_file, "r", encoding="utf-8") as f:
            return f.read()
    return "<h1>DocArmor Lab Running (Port 8014)</h1>"


@app.get("/api/maldoc/status")
async def get_status():
    """Return the current lab status and progress."""
    solved_count = sum([
        1 if STATE["stage1_solved"] else 0,
        1 if STATE["stage2_solved"] else 0,
        1 if STATE["stage3_solved"] else 0,
        1 if STATE["stage4_solved"] else 0,
    ])
    return {
        "status": "running",
        "service": "DocArmor",
        "port": 8014,
        "total_stages": 4,
        "solved_count": solved_count,
        "stages": {
            "stage1_vba_deobfuscation": STATE["stage1_solved"],
            "stage2_pdf_stream_analysis": STATE["stage2_solved"],
            "stage3_cve_2017_11882_equation": STATE["stage3_solved"],
            "stage4_cve_2021_40444_mshtml": STATE["stage4_solved"]
        },
        "logs": STATE["logs"][-15:]
    }


@app.post("/api/reset")
async def reset_state():
    """Reset lab progress to initial state."""
    STATE["stage1_solved"] = False
    STATE["stage2_solved"] = False
    STATE["stage3_solved"] = False
    STATE["stage4_solved"] = False
    STATE["logs"] = ["Lab state reset to default."]
    return {"success": True, "message": "DocArmor lab state has been reset."}


@app.get("/api/flags")
async def get_flags():
    """Return currently solved flags."""
    return {
        "stage1": FLAGS["stage1"] if STATE["stage1_solved"] else None,
        "stage2": FLAGS["stage2"] if STATE["stage2_solved"] else None,
        "stage3": FLAGS["stage3"] if STATE["stage3_solved"] else None,
        "stage4": FLAGS["stage4"] if STATE["stage4_solved"] else None,
    }


# ----------------------------------------------------------------------
# Stage 1: VBA Macro Deobfuscation (OLE Stream Parsing)
# ----------------------------------------------------------------------
@app.post("/api/maldoc/vba/deobfuscate")
async def deobfuscate_vba(req: VbaDeobfuscateRequest):
    """
    Deobfuscate a multi-layered VBA payload that uses XOR encryption
    and string reverse logic to hide PowerShell downloader arguments.
    """
    if req.sample_id != "SAMPLE_OLE_MACRO_01":
        raise HTTPException(status_code=400, detail="Unknown sample ID.")
    
    # Expected key: 0x5A (90), Expected reversed command fragment containing 'powershell'
    if req.xor_key == 90 and ("powershell" in req.reversed_payload.lower() or "c2.apt-group.corp" in req.reversed_payload.lower()):
        STATE["stage1_solved"] = True
        STATE["logs"].append("Stage 1 Solved: Successfully deobfuscated VBA OLE stream.")
        return {
            "success": True,
            "stage": 1,
            "message": "VBA obfuscation stripped! Recovered C2: http://c2.apt-group.corp/payload.exe",
            "flag": FLAGS["stage1"]
        }
    
    return {
        "success": False,
        "stage": 1,
        "message": "Invalid deobfuscation key or payload structure. Check XOR key and string reversal.",
        "flag": None
    }


# ----------------------------------------------------------------------
# Stage 2: Malicious PDF FlateDecode Stream Analysis
# ----------------------------------------------------------------------
@app.post("/api/maldoc/pdf/analyze")
async def analyze_pdf(req: PdfAnalyzeRequest):
    """
    Decompress FlateDecode stream for indirect object and analyze
    /OpenAction and /JavaScript heap spray payloads.
    """
    # Expected: Object ID 7, /FlateDecode filter, /OpenAction trigger
    if req.object_id == 7 and req.filter_type.strip().lower() == "/flatedecode" and req.trigger_action.strip().lower() in ["/openaction", "/aa", "/javascript"]:
        STATE["stage2_solved"] = True
        STATE["logs"].append("Stage 2 Solved: Decompressed FlateDecode stream in Object 7, identified Heap Spray.")
        return {
            "success": True,
            "stage": 2,
            "message": "Stream decompressed! Detected /JavaScript heap spray allocating 0x0c0c0c0c NOP sled.",
            "flag": FLAGS["stage2"]
        }

    return {
        "success": False,
        "stage": 2,
        "message": "Object stream analysis failed. Check object ID (look for stream), filter type, and action trigger.",
        "flag": None
    }


# ----------------------------------------------------------------------
# Stage 3: CVE-2017-11882 Microsoft Equation Editor RCE
# ----------------------------------------------------------------------
@app.post("/api/maldoc/cve/equation")
async def exploit_equation(req: EquationExploitRequest):
    """
    Analyze Equation Editor EQNEDT32.EXE font name stack buffer overflow.
    Font name buffer is 32 bytes; exceeding it overwrites the return address to WinExec.
    """
    if req.font_name_length > 36 and req.target_api.strip().lower() in ["winexec", "0x00430c12"] and ("cmd.exe" in req.command_payload.lower() or "powershell" in req.command_payload.lower()):
        STATE["stage3_solved"] = True
        STATE["logs"].append("Stage 3 Solved: Reconstructed CVE-2017-11882 Equation Editor stack overflow.")
        return {
            "success": True,
            "stage": 3,
            "message": "Buffer overflow verified! Overwrote EIP to WinExec() executing spawned payload.",
            "flag": FLAGS["stage3"]
        }

    return {
        "success": False,
        "stage": 3,
        "message": "Exploit parameters did not cause overflow. Font name length must exceed 36 bytes targeting WinExec.",
        "flag": None
    }


# ----------------------------------------------------------------------
# Stage 4: CVE-2021-40444 MSHTML External OLE Defense
# ----------------------------------------------------------------------
@app.post("/api/maldoc/cve/mshtml")
async def defend_mshtml(req: MshtmlDefenseRequest):
    """
    Validate defenses against CVE-2021-40444 MSHTML external relationship
    ActiveX / CAB execution.
    """
    if req.block_external_relations and req.quarantine_cab and req.target_mode.strip().lower() == "external":
        STATE["stage4_solved"] = True
        STATE["logs"].append("Stage 4 Solved: Blocked CVE-2021-40444 MSHTML external CAB extraction.")
        return {
            "success": True,
            "stage": 4,
            "message": "Defense applied! Sanitized document.xml.rels and quarantined malicious ActiveX CAB archive.",
            "flag": FLAGS["stage4"]
        }

    return {
        "success": False,
        "stage": 4,
        "message": "Defense policy insufficient. You must block external relationships and quarantine CAB files.",
        "flag": None
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8014, reload=False)
