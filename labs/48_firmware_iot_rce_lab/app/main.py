#!/usr/bin/env python3
"""
Lab 48: FirmwareGuard — Embedded MIPS/ARM Firmware & IoT RCE Lab
Interactive simulation of embedded firmware analysis & emulation:
1. Binwalk SquashFS Unpacking & NVRAM Extraction
2. Fake NVRAM Interceptor Library Injection (LD_PRELOAD)
3. Embedded Web CGI Command Injection RCE
4. DM-Verity & Secure Boot Kernel Integrity Lockdown
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
    title="Lab 48: FirmwareGuard — Embedded Firmware & IoT RCE Lab",
    description="Interactive simulation of embedded IoT firmware analysis, NVRAM virtualization, CGI command injection, and secure boot hardening.",
    version="1.0.0",
)

# Flags
STAGE1_FLAG = "FLAG{binwalk_squashfs_nvram_extracted_8048}"
STAGE2_FLAG = "FLAG{libnvram_faker_preload_emulation_active_8048}"
STAGE3_FLAG = "FLAG{embedded_cgi_command_injection_rce_8048}"
STAGE4_FLAG = "FLAG{dm_verity_secure_boot_hardened_8048}"

class LabState:
    def __init__(self):
        self.reset()

    def reset(self):
        self.stage1_completed = False
        self.stage2_completed = False
        self.stage3_completed = False
        self.stage4_completed = False

        self.extracted_files = []
        self.nvram_loaded = False
        self.dm_verity_enforced = False

state = LabState()

class UnpackRequest(BaseModel):
    firmware_image: str
    extract_flag: str = "-Me"

class NvramPreloadRequest(BaseModel):
    preload_library: str = "/lib/libnvram.so"
    architecture: str = "mips"
    default_config: str = "http_port=8080\nlan_ipaddr=127.0.0.1"

class CGIExecuteRequest(BaseModel):
    cgi_script: str = "/cgi-bin/ping.cgi"
    target_host: str

class SecureBootHardenRequest(BaseModel):
    enable_dm_verity: bool
    disable_jtag_uart_pins: bool
    enforce_uboot_rsa_verify: bool

@app.get("/", response_class=HTMLResponse)
def index():
    return f"""<!DOCTYPE html>
<html>
<head>
    <title>Lab 48: FirmwareGuard - Embedded Firmware & IoT RCE Lab</title>
    <style>
        body {{ font-family: monospace; background: #0d1117; color: #c9d1d9; padding: 20px; }}
        h1 {{ color: #f0883e; }}
        .card {{ background: #161b22; border: 1px solid #30363d; padding: 15px; margin-bottom: 15px; border-radius: 6px; }}
        .badge {{ display: inline-block; padding: 3px 8px; border-radius: 4px; font-weight: bold; font-size: 12px; }}
        .badge-green {{ background: #238636; color: white; }}
        .badge-red {{ background: #da3633; color: white; }}
    </style>
</head>
<body>
    <h1>📟 Lab 48: FirmwareGuard — Embedded Firmware & IoT RCE Lab</h1>
    <p>포트 <b>8048</b> | Binwalk 펌웨어 언패킹, NVRAM 가상화, CGI RCE 익스플로잇 및 시큐어 부트</p>
    
    <div class="card">
        <h3>실습 단계 현황</h3>
        <p>Stage 1 (SquashFS Unpack): <span class="badge {'badge-green' if state.stage1_completed else 'badge-red'}">{'COMPLETED' if state.stage1_completed else 'PENDING'}</span></p>
        <p>Stage 2 (NVRAM Preload): <span class="badge {'badge-green' if state.stage2_completed else 'badge-red'}">{'COMPLETED' if state.stage2_completed else 'PENDING'}</span></p>
        <p>Stage 3 (CGI Command Injection): <span class="badge {'badge-green' if state.stage3_completed else 'badge-red'}">{'COMPLETED' if state.stage3_completed else 'PENDING'}</span></p>
        <p>Stage 4 (DM-Verity Secure Boot): <span class="badge {'badge-green' if state.stage4_completed else 'badge-red'}">{'COMPLETED' if state.stage4_completed else 'PENDING'}</span></p>
    </div>
</body>
</html>"""

@app.get("/status")
def get_status():
    return {
        "lab": "48_firmware_iot_rce_lab",
        "port": 8048,
        "stages": {
            "stage1_unpack": state.stage1_completed,
            "stage2_nvram": state.stage2_completed,
            "stage3_cgi_rce": state.stage3_completed,
            "stage4_secure_boot": state.stage4_completed,
        },
        "nvram_loaded": state.nvram_loaded,
        "dm_verity_enforced": state.dm_verity_enforced
    }

@app.post("/api/stage1/unpack_firmware")
def unpack_firmware(req: UnpackRequest):
    if "bin" in req.firmware_image.lower() and "-M" in req.extract_flag:
        state.stage1_completed = True
        state.extracted_files = ["/bin/busybox", "/usr/sbin/httpd", "/etc/nvram.default", "/www/cgi-bin/ping.cgi"]
        return {
            "success": True,
            "extracted_fs": "squashfs-root",
            "files": state.extracted_files,
            "message": "✓ Firmware unpacked: MIPS SquashFS filesystem identified!",
            "flag": STAGE1_FLAG
        }
    return {"success": False, "message": "Invalid firmware image or extraction parameters."}

@app.post("/api/stage2/preload_nvram")
def preload_nvram(req: NvramPreloadRequest):
    if "libnvram" in req.preload_library and "mips" in req.architecture.lower():
        state.nvram_loaded = True
        state.stage2_completed = True
        return {
            "success": True,
            "message": "✓ QEMU Virtualization: libnvram.so hooked and default keys mapped!",
            "flag": STAGE2_FLAG
        }
    return {"success": False, "message": "Failed to preload NVRAM emulation library."}

@app.post("/api/stage3/execute_cgi")
def execute_cgi(req: CGIExecuteRequest):
    if state.dm_verity_enforced:
        return {"success": False, "message": "Execution Blocked: DM-Verity enforced read-only integrity."}
        
    # Check for command injection characters
    injection_chars = [";", "|", "&", "`", "$("]
    has_injection = any(c in req.target_host for c in injection_chars)
    
    if has_injection and "cat" in req.target_host:
        state.stage3_completed = True
        return {
            "success": True,
            "rce_output": "root:x:0:0:root:/root:/bin/sh\nadmin:x:1000:1000:Admin:/home/admin:/bin/sh\n",
            "message": "🚨 Remote Code Execution Succeeded via Unsanitized CGI ping parameter!",
            "flag": STAGE3_FLAG
        }
    return {"success": False, "message": "Standard ping executed. No command injection payload detected."}

@app.post("/api/stage4/harden_secure_boot")
def harden_secure_boot(req: SecureBootHardenRequest):
    if req.enable_dm_verity and req.disable_jtag_uart_pins and req.enforce_uboot_rsa_verify:
        state.dm_verity_enforced = True
        state.stage4_completed = True
        return {
            "success": True,
            "message": "🔒 Secure Boot & DM-Verity Kernel Lockdown Active!",
            "flag": STAGE4_FLAG
        }
    return {"success": False, "message": "All three hardware/firmware integrity controls must be active."}

@app.post("/api/reset")
def reset():
    state.reset()
    return {"success": True, "message": "Lab state reset."}
