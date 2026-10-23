#!/usr/bin/env python3
"""
Lab 49: PQCTLSGuard — Quantum-Safe Hybrid TLS 1.3 & Post-Quantum Cryptography Lab
Interactive simulation of post-quantum cryptography migration & hybrid TLS 1.3:
1. Classical TLS 1.3 Harvest-Now-Decrypt-Later (HNDL) Threat Audit
2. ML-KEM-768 (Kyber) + X25519 Hybrid Key Exchange Handshake
3. ML-DSA-65 (Dilithium) Quantum-Resistant Digital Signature Verification
4. Downgrade Attack Prevention & Strict Non-Quantum Fallback Ban
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
    title="Lab 49: PQCTLSGuard — Quantum-Safe Hybrid TLS 1.3 Lab",
    description="Interactive simulation of FIPS 203 ML-KEM, FIPS 204 ML-DSA, and Hybrid TLS 1.3.",
    version="1.0.0",
)

# Flags
STAGE1_FLAG = "FLAG{classical_pki_hndl_vulnerability_audited_8049}"
STAGE2_FLAG = "FLAG{hybrid_kem_x25519_mlkem768_handshake_8049}"
STAGE3_FLAG = "FLAG{mldsa65_quantum_signature_verified_8049}"
STAGE4_FLAG = "FLAG{quantum_safe_tls13_downgrade_prevented_8049}"

class LabState:
    def __init__(self):
        self.reset()

    def reset(self):
        self.stage1_completed = False
        self.stage2_completed = False
        self.stage3_completed = False
        self.stage4_completed = False

        self.cipher_suite = "TLS_AES_256_GCM_SHA384"
        self.hybrid_group = "x25519_mlkem768"
        self.strict_pqc_only = False

state = LabState()

class HNDLAuditRequest(BaseModel):
    capture_file: str
    target_cipher: str = "ECDHE-RSA-AES256-GCM-SHA384"

class HybridHandshakeRequest(BaseModel):
    client_named_groups: List[str]
    enforce_hybrid_kdf: bool = True

class SignatureVerifyRequest(BaseModel):
    algorithm: str = "ML-DSA-65"
    public_key_pem: str
    signature_bytes: str

class DowngradeDefenseRequest(BaseModel):
    allow_classical_rsa_fallback: bool
    strict_fips203_enforcement: bool

@app.get("/", response_class=HTMLResponse)
def index():
    return f"""<!DOCTYPE html>
<html>
<head>
    <title>Lab 49: PQCTLSGuard - Quantum-Safe Hybrid TLS 1.3 Lab</title>
    <style>
        body {{ font-family: monospace; background: #0d1117; color: #c9d1d9; padding: 20px; }}
        h1 {{ color: #bc8cff; }}
        .card {{ background: #161b22; border: 1px solid #30363d; padding: 15px; margin-bottom: 15px; border-radius: 6px; }}
        .badge {{ display: inline-block; padding: 3px 8px; border-radius: 4px; font-weight: bold; font-size: 12px; }}
        .badge-green {{ background: #238636; color: white; }}
        .badge-red {{ background: #da3633; color: white; }}
    </style>
</head>
<body>
    <h1>⚛️ Lab 49: PQCTLSGuard — Quantum-Safe Hybrid TLS 1.3 Lab</h1>
    <p>포트 <b>8049</b> | HNDL 위협 감사, X25519+ML-KEM-768 하이브리드 키 교환, ML-DSA 서명 및 다운그레이드 방어</p>
    
    <div class="card">
        <h3>실습 단계 현황</h3>
        <p>Stage 1 (HNDL Threat Audit): <span class="badge {'badge-green' if state.stage1_completed else 'badge-red'}">{'COMPLETED' if state.stage1_completed else 'PENDING'}</span></p>
        <p>Stage 2 (Hybrid Handshake): <span class="badge {'badge-green' if state.stage2_completed else 'badge-red'}">{'COMPLETED' if state.stage2_completed else 'PENDING'}</span></p>
        <p>Stage 3 (ML-DSA Signature): <span class="badge {'badge-green' if state.stage3_completed else 'badge-red'}">{'COMPLETED' if state.stage3_completed else 'PENDING'}</span></p>
        <p>Stage 4 (Downgrade Defense): <span class="badge {'badge-green' if state.stage4_completed else 'badge-red'}">{'COMPLETED' if state.stage4_completed else 'PENDING'}</span></p>
    </div>
</body>
</html>"""

@app.get("/status")
def get_status():
    return {
        "lab": "49_pqc_hybrid_tls_lab",
        "port": 8049,
        "stages": {
            "stage1_hndl": state.stage1_completed,
            "stage2_hybrid": state.stage2_completed,
            "stage3_signature": state.stage3_completed,
            "stage4_downgrade": state.stage4_completed,
        },
        "hybrid_group": state.hybrid_group,
        "strict_pqc_only": state.strict_pqc_only
    }

@app.post("/api/stage1/audit_hndl")
def audit_hndl(req: HNDLAuditRequest):
    if "pcap" in req.capture_file.lower() and ("RSA" in req.target_cipher or "ECDHE" in req.target_cipher):
        state.stage1_completed = True
        return {
            "success": True,
            "threat_verdict": "CRITICAL_EXPOSURE_TO_SHORS_ALGORITHM",
            "message": "⚠️ Classical TLS Key Exchange vulnerable to Harvest-Now-Decrypt-Later (HNDL) adversary!",
            "flag": STAGE1_FLAG
        }
    return {"success": False, "message": "Invalid capture file or non-classical cipher suite."}

@app.post("/api/stage2/hybrid_handshake")
def hybrid_handshake(req: HybridHandshakeRequest):
    if any("mlkem768" in g.lower() or "kyber" in g.lower() for g in req.client_named_groups) and req.enforce_hybrid_kdf:
        state.stage2_completed = True
        return {
            "success": True,
            "selected_group": "x25519_mlkem768",
            "kdf_method": "HKDF-Extract-and-Expand(SS_classical || SS_pqc)",
            "message": "✓ Quantum-Safe Hybrid Key Exchange Completed successfully!",
            "flag": STAGE2_FLAG
        }
    return {"success": False, "message": "ML-KEM-768 hybrid group not supported in ClientHello."}

@app.post("/api/stage3/verify_mldsa")
def verify_mldsa(req: SignatureVerifyRequest):
    if "ML-DSA" in req.algorithm and len(req.public_key_pem) > 100:
        state.stage3_completed = True
        return {
            "success": True,
            "verified_standard": "NIST FIPS 204 (Module-Lattice-Based Digital Signature Standard)",
            "message": "✓ Post-Quantum Signature Validated without Classical Trapdoor!",
            "flag": STAGE3_FLAG
        }
    return {"success": False, "message": "Invalid post-quantum signature payload."}

@app.post("/api/stage4/prevent_downgrade")
def prevent_downgrade(req: DowngradeDefenseRequest):
    if not req.allow_classical_rsa_fallback and req.strict_fips203_enforcement:
        state.strict_pqc_only = True
        state.stage4_completed = True
        return {
            "success": True,
            "message": "🔒 Quantum-Safe Downgrade Attack Defense Active: Insecure Fallbacks Prohibited!",
            "flag": STAGE4_FLAG
        }
    return {"success": False, "message": "Classical fallbacks must be disabled to guarantee quantum safety."}

@app.post("/api/reset")
def reset():
    state.reset()
    return {"success": True, "message": "Lab state reset."}
