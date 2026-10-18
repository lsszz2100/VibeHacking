#!/usr/bin/env python3
"""
Lab 45: PQCShield — Quantum Cryptography & PQC Migration Lab
Interactive FastAPI service demonstrating post-quantum cryptographic security:
1. Classical PKI & HNDL Risk Analysis (Harvest-Now-Decrypt-Later & Shor's algorithm vulnerability)
2. Hybrid KEM Downgrade Attack (MitM stripping X25519Kyber768 extension to classical ECDH)
3. Lattice Side-Channel & Fault Injection Triage (Rejection sampling fault & timing skew anomaly)
4. FIPS 203 ML-KEM & FIPS 204 ML-DSA Migration (Strict Dual-KDF, ML-KEM-768, ML-DSA-65 certificate chain)
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
    title="Lab 45: PQCShield — Quantum Cryptography & PQC Lab",
    description="Hands-on quantum security simulation covering classical PKI Shor vulnerability, hybrid KEM downgrade attacks, lattice side-channel audit, and NIST FIPS 203/204 migration.",
    version="1.0.0",
)

# Flags
STAGE1_FLAG = "FLAG{classical_pki_hndl_shor_vulnerable_8045}"
STAGE2_FLAG = "FLAG{hybrid_kem_downgrade_mitm_exploited_8045}"
STAGE3_FLAG = "FLAG{lattice_fault_injection_leak_neutralized_8045}"
STAGE4_FLAG = "FLAG{pqc_fips203_mlkem768_mldsa65_hardened_8045}"

# ============================================================================
# Simulation Data & State
# ============================================================================

def get_initial_traffic() -> List[Dict[str, Any]]:
    return [
        {
            "session_id": "sess-tls-001",
            "client_ip": "10.0.4.15",
            "server_domain": "vault.internal.quantumcorp.com",
            "cipher_suite": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            "key_exchange": "RSA-2048",
            "captured_at": "2026-10-18T10:15:00Z",
            "hndl_risk_score": 98,
            "payload_preview": "ENC[vault-master-passphrase-backup-aes256]"
        },
        {
            "session_id": "sess-tls-002",
            "client_ip": "10.0.4.22",
            "server_domain": "api.internal.quantumcorp.com",
            "cipher_suite": "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
            "key_exchange": "ECDH-secp256r1",
            "captured_at": "2026-10-18T10:16:30Z",
            "hndl_risk_score": 92,
            "payload_preview": "ENC[financial-wire-transfer-batch-0x89ab]"
        },
        {
            "session_id": "sess-tls-003",
            "client_ip": "10.0.4.30",
            "server_domain": "pqc-gateway.quantumcorp.com",
            "cipher_suite": "TLS_AES_256_GCM_SHA384",
            "key_exchange": "X25519MLKEM768",
            "captured_at": "2026-10-18T10:18:10Z",
            "hndl_risk_score": 5,
            "payload_preview": "ENC[pqc-hybrid-telemetry-status-ok]"
        }
    ]

def get_initial_handshake() -> Dict[str, Any]:
    return {
        "client_hello": {
            "supported_versions": ["TLSv1.3", "TLSv1.2"],
            "supported_groups": ["x25519_kyber768", "x25519", "secp256r1"],
            "key_share": {
                "x25519": "04a1b2c3d4e5f6...",
                "kyber768": "08f3e2d1c0b9a8..."
            }
        },
        "server_policy": {
            "allow_classical_fallback": True,
            "strict_pqc_required": False,
            "dual_kdf_binding": False,
            "enforced_groups": ["x25519_kyber768", "x25519"]
        },
        "negotiated": None,
        "is_downgraded": False
    }

def get_initial_oracle_logs() -> List[Dict[str, Any]]:
    return [
        {
            "operation_id": "op-ntt-101",
            "algorithm": "ML-KEM-768-Decap",
            "cycle_count": 48210,
            "execution_time_us": 14.2,
            "branch_condition": "coeff_compression_fast_path",
            "timing_skew_detected": True,
            "constant_time_compliant": False
        },
        {
            "operation_id": "op-rej-102",
            "algorithm": "ML-DSA-65-Sign",
            "rejection_iterations": 3,
            "fault_injected": True,
            "glitch_offset_clock": 412,
            "signature_norm_check": "FAILED_OUT_OF_BOUNDS",
            "leakage_warning": "Secret vector coefficient bias observable in high norm output"
        },
        {
            "operation_id": "op-ntt-103",
            "algorithm": "ML-KEM-768-Decap",
            "cycle_count": 39150,
            "execution_time_us": 11.5,
            "branch_condition": "coeff_compression_slow_path",
            "timing_skew_detected": True,
            "constant_time_compliant": False
        }
    ]

class SimulationState:
    def __init__(self):
        self.reset()

    def reset(self):
        self.traffic = get_initial_traffic()
        self.handshake = get_initial_handshake()
        self.oracle_logs = get_initial_oracle_logs()
        self.stages = {
            "stage1_hndl_shor_audit": {"solved": False, "flag": None, "vulnerable_sessions_identified": 0},
            "stage2_hybrid_downgrade": {"solved": False, "flag": None, "downgraded_session_harvested": False},
            "stage3_lattice_fault_audit": {"solved": False, "flag": None, "fault_triage_complete": False},
            "stage4_pqc_hardening": {"solved": False, "flag": None, "hardened": False}
        }
        self.hardened_posture = {
            "strict_pqc_required": False,
            "kem_standard": "Legacy-RSA/ECDH",
            "signature_standard": "ECDSA-P256",
            "dual_kdf_binding": False,
            "constant_time_ntt": False,
            "certificate_chain_pqc": False
        }

sim_state = SimulationState()

# ============================================================================
# Request / Response Schemas
# ============================================================================

class TrafficAnalysisRequest(BaseModel):
    session_id: str = Field(..., description="Target session ID to evaluate for HNDL & Shor exploitability")
    analysis_type: str = Field("shor_factorization", description="Type of quantum analysis: 'shor_factorization' or 'discrete_log'")

class DowngradeExploitRequest(BaseModel):
    strip_extension: str = Field("x25519_kyber768", description="PQC group extension to strip from ClientHello")
    target_group: str = Field("x25519", description="Fallback classical group to force server into")

class FaultAuditRequest(BaseModel):
    audit_target: str = Field(..., description="Target anomaly to isolate: 'timing_skew' or 'rejection_sampling_fault'")
    remediation_proposal: str = Field(..., description="Remediation approach: 'constant_time_ntt' or 'strict_norm_bound_assertion'")

class HardeningRequest(BaseModel):
    strict_pqc_required: bool = Field(True, description="Enforce strict rejection of non-PQC TLS handshakes")
    kem_standard: str = Field("FIPS 203 (ML-KEM-768)", description="Target NIST KEM algorithm")
    signature_standard: str = Field("FIPS 204 (ML-DSA-65)", description="Target NIST digital signature algorithm")
    dual_kdf_binding: bool = Field(True, description="Enable Dual-KDF RFC 9370 hybrid transcript binding")
    constant_time_ntt: bool = Field(True, description="Assert constant-time polynomial multiplication without conditional branch")

# ============================================================================
# API Endpoints
# ============================================================================

@app.get("/", response_class=HTMLResponse)
async def serve_dashboard():
    """Interactive HTML web UI for Lab 45: PQCShield."""
    return f"""<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Lab 45: PQCShield — Quantum Cryptography & PQC Lab</title>
    <style>
        :root {{
            --bg: #0b0f19;
            --surface: #111827;
            --border: #1f293d;
            --text: #e2e8f0;
            --accent: #8b5cf6;
            --cyan: #06b6d4;
            --green: #10b981;
            --yellow: #f59e0b;
            --red: #ef4444;
        }}
        body {{
            background: var(--bg);
            color: var(--text);
            font-family: 'JetBrains Mono', 'Fira Code', monospace;
            margin: 0;
            padding: 24px;
        }}
        .header {{
            border-bottom: 2px solid var(--border);
            padding-bottom: 16px;
            margin-bottom: 24px;
        }}
        h1 {{ margin: 0; color: var(--accent); font-size: 1.6rem; }}
        .badge {{
            display: inline-block;
            background: rgba(139, 92, 246, 0.2);
            color: var(--accent);
            border: 1px solid var(--accent);
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 0.8rem;
            margin-top: 6px;
        }}
        .grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
            gap: 20px;
        }}
        .card {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 16px;
        }}
        .card h3 {{
            margin-top: 0;
            color: var(--cyan);
            border-bottom: 1px solid var(--border);
            padding-bottom: 8px;
        }}
        button {{
            background: var(--accent);
            color: #fff;
            border: none;
            padding: 8px 14px;
            border-radius: 4px;
            cursor: pointer;
            font-family: inherit;
            font-weight: 600;
            margin-top: 10px;
        }}
        button:hover {{ opacity: 0.9; }}
        pre {{
            background: #030712;
            padding: 10px;
            border-radius: 6px;
            overflow-x: auto;
            border: 1px solid #1f2937;
            font-size: 0.85rem;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>⚛️ Lab 45: PQCShield — Quantum Cryptography & PQC Lab</h1>
        <div class="badge">NIST FIPS 203 / 204 • Shor Threat • Hybrid KEM • Lattice Triage</div>
    </div>
    <div class="grid">
        <div class="card">
            <h3>Stage 1: Classical PKI & HNDL Risk</h3>
            <p>고전 RSA-2048 / ECDH 트래픽 도청 및 "지금 수집, 나중 해독(HNDL)" 위협 진단</p>
            <button onclick="runStage1()">Analyze Traffic</button>
            <pre id="st1-out">Ready to analyze captured sessions...</pre>
        </div>
        <div class="card">
            <h3>Stage 2: Hybrid KEM Downgrade</h3>
            <p>ClientHello의 x25519_kyber768 그룹을 제거하는 MitM 다운그레이드 공격</p>
            <button onclick="runStage2()">Execute Downgrade</button>
            <pre id="st2-out">Ready for MitM downgrade injection...</pre>
        </div>
        <div class="card">
            <h3>Stage 3: Lattice Side-Channel Triage</h3>
            <p>NTF 비상수 시간 연산 타이밍 편차 및 서명 거부 샘플링 글리치 감사</p>
            <button onclick="runStage3()">Audit Oracle</button>
            <pre id="st3-out">Ready to inspect oracle telemetry...</pre>
        </div>
        <div class="card">
            <h3>Stage 4: FIPS 203/204 Hardening</h3>
            <p>FIPS 203 ML-KEM-768, FIPS 204 ML-DSA 및 Dual-KDF 엄격 적용</p>
            <button onclick="runStage4()">Deploy PQC Hardening</button>
            <pre id="st4-out">Awaiting security migration...</pre>
        </div>
    </div>

    <script>
        async function runStage1() {{
            const res = await fetch('/api/v1/pqc/traffic/analyze', {{
                method: 'POST',
                headers: {{'Content-Type': 'application/json'}},
                body: JSON.stringify({{session_id: 'sess-tls-001', analysis_type: 'shor_factorization'}})
            }});
            document.getElementById('st1-out').innerText = JSON.stringify(await res.json(), null, 2);
        }}
        async function runStage2() {{
            const res = await fetch('/api/v1/pqc/hybrid/downgrade-exploit', {{
                method: 'POST',
                headers: {{'Content-Type': 'application/json'}},
                body: JSON.stringify({{strip_extension: 'x25519_kyber768', target_group: 'x25519'}})
            }});
            document.getElementById('st2-out').innerText = JSON.stringify(await res.json(), null, 2);
        }}
        async function runStage3() {{
            const res = await fetch('/api/v1/pqc/lattice/fault-audit', {{
                method: 'POST',
                headers: {{'Content-Type': 'application/json'}},
                body: JSON.stringify({{audit_target: 'timing_skew', remediation_proposal: 'constant_time_ntt'}})
            }});
            document.getElementById('st3-out').innerText = JSON.stringify(await res.json(), null, 2);
        }}
        async function runStage4() {{
            const res = await fetch('/api/v1/pqc/harden', {{
                method: 'POST',
                headers: {{'Content-Type': 'application/json'}},
                body: JSON.stringify({{
                    strict_pqc_required: true,
                    kem_standard: 'FIPS 203 (ML-KEM-768)',
                    signature_standard: 'FIPS 204 (ML-DSA-65)',
                    dual_kdf_binding: true,
                    constant_time_ntt: true
                }})
            }});
            document.getElementById('st4-out').innerText = JSON.stringify(await res.json(), null, 2);
        }}
    </script>
</body>
</html>"""

@app.get("/api/v1/status")
async def get_status():
    """Return current laboratory progression and security posture."""
    all_solved = all(s["solved"] for s in sim_state.stages.values())
    return {
        "lab": "Lab 45: PQCShield",
        "all_stages_solved": all_solved,
        "stages": sim_state.stages,
        "hardened_posture": sim_state.hardened_posture
    }

@app.post("/api/v1/reset")
async def reset_lab():
    """Reset simulation environment to baseline."""
    sim_state.reset()
    return {"status": "success", "message": "Simulation state reset successfully."}

# --- Stage 1: Classical PKI & HNDL Risk ---

@app.get("/api/v1/pqc/traffic")
async def list_captured_traffic():
    """List captured TLS traffic sessions subject to Harvest-Now-Decrypt-Later monitoring."""
    return {"total": len(sim_state.traffic), "sessions": sim_state.traffic}

@app.post("/api/v1/pqc/traffic/analyze")
async def analyze_traffic(req: TrafficAnalysisRequest):
    """Analyze a captured TLS session for Shor's algorithm and HNDL vulnerability."""
    target = next((s for s in sim_state.traffic if s["session_id"] == req.session_id), None)
    if not target:
        raise HTTPException(status_code=404, detail=f"Session {req.session_id} not found.")

    if target["key_exchange"] in ["RSA-2048", "ECDH-secp256r1"]:
        is_vuln = True
        quantum_qubits_needed = 4096 if "RSA" in target["key_exchange"] else 2330
        sim_state.stages["stage1_hndl_shor_audit"]["solved"] = True
        sim_state.stages["stage1_hndl_shor_audit"]["flag"] = STAGE1_FLAG
        sim_state.stages["stage1_hndl_shor_audit"]["vulnerable_sessions_identified"] += 1

        return {
            "session_id": target["session_id"],
            "vulnerable_to_shor": True,
            "hndl_exposure": "CRITICAL",
            "required_logical_qubits": quantum_qubits_needed,
            "factorization_complexity": "Polynomial Time (O((log N)^3))",
            "message": "Harvest-Now-Decrypt-Later vulnerability confirmed. Classical key exchange can be decrypted by Shor's algorithm.",
            "flag": STAGE1_FLAG
        }
    else:
        return {
            "session_id": target["session_id"],
            "vulnerable_to_shor": False,
            "hndl_exposure": "SAFE",
            "message": "Session utilizes quantum-resistant hybrid KEM. Shor's algorithm cannot invert lattice problems."
        }

# --- Stage 2: Hybrid KEM Downgrade ---

@app.get("/api/v1/pqc/hybrid/handshake")
async def get_handshake():
    """Fetch current ClientHello key share and server negotiation status."""
    return sim_state.handshake

@app.post("/api/v1/pqc/hybrid/downgrade-exploit")
async def exploit_downgrade(req: DowngradeExploitRequest):
    """Execute MitM downgrade attack by stripping PQC extension from TLS handshake."""
    if sim_state.hardened_posture["strict_pqc_required"]:
        raise HTTPException(
            status_code=403,
            detail="Downgrade rejected: Server enforces Strict PQC Policy and rejects classical fallback."
        )

    if req.strip_extension == "x25519_kyber768":
        sim_state.handshake["is_downgraded"] = True
        sim_state.handshake["negotiated"] = {
            "selected_group": req.target_group,
            "is_quantum_safe": False,
            "shared_secret_type": "Classical-ECDH-Only"
        }
        sim_state.stages["stage2_hybrid_downgrade"]["solved"] = True
        sim_state.stages["stage2_hybrid_downgrade"]["flag"] = STAGE2_FLAG
        sim_state.stages["stage2_hybrid_downgrade"]["downgraded_session_harvested"] = True

        return {
            "downgrade_successful": True,
            "stripped_group": req.strip_extension,
            "negotiated_group": req.target_group,
            "session_vulnerability": "Downgraded to classical ECDH. Forward secrecy vulnerable to retro-decryption.",
            "flag": STAGE2_FLAG
        }

    raise HTTPException(status_code=400, detail="Invalid extension to strip.")

# --- Stage 3: Lattice Side-Channel & Fault Injection Triage ---

@app.get("/api/v1/pqc/lattice/oracle")
async def get_oracle_telemetry():
    """Retrieve execution metrics and telemetry from the lattice cryptographic oracle."""
    return {"logs": sim_state.oracle_logs}

@app.post("/api/v1/pqc/lattice/fault-audit")
async def audit_faults(req: FaultAuditRequest):
    """Audit lattice oracle operations for timing side-channels and rejection sampling faults."""
    if req.audit_target == "timing_skew" and req.remediation_proposal == "constant_time_ntt":
        sim_state.stages["stage3_lattice_fault_audit"]["solved"] = True
        sim_state.stages["stage3_lattice_fault_audit"]["flag"] = STAGE3_FLAG
        sim_state.stages["stage3_lattice_fault_audit"]["fault_triage_complete"] = True
        return {
            "status": "TRIAGE_COMPLETE",
            "anomaly_detected": "Non-constant time conditional compression branch in NTT polynomial reduction.",
            "remediation_validated": "Branch replaced with bitwise constant-time mux. Timing side-channel neutralized.",
            "flag": STAGE3_FLAG
        }
    elif req.audit_target == "rejection_sampling_fault" and req.remediation_proposal == "strict_norm_bound_assertion":
        sim_state.stages["stage3_lattice_fault_audit"]["solved"] = True
        sim_state.stages["stage3_lattice_fault_audit"]["flag"] = STAGE3_FLAG
        sim_state.stages["stage3_lattice_fault_audit"]["fault_triage_complete"] = True
        return {
            "status": "TRIAGE_COMPLETE",
            "anomaly_detected": "Clock glitch bypassed vector norm verification in Fiat-Shamir with Aborts.",
            "remediation_validated": "Strict post-verification norm assertion enforced. Fault injection neutralized.",
            "flag": STAGE3_FLAG
        }

    raise HTTPException(
        status_code=400,
        detail="Invalid audit target or inadequate remediation proposal."
    )

# --- Stage 4: FIPS 203/204 Hardening ---

@app.post("/api/v1/pqc/harden")
async def apply_hardening(req: HardeningRequest):
    """Deploy comprehensive NIST FIPS 203 / 204 post-quantum hardening."""
    sim_state.hardened_posture["strict_pqc_required"] = req.strict_pqc_required
    sim_state.hardened_posture["kem_standard"] = req.kem_standard
    sim_state.hardened_posture["signature_standard"] = req.signature_standard
    sim_state.hardened_posture["dual_kdf_binding"] = req.dual_kdf_binding
    sim_state.hardened_posture["constant_time_ntt"] = req.constant_time_ntt
    sim_state.hardened_posture["certificate_chain_pqc"] = True

    sim_state.handshake["server_policy"]["strict_pqc_required"] = True
    sim_state.handshake["server_policy"]["allow_classical_fallback"] = False
    sim_state.handshake["server_policy"]["dual_kdf_binding"] = True

    sim_state.stages["stage4_pqc_hardening"]["solved"] = True
    sim_state.stages["stage4_pqc_hardening"]["flag"] = STAGE4_FLAG
    sim_state.stages["stage4_pqc_hardening"]["hardened"] = True

    return {
        "status": "HARDENED",
        "applied_policy": sim_state.hardened_posture,
        "message": "NIST FIPS 203 (ML-KEM-768) and FIPS 204 (ML-DSA-65) successfully deployed. Strict PQC policy prevents downgrade attacks.",
        "flag": STAGE4_FLAG
    }

@app.get("/api/v1/pqc/certificate/verify")
async def verify_certificate_chain():
    """Validate quantum-safe certificate chain validity and root of trust."""
    return {
        "root_ca": {
            "subject": "CN=QuantumCorp Post-Quantum Root CA, O=QuantumCorp, C=US",
            "algorithm": "FIPS 204 ML-DSA-87",
            "fingerprint_sha256": "8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b"
        },
        "intermediate_ca": {
            "subject": "CN=QuantumCorp ML-DSA-65 Server Sub-CA",
            "algorithm": "FIPS 204 ML-DSA-65",
            "parent": "CN=QuantumCorp Post-Quantum Root CA"
        },
        "server_leaf": {
            "subject": "CN=vault.internal.quantumcorp.com",
            "algorithm": "FIPS 204 ML-DSA-65",
            "kem_group": sim_state.hardened_posture["kem_standard"],
            "status": "VALID_POST_QUANTUM_TRUST_ANCHOR"
        }
    }
