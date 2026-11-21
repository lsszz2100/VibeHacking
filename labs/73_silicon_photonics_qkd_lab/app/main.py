from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, List
import hashlib
import hmac

app = FastAPI(
    title="Lab 73: Silicon Photonics Co-Packaged Optics & QKD Quantum Key Mesh Defense Lab",
    version="2.23.0",
    description="Silicon Photonics CPO Optical Interconnect, QKD Quantum Key Mesh, Optical Power Scrambling & Waveguide Isolation Defense"
)

PHOTONICS_SHARED_SECRET = b"vibe-2026-enterprise-photonics-qkd-defense-secret-8073"

class Stage1Payload(BaseModel):
    scrambling_policy: str
    optical_dummy_padding_active: bool
    line_rate_jitter_enabled: bool
    scramble_polynomials: List[str]

class Stage2Payload(BaseModel):
    qkd_protocol: str
    qber_threshold_pct: float
    quantum_channel_active: bool
    session_key_id: str
    qkd_audit_hmac: str

class Stage3Payload(BaseModel):
    waveguide_isolation_mode: str
    wdm_channel_spacing_ghz: int
    cross_talk_quarantine_enforced: bool
    adjacent_wavelength_leak_blocked: bool

class Stage4Payload(BaseModel):
    transceiver_firmware_sha256: str
    photonics_merkle_root: str
    attestation_sig: str
    transceiver_audit_hmac: str

@app.get("/api/health")
def health():
    return {
        "status": "ok",
        "lab_id": 73,
        "name": "silicon_photonics_qkd_lab",
        "stages": 4,
        "category": "hardware",
        "version": "2.23.0"
    }

@app.get("/")
def read_root():
    return {
        "lab": "Lab 73: Silicon Photonics Co-Packaged Optics & QKD Quantum Key Mesh Defense Lab",
        "status": "ready",
        "port": 8073,
        "stages": 4,
        "category": "hardware",
        "version": "2.23.0"
    }

@app.post("/api/stage1/eval")
def evaluate_stage1(payload: Stage1Payload):
    """Stage 1: Optical Bus Physical Scrambling & Line Rate Padding"""
    if payload.scrambling_policy != "optical_line_rate_pseudo_random_scramble":
        raise HTTPException(status_code=400, detail="Scrambling policy must be optical_line_rate_pseudo_random_scramble.")
    
    if not payload.optical_dummy_padding_active:
        raise HTTPException(status_code=400, detail="Optical dummy symbol padding must be active.")
    
    if not payload.line_rate_jitter_enabled:
        raise HTTPException(status_code=400, detail="Line-rate optical timing jitter must be enabled.")
    
    if len(payload.scramble_polynomials) < 2:
        raise HTTPException(status_code=400, detail="At least two scrambling polynomials required.")
    
    return {
        "success": True,
        "stage": 1,
        "flag": "FLAG{v223_s1_optical_bus_scrambling_line_padded}",
        "message": "Optical bus scrambling and line padding enforced. Differential optical power sidechannel neutralized."
    }

@app.post("/api/stage2/eval")
def evaluate_stage2(payload: Stage2Payload):
    """Stage 2: Continuous Quantum Key Distribution (QKD) Mesh Rotation & QBER Defense"""
    if payload.qkd_protocol not in ["bb84_decoy_state", "e91_entanglement"]:
        raise HTTPException(status_code=400, detail="Valid QKD protocol required (bb84_decoy_state or e91_entanglement).")
    
    if payload.qber_threshold_pct > 11.0:
        raise HTTPException(status_code=400, detail="Quantum Bit Error Rate (QBER) threshold must be <= 11.0% to detect eavesdropping.")
    
    if not payload.quantum_channel_active:
        raise HTTPException(status_code=400, detail="Auxiliary quantum optical channel must be active.")
    
    expected_hmac = hmac.new(
        PHOTONICS_SHARED_SECRET,
        f"{payload.qkd_protocol}:{payload.session_key_id}".encode(),
        hashlib.sha256
    ).hexdigest()
    
    if not hmac.compare_digest(payload.qkd_audit_hmac, expected_hmac):
        raise HTTPException(status_code=403, detail="Invalid cryptographic QKD audit HMAC token.")
    
    return {
        "success": True,
        "stage": 2,
        "flag": "FLAG{v223_s2_qkd_continuous_quantum_key_rotated}",
        "message": "Continuous QKD mesh key rotation active. Fiber tapping eavesdropping intercepted via QBER telemetry."
    }

@app.post("/api/stage3/eval")
def evaluate_stage3(payload: Stage3Payload):
    """Stage 3: Optical Waveguide Isolation & WDM Cross-Talk Quarantine"""
    if payload.waveguide_isolation_mode != "dielectric_cladding_shield":
        raise HTTPException(status_code=400, detail="Waveguide isolation mode must be dielectric_cladding_shield.")
    
    if payload.wdm_channel_spacing_ghz < 100:
        raise HTTPException(status_code=400, detail="WDM channel spacing must be at least 100 GHz (ITU Grid compliant).")
    
    if not payload.cross_talk_quarantine_enforced:
        raise HTTPException(status_code=400, detail="Cross-talk quarantine must be enforced.")
    
    if not payload.adjacent_wavelength_leak_blocked:
        raise HTTPException(status_code=400, detail="Adjacent wavelength optical leak must be blocked.")
    
    return {
        "success": True,
        "stage": 3,
        "flag": "FLAG{v223_s3_wdm_waveguide_cross_talk_isolated}",
        "message": "Waveguide physical isolation and WDM filter quarantine enforced. Multi-tenant optical leakage prevented."
    }

@app.post("/api/stage4/eval")
def evaluate_stage4(payload: Stage4Payload):
    """Stage 4: Cryptographic Optical Transceiver Attestation & Merkle Firmware Defense (Capstone)"""
    if len(payload.transceiver_firmware_sha256) != 64 or len(payload.photonics_merkle_root) != 64:
        raise HTTPException(status_code=400, detail="Invalid SHA-256 hash format for optical transceiver microcode or Merkle root.")
    
    if not payload.attestation_sig.startswith("sig_cpo_transceiver_v223_"):
        raise HTTPException(status_code=400, detail="Valid CPO transceiver attestation signature required.")
    
    expected_hmac = hmac.new(
        PHOTONICS_SHARED_SECRET,
        f"{payload.transceiver_firmware_sha256}:{payload.photonics_merkle_root}".encode(),
        hashlib.sha256
    ).hexdigest()
    
    if not hmac.compare_digest(payload.transceiver_audit_hmac, expected_hmac):
        raise HTTPException(status_code=403, detail="Invalid cryptographic optical transceiver audit HMAC attestation.")
    
    return {
        "success": True,
        "stage": 4,
        "flag": "FLAG{v223_s4_optical_transceiver_merkle_attested}",
        "message": "Optical transceiver microcode Merkle attestation verified. Hardware Root-of-Trust secured."
    }
