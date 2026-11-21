#!/usr/bin/env python3
"""
Lab 75: PhotonicIcPufSecurityLab
Photonic IC Physical Unclonable Function (PUF) & Silicon Hardware Security Lab
Port: 8075 (127.0.0.1 loopback isolation strictly enforced)
"""

import hashlib
import hmac
from typing import Any, Dict, List, Optional
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

app = FastAPI(
    title="Lab 75: PhotonicIcPufSecurityLab",
    description="Photonic IC Physical Unclonable Function (PUF) & Silicon Hardware Security Lab",
    version="2.25.0"
)

PHOTONIC_PUF_SHARED_SECRET = b"vibe-2026-enterprise-photonic-ic-puf-secret-8075"

class Stage1Payload(BaseModel):
    silicon_die_id: str
    optical_speckle_phase_rad: float
    mrr_resonance_q_factor: float
    speckle_entropy_bits: float

class Stage2Payload(BaseModel):
    crp_modeling_defense_active: bool
    phase_scrambler_rate_ghz: float
    cmaes_prediction_resistance: float
    puf_session_id: str
    puf_session_hmac: str

class Stage3Payload(BaseModel):
    anti_tamper_optical_monitor: bool
    chiplet_disconnection_threshold_db: float
    optical_erasure_latency_ns: float
    hardware_rot_binding_active: bool

class Stage4Payload(BaseModel):
    chiplet_firmware_sha256: str
    photonic_waveguide_merkle_root: str
    ml_dsa_attestation_sig: str
    hardware_puf_audit_hmac: str


@app.get("/")
def get_root():
    return {
        "lab": "Lab 75: Photonic IC Physical Unclonable Function (PUF) & Silicon Hardware Security Lab",
        "status": "ready",
        "port": 8075,
        "stages": 4,
        "category": "hardware_security",
        "version": "2.25.0"
    }


@app.get("/api/health")
def get_health():
    return {
        "status": "ok",
        "lab_id": 75,
        "name": "photonic_ic_puf_lab",
        "stages": 4,
        "category": "hardware_security",
        "version": "2.25.0"
    }


@app.post("/api/stage1/eval")
def evaluate_stage1(payload: Stage1Payload):
    """
    Stage 1: 반도체 실리콘 포토닉스 다이(Die) 미세 광학 위상 편차 추출 및 광학 PUF 키 유도
    """
    if not payload.silicon_die_id.startswith("die_sp_die_2026_"):
        raise HTTPException(status_code=400, detail="Invalid silicon die identifier format")
    if not (1.20 <= payload.optical_speckle_phase_rad <= 2.80):
        raise HTTPException(status_code=400, detail="Optical speckle phase radians outside physical bounds [1.20, 2.80]")
    if payload.mrr_resonance_q_factor < 15000.0:
        raise HTTPException(status_code=400, detail="MRR resonance Q-factor too low (< 15000) for stable PUF response")
    if payload.speckle_entropy_bits < 128.0:
        raise HTTPException(status_code=400, detail="Optical speckle min-entropy bits insufficient (< 128 bits)")

    flag = "FLAG{v225_s1_photonic_puf_speckle_key_derived_ok}"
    return {
        "status": "success",
        "stage": 1,
        "message": "Optical PUF speckle phase fingerprint authenticated and root key derived",
        "flag": flag,
        "derived_entropy": payload.speckle_entropy_bits
    }


@app.post("/api/stage2/eval")
def evaluate_stage2(payload: Stage2Payload):
    """
    Stage 2: 마이크로 링 공진기 CRP 머신러닝 모델링 공격 차단 및 능동 위상 스크램블링
    """
    if not payload.crp_modeling_defense_active:
        raise HTTPException(status_code=400, detail="CRP modeling defense must be active")
    if payload.phase_scrambler_rate_ghz < 10.0:
        raise HTTPException(status_code=400, detail="Phase scrambler clock rate must be at least 10.0 GHz to defeat sampling")
    if payload.cmaes_prediction_resistance < 0.999:
        raise HTTPException(status_code=400, detail="CMA-ES prediction resistance below security threshold 0.999")

    expected_hmac = hmac.new(
        PHOTONIC_PUF_SHARED_SECRET,
        f"crp_defense:{payload.puf_session_id}".encode(),
        hashlib.sha256
    ).hexdigest()

    if not hmac.compare_digest(expected_hmac, payload.puf_session_hmac):
        raise HTTPException(status_code=403, detail="Invalid PUF session HMAC signature")

    flag = "FLAG{v225_s2_mrr_crp_modeling_attack_scrambled}"
    return {
        "status": "success",
        "stage": 2,
        "message": "Micro-ring resonator CRP modeling attack successfully scrambled and neutralized",
        "flag": flag
    }


@app.post("/api/stage3/eval")
def evaluate_stage3(payload: Stage3Payload):
    """
    Stage 3: 광 칩let 분리 감지 비가역적 광학 소광 및 하드웨어 RoT 바인딩
    """
    if not payload.anti_tamper_optical_monitor:
        raise HTTPException(status_code=400, detail="Anti-tamper optical power monitor must be active")
    if payload.chiplet_disconnection_threshold_db < 3.0:
        raise HTTPException(status_code=400, detail="Chiplet optical loss threshold too sensitive or permissive (< 3.0 dB)")
    if payload.optical_erasure_latency_ns > 50.0:
        raise HTTPException(status_code=400, detail="Optical erasure latency too slow (> 50.0 ns) to prevent probe tapping")
    if not payload.hardware_rot_binding_active:
        raise HTTPException(status_code=400, detail="Hardware Root-of-Trust immutable binding must be active")

    flag = "FLAG{v225_s3_chiplet_optical_erasure_rot_secured}"
    return {
        "status": "success",
        "stage": 3,
        "message": "Inter-chiplet optical tamper erasure and immutable hardware RoT binding enforced",
        "flag": flag
    }


@app.post("/api/stage4/eval")
def evaluate_stage4(payload: Stage4Payload):
    """
    Stage 4: NIST FIPS 204 ML-DSA-87 서명 기반 칩let 상호 원격 증명 및 머클 무결성
    """
    expected_fw = hashlib.sha256(b"vibe-photonic-puf-firmware-v225").hexdigest()
    expected_root = hashlib.sha256(b"vibe-waveguide-merkle-tree-root-v225").hexdigest()

    if payload.chiplet_firmware_sha256 != expected_fw:
        raise HTTPException(status_code=400, detail="Untrusted chiplet firmware SHA-256 hash")
    if payload.photonic_waveguide_merkle_root != expected_root:
        raise HTTPException(status_code=400, detail="Photonic waveguide layout Merkle root mismatch")
    if payload.ml_dsa_attestation_sig != "sig_photonic_puf_v225_verified_ok":
        raise HTTPException(status_code=403, detail="Invalid ML-DSA-87 post-quantum attestation signature")

    expected_audit = hmac.new(
        PHOTONIC_PUF_SHARED_SECRET,
        f"{payload.chiplet_firmware_sha256}:{payload.photonic_waveguide_merkle_root}".encode(),
        hashlib.sha256
    ).hexdigest()

    if not hmac.compare_digest(expected_audit, payload.hardware_puf_audit_hmac):
        raise HTTPException(status_code=403, detail="Invalid hardware PUF audit HMAC token")

    flag = "FLAG{v225_s4_mldsa87_chiplet_remote_attestation_passed}"
    return {
        "status": "success",
        "stage": 4,
        "message": "ML-DSA-87 chiplet mutual attestation and waveguide Merkle provenance verified",
        "flag": flag
    }
