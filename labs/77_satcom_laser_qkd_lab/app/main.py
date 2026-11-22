#!/usr/bin/env python3
"""
Lab 77: SatComLaserQkdLab
LEO Satellite Laser Optical Communication & Space Quantum Key Distribution Defense Lab
Port: 8077 (127.0.0.1 loopback isolation strictly enforced)
"""

import hashlib
import hmac
from typing import Any, Dict, List, Optional
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

app = FastAPI(
    title="Lab 77: SatComLaserQkdLab",
    description="LEO Satellite Laser Optical Communication & Space Quantum Key Distribution Defense Lab",
    version="2.27.0"
)

SATCOM_SHARED_SECRET = b"vibe-2026-enterprise-satcom-qkd-secret-8077"


class Stage1Payload(BaseModel):
    satellite_constellation_id: str
    laser_beam_divergence_urad: float
    doppler_frequency_shift_mhz: float
    pointing_accuracy_mas: float


class Stage2Payload(BaseModel):
    ephemeris_drift_detector_active: bool
    semi_major_axis_variance_km: float
    eccentricity_error_pct: float
    orbit_session_id: str
    orbit_session_hmac: str


class Stage3Payload(BaseModel):
    ttc_replay_defense_active: bool
    telemetry_command_counter: int
    ttc_mldsa87_signature: str
    zero_trust_uplink_isolation: bool


class Stage4Payload(BaseModel):
    quantum_optical_ber_pct: float
    decoy_state_intensity_ratio: float
    fips203_ml_kem_shared_key_hash: str
    space_ground_qkd_audit_hmac: str


@app.get("/")
def get_root():
    return {
        "lab": "Lab 77: LEO Satellite Laser Optical Communication & Space Quantum Key Distribution Defense Lab",
        "status": "ready",
        "port": 8077,
        "stages": 4,
        "category": "space_quantum_security",
        "version": "2.27.0"
    }


@app.get("/api/health")
def get_health():
    return {
        "status": "ok",
        "lab_id": 77,
        "name": "satcom_laser_qkd_lab",
        "stages": 4,
        "category": "space_quantum_security",
        "version": "2.27.0"
    }


@app.post("/api/stage1/eval")
def evaluate_stage1(payload: Stage1Payload):
    """
    Stage 1: LEO 위성 간 레이저 광통신(ISL) 도플러 주파수 변이 보정 및 초정밀 빔 포인팅 지문 검증
    """
    if not payload.satellite_constellation_id.startswith("sat_leo_star_2026_"):
        raise HTTPException(status_code=400, detail="Invalid satellite constellation node identifier format")
    if not (5.0 <= payload.laser_beam_divergence_urad <= 20.0):
        raise HTTPException(status_code=400, detail="Laser optical beam divergence outside operational bounds [5.0, 20.0 urad]")
    if not (-150.0 <= payload.doppler_frequency_shift_mhz <= 150.0):
        raise HTTPException(status_code=400, detail="Doppler frequency shift compensation out of physical orbit bounds [-150.0, 150.0 MHz]")
    if payload.pointing_accuracy_mas > 50.0 or payload.pointing_accuracy_mas < 0.1:
        raise HTTPException(status_code=400, detail="Fine beam pointing acquisition accuracy insufficient (> 50.0 mas)")

    flag = "FLAG{v227_s1_satcom_laser_isl_doppler_tracking_locked}"
    return {
        "status": "success",
        "stage": 1,
        "message": "Satellite laser ISL Doppler shift synchronized and pointing telemetry locked",
        "flag": flag,
        "pointing_accuracy_mas": payload.pointing_accuracy_mas
    }


@app.post("/api/stage2/eval")
def evaluate_stage2(payload: Stage2Payload):
    """
    Stage 2: 위성 궤도력(TLE/궤도 상태 벡터) 위조 탐지 & 확장 칼만 필터(EKF) 궤적 드리프트 차단
    """
    if not payload.ephemeris_drift_detector_active:
        raise HTTPException(status_code=400, detail="Ephemeris Kalman filter drift detector must be active")
    if payload.semi_major_axis_variance_km > 0.05:
        raise HTTPException(status_code=400, detail="Semi-major axis orbit variance exceeds safety limit (> 0.05 km)")
    if payload.eccentricity_error_pct > 0.02:
        raise HTTPException(status_code=400, detail="Orbital eccentricity perturbation exceeds tolerance (> 2%)")

    expected_hmac = hmac.new(
        SATCOM_SHARED_SECRET,
        f"orbit_state:{payload.orbit_session_id}".encode(),
        hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(expected_hmac, payload.orbit_session_hmac):
        raise HTTPException(status_code=403, detail="Invalid satellite orbital telemetry HMAC proof")

    flag = "FLAG{v227_s2_satellite_ephemeris_kalman_drift_shielded}"
    return {
        "status": "success",
        "stage": 2,
        "message": "Orbital ephemeris telemetry verified against ground radar baselines and Kalman drift suppressed",
        "flag": flag,
        "session_id": payload.orbit_session_id
    }


@app.post("/api/stage3/eval")
def evaluate_stage3(payload: Stage3Payload):
    """
    Stage 3: 원격 측정·명령(TT&C) 업링크 명령 주입 방어 & NIST FIPS 204 ML-DSA-87 서명 인가
    """
    if not payload.ttc_replay_defense_active:
        raise HTTPException(status_code=400, detail="TT&C uplink anti-replay defense counter must be active")
    if payload.telemetry_command_counter <= 1000:
        raise HTTPException(status_code=400, detail="Uplink telemetry command counter sequence stale or replayed (<= 1000)")
    if not payload.zero_trust_uplink_isolation:
        raise HTTPException(status_code=400, detail="Zero-trust uplink airgap isolation must be enabled")
    if payload.ttc_mldsa87_signature != "sig_satcom_ttc_mldsa87_uplink_auth_ok":
        raise HTTPException(status_code=403, detail="Invalid post-quantum ML-DSA-87 TT&C command signature")

    flag = "FLAG{v227_s3_ttc_uplink_mldsa87_command_authenticated}"
    return {
        "status": "success",
        "stage": 3,
        "message": "TT&C command uplink authenticated via NIST FIPS 204 ML-DSA-87 and anti-replay barrier verified",
        "flag": flag,
        "command_counter": payload.telemetry_command_counter
    }


@app.post("/api/stage4/eval")
def evaluate_stage4(payload: Stage4Payload):
    """
    Stage 4: 지상국-위성 간 연속변수 양자키 분배(CV-QKD) 채널 상태 검증 & 데코이 상태 위상 무작위화
    """
    if payload.quantum_optical_ber_pct > 0.035:
        raise HTTPException(status_code=400, detail="Quantum bit error rate (QBER) exceeds eavesdropping threshold (> 3.5%)")
    if not (0.2 <= payload.decoy_state_intensity_ratio <= 0.8):
        raise HTTPException(status_code=400, detail="Decoy-state optical intensity ratio outside calibrated bounds [0.2, 0.8]")

    expected_audit = hmac.new(
        SATCOM_SHARED_SECRET,
        f"cv_qkd:{payload.fips203_ml_kem_shared_key_hash}".encode(),
        hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(expected_audit, payload.space_ground_qkd_audit_hmac):
        raise HTTPException(status_code=403, detail="Invalid space-ground QKD mutual audit telemetry HMAC")

    flag = "FLAG{v227_s4_space_ground_cv_qkd_decoy_state_secured}"
    return {
        "status": "success",
        "stage": 4,
        "message": "Continuous-variable space QKD secured with decoy states and ML-KEM-1024 hybrid key exchange locked",
        "flag": flag,
        "qber_pct": payload.quantum_optical_ber_pct
    }
