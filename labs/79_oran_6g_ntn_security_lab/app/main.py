#!/usr/bin/env python3
"""
Lab 79: Oran6gNtnSecurityLab
6G NTN & O-RAN Near-RT RIC / Open Fronthaul / PQC Handover Security Lab
Port: 8079 (127.0.0.1 loopback isolation strictly enforced)
"""

import hashlib
import hmac
import os
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

app = FastAPI(
    title="Lab 79: Oran6gNtnSecurityLab",
    description="6G NTN & O-RAN Telecom Infrastructure Security Lab",
    version="2.29.0",
)

ORAN_SHARED_SECRET = os.environ.get(
    "VHACK_ORAN_SECRET",
    "vibe-2026-enterprise-oran-6g-ntn-secret-8079",
).encode("utf-8")


class Stage1Payload(BaseModel):
    xapp_id: str
    spiffe_svid_uri: str
    e2_mtls_verified: bool
    e2sm_kpm_schema_allowlisted: bool


class Stage2Payload(BaseModel):
    fronthaul_protocol: str
    macsec_cipher: str
    ptp_nts_authenticated: bool
    ptp_clock_drift_ns: float
    ecpri_session_id: str
    ecpri_frame_hmac: str


class Stage3Payload(BaseModel):
    slice_sst: int
    a1_policy_signed_rbac: bool
    sla_bandwidth_guarantees_pct: float
    upf_teid_isolation_active: bool


class Stage4Payload(BaseModel):
    pqc_kem_suite: str
    fips204_mldsa65_ric_attestation: str
    ntn_handover_quorum_nodes: int
    handover_token_hash: str
    oran_audit_hmac: str


def _compute_hmac(prefix: str, value: str) -> str:
    return hmac.new(
        ORAN_SHARED_SECRET,
        f"{prefix}:{value}".encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


@app.get("/")
def get_root():
    return {
        "lab": "Lab 79: 6G NTN & O-RAN Telecom Infrastructure Security Lab",
        "status": "ready",
        "port": 8079,
        "stages": 4,
        "category": "telecom_oran_6g_security",
        "version": "2.29.0",
    }


@app.get("/api/health")
def get_health():
    return {
        "status": "ok",
        "lab_id": 79,
        "name": "oran_6g_ntn_security_lab",
        "stages": 4,
        "category": "telecom_oran_6g_security",
        "version": "2.29.0",
    }


@app.get("/api/status")
def get_status():
    return {
        "lab_id": "79",
        "name": "Oran6gNtnSecurityLab",
        "port": 8079,
        "status": "running",
        "total_stages": 4,
        "solved_count": 0,
        "stages": {
            "stage1_solved": False,
            "stage2_solved": False,
            "stage3_solved": False,
            "stage4_solved": False,
        },
    }


@app.post("/api/stage1/eval")
def evaluate_stage1(payload: Stage1Payload):
    """Stage 1: Near-RT RIC E2 xApp 등록 인가 및 SPIFFE mTLS 스키마 검증."""
    if not payload.xapp_id.startswith("xapp_oran_2026_"):
        raise HTTPException(status_code=400, detail="Invalid O-RAN xApp identifier format")
    if not payload.spiffe_svid_uri.startswith("spiffe://oran.vibe.local/ns/ric/sa/"):
        raise HTTPException(status_code=400, detail="SPIFFE SVID trust domain mismatch")
    if not payload.e2_mtls_verified:
        raise HTTPException(status_code=400, detail="E2 interface strict mTLS handshake must be verified")
    if not payload.e2sm_kpm_schema_allowlisted:
        raise HTTPException(status_code=400, detail="E2SM-KPM service model schema must be allowlisted")

    return {
        "status": "success",
        "stage": 1,
        "message": "Near-RT RIC E2 xApp identity and E2SM schema allowlist verified",
        "flag": "FLAG{v229_s1_oran_e2_spiffe_mtls_xapp_verified}",
        "xapp_id": payload.xapp_id,
    }


@app.post("/api/stage2/eval")
def evaluate_stage2(payload: Stage2Payload):
    """Stage 2: Open Fronthaul eCPRI MACsec 암호화 및 IEEE 1588v2 PTP NTS 동기화 방어."""
    if payload.fronthaul_protocol != "ecpri_split_7_2x":
        raise HTTPException(status_code=400, detail="Unsupported fronthaul split: must be ecpri_split_7_2x")
    if payload.macsec_cipher != "AES-256-GCM":
        raise HTTPException(status_code=400, detail="Fronthaul MACsec cipher must be AES-256-GCM")
    if not payload.ptp_nts_authenticated:
        raise HTTPException(status_code=400, detail="IEEE 1588v2 PTP timing must be NTS-authenticated")
    if payload.ptp_clock_drift_ns > 130.0 or payload.ptp_clock_drift_ns < 0.0:
        raise HTTPException(status_code=400, detail="PTP clock drift exceeds 3GPP 130ns phase sync bound")

    expected_hmac = _compute_hmac("ecpri_session", payload.ecpri_session_id)
    if not hmac.compare_digest(expected_hmac, payload.ecpri_frame_hmac):
        raise HTTPException(status_code=403, detail="Invalid eCPRI fronthaul frame HMAC")

    return {
        "status": "success",
        "stage": 2,
        "message": "Open Fronthaul eCPRI MACsec and NTS-authenticated PTP timing hardened",
        "flag": "FLAG{v229_s2_ecpri_macsec_ptp_sync_hardened}",
        "ecpri_session_id": payload.ecpri_session_id,
    }


@app.post("/api/stage3/eval")
def evaluate_stage3(payload: Stage3Payload):
    """Stage 3: A1 정책 서명 강제 및 6G 네트워크 슬라이스 UPF TEID 격리."""
    if payload.slice_sst not in (1, 2, 3):
        raise HTTPException(status_code=400, detail="Invalid 3GPP Slice/Service Type (SST must be 1, 2, or 3)")
    if not payload.a1_policy_signed_rbac:
        raise HTTPException(status_code=400, detail="A1 policy updates must enforce signed RBAC authorization")
    if payload.sla_bandwidth_guarantees_pct < 95.0 or payload.sla_bandwidth_guarantees_pct > 100.0:
        raise HTTPException(status_code=400, detail="Slice SLA bandwidth guarantee out of [95.0, 100.0] range")
    if not payload.upf_teid_isolation_active:
        raise HTTPException(status_code=400, detail="UPF GTP-U TEID per-slice isolation must be active")

    return {
        "status": "success",
        "stage": 3,
        "message": "A1 policy poisoning blocked and 6G network slice TEID isolation enforced",
        "flag": "FLAG{v229_s3_oran_a1_slice_teid_isolation_enforced}",
        "slice_sst": payload.slice_sst,
    }


@app.post("/api/stage4/eval")
def evaluate_stage4(payload: Stage4Payload):
    """Stage 4: 6G NTN 위성-지상국 PQC 핸드오버(ML-KEM-768 + ML-DSA-65) 및 원격 증명."""
    if payload.pqc_kem_suite != "X25519_MLKEM768":
        raise HTTPException(status_code=400, detail="NTN handover KEM must be hybrid X25519_MLKEM768")
    if payload.fips204_mldsa65_ric_attestation != "sig_oran_mldsa65_ric_enclave_attested":
        raise HTTPException(status_code=403, detail="Invalid NIST FIPS 204 ML-DSA-65 RIC attestation signature")
    if payload.ntn_handover_quorum_nodes < 3:
        raise HTTPException(status_code=400, detail="NTN multi-satellite handover quorum requires at least 3 nodes")

    expected_audit = _compute_hmac("ntn_handover", payload.handover_token_hash)
    if not hmac.compare_digest(expected_audit, payload.oran_audit_hmac):
        raise HTTPException(status_code=403, detail="Invalid 6G NTN handover audit HMAC")

    return {
        "status": "success",
        "stage": 4,
        "message": "6G NTN post-quantum handover and Zero-Trust RIC attestation verified",
        "flag": "FLAG{v229_s4_6g_ntn_pqc_handover_attested}",
        "quorum_nodes": payload.ntn_handover_quorum_nodes,
    }
