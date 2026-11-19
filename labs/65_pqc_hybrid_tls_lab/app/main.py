import hashlib
import hmac
import os
import time
from typing import Dict, Any, List, Optional
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

app = FastAPI(
    title="PqcHybridTlsLab",
    description="Post-Quantum Hybrid TLS 1.3 & ML-KEM / ML-DSA Migration Lab",
    version="1.0.0"
)

# Simulated PQC Cryptographic State
SUPPORTED_PQC_GROUPS = ["X25519_MLKEM768", "SecP256r1_MLKEM768", "x25519_kyber768"]
CLASSICAL_GROUPS = ["x25519", "secp256r1", "secp384r1"]
DOWNGRADE_CANARY_TLS12 = b"DOWNGRD\x01"


class Stage1Request(BaseModel):
    key_exchange_group: str = Field(..., description="Key exchange group (e.g. x25519, X25519_MLKEM768)")
    sndl_intercept_sim: bool = Field(True, description="Simulate adversary harvesting handshake for SNDL decryption")
    use_hybrid_kem: bool = Field(False, description="Enable FIPS 203 ML-KEM-768 hybrid key exchange")


class Stage2Request(BaseModel):
    cert_algorithm: str = Field(..., description="Certificate signature algorithm (e.g. RSA3072, ECDSA_P384, COMPOSITE_MLDSA65_ECDSA)")
    dual_signature_validation: bool = Field(False, description="Enforce composite dual-signature cross-verification")
    use_mldsa_guard: bool = Field(False, description="Enable FIPS 204 ML-DSA-65 post-quantum signature validation")


class Stage3Request(BaseModel):
    offered_versions: List[str] = Field(..., description="TLS protocol versions offered by client (e.g. ['TLSv1.2', 'TLSv1.3'])")
    cipher_suites: List[str] = Field(..., description="Cipher suites offered in ClientHello")
    supported_groups: List[str] = Field(..., description="Named groups supported for key exchange")
    enforce_anti_downgrade: bool = Field(False, description="Enforce strict TLS 1.3 and anti-downgrade canary verification")


class Stage4Request(BaseModel):
    ntt_algorithm: str = Field(..., description="NTT implementation (e.g. unmasked_standard_ntt, constant_time_masked_ntt)")
    side_channel_probe: bool = Field(True, description="Execute simulated power/timing side-channel probe")
    use_masked_memory: bool = Field(False, description="Enable constant-time Montgomery reduction & Boolean-to-Arithmetic masking")


@app.get("/", response_class=HTMLResponse)
def index():
    return """<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <title>Lab 65: Post-Quantum Hybrid TLS 1.3 & ML-KEM / ML-DSA Migration Lab</title>
    <style>
        body { font-family: monospace; background: #0d1117; color: #c9d1d9; padding: 2rem; }
        h1 { color: #58a6ff; border-bottom: 1px solid #30363d; padding-bottom: 0.5rem; }
        .card { background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 1.5rem; margin-bottom: 1.5rem; }
        .stage-title { color: #7ee787; font-weight: bold; margin-bottom: 0.5rem; }
        code { background: #21262d; padding: 0.2rem 0.4rem; border-radius: 3px; color: #f0883e; }
        .badge { display: inline-block; background: #1f6feb; color: #fff; padding: 0.2rem 0.6rem; border-radius: 12px; font-size: 0.8rem; }
    </style>
</head>
<body>
    <h1>⚛️ Lab 65: Post-Quantum Hybrid TLS 1.3 & ML-KEM / ML-DSA Migration Lab <span class="badge">Port 8065</span></h1>
    <div class="card">
        <p>포스트 양자 암호(PQC) FIPS 203 ML-KEM-768(Kyber) 하이브리드 키 교환 및 FIPS 204 ML-DSA-65(Dilithium) 복합 인증서를 TLS 1.3에 적용하여 SNDL(Harvest Now, Decrypt Later) 도청과 다운그레이드 공격을 방어하는 실전 랩입니다.</p>
        <p>컴플라이언스: <strong>KISA ISMS-P 2.7.1 / 2.7.2</strong>, <strong>NIST CSF 2.0 PR.DS-01 / PR.DS-02 (FIPS 203/204)</strong>, <strong>OWASP A02:2025</strong></p>
    </div>
    <div class="card">
        <div class="stage-title">Stage 1: Harvest Now, Decrypt Later (SNDL) & Hybrid ML-KEM-768 Key Exchange</div>
        <p>엔드포인트: <code>POST /api/stage1/eval</code></p>
    </div>
    <div class="card">
        <div class="stage-title">Stage 2: Quantum Forgery & FIPS 204 ML-DSA-65 Composite Dual Signature</div>
        <p>엔드포인트: <code>POST /api/stage2/eval</code></p>
    </div>
    <div class="card">
        <div class="stage-title">Stage 3: Active Downgrade Attack Defense & TLS 1.3 Cipher Suite Hardening</div>
        <p>엔드포인트: <code>POST /api/stage3/eval</code></p>
    </div>
    <div class="card">
        <div class="stage-title">Stage 4: Side-Channel Timing Probe Defense & Constant-Time NTT Verification</div>
        <p>엔드포인트: <code>POST /api/stage4/eval</code></p>
    </div>
</body>
</html>
"""


@app.get("/api/health")
def health():
    return {
        "status": "healthy",
        "lab": "Lab 65: Post-Quantum Hybrid TLS 1.3 & ML-KEM / ML-DSA Migration Lab",
        "port": 8065,
        "standards": ["FIPS 203 ML-KEM", "FIPS 204 ML-DSA", "RFC 8446 TLS 1.3"]
    }


@app.post("/api/stage1/eval")
def evaluate_stage1(req: Stage1Request):
    """
    Stage 1: Harvest Now, Decrypt Later (SNDL) & Hybrid ML-KEM-768 Key Exchange
    """
    norm_group = req.key_exchange_group.strip()
    is_hybrid = norm_group in SUPPORTED_PQC_GROUPS or "mlkem" in norm_group.lower() or "kyber" in norm_group.lower()

    if not req.use_hybrid_kem or not is_hybrid:
        # Exploit Path: Classical ECDHE captured for future Shor quantum attack
        simulated_shor_key = hashlib.sha256(f"classical_ecdh_{norm_group}".encode()).hexdigest()
        return {
            "status": "vulnerable",
            "message": f"SNDL 취약점 확인: 고전 키 교환 그룹 '{norm_group}' 단독 사용으로 양자 컴퓨터 쇼어 알고리즘에 의해 세션키가 사전 복호화 대상이 됩니다.",
            "classical_group": norm_group,
            "harvested_intercept": True,
            "simulated_quantum_decrypted_secret": simulated_shor_key[:32],
            "quantum_resistance_bits": 0,
            "remediation_hint": "FIPS 203 ML-KEM-768 하이브리드 키 교환 그룹('X25519_MLKEM768')을 활성화하고 use_hybrid_kem을 true로 설정하십시오."
        }

    # Defense Path: Hybrid X25519 + ML-KEM-768 key derivation
    classical_shared = hashlib.sha256(b"x25519_ephemeral_point").digest()
    pqc_shared = hashlib.sha3_256(b"ml_kem_768_lattice_ss").digest()
    hybrid_session_key = hmac.new(b"tls13_pqc_hybrid_extract", classical_shared + pqc_shared, hashlib.sha256).hexdigest()

    return {
        "status": "defended",
        "message": "하이브리드 PQC 키 교환(X25519 + ML-KEM-768) 수립 완료. 격자 기반 Learning With Errors(LWE) 난제로 인해 SNDL 공격이 원천 무력화되었습니다.",
        "negotiated_group": norm_group,
        "hybrid_kdf_binding": "HKDF-Extract(X25519_SS || ML-KEM-768_SS)",
        "quantum_security_level": "NIST Security Category 3 (192-bit quantum-resilient)",
        "derived_hybrid_key": hybrid_session_key[:32],
        "flag": "FLAG{pqc_hybrid_kem_sndl_resilient_2026}"
    }


@app.post("/api/stage2/eval")
def evaluate_stage2(req: Stage2Request):
    """
    Stage 2: Quantum Forgery & FIPS 204 ML-DSA-65 Composite Dual Signature
    """
    algo = req.cert_algorithm.strip().upper()
    is_composite = "COMPOSITE" in algo or ("MLDSA" in algo and "ECDSA" in algo)

    if not req.use_mldsa_guard or not req.dual_signature_validation or not is_composite:
        # Exploit Path: Classical RSA / ECDSA vulnerable to Shor factorization
        forged_cert_id = hashlib.sha256(f"forged_cert_{algo}".encode()).hexdigest()[:16]
        return {
            "status": "vulnerable",
            "message": f"양자 서명 위조 취약점 확인: 알고리즘 '{algo}'은 양자 컴퓨터 쇼어 알고리즘에 의해 개인키가 인수분해/이산대수 역산되어 인증서가 위조될 수 있습니다.",
            "algorithm": algo,
            "forged_certificate_serial": f"0x{forged_cert_id}",
            "mitm_spoofing_possible": True,
            "remediation_hint": "FIPS 204 ML-DSA-65와 ECDSA P-384 복합 인증서('COMPOSITE_MLDSA65_ECDSA')를 적용하고 dual_signature_validation 및 use_mldsa_guard를 활성화하십시오."
        }

    # Defense Path: Composite Dual-Signature validation
    classical_sig = hashlib.sha256(b"ecdsa_p384_sig").hexdigest()[:24]
    pqc_sig = hashlib.sha3_256(b"ml_dsa_65_lattice_sig").hexdigest()[:48]

    return {
        "status": "defended",
        "message": "FIPS 204 ML-DSA-65 + ECDSA P-384 복합 전자서명 교차 검증 통과. 고전 및 포스트 양자 서명이 모두 유효하여 양자 기반 신원 위조가 완벽 차단되었습니다.",
        "composite_algorithm": algo,
        "classical_sig_verified": f"ECDSA-P384: {classical_sig}",
        "pqc_sig_verified": f"ML-DSA-65: {pqc_sig}",
        "dual_verification_passed": True,
        "flag": "FLAG{pqc_dual_sig_mldsa_composite_certified}"
    }


@app.post("/api/stage3/eval")
def evaluate_stage3(req: Stage3Request):
    """
    Stage 3: Active Downgrade Attack Defense & TLS 1.3 Cipher Suite Hardening
    """
    # Check for legacy versions or non-PQC downgrade
    allows_legacy_tls = any(v in ["TLSv1.0", "TLSv1.1", "TLSv1.2"] for v in req.offered_versions)
    has_pqc_group = any(g in SUPPORTED_PQC_GROUPS or "mlkem" in g.lower() for g in req.supported_groups)

    if not req.enforce_anti_downgrade or allows_legacy_tls or not has_pqc_group:
        return {
            "status": "vulnerable",
            "message": "액티브 다운그레이드 공격 노출: 레거시 TLS 버전 허용 또는 PQC 하이브리드 그룹 미강제로 인해 MITM이 고전 암호 스위트로 강제 강등할 수 있습니다.",
            "allows_legacy_tls": allows_legacy_tls,
            "has_pqc_group": has_pqc_group,
            "stripping_attack_detected": True,
            "remediation_hint": "TLS 1.3 전용 강제(['TLSv1.3']), PQC 하이브리드 그룹 포함(['X25519_MLKEM768']), enforce_anti_downgrade=true로 설정하십시오."
        }

    # Defense Path: Strict TLS 1.3 with anti-downgrade canary
    downgrade_canary = hashlib.sha256(DOWNGRADE_CANARY_TLS12 + b":strict_tls13").hexdigest()[:16]

    return {
        "status": "defended",
        "message": "TLS 1.3 안티 다운그레이드 카나리 검증 및 고전 암호 스위트 전면 차단 완료. 비PQC 암호 강등 시도가 인라인에서 거부되었습니다.",
        "negotiated_version": "TLSv1.3",
        "anti_downgrade_canary_verified": f"0x{downgrade_canary}",
        "enforced_groups": req.supported_groups,
        "tls12_fallback_blocked": True,
        "flag": "FLAG{pqc_anti_downgrade_strict_handshake_guarded}"
    }


@app.post("/api/stage4/eval")
def evaluate_stage4(req: Stage4Request):
    """
    Stage 4: Side-Channel Timing Probe Defense & Constant-Time NTT Verification
    """
    algo = req.ntt_algorithm.strip().lower()
    is_constant_time = "constant" in algo and "masked" in algo

    if not req.use_masked_memory or not is_constant_time:
        # Exploit Path: Side-channel timing variance leaks secret polynomial
        simulated_leakage_variance_ns = 18.4
        return {
            "status": "vulnerable",
            "message": f"부채널 타이밍 공격 노출: '{req.ntt_algorithm}'의 비상수시간 연산 및 메모리 미마스킹으로 인해 타이밍 편차(Δt={simulated_leakage_variance_ns}ns)가 발생하여 비밀 다항식 계수가 복원될 수 있습니다.",
            "ntt_algorithm": req.ntt_algorithm,
            "timing_variance_ns": simulated_leakage_variance_ns,
            "side_channel_leakage_detected": True,
            "remediation_hint": "상수시간 몽고메리 연산과 메모리 마스킹 알고리즘('constant_time_masked_ntt')을 적용하고 use_masked_memory를 true로 설정하십시오."
        }

    # Defense Path: Constant-Time NTT & Masked Arithmetic
    simulated_flat_jitter_ns = 0.12
    return {
        "status": "defended",
        "message": "상수시간(Constant-Time) NTT 모듈러 축약 및 1차 불리언-산술 마스킹 적용 완료. 타이밍 편차가 0.12ns로 평탄화되어 부채널 공격이 완벽 방어되었습니다.",
        "ntt_algorithm": req.ntt_algorithm,
        "measured_timing_jitter_ns": simulated_flat_jitter_ns,
        "side_channel_leakage": "ZERO_LEAKAGE (Constant-Time Verified)",
        "flag": "FLAG{pqc_constant_time_ntt_masked_hardened}"
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8065)
