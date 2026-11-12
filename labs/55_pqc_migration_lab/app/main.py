#!/usr/bin/env python3
"""
Lab 55: PQCMigrationGuard — FIPS 203/204 Post-Quantum Cryptography & Hybrid Migration Lab
Interactive simulation based on enterprise PQC cryptographic transition:
1. Store-Now-Decrypt-Later (SNDL) & Shor Algorithm Simulation: Intercepting legacy RSA/ECDSA
2. NIST FIPS 203 ML-KEM-768 (Kyber): Lattice-based Key Encapsulation & Decapsulation
3. NIST FIPS 204 ML-DSA-65 (Dilithium): Module-Lattice Digital Signatures & Anti-Tamper Verification
4. Enterprise Hybrid Key Exchange: X25519 + ML-KEM-768 HKDF Composition & Quantum Downgrade Defense
"""

from typing import Dict, Any, List, Optional
import os
import hashlib
import hmac
import secrets
from fastapi import FastAPI, HTTPException, status
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field

app = FastAPI(
    title="Lab 55: PQCMigrationGuard — Post-Quantum Cryptography Lab",
    description="Hands-on FIPS 203 ML-KEM, FIPS 204 ML-DSA, and Hybrid X25519 PQC Migration.",
    version="1.0.0",
)

# CTF Flags
STAGE1_FLAG = "FLAG{STORE_NOW_DECRYPT_LATER_QUANTUM_THREAT_5501}"
STAGE2_FLAG = "FLAG{FIPS203_ML_KEM_768_ENCAPSULATION_MASTERED_5502}"
STAGE3_FLAG = "FLAG{FIPS204_ML_DSA_65_LATTICE_SIGNATURE_VERIFIED_5503}"
STAGE4_FLAG = "FLAG{HYBRID_X25519_ML_KEM_ANTI_DOWNGRADE_SHIELDED_5504}"


class LabState:
    """State manager for Lab 55."""
    def __init__(self) -> None:
        self.reset()

    def reset(self) -> None:
        self.stage1_completed: bool = False
        self.stage2_completed: bool = False
        self.stage3_completed: bool = False
        self.stage4_completed: bool = False

        # Mock PQC Vault State
        self.ml_kem_pubkey: str = hashlib.sha256(b"fips203_ml_kem_768_seed_pk_v1").hexdigest()
        self.ml_kem_privkey: str = hashlib.sha256(b"fips203_ml_kem_768_seed_sk_v1").hexdigest()
        self.last_shared_secret: Optional[str] = None
        self.anti_downgrade_enforced: bool = False


state = LabState()


# --- Pydantic Request Models ---
class ShorInterceptRequest(BaseModel):
    target_algorithm: str = Field(..., max_length=32, description="Target legacy algorithm (e.g., RSA-2048, ECDH-P256)")
    captured_ciphertext: str = Field(..., max_length=256, description="Captured encrypted session key ciphertext")
    shor_qubit_count: int = Field(..., ge=2048, le=65536, description="Logical qubit capacity for quantum factoring")


class MLKEMEncapsulateRequest(BaseModel):
    recipient_pubkey: str = Field(..., max_length=128, description="Recipient FIPS 203 ML-KEM-768 public key")
    encapsulation_entropy: str = Field(..., max_length=64, description="Cryptographic seed/entropy for lattice polynomial sampling")
    matrix_dimension_k: int = Field(default=3, ge=2, le=4, description="ML-KEM rank parameter (k=3 for ML-KEM-768)")


class MLDSAVerifyRequest(BaseModel):
    document_hash: str = Field(..., max_length=64, description="SHA-256 hash of the document/certificate to verify")
    signature_hex: str = Field(..., max_length=512, description="FIPS 204 ML-DSA-65 signature bytes in hex")
    signer_pubkey: str = Field(..., max_length=128, description="ML-DSA-65 public key in hex")
    tamper_test: bool = Field(default=False, description="Whether to simulate payload tampering")


class HybridExchangeRequest(BaseModel):
    classical_curve: str = Field(..., max_length=32, description="Classical ECDH curve (e.g., X25519)")
    pqc_algorithm: str = Field(..., max_length=32, description="PQC KEM algorithm (e.g., ML-KEM-768)")
    enable_downgrade_prevention: bool = Field(..., description="Enforce TLS 1.3 Quantum-Resistant NamedGroup extension")
    tls_negotiated_group: str = Field(..., max_length=64, description="Negotiated KeyShare group")


# --- API Routes ---
@app.get("/", response_class=HTMLResponse)
async def get_index() -> str:
    template_path = os.path.join(os.path.dirname(__file__), "templates", "index.html")
    if os.path.exists(template_path):
        with open(template_path, "r", encoding="utf-8") as f:
            return f.read()
    return "<h1>Lab 55: PQCMigrationGuard Console Active</h1>"


@app.get("/api/health")
async def get_health() -> Dict[str, Any]:
    return {"status": "ok", "lab": "55", "name": "PQCMigrationGuard"}


@app.get("/api/status")
async def get_status() -> Dict[str, Any]:
    return {
        "status": "ready",
        "lab_id": "55",
        "lab_name": "PQCMigrationGuard",
        "stage1_completed": state.stage1_completed,
        "stage2_completed": state.stage2_completed,
        "stage3_completed": state.stage3_completed,
        "stage4_completed": state.stage4_completed,
        "anti_downgrade_enforced": state.anti_downgrade_enforced,
    }


@app.post("/api/reset")
async def post_reset() -> Dict[str, Any]:
    state.reset()
    return {"message": "Lab 55 state reset to initial baseline."}


# --- Stage 1: Store-Now-Decrypt-Later & Shor Algorithm Attack ---
@app.post("/api/stage1/intercept_shor")
async def stage1_intercept_shor(req: ShorInterceptRequest) -> Dict[str, Any]:
    """
    Simulates Shor's quantum algorithm against legacy RSA/ECDH.
    Evaluates quantum susceptibility of public-key algorithms under SNDL threat.
    """
    algo_upper = req.target_algorithm.upper().strip()
    if algo_upper not in ["RSA-2048", "RSA-3072", "RSA-4096", "ECDH-P256", "ECDH-P384"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported legacy algorithm: {req.target_algorithm}. Must be RSA-* or ECDH-*.",
        )

    if req.shor_qubit_count < 4096:
        return {
            "success": False,
            "message": "Quantum factoring failed: Insufficient fault-tolerant logical qubits for full period-finding.",
            "required_qubits": 4096,
            "allocated_qubits": req.shor_qubit_count,
        }

    # Derive cracked private exponent / discrete log
    cracked_secret = hashlib.sha256(f"shor_factor_{algo_upper}_{req.captured_ciphertext}".encode()).hexdigest()[:32]
    decrypted_session_key = hashlib.sha256(f"session_plaintext_{cracked_secret}".encode()).hexdigest()

    state.stage1_completed = True
    return {
        "success": True,
        "stage": 1,
        "vulnerability": "SNDL (Store-Now-Decrypt-Later) Threat Confirmed",
        "cracked_discrete_log_or_factor": cracked_secret,
        "recovered_session_key": decrypted_session_key,
        "remediation": "Immediate migration to FIPS 203 ML-KEM lattice-based key encapsulation required.",
        "flag": STAGE1_FLAG,
    }


# --- Stage 2: NIST FIPS 203 ML-KEM-768 Encapsulation ---
@app.post("/api/stage2/ml_kem_encapsulate")
async def stage2_ml_kem_encapsulate(req: MLKEMEncapsulateRequest) -> Dict[str, Any]:
    """
    Implements NIST FIPS 203 ML-KEM-768 (Module-Lattice Key Encapsulation Mechanism).
    Generates lattice ciphertext vector c and establishes quantum-secure shared key K.
    """
    if req.matrix_dimension_k != 3:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="ML-KEM-768 requires matrix dimension parameter k=3 (NIST Security Category 3).",
        )

    if len(req.encapsulation_entropy) < 16:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Encapsulation entropy must be at least 16 characters for uniform polynomial sampling.",
        )

    # Deterministic simulation of ML-KEM.Encaps(pk, coins)
    c_vector = hashlib.sha256(f"mlkem_c_{req.recipient_pubkey}_{req.encapsulation_entropy}".encode()).hexdigest()
    shared_secret = hashlib.sha256(f"mlkem_ss_{req.recipient_pubkey}_{c_vector}".encode()).hexdigest()
    state.last_shared_secret = shared_secret

    # Verify decapsulation equivalence
    decaps_ss = hashlib.sha256(f"mlkem_ss_{req.recipient_pubkey}_{c_vector}".encode()).hexdigest()
    if decaps_ss != shared_secret:
        return {"success": False, "message": "ML-KEM decapsulation mismatch."}

    state.stage2_completed = True
    return {
        "success": True,
        "stage": 2,
        "standard": "NIST FIPS 203 (ML-KEM-768)",
        "security_category": "NIST Level 3 (AES-192 equivalent quantum hardness)",
        "ciphertext_vector_c": c_vector,
        "shared_secret_K": shared_secret,
        "flag": STAGE2_FLAG,
    }


# --- Stage 3: NIST FIPS 204 ML-DSA-65 Digital Signature Verification ---
@app.post("/api/stage3/ml_dsa_verify")
async def stage3_ml_dsa_verify(req: MLDSAVerifyRequest) -> Dict[str, Any]:
    """
    Verifies NIST FIPS 204 ML-DSA-65 (Module-Lattice Digital Signature Algorithm).
    Detects bit-flipping attacks on signatures and enforces lattice short-integer-solution (SIS) checks.
    """
    if len(req.document_hash) != 64:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Document hash must be a valid 64-char SHA-256 hex string.",
        )

    # Valid signature generation reference
    expected_sig = hashlib.sha256(f"mldsa_sig_{req.document_hash}_{req.signer_pubkey}".encode()).hexdigest()

    if req.tamper_test or req.signature_hex != expected_sig:
        return {
            "success": False,
            "verified": False,
            "stage": 3,
            "alert": "SECURITY ALERT: Signature verification failed. Cryptographic tampering or bit-flip detected.",
            "expected_signature": expected_sig,
            "provided_signature": req.signature_hex,
        }

    state.stage3_completed = True
    return {
        "success": True,
        "verified": True,
        "stage": 3,
        "standard": "NIST FIPS 204 (ML-DSA-65)",
        "hard_problem": "Module Short Integer Solution (M-SIS) & M-LWE",
        "status": "VALID_QUANTUM_RESISTANT_SIGNATURE",
        "flag": STAGE3_FLAG,
    }


# --- Stage 4: Enterprise Hybrid Key Exchange & Anti-Downgrade Defense ---
@app.post("/api/stage4/hybrid_key_exchange")
async def stage4_hybrid_key_exchange(req: HybridExchangeRequest) -> Dict[str, Any]:
    """
    Integrates Classical ECDH (X25519) + PQC (ML-KEM-768) dual hybrid key exchange.
    Enforces anti-downgrade controls to thwart quantum stripping attacks.
    """
    curve_norm = req.classical_curve.upper().strip()
    pqc_norm = req.pqc_algorithm.upper().strip()

    if curve_norm != "X25519" or "ML-KEM" not in pqc_norm:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Enterprise hybrid profile must pair X25519 with ML-KEM-768.",
        )

    # Check for downgrade attempt
    if not req.enable_downgrade_prevention:
        state.anti_downgrade_enforced = False
        return {
            "success": False,
            "stage": 4,
            "error": "DOWNGRADE_VULNERABILITY: Quantum stripping attack possible without enforced NamedGroup extension.",
            "remediation": "Set enable_downgrade_prevention=true and negotiate X25519MLKEM768.",
        }

    negotiated = req.tls_negotiated_group.lower().strip()
    valid_groups = ["x25519mlkem768", "x25519_kyber768", "x25519+ml-kem-768"]
    if not any(vg in negotiated for vg in valid_groups):
        return {
            "success": False,
            "stage": 4,
            "error": f"Negotiated group '{req.tls_negotiated_group}' rejected by anti-downgrade policy. Hybrid required.",
        }

    # Dual Key Derivation using HKDF-Extract & Expand
    k_x25519 = hashlib.sha256(b"mock_classical_x25519_shared_secret").digest()
    k_mlkem = hashlib.sha256(b"mock_pqc_mlkem768_shared_secret").digest()
    combined_input = k_x25519 + k_mlkem

    hybrid_session_key = hmac.new(b"hybrid_hkdf_salt_2026", combined_input, hashlib.sha256).hexdigest()

    state.stage4_completed = True
    state.anti_downgrade_enforced = True

    return {
        "success": True,
        "stage": 4,
        "architecture": "Hybrid Classical-PQC Key Exchange",
        "named_group": "X25519MLKEM768 (draft-ietf-tls-hybrid-design)",
        "hybrid_session_key": hybrid_session_key,
        "downgrade_shield": "ACTIVE (Strict PQC Enforcement Policy)",
        "flag": STAGE4_FLAG,
    }
