#!/usr/bin/env python3
"""
Lab 39: CryptoShield — Modern Cryptography & Cryptanalysis Lab
Interactive FastAPI service demonstrating core cryptographic attacks and defenses:
1. AES-CBC Padding Oracle & Bit-Flipping attack
2. RSA Bleichenbacher PKCS#1 v1.5 Signature Forgery (e=3)
3. ECDSA Nonce Reuse Private Key Recovery
4. Post-Quantum Cryptography (PQC) ML-KEM-768 Hybrid Key Exchange defense
"""

from typing import Dict, Any, Optional
import os
import hashlib
import json
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

app = FastAPI(
    title="Lab 39: CryptoShield — Modern Cryptography & Cryptanalysis Lab",
    description="Hands-on security simulation for AES-CBC Padding Oracle, RSA Bleichenbacher Forgery, ECDSA Nonce Reuse, and Post-Quantum Hybrid KEM.",
    version="1.0.0",
)

# Flags
STEP1_FLAG = "FLAG{CBC_PADDING_ORACLE_AND_BITFLIP_MASTER_8831}"
STEP2_FLAG = "FLAG{RSA_BLEICHENBACHER_SIGNATURE_FORGERY_PWN_7742}"
STEP3_FLAG = "FLAG{ECDSA_REUSED_NONCE_PRIVATE_KEY_CARVED_9953}"
STEP4_FLAG = "FLAG{POST_QUANTUM_HYBRID_KYBER_KEM_IMMUNE_4421}"

# ============================================================================
# Crypto Parameters & State
# ============================================================================
AES_KEY = b"CryptoShield_Key"  # 16-byte fixed AES-128 key
BLOCK_SIZE = 16

# 2048-bit RSA Modulus with small exponent e=3
RSA_E = 3
# Pre-generated safe 2048-bit modulus for deterministic lab experience
RSA_N_HEX = (
    "c5e93df7b5e43890f848be4cf9509df638a16723b7b4ff4c0e66cfa92a34bbec"
    "6dcfe2eb38202d6b3562a0ee6a661ef494dbd33b49704e6c3dc9bf6f6b5c00a7"
    "47565b3d68379ba2c13d9cf4ef24cbff20cfa823d458c8ec76329bf3368c2f16"
    "c02685cf75eb5b89ebcbf53ec6e2d83769c9eb11c62f22b0a1a0d33e5066d17b"
    "789ea2bf411e74f88e404b8686ff225ad7a68ea23df1f8eb4f7cfef07b8b7d90"
    "16259e89d13fc8dae28d84a7e9e51c89304a3ad2b4f9e4eb581b7a2d8cb3b8ef"
    "f27a69bc923e618e474582f3ef84c7de334f590b14c330fef6b8fef65c71be39"
    "d6840d216f9a0c6498ad067f917544ef4a65287ab666144e52ec77f1efd9c19b"
)
RSA_N = int(RSA_N_HEX, 16)
RSA_TARGET_MSG = "admin_access_token_v1"
ASN1_SHA256 = bytes.fromhex("3031300d060960864801650304020105000420")

# ECDSA Parameters (secp256k1 curve order)
ECDSA_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
ECDSA_SECRET_D = 0x1337C0DECAFEBEEF1337C0DECAFEBEEF1337C0DECAFEBEEF1337C0DECAFEBEEF
ECDSA_FIXED_K = 0x9876543210FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210FEDCBA
ECDSA_R = 0x4B3128C0FE49D1089201DE2B61B1E32A00F7A6E535C6D1F9975765691E14A895 % ECDSA_N
ECDSA_MSG1 = "transfer_funds_amount=100_to=Alice"
ECDSA_MSG2 = "transfer_funds_amount=50000_to=Bob"

# Pre-calculate ECDSA signatures for Msg1 and Msg2 with reused k
_z1 = int(hashlib.sha256(ECDSA_MSG1.encode()).hexdigest(), 16) % ECDSA_N
_z2 = int(hashlib.sha256(ECDSA_MSG2.encode()).hexdigest(), 16) % ECDSA_N
_k_inv = pow(ECDSA_FIXED_K, -1, ECDSA_N)
ECDSA_S1 = (_k_inv * (_z1 + ECDSA_R * ECDSA_SECRET_D)) % ECDSA_N
ECDSA_S2 = (_k_inv * (_z2 + ECDSA_R * ECDSA_SECRET_D)) % ECDSA_N

# Lab State
state: Dict[str, Any] = {}


def reset_lab() -> None:
    """Reset lab challenges to initial baseline."""
    global state
    state = {
        "step1_completed": False,
        "step2_completed": False,
        "step3_completed": False,
        "step4_completed": False,
        "quantum_attack_simulated": False,
        "hybrid_kem_enabled": False,
        "logs": [],
    }


reset_lab()


# ============================================================================
# Helpers
# ============================================================================
def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)


def pkcs7_unpad(data: bytes, block_size: int = 16) -> bytes:
    if not data or len(data) % block_size != 0:
        raise ValueError("Invalid length for block cipher ciphertext")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > block_size:
        raise ValueError(f"Invalid PKCS#7 padding byte: {pad_len}")
    if data[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("Inconsistent PKCS#7 padding bytes")
    return data[:-pad_len]


def aes_cbc_encrypt(plaintext: bytes, iv: bytes) -> bytes:
    backend = default_backend()
    cipher = Cipher(algorithms.AES(AES_KEY), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    padded = pkcs7_pad(plaintext, BLOCK_SIZE)
    return encryptor.update(padded) + encryptor.finalize()


def aes_cbc_decrypt_raw(ciphertext: bytes, iv: bytes) -> bytes:
    backend = default_backend()
    cipher = Cipher(algorithms.AES(AES_KEY), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


# ============================================================================
# Request Models
# ============================================================================
class CBCOracleRequest(BaseModel):
    iv: str = Field(..., description="Hex-encoded 16-byte IV")
    ciphertext: str = Field(..., description="Hex-encoded ciphertext")


class CBCVerifyRequest(BaseModel):
    iv: str = Field(..., description="Hex-encoded 16-byte IV")
    ciphertext: str = Field(..., description="Hex-encoded ciphertext")


class RSAVerifyRequest(BaseModel):
    message: str = Field(..., description="Target message to verify")
    signature: str = Field(..., description="Hex-encoded forged signature integer s")


class ECDSAKeySubmitRequest(BaseModel):
    private_key: str = Field(..., description="Hex or decimal carved private key d")


class HybridKEMRequest(BaseModel):
    client_public_share: str = Field(..., description="Hex-encoded client hybrid KEM share")


# ============================================================================
# Endpoints
# ============================================================================
@app.get("/", response_class=HTMLResponse)
async def root():
    static_file = os.path.join(os.path.dirname(__file__), "static", "index.html")
    if os.path.exists(static_file):
        with open(static_file, "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    return HTMLResponse(
        content="<h1>Lab 39: CryptoShield — Modern Cryptography Lab Active</h1>"
    )


@app.get("/health")
async def health():
    return {
        "status": "ok",
        "lab": "39_modern_cryptography_lab",
        "port": 8039,
        "step1_completed": state["step1_completed"],
        "step2_completed": state["step2_completed"],
        "step3_completed": state["step3_completed"],
        "step4_completed": state["step4_completed"],
    }


@app.get("/api/crypto/status")
async def get_status():
    return {
        "status": "operational",
        "steps": {
            "step1_cbc_oracle": state["step1_completed"],
            "step2_rsa_bleichenbacher": state["step2_completed"],
            "step3_ecdsa_nonce": state["step3_completed"],
            "step4_hybrid_kem": state["step4_completed"],
        },
        "quantum_attack_simulated": state["quantum_attack_simulated"],
        "hybrid_kem_enabled": state["hybrid_kem_enabled"],
        "recent_logs": state["logs"][-10:],
    }


@app.post("/api/crypto/reset")
async def reset_endpoint():
    reset_lab()
    return {"status": "reset", "message": "CryptoShield environment reset to initial state"}


# ----------------------------------------------------------------------------
# Stage 1: AES-CBC Padding Oracle & Bit-Flipping
# ----------------------------------------------------------------------------
@app.get("/api/crypto/cbc/profile")
async def get_cbc_profile():
    """Returns guest profile encrypted with AES-CBC."""
    plain = b"admin=0;role=user;uid=1092"
    iv = os.urandom(16)
    ct = aes_cbc_encrypt(plain, iv)
    return {
        "iv": iv.hex(),
        "ciphertext": ct.hex(),
        "format": "admin=0;role=user;uid=...",
        "hint": "Use padding oracle to decrypt or bit-flipping on IV[6] to change admin=0 to admin=1.",
    }


@app.post("/api/crypto/cbc/oracle")
async def cbc_oracle(req: CBCOracleRequest):
    """Padding oracle endpoint: tests whether decrypted bytes satisfy PKCS#7."""
    try:
        iv = bytes.fromhex(req.iv)
        ct = bytes.fromhex(req.ciphertext)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid hex encoding")

    if len(iv) != 16:
        raise HTTPException(status_code=400, detail="IV must be exactly 16 bytes")
    if len(ct) == 0 or len(ct) % 16 != 0:
        raise HTTPException(status_code=400, detail="Ciphertext must be a multiple of 16 bytes")

    raw_decrypted = aes_cbc_decrypt_raw(ct, iv)
    try:
        pkcs7_unpad(raw_decrypted, BLOCK_SIZE)
        return {"valid": True, "message": "Padding is valid PKCS#7"}
    except ValueError:
        return JSONResponse(
            status_code=400,
            content={"valid": False, "message": "Invalid PKCS#7 padding detected"},
        )


@app.post("/api/crypto/cbc/verify")
async def cbc_verify(req: CBCVerifyRequest):
    """Verifies authentication token. If decrypted token contains admin=true or role=admin, yields flag."""
    try:
        iv = bytes.fromhex(req.iv)
        ct = bytes.fromhex(req.ciphertext)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid hex encoding")

    if len(iv) != 16 or len(ct) % 16 != 0:
        raise HTTPException(status_code=400, detail="Malformed IV or ciphertext blocks")

    raw_decrypted = aes_cbc_decrypt_raw(ct, iv)
    try:
        unpadded = pkcs7_unpad(raw_decrypted, BLOCK_SIZE)
    except ValueError:
        raise HTTPException(status_code=400, detail="Decryption failed: bad padding")

    text = unpadded.decode("latin1", errors="ignore")
    is_admin = ("admin=1" in text) or ("admin=true" in text) or ("role=admin" in text)

    if is_admin:
        state["step1_completed"] = True
        state["logs"].append("Stage 1 SUCCESS: Administrator access obtained via CBC attack!")
        return {
            "success": True,
            "message": "Welcome Administrator! Privilege elevated successfully.",
            "plaintext": text,
            "flag": STEP1_FLAG,
        }
    return {
        "success": False,
        "message": "Token valid but privileges insufficient (guest).",
        "plaintext": text,
    }


# ----------------------------------------------------------------------------
# Stage 2: RSA Bleichenbacher PKCS#1 v1.5 Signature Forgery (e=3)
# ----------------------------------------------------------------------------
@app.get("/api/crypto/rsa/pubkey")
async def get_rsa_pubkey():
    """Returns RSA public parameters and vulnerable parsing specification."""
    return {
        "modulus_n": RSA_N_HEX,
        "exponent_e": RSA_E,
        "key_size_bits": 2048,
        "target_message": RSA_TARGET_MSG,
        "asn1_sha256_prefix": ASN1_SHA256.hex(),
        "vulnerability": "Bleichenbacher '06 loose PKCS#1 v1.5 validation: parser accepts garbage bytes after DigestInfo.",
    }


@app.post("/api/crypto/rsa/verify-signature")
async def rsa_verify_signature(req: RSAVerifyRequest):
    """Vulnerable PKCS#1 v1.5 verification parser."""
    if req.message != RSA_TARGET_MSG:
        raise HTTPException(
            status_code=400,
            detail=f"Target message must be exactly '{RSA_TARGET_MSG}'",
        )

    try:
        sig_int = int(req.signature.strip(), 16)
    except ValueError:
        try:
            sig_int = int(req.signature.strip(), 10)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid signature format (must be hex or int)")

    if sig_int <= 0 or sig_int >= RSA_N:
        raise HTTPException(status_code=400, detail="Signature integer out of range [1, N-1]")

    # Calculate s^3 mod N
    decrypted_int = pow(sig_int, RSA_E, RSA_N)
    decrypted_bytes = decrypted_int.to_bytes(256, "big")

    # Vulnerable parsing logic:
    # Looks for: \x00\x01\xff...\x00 || ASN.1 DigestInfo || SHA256(msg) at the prefix
    # Does NOT enforce padding length to the end of the 256 bytes!
    expected_hash = hashlib.sha256(req.message.encode()).digest()
    prefix_anchor = b"\x00\x01\xff\x00" + ASN1_SHA256 + expected_hash

    # Check if decrypted block begins with prefix anchor or has multiple 0xff followed by 0x00 and hash
    valid_format = False
    if decrypted_bytes.startswith(prefix_anchor):
        valid_format = True
    elif decrypted_bytes.startswith(b"\x00\x01\xff"):
        # Check generalized pattern \x00\x01 [\xff]+ \x00 ASN1 HASH
        idx = 2
        while idx < len(decrypted_bytes) and decrypted_bytes[idx] == 0xFF:
            idx += 1
        if idx < len(decrypted_bytes) and decrypted_bytes[idx] == 0x00:
            idx += 1
            expected_payload = ASN1_SHA256 + expected_hash
            if decrypted_bytes[idx : idx + len(expected_payload)] == expected_payload:
                valid_format = True

    if valid_format:
        state["step2_completed"] = True
        state["logs"].append("Stage 2 SUCCESS: RSA Bleichenbacher signature accepted without private key!")
        return {
            "success": True,
            "message": "Signature verified by vulnerable PKCS#1 v1.5 verifier! Root cert forged.",
            "flag": STEP2_FLAG,
        }
    raise HTTPException(
        status_code=400,
        detail="Signature verification rejected: malformed PKCS#1 v1.5 padding structure.",
    )


# ----------------------------------------------------------------------------
# Stage 3: ECDSA Nonce Reuse Private Key Recovery
# ----------------------------------------------------------------------------
@app.get("/api/crypto/ecdsa/samples")
async def get_ecdsa_samples():
    """Provides two ECDSA signatures created with the same secret nonce k."""
    return {
        "curve": "secp256k1",
        "order_n": hex(ECDSA_N),
        "r": hex(ECDSA_R),
        "sample1": {
            "message": ECDSA_MSG1,
            "hash_z1": hex(_z1),
            "s1": hex(ECDSA_S1),
        },
        "sample2": {
            "message": ECDSA_MSG2,
            "hash_z2": hex(_z2),
            "s2": hex(ECDSA_S2),
        },
        "hint": "k = (z1 - z2) * (s1 - s2)^-1 mod n; d = r^-1 * (s1 * k - z1) mod n.",
    }


@app.post("/api/crypto/ecdsa/submit-key")
async def submit_ecdsa_key(req: ECDSAKeySubmitRequest):
    """Validates carved private key d."""
    try:
        val = req.private_key.strip()
        sub_d = int(val, 16) if val.startswith("0x") or any(c in val.lower() for c in "abcdef") else int(val, 10)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid key format")

    if sub_d % ECDSA_N == ECDSA_SECRET_D % ECDSA_N:
        state["step3_completed"] = True
        state["logs"].append("Stage 3 SUCCESS: ECDSA private key recovered via reused nonce!")
        return {
            "success": True,
            "message": "Private key d successfully recovered! Full elliptic curve compromise.",
            "recovered_key": hex(sub_d),
            "flag": STEP3_FLAG,
        }
    raise HTTPException(status_code=400, detail="Invalid private key submitted.")


# ----------------------------------------------------------------------------
# Stage 4: Post-Quantum Cryptography (PQC) Hybrid KEM Defense
# ----------------------------------------------------------------------------
@app.post("/api/crypto/pqc/simulate-quantum-attack")
@app.post("/api/crypto/pqc/quantum-break")
async def simulate_quantum_attack():
    """Simulates Shor's quantum algorithm cracking classical ECDH / RSA."""
    state["quantum_attack_simulated"] = True
    msg = (
        "[SIMULATION] Quantum Shor's Algorithm executed on classical key exchange. "
        "Period-finding on 2048-bit discrete log completed in O(log^3 N) polynomial time. "
        "Classical session key compromised! Traffic decrypted."
    )
    state["logs"].append(msg)
    return {
        "status": "vulnerable",
        "quantum_attack_success": True,
        "vulnerability": "Classical ECDH/RSA lacks quantum resistance against Shor's algorithm.",
        "solution": "Enable Hybrid Post-Quantum Key Encapsulation Mechanism (ML-KEM-768 + X25519).",
    }


@app.post("/api/crypto/pqc/enable-hybrid")
async def enable_hybrid_kem(req: Optional[HybridKEMRequest] = None):
    """Enables NIST FIPS 203 ML-KEM-768 (Kyber) + X25519 Hybrid Key Exchange."""
    state["hybrid_kem_enabled"] = True
    state["step4_completed"] = True
    log_msg = (
        "[DEFENSE] NIST FIPS 203 ML-KEM-768 (Kyber) + X25519 Hybrid KEM enabled. "
        "Shared Secret = KDF(SS_X25519 || SS_Kyber768). Quantum attack defeated!"
    )
    state["logs"].append(log_msg)
    return {
        "success": True,
        "hybrid_pqc_active": True,
        "algorithm": "X25519 + ML-KEM-768 (Kyber)",
        "security_level": "NIST Category 3 (192-bit quantum security against Shor/Grover)",
        "message": "Post-Quantum Cryptography successfully defended the session against quantum interception.",
        "flag": STEP4_FLAG,
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8039)
