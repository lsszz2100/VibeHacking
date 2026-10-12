#!/usr/bin/env python3
"""
Unit and integration tests for Lab 39: CryptoShield — Modern Cryptography & Cryptanalysis Lab
Tests AES-CBC Padding Oracle & Bit-Flipping, RSA Bleichenbacher Signature Forgery,
ECDSA Nonce Reuse Private Key Recovery, and Post-Quantum ML-KEM-768 Hybrid Defense.
"""

import sys
import importlib.util
from pathlib import Path
import hashlib
import pytest
from fastapi.testclient import TestClient

# Dynamic import isolation
APP_PATH = Path(__file__).resolve().parent.parent / "app" / "main.py"
spec = importlib.util.spec_from_file_location("lab39_app", str(APP_PATH))
lab39_module = importlib.util.module_from_spec(spec)
sys.modules["lab39_app"] = lab39_module
spec.loader.exec_module(lab39_module)

app = lab39_module.app
reset_lab = lab39_module.reset_lab
STEP1_FLAG = lab39_module.STEP1_FLAG
STEP2_FLAG = lab39_module.STEP2_FLAG
STEP3_FLAG = lab39_module.STEP3_FLAG
STEP4_FLAG = lab39_module.STEP4_FLAG

RSA_N = lab39_module.RSA_N
RSA_TARGET_MSG = lab39_module.RSA_TARGET_MSG
ASN1_SHA256 = lab39_module.ASN1_SHA256
ECDSA_N = lab39_module.ECDSA_N
ECDSA_SECRET_D = lab39_module.ECDSA_SECRET_D
ECDSA_MSG1 = lab39_module.ECDSA_MSG1
ECDSA_MSG2 = lab39_module.ECDSA_MSG2
ECDSA_R = lab39_module.ECDSA_R
ECDSA_S1 = lab39_module.ECDSA_S1
ECDSA_S2 = lab39_module.ECDSA_S2


@pytest.fixture(autouse=True)
def run_reset():
    """Ensure each test runs with a fresh default baseline."""
    reset_lab()
    yield
    reset_lab()


@pytest.fixture
def client():
    return TestClient(app)


def test_health(client):
    res = client.get("/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "ok"
    assert data["lab"] == "39_modern_cryptography_lab"
    assert data["port"] == 8039
    assert data["step1_completed"] is False
    assert data["step2_completed"] is False
    assert data["step3_completed"] is False
    assert data["step4_completed"] is False


def test_index_html(client):
    res = client.get("/")
    assert res.status_code == 200
    assert "text/html" in res.headers["content-type"]
    assert "CryptoShield" in res.text
    assert "8039" in res.text


def test_reset(client):
    # Simulate step completion
    client.post("/api/crypto/pqc/enable-hybrid")
    status1 = client.get("/api/crypto/status").json()
    assert status1["steps"]["step4_hybrid_kem"] is True

    # Reset
    res = client.post("/api/crypto/reset")
    assert res.status_code == 200
    status2 = client.get("/api/crypto/status").json()
    assert status2["steps"]["step4_hybrid_kem"] is False


# ----------------------------------------------------------------------------
# Stage 1: AES-CBC Tests
# ----------------------------------------------------------------------------
def test_cbc_profile(client):
    res = client.get("/api/crypto/cbc/profile")
    assert res.status_code == 200
    data = res.json()
    assert "iv" in data
    assert "ciphertext" in data
    assert len(bytes.fromhex(data["iv"])) == 16
    assert len(bytes.fromhex(data["ciphertext"])) % 16 == 0


def test_cbc_oracle_valid_and_invalid(client):
    profile = client.get("/api/crypto/cbc/profile").json()
    iv = profile["iv"]
    ct = profile["ciphertext"]

    # Valid padding test
    res_valid = client.post("/api/crypto/cbc/oracle", json={"iv": iv, "ciphertext": ct})
    assert res_valid.status_code == 200
    assert res_valid.json()["valid"] is True

    # Tampered invalid padding test
    corrupted_ct = bytearray(bytes.fromhex(ct))
    corrupted_ct[-1] ^= 0x55  # flip last byte of last block
    res_invalid = client.post(
        "/api/crypto/cbc/oracle",
        json={"iv": iv, "ciphertext": corrupted_ct.hex()},
    )
    assert res_invalid.status_code == 400
    assert res_invalid.json()["valid"] is False


def test_cbc_verify_guest_insufficient(client):
    profile = client.get("/api/crypto/cbc/profile").json()
    res = client.post(
        "/api/crypto/cbc/verify",
        json={"iv": profile["iv"], "ciphertext": profile["ciphertext"]},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["success"] is False
    assert "guest" in data["message"]


def test_cbc_verify_bitflip_exploit(client):
    """
    Plaintext format: b'admin=0;role=user;uid=1092'
    Byte 6 is '0'. Modifying IV[6] flips byte 6 of decrypted Block 0 to '1' (admin=1)
    with zero block corruption!
    """
    profile = client.get("/api/crypto/cbc/profile").json()
    iv_bytes = bytearray(bytes.fromhex(profile["iv"]))
    ct = profile["ciphertext"]

    # Flip '0' to '1' at offset 6 in IV
    iv_bytes[6] ^= ord("0") ^ ord("1")

    res = client.post(
        "/api/crypto/cbc/verify",
        json={"iv": iv_bytes.hex(), "ciphertext": ct},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["success"] is True
    assert data["flag"] == STEP1_FLAG


def test_cbc_malformed_inputs(client):
    # Invalid hex
    res = client.post("/api/crypto/cbc/oracle", json={"iv": "zz", "ciphertext": "aa"})
    assert res.status_code == 400

    # Wrong IV length
    res = client.post("/api/crypto/cbc/oracle", json={"iv": "1234", "ciphertext": "00" * 16})
    assert res.status_code == 400


# ----------------------------------------------------------------------------
# Stage 2: RSA Bleichenbacher Tests
# ----------------------------------------------------------------------------
def test_rsa_pubkey(client):
    res = client.get("/api/crypto/rsa/pubkey")
    assert res.status_code == 200
    data = res.json()
    assert data["exponent_e"] == 3
    assert data["key_size_bits"] == 2048
    assert data["target_message"] == RSA_TARGET_MSG


def test_rsa_signature_rejected_invalid(client):
    res = client.post(
        "/api/crypto/rsa/verify-signature",
        json={"message": RSA_TARGET_MSG, "signature": "12345"},
    )
    assert res.status_code == 400


def test_rsa_wrong_message(client):
    res = client.post(
        "/api/crypto/rsa/verify-signature",
        json={"message": "wrong_msg", "signature": "12345"},
    )
    assert res.status_code == 400


def test_rsa_bleichenbacher_forgery(client):
    """
    Construct integer s such that s^3 mod N starts with
    \x00\x01\xff\x00 || ASN1 || SHA256(msg)
    """
    def integer_cube_root(n):
        low = 1
        high = 1 << ((n.bit_length() + 2) // 3 + 1)
        ans = high
        while low <= high:
            mid = (low + high) // 2
            if mid ** 3 >= n:
                ans = mid
                high = mid - 1
            else:
                low = mid + 1
        return ans

    h = hashlib.sha256(RSA_TARGET_MSG.encode()).digest()
    prefix = b"\x00\x01\xff\x00" + ASN1_SHA256 + h
    key_bytes = 256  # 2048 bits
    rem = key_bytes - len(prefix)

    D = int.from_bytes(prefix + b"\x00" * rem, "big")
    s = integer_cube_root(D)

    res = client.post(
        "/api/crypto/rsa/verify-signature",
        json={"message": RSA_TARGET_MSG, "signature": hex(s)},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["success"] is True
    assert data["flag"] == STEP2_FLAG


# ----------------------------------------------------------------------------
# Stage 3: ECDSA Nonce Reuse Tests
# ----------------------------------------------------------------------------
def test_ecdsa_samples(client):
    res = client.get("/api/crypto/ecdsa/samples")
    assert res.status_code == 200
    data = res.json()
    assert data["curve"] == "secp256k1"
    assert "r" in data
    assert "sample1" in data
    assert "sample2" in data


def test_ecdsa_wrong_key(client):
    res = client.post(
        "/api/crypto/ecdsa/submit-key",
        json={"private_key": "0x1234567890"},
    )
    assert res.status_code == 400


def test_ecdsa_nonce_reuse_crack(client):
    """
    Given (m1, r, s1) and (m2, r, s2) with same k:
    z1 = SHA256(m1) mod n
    z2 = SHA256(m2) mod n
    k = (z1 - z2) * (s1 - s2)^-1 mod n
    d = r^-1 * (s1 * k - z1) mod n
    """
    samples = client.get("/api/crypto/ecdsa/samples").json()
    n = int(samples["order_n"], 16)
    r = int(samples["r"], 16)
    z1 = int(samples["sample1"]["hash_z1"], 16)
    s1 = int(samples["sample1"]["s1"], 16)
    z2 = int(samples["sample2"]["hash_z2"], 16)
    s2 = int(samples["sample2"]["s2"], 16)

    # Recover k
    k = ((z1 - z2) * pow(s1 - s2, -1, n)) % n
    # Recover d
    d = (pow(r, -1, n) * (s1 * k - z1)) % n

    assert d == ECDSA_SECRET_D

    res = client.post(
        "/api/crypto/ecdsa/submit-key",
        json={"private_key": hex(d)},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["success"] is True
    assert data["flag"] == STEP3_FLAG


# ----------------------------------------------------------------------------
# Stage 4: Post-Quantum Kyber Tests
# ----------------------------------------------------------------------------
def test_pqc_simulate_quantum(client):
    res = client.post("/api/crypto/pqc/simulate-quantum-attack")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "vulnerable"
    assert data["quantum_attack_success"] is True


def test_pqc_enable_hybrid_kem(client):
    res = client.post("/api/crypto/pqc/enable-hybrid")
    assert res.status_code == 200
    data = res.json()
    assert data["success"] is True
    assert data["hybrid_pqc_active"] is True
    assert "ML-KEM-768" in data["algorithm"]
    assert data["flag"] == STEP4_FLAG


def test_all_steps_completed_status(client):
    # Complete step 1
    p = client.get("/api/crypto/cbc/profile").json()
    iv = bytearray(bytes.fromhex(p["iv"]))
    iv[6] ^= ord("0") ^ ord("1")
    client.post("/api/crypto/cbc/verify", json={"iv": iv.hex(), "ciphertext": p["ciphertext"]})

    # Complete step 2
    h = hashlib.sha256(RSA_TARGET_MSG.encode()).digest()
    prefix = b"\x00\x01\xff\x00" + ASN1_SHA256 + h
    rem = 256 - len(prefix)
    D = int.from_bytes(prefix + b"\x00" * rem, "big")
    low = 1
    high = 1 << ((D.bit_length() + 2) // 3 + 1)
    s = high
    while low <= high:
        mid = (low + high) // 2
        if mid ** 3 >= D:
            s = mid
            high = mid - 1
        else:
            low = mid + 1
    client.post("/api/crypto/rsa/verify-signature", json={"message": RSA_TARGET_MSG, "signature": hex(s)})

    # Complete step 3
    client.post("/api/crypto/ecdsa/submit-key", json={"private_key": hex(ECDSA_SECRET_D)})

    # Complete step 4
    client.post("/api/crypto/pqc/enable-hybrid")

    # Check status
    res = client.get("/api/crypto/status")
    assert res.status_code == 200
    steps = res.json()["steps"]
    assert steps["step1_cbc_oracle"] is True
    assert steps["step2_rsa_bleichenbacher"] is True
    assert steps["step3_ecdsa_nonce"] is True
    assert steps["step4_hybrid_kem"] is True
