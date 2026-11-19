#!/usr/bin/env python3
"""
Lab 65: Post-Quantum Hybrid TLS 1.3 & ML-KEM / ML-DSA Migration Lab Solver
Demonstrates 4-stage automated exploit and blue-team remediation pipeline.
"""
import sys
import requests

BASE_URL = "http://127.0.0.1:8065"

def solve():
    print("[*] Starting Lab 65 Solver against", BASE_URL)
    session = requests.Session()

    # Stage 1: Hybrid ML-KEM-768 Key Exchange
    print("[*] Stage 1: Enforcing ML-KEM-768 Hybrid Key Exchange...")
    r1 = session.post(f"{BASE_URL}/api/stage1/eval", json={
        "key_exchange_group": "X25519_MLKEM768",
        "sndl_intercept_sim": True,
        "use_hybrid_kem": True
    })
    res1 = r1.json()
    assert res1.get("status") == "defended", f"Stage 1 failed: {res1}"
    flag1 = res1.get("flag")
    print(f"[+] Stage 1 Flag: {flag1}")

    # Stage 2: Composite ML-DSA-65 Dual Signature
    print("[*] Stage 2: Validating Composite ML-DSA-65 Dual Signature...")
    r2 = session.post(f"{BASE_URL}/api/stage2/eval", json={
        "cert_algorithm": "COMPOSITE_MLDSA65_ECDSA",
        "dual_signature_validation": True,
        "use_mldsa_guard": True
    })
    res2 = r2.json()
    assert res2.get("status") == "defended", f"Stage 2 failed: {res2}"
    flag2 = res2.get("flag")
    print(f"[+] Stage 2 Flag: {flag2}")

    # Stage 3: Strict TLS 1.3 Anti-Downgrade Defense
    print("[*] Stage 3: Enforcing Strict TLS 1.3 & Anti-Downgrade Defense...")
    r3 = session.post(f"{BASE_URL}/api/stage3/eval", json={
        "offered_versions": ["TLSv1.3"],
        "cipher_suites": ["TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"],
        "supported_groups": ["X25519_MLKEM768"],
        "enforce_anti_downgrade": True
    })
    res3 = r3.json()
    assert res3.get("status") == "defended", f"Stage 3 failed: {res3}"
    flag3 = res3.get("flag")
    print(f"[+] Stage 3 Flag: {flag3}")

    # Stage 4: Constant-Time NTT & Masked Memory
    print("[*] Stage 4: Applying Constant-Time NTT & Masked Memory...")
    r4 = session.post(f"{BASE_URL}/api/stage4/eval", json={
        "ntt_algorithm": "constant_time_masked_ntt",
        "side_channel_probe": True,
        "use_masked_memory": True
    })
    res4 = r4.json()
    assert res4.get("status") == "defended", f"Stage 4 failed: {res4}"
    flag4 = res4.get("flag")
    print(f"[+] Stage 4 Flag: {flag4}")

    print("\n🎉 ALL 4 STAGES SOLVED SUCCESSFULLY!")
    print(f"1: {flag1}\n2: {flag2}\n3: {flag3}\n4: {flag4}")

if __name__ == "__main__":
    solve()
