#!/usr/bin/env python3
"""
Automated Solver for Lab 67: Confidential AI Inference & Hardware Enclave Attestation Defense Lab
Port: 8067
"""

import sys
import hmac
import hashlib
import requests

BASE_URL = "http://127.0.0.1:8067"
SHARED_TPM_SECRET = b"vibe-2026-enterprise-tpm-aik-hardware-secret-8067"

def solve(base_url=BASE_URL):
    flags = {}
    print(f"[*] Solving Lab 67 at {base_url}...")

    # Stage 1: Hardware Remote Attestation
    p1 = {
        "hardware_provider": "amd-sev-snp",
        "attestation_quote": "41" * 64,  # valid length > 64
        "measurement_pcr0": hashlib.sha256(b"enclave-firmware-v2.17.0").hexdigest(),
        "require_snp_vcek": True
    }
    r1 = requests.post(f"{base_url}/api/stage1/eval", json=p1)
    if r1.status_code == 200:
        flags["stage1"] = r1.json()["flag"]
        print(f"[+] Stage 1: {flags['stage1']}")
    else:
        print(f"[-] Stage 1 failed: {r1.text}")

    # Stage 2: In-Enclave AES-256-XTS Weight Sealing
    p2 = {
        "key_id": "kdf-tee-aes256-xts-v2",
        "encrypted_model_blob": "00" * 32,
        "memory_encryption_xts": True,
        "prevent_plain_weight_dump": True
    }
    r2 = requests.post(f"{base_url}/api/stage2/eval", json=p2)
    if r2.status_code == 200:
        flags["stage2"] = r2.json()["flag"]
        print(f"[+] Stage 2: {flags['stage2']}")
    else:
        print(f"[-] Stage 2 failed: {r2.text}")

    # Stage 3: Cache Timing Side-Channel Defense
    p3 = {
        "constant_time_gemm": True,
        "cache_line_flushing_mitigated": True,
        "oblivious_ram_or_shuffling": True,
        "detect_prime_probe": True
    }
    r3 = requests.post(f"{base_url}/api/stage3/eval", json=p3)
    if r3.status_code == 200:
        flags["stage3"] = r3.json()["flag"]
        print(f"[+] Stage 3: {flags['stage3']}")
    else:
        print(f"[-] Stage 3 failed: {r3.text}")

    # Stage 4: TPM AIK Tamper-Evident Inference Output Signing
    prompt = "Classify confidential transaction log"
    prompt_hash = hashlib.sha256(prompt.encode()).hexdigest()
    output = "Inference Result: SAFE [Confidence 0.999]"
    sig = hmac.new(SHARED_TPM_SECRET, f"{prompt_hash}:{output}".encode(), hashlib.sha256).hexdigest()
    p4 = {
        "prompt_hash": prompt_hash,
        "inference_output": output,
        "tpm_aik_signature": sig,
        "hardware_root_of_trust": True
    }
    r4 = requests.post(f"{base_url}/api/stage4/eval", json=p4)
    if r4.status_code == 200:
        flags["stage4"] = r4.json()["flag"]
        print(f"[+] Stage 4: {flags['stage4']}")
    else:
        print(f"[-] Stage 4 failed: {r4.text}")

    return flags

if __name__ == "__main__":
    solve()
