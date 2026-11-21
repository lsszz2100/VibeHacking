#!/usr/bin/env python3
"""
Automated Solver for Lab 73: Silicon Photonics Co-Packaged Optics & QKD Quantum Key Mesh Defense Lab
Port: 8073
"""

import sys
import hmac
import hashlib
import requests

BASE_URL = "http://127.0.0.1:8073"
PHOTONICS_SHARED_SECRET = b"vibe-2026-enterprise-photonics-qkd-defense-secret-8073"

def solve(base_url=BASE_URL):
    flags = {}
    print(f"[*] Solving Lab 73 at {base_url}...")

    # Stage 1: Optical Bus Physical Scrambling & Line Rate Padding
    p1 = {
        "scrambling_policy": "optical_line_rate_pseudo_random_scramble",
        "optical_dummy_padding_active": True,
        "line_rate_jitter_enabled": True,
        "scramble_polynomials": ["poly_prbs31_cpo", "poly_fibonacci_optical"]
    }
    r1 = requests.post(f"{base_url}/api/stage1/eval", json=p1)
    if r1.status_code == 200:
        flags["stage1"] = r1.json()["flag"]
        print(f"[+] Stage 1: {flags['stage1']}")
    else:
        print(f"[-] Stage 1 failed: {r1.text}")

    # Stage 2: Continuous Quantum Key Distribution (QKD) Mesh Rotation & QBER Defense
    qkd_proto = "bb84_decoy_state"
    key_id = "qkd_key_epoch_2026_01"
    audit_hmac = hmac.new(
        PHOTONICS_SHARED_SECRET,
        f"{qkd_proto}:{key_id}".encode(),
        hashlib.sha256
    ).hexdigest()
    p2 = {
        "qkd_protocol": qkd_proto,
        "qber_threshold_pct": 4.2,
        "quantum_channel_active": True,
        "session_key_id": key_id,
        "qkd_audit_hmac": audit_hmac
    }
    r2 = requests.post(f"{base_url}/api/stage2/eval", json=p2)
    if r2.status_code == 200:
        flags["stage2"] = r2.json()["flag"]
        print(f"[+] Stage 2: {flags['stage2']}")
    else:
        print(f"[-] Stage 2 failed: {r2.text}")

    # Stage 3: Optical Waveguide Isolation & WDM Cross-Talk Quarantine
    p3 = {
        "waveguide_isolation_mode": "dielectric_cladding_shield",
        "wdm_channel_spacing_ghz": 200,
        "cross_talk_quarantine_enforced": True,
        "adjacent_wavelength_leak_blocked": True
    }
    r3 = requests.post(f"{base_url}/api/stage3/eval", json=p3)
    if r3.status_code == 200:
        flags["stage3"] = r3.json()["flag"]
        print(f"[+] Stage 3: {flags['stage3']}")
    else:
        print(f"[-] Stage 3 failed: {r3.text}")

    # Stage 4: Cryptographic Optical Transceiver Attestation & Merkle Firmware Defense
    firmware_sha256 = hashlib.sha256(b"vibe-cpo-optical-transceiver-firmware-v223").hexdigest()
    merkle_root = hashlib.sha256(b"vibe-photonics-merkle-root-v223").hexdigest()
    transceiver_hmac = hmac.new(
        PHOTONICS_SHARED_SECRET,
        f"{firmware_sha256}:{merkle_root}".encode(),
        hashlib.sha256
    ).hexdigest()
    p4 = {
        "transceiver_firmware_sha256": firmware_sha256,
        "photonics_merkle_root": merkle_root,
        "attestation_sig": "sig_cpo_transceiver_v223_verified_ok",
        "transceiver_audit_hmac": transceiver_hmac
    }
    r4 = requests.post(f"{base_url}/api/stage4/eval", json=p4)
    if r4.status_code == 200:
        flags["stage4"] = r4.json()["flag"]
        print(f"[+] Stage 4: {flags['stage4']}")
    else:
        print(f"[-] Stage 4 failed: {r4.text}")

    return flags

if __name__ == "__main__":
    url = sys.argv[1] if len(sys.argv) > 1 else BASE_URL
    res = solve(url)
    print(f"\n[+] Total Flags Captured: {len(res)}/4")
