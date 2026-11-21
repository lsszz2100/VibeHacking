#!/usr/bin/env python3
"""
Automated Solver for Lab 75: Photonic IC Physical Unclonable Function (PUF) & Silicon Hardware Security Lab
Port: 8075
"""

import hashlib
import hmac
import sys
import requests

BASE_URL = "http://127.0.0.1:8075"
PHOTONIC_PUF_SHARED_SECRET = b"vibe-2026-enterprise-photonic-ic-puf-secret-8075"

def solve(base_url=BASE_URL):
    flags = {}
    print(f"[*] Solving Lab 75 at {base_url}...")

    # Stage 1: Optical PUF Speckle Phase Fingerprint Extraction & Key Derivation
    p1 = {
        "silicon_die_id": "die_sp_die_2026_chiplet_a01",
        "optical_speckle_phase_rad": 1.95,
        "mrr_resonance_q_factor": 25000.0,
        "speckle_entropy_bits": 256.0
    }
    r1 = requests.post(f"{base_url}/api/stage1/eval", json=p1)
    if r1.status_code == 200:
        flags["stage1"] = r1.json()["flag"]
        print(f"[+] Stage 1: {flags['stage1']}")
    else:
        print(f"[-] Stage 1 failed: {r1.text}")

    # Stage 2: Micro-Ring Resonator CRP Modeling Attack Defense & Phase Scrambling
    sess_id = "puf_sess_epoch_2026_01"
    sess_hmac = hmac.new(
        PHOTONIC_PUF_SHARED_SECRET,
        f"crp_defense:{sess_id}".encode(),
        hashlib.sha256
    ).hexdigest()
    p2 = {
        "crp_modeling_defense_active": True,
        "phase_scrambler_rate_ghz": 12.5,
        "cmaes_prediction_resistance": 0.9999,
        "puf_session_id": sess_id,
        "puf_session_hmac": sess_hmac
    }
    r2 = requests.post(f"{base_url}/api/stage2/eval", json=p2)
    if r2.status_code == 200:
        flags["stage2"] = r2.json()["flag"]
        print(f"[+] Stage 2: {flags['stage2']}")
    else:
        print(f"[-] Stage 2 failed: {r2.text}")

    # Stage 3: Chiplet Tamper Physical Disconnection Optical Erasure & Hardware RoT
    p3 = {
        "anti_tamper_optical_monitor": True,
        "chiplet_disconnection_threshold_db": 4.5,
        "optical_erasure_latency_ns": 15.0,
        "hardware_rot_binding_active": True
    }
    r3 = requests.post(f"{base_url}/api/stage3/eval", json=p3)
    if r3.status_code == 200:
        flags["stage3"] = r3.json()["flag"]
        print(f"[+] Stage 3: {flags['stage3']}")
    else:
        print(f"[-] Stage 3 failed: {r3.text}")

    # Stage 4: NIST FIPS 204 ML-DSA-87 Inter-Chiplet Remote Attestation & Merkle Provenance
    fw_sha = hashlib.sha256(b"vibe-photonic-puf-firmware-v225").hexdigest()
    merkle_root = hashlib.sha256(b"vibe-waveguide-merkle-tree-root-v225").hexdigest()
    audit_hmac = hmac.new(
        PHOTONIC_PUF_SHARED_SECRET,
        f"{fw_sha}:{merkle_root}".encode(),
        hashlib.sha256
    ).hexdigest()
    p4 = {
        "chiplet_firmware_sha256": fw_sha,
        "photonic_waveguide_merkle_root": merkle_root,
        "ml_dsa_attestation_sig": "sig_photonic_puf_v225_verified_ok",
        "hardware_puf_audit_hmac": audit_hmac
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
