#!/usr/bin/env python3
"""
Automated Solver for Lab 76: Neuromorphic SNN Hardware Security & Memristor Glitch Defense Lab
Port: 8076
"""

import hashlib
import hmac
import sys
import requests

BASE_URL = "http://127.0.0.1:8076"
NEUROMORPHIC_SHARED_SECRET = b"vibe-2026-enterprise-neuromorphic-snn-secret-8076"


def solve(base_url=BASE_URL):
    flags = {}
    print(f"[*] Solving Lab 76 at {base_url}...")

    # Stage 1: AER Spike Timing Fingerprint Extraction & LIF Threshold Lock
    p1 = {
        "neuromorphic_chip_id": "nchip_loihi_2026_core_node_alpha",
        "spike_inter_arrival_time_ns": 12.5,
        "lif_membrane_threshold_mv": -48.0,
        "aer_bus_bandwidth_gbps": 16.0
    }
    r1 = requests.post(f"{base_url}/api/stage1/eval", json=p1)
    if r1.status_code == 200:
        flags["stage1"] = r1.json()["flag"]
        print(f"[+] Stage 1: {flags['stage1']}")
    else:
        print(f"[-] Stage 1 failed: {r1.text}")

    # Stage 2: Memristor Crossbar Voltage Glitch & Laser Fault Shield
    sess_id = "snn_sess_epoch_2026_01"
    sess_hmac = hmac.new(
        NEUROMORPHIC_SHARED_SECRET,
        f"glitch_defense:{sess_id}".encode(),
        hashlib.sha256
    ).hexdigest()
    p2 = {
        "crossbar_glitch_detector_active": True,
        "memristor_conductance_drift_pct": 0.015,
        "voltage_glitch_threshold_mv": 15.0,
        "snn_session_id": sess_id,
        "snn_session_hmac": sess_hmac
    }
    r2 = requests.post(f"{base_url}/api/stage2/eval", json=p2)
    if r2.status_code == 200:
        flags["stage2"] = r2.json()["flag"]
        print(f"[+] Stage 2: {flags['stage2']}")
    else:
        print(f"[-] Stage 2 failed: {r2.text}")

    # Stage 3: STDP Synaptic Weight Integrity & Hardware RoT Binding
    p3 = {
        "stdp_weight_poisoning_monitor": True,
        "synapse_conductance_variance": 0.008,
        "hardware_rot_binding_active": True,
        "synaptic_circuit_zeroization_latency_ns": 12.0
    }
    r3 = requests.post(f"{base_url}/api/stage3/eval", json=p3)
    if r3.status_code == 200:
        flags["stage3"] = r3.json()["flag"]
        print(f"[+] Stage 3: {flags['stage3']}")
    else:
        print(f"[-] Stage 3 failed: {r3.text}")

    # Stage 4: NIST FIPS 204 ML-DSA-87 Neuromorphic Attestation
    fw_sha = hashlib.sha256(b"vibe-neuromorphic-snn-firmware-v226").hexdigest()
    merkle_root = hashlib.sha256(b"vibe-memristor-crossbar-merkle-root-v226").hexdigest()
    audit_hmac = hmac.new(
        NEUROMORPHIC_SHARED_SECRET,
        f"{fw_sha}:{merkle_root}".encode(),
        hashlib.sha256
    ).hexdigest()
    p4 = {
        "neuromorphic_fw_sha256": fw_sha,
        "memristor_crossbar_merkle_root": merkle_root,
        "ml_dsa_attestation_sig": "sig_neuromorphic_snn_v226_verified_ok",
        "hardware_snn_audit_hmac": audit_hmac
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
