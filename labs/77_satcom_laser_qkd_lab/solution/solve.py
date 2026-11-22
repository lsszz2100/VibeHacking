#!/usr/bin/env python3
"""
Automated Solver for Lab 77: SatComLaserQkdLab (LEO Satellite Laser Optical Communication & Space QKD Defense Lab)
Port: 8077
"""

import hashlib
import hmac
import sys
import requests

BASE_URL = "http://127.0.0.1:8077"
SATCOM_SHARED_SECRET = b"vibe-2026-enterprise-satcom-qkd-secret-8077"


def solve(base_url=BASE_URL):
    flags = {}
    print(f"[*] Solving Lab 77 at {base_url}...")

    # Stage 1: LEO Laser ISL Doppler Shift Compensation & Beam Tracking
    p1 = {
        "satellite_constellation_id": "sat_leo_star_2026_node_primary",
        "laser_beam_divergence_urad": 10.5,
        "doppler_frequency_shift_mhz": 42.8,
        "pointing_accuracy_mas": 12.0
    }
    r1 = requests.post(f"{base_url}/api/stage1/eval", json=p1)
    if r1.status_code == 200:
        flags["stage1"] = r1.json()["flag"]
        print(f"[+] Stage 1: {flags['stage1']}")
    else:
        print(f"[-] Stage 1 failed: {r1.text}")

    # Stage 2: Satellite Ephemeris Tampering Detection & Kalman Drift Guard
    sess_id = "orbit_ephemeris_epoch_2026_77"
    sess_hmac = hmac.new(
        SATCOM_SHARED_SECRET,
        f"orbit_state:{sess_id}".encode(),
        hashlib.sha256
    ).hexdigest()
    p2 = {
        "ephemeris_drift_detector_active": True,
        "semi_major_axis_variance_km": 0.018,
        "eccentricity_error_pct": 0.005,
        "orbit_session_id": sess_id,
        "orbit_session_hmac": sess_hmac
    }
    r2 = requests.post(f"{base_url}/api/stage2/eval", json=p2)
    if r2.status_code == 200:
        flags["stage2"] = r2.json()["flag"]
        print(f"[+] Stage 2: {flags['stage2']}")
    else:
        print(f"[-] Stage 2 failed: {r2.text}")

    # Stage 3: TT&C Uplink Injection Defense & FIPS 204 ML-DSA-87 Signatures
    p3 = {
        "ttc_replay_defense_active": True,
        "telemetry_command_counter": 2048,
        "ttc_mldsa87_signature": "sig_satcom_ttc_mldsa87_uplink_auth_ok",
        "zero_trust_uplink_isolation": True
    }
    r3 = requests.post(f"{base_url}/api/stage3/eval", json=p3)
    if r3.status_code == 200:
        flags["stage3"] = r3.json()["flag"]
        print(f"[+] Stage 3: {flags['stage3']}")
    else:
        print(f"[-] Stage 3 failed: {r3.text}")

    # Stage 4: Space-to-Ground Continuous-Variable QKD Channel State Verification
    kem_hash = hashlib.sha256(b"vibe-satcom-fips203-mlkem1024-shared-key-v227").hexdigest()
    qkd_hmac = hmac.new(
        SATCOM_SHARED_SECRET,
        f"cv_qkd:{kem_hash}".encode(),
        hashlib.sha256
    ).hexdigest()
    p4 = {
        "quantum_optical_ber_pct": 0.018,
        "decoy_state_intensity_ratio": 0.45,
        "fips203_ml_kem_shared_key_hash": kem_hash,
        "space_ground_qkd_audit_hmac": qkd_hmac
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
