#!/usr/bin/env python3
"""
Automated Solver for Lab 78: FedAiPoisonDefenseLab
(Federated Learning Byzantine Model Poisoning & Differential Privacy DP-SGD Defense Lab)
Port: 8078
"""

import hashlib
import hmac
import sys
import requests

BASE_URL = "http://127.0.0.1:8078"
FEDAI_SHARED_SECRET = b"vibe-2026-enterprise-fedai-poison-secret-8078"


def solve(base_url=BASE_URL):
    flags = {}
    print(f"[*] Solving Lab 78 at {base_url}...")

    # Stage 1: Byzantine Client Norm Clipping & Cosine Similarity Alignment
    p1 = {
        "client_node_id": "fed_worker_fl_2026_node_alpha",
        "gradient_l2_norm": 0.45,
        "cosine_similarity_to_global": 0.94,
        "gradient_explosion_clipping_active": True
    }
    r1 = requests.post(f"{base_url}/api/stage1/eval", json=p1)
    if r1.status_code == 200:
        flags["stage1"] = r1.json()["flag"]
        print(f"[+] Stage 1: {flags['stage1']}")
    else:
        print(f"[-] Stage 1 failed: {r1.text}")

    # Stage 2: Multi-Krum & Trimmed-Mean Byzantine Aggregation
    round_id = "fl_epoch_round_2026_78_beta"
    round_hmac = hmac.new(
        FEDAI_SHARED_SECRET,
        f"round_epoch:{round_id}".encode(),
        hashlib.sha256
    ).hexdigest()
    p2 = {
        "aggregation_protocol": "multi_krum",
        "byzantine_participants_f": 3,
        "multi_krum_selected_count": 8,
        "federated_round_id": round_id,
        "round_token_hmac": round_hmac
    }
    r2 = requests.post(f"{base_url}/api/stage2/eval", json=p2)
    if r2.status_code == 200:
        flags["stage2"] = r2.json()["flag"]
        print(f"[+] Stage 2: {flags['stage2']}")
    else:
        print(f"[-] Stage 2 failed: {r2.text}")

    # Stage 3: Differential Privacy DP-SGD Gaussian Noise & Privacy Budget Epsilon
    p3 = {
        "dp_sgd_gaussian_noise_sigma": 1.45,
        "privacy_budget_epsilon": 2.4,
        "delta_bound": 1e-6,
        "membership_inference_defense_active": True
    }
    r3 = requests.post(f"{base_url}/api/stage3/eval", json=p3)
    if r3.status_code == 200:
        flags["stage3"] = r3.json()["flag"]
        print(f"[+] Stage 3: {flags['stage3']}")
    else:
        print(f"[-] Stage 3 failed: {r3.text}")

    # Stage 4: Secure Multi-Party Aggregation & FIPS 204 ML-DSA-87 Attestation
    mpc_hash = hashlib.sha256(b"vibe-fedai-secure-aggregation-secret-sharing-v228").hexdigest()
    mpc_hmac = hmac.new(
        FEDAI_SHARED_SECRET,
        f"mpc_session:{mpc_hash}".encode(),
        hashlib.sha256
    ).hexdigest()
    p4 = {
        "secret_sharing_mask_verified": True,
        "fips204_mldsa87_node_attestation": "sig_fedai_mldsa87_hardware_enclave_attested",
        "secure_mpc_quorum_count": 9,
        "mpc_session_token_hash": mpc_hash,
        "federated_audit_hmac": mpc_hmac
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
