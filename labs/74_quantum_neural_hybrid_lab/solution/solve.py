#!/usr/bin/env python3
"""
Automated Solver for Lab 74: Quantum Neural Hybrid & QPU Memory Isolation Defense Lab
Port: 8074
"""

import sys
import hmac
import hashlib
import requests

BASE_URL = "http://127.0.0.1:8074"
QUANTUM_NN_SHARED_SECRET = b"vibe-2026-enterprise-quantum-neural-hybrid-secret-8074"

def solve(base_url=BASE_URL):
    flags = {}
    print(f"[*] Solving Lab 74 at {base_url}...")

    # Stage 1: Quantum Adversarial Perturbation Filtering & QFI Metric
    p1 = {
        "qnn_ansatz": "parameterized_quantum_circuit_hardware_efficient",
        "adversarial_epsilon": 0.02,
        "qfi_divergence_threshold": 1.85,
        "entanglement_depth": 6
    }
    r1 = requests.post(f"{base_url}/api/stage1/eval", json=p1)
    if r1.status_code == 200:
        flags["stage1"] = r1.json()["flag"]
        print(f"[+] Stage 1: {flags['stage1']}")
    else:
        print(f"[-] Stage 1 failed: {r1.text}")

    # Stage 2: QPU Memory Residual State Zeroization & Pauli Twirling Reset
    zero_proto = "active_reset_pauli_twirling"
    session_id = "qpu_sess_epoch_2026_01"
    zero_hmac = hmac.new(
        QUANTUM_NN_SHARED_SECRET,
        f"{zero_proto}:{session_id}".encode(),
        hashlib.sha256
    ).hexdigest()
    p2 = {
        "zeroization_protocol": zero_proto,
        "pauli_twirling_rounds": 128,
        "residual_state_fidelity": 0.0004,
        "qpu_session_id": session_id,
        "zeroization_hmac": zero_hmac
    }
    r2 = requests.post(f"{base_url}/api/stage2/eval", json=p2)
    if r2.status_code == 200:
        flags["stage2"] = r2.json()["flag"]
        print(f"[+] Stage 2: {flags['stage2']}")
    else:
        print(f"[-] Stage 2 failed: {r2.text}")

    # Stage 3: Hybrid Classical-Quantum PQC Enclave & Parameter Gradient Shield
    p3 = {
        "pqc_kem_scheme": "ml_kem_1024",
        "gradient_noise_snr_db": 28.5,
        "cross_domain_attestation_active": True,
        "parameter_tampering_blocked": True
    }
    r3 = requests.post(f"{base_url}/api/stage3/eval", json=p3)
    if r3.status_code == 200:
        flags["stage3"] = r3.json()["flag"]
        print(f"[+] Stage 3: {flags['stage3']}")
    else:
        print(f"[-] Stage 3 failed: {r3.text}")

    # Stage 4: Cryptographic QPU Firmware Attestation & Merkle Circuit Provenance
    microcode_sha256 = hashlib.sha256(b"vibe-qpu-control-microcode-v224").hexdigest()
    circuit_merkle = hashlib.sha256(b"vibe-qnn-circuit-merkle-root-v224").hexdigest()
    qpu_hmac = hmac.new(
        QUANTUM_NN_SHARED_SECRET,
        f"{microcode_sha256}:{circuit_merkle}".encode(),
        hashlib.sha256
    ).hexdigest()
    p4 = {
        "qpu_microcode_sha256": microcode_sha256,
        "qnn_circuit_merkle_root": circuit_merkle,
        "attestation_sig": "sig_qnn_hybrid_v224_verified_ok",
        "qpu_audit_hmac": qpu_hmac
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
