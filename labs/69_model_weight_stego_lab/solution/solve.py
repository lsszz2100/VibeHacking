#!/usr/bin/env python3
"""
Automated Solver for Lab 69: AI Model Weight Steganography & SafeTensors Supply Chain Defense Lab
Port: 8069
"""

import sys
import hmac
import hashlib
import requests

BASE_URL = "http://127.0.0.1:8069"
WEIGHT_SHARED_SECRET = b"vibe-2026-enterprise-neural-weight-stego-secret-8069"

def solve(base_url=BASE_URL):
    flags = {}
    print(f"[*] Solving Lab 69 at {base_url}...")

    # Stage 1: Legacy PyTorch/Pickle RCE vs SafeTensors Format Verification
    p1 = {
        "model_format": "safetensors",
        "magic_header": "safetensors-v1",
        "reject_pickle_opcodes": True,
        "header_metadata_json": {
            "__metadata__": {
                "format": "pt",
                "producer": "vibe-ai-safe-compiler",
                "version": "2.19.0"
            },
            "weight": {"dtype": "F32", "shape": [768, 768], "data_offsets": [0, 2359296]}
        }
    }
    r1 = requests.post(f"{base_url}/api/stage1/eval", json=p1)
    if r1.status_code == 200:
        flags["stage1"] = r1.json()["flag"]
        print(f"[+] Stage 1: {flags['stage1']}")
    else:
        print(f"[-] Stage 1 failed: {r1.text}")

    # Stage 2: Neural Weight LSB Steganography Extraction & Mantissa Sanitization
    p2 = {
        "layer_name": "transformer.encoder.layer.0.attention.weight",
        "weight_precision": "float32",
        "lsb_bitmask_sanitization": True,
        "quantization_clipping": True
    }
    r2 = requests.post(f"{base_url}/api/stage2/eval", json=p2)
    if r2.status_code == 200:
        flags["stage2"] = r2.json()["flag"]
        print(f"[+] Stage 2: {flags['stage2']}")
    else:
        print(f"[-] Stage 2 failed: {r2.text}")

    # Stage 3: Statistical Chi-Square Goodness-of-Fit & Bit Entropy Anomaly Detection
    p3 = {
        "chi_square_p_value": 0.42,
        "shannon_entropy": 7.65,
        "variance_threshold": 0.015,
        "statistical_anomaly_detected": True
    }
    r3 = requests.post(f"{base_url}/api/stage3/eval", json=p3)
    if r3.status_code == 200:
        flags["stage3"] = r3.json()["flag"]
        print(f"[+] Stage 3: {flags['stage3']}")
    else:
        print(f"[-] Stage 3 failed: {r3.text}")

    # Stage 4: Sigstore Cosign Merkle Tree & Transparent Model Provenance Verification
    model_sha256 = hashlib.sha256(b"vibe-neural-safetensors-v219-model").hexdigest()
    rekor_index = 8069219
    merkle_hmac = hmac.new(
        WEIGHT_SHARED_SECRET,
        f"{model_sha256}:{rekor_index}".encode(),
        hashlib.sha256
    ).hexdigest()
    p4 = {
        "model_sha256": model_sha256,
        "sigstore_rekor_log_index": rekor_index,
        "ed25519_signature": "sig_ed25519_cosign_v219_verified_pass",
        "merkle_root_audit_hmac": merkle_hmac
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
