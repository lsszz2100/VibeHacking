#!/usr/bin/env python3
"""
Automated Solver for Lab 71: Hardware GPU Acceleration Sidechannel & VRAM Isolation Defense Lab
Port: 8071
"""

import sys
import hmac
import hashlib
import requests

BASE_URL = "http://127.0.0.1:8071"
GPU_SHARED_SECRET = b"vibe-2026-enterprise-hardware-gpu-sidechannel-secret-8071"

def solve(base_url=BASE_URL):
    flags = {}
    print(f"[*] Solving Lab 71 at {base_url}...")

    # Stage 1: VRAM Residue Memory Zeroization
    p1 = {
        "zeroization_policy": "cuda_mem_zero_on_free",
        "vram_scrub_enabled": True,
        "leak_detection_active": True,
        "scrub_patterns": ["0x00_fill_pattern", "cuda_memset_context_clear"]
    }
    r1 = requests.post(f"{base_url}/api/stage1/eval", json=p1)
    if r1.status_code == 200:
        flags["stage1"] = r1.json()["flag"]
        print(f"[+] Stage 1: {flags['stage1']}")
    else:
        print(f"[-] Stage 1 failed: {r1.text}")

    # Stage 2: PCIe Bus Activity Timing Sidechannel Defense
    p2 = {
        "defense_mode": "constant_time_padding",
        "noise_injection_level": 4,
        "pcie_telemetry_obfuscated": True,
        "sub_millisecond_jitter": True
    }
    r2 = requests.post(f"{base_url}/api/stage2/eval", json=p2)
    if r2.status_code == 200:
        flags["stage2"] = r2.json()["flag"]
        print(f"[+] Stage 2: {flags['stage2']}")
    else:
        print(f"[-] Stage 2 failed: {r2.text}")

    # Stage 3: Multi-Instance GPU (MIG) Partition Boundary
    p3 = {
        "mig_instance_id": "mig_profile_3g_40gb",
        "cross_partition_dma_blocked": True,
        "shared_l2_cache_quarantine": True,
        "hardware_isolation_enforced": True
    }
    r3 = requests.post(f"{base_url}/api/stage3/eval", json=p3)
    if r3.status_code == 200:
        flags["stage3"] = r3.json()["flag"]
        print(f"[+] Stage 3: {flags['stage3']}")
    else:
        print(f"[-] Stage 3 failed: {r3.text}")

    # Stage 4: Cryptographic GPU Firmware Merkle Attestation
    firmware_sha256 = hashlib.sha256(b"vibe-gpu-firmware-v221-signed-blob").hexdigest()
    merkle_root = hashlib.sha256(b"vibe-gpu-merkle-root-v221").hexdigest()
    audit_hmac = hmac.new(
        GPU_SHARED_SECRET,
        f"{firmware_sha256}:{merkle_root}".encode(),
        hashlib.sha256
    ).hexdigest()
    p4 = {
        "firmware_sha256": firmware_sha256,
        "merkle_root_hash": merkle_root,
        "attestation_sig": "sig_gpu_firmware_v221_verified_ok",
        "firmware_audit_hmac": audit_hmac
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
