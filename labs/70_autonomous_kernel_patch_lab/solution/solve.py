#!/usr/bin/env python3
"""
Automated Solver for Lab 70: Autonomous Kernel eBPF LSM Hotpatching & 0-Day Runtime Defense Lab
Port: 8070
"""

import sys
import hmac
import hashlib
import requests

BASE_URL = "http://127.0.0.1:8070"
KERNEL_SHARED_SECRET = b"vibe-2026-enterprise-autonomous-kernel-lsm-secret-8070"

def solve(base_url=BASE_URL):
    flags = {}
    print(f"[*] Solving Lab 70 at {base_url}...")

    # Stage 1: eBPF LSM security_bprm_check Hook
    p1 = {
        "hook_type": "security_bprm_check",
        "target_syscall": "execve",
        "signature_block_enabled": True,
        "blocked_signatures": ["\\x48\\x31\\xc0\\x50\\x48\\xbb\\x2f\\x62\\x69\\x6e", "uaf_slub_freelist_overwrite"]
    }
    r1 = requests.post(f"{base_url}/api/stage1/eval", json=p1)
    if r1.status_code == 200:
        flags["stage1"] = r1.json()["flag"]
        print(f"[+] Stage 1: {flags['stage1']}")
    else:
        print(f"[-] Stage 1 failed: {r1.text}")

    # Stage 2: BPF_MAP_TYPE_HASH & RingBuffer Quarantine
    p2 = {
        "map_type": "BPF_MAP_TYPE_HASH",
        "max_entries": 65536,
        "ring_buffer_telemetry": True,
        "sub_microsecond_intercept": True
    }
    r2 = requests.post(f"{base_url}/api/stage2/eval", json=p2)
    if r2.status_code == 200:
        flags["stage2"] = r2.json()["flag"]
        print(f"[+] Stage 2: {flags['stage2']}")
    else:
        print(f"[-] Stage 2 failed: {r2.text}")

    # Stage 3: Seccomp-BPF Dynamic Hotpatching
    p3 = {
        "vulnerable_syscall": "io_uring_enter",
        "seccomp_filter_policy": "SECCOMP_RET_ERRNO",
        "dynamic_hotpatch_applied": True,
        "kernel_panic_prevention": True
    }
    r3 = requests.post(f"{base_url}/api/stage3/eval", json=p3)
    if r3.status_code == 200:
        flags["stage3"] = r3.json()["flag"]
        print(f"[+] Stage 3: {flags['stage3']}")
    else:
        print(f"[-] Stage 3 failed: {r3.text}")

    # Stage 4: Cryptographic Merkle Tree Patch Integrity
    patch_sha256 = hashlib.sha256(b"vibe-kernel-lsm-v220-hotpatch-bytecode").hexdigest()
    merkle_root = hashlib.sha256(b"vibe-kernel-merkle-root-v220").hexdigest()
    patch_hmac = hmac.new(
        KERNEL_SHARED_SECRET,
        f"{patch_sha256}:{merkle_root}".encode(),
        hashlib.sha256
    ).hexdigest()
    p4 = {
        "patch_sha256": patch_sha256,
        "merkle_root_hash": merkle_root,
        "ed25519_kernel_sig": "sig_ed25519_kernel_v220_verified_ok",
        "patch_audit_hmac": patch_hmac
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
