#!/usr/bin/env python3
"""
Automated Solver for Lab 66: AI Agent Sandbox Escape & Supply Chain Defense Lab
Port: 8066
"""

import sys
import hmac
import hashlib
import requests

BASE_URL = "http://127.0.0.1:8066"
SHARED_G3_SECRET = b"vibe-2026-enterprise-g3-autonomous-secret-key-8066"

def solve(base_url=BASE_URL):
    flags = {}
    print(f"[*] Solving Lab 66 at {base_url}...")

    # Stage 1
    p1 = {
        "package_name": "agent-core-telemetry",
        "expected_sha256": hashlib.sha256(b"agent-core-telemetry-v2.16.0").hexdigest(),
        "sigstore_verified": True,
        "slsa_provenance_level": 3,
        "allow_unpinned_deps": False
    }
    r1 = requests.post(f"{base_url}/api/stage1/eval", json=p1)
    if r1.status_code == 200:
        flags["stage1"] = r1.json()["flag"]
        print(f"[+] Stage 1: {flags['stage1']}")
    else:
        print(f"[-] Stage 1 failed: {r1.text}")

    # Stage 2
    p2 = {
        "cluster_mtls_enabled": True,
        "spiffe_id": "spiffe://prod.enterprise.cluster/ns/ai-agent/sa/runner",
        "safe_deserialization_only": True,
        "block_arbitrary_pickle": True
    }
    r2 = requests.post(f"{base_url}/api/stage2/eval", json=p2)
    if r2.status_code == 200:
        flags["stage2"] = r2.json()["flag"]
        print(f"[+] Stage 2: {flags['stage2']}")
    else:
        print(f"[-] Stage 2 failed: {r2.text}")

    # Stage 3
    p3 = {
        "landlock_abi_enforced": True,
        "restrict_proc_fd_traversal": True,
        "block_setns_unshare": True,
        "ebpf_lsm_sigkill_on_escape": True
    }
    r3 = requests.post(f"{base_url}/api/stage3/eval", json=p3)
    if r3.status_code == 200:
        flags["stage3"] = r3.json()["flag"]
        print(f"[+] Stage 3: {flags['stage3']}")
    else:
        print(f"[-] Stage 3 failed: {r3.text}")

    # Stage 4
    action_type = "EXECUTE_RESTRICTED_TOOL"
    sig = hmac.new(SHARED_G3_SECRET, action_type.encode(), hashlib.sha256).hexdigest()
    p4 = {
        "action_type": action_type,
        "g3_approval_required": True,
        "multi_signature_hmac": sig,
        "prevent_prompt_injection_bypass": True
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
