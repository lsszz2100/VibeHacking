#!/usr/bin/env python3
"""
Automated Solver for Lab 68: Autonomous Agent Swarm Security & Byzantine Defense Lab
Port: 8068
"""

import sys
import hmac
import hashlib
import requests

BASE_URL = "http://127.0.0.1:8068"
SWARM_SHARED_SECRET = b"vibe-2026-enterprise-agent-swarm-cluster-secret-8068"

def solve(base_url=BASE_URL):
    flags = {}
    print(f"[*] Solving Lab 68 at {base_url}...")

    # Stage 1: Rogue Agent Registration & mTLS Identity Verification
    spiffe_id = "spiffe://vibe.internal/agent/swarm-worker-verified"
    sig1 = hmac.new(SWARM_SHARED_SECRET, spiffe_id.encode(), hashlib.sha256).hexdigest()
    p1 = {
        "agent_spiffe_id": spiffe_id,
        "mtls_client_cert_hash": hashlib.sha256(b"agent-cert-x509-v218").hexdigest(),
        "signature": sig1,
        "enforce_identity_pinning": True
    }
    r1 = requests.post(f"{base_url}/api/stage1/eval", json=p1)
    if r1.status_code == 200:
        flags["stage1"] = r1.json()["flag"]
        print(f"[+] Stage 1: {flags['stage1']}")
    else:
        print(f"[-] Stage 1 failed: {r1.text}")

    # Stage 2: Swarm Consensus Poisoning & Byzantine Fault Mitigation
    p2 = {
        "quorum_size": 4,
        "byzantine_fault_tolerance": "pbft",
        "consensus_round": 1,
        "worker_votes": ["vote_commit_alpha", "vote_commit_beta", "vote_commit_gamma"],
        "mitigate_outlier_weight": True
    }
    r2 = requests.post(f"{base_url}/api/stage2/eval", json=p2)
    if r2.status_code == 200:
        flags["stage2"] = r2.json()["flag"]
        print(f"[+] Stage 2: {flags['stage2']}")
    else:
        print(f"[-] Stage 2 failed: {r2.text}")

    # Stage 3: Shared Swarm Context Window Hijacking & Landlock LSM Isolation
    p3 = {
        "context_window_id": "ctx-swarm-immutable-v218",
        "enforce_landlock_ro_snapshot": True,
        "ephemeral_memory_namespace": True,
        "prevent_cross_agent_injection": True
    }
    r3 = requests.post(f"{base_url}/api/stage3/eval", json=p3)
    if r3.status_code == 200:
        flags["stage3"] = r3.json()["flag"]
        print(f"[+] Stage 3: {flags['stage3']}")
    else:
        print(f"[-] Stage 3 failed: {r3.text}")

    # Stage 4: Worker-to-Worker Cascading Lateral Movement & eBPF Tetragon Kill
    target_agent = "agent-worker-node-07"
    audit_hmac = hmac.new(
        SWARM_SHARED_SECRET,
        f"{target_agent}:tetragon-zero-trust-sigkill".encode(),
        hashlib.sha256
    ).hexdigest()
    p4 = {
        "lateral_target_agent": target_agent,
        "tetragon_tracing_policy": "cilium-tetragon-swarm-ipc-sigkill-v218",
        "sigkill_on_unauthorized_ipc": True,
        "zero_trust_mesh_audit_hmac": audit_hmac
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
