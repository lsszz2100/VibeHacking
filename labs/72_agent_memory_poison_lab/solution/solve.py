#!/usr/bin/env python3
"""
Automated Solver for Lab 72: AI Agent Long-Term Context Memory & Knowledge Graph Poisoning Defense Lab
Port: 8072
"""

import sys
import hmac
import hashlib
import requests

BASE_URL = "http://127.0.0.1:8072"
MEMORY_SHARED_SECRET = b"vibe-2026-enterprise-agent-memory-defense-secret-8072"

def solve(base_url=BASE_URL):
    flags = {}
    print(f"[*] Solving Lab 72 at {base_url}...")

    # Stage 1: Episodic Memory Sanitization & Quarantine Partitioning
    p1 = {
        "sanitization_policy": "strip_prompt_delimiters_and_quarantine",
        "untrusted_tagging_active": True,
        "quarantine_partition_enabled": True,
        "blocked_directive_patterns": ["ROLE: SYSTEM", "EXEC_CMD:", "BYPASS_GUARD"]
    }
    r1 = requests.post(f"{base_url}/api/stage1/eval", json=p1)
    if r1.status_code == 200:
        flags["stage1"] = r1.json()["flag"]
        print(f"[+] Stage 1: {flags['stage1']}")
    else:
        print(f"[-] Stage 1 failed: {r1.text}")

    # Stage 2: Cryptographic Session Provenance & HMAC Attestation
    session_id = "session_frontier_agent_2026"
    context_hash = hashlib.sha256(b"agent_immutable_task_directive_verified").hexdigest()
    prov_hmac = hmac.new(
        MEMORY_SHARED_SECRET,
        f"{session_id}:{context_hash}".encode(),
        hashlib.sha256
    ).hexdigest()
    p2 = {
        "memory_node_id": "mem_node_session_attested_01",
        "session_id": session_id,
        "context_hash": context_hash,
        "attestation_sig": "sig_agent_mem_v222_verified_ok",
        "provenance_hmac": prov_hmac
    }
    r2 = requests.post(f"{base_url}/api/stage2/eval", json=p2)
    if r2.status_code == 200:
        flags["stage2"] = r2.json()["flag"]
        print(f"[+] Stage 2: {flags['stage2']}")
    else:
        print(f"[-] Stage 2 failed: {r2.text}")

    # Stage 3: Semantic Embedding Anomaly & Cosine Drift Detection
    p3 = {
        "embedding_model": "vibe-semantic-embed-v222",
        "cosine_drift_threshold": 0.28,
        "adversarial_cluster_filter_active": True,
        "vector_index_isolation_enforced": True
    }
    r3 = requests.post(f"{base_url}/api/stage3/eval", json=p3)
    if r3.status_code == 200:
        flags["stage3"] = r3.json()["flag"]
        print(f"[+] Stage 3: {flags['stage3']}")
    else:
        print(f"[-] Stage 3 failed: {r3.text}")

    # Stage 4: Knowledge Graph (GraphRAG) Permission Invariant & Topological Shield
    admin_hmac = hmac.new(
        MEMORY_SHARED_SECRET,
        b"graphrag_schema_v222:invariant_edges_secured",
        hashlib.sha256
    ).hexdigest()
    p4 = {
        "graph_schema_validation": "strict_topological_invariant",
        "unauthorized_edge_pruning": True,
        "admin_relationship_hmac": admin_hmac,
        "sleeper_trigger_neutralized": True
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
