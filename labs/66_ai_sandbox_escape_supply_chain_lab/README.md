# Lab 66: AI Agent Sandbox Escape & Supply Chain Poisoning Defense Lab

## Overview
- **Port:** `8066` (`http://127.0.0.1:8066`)
- **Category:** `ai` / `supplychain`
- **CVSS 3.1 Base Score:** 9.8 (Critical) `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H`
- **Vulnerability ID:** `VIBE-2026-6601`

## Architecture & Objectives
This lab simulates advanced offensive exploitation and defensive hardening of autonomous AI agent execution runtimes:
1. **Stage 1 (Supply Chain Integrity)**: Dependency typosquatting & malicious package hash poisoning. Remediated via PEP 665 immutable lockfile, Sigstore Cosign verification, and SLSA Level 3 provenance checking.
2. **Stage 2 (Distributed Cluster RCE)**: Unauthenticated Ray/vLLM RPC endpoints and insecure pickle deserialization. Hardened via mutual TLS (mTLS), SPIFFE/SPIRE workload attestation, and strict JSON-only serialization.
3. **Stage 3 (Runtime Sandbox Breakout)**: Container & seccomp boundary escape through leaked host file descriptors (`/proc/self/fd/..`) and `setns`. Defended by Landlock LSM filesystem sandboxing and eBPF `BPF_PROG_TYPE_LSM` instant `SIGKILL` termination.
4. **Stage 4 (Autonomous G3 Approval Bypass)**: LLM indirect prompt injection coercing agent to bypass human-in-the-loop (HITL) approval gates. Protected by dual-custody HMAC-SHA256 ledger signoff and schema-locked policy enforcement.

## Verification
```bash
pytest labs/66_ai_sandbox_escape_supply_chain_lab/tests/test_ai_sandbox_escape_supply_chain_lab.py -v
python3 labs/66_ai_sandbox_escape_supply_chain_lab/solution/solve.py
```
