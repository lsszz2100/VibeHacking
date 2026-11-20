# Lab 67: Confidential AI Inference & Hardware Enclave Attestation Defense Lab

## Overview
- **Port:** `8067` (`http://127.0.0.1:8067`)
- **Category:** `confidential` / `ai`
- **CVSS 3.1 Base Score:** 9.3 (Critical) `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N`
- **Vulnerability ID:** `VIBE-2026-6701`

## Architecture & Objectives
This lab simulates advanced offensive exploitation and defensive hardening of Confidential AI workloads operating within Trusted Execution Environments (TEEs):
1. **Stage 1 (Hardware TEE Remote Attestation)**: Bypassing forged attestation quotes on untrusted cloud hypervisors. Remediated via AMD SEV-SNP / Intel TDX hardware attestation quote verification and PCR0 measurement validation against VCEK root certificates.
2. **Stage 2 (In-Enclave Model Weight Sealing)**: Host hypervisor memory inspection and unencrypted weight extraction. Hardened via hardware AES-256-XTS enclave memory encryption and runtime plaintext dump barriers.
3. **Stage 3 (Microarchitectural Cache Timing Defense)**: Side-channel model reconstruction via Flush+Reload and Prime+Probe Last-Level Cache (LLC) timing attacks. Remediated through constant-time GEMM operations, cache flush mitigation, and oblivious RAM access shuffling.
4. **Stage 4 (Tamper-Evident Inference Output Signing)**: Prompt-response tampering and model impersonation. Defended through hardware TPM Attestation Identity Key (AIK) dual-custody cryptographic signatures over prompt hashes and model completions.

## Verification
```bash
pytest labs/67_confidential_ai_inference_lab/tests/test_confidential_ai_inference_lab.py -v
python3 labs/67_confidential_ai_inference_lab/solution/solve.py
```
