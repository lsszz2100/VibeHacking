# Lab 59: Confidential Computing & TEE Defense Lab

## Overview
- **Lab ID**: `59`
- **Name**: `ConfidentialComputingLab`
- **Port**: `8059` (Bound to `127.0.0.1` loopback)
- **Domain**: Confidential Computing, AMD SEV-SNP, Intel TDX, Hardware Memory Encryption Engine (MEE), Remote Attestation, Reverse Map Table (RMP), vCPU State Save Area (VMSA) Encryption
- **Track**: Wargame Track 71 (`teeconfidential`)
- **CVSS 3.1**: 8.5 (High, `CVSS:3.1/AV:L/AC:H/PR:H/UI:N/S:C/C:H/I:H/A:H`)

## 4 Defense Stages
1. **Stage 1 (Cold Boot & DMA Dump Defense)**: Verifies hardware memory encryption (AES-256-XTS) prevents host root DMA memory snooping.
2. **Stage 2 (Remote Attestation)**: Verifies hardware security processor ECDSA P-384 signature and MRENCLAVE measurement hash against counterfeit image injection.
3. **Stage 3 (Reverse Map Table RMP Defense)**: Reverse Map Table detects malicious hypervisor memory remapping and triggers hardware `#NPF` violation.
4. **Stage 4 (vCPU State Encryption VMSA)**: Protects guest vCPU registers during VM-Exit with hardware VMSA encryption and cache flush barriers.
