# Lab 60: Quantum Cryptanalysis & Post-Quantum Active Defense Lab

## Overview
- **Lab ID**: `60`
- **Name**: `QuantumCryptanalysisLab` (Quantum Cryptanalysis & Post-Quantum Active Defense Lab)
- **Port**: `8060` (Bound to `127.0.0.1` loopback)
- **Core Domains**: Quantum Cryptanalysis, Shor's Quantum Period Finding, Lattice Basis Reduction (SVP/CVP LLL & BKZ-40), Store Now Decrypt Later (SNDL) Defense, FIPS 203 ML-KEM-768 Masked NTT Polynomial Arithmetic
- **Associated Track**: Wargame Track 72 (`quantumcrypt`)
- **CVSS 3.1 Score**: 8.1 (High, `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N`)

## 4 Progressive Attack & Defense Stages
1. **Stage 1 (Shor's Algorithm Period Finding Defense)**: Factorization attempts on classical RSA-2048 / ECDSA P-256 via Quantum Phase Estimation (QPE) neutralized by hybrid key encapsulation (X25519 + ML-KEM-768).
2. **Stage 2 (Lattice Basis Reduction SVP Attack)**: Ring-LWE shortest vector searches via BKZ-40 basis reduction held secure by FIPS 203 ML-KEM-768 module lattice hardness (k=3, η1=2).
3. **Stage 3 (SNDL Harvest & Decrypt Defense)**: Adversarial Store Now Decrypt Later harvest attacks defeated via ephemeral post-quantum key exchange guaranteeing Perfect Forward Secrecy (PFS) and IND-CCA2 security.
4. **Stage 4 (Quantum Fault Injection & Masked NTT Defense)**: Quantum gate jitter and side-channel timing perturbation on polynomial multiplication mitigated by constant-time NTT masking and rejection sampling.
