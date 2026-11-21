# Lab 71: Hardware GPU Acceleration Sidechannel & VRAM Isolation Defense Lab

## Overview
- **Port**: `8071` (`127.0.0.1` Loopback binding)
- **Category**: Hardware / AI Acceleration Security
- **Defense Focus**: VRAM Residue Memory Zeroization, PCIe Bus Timing Sidechannel Obfuscation, Multi-Instance GPU (MIG) Partition Boundary, Cryptographic Firmware Merkle Attestation.

## Stages
1. **Stage 1**: VRAM Residue Memory Zeroization (`/api/stage1/eval`)
2. **Stage 2**: PCIe Bus Activity Timing Sidechannel Obfuscation (`/api/stage2/eval`)
3. **Stage 3**: MIG Hardware Multi-Tenant Partition Isolation (`/api/stage3/eval`)
4. **Stage 4**: Cryptographic GPU Firmware Merkle Attestation (`/api/stage4/eval`)

## Quickstart
```bash
python3 -m uvicorn labs.71_hardware_gpu_sidechannel_lab.app.main:app --host 127.0.0.1 --port 8071
python3 labs/71_hardware_gpu_sidechannel_lab/solution/solve.py
```
