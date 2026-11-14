# Lab 58: MicroVM & Hypervisor Escape Defense Lab

## 📌 Overview
- **Lab ID**: `Lab 58`
- **Target Port**: `8058` (Bound strictly to `127.0.0.1:8058`)
- **Category**: Cloud Infrastructure & Virtualization Security
- **MITRE ATT&CK**: `T1611` (Escape to Host) / `T1068` (Exploitation for Privilege Escalation)
- **CVSS 3.1 Score**: `8.8` (HIGH) — `CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N`

## 🎯 4-Stage Simulation Pipeline
1. **Stage 1 (VM-Exit Interception & MMIO Emulation Flaw)**: Induce EPT violations and trigger vulnerable hypervisor MMIO emulated device handlers.
2. **Stage 2 (Virtio-Net Shared Memory Ring Buffer OOB Corruption)**: Manipulate vring descriptor chains to cause out-of-bounds heap corruption on the host.
3. **Stage 3 (KVM vCPU Register State Smuggling & Host Address Leak)**: Exploit vCPU context switching flaw to leak MSR_LSTAR and recover host kernel base.
4. **Stage 4 (Seccomp/Landlock MicroVM Confinement & Hypervisor Hardening)**: Enforce strict KVM ioctl seccomp BPF filters, Landlock LSM filesystem sandboxing, and drop root capabilities.

## 🚀 Quick Start
```bash
docker compose up -d --build
# or direct python run
pip install -r requirements.txt
uvicorn app.main:app --port 8058
```
