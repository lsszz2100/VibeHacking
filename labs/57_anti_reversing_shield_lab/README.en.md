# Lab 57 — AntiReversingShield: Advanced Binary Protection & Anti-Reversing Lab

## 📌 Lab Overview
- **Lab ID**: Lab 57
- **Port Binding**: `127.0.0.1:8057` (Local loopback isolation)
- **Difficulty**: ★★★★★ (Advanced)
- **Core Topics**: Anti-Debugging (PEB BeingDebugged / ptrace / Hardware Breakpoints), Dynamic API Hashing (ROR13/Murmur3), Advanced Binary Packer Analysis & OEP Unpacking, Anti-VM & RDTSC Timing Analysis Neutralization

## 🚀 How to Run
```bash
# Docker Compose launch (or local FastAPI app)
docker compose up -d

# Web console browser access
http://localhost:8057

# Check status
curl http://127.0.0.1:8057/api/status

# Automatic validation via vhack CLI
python3 vhack.py lab test 57
```

## 🎯 4-Stage Hands-on Scenarios
1. **Stage 1 (Dynamic Anti-Debugging & PEB / ptrace Bypass)**:
   - Neutralize `ptrace(PTRACE_TRACEME)`, PEB `BeingDebugged`, and Hardware Breakpoint (DR0~DR7) traps via inline byte patching (`31c0c3` / `9090`) or `LD_PRELOAD` hooks.
   - Flag: `FLAG{ANTI_DEBUGGING_PEB_PTRACE_BYPASSED_5701}`
2. **Stage 2 (API Hashing & Dynamic IAT Resolution)**:
   - Reverse ROR13 hash (`0x91afca54`) to reveal dynamically imported `VirtualAlloc` API and reconstruct stealth Import Address Table.
   - Flag: `FLAG{API_HASHING_ROR13_DYNAMIC_IAT_RESOLVED_5702}`
3. **Stage 3 (Advanced Binary Packing & OEP Unpacking)**:
   - Trace unpacker stub tail jump, identify Original Entry Point (`0x00401580`), rebuild IAT, and dump clean unpacked binary.
   - Flag: `FLAG{CUSTOM_PACKER_OEP_DUMP_AND_UNPACKED_5703}`
4. **Stage 4 (Anti-VM & Timing Analysis Active Defense)**:
   - Circumvent RDTSC single-stepping cycle delay detection, spoof CPUID hypervisor flag, and sanitize SMBIOS virtualization artifacts (`VMware`, `QEMU`, `VirtualBox`).
   - Flag: `FLAG{ANTI_VM_RDTSC_TIMING_DEFENSE_NEUTRALIZED_5704}`
