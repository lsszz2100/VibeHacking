# Lab 56 — eBPFShield: eBPF Kernel Security & Runtime Threat Defense Lab

## 📌 Overview
- **Lab ID**: Lab 56
- **Port Binding**: `127.0.0.1:8056` (Isolated local loopback)
- **Difficulty**: ★★★★★ (Advanced)
- **Core Topics**: eBPF In-Kernel Syscall Telemetry, Ring Buffer Event Analysis, Process Hollowing & Masquerading Detection, Malicious eBPF Rootkit Hunting (`bpf_override_return`), and eBPF LSM Zero-Trust Runtime Sandboxing.

## 🚀 Getting Started
```bash
# Launch Docker container
docker compose up -d

# Access Web Console
http://localhost:8056

# Check status
curl http://127.0.0.1:8056/api/status

# Test via vhack CLI
python3 vhack.py lab test 56
```

## 🎯 4 Progressive Scenarios
1. **Stage 1 (Syscall Telemetry & Tracepoint Hooking)**:
   - Attach zero-overhead BPF probe to `tracepoint/syscalls/sys_enter_execve` to intercept in-memory `memfd_create` executions and anomalous C2 beacons.
   - Flag: `FLAG{EBPF_TRACEPOINT_EXECVE_TELEMETRY_ACQUIRED_5601}`
2. **Stage 2 (eBPF Ring Buffer & Process Hollowing Detection)**:
   - Correlate `task_struct->comm` with real executable inode and detect W^X violations in VAD regions.
   - Flag: `FLAG{RING_BUFFER_PROCESS_HOLLOWING_UNMASKED_5602}`
3. **Stage 3 (Malicious eBPF Rootkit Audit & Purge)**:
   - Audit kernel BPF programs to uncover rogue kprobe (ID 404) hooking `__x64_sys_getdents64` and sanitize poisoned BPF maps.
   - Flag: `FLAG{MALICIOUS_EBPF_ROOTKIT_HOOK_PURGED_5603}`
4. **Stage 4 (eBPF LSM Zero-Trust Runtime Defense)**:
   - Enforce proactive Linux Security Module (LSM) policies on `bpf_lsm_bprm_check_security` with immediate `-EPERM`/`SIGKILL` containment.
   - Flag: `FLAG{EBPF_LSM_RUNTIME_ZERO_TRUST_ENFORCED_5604}`
