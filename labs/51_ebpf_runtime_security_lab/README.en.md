# Lab 51: eBPFRuntimeGuard — Cloud Native eBPF Kernel Observability & Runtime Security Lab

## Overview
Practical hands-on lab environment for cloud-native eBPF kernel observability and real-time runtime security defense based on Cilium Tetragon and Falco. Master kernel syscall tracking, eBPF LSM-based namespace escape prevention, TracingPolicy CRD enforcement, and eBPF Shadow Rootkit memory triage.

## Stages
1. **Kernel Syscall Tracing & Unauthorized Execution**: Monitor reverse shell spawns via `kprobe:sys_execve` and `tracepoint:sched_process_exec` telemetry.
2. **eBPF LSM Namespace Escape Containment**: Block host namespace escapes and `/etc/shadow` exfiltration via `bpf_lsm_file_open` kernel hook returning `-EPERM`.
3. **Cilium Tetragon TracingPolicy Enforcement**: Apply Kubernetes CRD TracingPolicy to synchronously SIGKILL privilege escalation (`commit_creds`) attempts.
4. **eBPF Map Tampering & Shadow Rootkit Audit**: Inspect kernel BPF memory using `bpftool prog` and `bpftool map dump` to carve and neutralize hidden rootkits.

## How to Run
```bash
# Start lab
vhack lab start 51
# Verify tests
vhack lab test 51
# Auto solver
vhack solve 51
```
