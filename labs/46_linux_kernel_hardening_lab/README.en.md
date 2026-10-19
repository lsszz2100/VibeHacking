# Lab 46: KernelGuard — Linux Kernel Hardening & Runtime Defense Lab

Hands-on simulation lab covering modern Linux kernel isolation and self-protection techniques: Seccomp-BPF system call filtering, Landlock unprivileged filesystem sandboxing, IMA/EVM integrity appraisal, and KSPP kernel memory mitigations (kCFI, SLAB freelist hardening, zeroing on alloc/free).

## 🎯 Objectives
1. **Stage 1 (Seccomp-BPF Syscall Filter Triage)**: Validate architecture pinning (`AUDIT_ARCH_X86_64`) and block dangerous syscalls (`ptrace`, `process_vm_writev`) via `SECCOMP_RET_KILL_PROCESS`.
2. **Stage 2 (Landlock LSM Process Sandboxing)**: Restrict unprivileged process file access to dedicated directory subtrees (`LANDLOCK_ACCESS_FS_*`) and lock with `prctl(PR_SET_NO_NEW_PRIVS)`.
3. **Stage 3 (IMA & EVM Integrity Appraisal)**: Analyze `/sys/kernel/security/ima` runtime measurement logs, detect tampered binaries, and enforce digital signature appraisal.
4. **Stage 4 (KSPP & Kernel Memory Mitigations)**: Enforce Clang kCFI forward-edge control flow integrity, SLAB freelist randomization, and automatic memory zeroing.

## 🚀 Quick Start

### Local Execution (Python)
```bash
cd labs/46_linux_kernel_hardening_lab
pip install -r requirements.txt
python3 -m uvicorn app.main:app --host 127.0.0.1 --port 8046
```

### Docker Execution
```bash
docker-compose up -d --build
```
Access `http://127.0.0.1:8046` in your browser.

## 🧪 Run Tests
```bash
pytest -v labs/46_linux_kernel_hardening_lab/tests/
```
