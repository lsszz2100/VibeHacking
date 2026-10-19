# Lab 46: KernelGuard — 리눅스 커널 하드닝 & 런타임 방어 실습

리눅스 커널 수준의 보안 격리 및 자기 보호 기법을 실전 시뮬레이션하는 인터랙티브 랩입니다. Seccomp-BPF 시스템콜 필터링, Landlock 비특권 파일시스템 샌드박싱, IMA/EVM 무결성 측정 및 서명 검증, KSPP 커널 메모리 완화 기법(kCFI, SLAB 난독화, init_on_alloc)을 다룹니다.

## 🎯 실습 목표
1. **Stage 1 (Seccomp-BPF Syscall Filter Triage)**: 아키텍처 고정(AUDIT_ARCH_X86_64) 검증 및 악성 ptrace/VM 쓰기 시스템콜 원천 차단 (`SECCOMP_RET_KILL_PROCESS`)
2. **Stage 2 (Landlock LSM Process Sandboxing)**: 비특권 프로세스 디렉터리 경로 한정 격리 (`LANDLOCK_ACCESS_FS_*`) 및 `prctl(PR_SET_NO_NEW_PRIVS)` 잠금
3. **Stage 3 (IMA & EVM Integrity Appraisal)**: `/sys/kernel/security/ima` 런타임 측정 로그 분석, 변조된 바이너리 탐지 및 xattr 디지털 서명 검증 강제
4. **Stage 4 (KSPP & Kernel Memory Mitigations)**: Clang kCFI 간접 호출 제어 흐름 보호, SLAB 프리리스트 난독화 및 메모리 자동 0화 하드닝

## 🚀 빠른 시작

### 로컬 실행 (Python)
```bash
cd labs/46_linux_kernel_hardening_lab
pip install -r requirements.txt
python3 -m uvicorn app.main:app --host 127.0.0.1 --port 8046
```

### Docker 실행
```bash
docker-compose up -d --build
```
브라우저에서 `http://127.0.0.1:8046` 접속

## 🧪 테스트 실행
```bash
pytest -v labs/46_linux_kernel_hardening_lab/tests/
```
