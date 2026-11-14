# Lab 56 — eBPFShield: eBPF 런타임 보안 & 커널 루트킷 능동 방어 랩

## 📌 실습 개요
- **실습 번호**: Lab 56
- **포트 바인딩**: `127.0.0.1:8056` (로컬 루프백 격리)
- **난이도**: ★★★★★ (Advanced)
- **주요 테마**: eBPF 커널 시스콜 텔레메트리, Ring Buffer 분석, 프로세스 할로잉 위장 탐지, 악성 eBPF 루트킷(`bpf_override_return`) 색출 및 eBPF LSM 기반 제로 트러스트 능동 방어

## 🚀 실습 구동 방법
```bash
# Docker Compose 기동 (또는 로컬 FastAPI 실행)
docker compose up -d

# 웹 콘솔 브라우저 접속
http://localhost:8056

# 상태 확인
curl http://127.0.0.1:8056/api/status

# vhack CLI를 통한 자동 검증
python3 vhack.py lab test 56
```

## 🎯 4단계 실전 시나리오
1. **Stage 1 (Syscall Telemetry & Tracepoint Hooking)**:
   - `tracepoint/syscalls/sys_enter_execve`에 무오버헤드 BPF 프로브를 연동하여 memfd 익명 실행 및 은닉 프로세스를 실시간 포착
   - 획득 플래그: `FLAG{EBPF_TRACEPOINT_EXECVE_TELEMETRY_ACQUIRED_5601}`
2. **Stage 2 (eBPF Ring Buffer & Process Hollowing Detection)**:
   - `kworker` 커널 스레드로 위장한 불법 바이너리의 실제 `mm->exe_file` inode 및 W^X 메모리 VAD 구역 교차 검증
   - 획득 플래그: `FLAG{RING_BUFFER_PROCESS_HOLLOWING_UNMASKED_5602}`
3. **Stage 3 (Malicious eBPF Rootkit Audit & Purge)**:
   - `__x64_sys_getdents64` 디렉터리 시스콜을 후킹하여 백도어를 은닉하는 rogue BPF 프로그램(ID 404)을 색출 및 언링크
   - 획득 플래그: `FLAG{MALICIOUS_EBPF_ROOTKIT_HOOK_PURGED_5603}`
4. **Stage 4 (eBPF LSM Zero-Trust Runtime Defense)**:
   - `bpf_lsm_bprm_check_security` 훅을 통해 비인가 바이너리 실행 시스콜을 커널 레벨에서 즉각 차단(-EPERM / SIGKILL)
   - 획득 플래그: `FLAG{EBPF_LSM_RUNTIME_ZERO_TRUST_ENFORCED_5604}`
