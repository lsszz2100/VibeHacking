# Lab 51: eBPFRuntimeGuard — 클라우드 네이티브 eBPF 런타임 보안 실전 랩

## 개요
Cilium Tetragon 및 Falco 기반의 클라우드 네이티브 eBPF 커널 옵저버빌리티와 실시간 런타임 보안 방어 실전 실습 환경입니다. 커널 시스템콜 감시, eBPF LSM 기반 네임스페이스 탈출 차단, TracingPolicy CRD 적용, eBPF Shadow Rootkit 탐지 기법을 학습합니다.

## 실습 단계
1. **커널 시스템콜 추적 & 비인가 실행 탐지**: `kprobe:sys_execve` 및 `tracepoint:sched_process_exec` 텔레메트리 필터를 통한 컨테이너 내부 리버스 셸 침투 감시
2. **eBPF LSM 기반 네임스페이스 탈출 차단**: `bpf_lsm_file_open` 커널 훅을 통한 `/etc/shadow` 임의 유출 및 특권 컨테이너 탈출 실시간 방어 (`-EPERM` 커널 반환)
3. **Cilium Tetragon TracingPolicy 방어**: Kubernetes CRD 기반 TracingPolicy 매니페스트를 적용하여 권한 상승(`commit_creds`) 시도 프로세스 실시간 SIGKILL 종료
4. **eBPF 맵 변조 & Shadow Rootkit 무결성 감사**: `bpftool prog` 및 `bpftool map dump` 메모리 분석을 통한 은닉 BPF 프로그램(`getdents64` 후킹) 적출 및 무력화

## 실행 방법
```bash
# 단독 실행
vhack lab start 51
# 검증 테스트
vhack lab test 51
# 자동 익스플로잇 솔버
vhack solve 51
```
