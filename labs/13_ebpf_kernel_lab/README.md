# Lab 13: eBPF 커널 침투 및 런타임 보안 실습 랩 (BPFGuard)

## 1. 랩 개요 (Overview)

eBPF(extended Berkeley Packet Filter)는 리눅스 커널 소스코드를 변경하거나 별도 커널 모듈(LKM)을 적재하지 않고도 커널 공간에서 안전하게 샌드박싱된 바이트코드를 실행할 수 있게 해주는 혁신적인 기술입니다. 현대 클라우드 네이티브 환경의 네트워킹(Cilium), 관측성(Pixie), 보안 런타임(Falco, Tetragon)의 기반 기술로 채택되고 있습니다.

하지만 공격자들 역시 eBPF의 강력한 커널 계측 기능을 악용하여 kprobe 후킹을 통한 크리덴셜 탈취, `bpf_probe_write_user` 헬퍼를 통한 유저 메모리 변조 및 루트 권한 상승, XDP를 통한 스텔스 C2 은닉 데이터 유출 등 **차세대 커널 수준 악성코드(eBPF Rootkit)**를 개발하고 있습니다.

**BPFGuard 랩**은 클라우드 엔터프라이즈 환경의 리눅스 호스트 시스템을 모의하여, eBPF를 활용한 4단계 커널 침투 기법을 직접 시뮬레이션하고 BPF 서명 검증 및 LSM 보안 정책을 적용하여 방어 통제를 검증할 수 있는 인터랙티브 핸즈온 실습 환경입니다.

- **서비스 포트**: `8013` (웹 대시보드 및 eBPF REST API)
- **컨테이너 이름**: `ebpf_kernel_lab`
- **난이도**: ★★★★
- **연계 교재**: [01장 리눅스 기초 랩](../../01_Linux_Basics/06_linux_ctf_practical_lab.md), [26장 리눅스 하드닝](../../26_Linux_Hardening/README.md), [70장 쿠버네티스 보안](../../70_Kubernetes_Security/06_k8s_ctf_lab.md)
- **관련 워게임 트랙**: `ebpf` (35개 문제)
- **CLI 간편 실행**: `python3 vhack.py lab start 13`

---

## 2. 4단계 eBPF 침투 킬체인 (Kill Chain Stages)

```
[1. User Space Process] ──(sys_enter_execve)──> [2. eBPF Kprobe Hook]
        │                                                │
        │ Credential Leak                                │ bpf_probe_write_user (Stage 2)
        ▼                                                ▼
[Token / Auth Sniffed]                           [Sudoers Buffer Overwrite]
        │                                                │
        │ Root Shell Acquired                            ▼ (Root Escalated)
        ▼ (Stage 3)
[XDP / TC Driver Mode] ──(Covert ICMP Payload)──> [Stealth Exfiltration]
        │
        ▼ (Stage 4)
[Defense: BPF LSM Policy] ──(Block Unsigned BPF)──> [Kernel Hardened ✓]
```

### 1단계: Kprobe Function Hooking & Credential Sniffing (커널 프로브 도청)
- **공격 기법**: `sys_enter_execve` 및 인증 프로세스 시스템 콜 진입점에 kprobe 후킹 바이트코드 적재
- **취약 원인**: 비특권 또는 권한 상승된 공격자가 eBPF 프로그램 적재 권한(`CAP_BPF` / `CAP_SYS_ADMIN`)을 획득하여 커널 메모리 버퍼를 감시하고 실행 명령줄과 민감 API 토큰을 가로챔
- **획득 플래그**: `FLAG{EBPF_KPROBE_SYSCALL_HOOK_INTRUSION_4918}`

### 2단계: User Memory Mutation via `bpf_probe_write_user` (메모리 변조 권한상승)
- **공격 기법**: BPF 헬퍼 함수 `bpf_probe_write_user`를 악용하여 `/etc/sudoers` 파일 읽기 버퍼를 유저스페이스 반환 직전에 가상으로 조작
- **취약 원인**: 커널에서 프로세스 가상 메모리로의 인라인 쓰기 권한이 남용되어, 디스크 파일을 직접 수정하지 않고도 일반 사용자에게 패스워드 없는 루트 권한(`ALL=(ALL) NOPASSWD: ALL`)을 즉시 부여
- **획득 플래그**: `FLAG{BPF_PROBE_WRITE_USER_SUDO_ESCALATE_8321}`

### 3단계: XDP Packet Dropping & Covert ICMP Channel (스텔스 은닉 채널)
- **공격 기법**: 초고속 데이터 경로(XDP) 드라이버 레벨에서 소켓 버퍼 할당 전에 패킷을 가로채고 ICMP 에코 페이로드에 은닉 데이터를 심어 유출
- **취약 원인**: 상위 계층 방화벽(iptables, nftables)과 소켓 모니터링 EDR이 XDP 레벨의 로우 패킷 변조를 감지하지 못함
- **획득 플래그**: `FLAG{XDP_COVERT_ICMP_EXFIL_STEALTH_7104}`

### 4단계: BPF LSM Policy Enforcement & Runtime Protection (커널 보안 정책 방어)
- **공격 기법 / 방어 실증**: 서명되지 않은 임의 eBPF 바이트코드 로드 시도 및 악성 헬퍼 호출
- **방어 통제**: BPF LSM(Linux Security Module) 후크(`bpf_lsm_bpf`)를 활성화하여 SHA-256 디지털 서명이 없는 BPF 프로그램의 적재를 인라인 차단(`-EPERM`)하고 불법 커널 조작 차단 완료
- **획득 플래그**: `FLAG{EBPF_LSM_RUNTIME_VERIFIER_PROTECTED_9952}`

---

## 3. 방어 및 커널 하드닝 가이드 (Defensive Hardening)

본 랩의 웹 콘솔 또는 `/api/ebpf/policies` API를 통해 다음 4대 eBPF 방어 정책을 활성화하고 익스플로잇 방어 효과를 실증할 수 있습니다:

1. **Unprivileged eBPF 비활성화**:
   ```bash
   sysctl kernel.unprivileged_bpf_disabled=1
   ```
2. **eBPF JIT 하드닝 활성화**:
   ```bash
   sysctl net.core.bpf_jit_harden=2
   ```
3. **BPF LSM 무결성 강제 (`bpf_lsm_bpf`)**:
   디지털 서명 없는 ELF BPF 오브젝트의 커널 로드 원천 차단.
4. **런타임 BPF 활동 감사**:
   `bpftool prog list` 및 Falco/Tetragon을 통한 실시간 커널 이벤트 추적.
