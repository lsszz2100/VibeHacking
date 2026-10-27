> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 클라우드 네이티브 eBPF 런타임 보안 & 커널 옵저버빌리티 심층 분석: Cilium Tetragon, Falco eBPF LSM, TracingPolicy 및 Shadow Rootkit 무결성 감사

> 🏢 **연계 실습 랩**: [Lab 51: eBPFRuntimeGuard - Cloud Native eBPF Kernel Observability & Runtime Security Lab](../labs/51_ebpf_runtime_security_lab)  
> 🎯 **관련 워게임 트랙**: `ebpfruntime` (eBPF 런타임 보안 & 커널 프로브 분석 35제)  
> 🛠️ **관련 실습 도구**: `bpftool`, `bpftrace`, `Tetragon TracingPolicy`, `eBPF LSM Hooks`

---

## 0. 개요: 클라우드 네이티브 환경에서 eBPF 기반 실시간 커널 런타임 보안의 패러다임 변화

전통적인 호스트 보안 에이전트(Auditd, Syslog, ptrace 기반 디버거)는 고부하 클라우드 네이티브 워크로드에서 치명적인 I/O 병목을 유발하거나, 사용자 공간(User Space)과 커널 공간(Kernel Space) 간의 빈번한 컨텍스트 스위칭(Context Switching) 및 링버퍼 오버플로우로 인해 공격자의 우회(TOCTOU: Time-of-Check to Time-of-Use)에 취약했습니다.

**eBPF (Extended Berkeley Packet Filter)**는 커널 소스 코드를 재컴파일하거나 커널 모듈(LKM)을 로드하지 않고도, Linux 커널 내부의 샌드박스 가상 머신(eBPF VM)에서 안전하고 고성능인 커스텀 바이트코드를 이벤트 기반으로 실행할 수 있게 함으로써 보안 감시와 강제 집행(Enforcement)의 패러다임을 근본적으로 혁신했습니다.

```
+---------------------------------------------------------------------------------------------------+
|                        eBPF 기반 클라우드 네이티브 동기식 런타임 방어 아키텍처                    |
+---------------------------------------------------------------------------------------------------+

   [사용자 공간 애플리케이션 / K8s Pod / 악성 컨테이너]
   ┌────────────────────────────────────────────────────────────────────────┐
   │  공격 시도: 리버스 셸 스폰 (/bin/sh), 네임스페이스 탈출, 특권 상승 (pkexec)   │
   └────────────────────────────────────────────────────────────────────────┘
                       │ 시스템 호출 (syscall: execve, openat, setns, commit_creds)
                       ▼
   [Linux 커널 공간 (Kernel Space) - eBPF 런타임 감시 및 차단 계층]
   ┌────────────────────────────────────────────────────────────────────────┐
   │                                                                        │
   │  1. Kernel Hooks (kprobe / tracepoint / fentry)                        │
   │     • execve 파라미터(comm, filename, argv, namespace ID) 실시간 추출  │
   │                                                                        │
   │  2. eBPF Verifier & BPF Ring Buffer Telemetry                          │
   │     • 바이트코드 메모리 안전성 및 무한루프 배제 정적 검증              │
   │     • 저지연 제로카피(Zero-Copy) 이벤트 스트리밍 (Falco / Tetragon)     │
   │                                                                        │
   │  3. In-Kernel 동기식 강제 차단 (eBPF LSM & Tetragon TracingPolicy)     │
   │     • bpf_lsm_file_open: /etc/shadow 비인가 접근 시 즉시 -EPERM 반환   │
   │     • kprobe:commit_creds: 악성 권한 탈취 프로세스 동기식 SIGKILL 사살 │
   │                                                                        │
   │  4. eBPF 커널 메모리 무결성 감사 (bpftool)                             │
   │     • sys_enter_getdents64 후킹 기반 Shadow BPF Rootkit 탐지 및 언핀  │
   │                                                                        │
   └────────────────────────────────────────────────────────────────────────┘
                       │ 위협 원천 차단 (SIGKILL / -EPERM)
                       ▼
   [결과: 컨테이너 이탈 원천 봉쇄, 호스트 자격증명 보호, 침해 흔적 제로카피 로깅]
```

---

## 1. eBPF 커널 내부 구조 및 후킹 메커니즘 비교

eBPF 프로그램은 커널 내 특정 이벤트가 발생할 때 트리거되는 콜백 함수입니다. 적재 시점에 **eBPF Verifier**가 11개의 64비트 레지스터(R0~R10), 메모리 바운드, 스택 오버플로우(512바이트 제한), 미초기화 메모리 참조 여부를 정밀 분석하여 커널 패닉을 원천 차단합니다.

### 1.1 주요 커널 훅 인터페이스 비교

| 훅 유형 | 부착 위치 | 오버헤드 | 특징 및 보안 활용 |
| :--- | :--- | :--- | :--- |
| **kprobe / kretprobe** | 임의의 커널 함수 진입/반환 | 중간 (Breakpoint 기반) | 동적 커널 함수 후킹, 매개변수 변조 및 실시간 분석 가능 |
| **tracepoint** | 커널 소스에 하드코딩된 정적 추적점 | 낮음 (안정적 ABI) | 시스템콜 추적 (`sys_enter_execve`), 커널 버전 변경에도 안정 |
| **fentry / fexit** | BPF 트램펄린(Trampoline) 직접 점프 | 매우 낮음 (Zero-overhead) | kprobe 대비 최대 4배 빠른 성능, 레지스터 인자 직접 읽기 지원 |
| **eBPF LSM** | Linux Security Modules 훅 지점 | 매우 낮음 | 보안 결정 권한 보유, 정책 위반 시 `-EPERM` 반환하여 즉시 차단 |
| **XDP / TC** | 네트워크 드라이버 수신 / 트래픽 제어 | 극히 낮음 (드라이버 레벨) | 커널 네트워크 스택 도달 전 DDoS 드롭 및 패킷 필터링 |

---

## 2. Falco vs Cilium Tetragon: 비동기 탐지 vs 동기식 인커널 차단

클라우드 네이티브 런타임 보안의 대표적인 두 엔진은 철학적인 차이점이 존재합니다:

1. **Sysdig Falco (비동기 탐지 중심)**:
   - 커널 모듈 또는 eBPF 드라이버를 통해 시스템콜 이벤트를 링버퍼로 캡처하여 사용자 공간의 Falco 룰 엔진으로 전송합니다.
   - 유연한 YAML 규칙(Syscall, proc.name, container.id 매칭)을 지원하지만, 탐지와 알림 사이의 미세한 지연 시간(Milliseconds) 동안 공격자가 페이로드를 실행하고 증거를 삭제할 수 있는 레이스 컨디션이 존재합니다.

2. **Cilium Tetragon (인커널 실시간 동기 차단 중심)**:
   - 이벤트를 사용자 공간으로 보내기 전에 **커널 내부 eBPF 가상머신 안에서 직접 정책을 평가**합니다.
   - TracingPolicy CRD를 통해 특정 시스템콜(`execve`, `sys_setuid`) 또는 민감 커널 함수(`commit_creds`, `do_init_module`) 호출 시, 커널 내부에서 프로세스를 즉시 `SIGKILL`하거나 에러코드를 오버라이드하여 **0나노초 지연으로 공격을 봉쇄**합니다.

```yaml
# Cilium Tetragon TracingPolicy 실전 예시: 권한 상승 실시간 사살
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "block-privilege-escalation"
  namespace: "kube-system"
spec:
  kprobes:
    - call: "commit_creds"
      syscall: false
      args:
        - index: 0
          type: "cred"
      selectors:
        - matchArgs:
            - index: 0
              operator: "Equal"
              values:
                - "0" # root credentials check
          matchNamespaces:
            - operator: "In"
              values: ["default", "production"]
          matchActions:
            - action: Sigkill
```

---

## 3. Offensive eBPF: Shadow Rootkit과 커널 은닉 기법

eBPF의 막강한 관측성은 역으로 공격자에 의해 악용될 수 있습니다. 이를 **Offensive eBPF** 또는 **BPF Rootkit**이라 부릅니다:

1. **디렉터리 엔트리 은닉 (`sys_enter_getdents64`)**:
   - `getdents64` 시스템콜의 반환 시점(`kretprobe` 또는 `fexit`)에 사용자 버퍼의 `linux_dirent64` 연결 리스트를 순회하며, 악성 파일 접두어(`rootkit_`, `backdoor`)를 가진 엔트리의 `d_reclen`을 건너뛰도록 커널 메모리를 조작합니다.
2. **프로세스 은닉**:
   - `/proc` 가상 파일시스템의 PID 디렉터리 열거를 차단하여 `ps`, `top` 등의 도구로부터 악성 프로세스를 완벽히 숨깁니다.
3. **BPFdoor 네트워크 패킷 스니핑**:
   - `SO_ATTACH_BPF` 또는 raw 소켓을 열어 호스트 방화벽(iptables) 이전 계층에서 매직 패킷(Magic Packet)을 감지하고, 방화벽 포트 오픈 없이 리버스 셸을 트리거합니다.

### 3.1 BPF 메모리 무결성 감사 (`bpftool`)

```bash
# 1. 로드된 모든 BPF 프로그램 검사
bpftool prog show

# 2. 특정 악성 의심 BPF 프로그램의 JIT 디스어셈블리 덤프
bpftool prog dump xlated id 9942

# 3. /sys/fs/bpf 에 영구 핀(pinned)된 악성 맵 확인 및 언핀
bpftool map list
bpftool map dump id 4810
rm /sys/fs/bpf/shadow_rootkit_map
```

---

<a name="english"></a>

# Cloud Native eBPF Runtime Security & Kernel Observability Deepdive: Cilium Tetragon, Falco eBPF LSM, TracingPolicy & Shadow Rootkit Integrity Audit

> 🏢 **Hands-on Lab**: [Lab 51: eBPFRuntimeGuard - Cloud Native eBPF Kernel Observability & Runtime Security Lab](../labs/51_ebpf_runtime_security_lab)  
> 🎯 **Wargame Track**: `ebpfruntime` (eBPF Runtime Security & Kernel Probing 35 Challenges)  
> 🛠️ **Tools**: `bpftool`, `bpftrace`, `Tetragon TracingPolicy`, `eBPF LSM Hooks`

---

## 0. Overview: The Paradigm Shift to Kernel-Level Real-Time Observability

In high-throughput cloud-native environments, traditional user-space security agents (such as Auditd, Syslog, or ptrace-based debuggers) incur severe I/O bottlenecks and context-switching overhead. More critically, asynchronous user-space agents suffer from Time-of-Check to Time-of-Use (TOCTOU) race conditions, allowing adversaries to spawn reverse shells, exfiltrate data, and erase footprints before detection occurs.

**Extended Berkeley Packet Filter (eBPF)** revolutionizes runtime defense by enabling verified, sandboxed bytecode to execute directly inside the Linux kernel on an event-driven basis—delivering sub-microsecond telemetry and synchronous in-kernel enforcement without modifying the kernel source or loading unstable kernel modules.

---

## 1. Kernel Hook Architecture & Comparison

| Hook Type | Attachment Point | Overhead | Security Capability |
| :--- | :--- | :--- | :--- |
| **kprobe / kretprobe** | Dynamic kernel function entry/exit | Moderate (Breakpoint) | Dynamic telemetry, syscall interception, parameter inspection |
| **tracepoint** | Static kernel tracepoints | Low (Stable ABI) | Reliable syscall monitoring (`sys_enter_execve`) across kernel updates |
| **fentry / fexit** | BPF Trampolines | Negligible (Direct Jump) | Zero-overhead function tracking, direct register argument access |
| **eBPF LSM** | Linux Security Module hooks | Minimal | In-kernel policy enforcement: return `-EPERM` to prevent unauthorized execution |
| **XDP / TC** | Network driver ingress / Traffic control | Ultra-low (Driver level) | Packet filtering, DDoS mitigation, line-rate L4 packet inspection |

---

## 2. In-Kernel Synchronous Defense: Cilium Tetragon vs Falco

- **Falco (Asynchronous Detection)**: Extracts syscalls via ring buffers to user-space rule engines. Highly flexible, but alerts are post-execution.
- **Tetragon (Synchronous Enforcement)**: Evaluates TracingPolicies directly within the kernel eBPF VM. If a process violates policy (e.g. attempting privilege escalation via `commit_creds`), Tetragon issues an in-kernel `SIGKILL` synchronously before the syscall returns, guaranteeing zero-window mitigation.

---

## 3. Offensive eBPF & Kernel Integrity Triage

Adversaries leverage eBPF to construct evasive Shadow Rootkits:
1. **Directory Cloaking (`sys_enter_getdents64`)**: Modifying `linux_dirent64` buffer records in kernel memory to hide backdoor binaries from `ls` and forensic tools.
2. **Process Masking**: Suppressing PID directory listings under `/proc` to conceal malware from `ps` and monitoring daemons.
3. **BPFdoor Covert C2**: Attaching raw socket packet filters before netfilter/iptables evaluation to listen for magic trigger packets.

Defense requires strict **Lockdown mode**, disabling unprivileged BPF (`kernel.unprivileged_bpf_disabled=1`), and automated `bpftool` memory audits to carve unlinked or shadow BPF maps.
