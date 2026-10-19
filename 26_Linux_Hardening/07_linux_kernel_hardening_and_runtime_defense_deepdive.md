> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 리눅스 커널 하드닝 & 런타임 방어 심층 분석: Seccomp-BPF, Landlock LSM, 무결성 측정(IMA/EVM) 및 KSPP 완화 기법

> 🏢 **연계 실습 랩**: [Lab 46: KernelGuard - Linux Kernel Hardening Lab](../labs/46_linux_kernel_hardening_lab)  
> 🎯 **관련 워게임 트랙**: `linuxhard` (리눅스 커널 하드닝 & 런타임 샌드박스 35제)  
> 🛠️ **관련 시뮬레이터**: [Wargame Playground: Kernel Hardening & Sandbox Inspector](../wargame/index.html#playground)

---

## 0. 개요: 현대 리눅스 커널 공격 표면과 계층적 심층 방어

전통적인 리눅스 보안 모델은 DAC(Discretionary Access Control, 파일 소유자/권한 비트)와 루트(root, UID 0) 전능성에 의존해 왔습니다. 그러나 현대의 제로 트러스트(Zero Trust) 및 컨테이너화된 워크로드 환경에서는 애플리케이션의 단일 취약점(RCE, 메모리 손상)이 곧바로 호스트 커널 장악으로 이어지는 것을 방지하기 위해 **커널 레벨의 샌드박싱 및 자기 보호 기법(Kernel Self-Protection)**이 필수적입니다.

```
+---------------------------------------------------------------------------------------------------+
|                        현대 리눅스 엔터프라이즈 계층적 런타임 커널 방어 아키텍처                  |
+---------------------------------------------------------------------------------------------------+

   [사용자 공간 애플리케이션 (User Space)]
   ┌────────────────────────────────────────────────────────────────────────┐
   │  웹 서비스 / API / 마이크로서비스 / 컨테이너 워크로드                  │
   └────────────────────────────────────────────────────────────────────────┘
                       │ 시스템 호출 (syscall: execve, openat, socket...)
                       ▼
   [계층 1: 시스템 호출 인터셉트 & 필터링 (Seccomp-BPF)]
   ┌────────────────────────────────────────────────────────────────────────┐
   │ • cBPF 프로그램으로 아키텍처 검증 (audit_arch == AUDIT_ARCH_X86_64)    │
   │ • 허용되지 않은 시스템콜 즉시 사살 (SECCOMP_RET_KILL_PROCESS)          │
   │ • 공격 표면 80% 이상 원천 축소 (불필요한 ptrace, clone, unshare 차단)  │
   └────────────────────────────────────────────────────────────────────────┘
                       │ 검증 통과 시스템콜 전달
                       ▼
   [계층 2: 비특권 프로세스 접근 제한 (Landlock LSM)]
   ┌────────────────────────────────────────────────────────────────────────┐
   │ • root 권한 없이도 프로세스 스스로 파일시스템/네트워크 권한 격리       │
   │ • 디렉터리 트리 기반 세분화 규칙 (READ_FILE, WRITE_FILE, EXECUTE 제한) │
   │ • 프로세스가 탈취되어도 `/etc`, `/root` 접근 불가                      │
   └────────────────────────────────────────────────────────────────────────┘
                       │ 커널 내부 객체 접근
                       ▼
   [계층 3: 바이너리 실행 파일 무결성 감사 (IMA / EVM)]
   ┌────────────────────────────────────────────────────────────────────────┐
   │ • IMA (Integrity Measurement Architecture): 실행/로드 시 해시 측정     │
   │ • IMA Appraisal: xattr(security.ima) 디지털 서명 검증 실패 시 실행 차단│
   │ • EVM (Extended Verification Module): 메타데이터(inode, uid, mode) 무결│
   └────────────────────────────────────────────────────────────────────────┘
                       │ 커널 메모리 할당 및 실행
                       ▼
   [계층 4: 커널 자체 보호 기법 (KSPP: Kernel Self-Protection Project)]
   ┌────────────────────────────────────────────────────────────────────────┐
   │ • SLAB_FREELIST_HARDENED / init_on_alloc: 힙 메타데이터 난독화 & 0화   │
   │ • Clang kCFI (Forward-Edge Control Flow): 간접 함수 호출 타깃 검증     │
   │ • Shadow Call Stack (Backward-Edge): 함수 반환 주소 별도 메모리 보존   │
   │ • KPTI (Kernel Page Table Isolation): Meltdown 식별 정보 유출 차단    │
   └────────────────────────────────────────────────────────────────────────┘
```

---

## 1. Seccomp-BPF 시스템 호출 필터 아키텍처

Seccomp(Secure Computing Mode)은 프로세스가 호출할 수 있는 시스템 콜(System Call) 집합을 제한하는 커널 기능입니다. Seccomp-BPF(Mode 2)는 클래식 BPF(cBPF) 명령어 세트를 사용하여 시스템 콜 번호와 인자(Argument)를 동적으로 검사합니다.

### 1.1 BPF 필터 작성 및 동작 흐름
Seccomp 필터는 `struct sock_fprog` 구조체에 BPF 바이트코드 배열을 담아 `prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)` 또는 `seccomp(SECCOMP_SET_MODE_FILTER, 0, &prog)` 시스템 콜로 등록합니다.

```c
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <sys/ptrace.h>
#include <sys/prctl.h>
#include <stddef.h>

struct sock_filter filter[] = {
    /* 1. 아키텍처 검증 (x86_64 일치 여부 확인) */
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (offsetof(struct seccomp_data, arch))),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),

    /* 2. 시스템콜 번호 로드 */
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (offsetof(struct seccomp_data, nr))),

    /* 3. 위험한 시스템콜 차단 */
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_ptrace, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_process_vm_writev, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),

    /* 4. 기본 동작: 허용 */
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
};
```

### 1.2 반환 동작(Action Codes)
- `SECCOMP_RET_KILL_PROCESS` (0x80000000): 프로세스 내 모든 스레드를 즉시 종료(가장 안전).
- `SECCOMP_RET_ERRNO` (0x00050000): 지정된 errno(예: `EPERM`)를 반환하며 시스템콜 호출 실패 처리.
- `SECCOMP_RET_LOG` (0x7ffc0000): 시스템콜을 허용하되 감사 로그(`/var/log/audit/audit.log`)에 기록.
- `SECCOMP_RET_ALLOW` (0x7fff0000): 시스템콜 정상 실행.

---

## 2. Landlock LSM: 비특권 사용자 샌드박싱

Linux 5.13부터 도입된 **Landlock**은 비특권 프로세스(Unprivileged Process)가 `CAP_SYS_ADMIN` 권한 없이도 스스로의 파일시스템 및 네트워크 접근 권한을 제한할 수 있는 최신 보안 모듈(LSM)입니다.

### 2.1 Landlock 동작 메커니즘
1. **규칙셋 생성 (`landlock_create_ruleset`)**: 프로세스가 제한하고자 하는 파일시스템 작업 플래그(`LANDLOCK_ACCESS_FS_READ_FILE`, `WRITE_FILE`, `EXECUTE` 등)를 정의.
2. **경로별 권한 추가 (`landlock_add_rule`)**: 특정 디렉터리 파일 디스크립터(FD)에 허용할 액션 비트마스크를 결합하여 규칙 추가.
3. **규칙셋 적용 (`landlock_restrict_self`)**: `prctl(PR_SET_NO_NEW_PRIVS, 1)` 설정 후 프로세스에 영구 적용. 한 번 적용된 제한은 하위 프로세스로 상속되며 부모도 취소 불가.

```c
#include <linux/landlock.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <fcntl.h>

struct landlock_ruleset_attr ruleset_attr = {
    .handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE |
                         LANDLOCK_ACCESS_FS_READ_DIR |
                         LANDLOCK_ACCESS_FS_WRITE_FILE,
};

int ruleset_fd = syscall(__NR_landlock_create_ruleset, &ruleset_attr, sizeof(ruleset_attr), 0);

/* /tmp 디렉터리에만 읽기/쓰기 허용 */
struct landlock_path_beneath_attr path_attr = {
    .allowed_access = LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_WRITE_FILE,
    .parent_fd = open("/tmp", O_PATH | O_DIRECTORY | O_CLOEXEC),
};
syscall(__NR_landlock_add_rule, ruleset_fd, LANDLOCK_RULE_PATH_BENEATH, &path_attr, 0);

/* 샌드박스 잠금 */
prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
syscall(__NR_landlock_restrict_self, ruleset_fd, 0);
```

---

## 3. 무결성 측정 아키텍처 (IMA / EVM)

**IMA(Integrity Measurement Architecture)**는 파일이 실행(`execve`), 메모리 매핑(`mmap`), 모듈 로드(`init_module`)될 때 파일 내용의 암호학적 해시(SHA-256)를 측정하여 TPM(Trusted Platform Module) 또는 감사 로그에 기록하는 리눅스 무결성 하위 시스템입니다.

### 3.1 IMA Appraisal (평가 및 차단)
- **IMA Measurement**: 파일의 해시를 측정하여 `/sys/kernel/security/ima/ascii_runtime_measurements`에 남김.
- **IMA Appraisal**: 파일의 확장 속성(`xattr: security.ima`)에 저장된 디지털 서명(RSA/ECDSA)을 커널 키링의 공개키로 검증. 서명이 누락되거나 위변조된 파일은 실행 시 `EPERM`으로 즉시 차단.
- **EVM(Extended Verification Module)**: 파일 속성(`security.ima`, `security.selinux`, `uid`, `gid`, `mode`)의 HMAC/서명을 검증하여 오프라인 메타데이터 변조 공격 방어.

---

## 4. 커널 자기 보호 프로젝트 (KSPP) 및 메모리 완화 기법

KSPP(Kernel Self-Protection Project)는 커널 익스플로잇의 성공 가능성을 원천적으로 무력화하기 위한 커널 컴파일 및 런타임 하드닝 세트입니다.

| 완화 기법 | 커널 옵션 / 플래그 | 보호 효과 |
|:---|:---|:---|
| **SLAB 난독화** | `CONFIG_SLAB_FREELIST_HARDENED` | SLAB/SLUB 프리리스트 포인터를 포인터 쿠키와 XOR 난독화하여 힙 덮어쓰기 무력화 |
| **메모리 자동 0화** | `init_on_alloc=1`, `init_on_free=1` | 메모리 할당 및 해제 시 0으로 초기화하여 미초기화 정보 유출 및 UAF 데이터 오염 방어 |
| **kCFI (Control Flow)** | `CONFIG_CFI_CLANG` | 함수 포인터를 통한 간접 호출 시 컴파일 타임 생성된 타입 해시를 검증하여 ROP/JOP 차단 |
| **Shadow Call Stack** | `CONFIG_SHADOW_CALL_STACK` | 전용 레지스터(`x18`)로 분리된 스택에 복귀 주소를 저장하여 스택 버퍼 오버플로우 ROP 무력화 |
| **KPTI** | `pti=on` | 커널 페이지 테이블과 사용자 페이지 테이블을 분리하여 Meltdown(CVE-2017-5754) 방어 |

---

<a name="english"></a>

# Deep Dive: Linux Kernel Hardening & Runtime Defense: Seccomp-BPF, Landlock LSM, IMA/EVM & KSPP Mitigations

> 🏢 **Hands-on Lab**: [Lab 46: KernelGuard - Linux Kernel Hardening Lab](../labs/46_linux_kernel_hardening_lab)  
> 🎯 **Wargame Track**: `linuxhard` (Linux Kernel Hardening & Runtime Sandboxing - 35 Challenges)  
> 🛠️ **Simulator**: [Wargame Playground: Kernel Hardening & Sandbox Inspector](../wargame/index.html#playground)

---

## 0. Overview: Modern Linux Kernel Attack Surface and Defense-in-Depth

Traditional Linux security historically relied on DAC and superuser privileges. In modern containerized and zero-trust cloud architectures, comprehensive kernel-level sandboxing and self-protection mechanisms are mandatory to prevent single application compromises from escalating into host kernel takeovers.

```
+---------------------------------------------------------------------------------------------------+
|                   Modern Enterprise Multi-Tier Kernel Runtime Defense Architecture                |
+---------------------------------------------------------------------------------------------------+

   [User Space Workload]
   └─────────────────────────────────────────────────────────────┘
                                  │ System Calls
                                  ▼
   [Tier 1: Syscall Interception (Seccomp-BPF)]
   └─────────────────────────────────────────────────────────────┘
                                  │ Filtered Syscalls
                                  ▼
   [Tier 2: Unprivileged Sandboxing (Landlock LSM)]
   └─────────────────────────────────────────────────────────────┘
                                  │ File/Network Access
                                  ▼
   [Tier 3: Binary Integrity Verification (IMA / EVM)]
   └─────────────────────────────────────────────────────────────┘
                                  │ Kernel Space Memory Operations
                                  ▼
   [Tier 4: Kernel Self-Protection (KSPP Mitigations: CFI/SCS/SLAB)]
   └─────────────────────────────────────────────────────────────┘
```

---

## 1. Seccomp-BPF Syscall Filter Architecture

Seccomp-BPF leverages classic BPF bytecode to inspect syscall numbers and arguments dynamically, minimizing the kernel attack surface by terminating rogue calls before execution.

* **Architecture Pinning**: Verifies `seccomp_data.arch == AUDIT_ARCH_X86_64` to prevent syscall number confusion across architectures.
* **Action Codes**: Returns `SECCOMP_RET_KILL_PROCESS` to terminate all threads immediately on violation, or `SECCOMP_RET_ERRNO` to fail gracefully with an error code like `EPERM`.

---

## 2. Landlock LSM: Unprivileged Process Sandboxing

Introduced in Linux 5.13, **Landlock** is a modern security module that allows unprivileged processes to restrict their own file system and network access without requiring `CAP_SYS_ADMIN`.

1. **Ruleset Setup**: Define handled actions using `landlock_create_ruleset`.
2. **Path Confinement**: Associate specific directory file descriptors with permitted masks using `landlock_add_rule`.
3. **Lockdown**: Lock restrictions into place with `prctl(PR_SET_NO_NEW_PRIVS, 1)` and `landlock_restrict_self`. Once locked, restrictions permanently bind to current and child processes.

---

## 3. Integrity Measurement Architecture (IMA / EVM)

* **IMA Measurement**: Computes SHA-256 hashes of executed files and logs them to `/sys/kernel/security/ima/ascii_runtime_measurements`.
* **IMA Appraisal**: Validates digital signatures stored in extended attribute `security.ima` against trusted kernel keyrings. Executables lacking valid signatures are blocked with `EPERM`.
* **EVM**: Protects inode metadata (`mode`, `uid`, `gid`, `security.*`) against offline disk tampering using HMACs and digital signatures.

---

## 4. Kernel Self-Protection Project (KSPP)

* **`CONFIG_SLAB_FREELIST_HARDENED`**: Encrypts freelist pointers with per-cache random cookies to prevent heap exploitation.
* **`init_on_alloc=1` / `init_on_free=1`**: Wipes memory buffers upon allocation and release to eliminate uninitialized data leaks and UAF payload re-use.
* **Clang kCFI & Shadow Call Stack**: Hardware and software mechanisms that validate forward-edge and backward-edge control-flow integrity, preventing ROP/JOP gadgets.
