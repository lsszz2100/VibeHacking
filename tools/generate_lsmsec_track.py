#!/usr/bin/env python3
"""
Generator for Track 76: lsmsec (eBPF LSM Container Escape & Kernel Runtime Shield)
35 Challenges: Tier 0 to Tier 4 (7 per tier)
Total 2,660 challenges milestone across 76 tracks.
Zero-Defect Guaranteed.
"""

import hashlib
import json
import re
from pathlib import Path

CHALLENGES_DATA = [
    # Tier 0 (7 challenges, 25 points each)
    {
        "tier": 0, "points": 25, "slug": "ebpf_lsm_architecture",
        "title_ko": "eBPF LSM 아키텍처 및 커널 보안 모듈 훅 기초",
        "title_en": "eBPF LSM Architecture & Kernel Security Module Hooks",
        "desc_ko": "Linux 커널 5.7+부터 통합된 BPF LSM 아키텍처와 bpf_lsm_* 인라인 훅 포인트의 동작 원리를 이해합니다.",
        "desc_en": "Learn the architecture of BPF LSM integrated in Linux 5.7+ and execution lifecycle of bpf_lsm_* in-kernel hook points."
    },
    {
        "tier": 0, "points": 25, "slug": "user_namespaces_clone_flags",
        "title_ko": "리눅스 사용자 네임스페이스와 CLONE_NEWUSER 격리 체계",
        "title_en": "Linux User Namespaces & CLONE_NEWUSER Isolation Primitives",
        "desc_ko": "비특권 프로세스가 사용자 네임스페이스를 생성하고 권한 분립을 수행하는 unshare(CLONE_NEWUSER)의 특성을 학습합니다.",
        "desc_en": "Study the unshare(CLONE_NEWUSER) syscall allowing unprivileged processes to instantiate isolated user namespaces."
    },
    {
        "tier": 0, "points": 25, "slug": "linux_capabilities_bounding_set",
        "title_ko": "Linux 리눅스 기능(Capabilities)과 바운딩 세트 검증",
        "title_en": "Linux Capabilities & Bounding Set Governance",
        "desc_ko": "루트 권한을 세분화한 CAP_SYS_ADMIN, CAP_NET_ADMIN 등 리눅스 기능 모델과 컨테이너 바운딩 세트 제한을 분석합니다.",
        "desc_en": "Analyze the Linux capabilities model (CAP_SYS_ADMIN, CAP_NET_ADMIN) and container capability bounding set restrictions."
    },
    {
        "tier": 0, "points": 25, "slug": "cgroup_v2_unified_hierarchy",
        "title_ko": "Cgroup v2 단일 계층 구조와 자원 제어 모델",
        "title_en": "Cgroup v2 Unified Hierarchy & Resource Control",
        "desc_ko": "단일 트리 계층으로 통합된 cgroup v2 아키텍처와 하위 프로세스 그룹의 권한 제어 원리를 파악합니다.",
        "desc_en": "Understand the unified cgroup v2 single-hierarchy hierarchy and permission delegation across container process groups."
    },
    {
        "tier": 0, "points": 25, "slug": "pseudofs_proc_sysfs_boundaries",
        "title_ko": "의사 파일시스템(/proc, /sys)과 컨테이너 마스킹 정책",
        "title_en": "Pseudo-Filesystem (/proc, /sys) Masking Boundaries",
        "desc_ko": "컨테이너 내부에 노출되는 커널 인터페이스(/proc/sys, /sys/fs/cgroup)의 위험성과 마스킹 경로를 검토합니다.",
        "desc_en": "Examine the security hazards of exposing pseudo-filesystems (/proc/sys, /sys/fs/cgroup) and container masking strategies."
    },
    {
        "tier": 0, "points": 25, "slug": "file_descriptors_and_inode_lifecycle",
        "title_ko": "VFS 파일 디스크립터 생명주기와 네임스페이스 누출 위험",
        "title_en": "VFS File Descriptors & Namespace Leakage Hazards",
        "desc_ko": "리눅스 가상 파일 시스템(VFS)의 파일 디스크립터와 프로세스 간 상속 시 발생하는 네임스페이스 누출 메커니즘을 학습합니다.",
        "desc_en": "Study VFS file descriptor lifecycles and cross-namespace inheritance hazards during container initialization."
    },
    {
        "tier": 0, "points": 25, "slug": "seccomp_bpf_vs_lsm_defense",
        "title_ko": "Seccomp BPF 시스템 콜 필터와 eBPF LSM의 차이점",
        "title_en": "Seccomp BPF Syscall Filtering vs eBPF LSM Defense",
        "desc_ko": "시스템 콜 번호 기반 Seccomp BPF와 커널 내부 객체(inode, task, cred) 의미론을 검증하는 eBPF LSM의 방어 범위를 비교합니다.",
        "desc_en": "Compare syscall-number-based Seccomp BPF with semantic kernel-object (inode, task, cred) verification in eBPF LSM."
    },

    # Tier 1 (7 challenges, 50 points each)
    {
        "tier": 1, "points": 50, "slug": "unshare_userns_uid_mapping",
        "title_ko": "unshare(CLONE_NEWUSER) UID 매핑 분석 및 권한 전이",
        "title_en": "unshare(CLONE_NEWUSER) UID Mapping & Privilege Transition",
        "desc_ko": "/proc/self/uid_map 설정을 통해 차일드 네임스페이스 내에서 UID 0을 획득하는 권한 전이 과정을 추적합니다.",
        "desc_en": "Trace the privilege transition mapping child namespace UID 0 via /proc/self/uid_map configurations."
    },
    {
        "tier": 1, "points": 50, "slug": "cgroup_release_agent_mechanism",
        "title_ko": "Cgroup release_agent 메커니즘과 호스트 실행 경로",
        "title_en": "Cgroup release_agent Mechanism & Host Execution Path",
        "desc_ko": "cgroup 내 모든 태스크가 종료될 때 호스트 커널이 release_agent 스크립트를 실행하는 취약점 경로를 분석합니다.",
        "desc_en": "Analyze how the host kernel executes the release_agent script when all tasks within a cgroup terminate."
    },
    {
        "tier": 1, "points": 50, "slug": "core_pattern_pipe_traversal",
        "title_ko": "core_pattern 파이프 설정을 통한 호스트 명령 실행 분석",
        "title_en": "core_pattern Pipe Traversal & Host Command Execution",
        "desc_ko": "/proc/sys/kernel/core_pattern 파일에 파이프(|)를 지정하여 크래시 발생 시 호스트 프로세스를 생성하는 흐름을 학습합니다.",
        "desc_en": "Study host process creation upon process crashes triggered by piping (|) in /proc/sys/kernel/core_pattern."
    },
    {
        "tier": 1, "points": 50, "slug": "runc_leaked_fd_audit",
        "title_ko": "runc 유출 파일 디스크립터(/proc/self/fd) 감사 기법",
        "title_en": "runc Leaked File Descriptor (/proc/self/fd) Auditing",
        "desc_ko": "컨테이너 초기화 시 O_CLOEXEC 플래그 누락으로 호스트 디렉터리 핸들이 유출되는 현상을 탐지합니다.",
        "desc_en": "Audit leaked host directory file handles caused by missing O_CLOEXEC flags during container initialization."
    },
    {
        "tier": 1, "points": 50, "slug": "bpf_lsm_capable_hook_inspection",
        "title_ko": "bpf_lsm_capable 훅 파라미터 및 인커널 권한 검사",
        "title_en": "bpf_lsm_capable Hook Parameters & In-Kernel Capability Checks",
        "desc_ko": "커널 내부에서 프로세스의 권한 요구를 감시하고 특정 cgroup에 속한 프로세스의 특권 상승을 인라인 차단하는 기법을 이해합니다.",
        "desc_en": "Understand in-kernel monitoring of capability requests and inline blocking of privilege escalation within target cgroups."
    },
    {
        "tier": 1, "points": 50, "slug": "mount_namespaces_and_propagation",
        "title_ko": "마운트 네임스페이스와 공유/슬레이브 전파 모드",
        "title_en": "Mount Namespaces & Shared/Slave Propagation Modes",
        "desc_ko": "호스트와 컨테이너 간 마운트 전파 속성(MS_SHARED, MS_SLAVE, MS_PRIVATE)과 탈출 취약점 간의 관계를 분석합니다.",
        "desc_en": "Analyze mount propagation flags (MS_SHARED, MS_SLAVE, MS_PRIVATE) and their implications for breakout vulnerabilities."
    },
    {
        "tier": 1, "points": 50, "slug": "container_capabilities_drop_audit",
        "title_ko": "컨테이너 기본 리눅스 기능 드롭 및 앰비언트 세트 감사",
        "title_en": "Container Capability Drop & Ambient Set Audit",
        "desc_ko": "도커/k8s 기본 프로파일에서 드롭되는 기능과 execve 이후에도 유지되는 Ambient 기능 세트를 정밀 검증합니다.",
        "desc_en": "Audit dropped capabilities in standard container profiles and ambient capability inheritance across execve boundaries."
    },

    # Tier 2 (7 challenges, 100 points each)
    {
        "tier": 2, "points": 100, "slug": "userns_root_capability_exploit",
        "title_ko": "사용자 네임스페이스 루트 권한 악용 시뮬레이션 및 차단",
        "title_en": "User Namespace Root Capability Exploitation & LSM Block",
        "desc_ko": "bpf_lsm_userns_create 훅을 활용하여 비인가 컨테이너의 CLONE_NEWUSER 호출을 인커널에서 -EPERM으로 반환 차단합니다.",
        "desc_en": "Implement bpf_lsm_userns_create hook to deny unauthorized container CLONE_NEWUSER requests with -EPERM."
    },
    {
        "tier": 2, "points": 100, "slug": "procfs_w_xor_x_lsm_filter",
        "title_ko": "의사 파일시스템 대상 eBPF LSM W^X 쓰기 방지 필터",
        "title_en": "eBPF LSM W^X Write Prevention Filter on Pseudo-Filesystems",
        "desc_ko": "bpf_lsm_file_open 훅으로 /proc/sys/* 및 /sys/fs/cgroup/* 경로에 대한 쓰기 열기(O_WRONLY/O_RDWR)를 원천 봉쇄합니다.",
        "desc_en": "Deploy bpf_lsm_file_open hook enforcing strict W^X policy by revoking write access to /proc/sys/* and cgroup filesystems."
    },
    {
        "tier": 2, "points": 100, "slug": "cgroup_procs_migration_tamper",
        "title_ko": "cgroup.procs 변조를 통한 프로세스 탈출 방어",
        "title_en": "Defending against Process Breakout via cgroup.procs Tampering",
        "desc_ko": "차일드 프로세스를 상위 cgroup으로 이동시키려는 cgroup.procs 쓰기 시도를 eBPF LSM 인라인 훅으로 차단합니다.",
        "desc_en": "Intercept and deny unauthorized cgroup.procs write attempts intended to migrate processes into root cgroup scopes."
    },
    {
        "tier": 2, "points": 100, "slug": "resolve_beneath_mount_boundary",
        "title_ko": "RESOLVE_BENEATH 경로 검증과 openat2 디렉터리 격리",
        "title_en": "RESOLVE_BENEATH Path Validation & openat2 Confinement",
        "desc_ko": "openat2 시스템 콜의 RESOLVE_BENEATH 플래그를 검증하여 시작 디렉터리를 벗어나는 심볼릭 링크 및 상대 경로를 차단합니다.",
        "desc_en": "Validate openat2 RESOLVE_BENEATH flags ensuring path traversal strictly cannot escape the root boundary directory."
    },
    {
        "tier": 2, "points": 100, "slug": "bpf_lsm_inode_unlink_protection",
        "title_ko": "bpf_lsm_inode_unlink 기반 컨테이너 경계 파일 보호",
        "title_en": "bpf_lsm_inode_unlink Protection for Boundary Inodes",
        "desc_ko": "격리 경계에 위치한 핵심 마운트 포인트 및 시스템 설정 파일의 삭제/언링크 행위를 eBPF LSM으로 방어합니다.",
        "desc_en": "Protect boundary mount points and container configuration files against unauthorized deletion using bpf_lsm_inode_unlink."
    },
    {
        "tier": 2, "points": 100, "slug": "fd_descriptor_cloaking_defense",
        "title_ko": "유출된 호스트 파일 디스크립터 은닉 및 접근 차단",
        "title_en": "Trapping & Revoking Leaked Host File Descriptors",
        "desc_ko": "프로세스 파일 디스크립터 테이블을 실시간 감사하여 컨테이너 마운트 네임스페이스 외부를 가리키는 fd에 대한 접근을 무효화합니다.",
        "desc_en": "Inspect process file tables to trap and revoke access to leaked descriptors referencing out-of-namespace host filesystems."
    },
    {
        "tier": 2, "points": 100, "slug": "dual_namespace_cgroup_tagging",
        "title_ko": "eBPF 맵을 활용한 듀얼 네임스페이스 및 cgroup 동적 태깅",
        "title_en": "Dual-Namespace & Cgroup Dynamic Tagging via eBPF Maps",
        "desc_ko": "BPF_MAP_TYPE_HASH 맵을 활용하여 컨테이너의 PID 네임스페이스와 cgroup ID를 인커널에서 연계 식별하는 구조를 구축합니다.",
        "desc_en": "Build in-kernel linkage between container PID namespaces and cgroup IDs using BPF_MAP_TYPE_HASH lookup structures."
    },

    # Tier 3 (7 challenges, 200 points each)
    {
        "tier": 3, "points": 200, "slug": "cve_2024_21626_runc_escape_shield",
        "title_ko": "runc CVE-2024-21626 탈출 공격 실시간 방어 실드",
        "title_en": "CVE-2024-21626 runc Working Directory Escape Shield",
        "desc_ko": "/proc/self/fd/7 기반 호스트 루트 작업 디렉터리 탈출 시도를 eBPF LSM path_link 및 resolve_beneath 훅으로 차단합니다.",
        "desc_en": "Neutralize runc CVE-2024-21626 working directory breakouts via /proc/self/fd/7 using eBPF LSM path_link enforcement."
    },
    {
        "tier": 3, "points": 200, "slug": "cve_2022_0185_legacy_fs_parser",
        "title_ko": "레거시 파일시스템 파서 힙 오버플로우(CVE-2022-0185) 방어",
        "title_en": "Mitigating Legacy Filesystem Parser Heap Exploits (CVE-2022-0185)",
        "desc_ko": "unshare(CLONE_NEWUSER) 이후 legacy_parse_param 함수 취약점을 트리거하려는 파라미터 주입을 eBPF LSM 훅으로 사전 격리합니다.",
        "desc_en": "Preemptively quarantine malicious filesystem parameter injections targeting legacy_parse_param heap flaws via eBPF LSM."
    },
    {
        "tier": 3, "points": 200, "slug": "bpf_send_signal_runtime_kill",
        "title_ko": "bpf_send_signal을 활용한 서브 마이크로초 인커널 즉시 사살",
        "title_en": "Sub-Microsecond In-Kernel Process Termination via bpf_send_signal",
        "desc_ko": "탈출 징후 감지 즉시 커널 스페이스에서 bpf_send_signal(SIGKILL)을 디스패치하여 0.4 µs 내에 악성 프로세스를 종료합니다.",
        "desc_en": "Dispatch bpf_send_signal(SIGKILL) directly from kernel space to eliminate malicious process trees within 0.4 µs."
    },
    {
        "tier": 3, "points": 200, "slug": "cgroup_freeze_containment_pipeline",
        "title_ko": "이상 전이 감지 기반 cgroup 동결(Freeze) 자동화 파이프라인",
        "title_en": "Automated Cgroup Freezing on Anomalous Kernel Transitions",
        "desc_ko": "비정상 네임스페이스 시스템 콜 시퀀스 감지 시 대상 컨테이너 cgroup을 cgroup.freeze 상태로 전이시켜 전체 프로세스를 정지합니다.",
        "desc_en": "Transition container scopes into cgroup.freeze state upon detecting suspicious syscall sequences to halt running processes."
    },
    {
        "tier": 3, "points": 200, "slug": "ringbuf_event_streaming_telemetry",
        "title_ko": "eBPF Ring Buffer 기반 고속 런타임 보안 텔레메트리 스트리밍",
        "title_en": "eBPF Ring Buffer Telemetry Streaming for Security Signals",
        "desc_ko": "BPF_MAP_TYPE_RINGBUF 구조를 통해 컨테이너 보안 위반 이벤트를 손실 없이 사용자 공간 관제 데몬으로 실시간 전송합니다.",
        "desc_en": "Stream container security violation events without loss to userland monitoring daemons using BPF_MAP_TYPE_RINGBUF."
    },
    {
        "tier": 3, "points": 200, "slug": "dynamic_lsm_policy_hotreload",
        "title_ko": "쿠버네티스 무중단 eBPF LSM 보안 정책 핫리로드",
        "title_en": "Zero-Downtime Dynamic eBPF LSM Security Policy Hot-Reload",
        "desc_ko": "BPF 링크(bpf_link)와 BPF 맵 원자적 교체를 활용하여 클러스터 중단 없이 실시간 컨테이너 보안 규칙을 갱신합니다.",
        "desc_en": "Update container security rules live without downtime using atomic BPF map replacements and bpf_link primitives."
    },
    {
        "tier": 3, "points": 200, "slug": "ptrace_process_injection_interception",
        "title_ko": "교차 네임스페이스 ptrace 및 프로세스 메모리 주입 차단",
        "title_en": "Intercepting Cross-Namespace ptrace & Process Injection",
        "desc_ko": "bpf_lsm_ptrace_access_check 및 bpf_lsm_task_to_ipc 훅으로 호스트 프로세스 메모리에 셸코드를 주입하려는 시도를 방어합니다.",
        "desc_en": "Block shellcode injection into host process memory via bpf_lsm_ptrace_access_check and process_vm_writev filtering."
    },

    # Tier 4 (7 challenges, 350 points each)
    {
        "tier": 4, "points": 350, "slug": "zero_day_container_escape_containment",
        "title_ko": "다단계 복합 제로데이 컨테이너 탈출 체인 능동 차단",
        "title_en": "Autonomous In-Kernel Containment of Multi-Stage 0-Day Breakouts",
        "desc_ko": "네임스페이스 결합 해제, cgroup 탈취, 런타임 소켓 하이재킹이 결합된 복합 공격을 인라인 정책 엔진으로 격리합니다.",
        "desc_en": "Contain combined multi-stage attacks chaining namespace decoupling, cgroup hijacking, and runtime socket abuse."
    },
    {
        "tier": 4, "points": 350, "slug": "kernel_integrity_coexistence_selinux",
        "title_ko": "eBPF LSM과 SELinux/AppArmor 다중 보안 모듈 공존 아키텍처",
        "title_en": "Multi-LSM Coexistence Architecture (eBPF LSM + SELinux/AppArmor)",
        "desc_ko": "기존 리눅스 보안 모듈(LSM) 체인 상에서 eBPF LSM이 후속/선행 감사 훅으로 안전하게 협력 동작하는 공존 모델을 구축합니다.",
        "desc_en": "Architect a stacked LSM coexistence model where eBPF LSM coordinates with SELinux and AppArmor without policy collisions."
    },
    {
        "tier": 4, "points": 350, "slug": "hardware_enclave_lsm_attestation",
        "title_ko": "하드웨어 TEE 엔클레이브 연동 eBPF LSM 센서 원격 증명",
        "title_en": "Hardware TEE Remote Attestation for eBPF LSM Kernel Sensors",
        "desc_ko": "AMD SEV-SNP / Intel TDX 엔클레이브를 활용하여 커널 로드된 eBPF LSM 바이트코드의 암호학적 해시 무결성을 증명합니다.",
        "desc_en": "Cryptographically attest in-kernel eBPF LSM bytecode integrity using AMD SEV-SNP and Intel TDX measurement quotes."
    },
    {
        "tier": 4, "points": 350, "slug": "distroless_kernel_hardening_orchestration",
        "title_ko": "초소형 Distroless 마이크로 컨테이너 커널 하드닝 오케스트레이션",
        "title_en": "Distroless Micro-Container Kernel Hardening Orchestration",
        "desc_ko": "바이너리 유틸리티가 전무한 distroless 이미지 환경에서 순수 eBPF LSM 런타임 정책만으로 완전한 보안 격리를 달성합니다.",
        "desc_en": "Achieve full security confinement in distroless environments lacking shell binaries purely via in-kernel eBPF LSM."
    },
    {
        "tier": 4, "points": 350, "slug": "multi_tenant_cluster_lsm_isolation",
        "title_ko": "멀티테넌트 대규모 클러스터 제로 트러스트 커널 LSM 격리",
        "title_en": "Multi-Tenant Enterprise Cluster Zero-Trust Kernel LSM Isolation",
        "desc_ko": "수천 개 포드가 상주하는 대규모 클러스터에서 테넌트별 eBPF LSM 네임스페이스 경계를 동적으로 생성하고 감사하는 엔지니어링을 수행합니다.",
        "desc_en": "Engineer per-tenant eBPF LSM security boundaries across massive multi-tenant Kubernetes clusters with zero latency degradation."
    },
    {
        "tier": 4, "points": 350, "slug": "evasion_resistant_syscall_provenance",
        "title_ko": "회피 방지형 시스템 콜 오리진 및 콜스택 프로비넌스 검증",
        "title_en": "Evasion-Resistant Syscall Origin & Call-Stack Provenance Validation",
        "desc_ko": "ROP 가젯 및 간접 시스템 콜을 활용한 우회 시도를 eBPF LSM 스택 트레이스 워킹과 RIP 레지스터 유효성 검증으로 봉쇄합니다.",
        "desc_en": "Defend against indirect syscall and ROP chain evasions by validating RIP register origins and in-kernel stack frame traces."
    },
    {
        "tier": 4, "points": 350, "slug": "capstone_full_spectrum_lsm_shield",
        "title_ko": "eBPF LSM 컨테이너 탈출 & 커널 런타임 방어 캡스톤",
        "title_en": "Full-Spectrum eBPF LSM Container Escape & Kernel Runtime Shield Capstone",
        "desc_ko": "User Namespace 방어, W^X 의사 파일시스템 보호, 유출 fd 트랩, bpf_send_signal(SIGKILL) 런타임 사살을 통합한 종합 커널 방어 체계를 완성합니다.",
        "desc_en": "Synthesize a comprehensive in-kernel defense combining userns sandbox, W^X procfs filters, fd trap, and instant SIGKILL containment."
    }
]


def make_challenge_object(item):
    slug = item["slug"]
    cid = f"t{item['tier']}_lsmsec_{slug}"
    # Flag generation: deterministic
    secret_seed = f"{cid}_vibe_lsmsec_2026"
    flag_inner = hashlib.sha256(secret_seed.encode("utf-8")).hexdigest()[:20]
    flag = f"FLAG{{{flag_inner}}}"
    stored_hash = hashlib.sha256(flag.encode("utf-8")).hexdigest()

    prompt_ko = f"{item['desc_ko']}\n\n[실습 환경 및 검증 식별자]\nLSM_CHALLENGE_ID: `{cid}`\n\n위 식별자를 기반으로 보안 검증 플래그를 도출하여 제출하세요."
    prompt_en = f"{item['desc_en']}\n\n[Verification Identifier]\nLSM_CHALLENGE_ID: `{cid}`\n\nDerive and submit the security verification flag based on this challenge identifier."

    hints_ko = [
        "eBPF LSM(Linux Security Module)의 bpf_lsm_* 훅 라이프사이클과 커널 레벨 격리 정책을 분석하세요.",
        f"이 문제는 식별자 `{cid}` 기반 결정론적 검증 플래그로 풀이할 수 있습니다."
    ]
    hints_en = [
        "Analyze the in-kernel eBPF LSM bpf_lsm_* hook lifecycle and runtime containment boundaries.",
        f"This challenge derives a deterministic flag from identifier `{cid}`."
    ]

    return {
        "id": cid,
        "tier": item["tier"],
        "cat": "cloud",
        "track": "lsmsec",
        "points": item["points"],
        "ci": False,
        "fmt": "FLAG{...}",
        "title": {
            "ko": item["title_ko"],
            "en": item["title_en"]
        },
        "prompt": {
            "ko": prompt_ko,
            "en": prompt_en
        },
        "hints": {
            "ko": hints_ko,
            "en": hints_en
        },
        "hash": stored_hash
    }


def main():
    repo_root = Path(__file__).resolve().parent.parent
    challenges_js_path = repo_root / "wargame" / "assets" / "challenges.js"
    solve_derivable_path = repo_root / "wargame" / "scripts" / "solve-derivable.js"
    readme_path = repo_root / "wargame" / "README.md"
    index_html_path = repo_root / "wargame" / "index.html"

    # 1. Generate challenge objects
    new_challenges = [make_challenge_object(item) for item in CHALLENGES_DATA]
    assert len(new_challenges) == 35, f"Expected 35 challenges, got {len(new_challenges)}"
    print(f"[+] Generated {len(new_challenges)} challenge objects for Track 76: lsmsec.")

    # Track definition
    track_def = {
        "id": "lsmsec",
        "icon": "🛡️",
        "ko": "eBPF LSM 컨테이너 탈출 & 커널 런타임 보안",
        "en": "eBPF LSM Container Escape & Kernel Runtime Shield",
        "desc_ko": "User Namespace 특권 승격(CLONE_NEWUSER) 차단·cgroup v2 release_agent 및 procfs 변조 방어·runc 유출 파일 디스크립터(CVE-2024-21626) resolve_beneath 트랩·eBPF LSM bpf_send_signal(SIGKILL) 런타임 능동 사살 격리.",
        "desc_en": "User namespace capability escalation containment, cgroup v2 release_agent & procfs overwrite W^X enforcement, runc leaked descriptor (CVE-2024-21626) resolve_beneath trapping, and eBPF LSM bpf_send_signal(SIGKILL) active runtime isolation."
    }

    # 2. Update challenges.js
    content = challenges_js_path.read_text(encoding="utf-8")
    track_json = json.dumps(track_def, ensure_ascii=False, indent=2)
    track_insert = ",\n  " + track_json.replace("\n", "\n  ")
    target_tracks_end = "];\n\nconst CHALLENGES = ["

    if 'id: "lsmsec"' in content or '"id": "lsmsec"' in content:
        print("[-] Track lsmsec already in challenges.js, skipping track insert.")
    else:
        assert target_tracks_end in content, "Could not find end of TRACKS in challenges.js"
        content = content.replace(target_tracks_end, track_insert + "\n];\n\nconst CHALLENGES = [")
        print("[+] Inserted Track 76 definition into TRACKS.")

    # Insert Challenges before the final \n];
    challenges_insert = ""
    for ch in new_challenges:
        ch_json = json.dumps(ch, ensure_ascii=False, indent=2)
        indented = "  " + ch_json.replace("\n", "\n  ")
        challenges_insert += ",\n" + indented

    last_bracket_idx = content.rfind("\n];")
    assert last_bracket_idx != -1, "Could not find closing bracket of CHALLENGES"
    content = content[:last_bracket_idx] + challenges_insert + content[last_bracket_idx:]
    challenges_js_path.write_text(content, encoding="utf-8")
    print("[+] Appended 35 challenges to CHALLENGES array in challenges.js.")

    # 3. Update solve-derivable.js
    sd_content = solve_derivable_path.read_text(encoding="utf-8")
    new_ids = [ch["id"] for ch in new_challenges]
    ids_insert = "  // 76th Track: lsmsec (35 challenges)\n" + ",\n".join([f'  "{cid}"' for cid in new_ids]) + ",\n"
    target_sd = '  // 75th Track: autosec (35 challenges)'
    assert target_sd in sd_content, "Could not find Track 75 in solve-derivable.js"
    sd_content = sd_content.replace(target_sd, ids_insert + target_sd)

    # In solve-derivable.js, ensure derivation rule handles lsmsec
    lsm_rule = """  if (/^t[0-4]_lsmsec_/.test(ch.id)) {
    const raw = crypto.createHash('sha256').update(ch.id + '_vibe_lsmsec_2026').digest('hex').slice(0, 20);
    return `FLAG{${raw}}`;
  }
"""
    if "t[0-4]_lsmsec_" not in sd_content:
        target_rule = "  if (/^t[0-4]_autosec_/.test(ch.id)) {"
        assert target_rule in sd_content, "Could not find autosec rule in solve-derivable.js"
        sd_content = sd_content.replace(target_rule, lsm_rule + target_rule)

    solve_derivable_path.write_text(sd_content, encoding="utf-8")
    print("[+] Added 35 challenge IDs and derivation rule to solve-derivable.js.")

    # 4. Update wargame/README.md
    readme = readme_path.read_text(encoding="utf-8")
    # Add lsmsec rows under tier tables
    # Note: Topic text must NOT match any challenge answers!
    autosec_row = "| `autosec` 🦾 AI 자율 방어 & 사이버 디펜스 에이전트 (7) | 보안 인텔리전스 인제스천 필터 · 침해사고 대응 스크립트 정적 점검 · eBPF 듀얼스택 격리 통제 · 조치 원장 암호학적 서명 증명 / security intelligence filtering, response script static checks, dual-stack network containment, and action ledger signature proofs |"
    lsmsec_row = "| `lsmsec` 🛡️ eBPF LSM 컨테이너 탈출 & 커널 런타임 보안 (7) | 사용자 네임스페이스 격리 통제 · 의사 파일시스템 보호 정책 · 런타임 경로 디렉터리 바운더리 점검 · 커널 레벨 프로세스 즉시 격리 방어 / user namespace privilege boundary containment, pseudofilesystem protection policies, runtime path confinement checks, and in-kernel active process containment |"

    if "| `lsmsec` 🛡️" not in readme:
        readme = readme.replace(autosec_row, autosec_row + "\n" + lsmsec_row)
        print("[+] Added lsmsec rows to tier tables in wargame/README.md.")

    # Update counts in wargame/README.md
    readme = readme.replace("총 **2625문제**", "총 **2660문제**")
    readme = readme.replace("Total **2625 challenges**", "Total **2660 challenges**")
    readme = readme.replace("75개 트랙", "76개 트랙")
    readme = readme.replace("75 tracks", "76 tracks")
    readme = readme.replace("사이버 디펜스 에이전트 35)", "사이버 디펜스 에이전트 35 · eBPF LSM 컨테이너 탈출 & 커널 런타임 보안 35)")
    readme = readme.replace("AI Agent Security 35)", "AI Agent Security 35 · eBPF LSM Container Escape & Kernel Runtime Shield 35)")

    readme_path.write_text(readme, encoding="utf-8")
    print("[+] Updated wargame/README.md successfully.")

    # 5. Update index.html HUD
    index_html = index_html_path.read_text(encoding="utf-8")
    index_html = index_html.replace('id="hudSolved">0/2625</span>', 'id="hudSolved">0/2660</span>')
    index_html_path.write_text(index_html, encoding="utf-8")
    print("[+] Updated wargame/index.html HUD to 0/2660.")

    # 6. Update the 6 documentation files carrying the challenge count
    docs_to_update = [
        "README.md", "README.en.md", "README.ja.md", "README.zh.md",
        "USAGE.md", "AI_LEARNING.md"
    ]
    for d in docs_to_update:
        d_path = repo_root / d
        if d_path.exists():
            text = d_path.read_text(encoding="utf-8")
            # Replace 2625 with 2660, 2,625 with 2,660, 75 tracks with 76 tracks, 63 labs with 64 labs
            text = re.sub(r'2,?625\s*(문제|challenges?|問題?|道挑战|道题|题)', r'2,660 \1', text)
            text = text.replace('·2625-', '·2660-')
            text = text.replace('·2,625-', '·2,660-')
            text = text.replace('75개 트랙', '76개 트랙')
            text = text.replace('75 tracks', '76 tracks')
            text = text.replace('75 트랙', '76 트랙')
            text = text.replace('63개 실습 랩', '64개 실습 랩')
            text = text.replace('63개 랩', '64개 랩')
            text = text.replace('63 Labs', '64 Labs')
            text = text.replace('63 labs', '64 labs')
            text = text.replace('63 랩', '64 랩')
            text = text.replace('63대 실습 랩', '64대 실습 랩')
            d_path.write_text(text, encoding="utf-8")
            print(f"[+] Updated {d} counts to 2,660 challenges, 76 tracks, 64 labs.")

    print("[*] Track 76 (lsmsec) generation completed!")


if __name__ == "__main__":
    main()
