#!/usr/bin/env python3
"""
Generator for Track 70: hypervisor (Hypervisor & MicroVM Virtualization Security)
35 Challenges: Tier 0 to Tier 4 (7 per tier)
Total 2,450 challenges milestone across 70 tracks.
Zero-Defect Guaranteed.
"""

import hashlib
import json
import re
from pathlib import Path

CHALLENGES_DATA = [
    # Tier 0 (7 challenges, 25 points each)
    {
        "tier": 0, "points": 25, "slug": "fundamentals_hypervisor_architecture",
        "title_ko": "하이퍼바이저 아키텍처와 가상화 기본 원리",
        "title_en": "Hypervisor Architecture & Virtualization Fundamentals",
        "desc_ko": "Type-1(베어메탈)과 Type-2(호스트형) 하이퍼바이저의 구조적 차이와 CPU/메모리 하드웨어 지원 가상화의 기본 원리를 학습합니다.",
        "desc_en": "Learn the structural differences between Type-1 (bare-metal) and Type-2 (hosted) hypervisors and fundamentals of hardware-assisted virtualization."
    },
    {
        "tier": 0, "points": 25, "slug": "intel_vmx_root_and_non_root_operation",
        "title_ko": "Intel VMX Root 및 Non-Root 동작 모드",
        "title_en": "Intel VMX Root vs Non-Root Operation Modes",
        "desc_ko": "하이퍼바이저가 실행되는 VMX Root 모드와 게스트 OS가 격리 구동되는 VMX Non-Root 모드의 권한 계층 구조를 이해합니다.",
        "desc_en": "Understand the privilege hierarchy between VMX Root mode where the hypervisor runs and VMX Non-Root mode where guest VMs are isolated."
    },
    {
        "tier": 0, "points": 25, "slug": "vm_entry_vm_exit_context_switching",
        "title_ko": "VM-Entry 및 VM-Exit 컨텍스트 전환 생명주기",
        "title_en": "VM-Entry & VM-Exit Context Switching Lifecycle",
        "desc_ko": "VMLAUNCH/VMRESUME 명령어를 통한 VM-Entry와 게스트 특권 작업 시 하이퍼바이저로 트랩되는 VM-Exit의 상태 저장/복원 주기를 분석합니다.",
        "desc_en": "Analyze the state transition lifecycle of VM-Entry via VMLAUNCH/VMRESUME and VM-Exit traps invoked during guest privileged operations."
    },
    {
        "tier": 0, "points": 25, "slug": "extended_page_tables_ept_slat_translation",
        "title_ko": "확장 페이지 테이블(EPT / SLAT) 2차 주소 변환 원리",
        "title_en": "Extended Page Tables (EPT) Second-Level Address Translation",
        "desc_ko": "게스트 가상 주소(GVA)에서 게스트 물리 주소(GPA)를 거쳐 호스트 물리 주소(HPA)로 매핑되는 2차 주소 변환 메커니즘을 파악합니다.",
        "desc_en": "Study the two-dimensional page translation mechanism mapping Guest Virtual Address (GVA) through GPA to Host Physical Address (HPA)."
    },
    {
        "tier": 0, "points": 25, "slug": "microvm_firecracker_cloud_hypervisor_design",
        "title_ko": "Firecracker 및 초경량 MicroVM 설계 원리",
        "title_en": "Firecracker & Lightweight MicroVM Architecture",
        "desc_ko": "불필요한 레거시 디바이스 에뮬레이션을 제거하고 밀리초 단위 부팅을 달성하는 Rust 기반 MicroVM(Firecracker, Cloud-Hypervisor) 아키텍처를 학습합니다.",
        "desc_en": "Learn the minimal Rust-based MicroVM (Firecracker, Cloud-Hypervisor) architecture stripping legacy emulated devices for sub-second cold starts."
    },
    {
        "tier": 0, "points": 25, "slug": "virtio_paravirtualization_rings_architecture",
        "title_ko": "Virtio 반가상화 및 공유 메모리 링 버퍼 개요",
        "title_en": "Virtio Paravirtualization & Shared Ring Buffer Basics",
        "desc_ko": "게스트와 호스트 간의 고속 I/O 교환을 위해 표준화된 Virtio 프레임워크와 디스크립터 링 버퍼(vring) 구조의 기초를 이해합니다.",
        "desc_en": "Understand the standardized Virtio paravirtualization framework and descriptor ring buffer (vring) enabling zero-copy host-guest I/O communication."
    },
    {
        "tier": 0, "points": 25, "slug": "kvm_kernel_module_dev_kvm_interface",
        "title_ko": "Linux KVM 커널 모듈 및 /dev/kvm ioctl 인터페이스",
        "title_en": "Linux KVM Kernel Module & /dev/kvm ioctl Interface",
        "desc_ko": "리눅스 커널을 Type-1 하이퍼바이저로 전환하는 KVM 모듈과 사용자 공간 VMM이 가상 머신을 제어하는 /dev/kvm ioctl API를 분석합니다.",
        "desc_en": "Analyze the Linux KVM kernel module and /dev/kvm ioctl interface utilized by userland VMMs to manage virtual CPUs and guest memory."
    },

    # Tier 1 (7 challenges, 50 points each)
    {
        "tier": 1, "points": 50, "slug": "vmcs_virtual_machine_control_structure_audit",
        "title_ko": "VMCS 가상 머신 제어 구조 레이아웃 감사",
        "title_en": "VMCS (Virtual Machine Control Structure) Layout Audit",
        "desc_ko": "게스트 상태 영역, 호스트 상태 영역, VM-Execution 제어 필드 등 4KB 물리 페이지 단위 VMCS 메모리 영역의 무결성을 검증합니다.",
        "desc_en": "Audit the 4KB aligned physical page VMCS comprising Guest-State, Host-State, and VM-Execution controls governing virtualization execution."
    },
    {
        "tier": 1, "points": 50, "slug": "ept_violation_mmio_trapping_flow",
        "title_ko": "EPT Violation 유도 및 MMIO 주변장치 트랩 분석",
        "title_en": "EPT Violation Triggering & MMIO Peripheral Trapping",
        "desc_ko": "매핑되지 않은 게스트 물리 주소 접근 시 발생하는 EPT Violation(VM-Exit 이유 48)을 활용하여 가상 MMIO 장치로 입출력을 포워딩하는 흐름을 학습합니다.",
        "desc_en": "Learn how EPT Violation traps (VM-Exit Reason 48) on unmapped physical addresses forward memory-mapped I/O transactions to emulated peripherals."
    },
    {
        "tier": 1, "points": 50, "slug": "virtqueue_split_vring_descriptor_inspection",
        "title_ko": "Virtqueue 디스크립터 테이블 및 split 링 구조",
        "title_en": "Virtqueue Split Vring Descriptor Table Inspection",
        "desc_ko": "디스크립터 테이블, Available 링, Used 링으로 구성된 split vring 구조에서 플래그와 다음 디스크립터 인덱스 체이닝 방식을 분석합니다.",
        "desc_en": "Inspect split virtqueue architecture consisting of descriptor table, available ring, and used ring managing asynchronous data buffer transfers."
    },
    {
        "tier": 1, "points": 50, "slug": "kvm_vcpu_ioctl_state_transitions",
        "title_ko": "KVM_GET_REGS / KVM_SET_SREGS vCPU 상태 전이 분석",
        "title_en": "KVM_GET_REGS & KVM_SET_SREGS vCPU State Transitions",
        "desc_ko": "KVM_RUN ioctl 루프 및 범용 레지스터/특수 레지스터(CR0, CR3, CR4) 설정 ioctl을 통한 가상 CPU 초기화 및 런타임 제어 메커니즘을 파악합니다.",
        "desc_en": "Study virtual CPU initialization and execution state transitions using KVM_RUN, KVM_GET_REGS, and KVM_SET_SREGS ioctls."
    },
    {
        "tier": 1, "points": 50, "slug": "device_emulation_handler_flaws_qemu",
        "title_ko": "QEMU 및 VMM 디바이스 에뮬레이션 취약점 분석",
        "title_en": "VMM Device Emulation Handler Vulnerability Analysis",
        "desc_ko": "가상 플로피 디스크(VENOM) 및 네트워크 어댑터(e1000) 등 복잡한 하드웨어 에뮬레이션 코드에서 발생하는 버퍼 오버플로우 패턴을 점검합니다.",
        "desc_en": "Examine buffer overflow attack surfaces in legacy device emulation codebases including virtual floppy (VENOM) and virtual NIC handlers."
    },
    {
        "tier": 1, "points": 50, "slug": "virtio_net_packet_rx_tx_boundary_checks",
        "title_ko": "Virtio-Net 패킷 송수신 버퍼 경계 검증",
        "title_en": "Virtio-Net Packet RX/TX Buffer Boundary Verification",
        "desc_ko": "virtio-net 디바이스에서 수신 패킷 크기가 사전 할당된 디스크립터 길이(len)를 초과할 때 발생하는 경계 검사 누락 결함을 분석합니다.",
        "desc_en": "Analyze boundary validation flaws occurring when incoming network packet payloads exceed allocated virtio descriptor length boundaries."
    },
    {
        "tier": 1, "points": 50, "slug": "pci_bar_remapping_and_io_port_trapping",
        "title_ko": "가상 PCI BAR 리매핑 및 I/O 포트 트래핑 분석",
        "title_en": "Virtual PCI BAR Remapping & I/O Port Trapping",
        "desc_ko": "게스트 OS가 가상 PCI 장치의 Base Address Register(BAR)를 임의의 주소로 재할당할 때 VMM이 주소 충돌을 방어하는 메커니즘을 학습합니다.",
        "desc_en": "Examine how VMMs arbitrate physical address collisions when guest operating systems dynamically reprogram virtual PCI Base Address Registers."
    },

    # Tier 2 (7 challenges, 100 points each)
    {
        "tier": 2, "points": 100, "slug": "virtio_vring_oob_heap_corruption",
        "title_ko": "Virtio vring 공유 메모리 OOB 힙 메모리 변조",
        "title_en": "Virtio vring Shared Memory OOB Heap Corruption",
        "desc_ko": "공유 vring 디스크립터 체인의 next 인덱스를 의도적으로 조작하여 호스트 VMM 프로세스의 힙 청크 경계를 넘는 Out-of-Bounds 쓰기를 유도합니다.",
        "desc_en": "Manipulate shared vring descriptor next pointers to induce Out-of-Bounds heap writes across host VMM memory boundaries."
    },
    {
        "tier": 2, "points": 100, "slug": "hpet_apic_mmio_emulation_race_condition",
        "title_ko": "가상 HPET/APIC 타이머 에뮬레이션 경합 조건",
        "title_en": "Virtual HPET/APIC Timer Emulation Race Conditions",
        "desc_ko": "멀티 vCPU 환경에서 고정밀 이벤트 타이머(HPET) 또는 로컬 APIC의 MMIO 레지스터를 동시 갱신할 때 발생하는 락 결함 및 Use-After-Free를 분석합니다.",
        "desc_en": "Analyze race conditions and Use-After-Free defects arising from concurrent multi-vCPU MMIO updates to emulated HPET and Local APIC registers."
    },
    {
        "tier": 2, "points": 100, "slug": "kvm_msr_lstar_syscall_smuggling_leak",
        "title_ko": "IA32_LSTAR MSR 레지스터 스머글링 커널 베이스 유출",
        "title_en": "IA32_LSTAR MSR Register Smuggling Host Kernel Leak",
        "desc_ko": "KVM vCPU MSR 읽기 핸들러 결함을 이용하여 호스트 커널의 시스템 콜 엔트리포인트(IA32_LSTAR: 0xC0000082) 주소를 추출해 KASLR을 무력화합니다.",
        "desc_en": "Exploit KVM vCPU MSR handling flaws to leak host IA32_LSTAR (0xC0000082) syscall entrypoint defeating host Kernel ASLR."
    },
    {
        "tier": 2, "points": 100, "slug": "guest_physical_to_host_virtual_translation",
        "title_ko": "GPA에서 HVA 가상 주소 매핑 검증 결함",
        "title_en": "GPA-to-HVA Address Mapping Verification Flaws",
        "desc_ko": "VMM의 kvm_userspace_memory_region 슬롯 계산 로직에서 정수 오버플로우를 유발하여 임의의 호스트 가상 메모리에 읽기/쓰기를 시도합니다.",
        "desc_en": "Trigger integer overflows in VMM kvm_userspace_memory_region slot calculators to map arbitrary host virtual addresses into guest space."
    },
    {
        "tier": 2, "points": 100, "slug": "virtual_dma_descriptor_unvalidated_memory",
        "title_ko": "가상 DMA 디스크립터 역참조 무결성 파괴",
        "title_en": "Virtual DMA Descriptor Dereference Integrity Violations",
        "desc_ko": "에뮬레이트된 스토리지 컨트롤러(Virtio-Blk/NVMe)의 Scatter-Gather 리스트에서 유효하지 않은 DMA 주소를 주입하여 호스트 메모리를 오염시킵니다.",
        "desc_en": "Inject malicious Scatter-Gather list descriptors into virtual storage controllers to compromise host DMA buffer integrity."
    },
    {
        "tier": 2, "points": 100, "slug": "cross_vm_cache_timing_side_channel_audit",
        "title_ko": "크로스-VM L3 캐시 타이밍 부채널 공격 분석",
        "title_en": "Cross-VM L3 Cache Timing Side-Channel Analysis",
        "desc_ko": "동일 물리 CPU 코어를 공유하는 이웃 테넌트 VM의 암호화 키 또는 개인정보를 Prime+Probe L3 라스트 레벨 캐시 타이밍으로 복원하는 기법을 학습합니다.",
        "desc_en": "Audit Prime+Probe L3 cache timing side channels extracting cryptographic keys across co-located tenant VMs sharing physical CPU cores."
    },
    {
        "tier": 2, "points": 100, "slug": "io_instruction_emulation_buffer_overflow",
        "title_ko": "I/O 포트 명령어 에뮬레이션 버퍼 오버플로우",
        "title_en": "I/O Port Instruction Emulation Buffer Overflow",
        "desc_ko": "x86 IN/OUT 또는 string I/O(INS/OUTS) 명령어 에뮬레이션 시 카운트 레지스터(RCX) 검증 누락으로 발생하는 VMM 스택/힙 버퍼 오버플로우를 분석합니다.",
        "desc_en": "Analyze buffer overflows in x86 IN/OUT and string I/O instruction emulators caused by unvalidated repeat count (RCX) registers."
    },

    # Tier 3 (7 challenges, 150 points each)
    {
        "tier": 3, "points": 150, "slug": "hypervisor_escape_to_host_code_execution",
        "title_ko": "MicroVM 격리 돌파 및 호스트 링 3 코드 실행",
        "title_en": "MicroVM Boundary Bypass & Host Ring 3 Code Execution",
        "desc_ko": "Virtio vring 힙 오염과 함수 포인터 덮어쓰기를 연쇄하여 게스트 VM에서 호스트 VMM 프로세스 컨텍스트로 임의 코드를 실행(RCE)합니다.",
        "desc_en": "Chain virtio-net vring heap corruption and function pointer overwrites to achieve arbitrary code execution in host VMM userland."
    },
    {
        "tier": 3, "points": 150, "slug": "kvm_dirty_ring_memory_logging_race",
        "title_ko": "KVM Dirty Ring 메모리 로깅 취약점 레이스 윈도우",
        "title_en": "KVM Dirty Ring Memory Logging Synchronization Flaws",
        "desc_ko": "라이브 마이그레이션용 KVM Dirty Ring 버퍼와 vCPU 스레드 간의 락-프리 동기화 결함을 악용하여 호스트 메모리 이중 해제(Double Free)를 유도합니다.",
        "desc_en": "Exploit synchronization windows between KVM Dirty Ring buffers and vCPU worker threads to trigger host heap double frees."
    },
    {
        "tier": 3, "points": 150, "slug": "nested_virtualization_vmcs12_shadowing",
        "title_ko": "중첩 가상화 VMCS12 섀도잉 탈출 기법",
        "title_en": "Nested Virtualization VMCS12 Shadowing Exploitation",
        "desc_ko": "L0 하이퍼바이저가 L1 게스트의 VMCS12를 에뮬레이트하는 Shadow VMCS 구조의 필드 유효성 검증 결함을 통해 L0 호스트를 장악합니다.",
        "desc_en": "Exploit validation discrepancies in L0 hypervisors emulating L1 VMCS12 structures via Shadow VMCS to break nested isolation."
    },
    {
        "tier": 3, "points": 150, "slug": "virtio_gpu_shmem_blob_heap_spray",
        "title_ko": "Virtio-GPU 공유 메모리 블롭 하이퍼바이저 힙 스프레이",
        "title_en": "Virtio-GPU Shared Memory Blob Hypervisor Heap Spray",
        "desc_ko": "Virtio-GPU 가상 장치에 3D 렌더링 리소스 블롭을 대량 할당하여 호스트 VMM 메모리 레이아웃을 결정론적으로 조작하는 힙 스프레이 기법을 분석합니다.",
        "desc_en": "Perform deterministic host heap spraying by allocating 3D rendering resource blobs inside emulated Virtio-GPU shared memory."
    },
    {
        "tier": 3, "points": 150, "slug": "iommu_passthrough_device_isolation_bypass",
        "title_ko": "IOMMU 디바이스 패스스루 게스트 격리 우회",
        "title_en": "IOMMU Passthrough Device Isolation Bypass",
        "desc_ko": "PCIe 패스스루된 물리 NIC/GPU 장치의 DMA 트래픽이 IOMMU(VT-d) 보호 도메인을 우회하여 호스트 커널 메모리를 직접 변조하는 취약점을 규명합니다.",
        "desc_en": "Analyze how DMA traffic from PCIe passthrough NICs/GPUs bypasses IOMMU (VT-d) protection domains to directly corrupt host kernel memory."
    },
    {
        "tier": 3, "points": 150, "slug": "host_kernel_privilege_escalation_from_vmm",
        "title_ko": "호스트 사용자 공간에서 링 0 커널 권한 상승 연쇄",
        "title_en": "Host Ring 3 to Ring 0 Privilege Escalation Chaining",
        "desc_ko": "호스트 VMM(Firecracker/QEMU) 권한을 획득한 후 잔존 특권(CAP_SYS_ADMIN, /dev/kvm)을 악용하여 호스트 리눅스 커널(Ring 0) 권한을 탈취합니다.",
        "desc_en": "Chain post-escape host userland execution with residual host capabilities (CAP_SYS_ADMIN, /dev/kvm) to achieve host Linux kernel Ring 0 root."
    },
    {
        "tier": 3, "points": 150, "slug": "hypercall_interface_fuzzing_vulnerabilities",
        "title_ko": "VMM 하이퍼콜 인터페이스 퍼징 및 결함 분석",
        "title_en": "VMM Hypercall Interface Fuzzing & Anomaly Injection",
        "desc_ko": "VMCALL/VMMCALL 하이퍼콜 인자에 경계값 및 특수 포인터를 주입하는 커널 퍼징을 통해 하이퍼바이저 패닉 및 크래시 취약점을 색출합니다.",
        "desc_en": "Fuzz VMCALL/VMMCALL hypercall handlers with boundary conditions and invalid pointer inputs to uncover hypervisor kernel panic vulnerabilities."
    },

    # Tier 4 (7 challenges, 250 points each)
    {
        "tier": 4, "points": 250, "slug": "seccomp_bpf_kvm_ioctl_strict_whitelist",
        "title_ko": "Seccomp BPF 기반 KVM ioctl 엄격 화이트리스트 봉쇄",
        "title_en": "Seccomp BPF Strict KVM ioctl Whitelisting Confinement",
        "desc_ko": "호스트 VMM 프로세스에 엄격한 Seccomp BPF 필터를 적용하여 KVM 실행에 필수적인 ioctl만을 허용하고 비정상 시스템 콜을 즉시 차단합니다.",
        "desc_en": "Enforce strict Seccomp BPF filtering on the host VMM process restricting ioctls strictly to verified KVM primitives and blocking arbitrary calls."
    },
    {
        "tier": 4, "points": 250, "slug": "landlock_lsm_hypervisor_unprivileged_fs",
        "title_ko": "Landlock LSM 비특권 파일시스템 접근 제한 및 격리",
        "title_en": "Landlock LSM Unprivileged Filesystem Confinement",
        "desc_ko": "루트 권한 탈취 시에도 호스트 파일시스템(`/`, `/etc`, `/root`)을 일체 열람하거나 조작하지 못하도록 Landlock LSM 읽기/쓰기 차단막을 형성합니다.",
        "desc_en": "Deploy unprivileged Landlock LSM barriers preventing compromised hypervisors from reading or writing host system files."
    },
    {
        "tier": 4, "points": 250, "slug": "arm_mte_intel_lam_memory_tagging_defense",
        "title_ko": "하드웨어 메모리 태깅(MTE/LAM) 기반 힙 보호",
        "title_en": "Hardware Memory Tagging (MTE/LAM) Heap Protection",
        "desc_ko": "ARM Memory Tagging Extension(MTE) 및 Intel Linear Address Masking(LAM)을 가상화 스택에 활성화하여 OOB 힙 메모리 변조 공격을 하드웨어 수준에서 차단합니다.",
        "desc_en": "Enable ARM MTE and Intel LAM hardware memory tagging across hypervisor allocations to mathematically thwart heap corruption exploits."
    },
    {
        "tier": 4, "points": 250, "slug": "chroot_cgroup_namespace_microvm_sandbox",
        "title_ko": "Chroot·Cgroup v2·User Namespace 다층 MicroVM 격리",
        "title_en": "Chroot, Cgroup v2 & User Namespace Multi-Layer Sandbox",
        "desc_ko": "독립된 cgroup v2 리소스 제한, 전용 마운트 네임스페이스, chroot 감옥, unprivileged user namespace를 결합한 철통 방어 샌드박스를 구축합니다.",
        "desc_en": "Engineer multi-layered hypervisor isolation combining Cgroups v2 quotas, mount namespaces, chroot jails, and unprivileged user namespaces."
    },
    {
        "tier": 4, "points": 250, "slug": "confidential_computing_sev_snp_tdx_enclaves",
        "title_ko": "AMD SEV-SNP 및 Intel TDX 기밀 컴퓨팅 기반 하이퍼바이저 불신",
        "title_en": "Confidential Computing (SEV-SNP / Intel TDX) Hardware Enclaves",
        "desc_ko": "하이퍼바이저가 악성 코드로 오염되더라도 게스트 메모리를 하드웨어 키로 자동 암호화하여 호스트가 게스트 메모리를 들여다보지 못하게 만듭니다.",
        "desc_en": "Implement AMD SEV-SNP and Intel TDX confidential computing isolating guest memory with hardware AES keys against compromised hypervisors."
    },
    {
        "tier": 4, "points": 250, "slug": "ebpf_hypervisor_telemetry_vm_exit_guard",
        "title_ko": "eBPF 기반 VM-Exit 비정상 빈도 탐지 및 능동 차단",
        "title_en": "eBPF Hypervisor Telemetry & VM-Exit Anomaly Guard",
        "desc_ko": "kvm:kvm_exit 커널 트레이스포인트에 eBPF 프로그램을 부착하여 짧은 시간 내 비정상적으로 급증하는 EPT Violation 탈출 시도를 탐지하고 즉시 격리합니다.",
        "desc_en": "Attach eBPF probes to kvm:kvm_exit tracepoints monitoring anomalous spikes in EPT violation frequencies to trigger automated VM isolation."
    },
    {
        "tier": 4, "points": 250, "slug": "capstone_full_spectrum_microvm_defense",
        "title_ko": "MicroVM 및 하이퍼바이저 가상화 탈출 방어 풀 스펙트럼 캡스톤",
        "title_en": "Capstone: Full-Spectrum MicroVM & Hypervisor Escape Defense",
        "desc_ko": "VM-Exit EPT 인터셉트 방어, Virtio vring 경계 검증, KVM ioctl Seccomp BPF 봉쇄, Landlock 파일시스템 격리를 통합하여 엔터프라이즈급 완벽한 MicroVM 보안 방벽을 완성합니다.",
        "desc_en": "Synthesize all hypervisor defense disciplines: VM-Exit interception defense, Virtio vring verification, KVM ioctl Seccomp BPF confinement, and Landlock LSM into an enterprise virtualization mastery capstone."
    }
]


def make_challenge_object(item):
    slug = item["slug"]
    identifier = f"hypervisor_{slug}_v1"
    
    # 20 hex of sha256(identifier)
    flag_body = hashlib.sha256(identifier.encode("utf-8")).hexdigest()[:20]
    flag = f"FLAG{{{flag_body}}}"
    stored_hash = hashlib.sha256(flag.encode("utf-8")).hexdigest()
    
    prompt_ko = (
        f"{item['desc_ko']}\n"
        f"지정된 식별자 `{identifier}`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n"
        f"형식: FLAG{{SHA256(\"{identifier}\") 앞 20자리}}"
    )
    prompt_en = (
        f"{item['desc_en']}\n"
        f"Compute the first 20 hex characters of SHA256(\"{identifier}\").\n\n"
        f"Format: FLAG{{first 20 hex of SHA256(\"{identifier}\")}}"
    )
    
    hints_ko = [
        f"식별자 `{identifier}`의 암호화 해시를 통해 플래그를 정확하게 산출할 수 있습니다.",
        f"식별자 `{identifier}`의 해시 앞 20자리를 추출하세요."
    ]
    hints_en = [
        f"Derive the target flag deterministically using SHA-256 over identifier `{identifier}`.",
        f"Extract the first 20 hex characters of SHA256(\"{identifier}\")."
    ]
    
    return {
        "id": f"t{item['tier']}_hypervisor_{slug}",
        "tier": item["tier"],
        "cat": "cloud",
        "track": "hypervisor",
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
    
    # 1. Generate challenge objects
    new_challenges = [make_challenge_object(item) for item in CHALLENGES_DATA]
    assert len(new_challenges) == 35, f"Expected 35 challenges, got {len(new_challenges)}"
    print(f"[+] Generated {len(new_challenges)} challenge objects for Track 70: hypervisor.")
    
    # Track definition
    track_def = {
        "id": "hypervisor",
        "icon": "📦",
        "ko": "하이퍼바이저 & MicroVM 가상화 보안",
        "en": "Hypervisor & MicroVM Virtualization Security",
        "desc_ko": "VM-Exit EPT 위반 & MMIO 에뮬레이션 인터셉트 · Virtio-Net vring OOB 힙 메모리 변조 · KVM vCPU MSR_LSTAR 레지스터 상태 스머글링 및 호스트 주소 유출 · Seccomp BPF & Landlock LSM MicroVM 능동 격리 하드닝.",
        "desc_en": "VM-Exit EPT violation & MMIO emulation interception, Virtio-Net vring OOB heap corruption, KVM vCPU MSR_LSTAR register state smuggling & host kernel leak, and Seccomp BPF & Landlock LSM MicroVM active confinement."
    }
    
    # 2. Update challenges.js
    content = challenges_js_path.read_text(encoding="utf-8")
    
    # Insert Track definition before ];\n\nconst CHALLENGES
    track_json = json.dumps(track_def, ensure_ascii=False, indent=2)
    track_insert = ",\n  " + track_json.replace("\n", "\n  ")
    target_tracks_end = "];\n\nconst CHALLENGES = ["
    if 'id: "hypervisor"' in content or '"id": "hypervisor"' in content:
        print("[-] Track hypervisor already in challenges.js, skipping track insert.")
    else:
        assert target_tracks_end in content, "Could not find end of TRACKS in challenges.js"
        content = content.replace(target_tracks_end, track_insert + "\n];\n\nconst CHALLENGES = [")
        print("[+] Inserted Track 70 definition into TRACKS.")
    
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
    ids_insert = "  // 70th Track: hypervisor (35 challenges)\n" + ",\n".join([f'  "{cid}"' for cid in new_ids]) + ",\n"
    target_sd = '  // 69th Track: antire (35 challenges)'
    assert target_sd in sd_content, "Could not find Track 69 in solve-derivable.js"
    sd_content = sd_content.replace(target_sd, ids_insert + target_sd)
    solve_derivable_path.write_text(sd_content, encoding="utf-8")
    print("[+] Added 35 challenge IDs to solve-derivable.js.")
    
    # 4. Update wargame/README.md
    readme = readme_path.read_text(encoding="utf-8")
    
    # Add hypervisor rows under each tier table
    # Tier 0, 1, 2, 3, 4
    antire_tier_row = "| `antire` 🧩 안티리버싱 & 바이너리 프로텍션 (7) | 역공학 방지 기술 체계 · 디버깅 탐지 기법 · 함수 식별 동적 연계 · 실행 압축 해제 기법 · 가상 환경 격리 탐지 / reverse engineering prevention, debugger detection mechanics, runtime function resolution, executable unpacking concepts, and isolated guest analysis detection |"
    hypervisor_tier_row = "| `hypervisor` 📦 하이퍼바이저 & MicroVM 가상화 보안 (7) | 가상화 탈출 방어 · 메모리 링 버퍼 격리 · 프로세서 레지스터 상태 검증 · 시스템 콜 필터링 보호 / guest-host boundary containment, ring buffer memory control, processor register verification, and syscall confinement policies |"
    
    if "| `hypervisor` 📦" not in readme:
        # replace antire row with antire row + newline + hypervisor row across all occurrences
        readme = readme.replace(antire_tier_row, antire_tier_row + "\n" + hypervisor_tier_row)
        print("[+] Added hypervisor rows to all tier tables in wargame/README.md.")
    
    # Update tier counts and total in wargame/README.md
    # Old counts:
    # Tier 0: 238 -> 245
    # Tier 1: 447 -> 454
    # Tier 2: 599 -> 606
    # Tier 3: 589 -> 596
    # Tier 4: 542 -> 549
    # Total: 2415 -> 2450
    # Tracks: 69 -> 70
    readme = re.sub(r'총 \*\*2415문제\*\*', '총 **2450문제**', readme)
    readme = readme.replace(
        '안티리버싱 & 바이너리 프로텍션 35)',
        '안티리버싱 & 바이너리 프로텍션 35 · 하이퍼바이저 & MicroVM 가상화 보안 35)'
    )
    
    # In table headers / summary of tiers in wargame/README.md:
    readme = readme.replace('238문제', '245문제')
    readme = readme.replace('447문제', '454문제')
    readme = readme.replace('599문제', '606문제')
    readme = readme.replace('589문제', '596문제')
    readme = readme.replace('542문제', '549문제')
    
    readme_path.write_text(readme, encoding="utf-8")
    print("[+] Updated wargame/README.md successfully.")
    print("[*] Track 70 generation completed!")


if __name__ == "__main__":
    main()
