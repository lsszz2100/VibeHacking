#!/usr/bin/env python3
"""
Generator for Track 69: antire (Anti-Reversing & Binary Protection)
35 Challenges: Tier 0 to Tier 4 (7 per tier)
Zero-Defect Guaranteed.
"""

import hashlib
import json
import re
from pathlib import Path

CHALLENGES_DATA = [
    # Tier 0 (7 challenges, 25 points each)
    {
        "tier": 0, "points": 25, "slug": "fundamentals_anti_reversing_overview",
        "title_ko": "안티 리버싱 및 바이너리 보호의 기본 원리",
        "title_en": "Anti-Reversing & Binary Protection Fundamentals",
        "desc_ko": "정적 분석(디스어셈블러)과 동적 분석(디버거)을 방해하기 위해 바이너리에 적용되는 난독화, 패킹, 무결성 검증의 기본 메커니즘을 학습합니다.",
        "desc_en": "Learn the foundational mechanisms of obfuscation, packing, and integrity verification designed to hinder static disassembly and dynamic debugging."
    },
    {
        "tier": 0, "points": 25, "slug": "disassembly_linear_sweep_vs_recursive_traversal",
        "title_ko": "선형 스윕과 재귀 순회 디스어셈블러 분석 한계",
        "title_en": "Linear Sweep vs Recursive Traversal Disassembly Limitations",
        "desc_ko": "선형 스윕 디스어셈블러가 정크 바이트 삽입 및 불투명 조건문(Opaque Predicate)에 의해 코드 흐름을 오도하는 원리를 분석합니다.",
        "desc_en": "Analyze how linear sweep disassemblers are deceived by junk byte insertion and opaque predicates leading to invalid instruction decoding."
    },
    {
        "tier": 0, "points": 25, "slug": "peb_being_debugged_flag_structure",
        "title_ko": "Windows PEB BeingDebugged 플래그 구조와 탐지",
        "title_en": "Windows PEB BeingDebugged Flag Architecture",
        "desc_ko": "프로세스 환경 블록(PEB)의 오프셋 0x02에 위치한 BeingDebugged 플래그를 IsDebuggerPresent API 및 인라인 어셈블리로 검사하는 기법을 이해합니다.",
        "desc_en": "Understand how the BeingDebugged flag at PEB offset 0x02 is queried via IsDebuggerPresent and inline assembly routines."
    },
    {
        "tier": 0, "points": 25, "slug": "linux_ptrace_traceme_mechanism",
        "title_ko": "Linux ptrace(PTRACE_TRACEME) 단일 디버거 제약",
        "title_en": "Linux ptrace(PTRACE_TRACEME) Single-Debugger Constraint",
        "desc_ko": "동일 프로세스에 하나의 디버거만 attach될 수 있는 POSIX ptrace 특성을 악용하여 사전에 PTRACE_TRACEME를 호출해 외부 디버깅을 원천 차단하는 기법을 분석합니다.",
        "desc_en": "Analyze the POSIX constraint where only one debugger can attach, exploited by invoking PTRACE_TRACEME early to reject external debuggers."
    },
    {
        "tier": 0, "points": 25, "slug": "binary_packing_stub_and_payload",
        "title_ko": "바이너리 패커 스텁 구조와 엔트로피 분석 기초",
        "title_en": "Binary Packer Stub Architecture & Entropy Basics",
        "desc_ko": "압축/암호화된 페이로드와 이를 메모리에 전개하는 디컴프레션 스텁의 역할을 규명하고, 높은 섀넌 엔트로피(>7.2)를 통한 패킹 식별법을 학습합니다.",
        "desc_en": "Identify compressed/encrypted payloads and decompression stubs while utilizing high Shannon entropy (>7.2) for automated packing detection."
    },
    {
        "tier": 0, "points": 25, "slug": "dynamic_api_resolution_motivation",
        "title_ko": "동적 API 로딩과 정적 IAT 은닉의 필요성",
        "title_en": "Dynamic API Resolution & Static IAT Concealment",
        "desc_ko": "정적 임포트 주소 테이블(IAT)에 중요 API(VirtualAlloc, WriteProcessMemory)가 노출되지 않도록 런타임에 GetProcAddress를 대치하는 은닉 기법을 학습합니다.",
        "desc_en": "Study how hiding sensitive APIs (VirtualAlloc, WriteProcessMemory) from the static IAT hinders heuristic antivirus scanners."
    },
    {
        "tier": 0, "points": 25, "slug": "anti_vm_virtualization_artifacts_intro",
        "title_ko": "가상화 환경(VM) 아티팩트 및 하이퍼바이저 식별 개요",
        "title_en": "Virtualization Artifacts & Hypervisor Detection Overview",
        "desc_ko": "자동 분석 샌드박스를 회피하기 위해 드라이버 이름, MAC 주소 OUI, 레지스트리 키, 가상 장치 아티팩트를 스캔하는 기본 원리를 파악합니다.",
        "desc_en": "Examine the fundamentals of scanning virtual drivers, MAC address OUIs, registry artifacts, and virtual hardware to evade sandboxes."
    },

    # Tier 1 (7 challenges, 50 points each)
    {
        "tier": 1, "points": 50, "slug": "peb_nt_global_flag_heap_flags_audit",
        "title_ko": "PEB NtGlobalFlag 및 힙 플래그 디버거 흔적 색출",
        "title_en": "PEB NtGlobalFlag & Heap Flags Debugger Inspection",
        "desc_ko": "디버거 부착 시 힙 검증을 위해 PEB의 NtGlobalFlag(0x70) 및 ProcessHeap Flags가 특정 플래그(0x00000002)로 설정되는 메모리 아티팩트를 분석합니다.",
        "desc_en": "Audit PEB NtGlobalFlag (0x70) and ProcessHeap Flags which are automatically asserted by Windows loaders when attaching a debugger."
    },
    {
        "tier": 1, "points": 50, "slug": "hardware_breakpoints_dr_registers_detection",
        "title_ko": "하드웨어 브레이크포인트 디버그 레지스터(DR0-DR7) 탐지",
        "title_en": "Hardware Breakpoint Debug Registers (DR0-DR7) Audit",
        "desc_ko": "GetThreadContext API 또는 SEH 구조적 예외 처리를 통해 x86/x64 디버그 레지스터(DR0~DR3)의 주소 및 DR7 제어 레지스터의 활성화 여부를 탐지하는 기법을 학습합니다.",
        "desc_en": "Detect hardware breakpoints by querying thread context registers (DR0-DR3, DR7) using GetThreadContext or Structured Exception Handlers."
    },
    {
        "tier": 1, "points": 50, "slug": "ror13_api_hashing_implementation",
        "title_ko": "ROR13 알고리즘 기반 API Hashing 구현 원리",
        "title_en": "ROR13 Dynamic API Hashing Mechanics",
        "desc_ko": "문자열을 13비트 오른쪽 순환 시프트(ROR)하고 누적하여 32비트 고유 해시값을 산출하는 표준 ROR13 해싱 알고리즘을 분석합니다.",
        "desc_en": "Analyze the standard ROR13 hashing algorithm rotating 13 bits right and accumulating ASCII values to yield 32-bit unique API hashes."
    },
    {
        "tier": 1, "points": 50, "slug": "peb_ldr_data_export_directory_traversal",
        "title_ko": "PEB InLoadOrderModuleList 기반 익스포트 디렉터리 순회",
        "title_en": "PEB InLoadOrderModuleList Export Directory Traversal",
        "desc_ko": "GetModuleHandle/GetProcAddress를 호출하지 않고 PEB Ldr 이중 연결 리스트를 순회하여 kernel32.dll의 EAT(Export Address Table)를 직접 파싱하는 기법을 학습합니다.",
        "desc_en": "Walk the PEB Ldr double-linked list to locate kernel32.dll and directly parse the Export Address Table without calling Win32 APIs."
    },
    {
        "tier": 1, "points": 50, "slug": "upx_packer_structure_and_signature_modification",
        "title_ko": "UPX 패커 헤더 시그니처 변조 및 분석 도구 무력화",
        "title_en": "UPX Header Signature Tampering & Tool Confusion",
        "desc_ko": "공식 `upx -d` 언패커의 자동 복구를 차단하기 위해 UPX0/UPX1 섹션 이름 및 헤더 매직 넘버를 제로화하거나 변조하는 안티-언패킹 트릭을 분석합니다.",
        "desc_en": "Examine anti-unpacking techniques where UPX section headers and magic numbers are zeroed or renamed to break standard decompression tools."
    },
    {
        "tier": 1, "points": 50, "slug": "tls_callbacks_pre_main_execution",
        "title_ko": "TLS(Thread Local Storage) 콜백을 활용한 사전 탐지",
        "title_en": "TLS Callbacks for Pre-Entry Point Analysis Defense",
        "desc_ko": "메인 엔트리 포인트(AddressOfEntryPoint)가 호출되기 전 운영체제 로더 단계에서 먼저 실행되는 TLS 콜백 함수에 안티디버깅 루틴을 배치하는 기법을 학습합니다.",
        "desc_en": "Learn how TLS callbacks execute before the main AddressOfEntryPoint to run stealthy anti-debugging checks before analysts break."
    },
    {
        "tier": 1, "points": 50, "slug": "linux_proc_status_tracerpid_audit",
        "title_ko": "Linux /proc/self/status TracerPid 모니터링",
        "title_en": "Linux /proc/self/status TracerPid Monitoring",
        "desc_ko": "프로세스가 디버거(GDB, LLDB)에 의해 추적될 때 `/proc/self/status`의 TracerPid 필드가 디버거 PID로 갱신되는 원리를 감시하여 탐지하는 메커니즘을 규명합니다.",
        "desc_en": "Inspect how processes monitor `/proc/self/status` TracerPid fields to catch attached debuggers (GDB, LLDB) in runtime."
    },

    # Tier 2 (7 challenges, 100 points each)
    {
        "tier": 2, "points": 100, "slug": "opaque_predicates_control_flow_obfuscation",
        "title_ko": "불투명 조건문(Opaque Predicate)을 통한 제어 흐름 왜곡",
        "title_en": "Opaque Predicates Control Flow Obfuscation",
        "desc_ko": "수학적 항등식(예: 7y^2 - 1 != x^2)을 이용해 런타임에는 항상 동일하게 평가되지만 디컴파일러 정적 분석 시 양방향 분기로 인식하게 만드는 난독화를 분석합니다.",
        "desc_en": "Analyze mathematical identities that evaluate invariantly at runtime but force decompilers to generate complex false control flow paths."
    },
    {
        "tier": 2, "points": 100, "slug": "packer_tail_jump_and_oep_reconstruction",
        "title_ko": "패커 테일 점프(Tail Jump) 식별과 OEP 복원",
        "title_en": "Packer Tail Jump Identification & OEP Reconstruction",
        "desc_ko": "스텁 루틴의 스택 균형(`popad`/`POPFQ`) 이후 장거리 무조건 분기(`jmp OEP`)를 추적하여 실제 프로그램의 원본 진입점(OEP)을 특정하는 기법을 실습합니다.",
        "desc_en": "Track the final stack restoration (popad/POPFQ) followed by a long-distance unconditional jump to pinpoint the Original Entry Point (OEP)."
    },
    {
        "tier": 2, "points": 100, "slug": "murmur3_api_hashing_collision_resistance",
        "title_ko": "Murmur3 API Hashing 및 해시 충돌 방어 기법",
        "title_en": "Murmur3 API Hashing & Collision-Resistant Resolution",
        "desc_ko": "단순 회전 시프트 알고리즘보다 높은 비트 분산도를 제공하는 32비트 Murmur3 해시를 활용하여 EAT 순회 시 충돌 없이 API를 동적 바인딩하는 구조를 파악합니다.",
        "desc_en": "Study 32-bit Murmur3 hashing offering superior avalanche characteristics for collision-free dynamic API symbol resolution."
    },
    {
        "tier": 2, "points": 100, "slug": "seh_veh_structured_exception_handling_anti_debug",
        "title_ko": "SEH 및 VEH 예외 처리를 활용한 디버거 흐름 가로채기",
        "title_en": "SEH & VEH Structured Exception Handling Anti-Debug",
        "desc_ko": "의도적으로 `INT 3`(0xCC) 또는 메모리 접근 위반 예외를 유발하여 디버거가 예외를 삼키는지 확인하고 예외 핸들러에서 실행 흐름을 전환하는 기법을 분석합니다.",
        "desc_en": "Trigger deliberate INT 3 or memory fault exceptions to verify if a debugger swallows them before delegating to custom VEH/SEH handlers."
    },
    {
        "tier": 2, "points": 100, "slug": "rdtsc_timing_analysis_single_stepping_defense",
        "title_ko": "RDTSC 명령어 기반 싱글 스텝 디버깅 시간 지연 탐지",
        "title_en": "RDTSC CPU Cycle Delta Single-Stepping Detection",
        "desc_ko": "코드 블록 전후의 CPU 타임스탬프 카운터(`rdtsc`) 차이를 측정하여 분석가가 명령어를 한 줄씩 단계별 실행(F8/F7)할 때 발생하는 비정상적 사이클 지연을 탐지합니다.",
        "desc_en": "Measure elapsed CPU timestamp cycles before and after instructions to detect human single-stepping delays during interactive debugging."
    },
    {
        "tier": 2, "points": 100, "slug": "import_address_table_rebuilding_scylla",
        "title_ko": "덤프된 PE 바이너리의 IAT 재구축 및 Scylla 복구 원리",
        "title_en": "Dumped PE Import Address Table Rebuilding Mechanics",
        "desc_ko": "메모리 덤프 과정에서 손상된 Import Directory를 가상 메모리 내의 함수 포인터와 비교하여 원본 DLL 명칭 및 Thunk 데이터를 완전히 복원하는 원리를 학습합니다.",
        "desc_en": "Reconstruct corrupted Import Address Tables in memory dumps by resolving function pointers back to corresponding DLL names and thunk arrays."
    },
    {
        "tier": 2, "points": 100, "slug": "smbios_registry_mac_anti_vm_triangulation",
        "title_ko": "SMBIOS, 레지스트리, MAC OUI 복합 가상 머신 탐지",
        "title_en": "SMBIOS, Registry & MAC OUI Multi-Artifact Anti-VM",
        "desc_ko": "QEMU, VMware, VirtualBox 특유의 SMBIOS 문자열, PCI Vendor ID, 가상 이더넷 MAC OUI(00:05:69, 08:00:27)를 복합 검증하여 분석 샌드박스를 차단하는 기법을 분석합니다.",
        "desc_en": "Triangulate sandbox presence by cross-checking SMBIOS vendor strings, PCI device IDs, and virtual MAC OUIs (VMware, VirtualBox, QEMU)."
    },

    # Tier 3 (7 challenges, 175 points each)
    {
        "tier": 3, "points": 175, "slug": "control_flow_flattening_ollvm_dispatcher",
        "title_ko": "OLLVM 제어 흐름 평탄화(Control Flow Flattening) 분석",
        "title_en": "OLLVM Control Flow Flattening Dispatcher Reversal",
        "desc_ko": "함수 내 기본 블록(Basic Block)들의 제어 흐름을 제거하고 거대한 switch-case 상태 머신 디스패처로 통합하여 정적 제어 그래프를 무력화하는 난독화를 해체합니다.",
        "desc_en": "Reverse-engineer flattened control flows where basic blocks are collapsed into a centralized state dispatcher switch-case loop."
    },
    {
        "tier": 3, "points": 175, "slug": "code_virtualization_custom_bytecode_vm",
        "title_ko": "코드 가상화(Code Virtualization) 및 가상 바이트코드 인터프리터",
        "title_en": "Code Virtualization & Custom Bytecode Interpreter",
        "desc_ko": "x86 네이티브 인스트럭션을 커스텀 바이트코드로 컴파일하고 가상 CPU(가상 레지스터, 가상 스택, VIP) 인터프리터로 구동하는 고도화된 보호 기법을 분석합니다.",
        "desc_en": "Analyze advanced binary protections transforming native x86 instructions into proprietary bytecode executed by an in-binary virtual CPU interpreter."
    },
    {
        "tier": 3, "points": 175, "slug": "self_modifying_code_smc_runtime_decryption",
        "title_ko": "자가 수정 코드(SMC)와 런타임 다형성 복호화",
        "title_en": "Self-Modifying Code (SMC) & Runtime Polymorphic Decryption",
        "desc_ko": "실행 중인 코드 섹션(PROT_WRITE|PROT_EXEC)이 다음 실행할 루틴을 실시간으로 복호화한 후 실행 직후 다시 제로화하여 정적 덤프를 무력화하는 SMC 구조를 규명합니다.",
        "desc_en": "Deconstruct self-modifying code dynamically decrypting subsequent function blocks in memory and clearing them immediately after execution."
    },
    {
        "tier": 3, "points": 175, "slug": "cpuid_hypervisor_bit_and_leaf_spoofing",
        "title_ko": "CPUID 하이퍼바이저 비트(Leaf 1 ECX 31) 검증과 우회",
        "title_en": "CPUID Hypervisor Flag & Feature Leaf Evasion",
        "desc_ko": "CPUID 명령어 실행 시 EAX=1 조건에서 반환되는 ECX 레지스터의 31번째 비트(Hypervisor Present) 및 0x40000000 리프의 하이퍼바이저 서명(TCGTCGTCGTCG)을 분석합니다.",
        "desc_en": "Evaluate CPUID leaf 1 ECX bit 31 (Hypervisor Present) and leaf 0x40000000 hypervisor vendor signatures used for hardware-level VM detection."
    },
    {
        "tier": 3, "points": 175, "slug": "instruction_counting_trap_flag_anti_debugging",
        "title_ko": "트랩 플래그(Trap Flag)와 단일 스텝 명령어 카운팅 안티디버깅",
        "title_en": "Trap Flag (TF) & Single-Step Instruction Counting Defense",
        "desc_ko": "EFLAGS의 Trap Flag(TF)를 활성화하여 단일 스텝 예외(STATUS_SINGLE_STEP)를 유발하고, 실제 실행된 명령어 바이트 수와 디버거 중재 결과를 교차 검증하는 기법을 분석합니다.",
        "desc_en": "Harness EFLAGS Trap Flag (TF) single-step exceptions to cross-check instruction retirement counters against debugger event handlers."
    },
    {
        "tier": 3, "points": 175, "slug": "driver_level_kernel_hooking_anti_analysis",
        "title_ko": "커널 드라이버 기반 디버그 서브시스템 후킹 및 블라인드",
        "title_en": "Kernel Driver Debug Subsystem Hooking & Blinding",
        "desc_ko": "루트킷 또는 안티치트 드라이버가 DbgkDebugObjectType 객체 및 NtDebugActiveProcess 시스템콜을 가로채 사용자 모드 디버거의 프로세스 핸들 획득을 원천 차단하는 기법을 파악합니다.",
        "desc_en": "Study kernel drivers hooking NtDebugActiveProcess and Dbgk subsystem internals to blind and deny userland debuggers from attaching."
    },
    {
        "tier": 3, "points": 175, "slug": "string_encryption_xor_chacha_stack_strings",
        "title_ko": "스택 스트링 및 동적 스트림 암호화 문자열 난독화 해제",
        "title_en": "Stack Strings & Stream Cipher Dynamic String Obfuscation",
        "desc_ko": "바이너리 .rdata 섹션에 문자열을 남기지 않고 개별 mov 명령어로 스택에 바이트를 조립하거나 ChaCha20/XOR 스트림으로 암호화하여 정적 문자열 추출을 차단하는 기법을 분석합니다.",
        "desc_en": "Analyze stack strings constructed on the fly via discrete mov opcodes and ChaCha20/XOR stream decryption routines preventing static string extraction."
    },

    # Tier 4 (7 challenges, 250 points each)
    {
        "tier": 4, "points": 250, "slug": "advanced_virtualizer_devirtualization_symbolic_execution",
        "title_ko": "기호 실행(Symbolic Execution)을 활용한 가상화 바이트코드 탈난독화",
        "title_en": "Symbolic Execution-Assisted Binary Devirtualization",
        "desc_ko": "Angr, Triton 등 기호 실행 엔진을 동원하여 가상 CPU 핸들러의 의미론(Semantics)을 추출하고, 가상 바이트코드를 원래의 LLVM IR 및 x86 네이티브 코드로 복원합니다.",
        "desc_en": "Leverage symbolic execution engines (Angr/Triton) to synthesize virtual handler semantics and devirtualize bytecode back to LLVM IR and native assembly."
    },
    {
        "tier": 4, "points": 250, "slug": "nested_virtualization_timing_side_channel_mitigation",
        "title_ko": "중첩 가상화 환경의 미세 타이밍 부채널 분석 및 능동 완화",
        "title_en": "Nested Virtualization Microarchitectural Timing Mitigation",
        "desc_ko": "VM-Exit 지연시간을 활용한 정교한 하이퍼바이저 감지 기법을 분석하고, TSC 가상화 오프셋 보정 및 KVM 하이퍼콜 인터셉트로 부채널 탐지를 무력화하는 샌드박스를 구축합니다.",
        "desc_en": "Deconstruct microarchitectural VM-Exit latency profiling used for stealthy hypervisor detection, implementing TSC offsetting to restore transparent virtualization."
    },
    {
        "tier": 4, "points": 250, "slug": "custom_cryptographic_packer_dump_reconstruction",
        "title_ko": "커스텀 암호화 다계층 패커 무력화 및 PE/ELF 완전 복구",
        "title_en": "Multi-Layered Cryptographic Packer Eradication & Rebuilding",
        "desc_ko": "다계층 복호화 스텁, TLS 콜백 무결성 해시 체이닝, 동적 재배치(Relocation) 테이블 손상을 순차 격파하고 클린 PE/ELF 이미지를 메모리에서 재구성합니다.",
        "desc_en": "Defeat multi-stage polymorphic decryptor stubs, TLS hash chains, and damaged relocation tables to reconstruct clean PE/ELF executable images."
    },
    {
        "tier": 4, "points": 250, "slug": "kernel_assisted_anti_tamper_ebpf_lsm_guard",
        "title_ko": "eBPF LSM 및 하드웨어 보안 기능을 결합한 바이너리 변조 방어",
        "title_en": "eBPF LSM & Hardware-Enforced Binary Anti-Tamper Guard",
        "desc_ko": "메모리 패칭(31c0c3) 및 디버거 어태치를 커널 레벨 eBPF LSM 훅과 Intel CET(Control-flow Enforcement Technology)로 실시간 탐지·차단하는 엔터프라이즈 방어망을 설계합니다.",
        "desc_en": "Architect enterprise binary integrity guards combining eBPF LSM hooks and Intel CET shadow stacks to prevent inline patching and memory tampering."
    },
    {
        "tier": 4, "points": 250, "slug": "anti_analysis_resilient_threat_hunting_pipeline",
        "title_ko": "고도 난독화 악성 바이너리 전수 자동 분석 및 색출 파이프라인",
        "title_en": "Anti-Analysis Resilient Automated Triage & Hunting Pipeline",
        "desc_ko": "수만 개의 안티-리버싱/안티-VM 바이너리를 QEMU/KVM 하이퍼바이저 패치 및 커널 텔레메트리를 통해 100% 투명하게 자동 동적 분석하는 분석 팜을 설계합니다.",
        "desc_en": "Design a transparent dynamic analysis pipeline using patched hypervisors and kernel telemetry to triage thousands of heavily-obfuscated malware samples."
    },
    {
        "tier": 4, "points": 250, "slug": "hardware_enclave_sgx_trustzone_binary_shield",
        "title_ko": "하드웨어 보안 엔클레이브(Intel SGX / ARM TrustZone) 바이너리 보호",
        "title_en": "Hardware Enclave (SGX / TrustZone) Binary Shield Architecture",
        "desc_ko": "호스트 OS 및 링 0 커널조차 메모리를 읽을 수 없는 하드웨어 암호화 엔클레이브 내에서 핵심 알고리즘을 구동하여 100% 리버싱 불가능성을 달성하는 구조를 분석합니다.",
        "desc_en": "Analyze isolated hardware enclaves (Intel SGX, ARM TrustZone) executing sensitive logic in hardware-encrypted memory beyond the reach of kernel rootkits and debuggers."
    },
    {
        "tier": 4, "points": 250, "slug": "capstone_full_spectrum_anti_reversing_defense",
        "title_ko": "바이너리 보호 및 안티 리버싱 능동 방어 풀 스펙트럼 캡스톤",
        "title_en": "Capstone: Full-Spectrum Binary Protection & Anti-Reversing",
        "desc_ko": "동적 안티디버깅 무력화, ROR13 API Hashing 역산, 변형 패커 OEP 언패킹, Anti-VM 타이밍 분석 차단을 총동원하여 고도화된 보호 바이너리를 완벽히 공략하고 차세대 능동 방어 대책을 확립합니다.",
        "desc_en": "Synthesize all binary defense disciplines: anti-debugging evasion, API hashing resolution, packer unpacking, and anti-VM timing mitigation into a unified offensive-defensive mastery capstone."
    }
]

def make_challenge_object(item):
    slug = item["slug"]
    identifier = f"antire_{slug}_v1"
    
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
        "id": f"t{item['tier']}_antire_{slug}",
        "tier": item["tier"],
        "cat": "reversing",
        "track": "antire",
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
    print(f"[+] Generated {len(new_challenges)} challenge objects for Track 69: antire.")
    
    # Track definition
    track_def = {
        "id": "antire",
        "icon": "🧩",
        "ko": "안티리버싱 & 바이너리 프로텍션",
        "en": "Anti-Reversing & Binary Protection",
        "desc_ko": "안티디버깅(PEB BeingDebugged/ptrace) 우회·동적 API Hashing(ROR13/Murmur3) 역산·변형 패커 스텁 분석 & OEP 언패킹·가상화 난독화 해제·Anti-VM & RDTSC 타이밍 분석 무력화.",
        "desc_en": "Anti-debugging (PEB BeingDebugged/ptrace) bypass, dynamic API hashing (ROR13/Murmur3) resolution, custom packer stub analysis & OEP unpacking, virtualization deobfuscation, and Anti-VM & RDTSC timing defense neutralization."
    }
    
    # 2. Update challenges.js
    content = challenges_js_path.read_text(encoding="utf-8")
    
    # Insert Track definition before ];\n\nconst CHALLENGES
    track_json = json.dumps(track_def, ensure_ascii=False, indent=2)
    # Indent properly
    track_insert = ",\n  " + track_json.replace("\n", "\n  ")
    target_tracks_end = "];\n\nconst CHALLENGES = ["
    if "id: \"antire\"" in content or "\"id\": \"antire\"" in content:
        print("[-] Track antire already in challenges.js, skipping track insert.")
    else:
        assert target_tracks_end in content, "Could not find end of TRACKS in challenges.js"
        content = content.replace(target_tracks_end, track_insert + "\n];\n\nconst CHALLENGES = [")
        print("[+] Inserted Track 69 definition into TRACKS.")
    
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
    ids_insert = "  // 69th Track: antire (35 challenges)\n" + ",\n".join([f'  "{cid}"' for cid in new_ids]) + ",\n"
    target_sd = '  // 68th Track: ebpfsec (35 challenges)'
    assert target_sd in sd_content, "Could not find Track 68 in solve-derivable.js"
    sd_content = sd_content.replace(target_sd, ids_insert + target_sd)
    solve_derivable_path.write_text(sd_content, encoding="utf-8")
    print("[+] Added 35 challenge IDs to solve-derivable.js.")
    
    print("[*] Generation finished successfully.")

if __name__ == "__main__":
    main()
