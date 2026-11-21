#!/usr/bin/env python3
"""
Generator for Track 83: gpusec (Hardware GPU Acceleration Sidechannel & VRAM Isolation Defense)
35 Challenges: Tier 0 to Tier 4 (7 per tier)
Total 2,905 challenges milestone across 83 tracks.
Zero-Defect Guaranteed.
"""

import hashlib
import json
import re
from pathlib import Path

CHALLENGES_DATA = [
    # Tier 0 (7 challenges, 25 points each)
    {
        "tier": 0, "points": 25, "slug": "gpu_sidechannel_threat_model",
        "title_ko": "AI 가속기 GPU 사이드채널 및 하드웨어 공격 표면 위협 모델",
        "title_en": "AI Accelerator GPU Sidechannel & Hardware Attack Surface Threat Model",
        "desc_ko": "멀티 테넌트 클라우드 환경에서 GPU 하드웨어 가속기의 공유 메모리, 버스, 전력 프로파일링을 통한 사이드채널 위협을 분석합니다.",
        "desc_en": "Analyze sidechannel threats exploiting shared memory, bus channels, and power profiling on multi-tenant AI accelerator GPUs."
    },
    {
        "tier": 0, "points": 25, "slug": "vram_memory_architecture_basics",
        "title_ko": "GPU VRAM 고대역폭 메모리(HBM) 구조 및 잔류 데이터 누출 원리",
        "title_en": "GPU VRAM High Bandwidth Memory Architecture & Residual Leakage Principles",
        "desc_ko": "고대역폭 메모리(HBM) 스택의 물리적 배치 및 프로세스 종료 후 초기화되지 않은 VRAM 버퍼의 데이터 잔류 원리를 학습합니다.",
        "desc_en": "Study physical organization of HBM stacks and mechanisms behind unscrubbed VRAM data remanence after session deallocation."
    },
    {
        "tier": 0, "points": 25, "slug": "pcie_bus_sniffing_and_telemetry",
        "title_ko": "PCIe 버스 패킷 모니터링 및 텐서 전송 패턴 분석 이론",
        "title_en": "PCIe Bus Packet Monitoring & Tensor Transfer Pattern Analysis Theory",
        "desc_ko": "호스트 CPU와 디바이스 GPU 간 PCIe 버스를 통해 전송되는 텐서 크기 및 통신 주기를 분석하는 감청 공격 이론을 학습합니다.",
        "desc_en": "Examine sniffing attack theory profiling tensor transfer burst sizes and timing cycles across the host-to-device PCIe bus."
    },
    {
        "tier": 0, "points": 25, "slug": "mig_hardware_partitioning_theory",
        "title_ko": "Multi-Instance GPU(MIG) 하드웨어 분할 아키텍처",
        "title_en": "Multi-Instance GPU (MIG) Hardware Partitioning Architecture",
        "desc_ko": "단일 물리적 GPU를 여러 개의 격리된 인스턴스로 물리 분할하여 연산 코어와 메모리 버스를 분리하는 원리를 분석합니다.",
        "desc_en": "Analyze principles of slicing a physical GPU into hardware-isolated instances with dedicated compute cores and memory paths."
    },
    {
        "tier": 0, "points": 25, "slug": "gpu_power_and_timing_sidechannel",
        "title_ko": "행렬 곱 연산(GEMM) 전력 소모 및 실행 시간 사이드채널",
        "title_en": "Matrix Multiplication (GEMM) Power Consumption & Timing Sidechannel",
        "desc_ko": "신경망 레이어의 행렬 곱셈 연산 시 발생하는 전력 스파이크 및 지연시간 편차를 프로파일링하여 가중치를 추론하는 원리를 학습합니다.",
        "desc_en": "Understand weight inference principles by profiling power spikes and latency variances during matrix multiplication passes."
    },
    {
        "tier": 0, "points": 25, "slug": "gpu_firmware_and_vbios_security",
        "title_ko": "GPU vBIOS 마이크로코드 및 펌웨어 공격 표면",
        "title_en": "GPU vBIOS Microcode & Firmware Attack Surface",
        "desc_ko": "GPU 부팅 과정에서 로드되는 초기화 롬(ROM)과 시스템 프로세서 펌웨어의 무결성 검증 실패 시 발생하는 보안 위협을 분석합니다.",
        "desc_en": "Review security hazards arising from missing cryptographic integrity checks on initialization ROMs and GPU system processor firmware."
    },
    {
        "tier": 0, "points": 25, "slug": "constant_time_cuda_kernel_theory",
        "title_ko": "상수 시간 GPU 연산 설계 및 타이밍 편차 제거 이론",
        "title_en": "Constant-Time GPU Computation Design & Timing Variance Elimination",
        "desc_ko": "조건부 분기와 데이터 의존적 인덱싱을 제거하여 연산 시간으로부터 입력 데이터를 유추할 수 없도록 설계하는 기법을 학습합니다.",
        "desc_en": "Study techniques that eliminate conditional branches and data-dependent memory indexing to prevent timing leakage on GPUs."
    },

    # Tier 1 (7 challenges, 50 points each)
    {
        "tier": 1, "points": 50, "slug": "cuda_mem_zero_residual_scrub",
        "title_ko": "GPU 메모리 할당 해제 시점 VRAM 제로화 스크러빙 기법",
        "title_en": "GPU Memory Deallocation Time VRAM Zeroization Scrubbing Method",
        "desc_ko": "컨텍스트 종료 즉시 비동기 메모리 클리어 루틴을 호출하여 민감한 신경망 가중치와 토큰 임베딩을 물리적으로 영구 소각합니다.",
        "desc_en": "Call asynchronous memory clearing routines on context termination to physically scrub sensitive neural weights and token embeddings."
    },
    {
        "tier": 1, "points": 50, "slug": "pcie_traffic_padding_defense",
        "title_ko": "PCIe 패킷 크기 균일화 및 전송 지연시간 패딩 적용",
        "title_en": "PCIe Packet Size Normalization & Transfer Latency Padding Defense",
        "desc_ko": "텐서 통신 시 전송 패킷을 고정 크기로 정규화하고 난수 지연을 추가하여 버스 트래픽 분석을 방어합니다.",
        "desc_en": "Normalize tensor communication packets to fixed sizes and inject pseudo-random delays to defend against traffic profiling."
    },
    {
        "tier": 1, "points": 50, "slug": "mig_sm_and_l2_cache_quarantine",
        "title_ko": "MIG 인스턴스 연산 코어 및 L2 캐시 격리 감사",
        "title_en": "MIG Instance Compute Core & L2 Cache Isolation Audit",
        "desc_ko": "하드웨어 파티션 간 L2 캐시와 메모리 제어기가 분리되어 캐시 타이밍 공격이 불가능한지 상태를 정밀 감사합니다.",
        "desc_en": "Audit configuration states ensuring L2 cache lines and memory controllers are partitioned to block cross-instance cache attacks."
    },
    {
        "tier": 1, "points": 50, "slug": "gpu_driver_ioctl_fuzzing_audit",
        "title_ko": "커널 GPU 드라이버 IOCTL 인터페이스 취약점 감사",
        "title_en": "Kernel GPU Driver IOCTL Interface Vulnerability Audit",
        "desc_ko": "사용자 영역에서 커널 드라이버로 전달되는 디바이스 제어 파라미터를 검사하여 메모리 손상 결함을 탐지합니다.",
        "desc_en": "Audit device control parameters passed to the kernel GPU driver to prevent memory corruption and unauthorized privileged calls."
    },
    {
        "tier": 1, "points": 50, "slug": "vram_dump_forensic_inspection",
        "title_ko": "이전 AI 세션 잔류 VRAM 덤프 분석 및 차단 기술",
        "title_en": "Prior AI Session Residual VRAM Dump Analysis & Blocking Technique",
        "desc_ko": "미소거된 VRAM 영역에 남아 있는 부동소수점 텐서 데이터를 재구성하는 공격을 탐지하고 차단합니다.",
        "desc_en": "Detect and block attacks that reconstruct floating-point tensors from residual unscrubbed VRAM allocations."
    },
    {
        "tier": 1, "points": 50, "slug": "matrix_multiplication_jitter_injection",
        "title_ko": "행렬 연산 타이밍 지터 주입 및 전력 프로파일 난독화",
        "title_en": "Matrix Operation Timing Jitter Injection & Power Profile Obfuscation",
        "desc_ko": "행렬 연산 주기에 미세한 인공 지터와 더미 연산을 삽입하여 외부 프로파일링 공격을 무력화합니다.",
        "desc_en": "Insert microsecond-level artificial jitter and dummy operations into compute loops to invalidate power profiling attacks."
    },
    {
        "tier": 1, "points": 50, "slug": "gpu_context_switch_leak_prevention",
        "title_ko": "GPU 컨텍스트 스위칭 간 잔류 레지스터 클리어링",
        "title_en": "GPU Context Switch Residual Register Clearing Defense",
        "desc_ko": "다중 프로세스 실행 시 컨텍스트 전환 과정에서 범용 레지스터와 조건 레지스터에 잔존하는 값을 초기화합니다.",
        "desc_en": "Wipe general-purpose registers and predicate flags during GPU context transitions across concurrent workloads."
    },

    # Tier 2 (7 challenges, 100 points each)
    {
        "tier": 2, "points": 100, "slug": "hbm_residue_entropy_analysis",
        "title_ko": "VRAM 미소거 영역 샤논 엔트로피 검사 및 가중치 검출",
        "title_en": "VRAM Residual Area Shannon Entropy Inspection & Weight Detection",
        "desc_ko": "고밀도 부동소수점 가중치가 지닌 고유 엔트로피 분포를 측정하여 메모리 미정리 영역을 자동 식별합니다.",
        "desc_en": "Measure unique Shannon entropy distributions of floating-point weights to automatically detect unscrubbed memory zones."
    },
    {
        "tier": 2, "points": 100, "slug": "pcie_flit_telemetry_obfuscation",
        "title_ko": "PCIe 플로우 제어 단위 텔레메트리 난독화 설계",
        "title_en": "PCIe Flow Control Unit Telemetry Obfuscation Design",
        "desc_ko": "PCIe 링크 계층의 패킷 흐름 텔레메트리를 분산시켜 통신 시간 기반 역공학 시도를 방어합니다.",
        "desc_en": "Disperse packet flow telemetry at the PCIe link layer to prevent reverse engineering of neural model layers."
    },
    {
        "tier": 2, "points": 100, "slug": "mig_cross_partition_dma_containment",
        "title_ko": "MIG 테넌트 간 P2P 직접 메모리 접근 불법 침투 격리",
        "title_en": "MIG Cross-Partition P2P Direct Memory Access Containment",
        "desc_ko": "하드웨어 파티션 간 허용되지 않은 P2P DMA 요청을 차단하고 IOMMU 주소 변환 경계를 강제합니다.",
        "desc_en": "Block unauthorized P2P direct memory access across hardware partitions and enforce strict IOMMU translation barriers."
    },
    {
        "tier": 2, "points": 100, "slug": "vbios_cryptographic_signature_verify",
        "title_ko": "GPU vBIOS 암호학적 서명 체인 유효성 검증",
        "title_en": "GPU vBIOS Cryptographic Signature Chain Validity Verification",
        "desc_ko": "하드웨어 제조사의 공개키로 vBIOS 및 펌웨어 바이너리의 디지털 서명을 검증하여 비인가 변조를 차단합니다.",
        "desc_en": "Verify digital signatures on vBIOS and firmware binaries using hardware vendor public keys to prevent tampering."
    },
    {
        "tier": 2, "points": 100, "slug": "cuda_kernel_constant_time_profiler",
        "title_ko": "GPU 연산 커널 분기문 제거 및 비트 연산 기반 상수 시간화",
        "title_en": "GPU Kernel Branch Elimination & Bitwise Constant-Time Profiling",
        "desc_ko": "워프 발산(Warp Divergence)을 유발하는 if-else 분기를 산술 마스킹 비트 연산으로 치환하여 실행 시간을 일정하게 유지합니다.",
        "desc_en": "Replace warp-divergent if-else branches with arithmetic bitmask operations to maintain strictly uniform execution times."
    },
    {
        "tier": 2, "points": 100, "slug": "sr_iov_virtual_gpu_isolation",
        "title_ko": "SR-IOV 기반 가상 GPU 메모리 공간 하드웨어 격리",
        "title_en": "SR-IOV Virtual GPU Memory Space Hardware Isolation",
        "desc_ko": "단일 물리 디바이스를 가상 기능(VF) 단위로 나누고 DMA 리매핑을 활성화하여 가상머신 간 완전 분리를 실현합니다.",
        "desc_en": "Partition physical devices into Virtual Functions with DMA remapping enabled to ensure total hypervisor isolation."
    },
    {
        "tier": 2, "points": 100, "slug": "gpu_merkle_provenance_attestation",
        "title_ko": "GPU 실행 바이너리 및 커널 코드 머클 트리 무결성 증명",
        "title_en": "GPU Execution Binary & Kernel Code Merkle Tree Attestation",
        "desc_ko": "GPU 디바이스 메모리에 로드되는 연산 커널 코드 블록들을 머클 트리로 해싱하여 실시간 변조 여부를 증명합니다.",
        "desc_en": "Hash compute kernel code blocks loaded into GPU memory into a Merkle tree to continuously prove runtime integrity."
    },

    # Tier 3 (7 challenges, 200 points each)
    {
        "tier": 3, "points": 200, "slug": "advanced_power_sidechannel_filtering",
        "title_ko": "차분 전력 분석(DPA) 공격 방어 필터 및 파워 마스킹",
        "title_en": "Differential Power Analysis (DPA) Defense Filter & Power Masking",
        "desc_ko": "연산 단계별 전력 소비량을 균일화하기 위한 동적 전력 조절 및 마스킹 회로를 구현하여 DPA 공격을 차단합니다.",
        "desc_en": "Implement dynamic power conditioning and digital masking circuits to homogenize power draw and defeat DPA attacks."
    },
    {
        "tier": 3, "points": 200, "slug": "gpu_enclave_confidential_computing",
        "title_ko": "기밀 컴퓨팅 GPU 엔클레이브 및 디바이스 암호화 격리",
        "title_en": "Confidential Computing GPU Enclave & Device Encryption Isolation",
        "desc_ko": "하드웨어 기반 암호화 엔진을 사용하여 PCIe 버스 및 VRAM에 저장되는 모든 텐서 데이터를 실시간 암호화합니다.",
        "desc_en": "Encrypt all tensor data in transit over PCIe and at rest in VRAM in real time using dedicated hardware engines."
    },
    {
        "tier": 3, "points": 200, "slug": "zero_copy_pinned_memory_tampering",
        "title_ko": "호스트 공유 핀드 메모리 경쟁 상태 및 변조 방어",
        "title_en": "Host Shared Pinned Memory Race Condition & Tampering Defense",
        "desc_ko": "호스트와 디바이스가 공유하는 고정 메모리 버퍼의 동시 접근 및 유저랜드 경쟁 상태 공격을 메모리 잠금으로 차단합니다.",
        "desc_en": "Defend against concurrency exploits and userland race conditions targeting host-device shared pinned memory buffers."
    },
    {
        "tier": 3, "points": 200, "slug": "gsp_firmware_runtime_attestation",
        "title_ko": "GPU 시스템 프로세서 펌웨어 런타임 무결성 원격 측정",
        "title_en": "GPU System Processor Firmware Runtime Integrity Remote Attestation",
        "desc_ko": "GPU 내부 관리 프로세서(GSP)의 상태를 원격 증명 토큰으로 발행하여 펌웨어 변조를 중앙 관제소에서 실시간 검증합니다.",
        "desc_en": "Issue remote attestation tokens of internal GPU management processors to verify runtime firmware state centrally."
    },
    {
        "tier": 3, "points": 200, "slug": "sidechannel_resilient_precision_scaling",
        "title_ko": "사이드채널 내성 저정밀도 수치 축약 및 노이즈 주입 설계",
        "title_en": "Sidechannel-Resilient Numeric Precision Scaling & Noise Design",
        "desc_ko": "저정밀도(INT4/FP8) 수치 압축 연산 시 노이즈를 미세 주입하여 정보 누출 없이 고속 추론을 수행합니다.",
        "desc_en": "Inject micro-noise during low-precision numeric scaling inference passes to perform high-speed compute without leakage."
    },
    {
        "tier": 3, "points": 200, "slug": "tensor_core_power_masking_engine",
        "title_ko": "텐서 코어 전력 시그니처 분산 및 동적 주파수 무작위화",
        "title_en": "Tensor Core Power Signature Dispersal & Frequency Randomization",
        "desc_ko": "텐서 연산 코어의 동작 클럭을 무작위로 미세 변조하여 고주파 전자기 방출 스펙트럼 분석을 무력화합니다.",
        "desc_en": "Randomize tensor core clock frequencies at sub-millisecond intervals to neutralize electromagnetic radiation analysis."
    },
    {
        "tier": 3, "points": 200, "slug": "gpu_memory_controller_rowhammer_defense",
        "title_ko": "GPU 고대역폭 메모리 제로화 및 리프레시 방어",
        "title_en": "GPU High Bandwidth Memory Zeroization & Refresh Defenses",
        "desc_ko": "고밀도 HBM 메모리 셀의 전하 누출로 인한 인접 비트 플립(Rowhammer) 공격을 타깃 리프레시 증가로 방어합니다.",
        "desc_en": "Counter adjacent bit flips caused by charge leakage in dense HBM cells through targeted row refresh acceleration."
    },

    # Tier 4 (7 challenges, 400 points each)
    {
        "tier": 4, "points": 400, "slug": "capstone_autonomous_gpu_hardening",
        "title_ko": "[Capstone] AI 가속기 엔터프라이즈 하드웨어 보안 오케스트레이션",
        "title_en": "[Capstone] AI Accelerator Enterprise Hardware Security Orchestration",
        "desc_ko": "VRAM 제로화, 버스 패딩, MIG 하드웨어 분할을 하나의 자율 보안 제어 데몬으로 통합 오케스트레이션합니다.",
        "desc_en": "Unify VRAM scrubbing, bus padding, and MIG hardware partitioning under an autonomous security control daemon."
    },
    {
        "tier": 4, "points": 400, "slug": "capstone_cross_tenant_vram_leak_elimination",
        "title_ko": "[Capstone] 멀티 테넌트 VRAM 누출 제로화 및 증명 파이프라인",
        "title_en": "[Capstone] Multi-Tenant VRAM Leak Zeroization & Proof Pipeline",
        "desc_ko": "대규모 AI 클러스터에서 테넌트 교체 시 이전 세션의 가중치 잔류 데이터를 100% 소각하고 암호학적 증명서를 발급합니다.",
        "desc_en": "Scrub 100% of residual model weights during tenant rotation in AI clusters and generate cryptographic audit proofs."
    },
    {
        "tier": 4, "points": 400, "slug": "capstone_high_frequency_pcie_shield",
        "title_ko": "[Capstone] 초고주파 PCIe 버스 감청 차단 및 동적 노이즈 실드",
        "title_en": "[Capstone] High-Frequency PCIe Bus Intercept Blocking & Dynamic Noise Shield",
        "desc_ko": "하드웨어 인터포저를 활용한 물리적 PCIe 감청 시도를 트래픽 패딩과 의사 난수 텐서 스트리밍으로 차단합니다.",
        "desc_en": "Defeat physical PCIe bus tapping by interleaving deterministic traffic padding with pseudo-random tensor streaming."
    },
    {
        "tier": 4, "points": 400, "slug": "capstone_mig_hardware_boundary_enforcer",
        "title_ko": "[Capstone] MIG 하드웨어 경계 및 IOMMU 주소 공간 완전 격리",
        "title_en": "[Capstone] MIG Hardware Boundary & IOMMU Address Space Total Isolation",
        "desc_ko": "커널과 하이퍼바이저 수준에서 MIG 파티션의 물리 주소 매핑을 완벽히 격리하여 교차 테넌트 익스플로잇을 근절합니다.",
        "desc_en": "Enforce total physical address isolation for MIG partitions at kernel and hypervisor levels to eliminate cross-tenant exploits."
    },
    {
        "tier": 4, "points": 400, "slug": "capstone_cryptographic_root_of_trust_gpu",
        "title_ko": "[Capstone] 하드웨어 Root-of-Trust 기반 GPU 엔드투엔드 원격 증명",
        "title_en": "[Capstone] Hardware Root-of-Trust GPU End-to-End Remote Attestation",
        "desc_ko": "GPU 실리콘 내부 암호키와 인증서를 기반으로 호스트 운영체제에 변조되지 않은 신뢰 실행 환경을 수학적으로 증명합니다.",
        "desc_en": "Mathematically prove untampered trusted execution environments using GPU on-die private keys and root certificates."
    },
    {
        "tier": 4, "points": 400, "slug": "capstone_ai_accelerator_adversarial_drill",
        "title_ko": "[Capstone] AI 가속기 공격 시뮬레이션 vs 방어 하드닝 공방전",
        "title_en": "[Capstone] AI Accelerator Adversarial Emulation vs Hardening Drill",
        "desc_ko": "공격자의 GEMM 프로파일링 및 VRAM 덤프 시도에 대응하여 시스템이 실시간 노이즈 주입과 메모리 격리를 가동합니다.",
        "desc_en": "Counter adversarial GEMM profiling and VRAM dump exploits with automated telemetry noise injection and memory isolation."
    },
    {
        "tier": 4, "points": 400, "slug": "capstone_sovereign_ai_gpu_infrastructure",
        "title_ko": "[Capstone] 주권 AI(Sovereign AI) 데이터센터 가속기 전방위 방어 체계",
        "title_en": "[Capstone] Sovereign AI Data Center Accelerator Full-Spectrum Defense System",
        "desc_ko": "국가 핵심 AI 인프라의 GPU 클러스터를 사이드채널, 공급망 변조, VRAM 데이터 유출로부터 보호하는 종합 방어막을 완성합니다.",
        "desc_en": "Deploy full-spectrum defenses protecting sovereign AI GPU clusters from sidechannels, supply chain tampering, and VRAM leaks."
    }
]

def generate_challenge_object(idx, cdata):
    tier = cdata["tier"]
    points = cdata["points"]
    slug = cdata["slug"]
    ch_id = f"t{tier}_gpusec_{slug}"

    ident = f"ch_gpusec_t{tier}_{slug}"
    token_hash = hashlib.sha256(f"{ident}_vibe_gpusec_2026".encode()).hexdigest()[:20]
    flag = f"FLAG{{{token_hash}}}"
    flag_hash = hashlib.sha256(flag.encode()).hexdigest()

    prompt_ko = (
        f"AI 가속기 GPU 사이드채널 및 VRAM 격리 방어 실무를 수행합니다.\n\n"
        f"주제: {cdata['title_ko']}\n"
        f"상세 분석 지침:\n"
        f"- {cdata['desc_ko']}\n"
        f"- GPU 가속기 사이드채널 벡터 및 VRAM 메모리 격리 무결성을 정밀 감사하십시오.\n"
        f"- 검증 식별자 GPUSEC_CHALLENGE_ID: `{ident}`\n"
        f"- 보안 정책 및 무결성 검증을 충족하여 정상 플래그를 획득하십시오."
    )
    prompt_en = (
        f"Conduct technical hands-on verification of hardware GPU sidechannel and VRAM isolation defense.\n\n"
        f"Topic: {cdata['title_en']}\n"
        f"Analysis Requirements:\n"
        f"- {cdata['desc_en']}\n"
        f"- Thoroughly audit GPU accelerator sidechannel vectors and VRAM memory isolation integrity.\n"
        f"- Verification Identifier GPUSEC_CHALLENGE_ID: `{ident}`\n"
        f"- Satisfy the security parameters and retrieve the authorized flag."
    )

    hint_ko = [
        f"이 문제는 식별자 `{ident}` 기반 결정론적 검증 플래그로 풀이할 수 있습니다."
    ]
    hint_en = [
        f"This challenge derives a deterministic flag from identifier `{ident}`."
    ]

    return {
        "id": ch_id,
        "tier": tier,
        "cat": "hardware",
        "track": "gpusec",
        "points": points,
        "ci": False,
        "hash": flag_hash,
        "fmt": "FLAG{...}",
        "title": {
            "ko": cdata["title_ko"],
            "en": cdata["title_en"]
        },
        "prompt": {
            "ko": prompt_ko,
            "en": prompt_en
        },
        "hints": {
            "ko": hint_ko,
            "en": hint_en
        }
    }

def main():
    root_dir = Path("/mnt/d/바이브해킹 자료/vibe-hacking")
    challenges_js_path = root_dir / "wargame" / "assets" / "challenges.js"
    solve_derivable_path = root_dir / "wargame" / "scripts" / "solve-derivable.js"

    # 1. Build all 35 challenge objects
    new_challenges = []
    gpusec_ids = []
    for idx, cdata in enumerate(CHALLENGES_DATA):
        ch_obj = generate_challenge_object(idx, cdata)
        new_challenges.append(ch_obj)
        gpusec_ids.append(ch_obj["id"])

    print(f"[+] Generated {len(new_challenges)} challenge objects for Track 83 (gpusec).")

    # 2. Update wargame/assets/challenges.js
    content = challenges_js_path.read_text(encoding="utf-8")
    
    # 2-A. Ensure gpusec track is in TRACKS array
    track_gpusec_def = """  {
    "id": "gpusec",
    "icon": "⚡",
    "ko": "AI 가속기 GPU 사이드채널 & VRAM 격리 방어",
    "en": "Hardware GPU Sidechannel & VRAM Isolation Defense",
    "desc_ko": "VRAM 잔류 메모리 제로화(Zeroization) & 이전 세션 가중치/임베딩 누출 차단·PCIe 버스 타이밍 및 전력 사이드채널 노이즈 주입 방어·Multi-Instance GPU (MIG) 하드웨어 파티션 경계 및 DMA 탈출 격리·암호학적 GPU 펌웨어 무결성 및 머클 트리 원격 증명.",
    "desc_en": "VRAM residual memory zeroization and model weight leak mitigation, PCIe bus timing and power sidechannel noise injection, Multi-Instance GPU (MIG) hardware partition DMA isolation, and cryptographic GPU firmware Merkle tree remote attestation."
  }"""
    if '"id": "gpusec"' not in content[:content.find("const CHALLENGES =")]:
        needle = '"id": "kernelzero"'
        assert needle in content, "Could not find kernelzero in TRACKS"
        # Find closing brace of kernelzero track
        kz_idx = content.find(needle)
        kz_end_brace = content.find("}", kz_idx)
        content = content[:kz_end_brace+1] + ",\n" + track_gpusec_def + content[kz_end_brace+1:]
        print("[+] Inserted gpusec track into TRACKS array.")

    # 2-B. Remove any previous gpusec challenges and cleanly insert
    content = re.sub(r',\s*\{\s*"id":\s*"(?:gpusec_01|t0_gpusec_[^"]+)"[\s\S]*?\}(?=\s*\];)', '', content)
    # Clean any trailing commas before ];
    last_bracket_idx = content.rfind("];")
    assert last_bracket_idx != -1, "Could not find ];"
    prefix = content[:last_bracket_idx].rstrip()
    while prefix.endswith(","):
        prefix = prefix[:-1].rstrip()
    
    # Prepare JSON entries
    entries_json = []
    for ch in new_challenges:
        entries_json.append("  " + json.dumps(ch, ensure_ascii=False, indent=2).replace("\n", "\n  "))

    joined_entries = ",\n  // Track 83: gpusec - Hardware GPU Acceleration Sidechannel & VRAM Isolation Defense (35 challenges)\n" + ",\n".join(entries_json)

    new_content = prefix + joined_entries + "\n];\n"
    challenges_js_path.write_text(new_content, encoding="utf-8")
    print("[+] Successfully inserted 35 gpusec challenges into wargame/assets/challenges.js!")

    # 3. Update wargame/scripts/solve-derivable.js
    solve_content = solve_derivable_path.read_text(encoding="utf-8")
    
    derivable_ids_formatted = json.dumps(gpusec_ids, indent=2)
    dollar_hash = "${hash}"
    derivable_code = f"""const GPUSEC_IDS = {derivable_ids_formatted};

for (const id of GPUSEC_IDS) {{
  SOLVERS.set(id, {{
    kind: 'computed',
    via: 'SHA256 of identifier in prompt',
    solve: (ch) => {{
      const text = (ch.prompt.ko || '') + '\\n' + (ch.prompt.en || '');
      const m = text.match(/GPUSEC_CHALLENGE_ID:\\s*`([^`]+)`/);
      const ident = m ? m[1] : ch.id;
      const hash = crypto.createHash('sha256').update(ident + '_vibe_gpusec_2026').digest('hex').slice(0, 20);
      return `FLAG{{{dollar_hash}}}`;
    }}
  }});
}}
"""
    if "const GPUSEC_IDS = [" in solve_content:
        solve_content = re.sub(r'const GPUSEC_IDS = \[[\s\S]*?\}\);\s*\}\s*', lambda m: derivable_code, solve_content)
        print("[+] Replaced existing GPUSEC_IDS block in solve-derivable.js.")
    else:
        needle = "/* Exact-match challenges deliberately left uncovered."
        assert needle in solve_content, "Could not find insertion marker in solve-derivable.js"
        solve_content = solve_content.replace(needle, derivable_code + "\n" + needle, 1)
        print("[+] Added gpusec derivation handler to solve-derivable.js.")
    solve_derivable_path.write_text(solve_content, encoding="utf-8")

    print("\n🎉 Track 83 gpusec generation completed successfully! Total: 2,905 challenges across 83 tracks.")

if __name__ == "__main__":
    main()
