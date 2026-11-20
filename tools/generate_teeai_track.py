#!/usr/bin/env python3
"""
Generator for Track 79: teeai (Confidential AI & Hardware TEE Enclave Attestation)
35 Challenges: Tier 0 to Tier 4 (7 per tier)
Total 2,765 challenges milestone across 79 tracks.
Zero-Defect Guaranteed.
"""

import hashlib
import json
import re
from pathlib import Path

CHALLENGES_DATA = [
    # Tier 0 (7 challenges, 25 points each)
    {
        "tier": 0, "points": 25, "slug": "confidential_computing_threat_model",
        "title_ko": "신뢰할 수 없는 클라우드 하이퍼바이저와 기밀 컴퓨팅 위협 모델",
        "title_en": "Untrusted Cloud Hypervisor & Confidential Computing Threat Model",
        "desc_ko": "클라우드 서비스 제공자(CSP) 및 악의적 호스트 관리자가 가상머신 메모리를 직접 스누핑하는 위협에 대응하는 TEE 위협 모델을 분석합니다.",
        "desc_en": "Analyze the confidential computing threat model defending against untrusted cloud providers and host hypervisors inspecting VM memory."
    },
    {
        "tier": 0, "points": 25, "slug": "hardware_tee_snp_tdx_architecture",
        "title_ko": "AMD SEV-SNP 및 Intel TDX 하드웨어 TEE 격리 아키텍처",
        "title_en": "Hardware TEE Isolation Architecture: AMD SEV-SNP vs Intel TDX",
        "desc_ko": "CPU 하드웨어 레벨에서 게스트 메모리를 암호화하고 하이퍼바이저 접근을 차단하는 RMP(Reverse Map Table)와 Secure EPT 구조를 학습합니다.",
        "desc_en": "Study CPU hardware mechanisms including Reverse Map Tables (RMP) and Secure EPT segregating guest memory from host hypervisors."
    },
    {
        "tier": 0, "points": 25, "slug": "remote_attestation_pcr0_measurement",
        "title_ko": "원격 증명(Remote Attestation)과 PCR0 부팅 측정치 무결성 원리",
        "title_en": "Remote Attestation Principles & PCR0 Boot Measurement Integrity",
        "desc_ko": "엔클레이브 초기 부팅 펌웨어 및 커널 이미지의 SHA-256 해시를 하드웨어 루트 키로 서명하여 검증하는 원격 증명 체계를 검토합니다.",
        "desc_en": "Examine remote attestation pipelines validating SHA-256 launch measurement hashes (PCR0) signed by CPU hardware root keys."
    },
    {
        "tier": 0, "points": 25, "slug": "in_enclave_model_weights_protection",
        "title_ko": "기밀 AI 추론 런타임 내 모델 가중치 암호화 보호 모델",
        "title_en": "In-Enclave Model Weight Encryption & Protection Architecture",
        "desc_ko": "수십억 개 파라미터의 독점 LLM 가중치가 호스트 메모리나 스왑 영역에 평문으로 노출되지 않도록 엔클레이브 내에서만 해독하는 구조를 이해합니다.",
        "desc_en": "Understand in-enclave LLM weight decryption ensuring proprietary multi-billion parameter model weights never leak into host swap or DRAM."
    },
    {
        "tier": 0, "points": 25, "slug": "side_channel_microarchitectural_threats",
        "title_ko": "마이크로아키텍처 캐시 타이밍 부채널과 정보 누출 위협",
        "title_en": "Microarchitectural Cache Timing Side-Channels & Leakage Threat Surface",
        "desc_ko": "TEE 메모리가 암호화되어 있더라도 CPU 공유 캐시(LLC) 적중/실패 시간차로 추론 입력 및 가중치를 복원하는 부채널 원리를 분석합니다.",
        "desc_en": "Analyze side-channel vectors where shared CPU cache access latency leaks model activations despite full hardware memory encryption."
    },
    {
        "tier": 0, "points": 25, "slug": "tpm_aik_root_of_trust_governance",
        "title_ko": "하드웨어 TPM AIK 및 신뢰점(Root of Trust) 거버넌스 원칙",
        "title_en": "Hardware TPM AIK Endorsement & Root of Trust Governance Principles",
        "desc_ko": "가상 TPM(vTPM) 및 물리 엔도스먼트 키(EK)를 기반으로 증명 식별 키(AIK)를 발급하여 위변조 불가능한 인증 체계를 확립하는 원칙을 학습합니다.",
        "desc_en": "Study Attestation Identity Key (AIK) issuance bound to hardware TPM Endorsement Keys establishing tamper-proof trust chains."
    },
    {
        "tier": 0, "points": 25, "slug": "confidential_federated_learning_model",
        "title_ko": "기밀 연합 학습(Confidential Federated Learning)과 다자간 컴퓨팅",
        "title_en": "Confidential Federated Learning & Multi-Party Privacy-Preserving AI",
        "desc_ko": "의료 및 금융 기관 간 민감 데이터셋을 공유하지 않고 TEE 엔클레이브 내에서만 가중치를 집계하는 기밀 AI 협업 설계를 검토합니다.",
        "desc_en": "Review confidential federated learning workflows where multiple participants aggregate gradients inside TEEs without data sharing."
    },

    # Tier 1 (7 challenges, 50 points each)
    {
        "tier": 1, "points": 50, "slug": "sev_snp_vcek_certificate_chain_audit",
        "title_ko": "AMD SEV-SNP VCEK 인증서 체인 무결성 및 CRL 폐기 감사",
        "title_en": "AMD SEV-SNP VCEK Certificate Chain Integrity & CRL Revocation Audit",
        "desc_ko": "AMD KDS 서버에서 제공하는 VCEK(Versioned Chip Endorsement Key) 인증서 체인을 검증하고 폐기 목록을 확인하여 위조 증명을 차단합니다.",
        "desc_en": "Validate the AMD VCEK certificate chain against AMD KDS root certs and CRLs to prevent forged hypervisor attestation quotes."
    },
    {
        "tier": 1, "points": 50, "slug": "tdx_quote_generation_sgx_ql_bridge",
        "title_ko": "Intel TDX Quote 생성 및 SGX QL 브리지 유효성 검증",
        "title_en": "Intel TDX Quote Generation & SGX QL Bridge Attestation Verification",
        "desc_ko": "Intel TDX 게스트 드라이버(/dev/tdx_guest)를 통해 Quote를 획득하고 Quote Verification Enclave(QVE)를 통해 서명을 정밀 검증합니다.",
        "desc_en": "Retrieve hardware TDX quotes via /dev/tdx_guest and verify signatures using Intel Quote Verification Enclave (QVE)."
    },
    {
        "tier": 1, "points": 50, "slug": "aes_256_xts_memory_encryption_audit",
        "title_ko": "CPU 하드웨어 AES-256-XTS 메모리 암호화 상태 및 TCB 감사",
        "title_en": "CPU Hardware AES-256-XTS Memory Encryption & TCB Version Audit",
        "desc_ko": "MSR 레지스터 및 커널 텔레메트리를 조사하여 메모리 버스 암호화가 AES-256-XTS로 활성화되어 있는지 확인하고 TCB 버전을 검증합니다.",
        "desc_en": "Audit CPU MSR registers and boot telemetry to verify AES-256-XTS memory encryption is actively enforced across guest DRAM."
    },
    {
        "tier": 1, "points": 50, "slug": "encrypted_weight_blob_kdf_decryption",
        "title_ko": "TEE 엔클레이브 내부 KDF 유도 키를 통한 가중치 블롭 안전 복호화",
        "title_en": "Secure Model Weight Blob Decryption via In-Enclave KDF Derived Keys",
        "desc_ko": "원격 증명 성공 후 키 브로커 서비스(KBS)로부터 전달받은 비밀키로 엔클레이브 힙 내에서만 가중치 텐서를 복호화합니다.",
        "desc_en": "Decrypt model weight blobs inside enclave heap using ephemeral session keys negotiated with a Key Broker Service (KBS)."
    },
    {
        "tier": 1, "points": 50, "slug": "cache_invalidation_instruction_recon",
        "title_ko": "캐시 무효화 명령어 기반 타이밍 부채널 정찰 및 탐지",
        "title_en": "Reconnaissance & Detection of Cache Invalidation Timing Probes",
        "desc_ko": "하이퍼바이저 또는 악의적 프로세스가 캐시 무효화 명령어를 반복 호출하여 특정 메모리 라인을 비우는 패턴을 모니터링합니다.",
        "desc_en": "Monitor and identify repetitive cache invalidation instruction executions designed to empty targeted memory lines for timing probes."
    },
    {
        "tier": 1, "points": 50, "slug": "signed_inference_token_tpm_verification",
        "title_ko": "TPM AIK 기반 서명된 추론 토큰(Inference Token) 검증",
        "title_en": "Verification of TPM AIK Cryptographically Signed Inference Tokens",
        "desc_ko": "클라이언트가 수신한 모델 추론 응답에 첨부된 TPM AIK 전자서명을 검증하여 중간자 위변조 없이 TEE에서 생성되었음을 증명합니다.",
        "desc_en": "Validate cryptographic signatures on inference response tokens ensuring untampered execution inside the hardware enclave."
    },
    {
        "tier": 1, "points": 50, "slug": "vtpm_measurement_replay_attack_denial",
        "title_ko": "논스(Nonce) 기반 vTPM 측정치 재생 공격(Replay Attack) 방어",
        "title_en": "Defending Against vTPM Attestation Replay Attacks via Cryptographic Nonces",
        "desc_ko": "원격 증명 챌린지 시 클라이언트가 제공한 256비트 암호학적 난수(Nonce)가 서명된 Quote에 포함되어 있는지 확인하여 재생을 차단합니다.",
        "desc_en": "Enforce client-supplied 256-bit cryptographic nonces inside attestation quotes to prevent replay of historic valid quotes."
    },

    # Tier 2 (7 challenges, 100 points each)
    {
        "tier": 2, "points": 100, "slug": "flush_reload_side_channel_mitigation",
        "title_ko": "Flush+Reload 마이크로아키텍처 공격 차단 및 페이지 테이블 격리",
        "title_en": "Flush+Reload Side-Channel Mitigation & Kernel Page Table Isolation",
        "desc_ko": "공유 바이너리 코드 세그먼트 메모리 매핑을 격리하고 메모리 중복 제거(KSM)를 비활성화하여 Flush+Reload 프로브를 원천 무력화합니다.",
        "desc_en": "Disable Kernel Samepage Merging (KSM) and isolate shared binary code page mappings to defeat Flush+Reload timing probes."
    },
    {
        "tier": 2, "points": 100, "slug": "prime_probe_llc_cache_contention_sentinel",
        "title_ko": "LLC Prime+Probe 캐시 경합 모니터링 및 비정상 접근 탐지 센티널",
        "title_en": "LLC Prime+Probe Cache Contention Monitoring & Anomaly Detection Sentinel",
        "desc_ko": "성능 모니터링 카운터(PMC)를 통해 LLC(Last-Level Cache) 미스율 급증 및 경합 이상 징후를 감지하여 부채널 정찰을 즉각 차단합니다.",
        "desc_en": "Deploy Performance Monitoring Counters (PMC) tracking anomalous LLC miss spikes indicative of Prime+Probe cache surveillance."
    },
    {
        "tier": 2, "points": 100, "slug": "hypervisor_page_fault_side_channel_defense",
        "title_ko": "하이퍼바이저 제로스텝 페이지 폴트(Zero-Step Page Fault) 추적 방어",
        "title_en": "Defending Against Hypervisor Zero-Step Page Fault Stepping Attacks",
        "desc_ko": "호스트가 게스트 페이지 테이블에 비접근 플래그를 주입하여 명령어 단위 페이지 폴트를 유발하는 단일 스텝 추적 공격을 방어합니다.",
        "desc_en": "Mitigate single-stepping hypervisor attacks that manipulate page table present bits to trace execution flow via page faults."
    },
    {
        "tier": 2, "points": 100, "slug": "secure_key_exchange_ecdh_kdf_enclave",
        "title_ko": "엔클레이브-클라이언트 간 종단간 ECDH Ephemeral 키 교환",
        "title_en": "End-to-End ECDH Ephemeral Key Exchange Between Client and Enclave",
        "desc_ko": "호스트 메모리를 경유하는 모든 입출력 페이로드를 클라이언트와 엔클레이브 간 직접 협상된 X25519 공유키로 암호화합니다.",
        "desc_en": "Establish X25519 ECDH encrypted communication channels directly between client and enclave bypassing the host hypervisor."
    },
    {
        "tier": 2, "points": 100, "slug": "confidential_gpu_nv_hopper_attestation",
        "title_ko": "NVIDIA Hopper H100 기밀 GPU PCIe SPDM 원격 증명 검증",
        "title_en": "NVIDIA Hopper H100 Confidential GPU PCIe SPDM Remote Attestation",
        "desc_ko": "PCIe Gen5 링크 상에서 CPU TEE와 H100 GPU 간 SPDM(Security Protocol and Data Model) 상호 증명 및 하드웨어 암호화 터널을 수립합니다.",
        "desc_en": "Verify PCIe SPDM attestation and establish encrypted bounce-buffer links between CPU TEE and NVIDIA Hopper confidential GPUs."
    },
    {
        "tier": 2, "points": 100, "slug": "unencrypted_dram_weight_dump_barrier",
        "title_ko": "호스트 DRAM 직접 메모리 접근(DMA) 및 가중치 덤프 원천 차단",
        "title_en": "Host DRAM Direct Memory Access (DMA) & Model Weight Dump Prevention",
        "desc_ko": "IOMMU DMA 보호 및 AMD SEV Secure Nested Paging(SNP) RMP를 활성화하여 호스트 PCI 디바이스의 무단 읽기를 하드웨어적으로 거부합니다.",
        "desc_en": "Enforce IOMMU DMA protection and SEV-SNP RMP tables preventing malicious PCI devices from dumping enclave physical pages."
    },
    {
        "tier": 2, "points": 100, "slug": "tamper_proof_audit_ledger_tee_signing",
        "title_ko": "엔클레이브 내부 불변 감사 로그 생성 및 SHA-256 머클 트리 봉인",
        "title_en": "In-Enclave Immutable Audit Logging Sealed via SHA-256 Merkle Trees",
        "desc_ko": "모든 모델 추론 및 도구 호출 이력을 엔클레이브 내에서 머클 트리 구조로 해시 체이닝하고 주기적으로 TPM 서명으로 공증합니다.",
        "desc_en": "Record all model inferences in an in-enclave Merkle tree sealed with periodic hardware TPM attestation signatures."
    },

    # Tier 3 (7 challenges, 200 points each)
    {
        "tier": 3, "points": 200, "slug": "constant_time_gemm_kernel_hardening",
        "title_ko": "상수 시간 행렬곱(Constant-Time GEMM) 커널 하드닝 및 분기 제거",
        "title_en": "Constant-Time GEMM Kernel Hardening & Secret-Dependent Branch Removal",
        "desc_ko": "활성화 함수(ReLU, GeLU) 및 부동소수점 곱셈 시 피연산자 값에 따른 클록 주기 편차를 제거하여 사이드채널 정보 유출을 차단합니다.",
        "desc_en": "Implement constant-time matrix multiplication (GEMM) eliminating data-dependent branch variations and memory latencies."
    },
    {
        "tier": 3, "points": 200, "slug": "oblivious_ram_oram_inference_memory_access",
        "title_ko": "ORAM(Oblivious RAM) 기반 추론 메모리 접근 패턴 은닉화",
        "title_en": "Oblivious RAM (ORAM) Access Pattern Shuffling for Inference Protection",
        "desc_ko": "Path ORAM 알고리즘을 적용하여 모델 추론 시 토큰별 메모리 접근 위치를 랜덤 셔플링함으로써 호스트의 접근 패턴 분석을 무력화합니다.",
        "desc_en": "Deploy Path ORAM protocols shuffling memory addresses during token generation to mask inference access patterns from hypervisors."
    },
    {
        "tier": 3, "points": 200, "slug": "tdx_sept_violation_attack_containment",
        "title_ko": "Intel TDX Secure EPT(SEPT) 위반 트랩 및 컨테이너 샌드박스 격리",
        "title_en": "Intel TDX Secure EPT (SEPT) Violation Trapping & Enclave Containment",
        "desc_ko": "호스트 하이퍼바이저가 게스트 메모리 페이지 속성을 무단 변경할 때 발생하는 TDX SEPT 위반을 감지하고 즉각 실행을 중단합니다.",
        "desc_en": "Detect hypervisor-induced Secure EPT (SEPT) mapping violations and trigger emergency enclave self-destruct routines."
    },
    {
        "tier": 3, "points": 200, "slug": "ephemeral_attestation_key_rotation_30s",
        "title_ko": "30초 주기 임시 증명 세션 키 고속 순환 및 PFS 보장",
        "title_en": "30-Second Ephemeral Attestation Session Key Rotation & PFS Assurance",
        "desc_ko": "원격 클라이언트 세션마다 30초 주기로 HKDF-SHA256 기반 대칭 세션키를 자동 롤오버하여 과거 세션의 완전 순방향 비밀성(PFS)을 달성합니다.",
        "desc_en": "Rotate ephemeral symmetric encryption keys every 30 seconds using HKDF-SHA256 ensuring strict Perfect Forward Secrecy."
    },
    {
        "tier": 3, "points": 200, "slug": "masked_activation_tensor_protection",
        "title_ko": "마스킹된 활성화 텐서(Masked Activation) 연산 및 차수별 엔트로피 보호",
        "title_en": "Higher-Order Masked Activation Tensor Arithmetic for Side-Channel Defense",
        "desc_ko": "중간 계층 텐서에 1차 및 2차 불리언 마스킹 난수를 주입하여 차동 전력 분석(DPA) 및 전자파 부채널 분석(EMA)을 방어합니다.",
        "desc_en": "Inject 1st and 2nd-order boolean masking entropy into intermediate activations preventing differential power analysis (DPA)."
    },
    {
        "tier": 3, "points": 200, "slug": "speculative_execution_spectre_v2_barrier",
        "title_ko": "TEE 엔클레이브 내 투기적 실행 공격(Spectre v2/BTI) 방어 배리어",
        "title_en": "Spectre v2 Branch Target Injection (BTI) Mitigation Inside Enclaves",
        "desc_ko": "IBRS(Indirect Branch Restricted Speculation) 및 Retpoline 컴파일러 플래그를 강제하여 교차 VM 분기 예측기 오염 공격을 방어합니다.",
        "desc_en": "Enforce Enhanced IBRS and retpoline instrumentation within enclave binaries to defeat cross-VM Spectre v2 branch poisoning."
    },
    {
        "tier": 3, "points": 200, "slug": "key_broker_service_kbs_attestation_protocol",
        "title_ko": "RATS 표준 기반 키 브로커 서비스(KBS) 상호 증명 프로토콜 구현",
        "title_en": "IETF RATS Standard Key Broker Service (KBS) Mutual Attestation Protocol",
        "desc_ko": "IETF RATS(Remote Attestation Procedures) 아키텍처를 준수하여 Verifier-Relying Party 간 암호학적 신뢰 토큰 규격을 교환합니다.",
        "desc_en": "Implement IETF RATS Entity Attestation Token architecture for mutual verification between Key Broker Services and client enclaves."
    },

    # Tier 4 (7 challenges, 500 points each)
    {
        "tier": 4, "points": 500, "slug": "zero_leak_confidential_gpu_pipeline",
        "title_ko": "CPU-GPU 이종 TEE 간 제로-릭(Zero-Leak) 통합 기밀 파이프라인 수립",
        "title_en": "Zero-Leak End-to-End Heterogeneous CPU-GPU Confidential Pipeline",
        "desc_ko": "AMD SEV-SNP 호스트와 NVIDIA H100 Hopper GPU 간 통합 SPDM 암호화 바운스 버퍼를 구축하여 전 파이프라인 무결성을 보장합니다.",
        "desc_en": "Deploy end-to-end encrypted PCIe bounce buffers across AMD SEV-SNP host CPUs and NVIDIA H100 Hopper confidential GPUs."
    },
    {
        "tier": 4, "points": 500, "slug": "sub_nanosecond_cache_jitter_shield",
        "title_ko": "서브나노초 캐시 타이밍 지터 주입과 동적 더미 연산 실드",
        "title_en": "Sub-Nanosecond Cache Timing Jitter Injection & Dynamic Dummy Ops Shield",
        "desc_ko": "하드웨어 난수 생성기(RDRAND) 기반으로 동적 더미 메모리 접근과 마이크로코드 딜레이를 주입하여 초정밀 통계적 타이밍 분석을 무력화합니다.",
        "desc_en": "Inject RDRAND-driven dummy memory accesses and microcode timing jitter to defeat ultra-high-resolution statistical timing attacks."
    },
    {
        "tier": 4, "points": 500, "slug": "hardware_tpm_quote_live_pcr_verification",
        "title_ko": "물리 하드웨어 TPM 2.0 인라인 Quote와 실시간 PCR 0~7 롤링 검증",
        "title_en": "Physical TPM 2.0 Inline Quote & Real-Time Rolling PCR 0~7 Verification",
        "desc_ko": "부팅 단계부터 런타임까지 확장된 PCR 0~7 해시를 실시간 롤링 검증하여 마이크로코드 패치 및 하이퍼바이저 변조를 즉시 적발합니다.",
        "desc_en": "Verify rolling physical TPM 2.0 PCR 0~7 measurements continuously detecting runtime hypervisor firmware modifications."
    },
    {
        "tier": 4, "points": 500, "slug": "cross_cloud_tee_confidential_mesh",
        "title_ko": "멀티 클라우드(AWS Nitro / Azure SNP / GCP TDX) 연합 기밀 메시 네트워크",
        "title_en": "Multi-Cloud (AWS Nitro / Azure SNP / GCP TDX) Federated Confidential Mesh",
        "desc_ko": "이종 클라우드 환경에서 운영되는 TEE 엔클레이브 간 교차 증명(Cross-Attestation)을 수행하고 상호 mTLS 터널을 연동합니다.",
        "desc_en": "Perform cross-cloud remote attestation and establish encrypted mTLS mesh networks across AWS Nitro, Azure SNP, and GCP TDX."
    },
    {
        "tier": 4, "points": 500, "slug": "post_quantum_hybrid_attestation_signature",
        "title_ko": "FIPS 204 ML-DSA-65 기반 포스트 양자 하이브리드 원격 증명 서명",
        "title_en": "FIPS 204 ML-DSA-65 Post-Quantum Hybrid Remote Attestation Signatures",
        "desc_ko": "기존 ECDSA P-384 증명 서명에 FIPS 204 양자 내성 격자 전자서명(ML-DSA-65)을 결합하여 양자 컴퓨터 기반 증명 위조를 영구 차단합니다.",
        "desc_en": "Combine classical ECDSA with FIPS 204 ML-DSA-65 lattice signatures on attestation quotes to secure long-term enclave authenticity."
    },
    {
        "tier": 4, "points": 500, "slug": "tamper_evident_token_stream_blockchain",
        "title_ko": "위변조 불가능한 LLM 토큰 스트림 실시간 서명 및 온체인 영지식 증명",
        "title_en": "Tamper-Evident Real-Time LLM Token Stream Signing & zk-SNARK Verification",
        "desc_ko": "생성되는 모든 토큰 청크를 엔클레이브 TPM 키로 스트리밍 서명하고 zk-SNARK 증거를 생성하여 외부 검증자가 실시간 확인하게 합니다.",
        "desc_en": "Sign streaming LLM token chunks via enclave TPM keys and emit zk-SNARK proofs validating confidential inference fidelity."
    },
    {
        "tier": 4, "points": 500, "slug": "capstone_full_spectrum_confidential_ai_defense",
        "title_ko": "기밀 AI 추론 & 하드웨어 엔클레이브 풀 스펙트럼 방어 체계 (Capstone)",
        "title_en": "Capstone: Full-Spectrum Confidential AI Inference & Hardware TEE Defense",
        "desc_ko": "AMD SEV-SNP 원격 증명, AES-256-XTS 메모리 암호화, 상수시간 GEMM, ORAM 셔플링, TPM AIK 서명을 완벽 통합한 방어를 완성합니다.",
        "desc_en": "Synthesize hardware TEE attestation, in-enclave AES-256-XTS weight sealing, constant-time GEMM, ORAM shuffling, and TPM AIK output signatures."
    }
]

def main():
    repo_root = Path(__file__).resolve().parent.parent
    challenges_js_path = repo_root / "wargame" / "assets" / "challenges.js"
    solve_derivable_path = repo_root / "wargame" / "scripts" / "solve-derivable.js"
    readme_path = repo_root / "wargame" / "README.md"
    index_html_path = repo_root / "wargame" / "index.html"
    root_index_html_path = repo_root / "index.html"

    print(f"[*] Repository root: {repo_root}")

    # 1. Build challenge objects
    new_challenges = []
    for cdata in CHALLENGES_DATA:
        cid = f"t{cdata['tier']}_teeai_{cdata['slug']}"
        raw_flag = f"FLAG{{{hashlib.sha256((cid + '_vibe_teeai_2026').encode()).hexdigest()[:20]}}}"
        ch_hash = hashlib.sha256(raw_flag.encode()).hexdigest()

        prompt_ko = (
            f"{cdata['desc_ko']}\n\n"
            f"[실습 환경 및 검증 식별자]\n"
            f"TEEAI_CHALLENGE_ID: `{cid}`\n\n"
            f"위 식별자를 기반으로 기밀 AI & 하드웨어 TEE 원격 증명 검증 플래그를 도출하여 제출하세요."
        )
        prompt_en = (
            f"{cdata['desc_en']}\n\n"
            f"[Verification Identifier]\n"
            f"TEEAI_CHALLENGE_ID: `{cid}`\n\n"
            f"Derive and submit the confidential AI & hardware TEE attestation verification flag based on this challenge identifier."
        )

        ch = {
            "id": cid,
            "tier": cdata["tier"],
            "cat": "confidential",
            "track": "teeai",
            "points": cdata["points"],
            "ci": False,
            "hash": ch_hash,
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
                "ko": [
                    f"이 문제는 식별자 `{cid}` 기반 결정론적 검증 플래그로 풀이할 수 있습니다."
                ],
                "en": [
                    f"This challenge derives a deterministic flag from identifier `{cid}`."
                ]
            }
        }
        new_challenges.append(ch)

    print(f"[+] Prepared {len(new_challenges)} challenges for Track 79 (teeai).")

    # 2. Update challenges.js
    content = challenges_js_path.read_text(encoding="utf-8")

    # Check if TRACK 79 already in TRACKS
    if '"id": "teeai"' in content:
        print("[-] Track 79 (teeai) already in TRACKS.")
    else:
        track_entry = """,
  {
    "id": "teeai",
    "icon": "🔒",
    "ko": "기밀 AI & 하드웨어 TEE 엔클레이브 원격 증명",
    "en": "Confidential AI & Hardware TEE Enclave Attestation",
    "desc_ko": "AMD SEV-SNP/Intel TDX 하드웨어 TEE 원격 증명·VCEK 인증서 체인 및 PCR0 무결성·엔클레이브 내 AES-256-XTS 가중치 복호화·Flush+Reload 캐시 타이밍 부채널 방어·TPM AIK 암호학적 서명.",
    "desc_en": "AMD SEV-SNP/Intel TDX hardware TEE remote attestation, VCEK certificate chain and PCR0 measurement integrity, in-enclave AES-256-XTS weight sealing, Flush+Reload cache timing side-channel mitigation, and TPM AIK cryptographic signatures."
  }"""
        aisbox_track_needle = '  {\n    "id": "aisbox",\n    "icon": "🤖",\n    "ko": "AI 에이전트 샌드박스 탈출 & 공급망 보안",\n    "en": "AI Agent Sandbox Escape & Supply Chain Security",\n    "desc_ko": "AI 에이전트 툴 동적 로딩 오염·SLSA Level 3 출처 증명·Ray/vLLM 분산 RCE 차단 & SPIFFE mTLS·Landlock LSM 샌드박싱·eBPF 런타임 탈출 SIGKILL 격리·G3 다자간 승인 거버넌스.",\n    "desc_en": "AI agent dynamic tool loading poisoning, SLSA Level 3 provenance, Ray/vLLM distributed RCE defense with SPIFFE mTLS, Landlock LSM sandboxing, eBPF instant SIGKILL breakout containment, and G3 multi-party approval governance."\n  }\n];'
        
        if aisbox_track_needle in content:
            replacement = aisbox_track_needle[:-3] + track_entry + "\n];"
            content = content.replace(aisbox_track_needle, replacement, 1)
            print("[+] Inserted Track 79 definition into TRACKS.")
        else:
            # Fallback regex search for end of tracks
            m = re.search(r'("id":\s*"aisbox"[\s\S]*?\n  }\n)(];)', content)
            assert m, "Could not locate aisbox track in TRACKS array"
            content = content[:m.end(1)] + track_entry + "\n" + content[m.start(2):]
            print("[+] Inserted Track 79 definition into TRACKS via regex.")

    # Check if challenges already present
    existing_cids = set(re.findall(r'"id":\s*"(t\d_teeai_[^"]+)"', content))
    if existing_cids:
        print(f"[*] Removing {len(existing_cids)} old teeai challenges from challenges.js...")
        m_start = re.search(r',\s*\{\s*"id":\s*"t0_teeai_[^"]+"', content)
        if m_start:
            target_challs_end = "\n];"
            idx_end = content.rfind(target_challs_end)
            content = content[:m_start.start()] + content[idx_end:]

    target_challs_end = "\n];"
    formatted_challs = []
    for ch in new_challenges:
        ch_str = json.dumps(ch, ensure_ascii=False, indent=2)
        formatted_challs.append("  " + ch_str.replace("\n", "\n  "))
    challs_block = ",\n" + ",\n".join(formatted_challs)
    idx = content.rfind(target_challs_end)
    assert idx != -1, "Could not find end of CHALLENGES in challenges.js"
    content = content[:idx] + challs_block + "\n];" + content[idx + len(target_challs_end):]
    print("[+] Appended 35 teeai challenges to CHALLENGES array with proper hints object.")

    challenges_js_path.write_text(content, encoding="utf-8")
    print(f"[+] Wrote updated {challenges_js_path}")

    # 3. Update solve-derivable.js
    solve_content = solve_derivable_path.read_text(encoding="utf-8")
    teeai_ids = [ch["id"] for ch in new_challenges]
    ids_js = ",\n  ".join([f'"{cid}"' for cid in teeai_ids])
    derivable_code = f"""const TEEAI_IDS = [
  {ids_js}
];

for (const id of TEEAI_IDS) {{
  SOLVERS.set(id, {{
    kind: 'computed',
    via: 'SHA256 of identifier in prompt',
    solve: (ch) => {{
      const text = (ch.prompt.ko || '') + '\\n' + (ch.prompt.en || '');
      const m = text.match(/TEEAI_CHALLENGE_ID:\\s*`([^`]+)`/);
      const ident = m ? m[1] : ch.id;
      const hash = crypto.createHash('sha256').update(ident + '_vibe_teeai_2026').digest('hex').slice(0, 20);
      return `FLAG${{{{hash}}}}`;
    }}
  }});
}}
"""
    if "const TEEAI_IDS = [" in solve_content:
        # replace existing block
        solve_content = re.sub(r'const TEEAI_IDS = \[[\s\S]*?\}\);\s*\}\s*', lambda m: derivable_code, solve_content)
        print("[+] Replaced existing TEEAI_IDS block in solve-derivable.js.")
    else:
        needle = "/* Exact-match challenges deliberately left uncovered."
        assert needle in solve_content, "Could not find insertion marker in solve-derivable.js"
        solve_content = solve_content.replace(needle, derivable_code + "\n" + needle, 1)
        print("[+] Added teeai derivation handler to solve-derivable.js.")
    solve_derivable_path.write_text(solve_content, encoding="utf-8")

    # 4. Update wargame/README.md
    readme_text = readme_path.read_text(encoding="utf-8")
    readme_text = readme_text.replace("총 2730문제", "총 2765문제")
    readme_text = readme_text.replace("총 **2730문제**", "총 **2765문제**")
    readme_text = readme_text.replace("78개 트랙", "79개 트랙")
    readme_text = readme_text.replace("78개 섹션", "79개 섹션")
    readme_text = readme_text.replace("Total **2730 challenges**", "Total **2765 challenges**")

    # Update tier counts table
    readme_text = readme_text.replace("| `perimeter` 외곽 | **0** | 301 |", "| `perimeter` 외곽 | **0** | 308 |")
    readme_text = readme_text.replace("| `webserver` 웹서버 | **1** | 510 |", "| `webserver` 웹서버 | **1** | 517 |")
    readme_text = readme_text.replace("| `internal` 내부망 | **2** | 662 |", "| `internal` 내부망 | **2** | 669 |")
    readme_text = readme_text.replace("| `vault` 금고 | **3** | 652 |", "| `vault` 금고 | **3** | 659 |")
    readme_text = readme_text.replace("| `core` 코어 | **4** | 605 |", "| `core` 코어 | **4** | 612 |")

    # Update English summary list
    old_en_tail = "post-quantum hybrid TLS 1.3 & PQC network defense 35 · AI agent sandbox escape & supply chain security 35); each maps to a topic from the [main repo](../README.md)'s 78 sections."
    new_en_tail = "post-quantum hybrid TLS 1.3 & PQC network defense 35 · AI agent sandbox escape & supply chain security 35 · confidential AI & hardware TEE attestation 35); each maps to a topic from the [main repo](../README.md)'s 79 sections."
    readme_text = readme_text.replace(old_en_tail, new_en_tail)

    tier0_row = "| `teeai` 🔒 기밀 AI & 하드웨어 TEE 엔클레이브 원격 증명 (7) | TEE 위협 모델 · 하드웨어 격리 아키텍처 · 원격 증명 PCR0 원리 · 가중치 보호 모델 / TEE threat model, hardware isolation architecture, remote attestation PCR0 principles, and weight protection model |"
    tier1_row = "| `teeai` 🔒 기밀 AI & 하드웨어 TEE 엔클레이브 원격 증명 (7) | VCEK 인증서 체인 감사 · TDX Quote 생성 검증 · AES 메모리 암호화 감사 · KDF 가중치 복호화 / VCEK certificate chain audit, TDX quote validation, AES memory encryption audit, and KDF weight decryption |"
    tier2_row = "| `teeai` 🔒 기밀 AI & 하드웨어 TEE 엔클레이브 원격 증명 (7) | Flush+Reload 부채널 차단 · Prime+Probe 캐시 감시 · 페이지 폴트 추적 방어 · 종단간 ECDH 교환 / Flush+Reload side-channel mitigation, Prime+Probe cache monitoring, page fault tracking defense, and end-to-end ECDH exchange |"
    tier3_row = "| `teeai` 🔒 기밀 AI & 하드웨어 TEE 엔클레이브 원격 증명 (7) | 상수시간 GEMM 하드닝 · ORAM 메모리 접근 은닉 · TDX SEPT 위반 트랩 · 30초 세션키 롤오버 / Constant-time GEMM hardening, ORAM memory access shuffling, TDX SEPT violation trapping, and 30s session key rollover |"
    tier4_row = "| `teeai` 🔒 기밀 AI & 하드웨어 TEE 엔클레이브 원격 증명 (7) | 제로-릭 GPU 파이프라인 · 서브나노초 타이밍 지터 · 물리 TPM 롤링 검증 · 기밀 AI TEE 방어 캡스톤 / Zero-leak GPU pipeline, sub-nanosecond timing jitter, physical TPM rolling audit, and confidential AI TEE defense capstone |"

    aisbox_t0 = "| `aisbox` 🤖 AI 에이전트 샌드박스 탈출 & 공급망 보안 (7) | 도구 동적 로딩 위협 · SLSA Level 3 출처 증명 · PEP 665 해시 고정 · Landlock 비특권 원리 / Tool dynamic loading threat, SLSA Level 3 provenance, PEP 665 hash pinning, and Landlock unprivileged principles |"
    aisbox_t1 = "| `aisbox` 🤖 AI 에이전트 샌드박스 탈출 & 공급망 보안 (7) | 타이포스쿼팅 해시 감사 · Ray 피클 역직렬화 RCE · Seccomp 시스템콜 필터 · Cosign 컨테이너 서명 / Typosquatting hash audit, Ray pickle deserialization RCE, Seccomp syscall filter, and Cosign container signatures |"
    aisbox_t2 = "| `aisbox` 🤖 AI 에이전트 샌드박스 탈출 & 공급망 보안 (7) | /proc/self/fd 누출 디스크립터 · setns 피벗 차단 · Safetensors 무결성 강제 · 30초 기능 토큰 회전 / /proc/self/fd leaked descriptor, setns pivot denial, Safetensors integrity enforcement, and 30s capability token rotation |"
    aisbox_t3 = "| `aisbox` 🤖 AI 에이전트 샌드박스 탈출 & 공급망 보안 (7) | eBPF bpf_lsm_file_open 차단 · Wasm 메모리 격리 런타임 · G3 다자간 합의 원장 · 28개 시스템콜 화이트리스트 / eBPF bpf_lsm_file_open denial, Wasm memory-isolated runtime, G3 multi-party ledger, and 28-syscall whitelist |"
    aisbox_t4 = "| `aisbox` 🤖 AI 에이전트 샌드박스 탈출 & 공급망 보안 (7) | 크로스클라우드 메시 격리 · 하드웨어 TEE 추론 보호 · 서브마이크로초 SIGKILL 쉴드 · AI 샌드박스 방어 캡스톤 / Cross-cloud mesh containment, hardware TEE reasoning shield, sub-microsecond SIGKILL shield, and AI sandbox defense capstone |"

    if '`teeai`' not in readme_text:
        readme_text = readme_text.replace(aisbox_t0, aisbox_t0 + "\n" + tier0_row)
        readme_text = readme_text.replace(aisbox_t1, aisbox_t1 + "\n" + tier1_row)
        readme_text = readme_text.replace(aisbox_t2, aisbox_t2 + "\n" + tier2_row)
        readme_text = readme_text.replace(aisbox_t3, aisbox_t3 + "\n" + tier3_row)
        readme_text = readme_text.replace(aisbox_t4, aisbox_t4 + "\n" + tier4_row)
        print("[+] Updated wargame/README.md with teeai rows.")
    readme_path.write_text(readme_text, encoding="utf-8")
    print("[+] Wrote updated wargame/README.md.")

    # 5. Update index.html HUD in wargame/index.html & root index.html (2730 -> 2765)
    for p in [index_html_path, root_index_html_path]:
        if p.exists():
            txt = p.read_text(encoding="utf-8")
            txt = txt.replace("0/2730", "0/2765")
            txt = txt.replace("/2730", "/2765")
            txt = txt.replace("2,730", "2,765")
            txt = txt.replace("2730", "2765")
            p.write_text(txt, encoding="utf-8")
            print(f"[+] Updated HUD counters in {p.name}")

    print("\n🎉 Track 79 teeai generation completed successfully!")

if __name__ == "__main__":
    main()
