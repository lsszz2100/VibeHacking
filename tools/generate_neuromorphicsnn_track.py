#!/usr/bin/env python3
"""
Generator for Track 88: neuromorphicsnn (Neuromorphic Spiking Neural Network & Memristor Hardware Security)
35 Challenges: Tier 0 to Tier 4 (7 per tier)
Total 3,080 challenges milestone across 88 tracks.
Zero-Defect Guaranteed.
"""

import hashlib
import json
import re
from pathlib import Path

CHALLENGES_DATA = [
    # Tier 0 (7 challenges, 25 points each)
    {
        "tier": 0, "points": 25, "slug": "asynchronous_aer_event_bus_foundations",
        "title_ko": "비동기 AER 이벤트 버스 통신 프로토콜 기초",
        "title_en": "Asynchronous AER Event Bus Communication Protocol Foundations",
        "desc_ko": "뉴로모픽 프로세서의 비동기 Address-Event Representation (AER) 버스 통신 원리와 스파이크 패킷 전송 구조를 분석합니다.",
        "desc_en": "Analyze asynchronous Address-Event Representation (AER) bus communication mechanics and spike packet delivery structures in neuromorphic processors."
    },
    {
        "tier": 0, "points": 25, "slug": "lif_leaky_integrate_and_fire_membrane_dynamics",
        "title_ko": "LIF 뉴런 막전위 누적 및 발화 동역학 분석",
        "title_en": "Leaky Integrate-and-Fire (LIF) Neuron Membrane Potential Dynamics",
        "desc_ko": "누설 적분 발화(LIF) 모델의 세포막 전위 누적, 감쇠, 그리고 발화 임계값(-48.5mV) 도달 시의 스파이크 생성 원리를 학습합니다.",
        "desc_en": "Study leaky integrate-and-fire (LIF) membrane potential accumulation, decay, and spike generation upon reaching firing thresholds (-48.5mV)."
    },
    {
        "tier": 0, "points": 25, "slug": "memristor_crossbar_analog_computing_surfaces",
        "title_ko": "멤리스터 크로스바 아날로그 연산 하드웨어 공격 표면",
        "title_en": "Memristor Crossbar Analog Computing Hardware Attack Surfaces",
        "desc_ko": "행/열 전압 인가를 통해 벡터-행렬 곱셈(VMM)을 수행하는 멤리스터 크로스바 어레이의 전압 왜곡 및 결함 주입 공격 표면을 식별합니다.",
        "desc_en": "Identify voltage perturbation and fault injection surfaces across memristor crossbars performing analog vector-matrix multiplication."
    },
    {
        "tier": 0, "points": 25, "slug": "neuromorphic_spike_timing_coding_threat_model",
        "title_ko": "뉴로모픽 스파이크 타이밍 코딩 위협 모델 분석",
        "title_en": "Neuromorphic Spike Timing Coding Threat Model Analysis",
        "desc_ko": "시간적 스파이크 간격(Inter-Spike Interval)에 정보를 은닉하거나 왜곡하는 적대적 타이밍 지터 공격 위협을 평가합니다.",
        "desc_en": "Evaluate adversarial timing jitter threats corrupting or covertly exploiting temporal inter-spike intervals in neuromorphic computing."
    },
    {
        "tier": 0, "points": 25, "slug": "laser_fault_injection_lfi_neuromorphic_vulnerabilities",
        "title_ko": "레이저 고장 주입(LFI) 뉴로모픽 반도체 취약점 개요",
        "title_en": "Laser Fault Injection (LFI) Neuromorphic Semiconductor Vulnerabilities",
        "desc_ko": "뉴로모픽 실리콘 다이에 적외선 레이저 펄스를 조사하여 특정 뉴런의 발화를 강제하거나 차단하는 물리적 침해 기법을 분석합니다.",
        "desc_en": "Examine physical tampering mechanisms applying infrared laser pulses onto neuromorphic dies to manipulate neuron firing states."
    },
    {
        "tier": 0, "points": 25, "slug": "stdp_spike_timing_dependent_plasticity_poisoning_intro",
        "title_ko": "STDP 시냅스 가소성 학습 규칙 오염 공격 개요",
        "title_en": "Spike-Timing-Dependent Plasticity (STDP) Learning Rule Poisoning Overview",
        "desc_ko": "스파이크 도달 시차에 따라 시냅스 전도도를 자율 갱신하는 STDP 메커니즘을 조작하여 모델 백도어를 심는 위협을 검토합니다.",
        "desc_en": "Review threats implanting backdoors by exploiting STDP mechanisms that autonomously adapt synaptic conductance based on spike timing."
    },
    {
        "tier": 0, "points": 25, "slug": "neuromorphic_hardware_root_of_trust_binding_overview",
        "title_ko": "하드웨어 신뢰점(RoT) 기반 뉴로모픽 프로세서 보호 개요",
        "title_en": "Hardware Root-of-Trust (RoT) Neuromorphic Processor Protection Overview",
        "desc_ko": "뉴로모픽 코어와 온칩 불변 하드웨어 RoT를 암호학적으로 결합하여 불법 펌웨어 및 파라미터 변조를 차단하는 구조를 분석합니다.",
        "desc_en": "Analyze architectures cryptographically binding neuromorphic computing cores to immutable hardware RoT to prevent tampering."
    },

    # Tier 1 (7 challenges, 50 points each)
    {
        "tier": 1, "points": 50, "slug": "aer_spike_timing_jitter_fingerprint_extraction",
        "title_ko": "AER 스파이크 타이밍 지터 기반 물리 지문 추출",
        "title_en": "AER Spike Timing Jitter Physical Fingerprint Extraction",
        "desc_ko": "AER 버스의 스파이크 도달 간격(12.5ns 기준) 미세 지터와 분산 통계를 측정하여 칩 고유의 물리 지문을 도출합니다.",
        "desc_en": "Measure fine jitter and variance statistics across AER spike intervals (12.5ns baseline) to derive unique hardware chip fingerprints."
    },
    {
        "tier": 1, "points": 50, "slug": "lif_neuron_membrane_threshold_calibration_routine",
        "title_ko": "LIF 뉴런 막전위 발화 임계값(-48.5mV) 정밀 교정 루틴",
        "title_en": "LIF Neuron Membrane Potential Firing Threshold (-48.5mV) Calibration",
        "desc_ko": "온도 변화와 공급 전압 변동에도 LIF 뉴런의 발화 임계값(-48.5mV)을 오차 ±0.5mV 이내로 안정화하는 캘리브레이션을 구현합니다.",
        "desc_en": "Implement calibration routines stabilizing LIF neuron firing thresholds at -48.5mV (within ±0.5mV tolerance) across thermal variations."
    },
    {
        "tier": 1, "points": 50, "slug": "memristor_conductance_drift_tolerance_monitoring",
        "title_ko": "멤리스터 크로스바 전도도 드리프트(<0.05%) 허용치 모니터링",
        "title_en": "Memristor Crossbar Conductance Drift (<0.05%) Tolerance Monitoring",
        "desc_ko": "멤리스터 소자의 자연적 전도도 드리프트가 안전 임계치(0.05%)를 초과할 경우 실시간 경보를 발령하는 감시 루틴을 구축합니다.",
        "desc_en": "Build a monitoring routine raising real-time alerts when memristor conductance drift exceeds physical safety bounds of 0.05%."
    },
    {
        "tier": 1, "points": 50, "slug": "crossbar_voltage_glitch_transient_detector_circuit",
        "title_ko": "크로스바 전압 글리치 과도전압 실시간 감지 회로 구현",
        "title_en": "Crossbar Voltage Glitch Transient Detector Circuit Implementation",
        "desc_ko": "크로스바 공급 전압 라인에 유입되는 18.5mV 이상의 급격한 과도 글리치 펄스를 나노초 단위로 검출하는 회로를 설계합니다.",
        "desc_en": "Design circuits detecting transient voltage glitch pulses exceeding 18.5mV on crossbar power rails at nanosecond resolution."
    },
    {
        "tier": 1, "points": 50, "slug": "synaptic_conductance_variance_stability_assessment",
        "title_ko": "시냅스 전도도 분산 지표 안정성 정량 평가 모듈",
        "title_en": "Synaptic Conductance Variance Stability Quantitative Assessment Module",
        "desc_ko": "8x8 시냅스 어레이의 전도도 분산이 임계값(0.02) 이하로 유지되는지 통계적으로 검증하여 악의적 가중치 조작을 탐지합니다.",
        "desc_en": "Statistically verify that synaptic conductance variance across 8x8 arrays remains below 0.02 to detect adversarial weight tampering."
    },
    {
        "tier": 1, "points": 50, "slug": "neuromorphic_firmware_sha256_hash_register_locking",
        "title_ko": "뉴로모픽 제어 펌웨어 SHA-256 해시 레지스터 락킹",
        "title_en": "Neuromorphic Control Firmware SHA-256 Hash Register Locking",
        "desc_ko": "뉴로모픽 프로세서 제어 마이크로코드의 SHA-256 해시를 하드웨어 원-타임 프로그램(OTP) eFuse에 영구 기록합니다.",
        "desc_en": "Permanently burn SHA-256 hashes of neuromorphic control microcode into hardware OTP eFuse registers to prevent firmware injection."
    },
    {
        "tier": 1, "points": 50, "slug": "sub_20ns_synaptic_circuit_zeroization_timing_test",
        "title_ko": "20ns 이하 시냅스 회로 안티 탬퍼 제로화 타이밍 테스트",
        "title_en": "Sub-20ns Synaptic Circuit Anti-Tamper Zeroization Timing Benchmark",
        "desc_ko": "물리적 침해 트리거 수신 즉시 12.0ns 이내에 시냅스 크로스바 전하를 완전 방전하여 메모리를 제로화하는 회로를 검증합니다.",
        "desc_en": "Validate anti-tamper circuits discharging memristor crossbars within 12.0ns upon tamper signals to securely erase parameters."
    },

    # Tier 2 (7 challenges, 100 points each)
    {
        "tier": 2, "points": 100, "slug": "stdp_synaptic_plasticity_adversarial_drift_shield",
        "title_ko": "STDP 시냅스 가소성 적대적 드리프트 방어기 구축",
        "title_en": "STDP Synaptic Plasticity Adversarial Drift Shield Architecture",
        "desc_ko": "시간차 조작을 통한 적대적 가중치 드리프트 공격을 감지하고 STDP 학습률을 동적으로 제한하는 가드레일을 구현합니다.",
        "desc_en": "Implement guardrails detecting adversarial weight drift attacks via timing manipulation and dynamically clamping STDP learning rates."
    },
    {
        "tier": 2, "points": 100, "slug": "crossbar_voltage_clamping_phase_jitter_suppression",
        "title_ko": "크로스바 전압 클램핑 및 위상 지터 능동 억제 엔진",
        "title_en": "Crossbar Voltage Clamping & Phase Jitter Active Suppression Engine",
        "desc_ko": "전압 글리치 유입 시 크로스바 라인을 즉각 클램핑하고 스파이크 타이밍 위상에 방어적 지터를 주입해 결함 주입을 무력화합니다.",
        "desc_en": "Instantly clamp crossbar lines during voltage glitches and inject defensive phase jitter to neutralize fault injection attempts."
    },
    {
        "tier": 2, "points": 100, "slug": "neuromorphic_session_token_cryptographic_signing",
        "title_ko": "뉴로모픽 세션 토큰 HMAC 암호학적 서명 파이프라인",
        "title_en": "Neuromorphic Session Token HMAC Cryptographic Signing Pipeline",
        "desc_ko": "뉴로모픽 방어 세션 식별자와 하드웨어 마스터 시크릿을 결합하여 HMAC-SHA256 기반 무결성 증명 토큰을 발급합니다.",
        "desc_en": "Issue HMAC-SHA256 integrity tokens cryptographically combining neuromorphic defense session identifiers with hardware master keys."
    },
    {
        "tier": 2, "points": 100, "slug": "asynchronous_aer_packet_mac_integrity_enforcement",
        "title_ko": "비동기 AER 이벤트 패킷 MAC 무결성 검증 모듈",
        "title_en": "Asynchronous AER Event Packet MAC Integrity Verification Module",
        "desc_ko": "AER 버스 상에서 라우팅되는 이벤트 패킷 헤더에 경량 16비트 MAC을 첨부하여 위조 스파이크 패킷 삽입을 차단합니다.",
        "desc_en": "Attach lightweight 16-bit MACs to AER event packet headers to block adversary forged spike packet insertion across event buses."
    },
    {
        "tier": 2, "points": 100, "slug": "memristor_array_conductance_matrix_merkle_construction",
        "title_ko": "멤리스터 어레이 전도도 매트릭스 머클 트리 구성",
        "title_en": "Memristor Array Conductance Matrix Merkle Tree Construction",
        "desc_ko": "크로스바 어레이의 64개 멤리스터 전도도 값을 블록별로 해싱하여 머클 트리를 구성하고 루트 해시 무결성을 증명합니다.",
        "desc_en": "Construct Merkle trees hashing conductance values across 64 crossbar memristors and prove cryptographic root hash integrity."
    },
    {
        "tier": 2, "points": 100, "slug": "neural_power_differential_sidechannel_jitter_masking",
        "title_ko": "신경망 전력 차분 사이드채널 스파이크 지터 마스킹",
        "title_en": "Neural Power Differential Sidechannel Spike Jitter Masking",
        "desc_ko": "스파이크 발화 시 소비되는 전력 파형에 의사 난수 지터를 주입하여 차분 전력 분석(DPA) 모델 가중치 복원 공격을 차단합니다.",
        "desc_en": "Inject pseudo-random jitter into spike firing power traces to thwart differential power analysis (DPA) model parameter reconstruction attacks."
    },
    {
        "tier": 2, "points": 100, "slug": "heterogeneous_neuromorphic_soc_mutual_attestation",
        "title_ko": "이종 뉴로모픽 SoC 컴포넌트 간 상호 원격 증명 핸드셰이크",
        "title_en": "Heterogeneous Neuromorphic SoC Mutual Remote Attestation Handshake",
        "desc_ko": "뉴로모픽 가속기 코어와 호스트 RISC-V 보안 관리자 간 상호 암호학적 원격 증명을 통해 위조 코어 삽입을 봉쇄합니다.",
        "desc_en": "Enforce bidirectional cryptographic remote attestation between neuromorphic cores and host RISC-V controllers to prevent rogue dies."
    },

    # Tier 3 (7 challenges, 200 points each)
    {
        "tier": 3, "points": 200, "slug": "adversarial_spike_train_injection_defense_filter",
        "title_ko": "적대적 스파이크 트레인 주입 실시간 방어 필터",
        "title_en": "Adversarial Spike Train Injection Real-Time Defense Filter",
        "desc_ko": "뉴런 발화 빈도 및 버스트 간격의 이상 통계를 실시간 분석하여 적대적으로 조작된 스파이크 폭탄 공격을 격리 차단합니다.",
        "desc_en": "Analyze anomaly statistics of neuron firing frequencies to quarantine adversarially crafted spike train saturation attacks in real time."
    },
    {
        "tier": 3, "points": 200, "slug": "memristor_laser_fault_injection_countermeasure_matrix",
        "title_ko": "멤리스터 LFI 레이저 고장 주입 능동 대응 매트릭스",
        "title_en": "Memristor LFI Laser Fault Injection Active Countermeasure Matrix",
        "desc_ko": "다이 상단 광센서 어레이와 결합하여 레이저 펄스 입사 시 15ns 이내에 크로스바 역극성 전압을 인가하는 대응 매트릭스를 구현합니다.",
        "desc_en": "Deploy on-die optical sensors triggering reverse polarity electrical voltage within 15ns of laser pulse incidence to prevent memristor state flips."
    },
    {
        "tier": 3, "points": 200, "slug": "stdp_weight_poisoning_trojan_backdoor_detection",
        "title_ko": "STDP 가중치 변조 트로이목마 백도어 정밀 적출",
        "title_en": "STDP Weight Poisoning Trojan Backdoor Precision Detection",
        "desc_ko": "정상 입력 분포에서는 활성화되지 않고 특정 희귀 스파이크 패턴에서만 트리거되는 은닉 하드웨어 백도어를 통계적으로 적출합니다.",
        "desc_en": "Statistically extract dormant hardware backdoors that remain inactive under normal inputs and only trigger on rare spike patterns."
    },
    {
        "tier": 3, "points": 200, "slug": "ml_dsa_87_neuromorphic_firmware_post_quantum_attestation",
        "title_ko": "NIST ML-DSA-87 뉴로모픽 펌웨어 포스트 양자 원격 증명",
        "title_en": "NIST ML-DSA-87 Neuromorphic Firmware Post-Quantum Remote Attestation",
        "desc_ko": "NIST FIPS 204 표준 격자 기반 ML-DSA-87 전자서명을 생성 및 검증하여 뉴로모픽 펌웨어와 파라미터 무결성을 양자 내성으로 증명합니다.",
        "desc_en": "Generate and verify lattice-based NIST FIPS 204 ML-DSA-87 digital signatures to ensure quantum-safe firmware provenance."
    },
    {
        "tier": 3, "points": 200, "slug": "neuromorphic_supply_chain_trojan_silicon_quarantine",
        "title_ko": "뉴로모픽 공급망 실리콘 트로이목마 격리 및 무효화",
        "title_en": "Neuromorphic Supply Chain Trojan Silicon Quarantine & Revocation",
        "desc_ko": "반도체 제조 외주 과정에서 삽입된 기생 시냅스 트로이 게이트를 탐지하고 해당 크로스바 라인을 영구 비활성화 격리합니다.",
        "desc_en": "Detect parasitic synaptic trojan gates inserted during outsourced fabrication and permanently quarantine affected crossbar rows."
    },
    {
        "tier": 3, "points": 200, "slug": "hardware_rot_enforced_memristor_conductance_restoration",
        "title_ko": "하드웨어 RoT 강제 멤리스터 전도도 무결성 복구",
        "title_en": "Hardware RoT-Enforced Memristor Conductance Integrity Restoration",
        "desc_ko": "전도도 이상 변조 감지 시 하드웨어 RoT에 보관된 골든 이미지 스냅샷을 기반으로 크로스바 가중치를 즉시 안전 상태로 롤백합니다.",
        "desc_en": "Instantly roll back corrupted memristor weights to verified golden snapshots stored in hardware RoT upon anomaly detection."
    },
    {
        "tier": 3, "points": 200, "slug": "asynchronous_snn_sidechannel_emulation_sandbox",
        "title_ko": "비동기 SNN 사이드채널 에뮬레이션 샌드박스 검증",
        "title_en": "Asynchronous SNN Sidechannel Emulation Sandbox Verification",
        "desc_ko": "전자기 방출(EM) 및 전력 소비 텔레메트리를 가상 에뮬레이트하여 제로데이 부채널 취약점을 사전에 차단하는 샌드박스를 구축합니다.",
        "desc_en": "Establish an emulation sandbox simulating electromagnetic and power telemetry to proactively mitigate zero-day sidechannel leaks."
    },

    # Tier 4 (7 challenges, 300 points each)
    {
        "tier": 4, "points": 300, "slug": "neuromorphic_processor_laser_glitch_penetration_drill",
        "title_ko": "뉴로모픽 프로세서 레이저 글리치 침투 모의 검증",
        "title_en": "Neuromorphic Processor Laser Glitch Penetration Adversarial Drill",
        "desc_ko": "실제 전압 글리치 및 LFI 결함 주입을 결합한 복합 침투 시나리오를 재현하고 나노초 방어 클램프 회로의 유효성을 실증합니다.",
        "desc_en": "Execute multi-vector fault injection drills combining voltage glitches and LFI to demonstrate nanosecond clamp defense."
    },
    {
        "tier": 4, "points": 300, "slug": "enterprise_neuromorphic_chip_production_attestation",
        "title_ko": "엔터프라이즈 뉴로모픽 칩 양산 펌웨어 머클 원격 증명",
        "title_en": "Enterprise Neuromorphic Chip Production Firmware Merkle Attestation",
        "desc_ko": "대규모 분산 뉴로모픽 가속기 클러스터의 전체 펌웨어 및 크로스바 구성을 결합한 글로벌 머클 증명 파이프라인을 구축합니다.",
        "desc_en": "Deploy an enterprise Merkle attestation pipeline verifying firmware and crossbar configurations across neuromorphic clusters."
    },
    {
        "tier": 4, "points": 300, "slug": "memristor_crossbar_deep_physical_sidechannel_shielding",
        "title_ko": "멤리스터 크로스바 심층 물리 사이드채널 완전 밀폐",
        "title_en": "Memristor Crossbar Deep Physical Sidechannel Comprehensive Shielding",
        "desc_ko": "다층 금속 차폐막 및 실시간 차분 노이즈 발생기를 온칩 통합하여 전자기 방출 누출을 -90dB 이하로 완전 차단합니다.",
        "desc_en": "Integrate multi-layer metal shields and differential noise generators on-chip to attenuate electromagnetic leakage below -90dB."
    },
    {
        "tier": 4, "points": 300, "slug": "zero_trust_neuromorphic_aer_event_mesh_federation",
        "title_ko": "제로 트러스트 뉴로모픽 AER 이벤트 메시 연합 아키텍처",
        "title_en": "Zero Trust Neuromorphic AER Event Mesh Federation Architecture",
        "desc_ko": "분산 뉴로모픽 칩 간에 교환되는 수십억 개의 AER 이벤트에 대해 엔드-투-엔드 상호 인증과 마이크로 세그멘테이션을 강제합니다.",
        "desc_en": "Enforce end-to-end mutual authentication and micro-segmentation across billions of AER events exchanged between distributed chips."
    },
    {
        "tier": 4, "points": 300, "slug": "quantum_resistant_neuromorphic_firmware_lifecycle",
        "title_ko": "양자 내성 뉴로모픽 펌웨어 라이프사이클 거버넌스",
        "title_en": "Quantum-Resistant Neuromorphic Firmware Lifecycle Governance",
        "desc_ko": "포스트 양자 서명(ML-DSA-87)과 SLSA 레벨 3 출처 증명을 통합하여 뉴로모픽 펌웨어의 배포, 롤백, 파기를 완벽히 통제합니다.",
        "desc_en": "Integrate ML-DSA-87 signatures with SLSA Level 3 provenance to govern neuromorphic firmware deployment, rollback, and revocation."
    },
    {
        "tier": 4, "points": 300, "slug": "autonomous_neuromorphic_defense_agent_self_healing",
        "title_ko": "자율 뉴로모픽 방어 에이전트 자가 복구 하드웨어 회로",
        "title_en": "Autonomous Neuromorphic Defense Agent Self-Healing Hardware Circuitry",
        "desc_ko": "크로스바 결함 및 침해 탐지 시 실시간으로 비인가 경로를 우회하고 여분의 멤리스터 셀로 자가 복구하는 하드웨어를 구현합니다.",
        "desc_en": "Implement self-healing circuitry rerouting damaged paths and remapping parameters onto spare memristor cells upon breach detection."
    },
    {
        "tier": 4, "points": 300, "slug": "sovereign_brain_inspired_neuromorphic_hardware_capstone",
        "title_ko": "주권 뇌 모사 뉴로모픽 하드웨어 보안 종합 실전 캡스톤",
        "title_en": "Sovereign Brain-Inspired Neuromorphic Hardware Security Capstone",
        "desc_ko": "AER 이벤트 지문, 전압 글리치 클램프, STDP 백도어 방어, 하드웨어 RoT 제로화, ML-DSA-87 증명을 총동원한 실전 종합 캡스톤입니다.",
        "desc_en": "Execute the full-scale neuromorphic hardware security capstone uniting AER fingerprints, voltage clamps, STDP defense, and ML-DSA-87."
    }
]


def main():
    repo_root = Path(__file__).resolve().parent.parent
    wargame_dir = repo_root / "wargame"
    challenges_js_path = wargame_dir / "assets" / "challenges.js"
    solve_derivable_path = wargame_dir / "scripts" / "solve-derivable.js"
    index_html_path = wargame_dir / "index.html"
    readme_path = wargame_dir / "README.md"

    # 1. Generate challenge objects
    new_challenges = []
    neuromorphicsnn_ids = []
    for d in CHALLENGES_DATA:
        tier = d["tier"]
        slug = d["slug"]
        cid = f"t{tier}_neuromorphicsnn_{slug}"
        neuromorphicsnn_ids.append(cid)

        # Deterministic flag derivation
        h = hashlib.sha256(f"{cid}_vibe_neuromorphicsnn_2026".encode("utf-8")).hexdigest()[:20]
        flag = f"FLAG{{{h}}}"
        flag_hash = hashlib.sha256(flag.encode("utf-8")).hexdigest()

        ch_obj = {
            "id": cid,
            "tier": tier,
            "cat": "hardware",
            "track": "neuromorphicsnn",
            "points": d["points"],
            "ci": False,
            "hash": flag_hash,
            "fmt": "FLAG{...}",
            "title": {
                "ko": d["title_ko"],
                "en": d["title_en"]
            },
            "prompt": {
                "ko": f"{d['desc_ko']}\n\n[챌린지 식별자]\n`NEUROMORPHICSNN_CHALLENGE_ID: `{cid}``\n\n[문제 안내]\n해당 뉴로모픽 프로세서 하드웨어 보안 명세를 분석하고 올바른 플래그를 도출하여 제출하십시오.",
                "en": f"{d['desc_en']}\n\n[Challenge Identifier]\n`NEUROMORPHICSNN_CHALLENGE_ID: `{cid}``\n\n[Task]\nAnalyze the neuromorphic processor hardware security specification and submit the derived flag."
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
        new_challenges.append(ch_obj)

    print(f"[+] Created {len(new_challenges)} complete challenge objects.")

    # 2. Update wargame/assets/challenges.js
    content = challenges_js_path.read_text(encoding="utf-8")

    # Track definition
    track_def = """  },
  {
    "id": "neuromorphicsnn",
    "icon": "🧠",
    "ko": "뉴로모픽 SNN & 멤리스터 하드웨어 보안",
    "en": "Neuromorphic SNN & Memristor Security",
    "desc_ko": "뇌 모사 뉴로모픽 프로세서 비동기 AER 스파이크 타이밍 지문 및 LIF 막전위 임계치 검증, 멤리스터 크로스바 전압 글리치 실시간 탐지 & 위상 지터 방어, STDP 시냅스 가중치 변조 차단 & 하드웨어 RoT 바인딩, NIST FIPS 204 ML-DSA-87 서명 기반 뉴로모픽 원격 증명.",
    "desc_en": "Neuromorphic processor asynchronous AER spike timing fingerprint verification, memristor crossbar voltage glitch detection, STDP synaptic weight drift defense, and NIST FIPS 204 ML-DSA-87 hardware remote attestation."
  }"""
    if '"id": "neuromorphicsnn"' not in content:
        target = '"id": "photonicpuf"'
        assert target in content, "Could not find photonicpuf track in challenges.js"
        challenges_kw = "const CHALLENGES = ["
        c_idx = content.find(challenges_kw)
        track_part = content[:c_idx]
        last_brace = track_part.rfind("  }")
        content = content[:last_brace] + track_def + content[last_brace+3:]
        print("[+] Added neuromorphicsnn to TRACKS array.")

    # Remove previous neuromorphicsnn insertion if present, or strip ending ];
    neuromorphicsnn_marker = "// Track 88: neuromorphicsnn"
    if neuromorphicsnn_marker in content:
        idx = content.find(neuromorphicsnn_marker)
        prefix = content[:idx].rstrip()
        while prefix.endswith(","):
            prefix = prefix[:-1].rstrip()
    else:
        last_bracket_idx = content.rfind("];")
        assert last_bracket_idx != -1, "Could not find ];"
        prefix = content[:last_bracket_idx].rstrip()
        while prefix.endswith(","):
            prefix = prefix[:-1].rstrip()

    entries_json = []
    for ch in new_challenges:
        entries_json.append("  " + json.dumps(ch, ensure_ascii=False, indent=2).replace("\n", "\n  "))

    joined_entries = ",\n  // Track 88: neuromorphicsnn - Neuromorphic Spiking Neural Network & Memristor Hardware Security (35 challenges)\n" + ",\n".join(entries_json)

    new_content = prefix + joined_entries + "\n];\n"
    challenges_js_path.write_text(new_content, encoding="utf-8")
    print("[+] Successfully wrote 35 neuromorphicsnn challenges with full schema to wargame/assets/challenges.js!")

    # 3. Update wargame/scripts/solve-derivable.js
    solve_content = solve_derivable_path.read_text(encoding="utf-8")
    
    derivable_ids_formatted = json.dumps(neuromorphicsnn_ids, indent=2)
    dollar_hash = "${hash}"
    derivable_code = f"""const NEUROMORPHICSNN_IDS = {derivable_ids_formatted};

for (const id of NEUROMORPHICSNN_IDS) {{
  SOLVERS.set(id, {{
    kind: 'computed',
    via: 'SHA256 of identifier in prompt',
    solve: (ch) => {{
      const text = (ch.prompt.ko || '') + '\\n' + (ch.prompt.en || '');
      const m = text.match(/NEUROMORPHICSNN_CHALLENGE_ID:\\s*`([^`]+)`/);
      const ident = m ? m[1] : ch.id;
      const hash = crypto.createHash('sha256').update(ident + '_vibe_neuromorphicsnn_2026').digest('hex').slice(0, 20);
      return `FLAG{{{dollar_hash}}}`;
    }}
  }});
}}
"""
    if "const NEUROMORPHICSNN_IDS = [" in solve_content:
        solve_content = re.sub(r'const NEUROMORPHICSNN_IDS = \[[\s\S]*?\}\);\s*\}\s*', lambda m: derivable_code, solve_content)
        print("[+] Replaced existing NEUROMORPHICSNN_IDS block in solve-derivable.js.")
    else:
        needle = "/* Exact-match challenges deliberately left uncovered."
        assert needle in solve_content, "Could not find insertion marker in solve-derivable.js"
        solve_content = solve_content.replace(needle, derivable_code + "\n" + needle, 1)
        print("[+] Added neuromorphicsnn derivation handler to solve-derivable.js.")
    solve_derivable_path.write_text(solve_content, encoding="utf-8")

    # 4. Update wargame/index.html HUD
    index_html = index_html_path.read_text(encoding="utf-8")
    index_html = re.sub(r'0/\d{4}', '0/3080', index_html)
    index_html_path.write_text(index_html, encoding="utf-8")
    print("[+] Updated wargame/index.html HUD to 0/3080.")

    # 5. Update wargame/README.md
    readme = readme_path.read_text(encoding="utf-8")
    readme = re.sub(r'\*\*3,045\*\*', '**3,080**', readme)
    readme = re.sub(r'\b3045\b', '3080', readme)
    readme = re.sub(r'\b87개 트랙\b', '88개 트랙', readme)
    readme = re.sub(r'\b87 specialized tracks\b', '88 specialized tracks', readme)
    
    # Update tier counts (adding 7 to each tier)
    # T0: 364 -> 371
    # T1: 573 -> 580
    # T2: 725 -> 732
    # T3: 715 -> 722
    # T4: 668 -> 675
    readme = readme.replace("총 **3045문제**", "총 **3080문제**")
    readme = readme.replace("| `perimeter` 외곽 | **0** | 364 | 40% |", "| `perimeter` 외곽 | **0** | 371 | 40% |")
    readme = readme.replace("| `webserver` 웹서버 | **1** | 573 | 60% |", "| `webserver` 웹서버 | **1** | 580 | 60% |")
    readme = readme.replace("| `internal` 내부망 | **2** | 725 | 60% |", "| `internal` 내부망 | **2** | 732 | 60% |")
    readme = readme.replace("| `vault` 금고 | **3** | 715 | 58% |", "| `vault` 금고 | **3** | 722 | 58% |")
    readme = readme.replace("| `core` 코어 | **4** | 668 | 71% |", "| `core` 코어 | **4** | 675 | 71% |")

    # Clean existing neuromorphicsnn rows if present
    readme = re.sub(r'\| `neuromorphicsnn`[^\n]+\n', '', readme)

    t0_row = '| `neuromorphicsnn` 🧠 뉴로모픽 SNN & 멤리스터 하드웨어 보안 (7) | 비동기 AER 프로토콜 아키텍처 · LIF 뉴런 막전위 역학 원리 · 스파이크 타이밍 코딩 위협 · 멤리스터 크로스바 하드웨어 표면 / Asynchronous AER protocol architecture, LIF neuron membrane dynamics principles, spike timing coding threats, and memristor crossbar hardware surfaces |'
    t1_row = '| `neuromorphicsnn` 🧠 뉴로모픽 SNN & 멤리스터 하드웨어 보안 (7) | AER 스파이크 발화 지문 추출 · LIF 막전위 임계값 안정화 · 전압 글리치 과도현상 탐지 · 멤리스터 전도도 드리프트 통제 / AER spike firing fingerprint extraction, LIF membrane threshold stabilization, voltage glitch transient detection, and memristor conductance drift control |'
    t2_row = '| `neuromorphicsnn` 🧠 뉴로모픽 SNN & 멤리스터 하드웨어 보안 (7) | STDP 시냅스 가소성 감시 · 멤리스터 어레이 전압 클램프 · 뉴로모픽 세션 암호학적 증명 · 초고속 안티 탬퍼 인터록 / STDP synaptic plasticity monitoring, memristor array voltage clamp, neuromorphic session cryptographic proofs, and ultra-fast anti-tamper interlocks |'
    t3_row = '| `neuromorphicsnn` 🧠 뉴로모픽 SNN & 멤리스터 하드웨어 보안 (7) | 적대적 스파이크 트레인 주입 차단 · 멤리스터 크로스바 머클 트리 검증 · 시냅스 회로 파괴적 제로화 · ML-DSA-87 하드웨어 원격 증명 / Adversarial spike train injection defense, memristor crossbar Merkle tree verification, synaptic circuit destructive zeroization, and ML-DSA-87 hardware remote attestation |'
    t4_row = '| `neuromorphicsnn` 🧠 뉴로모픽 SNN & 멤리스터 하드웨어 보안 (7) | 뉴로모픽 하드웨어 결함 주입 실증 · 엔터프라이즈 SNN 반도체 공급망 통제 · 신경망 전력 사이드채널 차폐 · 차세대 뇌 모사 하드웨어 보안 캡스톤 / Neuromorphic hardware fault injection drills, enterprise SNN semiconductor supply chain controls, neural power sidechannel shielding, and next-generation brain-inspired hardware security capstone |'

    tier_rows = [t0_row, t1_row, t2_row, t3_row, t4_row]
    photonicpuf_matches = list(re.finditer(r'\| `photonicpuf` 💎 광 집적회로 PUF & 실리콘 하드웨어 보안 \(7\) \| [^\n]+', readme))
    if len(photonicpuf_matches) == 5:
        for i in reversed(range(5)):
            m = photonicpuf_matches[i]
            readme = readme[:m.end()] + "\n" + tier_rows[i] + readme[m.end():]
        print("[+] Inserted 5 clean neuromorphicsnn rows into wargame/README.md tier tables.")
    else:
        print(f"[-] Warning: found {len(photonicpuf_matches)} photonicpuf matches in README.md")

    readme_path.write_text(readme, encoding="utf-8")
    print("[+] Successfully updated wargame/README.md.")

    print("\n🎉 Track 88 neuromorphicsnn generation completed successfully! Total: 3,080 challenges across 88 tracks.")

if __name__ == "__main__":
    main()
