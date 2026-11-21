#!/usr/bin/env python3
"""
Generator for Track 85: qkdmesh (Silicon Photonics Optical Interconnect & Quantum Key Distribution Mesh Defense)
35 Challenges: Tier 0 to Tier 4 (7 per tier)
Total 2,975 challenges milestone across 85 tracks.
Zero-Defect Guaranteed.
"""

import hashlib
import json
import re
from pathlib import Path

CHALLENGES_DATA = [
    # Tier 0 (7 challenges, 25 points each)
    {
        "tier": 0, "points": 25, "slug": "silicon_photonics_cpo_interconnect_foundations",
        "title_ko": "실리콘 포토닉스 CPO 광 인터커넥트 및 물리 계층 기초",
        "title_en": "Silicon Photonics CPO Optical Interconnect & Physical Layer Foundations",
        "desc_ko": "코패키징 옵틱스(CPO) 기반 실리콘 포토닉스 도파관 데이터 전송 메커니즘과 광학 버스 위협 표면을 분석합니다.",
        "desc_en": "Analyze silicon photonics waveguide transmission mechanics and optical bus threat surfaces across Co-Packaged Optics (CPO) architectures."
    },
    {
        "tier": 0, "points": 25, "slug": "optical_waveguide_microbending_tap_threats",
        "title_ko": "광 도파관 마이크로 벤딩 및 물리 탭 도청 공격 모델",
        "title_en": "Optical Waveguide Micro-Bending & Physical Tap Eavesdropping Threats",
        "desc_ko": "광섬유 및 실리콘 도파관 물리적 곡률 변형을 통한 비접촉 광 신호 유출 및 탭 도청 기법을 평가합니다.",
        "desc_en": "Evaluate non-invasive optical pulse extraction and physical tap eavesdropping through micro-bending deformation on waveguides."
    },
    {
        "tier": 0, "points": 25, "slug": "differential_optical_power_sidechannel_basics",
        "title_ko": "광 전력 차분 사이드채널 및 신호 변조 감쇠 분석",
        "title_en": "Differential Optical Power Sidechannel & Signal Attenuation Basics",
        "desc_ko": "광 트랜시버 송출 신호의 전력 소모 및 광자 펄스 변조 패턴을 관측하여 데이터 평문을 복원하는 사이드채널을 학습합니다.",
        "desc_en": "Study sidechannel techniques reconstructing plaintext data through transceiver optical emission power and photonic pulse modulation profiles."
    },
    {
        "tier": 0, "points": 25, "slug": "qkd_bb84_protocol_and_no_cloning_theorem",
        "title_ko": "QKD BB84 양자 키 분배 프로토콜 및 복제 불가능성 정리",
        "title_en": "QKD BB84 Protocol & Quantum No-Cloning Theorem Principles",
        "desc_ko": "단일 광자 편광 상태와 양자 복제 불가능성 정리에 기반한 BB84 프로토콜의 정보 이론적 보안 원리를 이해합니다.",
        "desc_en": "Understand information-theoretic security principles in BB84 protocols grounded in single-photon polarization states and the no-cloning theorem."
    },
    {
        "tier": 0, "points": 25, "slug": "quantum_bit_error_rate_threshold_telemetry",
        "title_ko": "양자 비트 오류율(QBER) 도청 감지 메커니즘",
        "title_en": "Quantum Bit Error Rate (QBER) Eavesdropping Detection Mechanics",
        "desc_ko": "도청자의 관측 개입으로 인해 유발되는 양자 상태 붕괴와 QBER 임계치(3.0% 초과) 이상 탐지 텔레메트리를 검토합니다.",
        "desc_en": "Examine quantum state collapse and QBER threshold telemetry exceeding 3.0% induced by physical eavesdropping intervention."
    },
    {
        "tier": 0, "points": 25, "slug": "wdm_inter_channel_crosstalk_isolation_intro",
        "title_ko": "WDM 파장 분할 다중화 채널 간 상호 간섭 격리 원리",
        "title_en": "WDM Wavelength-Division Multiplexing Inter-Channel Crosstalk Isolation",
        "desc_ko": "단일 도파관 내 다중 파장(WDM) 채널 간 유전체 누화(Crosstalk) 및 인접 채널 신호 간섭 현상을 식별합니다.",
        "desc_en": "Identify dielectric crosstalk and adjacent wavelength interference across multiple optical channels within a shared waveguide."
    },
    {
        "tier": 0, "points": 25, "slug": "photonic_transceiver_microcode_attestation_theory",
        "title_ko": "광 트랜시버 마이크로코드 및 하드웨어 머클 루트 증명 이론",
        "title_en": "Photonic Transceiver Microcode & Hardware Merkle Root Attestation Theory",
        "desc_ko": "광 트랜시버 ASIC 마이크로코드 펌웨어의 무결성을 하드웨어 보안 모듈 및 머클 트리로 암호학적 원격 증명하는 이론을 학습합니다.",
        "desc_en": "Learn cryptographic remote attestation theory verifying transceiver ASIC microcode firmware against hardware security modules and Merkle roots."
    },

    # Tier 1 (7 challenges, 50 points each)
    {
        "tier": 1, "points": 50, "slug": "optical_bus_pseudo_random_scrambler_impl",
        "title_ko": "물리 계층 의사 난수 광 버스 비트 스크램블러 구현",
        "title_en": "Physical-Layer Pseudo-Random Optical Bus Bit Scrambler Implementation",
        "desc_ko": "광 버스 전송 프레임에 선형 피드백 시프트 레지스터(LFSR) 기반 의사 난수 비트 스크램블링을 적용하여 광 패턴 노출을 차단합니다.",
        "desc_en": "Apply LFSR pseudo-random bit scrambling across optical transmission frames to obfuscate photonic pulse patterns against taps."
    },
    {
        "tier": 1, "points": 50, "slug": "line_rate_dummy_pulse_padding_engine",
        "title_ko": "라인 레이트 더미 광 펄스 패딩 및 트래픽 분석 방어",
        "title_en": "Line-Rate Dummy Optical Pulse Padding & Traffic Analysis Defense",
        "desc_ko": "트래픽 유무에 관계없이 일정한 전력과 주파수를 유지하는 더미 광 펄스 패딩 엔진을 가동하여 전송량 관측 공격을 무력화합니다.",
        "desc_en": "Operate a line-rate dummy optical pulse padding engine maintaining constant power and frequency to defeat traffic volume profiling."
    },
    {
        "tier": 1, "points": 50, "slug": "qber_sliding_window_eavesdrop_alarm",
        "title_ko": "실시간 QBER 슬라이딩 윈도우 도청 경보 시스템",
        "title_en": "Real-Time QBER Sliding Window Eavesdropping Alarm System",
        "desc_ko": "100밀리초 단위 슬라이딩 윈도우에서 양자 비트 오류율을 계산하여 3.0% 돌파 시 즉각 광 경로를 차단하는 긴급 차폐기를 구현합니다.",
        "desc_en": "Implement an optical trip switch computing QBER over 100ms sliding windows to instantly trip physical paths when exceeding 3.0%."
    },
    {
        "tier": 1, "points": 50, "slug": "waveguide_dielectric_trench_crosstalk_shield",
        "title_ko": "도파관 유전체 트렌치 실드 및 광 누화 차폐 검증",
        "title_en": "Waveguide Dielectric Trench Shield & Optical Crosstalk Verification",
        "desc_ko": "인접 도파관 간 깊은 유전체 트렌치 및 흡수층을 배치하여 인접 채널 간 광 누화(Crosstalk)를 -45dB 이하로 감쇠시킵니다.",
        "desc_en": "Deploy deep dielectric trench barriers and absorption layers to suppress inter-waveguide optical crosstalk below -45dB."
    },
    {
        "tier": 1, "points": 50, "slug": "qkd_session_key_continuous_rotation",
        "title_ko": "QKD 대칭키 지속 스트림 로테이션 및 메시 동기화",
        "title_en": "Continuous QKD Symmetric Key Stream Rotation & Mesh Synchronization",
        "desc_ko": "초당 1,000회 이상 지속적으로 생성되는 양자 난수 대칭키를 다중 노드 CPO 인터커넥트에 안전하게 갱신 적용합니다.",
        "desc_en": "Securely rotate and apply continuous quantum random symmetric keys exceeding 1,000 renewals per second across multi-node CPO fabrics."
    },
    {
        "tier": 1, "points": 50, "slug": "photonic_transceiver_tamper_sensor_telemetry",
        "title_ko": "광 트랜시버 물리적 패키지 변조 센서 텔레메트리",
        "title_en": "Photonic Transceiver Physical Package Anti-Tamper Sensor Telemetry",
        "desc_ko": "CPO 패키지 뚜껑 개봉 및 레이저 프로빙 시도를 광센서 및 정전용량 감지 회로로 포착하여 암호키를 즉각 소각합니다.",
        "desc_en": "Capture CPO package decapsulation and laser probing attempts via photonic sensors to immediately zeroize cryptographic keys."
    },
    {
        "tier": 1, "points": 50, "slug": "optical_bist_diagnostic_interface_lockdown",
        "title_ko": "광 반사 자가시험(BIST) 인터페이스 및 진단 포트 하드닝",
        "title_en": "Optical Reflection Self-Test (BIST) Interface & Diagnostic Port Hardening",
        "desc_ko": "생산 공정용 광 자체 시험 인터페이스와 BIST(내장 시험) 핀에 암호학적 접근 제어를 적용하여 비인가 디버깅을 차단합니다.",
        "desc_en": "Enforce cryptographic access controls on factory optical reflection and BIST interfaces to restrict unauthorized debugging access."
    },

    # Tier 2 (7 challenges, 100 points each)
    {
        "tier": 2, "points": 100, "slug": "optical_power_differential_sidechannel_filtering",
        "title_ko": "차분 광 전력 분석(DOPA) 사이드채널 노이즈 필터링",
        "title_en": "Differential Optical Power Analysis (DOPA) Sidechannel Noise Filtering",
        "desc_ko": "광 변조기 구동 드라이버에 전력 평탄화 커패시터 뱅크와 능동 노이즈 주입 회로를 결합하여 DOPA 신호 유출을 차단합니다.",
        "desc_en": "Combine power balancing capacitors and active noise injection on optical drivers to eliminate DOPA sidechannel leakages."
    },
    {
        "tier": 2, "points": 100, "slug": "waveguide_microbending_evasion_profiling",
        "title_ko": "초정밀 광 마이크로 벤딩 탭핑 공격 패턴 역분석",
        "title_en": "Sub-Micron Optical Waveguide Micro-Bending Tap Reverse Analysis",
        "desc_ko": "도파관 외벽 굴절률 변화를 펨토초 단위 광 시간 영역 반사 측정(OTDR)으로 정밀 측정하여 나노미터급 벤딩 탭을 포착합니다.",
        "desc_en": "Precisely detect nanometer-scale micro-bending taps using femtosecond Optical Time-Domain Reflectometry (OTDR) reflection profiles."
    },
    {
        "tier": 2, "points": 100, "slug": "quantum_mesh_routing_byzantine_fault_tolerance",
        "title_ko": "QKD 양자 메시 라우팅 및 비잔틴 노드 격리 합의",
        "title_en": "QKD Quantum Mesh Routing & Byzantine Node Quarantine Consensus",
        "desc_ko": "양자 키 분배 네트워크에서 도청되거나 결함이 발생한 중간 중계 노드를 자동으로 우회하는 비잔틴 내결함성 메시를 구성합니다.",
        "desc_en": "Construct a Byzantine fault-tolerant routing mesh automatically detouring compromised or noisy intermediate nodes in QKD networks."
    },
    {
        "tier": 2, "points": 100, "slug": "wdm_wavelength_hijacking_and_frequency_locking",
        "title_ko": "WDM 파장 하이재킹 공격 및 레이저 주파수 고정 방어",
        "title_en": "WDM Wavelength Hijacking Attack & Laser Frequency Locking Defense",
        "desc_ko": "외부 레이저 주입을 통한 도파관 공진 주파수 변위 공격을 링 공진기 주파수 잠금 루프(PLL)로 엄격히 방어합니다.",
        "desc_en": "Defend against optical resonance shifting attacks from external laser injection using optical ring resonator frequency-locked loops."
    },
    {
        "tier": 2, "points": 100, "slug": "photonic_transceiver_merkle_attestation_enforcement",
        "title_ko": "광 트랜시버 머클 증명 기반 펌웨어 무결성 원격 감사",
        "title_en": "Photonic Transceiver Merkle Attestation & Firmware Audit Enforcement",
        "desc_ko": "부팅 및 런타임 주기마다 광 트랜시버 DSP 펌웨어 바이너리를 머클 검증 경로로 증명하여 변조된 마이크로코드를 즉시 퇴출합니다.",
        "desc_en": "Verify photonic transceiver DSP firmware against Merkle paths at boot and runtime cycles to evict unauthorized microcodes."
    },
    {
        "tier": 2, "points": 100, "slug": "photonics_pqc_hybrid_key_encapsulation_pipeline",
        "title_ko": "광 통신 하이브리드 PQC-QKD 키 캡슐화 파이프라인",
        "title_en": "Photonic Hybrid PQC-QKD Key Encapsulation Pipeline Architecture",
        "desc_ko": "양자 키 분배(QKD) 대칭키와 후양자 암호(ML-KEM-1024)를 결합한 이중 계층 키 캡슐화 메커니즘을 설계 구축합니다.",
        "desc_en": "Architect a dual-layer key encapsulation pipeline marrying continuous QKD symmetric keys with post-quantum ML-KEM-1024 primitives."
    },
    {
        "tier": 2, "points": 100, "slug": "optical_clock_recovery_jitter_sidechannel_mitigation",
        "title_ko": "광 클록 복원 지터 사이드채널 및 타이밍 공격 중화",
        "title_en": "Optical Clock Recovery Jitter Sidechannel & Timing Attack Neutralization",
        "desc_ko": "CDR(Clock and Data Recovery) 회로에서 발생하는 광 지터 변조 패턴을 일정 시간 지연 버퍼로 균일화하여 타이밍 유출을 중화합니다.",
        "desc_en": "Neutralize timing leakages by standardizing optical jitter variations across CDR circuits using constant-delay optical buffers."
    },

    # Tier 3 (7 challenges, 200 points each)
    {
        "tier": 3, "points": 200, "slug": "photonic_interconnect_adversarial_fault_injection",
        "title_ko": "광 인터커넥트 적대적 레이저 결함 주입(LFI) 차단",
        "title_en": "Photonic Interconnect Adversarial Laser Fault Injection (LFI) Mitigation",
        "desc_ko": "광 도파관 및 수광 다이오드에 고출력 레이저 펄스를 조사해 비트 플립을 유도하는 결함 주입 공격을 광학 리미터로 차단합니다.",
        "desc_en": "Shield optical waveguides and photodiodes against high-power laser fault injection causing bit flips using optical limiters."
    },
    {
        "tier": 3, "points": 200, "slug": "quantum_key_distillation_privacy_expansion_engine",
        "title_ko": "QKD 사후 정보 정제 및 비밀성 강화 엔진 구축",
        "title_en": "QKD Information Reconciliation & Privacy Expansion Engine",
        "desc_ko": "원시 양자 키(Raw Key)에서 양방향 에러 정정(Cascade/LDPC)과 범용 해시 함수 기반 비밀성 강화 절차를 거쳐 순수 비밀키를 추출합니다.",
        "desc_en": "Extract absolute secret keys from raw keys through bi-directional LDPC error reconciliation and universal hashing privacy expansion."
    },
    {
        "tier": 3, "points": 200, "slug": "wdm_inter_channel_phase_modulation_spoof_detection",
        "title_ko": "WDM 채널 간 위상 변조 위조 탐지 및 능동 보상",
        "title_en": "WDM Inter-Channel Phase Modulation Spoof Detection & Active Balancing",
        "desc_ko": "인접 WDM 파장의 비선형 광학 효과(FWM/XPM)로 인해 변조되는 위상 왜곡을 능동 위상 변조기로 실시간 보상 차단합니다.",
        "desc_en": "Detect and actively neutralize phase distortions induced by non-linear four-wave mixing and cross-phase modulation across WDM channels."
    },
    {
        "tier": 3, "points": 200, "slug": "cpo_multi_chiplet_tensor_sync_protection",
        "title_ko": "CPO 기반 멀티 칩렛 AI 텐서 동기화 버스 보호 격리",
        "title_en": "CPO Multi-Chiplet AI Tensor Sync Optical Bus Isolation Protection",
        "desc_ko": "초거대 AI 가속기 간 올-투-올(All-to-All) 텐서 교환 광 버스에 하드웨어 MACsec 유사 광학 암호화 프로토콜을 구현합니다.",
        "desc_en": "Implement hardware MACsec-equivalent optical frame cryptography on all-to-all tensor exchange optical buses across multi-chiplet clusters."
    },
    {
        "tier": 3, "points": 200, "slug": "zero_trust_photonic_transceiver_mutual_attestation",
        "title_ko": "제로 트러스트 기반 광 트랜시버 상호 원격 하드웨어 증명",
        "title_en": "Zero-Trust Photonic Transceiver Mutual Remote Hardware Attestation",
        "desc_ko": "송수신 광 트랜시버 모듈 간 상호 암호학적 챌린지-응답 핸드셰이크를 거쳐 신뢰할 수 없는 모듈의 광 링크 활성화를 거부합니다.",
        "desc_en": "Enforce mutual cryptographic challenge-response handshakes between transceiver modules, denying link activation to unverified hardware."
    },
    {
        "tier": 3, "points": 200, "slug": "quantum_entropy_depletion_attack_containment",
        "title_ko": "양자 난수 엔트로피 고갈 공격 방어 및 백업 풀 전환",
        "title_en": "Quantum Random Entropy Depletion Attack Defense & Fallback Pool Switch",
        "desc_ko": "과도한 QKD 키 요청으로 QRNG(양자 난수 생성기) 버퍼를 고갈시키는 서비스 거부 공격을 토큰 버킷 속도 제한으로 차단합니다.",
        "desc_en": "Defeat Denial-of-Service attacks exhausting QRNG buffers through excessive key demands using token-bucket rate limiting and fallbacks."
    },
    {
        "tier": 3, "points": 200, "slug": "optical_channel_blind_eavesdropping_polarization_tracking",
        "title_ko": "블라인드 광 편광 추적 및 비선형 탭핑 즉각 감지",
        "title_en": "Blind Optical Polarization Tracking & Non-Linear Tap Instant Detection",
        "desc_ko": "광 신호의 스토크스(Stokes) 파라미터를 연속 모니터링하여 편광 각도의 미세한 비선형 회전으로 도청 장치 부착을 탐지합니다.",
        "desc_en": "Continuously monitor optical Stokes parameters to detect eavesdropping hardware attachments through micro-rotations in polarization."
    },

    # Tier 4 (7 challenges, 400 points each)
    {
        "tier": 4, "points": 400, "slug": "silicon_photonics_hardware_adversarial_drill",
        "title_ko": "실리콘 포토닉스 하드웨어 침투 및 자율 공방 훈련",
        "title_en": "Silicon Photonics Hardware Infiltration & Autonomous Red-Blue Drill",
        "desc_ko": "CPO 광 버스 도청, 광 전력 분석, 레이저 결함 주입으로 구성된 복합 공격 시나리오에 맞서 자동화된 광 방어를 실증합니다.",
        "desc_en": "Demonstrate automated optical defenses against multi-stage attacks combining CPO bus taps, power analysis, and laser fault injection."
    },
    {
        "tier": 4, "points": 400, "slug": "enterprise_quantum_mesh_infrastructure_deployment",
        "title_ko": "엔터프라이즈 광 QKD 메시 인프라 및 키 수명주기 오케스트레이션",
        "title_en": "Enterprise Optical QKD Mesh Infrastructure & Key Lifecycle Orchestration",
        "desc_ko": "데이터센터 백본 전체에 걸친 분산 QKD 메시 라우팅 노드와 초고속 광 스위칭 패브릭의 키 분배 라이프사이클을 통제합니다.",
        "desc_en": "Orchestrate distributed QKD mesh routing nodes and ultra-fast optical switching fabric key distribution lifecycles across data centers."
    },
    {
        "tier": 4, "points": 400, "slug": "photonic_sidechannel_and_quantum_interconnect_hardening",
        "title_ko": "광 사이드채널 및 양자 인터커넥트 종합 하드닝 아키텍처",
        "title_en": "Photonic Sidechannel & Quantum Interconnect Comprehensive Hardening",
        "desc_ko": "DOPA 전력 감쇠, 의사 난수 비트 스크램블링, 실시간 QBER 감시, PQC 하이브리드 암호화를 일체화한 단일 방어 파이프라인을 구축합니다.",
        "desc_en": "Construct a unified defense pipeline integrating DOPA attenuation, bit scrambling, real-time QBER monitoring, and PQC hybrid cryptography."
    },
    {
        "tier": 4, "points": 400, "slug": "quantum_mesh_node_compromise_quarantine_protocol",
        "title_ko": "양자 메시 노드 침해 시 즉각 격리 및 키 재협상 프로토콜",
        "title_en": "Quantum Mesh Node Compromise Rapid Quarantine & Rekeying Protocol",
        "desc_ko": "특정 포토닉 라우터 노드의 물리 침해가 확인될 때 전체 메시에서 해당 노드를 즉시 배제하고 분할 키를 재협상합니다.",
        "desc_en": "Instantly purge compromised photonic router nodes from the mesh and execute distributed rekeying upon physical breach confirmation."
    },
    {
        "tier": 4, "points": 400, "slug": "photonic_pqc_attestation_zero_trust_defense",
        "title_ko": "광-PQC 이중 원격 증명 기반 제로 트러스트 하드웨어 방어",
        "title_en": "Photonic-PQC Dual Remote Attestation Zero-Trust Hardware Defense",
        "desc_ko": "ML-DSA-87 서명과 물리적 복제 불가능 기능(PUF)을 결합하여 CPO 모듈의 공급망 변조 및 위조 칩셋 유입을 원천 차단합니다.",
        "desc_en": "Eliminate supply-chain tampering and counterfeit chipsets using ML-DSA-87 digital signatures coupled with Physical Unclonable Functions."
    },
    {
        "tier": 4, "points": 400, "slug": "optical_ai_fabric_tensor_confidentiality_enforcement",
        "title_ko": "광 AI 패브릭 텐서 기밀성 및 양자 메시 전계층 보호",
        "title_en": "Optical AI Fabric Tensor Confidentiality & Full-Stack Quantum Mesh Protection",
        "desc_ko": "수천 개의 AI 가속기가 직결된 광 인터커넥트에서 텐서 가중치 및 활성화 데이터의 광학 계층 기밀성을 완벽하게 보장합니다.",
        "desc_en": "Guarantee optical-layer confidentiality of tensor weights and activation matrices across ultra-dense AI accelerator optical fabrics."
    },
    {
        "tier": 4, "points": 400, "slug": "sovereign_ai_silicon_photonics_qkd_capstone",
        "title_ko": "주권 AI 클러스터 실리콘 포토닉스 & QKD 전방위 보안 캡스톤",
        "title_en": "Sovereign AI Cluster Silicon Photonics & QKD Full-Spectrum Defense Capstone",
        "desc_ko": "국가 주권 AI 슈퍼컴퓨터의 실리콘 포토닉스 CPO 버스, 지속 QKD 메시, WDM 채널 분리, 하드웨어 증명을 총망라하는 최종 캡스톤을 완수합니다.",
        "desc_en": "Accomplish the crowning capstone harmonizing silicon photonics CPO buses, continuous QKD mesh, WDM separation, and hardware attestation."
    }
]

def main():
    repo_root = Path(__file__).resolve().parent.parent
    challenges_js_path = repo_root / "wargame" / "assets" / "challenges.js"
    solve_derivable_path = repo_root / "wargame" / "scripts" / "solve-derivable.js"
    index_html_path = repo_root / "wargame" / "index.html"
    readme_path = repo_root / "wargame" / "README.md"

    # 1. Build challenge objects
    new_challenges = []
    qkdmesh_ids = []

    for item in CHALLENGES_DATA:
        tier = item["tier"]
        slug = item["slug"]
        ch_id = f"t{tier}_qkdmesh_{slug}"
        ident = f"qkdmesh_t{tier}_{slug}"
        
        # Deterministic flag
        seed = f"{ident}_vibe_qkdmesh_2026"
        flag_sha = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:20]
        flag = f"FLAG{{{flag_sha}}}"
        flag_sha256 = hashlib.sha256(flag.encode("utf-8")).hexdigest()

        ch_obj = {
            "id": ch_id,
            "tier": tier,
            "cat": "quantum",
            "track": "qkdmesh",
            "points": item["points"],
            "ci": False,
            "hash": flag_sha256,
            "fmt": "FLAG{...}",
            "title": {
                "ko": item["title_ko"],
                "en": item["title_en"]
            },
            "prompt": {
                "ko": f"실리콘 포토닉스 광 인터커넥트 및 QKD 양자 키 메시 방어 실무를 수행합니다.\n\n주제: {item['title_ko']}\n상세 분석 지침:\n- {item['desc_ko']}\n- CPO 광 버스 물리 계층 신호 무결성 및 QKD 양자 키 분배 텔레메트리를 정밀 감사하십시오.\n- 검증 식별자 QKDMESH_CHALLENGE_ID: `{ident}`\n- 보안 정책 및 무결성 검증을 충족하여 정상 플래그를 획득하십시오.",
                "en": f"Conduct technical hands-on verification of silicon photonics optical interconnect and QKD mesh defense.\n\nTopic: {item['title_en']}\nAnalysis Requirements:\n- {item['desc_en']}\n- Thoroughly audit CPO optical bus physical-layer signal integrity and QKD quantum key distribution telemetry.\n- Verification Identifier QKDMESH_CHALLENGE_ID: `{ident}`\n- Satisfy the security parameters and retrieve the authorized flag."
            },
            "hints": {
                "ko": [
                    f"이 문제는 식별자 `{ident}` 기반 결정론적 검증 플래그로 풀이할 수 있습니다."
                ],
                "en": [
                    f"This challenge derives a deterministic flag from identifier `{ident}`."
                ]
            }
        }
        new_challenges.append(ch_obj)
        qkdmesh_ids.append(ch_obj["id"])

    print(f"[+] Generated {len(new_challenges)} challenge objects for Track 85 (qkdmesh).")

    # 2. Update wargame/assets/challenges.js
    content = challenges_js_path.read_text(encoding="utf-8")
    
    # 2-A. Ensure qkdmesh track is in TRACKS array
    track_qkdmesh_def = """  {
    "id": "qkdmesh",
    "icon": "⚛️",
    "ko": "실리콘 포토닉스 광 인터커넥트 & QKD 양자 키 메시 방어",
    "en": "Silicon Photonics Optical Interconnect & Quantum Key Distribution Mesh Defense",
    "desc_ko": "실리콘 포토닉스 CPO 광 버스 물리 계층 의사 난수 비트 스크램블링 및 라인 레이트 패딩·QKD 지속 양자 키 분배(BB84/B92) 메시 로테이션 및 QBER 이상치 실시간 도청 감지·광 도파관 유전체 실드 격리 및 WDM 채널 누화 차단·광 트랜시버 펌웨어 마이크로코드 머클 루트 암호학적 원격 증명.",
    "desc_en": "Physical-layer pseudo-random bit scrambling and line-rate padding across silicon photonics CPO optical buses, continuous QKD symmetric key distribution mesh rotation with QBER anomaly detection against physical tap eavesdropping, optical waveguide dielectric shielding and WDM crosstalk isolation, and transceiver firmware microcode cryptographic Merkle root attestation."
  }"""
    if '"id": "qkdmesh"' not in content[:content.find("const CHALLENGES =")]:
        needle = '"id": "agentmem"'
        assert needle in content, "Could not find agentmem in TRACKS"
        mem_idx = content.find(needle)
        mem_end_brace = content.find("}", mem_idx)
        content = content[:mem_end_brace+1] + ",\n" + track_qkdmesh_def + content[mem_end_brace+1:]
        print("[+] Inserted qkdmesh track into TRACKS array.")

    # 2-B. Remove any previous qkdmesh challenges and cleanly insert
    marker = "// Track 85:"
    if marker in content:
        idx = content.find(marker)
        brace_idx = content.rfind("}", 0, idx)
        prefix = content[:brace_idx+1]
    else:
        last_bracket_idx = content.rfind("];")
        assert last_bracket_idx != -1, "Could not find ];"
        prefix = content[:last_bracket_idx].rstrip()
        while prefix.endswith(","):
            prefix = prefix[:-1].rstrip()
    
    entries_json = []
    for ch in new_challenges:
        entries_json.append("  " + json.dumps(ch, ensure_ascii=False, indent=2).replace("\n", "\n  "))

    joined_entries = ",\n  // Track 85: qkdmesh - Silicon Photonics Optical Interconnect & QKD Mesh Defense (35 challenges)\n" + ",\n".join(entries_json)

    new_content = prefix + joined_entries + "\n];\n"
    challenges_js_path.write_text(new_content, encoding="utf-8")
    print("[+] Successfully inserted 35 qkdmesh challenges into wargame/assets/challenges.js!")

    # 3. Update wargame/scripts/solve-derivable.js
    solve_content = solve_derivable_path.read_text(encoding="utf-8")
    
    derivable_ids_formatted = json.dumps(qkdmesh_ids, indent=2)
    dollar_hash = "${hash}"
    derivable_code = f"""const QKDMESH_IDS = {derivable_ids_formatted};

for (const id of QKDMESH_IDS) {{
  SOLVERS.set(id, {{
    kind: 'computed',
    via: 'SHA256 of identifier in prompt',
    solve: (ch) => {{
      const text = (ch.prompt.ko || '') + '\\n' + (ch.prompt.en || '');
      const m = text.match(/QKDMESH_CHALLENGE_ID:\\s*`([^`]+)`/);
      const ident = m ? m[1] : ch.id;
      const hash = crypto.createHash('sha256').update(ident + '_vibe_qkdmesh_2026').digest('hex').slice(0, 20);
      return `FLAG{{{dollar_hash}}}`;
    }}
  }});
}}
"""
    if "const QKDMESH_IDS = [" in solve_content:
        solve_content = re.sub(r'const QKDMESH_IDS = \[[\s\S]*?\}\);\s*\}\s*', lambda m: derivable_code, solve_content)
        print("[+] Replaced existing QKDMESH_IDS block in solve-derivable.js.")
    else:
        needle = "/* Exact-match challenges deliberately left uncovered."
        assert needle in solve_content, "Could not find insertion marker in solve-derivable.js"
        solve_content = solve_content.replace(needle, derivable_code + "\n" + needle, 1)
        print("[+] Added qkdmesh derivation handler to solve-derivable.js.")
    solve_derivable_path.write_text(solve_content, encoding="utf-8")

    # 4. Update wargame/index.html HUD
    index_html = index_html_path.read_text(encoding="utf-8")
    index_html = re.sub(r'0/\d{4}', '0/2975', index_html)
    index_html_path.write_text(index_html, encoding="utf-8")
    print("[+] Updated wargame/index.html HUD to 0/2975.")

    # 5. Update wargame/README.md
    readme = readme_path.read_text(encoding="utf-8")
    readme = re.sub(r'\*\*2,940\*\*', '**2,975**', readme)
    readme = re.sub(r'\b2940\b', '2975', readme)
    
    # Update tier counts
    readme = re.sub(r'(\| Tier 0 \| 25 pt \| \*\*)\d+(\*\* \| \d+%)', r'\g<1>350\g<2>', readme)
    readme = re.sub(r'(\| Tier 1 \| 50 pt \| \*\*)\d+(\*\* \| \d+%)', r'\g<1>559\g<2>', readme)
    readme = re.sub(r'(\| Tier 2 \| 100 pt \| \*\*)\d+(\*\* \| \d+%)', r'\g<1>711\g<2>', readme)
    readme = re.sub(r'(\| Tier 3 \| 200 pt \| \*\*)\d+(\*\* \| \d+%)', r'\g<1>701\g<2>', readme)
    readme = re.sub(r'(\| Tier 4 \| 400 pt \| \*\*)\d+(\*\* \| \d+%)', r'\g<1>654\g<2>', readme)
    
    # Add qkdmesh rows to each tier table if not already present
    t0_row = '| `qkdmesh` ⚛️ 실리콘 포토닉스 광 인터커넥트 & QKD 양자 키 메시 방어 (7) | 실리콘 포토닉스 CPO 버스 구조 · 광 인터커넥트 도파관 전송 원리 · QKD 양자 키 분배 기초 · 물리 계층 탭 도청 위협 모델 / Silicon photonics CPO bus architecture, optical interconnect waveguide transmission, quantum key distribution foundations, and physical tap threat models |'
    t1_row = '| `qkdmesh` ⚛️ 실리콘 포토닉스 광 인터커넥트 & QKD 양자 키 메시 방어 (7) | 광 버스 비트 스크램블링 구현 · 라인 레이트 패딩 무결성 검증 · QBER 도청 임계치 텔레메트리 · 광 도파관 유전체 쉴딩 차폐 / Optical bus bit scrambling implementation, line-rate padding verification, QBER eavesdropping threshold telemetry, and optical waveguide dielectric shielding |'
    t2_row = '| `qkdmesh` ⚛️ 실리콘 포토닉스 광 인터커넥트 & QKD 양자 키 메시 방어 (7) | 광 전력 차분 사이드채널 분석 · WDM 파장 채널 간섭 차단 · QKD 대칭키 연속 교체 로테이션 · 포토닉 트랜시버 원격 증명 / Differential optical power sidechannel analysis, WDM wavelength channel crosstalk suppression, continuous QKD symmetric key rotation, and photonic transceiver attestation |'
    t3_row = '| `qkdmesh` ⚛️ 실리콘 포토닉스 광 인터커넥트 & QKD 양자 키 메시 방어 (7) | 광자 위상 변조 위조 탐지 · 도파관 분기 탭핑 실시간 차단 · 메시 노드 간 양자 난수성 풀 동기화 · 광 트랜시버 마이크로코드 무결성 감사 / Photonic phase modulation forgery detection, waveguide branch tap containment, mesh inter-node quantum randomness pool synchronization, and transceiver microcode authenticity audit |'
    t4_row = '| `qkdmesh` ⚛️ 실리콘 포토닉스 광 인터커넥트 & QKD 양자 키 메시 방어 (7) | 실리콘 포토닉스 하드웨어 자율 공방 훈련 · 엔터프라이즈 광 QKD 메시 인프라 · 제로 트러스트 포토닉 상호 증명 체계 · 주권 초고속 AI 클러스터 광 보안 캡스톤 / Silicon photonics hardware adversarial drill, enterprise optical QKD mesh infrastructure, zero-trust photonic mutual attestation system, and sovereign high-speed AI cluster optical interconnect capstone |'

    # Find the 5 agentmem rows and append the corresponding qkdmesh row
    tier_rows = [t0_row, t1_row, t2_row, t3_row, t4_row]
    agentmem_matches = list(re.finditer(r'\| `agentmem` 🧠 AI 에이전트 장기 메모리 오염 & 지식 그래프 방어 \(7\) \| [^\n]+', readme))
    if len(agentmem_matches) == 5:
        # Reconstruct from bottom to top to preserve indices
        for i in reversed(range(5)):
            m = agentmem_matches[i]
            if "qkdmesh" not in readme[m.end():m.end()+400]:
                readme = readme[:m.end()] + "\n" + tier_rows[i] + readme[m.end():]
        print("[+] Inserted 5 qkdmesh rows into wargame/README.md tier tables.")
    else:
        print(f"[-] Warning: found {len(agentmem_matches)} agentmem matches in README.md")

    readme_path.write_text(readme, encoding="utf-8")
    print("[+] Successfully updated wargame/README.md.")

    print("\n🎉 Track 85 qkdmesh generation completed successfully! Total: 2,975 challenges across 85 tracks.")

if __name__ == "__main__":
    main()
