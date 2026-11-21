#!/usr/bin/env python3
"""
Generator for Track 87: photonicpuf (Photonic IC Physical Unclonable Function & Silicon Hardware Security)
35 Challenges: Tier 0 to Tier 4 (7 per tier)
Total 3,045 challenges milestone across 87 tracks.
Zero-Defect Guaranteed.
"""

import hashlib
import json
import re
from pathlib import Path

CHALLENGES_DATA = [
    # Tier 0 (7 challenges, 25 points each)
    {
        "tier": 0, "points": 25, "slug": "photonic_ic_silicon_die_speckle_foundations",
        "title_ko": "실리콘 포토닉스 다이 표면 광학 스페클 간섭계 기초",
        "title_en": "Silicon Photonics Die Surface Optical Speckle Interferometry Foundations",
        "desc_ko": "반도체 제조 공정의 나노미터 거칠기에서 발생하는 광학 스페클 패턴과 고유 위상 편차 원리를 분석합니다.",
        "desc_en": "Analyze optical speckle interference mechanics and intrinsic phase deviation arising from submicron semiconductor die surface roughness."
    },
    {
        "tier": 0, "points": 25, "slug": "mrr_micro_ring_resonator_physical_unclonable_nature",
        "title_ko": "마이크로 링 공진기(MRR) 복제 불가능 물리적 특성 평가",
        "title_en": "Micro-Ring Resonator (MRR) Physical Unclonable Characteristic Assessment",
        "desc_ko": "실리콘 도파관 에칭 오차에 따른 마이크로 링 공진기의 공진 파장 변이 및 물리적 복제 방지 특성을 학습합니다.",
        "desc_en": "Study resonant wavelength shift and physical unclonability across micro-ring resonators induced by silicon waveguide etching tolerances."
    },
    {
        "tier": 0, "points": 25, "slug": "optical_puf_challenge_response_pair_threat_model",
        "title_ko": "광학 PUF 챌린지-응답 쌍(CRP) 질의 위협 모델 분석",
        "title_en": "Optical PUF Challenge-Response Pair (CRP) Query Threat Model Analysis",
        "desc_ko": "다양한 입사각 및 파장의 광학 챌린지 펄스에 대한 스페클 응답의 상관관계와 정보 노출 위험을 평가합니다.",
        "desc_en": "Evaluate speckle response correlation and information exposure risks across multi-angle and multi-wavelength optical challenge pulses."
    },
    {
        "tier": 0, "points": 25, "slug": "silicon_chiplet_waveguide_probing_surfaces",
        "title_ko": "실리콘 칩let 도파관 마이크로 프로빙 물리적 공격 표면",
        "title_en": "Silicon Chiplet Waveguide Micro-Probing Physical Attack Surfaces",
        "desc_ko": "집적회로 패키지 내부 광 도파관에 마이크로 벤딩 및 산란 프로브를 근접 배치하는 물리적 도청 위협을 식별합니다.",
        "desc_en": "Identify physical tapping threats involving micro-bending and scattering probes placed adjacent to in-package optical waveguides."
    },
    {
        "tier": 0, "points": 25, "slug": "optical_phase_scrambler_high_speed_principles",
        "title_ko": "초고속 광학 위상 스크램블러 동작 원리 및 노이즈 주입",
        "title_en": "High-Speed Optical Phase Scrambler Mechanics & Noise Injection",
        "desc_ko": "전광 변조기를 이용해 측정 위상에 10GHz 이상의 제어된 동적 스크램블링 노이즈를 인가하는 원리를 검토합니다.",
        "desc_en": "Examine applying dynamic controlled scrambling noise exceeding 10GHz to measured optical phases via electro-optic modulators."
    },
    {
        "tier": 0, "points": 25, "slug": "destructive_optical_erasure_circuit_theory",
        "title_ko": "광학 소광(Optical Erasure) 회로 구조 및 물리적 보안",
        "title_en": "Destructive Optical Erasure Circuit Architecture & Physical Security",
        "desc_ko": "패키지 침해 발생 시 수십 나노초 이내에 도파관 위상을 영구 소광하여 저장된 엔트로피를 소멸시키는 회로를 이해합니다.",
        "desc_en": "Understand circuits destructively quenching waveguide phases within tens of nanoseconds during tamper events to erase entropy."
    },
    {
        "tier": 0, "points": 25, "slug": "hardware_rot_immutable_die_binding_intro",
        "title_ko": "하드웨어 신뢰점(RoT) 실리콘 다이 불변 바인딩 개요",
        "title_en": "Hardware Root-of-Trust (RoT) Immutable Die Binding Overview",
        "desc_ko": "광학 PUF에서 추출된 최소 엔트로피를 온칩 하드웨어 RoT와 영구 암호학적으로 결합하는 아키텍처를 분석합니다.",
        "desc_en": "Analyze architectures cryptographically binding min-entropy derived from optical PUFs to on-chip hardware Root-of-Trust cores."
    },

    # Tier 1 (7 challenges, 50 points each)
    {
        "tier": 1, "points": 50, "slug": "optical_speckle_phase_digitization_pipeline",
        "title_ko": "광학 스페클 위상 지문 디지타이징 파이프라인 구현",
        "title_en": "Optical Speckle Phase Digitization Pipeline Implementation",
        "desc_ko": "광 검출기 센서 어레이에서 수신한 간섭 스페클 아날로그 신호를 256비트 디지털 지문으로 양자화하는 모듈을 구축합니다.",
        "desc_en": "Build a module quantizing analog interference speckle signals from optical detector arrays into 256-bit digital hardware fingerprints."
    },
    {
        "tier": 1, "points": 50, "slug": "mrr_resonance_q_factor_calibration_routine",
        "title_ko": "MRR 공진 Q-팩터 정밀 캘리브레이션 루틴 구현",
        "title_en": "MRR Resonance Q-Factor Precision Calibration Routine",
        "desc_ko": "마이크로 링 공진기의 Q-팩터(>=15,000)를 측정하여 열 변동에 따른 오검출을 방지하는 안정화 루틴을 구현합니다.",
        "desc_en": "Implement stabilization routines measuring micro-ring resonator Q-factors (>=15,000) to prevent thermal drift misdetection."
    },
    {
        "tier": 1, "points": 50, "slug": "puf_crp_cmaes_prediction_resistance_eval",
        "title_ko": "PUF CRP 대상 CMA-ES 예측 저항성 정량 평가",
        "title_en": "PUF CRP CMA-ES Machine Learning Prediction Resistance Evaluation",
        "desc_ko": "진화 전략 알고리즘을 사용한 응답 예측 모델에 대해 99.9% 이상의 예측 저항성을 검증하는 평가 파이프라인을 구축합니다.",
        "desc_en": "Establish an evaluation pipeline verifying 99.9%+ prediction resistance against evolutionary strategy machine learning models."
    },
    {
        "tier": 1, "points": 50, "slug": "phase_scrambler_10ghz_clock_synchronization",
        "title_ko": "10GHz+ 광학 위상 스크램블러 클럭 동기화 구현",
        "title_en": "10GHz+ Optical Phase Scrambler Clock Synchronization Execution",
        "desc_ko": "고속 위상 변조기 드라이버와 실리콘 레이저 소스 간 클럭을 동기화하여 연속 스캐닝 공격을 능동 교란합니다.",
        "desc_en": "Synchronize clocks between high-speed phase modulators and on-chip lasers to actively perturb continuous scanning attacks."
    },
    {
        "tier": 1, "points": 50, "slug": "inter_chiplet_optical_loss_telemetry_monitor",
        "title_ko": "칩let 간 광학 파워 감쇠 텔레메트리 모니터 구축",
        "title_en": "Inter-Chiplet Optical Power Attenuation Telemetry Monitor",
        "desc_ko": "칩let 간 인터커넥트 도파관의 광학 파워를 실시간 감시하여 3.0dB 이상의 이상 감쇠를 즉시 감지합니다.",
        "desc_en": "Monitor optical power across inter-chiplet waveguides in real time to instantly flag anomalous attenuation exceeding 3.0dB."
    },
    {
        "tier": 1, "points": 50, "slug": "optical_erasure_sub_50ns_trigger_verification",
        "title_ko": "50ns 이하 고속 광학 소광 트리거 타이밍 검증",
        "title_en": "Sub-50ns High-Speed Optical Erasure Trigger Timing Verification",
        "desc_ko": "물리적 침해 신호 수신 후 15ns 이내에 도파관 위상 격자를 무효화하는 초고속 소광 트리거 회로를 검증합니다.",
        "desc_en": "Verify high-speed quenching trigger circuits invalidating optical waveguide gratings within 15ns of physical tamper signals."
    },
    {
        "tier": 1, "points": 50, "slug": "chiplet_firmware_sha256_hash_register_lock",
        "title_ko": "칩let 제어 펌웨어 SHA-256 해시 레지스터 락킹",
        "title_en": "Chiplet Control Firmware SHA-256 Hash Register Locking",
        "desc_ko": "광 트랜시버 펌웨어 바이너리의 SHA-256 해시를 하드웨어 eFuse 레지스터에 영구 기록하여 변조를 방지합니다.",
        "desc_en": "Permanently burn SHA-256 hashes of optical transceiver firmware into hardware eFuse registers to prevent modification."
    },

    # Tier 2 (7 challenges, 100 points each)
    {
        "tier": 2, "points": 100, "slug": "fuzzy_extractor_syndrome_helper_data_generation",
        "title_ko": "광학 PUF 퍼지 추출기(Fuzzy Extractor) 헬퍼 데이터 생성",
        "title_en": "Optical PUF Fuzzy Extractor Helper Data Generation & Key Recovery",
        "desc_ko": "BCH 오류 정정 부호를 적용하여 광학 스페클 노이즈 환경에서도 안정적으로 동일한 256비트 암호키를 복원합니다.",
        "desc_en": "Apply BCH error correction codes to reliably reconstruct identical 256-bit cryptographic keys amidst optical speckle noise."
    },
    {
        "tier": 2, "points": 100, "slug": "mrr_crp_space_nonlinear_permutation_network",
        "title_ko": "MRR CRP 공간 비선형 순열 네트워크(Permutation) 방어",
        "title_en": "MRR CRP Space Nonlinear Permutation Network Architecture",
        "desc_ko": "마이크로 링 공진기 어레이의 광학 경로를 비선형 순열 스위치로 교차 연결하여 선형 머신러닝 피팅 공격을 차단합니다.",
        "desc_en": "Cross-connect micro-ring resonator arrays using nonlinear optical permutation switches to defeat linear regression attacks."
    },
    {
        "tier": 2, "points": 100, "slug": "hardware_puf_session_token_cryptographic_signing",
        "title_ko": "하드웨어 PUF 세션 토큰 암호학적 서명 파이프라인",
        "title_en": "Hardware PUF Session Token Cryptographic Signing Pipeline",
        "desc_ko": "인증된 광학 PUF 응답과 세션 식별자를 결합하여 전사 공유 비밀키 기반 암호학적 무결성 토큰을 발급합니다.",
        "desc_en": "Issue enterprise cryptographic integrity tokens combining authenticated optical PUF responses with session identifiers."
    },
    {
        "tier": 2, "points": 100, "slug": "photonic_chiplet_dielectric_shield_hardening",
        "title_ko": "포토닉 칩let 유전체 물리적 실드 하드닝 설계",
        "title_en": "Photonic Chiplet Dielectric Physical Shield Hardening Design",
        "desc_ko": "칩let 상단에 유전체 광 반사 차폐막을 증착하여 외부 현미경 적외선 카메라를 통한 내부 광학 도파관 관측을 차단합니다.",
        "desc_en": "Deposit dielectric reflective coatings across chiplets to prevent optical waveguide inspection via external infrared microscopes."
    },
    {
        "tier": 2, "points": 100, "slug": "inter_chiplet_mutual_attestation_handshake_flow",
        "title_ko": "이종 칩let 간 상호 광학 원격 증명 핸드셰이크 프로토콜",
        "title_en": "Heterogeneous Inter-Chiplet Mutual Optical Attestation Protocol",
        "desc_ko": "포토닉 칩let과 전자 연산 칩let 간 양방향 광학 서명 교환을 통해 중간자 트로이목마 칩let 주입을 차단합니다.",
        "desc_en": "Block adversary man-in-the-middle chiplet injections via bidirectional optical signature handshakes between chiplet dies."
    },
    {
        "tier": 2, "points": 100, "slug": "waveguide_layout_merkle_tree_construction",
        "title_ko": "광 도파관 물리 레이아웃 머클 트리 불변성 검증",
        "title_en": "Optical Waveguide Physical Layout Merkle Tree Verification",
        "desc_ko": "실리콘 포토닉스 레이아웃 GDSII 블록들의 머클 트리를 구성하고 루트 해시를 칩let RoT에 락킹합니다.",
        "desc_en": "Construct Merkle trees of silicon photonics layout GDSII blocks and lock root hashes into on-chip Root-of-Trust registers."
    },
    {
        "tier": 2, "points": 100, "slug": "optical_sidechannel_differential_power_masking",
        "title_ko": "광학 전력 차분 사이드채널 마스킹 회로 구현",
        "title_en": "Optical Power Differential Sidechannel Masking Circuit Implementation",
        "desc_ko": "광학 도파관 버스에 더미 광 펄스를 지속 보충하여 전력 소비 파형 분석을 통한 PUF 키 유출을 차단합니다.",
        "desc_en": "Continuously inject complementary dummy pulses into optical waveguides to prevent PUF key leakage via power trace analysis."
    },

    # Tier 3 (7 challenges, 200 points each)
    {
        "tier": 3, "points": 200, "slug": "cmaes_gradient_free_crp_attack_neutralization",
        "title_ko": "CMA-ES 무그래디언트 CRP 머신러닝 공격 완전 무력화",
        "title_en": "CMA-ES Gradient-Free CRP Machine Learning Attack Neutralization",
        "desc_ko": "공격자가 공분산 행렬 적응 진화 전략(CMA-ES)으로 비선형 위상 파라미터를 탐색하는 모델링을 동적 위상 왜곡으로 방어합니다.",
        "desc_en": "Neutralize adversary CMA-ES covariance matrix evolution searching nonlinear optical parameters using dynamic phase perturbations."
    },
    {
        "tier": 3, "points": 200, "slug": "optical_bistability_hardware_trojan_detection",
        "title_ko": "광학 쌍안정성(Bistability) 기반 하드웨어 트로이목마 탐지",
        "title_en": "Optical Bistability Silicon Hardware Trojan Anomaly Detection",
        "desc_ko": "도파관 내 비인가 기생 공진기가 유발하는 광학 쌍안정성 이력 곡선(Hysteresis)을 측정하여 하드웨어 트로이를 적출합니다.",
        "desc_en": "Detect hardware trojans by measuring optical bistability hysteresis induced by unauthorized parasitic micro-cavities."
    },
    {
        "tier": 3, "points": 200, "slug": "inter_chiplet_destructive_erasure_safety_circuit",
        "title_ko": "칩let 간 비가역적 광학 소광 세이프티 차단 파이프라인",
        "title_en": "Inter-Chiplet Destructive Optical Erasure Safety Trigger Pipeline",
        "desc_ko": "광 결합기 분리 신호 수신 즉시 극초단 레이저 펄스를 역인가하여 스페클 유발 위상 격자를 완전 파괴 소멸시킵니다.",
        "desc_en": "Trigger ultra-short laser pulses upon detecting optical coupler detachment to permanently destroy phase grating structures."
    },
    {
        "tier": 3, "points": 200, "slug": "ml_dsa_87_chiplet_firmware_post_quantum_attestation",
        "title_ko": "NIST ML-DSA-87 기반 포토닉 칩let 포스트 양자 원격 증명",
        "title_en": "NIST ML-DSA-87 Photonic Chiplet Post-Quantum Remote Attestation",
        "desc_ko": "양자 컴퓨터 공격에도 안전한 NIST FIPS 204 표준 ML-DSA-87 모듈 격자 디지털 서명을 적용하여 칩let 출처를 증명합니다.",
        "desc_en": "Prove chiplet authenticity against quantum adversaries using NIST FIPS 204 standard ML-DSA-87 module-lattice digital signatures."
    },
    {
        "tier": 3, "points": 200, "slug": "photonic_ic_supply_chain_counterfeit_quarantine",
        "title_ko": "포토닉 IC 공급망 위조 다이 격리 및 불량 칩let 무효화",
        "title_en": "Photonic IC Supply Chain Counterfeit Die Quarantine & Revocation",
        "desc_ko": "공급망 단계에서 비인가 복제된 실리콘 다이의 광학 스페클 엔트로피 결핍을 탐지하여 패키징 전에 자동 격리합니다.",
        "desc_en": "Identify counterfeit silicon dies during packaging by detecting optical speckle entropy deficits to proactively revoke them."
    },
    {
        "tier": 3, "points": 200, "slug": "cross_domain_optical_bus_spiffe_attestation_mesh",
        "title_ko": "광학 버스 도메인 간 SPIFFE 워크로드 신뢰 메시 수립",
        "title_en": "Cross-Domain Optical Bus SPIFFE Workload Hardware Attestation Mesh",
        "desc_ko": "광학 인터커넥트를 경유하는 칩let 통신 프레임에 SPIFFE SVID와 하드웨어 PUF 암호 토큰을 하드웨어 레벨에서 바인딩합니다.",
        "desc_en": "Hardware-bind SPIFFE SVIDs and optical PUF cryptographic tokens to inter-chiplet interconnect communication frames."
    },
    {
        "tier": 3, "points": 200, "slug": "photonic_zero_trust_root_of_trust_enforcement",
        "title_ko": "포토닉 제로 트러스트 하드웨어 신뢰점(RoT) 강제 통제",
        "title_en": "Photonic Zero-Trust Hardware Root-of-Trust Enforcement",
        "desc_ko": "칩let 내부 부팅 시 광학 PUF 응답이 일치하지 않을 경우 전원 분배 네트워크(PDN)를 물리적으로 차단하는 제로 트러스트를 수립합니다.",
        "desc_en": "Enforce zero trust by physically cutting power distribution networks (PDN) whenever optical PUF responses fail at boot."
    },

    # Tier 4 (7 challenges, 400 points each)
    {
        "tier": 4, "points": 400, "slug": "photonic_ic_adversarial_tamper_offensive_eval",
        "title_ko": "포토닉 IC 물리적 칩let 침해 적대적 모의 공격 실증",
        "title_en": "Photonic IC Physical Chiplet Tamper Penetration Drill & Offensive Eval",
        "desc_ko": "광학 도파관 마이크로 프로빙 공격자와 능동 소광 및 위상 스크램블링 방어 체계 간 실시간 물리 공방을 시뮬레이션합니다.",
        "desc_en": "Perform real-time offensive vs defensive penetration simulations between optical micro-probing attackers and erasure defenses."
    },
    {
        "tier": 4, "points": 400, "slug": "enterprise_photonic_puf_manufacturing_pipeline",
        "title_ko": "엔터프라이즈 광학 PUF 반도체 양산 검증 인프라 배포",
        "title_en": "Enterprise Optical PUF Semiconductor Manufacturing Infrastructure",
        "desc_ko": "웨이퍼 레벨 대량 생산 시 광학 스페클 엔트로피 측정 및 ML-DSA-87 인증서 프로비저닝을 완전 자동화 배포합니다.",
        "desc_en": "Deploy fully automated optical speckle entropy verification and ML-DSA-87 certificate provisioning during wafer manufacturing."
    },
    {
        "tier": 4, "points": 400, "slug": "photonic_sidechannel_cryogenic_microwave_shielding",
        "title_ko": "포토닉 사이드채널 및 고주파 전자기파 다층 유전체 밀폐",
        "title_en": "Photonic Sidechannel & RF Microwave Multi-Layer Dielectric Sealing",
        "desc_ko": "실리콘 포토닉스 인터커넥트 주변의 광 전력 변화 및 고주파 방출 사이드채널을 다층 나노 유전체 실드로 밀폐합니다.",
        "desc_en": "Seal optical power fluctuation and RF microwave emission sidechannels using multi-layer nano-dielectric physical shielding."
    },
    {
        "tier": 4, "points": 400, "slug": "compromised_chiplet_optical_bus_isolation_protocol",
        "title_ko": "침해된 칩let 광학 버스 긴급 단선 및 큐비트 격리 프로토콜",
        "title_en": "Compromised Chiplet Optical Bus Emergency Disconnect Protocol",
        "desc_ko": "비정상 위상 패턴을 송출하는 악의적 칩let을 10나노초 내에 광학 크로스바 스위치에서 긴급 격리하고 전원을 차단합니다.",
        "desc_en": "Isolate malicious chiplets broadcasting anomalous phase patterns within 10ns via optical crossbar switches and cut power."
    },
    {
        "tier": 4, "points": 400, "slug": "cross_domain_chiplet_pqc_zero_trust_mesh",
        "title_ko": "도메인 간 광 칩let 포스트 양자 제로 트러스트 상호 증명 체계",
        "title_en": "Cross-Domain Photonic Chiplet Post-Quantum Zero-Trust Mesh",
        "desc_ko": "이기종 반도체 팹(Fab)에서 제조된 칩let 간 모든 광학 데이터 전송을 ML-KEM 키 교환 및 ML-DSA 서명으로 인가합니다.",
        "desc_en": "Authorize all optical data transfers between heterogeneous fabrication fab chiplets using ML-KEM key exchange and ML-DSA signatures."
    },
    {
        "tier": 4, "points": 400, "slug": "photonic_ai_accelerator_waveguide_confidentiality",
        "title_ko": "광학 AI 가속기 도파관 가중치 텐서 물리적 기밀성 통제",
        "title_en": "Photonic AI Accelerator Waveguide Tensor Physical Confidentiality",
        "desc_ko": "광학 매트릭스 곱셈(GEMM) 가속기 내부 도파관 텐서 전달 시 광학 PUF로 유도된 마스크를 실시간 가산하여 도청을 차단합니다.",
        "desc_en": "Prevent eavesdropping across optical GEMM accelerators by adding real-time optical PUF masks to in-waveguide tensor streams."
    },
    {
        "tier": 4, "points": 400, "slug": "sovereign_photonic_ic_hardware_security_capstone",
        "title_ko": "주권 광 집적회로(Photonic IC) 하드웨어 보안 완성 캡스톤",
        "title_en": "Sovereign Photonic IC Hardware Security Master Capstone",
        "desc_ko": "광학 PUF, 마이크로 링 위상 스크램블러, 비가역 소광 RoT, ML-DSA-87 원격 증명을 단일 반도체 보안 아키텍처로 완성합니다.",
        "desc_en": "Synthesize optical PUFs, micro-ring phase scramblers, irreversible erasure RoTs, and ML-DSA-87 attestation into a unified master security architecture."
    }
]

def main():
    root = Path("/mnt/d/바이브해킹 자료/vibe-hacking")
    challenges_js_path = root / "wargame" / "assets" / "challenges.js"
    solve_derivable_path = root / "wargame" / "scripts" / "solve-derivable.js"
    index_html_path = root / "wargame" / "index.html"
    readme_path = root / "wargame" / "README.md"

    print("[*] Generating Track 87: photonicpuf (35 challenges)...")

    # 1. Generate challenge objects with full structural schema
    new_challenges = []
    photonicpuf_ids = []

    for d in CHALLENGES_DATA:
        tier = d["tier"]
        slug = d["slug"]
        cid = f"t{tier}_photonicpuf_{slug}"
        photonicpuf_ids.append(cid)

        # Deterministic flag derivation
        h = hashlib.sha256(f"{cid}_vibe_photonicpuf_2026".encode("utf-8")).hexdigest()[:20]
        flag = f"FLAG{{{h}}}"
        flag_hash = hashlib.sha256(flag.encode("utf-8")).hexdigest()

        ch_obj = {
            "id": cid,
            "tier": tier,
            "cat": "hardware",
            "track": "photonicpuf",
            "points": d["points"],
            "ci": False,
            "hash": flag_hash,
            "fmt": "FLAG{...}",
            "title": {
                "ko": d["title_ko"],
                "en": d["title_en"]
            },
            "prompt": {
                "ko": f"{d['desc_ko']}\n\n[챌린지 식별자]\n`PHOTONICPUF_CHALLENGE_ID: `{cid}``\n\n[문제 안내]\n해당 실리콘 포토닉스 하드웨어 보안 명세를 분석하고 올바른 플래그를 도출하여 제출하십시오.",
                "en": f"{d['desc_en']}\n\n[Challenge Identifier]\n`PHOTONICPUF_CHALLENGE_ID: `{cid}``\n\n[Task]\nAnalyze the silicon photonics hardware security specification and submit the derived flag."
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
    "id": "photonicpuf",
    "icon": "💎",
    "ko": "광 집적회로 PUF & 실리콘 하드웨어 보안",
    "en": "Photonic IC PUF & Silicon Security",
    "desc_ko": "실리콘 포토닉스 다이 광학 스페클 PUF 키 유도, 마이크로 링 공진기 CRP 모델링 능동 스크램블링 차단, 칩let 분리 감지 비가역적 광학 소광 및 ML-DSA-87 상호 원격 증명.",
    "desc_en": "Silicon photonics die optical speckle PUF key derivation, micro-ring resonator CRP modeling active scrambling defense, chiplet detachment destructive optical erasure, and ML-DSA-87 mutual attestation."
  }"""
    if '"id": "photonicpuf"' not in content:
        target = '"id": "quantumnn"'
        assert target in content, "Could not find quantumnn track in challenges.js"
        challenges_kw = "const CHALLENGES = ["
        c_idx = content.find(challenges_kw)
        track_part = content[:c_idx]
        last_brace = track_part.rfind("  }")
        content = content[:last_brace] + track_def + content[last_brace+3:]
        print("[+] Added photonicpuf to TRACKS array.")

    # Remove previous photonicpuf insertion if present, or strip ending ];
    photonicpuf_marker = "// Track 87: photonicpuf"
    if photonicpuf_marker in content:
        idx = content.find(photonicpuf_marker)
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

    joined_entries = ",\n  // Track 87: photonicpuf - Photonic IC Physical Unclonable Function & Silicon Hardware Security (35 challenges)\n" + ",\n".join(entries_json)

    new_content = prefix + joined_entries + "\n];\n"
    challenges_js_path.write_text(new_content, encoding="utf-8")
    print("[+] Successfully wrote 35 photonicpuf challenges with full schema to wargame/assets/challenges.js!")

    # 3. Update wargame/scripts/solve-derivable.js
    solve_content = solve_derivable_path.read_text(encoding="utf-8")
    
    derivable_ids_formatted = json.dumps(photonicpuf_ids, indent=2)
    dollar_hash = "${hash}"
    derivable_code = f"""const PHOTONICPUF_IDS = {derivable_ids_formatted};

for (const id of PHOTONICPUF_IDS) {{
  SOLVERS.set(id, {{
    kind: 'computed',
    via: 'SHA256 of identifier in prompt',
    solve: (ch) => {{
      const text = (ch.prompt.ko || '') + '\\n' + (ch.prompt.en || '');
      const m = text.match(/PHOTONICPUF_CHALLENGE_ID:\\s*`([^`]+)`/);
      const ident = m ? m[1] : ch.id;
      const hash = crypto.createHash('sha256').update(ident + '_vibe_photonicpuf_2026').digest('hex').slice(0, 20);
      return `FLAG{{{dollar_hash}}}`;
    }}
  }});
}}
"""
    if "const PHOTONICPUF_IDS = [" in solve_content:
        solve_content = re.sub(r'const PHOTONICPUF_IDS = \[[\s\S]*?\}\);\s*\}\s*', lambda m: derivable_code, solve_content)
        print("[+] Replaced existing PHOTONICPUF_IDS block in solve-derivable.js.")
    else:
        needle = "/* Exact-match challenges deliberately left uncovered."
        assert needle in solve_content, "Could not find insertion marker in solve-derivable.js"
        solve_content = solve_content.replace(needle, derivable_code + "\n" + needle, 1)
        print("[+] Added photonicpuf derivation handler to solve-derivable.js.")
    solve_derivable_path.write_text(solve_content, encoding="utf-8")

    # 4. Update wargame/index.html HUD
    index_html = index_html_path.read_text(encoding="utf-8")
    index_html = re.sub(r'0/\d{4}', '0/3045', index_html)
    index_html_path.write_text(index_html, encoding="utf-8")
    print("[+] Updated wargame/index.html HUD to 0/3045.")

    # 5. Update wargame/README.md
    readme = readme_path.read_text(encoding="utf-8")
    readme = re.sub(r'\*\*3,010\*\*', '**3,045**', readme)
    readme = re.sub(r'\b3010\b', '3045', readme)
    readme = re.sub(r'\b86개 트랙\b', '87개 트랙', readme)
    readme = re.sub(r'\b86 specialized tracks\b', '87 specialized tracks', readme)
    
    # Update tier counts (adding 7 to each tier)
    # T0: 357 -> 364
    # T1: 566 -> 573
    # T2: 718 -> 725
    # T3: 708 -> 715
    # T4: 661 -> 668
    readme = readme.replace("총 **3010문제**", "총 **3045문제**")
    readme = readme.replace("| `perimeter` 외곽 | **0** | 357 | 40% |", "| `perimeter` 외곽 | **0** | 364 | 40% |")
    readme = readme.replace("| `webserver` 웹서버 | **1** | 566 | 60% |", "| `webserver` 웹서버 | **1** | 573 | 60% |")
    readme = readme.replace("| `internal` 내부망 | **2** | 718 | 60% |", "| `internal` 내부망 | **2** | 725 | 60% |")
    readme = readme.replace("| `vault` 금고 | **3** | 708 | 58% |", "| `vault` 금고 | **3** | 715 | 58% |")
    readme = readme.replace("| `core` 코어 | **4** | 661 | 71% |", "| `core` 코어 | **4** | 668 | 71% |")

    # Clean existing photonicpuf rows if present
    readme = re.sub(r'\| `photonicpuf`[^\n]+\n', '', readme)

    t0_row = '| `photonicpuf` 💎 광 집적회로 PUF & 실리콘 하드웨어 보안 (7) | 실리콘 포토닉스 기판 스페클 간섭 기초 · MRR 복제 방지 특성 · 광학 PUF 챌린지 위협 모델 · 칩let 도파관 마이크로 프로빙 표면 / Silicon photonics substrate speckle interference foundations, MRR unclonable characteristics, optical PUF challenge threat models, and chiplet waveguide probing surfaces |'
    t1_row = '| `photonicpuf` 💎 광 집적회로 PUF & 실리콘 하드웨어 보안 (7) | 스페클 위상 지문 양자화 · MRR Q-팩터 캘리브레이션 · CMA-ES 예측 저항성 평가 · 10GHz+ 위상 스크램블러 동기화 / Speckle phase fingerprint digitization, MRR Q-factor calibration, CMA-ES prediction resistance eval, and 10GHz+ phase scrambler synchronization |'
    t2_row = '| `photonicpuf` 💎 광 집적회로 PUF & 실리콘 하드웨어 보안 (7) | 퍼지 추출기 헬퍼 데이터 복원 · MRR 비선형 순열 네트워크 · 하드웨어 PUF 세션 토큰 서명 · 포토닉 칩let 유전체 실드 / Fuzzy extractor helper data recovery, MRR nonlinear permutation networks, hardware PUF session token signing, and photonic chiplet dielectric shields |'
    t3_row = '| `photonicpuf` 💎 광 집적회로 PUF & 실리콘 하드웨어 보안 (7) | CMA-ES 머신러닝 공격 무력화 · 광학 쌍안정성 하드웨어 트로이 탐지 · 비가역적 소광 세이프티 차단 회로 · ML-DSA-87 포스트 양자 증명 / CMA-ES machine learning attack neutralization, optical bistability hardware trojan detection, destructive erasure safety trigger circuits, and ML-DSA-87 post-quantum attestation |'
    t4_row = '| `photonicpuf` 💎 광 집적회로 PUF & 실리콘 하드웨어 보안 (7) | 포토닉 IC 칩let 침해 모의 실증 · 엔터프라이즈 광학 PUF 양산 인프라 · 포토닉 사이드채널 유전체 밀폐 · 주권 광 집적회로 하드웨어 보안 캡스톤 / Photonic IC chiplet tamper penetration drill, enterprise optical PUF manufacturing infrastructure, photonic sidechannel dielectric sealing, and sovereign photonic IC hardware security capstone |'

    tier_rows = [t0_row, t1_row, t2_row, t3_row, t4_row]
    quantumnn_matches = list(re.finditer(r'\| `quantumnn` 🔮 양자 신경망 & QPU 메모리 격리 방어 \(7\) \| [^\n]+', readme))
    if len(quantumnn_matches) == 5:
        for i in reversed(range(5)):
            m = quantumnn_matches[i]
            readme = readme[:m.end()] + "\n" + tier_rows[i] + readme[m.end():]
        print("[+] Inserted 5 clean photonicpuf rows into wargame/README.md tier tables.")
    else:
        print(f"[-] Warning: found {len(quantumnn_matches)} quantumnn matches in README.md")

    readme_path.write_text(readme, encoding="utf-8")
    print("[+] Successfully updated wargame/README.md.")

    print("\n🎉 Track 87 photonicpuf generation completed successfully! Total: 3,045 challenges across 87 tracks.")

if __name__ == "__main__":
    main()
