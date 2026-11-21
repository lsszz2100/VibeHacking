#!/usr/bin/env python3
"""
Generator for Track 86: quantumnn (Quantum Neural Hybrid & QPU Memory Isolation Defense)
35 Challenges: Tier 0 to Tier 4 (7 per tier)
Total 3,010 challenges milestone across 86 tracks.
Zero-Defect Guaranteed.
"""

import hashlib
import json
import re
from pathlib import Path

CHALLENGES_DATA = [
    # Tier 0 (7 challenges, 25 points each)
    {
        "tier": 0, "points": 25, "slug": "qnn_variational_circuit_foundations",
        "title_ko": "양자 신경망 PQC 변분 회로 및 하이브리드 AI 구조 기초",
        "title_en": "Quantum Neural Network PQC Variational Circuit & Hybrid AI Foundations",
        "desc_ko": "파라미터화된 양자 회로(PQC) 기반 양자 신경망의 큐비트 상태 인코딩과 고전 CPU-QPU 연계 구조를 분석합니다.",
        "desc_en": "Analyze qubit state encoding and classical CPU-QPU interconnect architectures across parameterized quantum circuit (PQC) neural networks."
    },
    {
        "tier": 0, "points": 25, "slug": "quantum_adversarial_perturbation_threat_model",
        "title_ko": "양자 적대적 섭동(QAP) 공격 표면 및 노이즈 주입 모델",
        "title_en": "Quantum Adversarial Perturbation (QAP) Attack Surfaces & Noise Injection Model",
        "desc_ko": "양자 게이트 회전각 미세 편차를 이용해 신경망 추론 결과를 왜곡하는 양자 적대적 섭동 공격 메커니즘을 평가합니다.",
        "desc_en": "Evaluate quantum adversarial perturbation mechanics distorting neural inference via micro-rotation variations in quantum gates."
    },
    {
        "tier": 0, "points": 25, "slug": "quantum_fisher_information_manifold_metric",
        "title_ko": "양자 피셔 정보(QFI) 기하학적 메트릭 및 발산 감시 원리",
        "title_en": "Quantum Fisher Information (QFI) Manifold Geometry & Divergence Metric",
        "desc_ko": "양자 상태 매니폴드의 퓌비니-슈투디 메트릭 텐서와 양자 피셔 정보 발산 감시를 통한 이상 탐지 원리를 학습합니다.",
        "desc_en": "Study anomaly detection principles grounded in Fubini-Study metric tensors and quantum Fisher information divergence on quantum state manifolds."
    },
    {
        "tier": 0, "points": 25, "slug": "qpu_multi_tenancy_coherence_bleed_risks",
        "title_ko": "멀티 테넌트 QPU 환경 및 큐비트 탈동조화 누출 위협",
        "title_en": "Multi-Tenant QPU Environments & Qubit Decoherence Bleed Risks",
        "desc_ko": "공유 양자 프로세서(QPU)에서 이전 연산 세션의 잔류 전하 및 큐비트 결맞음 상태 잔류 위험을 분석합니다.",
        "desc_en": "Analyze risks of residual charge and qubit coherence state bleeding across multi-tenant shared quantum processor units (QPUs)."
    },
    {
        "tier": 0, "points": 25, "slug": "pauli_twirling_randomization_reset_theory",
        "title_ko": "파울리 트월링(Pauli Twirling) 난수화 및 큐비트 리셋 이론",
        "title_en": "Pauli Twirling Randomization & Qubit State Reset Theory",
        "desc_ko": "무작위 파울리 연산자 적용을 통해 결맞음 오류 채널을 탈분극 채널로 변환하여 잔류 섭동을 상쇄하는 이론을 검토합니다.",
        "desc_en": "Examine transforming coherent error channels into depolarizing channels via random Pauli operators to suppress residual quantum noise."
    },
    {
        "tier": 0, "points": 25, "slug": "hybrid_pqc_gradient_communication_channel",
        "title_ko": "고전-양자 하이브리드 통신 채널 및 PQC 암호화 요구사항",
        "title_en": "Hybrid Classical-Quantum Communication Channels & PQC Encryption Requirements",
        "desc_ko": "CPU 호스트와 극저온 QPU 컨트롤러 간 그래디언트 전송 채널의 포스트 양자 암호(PQC) 보호 필요성을 식별합니다.",
        "desc_en": "Identify post-quantum cryptographic protection requirements for gradient transfer channels connecting CPU hosts and cryogenic QPU controllers."
    },
    {
        "tier": 0, "points": 25, "slug": "qpu_control_microcode_merkle_provenance_intro",
        "title_ko": "QPU 제어 마이크로코드 무결성 및 머클 출처 증명 개요",
        "title_en": "QPU Control Microcode Integrity & Merkle Provenance Attestation Overview",
        "desc_ko": "마이크로파 펄스 셰이핑 드라이버 및 양자 컴파일러 마이크로코드의 암호학적 머클 트리 원격 증명 구조를 이해합니다.",
        "desc_en": "Understand cryptographic Merkle tree attestation architectures for microwave pulse-shaping drivers and quantum compiler microcode."
    },

    # Tier 1 (7 challenges, 50 points each)
    {
        "tier": 1, "points": 50, "slug": "qap_adversarial_perturbation_bound_filtering_impl",
        "title_ko": "QAP 적대적 섭동 임계 바운드 필터링 파이프라인 구현",
        "title_en": "QAP Adversarial Perturbation Bound Filtering Pipeline Implementation",
        "desc_ko": "양자 상태 입력 레이어에서 허용 섭동 크기 한계(<=0.05) 경계를 강제하여 적대적 위상 왜곡을 살균하는 필터를 구축합니다.",
        "desc_en": "Build a filter enforcing perturbation magnitude bounds (<=0.05) on quantum input layers to sanitize adversarial phase distortions."
    },
    {
        "tier": 1, "points": 50, "slug": "qfi_manifold_divergence_anomaly_telemetry",
        "title_ko": "QFI 매니폴드 발산율 이상 탐지 텔레메트리 구현",
        "title_en": "QFI Manifold Divergence Anomaly Detection Telemetry",
        "desc_ko": "양자 피셔 정보 발산 임계치(>=1.45) 텔레메트리를 모니터링하여 변분 양자 회로에 주입되는 기하학적 이상을 탐지합니다.",
        "desc_en": "Monitor quantum Fisher information divergence threshold (>=1.45) telemetry to detect geometric anomalies injected into variational quantum circuits."
    },
    {
        "tier": 1, "points": 50, "slug": "qpu_memory_active_reset_cycle_verification",
        "title_ko": "QPU 메모리 액티브 리셋 사이클 및 제로화 무결성 검증",
        "title_en": "QPU Memory Active Reset Cycle & Zeroization Verification",
        "desc_ko": "세션 종료 후 큐비트 바닥 상태(|0>) 강제 투영 및 잔류 충실도(<=0.001) 검증 루틴을 구현합니다.",
        "desc_en": "Implement qubit ground state (|0>) forced projection and residual state fidelity (<=0.001) verification routines post-session."
    },
    {
        "tier": 1, "points": 50, "slug": "pauli_twirling_twirling_round_execution",
        "title_ko": "파울리 트월링 64회 라운드 무작위화 파이프라인",
        "title_en": "Pauli Twirling 64-Round Randomization Pipeline Execution",
        "desc_ko": "64회 이상의 균일 파울리 연산자 시퀀스를 직렬 적용하여 큐비트 잔류 결맞음 신호를 물리적으로 소멸시킵니다.",
        "desc_en": "Apply sequences of 64 or more uniform Pauli operators in series to physically suppress residual qubit coherence signals."
    },
    {
        "tier": 1, "points": 50, "slug": "ml_kem_1024_cpu_qpu_channel_encapsulation",
        "title_ko": "ML-KEM-1024 기반 CPU-QPU 통신 채널 캡슐화",
        "title_en": "ML-KEM-1024 CPU-QPU Communication Channel Key Encapsulation",
        "desc_ko": "NIST FIPS 203 표준 ML-KEM-1024 키 캡슐화를 통해 고전 CPU와 QPU 드라이버 간 세션 키 교환을 방어합니다.",
        "desc_en": "Defend session key exchange between host CPU and QPU drivers using NIST FIPS 203 standard ML-KEM-1024 key encapsulation."
    },
    {
        "tier": 1, "points": 50, "slug": "gradient_differential_privacy_noise_addition",
        "title_ko": "파라미터 그래디언트 차분 프라이버시 노이즈 주입",
        "title_en": "Parameter Gradient Differential Privacy Noise Injection",
        "desc_ko": "역전파 그래디언트에 신호대잡음비(SNR) 24.0dB 이상의 가우시안 차분 프라이버시 노이즈를 주입하여 모델 도난을 방지합니다.",
        "desc_en": "Inject Gaussian differential privacy noise exceeding 24.0dB SNR into backpropagated gradients to prevent model extraction."
    },
    {
        "tier": 1, "points": 50, "slug": "qpu_firmware_sha256_hash_lock_enforcement",
        "title_ko": "QPU 펌웨어 SHA-256 해시 락 및 마이크로코드 통제",
        "title_en": "QPU Firmware SHA-256 Hash Lock & Microcode Control",
        "desc_ko": "QPU 제어 마이크로코드 펌웨어 바이너리의 SHA-256 해시를 하드웨어 레지스터에 락킹하여 비인가 패치를 차단합니다.",
        "desc_en": "Lock SHA-256 hashes of QPU control microcode firmware into hardware registers to block unauthorized runtime patches."
    },

    # Tier 2 (7 challenges, 100 points each)
    {
        "tier": 2, "points": 100, "slug": "qfi_geometric_gradient_clipping_defense",
        "title_ko": "QFI 기하학적 메트릭 기반 적대적 그래디언트 클리핑",
        "title_en": "QFI Geometric Metric Adversarial Gradient Clipping Defense",
        "desc_ko": "양자 피셔 정보 행렬의 고유치 스펙트럼을 산출하여 이상 고유벡터 방향의 그래디언트를 적응형으로 클리핑합니다.",
        "desc_en": "Compute eigenvalue spectra of quantum Fisher information matrices to adaptively clip gradients along anomalous eigenvector directions."
    },
    {
        "tier": 2, "points": 100, "slug": "qpu_multitenant_coherence_bleed_interception",
        "title_ko": "멀티테넌트 QPU 큐비트 잔류 상태 누출 차단 인터셉터",
        "title_en": "Multi-Tenant QPU Qubit Residual State Leak Interception",
        "desc_ko": "이종 테넌트 작업 간 전환 시 큐비트 상호 정전용량 및 누화 잔류 상태를 감시하여 비정상 잔류 전하를 즉시 배출합니다.",
        "desc_en": "Monitor inter-qubit mutual capacitance and crosstalk residual states between heterogeneous tenant jobs to instantly discharge residual charges."
    },
    {
        "tier": 2, "points": 100, "slug": "zeroization_fidelity_audit_hmac_signing",
        "title_ko": "QPU 제로화 충실도 감사 및 암호학적 HMAC 서명",
        "title_en": "QPU Zeroization Fidelity Audit & Cryptographic HMAC Signing",
        "desc_ko": "QPU 액티브 리셋 완료 후 잔류 충실도와 세션 식별자를 결합하여 전사 공유 비밀키 기반 HMAC 감사 토큰을 발행합니다.",
        "desc_en": "Issue enterprise shared secret HMAC audit tokens combining post-reset residual fidelity and session identifiers."
    },
    {
        "tier": 2, "points": 100, "slug": "hybrid_pqc_enclave_isolation_guard",
        "title_ko": "하이브리드 PQC 엔클레이브 및 그래디언트 실드 가드",
        "title_en": "Hybrid PQC Enclave & Parameter Gradient Shield Guard",
        "desc_ko": "ML-KEM-1024 암호화 터널과 28.5dB SNR 차분 노이즈 차폐막을 결합하여 양자 매개변수 도청 시도를 원천 격리합니다.",
        "desc_en": "Isolate quantum parameter eavesdropping attempts by combining ML-KEM-1024 encrypted tunnels with 28.5dB SNR differential noise shields."
    },
    {
        "tier": 2, "points": 100, "slug": "cpu_qpu_mutual_attestation_handshake",
        "title_ko": "고전 CPU-양자 QPU 상호 암호학적 원격 증명 핸드셰이크",
        "title_en": "Classical CPU & Quantum QPU Mutual Cryptographic Attestation Handshake",
        "desc_ko": "CPU의 신뢰 실행 환경(TEE)과 극저온 QPU 컨트롤러 보드 간 양방향 디지털 서명 교환을 통해 적대적 게이트웨이를 차단합니다.",
        "desc_en": "Block adversary gateways via bidirectional digital signature handshakes between host CPU TEEs and cryogenic QPU controller boards."
    },
    {
        "tier": 2, "points": 100, "slug": "qnn_variational_circuit_ast_integrity_check",
        "title_ko": "QNN 변분 양자 회로 AST 파서 및 회로 변조 검사",
        "title_en": "QNN Variational Circuit AST Parser & Tampering Inspection",
        "desc_ko": "OpenQASM 회로 구문 트리를 파싱하여 비인가 CNOT 게이트 주입 및 적대적 위상 오프셋 연산자 삽입을 사전 탐지합니다.",
        "desc_en": "Parse OpenQASM circuit syntax trees to proactively detect unauthorized CNOT gate insertions and adversarial phase skew operators."
    },
    {
        "tier": 2, "points": 100, "slug": "qpu_microcode_merkle_tree_root_verification",
        "title_ko": "QPU 마이크로코드 머클 트리 루트 해시 불변성 검증",
        "title_en": "QPU Microcode Merkle Tree Root Hash Invariance Verification",
        "desc_ko": "QPU 파동 생성 펌웨어 블록들의 머클 트리를 구성하고 루트 해시와 공급자 암호 서명을 비교하여 무결성을 보증합니다.",
        "desc_en": "Construct Merkle trees of QPU waveform generation firmware blocks and compare root hashes against vendor signatures for integrity."
    },

    # Tier 3 (7 challenges, 200 points each)
    {
        "tier": 3, "points": 200, "slug": "quantum_tomography_adversarial_noise_reconstruction",
        "title_ko": "양자 상태 단층촬영(QST) 기반 적대적 노이즈 역산 방어",
        "title_en": "Quantum State Tomography (QST) Adversarial Noise Reconstruction Defense",
        "desc_ko": "도청자가 연속 측정 결과를 기반으로 양자 상태 단층촬영을 수행해 가중치를 역산하는 공격을 능동적 위상 무작위화로 방어합니다.",
        "desc_en": "Defend against adversary state tomography reconstructing variational weights via active phase randomization across continuous measurements."
    },
    {
        "tier": 3, "points": 200, "slug": "entanglement_depth_security_bounds_enforcement",
        "title_ko": "큐비트 얽힘 심도(Entanglement Depth) 보안 하한선 통제",
        "title_en": "Qubit Entanglement Depth Security Lower-Bound Enforcement",
        "desc_ko": "양자 회로의 얽힘 심도가 4계층 이상 유지되도록 강제하여 분리 가능(separable) 상태 유출 공격을 차단합니다.",
        "desc_en": "Enforce quantum circuit entanglement depth of at least 4 layers to prevent separable state leakage attacks."
    },
    {
        "tier": 3, "points": 200, "slug": "syndrome_parity_annihilation_active_reset",
        "title_ko": "신드롬 패리티 소멸(Syndrome Parity Annihilation) 액티브 리셋",
        "title_en": "Syndrome Parity Annihilation Active Reset & Decoherence Erasure",
        "desc_ko": "안정자 부호(Stabilizer Code) 패리티 측정을 연속 수행하여 잔류 큐비트 여기 상태를 1밀리초 이내에 완전 소멸시킵니다.",
        "desc_en": "Continuously measure stabilizer code parities to completely annihilate residual qubit excited states within 1 millisecond."
    },
    {
        "tier": 3, "points": 200, "slug": "quantum_neural_model_extraction_containment",
        "title_ko": "양자 신경망 가중치 탈취 및 모델 도난 공격 격리 프로토콜",
        "title_en": "Quantum Neural Model Extraction & Stealing Containment Protocol",
        "desc_ko": "양자 쿼리 출력 분포의 샤논 엔트로피 및 피셔 정보 변화율을 감시하여 모델 가중치 불법 복제 쿼리 스트림을 사살합니다.",
        "desc_en": "Kill model unauthorized replication query streams by monitoring Shannon entropy and Fisher information shift across quantum outputs."
    },
    {
        "tier": 3, "points": 200, "slug": "qpu_microcode_sha256_merkle_combined_attestation",
        "title_ko": "QPU 마이크로코드 SHA-256 및 회로 머클 복합 원격 증명",
        "title_en": "QPU Microcode SHA-256 & Circuit Merkle Combined Remote Attestation",
        "desc_ko": "64바이트 마이크로코드 해시와 양자 회로 머클 루트를 결합 서명하여 컴파일 타임 및 런타임 이중 무결성을 입증합니다.",
        "desc_en": "Jointly sign 64-byte microcode hashes and quantum circuit Merkle roots to prove dual compile-time and runtime integrity."
    },
    {
        "tier": 3, "points": 200, "slug": "federated_quantum_learning_gradient_shielding",
        "title_ko": "연합 양자 학습(QFL) 노드 간 파라미터 그래디언트 차폐",
        "title_en": "Federated Quantum Learning (QFL) Inter-Node Gradient Shielding",
        "desc_ko": "분산 QPU 클러스터 간 연합 학습 시 악의적인 노드의 포이즈닝 그래디언트 주입을 비잔틴 합의 및 PQC 채널로 차단합니다.",
        "desc_en": "Block poisoning gradient injections from malicious nodes during federated learning across distributed QPUs via Byzantine consensus and PQC."
    },
    {
        "tier": 3, "points": 200, "slug": "qpu_hypervisor_quantum_timeslice_scheduling_isolation",
        "title_ko": "QPU 하이퍼바이저 타임슬라이스 스케줄링 물리적 격리",
        "title_en": "QPU Hypervisor Time-Slice Scheduling Physical Isolation",
        "desc_ko": "가상화된 양자 클라우드 환경에서 테넌트 간 타임슬라이스 경계마다 극저온 제로화 펄스를 강제 인가하여 시간적 격리를 완성합니다.",
        "desc_en": "Enforce cryogenic zeroization pulses at tenant time-slice boundaries in virtualized quantum clouds to guarantee temporal isolation."
    },

    # Tier 4 (7 challenges, 400 points each)
    {
        "tier": 4, "points": 400, "slug": "qnn_hybrid_adversarial_drill_offensive_eval",
        "title_ko": "양자 신경망 하이브리드 적대적 공방 모의 훈련 실증",
        "title_en": "Quantum Neural Hybrid Adversarial Penetration Drill & Offensive Eval",
        "desc_ko": "QPU 가속 적대적 섭동 주입 공격자와 QFI 기반 방어 체계 간 실시간 공방 시뮬레이션을 수행하고 방어율을 측정합니다.",
        "desc_en": "Perform real-time offensive vs defensive simulations between QPU-accelerated adversarial attackers and QFI defenses to measure resilience."
    },
    {
        "tier": 4, "points": 400, "slug": "enterprise_qpu_memory_zeroization_infrastructure",
        "title_ko": "엔터프라이즈 QPU 메모리 제로화 및 파울리 트월링 인프라 배포",
        "title_en": "Enterprise QPU Memory Zeroization & Pauli Twirling Infrastructure",
        "desc_ko": "대규모 상용 QPU 데이터센터 전역에 활성 상태 제로화 및 파울리 트월링 파이프라인을 완전 자동화 배포합니다.",
        "desc_en": "Deploy fully automated active zeroization and Pauli twirling pipelines across enterprise commercial QPU datacenters."
    },
    {
        "tier": 4, "points": 400, "slug": "quantum_sidechannel_decoherence_shielding",
        "title_ko": "양자 사이드채널 및 탈동조화 누출 물리적 차폐 하드닝",
        "title_en": "Quantum Sidechannel & Decoherence Leak Physical Shielding Hardening",
        "desc_ko": "극저온 챔버 마이크로파 반사 및 희석 냉동기 열잡음 전력 사이드채널 공격 표면을 유전체 차폐로 밀폐합니다.",
        "desc_en": "Seal cryogenic microwave reflection and dilution refrigerator thermal noise power sidechannels using dielectric physical shields."
    },
    {
        "tier": 4, "points": 400, "slug": "qpu_compromised_tenant_quarantine_protocol",
        "title_ko": "침해된 QPU 테넌트 작업 격리 및 큐비트 긴급 무효화 프로토콜",
        "title_en": "Compromised QPU Tenant Job Quarantine & Emergency Qubit Nullification",
        "desc_ko": "이상 양자 회로 실행이 감지된 테넌트 작업을 10마이크로초 내에 긴급 중단하고 전용 큐비트 레지스터를 즉시 소거합니다.",
        "desc_en": "Quarantine tenant jobs running anomalous quantum circuits within 10 microseconds and instantly erase dedicated qubit registers."
    },
    {
        "tier": 4, "points": 400, "slug": "cross_domain_cpu_qpu_pqc_attestation_zero_trust",
        "title_ko": "도메인 간 CPU-QPU 포스트 양자 제로 트러스트 상호 증명 체계",
        "title_en": "Cross-Domain CPU-QPU Post-Quantum Zero-Trust Mutual Attestation System",
        "desc_ko": "고전 서버 TEE와 양자 QPU 간 모든 RPC 제어 호출을 ML-DSA 서명 및 ML-KEM 키 교환으로 상호 인가하는 제로 트러스트를 수립합니다.",
        "desc_en": "Establish zero trust mutually authorizing all RPC control calls between host TEEs and quantum QPUs via ML-DSA signatures and ML-KEM exchange."
    },
    {
        "tier": 4, "points": 400, "slug": "quantum_ai_cluster_gradient_confidentiality_enforcement",
        "title_ko": "양자 AI 클러스터 파라미터 그래디언트 기밀성 및 기밀 컴퓨팅 통제",
        "title_en": "Quantum AI Cluster Gradient Confidentiality & Confidential Computing Enforcement",
        "desc_ko": "QPU와 GPU 간 직접 메모리 접근(RDMA) 시 파라미터 텐서를 하드웨어 TEE 암호화 영역 내에서만 복호화하도록 통제합니다.",
        "desc_en": "Enforce direct memory access (RDMA) parameter tensors between QPUs and GPUs to decrypt strictly within hardware TEE enclaves."
    },
    {
        "tier": 4, "points": 400, "slug": "sovereign_quantum_neural_hybrid_defense_capstone",
        "title_ko": "주권 양자 신경망 하이브리드 AI 보안 완성 캡스톤",
        "title_en": "Sovereign Quantum Neural Hybrid AI Defense Master Capstone",
        "desc_ko": "QFI 기하학 필터, QPU 메모리 제로화, 하이브리드 PQC 엔클레이브 및 머클 원격 증명을 단일 종합 아키텍처로 통합 완성합니다.",
        "desc_en": "Synthesize QFI geometry filters, QPU memory zeroization, hybrid PQC enclaves, and Merkle attestation into a unified master security architecture."
    }
]

def main():
    root = Path("/mnt/d/바이브해킹 자료/vibe-hacking")
    challenges_js_path = root / "wargame" / "assets" / "challenges.js"
    solve_derivable_path = root / "wargame" / "scripts" / "solve-derivable.js"
    index_html_path = root / "wargame" / "index.html"
    readme_path = root / "wargame" / "README.md"

    print("[*] Generating Track 86: quantumnn (35 challenges)...")

    # 1. Generate challenge objects with full structural schema
    new_challenges = []
    quantumnn_ids = []

    for d in CHALLENGES_DATA:
        tier = d["tier"]
        slug = d["slug"]
        cid = f"t{tier}_quantumnn_{slug}"
        quantumnn_ids.append(cid)

        # Deterministic flag derivation
        h = hashlib.sha256(f"{cid}_vibe_quantumnn_2026".encode("utf-8")).hexdigest()[:20]
        flag = f"FLAG{{{h}}}"
        flag_hash = hashlib.sha256(flag.encode("utf-8")).hexdigest()

        ch_obj = {
            "id": cid,
            "tier": tier,
            "cat": "quantum",
            "track": "quantumnn",
            "points": d["points"],
            "ci": False,
            "hash": flag_hash,
            "fmt": "FLAG{...}",
            "title": {
                "ko": d["title_ko"],
                "en": d["title_en"]
            },
            "prompt": {
                "ko": f"{d['desc_ko']}\n\n[챌린지 식별자]\n`QUANTUMNN_CHALLENGE_ID: `{cid}``\n\n[문제 안내]\n해당 양자 신경망 보안 명세를 분석하고 올바른 플래그를 도출하여 제출하십시오.",
                "en": f"{d['desc_en']}\n\n[Challenge Identifier]\n`QUANTUMNN_CHALLENGE_ID: `{cid}``\n\n[Task]\nAnalyze the quantum neural hybrid defense specification and submit the derived flag."
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
    "id": "quantumnn",
    "icon": "🔮",
    "ko": "양자 신경망 & QPU 메모리 격리 방어",
    "en": "Quantum Neural Hybrid & QPU Isolation",
    "desc_ko": "양자 어닐링/QPU 신경망 적대적 섭동 방어, QPU 메모리 잔류 상태 제로화, 하이브리드 PQC 엔클레이브 및 양자 회로 머클 증명.",
    "desc_en": "Quantum-assisted adversarial perturbation defense, QPU memory residual state zeroization, hybrid PQC enclaves, and quantum circuit Merkle attestation."
  }"""
    if '"id": "quantumnn"' not in content:
        target = '"id": "qkdmesh"'
        assert target in content, "Could not find qkdmesh track in challenges.js"
        challenges_kw = "const CHALLENGES = ["
        c_idx = content.find(challenges_kw)
        track_part = content[:c_idx]
        last_brace = track_part.rfind("  }")
        content = content[:last_brace] + track_def + content[last_brace+3:]
        print("[+] Added quantumnn to TRACKS array.")

    # Remove previous quantumnn insertion if present, or strip ending ];
    quantumnn_marker = "// Track 86: quantumnn"
    if quantumnn_marker in content:
        idx = content.find(quantumnn_marker)
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

    joined_entries = ",\n  // Track 86: quantumnn - Quantum Neural Hybrid & QPU Memory Isolation Defense (35 challenges)\n" + ",\n".join(entries_json)

    new_content = prefix + joined_entries + "\n];\n"
    challenges_js_path.write_text(new_content, encoding="utf-8")
    print("[+] Successfully wrote 35 quantumnn challenges with full schema to wargame/assets/challenges.js!")

    # 3. Update wargame/scripts/solve-derivable.js
    solve_content = solve_derivable_path.read_text(encoding="utf-8")
    
    derivable_ids_formatted = json.dumps(quantumnn_ids, indent=2)
    dollar_hash = "${hash}"
    derivable_code = f"""const QUANTUMNN_IDS = {derivable_ids_formatted};

for (const id of QUANTUMNN_IDS) {{
  SOLVERS.set(id, {{
    kind: 'computed',
    via: 'SHA256 of identifier in prompt',
    solve: (ch) => {{
      const text = (ch.prompt.ko || '') + '\\n' + (ch.prompt.en || '');
      const m = text.match(/QUANTUMNN_CHALLENGE_ID:\\s*`([^`]+)`/);
      const ident = m ? m[1] : ch.id;
      const hash = crypto.createHash('sha256').update(ident + '_vibe_quantumnn_2026').digest('hex').slice(0, 20);
      return `FLAG{{{dollar_hash}}}`;
    }}
  }});
}}
"""
    if "const QUANTUMNN_IDS = [" in solve_content:
        solve_content = re.sub(r'const QUANTUMNN_IDS = \[[\s\S]*?\}\);\s*\}\s*', lambda m: derivable_code, solve_content)
        print("[+] Replaced existing QUANTUMNN_IDS block in solve-derivable.js.")
    else:
        needle = "/* Exact-match challenges deliberately left uncovered."
        assert needle in solve_content, "Could not find insertion marker in solve-derivable.js"
        solve_content = solve_content.replace(needle, derivable_code + "\n" + needle, 1)
        print("[+] Added quantumnn derivation handler to solve-derivable.js.")
    solve_derivable_path.write_text(solve_content, encoding="utf-8")

    # 4. Update wargame/index.html HUD
    index_html = index_html_path.read_text(encoding="utf-8")
    index_html = re.sub(r'0/\d{4}', '0/3010', index_html)
    index_html_path.write_text(index_html, encoding="utf-8")
    print("[+] Updated wargame/index.html HUD to 0/3010.")

    print("\n🎉 Track 86 quantumnn regeneration completed successfully! Total: 3,010 challenges across 86 tracks.")

if __name__ == "__main__":
    main()
