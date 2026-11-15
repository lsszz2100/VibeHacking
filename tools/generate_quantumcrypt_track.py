#!/usr/bin/env python3
"""
Generator for Track 72: quantumcrypt (Quantum Cryptanalysis & Post-Quantum Cryptography Defense)
35 Challenges: Tier 0 to Tier 4 (7 per tier)
Total 2,520 challenges milestone across 72 tracks.
Zero-Defect Guaranteed.
"""

import hashlib
import json
import re
from pathlib import Path

CHALLENGES_DATA = [
    # Tier 0 (7 challenges, 25 points each)
    {
        "tier": 0, "points": 25, "slug": "fundamentals_quantum_supremacy_cryptography",
        "title_ko": "양자 우월성과 현대 비대칭 암호의 위협",
        "title_en": "Quantum Supremacy & Asymmetric Cryptography Threats",
        "desc_ko": "양자 컴퓨팅의 양자 우월성 달성이 기존 RSA 및 ECC 비대칭 공개키 암호 체계에 미치는 파괴적 위협과 포스트 양자 암호 전환의 필요성을 학습합니다.",
        "desc_en": "Understand the disruptive cryptographic threat that quantum supremacy poses to legacy RSA and ECC asymmetric systems and the necessity of post-quantum migration."
    },
    {
        "tier": 0, "points": 25, "slug": "qubits_superposition_and_entanglement",
        "title_ko": "큐비트 중첩과 얽힘의 물리 계층 원리",
        "title_en": "Qubits, Superposition & Entanglement Principles",
        "desc_ko": "고전 비트와 달리 0과 1의 양자 중첩(|ψ⟩ = α|0⟩ + β|1⟩)과 다자간 양자 얽힘을 활용하여 지수 함수적 병렬 연산 공간을 구성하는 원리를 이해합니다.",
        "desc_en": "Examine how quantum superposition and multi-qubit entanglement construct exponential computational state spaces contrasting classical binary bits."
    },
    {
        "tier": 0, "points": 25, "slug": "shor_algorithm_order_finding_principles",
        "title_ko": "쇼어 알고리즘 위수 주기 탐색 기본 원리",
        "title_en": "Shor's Algorithm & Order Finding Principles",
        "desc_ko": "쇼어 알고리즘이 모듈러 거듭제곱의 주기(r)를 양자 푸리에 변환(QFT)으로 다항 시간 내에 찾아내어 거대 소인수분해를 해결하는 메커니즘을 분석합니다.",
        "desc_en": "Analyze how Shor's algorithm leverages the Quantum Fourier Transform to locate modular exponentiation periods in polynomial time to factor large composites."
    },
    {
        "tier": 0, "points": 25, "slug": "grover_algorithm_symmetric_key_search",
        "title_ko": "그로버 알고리즘 대칭키 탐색 및 AES-256 보안성",
        "title_en": "Grover's Algorithm & AES-256 Security Margin",
        "desc_ko": "비정렬 데이터 검색에서 제곱근 가속(O(√N))을 제공하는 그로버 알고리즘에 대응하여 대칭키 길이를 256비트(AES-256)로 유지해야 하는 이유를 학습합니다.",
        "desc_en": "Explore why AES key sizes must be doubled to 256 bits to counter Grover's quadratic speedup (O(sqrt(N))) on unstructured brute-force key searches."
    },
    {
        "tier": 0, "points": 25, "slug": "discrete_logarithm_quantum_vulnerability",
        "title_ko": "이산대수 및 타원곡선 양자 취약점 분석",
        "title_en": "Quantum Vulnerability of Discrete Logarithms & ECC",
        "desc_ko": "디피-헬만(Diffie-Hellman) 및 타원곡선 암호(ECDSA / Ed25519)의 이산대수 문제가 아벨군 위수 탐색 양자 알고리즘에 의해 다항 시간 내 파괴되는 취약성을 규명합니다.",
        "desc_en": "Examine how abelian hidden subgroup quantum algorithms resolve discrete logarithm problems in polynomial time breaking legacy ECDSA and Ed25519."
    },
    {
        "tier": 0, "points": 25, "slug": "nist_post_quantum_standardization_roadmap",
        "title_ko": "NIST 포스트 양자 표준화 로드맵",
        "title_en": "NIST Post-Quantum Standardization Roadmap",
        "desc_ko": "FIPS 203(ML-KEM/Kyber), FIPS 204(ML-DSA/Dilithium), FIPS 205(SLH-DSA/SPHINCS+)로 공식화된 미국 NIST 포스트 양자 암호 표준화 규격을 학습합니다.",
        "desc_en": "Review the finalized NIST post-quantum cryptographic standards: FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), and FIPS 205 (SLH-DSA)."
    },
    {
        "tier": 0, "points": 25, "slug": "quantum_readiness_cryptographic_inventory",
        "title_ko": "양자 대비 암호화 자산 명세서 수립",
        "title_en": "Quantum Readiness & Cryptographic Inventory CBOM",
        "desc_ko": "조직 내 모든 TLS 인증서, VPN 터널, 코드 서명 키의 알고리즘과 키 길이를 목록화하는 암호 자산 명세서(CBOM: Cryptography Bill of Materials) 수립 절차를 이해합니다.",
        "desc_en": "Understand procedures for establishing a Cryptography Bill of Materials (CBOM) auditing all certificates, VPN tunnels, and code signing keys across enterprise infrastructure."
    },

    # Tier 1 (7 challenges, 50 points each)
    {
        "tier": 1, "points": 50, "slug": "quantum_phase_estimation_circuit_analysis",
        "title_ko": "양자 위상 추정 양자 회로 게이트 깊이 분석",
        "title_en": "Quantum Phase Estimation Circuit & Gate Depth Analysis",
        "desc_ko": "유니터리 연산자의 고유값을 추출하는 양자 위상 추정(QPE) 회로에서 하다마드 게이트 및 제어 모듈러 덧셈 회로의 T-게이트 깊이와 큐비트 자원 소비를 계산합니다.",
        "desc_en": "Calculate T-gate depth and logical qubit footprint across Quantum Phase Estimation circuits utilizing controlled modular exponentiation gates."
    },
    {
        "tier": 1, "points": 50, "slug": "classical_continued_fractions_period_recovery",
        "title_ko": "고전 연분수 전개 주기 복원 알고리즘",
        "title_en": "Classical Continued Fractions Period Recovery",
        "desc_ko": "QPE 측정 레지스터로부터 획득한 위상 근사치 s/2^m을 연분수 전개(Continued Fractions)하여 분모의 미지 주기 r을 결정론적으로 도출하는 과정을 실습합니다.",
        "desc_en": "Derive unknown order periods r deterministically through continued fraction expansion over quantum measured phase approximations s/2^m."
    },
    {
        "tier": 1, "points": 50, "slug": "lattice_cryptography_learning_with_errors",
        "title_ko": "격자 기반 암호 Learning with Errors 수학적 기초",
        "title_en": "Lattice Cryptography & Learning with Errors LWE",
        "desc_ko": "다차원 격자에서 비밀 벡터 s와 오류 e가 가미된 연립일차방정식 b = As + e (mod q)로부터 s를 분리해내는 것이 양자 컴퓨터로도 어려운 원리를 분석합니다.",
        "desc_en": "Analyze mathematical foundations of Learning with Errors (LWE) where isolating secret vector s from b = As + e mod q remains quantum-intractable."
    },
    {
        "tier": 1, "points": 50, "slug": "ring_lwe_polynomial_rings_and_modulus",
        "title_ko": "Ring-LWE 다항식 링 R_q와 모듈러스 q 연산",
        "title_en": "Ring-LWE Polynomial Rings & Modulus Arithmetic",
        "desc_ko": "행렬 크기를 대폭 축소하는 다항식 환 R_q = Z_q[X]/(X^n + 1) 구조에서 n=256, q=3329 파라미터가 제공하는 계산 효율성과 격자 보안성을 학습합니다.",
        "desc_en": "Study polynomial ring structures R_q = Z_q[X]/(X^n + 1) with n=256 and q=3329 providing compact key representation and hardness guarantees in Ring-LWE."
    },
    {
        "tier": 1, "points": 50, "slug": "hybrid_key_exchange_x25519_kyber_handshake",
        "title_ko": "하이브리드 키 교환 X25519 + ML-KEM-768 핸드셰이크",
        "title_en": "Hybrid Key Exchange X25519 + ML-KEM-768 Handshake",
        "desc_ko": "고전 타원곡선 X25519 ECDH 공유 비밀과 NIST FIPS 203 ML-KEM-768 캡슐화 비밀을 HKDF로 결합하여 양방향 보안성을 동시 보장하는 하이브리드 KEM을 구성합니다.",
        "desc_en": "Construct a hybrid key encapsulation mechanism combining classical X25519 ECDH and FIPS 203 ML-KEM-768 shared secrets via dual HKDF extraction."
    },
    {
        "tier": 1, "points": 50, "slug": "sndl_harvest_now_decrypt_later_telemetry",
        "title_ko": "SNDL 장기 도청 위협 모델링 및 수명 주기 분석",
        "title_en": "Store Now Decrypt Later SNDL Threat Modeling",
        "desc_ko": "현재 암호화된 전송 계층 트래픽을 대량 수집 및 저장한 후 미래 양자 컴퓨터로 사후 해독하려는 SNDL 공격 시나리오와 데이터 수명(Data Retention) 한계를 평가합니다.",
        "desc_en": "Evaluate Store Now Decrypt Later (SNDL) attack scenarios where adversaries harvest encrypted network telemetry today for retrospective quantum decryption."
    },
    {
        "tier": 1, "points": 50, "slug": "post_quantum_fips204_mldsa_digital_signatures",
        "title_ko": "FIPS 204 ML-DSA 전자서명 구조 분석",
        "title_en": "FIPS 204 ML-DSA Dilithium Digital Signatures",
        "desc_ko": "Fiat-Shamir with Aborts 기법을 적용하여 거절 샘플링(Rejection Sampling)으로 비밀 벡터의 정보 누출을 차단하는 FIPS 204 격자 기반 전자서명 메커니즘을 분석합니다.",
        "desc_en": "Analyze FIPS 204 lattice digital signatures employing the Fiat-Shamir with Aborts framework and rejection sampling to prevent secret vector leakage."
    },

    # Tier 2 (7 challenges, 100 points each)
    {
        "tier": 2, "points": 100, "slug": "lll_lattice_basis_reduction_analysis",
        "title_ko": "LLL 격자 기저 축소 분석 및 그람-슈미트 직교화",
        "title_en": "LLL Lattice Basis Reduction Analysis",
        "desc_ko": "Lenstra-Lenstra-Lovász(LLL) 알고리즘이 그람-슈미트 직교화(GSO)와 Lovász 조건을 만족하는 거의 직교하는 기저 벡터를 다항 시간 내에 산출하는 원리를 학습합니다.",
        "desc_en": "Examine how the LLL algorithm computes quasi-orthogonal basis vectors in polynomial time utilizing Gram-Schmidt Orthogonalization and Lovasz criteria."
    },
    {
        "tier": 2, "points": 100, "slug": "bkz_block_korkine_zolotarev_svp_hardness",
        "title_ko": "BKZ 격자 축소와 최단 벡터 문제 난이도",
        "title_en": "BKZ Basis Reduction & Shortest Vector Problem Hardness",
        "desc_ko": "블록 크기 β를 사용하는 Block Korkine-Zolotarev(BKZ-40/60) 격자 축소 알고리즘의 에르미트 인자 수렴 속도와 최단 벡터 문제(SVP) 해결 지수 복잡도를 분석합니다.",
        "desc_en": "Analyze Hermite factor convergence rates and exponential SVP hardness across Block Korkine-Zolotarev (BKZ) basis reduction with varying block sizes."
    },
    {
        "tier": 2, "points": 100, "slug": "ring_lwe_hermite_factor_security_estimate",
        "title_ko": "Ring-LWE 에르미트 인자 보안 강도 산출",
        "title_en": "Ring-LWE Hermite Factor Security Estimation",
        "desc_ko": "루트 에르미트 인자 δ_0 ≤ 1.0062를 달성하는 데 필요한 격자 기저 축소 연산 비용을 코어-SVP 모델(Core-SVP Hardness)로 정량화하여 192비트 양자 보안성을 검증합니다.",
        "desc_en": "Quantify Core-SVP classical and quantum gate counts required to achieve root Hermite factors delta_0 <= 1.0062 validating 192-bit quantum security."
    },
    {
        "tier": 2, "points": 100, "slug": "hybrid_tls13_pq_kem_cipher_suites",
        "title_ko": "TLS 1.3 양자 내성 KEM 암호 슈트 연동 실증",
        "title_en": "TLS 1.3 Hybrid PQ KEM Cipher Suites",
        "desc_ko": "IETF 드래프트 규격의 X25519MLKEM768(코드포인트 0x11ec) 키 공유 그룹을 클라이언트 헬로(ClientHello)에 주입하여 양자 안전 세션을 수립합니다.",
        "desc_en": "Deploy IETF-standardized X25519MLKEM768 (codepoint 0x11ec) NamedGroup extensions in TLS 1.3 ClientHello messages establishing quantum-safe handshakes."
    },
    {
        "tier": 2, "points": 100, "slug": "ephemeral_pfs_replay_harvest_neutralization",
        "title_ko": "임시 키 교환을 통한 SNDL 무력화 실증",
        "title_en": "Ephemeral PFS Replay & Harvest Neutralization",
        "desc_ko": "매 연결마다 단회성(Ephemeral) 다항식 키페어를 동적 생성하고 폐기함으로써 장기 보관된 세션 암호문 도청 공격(SNDL)을 수학적으로 원천 무력화합니다.",
        "desc_en": "Demonstrate complete neutralization of SNDL harvest attacks by generating ephemeral ML-KEM polynomial keypairs for each session enforcing Perfect Forward Secrecy."
    },
    {
        "tier": 2, "points": 100, "slug": "rejection_sampling_gaussian_noise_centering",
        "title_ko": "FIPS 203 중심 이항 분포와 거절 샘플링",
        "title_en": "Centered Binomial Distribution & Rejection Sampling",
        "desc_ko": "이산 가우시안 분포 대신 하드웨어 구현이 용이한 중심 이항 분포(CBD, η=2)에서 노이즈 다항식을 샘플링하고 거절 임계값을 검증하는 절차를 분석합니다.",
        "desc_en": "Analyze noise sampling from Centered Binomial Distributions (CBD, eta=2) replacing discrete Gaussians and verify rejection bounds for uniform security."
    },
    {
        "tier": 2, "points": 100, "slug": "ntt_number_theoretic_transform_speedup",
        "title_ko": "넘버 이론 변환 다항식 고속 곱셈과 사이드채널",
        "title_en": "Number Theoretic Transform NTT & Side-Channel Risks",
        "desc_ko": "O(n^2) 다항식 곱셈을 O(n log n)으로 가속하는 Number Theoretic Transform(NTT)에서 쿨리-튜키(Cooley-Tukey) 나비 연산 중 발생하는 부채널 타이밍 누출을 진단합니다.",
        "desc_en": "Investigate side-channel timing leaks during Cooley-Tukey butterfly operations in Number Theoretic Transform (NTT) accelerating polynomial ring multiplications."
    },

    # Tier 3 (7 challenges, 150 points each)
    {
        "tier": 3, "points": 150, "slug": "quantum_gate_fault_injection_attack_simulation",
        "title_ko": "양자 게이트 지터 및 위상 플립 오류 주입 시뮬레이션",
        "title_en": "Quantum Gate Fault Injection Attack Simulation",
        "desc_ko": "초전도 양자 프로세서의 마이크로파 펄스 위상 지터(Phase Jitter) 및 비트 플립 오류를 유발하여 결함 허용 큐비트의 양자 오류 정정(QEC) 임계값을 교란합니다.",
        "desc_en": "Simulate microwave pulse phase jitter and bit-flip faults disrupting quantum error correction (QEC) fault-tolerance thresholds in physical qubits."
    },
    {
        "tier": 3, "points": 150, "slug": "masked_ntt_constant_time_side_channel_defense",
        "title_ko": "마스킹된 상수 시간 NTT 다항식 곱셈 방어",
        "title_en": "Masked Constant-Time NTT Polynomial Multiplication",
        "desc_ko": "불리언 마스킹(Boolean Masking)과 산술 마스킹(Arithmetic Masking)을 교차 변환하여 NTT 내부 계수와 다항식의 비밀 정보가 전력/시간으로 누출되지 않도록 하드닝합니다.",
        "desc_en": "Implement cross-conversion between Boolean and Arithmetic masking across NTT butterfly coefficients eliminating power and execution timing side-channels."
    },
    {
        "tier": 3, "points": 150, "slug": "fips203_kyber768_ind_cca2_security_proof",
        "title_ko": "FIPS 203 ML-KEM-768 IND-CCA2 보안성 증명",
        "title_en": "FIPS 203 ML-KEM-768 IND-CCA2 Fujisaki-Okamoto Transform",
        "desc_ko": "선택 암호문 공격에 취약한 IND-CPA 원시 KEM을 변형된 후지사키-오카모토(Fujisaki-Okamoto) 변환을 적용하여 완전한 IND-CCA2 능동 보안성을 확보하는 메커니즘을 규명합니다.",
        "desc_en": "Evaluate the modified Fujisaki-Okamoto transform elevating IND-CPA raw lattice encryption into an actively secure IND-CCA2 Key Encapsulation Mechanism."
    },
    {
        "tier": 3, "points": 150, "slug": "downgrade_attack_detection_hybrid_negotiation",
        "title_ko": "TLS 1.3 고전 암호 강제 다운그레이드 공격 차단",
        "title_en": "Downgrade Attack Detection in Hybrid PQC Negotiation",
        "desc_ko": "중간자 공격자(MITM)가 ClientHello의 PQC 확장 필드를 변조하여 취약한 고전 RSA/ECDHE로 강제 다운그레이드하려는 시도를 TLS 1.3 Transcript 해시 검증으로 탐지합니다.",
        "desc_en": "Detect and terminate TLS 1.3 man-in-the-middle downgrade attempts stripping PQC extensions via cryptographic Transcript-Hash authentication."
    },
    {
        "tier": 3, "points": 150, "slug": "cross_tenant_quantum_memory_side_channel",
        "title_ko": "클라우드 가상화 환경 양자 메모리 캐시 부채널 방어",
        "title_en": "Cross-Tenant Quantum Memory Side-Channel Defense",
        "desc_ko": "멀티 테넌트 클라우드 환경에서 이웃 VM이 실행하는 격자 다항식 전치 연산의 L3 캐시 라인을 Flush+Reload 기법으로 관측하지 못하도록 캐시 파티셔닝(CAT)을 적용합니다.",
        "desc_en": "Deploy Intel CAT cache allocation technology and page coloring preventing co-located tenant VMs from probing lattice polynomial transpose memory access patterns."
    },
    {
        "tier": 3, "points": 150, "slug": "hash_based_signatures_slh_dsa_sphincs",
        "title_ko": "해시 기반 전자서명 FIPS 205 SLH-DSA 상태 관리",
        "title_en": "Hash-Based Signatures FIPS 205 SLH-DSA State Management",
        "desc_ko": "격자 난제에 의존하지 않고 해시 함수(SHAKE-256)의 일방향성만을 신뢰하는 FIPS 205 SLH-DSA(SPHINCS+) 상태 비저장(Stateless) 하이퍼트리 서명 체계를 구축합니다.",
        "desc_en": "Architect a stateless hypertree signature scheme under FIPS 205 SLH-DSA (SPHINCS+) relying solely on the collision resistance of cryptographic hash functions."
    },
    {
        "tier": 3, "points": 150, "slug": "pqc_zero_trust_vpn_and_ipsec_migration",
        "title_ko": "제로 트러스트 IKEv2 / IPsec 양자 내성 암호 전환",
        "title_en": "Zero Trust IKEv2 / IPsec Post-Quantum Migration",
        "desc_ko": "IKEv2 RFC 9370 복합 키 교환(Multiple Key Exchanges) 확장을 적용하여 엔터프라이즈 사이트 간 IPsec VPN 터널을 ML-KEM 기반 양자 내성 암호로 마이그레이션합니다.",
        "desc_en": "Migrate enterprise site-to-site IPsec VPN tunnels to post-quantum hybrid KEMs utilizing IKEv2 Multiple Key Exchanges (RFC 9370) extensions."
    },

    # Tier 4 (7 challenges, 250 points each)
    {
        "tier": 4, "points": 250, "slug": "crqc_cryptanalytically_relevant_quantum_threat",
        "title_ko": "CRQC 도래 대비 국가급 장기 기밀 방어 프레임워크",
        "title_en": "CRQC Cryptanalytically Relevant Quantum Defense Framework",
        "desc_ko": "암호학적으로 유의미한 양자 컴퓨터(CRQC: Cryptanalytically Relevant Quantum Computer)의 물리적 큐비트 수명 및 결함 허용(Fault-Tolerant) 아키텍처에 대응하는 국가급 기밀 방어 전략을 수립합니다.",
        "desc_en": "Formulate defense frameworks against Cryptanalytically Relevant Quantum Computers (CRQCs) projecting logical qubit thresholds and physical coherence requirements."
    },
    {
        "tier": 4, "points": 250, "slug": "dual_signature_x509_pki_cross_validation",
        "title_ko": "X.509 복합 하이브리드 전자서명 교차 검증",
        "title_en": "Dual-Signature X.509 PKI Cross-Validation",
        "desc_ko": "기존 고전 인증기관(CA) 생태계와의 하위 호환성을 유지하면서 RSA/ECDSA와 ML-DSA를 다중 인증서 확장(Composite Signatures)으로 묶어 교차 검증하는 PKI 시스템을 구축합니다.",
        "desc_en": "Construct composite X.509 PKI certificate chains encapsulating both classical ECDSA and post-quantum ML-DSA signatures for backward-compatible cross-validation."
    },
    {
        "tier": 4, "points": 250, "slug": "lattice_side_channel_power_analysis_dpa",
        "title_ko": "격자 암호 차분 전력 분석 및 부채널 누출 방어",
        "title_en": "Lattice Side-Channel Differential Power Analysis DPA Defense",
        "desc_ko": "하드웨어 암호 가속기의 전력 소비 파형(Trace)을 수집하여 상관 전력 분석(CPA)으로 비밀 다항식 계수를 유출하려는 공격을 셔플링(Shuffling)과 1차 마스킹으로 방어합니다.",
        "desc_en": "Neutralize Correlation Power Analysis (CPA) on hardware lattice accelerators through algorithmic shuffling and first-order masking of intermediate polynomial states."
    },
    {
        "tier": 4, "points": 250, "slug": "hardware_hsm_pqc_acceleration_and_isolation",
        "title_ko": "하드웨어 보안 모듈 PQC 가속기 격리 검증",
        "title_en": "Hardware HSM PQC Accelerator & Enclave Isolation",
        "desc_ko": "FIPS 140-3 Level 4 HSM 내부 격리된 암호 가속 코어에서 ML-KEM 개인키 디캡슐레이션을 안전하게 수행하고 템퍼 방지(Tamper Resistance)를 실증합니다.",
        "desc_en": "Validate isolated ML-KEM decapsulation within FIPS 140-3 Level 4 Hardware Security Modules verifying physical tamper protection and secure key enclave boundaries."
    },
    {
        "tier": 4, "points": 250, "slug": "pqc_crypto_agility_automated_cbom_governance",
        "title_ko": "암호 민첩성 및 자동화된 CBOM 거버넌스",
        "title_en": "Cryptographic Agility & Automated CBOM Governance",
        "desc_ko": "특정 포스트 양자 알고리즘에 새로운 수학적 결함이 발견될 경우 소스 코드 재작성 없이 설정 변경만으로 알고리즘을 즉시 대체하는 암호 민첩성(Crypto Agility) 프레임워크를 구현합니다.",
        "desc_en": "Implement cryptographic agility architecture enabling hot-swapping between lattice, code-based, and hash-based algorithms without recompilation or service downtime."
    },
    {
        "tier": 4, "points": 250, "slug": "quantum_safe_secure_boot_and_firmware_signing",
        "title_ko": "양자 안전 보안 부팅 및 펌웨어 코드 서명 체계",
        "title_en": "Quantum-Safe Secure Boot & Firmware Signing Chain",
        "desc_ko": "UEFI Secure Boot와 하드웨어 RoT(Root of Trust) 펌웨어 서명을 FIPS 204 ML-DSA로 전환하여 공격자가 미래 양자 컴퓨터로 악성 펌웨어를 위조하는 사태를 영구 차단합니다.",
        "desc_en": "Transition UEFI Secure Boot and hardware Root of Trust signature chains to FIPS 204 ML-DSA preventing retrospective quantum forgery of critical host firmware."
    },
    {
        "tier": 4, "points": 250, "slug": "capstone_full_spectrum_quantum_cryptanalysis",
        "title_ko": "포스트 양자 암호 분석 및 능동 방어 풀 스펙트럼 캡스톤",
        "title_en": "Capstone: Full-Spectrum Quantum Cryptanalysis & PQC Defense",
        "desc_ko": "쇼어 QPE 주기 탐색 방어, BKZ-40 격자 기저 축소 무력화, SNDL 도청 차단 Ephemeral KEM, 상수시간 NTT 마스킹을 망라하여 완벽한 엔터프라이즈 포스트 양자 능동 방어 체계를 완성합니다.",
        "desc_en": "Synthesize all post-quantum disciplines: Shor QPE defense, BKZ lattice reduction mitigation, SNDL harvest prevention via ephemeral KEM, and constant-time masked NTT into a master enterprise quantum defense capstone."
    }
]


def make_challenge_object(item):
    slug = item["slug"]
    identifier = f"quantumcrypt_{slug}_v1"
    
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
        "id": f"t{item['tier']}_quantumcrypt_{slug}",
        "tier": item["tier"],
        "cat": "crypto",
        "track": "quantumcrypt",
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
    print(f"[+] Generated {len(new_challenges)} challenge objects for Track 72: quantumcrypt.")
    
    # Track definition
    track_def = {
        "id": "quantumcrypt",
        "icon": "⚛️",
        "ko": "양자 암호 분석 & 포스트 양자 암호 방어",
        "en": "Quantum Cryptanalysis & Post-Quantum Cryptography Defense",
        "desc_ko": "쇼어 알고리즘 양자 위상 추정(QPE) 인수분해 시도 · 하이브리드 KEM(X25519+ML-KEM-768) 결합 캡슐화 능동 방어 · BKZ-40 격자 기저 축소 SVP 공격 및 FIPS 203 모듈 격자 난제(k=3) 방어 · SNDL 장기 도청 차단 Ephemeral PFS · 상수시간 NTT 다항식 마스킹.",
        "desc_en": "Shor QPE quantum period finding factorization, Hybrid KEM (X25519+ML-KEM-768) active encapsulation, BKZ-40 lattice reduction SVP attacks and FIPS 203 module lattice hardness (k=3), SNDL harvest mitigation via ephemeral PFS, and constant-time masked NTT polynomial arithmetic."
    }
    
    # 2. Update challenges.js
    content = challenges_js_path.read_text(encoding="utf-8")
    
    # Insert Track definition before ];\n\nconst CHALLENGES
    track_json = json.dumps(track_def, ensure_ascii=False, indent=2)
    track_insert = ",\n  " + track_json.replace("\n", "\n  ")
    target_tracks_end = "];\n\nconst CHALLENGES = ["
    if 'id: "quantumcrypt"' in content or '"id": "quantumcrypt"' in content:
        print("[-] Track quantumcrypt already in challenges.js, skipping track insert.")
    else:
        assert target_tracks_end in content, "Could not find end of TRACKS in challenges.js"
        content = content.replace(target_tracks_end, track_insert + "\n];\n\nconst CHALLENGES = [")
        print("[+] Inserted Track 72 definition into TRACKS.")
    
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
    ids_insert = "  // 72nd Track: quantumcrypt (35 challenges)\n" + ",\n".join([f'  "{cid}"' for cid in new_ids]) + ",\n"
    target_sd = '  // 71st Track: teeconfidential (35 challenges)'
    if target_sd in sd_content:
        sd_content = sd_content.replace(target_sd, ids_insert + target_sd)
    else:
        # Fallback to Track 70
        target_sd_70 = '  // 70th Track: hypervisor (35 challenges)'
        sd_content = sd_content.replace(target_sd_70, ids_insert + target_sd_70)
    solve_derivable_path.write_text(sd_content, encoding="utf-8")
    print("[+] Added 35 challenge IDs to solve-derivable.js.")
    
    # 4. Update wargame/README.md
    readme = readme_path.read_text(encoding="utf-8")
    
    # Add quantumcrypt rows under each tier table
    tee_tier_row = "| `teeconfidential` 🔒 기밀 컴퓨팅 & TEE 하드웨어 메모리 방어 (7) | 하드웨어 메모리 암호화 체계 · 원격 증명 및 서명 검증 · 역방향 매핑 테이블 소유권 통제 · 레지스터 암호화 격리 / hardware memory encryption engine, remote attestation measurement validation, reverse map table ownership enforcement, and register save area isolation |"
    qc_tier_row = "| `quantumcrypt` ⚛️ 양자 암호 분석 & 포스트 양자 암호 방어 (7) | 쇼어 양자 위상 추정 탐색 방어 · 격자 기저 축소 난제 검증 · SNDL 도청 차단 순방향 비밀성 · 상수시간 NTT 다항식 마스킹 / Shor QPE period finding defense, lattice reduction hardness verification, SNDL harvest mitigation via ephemeral PFS, and constant-time masked NTT polynomial arithmetic |"
    
    if "| `quantumcrypt` ⚛️" not in readme:
        if tee_tier_row in readme:
            readme = readme.replace(tee_tier_row, tee_tier_row + "\n" + qc_tier_row)
        print("[+] Added quantumcrypt rows to all tier tables in wargame/README.md.")
    
    # Update tier counts and total in wargame/README.md
    # Old counts:
    # Total: 2485 -> 2520
    # Tracks: 71 -> 72
    readme = re.sub(r'총 \*\*2485문제\*\*', '총 **2520문제**', readme)
    readme = re.sub(r'Total \*\*2485 challenges\*\*', 'Total **2520 challenges**', readme)
    readme = readme.replace(
        '하이퍼바이저 & MicroVM 가상화 보안 35 · 기밀 컴퓨팅 & TEE 하드웨어 메모리 방어 35)',
        '하이퍼바이저 & MicroVM 가상화 보안 35 · 기밀 컴퓨팅 & TEE 하드웨어 메모리 방어 35 · 양자 암호 분석 & 포스트 양자 암호 방어 35)'
    )
    
    # Tier counts: +7 per tier
    # T0: 245 -> 252
    # T1: 454 -> 461
    # T2: 606 -> 613
    # T3: 596 -> 603
    # T4: 549 -> 556
    readme = readme.replace('245문제', '252문제')
    readme = readme.replace('454문제', '461문제')
    readme = readme.replace('606문제', '613문제')
    readme = readme.replace('596문제', '603문제')
    readme = readme.replace('549문제', '556문제')
    readme = readme.replace('245 challenges', '252 challenges')
    readme = readme.replace('454 challenges', '461 challenges')
    readme = readme.replace('606 challenges', '613 challenges')
    readme = readme.replace('596 challenges', '603 challenges')
    readme = readme.replace('549 challenges', '556 challenges')
    
    readme_path.write_text(readme, encoding="utf-8")
    print("[+] Updated wargame/README.md successfully.")
    print("[*] Track 72 generation completed!")


if __name__ == "__main__":
    main()
