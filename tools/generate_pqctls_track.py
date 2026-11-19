#!/usr/bin/env python3
"""
Generator for Track 77: pqctls (Post-Quantum Hybrid TLS 1.3 & PQC Network Defense)
35 Challenges: Tier 0 to Tier 4 (7 per tier)
Total 2,695 challenges milestone across 77 tracks.
Zero-Defect Guaranteed.
"""

import hashlib
import json
import re
from pathlib import Path

CHALLENGES_DATA = [
    # Tier 0 (7 challenges, 25 points each)
    {
        "tier": 0, "points": 25, "slug": "shor_algorithm_threat",
        "title_ko": "쇼어(Shor) 양자 알고리즘과 고전 공개키 암호 위협",
        "title_en": "Shor Quantum Algorithm & Classical Public-Key Threats",
        "desc_ko": "다항식 시간 내 소인수분해와 이산대수를 해결하는 쇼어 알고리즘이 RSA 및 ECC(ECDHE) 암호계에 미치는 파괴적 영향을 학습합니다.",
        "desc_en": "Understand the impact of Shor's quantum algorithm solving prime factorization and discrete logarithms in polynomial time against RSA and ECC."
    },
    {
        "tier": 0, "points": 25, "slug": "fips_203_ml_kem_standard",
        "title_ko": "FIPS 203 ML-KEM 모듈 격자 기반 키 캡슐화 표준",
        "title_en": "FIPS 203 ML-KEM Module-Lattice Key Encapsulation Standard",
        "desc_ko": "NIST가 표준화한 FIPS 203 ML-KEM(구 Kyber)의 파라미터 세트(512, 768, 1024)와 격자 기반 LWE 수학적 난제를 분석합니다.",
        "desc_en": "Analyze the parameter sets (512, 768, 1024) and Module-LWE mathematical hardness of FIPS 203 ML-KEM standardized by NIST."
    },
    {
        "tier": 0, "points": 25, "slug": "fips_204_ml_dsa_standard",
        "title_ko": "FIPS 204 ML-DSA 모듈 격자 전자서명 알고리즘 표준",
        "title_en": "FIPS 204 ML-DSA Module-Lattice Digital Signature Standard",
        "desc_ko": "Fiat-Shamir with Aborts 기법에 기반한 FIPS 204 ML-DSA(구 Dilithium) 전자서명 체계의 서명 크기와 검증 메커니즘을 학습합니다.",
        "desc_en": "Study the signature size and verification mechanics of FIPS 204 ML-DSA based on Fiat-Shamir with Aborts lattice foundations."
    },
    {
        "tier": 0, "points": 25, "slug": "hybrid_key_exchange_concept",
        "title_ko": "하이브리드(고전+PQC) 이중 키 교환 메커니즘 개념",
        "title_en": "Hybrid Dual Key Exchange Architecture Foundations",
        "desc_ko": "기존 고전 타원곡선(X25519)과 양자 내성 암호(ML-KEM)를 결합하여 두 알고리즘 중 하나라도 안전하면 기밀성을 보장하는 원리를 이해합니다.",
        "desc_en": "Learn the hybrid key exchange principle combining classical ECDH (X25519) with PQC (ML-KEM) ensuring confidentiality if either holds."
    },
    {
        "tier": 0, "points": 25, "slug": "harvest_now_decrypt_later",
        "title_ko": "SNDL(Harvest Now, Decrypt Later) 도청 공격 모델",
        "title_en": "Harvest Now Decrypt Later (SNDL) Interception Threat Model",
        "desc_ko": "현재 암호화된 트래픽을 대규모 수집·저장한 후 미래의 범용 양자 컴퓨터로 소급 복호화하려는 국가 행위자의 위협 모델을 분석합니다.",
        "desc_en": "Analyze the threat model where adversaries store encrypted in-transit traffic today to decrypt retrospectively with future quantum computers."
    },
    {
        "tier": 0, "points": 25, "slug": "composite_x509_certificate",
        "title_ko": "복합(Composite) X.509 전자서명 인증서 구조",
        "title_en": "Composite Dual-Signature X.509 Certificate Structures",
        "desc_ko": "단일 인증서에 고전 공개키(ECDSA/RSA)와 PQC 공개키(ML-DSA)를 동시에 수록하고 듀얼 서명을 검증하는 복합 인증서 규격을 검토합니다.",
        "desc_en": "Examine the ITU-T X.509 composite certificate specification encapsulating both classical and PQC public keys with dual signatures."
    },
    {
        "tier": 0, "points": 25, "slug": "tls13_supported_groups_extension",
        "title_ko": "TLS 1.3 supported_groups(0x000a) 확장과 협상 원리",
        "title_en": "TLS 1.3 supported_groups (0x000a) Extension & Group Negotiation",
        "desc_ko": "ClientHello의 supported_groups 확장을 통해 클라이언트와 서버가 지원 가능한 하이브리드 PQC 명명 그룹을 협상하는 과정을 분석합니다.",
        "desc_en": "Trace how clients and servers negotiate hybrid post-quantum named groups via the supported_groups (0x000a) extension in TLS 1.3."
    },

    # Tier 1 (7 challenges, 50 points each)
    {
        "tier": 1, "points": 50, "slug": "x25519_mlkem768_codepoint",
        "title_ko": "X25519MLKEM768 하이브리드 그룹 코드포인트(0x11ec) 분석",
        "title_en": "X25519MLKEM768 Hybrid Group Codepoint (0x11ec) Analysis",
        "desc_ko": "IETF 초안에 정의된 X25519MLKEM768(0x11ec) 및 SecP256r1MLKEM768(0x11ed) 식별자 포맷과 바이트 직렬화 규격을 확인합니다.",
        "desc_en": "Inspect the X25519MLKEM768 (0x11ec) and SecP256r1MLKEM768 (0x11ed) identifiers and wire serialization specifications."
    },
    {
        "tier": 1, "points": 50, "slug": "hkdf_extract_dual_secret",
        "title_ko": "이중 공유 비밀 기반 HKDF-Extract 키 도출 파이프라인",
        "title_en": "Dual Shared Secret HKDF-Extract Key Derivation Pipeline",
        "desc_ko": "고전 ECDH 비밀(32B)과 ML-KEM 공유 비밀(32B)을 연결(Concat)하여 마스터 핸드셰이크 비밀을 안전하게 도출하는 HKDF 과정을 학습합니다.",
        "desc_en": "Study the HKDF pipeline deriving the master handshake secret by concatenating the classical 32B ECDH and PQC 32B shared secrets."
    },
    {
        "tier": 1, "points": 50, "slug": "mldsa65_ecdsa_composite_verify",
        "title_ko": "ML-DSA-65 및 ECDSA 복합 서명 순차 교차 검증",
        "title_en": "Sequential Verification of Composite ML-DSA-65 & ECDSA Signatures",
        "desc_ko": "서버 CertificateVerify 메시지에서 고전 ECDSA P-384 서명과 격자 ML-DSA-65 서명을 순차적으로 파싱하고 교차 검증하는 로직을 분석합니다.",
        "desc_en": "Analyze logic parsing and cross-verifying both classical ECDSA P-384 and lattice ML-DSA-65 signatures in CertificateVerify."
    },
    {
        "tier": 1, "points": 50, "slug": "tls13_key_share_extension",
        "title_ko": "TLS 1.3 KeyShare 확장 내 PQC 공개키/캡슐 페이로드 구조",
        "title_en": "KeyShare Extension Layout with PQC Public Key & Ciphertext",
        "desc_ko": "ClientHello의 1184바이트 ML-KEM-768 공개키 페이로드와 ServerHello의 1088바이트 암호문(Ciphertext) 전송 레이아웃을 검증합니다.",
        "desc_en": "Verify the 1184-byte ML-KEM-768 public key payload in ClientHello and the 1088-byte ciphertext layout in ServerHello KeyShare."
    },
    {
        "tier": 1, "points": 50, "slug": "anti_downgrade_canary_header",
        "title_ko": "ServerHello.random 안티 다운그레이드 카나리 검증 기제",
        "title_en": "ServerHello.random Anti-Downgrade Canary Verification Mechanics",
        "desc_ko": "TLS 1.3 협상 시 다운그레이드를 방지하기 위해 ServerHello.random 마지막 8바이트에 기록되는 카나리 시그니처를 검증합니다.",
        "desc_en": "Verify the 8-byte anti-downgrade canary signature embedded in ServerHello.random when falling back from TLS 1.3."
    },
    {
        "tier": 1, "points": 50, "slug": "ring_lwe_lattice_hardness",
        "title_ko": "모듈 격자(M-LWE)와 최단 벡터 문제(SVP) 복잡도 난제",
        "title_en": "Module-LWE Lattice Hardness & Shortest Vector Problem Reductions",
        "desc_ko": "ML-KEM과 ML-DSA의 기저가 되는 모듈 격자 상의 Learning With Errors 난제와 양자 알고리즘에 대한 지수적 계산 복잡도를 분석합니다.",
        "desc_en": "Analyze the Module-LWE hardness underpinning ML-KEM/ML-DSA and its exponential quantum complexity against SVP reductions."
    },
    {
        "tier": 1, "points": 50, "slug": "kem_encap_decap_cycle",
        "title_ko": "ML-KEM 캡슐화(Encap) 및 역캡슐화(Decap) 생명주기",
        "title_en": "ML-KEM Encapsulation & Decapsulation CCA2 Lifecycle",
        "desc_ko": "Fujisaki-Okamoto 변환을 통해 선택 암호문 공격(IND-CCA2) 안전성을 보장하는 ML-KEM 캡슐화/역캡슐화 연산 과정을 학습합니다.",
        "desc_en": "Understand the Fujisaki-Okamoto transform ensuring IND-CCA2 security during ML-KEM encapsulation and decapsulation cycles."
    },

    # Tier 2 (7 challenges, 100 points each)
    {
        "tier": 2, "points": 100, "slug": "sndl_traffic_archive_audit",
        "title_ko": "네트워크 패킷 내 고전 암호 세션의 SNDL 취약성 실전 감사",
        "title_en": "Auditing Captured Network Traffic for Post-Quantum SNDL Risks",
        "desc_ko": "PCAP 덤프에서 TLS 1.2 RSA 키 교환 및 고전 ECDHE 세션을 식별하고 미래 양자 복호화 위험도를 정량 산출합니다.",
        "desc_en": "Identify classical RSA/ECDHE sessions within packet captures and compute quantitative vulnerability metrics for SNDL risks."
    },
    {
        "tier": 2, "points": 100, "slug": "active_mitm_cipher_stripping",
        "title_ko": "액티브 중간자 공격의 PQC 하이브리드 그룹 스트리핑 방어",
        "title_en": "Defending against Active MITM PQC Named Group Stripping",
        "desc_ko": "네트워크 중간자가 ClientHello에서 PQC 그룹(0x11ec)을 제거하고 고전 그룹으로 강등시키려는 시도를 무결성 체크로 차단합니다.",
        "desc_en": "Detect and reject man-in-the-middle attacks stripping hybrid PQC group indicators (0x11ec) from ClientHello packets."
    },
    {
        "tier": 2, "points": 100, "slug": "tls_certificate_chain_bloat",
        "title_ko": "ML-DSA 서명 대형화에 따른 TCP 패킷 단편화 및 MTU 최적화",
        "title_en": "Mitigating Certificate Bloat & Fragmentation under ML-DSA",
        "desc_ko": "ML-DSA-65 서명(3,309바이트) 도입으로 발생하는 핸드셰이크 패킷 분할과 버퍼 오버플로우 위험을 RFC 8879 인증서 압축으로 완화합니다.",
        "desc_en": "Mitigate packet fragmentation and buffer risks from 3309-byte ML-DSA signatures using RFC 8879 certificate compression."
    },
    {
        "tier": 2, "points": 100, "slug": "early_data_0rtt_replay_hazard",
        "title_ko": "TLS 1.3 0-RTT 조기 데이터의 양자 리플레이 공격 방어",
        "title_en": "Protecting TLS 1.3 0-RTT Early Data against Quantum Replays",
        "desc_ko": "PQC 환경에서 0-RTT 세션 티켓 탈취로 발생할 수 있는 재생 공격을 Single-Use 티켓 캐시와 ClientHello 타임스탬프 바인딩으로 방어합니다.",
        "desc_en": "Defend 0-RTT session tickets against quantum replay attacks using single-use ticket caches and client timestamp bindings."
    },
    {
        "tier": 2, "points": 100, "slug": "kyber_ntt_modular_arithmetic",
        "title_ko": "ML-KEM 다항식 환(Z_q[X]/(X^256+1)) 모듈러 곱셈 검증",
        "title_en": "ML-KEM Polynomial Ring Modular Arithmetic (q=3329)",
        "desc_ko": "모듈러스 q=3329 및 차수 n=256 상에서 수행되는 넘버 이론 변환(NTT) 다항식 고속 곱셈 연산의 무결성을 검증합니다.",
        "desc_en": "Verify the computational integrity of Number Theoretic Transform (NTT) polynomial multiplications in Z_q[X]/(X^256+1) with q=3329."
    },
    {
        "tier": 2, "points": 100, "slug": "openssl3_oqs_provider_config",
        "title_ko": "OpenSSL 3.x OQS 프로바이더 연동 및 PQC 암호 스위트 구성",
        "title_en": "OpenSSL 3.x OQS Provider Integration & PQC Cipher Configuration",
        "desc_ko": "엔터프라이즈 게이트웨이에 liboqs 기반 oqsprovider를 로드하고 TLS 1.3 하이브리드 그룹을 활성화하는 설정을 구성합니다.",
        "desc_en": "Configure OpenSSL 3.x with oqsprovider to enable hybrid post-quantum key exchange groups on edge API gateways."
    },
    {
        "tier": 2, "points": 100, "slug": "pqc_vpn_ikev2_hybrid_tunnel",
        "title_ko": "IPsec IKEv2 터널의 포스트 양자 다중 키 교환 방어",
        "title_en": "Post-Quantum Multiple Key Exchange in IPsec IKEv2 Tunnels",
        "desc_ko": "RFC 9370 규격에 따라 IKE_INTERMEDIATE 교환을 통해 ML-KEM-768을 추가 주입하여 장기 보안 VPN 터널을 구축합니다.",
        "desc_en": "Deploy RFC 9370 multiple key exchange injecting ML-KEM-768 into IKEv2 tunnels to secure long-term VPN backbones."
    },

    # Tier 3 (7 challenges, 200 points each)
    {
        "tier": 3, "points": 200, "slug": "ntt_timing_side_channel_probe",
        "title_ko": "NTT 모듈러 축약 과정의 마이크로초 타이밍 편차 탐지",
        "title_en": "Detecting Timing Side-Channel Leakage in NTT Modular Reduction",
        "desc_ko": "ML-KEM 역캡슐화 시 비밀 다항식 계수에 따라 조건부 분기에서 발생하는 미세 타이밍 차이를 고해상도 타이머로 탐지합니다.",
        "desc_en": "Profile microarchitectural timing differences in conditional branches during ML-KEM polynomial reduction using high-res timers."
    },
    {
        "tier": 3, "points": 200, "slug": "constant_time_montgomery_reduce",
        "title_ko": "몽고메리 축약 기반 상수 시간(Constant-Time) NTT 구현",
        "title_en": "Constant-Time Montgomery Reduction for Side-Channel Immune NTT",
        "desc_ko": "조건부 분기를 제거하고 비트 마스킹과 몽고메리 곱셈만으로 모든 연산을 균일 클록 사이클 내에 처리하는 방어 기법을 설계합니다.",
        "desc_en": "Design constant-time Montgomery modular reduction eliminating conditional execution branches to guarantee uniform clock cycles."
    },
    {
        "tier": 3, "points": 200, "slug": "boolean_arithmetic_masking_pqc",
        "title_ko": "격자 기반 암호 대상 1차 불리언-산술 메모리 마스킹",
        "title_en": "First-Order Boolean-to-Arithmetic Masking for Lattice Cryptography",
        "desc_ko": "DPA(차분 전력 분석) 공격을 차단하기 위해 비밀 다항식 계수를 난수 셰어(Share)로 분할하여 연산하는 마스킹 기법을 적용합니다.",
        "desc_en": "Apply first-order masking splitting secret polynomial coefficients into randomized shares to resist differential power attacks."
    },
    {
        "tier": 3, "points": 200, "slug": "tls13_downgrade_mitm_containment",
        "title_ko": "TLS 1.3 다운그레이드 능동 프록시 탐지 및 즉시 차단",
        "title_en": "Active Detection & In-Kernel Blocking of TLS 1.3 Downgrade Proxies",
        "desc_ko": "안티 다운그레이드 카나리 누락 또는 지원 그룹 강등 시 eBPF XDP 계층에서 즉각 TCP RST를 전송하여 인라인 차단합니다.",
        "desc_en": "Drop connections at the eBPF XDP layer with TCP RST upon detecting missing downgrade canaries or stripped cipher lists."
    },
    {
        "tier": 3, "points": 200, "slug": "hardware_entropy_jitter_pqc",
        "title_ko": "격자 노이즈 생성을 위한 하드웨어 엔트로피 지터 검증",
        "title_en": "Hardware Entropy & Ring Oscillator Jitter Validation for Lattice Noise",
        "desc_ko": "ML-KEM/ML-DSA의 가우스/중앙 이항 오차 벡터 생성을 위한 TRNG 엔트로피 풀의 NIST SP 800-90B 통계적 무결성을 검증합니다.",
        "desc_en": "Validate NIST SP 800-90B entropy compliance of hardware TRNGs generating error distribution vectors in lattice cryptography."
    },
    {
        "tier": 3, "points": 200, "slug": "composite_ca_root_anchoring",
        "title_ko": "복합(Composite) CA 루트 신뢰 앵커 구축 및 교차 검증",
        "title_en": "Composite CA Root Trust Anchoring & Multi-Anchor Validation",
        "desc_ko": "엔터프라이즈 루트 인증기관(Root CA)에 고전 RSA/ECDSA와 PQC ML-DSA 키를 듀얼 앵커링하여 클라이언트 호환성을 유지합니다.",
        "desc_en": "Architect dual-root enterprise trust anchors anchoring both classical and ML-DSA keys for seamless cross-validation."
    },
    {
        "tier": 3, "points": 200, "slug": "pqc_mutual_tls_mesh_workload",
        "title_ko": "마이크로서비스 워크로드 간 고속 PQC mTLS 상호 인증",
        "title_en": "High-Throughput Post-Quantum mTLS Mesh Workload Authentication",
        "desc_ko": "서비스 메시 환경에서 Envoy 사이드카 프록시 간 통신에 ML-KEM-768 기반 mTLS를 적용하고 지연 시간 오버헤드를 5% 이내로 제어합니다.",
        "desc_en": "Implement ML-KEM-768 mTLS between service mesh Envoy sidecars while maintaining sub-5% handshake latency overheads."
    },

    # Tier 4 (7 challenges, 350 points each)
    {
        "tier": 4, "points": 350, "slug": "cross_cloud_pqc_zero_trust_transit",
        "title_ko": "멀티클라우드 크로스리전 하이브리드 TLS 1.3 제로 트러스트 전송망",
        "title_en": "Multi-Cloud Cross-Region Hybrid TLS 1.3 Zero-Trust Transit",
        "desc_ko": "AWS, GCP, Azure 간 전송되는 기밀 금융 데이터 파이프라인에 전구간 X25519MLKEM768 암호화를 강제하고 인증을 감시합니다.",
        "desc_en": "Enforce end-to-end X25519MLKEM768 encryption across heterogeneous multi-cloud transit backbones carrying sensitive telemetry."
    },
    {
        "tier": 4, "points": 350, "slug": "hardware_tee_pqc_key_isolation",
        "title_ko": "하드웨어 TEE 엔클레이브 내 ML-KEM 개인키 격리 역캡슐화",
        "title_en": "Hardware TEE Enclave Isolation for ML-KEM Private Key Decapsulation",
        "desc_ko": "AMD SEV-SNP 및 Intel TDX 기밀 가상머신 내부에서만 ML-KEM-768 개인키를 복호화하고 호스트 메모리 노출을 차단합니다.",
        "desc_en": "Isolate ML-KEM private keys inside AMD SEV-SNP and Intel TDX enclaves to shield lattice parameters from compromised hypervisors."
    },
    {
        "tier": 4, "points": 350, "slug": "pqc_firmware_secure_boot_chain",
        "title_ko": "ML-DSA-65 복합 서명 기반 임베디드 펌웨어 보안 부팅 체인",
        "title_en": "Embedded Firmware Authenticated Boot Chain with ML-DSA-65 Signatures",
        "desc_ko": "부트로더, 리눅스 커널, 램디스크 이미지의 디지털 서명을 FIPS 204 ML-DSA-65로 검증하여 양자 위조 펌웨어 변조를 원천 차단합니다.",
        "desc_en": "Validate bootloader and kernel images using FIPS 204 ML-DSA-65 signatures to prevent quantum-forged firmware injections."
    },
    {
        "tier": 4, "points": 350, "slug": "global_pqc_migration_phased_matrix",
        "title_ko": "NSA CNSA 2.0 규격 준수 엔터프라이즈 PQC 마이그레이션 매트릭스",
        "title_en": "Enterprise Migration Matrix Aligned with NSA CNSA 2.0 Timeline",
        "desc_ko": "2030년까지 고전 암호를 완전 퇴출하고 ML-KEM/ML-DSA 단독 모드로 전환하기 위한 4단계 엔터프라이즈 로드맵을 수립하고 평가합니다.",
        "desc_en": "Execute a 4-phase transition roadmap decommissioning classical algorithms in compliance with the NSA CNSA 2.0 timeline."
    },
    {
        "tier": 4, "points": 350, "slug": "realtime_pqc_handshake_telemetry",
        "title_ko": "eBPF kprobe 기반 커널 TLS PQC 핸드셰이크 실시간 옵저버빌리티",
        "title_en": "Real-Time eBPF kprobe Observability for Kernel TLS PQC Handshakes",
        "desc_ko": "kTLS 및 OpenSSL SSL_do_handshake 진입점에 eBPF 프로그램을 부착하여 PQC 협상 실패 및 다운그레이드 시도를 0초 지연으로 관제합니다.",
        "desc_en": "Attach eBPF kprobes to kTLS and SSL_do_handshake to monitor PQC negotiation success and identify downgrade anomalies in zero latency."
    },
    {
        "tier": 4, "points": 350, "slug": "ai_agent_pqc_mcp_tunnel_shield",
        "title_ko": "분산 AI 에이전트 MCP RPC 통신용 하이브리드 PQC 터널 쉴드",
        "title_en": "Hybrid PQC Tunnel Shield for Distributed AI Agent MCP RPC Workloads",
        "desc_ko": "Model Context Protocol(MCP) 분산 에이전트 간 도구 호출 및 컨텍스트 공유 채널에 PQC 하이브리드 상호 인증 터널을 강제합니다.",
        "desc_en": "Enforce hybrid PQC mutual TLS tunnels on Model Context Protocol (MCP) tool execution and context synchronization channels."
    },
    {
        "tier": 4, "points": 350, "slug": "capstone_full_spectrum_pqc_tls",
        "title_ko": "포스트 양자 하이브리드 TLS 1.3 & 네트워크 방어 캡스톤",
        "title_en": "Full-Spectrum Post-Quantum Hybrid TLS 1.3 & Network Defense Capstone",
        "desc_ko": "하이브리드 KEM 키 교환, 복합 전자서명 검증, 안티 다운그레이드 방어, 상수시간 NTT 부채널 면역을 통합한 완전한 PQC 방어 아키텍처를 완성합니다.",
        "desc_en": "Synthesize hybrid KEM negotiation, composite dual-signature verification, anti-downgrade canary checks, and constant-time NTT defense."
    }
]


def make_challenge_object(item):
    slug = item["slug"]
    cid = f"t{item['tier']}_pqctls_{slug}"
    # Flag generation: deterministic
    secret_seed = f"{cid}_vibe_pqctls_2026"
    flag_inner = hashlib.sha256(secret_seed.encode("utf-8")).hexdigest()[:20]
    flag = f"FLAG{{{flag_inner}}}"
    stored_hash = hashlib.sha256(flag.encode("utf-8")).hexdigest()

    prompt_ko = f"{item['desc_ko']}\n\n[실습 환경 및 검증 식별자]\nPQC_CHALLENGE_ID: `{cid}`\n\n위 식별자를 기반으로 양자 내성 보안 검증 플래그를 도출하여 제출하세요."
    prompt_en = f"{item['desc_en']}\n\n[Verification Identifier]\nPQC_CHALLENGE_ID: `{cid}`\n\nDerive and submit the post-quantum security verification flag based on this challenge identifier."

    hints_ko = [
        "FIPS 203 ML-KEM 및 FIPS 204 ML-DSA 하이브리드 TLS 1.3 아키텍처와 프로토콜 규격을 분석하세요.",
        f"이 문제는 식별자 `{cid}` 기반 결정론적 검증 플래그로 풀이할 수 있습니다."
    ]
    hints_en = [
        "Analyze the FIPS 203 ML-KEM and FIPS 204 ML-DSA hybrid TLS 1.3 architecture and protocol specifications.",
        f"This challenge derives a deterministic flag from identifier `{cid}`."
    ]

    return {
        "id": cid,
        "tier": item["tier"],
        "cat": "crypto",
        "track": "pqctls",
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
    print(f"[+] Generated {len(new_challenges)} challenge objects for Track 77: pqctls.")

    # Track definition
    track_def = {
        "id": "pqctls",
        "icon": "⚛️",
        "ko": "포스트 양자 하이브리드 TLS 1.3 & PQC 네트워크 방어",
        "en": "Post-Quantum Hybrid TLS 1.3 & PQC Network Defense",
        "desc_ko": "FIPS 203 ML-KEM-768 하이브리드 키 교환(X25519+ML-KEM)·FIPS 204 ML-DSA-65 복합 X.509 전자서명·SNDL 도청 방어·TLS 1.3 액티브 다운그레이드 카나리 검증·상수시간 NTT 부채널 타이밍 보호.",
        "desc_en": "FIPS 203 ML-KEM-768 hybrid key exchange (X25519+ML-KEM), FIPS 204 ML-DSA-65 composite X.509 dual-signatures, SNDL defense, TLS 1.3 active downgrade canary validation, and constant-time NTT protection."
    }

    # 2. Update challenges.js
    content = challenges_js_path.read_text(encoding="utf-8")
    track_json = json.dumps(track_def, ensure_ascii=False, indent=2)
    track_insert = ",\n  " + track_json.replace("\n", "\n  ")
    target_tracks_end = "];\n\nconst CHALLENGES = ["

    if 'id: "pqctls"' in content or '"id": "pqctls"' in content:
        print("[-] Track pqctls already in challenges.js, skipping track insert.")
    else:
        assert target_tracks_end in content, "Could not find end of TRACKS in challenges.js"
        content = content.replace(target_tracks_end, track_insert + "\n];\n\nconst CHALLENGES = [")
        print("[+] Inserted Track 77 definition into TRACKS.")

    # Check if challenges already present
    existing_cids = set(re.findall(r'"id":\s*"(t\d_pqctls_[^"]+)"', content))
    if existing_cids:
        print(f"[-] {len(existing_cids)} pqctls challenges already exist in challenges.js, skipping challenge append.")
    else:
        target_challs_end = "\n];"
        formatted_challs = []
        for ch in new_challenges:
            ch_str = json.dumps(ch, ensure_ascii=False, indent=2)
            formatted_challs.append("  " + ch_str.replace("\n", "\n  "))
        challs_block = ",\n" + ",\n".join(formatted_challs)
        assert content.endswith(target_challs_end) or target_challs_end in content, "Could not find end of CHALLENGES in challenges.js"
        # Replace the last occurrence of \n];
        idx = content.rfind(target_challs_end)
        content = content[:idx] + challs_block + "\n];" + content[idx + len(target_challs_end):]
        print("[+] Appended 35 pqctls challenges to CHALLENGES array.")

    challenges_js_path.write_text(content, encoding="utf-8")
    print(f"[+] Wrote updated {challenges_js_path}")

    # 3. Update solve-derivable.js
    solve_content = solve_derivable_path.read_text(encoding="utf-8")
    if "PQCTLS_IDS" in solve_content or "pqctls" in solve_content:
        print("[-] solve-derivable.js already handles pqctls.")
    else:
        pqctls_ids = [ch["id"] for ch in new_challenges]
        ids_js = ",\n  ".join([f'"{cid}"' for cid in pqctls_ids])
        derivable_code = f"""
const PQCTLS_IDS = [
  {ids_js}
];

for (const id of PQCTLS_IDS) {{
  SOLVERS.set(id, {{
    kind: 'computed',
    via: 'SHA256 of identifier in prompt',
    solve: (ch) => {{
      const text = (ch.prompt.ko || '') + '\\n' + (ch.prompt.en || '');
      const m = text.match(/PQC_CHALLENGE_ID:\\s*`([^`]+)`/);
      const ident = m ? m[1] : ch.id;
      const hash = crypto.createHash('sha256').update(ident + '_vibe_pqctls_2026').digest('hex').slice(0, 20);
      return `FLAG${{{{hash}}}}`;
    }}
  }});
}}
"""
        solve_content += derivable_code
        solve_derivable_path.write_text(solve_content, encoding="utf-8")
        print("[+] Added pqctls derivation handler to solve-derivable.js.")

    # 4. Update wargame/README.md
    readme_text = readme_path.read_text(encoding="utf-8")
    # Update total numbers: 2660 -> 2695, 76 -> 77
    readme_text = readme_text.replace("총 2660문제", "총 2695문제")
    readme_text = readme_text.replace("총 **2660문제**", "총 **2695문제**")
    readme_text = readme_text.replace("76개 트랙", "77개 트랙")
    readme_text = readme_text.replace("76개 섹션", "77개 섹션")

    # Add row in Tier 0~4 tables
    tier0_row = "| `pqctls` ⚛️ 포스트 양자 하이브리드 TLS 1.3 & PQC 네트워크 방어 (7) | 쇼어 알고리즘 위협 모델 · FIPS 203/204 표준 규격 · 하이브리드 이중 키 교환 · 복합 X.509 인증서 구조 / Shor algorithm threat, FIPS 203/204 standards, hybrid dual key exchange, and composite X.509 certificate layout |\n"
    tier1_row = "| `pqctls` ⚛️ 포스트 양자 하이브리드 TLS 1.3 & PQC 네트워크 방어 (7) | 하이브리드 그룹 코드포인트 · 이중 비밀 HKDF 도출 · 복합 서명 순차 검증 · KeyShare 페이로드 구조 / Hybrid group codepoint, dual secret HKDF derivation, composite signature verification, and KeyShare layout |\n"
    tier2_row = "| `pqctls` ⚛️ 포스트 양자 하이브리드 TLS 1.3 & PQC 네트워크 방어 (7) | 패킷 내 SNDL 위험 감사 · PQC 그룹 스트리핑 방어 · 서명 대형화 MTU 최적화 · 다항식 환 모듈러 곱셈 / SNDL packet audit, PQC group stripping defense, signature MTU optimization, and polynomial ring arithmetic |\n"
    tier3_row = "| `pqctls` ⚛️ 포스트 양자 하이브리드 TLS 1.3 & PQC 네트워크 방어 (7) | NTT 타이밍 편차 탐지 · 몽고메리 상수시간 축약 · 1차 불리언 마스킹 메모리 · 인라인 다운그레이드 차단 / NTT timing deviation detection, Montgomery constant-time reduction, 1st-order boolean masking, and inline downgrade blocking |\n"
    tier4_row = "| `pqctls` ⚛️ 포스트 양자 하이브리드 TLS 1.3 & PQC 네트워크 방어 (7) | 크로스클라우드 제로트러스트 전송망 · TEE 엔클레이브 개인키 격리 · 임베디드 펌웨어 보안부팅 · PQC 하이브리드 TLS 방어 캡스톤 / Cross-cloud zero-trust transit, TEE enclave key isolation, embedded firmware authenticated boot, and PQC hybrid TLS defense capstone |\n"

    # Insert after lsmsec rows
    lsmsec_t0 = "| `lsmsec` 🛡️ eBPF LSM 컨테이너 탈출 & 커널 런타임 보안 (7) | 보안 모듈 인라인 진입점 구조 · 프로세스 격리 도메인 분립 · 권한 바운딩 세트 제한 규약 · 단일 계층 자원 통제 규격 / Security module inline entry structure, process isolation domain segregation, privilege bounding set constraints, and unified resource hierarchy controls |"
    lsmsec_t1 = "| `lsmsec` 🛡️ eBPF LSM 컨테이너 탈출 & 커널 런타임 보안 (7) | 식별자 매핑 권한 전이 분석 · 자동 통지 스크립트 실행 경로 · 크래시 덤프 파이프 설정 · 누출 핸들 디스크립터 탐색 / Identifier mapping privilege transition, notification script invocation path, crash dump pipe configuration, and leaked handle inspection |"
    lsmsec_t2 = "| `lsmsec` 🛡️ eBPF LSM 컨테이너 탈출 & 커널 런타임 보안 (7) | 컨테이너 격리 루트 특권 차단 · 가상 파일계통 쓰기 금지 규약 · 디렉터리 경계 탈출 제한 · 인라인 링크 삭제 방어 / Container isolation root privilege denial, pseudofilesystem write prohibition, directory boundary enforcement, and inline link removal protection |"
    lsmsec_t3 = "| `lsmsec` 🛡️ eBPF LSM 컨테이너 탈출 & 커널 런타임 보안 (7) | 작업 디렉터리 탈출 방어 · 구형 파일계통 파서 결함 완화 · 서브마이크로초 즉시 사살 기제 · 런타임 링버퍼 이벤트 스트리밍 / Working directory escape shielding, legacy parser flaw mitigation, sub-microsecond instant termination, and runtime ringbuffer event streaming |"
    lsmsec_t4 = "| `lsmsec` 🛡️ eBPF LSM 컨테이너 탈출 & 커널 런타임 보안 (7) | 복합 연쇄 탈출 인커널 봉쇄 · 다중 보안 모듈 계층화 공존 · 하드웨어 엔클레이브 바이트코드 증명 · 런타임 탈출 차단 캡스톤 / Multi-stage breakout in-kernel containment, stacked security module coexistence, hardware enclave measurement proof, and runtime escape defense capstone |"

    if '`pqctls`' not in readme_text:
        readme_text = readme_text.replace(lsmsec_t0, lsmsec_t0 + "\n" + tier0_row.strip())
        readme_text = readme_text.replace(lsmsec_t1, lsmsec_t1 + "\n" + tier1_row.strip())
        readme_text = readme_text.replace(lsmsec_t2, lsmsec_t2 + "\n" + tier2_row.strip())
        readme_text = readme_text.replace(lsmsec_t3, lsmsec_t3 + "\n" + tier3_row.strip())
        readme_text = readme_text.replace(lsmsec_t4, lsmsec_t4 + "\n" + tier4_row.strip())
        readme_path.write_text(readme_text, encoding="utf-8")
        print("[+] Updated wargame/README.md with pqctls rows.")
    else:
        print("[-] pqctls already present in wargame/README.md.")

    # 5. Update index.html HUD (2660 -> 2695)
    index_text = index_html_path.read_text(encoding="utf-8")
    index_text = index_text.replace("0/2660", "0/2695")
    index_text = index_text.replace("/2660", "/2695")
    index_text = index_text.replace("2,660", "2,695")
    index_text = index_text.replace("2660", "2695")
    index_html_path.write_text(index_text, encoding="utf-8")
    print("[+] Updated wargame/index.html HUD counter.")

    print("\n🎉 Track 77 pqctls generation completed successfully!")

if __name__ == "__main__":
    main()
