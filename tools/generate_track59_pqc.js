#!/usr/bin/env node
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

function computeHash(id) {
  const ident = id.replace(/^t\d_/, '') + "_v1";
  const flag = "FLAG{" + crypto.createHash('sha256').update(ident).digest('hex').substring(0, 20) + "}";
  return crypto.createHash('sha256').update(flag).digest('hex');
}

const challengesDef = [
  // Tier 0 (2)
  {
    id: "t0_pqc_quantum_computing_shor_algorithm_threat",
    tier: 0, cat: "pqc", track: "pqc", points: 25, ci: false, fmt: "FLAG{...}",
    title: { ko: "양자 컴퓨팅과 쇼어 알고리즘의 공개키 암호 붕괴 위협", en: "Quantum Computing & Shor's Algorithm Threat to Public Key Cryptography" },
    prompt: {
      ko: "대규모 양자 컴퓨터 상에서 소인수분해와 이산로그 문제를 다항 시간에 해결하는 쇼어 알고리즘의 암호학적 파괴력을 분석합니다.\n지정된 식별자 `pqc_quantum_computing_shor_algorithm_threat_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"pqc_quantum_computing_shor_algorithm_threat_v1\") 앞 20자리}`",
      en: "Analyze the cryptographic impact of Shor's algorithm solving integer factorization and discrete logarithms in polynomial time on quantum machines.\nCompute the first 20 hex characters of SHA256(\"pqc_quantum_computing_shor_algorithm_threat_v1\").\n\nFormat: `FLAG{SHA256(\"pqc_quantum_computing_shor_algorithm_threat_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["쇼어 알고리즘은 기존 RSA와 타원곡선 암호(ECC)를 전면 무력화합니다.", "식별자 `pqc_quantum_computing_shor_algorithm_threat_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Shor's algorithm breaks classical RSA and Elliptic Curve Cryptography in polynomial time.", "Extract first 20 hex chars of SHA256(\"pqc_quantum_computing_shor_algorithm_threat_v1\")."]
    }
  },
  {
    id: "t0_pqc_harvest_now_decrypt_later_hndl_threat",
    tier: 0, cat: "pqc", track: "pqc", points: 25, ci: false, fmt: "FLAG{...}",
    title: { ko: "지금 수집하고 나중에 해독하는 HNDL 전략 분석", en: "Harvest Now, Decrypt Later (HNDL) Threat Analysis" },
    prompt: {
      ko: "위협 행위자가 현재 유통되는 암호화 트래픽을 선제 도청하여 저장한 뒤 훗날 양자 컴퓨터로 소급 해독하는 HNDL 공격 모델을 분석합니다.\n지정된 식별자 `pqc_harvest_now_decrypt_later_hndl_threat_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"pqc_harvest_now_decrypt_later_hndl_threat_v1\") 앞 20자리}`",
      en: "Examine the Harvest-Now-Decrypt-Later (HNDL) threat model where adversaries intercept encrypted traffic today to decrypt retroactively with future quantum computers.\nCompute the first 20 hex characters of SHA256(\"pqc_harvest_now_decrypt_later_hndl_threat_v1\").\n\nFormat: `FLAG{SHA256(\"pqc_harvest_now_decrypt_later_hndl_threat_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["HNDL은 장기 기밀성이 요구되는 군사·금융 데이터에 즉각적인 양자 내성 마이그레이션을 요구합니다.", "식별자 `pqc_harvest_now_decrypt_later_hndl_threat_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["HNDL mandates immediate quantum-safe migration for long-retention financial and national security assets.", "Extract first 20 hex chars of SHA256(\"pqc_harvest_now_decrypt_later_hndl_threat_v1\")."]
    }
  },

  // Tier 1 (6)
  {
    id: "t1_pqc_lattice_cryptography_and_lwe_foundations",
    tier: 1, cat: "lattice", track: "pqc", points: 50, ci: false, fmt: "FLAG{...}",
    title: { ko: "격자 기반 암호학과 LWE 문제의 수학적 난해성", en: "Lattice-Based Cryptography & Hardness of Learning With Errors (LWE)" },
    prompt: {
      ko: "고차원 격자에서 최단 벡터 문제(SVP)에 기반하여 오차 노이즈 벡터를 선형 방정식에 결합한 LWE 기본 수학 구조를 분석합니다.\n지정된 식별자 `pqc_lattice_cryptography_and_lwe_foundations_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"pqc_lattice_cryptography_and_lwe_foundations_v1\") 앞 20자리}`",
      en: "Analyze the mathematical hardness of the Learning With Errors problem founded on high-dimensional lattice Shortest Vector Problems.\nCompute the first 20 hex characters of SHA256(\"pqc_lattice_cryptography_and_lwe_foundations_v1\").\n\nFormat: `FLAG{SHA256(\"pqc_lattice_cryptography_and_lwe_foundations_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["LWE는 비밀 벡터와 랜덤 행렬 곱에 작은 에러 벡터를 더해 양자 컴퓨터로도 복원이 극히 어렵습니다.", "식별자 `pqc_lattice_cryptography_and_lwe_foundations_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["LWE perturbs linear equations with small discrete noise, preventing polynomial quantum inversion.", "Extract first 20 hex chars of SHA256(\"pqc_lattice_cryptography_and_lwe_foundations_v1\")."]
    }
  },
  {
    id: "t1_pqc_nist_fips_203_ml_kem_standard_overview",
    tier: 1, cat: "pqc", track: "pqc", points: 50, ci: false, fmt: "FLAG{...}",
    title: { ko: "NIST FIPS 203 ML-KEM 키 캡슐화 표준 개요", en: "NIST FIPS 203 ML-KEM Key Encapsulation Standard Overview" },
    prompt: {
      ko: "Module-LWE 기반의 양자 안전 키 캡슐화 메커니즘인 NIST 공식 표준 FIPS 203(구 CRYSTALS-Kyber)의 아키텍처를 분석합니다.\n지정된 식별자 `pqc_nist_fips_203_ml_kem_standard_overview_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"pqc_nist_fips_203_ml_kem_standard_overview_v1\") 앞 20자리}`",
      en: "Review the NIST FIPS 203 standard (formerly CRYSTALS-Kyber) for quantum-safe Key Encapsulation Mechanisms built on Module-LWE.\nCompute the first 20 hex characters of SHA256(\"pqc_nist_fips_203_ml_kem_standard_overview_v1\").\n\nFormat: `FLAG{SHA256(\"pqc_nist_fips_203_ml_kem_standard_overview_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["ML-KEM은 키 생성, 캡슐화, 역캡슐화 3단계로 대칭 세션 키를 안전하게 공유합니다.", "식별자 `pqc_nist_fips_203_ml_kem_standard_overview_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["FIPS 203 formalizes KeyGen, Encaps, and Decaps phases for establishing shared session keys.", "Extract first 20 hex chars of SHA256(\"pqc_nist_fips_203_ml_kem_standard_overview_v1\")."]
    }
  },
  {
    id: "t1_pqc_nist_fips_204_ml_dsa_signature_scheme",
    tier: 1, cat: "pqc", track: "pqc", points: 50, ci: false, fmt: "FLAG{...}",
    title: { ko: "NIST FIPS 204 ML-DSA 격자 전자서명 체계", en: "NIST FIPS 204 ML-DSA Lattice Digital Signature Scheme" },
    prompt: {
      ko: "Module-LWE와 거부 샘플링을 결합한 Fiat-Shamir 기반의 공식 디지털 서명 표준 FIPS 204(구 CRYSTALS-Dilithium)를 분석합니다.\n지정된 식별자 `pqc_nist_fips_204_ml_dsa_signature_scheme_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"pqc_nist_fips_204_ml_dsa_signature_scheme_v1\") 앞 20자리}`",
      en: "Examine NIST FIPS 204 (formerly CRYSTALS-Dilithium) digital signatures based on Module-LWE and Fiat-Shamir with Aborts.\nCompute the first 20 hex characters of SHA256(\"pqc_nist_fips_204_ml_dsa_signature_scheme_v1\").\n\nFormat: `FLAG{SHA256(\"pqc_nist_fips_204_ml_dsa_signature_scheme_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["ML-DSA는 서명 시 비밀키 노이즈가 누설되지 않도록 Rejection Sampling 기법을 채택합니다.", "식별자 `pqc_nist_fips_204_ml_dsa_signature_scheme_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["ML-DSA employs rejection sampling to prevent secret key distribution leakage in signatures.", "Extract first 20 hex chars of SHA256(\"pqc_nist_fips_204_ml_dsa_signature_scheme_v1\")."]
    }
  },
  {
    id: "t1_pqc_nist_fips_205_slh_dsa_stateless_hash",
    tier: 1, cat: "pqc", track: "pqc", points: 50, ci: false, fmt: "FLAG{...}",
    title: { ko: "NIST FIPS 205 SLH-DSA 무상태 해시 기반 전자서명", en: "NIST FIPS 205 SLH-DSA Stateless Hash-Based Digital Signature" },
    prompt: {
      ko: "격자 수학 대신 순수 암호학적 해시 함수의 충돌 저항성에만 의존하는 상태 비보존 디지털 서명 표준 FIPS 205(SPHINCS+)를 분석합니다.\n지정된 식별자 `pqc_nist_fips_205_slh_dsa_stateless_hash_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"pqc_nist_fips_205_slh_dsa_stateless_hash_v1\") 앞 20자리}`",
      en: "Investigate NIST FIPS 205 (SPHINCS+) stateless hash-based signatures providing hedge security independent of lattice assumptions.\nCompute the first 20 hex characters of SHA256(\"pqc_nist_fips_205_slh_dsa_stateless_hash_v1\").\n\nFormat: `FLAG{SHA256(\"pqc_nist_fips_205_slh_dsa_stateless_hash_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["SLH-DSA는 XMSS/LMS와 달리 서명 상태(State) 카운터를 관리할 필요가 없어 복제 결함이 없습니다.", "식별자 `pqc_nist_fips_205_slh_dsa_stateless_hash_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["SLH-DSA eliminates state management vulnerabilities inherent in stateful hash signatures like XMSS.", "Extract first 20 hex chars of SHA256(\"pqc_nist_fips_205_slh_dsa_stateless_hash_v1\")."]
    }
  },
  {
    id: "t1_pqc_hybrid_key_exchange_dual_kdf_concept",
    tier: 1, cat: "hybrid", track: "pqc", points: 50, ci: false, fmt: "FLAG{...}",
    title: { ko: "하이브리드 키 교환과 Dual-KDF 결합 원리", en: "Hybrid Key Exchange & Dual-KDF Combination Principles" },
    prompt: {
      ko: "고전 타원곡선 Diffie-Hellman(X25519)과 양자 내성 KEM(ML-KEM-768)의 공유 비밀을 HKDF로 결합하여 양방향 보안을 보장하는 구조를 분석합니다.\n지정된 식별자 `pqc_hybrid_key_exchange_dual_kdf_concept_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"pqc_hybrid_key_exchange_dual_kdf_concept_v1\") 앞 20자리}`",
      en: "Analyze hybrid key exchange combining classical ECDH (X25519) and ML-KEM-768 shared secrets via dual HKDF extract-and-expand.\nCompute the first 20 hex characters of SHA256(\"pqc_hybrid_key_exchange_dual_kdf_concept_v1\").\n\nFormat: `FLAG{SHA256(\"pqc_hybrid_key_exchange_dual_kdf_concept_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["하이브리드 방식은 두 알고리즘 중 하나만 뚫리지 않아도 전체 세션 키의 기밀성이 유지됩니다.", "식별자 `pqc_hybrid_key_exchange_dual_kdf_concept_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Hybrid key exchange preserves forward secrecy as long as either classical or PQC algorithm holds.", "Extract first 20 hex chars of SHA256(\"pqc_hybrid_key_exchange_dual_kdf_concept_v1\")."]
    }
  },
  {
    id: "t1_pqc_grover_algorithm_symmetric_key_security",
    tier: 1, cat: "pqc", track: "pqc", points: 50, ci: false, fmt: "FLAG{...}",
    title: { ko: "그로버 알고리즘과 대칭키 암호 유효 보안 비트", en: "Grover's Algorithm & Effective Symmetric Key Bit Strength" },
    prompt: {
      ko: "비정렬 데이터베이스 검색에서 양자 이차 가속(Quadratic Speedup)을 제공하여 AES 키 길이를 실질적으로 절반으로 축소시키는 그로버 알고리즘의 영향을 분석합니다.\n지정된 식별자 `pqc_grover_algorithm_symmetric_key_security_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"pqc_grover_algorithm_symmetric_key_security_v1\") 앞 20자리}`",
      en: "Assess the quadratic speedup of Grover's search algorithm halving the effective bit security of symmetric primitives like AES.\nCompute the first 20 hex characters of SHA256(\"pqc_grover_algorithm_symmetric_key_security_v1\").\n\nFormat: `FLAG{SHA256(\"pqc_grover_algorithm_symmetric_key_security_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["AES-128은 유효 보안 강도가 64비트로 감소하므로 양자 안전을 위해 AES-256 채택이 필수적입니다.", "식별자 `pqc_grover_algorithm_symmetric_key_security_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Grover reduces AES-128 to 64 bits of security, making AES-256 mandatory for post-quantum defense.", "Extract first 20 hex chars of SHA256(\"pqc_grover_algorithm_symmetric_key_security_v1\")."]
    }
  },

  // Tier 2 (8)
  {
    id: "t2_pqc_module_lwe_polynomial_ring_reduction",
    tier: 2, cat: "lattice", track: "pqc", points: 100, ci: false, fmt: "FLAG{...}",
    title: { ko: "Module-LWE 다항식 환 구조와 모듈러스 q 연산", en: "Module-LWE Polynomial Ring Reduction & Modulus q Operations" },
    prompt: {
      ko: "다항식 환 R_q = Z_q[X]/(X^n + 1) 위에서 모듈 행렬과 비밀 다항식 벡터 간의 다항식 곱셈 및 계수 환산을 분석합니다.\n지정된 식별자 `pqc_module_lwe_polynomial_ring_reduction_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"pqc_module_lwe_polynomial_ring_reduction_v1\") 앞 20자리}`",
      en: "Study polynomial ring R_q arithmetic over Z_q[X]/(X^n + 1) driving matrix vector operations in Module-LWE.\nCompute the first 20 hex characters of SHA256(\"pqc_module_lwe_polynomial_ring_reduction_v1\").\n\nFormat: `FLAG{SHA256(\"pqc_module_lwe_polynomial_ring_reduction_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["ML-KEM은 n=256, q=3329 파라미터를 사용하여 효율적인 환 연산을 보장합니다.", "식별자 `pqc_module_lwe_polynomial_ring_reduction_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["ML-KEM standardizes n=256 and prime modulus q=3329 for efficient NTT ring transformations.", "Extract first 20 hex chars of SHA256(\"pqc_module_lwe_polynomial_ring_reduction_v1\")."]
    }
  },
  {
    id: "t2_pqc_ml_kem_768_parameter_set_and_key_size",
    tier: 2, cat: "lattice", track: "pqc", points: 100, ci: false, fmt: "FLAG{...}",
    title: { ko: "ML-KEM-768 파라미터 세트와 공개키/암호문 바이트 크기", en: "ML-KEM-768 Parameter Set & Public Key / Ciphertext Sizing" },
    prompt: {
      ko: "NIST 보안 레벨 3을 충족하며 모듈 차원 k=3을 적용하여 1,184바이트 공개키와 1,088바이트 암호문을 구성하는 ML-KEM-768 규격을 분석합니다.\n지정된 식별자 `pqc_ml_kem_768_parameter_set_and_key_size_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"pqc_ml_kem_768_parameter_set_and_key_size_v1\") 앞 20자리}`",
      en: "Audit ML-KEM-768 NIST Security Level 3 parameters with module rank k=3 yielding a 1,184-byte public key and 1,088-byte ciphertext.\nCompute the first 20 hex characters of SHA256(\"pqc_ml_kem_768_parameter_set_and_key_size_v1\").\n\nFormat: `FLAG{SHA256(\"pqc_ml_kem_768_parameter_set_and_key_size_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["k=3일 때 다항식 벡터 크기와 32바이트 시드가 결합되어 1184바이트 공개키가 완성됩니다.", "식별자 `pqc_ml_kem_768_parameter_set_and_key_size_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["In ML-KEM-768, 3 ring elements of compressed coefficients plus a 32-byte seed form the 1,184-byte key.", "Extract first 20 hex chars of SHA256(\"pqc_ml_kem_768_parameter_set_and_key_size_v1\")."]
    }
  },
  {
    id: "t2_pqc_tls_13_x25519_ml_kem_768_handshake",
    tier: 2, cat: "hybrid", track: "pqc", points: 100, ci: false, fmt: "FLAG{...}",
    title: { ko: "TLS 1.3 X25519MLKEM768 하이브리드 핸드셰이크 프로토콜", en: "TLS 1.3 X25519MLKEM768 Hybrid Handshake Protocol" },
    prompt: {
      ko: "IETF 명세에 따라 ClientHello의 key_share 확장에 X25519와 ML-KEM-768 공개키를 동시에 패킹하여 전송하는 TLS 1.3 하이브리드 핸드셰이크를 분석합니다.\n지정된 식별자 `pqc_tls_13_x25519_ml_kem_768_handshake_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"pqc_tls_13_x25519_ml_kem_768_handshake_v1\") 앞 20자리}`",
      en: "Examine the TLS 1.3 X25519MLKEM768 hybrid extension encoding both ECDH and lattice keys within ClientHello key_share.\nCompute the first 20 hex characters of SHA256(\"pqc_tls_13_x25519_ml_kem_768_handshake_v1\").\n\nFormat: `FLAG{SHA256(\"pqc_tls_13_x25519_ml_kem_768_handshake_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["클라이언트는 32바이트 X25519 키와 1184바이트 ML-KEM 키를 연접하여 1216바이트 key_share를 구성합니다.", "식별자 `pqc_tls_13_x25519_ml_kem_768_handshake_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Concatenating the 32-byte X25519 share with 1,184 bytes of ML-KEM produces a 1,216-byte key share payload.", "Extract first 20 hex chars of SHA256(\"pqc_tls_13_x25519_ml_kem_768_handshake_v1\")."]
    }
  },
  {
    id: "t2_pqc_fiat_shamir_with_aborts_rejection_sampling",
    tier: 2, cat: "lattice", track: "pqc", points: 100, ci: false, fmt: "FLAG{...}",
    title: { ko: "Fiat-Shamir with Aborts와 거부 샘플링 메커니즘", en: "Fiat-Shamir with Aborts & Rejection Sampling Mechanics" },
    prompt: {
      ko: "전자서명 결과 벡터 z = y + c*s의 분포가 비밀키 s의 노이즈 정보에 의존하지 않도록 특정 노름 경계를 초과할 경우 서명을 폐기하고 재시도하는 과정을 분석합니다.\n지정된 식별자 `pqc_fiat_shamir_with_aborts_rejection_sampling_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"pqc_fiat_shamir_with_aborts_rejection_sampling_v1\") 앞 20자리}`",
      en: "Analyze Fiat-Shamir with Aborts where signature candidate z = y + c*s is rejected if its norm exceeds boundary bounds to prevent secret key leakage.\nCompute the first 20 hex characters of SHA256(\"pqc_fiat_shamir_with_aborts_rejection_sampling_v1\").\n\nFormat: `FLAG{SHA256(\"pqc_fiat_shamir_with_aborts_rejection_sampling_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["거부 샘플링은 서명 출력물이 비밀키와 통계적으로 독립적인 균등/가우스 분포를 갖도록 강제합니다.", "식별자 `pqc_fiat_shamir_with_aborts_rejection_sampling_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Rejection sampling decouples the statistical distribution of signatures from underlying private secrets.", "Extract first 20 hex chars of SHA256(\"pqc_fiat_shamir_with_aborts_rejection_sampling_v1\")."]
    }
  },
  {
    id: "t2_pqc_downgrade_attack_mitm_extension_stripping",
    tier: 2, cat: "hybrid", track: "pqc", points: 100, ci: false, fmt: "FLAG{...}",
    title: { ko: "중간자 공격자의 PQC 확장 필드 제거 다운그레이드 공격", en: "Man-in-the-Middle PQC Extension Stripping Downgrade Attack" },
    prompt: {
      ko: "네트워크 인라인 중간자가 ClientHello에서 PQC 지원 그룹 확장을 제거하여 고전 취약 암호로 강제 폴백시키는 다운그레이드 벡터를 분석합니다.\n지정된 식별자 `pqc_downgrade_attack_mitm_extension_stripping_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"pqc_downgrade_attack_mitm_extension_stripping_v1\") 앞 20자리}`",
      en: "Evaluate the MitM downgrade vector where an adversary strips post-quantum extension advertisements from TLS ClientHello packets.\nCompute the first 20 hex characters of SHA256(\"pqc_downgrade_attack_mitm_extension_stripping_v1\").\n\nFormat: `FLAG{SHA256(\"pqc_downgrade_attack_mitm_extension_stripping_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["서버에서 Strict PQC 정책을 활성화하여 비-PQC 연결 시도를 강제 거부해야 합니다.", "식별자 `pqc_downgrade_attack_mitm_extension_stripping_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Enforcing strict server-side PQC policies rejects insecure legacy fallbacks and halts downgrade exploits.", "Extract first 20 hex chars of SHA256(\"pqc_downgrade_attack_mitm_extension_stripping_v1\")."]
    }
  },
  {
    id: "t2_pqc_number_theoretic_transform_ntt_acceleration",
    tier: 2, cat: "lattice", track: "pqc", points: 100, ci: false, fmt: "FLAG{...}",
    title: { ko: "수론 변환(NTT)을 활용한 다항식 곱셈 고속 가속", en: "Number Theoretic Transform (NTT) for High-Speed Polynomial Multiplication" },
    prompt: {
      ko: "O(n^2) 복잡도의 학교식 다항식 곱셈을 O(n log n)으로 가속하는 수론 변환(NTT)과 음의 순환 합성곱(Negacyclic Convolution)을 분석합니다.\n지정된 식별자 `pqc_number_theoretic_transform_ntt_acceleration_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"pqc_number_theoretic_transform_ntt_acceleration_v1\") 앞 20자리}`",
      en: "Study Number Theoretic Transforms accelerating polynomial multiplications in Z_q[X]/(X^n + 1) from O(n^2) to O(n log n).\nCompute the first 20 hex characters of SHA256(\"pqc_number_theoretic_transform_ntt_acceleration_v1\").\n\nFormat: `FLAG{SHA256(\"pqc_number_theoretic_transform_ntt_acceleration_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["NTT는 FFT(고속 푸리에 변환)를 소수 체 Z_q 상의 원시 거듭제곱근으로 구현한 것입니다.", "식별자 `pqc_number_theoretic_transform_ntt_acceleration_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["NTT maps discrete polynomials to frequency domain representations over finite fields for elementwise multiplication.", "Extract first 20 hex chars of SHA256(\"pqc_number_theoretic_transform_ntt_acceleration_v1\")."]
    }
  },
  {
    id: "t2_pqc_fujisaki_okamoto_transform_cca_security",
    tier: 2, cat: "defense", track: "pqc", points: 100, ci: false, fmt: "FLAG{...}",
    title: { ko: "Fujisaki-Okamoto 변환과 IND-CCA2 적응형 선택 암호문 보안", en: "Fujisaki-Okamoto Transform & IND-CCA2 Chosen-Ciphertext Security" },
    prompt: {
      ko: "수동적 도청(CPA)만 방어하는 기본 격자 PKE를 적응형 선택 암호문 공격(CCA2)에 안전한 KEM으로 변환하는 FO 변환의 재암호화 검증 원리를 분석합니다.\n지정된 식별자 `pqc_fujisaki_okamoto_transform_cca_security_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"pqc_fujisaki_okamoto_transform_cca_security_v1\") 앞 20자리}`",
      en: "Analyze the Fujisaki-Okamoto (FO) transform converting CPA-secure lattice PKEs into IND-CCA2 secure KEMs via deterministic re-encryption checks.\nCompute the first 20 hex characters of SHA256(\"pqc_fujisaki_okamoto_transform_cca_security_v1\").\n\nFormat: `FLAG{SHA256(\"pqc_fujisaki_okamoto_transform_cca_security_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["역캡슐화 시 복호화된 평문 메시지로 암호문을 다시 만들어 원본 암호문과 엄격히 일치하는지 검증합니다.", "식별자 `pqc_fujisaki_okamoto_transform_cca_security_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["FO verification re-encrypts the decrypted message to ensure the ciphertext was not maliciously manipulated.", "Extract first 20 hex chars of SHA256(\"pqc_fujisaki_okamoto_transform_cca_security_v1\")."]
    }
  },
  {
    id: "t2_pqc_quantum_resistant_x509_certificate_chains",
    tier: 2, cat: "defense", track: "pqc", points: 100, ci: false, fmt: "FLAG{...}",
    title: { ko: "양자 내성 X.509 공개키 인증서 체인 구조", en: "Quantum-Resistant X.509 Public Key Certificate Architecture" },
    prompt: {
      ko: "FIPS 204 ML-DSA 공개키와 서명을 X.509 v3 인증서 ASN.1 구조에 인코딩하고 루트 CA부터 서브 CA, 리프 인증서까지 검증하는 체인을 분석합니다.\n지정된 식별자 `pqc_quantum_resistant_x509_certificate_chains_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"pqc_quantum_resistant_x509_certificate_chains_v1\") 앞 20자리}`",
      en: "Examine X.509 v3 certificate infrastructure incorporating ML-DSA OIDs, large lattice public keys, and signature validation across the PKI hierarchy.\nCompute the first 20 hex characters of SHA256(\"pqc_quantum_resistant_x509_certificate_chains_v1\").\n\nFormat: `FLAG{SHA256(\"pqc_quantum_resistant_x509_certificate_chains_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["ML-DSA 서명은 수 KB에 달하므로 TLS 핸드셰이크 패킷 분할(Fragmentation) 및 MTU 고려가 필요합니다.", "식별자 `pqc_quantum_resistant_x509_certificate_chains_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Multi-kilobyte ML-DSA signatures necessitate TCP segmentation and MTU consideration during TLS handshakes.", "Extract first 20 hex chars of SHA256(\"pqc_quantum_resistant_x509_certificate_chains_v1\")."]
    }
  },

  // Tier 3 (9)
  {
    id: "t3_pqc_side_channel_timing_attacks_on_ntt_compression",
    tier: 3, cat: "defense", track: "pqc", points: 150, ci: false, fmt: "FLAG{...}",
    title: { ko: "다항식 계수 압축 시 발생하는 타이밍 부채널 이상 징후 분석", en: "Timing Side-Channel Analysis in Polynomial Coefficient Compression" },
    prompt: {
      ko: "ML-KEM 역캡슐화의 다항식 계수 압축/복원 연산에서 조건부 분기문에 따른 실행 시간 차이를 도청하여 비밀키를 복원하는 부채널 공격을 분석합니다.\n지정된 식별자 `pqc_side_channel_timing_attacks_on_ntt_compression_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"pqc_side_channel_timing_attacks_on_ntt_compression_v1\") 앞 20자리}`",
      en: "Investigate timing leakage arising from conditional branching in coefficient compression during ML-KEM decapsulation.\nCompute the first 20 hex characters of SHA256(\"pqc_side_channel_timing_attacks_on_ntt_compression_v1\").\n\nFormat: `FLAG{SHA256(\"pqc_side_channel_timing_attacks_on_ntt_compression_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["모든 다항식 연산은 조건문(if) 없이 비트마스킹을 활용한 상수 시간(Constant-time)으로 구현되어야 합니다.", "식별자 `pqc_side_channel_timing_attacks_on_ntt_compression_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["All lattice arithmetic and compression routines must strictly execute in constant time without data-dependent branches.", "Extract first 20 hex chars of SHA256(\"pqc_side_channel_timing_attacks_on_ntt_compression_v1\")."]
    }
  },
  {
    id: "t3_pqc_fault_injection_glitch_in_rejection_sampling",
    tier: 3, cat: "defense", track: "pqc", points: 150, ci: false, fmt: "FLAG{...}",
    title: { ko: "거부 샘플링 루틴 대상 클록 글리치 결함 주입 공격", en: "Clock Glitch Fault Injection Attacks on Rejection Sampling Loops" },
    prompt: {
      ko: "ML-DSA 서명 시 하드웨어 클록 글리치를 주입하여 거부 검사를 강제 통과시킴으로써 비정상 노름 서명 출력을 유도하고 비밀키를 카빙하는 기법을 분석합니다.\n지정된 식별자 `pqc_fault_injection_glitch_in_rejection_sampling_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"pqc_fault_injection_glitch_in_rejection_sampling_v1\") 앞 20자리}`",
      en: "Assess clock glitching fault injection attacks bypassing ML-DSA rejection sampling norm boundaries to force secret-dependent signature output.\nCompute the first 20 hex characters of SHA256(\"pqc_fault_injection_glitch_in_rejection_sampling_v1\").\n\nFormat: `FLAG{SHA256(\"pqc_fault_injection_glitch_in_rejection_sampling_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["서명 생성 직후 자체 노름 검증(Self-verification)을 수행하여 비정상 서명의 외부 송출을 차단합니다.", "식별자 `pqc_fault_injection_glitch_in_rejection_sampling_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Enforcing post-generation self-verification prevents faulted, secret-biased signatures from exiting the cryptomodule.", "Extract first 20 hex chars of SHA256(\"pqc_fault_injection_glitch_in_rejection_sampling_v1\")."]
    }
  },
  {
    id: "t3_pqc_crypto_agility_and_algorithm_swapping",
    tier: 3, cat: "defense", track: "pqc", points: 150, ci: false, fmt: "FLAG{...}",
    title: { ko: "암호 민첩성(Crypto Agility) 설계와 알고리즘 동적 전환", en: "Crypto Agility Architecture & Dynamic Algorithm Swapping" },
    prompt: {
      ko: "새로운 수학적 취약점이 발견될 경우 코드베이스 전면 재작성 없이 설정 변경만으로 다른 PQC 원천 알고리즘으로 즉시 교체 가능한 암호 민첩성 아키텍처를 분석합니다.\n지정된 식별자 `pqc_crypto_agility_and_algorithm_swapping_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"pqc_crypto_agility_and_algorithm_swapping_v1\") 앞 20자리}`",
      en: "Design crypto agility frameworks allowing seamless swapping between ML-KEM, BIKE, and HQC without breaking application interfaces.\nCompute the first 20 hex characters of SHA256(\"pqc_crypto_agility_and_algorithm_swapping_v1\").\n\nFormat: `FLAG{SHA256(\"pqc_crypto_agility_and_algorithm_swapping_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["하드코딩된 알고리즘을 지양하고 추상화된 암호화 프로바이더 인터페이스(JCA, OpenSSL EVP)를 사용합니다.", "식별자 `pqc_crypto_agility_and_algorithm_swapping_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Decoupling cryptographic algorithms behind abstract provider interfaces enables rapid post-quantum pivoting.", "Extract first 20 hex chars of SHA256(\"pqc_crypto_agility_and_algorithm_swapping_v1\")."]
    }
  },
  {
    id: "t3_pqc_short_vector_problem_svp_lattice_reduction",
    tier: 3, cat: "lattice", track: "pqc", points: 150, ci: false, fmt: "FLAG{...}",
    title: { ko: "최단 벡터 문제(SVP)와 BKZ 격자 기저 축소 공격 복잡도", en: "Shortest Vector Problem (SVP) & BKZ Lattice Basis Reduction Complexity" },
    prompt: {
      ko: "LLL 및 BKZ(Block Korkine-Zolotarev) 격자 축소 알고리즘이 고차원 격자에서 최단 벡터를 탐색하는 데 소요되는 지수적 계산 복잡도를 분석합니다.\n지정된 식별자 `pqc_short_vector_problem_svp_lattice_reduction_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"pqc_short_vector_problem_svp_lattice_reduction_v1\") 앞 20자리}`",
      en: "Examine the exponential complexity of BKZ lattice basis reduction algorithms attempting to solve SVP against high-dimension LWE lattices.\nCompute the first 20 hex characters of SHA256(\"pqc_short_vector_problem_svp_lattice_reduction_v1\").\n\nFormat: `FLAG{SHA256(\"pqc_short_vector_problem_svp_lattice_reduction_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["격자 차원이 증가함에 따라 최단 벡터를 찾는 고전 및 양자 체질(Sieving) 비용이 지수함수적으로 폭증합니다.", "식별자 `pqc_short_vector_problem_svp_lattice_reduction_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["The core-SVP hardness metric guarantees exponential security against both classical and quantum sieving attacks.", "Extract first 20 hex chars of SHA256(\"pqc_short_vector_problem_svp_lattice_reduction_v1\")."]
    }
  },
  {
    id: "t3_pqc_fips_203_encapsulation_matrix_multiplication",
    tier: 3, cat: "lattice", track: "pqc", points: 150, ci: false, fmt: "FLAG{...}",
    title: { ko: "FIPS 203 키 캡슐화의 행렬-벡터 연산 및 노이즈 주입", en: "FIPS 203 Encapsulation Matrix-Vector Operations & Noise Injection" },
    prompt: {
      ko: "송신자가 수신자의 공개키 벡터 t와 무작위 다항식 벡터 r을 내적하고 이산 가우스 오차를 주입하여 암호문 (u, v)를 생성하는 과정을 분석합니다.\n지정된 식별자 `pqc_fips_203_encapsulation_matrix_multiplication_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"pqc_fips_203_encapsulation_matrix_multiplication_v1\") 앞 20자리}`",
      en: "Analyze the mathematical inner product and noise sampling generating ciphertext pairs (u, v) during ML-KEM encapsulation.\nCompute the first 20 hex characters of SHA256(\"pqc_fips_203_encapsulation_matrix_multiplication_v1\").\n\nFormat: `FLAG{SHA256(\"pqc_fips_203_encapsulation_matrix_multiplication_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["암호문 u는 A^T * r + e1, v는 t^T * r + e2 + round(q/2)*m으로 계산됩니다.", "식별자 `pqc_fips_203_encapsulation_matrix_multiplication_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["The ciphertext vector u and scalar v encode the message m disguised by deterministic lattice noise polynomials.", "Extract first 20 hex chars of SHA256(\"pqc_fips_203_encapsulation_matrix_multiplication_v1\")."]
    }
  },
  {
    id: "t3_pqc_hybrid_tls_client_hello_key_share_encoding",
    tier: 3, cat: "hybrid", track: "pqc", points: 150, ci: false, fmt: "FLAG{...}",
    title: { ko: "하이브리드 TLS 1.3 ClientHello 키 공유 ASN.1/바이너리 인코딩", en: "Hybrid TLS 1.3 ClientHello Key Share Binary Encoding Specifications" },
    prompt: {
      ko: "RFC 9370 및 IETF 표준 초안에 규정된 NamedGroup 0x11ec (X25519MLKEM768) 바이너리 프레이밍과 확장 패킷 구조를 분석합니다.\n지정된 식별자 `pqc_hybrid_tls_client_hello_key_share_encoding_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"pqc_hybrid_tls_client_hello_key_share_encoding_v1\") 앞 20자리}`",
      en: "Inspect the binary structure of NamedGroup 0x11ec (X25519MLKEM768) key shares within the TLS 1.3 ClientHello extension parser.\nCompute the first 20 hex characters of SHA256(\"pqc_hybrid_tls_client_hello_key_share_encoding_v1\").\n\nFormat: `FLAG{SHA256(\"pqc_hybrid_tls_client_hello_key_share_encoding_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["하이브리드 그룹 코드는 2바이트 식별자, 2바이트 길이, 그리고 연접된 키 페이로드로 구성됩니다.", "식별자 `pqc_hybrid_tls_client_hello_key_share_encoding_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["The TLS key share header encodes group ID 0x11ec followed by uint16 length and the composite key payload.", "Extract first 20 hex chars of SHA256(\"pqc_hybrid_tls_client_hello_key_share_encoding_v1\")."]
    }
  },
  {
    id: "t3_pqc_post_quantum_ipsec_and_vpn_migration",
    tier: 3, cat: "hybrid", track: "pqc", points: 150, ci: false, fmt: "FLAG{...}",
    title: { ko: "IPsec IKEv2 및 사이트 간 VPN의 양자 내성 마이그레이션", en: "Post-Quantum IPsec IKEv2 & Site-to-Site VPN Migration" },
    prompt: {
      ko: "RFC 8784(PPK) 및 IKEv2 다중 키 교환(RFC 9370)을 적용하여 엔터프라이즈 사이트 간 터널에 ML-KEM을 통합하는 VPN 아키텍처를 분석합니다.\n지정된 식별자 `pqc_post_quantum_ipsec_and_vpn_migration_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"pqc_post_quantum_ipsec_and_vpn_migration_v1\") 앞 20자리}`",
      en: "Analyze post-quantum IPsec architectures employing IKEv2 intermediate exchanges (RFC 9370) and Post-Quantum Preshared Keys (RFC 8784).\nCompute the first 20 hex characters of SHA256(\"pqc_post_quantum_ipsec_and_vpn_migration_v1\").\n\nFormat: `FLAG{SHA256(\"pqc_post_quantum_ipsec_and_vpn_migration_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["IKEv2 SA_INIT 후 IKE_INTERMEDIATE 메시지를 통해 대용량 PQC 키 교환 데이터를 협상합니다.", "식별자 `pqc_post_quantum_ipsec_and_vpn_migration_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["RFC 9370 introduces IKE_INTERMEDIATE exchanges to accommodate larger post-quantum key payloads without packet drop.", "Extract first 20 hex chars of SHA256(\"pqc_post_quantum_ipsec_and_vpn_migration_v1\")."]
    }
  },
  {
    id: "t3_pqc_stateful_hash_based_signatures_xmss_lms",
    tier: 3, cat: "defense", track: "pqc", points: 150, ci: false, fmt: "FLAG{...}",
    title: { ko: "상태 기반 해시 서명(LMS/XMSS)과 상태 보존 보안 결함", en: "Stateful Hash-Based Signatures (LMS/XMSS) & State Reuse Pitfalls" },
    prompt: {
      ko: "RFC 8554(LMS) 및 RFC 8391(XMSS)의 일회성 서명(OTS) 머클 트리 구조에서 서명 상태(Index)가 재사용될 때 발생하는 개인키 유출 결함을 분석합니다.\n지정된 식별자 `pqc_stateful_hash_based_signatures_xmss_lms_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"pqc_stateful_hash_based_signatures_xmss_lms_v1\") 앞 20자리}`",
      en: "Examine stateful hash-based signatures (LMS/XMSS) and catastrophic private key recovery resulting from OTS one-time state reuse.\nCompute the first 20 hex characters of SHA256(\"pqc_stateful_hash_based_signatures_xmss_lms_v1\").\n\nFormat: `FLAG{SHA256(\"pqc_stateful_hash_based_signatures_xmss_lms_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["상태 기반 서명은 VM 스냅샷 롤백 시 동일한 인덱스가 재서명되어 비밀키가 영구 탈취될 수 있습니다.", "식별자 `pqc_stateful_hash_based_signatures_xmss_lms_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Restoring a VM snapshot can revert OTS counter state, leading to catastrophic key compromise.", "Extract first 20 hex chars of SHA256(\"pqc_stateful_hash_based_signatures_xmss_lms_v1\")."]
    }
  },
  {
    id: "t3_pqc_cnsa_20_quantum_readiness_compliance",
    tier: 3, cat: "defense", track: "pqc", points: 150, ci: false, fmt: "FLAG{...}",
    title: { ko: "미국 국가안보국 CNSA 2.0 양자 대비 규정 준수 일정", en: "NSA Commercial National Security Algorithm Suite 2.0 (CNSA 2.0) Timeline" },
    prompt: {
      ko: "미국 NSA가 2025~2033년까지 국가안보 시스템(NSS)에 대해 RSA/ECC 전면 폐기 및 ML-KEM/ML-DSA 의무화를 선언한 CNSA 2.0 로드맵을 분석합니다.\n지정된 식별자 `pqc_cnsa_20_quantum_readiness_compliance_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"pqc_cnsa_20_quantum_readiness_compliance_v1\") 앞 20자리}`",
      en: "Audit NSA CNSA 2.0 mandates phasing out legacy RSA/ECDH by 2030 and strictly enforcing ML-KEM-1024 and ML-DSA-87 by 2033.\nCompute the first 20 hex characters of SHA256(\"pqc_cnsa_20_quantum_readiness_compliance_v1\").\n\nFormat: `FLAG{SHA256(\"pqc_cnsa_20_quantum_readiness_compliance_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["CNSA 2.0은 펌웨어, 운영체제, 네트워킹 장비별로 단계적 PQC 의무화 데드라인을 지정하고 있습니다.", "식별자 `pqc_cnsa_20_quantum_readiness_compliance_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["CNSA 2.0 defines strict transition deadlines for software updates, web browsers, and enterprise networking hardware.", "Extract first 20 hex chars of SHA256(\"pqc_cnsa_20_quantum_readiness_compliance_v1\")."]
    }
  },

  // Tier 4 (10)
  {
    id: "t4_pqc_quantum_cryptanalysis_and_lattice_sieving",
    tier: 4, cat: "lattice", track: "pqc", points: 250, ci: false, fmt: "FLAG{...}",
    title: { ko: "양자 암호 분석과 고차원 격자 체질(Lattice Sieving) 알고리즘", en: "Quantum Cryptanalysis & High-Dimension Lattice Sieving Algorithms" },
    prompt: {
      ko: "BKZ의 핵심 서브루틴으로 고차원 격자에서 지수 개의 격자 벡터를 조합하여 점진적으로 더 짧은 벡터를 탐색하는 가우스 체질(Sieving)을 분석합니다.\n지정된 식별자 `pqc_quantum_cryptanalysis_and_lattice_sieving_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"pqc_quantum_cryptanalysis_and_lattice_sieving_v1\") 앞 20자리}`",
      en: "Evaluate asymptotic quantum sieving complexities 2^(0.265d) bounded by memory and parallel quantum Grover acceleration against LWE.\nCompute the first 20 hex characters of SHA256(\"pqc_quantum_cryptanalysis_and_lattice_sieving_v1\").\n\nFormat: `FLAG{SHA256(\"pqc_quantum_cryptanalysis_and_lattice_sieving_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["체질 알고리즘은 거대한 메모리(2^0.2075d)를 요구하므로 실질적 물리적 자원 한계가 암호의 방어벽 역할을 합니다.", "식별자 `pqc_quantum_cryptanalysis_and_lattice_sieving_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Exponential spatial memory bounds in lattice sieving establish real-world quantum hardness thresholds.", "Extract first 20 hex chars of SHA256(\"pqc_quantum_cryptanalysis_and_lattice_sieving_v1\")."]
    }
  },
  {
    id: "t4_pqc_decapsulation_oracle_chosen_ciphertext_attack",
    tier: 4, cat: "defense", track: "pqc", points: 250, ci: false, fmt: "FLAG{...}",
    title: { ko: "역캡슐화 오라클 대상 선택 암호문 공격(CCA)과 FO 우회 탐지", en: "Decapsulation Oracle Chosen-Ciphertext Attacks & FO Bypass Detection" },
    prompt: {
      ko: "FO 변환의 암호문 무결성 검증 루틴에 결함이 있을 때 조작된 비정상 암호문을 반복 주입하여 비밀키 비트를 추출하는 CCA 공격을 분석합니다.\n지정된 식별자 `pqc_decapsulation_oracle_chosen_ciphertext_attack_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"pqc_decapsulation_oracle_chosen_ciphertext_attack_v1\") 앞 20자리}`",
      en: "Assess chosen-ciphertext attacks exploiting flawed FO decapsulation checks where malformed ciphertexts leak private lattice polynomial coefficients.\nCompute the first 20 hex characters of SHA256(\"pqc_decapsulation_oracle_chosen_ciphertext_attack_v1\").\n\nFormat: `FLAG{SHA256(\"pqc_decapsulation_oracle_chosen_ciphertext_attack_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["검증 실패 시 무작위 가짜 세션 키(Pseudorandom fallback)를 반환하여 오류 오라클 정보 누설을 차단합니다.", "식별자 `pqc_decapsulation_oracle_chosen_ciphertext_attack_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Implicit rejection returning deterministic pseudorandom secrets prevents error oracle information leakage.", "Extract first 20 hex chars of SHA256(\"pqc_decapsulation_oracle_chosen_ciphertext_attack_v1\")."]
    }
  },
  {
    id: "t4_pqc_constant_time_gaussian_noise_sampling",
    tier: 4, cat: "defense", track: "pqc", points: 250, ci: false, fmt: "FLAG{...}",
    title: { ko: "상수 시간 이산 가우스 노이즈 샘플링 구현과 엔트로피 검증", en: "Constant-Time Discrete Gaussian Noise Sampling Implementation" },
    prompt: {
      ko: "누적 분포 함수(CDF) 룩업 테이블이나 CDT 역변환 시 캐시 타이밍 부채널이 발생하지 않도록 비트 연산으로 완전 일정한 시간 안에 노이즈를 샘플링하는 기법을 분석합니다.\n지정된 식별자 `pqc_constant_time_gaussian_noise_sampling_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"pqc_constant_time_gaussian_noise_sampling_v1\") 앞 20자리}`",
      en: "Analyze constant-time discrete Gaussian noise sampling avoiding cache-timing leaks in Cumulative Distribution Function (CDF) table lookups.\nCompute the first 20 hex characters of SHA256(\"pqc_constant_time_gaussian_noise_sampling_v1\").\n\nFormat: `FLAG{SHA256(\"pqc_constant_time_gaussian_noise_sampling_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["비트 수준의 비트슬라이싱(Bitslicing) 또는 중심 극한 정리를 활용한 상수 시간 샘플러가 사용됩니다.", "식별자 `pqc_constant_time_gaussian_noise_sampling_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Constant-time bitslicing prevents microarchitectural cache hits from leaking discrete noise magnitudes.", "Extract first 20 hex chars of SHA256(\"pqc_constant_time_gaussian_noise_sampling_v1\")."]
    }
  },
  {
    id: "t4_pqc_enterprise_pqc_asset_inventory_and_cbom",
    tier: 4, cat: "defense", track: "pqc", points: 250, ci: false, fmt: "FLAG{...}",
    title: { ko: "암호화 자산 명세서(CBOM) 자동 카빙 및 인벤토리 감사", en: "Cryptographic Bill of Materials (CBOM) Automated Carving & Inventory" },
    prompt: {
      ko: "CycloneDX 1.6 CBOM 표준을 활용하여 엔터프라이즈 소스코드, 바이너리, 네트워크 트래픽에서 고전 암호 알고리즘과 키 길이를 자동 카빙하는 거버넌스 파이프라인을 분석합니다.\n지정된 식별자 `pqc_enterprise_pqc_asset_inventory_and_cbom_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"pqc_enterprise_pqc_asset_inventory_and_cbom_v1\") 앞 20자리}`",
      en: "Deploy Cryptographic Bill of Materials (CBOM) scanning pipelines discovering vulnerable RSA/ECC assets across enterprise microservices.\nCompute the first 20 hex characters of SHA256(\"pqc_enterprise_pqc_asset_inventory_and_cbom_v1\").\n\nFormat: `FLAG{SHA256(\"pqc_enterprise_pqc_asset_inventory_and_cbom_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["CBOM은 SBOM의 확장 규격으로 모든 인증서, 비대칭키, 암호 라이브러리의 알고리즘과 양자 안전 여부를 명시합니다.", "식별자 `pqc_enterprise_pqc_asset_inventory_and_cbom_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["CBOM structures machine-readable inventories tracking algorithmic lifecycles, key lengths, and PQC compliance status.", "Extract first 20 hex chars of SHA256(\"pqc_enterprise_pqc_asset_inventory_and_cbom_v1\")."]
    }
  },
  {
    id: "t4_pqc_hardware_accelerated_pqc_fpga_and_asic",
    tier: 4, cat: "defense", track: "pqc", points: 250, ci: false, fmt: "FLAG{...}",
    title: { ko: "FPGA 및 ASIC 하드웨어 가속기 기반의 고성능 PQC 엔진", en: "FPGA & ASIC Hardware Acceleration Engines for High-Throughput PQC" },
    prompt: {
      ko: "대규모 데이터센터 트래픽 처리를 위해 NTT 파이프라인, Keccak/SHA-3 해시 코어, 고속 배럴 시프터를 온칩 하드웨어로 구현한 PQC 가속기 아키텍처를 분석합니다.\n지정된 식별자 `pqc_hardware_accelerated_pqc_fpga_and_asic_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"pqc_hardware_accelerated_pqc_fpga_and_asic_v1\") 앞 20자리}`",
      en: "Study hardware coprocessor architectures integrating pipelined NTT butterflies and Keccak cores for 100Gbps PQC line-rate TLS offloading.\nCompute the first 20 hex characters of SHA256(\"pqc_hardware_accelerated_pqc_fpga_and_asic_v1\").\n\nFormat: `FLAG{SHA256(\"pqc_hardware_accelerated_pqc_fpga_and_asic_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["하드웨어 가속기는 소프트웨어 대비 수십 배의 핸드셰이크 처리량과 마이크로초 단위의 지연 시간을 보장합니다.", "식별자 `pqc_hardware_accelerated_pqc_fpga_and_asic_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Dedicated NTT butterfly logic and dual-port BRAMs achieve sub-microsecond encapsulation and decapsulation cycles.", "Extract first 20 hex chars of SHA256(\"pqc_hardware_accelerated_pqc_fpga_and_asic_v1\")."]
    }
  },
  {
    id: "t4_pqc_zero_knowledge_proofs_on_lattice_assumptions",
    tier: 4, cat: "lattice", track: "pqc", points: 250, ci: false, fmt: "FLAG{...}",
    title: { ko: "격자 난제 기반의 포스트 퀀텀 영지식 증명(Lattice ZKP)", en: "Post-Quantum Zero-Knowledge Proofs (ZKP) on Lattice Hardness" },
    prompt: {
      ko: "양자 컴퓨터 공격에도 안전한 영지식 스나크(SNARK) 및 슈노르 변형 증명을 위해 SIS(Short Integer Solution) 난제에 기반한 PQC ZKP 체계를 분석합니다.\n지정된 식별자 `pqc_zero_knowledge_proofs_on_lattice_assumptions_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"pqc_zero_knowledge_proofs_on_lattice_assumptions_v1\") 앞 20자리}`",
      en: "Explore post-quantum zero-knowledge proofs constructed over Short Integer Solution (SIS) and Ring-LWE lattice hardness assumptions.\nCompute the first 20 hex characters of SHA256(\"pqc_zero_knowledge_proofs_on_lattice_assumptions_v1\").\n\nFormat: `FLAG{SHA256(\"pqc_zero_knowledge_proofs_on_lattice_assumptions_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["격자 기반 영지식 증명은 블록체인 프라이버시와 신원 인증을 양자 시대로 안전하게 확장합니다.", "식별자 `pqc_zero_knowledge_proofs_on_lattice_assumptions_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Lattice-based non-interactive zero-knowledge protocols ensure post-quantum anonymity and verifiable computation.", "Extract first 20 hex chars of SHA256(\"pqc_zero_knowledge_proofs_on_lattice_assumptions_v1\")."]
    }
  },
  {
    id: "t4_pqc_hybrid_signature_dual_envelope_verification",
    tier: 4, cat: "hybrid", track: "pqc", points: 250, ci: false, fmt: "FLAG{...}",
    title: { ko: "하이브리드 전자서명 이중 봉투(Dual Envelope) 교차 검증", en: "Hybrid Digital Signature Dual Envelope Cross-Verification" },
    prompt: {
      ko: "기존 규제 준수를 위해 RSA/ECDSA 서명과 양자 안전을 위한 ML-DSA 서명을 단일 CMS/PKCS#7 객체에 결합하여 이중 검증하는 아키텍처를 분석합니다.\n지정된 식별자 `pqc_hybrid_signature_dual_envelope_verification_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"pqc_hybrid_signature_dual_envelope_verification_v1\") 앞 20자리}`",
      en: "Audit hybrid digital signature envelopes binding classical ECDSA and ML-DSA signatures together under composite CMS message structures.\nCompute the first 20 hex characters of SHA256(\"pqc_hybrid_signature_dual_envelope_verification_v1\").\n\nFormat: `FLAG{SHA256(\"pqc_hybrid_signature_dual_envelope_verification_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["양방향 논리곱(AND) 검증을 적용하여 두 서명이 모두 유효해야만 문서 무결성을 승인합니다.", "식별자 `pqc_hybrid_signature_dual_envelope_verification_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Dual-envelope schemes enforce conjunction verification requiring both classical and PQC signature validity.", "Extract first 20 hex chars of SHA256(\"pqc_hybrid_signature_dual_envelope_verification_v1\")."]
    }
  },
  {
    id: "t4_pqc_quantum_key_distribution_qkd_vs_pqc_coexistence",
    tier: 4, cat: "hybrid", track: "pqc", points: 250, ci: false, fmt: "FLAG{...}",
    title: { ko: "양자 키 분배(QKD)와 수학적 PQC의 상호 보완 및 공존 모델", en: "Quantum Key Distribution (QKD) vs Algorithmic PQC Coexistence" },
    prompt: {
      ko: "물리 계층 광섬유 양자 얽힘 기반의 QKD(BB84)와 소프트웨어 애플리케이션 계층 PQC(ML-KEM)의 장단점 및 심층 방어 결합 체계를 분석합니다.\n지정된 식별자 `pqc_quantum_key_distribution_qkd_vs_pqc_coexistence_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"pqc_quantum_key_distribution_qkd_vs_pqc_coexistence_v1\") 앞 20자리}`",
      en: "Compare physical-layer Quantum Key Distribution (QKD) hardware with software-deployable algorithmic PQC in defense-in-depth frameworks.\nCompute the first 20 hex characters of SHA256(\"pqc_quantum_key_distribution_qkd_vs_pqc_coexistence_v1\").\n\nFormat: `FLAG{SHA256(\"pqc_quantum_key_distribution_qkd_vs_pqc_coexistence_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["QKD는 전용 광학 장비와 거리 제약이 있으나 정보이론적 안전성을 제공하며, PQC는 기존 인터넷 인프라에 즉시 배포 가능합니다.", "식별자 `pqc_quantum_key_distribution_qkd_vs_pqc_coexistence_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["QKD offers physical information-theoretic security over dedicated fiber, while PQC scales over standard IP routing.", "Extract first 20 hex chars of SHA256(\"pqc_quantum_key_distribution_qkd_vs_pqc_coexistence_v1\")."]
    }
  },
  {
    id: "t4_pqc_fault_tolerant_quantum_computer_qubit_overhead",
    tier: 4, cat: "pqc", track: "pqc", points: 250, ci: false, fmt: "FLAG{...}",
    title: { ko: "오류 정정 양자 컴퓨터(FTQC)의 표면 코드와 물리 큐비트 오버헤드", en: "Fault-Tolerant Quantum Computing Surface Codes & Physical Qubit Overhead" },
    prompt: {
      ko: "RSA-2048을 쇼어 알고리즘으로 해독하기 위해 요구되는 약 4,096개의 논리 큐비트와 1:1000 이상의 표면 코드(Surface Code) 물리 큐비트 오버헤드를 분석합니다.\n지정된 식별자 `pqc_fault_tolerant_quantum_computer_qubit_overhead_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"pqc_fault_tolerant_quantum_computer_qubit_overhead_v1\") 앞 20자리}`",
      en: "Analyze physical qubit overheads where 4,096 logical qubits required for breaking RSA-2048 translate to millions of physical qubits under 2D surface codes.\nCompute the first 20 hex characters of SHA256(\"pqc_fault_tolerant_quantum_computer_qubit_overhead_v1\").\n\nFormat: `FLAG{SHA256(\"pqc_fault_tolerant_quantum_computer_qubit_overhead_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["물리 큐비트 에러율을 낮추기 위한 양자 오류 정정(QEC) 사이클이 대규모 양자 컴퓨터 상용화의 핵심 척도입니다.", "식별자 `pqc_fault_tolerant_quantum_computer_qubit_overhead_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Threshold theorems in quantum error correction govern the realistic timeline to Cryptographically Relevant Quantum Computers (CRQC).", "Extract first 20 hex chars of SHA256(\"pqc_fault_tolerant_quantum_computer_qubit_overhead_v1\")."]
    }
  },
  {
    id: "t4_pqc_capstone_enterprise_pqc_defense_architecture",
    tier: 4, cat: "defense", track: "pqc", points: 250, ci: false, fmt: "FLAG{...}",
    title: { ko: "엔터프라이즈 전사 양자 내성 암호 전환 캡스톤 아키텍처", en: "Capstone: Enterprise-Wide Post-Quantum Cryptographic Defense Architecture" },
    prompt: {
      ko: "CBOM 자산 식별부터 TLS 하이브리드 KEM, FIPS 203/204 표준 배포, IPsec VPN 전환, 엄격한 다운그레이드 방어까지 통합한 전사 PQC 아키텍처를 완성합니다.\n지정된 식별자 `pqc_capstone_enterprise_pqc_defense_architecture_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"pqc_capstone_enterprise_pqc_defense_architecture_v1\") 앞 20자리}`",
      en: "Synthesize full-spectrum enterprise post-quantum transition combining CBOM auditing, ML-KEM/ML-DSA deployment, and hybrid TLS resilience.\nCompute the first 20 hex characters of SHA256(\"pqc_capstone_enterprise_pqc_defense_architecture_v1\").\n\nFormat: `FLAG{SHA256(\"pqc_capstone_enterprise_pqc_defense_architecture_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["엔터프라이즈 PQC 전환은 암호 인벤토리 파악, 하이브리드 과도기 도입, 완전한 FIPS 표준화 3단계로 완결됩니다.", "식별자 `pqc_capstone_enterprise_pqc_defense_architecture_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Comprehensive PQC architecture integrates CBOM discovery, hybrid transition channels, and strict cryptographic agility.", "Extract first 20 hex chars of SHA256(\"pqc_capstone_enterprise_pqc_defense_architecture_v1\")."]
    }
  }
];

// Attach computed hashes
const challengesWithHash = challengesDef.map(ch => ({
  ...ch,
  hash: computeHash(ch.id)
}));

console.log(`Generated ${challengesWithHash.length} challenges for Track 59 (pqc)`);
fs.writeFileSync(path.join(__dirname, 'track59_challenges.json'), JSON.stringify(challengesWithHash, null, 2), 'utf8');
console.log('Saved to tools/track59_challenges.json');
