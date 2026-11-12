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
    id: "t0_pqcmigrate_shor_algorithm_rsa_threat",
    tier: 0, cat: "quantum", track: "pqcmigrate", points: 25, ci: false, fmt: "FLAG{...}",
    title: {
      ko: "쇼어 알고리즘(Shor's Algorithm)과 기존 공개키 암호(RSA/ECC) 위협",
      en: "Shor's Algorithm & Quantum Threat to Classical Public-Key Cryptography (RSA/ECC)"
    },
    prompt: {
      ko: "대규모 양자 컴퓨터가 구현될 경우 다항 시간(Polynomial Time) 내에 소인수분해 및 이산대수를 해결하는 쇼어 알고리즘의 원리와 기존 RSA/ECC 붕괴 위험을 분석합니다.\n지정된 식별자 `pqcmigrate_shor_algorithm_rsa_threat_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"pqcmigrate_shor_algorithm_rsa_threat_v1\") 앞 20자리}`",
      en: "Analyze how Shor's algorithm solves discrete logarithms and prime factorizations in polynomial time, collapsing classical RSA and ECC cryptosystems.\nCompute the first 20 hex characters of SHA256(\"pqcmigrate_shor_algorithm_rsa_threat_v1\").\n\nFormat: `FLAG{SHA256(\"pqcmigrate_shor_algorithm_rsa_threat_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["양자 푸리에 변환(QFT)을 활용한 주기 탐색(Period Finding)이 소인수분해를 지수 시간에서 다항 시간으로 가속합니다.", "식별자 `pqcmigrate_shor_algorithm_rsa_threat_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Quantum Fourier Transform (QFT) based period finding reduces factorization from exponential to polynomial complexity.", "Extract the first 20 hex characters of SHA256(\"pqcmigrate_shor_algorithm_rsa_threat_v1\")."]
    }
  },
  {
    id: "t0_pqcmigrate_nist_pqc_standards_overview",
    tier: 0, cat: "standards", track: "pqcmigrate", points: 25, ci: false, fmt: "FLAG{...}",
    title: {
      ko: "NIST PQC 표준화 규격(FIPS 203 ML-KEM & FIPS 204 ML-DSA) 개요",
      en: "NIST Post-Quantum Cryptography Standards Overview (FIPS 203 ML-KEM & FIPS 204 ML-DSA)"
    },
    prompt: {
      ko: "2024년 공식 제정된 미국 NIST의 양자 내성 암호 표준 FIPS 203(ML-KEM, 구 Kyber)과 FIPS 204(ML-DSA, 구 Dilithium)의 핵심 규격을 비교 분석합니다.\n지정된 식별자 `pqcmigrate_nist_pqc_standards_overview_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"pqcmigrate_nist_pqc_standards_overview_v1\") 앞 20자리}`",
      en: "Review the NIST Post-Quantum Cryptography final standards released in 2024: FIPS 203 (ML-KEM, formerly Kyber) and FIPS 204 (ML-DSA, formerly Dilithium).\nCompute the first 20 hex characters of SHA256(\"pqcmigrate_nist_pqc_standards_overview_v1\").\n\nFormat: `FLAG{SHA256(\"pqcmigrate_nist_pqc_standards_overview_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["FIPS 203은 모듈 격자 기반 키 캡슐화(KEM), FIPS 204는 모듈 격자 기반 전자서명(DSA) 규격입니다.", "식별자 `pqcmigrate_nist_pqc_standards_overview_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["FIPS 203 governs Module-Lattice Key Encapsulation (KEM) while FIPS 204 specifies Module-Lattice Digital Signatures.", "Extract the first 20 hex characters of SHA256(\"pqcmigrate_nist_pqc_standards_overview_v1\")."]
    }
  },

  // Tier 1 (8)
  {
    id: "t1_pqcmigrate_sndl_store_now_decrypt_later",
    tier: 1, cat: "sndl", track: "pqcmigrate", points: 50, ci: false, fmt: "FLAG{...}",
    title: {
      ko: "현재 수집 후 미래 복호화(SNDL) 공격 모델과 대응 시급성",
      en: "Store-Now-Decrypt-Later (SNDL) Attack Model & Migration Urgency"
    },
    prompt: {
      ko: "공격자가 현재 암호화된 통신 트래픽을 대량으로 수집·저장해 두고 미래 양자 컴퓨터 등장 시 복호화하는 SNDL(Harvest Now, Decrypt Later) 위협 모델을 분석합니다.\n지정된 식별자 `pqcmigrate_sndl_store_now_decrypt_later_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"pqcmigrate_sndl_store_now_decrypt_later_v1\") 앞 20자리}`",
      en: "Evaluate the Store-Now-Decrypt-Later (SNDL) threat model where adversarial actors record encrypted ciphertext today for retroactive decryption when cryptanalytically relevant quantum computers emerge.\nCompute the first 20 hex characters of SHA256(\"pqcmigrate_sndl_store_now_decrypt_later_v1\").\n\nFormat: `FLAG{SHA256(\"pqcmigrate_sndl_store_now_decrypt_later_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["기밀 유지 수명이 10년 이상인 정부 기밀, 의료 정보, 금융 마스터키는 즉각적인 PQC 전환이 요구됩니다.", "식별자 `pqcmigrate_sndl_store_now_decrypt_later_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Data with shelf-life exceeding 10 years (defense secrets, medical histories) must transition to PQC immediately to nullify SNDL.", "Extract the first 20 hex characters of SHA256(\"pqcmigrate_sndl_store_now_decrypt_later_v1\")."]
    }
  },
  {
    id: "t1_pqcmigrate_fips203_ml_kem_parameter_sets",
    tier: 1, cat: "kem", track: "pqcmigrate", points: 50, ci: false, fmt: "FLAG{...}",
    title: {
      ko: "FIPS 203 ML-KEM 보안 레벨별 파라미터 세트 (512/768/1024)",
      en: "FIPS 203 ML-KEM Parameter Sets Across Security Levels (512/768/1024)"
    },
    prompt: {
      ko: "ML-KEM-512 (보안 강도 1, AES-128 동급), ML-KEM-768 (보안 강도 3, AES-192 동급), ML-KEM-1024 (보안 강도 5, AES-256 동급)의 키 및 암호문 크기를 비교합니다.\n지정된 식별자 `pqcmigrate_fips203_ml_kem_parameter_sets_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"pqcmigrate_fips203_ml_kem_parameter_sets_v1\") 앞 20자리}`",
      en: "Compare parameter sets of ML-KEM: ML-KEM-512 (Category 1), ML-KEM-768 (Category 3, standard default), and ML-KEM-1024 (Category 5).\nCompute the first 20 hex characters of SHA256(\"pqcmigrate_fips203_ml_kem_parameter_sets_v1\").\n\nFormat: `FLAG{SHA256(\"pqcmigrate_fips203_ml_kem_parameter_sets_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["일반적인 범용 TLS 마이그레이션 권장 파라미터는 보안성과 성능 균형을 갖춘 ML-KEM-768입니다.", "식별자 `pqcmigrate_fips203_ml_kem_parameter_sets_v1`의 해시 앞 20자리를 계산하세요."],
      en: ["ML-KEM-768 represents the recommended sweet spot balancing transmission overhead and quantum resistance for TLS.", "Extract the first 20 hex characters of SHA256(\"pqcmigrate_fips203_ml_kem_parameter_sets_v1\")."]
    }
  },
  {
    id: "t1_pqcmigrate_fips204_ml_dsa_dilithium_spec",
    tier: 1, cat: "dsa", track: "pqcmigrate", points: 50, ci: false, fmt: "FLAG{...}",
    title: {
      ko: "FIPS 204 ML-DSA (Dilithium) 격자 기반 전자서명 규격",
      en: "FIPS 204 ML-DSA (Dilithium) Lattice-Based Digital Signature Specification"
    },
    prompt: {
      ko: "Module Learning with Errors(M-LWE) 및 Module Short Integer Solution(M-SIS) 문제의 난해성에 기반한 FIPS 204 ML-DSA 전자서명 규격을 분석합니다.\n지정된 식별자 `pqcmigrate_fips204_ml_dsa_dilithium_spec_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"pqcmigrate_fips204_ml_dsa_dilithium_spec_v1\") 앞 20자리}`",
      en: "Analyze the FIPS 204 ML-DSA digital signature standard based on Module Learning with Errors (M-LWE) and Module Short Integer Solution (M-SIS) lattice hardness.\nCompute the first 20 hex characters of SHA256(\"pqcmigrate_fips204_ml_dsa_dilithium_spec_v1\").\n\nFormat: `FLAG{SHA256(\"pqcmigrate_fips204_ml_dsa_dilithium_spec_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["ML-DSA는 Fiat-Shamir with Aborts 기법을 적용하여 거부 샘플링을 통해 개인키 노출을 방지합니다.", "식별자 `pqcmigrate_fips204_ml_dsa_dilithium_spec_v1`의 해시 앞 20자리를 계산하세요."],
      en: ["ML-DSA leverages the Fiat-Shamir with Aborts paradigm to eliminate private key leakage during signature sampling.", "Extract the first 20 hex characters of SHA256(\"pqcmigrate_fips204_ml_dsa_dilithium_spec_v1\")."]
    }
  },
  {
    id: "t1_pqcmigrate_fips205_slh_dsa_sphincs_hash",
    tier: 1, cat: "hashsig", track: "pqcmigrate", points: 50, ci: false, fmt: "FLAG{...}",
    title: {
      ko: "FIPS 205 SLH-DSA (SPHINCS+) 상태 비저장 해시 기반 서명",
      en: "FIPS 205 SLH-DSA (SPHINCS+) Stateless Hash-Based Signature Scheme"
    },
    prompt: {
      ko: "격자 암호의 수학적 가정이 공격받을 때 백업 안전장치 역할을 수행하는 무상태 해시 기반 디지털 서명 FIPS 205(SLH-DSA)의 작동 메커니즘을 분석합니다.\n지정된 식별자 `pqcmigrate_fips205_slh_dsa_sphincs_hash_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"pqcmigrate_fips205_slh_dsa_sphincs_hash_v1\") 앞 20자리}`",
      en: "Examine FIPS 205 SLH-DSA (stateless hash-based signatures), which serves as a hedge against potential mathematical cryptanalysis against lattice schemes.\nCompute the first 20 hex characters of SHA256(\"pqcmigrate_fips205_slh_dsa_sphincs_hash_v1\").\n\nFormat: `FLAG{SHA256(\"pqcmigrate_fips205_slh_dsa_sphincs_hash_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["SLH-DSA는 WOTS+ 일회용 서명과 하이퍼트리(Hypertree) 구조를 결합하여 상태 동기화 없이 안전한 다중 서명을 제공합니다.", "식별자 `pqcmigrate_fips205_slh_dsa_sphincs_hash_v1`의 해시 앞 20자리를 확인하세요."],
      en: ["SLH-DSA uses WOTS+ one-time signatures and hypertree hierarchies to ensure stateless multi-signature safety.", "Extract the first 20 hex characters of SHA256(\"pqcmigrate_fips205_slh_dsa_sphincs_hash_v1\")."]
    }
  },
  {
    id: "t1_pqcmigrate_hybrid_key_exchange_x25519_kyber",
    tier: 1, cat: "hybrid", track: "pqcmigrate", points: 50, ci: false, fmt: "FLAG{...}",
    title: {
      ko: "하이브리드 키 교환 프로토콜 구조 (X25519 + ML-KEM-768)",
      en: "Hybrid Key Exchange Protocol Architecture (X25519 + ML-KEM-768)"
    },
    prompt: {
      ko: "검증된 고전 알고리즘(ECDH X25519)과 양자 내성 KEM(ML-KEM-768)을 동시에 수행하여 둘 중 하나가 뚫려도 세션 기밀성을 보장하는 하이브리드 키 교환 방식을 분석합니다.\n지정된 식별자 `pqcmigrate_hybrid_key_exchange_x25519_kyber_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"pqcmigrate_hybrid_key_exchange_x25519_kyber_v1\") 앞 20자리}`",
      en: "Study dual-key exchange combining classical X25519 ECDH with ML-KEM-768 to guarantee forward secrecy if either algorithm remains unbroken.\nCompute the first 20 hex characters of SHA256(\"pqcmigrate_hybrid_key_exchange_x25519_kyber_v1\").\n\nFormat: `FLAG{SHA256(\"pqcmigrate_hybrid_key_exchange_x25519_kyber_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["IETF RFC 9180 HPKE 및 TLS 1.3 하이브리드 확장은 두 공유 비밀키를 HKDF-Extract/Expand로 결합합니다.", "식별자 `pqcmigrate_hybrid_key_exchange_x25519_kyber_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["The combined shared secret is derived through HKDF-Extract combining both classical and lattice secrets.", "Extract the first 20 hex characters of SHA256(\"pqcmigrate_hybrid_key_exchange_x25519_kyber_v1\")."]
    }
  },
  {
    id: "t1_pqcmigrate_tls13_supported_groups_extension",
    tier: 1, cat: "tls", track: "pqcmigrate", points: 50, ci: false, fmt: "FLAG{...}",
    title: {
      ko: "TLS 1.3 supported_groups 확장을 통한 PQC 암호 그룹 협상",
      en: "Negotiating PQC Named Groups via TLS 1.3 supported_groups Extension"
    },
    prompt: {
      ko: "ClientHello 메시지의 supported_groups 확장에 하이브리드 PQC 그룹 ID(예: 0x11ec / X25519Kyber768Draft00)를 광고하고 협상하는 메커니즘을 분석합니다.\n지정된 식별자 `pqcmigrate_tls13_supported_groups_extension_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"pqcmigrate_tls13_supported_groups_extension_v1\") 앞 20자리}`",
      en: "Investigate TLS 1.3 supported_groups extension negotiation advertising Post-Quantum hybrid named group codepoints (e.g. 0x11ec).\nCompute the first 20 hex characters of SHA256(\"pqcmigrate_tls13_supported_groups_extension_v1\").\n\nFormat: `FLAG{SHA256(\"pqcmigrate_tls13_supported_groups_extension_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["클라이언트는 key_share 확장에 해당 그룹의 공개키 쉐어를 함께 전송하여 1-RTT 핸드셰이크를 완료합니다.", "식별자 `pqcmigrate_tls13_supported_groups_extension_v1`의 해시 앞 20자리를 확인하세요."],
      en: ["Clients include key_share entries matching the highest preference supported_groups for zero latency overhead.", "Extract the first 20 hex characters of SHA256(\"pqcmigrate_tls13_supported_groups_extension_v1\")."]
    }
  },
  {
    id: "t1_pqcmigrate_crypto_agility_concept",
    tier: 1, cat: "agility", track: "pqcmigrate", points: 50, ci: false, fmt: "FLAG{...}",
    title: {
      ko: "암호 민첩성(Crypto-Agility)과 알고리즘 핫스왑 아키텍처",
      en: "Crypto-Agility Principles & Pluggable Algorithm Architecture"
    },
    prompt: {
      ko: "암호 알고리즘의 결함이나 표준 변경 시 소스 코드 재작성 없이 설정과 플러그인 교체만으로 알고리즘을 즉시 전환할 수 있는 암호 민첩성 설계를 분석합니다.\n지정된 식별자 `pqcmigrate_crypto_agility_concept_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"pqcmigrate_crypto_agility_concept_v1\") 앞 20자리}`",
      en: "Analyze crypto-agility design principles that allow dynamic algorithm hot-swapping via configuration rather than application refactoring.\nCompute the first 20 hex characters of SHA256(\"pqcmigrate_crypto_agility_concept_v1\").\n\nFormat: `FLAG{SHA256(\"pqcmigrate_crypto_agility_concept_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["암호 제공자(Provider API) 추상화와 메타데이터 주도 키 관리 계층이 암호 민첩성의 핵심 인프라입니다.", "식별자 `pqcmigrate_crypto_agility_concept_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Crypto provider abstraction layers and declarative cipher negotiation pipelines enable seamless crypto-agility.", "Extract the first 20 hex characters of SHA256(\"pqcmigrate_crypto_agility_concept_v1\")."]
    }
  },
  {
    id: "t1_pqcmigrate_public_key_ciphertext_overhead",
    tier: 1, cat: "overhead", track: "pqcmigrate", points: 50, ci: false, fmt: "FLAG{...}",
    title: {
      ko: "PQC 공개키 및 암호문(Ciphertext) 크기 오버헤드 분석",
      en: "PQC Public Key & Ciphertext Size Overhead Analysis"
    },
    prompt: {
      ko: "고전 X25519(공개키 32바이트) 대비 ML-KEM-768(공개키 1,184바이트, 암호문 1,088바이트)의 대역폭 및 패킷 크기 증가율을 평가합니다.\n지정된 식별자 `pqcmigrate_public_key_ciphertext_overhead_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"pqcmigrate_public_key_ciphertext_overhead_v1\") 앞 20자리}`",
      en: "Evaluate the bandwidth overhead ratio between classical X25519 (32-byte public key) and ML-KEM-768 (1,184-byte public key, 1,088-byte ciphertext).\nCompute the first 20 hex characters of SHA256(\"pqcmigrate_public_key_ciphertext_overhead_v1\").\n\nFormat: `FLAG{SHA256(\"pqcmigrate_public_key_ciphertext_overhead_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["격자 암호의 다항식 계수 표현으로 인해 고전 암호 대비 수십 배의 크기 오버헤드가 발생합니다.", "식별자 `pqcmigrate_public_key_ciphertext_overhead_v1`의 해시 앞 20자리를 계산하세요."],
      en: ["Lattice polynomial vectors introduce roughly a 30x to 40x payload expansion over classical elliptic curves.", "Extract the first 20 hex characters of SHA256(\"pqcmigrate_public_key_ciphertext_overhead_v1\")."]
    }
  },

  // Tier 2 (12)
  {
    id: "t2_pqcmigrate_mldsa_signature_verification_flow",
    tier: 2, cat: "mldsa", track: "pqcmigrate", points: 100, ci: false, fmt: "FLAG{...}",
    title: {
      ko: "ML-DSA 서명 생성 및 검증 과정의 거부 샘플링(Rejection Sampling)",
      en: "Rejection Sampling in ML-DSA Signature Generation and Verification Flow"
    },
    prompt: {
      ko: "서명 벡터 z의 계수 분포가 비밀키 s의 정보를 누설하지 않도록 임계값을 초과하는 벡터를 기각하고 재생성하는 거부 샘플링 알고리즘을 분석합니다.\n지정된 식별자 `pqcmigrate_mldsa_signature_verification_flow_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"pqcmigrate_mldsa_signature_verification_flow_v1\") 앞 20자리}`",
      en: "Examine rejection sampling in ML-DSA where signature candidates with non-uniform norm distributions are discarded to prevent private vector leakage.\nCompute the first 20 hex characters of SHA256(\"pqcmigrate_mldsa_signature_verification_flow_v1\").\n\nFormat: `FLAG{SHA256(\"pqcmigrate_mldsa_signature_verification_flow_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["거부 샘플링은 서명 출력 분포를 비밀키와 무관하게 균일하게 만듭니다.", "식별자 `pqcmigrate_mldsa_signature_verification_flow_v1`의 해시 앞 20자리를 계산하세요."],
      en: ["Rejection sampling decouples the statistical distribution of signatures from secret key coefficients.", "Extract the first 20 hex characters of SHA256(\"pqcmigrate_mldsa_signature_verification_flow_v1\")."]
    }
  },
  {
    id: "t2_pqcmigrate_mlkem_ind_cca2_transform",
    tier: 2, cat: "mlkem", track: "pqcmigrate", points: 100, ci: false, fmt: "FLAG{...}",
    title: {
      ko: "ML-KEM 인캡슐레이션의 IND-CCA2 보안과 후지사키-오카모토 변환",
      en: "IND-CCA2 Security in ML-KEM via Fujisaki-Okamoto Transform"
    },
    prompt: {
      ko: "선택 암호문 공격(IND-CCA2)에 취약한 IND-CPA 암호 시스템을 안전한 키 캡슐화 매커니즘으로 전환하는 수정된 후지사키-오카모토(FO) 변환을 분석합니다.\n지정된 식별자 `pqcmigrate_mlkem_ind_cca2_transform_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"pqcmigrate_mlkem_ind_cca2_transform_v1\") 앞 20자리}`",
      en: "Investigate how ML-KEM converts an IND-CPA public-key scheme into an IND-CCA2 secure KEM via the modified Fujisaki-Okamoto (FO) transform.\nCompute the first 20 hex characters of SHA256(\"pqcmigrate_mlkem_ind_cca2_transform_v1\").\n\nFormat: `FLAG{SHA256(\"pqcmigrate_mlkem_ind_cca2_transform_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["FO 변환은 역캡슐화 시 재암호화(Re-encryption)를 수행하여 위조된 암호문을 감지하고 거부합니다.", "식별자 `pqcmigrate_mlkem_ind_cca2_transform_v1`의 해시 앞 20자리를 확인하세요."],
      en: ["The FO transform validates decapsulation candidates by re-encrypting the derived plaintext to check ciphertext equality.", "Extract the first 20 hex characters of SHA256(\"pqcmigrate_mlkem_ind_cca2_transform_v1\")."]
    }
  },
  {
    id: "t2_pqcmigrate_tls_anti_downgrade_server_hello",
    tier: 2, cat: "downgrade", track: "pqcmigrate", points: 100, ci: false, fmt: "FLAG{...}",
    title: {
      ko: "TLS 1.3 ServerHello PQC 다운그레이드 탐지 및 방어 메커니즘",
      en: "TLS 1.3 ServerHello Anti-Downgrade Detection & Enforcement Mechanism"
    },
    prompt: {
      ko: "중간자 공격자가 PQC 암호 그룹 제안을 변조하여 고전 알고리즘으로 강제 다운그레이드시키는 공격을 Finished 해시 검증 및 서버 서명으로 차단하는 원리를 분석합니다.\n지정된 식별자 `pqcmigrate_tls_anti_downgrade_server_hello_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"pqcmigrate_tls_anti_downgrade_server_hello_v1\") 앞 20자리}`",
      en: "Analyze how TLS 1.3 Finished transcript hashing and CertificateVerify signatures prevent MitM attackers from stripping PQC cipher proposals.\nCompute the first 20 hex characters of SHA256(\"pqcmigrate_tls_anti_downgrade_server_hello_v1\").\n\nFormat: `FLAG{SHA256(\"pqcmigrate_tls_anti_downgrade_server_hello_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["핸드셰이크 전송 기록(Transcript)의 무결성 검증 실패 시 연결이 즉시 중단(Decrypt Error Alert)됩니다.", "식별자 `pqcmigrate_tls_anti_downgrade_server_hello_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Any tampering with advertised supported_groups alters the transcript hash, triggering fatal decrypt_error alerts.", "Extract the first 20 hex characters of SHA256(\"pqcmigrate_tls_anti_downgrade_server_hello_v1\")."]
    }
  },
  {
    id: "t2_pqcmigrate_hybrid_kdf_dual_secret_binding",
    tier: 2, cat: "kdf", track: "pqcmigrate", points: 100, ci: false, fmt: "FLAG{...}",
    title: {
      ko: "하이브리드 KDF의 고전-양자 이중 비밀키(Dual Shared Secret) 바인딩",
      en: "Classical-Quantum Dual Secret Binding in Hybrid KDF Pipelines"
    },
    prompt: {
      ko: "고전 ECDH 비밀키(SS_classic)와 양자 KEM 비밀키(SS_pqc)를 결합하여 HKDF-Extract(IKM = SS_classic || SS_pqc)로 마스터 세션 키를 유도하는 구조를 분석합니다.\n지정된 식별자 `pqcmigrate_hybrid_kdf_dual_secret_binding_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"pqcmigrate_hybrid_kdf_dual_secret_binding_v1\") 앞 20자리}`",
      en: "Evaluate hybrid key derivation binding where input key material combines SS_classic and SS_pqc into a unified master derivation pipeline.\nCompute the first 20 hex characters of SHA256(\"pqcmigrate_hybrid_kdf_dual_secret_binding_v1\").\n\nFormat: `FLAG{SHA256(\"pqcmigrate_hybrid_kdf_dual_secret_binding_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["두 비밀키의 접합(Concatenation)은 암호학적 비분리성(Indivisibility)을 제공합니다.", "식별자 `pqcmigrate_hybrid_kdf_dual_secret_binding_v1`의 해시 앞 20자리를 계산하세요."],
      en: ["Concatenation ensures that knowledge of only one component provides zero advantage against the pseudo-random PRK.", "Extract the first 20 hex characters of SHA256(\"pqcmigrate_hybrid_kdf_dual_secret_binding_v1\")."]
    }
  },
  {
    id: "t2_pqcmigrate_x509_composite_pqc_certificates",
    tier: 2, cat: "x509", track: "pqcmigrate", points: 100, ci: false, fmt: "FLAG{...}",
    title: {
      ko: "X.509 복합(Composite) 및 이중(Dual) PQC 인증서 프로파일",
      en: "X.509 Composite & Dual PQC Certificate Profiles (ITU-T & IETF Draft)"
    },
    prompt: {
      ko: "기존 PKI 시스템과의 역호환성을 위해 하나의 인증서에 고전 서명(ECDSA)과 PQC 서명(ML-DSA)을 병기하는 Composite X.509 인증서 구조를 분석합니다.\n지정된 식별자 `pqcmigrate_x509_composite_pqc_certificates_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"pqcmigrate_x509_composite_pqc_certificates_v1\") 앞 20자리}`",
      en: "Analyze Composite X.509 certificate formats bundling both classical (ECDSA) and post-quantum (ML-DSA) keys to satisfy dual validation requirements.\nCompute the first 20 hex characters of SHA256(\"pqcmigrate_x509_composite_pqc_certificates_v1\").\n\nFormat: `FLAG{SHA256(\"pqcmigrate_x509_composite_pqc_certificates_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["복합 키 알고리즘 OID는 단일 검증 실패 시 전체 인증서를 거부하도록 강제합니다.", "식별자 `pqcmigrate_x509_composite_pqc_certificates_v1`의 해시 앞 20자리를 확인하세요."],
      en: ["Composite algorithms define strict validation logic requiring all constituent signatures to pass verification.", "Extract the first 20 hex characters of SHA256(\"pqcmigrate_x509_composite_pqc_certificates_v1\")."]
    }
  },
  {
    id: "t2_pqcmigrate_mtu_fragmentation_hazard",
    tier: 2, cat: "mtu", track: "pqcmigrate", points: 100, ci: false, fmt: "FLAG{...}",
    title: {
      ko: "PQC 대형 핸드셰이크 패킷으로 인한 MTU 단편화 및 패킷 드롭 위험",
      en: "MTU Fragmentation Hazards & Packet Loss from Large PQC Handshakes"
    },
    prompt: {
      ko: "PQC 공개키와 인증서 체인의 크기가 표준 이더넷 MTU(1500바이트)를 초과하여 TCP 세그먼트 단편화 및 일부 방화벽/WAF에서 패킷이 드롭되는 문제를 분석합니다.\n지정된 식별자 `pqcmigrate_mtu_fragmentation_hazard_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"pqcmigrate_mtu_fragmentation_hazard_v1\") 앞 20자리}`",
      en: "Examine IP fragmentation hazards when PQC public keys and certificates exceed Ethernet MTU (1500B), causing packet drops in legacy middleboxes.\nCompute the first 20 hex characters of SHA256(\"pqcmigrate_mtu_fragmentation_hazard_v1\").\n\nFormat: `FLAG{SHA256(\"pqcmigrate_mtu_fragmentation_hazard_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["TCP 세그먼트 크기(MSS) 클램핑과 TLS 인증서 압축(RFC 8879)이 단편화 완화 솔루션으로 활용됩니다.", "식별자 `pqcmigrate_mtu_fragmentation_hazard_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["MSS clamping and RFC 8879 TLS Certificate Compression mitigate handshake fragmentation issues.", "Extract the first 20 hex characters of SHA256(\"pqcmigrate_mtu_fragmentation_hazard_v1\")."]
    }
  },
  {
    id: "t2_pqcmigrate_ssh_openquantumsafe_liboqs",
    tier: 2, cat: "liboqs", track: "pqcmigrate", points: 100, ci: false, fmt: "FLAG{...}",
    title: {
      ko: "OpenSSH 및 liboqs 통합을 통한 양자 내성 원격 셸 구축",
      en: "Post-Quantum Remote Shell Deployment via OpenSSH & liboqs Integration"
    },
    prompt: {
      ko: "Open Quantum Safe(OQS) 프로젝트의 liboqs 라이브러리를 활용하여 OpenSSH의 KexAlgorithms 설정에 `sntrup761x25519-sha512@openssh.com` 및 `mlkem768x25519-sha256`을 적용하는 절차를 분석합니다.\n지정된 식별자 `pqcmigrate_ssh_openquantumsafe_liboqs_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"pqcmigrate_ssh_openquantumsafe_liboqs_v1\") 앞 20자리}`",
      en: "Analyze OpenSSH configuration hardening integrating liboqs and activating sntrup761 and mlkem768 hybrid key exchange algorithms.\nCompute the first 20 hex characters of SHA256(\"pqcmigrate_ssh_openquantumsafe_liboqs_v1\").\n\nFormat: `FLAG{SHA256(\"pqcmigrate_ssh_openquantumsafe_liboqs_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["OpenSSH 9.0+ 버전부터 NTRU Prime 하이브리드가 기본 키 교환 알고리즘으로 활성화되어 있습니다.", "식별자 `pqcmigrate_ssh_openquantumsafe_liboqs_v1`의 해시 앞 20자리를 확인하세요."],
      en: ["OpenSSH 9.0+ defaulted to sntrup761x25519 hybrid key exchange as an early hedge against quantum capture.", "Extract the first 20 hex characters of SHA256(\"pqcmigrate_ssh_openquantumsafe_liboqs_v1\")."]
    }
  },
  {
    id: "t2_pqcmigrate_ipsec_ikev2_pqc_extension",
    tier: 2, cat: "ipsec", track: "pqcmigrate", points: 100, ci: false, fmt: "FLAG{...}",
    title: {
      ko: "IPsec IKEv2 RFC 9370 다중 키 교환 확장을 통한 PQC 터널링",
      en: "IPsec IKEv2 RFC 9370 Multiple Key Exchange Extension for PQC Tunnels"
    },
    prompt: {
      ko: "VPN 및 사이트 간 암호화 터널에서 RFC 9370 표준을 활용하여 IKEv2에 추가 키 교환(Additional Key Exchange) 페이로드를 전달하는 PQC 터널링 설계를 분석합니다.\n지정된 식별자 `pqcmigrate_ipsec_ikev2_pqc_extension_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"pqcmigrate_ipsec_ikev2_pqc_extension_v1\") 앞 20자리}`",
      en: "Evaluate IPsec IKEv2 multiple key exchanges per RFC 9370, enabling modular addition of post-quantum key shares into site-to-site IPsec tunnels.\nCompute the first 20 hex characters of SHA256(\"pqcmigrate_ipsec_ikev2_pqc_extension_v1\").\n\nFormat: `FLAG{SHA256(\"pqcmigrate_ipsec_ikev2_pqc_extension_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["IKE_INTERMEDIATE 메시지를 통해 대형 PQC 키 교환 데이터를 분할 전송하여 터널을 수립합니다.", "식별자 `pqcmigrate_ipsec_ikev2_pqc_extension_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["RFC 9370 introduces IKE_INTERMEDIATE exchanges to transmit auxiliary post-quantum key shares before IKE_AUTH.", "Extract the first 20 hex characters of SHA256(\"pqcmigrate_ipsec_ikev2_pqc_extension_v1\")."]
    }
  },
  {
    id: "t2_pqcmigrate_side_channel_lattice_timing",
    tier: 2, cat: "sidechannel", track: "pqcmigrate", points: 100, ci: false, fmt: "FLAG{...}",
    title: {
      ko: "격자 암호 다항식 곱셈 과정의 부채널(타이밍/전력) 취약점 분석",
      en: "Side-Channel Timing & Power Leakage Analysis in Lattice Polynomial Multiplication"
    },
    prompt: {
      ko: "격자 기반 암호 연산 중 다항식 곱셈 및 샘플링에서 분기 분기문(Branching)이나 캐시 접근 패턴의 불균일성으로 인해 비밀 계수가 누설되는 부채널 공격을 분석합니다.\n지정된 식별자 `pqcmigrate_side_channel_lattice_timing_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"pqcmigrate_side_channel_lattice_timing_v1\") 앞 20자리}`",
      en: "Analyze timing and power side-channel vulnerabilities in polynomial multiplication where non-constant-time sampling leaks lattice coefficients.\nCompute the first 20 hex characters of SHA256(\"pqcmigrate_side_channel_lattice_timing_v1\").\n\nFormat: `FLAG{SHA256(\"pqcmigrate_side_channel_lattice_timing_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["모든 다항식 연산과 조건문 비교는 반드시 상수 시간(Constant-Time)으로 구현되어야 합니다.", "식별자 `pqcmigrate_side_channel_lattice_timing_v1`의 해시 앞 20자리를 계산하세요."],
      en: ["Constant-time masking and arithmetic implementations are essential to protect lattice operations against DPA/timing leaks.", "Extract the first 20 hex characters of SHA256(\"pqcmigrate_side_channel_lattice_timing_v1\")."]
    }
  },
  {
    id: "t2_pqcmigrate_fault_injection_lattice_ntt",
    tier: 2, cat: "fault", track: "pqcmigrate", points: 100, ci: false, fmt: "FLAG{...}",
    title: {
      ko: "NTT(Number Theoretic Transform) 연산 대상 결함 주입 공격 방어",
      en: "Fault Injection Attack Mitigation in Number Theoretic Transform (NTT)"
    },
    prompt: {
      ko: "격자 암호의 고속 다항식 곱셈을 담당하는 NTT 연산 단계에 레이저/전압 글리치를 주입하여 비밀 다항식 계수를 복원하는 결함 주입 공격의 방어책을 분석합니다.\n지정된 식별자 `pqcmigrate_fault_injection_lattice_ntt_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"pqcmigrate_fault_injection_lattice_ntt_v1\") 앞 20자리}`",
      en: "Examine fault injection countermeasures during Number Theoretic Transform (NTT) executions in hardware accelerators against glitch-induced coefficient leaks.\nCompute the first 20 hex characters of SHA256(\"pqcmigrate_fault_injection_lattice_ntt_v1\").\n\nFormat: `FLAG{SHA256(\"pqcmigrate_fault_injection_lattice_ntt_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["이중 계산(Redundant Computation) 및 역변환 체크섬 검증이 하드웨어 결함 주입을 차단합니다.", "식별자 `pqcmigrate_fault_injection_lattice_ntt_v1`의 해시 앞 20자리를 확인하세요."],
      en: ["Dual-rail arithmetic and post-transform checksum invariants effectively neutralize laser fault perturbations.", "Extract the first 20 hex characters of SHA256(\"pqcmigrate_fault_injection_lattice_ntt_v1\")."]
    }
  },
  {
    id: "t2_pqcmigrate_hsm_kms_pqc_key_custody",
    tier: 2, cat: "hsm", track: "pqcmigrate", points: 100, ci: false, fmt: "FLAG{...}",
    title: {
      ko: "클라우드 KMS 및 HSM(FIPS 140-3) PQC 루트 키 수명주기 관리",
      en: "Cloud KMS & HSM (FIPS 140-3) PQC Root Key Lifecycle Custody"
    },
    prompt: {
      ko: "FIPS 140-3 보안 요구사항을 충족하는 하드웨어 보안 모듈(HSM) 및 클라우드 KMS 환경에서 PQC 루트 키를 안전하게 생성·보관·로테이션하는 수명주기 아키텍처를 분석합니다.\n지정된 식별자 `pqcmigrate_hsm_kms_pqc_key_custody_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"pqcmigrate_hsm_kms_pqc_key_custody_v1\") 앞 20자리}`",
      en: "Review FIPS 140-3 HSM firmware extensions and cloud KMS custody frameworks supporting ML-KEM/ML-DSA root cryptographic lifecycles.\nCompute the first 20 hex characters of SHA256(\"pqcmigrate_hsm_kms_pqc_key_custody_v1\").\n\nFormat: `FLAG{SHA256(\"pqcmigrate_hsm_kms_pqc_key_custody_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["HSM 펌웨어의 PKCS#11 v3.2 PQC 메커니즘 지원 여부가 엔터프라이즈 키 커스터디의 핵심 기준입니다.", "식별자 `pqcmigrate_hsm_kms_pqc_key_custody_v1`의 해시 앞 20자리를 계산하세요."],
      en: ["PKCS#11 v3.2 mechanism interfaces allow applications to invoke hardware-isolated PQC key generation and signing.", "Extract the first 20 hex characters of SHA256(\"pqcmigrate_hsm_kms_pqc_key_custody_v1\")."]
    }
  },
  {
    id: "t2_pqcmigrate_code_signing_secure_boot_pqc",
    tier: 2, cat: "boot", track: "pqcmigrate", points: 100, ci: false, fmt: "FLAG{...}",
    title: {
      ko: "PQC 기반 코드 서명 및 시큐어 부트(Secure Boot) 펌웨어 검증",
      en: "PQC-Based Code Signing & Secure Boot Firmware Integrity Verification"
    },
    prompt: {
      ko: "임베디드 ROM 및 UEFI 환경에서 부팅 단계의 펌웨어 무결성을 검증하기 위해 ML-DSA 또는 LMS 상태 기반 서명을 시큐어 부트 체인에 통합하는 설계를 분석합니다.\n지정된 식별자 `pqcmigrate_code_signing_secure_boot_pqc_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"pqcmigrate_code_signing_secure_boot_pqc_v1\") 앞 20자리}`",
      en: "Analyze UEFI Secure Boot and embedded ROM code signing architectures integrating ML-DSA and stateful LMS signatures for immutable firmware roots of trust.\nCompute the first 20 hex characters of SHA256(\"pqcmigrate_code_signing_secure_boot_pqc_v1\").\n\nFormat: `FLAG{SHA256(\"pqcmigrate_code_signing_secure_boot_pqc_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["LMS/XMSS 서명은 빠른 검증 속도와 작은 공개키 크기로 하드웨어 부트로더에 적합합니다.", "식별자 `pqcmigrate_code_signing_secure_boot_pqc_v1`의 해시 앞 20자리를 확인하세요."],
      en: ["Stateful hash signatures (LMS) offer lightweight verification code footprints ideal for early stage ROM boot stages.", "Extract the first 20 hex characters of SHA256(\"pqcmigrate_code_signing_secure_boot_pqc_v1\")."]
    }
  },

  // Tier 3 (8)
  {
    id: "t3_pqcmigrate_grover_aes_sha_bitlength_policy",
    tier: 3, cat: "grover", track: "pqcmigrate", points: 150, ci: false, fmt: "FLAG{...}",
    title: {
      ko: "그로버 알고리즘(Grover's Algorithm) 대응 대칭키 및 해시 비트길이 정책 (AES-256/SHA-384)",
      en: "Symmetric Key & Hash Bit-Length Policy Under Grover's Algorithm (AES-256 & SHA-384)"
    },
    prompt: {
      ko: "그로버 양자 검색 알고리즘이 대칭키 암호(AES)의 유효 키 길이를 절반으로 줄이는 위협에 대응하여 AES-128을 배제하고 AES-256 및 SHA-384+를 의무화하는 정책을 분석합니다.\n지정된 식별자 `pqcmigrate_grover_aes_sha_bitlength_policy_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"pqcmigrate_grover_aes_sha_bitlength_policy_v1\") 앞 20자리}`",
      en: "Evaluate the quadratic speedup of Grover's search algorithm cutting symmetric security in half, mandating 256-bit symmetric keys and 384-bit collision resistance.\nCompute the first 20 hex characters of SHA256(\"pqcmigrate_grover_aes_sha_bitlength_policy_v1\").\n\nFormat: `FLAG{SHA256(\"pqcmigrate_grover_aes_sha_bitlength_policy_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["Grover 알고리즘 하에서 AES-256은 128비트 양자 보안 강도를 제공하므로 장기 기밀성에 안전합니다.", "식별자 `pqcmigrate_grover_aes_sha_bitlength_policy_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["AES-256 delivers 128-bit quantum security under Grover's search, satisfying long-term national security thresholds.", "Extract the first 20 hex characters of SHA256(\"pqcmigrate_grover_aes_sha_bitlength_policy_v1\")."]
    }
  },
  {
    id: "t3_pqcmigrate_pqc_cryptanalytic_break_rollback",
    tier: 3, cat: "rollback", track: "pqcmigrate", points: 150, ci: false, fmt: "FLAG{...}",
    title: {
      ko: "PQC 알고리즘 수학적 결함 발견 시 즉각 롤백을 보장하는 비상 제어 절차",
      en: "Emergency Rollback Protocol for PQC Mathematical Breakages"
    },
    prompt: {
      ko: "SIKE 알고리즘의 급작스러운 수학적 붕괴 사례와 같이 특정 PQC 알고리즘에 치명적 결함이 발견되었을 때 트래픽 중단 없이 알고리즘을 격리하고 롤백하는 절차를 분석합니다.\n지정된 식별자 `pqcmigrate_pqc_cryptanalytic_break_rollback_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"pqcmigrate_pqc_cryptanalytic_break_rollback_v1\") 앞 20자리}`",
      en: "Develop an automated emergency rollback pipeline that decouples and isolates compromised PQC primitives (analogous to the SIKE break) without service interruption.\nCompute the first 20 hex characters of SHA256(\"pqcmigrate_pqc_cryptanalytic_break_rollback_v1\").\n\nFormat: `FLAG{SHA256(\"pqcmigrate_pqc_cryptanalytic_break_rollback_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["하이브리드 암호화 구조를 유지하면 단일 PQC 알고리즘의 결함 시에도 고전 계층이 즉각적인 공격을 방어합니다.", "식별자 `pqcmigrate_pqc_cryptanalytic_break_rollback_v1`의 해시 앞 20자리를 확인하세요."],
      en: ["Maintaining hybrid mode provides fail-safe protection: if the lattice primitive is broken, classical hardness still defends against classical attacks.", "Extract the first 20 hex characters of SHA256(\"pqcmigrate_pqc_cryptanalytic_break_rollback_v1\")."]
    }
  },
  {
    id: "t3_pqcmigrate_zero_knowledge_stark_pqc",
    tier: 3, cat: "zk", track: "pqcmigrate", points: 150, ci: false, fmt: "FLAG{...}",
    title: {
      ko: "영지식 증명(ZK-STARK)의 양자 내성 특성과 암호학적 신뢰 설정",
      en: "Post-Quantum Security Properties & Transparent Setup of ZK-STARKs"
    },
    prompt: {
      ko: "타원곡선 페어링에 의존하는 SNARK와 달리 충돌 저항 해시 함수에만 의존하여 양자 내성을 갖는 ZK-STARK의 투명한 신뢰 설정(Transparent Setup)을 분석합니다.\n지정된 식별자 `pqcmigrate_zero_knowledge_stark_pqc_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"pqcmigrate_zero_knowledge_stark_pqc_v1\") 앞 20자리}`",
      en: "Analyze the post-quantum hardness of ZK-STARKs relying solely on collision-resistant hash functions without elliptic-curve trusted setups.\nCompute the first 20 hex characters of SHA256(\"pqcmigrate_zero_knowledge_stark_pqc_v1\").\n\nFormat: `FLAG{SHA256(\"pqcmigrate_zero_knowledge_stark_pqc_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["STARK는 FRI(Fast Reed-Solomon IOP of Proximity) 프로토콜을 사용하여 다항식 차수를 검증합니다.", "식별자 `pqcmigrate_zero_knowledge_stark_pqc_v1`의 해시 앞 20자리를 계산하세요."],
      en: ["STARKs use the FRI protocol to verify low-degree polynomial proximity purely via hash trees.", "Extract the first 20 hex characters of SHA256(\"pqcmigrate_zero_knowledge_stark_pqc_v1\")."]
    }
  },
  {
    id: "t3_pqcmigrate_tls13_pq_sni_esni_ech_protection",
    tier: 3, cat: "ech", track: "pqcmigrate", points: 150, ci: false, fmt: "FLAG{...}",
    title: {
      ko: "ECH(Encrypted Client Hello)와 PQC 결합을 통한 메타데이터 도청 차단",
      en: "Combining Encrypted Client Hello (ECH) & PQC Against Metadata Snooping"
    },
    prompt: {
      ko: "평문으로 노출되는 SNI(서버 이름 표시)를 클라이언트 헬로 암호화(ECH)와 PQC HPKE(ML-KEM)로 암호화하여 양자 도청자로부터 도메인 메타데이터를 은닉하는 기술을 분석합니다.\n지정된 식별자 `pqcmigrate_tls13_pq_sni_esni_ech_protection_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"pqcmigrate_tls13_pq_sni_esni_ech_protection_v1\") 앞 20자리}`",
      en: "Examine Encrypted Client Hello (ECH) combined with Post-Quantum HPKE configurations preventing eavesdroppers from harvesting target SNI metadata.\nCompute the first 20 hex characters of SHA256(\"pqcmigrate_tls13_pq_sni_esni_ech_protection_v1\").\n\nFormat: `FLAG{SHA256(\"pqcmigrate_tls13_pq_sni_esni_ech_protection_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["ECH는 ClientHelloOuter와 암호화된 ClientHelloInner 구조로 분리되어 미들박스 감청을 차단합니다.", "식별자 `pqcmigrate_tls13_pq_sni_esni_ech_protection_v1`의 해시 앞 20자리를 확인하세요."],
      en: ["ECH wraps inner encrypted handshake records inside outer public facades, shielding destination hostnames.", "Extract the first 20 hex characters of SHA256(\"pqcmigrate_tls13_pq_sni_esni_ech_protection_v1\")."]
    }
  },
  {
    id: "t3_pqcmigrate_pqc_canbus_v2x_latency_budget",
    tier: 3, cat: "v2x", track: "pqcmigrate", points: 150, ci: false, fmt: "FLAG{...}",
    title: {
      ko: "차량 CAN Bus 및 V2X 통신 환경의 PQC 서명 지연시간 한도(Latency Budget) 준수",
      en: "Automotive CAN Bus & V2X Latency Budget Enforcement with PQC Signatures"
    },
    prompt: {
      ko: "수십 밀리초(ms) 단위의 엄격한 지연시간 한도를 갖는 커넥티드 카 V2X 안전 메시지(CAM/BSM)에서 대형 PQC 전자서명을 효율적으로 처리하는 가속 및 배치 검증을 분석합니다.\n지정된 식별자 `pqcmigrate_pqc_canbus_v2x_latency_budget_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"pqcmigrate_pqc_canbus_v2x_latency_budget_v1\") 앞 20자리}`",
      en: "Analyze low-latency hardware acceleration and batch verification of PQC signatures within strict 20ms V2X automotive communication deadlines.\nCompute the first 20 hex characters of SHA256(\"pqcmigrate_pqc_canbus_v2x_latency_budget_v1\").\n\nFormat: `FLAG{SHA256(\"pqcmigrate_pqc_canbus_v2x_latency_budget_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["차량용 HSM의 하드웨어 가속기(Crypto Engine)와 서명 집약 기법이 CAN/CAN-FD 대역폭 병목을 완화합니다.", "식별자 `pqcmigrate_pqc_canbus_v2x_latency_budget_v1`의 해시 앞 20자리를 확인하세요."],
      en: ["Hardware-assisted NTT accelerators and batch signature verification pipelines prevent bus latency violations.", "Extract the first 20 hex characters of SHA256(\"pqcmigrate_pqc_canbus_v2x_latency_budget_v1\")."]
    }
  },
  {
    id: "t3_pqcmigrate_crypto_asset_inventory_cbom",
    tier: 3, cat: "cbom", track: "pqcmigrate", points: 150, ci: false, fmt: "FLAG{...}",
    title: {
      ko: "CBOM(Cryptography Bill of Materials) 기반 전사 암호 자산 인벤토리 자동화",
      en: "Enterprise Cryptography Bill of Materials (CBOM) & Asset Discovery Automation"
    },
    prompt: {
      ko: "엔터프라이즈 코드베이스, 바이너리, 네트워크 트래픽에서 취약한 레거시 암호 알고리즘과 인증서를 스캔하여 CycloneDX CBOM 표준 형식으로 시각화하는 파이프라인을 분석합니다.\n지정된 식별자 `pqcmigrate_crypto_asset_inventory_cbom_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"pqcmigrate_crypto_asset_inventory_cbom_v1\") 앞 20자리}`",
      en: "Examine automated Cryptography Bill of Materials (CBOM) discovery pipelines cataloging legacy algorithms across enterprise git repos and runtime TLS endpoints.\nCompute the first 20 hex characters of SHA256(\"pqcmigrate_crypto_asset_inventory_cbom_v1\").\n\nFormat: `FLAG{SHA256(\"pqcmigrate_crypto_asset_inventory_cbom_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["CBOM은 취약 알고리즘의 호출 지점과 인증서 만료일, 양자 취약성 지표를 구조화된 JSON으로 생성합니다.", "식별자 `pqcmigrate_crypto_asset_inventory_cbom_v1`의 해시 앞 20자리를 계산하세요."],
      en: ["CBOM specifications standardize the discovery of quantum-vulnerable cryptographic primitives across applications.", "Extract the first 20 hex characters of SHA256(\"pqcmigrate_crypto_asset_inventory_cbom_v1\")."]
    }
  },
  {
    id: "t3_pqcmigrate_nist_sp800_208_stateful_hash_signatures",
    tier: 3, cat: "sp800_208", track: "pqcmigrate", points: 150, ci: false, fmt: "FLAG{...}",
    title: {
      ko: "NIST SP 800-208 상태 보존형 해시 전자서명(LMS/XMSS) 서명 고갈 방어",
      en: "NIST SP 800-208 Stateful Hash-Based Signatures (LMS/XMSS) State Exhaustion Defense"
    },
    prompt: {
      ko: "개인키 상태(State)가 중복 사용될 경우 서명 키가 완전히 유출되는 상태 보존형 서명의 치명적 결함을 방지하기 위해 비휘발성 카운터와 원자적(Atomic) 트랜잭션을 적용하는 기법을 분석합니다.\n지정된 식별자 `pqcmigrate_nist_sp800_208_stateful_hash_signatures_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"pqcmigrate_nist_sp800_208_stateful_hash_signatures_v1\") 앞 20자리}`",
      en: "Analyze state management mechanisms in NIST SP 800-208 stateful hash signatures preventing catastrophic key re-use through secure non-volatile monotonic counters.\nCompute the first 20 hex characters of SHA256(\"pqcmigrate_nist_sp800_208_stateful_hash_signatures_v1\").\n\nFormat: `FLAG{SHA256(\"pqcmigrate_nist_sp800_208_stateful_hash_signatures_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["동일한 리프 인덱스로 두 번 서명하면 공격자가 사설 오츠 서명 키를 즉시 복구할 수 있습니다.", "식별자 `pqcmigrate_nist_sp800_208_stateful_hash_signatures_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Reusing a single OTS key index completely breaks the signature security, demanding hardware monotonic enforcement.", "Extract the first 20 hex characters of SHA256(\"pqcmigrate_nist_sp800_208_stateful_hash_signatures_v1\")."]
    }
  },
  {
    id: "t3_pqcmigrate_quantum_random_number_generator_qrng",
    tier: 3, cat: "qrng", track: "pqcmigrate", points: 150, ci: false, fmt: "FLAG{...}",
    title: {
      ko: "양자 난수 발생기(QRNG) 엔트로피 풀 통합 및 PQC 키 생성 무결성",
      en: "Quantum Random Number Generator (QRNG) Entropy Pool Integration for PQC Keys"
    },
    prompt: {
      ko: "광자의 양자 위상 요동 및 양자 터널링 잡음을 엔트로피 소스로 수집하여 Linux 커널 `/dev/urandom` 및 PQC 키 생성 시드의 예측 불가능성을 극대화하는 QRNG 아키텍처를 분석합니다.\n지정된 식별자 `pqcmigrate_quantum_random_number_generator_qrng_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"pqcmigrate_quantum_random_number_generator_qrng_v1\") 앞 20자리}`",
      en: "Examine Quantum Random Number Generator (QRNG) physical photon phase entropy feeding kernel random pools to ensure quantum-safe seed randomness.\nCompute the first 20 hex characters of SHA256(\"pqcmigrate_quantum_random_number_generator_qrng_v1\").\n\nFormat: `FLAG{SHA256(\"pqcmigrate_quantum_random_number_generator_qrng_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["진정한 양자 엔트로피는 알고리즘적 유사 난수 생성기(PRNG)의 주기성 위험을 근본적으로 제거합니다.", "식별자 `pqcmigrate_quantum_random_number_generator_qrng_v1`의 해시 앞 20자리를 확인하세요."],
      en: ["QRNG hardware provides unconditioned quantum entropy protecting seed freshness against predictability flaws.", "Extract the first 20 hex characters of SHA256(\"pqcmigrate_quantum_random_number_generator_qrng_v1\")."]
    }
  },

  // Tier 4 (5)
  {
    id: "t4_pqcmigrate_enterprise_sndl_interception_triage",
    tier: 4, cat: "incident", track: "pqcmigrate", points: 250, ci: false, fmt: "FLAG{...}",
    title: {
      ko: "국가 단위 지속 위협(APT)의 SNDL 도청 트래픽 탐지 및 PQC 긴급 차단 대응",
      en: "Nation-State SNDL Interception Triage & Emergency PQC Enforcement"
    },
    prompt: {
      ko: "해저 케이블 및 백본 ISP 회선에서 패시브 탭핑 장비로 암호화 트래픽을 장기 수집하는 이상 징후를 탐지하고, 전사 대외 채널에 ML-KEM-768을 강제 활성화하는 침해대응 시나리오를 분석합니다.\n지정된 식별자 `pqcmigrate_enterprise_sndl_interception_triage_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"pqcmigrate_enterprise_sndl_interception_triage_v1\") 앞 20자리}`",
      en: "Triage a nation-state SNDL interception campaign operating on backbone routing paths and execute emergency ML-KEM-768 hybrid enforcement across external ingress points.\nCompute the first 20 hex characters of SHA256(\"pqcmigrate_enterprise_sndl_interception_triage_v1\").\n\nFormat: `FLAG{SHA256(\"pqcmigrate_enterprise_sndl_interception_triage_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["SNDL 공격은 수동적이므로 대외 트래픽의 암호화 스펙을 즉시 양자 내성 모드로 강제 격상하는 선제 차단이 유일한 방어입니다.", "식별자 `pqcmigrate_enterprise_sndl_interception_triage_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Passive wiretapping leaves no active telemetry; proactive hybrid PQC key exchange rollout is the decisive defense.", "Extract the first 20 hex characters of SHA256(\"pqcmigrate_enterprise_sndl_interception_triage_v1\")."]
    }
  },
  {
    id: "t4_pqcmigrate_fips203_lattice_kem_decapsulation_validation",
    tier: 4, cat: "validation", track: "pqcmigrate", points: 250, ci: false, fmt: "FLAG{...}",
    title: {
      ko: "FIPS 203 ML-KEM-768 역캡슐화(Decapsulation) 무결성 및 암호문 조작 공격 방어",
      en: "FIPS 203 ML-KEM-768 Decapsulation Integrity & Ciphertext Tampering Defense"
    },
    prompt: {
      ko: "공격자가 조작된 격자 암호문을 전송하여 역캡슐화 과정의 암호문 유효성 검사 누락을 유도하는 공격을 상대로, FIPS 203 표준의 상수 시간 implicit rejection 검증을 수행하는 방어 로직을 분석합니다.\n지정된 식별자 `pqcmigrate_fips203_lattice_kem_decapsulation_validation_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"pqcmigrate_fips203_lattice_kem_decapsulation_validation_v1\") 앞 20자리}`",
      en: "Analyze implicit rejection verification in FIPS 203 ML-KEM-768 decapsulation preventing chosen-ciphertext attacks attempting to exploit invalid ciphertext error oracles.\nCompute the first 20 hex characters of SHA256(\"pqcmigrate_fips203_lattice_kem_decapsulation_validation_v1\").\n\nFormat: `FLAG{SHA256(\"pqcmigrate_fips203_lattice_kem_decapsulation_validation_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["암호문 불일치 시 에러를 반환하지 않고 의사 난수 키를 도출하여 공격자에게 오라클 피드백을 제공하지 않습니다.", "식별자 `pqcmigrate_fips203_lattice_kem_decapsulation_validation_v1`의 해시 앞 20자리를 계산하세요."],
      en: ["Implicit rejection outputs a pseudorandom secret on validation failure, neutralizing adaptive ciphertext oracle probes.", "Extract the first 20 hex characters of SHA256(\"pqcmigrate_fips203_lattice_kem_decapsulation_validation_v1\")."]
    }
  },
  {
    id: "t4_pqcmigrate_hybrid_tls_middlebox_downgrade_mitigation",
    tier: 4, cat: "mitm", track: "pqcmigrate", points: 250, ci: false, fmt: "FLAG{...}",
    title: {
      ko: "엔터프라이즈 미들박스/WAF의 PQC 핸드셰이크 강제 다운그레이드 탐지 및 차단",
      en: "Enterprise Middlebox/WAF PQC Handshake Forced Downgrade Interception"
    },
    prompt: {
      ko: "레거시 SSL 복호화 인스펙터나 악성 프록시가 PQC ClientHello를 고의로 거부하거나 고전 암호로 다운그레이드를 유도할 때 이를 실시간 탐지하고 차단하는 보안 게이트웨이 정책을 분석합니다.\n지정된 식별자 `pqcmigrate_hybrid_tls_middlebox_downgrade_mitigation_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"pqcmigrate_hybrid_tls_middlebox_downgrade_mitigation_v1\") 앞 20자리}`",
      en: "Design security gateway controls intercepting and blocking middleboxes attempting forced fallback from hybrid PQC suites to legacy classical cipher groups.\nCompute the first 20 hex characters of SHA256(\"pqcmigrate_hybrid_tls_middlebox_downgrade_mitigation_v1\").\n\nFormat: `FLAG{SHA256(\"pqcmigrate_hybrid_tls_middlebox_downgrade_mitigation_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["최소 보안 암호 스위트 정책(Minimum Cipher Policy)을 통해 비PQC 연결 시도를 강제 드롭합니다.", "식별자 `pqcmigrate_hybrid_tls_middlebox_downgrade_mitigation_v1`의 해시 앞 20자리를 확인하세요."],
      en: ["Enforcing hard strict-quantum cipher policies prevents involuntary fallback on rogue intermediate proxies.", "Extract the first 20 hex characters of SHA256(\"pqcmigrate_hybrid_tls_middlebox_downgrade_mitigation_v1\")."]
    }
  },
  {
    id: "t4_pqcmigrate_full_lifecycle_cbom_compliance_audit",
    tier: 4, cat: "compliance", track: "pqcmigrate", points: 250, ci: false, fmt: "FLAG{...}",
    title: {
      ko: "전사 암호 자산 수명주기 감사 및 NIST CSF 2.0 / KISA ISMS-P PQC 마이그레이션 규정 준수",
      en: "Full-Lifecycle CBOM Audit & NIST CSF 2.0 / KISA ISMS-P PQC Regulatory Compliance"
    },
    prompt: {
      ko: "엔터프라이즈 전반의 키 저장소, DB 컬럼 암호화, API 게이트웨이의 PQC 규정 준수 상태를 감사하고 KISA ISMS-P 및 NIST PQC 로드맵 이행 증적을 생성하는 파이프라인을 분석합니다.\n지정된 식별자 `pqcmigrate_full_lifecycle_cbom_compliance_audit_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"pqcmigrate_full_lifecycle_cbom_compliance_audit_v1\") 앞 20자리}`",
      en: "Audit enterprise-wide cryptographic asset compliance against NIST Post-Quantum Transition Guidelines and KISA ISMS-P controls.\nCompute the first 20 hex characters of SHA256(\"pqcmigrate_full_lifecycle_cbom_compliance_audit_v1\").\n\nFormat: `FLAG{SHA256(\"pqcmigrate_full_lifecycle_cbom_compliance_audit_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["CBOM 자산 명세서와 자동화된 스캐너 감사 로그가 규제 기관 제출용 PQC 마이그레이션 증적으로 활용됩니다.", "식별자 `pqcmigrate_full_lifecycle_cbom_compliance_audit_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Continuous automated CBOM audits provide compliance attestations for governance regulators.", "Extract the first 20 hex characters of SHA256(\"pqcmigrate_full_lifecycle_cbom_compliance_audit_v1\")."]
    }
  },
  {
    id: "t4_pqcmigrate_capstone_quantum_resilient_zero_trust",
    tier: 4, cat: "capstone", track: "pqcmigrate", points: 250, ci: false, fmt: "FLAG{...}",
    title: {
      ko: "캡스톤: 양자 내성 제로 트러스트(Quantum-Resilient Zero Trust) 전사 아키텍처",
      en: "Capstone: Enterprise Quantum-Resilient Zero Trust Defense Architecture"
    },
    prompt: {
      ko: "ID 발급(ML-DSA), 서비스 메시 상호 mTLS(X25519Kyber768), 데이터베이스 TDE(AES-256), 그리고 암호 민첩성 핫스왑까지 통합된 완전한 양자 내성 제로 트러스트 아키텍처를 설계·검증합니다.\n지정된 식별자 `pqcmigrate_capstone_quantum_resilient_zero_trust_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"pqcmigrate_capstone_quantum_resilient_zero_trust_v1\") 앞 20자리}`",
      en: "Design and validate a complete end-to-end Quantum-Resilient Zero Trust architecture integrating ML-DSA identity attestations, hybrid mTLS mesh, and crypto-agile KMS.\nCompute the first 20 hex characters of SHA256(\"pqcmigrate_capstone_quantum_resilient_zero_trust_v1\").\n\nFormat: `FLAG{SHA256(\"pqcmigrate_capstone_quantum_resilient_zero_trust_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["모든 통신 계층과 저장 계층이 PQC 알고리즘과 심층 방어 모델로 결합되어 미래 양자 위협을 완벽히 무력화합니다.", "식별자 `pqcmigrate_capstone_quantum_resilient_zero_trust_v1`의 해시 앞 20자리를 계산하세요."],
      en: ["Synthesizing hybrid KEMs, lattice signatures, and agile providers forms the apex of modern enterprise cryptography.", "Extract the first 20 hex characters of SHA256(\"pqcmigrate_capstone_quantum_resilient_zero_trust_v1\")."]
    }
  }
];

// Add computed hash to each challenge
const processedChallenges = challengesDef.map(ch => {
  return {
    ...ch,
    hash: computeHash(ch.id)
  };
});

// Output JSON file
const outPath = path.join(__dirname, 'track67_challenges.json');
fs.writeFileSync(outPath, JSON.stringify(processedChallenges, null, 2), 'utf8');
console.log(`Generated ${processedChallenges.length} challenges for Track 67 (pqcmigrate) at ${outPath}`);
