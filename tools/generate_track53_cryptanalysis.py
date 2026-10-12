#!/usr/bin/env python3
"""
Generates the 53rd Wargame Track: 'cryptanalysis' (Modern Cryptanalysis & PQC - 35 Challenges)
Integrates cleanly into challenges.js, index.html, app.js, solve-derivable.js, and README.md.
"""

import hashlib
import json
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
CHALLENGES_JS = REPO_ROOT / "wargame" / "assets" / "challenges.js"
INDEX_HTML = REPO_ROOT / "wargame" / "index.html"
APP_JS = REPO_ROOT / "wargame" / "assets" / "app.js"
SOLVE_DERIVABLE_JS = REPO_ROOT / "wargame" / "scripts" / "solve-derivable.js"
WARGAME_README = REPO_ROOT / "wargame" / "README.md"

TRACK_INFO = {
    "id": "cryptanalysis",
    "icon": "🔐",
    "ko": "현대 응용 암호학 & 암호 분석",
    "en": "Modern Cryptanalysis & PQC",
    "desc_ko": "AES-CBC 패딩 오라클·IV 비트 플리핑·RSA Bleichenbacher '06 e=3 서명 위조·ECDSA 난수 재사용 개인키 역산·ML-KEM-768 포스트 퀀텀 하이브리드 방어.",
    "desc_en": "AES-CBC padding oracle, IV bit-flipping, RSA Bleichenbacher '06 e=3 forgery, ECDSA nonce reuse private key carving, and ML-KEM-768 hybrid PQC defense."
}

RAW_CHALLENGES = [
    # Tier 0 (2 challenges, 25 points)
    (0, "t0_cryptanalysis_kerckhoffs_principle", 25, "oracle",
     "케르크호프스의 원리 및 개방형 암호 설계",
     "Kerckhoffs's Principle and Open Cryptographic Design",
     "암호 시스템의 안전성은 키의 비밀성에만 의존해야 하며 알고리즘은 공개되어야 한다는 케르크호프스의 원리를 분석합니다.\n지정된 식별자 `cryptanalysis_kerckhoffs_principle_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"cryptanalysis_kerckhoffs_principle_v1\") 앞 20자리}`",
     "Analyze Kerckhoffs's principle stating cryptographic security must rely strictly on key secrecy while algorithms remain public.\nCompute the first 20 hex characters of SHA256(\"cryptanalysis_kerckhoffs_principle_v1\").\n\nFormat: `FLAG{SHA256(\"cryptanalysis_kerckhoffs_principle_v1\") first 20 hex}`",
     ["알고리즘 공개와 비밀키 분리 원칙을 확인하세요.", "식별자 `cryptanalysis_kerckhoffs_principle_v1`의 해시 앞 20자리를 추출하세요."],
     ["Review open algorithm specification and key isolation.", "Extract first 20 hex chars of SHA256(\"cryptanalysis_kerckhoffs_principle_v1\")."],
     "cryptanalysis_kerckhoffs_principle_v1"),

    (0, "t0_cryptanalysis_block_cipher_modes", 25, "oracle",
     "블록 암호화 운용 모드 및 ECB의 취약성",
     "Block Cipher Operational Modes and ECB Deterministic Hazards",
     "전자 부호표(ECB) 모드가 동일한 평문 블록을 동일한 암호문으로 변환하여 패턴(Tux 펭귄)을 노출하는 구조적 취약점을 분석합니다.\n지정된 식별자 `cryptanalysis_block_cipher_modes_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"cryptanalysis_block_cipher_modes_v1\") 앞 20자리}`",
     "Examine how Electronic Codebook (ECB) leaks plaintext visual patterns and why non-deterministic chaining modes are required.\nCompute the first 20 hex characters of SHA256(\"cryptanalysis_block_cipher_modes_v1\").\n\nFormat: `FLAG{SHA256(\"cryptanalysis_block_cipher_modes_v1\") first 20 hex}`",
     ["ECB 모드의 결정론적 블록 변환 문제를 검토하세요.", "식별자 `cryptanalysis_block_cipher_modes_v1`의 해시 앞 20자리를 추출하세요."],
     ["Analyze deterministic cipher mapping in ECB mode.", "Extract first 20 hex chars of SHA256(\"cryptanalysis_block_cipher_modes_v1\")."],
     "cryptanalysis_block_cipher_modes_v1"),

    # Tier 1 (6 challenges, 50 points)
    (1, "t1_cryptanalysis_aes_sbox_nonlinearity", 50, "oracle",
     "AES Rijndael S-Box 비선형 치환 계층 분석",
     "AES Rijndael S-Box Non-Linear Substitution Layer",
     "유한체 GF(2^8) 상의 곱셈 역원 및 아핀 변환을 통해 차분 및 선형 암호해독 공격을 방어하는 AES S-Box 구조를 분석합니다.\n지정된 식별자 `cryptanalysis_aes_sbox_nonlinearity_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"cryptanalysis_aes_sbox_nonlinearity_v1\") 앞 20자리}`",
     "Analyze non-linear substitution over Galois Field GF(2^8) and affine transformations resisting differential cryptanalysis in AES.\nCompute the first 20 hex characters of SHA256(\"cryptanalysis_aes_sbox_nonlinearity_v1\").\n\nFormat: `FLAG{SHA256(\"cryptanalysis_aes_sbox_nonlinearity_v1\") first 20 hex}`",
     ["GF(2^8) 상의 대수적 치환 박스 구조를 검토하세요.", "식별자 `cryptanalysis_aes_sbox_nonlinearity_v1`의 해시 앞 20자리를 추출하세요."],
     ["Review algebraic S-Box inversion and affine steps.", "Extract first 20 hex chars of SHA256(\"cryptanalysis_aes_sbox_nonlinearity_v1\")."],
     "cryptanalysis_aes_sbox_nonlinearity_v1"),

    (1, "t1_cryptanalysis_pkcs7_padding_validation", 50, "oracle",
     "PKCS#7 블록 패딩 규격 및 무결성 검증",
     "PKCS#7 Block Padding Specification and Boundary Checks",
     "16바이트 블록 암호화에서 마지막 블록에 채워지는 0x01~0x10 바이트 규격과 검증 함수의 경계값 처리를 분석합니다.\n지정된 식별자 `cryptanalysis_pkcs7_padding_validation_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"cryptanalysis_pkcs7_padding_validation_v1\") 앞 20자리}`",
     "Examine PKCS#7 padding validation where values 0x01 through 0x10 pad incomplete 16-byte blocks.\nCompute the first 20 hex characters of SHA256(\"cryptanalysis_pkcs7_padding_validation_v1\").\n\nFormat: `FLAG{SHA256(\"cryptanalysis_pkcs7_padding_validation_v1\") first 20 hex}`",
     ["PKCS#7 패딩의 유효성 검사 경계 조건을 확인하세요.", "식별자 `cryptanalysis_pkcs7_padding_validation_v1`의 해시 앞 20자리를 추출하세요."],
     ["Inspect boundary byte validation rules in PKCS#7.", "Extract first 20 hex chars of SHA256(\"cryptanalysis_pkcs7_padding_validation_v1\")."],
     "cryptanalysis_pkcs7_padding_validation_v1"),

    (1, "t1_cryptanalysis_length_extension_attack", 50, "oracle",
     "Merkle-Damgard 해시 길이 확장 공격 (Hash Length Extension)",
     "Merkle-Damgard Construction & Hash Length Extension Exploitation",
     "MD5, SHA-1, SHA-256의 순차 압축 함수 상태 노출로 인해 비밀 키를 몰라도 접미 데이터를 추가하고 서명을 재구성하는 공격을 분석합니다.\n지정된 식별자 `cryptanalysis_length_extension_attack_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"cryptanalysis_length_extension_attack_v1\") 앞 20자리}`",
     "Investigate how internal state leakage in Merkle-Damgard hash functions enables forging message signatures with appended data.\nCompute the first 20 hex characters of SHA256(\"cryptanalysis_length_extension_attack_v1\").\n\nFormat: `FLAG{SHA256(\"cryptanalysis_length_extension_attack_v1\") first 20 hex}`",
     ["Merkle-Damgard 내부 상태 H0~H7 복원 메커니즘을 확인하세요.", "식별자 `cryptanalysis_length_extension_attack_v1`의 해시 앞 20자리를 추출하세요."],
     ["Examine compression state preservation in Merkle-Damgard hashes.", "Extract first 20 hex chars of SHA256(\"cryptanalysis_length_extension_attack_v1\")."],
     "cryptanalysis_length_extension_attack_v1"),

    (1, "t1_cryptanalysis_hash_collision_birthday", 50, "oracle",
     "생일 역설(Birthday Paradox)과 해시 충돌 복잡도",
     "Birthday Paradox and Hash Collision Search Complexity",
     "n비트 해시 함수에서 충돌 쌍(Collision)을 발견하는 데 필요한 무작위 대입 횟수가 2^(n/2)로 축소되는 원리를 분석합니다.\n지정된 식별자 `cryptanalysis_hash_collision_birthday_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"cryptanalysis_hash_collision_birthday_v1\") 앞 20자리}`",
     "Analyze how the Birthday problem reduces hash collision search space from O(2^n) to O(2^(n/2)).\nCompute the first 20 hex characters of SHA256(\"cryptanalysis_hash_collision_birthday_v1\").\n\nFormat: `FLAG{SHA256(\"cryptanalysis_hash_collision_birthday_v1\") first 20 hex}`",
     ["생일 역설에 따른 제곱근 복잡도를 검토하세요.", "식별자 `cryptanalysis_hash_collision_birthday_v1`의 해시 앞 20자리를 추출하세요."],
     ["Review square-root complexity bounds from the birthday problem.", "Extract first 20 hex chars of SHA256(\"cryptanalysis_hash_collision_birthday_v1\")."],
     "cryptanalysis_hash_collision_birthday_v1"),

    (1, "t1_cryptanalysis_stream_cipher_keystream_reuse", 50, "oracle",
     "스트림 암호 키스트림 재사용 (Two-Time Pad) 취약점",
     "Stream Cipher Keystream Reuse & Two-Time Pad Cryptanalysis",
     "동일한 Nonce와 키로 스트림 암호(RC4, ChaCha20, AES-CTR)를 두 번 암호화할 때 C1 XOR C2 = P1 XOR P2가 되어 평문이 노출되는 원리를 분석합니다.\n지정된 식별자 `cryptanalysis_stream_cipher_keystream_reuse_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"cryptanalysis_stream_cipher_keystream_reuse_v1\") 앞 20자리}`",
     "Analyze keystream cancellation when identical nonces encrypt distinct plaintexts enabling frequency analysis on P1 XOR P2.\nCompute the first 20 hex characters of SHA256(\"cryptanalysis_stream_cipher_keystream_reuse_v1\").\n\nFormat: `FLAG{SHA256(\"cryptanalysis_stream_cipher_keystream_reuse_v1\") first 20 hex}`",
     ["C1 XOR C2에서 키스트림이 상쇄되는 수식을 확인하세요.", "식별자 `cryptanalysis_stream_cipher_keystream_reuse_v1`의 해시 앞 20자리를 추출하세요."],
     ["Verify keystream cancellation where C1 XOR C2 equals P1 XOR P2.", "Extract first 20 hex chars of SHA256(\"cryptanalysis_stream_cipher_keystream_reuse_v1\")."],
     "cryptanalysis_stream_cipher_keystream_reuse_v1"),

    (1, "t1_cryptanalysis_timing_attack_constant_time", 50, "oracle",
     "부채널 타이밍 공격과 상수 시간(Constant-Time) 비교",
     "Side-Channel Timing Attacks and Constant-Time Comparison",
     "문자열/바이트 단위 조기 종료(Early Exit) 비교 함수가 서명 및 HMAC을 1바이트씩 누출시키는 취약점과 `hmac.compare_digest` 하드닝을 분석합니다.\n지정된 식별자 `cryptanalysis_timing_attack_constant_time_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"cryptanalysis_timing_attack_constant_time_v1\") 앞 20자리}`",
     "Examine timing leakage from early-terminating memory comparisons and the cryptographic necessity of constant-time primitives.\nCompute the first 20 hex characters of SHA256(\"cryptanalysis_timing_attack_constant_time_v1\").\n\nFormat: `FLAG{SHA256(\"cryptanalysis_timing_attack_constant_time_v1\") first 20 hex}`",
     ["조기 반환(Early return)과 비트별 상수 시간 연산 차이를 확인하세요.", "식별자 `cryptanalysis_timing_attack_constant_time_v1`의 해시 앞 20자리를 추출하세요."],
     ["Distinguish variable-time memcmp from constant-time byte comparisons.", "Extract first 20 hex chars of SHA256(\"cryptanalysis_timing_attack_constant_time_v1\")."],
     "cryptanalysis_timing_attack_constant_time_v1"),

    # Tier 2 (8 challenges, 80 points)
    (2, "t2_cryptanalysis_rsa_euler_totient", 80, "asymmetric",
     "RSA 키 생성 및 오일러 피 함수 phi(N) 관계",
     "RSA Key Generation & Euler Totient Inversion",
     "두 거대 소수 p, q에 대해 모듈러스 N=pq와 오일러 피 함수 phi(N)=(p-1)(q-1), ed = 1 mod phi(N) 개인 지수 유도 과정을 분석합니다.\n지정된 식별자 `cryptanalysis_rsa_euler_totient_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"cryptanalysis_rsa_euler_totient_v1\") 앞 20자리}`",
     "Audit RSA mathematical foundations: modulus N=pq, totient phi(N)=(p-1)(q-1), and modular inverse d = e^(-1) mod phi(N).\nCompute the first 20 hex characters of SHA256(\"cryptanalysis_rsa_euler_totient_v1\").\n\nFormat: `FLAG{SHA256(\"cryptanalysis_rsa_euler_totient_v1\") first 20 hex}`",
     ["오일러 피 함수와 확장 유클리드 호제법의 관계를 검토하세요.", "식별자 `cryptanalysis_rsa_euler_totient_v1`의 해시 앞 20자리를 추출하세요."],
     ["Review the extended Euclidean algorithm for modular inverse d.", "Extract first 20 hex chars of SHA256(\"cryptanalysis_rsa_euler_totient_v1\")."],
     "cryptanalysis_rsa_euler_totient_v1"),

    (2, "t2_cryptanalysis_diffie_hellman_mitm", 80, "asymmetric",
     "디피-헬만(Diffie-Hellman) 키 교환 및 MITM 중간자 공격",
     "Diffie-Hellman Key Exchange and Man-in-the-Middle Vulnerability",
     "비인증 디피-헬만 프로토콜에서 공격자가 Alice와 Bob 사이에 개입하여 각각 독립적인 공유 비밀을 수립하고 도청하는 공격을 분석합니다.\n지정된 식별자 `cryptanalysis_diffie_hellman_mitm_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"cryptanalysis_diffie_hellman_mitm_v1\") 앞 20자리}`",
     "Analyze man-in-the-middle interception against unauthenticated Diffie-Hellman key exchanges and mutual authentication mitigations.\nCompute the first 20 hex characters of SHA256(\"cryptanalysis_diffie_hellman_mitm_v1\").\n\nFormat: `FLAG{SHA256(\"cryptanalysis_diffie_hellman_mitm_v1\") first 20 hex}`",
     ["디피-헬만 공개키 교환 시 서명 기반 상호 인증의 필요성을 확인하세요.", "식별자 `cryptanalysis_diffie_hellman_mitm_v1`의 해시 앞 20자리를 추출하세요."],
     ["Verify signature-based identity binding in DH key agreements.", "Extract first 20 hex chars of SHA256(\"cryptanalysis_diffie_hellman_mitm_v1\")."],
     "cryptanalysis_diffie_hellman_mitm_v1"),

    (2, "t2_cryptanalysis_rsa_wiener_small_exponent", 80, "asymmetric",
     "위너(Wiener) 공격을 통한 작은 개인 지수 d 복원",
     "Wiener's Attack on Small Private Exponent RSA",
     "개인 지수 d < (1/3) * N^(1/4) 일 때 연분수(Continued Fraction) 전개를 통해 e/N의 점근 분수로 d를 복원하는 위너 공격을 분석합니다.\n지정된 식별자 `cryptanalysis_rsa_wiener_small_exponent_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"cryptanalysis_rsa_wiener_small_exponent_v1\") 앞 20자리}`",
     "Investigate Wiener's continued fraction expansion recovering private exponent d when d is smaller than (1/3) * N^(1/4).\nCompute the first 20 hex characters of SHA256(\"cryptanalysis_rsa_wiener_small_exponent_v1\").\n\nFormat: `FLAG{SHA256(\"cryptanalysis_rsa_wiener_small_exponent_v1\") first 20 hex}`",
     ["e/N의 연분수 전개와 점근 분수(Convergents) 계산을 확인하세요.", "식별자 `cryptanalysis_rsa_wiener_small_exponent_v1`의 해시 앞 20자리를 추출하세요."],
     ["Examine continued fraction convergents of e/N in Wiener's theorem.", "Extract first 20 hex chars of SHA256(\"cryptanalysis_rsa_wiener_small_exponent_v1\")."],
     "cryptanalysis_rsa_wiener_small_exponent_v1"),

    (2, "t2_cryptanalysis_fermat_factorization_close_primes", 80, "asymmetric",
     "페르마 소인수분해와 근접 소수 (|p - q| < N^(1/4))",
     "Fermat's Factorization on Closely Spaced Primes",
     "RSA 소수 p와 q의 차이가 작을 때 a^2 - N = b^2 제곱수 탐색을 통해 N을 즉시 인수분해하는 페르마 공격을 분석합니다.\n지정된 식별자 `cryptanalysis_fermat_factorization_close_primes_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"cryptanalysis_fermat_factorization_close_primes_v1\") 앞 20자리}`",
     "Analyze Fermat factorization recovering p and q in seconds when prime difference |p - q| is bounded near N^(1/4).\nCompute the first 20 hex characters of SHA256(\"cryptanalysis_fermat_factorization_close_primes_v1\").\n\nFormat: `FLAG{SHA256(\"cryptanalysis_fermat_factorization_close_primes_v1\") first 20 hex}`",
     ["sqrt(N) 근방에서 완전 제곱수 a^2 - N을 탐색하는 알고리즘을 확인하세요.", "식별자 `cryptanalysis_fermat_factorization_close_primes_v1`의 해시 앞 20자리를 추출하세요."],
     ["Inspect square tests for a^2 - N starting at ceil(sqrt(N)).", "Extract first 20 hex chars of SHA256(\"cryptanalysis_fermat_factorization_close_primes_v1\")."],
     "cryptanalysis_fermat_factorization_close_primes_v1"),

    (2, "t2_cryptanalysis_rsa_common_modulus_attack", 80, "asymmetric",
     "동일 모듈러스 N 및 서로소 공개 지수 공격 (Common Modulus)",
     "RSA Common Modulus Attack with Coprime Public Exponents",
     "동일한 모듈러스 N과 gcd(e1, e2) = 1인 두 공개키로 동일 메시지를 암호화했을 때 베주 항등식 r*e1 + s*e2 = 1로 평문을 복원하는 기법을 분석합니다.\n지정된 식별자 `cryptanalysis_rsa_common_modulus_attack_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"cryptanalysis_rsa_common_modulus_attack_v1\") 앞 20자리}`",
     "Examine how Bezout coefficients r*e1 + s*e2 = 1 reconstruct plaintext M from C1^r * C2^s mod N when gcd(e1, e2) = 1.\nCompute the first 20 hex characters of SHA256(\"cryptanalysis_rsa_common_modulus_attack_v1\").\n\nFormat: `FLAG{SHA256(\"cryptanalysis_rsa_common_modulus_attack_v1\") first 20 hex}`",
     ["확장 유클리드로 구한 계수 r, s를 이용한 C1^r * C2^s mod N 연산을 확인하세요.", "식별자 `cryptanalysis_rsa_common_modulus_attack_v1`의 해시 앞 20자리를 추출하세요."],
     ["Review Bezout coefficient recovery and negative modular exponentiation.", "Extract first 20 hex chars of SHA256(\"cryptanalysis_rsa_common_modulus_attack_v1\")."],
     "cryptanalysis_rsa_common_modulus_attack_v1"),

    (2, "t2_cryptanalysis_elliptic_curve_weierstrass", 80, "elliptic",
     "바이어슈트라스 타원곡선 방정식 및 점 덧셈 군(Group) 법칙",
     "Short Weierstrass Elliptic Curves & Point Addition Group Laws",
     "y^2 = x^3 + ax + b (mod p) 타원곡선 상의 점 덧셈(Point Addition)과 점 2배 연산(Point Doubling), 무한대점 O의 군 구조를 분석합니다.\n지정된 식별자 `cryptanalysis_elliptic_curve_weierstrass_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"cryptanalysis_elliptic_curve_weierstrass_v1\") 앞 20자리}`",
     "Audit Weierstrass curve chord-and-tangent arithmetic, discriminant 4a^3 + 27b^2 != 0, and abelian group properties.\nCompute the first 20 hex characters of SHA256(\"cryptanalysis_elliptic_curve_weierstrass_v1\").\n\nFormat: `FLAG{SHA256(\"cryptanalysis_elliptic_curve_weierstrass_v1\") first 20 hex}`",
     ["타원곡선 위의 두 점 P, Q의 접선 및 할선 공식에 따른 덧셈 법칙을 확인하세요.", "식별자 `cryptanalysis_elliptic_curve_weierstrass_v1`의 해시 앞 20자리를 추출하세요."],
     ["Examine chord-and-tangent slope formulas for point addition.", "Extract first 20 hex chars of SHA256(\"cryptanalysis_elliptic_curve_weierstrass_v1\")."],
     "cryptanalysis_elliptic_curve_weierstrass_v1"),

    (2, "t2_cryptanalysis_ecdsa_signature_verification", 80, "elliptic",
     "ECDSA 서명 검증 방정식 u1*G + u2*Q = R",
     "ECDSA Signature Verification Mechanics: u1*G + u2*Q = R",
     "ECDSA 검증 함수가 w = s^(-1) mod n, u1 = z*w, u2 = r*w를 계산하고 u1*G + u2*Q의 x좌표가 r과 일치하는지 확인하는 수학적 메커니즘을 분석합니다.\n지정된 식별자 `cryptanalysis_ecdsa_signature_verification_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"cryptanalysis_ecdsa_signature_verification_v1\") 앞 20자리}`",
     "Trace ECDSA signature verification mechanics proving u1*G + u2*Q recovers ephemeral point (x1, y1) where x1 mod n equals r.\nCompute the first 20 hex characters of SHA256(\"cryptanalysis_ecdsa_signature_verification_v1\").\n\nFormat: `FLAG{SHA256(\"cryptanalysis_ecdsa_signature_verification_v1\") first 20 hex}`",
     ["u1*G + u2*Q = (z/s)*G + (r/s)*(d*G) = ((z+rd)/s)*G = k*G 증명을 확인하세요.", "식별자 `cryptanalysis_ecdsa_signature_verification_v1`의 해시 앞 20자리를 추출하세요."],
     ["Verify algebraic cancellation proving u1*G + u2*Q equals k*G.", "Extract first 20 hex chars of SHA256(\"cryptanalysis_ecdsa_signature_verification_v1\")."],
     "cryptanalysis_ecdsa_signature_verification_v1"),

    (2, "t2_cryptanalysis_aead_gcm_ghash_authenticity", 80, "oracle",
     "AES-GCM 인증 암호화 및 GHASH 무결성 보장",
     "Authenticated Encryption with Associated Data (AEAD) & GHASH",
     "갈루아 카운터 모드(GCM)가 CTR 암호화와 갈루아체 GF(2^128) 상의 GHASH 곱셈기를 결합하여 기밀성과 무결성을 동시 보장하는 원리를 분석합니다.\n지정된 식별자 `cryptanalysis_aead_gcm_ghash_authenticity_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"cryptanalysis_aead_gcm_ghash_authenticity_v1\") 앞 20자리}`",
     "Investigate Galois/Counter Mode (GCM) combining CTR encryption and GF(2^128) GHASH authentication tag verification.\nCompute the first 20 hex characters of SHA256(\"cryptanalysis_aead_gcm_ghash_authenticity_v1\").\n\nFormat: `FLAG{SHA256(\"cryptanalysis_aead_gcm_ghash_authenticity_v1\") first 20 hex}`",
     ["CTR 모드와 GHASH 인증 태그의 결합 방식을 확인하세요.", "식별자 `cryptanalysis_aead_gcm_ghash_authenticity_v1`의 해시 앞 20자리를 추출하세요."],
     ["Review authentication tag computation over GF(2^128) in GCM.", "Extract first 20 hex chars of SHA256(\"cryptanalysis_aead_gcm_ghash_authenticity_v1\")."],
     "cryptanalysis_aead_gcm_ghash_authenticity_v1"),

    # Tier 3 (9 challenges, 120 points)
    (3, "t3_cryptanalysis_cbc_padding_oracle_intermediate", 120, "oracle",
     "AES-CBC 패딩 오라클 중간 바이트 (Intermediate State) 역산",
     "AES-CBC Padding Oracle Intermediate State Byte Recovery",
     "Vaudenay(2002) 패딩 오라클 공격에서 이전 블록의 바이트를 조작하여 복호화 중간 상태 I_k[i]를 1바이트씩 완전히 추출하는 알고리즘을 분석합니다.\n지정된 식별자 `cryptanalysis_cbc_padding_oracle_intermediate_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"cryptanalysis_cbc_padding_oracle_intermediate_v1\") 앞 20자리}`",
     "Trace Vaudenay padding oracle attacks recovering intermediate decryption state I_k[i] = C'_{k-1}[i] XOR pad_byte iteratively.\nCompute the first 20 hex characters of SHA256(\"cryptanalysis_cbc_padding_oracle_intermediate_v1\").\n\nFormat: `FLAG{SHA256(\"cryptanalysis_cbc_padding_oracle_intermediate_v1\") first 20 hex}`",
     ["I_k[i] XOR C_{k-1}[i] = P_k[i] 역산 관계식을 확인하세요.", "식별자 `cryptanalysis_cbc_padding_oracle_intermediate_v1`의 해시 앞 20자리를 추출하세요."],
     ["Verify plaintext derivation formula P_k[i] = I_k[i] XOR C_{k-1}[i].", "Extract first 20 hex chars of SHA256(\"cryptanalysis_cbc_padding_oracle_intermediate_v1\")."],
     "cryptanalysis_cbc_padding_oracle_intermediate_v1"),

    (3, "t3_cryptanalysis_cbc_iv_bit_flipping_exploit", 120, "oracle",
     "CBC IV 비트 플리핑을 통한 임의 평문 조작",
     "CBC Mode IV Bit-Flipping for Arbitrary Plaintext Mutation",
     "IV의 특정 바이트를 변조하여 첫 번째 블록 평문의 해당 바이트를 정확히 원하는 값으로 반전시켜 관리자 권한을 획득하는 공격을 분석합니다.\n지정된 식별자 `cryptanalysis_cbc_iv_bit_flipping_exploit_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"cryptanalysis_cbc_iv_bit_flipping_exploit_v1\") 앞 20자리}`",
     "Analyze IV bit-flipping where mutating IV[i] ^= original ^ target alters decrypted P[0][i] without cipher block corruption.\nCompute the first 20 hex characters of SHA256(\"cryptanalysis_cbc_iv_bit_flipping_exploit_v1\").\n\nFormat: `FLAG{SHA256(\"cryptanalysis_cbc_iv_bit_flipping_exploit_v1\") first 20 hex}`",
     ["IV[i] 조작이 평문 P0[i]에 1:1로 전달되는 비트 플리핑 수식을 확인하세요.", "식별자 `cryptanalysis_cbc_iv_bit_flipping_exploit_v1`의 해시 앞 20자리를 추출하세요."],
     ["Inspect 1-to-1 bit propagation from IV mutations into block 0 plaintext.", "Extract first 20 hex chars of SHA256(\"cryptanalysis_cbc_iv_bit_flipping_exploit_v1\")."],
     "cryptanalysis_cbc_iv_bit_flipping_exploit_v1"),

    (3, "t3_cryptanalysis_rsa_bleichenbacher_06_e3", 120, "asymmetric",
     "Bleichenbacher '06 RSA e=3 정수 세제곱근 서명 위조",
     "Bleichenbacher '06 RSA Signature Forgery with e=3 & Loose Parsers",
     "느슨한 PKCS#1 v1.5 검증 파서를 대상으로 타깃 접두사 D 뒤에 0을 채우고 정수 세제곱근 s = ceil(cbrt(D))를 계산해 유효한 서명을 위조하는 공격을 분석합니다.\n지정된 식별자 `cryptanalysis_rsa_bleichenbacher_06_e3_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"cryptanalysis_rsa_bleichenbacher_06_e3_v1\") 앞 20자리}`",
     "Examine Bleichenbacher '06 signature forgery calculating integer cube roots s = ceil(D^(1/3)) against lax PKCS#1 v1.5 parsers.\nCompute the first 20 hex characters of SHA256(\"cryptanalysis_rsa_bleichenbacher_06_e3_v1\").\n\nFormat: `FLAG{SHA256(\"cryptanalysis_rsa_bleichenbacher_06_e3_v1\") first 20 hex}`",
     ["2048비트 키에서 세제곱근 전개 시 가비지 영역 한계 조건을 확인하세요.", "식별자 `cryptanalysis_rsa_bleichenbacher_06_e3_v1`의 해시 앞 20자리를 추출하세요."],
     ["Verify 2048-bit modulus boundary conditions for prefix preservation.", "Extract first 20 hex chars of SHA256(\"cryptanalysis_rsa_bleichenbacher_06_e3_v1\")."],
     "cryptanalysis_rsa_bleichenbacher_06_e3_v1"),

    (3, "t3_cryptanalysis_ecdsa_nonce_reuse_private_key", 120, "elliptic",
     "ECDSA 난수 재사용 (Nonce Reuse) 개인키 d 수학적 역산",
     "ECDSA Ephemeral Nonce Reuse Private Key Carving (CVE-2010-4740)",
     "동일한 비밀 난수 k로 생성된 두 서명 (r, s1), (r, s2)로부터 k = (z1-z2)/(s1-s2) 및 개인키 d = (s1*k - z1)/r 을 유도하는 공격을 분석합니다.\n지정된 식별자 `cryptanalysis_ecdsa_nonce_reuse_private_key_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"cryptanalysis_ecdsa_nonce_reuse_private_key_v1\") 앞 20자리}`",
     "Analyze private key carving from duplicate ECDSA nonces k = (z1 - z2) * (s1 - s2)^(-1) mod n and d = r^(-1) * (s1*k - z1) mod n.\nCompute the first 20 hex characters of SHA256(\"cryptanalysis_ecdsa_nonce_reuse_private_key_v1\").\n\nFormat: `FLAG{SHA256(\"cryptanalysis_ecdsa_nonce_reuse_private_key_v1\") first 20 hex}`",
     ["두 서명의 감산을 통해 미지수 d를 소거하고 k를 구하는 공식을 확인하세요.", "식별자 `cryptanalysis_ecdsa_nonce_reuse_private_key_v1`의 해시 앞 20자리를 추출하세요."],
     ["Review algebraic elimination of private key d yielding secret nonce k.", "Extract first 20 hex chars of SHA256(\"cryptanalysis_ecdsa_nonce_reuse_private_key_v1\")."],
     "cryptanalysis_ecdsa_nonce_reuse_private_key_v1"),

    (3, "t3_cryptanalysis_coppersmith_stereotyped_messages", 120, "asymmetric",
     "코퍼스미스(Coppersmith) 정리와 정형 메시지 부분 복원",
     "Coppersmith's Theorem & Small Roots of Polynomials mod N",
     "메시지의 일부분(Stereotyped Prefix)을 알고 있을 때 LLL 격자 기저 축소 알고리즘으로 모듈러 다항식의 작은 근 x0 < N^(1/e)을 찾아내는 공격을 분석합니다.\n지정된 식별자 `cryptanalysis_coppersmith_stereotyped_messages_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"cryptanalysis_coppersmith_stereotyped_messages_v1\") 앞 20자리}`",
     "Trace Coppersmith polynomial root recovery using LLL lattice reduction to recover missing plaintext fragments when bound x0 < N^(1/e).\nCompute the first 20 hex characters of SHA256(\"cryptanalysis_coppersmith_stereotyped_messages_v1\").\n\nFormat: `FLAG{SHA256(\"cryptanalysis_coppersmith_stereotyped_messages_v1\") first 20 hex}`",
     ["LLL 격자 기저 축소와 Howgrave-Graham 보조정리를 확인하세요.", "식별자 `cryptanalysis_coppersmith_stereotyped_messages_v1`의 해시 앞 20자리를 추출하세요."],
     ["Examine LLL lattice basis reduction in polynomial small root finding.", "Extract first 20 hex chars of SHA256(\"cryptanalysis_coppersmith_stereotyped_messages_v1\")."],
     "cryptanalysis_coppersmith_stereotyped_messages_v1"),

    (3, "t3_cryptanalysis_fault_injection_bellcore_rsa", 120, "asymmetric",
     "벨코어(Bellcore) 차분 고장 주입 (DFA) CRT-RSA 공격",
     "Bellcore Differential Fault Analysis on CRT-RSA Hardware",
     "중국인의 나머지 정리(CRT) 기반 RSA 하드웨어 연산 중 한 분기(q)에 하드웨어 글리치 고장을 주입하여 gcd(S - S', N)으로 소수 p를 분리하는 공격을 분석합니다.\n지정된 식별자 `cryptanalysis_fault_injection_bellcore_rsa_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"cryptanalysis_fault_injection_bellcore_rsa_v1\") 앞 20자리}`",
     "Analyze Bellcore fault attacks factoring modulus N via gcd(S - S', N) when transient glitches corrupt one CRT branch.\nCompute the first 20 hex characters of SHA256(\"cryptanalysis_fault_injection_bellcore_rsa_v1\").\n\nFormat: `FLAG{SHA256(\"cryptanalysis_fault_injection_bellcore_rsa_v1\") first 20 hex}`",
     ["정상 서명 S와 고장 서명 S'의 차이와 N의 최대공약수 gcd 계산을 확인하세요.", "식별자 `cryptanalysis_fault_injection_bellcore_rsa_v1`의 해시 앞 20자리를 추출하세요."],
     ["Review factorization via greatest common divisor gcd(S - S', N).", "Extract first 20 hex chars of SHA256(\"cryptanalysis_fault_injection_bellcore_rsa_v1\")."],
     "cryptanalysis_fault_injection_bellcore_rsa_v1"),

    (3, "t3_cryptanalysis_dual_ec_drbg_nsa_backdoor", 120, "elliptic",
     "Dual_EC_DRBG 타원곡선 난수 생성기 관계식 백도어",
     "Dual_EC_DRBG Elliptic Curve PRNG Backdoor & Point Relationship",
     "NIST SP 800-90A 표준에 포함되었던 Dual_EC_DRBG에서 두 곡선 점 P와 Q 사이의 비밀 관계 Q = e*P를 아는 공격자가 난수 출력을 예측하는 메커니즘을 분석합니다.\n지정된 식별자 `cryptanalysis_dual_ec_drbg_nsa_backdoor_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"cryptanalysis_dual_ec_drbg_nsa_backdoor_v1\") 앞 20자리}`",
     "Audit Dual_EC_DRBG backdoor architecture where knowledge of scalar e in Q = e*P enables reconstructing internal RNG states.\nCompute the first 20 hex characters of SHA256(\"cryptanalysis_dual_ec_drbg_nsa_backdoor_v1\").\n\nFormat: `FLAG{SHA256(\"cryptanalysis_dual_ec_drbg_nsa_backdoor_v1\") first 20 hex}`",
     ["타원곡선 점 P, Q 사이의 이산대수 관계 e를 이용한 내부 상태 복원을 확인하세요.", "식별자 `cryptanalysis_dual_ec_drbg_nsa_backdoor_v1`의 해시 앞 20자리를 추출하세요."],
     ["Review discrete logarithm scalar e linking curve generators P and Q.", "Extract first 20 hex chars of SHA256(\"cryptanalysis_dual_ec_drbg_nsa_backdoor_v1\")."],
     "cryptanalysis_dual_ec_drbg_nsa_backdoor_v1"),

    (3, "t3_cryptanalysis_shor_algorithm_quantum_period", 120, "pqc",
     "쇼어(Shor) 양자 알고리즘과 이산대수 주기 탐색",
     "Shor's Algorithm & Quantum Order Finding against RSA/ECC",
     "양자 얽힘과 양자 푸리에 변환(QFT)을 활용하여 모듈러 지수 함수의 주기 r을 O((log N)^3) 다항 시간에 찾아내 RSA와 ECC를 무력화하는 원리를 분석합니다.\n지정된 식별자 `cryptanalysis_shor_algorithm_quantum_period_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"cryptanalysis_shor_algorithm_quantum_period_v1\") 앞 20자리}`",
     "Investigate how Shor's algorithm utilizes Quantum Fourier Transform (QFT) to compute function period r solving DLP and factoring in polynomial time.\nCompute the first 20 hex characters of SHA256(\"cryptanalysis_shor_algorithm_quantum_period_v1\").\n\nFormat: `FLAG{SHA256(\"cryptanalysis_shor_algorithm_quantum_period_v1\") first 20 hex}`",
     ["양자 푸리에 변환(QFT)을 통한 주기 탐색과 연분수 전개 원리를 확인하세요.", "식별자 `cryptanalysis_shor_algorithm_quantum_period_v1`의 해시 앞 20자리를 추출하세요."],
     ["Examine Quantum Fourier Transform order finding and continued fractions.", "Extract first 20 hex chars of SHA256(\"cryptanalysis_shor_algorithm_quantum_period_v1\")."],
     "cryptanalysis_shor_algorithm_quantum_period_v1"),

    (3, "t3_cryptanalysis_grover_algorithm_brute_force", 120, "pqc",
     "그로버(Grover) 양자 탐색과 대칭키 비트 강도 반감",
     "Grover's Algorithm Quadratic Speedup on Symmetric Ciphers",
     "양자 진폭 증폭(Amplitude Amplification)을 통해 비정렬 데이터베이스 탐색을 O(sqrt(N))으로 가속하여 AES-128의 유효 보안 강도를 64비트로 반감시키는 원리를 분석합니다.\n지정된 식별자 `cryptanalysis_grover_algorithm_brute_force_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"cryptanalysis_grover_algorithm_brute_force_v1\") 앞 20자리}`",
     "Analyze Grover's quadratic speedup reducing symmetric cipher key search from 2^k to 2^(k/2) requiring AES-256 upgrades.\nCompute the first 20 hex characters of SHA256(\"cryptanalysis_grover_algorithm_brute_force_v1\").\n\nFormat: `FLAG{SHA256(\"cryptanalysis_grover_algorithm_brute_force_v1\") first 20 hex}`",
     ["양자 진폭 증폭 연산과 대칭키 256비트 전환 권고를 확인하세요.", "식별자 `cryptanalysis_grover_algorithm_brute_force_v1`의 해시 앞 20자리를 추출하세요."],
     ["Review quantum amplitude amplification and AES-256 migration recommendations.", "Extract first 20 hex chars of SHA256(\"cryptanalysis_grover_algorithm_brute_force_v1\")."],
     "cryptanalysis_grover_algorithm_brute_force_v1"),

    # Tier 4 (10 challenges, 180~250 points)
    (4, "t4_cryptanalysis_fips203_ml_kem_kyber", 180, "pqc",
     "NIST FIPS 203 ML-KEM (Kyber) 격자 모듈-LWE 구조",
     "NIST FIPS 203 ML-KEM (Kyber) Module Lattice-LWE Mechanics",
     "모듈 격자 기반 오차 학습 문제(Module-LWE)와 NTT(Number Theoretic Transform) 고속 다항식 곱셈을 사용하는 ML-KEM-768 메커니즘을 분석합니다.\n지정된 식별자 `cryptanalysis_fips203_ml_kem_kyber_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"cryptanalysis_fips203_ml_kem_kyber_v1\") 앞 20자리}`",
     "Analyze NIST FIPS 203 ML-KEM-768 lattice-based encryption relying on hardness of Module Learning With Errors (M-LWE).\nCompute the first 20 hex characters of SHA256(\"cryptanalysis_fips203_ml_kem_kyber_v1\").\n\nFormat: `FLAG{SHA256(\"cryptanalysis_fips203_ml_kem_kyber_v1\") first 20 hex}`",
     ["격자 상의 오차 벡터 e 주입과 노이즈 허용 복호화 원리를 확인하세요.", "식별자 `cryptanalysis_fips203_ml_kem_kyber_v1`의 해시 앞 20자리를 추출하세요."],
     ["Examine Module-LWE noise tolerance and NTT polynomial multiplication.", "Extract first 20 hex chars of SHA256(\"cryptanalysis_fips203_ml_kem_kyber_v1\")."],
     "cryptanalysis_fips203_ml_kem_kyber_v1"),

    (4, "t4_cryptanalysis_fips204_ml_dsa_dilithium", 180, "pqc",
     "NIST FIPS 204 ML-DSA (Dilithium) 격자 기반 전자 서명",
     "NIST FIPS 204 ML-DSA (Dilithium) Lattice Signature Verification",
     "모듈 격자 기반 거부 샘플링(Rejection Sampling)과 Fiat-Shamir 변환을 적용하여 서명 크기와 연산 효율을 최적화한 ML-DSA 서명 구조를 분석합니다.\n지정된 식별자 `cryptanalysis_fips204_ml_dsa_dilithium_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"cryptanalysis_fips204_ml_dsa_dilithium_v1\") 앞 20자리}`",
     "Audit NIST FIPS 204 ML-DSA lattice digital signatures combining Module-SIS hardness with Fiat-Shamir with Aborts.\nCompute the first 20 hex characters of SHA256(\"cryptanalysis_fips204_ml_dsa_dilithium_v1\").\n\nFormat: `FLAG{SHA256(\"cryptanalysis_fips204_ml_dsa_dilithium_v1\") first 20 hex}`",
     ["거부 샘플링(Rejection sampling)을 통한 개인키 정보 누출 차단 원리를 확인하세요.", "식별자 `cryptanalysis_fips204_ml_dsa_dilithium_v1`의 해시 앞 20자리를 추출하세요."],
     ["Review Fiat-Shamir with Aborts preventing side-channel leakage.", "Extract first 20 hex chars of SHA256(\"cryptanalysis_fips204_ml_dsa_dilithium_v1\")."],
     "cryptanalysis_fips204_ml_dsa_dilithium_v1"),

    (4, "t4_cryptanalysis_fips205_slh_dsa_sphincs", 190, "pqc",
     "NIST FIPS 205 SLH-DSA (SPHINCS+) 상태 비저장 해시 서명",
     "NIST FIPS 205 SLH-DSA (SPHINCS+) Stateless Hash-Based Signatures",
     "격자 가정이 아닌 순수 암호학적 해시 함수의 충돌 저항성에만 의존하는 상태 비저장 머클 다중 서명 트리(WOTS+, FORS, XMSS) 구조를 분석합니다.\n지정된 식별자 `cryptanalysis_fips205_slh_dsa_sphincs_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"cryptanalysis_fips205_slh_dsa_sphincs_v1\") 앞 20자리}`",
     "Investigate NIST FIPS 205 SLH-DSA stateless hash-based signature trees relying exclusively on hash function pre-image resistance.\nCompute the first 20 hex characters of SHA256(\"cryptanalysis_fips205_slh_dsa_sphincs_v1\").\n\nFormat: `FLAG{SHA256(\"cryptanalysis_fips205_slh_dsa_sphincs_v1\") first 20 hex}`",
     ["WOTS+ 일회용 서명과 FORS 소수 서명 결합 메커니즘을 확인하세요.", "식별자 `cryptanalysis_fips205_slh_dsa_sphincs_v1`의 해시 앞 20자리를 추출하세요."],
     ["Examine WOTS+ one-time signatures and hypertree structures in SLH-DSA.", "Extract first 20 hex chars of SHA256(\"cryptanalysis_fips205_slh_dsa_sphincs_v1\")."],
     "cryptanalysis_fips205_slh_dsa_sphincs_v1"),

    (4, "t4_cryptanalysis_hybrid_key_exchange_x25519_kyber", 190, "pqc",
     "X25519 + ML-KEM-768 하이브리드 키 교환 프로토콜",
     "Hybrid Key Exchange: Dual Protection via X25519 + ML-KEM-768",
     "TLS 1.3에서 고전 ECDH(X25519)와 포스트 퀀텀(ML-KEM-768) 공유 비밀을 KDF로 합성하여 두 알고리즘 중 하나만 안전해도 세션을 보호하는 하이브리드 KEM을 분석합니다.\n지정된 식별자 `cryptanalysis_hybrid_key_exchange_x25519_kyber_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"cryptanalysis_hybrid_key_exchange_x25519_kyber_v1\") 앞 20자리}`",
     "Trace TLS 1.3 hybrid KEM combining X25519 and ML-KEM-768 shared secrets through HKDF ensuring dual security against classical and quantum cryptanalysis.\nCompute the first 20 hex characters of SHA256(\"cryptanalysis_hybrid_key_exchange_x25519_kyber_v1\").\n\nFormat: `FLAG{SHA256(\"cryptanalysis_hybrid_key_exchange_x25519_kyber_v1\") first 20 hex}`",
     ["HKDF-Extract(Salt, SS_Classical || SS_Kyber) 이중 비밀 결합 방식을 확인하세요.", "식별자 `cryptanalysis_hybrid_key_exchange_x25519_kyber_v1`의 해시 앞 20자리를 추출하세요."],
     ["Verify HKDF-Extract combining classical and quantum shared secrets.", "Extract first 20 hex chars of SHA256(\"cryptanalysis_hybrid_key_exchange_x25519_kyber_v1\")."],
     "cryptanalysis_hybrid_key_exchange_x25519_kyber_v1"),

    (4, "t4_cryptanalysis_harvest_now_decrypt_later_threat", 190, "pqc",
     "Harvest Now, Decrypt Later (HNDL) 위협 모델 및 선제적 방어",
     "Harvest Now, Decrypt Later (HNDL) Threat Modeling & Forward Secrecy",
     "현재 암호화된 트래픽을 미리 저장한 후 양자 컴퓨터로 소급 복호화하는 HNDL 공격 벡터와 PQC 조기 마이그레이션 우선순위 산정을 분석합니다.\n지정된 식별자 `cryptanalysis_harvest_now_decrypt_later_threat_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"cryptanalysis_harvest_now_decrypt_later_threat_v1\") 앞 20자리}`",
     "Analyze adversary data interception pipelines executing HNDL attacks and enterprise risk assessment for long-term secret data lifecycles.\nCompute the first 20 hex characters of SHA256(\"cryptanalysis_harvest_now_decrypt_later_threat_v1\").\n\nFormat: `FLAG{SHA256(\"cryptanalysis_harvest_now_decrypt_later_threat_v1\") first 20 hex}`",
     ["데이터 기밀성 요구 기간과 양자 컴퓨터 출현 예상 시점 비교를 확인하세요.", "식별자 `cryptanalysis_harvest_now_decrypt_later_threat_v1`의 해시 앞 20자리를 추출하세요."],
     ["Examine data shelf-life risk versus cryptographically relevant quantum timelines.", "Extract first 20 hex chars of SHA256(\"cryptanalysis_harvest_now_decrypt_later_threat_v1\")."],
     "cryptanalysis_harvest_now_decrypt_later_threat_v1"),

    (4, "t4_cryptanalysis_rsa_pss_probabilistic_padding", 200, "asymmetric",
     "RSA-PSS 확률적 서명 구조와 MGF1 마스크 생성",
     "RSA-PSS Probabilistic Signature Scheme & MGF1 Masking",
     "결정론적 PKCS#1 v1.5의 취약점을 해결하기 위해 임의 솔트(Salt)와 MGF1 해시 마스크를 결합하여 선택 암호문 공격에 대한 증명 가능 안전성을 제공하는 PSS를 분석합니다.\n지정된 식별자 `cryptanalysis_rsa_pss_probabilistic_padding_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"cryptanalysis_rsa_pss_probabilistic_padding_v1\") 앞 20자리}`",
     "Audit RSA-PSS probabilistic padding combining random salt and Mask Generation Function (MGF1) delivering provable security against Bleichenbacher forgery.\nCompute the first 20 hex characters of SHA256(\"cryptanalysis_rsa_pss_probabilistic_padding_v1\").\n\nFormat: `FLAG{SHA256(\"cryptanalysis_rsa_pss_probabilistic_padding_v1\") first 20 hex}`",
     ["임의 솔트 바이트와 MGF1 마스킹을 통한 확률적 서명 인코딩을 확인하세요.", "식별자 `cryptanalysis_rsa_pss_probabilistic_padding_v1`의 해시 앞 20자리를 추출하세요."],
     ["Review randomized salting and MGF1 masking eliminating deterministic forgery.", "Extract first 20 hex chars of SHA256(\"cryptanalysis_rsa_pss_probabilistic_padding_v1\")."],
     "cryptanalysis_rsa_pss_probabilistic_padding_v1"),

    (4, "t4_cryptanalysis_rfc6979_deterministic_ecdsa", 200, "elliptic",
     "RFC 6979 결정론적 ECDSA 서명 생성 표준",
     "RFC 6979 Deterministic Nonce Derivation via HMAC-SHA256",
     "엔트로피 부족으로 인한 난수 재사용 재앙을 원천 방지하기 위해 개인키와 메시지 해시의 HMAC으로 비밀 난수 k를 결정론적으로 유도하는 RFC 6979를 분석합니다.\n지정된 식별자 `cryptanalysis_rfc6979_deterministic_ecdsa_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"cryptanalysis_rfc6979_deterministic_ecdsa_v1\") 앞 20자리}`",
     "Analyze RFC 6979 deterministic nonce derivation k = HMAC_DRBG(private_key, hash(m)) eliminating RNG entropy failure vulnerabilities.\nCompute the first 20 hex characters of SHA256(\"cryptanalysis_rfc6979_deterministic_ecdsa_v1\").\n\nFormat: `FLAG{SHA256(\"cryptanalysis_rfc6979_deterministic_ecdsa_v1\") first 20 hex}`",
     ["HMAC-DRBG를 통해 개인키와 메시지로부터 고유 k를 계산하는 의사 코드를 확인하세요.", "식별자 `cryptanalysis_rfc6979_deterministic_ecdsa_v1`의 해시 앞 20자리를 추출하세요."],
     ["Review HMAC-DRBG loop generating nonces strictly within [1, n-1].", "Extract first 20 hex chars of SHA256(\"cryptanalysis_rfc6979_deterministic_ecdsa_v1\")."],
     "cryptanalysis_rfc6979_deterministic_ecdsa_v1"),

    (4, "t4_cryptanalysis_side_channel_dpa_cpa_masking", 200, "oracle",
     "차분 전력 분석 (DPA/CPA) 및 불리언 마스킹 하드닝",
     "Differential Power Analysis (DPA/CPA) & Boolean Masking Defenses",
     "하드웨어 암호 칩에서 해밍 가중치(Hamming Weight) 기반 전력 소비 파형을 상관분석하는 CPA 공격과 중간값을 난수로 마스킹하는 방어 설계를 분석합니다.\n지정된 식별자 `cryptanalysis_side_channel_dpa_cpa_masking_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"cryptanalysis_side_channel_dpa_cpa_masking_v1\") 앞 20자리}`",
     "Investigate Correlation Power Analysis (CPA) on CMOS leakage and first-order Boolean masking defenses splitting sensitive variables x = x_m XOR m.\nCompute the first 20 hex characters of SHA256(\"cryptanalysis_side_channel_dpa_cpa_masking_v1\").\n\nFormat: `FLAG{SHA256(\"cryptanalysis_side_channel_dpa_cpa_masking_v1\") first 20 hex}`",
     ["해밍 가중치와 측정 전력 간의 피어슨 상관계수 분석식을 확인하세요.", "식별자 `cryptanalysis_side_channel_dpa_cpa_masking_v1`의 해시 앞 20자리를 추출하세요."],
     ["Review Pearson correlation coefficient metrics against Hamming distance.", "Extract first 20 hex chars of SHA256(\"cryptanalysis_side_channel_dpa_cpa_masking_v1\")."],
     "cryptanalysis_side_channel_dpa_cpa_masking_v1"),

    (4, "t4_cryptanalysis_zero_knowledge_zkp_snark", 220, "pqc",
     "영지식 증명 zk-SNARKs 및 준동형 암호(FHE) 프라이버시",
     "Zero-Knowledge Proofs (zk-SNARKs) & Fully Homomorphic Encryption",
     "증명자가 비밀 정보 자체를 누출하지 않고 명제의 참 거짓을 수학적으로 증명하는 zk-SNARKs QAP 다항식 검증과 암호화 상태 연산(FHE) 원리를 분석합니다.\n지정된 식별자 `cryptanalysis_zero_knowledge_zkp_snark_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"cryptanalysis_zero_knowledge_zkp_snark_v1\") 앞 20자리}`",
     "Examine Quadratic Arithmetic Programs (QAP) and elliptic pairing verification enabling non-interactive zero-knowledge proofs.\nCompute the first 20 hex characters of SHA256(\"cryptanalysis_zero_knowledge_zkp_snark_v1\").\n\nFormat: `FLAG{SHA256(\"cryptanalysis_zero_knowledge_zkp_snark_v1\") first 20 hex}`",
     ["QAP 다항식 분할 및 타원곡선 페어링 e(A, B) = e(alpha, beta)*e(C, gamma) 검증을 확인하세요.", "식별자 `cryptanalysis_zero_knowledge_zkp_snark_v1`의 해시 앞 20자리를 추출하세요."],
     ["Review quadratic arithmetic programs and bilinear pairing verification.", "Extract first 20 hex chars of SHA256(\"cryptanalysis_zero_knowledge_zkp_snark_v1\")."],
     "cryptanalysis_zero_knowledge_zkp_snark_v1"),

    (4, "t4_cryptanalysis_enterprise_crypto_agility_governance", 250, "pqc",
     "엔터프라이즈 크립토 어질리티(Crypto-Agility) 및 PQC 마이그레이션",
     "Enterprise Cryptographic Agility & Global PQC Migration Governance",
     "CBOM(Cryptographic Bill of Materials) 생성, 알고리즘 플러그인 모듈화, 양자 내성 마이그레이션 로드맵을 수립하는 전사 암호 거버넌스를 종합 분석합니다.\n지정된 식별자 `cryptanalysis_enterprise_crypto_agility_governance_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"cryptanalysis_enterprise_crypto_agility_governance_v1\") 앞 20자리}`",
     "Synthesize enterprise crypto-agility frameworks, CBOM discovery pipelines, and multi-year Post-Quantum Cryptography transition governance.\nCompute the first 20 hex characters of SHA256(\"cryptanalysis_enterprise_crypto_agility_governance_v1\").\n\nFormat: `FLAG{SHA256(\"cryptanalysis_enterprise_crypto_agility_governance_v1\") first 20 hex}`",
     ["CBOM 자동화 발견, 알고리즘 분리 아키텍처 및 PQC 전환 로드맵을 확인하세요.", "식별자 `cryptanalysis_enterprise_crypto_agility_governance_v1`의 해시 앞 20자리를 추출하세요."],
     ["Review Cryptographic Bill of Materials governance and agile algorithm swap designs.", "Extract first 20 hex chars of SHA256(\"cryptanalysis_enterprise_crypto_agility_governance_v1\")."],
     "cryptanalysis_enterprise_crypto_agility_governance_v1")
]


def build_challenges():
    challenges = []
    derivable_ids = []

    for tier, cid, points, cat, title_ko, title_en, p_ko, p_en, h_ko, h_en, ident in RAW_CHALLENGES:
        inner_hash = hashlib.sha256(ident.encode("utf-8")).hexdigest()[:20]
        flag = f"FLAG{{{inner_hash}}}"
        target_hash = hashlib.sha256(flag.encode("utf-8")).hexdigest()

        ch = {
            "id": cid,
            "tier": tier,
            "cat": cat,
            "track": "cryptanalysis",
            "points": points,
            "ci": False,
            "fmt": "FLAG{...}",
            "title": {
                "ko": title_ko,
                "en": title_en
            },
            "prompt": {
                "ko": p_ko,
                "en": p_en
            },
            "hints": {
                "ko": h_ko,
                "en": h_en
            },
            "hash": target_hash
        }
        challenges.append(ch)
        derivable_ids.append((cid, ident))

    return challenges, derivable_ids


def update_challenges_js(new_challenges):
    content = CHALLENGES_JS.read_text(encoding="utf-8")

    # 1. Add TRACK_INFO to TRACKS if missing
    if '"cryptanalysis"' not in content:
        pattern = r'(\s*\{\s*"id":\s*"edrbypass"[^}]+desc_en"[^}]+}\s*)(\];)'
        track_json = (
            '  },\n  {\n'
            f'    "id": "{TRACK_INFO["id"]}",\n'
            f'    "icon": "{TRACK_INFO["icon"]}",\n'
            f'    "ko": "{TRACK_INFO["ko"]}",\n'
            f'    "en": "{TRACK_INFO["en"]}",\n'
            f'    "desc_ko": "{TRACK_INFO["desc_ko"]}",\n'
            f'    "desc_en": "{TRACK_INFO["desc_en"]}"\n'
            '  }'
        )
        content = re.sub(pattern, r'\1' + track_json + r'\n\2', content)

    # 2. Add new challenges to CHALLENGES array
    last_bracket_idx = content.rfind("];")
    if last_bracket_idx == -1:
        raise ValueError("Could not find end of CHALLENGES array")

    ch_entries = []
    for ch in new_challenges:
        ch_entries.append("  " + json.dumps(ch, ensure_ascii=False, indent=2).replace("\n", "\n  "))

    joined = ",\n" + ",\n".join(ch_entries) + "\n"
    content = content[:last_bracket_idx].rstrip() + joined + "];\n"

    CHALLENGES_JS.write_text(content, encoding="utf-8")
    print(f"[✓] Added {len(new_challenges)} challenges and track info to {CHALLENGES_JS.name}")


def update_solve_derivable_js(derivable_ids):
    content = SOLVE_DERIVABLE_JS.read_text(encoding="utf-8")

    solver_entries = []
    for cid, ident in derivable_ids:
        if f"'{cid}'" in content:
            continue
        entry = (
            f"  ['{cid}', (ch) => {{\n"
            f"    const h = crypto.createHash('sha256').update('{ident}', 'utf8').digest('hex').slice(0, 20);\n"
            f"    return `FLAG${{{{h}}}}`;\n"
            f"  }}],"
        )
        solver_entries.append(entry)

    if solver_entries:
        target_str = "]);\n\n// Run audit"
        idx = content.find(target_str)
        if idx != -1:
            insertion = "\n" + "\n".join(solver_entries) + "\n"
            content = content[:idx] + insertion + content[idx:]
            SOLVE_DERIVABLE_JS.write_text(content, encoding="utf-8")
            print(f"[✓] Added {len(solver_entries)} solvers to {SOLVE_DERIVABLE_JS.name}")


def update_index_html():
    content = INDEX_HTML.read_text(encoding="utf-8")

    # Update counts: 52 -> 53, 1820 -> 1855, 1,820 -> 1,855
    content = re.sub(r'52개\s*트랙', '53개 트랙', content)
    content = re.sub(r'52\s*Tracks', '53 Tracks', content)
    content = re.sub(r'52\s*tracks', '53 tracks', content)
    content = re.sub(r'1,820', '1,855', content)
    content = re.sub(r'1820', '1855', content)

    # Add track chip if missing
    if 'data-track="cryptanalysis"' not in content:
        pattern = r'(<button class="track-chip"[^>]*data-track="edrbypass"[^>]*>.*?</button>)'
        replacement = r'\1\n      <button class="track-chip" data-track="cryptanalysis">🔐 현대 응용 암호·PQC</button>'
        content = re.sub(pattern, replacement, content, count=1)

    INDEX_HTML.write_text(content, encoding="utf-8")
    print(f"[✓] Updated HUD count (1855) and added cryptanalysis chip in {INDEX_HTML.name}")


def update_app_js():
    content = APP_JS.read_text(encoding="utf-8")

    if 'cryptanalysis:' not in content:
        pattern = r'(\s*edrbypass:\s*\{[^}]+\},)'
        replacement = r'\1\n    cryptanalysis: { id:"cryptanalysis", icon:"🔐", ko:"현대 응용 암호학 & 암호 분석", en:"Modern Cryptanalysis & PQC" },'
        content = re.sub(pattern, replacement, content, count=1)

    content = re.sub(r'1820', '1855', content)

    APP_JS.write_text(content, encoding="utf-8")
    print(f"[✓] Updated TRACKS and pool count in {APP_JS.name}")


def update_wargame_readme():
    content = WARGAME_README.read_text(encoding="utf-8")

    content = re.sub(r'1820', '1855', content)
    content = re.sub(r'1,820', '1,855', content)
    content = re.sub(r'52개 트랙', '53개 트랙', content)
    content = re.sub(r'52 tracks', '53 tracks', content)

    if '| `cryptanalysis` |' not in content:
        pattern = r'(\| `edrbypass` \|[^\n]+\n)'
        replacement = (
            r'\1| `cryptanalysis` | 🔐 현대 응용 암호학 & 암호 분석 | '
            'AES-CBC 패딩 오라클, IV 비트 플리핑, RSA Bleichenbacher 서명 위조, ECDSA 난수 재사용 개인키 역산, ML-KEM-768 포스트 퀀텀 하이브리드 방어 | 35 |\n'
        )
        content = re.sub(pattern, replacement, content, count=1)

    WARGAME_README.write_text(content, encoding="utf-8")
    print(f"[✓] Updated {WARGAME_README.name} to 53 tracks and 1,855 challenges")


def update_global_readmes():
    files = [
        REPO_ROOT / "README.md",
        REPO_ROOT / "README.en.md",
        REPO_ROOT / "README.ja.md",
        REPO_ROOT / "README.zh.md",
        REPO_ROOT / "USAGE.md",
        REPO_ROOT / "AI_LEARNING.md"
    ]
    for p in files:
        if not p.exists():
            continue
        c = p.read_text(encoding="utf-8")
        c = re.sub(r'1,820\s*문제', '1,855 문제', c)
        c = re.sub(r'1820\s*문제', '1855 문제', c)
        c = re.sub(r'1,820\s*challenges', '1,855 challenges', c)
        c = re.sub(r'1820\s*challenges', '1855 challenges', c)
        c = re.sub(r'1,820\s*問', '1,855 問', c)
        c = re.sub(r'1820\s*問', '1855 問', c)
        c = re.sub(r'1,820\s*道挑战', '1,855 道挑战', c)
        c = re.sub(r'1820\s*道挑战', '1855 道挑战', c)
        c = re.sub(r'1,820\s*题', '1,855 题', c)
        c = re.sub(r'1820\s*题', '1855 题', c)
        c = re.sub(r'wargame-1820', 'wargame-1855', c)
        c = re.sub(r'52개\s*트랙', '53개 트랙', c)
        c = re.sub(r'52\s*tracks', '53 tracks', c)
        c = re.sub(r'52\s*Tracks', '53 Tracks', c)
        p.write_text(c, encoding="utf-8")
        print(f"  ✓ Synchronized 1855 count in {p.name}")


def main():
    print("[*] Generating Track 53: cryptanalysis (Modern Cryptanalysis & PQC)...")
    challenges, ids = build_challenges()
    print(f"[*] Built {len(challenges)} challenges.")

    update_challenges_js(challenges)
    update_solve_derivable_js(ids)
    update_index_html()
    update_app_js()
    update_wargame_readme()
    update_global_readmes()
    print("[🎉] Track 53 generation completed successfully!")


if __name__ == "__main__":
    main()
