> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 양자 내성 암호(PQC) 심층 분석: 격자 기반 암호학(LWE/ML-KEM/ML-DSA), 하이브리드 키 교환 및 엔터프라이즈 마이그레이션

> 🏢 **연계 실습 랩**: [Lab 45: PQCShield - Quantum Cryptography & PQC Lab](../../labs/45_quantum_cryptography_pqc_lab)  
> 🎯 **관련 워게임 트랙**: `pqc` (양자 내성 암호 & PQC 마이그레이션 35제)  
> 🛠️ **관련 시뮬레이터**: [Wargame Playground: Lattice Key Exchange & PQC Inspector](../../wargame/index.html#playground)

---

## 0. 개요: 양자 컴퓨팅의 암호학적 위협과 패러다임 전환

기존 공개키 암호 체계(RSA, ECC, Diffie-Hellman)는 **소인수분해(Integer Factorization)** 및 **이산로그 문제(Discrete Logarithm Problem, DLP/ECDLP)**의 계산적 난해성에 의존합니다. 그러나 대규모 오류 정정 양자 컴퓨터(Fault-Tolerant Quantum Computer, FTQC) 상에서 동작하는 **쇼어 알고리즘(Shor's Algorithm)**은 이러한 난제를 다항 시간(Polynomial Time, $\mathcal{O}((\log N)^3)$) 안에 해결함으로써 기존 비대칭 암호를 완전히 무력화합니다.

```
+---------------------------------------------------------------------------------------------------+
|                        양자 컴퓨팅 위협과 포스트 퀀텀 암호(PQC) 생태계 전이 체계                 |
+---------------------------------------------------------------------------------------------------+

   [고전 공개키 암호 (쇼어 알고리즘으로 붕괴)]                  [NIST FIPS PQC 표준 (양자 내성 보장)]
   ┌────────────────────────────────────────┐                 ┌────────────────────────────────────────┐
   │ • RSA-2048 / RSA-4096                  │                 │ FIPS 203: ML-KEM (Module-LWE, Kyber)   │
   │ • ECDSA P-256 / Ed25519                │   마이그레이션  │ • 양자 안전 키 캡슐화 (KEM)            │
   │ • ECDH / X25519 (전방향 보안 파괴)     │ ───────────────>│                                        │
   │ ⚠️ "지금 수집, 나중 해독" (HNDL) 위협  │                 │ FIPS 204: ML-DSA (Module-LWE, Dilithium│
   └────────────────────────────────────────┘                 │ • 양자 안전 전자서명 (Digital Signature│
                       │                                      │                                        │
                       │ 공격 위험 매트릭스                   │ FIPS 205: SLH-DSA (SPHINCS+, 상태비보존)│
                       ▼                                      │ • 해시 기반 무상태 전자서명 (State-free│
   ┌────────────────────────────────────────┐                 └────────────────────────────────────────┘
   │ 대칭키 & 해시 (그로버 알고리즘 영향)   │                                     ▲
   │ • AES-128: 유효 보안 64비트 (위험)    │                                     │
   │ • AES-256: 유효 보안 128비트 (안전)   │                [과도기 하이브리드 키 교환 프로토콜]
   │ • SHA-256/384/512: 충돌 저항 유지     │ ──────────────> • X25519 + ML-KEM-768 결합 핸드셰이크
   └────────────────────────────────────────┘                 • 이중 키 파생(KDF)으로 클래식/PQC 동시 충족
```

공격자들은 현재 유통되는 암호화 트래픽을 미리 도청하여 저장한 뒤, 훗날 양자 컴퓨터가 실용화되었을 때 일괄 해독하는 **HNDL (Harvest Now, Decrypt Later)** 전략을 활발히 전개하고 있습니다. 이에 따라 미국 NIST는 2024년 8월 **FIPS 203 (ML-KEM)**, **FIPS 204 (ML-DSA)**, **FIPS 205 (SLH-DSA)** 표준을 공식 발표하였으며, 글로벌 IT 인프라는 하이브리드 키 교환을 거쳐 완전한 PQC로의 마이그레이션을 급속히 추진하고 있습니다.

---

## 1. 격자 기반 암호학(Lattice-Based Cryptography)과 LWE 수학적 원리

NIST PQC의 핵심 주류를 형성하는 **격자 기반 암호(Lattice Cryptography)**는 고차원 유클리드 공간 $\mathbb{R}^n$ 상의 이산 부분군(Discrete Subgroup)인 격자 $\Lambda$에서 최단 벡터 문제(Shortest Vector Problem, SVP)와 최근접 벡터 문제(Closest Vector Problem, CVP)의 계산적 어려움에 기반합니다.

### 1.1 LWE (Learning With Errors)와 Ring/Module-LWE
LWE 문제는 비밀 벡터 $\mathbf{s} \in \mathbb{Z}_q^n$와 오차 벡터 $\mathbf{e} \leftarrow \chi$가 주어졌을 때, 선형 방정식 쌍 $(\mathbf{A}, \mathbf{b} = \mathbf{A}\mathbf{s} + \mathbf{e} \pmod q)$로부터 비밀 $\mathbf{s}$를 복원하거나 무작위 균등 분포와 구별하는 문제입니다.

1. **기본 LWE**: 행렬 $\mathbf{A} \in \mathbb{Z}_q^{m \times n}$의 크기가 거대하여 공개키 크기가 수십 KB에 달하는 성능 한계가 존재합니다.
2. **Ring-LWE**: 다항식 환 $\mathcal{R}_q = \mathbb{Z}_q[X]/(X^n + 1)$ 위에서 원소를 정의하여 곱셈을 순환 합성곱(Cyclic Convolution)으로 치환함으로써 키 크기를 획기적으로 축소합니다.
3. **Module-LWE (ML-KEM, ML-DSA 채택)**: Ring-LWE의 대수적 구조 취약점 위험과 기본 LWE의 과도한 키 크기 사이의 최적 균형점으로, 환 원소를 성분으로 갖는 작은 모듈 벡터/행렬을 사용합니다.

```
ML-KEM 암호화 행렬 연산 모델:
A_hat ∈ R_q^{k × k}  (공개 생성 시드로부터 확정적 파생)
s ∈ R_q^k, e ∈ R_q^k (비밀 및 노이즈 벡터)
공개키: t = A_hat ∘ s + e
암호문: u = A_hat^T ∘ r + e_1,  v = t^T ∘ r + e_2 + ⌈q/2⌋ ⋅ m
```

---

## 2. NIST 공식 표준: FIPS 203 (ML-KEM) 및 FIPS 204 (ML-DSA)

### 2.1 FIPS 203: ML-KEM (구 CRYSTALS-Kyber)
ML-KEM은 키 캡슐화 메커니즘(Key Encapsulation Mechanism)으로, 송신자가 수신자의 공개키를 이용해 비밀 키(Shared Secret)를 캡슐화한 암호문(Ciphertext)을 생성하고, 수신자는 자신의 비밀키로 이를 역캡슐화(Decapsulate)하여 동일한 세션 대칭키를 유도합니다.

| 보안 파라미터 | 격자 모듈 차원 $k$ | 계수 모듈러스 $q$ | 공개키 크기 (Bytes) | 암호문 크기 (Bytes) | NIST 보안 수준 |
|:---|:---:|:---:|:---:|:---:|:---|
| **ML-KEM-512** | 2 | 3329 | 800 | 768 | Level 1 (AES-128 대응) |
| **ML-KEM-768** | 3 | 3329 | 1,184 | 1,088 | Level 3 (AES-192 대응) ⭐ *표준 권고* |
| **ML-KEM-1024** | 4 | 3329 | 1,568 | 1,568 | Level 5 (AES-256 대응) |

### 2.2 FIPS 204: ML-DSA (구 CRYSTALS-Dilithium)
Fiat-Shamir with Aborts 기법을 적용한 격자 기반 디지털 서명 알고리즘으로, 거부 샘플링(Rejection Sampling)을 통해 서명 결과물에서 비밀키 노이즈의 통계적 분포 정보가 누설되는 것을 수학적으로 차단합니다.

* **ML-DSA-44**: NIST Level 2, 서명 크기 2,420 Bytes
* **ML-DSA-65**: NIST Level 3, 서명 크기 3,309 Bytes (엔터프라이즈 권장)
* **ML-DSA-87**: NIST Level 5, 서명 크기 4,627 Bytes

---

## 3. 하이브리드 키 교환(Hybrid KEM) 구조 및 TLS 1.3 결합

현재 PQC 알고리즘은 수학적 공격 가능성이 아직 100년 이상 장기 실증되지 않았으므로, 엔터프라이즈와 브라우저는 **고전 암호(ECDH)와 PQC(ML-KEM)를 결합한 하이브리드 키 교환**을 필수 채택하고 있습니다.

```python
# 하이브리드 키 파생 (Dual KDF) 의사코드
# 두 키 중 하나만 안전하더라도 전체 세션 키의 기밀성이 수학적으로 보장됨
import hashlib
from cryptography.hazmat.primitives.asymmetric import x25519

def derive_hybrid_session_key(x25519_ss: bytes, mlkem_ss: bytes) -> bytes:
    """
    RFC 9370 / IETF Hybrid Key Exchange KDF:
    Shared Secret = HKDF-Extract(Salt=0, IKM = x25519_ss || mlkem_ss)
    """
    ikm = x25519_ss + mlkem_ss
    transcript_binding = hashlib.sha256(ikm).digest()
    return transcript_binding
```

1. **다운그레이드 공격(Downgrade Attack)**: 중간자(MitM)가 ClientHello의 PQC 확장 필드(`X25519Kyber768Draft00`)를 강제로 제거하여 구형 ECDH로 유도하려는 공격 시도.
2. **방어 대책**: 서버 TLS 스택에서 하이브리드 미지원 핸드셰이크에 대해 강제 거부(Strict PQC Policy) 설정 및 TLS 1.3 `Finished` 메시지 내 전송 트랜스크립트 무결성 검증.

---

## 4. 부채널 공격(Side-Channel Attacks) 및 결함 주입 방어

격자 암호의 수학적 안전성과 별개로, 물리적 구현체에서는 다음과 같은 구현 취약점이 존재합니다:

1. **타이밍 부채널(Timing Side-Channel)**: 다항식 곱셈 시 NTT(Number Theoretic Transform) 연산이나 다항식 계수 압축/복원 시 분기문에 의한 실행 시간 편차. 반드시 상수 시간(Constant-Time) 연산 보장 필요.
2. **결함 주입 공격(Fault Injection Attacks)**: 거부 샘플링 또는 해시 검증 루틴에 클록 글리치를 주입하여 불완전한 서명/복호화를 유도한 후 LLL 격자 축소 알고리즘으로 비밀키 복원.
3. **방어 대책**: Fujisaki-Okamoto(FO) 변환의 엄격한 재암호화 검증(`verify(c, Enc(pk, m')) == 0`), 하드웨어 차원 메모리 난독화.

---

<a name="english"></a>

# Deep Dive: Post-Quantum Cryptography (PQC) - Lattice-Based Cryptography (ML-KEM/ML-DSA), Hybrid Key Exchange & Migration

> 🏢 **Hands-on Lab**: [Lab 45: PQCShield - Quantum Cryptography & PQC Lab](../../labs/45_quantum_cryptography_pqc_lab)  
> 🎯 **Wargame Track**: `pqc` (Post-Quantum Cryptography & PQC Migration - 35 Challenges)  
> 🛠️ **Simulator**: [Wargame Playground: Lattice Key Exchange & PQC Inspector](../../wargame/index.html#playground)

---

## 0. Overview: The Quantum Threat and Cryptographic Paradigm Shift

Classical asymmetric cryptography (RSA, ECDSA, ECDH) relies on mathematical problems such as Integer Factorization and Discrete Logarithms. When fault-tolerant quantum computers emerge, **Shor's Algorithm** solves these problems in polynomial time ($\mathcal{O}((\log N)^3)$), rendering classical public-key cryptography obsolete.

Threat actors are already executing **"Harvest Now, Decrypt Later" (HNDL)** campaigns by recording encrypted traffic today to decrypt with future quantum machines. In response, NIST standardized **FIPS 203 (ML-KEM)**, **FIPS 204 (ML-DSA)**, and **FIPS 205 (SLH-DSA)** in August 2024.

---

## 1. Mathematical Foundations of Lattice-Based Cryptography

Lattice cryptography relies on the hardness of high-dimensional lattice problems like the Shortest Vector Problem (SVP) and Closest Vector Problem (CVP).

* **Learning With Errors (LWE)**: Solving for secret $\mathbf{s}$ from noisy linear systems $\mathbf{b} = \mathbf{A}\mathbf{s} + \mathbf{e} \pmod q$.
* **Module-LWE**: Used in ML-KEM and ML-DSA, structuring matrix elements over the polynomial ring $\mathcal{R}_q = \mathbb{Z}_q[X]/(X^n + 1)$, balancing compact key size and provable security.

---

## 2. NIST Standards: FIPS 203 (ML-KEM) & FIPS 204 (ML-DSA)

* **ML-KEM-768 (FIPS 203)**: Recommended default parameter set matching NIST Security Level 3 (AES-192 equivalent), featuring 1,184-byte public keys and 1,088-byte ciphertexts.
* **ML-DSA-65 (FIPS 204)**: Recommended enterprise digital signature matching Level 3 with a 3,309-byte signature size using Fiat-Shamir with Aborts and rejection sampling.

---

## 3. Hybrid Key Exchange and Downgrade Mitigation

To mitigate algorithm implementation maturity concerns, modern systems adopt hybrid key exchange combining classical ECDH (e.g. X25519) and ML-KEM-768.

```
Hybrid Shared Secret = HKDF-Extract(Salt=0, IKM = SS_ECDH || SS_MLKEM)
```

MitM downgrade attempts that strip PQC extensions from TLS ClientHello are mitigated via strict server enforcement policies and cryptographic transcript binding verified in the TLS 1.3 `Finished` MAC exchange.
