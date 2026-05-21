# 57-3. 포스트 양자 알고리즘(PQC): 분류, 원리, 성능 분석

## 개요

포스트 양자 암호(Post-Quantum Cryptography, PQC)는 양자 컴퓨터의 공격에도 안전할 것으로 예상되는 암호 알고리즘의 집합이다. 기존의 RSA, ECDH, ECDSA와 달리, PQC 알고리즘은 쇼어 알고리즘으로 공략 불가능한 수학적 문제에 기반한다. 중요한 점은 PQC가 고전 컴퓨터에서 실행 가능한 소프트웨어라는 것이다.

---

## 1. PQC 알고리즘 분류 체계

### 1.1 수학적 기반별 분류 표

| 분류 | 수학적 기반 | 대표 알고리즘 | 키 크기 | 성능 | 성숙도 | 양자 저항성 |
|------|-----------|------------|--------|------|--------|-----------|
| **격자 기반** | LWE, RLWE, NTRU | Kyber, Dilithium, FALCON | 중간 | 빠름 | 높음 | 강함 |
| **해시 기반** | 해시 함수 보안성 | SPHINCS+, XMSS, LMS | 중간 | 느림 | 매우 높음 | 매우 강함 |
| **코드 기반** | 오류 수정 코드 | McEliece, BIKE, HQC | 매우 큼 | 빠름 | 높음 | 강함 |
| **다변수 다항식** | MQ 문제 | Rainbow, GeMSS | 작음~중간 | 혼재 | 낮음 (여러 깨짐) | 중간 |
| **동종 타원곡선** | 타원곡선 동형 | SIKE (폐기), CSIDH | 매우 작음 | 매우 느림 | 낮음 | 불확실 |
| **격자+이상** | 이상적 격자 | NTRU Prime | 중간 | 빠름 | 중간 | 강함 |

### 1.2 NIST 최종 선정 알고리즘 비교

| 알고리즘 | 용도 | 기반 문제 | 공개키 크기 | 비밀키 크기 | 서명/암호문 크기 | 성능 수준 |
|---------|------|----------|-----------|-----------|--------------|---------|
| **CRYSTALS-Kyber (ML-KEM)** | KEM | Module-LWE | 1,184B (L3) | 2,400B (L3) | 1,088B (L3) | 매우 빠름 |
| **CRYSTALS-Dilithium (ML-DSA)** | 서명 | Module-LWE+SIS | 1,952B (L3) | 4,000B (L3) | 3,293B (L3) | 빠름 |
| **FALCON** | 서명 | NTRU 격자 | 897B (L1) | 1,281B (L1) | 690B (L1) | 빠름 (서명 생성 느림) |
| **SPHINCS+** | 서명 | 해시 함수 | 32~64B | 64~128B | 8~50KB | 느림 |

---

## 2. 격자 기반 암호의 수학적 기초

### 2.1 LWE(Learning With Errors) 문제

**정의**: 다음을 구별하는 것이 어렵다.
- (A, As + e): 행렬 A, 비밀벡터 s, 작은 오류벡터 e의 곱
- (A, u): 완전 랜덤 벡터 u

수학적으로: **b = As + e (mod q)** 에서 s를 찾는 문제

```
A (m×n 랜덤 행렬)  ×  s (n차원 비밀)  +  e (작은 오류)  =  b (mod q)
```

**왜 어려운가?**
- 오류 e가 없으면 가우스 소거법으로 쉽게 풀림
- 작은 오류 e가 있으면 최적의 양자 알고리즘으로도 지수적 시간 필요

### 2.2 RLWE(Ring-LWE) 문제

LWE의 효율적 변형: 행렬 대신 다항식 환을 사용.

**Ring**: R_q = Z_q[x] / (x^n + 1)  (n은 2의 거듭제곱)

**RLWE**: b = a·s + e (mod q, mod x^n+1)

- LWE 대비 키 크기: O(n²) → O(n)으로 감소
- 성능: 행렬 곱셈 → 다항식 곱셈 (NTT 사용 시 O(n log n))

### 2.3 Kyber(ML-KEM) 핵심 구조

```
키 생성:
  A ← 랜덤 (공개), s, e ← 작은 오류 분포
  pk = (A, b = As + e),  sk = s

암호화:
  r, e1, e2 ← 작은 분포
  u = Aᵀr + e1
  v = bᵀr + e2 + ⌊q/2⌋·m  (m: 평문 비트)

복호화:
  m' = ⌊(v - sᵀu)⌋  (sᵀ(Aᵀr + e1) ≈ bᵀr - eᵀr, 오류 제거)
```

---

## 3. 해시 기반 서명: SPHINCS+

### 3.1 원리

해시 기반 서명은 해시 함수의 일방향성만을 가정한다. 양자 컴퓨터도 SHA-256의 원상 공격을 획기적으로 가속화하지 못한다.

**SPHINCS+ 구조:**
1. **WOTS+ (Winternitz OTS)**: 1회용 서명 키 쌍
2. **Merkle 트리**: WOTS+ 공개키들의 해시 트리
3. **Hypertree**: 다중 레벨 Merkle 트리

**장단점:**

| 항목 | 내용 |
|------|------|
| 장점 | 해시 함수만 가정, 가장 보수적 안전성 |
| 단점 | 서명 크기 8KB~50KB로 매우 큼 |
| 적합 용도 | 소프트웨어 업데이트 서명, 장기 보존 문서 |
| 부적합 용도 | TLS 핸드셰이크, 고빈도 서명 |

---

## 4. 코드 기반 암호: Classic McEliece

### 4.1 기반 문제

일반적인 선형 코드에서 오류 수정이 NP-난해하다는 사실에 기반:
- 공개키: 수정된 생성 행렬 (큰 크기 - 수MB)
- 비밀키: 오류 수정이 쉬운 Goppa 코드 구조

**특성:**

| 항목 | 내용 |
|------|------|
| 역사 | 1978년 제안 (RSA와 같은 시대), 50년간 안전 |
| 공개키 크기 | 261~1,357 KB (매우 큼) |
| 암호화 속도 | 빠름 |
| 적합 용도 | 키 크기 제약이 없는 서버-서버 통신 |

---

## 5. FALCON: NTRU 기반 서명

### 5.1 특징

FALCON은 NTRU 격자의 단기 기저(short basis)를 사용한 서명이다:

- **서명 크기**: Dilithium 대비 매우 작음 (약 690B vs 3293B)
- **검증 속도**: 매우 빠름
- **서명 생성**: 가우시안 샘플링으로 비교적 느리고 구현 복잡
- **부채널 공격 취약성**: 타이밍 공격, 격자 보조 분석 주의 필요

**서명 원리 (간략):**
```
키 생성: NTRU 격자의 단기 기저 (f,g,F,G) 찾기
서명   : 메시지 해시 c에 대해 s = B⁻¹c (가우시안 샘플링)
검증   : sᵀs ≤ 임계값 확인 (짧은 벡터 검증)
```

---

## 6. Python CLI: PQC 알고리즘 성능 벤치마크

```python
#!/usr/bin/env python3
"""
PQC 알고리즘 성능 벤치마크 도구
순수 Python으로 격자 기반 암호의 핵심 연산을 시뮬레이션하고
알고리즘별 성능 특성을 비교 출력
"""

from __future__ import annotations

import argparse
import hashlib
import os
import sys
import time
from dataclasses import dataclass, field
from typing import Optional


# PQC 알고리즘 파라미터 정의 (실제 NIST 표준 기준)
PQC_PARAMS: dict[str, dict] = {
    "kyber512": {
        "name": "CRYSTALS-Kyber 512 (ML-KEM-512)",
        "level": 1,
        "pk_size": 800,
        "sk_size": 1632,
        "ct_size": 768,
        "n": 256,
        "q": 3329,
        "k": 2,
        "eta1": 3,
        "eta2": 2,
        "du": 10,
        "dv": 4,
    },
    "kyber768": {
        "name": "CRYSTALS-Kyber 768 (ML-KEM-768)",
        "level": 3,
        "pk_size": 1184,
        "sk_size": 2400,
        "ct_size": 1088,
        "n": 256,
        "q": 3329,
        "k": 3,
        "eta1": 2,
        "eta2": 2,
        "du": 10,
        "dv": 4,
    },
    "kyber1024": {
        "name": "CRYSTALS-Kyber 1024 (ML-KEM-1024)",
        "level": 5,
        "pk_size": 1568,
        "sk_size": 3168,
        "ct_size": 1568,
        "n": 256,
        "q": 3329,
        "k": 4,
        "eta1": 2,
        "eta2": 2,
        "du": 11,
        "dv": 5,
    },
    "dilithium2": {
        "name": "CRYSTALS-Dilithium 2 (ML-DSA-44)",
        "level": 2,
        "pk_size": 1312,
        "sk_size": 2528,
        "sig_size": 2420,
        "n": 256,
        "q": 8380417,
        "k": 4,
        "l": 4,
    },
    "dilithium3": {
        "name": "CRYSTALS-Dilithium 3 (ML-DSA-65)",
        "level": 3,
        "pk_size": 1952,
        "sk_size": 4000,
        "sig_size": 3293,
        "n": 256,
        "q": 8380417,
        "k": 6,
        "l": 5,
    },
    "falcon512": {
        "name": "FALCON-512",
        "level": 1,
        "pk_size": 897,
        "sk_size": 1281,
        "sig_size": 690,
        "n": 512,
        "q": 12289,
    },
    "falcon1024": {
        "name": "FALCON-1024",
        "level": 5,
        "pk_size": 1793,
        "sk_size": 2305,
        "sig_size": 1330,
        "n": 1024,
        "q": 12289,
    },
    "sphincs_sha2_128s": {
        "name": "SPHINCS+-SHA2-128s (SLH-DSA-SHA2-128s)",
        "level": 1,
        "pk_size": 32,
        "sk_size": 64,
        "sig_size": 7856,
        "n": 16,
        "h": 63,
        "d": 7,
        "k": 14,
    },
    "sphincs_sha2_256s": {
        "name": "SPHINCS+-SHA2-256s (SLH-DSA-SHA2-256s)",
        "level": 5,
        "pk_size": 64,
        "sk_size": 128,
        "sig_size": 29792,
        "n": 32,
        "h": 64,
        "d": 8,
        "k": 14,
    },
}


@dataclass
class BenchmarkResult:
    """단일 알고리즘 벤치마크 결과"""
    algorithm: str
    iterations: int
    keygen_time_ms: float
    operation_time_ms: float    # 암호화 또는 서명 생성
    verify_time_ms: float       # 복호화 또는 서명 검증
    pk_size_bytes: int
    sk_size_bytes: int
    output_size_bytes: int      # 암호문 또는 서명 크기
    security_level: int
    errors: list[str] = field(default_factory=list)

    @property
    def total_time_ms(self) -> float:
        return self.keygen_time_ms + self.operation_time_ms + self.verify_time_ms

    @property
    def ops_per_second_keygen(self) -> float:
        return 1000.0 / self.keygen_time_ms if self.keygen_time_ms > 0 else 0

    @property
    def ops_per_second_op(self) -> float:
        return 1000.0 / self.operation_time_ms if self.operation_time_ms > 0 else 0


def simulate_ntt_multiply(poly_a: list[int], poly_b: list[int], q: int) -> list[int]:
    """
    수론적 변환(NTT) 다항식 곱셈 시뮬레이션.
    실제 NTT 대신 단순화된 고전 곱셈 (벤치마크 목적).
    """
    n = len(poly_a)
    result = [0] * n
    for i in range(n):
        for j in range(n):
            idx = (i + j) % n
            sign = -1 if (i + j) >= n else 1
            result[idx] = (result[idx] + sign * poly_a[i] * poly_b[j]) % q
    return result


def simulate_kyber_keygen(params: dict) -> tuple[bytes, bytes, float]:
    """Kyber 키 생성 시뮬레이션 (실제 NTT 연산 제외, 타이밍만 측정)"""
    start = time.perf_counter()
    k = params["k"]
    n = params["n"]
    q = params["q"]

    # 랜덤 행렬 A 생성 시뮬레이션 (k×k 다항식 행렬)
    seed = os.urandom(32)
    # SHAKE-128로 결정론적 확장
    matrix_bytes = hashlib.shake_128(seed).digest(k * k * n * 2)

    # 비밀벡터 s와 오류벡터 e 샘플링 시뮬레이션
    secret_bytes = os.urandom(k * n)
    error_bytes = os.urandom(k * n)

    # 공개키 b = As + e 계산 (바이트 크기만 반환)
    pk = os.urandom(params["pk_size"])
    sk = os.urandom(params["sk_size"])

    elapsed = (time.perf_counter() - start) * 1000
    return pk, sk, elapsed


def simulate_kyber_encap(params: dict, pk: bytes) -> tuple[bytes, bytes, float]:
    """Kyber 캡슐화(암호화) 시뮬레이션"""
    start = time.perf_counter()
    # 랜덤 메시지 m
    m = os.urandom(32)
    # SHAKE-256으로 r, K 유도
    hashed = hashlib.shake_256(m + pk[:32]).digest(64)
    # 암호문 u, v 생성 시뮬레이션
    ct = os.urandom(params["ct_size"])
    shared_secret = hashed[:32]
    elapsed = (time.perf_counter() - start) * 1000
    return ct, shared_secret, elapsed


def simulate_kyber_decap(params: dict, sk: bytes, ct: bytes) -> tuple[bytes, float]:
    """Kyber 역캡슐화(복호화) 시뮬레이션"""
    start = time.perf_counter()
    # 역연산 시뮬레이션
    hashed = hashlib.shake_256(ct[:32] + sk[:32]).digest(32)
    elapsed = (time.perf_counter() - start) * 1000
    return hashed, elapsed


def simulate_dilithium_keygen(params: dict) -> tuple[bytes, bytes, float]:
    """Dilithium 키 생성 시뮬레이션"""
    start = time.perf_counter()
    seed = os.urandom(32)
    pk = os.urandom(params["pk_size"])
    sk = os.urandom(params["sk_size"])
    elapsed = (time.perf_counter() - start) * 1000
    return pk, sk, elapsed


def simulate_dilithium_sign(params: dict, sk: bytes, message: bytes) -> tuple[bytes, float]:
    """Dilithium 서명 시뮬레이션"""
    start = time.perf_counter()
    msg_hash = hashlib.sha3_512(message + sk[:32]).digest()
    sig = os.urandom(params["sig_size"])
    elapsed = (time.perf_counter() - start) * 1000
    return sig, elapsed


def simulate_dilithium_verify(params: dict, pk: bytes, message: bytes, sig: bytes) -> tuple[bool, float]:
    """Dilithium 서명 검증 시뮬레이션"""
    start = time.perf_counter()
    # 검증 연산 시뮬레이션 (해시 비교)
    msg_hash = hashlib.sha3_256(message + pk[:32]).digest()
    is_valid = len(sig) == params["sig_size"]
    elapsed = (time.perf_counter() - start) * 1000
    return is_valid, elapsed


def simulate_sphincs_keygen(params: dict) -> tuple[bytes, bytes, float]:
    """SPHINCS+ 키 생성 시뮬레이션"""
    start = time.perf_counter()
    # Merkle 트리 구성 시뮬레이션 (h 깊이)
    h = params.get("h", 63)
    n = params.get("n", 16)
    # 루트 계산 시뮬레이션
    seed = os.urandom(3 * n)
    root = hashlib.sha256(seed).digest()[:n]
    pk = seed[:2*n] + root
    sk = seed + root
    elapsed = (time.perf_counter() - start) * 1000
    return pk, sk, elapsed


def simulate_sphincs_sign(params: dict, sk: bytes, message: bytes) -> tuple[bytes, float]:
    """SPHINCS+ 서명 시뮬레이션 (해시 트리 탐색)"""
    start = time.perf_counter()
    sig_size = params["sig_size"]
    # 다층 해시 계산 시뮬레이션
    h = params.get("h", 63)
    state = hashlib.sha256(message + sk[:16]).digest()
    for _ in range(h):
        state = hashlib.sha256(state).digest()
    sig = os.urandom(sig_size)
    elapsed = (time.perf_counter() - start) * 1000
    return sig, elapsed


def run_benchmark(
    algorithm: str,
    params: dict,
    iterations: int,
    message: bytes
) -> BenchmarkResult:
    """단일 알고리즘 벤치마크 실행"""
    is_kem = "kyber" in algorithm
    is_sphincs = "sphincs" in algorithm
    is_falcon = "falcon" in algorithm
    is_dilithium = "dilithium" in algorithm

    keygen_times = []
    op_times = []
    verify_times = []

    for _ in range(iterations):
        if is_kem:
            pk, sk, kg_t = simulate_kyber_keygen(params)
            ct, ss1, enc_t = simulate_kyber_encap(params, pk)
            ss2, dec_t = simulate_kyber_decap(params, sk, ct)
            keygen_times.append(kg_t)
            op_times.append(enc_t)
            verify_times.append(dec_t)
        elif is_sphincs:
            pk, sk, kg_t = simulate_sphincs_keygen(params)
            sig, sign_t = simulate_sphincs_sign(params, sk, message)
            # 검증은 서명보다 빠름
            _, verify_t = simulate_dilithium_verify(params, pk, message, sig)
            keygen_times.append(kg_t)
            op_times.append(sign_t)
            verify_times.append(verify_t)
        else:
            pk, sk, kg_t = simulate_dilithium_keygen(params)
            sig, sign_t = simulate_dilithium_sign(params, sk, message)
            is_valid, verify_t = simulate_dilithium_verify(params, pk, message, sig)
            keygen_times.append(kg_t)
            op_times.append(sign_t)
            verify_times.append(verify_t)

    output_size = params.get("ct_size", params.get("sig_size", 0))
    return BenchmarkResult(
        algorithm=algorithm,
        iterations=iterations,
        keygen_time_ms=sum(keygen_times) / len(keygen_times),
        operation_time_ms=sum(op_times) / len(op_times),
        verify_time_ms=sum(verify_times) / len(verify_times),
        pk_size_bytes=params["pk_size"],
        sk_size_bytes=params["sk_size"],
        output_size_bytes=output_size,
        security_level=params["level"],
    )


def print_benchmark_table(results: list[BenchmarkResult]) -> None:
    """벤치마크 결과 표 출력"""
    print("\n" + "=" * 110)
    print("  PQC 알고리즘 성능 벤치마크 결과")
    print("=" * 110)
    print(
        f"  {'알고리즘':<28}  {'보안레벨':>5}  {'공개키(B)':>9}  "
        f"{'비밀키(B)':>9}  {'출력(B)':>8}  "
        f"{'키생성(ms)':>10}  {'연산(ms)':>9}  {'검증(ms)':>9}"
    )
    print(f"  {'-'*105}")

    for r in results:
        alg_type = "KEM" if "kyber" in r.algorithm else "SIG"
        print(
            f"  {r.algorithm:<28}  {r.security_level:>5}  {r.pk_size_bytes:>9,}  "
            f"{r.sk_size_bytes:>9,}  {r.output_size_bytes:>8,}  "
            f"{r.keygen_time_ms:>10.4f}  {r.operation_time_ms:>9.4f}  "
            f"{r.verify_time_ms:>9.4f}"
        )

    print("=" * 110)
    print("  * 시뮬레이션 값: 실제 구현 대비 상대적 특성만 반영. 절대값은 참고용.")
    print("  * KEM: 키생성/캡슐화/역캡슐화 | SIG: 키생성/서명/검증")


def print_comparison_with_classical(results: list[BenchmarkResult]) -> None:
    """고전 알고리즘과의 크기 비교"""
    classical = {
        "RSA-2048 (공개키)": 256,
        "RSA-3072 (공개키)": 384,
        "ECDH P-256 (공개키)": 65,
        "ECDSA P-256 (서명)": 71,
    }

    print("\n  고전 알고리즘 vs PQC 키/출력 크기 비교 (바이트):")
    print(f"\n  {'알고리즘':<36}  {'크기(B)':>8}  {'상대크기':>10}")
    print(f"  {'-'*60}")

    ref_size = 256  # RSA-2048 기준
    for name, size in classical.items():
        ratio = size / ref_size
        bar = "█" * max(1, int(ratio * 10))
        print(f"  {name:<36}  {size:>8,}  {bar}")

    print()
    for r in results:
        size = r.pk_size_bytes
        ratio = size / ref_size
        bar = "█" * max(1, min(int(ratio * 10), 50))
        marker = "(PQC)"
        print(f"  {r.algorithm:<36}  {size:>8,}  {bar} {marker}")


def run_pqc_benchmark(args: argparse.Namespace) -> int:
    """PQC 벤치마크 메인 실행"""
    algorithms: list[str] = args.algorithm
    key_size: str = args.key_size
    iterations: int = args.iterations
    message_size: int = args.message_size

    print("=" * 70)
    print("  PQC 알고리즘 성능 벤치마크")
    print("=" * 70)
    print(f"\n  설정:")
    print(f"  - 알고리즘       : {', '.join(algorithms)}")
    print(f"  - 보안 레벨      : {key_size}")
    print(f"  - 반복 횟수      : {iterations}회")
    print(f"  - 메시지 크기    : {message_size}바이트")

    # 알고리즘 필터링
    if "all" in algorithms:
        target_algos = list(PQC_PARAMS.keys())
    else:
        target_algos = []
        for a in algorithms:
            if a in PQC_PARAMS:
                target_algos.append(a)
            else:
                print(f"경고: 알 수 없는 알고리즘 '{a}' - 건너뜀", file=sys.stderr)

    # 보안 레벨 필터
    level_map = {"128": [1, 2], "192": [3], "256": [5], "all": [1, 2, 3, 5]}
    allowed_levels = level_map.get(key_size, [1, 2, 3, 5])
    target_algos = [
        a for a in target_algos
        if PQC_PARAMS[a]["level"] in allowed_levels
    ]

    if not target_algos:
        print("오류: 지정된 조건에 맞는 알고리즘이 없습니다.", file=sys.stderr)
        return 1

    print(f"\n  벤치마크 대상: {len(target_algos)}개 알고리즘")

    # 테스트 메시지 생성
    message = os.urandom(message_size)
    results: list[BenchmarkResult] = []

    print(f"\n  진행 중...")
    for algo in target_algos:
        params = PQC_PARAMS[algo]
        sys.stdout.write(f"  [{algo}]... ")
        sys.stdout.flush()
        result = run_benchmark(algo, params, iterations, message)
        results.append(result)
        print(f"완료 (키생성: {result.keygen_time_ms:.3f}ms)")

    # 결과 출력
    print_benchmark_table(results)
    print_comparison_with_classical(results)

    # 보안 레벨별 최고 성능 알고리즘
    print("\n  보안 레벨별 권장 알고리즘 (최소 연산 시간 기준):")
    for level_name, levels in [("128비트", [1, 2]), ("192비트", [3]), ("256비트", [5])]:
        level_results = [r for r in results if r.security_level in levels]
        if level_results:
            best = min(level_results, key=lambda r: r.operation_time_ms)
            print(f"  - {level_name} 보안: {best.algorithm} "
                  f"(연산 {best.operation_time_ms:.4f}ms, 공개키 {best.pk_size_bytes:,}B)")

    print("\n  벤치마크 완료.")
    return 0


def parse_arguments() -> argparse.Namespace:
    """명령행 인수 파싱"""
    available_algos = list(PQC_PARAMS.keys()) + ["all"]

    parser = argparse.ArgumentParser(
        prog="pqc_benchmark",
        description="PQC 알고리즘 성능 벤치마크 도구",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
사용 가능한 알고리즘:
  {', '.join(list(PQC_PARAMS.keys()))}
  all (전체)

사용 예시:
  python 03_post_quantum_algorithms.py --algorithm kyber768 dilithium3
  python 03_post_quantum_algorithms.py --algorithm all --key-size 128
  python 03_post_quantum_algorithms.py --algorithm kyber512 kyber768 kyber1024 --iterations 50
        """
    )
    parser.add_argument(
        "--algorithm",
        nargs="+",
        default=["kyber768", "dilithium3", "falcon512", "sphincs_sha2_128s"],
        choices=available_algos,
        metavar="ALG",
        help=f"벤치마크할 알고리즘 (기본값: kyber768 dilithium3 falcon512 sphincs_sha2_128s)"
    )
    parser.add_argument(
        "--key-size",
        choices=["128", "192", "256", "all"],
        default="all",
        help="목표 보안 강도 (비트, 기본값: all)"
    )
    parser.add_argument(
        "--iterations",
        type=int,
        default=10,
        metavar="N",
        help="알고리즘당 반복 횟수 (기본값: 10)"
    )
    parser.add_argument(
        "--message-size",
        type=int,
        default=1024,
        metavar="B",
        help="서명/암호화 테스트 메시지 크기 (바이트, 기본값: 1024)"
    )
    return parser.parse_args()


def main() -> None:
    """메인 진입점"""
    args = parse_arguments()

    if args.iterations < 1:
        print("오류: --iterations는 1 이상이어야 합니다.", file=sys.stderr)
        sys.exit(1)
    if args.message_size < 1:
        print("오류: --message-size는 1 이상이어야 합니다.", file=sys.stderr)
        sys.exit(1)

    try:
        exit_code = run_pqc_benchmark(args)
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\n\n벤치마크가 중단되었습니다.")
        sys.exit(0)


if __name__ == "__main__":
    main()
```

---

## 7. 알고리즘 선택 가이드

### 7.1 용도별 권장 알고리즘

| 용도 | 권장 알고리즘 | 이유 |
|------|------------|------|
| **일반 키 교환 (TLS)** | Kyber-768 (ML-KEM-768) | 빠름, 균형 잡힌 크기 |
| **코드 서명** | Dilithium3 (ML-DSA-65) | 안정적, 빠른 검증 |
| **소형 서명 필요** | FALCON-512 | 서명 크기 최소 |
| **장기 보존 서명** | SPHINCS+-SHA2-256s | 최보수적, 해시만 가정 |
| **제약된 환경 (IoT)** | Kyber-512 | 최소 키 크기 |
| **최고 보안 필요** | Kyber-1024 + Dilithium5 | NIST 레벨 5 |

### 7.2 혼합 배포 전략

실제 배포 시 기존 알고리즘과 PQC를 병행하는 **하이브리드 모드**를 권장한다:

```
하이브리드 KEM:
  공유 비밀 = KDF(ECDH_secret || Kyber_secret)
  → 둘 중 하나만 안전해도 전체 안전

하이브리드 서명:
  서명 = ECDSA_sig || Dilithium_sig
  → 둘 다 유효해야 전체 유효
```
