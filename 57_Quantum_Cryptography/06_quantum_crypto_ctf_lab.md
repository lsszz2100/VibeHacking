> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 양자 암호학 CTF 실습 랩

## 랩 개요

양자 컴퓨팅 시대의 암호학적 취약점을 CTF 형식으로 학습한다. 쇼어 알고리즘, 그로버 알고리즘, 후양자 암호의 약점을 실습한다.

## 챌린지 1: 소인수 분해 (Shor's Algorithm 모방)

```python
#!/usr/bin/env python3
"""양자 알고리즘 기반 암호 공격 CTF."""

import argparse
import math
import random
import sys
from dataclasses import dataclass


@dataclass
class RSAChallenge:
    n: int        # 모듈러스
    e: int        # 공개 지수
    ciphertext: int


def generate_weak_rsa(bits: int = 64) -> tuple[int, int, int, int]:
    """약한 RSA 키 생성 (작은 소수)."""
    def is_prime(n: int) -> bool:
        if n < 2:
            return False
        if n % 2 == 0:
            return n == 2
        for i in range(3, int(n**0.5) + 1, 2):
            if n % i == 0:
                return False
        return True

    def gen_prime(bits: int) -> int:
        while True:
            n = random.getrandbits(bits) | 1
            if is_prime(n):
                return n

    p = gen_prime(bits // 2)
    q = gen_prime(bits // 2)
    while p == q:
        q = gen_prime(bits // 2)

    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    d = pow(e, -1, phi)
    return p, q, n, e


def pollard_rho_factorization(n: int) -> int:
    """Pollard's Rho 소인수 분해 (양자 효율의 고전 근사)."""
    if n % 2 == 0:
        return 2

    x = random.randint(2, n - 1)
    y = x
    c = random.randint(1, n - 1)
    d = 1

    while d == 1:
        x = (x * x + c) % n
        y = (y * y + c) % n
        y = (y * y + c) % n
        d = math.gcd(abs(x - y), n)

    return d if d != n else None


def factor_with_pollard(n: int, max_tries: int = 100) -> tuple[int, int] | None:
    """소인수 분해 반복 시도."""
    for _ in range(max_tries):
        d = pollard_rho_factorization(n)
        if d and d != n:
            return d, n // d
    return None


def rsa_decrypt_from_factors(
    c: int, n: int, e: int, p: int, q: int
) -> int:
    """소인수에서 RSA 복호화."""
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)
    return pow(c, d, n)


def challenge_factor_rsa(bits: int = 64) -> dict:
    """RSA 소인수 분해 챌린지 생성."""
    p, q, n, e = generate_weak_rsa(bits)
    # 비밀 메시지 (플래그)
    flag = b"CTF{quantum_breaks_rsa_crypto}"
    m = int.from_bytes(flag, "big")

    if m >= n:
        m = m % n  # 길이 제한

    c = pow(m, e, n)
    return {
        "challenge": f"RSA-{bits}",
        "n": n,
        "e": e,
        "ciphertext": c,
        "p": p,  # 정답 검증용
        "q": q,
        "flag": flag.decode(),
    }


def solve_rsa_challenge(n: int, e: int, c: int) -> str | None:
    """RSA 챌린지 풀기."""
    print(f"[*] 소인수 분해 시도: n={n}")
    result = factor_with_pollard(n)
    if not result:
        print("[-] 소인수 분해 실패")
        return None
    p, q = result
    print(f"[+] 소인수 발견: p={p}, q={q}")
    m = rsa_decrypt_from_factors(c, n, e, p, q)
    try:
        byte_len = (m.bit_length() + 7) // 8
        flag = m.to_bytes(byte_len, "big").decode("utf-8", errors="replace")
        return flag
    except Exception:
        return str(m)


def main_rsa() -> None:
    ch = challenge_factor_rsa(bits=64)
    print(f"[챌린지] RSA 소인수 분해")
    print(f"  N = {ch['n']}")
    print(f"  e = {ch['e']}")
    print(f"  암호문 = {ch['ciphertext']}")
    print(f"\n[*] 풀이 시도...")
    flag = solve_rsa_challenge(ch["n"], ch["e"], ch["ciphertext"])
    if flag:
        print(f"[+] 복호화 성공: {flag}")
```

## 챌린지 2: 그로버 알고리즘 — 해시 역상 공격

```python
#!/usr/bin/env python3
"""그로버 알고리즘 시뮬레이션 — 해시 역상 탐색."""

import hashlib
import time
import argparse


def grover_classical_simulation(
    target_hash: str,
    prefix: str = "CTF{",
    suffix: str = "}",
    charset: str = "abcdefghijklmnopqrstuvwxyz0123456789_",
    max_length: int = 10,
) -> str | None:
    """
    그로버 알고리즘의 이점 시뮬레이션:
    - 고전: O(N) 탐색
    - 양자: O(√N) 탐색

    짧은 플래그에 대한 브루트포스 (교육 목적).
    """
    import itertools

    total_searched = 0
    start = time.time()

    for length in range(1, max_length + 1):
        print(f"[*] 길이 {length} 탐색 중...", end="\r")
        for combo in itertools.product(charset, repeat=length):
            candidate = prefix + "".join(combo) + suffix
            candidate_hash = hashlib.md5(candidate.encode()).hexdigest()
            total_searched += 1

            if candidate_hash == target_hash:
                elapsed = time.time() - start
                print(f"\n[+] 발견! '{candidate}' (탐색: {total_searched:,}회, {elapsed:.2f}초)")
                return candidate

            if total_searched % 100000 == 0:
                elapsed = time.time() - start
                rate = total_searched / elapsed
                print(f"[*] {total_searched:,}회 탐색 ({rate:,.0f}/s)...", end="\r")

    return None


def demonstrate_grover_advantage(key_bits: int = 64) -> None:
    """그로버 알고리즘의 양자 이점 시각화."""
    classical_ops = 2 ** key_bits
    quantum_ops = 2 ** (key_bits // 2)  # √N

    print(f"\n[{key_bits}비트 키 공격 비교]")
    print(f"  고전 브루트포스: 2^{key_bits} = {classical_ops:.2e} 연산")
    print(f"  그로버 알고리즘: 2^{key_bits//2} = {quantum_ops:.2e} 연산")
    print(f"  양자 이점 배수: {classical_ops / quantum_ops:.2e}x")

    print(f"\n[AES 키 강도 (양자 컴퓨터 기준)]")
    for bits in [128, 192, 256]:
        effective = bits // 2
        print(f"  AES-{bits}: 양자 유효 강도 ≈ {effective}비트")


def ctf_hash_challenge() -> dict:
    """해시 역상 CTF 챌린지."""
    import random
    import string

    # 쉬운 챌린지 (짧은 플래그)
    chars = string.ascii_lowercase + string.digits + "_"
    inner = "".join(random.choices(chars, k=6))
    flag = f"CTF{{{inner}}}"
    flag_hash = hashlib.md5(flag.encode()).hexdigest()

    return {
        "challenge": "MD5 역상 탐색",
        "hash": flag_hash,
        "hint": "플래그 형식: CTF{[a-z0-9_]{6}}",
        "flag": flag,
        "quantum_advantage": "그로버 알고리즘으로 √N 복잡도",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="양자 암호학 CTF 랩")
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("rsa", help="RSA 소인수 분해 챌린지")
    
    hash_p = sub.add_parser("hash", help="해시 역상 챌린지")
    hash_p.add_argument("--max-length", type=int, default=6)

    adv_p = sub.add_parser("advantage", help="그로버 이점 시연")
    adv_p.add_argument("--bits", type=int, default=64)

    args = parser.parse_args()

    if args.cmd == "rsa":
        main_rsa()

    elif args.cmd == "hash":
        ch = ctf_hash_challenge()
        print(f"[챌린지] MD5 역상 탐색")
        print(f"  해시: {ch['hash']}")
        print(f"  힌트: {ch['hint']}")
        print(f"\n[*] 브루트포스 탐색 (최대 길이: {args.max_length})...")
        result = grover_classical_simulation(
            ch["hash"], max_length=args.max_length
        )
        if result:
            print(f"[+] 플래그: {result}")
        else:
            print(f"[-] 찾지 못함")

    elif args.cmd == "advantage":
        demonstrate_grover_advantage(args.bits)


if __name__ == "__main__":
    main()
```

## 챌린지 3: 후양자 암호 분석

```python
#!/usr/bin/env python3
"""후양자 암호 구현 취약점 CTF."""

import argparse
import random
import numpy as np
from dataclasses import dataclass


@dataclass
class LWEChallenge:
    """LWE (Learning With Errors) 기반 챌린지."""
    n: int      # 차원
    q: int      # 모듈러스
    A: list     # 공개 행렬
    b: list     # 암호화된 벡터
    ciphertext: int


def generate_lwe_challenge(n: int = 10, q: int = 101) -> dict:
    """약한 LWE 인스턴스 생성."""
    # 비밀 키
    s = [random.randint(0, 1) for _ in range(n)]

    # 공개 행렬
    A = [[random.randint(0, q - 1) for _ in range(n)]
         for _ in range(n)]

    # 작은 오류 (CTF용 — 실제로는 더 큰 오류)
    errors = [random.choice([-1, 0, 0, 0, 1]) for _ in range(n)]

    # b = As + e (mod q)
    b = []
    for i in range(n):
        bi = sum(A[i][j] * s[j] for j in range(n)) + errors[i]
        b.append(bi % q)

    # 플래그 암호화 (s 해시)
    import hashlib
    s_bytes = bytes(s)
    flag_hash = hashlib.sha256(s_bytes).hexdigest()[:16]
    flag = f"CTF{{lwe_{flag_hash}}}"

    return {
        "n": n,
        "q": q,
        "A": A,
        "b": b,
        "s": s,           # 정답 검증용
        "flag": flag,
        "hint": "작은 오류 → 반올림으로 비밀 키 복구",
    }


def solve_weak_lwe(A: list, b: list, q: int) -> list[int] | None:
    """약한 LWE 솔버 (오류가 작은 경우)."""
    n = len(b)
    # Babai's nearest plane 근사 (간략화)
    try:
        import numpy as np
        A_np = np.array(A, dtype=float)
        b_np = np.array(b, dtype=float)
        # 최소 제곱법으로 s 추정
        s_approx, _, _, _ = np.linalg.lstsq(A_np, b_np, rcond=None)
        s_rounded = [round(x) % q for x in s_approx]
        return s_rounded
    except Exception:
        return None


def pqc_ctf_demo() -> None:
    """후양자 암호 CTF 데모."""
    print("[*] LWE 기반 챌린지 생성 (n=10, q=101)")
    ch = generate_lwe_challenge(n=10, q=101)

    print(f"  공개 행렬 A (10x10, mod {ch['q']})")
    print(f"  벡터 b = As + e (mod {ch['q']})")
    print(f"\n  목표: 비밀 키 s를 복구하여 플래그를 획득하세요")

    print(f"\n[*] 풀이 시도...")
    s_found = solve_weak_lwe(ch["A"], ch["b"], ch["q"])

    if s_found and s_found == ch["s"]:
        print(f"[+] 비밀 키 복구 성공!")
        print(f"    s = {s_found}")
        print(f"    플래그: {ch['flag']}")
    else:
        print(f"[-] 근사값: {s_found}")
        print(f"    실제 s: {ch['s']}")
        print(f"    힌트: 오류 범위가 작으므로 반올림이 효과적")


if __name__ == "__main__":
    pqc_ctf_demo()
```

## 실습 과제

```
초급 (50~100점)
☐ 작은 RSA (64비트) 소인수 분해
☐ MD5 해시 역상 (6자리 플래그)
☐ 약한 LWE 인스턴스 복호화

중급 (200~300점)
☐ Wiener 공격 (작은 d)
☐ Hastad Broadcast 공격 (동일 메시지, 여러 수신자)
☐ ECDSA nonce 재사용 공격

고급 (400~500점)
☐ 격자 기반 공격 (LLL 알고리즘)
☐ 측채널 공격 시뮬레이션
☐ CRYSTALS-Kyber 파라미터 취약점 분석
```

양자 컴퓨팅 시대의 암호학은 **기존 RSA/ECC 기반 시스템의 전면 교체**를 요구한다. 후양자 암호로의 전환은 지금 시작해야 한다.

---

<a name="english"></a>

# Quantum Cryptography CTF Lab

## Lab Overview

Study cryptographic vulnerabilities in the quantum computing era through CTF format. Practice Shor's algorithm, Grover's algorithm, and weaknesses in post-quantum cryptography.

## Challenge 1: Integer Factorization (Shor's Algorithm Simulation)

```python
#!/usr/bin/env python3
"""CTF for quantum algorithm-based cryptographic attacks."""

import argparse
import math
import random
import sys
from dataclasses import dataclass


@dataclass
class RSAChallenge:
    n: int        # modulus
    e: int        # public exponent
    ciphertext: int


def generate_weak_rsa(bits: int = 64) -> tuple[int, int, int, int]:
    """Generate weak RSA keys (small primes)."""
    def is_prime(n: int) -> bool:
        if n < 2:
            return False
        if n % 2 == 0:
            return n == 2
        for i in range(3, int(n**0.5) + 1, 2):
            if n % i == 0:
                return False
        return True

    def gen_prime(bits: int) -> int:
        while True:
            n = random.getrandbits(bits) | 1
            if is_prime(n):
                return n

    p = gen_prime(bits // 2)
    q = gen_prime(bits // 2)
    while p == q:
        q = gen_prime(bits // 2)

    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    d = pow(e, -1, phi)
    return p, q, n, e


def pollard_rho_factorization(n: int) -> int:
    """Pollard's Rho factorization (classical approximation of quantum efficiency)."""
    if n % 2 == 0:
        return 2

    x = random.randint(2, n - 1)
    y = x
    c = random.randint(1, n - 1)
    d = 1

    while d == 1:
        x = (x * x + c) % n
        y = (y * y + c) % n
        y = (y * y + c) % n
        d = math.gcd(abs(x - y), n)

    return d if d != n else None


def factor_with_pollard(n: int, max_tries: int = 100) -> tuple[int, int] | None:
    """Repeated factorization attempts."""
    for _ in range(max_tries):
        d = pollard_rho_factorization(n)
        if d and d != n:
            return d, n // d
    return None


def rsa_decrypt_from_factors(
    c: int, n: int, e: int, p: int, q: int
) -> int:
    """RSA decryption from prime factors."""
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)
    return pow(c, d, n)


def challenge_factor_rsa(bits: int = 64) -> dict:
    """Generate RSA factorization challenge."""
    p, q, n, e = generate_weak_rsa(bits)
    # Secret message (flag)
    flag = b"CTF{quantum_breaks_rsa_crypto}"
    m = int.from_bytes(flag, "big")

    if m >= n:
        m = m % n  # length constraint

    c = pow(m, e, n)
    return {
        "challenge": f"RSA-{bits}",
        "n": n,
        "e": e,
        "ciphertext": c,
        "p": p,  # for answer verification
        "q": q,
        "flag": flag.decode(),
    }


def solve_rsa_challenge(n: int, e: int, c: int) -> str | None:
    """Solve RSA challenge."""
    print(f"[*] Attempting factorization: n={n}")
    result = factor_with_pollard(n)
    if not result:
        print("[-] Factorization failed")
        return None
    p, q = result
    print(f"[+] Factors found: p={p}, q={q}")
    m = rsa_decrypt_from_factors(c, n, e, p, q)
    try:
        byte_len = (m.bit_length() + 7) // 8
        flag = m.to_bytes(byte_len, "big").decode("utf-8", errors="replace")
        return flag
    except Exception:
        return str(m)


def main_rsa() -> None:
    ch = challenge_factor_rsa(bits=64)
    print(f"[Challenge] RSA Factorization")
    print(f"  N = {ch['n']}")
    print(f"  e = {ch['e']}")
    print(f"  Ciphertext = {ch['ciphertext']}")
    print(f"\n[*] Attempting solution...")
    flag = solve_rsa_challenge(ch["n"], ch["e"], ch["ciphertext"])
    if flag:
        print(f"[+] Decryption successful: {flag}")
```

## Challenge 2: Grover's Algorithm — Hash Preimage Attack

```python
#!/usr/bin/env python3
"""Grover's algorithm simulation — hash preimage search."""

import hashlib
import time
import argparse


def grover_classical_simulation(
    target_hash: str,
    prefix: str = "CTF{",
    suffix: str = "}",
    charset: str = "abcdefghijklmnopqrstuvwxyz0123456789_",
    max_length: int = 10,
) -> str | None:
    """
    Simulation of Grover's algorithm advantage:
    - Classical: O(N) search
    - Quantum: O(√N) search

    Brute force for short flags (educational purposes).
    """
    import itertools

    total_searched = 0
    start = time.time()

    for length in range(1, max_length + 1):
        print(f"[*] Searching length {length}...", end="\r")
        for combo in itertools.product(charset, repeat=length):
            candidate = prefix + "".join(combo) + suffix
            candidate_hash = hashlib.md5(candidate.encode()).hexdigest()
            total_searched += 1

            if candidate_hash == target_hash:
                elapsed = time.time() - start
                print(f"\n[+] Found! '{candidate}' (searched: {total_searched:,} attempts, {elapsed:.2f}s)")
                return candidate

            if total_searched % 100000 == 0:
                elapsed = time.time() - start
                rate = total_searched / elapsed
                print(f"[*] {total_searched:,} searched ({rate:,.0f}/s)...", end="\r")

    return None


def demonstrate_grover_advantage(key_bits: int = 64) -> None:
    """Visualize Grover's algorithm quantum advantage."""
    classical_ops = 2 ** key_bits
    quantum_ops = 2 ** (key_bits // 2)  # √N

    print(f"\n[{key_bits}-bit Key Attack Comparison]")
    print(f"  Classical brute force: 2^{key_bits} = {classical_ops:.2e} operations")
    print(f"  Grover's algorithm: 2^{key_bits//2} = {quantum_ops:.2e} operations")
    print(f"  Quantum speedup: {classical_ops / quantum_ops:.2e}x")

    print(f"\n[AES Key Strength (against quantum computers)]")
    for bits in [128, 192, 256]:
        effective = bits // 2
        print(f"  AES-{bits}: effective quantum strength ≈ {effective} bits")


def ctf_hash_challenge() -> dict:
    """Hash preimage CTF challenge."""
    import random
    import string

    # Easy challenge (short flag)
    chars = string.ascii_lowercase + string.digits + "_"
    inner = "".join(random.choices(chars, k=6))
    flag = f"CTF{{{inner}}}"
    flag_hash = hashlib.md5(flag.encode()).hexdigest()

    return {
        "challenge": "MD5 Preimage Search",
        "hash": flag_hash,
        "hint": "Flag format: CTF{[a-z0-9_]{6}}",
        "flag": flag,
        "quantum_advantage": "O(√N) complexity with Grover's algorithm",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Quantum Cryptography CTF Lab")
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("rsa", help="RSA factorization challenge")
    
    hash_p = sub.add_parser("hash", help="Hash preimage challenge")
    hash_p.add_argument("--max-length", type=int, default=6)

    adv_p = sub.add_parser("advantage", help="Demonstrate Grover's advantage")
    adv_p.add_argument("--bits", type=int, default=64)

    args = parser.parse_args()

    if args.cmd == "rsa":
        main_rsa()

    elif args.cmd == "hash":
        ch = ctf_hash_challenge()
        print(f"[Challenge] MD5 Preimage Search")
        print(f"  Hash: {ch['hash']}")
        print(f"  Hint: {ch['hint']}")
        print(f"\n[*] Brute force search (max length: {args.max_length})...")
        result = grover_classical_simulation(
            ch["hash"], max_length=args.max_length
        )
        if result:
            print(f"[+] Flag: {result}")
        else:
            print(f"[-] Not found")

    elif args.cmd == "advantage":
        demonstrate_grover_advantage(args.bits)


if __name__ == "__main__":
    main()
```

## Challenge 3: Post-Quantum Cryptography Analysis

```python
#!/usr/bin/env python3
"""Post-quantum cryptography implementation vulnerability CTF."""

import argparse
import random
import numpy as np
from dataclasses import dataclass


@dataclass
class LWEChallenge:
    """LWE (Learning With Errors) based challenge."""
    n: int      # dimension
    q: int      # modulus
    A: list     # public matrix
    b: list     # encrypted vector
    ciphertext: int


def generate_lwe_challenge(n: int = 10, q: int = 101) -> dict:
    """Generate a weak LWE instance."""
    # Secret key
    s = [random.randint(0, 1) for _ in range(n)]

    # Public matrix
    A = [[random.randint(0, q - 1) for _ in range(n)]
         for _ in range(n)]

    # Small errors (for CTF — real implementations use larger errors)
    errors = [random.choice([-1, 0, 0, 0, 1]) for _ in range(n)]

    # b = As + e (mod q)
    b = []
    for i in range(n):
        bi = sum(A[i][j] * s[j] for j in range(n)) + errors[i]
        b.append(bi % q)

    # Encrypt flag (hash of s)
    import hashlib
    s_bytes = bytes(s)
    flag_hash = hashlib.sha256(s_bytes).hexdigest()[:16]
    flag = f"CTF{{lwe_{flag_hash}}}"

    return {
        "n": n,
        "q": q,
        "A": A,
        "b": b,
        "s": s,           # for answer verification
        "flag": flag,
        "hint": "Small errors → recover secret key by rounding",
    }


def solve_weak_lwe(A: list, b: list, q: int) -> list[int] | None:
    """Weak LWE solver (when errors are small)."""
    n = len(b)
    # Babai's nearest plane approximation (simplified)
    try:
        import numpy as np
        A_np = np.array(A, dtype=float)
        b_np = np.array(b, dtype=float)
        # Estimate s using least squares
        s_approx, _, _, _ = np.linalg.lstsq(A_np, b_np, rcond=None)
        s_rounded = [round(x) % q for x in s_approx]
        return s_rounded
    except Exception:
        return None


def pqc_ctf_demo() -> None:
    """Post-quantum cryptography CTF demo."""
    print("[*] Generating LWE challenge (n=10, q=101)")
    ch = generate_lwe_challenge(n=10, q=101)

    print(f"  Public matrix A (10x10, mod {ch['q']})")
    print(f"  Vector b = As + e (mod {ch['q']})")
    print(f"\n  Objective: Recover secret key s to obtain the flag")

    print(f"\n[*] Attempting solution...")
    s_found = solve_weak_lwe(ch["A"], ch["b"], ch["q"])

    if s_found and s_found == ch["s"]:
        print(f"[+] Secret key successfully recovered!")
        print(f"    s = {s_found}")
        print(f"    Flag: {ch['flag']}")
    else:
        print(f"[-] Approximation: {s_found}")
        print(f"    Actual s: {ch['s']}")
        print(f"    Hint: Small error range makes rounding effective")


if __name__ == "__main__":
    pqc_ctf_demo()
```

## Practice Exercises

```
Beginner (50~100 points)
☐ Factor small RSA (64-bit)
☐ MD5 hash preimage (6-character flag)
☐ Decode weak LWE instance

Intermediate (200~300 points)
☐ Wiener's attack (small d)
☐ Hastad Broadcast attack (same message, multiple recipients)
☐ ECDSA nonce reuse attack

Advanced (400~500 points)
☐ Lattice-based attack (LLL algorithm)
☐ Side-channel attack simulation
☐ CRYSTALS-Kyber parameter vulnerability analysis
```

Cryptography in the quantum computing era demands a **complete replacement of existing RSA/ECC-based systems**. The transition to post-quantum cryptography must begin now.
