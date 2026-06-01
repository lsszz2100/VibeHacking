> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 암호학 CTF 실습 랩 — 고전암호·RSA·ECC·해시 종합

## 1. 실습 환경

### 필수 패키지 설치

```bash
pip install pycryptodome sympy gmpy2
```

### CTF 암호 문제 분류표

| 분류 | 대표 기법 | 난이도 | 주요 도구 |
|------|-----------|--------|-----------|
| 고전 암호 | Caesar, Vigenere, Playfair, Rail Fence | ★☆☆ | 빈도 분석, Kasiski |
| 대칭 암호 | AES ECB/CBC, DES, RC4 | ★★☆ | PyCryptodome, 블록 분석 |
| 비대칭 암호 | RSA, ECC, ElGamal | ★★★ | sympy, gmpy2, SageMath |
| 해시 | MD5, SHA, HMAC, 길이 확장 | ★★☆ | hashlib, hashpumpy |
| 기타 | XOR, OTP, LFSR | ★☆☆ | 통계 분석, Z3 |

### 디렉터리 구조

```
crypto_ctf_lab/
├── rsa_attacker.py          # CTF 문제 1: RSA 공격
├── classical_solver.py      # CTF 문제 2: 고전 암호 해독
├── hash_extender.py         # CTF 문제 3: 해시 길이 확장
├── xor_breaker.py           # CTF 문제 4: XOR 키 복구
└── tests/
    ├── test_rsa.py
    ├── test_classical.py
    └── test_hash.py
```

---

## 2. CTF 문제 1: RSA 취약 구현 공격

### 배경 이론

RSA의 안전성은 큰 소수의 인수분해 어려움에 기반한다.
그러나 구현 실수나 파라미터 선택 오류가 있으면 여러 공격이 가능하다.

| 공격 기법 | 조건 | 복잡도 |
|-----------|------|--------|
| Small-e (e=3) Cube Root | e=3, 패딩 없음 | O(n^(1/3)) |
| 공통 모듈러스 | 같은 n, 다른 e | gcd 계산 |
| Wiener 공격 | d < n^0.25 | 연분수 전개 |
| Fermat 인수분해 | p ≈ q | 반복 제곱근 |

### 2.1 Cube Root Attack (e=3)

평문 m에 패딩 없이 e=3으로 암호화하면:

```
c = m^3 mod n
```

m이 충분히 작으면 `c = m^3` (mod 연산 없이)이므로 세제곱근으로 복원 가능.

### 2.2 공통 모듈러스 공격

같은 n, 서로소인 e1·e2로 같은 m을 암호화:

```
c1 = m^e1 mod n
c2 = m^e2 mod n
gcd(e1, e2) = 1이면 → a*e1 + b*e2 = 1 (베주 정리)
→ c1^a * c2^b = m mod n
```

### 2.3 Wiener 공격

d가 작으면(d < n^0.25) e/n의 연분수 전개에서 d를 복원할 수 있다.

### 2.4 Fermat 인수분해

p와 q가 가까우면 n ≈ ((p+q)/2)^2이므로 제곱근 근방 탐색으로 인수분해 가능.

### Python CLI: RSA 공격 자동화

```python
#!/usr/bin/env python3
"""
rsa_attacker.py — RSA 취약 구현 공격 자동화 CLI
사용: python rsa_attacker.py --mode small-e --n <N> --e <E> --c <C>
"""

import argparse
import sys
from typing import Optional
from sympy import integer_nthroot, gcd, mod_inverse
from fractions import Fraction


def cube_root_attack(n: int, e: int, c: int) -> Optional[int]:
    """e=3 소지수 공격: 세제곱근으로 평문 복원"""
    if e != 3:
        print(f"[!] e={e}이지만 e=3만 지원합니다.")
        return None

    # 패딩 없는 경우: c = m^3 (mod 없이)
    m, exact = integer_nthroot(c, 3)
    if exact:
        print(f"[+] Cube root attack 성공 (패딩 없음)")
        return m

    # mod 환경: Broadcast attack (c < n인 경우만 유효)
    print("[-] 직접 세제곱근 실패. n 범위 내 검색 시도...")
    # 단순 탐색 (n이 작은 경우)
    for k in range(10000):
        candidate = k * n + c
        m, exact = integer_nthroot(candidate, 3)
        if exact:
            print(f"[+] k={k}에서 성공")
            return m
    return None


def common_modulus_attack(n: int, e1: int, c1: int, e2: int, c2: int) -> Optional[int]:
    """공통 모듈러스 공격: gcd(e1,e2)=1 조건 필요"""
    g = int(gcd(e1, e2))
    if g != 1:
        print(f"[!] gcd(e1,e2)={g} ≠ 1, 공통 모듈러스 공격 불가")
        return None

    # 베주 계수 계산
    def extended_gcd(a: int, b: int) -> tuple[int, int, int]:
        if b == 0:
            return a, 1, 0
        g, x, y = extended_gcd(b, a % b)
        return g, y, x - (a // b) * y

    _, a, b = extended_gcd(e1, e2)
    print(f"[*] 베주 계수: a={a}, b={b}")

    # c1^a * c2^b mod n
    if a < 0:
        c1 = mod_inverse(c1, n)
        a = -a
    if b < 0:
        c2 = mod_inverse(c2, n)
        b = -b

    m = (pow(c1, a, n) * pow(c2, b, n)) % n
    return m


def continued_fraction_convergents(numerator: int, denominator: int):
    """연분수 전개의 수렴자(convergents) 생성"""
    a = numerator // denominator
    convergents = []
    h_prev, h_curr = 1, a
    k_prev, k_curr = 0, 1

    while True:
        convergents.append((h_curr, k_curr))
        numerator, denominator = denominator, numerator - a * denominator
        if denominator == 0:
            break
        a = numerator // denominator
        h_prev, h_curr = h_curr, a * h_curr + h_prev
        k_prev, k_curr = k_curr, a * k_curr + k_prev

    return convergents


def wiener_attack(n: int, e: int) -> Optional[int]:
    """Wiener 공격: e/n 연분수 전개로 작은 d 복원"""
    convergents = continued_fraction_convergents(e, n)

    for k, d in convergents:
        if k == 0:
            continue
        if (e * d - 1) % k != 0:
            continue
        phi_n = (e * d - 1) // k

        # x^2 - (n - phi_n + 1)x + n = 0 판별식 검사
        b = n - phi_n + 1
        discriminant = b * b - 4 * n
        if discriminant < 0:
            continue
        sqrt_disc, exact = integer_nthroot(discriminant, 2)
        if exact and (b + sqrt_disc) % 2 == 0:
            p = (b + sqrt_disc) // 2
            q = (b - sqrt_disc) // 2
            if p * q == n:
                print(f"[+] Wiener 공격 성공! d={d}, p={p}, q={q}")
                return d
    return None


def fermat_factorize(n: int, max_iter: int = 1_000_000) -> Optional[tuple[int, int]]:
    """Fermat 인수분해: p ≈ q인 경우 빠르게 동작"""
    a, exact = integer_nthroot(n, 2)
    if exact:
        return a, a  # 완전제곱수

    a += 1
    for _ in range(max_iter):
        b2 = a * a - n
        b, exact = integer_nthroot(b2, 2)
        if exact:
            p, q = a - b, a + b
            print(f"[+] Fermat 인수분해 성공! p={p}, q={q}")
            return p, q
        a += 1
    return None


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="RSA 취약 구현 공격 자동화",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
사용 예시:
  python rsa_attacker.py --mode small-e --n 3233 --e 3 --c 855
  python rsa_attacker.py --mode common-modulus --n 3233 --e 17 --c 2790 --e2 65537 --c2 1000
  python rsa_attacker.py --mode wiener --n 90581 --e 17993
  python rsa_attacker.py --mode fermat --n 18923
        """
    )
    parser.add_argument("--mode", required=True,
                        choices=["small-e", "common-modulus", "wiener", "fermat"],
                        help="공격 모드 선택")
    parser.add_argument("--n", type=int, help="RSA 모듈러스 N")
    parser.add_argument("--e", type=int, help="공개 지수 e")
    parser.add_argument("--c", type=int, help="암호문 c")
    parser.add_argument("--e2", type=int, help="두 번째 공개 지수 (common-modulus용)")
    parser.add_argument("--c2", type=int, help="두 번째 암호문 (common-modulus용)")
    parser.add_argument("--max-iter", type=int, default=1_000_000,
                        help="Fermat 최대 반복 횟수 (기본값: 1000000)")
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    match args.mode:
        case "small-e":
            if not all([args.n, args.e, args.c]):
                print("[!] --n, --e, --c 필수", file=sys.stderr)
                sys.exit(1)
            result = cube_root_attack(args.n, args.e, args.c)
            if result:
                print(f"[+] 복원된 평문 (정수): {result}")
                try:
                    print(f"[+] 복원된 평문 (ASCII): {bytes.fromhex(hex(result)[2:]).decode()}")
                except Exception:
                    pass

        case "common-modulus":
            if not all([args.n, args.e, args.c, args.e2, args.c2]):
                print("[!] --n, --e, --c, --e2, --c2 필수", file=sys.stderr)
                sys.exit(1)
            result = common_modulus_attack(args.n, args.e, args.c, args.e2, args.c2)
            if result:
                print(f"[+] 복원된 평문: {result}")

        case "wiener":
            if not all([args.n, args.e]):
                print("[!] --n, --e 필수", file=sys.stderr)
                sys.exit(1)
            d = wiener_attack(args.n, args.e)
            if d:
                print(f"[+] 복원된 비밀키 d={d}")
            else:
                print("[-] Wiener 공격 실패 (d가 충분히 작지 않음)")

        case "fermat":
            if not args.n:
                print("[!] --n 필수", file=sys.stderr)
                sys.exit(1)
            result = fermat_factorize(args.n, args.max_iter)
            if result:
                p, q = result
                print(f"[+] 인수분해 결과: p={p}, q={q}")
            else:
                print("[-] Fermat 인수분해 실패 (p, q가 너무 다름)")


if __name__ == "__main__":
    main()
```

---

## 3. CTF 문제 2: 고전 암호 해독

### 빈도 분석 이론

영어 텍스트의 문자 빈도:

| 순위 | 문자 | 빈도(%) |
|------|------|---------|
| 1 | E | 12.70 |
| 2 | T | 9.06 |
| 3 | A | 8.17 |
| 4 | O | 7.51 |
| 5 | I | 6.97 |

### 각 암호 해독 전략

| 암호 | 핵심 취약점 | 해독 전략 |
|------|-------------|-----------|
| Caesar | 단일 치환, 키공간 26 | 전수 탐색 |
| Vigenere | 반복 키 | Kasiski + 인덱스 일치도(IC) |
| Rail Fence | 레일 수 소수 | 레일 수 브루트포스 |
| Playfair | 이중 문자 치환 | 빈도 분석 + 탐색 |

### Python CLI: 고전 암호 자동 해독기

```python
#!/usr/bin/env python3
"""
classical_solver.py — 고전 암호 자동 해독기 CLI
사용: python classical_solver.py --cipher caesar --ciphertext "Khoor Zruog"
"""

import argparse
import sys
import math
import string
from collections import Counter
from typing import Optional


# 영어 문자 빈도표
ENGLISH_FREQ: dict[str, float] = {
    'A': 0.0817, 'B': 0.0150, 'C': 0.0278, 'D': 0.0425, 'E': 0.1270,
    'F': 0.0223, 'G': 0.0202, 'H': 0.0609, 'I': 0.0697, 'J': 0.0015,
    'K': 0.0077, 'L': 0.0403, 'M': 0.0241, 'N': 0.0675, 'O': 0.0751,
    'P': 0.0193, 'Q': 0.0010, 'R': 0.0599, 'S': 0.0633, 'T': 0.0906,
    'U': 0.0276, 'V': 0.0098, 'W': 0.0236, 'X': 0.0015, 'Y': 0.0197,
    'Z': 0.0007,
}


def index_of_coincidence(text: str) -> float:
    """인덱스 일치도(IC) 계산"""
    text = ''.join(c for c in text.upper() if c.isalpha())
    n = len(text)
    if n < 2:
        return 0.0
    counts = Counter(text)
    return sum(c * (c - 1) for c in counts.values()) / (n * (n - 1))


def chi_squared_score(text: str) -> float:
    """카이제곱 통계로 영어 유사도 측정 (낮을수록 영어에 가까움)"""
    text = ''.join(c for c in text.upper() if c.isalpha())
    n = len(text)
    if n == 0:
        return float('inf')
    counts = Counter(text)
    score = 0.0
    for ch in string.ascii_uppercase:
        observed = counts.get(ch, 0)
        expected = ENGLISH_FREQ[ch] * n
        score += (observed - expected) ** 2 / expected
    return score


def caesar_decrypt(ciphertext: str, shift: int) -> str:
    """Caesar 복호화"""
    result = []
    for ch in ciphertext:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            result.append(chr((ord(ch) - base - shift) % 26 + base))
        else:
            result.append(ch)
    return ''.join(result)


def solve_caesar(ciphertext: str, key_guess: Optional[int] = None) -> str:
    """Caesar 암호 해독 (키 모르면 전수 탐색)"""
    if key_guess is not None:
        return caesar_decrypt(ciphertext, key_guess)

    best_shift = 0
    best_score = float('inf')
    for shift in range(26):
        candidate = caesar_decrypt(ciphertext, shift)
        score = chi_squared_score(candidate)
        if score < best_score:
            best_score = score
            best_shift = shift

    print(f"[*] 추정 키(shift): {best_shift}")
    return caesar_decrypt(ciphertext, best_shift)


def kasiski_key_length(ciphertext: str, min_len: int = 2, max_len: int = 20) -> list[int]:
    """Kasiski 테스트로 Vigenere 키 길이 후보 추정"""
    text = ''.join(c for c in ciphertext.upper() if c.isalpha())
    distances = []

    for ngram_len in range(3, 6):
        for i in range(len(text) - ngram_len):
            ngram = text[i:i + ngram_len]
            j = text.find(ngram, i + 1)
            if j != -1:
                distances.append(j - i)

    if not distances:
        return list(range(min_len, max_len + 1))

    from math import gcd
    from functools import reduce
    factor_counts: Counter = Counter()
    for d in distances:
        for f in range(2, min(d + 1, max_len + 1)):
            if d % f == 0:
                factor_counts[f] += 1

    candidates = sorted(factor_counts, key=lambda x: -factor_counts[x])
    return candidates[:5] if candidates else list(range(min_len, max_len + 1))


def solve_vigenere(ciphertext: str, key_guess: Optional[str] = None) -> str:
    """Vigenere 암호 해독"""
    text = ''.join(c for c in ciphertext.upper() if c.isalpha())

    if key_guess:
        key = key_guess.upper()
        result = []
        key_idx = 0
        for ch in ciphertext:
            if ch.isalpha():
                shift = ord(key[key_idx % len(key)]) - ord('A')
                base = ord('A') if ch.isupper() else ord('a')
                result.append(chr((ord(ch.upper()) - ord('A') - shift) % 26 + base))
                key_idx += 1
            else:
                result.append(ch)
        return ''.join(result)

    # 자동 키 복구
    key_lengths = kasiski_key_length(ciphertext)
    best_key = ""
    best_score = float('inf')

    for key_len in key_lengths[:3]:
        recovered_key = []
        for col in range(key_len):
            column = text[col::key_len]
            col_best_shift = 0
            col_best_score = float('inf')
            for shift in range(26):
                candidate = caesar_decrypt(column, shift)
                score = chi_squared_score(candidate)
                if score < col_best_score:
                    col_best_score = score
                    col_best_shift = shift
            recovered_key.append(chr(col_best_shift + ord('A')))

        key_str = ''.join(recovered_key)
        decrypted = solve_vigenere(ciphertext, key_str)
        score = chi_squared_score(decrypted)
        if score < best_score:
            best_score = score
            best_key = key_str

    print(f"[*] 추정 키: {best_key}")
    return solve_vigenere(ciphertext, best_key)


def solve_railfence(ciphertext: str, rails: Optional[int] = None) -> str:
    """Rail Fence 암호 해독"""
    def decrypt_railfence(text: str, num_rails: int) -> str:
        n = len(text)
        pattern = []
        rail = 0
        direction = 1
        for i in range(n):
            pattern.append(rail)
            if rail == 0:
                direction = 1
            elif rail == num_rails - 1:
                direction = -1
            rail += direction

        indices = sorted(range(n), key=lambda x: pattern[x])
        result = [''] * n
        for i, idx in enumerate(indices):
            result[idx] = text[i]
        return ''.join(result)

    if rails is not None:
        return decrypt_railfence(ciphertext, rails)

    best_result = ""
    best_score = float('inf')
    for r in range(2, min(len(ciphertext), 20)):
        candidate = decrypt_railfence(ciphertext, r)
        score = chi_squared_score(candidate)
        if score < best_score:
            best_score = score
            best_result = candidate
            print(f"[*] rails={r}, 점수={score:.2f}")

    return best_result


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="고전 암호 자동 해독기",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
사용 예시:
  python classical_solver.py --cipher caesar --ciphertext "Khoor Zruog"
  python classical_solver.py --cipher vigenere --ciphertext "Rijvs Uyvjn" --key-guess KEY
  python classical_solver.py --cipher railfence --ciphertext "HloWrd el ol"
        """
    )
    parser.add_argument("--cipher", required=True,
                        choices=["caesar", "vigenere", "railfence", "playfair"],
                        help="암호 종류 선택")
    parser.add_argument("--ciphertext", required=True, help="해독할 암호문")
    parser.add_argument("--key-guess", help="키 추측값 (없으면 자동 분석)")
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    match args.cipher:
        case "caesar":
            key = int(args.key_guess) if args.key_guess else None
            result = solve_caesar(args.ciphertext, key)
            print(f"[+] 복호화 결과: {result}")

        case "vigenere":
            result = solve_vigenere(args.ciphertext, args.key_guess)
            print(f"[+] 복호화 결과: {result}")

        case "railfence":
            rails = int(args.key_guess) if args.key_guess else None
            result = solve_railfence(args.ciphertext, rails)
            print(f"[+] 복호화 결과: {result}")

        case "playfair":
            print("[!] Playfair 자동 해독은 사전 기반 탐색이 필요합니다.")
            print("[*] 추천: https://www.dcode.fr/playfair-cipher")


if __name__ == "__main__":
    main()
```

---

## 4. CTF 문제 3: 해시 길이 확장 공격

### 공격 원리

SHA-256, MD5는 Merkle-Damgård 구조를 사용한다.
메시지 m의 해시를 알면, 내부 상태를 복원하여 `m || padding || extra` 의 해시를 계산할 수 있다.

```
H(secret || message) 을 알고 있을 때
H(secret || message || padding || extra) 계산 가능
```

### 취약 패턴

```python
# 취약한 MAC 구현
mac = sha256(secret + user_data)
# → 길이 확장 공격으로 user_data 뒤에 arbitrary 데이터 추가 가능
```

### Python 구현: 해시 길이 확장 공격

```python
#!/usr/bin/env python3
"""
hash_extender.py — SHA-256/MD5 해시 길이 확장 공격 구현
사용: python hash_extender.py --hash <hex> --orig-len <N> --append "data" --secret-len <K>
"""

import argparse
import struct
import hashlib
import sys


def md_padding(msg_len: int, is_sha256: bool = True) -> bytes:
    """Merkle-Damgård 패딩 계산"""
    bit_len = msg_len * 8
    padding = b'\x80'
    # 56 mod 64 바이트가 될 때까지 0x00 추가
    padding += b'\x00' * ((55 - msg_len) % 64)
    if is_sha256:
        padding += struct.pack('>Q', bit_len)  # SHA: big-endian
    else:
        padding += struct.pack('<Q', bit_len)  # MD5: little-endian
    return padding


class SHA256Extension:
    """SHA-256 내부 상태 주입 기반 길이 확장"""

    def __init__(self, known_hash: str, secret_len: int, orig_msg: bytes) -> None:
        self.state = self._parse_state(known_hash)
        self.secret_len = secret_len
        self.orig_msg = orig_msg

    def _parse_state(self, hex_hash: str) -> list[int]:
        """16진수 해시에서 SHA-256 내부 상태(8개 워드) 추출"""
        raw = bytes.fromhex(hex_hash)
        return list(struct.unpack('>8I', raw))

    def extend(self, append_data: bytes) -> tuple[bytes, str]:
        """
        Returns:
            (forged_message, forged_hash)
            forged_message = orig_msg || padding || append_data
        """
        orig_total = self.secret_len + len(self.orig_msg)
        padding = md_padding(orig_total, is_sha256=True)
        forged_msg = self.orig_msg + padding + append_data

        # 내부 상태를 known_hash로 초기화하여 append_data만 계산
        new_total = self.secret_len + len(forged_msg)
        forged_hash = self._sha256_from_state(
            self.state,
            append_data,
            orig_total + len(padding)
        )
        return forged_msg, forged_hash

    def _sha256_from_state(
        self, state: list[int], data: bytes, processed_len: int
    ) -> str:
        """주어진 내부 상태에서 계속하여 SHA-256 계산"""
        # Python hashlib은 내부 상태 주입 미지원 → struct로 직접 구현
        # 실제 CTF에서는 hashpumpy 라이브러리 사용 권장
        import hashlib
        # 시뮬레이션: 시크릿+원본+패딩을 포함한 전체 메시지 해시
        # (데모용: 실제 내부 상태 주입은 C 확장 필요)
        print("[*] 실제 구현은 hashpumpy 사용 권장:")
        print("    pip install hashpumpy")
        print("    import hashpumpy")
        print("    new_sig, new_msg = hashpumpy.hashpump(known_hash, orig_msg, append_data, secret_len)")
        return "데모: hashpumpy 사용 필요"


def demonstrate_vulnerability() -> None:
    """길이 확장 공격 취약성 시연"""
    secret = b"supersecret"
    message = b"user=guest"

    mac = hashlib.sha256(secret + message).hexdigest()
    print(f"[*] 원본 MAC: {mac}")
    print(f"[*] 원본 메시지: {message}")
    print(f"[*] 비밀키 길이: {len(secret)}")

    padding = md_padding(len(secret) + len(message))
    append = b"&role=admin"
    forged_msg = message + padding + append

    # 실제 공격에서는 내부 상태를 재구성해야 함
    # 여기서는 검증 목적으로 전체 메시지로 계산
    forged_mac = hashlib.sha256(secret + forged_msg).hexdigest()
    print(f"\n[+] 위조된 메시지: {forged_msg}")
    print(f"[+] 위조된 MAC: {forged_mac}")
    print(f"\n[!] 서버가 H(secret || forged_msg) == forged_mac 을 검증하면 통과!")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="해시 길이 확장 공격 도구",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
사용 예시:
  python hash_extender.py --demo
  python hash_extender.py --hash abc123... --orig-msg "user=guest" --append "&role=admin" --secret-len 11
        """
    )
    parser.add_argument("--demo", action="store_true", help="취약성 시연 실행")
    parser.add_argument("--hash", help="알려진 MAC 해시 (hex)")
    parser.add_argument("--orig-msg", help="원본 메시지")
    parser.add_argument("--append", help="추가할 데이터")
    parser.add_argument("--secret-len", type=int, help="비밀키 길이")
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    if args.demo:
        demonstrate_vulnerability()
        return

    if not all([args.hash, args.orig_msg, args.append, args.secret_len]):
        print("[!] --hash, --orig-msg, --append, --secret-len 모두 필요", file=sys.stderr)
        sys.exit(1)

    extender = SHA256Extension(
        args.hash,
        args.secret_len,
        args.orig_msg.encode()
    )
    forged_msg, forged_hash = extender.extend(args.append.encode())
    print(f"[+] 위조 메시지 (hex): {forged_msg.hex()}")
    print(f"[+] 위조 해시: {forged_hash}")


if __name__ == "__main__":
    main()
```

---

## 5. CTF 문제 4: XOR 암호 해독

### 반복 XOR 키 복구 이론

반복 키 XOR에서 키 길이 k를 알면:
- 0, k, 2k, ... 번째 바이트들은 같은 키 바이트로 암호화됨
- 각 열에 대해 단일 바이트 XOR 탐색 → 카이제곱 통계로 판별

### 키 길이 탐지

인덱스 일치도(IC)로 키 길이 탐지:
- 같은 키로 암호화된 열의 IC ≈ 0.065 (영어 텍스트)
- 다른 키 열의 IC ≈ 0.038 (균일 분포)

### Python CLI: XOR 키 복구기

```python
#!/usr/bin/env python3
"""
xor_breaker.py — 반복 XOR 암호 키 복구 CLI
사용: python xor_breaker.py --ciphertext-file enc.bin --max-keylen 32 --output plain.txt
"""

import argparse
import sys
import math
import string
from pathlib import Path
from collections import Counter


ENGLISH_FREQ: dict[str, float] = {
    'A': 0.0817, 'B': 0.0150, 'C': 0.0278, 'D': 0.0425, 'E': 0.1270,
    'F': 0.0223, 'G': 0.0202, 'H': 0.0609, 'I': 0.0697, 'J': 0.0015,
    'K': 0.0077, 'L': 0.0403, 'M': 0.0241, 'N': 0.0675, 'O': 0.0751,
    'P': 0.0193, 'Q': 0.0010, 'R': 0.0599, 'S': 0.0633, 'T': 0.0906,
    'U': 0.0276, 'V': 0.0098, 'W': 0.0236, 'X': 0.0015, 'Y': 0.0197,
    'Z': 0.0007,
}


def hamming_distance(b1: bytes, b2: bytes) -> int:
    """두 바이트 시퀀스의 해밍 거리"""
    return sum(bin(x ^ y).count('1') for x, y in zip(b1, b2))


def normalized_hamming(data: bytes, key_len: int, samples: int = 4) -> float:
    """정규화된 해밍 거리로 키 길이 평가 (낮을수록 유력)"""
    blocks = [data[i * key_len:(i + 1) * key_len]
              for i in range(min(samples, len(data) // key_len))]
    if len(blocks) < 2:
        return float('inf')

    distances = []
    for i in range(len(blocks) - 1):
        dist = hamming_distance(blocks[i], blocks[i + 1])
        distances.append(dist / key_len)
    return sum(distances) / len(distances)


def guess_key_length(data: bytes, max_keylen: int) -> list[int]:
    """해밍 거리 기반 키 길이 후보 정렬"""
    scores = []
    for kl in range(1, min(max_keylen + 1, len(data) // 2)):
        score = normalized_hamming(data, kl)
        scores.append((kl, score))
    scores.sort(key=lambda x: x[1])
    return [kl for kl, _ in scores[:5]]


def chi_squared(column: bytes) -> float:
    """단일 바이트 복호 카이제곱 점수 (영어 텍스트 기준)"""
    n = len(column)
    if n == 0:
        return float('inf')
    counts = Counter(column)
    score = 0.0
    for ch in string.ascii_uppercase:
        observed = counts.get(ord(ch), 0) + counts.get(ord(ch.lower()), 0)
        expected = ENGLISH_FREQ[ch] * n
        if expected > 0:
            score += (observed - expected) ** 2 / expected
    return score


def break_single_byte_xor(column: bytes) -> tuple[int, float]:
    """단일 바이트 XOR 키 복구"""
    best_key = 0
    best_score = float('inf')
    for key_byte in range(256):
        decrypted = bytes(b ^ key_byte for b in column)
        score = chi_squared(decrypted)
        if score < best_score:
            best_score = score
            best_key = key_byte
    return best_key, best_score


def recover_xor_key(data: bytes, key_len: int) -> bytes:
    """키 길이를 알 때 전체 XOR 키 복구"""
    key = []
    for col_idx in range(key_len):
        column = bytes(data[i] for i in range(col_idx, len(data), key_len))
        key_byte, score = break_single_byte_xor(column)
        key.append(key_byte)
        print(f"  [*] 키[{col_idx}] = 0x{key_byte:02x} ({chr(key_byte) if 32 <= key_byte < 127 else '?'}), 점수={score:.2f}")
    return bytes(key)


def xor_decrypt(data: bytes, key: bytes) -> bytes:
    """반복 XOR 복호화"""
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="반복 XOR 암호 키 복구기",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
사용 예시:
  python xor_breaker.py --ciphertext-file enc.bin --max-keylen 32 --output plain.txt
  python xor_breaker.py --ciphertext-hex 1a2b3c... --max-keylen 16
        """
    )
    parser.add_argument("--ciphertext-file", help="암호문 바이너리 파일 경로")
    parser.add_argument("--ciphertext-hex", help="암호문 hex 문자열")
    parser.add_argument("--max-keylen", type=int, default=32, help="최대 키 길이 탐색 범위 (기본값: 32)")
    parser.add_argument("--output", help="복호화 결과 저장 파일 (없으면 stdout)")
    parser.add_argument("--key-len", type=int, help="키 길이 직접 지정 (자동 탐지 건너뜀)")
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    # 입력 로드
    if args.ciphertext_file:
        data = Path(args.ciphertext_file).read_bytes()
    elif args.ciphertext_hex:
        data = bytes.fromhex(args.ciphertext_hex)
    else:
        print("[!] --ciphertext-file 또는 --ciphertext-hex 필수", file=sys.stderr)
        sys.exit(1)

    print(f"[*] 암호문 길이: {len(data)} 바이트")

    # 키 길이 결정
    if args.key_len:
        key_length = args.key_len
        print(f"[*] 지정된 키 길이: {key_length}")
    else:
        candidates = guess_key_length(data, args.max_keylen)
        print(f"[*] 키 길이 후보 (해밍 거리 순): {candidates}")
        key_length = candidates[0]
        print(f"[*] 사용할 키 길이: {key_length}")

    # 키 복구
    print(f"\n[*] 키 복구 중 (키 길이={key_length})...")
    key = recover_xor_key(data, key_length)
    key_printable = ''.join(chr(b) if 32 <= b < 127 else f'\\x{b:02x}' for b in key)
    print(f"\n[+] 복구된 키: {key.hex()}")
    print(f"[+] 키 (ASCII): {key_printable}")

    # 복호화
    plaintext = xor_decrypt(data, key)

    if args.output:
        Path(args.output).write_bytes(plaintext)
        print(f"[+] 복호화 결과 저장: {args.output}")
    else:
        print("\n[+] 복호화 결과 (처음 200바이트):")
        try:
            print(plaintext[:200].decode('utf-8', errors='replace'))
        except Exception:
            print(plaintext[:200].hex())


if __name__ == "__main__":
    main()
```

---

## 6. 점수표 및 학습 체크리스트

### 난이도별 CTF 문제 분류표

| 문제 유형 | 난이도 | 예상 점수 | 핵심 기법 | 추천 도구 |
|-----------|--------|-----------|-----------|-----------|
| Caesar/ROT13 | ★☆☆ | 50-100 | 전수 탐색 | CyberChef |
| Vigenere | ★★☆ | 100-200 | Kasiski + IC | dcode.fr |
| Rail Fence | ★☆☆ | 50-100 | 브루트포스 | CyberChef |
| RSA small-e | ★★☆ | 150-250 | 세제곱근 | sympy |
| RSA Wiener | ★★★ | 200-350 | 연분수 전개 | RsaCtfTool |
| Fermat 인수분해 | ★★☆ | 150-250 | p≈q 탐색 | factordb |
| 해시 길이 확장 | ★★★ | 200-350 | 내부 상태 주입 | hashpumpy |
| XOR 반복 키 | ★★☆ | 100-200 | 해밍 거리 + IC | xortool |
| ECC 취약 파라미터 | ★★★★ | 300-500 | pohlig-hellman | SageMath |

### 학습 체크리스트

#### 기초 (입문)
- [ ] 모듈러 산술 (mod, 역원, CRT) 이해
- [ ] XOR 연산 특성 이해
- [ ] Caesar, Vigenere 수동 복호화 가능
- [ ] Python hashlib, struct 기초 사용 가능

#### 중급
- [ ] RSA 수학적 원리 이해 (오일러 정리, 페르마 소정리)
- [ ] 빈도 분석 구현 가능
- [ ] gmpy2, sympy으로 큰 수 연산 가능
- [ ] Wiener 공격 연분수 전개 직접 구현 가능
- [ ] 해시 길이 확장 공격 원리 설명 가능

#### 고급
- [ ] ECC 기초 (타원 곡선 군 연산, ECDLP)
- [ ] Pohlig-Hellman 알고리즘 이해
- [ ] Lattice 기반 공격 (LLL 알고리즘) 개요 파악
- [ ] SageMath 기본 활용 가능
- [ ] RsaCtfTool 옵션 숙지

### 참고 도구 표

| 도구 | 용도 | 링크/설치 |
|------|------|-----------|
| RsaCtfTool | RSA 자동 공격 | `pip install rsactftool` |
| SageMath | 수학 계산 | sagemath.org |
| CyberChef | 다목적 암호 분석 | gchq.github.io/CyberChef |
| dcode.fr | 고전 암호 해독 | dcode.fr |
| hashpumpy | 해시 길이 확장 | `pip install hashpumpy` |
| xortool | XOR 키 분석 | `pip install xortool` |
| factordb | 인수분해 DB | factordb.com |
| pwntools | CTF 익스플로잇 | `pip install pwntools` |

### 빠른 참조: CTF 시나리오별 접근 순서

```
RSA 문제 받았을 때:
1. n, e, c 확인
2. e가 3이면 → Cube Root Attack
3. n이 두 문제에서 같으면 → Common Modulus
4. e가 매우 크면 → Wiener Attack
5. factordb.com에서 n 검색
6. RsaCtfTool --attack all

고전 암호 문제 받았을 때:
1. 문자 집합 확인 (알파벳만? 숫자 포함?)
2. 빈도 분석 → 단일 치환이면 Caesar/Affine
3. IC ≈ 0.065이면 단일 치환, ≈ 0.038이면 복잡한 다중 치환
4. Kasiski 테스트로 키 길이 추정 → Vigenere

해시 문제:
1. 해시 길이 확인 (32=MD5, 64=SHA256)
2. MAC 검증 로직 확인 → H(secret||msg) 패턴이면 길이 확장
3. hashpumpy 사용
```

---

<a name="english"></a>

# Cryptography CTF Practical Lab — Classical Ciphers, RSA, ECC, and Hash Comprehensive

## 1. Lab Environment

### Required Package Installation

```bash
pip install pycryptodome sympy gmpy2
```

### CTF Crypto Problem Classification Table

| Category | Representative Techniques | Difficulty | Key Tools |
|----------|--------------------------|------------|-----------|
| Classical Ciphers | Caesar, Vigenere, Playfair, Rail Fence | ★☆☆ | Frequency analysis, Kasiski |
| Symmetric Ciphers | AES ECB/CBC, DES, RC4 | ★★☆ | PyCryptodome, block analysis |
| Asymmetric Ciphers | RSA, ECC, ElGamal | ★★★ | sympy, gmpy2, SageMath |
| Hash | MD5, SHA, HMAC, length extension | ★★☆ | hashlib, hashpumpy |
| Other | XOR, OTP, LFSR | ★☆☆ | Statistical analysis, Z3 |

### Directory Structure

```
crypto_ctf_lab/
├── rsa_attacker.py          # CTF Challenge 1: RSA attacks
├── classical_solver.py      # CTF Challenge 2: Classical cipher decryption
├── hash_extender.py         # CTF Challenge 3: Hash length extension
├── xor_breaker.py           # CTF Challenge 4: XOR key recovery
└── tests/
    ├── test_rsa.py
    ├── test_classical.py
    └── test_hash.py
```

---

## 2. CTF Challenge 1: RSA Weak Implementation Attacks

### Background Theory

RSA security is based on the difficulty of factoring large primes.
However, implementation mistakes or parameter selection errors enable various attacks.

| Attack Technique | Condition | Complexity |
|-----------------|-----------|------------|
| Small-e (e=3) Cube Root | e=3, no padding | O(n^(1/3)) |
| Common Modulus | Same n, different e | gcd calculation |
| Wiener Attack | d < n^0.25 | Continued fraction expansion |
| Fermat Factorization | p ≈ q | Iterative square root |

### 2.1 Cube Root Attack (e=3)

When plaintext m is encrypted without padding using e=3:

```
c = m^3 mod n
```

If m is small enough, `c = m^3` (without mod operation), so it can be recovered using cube root.

### 2.2 Common Modulus Attack

Same n, same m encrypted with coprime e1·e2:

```
c1 = m^e1 mod n
c2 = m^e2 mod n
If gcd(e1, e2) = 1 → a*e1 + b*e2 = 1 (Bezout's theorem)
→ c1^a * c2^b = m mod n
```

### 2.3 Wiener Attack

If d is small (d < n^0.25), d can be recovered from continued fraction expansion of e/n.

### 2.4 Fermat Factorization

If p and q are close, n ≈ ((p+q)/2)^2, so factorization is possible by searching near the square root.

### Python CLI: RSA Attack Automation

```python
#!/usr/bin/env python3
"""
rsa_attacker.py — RSA weak implementation attack automation CLI
Usage: python rsa_attacker.py --mode small-e --n <N> --e <E> --c <C>
"""

import argparse
import sys
from typing import Optional
from sympy import integer_nthroot, gcd, mod_inverse
from fractions import Fraction


def cube_root_attack(n: int, e: int, c: int) -> Optional[int]:
    """Small exponent attack (e=3): recover plaintext using cube root"""
    if e != 3:
        print(f"[!] e={e} but only e=3 is supported.")
        return None

    # No padding case: c = m^3 (without mod)
    m, exact = integer_nthroot(c, 3)
    if exact:
        print(f"[+] Cube root attack succeeded (no padding)")
        return m

    # Mod environment: Broadcast attack (valid only when c < n)
    print("[-] Direct cube root failed. Attempting search within n range...")
    # Simple search (for small n)
    for k in range(10000):
        candidate = k * n + c
        m, exact = integer_nthroot(candidate, 3)
        if exact:
            print(f"[+] Succeeded at k={k}")
            return m
    return None


def common_modulus_attack(n: int, e1: int, c1: int, e2: int, c2: int) -> Optional[int]:
    """Common modulus attack: requires gcd(e1,e2)=1 condition"""
    g = int(gcd(e1, e2))
    if g != 1:
        print(f"[!] gcd(e1,e2)={g} ≠ 1, common modulus attack not possible")
        return None

    # Calculate Bezout coefficients
    def extended_gcd(a: int, b: int) -> tuple[int, int, int]:
        if b == 0:
            return a, 1, 0
        g, x, y = extended_gcd(b, a % b)
        return g, y, x - (a // b) * y

    _, a, b = extended_gcd(e1, e2)
    print(f"[*] Bezout coefficients: a={a}, b={b}")

    # c1^a * c2^b mod n
    if a < 0:
        c1 = mod_inverse(c1, n)
        a = -a
    if b < 0:
        c2 = mod_inverse(c2, n)
        b = -b

    m = (pow(c1, a, n) * pow(c2, b, n)) % n
    return m


def continued_fraction_convergents(numerator: int, denominator: int):
    """Generate convergents from continued fraction expansion"""
    a = numerator // denominator
    convergents = []
    h_prev, h_curr = 1, a
    k_prev, k_curr = 0, 1

    while True:
        convergents.append((h_curr, k_curr))
        numerator, denominator = denominator, numerator - a * denominator
        if denominator == 0:
            break
        a = numerator // denominator
        h_prev, h_curr = h_curr, a * h_curr + h_prev
        k_prev, k_curr = k_curr, a * k_curr + k_prev

    return convergents


def wiener_attack(n: int, e: int) -> Optional[int]:
    """Wiener attack: recover small d from continued fraction expansion of e/n"""
    convergents = continued_fraction_convergents(e, n)

    for k, d in convergents:
        if k == 0:
            continue
        if (e * d - 1) % k != 0:
            continue
        phi_n = (e * d - 1) // k

        # Check discriminant of x^2 - (n - phi_n + 1)x + n = 0
        b = n - phi_n + 1
        discriminant = b * b - 4 * n
        if discriminant < 0:
            continue
        sqrt_disc, exact = integer_nthroot(discriminant, 2)
        if exact and (b + sqrt_disc) % 2 == 0:
            p = (b + sqrt_disc) // 2
            q = (b - sqrt_disc) // 2
            if p * q == n:
                print(f"[+] Wiener attack succeeded! d={d}, p={p}, q={q}")
                return d
    return None


def fermat_factorize(n: int, max_iter: int = 1_000_000) -> Optional[tuple[int, int]]:
    """Fermat factorization: works quickly when p ≈ q"""
    a, exact = integer_nthroot(n, 2)
    if exact:
        return a, a  # Perfect square

    a += 1
    for _ in range(max_iter):
        b2 = a * a - n
        b, exact = integer_nthroot(b2, 2)
        if exact:
            p, q = a - b, a + b
            print(f"[+] Fermat factorization succeeded! p={p}, q={q}")
            return p, q
        a += 1
    return None


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="RSA weak implementation attack automation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python rsa_attacker.py --mode small-e --n 3233 --e 3 --c 855
  python rsa_attacker.py --mode common-modulus --n 3233 --e 17 --c 2790 --e2 65537 --c2 1000
  python rsa_attacker.py --mode wiener --n 90581 --e 17993
  python rsa_attacker.py --mode fermat --n 18923
        """
    )
    parser.add_argument("--mode", required=True,
                        choices=["small-e", "common-modulus", "wiener", "fermat"],
                        help="Select attack mode")
    parser.add_argument("--n", type=int, help="RSA modulus N")
    parser.add_argument("--e", type=int, help="Public exponent e")
    parser.add_argument("--c", type=int, help="Ciphertext c")
    parser.add_argument("--e2", type=int, help="Second public exponent (for common-modulus)")
    parser.add_argument("--c2", type=int, help="Second ciphertext (for common-modulus)")
    parser.add_argument("--max-iter", type=int, default=1_000_000,
                        help="Fermat max iterations (default: 1000000)")
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    match args.mode:
        case "small-e":
            if not all([args.n, args.e, args.c]):
                print("[!] --n, --e, --c are required", file=sys.stderr)
                sys.exit(1)
            result = cube_root_attack(args.n, args.e, args.c)
            if result:
                print(f"[+] Recovered plaintext (integer): {result}")
                try:
                    print(f"[+] Recovered plaintext (ASCII): {bytes.fromhex(hex(result)[2:]).decode()}")
                except Exception:
                    pass

        case "common-modulus":
            if not all([args.n, args.e, args.c, args.e2, args.c2]):
                print("[!] --n, --e, --c, --e2, --c2 are required", file=sys.stderr)
                sys.exit(1)
            result = common_modulus_attack(args.n, args.e, args.c, args.e2, args.c2)
            if result:
                print(f"[+] Recovered plaintext: {result}")

        case "wiener":
            if not all([args.n, args.e]):
                print("[!] --n, --e are required", file=sys.stderr)
                sys.exit(1)
            d = wiener_attack(args.n, args.e)
            if d:
                print(f"[+] Recovered private key d={d}")
            else:
                print("[-] Wiener attack failed (d not small enough)")

        case "fermat":
            if not args.n:
                print("[!] --n is required", file=sys.stderr)
                sys.exit(1)
            result = fermat_factorize(args.n, args.max_iter)
            if result:
                p, q = result
                print(f"[+] Factorization result: p={p}, q={q}")
            else:
                print("[-] Fermat factorization failed (p, q too different)")


if __name__ == "__main__":
    main()
```

---

## 3. CTF Challenge 2: Classical Cipher Decryption

### Frequency Analysis Theory

Character frequencies in English text:

| Rank | Character | Frequency (%) |
|------|-----------|---------------|
| 1 | E | 12.70 |
| 2 | T | 9.06 |
| 3 | A | 8.17 |
| 4 | O | 7.51 |
| 5 | I | 6.97 |

### Decryption Strategy for Each Cipher

| Cipher | Core Vulnerability | Decryption Strategy |
|--------|-------------------|---------------------|
| Caesar | Single substitution, keyspace 26 | Brute force |
| Vigenere | Repeating key | Kasiski + Index of Coincidence (IC) |
| Rail Fence | Small number of rails | Brute force on rail count |
| Playfair | Digraph substitution | Frequency analysis + search |

### Python CLI: Classical Cipher Auto-Solver

```python
#!/usr/bin/env python3
"""
classical_solver.py — Classical cipher auto-solver CLI
Usage: python classical_solver.py --cipher caesar --ciphertext "Khoor Zruog"
"""

import argparse
import sys
import math
import string
from collections import Counter
from typing import Optional


# English character frequency table
ENGLISH_FREQ: dict[str, float] = {
    'A': 0.0817, 'B': 0.0150, 'C': 0.0278, 'D': 0.0425, 'E': 0.1270,
    'F': 0.0223, 'G': 0.0202, 'H': 0.0609, 'I': 0.0697, 'J': 0.0015,
    'K': 0.0077, 'L': 0.0403, 'M': 0.0241, 'N': 0.0675, 'O': 0.0751,
    'P': 0.0193, 'Q': 0.0010, 'R': 0.0599, 'S': 0.0633, 'T': 0.0906,
    'U': 0.0276, 'V': 0.0098, 'W': 0.0236, 'X': 0.0015, 'Y': 0.0197,
    'Z': 0.0007,
}


def index_of_coincidence(text: str) -> float:
    """Calculate Index of Coincidence (IC)"""
    text = ''.join(c for c in text.upper() if c.isalpha())
    n = len(text)
    if n < 2:
        return 0.0
    counts = Counter(text)
    return sum(c * (c - 1) for c in counts.values()) / (n * (n - 1))


def chi_squared_score(text: str) -> float:
    """Measure English similarity using chi-squared statistics (lower = closer to English)"""
    text = ''.join(c for c in text.upper() if c.isalpha())
    n = len(text)
    if n == 0:
        return float('inf')
    counts = Counter(text)
    score = 0.0
    for ch in string.ascii_uppercase:
        observed = counts.get(ch, 0)
        expected = ENGLISH_FREQ[ch] * n
        score += (observed - expected) ** 2 / expected
    return score


def caesar_decrypt(ciphertext: str, shift: int) -> str:
    """Caesar decryption"""
    result = []
    for ch in ciphertext:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            result.append(chr((ord(ch) - base - shift) % 26 + base))
        else:
            result.append(ch)
    return ''.join(result)


def solve_caesar(ciphertext: str, key_guess: Optional[int] = None) -> str:
    """Caesar cipher decryption (brute force if key unknown)"""
    if key_guess is not None:
        return caesar_decrypt(ciphertext, key_guess)

    best_shift = 0
    best_score = float('inf')
    for shift in range(26):
        candidate = caesar_decrypt(ciphertext, shift)
        score = chi_squared_score(candidate)
        if score < best_score:
            best_score = score
            best_shift = shift

    print(f"[*] Estimated key (shift): {best_shift}")
    return caesar_decrypt(ciphertext, best_shift)


def kasiski_key_length(ciphertext: str, min_len: int = 2, max_len: int = 20) -> list[int]:
    """Estimate Vigenere key length candidates using Kasiski test"""
    text = ''.join(c for c in ciphertext.upper() if c.isalpha())
    distances = []

    for ngram_len in range(3, 6):
        for i in range(len(text) - ngram_len):
            ngram = text[i:i + ngram_len]
            j = text.find(ngram, i + 1)
            if j != -1:
                distances.append(j - i)

    if not distances:
        return list(range(min_len, max_len + 1))

    from math import gcd
    from functools import reduce
    factor_counts: Counter = Counter()
    for d in distances:
        for f in range(2, min(d + 1, max_len + 1)):
            if d % f == 0:
                factor_counts[f] += 1

    candidates = sorted(factor_counts, key=lambda x: -factor_counts[x])
    return candidates[:5] if candidates else list(range(min_len, max_len + 1))


def solve_vigenere(ciphertext: str, key_guess: Optional[str] = None) -> str:
    """Vigenere cipher decryption"""
    text = ''.join(c for c in ciphertext.upper() if c.isalpha())

    if key_guess:
        key = key_guess.upper()
        result = []
        key_idx = 0
        for ch in ciphertext:
            if ch.isalpha():
                shift = ord(key[key_idx % len(key)]) - ord('A')
                base = ord('A') if ch.isupper() else ord('a')
                result.append(chr((ord(ch.upper()) - ord('A') - shift) % 26 + base))
                key_idx += 1
            else:
                result.append(ch)
        return ''.join(result)

    # Automatic key recovery
    key_lengths = kasiski_key_length(ciphertext)
    best_key = ""
    best_score = float('inf')

    for key_len in key_lengths[:3]:
        recovered_key = []
        for col in range(key_len):
            column = text[col::key_len]
            col_best_shift = 0
            col_best_score = float('inf')
            for shift in range(26):
                candidate = caesar_decrypt(column, shift)
                score = chi_squared_score(candidate)
                if score < col_best_score:
                    col_best_score = score
                    col_best_shift = shift
            recovered_key.append(chr(col_best_shift + ord('A')))

        key_str = ''.join(recovered_key)
        decrypted = solve_vigenere(ciphertext, key_str)
        score = chi_squared_score(decrypted)
        if score < best_score:
            best_score = score
            best_key = key_str

    print(f"[*] Estimated key: {best_key}")
    return solve_vigenere(ciphertext, best_key)


def solve_railfence(ciphertext: str, rails: Optional[int] = None) -> str:
    """Rail Fence cipher decryption"""
    def decrypt_railfence(text: str, num_rails: int) -> str:
        n = len(text)
        pattern = []
        rail = 0
        direction = 1
        for i in range(n):
            pattern.append(rail)
            if rail == 0:
                direction = 1
            elif rail == num_rails - 1:
                direction = -1
            rail += direction

        indices = sorted(range(n), key=lambda x: pattern[x])
        result = [''] * n
        for i, idx in enumerate(indices):
            result[idx] = text[i]
        return ''.join(result)

    if rails is not None:
        return decrypt_railfence(ciphertext, rails)

    best_result = ""
    best_score = float('inf')
    for r in range(2, min(len(ciphertext), 20)):
        candidate = decrypt_railfence(ciphertext, r)
        score = chi_squared_score(candidate)
        if score < best_score:
            best_score = score
            best_result = candidate
            print(f"[*] rails={r}, score={score:.2f}")

    return best_result


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Classical cipher auto-solver",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python classical_solver.py --cipher caesar --ciphertext "Khoor Zruog"
  python classical_solver.py --cipher vigenere --ciphertext "Rijvs Uyvjn" --key-guess KEY
  python classical_solver.py --cipher railfence --ciphertext "HloWrd el ol"
        """
    )
    parser.add_argument("--cipher", required=True,
                        choices=["caesar", "vigenere", "railfence", "playfair"],
                        help="Select cipher type")
    parser.add_argument("--ciphertext", required=True, help="Ciphertext to decrypt")
    parser.add_argument("--key-guess", help="Key guess value (auto-analysis if omitted)")
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    match args.cipher:
        case "caesar":
            key = int(args.key_guess) if args.key_guess else None
            result = solve_caesar(args.ciphertext, key)
            print(f"[+] Decryption result: {result}")

        case "vigenere":
            result = solve_vigenere(args.ciphertext, args.key_guess)
            print(f"[+] Decryption result: {result}")

        case "railfence":
            rails = int(args.key_guess) if args.key_guess else None
            result = solve_railfence(args.ciphertext, rails)
            print(f"[+] Decryption result: {result}")

        case "playfair":
            print("[!] Playfair auto-decryption requires dictionary-based search.")
            print("[*] Recommended: https://www.dcode.fr/playfair-cipher")


if __name__ == "__main__":
    main()
```

---

## 4. CTF Challenge 3: Hash Length Extension Attack

### Attack Principle

SHA-256 and MD5 use the Merkle-Damgård construction.
If you know the hash of message m, you can restore the internal state and compute the hash of `m || padding || extra`.

```
When H(secret || message) is known,
H(secret || message || padding || extra) can be computed
```

### Vulnerable Pattern

```python
# Vulnerable MAC implementation
mac = sha256(secret + user_data)
# → Hash length extension attack can append arbitrary data after user_data
```

### Python Implementation: Hash Length Extension Attack

```python
#!/usr/bin/env python3
"""
hash_extender.py — SHA-256/MD5 hash length extension attack implementation
Usage: python hash_extender.py --hash <hex> --orig-len <N> --append "data" --secret-len <K>
"""

import argparse
import struct
import hashlib
import sys


def md_padding(msg_len: int, is_sha256: bool = True) -> bytes:
    """Calculate Merkle-Damgård padding"""
    bit_len = msg_len * 8
    padding = b'\x80'
    # Add 0x00 bytes until 56 mod 64 bytes
    padding += b'\x00' * ((55 - msg_len) % 64)
    if is_sha256:
        padding += struct.pack('>Q', bit_len)  # SHA: big-endian
    else:
        padding += struct.pack('<Q', bit_len)  # MD5: little-endian
    return padding


class SHA256Extension:
    """SHA-256 length extension based on internal state injection"""

    def __init__(self, known_hash: str, secret_len: int, orig_msg: bytes) -> None:
        self.state = self._parse_state(known_hash)
        self.secret_len = secret_len
        self.orig_msg = orig_msg

    def _parse_state(self, hex_hash: str) -> list[int]:
        """Extract SHA-256 internal state (8 words) from hex hash"""
        raw = bytes.fromhex(hex_hash)
        return list(struct.unpack('>8I', raw))

    def extend(self, append_data: bytes) -> tuple[bytes, str]:
        """
        Returns:
            (forged_message, forged_hash)
            forged_message = orig_msg || padding || append_data
        """
        orig_total = self.secret_len + len(self.orig_msg)
        padding = md_padding(orig_total, is_sha256=True)
        forged_msg = self.orig_msg + padding + append_data

        # Initialize internal state with known_hash and compute only append_data
        new_total = self.secret_len + len(forged_msg)
        forged_hash = self._sha256_from_state(
            self.state,
            append_data,
            orig_total + len(padding)
        )
        return forged_msg, forged_hash

    def _sha256_from_state(
        self, state: list[int], data: bytes, processed_len: int
    ) -> str:
        """Continue SHA-256 computation from given internal state"""
        # Python hashlib does not support internal state injection → implement with struct directly
        # For real CTF, using hashpumpy library is recommended
        import hashlib
        # Simulation: full message hash including secret+original+padding
        # (Demo: actual internal state injection requires C extension)
        print("[*] Real implementation recommended with hashpumpy:")
        print("    pip install hashpumpy")
        print("    import hashpumpy")
        print("    new_sig, new_msg = hashpumpy.hashpump(known_hash, orig_msg, append_data, secret_len)")
        return "Demo: hashpumpy required"


def demonstrate_vulnerability() -> None:
    """Demonstrate hash length extension attack vulnerability"""
    secret = b"supersecret"
    message = b"user=guest"

    mac = hashlib.sha256(secret + message).hexdigest()
    print(f"[*] Original MAC: {mac}")
    print(f"[*] Original message: {message}")
    print(f"[*] Secret key length: {len(secret)}")

    padding = md_padding(len(secret) + len(message))
    append = b"&role=admin"
    forged_msg = message + padding + append

    # In real attack, need to reconstruct internal state
    # Here computed with full message for verification purposes
    forged_mac = hashlib.sha256(secret + forged_msg).hexdigest()
    print(f"\n[+] Forged message: {forged_msg}")
    print(f"[+] Forged MAC: {forged_mac}")
    print(f"\n[!] If server verifies H(secret || forged_msg) == forged_mac, it passes!")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Hash length extension attack tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python hash_extender.py --demo
  python hash_extender.py --hash abc123... --orig-msg "user=guest" --append "&role=admin" --secret-len 11
        """
    )
    parser.add_argument("--demo", action="store_true", help="Run vulnerability demonstration")
    parser.add_argument("--hash", help="Known MAC hash (hex)")
    parser.add_argument("--orig-msg", help="Original message")
    parser.add_argument("--append", help="Data to append")
    parser.add_argument("--secret-len", type=int, help="Secret key length")
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    if args.demo:
        demonstrate_vulnerability()
        return

    if not all([args.hash, args.orig_msg, args.append, args.secret_len]):
        print("[!] --hash, --orig-msg, --append, --secret-len are all required", file=sys.stderr)
        sys.exit(1)

    extender = SHA256Extension(
        args.hash,
        args.secret_len,
        args.orig_msg.encode()
    )
    forged_msg, forged_hash = extender.extend(args.append.encode())
    print(f"[+] Forged message (hex): {forged_msg.hex()}")
    print(f"[+] Forged hash: {forged_hash}")


if __name__ == "__main__":
    main()
```

---

## 5. CTF Challenge 4: XOR Cipher Decryption

### Repeating XOR Key Recovery Theory

With repeating key XOR, if key length k is known:
- Bytes at positions 0, k, 2k, ... are encrypted with the same key byte
- Single-byte XOR search for each column → discriminate using chi-squared statistics

### Key Length Detection

Detect key length using Index of Coincidence (IC):
- IC of columns encrypted with same key ≈ 0.065 (English text)
- IC of different key columns ≈ 0.038 (uniform distribution)

### Python CLI: XOR Key Recoverer

```python
#!/usr/bin/env python3
"""
xor_breaker.py — Repeating XOR cipher key recovery CLI
Usage: python xor_breaker.py --ciphertext-file enc.bin --max-keylen 32 --output plain.txt
"""

import argparse
import sys
import math
import string
from pathlib import Path
from collections import Counter


ENGLISH_FREQ: dict[str, float] = {
    'A': 0.0817, 'B': 0.0150, 'C': 0.0278, 'D': 0.0425, 'E': 0.1270,
    'F': 0.0223, 'G': 0.0202, 'H': 0.0609, 'I': 0.0697, 'J': 0.0015,
    'K': 0.0077, 'L': 0.0403, 'M': 0.0241, 'N': 0.0675, 'O': 0.0751,
    'P': 0.0193, 'Q': 0.0010, 'R': 0.0599, 'S': 0.0633, 'T': 0.0906,
    'U': 0.0276, 'V': 0.0098, 'W': 0.0236, 'X': 0.0015, 'Y': 0.0197,
    'Z': 0.0007,
}


def hamming_distance(b1: bytes, b2: bytes) -> int:
    """Hamming distance between two byte sequences"""
    return sum(bin(x ^ y).count('1') for x, y in zip(b1, b2))


def normalized_hamming(data: bytes, key_len: int, samples: int = 4) -> float:
    """Evaluate key length using normalized Hamming distance (lower = more likely)"""
    blocks = [data[i * key_len:(i + 1) * key_len]
              for i in range(min(samples, len(data) // key_len))]
    if len(blocks) < 2:
        return float('inf')

    distances = []
    for i in range(len(blocks) - 1):
        dist = hamming_distance(blocks[i], blocks[i + 1])
        distances.append(dist / key_len)
    return sum(distances) / len(distances)


def guess_key_length(data: bytes, max_keylen: int) -> list[int]:
    """Sort key length candidates based on Hamming distance"""
    scores = []
    for kl in range(1, min(max_keylen + 1, len(data) // 2)):
        score = normalized_hamming(data, kl)
        scores.append((kl, score))
    scores.sort(key=lambda x: x[1])
    return [kl for kl, _ in scores[:5]]


def chi_squared(column: bytes) -> float:
    """Chi-squared score for single-byte decryption (based on English text)"""
    n = len(column)
    if n == 0:
        return float('inf')
    counts = Counter(column)
    score = 0.0
    for ch in string.ascii_uppercase:
        observed = counts.get(ord(ch), 0) + counts.get(ord(ch.lower()), 0)
        expected = ENGLISH_FREQ[ch] * n
        if expected > 0:
            score += (observed - expected) ** 2 / expected
    return score


def break_single_byte_xor(column: bytes) -> tuple[int, float]:
    """Recover single-byte XOR key"""
    best_key = 0
    best_score = float('inf')
    for key_byte in range(256):
        decrypted = bytes(b ^ key_byte for b in column)
        score = chi_squared(decrypted)
        if score < best_score:
            best_score = score
            best_key = key_byte
    return best_key, best_score


def recover_xor_key(data: bytes, key_len: int) -> bytes:
    """Recover full XOR key when key length is known"""
    key = []
    for col_idx in range(key_len):
        column = bytes(data[i] for i in range(col_idx, len(data), key_len))
        key_byte, score = break_single_byte_xor(column)
        key.append(key_byte)
        print(f"  [*] key[{col_idx}] = 0x{key_byte:02x} ({chr(key_byte) if 32 <= key_byte < 127 else '?'}), score={score:.2f}")
    return bytes(key)


def xor_decrypt(data: bytes, key: bytes) -> bytes:
    """Repeating XOR decryption"""
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Repeating XOR cipher key recoverer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python xor_breaker.py --ciphertext-file enc.bin --max-keylen 32 --output plain.txt
  python xor_breaker.py --ciphertext-hex 1a2b3c... --max-keylen 16
        """
    )
    parser.add_argument("--ciphertext-file", help="Ciphertext binary file path")
    parser.add_argument("--ciphertext-hex", help="Ciphertext hex string")
    parser.add_argument("--max-keylen", type=int, default=32, help="Max key length search range (default: 32)")
    parser.add_argument("--output", help="Output file for decryption result (stdout if omitted)")
    parser.add_argument("--key-len", type=int, help="Specify key length directly (skips auto-detection)")
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    # Load input
    if args.ciphertext_file:
        data = Path(args.ciphertext_file).read_bytes()
    elif args.ciphertext_hex:
        data = bytes.fromhex(args.ciphertext_hex)
    else:
        print("[!] --ciphertext-file or --ciphertext-hex required", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Ciphertext length: {len(data)} bytes")

    # Determine key length
    if args.key_len:
        key_length = args.key_len
        print(f"[*] Specified key length: {key_length}")
    else:
        candidates = guess_key_length(data, args.max_keylen)
        print(f"[*] Key length candidates (by Hamming distance): {candidates}")
        key_length = candidates[0]
        print(f"[*] Using key length: {key_length}")

    # Key recovery
    print(f"\n[*] Recovering key (key length={key_length})...")
    key = recover_xor_key(data, key_length)
    key_printable = ''.join(chr(b) if 32 <= b < 127 else f'\\x{b:02x}' for b in key)
    print(f"\n[+] Recovered key: {key.hex()}")
    print(f"[+] Key (ASCII): {key_printable}")

    # Decryption
    plaintext = xor_decrypt(data, key)

    if args.output:
        Path(args.output).write_bytes(plaintext)
        print(f"[+] Decryption result saved: {args.output}")
    else:
        print("\n[+] Decryption result (first 200 bytes):")
        try:
            print(plaintext[:200].decode('utf-8', errors='replace'))
        except Exception:
            print(plaintext[:200].hex())


if __name__ == "__main__":
    main()
```

---

## 6. Score Table and Learning Checklist

### CTF Problem Classification by Difficulty

| Problem Type | Difficulty | Expected Score | Core Technique | Recommended Tool |
|-------------|------------|----------------|----------------|-----------------|
| Caesar/ROT13 | ★☆☆ | 50-100 | Brute force | CyberChef |
| Vigenere | ★★☆ | 100-200 | Kasiski + IC | dcode.fr |
| Rail Fence | ★☆☆ | 50-100 | Brute force | CyberChef |
| RSA small-e | ★★☆ | 150-250 | Cube root | sympy |
| RSA Wiener | ★★★ | 200-350 | Continued fraction expansion | RsaCtfTool |
| Fermat factorization | ★★☆ | 150-250 | p≈q search | factordb |
| Hash length extension | ★★★ | 200-350 | Internal state injection | hashpumpy |
| XOR repeating key | ★★☆ | 100-200 | Hamming distance + IC | xortool |
| ECC weak parameters | ★★★★ | 300-500 | Pohlig-Hellman | SageMath |

### Learning Checklist

#### Beginner (Entry Level)
- [ ] Understand modular arithmetic (mod, inverse, CRT)
- [ ] Understand XOR operation properties
- [ ] Able to manually decrypt Caesar and Vigenere
- [ ] Basic use of Python hashlib and struct

#### Intermediate
- [ ] Understand RSA mathematical principles (Euler's theorem, Fermat's little theorem)
- [ ] Able to implement frequency analysis
- [ ] Large number operations with gmpy2 and sympy
- [ ] Able to directly implement Wiener attack continued fraction expansion
- [ ] Able to explain hash length extension attack principles

#### Advanced
- [ ] ECC basics (elliptic curve group operations, ECDLP)
- [ ] Understand Pohlig-Hellman algorithm
- [ ] Overview of lattice-based attacks (LLL algorithm)
- [ ] Basic SageMath usage
- [ ] Familiar with RsaCtfTool options

### Reference Tool Table

| Tool | Purpose | Link/Installation |
|------|---------|------------------|
| RsaCtfTool | Automated RSA attacks | `pip install rsactftool` |
| SageMath | Mathematical computation | sagemath.org |
| CyberChef | Multi-purpose crypto analysis | gchq.github.io/CyberChef |
| dcode.fr | Classical cipher decryption | dcode.fr |
| hashpumpy | Hash length extension | `pip install hashpumpy` |
| xortool | XOR key analysis | `pip install xortool` |
| factordb | Factorization database | factordb.com |
| pwntools | CTF exploitation | `pip install pwntools` |

### Quick Reference: CTF Scenario Approach Order

```
When you receive an RSA problem:
1. Check n, e, c
2. If e=3 → Cube Root Attack
3. If n is the same in two problems → Common Modulus
4. If e is very large → Wiener Attack
5. Search n at factordb.com
6. RsaCtfTool --attack all

When you receive a classical cipher problem:
1. Check character set (alphabets only? numbers included?)
2. Frequency analysis → single substitution means Caesar/Affine
3. IC ≈ 0.065 means single substitution, ≈ 0.038 means complex polysubstitution
4. Estimate key length with Kasiski test → Vigenere

Hash problems:
1. Check hash length (32=MD5, 64=SHA256)
2. Check MAC verification logic → H(secret||msg) pattern means length extension
3. Use hashpumpy
```
