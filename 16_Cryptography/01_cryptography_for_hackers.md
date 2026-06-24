> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 해커를 위한 암호학

## 0. 초보자를 위한 개념 이해

### 해커를 위한 암호학이란?

암호학(Cryptography)은 데이터를 안전하게 변환하여 허가된 사람만 읽을 수 있게 하는 학문입니다. 해커 관점에서는 잘못 구현된 암호화, 취약한 알고리즘, 키 관리 실수를 찾아 데이터를 복원하거나 시스템을 공격합니다. CTF 암호학 문제와 버그바운티 JWT 공격에서 암호학 기초는 필수입니다.

**왜 배우는가:**
```
암호학 취약점의 현실적 영향:

  고전 암호 (Caesar, Vigenère)
    → CTF 입문, 암호 사고방식 이해

  약한 해시 (MD5, SHA-1)
    → 패스워드 크래킹, 파일 위변조

  RSA 구현 오류 (작은 e, 공개 모듈러스 재사용)
    → 비밀 메시지 복원, 서명 위조

  AES 모드 오류 (ECB 모드, IV 재사용)
    → 패턴 노출, 평문 복원

  JWT alg:none / 약한 시크릿
    → 인증 우회, 권한 상승
```

### 핵심 개념 정리

```
암호 유형 비교:

  대칭 암호 (Symmetric)
    암호화 키 = 복호화 키
    빠름, 키 공유 문제
    AES, DES, ChaCha20

  비대칭 암호 (Asymmetric)
    공개키로 암호화 → 개인키로 복호화
    느림, 키 공유 불필요
    RSA, ECC, DSA

  해시 함수 (Hash)
    단방향 변환 (복호화 불가)
    MD5(파훼), SHA-1(파훼), SHA-256(안전)

  주요 공격 유형:
    전수 공격 (Brute Force)  — 모든 키 시도
    통계 분석 (Frequency)    — 문자 빈도 분석
    관련 메시지 공격           — 여러 암호문 비교
    타이밍 공격               — 실행 시간 측정
```

### 필요한 도구 및 환경
- **pycryptodome**: Python 암호화 라이브러리 (AES, RSA 등)
- **gmpy2**: 고정밀 정수 연산 (RSA 공격에 필수)
- **SageMath**: 수학 연산 환경 (고급 암호 공격)
- **CyberChef**: 브라우저 기반 암호화/인코딩 분석 도구

### 기초 실습 예제
```python
#!/usr/bin/env python3
"""고전 암호 분석 — 시저 암호 전수 공격 및 빈도 분석."""

from collections import Counter
import string


def caesar_decrypt(ciphertext: str, shift: int) -> str:
    """시저 암호를 주어진 shift로 복호화합니다."""
    result: list[str] = []
    for char in ciphertext:
        if char.isalpha():
            base = ord("A") if char.isupper() else ord("a")
            result.append(chr((ord(char) - base - shift) % 26 + base))
        else:
            result.append(char)
    return "".join(result)


def frequency_score(text: str) -> float:
    """영어 문자 빈도 기반으로 평문 유사도를 점수화합니다."""
    english_freq = "etaoinshrdlcumwfgypbvkjxqz"
    text_lower = text.lower()
    letter_counts = Counter(c for c in text_lower if c.isalpha())
    if not letter_counts:
        return 0.0
    sorted_letters = [k for k, _ in letter_counts.most_common()]
    score = sum(
        1 for i, letter in enumerate(sorted_letters[:8])
        if letter in english_freq[:8]
    )
    return score / 8.0


def crack_caesar(ciphertext: str) -> tuple[int, str]:
    """시저 암호를 빈도 분석으로 자동 크랙합니다."""
    best_shift = 0
    best_score = -1.0
    best_plaintext = ""
    for shift in range(26):
        candidate = caesar_decrypt(ciphertext, shift)
        score = frequency_score(candidate)
        if score > best_score:
            best_score = score
            best_shift = shift
            best_plaintext = candidate
    return best_shift, best_plaintext


if __name__ == "__main__":
    # "Hello, Security World!" → shift 13으로 암호화
    ciphertext = "Uryyb, Frphevgl Jbeyq!"
    shift, plaintext = crack_caesar(ciphertext)
    print(f"암호문: {ciphertext}")
    print(f"추정 shift: {shift}")
    print(f"복호화 결과: {plaintext}")
```

---

## 암호학 기초 개념

```
평문(Plaintext) → [암호화] → 암호문(Ciphertext) → [복호화] → 평문
                      ↑                                   ↑
                    키(Key)                            키(Key)

대칭 암호: 암호화 키 = 복호화 키
  AES, DES, 3DES, ChaCha20, Blowfish

비대칭 암호: 공개키(암호화) ≠ 개인키(복호화)
  RSA, ECC, DSA, ElGamal

해시 함수: 단방향 변환 (복호화 불가)
  MD5, SHA-1, SHA-256, SHA-3, bcrypt, Argon2
```

---

## 1. 고전 암호 (취약점 이해)

### Caesar Cipher (시저 암호)

시저 암호(Caesar Cipher) 구현입니다. 알파벳을 고정된 자릿수만큼 이동시키는 가장 단순한 치환 암호로, 26가지 모든 키를 시도하면 즉시 해독됩니다.

```python
def caesar_encrypt(text: str, shift: int) -> str:
    result = ""
    for char in text:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            result += chr((ord(char) - base + shift) % 26 + base)
        else:
            result += char
    return result

def caesar_brute_force(ciphertext: str):
    """시저 암호 전수 공격 (26가지 키)"""
    for shift in range(26):
        decrypted = caesar_encrypt(ciphertext, -shift)
        print(f"Shift {shift:2d}: {decrypted}")

# 예시
ciphertext = "Khoor, Zruog!"  # Hello, World! (shift=3)
caesar_brute_force(ciphertext)
```

### Vigenere Cipher

비제네르 암호 복호화 구현입니다. 여러 시저 암호를 키 길이만큼 반복 사용하지만 Kasiski 분석이나 Index of Coincidence로 키 길이를 파악하면 해독됩니다.

```python
def vigenere_decrypt(ciphertext: str, key: str) -> str:
    """비제네르 암호 복호화"""
    result = ""
    key_len = len(key)
    key_idx = 0
    
    for char in ciphertext:
        if char.isalpha():
            shift = ord(key[key_idx % key_len].upper()) - ord('A')
            base = ord('A') if char.isupper() else ord('a')
            result += chr((ord(char) - base - shift) % 26 + base)
            key_idx += 1
        else:
            result += char
    
    return result

def kasiski_test(ciphertext: str, min_len: int = 3) -> dict:
    """카시스키 검사 - 키 길이 추정"""
    from math import gcd
    from functools import reduce
    
    distances = {}
    clean = ciphertext.replace(" ", "").upper()
    
    # 반복되는 패턴 찾기
    for length in range(min_len, 6):
        for i in range(len(clean) - length):
            seq = clean[i:i+length]
            occurrences = [j for j in range(i+1, len(clean)-length)
                          if clean[j:j+length] == seq]
            if occurrences:
                for occ in occurrences:
                    distance = occ - i
                    distances[seq] = distances.get(seq, []) + [distance]
    
    # 거리들의 GCD → 키 길이 추정
    all_distances = [d for dists in distances.values() for d in dists]
    if all_distances:
        key_length = reduce(gcd, all_distances)
        print(f"추정 키 길이: {key_length}")
    
    return distances
```

### XOR 암호

XOR 암호 구현입니다. 동일한 키 길이의 단순 XOR은 crib-dragging 공격으로 해독됩니다. 악성코드에서 페이로드 난독화에 자주 사용됩니다.

```python
#!/usr/bin/env python3
"""XOR 암호화 및 단일/반복 키 크래킹 CLI 도구"""

import argparse
import sys
from typing import Optional


def xor_encrypt(data: bytes, key: bytes) -> bytes:
    """XOR 암호화/복호화 (동일 연산)"""
    key_len = len(key)
    return bytes([b ^ key[i % key_len] for i, b in enumerate(data)])


def xor_crack_single_byte(ciphertext: bytes) -> tuple[int, bytes, float]:
    """단일 바이트 XOR 크랙 — 영어 빈도 분석"""
    english_freq: dict[str, float] = {
        'e': 12.7, 't': 9.1, 'a': 8.2, 'o': 7.5, 'i': 7.0,
        'n': 6.7, 's': 6.3, 'h': 6.1, 'r': 6.0, 'd': 4.3,
        ' ': 13.0,  # 공백 가중치
    }
    best_key, best_score, best_plain = 0, 0.0, b""

    for key_byte in range(256):
        decrypted = bytes([b ^ key_byte for b in ciphertext])
        try:
            text = decrypted.decode('ascii')
        except (UnicodeDecodeError, ValueError):
            continue
        score = sum(english_freq.get(c.lower(), 0) for c in text)
        if score > best_score:
            best_score, best_key, best_plain = score, key_byte, decrypted

    return best_key, best_plain, best_score


def crack_repeating_xor(ciphertext: bytes, max_keysize: int = 40) -> tuple[bytes, bytes]:
    """반복 키 XOR 크랙 (CryptoPals Set1 Ch6 스타일)"""

    def hamming(a: bytes, b: bytes) -> int:
        return sum(bin(x ^ y).count('1') for x, y in zip(a, b))

    # 1단계: 키 크기 추정
    scores: dict[int, float] = {}
    for ks in range(2, min(max_keysize + 1, len(ciphertext) // 4 + 1)):
        blocks = [ciphertext[i * ks:(i + 1) * ks] for i in range(4)]
        pairs = [(blocks[i], blocks[j]) for i in range(4) for j in range(i + 1, 4)
                 if len(blocks[i]) == ks and len(blocks[j]) == ks]
        if not pairs:
            continue
        avg = sum(hamming(a, b) / ks for a, b in pairs) / len(pairs)
        scores[ks] = avg

    best_ks = min(scores, key=scores.get)

    # 2단계: 각 키 바이트 복원
    key = bytes(
        xor_crack_single_byte(
            bytes([ciphertext[j] for j in range(i, len(ciphertext), best_ks)])
        )[0]
        for i in range(best_ks)
    )

    plaintext = xor_encrypt(ciphertext, key)
    return key, plaintext


def main() -> None:
    parser = argparse.ArgumentParser(description="XOR 암호화/크래킹 도구")
    sub = parser.add_subparsers(dest="cmd", required=True)

    enc_p = sub.add_parser("encrypt", help="XOR 암호화/복호화")
    enc_p.add_argument("--hex-input", required=True, help="입력 데이터 (hex)")
    enc_p.add_argument("--key", required=True, help="키 (hex 또는 문자열)")
    enc_p.add_argument("--key-hex", action="store_true", help="키를 hex로 해석")

    crack_p = sub.add_parser("crack", help="단일/반복 바이트 XOR 크랙")
    crack_p.add_argument("--hex-input", required=True, help="암호문 (hex)")
    crack_p.add_argument("--mode", choices=["single", "repeating"], default="single")
    crack_p.add_argument("--max-keysize", type=int, default=40)

    args = parser.parse_args()

    if args.cmd == "encrypt":
        data = bytes.fromhex(args.hex_input)
        key = bytes.fromhex(args.key) if args.key_hex else args.key.encode()
        result = xor_encrypt(data, key)
        print(f"Result (hex): {result.hex()}")
        try:
            print(f"Result (ascii): {result.decode('ascii')}")
        except (UnicodeDecodeError, ValueError):
            pass

    elif args.cmd == "crack":
        ct = bytes.fromhex(args.hex_input)
        if args.mode == "single":
            k, plain, score = xor_crack_single_byte(ct)
            print(f"Key byte : 0x{k:02x}  ({chr(k) if 32 <= k < 127 else '?'})")
            print(f"Score    : {score:.2f}")
            print(f"Plaintext: {plain}")
        else:
            key, plain = crack_repeating_xor(ct, args.max_keysize)
            print(f"Key (hex)  : {key.hex()}")
            print(f"Key (ascii): {key.decode('latin-1')}")
            print(f"Plaintext  :\n{plain.decode('latin-1')}")


if __name__ == "__main__":
    # 빠른 데모 (인수 없이 실행 시)
    if len(sys.argv) == 1:
        demo_ct = bytes.fromhex(
            "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
        )
        k, plain, score = xor_crack_single_byte(demo_ct)
        print(f"[Demo] Key: 0x{k:02x} ({chr(k)})  Score: {score:.2f}")
        print(f"[Demo] Plaintext: {plain}")
    else:
        main()
```

---

## 2. 현대 암호학

### AES 암호화 모드별 취약점

AES 운용 모드별 취약점을 보여주는 코드입니다. ECB 모드는 동일 블록이 동일 암호문으로 나타나는 패턴 노출 취약점이 있습니다.

```python
#!/usr/bin/env python3
"""AES 모드별 취약점 PoC — CBC 비트플리핑, CTR 논스 재사용, ECB 패턴 공격, AES-GCM 올바른 구현"""

import argparse
import os
import sys

try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad
except ImportError:
    print("[-] pycryptodome 필요: pip install pycryptodome", file=sys.stderr)
    sys.exit(1)


# ── 보조 함수 ────────────────────────────────────────────────

def aes_cbc_encrypt(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    return AES.new(key, AES.MODE_CBC, iv).encrypt(pad(plaintext, 16))


def aes_cbc_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    return unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(ciphertext), 16)


# ── 공격 1: CBC 비트 플리핑 ──────────────────────────────────

def cbc_bit_flip_demo() -> None:
    """
    CBC 비트 플리핑: 이전 암호문 블록 조작 → 복호화 결과 변조
      P'[i] = AES_Dec(C[i]) XOR C'[i-1]
    목표: 2번째 블록 'role=user&admin=' 중 'user' → 'admi' 변조
    """
    key = os.urandom(16)
    iv  = os.urandom(16)

    # 블록0(16B) = 패딩, 블록1(16B) = 'role=user&admin='
    plaintext = b"A" * 16 + b"role=user&admin="
    ciphertext = aes_cbc_encrypt(plaintext, key, iv)

    original_bytes = b"role=user"
    target_bytes   = b"role=admi"

    modified = bytearray(ciphertext)
    for i, (orig, targ) in enumerate(zip(original_bytes, target_bytes)):
        modified[16 + i] ^= orig ^ targ   # 블록0 (인덱스 16~31) 변조

    try:
        result = aes_cbc_decrypt(bytes(modified), key, iv)
        print(f"[CBC Bit-Flip] 복호화 결과: {result}")
    except ValueError as e:
        print(f"[CBC Bit-Flip] 패딩 오류 (일부 바이트 변조됨): {e}")


# ── 공격 2: CTR 논스 재사용 ──────────────────────────────────

def ctr_nonce_reuse_demo() -> None:
    """
    CTR 모드 논스 재사용:
      C1 = P1 ⊕ KS,  C2 = P2 ⊕ KS  →  C1⊕C2 = P1⊕P2
    P1을 알면 P2 완전 복원 가능
    """
    key   = os.urandom(16)
    nonce = b"\x00" * 8   # 치명적 실수: 고정 논스

    def ctr_enc(pt: bytes) -> bytes:
        return AES.new(key, AES.MODE_CTR, nonce=nonce).encrypt(pt)

    msg1 = b"Hello, World!!!!!"
    msg2 = b"Secret Password!!"

    c1 = ctr_enc(msg1)
    c2 = ctr_enc(msg2)   # 동일 논스 재사용!

    # 공격자가 msg1과 c1, c2를 알 때
    keystream = bytes(a ^ b for a, b in zip(c1, msg1))
    recovered = bytes(a ^ b for a, b in zip(c2, keystream))
    print(f"[CTR Nonce Reuse] 복원된 msg2: {recovered}")


# ── 공격 3: ECB Cut-and-Paste ────────────────────────────────

def ecb_cut_and_paste_demo() -> None:
    """
    ECB 모드: 동일 16B 블록 → 동일 암호문 블록
    admin 패딩 블록을 잘라서 role=user 자리에 붙여넣기
    """
    key = os.urandom(16)

    def encrypt_profile(email: str) -> bytes:
        profile = f"email={email}&uid=10&role=user"
        return AES.new(key, AES.MODE_ECB).encrypt(pad(profile.encode(), 16))

    # 블록0: "email=AAAAAAAAAA" (16B)
    # 블록1: "admin\x0b\x0b...\x0b" — 패딩된 admin 블록 (16B)
    # 블록2: "&uid=10&role=use"
    craft_email = "AAAAAAAAAA" + "admin" + chr(11) * 11
    encrypted   = encrypt_profile(craft_email)
    admin_block = encrypted[16:32]

    # role=user 가 정확히 블록 경계에 오도록 이메일 길이 조정
    # "email=" = 6, "&uid=10&role=" = 13  → 6 + email_len ≡ 0 (mod 16) → len=10
    normal_enc = encrypt_profile("test@ex.co")   # 10자
    forged     = normal_enc[:-16] + admin_block  # 마지막 블록 교체

    decrypted = unpad(AES.new(key, AES.MODE_ECB).decrypt(forged), 16)
    print(f"[ECB Cut-Paste] 위조 결과: {decrypted.decode()}")


# ── 올바른 구현: AES-256-GCM ────────────────────────────────

def aes_gcm_demo() -> None:
    """AES-256-GCM — AEAD (인증 + 암호화), 논스는 매번 새로 생성"""
    key   = os.urandom(32)   # 256-bit
    nonce = os.urandom(12)   # 96-bit (GCM 권장)
    aad   = b"authenticated-but-not-encrypted"

    plaintext = b"Sensitive data: TOP SECRET"

    cipher     = AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher.update(aad)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    print(f"[AES-GCM] CT={ciphertext.hex()}  TAG={tag.hex()}")

    # 복호화 + 인증 검증
    dec = AES.new(key, AES.MODE_GCM, nonce=nonce)
    dec.update(aad)
    try:
        recovered = dec.decrypt_and_verify(ciphertext, tag)
        print(f"[AES-GCM] 복호화 성공: {recovered}")
    except ValueError:
        print("[AES-GCM] 인증 실패 — 데이터 변조 감지!")


# ── CLI ──────────────────────────────────────────────────────

def main() -> None:
    demos = {
        "cbc-flip":   cbc_bit_flip_demo,
        "ctr-reuse":  ctr_nonce_reuse_demo,
        "ecb-paste":  ecb_cut_and_paste_demo,
        "gcm":        aes_gcm_demo,
    }

    parser = argparse.ArgumentParser(description="AES 모드별 취약점 PoC")
    parser.add_argument("demo", choices=list(demos) + ["all"],
                        nargs="?", default="all",
                        help="실행할 데모 (기본: all)")
    args = parser.parse_args()

    targets = list(demos.values()) if args.demo == "all" else [demos[args.demo]]
    for fn in targets:
        fn()
        print()


if __name__ == "__main__":
    main()
```

---

## 3. RSA 공격 기법

### RSA 기초

```
RSA 키 생성:
  1. 큰 소수 p, q 선택
  2. n = p * q (모듈러스)
  3. φ(n) = (p-1)(q-1) (오일러 파이)
  4. gcd(e, φ(n)) = 1인 e 선택 (보통 65537)
  5. d = e^(-1) mod φ(n) (개인키)
  
  공개키: (n, e)
  개인키: (n, d)

암호화: C = M^e mod n
복호화: M = C^d mod n
서명: S = M^d mod n
검증: M = S^e mod n
```

### RSA 취약점 공격

RSA 취약 구현을 공격하는 코드입니다. 작은 지수(e=3) 공격, 공통 모듈러스 공격, 패딩 오라클 공격 등 RSA 구현 오류를 이용합니다.

```python
#!/usr/bin/env python3
"""RSA 취약점 공격 도구 — Small-e, GCD, Wiener, Hastad 브로드캐스트"""

from __future__ import annotations
import argparse
import sys
from math import gcd, isqrt
from functools import reduce


# ── 정수 e제곱근 (작은 지수 공격용) ─────────────────────────

def iroot(n: int, e: int) -> tuple[int, bool]:
    """n의 e제곱근 정수 부분 반환 (정확한지 여부도 함께)"""
    if n < 0:
        return 0, False
    if e == 1:
        return n, True
    # 뉴턴 방법
    x = int(round(n ** (1 / e)))
    for candidate in range(max(0, x - 2), x + 3):
        if candidate ** e == n:
            return candidate, True
    return x, False


# ── 1. Small-e 공격 ──────────────────────────────────────────

def small_e_attack(ciphertext: int, e: int = 3) -> int | None:
    """
    e=3, M^e < n 이면 모듈러 감소 없이 C = M^e
    → 정수 e제곱근으로 평문 복원
    """
    m, exact = iroot(ciphertext, e)
    if exact:
        print(f"[+] Small-e 성공: M = {m}")
        return m
    print("[-] Small-e 실패: M^e >= n 이거나 정확한 제곱근 없음")
    return None


# ── 2. 공통 소인수 공격 ──────────────────────────────────────

def common_factor_attack(n1: int, n2: int, e: int, c1: int) -> int | None:
    """
    두 RSA 모듈러스가 소수 p를 공유할 때 gcd(n1, n2) = p
    → n1 인수분해 → d 복원 → c1 복호화
    """
    p = gcd(n1, n2)
    if p == 1:
        print("[-] 공통 소인수 없음")
        return None

    q     = n1 // p
    phi_n = (p - 1) * (q - 1)
    d     = pow(e, -1, phi_n)
    m     = pow(c1, d, n1)
    print(f"[+] 공통 소인수 p = {p}")
    print(f"[+] 복호화 결과 M = {m}")
    return m


# ── 3. Wiener 공격 (작은 d) ──────────────────────────────────

def wiener_attack(e: int, n: int) -> int | None:
    """
    d < n^0.25 일 때 e/n의 연분수 수렴값으로 d 복원
    """

    def continued_fraction(num: int, den: int) -> list[int]:
        cf: list[int] = []
        while den:
            cf.append(num // den)
            num, den = den, num % den
        return cf

    def convergents(cf: list[int]) -> list[tuple[int, int]]:
        convs: list[tuple[int, int]] = []
        for i, q in enumerate(cf):
            if i == 0:
                convs.append((q, 1))
            elif i == 1:
                convs.append((q * cf[0] + 1, q))
            else:
                h = q * convs[-1][0] + convs[-2][0]
                k = q * convs[-1][1] + convs[-2][1]
                convs.append((h, k))
        return convs

    for k, d in convergents(continued_fraction(e, n)):
        if k == 0 or (e * d - 1) % k != 0:
            continue
        phi_n = (e * d - 1) // k
        # p + q = n - phi_n + 1,  판별식 = (p+q)^2 - 4n
        b    = n - phi_n + 1
        disc = b * b - 4 * n
        if disc < 0:
            continue
        sq = isqrt(disc)
        if sq * sq == disc:
            p, q = (b + sq) // 2, (b - sq) // 2
            if p * q == n:
                print(f"[+] Wiener 성공: d = {d}")
                return d

    print("[-] Wiener 공격 실패: d가 충분히 작지 않음")
    return None


# ── 4. Hastad 브로드캐스트 공격 ──────────────────────────────

def hastad_broadcast(ciphertexts: list[int], moduli: list[int],
                     e: int = 3) -> int | None:
    """
    동일 평문을 e개의 다른 공개키로 암호화 → CRT로 M^e 복원 후 e제곱근
    요구: len(ciphertexts) == len(moduli) == e
    """
    if len(ciphertexts) < e or len(moduli) < e:
        print(f"[-] 암호문/모듈러스가 {e}개 미만")
        return None

    # 중국인 나머지 정리
    M = reduce(lambda a, b: a * b, moduli[:e])
    x = 0
    for ci, ni in zip(ciphertexts[:e], moduli[:e]):
        Mi = M // ni
        yi = pow(Mi, -1, ni)
        x  = (x + ci * Mi * yi) % M

    m, exact = iroot(x, e)
    if exact:
        print(f"[+] Hastad 성공: M = {m}")
        return m
    print("[-] Hastad 실패: CRT 복원값의 e제곱근이 정수가 아님")
    return None


# ── CLI ──────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="RSA 공격 도구")
    sub = parser.add_subparsers(dest="attack", required=True)

    # small-e
    p1 = sub.add_parser("small-e", help="Small public exponent attack")
    p1.add_argument("--ciphertext", type=lambda x: int(x, 0), required=True)
    p1.add_argument("--e", type=int, default=3)

    # gcd
    p2 = sub.add_parser("gcd", help="Common prime factor attack")
    p2.add_argument("--n1", type=lambda x: int(x, 0), required=True)
    p2.add_argument("--n2", type=lambda x: int(x, 0), required=True)
    p2.add_argument("--e", type=int, required=True)
    p2.add_argument("--c1", type=lambda x: int(x, 0), required=True)

    # wiener
    p3 = sub.add_parser("wiener", help="Wiener small-d attack")
    p3.add_argument("--e", type=lambda x: int(x, 0), required=True)
    p3.add_argument("--n", type=lambda x: int(x, 0), required=True)

    # hastad
    p4 = sub.add_parser("hastad", help="Hastad broadcast attack")
    p4.add_argument("--e", type=int, default=3)
    p4.add_argument("--ciphertexts", nargs="+", type=lambda x: int(x, 0), required=True)
    p4.add_argument("--moduli",      nargs="+", type=lambda x: int(x, 0), required=True)

    args = parser.parse_args()

    if args.attack == "small-e":
        small_e_attack(args.ciphertext, args.e)
    elif args.attack == "gcd":
        common_factor_attack(args.n1, args.n2, args.e, args.c1)
    elif args.attack == "wiener":
        wiener_attack(args.e, args.n)
    elif args.attack == "hastad":
        hastad_broadcast(args.ciphertexts, args.moduli, args.e)


if __name__ == "__main__":
    if len(sys.argv) == 1:
        # 기본 데모: small-e
        print("[Demo] small-e: M=42, e=3, C=42^3=74088")
        small_e_attack(74088, 3)
    else:
        main()
```

---

## 4. 해시 크래킹

### 해시 유형 식별

hashid 또는 hash-identifier로 해시 알고리즘 유형을 식별합니다. 해시 길이와 문자 집합 패턴으로 MD5, SHA-1, bcrypt 등을 구분합니다.

```bash
# hashid로 해시 유형 식별
hashid "5f4dcc3b5aa765d61d8327deb882cf99"
hashid "e3b0c44298fc1c149afbf4c8996fb924"

# hashcat 모드별 주요 해시
# -m 0    MD5
# -m 100  SHA1
# -m 1400 SHA256
# -m 1700 SHA512
# -m 1800 sha512crypt ($6$) (Linux /etc/shadow)
# -m 500  md5crypt ($1$) (Linux /etc/shadow)
# -m 3200 bcrypt ($2*$)
# -m 1000 NTLM (Windows)
# -m 5600 NetNTLMv2
# -m 13100 Kerberoast ($krb5tgs$)
# -m 18200 AS-REP Roast ($krb5asrep$)
```

```python
#!/usr/bin/env python3
"""해시 유형 자동 식별 및 크랙 준비"""

import re
import hashlib

HASH_PATTERNS = {
    'MD5': (r'^[a-f0-9]{32}$', 0),
    'SHA1': (r'^[a-f0-9]{40}$', 100),
    'SHA256': (r'^[a-f0-9]{64}$', 1400),
    'SHA512': (r'^[a-f0-9]{128}$', 1700),
    'NTLM': (r'^[a-f0-9]{32}$', 1000),  # MD5와 동일 길이
    'bcrypt': (r'^\$2[ayb]\$.{56}$', 3200),
    'sha512crypt': (r'^\$6\$.{8,16}\$.{86}$', 1800),
    'md5crypt': (r'^\$1\$.{8}\$.{22}$', 500),
}

def identify_hash(hash_str: str) -> list:
    matches = []
    for name, (pattern, mode) in HASH_PATTERNS.items():
        if re.match(pattern, hash_str, re.IGNORECASE):
            matches.append((name, mode))
    return matches

def crack_md5(hash_str: str, wordlist: str) -> str:
    """MD5 해시 딕셔너리 크래킹"""
    with open(wordlist, 'r', encoding='latin-1') as f:
        for word in f:
            word = word.strip()
            if hashlib.md5(word.encode()).hexdigest() == hash_str:
                return word
    return None

# 사용 예시
test_hash = "5f4dcc3b5aa765d61d8327deb882cf99"
types = identify_hash(test_hash)
print(f"해시 유형 후보: {types}")

# hashcat 명령어 생성
for name, mode in types:
    print(f"hashcat -m {mode} {test_hash} wordlist.txt")
```

---

## 5. TLS/SSL 취약점

### 알려진 TLS 공격

알려진 TLS 취약점(BEAST, POODLE, FREAK, Heartbleed)을 점검합니다. 취약한 TLS 버전과 암호 스위트가 사용되는지 확인합니다.

```bash
# BEAST (TLS 1.0 CBC)
# 대응: TLS 1.2+ 사용

# POODLE (SSL 3.0 CBC padding oracle)
# 확인
openssl s_client -ssl3 -connect target.com:443
# 대응: SSL 3.0 비활성화

# HEARTBLEED (OpenSSL 1.0.1-1.0.1f)
# CVE-2014-0160
nmap --script ssl-heartbleed target.com
python3 heartbleed.py target.com

# DROWN (SSLv2 공유 키)
# SSLv2 활성화 여부 확인
openssl s_client -ssl2 -connect target.com:443
nmap --script sslv2 target.com

# FREAK (512비트 RSA)
openssl s_client -cipher EXPORT -connect target.com:443

# LOGJAM (512비트 DH)
openssl s_client -cipher DHE -connect target.com:443

# 종합 TLS 스캔
testssl.sh target.com
sslyze target.com --regular
```

### 인증서 분석


OpenSSL CLI 명령어로 다양한 암호화 작업을 수행합니다. 대칭 암호화(`enc`), 비대칭 키 생성(`genrsa`, `genpkey`), 인증서 생성(`req`), TLS 서버 테스트(`s_client`) 등 보안 실습에 필수적인 도구입니다.

```bash
# 인증서 정보 추출
echo | openssl s_client -connect target.com:443 2>/dev/null | \
    openssl x509 -noout -text

# 인증서 만료 확인
echo | openssl s_client -connect target.com:443 2>/dev/null | \
    openssl x509 -noout -dates

# 인증서 해시 (피닝 우회 연구)
echo | openssl s_client -connect target.com:443 2>/dev/null | \
    openssl x509 -noout -fingerprint -sha256

# Certificate Transparency 검색
curl -s "https://crt.sh/?q=%.target.com&output=json" | \
    python3 -c "import json,sys; [print(e['name_value']) for e in json.load(sys.stdin)]" | \
    sort -u
```

---

## 6. 난수 생성기 취약점

취약한 난수 생성기(PRNG) 상태를 예측하는 공격 코드입니다. 예측 가능한 시드나 짧은 주기를 가진 PRNG는 암호학적으로 안전하지 않습니다.

```python
# 취약한 난수 생성기 예측
import random
import time

# 나쁜 예: 시간 기반 시드
def bad_token_generation():
    random.seed(int(time.time()))  # 예측 가능!
    return hex(random.getrandbits(64))

# 취약한 시드 역산 공격
def crack_time_seed(leaked_token: int, time_window: int = 3600):
    """
    시간 기반 시드를 사용하는 경우:
    현재 시간 ± time_window 내 모든 시드 시도
    """
    current_time = int(time.time())
    
    for seed in range(current_time - time_window, current_time + 1):
        random.seed(seed)
        candidate = random.getrandbits(64)
        
        if candidate == leaked_token:
            print(f"[+] 시드 발견: {seed}")
            # 다음 토큰 예측 가능
            next_token = hex(random.getrandbits(64))
            print(f"[+] 다음 토큰 예측: {next_token}")
            return seed
    
    return None

# PHP rand() 크랙 (32비트 시드)
def crack_php_rand(known_output: int):
    """PHP mt_rand() 크랙 (전수 조사)"""
    # PHP 7 이전 mt_srand 취약점
    for seed in range(0, 2**32):
        # PHP mt_rand 시뮬레이션 (실제로는 더 복잡)
        import ctypes
        # ...실제 구현은 PHP 내부 알고리즘 역공학 필요
        pass
```

---

## 7. 암호학 도전과제 (CTF 유형)

### CryptoPals 챌린지 스타일

CryptoPals 암호 챌린지 스타일의 구현입니다. 반복 키 XOR 크래킹은 키 길이를 Hamming Distance로 추정한 후 단일 바이트 XOR 분석을 적용합니다.

```python
# Set 1, Challenge 6: 반복 키 XOR 크랙
def crack_repeating_xor(ciphertext: bytes) -> str:
    """
    1. Hamming distance로 키 크기 추정
    2. 각 위치별 단일 바이트 XOR 크랙
    3. 키 재조합
    """
    def hamming_distance(a: bytes, b: bytes) -> int:
        return sum(bin(x ^ y).count('1') for x, y in zip(a, b))
    
    # 1단계: 키 크기 추정
    scores = {}
    for keysize in range(2, 41):
        if len(ciphertext) < keysize * 4:
            break
        
        blocks = [ciphertext[i*keysize:(i+1)*keysize] for i in range(4)]
        
        distances = []
        for i in range(len(blocks)-1):
            for j in range(i+1, len(blocks)):
                d = hamming_distance(blocks[i], blocks[j]) / keysize
                distances.append(d)
        
        scores[keysize] = sum(distances) / len(distances)
    
    best_keysize = min(scores, key=scores.get)
    print(f"추정 키 크기: {best_keysize}")
    
    # 2단계: 각 키 바이트 크랙
    key = []
    for i in range(best_keysize):
        block = bytes([ciphertext[j] for j in range(i, len(ciphertext), best_keysize)])
        best_byte, _ = xor_crack_single_byte(block)  # 위에서 정의
        key.append(best_byte)
    
    # 3단계: 복호화
    key_bytes = bytes(key)
    plaintext = bytes([c ^ key_bytes[i % len(key_bytes)] 
                       for i, c in enumerate(ciphertext)])
    
    return plaintext.decode('utf-8', errors='replace'), key_bytes
```

---

## 8. 실전 암호 분석 도구

암호 분석에 사용하는 주요 도구들입니다. CyberChef는 브라우저 기반으로 다양한 인코딩/암호화 변환을 지원합니다.

```bash
# CyberChef - 브라우저 기반 암호 분석
# https://gchq.github.io/CyberChef/

# hashcat - 해시 크래킹
hashcat -m 0 hash.txt wordlist.txt

# John the Ripper
john hash.txt --wordlist=wordlist.txt

# rsatool - RSA 계산
python3 rsatool.py -n N -e E -p P -q Q

# factordb - 소인수 분해 DB 조회
curl http://factordb.com/api?query=LARGE_NUMBER

# SageMath - 수학적 암호 분석
sage -c "factor(n)"

# OpenSSL 종합 분석
openssl rsa -text -noout -in private.pem
openssl x509 -text -noout -in cert.pem
openssl dgst -sha256 file.txt
```

---

<!-- detect-validate-16 -->
## 암호 약점 탐지와 방어 검증

암호 공격은 *약한 알고리즘·잘못된 파라미터·빈약한 난수*를 노린다. 방어자는 **어떤 암호·키 크기·TLS 버전이 실제 가동 중인가**와 **약한 스위트·구식 서명·예측 가능한 토큰이 탐지되는가**를 검증해야 한다. 실습은 **소유·허가된 대상**에서만.

### 공격 → 노리는 약점 → 1차 통제(방어자) → 탐지 신호

| 기법 | 노리는 약점 | 1차 통제(방어자) | 탐지 신호 |
|---|---|---|---|
| 구식 암호 악용(DES/RC4/MD5) | 레거시 알고리즘 | 강한 스위트 강제, 레거시 비활성 | 핸드셰이크/설정의 약한 알고리즘 |
| RSA 약한 파라미터(작은 e·공통 모듈러스) | 잘못된 키 생성 | 검증 라이브러리·2048+ 키 | 비표준 키 크기·지수 |
| 약한 난수(예측 가능 시드) | 엔트로피 부족 | CSPRNG(secrets, /dev/urandom) | 반복·예측 가능 토큰 |
| 평문·약한 TLS 전송 | 전송 보호 미비 | TLS1.2+ 강제·HSTS | 다운그레이드·평문 전송  |

### 방어 검증 (직접 확인)

```bash
# 1) 인증서/키의 알고리즘·키 크기 점검 — 약한 RSA(<2048)·구식 서명 식별
openssl x509 -in cert.pem -noout -text | grep -E "Public-Key|Signature Algorithm"
# 2) 서버가 구버전 TLS/약한 cipher 를 받는지 사실 확인(소유 대상)
openssl s_client -connect example.com:443 -tls1_1 </dev/null 2>&1 | grep -E "Protocol|Cipher"
#   핸드셰이크가 성립하면 TLS1.1 잔존 → 다운그레이드 표면
```

> 암호 방어의 출발점은 *무엇이 실제 가동 중인가*를 사실로 확인하는 것이다 — "강한 암호 쓴다"와 "약한 스위트·구버전 TLS 가 비활성"은 다르다. 소유 대상에서 알고리즘·키 크기·프로토콜을 직접 점검한다([[02_Network_Hacking]], [[13_SOC_Blue_Team]], [[68_Purple_Team]]).

---

<a name="english"></a>

# Cryptography for Hackers

## Fundamental Cryptography Concepts

```
Plaintext → [Encryption] → Ciphertext → [Decryption] → Plaintext
                ↑                                ↑
              Key                              Key

Symmetric Cipher: Encryption Key = Decryption Key
  AES, DES, 3DES, ChaCha20, Blowfish

Asymmetric Cipher: Public Key (encryption) ≠ Private Key (decryption)
  RSA, ECC, DSA, ElGamal

Hash Function: One-way transformation (cannot be decrypted)
  MD5, SHA-1, SHA-256, SHA-3, bcrypt, Argon2
```

---

## 1. Classical Ciphers (Understanding Vulnerabilities)

### Caesar Cipher

This is an implementation of the Caesar Cipher. It is the simplest substitution cipher, shifting each letter by a fixed number of positions. Since there are only 26 possible keys, it can be broken immediately by brute force.

```python
def caesar_encrypt(text: str, shift: int) -> str:
    result = ""
    for char in text:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            result += chr((ord(char) - base + shift) % 26 + base)
        else:
            result += char
    return result

def caesar_brute_force(ciphertext: str):
    """Caesar cipher brute-force attack (all 26 keys)"""
    for shift in range(26):
        decrypted = caesar_encrypt(ciphertext, -shift)
        print(f"Shift {shift:2d}: {decrypted}")

# Example
ciphertext = "Khoor, Zruog!"  # Hello, World! (shift=3)
caesar_brute_force(ciphertext)
```

### Vigenere Cipher

This implements Vigenere cipher decryption. It uses multiple Caesar ciphers repeated over the key length. However, once the key length is determined via Kasiski analysis or the Index of Coincidence, it can be broken.

```python
def vigenere_decrypt(ciphertext: str, key: str) -> str:
    """Vigenere cipher decryption"""
    result = ""
    key_len = len(key)
    key_idx = 0
    
    for char in ciphertext:
        if char.isalpha():
            shift = ord(key[key_idx % key_len].upper()) - ord('A')
            base = ord('A') if char.isupper() else ord('a')
            result += chr((ord(char) - base - shift) % 26 + base)
            key_idx += 1
        else:
            result += char
    
    return result

def kasiski_test(ciphertext: str, min_len: int = 3) -> dict:
    """Kasiski test — estimate key length"""
    from math import gcd
    from functools import reduce
    
    distances = {}
    clean = ciphertext.replace(" ", "").upper()
    
    # Find repeated patterns
    for length in range(min_len, 6):
        for i in range(len(clean) - length):
            seq = clean[i:i+length]
            occurrences = [j for j in range(i+1, len(clean)-length)
                          if clean[j:j+length] == seq]
            if occurrences:
                for occ in occurrences:
                    distance = occ - i
                    distances[seq] = distances.get(seq, []) + [distance]
    
    # GCD of distances → estimated key length
    all_distances = [d for dists in distances.values() for d in dists]
    if all_distances:
        key_length = reduce(gcd, all_distances)
        print(f"Estimated key length: {key_length}")
    
    return distances
```

### XOR Cipher

This implements XOR encryption. Simple single-key-length XOR can be broken by crib-dragging attacks. It is commonly used in malware to obfuscate payloads.

```python
#!/usr/bin/env python3
"""XOR encryption and single/repeating key cracking CLI tool"""

import argparse
import sys
from typing import Optional


def xor_encrypt(data: bytes, key: bytes) -> bytes:
    """XOR encrypt/decrypt (same operation)"""
    key_len = len(key)
    return bytes([b ^ key[i % key_len] for i, b in enumerate(data)])


def xor_crack_single_byte(ciphertext: bytes) -> tuple[int, bytes, float]:
    """Single-byte XOR crack — English frequency analysis"""
    english_freq: dict[str, float] = {
        'e': 12.7, 't': 9.1, 'a': 8.2, 'o': 7.5, 'i': 7.0,
        'n': 6.7, 's': 6.3, 'h': 6.1, 'r': 6.0, 'd': 4.3,
        ' ': 13.0,  # space weight
    }
    best_key, best_score, best_plain = 0, 0.0, b""

    for key_byte in range(256):
        decrypted = bytes([b ^ key_byte for b in ciphertext])
        try:
            text = decrypted.decode('ascii')
        except (UnicodeDecodeError, ValueError):
            continue
        score = sum(english_freq.get(c.lower(), 0) for c in text)
        if score > best_score:
            best_score, best_key, best_plain = score, key_byte, decrypted

    return best_key, best_plain, best_score


def crack_repeating_xor(ciphertext: bytes, max_keysize: int = 40) -> tuple[bytes, bytes]:
    """Repeating-key XOR crack (CryptoPals Set1 Ch6 style)"""

    def hamming(a: bytes, b: bytes) -> int:
        return sum(bin(x ^ y).count('1') for x, y in zip(a, b))

    # Step 1: Estimate key size
    scores: dict[int, float] = {}
    for ks in range(2, min(max_keysize + 1, len(ciphertext) // 4 + 1)):
        blocks = [ciphertext[i * ks:(i + 1) * ks] for i in range(4)]
        pairs = [(blocks[i], blocks[j]) for i in range(4) for j in range(i + 1, 4)
                 if len(blocks[i]) == ks and len(blocks[j]) == ks]
        if not pairs:
            continue
        avg = sum(hamming(a, b) / ks for a, b in pairs) / len(pairs)
        scores[ks] = avg

    best_ks = min(scores, key=scores.get)

    # Step 2: Recover each key byte
    key = bytes(
        xor_crack_single_byte(
            bytes([ciphertext[j] for j in range(i, len(ciphertext), best_ks)])
        )[0]
        for i in range(best_ks)
    )

    plaintext = xor_encrypt(ciphertext, key)
    return key, plaintext


def main() -> None:
    parser = argparse.ArgumentParser(description="XOR encryption/cracking tool")
    sub = parser.add_subparsers(dest="cmd", required=True)

    enc_p = sub.add_parser("encrypt", help="XOR encrypt/decrypt")
    enc_p.add_argument("--hex-input", required=True, help="Input data (hex)")
    enc_p.add_argument("--key", required=True, help="Key (hex or string)")
    enc_p.add_argument("--key-hex", action="store_true", help="Interpret key as hex")

    crack_p = sub.add_parser("crack", help="Single/repeating byte XOR crack")
    crack_p.add_argument("--hex-input", required=True, help="Ciphertext (hex)")
    crack_p.add_argument("--mode", choices=["single", "repeating"], default="single")
    crack_p.add_argument("--max-keysize", type=int, default=40)

    args = parser.parse_args()

    if args.cmd == "encrypt":
        data = bytes.fromhex(args.hex_input)
        key = bytes.fromhex(args.key) if args.key_hex else args.key.encode()
        result = xor_encrypt(data, key)
        print(f"Result (hex): {result.hex()}")
        try:
            print(f"Result (ascii): {result.decode('ascii')}")
        except (UnicodeDecodeError, ValueError):
            pass

    elif args.cmd == "crack":
        ct = bytes.fromhex(args.hex_input)
        if args.mode == "single":
            k, plain, score = xor_crack_single_byte(ct)
            print(f"Key byte : 0x{k:02x}  ({chr(k) if 32 <= k < 127 else '?'})")
            print(f"Score    : {score:.2f}")
            print(f"Plaintext: {plain}")
        else:
            key, plain = crack_repeating_xor(ct, args.max_keysize)
            print(f"Key (hex)  : {key.hex()}")
            print(f"Key (ascii): {key.decode('latin-1')}")
            print(f"Plaintext  :\n{plain.decode('latin-1')}")


if __name__ == "__main__":
    # Quick demo (when run with no arguments)
    if len(sys.argv) == 1:
        demo_ct = bytes.fromhex(
            "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
        )
        k, plain, score = xor_crack_single_byte(demo_ct)
        print(f"[Demo] Key: 0x{k:02x} ({chr(k)})  Score: {score:.2f}")
        print(f"[Demo] Plaintext: {plain}")
    else:
        main()
```

---

## 2. Modern Cryptography

### AES Encryption Mode Vulnerabilities

This code demonstrates vulnerabilities in different AES modes of operation. ECB mode has a pattern exposure weakness where identical input blocks produce identical ciphertext blocks.

```python
#!/usr/bin/env python3
"""AES mode vulnerability PoC — CBC bit-flipping, CTR nonce reuse, ECB pattern attack, AES-GCM correct implementation"""

import argparse
import os
import sys

try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad
except ImportError:
    print("[-] pycryptodome required: pip install pycryptodome", file=sys.stderr)
    sys.exit(1)


# ── Helper functions ────────────────────────────────────────────────

def aes_cbc_encrypt(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    return AES.new(key, AES.MODE_CBC, iv).encrypt(pad(plaintext, 16))


def aes_cbc_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    return unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(ciphertext), 16)


# ── Attack 1: CBC Bit Flipping ──────────────────────────────────

def cbc_bit_flip_demo() -> None:
    """
    CBC bit flipping: manipulate a previous ciphertext block → tamper with the decrypted output
      P'[i] = AES_Dec(C[i]) XOR C'[i-1]
    Goal: in the second block 'role=user&admin=', change 'user' → 'admi'
    """
    key = os.urandom(16)
    iv  = os.urandom(16)

    # Block0 (16B) = padding, Block1 (16B) = 'role=user&admin='
    plaintext = b"A" * 16 + b"role=user&admin="
    ciphertext = aes_cbc_encrypt(plaintext, key, iv)

    original_bytes = b"role=user"
    target_bytes   = b"role=admi"

    modified = bytearray(ciphertext)
    for i, (orig, targ) in enumerate(zip(original_bytes, target_bytes)):
        modified[16 + i] ^= orig ^ targ   # Tamper with block0 (indices 16–31)

    try:
        result = aes_cbc_decrypt(bytes(modified), key, iv)
        print(f"[CBC Bit-Flip] Decryption result: {result}")
    except ValueError as e:
        print(f"[CBC Bit-Flip] Padding error (some bytes modified): {e}")


# ── Attack 2: CTR Nonce Reuse ──────────────────────────────────

def ctr_nonce_reuse_demo() -> None:
    """
    CTR mode nonce reuse:
      C1 = P1 ⊕ KS,  C2 = P2 ⊕ KS  →  C1⊕C2 = P1⊕P2
    If P1 is known, P2 can be fully recovered
    """
    key   = os.urandom(16)
    nonce = b"\x00" * 8   # Fatal mistake: fixed nonce

    def ctr_enc(pt: bytes) -> bytes:
        return AES.new(key, AES.MODE_CTR, nonce=nonce).encrypt(pt)

    msg1 = b"Hello, World!!!!!"
    msg2 = b"Secret Password!!"

    c1 = ctr_enc(msg1)
    c2 = ctr_enc(msg2)   # Same nonce reused!

    # When attacker knows msg1, c1, and c2
    keystream = bytes(a ^ b for a, b in zip(c1, msg1))
    recovered = bytes(a ^ b for a, b in zip(c2, keystream))
    print(f"[CTR Nonce Reuse] Recovered msg2: {recovered}")


# ── Attack 3: ECB Cut-and-Paste ────────────────────────────────

def ecb_cut_and_paste_demo() -> None:
    """
    ECB mode: identical 16-byte blocks → identical ciphertext blocks
    Cut the admin-padded block and paste it over the role=user position
    """
    key = os.urandom(16)

    def encrypt_profile(email: str) -> bytes:
        profile = f"email={email}&uid=10&role=user"
        return AES.new(key, AES.MODE_ECB).encrypt(pad(profile.encode(), 16))

    # Block0: "email=AAAAAAAAAA" (16B)
    # Block1: "admin\x0b\x0b...\x0b" — padded admin block (16B)
    # Block2: "&uid=10&role=use"
    craft_email = "AAAAAAAAAA" + "admin" + chr(11) * 11
    encrypted   = encrypt_profile(craft_email)
    admin_block = encrypted[16:32]

    # Adjust email length so role=user falls exactly on a block boundary
    # "email=" = 6, "&uid=10&role=" = 13  → 6 + email_len ≡ 0 (mod 16) → len=10
    normal_enc = encrypt_profile("test@ex.co")   # 10 chars
    forged     = normal_enc[:-16] + admin_block  # Replace last block

    decrypted = unpad(AES.new(key, AES.MODE_ECB).decrypt(forged), 16)
    print(f"[ECB Cut-Paste] Forged result: {decrypted.decode()}")


# ── Correct Implementation: AES-256-GCM ────────────────────────────────

def aes_gcm_demo() -> None:
    """AES-256-GCM — AEAD (authentication + encryption), fresh nonce every time"""
    key   = os.urandom(32)   # 256-bit
    nonce = os.urandom(12)   # 96-bit (recommended for GCM)
    aad   = b"authenticated-but-not-encrypted"

    plaintext = b"Sensitive data: TOP SECRET"

    cipher     = AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher.update(aad)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    print(f"[AES-GCM] CT={ciphertext.hex()}  TAG={tag.hex()}")

    # Decrypt + verify authentication tag
    dec = AES.new(key, AES.MODE_GCM, nonce=nonce)
    dec.update(aad)
    try:
        recovered = dec.decrypt_and_verify(ciphertext, tag)
        print(f"[AES-GCM] Decryption successful: {recovered}")
    except ValueError:
        print("[AES-GCM] Authentication failed — data tampering detected!")


# ── CLI ──────────────────────────────────────────────────────

def main() -> None:
    demos = {
        "cbc-flip":   cbc_bit_flip_demo,
        "ctr-reuse":  ctr_nonce_reuse_demo,
        "ecb-paste":  ecb_cut_and_paste_demo,
        "gcm":        aes_gcm_demo,
    }

    parser = argparse.ArgumentParser(description="AES mode vulnerability PoC")
    parser.add_argument("demo", choices=list(demos) + ["all"],
                        nargs="?", default="all",
                        help="Demo to run (default: all)")
    args = parser.parse_args()

    targets = list(demos.values()) if args.demo == "all" else [demos[args.demo]]
    for fn in targets:
        fn()
        print()


if __name__ == "__main__":
    main()
```

---

## 3. RSA Attack Techniques

### RSA Basics

```
RSA Key Generation:
  1. Select large primes p, q
  2. n = p * q (modulus)
  3. φ(n) = (p-1)(q-1) (Euler's totient)
  4. Choose e such that gcd(e, φ(n)) = 1 (commonly 65537)
  5. d = e^(-1) mod φ(n) (private key)
  
  Public key:  (n, e)
  Private key: (n, d)

Encryption: C = M^e mod n
Decryption: M = C^d mod n
Signing:    S = M^d mod n
Verify:     M = S^e mod n
```

### RSA Vulnerability Attacks

This code attacks weak RSA implementations. It exploits small public exponent (e=3), common modulus attacks, padding oracle attacks, and other RSA implementation flaws.

```python
#!/usr/bin/env python3
"""RSA vulnerability attack toolkit — Small-e, GCD, Wiener, Hastad broadcast"""

from __future__ import annotations
import argparse
import sys
from math import gcd, isqrt
from functools import reduce


# ── Integer e-th root (for small exponent attacks) ─────────────────────────

def iroot(n: int, e: int) -> tuple[int, bool]:
    """Return the integer e-th root of n, and whether it is exact"""
    if n < 0:
        return 0, False
    if e == 1:
        return n, True
    # Newton's method
    x = int(round(n ** (1 / e)))
    for candidate in range(max(0, x - 2), x + 3):
        if candidate ** e == n:
            return candidate, True
    return x, False


# ── 1. Small-e Attack ──────────────────────────────────────────

def small_e_attack(ciphertext: int, e: int = 3) -> int | None:
    """
    If e=3 and M^e < n, then C = M^e with no modular reduction
    → Recover plaintext by taking the integer e-th root
    """
    m, exact = iroot(ciphertext, e)
    if exact:
        print(f"[+] Small-e success: M = {m}")
        return m
    print("[-] Small-e failed: M^e >= n or no exact integer root")
    return None


# ── 2. Common Factor Attack ──────────────────────────────────────

def common_factor_attack(n1: int, n2: int, e: int, c1: int) -> int | None:
    """
    When two RSA moduli share a common prime p, gcd(n1, n2) = p
    → Factor n1 → recover d → decrypt c1
    """
    p = gcd(n1, n2)
    if p == 1:
        print("[-] No common factor found")
        return None

    q     = n1 // p
    phi_n = (p - 1) * (q - 1)
    d     = pow(e, -1, phi_n)
    m     = pow(c1, d, n1)
    print(f"[+] Common factor p = {p}")
    print(f"[+] Decrypted M = {m}")
    return m


# ── 3. Wiener Attack (small d) ──────────────────────────────────

def wiener_attack(e: int, n: int) -> int | None:
    """
    When d < n^0.25, recover d via convergents of the continued fraction of e/n
    """

    def continued_fraction(num: int, den: int) -> list[int]:
        cf: list[int] = []
        while den:
            cf.append(num // den)
            num, den = den, num % den
        return cf

    def convergents(cf: list[int]) -> list[tuple[int, int]]:
        convs: list[tuple[int, int]] = []
        for i, q in enumerate(cf):
            if i == 0:
                convs.append((q, 1))
            elif i == 1:
                convs.append((q * cf[0] + 1, q))
            else:
                h = q * convs[-1][0] + convs[-2][0]
                k = q * convs[-1][1] + convs[-2][1]
                convs.append((h, k))
        return convs

    for k, d in convergents(continued_fraction(e, n)):
        if k == 0 or (e * d - 1) % k != 0:
            continue
        phi_n = (e * d - 1) // k
        # p + q = n - phi_n + 1,  discriminant = (p+q)^2 - 4n
        b    = n - phi_n + 1
        disc = b * b - 4 * n
        if disc < 0:
            continue
        sq = isqrt(disc)
        if sq * sq == disc:
            p, q = (b + sq) // 2, (b - sq) // 2
            if p * q == n:
                print(f"[+] Wiener success: d = {d}")
                return d

    print("[-] Wiener attack failed: d is not small enough")
    return None


# ── 4. Hastad Broadcast Attack ──────────────────────────────────

def hastad_broadcast(ciphertexts: list[int], moduli: list[int],
                     e: int = 3) -> int | None:
    """
    Same plaintext encrypted with e different public keys → recover M^e via CRT, then take e-th root
    Requires: len(ciphertexts) == len(moduli) == e
    """
    if len(ciphertexts) < e or len(moduli) < e:
        print(f"[-] Fewer than {e} ciphertexts/moduli provided")
        return None

    # Chinese Remainder Theorem
    M = reduce(lambda a, b: a * b, moduli[:e])
    x = 0
    for ci, ni in zip(ciphertexts[:e], moduli[:e]):
        Mi = M // ni
        yi = pow(Mi, -1, ni)
        x  = (x + ci * Mi * yi) % M

    m, exact = iroot(x, e)
    if exact:
        print(f"[+] Hastad success: M = {m}")
        return m
    print("[-] Hastad failed: CRT result has no exact integer e-th root")
    return None


# ── CLI ──────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="RSA attack toolkit")
    sub = parser.add_subparsers(dest="attack", required=True)

    # small-e
    p1 = sub.add_parser("small-e", help="Small public exponent attack")
    p1.add_argument("--ciphertext", type=lambda x: int(x, 0), required=True)
    p1.add_argument("--e", type=int, default=3)

    # gcd
    p2 = sub.add_parser("gcd", help="Common prime factor attack")
    p2.add_argument("--n1", type=lambda x: int(x, 0), required=True)
    p2.add_argument("--n2", type=lambda x: int(x, 0), required=True)
    p2.add_argument("--e", type=int, required=True)
    p2.add_argument("--c1", type=lambda x: int(x, 0), required=True)

    # wiener
    p3 = sub.add_parser("wiener", help="Wiener small-d attack")
    p3.add_argument("--e", type=lambda x: int(x, 0), required=True)
    p3.add_argument("--n", type=lambda x: int(x, 0), required=True)

    # hastad
    p4 = sub.add_parser("hastad", help="Hastad broadcast attack")
    p4.add_argument("--e", type=int, default=3)
    p4.add_argument("--ciphertexts", nargs="+", type=lambda x: int(x, 0), required=True)
    p4.add_argument("--moduli",      nargs="+", type=lambda x: int(x, 0), required=True)

    args = parser.parse_args()

    if args.attack == "small-e":
        small_e_attack(args.ciphertext, args.e)
    elif args.attack == "gcd":
        common_factor_attack(args.n1, args.n2, args.e, args.c1)
    elif args.attack == "wiener":
        wiener_attack(args.e, args.n)
    elif args.attack == "hastad":
        hastad_broadcast(args.ciphertexts, args.moduli, args.e)


if __name__ == "__main__":
    if len(sys.argv) == 1:
        # Default demo: small-e
        print("[Demo] small-e: M=42, e=3, C=42^3=74088")
        small_e_attack(74088, 3)
    else:
        main()
```

---

## 4. Hash Cracking

### Hash Type Identification

Use hashid or hash-identifier to determine the hash algorithm. The hash length and character set pattern help distinguish MD5, SHA-1, bcrypt, and others.

```bash
# Identify hash type with hashid
hashid "5f4dcc3b5aa765d61d8327deb882cf99"
hashid "e3b0c44298fc1c149afbf4c8996fb924"

# Key hashcat modes
# -m 0    MD5
# -m 100  SHA1
# -m 1400 SHA256
# -m 1700 SHA512
# -m 1800 sha512crypt ($6$) (Linux /etc/shadow)
# -m 500  md5crypt ($1$) (Linux /etc/shadow)
# -m 3200 bcrypt ($2*$)
# -m 1000 NTLM (Windows)
# -m 5600 NetNTLMv2
# -m 13100 Kerberoast ($krb5tgs$)
# -m 18200 AS-REP Roast ($krb5asrep$)
```

```python
#!/usr/bin/env python3
"""Automatic hash type identification and crack preparation"""

import re
import hashlib

HASH_PATTERNS = {
    'MD5': (r'^[a-f0-9]{32}$', 0),
    'SHA1': (r'^[a-f0-9]{40}$', 100),
    'SHA256': (r'^[a-f0-9]{64}$', 1400),
    'SHA512': (r'^[a-f0-9]{128}$', 1700),
    'NTLM': (r'^[a-f0-9]{32}$', 1000),  # Same length as MD5
    'bcrypt': (r'^\$2[ayb]\$.{56}$', 3200),
    'sha512crypt': (r'^\$6\$.{8,16}\$.{86}$', 1800),
    'md5crypt': (r'^\$1\$.{8}\$.{22}$', 500),
}

def identify_hash(hash_str: str) -> list:
    matches = []
    for name, (pattern, mode) in HASH_PATTERNS.items():
        if re.match(pattern, hash_str, re.IGNORECASE):
            matches.append((name, mode))
    return matches

def crack_md5(hash_str: str, wordlist: str) -> str:
    """MD5 hash dictionary cracking"""
    with open(wordlist, 'r', encoding='latin-1') as f:
        for word in f:
            word = word.strip()
            if hashlib.md5(word.encode()).hexdigest() == hash_str:
                return word
    return None

# Usage example
test_hash = "5f4dcc3b5aa765d61d8327deb882cf99"
types = identify_hash(test_hash)
print(f"Candidate hash types: {types}")

# Generate hashcat commands
for name, mode in types:
    print(f"hashcat -m {mode} {test_hash} wordlist.txt")
```

---

## 5. TLS/SSL Vulnerabilities

### Known TLS Attacks

Check for known TLS vulnerabilities (BEAST, POODLE, FREAK, Heartbleed). Verify whether vulnerable TLS versions and cipher suites are in use.

```bash
# BEAST (TLS 1.0 CBC)
# Mitigation: use TLS 1.2+

# POODLE (SSL 3.0 CBC padding oracle)
# Check
openssl s_client -ssl3 -connect target.com:443
# Mitigation: disable SSL 3.0

# HEARTBLEED (OpenSSL 1.0.1-1.0.1f)
# CVE-2014-0160
nmap --script ssl-heartbleed target.com
python3 heartbleed.py target.com

# DROWN (SSLv2 shared keys)
# Check if SSLv2 is enabled
openssl s_client -ssl2 -connect target.com:443
nmap --script sslv2 target.com

# FREAK (512-bit RSA export keys)
openssl s_client -cipher EXPORT -connect target.com:443

# LOGJAM (512-bit DH)
openssl s_client -cipher DHE -connect target.com:443

# Comprehensive TLS scan
testssl.sh target.com
sslyze target.com --regular
```

### Certificate Analysis

OpenSSL CLI commands for various cryptographic operations. Essential tools for security practice: symmetric encryption (`enc`), asymmetric key generation (`genrsa`, `genpkey`), certificate generation (`req`), and TLS server testing (`s_client`).

```bash
# Extract certificate information
echo | openssl s_client -connect target.com:443 2>/dev/null | \
    openssl x509 -noout -text

# Check certificate expiry
echo | openssl s_client -connect target.com:443 2>/dev/null | \
    openssl x509 -noout -dates

# Certificate hash (for certificate pinning bypass research)
echo | openssl s_client -connect target.com:443 2>/dev/null | \
    openssl x509 -noout -fingerprint -sha256

# Certificate Transparency search
curl -s "https://crt.sh/?q=%.target.com&output=json" | \
    python3 -c "import json,sys; [print(e['name_value']) for e in json.load(sys.stdin)]" | \
    sort -u
```

---

## 6. Random Number Generator Vulnerabilities

This code demonstrates attacks that predict the state of a weak pseudo-random number generator (PRNG). PRNGs with predictable seeds or short cycles are not cryptographically secure.

```python
# Predicting a weak random number generator
import random
import time

# Bad example: time-based seed
def bad_token_generation():
    random.seed(int(time.time()))  # Predictable!
    return hex(random.getrandbits(64))

# Reversing a weak seed
def crack_time_seed(leaked_token: int, time_window: int = 3600):
    """
    For a time-based seed:
    Try all seeds within current time ± time_window
    """
    current_time = int(time.time())
    
    for seed in range(current_time - time_window, current_time + 1):
        random.seed(seed)
        candidate = random.getrandbits(64)
        
        if candidate == leaked_token:
            print(f"[+] Seed found: {seed}")
            # Next token can now be predicted
            next_token = hex(random.getrandbits(64))
            print(f"[+] Predicted next token: {next_token}")
            return seed
    
    return None

# PHP rand() crack (32-bit seed)
def crack_php_rand(known_output: int):
    """PHP mt_rand() crack (exhaustive search)"""
    # mt_srand vulnerability prior to PHP 7
    for seed in range(0, 2**32):
        # PHP mt_rand simulation (actually more complex)
        import ctypes
        # ...actual implementation requires reverse engineering PHP internals
        pass
```

---

## 7. Cryptographic Challenges (CTF Style)

### CryptoPals Challenge Style

This is a CryptoPals-style implementation. Repeating-key XOR cracking first estimates the key length using Hamming distance, then applies single-byte XOR frequency analysis.

```python
# Set 1, Challenge 6: Repeating-key XOR crack
def crack_repeating_xor(ciphertext: bytes) -> str:
    """
    1. Estimate key size using Hamming distance
    2. Crack each position as single-byte XOR
    3. Reassemble the key
    """
    def hamming_distance(a: bytes, b: bytes) -> int:
        return sum(bin(x ^ y).count('1') for x, y in zip(a, b))
    
    # Step 1: Estimate key size
    scores = {}
    for keysize in range(2, 41):
        if len(ciphertext) < keysize * 4:
            break
        
        blocks = [ciphertext[i*keysize:(i+1)*keysize] for i in range(4)]
        
        distances = []
        for i in range(len(blocks)-1):
            for j in range(i+1, len(blocks)):
                d = hamming_distance(blocks[i], blocks[j]) / keysize
                distances.append(d)
        
        scores[keysize] = sum(distances) / len(distances)
    
    best_keysize = min(scores, key=scores.get)
    print(f"Estimated key size: {best_keysize}")
    
    # Step 2: Crack each key byte
    key = []
    for i in range(best_keysize):
        block = bytes([ciphertext[j] for j in range(i, len(ciphertext), best_keysize)])
        best_byte, _ = xor_crack_single_byte(block)  # Defined above
        key.append(best_byte)
    
    # Step 3: Decrypt
    key_bytes = bytes(key)
    plaintext = bytes([c ^ key_bytes[i % len(key_bytes)] 
                       for i, c in enumerate(ciphertext)])
    
    return plaintext.decode('utf-8', errors='replace'), key_bytes
```

---

## 8. Practical Cryptanalysis Tools

Key tools used in cryptanalysis. CyberChef is a browser-based tool that supports a wide range of encoding and encryption transformations.

```bash
# CyberChef - browser-based cryptanalysis
# https://gchq.github.io/CyberChef/

# hashcat - hash cracking
hashcat -m 0 hash.txt wordlist.txt

# John the Ripper
john hash.txt --wordlist=wordlist.txt

# rsatool - RSA calculations
python3 rsatool.py -n N -e E -p P -q Q

# factordb - factorization database lookup
curl http://factordb.com/api?query=LARGE_NUMBER

# SageMath - mathematical cryptanalysis
sage -c "factor(n)"

# OpenSSL comprehensive analysis
openssl rsa -text -noout -in private.pem
openssl x509 -text -noout -in cert.pem
openssl dgst -sha256 file.txt
```

<!-- detect-validate-16 -->
## Cryptography Weakness Detection and Defense Validation

Crypto attacks target *weak algorithms, bad parameters, and poor randomness*. Defenders must verify **which ciphers, key sizes, and TLS versions are actually in use** and **whether weak suites, legacy signatures, and predictable tokens are detected**. Practice only on **owned/authorized targets**.

### Attack -> Targeted weakness -> Primary control (defender) -> Detection signal

| Technique | Targeted weakness | Primary control (defender) | Detection signal |
|---|---|---|---|
| Legacy cipher abuse (DES/RC4/MD5) | Legacy algorithms | Enforce strong suites, disable legacy | Weak algorithm in handshake/config |
| RSA weak params (small e/common modulus) | Bad key generation | Vetted libraries, 2048+ keys | Non-standard key size/exponent |
| Weak randomness (predictable seed) | Low entropy | CSPRNG (secrets, /dev/urandom) | Repeated/predictable tokens |
| Plaintext/weak TLS transport | Missing transport protection | Enforce TLS1.2+, HSTS | Downgrade/plaintext transport  |

### Defense validation (verify directly)

```bash
# 1) Inspect cert/key algorithm and size — flag weak RSA (<2048) and legacy signatures
openssl x509 -in cert.pem -noout -text | grep -E "Public-Key|Signature Algorithm"
# 2) Confirm whether the server accepts old TLS/weak ciphers (own target)
openssl s_client -connect example.com:443 -tls1_1 </dev/null 2>&1 | grep -E "Protocol|Cipher"
#   A completed handshake means TLS1.1 lingers -> downgrade surface
```

> Crypto defense starts by confirming *what is actually running* as fact -- "we use strong crypto" differs from "weak suites and old TLS are disabled". Inspect algorithms, key sizes, and protocols directly on owned targets ([[02_Network_Hacking]], [[13_SOC_Blue_Team]], [[68_Purple_Team]]).
