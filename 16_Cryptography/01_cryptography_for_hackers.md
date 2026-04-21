# 해커를 위한 암호학

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
