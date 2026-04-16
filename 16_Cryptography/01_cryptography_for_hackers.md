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

```python
def xor_encrypt(data: bytes, key: bytes) -> bytes:
    """XOR 암호화/복호화 (동일 연산)"""
    key_len = len(key)
    return bytes([b ^ key[i % key_len] for i, b in enumerate(data)])

def xor_crack_single_byte(ciphertext: bytes) -> tuple:
    """단일 바이트 XOR 크랙 (빈도 분석)"""
    best_key = 0
    best_score = 0
    
    english_freq = {
        'e': 12.7, 't': 9.1, 'a': 8.2, 'o': 7.5, 'i': 7.0,
        'n': 6.7, 's': 6.3, 'h': 6.1, 'r': 6.0, 'd': 4.3
    }
    
    for key in range(256):
        decrypted = bytes([b ^ key for b in ciphertext])
        
        try:
            text = decrypted.decode('ascii')
        except:
            continue
        
        score = sum(english_freq.get(c.lower(), 0) for c in text)
        
        if score > best_score:
            best_score = score
            best_key = key
    
    return best_key, bytes([b ^ best_key for b in ciphertext])

# CryptoPals 챌린지 스타일
if __name__ == "__main__":
    import base64
    
    ciphertext = bytes.fromhex(
        "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
    )
    key, plaintext = xor_crack_single_byte(ciphertext)
    print(f"Key: {key} ({chr(key)})")
    print(f"Plaintext: {plaintext}")
```

---

## 2. 현대 암호학

### AES 암호화 모드별 취약점

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os

# CBC 모드 - 비트 플리핑 공격 가능
def aes_cbc_encrypt(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(plaintext, 16))

def aes_cbc_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), 16)

# CBC 비트 플리핑 공격
def cbc_bit_flip_attack():
    """
    CBC 비트 플리핑: IV 또는 이전 블록 변조로 복호화 결과 조작
    
    블록 N 복호화 = AES_Dec(블록 N) XOR 블록 N-1
    
    목표: "role=user" → "role=admi" 로 변조
    """
    key = os.urandom(16)
    iv = os.urandom(16)
    
    # 원본 데이터
    plaintext = b"A" * 16 + b"role=user&admin="
    ciphertext = aes_cbc_encrypt(plaintext, key, iv)
    
    # 공격: 첫 번째 블록을 변조해서 두 번째 블록의 복호화 결과를 바꿈
    # 변조할 블록 인덱스 계산
    original = b"role=user"
    target   = b"role=admi"
    
    modified_ciphertext = bytearray(ciphertext)
    
    for i, (orig, targ) in enumerate(zip(original, target)):
        modified_ciphertext[16 + i] ^= orig ^ targ  # 비트 플립
    
    decrypted = aes_cbc_decrypt(bytes(modified_ciphertext), key, iv)
    print(f"변조 결과: {decrypted}")

# CTR 모드 - 키스트림 재사용 취약점
def ctr_keystream_reuse():
    """
    CTR 모드에서 동일 키+논스 재사용 시:
    C1 = P1 XOR KeyStream
    C2 = P2 XOR KeyStream
    C1 XOR C2 = P1 XOR P2
    → 하나의 평문 알면 다른 평문 복원 가능
    """
    key = os.urandom(16)
    nonce = 0  # 치명적 실수: 논스 재사용
    
    msg1 = b"Hello, World!!!!!"
    msg2 = b"Secret Password!!"
    
    def ctr_encrypt(plaintext, key, nonce):
        cipher = AES.new(key, AES.MODE_CTR, nonce=nonce.to_bytes(8, 'little'))
        return cipher.encrypt(plaintext)
    
    c1 = ctr_encrypt(msg1, key, nonce)
    c2 = ctr_encrypt(msg2, key, nonce)  # 동일 논스!
    
    # 공격: c1 XOR c2 = msg1 XOR msg2
    xored = bytes([a ^ b for a, b in zip(c1, c2)])
    
    # msg1을 알면 msg2 복원
    recovered = bytes([a ^ b for a, b in zip(xored, msg1)])
    print(f"복원된 msg2: {recovered}")

# ECB 모드 - 패턴 노출 취약점
def ecb_penguin_attack():
    """
    ECB 모드: 동일 평문 블록 → 동일 암호문 블록
    → 패턴 분석으로 정보 유출
    """
    key = os.urandom(16)
    
    # 예: 사용자 프로파일 암호화
    def encrypt_profile(email: str) -> bytes:
        profile = f"email={email}&uid=10&role=user"
        cipher = AES.new(key, AES.MODE_ECB)
        return cipher.encrypt(pad(profile.encode(), 16))
    
    # 블록 경계 조작으로 "role=admin" 블록 생성
    # 블록 1: "email=AAAAAAAAA"  (16바이트)
    # 블록 2: "admin\x0b\x0b\x0b..." (패딩된 admin 블록)
    # 블록 3: "&uid=10&role=us"
    # ...
    
    malicious = "AAAAAAAAAA" + "admin" + "\x0b" * 11
    encrypted = encrypt_profile(malicious)
    
    # 블록 2가 "admin" 블록
    admin_block = encrypted[16:32]
    
    # 정상 이메일로 만든 암호문의 마지막 블록을 교체
    normal = encrypt_profile("test@test.co")  # 블록 경계 맞춤
    
    forged = normal[:32] + admin_block
    
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted = unpad(cipher.decrypt(forged), 16)
    print(f"위조 결과: {decrypted.decode()}")
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

```python
from math import gcd, isqrt
from sympy import factorint

# 1. 작은 공개 지수 (e=3) + 작은 메시지 → 세제곱근 공격
def small_e_attack(ciphertext: int, e: int = 3) -> int:
    """
    e=3, M이 작을 때: C = M^3 mod n
    M^3 < n이면: M = cbrt(C)
    """
    # 세제곱근 계산
    m = round(ciphertext ** (1/e))
    for candidate in range(m-2, m+3):
        if candidate ** e == ciphertext:
            return candidate
    return None

# 2. 공통 소인수 공격 (GCD 공격)
def common_factor_attack(n1: int, n2: int, e: int, c1: int) -> int:
    """
    두 RSA 키가 공통 소수를 공유할 때
    gcd(n1, n2) = p → 두 키 모두 해독 가능
    """
    p = gcd(n1, n2)
    if p == 1:
        print("공통 소인수 없음")
        return None
    
    q = n1 // p
    phi_n = (p-1) * (q-1)
    d = pow(e, -1, phi_n)  # 모듈러 역수
    
    m = pow(c1, d, n1)
    return m

# 3. 위너 공격 (작은 d)
def wiener_attack(e: int, n: int):
    """
    d < n^0.25 일 때 연분수 전개로 d 복원
    """
    from fractions import Fraction
    
    def continued_fraction(numerator, denominator):
        quotients = []
        while denominator:
            quotients.append(numerator // denominator)
            numerator, denominator = denominator, numerator % denominator
        return quotients
    
    def convergents(quotients):
        convergents = []
        for i in range(len(quotients)):
            if i == 0:
                convergents.append((quotients[0], 1))
            elif i == 1:
                h = quotients[0] * quotients[1] + 1
                k = quotients[1]
                convergents.append((h, k))
            else:
                h = quotients[i] * convergents[i-1][0] + convergents[i-2][0]
                k = quotients[i] * convergents[i-1][1] + convergents[i-2][1]
                convergents.append((h, k))
        return convergents
    
    quotients = continued_fraction(e, n)
    convs = convergents(quotients)
    
    for (k, d) in convs:
        if k == 0:
            continue
        
        # φ(n) 추정
        phi_n = (e * d - 1) // k
        
        # p, q 복원 시도
        # n = p*q, p+q = n - φ(n) + 1, p-q = sqrt((p+q)^2 - 4n)
        b = n - phi_n + 1
        discriminant = b*b - 4*n
        
        if discriminant < 0:
            continue
        
        sqrt_disc = isqrt(discriminant)
        if sqrt_disc * sqrt_disc == discriminant:
            p = (b + sqrt_disc) // 2
            q = (b - sqrt_disc) // 2
            
            if p * q == n:
                print(f"[+] 개인키 d 발견: {d}")
                return d
    
    return None

# 4. Hastad 브로드캐스트 공격
def hastad_broadcast(ciphertexts: list, moduli: list, e: int = 3):
    """
    동일 메시지를 e개 다른 공개키로 암호화한 경우
    중국인 나머지 정리(CRT)로 M^e 복원 후 e제곱근
    """
    from functools import reduce
    
    def crt(remainders, moduli):
        M = reduce(lambda x, y: x*y, moduli)
        result = 0
        for r, m in zip(remainders, moduli):
            Mi = M // m
            yi = pow(Mi, -1, m)
            result += r * Mi * yi
        return result % M
    
    x = crt(ciphertexts, moduli)
    m = round(x ** (1/e))
    
    if pow(m, e) == x:
        return m
    return None
```

---

## 4. 해시 크래킹

### 해시 유형 식별

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
