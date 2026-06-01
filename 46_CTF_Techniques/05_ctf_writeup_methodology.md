> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# CTF 라이트업 작성 방법론

좋은 CTF 라이트업은 다른 사람이 같은 경로로 재현할 수 있어야 한다. 풀이 과정 문서화, 자동화 솔버 작성, 카테고리별 템플릿과 구조화된 writeup 포맷을 정리한다.

---

## 1. 라이트업 작성 원칙

### 1.1 구조 템플릿

```markdown
# [CTF 이름] — [문제 이름]

**카테고리**: Web / Pwn / Crypto / Rev / Misc / Forensics  
**점수**: 500점  
**난이도**: Hard  
**풀이 시간**: 4시간  

## 문제 설명

> 문제 원문 복사 (따옴표 블록)

접속 정보:  
- URL: http://challenge.ctf.example.com:8080  
- 파일: challenge.zip

## 분석 과정

### 1. 초기 정찰

[초기 분석 내용]

### 2. 취약점 발견

[취약점 분석 내용]

### 3. 익스플로잇

[익스플로잇 개발 과정]

## 풀이 코드

```python
# 전체 익스플로잇 코드
```

## 플래그

`FLAG{...}`

## 핵심 교훈

- 배운 점 1
- 배운 점 2
```

---

## 2. 카테고리별 자동화 도구

### 2.1 Web CTF 솔버 프레임워크

```python
#!/usr/bin/env python3
"""Web CTF 문제 자동화 솔버 프레임워크"""
import argparse
import re
from typing import Optional
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup


class WebCTFSolver:
    def __init__(self, base_url: str, proxy: Optional[str] = None) -> None:
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        if proxy:
            self.session.proxies = {"http": proxy, "https": proxy}
        self.session.verify = False
        self.flags: list[str] = []
        self.FLAG_PATTERN = re.compile(r"[A-Z0-9_]{3,10}\{[A-Za-z0-9_!@#$%^&*()\-+=.]+\}")

    def get(self, path: str, **kwargs) -> requests.Response:
        return self.session.get(urljoin(self.base_url, path), **kwargs)

    def post(self, path: str, **kwargs) -> requests.Response:
        return self.session.post(urljoin(self.base_url, path), **kwargs)

    def find_flag(self, text: str) -> list[str]:
        found = self.FLAG_PATTERN.findall(text)
        self.flags.extend(found)
        return found

    # SQLi 자동 탐지
    def test_sqli(self, path: str, param: str) -> Optional[str]:
        payloads = [
            "' OR '1'='1",
            "' OR 1=1--",
            "\" OR \"1\"=\"1",
            "1; SELECT SLEEP(3)--",
            "1 UNION SELECT NULL--",
        ]
        baseline = self.get(path, params={param: "normal_value"})

        for payload in payloads:
            resp = self.get(path, params={param: payload})
            if resp.elapsed.total_seconds() > 2.5:  # 시간 기반
                return f"Time-based SQLi: {payload}"
            if self.find_flag(resp.text):
                return f"Error-based SQLi: {payload} → FLAG 발견"
            if len(resp.text) != len(baseline.text):
                return f"Boolean SQLi 의심: {payload}"

        return None

    # XSS 탐지
    def test_xss(self, path: str, param: str) -> list[str]:
        payloads = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "{{7*7}}",  # SSTI 탐지도 겸용
            "${7*7}",
        ]
        found = []
        for payload in payloads:
            resp = self.post(path, data={param: payload})
            if payload in resp.text:
                found.append(f"반영형 XSS: {payload}")
            if "49" in resp.text and "7*7" in payload:
                found.append(f"SSTI 탐지: {payload}")
        return found

    # JWT 분석
    def analyze_jwt(self, token: str) -> dict:
        import base64
        import json

        parts = token.split(".")
        if len(parts) != 3:
            return {"error": "유효하지 않은 JWT 형식"}

        def decode_part(part: str) -> dict:
            padded = part + "=" * (4 - len(part) % 4)
            return json.loads(base64.urlsafe_b64decode(padded))

        try:
            header = decode_part(parts[0])
            payload = decode_part(parts[1])
            return {
                "header": header,
                "payload": payload,
                "algorithm": header.get("alg"),
                "none_attack": header.get("alg", "").lower() != "none",
            }
        except Exception as e:
            return {"error": str(e)}


def main() -> None:
    parser = argparse.ArgumentParser(description="Web CTF 솔버")
    parser.add_argument("url", help="대상 URL")
    parser.add_argument("--proxy", help="Burp Suite 프록시 (예: http://127.0.0.1:8080)")
    parser.add_argument("--sqli-path", help="SQLi 테스트 경로")
    parser.add_argument("--sqli-param", help="SQLi 테스트 파라미터")
    args = parser.parse_args()

    solver = WebCTFSolver(args.url, args.proxy)

    if args.sqli_path and args.sqli_param:
        result = solver.test_sqli(args.sqli_path, args.sqli_param)
        if result:
            print(f"[+] SQLi 발견: {result}")
        else:
            print("[-] SQLi 탐지 실패")


if __name__ == "__main__":
    main()
```

### 2.2 Crypto CTF 솔버

```python
#!/usr/bin/env python3
"""Crypto CTF 공통 공격 자동화"""
import argparse
import math
from typing import Optional


class CryptoCTFSolver:

    # RSA 소인수분해 (소수 차이가 작을 때 — Fermat's factorization)
    @staticmethod
    def fermat_factor(n: int) -> tuple[int, int]:
        a = math.isqrt(n)
        if a * a < n:
            a += 1
        b2 = a * a - n
        while True:
            b = math.isqrt(b2)
            if b * b == b2:
                return a - b, a + b
            a += 1
            b2 = a * a - n

    # RSA 공통 모듈러스 공격
    @staticmethod
    def common_modulus_attack(n: int, e1: int, c1: int, e2: int, c2: int) -> Optional[int]:
        def extended_gcd(a: int, b: int) -> tuple[int, int, int]:
            if b == 0:
                return a, 1, 0
            g, x, y = extended_gcd(b, a % b)
            return g, y, x - (a // b) * y

        g, s, t = extended_gcd(e1, e2)
        if g != 1:
            return None

        if s < 0:
            c1 = pow(c1, -1, n)
            s = -s
        if t < 0:
            c2 = pow(c2, -1, n)
            t = -t

        m = (pow(c1, s, n) * pow(c2, t, n)) % n
        return m

    # Wiener 공격 (작은 d)
    @staticmethod
    def wiener_attack(e: int, n: int) -> Optional[int]:
        def continued_fraction(num: int, den: int) -> list[int]:
            cf = []
            while den:
                cf.append(num // den)
                num, den = den, num % den
            return cf

        def convergents(cf: list[int]) -> list[tuple[int, int]]:
            convs = []
            for i in range(len(cf)):
                if i == 0:
                    convs.append((cf[0], 1))
                elif i == 1:
                    convs.append((cf[0] * cf[1] + 1, cf[1]))
                else:
                    h_prev, k_prev = convs[-1]
                    h_prev2, k_prev2 = convs[-2]
                    convs.append((cf[i] * h_prev + h_prev2, cf[i] * k_prev + k_prev2))
            return convs

        cf = continued_fraction(e, n)
        for k, d in convergents(cf):
            if k == 0:
                continue
            if (e * d - 1) % k != 0:
                continue
            phi = (e * d - 1) // k
            discriminant = (n - phi + 1) ** 2 - 4 * n
            if discriminant < 0:
                continue
            sqrt_disc = math.isqrt(discriminant)
            if sqrt_disc * sqrt_disc == discriminant:
                return d
        return None

    # XOR 반복키 크랙 (Kasiski 분석)
    @staticmethod
    def crack_repeating_xor(ciphertext: bytes, max_keysize: int = 40) -> bytes:
        def hamming(b1: bytes, b2: bytes) -> int:
            return sum(bin(x ^ y).count("1") for x, y in zip(b1, b2))

        scores = []
        for ks in range(2, max_keysize + 1):
            blocks = [ciphertext[i:i+ks] for i in range(0, len(ciphertext) - ks, ks)]
            if len(blocks) < 2:
                continue
            dist = sum(hamming(blocks[i], blocks[i+1]) for i in range(min(4, len(blocks)-1)))
            scores.append((dist / (ks * min(4, len(blocks)-1)), ks))

        scores.sort()
        keysize = scores[0][1]

        key = bytes()
        for i in range(keysize):
            block = bytes(ciphertext[j] for j in range(i, len(ciphertext), keysize))
            # 영어 텍스트 가정: 빈도 분석
            best_score = -1
            best_byte = 0
            for b in range(256):
                decrypted = bytes(x ^ b for x in block)
                score = sum(decrypted.count(c) for c in b" etaoinshrdlu")
                if score > best_score:
                    best_score = score
                    best_byte = b
            key += bytes([best_byte])

        return key

    # Base64 스테가노그래피 (공백 인코딩)
    @staticmethod
    def base64_steg_decode(text: str) -> str:
        import base64
        lines = text.strip().split("\n")
        bits = ""
        for line in lines:
            decoded_len = len(base64.b64decode(line + "=="))
            padding = line.count("=")
            wasted_bits = padding * 2
            if wasted_bits > 0:
                value = base64.b64decode(line + "==")[-1]
                bits += format(value & ((1 << wasted_bits) - 1), f"0{wasted_bits}b")
        chars = [chr(int(bits[i:i+8], 2)) for i in range(0, len(bits) - 7, 8)]
        return "".join(chars)


def main() -> None:
    parser = argparse.ArgumentParser(description="Crypto CTF 솔버")
    subparsers = parser.add_subparsers(dest="attack")

    rsa_p = subparsers.add_parser("rsa-fermat")
    rsa_p.add_argument("n", type=int)

    wiener_p = subparsers.add_parser("rsa-wiener")
    wiener_p.add_argument("e", type=int)
    wiener_p.add_argument("n", type=int)

    xor_p = subparsers.add_parser("xor")
    xor_p.add_argument("hex_cipher", help="16진수 암호문")

    args = parser.parse_args()
    solver = CryptoCTFSolver()

    if args.attack == "rsa-fermat":
        p, q = solver.fermat_factor(args.n)
        print(f"[+] p = {p}")
        print(f"[+] q = {q}")
    elif args.attack == "rsa-wiener":
        d = solver.wiener_attack(args.e, args.n)
        print(f"[+] d = {d}" if d else "[-] Wiener 공격 실패")
    elif args.attack == "xor":
        ct = bytes.fromhex(args.hex_cipher)
        key = solver.crack_repeating_xor(ct)
        print(f"[+] 키: {key}")
        pt = bytes(c ^ k for c, k in zip(ct, (key * (len(ct) // len(key) + 1))[:len(ct)]))
        print(f"[+] 복호화: {pt[:100]}")


if __name__ == "__main__":
    main()
```

### 2.3 Forensics CTF 솔버

```python
#!/usr/bin/env python3
"""Forensics CTF 파일 분석 자동화"""
import argparse
import struct
import zlib
from pathlib import Path


class ForensicsSolver:
    # PNG 파일 숨겨진 청크 추출
    @staticmethod
    def extract_png_chunks(path: Path) -> list[dict]:
        data = path.read_bytes()
        if data[:8] != b"\x89PNG\r\n\x1a\n":
            return []

        chunks = []
        offset = 8
        while offset < len(data):
            length = struct.unpack(">I", data[offset:offset+4])[0]
            chunk_type = data[offset+4:offset+8].decode("ascii", errors="replace")
            chunk_data = data[offset+8:offset+8+length]
            crc = struct.unpack(">I", data[offset+8+length:offset+12+length])[0]

            chunks.append({
                "type": chunk_type,
                "length": length,
                "data_preview": chunk_data[:32].hex(),
            })

            if chunk_type not in ("IHDR", "IDAT", "IEND", "tEXt", "zTXt", "bKGD", "pHYs", "gAMA"):
                print(f"[!] 비표준 청크 발견: {chunk_type} ({length} bytes)")

            offset += 12 + length

        return chunks

    # LSB 스테가노그래피 추출 (Python Imaging Library)
    @staticmethod
    def extract_lsb(image_path: Path, bits: int = 1) -> bytes:
        from PIL import Image
        img = Image.open(image_path).convert("RGB")
        pixels = list(img.getdata())

        extracted_bits = []
        for pixel in pixels:
            for channel in pixel:
                for b in range(bits):
                    extracted_bits.append((channel >> b) & 1)

        byte_data = bytes(
            int("".join(str(b) for b in extracted_bits[i:i+8]), 2)
            for i in range(0, len(extracted_bits) - 7, 8)
        )
        return byte_data

    # ZIP 패스워드 브루트포스
    @staticmethod
    def crack_zip(zip_path: Path, wordlist: Path) -> Optional[str]:
        import zipfile
        with zipfile.ZipFile(zip_path) as zf:
            for line in wordlist.read_bytes().splitlines():
                try:
                    zf.extractall(pwd=line)
                    return line.decode("utf-8", errors="replace")
                except Exception:
                    continue
        return None

    # 파일 시그니처 탐지
    @staticmethod
    def detect_embedded_files(data: bytes) -> list[dict]:
        SIGNATURES = {
            b"\x89PNG": "PNG",
            b"\xff\xd8\xff": "JPEG",
            b"PK\x03\x04": "ZIP",
            b"GIF8": "GIF",
            b"%PDF": "PDF",
            b"MZ": "PE",
            b"\x7fELF": "ELF",
            b"RIFF": "RIFF (AVI/WAV)",
        }
        found = []
        for offset in range(len(data) - 4):
            for sig, name in SIGNATURES.items():
                if data[offset:offset+len(sig)] == sig:
                    found.append({"type": name, "offset": hex(offset)})
        return found


def main() -> None:
    parser = argparse.ArgumentParser(description="Forensics CTF 솔버")
    parser.add_argument("file", help="분석할 파일")
    parser.add_argument("--png-chunks", action="store_true")
    parser.add_argument("--lsb", action="store_true")
    parser.add_argument("--embedded", action="store_true")
    args = parser.parse_args()

    path = Path(args.file)
    solver = ForensicsSolver()

    if args.png_chunks:
        chunks = solver.extract_png_chunks(path)
        for c in chunks:
            print(f"  [{c['type']}] {c['length']} bytes: {c['data_preview']}")

    if args.lsb:
        data = solver.extract_lsb(path)
        printable = "".join(chr(b) for b in data[:200] if 32 <= b < 127)
        print(f"[+] LSB 데이터 (앞 200자): {printable}")

    if args.embedded:
        data = path.read_bytes()
        files = solver.detect_embedded_files(data)
        for f in files[:20]:
            print(f"  [{f['type']}] @ {f['offset']}")


if __name__ == "__main__":
    main()
```

---

## 3. 라이트업 퀄리티 체크리스트

### 3.1 좋은 라이트업의 조건

```
재현 가능성:
  ✅ 모든 도구 버전 명시 (Python 3.12, pwntools 4.12)
  ✅ 의존성 설치 방법 포함
  ✅ 익스플로잇 코드 전체 공유
  ✅ 대상 서버가 없어도 로컬 재현 가능한 방법 제시

이해도:
  ✅ 잘못된 시도도 포함 ("처음에는 X를 시도했으나...")
  ✅ 핵심 인사이트 강조
  ✅ 관련 CVE/기술 문서 링크
  ✅ 도구 사용 이유 설명

구조:
  ✅ 목차 있음 (긴 라이트업)
  ✅ 코드 블록에 언어 명시
  ✅ 스크린샷 대신 텍스트 출력 선호
  ✅ 플래그 맨 마지막에 한 번만 명시
```

### 3.2 라이트업 플랫폼

| 플랫폼 | 특징 |
|--------|------|
| CTFtime.org | 대회 결과 + writeup 링크 |
| GitHub | Gist 또는 repo로 관리 |
| 개인 블로그 | SEO, 장기 관리 |
| HackMD | 팀 공동 작성 가능 |

---

## 4. CTF 환경 자동화

```python
#!/usr/bin/env python3
"""CTF 문제 풀이 환경 자동 세팅"""
import argparse
import subprocess
from pathlib import Path


def setup_ctf_env(name: str, category: str, base_dir: Path) -> Path:
    challenge_dir = base_dir / name
    challenge_dir.mkdir(parents=True, exist_ok=True)

    # 카테고리별 초기 파일 생성
    templates = {
        "pwn": "from pwn import *\n\ncontext.log_level = 'debug'\n\nio = remote('', 0)\nio.interactive()\n",
        "web": "import requests\n\nURL = 'http://'\nsession = requests.Session()\n",
        "crypto": "from Crypto.Util.number import *\nfrom sympy import factorint\n\n",
        "rev": "# strings, ghidra, IDA, angr\nimport angr\n\n",
        "forensics": "from pathlib import Path\nimport struct\n\n",
        "misc": "# 분류 미정\n\n",
    }

    solver_content = templates.get(category, "# CTF 솔버\n\n")
    (challenge_dir / "solve.py").write_text(solver_content)

    # 라이트업 템플릿
    writeup = f"""# {name}

**카테고리**: {category.upper()}  
**점수**: TODO  
**태그**: TODO

## 문제 설명

> TODO

## 풀이

### 1. 분석

TODO

### 2. 익스플로잇

TODO

## 코드

```python
# solve.py 참조
```

## 플래그

`FLAG{{TODO}}`
"""
    (challenge_dir / "writeup.md").write_text(writeup)
    print(f"[+] 환경 생성: {challenge_dir}")
    return challenge_dir


def main() -> None:
    parser = argparse.ArgumentParser(description="CTF 환경 자동 세팅")
    parser.add_argument("name", help="문제 이름")
    parser.add_argument("-c", "--category", choices=["pwn", "web", "crypto", "rev", "forensics", "misc"],
                        default="misc")
    parser.add_argument("-d", "--dir", default=".", help="기본 디렉터리")
    args = parser.parse_args()

    setup_ctf_env(args.name, args.category, Path(args.dir))


if __name__ == "__main__":
    main()
```

---

<a name="english"></a>

# CTF Writeup Methodology

A good CTF writeup must be reproducible — another person should be able to follow the same steps and reach the same result. This document covers writeup documentation practices, automated solver scripts, category-specific templates, and structured writeup formats.

---

## 1. Writeup Writing Principles

### 1.1 Structure Template

```markdown
# [CTF Name] — [Challenge Name]

**Category**: Web / Pwn / Crypto / Rev / Misc / Forensics  
**Points**: 500  
**Difficulty**: Hard  
**Time to Solve**: 4 hours  

## Challenge Description

> Copy of original challenge text (blockquote)

Connection info:  
- URL: http://challenge.ctf.example.com:8080  
- File: challenge.zip

## Analysis Process

### 1. Initial Reconnaissance

[Initial analysis content]

### 2. Vulnerability Discovery

[Vulnerability analysis content]

### 3. Exploitation

[Exploit development process]

## Solution Code

```python
# Full exploit code
```

## Flag

`FLAG{...}`

## Key Takeaways

- Lesson 1
- Lesson 2
```

---

## 2. Category-Specific Automation Tools

### 2.1 Web CTF Solver Framework

```python
#!/usr/bin/env python3
"""Web CTF challenge automated solver framework"""
import argparse
import re
from typing import Optional
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup


class WebCTFSolver:
    def __init__(self, base_url: str, proxy: Optional[str] = None) -> None:
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        if proxy:
            self.session.proxies = {"http": proxy, "https": proxy}
        self.session.verify = False
        self.flags: list[str] = []
        self.FLAG_PATTERN = re.compile(r"[A-Z0-9_]{3,10}\{[A-Za-z0-9_!@#$%^&*()\-+=.]+\}")

    def get(self, path: str, **kwargs) -> requests.Response:
        return self.session.get(urljoin(self.base_url, path), **kwargs)

    def post(self, path: str, **kwargs) -> requests.Response:
        return self.session.post(urljoin(self.base_url, path), **kwargs)

    def find_flag(self, text: str) -> list[str]:
        found = self.FLAG_PATTERN.findall(text)
        self.flags.extend(found)
        return found

    # Automatic SQLi detection
    def test_sqli(self, path: str, param: str) -> Optional[str]:
        payloads = [
            "' OR '1'='1",
            "' OR 1=1--",
            "\" OR \"1\"=\"1",
            "1; SELECT SLEEP(3)--",
            "1 UNION SELECT NULL--",
        ]
        baseline = self.get(path, params={param: "normal_value"})

        for payload in payloads:
            resp = self.get(path, params={param: payload})
            if resp.elapsed.total_seconds() > 2.5:  # time-based
                return f"Time-based SQLi: {payload}"
            if self.find_flag(resp.text):
                return f"Error-based SQLi: {payload} → FLAG found"
            if len(resp.text) != len(baseline.text):
                return f"Possible Boolean SQLi: {payload}"

        return None

    # XSS detection
    def test_xss(self, path: str, param: str) -> list[str]:
        payloads = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "{{7*7}}",  # also detects SSTI
            "${7*7}",
        ]
        found = []
        for payload in payloads:
            resp = self.post(path, data={param: payload})
            if payload in resp.text:
                found.append(f"Reflected XSS: {payload}")
            if "49" in resp.text and "7*7" in payload:
                found.append(f"SSTI detected: {payload}")
        return found

    # JWT analysis
    def analyze_jwt(self, token: str) -> dict:
        import base64
        import json

        parts = token.split(".")
        if len(parts) != 3:
            return {"error": "Invalid JWT format"}

        def decode_part(part: str) -> dict:
            padded = part + "=" * (4 - len(part) % 4)
            return json.loads(base64.urlsafe_b64decode(padded))

        try:
            header = decode_part(parts[0])
            payload = decode_part(parts[1])
            return {
                "header": header,
                "payload": payload,
                "algorithm": header.get("alg"),
                "none_attack": header.get("alg", "").lower() != "none",
            }
        except Exception as e:
            return {"error": str(e)}


def main() -> None:
    parser = argparse.ArgumentParser(description="Web CTF solver")
    parser.add_argument("url", help="Target URL")
    parser.add_argument("--proxy", help="Burp Suite proxy (e.g., http://127.0.0.1:8080)")
    parser.add_argument("--sqli-path", help="SQLi test path")
    parser.add_argument("--sqli-param", help="SQLi test parameter")
    args = parser.parse_args()

    solver = WebCTFSolver(args.url, args.proxy)

    if args.sqli_path and args.sqli_param:
        result = solver.test_sqli(args.sqli_path, args.sqli_param)
        if result:
            print(f"[+] SQLi found: {result}")
        else:
            print("[-] SQLi detection failed")


if __name__ == "__main__":
    main()
```

### 2.2 Crypto CTF Solver

```python
#!/usr/bin/env python3
"""Automation of common Crypto CTF attacks"""
import argparse
import math
from typing import Optional


class CryptoCTFSolver:

    # RSA factorization (when primes are close — Fermat's factorization)
    @staticmethod
    def fermat_factor(n: int) -> tuple[int, int]:
        a = math.isqrt(n)
        if a * a < n:
            a += 1
        b2 = a * a - n
        while True:
            b = math.isqrt(b2)
            if b * b == b2:
                return a - b, a + b
            a += 1
            b2 = a * a - n

    # RSA common modulus attack
    @staticmethod
    def common_modulus_attack(n: int, e1: int, c1: int, e2: int, c2: int) -> Optional[int]:
        def extended_gcd(a: int, b: int) -> tuple[int, int, int]:
            if b == 0:
                return a, 1, 0
            g, x, y = extended_gcd(b, a % b)
            return g, y, x - (a // b) * y

        g, s, t = extended_gcd(e1, e2)
        if g != 1:
            return None

        if s < 0:
            c1 = pow(c1, -1, n)
            s = -s
        if t < 0:
            c2 = pow(c2, -1, n)
            t = -t

        m = (pow(c1, s, n) * pow(c2, t, n)) % n
        return m

    # Wiener's attack (small d)
    @staticmethod
    def wiener_attack(e: int, n: int) -> Optional[int]:
        def continued_fraction(num: int, den: int) -> list[int]:
            cf = []
            while den:
                cf.append(num // den)
                num, den = den, num % den
            return cf

        def convergents(cf: list[int]) -> list[tuple[int, int]]:
            convs = []
            for i in range(len(cf)):
                if i == 0:
                    convs.append((cf[0], 1))
                elif i == 1:
                    convs.append((cf[0] * cf[1] + 1, cf[1]))
                else:
                    h_prev, k_prev = convs[-1]
                    h_prev2, k_prev2 = convs[-2]
                    convs.append((cf[i] * h_prev + h_prev2, cf[i] * k_prev + k_prev2))
            return convs

        cf = continued_fraction(e, n)
        for k, d in convergents(cf):
            if k == 0:
                continue
            if (e * d - 1) % k != 0:
                continue
            phi = (e * d - 1) // k
            discriminant = (n - phi + 1) ** 2 - 4 * n
            if discriminant < 0:
                continue
            sqrt_disc = math.isqrt(discriminant)
            if sqrt_disc * sqrt_disc == discriminant:
                return d
        return None

    # Repeating XOR key crack (Kasiski analysis)
    @staticmethod
    def crack_repeating_xor(ciphertext: bytes, max_keysize: int = 40) -> bytes:
        def hamming(b1: bytes, b2: bytes) -> int:
            return sum(bin(x ^ y).count("1") for x, y in zip(b1, b2))

        scores = []
        for ks in range(2, max_keysize + 1):
            blocks = [ciphertext[i:i+ks] for i in range(0, len(ciphertext) - ks, ks)]
            if len(blocks) < 2:
                continue
            dist = sum(hamming(blocks[i], blocks[i+1]) for i in range(min(4, len(blocks)-1)))
            scores.append((dist / (ks * min(4, len(blocks)-1)), ks))

        scores.sort()
        keysize = scores[0][1]

        key = bytes()
        for i in range(keysize):
            block = bytes(ciphertext[j] for j in range(i, len(ciphertext), keysize))
            # Assuming English text: frequency analysis
            best_score = -1
            best_byte = 0
            for b in range(256):
                decrypted = bytes(x ^ b for x in block)
                score = sum(decrypted.count(c) for c in b" etaoinshrdlu")
                if score > best_score:
                    best_score = score
                    best_byte = b
            key += bytes([best_byte])

        return key

    # Base64 steganography (whitespace encoding)
    @staticmethod
    def base64_steg_decode(text: str) -> str:
        import base64
        lines = text.strip().split("\n")
        bits = ""
        for line in lines:
            decoded_len = len(base64.b64decode(line + "=="))
            padding = line.count("=")
            wasted_bits = padding * 2
            if wasted_bits > 0:
                value = base64.b64decode(line + "==")[-1]
                bits += format(value & ((1 << wasted_bits) - 1), f"0{wasted_bits}b")
        chars = [chr(int(bits[i:i+8], 2)) for i in range(0, len(bits) - 7, 8)]
        return "".join(chars)


def main() -> None:
    parser = argparse.ArgumentParser(description="Crypto CTF solver")
    subparsers = parser.add_subparsers(dest="attack")

    rsa_p = subparsers.add_parser("rsa-fermat")
    rsa_p.add_argument("n", type=int)

    wiener_p = subparsers.add_parser("rsa-wiener")
    wiener_p.add_argument("e", type=int)
    wiener_p.add_argument("n", type=int)

    xor_p = subparsers.add_parser("xor")
    xor_p.add_argument("hex_cipher", help="Hex ciphertext")

    args = parser.parse_args()
    solver = CryptoCTFSolver()

    if args.attack == "rsa-fermat":
        p, q = solver.fermat_factor(args.n)
        print(f"[+] p = {p}")
        print(f"[+] q = {q}")
    elif args.attack == "rsa-wiener":
        d = solver.wiener_attack(args.e, args.n)
        print(f"[+] d = {d}" if d else "[-] Wiener attack failed")
    elif args.attack == "xor":
        ct = bytes.fromhex(args.hex_cipher)
        key = solver.crack_repeating_xor(ct)
        print(f"[+] Key: {key}")
        pt = bytes(c ^ k for c, k in zip(ct, (key * (len(ct) // len(key) + 1))[:len(ct)]))
        print(f"[+] Decrypted: {pt[:100]}")


if __name__ == "__main__":
    main()
```

### 2.3 Forensics CTF Solver

```python
#!/usr/bin/env python3
"""Forensics CTF file analysis automation"""
import argparse
import struct
import zlib
from pathlib import Path


class ForensicsSolver:
    # Extract hidden chunks from PNG files
    @staticmethod
    def extract_png_chunks(path: Path) -> list[dict]:
        data = path.read_bytes()
        if data[:8] != b"\x89PNG\r\n\x1a\n":
            return []

        chunks = []
        offset = 8
        while offset < len(data):
            length = struct.unpack(">I", data[offset:offset+4])[0]
            chunk_type = data[offset+4:offset+8].decode("ascii", errors="replace")
            chunk_data = data[offset+8:offset+8+length]
            crc = struct.unpack(">I", data[offset+8+length:offset+12+length])[0]

            chunks.append({
                "type": chunk_type,
                "length": length,
                "data_preview": chunk_data[:32].hex(),
            })

            if chunk_type not in ("IHDR", "IDAT", "IEND", "tEXt", "zTXt", "bKGD", "pHYs", "gAMA"):
                print(f"[!] Non-standard chunk found: {chunk_type} ({length} bytes)")

            offset += 12 + length

        return chunks

    # LSB steganography extraction (Python Imaging Library)
    @staticmethod
    def extract_lsb(image_path: Path, bits: int = 1) -> bytes:
        from PIL import Image
        img = Image.open(image_path).convert("RGB")
        pixels = list(img.getdata())

        extracted_bits = []
        for pixel in pixels:
            for channel in pixel:
                for b in range(bits):
                    extracted_bits.append((channel >> b) & 1)

        byte_data = bytes(
            int("".join(str(b) for b in extracted_bits[i:i+8]), 2)
            for i in range(0, len(extracted_bits) - 7, 8)
        )
        return byte_data

    # ZIP password brute-force
    @staticmethod
    def crack_zip(zip_path: Path, wordlist: Path) -> Optional[str]:
        import zipfile
        with zipfile.ZipFile(zip_path) as zf:
            for line in wordlist.read_bytes().splitlines():
                try:
                    zf.extractall(pwd=line)
                    return line.decode("utf-8", errors="replace")
                except Exception:
                    continue
        return None

    # File signature detection
    @staticmethod
    def detect_embedded_files(data: bytes) -> list[dict]:
        SIGNATURES = {
            b"\x89PNG": "PNG",
            b"\xff\xd8\xff": "JPEG",
            b"PK\x03\x04": "ZIP",
            b"GIF8": "GIF",
            b"%PDF": "PDF",
            b"MZ": "PE",
            b"\x7fELF": "ELF",
            b"RIFF": "RIFF (AVI/WAV)",
        }
        found = []
        for offset in range(len(data) - 4):
            for sig, name in SIGNATURES.items():
                if data[offset:offset+len(sig)] == sig:
                    found.append({"type": name, "offset": hex(offset)})
        return found


def main() -> None:
    parser = argparse.ArgumentParser(description="Forensics CTF solver")
    parser.add_argument("file", help="File to analyze")
    parser.add_argument("--png-chunks", action="store_true")
    parser.add_argument("--lsb", action="store_true")
    parser.add_argument("--embedded", action="store_true")
    args = parser.parse_args()

    path = Path(args.file)
    solver = ForensicsSolver()

    if args.png_chunks:
        chunks = solver.extract_png_chunks(path)
        for c in chunks:
            print(f"  [{c['type']}] {c['length']} bytes: {c['data_preview']}")

    if args.lsb:
        data = solver.extract_lsb(path)
        printable = "".join(chr(b) for b in data[:200] if 32 <= b < 127)
        print(f"[+] LSB data (first 200 chars): {printable}")

    if args.embedded:
        data = path.read_bytes()
        files = solver.detect_embedded_files(data)
        for f in files[:20]:
            print(f"  [{f['type']}] @ {f['offset']}")


if __name__ == "__main__":
    main()
```

---

## 3. Writeup Quality Checklist

### 3.1 Characteristics of a Good Writeup

```
Reproducibility:
  ✅ All tool versions specified (Python 3.12, pwntools 4.12)
  ✅ Dependency installation instructions included
  ✅ Full exploit code shared
  ✅ Method for local reproduction without target server provided

Comprehension:
  ✅ Failed attempts included ("Initially I tried X, but...")
  ✅ Key insights highlighted
  ✅ Links to relevant CVEs/technical documentation
  ✅ Reasons for tool usage explained

Structure:
  ✅ Table of contents (for long writeups)
  ✅ Language specified in code blocks
  ✅ Text output preferred over screenshots
  ✅ Flag mentioned only once at the very end
```

### 3.2 Writeup Platforms

| Platform | Features |
|----------|----------|
| CTFtime.org | Competition results + writeup links |
| GitHub | Managed as Gist or repo |
| Personal blog | SEO, long-term management |
| HackMD | Team collaborative writing |

---

## 4. CTF Environment Automation

```python
#!/usr/bin/env python3
"""Automated CTF challenge solving environment setup"""
import argparse
import subprocess
from pathlib import Path


def setup_ctf_env(name: str, category: str, base_dir: Path) -> Path:
    challenge_dir = base_dir / name
    challenge_dir.mkdir(parents=True, exist_ok=True)

    # Create initial files per category
    templates = {
        "pwn": "from pwn import *\n\ncontext.log_level = 'debug'\n\nio = remote('', 0)\nio.interactive()\n",
        "web": "import requests\n\nURL = 'http://'\nsession = requests.Session()\n",
        "crypto": "from Crypto.Util.number import *\nfrom sympy import factorint\n\n",
        "rev": "# strings, ghidra, IDA, angr\nimport angr\n\n",
        "forensics": "from pathlib import Path\nimport struct\n\n",
        "misc": "# Uncategorized\n\n",
    }

    solver_content = templates.get(category, "# CTF solver\n\n")
    (challenge_dir / "solve.py").write_text(solver_content)

    # Writeup template
    writeup = f"""# {name}

**Category**: {category.upper()}  
**Points**: TODO  
**Tags**: TODO

## Challenge Description

> TODO

## Solution

### 1. Analysis

TODO

### 2. Exploit

TODO

## Code

```python
# See solve.py
```

## Flag

`FLAG{{TODO}}`
"""
    (challenge_dir / "writeup.md").write_text(writeup)
    print(f"[+] Environment created: {challenge_dir}")
    return challenge_dir


def main() -> None:
    parser = argparse.ArgumentParser(description="Automated CTF environment setup")
    parser.add_argument("name", help="Challenge name")
    parser.add_argument("-c", "--category", choices=["pwn", "web", "crypto", "rev", "forensics", "misc"],
                        default="misc")
    parser.add_argument("-d", "--dir", default=".", help="Base directory")
    args = parser.parse_args()

    setup_ctf_env(args.name, args.category, Path(args.dir))


if __name__ == "__main__":
    main()
```
