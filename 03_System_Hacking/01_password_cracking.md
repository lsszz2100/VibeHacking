# 패스워드 크랙 — 이론과 실전

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
