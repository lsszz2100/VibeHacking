> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 01 Hash Types and Wordlists

## 주요 해시 알고리즘 비교

| 알고리즘 | 길이(hex) | 속도 | 솔트 | 주요 사용처 | hashcat 모드 |
|---------|-----------|------|------|------------|-------------|
| MD5 | 32 | 매우 빠름 | 없음 | 레거시 웹, 파일 무결성 | 0 |
| SHA-1 | 40 | 빠름 | 없음 | Git, 레거시 인증 | 100 |
| SHA-256 | 64 | 빠름 | 없음 | 현대 웹, 블록체인 | 1400 |
| SHA-512 | 128 | 빠름 | 없음 | Linux shadow (SHA512crypt 별도) | 1700 |
| SHA-512crypt | $6$ 접두사 | 느림 | 있음 | Linux /etc/shadow | 1800 |
| bcrypt | 60 | 매우 느림 | 포함 | PHP/Rails/Node 웹앱 | 3200 |
| NTLM | 32 | 매우 빠름 | 없음 | Windows SAM/AD | 1000 |
| NetNTLMv1 | 가변 | 빠름 | 챌린지 | SMB 인증 캡처 | 5500 |
| NetNTLMv2 | 가변 | 빠름 | 챌린지 | SMB 인증 캡처 | 5600 |
| WPA/WPA2 | 가변 | 느림 | SSID | 무선랜 핸드셰이크 | 22000 |
| MD5crypt | $1$ 접두사 | 느림 | 있음 | 구형 Linux shadow | 500 |
| PBKDF2-SHA256 | 가변 | 느림 | 있음 | Django, iOS 키체인 | 10900 |

### 알고리즘별 특성 상세

**MD5 / SHA 계열 (빠른 해시)**
- 초당 수백억 회 연산 가능 (GPU 기준)
- 솔트 없으면 레인보우 테이블 공격 가능
- 동일 평문 → 항상 동일 해시 (결정론적)

**bcrypt**
- cost factor(work factor)로 속도 조절: `$2b$10$` = 2^10 = 1024 라운드
- GPU 병렬화 저항성 높음 → hashcat에서도 초당 수천 회 수준
- 솔트 22자 자동 내장

**NTLM**
- `MD4(UTF-16LE(password))` — 솔트 없음, 매우 빠름
- Pass-the-Hash 공격에 직접 사용 가능
- LM 해시(구형)보다 강하지만 여전히 취약

**NetNTLMv2**
- NTLM 해시 + 챌린지로 계산된 응답값
- Responder로 캡처 → hashcat 5600으로 크래킹
- Pass-the-Hash에는 직접 사용 불가

**WPA/WPA2**
- PBKDF2-SHA1(passphrase, SSID, 4096 iterations)
- 핸드셰이크(.cap) 또는 PMKID 캡처 후 오프라인 크래킹
- hashcat 22000 모드 (hc22000 포맷)

---

## 해시 식별 도구

### hashid


`hashid`와 `hash-identifier`는 해시 문자열의 형식을 자동으로 식별하는 도구입니다. 해시의 길이, 문자 집합, 접두사(`$6$`, `$2y$` 등)를 분석하여 가능한 해시 알고리즘 목록을 반환합니다.

```bash
# 설치
pip install hashid

# 단일 해시 식별
hashid '5f4dcc3b5aa765d61d8327deb882cf99'

# 파일 내 해시 일괄 식별
hashid -f hashes.txt

# hashcat 모드 번호 함께 출력
hashid -m '5f4dcc3b5aa765d61d8327deb882cf99'

# John 포맷도 함께 출력
hashid -mj '$2y$10$vI8aWBnW3fID.ZQ4/zo1G.q1lRps.9cGLcZEiGDMVr5yUP1KUOYTa'
```

```
# 출력 예시
Analyzing '5f4dcc3b5aa765d61d8327deb882cf99'
[+] MD2
[+] MD5 [Hashcat Mode: 0][JtR Format: raw-md5]
[+] MD4 [Hashcat Mode: 900][JtR Format: raw-md4]
```

### hash-identifier

hash-identifier 도구를 설치합니다. 해시 값의 길이와 형식을 분석하여 알고리즘 종류를 추정합니다.

```bash
# 설치
sudo apt install hash-identifier
# 또는
git clone https://github.com/blackploit/hash-identifier

# 실행
hash-identifier
# 프롬프트에 해시 입력

# Python으로 직접 실행
python3 hash-id.py
```

### name-that-hash (현대적 대안)

name-that-hash는 현대적인 해시 식별 도구입니다. hashid보다 더 많은 해시 유형을 지원하고 확률 기반으로 결과를 정렬합니다.

```bash
pip install name-that-hash

# 단일 해시
nth --text '5f4dcc3b5aa765d61d8327deb882cf99'

# 파일
nth --file hashes.txt

# JSON 출력
nth --text 'abc123...' --json
```

---

## 워드리스트 구조

### rockyou.txt

칼리 리눅스에 포함된 rockyou.txt 워드리스트 경로입니다. 약 1,400만 개의 실제 유출된 비밀번호를 포함하며 패스워드 크래킹의 기본 시작점입니다.

```bash
# Kali Linux 기본 경로
ls -lh /usr/share/wordlists/rockyou.txt.gz

# 압축 해제
sudo gunzip /usr/share/wordlists/rockyou.txt.gz

# 통계
wc -l /usr/share/wordlists/rockyou.txt
# 14,344,391 줄

# 상위 20개 확인
head -20 /usr/share/wordlists/rockyou.txt

# 특정 패턴 검색
grep -i '^admin' /usr/share/wordlists/rockyou.txt | head -10
grep '[0-9]\{4\}$' /usr/share/wordlists/rockyou.txt | wc -l
```

### SecLists

SecLists는 침투 테스트에 필요한 다양한 목록을 모은 컬렉션입니다. 서브도메인, 디렉토리, 비밀번호, 사용자명 등 수십 가지 카테고리를 포함합니다.

```bash
# 설치
sudo apt install seclists
# 또는
git clone https://github.com/danielmiessler/SecLists /opt/SecLists

# 디렉토리 구조
ls /usr/share/seclists/
# Discovery/  Fuzzing/  Miscellaneous/  Passwords/  Usernames/  ...

# 주요 패스워드 리스트
ls /usr/share/seclists/Passwords/
# Common-Credentials/  Leaked-Databases/  Default-Credentials/  ...

# 자주 쓰는 리스트
/usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt
/usr/share/seclists/Passwords/Common-Credentials/100k-most-used-passwords-NCSC.txt
/usr/share/seclists/Passwords/Leaked-Databases/rockyou-75.txt
/usr/share/seclists/Usernames/top-usernames-shortlist.txt
```

---

## 커스텀 워드리스트 생성

### CeWL — 웹사이트 크롤링


`cewl`은 지정한 웹사이트를 크롤링하여 단어를 수집하고 커스텀 워드리스트를 생성합니다. 대상 조직 관련 단어(직원명, 제품명, 슬로건)가 패스워드에 포함될 가능성이 높아 타겟형 공격에 효과적입니다.

```bash
# 기본 사용법 (깊이 2, 최소 길이 6)
cewl http://target.com -d 2 -m 6 -w wordlist.txt

# 이메일 주소도 수집
cewl http://target.com -d 3 -m 5 -e -w wordlist.txt

# 인증이 필요한 페이지
cewl http://target.com -d 2 -m 6 \
  --auth_type basic \
  --auth_user admin \
  --auth_pass password \
  -w wordlist.txt

# 대소문자 변형 포함
cewl http://target.com -d 2 -m 6 --with-numbers -w raw.txt
# 후처리로 변형 생성
```

### Crunch — 패턴 기반 생성


`crunch`는 지정한 문자 집합과 길이로 커스텀 워드리스트를 생성하는 도구입니다. 특정 패스워드 정책(길이, 포함 문자)을 알고 있을 때 효율적인 타겟 워드리스트를 만들 수 있습니다.

```bash
# crunch <min> <max> <charset> [options]

# 4자리 숫자 전체
crunch 4 4 0123456789 -o pins.txt

# 6~8자 소문자+숫자
crunch 6 8 abcdefghijklmnopqrstuvwxyz0123456789 -o wordlist.txt

# 패턴 사용 (@=소문자, ,=대문자, %=숫자, ^=특수문자)
crunch 8 8 -t @@@@%%%% -o pattern.txt    # 소문자4개+숫자4개
crunch 8 8 -t Pass%%%% -o pass_nums.txt   # Pass + 숫자4개

# 내장 문자셋 사용
crunch 8 8 -f /usr/share/crunch/charset.lst mixalpha-numeric -o out.txt

# 특정 단어 포함
crunch 1 1 -p admin user guest root -o keywords.txt
```

### CUPP — 개인정보 기반 생성

CUPP(Common User Password Profiler)는 대상자 개인 정보 기반 맞춤형 워드리스트를 생성합니다. 이름, 생일, 관심사 등을 조합하여 개인화된 비밀번호를 생성합니다.

```bash
# 설치
git clone https://github.com/Mebus/cupp /opt/cupp

# 대화형 모드 (이름, 생일, 반려동물 등 입력)
python3 /opt/cupp/cupp.py -i

# 기존 워드리스트 개선 (leetspeak, 숫자 추가 등)
python3 /opt/cupp/cupp.py -w wordlist.txt

# 알라딘 모드 (온라인 DB)
python3 /opt/cupp/cupp.py -a

# 생성된 파일 확인
wc -l cupp_output.txt
```

### 워드리스트 후처리

수집한 워드리스트를 중복 제거하고 정렬하여 최적화합니다. 크기를 줄이고 중복 제거로 크래킹 효율을 높입니다.

```bash
# 중복 제거 및 정렬
sort wordlist.txt | uniq > clean_wordlist.txt

# 길이별 필터링
awk 'length >= 8 && length <= 16' wordlist.txt > filtered.txt

# 여러 리스트 병합 후 정렬/중복제거
cat list1.txt list2.txt list3.txt | sort -u > combined.txt

# 특수문자 없는 항목만
grep -P '^[a-zA-Z0-9]+$' wordlist.txt > alphanum_only.txt

# 대문자 포함 항목만
grep '[A-Z]' wordlist.txt > has_upper.txt
```

---

## Python 해시 식별 + 크래킹 스크립트

```python
#!/usr/bin/env python3
"""
해시 식별 및 워드리스트 기반 크래킹 도구
사용법: python3 hash_cracker.py -H <hash> -w <wordlist> [-t <threads>]
"""

import argparse
import hashlib
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Optional


# 해시 패턴 정의
HASH_PATTERNS: dict[str, tuple[str, int]] = {
    "MD5":          (r"^[a-fA-F0-9]{32}$",   0),
    "SHA-1":        (r"^[a-fA-F0-9]{40}$",   100),
    "SHA-256":      (r"^[a-fA-F0-9]{64}$",   1400),
    "SHA-512":      (r"^[a-fA-F0-9]{128}$",  1700),
    "NTLM":         (r"^[a-fA-F0-9]{32}$",   1000),
    "bcrypt":       (r"^\$2[ayb]\$.{56}$",    3200),
    "MD5crypt":     (r"^\$1\$.{8}\$.{22}$",   500),
    "SHA512crypt":  (r"^\$6\$.{8,16}\$.+$",   1800),
}

# 알고리즘 → hashlib 매핑
HASH_FUNCS: dict[str, str] = {
    "MD5":     "md5",
    "SHA-1":   "sha1",
    "SHA-256": "sha256",
    "SHA-512": "sha512",
    "NTLM":    "md4",   # NTLM은 MD4 기반, hashlib에서 지원 여부 확인 필요
}


def identify_hash(hash_str: str) -> list[str]:
    """해시 문자열의 가능한 알고리즘 목록 반환."""
    candidates: list[str] = []
    for name, (pattern, _) in HASH_PATTERNS.items():
        if re.match(pattern, hash_str):
            candidates.append(name)
    return candidates if candidates else ["Unknown"]


def compute_hash(algorithm: str, plaintext: str) -> Optional[str]:
    """주어진 알고리즘으로 평문 해시 계산."""
    func_name = HASH_FUNCS.get(algorithm)
    if not func_name:
        return None
    try:
        h = hashlib.new(func_name, plaintext.encode("utf-8", errors="replace"))
        return h.hexdigest()
    except ValueError:
        return None


def try_word(word: str, target_hash: str, algorithm: str) -> Optional[str]:
    """단일 단어 크래킹 시도. 성공 시 평문 반환."""
    word = word.strip()
    computed = compute_hash(algorithm, word)
    if computed and computed.lower() == target_hash.lower():
        return word
    return None


def crack_hash(
    target_hash: str,
    wordlist_path: Path,
    algorithm: str,
    max_workers: int = 8,
) -> Optional[str]:
    """
    워드리스트를 읽어 멀티스레드로 해시 크래킹 시도.
    성공 시 평문 반환, 실패 시 None.
    """
    if not wordlist_path.exists():
        print(f"[!] 워드리스트 파일 없음: {wordlist_path}", file=sys.stderr)
        return None

    print(f"[*] 알고리즘: {algorithm} | 해시: {target_hash[:16]}...")
    print(f"[*] 워드리스트: {wordlist_path}")

    total = 0
    found: Optional[str] = None

    try:
        with wordlist_path.open("r", encoding="utf-8", errors="ignore") as f:
            words = f.readlines()

        total = len(words)
        print(f"[*] 총 {total:,}개 단어 로드 완료, 스레드: {max_workers}")

        chunk_size = max(1, total // (max_workers * 10))
        futures = {}

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            for i, word in enumerate(words):
                if found:
                    break
                future = executor.submit(try_word, word, target_hash, algorithm)
                futures[future] = i

                # 진행률 출력 (1만 건마다)
                if i % 10000 == 0 and i > 0:
                    print(f"[*] 진행: {i:,}/{total:,} ({i/total*100:.1f}%)")

            for future in as_completed(futures):
                result = future.result()
                if result is not None:
                    found = result
                    print(f"\n[+] 크래킹 성공!")
                    print(f"[+] 평문: {result}")
                    executor.shutdown(wait=False, cancel_futures=True)
                    break

    except KeyboardInterrupt:
        print("\n[!] 사용자 중단")

    return found


def load_hash_file(path: Path) -> list[str]:
    """해시 파일에서 해시 목록 읽기."""
    try:
        return [line.strip() for line in path.read_text().splitlines() if line.strip()]
    except OSError as e:
        print(f"[!] 파일 읽기 실패: {e}", file=sys.stderr)
        sys.exit(1)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="해시 식별 및 워드리스트 크래킹 도구",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
예시:
  python3 hash_cracker.py -H 5f4dcc3b5aa765d61d8327deb882cf99 -w rockyou.txt
  python3 hash_cracker.py -H 5f4dcc3b... -w rockyou.txt -a MD5 -t 16
  python3 hash_cracker.py -f hashes.txt -w wordlist.txt --identify-only
        """,
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-H", "--hash", help="크래킹할 단일 해시")
    group.add_argument("-f", "--file", type=Path, help="해시 목록 파일")

    parser.add_argument("-w", "--wordlist", type=Path, help="워드리스트 파일 경로")
    parser.add_argument(
        "-a", "--algorithm",
        choices=list(HASH_FUNCS.keys()),
        default=None,
        help="해시 알고리즘 강제 지정 (미지정 시 자동 감지)",
    )
    parser.add_argument("-t", "--threads", type=int, default=8, help="스레드 수 (기본: 8)")
    parser.add_argument(
        "--identify-only", action="store_true",
        help="식별만 하고 크래킹 시도 안 함",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    # 해시 목록 준비
    hashes: list[str] = []
    if args.hash:
        hashes = [args.hash]
    elif args.file:
        hashes = load_hash_file(args.file)

    print(f"[*] 총 {len(hashes)}개 해시 처리 예정\n")

    for target in hashes:
        print(f"{'='*60}")
        print(f"[*] 대상 해시: {target}")

        # 해시 식별
        candidates = identify_hash(target)
        print(f"[*] 가능한 알고리즘: {', '.join(candidates)}")

        if args.identify_only:
            continue

        if not args.wordlist:
            print("[!] 크래킹에는 -w 옵션 필요", file=sys.stderr)
            continue

        # 알고리즘 결정
        algorithm = args.algorithm
        if not algorithm:
            # 지원 가능한 첫 번째 알고리즘 선택
            for c in candidates:
                if c in HASH_FUNCS:
                    algorithm = c
                    break

        if not algorithm:
            print(f"[!] 지원되지 않는 알고리즘: {candidates}")
            print("[!] -a 옵션으로 알고리즘 직접 지정 필요")
            continue

        result = crack_hash(target, args.wordlist, algorithm, args.threads)
        if result is None:
            print(f"[-] 크래킹 실패 — 워드리스트에 없음")

    print(f"\n[*] 완료")


if __name__ == "__main__":
    main()
```

### 스크립트 실행 예시

해시 식별 및 크래킹 스크립트의 실행 예시입니다. 해시 값을 입력하면 자동으로 유형을 판별하고 적합한 크래킹 도구를 선택합니다.

```bash
# 단일 MD5 해시 크래킹
python3 hash_cracker.py -H 5f4dcc3b5aa765d61d8327deb882cf99 \
  -w /usr/share/wordlists/rockyou.txt

# SHA-256 해시, 알고리즘 명시, 스레드 16
python3 hash_cracker.py \
  -H a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3 \
  -w /usr/share/wordlists/rockyou.txt \
  -a SHA-256 \
  -t 16

# 해시 파일 일괄 식별만
python3 hash_cracker.py -f hashes.txt --identify-only

# 해시 파일 일괄 크래킹
python3 hash_cracker.py -f hashes.txt -w /opt/SecLists/Passwords/rockyou-75.txt -t 4
```

---

## 해시 샘플 레퍼런스

각 알고리즘별 해시를 직접 생성하여 참고 샘플을 만듭니다. MD5, SHA-1, SHA-256, bcrypt 등의 출력 형식을 비교합니다.

```bash
# 직접 해시 생성 (테스트용)
echo -n "password" | md5sum
# 5f4dcc3b5aa765d61d8327deb882cf99

echo -n "password" | sha1sum
# 5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8

echo -n "password" | sha256sum
# 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8

# Python으로 NTLM 해시 계산
python3 -c "
import hashlib
pw = 'Password123'
ntlm = hashlib.new('md4', pw.encode('utf-16le')).hexdigest()
print(f'NTLM: {ntlm}')
"

# OpenSSL로 bcrypt
python3 -c "
import bcrypt
pw = b'password'
hashed = bcrypt.hashpw(pw, bcrypt.gensalt(rounds=10))
print(hashed.decode())
"
```

---

<a name="english"></a>

# 01 Hash Types and Wordlists

## Major Hash Algorithm Comparison

| Algorithm | Length (hex) | Speed | Salt | Primary Use | hashcat Mode |
|-----------|-------------|-------|------|-------------|-------------|
| MD5 | 32 | Very Fast | None | Legacy web, file integrity | 0 |
| SHA-1 | 40 | Fast | None | Git, legacy authentication | 100 |
| SHA-256 | 64 | Fast | None | Modern web, blockchain | 1400 |
| SHA-512 | 128 | Fast | None | Linux shadow (SHA512crypt separate) | 1700 |
| SHA-512crypt | $6$ prefix | Slow | Yes | Linux /etc/shadow | 1800 |
| bcrypt | 60 | Very Slow | Included | PHP/Rails/Node web apps | 3200 |
| NTLM | 32 | Very Fast | None | Windows SAM/AD | 1000 |
| NetNTLMv1 | Variable | Fast | Challenge | SMB authentication capture | 5500 |
| NetNTLMv2 | Variable | Fast | Challenge | SMB authentication capture | 5600 |
| WPA/WPA2 | Variable | Slow | SSID | Wireless LAN handshake | 22000 |
| MD5crypt | $1$ prefix | Slow | Yes | Legacy Linux shadow | 500 |
| PBKDF2-SHA256 | Variable | Slow | Yes | Django, iOS Keychain | 10900 |

### Detailed Algorithm Characteristics

**MD5 / SHA Family (Fast Hashes)**
- Billions of operations per second possible (GPU-based)
- Without salt, rainbow table attacks are feasible
- Same plaintext → always same hash (deterministic)

**bcrypt**
- Speed adjustable via cost factor (work factor): `$2b$10$` = 2^10 = 1024 rounds
- High resistance to GPU parallelization → only thousands of attempts per second even in hashcat
- Automatically embeds a 22-character salt

**NTLM**
- `MD4(UTF-16LE(password))` — no salt, extremely fast
- Can be directly used for Pass-the-Hash attacks
- Stronger than LM hashes (legacy) but still vulnerable

**NetNTLMv2**
- Response value computed from NTLM hash + challenge
- Capture with Responder → crack with hashcat mode 5600
- Cannot be used directly for Pass-the-Hash

**WPA/WPA2**
- PBKDF2-SHA1(passphrase, SSID, 4096 iterations)
- Offline cracking after capturing handshake (.cap) or PMKID
- hashcat mode 22000 (hc22000 format)

---

## Hash Identification Tools

### hashid

`hashid` and `hash-identifier` are tools that automatically identify the format of hash strings. They analyze the hash's length, character set, and prefix (`$6$`, `$2y$`, etc.) and return a list of possible hash algorithms.

```bash
# Install
pip install hashid

# Identify a single hash
hashid '5f4dcc3b5aa765d61d8327deb882cf99'

# Batch identify hashes in a file
hashid -f hashes.txt

# Also output hashcat mode numbers
hashid -m '5f4dcc3b5aa765d61d8327deb882cf99'

# Also output John format
hashid -mj '$2y$10$vI8aWBnW3fID.ZQ4/zo1G.q1lRps.9cGLcZEiGDMVr5yUP1KUOYTa'
```

```
# Example output
Analyzing '5f4dcc3b5aa765d61d8327deb882cf99'
[+] MD2
[+] MD5 [Hashcat Mode: 0][JtR Format: raw-md5]
[+] MD4 [Hashcat Mode: 900][JtR Format: raw-md4]
```

### hash-identifier

Install the hash-identifier tool. It analyzes the length and format of the hash value to estimate the algorithm type.

```bash
# Install
sudo apt install hash-identifier
# or
git clone https://github.com/blackploit/hash-identifier

# Run
hash-identifier
# Enter hash at the prompt

# Run directly with Python
python3 hash-id.py
```

### name-that-hash (Modern Alternative)

name-that-hash is a modern hash identification tool. It supports more hash types than hashid and sorts results by probability.

```bash
pip install name-that-hash

# Single hash
nth --text '5f4dcc3b5aa765d61d8327deb882cf99'

# File
nth --file hashes.txt

# JSON output
nth --text 'abc123...' --json
```

---

## Wordlist Structure

### rockyou.txt

This is the path to the rockyou.txt wordlist included in Kali Linux. It contains approximately 14 million real leaked passwords and is the standard starting point for password cracking.

```bash
# Default path in Kali Linux
ls -lh /usr/share/wordlists/rockyou.txt.gz

# Decompress
sudo gunzip /usr/share/wordlists/rockyou.txt.gz

# Statistics
wc -l /usr/share/wordlists/rockyou.txt
# 14,344,391 lines

# View top 20 entries
head -20 /usr/share/wordlists/rockyou.txt

# Search for specific patterns
grep -i '^admin' /usr/share/wordlists/rockyou.txt | head -10
grep '[0-9]\{4\}$' /usr/share/wordlists/rockyou.txt | wc -l
```

### SecLists

SecLists is a collection of various lists needed for penetration testing. It includes dozens of categories such as subdomains, directories, passwords, and usernames.

```bash
# Install
sudo apt install seclists
# or
git clone https://github.com/danielmiessler/SecLists /opt/SecLists

# Directory structure
ls /usr/share/seclists/
# Discovery/  Fuzzing/  Miscellaneous/  Passwords/  Usernames/  ...

# Key password lists
ls /usr/share/seclists/Passwords/
# Common-Credentials/  Leaked-Databases/  Default-Credentials/  ...

# Frequently used lists
/usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt
/usr/share/seclists/Passwords/Common-Credentials/100k-most-used-passwords-NCSC.txt
/usr/share/seclists/Passwords/Leaked-Databases/rockyou-75.txt
/usr/share/seclists/Usernames/top-usernames-shortlist.txt
```

---

## Custom Wordlist Generation

### CeWL — Website Crawling

`cewl` crawls a specified website to collect words and generate a custom wordlist. Words related to the target organization (employee names, product names, slogans) are likely to appear in passwords, making it effective for targeted attacks.

```bash
# Basic usage (depth 2, minimum length 6)
cewl http://target.com -d 2 -m 6 -w wordlist.txt

# Also collect email addresses
cewl http://target.com -d 3 -m 5 -e -w wordlist.txt

# Pages requiring authentication
cewl http://target.com -d 2 -m 6 \
  --auth_type basic \
  --auth_user admin \
  --auth_pass password \
  -w wordlist.txt

# Include case variations
cewl http://target.com -d 2 -m 6 --with-numbers -w raw.txt
# Generate variations via post-processing
```

### Crunch — Pattern-Based Generation

`crunch` is a tool that generates custom wordlists with a specified character set and length. When you know the specific password policy (length, included characters), you can create efficient targeted wordlists.

```bash
# crunch <min> <max> <charset> [options]

# All 4-digit numbers
crunch 4 4 0123456789 -o pins.txt

# 6-8 characters, lowercase + digits
crunch 6 8 abcdefghijklmnopqrstuvwxyz0123456789 -o wordlist.txt

# Using patterns (@=lowercase, ,=uppercase, %=digit, ^=special)
crunch 8 8 -t @@@@%%%% -o pattern.txt    # 4 lowercase + 4 digits
crunch 8 8 -t Pass%%%% -o pass_nums.txt   # Pass + 4 digits

# Using built-in charsets
crunch 8 8 -f /usr/share/crunch/charset.lst mixalpha-numeric -o out.txt

# Include specific words
crunch 1 1 -p admin user guest root -o keywords.txt
```

### CUPP — Personal Information-Based Generation

CUPP (Common User Password Profiler) generates customized wordlists based on the target's personal information. It combines name, birthday, interests, etc. to generate personalized passwords.

```bash
# Install
git clone https://github.com/Mebus/cupp /opt/cupp

# Interactive mode (enter name, birthday, pet, etc.)
python3 /opt/cupp/cupp.py -i

# Improve existing wordlist (add leetspeak, numbers, etc.)
python3 /opt/cupp/cupp.py -w wordlist.txt

# Aladddin mode (online DB)
python3 /opt/cupp/cupp.py -a

# Check generated file
wc -l cupp_output.txt
```

### Wordlist Post-Processing

Optimize collected wordlists by removing duplicates and sorting. This reduces size and improves cracking efficiency by eliminating redundancy.

```bash
# Remove duplicates and sort
sort wordlist.txt | uniq > clean_wordlist.txt

# Filter by length
awk 'length >= 8 && length <= 16' wordlist.txt > filtered.txt

# Merge multiple lists, then sort and deduplicate
cat list1.txt list2.txt list3.txt | sort -u > combined.txt

# Only entries without special characters
grep -P '^[a-zA-Z0-9]+$' wordlist.txt > alphanum_only.txt

# Only entries containing uppercase letters
grep '[A-Z]' wordlist.txt > has_upper.txt
```

---

## Python Hash Identification + Cracking Script

```python
#!/usr/bin/env python3
"""
Hash identification and wordlist-based cracking tool
Usage: python3 hash_cracker.py -H <hash> -w <wordlist> [-t <threads>]
"""

import argparse
import hashlib
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Optional


# Hash pattern definitions
HASH_PATTERNS: dict[str, tuple[str, int]] = {
    "MD5":          (r"^[a-fA-F0-9]{32}$",   0),
    "SHA-1":        (r"^[a-fA-F0-9]{40}$",   100),
    "SHA-256":      (r"^[a-fA-F0-9]{64}$",   1400),
    "SHA-512":      (r"^[a-fA-F0-9]{128}$",  1700),
    "NTLM":         (r"^[a-fA-F0-9]{32}$",   1000),
    "bcrypt":       (r"^\$2[ayb]\$.{56}$",    3200),
    "MD5crypt":     (r"^\$1\$.{8}\$.{22}$",   500),
    "SHA512crypt":  (r"^\$6\$.{8,16}\$.+$",   1800),
}

# Algorithm → hashlib mapping
HASH_FUNCS: dict[str, str] = {
    "MD5":     "md5",
    "SHA-1":   "sha1",
    "SHA-256": "sha256",
    "SHA-512": "sha512",
    "NTLM":    "md4",   # NTLM is MD4-based; verify hashlib support
}


def identify_hash(hash_str: str) -> list[str]:
    """Return list of possible algorithms for a hash string."""
    candidates: list[str] = []
    for name, (pattern, _) in HASH_PATTERNS.items():
        if re.match(pattern, hash_str):
            candidates.append(name)
    return candidates if candidates else ["Unknown"]


def compute_hash(algorithm: str, plaintext: str) -> Optional[str]:
    """Compute the hash of plaintext using the given algorithm."""
    func_name = HASH_FUNCS.get(algorithm)
    if not func_name:
        return None
    try:
        h = hashlib.new(func_name, plaintext.encode("utf-8", errors="replace"))
        return h.hexdigest()
    except ValueError:
        return None


def try_word(word: str, target_hash: str, algorithm: str) -> Optional[str]:
    """Attempt to crack with a single word. Returns plaintext on success."""
    word = word.strip()
    computed = compute_hash(algorithm, word)
    if computed and computed.lower() == target_hash.lower():
        return word
    return None


def crack_hash(
    target_hash: str,
    wordlist_path: Path,
    algorithm: str,
    max_workers: int = 8,
) -> Optional[str]:
    """
    Read wordlist and attempt hash cracking with multiple threads.
    Returns plaintext on success, None on failure.
    """
    if not wordlist_path.exists():
        print(f"[!] Wordlist file not found: {wordlist_path}", file=sys.stderr)
        return None

    print(f"[*] Algorithm: {algorithm} | Hash: {target_hash[:16]}...")
    print(f"[*] Wordlist: {wordlist_path}")

    total = 0
    found: Optional[str] = None

    try:
        with wordlist_path.open("r", encoding="utf-8", errors="ignore") as f:
            words = f.readlines()

        total = len(words)
        print(f"[*] Loaded {total:,} words, threads: {max_workers}")

        chunk_size = max(1, total // (max_workers * 10))
        futures = {}

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            for i, word in enumerate(words):
                if found:
                    break
                future = executor.submit(try_word, word, target_hash, algorithm)
                futures[future] = i

                # Print progress every 10,000 entries
                if i % 10000 == 0 and i > 0:
                    print(f"[*] Progress: {i:,}/{total:,} ({i/total*100:.1f}%)")

            for future in as_completed(futures):
                result = future.result()
                if result is not None:
                    found = result
                    print(f"\n[+] Cracking successful!")
                    print(f"[+] Plaintext: {result}")
                    executor.shutdown(wait=False, cancel_futures=True)
                    break

    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")

    return found


def load_hash_file(path: Path) -> list[str]:
    """Read list of hashes from a hash file."""
    try:
        return [line.strip() for line in path.read_text().splitlines() if line.strip()]
    except OSError as e:
        print(f"[!] Failed to read file: {e}", file=sys.stderr)
        sys.exit(1)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Hash identification and wordlist cracking tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 hash_cracker.py -H 5f4dcc3b5aa765d61d8327deb882cf99 -w rockyou.txt
  python3 hash_cracker.py -H 5f4dcc3b... -w rockyou.txt -a MD5 -t 16
  python3 hash_cracker.py -f hashes.txt -w wordlist.txt --identify-only
        """,
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-H", "--hash", help="Single hash to crack")
    group.add_argument("-f", "--file", type=Path, help="File containing list of hashes")

    parser.add_argument("-w", "--wordlist", type=Path, help="Path to wordlist file")
    parser.add_argument(
        "-a", "--algorithm",
        choices=list(HASH_FUNCS.keys()),
        default=None,
        help="Force hash algorithm (auto-detected if not specified)",
    )
    parser.add_argument("-t", "--threads", type=int, default=8, help="Number of threads (default: 8)")
    parser.add_argument(
        "--identify-only", action="store_true",
        help="Identify only, do not attempt cracking",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    # Prepare hash list
    hashes: list[str] = []
    if args.hash:
        hashes = [args.hash]
    elif args.file:
        hashes = load_hash_file(args.file)

    print(f"[*] Processing {len(hashes)} hashes\n")

    for target in hashes:
        print(f"{'='*60}")
        print(f"[*] Target hash: {target}")

        # Identify hash
        candidates = identify_hash(target)
        print(f"[*] Possible algorithms: {', '.join(candidates)}")

        if args.identify_only:
            continue

        if not args.wordlist:
            print("[!] Cracking requires -w option", file=sys.stderr)
            continue

        # Determine algorithm
        algorithm = args.algorithm
        if not algorithm:
            # Select the first supported algorithm
            for c in candidates:
                if c in HASH_FUNCS:
                    algorithm = c
                    break

        if not algorithm:
            print(f"[!] Unsupported algorithm: {candidates}")
            print("[!] Specify algorithm manually with -a option")
            continue

        result = crack_hash(target, args.wordlist, algorithm, args.threads)
        if result is None:
            print(f"[-] Cracking failed — not found in wordlist")

    print(f"\n[*] Done")


if __name__ == "__main__":
    main()
```

### Script Usage Examples

These are usage examples for the hash identification and cracking script. When you provide a hash value, it automatically determines the type and selects the appropriate cracking approach.

```bash
# Crack a single MD5 hash
python3 hash_cracker.py -H 5f4dcc3b5aa765d61d8327deb882cf99 \
  -w /usr/share/wordlists/rockyou.txt

# SHA-256 hash with explicit algorithm, 16 threads
python3 hash_cracker.py \
  -H a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3 \
  -w /usr/share/wordlists/rockyou.txt \
  -a SHA-256 \
  -t 16

# Batch identify hashes in a file only
python3 hash_cracker.py -f hashes.txt --identify-only

# Batch crack hashes from a file
python3 hash_cracker.py -f hashes.txt -w /opt/SecLists/Passwords/rockyou-75.txt -t 4
```

---

## Hash Sample Reference

Generate hashes directly for each algorithm to create reference samples. Compare the output formats of MD5, SHA-1, SHA-256, bcrypt, and others.

```bash
# Generate hashes directly (for testing)
echo -n "password" | md5sum
# 5f4dcc3b5aa765d61d8327deb882cf99

echo -n "password" | sha1sum
# 5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8

echo -n "password" | sha256sum
# 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8

# Compute NTLM hash with Python
python3 -c "
import hashlib
pw = 'Password123'
ntlm = hashlib.new('md4', pw.encode('utf-16le')).hexdigest()
print(f'NTLM: {ntlm}')
"

# bcrypt with Python
python3 -c "
import bcrypt
pw = b'password'
hashed = bcrypt.hashpw(pw, bcrypt.gensalt(rounds=10))
print(hashed.decode())
"
```
