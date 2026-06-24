> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 크리덴셜 스터핑 및 패스워드 분석 자동화

## 0. 초보자를 위한 개념 이해

### 크리덴셜 스터핑이란?

크리덴셜 스터핑(Credential Stuffing)은 다른 서비스에서 유출된 아이디/비밀번호 쌍을 자동으로 다른 사이트에 대입하는 공격이다. 사용자들이 여러 사이트에서 같은 비밀번호를 재사용하는 습관을 악용한다. 예를 들어 게임 사이트에서 유출된 계정 정보로 은행 사이트에 로그인을 시도하는 것이다.

**왜 배우는가:**
```
크리덴셜 스터핑 공격 흐름

[유출 데이터베이스] → [id:pw 쌍 수백만 개]
         ↓
[자동화 도구]       → 초당 수십~수백 개 시도
         ↓
[다른 서비스들]     → Netflix, 이메일, 쇼핑몰, 은행...
         ↓
[성공한 계정]       → 사기, 정보 탈취, 계정 판매

방어 담당자가 배워야 할 이유:
  - 어떻게 탐지할 것인가 (속도 제한, 비정상 로그인 패턴)
  - 어떻게 차단할 것인가 (MFA, CAPTCHA, IP 차단)
  - 유출된 비밀번호를 즉시 확인하는 방법
```

### 핵심 개념 정리

```
크리덴셜 스터핑 vs 브루트포스

크리덴셜 스터핑:
  - 유출된 실제 id:pw 쌍 사용
  - 서비스마다 다른 사이트에 적용
  - 성공률: 0.1~2% (그래도 수백만 개면 수천~수만 계정)
  - 탐지: 다양한 IP에서 정상적인 속도로 시도 → 탐지 어려움

브루트포스:
  - 모든 조합을 시도
  - 같은 계정 반복 시도
  - 성공률: 비밀번호 복잡도에 의존
  - 탐지: 같은 계정 반복 실패 → 상대적으로 탐지 쉬움
```

### 필요한 도구 및 환경
- **HaveIBeenPwned API**: 유출 여부 확인 (합법적, 안전)
- **Python 3.10+**: 자동화 스크립트 작성
- **테스트 환경**: 반드시 자신이 소유한 시스템에서만 실습

### 기초 실습 예제
```python
#!/usr/bin/env python3
"""HaveIBeenPwned — 비밀번호 유출 여부 안전하게 확인 (k-익명성 방식)"""
import hashlib
import urllib.request

def check_pwned(password: str) -> int:
    """비밀번호 유출 횟수 반환 (0이면 안전, 양수면 유출됨)
    
    k-익명성: 해시 앞 5자리만 API에 전송 → 실제 비밀번호 노출 안 됨
    """
    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]

    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    with urllib.request.urlopen(url) as resp:
        lines = resp.read().decode().splitlines()

    for line in lines:
        h, count = line.split(":")
        if h == suffix:
            return int(count)
    return 0

# 테스트
for pw in ["password", "password123", "xK9#mP2$vL8@"]:
    count = check_pwned(pw)
    status = f"유출 {count:,}회" if count else "안전"
    print(f"  {pw!r:25s} → {status}")
```

---

## 개요

크리덴셜 스터핑(Credential Stuffing)은 유출된 아이디/패스워드 조합을 다른 서비스에 대입하는 공격으로, 사용자가 여러 사이트에서 동일한 패스워드를 재사용하는 습관을 악용한다.

---

## 유출 데이터베이스 분석

### HaveIBeenPwned API 활용

```python
import hashlib
import urllib.request


def check_password_pwned(password: str) -> int:
    """비밀번호가 유출 DB에 있는지 확인. 반환값: 유출 횟수 (0=안전)"""
    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]

    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    with urllib.request.urlopen(url) as resp:
        lines = resp.read().decode().splitlines()

    for line in lines:
        hash_suffix, count = line.split(":")
        if hash_suffix == suffix:
            return int(count)
    return 0
```

```bash
# 커맨드라인에서 확인
echo -n "password123" | sha1sum | cut -c1-5
# → e38ad → https://api.pwnedpasswords.com/range/E38AD

# 결과에서 나머지 해시 검색
curl -s https://api.pwnedpasswords.com/range/E38AD | grep "21BD1"
```

### 유출 데이터베이스 처리 (대용량 파일)

```python
#!/usr/bin/env python3
"""유출 크리덴셜 파일 파싱 및 통계 분석"""

import argparse
import re
import sys
from collections import Counter
from pathlib import Path


def parse_credential_file(filepath: Path, delimiter: str = ":") -> list[tuple[str, str]]:
    """email:password 형식 파일 파싱"""
    creds: list[tuple[str, str]] = []
    error_count = 0

    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            parts = line.split(delimiter, 1)
            if len(parts) == 2:
                email, password = parts
                creds.append((email.lower(), password))
            else:
                error_count += 1

    if error_count > 0:
        print(f"[!] 파싱 실패 라인: {error_count}개", file=sys.stderr)

    return creds


def analyze_passwords(creds: list[tuple[str, str]]) -> dict:
    """패스워드 통계 분석"""
    passwords = [p for _, p in creds]

    analysis = {
        "total": len(passwords),
        "unique": len(set(passwords)),
        "duplicate_rate": 0.0,
        "top_10": [],
        "length_distribution": {},
        "pattern_stats": {},
    }

    analysis["duplicate_rate"] = 1 - (analysis["unique"] / max(analysis["total"], 1))

    # 상위 10개 패스워드
    counter = Counter(passwords)
    analysis["top_10"] = counter.most_common(10)

    # 길이 분포
    length_counter: Counter = Counter(len(p) for p in passwords)
    analysis["length_distribution"] = dict(sorted(length_counter.items()))

    # 패턴 통계
    patterns = {
        "숫자만": r"^\d+$",
        "영소문자만": r"^[a-z]+$",
        "영대소문자": r"^[a-zA-Z]+$",
        "영숫자": r"^[a-zA-Z0-9]+$",
        "특수문자 포함": r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?]",
        "8자 미만": None,
        "12자 이상": None,
    }

    for name, pattern in patterns.items():
        if pattern:
            count = sum(1 for p in passwords if re.match(pattern, p))
        elif name == "8자 미만":
            count = sum(1 for p in passwords if len(p) < 8)
        else:
            count = sum(1 for p in passwords if len(p) >= 12)

        analysis["pattern_stats"][name] = {
            "count": count,
            "percent": round(count / max(len(passwords), 1) * 100, 1),
        }

    return analysis


def extract_by_domain(
    creds: list[tuple[str, str]], domain: str
) -> list[tuple[str, str]]:
    """특정 도메인의 이메일만 추출"""
    return [(e, p) for e, p in creds if e.endswith(f"@{domain}")]
```

---

## 패스워드 패턴 생성 (CUPP 원리)

CUPP(Common User Password Profiler)는 대상자 정보를 기반으로 맞춤형 워드리스트를 생성한다.

```python
#!/usr/bin/env python3
"""
Password Profile Generator - 타겟 기반 워드리스트 생성
사용법: python3 profiler.py --name "김철수" --birth 1990 --output wordlist.txt
"""

import argparse
import itertools
from pathlib import Path


LEET_MAP = {
    "a": ["@", "4"],
    "e": ["3"],
    "i": ["1", "!"],
    "o": ["0"],
    "s": ["$", "5"],
    "t": ["7"],
    "l": ["1"],
    "g": ["9"],
}

COMMON_SUFFIXES = [
    "!", "!!", "123", "1234", "12345",
    "1", "2", "01", "00",
    "2023", "2024", "2025",
    "@", "#", "$",
]

COMMON_PREFIXES = ["", "1", "!", "123"]


def apply_leet(word: str) -> list[str]:
    """리트(leet) 변환 변형 생성"""
    results = {word}
    for char, replacements in LEET_MAP.items():
        new_results = set()
        for current in results:
            new_results.add(current)
            for rep in replacements:
                new_results.add(current.replace(char, rep))
        results = new_results
    return list(results)


def generate_base_words(profile: dict) -> list[str]:
    """프로필 정보에서 기본 단어 생성"""
    words: list[str] = []

    for field in ["name", "pet", "partner", "company", "city"]:
        if val := profile.get(field):
            words.extend([
                val,
                val.lower(),
                val.upper(),
                val.capitalize(),
            ])

    if birth := profile.get("birth"):
        birth_str = str(birth)
        words.extend([
            birth_str,
            birth_str[-2:],  # 년도 끝 두 자리
            birth_str[-4:],  # 년도
        ])

        if month := profile.get("birth_month"):
            words.append(f"{birth_str[-4:]}{int(month):02d}")

        if day := profile.get("birth_day"):
            words.append(f"{int(day):02d}")

    return list(set(words))


def generate_wordlist(
    base_words: list[str],
    min_length: int = 6,
    max_length: int = 16,
) -> list[str]:
    """기본 단어에서 변형 워드리스트 생성"""
    all_words: set[str] = set()

    for word in base_words:
        # 원본
        all_words.add(word)

        # 대소문자 변형
        all_words.add(word.upper())
        all_words.add(word.lower())
        all_words.add(word.capitalize())

        # 리트 변환
        all_words.update(apply_leet(word.lower()))

        # 접미사 추가
        for suffix in COMMON_SUFFIXES:
            all_words.add(word + suffix)
            all_words.add(word.capitalize() + suffix)

        # 접두사 추가
        for prefix in COMMON_PREFIXES:
            all_words.add(prefix + word)

        # 두 단어 조합 (3개까지)
        for word2 in base_words[:5]:
            if word != word2:
                all_words.add(word + word2)
                all_words.add(word.capitalize() + word2.capitalize())

    # 길이 필터
    return [w for w in all_words if min_length <= len(w) <= max_length]


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Password Profile Generator - 타겟 기반 워드리스트",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
사용 예시:
  python3 profiler.py --name "chulsoo" --birth 1990 --company "samsung"
  python3 profiler.py --name "kim" --pet "bori" --output my_wordlist.txt
        """,
    )
    parser.add_argument("--name", help="이름")
    parser.add_argument("--birth", type=int, help="출생연도")
    parser.add_argument("--birth-month", type=int, help="생월")
    parser.add_argument("--birth-day", type=int, help="생일")
    parser.add_argument("--pet", help="반려동물 이름")
    parser.add_argument("--partner", help="배우자/파트너 이름")
    parser.add_argument("--company", help="직장")
    parser.add_argument("--city", help="도시")
    parser.add_argument("--keywords", nargs="+", help="추가 키워드")
    parser.add_argument("--output", type=Path, help="출력 파일")
    parser.add_argument("--min-length", type=int, default=6, help="최소 길이")
    parser.add_argument("--max-length", type=int, default=16, help="최대 길이")

    args = parser.parse_args()

    profile: dict = {}
    for field in ["name", "birth", "pet", "partner", "company", "city"]:
        if val := getattr(args, field, None):
            profile[field] = str(val)

    if args.birth_month:
        profile["birth_month"] = args.birth_month
    if args.birth_day:
        profile["birth_day"] = args.birth_day

    base_words = generate_base_words(profile)

    if args.keywords:
        base_words.extend(args.keywords)

    wordlist = generate_wordlist(base_words, args.min_length, args.max_length)
    wordlist.sort(key=lambda w: (-len(w), w))

    print(f"[+] 생성된 패스워드 후보: {len(wordlist)}개")

    if args.output:
        args.output.write_text("\n".join(wordlist))
        print(f"[+] 저장: {args.output}")
        print(f"    hashcat: hashcat -m 0 hash.txt {args.output}")
    else:
        print("\n".join(wordlist[:50]))
        if len(wordlist) > 50:
            print(f"... (총 {len(wordlist)}개, --output으로 전체 저장)")


if __name__ == "__main__":
    main()
```

---

## Hashcat 마스크 공격 최적화

```bash
# 마스크 문자
# ?l = 소문자 (a-z)
# ?u = 대문자 (A-Z)
# ?d = 숫자 (0-9)
# ?s = 특수문자
# ?a = ?l?u?d?s 모두

# 한국 기업 패스워드 패턴 (이름+생년월일)
hashcat -m 0 hash.txt -a 3 ?u?l?l?l?l?d?d?d?d?d?d?d?d

# 8자리 패턴: 대문자1+소문자5+숫자2
hashcat -m 0 hash.txt -a 3 ?u?l?l?l?l?l?d?d

# 커스텀 문자셋 정의
hashcat -m 0 hash.txt -a 3 \
  -1 "abcdefghijklmnopqrstuvwxyz0123456789" \
  ?1?1?1?1?1?1?1?1

# 룰 + 사전 공격 조합
hashcat -m 0 hash.txt -a 0 \
  /usr/share/wordlists/rockyou.txt \
  -r /usr/share/hashcat/rules/best64.rule \
  -r /usr/share/hashcat/rules/OneRuleToRuleThemAll.rule

# PRINCE 공격 (단어 조합)
hashcat -m 0 hash.txt -a 6 wordlist.txt ?d?d?d?d

# 복합 마스크 파일
cat > masks.hcmask << 'EOF'
?u?l?l?l?l?l?d?d
?u?l?l?l?l?l?l?d?d
?u?l?l?l?l?l?d?d?d?d
?u?l?l?l?l?l?l?d?d?d?d
?u?l?l?l?l?l?s?d?d
EOF
hashcat -m 0 hash.txt -a 3 masks.hcmask
```

---

## 방어 측 탐지: 크리덴셜 스터핑 식별

### 로그 기반 탐지 (Nginx)

```python
#!/usr/bin/env python3
"""크리덴셜 스터핑 공격 탐지 - Nginx 액세스 로그 분석"""

import argparse
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class AttackCandidate:
    ip: str
    request_count: int
    unique_usernames: int
    failure_rate: float
    time_window: tuple[str, str]


def parse_nginx_log(filepath: Path) -> list[dict]:
    pattern = re.compile(
        r'(?P<ip>\S+) .+ \[(?P<time>[^\]]+)\] '
        r'"POST (?P<path>\S+) HTTP/[^"]*" (?P<status>\d+)'
    )
    entries = []
    for line in filepath.read_text(errors="ignore").splitlines():
        if m := pattern.match(line):
            entries.append(m.groupdict())
    return entries


def detect_stuffing(
    entries: list[dict],
    login_path: str = "/api/login",
    threshold: int = 50,
) -> list[AttackCandidate]:
    ip_stats: defaultdict = defaultdict(lambda: {"total": 0, "failed": 0, "times": []})

    for entry in entries:
        if entry["path"] != login_path:
            continue
        ip = entry["ip"]
        ip_stats[ip]["total"] += 1
        if entry["status"] in ("401", "403", "429"):
            ip_stats[ip]["failed"] += 1
        ip_stats[ip]["times"].append(entry["time"])

    candidates: list[AttackCandidate] = []
    for ip, stats in ip_stats.items():
        if stats["total"] < threshold:
            continue
        failure_rate = stats["failed"] / max(stats["total"], 1)
        if failure_rate > 0.7:  # 70% 이상 실패
            times = sorted(stats["times"])
            candidates.append(
                AttackCandidate(
                    ip=ip,
                    request_count=stats["total"],
                    unique_usernames=0,
                    failure_rate=round(failure_rate * 100, 1),
                    time_window=(times[0], times[-1]),
                )
            )

    return sorted(candidates, key=lambda c: c.request_count, reverse=True)
```

---

## 실전 체크리스트

### 크리덴셜 스터핑 방어

- [ ] Rate Limiting: IP당 로그인 시도 횟수 제한 (5회/분)
- [ ] CAPTCHA: 반복 실패 시 CAPTCHA 요구
- [ ] MFA: 모든 계정에 다중 인증 필수화
- [ ] 비밀번호 유출 감지: HIBP API 연동, 회원가입/로그인 시 확인
- [ ] 디바이스 핑거프린팅: 새 기기에서 로그인 시 추가 검증
- [ ] 지리적 이상 탐지: 평소와 다른 국가에서 접근 시 알림
- [ ] 비밀번호 정책: 최소 12자, 복잡도 요구, 흔한 패스워드 차단

---

<!-- detect-validate-22 -->
## 크레덴셜 스터핑·계정탈취 탐지와 방어 검증

크레덴셜 스터핑은 *유출셋 재생·프록시 로테이션·저속 분산 시도*로 계정을 탈취한다. 방어자는 **자체 로그인이 대량 시도를 차단·탐지하는가**를 검증해야 한다. 검증은 **소유 애플리케이션**에서만.

### 공격 → 노리는 약점 → 1차 통제(방어자) → 탐지 신호

| 기법 | 노리는 약점 | 1차 통제(방어자) | 탐지 신호 |
|---|---|---|---|
| 유출셋 재생 | 재사용 패스워드 | HIBP 대조·MFA | 신규 IP 대량 로그인 시도 |
| 프록시 로테이션 | IP 기반 차단 한계 | 디바이스 핑거프린팅 | 분산 IP 동일 UA 패턴 |
| 저속 분산(low-and-slow) | 임계 기반 탐지 | 행위 기반 탐지 | 장기 저빈도 401/403 |
| 봇 자동화 | 인간 검증 부재 | CAPTCHA·리스크 점수 | 비정상 로그인 성공률 |

### 방어 검증 (직접 확인)

```bash
# 1) 자체 로그인 로그에서 스터핑 신호 — 4xx 폭주/분산 IP(소유 앱)
awk '$9~/40[13]/ && $7~/login/ {print $1}' /var/log/nginx/access.log 2>/dev/null | sort | uniq -c | sort -rn | head
# 2) 불가능 이동·동일 UA 분산 점검
awk '$7~/login/ {print $1, $12}' /var/log/nginx/access.log 2>/dev/null | sort | uniq -c | sort -rn | head
```

> 스터핑 방어는 *대량 시도가 실제로 걸리는가*다 — "MFA 있다"와 "유출셋 재생이 차단되고 분산 시도가 탐지된다"는 다르다. 소유 앱 로그에서 4xx 폭주·불가능 이동을 직접 확인한다([[52_API_Security]], [[05_Web_Hacking]], [[13_SOC_Blue_Team]]).

---

<a name="english"></a>

# Credential Stuffing and Password Analysis Automation

## Overview

Credential stuffing attacks use leaked username/password combinations against other services, exploiting the habit of users reusing the same password across multiple sites.

---

## Analyzing Leaked Databases

### Using the HaveIBeenPwned API

```python
import hashlib
import urllib.request


def check_password_pwned(password: str) -> int:
    """Check if password exists in breach database. Returns: breach count (0=safe)"""
    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]

    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    with urllib.request.urlopen(url) as resp:
        lines = resp.read().decode().splitlines()

    for line in lines:
        hash_suffix, count = line.split(":")
        if hash_suffix == suffix:
            return int(count)
    return 0
```

```bash
# Check from command line
echo -n "password123" | sha1sum | cut -c1-5
# → e38ad → https://api.pwnedpasswords.com/range/E38AD

# Search remaining hash in result
curl -s https://api.pwnedpasswords.com/range/E38AD | grep "21BD1"
```

### Processing Leaked Databases (Large Files)

```python
#!/usr/bin/env python3
"""Parse and statistically analyze leaked credential files"""

import argparse
import re
import sys
from collections import Counter
from pathlib import Path


def parse_credential_file(filepath: Path, delimiter: str = ":") -> list[tuple[str, str]]:
    """Parse email:password format file"""
    creds: list[tuple[str, str]] = []
    error_count = 0

    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            parts = line.split(delimiter, 1)
            if len(parts) == 2:
                email, password = parts
                creds.append((email.lower(), password))
            else:
                error_count += 1

    if error_count > 0:
        print(f"[!] Failed to parse lines: {error_count}", file=sys.stderr)

    return creds


def analyze_passwords(creds: list[tuple[str, str]]) -> dict:
    """Statistical password analysis"""
    passwords = [p for _, p in creds]

    analysis = {
        "total": len(passwords),
        "unique": len(set(passwords)),
        "duplicate_rate": 0.0,
        "top_10": [],
        "length_distribution": {},
        "pattern_stats": {},
    }

    analysis["duplicate_rate"] = 1 - (analysis["unique"] / max(analysis["total"], 1))

    # Top 10 passwords
    counter = Counter(passwords)
    analysis["top_10"] = counter.most_common(10)

    # Length distribution
    length_counter: Counter = Counter(len(p) for p in passwords)
    analysis["length_distribution"] = dict(sorted(length_counter.items()))

    # Pattern statistics
    patterns = {
        "digits only": r"^\d+$",
        "lowercase only": r"^[a-z]+$",
        "mixed case letters": r"^[a-zA-Z]+$",
        "alphanumeric": r"^[a-zA-Z0-9]+$",
        "contains special chars": r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?]",
        "less than 8 chars": None,
        "12+ chars": None,
    }

    for name, pattern in patterns.items():
        if pattern:
            count = sum(1 for p in passwords if re.match(pattern, p))
        elif name == "less than 8 chars":
            count = sum(1 for p in passwords if len(p) < 8)
        else:
            count = sum(1 for p in passwords if len(p) >= 12)

        analysis["pattern_stats"][name] = {
            "count": count,
            "percent": round(count / max(len(passwords), 1) * 100, 1),
        }

    return analysis


def extract_by_domain(
    creds: list[tuple[str, str]], domain: str
) -> list[tuple[str, str]]:
    """Extract credentials for a specific domain"""
    return [(e, p) for e, p in creds if e.endswith(f"@{domain}")]
```

---

## Password Pattern Generation (CUPP Principles)

CUPP (Common User Password Profiler) generates custom wordlists based on target profile information.

```python
#!/usr/bin/env python3
"""
Password Profile Generator - target-based wordlist generation
Usage: python3 profiler.py --name "chulsoo" --birth 1990 --output wordlist.txt
"""

import argparse
import itertools
from pathlib import Path


LEET_MAP = {
    "a": ["@", "4"],
    "e": ["3"],
    "i": ["1", "!"],
    "o": ["0"],
    "s": ["$", "5"],
    "t": ["7"],
    "l": ["1"],
    "g": ["9"],
}

COMMON_SUFFIXES = [
    "!", "!!", "123", "1234", "12345",
    "1", "2", "01", "00",
    "2023", "2024", "2025",
    "@", "#", "$",
]

COMMON_PREFIXES = ["", "1", "!", "123"]


def apply_leet(word: str) -> list[str]:
    """Generate leet-speak transformations"""
    results = {word}
    for char, replacements in LEET_MAP.items():
        new_results = set()
        for current in results:
            new_results.add(current)
            for rep in replacements:
                new_results.add(current.replace(char, rep))
        results = new_results
    return list(results)


def generate_base_words(profile: dict) -> list[str]:
    """Generate base words from profile information"""
    words: list[str] = []

    for field in ["name", "pet", "partner", "company", "city"]:
        if val := profile.get(field):
            words.extend([
                val,
                val.lower(),
                val.upper(),
                val.capitalize(),
            ])

    if birth := profile.get("birth"):
        birth_str = str(birth)
        words.extend([
            birth_str,
            birth_str[-2:],  # last 2 digits of year
            birth_str[-4:],  # year
        ])

        if month := profile.get("birth_month"):
            words.append(f"{birth_str[-4:]}{int(month):02d}")

        if day := profile.get("birth_day"):
            words.append(f"{int(day):02d}")

    return list(set(words))


def generate_wordlist(
    base_words: list[str],
    min_length: int = 6,
    max_length: int = 16,
) -> list[str]:
    """Generate variations wordlist from base words"""
    all_words: set[str] = set()

    for word in base_words:
        # Original
        all_words.add(word)

        # Case variations
        all_words.add(word.upper())
        all_words.add(word.lower())
        all_words.add(word.capitalize())

        # Leet transformations
        all_words.update(apply_leet(word.lower()))

        # Append suffixes
        for suffix in COMMON_SUFFIXES:
            all_words.add(word + suffix)
            all_words.add(word.capitalize() + suffix)

        # Prepend prefixes
        for prefix in COMMON_PREFIXES:
            all_words.add(prefix + word)

        # Two-word combinations (up to 3)
        for word2 in base_words[:5]:
            if word != word2:
                all_words.add(word + word2)
                all_words.add(word.capitalize() + word2.capitalize())

    # Length filter
    return [w for w in all_words if min_length <= len(w) <= max_length]


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Password Profile Generator - target-based wordlist",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 profiler.py --name "chulsoo" --birth 1990 --company "samsung"
  python3 profiler.py --name "kim" --pet "bori" --output my_wordlist.txt
        """,
    )
    parser.add_argument("--name", help="Name")
    parser.add_argument("--birth", type=int, help="Birth year")
    parser.add_argument("--birth-month", type=int, help="Birth month")
    parser.add_argument("--birth-day", type=int, help="Birth day")
    parser.add_argument("--pet", help="Pet name")
    parser.add_argument("--partner", help="Spouse/partner name")
    parser.add_argument("--company", help="Employer")
    parser.add_argument("--city", help="City")
    parser.add_argument("--keywords", nargs="+", help="Additional keywords")
    parser.add_argument("--output", type=Path, help="Output file")
    parser.add_argument("--min-length", type=int, default=6, help="Minimum length")
    parser.add_argument("--max-length", type=int, default=16, help="Maximum length")

    args = parser.parse_args()

    profile: dict = {}
    for field in ["name", "birth", "pet", "partner", "company", "city"]:
        if val := getattr(args, field, None):
            profile[field] = str(val)

    if args.birth_month:
        profile["birth_month"] = args.birth_month
    if args.birth_day:
        profile["birth_day"] = args.birth_day

    base_words = generate_base_words(profile)

    if args.keywords:
        base_words.extend(args.keywords)

    wordlist = generate_wordlist(base_words, args.min_length, args.max_length)
    wordlist.sort(key=lambda w: (-len(w), w))

    print(f"[+] Generated password candidates: {len(wordlist)}")

    if args.output:
        args.output.write_text("\n".join(wordlist))
        print(f"[+] Saved: {args.output}")
        print(f"    hashcat: hashcat -m 0 hash.txt {args.output}")
    else:
        print("\n".join(wordlist[:50]))
        if len(wordlist) > 50:
            print(f"... (total {len(wordlist)}, use --output to save all)")


if __name__ == "__main__":
    main()
```

---

## Hashcat Mask Attack Optimization

```bash
# Mask characters
# ?l = lowercase (a-z)
# ?u = uppercase (A-Z)
# ?d = digits (0-9)
# ?s = special characters
# ?a = all of ?l?u?d?s

# Korean corporate password pattern (name+birthdate)
hashcat -m 0 hash.txt -a 3 ?u?l?l?l?l?d?d?d?d?d?d?d?d

# 8-character pattern: 1 uppercase + 5 lowercase + 2 digits
hashcat -m 0 hash.txt -a 3 ?u?l?l?l?l?l?d?d

# Define custom charset
hashcat -m 0 hash.txt -a 3 \
  -1 "abcdefghijklmnopqrstuvwxyz0123456789" \
  ?1?1?1?1?1?1?1?1

# Rule + dictionary attack combination
hashcat -m 0 hash.txt -a 0 \
  /usr/share/wordlists/rockyou.txt \
  -r /usr/share/hashcat/rules/best64.rule \
  -r /usr/share/hashcat/rules/OneRuleToRuleThemAll.rule

# PRINCE attack (word combinations)
hashcat -m 0 hash.txt -a 6 wordlist.txt ?d?d?d?d

# Combined mask file
cat > masks.hcmask << 'EOF'
?u?l?l?l?l?l?d?d
?u?l?l?l?l?l?l?d?d
?u?l?l?l?l?l?d?d?d?d
?u?l?l?l?l?l?l?d?d?d?d
?u?l?l?l?l?l?s?d?d
EOF
hashcat -m 0 hash.txt -a 3 masks.hcmask
```

---

## Defensive Detection: Identifying Credential Stuffing

### Log-based Detection (Nginx)

```python
#!/usr/bin/env python3
"""Credential stuffing attack detection - Nginx access log analysis"""

import argparse
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class AttackCandidate:
    ip: str
    request_count: int
    unique_usernames: int
    failure_rate: float
    time_window: tuple[str, str]


def parse_nginx_log(filepath: Path) -> list[dict]:
    pattern = re.compile(
        r'(?P<ip>\S+) .+ \[(?P<time>[^\]]+)\] '
        r'"POST (?P<path>\S+) HTTP/[^"]*" (?P<status>\d+)'
    )
    entries = []
    for line in filepath.read_text(errors="ignore").splitlines():
        if m := pattern.match(line):
            entries.append(m.groupdict())
    return entries


def detect_stuffing(
    entries: list[dict],
    login_path: str = "/api/login",
    threshold: int = 50,
) -> list[AttackCandidate]:
    ip_stats: defaultdict = defaultdict(lambda: {"total": 0, "failed": 0, "times": []})

    for entry in entries:
        if entry["path"] != login_path:
            continue
        ip = entry["ip"]
        ip_stats[ip]["total"] += 1
        if entry["status"] in ("401", "403", "429"):
            ip_stats[ip]["failed"] += 1
        ip_stats[ip]["times"].append(entry["time"])

    candidates: list[AttackCandidate] = []
    for ip, stats in ip_stats.items():
        if stats["total"] < threshold:
            continue
        failure_rate = stats["failed"] / max(stats["total"], 1)
        if failure_rate > 0.7:  # more than 70% failure rate
            times = sorted(stats["times"])
            candidates.append(
                AttackCandidate(
                    ip=ip,
                    request_count=stats["total"],
                    unique_usernames=0,
                    failure_rate=round(failure_rate * 100, 1),
                    time_window=(times[0], times[-1]),
                )
            )

    return sorted(candidates, key=lambda c: c.request_count, reverse=True)
```

---

## Practical Checklist

### Credential Stuffing Defense

- [ ] Rate Limiting: limit login attempts per IP (5 attempts/minute)
- [ ] CAPTCHA: require CAPTCHA after repeated failures
- [ ] MFA: mandate multi-factor authentication for all accounts
- [ ] Breach password detection: integrate HIBP API, check on registration/login
- [ ] Device fingerprinting: require additional verification for new devices
- [ ] Geo-anomaly detection: alert on logins from unusual countries
- [ ] Password policy: minimum 12 characters, complexity requirements, block common passwords

<!-- detect-validate-22 -->
## Credential Stuffing and Account-Takeover Detection and Defense Validation

Credential stuffing takes over accounts via *breach-set replay, proxy rotation, and low-and-slow distributed attempts*. Defenders must verify **whether their own login blocks and detects mass attempts**. Validate only on **owned applications**.

### Attack -> Targeted weakness -> Primary control (defender) -> Detection signal

| Technique | Targeted weakness | Primary control (defender) | Detection signal |
|---|---|---|---|
| Breach-set replay | Reused passwords | HIBP check, MFA | Mass login attempts from new IPs |
| Proxy rotation | IP-block limits | Device fingerprinting | Distributed IPs, same UA pattern |
| Low-and-slow | Threshold-based detection | Behavior-based detection | Long-term low-rate 401/403 |
| Bot automation | No human verification | CAPTCHA, risk score | Abnormal login success rate |

### Defense validation (verify directly)

```bash
# 1) Look for stuffing signals in your own login logs — 4xx bursts / distributed IPs (owned app)
awk '$9~/40[13]/ && $7~/login/ {print $1}' /var/log/nginx/access.log 2>/dev/null | sort | uniq -c | sort -rn | head
# 2) Check impossible travel / same-UA distribution
awk '$7~/login/ {print $1, $12}' /var/log/nginx/access.log 2>/dev/null | sort | uniq -c | sort -rn | head
```

> Stuffing defense is *whether mass attempts are actually caught* -- "we have MFA" differs from "breach-set replay is blocked and distributed attempts are detected". Confirm 4xx bursts and impossible travel in owned-app logs directly ([[52_API_Security]], [[05_Web_Hacking]], [[13_SOC_Blue_Team]]).
