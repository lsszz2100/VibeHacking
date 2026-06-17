> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 버그바운티 기초: 해커로 돈 버는 합법적인 방법

## 버그바운티란 무엇인가?

버그바운티(Bug Bounty)는 기업이 외부 보안 연구자들에게 자사 시스템의 취약점을 찾아 신고해 달라고 공개적으로 의뢰하는 프로그램입니다. 쉽게 말하면 "우리 서비스에서 버그를 찾으면 돈을 드립니다"라는 계약입니다.

은행을 털려고 시도하는 것과 은행 측의 허락을 받고 보안 점검을 하는 것은 전혀 다릅니다. 버그바운티는 후자입니다. 법적으로 보호받으면서 해킹 실력을 발휘하고, 그 대가로 보상을 받는 구조입니다.

---

## 주요 버그바운티 플랫폼

### HackerOne
- 세계 최대 버그바운티 플랫폼
- Uber, Twitter, GitHub, U.S. Department of Defense 등이 사용
- 공개 프로그램(Public)과 초대 전용(Private) 프로그램 구분
- 누적 지급 보상액 3억 달러 이상

### Bugcrowd
- HackerOne과 양대 산맥
- Mastercard, Barclays, Tesla 등이 사용
- 버그바운티 외에도 침투 테스트(PTaaS) 서비스 제공

### Intigriti
- 유럽 중심의 플랫폼
- GDPR 관련 보안에 특화
- 유럽 기업 버그바운티에 강점

### 자체 운영 프로그램
- Google Vulnerability Reward Program (VRP)
- Apple Security Bounty
- Microsoft Bug Bounty Program
- Meta Bug Bounty

---

## 책임감 있는 공개 (Responsible Disclosure)

버그바운티에서 가장 중요한 원칙입니다. 무엇을 하든 이 원칙을 지켜야 합니다.

### 핵심 원칙

1. **허가된 범위 안에서만 테스트**: 스코프(Scope)에 명시된 도메인/IP만 테스트
2. **발견 즉시 신고**: 취약점을 발견하면 악용하지 않고 즉시 신고
3. **데이터 접근 최소화**: 취약점 증명에 필요한 최소한의 데이터만 접근
4. **비밀 유지**: 기업이 패치하기 전까지 외부에 공개하지 않음
5. **시스템 훼손 금지**: 서비스 중단이나 데이터 삭제는 절대 금지

### 잘못된 행동 예시
- 스코프 밖의 서버를 테스트하는 것
- SQL Injection으로 실제 고객 데이터를 덤프하는 것
- DoS 공격으로 서비스를 중단시키는 것
- 취약점을 SNS에 먼저 공개하는 것

---

## 스코프(Scope) 이해

스코프는 "어디까지 테스트해도 되는가"를 명시한 경계선입니다.

### In-Scope (테스트 가능)
```
*.example.com       # 모든 서브도메인
api.example.com     # API 서버
mobile.example.com  # 모바일 웹
```

### Out-of-Scope (테스트 불가)
```
admin.example.com   # 관리자 패널 (별도 명시)
partner.example.com # 파트너사 시스템
third-party CDN     # 외부 서비스
```

### 스코프 확인이 왜 중요한가?
스코프 밖에서 취약점을 발견해도 보상을 받지 못하며, 오히려 법적 문제가 생길 수 있습니다. 테스트 전에 반드시 프로그램 정책을 꼼꼼히 읽으세요.

---

## 취약점 심각도와 보상 금액

### CVSS 점수 기반 심각도 분류

| 심각도 | CVSS 점수 | 예시 취약점 | 평균 보상 |
|--------|-----------|-------------|-----------|
| Critical | 9.0–10.0 | RCE, SQL Injection (admin) | $5,000–$50,000+ |
| High | 7.0–8.9 | SSRF, XXE, Auth Bypass | $1,000–$10,000 |
| Medium | 4.0–6.9 | XSS, IDOR, 정보 노출 | $300–$2,000 |
| Low | 0.1–3.9 | 약한 암호화, 배너 노출 | $50–$500 |
| Informational | 없음 | 보안 설정 권고 | 보상 없음 |

### 실제 보상 사례
- Google Chrome 취약점: $30,000+
- Apple iCloud RCE: $50,000+
- HackerOne 자체 취약점: $20,000+
- Facebook 계정 탈취: $25,000+

---

## 초보자가 시작하는 방법

### Step 1: 기초 지식 습득
- OWASP Top 10 이해
- HTTP 프로토콜 완전 이해
- Burp Suite 기본 사용법

### Step 2: 실습 환경 구축
```bash
# DVWA (Damn Vulnerable Web Application) 설치
docker pull vulnerables/web-dvwa
docker run -d -p 80:80 vulnerables/web-dvwa

# HackTheBox, TryHackMe 계정 생성
# PortSwigger Web Security Academy (무료, 최고의 교재)
```

### Step 3: 공개 프로그램으로 시작
처음에는 Hall of Fame만 있는 프로그램(보상 없음)부터 시작하세요. 실전 감각을 키우고 포트폴리오를 만들 수 있습니다.

### Step 4: 신고 및 평판 쌓기
- HackerOne 신호(Signal) 점수 올리기
- 명확하고 재현 가능한 리포트 작성
- 프라이빗 프로그램 초대 받기

### Step 5: 지속적인 학습
- Pentester Land (writeup 모음 사이트)
- HackerOne Hacktivity (공개된 리포트들)
- Twitter/X 해커 커뮤니티 팔로우

---

## 버그바운티 수익 구조 계산기

```python
#!/usr/bin/env python3
"""
버그바운티 예상 수익 계산기
Bug Bounty Expected Earnings Calculator
"""

from __future__ import annotations
from dataclasses import dataclass
from enum import Enum


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


@dataclass
class BountyRange:
    severity: Severity
    min_usd: int
    max_usd: int
    acceptance_rate: float  # 0.0 ~ 1.0

    @property
    def expected_value(self) -> float:
        """기대값 = 중간값 × 수락률"""
        midpoint = (self.min_usd + self.max_usd) / 2
        return midpoint * self.acceptance_rate


# 일반적인 중견 기업 기준 보상 테이블
BOUNTY_TABLE: dict[Severity, BountyRange] = {
    Severity.CRITICAL: BountyRange(Severity.CRITICAL, 3000, 15000, 0.70),
    Severity.HIGH:     BountyRange(Severity.HIGH,     800,  4000,  0.60),
    Severity.MEDIUM:   BountyRange(Severity.MEDIUM,   200,  1000,  0.55),
    Severity.LOW:      BountyRange(Severity.LOW,      50,   300,   0.40),
    Severity.INFORMATIONAL: BountyRange(Severity.INFORMATIONAL, 0, 0, 0.0),
}


def calculate_monthly_target(
    reports_per_month: int,
    severity_distribution: dict[Severity, float],
) -> dict[str, float]:
    """
    월간 예상 수익을 계산합니다.

    Args:
        reports_per_month: 월 평균 신고 건수
        severity_distribution: 심각도별 비율 (합계 1.0)

    Returns:
        월간 예상 수익 통계
    """
    total = sum(severity_distribution.values())
    if abs(total - 1.0) > 0.01:
        raise ValueError(f"심각도 비율의 합이 1.0이어야 합니다. 현재: {total}")

    monthly_earnings = 0.0
    breakdown: dict[str, float] = {}

    for severity, ratio in severity_distribution.items():
        bounty = BOUNTY_TABLE[severity]
        count = reports_per_month * ratio
        earnings = count * bounty.expected_value
        monthly_earnings += earnings
        breakdown[severity.value] = round(earnings, 2)

    breakdown["total_monthly_usd"] = round(monthly_earnings, 2)
    breakdown["annual_usd"] = round(monthly_earnings * 12, 2)
    return breakdown


def main() -> None:
    print("=" * 50)
    print("버그바운티 수익 시뮬레이터")
    print("=" * 50)

    # 초보자 시나리오: 월 5건 신고, 주로 Low/Medium
    beginner_dist = {
        Severity.CRITICAL: 0.05,
        Severity.HIGH: 0.10,
        Severity.MEDIUM: 0.40,
        Severity.LOW: 0.35,
        Severity.INFORMATIONAL: 0.10,
    }

    # 중급자 시나리오: 월 15건 신고
    intermediate_dist = {
        Severity.CRITICAL: 0.10,
        Severity.HIGH: 0.25,
        Severity.MEDIUM: 0.40,
        Severity.LOW: 0.20,
        Severity.INFORMATIONAL: 0.05,
    }

    for label, dist, count in [
        ("초보자 (월 5건)", beginner_dist, 5),
        ("중급자 (월 15건)", intermediate_dist, 15),
    ]:
        result = calculate_monthly_target(count, dist)
        print(f"\n[{label}]")
        for key, value in result.items():
            print(f"  {key:30s}: ${value:,.2f}")


if __name__ == "__main__":
    main()
```

---

<!-- safety-validate-73 -->
## 스코프·권한 검증 (테스트 시작 전)

버그바운티에서 가장 먼저 검증할 것은 취약점이 아니라 **"내가 지금 테스트해도 되는 대상·행위인가"**입니다. 스코프를 벗어난 테스트는 보상은커녕 법적 문제로 이어집니다.

| 확인 항목 | 왜 중요한가 | 검증 |
|---|---|---|
| In-scope 자산 | 범위 밖 도메인/IP 테스트는 무단 접근 | 프로그램 정책의 자산 목록과 대조 |
| 금지 행위 | DoS·소셜엔지니어링·자동 대량요청 흔히 금지 | 정책의 "Out of scope / Prohibited" 정독 |
| 세이프하버 | 선의의 연구 보호 조항 유무 | safe harbor 문구 확인, 없으면 보수적으로 |
| 데이터 취급 | 실제 사용자 데이터 접근·보관 금지 | PoC는 자기 계정/더미 데이터로만 |

### 테스트 전 확인 (직접)

```python
IN_SCOPE = {"app.example.com", "api.example.com"}

def is_testable(host: str) -> bool:
    """대상이 명시적 in-scope일 때만 테스트 허용. 모호하면 False."""
    return host in IN_SCOPE  # 와일드카드는 정책 문구를 직접 확인 후에만 확장

# 운영 원칙: 모호하면 테스트하지 말고 프로그램에 먼저 문의한다.
```

> 핵심: 스코프와 권한 검증은 한 줄짜리 형식 절차가 아니라 **모든 테스트의 전제 조건**입니다. 범위 밖이거나 금지 행위면, 취약점을 찾았더라도 보고가 아니라 사고가 됩니다([[68_Purple_Team]]).

---

## 참고 링크

- HackerOne 공개 프로그램 목록: https://www.hackerone.com/bug-bounty-programs
- Bugcrowd 프로그램 검색: https://bugcrowd.com/programs
- PortSwigger Web Security Academy (무료 교육): https://portswigger.net/web-security

---

<a name="english"></a>

# Bug Bounty Fundamentals: The Legal Way to Get Paid for Hacking

## What Is Bug Bounty?

A bug bounty program is a public invitation from a company to external security researchers: "Find vulnerabilities in our systems and we will reward you." In plain terms, it is a contract that says "find bugs in our service and get paid."

The difference between trying to rob a bank and conducting an authorized security audit of that same bank is enormous. Bug bounty is the latter — you get to exercise your hacking skills under legal protection and receive compensation for your findings.

---

## Major Bug Bounty Platforms

### HackerOne
- World's largest bug bounty platform
- Clients include Uber, Twitter, GitHub, and the U.S. Department of Defense
- Distinguishes between Public programs and Private (invite-only) programs
- Over $300 million paid out cumulatively

### Bugcrowd
- Direct competitor to HackerOne
- Clients include Mastercard, Barclays, and Tesla
- Offers PTaaS (Penetration Testing as a Service) alongside bug bounties

### Intigriti
- Europe-focused platform
- Specializes in GDPR-related security
- Strong presence among European enterprise clients

### Self-Managed Programs
- Google Vulnerability Reward Program (VRP)
- Apple Security Bounty
- Microsoft Bug Bounty Program
- Meta Bug Bounty

---

## Responsible Disclosure

This is the single most important principle in bug bounty. Regardless of what you do, you must follow it.

### Core Principles

1. **Test only within the defined scope**: Only test domains/IPs listed in the program scope
2. **Report immediately upon discovery**: Do not exploit the vulnerability; report it right away
3. **Minimize data access**: Access only the minimum data needed to prove the vulnerability
4. **Maintain confidentiality**: Do not disclose to the public before the company patches it
5. **No system damage**: Never disrupt the service or delete data

### Examples of Prohibited Behavior
- Testing servers outside the defined scope
- Dumping real customer data via SQL Injection
- Disrupting services with a DoS attack
- Publicly disclosing a vulnerability before it is patched

---

## Understanding Scope

Scope defines the boundaries of what you are permitted to test.

### In-Scope (Testable)
```
*.example.com       # All subdomains
api.example.com     # API server
mobile.example.com  # Mobile web
```

### Out-of-Scope (Not Testable)
```
admin.example.com   # Admin panel (unless explicitly stated)
partner.example.com # Partner systems
third-party CDN     # External services
```

### Why Scope Matters
Finding a vulnerability outside the defined scope earns you nothing and may create legal issues. Always read the program policy carefully before testing.

---

## Severity Levels and Reward Ranges

### CVSS-Based Severity Classification

| Severity | CVSS Score | Example Vuln | Avg Reward |
|----------|-----------|--------------|------------|
| Critical | 9.0–10.0 | RCE, Admin SQLi | $5,000–$50,000+ |
| High | 7.0–8.9 | SSRF, XXE, Auth Bypass | $1,000–$10,000 |
| Medium | 4.0–6.9 | XSS, IDOR, Info Leak | $300–$2,000 |
| Low | 0.1–3.9 | Weak Crypto, Banner Leak | $50–$500 |
| Informational | None | Config Recommendations | No reward |

### Real-World Examples
- Google Chrome vulnerability: $30,000+
- Apple iCloud RCE: $50,000+
- HackerOne platform bug: $20,000+
- Facebook account takeover: $25,000+

---

## How Beginners Should Start

### Step 1: Build Foundational Knowledge
- Understand the OWASP Top 10
- Master the HTTP protocol
- Learn Burp Suite basics

### Step 2: Set Up a Practice Environment
```bash
# Install DVWA (Damn Vulnerable Web Application)
docker pull vulnerables/web-dvwa
docker run -d -p 80:80 vulnerables/web-dvwa

# Sign up for HackTheBox and TryHackMe
# PortSwigger Web Security Academy (free, best resource available)
```

### Step 3: Start with Public Programs
Begin with Hall of Fame-only programs (no monetary reward). This helps you build real-world experience and create a portfolio.

### Step 4: Submit Reports and Build Reputation
- Raise your HackerOne Signal score
- Write clear, reproducible reports
- Earn invitations to private programs

### Step 5: Keep Learning
- Pentester Land (writeup aggregator)
- HackerOne Hacktivity (disclosed reports)
- Follow the hacker community on Twitter/X

---

## Bug Bounty Earnings Calculator

```python
#!/usr/bin/env python3
"""
Bug Bounty Expected Earnings Calculator
"""

from __future__ import annotations
from dataclasses import dataclass
from enum import Enum


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


@dataclass
class BountyRange:
    severity: Severity
    min_usd: int
    max_usd: int
    acceptance_rate: float  # 0.0 to 1.0

    @property
    def expected_value(self) -> float:
        """Expected value = midpoint × acceptance rate"""
        midpoint = (self.min_usd + self.max_usd) / 2
        return midpoint * self.acceptance_rate


# Reward table for a typical mid-size company
BOUNTY_TABLE: dict[Severity, BountyRange] = {
    Severity.CRITICAL: BountyRange(Severity.CRITICAL, 3000, 15000, 0.70),
    Severity.HIGH:     BountyRange(Severity.HIGH,     800,  4000,  0.60),
    Severity.MEDIUM:   BountyRange(Severity.MEDIUM,   200,  1000,  0.55),
    Severity.LOW:      BountyRange(Severity.LOW,      50,   300,   0.40),
    Severity.INFORMATIONAL: BountyRange(Severity.INFORMATIONAL, 0, 0, 0.0),
}


def calculate_monthly_target(
    reports_per_month: int,
    severity_distribution: dict[Severity, float],
) -> dict[str, float]:
    """
    Calculate estimated monthly earnings.

    Args:
        reports_per_month: Average number of reports submitted per month
        severity_distribution: Ratio per severity level (must sum to 1.0)

    Returns:
        Monthly earnings statistics
    """
    total = sum(severity_distribution.values())
    if abs(total - 1.0) > 0.01:
        raise ValueError(f"Severity ratios must sum to 1.0. Got: {total}")

    monthly_earnings = 0.0
    breakdown: dict[str, float] = {}

    for severity, ratio in severity_distribution.items():
        bounty = BOUNTY_TABLE[severity]
        count = reports_per_month * ratio
        earnings = count * bounty.expected_value
        monthly_earnings += earnings
        breakdown[severity.value] = round(earnings, 2)

    breakdown["total_monthly_usd"] = round(monthly_earnings, 2)
    breakdown["annual_usd"] = round(monthly_earnings * 12, 2)
    return breakdown


def main() -> None:
    print("=" * 50)
    print("Bug Bounty Earnings Simulator")
    print("=" * 50)

    # Beginner scenario: 5 reports/month, mostly Low/Medium
    beginner_dist = {
        Severity.CRITICAL: 0.05,
        Severity.HIGH: 0.10,
        Severity.MEDIUM: 0.40,
        Severity.LOW: 0.35,
        Severity.INFORMATIONAL: 0.10,
    }

    # Intermediate scenario: 15 reports/month
    intermediate_dist = {
        Severity.CRITICAL: 0.10,
        Severity.HIGH: 0.25,
        Severity.MEDIUM: 0.40,
        Severity.LOW: 0.20,
        Severity.INFORMATIONAL: 0.05,
    }

    for label, dist, count in [
        ("Beginner (5 reports/month)", beginner_dist, 5),
        ("Intermediate (15 reports/month)", intermediate_dist, 15),
    ]:
        result = calculate_monthly_target(count, dist)
        print(f"\n[{label}]")
        for key, value in result.items():
            print(f"  {key:30s}: ${value:,.2f}")


if __name__ == "__main__":
    main()
```

---

## Reference Links

- HackerOne public programs: https://www.hackerone.com/bug-bounty-programs
- Bugcrowd program search: https://bugcrowd.com/programs
- PortSwigger Web Security Academy (free training): https://portswigger.net/web-security

## Scope and Authorization Validation (before testing)

The first thing to validate in bug bounty is not a vulnerability but **"am I allowed to test this asset/action right now?"** Out-of-scope testing leads to legal trouble, not rewards.

| Check | Why it matters | Validation |
|---|---|---|
| In-scope assets | Testing OOS domains/IPs is unauthorized access | Compare against the program's asset list |
| Prohibited actions | DoS, social engineering, mass automation often banned | Read the "Out of scope / Prohibited" policy |
| Safe harbor | Protection for good-faith research | Confirm safe-harbor language; if absent, be conservative |
| Data handling | Accessing/storing real user data is forbidden | PoC only with your own/dummy data |

### Pre-test check (do it yourself)

```python
IN_SCOPE = {"app.example.com", "api.example.com"}

def is_testable(host: str) -> bool:
    """Allow testing only for explicit in-scope hosts; if unsure, False."""
    return host in IN_SCOPE  # expand wildcards only after checking the policy text

# Operating rule: if unsure, do not test — ask the program first.
```

> Core: scope and authorization validation is not a one-line formality but **a precondition for every test**. Out of scope or prohibited means that even a real vulnerability becomes an incident, not a report (see [[68_Purple_Team]]).
