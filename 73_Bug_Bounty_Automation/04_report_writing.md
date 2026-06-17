> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 버그바운티 리포트 작성법: 돈을 받는 리포트 vs 거절당하는 리포트

## 리포트가 왜 이렇게 중요한가?

버그바운티에서 많은 초보자가 빠지는 함정이 있습니다. 실제로 취약점을 발견했음에도 불구하고 리포트가 엉망이어서 "Informative"(보상 없음) 또는 "N/A"(관련 없음)로 처리되는 경우입니다.

좋은 리포트는 다음 두 가지를 동시에 달성합니다:
1. **트라이아저(Triager)가 5분 안에 재현**할 수 있을 것
2. **영향도(Impact)가 명확하게 전달**될 것

---

## 버그바운티 리포트 필수 구조

### 1. 제목 (Title)
제목 하나만 봐도 "어디서, 어떤 버그가, 얼마나 심각한지"가 전달되어야 합니다.

| 나쁜 제목 | 좋은 제목 |
|-----------|-----------|
| XSS 발견 | Stored XSS in `/api/profile` `bio` field — allows session hijacking |
| SQL 인젝션 | SQL Injection in `/search?q=` parameter leaks all user records |
| IDOR 있음 | IDOR in `/api/orders/{id}` allows any user to access other users' order history |

### 2. 심각도 (Severity)
CVSS v3 점수를 직접 계산하거나, 플랫폼 기준에 따른 분류를 사용합니다.

**CVSS v3 계산 요소**
- **Attack Vector (AV)**: Network(N) > Adjacent(A) > Local(L) > Physical(P)
- **Attack Complexity (AC)**: Low(L) > High(H)
- **Privileges Required (PR)**: None(N) > Low(L) > High(H)
- **User Interaction (UI)**: None(N) > Required(R)
- **Scope (S)**: Changed(C) > Unchanged(U)
- **Confidentiality (C)**: High(H) > Low(L) > None(N)
- **Integrity (I)**: High(H) > Low(L) > None(N)
- **Availability (A)**: High(H) > Low(L) > None(N)

```
Stored XSS 예시: AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N → 5.4 (Medium)
RCE 예시:       AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H → 9.8 (Critical)
```

### 3. 취약점 설명 (Description)
- 취약점이 무엇인지 (기술적 설명)
- 어디에 있는지 (URL, 파라미터, 기능)
- 왜 발생하는지 (근본 원인)

### 4. 재현 단계 (Steps to Reproduce)
번호를 매겨 단계별로 작성. 트라이아저가 복사-붙여넣기로 재현할 수 있어야 합니다.

```
1. https://example.com/login에서 계정 A로 로그인
2. https://example.com/profile로 이동
3. Bio 필드에 다음을 입력: <img src=x onerror=alert(document.cookie)>
4. "저장" 클릭
5. 다른 브라우저에서 계정 B로 로그인
6. 계정 A의 프로필 페이지 방문
7. 계정 B의 쿠키가 팝업으로 표시됨 → XSS 확인
```

### 5. 개념 증명 (Proof of Concept, PoC)
- 스크린샷 (빨간 박스로 핵심 표시)
- Burp Suite HTTP 요청/응답 전문
- 영상 (민감한 영향을 보여줄 때 특히 효과적)
- 페이로드 코드

### 6. 영향 (Impact)
비즈니스 관점에서 실제 피해를 설명합니다.

나쁜 예: "XSS가 있습니다."
좋은 예: "인증된 공격자가 다른 사용자의 세션 쿠키를 탈취하여 해당 계정을 완전히 장악할 수 있습니다. 결제 정보, 개인정보, 이메일 주소가 노출될 수 있습니다."

### 7. 수정 권고 (Remediation)
어떻게 고쳐야 하는지 구체적으로 제안합니다.

---

## 좋은 PoC vs 나쁜 PoC 비교

### 나쁜 PoC 예시
```
URL: https://example.com/search?q=test'
결과: 에러 발생
```

### 좋은 PoC 예시
```http
GET /search?q=test'%20AND%201=1--%20- HTTP/1.1
Host: example.com
Cookie: session=abc123
User-Agent: Mozilla/5.0

---
HTTP/1.1 200 OK
Content-Type: text/html

<html>...10개의 사용자 레코드 노출...</html>
```

```
페이로드: test' AND 1=1-- -
설명: 싱글 쿼트로 SQL 문자열을 이탈하고, AND 1=1로 조건을 항상 참으로 만들어 
     모든 레코드를 반환하도록 합니다. -- -는 SQL 주석으로 이후 쿼리를 무효화합니다.
재현 횟수: 5회 모두 동일한 결과 확인
```

---

## 트라이아지(Triage) 과정 이해

트라이아지는 플랫폼 또는 기업의 보안 팀이 신고된 취약점을 검토하는 과정입니다.

### 일반적인 타임라인
```
D+0:  리포트 제출
D+1:  자동 확인 이메일
D+3:  트라이아저 초기 검토 (New → Triaged 또는 N/A)
D+7:  기술 팀 검토
D+30: 패치 개발
D+60: 패치 배포
D+90: 취약점 공개 (합의 시)
```

### 트라이아저와 소통하는 법
- 추가 정보 요청 시 24시간 내에 응답
- 공격적이거나 조급한 태도 금지
- "언제 답변 주실 건가요?" 반복 금지
- 유용한 추가 정보 발견 시 즉시 공유

---

## Markdown 리포트 자동 생성 Python 코드

```python
#!/usr/bin/env python3
"""
report_generator.py — 버그바운티 리포트 자동 생성기

사용법:
    python report_generator.py --interactive
    python report_generator.py -t template.json -o report.md
    python report_generator.py --template-list
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from pathlib import Path


class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFORMATIONAL = "Informational"


class VulnType(str, Enum):
    XSS = "Cross-Site Scripting (XSS)"
    SQLI = "SQL Injection"
    SSRF = "Server-Side Request Forgery (SSRF)"
    RCE = "Remote Code Execution (RCE)"
    IDOR = "Insecure Direct Object Reference (IDOR)"
    XXE = "XML External Entity (XXE)"
    OPEN_REDIRECT = "Open Redirect"
    AUTH_BYPASS = "Authentication Bypass"
    INFO_DISCLOSURE = "Information Disclosure"
    CSRF = "Cross-Site Request Forgery (CSRF)"
    CUSTOM = "Custom"


@dataclass
class CvssVector:
    """CVSS v3.1 벡터 컴포넌트"""
    attack_vector: str = "N"         # N/A/L/P
    attack_complexity: str = "L"     # L/H
    privileges_required: str = "N"   # N/L/H
    user_interaction: str = "N"      # N/R
    scope: str = "U"                 # U/C
    confidentiality: str = "N"       # N/L/H
    integrity: str = "N"             # N/L/H
    availability: str = "N"          # N/L/H

    def to_vector_string(self) -> str:
        return (
            f"CVSS:3.1/AV:{self.attack_vector}/AC:{self.attack_complexity}"
            f"/PR:{self.privileges_required}/UI:{self.user_interaction}"
            f"/S:{self.scope}/C:{self.confidentiality}"
            f"/I:{self.integrity}/A:{self.availability}"
        )

    def estimate_score(self) -> float:
        """
        간단한 CVSS 점수 추정 (실제 계산과 오차가 있을 수 있습니다).
        정확한 점수는 https://www.first.org/cvss/calculator/3.1 에서 계산하세요.
        """
        score = 0.0

        # Attack Vector
        av_scores = {"N": 3.0, "A": 2.0, "L": 1.0, "P": 0.5}
        score += av_scores.get(self.attack_vector, 0)

        # Scope Change 보너스
        if self.scope == "C":
            score += 1.5

        # Impact (CIA)
        impact_scores = {"H": 2.0, "L": 1.0, "N": 0.0}
        for component in [self.confidentiality, self.integrity, self.availability]:
            score += impact_scores.get(component, 0)

        # 정규화 (0-10)
        score = min(score / 1.05, 10.0)

        # Privileges Required에 따른 감점
        pr_penalties = {"N": 0, "L": 0.5, "H": 1.5}
        score -= pr_penalties.get(self.privileges_required, 0)

        # User Interaction 감점
        if self.user_interaction == "R":
            score -= 0.5

        return round(max(0.0, min(10.0, score)), 1)


@dataclass
class ReproductionStep:
    step_number: int
    description: str
    expected_result: str = ""


@dataclass
class BugReport:
    # 기본 정보
    title: str = ""
    severity: Severity = Severity.MEDIUM
    vuln_type: VulnType = VulnType.CUSTOM
    cvss: CvssVector = field(default_factory=CvssVector)

    # 취약점 정보
    affected_url: str = ""
    affected_parameter: str = ""
    description: str = ""
    root_cause: str = ""

    # 재현
    steps: list[ReproductionStep] = field(default_factory=list)
    payload: str = ""
    http_request: str = ""
    http_response: str = ""

    # 영향 및 수정
    impact: str = ""
    remediation: str = ""

    # 메타데이터
    created_at: str = field(default_factory=lambda: datetime.now().strftime("%Y-%m-%d"))

    def to_markdown(self) -> str:
        """리포트를 Markdown 형식으로 변환합니다."""
        cvss_vector = self.cvss.to_vector_string()
        estimated_score = self.cvss.estimate_score()

        severity_badge = {
            Severity.CRITICAL: "🔴",
            Severity.HIGH: "🟠",
            Severity.MEDIUM: "🟡",
            Severity.LOW: "🔵",
            Severity.INFORMATIONAL: "⚪",
        }.get(self.severity, "⚪")

        lines = [
            f"# {self.title}",
            "",
            f"**날짜**: {self.created_at}",
            f"**심각도**: {severity_badge} **{self.severity.value}**",
            f"**취약점 유형**: {self.vuln_type.value}",
            f"**CVSS v3.1**: `{cvss_vector}` (추정 점수: {estimated_score}/10.0)",
            "",
            "---",
            "",
            "## 취약점 설명",
            "",
            self.description or "_설명을 입력하세요._",
            "",
            f"**영향받는 URL**: `{self.affected_url}`",
            f"**영향받는 파라미터**: `{self.affected_parameter}`",
            "",
            "**근본 원인**:",
            self.root_cause or "_근본 원인을 설명하세요._",
            "",
            "---",
            "",
            "## 재현 단계",
            "",
        ]

        for step in self.steps:
            lines.append(f"{step.step_number}. {step.description}")
            if step.expected_result:
                lines.append(f"   - 예상 결과: {step.expected_result}")

        if not self.steps:
            lines.append("_재현 단계를 추가하세요._")

        lines += [
            "",
            "---",
            "",
            "## Proof of Concept",
            "",
        ]

        if self.payload:
            lines += [
                "**페이로드**:",
                "```",
                self.payload,
                "```",
                "",
            ]

        if self.http_request:
            lines += [
                "**HTTP 요청**:",
                "```http",
                self.http_request,
                "```",
                "",
            ]

        if self.http_response:
            lines += [
                "**HTTP 응답 (관련 부분)**:",
                "```http",
                self.http_response,
                "```",
                "",
            ]

        lines += [
            "---",
            "",
            "## 영향 (Impact)",
            "",
            self.impact or "_영향을 비즈니스 관점에서 설명하세요._",
            "",
            "---",
            "",
            "## 수정 권고 (Remediation)",
            "",
            self.remediation or "_수정 방법을 구체적으로 제안하세요._",
            "",
        ]

        return "\n".join(lines)

    def to_json(self) -> str:
        """리포트를 JSON 형식으로 직렬화합니다."""
        data = asdict(self)
        data["severity"] = self.severity.value
        data["vuln_type"] = self.vuln_type.value
        return json.dumps(data, indent=2, ensure_ascii=False)


def interactive_mode() -> BugReport:
    """대화형으로 리포트를 작성합니다."""
    print("=" * 60)
    print("버그바운티 리포트 생성기 (대화형 모드)")
    print("=" * 60)

    report = BugReport()

    report.title = input("\n취약점 제목 (예: IDOR in /api/users/): ").strip()
    report.affected_url = input("영향받는 URL: ").strip()
    report.affected_parameter = input("영향받는 파라미터/필드: ").strip()

    print("\n심각도 선택:")
    for i, sev in enumerate(Severity, 1):
        print(f"  {i}. {sev.value}")
    sev_choices = list(Severity)
    try:
        choice = int(input("선택 (1-5): ").strip()) - 1
        report.severity = sev_choices[choice]
    except (ValueError, IndexError):
        report.severity = Severity.MEDIUM

    report.description = input("\n취약점 설명 (간략히): ").strip()
    report.impact = input("영향 (비즈니스 관점): ").strip()
    report.remediation = input("수정 권고: ").strip()

    # 재현 단계
    print("\n재현 단계 입력 (빈 줄 입력 시 종료):")
    step_num = 1
    while True:
        desc = input(f"  단계 {step_num}: ").strip()
        if not desc:
            break
        report.steps.append(ReproductionStep(step_number=step_num, description=desc))
        step_num += 1

    return report


def main() -> None:
    parser = argparse.ArgumentParser(description="버그바운티 리포트 자동 생성기")
    parser.add_argument("--interactive", action="store_true", help="대화형 모드로 실행")
    parser.add_argument("-t", "--template", help="JSON 템플릿 파일 입력")
    parser.add_argument("-o", "--output", default="report.md", help="출력 파일 (기본: report.md)")
    parser.add_argument("--json", action="store_true", help="JSON 형식으로도 저장")
    args = parser.parse_args()

    if args.interactive:
        report = interactive_mode()
    elif args.template:
        template_path = Path(args.template)
        if not template_path.exists():
            print(f"오류: 템플릿 파일 없음: {template_path}")
            sys.exit(1)
        # 간단한 예시 로드
        data = json.loads(template_path.read_text(encoding="utf-8"))
        report = BugReport(**data)
    else:
        # 예시 리포트 생성
        report = BugReport(
            title="IDOR in /api/orders/{id} — Any user can access other users' orders",
            severity=Severity.HIGH,
            vuln_type=VulnType.IDOR,
            affected_url="https://example.com/api/orders/12345",
            affected_parameter="id (path parameter)",
            description="The order detail endpoint does not verify that the requesting "
                        "user owns the order. By changing the numeric `id` in the URL, "
                        "any authenticated user can read any other user's order history.",
            root_cause="Missing authorization check: the server queries the database "
                       "with only the order ID, without verifying ownership against "
                       "the session user.",
            steps=[
                ReproductionStep(1, "Log in as User A (user_a@example.com)"),
                ReproductionStep(2, "Place an order and note the order ID (e.g., 12345)"),
                ReproductionStep(3, "Log out and log in as User B"),
                ReproductionStep(
                    4,
                    "Visit GET /api/orders/12345",
                    expected_result="User A's full order details are returned to User B",
                ),
            ],
            payload="GET /api/orders/12345 HTTP/1.1\nCookie: session=<User B session>",
            impact="Any authenticated user can enumerate and read all other users' "
                   "order history, including shipping addresses, item details, and "
                   "pricing information. This constitutes a significant privacy breach.",
            remediation="Add an authorization check: verify that `orders.user_id == "
                        "request.session.user_id` before returning order data. "
                        "Return HTTP 403 if the check fails.",
        )

    # Markdown 저장
    output_path = Path(args.output)
    output_path.write_text(report.to_markdown(), encoding="utf-8")
    print(f"리포트 저장 완료: {output_path.absolute()}")

    # JSON 저장 (옵션)
    if args.json:
        json_path = output_path.with_suffix(".json")
        json_path.write_text(report.to_json(), encoding="utf-8")
        print(f"JSON 저장 완료: {json_path.absolute()}")

    # CVSS 정보 출력
    print(f"\nCVSS 추정 점수: {report.cvss.estimate_score()}/10.0")
    print(f"CVSS 벡터: {report.cvss.to_vector_string()}")


if __name__ == "__main__":
    main()
```

---

<!-- safety-validate-73 -->
## 재현성·최소영향 PoC 검증

좋은 보고서의 핵심은 화려한 설명이 아니라 **재현 가능성**과 **최소 영향 증명**입니다. 실제 피해를 내지 않고도 영향을 입증할 수 있어야 합니다.

| 항목 | 나쁜 예 | 좋은 예(검증된) |
|---|---|---|
| 재현 단계 | "취약함" 한 줄 | 누구나 따라 하면 재현되는 정확한 단계 |
| PoC 영향 | 실제 사용자 데이터 덤프 | 자기 계정/더미로 개념 증명 후 중단 |
| 민감정보 | 실제 토큰·PII 그대로 첨부 | 마스킹/디팽, 최소 증거만 |
| 범위 | 권한 넘어 추가 침투 | 증명 시점에서 멈추고 보고 |

### 보고 전 검증 (직접)

```text
제출 전 셀프체크:
  □ 깨끗한 환경에서 단계를 그대로 따라 재현되는가?
  □ PoC가 '증명'에서 멈췄는가? (실데이터 탈취/파괴 없음)
  □ 스크린샷/로그에 실제 PII·토큰이 노출되지 않았는가?
  □ 영향(impact)을 과장 없이 사실대로 기술했는가?
```

> 핵심: PoC는 **"할 수 있음을 증명"하는 것이지 "실제로 피해를 입히는 것"이 아닙니다.** 자기 계정·더미 데이터로 멈추고, 증거에서 민감정보를 제거하세요. 재현 가능하고 최소 영향인 보고가 가장 빨리 인정받습니다([[68_Purple_Team]]).

---

## 참고 링크

- HackerOne 리포트 작성 가이드: https://docs.hackerone.com/hackers/submitting-reports.html
- CVSS v3.1 계산기: https://www.first.org/cvss/calculator/3.1

---

<a name="english"></a>

# Bug Bounty Report Writing: Reports That Get Paid vs Reports That Get Rejected

## Why Does the Report Matter So Much?

Many beginners fall into a trap: they find a real vulnerability but receive "Informative" (no reward) or "N/A" because the report is poorly written.

A good report achieves two things simultaneously:
1. **A triager can reproduce it in under 5 minutes**
2. **The impact is communicated clearly**

---

## Required Report Structure

### 1. Title
The title alone should convey "where, what bug, how severe."

| Bad Title | Good Title |
|-----------|------------|
| Found XSS | Stored XSS in `/api/profile` `bio` field — allows session hijacking |
| SQL injection | SQL Injection in `/search?q=` parameter leaks all user records |
| IDOR issue | IDOR in `/api/orders/{id}` — any user can read others' order history |

### 2. Severity
Calculate a CVSS v3 score or use the platform's classification system.

**CVSS v3 Components**
- **Attack Vector (AV)**: Network(N) > Adjacent(A) > Local(L) > Physical(P)
- **Attack Complexity (AC)**: Low(L) > High(H)
- **Privileges Required (PR)**: None(N) > Low(L) > High(H)
- **User Interaction (UI)**: None(N) > Required(R)
- **Scope (S)**: Changed(C) > Unchanged(U)
- **Confidentiality/Integrity/Availability**: High(H) > Low(L) > None(N)

### 3. Description
- What the vulnerability is (technical explanation)
- Where it exists (URL, parameter, feature)
- Why it exists (root cause)

### 4. Steps to Reproduce
Numbered steps. The triager must be able to copy-paste and reproduce.

```
1. Log in at https://example.com/login with Account A
2. Navigate to https://example.com/profile
3. Enter in the Bio field: <img src=x onerror=alert(document.cookie)>
4. Click Save
5. Open a separate browser and log in as Account B
6. Visit Account A's profile page
7. Account B's cookie is displayed in a popup → XSS confirmed
```

### 5. Proof of Concept
- Screenshots (highlight key areas with a red box)
- Full Burp Suite HTTP request and response
- Video (especially effective for complex impact demonstrations)
- Payload code

### 6. Impact
Describe the real business harm.

Poor: "There is an XSS."
Good: "An authenticated attacker can steal any other user's session cookie and fully take over their account. Payment information, personal data, and email addresses are exposed."

### 7. Remediation
Provide specific, actionable fix recommendations.

---

## Good PoC vs Bad PoC

### Bad PoC
```
URL: https://example.com/search?q=test'
Result: Error occurred
```

### Good PoC
```http
GET /search?q=test'%20AND%201=1--%20- HTTP/1.1
Host: example.com
Cookie: session=abc123

---
HTTP/1.1 200 OK
Content-Type: text/html

<html>...10 user records exposed in response...</html>
```

```
Payload: test' AND 1=1-- -
Explanation: The single quote breaks out of the SQL string context.
             AND 1=1 makes the WHERE clause always true, returning all records.
             -- - comments out the rest of the query.
Reproduced: 5 out of 5 attempts yielded the same result.
```

---

## Understanding the Triage Process

Triage is the process by which the platform or company's security team reviews a submitted report.

### Typical Timeline
```
D+0:   Report submitted
D+1:   Automated acknowledgment email
D+3:   Triager initial review (New → Triaged or N/A)
D+7:   Engineering team review
D+30:  Patch development
D+60:  Patch deployed
D+90:  Vulnerability disclosure (with mutual agreement)
```

### Communicating with Triagers
- Respond to information requests within 24 hours
- Never be aggressive or impatient
- Do not repeatedly ask "when will you respond?"
- Share useful additional findings immediately

---

## Report Generator Usage

The full Python `report_generator.py` script from the Korean section works in English as well. Run it as follows:

```bash
# Interactive mode — step-by-step prompts
python report_generator.py --interactive -o my_report.md

# Generate an example report and save JSON alongside
python report_generator.py -o example_report.md --json

# Load from a JSON template
python report_generator.py -t my_template.json -o report.md
```

The script supports:
- All major vulnerability types via `VulnType` enum
- CVSS v3.1 vector string generation and score estimation
- Numbered step-by-step reproduction instructions
- Full HTTP request/response PoC embedding
- Markdown output ready to paste into HackerOne or Bugcrowd

---

## Reference Links

- HackerOne report submission guide: https://docs.hackerone.com/hackers/submitting-reports.html
- CVSS v3.1 calculator: https://www.first.org/cvss/calculator/3.1

## Reproducibility and Minimal-Impact PoC Validation

The heart of a good report is not flashy prose but **reproducibility** and **minimal-impact proof**. You should be able to demonstrate impact without causing real harm.

| Item | Bad | Good (validated) |
|---|---|---|
| Repro steps | "It's vulnerable" one-liner | Exact steps anyone can follow to reproduce |
| PoC impact | Dumping real user data | Prove the concept with your own/dummy data, then stop |
| Sensitive info | Attaching real tokens/PII as-is | Mask/defang, minimal evidence only |
| Scope | Pivoting beyond authorization | Stop at proof and report |

### Pre-report validation (do it yourself)

```text
Pre-submission self-check:
  [ ] Do the steps reproduce as written in a clean environment?
  [ ] Did the PoC stop at 'proof'? (no real-data theft/destruction)
  [ ] Do screenshots/logs avoid exposing real PII/tokens?
  [ ] Is impact stated truthfully without exaggeration?
```

> Core: a PoC **proves you can, it does not actually cause harm.** Stop at your own account/dummy data and strip sensitive info from evidence. Reproducible, minimal-impact reports get accepted fastest (see [[68_Purple_Team]]).
