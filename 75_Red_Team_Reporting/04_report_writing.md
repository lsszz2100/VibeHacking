> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 레드팀 보고서 작성

## 보고서는 왜 중요한가?

레드팀 작전의 모든 기술적 성과는 보고서에 담기지 않으면 의미가 없습니다. 아무리 탁월한 침투 경로를 발견했더라도, 경영진이 이해하지 못하거나 기술팀이 재현하지 못한다면 아무런 보안 개선도 일어나지 않습니다.

좋은 레드팀 보고서는 두 가지 독자를 동시에 만족시켜야 합니다:

```
독자 A — 경영진 (CISO, CEO, 이사회)
  원하는 정보: 우리가 얼마나 위험한가? 무엇부터 고쳐야 하는가?
  읽는 분량: 2~3페이지 (경영진 요약)
  
독자 B — 기술팀 (개발자, 시스템 관리자, SOC 분석가)
  원하는 정보: 정확히 어떤 취약점이 있고, 어떻게 수정하는가?
  읽는 분량: 전체 기술 세부사항 (수십 ~ 수백 페이지)
```

---

## 레드팀 보고서 구조

### 표준 보고서 구성

```
1. 표지 (Cover Page)
   - 작전명, 날짜, 기밀등급, 버전

2. 경영진 요약 (Executive Summary) ← 가장 중요!
   - 목적, 범위, 핵심 발견사항 (3~5개), 전체 위험 수준

3. 작전 개요 (Operation Overview)
   - 교전 규칙(RoE), 타임라인, 팀 구성

4. 발견사항 (Findings)
   - Critical / High / Medium / Low 분류
   - 각 발견사항: 제목, 위험도, 설명, 증거, 권고사항

5. 공격 내러티브 (Attack Narrative)
   - 처음부터 끝까지 스토리 형식으로 서술

6. TTP 매핑 (MITRE ATT&CK)
   - 사용된 기법 매트릭스

7. 수정 권고사항 (Remediation Recommendations)
   - 우선순위별 수정 로드맵

8. 결론 (Conclusion)

9. 부록 (Appendix)
   - 도구 목록, 스크린샷, 로그 증거
```

---

## 경영진 요약 작성 요령

경영진 요약은 기술 용어를 최소화하고 비즈니스 언어로 작성합니다.

### 나쁜 예시 vs 좋은 예시

```
나쁜 예시:
"SQL Injection 취약점을 이용하여 UNION 기반 공격으로 
users 테이블의 password_hash 컬럼을 추출하였음."

좋은 예시:
"온라인 쇼핑몰 로그인 페이지의 취약점을 통해 
15만 명의 고객 계정 정보에 접근할 수 있었습니다.
이는 개인정보보호법 위반으로 최대 3억 원의 과태료 대상이 됩니다."
```

---

## 위험도 평가 방법

위험도는 **가능성(Likelihood) × 영향(Impact)**으로 산정합니다.

### CVSS v3.1 기반 점수화

| 점수 | 등급 | 의미 |
|---|---|---|
| 9.0 ~ 10.0 | Critical | 즉각적 패치 필요 (24시간 이내) |
| 7.0 ~ 8.9 | High | 빠른 패치 필요 (1주일 이내) |
| 4.0 ~ 6.9 | Medium | 계획적 패치 (1개월 이내) |
| 0.1 ~ 3.9 | Low | 위험 수용 또는 완화 조치 |

### 내부 위험 매트릭스

```
영향(Impact)
높음 │  Medium │  High  │ Critical
보통 │  Low    │ Medium │  High
낮음 │  Low    │  Low   │ Medium
     └─────────┴────────┴─────────
         낮음      보통      높음
                        가능성(Likelihood)
```

---

## 발견사항 분류 및 작성 양식

각 발견사항은 다음 양식으로 작성합니다:

```markdown
## F-001: 도메인 관리자 권한 탈취 가능

**위험도**: Critical (CVSS: 9.8)
**발견일**: 2024-01-09
**영향 받는 시스템**: DC01.corp.example.com

### 설명
레드팀은 재무팀 직원의 이메일을 통해 악성 매크로를 
실행시킨 후, Mimikatz를 이용해 도메인 관리자 계정의 
NTLM 해시를 추출했습니다. 이를 통해 도메인 전체를 
완전히 제어할 수 있었습니다.

### 공격 경로
피싱 이메일 → 매크로 실행 → PowerShell C2 → 
LSASS 덤프 → 도메인 관리자 해시 → DC 접근

### 증거
[스크린샷 1] LSASS 메모리 덤프 성공
[스크린샷 2] DC01 관리자 세션 확립

### 수정 권고사항
1. (즉시) LSASS 프로세스에 Protected Process Light(PPL) 적용
2. (1주) 도메인 관리자 계정에 MFA 적용
3. (1개월) 특권 접근 워크스테이션(PAW) 도입
```

---

## Python Markdown 보고서 자동 생성기

```python
#!/usr/bin/env python3
"""
레드팀 보고서 자동 생성기
사용법: python3 04_report_writing.py --name "Operation X" --add-finding
"""

import argparse
import sys
from dataclasses import dataclass, field
from datetime import date
from enum import Enum
from typing import List


class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFORMATIONAL = "Informational"

    def emoji(self) -> str:
        return {
            "Critical": "🔴",
            "High": "🟠",
            "Medium": "🟡",
            "Low": "🟢",
            "Informational": "⚪",
        }[self.value]

    def cvss_range(self) -> str:
        return {
            "Critical": "9.0–10.0",
            "High": "7.0–8.9",
            "Medium": "4.0–6.9",
            "Low": "0.1–3.9",
            "Informational": "0.0",
        }[self.value]


@dataclass
class Finding:
    finding_id: str
    title: str
    severity: Severity
    cvss_score: float
    affected_system: str
    description: str
    attack_path: str
    recommendation: str
    found_date: date = field(default_factory=date.today)

    def validate(self) -> None:
        if not 0.0 <= self.cvss_score <= 10.0:
            raise ValueError(f"CVSS 점수는 0.0~10.0이어야 합니다. 입력값: {self.cvss_score}")
        if not self.title.strip():
            raise ValueError("발견사항 제목이 비어 있습니다.")

    def to_markdown(self) -> str:
        return (
            f"## {self.finding_id}: {self.title}\n\n"
            f"**위험도**: {self.severity.emoji()} {self.severity.value} "
            f"(CVSS: {self.cvss_score:.1f})\n"
            f"**발견일**: {self.found_date}\n"
            f"**영향 시스템**: `{self.affected_system}`\n\n"
            f"### 설명\n{self.description}\n\n"
            f"### 공격 경로\n```\n{self.attack_path}\n```\n\n"
            f"### 수정 권고사항\n{self.recommendation}\n\n"
            f"---"
        )


@dataclass
class RedTeamReport:
    operation_name: str
    client_name: str
    report_date: date
    scope: str
    findings: List[Finding] = field(default_factory=list)

    def add_finding(self, finding: Finding) -> None:
        finding.validate()
        self.findings.append(finding)

    def risk_summary(self) -> dict:
        summary: dict = {s: 0 for s in Severity}
        for f in self.findings:
            summary[f.severity] += 1
        return summary

    def executive_summary(self) -> str:
        total = len(self.findings)
        summary = self.risk_summary()
        critical = summary[Severity.CRITICAL]
        high = summary[Severity.HIGH]
        risk_level = "매우 높음" if critical > 0 else ("높음" if high > 0 else "중간")
        return (
            f"## 경영진 요약\n\n"
            f"레드팀은 **{self.scope}**을(를) 대상으로 작전을 수행하였습니다.\n"
            f"총 **{total}개**의 보안 취약점이 발견되었으며, "
            f"전체 보안 위험 수준은 **{risk_level}**으로 평가됩니다.\n\n"
            f"| 위험도 | 건수 |\n|---|---|\n"
            + "\n".join(f"| {s.emoji()} {s.value} | {summary[s]} |" for s in Severity)
            + f"\n\n> **중요**: Critical 취약점 {critical}건은 즉각적인 조치가 필요합니다."
        )

    def to_markdown(self) -> str:
        sorted_findings = sorted(
            self.findings,
            key=lambda f: list(Severity).index(f.severity),
        )
        parts = [
            f"# 레드팀 침투 테스트 보고서",
            f"",
            f"| 항목 | 내용 |",
            f"|---|---|",
            f"| 작전명 | {self.operation_name} |",
            f"| 고객사 | {self.client_name} |",
            f"| 보고일 | {self.report_date} |",
            f"| 범위 | {self.scope} |",
            f"",
            f"---",
            f"",
            self.executive_summary(),
            f"",
            f"---",
            f"",
            f"# 발견사항 상세",
            f"",
        ]
        for finding in sorted_findings:
            parts.append(finding.to_markdown())
            parts.append("")
        return "\n".join(parts)


def prompt_finding(finding_number: int) -> Finding:
    """대화형 발견사항 입력"""
    print(f"\n--- 발견사항 {finding_number} 입력 ---")
    finding_id = f"F-{finding_number:03d}"
    title = input("제목: ").strip()
    print("위험도 선택: 1=Critical, 2=High, 3=Medium, 4=Low, 5=Informational")
    severity_choice = input("선택 (1-5): ").strip()
    severity_map = {"1": Severity.CRITICAL, "2": Severity.HIGH, "3": Severity.MEDIUM,
                    "4": Severity.LOW, "5": Severity.INFORMATIONAL}
    severity = severity_map.get(severity_choice, Severity.MEDIUM)

    try:
        cvss = float(input("CVSS 점수 (0.0~10.0): ").strip())
    except ValueError:
        cvss = 5.0

    affected = input("영향 받는 시스템: ").strip()
    description = input("설명 (한 줄): ").strip()
    attack_path = input("공격 경로 (→ 로 구분): ").strip()
    recommendation = input("수정 권고사항: ").strip()

    return Finding(
        finding_id=finding_id,
        title=title,
        severity=severity,
        cvss_score=cvss,
        affected_system=affected,
        description=description,
        attack_path=attack_path,
        recommendation=recommendation,
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="레드팀 보고서 자동 생성기",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "예시:\n"
            "  python3 04_report_writing.py --name 'Op Storm' --client 'ABC Corp' --scope '내부망 전체' --add-finding\n"
            "  python3 04_report_writing.py --demo --output report.md"
        ),
    )
    parser.add_argument("--name", default="Red Team Operation", help="작전 이름")
    parser.add_argument("--client", default="고객사", help="고객사 이름")
    parser.add_argument("--scope", default="전체 내부망", help="작전 범위")
    parser.add_argument("--add-finding", action="store_true", help="대화형으로 발견사항 입력")
    parser.add_argument("--demo", action="store_true", help="샘플 발견사항으로 데모 보고서 생성")
    parser.add_argument("--output", help="출력 파일 경로 (미지정 시 stdout)")
    return parser.parse_args()


def create_demo_report(operation_name: str, client: str, scope: str) -> RedTeamReport:
    """데모용 샘플 보고서 생성"""
    report = RedTeamReport(
        operation_name=operation_name,
        client_name=client,
        report_date=date.today(),
        scope=scope,
    )
    report.add_finding(Finding(
        finding_id="F-001",
        title="도메인 관리자 권한 탈취",
        severity=Severity.CRITICAL,
        cvss_score=9.8,
        affected_system="DC01.corp.example.com",
        description="Mimikatz를 통한 LSASS 덤프로 도메인 관리자 해시 추출 성공",
        attack_path="피싱 → 매크로 실행 → PowerShell C2 → LSASS 덤프 → DC 접근",
        recommendation="1. PPL 즉시 적용\n2. 도메인 관리자 MFA 도입\n3. PAW 워크스테이션 구축",
    ))
    report.add_finding(Finding(
        finding_id="F-002",
        title="VPN 서버 인증 우회",
        severity=Severity.HIGH,
        cvss_score=8.1,
        affected_system="vpn.example.com",
        description="CVE-2024-XXXX 취약점으로 VPN 인증 없이 내부망 접근 가능",
        attack_path="공개 인터넷 → VPN 취약점 악용 → 내부망 접근",
        recommendation="VPN 소프트웨어 즉시 업데이트",
    ))
    report.add_finding(Finding(
        finding_id="F-003",
        title="기본 계정 비밀번호 사용",
        severity=Severity.MEDIUM,
        cvss_score=5.3,
        affected_system="192.168.1.50 (프린터 서버)",
        description="네트워크 프린터 관리 페이지가 기본 계정(admin/admin)으로 접근 가능",
        attack_path="내부망 → 프린터 웹 인터페이스 → 기본 계정 로그인",
        recommendation="기본 비밀번호 즉시 변경 및 관리자 계정 감사",
    ))
    return report


def main() -> None:
    args = parse_args()

    if args.demo:
        report = create_demo_report(args.name, args.client, args.scope)
    elif args.add_finding:
        report = RedTeamReport(
            operation_name=args.name,
            client_name=args.client,
            report_date=date.today(),
            scope=args.scope,
        )
        finding_num = 1
        while True:
            try:
                finding = prompt_finding(finding_num)
                report.add_finding(finding)
                finding_num += 1
            except ValueError as e:
                print(f"입력 오류: {e}", file=sys.stderr)
                continue
            if input("\n발견사항 추가? (y/N): ").strip().lower() != "y":
                break
    else:
        print("--demo 또는 --add-finding 옵션을 사용하세요.", file=sys.stderr)
        sys.exit(1)

    markdown = report.to_markdown()

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(markdown)
            print(f"보고서가 저장되었습니다: {args.output}")
        except OSError as e:
            print(f"파일 저장 오류: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        print(markdown)


if __name__ == "__main__":
    main()
```

### 사용 예시

```bash
# 데모 보고서 생성
python3 04_report_writing.py --demo --client "ABC Corp" --output report.md

# 대화형으로 발견사항 입력
python3 04_report_writing.py --name "Operation Storm" --client "XYZ Ltd" --add-finding
```

---

## 보고서 작성 황금 법칙

1. **증거 없으면 발견사항 없음**: 모든 발견사항에 스크린샷, 로그, 파일이 첨부되어야 합니다.
2. **재현 가능해야 함**: 기술 세부사항은 다른 사람이 똑같이 재현할 수 있어야 합니다.
3. **수정 가능해야 함**: 모든 발견사항에는 실행 가능한 수정 권고사항이 포함되어야 합니다.
4. **독자를 고려하라**: 경영진 요약은 비즈니스 언어로, 기술 세부사항은 기술 언어로.
5. **우선순위를 명확히**: Critical부터 수정해야 한다는 것을 명확히 전달합니다.

**참고 자료**: [Red Team Guide](https://redteam.guide/)

---

<!-- safety-validate-75 -->
## 민감정보 취급과 보고서 보안

레드팀 보고서는 그 자체가 **조직의 가장 위험한 문서**입니다 — 탈취한 자격증명, 동작하는 공격 경로, 미패치 취약점이 한곳에 모입니다. 유출되면 보고서가 곧 공격 매뉴얼이 됩니다.

| 위험 | 문제 | 대응 |
|---|---|---|
| 실자격증명 포함 | 보고서 유출 시 즉시 악용 | 마스킹, 평문 비밀번호·키 제거 |
| 완전한 익스플로잇 | 그대로 재공격 가능 | 재현에 필요한 최소만, 무기화 코드 자제 |
| 광범위 배포 | 노출면 확대 | need-to-know, 암호화 전달 |
| 미패치 상세 | 수정 전 노출 위험 | 배포 통제, 보존기간 설정 |

### 배포 전 검증 (직접)

```text
보고서 제출 전:
  □ 캡처한 실자격증명·토큰·키를 마스킹/제거했는가?
  □ PoC가 재현에 필요한 최소 수준인가? (완전 무기화 코드 제외)
  □ 배포 대상이 need-to-know로 제한되고 암호화 전달인가?
  □ 보고서 보관·파기(보존기간) 정책이 정해졌는가?
```

> 핵심: 보고서는 결함을 고치게 하는 문서이지 **공격 재료를 배포하는 문서가 아닙니다.** 실자격증명을 지우고, 무기화 코드를 자제하고, need-to-know로 암호화 배포하세요. 안전한 취급이 안 되면 보고 자체가 새 위험이 됩니다([[68_Purple_Team]]).

---

<a name="english"></a>

# Red Team Report Writing

## Why Is the Report Important?

All the technical achievements of a red team operation are meaningless if they are not captured in a report. No matter how brilliant the attack path discovered, if executives cannot understand it or the technical team cannot reproduce it, no security improvement will occur.

A good red team report must satisfy two audiences simultaneously:

```
Audience A — Executives (CISO, CEO, Board)
  Needs: How at risk are we? What do we fix first?
  Will read: 2–3 pages (Executive Summary)
  
Audience B — Technical team (developers, sys admins, SOC analysts)
  Needs: What exactly are the vulnerabilities and how to fix them?
  Will read: Full technical details (tens to hundreds of pages)
```

---

## Red Team Report Structure

### Standard Report Layout

```
1. Cover Page
   - Operation name, date, classification, version

2. Executive Summary ← Most important!
   - Purpose, scope, key findings (3–5), overall risk level

3. Operation Overview
   - RoE, timeline, team composition

4. Findings
   - Critical / High / Medium / Low classification
   - Each finding: title, severity, description, evidence, recommendation

5. Attack Narrative
   - Story-format account from beginning to end

6. TTP Mapping (MITRE ATT&CK)
   - Matrix of techniques used

7. Remediation Recommendations
   - Prioritized remediation roadmap

8. Conclusion

9. Appendix
   - Tool list, screenshots, log evidence
```

---

## Writing the Executive Summary

The executive summary minimizes technical jargon and uses business language.

### Bad Example vs. Good Example

```
Bad:
"Using a SQL Injection vulnerability, we performed a UNION-based 
attack to extract the password_hash column from the users table."

Good:
"Through a vulnerability in the online shopping mall's login page, 
we were able to access account information for 150,000 customers. 
This constitutes a violation of the Personal Information Protection Act, 
subject to penalties of up to 300 million KRW."
```

---

## Risk Assessment Method

Risk is calculated as **Likelihood × Impact**.

### CVSS v3.1 Scoring

| Score | Rating | Meaning |
|---|---|---|
| 9.0 ~ 10.0 | Critical | Immediate patch required (within 24 hours) |
| 7.0 ~ 8.9 | High | Urgent patch needed (within 1 week) |
| 4.0 ~ 6.9 | Medium | Scheduled patch (within 1 month) |
| 0.1 ~ 3.9 | Low | Accept risk or apply mitigation |

### Internal Risk Matrix

```
Impact
High   │  Medium │  High  │ Critical
Medium │  Low    │ Medium │  High
Low    │  Low    │  Low   │ Medium
       └─────────┴────────┴─────────
           Low     Medium    High
                          Likelihood
```

---

## Finding Template

Each finding is written using this template:

```markdown
## F-001: Domain Administrator Privilege Takeover

**Severity**: Critical (CVSS: 9.8)
**Date Found**: 2024-01-09
**Affected System**: DC01.corp.example.com

### Description
The red team executed a malicious macro via a finance staff member's email, 
then used Mimikatz to extract the domain administrator account's NTLM hash. 
This provided complete control over the entire domain.

### Attack Path
Phishing email → Macro execution → PowerShell C2 → 
LSASS dump → Domain admin hash → DC access

### Evidence
[Screenshot 1] Successful LSASS memory dump
[Screenshot 2] DC01 administrator session established

### Remediation Recommendations
1. (Immediate) Apply Protected Process Light (PPL) to LSASS
2. (1 week) Apply MFA to domain admin accounts
3. (1 month) Implement Privileged Access Workstations (PAW)
```

---

## Python Markdown Report Auto-Generator

```python
#!/usr/bin/env python3
"""
Red Team Report Auto-Generator
Usage: python3 04_report_writing.py --demo --output report.md
       python3 04_report_writing.py --add-finding
"""

import argparse
import sys
from dataclasses import dataclass, field
from datetime import date
from enum import Enum
from typing import List


class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFORMATIONAL = "Informational"

    def cvss_range(self) -> str:
        return {
            "Critical": "9.0–10.0",
            "High": "7.0–8.9",
            "Medium": "4.0–6.9",
            "Low": "0.1–3.9",
            "Informational": "0.0",
        }[self.value]


@dataclass
class Finding:
    finding_id: str
    title: str
    severity: Severity
    cvss_score: float
    affected_system: str
    description: str
    attack_path: str
    recommendation: str
    found_date: date = field(default_factory=date.today)

    def validate(self) -> None:
        if not 0.0 <= self.cvss_score <= 10.0:
            raise ValueError(f"CVSS score must be 0.0–10.0. Got: {self.cvss_score}")

    def to_markdown(self) -> str:
        return (
            f"## {self.finding_id}: {self.title}\n\n"
            f"**Severity**: {self.severity.value} (CVSS: {self.cvss_score:.1f})\n"
            f"**Found**: {self.found_date}\n"
            f"**Affected System**: `{self.affected_system}`\n\n"
            f"### Description\n{self.description}\n\n"
            f"### Attack Path\n```\n{self.attack_path}\n```\n\n"
            f"### Recommendations\n{self.recommendation}\n\n---"
        )


@dataclass
class RedTeamReport:
    operation_name: str
    client_name: str
    report_date: date
    scope: str
    findings: List[Finding] = field(default_factory=list)

    def add_finding(self, finding: Finding) -> None:
        finding.validate()
        self.findings.append(finding)

    def to_markdown(self) -> str:
        sorted_findings = sorted(self.findings, key=lambda f: list(Severity).index(f.severity))
        counts = {s: sum(1 for f in self.findings if f.severity == s) for s in Severity}
        critical_count = counts[Severity.CRITICAL]
        risk = "Very High" if critical_count > 0 else "High" if counts[Severity.HIGH] > 0 else "Moderate"

        parts = [
            f"# Red Team Penetration Test Report",
            f"",
            f"| Item | Value |",
            f"|---|---|",
            f"| Operation | {self.operation_name} |",
            f"| Client | {self.client_name} |",
            f"| Date | {self.report_date} |",
            f"| Scope | {self.scope} |",
            f"",
            f"---",
            f"",
            f"## Executive Summary",
            f"",
            f"The red team assessed **{self.scope}** and identified "
            f"**{len(self.findings)}** security issues. "
            f"Overall risk level: **{risk}**.",
            f"",
            f"| Severity | Count |",
            f"|---|---|",
        ]
        for s in Severity:
            parts.append(f"| {s.value} | {counts[s]} |")
        parts += [
            f"",
            f"> **Action Required**: {critical_count} Critical findings need immediate remediation.",
            f"",
            f"---",
            f"",
            f"# Findings",
            f"",
        ]
        for finding in sorted_findings:
            parts.append(finding.to_markdown())
            parts.append("")
        return "\n".join(parts)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Red Team Report Auto-Generator")
    parser.add_argument("--name", default="Red Team Operation", help="Operation name")
    parser.add_argument("--client", default="Client", help="Client name")
    parser.add_argument("--scope", default="Internal network", help="Operation scope")
    parser.add_argument("--demo", action="store_true", help="Generate demo report with sample findings")
    parser.add_argument("--add-finding", action="store_true", help="Add findings interactively")
    parser.add_argument("--output", help="Output file path (stdout if not specified)")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    report = RedTeamReport(
        operation_name=args.name,
        client_name=args.client,
        report_date=date.today(),
        scope=args.scope,
    )

    if args.demo:
        report.add_finding(Finding(
            finding_id="F-001",
            title="Domain Administrator Credential Theft",
            severity=Severity.CRITICAL,
            cvss_score=9.8,
            affected_system="DC01.corp.example.com",
            description="Successfully extracted domain admin NTLM hash via LSASS dump using Mimikatz.",
            attack_path="Phishing → Macro execution → PowerShell C2 → LSASS dump → DC access",
            recommendation="1. Apply PPL to LSASS immediately\n2. Enforce MFA for admin accounts",
        ))
        report.add_finding(Finding(
            finding_id="F-002",
            title="VPN Authentication Bypass",
            severity=Severity.HIGH,
            cvss_score=8.1,
            affected_system="vpn.example.com",
            description="CVE-2024-XXXX allows unauthenticated access to internal network via VPN.",
            attack_path="Internet → VPN vulnerability exploit → Internal network",
            recommendation="Update VPN software immediately",
        ))
    elif args.add_finding:
        finding_num = 1
        while True:
            finding_id = f"F-{finding_num:03d}"
            title = input(f"\nFinding {finding_num} title: ").strip()
            severity_input = input("Severity (critical/high/medium/low): ").strip().lower()
            severity_map = {"critical": Severity.CRITICAL, "high": Severity.HIGH,
                            "medium": Severity.MEDIUM, "low": Severity.LOW}
            severity = severity_map.get(severity_input, Severity.MEDIUM)
            try:
                cvss = float(input("CVSS score: ").strip())
            except ValueError:
                cvss = 5.0
            report.add_finding(Finding(
                finding_id=finding_id,
                title=title,
                severity=severity,
                cvss_score=cvss,
                affected_system=input("Affected system: ").strip(),
                description=input("Description: ").strip(),
                attack_path=input("Attack path: ").strip(),
                recommendation=input("Recommendation: ").strip(),
            ))
            finding_num += 1
            if input("\nAdd another finding? (y/N): ").strip().lower() != "y":
                break
    else:
        print("Use --demo or --add-finding", file=sys.stderr)
        sys.exit(1)

    output = report.to_markdown()
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(output)
        print(f"Report saved to: {args.output}")
    else:
        print(output)


if __name__ == "__main__":
    main()
```

### Usage Examples

```bash
# Generate demo report
python3 04_report_writing.py --demo --client "ABC Corp" --output report.md

# Add findings interactively
python3 04_report_writing.py --name "Operation Storm" --client "XYZ Ltd" --add-finding
```

---

## Report Writing Golden Rules

1. **No evidence, no finding**: Every finding must have screenshots, logs, or files attached.
2. **Must be reproducible**: Technical details must allow someone else to reproduce the steps exactly.
3. **Must be actionable**: Every finding must include actionable remediation recommendations.
4. **Consider your audience**: Executive summary in business language; technical details in technical language.
5. **Clear prioritization**: Clearly communicate that Critical findings must be fixed first.

**Reference**: [Red Team Guide](https://redteam.guide/)

## Sensitive-Data Handling and Report Security

A red team report is itself **the organization's most dangerous document** — captured credentials, working attack paths, and unpatched vulnerabilities in one place. If leaked, the report becomes an attack manual.

| Risk | Problem | Response |
|---|---|---|
| Real credentials | Immediate abuse if the report leaks | Mask; remove plaintext passwords/keys |
| Full exploit | Enables direct re-attack | Minimum needed to reproduce; avoid weaponized code |
| Broad distribution | Expands exposure | Need-to-know, encrypted delivery |
| Unpatched detail | Exposure risk before fixes | Control distribution, set retention |

### Pre-distribution validation (do it yourself)

```text
Before submitting the report:
  [ ] Masked/removed captured real credentials/tokens/keys?
  [ ] Is the PoC the minimum needed to reproduce? (exclude fully weaponized code)
  [ ] Is distribution restricted to need-to-know and delivered encrypted?
  [ ] Is a report storage/destruction (retention) policy set?
```

> Core: a report is a document that gets defects fixed, **not one that distributes attack material**. Strip real credentials, avoid weaponized code, and deliver encrypted on a need-to-know basis. Without safe handling, the report itself becomes a new risk (see [[68_Purple_Team]]).
