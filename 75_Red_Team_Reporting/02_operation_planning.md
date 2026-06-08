> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 레드팀 작전 계획 수립

## 작전 계획이란?

레드팀 작전은 즉흥적인 해킹이 아닙니다. 군사 작전처럼 치밀하게 계획됩니다. 작전 계획이 없으면 팀원들이 중복 작업을 하거나, 중요한 단계를 빠뜨리거나, 범위를 벗어난 행동을 할 수 있습니다.

좋은 작전 계획은 다음 질문에 답합니다:
- **무엇을**: 어떤 목표를 달성할 것인가?
- **왜**: 왜 이 목표가 중요한가?
- **어떻게**: 어떤 기법과 경로를 사용할 것인가?
- **언제**: 각 단계가 언제 실행되는가?
- **누가**: 누가 어떤 역할을 담당하는가?

---

## 1단계: 목표 설정 — 크라운 쥬얼 식별

### 크라운 쥬얼(Crown Jewel)이란?

크라운 쥬얼은 조직에서 가장 중요한 자산입니다. 이것이 침해되면 조직에 치명적인 피해가 발생합니다.

```
크라운 쥬얼 예시:
  금융기관:   고객 계좌 데이터베이스, 거래 처리 시스템
  병원:       환자 의료 기록, 의료 장비 제어 시스템
  제조업:     설계 도면, 생산 공정 제어 시스템 (ICS/SCADA)
  IT 기업:    소스 코드 저장소, 고객 데이터
  정부기관:   기밀 문서 시스템, 국민 개인정보
```

### 크라운 쥬얼 식별 워크숍

조직의 이해관계자(CISO, CTO, 사업부 팀장)와 함께 다음 질문으로 워크숍을 진행합니다:

1. 어떤 시스템이 중단되면 사업이 멈추는가?
2. 어떤 데이터가 유출되면 법적 문제가 생기는가?
3. 경쟁사가 가장 탐내는 정보는 무엇인가?
4. 공격자가 무엇을 노릴 가능성이 높은가?

---

## 2단계: 타임라인 및 마일스톤 계획

레드팀 작전은 보통 다음 단계로 진행됩니다:

```
Phase 1 — 준비 (1~2주)
  - RoE 서명
  - 인프라 구축 (C2 서버, 프록시)
  - OSINT 정보 수집

Phase 2 — 초기 침투 (1~2주)
  - 스피어피싱 캠페인
  - 공개 취약점 활용
  - 거점 확보

Phase 3 — 내부 이동 (1~2주)
  - 내부 정찰
  - 권한 상승
  - 횡이동

Phase 4 — 목표 달성 (3~5일)
  - 크라운 쥬얼 접근
  - 증거 수집

Phase 5 — 보고 (1주)
  - 보고서 작성
  - 디브리핑
```

---

## 3단계: 팀 역할 분담

### 레드팀 구성

| 역할 | 영문명 | 책임 |
|---|---|---|
| **팀장** | Operator Lead | 작전 총괄, RoE 준수 관리, 보고서 승인 |
| **오퍼레이터** | Operator | 실제 공격 수행, 접근 경로 개척 |
| **지원 오퍼레이터** | Support Operator | C2 인프라 관리, 도구 준비 |
| **보고 담당** | Reporting Lead | 발견사항 문서화, 보고서 작성 |

```
작전 중 통신 규칙:
  - 암호화된 채널만 사용 (Signal, ProtonMail)
  - 작전 코드명 사용 (실명 금지)
  - 일일 상황 보고 (매일 18:00)
  - 중요 발견사항은 즉시 보고
```

---

## 4단계: 킬 체인 기반 계획 수립

Lockheed Martin의 사이버 킬 체인(Cyber Kill Chain)은 공격의 7단계를 정의합니다.

| 단계 | 이름 | 레드팀 계획 항목 |
|---|---|---|
| 1 | Reconnaissance | OSINT 목표, WHOIS, LinkedIn |
| 2 | Weaponization | 페이로드 제작, 익스플로잇 선택 |
| 3 | Delivery | 피싱 이메일, USB, 웹 취약점 |
| 4 | Exploitation | 취약점 악용, 코드 실행 |
| 5 | Installation | 백도어, 지속성 메커니즘 |
| 6 | Command & Control | C2 채널 구축 |
| 7 | Actions on Objectives | 크라운 쥬얼 접근, 데이터 탈취 |

---

## Python 작전 타임라인 Markdown 생성기

다음 코드는 레드팀 작전 타임라인을 Markdown 형식으로 자동 생성합니다.

```python
#!/usr/bin/env python3
"""
레드팀 작전 타임라인 Markdown 생성기
사용법: python3 02_operation_planning.py --name "Operation X" --start 2024-01-01 --days 30
"""

import argparse
import sys
from dataclasses import dataclass, field
from datetime import date, timedelta
from typing import List


@dataclass
class Phase:
    name: str
    duration_days: int
    objectives: List[str] = field(default_factory=list)
    techniques: List[str] = field(default_factory=list)


DEFAULT_PHASES: List[Phase] = [
    Phase(
        name="Phase 1 — 준비 (Preparation)",
        duration_days=7,
        objectives=["RoE 서명 완료", "C2 인프라 구축", "OSINT 정보 수집"],
        techniques=["Shodan 검색", "LinkedIn OSINT", "WHOIS 조회"],
    ),
    Phase(
        name="Phase 2 — 초기 침투 (Initial Access)",
        duration_days=7,
        objectives=["스피어피싱 캠페인 실행", "거점 확보"],
        techniques=["T1566.001 (Spearphishing Attachment)", "T1190 (Exploit Public-Facing Application)"],
    ),
    Phase(
        name="Phase 3 — 내부 이동 (Lateral Movement)",
        duration_days=7,
        objectives=["내부 정찰", "권한 상승", "횡이동"],
        techniques=["T1021 (Remote Services)", "T1078 (Valid Accounts)", "T1548 (Privilege Escalation)"],
    ),
    Phase(
        name="Phase 4 — 목표 달성 (Actions on Objectives)",
        duration_days=5,
        objectives=["크라운 쥬얼 접근", "증거 수집"],
        techniques=["T1005 (Data from Local System)", "T1041 (Exfiltration Over C2 Channel)"],
    ),
    Phase(
        name="Phase 5 — 보고 (Reporting)",
        duration_days=4,
        objectives=["보고서 초안 작성", "내부 검토", "디브리핑 준비"],
        techniques=["발견사항 문서화", "CVSS 점수 산정", "수정 권고사항 작성"],
    ),
]


def generate_timeline_markdown(
    operation_name: str,
    start_date: date,
    team_lead: str,
    phases: List[Phase],
) -> str:
    """작전 타임라인 Markdown 생성"""
    lines = [
        f"# 레드팀 작전 타임라인",
        f"",
        f"| 항목 | 내용 |",
        f"|---|---|",
        f"| 작전명 | {operation_name} |",
        f"| 팀장 | {team_lead} |",
        f"| 시작일 | {start_date} |",
        f"",
        f"---",
        f"",
        f"## 킬 체인 단계별 계획",
        f"",
    ]

    current_date = start_date
    for phase in phases:
        end_date = current_date + timedelta(days=phase.duration_days - 1)
        lines += [
            f"### {phase.name}",
            f"**기간**: {current_date} ~ {end_date} ({phase.duration_days}일)",
            f"",
            f"**목표**:",
        ]
        for obj in phase.objectives:
            lines.append(f"- {obj}")
        lines += ["", "**사용 기법**:"]
        for tech in phase.techniques:
            lines.append(f"- {tech}")
        lines += ["", "---", ""]
        current_date = end_date + timedelta(days=1)

    total_days = sum(p.duration_days for p in phases)
    end_date_total = start_date + timedelta(days=total_days - 1)
    lines += [
        f"## 작전 요약",
        f"",
        f"- **총 기간**: {total_days}일 ({start_date} ~ {end_date_total})",
        f"- **총 단계**: {len(phases)}개 Phase",
        f"- **크라운 쥬얼 접근 목표일**: {end_date_total - timedelta(days=4)}",
    ]
    return "\n".join(lines)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="레드팀 작전 타임라인 Markdown 생성기",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="예시: python3 02_operation_planning.py --name 'Operation Storm' --start 2024-01-01 --lead '홍길동'",
    )
    parser.add_argument("--name", required=True, help="작전 이름")
    parser.add_argument("--start", required=True, help="시작일 (YYYY-MM-DD)")
    parser.add_argument("--lead", default="미정", help="팀장 이름 (기본값: 미정)")
    parser.add_argument("--output", help="출력 파일 경로 (미지정 시 stdout)")
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    try:
        start_date = date.fromisoformat(args.start)
    except ValueError:
        print(f"오류: 날짜 형식이 잘못되었습니다. YYYY-MM-DD 형식을 사용하세요. 입력값: {args.start}", file=sys.stderr)
        sys.exit(1)

    markdown = generate_timeline_markdown(
        operation_name=args.name,
        start_date=start_date,
        team_lead=args.lead,
        phases=DEFAULT_PHASES,
    )

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(markdown)
            print(f"타임라인이 저장되었습니다: {args.output}")
        except OSError as e:
            print(f"파일 저장 오류: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        print(markdown)


if __name__ == "__main__":
    main()
```

### 실행 예시

```bash
# 기본 실행 (콘솔 출력)
python3 02_operation_planning.py --name "Operation Silent Storm" --start 2024-01-01 --lead "팀장A"

# 파일로 저장
python3 02_operation_planning.py --name "Operation Silent Storm" --start 2024-01-01 --output timeline.md
```

---

## 작전 계획 체크리스트

작전 시작 전 반드시 확인해야 할 항목들입니다.

```
[ ] RoE 문서 서명 완료 (고객사 + 레드팀)
[ ] 법적 승인서 확보
[ ] 비상 연락처 공유 (모든 팀원)
[ ] C2 인프라 구축 및 테스트 완료
[ ] 도구 및 페이로드 준비 완료
[ ] 탈출 조항(Escape Clause) 조건 숙지
[ ] 디-컨플리션(De-confliction) 절차 확인
[ ] 작전 코드명 배정
[ ] 암호화 통신 채널 설정
[ ] 일일 보고 일정 확인
```

**참고 자료**: [Lockheed Martin Cyber Kill Chain](https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html)

---

<a name="english"></a>

# Red Team Operation Planning

## What Is an Operation Plan?

A red team operation is not improvised hacking. It is planned with the precision of a military operation. Without an operation plan, team members may duplicate efforts, skip critical steps, or act outside the defined scope.

A good operation plan answers these questions:
- **What**: What objectives will be achieved?
- **Why**: Why are these objectives important?
- **How**: What techniques and paths will be used?
- **When**: When does each phase execute?
- **Who**: Who is responsible for each role?

---

## Step 1: Setting Objectives — Identifying Crown Jewels

### What Is a Crown Jewel?

Crown Jewels are an organization's most critical assets. If compromised, they cause catastrophic damage.

```
Crown Jewel Examples:
  Financial:     Customer account database, transaction processing system
  Hospital:      Patient medical records, medical device control systems
  Manufacturing: Design blueprints, production control systems (ICS/SCADA)
  IT company:    Source code repositories, customer data
  Government:    Classified document systems, citizen personal data
```

### Crown Jewel Identification Workshop

Conduct a workshop with organizational stakeholders (CISO, CTO, business unit leads) using these questions:

1. Which system stoppage would halt business operations?
2. Which data breach would create legal issues?
3. What information would competitors most want to steal?
4. What is an attacker most likely to target?

---

## Step 2: Timeline and Milestone Planning

Red team operations typically proceed through the following phases:

```
Phase 1 — Preparation (1–2 weeks)
  - RoE signing
  - Infrastructure setup (C2 server, proxies)
  - OSINT reconnaissance

Phase 2 — Initial Access (1–2 weeks)
  - Spear phishing campaign
  - Public vulnerability exploitation
  - Establishing foothold

Phase 3 — Lateral Movement (1–2 weeks)
  - Internal reconnaissance
  - Privilege escalation
  - Lateral movement

Phase 4 — Actions on Objectives (3–5 days)
  - Crown Jewel access
  - Evidence collection

Phase 5 — Reporting (1 week)
  - Report writing
  - Debriefing
```

---

## Step 3: Team Role Assignment

### Red Team Structure

| Role | Description |
|---|---|
| **Operator Lead** | Overall operation management, RoE compliance, report approval |
| **Operator** | Executes actual attacks, pioneers access paths |
| **Support Operator** | Manages C2 infrastructure, prepares tools |
| **Reporting Lead** | Documents findings, writes reports |

```
Operational Communication Rules:
  - Use only encrypted channels (Signal, ProtonMail)
  - Use operation code names (no real names)
  - Daily status reports (18:00 daily)
  - Immediately report critical findings
```

---

## Step 4: Kill Chain-Based Planning

Lockheed Martin's Cyber Kill Chain defines seven stages of an attack.

| Stage | Name | Red Team Planning Item |
|---|---|---|
| 1 | Reconnaissance | OSINT targets, WHOIS, LinkedIn |
| 2 | Weaponization | Payload creation, exploit selection |
| 3 | Delivery | Phishing email, USB, web vulnerability |
| 4 | Exploitation | Vulnerability exploitation, code execution |
| 5 | Installation | Backdoor, persistence mechanism |
| 6 | Command & Control | C2 channel establishment |
| 7 | Actions on Objectives | Crown Jewel access, data exfiltration |

---

## Python Operation Timeline Markdown Generator

The following code automatically generates an operation timeline in Markdown format.

```python
#!/usr/bin/env python3
"""
Red Team Operation Timeline Markdown Generator
Usage: python3 02_operation_planning.py --name "Operation X" --start 2024-01-01 --days 30
"""

import argparse
import sys
from dataclasses import dataclass, field
from datetime import date, timedelta
from typing import List


@dataclass
class Phase:
    name: str
    duration_days: int
    objectives: List[str] = field(default_factory=list)
    techniques: List[str] = field(default_factory=list)


DEFAULT_PHASES: List[Phase] = [
    Phase(
        name="Phase 1 — Preparation",
        duration_days=7,
        objectives=["Complete RoE signing", "Build C2 infrastructure", "OSINT reconnaissance"],
        techniques=["Shodan search", "LinkedIn OSINT", "WHOIS lookup"],
    ),
    Phase(
        name="Phase 2 — Initial Access",
        duration_days=7,
        objectives=["Execute spear phishing campaign", "Establish foothold"],
        techniques=["T1566.001 (Spearphishing Attachment)", "T1190 (Exploit Public-Facing Application)"],
    ),
    Phase(
        name="Phase 3 — Lateral Movement",
        duration_days=7,
        objectives=["Internal reconnaissance", "Privilege escalation", "Lateral movement"],
        techniques=["T1021 (Remote Services)", "T1078 (Valid Accounts)", "T1548 (Privilege Escalation)"],
    ),
    Phase(
        name="Phase 4 — Actions on Objectives",
        duration_days=5,
        objectives=["Access Crown Jewels", "Collect evidence"],
        techniques=["T1005 (Data from Local System)", "T1041 (Exfiltration Over C2 Channel)"],
    ),
    Phase(
        name="Phase 5 — Reporting",
        duration_days=4,
        objectives=["Draft report", "Internal review", "Prepare debriefing"],
        techniques=["Finding documentation", "CVSS scoring", "Write remediation recommendations"],
    ),
]


def generate_timeline_markdown(
    operation_name: str,
    start_date: date,
    team_lead: str,
    phases: List[Phase],
) -> str:
    """Generate operation timeline in Markdown format"""
    lines = [
        f"# Red Team Operation Timeline",
        f"",
        f"| Item | Value |",
        f"|---|---|",
        f"| Operation Name | {operation_name} |",
        f"| Team Lead | {team_lead} |",
        f"| Start Date | {start_date} |",
        f"",
        f"---",
        f"",
        f"## Kill Chain Phase Plan",
        f"",
    ]

    current_date = start_date
    for phase in phases:
        end_date = current_date + timedelta(days=phase.duration_days - 1)
        lines += [
            f"### {phase.name}",
            f"**Duration**: {current_date} ~ {end_date} ({phase.duration_days} days)",
            f"",
            f"**Objectives**:",
        ]
        for obj in phase.objectives:
            lines.append(f"- {obj}")
        lines += ["", "**Techniques Used**:"]
        for tech in phase.techniques:
            lines.append(f"- {tech}")
        lines += ["", "---", ""]
        current_date = end_date + timedelta(days=1)

    total_days = sum(p.duration_days for p in phases)
    end_date_total = start_date + timedelta(days=total_days - 1)
    lines += [
        f"## Operation Summary",
        f"",
        f"- **Total Duration**: {total_days} days ({start_date} ~ {end_date_total})",
        f"- **Total Phases**: {len(phases)}",
        f"- **Crown Jewel Access Target Date**: {end_date_total - timedelta(days=4)}",
    ]
    return "\n".join(lines)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Red Team Operation Timeline Markdown Generator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Example: python3 02_operation_planning.py --name 'Operation Storm' --start 2024-01-01 --lead 'Alice'",
    )
    parser.add_argument("--name", required=True, help="Operation name")
    parser.add_argument("--start", required=True, help="Start date (YYYY-MM-DD)")
    parser.add_argument("--lead", default="TBD", help="Team lead name (default: TBD)")
    parser.add_argument("--output", help="Output file path (stdout if not specified)")
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    try:
        start_date = date.fromisoformat(args.start)
    except ValueError:
        print(f"Error: Invalid date format. Use YYYY-MM-DD. Input: {args.start}", file=sys.stderr)
        sys.exit(1)

    markdown = generate_timeline_markdown(
        operation_name=args.name,
        start_date=start_date,
        team_lead=args.lead,
        phases=DEFAULT_PHASES,
    )

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(markdown)
            print(f"Timeline saved to: {args.output}")
        except OSError as e:
            print(f"File save error: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        print(markdown)


if __name__ == "__main__":
    main()
```

### Execution Examples

```bash
# Basic run (console output)
python3 02_operation_planning.py --name "Operation Silent Storm" --start 2024-01-01 --lead "Alice"

# Save to file
python3 02_operation_planning.py --name "Operation Silent Storm" --start 2024-01-01 --output timeline.md
```

---

## Operation Planning Checklist

Items that must be verified before starting an operation.

```
[ ] RoE document signed (client + red team)
[ ] Legal authorization obtained
[ ] Emergency contacts shared (all team members)
[ ] C2 infrastructure built and tested
[ ] Tools and payloads prepared
[ ] Escape clause conditions understood
[ ] De-confliction procedure confirmed
[ ] Operation code name assigned
[ ] Encrypted communication channels configured
[ ] Daily reporting schedule confirmed
```

**Reference**: [Lockheed Martin Cyber Kill Chain](https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html)
