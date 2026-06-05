> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 퍼플팀 결과 보고서 (Purple Team Reporting)

## 개념 소개

퍼플팀 활동의 최종 산출물은 보고서입니다. 마치 의사가 진단 결과를 환자에게 설명할 때 전문 용어를 쉽게 풀어주듯, 퍼플팀 보고서는 기술적 발견사항을 경영진과 실무진 모두가 이해할 수 있는 형식으로 전달해야 합니다.

---

## 보고서 구성 요소

### 1. 경영진 요약 (Executive Summary)

- 전체 탐지율 (Coverage Rate)
- 최고 위험 갭 3~5개
- 즉각적 조치 권고사항

### 2. 기술적 발견사항

- 실행된 기법 목록 (ATT&CK 매핑)
- 탐지 성공/실패 결과
- 증거 로그, 타임라인

### 3. 갭 분석 (Gap Analysis)

```
탐지 갭 = 실행된 기법 수 - 탐지된 기법 수
탐지율 = 탐지된 기법 / 전체 실행 기법 × 100%
```

### 4. 개선 로드맵

| 우선순위 | 기법 ID | 개선 조치 | 담당 | 기한 |
|---|---|---|---|---|
| P1 (즉각) | T1003.001 | LSASS 접근 탐지 룰 추가 | SOC | 1주 |
| P2 (단기) | T1053.005 | Task Scheduler 감사 활성화 | IT | 1개월 |
| P3 (중기) | T1021.001 | RDP 접근 위치 기반 필터 | 인프라 | 3개월 |

### 5. 재테스트 계획

- 개선 후 동일 기법 재실행으로 효과 검증
- 분기별 정기 평가 일정

---

## Python 실습: 퍼플팀 결과 → 마크다운 보고서 자동 생성기

```python
#!/usr/bin/env python3
"""
퍼플팀 테스트 결과 데이터(JSON)를 마크다운 보고서로 자동 생성합니다.
"""

import argparse
import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path


@dataclass
class TechniqueResult:
    technique_id: str
    technique_name: str
    tactic: str
    detected: bool
    blocked: bool
    detection_time_min: float | None
    notes: str = ""
    remediation: str = ""
    priority: str = "P3"  # P1/P2/P3


@dataclass
class PurpleTeamReport:
    engagement_name: str
    organization: str
    test_period_start: str
    test_period_end: str
    scope: str
    team_lead: str = ""
    techniques: list[TechniqueResult] = field(default_factory=list)
    executive_notes: str = ""
    recommendations: list[str] = field(default_factory=list)


def calculate_stats(report: PurpleTeamReport) -> dict:
    total = len(report.techniques)
    detected = sum(1 for t in report.techniques if t.detected)
    blocked = sum(1 for t in report.techniques if t.blocked)
    undetected = total - detected - blocked
    detection_rate = (detected + blocked) / total * 100 if total > 0 else 0.0
    p1 = sum(1 for t in report.techniques if t.priority == "P1")
    p2 = sum(1 for t in report.techniques if t.priority == "P2")
    p3 = sum(1 for t in report.techniques if t.priority == "P3")

    detection_times = [
        t.detection_time_min for t in report.techniques
        if t.detected and t.detection_time_min is not None
    ]
    avg_detection_time = (
        sum(detection_times) / len(detection_times) if detection_times else None
    )

    by_tactic: dict[str, dict] = {}
    for t in report.techniques:
        if t.tactic not in by_tactic:
            by_tactic[t.tactic] = {"total": 0, "detected": 0}
        by_tactic[t.tactic]["total"] += 1
        if t.detected or t.blocked:
            by_tactic[t.tactic]["detected"] += 1

    return {
        "total": total,
        "detected": detected,
        "blocked": blocked,
        "undetected": undetected,
        "detection_rate": round(detection_rate, 1),
        "p1": p1, "p2": p2, "p3": p3,
        "avg_detection_time": avg_detection_time,
        "by_tactic": by_tactic,
    }


def generate_markdown(report: PurpleTeamReport, stats: dict) -> str:
    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    lines: list[str] = []

    # 표지
    lines += [
        f"# 퍼플팀 결과 보고서",
        f"",
        f"| 항목 | 내용 |",
        f"|---|---|",
        f"| 평가명 | {report.engagement_name} |",
        f"| 대상 조직 | {report.organization} |",
        f"| 테스트 기간 | {report.test_period_start} ~ {report.test_period_end} |",
        f"| 스코프 | {report.scope} |",
        f"| 보고서 생성 | {now} |",
        f"",
        f"---",
        f"",
    ]

    # 경영진 요약
    coverage_emoji = "🟢" if stats["detection_rate"] >= 70 else ("🟡" if stats["detection_rate"] >= 40 else "🔴")
    lines += [
        f"## 경영진 요약",
        f"",
        f"### 전체 탐지 커버리지",
        f"",
        f"```",
        f"탐지율: {stats['detection_rate']}%  {coverage_emoji}",
        f"실행 기법: {stats['total']}개",
        f"탐지/차단: {stats['detected'] + stats['blocked']}개",
        f"미탐지:   {stats['undetected']}개",
        f"```",
        f"",
    ]

    if stats["avg_detection_time"] is not None:
        lines.append(f"평균 탐지 시간: **{stats['avg_detection_time']:.1f}분**\n")

    if report.executive_notes:
        lines += [f"### 주요 관찰사항", f"", report.executive_notes, f""]

    # 개선 우선순위 요약
    lines += [
        f"### 즉각 조치 필요 (P1: {stats['p1']}건)",
        f"",
    ]
    p1_items = [t for t in report.techniques if t.priority == "P1" and not t.detected]
    for item in p1_items:
        lines.append(f"- **{item.technique_id}** {item.technique_name}: {item.remediation}")
    lines.append("")

    # 전술별 탐지 현황
    lines += [
        f"---",
        f"",
        f"## 전술별 탐지 현황",
        f"",
        f"| 전술 | 실행 | 탐지 | 탐지율 |",
        f"|---|---|---|---|",
    ]
    for tactic, data in sorted(stats["by_tactic"].items()):
        rate = data["detected"] / data["total"] * 100 if data["total"] else 0
        bar = "█" * int(rate / 10) + "░" * (10 - int(rate / 10))
        lines.append(f"| {tactic} | {data['total']} | {data['detected']} | {bar} {rate:.0f}% |")
    lines.append("")

    # 상세 기법 결과
    lines += [
        f"---",
        f"",
        f"## 기법별 상세 결과",
        f"",
        f"| 우선순위 | 기법 ID | 기법명 | 전술 | 탐지 | 차단 | 탐지시간 |",
        f"|---|---|---|---|---|---|---|",
    ]
    sorted_techs = sorted(
        report.techniques,
        key=lambda t: ("P1", "P2", "P3").index(t.priority) if t.priority in ("P1", "P2", "P3") else 3,
    )
    for t in sorted_techs:
        det = "✓" if t.detected else "✗"
        blk = "✓" if t.blocked else "-"
        dt = f"{t.detection_time_min:.1f}분" if t.detection_time_min else "-"
        lines.append(
            f"| {t.priority} | `{t.technique_id}` | {t.technique_name} "
            f"| {t.tactic} | {det} | {blk} | {dt} |"
        )
    lines.append("")

    # 갭 분석
    gaps = [t for t in report.techniques if not t.detected and not t.blocked]
    if gaps:
        lines += [
            f"---",
            f"",
            f"## 갭 분석 (미탐지 기법: {len(gaps)}건)",
            f"",
        ]
        for t in gaps:
            lines += [
                f"### {t.technique_id}: {t.technique_name}",
                f"",
                f"- **전술**: {t.tactic}",
                f"- **우선순위**: {t.priority}",
                f"- **개선 조치**: {t.remediation if t.remediation else '탐지 룰 개발 필요'}",
                f"- **비고**: {t.notes if t.notes else '-'}",
                f"",
            ]

    # 개선 권고사항
    if report.recommendations:
        lines += [
            f"---",
            f"",
            f"## 개선 권고사항",
            f"",
        ]
        for i, rec in enumerate(report.recommendations, 1):
            lines.append(f"{i}. {rec}")
        lines.append("")

    # 재테스트 계획
    lines += [
        f"---",
        f"",
        f"## 재테스트 계획",
        f"",
        f"| 단계 | 내용 | 예상 시기 |",
        f"|---|---|---|",
        f"| P1 수정 검증 | P1 기법 즉시 재실행 | 개선 후 2주 내 |",
        f"| 전체 재평가 | 모든 기법 재테스트 | 3개월 후 |",
        f"| 정기 평가 | 신규 기법 포함 | 분기별 |",
        f"",
        f"---",
        f"",
        f"*본 보고서는 퍼플팀 자동 보고서 생성기로 작성되었습니다.*",
    ]

    return "\n".join(lines)


def create_sample_data() -> PurpleTeamReport:
    """샘플 퍼플팀 결과 데이터를 생성합니다."""
    return PurpleTeamReport(
        engagement_name="2026 Q2 퍼플팀 평가",
        organization="ACME Corp",
        test_period_start="2026-04-01",
        test_period_end="2026-04-05",
        scope="내부망 전체 (DMZ 제외)",
        executive_notes=(
            "전체 탐지율 60%로 업계 평균(55%) 수준. "
            "자격증명 접근 관련 탐지가 취약하며 즉각 개선이 필요합니다."
        ),
        recommendations=[
            "LSASS 보호 모드(PPL) 활성화로 자격증명 덤핑 방어 강화",
            "PowerShell 스크립트 블록 로깅 전사 배포",
            "EDR 에이전트 커버리지를 95% 이상으로 확대",
            "SOC 탐지 룰 라이브러리를 Sigma 형식으로 표준화",
        ],
        techniques=[
            TechniqueResult(
                technique_id="T1059.001", technique_name="PowerShell",
                tactic="Execution", detected=True, blocked=False,
                detection_time_min=4.5, priority="P2",
                notes="ScriptBlock 로깅으로 탐지",
            ),
            TechniqueResult(
                technique_id="T1003.001", technique_name="LSASS Memory",
                tactic="Credential Access", detected=False, blocked=False,
                detection_time_min=None, priority="P1",
                remediation="Sysmon EID 10 룰 추가, LSASS PPL 활성화",
                notes="EDR 미탐지 - 갭 발견",
            ),
            TechniqueResult(
                technique_id="T1053.005", technique_name="Scheduled Task",
                tactic="Persistence", detected=True, blocked=False,
                detection_time_min=12.0, priority="P2",
                notes="Event ID 4698 탐지 룰 동작 확인",
            ),
            TechniqueResult(
                technique_id="T1021.001", technique_name="Remote Desktop",
                tactic="Lateral Movement", detected=False, blocked=False,
                detection_time_min=None, priority="P1",
                remediation="RDP 접근 위치 기반 탐지 룰 추가",
            ),
            TechniqueResult(
                technique_id="T1041", technique_name="Exfiltration Over C2",
                tactic="Exfiltration", detected=True, blocked=True,
                detection_time_min=8.2, priority="P2",
                notes="DLP 정책으로 차단됨",
            ),
            TechniqueResult(
                technique_id="T1082", technique_name="System Information Discovery",
                tactic="Discovery", detected=False, blocked=False,
                detection_time_min=None, priority="P3",
                remediation="호스트 기반 행위 탐지 강화",
            ),
        ],
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="퍼플팀 결과 → 마크다운 보고서 자동 생성기",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--input", "-i", type=Path, help="결과 JSON 파일 (없으면 샘플 사용)")
    parser.add_argument("--output", "-o", type=Path, default=Path("purple_team_report.md"),
                        help="출력 마크다운 파일 (기본: purple_team_report.md)")
    parser.add_argument("--preview", action="store_true", help="터미널에 미리보기 출력")
    args = parser.parse_args()

    if args.input and args.input.exists():
        raw = json.loads(args.input.read_text())
        # JSON에서 PurpleTeamReport 객체로 변환
        techniques = [TechniqueResult(**t) for t in raw.get("techniques", [])]
        report = PurpleTeamReport(
            engagement_name=raw.get("engagement_name", "퍼플팀 평가"),
            organization=raw.get("organization", "-"),
            test_period_start=raw.get("test_period_start", "-"),
            test_period_end=raw.get("test_period_end", "-"),
            scope=raw.get("scope", "-"),
            executive_notes=raw.get("executive_notes", ""),
            recommendations=raw.get("recommendations", []),
            techniques=techniques,
        )
    else:
        print("[*] 입력 파일 없음 - 샘플 데이터 사용")
        report = create_sample_data()

    stats = calculate_stats(report)
    markdown = generate_markdown(report, stats)

    args.output.write_text(markdown, encoding="utf-8")
    print(f"\n보고서 생성 완료: {args.output}")
    print(f"탐지율: {stats['detection_rate']}%  총 기법: {stats['total']}개  P1 갭: {stats['p1']}건")

    if args.preview:
        print("\n" + "=" * 70)
        print(markdown[:2000] + ("\n...(이하 생략)" if len(markdown) > 2000 else ""))


if __name__ == "__main__":
    main()
```

---

## 실무 적용 시나리오

1. **분기 보고**: 경영진에게 보안 탐지 커버리지 정기 보고
2. **예산 요청**: 갭 분석 결과를 기반으로 보안 투자 우선순위 제시
3. **컴플라이언스**: SOC2, ISO 27001 등 인증을 위한 보안 테스트 증빙

---

## 요약

| 보고서 섹션 | 대상 독자 | 핵심 내용 |
|---|---|---|
| 경영진 요약 | CISO, 경영진 | 탐지율, 최고 위험, 즉각 조치 |
| 기술적 발견 | SOC, 분석가 | ATT&CK 매핑, 로그 증거 |
| 갭 분석 | 블루팀 | 미탐지 기법, 개선 우선순위 |
| 개선 로드맵 | IT/보안팀 | 담당자, 기한, 측정 기준 |

---

<a name="english"></a>

# Purple Team Reporting

## Concept Overview

The final deliverable of purple team activity is the report. Like a doctor explaining diagnosis results to a patient in plain language, a purple team report must convey technical findings in a format understandable to both executives and technical staff.

---

## Report Components

### 1. Executive Summary
- Overall detection coverage rate
- Top 3–5 critical gaps
- Immediate action recommendations

### 2. Technical Findings
- Executed technique list (ATT&CK mapped)
- Detection success/failure results
- Evidence logs, timeline

### 3. Gap Analysis
```
Detection Gap = Techniques Executed - Techniques Detected
Coverage Rate = Detected / Total Executed × 100%
```

### 4. Improvement Roadmap

| Priority | Technique | Action | Owner | Deadline |
|---|---|---|---|---|
| P1 (Immediate) | T1003.001 | Add LSASS detection rule | SOC | 1 week |
| P2 (Short-term) | T1053.005 | Enable Task Scheduler audit | IT | 1 month |
| P3 (Medium-term) | T1021.001 | RDP location-based filter | Infra | 3 months |

---

## Summary Table

| Report Section | Audience | Key Content |
|---|---|---|
| Executive Summary | CISO, Management | Detection rate, top risks, immediate actions |
| Technical Findings | SOC, Analysts | ATT&CK mapping, log evidence |
| Gap Analysis | Blue team | Undetected techniques, improvement priorities |
| Improvement Roadmap | IT/Security | Owners, deadlines, metrics |
