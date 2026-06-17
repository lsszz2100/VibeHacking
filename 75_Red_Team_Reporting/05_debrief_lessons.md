> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 디브리핑과 레슨런

## 디브리핑이란?

레드팀 작전이 종료되면 가장 중요한 단계 중 하나가 시작됩니다. 바로 **디브리핑(Debriefing)**입니다.

디브리핑은 작전에서 일어난 일을 모든 관계자(레드팀, 블루팀, 경영진)가 함께 검토하는 회의입니다. 군사 용어로는 "작전 사후 검토(After Action Review)"라고도 합니다.

```
디브리핑 없는 레드팀 = 시험 점수만 주고 오답 해설이 없는 시험
디브리핑 있는 레드팀 = 오답 원인을 찾고 다음에 틀리지 않도록 학습
```

---

## 디브리핑 프로세스

### 1단계: 레드팀 내부 디브리핑 (작전 완료 후 1~2일)

레드팀끼리 먼저 모여 작전 전체를 복기합니다.

```
내부 디브리핑 아젠다:
  - 목표 달성 여부 확인
  - 작전 중 발생한 문제점 공유
  - 예상치 못한 탐지 발생 시 원인 분석
  - 각 오퍼레이터 피드백 수렴
  - 보고서 발견사항 초안 검토
```

### 2단계: 블루팀 디브리핑 (작전 완료 후 3~5일)

레드팀이 블루팀에게 전체 공격 경로를 공개합니다.

```
블루팀 디브리핑 핵심:
  - "우리가 언제, 어디서 탐지했는가?" vs "레드팀이 실제로 한 것"
  - 탐지 실패 지점 분석
  - 탐지 성공 지점 분석 (잘한 것도 인정)
  - SIEM 규칙 개선 방향 논의
  - EDR/NDR 탐지 커버리지 점검
```

### 3단계: 경영진 디브리핑 (작전 완료 후 1~2주)

경영진에게 비즈니스 언어로 결과를 설명합니다.

```
경영진 디브리핑 핵심:
  - 크라운 쥬얼이 위협받았는가?
  - 현재 보안 투자가 효과적인가?
  - 무엇을 얼마의 비용으로 개선해야 하는가?
  - 다음 레드팀 작전 예산 확보 필요성
```

---

## 레슨런(Lessons Learned) 도출

레슨런은 "이번 작전에서 배운 것"을 체계적으로 정리한 것입니다.

### 레슨런 4가지 카테고리

| 카테고리 | 질문 | 예시 |
|---|---|---|
| **잘한 것 (What Went Well)** | 어떤 방어가 효과적이었나? | "EDR이 Mimikatz를 즉시 탐지함" |
| **못한 것 (What Went Wrong)** | 어떤 방어가 실패했나? | "피싱 이메일이 필터를 통과함" |
| **놀라운 것 (Surprises)** | 예상치 못한 것은? | "공격자가 3일간 탐지 안됨" |
| **개선할 것 (Improvements)** | 다음에 무엇을 바꿀 것인가? | "LSASS PPL 즉시 적용" |

### 레슨런 워크숍 진행 방법

```
1. 침묵 브레인스토밍 (5분)
   - 각자 포스트잇에 레슨런 작성
   - 카테고리별로 구분

2. 공유 (15분)
   - 각자 발표, 중복 항목 합치기

3. 우선순위 투표 (10분)
   - 가장 중요한 레슨런에 점 스티커

4. 액션 아이템 도출 (15분)
   - 각 레슨런을 구체적 행동으로 전환
   - 담당자 + 기한 배정
```

---

## 블루팀 피드백 수렴 방법

### 피드백 수렴 설문 예시

```
[레드팀 작전 블루팀 피드백 설문]

1. 레드팀 작전 중 탐지한 활동은 몇 퍼센트라고 생각하십니까?
   □ 0-25%  □ 26-50%  □ 51-75%  □ 76-100%

2. 가장 탐지하기 어려웠던 기법은 무엇입니까?
   (자유 응답)

3. 어떤 도구/기법이 가장 유용했습니까?
   □ SIEM 규칙  □ EDR  □ 행동 분석  □ 네트워크 모니터링

4. 레드팀 작전이 우리 팀의 탐지 역량 향상에 도움이 되었습니까?
   □ 매우 도움됨  □ 도움됨  □ 보통  □ 도움 안됨

5. 다음 레드팀 작전에서 집중해야 할 영역은?
   (자유 응답)
```

---

## 퍼플팀 연습으로 전환

디브리핑 이후 가장 효과적인 보안 개선 방법은 **퍼플팀 연습**입니다.

```
퍼플팀 연습 흐름:

1. 레드팀이 특정 기법 실행
   예) T1003.001 — LSASS 메모리 덤프

2. 블루팀이 즉시 탐지 시도
   - SIEM 경보 발생하는가?
   - EDR이 탐지/차단하는가?

3. 탐지 실패 시 즉시 규칙 개선
   - 탐지 로직 추가
   - 시그니처 업데이트

4. 다음 기법으로 반복
```

퍼플팀 연습은 레드팀이 발견한 취약점을 실시간으로 방어력 향상에 활용하는 가장 빠른 방법입니다.

---

## 보안 개선 로드맵 제안

디브리핑 결과를 바탕으로 3단계 로드맵을 제안합니다.

| 기간 | 항목 | 우선순위 |
|---|---|---|
| **즉시 (1주)** | Critical 취약점 패치, PPL 적용 | P0 |
| **단기 (1개월)** | MFA 도입, SIEM 규칙 강화 | P1 |
| **중기 (3개월)** | PAW 구축, EDR 커버리지 확장 | P2 |
| **장기 (6개월~)** | Zero Trust 아키텍처 도입 | P3 |

---

## Python 디브리핑 슬라이드 Markdown 생성기

```python
#!/usr/bin/env python3
"""
레드팀 디브리핑 슬라이드 Markdown 생성기
사용법: python3 05_debrief_lessons.py --name "Operation X" --output debrief.md
"""

import argparse
import sys
from dataclasses import dataclass, field
from datetime import date
from typing import List, Literal


LessonCategory = Literal["well", "wrong", "surprise", "improvement"]

CATEGORY_LABELS = {
    "well": ("잘한 것", "What Went Well"),
    "wrong": ("못한 것", "What Went Wrong"),
    "surprise": ("놀라운 발견", "Surprises"),
    "improvement": ("개선 사항", "Improvements"),
}


@dataclass
class LessonLearned:
    category: LessonCategory
    description: str
    action_item: str = ""
    owner: str = ""
    due_date: str = ""


@dataclass
class DetectionResult:
    technique_id: str
    technique_name: str
    detected: bool
    detection_method: str = ""
    time_to_detect_hours: float | None = None
    notes: str = ""


@dataclass
class DebriefSlide:
    operation_name: str
    debrief_date: date
    operation_duration_days: int
    lessons: List[LessonLearned] = field(default_factory=list)
    detection_results: List[DetectionResult] = field(default_factory=list)

    def add_lesson(self, lesson: LessonLearned) -> None:
        if not lesson.description.strip():
            raise ValueError("레슨런 설명이 비어 있습니다.")
        self.lessons.append(lesson)

    def add_detection_result(self, result: DetectionResult) -> None:
        self.detection_results.append(result)

    def _detection_rate(self) -> float:
        if not self.detection_results:
            return 0.0
        detected = sum(1 for r in self.detection_results if r.detected)
        return detected / len(self.detection_results) * 100

    def _generate_lessons_section(self) -> List[str]:
        lines: List[str] = ["## 레슨런 (Lessons Learned)", ""]
        for category in ("well", "wrong", "surprise", "improvement"):
            label_kr, label_en = CATEGORY_LABELS[category]  # type: ignore[literal-required]
            items = [l for l in self.lessons if l.category == category]
            if not items:
                continue
            lines += [f"### {label_kr} / {label_en}", ""]
            for item in items:
                lines.append(f"- {item.description}")
                if item.action_item:
                    lines.append(f"  - **액션**: {item.action_item}")
                if item.owner:
                    lines.append(f"  - **담당**: {item.owner}")
                if item.due_date:
                    lines.append(f"  - **기한**: {item.due_date}")
            lines.append("")
        return lines

    def _generate_detection_section(self) -> List[str]:
        if not self.detection_results:
            return []
        rate = self._detection_rate()
        lines: List[str] = [
            "## 탐지율 분석 (Detection Rate Analysis)", "",
            f"**전체 탐지율**: {rate:.1f}% "
            f"({sum(1 for r in self.detection_results if r.detected)}/{len(self.detection_results)})",
            "",
            "| 기법 ID | 기법명 | 탐지 여부 | 탐지 방법 | 탐지 시간 |",
            "|---|---|---|---|---|",
        ]
        for r in self.detection_results:
            detected_str = "탐지됨" if r.detected else "미탐지"
            detect_time = f"{r.time_to_detect_hours:.1f}h" if r.time_to_detect_hours is not None else "-"
            lines.append(
                f"| {r.technique_id} | {r.technique_name} | {detected_str} "
                f"| {r.detection_method or '-'} | {detect_time} |"
            )
        lines.append("")
        return lines

    def _generate_roadmap_section(self) -> List[str]:
        improvement_items = [l for l in self.lessons if l.category == "improvement"]
        if not improvement_items:
            return []
        lines = ["## 개선 로드맵 (Improvement Roadmap)", "",
                 "| 기간 | 개선 항목 | 담당 | 기한 |",
                 "|---|---|---|---|"]
        for item in improvement_items:
            lines.append(
                f"| 단기 | {item.description} "
                f"| {item.owner or '미정'} | {item.due_date or '미정'} |"
            )
        lines.append("")
        return lines

    def to_markdown(self) -> str:
        sections: List[List[str]] = [
            [
                f"# 레드팀 디브리핑 슬라이드",
                f"",
                f"| 항목 | 내용 |",
                f"|---|---|",
                f"| 작전명 | {self.operation_name} |",
                f"| 디브리핑 일자 | {self.debrief_date} |",
                f"| 작전 기간 | {self.operation_duration_days}일 |",
                f"| 발견사항 수 | {len(self.lessons)}개 레슨런 |",
                f"",
                f"---",
                f"",
                f"## 작전 개요 (Operation Overview)",
                f"",
                f"> 레드팀은 {self.operation_duration_days}일간 작전을 수행하였습니다.",
                f"> 탐지율: **{self._detection_rate():.1f}%**",
                f"",
                f"---",
            ],
            self._generate_detection_section(),
            ["---", ""],
            self._generate_lessons_section(),
            ["---", ""],
            self._generate_roadmap_section(),
            [
                "---",
                "",
                "## 다음 단계 (Next Steps)",
                "",
                "1. Critical 발견사항 즉시 패치",
                "2. 퍼플팀 연습 일정 수립",
                "3. SIEM 탐지 규칙 업데이트",
                "4. 3개월 후 재검증 레드팀 작전 계획",
            ],
        ]
        return "\n".join(line for section in sections for line in section)


def demo_debrief() -> DebriefSlide:
    """데모 디브리핑 슬라이드 생성"""
    debrief = DebriefSlide(
        operation_name="Operation Silent Storm",
        debrief_date=date.today(),
        operation_duration_days=30,
    )

    debrief.add_detection_result(DetectionResult(
        technique_id="T1566.001",
        technique_name="Spearphishing Attachment",
        detected=False,
        notes="이메일 필터 우회 성공",
    ))
    debrief.add_detection_result(DetectionResult(
        technique_id="T1003.001",
        technique_name="LSASS Memory Dump",
        detected=True,
        detection_method="EDR (Defender for Endpoint)",
        time_to_detect_hours=2.5,
    ))
    debrief.add_detection_result(DetectionResult(
        technique_id="T1550.002",
        technique_name="Pass the Hash",
        detected=False,
        notes="SIEM 규칙 없음",
    ))

    debrief.add_lesson(LessonLearned(
        category="well",
        description="EDR이 LSASS 메모리 덤프를 2.5시간 내 탐지함",
        action_item="EDR 탐지 규칙을 다른 시스템에도 확대 적용",
        owner="SOC 팀",
        due_date="2024-02-15",
    ))
    debrief.add_lesson(LessonLearned(
        category="wrong",
        description="스피어피싱 이메일이 이메일 게이트웨이를 통과함",
        action_item="이메일 샌드박스 솔루션 도입 또는 기존 솔루션 정책 강화",
        owner="인프라 팀",
        due_date="2024-02-01",
    ))
    debrief.add_lesson(LessonLearned(
        category="surprise",
        description="Pass-the-Hash 탐지 SIEM 규칙이 전혀 없었음",
    ))
    debrief.add_lesson(LessonLearned(
        category="improvement",
        description="LSASS Protected Process Light(PPL) 즉시 적용",
        action_item="GPO를 통한 전사 PPL 배포",
        owner="시스템 팀",
        due_date="2024-01-20",
    ))
    debrief.add_lesson(LessonLearned(
        category="improvement",
        description="Pass-the-Hash 탐지 SIEM 규칙 추가",
        action_item="이벤트 ID 4624 Logon Type 3 + 비정상 시간 상관 규칙 작성",
        owner="SOC 팀",
        due_date="2024-01-31",
    ))
    return debrief


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="레드팀 디브리핑 슬라이드 Markdown 생성기",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="예시:\n  python3 05_debrief_lessons.py --demo --output debrief.md",
    )
    parser.add_argument("--name", default="Red Team Operation", help="작전 이름")
    parser.add_argument("--demo", action="store_true", help="데모 데이터로 슬라이드 생성")
    parser.add_argument("--output", help="출력 파일 경로 (미지정 시 stdout)")
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    if args.demo:
        debrief = demo_debrief()
    else:
        print("현재는 --demo 옵션만 지원됩니다.", file=sys.stderr)
        print("예: python3 05_debrief_lessons.py --demo --output debrief.md", file=sys.stderr)
        sys.exit(1)

    markdown = debrief.to_markdown()

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(markdown)
            print(f"디브리핑 슬라이드가 저장되었습니다: {args.output}")
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
# 데모 슬라이드 생성
python3 05_debrief_lessons.py --demo --output debrief.md

# 결과 미리보기 (콘솔 출력)
python3 05_debrief_lessons.py --demo
```

---

## 디브리핑 성공 체크리스트

```
레드팀 내부 디브리핑:
[ ] 모든 오퍼레이터 참석
[ ] 각 공격 단계 재검토 완료
[ ] 도구 효과성 평가 완료
[ ] 개선할 TTP 목록 작성

블루팀 디브리핑:
[ ] 탐지/미탐지 매트릭스 공유
[ ] 탐지 실패 원인 분석 완료
[ ] SIEM 개선 액션 아이템 배정
[ ] EDR 정책 검토 완료

경영진 디브리핑:
[ ] 비즈니스 언어 보고서 준비
[ ] 크라운 쥬얼 위협 수준 명확히 전달
[ ] 예산 투자 권고사항 제시
[ ] 다음 작전 일정 논의
```

---

<!-- safety-validate-75 -->
## 정리(클린업)와 개선 검증 (재테스트)

작전은 보고서로 끝나지 않습니다. **남긴 흔적을 정리**하고, 권고한 개선이 **실제로 작동하는지 재테스트**해야 가치가 완성됩니다. 이 단계가 레드팀을 퍼플팀 사이클로 연결합니다.

| 단계 | 왜 | 확인 |
|---|---|---|
| 아티팩트 정리 | 임플란트·계정·파일 잔존은 새 위험 | 생성물 목록화 후 제거/인계 |
| 변경 원복 | 가역 변경 복구 | 변경 로그 기준 원상복구 |
| 권고 추적 | 보고만으로는 안 고쳐짐 | 소유자·기한 지정 |
| 재테스트 | 수정이 진짜 막는지 | 동일 TTP 재현해 차단 확인 |

### 개선 검증 (직접)

```text
작전 종료 후:
  □ 만든 계정·임플란트·파일·룰을 모두 목록화하고 제거/인계했는가?
  □ 가역 변경을 원상복구했는가? (변경 로그 대조)
  □ 각 권고에 담당자·기한이 지정됐는가?
  □ 핵심 발견을 재테스트해 이제는 탐지·차단되는지 확인했는가?
```

> 핵심: 레드팀의 진짜 산출물은 보고서가 아니라 **방어 개선**입니다. 흔적을 정리해 새 위험을 남기지 말고, 권고한 수정이 동일 공격을 실제로 막는지 재테스트로 확인하세요 — 그것이 퍼플팀으로 가는 다리입니다([[68_Purple_Team]]).

---

<a name="english"></a>

# Debriefing and Lessons Learned

## What Is a Debrief?

After a red team operation concludes, one of the most important phases begins: the **Debriefing**.

A debrief is a meeting where all stakeholders (red team, blue team, executives) review what happened during the operation together. In military terms, this is also called an "After Action Review (AAR)."

```
Red team without debrief = Receiving a test score without seeing the answer key
Red team with debrief   = Finding the root cause of errors and learning not to repeat them
```

---

## Debrief Process

### Step 1: Red Team Internal Debrief (1–2 days after operation)

The red team meets first to review the entire operation.

```
Internal Debrief Agenda:
  - Confirm whether objectives were achieved
  - Share problems encountered during the operation
  - Analyze root cause of any unexpected detections
  - Collect feedback from each operator
  - Review draft report findings
```

### Step 2: Blue Team Debrief (3–5 days after operation)

The red team reveals the complete attack path to the blue team.

```
Blue Team Debrief Focus:
  - "When and where did we detect?" vs "What the red team actually did"
  - Analyze detection failure points
  - Acknowledge detection success points (credit good work too)
  - Discuss SIEM rule improvement directions
  - Review EDR/NDR detection coverage
```

### Step 3: Executive Debrief (1–2 weeks after operation)

Results are explained to executives in business language.

```
Executive Debrief Focus:
  - Were the Crown Jewels at risk?
  - Is current security investment effective?
  - What needs to be improved, and at what cost?
  - Justification for next red team operation budget
```

---

## Deriving Lessons Learned

Lessons Learned is a systematic summary of "what we learned from this operation."

### Four Categories of Lessons Learned

| Category | Question | Example |
|---|---|---|
| **What Went Well** | What defenses were effective? | "EDR immediately detected Mimikatz" |
| **What Went Wrong** | What defenses failed? | "Phishing email bypassed the filter" |
| **Surprises** | What was unexpected? | "Attacker undetected for 3 days" |
| **Improvements** | What will we change next time? | "Apply LSASS PPL immediately" |

### Lessons Learned Workshop Method

```
1. Silent brainstorming (5 minutes)
   - Everyone writes lessons on sticky notes
   - Categorize by type

2. Share (15 minutes)
   - Everyone presents; merge duplicates

3. Priority voting (10 minutes)
   - Dot-vote on most important lessons

4. Action item derivation (15 minutes)
   - Convert each lesson into a concrete action
   - Assign owner + deadline
```

---

## Collecting Blue Team Feedback

### Sample Feedback Survey

```
[Red Team Operation Blue Team Feedback Survey]

1. What percentage of red team activities do you think you detected?
   □ 0-25%  □ 26-50%  □ 51-75%  □ 76-100%

2. Which techniques were most difficult to detect?
   (Open answer)

3. Which tools/techniques were most useful?
   □ SIEM rules  □ EDR  □ Behavioral analysis  □ Network monitoring

4. Did the red team operation help improve your team's detection capability?
   □ Very helpful  □ Helpful  □ Neutral  □ Not helpful

5. What area should the next red team operation focus on?
   (Open answer)
```

---

## Transitioning to Purple Team Exercises

After debriefing, the most effective method of security improvement is **purple team exercises**.

```
Purple Team Exercise Flow:

1. Red team executes a specific technique
   Example: T1003.001 — LSASS Memory Dump

2. Blue team immediately attempts detection
   - Does a SIEM alert fire?
   - Does EDR detect/block it?

3. If detection fails, immediately improve rules
   - Add detection logic
   - Update signatures

4. Repeat with next technique
```

Purple team exercises are the fastest way to directly leverage red team findings to improve defensive capabilities in real time.

---

## Proposing a Security Improvement Roadmap

Based on debrief results, a 3-tier roadmap is proposed.

| Timeline | Item | Priority |
|---|---|---|
| **Immediate (1 week)** | Patch Critical findings, apply PPL | P0 |
| **Short-term (1 month)** | Deploy MFA, strengthen SIEM rules | P1 |
| **Mid-term (3 months)** | Build PAW, expand EDR coverage | P2 |
| **Long-term (6+ months)** | Adopt Zero Trust architecture | P3 |

---

## Python Debrief Slide Markdown Generator

```python
#!/usr/bin/env python3
"""
Red Team Debrief Slide Markdown Generator
Usage: python3 05_debrief_lessons.py --demo --output debrief.md
"""

import argparse
import sys
from dataclasses import dataclass, field
from datetime import date
from typing import List, Literal


LessonCategory = Literal["well", "wrong", "surprise", "improvement"]

CATEGORY_LABELS = {
    "well": "What Went Well",
    "wrong": "What Went Wrong",
    "surprise": "Surprises",
    "improvement": "Improvements",
}


@dataclass
class LessonLearned:
    category: LessonCategory
    description: str
    action_item: str = ""
    owner: str = ""
    due_date: str = ""


@dataclass
class DetectionResult:
    technique_id: str
    technique_name: str
    detected: bool
    detection_method: str = ""
    time_to_detect_hours: float | None = None


@dataclass
class DebriefSlide:
    operation_name: str
    debrief_date: date
    operation_duration_days: int
    lessons: List[LessonLearned] = field(default_factory=list)
    detection_results: List[DetectionResult] = field(default_factory=list)

    def _detection_rate(self) -> float:
        if not self.detection_results:
            return 0.0
        return sum(1 for r in self.detection_results if r.detected) / len(self.detection_results) * 100

    def to_markdown(self) -> str:
        lines = [
            f"# Red Team Debrief Slide — {self.operation_name}",
            f"",
            f"**Debrief Date**: {self.debrief_date}",
            f"**Operation Duration**: {self.operation_duration_days} days",
            f"**Overall Detection Rate**: {self._detection_rate():.1f}%",
            f"",
            f"---",
            f"",
            f"## Detection Rate Analysis",
            f"",
            f"| Technique ID | Name | Detected | Method | Time |",
            f"|---|---|---|---|---|",
        ]
        for r in self.detection_results:
            status = "Detected" if r.detected else "Missed"
            t = f"{r.time_to_detect_hours:.1f}h" if r.time_to_detect_hours is not None else "-"
            lines.append(f"| {r.technique_id} | {r.technique_name} | {status} | {r.detection_method or '-'} | {t} |")

        lines += ["", "---", "", "## Lessons Learned", ""]
        for category in ("well", "wrong", "surprise", "improvement"):
            items = [l for l in self.lessons if l.category == category]
            if not items:
                continue
            lines += [f"### {CATEGORY_LABELS[category]}", ""]  # type: ignore[literal-required]
            for item in items:
                lines.append(f"- {item.description}")
                if item.action_item:
                    lines.append(f"  - **Action**: {item.action_item}")
                if item.owner:
                    lines.append(f"  - **Owner**: {item.owner}")
                if item.due_date:
                    lines.append(f"  - **Due**: {item.due_date}")
            lines.append("")

        lines += [
            "---",
            "",
            "## Next Steps",
            "",
            "1. Patch Critical findings immediately",
            "2. Schedule purple team exercises",
            "3. Update SIEM detection rules",
            "4. Plan follow-up red team in 3 months",
        ]
        return "\n".join(lines)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Red Team Debrief Slide Generator")
    parser.add_argument("--demo", action="store_true", help="Generate with demo data")
    parser.add_argument("--output", help="Output file path (stdout if not specified)")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if not args.demo:
        print("Use --demo to generate a sample debrief slide.", file=sys.stderr)
        sys.exit(1)

    debrief = DebriefSlide(
        operation_name="Operation Silent Storm",
        debrief_date=date.today(),
        operation_duration_days=30,
    )
    debrief.detection_results = [
        DetectionResult("T1566.001", "Spearphishing Attachment", False, notes="Email filter bypass"),
        DetectionResult("T1003.001", "LSASS Memory Dump", True, "EDR", time_to_detect_hours=2.5),
        DetectionResult("T1550.002", "Pass the Hash", False),
    ]
    debrief.lessons = [
        LessonLearned("well", "EDR detected LSASS dump within 2.5 hours", "Expand EDR rules", "SOC Team", "2024-02-15"),
        LessonLearned("wrong", "Phishing email bypassed email gateway", "Evaluate sandboxing solutions", "Infra Team"),
        LessonLearned("surprise", "No SIEM rules for Pass-the-Hash detection"),
        LessonLearned("improvement", "Apply PPL to LSASS enterprise-wide", "Deploy via GPO", "Sys Team", "2024-01-20"),
    ]

    output = debrief.to_markdown()
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(output)
        print(f"Saved to: {args.output}")
    else:
        print(output)


if __name__ == "__main__":
    main()
```

### Usage Examples

```bash
# Generate demo slide
python3 05_debrief_lessons.py --demo --output debrief.md

# Preview in console
python3 05_debrief_lessons.py --demo
```

---

## Debrief Success Checklist

```
Red Team Internal Debrief:
[ ] All operators in attendance
[ ] Each attack phase reviewed
[ ] Tool effectiveness evaluated
[ ] List of TTPs to improve documented

Blue Team Debrief:
[ ] Detection/miss matrix shared
[ ] Root cause of detection failures analyzed
[ ] SIEM improvement action items assigned
[ ] EDR policy review completed

Executive Debrief:
[ ] Business-language report prepared
[ ] Crown Jewel risk level clearly communicated
[ ] Budget investment recommendations presented
[ ] Next operation timeline discussed
```

## Cleanup and Improvement Validation (retest)

An operation does not end with the report. You must **clean up the traces left** and **retest whether recommended fixes actually work** to complete the value. This step connects red teaming to the purple team cycle.

| Step | Why | Check |
|---|---|---|
| Artifact cleanup | Lingering implants/accounts/files are new risk | Inventory then remove/hand off creations |
| Change rollback | Recover reversible changes | Restore per the change log |
| Recommendation tracking | Reporting alone doesn't fix it | Assign owners and deadlines |
| Retest | Confirm fixes truly block | Reproduce the same TTP, confirm blocked |

### Improvement validation (do it yourself)

```text
After the operation:
  [ ] Inventoried and removed/handed off all accounts/implants/files/rules created?
  [ ] Restored reversible changes? (against the change log)
  [ ] Assigned an owner and deadline to each recommendation?
  [ ] Retested key findings to confirm they are now detected/blocked?
```

> Core: a red team's real deliverable is not the report but **improved defense**. Clean up traces so you leave no new risk, and use a retest to confirm the recommended fixes actually block the same attack — that is the bridge to purple teaming (see [[68_Purple_Team]]).
