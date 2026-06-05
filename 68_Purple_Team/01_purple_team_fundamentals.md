> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 퍼플팀 기초 (Purple Team Fundamentals)

## 개념 소개

퍼플팀은 레드팀(공격자 관점)과 블루팀(방어자 관점)이 협력하는 통합 보안 테스트 방법론입니다. 마치 농구팀의 공격 코치와 수비 코치가 함께 연습해서 팀 전체 실력을 높이듯, 퍼플팀은 공격자와 방어자가 실시간으로 지식을 공유하여 보안 역량을 함께 향상시킵니다.

---

## 레드팀 vs 블루팀 vs 퍼플팀

| 구분 | 역할 | 방식 | 한계 |
|---|---|---|---|
| 레드팀 | 공격자 시뮬레이션 | 독립 실행 | 블루팀이 배움 기회 부족 |
| 블루팀 | 방어, 탐지, 대응 | 반응적 | 실제 공격 패턴 학습 제한 |
| 퍼플팀 | 공격+방어 협업 | 협력적 | 시간/비용 더 필요 |

## ATT&CK 프레임워크 기반 협업

MITRE ATT&CK는 실제 위협 행위자가 사용하는 전술(Tactic), 기법(Technique), 절차(Procedure)를 체계화한 지식 베이스입니다.

### ATT&CK 매트릭스 구조

```
전술 (Tactic) → 기법 (Technique) → 서브기법 (Sub-technique)

예시:
Persistence (지속성)
  └─ T1053: Scheduled Task/Job
       ├─ T1053.001: At (Linux)
       ├─ T1053.003: Cron
       └─ T1053.005: Scheduled Task (Windows)
```

### 퍼플팀 운영 흐름

```
1. 계획  → 위협 모델링, ATT&CK 기법 선택
2. 공격  → 레드팀 기법 실행
3. 실시간 공유 → "지금 이 기법을 사용했음"
4. 탐지 검증 → 블루팀 탐지 여부 확인
5. 갭 분석 → 탐지 실패 원인 분석
6. 개선  → 탐지 룰/대응 절차 개선
```

---

## Python 실습: ATT&CK 테크닉 매핑 도구

```python
#!/usr/bin/env python3
"""
MITRE ATT&CK 테크닉 정보를 관리하고 퍼플팀 테스트 매핑을 생성합니다.
외부 API 없이 로컬 JSON 데이터로 동작합니다.
"""

import argparse
import json
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class AttackTechnique:
    technique_id: str
    name: str
    tactic: str
    description: str
    platforms: list[str] = field(default_factory=list)
    detection: str = ""
    sub_techniques: list[str] = field(default_factory=list)


@dataclass
class PurpleTestCase:
    technique_id: str
    test_name: str
    objective: str
    red_action: str
    detection_expected: str
    actual_detected: bool = False
    gap_notes: str = ""


# 내장 ATT&CK 테크닉 데이터베이스 (교육용 샘플)
BUILTIN_TECHNIQUES: list[dict] = [
    {
        "id": "T1059.001",
        "name": "PowerShell",
        "tactic": "Execution",
        "description": "PowerShell을 사용하여 악성 명령 실행",
        "platforms": ["Windows"],
        "detection": "PowerShell 로깅, ScriptBlock 로깅 활성화",
        "sub_techniques": [],
    },
    {
        "id": "T1053.005",
        "name": "Scheduled Task",
        "tactic": "Persistence",
        "description": "작업 스케줄러를 이용한 지속성 확보",
        "platforms": ["Windows"],
        "detection": "Event ID 4698 (작업 생성), schtasks 프로세스 모니터링",
        "sub_techniques": ["T1053"],
    },
    {
        "id": "T1003.001",
        "name": "LSASS Memory",
        "tactic": "Credential Access",
        "description": "LSASS 프로세스 메모리에서 자격증명 덤프",
        "platforms": ["Windows"],
        "detection": "LSASS 접근 프로세스 감사, Sysmon Event ID 10",
        "sub_techniques": ["T1003"],
    },
    {
        "id": "T1055.001",
        "name": "DLL Injection",
        "tactic": "Defense Evasion",
        "description": "정상 프로세스에 악성 DLL 주입",
        "platforms": ["Windows"],
        "detection": "메모리 보호 변경 감지, VirtualAllocEx 호출 모니터링",
        "sub_techniques": ["T1055"],
    },
    {
        "id": "T1071.001",
        "name": "Web Protocols",
        "tactic": "Command and Control",
        "description": "HTTP/HTTPS를 통한 C2 통신",
        "platforms": ["Windows", "Linux", "macOS"],
        "detection": "비정상 User-Agent, 비컨 패턴, 도메인 평판",
        "sub_techniques": ["T1071"],
    },
    {
        "id": "T1021.001",
        "name": "Remote Desktop Protocol",
        "tactic": "Lateral Movement",
        "description": "RDP를 통한 내부망 횡이동",
        "platforms": ["Windows"],
        "detection": "Event ID 4624 (타입 10), 비정상 RDP 연결",
        "sub_techniques": ["T1021"],
    },
    {
        "id": "T1083",
        "name": "File and Directory Discovery",
        "tactic": "Discovery",
        "description": "파일 시스템 탐색 및 민감 파일 발견",
        "platforms": ["Windows", "Linux", "macOS"],
        "detection": "대량 파일 접근 패턴, dir/ls 명령 모니터링",
        "sub_techniques": [],
    },
    {
        "id": "T1041",
        "name": "Exfiltration Over C2 Channel",
        "tactic": "Exfiltration",
        "description": "C2 채널을 통한 데이터 유출",
        "platforms": ["Windows", "Linux", "macOS"],
        "detection": "대용량 아웃바운드 트래픽, 비정상 데이터 전송",
        "sub_techniques": [],
    },
    {
        "id": "T1486",
        "name": "Data Encrypted for Impact",
        "tactic": "Impact",
        "description": "랜섬웨어 - 데이터 암호화",
        "platforms": ["Windows", "Linux", "macOS"],
        "detection": "대량 파일 수정, 볼륨 섀도 삭제, 파일 확장자 변경",
        "sub_techniques": [],
    },
    {
        "id": "T1078",
        "name": "Valid Accounts",
        "tactic": "Initial Access",
        "description": "유효한 계정 자격증명 악용",
        "platforms": ["Windows", "Linux", "macOS", "Cloud"],
        "detection": "비정상 로그인 시간/위치, 실패 후 성공 패턴",
        "sub_techniques": ["T1078.001", "T1078.002", "T1078.003"],
    },
]


class AttackDatabase:
    """ATT&CK 테크닉 데이터베이스"""

    def __init__(self, techniques: list[dict] | None = None):
        self._db: dict[str, AttackTechnique] = {}
        for t in (techniques or BUILTIN_TECHNIQUES):
            tech = AttackTechnique(
                technique_id=t["id"],
                name=t["name"],
                tactic=t["tactic"],
                description=t["description"],
                platforms=t.get("platforms", []),
                detection=t.get("detection", ""),
                sub_techniques=t.get("sub_techniques", []),
            )
            self._db[tech.technique_id] = tech

    def get(self, technique_id: str) -> AttackTechnique | None:
        return self._db.get(technique_id)

    def search(self, keyword: str) -> list[AttackTechnique]:
        kw = keyword.lower()
        return [
            t for t in self._db.values()
            if kw in t.name.lower()
            or kw in t.tactic.lower()
            or kw in t.description.lower()
        ]

    def by_tactic(self, tactic: str) -> list[AttackTechnique]:
        tactic_lower = tactic.lower()
        return [t for t in self._db.values() if tactic_lower in t.tactic.lower()]

    def all_tactics(self) -> list[str]:
        return sorted({t.tactic for t in self._db.values()})

    def export_json(self, path: Path) -> None:
        data = [
            {
                "id": t.technique_id, "name": t.name, "tactic": t.tactic,
                "description": t.description, "platforms": t.platforms,
                "detection": t.detection,
            }
            for t in self._db.values()
        ]
        path.write_text(json.dumps(data, indent=2, ensure_ascii=False))


def build_test_plan(db: AttackDatabase, tactics: list[str]) -> list[PurpleTestCase]:
    """주어진 전술 목록으로 퍼플팀 테스트 계획을 생성합니다."""
    test_cases: list[PurpleTestCase] = []
    for tactic in tactics:
        techniques = db.by_tactic(tactic)
        for tech in techniques[:2]:  # 전술당 최대 2개
            test_cases.append(PurpleTestCase(
                technique_id=tech.technique_id,
                test_name=f"{tech.technique_id}: {tech.name}",
                objective=f"{tactic} 기법 탐지 검증",
                red_action=tech.description,
                detection_expected=tech.detection,
            ))
    return test_cases


def print_technique(tech: AttackTechnique) -> None:
    print(f"\n  [{tech.technique_id}] {tech.name}")
    print(f"  전술: {tech.tactic}  플랫폼: {', '.join(tech.platforms)}")
    print(f"  설명: {tech.description}")
    print(f"  탐지: {tech.detection}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="ATT&CK 테크닉 매핑 도구",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="cmd")

    # search 서브커맨드
    search_p = sub.add_parser("search", help="키워드로 테크닉 검색")
    search_p.add_argument("keyword", help="검색 키워드")

    # tactic 서브커맨드
    tactic_p = sub.add_parser("tactic", help="전술별 테크닉 목록")
    tactic_p.add_argument("tactic_name", nargs="?", default="all", help="전술명")

    # plan 서브커맨드
    plan_p = sub.add_parser("plan", help="퍼플팀 테스트 계획 생성")
    plan_p.add_argument("tactics", nargs="+", help="테스트할 전술 목록")
    plan_p.add_argument("--output", "-o", type=Path, help="JSON 출력 파일")

    # export 서브커맨드
    export_p = sub.add_parser("export", help="전체 DB를 JSON으로 내보내기")
    export_p.add_argument("output", type=Path)

    args = parser.parse_args()
    db = AttackDatabase()

    if args.cmd == "search":
        results = db.search(args.keyword)
        print(f"\n'{args.keyword}' 검색 결과: {len(results)}개")
        for tech in results:
            print_technique(tech)

    elif args.cmd == "tactic":
        if args.tactic_name == "all":
            print("\n전술 목록:")
            for tactic in db.all_tactics():
                techs = db.by_tactic(tactic)
                print(f"  {tactic}: {len(techs)}개")
        else:
            techs = db.by_tactic(args.tactic_name)
            print(f"\n[{args.tactic_name}] 테크닉 {len(techs)}개:")
            for tech in techs:
                print_technique(tech)

    elif args.cmd == "plan":
        test_cases = build_test_plan(db, args.tactics)
        print(f"\n퍼플팀 테스트 계획 ({len(test_cases)}개 케이스)")
        print(f"{'='*60}")
        for i, tc in enumerate(test_cases, 1):
            print(f"\n[{i}] {tc.test_name}")
            print(f"    목표: {tc.objective}")
            print(f"    레드액션: {tc.red_action}")
            print(f"    탐지 기대: {tc.detection_expected}")
        if args.output:
            data = [
                {"id": tc.technique_id, "test": tc.test_name,
                 "red": tc.red_action, "detection": tc.detection_expected}
                for tc in test_cases
            ]
            args.output.write_text(json.dumps(data, indent=2, ensure_ascii=False))
            print(f"\n계획 저장: {args.output}")

    elif args.cmd == "export":
        db.export_json(args.output)
        print(f"내보내기 완료: {args.output}")

    else:
        # 기본: 전술 요약 출력
        print("\nATT&CK 테크닉 데이터베이스")
        print(f"총 {len(db._db)}개 테크닉  |  전술 {len(db.all_tactics())}개")
        for tactic in db.all_tactics():
            techs = db.by_tactic(tactic)
            print(f"  {tactic}: {len(techs)}개")
        print("\n사용법: python3 01_purple_team.py search <키워드>")
        print("        python3 01_purple_team.py tactic Persistence")
        print("        python3 01_purple_team.py plan Persistence 'Lateral Movement'")


if __name__ == "__main__":
    main()
```

---

## 실무 적용 시나리오

1. **보안 성숙도 평가**: ATT&CK 매트릭스에서 현재 탐지 커버리지 시각화
2. **우선순위 결정**: 위협 인텔리전스 기반으로 조직에 맞는 기법 선택
3. **팀 훈련**: 레드팀이 기법을 실행하고 블루팀이 실시간으로 대응 학습

---

## 요약

| 항목 | 내용 |
|---|---|
| 퍼플팀 목적 | 공격+방어 협업으로 탐지 역량 향상 |
| ATT&CK | TTP 기반 체계적 위협 분류 |
| 갭 분석 | 탐지 실패 원인 파악 및 룰 개선 |
| 핵심 산출물 | 탐지 커버리지 맵, 개선 로드맵 |

---

<a name="english"></a>

# Purple Team Fundamentals

## Concept Overview

Purple Team combines red team (attacker perspective) and blue team (defender perspective) in collaborative security testing. Like offensive and defensive coaches practicing together to improve the whole team, purple teams share knowledge in real time to jointly strengthen security posture.

---

## Comparison

| Team | Role | Approach | Limitation |
|---|---|---|---|
| Red Team | Attacker simulation | Independent | Blue team learns little |
| Blue Team | Detect, respond | Reactive | Limited exposure to real TTPs |
| Purple Team | Attack + defense collaboration | Cooperative | More time/cost required |

## ATT&CK Framework

MITRE ATT&CK systematizes the Tactics, Techniques, and Procedures (TTPs) used by real threat actors.

### Purple Team Workflow

```
1. Plan    → Threat modeling, select ATT&CK techniques
2. Attack  → Red team executes technique
3. Share   → "This technique was just used"
4. Verify  → Check if blue team detected it
5. Gap analysis → Analyze detection failures
6. Improve → Update detection rules and procedures
```

---

## Summary Table

| Item | Details |
|---|---|
| Purple team goal | Improve detection via attack/defense collaboration |
| ATT&CK | TTP-based systematic threat classification |
| Gap analysis | Identify detection failures, improve rules |
| Key output | Detection coverage map, improvement roadmap |
