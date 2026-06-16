> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 위협 에뮬레이션 (Threat Emulation)

## 개념 소개

위협 에뮬레이션은 특정 APT(Advanced Persistent Threat) 그룹의 실제 전술, 기법, 절차(TTP)를 최대한 충실하게 재현하는 고급 보안 테스트 기법입니다. 일반적인 취약점 스캐닝과 달리, 실제 공격자가 어떻게 움직이는지를 그대로 따라합니다. 마치 배우가 특정 인물의 말투와 행동 방식까지 연구해서 연기하는 것과 같습니다.

---

## APT 그룹 프로파일

### 주요 APT 그룹 특징

| 그룹 | 별칭 | 주요 산업 | 특징 TTP |
|---|---|---|---|
| APT29 | Cozy Bear | 정부, 외교 | WellMess, SUNBURST, Supply Chain |
| APT41 | Winnti | 게임, 의료 | 이중 스파이+사이버범죄 |
| Lazarus | APT38 | 금융, 암호화폐 | 워터링 홀, 공급망 |
| FIN7 | Carbanak | 금융, 소매 | 스피어피싱, POS 악성코드 |
| BlackCat | ALPHV | 다양 | Rust 랜섬웨어, 데이터 유출 협박 |

### TTP 에뮬레이션 절차

```
1. 인텔리전스 수집
   - CTI 보고서 분석 (Mandiant, CrowdStrike, CISA 권고)
   - MITRE ATT&CK Groups 페이지 참조

2. TTP 매핑
   - 사용 도구 목록 (예: APT29 → Cobalt Strike, BloodHound)
   - 공격 체인 순서 정의

3. 에뮬레이션 계획 수립
   - 스코프, 목표, 성공 기준 정의
   - 안전장치 (Kill Switch, Abort 조건)

4. 실행 및 관찰
   - 단계별 실행 후 블루팀과 실시간 공유

5. 보고 및 개선
   - 탐지 갭, 개선 우선순위, 재테스트 계획
```

### SCYTHE, OpenTIDE, CTID

- **SCYTHE**: 상용 위협 에뮬레이션 플랫폼
- **CTID (Center for Threat-Informed Defense)**: MITRE 산하, 에뮬레이션 계획 오픈소스 제공
- **OpenTIDE**: 오픈소스 TTP 데이터 공유 플랫폼

---

## Python 실습: APT 프로파일 기반 TTP 시나리오 생성기

```python
#!/usr/bin/env python3
"""
APT 그룹 프로파일을 기반으로 위협 에뮬레이션 시나리오를 자동 생성합니다.
"""

import argparse
import json
import random
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class TtpStep:
    order: int
    tactic: str
    technique_id: str
    technique_name: str
    tool: str
    command_description: str
    detection_hint: str
    ioc: str


@dataclass
class AptProfile:
    group_id: str
    name: str
    aliases: list[str]
    target_sectors: list[str]
    motivation: str
    ttps: list[dict]
    preferred_tools: list[str]


@dataclass
class EmulationPlan:
    apt_group: str
    scenario_name: str
    scope: str
    steps: list[TtpStep] = field(default_factory=list)
    total_techniques: int = 0
    estimated_duration_hours: float = 0.0


# APT 그룹 프로파일 데이터베이스
APT_PROFILES: list[dict] = [
    {
        "group_id": "G0016",
        "name": "APT29",
        "aliases": ["Cozy Bear", "The Dukes", "NOBELIUM"],
        "target_sectors": ["Government", "Defense", "Think Tanks", "Healthcare"],
        "motivation": "Espionage",
        "preferred_tools": ["Cobalt Strike", "BloodHound", "Mimikatz", "SUNBURST"],
        "ttps": [
            {
                "tactic": "Initial Access",
                "technique_id": "T1195.002",
                "technique_name": "Compromise Software Supply Chain",
                "tool": "SUNBURST/Solorigate",
                "command": "SolarWinds 업데이트 패키지에 백도어 삽입",
                "detection": "소프트웨어 빌드 파이프라인 무결성 모니터링, 코드 서명 검증",
                "ioc": "SolarWinds.Orion.Core.BusinessLayer.dll 해시 이상",
            },
            {
                "tactic": "Defense Evasion",
                "technique_id": "T1027",
                "technique_name": "Obfuscated Files or Information",
                "tool": "WellMess/WellMail",
                "command": "Go 언어로 작성된 맞춤형 백도어 배포",
                "detection": "Go 바이너리 특성 탐지, 비정상 네트워크 패턴",
                "ioc": "Go HTTP 클라이언트 User-Agent 이상",
            },
            {
                "tactic": "Credential Access",
                "technique_id": "T1003.001",
                "technique_name": "LSASS Memory",
                "tool": "Mimikatz",
                "command": "sekurlsa::logonpasswords",
                "detection": "Sysmon EID 10: LSASS 접근, Windows Defender ATP",
                "ioc": "mimikatz.exe, sekurlsa 문자열",
            },
            {
                "tactic": "Discovery",
                "technique_id": "T1482",
                "technique_name": "Domain Trust Discovery",
                "tool": "BloodHound/SharpHound",
                "command": "SharpHound.exe -c All",
                "detection": "과도한 LDAP 쿼리, AD 객체 대량 접근",
                "ioc": "BloodHound 실행 아티팩트",
            },
            {
                "tactic": "Lateral Movement",
                "technique_id": "T1021.006",
                "technique_name": "Windows Remote Management",
                "tool": "Evil-WinRM",
                "command": "winrm 5985/5986 포트 활용 원격 명령 실행",
                "detection": "WinRM 연결 이벤트, 비정상 소스 IP",
                "ioc": "WinRM 연결 EID 4624 타입3",
            },
        ],
    },
    {
        "group_id": "G0082",
        "name": "APT41",
        "aliases": ["Winnti", "Double Dragon", "BARIUM"],
        "target_sectors": ["Gaming", "Healthcare", "Technology", "Telecommunications"],
        "motivation": "Espionage + Financial",
        "preferred_tools": ["PlugX", "ShadowPad", "Cobalt Strike", "DEADEYE"],
        "ttps": [
            {
                "tactic": "Initial Access",
                "technique_id": "T1190",
                "technique_name": "Exploit Public-Facing Application",
                "tool": "CVE-2021-44228 (Log4Shell) 등",
                "command": "공개 서비스 취약점 원격 익스플로잇",
                "detection": "WAF 로그, 애플리케이션 예외 패턴",
                "ioc": "JNDI 조회 문자열: ${jndi:ldap://}",
            },
            {
                "tactic": "Persistence",
                "technique_id": "T1574.002",
                "technique_name": "DLL Side-Loading",
                "tool": "ShadowPad",
                "command": "정상 서명된 앱에 악성 DLL 사이드로딩",
                "detection": "DLL 로드 이벤트, 모듈 서명 불일치",
                "ioc": "정상 앱 디렉토리의 비표준 DLL",
            },
            {
                "tactic": "Exfiltration",
                "technique_id": "T1048",
                "technique_name": "Exfiltration Over Alternative Protocol",
                "tool": "PlugX",
                "command": "DNS 터널링으로 데이터 유출",
                "detection": "비정상적으로 긴 DNS 쿼리, 높은 DNS 빈도",
                "ioc": "서브도메인 길이 > 60자",
            },
        ],
    },
    {
        "group_id": "G0032",
        "name": "Lazarus",
        "aliases": ["APT38", "Hidden Cobra", "ZINC"],
        "target_sectors": ["Finance", "Cryptocurrency", "Defense"],
        "motivation": "Financial + Espionage",
        "preferred_tools": ["AppleJeus", "BLINDINGCAN", "HOPLIGHT"],
        "ttps": [
            {
                "tactic": "Initial Access",
                "technique_id": "T1566.002",
                "technique_name": "Spearphishing Link",
                "tool": "맞춤형 피싱 이메일",
                "command": "암호화폐 거래소 직원 대상 스피어피싱",
                "detection": "이메일 보안 게이트웨이, URL 평판 필터",
                "ioc": "금융 테마 피싱 도메인",
            },
            {
                "tactic": "Impact",
                "technique_id": "T1529",
                "technique_name": "System Shutdown/Reboot",
                "tool": "KillDisk",
                "command": "MBR 파괴 후 시스템 재부팅",
                "detection": "드라이버 로드 이벤트, MBR 접근 모니터링",
                "ioc": "KillDisk 특성 바이트 패턴",
            },
        ],
    },
]


def build_apt_database() -> dict[str, AptProfile]:
    db: dict[str, AptProfile] = {}
    for data in APT_PROFILES:
        profile = AptProfile(
            group_id=data["group_id"],
            name=data["name"],
            aliases=data["aliases"],
            target_sectors=data["target_sectors"],
            motivation=data["motivation"],
            ttps=data["ttps"],
            preferred_tools=data["preferred_tools"],
        )
        db[data["name"].lower()] = profile
        for alias in data["aliases"]:
            db[alias.lower()] = profile
    return db


def generate_emulation_plan(
    profile: AptProfile,
    scope: str = "Internal Network",
    max_steps: int | None = None,
    seed: int = 42,
) -> EmulationPlan:
    """APT 프로파일에서 에뮬레이션 계획을 생성합니다."""
    rng = random.Random(seed)
    ttps = profile.ttps
    if max_steps:
        ttps = ttps[:max_steps]

    plan = EmulationPlan(
        apt_group=f"{profile.name} ({profile.group_id})",
        scenario_name=f"{profile.name} TTP 에뮬레이션",
        scope=scope,
        total_techniques=len(ttps),
        estimated_duration_hours=len(ttps) * 0.5,
    )

    for i, ttp in enumerate(ttps):
        step = TtpStep(
            order=i + 1,
            tactic=ttp["tactic"],
            technique_id=ttp["technique_id"],
            technique_name=ttp["technique_name"],
            tool=ttp["tool"],
            command_description=ttp["command"],
            detection_hint=ttp["detection"],
            ioc=ttp["ioc"],
        )
        plan.steps.append(step)

    return plan


def print_plan(plan: EmulationPlan) -> None:
    print(f"\n{'='*70}")
    print(f"위협 에뮬레이션 계획")
    print(f"APT 그룹: {plan.apt_group}")
    print(f"시나리오: {plan.scenario_name}")
    print(f"스코프: {plan.scope}")
    print(f"기법 수: {plan.total_techniques}개  예상 소요: {plan.estimated_duration_hours}시간")
    print(f"{'='*70}")

    for step in plan.steps:
        print(f"\n[단계 {step.order}] {step.tactic} → {step.technique_id}: {step.technique_name}")
        print(f"  도구: {step.tool}")
        print(f"  실행: {step.command_description}")
        print(f"  탐지: {step.detection_hint}")
        print(f"  IOC:  {step.ioc}")


def export_plan_json(plan: EmulationPlan, path: Path) -> None:
    data = {
        "apt_group": plan.apt_group,
        "scenario": plan.scenario_name,
        "scope": plan.scope,
        "steps": [
            {
                "order": s.order, "tactic": s.tactic,
                "technique_id": s.technique_id, "technique_name": s.technique_name,
                "tool": s.tool, "command": s.command_description,
                "detection_hint": s.detection_hint, "ioc": s.ioc,
            }
            for s in plan.steps
        ],
    }
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False))


def main() -> None:
    parser = argparse.ArgumentParser(description="APT 프로파일 기반 TTP 시나리오 생성기")
    parser.add_argument("--list", action="store_true", help="APT 그룹 목록 출력")
    parser.add_argument("--apt", type=str, default="apt29", help="APT 그룹 이름")
    parser.add_argument("--scope", type=str, default="Internal Network", help="테스트 스코프")
    parser.add_argument("--max-steps", type=int, help="최대 단계 수")
    parser.add_argument("--output", "-o", type=Path, help="JSON 출력 파일")
    args = parser.parse_args()

    db = build_apt_database()

    if args.list:
        seen = set()
        print("\n지원되는 APT 그룹:")
        for profile in APT_PROFILES:
            if profile["name"] not in seen:
                seen.add(profile["name"])
                sectors = ", ".join(profile["target_sectors"][:3])
                print(f"  {profile['name']} ({profile['group_id']}) - {profile['motivation']}")
                print(f"    대상: {sectors}")
        return

    key = args.apt.lower()
    profile = db.get(key)
    if not profile:
        print(f"[오류] APT 그룹을 찾을 수 없습니다: {args.apt}")
        print(f"사용 가능: {[p['name'] for p in APT_PROFILES]}")
        return

    plan = generate_emulation_plan(
        profile, scope=args.scope, max_steps=args.max_steps
    )
    print_plan(plan)

    if args.output:
        export_plan_json(plan, args.output)
        print(f"\n계획 저장: {args.output}")


if __name__ == "__main__":
    main()
```

---

## 실무 적용 시나리오

1. **CISO 보고**: 조직이 직면한 실제 위협 그룹의 TTP 기반 위험 평가
2. **탐지 갭 식별**: 특정 APT 체인에서 현재 탐지 불가 구간 발견
3. **레드팀 계획**: CTI 기반으로 현실적인 공격 시나리오 수립

---

## 정보 기반 위협 우선순위 (Threat-Informed Prioritization)

모든 APT를 에뮬레이션할 수는 없습니다. "우리 조직을 실제로 노릴 가능성"을 기준으로 좁혀야 자원이 낭비되지 않습니다.

| 선정 기준 | 질문 | 출처 |
|---|---|---|
| 산업 표적성 | 우리 산업을 노린 이력이 있는가 | CTI 보고서, ISAC 공유 |
| 지역/지정학 | 우리 지역·정치적 맥락과 연관되는가 | 정부 권고(CISA, KISA) |
| 능력 수준 | 우리 방어 수준 대비 현실적 위협인가 | ATT&CK Groups 매핑 |
| 최근 활동성 | 최근 12개월 내 활동 보고가 있는가 | 위협 인텔 피드 |

선정 후에는 ATT&CK Navigator에 해당 그룹의 기법을 레이어로 올리고, 우리 탐지 커버리지와 겹쳐 "이 그룹 기준 우리의 사각지대"를 시각화합니다.

---

## 에뮬레이션 충실도 vs 안전성

위협 에뮬레이션의 가치는 "충실도(fidelity)"에 있지만, 실제 악성 도구·페이로드를 그대로 쓰는 것은 위험하고 불필요합니다. 목표는 **방어가 보는 신호를 동일하게 만드는 것**이지 실제 피해를 재현하는 것이 아닙니다.

| 차원 | 고충실도 방식 | 안전한 대체 |
|---|---|---|
| 페이로드 | 실제 멀웨어 실행 | 무해한 EICAR/시뮬레이터로 동일 행위 신호 발생 |
| C2 | 실제 공격자 인프라 | 통제된 랩 C2(Caldera) + 동일 비컨 패턴 |
| 파괴 기법 | 실제 암호화/삭제 | 더미 파일·격리 볼륨에서만 |
| 자격증명 | 운영 계정 탈취 | 사전 생성한 테스트 계정 |

> 핵심: "공격자가 남기는 텔레메트리"를 재현하면 탐지 검증 목적은 충분히 달성됩니다. 실제 파괴 효과는 검증 대상이 아니라 회피해야 할 부작용입니다. 본 섹션의 시나리오 생성기처럼 계획·매핑 단계는 자동화하되, 파괴적 영향이 있는 단계는 항상 격리 환경과 명시적 승인 하에서만 수행합니다.

---

## 요약

| 항목 | 내용 |
|---|---|
| APT 에뮬레이션 | 실제 위협 그룹 TTP 충실 재현 |
| CTI 활용 | 보고서 → ATT&CK 매핑 → 에뮬레이션 |
| 주요 플랫폼 | SCYTHE, CTID, Cobalt Strike |
| 산출물 | TTP 에뮬레이션 계획서, 갭 리포트 |

---

<a name="english"></a>

# Threat Emulation

## Concept Overview

Threat emulation faithfully reproduces the actual Tactics, Techniques, and Procedures (TTPs) of specific APT groups — like an actor studying not just words but every gesture and speaking style of a character. Unlike generic vulnerability scanning, this follows exactly how real attackers operate.

---

## APT Group Profiles

| Group | Alias | Target Sectors | Characteristic TTPs |
|---|---|---|---|
| APT29 | Cozy Bear | Government, Defense | Supply chain, WellMess |
| APT41 | Winnti | Gaming, Healthcare | Dual espionage/crime |
| Lazarus | APT38 | Finance, Crypto | Watering hole, supply chain |
| FIN7 | Carbanak | Finance, Retail | Spearphishing, POS malware |

### Emulation Process

```
1. Collect intelligence (CTI reports, MITRE ATT&CK Groups)
2. Map TTPs (tools list, attack chain order)
3. Build emulation plan (scope, goals, success criteria)
4. Execute and observe (share with blue team in real time)
5. Report and improve (gaps, priorities, retest plan)
```

---

### Threat-Informed Prioritization

You can't emulate every APT. Narrow by "realistic likelihood of targeting us" so resources aren't wasted.

| Criterion | Question | Source |
|---|---|---|
| Sector targeting | History of hitting our industry? | CTI reports, ISAC sharing |
| Geo/geopolitics | Tied to our region/political context? | Government advisories (CISA, KISA) |
| Capability level | Realistic threat vs our defenses? | ATT&CK Groups mapping |
| Recency | Reported activity in the last 12 months? | Threat intel feeds |

After selection, load the group's techniques as an ATT&CK Navigator layer and overlay your detection coverage to visualize your blind spots relative to that group.

### Emulation Fidelity vs Safety

The value of emulation is *fidelity*, but using real malware/payloads is dangerous and unnecessary. The goal is to **reproduce the signals defenders see**, not to recreate real damage.

| Dimension | High-fidelity way | Safe substitute |
|---|---|---|
| Payload | Run real malware | Harmless EICAR/simulator producing the same behavior signal |
| C2 | Real attacker infra | Controlled lab C2 (Caldera) + same beacon pattern |
| Destructive technique | Real encryption/wipe | Dummy files / isolated volume only |
| Credentials | Steal production accounts | Pre-created test accounts |

> Key: reproducing "the telemetry an attacker leaves" fully satisfies detection-validation goals. Real destructive effect is not the thing under test — it's a side effect to avoid. Automate the planning/mapping stages (like the scenario generator here), but run destructive-impact steps only in isolation under explicit approval.

## Summary Table

| Item | Details |
|---|---|
| APT emulation | Faithful reproduction of real threat group TTPs |
| CTI utilization | Reports → ATT&CK mapping → Emulation |
| Key platforms | SCYTHE, CTID, Cobalt Strike |
| Deliverables | TTP emulation plan, gap report |
