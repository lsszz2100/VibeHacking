> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 레드팀 기초 개념

## 레드팀이란 무엇인가?

보안 세계에는 세 가지 색깔의 팀이 있습니다. 마치 체스판 위의 공격과 수비처럼, 각 팀은 서로 다른 역할을 맡습니다.

| 팀 | 역할 | 비유 |
|---|---|---|
| **레드팀 (Red Team)** | 공격자 역할, 실제 해커처럼 조직 침투 시도 | 성을 공격하는 병사 |
| **블루팀 (Blue Team)** | 방어자 역할, 시스템 모니터링·탐지·대응 | 성을 지키는 경비대 |
| **퍼플팀 (Purple Team)** | 레드+블루 협력, 공격 기술을 방어에 즉시 반영 | 훈련 코치 |

레드팀은 단순한 침투 테스터(Penetration Tester)와 다릅니다. 침투 테스트가 "어떤 취약점이 있는가?"를 찾는다면, 레드팀은 "실제 공격자가 우리의 크라운 쥬얼(Crown Jewel, 핵심 자산)에 도달할 수 있는가?"를 검증합니다.

```
침투 테스트:  취약점 발견 → 보고서 작성
레드팀 작전:  목표 설정 → 정보 수집 → 침투 → 이동 → 목표 달성 → 보고
```

---

## 레드팀 운영 목표와 범위

### 핵심 목표

레드팀 작전의 목표는 단순히 "뚫는 것"이 아닙니다. 조직의 **탐지·대응 능력**을 현실적으로 평가하는 것입니다.

1. **탐지 역량 평가**: 블루팀이 공격을 얼마나 빨리 탐지하는가?
2. **대응 역량 평가**: 탐지 후 얼마나 효과적으로 대응하는가?
3. **크라운 쥬얼 보호 수준 측정**: 핵심 자산이 실제로 안전한가?
4. **가정 검증**: "우리는 안전하다"는 가정이 맞는가?

### 범위(Scope) 정의

모든 레드팀 작전은 명확한 범위가 필요합니다.

```
포함 범위 예시:
  - IP 대역: 192.168.1.0/24 (내부망)
  - 도메인: *.example.com
  - 기간: 2024-01-01 ~ 2024-01-31 (30일)

제외 범위 예시:
  - 프로덕션 결제 서버 (서비스 중단 위험)
  - 의료 장비 시스템 (환자 안전 우선)
  - 물리적 공격 (건물 침입 등)
```

---

## 교전 규칙 (Rules of Engagement, RoE)

RoE는 레드팀 작전의 헌법입니다. 법적·윤리적 보호막 역할을 합니다.

### RoE 필수 항목

| 항목 | 설명 | 예시 |
|---|---|---|
| 승인된 목표 | 공격 허용 시스템 목록 | "내부 AD 서버만 허용" |
| 금지 기법 | 사용 불가 공격 방법 | "랜섬웨어 배포 금지" |
| 비상 연락처 | 긴급 상황 시 연락처 | CISO, SOC 팀장 |
| 식별 코드 | 레드팀임을 증명하는 코드 | "ALPHA-2024-RT" |
| 탈출 조항 | 작전 중단 조건 | "실제 공격 감지 시 즉시 중단" |

```python
# RoE 문서 생성 예시
from dataclasses import dataclass, field
from datetime import date
from typing import List

@dataclass
class RulesOfEngagement:
    operation_name: str
    start_date: date
    end_date: date
    approved_targets: List[str] = field(default_factory=list)
    prohibited_techniques: List[str] = field(default_factory=list)
    emergency_contact: str = ""
    identifier_code: str = ""

    def validate(self) -> bool:
        """RoE 유효성 검사"""
        if not self.approved_targets:
            raise ValueError("승인된 목표가 없습니다. 작전을 시작할 수 없습니다.")
        if not self.emergency_contact:
            raise ValueError("비상 연락처가 없습니다.")
        if self.start_date >= self.end_date:
            raise ValueError("시작일이 종료일보다 늦습니다.")
        return True

    def to_markdown(self) -> str:
        lines = [
            f"# 교전 규칙 — {self.operation_name}",
            f"**기간**: {self.start_date} ~ {self.end_date}",
            f"**식별 코드**: {self.identifier_code}",
            "",
            "## 승인된 목표",
        ]
        for t in self.approved_targets:
            lines.append(f"- {t}")
        lines += ["", "## 금지 기법"]
        for p in self.prohibited_techniques:
            lines.append(f"- {p}")
        lines.append(f"\n**비상 연락처**: {self.emergency_contact}")
        return "\n".join(lines)


if __name__ == "__main__":
    roe = RulesOfEngagement(
        operation_name="Operation Silent Storm",
        start_date=date(2024, 1, 1),
        end_date=date(2024, 1, 31),
        approved_targets=["192.168.1.0/24", "vpn.example.com"],
        prohibited_techniques=["랜섬웨어 배포", "DDoS", "물리적 침입"],
        emergency_contact="CISO: 010-1234-5678",
        identifier_code="ALPHA-2024-RT",
    )
    roe.validate()
    print(roe.to_markdown())
```

---

## APT 시뮬레이션 개념

APT(Advanced Persistent Threat)는 고도화된 지속적 위협입니다. 국가 지원 해킹 그룹이나 전문 사이버 범죄 집단이 대표적입니다.

### APT vs 일반 해커

```
일반 해커:     기회주의적, 단기, 쉬운 목표 선호
APT 그룹:      목표 지향적, 장기 잠복, 특정 조직 집중

APT 작전 흐름:
1. 정찰 (수개월 ~ 수년)
2. 초기 침투 (스피어피싱, 공급망 공격)
3. 거점 확보 (백도어 설치)
4. 내부 이동 (권한 상승, 횡이동)
5. 목표 달성 (데이터 탈취, 파괴)
6. 장기 잠복 (탐지 회피)
```

레드팀은 이러한 APT 행동 패턴을 시뮬레이션합니다. 단순히 취약점을 찾는 것이 아니라, 실제 APT처럼 행동하여 조직의 방어 체계가 얼마나 버티는지 테스트합니다.

---

## MITRE ATT&CK 프레임워크

MITRE ATT&CK는 실제 공격자의 전술(Tactics), 기법(Techniques), 절차(Procedures)를 체계화한 지식 베이스입니다.

### 14가지 전술(Tactics)

| 번호 | 전술 | 설명 |
|---|---|---|
| TA0043 | Reconnaissance | 정보 수집 |
| TA0042 | Resource Development | 공격 자원 준비 |
| TA0001 | Initial Access | 초기 침투 |
| TA0002 | Execution | 코드 실행 |
| TA0003 | Persistence | 지속성 유지 |
| TA0004 | Privilege Escalation | 권한 상승 |
| TA0005 | Defense Evasion | 방어 회피 |
| TA0006 | Credential Access | 자격 증명 탈취 |
| TA0007 | Discovery | 내부 탐색 |
| TA0008 | Lateral Movement | 횡이동 |
| TA0009 | Collection | 데이터 수집 |
| TA0011 | Command and Control | C2 통신 |
| TA0010 | Exfiltration | 데이터 유출 |
| TA0040 | Impact | 시스템 영향 |

```python
# MITRE ATT&CK 기법 조회 간단 예시
from typing import Dict, List

ATT_CK_TECHNIQUES: Dict[str, Dict] = {
    "T1566": {
        "name": "Phishing",
        "tactic": "Initial Access",
        "description": "피싱 이메일을 통한 초기 침투",
        "sub_techniques": ["T1566.001", "T1566.002", "T1566.003"],
    },
    "T1078": {
        "name": "Valid Accounts",
        "tactic": "Initial Access / Persistence",
        "description": "합법적 계정 탈취 후 사용",
        "sub_techniques": ["T1078.001", "T1078.002", "T1078.003", "T1078.004"],
    },
    "T1059": {
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "description": "스크립트 인터프리터를 이용한 코드 실행",
        "sub_techniques": ["T1059.001", "T1059.003", "T1059.004"],
    },
}


def search_technique(keyword: str) -> List[Dict]:
    """키워드로 ATT&CK 기법 검색"""
    results = []
    keyword_lower = keyword.lower()
    for tid, info in ATT_CK_TECHNIQUES.items():
        if (keyword_lower in info["name"].lower()
                or keyword_lower in info["description"].lower()):
            results.append({"id": tid, **info})
    return results


if __name__ == "__main__":
    found = search_technique("phishing")
    for tech in found:
        print(f"[{tech['id']}] {tech['name']} — {tech['tactic']}")
        print(f"  설명: {tech['description']}")
        print(f"  하위 기법: {', '.join(tech['sub_techniques'])}")
```

### ATT&CK 네비게이터 활용

ATT&CK Navigator는 레드팀이 사용한 기법을 시각화하는 도구입니다.

```
사용 방법:
1. https://mitre-attack.github.io/attack-navigator/ 접속
2. 새 레이어 생성
3. 사용한 기법 셀 클릭 → 색상 표시
4. 레드팀 커버리지 한눈에 파악
```

---

## 요약 정리

```
레드팀 = APT 시뮬레이션 + 목표 기반 침투 + 탐지·대응 평가

핵심 개념 체계:
  레드팀 작전
  ├── RoE (교전 규칙) — 법적·윤리적 보호
  ├── APT 시뮬레이션 — 실제 공격자 행동 모방
  └── MITRE ATT&CK — 표준화된 기법 분류 체계
```

**참고 자료**: [MITRE ATT&CK 공식 사이트](https://attack.mitre.org/)

---

<!-- safety-validate-75 -->
## 권한·안전 통제 검증

레드팀의 모든 활동은 **사전 서면 권한** 위에서만 성립합니다. RoE를 문서로 두는 것과, 작전 중 그 경계가 실제로 지켜지는지는 다릅니다 — 시작 전에 안전 통제를 검증해야 합니다.

| 통제 | 왜 필요한가 | 검증 |
|---|---|---|
| 서면 권한(authorization letter) | 무단 접근 누명 방지(get-out-of-jail) | 서명·기간·범위 명시 사본 보유 |
| 디컨플릭션 연락선 | 실사고와 훈련 혼동 방지 | 블루팀/SOC 비상 연락 사전 합의 |
| 중단(abort) 기준 | 운영 피해·실침해 발견 시 정지 | 트리거 정의(가용성 영향 등) |
| 범위 경계 | OOS 자산·제3자 피해 방지 | in-scope 목록과 제외 항목 확인 |

### 작전 전 검증 (직접)

```text
킥오프 전 확인:
  □ 서명된 권한서가 있고 유효기간·범위가 현 작전과 일치하는가?
  □ 디컨플릭션 연락처(블루팀)가 합의·기록됐는가?
  □ 중단 기준과 비상 정지 절차가 합의됐는가?
  □ 제외 자산·금지 행위가 팀 전원에게 공유됐는가?
```

> 핵심: 레드팀과 범죄를 가르는 것은 기법이 아니라 **권한과 통제**입니다. 권한서·디컨플릭션·중단 기준이 검증되지 않은 상태로 시작하면 훈련이 실사고가 됩니다([[68_Purple_Team]]).

**최신 기법·통제 (2025–2026):**
- 목표기반(assumed breach·TIBER-EU/CBEST 등 인텔주도) 레드팀이 표준 — ROE·승인·범위가 문서로 강제. 검증: 활동이 승인범위 내이고 재현 가능한가
- 퍼플팀 협업으로 탐지개선 루프 결합 — 발견이 방어 델타로 이어지는지 확인([[68_Purple_Team]])

---

<a name="english"></a>

# Red Team Fundamentals

## What Is a Red Team?

In the security world, there are three colored teams. Like offense and defense on a chessboard, each team plays a different role.

| Team | Role | Analogy |
|---|---|---|
| **Red Team** | Attacker role — attempts to infiltrate the organization like a real hacker | Soldiers attacking a castle |
| **Blue Team** | Defender role — monitors, detects, and responds to threats | Guards defending the castle |
| **Purple Team** | Red + Blue collaboration — immediately applies attack techniques to defense | Training coach |

A red team is different from a simple penetration tester. While penetration testing asks "What vulnerabilities exist?", red teaming validates "Can a real attacker reach our Crown Jewels (critical assets)?"

```
Penetration Test:  Find vulnerabilities → Write report
Red Team Operation: Set objectives → Reconnaissance → Infiltration → Movement → Achieve goal → Report
```

---

## Red Team Operational Goals and Scope

### Core Objectives

The goal of a red team operation is not simply to "break in." It is to realistically assess an organization's **detection and response capabilities**.

1. **Assess detection capability**: How quickly does the blue team detect an attack?
2. **Assess response capability**: How effectively do they respond after detection?
3. **Measure Crown Jewel protection level**: Are critical assets actually safe?
4. **Validate assumptions**: Is the assumption that "we are secure" correct?

### Defining Scope

Every red team operation needs a clearly defined scope.

```
In-scope example:
  - IP range: 192.168.1.0/24 (internal network)
  - Domain: *.example.com
  - Duration: 2024-01-01 ~ 2024-01-31 (30 days)

Out-of-scope example:
  - Production payment servers (risk of service disruption)
  - Medical device systems (patient safety first)
  - Physical attacks (building intrusion, etc.)
```

---

## Rules of Engagement (RoE)

RoE is the constitution of a red team operation. It serves as legal and ethical protection.

### Essential RoE Elements

| Element | Description | Example |
|---|---|---|
| Approved targets | List of systems authorized for attack | "Internal AD server only" |
| Prohibited techniques | Attack methods not permitted | "No ransomware deployment" |
| Emergency contact | Contact for urgent situations | CISO, SOC team lead |
| Identification code | Code to prove red team identity | "ALPHA-2024-RT" |
| Escape clause | Conditions for stopping the operation | "Stop immediately if real attack detected" |

```python
# RoE document generation example
from dataclasses import dataclass, field
from datetime import date
from typing import List

@dataclass
class RulesOfEngagement:
    operation_name: str
    start_date: date
    end_date: date
    approved_targets: List[str] = field(default_factory=list)
    prohibited_techniques: List[str] = field(default_factory=list)
    emergency_contact: str = ""
    identifier_code: str = ""

    def validate(self) -> bool:
        """Validate RoE completeness"""
        if not self.approved_targets:
            raise ValueError("No approved targets. Cannot start operation.")
        if not self.emergency_contact:
            raise ValueError("No emergency contact provided.")
        if self.start_date >= self.end_date:
            raise ValueError("Start date must be before end date.")
        return True

    def to_markdown(self) -> str:
        lines = [
            f"# Rules of Engagement — {self.operation_name}",
            f"**Duration**: {self.start_date} ~ {self.end_date}",
            f"**Identifier Code**: {self.identifier_code}",
            "",
            "## Approved Targets",
        ]
        for t in self.approved_targets:
            lines.append(f"- {t}")
        lines += ["", "## Prohibited Techniques"]
        for p in self.prohibited_techniques:
            lines.append(f"- {p}")
        lines.append(f"\n**Emergency Contact**: {self.emergency_contact}")
        return "\n".join(lines)


if __name__ == "__main__":
    roe = RulesOfEngagement(
        operation_name="Operation Silent Storm",
        start_date=date(2024, 1, 1),
        end_date=date(2024, 1, 31),
        approved_targets=["192.168.1.0/24", "vpn.example.com"],
        prohibited_techniques=["Ransomware deployment", "DDoS", "Physical intrusion"],
        emergency_contact="CISO: +1-555-1234",
        identifier_code="ALPHA-2024-RT",
    )
    roe.validate()
    print(roe.to_markdown())
```

---

## APT Simulation Concepts

APT (Advanced Persistent Threat) refers to highly sophisticated, long-term threats. Nation-state hacking groups and professional cybercrime organizations are typical examples.

### APT vs. Ordinary Hacker

```
Ordinary hacker:  Opportunistic, short-term, prefers easy targets
APT group:        Goal-oriented, long-term dormancy, focused on specific organization

APT Operation Flow:
1. Reconnaissance (months to years)
2. Initial access (spear phishing, supply chain attack)
3. Establish foothold (backdoor installation)
4. Internal movement (privilege escalation, lateral movement)
5. Achieve objective (data exfiltration, destruction)
6. Long-term dormancy (evade detection)
```

Red teams simulate these APT behavioral patterns. Rather than simply finding vulnerabilities, they act like real APT groups to test how well the organization's defenses hold up.

---

## MITRE ATT&CK Framework

MITRE ATT&CK is a knowledge base that systematizes the Tactics, Techniques, and Procedures (TTPs) of real-world attackers.

### 14 Tactics

| Number | Tactic | Description |
|---|---|---|
| TA0043 | Reconnaissance | Information gathering |
| TA0042 | Resource Development | Preparing attack resources |
| TA0001 | Initial Access | Initial infiltration |
| TA0002 | Execution | Code execution |
| TA0003 | Persistence | Maintaining persistence |
| TA0004 | Privilege Escalation | Gaining higher privileges |
| TA0005 | Defense Evasion | Avoiding detection |
| TA0006 | Credential Access | Stealing credentials |
| TA0007 | Discovery | Internal enumeration |
| TA0008 | Lateral Movement | Moving within the network |
| TA0009 | Collection | Collecting data |
| TA0011 | Command and Control | C2 communication |
| TA0010 | Exfiltration | Data exfiltration |
| TA0040 | Impact | Impacting systems |

```python
# Simple MITRE ATT&CK technique lookup example
from typing import Dict, List

ATT_CK_TECHNIQUES: Dict[str, Dict] = {
    "T1566": {
        "name": "Phishing",
        "tactic": "Initial Access",
        "description": "Initial access via phishing emails",
        "sub_techniques": ["T1566.001", "T1566.002", "T1566.003"],
    },
    "T1078": {
        "name": "Valid Accounts",
        "tactic": "Initial Access / Persistence",
        "description": "Use of stolen legitimate accounts",
        "sub_techniques": ["T1078.001", "T1078.002", "T1078.003", "T1078.004"],
    },
    "T1059": {
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "description": "Code execution via scripting interpreters",
        "sub_techniques": ["T1059.001", "T1059.003", "T1059.004"],
    },
}


def search_technique(keyword: str) -> List[Dict]:
    """Search ATT&CK techniques by keyword"""
    results = []
    keyword_lower = keyword.lower()
    for tid, info in ATT_CK_TECHNIQUES.items():
        if (keyword_lower in info["name"].lower()
                or keyword_lower in info["description"].lower()):
            results.append({"id": tid, **info})
    return results


if __name__ == "__main__":
    found = search_technique("phishing")
    for tech in found:
        print(f"[{tech['id']}] {tech['name']} — {tech['tactic']}")
        print(f"  Description: {tech['description']}")
        print(f"  Sub-techniques: {', '.join(tech['sub_techniques'])}")
```

### Using the ATT&CK Navigator

The ATT&CK Navigator is a tool for visualizing the techniques used by a red team.

```
How to use:
1. Visit https://mitre-attack.github.io/attack-navigator/
2. Create a new layer
3. Click cells for techniques used → Apply color coding
4. View red team coverage at a glance
```

---

## Summary

```
Red Team = APT Simulation + Objective-Based Infiltration + Detection/Response Assessment

Core Concept Framework:
  Red Team Operation
  ├── RoE (Rules of Engagement) — Legal and ethical protection
  ├── APT Simulation — Mimicking real attacker behavior
  └── MITRE ATT&CK — Standardized technique classification
```

**Reference**: [MITRE ATT&CK Official Site](https://attack.mitre.org/)

## Authorization and Safety-Control Validation

Every red team activity stands only on **prior written authorization**. Having an RoE document is not the same as the boundary actually being honored during the operation — validate safety controls before you start.

| Control | Why needed | Validation |
|---|---|---|
| Authorization letter | Avoids unauthorized-access liability (get-out-of-jail) | Hold a copy with signature, dates, scope |
| Deconfliction line | Avoids confusing a real incident with the exercise | Pre-agree blue team/SOC emergency contact |
| Abort criteria | Stop on operational harm/real compromise | Define triggers (e.g., availability impact) |
| Scope boundary | Prevent OOS asset/third-party harm | Confirm in-scope list and exclusions |

### Pre-op validation (do it yourself)

```text
Before kickoff, confirm:
  [ ] Is there a signed authorization whose validity/scope matches this op?
  [ ] Is a deconfliction contact (blue team) agreed and recorded?
  [ ] Are abort criteria and an emergency-stop procedure agreed?
  [ ] Are excluded assets/prohibited actions shared with the whole team?
```

> Core: what separates a red team from a crime is not technique but **authorization and control**. Starting without validated authorization, deconfliction, and abort criteria turns an exercise into a real incident (see [[68_Purple_Team]]).
