> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# TTP 문서화 — 전술·기법·절차 기록

## TTP란 무엇인가?

TTP는 **Tactics(전술), Techniques(기법), Procedures(절차)**의 약자입니다. 공격자가 "무엇을 원하는지(전술)", "어떻게 달성하는지(기법)", "구체적으로 어떤 방식으로 실행하는지(절차)"를 기술합니다.

```
전술 (Tactic):    목적, 공격자가 달성하려는 것
                  예) 초기 침투 (Initial Access)

기법 (Technique): 목적을 달성하는 방법
                  예) 스피어피싱 (T1566 Phishing)

절차 (Procedure): 기법의 구체적 실행 방식
                  예) "Emotet 악성코드 첨부 PDF를 재무팀 직원에게 발송"
```

TTP 문서화는 레드팀 작전의 핵심 산출물입니다. 이것이 없으면 "무엇을 했는지"는 알지만, "왜 했는지"와 "어떻게 대응해야 하는지"를 알 수 없습니다.

---

## MITRE ATT&CK 기법 매핑 실습

### 매핑 프로세스

1. 레드팀이 수행한 행동 목록 작성
2. 각 행동을 ATT&CK 기법 ID와 연결
3. 전술(Tactic) 분류
4. 하위 기법(Sub-technique) 특정

### 실습 예시

레드팀이 다음 행동을 수행했다고 가정합니다:

```
[수행한 행동]
1. 대상 회사 LinkedIn에서 직원 목록 수집
2. 직원 이메일 주소 추측 (first.last@company.com 패턴)
3. 악성 Excel 매크로 파일 첨부 이메일 발송
4. 매크로 실행 → PowerShell로 C2 연결
5. Mimikatz로 LSASS 메모리 덤프 → 해시 추출
6. Pass-the-Hash로 도메인 컨트롤러 접근
7. NTDS.dit 파일 복사
```

```
[ATT&CK 매핑 결과]
행동 1: T1591.004 — Gather Victim Org Information (LinkedIn)
행동 2: T1598.003 — Phishing for Information (Email address guessing)
행동 3: T1566.001 — Phishing: Spearphishing Attachment
행동 4: T1059.001 — Command and Scripting Interpreter: PowerShell
행동 5: T1003.001 — OS Credential Dumping: LSASS Memory
행동 6: T1550.002 — Use Alternate Authentication Material: Pass the Hash
행동 7: T1003.003 — OS Credential Dumping: NTDS
```

---

## 공격 타임라인 재구성

TTP 문서화의 핵심 중 하나는 공격 타임라인을 시간 순서로 재구성하는 것입니다. 이는 블루팀이 탐지 실패 지점을 파악하는 데 매우 유용합니다.

```
타임라인 예시:

2024-01-05 09:15  정찰: LinkedIn OSINT로 직원 12명 식별
2024-01-05 14:30  무기화: 악성 Excel 파일 제작
2024-01-08 10:02  전달: 피싱 이메일 발송 (수신자: 재무팀 직원 3명)
2024-01-08 10:47  실행: 피해자 A가 매크로 활성화
2024-01-08 10:48  설치: PowerShell 기반 임플란트 설치
2024-01-08 11:05  C2: HTTPS C2 채널 확립 (비콘 간격: 60초)
2024-01-09 14:22  권한 상승: SeDebugPrivilege 획득
2024-01-09 14:25  자격 증명 탈취: LSASS 메모리 덤프
2024-01-09 15:10  횡이동: DC01 서버 접근 (Pass-the-Hash)
2024-01-10 09:30  목표 달성: NTDS.dit 탈취 (크라운 쥬얼)
```

---

## IOC(침해 지표) 목록 작성

IOC는 공격이 발생했음을 나타내는 증거물입니다. 블루팀의 탐지 규칙 개선에 직접 활용됩니다.

| IOC 유형 | 예시 | 설명 |
|---|---|---|
| IP 주소 | 203.0.113.42 | C2 서버 IP |
| 도메인 | update.microsoft-cdn.xyz | C2 도메인 (타이포스쿼팅) |
| 파일 해시 | SHA256: a3f2b1... | 악성 파일 해시 |
| 레지스트리 키 | HKCU\Software\...\Run | 지속성 레지스트리 |
| 뮤텍스 | Global\MUTEX_12345 | 악성코드 고유 식별자 |
| 사용자 에이전트 | Mozilla/5.0 (custom) | C2 HTTP 헤더 |
| 파일 경로 | C:\Users\...\AppData\Temp\svch0st.exe | 임플란트 경로 |

---

## Python ATT&CK 매핑 자동화 코드

다음 코드는 공격 행동 목록을 입력받아 ATT&CK 매핑 매트릭스를 출력합니다.

```python
#!/usr/bin/env python3
"""
ATT&CK TTP 매핑 자동화 도구
사용법: python3 03_ttps_documentation.py --input actions.txt
        python3 03_ttps_documentation.py --interactive
"""

import argparse
import json
import sys
from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class AttackTechnique:
    technique_id: str
    name: str
    tactic: str
    description: str
    detection_hint: str = ""
    sub_technique_of: Optional[str] = None


# 실전에서 자주 사용되는 기법 데이터베이스
TECHNIQUE_DB: Dict[str, AttackTechnique] = {
    "T1566.001": AttackTechnique(
        technique_id="T1566.001",
        name="Spearphishing Attachment",
        tactic="Initial Access",
        description="악성 첨부 파일이 포함된 스피어피싱 이메일 발송",
        detection_hint="이메일 게이트웨이 로그, 첨부 파일 샌드박스 분석",
        sub_technique_of="T1566",
    ),
    "T1059.001": AttackTechnique(
        technique_id="T1059.001",
        name="PowerShell",
        tactic="Execution",
        description="PowerShell 인터프리터를 이용한 악성 명령 실행",
        detection_hint="PowerShell 스크립트 블록 로깅, 인코딩된 명령어 탐지",
        sub_technique_of="T1059",
    ),
    "T1003.001": AttackTechnique(
        technique_id="T1003.001",
        name="LSASS Memory",
        tactic="Credential Access",
        description="LSASS 프로세스 메모리에서 자격 증명 추출",
        detection_hint="LSASS 접근 이벤트 ID 4656, Sysmon Event 10",
        sub_technique_of="T1003",
    ),
    "T1550.002": AttackTechnique(
        technique_id="T1550.002",
        name="Pass the Hash",
        tactic="Lateral Movement",
        description="NTLM 해시를 이용한 인증 없이 원격 시스템 접근",
        detection_hint="이벤트 ID 4624 (Logon Type 3), 비정상적 시간대 로그인",
        sub_technique_of="T1550",
    ),
    "T1003.003": AttackTechnique(
        technique_id="T1003.003",
        name="NTDS",
        tactic="Credential Access",
        description="Active Directory NTDS.dit 데이터베이스에서 자격 증명 추출",
        detection_hint="Volume Shadow Copy 접근 로그, ntdsutil.exe 실행",
        sub_technique_of="T1003",
    ),
    "T1078": AttackTechnique(
        technique_id="T1078",
        name="Valid Accounts",
        tactic="Persistence / Initial Access",
        description="합법적으로 탈취한 계정 자격 증명 사용",
        detection_hint="비정상 로그인 시간, 비정상 위치, 계정 행동 분석",
    ),
    "T1021.002": AttackTechnique(
        technique_id="T1021.002",
        name="SMB/Windows Admin Shares",
        tactic="Lateral Movement",
        description="SMB 프로토콜과 관리 공유를 통한 원격 시스템 접근",
        detection_hint="Net Use 명령어 로그, SMB 연결 이벤트 ID 5140",
        sub_technique_of="T1021",
    ),
    "T1041": AttackTechnique(
        technique_id="T1041",
        name="Exfiltration Over C2 Channel",
        tactic="Exfiltration",
        description="C2 채널을 통한 데이터 유출",
        detection_hint="비정상 아웃바운드 트래픽, DLP 솔루션 경보",
    ),
}


@dataclass
class MappedTTP:
    action_description: str
    technique: AttackTechnique
    timestamp: Optional[str] = None
    notes: str = ""


def map_action_to_technique(action: str) -> Optional[AttackTechnique]:
    """행동 설명을 ATT&CK 기법과 매핑 (키워드 기반)"""
    action_lower = action.lower()
    keyword_map = {
        "phishing": "T1566.001",
        "피싱": "T1566.001",
        "spearphishing": "T1566.001",
        "powershell": "T1059.001",
        "파워쉘": "T1059.001",
        "lsass": "T1003.001",
        "mimikatz": "T1003.001",
        "pass the hash": "T1550.002",
        "pth": "T1550.002",
        "ntds": "T1003.003",
        "ntds.dit": "T1003.003",
        "smb": "T1021.002",
        "exfil": "T1041",
        "유출": "T1041",
        "valid account": "T1078",
        "계정": "T1078",
    }
    for keyword, technique_id in keyword_map.items():
        if keyword in action_lower:
            return TECHNIQUE_DB.get(technique_id)
    return None


def generate_ttp_matrix(mapped_ttps: List[MappedTTP]) -> str:
    """매핑된 TTP를 Markdown 매트릭스로 출력"""
    tactic_groups: Dict[str, List[MappedTTP]] = {}
    for ttp in mapped_ttps:
        tactic = ttp.technique.tactic
        if tactic not in tactic_groups:
            tactic_groups[tactic] = []
        tactic_groups[tactic].append(ttp)

    lines = [
        "# ATT&CK TTP 매핑 매트릭스",
        "",
        f"총 {len(mapped_ttps)}개 행동 매핑됨",
        "",
    ]

    for tactic, ttps in tactic_groups.items():
        lines += [f"## {tactic}", ""]
        lines += ["| 기법 ID | 기법명 | 수행 행동 | 탐지 힌트 |", "|---|---|---|---|"]
        for ttp in ttps:
            tech = ttp.technique
            lines.append(
                f"| {tech.technique_id} | {tech.name} | "
                f"{ttp.action_description[:40]} | {tech.detection_hint[:50]} |"
            )
        lines.append("")

    lines += [
        "---",
        "## IOC 요약",
        "",
        "> 각 기법 실행 시 생성된 IOC를 여기에 기록하세요.",
    ]
    return "\n".join(lines)


def interactive_mode() -> List[MappedTTP]:
    """대화형 모드로 행동 입력"""
    print("ATT&CK TTP 매핑 도구 (대화형 모드)")
    print("행동을 입력하고 Enter. 종료하려면 빈 줄 입력.\n")
    mapped: List[MappedTTP] = []
    while True:
        action = input("행동 설명> ").strip()
        if not action:
            break
        technique = map_action_to_technique(action)
        if technique:
            print(f"  -> 매핑됨: [{technique.technique_id}] {technique.name} ({technique.tactic})")
            mapped.append(MappedTTP(action_description=action, technique=technique))
        else:
            print("  -> 매핑 실패: 수동으로 ATT&CK 기법을 지정하세요.")
    return mapped


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="ATT&CK TTP 매핑 자동화 도구",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="예시:\n  python3 03_ttps_documentation.py --interactive\n  python3 03_ttps_documentation.py --input actions.txt",
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--interactive", action="store_true", help="대화형 모드로 행동 입력")
    group.add_argument("--input", help="행동 목록 텍스트 파일 (줄별 행동)")
    parser.add_argument("--output", help="출력 파일 경로 (미지정 시 stdout)")
    parser.add_argument("--format", choices=["markdown", "json"], default="markdown", help="출력 형식")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    mapped_ttps: List[MappedTTP] = []

    if args.interactive:
        mapped_ttps = interactive_mode()
    elif args.input:
        try:
            with open(args.input, encoding="utf-8") as f:
                actions = [line.strip() for line in f if line.strip()]
        except OSError as e:
            print(f"파일 읽기 오류: {e}", file=sys.stderr)
            sys.exit(1)
        for action in actions:
            technique = map_action_to_technique(action)
            if technique:
                mapped_ttps.append(MappedTTP(action_description=action, technique=technique))
            else:
                print(f"경고: 매핑 실패 — '{action}'", file=sys.stderr)

    if not mapped_ttps:
        print("매핑된 TTP가 없습니다.", file=sys.stderr)
        sys.exit(1)

    if args.format == "json":
        output = json.dumps(
            [{"action": t.action_description, "technique_id": t.technique.technique_id,
              "technique_name": t.technique.name, "tactic": t.technique.tactic}
             for t in mapped_ttps],
            ensure_ascii=False, indent=2,
        )
    else:
        output = generate_ttp_matrix(mapped_ttps)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(output)
        print(f"결과가 저장되었습니다: {args.output}")
    else:
        print(output)


if __name__ == "__main__":
    main()
```

### 사용 예시

```bash
# 대화형 모드
python3 03_ttps_documentation.py --interactive

# 파일 입력 모드 (actions.txt 예시)
# 파일 내용:
#   피싱 이메일로 악성 Excel 첨부 발송
#   PowerShell로 C2 연결
#   LSASS 메모리 덤프로 해시 추출
#   Pass the Hash로 DC 접근
python3 03_ttps_documentation.py --input actions.txt --output ttp_matrix.md

# JSON 형식 출력
python3 03_ttps_documentation.py --input actions.txt --format json
```

---

## 우수한 TTP 문서화 체크리스트

```
[ ] 모든 수행 행동에 ATT&CK 기법 ID 매핑 완료
[ ] 타임스탬프가 포함된 공격 타임라인 작성
[ ] IOC 목록 (IP, 도메인, 파일 해시) 수집
[ ] 탐지 실패 지점 표시 (블루팀이 놓친 시점)
[ ] 탐지 성공 지점 표시 (블루팀이 발견한 시점)
[ ] 절차(Procedure) 수준의 세부 기술 포함
[ ] 스크린샷 또는 로그 증거 첨부
```

**참고 자료**: [ATT&CK Navigator GitHub](https://github.com/mitre-attack/attack-navigator)

---

<a name="english"></a>

# TTP Documentation — Tactics, Techniques, and Procedures

## What Is a TTP?

TTP stands for **Tactics, Techniques, and Procedures**. It describes what an attacker "wants to accomplish (tactic)", "how they accomplish it (technique)", and "the specific way they execute it (procedure)".

```
Tactic:    The goal — what the attacker is trying to achieve
           Example: Initial Access

Technique: The method for achieving the goal
           Example: Phishing (T1566)

Procedure: The specific implementation of the technique
           Example: "Send Emotet-attached PDF to finance department staff"
```

TTP documentation is a core deliverable of a red team operation. Without it, you know "what was done" but not "why it was done" or "how to respond to it."

---

## MITRE ATT&CK Technique Mapping Exercise

### Mapping Process

1. Write a list of actions the red team performed
2. Link each action to an ATT&CK technique ID
3. Classify by tactic
4. Specify sub-techniques

### Practice Example

Assume the red team performed the following actions:

```
[Actions Performed]
1. Collected employee list from target company's LinkedIn
2. Guessed employee email addresses (first.last@company.com pattern)
3. Sent spear phishing email with malicious Excel macro attachment
4. Macro executed → PowerShell connected to C2
5. Mimikatz dumped LSASS memory → extracted hashes
6. Pass-the-Hash to access domain controller
7. Copied NTDS.dit file
```

```
[ATT&CK Mapping Result]
Action 1: T1591.004 — Gather Victim Org Information (LinkedIn)
Action 2: T1598.003 — Phishing for Information (Email address guessing)
Action 3: T1566.001 — Phishing: Spearphishing Attachment
Action 4: T1059.001 — Command and Scripting Interpreter: PowerShell
Action 5: T1003.001 — OS Credential Dumping: LSASS Memory
Action 6: T1550.002 — Use Alternate Authentication Material: Pass the Hash
Action 7: T1003.003 — OS Credential Dumping: NTDS
```

---

## Attack Timeline Reconstruction

One of the core elements of TTP documentation is reconstructing the attack timeline in chronological order. This is extremely useful for the blue team to identify where detection failed.

```
Timeline Example:

2024-01-05 09:15  Reconnaissance: Identified 12 employees via LinkedIn OSINT
2024-01-05 14:30  Weaponization: Created malicious Excel file
2024-01-08 10:02  Delivery: Sent phishing email (recipients: 3 finance staff)
2024-01-08 10:47  Execution: Victim A enabled macros
2024-01-08 10:48  Installation: PowerShell-based implant installed
2024-01-08 11:05  C2: HTTPS C2 channel established (beacon interval: 60s)
2024-01-09 14:22  Privilege Escalation: SeDebugPrivilege obtained
2024-01-09 14:25  Credential Access: LSASS memory dump
2024-01-09 15:10  Lateral Movement: Accessed DC01 server (Pass-the-Hash)
2024-01-10 09:30  Actions on Objectives: NTDS.dit exfiltrated (Crown Jewel)
```

---

## IOC (Indicators of Compromise) List

IOCs are evidence indicating that an attack has occurred. They are directly used to improve blue team detection rules.

| IOC Type | Example | Description |
|---|---|---|
| IP Address | 203.0.113.42 | C2 server IP |
| Domain | update.microsoft-cdn.xyz | C2 domain (typosquatting) |
| File Hash | SHA256: a3f2b1... | Malicious file hash |
| Registry Key | HKCU\Software\...\Run | Persistence registry entry |
| Mutex | Global\MUTEX_12345 | Malware unique identifier |
| User Agent | Mozilla/5.0 (custom) | C2 HTTP header |
| File Path | C:\Users\...\AppData\Temp\svch0st.exe | Implant location |

---

## Python ATT&CK Mapping Automation Code

The following code accepts a list of attack actions and outputs an ATT&CK mapping matrix.

```python
#!/usr/bin/env python3
"""
ATT&CK TTP Mapping Automation Tool
Usage: python3 03_ttps_documentation.py --input actions.txt
       python3 03_ttps_documentation.py --interactive
"""

import argparse
import json
import sys
from dataclasses import dataclass
from typing import Dict, List, Optional


@dataclass
class AttackTechnique:
    technique_id: str
    name: str
    tactic: str
    description: str
    detection_hint: str = ""
    sub_technique_of: Optional[str] = None


TECHNIQUE_DB: Dict[str, AttackTechnique] = {
    "T1566.001": AttackTechnique(
        technique_id="T1566.001",
        name="Spearphishing Attachment",
        tactic="Initial Access",
        description="Spear phishing emails with malicious attachments",
        detection_hint="Email gateway logs, attachment sandbox analysis",
        sub_technique_of="T1566",
    ),
    "T1059.001": AttackTechnique(
        technique_id="T1059.001",
        name="PowerShell",
        tactic="Execution",
        description="Malicious command execution via PowerShell interpreter",
        detection_hint="PowerShell script block logging, encoded command detection",
        sub_technique_of="T1059",
    ),
    "T1003.001": AttackTechnique(
        technique_id="T1003.001",
        name="LSASS Memory",
        tactic="Credential Access",
        description="Credential extraction from LSASS process memory",
        detection_hint="LSASS access Event ID 4656, Sysmon Event 10",
        sub_technique_of="T1003",
    ),
    "T1550.002": AttackTechnique(
        technique_id="T1550.002",
        name="Pass the Hash",
        tactic="Lateral Movement",
        description="Remote system access using NTLM hash without cleartext password",
        detection_hint="Event ID 4624 (Logon Type 3), abnormal time-of-day logins",
        sub_technique_of="T1550",
    ),
}


def map_action_to_technique(action: str) -> Optional[AttackTechnique]:
    """Map an action description to an ATT&CK technique using keywords"""
    action_lower = action.lower()
    keyword_map = {
        "phishing": "T1566.001",
        "spearphishing": "T1566.001",
        "powershell": "T1059.001",
        "lsass": "T1003.001",
        "mimikatz": "T1003.001",
        "pass the hash": "T1550.002",
        "pth": "T1550.002",
    }
    for keyword, technique_id in keyword_map.items():
        if keyword in action_lower:
            return TECHNIQUE_DB.get(technique_id)
    return None


def generate_ttp_matrix(actions: List[str]) -> str:
    """Generate ATT&CK mapping matrix from a list of actions"""
    lines = ["# ATT&CK TTP Mapping Matrix", ""]
    lines += ["| Technique ID | Name | Action | Detection Hint |", "|---|---|---|---|"]
    unmapped = []
    for action in actions:
        tech = map_action_to_technique(action)
        if tech:
            lines.append(f"| {tech.technique_id} | {tech.name} | {action[:40]} | {tech.detection_hint[:50]} |")
        else:
            unmapped.append(action)
    if unmapped:
        lines += ["", "## Unmapped Actions (manual review required)"]
        for a in unmapped:
            lines.append(f"- {a}")
    return "\n".join(lines)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="ATT&CK TTP Mapping Automation Tool")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--interactive", action="store_true", help="Interactive mode")
    group.add_argument("--input", help="Input file with one action per line")
    parser.add_argument("--output", help="Output file path (stdout if not specified)")
    parser.add_argument("--format", choices=["markdown", "json"], default="markdown")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    actions: List[str] = []

    if args.interactive:
        print("ATT&CK TTP Mapping Tool (Interactive Mode)")
        print("Enter an action and press Enter. Empty line to finish.\n")
        while True:
            action = input("Action> ").strip()
            if not action:
                break
            actions.append(action)
            tech = map_action_to_technique(action)
            if tech:
                print(f"  -> Mapped: [{tech.technique_id}] {tech.name} ({tech.tactic})")
            else:
                print("  -> No mapping found. Manual review required.")
    else:
        try:
            with open(args.input, encoding="utf-8") as f:
                actions = [line.strip() for line in f if line.strip()]
        except OSError as e:
            print(f"File read error: {e}", file=sys.stderr)
            sys.exit(1)

    output = generate_ttp_matrix(actions)
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
# Interactive mode
python3 03_ttps_documentation.py --interactive

# File input mode
python3 03_ttps_documentation.py --input actions.txt --output ttp_matrix.md

# JSON output
python3 03_ttps_documentation.py --input actions.txt --format json
```

---

## TTP Documentation Quality Checklist

```
[ ] ATT&CK technique ID mapped for every action performed
[ ] Attack timeline written with timestamps
[ ] IOC list collected (IPs, domains, file hashes)
[ ] Detection failure points marked (where blue team missed)
[ ] Detection success points marked (where blue team caught it)
[ ] Procedure-level detail included
[ ] Screenshots or log evidence attached
```

**Reference**: [ATT&CK Navigator GitHub](https://github.com/mitre-attack/attack-navigator)
