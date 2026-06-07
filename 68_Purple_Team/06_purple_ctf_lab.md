> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 퍼플팀 CTF 실습 랩

## 실습 개요

이 랩은 ATT&CK 기술 매핑, Sigma 룰 작성, 공격 시뮬레이션 탐지율 측정, TTPs 역추출 등 퍼플팀 핵심 역량을 CTF 형식으로 훈련합니다. 각 챌린지는 실제 SOC/탐지 엔지니어링 업무와 직결되는 시나리오로 구성되어 있습니다.

---

## 챌린지 목록

| 번호 | 이름 | 난이도 | 설명 |
|------|------|--------|------|
| C01 | ATT&CK Mapper | ★☆☆ | ATT&CK 기술 ID로 탐지 규칙을 매핑하여 플래그 획득 |
| C02 | Sigma Rule Writer | ★★☆ | Sigma 룰을 작성하여 공격 이벤트를 탐지하고 플래그 획득 |
| C03 | Detection Rate Measurer | ★★☆ | 공격 시뮬레이션 스크립트로 탐지율을 측정하여 플래그 획득 |
| C04 | TTP Extractor | ★★★ | 레드팀 행동 로그에서 TTPs를 역추출하여 플래그 획득 |

---

## 챌린지 상세

### C01 — ATT&CK Mapper (★☆☆)

**시나리오**

5개의 보안 이벤트 로그가 주어집니다. 각 이벤트에 해당하는 MITRE ATT&CK 기술 ID(예: T1059.001)를 정확히 매핑하고, 매핑 결과를 SHA-256으로 해시하여 플래그를 생성하세요.

**학습 목표**
- MITRE ATT&CK 프레임워크 기술 계층 구조 이해
- 이벤트 로그 → 기술 ID 매핑 능력
- ATT&CK Navigator 활용법

**매핑 대상 이벤트**

| 이벤트 | 설명 | 예상 기술 ID |
|--------|------|-------------|
| E01 | PowerShell 스크립트 실행 (`powershell.exe -enc ...`) | T1059.001 |
| E02 | `schtasks /create` 명령으로 예약 작업 등록 | T1053.005 |
| E03 | `reg add HKCU\...\Run` 레지스트리 지속성 | T1547.001 |
| E04 | `net user /add` 계정 생성 | T1136.001 |
| E05 | `certutil -decode` 로 파일 디코딩 | T1140 |

**힌트**
1. [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) 에서 기술 ID를 검색하세요.
2. PowerShell 실행 → T1059(Command and Scripting Interpreter) → .001(PowerShell)
3. 예약 작업 → T1053(Scheduled Task/Job) → .005(Scheduled Task)
4. 매핑 결과를 `E01:T1059.001,E02:T1053.005,...` 형식으로 연결 후 플래그를 제출하세요.

**도구 명령어 예시**

```bash
# ATT&CK API로 기술 정보 검색
pip install mitreattack-python

python3 << 'EOF'
from mitreattack.stix20 import MitreAttackData

# ATT&CK STIX 데이터 로드
attack = MitreAttackData("enterprise-attack.json")

# 기술 ID로 검색
tech = attack.get_technique_by_id("T1059.001")
if tech:
    print(f"이름: {tech.get('name')}")
    print(f"설명: {tech.get('description', '')[:200]}")

# 키워드로 검색
techniques = attack.get_techniques()
for t in techniques:
    name = t.get('name', '')
    if 'PowerShell' in name:
        ext_id = [r.get('external_id') for r in t.get('external_references', [])
                  if r.get('source_name') == 'mitre-attack']
        print(f"{ext_id[0] if ext_id else '?'}: {name}")
EOF

# 로컬 ATT&CK 데이터 다운로드
wget https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json

# 이벤트-기술 매핑 검증 스크립트
python3 << 'EOF'
import hashlib

mapping = {
    "E01": "T1059.001",
    "E02": "T1053.005",
    "E03": "T1547.001",
    "E04": "T1136.001",
    "E05": "T1140",
}
result = ",".join(f"{k}:{v}" for k, v in sorted(mapping.items()))
print(f"매핑 문자열: {result}")
print(f"SHA-256: {hashlib.sha256(result.encode()).hexdigest()}")
EOF
```

---

### C02 — Sigma Rule Writer (★★☆)

**시나리오**

Cobalt Strike 비콘이 `rundll32.exe`를 부모 프로세스로 하여 `cmd.exe`를 실행하는 패턴이 탐지되었습니다. 이 공격을 탐지하는 Sigma 룰을 작성하고, 제공된 로그 샘플에 적용하여 올바른 이벤트를 탐지하면 플래그를 획득합니다.

**학습 목표**
- Sigma 룰 구조 이해 (title, detection, condition)
- 프로세스 생성 이벤트(EventID 4688, Sysmon ID 1) 필드 이해
- `sigma-cli` 또는 `sigmac`으로 룰 변환 및 테스트

**Sigma 룰 템플릿**

```yaml
title: Suspicious Rundll32 Spawning CMD
status: experimental
description: |
  rundll32.exe가 비정상적으로 cmd.exe를 자식 프로세스로 생성하는 경우를 탐지합니다.
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    ParentImage|endswith: '\rundll32.exe'
    Image|endswith: '\cmd.exe'
  condition: selection
falsepositives:
  - 정상적인 시스템 관리 스크립트
level: high
tags:
  - attack.execution
  - attack.t1218.011   # Rundll32
  - attack.t1059.003   # Windows Command Shell
```

**힌트**
1. Sigma 룰의 `detection.selection` 에서 `ParentImage`와 `Image` 필드를 사용하세요.
2. `sigma-cli` 로 룰을 검증하세요: `sigma check rule.yml`
3. 제공된 CSV 로그에서 조건에 맞는 이벤트 수를 세어 답을 제출하세요.
4. 탐지된 이벤트의 ProcessId 목록을 정렬 후 SHA-256 해시가 플래그입니다.

**도구 명령어 예시**

```bash
# sigma-cli 설치
pip install sigma-cli

# Sigma 룰 유효성 검사
sigma check rule.yml

# SIEM 쿼리로 변환
sigma convert -t splunk rule.yml
sigma convert -t elasticsearch rule.yml
sigma convert -t qradar rule.yml

# 로컬 로그에 직접 적용 (evtx-hunter 사용)
pip install evtx
python3 << 'EOF'
import csv, re

# 예제 로그 샘플 (실제는 EVTX 또는 CSV)
log_samples = [
    {"EventID": "4688", "ParentImage": "C:\\Windows\\System32\\rundll32.exe",
     "Image": "C:\\Windows\\System32\\cmd.exe", "ProcessId": "1234"},
    {"EventID": "4688", "ParentImage": "C:\\Windows\\explorer.exe",
     "Image": "C:\\Windows\\System32\\cmd.exe", "ProcessId": "5678"},
    {"EventID": "4688", "ParentImage": "C:\\Windows\\System32\\rundll32.exe",
     "Image": "C:\\Windows\\System32\\powershell.exe", "ProcessId": "9012"},
    {"EventID": "4688", "ParentImage": "C:\\Windows\\System32\\rundll32.exe",
     "Image": "C:\\Windows\\System32\\cmd.exe", "ProcessId": "3456"},
]

detected = [
    e for e in log_samples
    if e["ParentImage"].endswith("rundll32.exe") and e["Image"].endswith("cmd.exe")
]
print(f"탐지된 이벤트 수: {len(detected)}")
pids = sorted(int(e["ProcessId"]) for e in detected)
print(f"ProcessId 목록: {pids}")

import hashlib
answer = ",".join(str(p) for p in pids)
print(f"플래그 해시 입력값: {answer}")
EOF
```

---

### C03 — Detection Rate Measurer (★★☆)

**시나리오**

10개의 ATT&CK 기술을 시뮬레이션하는 스크립트를 실행했을 때, SIEM에서 탐지된 기술과 누락된 기술이 제공됩니다. 탐지율을 계산하고, 탐지 갭 TOP 3를 식별하며, 개선 후 예상 탐지율을 계산하면 플래그를 획득합니다.

**학습 목표**
- 탐지율(Coverage Rate) 계산 방법
- 탐지 갭 우선순위 분석
- 퍼플팀 메트릭 산출

**시뮬레이션 결과 데이터**

| 기술 ID | 기술명 | 심각도 | 탐지 여부 |
|---------|--------|--------|----------|
| T1059.001 | PowerShell | HIGH | 탐지됨 |
| T1053.005 | Scheduled Task | MEDIUM | 누락 |
| T1547.001 | Registry Run Keys | MEDIUM | 탐지됨 |
| T1003.001 | LSASS Memory | CRITICAL | 누락 |
| T1021.001 | Remote Desktop | MEDIUM | 탐지됨 |
| T1078 | Valid Accounts | HIGH | 누락 |
| T1566.001 | Spearphishing | HIGH | 탐지됨 |
| T1486 | Data Encrypted | CRITICAL | 누락 |
| T1070.001 | Event Log Clear | HIGH | 탐지됨 |
| T1105 | Ingress Tool Transfer | MEDIUM | 탐지됨 |

**힌트**
1. 탐지율 = 탐지된 기술 수 / 전체 기술 수 × 100
2. 탐지 갭 우선순위: CRITICAL > HIGH > MEDIUM
3. 상위 2개 갭(T1003.001, T1486) 개선 후 예상 탐지율도 계산하세요.
4. 탐지율(정수%) + 갭 TOP3 기술 ID를 조합한 값의 SHA-256이 플래그입니다.

**도구 명령어 예시**

```bash
# 탐지율 계산 스크립트
python3 << 'EOF'
import hashlib

techniques = [
    ("T1059.001", "PowerShell", "HIGH", True),
    ("T1053.005", "Scheduled Task", "MEDIUM", False),
    ("T1547.001", "Registry Run Keys", "MEDIUM", True),
    ("T1003.001", "LSASS Memory", "CRITICAL", False),
    ("T1021.001", "Remote Desktop", "MEDIUM", True),
    ("T1078", "Valid Accounts", "HIGH", False),
    ("T1566.001", "Spearphishing", "HIGH", True),
    ("T1486", "Data Encrypted", "CRITICAL", False),
    ("T1070.001", "Event Log Clear", "HIGH", True),
    ("T1105", "Ingress Tool Transfer", "MEDIUM", True),
]

total = len(techniques)
detected = sum(1 for _, _, _, d in techniques if d)
gaps = [(tid, name, sev) for tid, name, sev, d in techniques if not d]

severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}
gaps_sorted = sorted(gaps, key=lambda x: severity_order[x[2]])

detection_rate = (detected / total) * 100
print(f"탐지율: {detected}/{total} = {detection_rate:.1f}%")
print(f"\n탐지 갭 (우선순위순):")
for i, (tid, name, sev) in enumerate(gaps_sorted, 1):
    print(f"  {i}. [{sev}] {tid} — {name}")

top3 = [t[0] for t in gaps_sorted[:3]]
answer = f"{int(detection_rate)},{','.join(top3)}"
print(f"\n플래그 해시 입력: {answer}")
print(f"SHA-256: {hashlib.sha256(answer.encode()).hexdigest()}")

# 개선 후 예상 탐지율 (TOP2 갭 해결 시)
improved = detected + 2
improved_rate = (improved / total) * 100
print(f"\n개선 후 예상 탐지율: {improved}/{total} = {improved_rate:.1f}%")
EOF

# Atomic Red Team으로 실제 시뮬레이션 (Windows PowerShell)
# Invoke-AtomicTest T1003.001 -TestNumbers 1
# Invoke-AtomicTest T1059.001 -TestNumbers 1

#탐지 결과를 SIEM에서 쿼리 (Splunk 예시)
# index=sysmon EventCode=1 | stats count by technique_id | sort -count
```

---

### C04 — TTP Extractor (★★★)

**시나리오**

레드팀 교전 후 수집된 원시 로그(Windows 이벤트 로그 + 네트워크 PCAP + 파일시스템 아티팩트)가 제공됩니다. 로그를 분석하여 레드팀이 사용한 TTPs를 역추출하고, ATT&CK 기술 ID 매핑을 완성한 뒤, 공격 체인(Attack Chain)을 재구성하면 플래그를 획득합니다.

**학습 목표**
- 다중 데이터 소스 상관 분석
- 타임라인 분석으로 공격 체인 재구성
- 레드팀 행동을 ATT&CK 기술 ID로 역매핑
- 퍼플팀 보고서용 TTP 매핑 테이블 생성

**힌트**
1. Windows EventID 4688(프로세스 생성), 4624(로그온), 4698(예약 작업)을 중심으로 분석
2. 타임라인 기반 분석: `python-evtx` 또는 `Plaso`로 이벤트 시간 정렬
3. 네트워크 PCAP: `tshark -r traffic.pcap -Y "tcp.port==443" -T fields -e ip.dst` 로 C2 IP 추출
4. 파일 아티팩트: `%TEMP%`, `%APPDATA%`, Scheduled Tasks 폴더, Prefetch 파일 확인
5. 공격 체인 완성 후 각 단계의 기술 ID를 시간순으로 연결하면 플래그 입력값이 됨

**도구 명령어 예시**

```bash
# Windows 이벤트 로그 분석
pip install python-evtx

python3 << 'EOF'
from Evtx.Evtx import Evtx
from Evtx.Views import evtx_file_xml_view
import xml.etree.ElementTree as ET
from datetime import datetime

suspicious_events = []
with Evtx("Security.evtx") as log:
    for record in log.records():
        xml = record.xml()
        root = ET.fromstring(xml)
        ns = "{http://schemas.microsoft.com/win/2004/08/events/event}"
        event_id = root.find(f".//{ns}EventID")
        if event_id is not None and event_id.text in ["4688", "4624", "4698"]:
            time_elem = root.find(f".//{ns}TimeCreated")
            proc_elem = root.find(f".//{ns}NewProcessName")
            suspicious_events.append({
                "time": time_elem.get("SystemTime") if time_elem is not None else "",
                "event_id": event_id.text,
                "process": proc_elem.text if proc_elem is not None else "",
            })

suspicious_events.sort(key=lambda x: x["time"])
for e in suspicious_events[:20]:
    print(f"[{e['time'][:19]}] EventID={e['event_id']} Process={e['process']}")
EOF

# Prefetch 분석으로 실행된 프로그램 복원
pip install prefetch-parser
python3 -c "
from prefetch import Prefetch
pf = Prefetch('C:/Windows/Prefetch/MIMIKATZ.EXE-XXXXXXXX.pf')
print(f'실행 횟수: {pf.run_count}')
print(f'마지막 실행: {pf.latest_timestamp}')
"

# 타임라인 통합 분석 (Plaso)
log2timeline.py timeline.plaso Security.evtx
psort.py -o dynamic timeline.plaso | head -50

# TTP 역추출 자동화
python3 << 'EOF'
import hashlib

# 분석 결과 예시: 시간순 공격 체인
attack_chain = [
    ("2024-01-15 09:00:00", "T1566.001", "Spearphishing 이메일"),
    ("2024-01-15 09:05:00", "T1059.001", "PowerShell 다운로더"),
    ("2024-01-15 09:10:00", "T1105",     "도구 다운로드"),
    ("2024-01-15 09:15:00", "T1003.001", "LSASS 덤프"),
    ("2024-01-15 09:20:00", "T1053.005", "예약 작업 등록"),
    ("2024-01-15 09:30:00", "T1041",     "C2 데이터 전송"),
]

print("공격 체인 재구성:")
for time, tid, desc in attack_chain:
    print(f"  [{time}] {tid} — {desc}")

tids = "->".join(t[1] for t in attack_chain)
flag_input = f"chain:{tids}"
print(f"\n플래그 입력값: {flag_input}")
print(f"SHA-256: {hashlib.sha256(flag_input.encode()).hexdigest()}")
EOF
```

---

## CTF 스크립트

```python
#!/usr/bin/env python3
"""
퍼플팀 CTF 실습 시뮬레이터
섹션 68 - Purple Team

사용법:
  python3 06_purple_ctf_lab.py --list
  python3 06_purple_ctf_lab.py --challenge C01
  python3 06_purple_ctf_lab.py --hint C04
  python3 06_purple_ctf_lab.py --challenge C01 --submit CTF{your_flag_here}
  python3 06_purple_ctf_lab.py --simulate C03
  python3 06_purple_ctf_lab.py --demo-detection-rate
"""

from __future__ import annotations

import argparse
import hashlib
import sys
from dataclasses import dataclass, field


@dataclass
class Challenge:
    id: str
    name: str
    difficulty: str
    description: str
    hints: list[str]
    flag_sha256: str
    scenario: str
    tools: list[str]
    attack_techniques: list[str] = field(default_factory=list)


CHALLENGES: dict[str, Challenge] = {
    "C01": Challenge(
        id="C01",
        name="ATT&CK Mapper",
        difficulty="★☆☆",
        description="ATT&CK 기술 ID로 탐지 규칙을 매핑하여 플래그 획득",
        hints=[
            "Hint 1: ATT&CK Navigator(https://mitre-attack.github.io/attack-navigator/)에서 기술 ID를 검색하세요.",
            "Hint 2: PowerShell 실행 → T1059.001, 예약 작업 → T1053.005",
            "Hint 3: 레지스트리 Run 키 지속성 → T1547.001, 계정 생성 → T1136.001",
            "Hint 4: certutil 디코딩 → T1140(Deobfuscate/Decode Files or Information)",
        ],
        flag_sha256="f1c8d5b2e9a6f3c0d7e4b1a8f5c2d9e6b3a0f7c4d1e8b5a2f9c6d3b0e7a4f1c8",
        scenario="5개 이벤트를 ATT&CK 기술 ID로 매핑하여 플래그를 생성하세요.",
        tools=["ATT&CK Navigator", "mitreattack-python", "MITRE CTI"],
        attack_techniques=["T1059.001", "T1053.005", "T1547.001", "T1136.001", "T1140"],
    ),
    "C02": Challenge(
        id="C02",
        name="Sigma Rule Writer",
        difficulty="★★☆",
        description="Sigma 룰을 작성하여 공격 이벤트를 탐지하고 플래그 획득",
        hints=[
            "Hint 1: Sigma 룰에서 ParentImage와 Image 필드로 프로세스 계층을 필터링하세요.",
            "Hint 2: sigma-cli 설치: pip install sigma-cli",
            "Hint 3: sigma check rule.yml 로 룰 유효성을 검증하세요.",
            "Hint 4: 탐지된 이벤트의 ProcessId를 정렬 후 SHA-256 해시가 플래그입니다.",
        ],
        flag_sha256="c0d7e4b1a8f5c2d9e6b3a0f7c4d1e8b5a2f9c6d3b0e7a4f1c8d5b2e9a6f3c0d7",
        scenario="rundll32.exe → cmd.exe 프로세스 체인을 탐지하는 Sigma 룰을 작성하세요.",
        tools=["sigma-cli", "sigmac", "Splunk", "Elasticsearch", "EVTX"],
        attack_techniques=["T1218.011", "T1059.003"],
    ),
    "C03": Challenge(
        id="C03",
        name="Detection Rate Measurer",
        difficulty="★★☆",
        description="공격 시뮬레이션 스크립트로 탐지율을 측정하여 플래그 획득",
        hints=[
            "Hint 1: 탐지율 = 탐지된 기술 수 / 전체 기술 수 × 100",
            "Hint 2: 갭 우선순위: CRITICAL(T1003.001, T1486) > HIGH(T1078) > MEDIUM(T1053.005)",
            "Hint 3: 탐지율(정수%) + 갭 TOP3 기술 ID를 조합하여 플래그 입력값을 만드세요.",
            "Hint 4: 형식: '60,T1003.001,T1486,T1078' → SHA-256 해시",
        ],
        flag_sha256="d3b0e7a4f1c8d5b2e9a6f3c0d7e4b1a8f5c2d9e6b3a0f7c4d1e8b5a2f9c6d3b0",
        scenario="제공된 시뮬레이션 결과에서 탐지율과 탐지 갭 TOP3를 분석하세요.",
        tools=["Python3", "Atomic Red Team", "Splunk", "Elastic SIEM"],
        attack_techniques=["T1059.001", "T1053.005", "T1003.001", "T1078", "T1486"],
    ),
    "C04": Challenge(
        id="C04",
        name="TTP Extractor",
        difficulty="★★★",
        description="레드팀 행동 로그에서 TTPs를 역추출하여 플래그 획득",
        hints=[
            "Hint 1: EventID 4688, 4624, 4698을 중심으로 타임라인을 구성하세요.",
            "Hint 2: python-evtx 또는 Plaso로 다중 로그 소스를 통합 분석하세요.",
            "Hint 3: 네트워크 PCAP에서 C2 IP와 통신 시간을 추출하세요.",
            "Hint 4: 공격 체인 기술 ID를 시간순으로 '->'로 연결하면 플래그 입력값이 됩니다.",
        ],
        flag_sha256="e6b3a0f7c4d1e8b5a2f9c6d3b0e7a4f1c8d5b2e9a6f3c0d7e4b1a8f5c2d9e6b3",
        scenario="레드팀 로그에서 6단계 공격 체인을 재구성하고 TTPs를 역추출하세요.",
        tools=["python-evtx", "Plaso", "tshark", "Volatility", "Prefetch Parser"],
        attack_techniques=["T1566.001", "T1059.001", "T1105", "T1003.001", "T1053.005", "T1041"],
    ),
}


def list_challenges() -> None:
    print("\n퍼플팀 CTF 실습 랩 — 챌린지 목록\n")
    print(f"{'번호':<6} {'이름':<28} {'난이도':<8} 설명")
    print("-" * 78)
    for ch in CHALLENGES.values():
        print(f"{ch.id:<6} {ch.name:<28} {ch.difficulty:<8} {ch.description}")
    print()


def show_challenge(challenge_id: str) -> None:
    ch = CHALLENGES.get(challenge_id.upper())
    if ch is None:
        print(f"[오류] 존재하지 않는 챌린지: {challenge_id}")
        sys.exit(1)
    print(f"\n{'='*60}")
    print(f"  [{ch.id}] {ch.name}  {ch.difficulty}")
    print(f"{'='*60}")
    print(f"\n시나리오\n  {ch.scenario}")
    if ch.attack_techniques:
        print(f"\n관련 ATT&CK 기술\n  {', '.join(ch.attack_techniques)}")
    print(f"\n권장 도구\n  {', '.join(ch.tools)}")
    print(f"\n힌트 확인: python3 06_purple_ctf_lab.py --hint {ch.id}")
    print(f"플래그 제출: python3 06_purple_ctf_lab.py --challenge {ch.id} --submit CTF{{flag}}\n")


def show_hint(challenge_id: str) -> None:
    ch = CHALLENGES.get(challenge_id.upper())
    if ch is None:
        print(f"[오류] 존재하지 않는 챌린지: {challenge_id}")
        sys.exit(1)
    print(f"\n[{ch.id}] {ch.name} — 힌트\n")
    for hint in ch.hints:
        print(f"  {hint}")
    print()


def submit_flag(challenge_id: str, flag: str) -> None:
    ch = CHALLENGES.get(challenge_id.upper())
    if ch is None:
        print(f"[오류] 존재하지 않는 챌린지: {challenge_id}")
        sys.exit(1)
    flag_hash = hashlib.sha256(flag.strip().encode()).hexdigest()
    print(f"\n[{ch.id}] {ch.name} — 플래그 검증")
    print(f"  제출: {flag.strip()}")
    print(f"  해시: {flag_hash[:16]}...")
    if flag_hash == ch.flag_sha256:
        print(f"\n  정답입니다! 챌린지 [{ch.id}] 클리어!\n")
    else:
        print(f"\n  오답입니다. 힌트: python3 06_purple_ctf_lab.py --hint {ch.id}\n")


def demo_detection_rate() -> None:
    """C03 탐지율 계산 데모."""
    print("\n[데모] 퍼플팀 탐지율 계산\n")
    techniques = [
        ("T1059.001", "PowerShell", "HIGH", True),
        ("T1053.005", "Scheduled Task", "MEDIUM", False),
        ("T1547.001", "Registry Run Keys", "MEDIUM", True),
        ("T1003.001", "LSASS Memory", "CRITICAL", False),
        ("T1021.001", "Remote Desktop", "MEDIUM", True),
        ("T1078", "Valid Accounts", "HIGH", False),
        ("T1566.001", "Spearphishing", "HIGH", True),
        ("T1486", "Data Encrypted", "CRITICAL", False),
        ("T1070.001", "Event Log Clear", "HIGH", True),
        ("T1105", "Ingress Tool Transfer", "MEDIUM", True),
    ]
    total = len(techniques)
    detected = sum(1 for _, _, _, d in techniques if d)
    gaps = [(tid, name, sev) for tid, name, sev, d in techniques if not d]
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}
    gaps_sorted = sorted(gaps, key=lambda x: severity_order[x[2]])

    rate = (detected / total) * 100
    print(f"  전체 기술: {total}개")
    print(f"  탐지 성공: {detected}개")
    print(f"  탐지율: {rate:.1f}%")
    print(f"\n  탐지 갭 (우선순위순):")
    for i, (tid, name, sev) in enumerate(gaps_sorted, 1):
        mark = " <-- TOP" if i <= 3 else ""
        print(f"    {i}. [{sev}] {tid} — {name}{mark}")
    print()


def simulate_analysis(challenge_id: str) -> None:
    """챌린지별 분석 시뮬레이션 출력."""
    ch = CHALLENGES.get(challenge_id.upper())
    if ch is None:
        print(f"[오류] 존재하지 않는 챌린지: {challenge_id}")
        sys.exit(1)

    simulations: dict[str, list[str]] = {
        "C01": [
            "[*] 이벤트 로그 분석 시작...",
            "[*] E01: powershell.exe -enc ... → T1059.001 (PowerShell)",
            "[*] E02: schtasks /create → T1053.005 (Scheduled Task)",
            "[*] E03: reg add HKCU\\...\\Run → T1547.001 (Registry Run Keys)",
            "[*] E04: net user /add → T1136.001 (Local Account)",
            "[*] E05: certutil -decode → T1140 (Deobfuscate/Decode)",
            "[+] 매핑 완료! CTF{attack_technique_mapping_complete}",
        ],
        "C02": [
            "[*] 로그 샘플 분석: 4개 이벤트",
            "[*] EventID 4688 분석 중...",
            "[*] 이벤트 1: rundll32.exe → cmd.exe (탐지 대상!)",
            "[*] 이벤트 2: explorer.exe → cmd.exe (정상, 탐지 제외)",
            "[*] 이벤트 3: rundll32.exe → powershell.exe (Image 불일치, 제외)",
            "[*] 이벤트 4: rundll32.exe → cmd.exe (탐지 대상!)",
            "[+] 탐지된 ProcessId: [1234, 3456] → CTF{sigma_rule_detection_success}",
        ],
        "C03": [
            "[*] 시뮬레이션 결과 분석: 10개 기술",
            "[*] 탐지 성공: 6개 / 누락: 4개",
            "[*] 탐지율: 60.0%",
            "[*] 갭 TOP1: [CRITICAL] T1003.001 — LSASS Memory",
            "[*] 갭 TOP2: [CRITICAL] T1486 — Data Encrypted",
            "[*] 갭 TOP3: [HIGH] T1078 — Valid Accounts",
            "[+] 플래그 입력: '60,T1003.001,T1486,T1078'",
            "[+] CTF{detection_rate_60_gap_analysis_done}",
        ],
        "C04": [
            "[*] 다중 로그 소스 통합 분석...",
            "[*] Security.evtx: 4688 이벤트 2,341개 파싱",
            "[*] Network PCAP: C2 통신 IP 192.168.100.1:443 식별",
            "[*] Prefetch: MIMIKATZ.EXE 실행 기록 발견",
            "[*] 공격 체인 재구성:",
            "[*]   09:00 T1566.001 → 09:05 T1059.001 → 09:10 T1105",
            "[*]   09:15 T1003.001 → 09:20 T1053.005 → 09:30 T1041",
            "[+] TTP 추출 완료! CTF{ttp_chain_reconstruction_mastered}",
        ],
    }

    steps = simulations.get(challenge_id.upper(), [])
    print(f"\n[시뮬레이션] {ch.id} — {ch.name}\n")
    for step in steps:
        print(f"  {step}")
    print()


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="06_purple_ctf_lab.py",
        description="퍼플팀 CTF 실습 시뮬레이터 (섹션 68)",
    )
    parser.add_argument("--list", action="store_true", help="챌린지 목록 출력")
    parser.add_argument("--challenge", metavar="ID", help="챌린지 상세 정보 (예: C01)")
    parser.add_argument("--hint", metavar="ID", help="힌트 출력 (예: C02)")
    parser.add_argument("--submit", metavar="FLAG", help="플래그 제출 (--challenge 와 함께 사용)")
    parser.add_argument("--simulate", metavar="ID", help="분석 시뮬레이션 (예: C04)")
    parser.add_argument("--demo-detection-rate", action="store_true", help="탐지율 계산 데모")

    args = parser.parse_args()

    if args.list:
        list_challenges()
    elif args.hint:
        show_hint(args.hint)
    elif args.simulate:
        simulate_analysis(args.simulate)
    elif args.demo_detection_rate:
        demo_detection_rate()
    elif args.challenge and args.submit:
        submit_flag(args.challenge, args.submit)
    elif args.challenge:
        show_challenge(args.challenge)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
```

---

<a name="english"></a>

# Purple Team CTF Lab

## Lab Overview

This lab trains core Purple Team skills — ATT&CK technique mapping, Sigma rule writing, detection rate measurement, and TTP extraction — in CTF format. Every challenge maps directly to real SOC and detection engineering work.

---

## Challenge List

| No. | Name | Difficulty | Description |
|-----|------|------------|-------------|
| C01 | ATT&CK Mapper | ★☆☆ | Map security events to ATT&CK technique IDs to capture the flag |
| C02 | Sigma Rule Writer | ★★☆ | Write a Sigma rule to detect the attack pattern and capture the flag |
| C03 | Detection Rate Measurer | ★★☆ | Measure detection rate from simulation results to capture the flag |
| C04 | TTP Extractor | ★★★ | Reverse-extract TTPs from red team activity logs to capture the flag |

---

## Challenge Details

### C01 — ATT&CK Mapper (★☆☆)

**Scenario**

Five security events are provided. Map each event to the correct MITRE ATT&CK technique ID and generate the flag from your mapping.

**Event Mapping Table**

| Event | Description | Expected Technique |
|-------|-------------|-------------------|
| E01 | `powershell.exe -enc ...` execution | T1059.001 |
| E02 | `schtasks /create` scheduled task registration | T1053.005 |
| E03 | `reg add HKCU\...\Run` registry persistence | T1547.001 |
| E04 | `net user /add` local account creation | T1136.001 |
| E05 | `certutil -decode` file decoding | T1140 |

**Hints**
1. Use [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) to look up technique IDs
2. PowerShell execution → T1059 → .001 (PowerShell sub-technique)
3. Scheduled task → T1053 → .005 (Scheduled Task)
4. Combine results as `E01:T1059.001,E02:T1053.005,...` and submit

---

### C02 — Sigma Rule Writer (★★☆)

**Scenario**

A Cobalt Strike beacon is spawning `cmd.exe` as a child of `rundll32.exe`. Write a Sigma rule to detect this pattern and apply it to the provided log samples.

**Hints**
1. Use `ParentImage` and `Image` fields in `detection.selection`
2. `pip install sigma-cli` then `sigma check rule.yml` to validate
3. Convert to your SIEM format: `sigma convert -t splunk rule.yml`
4. Count matching events; sort ProcessIds and SHA-256 hash is the flag

---

### C03 — Detection Rate Measurer (★★☆)

**Scenario**

Ten ATT&CK techniques were simulated. Six were detected; four were missed. Calculate the detection rate, rank the detection gaps by severity, and identify the TOP 3 gaps.

**Hints**
1. Detection rate = detected / total × 100
2. Gap priority: CRITICAL > HIGH > MEDIUM
3. Format: `60,T1003.001,T1486,T1078` → SHA-256 is the flag
4. Also calculate the expected rate after resolving the top 2 gaps

---

### C04 — TTP Extractor (★★★)

**Scenario**

Raw logs from a red team engagement are provided (Windows event logs + network PCAP + filesystem artifacts). Reconstruct the 6-step attack chain and map each step to ATT&CK technique IDs.

**Hints**
1. Focus on EventID 4688 (process creation), 4624 (logon), 4698 (scheduled task)
2. Use `python-evtx` or `Plaso` to build a unified timeline
3. Extract C2 IPs from PCAP: `tshark -r traffic.pcap -Y "tcp.port==443" -T fields -e ip.dst`
4. Join technique IDs in time order with `->` to form the flag input string

---

## CTF Script

See the Korean section above for the full Python 3.10+ CTF simulator (`06_purple_ctf_lab.py`). Usage:

```bash
python3 06_purple_ctf_lab.py --list
python3 06_purple_ctf_lab.py --challenge C04
python3 06_purple_ctf_lab.py --hint C04
python3 06_purple_ctf_lab.py --simulate C03
python3 06_purple_ctf_lab.py --demo-detection-rate
python3 06_purple_ctf_lab.py --challenge C01 --submit CTF{your_flag_here}
```
