> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# MITRE ATT&CK 기반 위협 헌팅

## 0. 초보자를 위한 개념 이해

### MITRE ATT&CK 기반 위협 헌팅이란?

MITRE ATT&CK는 실제 관찰된 공격자의 전술(Tactics)·기법(Techniques)·세부 기법(Sub-techniques)을 정리한 공개 지식 베이스다. 위협 헌팅에서는 이 프레임워크를 "헌팅 가설 생성기"로 활용한다. "공격자가 T1059.001(PowerShell)을 사용한다면 어떤 흔적을 남길까?"라는 질문에서 시작해 구체적인 SIEM 쿼리로 전환하는 방식이다. 공통 언어로 팀 간 소통, 탐지 커버리지 측정, 우선순위 결정에 활용된다.

**왜 배우는가:**
```
[MITRE ATT&CK의 실용적 가치]

  보안 팀이 "PowerShell 공격 탐지됐어요"라고 말할 때:
  → 막연한 설명, 대응 방향 불명확

  ATT&CK 언어 사용 시:
  → "T1059.001 탐지, TA0002 실행 전술 단계
     → 다음 단계 T1105(도구 전송) 예상
     → T1083(파일 탐색) 이후 T1041(데이터 유출) 가능성"
  → 구체적 대응, 다음 단계 예측 가능

  [커버리지 측정]
  우리 탐지 규칙이 ATT&CK 14개 전술 중
  몇 개를 커버하는가? → 헌팅 우선순위 결정
```

### 핵심 개념 정리

```
[MITRE ATT&CK 구조]

전술 (Tactics) - 공격의 목적(Why)
  TA0043: 정찰 (Reconnaissance)
  TA0042: 리소스 개발 (Resource Development)
  TA0001: 초기 접근 (Initial Access)
  TA0002: 실행 (Execution)
  TA0003: 지속성 (Persistence)
  TA0004: 권한 상승 (Privilege Escalation)
  TA0005: 방어 회피 (Defense Evasion)
  TA0006: 자격증명 접근 (Credential Access)
  TA0007: 탐색 (Discovery)
  TA0008: 횡적 이동 (Lateral Movement)
  TA0009: 수집 (Collection)
  TA0011: C2 명령 제어 (Command and Control)
  TA0010: 유출 (Exfiltration)
  TA0040: 영향 (Impact)

기법 (Techniques) - 공격 방법(How)
  T1059: 명령어 및 스크립트 인터프리터
    T1059.001: PowerShell
    T1059.003: Windows Command Shell
  T1078: 유효한 계정 사용
  T1486: 데이터 암호화 (랜섬웨어)

[헌팅을 위한 데이터 소스 매핑]
  T1059.001 (PowerShell) →
    Windows Security 4688, Sysmon 1, PowerShell 4104
  T1110 (Brute Force) →
    Windows Security 4625 (로그온 실패)
  T1078 (유효 계정) →
    Windows Security 4624 (로그온 성공)
```

### 필요한 도구 및 환경
- **ATT&CK Navigator**: 커버리지 매핑 시각화 도구 (웹 기반 무료)
- **Atomic Red Team**: ATT&CK 기법별 테스트 케이스 오픈소스
- **Sigma**: SIEM 중립적 탐지 규칙 형식 (YAML)
- **MISP**: 위협 인텔리전스 공유 플랫폼

### 기초 실습 예제
```python
import json
import urllib.request

# ATT&CK STIX 데이터에서 기법 정보를 조회하는 예제
# (오프라인 JSON 파일 사용 버전)

COMMON_TECHNIQUES = {
    "T1059.001": {
        "name": "PowerShell",
        "tactic": "실행 (Execution)",
        "data_sources": ["Windows Security 4688", "Sysmon EventID 1", "PS Script Block 4104"],
        "hunting_idea": "Base64 인코딩된 명령(-EncodedCommand), 다운로드 스트링(DownloadString)"
    },
    "T1078": {
        "name": "유효한 계정 사용",
        "tactic": "초기 접근/지속성/권한 상승",
        "data_sources": ["Windows Security 4624/4625", "AAD Sign-in Logs"],
        "hunting_idea": "비정상 시간대 로그온, 새 지역 IP, 비활성 계정 로그온"
    },
    "T1110": {
        "name": "무차별 대입 공격",
        "tactic": "자격증명 접근 (Credential Access)",
        "data_sources": ["Windows Security 4625", "AAD Sign-in Logs"],
        "hunting_idea": "단시간 다수 로그온 실패 (임계값: 10회/분)"
    },
    "T1486": {
        "name": "데이터 암호화 (Impact)",
        "tactic": "영향 (Impact)",
        "data_sources": ["Sysmon 11/23", "EDR 파일 이벤트"],
        "hunting_idea": "대량 파일 확장자 변경, 볼륨 쉐도우 복사본 삭제"
    },
}

def get_technique_hunting_guide(technique_id: str) -> None:
    """ATT&CK 기법에 대한 헌팅 가이드를 출력한다."""
    technique = COMMON_TECHNIQUES.get(technique_id)
    if not technique:
        print(f"[-] {technique_id} 정보 없음 (https://attack.mitre.org/ 참조)")
        return

    print(f"\n[*] {technique_id}: {technique['name']}")
    print(f"    전술: {technique['tactic']}")
    print(f"    데이터 소스: {', '.join(technique['data_sources'])}")
    print(f"    헌팅 아이디어: {technique['hunting_idea']}")

# 사용 예시
for tid in ["T1059.001", "T1078", "T1110"]:
    get_technique_hunting_guide(tid)
```

---

## 1. MITRE ATT&CK 프레임워크 심화

### 1.1 프레임워크 개요

MITRE ATT&CK(Adversarial Tactics, Techniques, and Common Knowledge)는 실제 관찰된 공격 행위를 기반으로 구축된 사이버 공격 지식 베이스다. 2013년 MITRE Corporation이 내부 프로젝트로 시작하여 현재 전 세계 보안 커뮤니티의 표준 언어로 자리잡았다.

**세 가지 매트릭스**:
- **Enterprise**: Windows/Linux/macOS/Network/Cloud 대상
- **Mobile**: Android/iOS 대상
- **ICS**: 산업제어시스템 대상

### 1.2 전술 (Tactics)

전술은 공격자의 **목표(Why)**를 나타낸다. 현재 Enterprise 매트릭스에는 14개 전술이 존재한다.

```
TA0043 - Reconnaissance       : 정찰 (공격 전 정보 수집)
TA0042 - Resource Development : 자원 개발 (인프라, 계정, 악성코드 준비)
TA0001 - Initial Access       : 초기 접근 (내부 네트워크 진입)
TA0002 - Execution            : 실행 (악성 코드 실행)
TA0003 - Persistence          : 지속성 (시스템 재시작 후에도 유지)
TA0004 - Privilege Escalation : 권한 상승
TA0005 - Defense Evasion      : 방어 우회
TA0006 - Credential Access    : 자격증명 접근
TA0007 - Discovery            : 탐색 (환경 파악)
TA0008 - Lateral Movement     : 횡적 이동
TA0009 - Collection           : 수집 (데이터 취합)
TA0011 - Command and Control  : 명령 제어
TA0010 - Exfiltration         : 유출
TA0040 - Impact               : 영향 (파괴, 암호화, 방해)
```

### 1.3 기술 (Techniques) 및 하위 기술 (Sub-techniques)

**기술(Technique)**: 공격자가 전술 목표를 달성하는 **방법(How)**. 현재 200개 이상.
**하위 기술(Sub-technique)**: 기술의 더 구체적인 구현 방식. 현재 400개 이상.

```
T1059 - Command and Scripting Interpreter (기술)
  ├── T1059.001 - PowerShell (하위 기술)
  ├── T1059.002 - AppleScript
  ├── T1059.003 - Windows Command Shell
  ├── T1059.004 - Unix Shell
  ├── T1059.005 - Visual Basic
  ├── T1059.006 - Python
  └── T1059.007 - JavaScript
```

### 1.4 데이터 구성 요소 (Data Components)

ATT&CK v12부터 도입된 개념으로, 각 기술을 탐지하기 위해 필요한 데이터를 구체화한다.

- **Data Source**: 데이터를 수집하는 소스 (예: Process, Network Traffic)
- **Data Component**: 소스 내 구체적인 데이터 유형 (예: Process Creation, Network Connection)

---

## 2. 전술별 헌팅 쿼리 패턴

### 2.1 Initial Access (TA0001)

**T1566 — Phishing**:
```
# Splunk SPL: 이메일 첨부 파일에서 실행된 프로세스
index=endpoint source="WinEventLog:Security" EventCode=4688
| eval parent_proc=lower(ParentProcessName)
| where match(parent_proc, "outlook\.exe|thunderbird\.exe|winword\.exe|excel\.exe")
| where NOT match(NewProcessName, "splunkd|svchost|conhost")
| stats count by NewProcessName, ParentProcessName, Computer, _time
| where count < 3
```

```
# KQL (Microsoft Sentinel): 피싱 문서 실행 탐지
DeviceProcessEvents
| where InitiatingProcessFileName in~ ("WINWORD.EXE", "EXCEL.EXE", "POWERPNT.EXE", "OUTLOOK.EXE")
| where FileName in~ ("powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe")
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by TimeGenerated desc
```

**T1190 — Exploit Public-Facing Application**:
```
# KQL: 웹 서버에서 비정상 자식 프로세스
DeviceProcessEvents
| where InitiatingProcessFileName in~ ("w3wp.exe", "httpd.exe", "nginx.exe", "tomcat9.exe")
| where FileName in~ ("cmd.exe", "powershell.exe", "sh", "bash", "python.exe")
| summarize count() by DeviceName, FileName, InitiatingProcessFileName
```

### 2.2 Execution (TA0002)

**T1059.001 — PowerShell**:
```
# SPL: 인코딩된 PowerShell 명령 탐지
index=endpoint EventCode=4688
| where CommandLine like "%powershell%"
| eval has_encoded=if(match(CommandLine, "-[Ee][Nn][Cc]|-[Ee][Nn][Cc][Oo][Dd][Ee][Dd]"), 1, 0)
| eval has_bypass=if(match(CommandLine, "-[Ee][Xx][Ee][Cc].*[Bb][Yy][Pp][Aa][Ss][Ss]"), 1, 0)
| eval has_hidden=if(match(CommandLine, "-[Ww][Ii][Nn][Dd][Oo][Ww][Ss][Tt][Yy][Ll][Ee].*[Hh][Ii][Dd][Dd][Ee][Nn]"), 1, 0)
| where has_encoded=1 OR has_bypass=1 OR has_hidden=1
| stats count by Computer, CommandLine, _time
```

**T1047 — WMI**:
```
# KQL: WMI를 통한 원격 실행
DeviceProcessEvents
| where InitiatingProcessFileName =~ "WmiPrvSE.exe"
| where FileName in~ ("cmd.exe", "powershell.exe", "cscript.exe")
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine, RemoteIP
```

### 2.3 Persistence (TA0003)

**T1547.001 — Registry Run Keys**:
```
# KQL: 비정상적인 레지스트리 자동실행 키 수정
DeviceRegistryEvents
| where RegistryKey has_any (
    @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    @"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run"
)
| where ActionType == "RegistryValueSet"
| where not(InitiatingProcessFileName in~ ("svchost.exe", "MsMpEng.exe", "msiexec.exe"))
| project TimeGenerated, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName
```

**T1053.005 — Scheduled Task**:
```
# SPL: 예약 작업 생성 탐지
index=wineventlog EventCode=4698
| eval task_name=xml_decode(Task_Name)
| eval command=xml_decode(Command)
| where NOT (match(task_name, "Microsoft|Windows|MicrosoftEdge"))
| stats count by Computer, task_name, command, User, _time
```

### 2.4 Privilege Escalation (TA0004)

**T1055 — Process Injection**:
```
# KQL: 비정상 메모리 할당 패턴
DeviceEvents
| where ActionType == "CreateRemoteThreadApiCall"
| where not(InitiatingProcessFileName in~ ("svchost.exe", "csrss.exe", "lsass.exe"))
| project TimeGenerated, DeviceName, InitiatingProcessFileName, ProcessId, FileName, RemoteUrl
```

### 2.5 Defense Evasion (TA0005)

**T1036 — Masquerading**:
```
# SPL: 알려진 시스템 프로세스 이름을 사칭하는 프로세스
index=endpoint EventCode=4688
| eval proc_name=lower(mvindex(split(NewProcessName, "\\"), -1))
| where proc_name IN ("svchost.exe", "lsass.exe", "explorer.exe", "csrss.exe")
| eval expected_path=case(
    proc_name="svchost.exe", "c:\\windows\\system32\\svchost.exe",
    proc_name="lsass.exe", "c:\\windows\\system32\\lsass.exe",
    proc_name="explorer.exe", "c:\\windows\\explorer.exe",
    true(), "unknown"
)
| where NOT match(lower(NewProcessName), replace(lower(expected_path), "\\\\", "\\\\\\\\"))
| stats count by Computer, NewProcessName, ParentProcessName
```

**T1027 — Obfuscated Files/Information**:
```
# KQL: 높은 엔트로피를 가진 PowerShell 명령 (Base64 인코딩 기반)
DeviceProcessEvents
| where FileName =~ "powershell.exe"
| where strlen(ProcessCommandLine) > 500
| extend b64_chunks = extract_all(@"[A-Za-z0-9+/]{100,}={0,2}", ProcessCommandLine)
| where array_length(b64_chunks) > 0
| project TimeGenerated, DeviceName, ProcessCommandLine
```

### 2.6 Credential Access (TA0006)

**T1003.001 — LSASS Memory**:
```
# KQL: LSASS 프로세스 접근 탐지
DeviceEvents
| where ActionType == "OpenProcessApiCall"
| where FileName =~ "lsass.exe"
| where not(InitiatingProcessFileName in~ ("MsMpEng.exe", "csrss.exe", "wininit.exe", "svchost.exe"))
| project TimeGenerated, DeviceName, InitiatingProcessFileName, ProcessCommandLine
```

### 2.7 Lateral Movement (TA0008)

**T1021.001 — RDP**:
```
# SPL: 비정상 시간대 RDP 접근
index=wineventlog EventCode=4624 Logon_Type=10
| eval hour=strftime(_time, "%H")
| where hour < 6 OR hour > 22
| stats count by src_ip, dest, Account_Name, _time
| where count > 3
```

**T1021.002 — SMB/Windows Admin Shares**:
```
# KQL: PsExec 패턴 탐지
DeviceProcessEvents
| where ProcessCommandLine has_any ("\\ADMIN$", "\\C$", "\\IPC$")
| where FileName in~ ("psexec.exe", "psexesvc.exe", "paexec.exe", "remcom.exe")
```

### 2.8 Exfiltration (TA0010)

**T1048 — Exfiltration Over Alternative Protocol**:
```
# SPL: 비정상 DNS 쿼리 (DNS 터널링)
index=dns
| eval query_len=len(query)
| where query_len > 50
| eval subdomain_count=len(split(query, ".")) - 2
| where subdomain_count > 4
| stats avg(query_len) as avg_len, count by src, query
| where count > 100
| sort - avg_len
```

---

## 3. ATT&CK Navigator 활용

### 3.1 Navigator란

ATT&CK Navigator는 MITRE ATT&CK 매트릭스를 시각화하는 웹 기반 도구다. 탐지 커버리지, 위협 그룹 TTP, 헌팅 계획을 레이어로 표현한다.

**설치 (로컬)**:
```bash
git clone https://github.com/mitre-attack/attack-navigator.git
cd attack-navigator
npm install
ng serve
```

### 3.2 레이어 활용 사례

1. **커버리지 레이어**: 현재 탐지 가능한 기술 표시
2. **위협 그룹 레이어**: 특정 APT의 사용 기술 강조
3. **비교 레이어**: 커버리지와 위협 그룹 레이어 오버레이 → 공백 식별

### 3.3 JSON 레이어 형식

```json
{
  "name": "Hunt Coverage Layer",
  "versions": {"attack": "14", "navigator": "4.9"},
  "domain": "enterprise-attack",
  "techniques": [
    {
      "techniqueID": "T1059.001",
      "score": 100,
      "color": "#4caf50",
      "comment": "PowerShell Script Block Logging 활성화"
    },
    {
      "techniqueID": "T1003.001",
      "score": 50,
      "color": "#ffeb3b",
      "comment": "부분 탐지 - Mimikatz만 탐지"
    },
    {
      "techniqueID": "T1055",
      "score": 0,
      "color": "#f44336",
      "comment": "미탐지 - 헌팅 필요"
    }
  ]
}
```

---

## 4. 캠페인별 TTP 분석

### 4.1 APT28 (Fancy Bear, Sofacy)

**배경**: 러시아 GRU 산하. 정치·군사·정보기관 대상 첩보 활동.

**주요 TTP**:
```
Initial Access   : T1566 (Spearphishing), T1189 (Drive-by Compromise)
Execution        : T1059.003 (CMD), T1106 (Native API)
Persistence      : T1547.001 (Run Keys), T1543.003 (Windows Service)
Defense Evasion  : T1140 (Deobfuscate), T1027 (Obfuscation)
C2               : T1071.001 (Web Protocols), T1573 (Encrypted Channel)
Exfiltration     : T1041 (C2 Channel), T1048.003 (Non-C2 Protocol)
```

**특징적 도구**: X-Agent, Sofacy, Zebrocy, Drovorub

**헌팅 포인트**:
- HTTPS를 통한 비정상 비콘 패턴 (일정 간격 통신)
- 러시아 IP 범위에서의 연결 (단독 IOC로 사용 금지)
- lnk 파일을 통한 악성코드 실행

### 4.2 Lazarus Group (APT38)

**배경**: 북한 정찰총국 산하. 금융 기관 공격 및 사이버 절도.

**주요 TTP**:
```
Initial Access   : T1566.001 (Spearphishing Attachment)
Execution        : T1059.005 (VBScript), T1059.001 (PowerShell)
Persistence      : T1543.003 (Windows Service)
Defense Evasion  : T1036.005 (Match Legitimate Name)
Credential Access: T1555 (Credentials from Store)
Lateral Movement : T1021.001 (RDP), T1570 (Lateral Tool Transfer)
Exfiltration     : T1048 (Alternative Protocol)
```

**특징적 도구**: BLINDINGCAN, HOPLIGHT, ELECTRICFISH

**헌팅 포인트**:
- 금융 소프트웨어 (SWIFT 터미널) 프로세스에서 자식 프로세스 생성
- 비정상 FTP/SFTP 연결
- 비표준 포트를 통한 데이터 전송

### 4.3 FIN7 (Carbanak)

**배경**: 금융 범죄 조직. POS 단말기, 호텔, 레스토랑 체인 대상.

**주요 TTP**:
```
Initial Access   : T1566.001 (Spearphishing), T1566.002 (Spearphishing Link)
Execution        : T1059.005 (VBS), T1204 (User Execution)
Persistence      : T1053.005 (Scheduled Task)
Collection       : T1056.001 (Keylogging), T1115 (Clipboard Data)
Exfiltration     : T1041 (C2 Channel)
```

**특징적 도구**: Carbanak, GRIFFON, BOOSTWRITE

**헌팅 포인트**:
- VBS/JScript로 시작하는 프로세스 체인
- `regsvr32.exe`를 통한 DLL 실행
- POS 프로세스 메모리 접근

---

## 5. Atomic Red Team으로 탐지 검증

### 5.1 Atomic Red Team이란

Red Canary가 개발한 오픈소스 테스트 라이브러리. 각 ATT&CK 기술에 대한 작은 단위(atomic) 테스트를 제공하여 탐지 유효성을 검증한다.

**설치**:
```powershell
# PowerShell (Windows)
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing);
Install-AtomicRedTeam -getAtomics
```

```bash
# Linux/macOS
git clone https://github.com/redcanaryco/atomic-red-team.git
pip install atomicredteam
```

### 5.2 테스트 실행 예시

```powershell
# T1003.001: LSASS 메모리 덤프 테스트
Invoke-AtomicTest T1003.001 -ShowDetails       # 상세 정보 확인
Invoke-AtomicTest T1003.001 -TestNumbers 1     # 특정 테스트 실행
Invoke-AtomicTest T1003.001 -Cleanup           # 정리

# T1059.001: PowerShell 인코딩 실행
Invoke-AtomicTest T1059.001 -TestNumbers 1,2,3

# 탐지 검증 워크플로:
# 1. Atomic 테스트 실행 → 2. SIEM에서 탐지 확인 → 3. 탐지 없으면 규칙 보완
```

### 5.3 탐지 갭 분석 프로세스

```
Atomic 테스트 실행
       ↓
SIEM/EDR에서 이벤트 확인
       ↓
탐지됨? ──YES──→ 기존 탐지 규칙 유효 → 커버리지 기록
       │
      NO
       ↓
로그 존재? ──YES──→ 탐지 규칙 부재 → 새 규칙 작성
       │
      NO
       ↓
로깅 설정 미흡 → 로그 수집 설정 보완
```

---

## 6. Python: ATT&CK API 조회 및 TTP 매핑 도구

```python
#!/usr/bin/env python3
"""
MITRE ATT&CK API 조회 및 TTP 매핑 CLI 도구
의존성: pip install requests

사용법: python3 attack_mapper.py [command] [options]
"""

import argparse
import json
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Optional
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError
from urllib.parse import urlencode

ATTACK_STIX_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
CACHE_PATH = Path.home() / ".threat_hunting" / "attack_cache.json"
CACHE_MAX_AGE_HOURS = 24

# 위협 그룹 TTP 데이터 (오프라인 참조용)
KNOWN_GROUPS: dict[str, dict[str, Any]] = {
    "APT28": {
        "alias": ["Fancy Bear", "Sofacy", "Pawn Storm"],
        "country": "Russia",
        "sector": ["Government", "Military", "Political"],
        "techniques": [
            "T1566", "T1189", "T1059.003", "T1106", "T1547.001",
            "T1543.003", "T1140", "T1027", "T1071.001", "T1573",
            "T1041", "T1048.003", "T1003", "T1056",
        ],
    },
    "Lazarus": {
        "alias": ["APT38", "Hidden Cobra", "Zinc"],
        "country": "North Korea",
        "sector": ["Financial", "Cryptocurrency", "Defense"],
        "techniques": [
            "T1566.001", "T1059.005", "T1059.001", "T1543.003",
            "T1036.005", "T1555", "T1021.001", "T1570", "T1048",
            "T1003.001", "T1082", "T1016",
        ],
    },
    "FIN7": {
        "alias": ["Carbanak", "Navigator Group"],
        "country": "Unknown (Criminal)",
        "sector": ["Retail", "Hospitality", "Financial", "Healthcare"],
        "techniques": [
            "T1566.001", "T1566.002", "T1059.005", "T1204",
            "T1053.005", "T1056.001", "T1115", "T1041",
            "T1027", "T1036", "T1078",
        ],
    },
    "APT41": {
        "alias": ["Double Dragon", "Winnti", "Barium"],
        "country": "China",
        "sector": ["Technology", "Healthcare", "Telecommunications", "Gaming"],
        "techniques": [
            "T1190", "T1133", "T1566", "T1059.001", "T1059.003",
            "T1547.001", "T1053.005", "T1055", "T1078", "T1021.001",
            "T1003.001", "T1083", "T1082", "T1041", "T1048",
        ],
    },
}

# 전술 정보
TACTICS: dict[str, dict[str, str]] = {
    "TA0043": {"name": "Reconnaissance", "order": "0"},
    "TA0042": {"name": "Resource Development", "order": "1"},
    "TA0001": {"name": "Initial Access", "order": "2"},
    "TA0002": {"name": "Execution", "order": "3"},
    "TA0003": {"name": "Persistence", "order": "4"},
    "TA0004": {"name": "Privilege Escalation", "order": "5"},
    "TA0005": {"name": "Defense Evasion", "order": "6"},
    "TA0006": {"name": "Credential Access", "order": "7"},
    "TA0007": {"name": "Discovery", "order": "8"},
    "TA0008": {"name": "Lateral Movement", "order": "9"},
    "TA0009": {"name": "Collection", "order": "10"},
    "TA0011": {"name": "Command and Control", "order": "11"},
    "TA0010": {"name": "Exfiltration", "order": "12"},
    "TA0040": {"name": "Impact", "order": "13"},
}


def _load_cache() -> Optional[dict]:
    """캐시 로드 (유효 시간 내)."""
    if not CACHE_PATH.exists():
        return None
    try:
        data = json.loads(CACHE_PATH.read_text(encoding="utf-8"))
        age = time.time() - data.get("cached_at", 0)
        if age < CACHE_MAX_AGE_HOURS * 3600:
            return data["content"]
    except (json.JSONDecodeError, KeyError, OSError):
        pass
    return None


def _save_cache(content: dict) -> None:
    """캐시 저장."""
    CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
    try:
        CACHE_PATH.write_text(
            json.dumps({"cached_at": time.time(), "content": content}, ensure_ascii=False),
            encoding="utf-8",
        )
    except OSError:
        pass


def fetch_attack_data(force_refresh: bool = False) -> dict:
    """ATT&CK STIX 데이터 로드 (캐시 우선)."""
    if not force_refresh:
        cached = _load_cache()
        if cached:
            print("[*] ATT&CK 캐시 데이터 사용")
            return cached

    print("[*] ATT&CK STIX 데이터 다운로드 중... (시간이 걸릴 수 있습니다)")
    try:
        req = Request(ATTACK_STIX_URL, headers={"User-Agent": "ThreatHunter/1.0"})
        with urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        _save_cache(data)
        print("[+] ATT&CK 데이터 다운로드 완료")
        return data
    except (URLError, HTTPError) as e:
        print(f"[ERROR] ATT&CK 데이터 다운로드 실패: {e}", file=sys.stderr)
        print("[*] 오프라인 모드로 전환합니다.", file=sys.stderr)
        return {}


def parse_techniques(attack_data: dict) -> dict[str, dict]:
    """STIX 데이터에서 기술 정보 파싱."""
    techniques: dict[str, dict] = {}
    if not attack_data:
        return techniques

    for obj in attack_data.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("x_mitre_deprecated", False) or obj.get("revoked", False):
            continue

        ext_refs = obj.get("external_references", [])
        tech_id = next(
            (r["external_id"] for r in ext_refs if r.get("source_name") == "mitre-attack"),
            None,
        )
        if not tech_id:
            continue

        tactics = [
            kc["phase_name"]
            for kc in obj.get("kill_chain_phases", [])
            if kc.get("kill_chain_name") == "mitre-attack"
        ]

        techniques[tech_id] = {
            "id": tech_id,
            "name": obj.get("name", ""),
            "description": obj.get("description", "")[:200],
            "tactics": tactics,
            "platforms": obj.get("x_mitre_platforms", []),
            "detection": obj.get("x_mitre_detection", "")[:200],
            "data_sources": obj.get("x_mitre_data_sources", []),
            "is_subtechnique": "." in tech_id,
        }

    return techniques


def cmd_group_ttp(args: argparse.Namespace) -> None:
    """위협 그룹의 TTP 출력."""
    group_name = args.group
    match_key = next(
        (k for k in KNOWN_GROUPS if k.lower() == group_name.lower()
         or group_name.lower() in [a.lower() for a in KNOWN_GROUPS[k]["alias"]]),
        None,
    )
    if not match_key:
        print(f"[ERROR] 알려진 그룹이 아닙니다: {group_name}", file=sys.stderr)
        print(f"사용 가능한 그룹: {', '.join(KNOWN_GROUPS.keys())}")
        sys.exit(1)

    group = KNOWN_GROUPS[match_key]
    print(f"\n{'='*60}")
    print(f"위협 그룹: {match_key}")
    print(f"{'='*60}")
    print(f"별칭: {', '.join(group['alias'])}")
    print(f"출처 국가: {group['country']}")
    print(f"대상 섹터: {', '.join(group['sector'])}")
    print(f"\n사용 ATT&CK 기술 ({len(group['techniques'])}개):")

    # 기술을 전술별로 분류
    tactics_map: dict[str, list[str]] = {}
    for tech_id in group["techniques"]:
        # 간단한 전술 분류 (오프라인)
        prefix = tech_id.split(".")[0]
        tactics_map.setdefault(prefix, []).append(tech_id)

    for tech_id in sorted(group["techniques"]):
        is_sub = "." in tech_id
        indent = "  └─ " if is_sub else "  "
        print(f"{indent}{tech_id}")

    if args.export:
        export_path = Path(args.export)
        export_path.write_text(
            json.dumps(group, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        print(f"\n[+] 내보내기 완료: {args.export}")


def cmd_technique_info(args: argparse.Namespace) -> None:
    """기술 ID 상세 정보 조회."""
    attack_data = fetch_attack_data(args.refresh)
    techniques = parse_techniques(attack_data)

    tech_ids = [t.strip().upper() for t in args.technique_ids.split(",")]

    def fetch_one(tid: str) -> Optional[dict]:
        return techniques.get(tid)

    results = {}
    with ThreadPoolExecutor(max_workers=min(len(tech_ids), 5)) as executor:
        futures = {executor.submit(fetch_one, tid): tid for tid in tech_ids}
        for future in as_completed(futures):
            tid = futures[future]
            try:
                result = future.result()
                results[tid] = result
            except Exception as e:
                results[tid] = None
                print(f"[ERROR] {tid} 조회 실패: {e}", file=sys.stderr)

    for tid in tech_ids:
        tech = results.get(tid)
        if not tech:
            # 오프라인 기본 정보
            print(f"\n[{tid}] 정보를 찾을 수 없습니다. (오프라인 데이터 없음)")
            continue

        print(f"\n{'='*50}")
        print(f"기술 ID  : {tech['id']}")
        print(f"이름     : {tech['name']}")
        print(f"전술     : {', '.join(tech['tactics'])}")
        print(f"플랫폼   : {', '.join(tech['platforms'])}")
        print(f"데이터소스: {', '.join(tech['data_sources'][:3])}")
        print(f"설명     : {tech['description'][:150]}...")
        if tech.get("detection"):
            print(f"탐지     : {tech['detection'][:150]}...")


def cmd_coverage(args: argparse.Namespace) -> None:
    """탐지 커버리지 분석 및 갭 식별."""
    if not args.covered_file:
        print("[*] 커버된 기술 파일이 없습니다. 예시 출력:")
        print('    python3 attack_mapper.py coverage --covered-file covered.txt')
        print("    (covered.txt: 각 줄에 기술 ID, 예: T1059.001)")
        return

    covered_path = Path(args.covered_file)
    if not covered_path.exists():
        print(f"[ERROR] 파일 없음: {args.covered_file}", file=sys.stderr)
        sys.exit(1)

    covered_ids = set()
    for line in covered_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            covered_ids.add(line.upper())

    # 위협 그룹 TTP와 비교
    if args.group:
        match_key = next(
            (k for k in KNOWN_GROUPS if k.lower() == args.group.lower()),
            None,
        )
        if not match_key:
            print(f"[ERROR] 그룹 없음: {args.group}", file=sys.stderr)
            sys.exit(1)
        group_ttps = set(KNOWN_GROUPS[match_key]["techniques"])
        covered_in_group = covered_ids & group_ttps
        uncovered = group_ttps - covered_ids

        print(f"\n[{match_key}] TTP 커버리지 분석")
        print(f"{'='*50}")
        print(f"그룹 전체 TTP  : {len(group_ttps)}개")
        print(f"탐지 커버 중   : {len(covered_in_group)}개")
        print(f"탐지 미적용    : {len(uncovered)}개")
        coverage_pct = len(covered_in_group) / len(group_ttps) * 100 if group_ttps else 0
        print(f"커버리지       : {coverage_pct:.1f}%")

        if uncovered:
            print(f"\n[!] 탐지 갭 (우선 헌팅 권장):")
            for tid in sorted(uncovered):
                print(f"    - {tid}")
    else:
        print(f"커버된 기술 수: {len(covered_ids)}")
        print("커버된 기술 목록:")
        for tid in sorted(covered_ids):
            print(f"  {tid}")


def cmd_navigator_export(args: argparse.Namespace) -> None:
    """ATT&CK Navigator 레이어 JSON 생성."""
    layers = []

    # 소스에 따라 기술 목록 결정
    if args.group:
        match_key = next(
            (k for k in KNOWN_GROUPS if k.lower() == args.group.lower()),
            None,
        )
        if not match_key:
            print(f"[ERROR] 그룹 없음: {args.group}", file=sys.stderr)
            sys.exit(1)
        tech_ids = KNOWN_GROUPS[match_key]["techniques"]
        layer_name = f"{match_key} TTP Layer"
        color = "#ff6b6b"
    elif args.covered_file:
        covered_path = Path(args.covered_file)
        tech_ids = [
            l.strip().upper()
            for l in covered_path.read_text(encoding="utf-8").splitlines()
            if l.strip() and not l.startswith("#")
        ]
        layer_name = "Detection Coverage Layer"
        color = "#4caf50"
    else:
        print("[ERROR] --group 또는 --covered-file 중 하나를 지정하세요.", file=sys.stderr)
        sys.exit(1)

    for tid in tech_ids:
        layers.append({
            "techniqueID": tid,
            "color": color,
            "comment": f"Source: {args.group or args.covered_file}",
            "enabled": True,
            "score": 100,
        })

    navigator_layer = {
        "name": layer_name,
        "versions": {"attack": "14", "navigator": "4.9.1", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": f"Generated by attack_mapper.py",
        "techniques": layers,
        "gradient": {
            "colors": ["#ff6666", "#ffe766", "#8ec843"],
            "minValue": 0,
            "maxValue": 100,
        },
        "legendItems": [{"label": layer_name, "color": color}],
    }

    output_path = Path(args.output) if args.output else Path("navigator_layer.json")
    output_path.write_text(
        json.dumps(navigator_layer, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    print(f"[+] Navigator 레이어 생성: {output_path}")
    print(f"    기술 수: {len(layers)}")
    print(f"    사용법: https://mitre-attack.github.io/attack-navigator/ 에서 업로드")


def cmd_compare_groups(args: argparse.Namespace) -> None:
    """두 위협 그룹의 TTP 비교."""
    groups_input = [g.strip() for g in args.groups.split(",")]
    if len(groups_input) < 2:
        print("[ERROR] 최소 2개의 그룹을 쉼표로 구분하여 입력하세요.", file=sys.stderr)
        sys.exit(1)

    resolved: dict[str, set[str]] = {}
    for g in groups_input:
        match_key = next(
            (k for k in KNOWN_GROUPS if k.lower() == g.lower()),
            None,
        )
        if not match_key:
            print(f"[WARN] 알려지지 않은 그룹 (건너뜀): {g}", file=sys.stderr)
            continue
        resolved[match_key] = set(KNOWN_GROUPS[match_key]["techniques"])

    if len(resolved) < 2:
        print("[ERROR] 유효한 그룹이 2개 미만입니다.", file=sys.stderr)
        sys.exit(1)

    group_names = list(resolved.keys())
    all_ttps = set().union(*resolved.values())
    common_ttps = set.intersection(*resolved.values())
    unique: dict[str, set[str]] = {g: resolved[g] - set().union(*(resolved[h] for h in resolved if h != g))
                                    for g in resolved}

    print(f"\n위협 그룹 TTP 비교: {' vs '.join(group_names)}")
    print(f"{'='*60}")
    print(f"공통 TTP ({len(common_ttps)}개):")
    for tid in sorted(common_ttps):
        print(f"  {tid}")

    for g, ttps in unique.items():
        print(f"\n{g} 고유 TTP ({len(ttps)}개):")
        for tid in sorted(ttps):
            print(f"  {tid}")

    print(f"\n전체 고유 기술 수: {len(all_ttps)}개")
    print(f"공통 기술 비율: {len(common_ttps)/len(all_ttps)*100:.1f}%")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="MITRE ATT&CK API 조회 및 TTP 매핑 CLI 도구",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
예시:
  python3 attack_mapper.py group-ttp --group APT28
  python3 attack_mapper.py group-ttp --group Lazarus --export lazarus_ttp.json
  python3 attack_mapper.py technique-info --technique-ids T1059.001,T1003.001
  python3 attack_mapper.py coverage --covered-file my_detections.txt --group FIN7
  python3 attack_mapper.py navigator-export --group APT28 --output apt28_layer.json
  python3 attack_mapper.py compare-groups --groups "APT28,Lazarus,FIN7"
        """,
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # group-ttp
    p_g = sub.add_parser("group-ttp", help="위협 그룹 TTP 조회")
    p_g.add_argument("--group", required=True, help="그룹 이름 (APT28, Lazarus, FIN7, APT41)")
    p_g.add_argument("--export", help="JSON 파일로 내보내기")
    p_g.set_defaults(func=cmd_group_ttp)

    # technique-info
    p_t = sub.add_parser("technique-info", help="ATT&CK 기술 상세 조회")
    p_t.add_argument("--technique-ids", required=True, help="기술 ID (쉼표 구분, 예: T1059.001,T1003)")
    p_t.add_argument("--refresh", action="store_true", help="캐시 갱신")
    p_t.set_defaults(func=cmd_technique_info)

    # coverage
    p_c = sub.add_parser("coverage", help="탐지 커버리지 분석")
    p_c.add_argument("--covered-file", help="커버된 기술 ID 파일 (줄당 1개)")
    p_c.add_argument("--group", help="비교할 위협 그룹")
    p_c.set_defaults(func=cmd_coverage)

    # navigator-export
    p_n = sub.add_parser("navigator-export", help="ATT&CK Navigator 레이어 생성")
    p_n.add_argument("--group", help="위협 그룹 기준")
    p_n.add_argument("--covered-file", help="커버리지 파일 기준")
    p_n.add_argument("--output", help="출력 파일명 (기본: navigator_layer.json)")
    p_n.set_defaults(func=cmd_navigator_export)

    # compare-groups
    p_cmp = sub.add_parser("compare-groups", help="다수 위협 그룹 TTP 비교")
    p_cmp.add_argument("--groups", required=True, help="그룹 목록 (쉼표 구분, 예: APT28,Lazarus)")
    p_cmp.set_defaults(func=cmd_compare_groups)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
```

---

## 7. 헌팅 쿼리 작성 모범 사례

### 7.1 효율적인 ATT&CK 기반 쿼리 원칙

1. **구체적 기술에서 시작**: 광범위한 탐지보다 특정 하위 기술을 대상으로
2. **컨텍스트 포함**: 프로세스 계층, 사용자 컨텍스트, 시간대 고려
3. **화이트리스트 활용**: 알려진 정상 행위를 제외하여 노이즈 감소
4. **베이스라인 비교**: 평균 대비 이탈 정도로 이상 탐지
5. **여러 데이터 소스 연관**: 단일 소스보다 멀티 소스 상관관계로 신뢰도 향상

### 7.2 TTP 커버리지 우선순위 결정 매트릭스

| 기술 | 공격 빈도 | 피해 심각도 | 현재 커버리지 | 우선순위 |
|------|-----------|-------------|---------------|----------|
| T1003.001 | 높음 | 높음 | 낮음 | Critical |
| T1059.001 | 높음 | 중간 | 중간 | High |
| T1055 | 중간 | 높음 | 낮음 | High |
| T1021.001 | 높음 | 중간 | 높음 | Medium |
| T1083 | 높음 | 낮음 | 낮음 | Low |

---

<a name="english"></a>

# MITRE ATT&CK-Based Threat Hunting

## 1. Deep Dive into the MITRE ATT&CK Framework

### 1.1 Framework Overview

MITRE ATT&CK (Adversarial Tactics, Techniques, and Common Knowledge) is a cyber attack knowledge base built on real-world observed adversary behaviors. Started as an internal project by MITRE Corporation in 2013, it has become the standard language of the global security community.

**Three Matrices**:
- **Enterprise**: Targeting Windows/Linux/macOS/Network/Cloud
- **Mobile**: Targeting Android/iOS
- **ICS**: Targeting Industrial Control Systems

### 1.2 Tactics

Tactics represent the adversary's **goal (Why)**. The Enterprise matrix currently contains 14 tactics.

```
TA0043 - Reconnaissance       : Pre-attack information gathering
TA0042 - Resource Development : Preparing infrastructure, accounts, malware
TA0001 - Initial Access       : Gaining entry to the internal network
TA0002 - Execution            : Running malicious code
TA0003 - Persistence          : Maintaining presence after system restarts
TA0004 - Privilege Escalation : Gaining higher-level permissions
TA0005 - Defense Evasion      : Avoiding detection
TA0006 - Credential Access    : Stealing credentials
TA0007 - Discovery            : Exploring the environment
TA0008 - Lateral Movement     : Moving through the network
TA0009 - Collection           : Gathering data of interest
TA0011 - Command and Control  : Communicating with compromised systems
TA0010 - Exfiltration         : Stealing data out of the network
TA0040 - Impact               : Disruption, encryption, destruction
```

### 1.3 Techniques and Sub-techniques

**Technique**: The **method (How)** an adversary achieves a tactical goal. Currently 200+.
**Sub-technique**: A more specific implementation of a technique. Currently 400+.

```
T1059 - Command and Scripting Interpreter (Technique)
  ├── T1059.001 - PowerShell (Sub-technique)
  ├── T1059.002 - AppleScript
  ├── T1059.003 - Windows Command Shell
  ├── T1059.004 - Unix Shell
  ├── T1059.005 - Visual Basic
  ├── T1059.006 - Python
  └── T1059.007 - JavaScript
```

### 1.4 Data Components

Introduced in ATT&CK v12, this concept specifies the data needed to detect each technique.

- **Data Source**: The source collecting the data (e.g., Process, Network Traffic)
- **Data Component**: Specific data types within a source (e.g., Process Creation, Network Connection)

---

## 2. Hunting Query Patterns by Tactic

### 2.1 Initial Access (TA0001)

**T1566 — Phishing**:
```
# Splunk SPL: Processes spawned from email attachments
index=endpoint source="WinEventLog:Security" EventCode=4688
| eval parent_proc=lower(ParentProcessName)
| where match(parent_proc, "outlook\.exe|thunderbird\.exe|winword\.exe|excel\.exe")
| where NOT match(NewProcessName, "splunkd|svchost|conhost")
| stats count by NewProcessName, ParentProcessName, Computer, _time
| where count < 3
```

```
# KQL (Microsoft Sentinel): Detect phishing document execution
DeviceProcessEvents
| where InitiatingProcessFileName in~ ("WINWORD.EXE", "EXCEL.EXE", "POWERPNT.EXE", "OUTLOOK.EXE")
| where FileName in~ ("powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe")
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by TimeGenerated desc
```

**T1190 — Exploit Public-Facing Application**:
```
# KQL: Abnormal child processes from web servers
DeviceProcessEvents
| where InitiatingProcessFileName in~ ("w3wp.exe", "httpd.exe", "nginx.exe", "tomcat9.exe")
| where FileName in~ ("cmd.exe", "powershell.exe", "sh", "bash", "python.exe")
| summarize count() by DeviceName, FileName, InitiatingProcessFileName
```

### 2.2 Execution (TA0002)

**T1059.001 — PowerShell**:
```
# SPL: Detect encoded PowerShell commands
index=endpoint EventCode=4688
| where CommandLine like "%powershell%"
| eval has_encoded=if(match(CommandLine, "-[Ee][Nn][Cc]|-[Ee][Nn][Cc][Oo][Dd][Ee][Dd]"), 1, 0)
| eval has_bypass=if(match(CommandLine, "-[Ee][Xx][Ee][Cc].*[Bb][Yy][Pp][Aa][Ss][Ss]"), 1, 0)
| eval has_hidden=if(match(CommandLine, "-[Ww][Ii][Nn][Dd][Oo][Ww][Ss][Tt][Yy][Ll][Ee].*[Hh][Ii][Dd][Dd][Ee][Nn]"), 1, 0)
| where has_encoded=1 OR has_bypass=1 OR has_hidden=1
| stats count by Computer, CommandLine, _time
```

**T1047 — WMI**:
```
# KQL: Remote execution via WMI
DeviceProcessEvents
| where InitiatingProcessFileName =~ "WmiPrvSE.exe"
| where FileName in~ ("cmd.exe", "powershell.exe", "cscript.exe")
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine, RemoteIP
```

### 2.3 Persistence (TA0003)

**T1547.001 — Registry Run Keys**:
```
# KQL: Abnormal registry autorun key modifications
DeviceRegistryEvents
| where RegistryKey has_any (
    @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    @"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run"
)
| where ActionType == "RegistryValueSet"
| where not(InitiatingProcessFileName in~ ("svchost.exe", "MsMpEng.exe", "msiexec.exe"))
| project TimeGenerated, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName
```

**T1053.005 — Scheduled Task**:
```
# SPL: Detect scheduled task creation
index=wineventlog EventCode=4698
| eval task_name=xml_decode(Task_Name)
| eval command=xml_decode(Command)
| where NOT (match(task_name, "Microsoft|Windows|MicrosoftEdge"))
| stats count by Computer, task_name, command, User, _time
```

### 2.4 Privilege Escalation (TA0004)

**T1055 — Process Injection**:
```
# KQL: Abnormal memory allocation patterns
DeviceEvents
| where ActionType == "CreateRemoteThreadApiCall"
| where not(InitiatingProcessFileName in~ ("svchost.exe", "csrss.exe", "lsass.exe"))
| project TimeGenerated, DeviceName, InitiatingProcessFileName, ProcessId, FileName, RemoteUrl
```

### 2.5 Defense Evasion (TA0005)

**T1036 — Masquerading**:
```
# SPL: Processes impersonating known system process names
index=endpoint EventCode=4688
| eval proc_name=lower(mvindex(split(NewProcessName, "\\"), -1))
| where proc_name IN ("svchost.exe", "lsass.exe", "explorer.exe", "csrss.exe")
| eval expected_path=case(
    proc_name="svchost.exe", "c:\\windows\\system32\\svchost.exe",
    proc_name="lsass.exe", "c:\\windows\\system32\\lsass.exe",
    proc_name="explorer.exe", "c:\\windows\\explorer.exe",
    true(), "unknown"
)
| where NOT match(lower(NewProcessName), replace(lower(expected_path), "\\\\", "\\\\\\\\"))
| stats count by Computer, NewProcessName, ParentProcessName
```

**T1027 — Obfuscated Files/Information**:
```
# KQL: High-entropy PowerShell commands (Base64 encoding)
DeviceProcessEvents
| where FileName =~ "powershell.exe"
| where strlen(ProcessCommandLine) > 500
| extend b64_chunks = extract_all(@"[A-Za-z0-9+/]{100,}={0,2}", ProcessCommandLine)
| where array_length(b64_chunks) > 0
| project TimeGenerated, DeviceName, ProcessCommandLine
```

### 2.6 Credential Access (TA0006)

**T1003.001 — LSASS Memory**:
```
# KQL: Detect LSASS process access
DeviceEvents
| where ActionType == "OpenProcessApiCall"
| where FileName =~ "lsass.exe"
| where not(InitiatingProcessFileName in~ ("MsMpEng.exe", "csrss.exe", "wininit.exe", "svchost.exe"))
| project TimeGenerated, DeviceName, InitiatingProcessFileName, ProcessCommandLine
```

### 2.7 Lateral Movement (TA0008)

**T1021.001 — RDP**:
```
# SPL: RDP access during abnormal hours
index=wineventlog EventCode=4624 Logon_Type=10
| eval hour=strftime(_time, "%H")
| where hour < 6 OR hour > 22
| stats count by src_ip, dest, Account_Name, _time
| where count > 3
```

**T1021.002 — SMB/Windows Admin Shares**:
```
# KQL: PsExec pattern detection
DeviceProcessEvents
| where ProcessCommandLine has_any ("\\ADMIN$", "\\C$", "\\IPC$")
| where FileName in~ ("psexec.exe", "psexesvc.exe", "paexec.exe", "remcom.exe")
```

### 2.8 Exfiltration (TA0010)

**T1048 — Exfiltration Over Alternative Protocol**:
```
# SPL: Abnormal DNS queries (DNS tunneling)
index=dns
| eval query_len=len(query)
| where query_len > 50
| eval subdomain_count=len(split(query, ".")) - 2
| where subdomain_count > 4
| stats avg(query_len) as avg_len, count by src, query
| where count > 100
| sort - avg_len
```

---

## 3. Using ATT&CK Navigator

### 3.1 What is Navigator

ATT&CK Navigator is a web-based tool for visualizing the MITRE ATT&CK matrix. It represents detection coverage, threat group TTPs, and hunting plans as layers.

**Installation (local)**:
```bash
git clone https://github.com/mitre-attack/attack-navigator.git
cd attack-navigator
npm install
ng serve
```

### 3.2 Layer Use Cases

1. **Coverage Layer**: Show currently detectable techniques
2. **Threat Group Layer**: Highlight techniques used by specific APTs
3. **Comparison Layer**: Overlay coverage and threat group layers to identify gaps

### 3.3 JSON Layer Format

```json
{
  "name": "Hunt Coverage Layer",
  "versions": {"attack": "14", "navigator": "4.9"},
  "domain": "enterprise-attack",
  "techniques": [
    {
      "techniqueID": "T1059.001",
      "score": 100,
      "color": "#4caf50",
      "comment": "PowerShell Script Block Logging enabled"
    },
    {
      "techniqueID": "T1003.001",
      "score": 50,
      "color": "#ffeb3b",
      "comment": "Partial detection - Mimikatz only"
    },
    {
      "techniqueID": "T1055",
      "score": 0,
      "color": "#f44336",
      "comment": "No detection - hunting required"
    }
  ]
}
```

---

## 4. Campaign-Level TTP Analysis

### 4.1 APT28 (Fancy Bear, Sofacy)

**Background**: Under Russian GRU. Espionage targeting political, military, and intelligence agencies.

**Key TTPs**:
```
Initial Access   : T1566 (Spearphishing), T1189 (Drive-by Compromise)
Execution        : T1059.003 (CMD), T1106 (Native API)
Persistence      : T1547.001 (Run Keys), T1543.003 (Windows Service)
Defense Evasion  : T1140 (Deobfuscate), T1027 (Obfuscation)
C2               : T1071.001 (Web Protocols), T1573 (Encrypted Channel)
Exfiltration     : T1041 (C2 Channel), T1048.003 (Non-C2 Protocol)
```

**Characteristic Tools**: X-Agent, Sofacy, Zebrocy, Drovorub

**Hunting Points**:
- Abnormal beacon patterns over HTTPS (regular interval communications)
- Connections from Russian IP ranges (do not use as standalone IOC)
- Malware execution via .lnk files

### 4.2 Lazarus Group (APT38)

**Background**: Under North Korean Reconnaissance General Bureau. Financial institution attacks and cyber theft.

**Key TTPs**:
```
Initial Access   : T1566.001 (Spearphishing Attachment)
Execution        : T1059.005 (VBScript), T1059.001 (PowerShell)
Persistence      : T1543.003 (Windows Service)
Defense Evasion  : T1036.005 (Match Legitimate Name)
Credential Access: T1555 (Credentials from Store)
Lateral Movement : T1021.001 (RDP), T1570 (Lateral Tool Transfer)
Exfiltration     : T1048 (Alternative Protocol)
```

**Characteristic Tools**: BLINDINGCAN, HOPLIGHT, ELECTRICFISH

**Hunting Points**:
- Child process spawning from financial software (SWIFT terminal) processes
- Abnormal FTP/SFTP connections
- Data transfer via non-standard ports

### 4.3 FIN7 (Carbanak)

**Background**: Financial crime organization targeting POS terminals, hotels, and restaurant chains.

**Key TTPs**:
```
Initial Access   : T1566.001 (Spearphishing), T1566.002 (Spearphishing Link)
Execution        : T1059.005 (VBS), T1204 (User Execution)
Persistence      : T1053.005 (Scheduled Task)
Collection       : T1056.001 (Keylogging), T1115 (Clipboard Data)
Exfiltration     : T1041 (C2 Channel)
```

**Characteristic Tools**: Carbanak, GRIFFON, BOOSTWRITE

**Hunting Points**:
- Process chains initiated by VBS/JScript
- DLL execution via `regsvr32.exe`
- POS process memory access

---

## 5. Detection Validation with Atomic Red Team

### 5.1 What is Atomic Red Team

An open-source test library developed by Red Canary. Provides small unit (atomic) tests for each ATT&CK technique to validate detection effectiveness.

**Installation**:
```powershell
# PowerShell (Windows)
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing);
Install-AtomicRedTeam -getAtomics
```

```bash
# Linux/macOS
git clone https://github.com/redcanaryco/atomic-red-team.git
pip install atomicredteam
```

### 5.2 Test Execution Examples

```powershell
# T1003.001: LSASS memory dump test
Invoke-AtomicTest T1003.001 -ShowDetails       # View details
Invoke-AtomicTest T1003.001 -TestNumbers 1     # Run specific test
Invoke-AtomicTest T1003.001 -Cleanup           # Clean up

# T1059.001: PowerShell encoded execution
Invoke-AtomicTest T1059.001 -TestNumbers 1,2,3

# Detection validation workflow:
# 1. Run Atomic test -> 2. Confirm detection in SIEM -> 3. If not detected, improve rules
```

### 5.3 Detection Gap Analysis Process

```
Run Atomic Test
       |
Confirm event in SIEM/EDR
       |
Detected? --YES--> Existing detection rule valid -> Record coverage
       |
      NO
       |
Log exists? --YES--> Detection rule missing -> Write new rule
       |
      NO
       |
Insufficient logging config -> Improve log collection settings
```

---

## 6. Python: ATT&CK API Query and TTP Mapping Tool

```python
#!/usr/bin/env python3
"""
MITRE ATT&CK API Query and TTP Mapping CLI Tool
Dependencies: pip install requests

Usage: python3 attack_mapper.py [command] [options]
"""

import argparse
import json
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Optional
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError
from urllib.parse import urlencode

ATTACK_STIX_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
CACHE_PATH = Path.home() / ".threat_hunting" / "attack_cache.json"
CACHE_MAX_AGE_HOURS = 24

# Threat group TTP data (offline reference)
KNOWN_GROUPS: dict[str, dict[str, Any]] = {
    "APT28": {
        "alias": ["Fancy Bear", "Sofacy", "Pawn Storm"],
        "country": "Russia",
        "sector": ["Government", "Military", "Political"],
        "techniques": [
            "T1566", "T1189", "T1059.003", "T1106", "T1547.001",
            "T1543.003", "T1140", "T1027", "T1071.001", "T1573",
            "T1041", "T1048.003", "T1003", "T1056",
        ],
    },
    # ... (same structure for other groups)
}

def fetch_attack_data(force_refresh: bool = False) -> dict:
    """Load ATT&CK STIX data (cache-first)."""
    if not force_refresh:
        cached = _load_cache()
        if cached:
            print("[*] Using cached ATT&CK data")
            return cached

    print("[*] Downloading ATT&CK STIX data... (may take a moment)")
    try:
        req = Request(ATTACK_STIX_URL, headers={"User-Agent": "ThreatHunter/1.0"})
        with urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        _save_cache(data)
        print("[+] ATT&CK data download complete")
        return data
    except (URLError, HTTPError) as e:
        print(f"[ERROR] Failed to download ATT&CK data: {e}", file=sys.stderr)
        print("[*] Switching to offline mode.", file=sys.stderr)
        return {}
```

---

## 7. Best Practices for Writing Hunting Queries

### 7.1 Principles for Effective ATT&CK-Based Queries

1. **Start with specific techniques**: Target specific sub-techniques rather than broad detection
2. **Include context**: Consider process hierarchy, user context, and time of day
3. **Use whitelists**: Exclude known legitimate behaviors to reduce noise
4. **Compare to baselines**: Detect anomalies by measuring deviation from averages
5. **Correlate multiple data sources**: Improve confidence with multi-source correlation vs. single source

### 7.2 TTP Coverage Prioritization Matrix

| Technique | Attack Frequency | Impact Severity | Current Coverage | Priority |
|-----------|-----------------|-----------------|-----------------|----------|
| T1003.001 | High | High | Low | Critical |
| T1059.001 | High | Medium | Medium | High |
| T1055 | Medium | High | Low | High |
| T1021.001 | High | Medium | High | Medium |
| T1083 | High | Low | Low | Low |
