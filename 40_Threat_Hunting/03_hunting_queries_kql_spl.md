> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 헌팅 쿼리 — KQL 및 SPL 실전 가이드

## 0. 초보자를 위한 개념 이해

### KQL과 SPL이란?

KQL(Kusto Query Language)은 Microsoft Azure Sentinel/Log Analytics에서 사용하는 쿼리 언어이고, SPL(Search Processing Language)은 Splunk SIEM에서 사용하는 쿼리 언어다. 두 언어 모두 대용량 보안 로그를 빠르게 검색·분석·시각화하기 위해 설계됐으며, 위협 헌팅 분석가가 "PowerShell Base64 명령 실행 흔적"이나 "비정상 로그온 시도" 같은 보안 이벤트를 수백만 건의 로그에서 찾아내는 핵심 도구다.

**왜 배우는가:**
```
[SIEM 쿼리 없이 위협 헌팅이 불가능한 이유]

  일반적인 기업의 하루 로그 규모:
  Windows 이벤트: 수백만 건
  네트워크 플로우: 수억 건
  클라우드 API 호출: 수천만 건

  사람이 직접 분석: 불가능
  SIEM 쿼리로:
    "5분 안에 같은 계정으로 10개 국가에서 로그온"
    → 쿼리 실행 시간 수초~수십 초
    → 결과: 0건(정상) 또는 의심 이벤트 목록

  [쿼리 작성 능력의 실무 가치]
  SIEM 알림 규칙 작성 → 자동 탐지
  위협 헌팅 가설 검증 → 수동 탐색
  사고 대응 조사 → 공격 타임라인 재구성
```

### 핵심 개념 정리

```
[KQL vs SPL 비교]

KQL (Azure Sentinel/Log Analytics)
  파이프라인: | 연산자 체인
  예시: SecurityEvent | where EventID == 4625
        | summarize count() by Account
  특징: SQL과 유사, 시계열 분석 강력

SPL (Splunk)
  파이프라인: | 명령어 체인
  예시: index=wineventlog EventCode=4625
        | stats count by Account
  특징: 더 유연한 검색, 대규모 배포 강세

[주요 보안 이벤트 ID (Windows)]
  4624: 로그온 성공
  4625: 로그온 실패
  4648: 명시적 자격증명 로그온 (Pass-the-Hash 의심)
  4688: 새 프로세스 생성 (커맨드라인 포함)
  4698: 예약 작업 생성 (지속성)
  4732: 그룹에 사용자 추가
  7045: 새 서비스 설치

[Sysmon 이벤트 ID]
  1:  프로세스 생성 (상세 커맨드라인)
  3:  네트워크 연결
  11: 파일 생성
  13: 레지스트리 값 수정
  22: DNS 쿼리
```

### 필요한 도구 및 환경
- **Microsoft Sentinel 무료 체험**: Azure 계정으로 30일 무료
- **Splunk Free**: 단일 서버 500MB/일 무료 버전
- **Elastic SIEM + EQL**: 오픈소스 대안 (KQL 유사 문법)
- **Sigma**: SIEM 중립적 규칙 포맷 (KQL/SPL로 변환 가능)

### 기초 실습 예제
```python
def generate_hunting_query(
    technique_id: str,
    siem_type: str = "kql"
) -> str:
    """
    MITRE ATT&CK 기법 ID에 맞는 SIEM 헌팅 쿼리를 생성한다.
    siem_type: "kql" (Azure Sentinel) 또는 "spl" (Splunk)
    """
    queries = {
        "T1059.001": {  # PowerShell
            "kql": """// PowerShell 인코딩 명령 실행 탐지 (T1059.001)
SecurityEvent
| where EventID == 4688
| where CommandLine has_any (
    "-EncodedCommand", "-enc ", "-ec ",
    "DownloadString", "IEX", "Invoke-Expression"
  )
| project TimeGenerated, Account, CommandLine, Computer
| order by TimeGenerated desc""",
            "spl": """index=wineventlog EventCode=4688
(-EncodedCommand OR -enc OR DownloadString OR "IEX" OR "Invoke-Expression")
| table _time, Account, CommandLine, Computer
| sort -_time"""
        },
        "T1110": {  # Brute Force
            "kql": """// 무차별 대입 공격 탐지 (T1110) - 5분 내 10회 이상 실패
SecurityEvent
| where EventID == 4625
| summarize FailCount = count() by Account, IpAddress,
    bin(TimeGenerated, 5m)
| where FailCount >= 10
| order by FailCount desc""",
            "spl": """index=wineventlog EventCode=4625
| bin span=5m _time
| stats count as FailCount by Account, src_ip, _time
| where FailCount >= 10
| sort -FailCount"""
        }
    }

    query_set = queries.get(technique_id, {})
    query = query_set.get(siem_type, f"// {technique_id} 쿼리 없음")

    print(f"[*] {technique_id} 헌팅 쿼리 ({siem_type.upper()}):")
    print(query)
    return query

# 사용 예시
generate_hunting_query("T1059.001", "kql")
generate_hunting_query("T1110", "spl")
```

---

## 1. KQL (Kusto Query Language) 기초

### 1.1 개요

KQL은 Microsoft Azure Data Explorer, Microsoft Sentinel, Log Analytics에서 사용하는 쿼리 언어다. 읽기 전용 요청으로 대용량 데이터를 빠르게 처리하도록 설계되어 위협 헌팅에 최적화되어 있다.

### 1.2 기본 문법

```kql
// 테이블 조회 기본 구조
TableName
| operator1 [parameters]
| operator2 [parameters]
| ...

// 예시: SecurityEvent 테이블에서 로그온 실패 조회
SecurityEvent
| where EventID == 4625
| where TimeGenerated > ago(24h)
| project TimeGenerated, Account, Computer, IpAddress, LogonType
| order by TimeGenerated desc
```

### 1.3 핵심 연산자

**where**: 조건 필터링
```kql
// 비교 연산자
where EventID == 4624
where EventID != 4624
where EventID in (4624, 4625, 4688)
where EventID !in (4624, 4625)

// 문자열 연산자 (대소문자 구분)
where ProcessName == "powershell.exe"          // 정확히 일치 (대소문자 구분)
where ProcessName =~ "powershell.exe"          // 정확히 일치 (무시)
where CommandLine has "encodedcommand"         // 단어 포함 (빠름)
where CommandLine contains "encoded"           // 문자열 포함
where CommandLine startswith "powershell"      // 시작
where CommandLine endswith ".ps1"              // 끝
where CommandLine matches regex @"enc\w+"      // 정규식

// 복합 조건
where (EventID == 4688) and (SubjectUserName != "SYSTEM")
where (EventID == 4624) or (EventID == 4625)
```

**project**: 컬럼 선택 및 이름 변경
```kql
SecurityEvent
| project TimeGenerated, EventID, Account, Computer
| project-rename UserName = Account, Hostname = Computer
| project-away SubjectDomainName  // 특정 컬럼 제외
```

**extend**: 새 컬럼 추가 (파생 필드)
```kql
DeviceProcessEvents
| extend
    ProcessNameLower = tolower(FileName),
    CommandLineLen = strlen(ProcessCommandLine),
    Hour = hourofday(TimeGenerated),
    ParentName = tostring(split(InitiatingProcessFolderPath, "\\")[-1])
```

**summarize**: 집계
```kql
SecurityEvent
| where EventID == 4625
| summarize
    FailCount = count(),
    UniqueAccounts = dcount(Account),
    FirstFail = min(TimeGenerated),
    LastFail = max(TimeGenerated)
    by Computer, IpAddress
| where FailCount > 10
```

**join**: 테이블 조인
```kql
let SuspiciousIPs = externaldata(ip: string) [@"https://example.com/blocklist.txt"] with (format="txt");
DeviceNetworkEvents
| join kind=inner SuspiciousIPs on $left.RemoteIP == $right.ip
| project TimeGenerated, DeviceName, RemoteIP, RemotePort, InitiatingProcessFileName
```

**let**: 변수 및 함수 정의
```kql
let LookbackDays = 7d;
let SuspiciousProcesses = dynamic(["mimikatz.exe", "procdump.exe", "pwdump.exe"]);

DeviceProcessEvents
| where TimeGenerated > ago(LookbackDays)
| where FileName in~ (SuspiciousProcesses)
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine
```

**mv-expand**: 배열/딕셔너리 확장
```kql
SecurityEvent
| where EventID == 4688
| extend Tags = split(SubjectUserSid, "-")
| mv-expand Tag = Tags
| where tostring(Tag) startswith "S-1-5-21"
```

### 1.4 시계열 분석

```kql
// 시간대별 이벤트 추이
SecurityEvent
| where EventID == 4688
| summarize EventCount = count() by bin(TimeGenerated, 1h)
| render timechart

// 이동 평균을 이용한 이상 탐지
let Baseline = SecurityEvent
    | where TimeGenerated between(ago(14d)..ago(1d))
    | summarize BaselineCount = count() by bin(TimeGenerated, 1h), Computer
    | summarize AvgCount = avg(BaselineCount), StdDev = stdev(BaselineCount) by Computer;

SecurityEvent
| where TimeGenerated > ago(1d)
| summarize CurrentCount = count() by bin(TimeGenerated, 1h), Computer
| join Baseline on Computer
| extend ZScore = (CurrentCount - AvgCount) / StdDev
| where ZScore > 3
| project TimeGenerated, Computer, CurrentCount, AvgCount, ZScore
```

---

## 2. SPL (Search Processing Language) 기초

### 2.1 개요

SPL은 Splunk의 쿼리 언어다. 파이프 기반으로 데이터를 처리하며 강력한 통계 함수와 시각화 기능을 제공한다.

### 2.2 기본 문법

```splunk
// 기본 검색 구조
index=<인덱스> sourcetype=<소스타입> <조건>
| command1 [args]
| command2 [args]
```

### 2.3 핵심 명령어

**search/where**: 필터링
```splunk
// 기본 검색
index=windows EventCode=4688 NewProcessName=*powershell*

// where 명령어
index=windows EventCode=4688
| where len(CommandLine) > 500
| where match(CommandLine, "(?i)encodedcommand|(?i)-enc\b")
```

**eval**: 필드 계산
```splunk
index=endpoint EventCode=4688
| eval proc_name=lower(mvindex(split(NewProcessName, "\\"), -1))
| eval cmd_len=len(CommandLine)
| eval is_encoded=if(match(CommandLine, "(?i)-enc"), 1, 0)
| eval hour=strftime(_time, "%H")
| eval day_of_week=strftime(_time, "%A")
```

**stats**: 집계
```splunk
index=windows EventCode=4625
| stats
    count as fail_count,
    dc(Account_Name) as unique_accounts,
    values(Account_Name) as accounts,
    min(_time) as first_fail,
    max(_time) as last_fail
    by src_ip, dest
| where fail_count > 50
| sort -fail_count
```

**transaction**: 세션 그룹화
```splunk
// 동일 사용자의 로그온/로그오프 세션 분석
index=windows (EventCode=4624 OR EventCode=4634)
| transaction Account_Name startswith="EventCode=4624" endswith="EventCode=4634" maxpause=8h
| eval duration_min=duration/60
| where duration_min > 240
| table Account_Name, host, EventCode, duration_min, _time
```

**timechart**: 시계열 시각화
```splunk
index=endpoint EventCode=4688
| timechart span=1h count by NewProcessName limit=10
```

**lookup**: 외부 데이터 참조
```splunk
// IP 지리 정보 조회
index=network src_ip!=10.0.0.0/8
| lookup geoip clientip as src_ip OUTPUT country_name, city
| stats count by country_name, src_ip
| where country_name!="South Korea" AND count > 100
```

---

## 3. 실전 헌팅 쿼리 모음

### 3.1 프로세스 생성 (Process Creation)

**의심스러운 부모-자식 프로세스 관계 탐지**:
```kql
// KQL: Office 앱에서 쉘 실행
DeviceProcessEvents
| where InitiatingProcessFileName in~ (
    "WINWORD.EXE", "EXCEL.EXE", "POWERPNT.EXE",
    "OUTLOOK.EXE", "ONENOTE.EXE", "MSACCESS.EXE"
)
| where FileName in~ (
    "powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "regsvr32.exe", "rundll32.exe", "certutil.exe"
)
| project TimeGenerated, DeviceName, InitiatingProcessFileName, FileName, ProcessCommandLine
| order by TimeGenerated desc
```

```splunk
// SPL: 브라우저에서 비정상 자식 프로세스
index=endpoint EventCode=4688
| where ParentProcessName IN ("chrome.exe", "firefox.exe", "iexplore.exe", "msedge.exe")
| where NewProcessName IN ("powershell.exe", "cmd.exe", "wscript.exe", "mshta.exe")
| table _time, Computer, ParentProcessName, NewProcessName, CommandLine
```

**LOLBAS (Living Off The Land) 탐지**:
```kql
// KQL: 비정상 certutil 사용
DeviceProcessEvents
| where FileName =~ "certutil.exe"
| where ProcessCommandLine has_any ("-urlcache", "-decode", "-encode", "-split", "http://", "https://")
| project TimeGenerated, DeviceName, ProcessCommandLine, InitiatingProcessFileName
```

```splunk
// SPL: regsvr32 스크립틀릿 실행 (Squiblydoo)
index=endpoint EventCode=4688 NewProcessName="*regsvr32.exe"
| where match(CommandLine, "(?i)/s|/i|scrobj\.dll|http|\.sct")
| table _time, Computer, CommandLine, ParentProcessName
```

**프로세스 이름 스푸핑 탐지**:
```kql
// KQL: 시스템 프로세스가 비정상 경로에서 실행
DeviceProcessEvents
| where FileName in~ ("svchost.exe", "lsass.exe", "csrss.exe", "winlogon.exe", "explorer.exe")
| extend ExpectedPath = case(
    FileName =~ "svchost.exe", @"c:\windows\system32\svchost.exe",
    FileName =~ "lsass.exe", @"c:\windows\system32\lsass.exe",
    FileName =~ "csrss.exe", @"c:\windows\system32\csrss.exe",
    FileName =~ "winlogon.exe", @"c:\windows\system32\winlogon.exe",
    FileName =~ "explorer.exe", @"c:\windows\explorer.exe",
    "unknown"
)
| where tolower(FolderPath) != tolower(split(ExpectedPath, "\\", 0)[0])
| project TimeGenerated, DeviceName, FileName, FolderPath, ExpectedPath
```

### 3.2 네트워크 (Network)

**비콘(Beaconing) 탐지**:
```kql
// KQL: 일정 간격으로 반복되는 아웃바운드 연결
DeviceNetworkEvents
| where RemoteIPType == "Public"
| where ActionType == "ConnectionSuccess"
| where TimeGenerated > ago(24h)
| summarize
    ConnCount = count(),
    UniqueTimestamps = dcount(bin(TimeGenerated, 5m)),
    BytesSent = sum(SentBytes)
    by DeviceName, RemoteIP, RemotePort, InitiatingProcessFileName
| where ConnCount > 20
| extend ConsistencyScore = UniqueTimestamps * 1.0 / ConnCount
| where ConsistencyScore > 0.8  // 80% 이상 일정 간격
| order by ConsistencyScore desc
```

**DNS 터널링 탐지**:
```kql
// KQL: 비정상적으로 긴 DNS 쿼리 탐지
DnsEvents
| where strlen(Name) > 60
| extend SubdomainCount = array_length(split(Name, ".")) - 2
| where SubdomainCount > 5
| summarize
    QueryCount = count(),
    AvgQueryLen = avg(strlen(Name)),
    UniqueQueries = dcount(Name)
    by Computer, ClientIP
| where QueryCount > 50 or AvgQueryLen > 80
```

```splunk
// SPL: DNS 엔트로피 기반 DGA 도메인 탐지
index=dns
| eval domain=mvindex(split(query, "."), 0)
| eval domain_len=len(domain)
| where domain_len > 12
| eval char_freq=mvcount(split(domain, ""))
| stats avg(domain_len) as avg_len, count as query_count, dc(query) as unique_domains by src
| where unique_domains > 100 AND avg_len > 15
| sort -unique_domains
```

**비정상 포트 통신 탐지**:
```kql
// KQL: 알려진 프로세스의 비정상 포트 사용
DeviceNetworkEvents
| where ActionType == "ConnectionSuccess"
| where RemoteIPType == "Public"
| extend IsKnownPort = RemotePort in (80, 443, 22, 21, 25, 53, 8080, 8443)
| where not(IsKnownPort)
| where InitiatingProcessFileName !in~ ("svchost.exe", "lsass.exe")
| summarize count() by InitiatingProcessFileName, RemotePort, RemoteIP
| order by count_ desc
```

### 3.3 레지스트리 (Registry)

**지속성 목적 레지스트리 수정 탐지**:
```kql
// KQL: 자동 실행 레지스트리 키 수정
DeviceRegistryEvents
| where RegistryKey has_any (
    @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    @"SYSTEM\CurrentControlSet\Services",
    @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
    @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
)
| where ActionType in ("RegistryValueSet", "RegistryKeyCreated")
| where InitiatingProcessFileName !in~ (
    "svchost.exe", "MsMpEng.exe", "msiexec.exe", "TrustedInstaller.exe"
)
| project TimeGenerated, DeviceName, RegistryKey, RegistryValueName,
    RegistryValueData, InitiatingProcessFileName, InitiatingProcessCommandLine
```

**COM 하이재킹 탐지**:
```kql
// KQL: HKCU CLSID 등록 (COM 하이재킹)
DeviceRegistryEvents
| where RegistryKey has @"HKEY_CURRENT_USER\Software\Classes\CLSID"
| where ActionType == "RegistryKeyCreated" or ActionType == "RegistryValueSet"
| project TimeGenerated, DeviceName, RegistryKey, RegistryValueData, InitiatingProcessFileName
```

### 3.4 파일 (File)

**Drop된 실행 파일 탐지**:
```kql
// KQL: 임시 디렉토리에 실행 파일 생성
DeviceFileEvents
| where ActionType == "FileCreated"
| where FolderPath has_any (@"\Temp\", @"\AppData\Local\Temp\", @"\Downloads\", @"\Public\")
| where FileName endswith_cs ".exe" or FileName endswith_cs ".dll"
    or FileName endswith_cs ".ps1" or FileName endswith_cs ".bat"
    or FileName endswith_cs ".vbs" or FileName endswith_cs ".hta"
| where InitiatingProcessFileName !in~ ("msiexec.exe", "setup.exe", "installer.exe")
| project TimeGenerated, DeviceName, FolderPath, FileName,
    InitiatingProcessFileName, InitiatingProcessCommandLine
```

**민감 파일 접근 탐지**:
```kql
// KQL: NTDS.dit 또는 SAM 접근
DeviceFileEvents
| where FileName in~ ("ntds.dit", "SAM", "SYSTEM", "SECURITY")
| where FolderPath has_any (@"\Windows\NTDS\", @"\Windows\System32\config\")
| where not(InitiatingProcessFileName in~ ("svchost.exe", "csrss.exe", "wininit.exe"))
| project TimeGenerated, DeviceName, FolderPath, FileName, InitiatingProcessFileName
```

---

## 4. 베이스라인 이탈 탐지 쿼리

### 4.1 사용자 행위 베이스라인

```kql
// KQL: 사용자의 비정상 로그온 시간 탐지
let UserBaseline = SigninLogs
| where TimeGenerated between (ago(30d)..ago(1d))
| extend Hour = hourofday(TimeGenerated)
| summarize
    TypicalHours = make_set(Hour),
    AvgHour = avg(Hour)
    by UserPrincipalName;

SigninLogs
| where TimeGenerated > ago(1d)
| extend Hour = hourofday(TimeGenerated)
| join kind=leftouter UserBaseline on UserPrincipalName
| where not(Hour in (TypicalHours))
| project TimeGenerated, UserPrincipalName, IPAddress, Location, Hour, TypicalHours
```

### 4.2 프로세스 실행 빈도 베이스라인

```kql
// KQL: 희귀 프로세스 탐지 (Rare Process Hunting)
let RecentProcesses = DeviceProcessEvents
| where TimeGenerated > ago(1d)
| summarize RecentCount = count() by FileName, DeviceName;

let HistoricalProcesses = DeviceProcessEvents
| where TimeGenerated between (ago(30d)..ago(1d))
| summarize HistoricalCount = count(), HistoricalDevices = dcount(DeviceName) by FileName;

RecentProcesses
| join kind=leftouter HistoricalProcesses on FileName
| where isempty(HistoricalCount) or HistoricalDevices < 3
| where RecentCount < 5
| project FileName, RecentCount, HistoricalCount, HistoricalDevices
| order by HistoricalDevices asc
```

### 4.3 네트워크 트래픽 베이스라인

```splunk
// SPL: 평균 대비 대용량 데이터 전송 탐지
index=network
| bucket _time span=1h
| stats sum(bytes_out) as hourly_bytes by src_ip, _time
| eventstats avg(hourly_bytes) as avg_bytes, stdev(hourly_bytes) as std_bytes by src_ip
| eval zscore=(hourly_bytes - avg_bytes) / if(std_bytes > 0, std_bytes, 1)
| where zscore > 3 AND hourly_bytes > 100000000  // Z-score > 3 AND > 100MB
| table _time, src_ip, hourly_bytes, avg_bytes, zscore
| sort -zscore
```

---

## 5. 시계열 이상 탐지 쿼리

### 5.1 로그온 실패 급증 탐지

```kql
// KQL: 롤링 윈도우 기반 로그온 실패 급증
let Threshold = 50;
let WindowSize = 15m;

SecurityEvent
| where EventID == 4625
| where TimeGenerated > ago(24h)
| summarize FailCount = count() by bin(TimeGenerated, WindowSize), Computer, TargetAccount
| where FailCount > Threshold
| extend AlertTime = TimeGenerated
| project AlertTime, Computer, TargetAccount, FailCount
| order by FailCount desc
```

### 5.2 주기적 이상 행위 탐지 (Periodicity Analysis)

```kql
// KQL: 네트워크 연결의 주기성 분석 (비콘 탐지)
DeviceNetworkEvents
| where TimeGenerated > ago(6h)
| where RemoteIPType == "Public"
| summarize
    Timestamps = make_list(TimeGenerated),
    ConnCount = count()
    by DeviceName, RemoteIP, RemotePort
| where ConnCount > 10
| extend TimeDiffs = array_sort_asc(Timestamps)
| mv-apply with_itemindex=i TS to typeof(datetime) on (
    extend Diff = iff(i > 0, datetime_diff("second", TS, prev(TS)), long(null))
    | where isnotnull(Diff)
    | summarize AvgDiff = avg(Diff), StdDiff = stdev(Diff)
)
| where StdDiff < AvgDiff * 0.3  // 분산이 평균의 30% 미만 = 규칙적
| where AvgDiff between (30 .. 3600)  // 30초~1시간 간격
| project DeviceName, RemoteIP, RemotePort, ConnCount, AvgDiff, StdDiff
```

### 5.3 신규 연결 대상 탐지

```kql
// KQL: 과거에 없던 새로운 외부 통신 탐지
let HistoricalConnections = DeviceNetworkEvents
| where TimeGenerated between (ago(30d)..ago(1d))
| where RemoteIPType == "Public"
| distinct DeviceName, RemoteIP;

let RecentConnections = DeviceNetworkEvents
| where TimeGenerated > ago(1d)
| where RemoteIPType == "Public"
| distinct DeviceName, RemoteIP, RemotePort, InitiatingProcessFileName;

RecentConnections
| join kind=leftanti HistoricalConnections on DeviceName, RemoteIP
| project DeviceName, RemoteIP, RemotePort, InitiatingProcessFileName
| order by DeviceName
```

---

## 6. Python: 로그 데이터 통계적 이상 탐지 도구

```python
#!/usr/bin/env python3
"""
로그 데이터 통계적 이상 탐지 CLI 도구
의존성: pip install numpy (선택사항 — 없으면 순수 Python 통계 사용)

사용법: python3 log_anomaly_detector.py [command] [options]
"""

import argparse
import csv
import json
import math
import re
import sys
from collections import Counter, defaultdict
from concurrent.futures import ProcessPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional


# ── 통계 유틸리티 (numpy 없이도 동작) ──────────────────────────────────────

def mean(values: list[float]) -> float:
    if not values:
        return 0.0
    return sum(values) / len(values)


def variance(values: list[float]) -> float:
    if len(values) < 2:
        return 0.0
    m = mean(values)
    return sum((x - m) ** 2 for x in values) / (len(values) - 1)


def stdev(values: list[float]) -> float:
    return math.sqrt(variance(values))


def zscore(value: float, mu: float, sigma: float) -> float:
    if sigma == 0:
        return 0.0
    return (value - mu) / sigma


def percentile(values: list[float], p: float) -> float:
    """p번째 백분위수 계산 (0~100)."""
    if not values:
        return 0.0
    sorted_v = sorted(values)
    k = (len(sorted_v) - 1) * p / 100
    f, c = int(k), math.ceil(k)
    if f == c:
        return sorted_v[int(k)]
    return sorted_v[f] * (c - k) + sorted_v[c] * (k - f)


def iqr_bounds(values: list[float], factor: float = 1.5) -> tuple[float, float]:
    """IQR 기반 이상치 경계 계산."""
    q1 = percentile(values, 25)
    q3 = percentile(values, 75)
    iqr = q3 - q1
    return q1 - factor * iqr, q3 + factor * iqr


# ── 데이터 로딩 ─────────────────────────────────────────────────────────────

def load_csv(path: Path, time_col: str, value_col: str) -> list[dict[str, str]]:
    """CSV 파일 로드."""
    try:
        with path.open(encoding="utf-8", newline="") as f:
            reader = csv.DictReader(f)
            rows = list(reader)
        if not rows:
            print(f"[ERROR] 빈 파일: {path}", file=sys.stderr)
            sys.exit(1)
        # 컬럼 존재 확인
        headers = set(rows[0].keys())
        missing = {time_col, value_col} - headers
        if missing:
            print(f"[ERROR] 컬럼 없음: {missing}. 사용 가능: {headers}", file=sys.stderr)
            sys.exit(1)
        return rows
    except (OSError, csv.Error) as e:
        print(f"[ERROR] 파일 로드 실패: {e}", file=sys.stderr)
        sys.exit(1)


def load_json_log(path: Path) -> list[dict]:
    """JSON Lines 또는 JSON Array 로드."""
    try:
        content = path.read_text(encoding="utf-8").strip()
        if content.startswith("["):
            return json.loads(content)
        else:
            return [json.loads(line) for line in content.splitlines() if line.strip()]
    except (OSError, json.JSONDecodeError) as e:
        print(f"[ERROR] JSON 로드 실패: {e}", file=sys.stderr)
        sys.exit(1)


# ── 탐지 알고리즘 ────────────────────────────────────────────────────────────

def detect_zscore_anomalies(
    values: list[float],
    labels: list[str],
    threshold: float = 3.0,
    group_name: str = "unknown",
) -> list[dict[str, Any]]:
    """Z-score 기반 이상 탐지."""
    if len(values) < 3:
        return []
    mu = mean(values)
    sigma = stdev(values)
    anomalies = []
    for label, val in zip(labels, values):
        z = zscore(val, mu, sigma)
        if abs(z) >= threshold:
            anomalies.append({
                "group": group_name,
                "label": label,
                "value": val,
                "mean": round(mu, 2),
                "stdev": round(sigma, 2),
                "zscore": round(z, 2),
                "method": "z-score",
                "severity": "high" if abs(z) >= 5 else "medium",
            })
    return anomalies


def detect_iqr_anomalies(
    values: list[float],
    labels: list[str],
    factor: float = 1.5,
    group_name: str = "unknown",
) -> list[dict[str, Any]]:
    """IQR 기반 이상 탐지."""
    if len(values) < 4:
        return []
    lower, upper = iqr_bounds(values, factor)
    anomalies = []
    for label, val in zip(labels, values):
        if val < lower or val > upper:
            anomalies.append({
                "group": group_name,
                "label": label,
                "value": val,
                "lower_bound": round(lower, 2),
                "upper_bound": round(upper, 2),
                "method": "iqr",
                "severity": "high" if (val > upper * 2 or val < lower * 2) else "medium",
            })
    return anomalies


def detect_rare_values(
    items: list[str],
    threshold_pct: float = 0.5,
    group_name: str = "unknown",
) -> list[dict[str, Any]]:
    """희귀 값 탐지 (출현 빈도 기반)."""
    total = len(items)
    if total == 0:
        return []
    counter = Counter(items)
    anomalies = []
    for item, count in counter.items():
        pct = count / total * 100
        if pct < threshold_pct:
            anomalies.append({
                "group": group_name,
                "value": item,
                "count": count,
                "frequency_pct": round(pct, 4),
                "method": "rare_value",
                "severity": "medium" if count > 1 else "high",
            })
    return sorted(anomalies, key=lambda x: x["count"])


def detect_time_clustering(
    timestamps: list[float],
    window_seconds: int = 60,
    threshold_count: int = 10,
    group_name: str = "unknown",
) -> list[dict[str, Any]]:
    """단위 시간 내 이벤트 클러스터링 탐지."""
    if not timestamps:
        return []
    sorted_ts = sorted(timestamps)
    anomalies = []
    i = 0
    while i < len(sorted_ts):
        window_events = [sorted_ts[i]]
        j = i + 1
        while j < len(sorted_ts) and sorted_ts[j] - sorted_ts[i] <= window_seconds:
            window_events.append(sorted_ts[j])
            j += 1
        if len(window_events) >= threshold_count:
            anomalies.append({
                "group": group_name,
                "window_start": datetime.fromtimestamp(sorted_ts[i]).isoformat(),
                "window_end": datetime.fromtimestamp(sorted_ts[j-1] if j < len(sorted_ts) else sorted_ts[-1]).isoformat(),
                "event_count": len(window_events),
                "threshold": threshold_count,
                "method": "time_clustering",
                "severity": "high" if len(window_events) >= threshold_count * 3 else "medium",
            })
            i = j
        else:
            i += 1
    return anomalies


# ── 로그 분석 함수 ────────────────────────────────────────────────────────────

def analyze_process_log(
    rows: list[dict],
    proc_col: str = "process_name",
    user_col: str = "username",
    threshold_pct: float = 0.1,
) -> list[dict[str, Any]]:
    """프로세스 실행 로그에서 희귀 프로세스 탐지."""
    # 사용자별 프로세스 그룹화
    user_procs: dict[str, list[str]] = defaultdict(list)
    for row in rows:
        user = row.get(user_col, "unknown")
        proc = row.get(proc_col, "unknown").lower()
        user_procs[user].append(proc)

    all_anomalies: list[dict[str, Any]] = []

    def analyze_user(user: str, procs: list[str]) -> list[dict[str, Any]]:
        return detect_rare_values(procs, threshold_pct=threshold_pct, group_name=f"user:{user}")

    with ProcessPoolExecutor(max_workers=4) as executor:
        futures = {
            executor.submit(analyze_user, user, procs): user
            for user, procs in user_procs.items()
        }
        for future in as_completed(futures):
            try:
                all_anomalies.extend(future.result())
            except Exception as e:
                print(f"[WARN] 분석 실패: {e}", file=sys.stderr)

    return all_anomalies


def analyze_network_log(
    rows: list[dict],
    src_col: str = "src_ip",
    bytes_col: str = "bytes_out",
    time_col: str = "timestamp",
    zscore_threshold: float = 3.0,
) -> list[dict[str, Any]]:
    """네트워크 로그에서 대용량 전송 이상 탐지."""
    src_bytes: dict[str, list[tuple[str, float]]] = defaultdict(list)
    for row in rows:
        src = row.get(src_col, "unknown")
        try:
            val = float(row.get(bytes_col, 0))
        except (ValueError, TypeError):
            continue
        ts = row.get(time_col, "")
        src_bytes[src].append((ts, val))

    all_anomalies: list[dict[str, Any]] = []
    for src, records in src_bytes.items():
        if len(records) < 5:
            continue
        labels = [r[0] for r in records]
        values = [r[1] for r in records]
        anomalies = detect_zscore_anomalies(
            values, labels, threshold=zscore_threshold, group_name=f"src:{src}"
        )
        all_anomalies.extend(anomalies)
    return all_anomalies


def analyze_auth_log(
    rows: list[dict],
    user_col: str = "username",
    result_col: str = "result",
    time_col: str = "timestamp",
    fail_threshold: int = 10,
    window_seconds: int = 300,
) -> list[dict[str, Any]]:
    """인증 로그에서 무차별 대입 패턴 탐지."""
    user_fails: dict[str, list[float]] = defaultdict(list)
    for row in rows:
        if row.get(result_col, "").lower() in ("fail", "failure", "false", "0"):
            user = row.get(user_col, "unknown")
            ts_str = row.get(time_col, "")
            try:
                ts = datetime.fromisoformat(ts_str).timestamp()
                user_fails[user].append(ts)
            except (ValueError, TypeError):
                continue

    all_anomalies: list[dict[str, Any]] = []
    for user, timestamps in user_fails.items():
        anomalies = detect_time_clustering(
            timestamps,
            window_seconds=window_seconds,
            threshold_count=fail_threshold,
            group_name=f"auth_user:{user}",
        )
        all_anomalies.extend(anomalies)
    return all_anomalies


# ── CLI 명령어 ──────────────────────────────────────────────────────────────

def print_anomalies(anomalies: list[dict[str, Any]], output_format: str = "table") -> None:
    """이상 탐지 결과 출력."""
    if not anomalies:
        print("[-] 이상 탐지 결과 없음")
        return

    high = [a for a in anomalies if a.get("severity") == "high"]
    medium = [a for a in anomalies if a.get("severity") == "medium"]

    print(f"\n[!] 이상 탐지 결과: 총 {len(anomalies)}개")
    print(f"    High: {len(high)}, Medium: {len(medium)}")
    print(f"{'='*70}")

    if output_format == "json":
        print(json.dumps(anomalies, ensure_ascii=False, indent=2))
        return

    for a in sorted(anomalies, key=lambda x: (x.get("severity", ""), x.get("group", ""))):
        sev = a.get("severity", "?").upper()
        method = a.get("method", "?")
        group = a.get("group", "?")
        print(f"\n[{sev}] {group} | 방법: {method}")
        for k, v in a.items():
            if k not in ("severity", "method", "group"):
                print(f"    {k:<20}: {v}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="로그 데이터 통계적 이상 탐지 CLI 도구",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
예시:
  python3 log_anomaly_detector.py analyze-csv -f network.csv \\
      --time-col timestamp --value-col bytes_out --method zscore --threshold 3.0

  python3 log_anomaly_detector.py analyze-process -f process.csv \\
      --proc-col process_name --user-col username --threshold-pct 0.1

  python3 log_anomaly_detector.py analyze-auth -f auth.csv \\
      --user-col username --result-col status --fail-threshold 10 --window 300

  python3 log_anomaly_detector.py quick-stats -f events.csv --group-col EventID
        """,
    )
    sub = parser.add_subparsers(dest="command", required=True)

    fmt_choices = ["table", "json"]

    # analyze-csv
    p_csv = sub.add_parser("analyze-csv", help="수치형 CSV 이상 탐지")
    p_csv.add_argument("-f", "--file", required=True, help="CSV 파일 경로")
    p_csv.add_argument("--time-col", default="timestamp", help="시간 컬럼명")
    p_csv.add_argument("--value-col", required=True, help="분석할 수치 컬럼명")
    p_csv.add_argument("--method", choices=["zscore", "iqr", "all"], default="all")
    p_csv.add_argument("--threshold", type=float, default=3.0, help="Z-score 임계값")
    p_csv.add_argument("--format", choices=fmt_choices, default="table")
    p_csv.add_argument("--output", help="JSON 결과 저장 경로")
    p_csv.set_defaults(func=cmd_analyze_csv)

    # analyze-process
    p_proc = sub.add_parser("analyze-process", help="프로세스 로그 희귀 프로세스 탐지")
    p_proc.add_argument("-f", "--file", required=True, help="로그 파일 (CSV/JSON)")
    p_proc.add_argument("--proc-col", default="process_name", help="프로세스명 컬럼")
    p_proc.add_argument("--user-col", default="username", help="사용자 컬럼")
    p_proc.add_argument("--time-col", default="timestamp", help="시간 컬럼 (CSV용)")
    p_proc.add_argument("--threshold-pct", type=float, default=0.5, help="희귀 기준 비율 (%)")
    p_proc.add_argument("--format", choices=fmt_choices, default="table")
    p_proc.set_defaults(func=cmd_analyze_process)

    # analyze-auth
    p_auth = sub.add_parser("analyze-auth", help="인증 로그 무차별 대입 탐지")
    p_auth.add_argument("-f", "--file", required=True, help="로그 파일 (CSV/JSON)")
    p_auth.add_argument("--user-col", default="username", help="사용자 컬럼")
    p_auth.add_argument("--result-col", default="result", help="인증 결과 컬럼")
    p_auth.add_argument("--time-col", default="timestamp", help="시간 컬럼")
    p_auth.add_argument("--fail-threshold", type=int, default=10, help="실패 횟수 임계값")
    p_auth.add_argument("--window", type=int, default=300, help="시간 윈도우(초)")
    p_auth.add_argument("--format", choices=fmt_choices, default="table")
    p_auth.set_defaults(func=cmd_analyze_auth)

    # quick-stats
    p_stats = sub.add_parser("quick-stats", help="로그 빠른 통계 요약")
    p_stats.add_argument("-f", "--file", required=True, help="로그 파일 (CSV/JSON)")
    p_stats.add_argument("--group-col", help="분포 분석할 컬럼명")
    p_stats.set_defaults(func=cmd_quick_stats)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
```

---

## 7. 쿼리 최적화 팁

### 7.1 KQL 최적화

1. **시간 범위 먼저**: `where TimeGenerated > ago(24h)` 를 파이프라인 첫 번째로
2. **인덱스 필드 우선**: `EventID`, `DeviceName` 등 인덱스된 필드로 먼저 필터
3. **has 대신 contains 지양**: `has`는 단어 경계 기반으로 더 빠름
4. **project 일찍**: 불필요한 컬럼을 초기에 제거하여 전송 데이터 감소
5. **summarize 활용**: 개별 행보다 집계 결과로 이상 판단

### 7.2 SPL 최적화

1. **이른 필터링**: 파이프라인 앞에서 결과 수를 최소화
2. **tstats 사용**: 대용량 데이터에서 `stats`보다 빠른 `tstats` 활용
3. **index 명시**: `index=*` 대신 정확한 인덱스 지정
4. **시간 범위 지정**: 검색 시간 범위를 최소화
5. **필드 제한**: `fields` 명령어로 필요한 필드만 처리

### 7.3 공통 헌팅 원칙

| 원칙 | 설명 |
|------|------|
| 시간 제한 | 가능한 좁은 시간 범위에서 검증 후 확장 |
| 점진적 접근 | 광범위 → 세부 조건 추가 방식 |
| 노이즈 관리 | 화이트리스트/예외 처리를 점진적으로 추가 |
| 결과 검증 | 탐지 결과의 True Positive 여부 수동 확인 |
| 문서화 | 쿼리, 결과, 조치사항 모두 기록 |

<!-- detect-validate-40 -->
## 헌팅 쿼리 검증 — 베이스라인·시간창이 실제로 이상을 잡는가

KQL/SPL 쿼리는 *돌아가는가*가 아니라 **알려진 악성 이벤트를 실제로 잡고(미탐 0) 정상에 과탐하지 않는가**로 판정한다. 잘못된 베이스라인과 좁은 시간창은 저속 공격을 놓친다. 검증은 **소유 테스트 인덱스**에서만.

### 항목 → 실패 모드 → 검증 방법 → 양호 신호

| 항목 | 실패 모드 | 검증 방법 | 양호 신호 |
|---|---|---|---|
| 베이스라인 정확도 | 잘못된 정상기준 | 정상/이상 대조 | 이상만 표시 |
| 쿼리 무결성 | 필드 누락 오탐 | 필드 존재 검증 | 결과 일관 |
| 시간창 | 짧은 창 미탐 | 창 길이 튜닝 | 저속 공격 포착 |
| 성능 | 타임아웃 | 인덱스/요약 | 쿼리 완주 |

### 방어 검증 (직접 확인)

```bash
# 1) 쿼리가 알려진 악성 시드 이벤트를 실제로 잡는지 — 소유 테스트 인덱스에 시드 주입 후 확인
grep -c 'expected_malicious_marker' query_results.json   # 0이면 미탐(false negative)
# 2) 쿼리가 시간창/기법 메타를 포함해 재현 가능한지
grep -rEn 'TimeGenerated|earliest=|latest=' hunts/ | head
```

> 검증은 반드시 **소유 테스트 인덱스**에서만 한다. "쿼리가 돈다"와 "악성 이벤트를 실제 잡는다"는 다르다 — 시드 이벤트로 미탐/과탐을 직접 확인한다([[13_SOC_Blue_Team]], [[25_Threat_Intelligence]]).

---

<a name="english"></a>

# Hunting Queries — KQL and SPL Practical Guide

## 1. KQL (Kusto Query Language) Fundamentals

### 1.1 Overview

KQL is the query language used in Microsoft Azure Data Explorer, Microsoft Sentinel, and Log Analytics. Designed to process large volumes of data quickly with read-only requests, it is optimized for threat hunting.

### 1.2 Basic Syntax

```kql
// Basic table query structure
TableName
| operator1 [parameters]
| operator2 [parameters]
| ...

// Example: Query logon failures from SecurityEvent table
SecurityEvent
| where EventID == 4625
| where TimeGenerated > ago(24h)
| project TimeGenerated, Account, Computer, IpAddress, LogonType
| order by TimeGenerated desc
```

### 1.3 Core Operators

**where**: Condition filtering
```kql
// Comparison operators
where EventID == 4624
where EventID != 4624
where EventID in (4624, 4625, 4688)
where EventID !in (4624, 4625)

// String operators (case sensitivity)
where ProcessName == "powershell.exe"          // Exact match (case-sensitive)
where ProcessName =~ "powershell.exe"          // Exact match (case-insensitive)
where CommandLine has "encodedcommand"         // Word boundary match (fast)
where CommandLine contains "encoded"           // Substring match
where CommandLine startswith "powershell"      // Starts with
where CommandLine endswith ".ps1"              // Ends with
where CommandLine matches regex @"enc\w+"      // Regular expression

// Compound conditions
where (EventID == 4688) and (SubjectUserName != "SYSTEM")
where (EventID == 4624) or (EventID == 4625)
```

**project**: Column selection and renaming
```kql
SecurityEvent
| project TimeGenerated, EventID, Account, Computer
| project-rename UserName = Account, Hostname = Computer
| project-away SubjectDomainName  // Exclude specific column
```

**extend**: Add new columns (derived fields)
```kql
DeviceProcessEvents
| extend
    ProcessNameLower = tolower(FileName),
    CommandLineLen = strlen(ProcessCommandLine),
    Hour = hourofday(TimeGenerated),
    ParentName = tostring(split(InitiatingProcessFolderPath, "\\")[-1])
```

**summarize**: Aggregation
```kql
SecurityEvent
| where EventID == 4625
| summarize
    FailCount = count(),
    UniqueAccounts = dcount(Account),
    FirstFail = min(TimeGenerated),
    LastFail = max(TimeGenerated)
    by Computer, IpAddress
| where FailCount > 10
```

**join**: Table joining
```kql
let SuspiciousIPs = externaldata(ip: string) [@"https://example.com/blocklist.txt"] with (format="txt");
DeviceNetworkEvents
| join kind=inner SuspiciousIPs on $left.RemoteIP == $right.ip
| project TimeGenerated, DeviceName, RemoteIP, RemotePort, InitiatingProcessFileName
```

**let**: Variable and function definitions
```kql
let LookbackDays = 7d;
let SuspiciousProcesses = dynamic(["mimikatz.exe", "procdump.exe", "pwdump.exe"]);

DeviceProcessEvents
| where TimeGenerated > ago(LookbackDays)
| where FileName in~ (SuspiciousProcesses)
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine
```

**mv-expand**: Expand arrays/dictionaries
```kql
SecurityEvent
| where EventID == 4688
| extend Tags = split(SubjectUserSid, "-")
| mv-expand Tag = Tags
| where tostring(Tag) startswith "S-1-5-21"
```

### 1.4 Time Series Analysis

```kql
// Event trend by time period
SecurityEvent
| where EventID == 4688
| summarize EventCount = count() by bin(TimeGenerated, 1h)
| render timechart

// Anomaly detection using moving average
let Baseline = SecurityEvent
    | where TimeGenerated between(ago(14d)..ago(1d))
    | summarize BaselineCount = count() by bin(TimeGenerated, 1h), Computer
    | summarize AvgCount = avg(BaselineCount), StdDev = stdev(BaselineCount) by Computer;

SecurityEvent
| where TimeGenerated > ago(1d)
| summarize CurrentCount = count() by bin(TimeGenerated, 1h), Computer
| join Baseline on Computer
| extend ZScore = (CurrentCount - AvgCount) / StdDev
| where ZScore > 3
| project TimeGenerated, Computer, CurrentCount, AvgCount, ZScore
```

---

## 2. SPL (Search Processing Language) Fundamentals

### 2.1 Overview

SPL is Splunk's query language. It processes data through pipes and provides powerful statistical functions and visualization capabilities.

### 2.2 Basic Syntax

```splunk
// Basic search structure
index=<index> sourcetype=<sourcetype> <condition>
| command1 [args]
| command2 [args]
```

### 2.3 Core Commands

**search/where**: Filtering
```splunk
// Basic search
index=windows EventCode=4688 NewProcessName=*powershell*

// where command
index=windows EventCode=4688
| where len(CommandLine) > 500
| where match(CommandLine, "(?i)encodedcommand|(?i)-enc\b")
```

**eval**: Field calculation
```splunk
index=endpoint EventCode=4688
| eval proc_name=lower(mvindex(split(NewProcessName, "\\"), -1))
| eval cmd_len=len(CommandLine)
| eval is_encoded=if(match(CommandLine, "(?i)-enc"), 1, 0)
| eval hour=strftime(_time, "%H")
| eval day_of_week=strftime(_time, "%A")
```

**stats**: Aggregation
```splunk
index=windows EventCode=4625
| stats
    count as fail_count,
    dc(Account_Name) as unique_accounts,
    values(Account_Name) as accounts,
    min(_time) as first_fail,
    max(_time) as last_fail
    by src_ip, dest
| where fail_count > 50
| sort -fail_count
```

**transaction**: Session grouping
```splunk
// Analyze logon/logoff sessions for the same user
index=windows (EventCode=4624 OR EventCode=4634)
| transaction Account_Name startswith="EventCode=4624" endswith="EventCode=4634" maxpause=8h
| eval duration_min=duration/60
| where duration_min > 240
| table Account_Name, host, EventCode, duration_min, _time
```

**timechart**: Time series visualization
```splunk
index=endpoint EventCode=4688
| timechart span=1h count by NewProcessName limit=10
```

**lookup**: External data reference
```splunk
// IP geolocation lookup
index=network src_ip!=10.0.0.0/8
| lookup geoip clientip as src_ip OUTPUT country_name, city
| stats count by country_name, src_ip
| where country_name!="South Korea" AND count > 100
```

---

## 3. Practical Hunting Query Collection

### 3.1 Process Creation

**Detecting suspicious parent-child process relationships**:
```kql
// KQL: Shell execution from Office applications
DeviceProcessEvents
| where InitiatingProcessFileName in~ (
    "WINWORD.EXE", "EXCEL.EXE", "POWERPNT.EXE",
    "OUTLOOK.EXE", "ONENOTE.EXE", "MSACCESS.EXE"
)
| where FileName in~ (
    "powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "regsvr32.exe", "rundll32.exe", "certutil.exe"
)
| project TimeGenerated, DeviceName, InitiatingProcessFileName, FileName, ProcessCommandLine
| order by TimeGenerated desc
```

```splunk
// SPL: Abnormal child processes from browsers
index=endpoint EventCode=4688
| where ParentProcessName IN ("chrome.exe", "firefox.exe", "iexplore.exe", "msedge.exe")
| where NewProcessName IN ("powershell.exe", "cmd.exe", "wscript.exe", "mshta.exe")
| table _time, Computer, ParentProcessName, NewProcessName, CommandLine
```

**LOLBAS (Living Off The Land) Detection**:
```kql
// KQL: Abnormal certutil usage
DeviceProcessEvents
| where FileName =~ "certutil.exe"
| where ProcessCommandLine has_any ("-urlcache", "-decode", "-encode", "-split", "http://", "https://")
| project TimeGenerated, DeviceName, ProcessCommandLine, InitiatingProcessFileName
```

```splunk
// SPL: regsvr32 scriptlet execution (Squiblydoo)
index=endpoint EventCode=4688 NewProcessName="*regsvr32.exe"
| where match(CommandLine, "(?i)/s|/i|scrobj\.dll|http|\.sct")
| table _time, Computer, CommandLine, ParentProcessName
```

**Process name spoofing detection**:
```kql
// KQL: System processes running from abnormal paths
DeviceProcessEvents
| where FileName in~ ("svchost.exe", "lsass.exe", "csrss.exe", "winlogon.exe", "explorer.exe")
| extend ExpectedPath = case(
    FileName =~ "svchost.exe", @"c:\windows\system32\svchost.exe",
    FileName =~ "lsass.exe", @"c:\windows\system32\lsass.exe",
    FileName =~ "csrss.exe", @"c:\windows\system32\csrss.exe",
    FileName =~ "winlogon.exe", @"c:\windows\system32\winlogon.exe",
    FileName =~ "explorer.exe", @"c:\windows\explorer.exe",
    "unknown"
)
| where tolower(FolderPath) != tolower(split(ExpectedPath, "\\", 0)[0])
| project TimeGenerated, DeviceName, FileName, FolderPath, ExpectedPath
```

### 3.2 Network

**Beaconing detection**:
```kql
// KQL: Repeated outbound connections at regular intervals
DeviceNetworkEvents
| where RemoteIPType == "Public"
| where ActionType == "ConnectionSuccess"
| where TimeGenerated > ago(24h)
| summarize
    ConnCount = count(),
    UniqueTimestamps = dcount(bin(TimeGenerated, 5m)),
    BytesSent = sum(SentBytes)
    by DeviceName, RemoteIP, RemotePort, InitiatingProcessFileName
| where ConnCount > 20
| extend ConsistencyScore = UniqueTimestamps * 1.0 / ConnCount
| where ConsistencyScore > 0.8  // More than 80% consistent intervals
| order by ConsistencyScore desc
```

**DNS tunneling detection**:
```kql
// KQL: Detect abnormally long DNS queries
DnsEvents
| where strlen(Name) > 60
| extend SubdomainCount = array_length(split(Name, ".")) - 2
| where SubdomainCount > 5
| summarize
    QueryCount = count(),
    AvgQueryLen = avg(strlen(Name)),
    UniqueQueries = dcount(Name)
    by Computer, ClientIP
| where QueryCount > 50 or AvgQueryLen > 80
```

```splunk
// SPL: Entropy-based DGA domain detection
index=dns
| eval domain=mvindex(split(query, "."), 0)
| eval domain_len=len(domain)
| where domain_len > 12
| eval char_freq=mvcount(split(domain, ""))
| stats avg(domain_len) as avg_len, count as query_count, dc(query) as unique_domains by src
| where unique_domains > 100 AND avg_len > 15
| sort -unique_domains
```

**Abnormal port communication detection**:
```kql
// KQL: Known processes using abnormal ports
DeviceNetworkEvents
| where ActionType == "ConnectionSuccess"
| where RemoteIPType == "Public"
| extend IsKnownPort = RemotePort in (80, 443, 22, 21, 25, 53, 8080, 8443)
| where not(IsKnownPort)
| where InitiatingProcessFileName !in~ ("svchost.exe", "lsass.exe")
| summarize count() by InitiatingProcessFileName, RemotePort, RemoteIP
| order by count_ desc
```

### 3.3 Registry

**Detecting registry modifications for persistence**:
```kql
// KQL: Autorun registry key modifications
DeviceRegistryEvents
| where RegistryKey has_any (
    @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    @"SYSTEM\CurrentControlSet\Services",
    @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
    @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
)
| where ActionType in ("RegistryValueSet", "RegistryKeyCreated")
| where InitiatingProcessFileName !in~ (
    "svchost.exe", "MsMpEng.exe", "msiexec.exe", "TrustedInstaller.exe"
)
| project TimeGenerated, DeviceName, RegistryKey, RegistryValueName,
    RegistryValueData, InitiatingProcessFileName, InitiatingProcessCommandLine
```

**COM hijacking detection**:
```kql
// KQL: HKCU CLSID registration (COM hijacking)
DeviceRegistryEvents
| where RegistryKey has @"HKEY_CURRENT_USER\Software\Classes\CLSID"
| where ActionType == "RegistryKeyCreated" or ActionType == "RegistryValueSet"
| project TimeGenerated, DeviceName, RegistryKey, RegistryValueData, InitiatingProcessFileName
```

### 3.4 File

**Detecting dropped executables**:
```kql
// KQL: Executable file creation in temporary directories
DeviceFileEvents
| where ActionType == "FileCreated"
| where FolderPath has_any (@"\Temp\", @"\AppData\Local\Temp\", @"\Downloads\", @"\Public\")
| where FileName endswith_cs ".exe" or FileName endswith_cs ".dll"
    or FileName endswith_cs ".ps1" or FileName endswith_cs ".bat"
    or FileName endswith_cs ".vbs" or FileName endswith_cs ".hta"
| where InitiatingProcessFileName !in~ ("msiexec.exe", "setup.exe", "installer.exe")
| project TimeGenerated, DeviceName, FolderPath, FileName,
    InitiatingProcessFileName, InitiatingProcessCommandLine
```

**Sensitive file access detection**:
```kql
// KQL: Access to NTDS.dit or SAM
DeviceFileEvents
| where FileName in~ ("ntds.dit", "SAM", "SYSTEM", "SECURITY")
| where FolderPath has_any (@"\Windows\NTDS\", @"\Windows\System32\config\")
| where not(InitiatingProcessFileName in~ ("svchost.exe", "csrss.exe", "wininit.exe"))
| project TimeGenerated, DeviceName, FolderPath, FileName, InitiatingProcessFileName
```

---

## 4. Baseline Deviation Detection Queries

### 4.1 User Behavior Baseline

```kql
// KQL: Detect abnormal user logon times
let UserBaseline = SigninLogs
| where TimeGenerated between (ago(30d)..ago(1d))
| extend Hour = hourofday(TimeGenerated)
| summarize
    TypicalHours = make_set(Hour),
    AvgHour = avg(Hour)
    by UserPrincipalName;

SigninLogs
| where TimeGenerated > ago(1d)
| extend Hour = hourofday(TimeGenerated)
| join kind=leftouter UserBaseline on UserPrincipalName
| where not(Hour in (TypicalHours))
| project TimeGenerated, UserPrincipalName, IPAddress, Location, Hour, TypicalHours
```

### 4.2 Process Execution Frequency Baseline

```kql
// KQL: Rare process hunting
let RecentProcesses = DeviceProcessEvents
| where TimeGenerated > ago(1d)
| summarize RecentCount = count() by FileName, DeviceName;

let HistoricalProcesses = DeviceProcessEvents
| where TimeGenerated between (ago(30d)..ago(1d))
| summarize HistoricalCount = count(), HistoricalDevices = dcount(DeviceName) by FileName;

RecentProcesses
| join kind=leftouter HistoricalProcesses on FileName
| where isempty(HistoricalCount) or HistoricalDevices < 3
| where RecentCount < 5
| project FileName, RecentCount, HistoricalCount, HistoricalDevices
| order by HistoricalDevices asc
```

### 4.3 Network Traffic Baseline

```splunk
// SPL: Detect high-volume data transfers compared to average
index=network
| bucket _time span=1h
| stats sum(bytes_out) as hourly_bytes by src_ip, _time
| eventstats avg(hourly_bytes) as avg_bytes, stdev(hourly_bytes) as std_bytes by src_ip
| eval zscore=(hourly_bytes - avg_bytes) / if(std_bytes > 0, std_bytes, 1)
| where zscore > 3 AND hourly_bytes > 100000000  // Z-score > 3 AND > 100MB
| table _time, src_ip, hourly_bytes, avg_bytes, zscore
| sort -zscore
```

---

## 5. Time Series Anomaly Detection Queries

### 5.1 Logon Failure Spike Detection

```kql
// KQL: Rolling window-based logon failure spike
let Threshold = 50;
let WindowSize = 15m;

SecurityEvent
| where EventID == 4625
| where TimeGenerated > ago(24h)
| summarize FailCount = count() by bin(TimeGenerated, WindowSize), Computer, TargetAccount
| where FailCount > Threshold
| extend AlertTime = TimeGenerated
| project AlertTime, Computer, TargetAccount, FailCount
| order by FailCount desc
```

### 5.2 Periodic Anomaly Detection (Periodicity Analysis)

```kql
// KQL: Periodicity analysis of network connections (beacon detection)
DeviceNetworkEvents
| where TimeGenerated > ago(6h)
| where RemoteIPType == "Public"
| summarize
    Timestamps = make_list(TimeGenerated),
    ConnCount = count()
    by DeviceName, RemoteIP, RemotePort
| where ConnCount > 10
| extend TimeDiffs = array_sort_asc(Timestamps)
| mv-apply with_itemindex=i TS to typeof(datetime) on (
    extend Diff = iff(i > 0, datetime_diff("second", TS, prev(TS)), long(null))
    | where isnotnull(Diff)
    | summarize AvgDiff = avg(Diff), StdDiff = stdev(Diff)
)
| where StdDiff < AvgDiff * 0.3  // Variance less than 30% of mean = regular
| where AvgDiff between (30 .. 3600)  // 30 second to 1 hour intervals
| project DeviceName, RemoteIP, RemotePort, ConnCount, AvgDiff, StdDiff
```

### 5.3 New Connection Target Detection

```kql
// KQL: Detect new external communications not seen before
let HistoricalConnections = DeviceNetworkEvents
| where TimeGenerated between (ago(30d)..ago(1d))
| where RemoteIPType == "Public"
| distinct DeviceName, RemoteIP;

let RecentConnections = DeviceNetworkEvents
| where TimeGenerated > ago(1d)
| where RemoteIPType == "Public"
| distinct DeviceName, RemoteIP, RemotePort, InitiatingProcessFileName;

RecentConnections
| join kind=leftanti HistoricalConnections on DeviceName, RemoteIP
| project DeviceName, RemoteIP, RemotePort, InitiatingProcessFileName
| order by DeviceName
```

---

## 6. Python: Statistical Log Anomaly Detection Tool

```python
#!/usr/bin/env python3
"""
Statistical Log Anomaly Detection CLI Tool
Dependencies: pip install numpy (optional — uses pure Python stats if absent)

Usage: python3 log_anomaly_detector.py [command] [options]
"""

import argparse
import csv
import json
import math
import sys
from collections import Counter, defaultdict
from concurrent.futures import ProcessPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Any, Optional


def mean(values: list[float]) -> float:
    if not values:
        return 0.0
    return sum(values) / len(values)


def stdev(values: list[float]) -> float:
    if len(values) < 2:
        return 0.0
    m = mean(values)
    return math.sqrt(sum((x - m) ** 2 for x in values) / (len(values) - 1))


def zscore(value: float, mu: float, sigma: float) -> float:
    if sigma == 0:
        return 0.0
    return (value - mu) / sigma


def detect_zscore_anomalies(
    values: list[float],
    labels: list[str],
    threshold: float = 3.0,
    group_name: str = "unknown",
) -> list[dict[str, Any]]:
    """Z-score based anomaly detection."""
    if len(values) < 3:
        return []
    mu = mean(values)
    sigma = stdev(values)
    anomalies = []
    for label, val in zip(labels, values):
        z = zscore(val, mu, sigma)
        if abs(z) >= threshold:
            anomalies.append({
                "group": group_name,
                "label": label,
                "value": val,
                "mean": round(mu, 2),
                "stdev": round(sigma, 2),
                "zscore": round(z, 2),
                "method": "z-score",
                "severity": "high" if abs(z) >= 5 else "medium",
            })
    return anomalies
```

---

## 7. Query Optimization Tips

### 7.1 KQL Optimization

1. **Time range first**: Put `where TimeGenerated > ago(24h)` as the first pipe in the pipeline
2. **Indexed fields first**: Filter first with indexed fields like `EventID`, `DeviceName`
3. **Prefer `has` over `contains`**: `has` is faster as it uses word boundaries
4. **Early `project`**: Remove unnecessary columns early to reduce transferred data
5. **Use `summarize`**: Make anomaly decisions on aggregated results rather than individual rows

### 7.2 SPL Optimization

1. **Early filtering**: Minimize result counts at the front of the pipeline
2. **Use `tstats`**: Use `tstats` which is faster than `stats` for large datasets
3. **Specify index**: Use exact index names instead of `index=*`
4. **Limit time range**: Minimize the search time window
5. **Limit fields**: Use the `fields` command to process only required fields

### 7.3 Common Hunting Principles

| Principle | Description |
|-----------|-------------|
| Time constraints | Validate in narrow time windows, then expand |
| Incremental approach | Broad search -> add specific conditions progressively |
| Noise management | Incrementally add whitelists and exceptions |
| Result validation | Manually verify True Positive status of detections |
| Documentation | Record all queries, results, and actions taken |

<!-- detect-validate-40 -->
## Hunting-Query Validation — Do Baseline and Time Window Actually Catch Anomalies?

KQL/SPL queries are judged not by *whether they run* but by **whether they actually catch known-malicious events (zero false negatives) without over-alerting on normal**. A wrong baseline and a narrow time window miss low-and-slow attacks. Validate only on an **owned test index**.

### Item -> Failure mode -> Validation method -> Healthy signal

| Item | Failure mode | Validation method | Healthy signal |
|---|---|---|---|
| Baseline accuracy | Wrong normal | Compare normal/anomalous | Only anomalies surface |
| Query integrity | Missing-field false positive | Verify field presence | Consistent results |
| Time window | Short window miss | Tune window length | Catches slow attack |
| Performance | Timeout | Index/summarize | Query completes |

### Defense validation (verify directly)

```bash
# 1) Whether the query actually catches a known-malicious seed event — inject seed into owned test index, then check
grep -c 'expected_malicious_marker' query_results.json   # 0 => false negative
# 2) Whether the query carries time-window/technique metadata for reproducibility
grep -rEn 'TimeGenerated|earliest=|latest=' hunts/ | head
```

> Validate only on an **owned test index**. "The query runs" differs from "it actually catches the malicious event" — confirm false negatives/positives with seed events directly ([[13_SOC_Blue_Team]], [[25_Threat_Intelligence]]).
