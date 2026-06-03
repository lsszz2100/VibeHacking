> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# IBM QRadar & Azure Sentinel KQL & XDR 블루팀 실전
> AI_Innovation_Studio | SOC Analyst Practical Lab

---

## 0. 초보자를 위한 개념 이해

### QRadar & Azure Sentinel이란?

IBM QRadar는 기업 환경에서 가장 많이 사용되는 엔터프라이즈 SIEM 중 하나로, 수십만 개의 이벤트를 실시간으로 수집·상관 분석합니다. Microsoft Azure Sentinel(현 Microsoft Sentinel)은 클라우드 네이티브 SIEM으로, KQL(Kusto Query Language)을 사용해 Azure·Microsoft 365·서드파티 로그를 분석합니다. XDR(Extended Detection and Response)은 엔드포인트·네트워크·클라우드를 통합 방어하는 차세대 플랫폼입니다.

**왜 배우는가:**
```
SIEM 플랫폼 비교:

  IBM QRadar           Azure Sentinel         Splunk
  ──────────────────────────────────────────────────────
  기업 내부 설치       클라우드 네이티브       온프레미스/클라우드
  AQL 쿼리 언어        KQL 쿼리 언어           SPL 쿼리 언어
  오펜스(Offense) 중심  인시던트/경보 중심      유연한 검색 중심
  금융/공공기관 많음    Azure 환경 최적         데이터 분석 강점

  취업 시장 수요:
    QRadar   → 국내 대기업·금융권 SOC
    Sentinel → Azure 도입 기업, 클라우드 SOC
    Splunk   → 글로벌 기업, 다양한 업종
```

### 핵심 개념 정리

```
QRadar 핵심 개념:
  Offense      — 규칙에 따라 생성된 보안 사건 (인시던트)
  Event        — 단일 로그 항목
  Flow         — 네트워크 연결 요약 (NetFlow)
  AQL          — Ariel Query Language (QRadar 쿼리)
  DSM          — Device Support Module (로그 파서)

Azure Sentinel KQL 기초:
  SecurityEvent
  | where EventID == 4625              // 로그인 실패
  | summarize count() by Account       // 계정별 집계
  | order by count_ desc               // 내림차순 정렬
  | take 10                            // 상위 10개

XDR 구성요소:
  EDR → 엔드포인트 탐지·대응
  NDR → 네트워크 탐지·대응
  CDR → 클라우드 탐지·대응
  XDR → 위 세 가지 통합 플랫폼
```

### 필요한 도구 및 환경
- **QRadar Community Edition**: IBM 무료 가상화 SIEM 환경
- **Microsoft Sentinel (30일 무료)**: Azure 계정으로 체험 가능
- **KQL 플레이그라운드**: Microsoft 공식 학습 환경
- **Python qradar4py**: QRadar REST API Python 클라이언트

### 기초 실습 예제
```python
#!/usr/bin/env python3
"""KQL 쿼리 빌더 — Azure Sentinel 보안 이벤트 분석 기초."""

from dataclasses import dataclass
from enum import StrEnum


class LogTable(StrEnum):
    SECURITY_EVENT = "SecurityEvent"
    SIGNIN_LOGS    = "SigninLogs"
    AZURE_ACTIVITY = "AzureActivity"
    SYSLOG         = "Syslog"


@dataclass
class KqlQuery:
    table: LogTable
    filters: list[str]
    summarize: str | None = None
    order_by: str | None = None
    limit: int = 100

    def build(self) -> str:
        """KQL 쿼리 문자열 생성."""
        parts = [str(self.table)]
        for f in self.filters:
            parts.append(f"| where {f}")
        if self.summarize:
            parts.append(f"| summarize {self.summarize}")
        if self.order_by:
            parts.append(f"| order by {self.order_by} desc")
        parts.append(f"| take {self.limit}")
        return "\n".join(parts)


if __name__ == "__main__":
    # 로그인 실패 상위 계정 조회
    query = KqlQuery(
        table=LogTable.SECURITY_EVENT,
        filters=["EventID == 4625", "TimeGenerated > ago(1h)"],
        summarize="FailCount=count() by Account, IpAddress",
        order_by="FailCount",
        limit=20,
    )
    print("생성된 KQL 쿼리:")
    print(query.build())
```

---

## 1. IBM QRadar 아키텍처 심화

### 컴포넌트 구성

```
                    ┌──────────────────────────────────┐
                    │         QRadar Console           │
                    │  (UI / API / 오펜스 관리 / 보고)  │
                    └──────────┬───────────────────────┘
                               │
              ┌────────────────┼────────────────┐
              ▼                ▼                ▼
    ┌──────────────┐  ┌──────────────┐  ┌──────────────┐
    │Event Processor│  │Flow Processor│  │  Data Node   │
    │(이벤트 분석) │  │(플로우 분석) │  │(저장/검색)   │
    └──────┬───────┘  └──────┬───────┘  └──────────────┘
           │                 │
    ┌──────┴───────┐  ┌──────┴───────┐
    │Event Collector│  │Flow Collector│
    │(이벤트 수집) │  │(NetFlow수집) │
    └──────┬───────┘  └──────┬───────┘
           │                 │
    ┌──────┴─────────────────┴──────┐
    │         데이터 소스             │
    │  방화벽 / Windows / Linux /    │
    │  IDS / WAF / 클라우드 서비스   │
    └────────────────────────────────┘
```

### QRadar CE (Community Edition) Docker 설치

```bash
# QRadar CE 7.5 Docker 환경 구성
# 요구사항: RAM 8GB+, 디스크 50GB+

docker pull ibmqradar/qradar-ce:7.5.0

docker run -d \
    --name qradar-ce \
    --privileged \
    -p 443:443 \
    -p 514:514/udp \
    -p 514:514/tcp \
    -v qradar-data:/opt/IBM/qradar \
    -m 8g \
    --shm-size=2g \
    ibmqradar/qradar-ce:7.5.0

# 초기화 완료 대기 (5~10분)
docker logs -f qradar-ce | grep "SETUP COMPLETE"

# 접속: https://localhost
# 초기 계정: admin / admin (변경 필수)
```

### Log Source 추가

```bash
# Windows Event Log (WinCollect 에이전트)
# QRadar 콘솔 → Admin → Data Sources → Log Sources → Add

# Linux Syslog 설정 (대상 서버에서)
cat >> /etc/rsyslog.conf << 'EOF'
*.* @QRADAR_IP:514         # UDP
*.* @@QRADAR_IP:514        # TCP (권장)
EOF
systemctl restart rsyslog

# CEF 형식 (ArcSight 호환)
# 방화벽/WAF가 CEF 전송 지원 시 바로 사용

# LEEF 형식 (IBM 고유)
# IBM 제품에서 주로 사용
```

---

## 2. QRadar AQL (Ariel Query Language) 심화 실습

기존 `02_splunk_siem_analysis.md`에서 기초 AQL을 다뤘으므로 여기서는 실전 탐지 쿼리에 집중한다.

### Brute Force 탐지

```sql
-- 1분 내 동일 소스에서 10회 이상 인증 실패
SELECT sourceIP,
       destinationIP,
       QIDNAME(qid) AS event_name,
       count(*) AS attempt_count,
       CATEGORYNAME(category) AS category_name
FROM events
WHERE category = 5013  -- Authentication Failure
  AND LOCSRC(sourceIP)  -- 내부 소스만
GROUP BY sourceIP, destinationIP
HAVING count(*) >= 10
LAST 1 MINUTES
ORDER BY attempt_count DESC

-- Password Spray (다수 계정 대상 소수 시도)
SELECT sourceIP,
       UNIQUECOUNT(username) AS targeted_accounts,
       count(*) AS total_attempts
FROM events
WHERE category = 5013
GROUP BY sourceIP
HAVING UNIQUECOUNT(username) > 20
   AND count(*) / UNIQUECOUNT(username) < 5  -- 계정당 5회 미만
LAST 1 HOURS
```

### 대용량 데이터 유출 탐지

```sql
-- 아웃바운드 100MB 초과 플로우 (데이터 유출 의심)
SELECT sourceIP,
       destinationIP,
       destinationPort,
       SUM(destinationBytes) AS total_exfil_bytes,
       SUM(destinationPackets) AS total_packets,
       APPLICATIONNAME(applicationId) AS app_name
FROM flows
WHERE direction = 'L2R'  -- Local to Remote
  AND NOT (destinationIP STARTSWITH '10.'
       OR destinationIP STARTSWITH '192.168.'
       OR destinationIP STARTSWITH '172.')
GROUP BY sourceIP, destinationIP, destinationPort, applicationId
HAVING SUM(destinationBytes) > 104857600  -- 100MB
LAST 1 HOURS
ORDER BY total_exfil_bytes DESC

-- DNS 기반 데이터 유출 탐지 (DNS Tunneling)
SELECT sourceIP,
       destinationIP,
       AVG(payloadLength) AS avg_payload,
       count(*) AS query_count,
       UNIQUECOUNT(DOMAINNAME(destinationPayload)) AS unique_domains
FROM flows
WHERE destinationPort = 53
GROUP BY sourceIP, destinationIP
HAVING count(*) > 100
   AND AVG(payloadLength) > 100  -- DNS 페이로드가 비정상적으로 큼
LAST 1 HOURS
```

### 래터럴 무브먼트 탐지

```sql
-- 내부 네트워크에서 다수 호스트 탐색
SELECT sourceIP,
       UNIQUECOUNT(destinationIP) AS unique_targets,
       count(*) AS connection_count,
       UNIQUECOUNT(destinationPort) AS unique_ports
FROM flows
WHERE LOCSRC(sourceIP)
  AND LOCDST(destinationIP)
  AND sourceIP != destinationIP
GROUP BY sourceIP
HAVING UNIQUECOUNT(destinationIP) > 15
LAST 30 MINUTES
ORDER BY unique_targets DESC

-- SMB/WMI/PsExec 래터럴 무브먼트
SELECT sourceIP,
       destinationIP,
       QIDNAME(qid) AS event_name,
       username
FROM events
WHERE category IN (5001, 5002)  -- Remote Access
  AND (QIDNAME(qid) ILIKE '%psexec%'
    OR QIDNAME(qid) ILIKE '%wmi%'
    OR QIDNAME(qid) ILIKE '%smb%')
  AND LOCSRC(sourceIP)
LAST 1 HOURS
```

### QRadar Custom Rule 예시: Impossible Travel

```
Custom Rule 설정:
  Name: Impossible Travel Detection
  Type: Event Rule
  
  Building Block 1: Successful Login
    → When event category is Authentication Successful
    
  Rule Condition:
    When the same username has a login from Country A
    AND within 60 minutes has a login from Country B
    AND Country A != Country B
    
  Response:
    → Create offense (Severity: 8)
    → Send email to SOC team
    → Add source IP to Reference Set: "Suspicious IPs"
```

---

## 3. QRadar REST API 자동화 (Python 3.10+)

```python
#!/usr/bin/env python3
"""
QRadar REST API를 사용한 오펜스 자동 처리 및 AQL 쿼리 실행 도구.
오펜스를 자동으로 조회하고 SOAR 티켓을 생성합니다.
"""

from __future__ import annotations
import argparse
import json
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urljoin

import httpx


@dataclass
class QRadarConfig:
    host: str
    token: str
    verify_ssl: bool = True
    timeout: float = 30.0

    @property
    def base_url(self) -> str:
        return f"https://{self.host}/api"


@dataclass
class Offense:
    id: int
    description: str
    severity: int
    magnitude: int
    status: str
    source_count: int
    offense_type: int
    start_time: int
    last_updated_time: int


class QRadarClient:
    """IBM QRadar REST API 클라이언트."""

    VERSION = "17.0"

    def __init__(self, config: QRadarConfig) -> None:
        self.config = config
        self._client = httpx.Client(
            verify=config.verify_ssl,
            timeout=config.timeout,
            headers={
                "SEC": config.token,
                "Accept": "application/json",
                "Version": self.VERSION,
            },
        )

    def _get(self, endpoint: str, params: dict | None = None) -> Any:
        url = urljoin(self.config.base_url + "/", endpoint.lstrip("/"))
        resp = self._client.get(url, params=params)
        resp.raise_for_status()
        return resp.json()

    def _post(self, endpoint: str, data: dict) -> Any:
        url = urljoin(self.config.base_url + "/", endpoint.lstrip("/"))
        resp = self._client.post(url, json=data)
        resp.raise_for_status()
        return resp.json()

    def list_offenses(
        self,
        status: str = "OPEN",
        min_severity: int = 1,
        limit: int = 50,
    ) -> list[Offense]:
        """활성 오펜스 목록을 조회합니다."""
        params = {
            "filter": f"status = '{status}' and severity >= {min_severity}",
            "sort": "-magnitude",
            "fields": "id,description,severity,magnitude,status,source_count,offense_type,start_time,last_updated_time",
            "Range": f"items=0-{limit-1}",
        }
        data = self._get("/siem/offenses", params=params)
        return [
            Offense(
                id=o["id"],
                description=o.get("description", ""),
                severity=o.get("severity", 0),
                magnitude=o.get("magnitude", 0),
                status=o.get("status", ""),
                source_count=o.get("source_count", 0),
                offense_type=o.get("offense_type", 0),
                start_time=o.get("start_time", 0),
                last_updated_time=o.get("last_updated_time", 0),
            )
            for o in data
        ]

    def close_offense(self, offense_id: int, reason: str = "Non-Issue") -> dict:
        """오펜스를 종료 처리합니다."""
        data = {
            "status": "CLOSED",
            "closing_reason_id": 1,  # 1=False Positive, 2=Non-Issue
            "closing_notes": reason,
        }
        return self._post(f"/siem/offenses/{offense_id}", data)

    def run_aql(self, query: str, timeout_secs: int = 60) -> list[dict]:
        """AQL 쿼리를 실행하고 결과를 반환합니다."""
        # 쿼리 시작
        start_resp = self._post("/ariel/searches", {"query_expression": query})
        search_id = start_resp["search_id"]

        # 완료 대기
        deadline = time.time() + timeout_secs
        while time.time() < deadline:
            status_resp = self._get(f"/ariel/searches/{search_id}")
            if status_resp["status"] == "COMPLETED":
                break
            elif status_resp["status"] == "ERROR":
                raise RuntimeError(f"AQL 쿼리 오류: {status_resp.get('error_messages')}")
            time.sleep(2)
        else:
            raise TimeoutError(f"AQL 쿼리 타임아웃 ({timeout_secs}초)")

        # 결과 조회
        result_resp = self._get(f"/ariel/searches/{search_id}/results")
        return result_resp.get("events", result_resp.get("flows", []))

    def get_offense_source_addresses(self, offense_id: int) -> list[str]:
        """오펜스의 소스 IP 목록을 반환합니다."""
        data = self._get(
            f"/siem/offenses/{offense_id}/source_address_ids"
        )
        ips = []
        for addr_id in data[:10]:  # 최대 10개
            addr_data = self._get(f"/siem/source_addresses/{addr_id}")
            ips.append(addr_data.get("source_ip", ""))
        return ips


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="QRadar REST API 자동화 도구")
    parser.add_argument("--host", required=True, help="QRadar Console IP/도메인")
    parser.add_argument("--token", required=True, help="QRadar API Token (SEC 토큰)")
    parser.add_argument("--no-verify-ssl", action="store_true")

    subs = parser.add_subparsers(dest="cmd", required=True)

    # 오펜스 목록
    list_p = subs.add_parser("list-offenses", help="오펜스 목록 조회")
    list_p.add_argument("--status", default="OPEN", choices=["OPEN", "CLOSED", "HIDDEN"])
    list_p.add_argument("--min-severity", type=int, default=5)
    list_p.add_argument("--limit", type=int, default=20)

    # AQL 쿼리 실행
    aql_p = subs.add_parser("run-query", help="AQL 쿼리 실행")
    aql_p.add_argument("query", help="AQL 쿼리 문자열")
    aql_p.add_argument("-o", "--output", type=Path, help="결과 저장 경로")

    # 오펜스 종료
    close_p = subs.add_parser("close-offense", help="오펜스 종료")
    close_p.add_argument("offense_id", type=int)
    close_p.add_argument("--reason", default="False Positive")

    return parser.parse_args()


def main() -> None:
    args = parse_args()
    config = QRadarConfig(
        host=args.host,
        token=args.token,
        verify_ssl=not args.no_verify_ssl,
    )
    client = QRadarClient(config)

    if args.cmd == "list-offenses":
        offenses = client.list_offenses(
            status=args.status,
            min_severity=args.min_severity,
            limit=args.limit,
        )
        print(f"{'ID':>6}  {'심각도':>4}  {'Magnitude':>9}  {'소스':>5}  설명")
        print("-" * 70)
        for o in offenses:
            print(f"{o.id:>6}  {o.severity:>4}  {o.magnitude:>9}  {o.source_count:>5}  {o.description[:45]}")

    elif args.cmd == "run-query":
        print(f"[*] AQL 실행 중: {args.query[:80]}...")
        results = client.run_aql(args.query)
        print(f"[+] 결과: {len(results)}행")
        if results:
            print(json.dumps(results[:5], indent=2, ensure_ascii=False))
        if args.output:
            args.output.write_text(json.dumps(results, indent=2, ensure_ascii=False))
            print(f"[*] 저장: {args.output}")

    elif args.cmd == "close-offense":
        result = client.close_offense(args.offense_id, args.reason)
        print(f"[+] 오펜스 {args.offense_id} 종료 완료: {result.get('status')}")


if __name__ == "__main__":
    main()
```

QRadar REST API를 통해 오펜스 조회, AQL 쿼리 실행, 오펜스 자동 종료를 수행하는 SOC 자동화 클라이언트다.

---

## 4. Microsoft Sentinel (Azure Sentinel) KQL 실전

### 데이터 테이블 구조

```
핵심 테이블:
  SecurityEvent          → Windows 이벤트 로그 (4624, 4625, 4688 등)
  Syslog                 → Linux/Unix 시스템 로그
  SigninLogs             → Azure AD / Entra ID 로그인 기록
  AuditLogs              → Azure AD 관리 작업 감사
  SecurityAlert          → Microsoft Defender 경고
  DeviceProcessEvents    → MDE 프로세스 생성 이벤트
  DeviceNetworkEvents    → MDE 네트워크 이벤트
  DeviceFileEvents       → MDE 파일 시스템 이벤트
  ThreatIntelligenceIndicator → 위협 인텔리전스 IOC
  AzureActivity          → Azure 리소스 작업 로그
  OfficeActivity         → Microsoft 365 감사 로그
```

### 브루트포스 탐지

```kusto
// 1분 내 10회 이상 로그인 실패
SecurityEvent
| where EventID == 4625
| where TimeGenerated > ago(1h)
| summarize
    FailureCount = count(),
    TargetAccounts = make_set(TargetUserName),
    SourceIPs = make_set(IpAddress)
    by bin(TimeGenerated, 1m), Computer, IpAddress
| where FailureCount >= 10
| extend
    AlertName = "Brute Force 탐지",
    Severity = "High"
| project TimeGenerated, IpAddress, FailureCount, TargetAccounts, Severity
```

### 불가능한 이동 (Impossible Travel)

```kusto
// 동일 사용자가 1시간 내에 다른 국가에서 로그인
SigninLogs
| where ResultType == 0
| where TimeGenerated > ago(24h)
| extend
    Country = tostring(LocationDetails.countryOrRegion),
    City = tostring(LocationDetails.city)
| sort by UserPrincipalName asc, TimeGenerated asc
| serialize
| extend
    PrevCountry = prev(Country, 1),
    PrevTime = prev(TimeGenerated, 1),
    PrevUser = prev(UserPrincipalName, 1)
| where UserPrincipalName == PrevUser
| where Country != PrevCountry
| where datetime_diff("minute", TimeGenerated, PrevTime) < 60
| project
    TimeGenerated,
    UserPrincipalName,
    CurrentCountry = Country,
    PreviousCountry = PrevCountry,
    MinutesBetween = datetime_diff("minute", TimeGenerated, PrevTime),
    IPAddress
```

### 권한 상승 탐지

```kusto
// 높은 권한 그룹 멤버 추가 감지
SecurityEvent
| where EventID in (4728, 4732, 4756)  // 전역/로컬/유니버설 그룹 멤버 추가
| where TimeGenerated > ago(24h)
| extend
    MemberAdded = extract(@"Account Name:\s+(.+)", 1, EventData),
    GroupName = extract(@"Group Name:\s+(.+)", 1, EventData)
| where GroupName has_any ("Admin", "Domain", "Enterprise", "Schema")
| project
    TimeGenerated,
    Computer,
    SubjectUserName,
    GroupName,
    MemberAdded

// Azure AD 관리자 역할 할당
AuditLogs
| where OperationName == "Add member to role"
| where TimeGenerated > ago(24h)
| extend
    TargetUser = tostring(TargetResources[0].userPrincipalName),
    RoleName = tostring(TargetResources[0].displayName),
    Actor = tostring(InitiatedBy.user.userPrincipalName)
| where RoleName has_any ("Admin", "Global", "Privileged")
| project TimeGenerated, Actor, TargetUser, RoleName
```

### 랜섬웨어 행위 탐지

```kusto
// 단시간 대량 파일 수정 (랜섬웨어 암호화 행위)
DeviceFileEvents
| where ActionType in ("FileModified", "FileRenamed", "FileCreated")
| where TimeGenerated > ago(1h)
| where FileName matches regex @"\.(encrypted|locked|ransom|crypt|enc)$"
    or FileName matches regex @"\.[a-f0-9]{5,8}$"  // 랜덤 확장자
| summarize
    FileCount = count(),
    AffectedPaths = make_set(FolderPath, 5)
    by DeviceName, bin(TimeGenerated, 1m)
| where FileCount > 50
| extend AlertSeverity = "Critical"

// 볼륨 섀도 삭제 (랜섬웨어 복구 방해)
DeviceProcessEvents
| where TimeGenerated > ago(1h)
| where ProcessCommandLine has_all ("vssadmin", "delete", "shadows")
    or ProcessCommandLine has_all ("wmic", "shadowcopy", "delete")
    or ProcessCommandLine has_all ("bcdedit", "recoveryenabled", "no")
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine
| extend AlertSeverity = "Critical"
```

### C2 비콘 탐지 (주기적 DNS 쿼리)

```kusto
// 동일 도메인에 규칙적 간격 DNS 쿼리 (비콘 패턴)
DnsEvents
| where TimeGenerated > ago(1h)
| where QueryType == "A"
| summarize
    QueryCount = count(),
    UniqueClients = dcount(ClientIP),
    QueryTimes = make_list(TimeGenerated, 100)
    by Computer, Name
| where QueryCount > 50
| where UniqueClients <= 2  // 소수 클라이언트에서만 쿼리 → 비콘 의심
| extend
    AvgIntervalSeconds = 3600.0 / QueryCount
| where AvgIntervalSeconds between (25 .. 305)  // 30초~5분 간격
| project Computer, Name, QueryCount, AvgIntervalSeconds
```

### Microsoft Sentinel Analytics Rule 생성 (JSON)

```json
{
  "displayName": "랜섬웨어 파일 대량 수정 탐지",
  "description": "1분 내 50개 이상 파일이 수정되는 랜섬웨어 행위를 탐지합니다.",
  "severity": "High",
  "enabled": true,
  "query": "DeviceFileEvents\n| where ActionType in ('FileModified', 'FileRenamed')\n| summarize FileCount = count() by DeviceName, bin(TimeGenerated, 1m)\n| where FileCount > 50",
  "queryFrequency": "PT5M",
  "queryPeriod": "PT5M",
  "triggerOperator": "GreaterThan",
  "triggerThreshold": 0,
  "suppressionDuration": "PT1H",
  "suppressionEnabled": false,
  "tactics": ["Impact"],
  "techniques": ["T1486"],
  "alertDetailsOverride": {
    "alertDisplayNameFormat": "랜섬웨어 의심: {{DeviceName}}에서 {{FileCount}}개 파일 수정"
  }
}
```

---

## 5. XDR (Extended Detection and Response) 플랫폼

### EDR vs XDR vs SIEM 비교

| 항목 | SIEM | EDR | XDR |
|------|------|-----|-----|
| **데이터 소스** | 로그 (다양) | 엔드포인트만 | 엔드포인트+네트워크+클라우드+이메일 |
| **탐지 방법** | 룰 기반 | 행위 기반+ML | 다층 상관관계+ML |
| **대응 능력** | 없음(알림만) | 격리/프로세스 종료 | 자동화된 전체 대응 |
| **조사 편의성** | 수동 (쿼리) | 프로세스 트리 | 공격 체인 시각화 |
| **구축 복잡도** | 높음 | 중간 | 낮음~중간 |

### 주요 XDR 플랫폼 비교

| 플랫폼 | 제조사 | 핵심 특징 |
|--------|--------|---------|
| **Cortex XDR** | Palo Alto Networks | NGAV+EDR+NDR+CASB 통합, XQL 쿼리 |
| **CrowdStrike Falcon** | CrowdStrike | 클라우드 네이티브, 경량 에이전트(~2% CPU), OverWatch |
| **Microsoft Defender XDR** | Microsoft | M365/Entra/Azure 네이티브 통합, KQL 기반 |
| **SentinelOne Singularity** | SentinelOne | 자율 AI 대응, 1클릭 롤백 (Storyline) |
| **Trend Micro Vision One** | Trend Micro | 공격 표면 관리, XDR+ASM 결합 |

### Cortex XDR — XQL 쿼리 실습

```sql
-- 의심스러운 PowerShell 인코딩 명령 탐지
dataset = xdr_data
| filter event_type = "PROCESS"
| filter actor_process_image_name = "powershell.exe"
| filter action_process_image_command_line ~= ".*-enc.*|.*-EncodedCommand.*|.*-e .*"
| fields
    actor_primary_username,
    action_process_image_command_line,
    causality_actor_process_image_name,
    action_process_image_path,
    event_timestamp

-- 프로세스 인젝션 패턴 탐지
dataset = xdr_data
| filter event_type = "PROCESS"
| filter action_process_image_name != causality_actor_process_image_name
| filter causality_actor_process_image_name in ("winword.exe", "excel.exe", "outlook.exe", "acrord32.exe")
| filter action_process_image_name in ("powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe")
| fields
    causality_actor_process_image_name as parent_process,
    action_process_image_name as child_process,
    action_process_image_command_line,
    actor_primary_username,
    hostname

-- 희귀 프로세스 탐지 (조직 내 거의 사용되지 않는 바이너리)
dataset = xdr_data
| filter event_type = "PROCESS"
| filter event_timestamp > to_timestamp(now() - 86400, "seconds")  -- 최근 24시간
| alter process_name = lowercase(action_process_image_name)
| aggregate count() as exec_count by process_name
| filter exec_count < 5  -- 5회 미만 실행 = 희귀 프로세스
| sort exec_count asc
```

### Microsoft Defender XDR — 고급 헌팅 (KQL)

```kusto
// 의심스러운 오피스 매크로 실행 체인
DeviceProcessEvents
| where InitiatingProcessFileName has_any ("winword.exe", "excel.exe", "powerpnt.exe")
| where FileName in~ ("powershell.exe", "cmd.exe", "wscript.exe", "mshta.exe", "regsvr32.exe")
| where TimeGenerated > ago(24h)
| project
    TimeGenerated,
    DeviceName,
    AccountName,
    InitiatingProcessFileName,
    FileName,
    ProcessCommandLine
| order by TimeGenerated desc

// LOLBAS (Living off the Land) 탐지
let lolbas_binaries = dynamic([
    "certutil.exe", "bitsadmin.exe", "regsvr32.exe", "mshta.exe",
    "wmic.exe", "cmstp.exe", "msiexec.exe", "forfiles.exe",
    "ie4uinit.exe", "presentationhost.exe", "xwizard.exe"
]);
DeviceProcessEvents
| where FileName in~ (lolbas_binaries)
| where ProcessCommandLine has_any ("http://", "https://", "ftp://", "\\\\")
| where TimeGenerated > ago(1h)
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine

// 네트워크 IOC 매칭 (위협 인텔리전스)
DeviceNetworkEvents
| where TimeGenerated > ago(24h)
| join kind=inner (
    ThreatIntelligenceIndicator
    | where ExpirationDateTime > now()
    | where ConfidenceScore >= 70
    | where isnotempty(NetworkIP)
    | project ThreatIP = NetworkIP, ThreatType, Description
) on $left.RemoteIP == $right.ThreatIP
| project TimeGenerated, DeviceName, AccountName, RemoteIP, RemotePort, ThreatType, Description
```

---

## 6. Blue Team 필수 절차 (Blue Team Field Manual 기반)

### 사고 대응 6단계 (NIST SP 800-61)

```
┌─────────────────────────────────────────────────────────┐
│  1. 준비 (Preparation)                                   │
│     - 사고 대응 플레이북 작성                             │
│     - SOC 연락처 목록 (24/7 대기)                        │
│     - 디지털 포렌식 도구 준비 (KAPE, Velociraptor)        │
│     - 통신 채널 암호화 (Slack 격리 채널)                  │
└─────────────────────────────────────────────────────────┘
         ↓
┌─────────────────────────────────────────────────────────┐
│  2. 탐지 및 분석 (Detection & Analysis)                  │
│     - SIEM 경고 트리아지 (False Positive 필터링)          │
│     - IOC 추출 (IP, 도메인, 해시, 레지스트리 키)          │
│     - 공격 타임라인 재구성                               │
│     - 피해 범위 초기 파악                                │
└─────────────────────────────────────────────────────────┘
         ↓
┌─────────────────────────────────────────────────────────┐
│  3. 억제 (Containment)                                   │
│     - 감염 호스트 네트워크 격리 (VLAN 변경, ACL 적용)    │
│     - 악성 계정 잠금 / 패스워드 초기화                   │
│     - 악성 IP/도메인 방화벽 차단                         │
│     - 단기 억제 → 중기 억제 → 장기 억제 순서로           │
└─────────────────────────────────────────────────────────┘
         ↓
┌─────────────────────────────────────────────────────────┐
│  4. 제거 (Eradication)                                   │
│     - 악성코드 제거 (AV 스캔 + 수동 확인)                │
│     - 루트킷/지속성 메커니즘 제거                        │
│     - 취약점 패치 적용                                   │
│     - 감염 경로 근본 원인 제거                           │
└─────────────────────────────────────────────────────────┘
         ↓
┌─────────────────────────────────────────────────────────┐
│  5. 복구 (Recovery)                                      │
│     - 백업에서 시스템 복원                               │
│     - 서비스 재시작 및 정상 동작 확인                    │
│     - 모니터링 강화 (2~4주간 집중 감시)                  │
│     - 사용자에게 피해 통보 (법적 요건 확인)              │
└─────────────────────────────────────────────────────────┘
         ↓
┌─────────────────────────────────────────────────────────┐
│  6. 사후 활동 (Post-Incident Activity)                   │
│     - PIR (Post-Incident Review) 작성                   │
│     - 탐지 룰 및 플레이북 개선                          │
│     - 보안 교육 업데이트                                │
│     - 규제 기관 보고 (GDPR 72시간 이내 등)              │
└─────────────────────────────────────────────────────────┘
```

### Log4Shell (CVE-2021-44228) 사고 대응 케이스

```bash
# 1. 탐지: SIEM에서 Log4j 악용 패턴 검색
# Splunk
index=web_logs
| rex field=_raw "(?i)(?P<log4j>\$\{.*jndi:.*\})"
| where isnotnull(log4j)
| stats count, values(src_ip) by host

# 2. 영향 범위 파악
# 취약한 Log4j 버전 사용 서비스 목록
find / -name "log4j*.jar" 2>/dev/null | xargs -I{} sh -c \
    'echo "파일: {}"; unzip -p {} META-INF/MANIFEST.MF 2>/dev/null | grep Implementation-Version'

# 3. 억제: 취약 서버 네트워크 격리 (iptables 예시)
iptables -I OUTPUT -j DROP  # 아웃바운드 완전 차단
iptables -I INPUT -s ATTACKER_IP -j DROP

# 4. 임시 완화 (패치 전)
# Java 8u121+ 이상: com.sun.jndi.lookup.allowRemoteClasses=false
java -Dlog4j2.formatMsgNoLookups=true -jar application.jar

# WAF 룰 즉시 적용 (ModSecurity)
SecRule REQUEST_HEADERS|REQUEST_URI|REQUEST_BODY \
    "@rx \$\{.*j.*n.*d.*i.*:.*\}" \
    "id:1001,phase:2,deny,status:403,msg:'Log4Shell attempt'"

# 5. 역방향 쉘 연결 확인
netstat -tlnp | grep ESTABLISHED
ss -tlnp | grep ":4444\|:1234\|:9001"
```

### SOC 필수 도구 40선

| # | 카테고리 | 도구 | 용도 |
|---|---------|------|------|
| 1 | SIEM | Splunk Enterprise | 로그 집계/검색/경고 |
| 2 | SIEM | IBM QRadar | 엔터프라이즈 SIEM |
| 3 | SIEM | Microsoft Sentinel | 클라우드 네이티브 SIEM |
| 4 | SIEM | Elastic SIEM (ELK) | 오픈소스 SIEM |
| 5 | EDR | CrowdStrike Falcon | 클라우드 EDR |
| 6 | EDR | SentinelOne | AI 자율 대응 |
| 7 | EDR | Microsoft Defender for Endpoint | Windows 통합 |
| 8 | NDR | Zeek (Bro) | 네트워크 행위 분석 |
| 9 | NDR | Suricata | IDS/IPS/NSM |
| 10 | NDR | Darktrace | AI NDR |
| 11 | SOAR | Palo Alto XSOAR | 플레이북 자동화 |
| 12 | SOAR | Sentinel Playbook | Logic Apps 기반 |
| 13 | SOAR | TheHive | 오픈소스 사고 관리 |
| 14 | TIP | MISP | 위협 인텔리전스 공유 |
| 15 | TIP | OpenCTI | 위협 인텔 플랫폼 |
| 16 | TIP | Anomali ThreatStream | 상용 TIP |
| 17 | Forensics | Velociraptor | 원격 포렌식 |
| 18 | Forensics | KAPE | 아티팩트 수집 |
| 19 | Forensics | Volatility 3 | 메모리 포렌식 |
| 20 | Forensics | Autopsy | 디스크 포렌식 |
| 21 | Sandbox | Cuckoo Sandbox | 악성코드 동적 분석 |
| 22 | Sandbox | ANY.RUN | 클라우드 샌드박스 |
| 23 | Sandbox | Hybrid Analysis | 통합 분석 |
| 24 | AV/Anti-malware | VirusTotal | 멀티 엔진 스캔 |
| 25 | Deception | Thinkst Canary | 허니팟/카나리 토큰 |
| 26 | Vuln Mgmt | Tenable Nessus | 취약점 스캔 |
| 27 | Vuln Mgmt | Qualys | 클라우드 취약점 관리 |
| 28 | Vuln Mgmt | Rapid7 InsightVM | 위험 기반 취약점 관리 |
| 29 | OSINT | Shodan | 인터넷 자산 검색 |
| 30 | OSINT | Censys | 인터넷 자산 조회 |
| 31 | Phishing | GoPhish | 피싱 시뮬레이션 |
| 32 | Email | Proofpoint | 이메일 보안 게이트웨이 |
| 33 | WAF | ModSecurity | 오픈소스 WAF |
| 34 | WAF | Cloudflare | CDN+WAF |
| 35 | PAM | CyberArk | 특권 접근 관리 |
| 36 | IAM | Okta | SSO/MFA |
| 37 | Network | Wireshark | 패킷 분석 |
| 38 | Network | Nmap | 포트 스캔 |
| 39 | Logging | Fluentd | 로그 집계 파이프라인 |
| 40 | CMDB | ServiceNow | 자산/사고 티케팅 |

---

## 7. 악성코드 분석 — SOC Tier 1 워크플로우

### 정적 분석 기초

```bash
# 1. 파일 타입 확인
file suspicious.exe
exiftool suspicious.exe | grep -E "(FileType|MIME|Created|Modified)"

# 2. 해시 생성 및 VirusTotal 조회
md5sum suspicious.exe
sha256sum suspicious.exe
# → VirusTotal: https://www.virustotal.com/gui/file/<SHA256>

# 3. 문자열 추출
strings suspicious.exe | grep -E "(http|ftp|cmd|reg|HKEY|\.exe|\.dll|password|token)"
strings -e l suspicious.exe  # UTF-16 문자열 (Windows 실행 파일)

# 4. 엔트로피 측정 (패킹/암호화 탐지)
python3 -c "
import math, sys
data = open('suspicious.exe', 'rb').read()
freq = [data.count(bytes([b])) for b in range(256)]
n = len(data)
entropy = -sum((f/n)*math.log2(f/n) for f in freq if f > 0)
print(f'엔트로피: {entropy:.2f} / 8.0')
print('의심: 7.2 이상이면 패킹/암호화 가능성')
"
```

### 동적 분석 (샌드박스)

```
ANY.RUN (https://any.run):
  → 무료 플랜: 60초 분석
  → 상호작용 가능 (직접 클릭, 입력 가능)
  → MITRE ATT&CK 매핑 자동 생성
  → 네트워크 트래픽 PCAP 제공

Hybrid Analysis (https://hybrid-analysis.com):
  → 무료 멀티 샌드박스 (Windows 7/10, Linux)
  → 상세 행위 보고서
  → Falcon Intelligence Sandbox 연동

IOC 추출 자동화:
  → 샌드박스 보고서에서 다음 추출:
    - 접속 IP/도메인 (C2)
    - 생성/수정 파일 경로
    - 레지스트리 변경 키
    - 뮤텍스 이름 (악성코드 재감염 방지용)
    - 삭제된 섀도 카피
```

### VirusTotal Intelligence 활용

```python
#!/usr/bin/env python3
"""VirusTotal API를 사용해 파일 해시, URL, 도메인을 자동으로 분석합니다."""

from __future__ import annotations
import argparse
import hashlib
import json
import sys
from pathlib import Path

import httpx

VT_API_BASE = "https://www.virustotal.com/api/v3"


def check_hash(api_key: str, file_hash: str) -> dict:
    """파일 해시를 VirusTotal에서 조회합니다."""
    with httpx.Client(timeout=30.0) as client:
        resp = client.get(
            f"{VT_API_BASE}/files/{file_hash}",
            headers={"x-apikey": api_key},
        )
        if resp.status_code == 404:
            return {"error": "해시 없음 (미탐지 파일)"}
        resp.raise_for_status()
        data = resp.json()
        stats = data["data"]["attributes"]["last_analysis_stats"]
        names = data["data"]["attributes"].get("names", [])
        return {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "undetected": stats.get("undetected", 0),
            "total": sum(stats.values()),
            "known_names": names[:5],
        }


def main() -> None:
    parser = argparse.ArgumentParser(description="VirusTotal IOC 조회 도구")
    parser.add_argument("--api-key", required=True, help="VT API Key")
    parser.add_argument("--file", type=Path, help="분석할 파일")
    parser.add_argument("--hash", help="SHA256/MD5 해시")
    args = parser.parse_args()

    if args.file:
        data = args.file.read_bytes()
        file_hash = hashlib.sha256(data).hexdigest()
        print(f"[*] SHA256: {file_hash}")
    elif args.hash:
        file_hash = args.hash
    else:
        print("[!] --file 또는 --hash 필요", file=sys.stderr)
        sys.exit(1)

    result = check_hash(args.api_key, file_hash)
    total = result.get("total", 0)
    malicious = result.get("malicious", 0)

    if "error" in result:
        print(f"[?] {result['error']}")
    elif malicious > 0:
        print(f"[!] 악성 탐지: {malicious}/{total}")
        print(f"    알려진 이름: {result.get('known_names', [])}")
    else:
        print(f"[+] 클린: {malicious}/{total} 탐지")


if __name__ == "__main__":
    main()
```

---

## 8. Splunk Phantom / XSOAR SOAR 자동화

### 자동화 플레이북 예시 (의사코드)

```yaml
플레이북: 피싱 이메일 자동 처리

트리거: 이메일 보안 게이트웨이 경고

단계:
  1. 이메일 헤더 파싱
     → 발신자 IP, SPF/DKIM/DMARC 검증 결과 추출

  2. 첨부파일 추출
     → 각 첨부파일 VirusTotal/Sandbox 자동 제출

  3. URL 추출 및 평판 조회
     → URLhaus, VirusTotal, UrlScan.io 동시 조회

  4. 위험도 평가
     → IF (VT 탐지율 > 30% OR Sandbox = 악성):
          → 보낸 사람 차단, 관리자 알림, 티켓 생성 (Priority: Critical)
     → ELSE IF (의심스러운 패턴 있음):
          → 수동 검토 큐로 이동, 티켓 생성 (Priority: Medium)
     → ELSE:
          → 클린으로 표시, 티켓 생성 (Priority: Low)

  5. 결과 보고
     → Slack #soc-alerts 채널 알림
     → Jira 티켓 자동 생성
     → SIEM에 이벤트 기록
```

---

<a name="english"></a>

# IBM QRadar & Azure Sentinel KQL & XDR Blue Team Practical Guide

> AI_Innovation_Studio | SOC Analyst Practical Lab

---

## 1. IBM QRadar Fundamentals

### QRadar Architecture

```
Log Sources → Event Collectors → Event Processors → Console
                                      │
                                      ▼
                               Offense Manager
                               (Correlation Rules)
```

### AQL (Ariel Query Language)

```sql
-- Basic event search
SELECT DATEFORMAT(starttime,'YYYY-MM-dd HH:mm:ss') as Time,
       sourceip, destinationip, username, eventname
FROM events
WHERE LOGSOURCETYPENAME(devicetype) = 'Microsoft Windows Security Event Log'
  AND eventname IN ('An account failed to log on')
  AND DATEFORMAT(starttime,'YYYY-MM-dd') = DATEFORMAT(NOW(),'YYYY-MM-dd')
ORDER BY starttime DESC
LAST 24 HOURS

-- Brute force detection
SELECT sourceip, username, COUNT(*) as FailCount
FROM events
WHERE eventname = 'An account failed to log on'
GROUP BY sourceip, username
HAVING COUNT(*) > 20
LAST 1 HOURS

-- Lateral movement detection
SELECT sourceip, destinationip, username,
       COUNT(DISTINCT destinationip) as UniqueTargets
FROM events
WHERE eventname = 'An account was successfully logged on'
  AND LOGSOURCETYPENAME(devicetype) = 'Microsoft Windows Security Event Log'
GROUP BY sourceip, username
HAVING COUNT(DISTINCT destinationip) > 5
LAST 4 HOURS
```

---

## 2. Microsoft Sentinel KQL

### KQL Fundamentals

```kql
// Basic search
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4625
| project TimeGenerated, Computer, Account, IpAddress, LogonTypeName

// Aggregation
SecurityEvent
| where TimeGenerated > ago(1h)
| where EventID == 4625
| summarize FailCount=count() by IpAddress, Account
| where FailCount > 10
| order by FailCount desc

// Join
SecurityEvent
| where EventID == 4624
| join kind=inner (
    ThreatIntelligenceIndicator
    | where TimeGenerated > ago(7d)
    | where Active == true
) on $left.IpAddress == $right.NetworkIP
| project TimeGenerated, Computer, Account, IpAddress, ThreatType, Confidence
```

### Advanced Sentinel Detections

```kql
// Suspicious PowerShell execution
SecurityEvent
| where EventID == 4688
| where Process has_any ("powershell", "pwsh")
| where CommandLine has_any (
    "-enc", "-EncodedCommand", "-nop", "-NonInteractive",
    "IEX", "Invoke-Expression", "DownloadString", "bypass"
)
| project TimeGenerated, Computer, Account, CommandLine
| order by TimeGenerated desc

// Ransomware detection
DeviceFileEvents
| where TimeGenerated > ago(1h)
| where ActionType == "FileRenamed"
| where FileName has_any (".encrypted", ".locked", ".ransom", ".crypted")
| summarize FileCount=count() by DeviceName, InitiatingProcessFileName
| where FileCount > 50
| extend Severity="High", Alert="Possible Ransomware Activity"
```

---

## 3. XDR (Extended Detection and Response)

### XDR Architecture

```
Endpoint (EDR) ──┐
Network (NDR)  ──┼──► XDR Platform ──► Unified Detection & Response
Email          ──┘
Cloud          ──┘
Identity       ──┘

Key XDR Solutions:
  Microsoft Defender XDR (formerly M365 Defender)
  CrowdStrike Falcon XDR
  Palo Alto Cortex XDR
  SentinelOne Singularity XDR
```

### Microsoft Defender XDR KQL

```kql
// Cross-product correlation: Email → Endpoint
EmailEvents
| where ThreatTypes has "Phishing"
| join kind=inner DeviceProcessEvents on $left.RecipientEmailAddress == $right.AccountName
| where Timestamp between (EmailTimestamp .. (EmailTimestamp + 1h))
| project EmailTimestamp, SenderMailFromAddress, RecipientEmailAddress,
          DeviceName, FileName, ProcessCommandLine

// Incident hunting across all signals
AlertInfo
| join AlertEvidence on AlertId
| where Severity in ("High", "Critical")
| where DetectionSource in ("MDO", "MDE", "MCAS")
| project Timestamp, AlertId, Title, Severity, DetectionSource, EntityType, EvidenceRole
| order by Timestamp desc
```

---

## 4. SOAR (Security Orchestration, Automation, Response)

### Phishing Email Playbook

```
Automated Phishing Analysis Process:

1. Email receipt (via SIEM/email gateway alert)
   → Extract: sender, subject, attachment hash, URLs

2. Attachment analysis
   → Submit hash to VirusTotal API
   → Sandbox detonation (Cuckoo/Any.run)

3. URL extraction and reputation check
   → Query URLhaus, VirusTotal, UrlScan.io simultaneously

4. Risk assessment
   → IF (VT detection rate > 30% OR Sandbox = malicious):
        → Block sender, notify admin, create ticket (Priority: Critical)
   → ELSE IF (suspicious patterns found):
        → Move to manual review queue, create ticket (Priority: Medium)
   → ELSE:
        → Mark as clean, create ticket (Priority: Low)

5. Result reporting
   → Slack #soc-alerts channel notification
   → Jira ticket auto-creation
   → Log event to SIEM
```
