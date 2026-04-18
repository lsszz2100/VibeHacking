# Splunk & SIEM 실전 분석

## Splunk 아키텍처

```
Data Sources → Forwarder → Indexer → Search Head
                  │            │           │
              (수집/전달)   (저장/인덱싱) (검색/시각화)

Universal Forwarder: 경량, 로그 수집만
Heavy Forwarder: 파싱/필터링 가능
Indexer Cluster: 고가용성 분산 저장
Search Head Cluster: 분산 검색
```

---

## 1. Splunk SPL 기초 문법

### 기본 검색 구문

```spl
# 기본 검색
index=security EventCode=4625

# AND/OR/NOT
index=security (EventCode=4624 OR EventCode=4625) NOT host=DC01

# 와일드카드
index=windows host=WEB* Process_Name=*powershell*

# 필드 비교
index=security src_ip!=10.0.0.0/8 dest_port=443

# 시간 범위
index=security earliest=-24h latest=now
index=security earliest="01/01/2024:00:00:00" latest="01/02/2024:00:00:00"
```

### 변환 명령어

```spl
# stats - 통계 집계
index=security EventCode=4625
| stats count as FailCount by src_ip, user

# count, sum, avg, min, max, dc (distinct count)
index=web
| stats count, avg(response_time), max(bytes) by uri_path

# eval - 필드 계산/생성
index=security EventCode=4624
| eval LogonTypeDesc = case(
    LogonType==2, "Interactive",
    LogonType==3, "Network",
    LogonType==10, "RemoteInteractive",
    true(), "Other"
)

# rename - 필드명 변경
index=security
| rename src_ip as SourceIP, dest_ip as DestIP

# table - 특정 필드만 표시
index=security EventCode=4688
| table _time, host, user, Process_Name, Process_Command_Line

# sort - 정렬
| sort -count        # count 내림차순
| sort +_time        # 시간 오름차순

# head/tail - 상위/하위 N개
| head 100
| tail 10
```

### 파이프라인 조합

```spl
# 브루트포스 탐지
index=security EventCode=4625
| bucket _time span=5m
| stats count as FailCount, dc(user) as UniqueUsers
  by src_ip, _time
| where FailCount > 10
| sort -FailCount
| rename FailCount as "실패횟수", UniqueUsers as "시도계정수"

# 성공/실패 비율
index=security (EventCode=4624 OR EventCode=4625)
| eval Event = if(EventCode==4624, "Success", "Failure")
| stats count by Event, user
| eval Rate = round(count/sum(count)*100, 2)."%"
```

---

## 2. 핵심 SOC 탐지 쿼리 100+

### 2.1 계정 침해 탐지

```spl
# [1] 짧은 시간 내 동일 계정 다중 지역 로그인
index=security EventCode=4624 LogonType=10
| iplocation src_ip
| stats dc(Country) as Countries, values(Country) as CountryList
  by user, span(_time, 1h)
| where Countries > 1

# [2] 업무 시간 외 관리자 로그인
index=security EventCode=4624
| where date_hour < 8 OR date_hour > 18
| where match(user, "(?i)admin|svc|service")
| table _time, user, src_ip, host

# [3] 비활성화된 계정 로그인 시도
index=security EventCode=4625 SubStatus="0xC0000072"
| table _time, user, src_ip

# [4] 새로 생성된 관리자 계정
index=security EventCode=4720
| join user [
    search index=security EventCode=4732 GroupName="Administrators"
    | fields user
]
| table _time, CreatorUser, user, host

# [5] 계정 잠금 → 즉시 성공 패턴 (Pass-the-Hash 의심)
index=security (EventCode=4740 OR EventCode=4624)
| transaction user maxspan=10m
| where match(EventCodes, "4740") AND match(EventCodes, "4624")
| table user, host, src_ip, duration
```

### 2.2 프로세스/실행 탐지

```spl
# [6] LOLBins (Living off the Land Binaries) 탐지
index=sysmon EventCode=1
| where match(Image, 
  "(?i)certutil|bitsadmin|mshta|wscript|cscript|regsvr32|rundll32|msiexec")
| where match(CommandLine, "(?i)http|ftp|\\\\|cmd|powershell")
| table _time, host, User, Image, CommandLine

# [7] PowerShell 인코딩 커맨드 탐지
index=sysmon EventCode=1 Image="*powershell*"
| where match(CommandLine, "(?i)-enc|-encodedcommand|-en ")
| table _time, host, User, CommandLine

# [8] 자식 프로세스 이상 탐지 (Office → Shell)
index=sysmon EventCode=1
| where match(ParentImage, "(?i)winword|excel|powerpnt|outlook")
| where match(Image, "(?i)cmd|powershell|wscript|cscript|mshta")
| table _time, host, User, ParentImage, Image, CommandLine

# [9] 프로세스 인젝션 탐지 (CreateRemoteThread)
index=sysmon EventCode=8
| where NOT match(SourceImage, "(?i)\\\\Windows\\\\")
| where match(TargetImage, "(?i)lsass|svchost|explorer|winlogon")
| table _time, host, SourceImage, TargetImage, StartAddress

# [10] LSASS 메모리 덤프 탐지
index=sysmon (EventCode=10 OR EventCode=1)
| where match(TargetImage, "(?i)lsass.exe") 
  OR match(CommandLine, "(?i)lsass|procdump|sekurlsa|wce")
| table _time, host, User, Image, CommandLine
```

### 2.3 네트워크 이상 탐지

```spl
# [11] 내부 네트워크 스캔 탐지
index=network 
| stats dc(dest_ip) as UniqueTargets, count as Connections
  by src_ip, dest_port
| where UniqueTargets > 20 AND Connections > 50
| sort -UniqueTargets

# [12] DNS 비정상 쿼리 (DGA 도메인)
index=dns query_type=A
| eval domain_length = len(query)
| eval entropy = ... (엔트로피 계산)
| where domain_length > 20 AND entropy > 3.5
| table _time, src_ip, query, answer

# [13] 비정상 포트 통신 (C2 비콘 탐지)
index=network dest_port NOT IN (80, 443, 53, 25, 110, 143, 22, 3389)
| stats count, values(dest_ip) as DestIPs by src_ip, dest_port
| where count > 100
| sort -count

# [14] 대용량 데이터 외부 전송 (데이터 유출)
index=network dest_ip NOT CIDR "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"
| stats sum(bytes_out) as TotalBytes by src_ip, dest_ip, dest_port
| eval TotalMB = round(TotalBytes/1024/1024, 2)
| where TotalMB > 100
| sort -TotalMB

# [15] 의심스러운 TLS/SSL 통신 (비표준 포트)
index=ssl dest_port NOT IN (443, 8443, 8080)
| table _time, src_ip, dest_ip, dest_port, ssl_subject, ssl_issuer
```

### 2.4 지속성/권한 상승 탐지

```spl
# [16] 새 서비스 설치 탐지
index=windows EventCode=7045
| table _time, host, ServiceName, ImagePath, AccountName

# [17] 예약 작업 생성
index=security EventCode=4698
| table _time, host, SubjectUserName, TaskName, TaskContent

# [18] 레지스트리 자동 실행 키 수정
index=sysmon EventCode=13
| where match(TargetObject, 
  "(?i)CurrentVersion\\\\Run|RunOnce|Winlogon|Services")
| table _time, host, User, EventType, TargetObject, Details

# [19] DLL 사이드로딩 탐지
index=sysmon EventCode=7
| where NOT match(ImageLoaded, "(?i)\\\\Windows\\\\")
| where match(ImageLoaded, "(?i)\\\\Temp\\\\|\\\\AppData\\\\|\\\\Public\\\\")
| table _time, host, Image, ImageLoaded, Signed

# [20] UAC 우회 탐지
index=sysmon EventCode=1
| where match(CommandLine, "(?i)fodhelper|eventvwr|sdclt|slui|compmgmt")
| where IntegrityLevel="High" AND match(ParentIntegrityLevel, "Medium")
| table _time, host, User, Image, CommandLine, IntegrityLevel
```

---

## 3. 대시보드 구성

### SOC 운영 대시보드 XML

```xml
<dashboard>
  <label>SOC 실시간 모니터링</label>
  
  <!-- 패널 1: 실시간 알림 카운트 -->
  <row>
    <panel>
      <title>심각도별 알림 (최근 24시간)</title>
      <chart>
        <search>
          <query>
            index=alerts
            | stats count by severity
            | sort severity
          </query>
          <earliest>-24h</earliest>
        </search>
        <option name="charting.chart">pie</option>
      </chart>
    </panel>
    
    <!-- 패널 2: 로그인 실패 현황 -->
    <panel>
      <title>로그인 실패 Top 10 IP</title>
      <table>
        <search>
          <query>
            index=security EventCode=4625
            | stats count by src_ip
            | sort -count
            | head 10
          </query>
          <earliest>-1h</earliest>
        </search>
      </table>
    </panel>
  </row>
  
  <!-- 패널 3: 실시간 이벤트 스트림 -->
  <row>
    <panel>
      <title>실시간 보안 이벤트</title>
      <event>
        <search>
          <query>
            index=security (EventCode=4624 OR EventCode=4625 OR EventCode=4688)
            | table _time, host, user, EventCode, src_ip, Process_Name
          </query>
          <earliest>-15m</earliest>
          <refresh>30s</refresh>
        </search>
      </event>
    </panel>
  </row>
</dashboard>
```

---

## 4. Splunk 알림 설정

### 실시간 알림 설정

```spl
# 알림 쿼리: 랜섬웨어 행위 탐지
index=sysmon EventCode=1
| where match(CommandLine, 
  "(?i)vssadmin delete shadows|wbadmin delete|bcdedit.*/set")
| table _time, host, User, CommandLine

# 알림 설정:
# - 트리거: 결과 1개 이상
# - 빈도: 1분마다
# - 심각도: Critical
# - 알림: 이메일 + PagerDuty + Slack
```

### 알림 억제 (FP 감소)

```spl
# 정상 작업 제외
index=sysmon EventCode=1
| where match(CommandLine, "(?i)vssadmin delete")
| where NOT host IN ("BACKUP01", "BACKUP02")  # 백업 서버 제외
| where NOT user IN ("svc_backup", "admin_backup")
```

---

## 5. IBM QRadar 핵심 쿼리 (AQL)

### AQL (Ariel Query Language) 기초

```sql
-- 로그인 실패 조회
SELECT sourceIP, username, count(*) as FailCount
FROM events
WHERE QIDNAME(qid) = 'User Login Failed'
  AND starttime > '2024-01-01 00:00:00'
GROUP BY sourceIP, username
HAVING count(*) > 10
ORDER BY FailCount DESC
LAST 24 HOURS

-- 이상 트래픽 탐지
SELECT sourceIP, destinationIP, sum(magnitude) as TotalMag
FROM flows
WHERE destinationPort NOT IN (80, 443, 53)
  AND sourceIP INCIDR '10.0.0.0/8'
  AND NOT destinationIP INCIDR '10.0.0.0/8'
GROUP BY sourceIP, destinationIP
HAVING sum(bytes) > 100000000
ORDER BY TotalMag DESC
LAST 1 HOURS

-- 오펜스(Offense) 조회
SELECT id, description, starttime, magnitude, status
FROM offenses
WHERE status = 'OPEN' AND magnitude > 7
ORDER BY magnitude DESC
```

---

## 6. ELK Stack (Elastic SIEM)

### Kibana KQL (Kibana Query Language)

```kql
# 이벤트 ID 필터
event.code: "4625"

# AND 조건
event.code: "4624" AND winlog.logon.type: "RemoteInteractive"

# 범위 쿼리
winlog.event_data.FailureCount >= 10

# 와일드카드
process.command_line: *powershell* AND process.command_line: *-enc*

# 필드 존재 확인
_exists_: user.name AND NOT user.name: "SYSTEM"
```

### Elastic Detection Rule (YAML)

```yaml
name: PowerShell Encoded Command Execution
description: Detects PowerShell executing encoded commands
type: eql
language: eql
query: |
  process where event.type == "start"
    and process.name : ("powershell.exe", "pwsh.exe")
    and process.args : ("-enc", "-EncodedCommand", "-ec")

severity: high
risk_score: 73
tags:
  - Defense Evasion
  - Execution
references:
  - https://attack.mitre.org/techniques/T1059/001/
```

---

## 7. 로그 파싱 및 정규화

### Logstash 파이프라인 설정

```ruby
# logstash.conf - Windows 이벤트 로그 처리
input {
  beats {
    port => 5044
    type => "winlogbeat"
  }
}

filter {
  if [type] == "winlogbeat" {
    # 이벤트 ID 파싱
    grok {
      match => { "message" => "%{TIMESTAMP_ISO8601:timestamp} %{WORD:level} %{NUMBER:event_id} %{GREEDYDATA:msg}" }
    }
    
    # IP 지오로케이션
    if [source.ip] {
      geoip {
        source => "source.ip"
        target => "source.geo"
      }
    }
    
    # 이벤트 ID 분류
    translate {
      field => "event_id"
      destination => "event_category"
      dictionary => {
        "4624" => "Authentication Success"
        "4625" => "Authentication Failure"
        "4688" => "Process Creation"
        "7045" => "Service Installation"
      }
    }
  }
}

output {
  elasticsearch {
    hosts => ["localhost:9200"]
    index => "winlog-%{+YYYY.MM.dd}"
  }
}
```

---

## 8. 자동화 대응 (SOAR)

### Shuffle SOAR 워크플로우 예시

```python
#!/usr/bin/env python3
"""
SOAR 자동화 대응 스크립트 — SIEM 알림 수신 → IP 차단 → TheHive 케이스 생성
사용: python3 soar_response.py --ip 1.2.3.4 --reason "Brute force detected" --firewall-url https://fw.corp --thehive-url https://thehive.corp
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logging.basicConfig(
    format="%(asctime)s [%(levelname)s] %(message)s",
    level=logging.INFO,
)
log = logging.getLogger(__name__)


class Severity(int, Enum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


@dataclass
class SOARAction:
    ip: str
    reason: str
    severity: Severity = Severity.MEDIUM
    duration_seconds: int = 3600
    tags: list[str] | None = None


# ------------------------------------------------------------------ #
#  HTTP 클라이언트 (재시도 포함)
# ------------------------------------------------------------------ #
def make_session(retries: int = 3, backoff: float = 0.5) -> requests.Session:
    session = requests.Session()
    retry = Retry(
        total=retries,
        backoff_factor=backoff,
        status_forcelist=[429, 500, 502, 503, 504],
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session


# ------------------------------------------------------------------ #
#  방화벽 차단 (Palo Alto REST API 모델)
# ------------------------------------------------------------------ #
class FirewallClient:
    def __init__(self, base_url: str, api_key: str, verify_ssl: bool = True) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.verify_ssl = verify_ssl
        self._session = make_session()

    def block_ip(self, action: SOARAction) -> bool:
        payload = {
            "ip": action.ip,
            "action": "block",
            "duration": action.duration_seconds,
            "reason": action.reason,
            "severity": action.severity.name,
        }
        try:
            resp = self._session.post(
                f"{self.base_url}/api/v1/block",
                json=payload,
                headers={"X-API-Key": self.api_key},
                timeout=10,
                verify=self.verify_ssl,
            )
            resp.raise_for_status()
            log.info("[FW] IP 차단 성공: %s (기간: %ds)", action.ip, action.duration_seconds)
            return True
        except requests.RequestException as exc:
            log.error("[FW] IP 차단 실패: %s — %s", action.ip, exc)
            return False

    def unblock_ip(self, ip: str) -> bool:
        try:
            resp = self._session.delete(
                f"{self.base_url}/api/v1/block/{ip}",
                headers={"X-API-Key": self.api_key},
                timeout=10,
                verify=self.verify_ssl,
            )
            resp.raise_for_status()
            log.info("[FW] IP 차단 해제: %s", ip)
            return True
        except requests.RequestException as exc:
            log.error("[FW] 차단 해제 실패: %s", exc)
            return False


# ------------------------------------------------------------------ #
#  TheHive 케이스 생성
# ------------------------------------------------------------------ #
class TheHiveClient:
    def __init__(self, base_url: str, api_key: str, verify_ssl: bool = True) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.verify_ssl = verify_ssl
        self._session = make_session()
        self._headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }

    def create_alert(self, action: SOARAction) -> Optional[str]:
        """TheHive v4 알림 생성, 성공 시 alert ID 반환"""
        alert = {
            "title": f"[자동차단] 악성 IP: {action.ip}",
            "type": "malicious_ip",
            "source": "SIEM-SOAR",
            "sourceRef": f"soar-{action.ip}-{int(datetime.now().timestamp())}",
            "severity": action.severity.value,
            "date": int(datetime.now(timezone.utc).timestamp() * 1000),
            "description": (
                f"SIEM 자동 탐지에 의해 차단된 IP\n\n"
                f"**IP:** {action.ip}\n"
                f"**사유:** {action.reason}\n"
                f"**차단 기간:** {action.duration_seconds // 60}분\n"
                f"**심각도:** {action.severity.name}"
            ),
            "tags": (action.tags or []) + ["auto-block", "soar"],
            "observables": [
                {
                    "dataType": "ip",
                    "data": action.ip,
                    "message": action.reason,
                    "tlp": 2,
                    "ioc": True,
                    "tags": ["malicious"],
                }
            ],
        }

        try:
            resp = self._session.post(
                f"{self.base_url}/api/alert",
                json=alert,
                headers=self._headers,
                timeout=10,
                verify=self.verify_ssl,
            )
            resp.raise_for_status()
            alert_id = resp.json().get("id", "")
            log.info("[TheHive] 알림 생성: %s (ID: %s)", action.ip, alert_id)
            return alert_id
        except requests.RequestException as exc:
            log.error("[TheHive] 알림 생성 실패: %s", exc)
            return None


# ------------------------------------------------------------------ #
#  SOAR 오케스트레이터
# ------------------------------------------------------------------ #
class SOAROrchestrator:
    def __init__(
        self,
        firewall: Optional[FirewallClient] = None,
        thehive: Optional[TheHiveClient] = None,
    ) -> None:
        self.firewall = firewall
        self.thehive = thehive

    def respond(self, action: SOARAction) -> dict:
        results: dict = {"ip": action.ip, "actions": []}

        if self.firewall:
            fw_ok = self.firewall.block_ip(action)
            results["actions"].append({
                "component": "firewall",
                "success": fw_ok,
                "detail": f"차단 {'성공' if fw_ok else '실패'}: {action.ip}",
            })

        if self.thehive:
            alert_id = self.thehive.create_alert(action)
            results["actions"].append({
                "component": "thehive",
                "success": alert_id is not None,
                "alert_id": alert_id,
            })

        results["overall_success"] = all(a["success"] for a in results["actions"])
        return results


# ------------------------------------------------------------------ #
#  CLI
# ------------------------------------------------------------------ #
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="SOAR 자동화 대응 — IP 차단 + TheHive 케이스 생성",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="예시:\n"
               "  python3 soar_response.py --ip 1.2.3.4 --reason 'Brute force'\n"
               "  python3 soar_response.py --ip 1.2.3.4 --severity HIGH "
               "--firewall-url https://fw.corp --thehive-url https://thehive.corp",
    )
    parser.add_argument("--ip", required=True, help="차단할 IP 주소")
    parser.add_argument("--reason", required=True, help="차단 사유")
    parser.add_argument(
        "--severity",
        choices=[s.name for s in Severity],
        default="MEDIUM",
        help="심각도 (기본: MEDIUM)",
    )
    parser.add_argument(
        "--duration",
        type=int,
        default=3600,
        metavar="SECONDS",
        help="차단 지속 시간(초, 기본: 3600)",
    )
    parser.add_argument("--tags", nargs="*", default=[], help="추가 태그")
    parser.add_argument("--firewall-url", metavar="URL", help="방화벽 API URL")
    parser.add_argument("--firewall-key", metavar="KEY", help="방화벽 API 키")
    parser.add_argument("--thehive-url", metavar="URL", help="TheHive URL")
    parser.add_argument("--thehive-key", metavar="KEY", help="TheHive API 키")
    parser.add_argument("--no-verify-ssl", action="store_true")
    parser.add_argument("--json", action="store_true", help="결과를 JSON으로 출력")
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    action = SOARAction(
        ip=args.ip,
        reason=args.reason,
        severity=Severity[args.severity],
        duration_seconds=args.duration,
        tags=args.tags,
    )

    verify = not args.no_verify_ssl
    fw_client = None
    hive_client = None

    if args.firewall_url:
        if not args.firewall_key:
            parser.error("--firewall-url 사용 시 --firewall-key 필요")
        fw_client = FirewallClient(args.firewall_url, args.firewall_key, verify)

    if args.thehive_url:
        if not args.thehive_key:
            parser.error("--thehive-url 사용 시 --thehive-key 필요")
        hive_client = TheHiveClient(args.thehive_url, args.thehive_key, verify)

    if not fw_client and not hive_client:
        parser.error("--firewall-url 또는 --thehive-url 중 하나 이상 지정 필요")

    orchestrator = SOAROrchestrator(firewall=fw_client, thehive=hive_client)
    results = orchestrator.respond(action)

    if args.json:
        print(json.dumps(results, ensure_ascii=False, indent=2))
    else:
        status = "성공" if results["overall_success"] else "일부 실패"
        print(f"\n[SOAR 대응 결과: {status}]")
        for act in results["actions"]:
            icon = "+" if act["success"] else "-"
            print(f"  [{icon}] {act['component']}: {act.get('detail', act.get('alert_id', ''))}")


if __name__ == "__main__":
    main()
```

---

## 9. 위협 헌팅 쿼리

```spl
# 헌팅: 비정상 시간대 관리도구 실행
index=sysmon EventCode=1
| where match(Image, "(?i)psexec|mimikatz|procdump|wce|secretsdump")
| table _time, host, User, Image, CommandLine

# 헌팅: DNS Tunneling
index=dns
| eval subdomain_parts = split(query, ".")
| eval subdomain_length = len(mvindex(subdomain_parts, 0))
| where subdomain_length > 30  # 비정상적으로 긴 서브도메인
| stats count by query, src_ip
| where count < 5  # 새로운/드문 도메인

# 헌팅: WMI 지속성
index=sysmon EventCode=20 OR EventCode=21 OR EventCode=22
| table _time, host, User, EventType, Consumer, Filter, Operation

# 헌팅: 이상 트래픽 패턴 (비콘 탐지)
index=network
| bucket _time span=1m
| stats count by _time, src_ip, dest_ip, dest_port
| streamstats window=60 avg(count) as AvgCount stdev(count) as StdDev
  by src_ip, dest_ip, dest_port
| where abs(count - AvgCount) < StdDev * 0.5  # 매우 일정한 트래픽 = 비콘
| table src_ip, dest_ip, dest_port, AvgCount, StdDev
```
