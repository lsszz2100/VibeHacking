> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# Active Directory 방어 및 탐지

AD 공격(Pass-the-Hash, Kerberoasting, DCSync, BloodHound 경로 악용)을 탐지하는 방법과 계층적 방어 전략을 다룬다. SIEM 쿼리, 허니팟 계정, 탐지 룰을 중심으로 정리한다.

---

## 1. AD 핵심 탐지 이벤트

### 1.1 Windows 이벤트 ID 매핑

| 이벤트 ID | 설명 | 관련 공격 |
|---------|------|---------|
| 4624 | 로그온 성공 | Pass-the-Hash (LogonType 3) |
| 4625 | 로그온 실패 | 패스워드 스프레이, 브루트포스 |
| 4648 | 명시적 자격증명 로그온 | Overpass-the-Hash |
| 4662 | AD 객체 접근 | DCSync (DS-Replication-Get-Changes) |
| 4672 | 특수 권한 로그온 | 관리자 로그온 |
| 4720 | 계정 생성 | 백도어 계정 |
| 4728/4732 | 보안 그룹 멤버 추가 | 권한 상승 |
| 4769 | Kerberos 서비스 티켓 요청 | Kerberoasting |
| 4771 | Kerberos 사전 인증 실패 | AS-REP Roasting |
| 4776 | NTLM 인증 시도 | Pass-the-Hash |
| 7045 | 새 서비스 설치 | 지속성 설정 |

---

## 2. 자동화 탐지 시스템

### 2.1 이벤트 로그 기반 실시간 탐지

```python
#!/usr/bin/env python3
"""Windows 이벤트 로그 기반 AD 공격 탐지 (Elasticsearch/Python)"""
import argparse
import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Optional

from elasticsearch import Elasticsearch


@dataclass
class ADThreatRule:
    rule_id: str
    name: str
    severity: str
    event_ids: list[int]
    conditions: dict
    description: str
    mitre: str


AD_THREAT_RULES: list[ADThreatRule] = [
    ADThreatRule(
        "AD-001", "Kerberoasting 탐지",
        "High",
        [4769],
        {
            "TicketEncryptionType": "0x17",  # RC4-HMAC
            "ServiceName|not": ["krbtgt", "$"],  # 컴퓨터 계정 제외
        },
        "RC4 암호화 Kerberos 서비스 티켓 대량 요청",
        "T1558.003",
    ),
    ADThreatRule(
        "AD-002", "DCSync 탐지",
        "Critical",
        [4662],
        {
            "ObjectType": "19195a5b-6da0-11d0-afd3-00c04fd930c9",  # Domain NC
            "AccessMask": "0x100",  # DS-Replication-Get-Changes
        },
        "DC 복제 권한 사용 (DCSync 공격)",
        "T1003.006",
    ),
    ADThreatRule(
        "AD-003", "Pass-the-Hash 탐지",
        "High",
        [4624],
        {
            "LogonType": "3",
            "LogonProcessName": "NtLmSsp",
            "AuthenticationPackageName": "NTLM",
        },
        "NTLMv2 Pass-the-Hash 의심",
        "T1550.002",
    ),
    ADThreatRule(
        "AD-004", "관리자 그룹 변경",
        "Critical",
        [4728, 4732],
        {
            "GroupName": ["Domain Admins", "Enterprise Admins", "Schema Admins"],
        },
        "고권한 그룹 멤버십 변경",
        "T1098",
    ),
    ADThreatRule(
        "AD-005", "AS-REP Roasting",
        "High",
        [4771],
        {
            "PreAuthType": "0",  # 사전 인증 없음
        },
        "Kerberos 사전 인증 비활성화 계정 탐지",
        "T1558.004",
    ),
    ADThreatRule(
        "AD-006", "골든 티켓 의심",
        "Critical",
        [4624, 4634],
        {
            "LogonType": "3",
            "TicketLifetime|gt": 600,  # 비정상적으로 긴 티켓
        },
        "krbtgt 해시로 생성된 골든 티켓 의심",
        "T1558.001",
    ),
]


class ADThreatDetector:
    def __init__(self, es_host: str = "localhost", es_port: int = 9200) -> None:
        self.es = Elasticsearch(f"http://{es_host}:{es_port}")

    def search_events(
        self,
        event_ids: list[int],
        time_window_minutes: int = 60,
        conditions: Optional[dict] = None,
    ) -> list[dict]:
        now = datetime.now(timezone.utc)
        start = now - timedelta(minutes=time_window_minutes)

        query = {
            "bool": {
                "must": [
                    {"terms": {"EventID": event_ids}},
                    {"range": {"@timestamp": {"gte": start.isoformat(), "lte": now.isoformat()}}},
                ]
            }
        }

        if conditions:
            for field_name, value in conditions.items():
                if "|not" in field_name:
                    actual_field = field_name.replace("|not", "")
                    query["bool"].setdefault("must_not", []).append(
                        {"terms": {actual_field: value if isinstance(value, list) else [value]}}
                    )
                elif "|gt" in field_name:
                    actual_field = field_name.replace("|gt", "")
                    query["bool"]["must"].append({"range": {actual_field: {"gt": value}}})
                else:
                    query["bool"]["must"].append(
                        {"terms": {field_name: value if isinstance(value, list) else [value]}}
                    )

        result = self.es.search(
            index="winlogbeat-*",
            body={"query": query, "size": 100, "sort": [{"@timestamp": "desc"}]},
        )
        return [hit["_source"] for hit in result["hits"]["hits"]]

    def run_detection(self, time_window: int = 60) -> list[dict]:
        findings = []

        for rule in AD_THREAT_RULES:
            events = self.search_events(rule.event_ids, time_window, rule.conditions)

            # Kerberoasting: 짧은 시간 내 다수 요청
            if rule.rule_id == "AD-001" and len(events) > 5:
                findings.append({
                    "rule": rule.rule_id,
                    "name": rule.name,
                    "severity": rule.severity,
                    "count": len(events),
                    "mitre": rule.mitre,
                    "description": f"{len(events)}개 RC4 서비스 티켓 요청 감지",
                })

            elif rule.rule_id != "AD-001" and events:
                for event in events[:3]:
                    findings.append({
                        "rule": rule.rule_id,
                        "name": rule.name,
                        "severity": rule.severity,
                        "event": event,
                        "mitre": rule.mitre,
                    })

        return findings


def main() -> None:
    parser = argparse.ArgumentParser(description="AD 위협 탐지")
    parser.add_argument("--es-host", default="localhost")
    parser.add_argument("--es-port", type=int, default=9200)
    parser.add_argument("--window", type=int, default=60, help="탐지 시간 윈도우(분)")
    args = parser.parse_args()

    detector = ADThreatDetector(args.es_host, args.es_port)
    findings = detector.run_detection(args.window)

    if findings:
        print(f"[!!!] AD 위협 {len(findings)}건 탐지")
        for f in findings:
            print(f"  [{f['severity']}] {f['name']} ({f['mitre']}): {f.get('description', '')}")
    else:
        print("[*] 탐지된 위협 없음")


if __name__ == "__main__":
    main()
```

---

## 3. 허니팟 계정 (Canary Account)

### 3.1 허니팟 계정 설정 및 모니터링

```python
#!/usr/bin/env python3
"""AD 허니팟 계정 모니터링 — 접근 즉시 알림"""
import argparse
import smtplib
import subprocess
from dataclasses import dataclass
from datetime import datetime
from email.mime.text import MIMEText
from pathlib import Path
from typing import Optional


HONEYPOT_ACCOUNTS = [
    "svc_admin",      # 서비스 계정처럼 보이는 이름
    "backup_admin",   # 백업 관리자
    "helpdesk",       # 헬프데스크
    "sql_svc",        # SQL 서비스 계정
]


@dataclass
class HoneypotAlert:
    account: str
    source_ip: str
    timestamp: str
    event_type: str


def parse_security_log(log_path: Optional[Path] = None) -> list[HoneypotAlert]:
    alerts = []

    if log_path and log_path.exists():
        content = log_path.read_text()
    else:
        try:
            output = subprocess.check_output(
                ["wevtutil", "qe", "Security",
                 "/q:*[System[EventID=4624 or EventID=4625 or EventID=4769]]",
                 "/f:text", "/c:100"],
                text=True,
                shell=True,
            )
            content = output
        except Exception:
            return []

    for account in HONEYPOT_ACCOUNTS:
        if account.lower() in content.lower():
            alerts.append(HoneypotAlert(
                account=account,
                source_ip="unknown",
                timestamp=datetime.now().isoformat(),
                event_type="접근 시도",
            ))

    return alerts


def send_alert(alert: HoneypotAlert, smtp_host: str, smtp_to: str) -> None:
    msg = MIMEText(
        f"허니팟 계정 접근 탐지!\n\n"
        f"계정: {alert.account}\n"
        f"소스 IP: {alert.source_ip}\n"
        f"시간: {alert.timestamp}\n"
        f"이벤트: {alert.event_type}\n\n"
        f"즉시 조사 필요"
    )
    msg["Subject"] = f"[보안 경보] 허니팟 계정 접근: {alert.account}"
    msg["From"] = "security@company.com"
    msg["To"] = smtp_to

    try:
        with smtplib.SMTP(smtp_host) as server:
            server.send_message(msg)
        print(f"[+] 알림 발송: {smtp_to}")
    except Exception as e:
        print(f"[-] 알림 발송 실패: {e}")


def setup_honeypot_accounts(domain: str) -> None:
    """PowerShell로 허니팟 계정 생성 (관리자 실행 필요)"""
    for account in HONEYPOT_ACCOUNTS:
        ps_cmd = f"""
Import-Module ActiveDirectory
$SecurePassword = ConvertTo-SecureString "HoneyPot!@#2024NoAccess" -AsPlainText -Force
New-ADUser -Name "{account}" `
    -SamAccountName "{account}" `
    -UserPrincipalName "{account}@{domain}" `
    -AccountPassword $SecurePassword `
    -PasswordNeverExpires $true `
    -Description "Legacy service account - do not use" `
    -Enabled $true

# Kerberoasting 유도 (SPN 설정)
Set-ADUser "{account}" -ServicePrincipalNames @{{Add="MSSQLSvc/{account}.{domain}:1433"}}

# 감사 정책 활성화 (이 계정 접근 시 이벤트 생성)
Set-ADUser "{account}" -Add @{{'msDS-SupportedEncryptionTypes'=28}}
"""
        print(f"[*] 허니팟 계정 설정 명령:")
        print(ps_cmd[:200])


def main() -> None:
    parser = argparse.ArgumentParser(description="허니팟 계정 모니터링")
    parser.add_argument("--setup", action="store_true", help="허니팟 계정 생성")
    parser.add_argument("--domain", help="AD 도메인명")
    parser.add_argument("--smtp", help="SMTP 서버")
    parser.add_argument("--alert-to", help="알림 이메일")
    args = parser.parse_args()

    if args.setup and args.domain:
        setup_honeypot_accounts(args.domain)
    else:
        alerts = parse_security_log()
        if alerts:
            print(f"[!!!] {len(alerts)}개 허니팟 접근 탐지!")
            for alert in alerts:
                print(f"  [{alert.account}] {alert.event_type} @ {alert.timestamp}")
                if args.smtp and args.alert_to:
                    send_alert(alert, args.smtp, args.alert_to)
        else:
            print("[*] 허니팟 접근 없음")


if __name__ == "__main__":
    main()
```

---

## 4. AD Tier 모델 방어

### 4.1 3-Tier 관리 모델

```
Tier 0 (도메인 컨트롤러):
  - 도메인 관리자, krbtgt
  - 전용 PAW(Privileged Access Workstation)에서만 접근
  - 인터넷 연결 없는 격리 환경

Tier 1 (서버):
  - 서버 관리자, 서비스 계정
  - Tier 1 전용 관리 서버 경유
  - Tier 0 자격증명으로 로그인 금지

Tier 2 (워크스테이션/사용자):
  - 일반 사용자, 헬프데스크
  - 인터넷 접근 허용
  - Tier 0/1 리소스 직접 접근 금지
```

```python
#!/usr/bin/env python3
"""AD Tier 모델 위반 탐지"""
import argparse


TIER_MAPPING = {
    "tier0": ["CORP\\Domain Admins", "CORP\\Enterprise Admins", "CORP\\Schema Admins",
               "CORP\\krbtgt", "dc01$", "dc02$"],
    "tier1": ["CORP\\Server Admins", "CORP\\svc_sql", "CORP\\svc_iis",
               "srv01$", "srv02$"],
    "tier2": ["CORP\\Domain Users", "CORP\\helpdesk"],
}


def detect_tier_violation(
    account: str,
    source_computer: str,
    target_computer: str,
) -> list[str]:
    findings = []

    account_tier = None
    for tier, members in TIER_MAPPING.items():
        if any(m.lower() in account.lower() for m in members):
            account_tier = tier
            break

    target_tier = None
    for tier, members in TIER_MAPPING.items():
        if any(m.lower() in target_computer.lower() for m in members):
            target_tier = tier
            break

    if account_tier and target_tier:
        tier_order = {"tier0": 0, "tier1": 1, "tier2": 2}
        if tier_order.get(account_tier, 2) > tier_order.get(target_tier, 2):
            findings.append(
                f"Tier 위반: {account_tier} 계정 ({account})이 "
                f"{target_tier} 리소스 ({target_computer}) 접근"
            )

    return findings


def main() -> None:
    parser = argparse.ArgumentParser(description="AD Tier 위반 탐지")
    parser.add_argument("--account", required=True)
    parser.add_argument("--source", required=True)
    parser.add_argument("--target", required=True)
    args = parser.parse_args()

    findings = detect_tier_violation(args.account, args.source, args.target)
    for f in findings:
        print(f"[!] {f}")
    if not findings:
        print("[*] Tier 위반 없음")


if __name__ == "__main__":
    main()
```

---

## 5. AD 강화 설정 자동화

### 5.1 PowerShell 강화 스크립트

```powershell
# AD 보안 강화 — 주요 설정

# 1. krbtgt 계정 패스워드 주기적 변경 (연 2회 이상)
# 자동화 스크립트
$krbtgt = Get-ADUser krbtgt
$NewPassword = [System.Web.Security.Membership]::GeneratePassword(64, 10)
Set-ADAccountPassword -Identity krbtgt -Reset -NewPassword (ConvertTo-SecureString $NewPassword -AsPlainText -Force)
Write-Host "[+] krbtgt 패스워드 변경 완료"

# 2. 사용하지 않는 계정 비활성화 (90일 미사용)
$Inactive = Search-ADAccount -AccountInactive -TimeSpan 90 -UsersOnly
foreach ($user in $Inactive) {
    Disable-ADAccount -Identity $user
    Write-Host "[+] 비활성화: $($user.SamAccountName)"
}

# 3. AdminSDHolder 보호 대상 확인
Get-ADUser -Filter {AdminCount -eq 1} | Select-Object SamAccountName, Enabled

# 4. Kerberos 위임 제한
# 무제한 위임 계정 찾기
Get-ADComputer -Filter {TrustedForDelegation -eq $True} | Select-Object Name
Get-ADUser -Filter {TrustedForDelegation -eq $True} | Select-Object SamAccountName

# 5. LDAP 서명 강제
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" `
    -Name "LDAPServerIntegrity" -Value 2 -Type DWord

# 6. SMB 서명 강제
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" `
    -Name "RequireSecuritySignature" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" `
    -Name "RequireSecuritySignature" -Value 1 -Type DWord
```

---

## 6. BloodHound 공격 경로 방어

```python
#!/usr/bin/env python3
"""BloodHound JSON 데이터 분석 — 위험 경로 자동 탐지"""
import argparse
import json
from pathlib import Path


def analyze_bloodhound_data(data_dir: Path) -> list[dict]:
    risks = []

    for json_file in data_dir.glob("*.json"):
        with json_file.open() as f:
            data = json.load(f)

        # 도메인 관리자로의 직접 경로 확인
        for node_type in ["users", "computers", "groups"]:
            for item in data.get(node_type, []):
                props = item.get("Properties", {})
                aces = item.get("Aces", [])

                for ace in aces:
                    if "Domain Admins" in ace.get("PrincipalSID", ""):
                        right = ace.get("RightName", "")
                        if right in ("GenericAll", "WriteDacl", "WriteOwner", "GenericWrite"):
                            risks.append({
                                "type": "직접 DA 경로",
                                "source": props.get("name", ""),
                                "right": right,
                                "severity": "Critical",
                            })

                # AS-REP Roasting 대상
                if props.get("dontreqpreauth"):
                    risks.append({
                        "type": "AS-REP Roasting 대상 계정",
                        "source": props.get("name", ""),
                        "severity": "High",
                    })

                # Kerberoasting 대상 (SPN 있는 계정)
                if props.get("hasspn") and not props.get("name", "").endswith("$"):
                    risks.append({
                        "type": "Kerberoasting 대상 계정",
                        "source": props.get("name", ""),
                        "severity": "Medium",
                    })

    return risks


def main() -> None:
    parser = argparse.ArgumentParser(description="BloodHound 데이터 위험 분석")
    parser.add_argument("data_dir", help="BloodHound JSON 파일 디렉터리")
    args = parser.parse_args()

    risks = analyze_bloodhound_data(Path(args.data_dir))
    print(f"[+] 발견된 위험: {len(risks)}개")

    for risk in sorted(risks, key=lambda r: {"Critical": 0, "High": 1, "Medium": 2}.get(r["severity"], 3)):
        print(f"  [{risk['severity']}] {risk['type']}: {risk['source']}")


if __name__ == "__main__":
    main()
```

---

<a name="english"></a>

# Active Directory Defense and Detection

This section covers how to detect AD attacks (Pass-the-Hash, Kerberoasting, DCSync, BloodHound path abuse) and layered defense strategies. Focused on SIEM queries, honeypot accounts, and detection rules.

---

## 1. Core AD Detection Events

### 1.1 Windows Event ID Mapping

| Event ID  | Description                        | Related Attack                              |
|-----------|------------------------------------|---------------------------------------------|
| 4624      | Logon success                      | Pass-the-Hash (LogonType 3)                 |
| 4625      | Logon failure                      | Password spray, brute force                 |
| 4648      | Explicit credential logon          | Overpass-the-Hash                           |
| 4662      | AD object access                   | DCSync (DS-Replication-Get-Changes)         |
| 4672      | Special privilege logon            | Administrator logon                         |
| 4720      | Account created                    | Backdoor account                            |
| 4728/4732 | Security group member added        | Privilege escalation                        |
| 4769      | Kerberos service ticket request    | Kerberoasting                               |
| 4771      | Kerberos pre-authentication failed | AS-REP Roasting                             |
| 4776      | NTLM authentication attempt        | Pass-the-Hash                               |
| 7045      | New service installed              | Persistence establishment                   |

---

## 2. Automated Detection System

### 2.1 Real-Time Detection Based on Event Logs

```python
#!/usr/bin/env python3
"""AD attack detection based on Windows Event Logs (Elasticsearch/Python)"""
import argparse
import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Optional

from elasticsearch import Elasticsearch


@dataclass
class ADThreatRule:
    rule_id: str
    name: str
    severity: str
    event_ids: list[int]
    conditions: dict
    description: str
    mitre: str


AD_THREAT_RULES: list[ADThreatRule] = [
    ADThreatRule(
        "AD-001", "Kerberoasting Detection",
        "High",
        [4769],
        {
            "TicketEncryptionType": "0x17",  # RC4-HMAC
            "ServiceName|not": ["krbtgt", "$"],  # Exclude computer accounts
        },
        "Bulk request of RC4-encrypted Kerberos service tickets",
        "T1558.003",
    ),
    ADThreatRule(
        "AD-002", "DCSync Detection",
        "Critical",
        [4662],
        {
            "ObjectType": "19195a5b-6da0-11d0-afd3-00c04fd930c9",  # Domain NC
            "AccessMask": "0x100",  # DS-Replication-Get-Changes
        },
        "Use of DC replication rights (DCSync attack)",
        "T1003.006",
    ),
    ADThreatRule(
        "AD-003", "Pass-the-Hash Detection",
        "High",
        [4624],
        {
            "LogonType": "3",
            "LogonProcessName": "NtLmSsp",
            "AuthenticationPackageName": "NTLM",
        },
        "Suspected NTLMv2 Pass-the-Hash",
        "T1550.002",
    ),
    ADThreatRule(
        "AD-004", "Admin Group Modification",
        "Critical",
        [4728, 4732],
        {
            "GroupName": ["Domain Admins", "Enterprise Admins", "Schema Admins"],
        },
        "High-privilege group membership changed",
        "T1098",
    ),
    ADThreatRule(
        "AD-005", "AS-REP Roasting",
        "High",
        [4771],
        {
            "PreAuthType": "0",  # No pre-authentication
        },
        "Detection of accounts with Kerberos pre-auth disabled",
        "T1558.004",
    ),
    ADThreatRule(
        "AD-006", "Golden Ticket Suspected",
        "Critical",
        [4624, 4634],
        {
            "LogonType": "3",
            "TicketLifetime|gt": 600,  # Abnormally long ticket
        },
        "Suspected golden ticket created with krbtgt hash",
        "T1558.001",
    ),
]


class ADThreatDetector:
    def __init__(self, es_host: str = "localhost", es_port: int = 9200) -> None:
        self.es = Elasticsearch(f"http://{es_host}:{es_port}")

    def search_events(
        self,
        event_ids: list[int],
        time_window_minutes: int = 60,
        conditions: Optional[dict] = None,
    ) -> list[dict]:
        now = datetime.now(timezone.utc)
        start = now - timedelta(minutes=time_window_minutes)

        query = {
            "bool": {
                "must": [
                    {"terms": {"EventID": event_ids}},
                    {"range": {"@timestamp": {"gte": start.isoformat(), "lte": now.isoformat()}}},
                ]
            }
        }

        if conditions:
            for field_name, value in conditions.items():
                if "|not" in field_name:
                    actual_field = field_name.replace("|not", "")
                    query["bool"].setdefault("must_not", []).append(
                        {"terms": {actual_field: value if isinstance(value, list) else [value]}}
                    )
                elif "|gt" in field_name:
                    actual_field = field_name.replace("|gt", "")
                    query["bool"]["must"].append({"range": {actual_field: {"gt": value}}})
                else:
                    query["bool"]["must"].append(
                        {"terms": {field_name: value if isinstance(value, list) else [value]}}
                    )

        result = self.es.search(
            index="winlogbeat-*",
            body={"query": query, "size": 100, "sort": [{"@timestamp": "desc"}]},
        )
        return [hit["_source"] for hit in result["hits"]["hits"]]

    def run_detection(self, time_window: int = 60) -> list[dict]:
        findings = []

        for rule in AD_THREAT_RULES:
            events = self.search_events(rule.event_ids, time_window, rule.conditions)

            # Kerberoasting: multiple requests within a short time
            if rule.rule_id == "AD-001" and len(events) > 5:
                findings.append({
                    "rule": rule.rule_id,
                    "name": rule.name,
                    "severity": rule.severity,
                    "count": len(events),
                    "mitre": rule.mitre,
                    "description": f"Detected {len(events)} RC4 service ticket requests",
                })

            elif rule.rule_id != "AD-001" and events:
                for event in events[:3]:
                    findings.append({
                        "rule": rule.rule_id,
                        "name": rule.name,
                        "severity": rule.severity,
                        "event": event,
                        "mitre": rule.mitre,
                    })

        return findings


def main() -> None:
    parser = argparse.ArgumentParser(description="AD threat detection")
    parser.add_argument("--es-host", default="localhost")
    parser.add_argument("--es-port", type=int, default=9200)
    parser.add_argument("--window", type=int, default=60, help="Detection time window (minutes)")
    args = parser.parse_args()

    detector = ADThreatDetector(args.es_host, args.es_port)
    findings = detector.run_detection(args.window)

    if findings:
        print(f"[!!!] {len(findings)} AD threats detected")
        for f in findings:
            print(f"  [{f['severity']}] {f['name']} ({f['mitre']}): {f.get('description', '')}")
    else:
        print("[*] No threats detected")


if __name__ == "__main__":
    main()
```

---

## 3. Honeypot Accounts (Canary Accounts)

### 3.1 Honeypot Account Setup and Monitoring

```python
#!/usr/bin/env python3
"""AD honeypot account monitoring — immediate alert on access"""
import argparse
import smtplib
import subprocess
from dataclasses import dataclass
from datetime import datetime
from email.mime.text import MIMEText
from pathlib import Path
from typing import Optional


HONEYPOT_ACCOUNTS = [
    "svc_admin",      # Name that looks like a service account
    "backup_admin",   # Backup administrator
    "helpdesk",       # Help desk
    "sql_svc",        # SQL service account
]


@dataclass
class HoneypotAlert:
    account: str
    source_ip: str
    timestamp: str
    event_type: str


def parse_security_log(log_path: Optional[Path] = None) -> list[HoneypotAlert]:
    alerts = []

    if log_path and log_path.exists():
        content = log_path.read_text()
    else:
        try:
            output = subprocess.check_output(
                ["wevtutil", "qe", "Security",
                 "/q:*[System[EventID=4624 or EventID=4625 or EventID=4769]]",
                 "/f:text", "/c:100"],
                text=True,
                shell=True,
            )
            content = output
        except Exception:
            return []

    for account in HONEYPOT_ACCOUNTS:
        if account.lower() in content.lower():
            alerts.append(HoneypotAlert(
                account=account,
                source_ip="unknown",
                timestamp=datetime.now().isoformat(),
                event_type="Access attempt",
            ))

    return alerts


def send_alert(alert: HoneypotAlert, smtp_host: str, smtp_to: str) -> None:
    msg = MIMEText(
        f"Honeypot account access detected!\n\n"
        f"Account: {alert.account}\n"
        f"Source IP: {alert.source_ip}\n"
        f"Time: {alert.timestamp}\n"
        f"Event: {alert.event_type}\n\n"
        f"Immediate investigation required"
    )
    msg["Subject"] = f"[Security Alert] Honeypot account access: {alert.account}"
    msg["From"] = "security@company.com"
    msg["To"] = smtp_to

    try:
        with smtplib.SMTP(smtp_host) as server:
            server.send_message(msg)
        print(f"[+] Alert sent to: {smtp_to}")
    except Exception as e:
        print(f"[-] Failed to send alert: {e}")


def setup_honeypot_accounts(domain: str) -> None:
    """Create honeypot accounts with PowerShell (requires admin execution)"""
    for account in HONEYPOT_ACCOUNTS:
        ps_cmd = f"""
Import-Module ActiveDirectory
$SecurePassword = ConvertTo-SecureString "HoneyPot!@#2024NoAccess" -AsPlainText -Force
New-ADUser -Name "{account}" `
    -SamAccountName "{account}" `
    -UserPrincipalName "{account}@{domain}" `
    -AccountPassword $SecurePassword `
    -PasswordNeverExpires $true `
    -Description "Legacy service account - do not use" `
    -Enabled $true

# Induce Kerberoasting (set SPN)
Set-ADUser "{account}" -ServicePrincipalNames @{{Add="MSSQLSvc/{account}.{domain}:1433"}}

# Enable audit policy (generate event on access to this account)
Set-ADUser "{account}" -Add @{{'msDS-SupportedEncryptionTypes'=28}}
"""
        print(f"[*] Honeypot account setup command:")
        print(ps_cmd[:200])


def main() -> None:
    parser = argparse.ArgumentParser(description="Honeypot account monitoring")
    parser.add_argument("--setup", action="store_true", help="Create honeypot accounts")
    parser.add_argument("--domain", help="AD domain name")
    parser.add_argument("--smtp", help="SMTP server")
    parser.add_argument("--alert-to", help="Alert email address")
    args = parser.parse_args()

    if args.setup and args.domain:
        setup_honeypot_accounts(args.domain)
    else:
        alerts = parse_security_log()
        if alerts:
            print(f"[!!!] {len(alerts)} honeypot accesses detected!")
            for alert in alerts:
                print(f"  [{alert.account}] {alert.event_type} @ {alert.timestamp}")
                if args.smtp and args.alert_to:
                    send_alert(alert, args.smtp, args.alert_to)
        else:
            print("[*] No honeypot accesses")


if __name__ == "__main__":
    main()
```

---

## 4. AD Tier Model Defense

### 4.1 3-Tier Administration Model

```
Tier 0 (Domain Controllers):
  - Domain admins, krbtgt
  - Access only from dedicated PAW (Privileged Access Workstation)
  - Isolated environment with no internet connectivity

Tier 1 (Servers):
  - Server admins, service accounts
  - Access via dedicated Tier 1 management server
  - Prohibited from logging in with Tier 0 credentials

Tier 2 (Workstations/Users):
  - Regular users, helpdesk
  - Internet access permitted
  - Direct access to Tier 0/1 resources prohibited
```

```python
#!/usr/bin/env python3
"""AD Tier model violation detection"""
import argparse


TIER_MAPPING = {
    "tier0": ["CORP\\Domain Admins", "CORP\\Enterprise Admins", "CORP\\Schema Admins",
               "CORP\\krbtgt", "dc01$", "dc02$"],
    "tier1": ["CORP\\Server Admins", "CORP\\svc_sql", "CORP\\svc_iis",
               "srv01$", "srv02$"],
    "tier2": ["CORP\\Domain Users", "CORP\\helpdesk"],
}


def detect_tier_violation(
    account: str,
    source_computer: str,
    target_computer: str,
) -> list[str]:
    findings = []

    account_tier = None
    for tier, members in TIER_MAPPING.items():
        if any(m.lower() in account.lower() for m in members):
            account_tier = tier
            break

    target_tier = None
    for tier, members in TIER_MAPPING.items():
        if any(m.lower() in target_computer.lower() for m in members):
            target_tier = tier
            break

    if account_tier and target_tier:
        tier_order = {"tier0": 0, "tier1": 1, "tier2": 2}
        if tier_order.get(account_tier, 2) > tier_order.get(target_tier, 2):
            findings.append(
                f"Tier violation: {account_tier} account ({account}) "
                f"accessed {target_tier} resource ({target_computer})"
            )

    return findings


def main() -> None:
    parser = argparse.ArgumentParser(description="AD Tier violation detection")
    parser.add_argument("--account", required=True)
    parser.add_argument("--source", required=True)
    parser.add_argument("--target", required=True)
    args = parser.parse_args()

    findings = detect_tier_violation(args.account, args.source, args.target)
    for f in findings:
        print(f"[!] {f}")
    if not findings:
        print("[*] No tier violations")


if __name__ == "__main__":
    main()
```

---

## 5. AD Hardening Configuration Automation

### 5.1 PowerShell Hardening Script

```powershell
# AD security hardening — key settings

# 1. Periodic krbtgt account password change (at least twice a year)
# Automation script
$krbtgt = Get-ADUser krbtgt
$NewPassword = [System.Web.Security.Membership]::GeneratePassword(64, 10)
Set-ADAccountPassword -Identity krbtgt -Reset -NewPassword (ConvertTo-SecureString $NewPassword -AsPlainText -Force)
Write-Host "[+] krbtgt password changed successfully"

# 2. Disable unused accounts (inactive for 90 days)
$Inactive = Search-ADAccount -AccountInactive -TimeSpan 90 -UsersOnly
foreach ($user in $Inactive) {
    Disable-ADAccount -Identity $user
    Write-Host "[+] Disabled: $($user.SamAccountName)"
}

# 3. Check AdminSDHolder protected objects
Get-ADUser -Filter {AdminCount -eq 1} | Select-Object SamAccountName, Enabled

# 4. Restrict Kerberos delegation
# Find accounts with unconstrained delegation
Get-ADComputer -Filter {TrustedForDelegation -eq $True} | Select-Object Name
Get-ADUser -Filter {TrustedForDelegation -eq $True} | Select-Object SamAccountName

# 5. Enforce LDAP signing
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" `
    -Name "LDAPServerIntegrity" -Value 2 -Type DWord

# 6. Enforce SMB signing
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" `
    -Name "RequireSecuritySignature" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" `
    -Name "RequireSecuritySignature" -Value 1 -Type DWord
```

---

## 6. BloodHound Attack Path Defense

```python
#!/usr/bin/env python3
"""BloodHound JSON data analysis — automated detection of risky paths"""
import argparse
import json
from pathlib import Path


def analyze_bloodhound_data(data_dir: Path) -> list[dict]:
    risks = []

    for json_file in data_dir.glob("*.json"):
        with json_file.open() as f:
            data = json.load(f)

        # Check for direct paths to Domain Admins
        for node_type in ["users", "computers", "groups"]:
            for item in data.get(node_type, []):
                props = item.get("Properties", {})
                aces = item.get("Aces", [])

                for ace in aces:
                    if "Domain Admins" in ace.get("PrincipalSID", ""):
                        right = ace.get("RightName", "")
                        if right in ("GenericAll", "WriteDacl", "WriteOwner", "GenericWrite"):
                            risks.append({
                                "type": "Direct DA path",
                                "source": props.get("name", ""),
                                "right": right,
                                "severity": "Critical",
                            })

                # AS-REP Roasting targets
                if props.get("dontreqpreauth"):
                    risks.append({
                        "type": "AS-REP Roasting target account",
                        "source": props.get("name", ""),
                        "severity": "High",
                    })

                # Kerberoasting targets (accounts with SPN)
                if props.get("hasspn") and not props.get("name", "").endswith("$"):
                    risks.append({
                        "type": "Kerberoasting target account",
                        "source": props.get("name", ""),
                        "severity": "Medium",
                    })

    return risks


def main() -> None:
    parser = argparse.ArgumentParser(description="BloodHound data risk analysis")
    parser.add_argument("data_dir", help="Directory containing BloodHound JSON files")
    args = parser.parse_args()

    risks = analyze_bloodhound_data(Path(args.data_dir))
    print(f"[+] Risks found: {len(risks)}")

    for risk in sorted(risks, key=lambda r: {"Critical": 0, "High": 1, "Medium": 2}.get(r["severity"], 3)):
        print(f"  [{risk['severity']}] {risk['type']}: {risk['source']}")


if __name__ == "__main__":
    main()
```
