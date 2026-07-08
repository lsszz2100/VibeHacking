> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# Active Directory 방어 및 탐지

## 0. 초보자를 위한 개념 이해

### AD 방어와 탐지란?

**Active Directory 방어·탐지**는 Kerberoasting, Pass-the-Hash, DCSync 같은 AD 공격을 사전에 차단하고 실시간으로 탐지하는 보안 강화 전략입니다.

**왜 배우는가:**
```
AD = 기업 IT 인프라의 핵심:
  AD 장악 = 회사 전체 시스템 장악

방어자 입장:
  - AD 보안 설정 강화 → 공격 표면 축소
  - SIEM 탐지 룰 → 공격 조기 발견
  - 침해 시 빠른 격리 → 피해 최소화

사고 대응 통계:
  AD 관련 침해: 기업 침해 사고의 60%+
  → AD 방어 = 가장 중요한 보안 투자
```

### 핵심 방어 전략

```
계층적 AD 방어:

1. Tiered Administration (계층적 관리)
   Tier 0: DC, PKI (최고 권한, 인터넷 차단)
   Tier 1: 서버 관리자
   Tier 2: 워크스테이션 관리자
   → 계층 간 자격증명 공유 금지

2. Protected Users 그룹
   NTLM 인증 차단, 위임 불가
   → Pass-the-Hash, Kerberoasting 방어

3. LAPS (Local Administrator Password Solution)
   각 PC마다 다른 로컬 관리자 비밀번호
   → 자격증명 재사용 공격 차단

주요 탐지 이벤트 ID:
  4769: Kerberos TGS 요청 → Kerberoasting
  4625: 로그인 실패 → 무차별 대입
  4624 + 로그온유형3: PtH
  4662 + DS-Replication-Get-Changes: DCSync
```

### 필요한 도구
- **BloodHound**: AD 공격 경로 시각화 → 취약 경로 제거
- **PingCastle**: AD 보안 상태 스코어링
- **Microsoft Defender for Identity**: AD 공격 실시간 탐지

### 기초 실습 예제
```python
# AD 탐지 이벤트 분석 스크립트 (Windows 이벤트 로그)
import re
from datetime import datetime

# 탐지할 이벤트 ID 및 설명
AD_ATTACK_EVENTS = {
    "4769": "Kerberos TGS 요청 — Kerberoasting 가능성",
    "4625": "로그인 실패 — 무차별 대입 가능성",
    "4662": "AD 객체 접근 — DCSync 가능성",
    "4624": "로그인 성공 — 로그온 유형 확인 필요",
    "4648": "명시적 자격증명 사용 — Pass-the-Hash 가능성",
}

def analyze_event(event_id: str, details: str) -> str | None:
    if event_id in AD_ATTACK_EVENTS:
        return f"[경고] EventID {event_id}: {AD_ATTACK_EVENTS[event_id]}"
    return None

# 이벤트 분석 예시
events = [("4769", "SPN: MSSQLSvc/server"), ("4625", "사용자: admin")]
for eid, detail in events:
    result = analyze_event(eid, detail)
    if result:
        print(result)
```

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

## 7. AD CS(인증서 서비스) ESC 취약점 탐지

Kerberoasting/Pass-the-Hash 같은 전통적 자격증명 공격 방어가 성숙해지면서, 공격자는 **AD CS(Active Directory Certificate Services)의 취약한 인증서 템플릿(ESC1~ESC8로 분류)**으로 눈을 돌리고 있다 — 인증서는 발급 후 유효기간(보통 1~2년) 동안 살아있고, 인증서 기반 인증은 암호 변경으로도 무효화되지 않아 지속성(persistence) 확보에 특히 매력적이다. 가장 흔한 ESC1(임의 SAN 지정 허용 템플릿으로 임의 사용자 사칭)은 **인증서 발급 이벤트 자체가 정상 운영 트래픽과 구분이 안 된다**는 점이 탐지를 어렵게 만든다.

```python
#!/usr/bin/env python3
"""CA 서버의 인증서 발급 로그(이벤트 4886/4887)에서 요청자 계정과 발급된 인증서의
SAN(주체 대체 이름)이 불일치하는 경우(ESC1 악용 패턴)를 탐지."""
import re
from datetime import datetime

PRIVILEGED_UPN_PATTERNS = (r".*\\Administrator$", r".*\\krbtgt$", r".*-da@.*")  # 도메인관리자류 SAN 패턴


def parse_cert_issuance_events(security_log: list[dict]) -> list[dict]:
    """이벤트 4887(인증서 발급됨)만 추출."""
    return [e for e in security_log if e.get("EventID") == 4887]


def flag_san_mismatch(events: list[dict]) -> list[dict]:
    """요청자(Requester) 계정과 인증서 SAN에 기재된 계정이 다르면서,
    SAN이 고권한 계정 패턴과 일치하면 ESC1 악용 의심으로 표시."""
    findings = []
    for e in events:
        requester = e.get("RequesterAccount", "")
        san = e.get("SubjectAlternativeName", "")
        if not san or requester.lower() in san.lower():
            continue  # 요청자 본인 명의 발급은 정상
        if any(re.match(p, san, re.IGNORECASE) for p in PRIVILEGED_UPN_PATTERNS):
            findings.append({
                "template": e.get("CertificateTemplate"),
                "requester": requester,
                "san_impersonated": san,
                "timestamp": e.get("TimeCreated"),
                "verdict": "ESC1_SUSPECTED_IMPERSONATION",
            })
    return findings
```

| ESC 유형 | 취약 조건 | 탐지 신호 |
|---------|---------|---------|
| ESC1 | 템플릿이 요청자 지정 SAN 허용 + 클라이언트 인증 EKU | 요청자 계정 ≠ 발급된 SAN, 특히 SAN이 고권한 계정 |
| ESC4 | 낮은 권한 사용자가 템플릿 ACL을 수정 가능 | 템플릿 ACL 변경 이벤트(4899) 자체를 감사 대상으로 등록 |
| ESC8 | AD CS 웹 등록(HTTP)이 NTLM 릴레이에 노출 | CA 서버향 비정상 NTLM 인증 시도, HTTP 등록 엔드포인트 접근 로그 |

**탐지/방어**: ESC 계열 취약점의 근본 대응은 탐지보다 **사전 통제(템플릿 재설계, ESC8은 EPA/채널 바인딩 강제)**가 우선이지만, 레거시 템플릿을 즉시 제거할 수 없는 환경이 많아 위와 같은 발급 로그 이상탐지가 보완책으로 필요하다. `Certify`/`Certipy` 같은 공개 감사 도구로 **소유 환경에서 취약 템플릿 목록을 주기적으로 재점검**하는 것이 이 탐지의 전제조건이다 — 새 템플릿이 추가될 때마다 같은 취약점이 재도입될 수 있기 때문이다.

---

<!-- detect-validate-54 -->
## 공격 탐지와 방어 검증

이 단원은 AD 공격을 *방어자 관점*에서 다룬다. 핵심은 통제를 *설정했는가*가 아니라 **공격 발생 시 탐지 규칙이 실제로 발화하는가**를 통제된 랩에서 검증하는 것이다.

### 공격 → 완화 계층 → 통제(방어자) → 탐지 신호

| 기법 | 노리는 완화 | 1차 통제(예방) | 탐지 신호 |
|---|---|---|---|
| Kerberoasting 탐지 | - | 4769 RC4 모니터링, 허니 SPN | 탐지 규칙이 RC4 급증에 발화 |
| DCSync 탐지 | - | 4662 복제 권한 모니터링 | 비-DC 복제 시 경보 |
| Golden Ticket 탐지 | - | krbtgt 리셋, 이상 TGT 모니터링 | 비정상 티켓 수명/미존재 계정 |

### 방어 검증 (직접 확인)

```powershell
# 탐지가 실제 발화하는지 검증 — 통제된 랩에서만
# 1) 감사 정책이 Kerberos/디렉터리 접근을 기록하는지
auditpol /get /category:"Account Logon","DS Access"
# 2) 허니 SPN 에 Kerberoast 시도 → 4769 RC4 가 잡히는지 확인
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4769} -MaxEvents 20
# 3) 비-DC 복제 권한 부여 → 4662 경보 발화 확인 후 원복(랩 한정)
```

> 검증은 반드시 **소유한 시스템·통제된 환경**에서만 수행한다. 완화를 "설정했다"와 "런타임에 실제 막힌다"는 다르다 — PoC 를 재현해 완화가 차단하는지 확인해야 신뢰할 수 있다([[68_Purple_Team]]).

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

---

## 7. Detecting AD CS (Certificate Services) ESC Vulnerabilities

As defenses against traditional credential attacks like Kerberoasting and Pass-the-Hash mature, attackers are turning to **vulnerable certificate templates in AD CS (Active Directory Certificate Services), classified as ESC1 through ESC8** -- a certificate stays alive for its validity period (typically 1-2 years) after issuance, and certificate-based authentication isn't invalidated by a password change, making it especially attractive for persistence. The most common, ESC1 (a template that allows an arbitrary requester-supplied SAN, enabling impersonation of any user), is hard to detect precisely because **the certificate issuance event itself is indistinguishable from normal operational traffic**.

```python
#!/usr/bin/env python3
"""In the CA server's certificate-issuance log (events 4886/4887), detect cases where the
requesting account and the issued certificate's SAN (Subject Alternative Name) don't
match -- the ESC1 abuse pattern."""
import re
from datetime import datetime

PRIVILEGED_UPN_PATTERNS = (r".*\\Administrator$", r".*\\krbtgt$", r".*-da@.*")  # domain-admin-like SAN patterns


def parse_cert_issuance_events(security_log: list[dict]) -> list[dict]:
    """Extract only event 4887 (certificate issued)."""
    return [e for e in security_log if e.get("EventID") == 4887]


def flag_san_mismatch(events: list[dict]) -> list[dict]:
    """Flag as suspected ESC1 abuse when the requester account differs from the account
    named in the certificate's SAN, and that SAN matches a high-privilege account pattern."""
    findings = []
    for e in events:
        requester = e.get("RequesterAccount", "")
        san = e.get("SubjectAlternativeName", "")
        if not san or requester.lower() in san.lower():
            continue  # issuance under the requester's own name is normal
        if any(re.match(p, san, re.IGNORECASE) for p in PRIVILEGED_UPN_PATTERNS):
            findings.append({
                "template": e.get("CertificateTemplate"),
                "requester": requester,
                "san_impersonated": san,
                "timestamp": e.get("TimeCreated"),
                "verdict": "ESC1_SUSPECTED_IMPERSONATION",
            })
    return findings
```

| ESC Type | Vulnerable Condition | Detection Signal |
|----------|------------------------|-------------------|
| ESC1 | Template allows requester-supplied SAN + client authentication EKU | Requester account != issued SAN, especially when the SAN is a high-privilege account |
| ESC4 | A low-privileged user can modify the template ACL | Register the template ACL-change event (4899) itself as an audit target |
| ESC8 | AD CS web enrollment (HTTP) is exposed to NTLM relay | Abnormal NTLM authentication attempts toward the CA server, access logs on the HTTP enrollment endpoint |

**Detection/Defense**: the fundamental fix for ESC-family vulnerabilities is **preventive control (template redesign; for ESC8, enforcing EPA/channel binding)** rather than detection, but since many environments can't remove legacy templates immediately, issuance-log anomaly detection like the above is needed as a compensating control. Periodically re-auditing the environment's vulnerable-template list with a public auditing tool such as `Certify`/`Certipy` on **owned environments** is a prerequisite for this detection -- because the same vulnerability can be reintroduced every time a new template is added.

---

## Attack Detection and Defense Validation

This unit covers AD attacks from the *defender's* perspective. The point is not *whether* controls were configured, but verifying in a controlled lab **whether detection rules actually fire when an attack occurs**.

### Attack -> mitigation layer -> control (defender) -> detection signal

| Technique | Targeted mitigation | Primary control (prevention) | Detection signal |
|---|---|---|---|
| Kerberoasting detection | - | Monitor 4769 RC4, honey SPN | Rule fires on the RC4 spike |
| DCSync detection | - | Monitor 4662 replication rights | Alert on replication from a non-DC |
| Golden Ticket detection | - | Reset krbtgt, monitor anomalous TGTs | Abnormal ticket lifetime/non-existent account |

### Defense validation (verify yourself)

```powershell
# Verify detection actually fires -- in a controlled lab only
# 1) Confirm audit policy records Kerberos/directory access
auditpol /get /category:"Account Logon","DS Access"
# 2) Kerberoast a honey SPN -> confirm 4769 RC4 is caught
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4769} -MaxEvents 20
# 3) Grant non-DC replication rights -> confirm the 4662 alert, then revert (lab only)
```

> Run validation only on **systems you own, in a controlled environment**. "Configured" is not the same as "blocked at runtime" -- reproduce the PoC and confirm the mitigation stops it (see [[68_Purple_Team]]).
