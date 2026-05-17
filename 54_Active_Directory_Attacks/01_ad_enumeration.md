# Active Directory 열거 — BloodHound·LDAP·자동화

## 1. AD 공격 로드맵

```
초기 접근 (Initial Access)
    │
    ▼
AD 열거 (Enumeration) ←── 여기서 시작
    │  - 도메인 정보·사용자·그룹·컴퓨터
    │  - 신뢰 관계·GPO·ACL
    ▼
Kerberos 공격
    │  - Kerberoasting·AS-REP Roasting
    ▼
횡이동 (Lateral Movement)
    │  - Pass-the-Hash·Pass-the-Ticket
    │  - NTLM 릴레이·DCSync
    ▼
도메인 장악 (Domain Dominance)
       - Golden Ticket·Silver Ticket
       - AdminSDHolder·ACL 남용
```

---

## 2. 기본 AD 열거 명령어

### 2.1 PowerShell 기반

```powershell
# 도메인 기본 정보
Get-ADDomain
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()

# 도메인 사용자 열거
Get-ADUser -Filter * -Properties * | Select-Object Name, SamAccountName, MemberOf, LastLogonDate

# 관리자 그룹 멤버
Get-ADGroupMember "Domain Admins" -Recursive
Get-ADGroupMember "Enterprise Admins" -Recursive
Get-ADGroupMember "Administrators" -Recursive

# 도메인 컨트롤러
Get-ADDomainController -Filter *

# SPN 설정된 계정 (Kerberoasting 대상)
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName |
  Select-Object SamAccountName, ServicePrincipalName

# Pre-auth 불필요 계정 (AS-REP Roasting 대상)
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth |
  Select-Object SamAccountName

# GPO 열거
Get-GPO -All | Select-Object DisplayName, Id, GpoStatus

# 컴퓨터 계정 (WinRM 활성화 대상 탐색)
Get-ADComputer -Filter * -Properties OperatingSystem |
  Where-Object {$_.OperatingSystem -like "*Server*"} |
  Select-Object Name, OperatingSystem, DNSHostName
```

### 2.2 LDAP 쿼리 (Linux)

```bash
# LDAP 기본 열거
ldapsearch -x -H ldap://10.10.10.100 -D "DOMAIN\user" -w "Password123" \
  -b "DC=domain,DC=local" "(objectClass=user)" cn sAMAccountName memberOf

# 익명 LDAP 열거 시도
ldapsearch -x -H ldap://10.10.10.100 -b "" -s base namingContexts

# 모든 사용자 덤프
ldapsearch -x -H ldap://10.10.10.100 -D "user@domain.local" -w "Password" \
  -b "DC=domain,DC=local" "(&(objectClass=user)(objectCategory=person))" \
  sAMAccountName displayName mail memberOf | tee users.ldif

# SPN 계정
ldapsearch -x -H ldap://DC_IP -D "user@domain.local" -w "Password" \
  -b "DC=domain,DC=local" "(&(servicePrincipalName=*)(objectClass=user))" \
  sAMAccountName servicePrincipalName
```

---

## 3. BloodHound 수집 및 분석

### 3.1 SharpHound 데이터 수집

```powershell
# SharpHound 실행 (PowerShell)
Invoke-BloodHound -CollectionMethod All -OutputDirectory C:\temp

# 특정 수집 방법
# - Default: 기본 (세션·로컬 관리자·그룹 멤버십)
# - All: 전체
# - Session: 활성 세션만
# - DCOnly: DC에서만 수집 (네트워크 소음 최소화)
Invoke-BloodHound -CollectionMethod DCOnly -Compress

# Kerberos 인증으로 원격 수집
.\SharpHound.exe -c All --domain domain.local \
  --domaincontroller 10.10.10.100 \
  --ldapusername user --ldappassword Password
```

```bash
# bloodhound-python (Linux, 도메인 참가 없이)
pip install bloodhound
bloodhound-python -u user@domain.local -p Password \
  -ns 10.10.10.100 -d domain.local -c all \
  --zip -o /tmp/bloodhound/
```

### 3.2 BloodHound Cypher 쿼리

```cypher
// 도메인 관리자까지 최단 경로
MATCH p=shortestPath((u:User {owned:true})-[*1..]->(g:Group {name:"DOMAIN ADMINS@DOMAIN.LOCAL"}))
RETURN p

// Kerberoasting 가능한 경로
MATCH (u:User {hasspn:true}) RETURN u.name, u.serviceprincipalnames

// AS-REP Roasting 대상
MATCH (u:User {dontreqpreauth:true}) RETURN u.name

// DCSync 권한 보유 계정
MATCH (n)-[:DCSync|AllExtendedRights|GenericAll]->(d:Domain) RETURN n.name, d.name

// 패스워드 만료 없는 계정
MATCH (u:User {pwdneverexpires:true, enabled:true}) RETURN u.name

// 로컬 관리자 경로
MATCH p=(u:User {owned:true})-[r:AdminTo]->(c:Computer) RETURN p

// 신뢰 관계 맵
MATCH (d1:Domain)-[r:TrustedBy]->(d2:Domain) RETURN d1.name, r.trusttype, d2.name
```

---

## 4. AD 자동 열거 CLI

```python
#!/usr/bin/env python3
"""Active Directory 자동 열거 CLI — python-ldap3 기반."""

import argparse
import json
from dataclasses import dataclass, field
from pathlib import Path

from ldap3 import (
    ALL, ALL_ATTRIBUTES, NTLM, SAFE_SYNC,
    Connection, Server, SUBTREE, Tls,
)
from ldap3.core.exceptions import LDAPException


@dataclass
class ADObject:
    dn: str
    attributes: dict


@dataclass
class ADEnumResult:
    domain: str
    domain_controllers: list[str] = field(default_factory=list)
    users: list[ADObject] = field(default_factory=list)
    groups: list[ADObject] = field(default_factory=list)
    computers: list[ADObject] = field(default_factory=list)
    spn_accounts: list[ADObject] = field(default_factory=list)
    asrep_accounts: list[ADObject] = field(default_factory=list)


class ADEnumerator:
    def __init__(
        self,
        dc_ip: str,
        domain: str,
        username: str,
        password: str,
        use_tls: bool = False,
    ) -> None:
        self.domain = domain
        self.base_dn = ",".join(f"DC={part}" for part in domain.split("."))
        server = Server(dc_ip, get_info=ALL, use_ssl=use_tls)
        self.conn = Connection(
            server,
            user=f"{domain}\\{username}",
            password=password,
            authentication=NTLM,
            client_strategy=SAFE_SYNC,
            auto_bind=True,
        )

    def search(self, filter_: str, attributes: list[str]) -> list[ADObject]:
        self.conn.search(
            search_base=self.base_dn,
            search_filter=filter_,
            search_scope=SUBTREE,
            attributes=attributes,
        )
        return [
            ADObject(
                dn=entry.entry_dn,
                attributes={attr: entry[attr].values for attr in attributes if attr in entry},
            )
            for entry in self.conn.entries
        ]

    def enum_users(self) -> list[ADObject]:
        return self.search(
            "(&(objectClass=user)(objectCategory=person))",
            ["sAMAccountName", "displayName", "mail", "memberOf",
             "lastLogonTimestamp", "pwdLastSet", "userAccountControl"],
        )

    def enum_spn_accounts(self) -> list[ADObject]:
        return self.search(
            "(&(objectClass=user)(servicePrincipalName=*)(!(objectClass=computer)))",
            ["sAMAccountName", "servicePrincipalName", "memberOf"],
        )

    def enum_asrep_accounts(self) -> list[ADObject]:
        # userAccountControl bit 4194304 = DONT_REQ_PREAUTH
        return self.search(
            "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))",
            ["sAMAccountName", "userAccountControl"],
        )

    def enum_domain_admins(self) -> list[ADObject]:
        da_dn = f"CN=Domain Admins,CN=Users,{self.base_dn}"
        return self.search(
            f"(memberOf={da_dn})",
            ["sAMAccountName", "displayName"],
        )

    def enum_computers(self) -> list[ADObject]:
        return self.search(
            "(objectClass=computer)",
            ["dNSHostName", "operatingSystem", "operatingSystemVersion", "lastLogonTimestamp"],
        )

    def enumerate_all(self) -> ADEnumResult:
        result = ADEnumResult(domain=self.domain)
        print("[*] 사용자 열거 중...")
        result.users = self.enum_users()
        print(f"  발견: {len(result.users)}개")

        print("[*] SPN 계정 열거 중 (Kerberoasting 대상)...")
        result.spn_accounts = self.enum_spn_accounts()
        print(f"  발견: {len(result.spn_accounts)}개")

        print("[*] AS-REP Roasting 대상 열거 중...")
        result.asrep_accounts = self.enum_asrep_accounts()
        print(f"  발견: {len(result.asrep_accounts)}개")

        print("[*] 컴퓨터 열거 중...")
        result.computers = self.enum_computers()
        print(f"  발견: {len(result.computers)}개")

        return result

    def close(self) -> None:
        self.conn.unbind()


def main() -> None:
    parser = argparse.ArgumentParser(description="Active Directory 자동 열거")
    parser.add_argument("dc", help="도메인 컨트롤러 IP")
    parser.add_argument("domain", help="도메인 (예: corp.local)")
    parser.add_argument("-u", "--user", required=True, help="사용자명")
    parser.add_argument("-p", "--password", required=True, help="패스워드")
    parser.add_argument("--tls", action="store_true", help="LDAPS 사용")
    parser.add_argument("-o", "--output", type=Path, help="결과 저장 경로")
    args = parser.parse_args()

    try:
        enumerator = ADEnumerator(
            args.dc, args.domain, args.user, args.password, args.tls
        )
        result = enumerator.enumerate_all()
        enumerator.close()

        print(f"\n=== 결과 요약: {args.domain} ===")
        print(f"총 사용자: {len(result.users)}")
        print(f"Kerberoasting 대상: {len(result.spn_accounts)}")
        print(f"AS-REP Roasting 대상: {len(result.asrep_accounts)}")
        print(f"컴퓨터: {len(result.computers)}")

        if result.spn_accounts:
            print("\n[!] Kerberoasting 대상 계정:")
            for obj in result.spn_accounts:
                print(f"  {obj.attributes.get('sAMAccountName', ['?'])[0]}")

        if result.asrep_accounts:
            print("\n[!] AS-REP Roasting 대상:")
            for obj in result.asrep_accounts:
                print(f"  {obj.attributes.get('sAMAccountName', ['?'])[0]}")

        if args.output:
            data = {
                "domain": result.domain,
                "users_count": len(result.users),
                "spn_accounts": [o.attributes for o in result.spn_accounts],
                "asrep_accounts": [o.attributes for o in result.asrep_accounts],
                "computers": [o.attributes for o in result.computers],
            }
            args.output.write_text(json.dumps(data, indent=2, default=str, ensure_ascii=False))
            print(f"\n결과 저장: {args.output}")

    except LDAPException as e:
        print(f"LDAP 오류: {e}")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
```

---

## 5. 참고 도구

| 도구 | 용도 |
|------|------|
| `BloodHound` | AD 공격 경로 시각화 |
| `SharpHound` | BloodHound 데이터 수집 |
| `bloodhound-python` | Linux에서 BloodHound 수집 |
| `ldapdomaindump` | LDAP 데이터 HTML 덤프 |
| `CrackMapExec` / `NetExec` | SMB·AD 대량 열거 |
| `rpcclient` | RPC 기반 AD 열거 |
| `enum4linux-ng` | Linux SMB/AD 열거 |
| `ADRecon` | 포렌식 친화적 AD 정보 수집 |
