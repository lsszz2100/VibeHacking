> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 위협 격리, 박멸, 복구

인시던트 격리는 피해 확산을 막는 첫 번째 방어선이다. 악성코드 박멸은 루트 원인을 제거하고, 복구는 서비스를 안전하게 정상화한다.

## 0. 초보자를 위한 개념 이해

### 위협 격리, 박멸, 복구란?

침해사고 대응(Incident Response)의 핵심 3단계다. 격리(Containment)는 감염된 시스템을 네트워크에서 차단해 피해가 번지지 않도록 막는다. 박멸(Eradication)은 악성코드, 백도어, 공격자가 남긴 흔적을 완전히 제거한다. 복구(Recovery)는 시스템을 안전한 상태로 되돌리고 서비스를 정상화한다.

**왜 배우는가:**
```
침해사고 대응 3단계:

  [감염 탐지]
      │
      ▼
  1단계: 격리 (Containment)
     ├── 즉각 격리: 네트워크 케이블 뽑기, 방화벽 차단
     ├── 단기 격리: VPN 차단, 계정 비활성화
     └── 목표: 피해 확산 방지

      │
      ▼
  2단계: 박멸 (Eradication)
     ├── 악성코드 파일 삭제
     ├── 레지스트리 자동실행 항목 제거
     ├── 백도어 계정 삭제
     └── 취약점 패치 적용

      │
      ▼
  3단계: 복구 (Recovery)
     ├── 깨끗한 백업에서 시스템 복원
     ├── 모니터링 강화 후 서비스 재개
     └── 재감염 여부 24~72시간 관찰
```

### 핵심 개념 정리

```
주요 용어:

격리 전략 선택 기준:
  즉각 격리 → 랜섬웨어, 웜처럼 빠른 확산 위협
  단기 격리 → 일반 악성코드, 포렌식 증거 수집 필요 시
  장기 격리 → APT, 공격자 행동 추가 관찰 필요 시

IOC (Indicator of Compromise)
  - 침해 지표: 악성 IP, 파일 해시, 레지스트리 키 등
  - 박멸 단계에서 IOC 기반으로 모든 감염 흔적 제거

루트 원인 분석 (Root Cause Analysis)
  - 단순 악성코드 제거가 아닌 "어떻게 침입했는가" 파악
  - 원인 미제거 시 동일 경로로 재감염 발생

회귀 테스트 (Regression Test)
  - 복구 후 시스템이 다시 취약하지 않은지 확인
  - 패치 적용, 계정 재검토, 보안 설정 강화 포함
```

### 필요한 도구 및 환경
- **netsh / iptables**: Windows/Linux 방화벽 격리 명령
- **CrowdStrike Falcon / Carbon Black**: EDR 원격 격리 기능
- **Autoruns (Sysinternals)**: 자동실행 악성 항목 탐지·제거
- **Volatility**: 메모리 포렌식으로 악성코드 잔재 확인
- **Veeam / rsync**: 검증된 백업에서 복구

### 기초 실습 예제
```python
#!/usr/bin/env python3
"""Windows 시스템 격리 및 박멸 체크리스트 자동 생성기"""
import json
from datetime import datetime


def create_containment_plan(hostname: str, threat_type: str) -> dict:
    """침해된 시스템에 대한 격리·박멸 계획을 생성한다."""

    # 위협 유형별 격리 우선순위 결정
    urgency_map = {
        "ransomware": "즉각",
        "worm": "즉각",
        "apt": "단기",
        "malware": "단기",
        "phishing": "단기",
    }
    urgency = urgency_map.get(threat_type.lower(), "단기")

    plan = {
        "대상호스트": hostname,
        "위협유형": threat_type,
        "격리우선순위": urgency,
        "생성시각": datetime.now().isoformat(),
        "격리_단계": {
            "즉각조치": [
                f"[{hostname}] 네트워크 격리: iptables -P INPUT DROP",
                f"[{hostname}] 활성 세션 강제 종료",
                "SIEM에 격리 완료 이벤트 기록",
            ],
            "증거수집": [
                "메모리 덤프 생성 (winpmem 또는 LiME)",
                "실행 중인 프로세스 목록 저장",
                "네트워크 연결 상태 저장",
                "디스크 이미지 생성 (격리 후)",
            ],
        },
        "박멸_체크리스트": [
            "악성 파일/폴더 식별 및 해시 기록",
            "레지스트리 자동실행 항목 점검 (Run, RunOnce)",
            "예약 작업(Task Scheduler) 점검",
            "서비스 목록 비교 (기준값 vs 현재)",
            "백도어 계정 확인 (net user 비교)",
            "취약점 패치 적용 (CVE 목록 확인)",
        ],
        "복구_체크리스트": [
            "깨끗한 백업 날짜 확인 (감염 이전)",
            "백업 무결성 검증 (SHA256 해시)",
            "스테이징 환경에서 복원 테스트",
            "EDR 에이전트 재설치 및 최신 업데이트",
            "72시간 집중 모니터링 후 정상 운영 전환",
        ],
    }
    return plan


if __name__ == "__main__":
    plan = create_containment_plan("WORKSTATION-042", "ransomware")
    print(json.dumps(plan, ensure_ascii=False, indent=2))
```

---

## 1. 격리 전략

### 1.1 단기 격리 (즉각 대응)

```powershell
# Windows — 네트워크 격리 (방화벽으로 모든 트래픽 차단)
# IR 팀 IP만 허용
$irTeamIP = "10.0.0.100"

netsh advfirewall set allprofiles state on
netsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound

# IR 팀 접근 허용
netsh advfirewall firewall add rule name="IR_ALLOW_IN" dir=in `
    action=allow remoteip=$irTeamIP
netsh advfirewall firewall add rule name="IR_ALLOW_OUT" dir=out `
    action=allow remoteip=$irTeamIP

# 격리 확인
netsh advfirewall show allprofiles
```

```bash
# Linux — iptables 격리
IR_IP="10.0.0.100"

iptables -P INPUT DROP
iptables -P OUTPUT DROP
iptables -P FORWARD DROP

# IR 팀 허용
iptables -A INPUT -s $IR_IP -j ACCEPT
iptables -A OUTPUT -d $IR_IP -j ACCEPT

# 루프백 허용
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# 현재 연결 종료 (선택적 — 증거 보존 필요 시 생략)
# ss -K dst [suspicious_ip]
```

### 1.2 Active Directory 계정 격리

```powershell
# 침해된 계정 즉시 비활성화
$compromisedUsers = @("jsmith", "admin_backup", "svc_webapp")

foreach ($user in $compromisedUsers) {
    # 비활성화
    Disable-ADAccount -Identity $user
    
    # 비밀번호 강제 변경 (모든 세션 무효화)
    $newPass = ConvertTo-SecureString -AsPlainText "IR_Temp2026#$(Get-Random)" -Force
    Set-ADAccountPassword -Identity $user -Reset -NewPassword $newPass
    
    # 그룹 제거 (관리자 그룹 등)
    Get-ADPrincipalGroupMembership $user | 
        Where-Object {$_.Name -ne "Domain Users"} |
        ForEach-Object { Remove-ADGroupMember -Identity $_ -Members $user -Confirm:$false }
    
    Write-Host "[+] 격리 완료: $user"
}

# 활성 세션 강제 종료
Invoke-Command -ComputerName $targetPC -ScriptBlock {
    query session | Select-String "jsmith" | ForEach-Object {
        $sessionId = ($_ -split '\s+')[2]
        logoff $sessionId
    }
}
```

### 1.3 네트워크 세그먼트 격리

```
격리 수준 (영향도 ↑):
Level 1: 의심 호스트만 격리 (VLAN 이동)
Level 2: 의심 서브넷 격리 (라우팅 제거)
Level 3: 인터넷 연결 차단 (BGP 경로 제거 또는 방화벽)
Level 4: 전체 네트워크 셧다운 (최후 수단)

VLAN 격리 (Cisco):
interface GigabitEthernet0/1
  switchport access vlan 999  # 격리 VLAN으로 이동

# 격리 VLAN 999 — 라우팅 없음, IR 팀 접근만 허용
```

---

## 2. 악성코드 박멸

### 2.1 지속성 메커니즘 전체 점검

```powershell
# 1. 레지스트리 자동실행 키
$runKeys = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
)

foreach ($key in $runKeys) {
    if (Test-Path $key) {
        Write-Host "`n[$key]"
        Get-ItemProperty $key | Format-List
    }
}

# 2. 예약 작업
Get-ScheduledTask | Where-Object {$_.State -ne "Disabled"} |
    Select-Object TaskName, TaskPath,
        @{N='Command'; E={$_.Actions.Execute}},
        @{N='Args'; E={$_.Actions.Arguments}} |
    Format-Table -AutoSize

# 3. 서비스
Get-Service | Where-Object {$_.StartType -ne "Disabled"} |
    Select-Object Name, DisplayName, Status, StartType |
    Sort-Object StartType | Format-Table

# 4. WMI 이벤트 구독 (파일리스 지속성)
Get-WMIObject -Namespace root\subscription -Class __EventFilter
Get-WMIObject -Namespace root\subscription -Class __EventConsumer
Get-WMIObject -Namespace root\subscription -Class __FilterToConsumerBinding

# 5. 시작프로그램 폴더
$startupFolders = @(
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
    "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
)
foreach ($folder in $startupFolders) {
    Get-ChildItem $folder -ErrorAction SilentlyContinue
}

# 6. 드라이버 (루트킷)
Get-WmiObject Win32_SystemDriver | 
    Where-Object {$_.State -eq "Running"} |
    Select-Object Name, PathName |
    Where-Object {$_.PathName -notmatch "Windows\\System32\\drivers"}
```

### 2.2 지속성 제거

```powershell
# 레지스트리 악성 항목 삭제
Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" `
    -Name "MaliciousApp" -ErrorAction SilentlyContinue

# 예약 작업 삭제
Unregister-ScheduledTask -TaskName "MaliciousTask" -Confirm:$false

# 악성 서비스 삭제
Stop-Service "MaliciousService" -Force
sc.exe delete "MaliciousService"

# WMI 구독 삭제
$filter = Get-WMIObject -Namespace root\subscription -Class __EventFilter -Filter "Name='MalFilter'"
$filter.Delete()
$consumer = Get-WMIObject -Namespace root\subscription -Class __EventConsumer -Filter "Name='MalConsumer'"
$consumer.Delete()
$binding = Get-WMIObject -Namespace root\subscription -Class __FilterToConsumerBinding
$binding | Where-Object {$_.Filter -match "MalFilter"} | ForEach-Object { $_.Delete() }
```

---

## 3. 랜섬웨어 복구

### 3.1 복구 옵션 평가 순서

```
1. 무결성 있는 백업 복원 (오프라인 백업 확인 필수)
   → 백업도 암호화됐는지 먼저 확인
   → NAS/클라우드 백업이 동기화로 덮어써졌는지 확인

2. 볼륨 섀도 복사본 (VSS)
   vssadmin list shadows  # 사용 가능한 스냅샷 목록
   mklink /D C:\Shadow \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\

3. 공개 복호화 도구
   https://www.nomoreransom.org  # 랜섬웨어 종류별 복호화 도구
   ID Ransomware으로 종류 식별 후 도구 확인

4. 법집행 기관 협조
   경찰청 사이버수사대, KISA (한국인터넷진흥원) 118

5. 협상 (최후 수단, 권장하지 않음)
   → 지불해도 복호화 보장 없음
   → 법적 이슈 (일부 국가에서 제재 대상 그룹에 지불 불법)
```

### 3.2 VSS를 이용한 파일 복구

```powershell
# 사용 가능한 섀도 복사본 확인
vssadmin list shadows /for=C:

# 마운트 (심링크)
$shadowPath = "\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1"
cmd /c mklink /D "C:\Shadow" "$shadowPath\"

# 파일 복사
Copy-Item "C:\Shadow\Users\victim\Documents\important.docx" `
    "C:\Recovered\important.docx"

# 언마운트
cmd /c rmdir "C:\Shadow"
```

---

## 4. Windows 지속성 아티팩트 자동 수집 CLI

```python
#!/usr/bin/env python3
"""Windows 지속성 아티팩트 자동 수집 CLI (원격 WMI/레지스트리 분석)"""

import argparse
import json
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional


@dataclass
class PersistenceArtifact:
    category: str
    name: str
    value: str
    path: str
    risk: str = "unknown"
    note: str = ""


KNOWN_LEGIT = {
    "OneDrive", "SecurityHealth", "WindowsDefender",
    "MicrosoftEdgeAutoLaunch", "Teams", "Discord",
}

SUSPICIOUS_KEYWORDS = [
    "powershell", "cmd.exe", "wscript", "cscript", "mshta",
    "regsvr32", "rundll32 ..", "certutil", "bitsadmin",
    "AppData\\Local\\Temp", "Temp\\", "ProgramData\\Temp",
    "\\Users\\Public\\", "base64", "-enc", "-encodedcommand",
]


def run_ps_command(cmd: str, target: Optional[str] = None) -> str:
    """PowerShell 명령 실행"""
    if target:
        full_cmd = f'Invoke-Command -ComputerName {target} -ScriptBlock {{{cmd}}}'
    else:
        full_cmd = cmd

    result = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", full_cmd],
        capture_output=True, text=True, timeout=30
    )
    return result.stdout.strip()


def collect_registry_run(target: Optional[str] = None) -> list[PersistenceArtifact]:
    """레지스트리 자동실행 키 수집"""
    artifacts = []
    run_keys = [
        r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        r"HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        r"HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
    ]

    for reg_key in run_keys:
        cmd = f"Get-ItemProperty '{reg_key}' -ErrorAction SilentlyContinue | ConvertTo-Json"
        output = run_ps_command(cmd, target)

        if not output or output == "null":
            continue

        try:
            data = json.loads(output)
            for name, value in data.items():
                if name.startswith('PS') or name == 'PSPath':
                    continue
                if isinstance(value, str):
                    risk = assess_risk(name, value)
                    artifacts.append(PersistenceArtifact(
                        category="Registry_Run",
                        name=name, value=value,
                        path=reg_key, risk=risk,
                    ))
        except json.JSONDecodeError:
            pass

    return artifacts


def collect_scheduled_tasks(target: Optional[str] = None) -> list[PersistenceArtifact]:
    """예약 작업 수집"""
    cmd = """
    Get-ScheduledTask | Where-Object {$_.State -ne 'Disabled'} | ForEach-Object {
        $action = $_.Actions | Select-Object -First 1
        [PSCustomObject]@{
            Name = $_.TaskName
            Path = $_.TaskPath
            Command = $action.Execute
            Args = $action.Arguments
            State = $_.State
        }
    } | ConvertTo-Json
    """
    output = run_ps_command(cmd, target)
    artifacts = []

    try:
        tasks = json.loads(output) if output else []
        if isinstance(tasks, dict):
            tasks = [tasks]
        for task in tasks:
            name = task.get('Name', '')
            command = task.get('Command', '') or ''
            args = task.get('Args', '') or ''
            full_cmd = f"{command} {args}".strip()
            risk = assess_risk(name, full_cmd)
            artifacts.append(PersistenceArtifact(
                category="ScheduledTask",
                name=name, value=full_cmd,
                path=task.get('Path', ''), risk=risk,
            ))
    except (json.JSONDecodeError, TypeError):
        pass

    return artifacts


def collect_services(target: Optional[str] = None) -> list[PersistenceArtifact]:
    """의심 서비스 수집"""
    cmd = """
    Get-WmiObject Win32_Service | Where-Object {$_.StartMode -ne 'Disabled'} |
    Select-Object Name, DisplayName, PathName, StartMode, State |
    Where-Object {$_.PathName -notmatch 'System32|SysWOW64|Program Files'} |
    ConvertTo-Json
    """
    output = run_ps_command(cmd, target)
    artifacts = []

    try:
        services = json.loads(output) if output else []
        if isinstance(services, dict):
            services = [services]
        for svc in services:
            path = svc.get('PathName', '') or ''
            risk = assess_risk(svc.get('Name', ''), path)
            if risk in ('high', 'medium'):
                artifacts.append(PersistenceArtifact(
                    category="Service",
                    name=svc.get('Name', ''), value=path,
                    path=path, risk=risk,
                ))
    except (json.JSONDecodeError, TypeError):
        pass

    return artifacts


def assess_risk(name: str, value: str) -> str:
    """위험도 평가"""
    value_lower = value.lower()
    name_lower = name.lower()

    if any(kw.lower() in value_lower for kw in SUSPICIOUS_KEYWORDS):
        return "high"
    if name in KNOWN_LEGIT:
        return "low"
    if "temp" in value_lower or "appdata\\local\\temp" in value_lower:
        return "high"
    if any(ext in value_lower for ext in ['.vbs', '.js', '.hta', '.bat', '.ps1']):
        return "medium"
    return "low"


def print_report(artifacts: list[PersistenceArtifact], show_low: bool = False) -> None:
    COLOR = {"high": "\033[91m", "medium": "\033[93m", "low": "\033[92m", "unknown": "\033[96m"}
    RESET = "\033[0m"

    by_category: dict[str, list[PersistenceArtifact]] = {}
    for a in artifacts:
        by_category.setdefault(a.category, []).append(a)

    print(f"\n{'='*65}")
    print(f"Windows 지속성 아티팩트 수집 보고서")
    print(f"수집 시각: {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    print(f"총 발견: {len(artifacts)}개")
    print(f"{'='*65}\n")

    for category, arts in by_category.items():
        visible = [a for a in arts if show_low or a.risk != "low"]
        if not visible:
            continue
        print(f"[{category}] — {len(visible)}개")
        for a in visible:
            c = COLOR.get(a.risk, "")
            print(f"  {c}[{a.risk.upper()}]{RESET} {a.name}")
            print(f"    값: {a.value[:100]}")
            if a.note:
                print(f"    주의: {a.note}")
        print()


def main() -> None:
    parser = argparse.ArgumentParser(description="Windows 지속성 아티팩트 수집 CLI")
    parser.add_argument("--target", help="원격 컴퓨터명 (미지정 시 로컬)")
    parser.add_argument("--show-low", action="store_true", help="저위험 항목도 표시")
    parser.add_argument("--export", metavar="FILE", help="JSON 내보내기")
    parser.add_argument("--all", action="store_true", help="모든 카테고리 수집")

    args = parser.parse_args()

    if sys.platform != 'win32' and not args.target:
        print("[!] Windows 전용 도구입니다. --target으로 원격 Windows 대상 지정", file=sys.stderr)
        sys.exit(1)

    print(f"[*] 아티팩트 수집 중{'(원격: ' + args.target + ')' if args.target else '(로컬)'}...")

    all_artifacts: list[PersistenceArtifact] = []
    all_artifacts.extend(collect_registry_run(args.target))
    all_artifacts.extend(collect_scheduled_tasks(args.target))

    if args.all:
        all_artifacts.extend(collect_services(args.target))

    print_report(all_artifacts, args.show_low)

    if args.export:
        data = [{"category": a.category, "name": a.name, "value": a.value,
                 "risk": a.risk, "path": a.path} for a in all_artifacts]
        Path(args.export).write_text(json.dumps(data, ensure_ascii=False, indent=2))
        print(f"[+] JSON 저장: {args.export}")


if __name__ == "__main__":
    main()
```

---

## 5. 사후분석 (Post-Incident Review)

### 5.1 5-Why 분석 템플릿

```
인시던트: 랜섬웨어 감염 및 데이터 암호화

Why 1: 왜 랜섬웨어가 실행됐는가?
→ 피싱 이메일의 악성 첨부파일을 직원이 실행

Why 2: 왜 악성 파일 실행이 허용됐는가?
→ 매크로 자동 실행이 비활성화되지 않음

Why 3: 왜 매크로 정책이 설정되지 않았는가?
→ GPO 관리가 체계적이지 않았음

Why 4: 왜 GPO 관리가 부실했는가?
→ IT 보안팀 인력 부족으로 강화 설정 미적용

Why 5: 왜 인력이 부족한가?
→ 보안 예산 우선순위가 낮음

근본 원인: 경영진 수준의 보안 투자 부족
개선 방향: CISO 직제 신설, 보안 예산 확충, GPO 하드닝
```

### 5.2 개선 권고안 구조

| 우선순위 | 항목 | 구현 난이도 | 예상 비용 | 기한 |
|---------|------|-----------|---------|------|
| P1 | 매크로 비활성화 GPO | 낮음 | 무료 | 1주 |
| P1 | 이메일 첨부파일 샌드박스 | 중간 | 라이선스 | 1개월 |
| P2 | EDR 전사 배포 | 높음 | 중간 | 3개월 |
| P3 | 오프라인 백업 구성 | 중간 | 스토리지 | 1개월 |
| P3 | 직원 피싱 인식 교육 | 낮음 | 낮음 | 분기별 |

---

<a name="english"></a>

# Threat Containment, Eradication, and Recovery

Incident containment is the first line of defense against further damage. Malware eradication removes the root cause, while recovery safely restores services to normal operation.

---

## 1. Containment Strategies

### 1.1 Short-Term Containment (Immediate Response)

```powershell
# Windows — Network isolation (block all traffic with firewall)
# Allow only IR team IP
$irTeamIP = "10.0.0.100"

netsh advfirewall set allprofiles state on
netsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound

# Allow IR team access
netsh advfirewall firewall add rule name="IR_ALLOW_IN" dir=in `
    action=allow remoteip=$irTeamIP
netsh advfirewall firewall add rule name="IR_ALLOW_OUT" dir=out `
    action=allow remoteip=$irTeamIP

# Verify isolation
netsh advfirewall show allprofiles
```

```bash
# Linux — iptables isolation
IR_IP="10.0.0.100"

iptables -P INPUT DROP
iptables -P OUTPUT DROP
iptables -P FORWARD DROP

# Allow IR team
iptables -A INPUT -s $IR_IP -j ACCEPT
iptables -A OUTPUT -d $IR_IP -j ACCEPT

# Allow loopback
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# Terminate current connections (optional — omit if evidence preservation required)
# ss -K dst [suspicious_ip]
```

### 1.2 Active Directory Account Isolation

```powershell
# Immediately disable compromised accounts
$compromisedUsers = @("jsmith", "admin_backup", "svc_webapp")

foreach ($user in $compromisedUsers) {
    # Disable account
    Disable-ADAccount -Identity $user
    
    # Force password change (invalidates all sessions)
    $newPass = ConvertTo-SecureString -AsPlainText "IR_Temp2026#$(Get-Random)" -Force
    Set-ADAccountPassword -Identity $user -Reset -NewPassword $newPass
    
    # Remove group memberships (admin groups, etc.)
    Get-ADPrincipalGroupMembership $user | 
        Where-Object {$_.Name -ne "Domain Users"} |
        ForEach-Object { Remove-ADGroupMember -Identity $_ -Members $user -Confirm:$false }
    
    Write-Host "[+] Isolation complete: $user"
}

# Force terminate active sessions
Invoke-Command -ComputerName $targetPC -ScriptBlock {
    query session | Select-String "jsmith" | ForEach-Object {
        $sessionId = ($_ -split '\s+')[2]
        logoff $sessionId
    }
}
```

### 1.3 Network Segment Isolation

```
Isolation levels (increasing impact):
Level 1: Isolate only suspected hosts (VLAN move)
Level 2: Isolate suspected subnet (remove routing)
Level 3: Block internet connectivity (remove BGP routes or firewall)
Level 4: Full network shutdown (last resort)

VLAN isolation (Cisco):
interface GigabitEthernet0/1
  switchport access vlan 999  # Move to isolation VLAN

# Isolation VLAN 999 — no routing, IR team access only
```

---

## 2. Malware Eradication

### 2.1 Full Persistence Mechanism Audit

```powershell
# 1. Registry auto-run keys
$runKeys = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
)

foreach ($key in $runKeys) {
    if (Test-Path $key) {
        Write-Host "`n[$key]"
        Get-ItemProperty $key | Format-List
    }
}

# 2. Scheduled tasks
Get-ScheduledTask | Where-Object {$_.State -ne "Disabled"} |
    Select-Object TaskName, TaskPath,
        @{N='Command'; E={$_.Actions.Execute}},
        @{N='Args'; E={$_.Actions.Arguments}} |
    Format-Table -AutoSize

# 3. Services
Get-Service | Where-Object {$_.StartType -ne "Disabled"} |
    Select-Object Name, DisplayName, Status, StartType |
    Sort-Object StartType | Format-Table

# 4. WMI event subscriptions (fileless persistence)
Get-WMIObject -Namespace root\subscription -Class __EventFilter
Get-WMIObject -Namespace root\subscription -Class __EventConsumer
Get-WMIObject -Namespace root\subscription -Class __FilterToConsumerBinding

# 5. Startup folders
$startupFolders = @(
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
    "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
)
foreach ($folder in $startupFolders) {
    Get-ChildItem $folder -ErrorAction SilentlyContinue
}

# 6. Drivers (rootkits)
Get-WmiObject Win32_SystemDriver | 
    Where-Object {$_.State -eq "Running"} |
    Select-Object Name, PathName |
    Where-Object {$_.PathName -notmatch "Windows\\System32\\drivers"}
```

### 2.2 Persistence Removal

```powershell
# Delete malicious registry entries
Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" `
    -Name "MaliciousApp" -ErrorAction SilentlyContinue

# Delete scheduled tasks
Unregister-ScheduledTask -TaskName "MaliciousTask" -Confirm:$false

# Delete malicious service
Stop-Service "MaliciousService" -Force
sc.exe delete "MaliciousService"

# Delete WMI subscriptions
$filter = Get-WMIObject -Namespace root\subscription -Class __EventFilter -Filter "Name='MalFilter'"
$filter.Delete()
$consumer = Get-WMIObject -Namespace root\subscription -Class __EventConsumer -Filter "Name='MalConsumer'"
$consumer.Delete()
$binding = Get-WMIObject -Namespace root\subscription -Class __FilterToConsumerBinding
$binding | Where-Object {$_.Filter -match "MalFilter"} | ForEach-Object { $_.Delete() }
```

---

## 3. Ransomware Recovery

### 3.1 Recovery Option Evaluation Order

```
1. Restore from clean backup (verify offline backup first)
   → Check if backups were also encrypted
   → Check if NAS/cloud backups were overwritten by sync

2. Volume Shadow Copies (VSS)
   vssadmin list shadows  # List available snapshots
   mklink /D C:\Shadow \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\

3. Public decryption tools
   https://www.nomoreransom.org  # Decryption tools by ransomware type
   Use ID Ransomware to identify variant, then check for tools

4. Law enforcement cooperation
   Cybercrime unit, national CERT

5. Negotiation (last resort, not recommended)
   → Payment does not guarantee decryption
   → Legal issues (paying sanctioned groups may be illegal in some countries)
```

### 3.2 File Recovery Using VSS

```powershell
# Check available shadow copies
vssadmin list shadows /for=C:

# Mount (symlink)
$shadowPath = "\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1"
cmd /c mklink /D "C:\Shadow" "$shadowPath\"

# Copy files
Copy-Item "C:\Shadow\Users\victim\Documents\important.docx" `
    "C:\Recovered\important.docx"

# Unmount
cmd /c rmdir "C:\Shadow"
```

---

## 4. Windows Persistence Artifact Auto-Collection CLI

```python
#!/usr/bin/env python3
"""Windows Persistence Artifact Auto-Collection CLI (Remote WMI/Registry Analysis)"""

import argparse
import json
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional


@dataclass
class PersistenceArtifact:
    category: str
    name: str
    value: str
    path: str
    risk: str = "unknown"
    note: str = ""


KNOWN_LEGIT = {
    "OneDrive", "SecurityHealth", "WindowsDefender",
    "MicrosoftEdgeAutoLaunch", "Teams", "Discord",
}

SUSPICIOUS_KEYWORDS = [
    "powershell", "cmd.exe", "wscript", "cscript", "mshta",
    "regsvr32", "rundll32 ..", "certutil", "bitsadmin",
    "AppData\\Local\\Temp", "Temp\\", "ProgramData\\Temp",
    "\\Users\\Public\\", "base64", "-enc", "-encodedcommand",
]


def run_ps_command(cmd: str, target: Optional[str] = None) -> str:
    """Execute PowerShell command"""
    if target:
        full_cmd = f'Invoke-Command -ComputerName {target} -ScriptBlock {{{cmd}}}'
    else:
        full_cmd = cmd

    result = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", full_cmd],
        capture_output=True, text=True, timeout=30
    )
    return result.stdout.strip()


def assess_risk(name: str, value: str) -> str:
    """Risk assessment"""
    value_lower = value.lower()
    if any(kw.lower() in value_lower for kw in SUSPICIOUS_KEYWORDS):
        return "high"
    if name in KNOWN_LEGIT:
        return "low"
    if "temp" in value_lower or "appdata\\local\\temp" in value_lower:
        return "high"
    if any(ext in value_lower for ext in ['.vbs', '.js', '.hta', '.bat', '.ps1']):
        return "medium"
    return "low"


def main() -> None:
    parser = argparse.ArgumentParser(description="Windows Persistence Artifact Collection CLI")
    parser.add_argument("--target", help="Remote computer name (local if not specified)")
    parser.add_argument("--show-low", action="store_true", help="Also show low-risk items")
    parser.add_argument("--export", metavar="FILE", help="Export to JSON")
    parser.add_argument("--all", action="store_true", help="Collect all categories")

    args = parser.parse_args()

    if sys.platform != 'win32' and not args.target:
        print("[!] Windows-only tool. Use --target to specify remote Windows host", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Collecting artifacts {'(remote: ' + args.target + ')' if args.target else '(local)'}...")


if __name__ == "__main__":
    main()
```

---

## 5. Post-Incident Review

### 5.1 5-Why Analysis Template

```
Incident: Ransomware infection and data encryption

Why 1: Why did the ransomware execute?
→ Employee executed malicious attachment from phishing email

Why 2: Why was execution of the malicious file allowed?
→ Macro auto-execution was not disabled

Why 3: Why wasn't the macro policy configured?
→ GPO management was not systematic

Why 4: Why was GPO management inadequate?
→ IT security team was understaffed and hardening settings were not applied

Why 5: Why was there insufficient staff?
→ Security budget was not prioritized

Root Cause: Insufficient security investment at the executive level
Improvement Direction: Establish CISO role, increase security budget, GPO hardening
```

### 5.2 Improvement Recommendation Structure

| Priority | Item | Implementation Difficulty | Estimated Cost | Deadline |
|----------|------|--------------------------|----------------|----------|
| P1 | Disable macros via GPO | Low | Free | 1 week |
| P1 | Email attachment sandbox | Medium | License | 1 month |
| P2 | Enterprise-wide EDR deployment | High | Medium | 3 months |
| P3 | Offline backup configuration | Medium | Storage | 1 month |
| P3 | Employee phishing awareness training | Low | Low | Quarterly |
