> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 시스템 공격 탐지 및 방어

## 1. 메모리 보호 기법 원리

현대 운영체제는 메모리 기반 공격을 방어하기 위해 여러 하드웨어/소프트웨어 기반 보호 기법을 사용한다.

### 1.1 ASLR (Address Space Layout Randomization)

ASLR은 프로세스 메모리 레이아웃(스택, 힙, 라이브러리)을 실행 시마다 무작위로 배치하는 기법이다.

```bash
# Linux ASLR 설정 확인
cat /proc/sys/kernel/randomize_va_space
# 0 = 비활성화
# 1 = 스택/라이브러리/mmap만 무작위화
# 2 = 전체 무작위화 (기본)

# ASLR 일시 비활성화 (테스트용)
echo 0 | sudo tee /proc/sys/kernel/randomize_va_space

# 프로세스 메모리 맵 확인
cat /proc/$(pidof target_process)/maps | head -20
```

**우회 기법 (공격자 관점):**
- 정보 유출(Info Leak)로 베이스 주소 파악
- 브루트포스 (32비트 시스템)
- JIT Spray, Heap Spray

### 1.2 DEP/NX (Data Execution Prevention / No-eXecute)

데이터 영역(스택, 힙)에서의 코드 실행을 하드웨어 수준에서 차단한다.

```bash
# 바이너리의 NX 비트 활성화 여부 확인
checksec --file=/path/to/binary

# readelf로 스택 실행 권한 확인
readelf -l /path/to/binary | grep -A1 GNU_STACK
# RW 이면 NX 비활성화, RWE 이면 스택 실행 가능
```

**DEP 우회 기법:**
- ROP(Return-Oriented Programming): 기존 코드(가젯) 재사용
- ret2libc: libc 함수 직접 호출

### 1.3 Stack Canary

함수 진입 시 스택에 랜덤 값(카나리)을 삽입하고, 함수 종료 전 이 값이 바뀌었는지 검사하는 기법이다.

```bash
# 카나리 활성화 여부 확인
checksec --file=/path/to/binary
# Stack: Canary found = 카나리 활성화
# Stack: No canary found = 카나리 없음

# 컴파일 시 카나리 옵션
gcc -fstack-protector-all -o safe_binary source.c   # 카나리 활성화
gcc -fno-stack-protector -o unsafe_binary source.c  # 카나리 비활성화
```

**카나리 우회 기법:**
- 카나리 값 유출(Format String 취약점 활용)
- 포크 서버에서의 브루트포스 (카나리가 fork()로 공유됨)

### 1.4 보호 기법 전체 확인

```bash
# checksec으로 모든 보호 기법 한 번에 확인
checksec --file=/path/to/binary
# 예시 출력:
# RELRO: Full RELRO
# Stack: Canary found
# NX: NX enabled
# PIE: PIE enabled
# FORTIFY: Enabled
```

---

## 2. 버퍼 오버플로우 공격 탐지

### 2.1 Sysmon을 이용한 Windows 탐지

Sysmon(System Monitor)은 Windows 이벤트 로그에 상세 시스템 활동을 기록하는 Microsoft 도구이다.

**Sysmon 설정 예시 (sysmon-config 기반):**
```xml
<!-- sysmon-config.xml 일부 -->
<Sysmon schemaversion="4.90">
  <EventFiltering>
    <!-- 프로세스 생성 이벤트 (Event ID 1) -->
    <RuleGroup name="Process Creation" groupRelation="or">
      <ProcessCreate onmatch="include">
        <!-- cmd.exe, powershell.exe가 비정상적 부모에서 실행되는 경우 -->
        <ParentImage condition="is not">C:\Windows\explorer.exe</ParentImage>
        <Image condition="end with">cmd.exe</Image>
      </ProcessCreate>
    </RuleGroup>

    <!-- 네트워크 연결 이벤트 (Event ID 3) -->
    <RuleGroup name="Network Connect" groupRelation="or">
      <NetworkConnect onmatch="include">
        <!-- 443, 80 이외 포트로의 아웃바운드 연결 -->
        <DestinationPort condition="is not">443</DestinationPort>
        <DestinationPort condition="is not">80</DestinationPort>
        <Initiated condition="is">true</Initiated>
      </NetworkConnect>
    </RuleGroup>

    <!-- 메모리 접근 이벤트 (Event ID 10) - 코드 인젝션 탐지 -->
    <RuleGroup name="Process Access" groupRelation="or">
      <ProcessAccess onmatch="include">
        <TargetImage condition="end with">lsass.exe</TargetImage>
      </ProcessAccess>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
```

**Sysmon 설치 및 설정:**
```powershell
# Sysmon 설치 (관리자 권한)
.\Sysmon64.exe -accepteula -i sysmon-config.xml

# 설정 업데이트
.\Sysmon64.exe -c sysmon-config.xml

# 이벤트 확인
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" |
  Select-Object -First 10 |
  Format-List TimeCreated, Id, Message
```

### 2.2 Linux auditd를 이용한 탐지

```bash
# auditd 설치
apt-get install -y auditd

# 실행 파일 실행 감사 규칙 추가
auditctl -a always,exit -F arch=b64 -S execve -k exec_monitor

# setuid 비트 파일 접근 감사
auditctl -a always,exit -F arch=b64 -S setuid -k setuid_monitor

# /etc/passwd 수정 시도 감사
auditctl -w /etc/passwd -p wa -k passwd_changes

# 로그 확인
ausearch -k exec_monitor | aureport -f

# ausearch로 특정 이벤트 검색
ausearch -k setuid_monitor --start today
```

---

## 3. Active Directory 이상 탐지 룰

### 3.1 로그인 실패 패턴 탐지

**Windows 이벤트 ID 참조:**
| Event ID | 설명 |
|----------|------|
| 4625 | 계정 로그온 실패 |
| 4624 | 성공적인 로그온 |
| 4768 | Kerberos TGT 요청 |
| 4769 | Kerberos 서비스 티켓 요청 |
| 4771 | Kerberos 사전 인증 실패 |
| 4776 | NTLM 인증 시도 |
| 4648 | 명시적 자격증명 로그온 시도 |

**PowerShell 탐지 스크립트:**
```powershell
# 지난 1시간 내 동일 계정 5회 이상 로그인 실패
$threshold = 5
$timeWindow = (Get-Date).AddHours(-1)

$failedLogins = Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4625
    StartTime = $timeWindow
} | Group-Object -Property {
    ($_.Message -match 'Account Name:\s+(\S+)' | Out-Null); $Matches[1]
} | Where-Object { $_.Count -ge $threshold }

foreach ($group in $failedLogins) {
    Write-Warning "[경고] '$($group.Name)' 계정 로그인 실패 $($group.Count)회 (1시간 내)"
}
```

### 3.2 골든 티켓(Golden Ticket) 탐지

골든 티켓은 KRBTGT 계정의 해시로 위조된 Kerberos TGT이며, 유효 기간이 비정상적으로 길다.

**탐지 규칙:**
```powershell
# TGT 유효 기간이 10시간 초과인 경우 탐지 (Event ID 4769)
$suspiciousTGS = Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id      = 4769  # Kerberos 서비스 티켓 요청
} | Where-Object {
    # TicketOptions에서 비정상 플래그 확인
    $_.Message -match 'Ticket Options:\s+0x40810000' -or
    $_.Message -match 'Ticket Encryption Type:\s+0x17'  # RC4 암호화 (의심스러움)
}

$suspiciousTGS | Select-Object TimeCreated,
    @{N="Account";E={($_.Message -match 'Account Name:\s+(\S+)' | Out-Null); $Matches[1]}}
```

### 3.3 Pass-the-Hash / Pass-the-Ticket 탐지

```powershell
# NTLM 인증 + 비정상 로그온 타입 탐지 (Event ID 4624, LogonType 3)
$pthEvents = Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id      = 4624
} | Where-Object {
    $_.Message -match 'Logon Type:\s+3' -and
    $_.Message -match 'NTLM' -and
    $_.Message -notmatch 'WORKGROUP'
}

$pthEvents | Select-Object -First 20 |
    Format-Table TimeCreated, Message -AutoSize
```

---

## 4. Windows Defender 탐지 회피 방어 설정

공격자는 Defender를 우회하려 한다. 이를 방어하는 설정을 강화해야 한다.

### 4.1 ASR(Attack Surface Reduction) 규칙 활성화

```powershell
# ASR 규칙을 감사(Audit) 모드로 설정 (운영 환경에서 테스트)
$asrRules = @{
    # Office 매크로에서 Win32 API 호출 차단
    "92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B" = 2  # Audit
    # 난독화된 스크립트 실행 차단
    "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC" = 2
    # 자격증명 탈취 차단 (lsass.exe 보호)
    "9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2" = 2
    # WMI 영속성 차단
    "E6DB77E5-3DF2-4CF1-B95A-636979351E5B" = 2
}

foreach ($rule in $asrRules.GetEnumerator()) {
    Add-MpPreference -AttackSurfaceReductionRules_Ids $rule.Key `
                     -AttackSurfaceReductionRules_Actions $rule.Value
}

# 설정 확인
Get-MpPreference | Select-Object AttackSurfaceReductionRules_*
```

### 4.2 Controlled Folder Access 활성화

```powershell
# 랜섬웨어 방어: 보호된 폴더에 대한 무단 접근 차단
Set-MpPreference -EnableControlledFolderAccess Enabled

# 허용할 애플리케이션 추가
Add-MpPreference -ControlledFolderAccessAllowedApplications "C:\MyApp\app.exe"
```

### 4.3 PowerShell 스크립트 블록 로깅

```powershell
# 레지스트리 설정
$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
New-Item -Path $regPath -Force | Out-Null
Set-ItemProperty -Path $regPath -Name "EnableScriptBlockLogging" -Value 1

# 실행 정책 강화
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine
```

---

## 5. Python Windows 이벤트 로그 분석 + 이상 탐지

```python
#!/usr/bin/env python3
"""
Windows 이벤트 로그 분석 + 이상 탐지 도구
로컬 또는 원격 Windows 시스템의 보안 이벤트를 수집·분석한다.

의존성:
  pip install python-evtx pywin32  (Windows 전용)
  또는 evtx 파일을 분석할 경우: pip install python-evtx
"""

import argparse
import collections
import sys
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

try:
    import Evtx.Evtx as evtx
    import Evtx.Views as e_views
    import xml.etree.ElementTree as ET
    HAS_EVTX = True
except ImportError:
    HAS_EVTX = False

# Windows 보안 이벤트 ID 매핑
SECURITY_EVENTS: dict[int, str] = {
    4624: "로그온 성공",
    4625: "로그온 실패",
    4648: "명시적 자격증명 로그온",
    4672: "특권 로그온",
    4698: "예약 작업 생성",
    4702: "예약 작업 수정",
    4719: "시스템 감사 정책 변경",
    4728: "보안 그룹 멤버 추가",
    4732: "로컬 그룹 멤버 추가",
    4768: "Kerberos TGT 요청",
    4769: "Kerberos 서비스 티켓 요청",
    4771: "Kerberos 사전 인증 실패",
    4776: "NTLM 인증 시도",
    7045: "새 서비스 설치",
}

# 이상 탐지 임계값
THRESHOLDS = {
    "failed_login_per_hour": 5,       # 1시간 내 로그인 실패 횟수
    "kerberoast_tickets_per_min": 10, # 1분 내 Kerberos 티켓 요청 수
    "new_service_alert": 1,           # 신규 서비스 설치 즉시 알림
}


@dataclass
class SecurityEvent:
    event_id: int
    timestamp: datetime
    account_name: str = ""
    source_ip: str = ""
    logon_type: str = ""
    status: str = ""
    target_service: str = ""
    raw: str = ""


@dataclass
class DetectionResult:
    rule_name: str
    severity: str  # "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
    description: str
    events: list[SecurityEvent] = field(default_factory=list)
    count: int = 0

    def __str__(self) -> str:
        return (
            f"[{self.severity}] {self.rule_name}: {self.description}"
            f" (이벤트 {self.count}건)"
        )


def parse_evtx_file(evtx_path: str) -> list[SecurityEvent]:
    """EVTX 파일을 파싱해 SecurityEvent 목록을 반환한다."""
    if not HAS_EVTX:
        print("[!] python-evtx 필요: pip install python-evtx", file=sys.stderr)
        return []

    results: list[SecurityEvent] = []
    ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

    with evtx.Evtx(evtx_path) as log:
        for record in log.records():
            try:
                xml_str = record.xml()
                root = ET.fromstring(xml_str)

                # 이벤트 ID
                event_id_elem = root.find(".//e:EventID", ns)
                if event_id_elem is None:
                    continue
                event_id = int(event_id_elem.text or 0)

                # 타임스탬프
                ts_elem = root.find(".//e:TimeCreated", ns)
                ts_str = ts_elem.get("SystemTime", "") if ts_elem is not None else ""
                try:
                    ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                except ValueError:
                    ts = datetime.now()

                # EventData 파싱
                def get_data(name: str) -> str:
                    elem = root.find(f'.//e:Data[@Name="{name}"]', ns)
                    return (elem.text or "").strip() if elem is not None else ""

                evt = SecurityEvent(
                    event_id=event_id,
                    timestamp=ts,
                    account_name=get_data("TargetUserName") or get_data("SubjectUserName"),
                    source_ip=get_data("IpAddress"),
                    logon_type=get_data("LogonType"),
                    status=get_data("Status"),
                    target_service=get_data("ServiceName"),
                    raw=xml_str[:200],
                )
                results.append(evt)
            except Exception:
                continue

    return results


def detect_brute_force(
    events: list[SecurityEvent], window_hours: int = 1
) -> list[DetectionResult]:
    """반복 로그인 실패 패턴을 탐지한다."""
    detections: list[DetectionResult] = []
    threshold = THRESHOLDS["failed_login_per_hour"]
    cutoff = datetime.now() - timedelta(hours=window_hours)

    failed = [
        e for e in events
        if e.event_id == 4625 and e.timestamp.replace(tzinfo=None) >= cutoff
    ]

    # 계정별 실패 횟수 집계
    by_account: dict[str, list[SecurityEvent]] = collections.defaultdict(list)
    for evt in failed:
        if evt.account_name:
            by_account[evt.account_name].append(evt)

    for account, evts in by_account.items():
        if len(evts) >= threshold:
            detections.append(
                DetectionResult(
                    rule_name="BruteForce",
                    severity="HIGH",
                    description=f"계정 '{account}' 로그인 실패 {len(evts)}회 ({window_hours}h 내)",
                    events=evts,
                    count=len(evts),
                )
            )

    return detections


def detect_kerberoasting(
    events: list[SecurityEvent], window_minutes: int = 1
) -> list[DetectionResult]:
    """Kerberoasting 공격 패턴(짧은 시간에 대량 TGS 요청)을 탐지한다."""
    detections: list[DetectionResult] = []
    threshold = THRESHOLDS["kerberoast_tickets_per_min"]
    cutoff = datetime.now() - timedelta(minutes=window_minutes)

    tgs_events = [
        e for e in events
        if e.event_id == 4769 and e.timestamp.replace(tzinfo=None) >= cutoff
    ]

    by_account: dict[str, list[SecurityEvent]] = collections.defaultdict(list)
    for evt in tgs_events:
        by_account[evt.account_name].append(evt)

    for account, evts in by_account.items():
        if len(evts) >= threshold:
            detections.append(
                DetectionResult(
                    rule_name="Kerberoasting",
                    severity="CRITICAL",
                    description=(
                        f"계정 '{account}' Kerberos TGS 요청 {len(evts)}회 "
                        f"({window_minutes}분 내) — Kerberoasting 의심"
                    ),
                    events=evts,
                    count=len(evts),
                )
            )

    return detections


def detect_new_services(events: list[SecurityEvent]) -> list[DetectionResult]:
    """신규 서비스 설치(Event ID 7045)를 탐지한다."""
    detections: list[DetectionResult] = []
    svc_events = [e for e in events if e.event_id == 7045]
    for evt in svc_events:
        detections.append(
            DetectionResult(
                rule_name="NewService",
                severity="MEDIUM",
                description=f"새 서비스 설치: '{evt.target_service}' at {evt.timestamp}",
                events=[evt],
                count=1,
            )
        )
    return detections


def detect_privilege_escalation(events: list[SecurityEvent]) -> list[DetectionResult]:
    """비정상 권한 상승 패턴(로그온 성공 직후 특권 로그온)을 탐지한다."""
    detections: list[DetectionResult] = []
    priv_events = [e for e in events if e.event_id == 4672]
    logon_events = {e.account_name: e for e in events if e.event_id == 4624}

    for evt in priv_events:
        if evt.account_name in ("SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE"):
            continue
        if evt.account_name in logon_events:
            detections.append(
                DetectionResult(
                    rule_name="PrivilegeEscalation",
                    severity="HIGH",
                    description=f"계정 '{evt.account_name}' 특권 로그온 탐지",
                    events=[evt],
                    count=1,
                )
            )

    return detections


def analyze_events(events: list[SecurityEvent]) -> list[DetectionResult]:
    """모든 탐지 규칙을 실행한다."""
    all_detections: list[DetectionResult] = []
    all_detections.extend(detect_brute_force(events))
    all_detections.extend(detect_kerberoasting(events))
    all_detections.extend(detect_new_services(events))
    all_detections.extend(detect_privilege_escalation(events))
    return all_detections


def print_summary(events: list[SecurityEvent]) -> None:
    """이벤트 통계를 출력한다."""
    counter: collections.Counter[int] = collections.Counter(e.event_id for e in events)
    print(f"\n[*] 총 이벤트 수: {len(events)}")
    print("[*] 이벤트 ID별 집계:")
    for event_id, count in counter.most_common(10):
        name = SECURITY_EVENTS.get(event_id, "알 수 없음")
        print(f"    {event_id:6d}  {name:<30}  {count:>5}건")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Windows 이벤트 로그 분석 + 이상 탐지",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
예시:
  python3 event_analyzer.py Security.evtx
  python3 event_analyzer.py Security.evtx --severity HIGH CRITICAL
  python3 event_analyzer.py Security.evtx --summary-only
        """,
    )
    parser.add_argument("evtx_file", help=".evtx 이벤트 로그 파일 경로")
    parser.add_argument(
        "--severity",
        nargs="+",
        choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
        default=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
        help="출력할 심각도 필터",
    )
    parser.add_argument(
        "--summary-only", action="store_true", help="탐지 결과 없이 통계만 출력"
    )
    args = parser.parse_args()

    if not Path(args.evtx_file).exists():
        print(f"[오류] 파일을 찾을 수 없습니다: {args.evtx_file}", file=sys.stderr)
        sys.exit(1)

    print(f"[*] {args.evtx_file} 파싱 중...")
    events = parse_evtx_file(args.evtx_file)
    print(f"[+] {len(events)}개 이벤트 로드 완료")

    print_summary(events)

    if args.summary_only:
        return

    detections = analyze_events(events)
    filtered = [d for d in detections if d.severity in args.severity]

    if not filtered:
        print("\n[+] 이상 징후를 탐지하지 못했습니다.")
        return

    print(f"\n[!] 탐지 결과 ({len(filtered)}건):")
    for d in sorted(filtered, key=lambda x: ["LOW","MEDIUM","HIGH","CRITICAL"].index(x.severity), reverse=True):
        print(f"  {d}")


if __name__ == "__main__":
    main()
```

**사용 예시:**
```bash
# EVTX 파일 분석
python3 event_analyzer.py Security.evtx

# HIGH 이상 심각도만 출력
python3 event_analyzer.py Security.evtx --severity HIGH CRITICAL

# 통계만 확인
python3 event_analyzer.py Security.evtx --summary-only
```

---

## 참고 자료

- SwiftOnSecurity Sysmon 설정: https://github.com/SwiftOnSecurity/sysmon-config
- Microsoft Sysmon 공식 문서: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon

---

<!-- detect-validate-03 -->
## 시스템 방어 통제의 운영 검증

이 문서는 탐지·방어를 다루므로, 여기서는 *통제가 있는가*를 넘어 **각 통제가 런타임에 실제 작동하고 회귀하지 않는가**를 검증하는 데 집중한다. "설정됨 ≠ 작동함"이며, 방어는 공격 PoC 로 지속 재검증해야 한다.

### 공격 → 계층 → 통제(방어자) → 탐지 신호

| 방어 통제 | 검증 질문 | 측정 신호 | 회귀 위험 |
|---|---|---|---|
| 감사 로깅(auditd) | 핵심 행위가 기록되는가? | 룰 매칭 이벤트 수 | 룰 미적용/볼륨 폭주로 누락 |
| EDR/AV | 알려진 공격을 잡는가? | 탐지율, 우회 통과 수 | 업데이트 후 룰 무력화 |
| 무결성(AIDE/FIM) | 변조를 감지하는가? | 변경 알림 수 | 베이스라인 미갱신 |
| 권한최소화 | 권한상승을 막는가? | sudo/SUID 이상 | 새 SUID 바이너리 유입 |

### 방어 검증 (직접 확인)

```bash
# 1) auditd 핵심 룰이 실제 적용·발화하는지 검증(소유 호스트) — 예: /etc/shadow 접근 감사
sudo auditctl -l | grep -E 'shadow|execve' || echo 'NO AUDIT RULES — 룰 미적용'
sudo ausearch -k identity --start recent 2>/dev/null | tail   # 발화 이벤트 확인
# 2) 의도치 않은 SUID 바이너리 유입(권한상승 표면) 점검
find / -perm -4000 -type f 2>/dev/null | sort > /tmp/suid.now
# 베이스라인과 diff 해 신규 SUID 가 0 이어야 정상: diff suid.base /tmp/suid.now
```

> 검증은 반드시 **소유한 시스템·통제 환경**에서만. 방어는 한 번 통과로 끝나지 않는다 — 패치/설정 변경마다 공격 PoC 를 재실행해 탐지·차단이 유지되는지(회귀 없는지) 확인한다([[13_SOC_Blue_Team]], [[68_Purple_Team]]).

**최신 기법·통제 (2025–2026):**
- EDR·Sysmon·ETW 결합 텔레메트리가 탐지 기반 — 룰이 실제 공격 신호에서 발화하는지 검증([[13_SOC_Blue_Team]])
- 로그 무결성(전달·불변)·텔레메트리 공백 탐지가 핵심 — 로깅이 강제되는지 확인([[40_Threat_Hunting]])

---

<a name="english"></a>

# System Attack Detection and Defense

## 1. Memory Protection Mechanisms

Modern operating systems employ multiple hardware and software protections against memory-based attacks.

### 1.1 ASLR (Address Space Layout Randomization)

ASLR randomizes the memory layout (stack, heap, libraries) on each execution, making it harder for attackers to predict addresses.

```bash
# Check Linux ASLR setting
cat /proc/sys/kernel/randomize_va_space
# 0 = disabled, 1 = partial, 2 = full (default)

# Disable temporarily for testing
echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
```

**Bypass techniques (attacker perspective):**
- Information leak to obtain base address
- Brute force (32-bit only)
- JIT Spray, Heap Spray

### 1.2 DEP/NX (Data Execution Prevention)

Hardware-enforced prevention of code execution from data segments (stack, heap).

```bash
checksec --file=/path/to/binary
readelf -l /path/to/binary | grep -A1 GNU_STACK
```

**Bypass:** Return-Oriented Programming (ROP), ret2libc

### 1.3 Stack Canary

A random value placed on the stack before the return address; checked before function return.

```bash
checksec --file=/path/to/binary  # "Canary found" = enabled
```

**Bypass:** Format string leak, fork-server brute force

### 1.4 Full Protection Check

```bash
checksec --file=/path/to/binary
# Shows: RELRO, Stack canary, NX, PIE, FORTIFY status
```

---

## 2. Buffer Overflow Attack Detection

### 2.1 Sysmon on Windows

Key Sysmon event IDs for detecting exploitation:
- **Event ID 1** – Process creation (detect cmd/powershell spawned from unusual parents)
- **Event ID 3** – Network connection (detect outbound C2 channels)
- **Event ID 10** – Process access (detect lsass.exe credential dumping)

```powershell
# Install Sysmon with config
.\Sysmon64.exe -accepteula -i sysmon-config.xml

# View recent events
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" |
  Select-Object -First 10 | Format-List TimeCreated, Id, Message
```

### 2.2 Linux auditd

```bash
# Monitor execve syscalls
auditctl -a always,exit -F arch=b64 -S execve -k exec_monitor

# Watch for setuid changes
auditctl -a always,exit -F arch=b64 -S setuid -k setuid_monitor

# Monitor /etc/passwd modifications
auditctl -w /etc/passwd -p wa -k passwd_changes

# Review findings
ausearch -k exec_monitor | aureport -f
```

---

## 3. Active Directory Anomaly Detection

### 3.1 Failed Login Pattern Detection

Key Windows Security Event IDs:
| Event ID | Description |
|----------|-------------|
| 4625 | Account logon failure |
| 4769 | Kerberos service ticket request |
| 4771 | Kerberos pre-authentication failure |
| 7045 | New service installed |

```powershell
# Detect 5+ failed logins for same account within 1 hour
$failedLogins = Get-WinEvent -FilterHashtable @{
    LogName='Security'; Id=4625; StartTime=(Get-Date).AddHours(-1)
} | Group-Object { ($_.Message -match 'Account Name:\s+(\S+)' | Out-Null); $Matches[1] } |
    Where-Object { $_.Count -ge 5 }

$failedLogins | ForEach-Object {
    Write-Warning "Account '$($_.Name)' failed login $($_.Count) times in 1h"
}
```

### 3.2 Golden Ticket Detection

Golden Tickets are forged TGTs created with the KRBTGT hash — typically with abnormally long validity (>10h).

```powershell
# Detect TGS requests with RC4 encryption (weak, suspicious)
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4769} |
  Where-Object { $_.Message -match 'Ticket Encryption Type:\s+0x17' } |
  Select-Object TimeCreated, Message
```

### 3.3 Pass-the-Hash Detection

```powershell
# NTLM LogonType 3 from unexpected sources
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624} |
  Where-Object {
    $_.Message -match 'Logon Type:\s+3' -and $_.Message -match 'NTLM'
  } | Select-Object -First 20 | Format-Table TimeCreated, Message -AutoSize
```

---

## 4. Windows Defender Hardening

### 4.1 Attack Surface Reduction (ASR) Rules

```powershell
# Enable ASR rules in audit mode first
Add-MpPreference `
  -AttackSurfaceReductionRules_Ids "9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2" `
  -AttackSurfaceReductionRules_Actions 2  # 2 = Audit, 1 = Block

Get-MpPreference | Select-Object AttackSurfaceReductionRules_*
```

### 4.2 Controlled Folder Access and Script Logging

```powershell
# Enable ransomware protection
Set-MpPreference -EnableControlledFolderAccess Enabled

# Enable PowerShell script block logging
$p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
New-Item -Path $p -Force | Out-Null
Set-ItemProperty -Path $p -Name "EnableScriptBlockLogging" -Value 1
```

---

## 5. Python Windows Event Log Analyzer

The Python script above (see Korean section) provides a full event log analysis tool:

- **Brute force detection**: flags accounts with 5+ failures in 1 hour
- **Kerberoasting detection**: flags accounts requesting 10+ TGS tickets per minute
- **New service alerts**: immediate notification on Event ID 7045
- **Privilege escalation**: cross-correlates Event IDs 4624 and 4672

```bash
python3 event_analyzer.py Security.evtx --severity HIGH CRITICAL
```

---

## References

- SwiftOnSecurity Sysmon Config: https://github.com/SwiftOnSecurity/sysmon-config
- Microsoft Sysmon Documentation: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon

<!-- detect-validate-03 -->
## Operational Validation of System Defense Controls

Since this document covers detection/defense, here we go beyond *does the control exist* to verify **whether each works at runtime and does not regress**. "Configured != working" — defenses must be continuously re-validated with attack PoCs.

### Attack -> Layer -> Control (defender) -> Detection signal

| Defense control | Validation question | Measured signal | Regression risk |
|---|---|---|---|
| Audit logging (auditd) | Are key actions recorded? | Rule-matched event count | Missed via unapplied rules/volume flood |
| EDR/AV | Catches known attacks? | Detection rate, bypass passes | Neutralized after updates |
| Integrity (AIDE/FIM) | Detects tampering? | Change-alert count | Stale baseline |
| Least privilege | Stops escalation? | sudo/SUID anomalies | New SUID binaries introduced |

### Defense validation (verify directly)

```bash
# 1) Verify key auditd rules are applied and firing (own host) — e.g. /etc/shadow access audit
sudo auditctl -l | grep -E 'shadow|execve' || echo 'NO AUDIT RULES — not applied'
sudo ausearch -k identity --start recent 2>/dev/null | tail   # confirm fired events
# 2) Check for unintended SUID binaries (privilege-escalation surface)
find / -perm -4000 -type f 2>/dev/null | sort > /tmp/suid.now
# diff against baseline; new SUID count should be 0: diff suid.base /tmp/suid.now
```

> Validate only on **owned systems / controlled environments**. Defense is not one-and-done — re-run attack PoCs on every patch/config change to confirm detection/blocking holds (no regression) ([[13_SOC_Blue_Team]], [[68_Purple_Team]]).
