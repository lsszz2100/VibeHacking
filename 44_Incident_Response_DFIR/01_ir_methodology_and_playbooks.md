> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 인시던트 대응 방법론과 플레이북

인시던트 대응(IR)은 보안 사고 발생 시 피해를 최소화하고 빠르게 복구하는 체계적 프로세스다. NIST SP 800-61r2와 PICERL 프레임워크를 기반으로 한 실전 플레이북을 다룬다.

---

## 1. IR 프레임워크 비교

### 1.1 NIST SP 800-61r2 생명주기

```
1. 준비 (Preparation)
   ├── IR 팀 구성 및 역할 정의
   ├── 도구·환경 준비 (SIEM, EDR, 포렌식 워크스테이션)
   ├── 플레이북 작성 및 훈련
   └── 연락망·에스컬레이션 절차

2. 탐지 및 분석 (Detection & Analysis)
   ├── 알림 접수 (SIEM, EDR, 사용자 신고)
   ├── 트리아지: 진짜 인시던트인지 판단
   ├── 영향 범위 평가
   └── 인시던트 분류·우선순위 지정

3. 격리, 박멸, 복구 (Containment, Eradication, Recovery)
   ├── 격리: 감염 시스템 네트워크 분리
   ├── 박멸: 악성코드·지속성 제거
   └── 복구: 시스템 복원·정상화

4. 사후 활동 (Post-Incident Activity)
   ├── 사후분석 회의 (Lessons Learned)
   ├── 보고서 작성
   └── 방어 개선 적용
```

### 1.2 PICERL 프레임워크

| 단계 | 약자 | 핵심 활동 |
|------|------|---------|
| 준비 | **P**reparation | 팀·도구·플레이북 준비 |
| 식별 | **I**dentification | 인시던트 탐지 및 분류 |
| 격리 | **C**ontainment | 확산 방지, 단기·장기 격리 |
| 박멸 | **E**radication | 루트 원인 제거 |
| 복구 | **R**ecovery | 서비스 정상화 |
| 교훈 | **L**essons Learned | 사후분석, 개선 |

---

## 2. 인시던트 분류 체계

### 2.1 심각도 등급

| 등급 | 기준 | 대응 시간 | 에스컬레이션 |
|------|------|----------|------------|
| P1 — Critical | 핵심 시스템 침해, 데이터 유출 진행 중 | 즉시 (15분 이내) | CISO, CEO |
| P2 — High | 랜섬웨어 감지, 광범위 감염 가능 | 1시간 이내 | CISO, IT Director |
| P3 — Medium | 단일 시스템 악성코드, 피싱 성공 | 4시간 이내 | IR 팀장 |
| P4 — Low | 의심 이메일, 오탐 가능 알림 | 24시간 이내 | IR 분석가 |

### 2.2 인시던트 유형별 분류

```
악성코드:
- 랜섬웨어: P1 (즉시 격리 필요)
- 스파이웨어/RAT: P2 (데이터 유출 위험)
- 애드웨어: P4 (업무 영향 낮음)

접근 침해:
- 권한 상승 성공: P1
- 무차별 대입 성공: P2
- 실패한 무차별 대입: P4

내부자 위협:
- 대량 데이터 다운로드: P1~P2
- 비인가 시스템 접근: P2~P3

DDoS:
- 서비스 중단: P1
- 성능 저하: P2~P3

데이터 유출:
- 개인정보 대량 유출: P1 (법적 신고 의무)
- 기업 기밀 유출: P1~P2
```

---

## 3. 플레이북: 랜섬웨어

### 3.1 초기 대응 (0~30분)

```
[탐지]
- SIEM 알림: 대량 파일 암호화, .locked/.encrypted 확장자
- 사용자 신고: "파일이 열리지 않아요", 랜섬노트 발견

[즉시 조치]
□ 감염 의심 시스템 즉시 네트워크 분리 (케이블 제거 또는 방화벽 차단)
□ 공유 드라이브 마운트 해제 또는 읽기 전용 전환
□ 도메인 컨트롤러 접근 차단 (측면 이동 방지)
□ IR 팀장 및 CISO에게 에스컬레이션
□ 법적 증거 보존: 메모리 덤프 (전원 끄기 전)

[절대 하지 말 것]
✗ 감염 시스템 재부팅 (메모리 증거 소실)
✗ 복호화 시도 (2차 피해 가능)
✗ 백업 시스템에 감염 시스템 연결
```

### 3.2 분석 및 범위 파악 (30분~2시간)

```
[범위 파악]
1. EDR/SIEM에서 최초 감염 시점 및 환자 0 파악
2. 측면 이동 경로 추적: 로그인 이벤트 4624, 원격 실행 4688
3. 암호화된 파일 확장자 및 랜섬노트 내용으로 랜섬웨어 종류 식별
   → ID Ransomware (https://id-ransomware.malwarehunterteam.com/)

[식별 질문]
- 최초 침입 벡터: 피싱 이메일? RDP 브루트포스? VPN 취약점?
- 도메인 컨트롤러가 감염되었는가?
- 백업 시스템이 영향을 받았는가?
- 어떤 데이터가 암호화/유출되었는가?
```

### 3.3 격리 전략

```bash
# Windows 방화벽으로 격리 (원격 실행)
netsh advfirewall set allprofiles state on
netsh advfirewall firewall add rule name="IR_Block_All" dir=in action=block
netsh advfirewall firewall add rule name="IR_Allow_IR_Team" dir=in action=allow remoteip=10.0.0.100

# Active Directory 계정 비활성화 (감염 계정)
Disable-ADAccount -Identity "compromised_user"
Set-ADAccountPassword -Identity "compromised_user" -Reset -NewPassword (ConvertTo-SecureString -AsPlainText "TempSecure2026!" -Force)
```

---

## 4. 플레이북: 피싱 대응

```
[탐지]
- 사용자 신고: 의심스러운 이메일
- 이메일 게이트웨이 알림
- 크리덴셜 피싱 사이트 탐지

[초기 분석]
□ 이메일 원본 헤더 분석: Return-Path, Received, DKIM/SPF/DMARC
□ 링크 분석: URLScan.io, VirusTotal (클릭하지 말 것)
□ 첨부파일 분석: 격리된 샌드박스 사용 (Any.run, Cuckoo)
□ 동일 이메일 수신자 파악 → 클릭 여부 확인

[크리덴셜 노출 시]
□ 즉시 비밀번호 변경 (MFA 추가)
□ 세션 토큰 강제 만료
□ 활성 세션 로그 검토 (비정상 지역/시간 로그인)
□ 최근 이메일 전달 규칙 확인 (공격자가 설정했을 수 있음)
```

---

## 5. 인시던트 타임라인 자동 생성 CLI

```python
#!/usr/bin/env python3
"""인시던트 타임라인 자동 생성 CLI
로그 파일 입력 → 이벤트 시간순 정렬·출력"""

import argparse
import re
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional


# 로그 형식 패턴 정의
LOG_PATTERNS = [
    # Windows Event Log (evtx 텍스트 내보내기)
    {
        "name": "windows_event",
        "pattern": re.compile(
            r'(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})'
            r'.*?EventID["\s:]+(?P<event_id>\d+)'
            r'.*?(?:AccountName|SubjectUserName)["\s:]+(?P<user>\S+)',
            re.DOTALL
        ),
        "format": "%Y-%m-%dT%H:%M:%S",
    },
    # Syslog 형식
    {
        "name": "syslog",
        "pattern": re.compile(
            r'(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})'
            r'\s+(?P<host>\S+)\s+(?P<process>\S+):\s+(?P<message>.+)'
        ),
        "format": "%b %d %H:%M:%S",
    },
    # Apache/Nginx Access Log
    {
        "name": "apache",
        "pattern": re.compile(
            r'(?P<ip>\d+\.\d+\.\d+\.\d+).*?\[(?P<timestamp>[^\]]+)\]'
            r'\s+"(?P<method>\w+)\s+(?P<path>\S+)\s+HTTP/[\d.]+"'
            r'\s+(?P<status>\d+)'
        ),
        "format": "%d/%b/%Y:%H:%M:%S %z",
    },
    # Generic ISO8601
    {
        "name": "iso8601",
        "pattern": re.compile(
            r'(?P<timestamp>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)'
            r'\s+(?P<message>.+)'
        ),
        "format": "%Y-%m-%dT%H:%M:%S",
    },
]

SUSPICIOUS_KEYWORDS = [
    "failed", "denied", "error", "unauthorized", "privilege", "escalat",
    "admin", "root", "sudo", "powershell", "cmd.exe", "mimikatz",
    "lsass", "pass the hash", "kerberoast", "lateral", "ransomware",
    "encrypt", "exfil", "download", "upload", "beacon", "c2", "c&c",
]


@dataclass
class LogEvent:
    timestamp: datetime
    source_file: str
    raw_line: str
    log_type: str
    parsed: dict
    is_suspicious: bool = False
    tags: list[str] = None

    def __post_init__(self):
        if self.tags is None:
            self.tags = []
        # 의심 키워드 탐지
        line_lower = self.raw_line.lower()
        self.is_suspicious = any(kw in line_lower for kw in SUSPICIOUS_KEYWORDS)
        if self.is_suspicious:
            self.tags = [kw for kw in SUSPICIOUS_KEYWORDS if kw in line_lower][:3]


def parse_log_file(filepath: Path, log_type: Optional[str] = None) -> list[LogEvent]:
    """로그 파일 파싱"""
    events = []

    try:
        content = filepath.read_text(encoding='utf-8', errors='replace')
    except IOError as e:
        print(f"[!] 파일 읽기 실패 {filepath}: {e}", file=sys.stderr)
        return events

    patterns = LOG_PATTERNS
    if log_type:
        patterns = [p for p in LOG_PATTERNS if p['name'] == log_type]

    for line in content.splitlines():
        line = line.strip()
        if not line:
            continue

        for pdef in patterns:
            m = pdef['pattern'].search(line)
            if m:
                ts_str = m.group('timestamp').strip()
                # 연도 없는 syslog 처리
                if pdef['name'] == 'syslog':
                    ts_str = f"{datetime.now().year} {ts_str}"
                    fmt = f"%Y {pdef['format']}"
                else:
                    fmt = pdef['format']

                try:
                    # 타임존 suffix 제거
                    ts_str_clean = re.sub(r'Z$|[+-]\d{2}:?\d{2}$', '', ts_str)
                    ts = datetime.strptime(ts_str_clean[:19], fmt[:len('%Y-%m-%dT%H:%M:%S')])
                except ValueError:
                    try:
                        ts = datetime.fromisoformat(ts_str_clean[:19])
                    except ValueError:
                        continue

                events.append(LogEvent(
                    timestamp=ts,
                    source_file=filepath.name,
                    raw_line=line[:200],
                    log_type=pdef['name'],
                    parsed=m.groupdict(),
                ))
                break  # 첫 매칭 패턴 사용

    return events


def build_timeline(log_files: list[str], suspicious_only: bool = False) -> list[LogEvent]:
    all_events: list[LogEvent] = []

    for path_str in log_files:
        path = Path(path_str)
        if not path.exists():
            print(f"[!] 파일 없음: {path}", file=sys.stderr)
            continue
        events = parse_log_file(path)
        all_events.extend(events)
        print(f"[+] {path.name}: {len(events)}개 이벤트 파싱")

    all_events.sort(key=lambda e: e.timestamp)

    if suspicious_only:
        all_events = [e for e in all_events if e.is_suspicious]

    return all_events


def print_timeline(events: list[LogEvent], limit: int = 100) -> None:
    print(f"\n{'='*70}")
    print(f"인시던트 타임라인 — {len(events)}개 이벤트")
    print(f"{'='*70}\n")

    if events:
        print(f"[시작] {events[0].timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"[종료] {events[-1].timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
        duration = events[-1].timestamp - events[0].timestamp
        print(f"[기간] {duration}\n")

    for event in events[:limit]:
        flag = "⚠ " if event.is_suspicious else "  "
        ts = event.timestamp.strftime("%m-%d %H:%M:%S")
        src = event.source_file[:15].ljust(15)
        msg = event.raw_line[:80]
        tags = f" [{','.join(event.tags)}]" if event.tags else ""
        print(f"{flag}{ts} | {src} | {msg}{tags}")

    if len(events) > limit:
        print(f"\n... 이하 {len(events) - limit}개 생략 (--limit 옵션으로 조정)")


def export_timeline_md(events: list[LogEvent], output: str) -> None:
    lines = [
        "# 인시던트 타임라인",
        "",
        f"생성: {datetime.now().strftime('%Y-%m-%d %H:%M')}  ",
        f"총 이벤트: {len(events)}개  ",
        f"의심 이벤트: {sum(1 for e in events if e.is_suspicious)}개",
        "",
        "| 시간 | 소스 | 유형 | 내용 | 태그 |",
        "|------|------|------|------|------|",
    ]

    for event in events:
        ts = event.timestamp.strftime("%Y-%m-%d %H:%M:%S")
        flag = "⚠" if event.is_suspicious else ""
        tags = ",".join(event.tags) if event.tags else "-"
        msg = event.raw_line[:100].replace("|", "\\|")
        lines.append(f"| {ts} | {event.source_file} | {event.log_type} | {flag}{msg} | {tags} |")

    Path(output).write_text('\n'.join(lines), encoding='utf-8')
    print(f"[+] 타임라인 마크다운 저장: {output}")


def main() -> None:
    parser = argparse.ArgumentParser(description="인시던트 타임라인 자동 생성 CLI")
    parser.add_argument("logs", nargs="+", help="분석할 로그 파일 경로")
    parser.add_argument("--suspicious-only", action="store_true", help="의심 이벤트만 표시")
    parser.add_argument("--limit", type=int, default=200, help="출력 이벤트 수 제한")
    parser.add_argument("--export-md", metavar="FILE", help="마크다운 타임라인 내보내기")

    args = parser.parse_args()

    events = build_timeline(args.logs, args.suspicious_only)
    print_timeline(events, args.limit)

    if args.export_md:
        export_timeline_md(events, args.export_md)


if __name__ == "__main__":
    main()
```

**사용 예시:**
```bash
# 기본 타임라인 생성
python ir_timeline.py auth.log syslog apache.log

# 의심 이벤트만 필터링
python ir_timeline.py *.log --suspicious-only --limit 50

# 마크다운 보고서 생성
python ir_timeline.py *.log --export-md incident_timeline.md
```

---

## 6. 에스컬레이션 트리

```
P4 알림 접수
  └→ IR 분석가 트리아지
       ├── P4 확인 → 티켓 처리 후 종료
       └── P3+ 확인
             └→ IR 팀장 에스컬레이션
                  ├── P3 처리 → 표준 절차
                  └── P2+ 확인
                        └→ CISO 에스컬레이션
                             ├── P2 처리 → IR 팀 풀가동
                             └── P1 확인
                                   └→ CEO + 법무팀 + (필요 시) 당국
```

---

<a name="english"></a>

# Incident Response Methodology and Playbooks

Incident Response (IR) is a systematic process for minimizing damage and rapidly recovering when a security incident occurs. This document covers practical playbooks based on the NIST SP 800-61r2 and PICERL frameworks.

---

## 1. IR Framework Comparison

### 1.1 NIST SP 800-61r2 Lifecycle

```
1. Preparation
   ├── Forming the IR team and defining roles
   ├── Preparing tools and environment (SIEM, EDR, forensic workstation)
   ├── Writing playbooks and conducting drills
   └── Contact lists and escalation procedures

2. Detection & Analysis
   ├── Receiving alerts (SIEM, EDR, user reports)
   ├── Triage: determining whether it is a real incident
   ├── Assessing the scope of impact
   └── Classifying and prioritizing the incident

3. Containment, Eradication, Recovery
   ├── Containment: isolating infected systems from the network
   ├── Eradication: removing malware and persistence mechanisms
   └── Recovery: restoring systems to normal operation

4. Post-Incident Activity
   ├── Post-incident review meeting (Lessons Learned)
   ├── Writing the incident report
   └── Applying defensive improvements
```

### 1.2 PICERL Framework

| Phase | Acronym | Key Activities |
|-------|---------|---------------|
| Preparation | **P**reparation | Prepare team, tools, and playbooks |
| Identification | **I**dentification | Detect and classify the incident |
| Containment | **C**ontainment | Prevent spread; short-term and long-term isolation |
| Eradication | **E**radication | Remove the root cause |
| Recovery | **R**ecovery | Restore normal service operations |
| Lessons Learned | **L**essons Learned | Post-incident analysis and improvement |

---

## 2. Incident Classification System

### 2.1 Severity Levels

| Level | Criteria | Response Time | Escalation |
|-------|----------|--------------|------------|
| P1 — Critical | Core system compromised, data exfiltration in progress | Immediate (within 15 min) | CISO, CEO |
| P2 — High | Ransomware detected, widespread infection possible | Within 1 hour | CISO, IT Director |
| P3 — Medium | Single-system malware, successful phishing | Within 4 hours | IR Team Lead |
| P4 — Low | Suspicious email, alert that may be a false positive | Within 24 hours | IR Analyst |

### 2.2 Classification by Incident Type

```
Malware:
- Ransomware: P1 (immediate isolation required)
- Spyware/RAT: P2 (risk of data exfiltration)
- Adware: P4 (low business impact)

Access Compromise:
- Successful privilege escalation: P1
- Successful brute-force: P2
- Failed brute-force: P4

Insider Threat:
- Mass data download: P1~P2
- Unauthorized system access: P2~P3

DDoS:
- Service outage: P1
- Performance degradation: P2~P3

Data Exfiltration:
- Mass personal data leak: P1 (legal reporting obligation)
- Corporate confidential data leak: P1~P2
```

---

## 3. Playbook: Ransomware

### 3.1 Initial Response (0–30 Minutes)

```
[Detection]
- SIEM alert: mass file encryption, .locked/.encrypted extensions
- User report: "files won't open", ransom note found

[Immediate Actions]
□ Immediately isolate suspected infected systems from the network (remove cable or block via firewall)
□ Unmount or switch shared drives to read-only
□ Block access to the domain controller (prevent lateral movement)
□ Escalate to IR Team Lead and CISO
□ Preserve legal evidence: memory dump (before powering off)

[What NOT to Do]
✗ Reboot the infected system (destroys memory evidence)
✗ Attempt decryption (may cause secondary damage)
✗ Connect infected systems to backup systems
```

### 3.2 Analysis and Scope Assessment (30 Minutes–2 Hours)

```
[Scope Assessment]
1. Identify the initial infection time and Patient Zero from EDR/SIEM
2. Trace lateral movement paths: login event 4624, remote execution 4688
3. Identify ransomware family from encrypted file extensions and ransom note content
   → ID Ransomware (https://id-ransomware.malwarehunterteam.com/)

[Key Questions]
- Initial intrusion vector: phishing email? RDP brute-force? VPN vulnerability?
- Was the domain controller infected?
- Were backup systems affected?
- What data was encrypted/exfiltrated?
```

### 3.3 Containment Strategy

```bash
# Isolate via Windows Firewall (remote execution)
netsh advfirewall set allprofiles state on
netsh advfirewall firewall add rule name="IR_Block_All" dir=in action=block
netsh advfirewall firewall add rule name="IR_Allow_IR_Team" dir=in action=allow remoteip=10.0.0.100

# Disable Active Directory account (compromised account)
Disable-ADAccount -Identity "compromised_user"
Set-ADAccountPassword -Identity "compromised_user" -Reset -NewPassword (ConvertTo-SecureString -AsPlainText "TempSecure2026!" -Force)
```

---

## 4. Playbook: Phishing Response

```
[Detection]
- User report: suspicious email
- Email gateway alert
- Credential phishing site detected

[Initial Analysis]
□ Analyze raw email headers: Return-Path, Received, DKIM/SPF/DMARC
□ Analyze links: URLScan.io, VirusTotal (do NOT click them)
□ Analyze attachments: use an isolated sandbox (Any.run, Cuckoo)
□ Identify all recipients of the same email → confirm whether links were clicked

[If Credentials Were Exposed]
□ Immediately change the password (add MFA)
□ Force-expire session tokens
□ Review active session logs (abnormal location/time logins)
□ Check recent email forwarding rules (attacker may have set them)
```

---

## 5. Incident Timeline Auto-Generation CLI

```python
#!/usr/bin/env python3
"""Incident Timeline Auto-Generation CLI
Input log files → sort events chronologically and output"""

import argparse
import re
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional


# Define log format patterns
LOG_PATTERNS = [
    # Windows Event Log (evtx text export)
    {
        "name": "windows_event",
        "pattern": re.compile(
            r'(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})'
            r'.*?EventID["\s:]+(?P<event_id>\d+)'
            r'.*?(?:AccountName|SubjectUserName)["\s:]+(?P<user>\S+)',
            re.DOTALL
        ),
        "format": "%Y-%m-%dT%H:%M:%S",
    },
    # Syslog format
    {
        "name": "syslog",
        "pattern": re.compile(
            r'(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})'
            r'\s+(?P<host>\S+)\s+(?P<process>\S+):\s+(?P<message>.+)'
        ),
        "format": "%b %d %H:%M:%S",
    },
    # Apache/Nginx Access Log
    {
        "name": "apache",
        "pattern": re.compile(
            r'(?P<ip>\d+\.\d+\.\d+\.\d+).*?\[(?P<timestamp>[^\]]+)\]'
            r'\s+"(?P<method>\w+)\s+(?P<path>\S+)\s+HTTP/[\d.]+"'
            r'\s+(?P<status>\d+)'
        ),
        "format": "%d/%b/%Y:%H:%M:%S %z",
    },
    # Generic ISO8601
    {
        "name": "iso8601",
        "pattern": re.compile(
            r'(?P<timestamp>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)'
            r'\s+(?P<message>.+)'
        ),
        "format": "%Y-%m-%dT%H:%M:%S",
    },
]

SUSPICIOUS_KEYWORDS = [
    "failed", "denied", "error", "unauthorized", "privilege", "escalat",
    "admin", "root", "sudo", "powershell", "cmd.exe", "mimikatz",
    "lsass", "pass the hash", "kerberoast", "lateral", "ransomware",
    "encrypt", "exfil", "download", "upload", "beacon", "c2", "c&c",
]


@dataclass
class LogEvent:
    timestamp: datetime
    source_file: str
    raw_line: str
    log_type: str
    parsed: dict
    is_suspicious: bool = False
    tags: list[str] = None

    def __post_init__(self):
        if self.tags is None:
            self.tags = []
        # Detect suspicious keywords
        line_lower = self.raw_line.lower()
        self.is_suspicious = any(kw in line_lower for kw in SUSPICIOUS_KEYWORDS)
        if self.is_suspicious:
            self.tags = [kw for kw in SUSPICIOUS_KEYWORDS if kw in line_lower][:3]


def parse_log_file(filepath: Path, log_type: Optional[str] = None) -> list[LogEvent]:
    """Parse log file"""
    events = []

    try:
        content = filepath.read_text(encoding='utf-8', errors='replace')
    except IOError as e:
        print(f"[!] Failed to read file {filepath}: {e}", file=sys.stderr)
        return events

    patterns = LOG_PATTERNS
    if log_type:
        patterns = [p for p in LOG_PATTERNS if p['name'] == log_type]

    for line in content.splitlines():
        line = line.strip()
        if not line:
            continue

        for pdef in patterns:
            m = pdef['pattern'].search(line)
            if m:
                ts_str = m.group('timestamp').strip()
                # Handle syslog without year
                if pdef['name'] == 'syslog':
                    ts_str = f"{datetime.now().year} {ts_str}"
                    fmt = f"%Y {pdef['format']}"
                else:
                    fmt = pdef['format']

                try:
                    # Remove timezone suffix
                    ts_str_clean = re.sub(r'Z$|[+-]\d{2}:?\d{2}$', '', ts_str)
                    ts = datetime.strptime(ts_str_clean[:19], fmt[:len('%Y-%m-%dT%H:%M:%S')])
                except ValueError:
                    try:
                        ts = datetime.fromisoformat(ts_str_clean[:19])
                    except ValueError:
                        continue

                events.append(LogEvent(
                    timestamp=ts,
                    source_file=filepath.name,
                    raw_line=line[:200],
                    log_type=pdef['name'],
                    parsed=m.groupdict(),
                ))
                break  # Use first matching pattern

    return events


def build_timeline(log_files: list[str], suspicious_only: bool = False) -> list[LogEvent]:
    all_events: list[LogEvent] = []

    for path_str in log_files:
        path = Path(path_str)
        if not path.exists():
            print(f"[!] File not found: {path}", file=sys.stderr)
            continue
        events = parse_log_file(path)
        all_events.extend(events)
        print(f"[+] {path.name}: {len(events)} events parsed")

    all_events.sort(key=lambda e: e.timestamp)

    if suspicious_only:
        all_events = [e for e in all_events if e.is_suspicious]

    return all_events


def print_timeline(events: list[LogEvent], limit: int = 100) -> None:
    print(f"\n{'='*70}")
    print(f"Incident Timeline — {len(events)} events")
    print(f"{'='*70}\n")

    if events:
        print(f"[Start] {events[0].timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"[End]   {events[-1].timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
        duration = events[-1].timestamp - events[0].timestamp
        print(f"[Duration] {duration}\n")

    for event in events[:limit]:
        flag = "⚠ " if event.is_suspicious else "  "
        ts = event.timestamp.strftime("%m-%d %H:%M:%S")
        src = event.source_file[:15].ljust(15)
        msg = event.raw_line[:80]
        tags = f" [{','.join(event.tags)}]" if event.tags else ""
        print(f"{flag}{ts} | {src} | {msg}{tags}")

    if len(events) > limit:
        print(f"\n... {len(events) - limit} more events omitted (adjust with --limit)")


def export_timeline_md(events: list[LogEvent], output: str) -> None:
    lines = [
        "# Incident Timeline",
        "",
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}  ",
        f"Total Events: {len(events)}  ",
        f"Suspicious Events: {sum(1 for e in events if e.is_suspicious)}",
        "",
        "| Time | Source | Type | Content | Tags |",
        "|------|--------|------|---------|------|",
    ]

    for event in events:
        ts = event.timestamp.strftime("%Y-%m-%d %H:%M:%S")
        flag = "⚠" if event.is_suspicious else ""
        tags = ",".join(event.tags) if event.tags else "-"
        msg = event.raw_line[:100].replace("|", "\\|")
        lines.append(f"| {ts} | {event.source_file} | {event.log_type} | {flag}{msg} | {tags} |")

    Path(output).write_text('\n'.join(lines), encoding='utf-8')
    print(f"[+] Timeline markdown saved: {output}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Incident Timeline Auto-Generation CLI")
    parser.add_argument("logs", nargs="+", help="Log file paths to analyze")
    parser.add_argument("--suspicious-only", action="store_true", help="Show only suspicious events")
    parser.add_argument("--limit", type=int, default=200, help="Limit number of output events")
    parser.add_argument("--export-md", metavar="FILE", help="Export timeline as Markdown")

    args = parser.parse_args()

    events = build_timeline(args.logs, args.suspicious_only)
    print_timeline(events, args.limit)

    if args.export_md:
        export_timeline_md(events, args.export_md)


if __name__ == "__main__":
    main()
```

**Usage Examples:**
```bash
# Generate basic timeline
python ir_timeline.py auth.log syslog apache.log

# Filter suspicious events only
python ir_timeline.py *.log --suspicious-only --limit 50

# Generate Markdown report
python ir_timeline.py *.log --export-md incident_timeline.md
```

---

## 6. Escalation Tree

```
P4 Alert Received
  └→ IR Analyst Triage
       ├── Confirmed P4 → Close ticket after handling
       └── Confirmed P3+
             └→ Escalate to IR Team Lead
                  ├── Handle P3 → Standard procedure
                  └── Confirmed P2+
                        └→ Escalate to CISO
                             ├── Handle P2 → Full IR team activation
                             └── Confirmed P1
                                   └→ CEO + Legal Team + Authorities (if needed)
```
