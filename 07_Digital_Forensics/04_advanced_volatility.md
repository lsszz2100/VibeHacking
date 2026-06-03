> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# Volatility3 심화 — 프로세스 분석·네트워크·악성코드 탐지

## 0. 초보자를 위한 개념 이해

### 메모리 포렌식과 Volatility란?

메모리 포렌식은 컴퓨터의 RAM(메모리)에서 실행 중인 프로세스, 네트워크 연결, 암호화 키 등 휘발성 데이터를 추출하고 분석하는 기술입니다. Volatility는 메모리 덤프 파일을 분석하는 가장 널리 사용되는 오픈소스 프레임워크입니다.

**왜 배우는가:**
```
메모리 포렌식이 필요한 이유:

  "파일리스 악성코드(Fileless Malware)" 탐지:
    디스크에 파일을 남기지 않고 메모리에서만 실행
    → 안티바이러스 우회 → 메모리 분석만이 탐지 방법

  메모리에만 있는 증거:
    ├── 실행 중인 악성 프로세스
    ├── 복호화된 페이로드 (암호화된 악성코드의 실제 코드)
    ├── 네트워크 연결 목록 (C&C 서버 주소)
    ├── 패스워드/암호화 키 (메모리에 평문으로 존재)
    └── 숨겨진 DKOM 프로세스 (루트킷 탐지)

  실제 활용:
  랜섬웨어 감염 서버 → 메모리 덤프 → 복호화 키 추출
  APT 공격 분석    → 스피어피싱 후 메모리만 사용하는 백도어
```

### 핵심 개념 정리

```
메모리 분석 핵심 개념:

  메모리 덤프 획득 방법:
    Windows: winpmem, RAMMap, Task Manager (hibernation)
    Linux:   /proc/kcore, LiME 커널 모듈
    VMware:  .vmem 파일 (가상머신 메모리 스냅샷)

  Volatility3 기본 명령 구조:
    python3 vol.py -f <메모리덤프> <OS>.<플러그인>
    예: python3 vol.py -f memory.dmp windows.pslist

  핵심 분석 플러그인:
    windows.pslist   → 실행 중 프로세스 목록
    windows.pstree   → 프로세스 부모-자식 관계 (이상 관계 탐지)
    windows.psscan   → 숨겨진 프로세스 탐지 (DKOM 우회)
    windows.netscan  → 네트워크 연결 목록 (C&C 주소)
    windows.dlllist  → 프로세스별 로드된 DLL
    windows.cmdline  → 프로세스 실행 명령어 (악성 인자 확인)
    windows.malfind  → 악성코드 인젝션 탐지 (rwx 메모리 영역)
```

### 필요한 도구 및 환경
- **메모리 덤프**: 실습용 메모리 덤프 파일 (MemLabs, BlueTeamLabs Online 등에서 제공)
- **Volatility3**: Python 3.8+ 필요, `pip install volatility3`
- **심볼 테이블**: Windows 버전별 심볼 파일 자동 다운로드 또는 수동 설치

### 기초 실습 예제
```python
#!/usr/bin/env python3
"""
Volatility3 플러그인 결과 파서 — 의심 프로세스 자동 탐지.
실제 Volatility3 실행 후 출력된 텍스트를 분석.
"""
import re
from dataclasses import dataclass
from typing import Optional

@dataclass
class ProcessEntry:
    pid: int
    ppid: int
    name: str
    create_time: str
    is_suspicious: bool = False
    reason: str = ""

# 의심스러운 프로세스 이름 패턴
SUSPICIOUS_PROCESSES = {
    "cmd.exe": "명령 프롬프트 — 비정상 부모 프로세스 확인 필요",
    "powershell.exe": "PowerShell — 인코딩된 명령어 여부 확인",
    "wscript.exe": "VBScript 실행기 — 악성 스크립트 실행 경로",
    "cscript.exe": "명령줄 스크립트 — 악성 스크립트 실행 경로",
    "regsvr32.exe": "DLL 등록 — AppLocker 우회에 자주 악용",
    "rundll32.exe": "DLL 실행 — 악성 DLL 로드에 자주 악용",
    "mshta.exe": "HTA 실행기 — 피싱/악성 HTA 파일 실행",
}

def analyze_process_list(processes: list[ProcessEntry]) -> list[ProcessEntry]:
    """프로세스 목록에서 의심스러운 패턴 탐지."""
    suspicious = []
    for proc in processes:
        name_lower = proc.name.lower()
        if name_lower in SUSPICIOUS_PROCESSES:
            proc.is_suspicious = True
            proc.reason = SUSPICIOUS_PROCESSES[name_lower]
            suspicious.append(proc)
        # 부모 프로세스 이상 탐지 (예: Word가 cmd.exe 실행)
        parent = next((p for p in processes if p.pid == proc.ppid), None)
        if parent and "winword" in parent.name.lower() and "cmd" in name_lower:
            proc.is_suspicious = True
            proc.reason = f"Office 앱({parent.name})이 cmd 실행 — 매크로 악성코드 의심!"
            if proc not in suspicious:
                suspicious.append(proc)
    return suspicious

if __name__ == "__main__":
    # 예시 프로세스 목록 (실제 volatility pslist 출력 파싱 후 사용)
    sample_procs = [
        ProcessEntry(4, 0, "System", "2026-01-01", False),
        ProcessEntry(1234, 456, "winword.exe", "2026-01-01T10:00:00"),
        ProcessEntry(1235, 1234, "cmd.exe", "2026-01-01T10:00:05"),  # 의심!
        ProcessEntry(1236, 1235, "powershell.exe", "2026-01-01T10:00:06"),  # 의심!
    ]
    suspicious = analyze_process_list(sample_procs)
    for proc in suspicious:
        print(f"[의심] PID {proc.pid} {proc.name} (부모: PID {proc.ppid})")
        print(f"  이유: {proc.reason}")
```

---

## 1. Volatility3 설치 및 기본 사용

```bash
# 설치
git clone https://github.com/volatilityfoundation/volatility3
cd volatility3
pip install -r requirements.txt

# 심볼 테이블 다운로드 (자동)
python3 vol.py -f memory.dmp windows.info

# 기본 명령 구조
python3 vol.py -f <메모리 덤프> <플러그인>
```

---

## 2. 프로세스 분석

```bash
# 프로세스 목록 (전체)
python3 vol.py -f memory.dmp windows.pslist

# 프로세스 트리 (부모-자식 관계)
python3 vol.py -f memory.dmp windows.pstree

# 숨겨진 프로세스 탐지 (DKOM 우회)
python3 vol.py -f memory.dmp windows.psscan     # 풀 스캔
python3 vol.py -f memory.dmp windows.psxview    # 교차 검증

# 프로세스 DLL 목록
python3 vol.py -f memory.dmp windows.dlllist --pid 1234

# 프로세스 핸들
python3 vol.py -f memory.dmp windows.handles --pid 1234

# 의심 프로세스 메모리 덤프
python3 vol.py -f memory.dmp windows.memmap --pid 1234 --dump

# VAD (Virtual Address Descriptor) — 실행 가능 메모리 영역
python3 vol.py -f memory.dmp windows.vadinfo --pid 1234
python3 vol.py -f memory.dmp windows.vadwalk --pid 1234
```

### 2.1 의심 프로세스 탐지 체크리스트

```bash
# 1. svchost.exe 부모 확인 (정상: services.exe)
python3 vol.py -f memory.dmp windows.pstree | grep svchost

# 2. lsass.exe 복수 실행 탐지
python3 vol.py -f memory.dmp windows.pslist | grep lsass

# 3. 정상 프로세스 이름 위장 탐지 (svchost.exe → svch0st.exe)
python3 vol.py -f memory.dmp windows.pslist | \
  python3 -c "
import sys, re
for line in sys.stdin:
    name = line.split()[1] if len(line.split()) > 1 else ''
    legit = ['svchost.exe','lsass.exe','explorer.exe','csrss.exe','winlogon.exe']
    if name and name not in legit:
        # 레벤슈타인 거리로 위장 탐지
        for l in legit:
            if abs(len(name)-len(l)) <= 2 and name != l:
                print(f'위장 의심: {name} (유사: {l})')
"
```

---

## 3. 네트워크 아티팩트

```bash
# 현재 네트워크 연결 (Vista+)
python3 vol.py -f memory.dmp windows.netstat

# 오래된 연결 포함 (XP/2003)
python3 vol.py -f memory.dmp windows.netscan

# 결과 필터링 — ESTABLISHED 연결
python3 vol.py -f memory.dmp windows.netscan | grep ESTABLISHED

# 악성 C2 연결 탐지 (외부 IP, 비표준 포트)
python3 vol.py -f memory.dmp windows.netscan | awk '
/ESTABLISHED/ {
  split($3, local, ":");
  split($4, remote, ":");
  if (remote[2] != "80" && remote[2] != "443" && remote[2] != "53")
    print "의심 포트:", $0
}'
```

---

## 4. 레지스트리 분석

```bash
# 레지스트리 하이브 목록
python3 vol.py -f memory.dmp windows.registry.hivelist

# Run/RunOnce 키 (자동 실행)
python3 vol.py -f memory.dmp windows.registry.printkey \
  --key "SOFTWARE\Microsoft\Windows\CurrentVersion\Run"

# 최근 실행 파일
python3 vol.py -f memory.dmp windows.registry.printkey \
  --key "SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs"

# UserAssist (프로그램 실행 기록)
python3 vol.py -f memory.dmp windows.registry.userassist

# ShimCache (애플리케이션 호환성 캐시)
python3 vol.py -f memory.dmp windows.shimcache
```

---

## 5. 악성코드 탐지 자동화 CLI

```python
#!/usr/bin/env python3
"""Volatility3 기반 메모리 포렌식 자동화 CLI."""

import argparse
import json
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class ForensicsReport:
    dump_file: str
    os_info: dict = field(default_factory=dict)
    suspicious_processes: list[dict] = field(default_factory=list)
    network_connections: list[dict] = field(default_factory=list)
    injected_code: list[dict] = field(default_factory=list)
    persistence: list[dict] = field(default_factory=list)


def run_volatility(
    dump_file: str,
    plugin: str,
    vol_path: str = "python3 vol.py",
    extra_args: list[str] | None = None,
) -> list[str]:
    cmd = vol_path.split() + ["-f", dump_file, plugin]
    if extra_args:
        cmd.extend(extra_args)

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        return result.stdout.splitlines()
    except subprocess.TimeoutExpired:
        print(f"[!] 타임아웃: {plugin}")
        return []
    except Exception as e:
        print(f"[!] 오류: {plugin} — {e}")
        return []


SUSPICIOUS_PROCESS_NAMES = {
    "mimikatz.exe", "pwdump.exe", "fgdump.exe",
    "nc.exe", "ncat.exe", "netcat.exe",
    "meterpreter", "payload.exe", "shell.exe",
    "cobaltstrike.exe", "beacon.exe",
}

LEGITIMATE_PARENTS = {
    "svchost.exe": {"services.exe"},
    "lsass.exe": {"wininit.exe"},
    "csrss.exe": {"smss.exe"},
    "explorer.exe": {"userinit.exe"},
    "taskhost.exe": {"services.exe", "svchost.exe"},
}


def analyze_processes(dump_file: str, vol_path: str) -> list[dict]:
    suspicious = []
    lines = run_volatility(dump_file, "windows.pslist", vol_path)

    process_info: dict[int, dict] = {}
    for line in lines[2:]:  # 헤더 2줄 스킵
        parts = line.split()
        if len(parts) < 7:
            continue
        try:
            pid = int(parts[2])
            ppid = int(parts[3])
            name = parts[1]
            process_info[pid] = {"name": name, "pid": pid, "ppid": ppid}
        except (ValueError, IndexError):
            pass

    for pid, proc in process_info.items():
        name = proc["name"].lower()
        ppid = proc["ppid"]
        parent = process_info.get(ppid, {}).get("name", "unknown").lower()

        reasons = []

        if name in SUSPICIOUS_PROCESS_NAMES:
            reasons.append(f"알려진 악성 프로세스명: {name}")

        expected_parents = LEGITIMATE_PARENTS.get(name, set())
        if expected_parents and parent not in {p.lower() for p in expected_parents}:
            reasons.append(f"비정상 부모 프로세스: {parent} (기대: {expected_parents})")

        if reasons:
            suspicious.append({
                "name": proc["name"],
                "pid": pid,
                "ppid": ppid,
                "parent": parent,
                "reasons": reasons,
            })

    return suspicious


def analyze_network(dump_file: str, vol_path: str) -> list[dict]:
    suspicious = []
    lines = run_volatility(dump_file, "windows.netscan", vol_path)

    for line in lines[2:]:
        if "ESTABLISHED" not in line and "LISTEN" not in line:
            continue
        parts = line.split()
        if len(parts) < 5:
            continue

        try:
            remote = parts[3] if len(parts) > 3 else ""
            if ":" in remote:
                remote_port = int(remote.rsplit(":", 1)[1])
                # 비표준 포트 외부 연결
                if remote_port not in {80, 443, 53, 22, 8080, 8443}:
                    suspicious.append({
                        "connection": line.strip(),
                        "remote_port": remote_port,
                        "reason": f"비표준 포트 외부 연결: {remote_port}",
                    })
        except (ValueError, IndexError):
            pass

    return suspicious


def check_code_injection(dump_file: str, vol_path: str) -> list[dict]:
    """Malfind 플러그인으로 코드 인젝션 탐지."""
    findings = []
    lines = run_volatility(dump_file, "windows.malfind", vol_path)

    current_entry: dict = {}
    for line in lines:
        if "Process:" in line:
            if current_entry:
                findings.append(current_entry)
            parts = line.split()
            current_entry = {"process": parts[1] if len(parts) > 1 else "?", "details": []}
        elif current_entry and line.strip():
            current_entry.setdefault("details", []).append(line.strip())

    if current_entry:
        findings.append(current_entry)

    return findings


def main() -> None:
    parser = argparse.ArgumentParser(description="Volatility3 포렌식 자동화")
    parser.add_argument("dump", help="메모리 덤프 파일")
    parser.add_argument("--vol-path", default="python3 /opt/volatility3/vol.py",
                        help="Volatility3 경로")
    parser.add_argument("-o", "--output", type=Path, help="리포트 저장 경로")
    parser.add_argument("--quick", action="store_true", help="빠른 분석 (프로세스+네트워크만)")
    args = parser.parse_args()

    report = ForensicsReport(dump_file=args.dump)

    print("[*] 프로세스 분석 중...")
    report.suspicious_processes = analyze_processes(args.dump, args.vol_path)
    print(f"  의심 프로세스: {len(report.suspicious_processes)}개")

    print("[*] 네트워크 연결 분석 중...")
    report.network_connections = analyze_network(args.dump, args.vol_path)
    print(f"  의심 연결: {len(report.network_connections)}개")

    if not args.quick:
        print("[*] 코드 인젝션 탐지 중...")
        report.injected_code = check_code_injection(args.dump, args.vol_path)
        print(f"  인젝션 의심: {len(report.injected_code)}개")

    # 결과 출력
    print("\n=== 분석 결과 ===")
    for proc in report.suspicious_processes:
        print(f"[!] 프로세스: {proc['name']} (PID {proc['pid']})")
        for r in proc["reasons"]:
            print(f"    → {r}")

    for conn in report.network_connections:
        print(f"[!] 네트워크: {conn['reason']}")

    if args.output:
        data = {
            "dump": report.dump_file,
            "suspicious_processes": report.suspicious_processes,
            "network_connections": report.network_connections,
            "injected_code": report.injected_code,
        }
        args.output.write_text(json.dumps(data, indent=2, ensure_ascii=False))
        print(f"\n리포트 저장: {args.output}")


if __name__ == "__main__":
    main()
```

---

## 6. 타임라인 분석

```bash
# MFT 타임라인 추출
python3 vol.py -f memory.dmp windows.mftscan.MFTScan | \
  sort -k1 > timeline.txt

# 최근 24시간 이벤트
python3 vol.py -f memory.dmp windows.mftscan.MFTScan | \
  awk -v cutoff="$(date -d '-24 hours' '+%Y-%m-%d')" '$1 >= cutoff'

# Prefetch 파일 분석 (프로그램 실행 기록)
python3 vol.py -f memory.dmp windows.prefetch.PrefetchScan
```

---

## 7. Volatility3 플러그인 레퍼런스

| 플러그인 | 용도 |
|----------|------|
| `windows.pslist` | 프로세스 목록 (EPROCESS 연결 리스트) |
| `windows.psscan` | 프로세스 풀 스캔 (숨겨진 프로세스) |
| `windows.cmdline` | 프로세스 명령줄 인수 |
| `windows.dlllist` | 로드된 DLL 목록 |
| `windows.malfind` | 코드 인젝션 탐지 |
| `windows.netscan` | 네트워크 연결 |
| `windows.registry.hivelist` | 레지스트리 하이브 |
| `windows.hashdump` | 패스워드 해시 덤프 |
| `windows.lsadump` | LSA 시크릿 |
| `windows.mftscan.MFTScan` | MFT 파일 타임라인 |
| `windows.shimcache` | ShimCache 애플리케이션 기록 |
| `windows.userassist` | UserAssist 프로그램 실행 기록 |

---

<a name="english"></a>

# Volatility3 Advanced — Process Analysis, Network, and Malware Detection

## 1. Volatility3 Installation and Basic Usage

```bash
# Install
git clone https://github.com/volatilityfoundation/volatility3
cd volatility3
pip install -r requirements.txt

# Download symbol tables (automatic)
python3 vol.py -f memory.dmp windows.info

# Basic command structure
python3 vol.py -f <memory dump> <plugin>
```

---

## 2. Process Analysis

```bash
# Full process list
python3 vol.py -f memory.dmp windows.pslist

# Process tree (parent-child relationships)
python3 vol.py -f memory.dmp windows.pstree

# Hidden process detection (DKOM bypass)
python3 vol.py -f memory.dmp windows.psscan     # pool scan
python3 vol.py -f memory.dmp windows.psxview    # cross-validation

# Process DLL list
python3 vol.py -f memory.dmp windows.dlllist --pid 1234

# Process handles
python3 vol.py -f memory.dmp windows.handles --pid 1234

# Dump suspicious process memory
python3 vol.py -f memory.dmp windows.memmap --pid 1234 --dump

# VAD (Virtual Address Descriptor) — executable memory regions
python3 vol.py -f memory.dmp windows.vadinfo --pid 1234
python3 vol.py -f memory.dmp windows.vadwalk --pid 1234
```

### 2.1 Suspicious Process Detection Checklist

```bash
# 1. Check svchost.exe parent (normal: services.exe)
python3 vol.py -f memory.dmp windows.pstree | grep svchost

# 2. Detect multiple lsass.exe instances
python3 vol.py -f memory.dmp windows.pslist | grep lsass

# 3. Detect masquerading of legitimate process names (svchost.exe -> svch0st.exe)
python3 vol.py -f memory.dmp windows.pslist | \
  python3 -c "
import sys, re
for line in sys.stdin:
    name = line.split()[1] if len(line.split()) > 1 else ''
    legit = ['svchost.exe','lsass.exe','explorer.exe','csrss.exe','winlogon.exe']
    if name and name not in legit:
        # Levenshtein distance masquerade detection
        for l in legit:
            if abs(len(name)-len(l)) <= 2 and name != l:
                print(f'Suspicious masquerade: {name} (similar: {l})')
"
```

---

## 3. Network Artifacts

```bash
# Current network connections (Vista+)
python3 vol.py -f memory.dmp windows.netstat

# Including older connections (XP/2003)
python3 vol.py -f memory.dmp windows.netscan

# Filter results — ESTABLISHED connections
python3 vol.py -f memory.dmp windows.netscan | grep ESTABLISHED

# Malicious C2 connection detection (external IP, non-standard port)
python3 vol.py -f memory.dmp windows.netscan | awk '
/ESTABLISHED/ {
  split($3, local, ":");
  split($4, remote, ":");
  if (remote[2] != "80" && remote[2] != "443" && remote[2] != "53")
    print "Suspicious port:", $0
}'
```

---

## 4. Registry Analysis

```bash
# Registry hive list
python3 vol.py -f memory.dmp windows.registry.hivelist

# Run/RunOnce keys (auto-start)
python3 vol.py -f memory.dmp windows.registry.printkey \
  --key "SOFTWARE\Microsoft\Windows\CurrentVersion\Run"

# Recently executed files
python3 vol.py -f memory.dmp windows.registry.printkey \
  --key "SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs"

# UserAssist (program execution history)
python3 vol.py -f memory.dmp windows.registry.userassist

# ShimCache (application compatibility cache)
python3 vol.py -f memory.dmp windows.shimcache
```

---

## 5. Malware Detection Automation CLI

```python
#!/usr/bin/env python3
"""Volatility3-based memory forensics automation CLI."""

import argparse
import json
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class ForensicsReport:
    dump_file: str
    os_info: dict = field(default_factory=dict)
    suspicious_processes: list[dict] = field(default_factory=list)
    network_connections: list[dict] = field(default_factory=list)
    injected_code: list[dict] = field(default_factory=list)
    persistence: list[dict] = field(default_factory=list)


def run_volatility(
    dump_file: str,
    plugin: str,
    vol_path: str = "python3 vol.py",
    extra_args: list[str] | None = None,
) -> list[str]:
    cmd = vol_path.split() + ["-f", dump_file, plugin]
    if extra_args:
        cmd.extend(extra_args)

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        return result.stdout.splitlines()
    except subprocess.TimeoutExpired:
        print(f"[!] Timeout: {plugin}")
        return []
    except Exception as e:
        print(f"[!] Error: {plugin} — {e}")
        return []


SUSPICIOUS_PROCESS_NAMES = {
    "mimikatz.exe", "pwdump.exe", "fgdump.exe",
    "nc.exe", "ncat.exe", "netcat.exe",
    "meterpreter", "payload.exe", "shell.exe",
    "cobaltstrike.exe", "beacon.exe",
}

LEGITIMATE_PARENTS = {
    "svchost.exe": {"services.exe"},
    "lsass.exe": {"wininit.exe"},
    "csrss.exe": {"smss.exe"},
    "explorer.exe": {"userinit.exe"},
    "taskhost.exe": {"services.exe", "svchost.exe"},
}


def analyze_processes(dump_file: str, vol_path: str) -> list[dict]:
    suspicious = []
    lines = run_volatility(dump_file, "windows.pslist", vol_path)

    process_info: dict[int, dict] = {}
    for line in lines[2:]:  # Skip 2 header lines
        parts = line.split()
        if len(parts) < 7:
            continue
        try:
            pid = int(parts[2])
            ppid = int(parts[3])
            name = parts[1]
            process_info[pid] = {"name": name, "pid": pid, "ppid": ppid}
        except (ValueError, IndexError):
            pass

    for pid, proc in process_info.items():
        name = proc["name"].lower()
        ppid = proc["ppid"]
        parent = process_info.get(ppid, {}).get("name", "unknown").lower()

        reasons = []

        if name in SUSPICIOUS_PROCESS_NAMES:
            reasons.append(f"Known malicious process name: {name}")

        expected_parents = LEGITIMATE_PARENTS.get(name, set())
        if expected_parents and parent not in {p.lower() for p in expected_parents}:
            reasons.append(f"Abnormal parent process: {parent} (expected: {expected_parents})")

        if reasons:
            suspicious.append({
                "name": proc["name"],
                "pid": pid,
                "ppid": ppid,
                "parent": parent,
                "reasons": reasons,
            })

    return suspicious


def analyze_network(dump_file: str, vol_path: str) -> list[dict]:
    suspicious = []
    lines = run_volatility(dump_file, "windows.netscan", vol_path)

    for line in lines[2:]:
        if "ESTABLISHED" not in line and "LISTEN" not in line:
            continue
        parts = line.split()
        if len(parts) < 5:
            continue

        try:
            remote = parts[3] if len(parts) > 3 else ""
            if ":" in remote:
                remote_port = int(remote.rsplit(":", 1)[1])
                # Non-standard external port connections
                if remote_port not in {80, 443, 53, 22, 8080, 8443}:
                    suspicious.append({
                        "connection": line.strip(),
                        "remote_port": remote_port,
                        "reason": f"Non-standard external port: {remote_port}",
                    })
        except (ValueError, IndexError):
            pass

    return suspicious


def check_code_injection(dump_file: str, vol_path: str) -> list[dict]:
    """Code injection detection using Malfind plugin."""
    findings = []
    lines = run_volatility(dump_file, "windows.malfind", vol_path)

    current_entry: dict = {}
    for line in lines:
        if "Process:" in line:
            if current_entry:
                findings.append(current_entry)
            parts = line.split()
            current_entry = {"process": parts[1] if len(parts) > 1 else "?", "details": []}
        elif current_entry and line.strip():
            current_entry.setdefault("details", []).append(line.strip())

    if current_entry:
        findings.append(current_entry)

    return findings


def main() -> None:
    parser = argparse.ArgumentParser(description="Volatility3 Forensics Automation")
    parser.add_argument("dump", help="Memory dump file")
    parser.add_argument("--vol-path", default="python3 /opt/volatility3/vol.py",
                        help="Volatility3 path")
    parser.add_argument("-o", "--output", type=Path, help="Report save path")
    parser.add_argument("--quick", action="store_true", help="Quick analysis (process+network only)")
    args = parser.parse_args()

    report = ForensicsReport(dump_file=args.dump)

    print("[*] Analyzing processes...")
    report.suspicious_processes = analyze_processes(args.dump, args.vol_path)
    print(f"  Suspicious processes: {len(report.suspicious_processes)}")

    print("[*] Analyzing network connections...")
    report.network_connections = analyze_network(args.dump, args.vol_path)
    print(f"  Suspicious connections: {len(report.network_connections)}")

    if not args.quick:
        print("[*] Detecting code injection...")
        report.injected_code = check_code_injection(args.dump, args.vol_path)
        print(f"  Suspected injections: {len(report.injected_code)}")

    # Print results
    print("\n=== Analysis Results ===")
    for proc in report.suspicious_processes:
        print(f"[!] Process: {proc['name']} (PID {proc['pid']})")
        for r in proc["reasons"]:
            print(f"    -> {r}")

    for conn in report.network_connections:
        print(f"[!] Network: {conn['reason']}")

    if args.output:
        data = {
            "dump": report.dump_file,
            "suspicious_processes": report.suspicious_processes,
            "network_connections": report.network_connections,
            "injected_code": report.injected_code,
        }
        args.output.write_text(json.dumps(data, indent=2, ensure_ascii=False))
        print(f"\nReport saved: {args.output}")


if __name__ == "__main__":
    main()
```

---

## 6. Timeline Analysis

```bash
# Extract MFT timeline
python3 vol.py -f memory.dmp windows.mftscan.MFTScan | \
  sort -k1 > timeline.txt

# Events in the last 24 hours
python3 vol.py -f memory.dmp windows.mftscan.MFTScan | \
  awk -v cutoff="$(date -d '-24 hours' '+%Y-%m-%d')" '$1 >= cutoff'

# Prefetch file analysis (program execution history)
python3 vol.py -f memory.dmp windows.prefetch.PrefetchScan
```

---

## 7. Volatility3 Plugin Reference

| Plugin | Purpose |
|--------|---------|
| `windows.pslist` | Process list (EPROCESS linked list) |
| `windows.psscan` | Process pool scan (hidden processes) |
| `windows.cmdline` | Process command line arguments |
| `windows.dlllist` | Loaded DLL list |
| `windows.malfind` | Code injection detection |
| `windows.netscan` | Network connections |
| `windows.registry.hivelist` | Registry hives |
| `windows.hashdump` | Password hash dump |
| `windows.lsadump` | LSA secrets |
| `windows.mftscan.MFTScan` | MFT file timeline |
| `windows.shimcache` | ShimCache application history |
| `windows.userassist` | UserAssist program execution history |
