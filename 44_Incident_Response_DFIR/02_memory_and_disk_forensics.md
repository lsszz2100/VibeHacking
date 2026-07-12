> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 메모리 및 디스크 포렌식

## 0. 초보자를 위한 개념 이해

### 메모리 포렌식이란?

**메모리 포렌식**은 컴퓨터의 RAM에서 증거를 수집하고 분석하는 기법입니다.

```
왜 메모리가 중요한가:
  디스크에 없는 정보가 메모리에 있다:
  - 파일리스 악성코드 (디스크에 파일 없음, 메모리에만 존재)
  - 암호화 키 (복호화된 상태로 메모리에 있음)
  - 실행 중인 프로세스 목록
  - 네트워크 연결 정보 (C2 서버 주소)
  - 자격증명 (비밀번호, 세션 토큰)

메모리 포렌식으로 발견할 수 있는 것:
  ✓ 실행 중인 악성 프로세스
  ✓ 주입된 코드 (프로세스 인젝션)
  ✓ 암호화 전 데이터
  ✓ 네트워크 C2 통신
  ✓ 로그인 자격증명 (lsass.exe)
  ✓ 숨겨진 루트킷 프로세스
```

**핵심 제약 - 메모리의 휘발성:**
```
메모리는 전원이 꺼지면 모두 사라집니다!
→ 시스템 재부팅 전에 즉시 수집해야 함
→ 모든 포렌식 증거 중 우선순위 가장 높음
→ "라이브 포렌식" (켜진 상태에서 수집)이 필수
```

### 디스크 포렌식이란?

**디스크 포렌식**은 저장장치(HDD, SSD, USB)에서 증거를 수집하고 분석하는 기법입니다.

```
중요 개념: "삭제된" 파일이 사실은 남아있다

파일 삭제 시 실제로 일어나는 일:
  파일 시스템 인덱스에서 해당 파일 항목 제거
  (실제 데이터 블록은 그대로 남아있음)
  → "이 공간은 사용 가능" 표시만 바뀜
  
  새 파일이 그 공간을 덮어쓸 때까지:
  → 포렌식 도구로 복구 가능!
  
  따라서: 중요 데이터는 안전한 삭제(shred, secure erase) 필요
```

### 포렌식 황금 원칙

```
1. 원본 보존 (Preservation)
   원본 디스크를 직접 분석 → 증거 오염 위험
   → 반드시 비트 단위 이미지(사본) 만들어서 분석
   dd if=/dev/sda of=/evidence/disk.img
   
2. 무결성 검증 (Integrity)
   수집 전후 해시값으로 변조 없음 증명
   sha256sum /dev/sda > disk.sha256
   
3. 문서화 (Documentation)
   수집 시간, 수집자, 도구 버전 모두 기록
   
4. 체인 오브 커스터디 (Chain of Custody)
   증거가 누구의 손을 거쳤는지 기록
   법정 제출 시 필수
```

---

메모리 포렌식은 실행 중인 악성코드, 네트워크 연결, 암호화 키를 살아있는 시스템에서 추출하는 기법이다. 디스크 포렌식은 삭제된 파일 복구와 타임라인 재구성에 중점을 둔다.

---

## 1. 메모리 포렌식 기초

### 1.1 메모리 덤프 수집

```bash
# Windows — 전원 끄기 전 덤프 수집
# WinPmem (무료, 오픈소스)
winpmem_mini_x64_rc2.exe memory.raw

# DumpIt (빠름)
DumpIt.exe /O memory.raw

# ProcDump (특정 프로세스)
procdump -ma lsass.exe lsass.dmp   # 자격증명 추출용

# Linux — /dev/mem 또는 LiME
# LiME 커널 모듈 로드
insmod lime.ko "path=/tmp/memory.lime format=lime"

# VMware — 스냅샷에서 메모리 덤프
# 스냅샷 폴더의 .vmem 파일 사용

# 가상머신: VirtualBox
vboxmanage debugvm "VM Name" dumpvmcore --filename memory.elf
```

### 1.2 Volatility3 기본 사용법

```bash
# OS 프로파일 자동 탐지
vol3 -f memory.raw windows.info.Info

# 프로세스 목록
vol3 -f memory.raw windows.pslist.PsList

# 프로세스 트리
vol3 -f memory.raw windows.pstree.PsTree

# 네트워크 연결
vol3 -f memory.raw windows.netstat.NetStat

# DLL 목록 (특정 프로세스)
vol3 -f memory.raw windows.dlllist.DllList --pid 1234

# 프로세스 메모리 덤프
vol3 -f memory.raw windows.memmap.Memmap --pid 1234 --dump

# 레지스트리 하이브
vol3 -f memory.raw windows.registry.hivelist.HiveList

# 레지스트리 값 읽기
vol3 -f memory.raw windows.registry.printkey.PrintKey \
    --key "SOFTWARE\Microsoft\Windows\CurrentVersion\Run"

# 파일 캐시
vol3 -f memory.raw windows.filescan.FileScan

# 브라우저 아티팩트
vol3 -f memory.raw windows.registry.userassist.UserAssist
```

---

## 2. 악성 프로세스 탐지

### 2.1 프로세스 이름 위장 탐지

정상 Windows 프로세스 목록과 비교하여 이름을 도용한 악성코드 탐지.

```python
#!/usr/bin/env python3
"""Volatility3 pslist 출력 파싱 → 의심 프로세스 자동 플래깅 CLI"""

import argparse
import json
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


# 합법적 Windows 시스템 프로세스와 예상 부모-자식 관계
LEGIT_PROCESSES: dict[str, dict] = {
    "System":         {"ppid_name": None,    "expected_count": 1, "expected_path": None},
    "smss.exe":       {"ppid_name": "System","expected_count": 1, "expected_path": r"System32\smss.exe"},
    "csrss.exe":      {"ppid_name": "smss.exe","expected_count": (1,3),"expected_path": r"System32\csrss.exe"},
    "wininit.exe":    {"ppid_name": "smss.exe","expected_count": 1,"expected_path": r"System32\wininit.exe"},
    "winlogon.exe":   {"ppid_name": "smss.exe","expected_count": (1,5),"expected_path": r"System32\winlogon.exe"},
    "services.exe":   {"ppid_name": "wininit.exe","expected_count": 1,"expected_path": r"System32\services.exe"},
    "lsass.exe":      {"ppid_name": "wininit.exe","expected_count": 1,"expected_path": r"System32\lsass.exe"},
    "svchost.exe":    {"ppid_name": "services.exe","expected_count": (5,99),"expected_path": r"System32\svchost.exe"},
    "explorer.exe":   {"ppid_name": "userinit.exe","expected_count": (1,5),"expected_path": r"explorer.exe"},
    "taskhost.exe":   {"ppid_name": "services.exe","expected_count": (0,10),"expected_path": r"System32\taskhost.exe"},
    "spoolsv.exe":    {"ppid_name": "services.exe","expected_count": 1,"expected_path": r"System32\spoolsv.exe"},
}

# 흔한 이름 위장 유사 문자
LOOKALIKE_MAP = {
    "svchost.exe": ["svch0st.exe", "svchos1.exe", "svchosts.exe", "scvhost.exe"],
    "lsass.exe":   ["lssas.exe", "lsass.exe.exe", "lsasss.exe", "isass.exe"],
    "explorer.exe":["expl0rer.exe", "explor.exe", "iexplore.exe"],
    "csrss.exe":   ["cssrs.exe", "csrs.exe"],
    "winlogon.exe":["winiogon.exe", "winlogin.exe"],
}


@dataclass
class ProcessEntry:
    pid: int
    ppid: int
    name: str
    offset: str
    create_time: str
    exit_time: str
    path: str = ""
    suspicion_flags: list[str] = field(default_factory=list)


def run_volatility(memory_file: str, plugin: str) -> str:
    """Volatility3 플러그인 실행"""
    cmd = ["vol3", "-f", memory_file, plugin]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        return result.stdout
    except FileNotFoundError:
        print("[!] vol3 명령 없음. volatility3 설치 필요", file=sys.stderr)
        sys.exit(1)
    except subprocess.TimeoutExpired:
        print("[!] Volatility3 타임아웃", file=sys.stderr)
        sys.exit(1)


def parse_pslist(output: str) -> list[ProcessEntry]:
    """PsList 출력 파싱"""
    processes = []
    lines = output.strip().split('\n')

    for line in lines:
        # PID PPID ImageFileName 형식 파싱
        parts = re.split(r'\s{2,}', line.strip())
        if len(parts) < 4:
            continue
        try:
            pid = int(parts[0])
            ppid = int(parts[1])
            name = parts[2]
            create_time = parts[3] if len(parts) > 3 else ""
            processes.append(ProcessEntry(
                pid=pid, ppid=ppid, name=name,
                offset="", create_time=create_time, exit_time=""
            ))
        except (ValueError, IndexError):
            continue

    return processes


def flag_suspicious(processes: list[ProcessEntry]) -> list[ProcessEntry]:
    """의심 프로세스 플래깅"""
    name_counts: dict[str, int] = {}
    pid_to_name: dict[int, str] = {p.pid: p.name for p in processes}

    for p in processes:
        name_counts[p.name.lower()] = name_counts.get(p.name.lower(), 0) + 1

    # 유사 이름 집합 (소문자)
    all_lookalikes = set()
    for fakes in LOOKALIKE_MAP.values():
        all_lookalikes.update(f.lower() for f in fakes)

    for proc in processes:
        name_lower = proc.name.lower()

        # 유사 이름 위장 탐지
        if name_lower in all_lookalikes:
            proc.suspicion_flags.append(f"이름 위장 탐지: {proc.name}")

        # 비정상적 부모 프로세스
        legit = LEGIT_PROCESSES.get(proc.name)
        if legit:
            expected_ppid_name = legit.get("ppid_name")
            actual_ppid_name = pid_to_name.get(proc.ppid, "Unknown")
            if (expected_ppid_name and
                    actual_ppid_name.lower() != expected_ppid_name.lower() and
                    actual_ppid_name != "Unknown"):
                proc.suspicion_flags.append(
                    f"비정상 부모: expected={expected_ppid_name}, actual={actual_ppid_name}"
                )

            # 비정상적 인스턴스 수
            expected_count = legit.get("expected_count", 1)
            actual_count = name_counts.get(name_lower, 0)
            if isinstance(expected_count, int) and actual_count != expected_count:
                proc.suspicion_flags.append(
                    f"비정상 개수: expected={expected_count}, actual={actual_count}"
                )
            elif isinstance(expected_count, tuple):
                min_c, max_c = expected_count
                if not (min_c <= actual_count <= max_c):
                    proc.suspicion_flags.append(
                        f"비정상 개수: {actual_count}개 (정상: {min_c}~{max_c})"
                    )

        # lsass 이외의 프로세스에서 lsass 이름 사용
        if "lsass" in name_lower and proc.name != "lsass.exe":
            proc.suspicion_flags.append("lsass 위장 의심")

        # PPID가 없는 프로세스 (orphan, System 제외)
        if proc.ppid not in pid_to_name and proc.name not in ("System", "[System Process]"):
            proc.suspicion_flags.append(f"부모 PID {proc.ppid} 없음 (orphan)")

    return processes


def print_analysis(processes: list[ProcessEntry], all_processes: bool = False) -> None:
    suspicious = [p for p in processes if p.suspicion_flags]

    print(f"\n{'='*60}")
    print(f"메모리 포렌식 프로세스 분석")
    print(f"전체 프로세스: {len(processes)}개 | 의심: {len(suspicious)}개")
    print(f"{'='*60}\n")

    if suspicious:
        print("[의심 프로세스 목록]")
        for p in suspicious:
            print(f"\n  ⚠  PID {p.pid} | PPID {p.ppid} | {p.name}")
            for flag in p.suspicion_flags:
                print(f"      → {flag}")

    if all_processes:
        print("\n[전체 프로세스 목록]")
        for p in sorted(processes, key=lambda x: x.pid):
            icon = "⚠" if p.suspicion_flags else " "
            print(f"  {icon} PID {p.pid:5d} | PPID {p.ppid:5d} | {p.name}")


def main() -> None:
    parser = argparse.ArgumentParser(description="메모리 포렌식 프로세스 분석 CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    analyze_p = sub.add_parser("analyze", help="메모리 파일 직접 분석")
    analyze_p.add_argument("memory_file", help="메모리 덤프 파일")
    analyze_p.add_argument("-a", "--all", action="store_true", help="전체 프로세스 출력")

    parse_p = sub.add_parser("parse", help="PsList 텍스트 출력 파싱")
    parse_p.add_argument("pslist_file", help="vol3 PsList 출력 파일")
    parse_p.add_argument("-a", "--all", action="store_true")

    args = parser.parse_args()

    if args.command == "analyze":
        print(f"[*] Volatility3 실행: {args.memory_file}")
        output = run_volatility(args.memory_file, "windows.pslist.PsList")
        processes = parse_pslist(output)

    else:
        output = Path(args.pslist_file).read_text()
        processes = parse_pslist(output)

    processes = flag_suspicious(processes)
    print_analysis(processes, getattr(args, 'all', False))


if __name__ == "__main__":
    main()
```

---

## 3. 디스크 포렌식

### 3.1 이미지 수집

```bash
# dd (Linux)
dd if=/dev/sda of=/forensics/disk.img bs=4M status=progress conv=noerror,sync

# dcfldd (해시 동시 계산)
dcfldd if=/dev/sda of=disk.img hash=sha256 hashlog=hash.txt

# ewfacquire (E01 포맷)
ewfacquire /dev/sda

# 무결성 검증
sha256sum disk.img > disk.img.sha256
sha256sum -c disk.img.sha256
```

### 3.2 MFT (Master File Table) 분석

```bash
# MFT 추출
icat -f ntfs disk.img 0 > mft.raw  # The Sleuth Kit

# MFTECmd로 파싱 (Windows)
MFTECmd.exe -f mft.raw --csv mft_output.csv

# 삭제된 파일 탐지
fls -rld disk.img  # -l: 긴 형식, -d: 삭제된 파일

# 특정 파일 복구
icat disk.img [inode_number] > recovered_file
```

### 3.3 타임라인 분석 (MACB)

| 타임스탬프 | 의미 | NTFS 속성 |
|-----------|------|---------|
| M (Modified) | 파일 내용 마지막 수정 | $DATA |
| A (Accessed) | 마지막 접근 | $STANDARD_INFO |
| C (Changed) | 메타데이터 변경 ($MFT 수정) | $STANDARD_INFO |
| B (Birth) | 파일 생성 시간 | $STANDARD_INFO |

```bash
# 타임라인 생성 (Plaso)
log2timeline.py timeline.plaso disk.img
psort.py -o l2tcsv timeline.plaso > timeline.csv

# 필터링 (특정 기간)
psort.py timeline.plaso "date > '2026-01-01' AND date < '2026-01-31'"
```

---

## 4. 포렌식 아티팩트 위치 (Windows)

| 아티팩트 | 경로 | 정보 |
|---------|------|------|
| NTUSER.DAT | `%USERPROFILE%\NTUSER.DAT` | 사용자 레지스트리 |
| Prefetch | `C:\Windows\Prefetch\*.pf` | 최근 실행 프로그램 |
| Amcache | `C:\Windows\AppCompat\Programs\Amcache.hve` | 실행 파일 메타데이터 |
| Shimcache | SYSTEM 하이브 | 실행 이력 |
| LNK 파일 | `%APPDATA%\Microsoft\Windows\Recent\` | 최근 파일 |
| Jump Lists | `%APPDATA%\Microsoft\Windows\Recent\AutomaticDestinations\` | 최근 앱별 파일 |
| Browser History | `%APPDATA%\Local\Google\Chrome\User Data\Default\History` | 웹 기록 |
| Event Logs | `C:\Windows\System32\winevt\Logs\` | Windows 이벤트 |
| MFT | `C:\$MFT` | 파일 시스템 메타데이터 |
| VSS | `\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy*` | 볼륨 섀도 복사본 |

<!-- detect-validate-44 -->
## 포렌식 증거 검증 — 무결성과 반-포렌식 탐지

메모리/디스크 포렌식은 *덤프를 떴는가*가 아니라 **증거 무결성(해시·쓰기방지)이 유지되고 반-포렌식 흔적을 탐지하는가**로 신뢰된다. 검증은 **소유·승인 증거**에서만.

### 항목 → 위험 → 검증 방법 → 신뢰 신호

| 항목 | 위험 | 검증 방법 | 신뢰 신호 |
|---|---|---|---|
| 무결성 | 수집 후 변조 | 수집 전후 해시 | 해시 일치 |
| 쓰기 방지 | 원본 오염 | ro 마운트/write-blocker | 원본 불변 |
| 반-포렌식 | 타임스톰핑 | $MFT vs $STDINFO 비교 | 시간 불일치 탐지 |
| 휘발성 순서 | 메모리 증발 | 수집 순서 기록 | 휘발성 우선 수집 |

### 방어 검증 (직접 확인)

```bash
# 1) 수집 이미지의 무결성 해시가 수집 시점 기록과 일치하는지 — 소유 증거에서
sha256sum evidence.dd; cat evidence.dd.sha256   # 두 값이 일치해야 무결
# 2) 디스크 이미지를 읽기전용으로 마운트해 원본 오염을 방지하는지
mount | grep -E 'loop.*\bro\b' || echo "WARN: 읽기전용 마운트 아님"
```

> 검증은 반드시 **소유·승인 증거**에서만 한다. "덤프를 떴다"와 "무결성이 유지되고 반-포렌식이 탐지된다"는 다르다 — 해시·ro 마운트·타임스톰핑을 직접 확인한다([[07_Digital_Forensics]], [[47_Mobile_Forensics]]).

**최신 기법·통제 (2025–2026):**
- 원격 라이브 획득(Velociraptor)·인메모리 위협 분석이 표준 — 검증: 인젝션/셸코드가 메모리에서 재현 포착되는가([[07_Digital_Forensics]])
- 안티포렌식 대응·획득 무결성 — 보존되는지 확인

---

<a name="english"></a>

# Memory and Disk Forensics

Memory forensics is the technique of extracting running malware, network connections, and encryption keys from a live system. Disk forensics focuses on recovering deleted files and reconstructing timelines.

---

## 1. Memory Forensics Fundamentals

### 1.1 Memory Dump Collection

```bash
# Windows — collect dump before powering off
# WinPmem (free, open source)
winpmem_mini_x64_rc2.exe memory.raw

# DumpIt (fast)
DumpIt.exe /O memory.raw

# ProcDump (specific process)
procdump -ma lsass.exe lsass.dmp   # for credential extraction

# Linux — /dev/mem or LiME
# Load LiME kernel module
insmod lime.ko "path=/tmp/memory.lime format=lime"

# VMware — memory dump from snapshot
# Use .vmem file in snapshot folder

# Virtual machine: VirtualBox
vboxmanage debugvm "VM Name" dumpvmcore --filename memory.elf
```

### 1.2 Volatility3 Basic Usage

```bash
# Auto-detect OS profile
vol3 -f memory.raw windows.info.Info

# Process list
vol3 -f memory.raw windows.pslist.PsList

# Process tree
vol3 -f memory.raw windows.pstree.PsTree

# Network connections
vol3 -f memory.raw windows.netstat.NetStat

# DLL list (specific process)
vol3 -f memory.raw windows.dlllist.DllList --pid 1234

# Process memory dump
vol3 -f memory.raw windows.memmap.Memmap --pid 1234 --dump

# Registry hives
vol3 -f memory.raw windows.registry.hivelist.HiveList

# Read registry values
vol3 -f memory.raw windows.registry.printkey.PrintKey \
    --key "SOFTWARE\Microsoft\Windows\CurrentVersion\Run"

# File cache
vol3 -f memory.raw windows.filescan.FileScan

# Browser artifacts
vol3 -f memory.raw windows.registry.userassist.UserAssist
```

---

## 2. Malicious Process Detection

### 2.1 Process Name Masquerading Detection

Detect malware that steals names by comparing against the list of legitimate Windows processes.

```python
#!/usr/bin/env python3
"""Parse Volatility3 pslist output → auto-flag suspicious processes CLI"""

import argparse
import json
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


# Legitimate Windows system processes and expected parent-child relationships
LEGIT_PROCESSES: dict[str, dict] = {
    "System":         {"ppid_name": None,    "expected_count": 1, "expected_path": None},
    "smss.exe":       {"ppid_name": "System","expected_count": 1, "expected_path": r"System32\smss.exe"},
    "csrss.exe":      {"ppid_name": "smss.exe","expected_count": (1,3),"expected_path": r"System32\csrss.exe"},
    "wininit.exe":    {"ppid_name": "smss.exe","expected_count": 1,"expected_path": r"System32\wininit.exe"},
    "winlogon.exe":   {"ppid_name": "smss.exe","expected_count": (1,5),"expected_path": r"System32\winlogon.exe"},
    "services.exe":   {"ppid_name": "wininit.exe","expected_count": 1,"expected_path": r"System32\services.exe"},
    "lsass.exe":      {"ppid_name": "wininit.exe","expected_count": 1,"expected_path": r"System32\lsass.exe"},
    "svchost.exe":    {"ppid_name": "services.exe","expected_count": (5,99),"expected_path": r"System32\svchost.exe"},
    "explorer.exe":   {"ppid_name": "userinit.exe","expected_count": (1,5),"expected_path": r"explorer.exe"},
    "taskhost.exe":   {"ppid_name": "services.exe","expected_count": (0,10),"expected_path": r"System32\taskhost.exe"},
    "spoolsv.exe":    {"ppid_name": "services.exe","expected_count": 1,"expected_path": r"System32\spoolsv.exe"},
}

# Common lookalike characters used for name masquerading
LOOKALIKE_MAP = {
    "svchost.exe": ["svch0st.exe", "svchos1.exe", "svchosts.exe", "scvhost.exe"],
    "lsass.exe":   ["lssas.exe", "lsass.exe.exe", "lsasss.exe", "isass.exe"],
    "explorer.exe":["expl0rer.exe", "explor.exe", "iexplore.exe"],
    "csrss.exe":   ["cssrs.exe", "csrs.exe"],
    "winlogon.exe":["winiogon.exe", "winlogin.exe"],
}


@dataclass
class ProcessEntry:
    pid: int
    ppid: int
    name: str
    offset: str
    create_time: str
    exit_time: str
    path: str = ""
    suspicion_flags: list[str] = field(default_factory=list)


def run_volatility(memory_file: str, plugin: str) -> str:
    """Run Volatility3 plugin"""
    cmd = ["vol3", "-f", memory_file, plugin]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        return result.stdout
    except FileNotFoundError:
        print("[!] vol3 command not found. Install volatility3", file=sys.stderr)
        sys.exit(1)
    except subprocess.TimeoutExpired:
        print("[!] Volatility3 timed out", file=sys.stderr)
        sys.exit(1)


def parse_pslist(output: str) -> list[ProcessEntry]:
    """Parse PsList output"""
    processes = []
    lines = output.strip().split('\n')

    for line in lines:
        # Parse PID PPID ImageFileName format
        parts = re.split(r'\s{2,}', line.strip())
        if len(parts) < 4:
            continue
        try:
            pid = int(parts[0])
            ppid = int(parts[1])
            name = parts[2]
            create_time = parts[3] if len(parts) > 3 else ""
            processes.append(ProcessEntry(
                pid=pid, ppid=ppid, name=name,
                offset="", create_time=create_time, exit_time=""
            ))
        except (ValueError, IndexError):
            continue

    return processes


def flag_suspicious(processes: list[ProcessEntry]) -> list[ProcessEntry]:
    """Flag suspicious processes"""
    name_counts: dict[str, int] = {}
    pid_to_name: dict[int, str] = {p.pid: p.name for p in processes}

    for p in processes:
        name_counts[p.name.lower()] = name_counts.get(p.name.lower(), 0) + 1

    # Set of lookalike names (lowercase)
    all_lookalikes = set()
    for fakes in LOOKALIKE_MAP.values():
        all_lookalikes.update(f.lower() for f in fakes)

    for proc in processes:
        name_lower = proc.name.lower()

        # Detect lookalike name masquerading
        if name_lower in all_lookalikes:
            proc.suspicion_flags.append(f"Name masquerading detected: {proc.name}")

        # Abnormal parent process
        legit = LEGIT_PROCESSES.get(proc.name)
        if legit:
            expected_ppid_name = legit.get("ppid_name")
            actual_ppid_name = pid_to_name.get(proc.ppid, "Unknown")
            if (expected_ppid_name and
                    actual_ppid_name.lower() != expected_ppid_name.lower() and
                    actual_ppid_name != "Unknown"):
                proc.suspicion_flags.append(
                    f"Abnormal parent: expected={expected_ppid_name}, actual={actual_ppid_name}"
                )

            # Abnormal instance count
            expected_count = legit.get("expected_count", 1)
            actual_count = name_counts.get(name_lower, 0)
            if isinstance(expected_count, int) and actual_count != expected_count:
                proc.suspicion_flags.append(
                    f"Abnormal count: expected={expected_count}, actual={actual_count}"
                )
            elif isinstance(expected_count, tuple):
                min_c, max_c = expected_count
                if not (min_c <= actual_count <= max_c):
                    proc.suspicion_flags.append(
                        f"Abnormal count: {actual_count} instances (normal: {min_c}–{max_c})"
                    )

        # Process using lsass name that is not lsass.exe
        if "lsass" in name_lower and proc.name != "lsass.exe":
            proc.suspicion_flags.append("Suspected lsass masquerade")

        # Process with no parent PID (orphan, excluding System)
        if proc.ppid not in pid_to_name and proc.name not in ("System", "[System Process]"):
            proc.suspicion_flags.append(f"Parent PID {proc.ppid} not found (orphan)")

    return processes


def print_analysis(processes: list[ProcessEntry], all_processes: bool = False) -> None:
    suspicious = [p for p in processes if p.suspicion_flags]

    print(f"\n{'='*60}")
    print(f"Memory Forensics Process Analysis")
    print(f"Total processes: {len(processes)} | Suspicious: {len(suspicious)}")
    print(f"{'='*60}\n")

    if suspicious:
        print("[Suspicious Process List]")
        for p in suspicious:
            print(f"\n  ⚠  PID {p.pid} | PPID {p.ppid} | {p.name}")
            for flag in p.suspicion_flags:
                print(f"      → {flag}")

    if all_processes:
        print("\n[Full Process List]")
        for p in sorted(processes, key=lambda x: x.pid):
            icon = "⚠" if p.suspicion_flags else " "
            print(f"  {icon} PID {p.pid:5d} | PPID {p.ppid:5d} | {p.name}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Memory forensics process analysis CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    analyze_p = sub.add_parser("analyze", help="Analyze memory file directly")
    analyze_p.add_argument("memory_file", help="Memory dump file")
    analyze_p.add_argument("-a", "--all", action="store_true", help="Output all processes")

    parse_p = sub.add_parser("parse", help="Parse PsList text output")
    parse_p.add_argument("pslist_file", help="vol3 PsList output file")
    parse_p.add_argument("-a", "--all", action="store_true")

    args = parser.parse_args()

    if args.command == "analyze":
        print(f"[*] Running Volatility3: {args.memory_file}")
        output = run_volatility(args.memory_file, "windows.pslist.PsList")
        processes = parse_pslist(output)

    else:
        output = Path(args.pslist_file).read_text()
        processes = parse_pslist(output)

    processes = flag_suspicious(processes)
    print_analysis(processes, getattr(args, 'all', False))


if __name__ == "__main__":
    main()
```

---

## 3. Disk Forensics

### 3.1 Image Acquisition

```bash
# dd (Linux)
dd if=/dev/sda of=/forensics/disk.img bs=4M status=progress conv=noerror,sync

# dcfldd (simultaneous hash calculation)
dcfldd if=/dev/sda of=disk.img hash=sha256 hashlog=hash.txt

# ewfacquire (E01 format)
ewfacquire /dev/sda

# Integrity verification
sha256sum disk.img > disk.img.sha256
sha256sum -c disk.img.sha256
```

### 3.2 MFT (Master File Table) Analysis

```bash
# Extract MFT
icat -f ntfs disk.img 0 > mft.raw  # The Sleuth Kit

# Parse with MFTECmd (Windows)
MFTECmd.exe -f mft.raw --csv mft_output.csv

# Detect deleted files
fls -rld disk.img  # -l: long format, -d: deleted files

# Recover specific file
icat disk.img [inode_number] > recovered_file
```

### 3.3 Timeline Analysis (MACB)

| Timestamp | Meaning | NTFS Attribute |
|-----------|---------|----------------|
| M (Modified) | Last modification of file content | $DATA |
| A (Accessed) | Last access | $STANDARD_INFO |
| C (Changed) | Metadata change ($MFT modification) | $STANDARD_INFO |
| B (Birth) | File creation time | $STANDARD_INFO |

```bash
# Generate timeline (Plaso)
log2timeline.py timeline.plaso disk.img
psort.py -o l2tcsv timeline.plaso > timeline.csv

# Filter (specific time period)
psort.py timeline.plaso "date > '2026-01-01' AND date < '2026-01-31'"
```

---

## 4. Forensic Artifact Locations (Windows)

| Artifact | Path | Information |
|----------|------|-------------|
| NTUSER.DAT | `%USERPROFILE%\NTUSER.DAT` | User registry |
| Prefetch | `C:\Windows\Prefetch\*.pf` | Recently executed programs |
| Amcache | `C:\Windows\AppCompat\Programs\Amcache.hve` | Executable metadata |
| Shimcache | SYSTEM hive | Execution history |
| LNK files | `%APPDATA%\Microsoft\Windows\Recent\` | Recent files |
| Jump Lists | `%APPDATA%\Microsoft\Windows\Recent\AutomaticDestinations\` | Recent files per app |
| Browser History | `%APPDATA%\Local\Google\Chrome\User Data\Default\History` | Web history |
| Event Logs | `C:\Windows\System32\winevt\Logs\` | Windows events |
| MFT | `C:\$MFT` | File system metadata |
| VSS | `\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy*` | Volume Shadow Copies |

<!-- detect-validate-44 -->
## Forensic-Evidence Validation — Integrity and Anti-Forensics Detection

Memory/disk forensics is trusted not by *whether you took a dump* but by **whether evidence integrity (hash, write-block) is preserved and anti-forensic traces are detected**. Validate only on **owned / authorized evidence**.

### Item -> Risk -> Validation method -> Trust signal

| Item | Risk | Validation method | Trust signal |
|---|---|---|---|
| Integrity | Tamper after capture | Pre/post-capture hash | Hashes match |
| Write protection | Original contamination | ro mount/write-blocker | Original immutable |
| Anti-forensics | Timestomping | Compare $MFT vs $STDINFO | Time mismatch detected |
| Volatility order | Memory evaporates | Record capture order | Volatile captured first |

### Defense validation (verify directly)

```bash
# 1) Whether the captured image's integrity hash matches the recorded capture-time hash — owned evidence
sha256sum evidence.dd; cat evidence.dd.sha256   # the two must match for integrity
# 2) Whether the disk image is mounted read-only to prevent original contamination
mount | grep -E 'loop.*\bro\b' || echo "WARN: not mounted read-only"
```

> Validate only on **owned / authorized evidence**. "Took a dump" differs from "integrity preserved and anti-forensics detected" — confirm hash, ro-mount, and timestomping directly ([[07_Digital_Forensics]], [[47_Mobile_Forensics]]).
