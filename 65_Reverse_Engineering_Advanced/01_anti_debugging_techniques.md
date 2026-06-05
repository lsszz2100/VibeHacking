> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 안티디버깅 기법 (Anti-Debugging Techniques)

## 개념 소개

안티디버깅은 악성코드나 상용 소프트웨어가 자신이 분석당하고 있다는 사실을 탐지하여 실행을 방해하거나 종료하는 기법입니다. 마치 "내가 감시받고 있으면 아무것도 안 한다"는 스파이처럼, 디버거가 붙어 있으면 다르게 동작합니다.

---

## 핵심 안티디버깅 기법

### 1. API 기반 탐지

| 함수 / 기법 | 플랫폼 | 설명 |
|---|---|---|
| `IsDebuggerPresent()` | Windows | PEB의 `BeingDebugged` 플래그 확인 |
| `CheckRemoteDebuggerPresent()` | Windows | 외부 프로세스 디버거 탐지 |
| `NtQueryInformationProcess()` | Windows | `ProcessDebugPort` 쿼리 |
| `ptrace(PTRACE_TRACEME)` | Linux | 이미 트레이싱 중이면 실패 |
| `/proc/self/status` | Linux | `TracerPid` 필드 확인 |

### 2. 타이밍 기반 탐지 (RDTSC)

디버거는 브레이크포인트에서 실행을 멈추기 때문에, 두 지점 사이의 실행 시간이 비정상적으로 길어집니다.

```
정상 실행:  RDTSC → 코드 실행 → RDTSC → 차이: 수백 사이클
디버깅 중:  RDTSC → [BP 중단] → RDTSC → 차이: 수백만 사이클
```

### 3. 예외 기반 탐지

- `INT 3` (0xCC) 브레이크포인트 삽입 → 예외 핸들러에서 탐지
- `SEH (Structured Exception Handling)` 조작
- 하드웨어 브레이크포인트 (DR0~DR3 레지스터) 확인

### 4. 환경 기반 탐지

- 윈도우 타이틀에 "OllyDbg", "x64dbg" 포함 여부
- 프로세스 목록에서 `windbg.exe`, `ida.exe` 탐색
- 부모 프로세스가 Explorer가 아닌 경우 탐지

---

## 우회 방법론

### 정적 우회
- `IsDebuggerPresent` 반환값을 항상 0으로 패치
- PEB의 `BeingDebugged` 오프셋(0x02)을 0으로 초기화

### 동적 우회
- x64dbg 플러그인: `ScyllaHide`, `HideOD`
- 타이밍 체크 NOP 슬라이딩
- 조건 분기 강제 변경 (JZ → JMP)

---

## Python 실습: PE 파일 안티디버깅 패턴 탐지기

```python
#!/usr/bin/env python3
"""
PE 파일에서 안티디버깅 패턴을 탐지하는 도구
pefile 없이 수동 파싱으로 구현
"""

import argparse
import struct
from pathlib import Path
from dataclasses import dataclass, field


@dataclass
class AntiDebugPattern:
    name: str
    bytes_pattern: bytes
    description: str
    offset: int = -1


@dataclass
class ScanResult:
    file_path: Path
    patterns_found: list[AntiDebugPattern] = field(default_factory=list)
    suspicious_strings: list[str] = field(default_factory=list)
    error: str = ""


# 알려진 안티디버깅 바이트 패턴
ANTI_DEBUG_PATTERNS: list[AntiDebugPattern] = [
    AntiDebugPattern(
        name="IsDebuggerPresent 호출",
        bytes_pattern=bytes([0xFF, 0x15]),  # CALL DWORD PTR 간접 호출 시그니처
        description="Windows API IsDebuggerPresent 간접 호출 패턴",
    ),
    AntiDebugPattern(
        name="INT3 명령 (소프트웨어 BP)",
        bytes_pattern=bytes([0xCC]),
        description="소프트웨어 브레이크포인트 명령어",
    ),
    AntiDebugPattern(
        name="RDTSC 명령",
        bytes_pattern=bytes([0x0F, 0x31]),
        description="타이밍 기반 안티디버깅 - Read Time-Stamp Counter",
    ),
    AntiDebugPattern(
        name="CPUID 명령",
        bytes_pattern=bytes([0x0F, 0xA2]),
        description="하이퍼바이저/VM 탐지에 사용되는 CPUID",
    ),
    AntiDebugPattern(
        name="INT2D (디버거 전용 인터럽트)",
        bytes_pattern=bytes([0xCD, 0x2D]),
        description="디버거에서만 예외가 발생하는 인터럽트",
    ),
]

SUSPICIOUS_STRINGS = [
    b"IsDebuggerPresent",
    b"CheckRemoteDebuggerPresent",
    b"NtQueryInformationProcess",
    b"ZwQueryInformationProcess",
    b"OutputDebugString",
    b"ollydbg",
    b"x64dbg",
    b"windbg",
    b"ProcessDebugPort",
    b"BeingDebugged",
    b"TracerPid",
]


def read_pe_sections(data: bytes) -> list[tuple[int, int, str]]:
    """PE 섹션 오프셋과 크기를 수동으로 파싱합니다."""
    sections: list[tuple[int, int, str]] = []

    # MZ 시그니처 확인
    if len(data) < 0x40 or data[:2] != b"MZ":
        return sections

    # PE 헤더 오프셋 (e_lfanew @ 0x3C)
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if pe_offset + 4 >= len(data):
        return sections

    # PE 시그니처 확인
    if data[pe_offset : pe_offset + 4] != b"PE\x00\x00":
        return sections

    # Optional Header 크기, 섹션 수
    num_sections = struct.unpack_from("<H", data, pe_offset + 6)[0]
    opt_header_size = struct.unpack_from("<H", data, pe_offset + 20)[0]
    section_table_offset = pe_offset + 24 + opt_header_size

    for i in range(num_sections):
        sec_offset = section_table_offset + i * 40
        if sec_offset + 40 > len(data):
            break

        name_raw = data[sec_offset : sec_offset + 8]
        name = name_raw.rstrip(b"\x00").decode("ascii", errors="replace")
        raw_size = struct.unpack_from("<I", data, sec_offset + 16)[0]
        raw_offset = struct.unpack_from("<I", data, sec_offset + 20)[0]

        if raw_offset > 0 and raw_size > 0:
            sections.append((raw_offset, raw_size, name))

    return sections


def scan_pattern(data: bytes, pattern: AntiDebugPattern) -> list[int]:
    """바이트 패턴의 모든 발생 위치를 반환합니다."""
    positions: list[int] = []
    start = 0
    while True:
        pos = data.find(pattern.bytes_pattern, start)
        if pos == -1:
            break
        positions.append(pos)
        start = pos + 1
    return positions


def scan_file(file_path: Path) -> ScanResult:
    """PE 파일에서 안티디버깅 패턴을 스캔합니다."""
    result = ScanResult(file_path=file_path)

    try:
        data = file_path.read_bytes()
    except OSError as e:
        result.error = f"파일 읽기 실패: {e}"
        return result

    # 섹션별 스캔
    sections = read_pe_sections(data)
    scan_regions = sections if sections else [(0, len(data), "전체")]

    for pattern in ANTI_DEBUG_PATTERNS:
        for raw_offset, raw_size, sec_name in scan_regions:
            section_data = data[raw_offset : raw_offset + raw_size]
            positions = scan_pattern(section_data, pattern)
            if positions:
                found = AntiDebugPattern(
                    name=f"{pattern.name} [{sec_name}]",
                    bytes_pattern=pattern.bytes_pattern,
                    description=pattern.description,
                    offset=raw_offset + positions[0],
                )
                result.patterns_found.append(found)

    # 의심 문자열 스캔
    for sus_str in SUSPICIOUS_STRINGS:
        if sus_str.lower() in data.lower():
            result.suspicious_strings.append(sus_str.decode("ascii", errors="replace"))

    return result


def print_report(result: ScanResult) -> None:
    """스캔 결과를 출력합니다."""
    print(f"\n{'='*60}")
    print(f"대상 파일: {result.file_path}")
    print(f"{'='*60}")

    if result.error:
        print(f"[오류] {result.error}")
        return

    if result.patterns_found:
        print(f"\n[!] 안티디버깅 바이트 패턴 {len(result.patterns_found)}개 발견:")
        for p in result.patterns_found:
            print(f"  - {p.name}")
            print(f"    오프셋: 0x{p.offset:08X}")
            print(f"    설명: {p.description}")
    else:
        print("\n[*] 바이트 패턴 없음")

    if result.suspicious_strings:
        print(f"\n[!] 의심 문자열 {len(result.suspicious_strings)}개:")
        for s in result.suspicious_strings:
            print(f"  - {s}")
    else:
        print("[*] 의심 문자열 없음")

    score = len(result.patterns_found) * 10 + len(result.suspicious_strings) * 5
    print(f"\n위험도 점수: {score}점 ", end="")
    if score >= 50:
        print("(높음 - 강력한 안티디버깅 의심)")
    elif score >= 20:
        print("(중간 - 일부 안티디버깅 기법 사용)")
    else:
        print("(낮음)")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="PE 파일 안티디버깅 패턴 탐지기",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("files", nargs="+", type=Path, help="스캔할 PE 파일 경로")
    parser.add_argument("--verbose", "-v", action="store_true", help="상세 출력")
    args = parser.parse_args()

    for file_path in args.files:
        if not file_path.exists():
            print(f"[오류] 파일 없음: {file_path}")
            continue
        result = scan_file(file_path)
        print_report(result)


if __name__ == "__main__":
    main()
```

---

## 실무 적용 시나리오

1. **악성코드 분석 자동화**: 대량의 샘플에서 안티디버깅 기법 종류를 분류하여 분석 우선순위 결정
2. **소프트웨어 감사**: 상용 소프트웨어의 안티디버깅 사용 여부를 계약 전 검토
3. **CTF 바이너리 분석**: 문제 풀이 전 어떤 보호 기법이 적용되었는지 빠르게 파악

---

## 요약

| 기법 | 탐지 방법 | 우회 난이도 |
|---|---|---|
| `IsDebuggerPresent` | PEB 플래그 | 낮음 (직접 패치) |
| RDTSC 타이밍 | 사이클 차이 | 중간 (NOP 슬라이드) |
| 예외 기반 | SEH/INT3 | 중간 |
| 환경 탐지 | 프로세스명 | 낮음 (이름 변경) |
| 하드웨어 BP 탐지 | DR 레지스터 | 높음 |

---

<a name="english"></a>

# Anti-Debugging Techniques

## Concept Overview

Anti-debugging refers to techniques used by malware or commercial software to detect when they are being analyzed and alter or terminate execution accordingly. Like a spy who "does nothing if being watched," these programs behave differently when a debugger is attached.

---

## Core Anti-Debugging Techniques

### 1. API-Based Detection

| Function / Technique | Platform | Description |
|---|---|---|
| `IsDebuggerPresent()` | Windows | Checks `BeingDebugged` flag in PEB |
| `CheckRemoteDebuggerPresent()` | Windows | Detects external process debugger |
| `NtQueryInformationProcess()` | Windows | Queries `ProcessDebugPort` |
| `ptrace(PTRACE_TRACEME)` | Linux | Fails if already being traced |
| `/proc/self/status` | Linux | Checks `TracerPid` field |

### 2. Timing-Based Detection (RDTSC)

Debuggers pause execution at breakpoints, causing abnormally long elapsed time between two measurement points.

### 3. Exception-Based Detection

- Insert `INT 3` (0xCC) breakpoints → detect in exception handler
- Manipulate SEH (Structured Exception Handling)
- Check hardware breakpoints (DR0~DR3 registers)

### 4. Environment-Based Detection

- Window titles containing "OllyDbg", "x64dbg"
- Process list scan for `windbg.exe`, `ida.exe`
- Detect if parent process is not Explorer

---

## Bypass Methodology

- Patch `IsDebuggerPresent` return value to always return 0
- Zero out PEB `BeingDebugged` byte at offset 0x02
- x64dbg plugins: `ScyllaHide`, `HideOD`
- NOP-slide timing checks
- Force-flip conditional jumps (JZ → JMP)

---

## Summary Table

| Technique | Detection Method | Bypass Difficulty |
|---|---|---|
| `IsDebuggerPresent` | PEB flag | Low (direct patch) |
| RDTSC timing | Cycle difference | Medium (NOP slide) |
| Exception-based | SEH/INT3 | Medium |
| Environment check | Process name | Low (rename) |
| Hardware BP detection | DR registers | High |
