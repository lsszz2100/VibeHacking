> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 고급 바이너리 분석 (Advanced Binary Analysis)

## 개념 소개

CFG(Control Flow Graph)는 프로그램의 실행 흐름을 그래프로 표현한 것입니다. 마치 지하철 노선도처럼, 각 역(기본 블록)을 어떤 조건에서 어느 방향으로 이동할 수 있는지 보여줍니다. 이를 바탕으로 데이터 흐름을 추적하면 취약점 패턴을 자동으로 인식할 수 있습니다.

---

## 핵심 개념

### 기본 블록 (Basic Block)

연속된 명령의 집합으로, 내부에 분기가 없고 하나의 입구와 하나의 출구를 가집니다.

```
블록 A:          블록 B:          블록 C:
  mov eax, 1      add eax, 2      ret
  cmp eax, 5 ─→  jz 블록C    ─→
```

### 데이터 플로우 분석

| 분석 종류 | 설명 | 활용 |
|---|---|---|
| Def-Use Chain | 변수 정의 후 사용 지점 추적 | UAF 탐지 |
| Taint Analysis | 입력값이 어디까지 흘러가는지 | SQL Injection 경로 |
| Reaching Definition | 어떤 정의가 특정 지점에 도달하는지 | 초기화 검사 |

### 취약점 패턴 인식

- **Buffer Overflow**: 배열 인덱스가 제한 없이 증가하는 패턴
- **Format String**: 사용자 입력이 직접 format 인자로 사용
- **Integer Overflow**: 곱셈 결과로 malloc 크기 계산
- **UAF**: free() 이후 포인터 사용

---

## Python 실습: ELF/PE 바이너리 기본 CFG 추출기

```python
#!/usr/bin/env python3
"""
struct 모듈을 사용하여 ELF 바이너리에서 기본 CFG를 추출합니다.
실제 디스어셈블리 없이 분기 명령 패턴만으로 블록 경계를 추정합니다.
"""

import argparse
import struct
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class BasicBlock:
    start: int
    end: int
    instructions: int
    successors: list[int] = field(default_factory=list)
    predecessors: list[int] = field(default_factory=list)
    has_call: bool = False
    has_ret: bool = False


@dataclass
class CFGResult:
    file_path: Path
    arch: str
    entry_point: int
    blocks: dict[int, BasicBlock] = field(default_factory=dict)
    error: str = ""


# x86/x64 분기 명령 (오프셋 기반 블록 경계 추정)
X86_BRANCH_OPCODES: set[int] = {
    0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,  # Jcc 단거리
    0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F,  # Jcc 단거리
    0xE8,  # CALL rel32
    0xE9,  # JMP rel32
    0xEB,  # JMP rel8
    0xC3,  # RET
    0xC2,  # RET imm16
    0xFF,  # JMP/CALL 간접
}

X86_RET_OPCODES: set[int] = {0xC3, 0xC2, 0xCF}
X86_CALL_OPCODES: set[int] = {0xE8}


def parse_elf_header(data: bytes) -> tuple[int, str] | None:
    """ELF 헤더를 파싱하여 (진입점, 아키텍처)를 반환합니다."""
    if len(data) < 0x40 or data[:4] != b"\x7fELF":
        return None

    e_machine = struct.unpack_from("<H", data, 0x12)[0]
    arch_map = {
        0x03: "x86",
        0x3E: "x86_64",
        0x28: "ARM",
        0xB7: "AArch64",
        0x08: "MIPS",
    }
    arch = arch_map.get(e_machine, f"unknown(0x{e_machine:04X})")

    ei_class = data[4]  # 1=32bit, 2=64bit
    if ei_class == 1:
        entry_point = struct.unpack_from("<I", data, 0x18)[0]
    else:
        entry_point = struct.unpack_from("<Q", data, 0x18)[0]

    return entry_point, arch


def get_text_section(data: bytes) -> tuple[int, bytes] | None:
    """ELF에서 .text 섹션을 추출합니다."""
    if len(data) < 0x40 or data[:4] != b"\x7fELF":
        return None

    ei_class = data[4]
    is_64bit = ei_class == 2

    if is_64bit:
        e_shoff = struct.unpack_from("<Q", data, 0x28)[0]
        e_shentsize = struct.unpack_from("<H", data, 0x3A)[0]
        e_shnum = struct.unpack_from("<H", data, 0x3C)[0]
        e_shstrndx = struct.unpack_from("<H", data, 0x3E)[0]
    else:
        e_shoff = struct.unpack_from("<I", data, 0x20)[0]
        e_shentsize = struct.unpack_from("<H", data, 0x2E)[0]
        e_shnum = struct.unpack_from("<H", data, 0x30)[0]
        e_shstrndx = struct.unpack_from("<H", data, 0x32)[0]

    if e_shoff == 0 or e_shnum == 0:
        return None

    # 문자열 테이블 섹션 위치
    str_sh_off = e_shoff + e_shstrndx * e_shentsize
    if is_64bit:
        str_sec_off = struct.unpack_from("<Q", data, str_sh_off + 0x18)[0]
        str_sec_size = struct.unpack_from("<Q", data, str_sh_off + 0x20)[0]
    else:
        str_sec_off = struct.unpack_from("<I", data, str_sh_off + 0x10)[0]
        str_sec_size = struct.unpack_from("<I", data, str_sh_off + 0x14)[0]

    strtab = data[str_sec_off : str_sec_off + str_sec_size]

    for i in range(e_shnum):
        sh_off = e_shoff + i * e_shentsize
        sh_name_idx = struct.unpack_from("<I", data, sh_off)[0]

        # 섹션 이름 추출
        name_end = strtab.find(b"\x00", sh_name_idx)
        name = strtab[sh_name_idx:name_end].decode("ascii", errors="replace")

        if name == ".text":
            if is_64bit:
                sec_offset = struct.unpack_from("<Q", data, sh_off + 0x18)[0]
                sec_size = struct.unpack_from("<Q", data, sh_off + 0x20)[0]
                sec_addr = struct.unpack_from("<Q", data, sh_off + 0x10)[0]
            else:
                sec_offset = struct.unpack_from("<I", data, sh_off + 0x10)[0]
                sec_size = struct.unpack_from("<I", data, sh_off + 0x14)[0]
                sec_addr = struct.unpack_from("<I", data, sh_off + 0x0C)[0]
            return sec_addr, data[sec_offset : sec_offset + sec_size]

    return None


def extract_basic_blocks(code: bytes, base_addr: int, limit: int = 200) -> dict[int, BasicBlock]:
    """분기/RET 명령 기반으로 기본 블록 경계를 추정합니다."""
    blocks: dict[int, BasicBlock] = {}
    block_starts: set[int] = {base_addr}
    i = 0

    # 1차 패스: 블록 시작점 수집
    while i < len(code) and i < limit * 15:
        b = code[i]
        addr = base_addr + i

        if b in X86_BRANCH_OPCODES:
            block_starts.add(addr + 2)  # 다음 명령

        if b == 0xE9 and i + 5 <= len(code):
            rel = struct.unpack_from("<i", code, i + 1)[0]
            target = addr + 5 + rel
            block_starts.add(target)
            block_starts.add(addr + 5)

        elif b == 0xEB and i + 2 <= len(code):
            rel = struct.unpack_from("<b", code, i + 1)[0]
            block_starts.add(addr + 2 + rel)
            block_starts.add(addr + 2)

        i += 1

    # 2차 패스: 블록 구성
    sorted_starts = sorted(block_starts)[:limit]
    for idx, start in enumerate(sorted_starts):
        end = sorted_starts[idx + 1] if idx + 1 < len(sorted_starts) else base_addr + len(code)
        size = end - start
        instr_count = max(1, size // 3)

        rel_start = start - base_addr
        rel_end = min(end - base_addr, len(code))
        block_code = code[rel_start:rel_end] if rel_start < len(code) else b""

        has_ret = any(b in X86_RET_OPCODES for b in block_code)
        has_call = 0xE8 in block_code

        block = BasicBlock(
            start=start, end=end, instructions=instr_count,
            has_ret=has_ret, has_call=has_call
        )
        blocks[start] = block

    return blocks


def analyze_binary(file_path: Path) -> CFGResult:
    """바이너리를 분석하여 CFG를 추출합니다."""
    result = CFGResult(file_path=file_path, arch="unknown", entry_point=0)
    try:
        data = file_path.read_bytes()
    except OSError as e:
        result.error = str(e)
        return result

    header = parse_elf_header(data)
    if not header:
        result.error = "ELF 형식이 아닙니다."
        return result

    result.entry_point, result.arch = header
    text = get_text_section(data)
    if not text:
        result.error = ".text 섹션을 찾을 수 없습니다."
        return result

    sec_addr, sec_data = text
    result.blocks = extract_basic_blocks(sec_data, sec_addr)
    return result


def print_cfg(result: CFGResult) -> None:
    print(f"\n{'='*60}")
    print(f"파일: {result.file_path.name}")
    if result.error:
        print(f"[오류] {result.error}")
        return

    print(f"아키텍처: {result.arch}  진입점: 0x{result.entry_point:08X}")
    print(f"기본 블록 수: {len(result.blocks)}")
    ret_blocks = sum(1 for b in result.blocks.values() if b.has_ret)
    call_blocks = sum(1 for b in result.blocks.values() if b.has_call)
    print(f"  RET 포함 블록: {ret_blocks}  CALL 포함 블록: {call_blocks}")
    print(f"\n{'─'*40}")
    for addr, blk in list(result.blocks.items())[:10]:
        flags = ""
        if blk.has_call:
            flags += " [CALL]"
        if blk.has_ret:
            flags += " [RET]"
        print(f"  BB @ 0x{addr:08X}  크기: {blk.end-blk.start}B{flags}")
    if len(result.blocks) > 10:
        print(f"  ... (총 {len(result.blocks)}개)")


def main() -> None:
    parser = argparse.ArgumentParser(description="ELF 바이너리 기본 CFG 추출기")
    parser.add_argument("files", nargs="+", type=Path)
    args = parser.parse_args()
    for fp in args.files:
        result = analyze_binary(fp)
        print_cfg(result)


if __name__ == "__main__":
    main()
```

---

## 실무 적용 시나리오

1. **취약점 헌팅**: CFG에서 복잡도가 높은 함수를 우선 분석
2. **패치 비교**: 취약점 패치 전/후 CFG 차이 분석
3. **유사 바이너리 탐지**: CFG 구조를 해시화하여 변종 악성코드 탐지

---

## 심화: 테인트 분석 — source/sink 모델

테인트 분석은 "오염원(source)"에서 들어온 데이터가 "위험 지점(sink)"에 검증 없이 도달하는지를 추적한다.

| 구분 | 예시 | 의미 |
|---|---|---|
| Source (오염원) | `recv`, `read`, `argv`, `getenv` | 외부에서 통제 가능한 입력 |
| Propagation (전파) | `strcpy`, `memcpy`, 산술 연산 | 오염이 다른 변수로 번짐 |
| Sanitizer (정화) | 길이 검사, 화이트리스트 | 오염 제거 — 안전해짐 |
| Sink (위험 지점) | `system`, `strcpy(dst,..)`, `printf(fmt)` | 오염 도달 시 취약 |

```
recv(buf) ──오염──► strcpy(local, buf) ──전파──► system(local)
  source                  propagation                sink
   ▲ 중간에 길이검사/화이트리스트(sanitizer) 없으면 → 명령 인젝션/오버플로
```

> 정적 테인트는 거짓양성이 많으므로, DynamoRIO/Pin 기반 **동적 테인트**로 실제 실행 경로에서 오염 흐름을 확인하면 정밀도가 높아진다.

---

## CFG 복잡도 기반 트리아지

대형 바이너리는 모든 함수를 볼 수 없으므로, **순환 복잡도(Cyclomatic Complexity)**로 우선순위를 정한다.

```
복잡도 M = E - N + 2P
  E = 엣지 수, N = 노드(블록) 수, P = 연결 컴포넌트 수
```

| 복잡도 M | 해석 | 분석 우선순위 |
|---|---|---|
| 1 ~ 10 | 단순 함수 | 낮음 |
| 11 ~ 20 | 중간 복잡 | 중간 |
| 21 ~ 50 | 복잡 — 버그 잠복 가능 | 높음 |
| > 50 | 파서/상태머신 — 핫스팟 | 최우선 |

> 위 Python CFG 추출기의 `blocks`/엣지 수로 M을 근사 계산해 분석 순서를 자동화할 수 있다.

---

## 패치 디핑(BinDiff) 워크플로우

```
취약 버전 vs 패치 버전 바이너리 확보
   │
   ▼
함수 단위 CFG 해시 매칭 (BinDiff/Diaphora)
   │
   ▼
변경된 함수만 추출 → 추가된 검사(길이·NULL·바운드) 식별
   │
   ▼
"무엇이 부족했는가" = 원본 취약점 → PoC/익스플로잇 역설계
```

---

## 빠른 자가진단 체크리스트

- [ ] source(외부 입력)와 sink(위험 함수)를 명확히 식별했는가?
- [ ] sanitizer(길이·바운드 검사)가 경로 중간에 있는지 확인했는가?
- [ ] 순환 복잡도로 분석 우선순위를 정했는가?
- [ ] 정적 테인트 거짓양성을 동적 테인트로 교차 검증했는가?
- [ ] 패치 디핑으로 추가된 검사를 원본 취약점과 매핑했는가?

---

## 요약

| 분석 기법 | 목적 | 도구 |
|---|---|---|
| CFG | 실행 흐름 시각화 | IDA, Ghidra, angr |
| Def-Use Chain | 변수 수명 추적 | Binary Ninja |
| Taint Analysis | 입력 오염 추적 | DynamoRIO, Pin |
| Pattern Matching | 취약점 패턴 인식 | CodeQL, Semgrep |
| 순환 복잡도 | 분석 트리아지 | IDA metrics |
| 패치 디핑 | 취약점 역설계 | BinDiff, Diaphora |

---

<a name="english"></a>

# Advanced Binary Analysis

## Concept Overview

A CFG (Control Flow Graph) represents program execution flow as a graph — like a subway map where each station (basic block) shows where execution can go under each condition. Tracking data flow on top of this enables automatic recognition of vulnerability patterns.

---

## Core Concepts

### Basic Block

A sequence of instructions with no internal branches — one entry, one exit.

### Data Flow Analysis

| Analysis Type | Description | Use Case |
|---|---|---|
| Def-Use Chain | Track variable definition to use | UAF detection |
| Taint Analysis | Trace how inputs propagate | SQL injection paths |
| Reaching Definition | Which definitions reach a point | Initialization checks |

---

## Summary Table

| Technique | Purpose | Tools |
|---|---|---|
| CFG | Visualize execution flow | IDA, Ghidra, angr |
| Def-Use Chain | Variable lifetime tracking | Binary Ninja |
| Taint Analysis | Input contamination tracing | DynamoRIO, Pin |
| Pattern Matching | Vulnerability pattern recognition | CodeQL, Semgrep |
| Cyclomatic complexity | Analysis triage | IDA metrics |
| Patch diffing | Vulnerability reversing | BinDiff, Diaphora |

---

## Deep Dive: Taint Analysis — Source/Sink Model

Taint analysis tracks whether data from a "source" reaches a dangerous "sink" without validation.

| Category | Examples | Meaning |
|---|---|---|
| Source | `recv`, `read`, `argv`, `getenv` | Externally controllable input |
| Propagation | `strcpy`, `memcpy`, arithmetic | Taint spreads to other variables |
| Sanitizer | Length check, allowlist | Removes taint — becomes safe |
| Sink | `system`, `strcpy(dst,..)`, `printf(fmt)` | Vulnerable if taint reaches |

```
recv(buf) ──tainted──► strcpy(local, buf) ──propagate──► system(local)
  source                   propagation                      sink
   ▲ no length check / allowlist (sanitizer) in between → cmd injection / overflow
```

> Static taint has many false positives; confirming taint flow on the real execution path with **dynamic taint** (DynamoRIO/Pin) improves precision.

---

## CFG Complexity–Based Triage

Large binaries can't be fully reviewed; prioritize by **cyclomatic complexity**.

```
Complexity M = E - N + 2P
  E = edges, N = nodes (blocks), P = connected components
```

| Complexity M | Interpretation | Priority |
|---|---|---|
| 1 ~ 10 | Simple function | Low |
| 11 ~ 20 | Moderate | Medium |
| 21 ~ 50 | Complex — bugs likely | High |
| > 50 | Parser/state machine — hotspot | Highest |

> You can approximate M from the `blocks`/edge counts of the Python CFG extractor above to automate review ordering.

---

## Patch Diffing (BinDiff) Workflow

```
Obtain vulnerable vs patched binaries
   │
   ▼
Match per-function CFG hashes (BinDiff/Diaphora)
   │
   ▼
Extract changed functions → identify added checks (length/NULL/bounds)
   │
   ▼
"What was missing" = original vuln → reverse-engineer PoC/exploit
```

---

## Quick Self-Assessment Checklist

- [ ] Did you clearly identify sources (external input) and sinks (dangerous functions)?
- [ ] Did you check for sanitizers (length/bounds checks) along the path?
- [ ] Did you prioritize review by cyclomatic complexity?
- [ ] Did you cross-check static taint false positives with dynamic taint?
- [ ] Did you map patch-diff added checks back to the original vulnerability?
