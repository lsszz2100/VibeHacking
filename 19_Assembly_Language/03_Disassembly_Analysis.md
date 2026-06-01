> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 디스어셈블리 분석

## 1. GDB / pwndbg 실전 명령어

### 1.1 pwndbg 설치 및 기본 설정

```bash
# pwndbg 설치
git clone https://github.com/pwndbg/pwndbg
cd pwndbg && ./setup.sh

# 또는 pip 설치
pip install pwndbg

# .gdbinit 설정
echo "source /path/to/pwndbg/gdbinit.py" >> ~/.gdbinit
echo "set disassembly-flavor intel" >> ~/.gdbinit
echo "set pagination off" >> ~/.gdbinit
```

### 1.2 pwndbg 전용 명령어

GDB 디버거 명령어입니다. 리버싱이나 익스플로잇 개발 시 프로그램 실행을 단계별로 제어하고 메모리/레지스터 상태를 확인합니다.

```gdb
# 컨텍스트 출력 (레지스터 + 스택 + 코드 한눈에)
context           # 현재 상태 전체 출력
context reg       # 레지스터만
context stack     # 스택만
context code      # 코드만
context args      # 함수 인자 추정

# 메모리 탐색
vmmap             # 가상 메모리 맵 출력
vmmap 0x401000    # 특정 주소가 속한 영역 확인
search -x "909090" # 패턴 검색 (NOP sled)
search -s "/bin/sh" # 문자열 검색
search -t qword 0x401234  # 특정 값 검색

# 스택/힙 분석
stack 20          # 스택 20개 항목 출력
telescope $rsp 20 # 스택 포인터 체이닝 분석 (포인터 추적)
telescope $rbp    # 스택 프레임 확인

# 힙 분석
heap              # 힙 청크 목록
bins              # 힙 bin 상태 (free list)
arena             # malloc arena 상태
vis_heap_chunks   # 힙 청크 시각화

# 심볼/라이브러리
info proc mappings  # 프로세스 메모리 매핑
got               # GOT(Global Offset Table) 내용
plt               # PLT 항목 목록
```

### 1.3 브레이크포인트 고급 활용

GDB 디버거 명령어입니다. 리버싱이나 익스플로잇 개발 시 프로그램 실행을 단계별로 제어하고 메모리/레지스터 상태를 확인합니다.

```gdb
# 함수 진입/반환 지점
break *main       # main 시작
break *main+100   # 오프셋
rbreak ^func_     # 정규식으로 모든 func_ 시작 함수

# 조건부/카운트
break *0x401234 if $rdi == 0
ignore 1 5        # 1번 브레이크포인트를 5번 무시 후 멈춤

# 명령어 자동 실행 (브레이크마다)
commands 1
    silent
    printf "RAX=%lx\n", $rax
    continue
end

# 하드웨어 브레이크포인트 (코드 수정 탐지 등)
hbreak *0x401000  # 하드웨어 실행 브레이크
watch  $rsp       # 스택 포인터 변경 감시
awatch *0x601060  # 읽기+쓰기 감시
```

### 1.4 메모리 조작 및 패치

GDB 디버거 명령어입니다. 리버싱이나 익스플로잇 개발 시 프로그램 실행을 단계별로 제어하고 메모리/레지스터 상태를 확인합니다.

```gdb
# 메모리 쓰기
set *0x601060 = 0xdeadbeef
set {char}0x401000 = 0x90  # NOP 패치
set {long long}$rsp = 0x1234

# 레지스터 변경
set $rip = 0x401234   # 실행 흐름 강제 변경
set $rax = 0
set $eflags = $eflags | 0x40  # ZF 비트 설정

# 메모리 덤프
dump binary memory out.bin 0x401000 0x402000
dump ihex memory out.hex 0x601000 0x602000

# 메모리 복원
restore out.bin binary 0x401000
```

### 1.5 동적 분석 스크립트 (.gdbinit)

```python
# gdb Python API 활용 예시
# ~/.gdbinit에 추가하거나 gdb -x script.py 로 실행

import gdb

class TraceFunc(gdb.Command):
    """특정 함수 호출 시 인자를 자동 출력."""

    def __init__(self):
        super().__init__("trace-func", gdb.COMMAND_USER)

    def invoke(self, args: str, from_tty: bool) -> None:
        func_name = args.strip()
        bp = gdb.Breakpoint(func_name)
        bp.commands = f"""
            printf "called {func_name}\\n"
            info args
            continue
        """
        print(f"[*] {func_name} 추적 시작")

TraceFunc()
```

---

## 2. IDA Pro 정적 분석 워크플로우

### 2.1 기본 단축키

| 단축키 | 기능 |
|--------|------|
| `F5`       | 현재 함수를 C 슈도코드로 디컴파일 (Hex-Rays) |
| `Space`    | 그래프 뷰 ↔ 텍스트 뷰 전환 |
| `N`        | 이름 변경 (변수/함수/레이블) |
| `Y`        | 타입 선언 변경 |
| `D`        | 데이터 타입 순환 (byte → word → dword → qword) |
| `C`        | 코드로 변환 (데이터 → 코드) |
| `U`        | 코드 → 데이터로 변환 (undefine) |
| `X`        | 크로스 참조 목록 |
| `G`        | 주소로 이동 |
| `Ctrl+F`   | 함수/이름 검색 |
| `Alt+T`    | 텍스트 검색 |
| `Alt+B`    | 바이트 패턴 검색 |
| `Ctrl+X`   | 선택된 심볼 크로스 참조 |
| `Tab`      | 어셈블리 ↔ 디컴파일 뷰 동기화 |
| `Ctrl+S`   | 세그먼트 목록 |
| `Shift+F12`| 문자열 목록 |

### 2.2 분석 워크플로우

```
1. 파일 열기 및 자동 분석 완료 대기
         ↓
2. 문자열 뷰 확인 (Shift+F12)
   - 의심 문자열: "/bin/sh", "cmd.exe", 암호화 키, URL 등
         ↓
3. import/export 확인
   - 수상한 API: VirtualAlloc, WriteProcessMemory, CreateRemoteThread
   - 암호화 관련: CryptDecrypt, BCryptEncrypt
         ↓
4. main/entry point에서 시작
   - 함수 호출 그래프 추적
   - 중요 로직 함수 이름 변경 (N)
         ↓
5. 크로스 참조 역추적 (X)
   - 관심 함수/변수가 어디서 호출되는지 파악
         ↓
6. 디컴파일러(F5)로 로직 이해
   - 변수/구조체 타입 정의 (Y)
   - 반복 구조 파악
         ↓
7. 패치/분석 결과 저장 (idb 파일)
```

### 2.3 IDAPython 자동화 스크립트

```python
# ida_find_calls.py — 특정 함수 호출 위치 수집
import idaapi
import idautils
import idc

def find_all_calls(func_name: str) -> list[int]:
    """지정한 함수명의 모든 호출 위치 반환."""
    ea = idc.get_name_ea_simple(func_name)
    if ea == idaapi.BADADDR:
        print(f"[-] 함수를 찾을 수 없음: {func_name}")
        return []

    call_sites: list[int] = []
    for xref in idautils.XrefsTo(ea, idaapi.XREF_FAR):
        call_sites.append(xref.frm)
        print(f"  {hex(xref.frm)}: {idc.generate_disasm_line(xref.frm, 0)}")

    return call_sites

# 실행
results = find_all_calls("printf")
print(f"\n총 {len(results)}개 호출 위치")
```

---

## 3. Ghidra 정적 분석 워크플로우

### 3.1 기본 단축키

| 단축키 | 기능 |
|--------|------|
| `L`        | 레이블/이름 변경 |
| `Ctrl+L`   | 함수 시그니처 변경 |
| `D`        | 디컴파일 창 열기/포커스 |
| `Ctrl+Z`   | 실행 취소 |
| `G`        | 주소로 이동 |
| `Ctrl+F`   | 검색 |
| `T`        | 타입 선언 적용 |
| `Alt+Left` | 이전 위치로 이동 |
| `Ctrl+E`   | 내보내기 |

### 3.2 Ghidra Script (Python 3)


Ghidra는 NSA가 개발한 오픈소스 리버스 엔지니어링 프레임워크입니다. C 코드 수준의 디컴파일, 멀티아키텍처 지원, 협업 기능이 장점이며, IDA Pro의 무료 대안으로 많이 활용됩니다.

```python
# GhidraScript — 함수 목록 및 크기 출력
# Ghidra Script Manager에서 실행

from ghidra.program.model.listing import Function
from ghidra.app.script import GhidraScript

listing = currentProgram.getListing()
func_iter = listing.getFunctions(True)

funcs: list[tuple[str, int, int]] = []
for func in func_iter:
    body = func.getBody()
    funcs.append((
        func.getName(),
        func.getEntryPoint().getOffset(),
        body.getNumAddresses()
    ))

# 크기 기준 내림차순 정렬
funcs.sort(key=lambda x: x[2], reverse=True)

print("=== 함수 목록 (크기 순) ===")
for name, addr, size in funcs[:20]:
    print(f"  {addr:#010x}  {size:6d} bytes  {name}")
```

---

## 4. objdump / readelf 활용

### 4.1 objdump 주요 옵션


바이너리 역어셈블리 분석 명령어입니다. `objdump -d`로 모든 실행 섹션을, `-M intel`로 Intel 문법으로 출력합니다. 특정 함수 분석 시 `grep -A 30 '<함수명>'`으로 해당 부분만 추출합니다.

```bash
# 전체 디스어셈블 (Intel 문법)
objdump -d -M intel ./binary

# 전체 디스어셈블 (소스 포함, 디버그 심볼 필요)
objdump -d -M intel -S ./binary

# 특정 섹션만
objdump -d -M intel -j .text ./binary
objdump -s -j .data ./binary    # 데이터 섹션 헥스 덤프
objdump -s -j .rodata ./binary  # 읽기전용 데이터

# 섹션 헤더 목록
objdump -h ./binary

# 심볼 테이블
objdump -t ./binary             # 전체 심볼
objdump -T ./binary             # 동적 심볼

# 재배치 정보
objdump -R ./binary             # 동적 재배치 (PLT/GOT)
objdump -r ./binary             # 정적 재배치

# 바이트 포함 디스어셈블
objdump -d -M intel --show-raw-insn ./binary
```

### 4.2 readelf 주요 옵션

```bash
# ELF 헤더
readelf -h ./binary

# 섹션 헤더 테이블
readelf -S ./binary

# 프로그램 헤더 (세그먼트)
readelf -l ./binary

# 심볼 테이블
readelf -s ./binary             # 정적 심볼
readelf -s --wide ./binary      # 긴 이름 잘림 없이

# 동적 섹션 (.dynamic)
readelf -d ./binary

# 재배치 섹션
readelf -r ./binary

# 노트 섹션 (빌드ID 등)
readelf -n ./binary

# 헥스 덤프
readelf -x .rodata ./binary     # .rodata 헥스 덤프
readelf -p .rodata ./binary     # .rodata 문자열 덤프

# DWARF 디버그 정보
readelf --debug-dump=info ./binary
readelf --debug-dump=frames ./binary   # 스택 언와인드 정보

# GNU 해시 확인
readelf -x .gnu.hash ./binary
```

### 4.3 실전 분석 커맨드

```bash
# 보안 기법 확인 (checksec 없을 때)
readelf -l ./binary | grep -E "GNU_STACK|GNU_RELRO"
readelf -d ./binary | grep -E "BIND_NOW|FLAGS"
readelf -s ./binary | grep -i "canary\|stack_chk"

# NX 비트 확인
readelf -l ./binary | grep "GNU_STACK" | awk '{print $NF}'
# RWE면 NX 없음, RW면 NX 있음

# PIE 확인 (Type이 DYN이면 PIE)
readelf -h ./binary | grep "Type:"

# PLT 분석 (호출되는 외부 함수)
objdump -d -M intel -j .plt ./binary

# GOT 내용 (실행 중 주소 확인)
objdump -d -M intel -j .got.plt ./binary
```

---

## 5. 함수 프롤로그/에필로그 패턴 인식

### 5.1 표준 프롤로그 패턴

```
패턴 1 (전통적)
55           push rbp
48 89 e5     mov  rbp, rsp
48 83 ec XX  sub  rsp, 0xXX

패턴 2 (최적화 — 프레임 포인터 생략)
48 83 ec XX  sub  rsp, 0xXX

패턴 3 (스택 카나리 포함)
55           push rbp
48 89 e5     mov  rbp, rsp
48 83 ec XX  sub  rsp, 0xXX
64 48 8b 04 25 28 00 00 00   mov rax, fs:0x28   ; 카나리 로드
48 89 45 f8  mov  QWORD PTR [rbp-0x8], rax      ; 카나리 저장
```

### 5.2 에필로그 패턴

```
패턴 1 (LEAVE + RET)
c9           leave        ; = mov rsp, rbp + pop rbp
c3           ret

패턴 2 (명시적)
48 89 ec     mov  rsp, rbp
5d           pop  rbp
c3           ret

패턴 3 (카나리 검사 포함)
48 8b 45 f8  mov  rax, QWORD PTR [rbp-0x8]  ; 카나리 로드
64 48 33 04 25 28 00 00 00  xor rax, fs:0x28 ; 검증
74 xx        je   .ok                         ; 일치하면 정상
e8 xx xx xx xx  call __stack_chk_fail         ; 불일치 → 종료
.ok:
c9           leave
c3           ret
```

### 5.3 패턴으로 파악할 수 있는 정보

```
프롤로그 sub rsp 크기 → 지역 변수 총 크기 추정
카나리 존재 → 스택 버퍼 오버플로우 보호 활성
LEAVE 패턴 → 컴파일러가 프레임 포인터 사용
call __stack_chk_fail → __attribute__((stack_protector)) 적용됨
RET 앞 XOR → 카나리 검증
```

---

## 6. 리버싱 Python 자동화 스크립트 (Capstone)

```python
#!/usr/bin/env python3
"""
disasm_tool.py — Capstone 기반 바이너리 디스어셈블러

사용법:
    python disasm_tool.py -f ./binary
    python disasm_tool.py -f ./binary --arch x64 --section .text
    python disasm_tool.py -f ./binary --offset 0x1000 --size 256
    python disasm_tool.py --hex "4831d2524889e7" --arch x64
    python disasm_tool.py -f ./binary --find-calls printf
"""

import argparse
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Generator

try:
    import capstone as cs
except ImportError:
    print("[-] capstone 미설치: pip install capstone")
    sys.exit(1)

try:
    from elftools.elf.elffile import ELFFile
    HAS_ELFTOOLS = True
except ImportError:
    HAS_ELFTOOLS = False


# ──────────────────────────────────────────────
# 아키텍처 설정
# ──────────────────────────────────────────────

ARCH_MAP: dict[str, tuple[int, int]] = {
    "x86":   (cs.CS_ARCH_X86,  cs.CS_MODE_32),
    "x64":   (cs.CS_ARCH_X86,  cs.CS_MODE_64),
    "arm":   (cs.CS_ARCH_ARM,  cs.CS_MODE_ARM),
    "arm64": (cs.CS_ARCH_ARM64, cs.CS_MODE_ARM),
    "mips":  (cs.CS_ARCH_MIPS, cs.CS_MODE_MIPS32),
}


@dataclass
class Instruction:
    """디스어셈블된 명령어 표현."""
    address: int
    mnemonic: str
    op_str: str
    bytes_: bytes

    def __str__(self) -> str:
        hex_bytes = " ".join(f"{b:02x}" for b in self.bytes_)
        return f"{self.address:#010x}  {hex_bytes:<24s}  {self.mnemonic} {self.op_str}"


@dataclass
class DisasmResult:
    """디스어셈블 결과 묶음."""
    instructions: list[Instruction] = field(default_factory=list)
    arch: str = "x64"
    base_address: int = 0

    @property
    def count(self) -> int:
        return len(self.instructions)


# ──────────────────────────────────────────────
# 디스어셈블 코어
# ──────────────────────────────────────────────

def make_disasm(arch: str) -> cs.Cs:
    """아키텍처 이름으로 Capstone 인스턴스 생성."""
    if arch not in ARCH_MAP:
        raise ValueError(f"지원하지 않는 아키텍처: {arch}. 지원 목록: {list(ARCH_MAP)}")
    arch_id, mode_id = ARCH_MAP[arch]
    md = cs.Cs(arch_id, mode_id)
    md.detail = True
    return md


def disassemble_bytes(
    data: bytes,
    arch: str,
    base_addr: int = 0,
) -> Generator[Instruction, None, None]:
    """
    바이트열을 디스어셈블하여 Instruction을 순차 반환.

    Args:
        data:      디스어셈블할 바이트열
        arch:      아키텍처 문자열 ("x64", "x86", "arm64" 등)
        base_addr: 시작 가상 주소

    Yields:
        Instruction 객체
    """
    md = make_disasm(arch)
    for insn in md.disasm(data, base_addr):
        yield Instruction(
            address=insn.address,
            mnemonic=insn.mnemonic,
            op_str=insn.op_str,
            bytes_=bytes(insn.bytes),
        )


# ──────────────────────────────────────────────
# ELF 파일 처리
# ──────────────────────────────────────────────

def read_elf_section(
    path: Path,
    section_name: str,
) -> tuple[bytes, int]:
    """
    ELF 파일에서 지정 섹션의 데이터와 로드 주소 반환.

    Returns:
        (섹션 데이터, 가상 주소)

    Raises:
        ImportError: pyelftools 미설치
        ValueError:  섹션 없음
    """
    if not HAS_ELFTOOLS:
        raise ImportError("pyelftools 미설치: pip install pyelftools")

    with path.open("rb") as f:
        elf = ELFFile(f)
        sec = elf.get_section_by_name(section_name)
        if sec is None:
            raise ValueError(f"섹션을 찾을 수 없음: {section_name}")
        return sec.data(), sec["sh_addr"]


def read_elf_at_offset(
    path: Path,
    offset: int,
    size: int,
) -> tuple[bytes, int]:
    """파일 오프셋에서 size 바이트 읽기."""
    data = path.read_bytes()
    return data[offset: offset + size], offset


def list_elf_sections(path: Path) -> list[dict[str, object]]:
    """ELF 섹션 목록 반환."""
    if not HAS_ELFTOOLS:
        raise ImportError("pyelftools 미설치: pip install pyelftools")

    sections: list[dict[str, object]] = []
    with path.open("rb") as f:
        elf = ELFFile(f)
        for sec in elf.iter_sections():
            sections.append({
                "name": sec.name,
                "addr": sec["sh_addr"],
                "offset": sec["sh_offset"],
                "size": sec["sh_size"],
                "type": sec["sh_type"],
            })
    return sections


# ──────────────────────────────────────────────
# 분석 기능
# ──────────────────────────────────────────────

def find_calls(
    instructions: list[Instruction],
    target_name: str | None = None,
) -> list[Instruction]:
    """
    call 명령어 목록 반환.

    Args:
        instructions: 전체 명령어 목록
        target_name:  특정 피호출 대상 필터 (부분 일치)

    Returns:
        call 명령어 목록
    """
    calls: list[Instruction] = []
    for insn in instructions:
        if insn.mnemonic.startswith("call"):
            if target_name is None or target_name.lower() in insn.op_str.lower():
                calls.append(insn)
    return calls


def find_pattern(
    instructions: list[Instruction],
    mnemonic_seq: list[str],
) -> list[list[Instruction]]:
    """
    명령어 니모닉 시퀀스 패턴 검색.

    예: ["push", "mov", "sub"] → 프롤로그 패턴 검색

    Returns:
        패턴이 일치하는 명령어 그룹 목록
    """
    results: list[list[Instruction]] = []
    n = len(mnemonic_seq)
    for i in range(len(instructions) - n + 1):
        window = instructions[i: i + n]
        if all(
            w.mnemonic == p
            for w, p in zip(window, mnemonic_seq)
        ):
            results.append(window)
    return results


def find_function_prologues(instructions: list[Instruction]) -> list[int]:
    """
    표준 함수 프롤로그 패턴으로 함수 시작 주소 후보 반환.

    인식 패턴:
        push rbp / mov rbp, rsp
        또는 sub rsp, imm
    """
    prologues: list[int] = []

    for i, insn in enumerate(instructions):
        # 패턴: push rbp → mov rbp, rsp
        if (
            insn.mnemonic == "push"
            and "rbp" in insn.op_str
            and i + 1 < len(instructions)
            and instructions[i + 1].mnemonic == "mov"
            and "rbp, rsp" in instructions[i + 1].op_str
        ):
            prologues.append(insn.address)

    return prologues


def find_syscalls(instructions: list[Instruction]) -> list[Instruction]:
    """syscall / int 0x80 명령어 위치 반환."""
    return [
        insn for insn in instructions
        if insn.mnemonic in ("syscall", "int") and (
            insn.mnemonic == "syscall" or "0x80" in insn.op_str
        )
    ]


# ──────────────────────────────────────────────
# 출력 포맷
# ──────────────────────────────────────────────

def print_instructions(
    instructions: list[Instruction],
    limit: int | None = None,
    show_bytes: bool = True,
) -> None:
    """명령어 목록을 형식에 맞게 출력."""
    for i, insn in enumerate(instructions):
        if limit is not None and i >= limit:
            print(f"  ... ({len(instructions) - limit}개 생략)")
            break
        if show_bytes:
            hex_b = " ".join(f"{b:02x}" for b in insn.bytes_)
            print(f"  {insn.address:#010x}  {hex_b:<24s}  {insn.mnemonic:<8s} {insn.op_str}")
        else:
            print(f"  {insn.address:#010x}  {insn.mnemonic:<8s} {insn.op_str}")


# ──────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Capstone 기반 바이너리 디스어셈블 분석 도구",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
예시:
  %(prog)s -f ./binary
  %(prog)s -f ./binary --arch x64 --section .text
  %(prog)s -f ./binary --offset 0x1000 --size 256
  %(prog)s --hex "4831d2524889e7b03b0f05" --arch x64
  %(prog)s -f ./binary --find-calls printf
  %(prog)s -f ./binary --find-prologues
  %(prog)s -f ./binary --list-sections
        """,
    )

    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument("-f", "--file", type=Path, metavar="FILE", help="분석할 바이너리")
    src.add_argument("--hex", metavar="HEX", help="헥스 문자열 직접 입력")

    parser.add_argument(
        "--arch",
        choices=list(ARCH_MAP),
        default="x64",
        help="아키텍처 (기본: x64)",
    )
    parser.add_argument(
        "--section",
        metavar="NAME",
        default=".text",
        help="분석할 ELF 섹션 (기본: .text)",
    )
    parser.add_argument(
        "--offset",
        type=lambda x: int(x, 0),
        metavar="OFFSET",
        help="파일 오프셋 (0x... 또는 10진수)",
    )
    parser.add_argument(
        "--size",
        type=lambda x: int(x, 0),
        metavar="BYTES",
        default=256,
        help="읽을 바이트 수 (기본: 256)",
    )
    parser.add_argument(
        "--base-addr",
        type=lambda x: int(x, 0),
        metavar="ADDR",
        default=0,
        help="기준 가상 주소 (--hex 또는 --offset 사용 시)",
    )
    parser.add_argument(
        "--limit",
        type=int,
        metavar="N",
        help="출력할 최대 명령어 수",
    )
    parser.add_argument(
        "--find-calls",
        metavar="TARGET",
        nargs="?",
        const="",
        help="call 명령어 검색 (TARGET 생략 시 전체)",
    )
    parser.add_argument(
        "--find-prologues",
        action="store_true",
        help="함수 프롤로그 패턴 검색",
    )
    parser.add_argument(
        "--find-syscalls",
        action="store_true",
        help="syscall / int 0x80 위치 검색",
    )
    parser.add_argument(
        "--list-sections",
        action="store_true",
        help="ELF 섹션 목록만 출력",
    )
    parser.add_argument(
        "--no-bytes",
        action="store_true",
        help="명령어 바이트 출력 생략",
    )

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    # ── 섹션 목록만 출력 ──
    if args.list_sections:
        if not args.file:
            print("[-] --list-sections은 -f 옵션 필요")
            return 1
        try:
            sections = list_elf_sections(args.file)
        except (ImportError, OSError) as e:
            print(f"[-] {e}")
            return 1
        print(f"{'이름':<20s} {'주소':>12s} {'오프셋':>12s} {'크기':>10s}  타입")
        print("-" * 65)
        for s in sections:
            print(
                f"{s['name']:<20s} {s['addr']:>#12x} "
                f"{s['offset']:>#12x} {s['size']:>10d}  {s['type']}"
            )
        return 0

    # ── 바이트 데이터 로드 ──
    base_addr = args.base_addr
    try:
        if args.hex:
            cleaned = (
                args.hex.replace("\\x", "").replace("0x", "")
                        .replace(" ", "").replace("\n", "")
            )
            data = bytes.fromhex(cleaned)
        elif args.offset is not None:
            data, base_addr = read_elf_at_offset(args.file, args.offset, args.size)
        else:
            try:
                data, base_addr = read_elf_section(args.file, args.section)
            except (ImportError, ValueError) as e:
                print(f"[-] ELF 섹션 로드 실패: {e}")
                print("    --offset 옵션으로 파일 오프셋을 직접 지정하세요.")
                return 1
    except (FileNotFoundError, ValueError, OSError) as e:
        print(f"[-] 데이터 로드 실패: {e}")
        return 1

    print(f"[*] 아키텍처: {args.arch}")
    print(f"[*] 데이터 크기: {len(data)} bytes")
    print(f"[*] 기준 주소: {base_addr:#x}")
    print()

    # ── 디스어셈블 ──
    try:
        instructions = list(disassemble_bytes(data, args.arch, base_addr))
    except ValueError as e:
        print(f"[-] 디스어셈블 실패: {e}")
        return 1

    print(f"[+] 명령어 {len(instructions)}개 디스어셈블 완료")
    print()

    # ── 모드별 출력 ──
    any_mode = False

    if args.find_calls is not None:
        any_mode = True
        target = args.find_calls if args.find_calls else None
        calls = find_calls(instructions, target)
        label = f'"{target}"' if target else "전체"
        print(f"[+] call 명령어 {len(calls)}개 ({label}):")
        print_instructions(calls, show_bytes=not args.no_bytes)
        print()

    if args.find_prologues:
        any_mode = True
        prologues = find_function_prologues(instructions)
        print(f"[+] 함수 프롤로그 후보 {len(prologues)}개:")
        for addr in prologues:
            print(f"  {addr:#010x}")
        print()

    if args.find_syscalls:
        any_mode = True
        syscalls = find_syscalls(instructions)
        print(f"[+] syscall 위치 {len(syscalls)}개:")
        print_instructions(syscalls, show_bytes=not args.no_bytes)
        print()

    if not any_mode:
        print("[+] 디스어셈블 결과:")
        print_instructions(instructions, limit=args.limit, show_bytes=not args.no_bytes)

    return 0


if __name__ == "__main__":
    sys.exit(main())
```

---

## 7. 실전 분석 시나리오

### 7.1 CTF 바이너리 초기 분석 체크리스트

```bash
# 1. 파일 형식 및 아키텍처 확인
file ./challenge

# 2. 보안 기법 확인
checksec --file=./challenge
# 또는
python3 - <<'EOF'
import subprocess, re
out = subprocess.check_output(["readelf", "-h", "-l", "-d", "-s", "./challenge"],
                              stderr=subprocess.DEVNULL, text=True)
checks = {
    "PIE":     "Type:.*DYN" in out,
    "NX":      "GNU_STACK.*RW " in out,
    "Canary":  "__stack_chk" in out,
    "RELRO":   "GNU_RELRO" in out,
    "BIND_NOW":"BIND_NOW" in out or "(NOW)" in out,
}
for k, v in checks.items():
    status = "ON" if v else "OFF"
    print(f"  {k:<10}: {status}")
EOF

# 3. 문자열 검색
strings ./challenge | grep -E '/bin|sh|flag|password|key'

# 4. 동적 의존성
ldd ./challenge

# 5. 섹션 구조
readelf -S ./challenge | grep -E "\.text|\.data|\.bss|\.got|\.plt"

# 6. 외부 함수 호출 목록
objdump -d -M intel -j .plt ./challenge | grep "@plt"
```

### 7.2 GDB + pwndbg 리버싱 세션 예시

GDB 디버거 명령어입니다. 리버싱이나 익스플로잇 개발 시 프로그램 실행을 단계별로 제어하고 메모리/레지스터 상태를 확인합니다.

```gdb
gdb ./challenge

# 진입점 확인
info file

# main 찾아서 브레이크
break main
run

# 컨텍스트 확인
context

# GOT 확인
got

# 스택 카나리 위치 찾기
info frame
x/20gx $rsp

# 반복 실행하며 레지스터 추적
define trace_rax
    while 1
        ni
        printf "rip=%lx rax=%lx\n", $rip, $rax
    end
end
```

### 7.3 Capstone + pwntools 연동

pwntools 라이브러리로 EIP 오프셋 계산과 익스플로잇 작성을 자동화합니다. cyclic, p32, remote, process 함수를 활용합니다.

```python
#!/usr/bin/env python3
"""combined_analysis.py — pwntools + Capstone 연동 분석."""

from pwn import ELF, context
import capstone as cs

def analyze_binary(path: str) -> None:
    context.log_level = "warning"
    elf = ELF(path)

    # .text 섹션 데이터
    text_data = elf.get_section_by_name(".text").data()
    text_addr = elf.get_section_by_name(".text")["sh_addr"]

    # Capstone 디스어셈블
    md = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_64)
    md.detail = True

    calls: list[tuple[int, str]] = []
    for insn in md.disasm(text_data, text_addr):
        if insn.mnemonic == "call":
            # PLT 심볼 역조회
            target_addr = int(insn.op_str, 16) if insn.op_str.startswith("0x") else 0
            sym_name = elf.reverse_lookup(target_addr) or insn.op_str
            calls.append((insn.address, sym_name))

    print(f"[+] call 명령어 {len(calls)}개:")
    for addr, target in calls:
        print(f"  {addr:#010x} → {target}")

    # GOT 엔트리 출력
    print("\n[+] GOT 엔트리:")
    for sym, addr in elf.got.items():
        print(f"  {sym:<30s} {addr:#010x}")

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print(f"사용법: {sys.argv[0]} <binary>")
        sys.exit(1)
    analyze_binary(sys.argv[1])
```

---

<a name="english"></a>

# Disassembly Analysis

## 1. GDB / pwndbg Practical Commands

### pwndbg Installation and Configuration

```bash
# Install pwndbg
git clone https://github.com/pwndbg/pwndbg
cd pwndbg && ./setup.sh

# Basic usage
gdb ./binary
gdb -q ./binary    # Quiet mode

# Attach to running process
gdb -p PID
```

### Core pwndbg Commands

```bash
# Basic commands
run [args]         # Run program
continue / c       # Continue execution
break *0x401234    # Set breakpoint at address
break main         # Set breakpoint at function
info breakpoints   # List breakpoints
delete 1           # Delete breakpoint 1

# Information
info registers     # Show all registers
registers          # pwndbg: colored register display
stack 20           # Show stack (20 entries)
telescope esp 20   # pwndbg: annotated stack
backtrace / bt     # Call stack

# Memory examination
x/10x $esp         # Hex, 10 words from esp
x/s 0x4040a0       # Show as string
x/20i $rip         # Show 20 instructions
disass main        # Disassemble function

# pwndbg specific
checksec           # Binary protection check
vmmap              # Memory map
heap               # Heap analysis
```

---

## 2. Ghidra Usage Guide

```
Ghidra workflow:

1. Create new project
   File → New Project → Non-Shared Project

2. Import binary
   File → Import File → select binary

3. Auto-analysis
   When prompted: Analyze → Yes
   Wait for analysis to complete (~30 seconds)

4. Key views
   - Symbol Tree: Functions, imports, exports
   - Listing: Disassembly view
   - Decompiler: C pseudocode (window)
   - Function Graph: Visual flow

5. Rename functions/variables
   Press 'L' on function name → Rename
   Context menu → Edit Function Signature

6. Find key functions
   Ctrl+Shift+F → Search for text in decompiled code
   Look for: strcmp, strcpy, scanf, gets, malloc, free
```

---

## 3. radare2 Analysis

```bash
# Basic analysis
r2 ./binary          # Open binary
r2 -A ./binary       # Open and auto-analyze
r2 -d ./binary       # Open in debug mode

# Analysis commands (prefix: a)
aa               # Auto-analyze
aaa              # Deep analysis (more thorough)
afl              # List all functions
afn main         # Rename function to "main"
af @ sym.main    # Analyze specific function

# Navigation
s main           # Seek to main
s 0x401234       # Seek to address
pdf @ sym.main   # Print disassembly of function

# Print/display (prefix: p)
pd 20            # Print 20 disassembly lines
px 32            # Print 32 bytes in hex
ps @ 0x4040a0    # Print string at address
pf xxx @ 0x1234  # Print formatted struct

# Cross-references
axt 0x4040a0     # Find all references to address
axf 0x401234     # Find all calls from function

# Visual mode
V                # Visual mode
p                # Cycle display formats
:               # Enter command
```

---

## 4. Binary Analysis Script

```python
#!/usr/bin/env python3
"""Automated binary analysis using pwntools and radare2"""
import subprocess
import json
from pwn import ELF, context

def analyze_binary(binary_path: str) -> dict:
    """Comprehensive binary analysis"""
    
    results = {
        "path": binary_path,
        "protections": {},
        "functions": [],
        "strings": [],
        "imports": []
    }
    
    # pwntools ELF analysis
    try:
        elf = ELF(binary_path)
        results["protections"] = {
            "ASLR": "check /proc/sys/kernel/randomize_va_space",
            "NX": elf.nx,
            "PIE": elf.pie,
            "RELRO": "full" if elf.relro == "full" else "partial" if elf.relro else "none",
            "Canary": elf.canary
        }
        
        # Get functions
        results["functions"] = [
            {"name": name, "address": hex(addr)} 
            for name, addr in elf.symbols.items() 
            if addr > 0
        ]
        
        # Get strings (dangerous ones)
        dangerous_funcs = ['gets', 'strcpy', 'sprintf', 'scanf', 
                          'system', 'exec', 'popen']
        results["dangerous_imports"] = [
            f for f in dangerous_funcs 
            if f in elf.plt
        ]
        
    except Exception as e:
        results["error"] = str(e)
    
    return results

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <binary>")
        sys.exit(1)
    
    result = analyze_binary(sys.argv[1])
    print(json.dumps(result, indent=2))
```
