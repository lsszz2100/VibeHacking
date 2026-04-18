# OllyDbg & x64dbg 실전 사용 가이드

## 1. OllyDbg 기본 레이아웃

```
┌──────────────────────────────────────────────────────────┐
│  [Menu Bar]  File, View, Debug, Plugins, Options          │
├──────────────────────────┬───────────────────────────────┤
│  [디스어셈블리 창]         │  [레지스터 창]                 │
│  주소 | 옵코드 | 어셈블리  │  EAX: 00000000               │
│  004011A0 | 55 | PUSH EBP│  EBX: 7FFD7000               │
│  004011A1 | 89E5 | MOV..  │  ECX: 00000001               │
│                          │  EDX: 00000000               │
│                          │  ESI: 00000000               │
│                          │  EDI: 00000000               │
│                          │  EBP: 0019FF94               │
│                          │  ESP: 0019FF90               │
│                          │  EIP: 004011A0               │
├──────────────────────────┼───────────────────────────────┤
│  [메모리/덤프 창]         │  [스택 창]                     │
│  주소 | 16진수 | ASCII    │  0019FF90: 004011C5           │
└──────────────────────────┴───────────────────────────────┘
```

---

## 2. OllyDbg 핵심 단축키

| 단축키 | 기능 | 설명 |
|--------|------|------|
| **F2** | BreakPoint 설정/해제 | 현재 줄에 중단점 설정 |
| **F7** | Step Into | 함수 내부로 진입 |
| **F8** | Step Over | 함수를 한 줄로 실행 |
| **F9** | Run | 실행 (다음 BreakPoint까지) |
| **Ctrl+F2** | Restart | 프로그램 재시작 |
| **Ctrl+G** | Go To Address | 특정 주소로 이동 |
| **Ctrl+F9** | Execute Till Return | 현재 함수 끝까지 실행 |
| **Alt+M** | Memory Map | 메모리 맵 보기 |
| **Alt+K** | Call Stack | 호출 스택 보기 |
| **Enter** | Follow | 점프/함수 내부로 이동 |
| **-** (마이너스) | 이전으로 | 이전 뷰로 돌아가기 |
| **Spacebar** | Assemble | 코드 직접 수정 |
| **;** (세미콜론) | Comment | 주석 추가 |
| **:** (콜론) | Label | 레이블 추가 |
| **Ctrl+A** | Analyse | 코드 분석 재실행 |

---

## 3. 브레이크포인트 종류

### 소프트웨어 브레이크포인트 (F2)
```
- 해당 주소의 첫 번째 바이트를 0xCC (INT 3)로 교체
- 가장 일반적인 브레이크포인트
- 프로그램 실행 중 0xCC 실행 시 디버거에 제어 넘김

설정 방법:
  1. 디스어셈블리 창에서 원하는 줄 클릭
  2. F2 또는 더블클릭으로 설정
  3. 빨간색으로 표시됨
```

### 하드웨어 브레이크포인트
```
- DR0~DR3 디버그 레지스터 사용
- 최대 4개
- 실행/읽기/쓰기 조건 지정 가능

설정 방법:
  1. 주소 우클릭
  2. Breakpoint → Hardware → Execute/Write/Read
  
용도: 안티디버깅 우회 (INT 3 체크하는 경우)
```

### 메모리 브레이크포인트
```
- 특정 메모리 영역 접근 시 중단
- 버퍼에 언제 값이 쓰이는지 추적에 유용

설정 방법 (Memory Map 창):
  1. Alt+M으로 Memory Map 열기
  2. 원하는 영역 선택
  3. F2 또는 우클릭 → Set Memory Breakpoint
```

### 조건 브레이크포인트 (Conditional)
```
특정 조건이 충족될 때만 중단:
  1. 브레이크포인트 설정 후
  2. Breakpoints 창에서 우클릭 → Condition 입력
  
예: EAX == 1 일 때만 중단
    ECX > 100 일 때만 중단
```

---

## 4. 실전 분석 시나리오

### 시나리오 1: 시리얼 넘버 크래킹
```
목표: 입력한 시리얼이 맞는지 확인하는 루틴 찾기

방법:
1. 프로그램 실행 후 틀린 시리얼 입력
2. "Wrong" 또는 "Invalid" 문자열 검색
   → 우클릭 → Search for → All referenced text strings
3. 에러 메시지 줄에 브레이크포인트
4. 다시 실행 → 브레이크포인트에서 멈춤
5. 역방향으로 비교 루틴(CMP/JE) 찾기
6. 조건 분기를 NOP으로 패치하거나 방향 변경
```

### 시나리오 2: 조건 분기 패치
```asm
; 원본 코드 (틀린 시리얼 시 에러로 점프)
004011A0: CMP EAX, ECX
004011A2: JNE 004011B0   ; 다르면 에러 루틴으로

; 패치 방법 1: JNE → JMP (항상 성공 루틴으로)
  Spacebar → JMP 004011B0 → 성공 루틴 주소로 변경

; 패치 방법 2: JNE → NOP (분기 무력화)
  두 바이트를 NOP(0x90)으로 채우기
  JNE(0x75, 거리) → 0x90 0x90

; 패치 적용:
  Spacebar 키로 어셈블리 직접 편집 가능
```

### 시나리오 3: 안티 디버깅 우회

#### IsDebuggerPresent 우회
```asm
; 안티디버깅 코드 패턴
CALL DWORD PTR [<&KERNEL32.IsDebuggerPresent>]
TEST EAX, EAX
JNZ  anti_debug_exit    ; 디버거 탐지 시 종료

; 우회 방법 1: JNZ → NOP
; 우회 방법 2: CALL 후 EAX를 0으로 설정
;   → 레지스터 창에서 EAX 값 더블클릭 → 0으로 변경
```

#### 타이밍 공격 우회 (GetTickCount)
```asm
; 프로그램 실행 시간으로 디버거 탐지
CALL GetTickCount
MOV  saved_tick, EAX
; ... 코드 실행 ...
CALL GetTickCount
SUB  EAX, saved_tick
CMP  EAX, 1000h          ; 4096ms 초과 시 디버거로 판단
JA   anti_debug_exit

; 우회: JA → NOP
;       또는 EAX를 작은 값으로 수동 변경
```

---

## 5. 리버싱 기초 실습 과제

### 과제 1: 조건 분기 분석
```c
// 대상 프로그램 (소스코드 모름, 바이너리만 분석)
// 목표: 올바른 입력값 찾기 또는 우회

/* 어셈블리로 보이는 코드:
00401020: PUSH EBP
00401021: MOV EBP, ESP
00401023: MOV EAX, DWORD PTR [EBP+8]  ; 입력값
00401026: CMP EAX, 3E7h               ; 999와 비교
0040102B: JNE 0040103A                 ; 다르면 실패
0040102D: PUSH "Success!"
00401032: CALL MessageBox
...
0040103A: PUSH "Fail!"
...
*/

// 해결책:
// 1. 입력값으로 999(0x3E7)를 입력
// 2. 또는 JNE를 NOP으로 패치
```

### 과제 2: 변수 추적
```asm
; 코드에서 특정 변수의 값 추적
; n=33670, m=178503이 되도록 패치하기

; 접근 방법:
; 1. MessageBox 호출 전 브레이크포인트 설정
; 2. 역방향으로 n, m이 계산되는 루틴 찾기
; 3. 레지스터/메모리 값을 원하는 값으로 수동 변경
; 4. 또는 계산 루틴을 MOV n, 33670h로 패치
```

### 과제 3: 인자 분석
```asm
; 함수 첫 번째 인자 조건 분석

PUSH 인자2
PUSH 인자1           ; 스택에 인자 저장 (역순)
CALL 00401050

; 함수 내부
00401050: PUSH EBP
00401051: MOV EBP, ESP
00401053: MOV EAX, DWORD PTR [EBP+8]  ; 인자1 = 첫 번째 인자
00401056: CMP EAX, 특정값
...

; OllyDbg에서:
; CALL 시 F7로 진입 → EBP+8, EBP+C의 값 확인
```

---

## 6. IDA Pro 기초

### 주요 뷰
```
Graph View: 함수의 흐름을 다이어그램으로 표시
Text View:  전통적인 어셈블리 텍스트 뷰
Hex View:   원시 바이트 뷰
Pseudocode: 디컴파일된 C 유사 코드 (IDA Pro 기능)
```

### 기본 단축키
| 단축키 | 기능 |
|--------|------|
| F5 | 디컴파일 (Pseudocode) |
| Space | Graph/Text 뷰 전환 |
| G | 주소로 이동 |
| N | 이름 변경 |
| ; | 주석 추가 |
| Esc | 이전 위치로 |
| X | 크로스 레퍼런스 |
| Ctrl+F | 텍스트 검색 |
| Alt+T | 텍스트 검색 (전체) |

### 크로스 레퍼런스 (XREF) 활용
```
특정 함수/변수를 누가 호출하는지 추적:
  1. 함수명 또는 변수명에서 X 키
  2. 모든 호출 위치 목록 표시
  3. 분석 경로 역방향 추적에 필수

예: "Wrong Serial" 문자열에서 X → 어디서 출력하는지 확인
```

---

## 7. GDB (Linux) 실전 활용

### 기본 명령어
```bash
gdb ./binary              # 바이너리 로드

# PEDA/pwndbg 설치 (권장)
git clone https://github.com/longld/peda.git ~/peda
echo "source ~/peda/peda.py" >> ~/.gdbinit
```

### GDB 명령어
```gdb
(gdb) run arg1 arg2          # 인자와 함께 실행
(gdb) run < input.txt        # 파일에서 stdin 입력
(gdb) break main             # 함수 이름으로 BP 설정
(gdb) break *0x804851a       # 절대 주소로 BP 설정
(gdb) break *main+42         # 상대 오프셋으로 BP 설정
(gdb) info breakpoints       # BP 목록 확인
(gdb) delete 1               # 1번 BP 삭제
(gdb) continue               # 다음 BP까지 실행
(gdb) next                   # Step Over (함수 단위)
(gdb) step                   # Step Into (명령어 단위)
(gdb) finish                 # 현재 함수 끝까지 실행 후 리턴
(gdb) info registers         # 전체 레지스터 값 출력
(gdb) p/x $eax               # eax 값 16진수 출력
(gdb) x/10xw $esp            # esp 기준 10개 word (4B) hex 출력
(gdb) x/10i $eip             # eip 기준 10개 명령어 디스어셈블
(gdb) x/s 0x804a0c0          # 해당 주소를 문자열로 출력
(gdb) set $eax = 0           # 레지스터 값 수동 변경
(gdb) set *(int*)0x804a010=1 # 메모리 값 수동 변경
(gdb) disassemble main       # 함수 전체 역어셈블
(gdb) disassemble /r main    # raw bytes 포함 역어셈블
(gdb) info frame             # 현재 스택 프레임 정보
(gdb) backtrace              # 콜 스택 (call chain)
(gdb) watch *(int*)0x804a010 # 메모리 와치포인트 설정
```

### GDB 자동화 스크립트 (Python GDB API)
```python
#!/usr/bin/env python3
"""
GDB Python API를 이용한 바이너리 자동 분석 스크립트
사용법: gdb -x gdb_auto.py ./target
"""
import gdb
import re


class MalwareTracer(gdb.Command):
    """의심 함수 호출 시 자동 로깅하는 GDB 커맨드"""

    WATCH_FUNCS = [
        "system", "execve", "execvp",
        "popen", "fopen", "fwrite",
        "connect", "send", "recv",
        "strcmp", "strncmp",          # 시리얼 비교 탐지
    ]

    def __init__(self) -> None:
        super().__init__("trace-malware", gdb.COMMAND_USER)
        self.log: list[str] = []

    def invoke(self, arg: str, from_tty: bool) -> None:
        print("[*] 의심 함수 BP 설정 중...")
        for func in self.WATCH_FUNCS:
            try:
                bp = gdb.Breakpoint(func, internal=True)
                bp.commands = (
                    f'python gdb.execute("set logging file /tmp/trace.log")\n'
                    f'python gdb.execute("set logging on")\n'
                    f'info args\n'
                    f'backtrace 3\n'
                    f'continue\n'
                )
                print(f"  [+] BP @ {func}")
            except gdb.error:
                pass  # 심볼 없으면 스킵

        gdb.execute("run")
        print(f"[*] 트레이스 완료 → /tmp/trace.log 확인")


class EIPController(gdb.Command):
    """EIP/RIP 강제 변경 헬퍼"""

    def __init__(self) -> None:
        super().__init__("set-eip", gdb.COMMAND_USER)

    def invoke(self, arg: str, from_tty: bool) -> None:
        addr = int(arg.strip(), 16)
        arch = gdb.selected_frame().architecture().name()
        reg = "rip" if "x86-64" in arch else "eip"
        gdb.execute(f"set ${reg} = {addr}")
        print(f"[+] {reg.upper()} → {hex(addr)}")


MalwareTracer()
EIPController()
print("[*] 커스텀 GDB 커맨드 로드: trace-malware, set-eip")


# 자동 실행 — 바이너리 로드 직후 main에 BP 설정
def on_new_objfile(event: gdb.ObjfileEvent) -> None:
    try:
        gdb.execute("break main")
        print("[+] main BP 자동 설정")
    except gdb.error:
        pass

gdb.events.new_objfile.connect(on_new_objfile)
```

### Linux 환경 컴파일 & 디버깅
```bash
# 인텔 문법 어셈블리 출력으로 컴파일
gcc -masm=intel -S -O0 test.c -o test.s
cat test.s

# 보호 기법 비활성화 후 컴파일 (학습용, 32비트)
gcc -m32 -o vuln32 vuln.c \
    -fno-stack-protector \
    -z execstack \
    -no-pie \
    -mpreferred-stack-boundary=2

# 보호 기법 비활성화 후 컴파일 (학습용, 64비트)
gcc -o vuln64 vuln.c \
    -fno-stack-protector \
    -z execstack \
    -no-pie

# 실행 파일 보호 기법 자동 확인 (pwntools checksec)
python3 -c "
from pwn import *
elf = ELF('./vuln64')
print(f'  RELRO:     {\"Full\" if elf.relro == \"full\" else elf.relro}')
print(f'  Canary:    {elf.canary}')
print(f'  NX:        {elf.nx}')
print(f'  PIE:       {elf.pie}')
"

# ASLR 비활성화 (학습/디버깅용, 재부팅 전까지 유효)
echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
```

### Linux C 코드 → 어셈블리 변환 실전

```c
// test.c — 기본 산술 연산 어셈블리 확인
#include <stdio.h>

int add(int a, int b) {
    return a + b;
}

int main(void) {
    int a = 10;
    int b = 20;
    int c = add(a, b);
    printf("c = %d\n", c);
    return 0;
}
```

컴파일 후 생성되는 어셈블리(`gcc -m32 -masm=intel -S -O0 test.c`):

```asm
; add 함수 — 인자 2개, 합산 후 eax로 반환
add:
    push    ebp
    mov     ebp, esp
    mov     eax, DWORD PTR [ebp+8]   ; a (첫 번째 인자)
    add     eax, DWORD PTR [ebp+12]  ; eax += b (두 번째 인자)
    pop     ebp
    ret                               ; 반환값은 eax

; main 함수 — 지역변수 3개 (a, b, c) → 스택 12바이트 확보
main:
    push    ebp
    mov     ebp, esp
    sub     esp, 12                      ; 지역변수 공간 확보
    mov     DWORD PTR [ebp-4],  10       ; a = 10
    mov     DWORD PTR [ebp-8],  20       ; b = 20
    push    DWORD PTR [ebp-8]            ; 인자2: b (역순 push)
    push    DWORD PTR [ebp-4]            ; 인자1: a
    call    add                          ; add(a, b)
    add     esp, 8                       ; __cdecl: caller가 스택 정리
    mov     DWORD PTR [ebp-12], eax      ; c = 반환값
    push    DWORD PTR [ebp-12]
    push    OFFSET .LC0                  ; "c = %d\n"
    call    printf
    add     esp, 8
    mov     eax, 0
    leave
    ret
```

```python
#!/usr/bin/env python3
"""
r2pipe를 이용한 함수 자동 역어셈블 + 제어 흐름 분석
사용법: python3 r2_disasm.py <binary> [함수명]
"""
import sys
import json
import argparse
import r2pipe


def disasm_function(binary: str, func_name: str = "main") -> None:
    r2 = r2pipe.open(binary, flags=["-2"])
    r2.cmd("aaa")  # 전체 분석 수행

    # 함수 목록에서 대상 검색
    funcs = json.loads(r2.cmd("aflj") or "[]")
    target = next(
        (f for f in funcs if func_name in f.get("name", "")), None
    )
    if not target:
        print(f"[-] 함수 '{func_name}' 를 찾을 수 없습니다.")
        avail = [f["name"] for f in funcs[:20]]
        print(f"    사용 가능한 함수 (최대 20개): {avail}")
        r2.quit()
        return

    addr = target["offset"]
    print(f"\n[+] {func_name} @ {hex(addr)}")
    print(f"    크기: {target.get('size', '?')} bytes")
    print(f"    호출 횟수: {target.get('cc', '?')}\n")

    # 인텔 문법으로 역어셈블
    r2.cmd("e asm.syntax=intel")
    r2.cmd(f"s {addr}")
    print(r2.cmd(f"pdf"))  # 함수 전체 디스어셈블

    # 제어 흐름 그래프 (텍스트)
    print("\n[*] 제어 흐름 블록:")
    blocks = json.loads(r2.cmd(f"afbj @ {addr}") or "[]")
    for blk in blocks:
        print(f"  블록 {hex(blk['addr'])}: {blk.get('ninstr', 0)}개 명령어"
              f"  → jump: {hex(blk['jump']) if blk.get('jump') else 'None'}"
              f"  / fail: {hex(blk['fail']) if blk.get('fail') else 'None'}")

    r2.quit()


def main() -> None:
    parser = argparse.ArgumentParser(description="r2pipe 함수 역어셈블러")
    parser.add_argument("binary", help="분석 대상 바이너리")
    parser.add_argument("func", nargs="?", default="main", help="함수명 (기본: main)")
    args = parser.parse_args()
    disasm_function(args.binary, args.func)


if __name__ == "__main__":
    main()
```

---

## 8. 리버싱 기초 실습 과제 상세 분석

### 과제 유형별 접근법

#### 유형 1: 조건 분기 조작
```asm
; 프로그램이 특정 값을 비교하고 성공/실패를 나눌 때

; 원본 코드 — 분기 지점 찾기
CMP EAX, 특정값
JE  success_label      ; 같으면 성공
JMP fail_label         ; 나머지는 실패

; 패치 방법 A: JE → JMP (항상 성공으로)
; Spacebar → JMP success_label

; 패치 방법 B: JE를 NOP으로 (조건 무력화 후 다음 줄 실행)
; JE (0x74 또는 0x0F 0x84) → NOP (0x90)

; 패치 방법 C: CMP 자체 제거
; CMP 명령어를 NOP으로 채우면 ZF가 변하지 않음
```

#### 유형 2: sum 값 계산 패치
```asm
; 목표: sum이 특정 값(15, 21 등)이 되도록 패치
; 접근: sum을 계산하는 루프를 찾아 조건 변경 또는 직접 값 주입

; 예시: sum == 21 이 되어야 success
; 방법 1: MOV [sum_address], 15h (직접 값 주입)
; 방법 2: 루프 조건 CMP를 원하는 값으로 변경
```

#### 유형 3: MessageBox 추가/수정
```asm
; 스택 창에서 직접 인자 확인
PUSH 0              ; uType (MB_OK)
PUSH 타이틀주소      ; lpCaption
PUSH 메시지주소      ; lpText
PUSH 0              ; hWnd
CALL MessageBox

; OllyDbg에서:
; F7로 CALL 내부 진입 → EBP+8=hWnd, EBP+C=lpText 확인
; 스택 창에서 직접 값 수정 가능
```

#### 유형 4: new(동적 할당) 분석
```asm
; C++ new 연산자 역어셈블 패턴
PUSH 크기            ; 할당할 바이트 수
CALL operator new   ; 내부적으로 HeapAlloc 호출
ADD ESP, 4
MOV [포인터변수], EAX ; EAX에 할당된 주소 반환

; OllyDbg에서 Heap 추적:
; Alt+M → Memory Map에서 Heap 영역 확인
; Heap 주소에 Memory BP 설정하여 접근 시 멈춤
```

---

## 9. 안티 디버깅 기법 목록

### 탐지 방법과 우회법

| 안티디버깅 기법 | 동작 원리 | 우회 방법 |
|--------------|---------|---------|
| IsDebuggerPresent | PEB.IsDebugged 필드 확인 | EAX를 0으로 수동 설정 후 JNZ→NOP |
| CheckRemoteDebuggerPresent | NtQueryInformationProcess 호출 | 반환 bool 포인터 값을 0으로 패치 |
| GetTickCount 타이밍 | 실행 시간이 너무 길면 디버거로 판단 | JA/JG → NOP 또는 EAX를 작은 값으로 변경 |
| QueryPerformanceCounter | 고해상도 타이머로 시간 측정 | 결과 비교 분기 NOP |
| INT 3 (0xCC) 탐지 | 코드에서 0xCC 바이트 스캔 | Hardware BP 사용 (DR 레지스터, INT 3 없음) |
| TLS 콜백 | main 이전에 실행되는 코드 | TLS 콜백 함수에 직접 BP 설정 |
| SEH 핸들러 | 예외 발생 시 디버거 존재 확인 | FS:[0] 체인 추적, 핸들러 내 분기 패치 |

```asm
; PEB를 이용한 디버거 탐지 (수동 방식)
MOV EAX, DWORD PTR FS:[30h]   ; EAX = PEB 주소
MOV AL,  BYTE PTR [EAX+2]     ; AL = PEB.IsDebugged (offset 0x2)
TEST AL, AL
JNZ  debugger_detected

; 우회: [EAX+2] 값을 0으로 직접 수정 (Memory 창에서)
; 또는 JNZ → JZ 로 조건 반전
```

```python
#!/usr/bin/env python3
"""
pwntools 기반 안티디버깅 우회 자동화 스크립트
IsDebuggerPresent / PEB.IsDebugged 패치 후 바이너리 실행
사용법: python3 anti_debug_bypass.py ./target [인자...]
"""
import sys
import argparse
from pwn import (
    ELF, process, remote,
    context, log, p32, p64,
    u32, u64,
)


def patch_is_debugger_present(binary_path: str) -> str:
    """
    IsDebuggerPresent 임포트를 NOP 패턴으로 패치한 바이너리를 반환.
    Windows PE 전용 — Linux ELF에서는 동적 훅킹 방식 사용 권장.
    """
    import pefile
    import shutil
    import os

    patched = binary_path + ".patched"
    shutil.copy2(binary_path, patched)

    pe = pefile.PE(patched)
    if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        log.warning("Import 디렉토리 없음")
        return patched

    with open(patched, "r+b") as f:
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                if imp.name and b"IsDebuggerPresent" in imp.name:
                    # IAT 엔트리를 0으로 초기화 → 호출 시 NULL 포인터
                    # 실전에서는 xor eax,eax/ret 셸코드 주소로 대체
                    f.seek(imp.address - pe.OPTIONAL_HEADER.ImageBase)
                    f.write(b"\x00\x00\x00\x00")
                    log.success(f"IsDebuggerPresent IAT 패치 완료 @ {hex(imp.address)}")

    return patched


def run_with_antidebug_bypass_frida(binary_path: str, args: list[str]) -> None:
    """
    Frida를 이용한 런타임 안티디버깅 우회 (Windows/Linux 공통)
    frida-tools 필요: pip install frida-tools
    """
    frida_script = r"""
    // IsDebuggerPresent 반환값 항상 0으로 패치
    var isDbgPresent = Module.findExportByName(null, "IsDebuggerPresent");
    if (isDbgPresent) {
        Interceptor.replace(isDbgPresent, new NativeCallback(function() {
            return 0;
        }, 'int', []));
        send("[+] IsDebuggerPresent 후킹 완료");
    }

    // CheckRemoteDebuggerPresent 우회
    var checkRemote = Module.findExportByName(null, "CheckRemoteDebuggerPresent");
    if (checkRemote) {
        Interceptor.attach(checkRemote, {
            onLeave: function(retval) {
                // pbDebuggerPresent 포인터가 가리키는 값을 FALSE로
                var ptr = this.context.ecx || this.context.rdx;
                if (ptr) Memory.writeU32(ptr, 0);
            }
        });
        send("[+] CheckRemoteDebuggerPresent 후킹 완료");
    }

    // GetTickCount 시간 차이 우회 (항상 이전 값 +1 반환)
    var prevTick = 0;
    var getTickCount = Module.findExportByName(null, "GetTickCount");
    if (getTickCount) {
        Interceptor.replace(getTickCount, new NativeCallback(function() {
            prevTick += 1;
            return prevTick;
        }, 'uint32', []));
        send("[+] GetTickCount 후킹 완료");
    }
    """
    print("[*] Frida 안티디버깅 우회 스크립트:")
    print(frida_script)
    print(f"\n[*] 실행: frida -l script.js {binary_path}")
    print(f"    또는: frida --no-pause -f {binary_path}")


def main() -> None:
    parser = argparse.ArgumentParser(description="안티디버깅 우회 도구")
    parser.add_argument("binary", help="대상 바이너리")
    parser.add_argument("args", nargs="*", help="프로그램 인자")
    parser.add_argument("--frida", action="store_true",
                        help="Frida 스크립트 출력 모드")
    args = parser.parse_args()

    if args.frida:
        run_with_antidebug_bypass_frida(args.binary, args.args)
    else:
        patched = patch_is_debugger_present(args.binary)
        log.info(f"패치된 바이너리: {patched}")


if __name__ == "__main__":
    main()
```
