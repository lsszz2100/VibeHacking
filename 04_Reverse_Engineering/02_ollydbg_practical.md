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
(gdb) run arg1 arg2       # 실행
(gdb) run < input.txt     # 파일에서 입력
(gdb) break main          # 함수에 브레이크포인트
(gdb) break *0x804851a    # 주소에 브레이크포인트
(gdb) continue            # 계속 실행
(gdb) next                # 다음 줄 (Step Over)
(gdb) step                # 함수 내부로 (Step Into)
(gdb) finish              # 현재 함수 종료까지
(gdb) info registers      # 레지스터 값
(gdb) x/10x $esp          # ESP부터 10개 hex
(gdb) x/10i $eip          # EIP부터 10개 명령어
(gdb) x/s 0x804a0c0       # 메모리를 문자열로
(gdb) set $eax = 0        # 레지스터 값 변경
(gdb) disassemble main    # 함수 역어셈블
(gdb) info frame          # 현재 스택 프레임
(gdb) backtrace           # 콜 스택
```

### Linux 환경 컴파일 & 디버깅
```bash
# ~/.bashrc에 gcc alias 추가 (스택 경계 정렬)
alias gcc='gcc -mpreferred-stack-boundary=2'

# 어셈블리 출력으로 컴파일
gcc -masm=intel -S test.c
cat test.s  # 인텔 문법 어셈블리 확인

# 보호 기법 비활성화 후 컴파일 (학습용)
gcc -o vuln vuln.c -fno-stack-protector -z execstack -no-pie

# 실행 파일 보호 기법 확인
checksec --file=vuln
# RELRO:    Full
# STACK CANARY: No canary found
# NX:       NX disabled
# PIE:      No PIE
```

### Linux C 코드 → 어셈블리 변환 실전

```c
// test.c
#include <stdio.h>
int main() {
    int a = 10;
    int b = 20;
    int c;
    c = a + b;
}
```

컴파일 후 생성되는 어셈블리(`gcc -masm=intel -S test.c`):

```asm
main:
    push    %ebp
    mov     %ebp, %esp
    sub     %esp, 12                     ; 지역변수 공간 확보 (a, b, c = 4*3)
    mov     DWORD PTR [%ebp-4],  10      ; a = 10
    mov     DWORD PTR [%ebp-8],  20      ; b = 20
    mov     %eax, DWORD PTR [%ebp-8]     ; eax = b
    add     %eax, DWORD PTR [%ebp-4]     ; eax = b + a
    mov     DWORD PTR [%ebp-12], %eax    ; c = eax
    leave
    ret
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
