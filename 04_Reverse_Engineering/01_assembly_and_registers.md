# 리버스 엔지니어링 — 어셈블리어와 레지스터 완전 정복

## 1. 리버싱(Reversing)이란?

리버스 엔지니어링(Reverse Engineering)은 이미 완성된 제품을 분해하여 내부 구조와 동작 원리를 파악하는 기법이다.
소프트웨어 보안 분야에서는 컴파일된 실행 파일(바이너리)을 분석하여 소스코드가 없어도 동작을 이해하는 것을 의미한다.

### 리버싱이 필요한 상황
- **크랙킹**: 소프트웨어 라이선스 보호 메커니즘 분석 (취약점 발견)
- **악성코드 분석**: 바이러스/트로이목마의 동작 파악
- **취약점 분석**: 패치 없는 바이너리에서 취약점 발견
- **프로토콜 역분석**: 미공개 네트워크 프로토콜 해석
- **버그 수정**: 소스가 없는 레거시 소프트웨어 패치

### 필요한 역량
- 어셈블리어 이해 (가장 중요)
- OS 구조 (프로세스, 메모리, 시스템 콜)
- C/C++ 언어 이해
- 인내심과 분석 능력

---

## 2. 분석 도구

### Disassembler (역어셈블러)
| 도구 | 특징 |
|------|------|
| IDA Pro | 업계 표준, 강력한 분석 기능, 고가 |
| Ghidra | NSA 개발, 오픈소스, 디컴파일 지원 |
| Binary Ninja | 모던 UI, API 풍부 |
| radare2 | 오픈소스, CLI, 강력한 스크립팅 |
| W32DASM | 구버전 Windows 프로그램 분석 |

### Debugger (디버거)
| 도구 | 대상 | 특징 |
|------|------|------|
| OllyDbg | Windows 32-bit | 사용이 간편, 리버싱 입문 최적 |
| x64dbg | Windows 32/64-bit | OllyDbg 계승, 오픈소스 |
| WinDbg | Windows Kernel | 커널 디버깅 |
| GDB | Linux | 기본 디버거 |
| PEDA/pwndbg | Linux | GDB 확장, 익스플로잇 특화 |

### 분석 환경 구성
```
분석 환경 기본 구성:
- OS: Windows XP/7 또는 Windows 10 (VM 권장)
- 컴파일러: Visual C++ 6.0 (레거시 분석 시)
- 디버거: OllyDbg (32비트) / x64dbg (64비트)
- 역어셈블러: IDA Pro 또는 Ghidra (무료)
- Release Mode로 컴파일된 바이너리 분석 권장
  (Debug Mode는 디버깅 심볼이 포함되어 실제와 다름)
```

---

## 3. CPU 레지스터 완전 이해

### IA-32 (Intel 32비트) 레지스터 구조

```
32-bit (EAX):
┌────────────────────────────────────────┐
│                  EAX (32비트, 4바이트)  │
└────────────────────────────────────────┘
                        ┌───────────────┐
                        │   AX (16비트)  │
                        └───────────────┘
                        ┌──────┬────────┐
                        │AH(8) │ AL(8)  │
                        └──────┴────────┘
```

### 범용 레지스터 (General Purpose Registers)

#### EAX (Accumulator)
- 산술연산 및 함수 반환값 저장
- 모든 Win32 API 함수의 반환값이 EAX에 저장됨
- `EAX = AX = AH + AL` (32비트 = 16비트 = 8비트 + 8비트)

#### EBX (Base)
- 주소 기반 레지스터
- 일반 목적 레지스터로도 사용

#### ECX (Counter)
- 반복문(LOOP 명령) 카운터
- 반복 횟수 저장 → 0이 될 때까지 반복

#### EDX (Data)
- 확장 연산 시 EAX의 상위 32비트를 저장
- I/O 포인터로도 사용

### 인덱스/포인터 레지스터

#### ESP (Stack Pointer)
- 현재 스택의 최상단 주소 가리킴
- `PUSH`: ESP -= 4, 데이터 저장
- `POP`:  데이터 읽기, ESP += 4

#### EBP (Base Pointer)
- 현재 스택 프레임의 베이스 주소
- 함수 내 지역변수 접근 기준점 (`EBP-4`, `EBP-8` 등)
- 함수 시작: `PUSH EBP / MOV EBP, ESP`
- 함수 종료: `MOV ESP, EBP / POP EBP / RET`

#### ESI (Source Index)
- 복사 연산의 소스 주소

#### EDI (Destination Index)
- 복사 연산의 목적지 주소

#### EIP (Instruction Pointer)
- 다음에 실행할 명령어의 주소
- **BoF 공격의 핵심 타겟** — EIP를 제어하면 실행 흐름 제어 가능
- PC(Program Counter)라고도 불림

---

## 4. 플래그 레지스터 (EFLAGS)

```
플래그 레지스터는 각 비트가 0 또는 1의 플래그 값을 가짐
주요 분석 대상 플래그:
```

| 플래그 | 이름 | 조건 |
|--------|------|------|
| OF | Overflow | 부호 있는 수의 오버플로우 발생 시 1 |
| SF | Sign | 결과값이 음수이면 1, 양수이면 0 |
| ZF | Zero | 연산 결과가 0이면 1 (조건 분기에서 매우 중요) |
| CF | Carry | 부호 없는 수의 오버플로우 발생 시 1 |
| PF | Parity | 결과 하위 8비트의 1비트 수가 짝수이면 1 |
| AF | Auxiliary | BCD 연산 시 자리올림 |
| TF | Trap | 단계 실행(Single Step) 모드 |

---

## 5. 어셈블리 명령어 완전 정리

### MOV 명령어 (데이터 이동)
```asm
MOV DST, SRC    ; SRC의 값을 DST로 복사

; 예시
MOV EAX, 12345678h       ; EAX = 0x12345678 (즉시값)
MOV ECX, EAX             ; ECX = EAX (레지스터간 복사)
MOV DWORD PTR [00406000h], 12345678h  ; 메모리[0x406000] = 0x12345678

; 크기 지정자
DWORD PTR  ; 4바이트 (int)
WORD PTR   ; 2바이트 (short)
BYTE PTR   ; 1바이트 (char)

; 잘못된 사용 (오류)
MOV AX, EDX   ; 크기 불일치 (AX=16bit, EDX=32bit)
```

### LEA 명령어 (주소 로드)
```asm
; MOV와의 차이 — LEA는 주소 자체를 로드
MOV EAX, DWORD PTR [00406000h]   ; EAX = 메모리[0x406000]의 값
LEA EAX, DWORD PTR [00406000h]   ; EAX = 0x406000 (주소 자체)

; C 코드 변환 예시
int a = 5;
int *p = &a;

; → 어셈블리 변환
MOV DWORD PTR [00406000h], 5     ; a = 5
LEA EAX, DWORD PTR [00406000h]   ; EAX = &a
MOV DWORD PTR [00406004h], EAX   ; p = &a
```

### 산술 연산
```asm
; 덧셈
ADD EAX, 3       ; EAX = EAX + 3
ADD EAX, ECX     ; EAX = EAX + ECX

; 뺄셈
SUB EAX, 3       ; EAX = EAX - 3

; 곱셈 (MUL: 부호 없음, IMUL: 부호 있음)
MUL ECX          ; EDX:EAX = EAX * ECX (결과가 큰 경우 EDX 사용)
IMUL EAX, ECX, 10h  ; EAX = ECX * 0x10

; 나눗셈 (DIV: 부호 없음, IDIV: 부호 있음)
DIV ECX          ; EAX = EAX / ECX (몫)
                 ; EDX = EAX % ECX (나머지)

; C 코드 대응
; int c = a / b;
MOV EAX, DWORD PTR [a]
MOV ECX, DWORD PTR [b]
IDIV ECX
MOV DWORD PTR [c], EAX    ; 몫

; int c = a % b;
MOV EAX, DWORD PTR [a]
MOV ECX, DWORD PTR [b]
IDIV ECX
MOV DWORD PTR [c], EDX    ; 나머지
```

### 비트 연산
```asm
; AND
AND EAX, ECX     ; EAX = EAX & ECX

; OR
OR EAX, ECX      ; EAX = EAX | ECX

; XOR
XOR EAX, EAX     ; EAX = 0 (자기 자신과 XOR → 0으로 초기화, 최적화 기법)
XOR EAX, ECX     ; EAX = EAX ^ ECX

; NOT (비트 반전)
NOT EAX          ; EAX = ~EAX

; 실용 예시: 대소문자 변환
; 'a'(0x61) XOR 0x20 = 'A'(0x41)
; 'A'(0x41) XOR 0x20 = 'a'(0x61)
MOV EAX, 61h     ; 'a'
XOR EAX, 20h     ; → 0x41 = 'A'
```

### 비교 및 조건 분기
```asm
; CMP: 두 값을 비교 (뺄셈 수행 후 결과 버림, 플래그만 변경)
CMP EAX, 3       ; EAX - 3 결과로 플래그 설정

; 조건 점프 명령어
JE  label        ; Jump if Equal     (ZF=1)
JNE label        ; Jump if Not Equal (ZF=0)
JG  label        ; Jump if Greater   (ZF=0 and SF=OF, 부호 있음)
JGE label        ; Jump if Greater or Equal (SF=OF)
JL  label        ; Jump if Less      (SF≠OF, 부호 있음)
JLE label        ; Jump if Less or Equal
JA  label        ; Jump if Above     (CF=0 and ZF=0, 부호 없음)
JB  label        ; Jump if Below     (CF=1, 부호 없음)
JZ  label        ; Jump if Zero      (ZF=1, JE와 동일)
JNZ label        ; Jump if Not Zero  (ZF=0, JNE와 동일)
JMP label        ; 무조건 점프

; C 코드 대응
; if (a != b) { a = 1000; }
MOV DWORD PTR [EBP-4], 10      ; a = 10
MOV DWORD PTR [EBP-8], 20      ; b = 20
MOV EAX, DWORD PTR [EBP-4]
CMP EAX, DWORD PTR [EBP-8]
JE  equal_label                 ; a == b 이면 점프
MOV DWORD PTR [EBP-4], 3E8h    ; a = 1000
equal_label:
```

---

## 6. 스택 연산

### PUSH / POP
```asm
; PUSH 내부 동작
PUSH 10h
; = SUB ESP, 4
; = MOV DWORD PTR [ESP], 10h

; POP 내부 동작
POP EAX
; = MOV EAX, DWORD PTR [ESP]
; = ADD ESP, 4

; 스택 상태 시각화 (PUSH 10, PUSH 20, PUSH 30)
; 전:                   후:
;              ↑ESP      ┌────────┐ ← ESP
;                        │  0x30  │
;                        │  0x20  │
;                        │  0x10  │
;                        └────────┘ ← EBP
```

### 함수 호출 (CALL / RET)
```asm
; CALL 내부 동작
CALL 00401000h
; = PUSH EIP        (다음 명령어 주소를 스택에 저장)
; = JMP 00401000h   (함수로 점프)

; 함수 프롤로그 (거의 모든 함수 시작부)
PUSH EBP          ; 이전 EBP 저장
MOV EBP, ESP      ; 새 스택 프레임 설정

; 함수 에필로그 (함수 종료)
MOV ESP, EBP      ; 스택 복구
POP EBP           ; 이전 EBP 복원
RETN              ; = POP EIP → 호출자로 복귀

; RETN 8 (인자 정리)
; = POP EIP
; = ADD ESP, 8     (함수 인자 4바이트 * 2개 정리)
```

---

## 7. 반복문 어셈블리 변환

### for 루프
```c
// C 코드
for (int i = 0; i < 10; i++) {
    // 작업
}
```
```asm
; 어셈블리 변환
MOV ECX, 0Ah      ; ECX = 10 (반복 횟수)
MOV DWORD PTR [i], 0

loop_start:
    CMP DWORD PTR [i], 0Ah
    JGE loop_end       ; i >= 10 이면 종료
    ; ... 작업 ...
    INC DWORD PTR [i]  ; i++
    JMP loop_start

loop_end:

; 또는 REP 명령어 활용
MOV ECX, 0Ah           ; 반복 횟수
loop_start:
    ; ... 작업 ...
    LOOP loop_start    ; ECX--, ZF=0이면 점프
```

### 대량 초기화 (memset 최적화)
```asm
; char buf[12] = {0};  → 어셈블리 최적화
MOV ECX, 3             ; 3 * 4 = 12바이트
XOR EAX, EAX           ; EAX = 0
LEA EDI, [EBP-0Ch]     ; EDI = buf 시작 주소
REP STOS DWORD PTR ES:[EDI]  ; [EDI] = 0, EDI += 4, ECX-- (ECX=0 될 때까지)
```

---

## 8. C언어 vs 어셈블리 매핑 요약

| C 코드 | 어셈블리 패턴 |
|-------|-------------|
| `int a = 5;` | `MOV DWORD PTR [EBP-4], 5` |
| `a = b + c;` | `MOV EAX, [b]` / `ADD EAX, [c]` / `MOV [a], EAX` |
| `if (a == b)` | `CMP EAX, ECX` / `JNE else_label` |
| `for (i=0; i<n; i++)` | `MOV ECX, n` / `loop:` / `LOOP loop` |
| `func(a, b)` | `PUSH b` / `PUSH a` / `CALL func` |
| `return val;` | `MOV EAX, val` / `RETN` |
| `*ptr` | `MOV EAX, DWORD PTR [ptr]` |
| `&var` | `LEA EAX, DWORD PTR [var]` |
| `a & b` | `AND EAX, ECX` |
| `a ^ b` | `XOR EAX, ECX` |

---

## 9. 데이터 이동 확장 명령어 (MOVSX / MOVZX)

크기가 다른 레지스터 간에 값을 이동할 때 단순 MOV는 오류를 발생시킨다.
이 경우 부호 확장 여부에 따라 MOVSX 또는 MOVZX를 사용한다.

```asm
; al = 1111 1111b (= -1 signed, 255 unsigned)

; MOVSX : Signed 확장 (부호 비트를 상위로 복사)
MOVSX ECX, AL
; → ECX = 1000 0000 0000 0000 0000 0000 0111 1111b (= -1 signed)
; 상위 비트가 부호 비트(1)로 채워짐

; MOVZX : Unsigned 확장 (상위를 0으로 채움)
MOVZX ECX, AL
; → ECX = 0000 0000 0000 0000 0000 0000 1111 1111b (= 255)
; 상위 비트가 0으로 채워짐
```

```asm
; 실전 예시 - char → int 대입
char b = 'a';    ; 0x61 = 97
int a;
a = b;

; 어셈블리 변환
MOV BYTE PTR [EBP-8], 61h       ; b = 'a'
MOVSX EAX, BYTE PTR [EBP-8]     ; signed 확장하여 EAX에 로드
MOV DWORD PTR [EBP-4], EAX      ; a = (int)b
```

---

## 10. 시프트 연산 (Shift)

```asm
; SHL (Shift Left Logical) — 왼쪽 시프트 (= *2)
SHL EAX, 1       ; EAX = EAX * 2
SHL EAX, 3       ; EAX = EAX * 8 (2^3)

; SHR (Shift Right Logical) — 오른쪽 시프트, 부호 없음 (= /2)
SHR EAX, 1       ; EAX = EAX / 2 (상위에 0 채움)

; SAR (Shift Arithmetic Right) — 오른쪽 시프트, 부호 있음
SAR EAX, 1       ; EAX = EAX / 2 (부호 비트 유지)
; 음수일 때: -8 >> 1 = -4 (SAR), 2147483644 (SHR)

; 활용: 곱셈/나눗셈 최적화
; 컴파일러는 2의 거듭제곱 곱셈을 SHL로 최적화하는 경우 많음
```

---

## 11. 조건 분기 명령어 완전 목록

CMP 명령어 실행 후 플래그 값에 따라 분기한다.
`***` 표시는 리버싱에서 자주 등장하는 핵심 명령어이다.

```
*** JE  / JZ   : ZF=1          → Equal / Zero
*** JNE / JNZ  : ZF=0          → Not Equal / Not Zero
*** JG  / JNLE : ZF=0, SF=OF   → Greater (signed)
*** JGE / JNL  : SF=OF         → Greater or Equal (signed)
*** JL  / JNGE : SF≠OF         → Less (signed)
*** JLE / JNG  : ZF=1 or SF≠OF → Less or Equal (signed)
    JA  / JNBE : CF=0, ZF=0    → Above (unsigned)
    JAE / JNB  : CF=0          → Above or Equal (unsigned)
    JB  / JNAE : CF=1          → Below (unsigned)
    JBE / JNA  : CF=1 or ZF=1  → Below or Equal (unsigned)
    JC         : CF=1          → Carry flag set
    JNC        : CF=0          → Carry flag not set
    JO         : OF=1          → Overflow flag set
    JNO        : OF=0          → Overflow flag not set
    JS         : SF=1          → Sign flag set
    JNS        : SF=0          → Sign flag not set
    JP  / JPE  : PF=1          → Parity Even
    JNP / JPO  : PF=0          → Parity Odd
    JCXZ       : CX=0          → CX register is zero
    JECXZ      : ECX=0         → ECX register is zero
    JMP        : 무조건          → Unconditional jump
```

```asm
; 실전 예시 — if/else 패턴
; if (a != b) { a = 1000; }

MOV DWORD PTR SS:[EBP-4], 0Ah   ; a = 10
MOV DWORD PTR SS:[EBP-8], 14h   ; b = 20
MOV EAX, DWORD PTR SS:[EBP-4]
CMP EAX, DWORD PTR SS:[EBP-8]
JE  SHORT equal_label             ; a == b 이면 건너뜀
MOV DWORD PTR SS:[EBP-4], 3E8h  ; a = 1000
equal_label:

; 실전 예시 — 비교 연산 흐름
MOV EAX, 30
CMP EAX, 31     ; EAX - 31 = -1 → SF 설정
JG  label       ; -1 > 0 아니므로 미분기
CMP EAX, 29     ; EAX - 29 = 1
JG  label       ; 1 > 0 이므로 분기 발생
```

---

## 12. 함수 호출 규약 (Calling Convention)

Caller(호출하는 함수)와 Callee(호출되는 함수) 사이의 인자 전달 및 스택 정리 규칙이다.

| 규약 | 인자 전달 | 스택 정리 | 주 사용처 |
|------|----------|----------|---------|
| `__cdecl` | 스택 (우→좌 push) | Caller가 정리 `ADD ESP, XX` | C 라이브러리 함수 |
| `__stdcall` | 스택 (우→좌 push) | Callee가 정리 `RETN XX` | Win32 API |
| `__fastcall` | ECX, EDX (1~2개), 나머지는 스택 | Callee가 정리 `RETN XX` | 빠른 함수 호출 |

```asm
; __cdecl 예시 — C 함수 호출
PUSH 인자2
PUSH 인자1          ; 스택에 역순으로 push
CALL 함수주소
ADD ESP, 8          ; caller가 인자 크기만큼 스택 복구

; __stdcall 예시 — Win32 API 호출
PUSH MB_OK          ; 인자4
PUSH 0              ; 인자3 (hWnd)
PUSH "Title"        ; 인자2
PUSH "Message"      ; 인자1
CALL MessageBoxA
; callee 내부에서 RETN 10h (4*4=16 바이트 정리)

; __fastcall 예시
; func(int a, int b)  → ECX=a, EDX=b
; func(int a, int b, int c) → ECX=a, EDX=b, PUSH c
```

```
스택 프레임 구조 (함수 내부):
  [EBP+0C] = 두 번째 인자 (arg2)
  [EBP+08] = 첫 번째 인자 (arg1)
  [EBP+04] = 리턴 주소 (Return Address)
  [EBP+00] = 이전 EBP
  [EBP-04] = 첫 번째 지역변수 (local1)
  [EBP-08] = 두 번째 지역변수 (local2)
```

---

## 13. 라이브러리 (Library)

함수의 실행 코드가 모여 있는 파일이다. 링크 방식에 따라 두 가지로 나뉜다.

### 정적 링크 라이브러리 (Static Link Library, .lib)
- 컴파일 시 라이브러리 코드가 실행 파일에 직접 포함됨
- 장점: 런타임에 외부 파일 불필요
- 단점: 실행 파일 크기 증가, 메모리 낭비, 라이브러리 업데이트 반영 불가

### 동적 링크 라이브러리 (Dynamic Link Library, .dll)
- 프로그램 실행 중 필요한 시점에 DLL에서 코드 로드
- 장점: 실행 파일 크기 감소, 라이브러리 업데이트 시 프로그램도 반영
- 단점: DLL 파일이 반드시 필요

### DLL 로드 방식
```c
// 암시적 로드 (프로그램 시작 시 자동 로드)
#include <windows.h>
MessageBox(NULL, "Hello", "Title", MB_OK);

// 명시적 로드 — 동적으로 필요 시 로드 (분석 어려움)
HMODULE hModule = LoadLibrary("user32.dll");
FARPROC pMB = GetProcAddress(hModule, "MessageBoxA");
// 사용 후
FreeLibrary(hModule);
```

---

## 14. 자료형과 메모리 할당

### 자료형 종류
```
기본 자료형 (Primitive Types): int, char, float, double, short, long
사용자 정의 자료형:
  - 구조체 (struct)
  - 공용체 (union)
```

### 스택 메모리에서의 지역변수 위치
```asm
; 함수 내 지역변수는 EBP 기준 음수 오프셋
EBP - 4  → 첫 번째 지역변수 (int a)
EBP - 8  → 두 번째 지역변수 (int b)
EBP - C  → 세 번째 지역변수 (int c)

; 함수 인자는 EBP 기준 양수 오프셋
EBP + 8  → 첫 번째 인자 (arg1)
EBP + C  → 두 번째 인자 (arg2)
```

### 메모리 할당 종류
| 구분 | 방식 | 영역 | 특징 |
|------|------|------|------|
| 정적 메모리 할당 | 컴파일 시 결정 | Stack, Data | 프로그램 시작 시 할당, 종료 시 해제 |
| 동적 메모리 할당 | Runtime 결정 | Heap | malloc, calloc, VirtualAlloc 등으로 할당 |

### RAM 메모리 구조
```
Code  영역: 프로그램 실행 코드 (기계어)
Data  영역: 전역변수, 정적변수, 문자열 상수 등 초기화된 값
Heap  영역: 동적 할당 요청 시 사용 (malloc, calloc, VirtualAlloc)
Stack 영역: 지역변수, 리턴 주소, 함수 인자 (매개변수)

특징:
- Windows: PE 포맷을 기반으로 메모리에 올라감
- Linux: ELF 포맷을 기반으로 메모리에 올라감
- 메모리 최소 단위: 4바이트
- Stack은 IA-32에서 4바이트 단위로 관리됨
- Stack 위치는 Runtime 시 Random으로 결정됨 (ASLR)
```

---

## 15. main 함수와 WinMain

### CUI 프로그램 (콘솔)
```c
// main 함수 — 기본 인자 3개
int main(int argc, char *argv[], char **envp)
{
    // argc: 전달된 인자 개수
    // argv: 인자 값 배열 (argv[0] = 실행 파일 경로)
    // envp: 환경 변수 배열
    return 0;
}
```

### GUI 프로그램 (Windows)
```c
// WinMain 함수 — 기본 인자 4개
int APIENTRY WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
                     LPSTR lpszCmdParam, int nCmdShow)
{
    // hInstance: 현재 프로그램 인스턴스 핸들
    // hPrevInstance: 이전 인스턴스 (현재는 항상 NULL)
    // lpszCmdParam: 커맨드 라인 인자 문자열
    // nCmdShow: 윈도우 표시 방식
    return 0;
}
```

```asm
; OllyDbg에서 WinMain 인식:
; main 또는 WinMain 함수 호출 전에 CRT 초기화 코드가 있음
; 함수 인자 4개가 PUSH로 쌓인 후 CALL이 나오면 WinMain
```
