> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 리버스 엔지니어링 — 어셈블리어와 레지스터 완전 정복

## 0. 초보자를 위한 개념 이해

### 어셈블리어와 레지스터란?

어셈블리어(Assembly Language)는 CPU가 직접 이해하는 기계어(0과 1)를 사람이 읽을 수 있는 니모닉(MOV, PUSH, CALL 등)으로 표현한 저수준 언어입니다. 리버스 엔지니어링에서 어셈블리 코드를 읽는 능력은 가장 핵심적인 기술입니다.

**왜 배우는가:**
```
리버싱에서 어셈블리가 필요한 이유:

  소스코드 있음:  C코드 → 컴파일 → 실행파일
  소스코드 없음:  실행파일 → 역어셈블 → 어셈블리 코드 → 분석

  활용 분야:
  악성코드 분석  → 바이러스가 무슨 일을 하는지 파악
  취약점 발굴    → 패치 없는 바이너리에서 버그 발견
  크랙 분석      → 라이선스 검증 로직 우회
  CTF 문제 풀기  → 리버싱 카테고리 필수 역량
```

### 핵심 개념 정리

```
x86 레지스터 역할:

  EAX  → 산술 연산 결과, 함수 반환값 저장
  EBX  → 베이스 레지스터 (메모리 주소)
  ECX  → 반복문 카운터 (LOOP 명령어)
  EDX  → 나눗셈 보조, 확장 저장
  ESI  → 소스 인덱스 (문자열 복사 출발)
  EDI  → 목적 인덱스 (문자열 복사 도착)
  ESP  → 스택 포인터 (현재 스택 최상단)
  EBP  → 베이스 포인터 (현재 스택 프레임 기준)
  EIP  → 명령어 포인터 (다음 실행할 명령어 주소)

핵심 어셈블리 명령어:
  MOV EAX, 5     → EAX = 5
  PUSH EAX       → 스택에 EAX 값 저장
  POP EBX        → 스택에서 값 꺼내 EBX에 저장
  CALL function  → 함수 호출 (리턴 주소 스택에 저장)
  RET            → 함수 종료 (스택의 리턴 주소로 점프)
  JMP 주소       → 무조건 점프
  JZ 주소        → 0이면 점프 (if 조건문)
```

### 필요한 도구 및 환경
- **역어셈블러**: Ghidra(무료) — 어셈블리 코드를 C 유사 코드로 디컴파일
- **디버거**: x64dbg(Windows), gdb + pwndbg(Linux) — 실행 중 레지스터/메모리 관찰
- **실습 바이너리**: CTF 문제, crackme 문제 — reversing.kr, ctftime.org에서 다운로드

### 기초 실습 예제
```python
#!/usr/bin/env python3
"""어셈블리 명령어 시뮬레이터 — x86 레지스터 동작 원리 학습."""
from dataclasses import dataclass, field

@dataclass
class X86Registers:
    """x86 레지스터 상태 시뮬레이션 (교육 목적)."""
    eax: int = 0
    ebx: int = 0
    ecx: int = 0
    edx: int = 0
    esp: int = 0xFFFF0000  # 스택 포인터 초기값
    ebp: int = 0xFFFF0000
    eip: int = 0x00401000  # 코드 시작 주소

    def mov(self, dest: str, value: int) -> None:
        """MOV 명령어: 레지스터에 값 저장."""
        setattr(self, dest.lower(), value & 0xFFFFFFFF)

    def push(self, value: int, stack: list[int]) -> None:
        """PUSH 명령어: 스택에 값 저장, ESP 감소."""
        self.esp -= 4
        stack.append(value)

    def pop(self, dest: str, stack: list[int]) -> None:
        """POP 명령어: 스택에서 값 꺼내 레지스터에 저장."""
        value = stack.pop()
        self.esp += 4
        self.mov(dest, value)

    def dump(self) -> None:
        """현재 레지스터 상태 출력."""
        print(f"EAX={self.eax:#010x} EBX={self.ebx:#010x}")
        print(f"ECX={self.ecx:#010x} EDX={self.edx:#010x}")
        print(f"ESP={self.esp:#010x} EBP={self.ebp:#010x}")

if __name__ == "__main__":
    regs = X86Registers()
    stack: list[int] = []
    regs.mov("eax", 0x41414141)   # MOV EAX, 0x41414141
    regs.mov("ecx", 10)            # MOV ECX, 10
    regs.push(regs.eax, stack)    # PUSH EAX
    regs.dump()
    print(f"스택: {[hex(v) for v in stack]}")
```

---

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

리버싱 분석 환경을 자동으로 구성하는 스크립트입니다. GDB와 NASM, pwntools, pwndbg 등 익스플로잇·역공학에 필수적인 도구들을 한 번에 설치하고 GDB 플러그인 설정까지 완료합니다.

```bash
# 분석 환경 자동 구성 스크립트 (Ubuntu/Kali)
#!/usr/bin/env bash
set -euo pipefail

echo "[*] 리버싱 분석 환경 구성 시작"

# 기본 도구 설치
sudo apt-get update -qq
sudo apt-get install -y \
    gdb gdb-multiarch \
    nasm binutils \
    python3-pip \
    upx-ucl \
    file binwalk

# pwntools 및 분석 라이브러리 설치
pip3 install --quiet \
    pwntools \
    pefile \
    capstone \
    unicorn \
    keystone-engine \
    r2pipe

# GDB 확장 설치 (pwndbg 권장)
if [ ! -d "$HOME/pwndbg" ]; then
    git clone https://github.com/pwndbg/pwndbg.git "$HOME/pwndbg"
    cd "$HOME/pwndbg" && ./setup.sh
fi

# checksec 설치
pip3 install --quiet checksec.py

echo "[+] 환경 구성 완료"
echo "    GDB+pwndbg, pwntools, pefile, r2pipe 사용 가능"

# 학습용 취약 바이너리 컴파일 옵션 (보호 기법 비활성화)
# gcc -o vuln vuln.c -fno-stack-protector -z execstack -no-pie -m32
```

---

## 3. CPU 레지스터 완전 이해

### IA-32 (Intel 32비트) 레지스터 구조


x86/x64 레지스터는 CPU가 직접 접근하는 초고속 저장 공간입니다. EAX는 함수 반환값, ESP는 스택 포인터, EIP는 다음 실행할 명령 주소를 가리키며, 익스플로잇 개발 시 이 레지스터들을 조작하는 것이 핵심입니다.

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


x86/x64 레지스터는 CPU가 직접 접근하는 초고속 저장 공간입니다. EAX는 함수 반환값, ESP는 스택 포인터, EIP는 다음 실행할 명령 주소를 가리키며, 익스플로잇 개발 시 이 레지스터들을 조작하는 것이 핵심입니다.

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

어셈블리 데이터 이동 명령어들입니다. `MOV`는 가장 기본적인 데이터 복사이고, `LEA`는 메모리를 실제로 읽지 않고 주소 계산만 수행합니다. PIE 바이너리에서는 `lea rdi, [rip + offset]` 형태로 전역 변수에 접근합니다.

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

LEA(Load Effective Address) 명령어는 메모리 주소를 계산하여 레지스터에 저장합니다. MOV와 달리 메모리를 실제로 읽지 않고 주소 값만 계산합니다.

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

어셈블리 수준의 산술 연산 명령어입니다. ADD, SUB, MUL, DIV 등의 연산이 CPU 레지스터와 플래그 레지스터에 어떤 영향을 미치는지 보여줍니다.

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

어셈블리의 비트 연산 명령어(AND, OR, XOR, NOT)입니다. 악성코드 분석 시 XOR은 데이터 난독화와 암호화에 자주 사용됩니다.

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

CMP 명령어로 두 값을 비교하고 조건 분기(JE, JNE, JG 등)로 프로그램 흐름을 제어합니다. 리버싱에서 시리얼 검증 로직 분석의 핵심입니다.

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

PUSH와 POP으로 스택에 데이터를 저장하고 꺼냅니다. 함수 호출 시 인자 전달과 레지스터 보존에 사용됩니다.

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

CALL 명령어는 리턴 주소를 스택에 저장하고 함수로 점프합니다. RET은 스택에서 리턴 주소를 꺼내 원래 위치로 돌아옵니다.

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

C 언어의 for 루프 코드입니다. 이 코드가 어셈블리로 변환되면 어떻게 표현되는지 비교하여 컴파일러 최적화를 이해합니다.

```c
// C 코드
for (int i = 0; i < 10; i++) {
    // 작업
}
```

C 언어의 for 루프가 어셈블리로 변환된 모습입니다. 카운터 초기화, 조건 비교, 증감, 점프 명령어의 조합으로 반복이 구현됩니다.

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

대량 메모리 초기화 시 컴파일러가 사용하는 최적화된 어셈블리 패턴입니다. REP STOSD 명령어로 한 번에 여러 바이트를 초기화합니다.

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

MOVSX(부호 확장)와 MOVZX(제로 확장) 명령어입니다. 작은 데이터 타입(char, short)을 큰 레지스터로 이동할 때 부호 비트 처리 방식이 다릅니다.

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

SHL/SHR 시프트 연산은 2의 거듭제곱 곱셈/나눗셈을 빠르게 수행합니다. 악성코드에서 암호화나 데이터 조작에 자주 사용됩니다.

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

조건 분기 명령어 전체 목록입니다. 각 명령어가 어떤 플래그 조건에서 분기하는지 이해하면 리버싱 시 프로그램 로직을 빠르게 파악할 수 있습니다.

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

CALL 명령어는 리턴 주소를 스택에 저장하고 함수로 점프합니다. RET은 스택에서 리턴 주소를 꺼내 원래 위치로 돌아옵니다.

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

DLL을 암시적(컴파일 시)과 명시적(런타임)으로 로드하는 C 코드입니다. 악성코드는 탐지 회피를 위해 런타임 로드를 선호합니다.

```c
// 암시적 로드 (컴파일 시 자동 링크 — IAT에 기록됨)
#include <windows.h>
int main(void) {
    MessageBoxA(NULL, "Hello", "Title", MB_OK);
    return 0;
}

// 명시적 로드 — 런타임에 동적으로 로드 (IAT에 기록 안 됨, 분석 어려움)
#include <windows.h>
#include <stdio.h>

typedef int (WINAPI *PFN_MessageBoxA)(HWND, LPCSTR, LPCSTR, UINT);

int main(void) {
    HMODULE hMod = LoadLibraryA("user32.dll");
    if (!hMod) { fprintf(stderr, "LoadLibrary 실패\n"); return 1; }

    PFN_MessageBoxA pMB = (PFN_MessageBoxA)GetProcAddress(hMod, "MessageBoxA");
    if (pMB) {
        pMB(NULL, "Dynamic load", "Info", MB_OK);
    }
    FreeLibrary(hMod);
    return 0;
}
```

```python
#!/usr/bin/env python3
"""
pefile로 IAT(Import Address Table) 분석 — 의심 API 자동 탐지
사용법: python3 iat_analyzer.py <PE파일>
"""
import sys
import pefile

SUSPICIOUS: dict[str, list[str]] = {
    "네트워크":    ["WSAStartup", "connect", "send", "recv",
                  "URLDownloadToFile", "InternetOpen", "InternetConnectA"],
    "코드인젝션":  ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
                  "SetWindowsHookEx", "NtUnmapViewOfSection"],
    "지속성":      ["RegSetValueEx", "RegCreateKeyEx", "CreateServiceA",
                  "StartServiceA"],
    "안티분석":    ["IsDebuggerPresent", "CheckRemoteDebuggerPresent",
                  "NtQueryInformationProcess", "GetTickCount"],
    "암호화":      ["CryptEncrypt", "CryptCreateHash", "CryptDeriveKey"],
}


def analyze_iat(path: str) -> None:
    pe = pefile.PE(path)
    if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        print("[-] Import 디렉토리가 없습니다.")
        return

    found_flags: dict[str, list[str]] = {}
    print(f"\n[*] IAT 분석: {path}\n{'='*50}")

    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        dll_name = entry.dll.decode(errors="replace")
        for imp in entry.imports:
            if not imp.name:
                continue
            func = imp.name.decode(errors="replace")
            for category, apis in SUSPICIOUS.items():
                if func in apis:
                    found_flags.setdefault(category, []).append(
                        f"{dll_name}!{func}"
                    )

    if found_flags:
        print("[!] 의심 API 탐지:")
        for cat, funcs in found_flags.items():
            print(f"\n  [{cat}]")
            for f in funcs:
                print(f"    - {f}")
    else:
        print("[+] 의심 API 없음")

    # 전체 임포트 출력
    print(f"\n[*] 전체 임포트 DLL 목록:")
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        print(f"  {entry.dll.decode(errors='replace')}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <PE파일>")
        sys.exit(1)
    analyze_iat(sys.argv[1])
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

함수 내 지역변수는 EBP(또는 RBP) 기준 음수 오프셋으로 스택에 위치합니다. 버퍼 오버플로우 취약점 분석 시 변수 레이아웃을 파악하는 데 필수적입니다.

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

CUI(콘솔) 프로그램의 main 함수 시그니처입니다. argc/argv로 명령줄 인자를, envp로 환경 변수를 받습니다.

```c
// main 함수 — 기본 인자 3개 (Linux/Windows CUI 공통)
int main(int argc, char *argv[], char **envp)
{
    // argc: 전달된 인자 개수 (프로그램명 포함)
    // argv: 인자 값 배열 (argv[0] = 실행 파일 경로)
    // envp: 환경 변수 배열 (NULL 종료)
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <input>\n", argv[0]);
        return EXIT_FAILURE;
    }
    printf("arg: %s\n", argv[1]);
    return EXIT_SUCCESS;
}
```

### GUI 프로그램 (Windows)

Windows GUI 프로그램의 WinMain 함수 시그니처입니다. 메시지 루프를 통해 이벤트를 처리하는 Windows 특유의 구조입니다.

```c
// WinMain 함수 — 기본 인자 4개 (Windows GUI)
int APIENTRY WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
                     LPSTR lpszCmdParam, int nCmdShow)
{
    // hInstance: 현재 프로그램 인스턴스 핸들
    // hPrevInstance: 항상 NULL (Win32 이후 사용 안 함)
    // lpszCmdParam: 커맨드 라인 인자 문자열 (argv 아님!)
    // nCmdShow: 윈도우 표시 방식 (SW_SHOW, SW_HIDE 등)
    MessageBoxA(NULL, "Hello, Reverser!", "Info", MB_OK);
    return 0;
}
```

```python
#!/usr/bin/env python3
"""
main 함수 진입점 자동 탐지 스크립트 (r2pipe 사용)
사용법: python3 find_main.py <binary>
"""
import sys
import r2pipe
import json


def find_main_entry(binary_path: str) -> None:
    r2 = r2pipe.open(binary_path, flags=["-2"])  # 경고 억제
    r2.cmd("aaa")  # 전체 분석

    # 엔트리포인트 확인
    entry_info = json.loads(r2.cmd("iej"))
    print(f"[*] 엔트리포인트: {[e for e in entry_info]}")

    # main 함수 탐지 (심볼 또는 패턴 매칭)
    symbols = json.loads(r2.cmd("isj"))
    main_syms = [s for s in symbols if "main" in s.get("name", "").lower()]
    for sym in main_syms:
        print(f"[+] main 후보: {sym['name']} @ {hex(sym['vaddr'])}")

    # CRT 초기화 이후 첫 CALL 대상 (심볼 없는 경우)
    if not main_syms:
        entry_addr = entry_info[0]["vaddr"] if entry_info else None
        if entry_addr:
            r2.cmd(f"s {entry_addr}")
            # 엔트리포인트에서 CALL 명령 목록 추출
            disasm = json.loads(r2.cmd("pdj 30"))
            calls = [i for i in disasm if i.get("type") == "call"]
            if calls:
                print(f"[+] WinMain/main 추정 주소: {hex(calls[-1]['jump'])}")

    r2.quit()


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <binary>")
        sys.exit(1)
    find_main_entry(sys.argv[1])
```

---

<a name="english"></a>

# Reverse Engineering — Complete Guide to Assembly and Registers

## 1. What is Reversing?

Reverse Engineering is the technique of disassembling a finished product to understand its internal structure and operating principles.
In software security, it means analyzing compiled executables (binaries) to understand their behavior without source code.

### When Reversing is Needed
- **Cracking**: Analyzing software license protection mechanisms (finding vulnerabilities)
- **Malware Analysis**: Understanding virus/trojan behavior
- **Vulnerability Analysis**: Finding vulnerabilities in unpatched binaries
- **Protocol Reverse Engineering**: Decoding undisclosed network protocols
- **Bug Fixing**: Patching legacy software without source code

### Required Skills
- Assembly language understanding (most important)
- OS structure (processes, memory, system calls)
- C/C++ language understanding
- Patience and analytical ability

---

## 2. Analysis Tools

### Disassemblers
| Tool | Features |
|------|---------|
| IDA Pro | Industry standard, powerful analysis, expensive |
| Ghidra | NSA developed, open source, decompiler support |
| Binary Ninja | Modern UI, rich API |
| radare2 | Open source, CLI, powerful scripting |
| W32DASM | Old Windows program analysis |

### Debuggers
| Tool | Target | Features |
|------|--------|---------|
| OllyDbg | Windows 32-bit | Easy to use, best for reversing beginners |
| x64dbg | Windows 32/64-bit | OllyDbg successor, open source |
| WinDbg | Windows Kernel | Kernel debugging |
| GDB | Linux | Default debugger |
| PEDA/pwndbg | Linux | GDB extension, exploit-focused |

### Analysis Environment Setup

Script for automatic reversing analysis environment setup. Installs GDB, NASM, pwntools, pwndbg and other essential tools for exploit development and reverse engineering in one go.

```bash
# Analysis environment auto-setup script (Ubuntu/Kali)
#!/usr/bin/env bash
set -euo pipefail

echo "[*] Setting up reversing analysis environment"

# Install basic tools
sudo apt-get update -qq
sudo apt-get install -y \
    gdb gdb-multiarch \
    nasm binutils \
    python3-pip \
    upx-ucl \
    file binwalk

# Install pwntools and analysis libraries
pip3 install --quiet \
    pwntools \
    pefile \
    capstone \
    unicorn \
    keystone-engine \
    r2pipe

# Install GDB extension (pwndbg recommended)
if [ ! -d "$HOME/pwndbg" ]; then
    git clone https://github.com/pwndbg/pwndbg.git "$HOME/pwndbg"
    cd "$HOME/pwndbg" && ./setup.sh
fi

# Install checksec
pip3 install --quiet checksec.py

echo "[+] Environment setup complete"
echo "    GDB+pwndbg, pwntools, pefile, r2pipe available"

# Compile options for practice vulnerable binaries (disable protections)
# gcc -o vuln vuln.c -fno-stack-protector -z execstack -no-pie -m32
```

---

## 3. CPU Registers — Complete Understanding

### IA-32 (Intel 32-bit) Register Structure

x86/x64 registers are ultra-fast storage directly accessed by the CPU. EAX holds function return values, ESP is the stack pointer, EIP holds the address of the next instruction — controlling these registers is the core of exploit development.

```
32-bit (EAX):
┌────────────────────────────────────────┐
│                  EAX (32-bit, 4 bytes) │
└────────────────────────────────────────┘
                        ┌───────────────┐
                        │   AX (16-bit)  │
                        └───────────────┘
                        ┌──────┬────────┐
                        │AH(8) │ AL(8)  │
                        └──────┴────────┘
```

### General Purpose Registers

#### EAX (Accumulator)
- Stores arithmetic results and function return values
- All Win32 API function return values are stored in EAX
- `EAX = AX = AH + AL` (32-bit = 16-bit = 8-bit + 8-bit)

#### EBX (Base)
- Address-based register
- Also used as general purpose register

#### ECX (Counter)
- Loop counter (for LOOP instruction)
- Stores iteration count → repeats until zero

#### EDX (Data)
- Stores upper 32 bits of EAX in extended operations
- Also used as I/O pointer

### Index/Pointer Registers

#### ESP (Stack Pointer)
- Points to the current top of the stack
- `PUSH`: ESP -= 4, stores data
- `POP`:  reads data, ESP += 4

#### EBP (Base Pointer)
- Base address of the current stack frame
- Reference point for local variable access (`EBP-4`, `EBP-8`, etc.)
- Function start: `PUSH EBP / MOV EBP, ESP`
- Function end: `MOV ESP, EBP / POP EBP / RET`

#### ESI (Source Index)
- Source address for copy operations

#### EDI (Destination Index)
- Destination address for copy operations

#### EIP (Instruction Pointer)
- Address of the next instruction to execute
- **Core target of BoF attacks** — controlling EIP means controlling execution flow
- Also called PC (Program Counter)

---

## 4. Flag Register (EFLAGS)

x86/x64 registers are ultra-fast storage directly accessed by the CPU. EAX holds function return values, ESP is the stack pointer, EIP holds the address of the next instruction — controlling these registers is the core of exploit development.

```
Each bit in the flag register holds a 0 or 1 flag value
Key flags for analysis:
```

| Flag | Name | Condition |
|------|------|-----------|
| OF | Overflow | 1 when signed overflow occurs |
| SF | Sign | 1 if result is negative, 0 if positive |
| ZF | Zero | 1 if result is zero (very important in conditional branching) |
| CF | Carry | 1 when unsigned overflow occurs |
| PF | Parity | 1 if number of 1-bits in lower 8 bits is even |
| AF | Auxiliary | Carry in BCD arithmetic |
| TF | Trap | Single step mode |

---

## 5. Assembly Instructions — Complete Reference

### MOV Instruction (Data Movement)

Assembly data movement instructions. `MOV` is basic data copy, while `LEA` only computes the address without actually reading memory. In PIE binaries, global variables are accessed via `lea rdi, [rip + offset]`.

```asm
MOV DST, SRC    ; Copy value of SRC to DST

; Examples
MOV EAX, 12345678h       ; EAX = 0x12345678 (immediate)
MOV ECX, EAX             ; ECX = EAX (register-to-register copy)
MOV DWORD PTR [00406000h], 12345678h  ; memory[0x406000] = 0x12345678

; Size specifiers
DWORD PTR  ; 4 bytes (int)
WORD PTR   ; 2 bytes (short)
BYTE PTR   ; 1 byte (char)

; Invalid usage (error)
MOV AX, EDX   ; Size mismatch (AX=16bit, EDX=32bit)
```

### LEA Instruction (Load Effective Address)

The LEA (Load Effective Address) instruction calculates a memory address and stores it in a register. Unlike MOV, it doesn't actually read memory — it only computes the address.

```asm
; Difference from MOV — LEA loads the address itself
MOV EAX, DWORD PTR [00406000h]   ; EAX = value at memory[0x406000]
LEA EAX, DWORD PTR [00406000h]   ; EAX = 0x406000 (the address itself)

; C code translation example
int a = 5;
int *p = &a;

; → Assembly translation
MOV DWORD PTR [00406000h], 5     ; a = 5
LEA EAX, DWORD PTR [00406000h]   ; EAX = &a
MOV DWORD PTR [00406004h], EAX   ; p = &a
```

### Arithmetic Operations

Assembly arithmetic instructions. Shows how ADD, SUB, MUL, DIV and other operations affect CPU registers and the flag register.

```asm
; Addition
ADD EAX, 3       ; EAX = EAX + 3
ADD EAX, ECX     ; EAX = EAX + ECX

; Subtraction
SUB EAX, 3       ; EAX = EAX - 3

; Multiplication (MUL: unsigned, IMUL: signed)
MUL ECX          ; EDX:EAX = EAX * ECX (EDX used when result is large)
IMUL EAX, ECX, 10h  ; EAX = ECX * 0x10

; Division (DIV: unsigned, IDIV: signed)
DIV ECX          ; EAX = EAX / ECX (quotient)
                 ; EDX = EAX % ECX (remainder)

; C code mapping
; int c = a / b;
MOV EAX, DWORD PTR [a]
MOV ECX, DWORD PTR [b]
IDIV ECX
MOV DWORD PTR [c], EAX    ; quotient

; int c = a % b;
MOV EAX, DWORD PTR [a]
MOV ECX, DWORD PTR [b]
IDIV ECX
MOV DWORD PTR [c], EDX    ; remainder
```

### Bitwise Operations

Assembly bitwise instructions (AND, OR, XOR, NOT). In malware analysis, XOR is frequently used for data obfuscation and encryption.

```asm
; AND
AND EAX, ECX     ; EAX = EAX & ECX

; OR
OR EAX, ECX      ; EAX = EAX | ECX

; XOR
XOR EAX, EAX     ; EAX = 0 (XOR with itself → zero initialization, optimization technique)
XOR EAX, ECX     ; EAX = EAX ^ ECX

; NOT (bitwise complement)
NOT EAX          ; EAX = ~EAX

; Practical example: case conversion
; 'a'(0x61) XOR 0x20 = 'A'(0x41)
; 'A'(0x41) XOR 0x20 = 'a'(0x61)
MOV EAX, 61h     ; 'a'
XOR EAX, 20h     ; → 0x41 = 'A'
```

### Comparison and Conditional Branching

Use the CMP instruction to compare two values, then conditional branches (JE, JNE, JG, etc.) to control program flow. This is the core of analyzing serial validation logic during reversing.

```asm
; CMP: compare two values (subtracts, discards result, only updates flags)
CMP EAX, 3       ; Set flags based on EAX - 3

; Conditional jump instructions
JE  label        ; Jump if Equal     (ZF=1)
JNE label        ; Jump if Not Equal (ZF=0)
JG  label        ; Jump if Greater   (ZF=0 and SF=OF, signed)
JGE label        ; Jump if Greater or Equal (SF=OF)
JL  label        ; Jump if Less      (SF≠OF, signed)
JLE label        ; Jump if Less or Equal
JA  label        ; Jump if Above     (CF=0 and ZF=0, unsigned)
JB  label        ; Jump if Below     (CF=1, unsigned)
JZ  label        ; Jump if Zero      (ZF=1, same as JE)
JNZ label        ; Jump if Not Zero  (ZF=0, same as JNE)
JMP label        ; Unconditional jump

; C code mapping
; if (a != b) { a = 1000; }
MOV DWORD PTR [EBP-4], 10      ; a = 10
MOV DWORD PTR [EBP-8], 20      ; b = 20
MOV EAX, DWORD PTR [EBP-4]
CMP EAX, DWORD PTR [EBP-8]
JE  equal_label                 ; jump if a == b
MOV DWORD PTR [EBP-4], 3E8h    ; a = 1000
equal_label:
```

---

## 6. Stack Operations

### PUSH / POP

PUSH and POP store and retrieve data on the stack. Used for argument passing in function calls and register preservation.

```asm
; PUSH internal operation
PUSH 10h
; = SUB ESP, 4
; = MOV DWORD PTR [ESP], 10h

; POP internal operation
POP EAX
; = MOV EAX, DWORD PTR [ESP]
; = ADD ESP, 4

; Stack state visualization (PUSH 10, PUSH 20, PUSH 30)
; Before:               After:
;              ↑ESP      ┌────────┐ ← ESP
;                        │  0x30  │
;                        │  0x20  │
;                        │  0x10  │
;                        └────────┘ ← EBP
```

### Function Call (CALL / RET)

The CALL instruction saves the return address on the stack and jumps to the function. RET pops the return address from the stack and returns to the original location.

```asm
; CALL internal operation
CALL 00401000h
; = PUSH EIP        (save next instruction address on stack)
; = JMP 00401000h   (jump to function)

; Function prologue (beginning of almost every function)
PUSH EBP          ; save previous EBP
MOV EBP, ESP      ; set up new stack frame

; Function epilogue (function end)
MOV ESP, EBP      ; restore stack
POP EBP           ; restore previous EBP
RETN              ; = POP EIP → return to caller

; RETN 8 (argument cleanup)
; = POP EIP
; = ADD ESP, 8     (cleanup 4-byte * 2 function arguments)
```

---

## 7. Loop Assembly Translation

### for Loop

A C language for loop. Comparing it with its assembly translation helps understand compiler optimization.

```c
// C code
for (int i = 0; i < 10; i++) {
    // work
}
```

A C for loop translated to assembly. The loop is implemented as a combination of counter initialization, condition comparison, increment, and jump instructions.

```asm
; Assembly translation
MOV ECX, 0Ah      ; ECX = 10 (iteration count)
MOV DWORD PTR [i], 0

loop_start:
    CMP DWORD PTR [i], 0Ah
    JGE loop_end       ; exit if i >= 10
    ; ... work ...
    INC DWORD PTR [i]  ; i++
    JMP loop_start

loop_end:

; Or using REP instruction
MOV ECX, 0Ah           ; iteration count
loop_start:
    ; ... work ...
    LOOP loop_start    ; ECX--, jump if ZF=0
```

### Bulk Initialization (memset optimization)

The optimized assembly pattern that compilers use for bulk memory initialization. The REP STOSD instruction initializes multiple bytes at once.

```asm
; char buf[12] = {0};  → assembly optimization
MOV ECX, 3             ; 3 * 4 = 12 bytes
XOR EAX, EAX           ; EAX = 0
LEA EDI, [EBP-0Ch]     ; EDI = buf start address
REP STOS DWORD PTR ES:[EDI]  ; [EDI] = 0, EDI += 4, ECX-- (until ECX=0)
```

---

## 8. C Language vs Assembly Mapping Summary

| C Code | Assembly Pattern |
|--------|----------------|
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

## 9. Extended Data Movement Instructions (MOVSX / MOVZX)

When moving values between registers of different sizes, a simple MOV causes an error.
In this case, use MOVSX or MOVZX depending on whether sign extension is needed.

```asm
; al = 1111 1111b (= -1 signed, 255 unsigned)

; MOVSX : Signed extension (copies sign bit to upper bits)
MOVSX ECX, AL
; → ECX = 1000 0000 0000 0000 0000 0000 0111 1111b (= -1 signed)
; upper bits filled with sign bit (1)

; MOVZX : Unsigned extension (fills upper bits with 0)
MOVZX ECX, AL
; → ECX = 0000 0000 0000 0000 0000 0000 1111 1111b (= 255)
; upper bits filled with 0
```

MOVSX (sign extension) and MOVZX (zero extension) instructions. When moving small data types (char, short) to larger registers, sign bit handling differs.

```asm
; Practical example - char → int assignment
char b = 'a';    ; 0x61 = 97
int a;
a = b;

; Assembly translation
MOV BYTE PTR [EBP-8], 61h       ; b = 'a'
MOVSX EAX, BYTE PTR [EBP-8]     ; load to EAX with signed extension
MOV DWORD PTR [EBP-4], EAX      ; a = (int)b
```

---

## 10. Shift Operations

SHL/SHR shift operations quickly perform multiplication/division by powers of 2. Frequently used in malware for encryption and data manipulation.

```asm
; SHL (Shift Left Logical) — left shift (= *2)
SHL EAX, 1       ; EAX = EAX * 2
SHL EAX, 3       ; EAX = EAX * 8 (2^3)

; SHR (Shift Right Logical) — right shift, unsigned (= /2)
SHR EAX, 1       ; EAX = EAX / 2 (fills upper with 0)

; SAR (Shift Arithmetic Right) — right shift, signed
SAR EAX, 1       ; EAX = EAX / 2 (preserves sign bit)
; For negative: -8 >> 1 = -4 (SAR), 2147483644 (SHR)

; Usage: multiplication/division optimization
; Compilers often optimize power-of-2 multiplication to SHL
```

---

## 11. Complete Conditional Branch Instruction List

Branching occurs based on flag values after CMP instruction execution.
`***` marks core instructions that frequently appear during reversing.

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
    JMP        : always        → Unconditional jump
```

Complete list of conditional branch instructions. Understanding which flag conditions each instruction branches on allows quick comprehension of program logic during reversing.

```asm
; Practical example — if/else pattern
; if (a != b) { a = 1000; }

MOV DWORD PTR SS:[EBP-4], 0Ah   ; a = 10
MOV DWORD PTR SS:[EBP-8], 14h   ; b = 20
MOV EAX, DWORD PTR SS:[EBP-4]
CMP EAX, DWORD PTR SS:[EBP-8]
JE  SHORT equal_label             ; skip if a == b
MOV DWORD PTR SS:[EBP-4], 3E8h  ; a = 1000
equal_label:

; Practical example — comparison flow
MOV EAX, 30
CMP EAX, 31     ; EAX - 31 = -1 → SF set
JG  label       ; -1 > 0 is false, no branch
CMP EAX, 29     ; EAX - 29 = 1
JG  label       ; 1 > 0 is true, branch taken
```

---

## 12. Calling Conventions

Rules for argument passing and stack cleanup between Caller (calling function) and Callee (called function).

| Convention | Argument Passing | Stack Cleanup | Main Usage |
|-----------|-----------------|--------------|-----------|
| `__cdecl` | Stack (right→left push) | Caller cleans up `ADD ESP, XX` | C library functions |
| `__stdcall` | Stack (right→left push) | Callee cleans up `RETN XX` | Win32 API |
| `__fastcall` | ECX, EDX (1~2 args), rest on stack | Callee cleans up `RETN XX` | Fast function calls |

The CALL instruction saves the return address on the stack and jumps to the function. RET pops the return address from the stack and returns to the original location.

```asm
; __cdecl example — C function call
PUSH arg2
PUSH arg1          ; push on stack in reverse order
CALL function_addr
ADD ESP, 8          ; caller restores stack by arg size

; __stdcall example — Win32 API call
PUSH MB_OK          ; arg4
PUSH 0              ; arg3 (hWnd)
PUSH "Title"        ; arg2
PUSH "Message"      ; arg1
CALL MessageBoxA
; callee internally: RETN 10h (cleans up 4*4=16 bytes)

; __fastcall example
; func(int a, int b)  → ECX=a, EDX=b
; func(int a, int b, int c) → ECX=a, EDX=b, PUSH c
```

```
Stack frame structure (inside function):
  [EBP+0C] = second argument (arg2)
  [EBP+08] = first argument (arg1)
  [EBP+04] = return address
  [EBP+00] = previous EBP
  [EBP-04] = first local variable (local1)
  [EBP-08] = second local variable (local2)
```

---

## 13. Libraries

Files containing function execution code. Divided into two types based on linking method.

### Static Link Library (.lib)
- Library code is directly embedded in the executable at compile time
- Advantage: no external files needed at runtime
- Disadvantage: larger executable, memory waste, library updates not reflected

### Dynamic Link Library (.dll)
- Code is loaded from DLL when needed during program execution
- Advantage: smaller executable, library updates reflected in program
- Disadvantage: DLL file must be present

### DLL Loading Methods

C code for implicit (compile-time) and explicit (runtime) DLL loading. Malware prefers runtime loading to evade detection.

```c
// Implicit load (auto-linked at compile time — recorded in IAT)
#include <windows.h>
int main(void) {
    MessageBoxA(NULL, "Hello", "Title", MB_OK);
    return 0;
}

// Explicit load — dynamically loaded at runtime (not recorded in IAT, harder to analyze)
#include <windows.h>
#include <stdio.h>

typedef int (WINAPI *PFN_MessageBoxA)(HWND, LPCSTR, LPCSTR, UINT);

int main(void) {
    HMODULE hMod = LoadLibraryA("user32.dll");
    if (!hMod) { fprintf(stderr, "LoadLibrary failed\n"); return 1; }

    PFN_MessageBoxA pMB = (PFN_MessageBoxA)GetProcAddress(hMod, "MessageBoxA");
    if (pMB) {
        pMB(NULL, "Dynamic load", "Info", MB_OK);
    }
    FreeLibrary(hMod);
    return 0;
}
```

```python
#!/usr/bin/env python3
"""
IAT (Import Address Table) analysis with pefile — auto-detect suspicious APIs
Usage: python3 iat_analyzer.py <PE_file>
"""
import sys
import pefile

SUSPICIOUS: dict[str, list[str]] = {
    "Network":       ["WSAStartup", "connect", "send", "recv",
                      "URLDownloadToFile", "InternetOpen", "InternetConnectA"],
    "CodeInjection": ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
                      "SetWindowsHookEx", "NtUnmapViewOfSection"],
    "Persistence":   ["RegSetValueEx", "RegCreateKeyEx", "CreateServiceA",
                      "StartServiceA"],
    "AntiAnalysis":  ["IsDebuggerPresent", "CheckRemoteDebuggerPresent",
                      "NtQueryInformationProcess", "GetTickCount"],
    "Encryption":    ["CryptEncrypt", "CryptCreateHash", "CryptDeriveKey"],
}


def analyze_iat(path: str) -> None:
    pe = pefile.PE(path)
    if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        print("[-] No import directory found.")
        return

    found_flags: dict[str, list[str]] = {}
    print(f"\n[*] IAT Analysis: {path}\n{'='*50}")

    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        dll_name = entry.dll.decode(errors="replace")
        for imp in entry.imports:
            if not imp.name:
                continue
            func = imp.name.decode(errors="replace")
            for category, apis in SUSPICIOUS.items():
                if func in apis:
                    found_flags.setdefault(category, []).append(
                        f"{dll_name}!{func}"
                    )

    if found_flags:
        print("[!] Suspicious APIs detected:")
        for cat, funcs in found_flags.items():
            print(f"\n  [{cat}]")
            for f in funcs:
                print(f"    - {f}")
    else:
        print("[+] No suspicious APIs found")

    # Print all imports
    print(f"\n[*] All imported DLL list:")
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        print(f"  {entry.dll.decode(errors='replace')}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <PE_file>")
        sys.exit(1)
    analyze_iat(sys.argv[1])
```

---

## 14. Data Types and Memory Allocation

### Data Type Categories
```
Primitive Types: int, char, float, double, short, long
User-defined Types:
  - struct
  - union
```

### Local Variable Position in Stack Memory

Local variables in a function are located on the stack at negative offsets relative to EBP (or RBP). Understanding variable layout is essential for analyzing buffer overflow vulnerabilities.

```asm
; Local variables inside function at negative EBP offsets
EBP - 4  → first local variable (int a)
EBP - 8  → second local variable (int b)
EBP - C  → third local variable (int c)

; Function arguments at positive EBP offsets
EBP + 8  → first argument (arg1)
EBP + C  → second argument (arg2)
```

### Memory Allocation Types
| Type | Method | Region | Characteristics |
|------|--------|--------|----------------|
| Static allocation | Determined at compile time | Stack, Data | Allocated at program start, freed at end |
| Dynamic allocation | Determined at runtime | Heap | Allocated with malloc, calloc, VirtualAlloc, etc. |

### RAM Memory Structure
```
Code  region: Program execution code (machine code)
Data  region: Global/static variables, string constants (initialized values)
Heap  region: Used for dynamic allocation (malloc, calloc, VirtualAlloc)
Stack region: Local variables, return addresses, function arguments

Characteristics:
- Windows: loaded into memory as PE format
- Linux: loaded into memory as ELF format
- Minimum memory unit: 4 bytes
- Stack managed in 4-byte units in IA-32
- Stack location determined randomly at runtime (ASLR)
```

---

## 15. main Function and WinMain

### CUI Program (Console)

The main function signature for CUI (console) programs. Receives command-line arguments via argc/argv and environment variables via envp.

```c
// main function — 3 default arguments (common to Linux/Windows CUI)
int main(int argc, char *argv[], char **envp)
{
    // argc: number of arguments passed (including program name)
    // argv: array of argument values (argv[0] = executable path)
    // envp: array of environment variables (NULL-terminated)
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <input>\n", argv[0]);
        return EXIT_FAILURE;
    }
    printf("arg: %s\n", argv[1]);
    return EXIT_SUCCESS;
}
```

### GUI Program (Windows)

The WinMain function signature for Windows GUI programs. The Windows-specific structure processes events through a message loop.

```c
// WinMain function — 4 default arguments (Windows GUI)
int APIENTRY WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
                     LPSTR lpszCmdParam, int nCmdShow)
{
    // hInstance: current program instance handle
    // hPrevInstance: always NULL (unused since Win32)
    // lpszCmdParam: command line argument string (not argv!)
    // nCmdShow: window display mode (SW_SHOW, SW_HIDE, etc.)
    MessageBoxA(NULL, "Hello, Reverser!", "Info", MB_OK);
    return 0;
}
```

```python
#!/usr/bin/env python3
"""
Auto-detection script for main function entry point (using r2pipe)
Usage: python3 find_main.py <binary>
"""
import sys
import r2pipe
import json


def find_main_entry(binary_path: str) -> None:
    r2 = r2pipe.open(binary_path, flags=["-2"])  # suppress warnings
    r2.cmd("aaa")  # full analysis

    # Check entry point
    entry_info = json.loads(r2.cmd("iej"))
    print(f"[*] Entry point: {[e for e in entry_info]}")

    # Detect main function (symbol or pattern matching)
    symbols = json.loads(r2.cmd("isj"))
    main_syms = [s for s in symbols if "main" in s.get("name", "").lower()]
    for sym in main_syms:
        print(f"[+] main candidate: {sym['name']} @ {hex(sym['vaddr'])}")

    # First CALL target after CRT initialization (when no symbol)
    if not main_syms:
        entry_addr = entry_info[0]["vaddr"] if entry_info else None
        if entry_addr:
            r2.cmd(f"s {entry_addr}")
            # Extract CALL instruction list from entry point
            disasm = json.loads(r2.cmd("pdj 30"))
            calls = [i for i in disasm if i.get("type") == "call"]
            if calls:
                print(f"[+] Estimated WinMain/main address: {hex(calls[-1]['jump'])}")

    r2.quit()


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <binary>")
        sys.exit(1)
    find_main_entry(sys.argv[1])
```
