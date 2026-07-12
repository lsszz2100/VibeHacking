> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# x86/x64 어셈블리 기초

## 0. 초보자를 위한 개념 이해

### 어셈블리 언어란?

**어셈블리 언어(Assembly Language)**는 CPU가 직접 이해하는 기계어와 1:1 대응되는 저수준 언어입니다. C언어 `a = b + 1`을 어셈블리로 쓰면 `mov eax, [rbp-8] / add eax, 1 / mov [rbp-4], eax`처럼 됩니다.

**왜 보안에서 필수인가:**
```
역공학(리버싱):
  .exe 파일 → 어셈블리 코드로 변환 → 동작 분석
  (소스코드가 없어도 무엇을 하는지 파악 가능)

취약점 분석:
  스택 오버플로, 버퍼 오버플로 이해 → 어셈블리 필수

셸코드 작성:
  직접 기계어 작성 → 어셈블리로만 가능
```

### 핵심 레지스터 정리

```
x86-64 범용 레지스터:

64bit   32bit  16bit  8bit   역할
------  -----  -----  ----   ----
RAX     EAX    AX     AL     함수 반환값
RBX     EBX    BX     BL     베이스 포인터
RCX     ECX    CX     CL     카운터 (루프)
RDX     EDX    DX     DL     데이터
RSI     ESI    SI     SIL    소스 인덱스
RDI     EDI    DI     DIL    목적 인덱스 (Linux 1번째 인자)
RSP     ESP    SP     SPL    스택 포인터 (현재 스택 위치)
RBP     EBP    BP     BPL    프레임 포인터 (현재 함수 기준)
RIP     EIP    IP     --     명령어 포인터 (다음 실행 주소)
```

### 필요한 도구
- **GDB + pwndbg**: Linux 어셈블리 디버거
- **x64dbg**: Windows 어셈블리 디버거
- **nasm**: 어셈블리 코드 컴파일러
- **objdump**: 바이너리 → 어셈블리 변환

### 기초 실습 예제
```nasm
; Hello World 어셈블리 (Linux x64)
; nasm -f elf64 hello.asm && ld hello.o -o hello

section .data
    msg db "Hello, World!", 0x0a  ; 문자열 + 줄바꿈
    len equ $ - msg               ; 문자열 길이

section .text
    global _start

_start:
    mov rax, 1       ; sys_write 시스템 콜 번호
    mov rdi, 1       ; stdout (파일 디스크립터 1)
    mov rsi, msg     ; 출력할 문자열 주소
    mov rdx, len     ; 출력할 길이
    syscall          ; 커널 호출

    mov rax, 60      ; sys_exit 시스템 콜
    xor rdi, rdi     ; 종료 코드 0
    syscall
```

---

## 1. 레지스터 체계

### 1.1 범용 레지스터 (General Purpose Registers)

| 64bit | 32bit | 16bit | 8bit(H) | 8bit(L) | 주요 용도 |
|-------|-------|-------|---------|---------|-----------|
| RAX   | EAX   | AX    | AH      | AL      | 누산기, 함수 반환값 |
| RBX   | EBX   | BX    | BH      | BL      | 베이스 주소 |
| RCX   | ECX   | CX    | CH      | CL      | 카운터, 4번째 인자 |
| RDX   | EDX   | DX    | DH      | DL      | 데이터, 3번째 인자 |
| RSI   | ESI   | SI    | -       | SIL     | 소스 인덱스, 2번째 인자 |
| RDI   | EDI   | DI    | -       | DIL     | 목적지 인덱스, 1번째 인자 |
| RSP   | ESP   | SP    | -       | SPL     | 스택 포인터 |
| RBP   | EBP   | BP    | -       | BPL     | 베이스 포인터(프레임) |
| R8    | R8D   | R8W   | -       | R8B     | 5번째 인자 |
| R9    | R9D   | R9W   | -       | R9B     | 6번째 인자 |
| R10~R15 | ... | ...  | -       | ...     | 임시 저장 |

```
RAX (64bit)
├── EAX (하위 32bit)
│   ├── AX (하위 16bit)
│   │   ├── AH (비트 8~15)
│   │   └── AL (비트 0~7)
```

### 1.2 특수 목적 레지스터

| 레지스터 | 설명 |
|----------|------|
| RIP      | Instruction Pointer — 다음 실행할 명령어 주소 |
| RFLAGS   | 플래그 레지스터 (상태 비트 집합) |

### 1.3 세그먼트 레지스터

| 레지스터 | 용도 |
|----------|------|
| CS       | Code Segment |
| DS       | Data Segment |
| SS       | Stack Segment |
| ES       | Extra Segment |
| FS       | 스레드 로컬 스토리지 (Linux: TLS, Windows: TEB) |
| GS       | 커널 구조체 접근 (Linux: percpu, Windows: TEB) |

### 1.4 RFLAGS 주요 비트

| 비트 | 이름 | 설명 |
|------|------|------|
| CF (0)  | Carry Flag       | 올림수/빌림수 발생 |
| PF (2)  | Parity Flag      | 결과 하위 바이트 1의 개수 짝수 |
| AF (4)  | Auxiliary Flag   | BCD 연산 올림수 |
| ZF (6)  | Zero Flag        | 결과가 0 |
| SF (7)  | Sign Flag        | 결과 최상위 비트(부호) |
| TF (8)  | Trap Flag        | 단계 실행 모드 |
| IF (9)  | Interrupt Flag   | 외부 인터럽트 허용 |
| DF (10) | Direction Flag   | 문자열 연산 방향 |
| OF (11) | Overflow Flag    | 부호있는 오버플로우 |

---

## 2. 핵심 명령어

### 2.1 데이터 이동


x86/x64 어셈블리 데이터 이동 명령어입니다. `MOV`로 레지스터·메모리 간 데이터를 복사하고, `LEA`로 메모리 접근 없이 주소를 계산합니다. 메모리 접근 시 대괄호 `[]`로 포인터 역참조를 표시합니다.

```nasm
; MOV — 데이터 복사
mov rax, 0x1234          ; 즉시값 → 레지스터
mov rax, rbx             ; 레지스터 → 레지스터
mov rax, [rbx]           ; 메모리(rbx가 가리키는 주소) → 레지스터
mov [rax], rbx           ; 레지스터 → 메모리
mov [rax + 8], rcx       ; 오프셋 메모리 접근
mov BYTE PTR [rax], 0x41 ; 크기 지정 메모리 쓰기

; LEA — 유효 주소 계산 (실제 메모리 접근 없음)
lea rax, [rbx + rcx*4 + 8]  ; 주소 계산만 수행
lea rdi, [rip + msg]         ; RIP-relative 주소 (PIE 코드에서 흔함)

; XCHG — 교환
xchg rax, rbx

; MOVZX / MOVSX — 제로확장 / 부호확장
movzx rax, BYTE PTR [rbx]   ; 8bit를 64bit로 제로확장
movsx rax, DWORD PTR [rbx]  ; 32bit를 64bit로 부호확장
```

### 2.2 스택 조작


스택 조작과 함수 호출/반환 어셈블리 코드입니다. `PUSH`로 스택에 값을 저장하고 `POP`으로 꺼내며, `CALL`은 리턴 주소를 스택에 저장 후 점프합니다. `RET`은 스택에서 꺼낸 주소로 실행을 복귀합니다.

```nasm
; PUSH — RSP를 8 감소시키고 값 저장
push rax          ; [rsp-8] = rax, rsp -= 8
push 0x1234       ; 즉시값 push
push QWORD PTR [rbx]  ; 메모리값 push

; POP — 값 꺼내고 RSP를 8 증가
pop rax           ; rax = [rsp], rsp += 8
pop QWORD PTR [rbx]   ; 메모리로 pop

; PUSHA/POPA — 모든 범용 레지스터 저장/복원 (32bit 전용)
; 64bit에서는 각각 push/pop 사용
```

### 2.3 제어 흐름

NASM(Netwide Assembler) 어셈블리 코드입니다. x86/x64 셸코드 개발이나 저수준 프로그래밍에 사용하는 어셈블러 문법입니다.

```nasm
; JMP — 무조건 점프
jmp 0x401000      ; 절대 주소
jmp rax           ; 레지스터 간접 점프
jmp [rax]         ; 메모리 간접 점프
jmp short .label  ; 단거리 점프 (±127 바이트)

; 조건부 점프 (CMP/TEST 이후 사용)
je  .equal        ; ZF=1 (같을 때)
jne .not_equal    ; ZF=0
jz  .zero         ; ZF=1 (je와 동일)
jnz .not_zero     ; ZF=0
jg  .greater      ; SF=OF, ZF=0 (부호있는 초과)
jge .greater_eq   ; SF=OF (부호있는 이상)
jl  .less         ; SF≠OF (부호있는 미만)
jle .less_eq      ; SF≠OF or ZF=1
ja  .above        ; CF=0, ZF=0 (부호없는 초과)
jb  .below        ; CF=1 (부호없는 미만)
jae .above_eq     ; CF=0
jbe .below_eq     ; CF=1 or ZF=1
js  .sign         ; SF=1 (음수)
jns .not_sign     ; SF=0
jo  .overflow     ; OF=1
jno .not_overflow ; OF=0

; CALL / RET
call 0x401234     ; [rsp-8] = rip+5, rsp -= 8, jmp 0x401234
call rax          ; 간접 호출
ret               ; rip = [rsp], rsp += 8
ret 0x10          ; ret + 스택 정리 (stdcall)

; LOOP
loop .label       ; rcx -= 1, rcx != 0 이면 점프
```

### 2.4 산술/논리 연산

NASM(Netwide Assembler) 어셈블리 코드입니다. x86/x64 셸코드 개발이나 저수준 프로그래밍에 사용하는 어셈블러 문법입니다.

```nasm
; 산술
add rax, rbx      ; rax += rbx
sub rax, rbx      ; rax -= rbx
mul rbx           ; rdx:rax = rax * rbx (unsigned)
imul rax, rbx     ; rax = rax * rbx (signed)
imul rax, rbx, 5  ; rax = rbx * 5
div rbx           ; rax = rdx:rax / rbx, rdx = 나머지 (unsigned)
idiv rbx          ; 부호있는 나눗셈
inc rax           ; rax++
dec rax           ; rax--
neg rax           ; rax = -rax

; 논리
and rax, rbx      ; 비트 AND
or  rax, rbx      ; 비트 OR
xor rax, rax      ; rax = 0 (자기 자신 XOR = 레지스터 초기화)
not rax           ; 비트 NOT
test rax, rax     ; AND 연산(결과 버림, ZF만 설정)
cmp  rax, rbx     ; SUB 연산(결과 버림, 플래그만 설정)

; 시프트
shl rax, 3        ; 왼쪽 논리 시프트 (×8)
shr rax, 3        ; 오른쪽 논리 시프트 (÷8)
sar rax, 3        ; 오른쪽 산술 시프트 (부호 보존)
rol rax, 1        ; 왼쪽 순환
ror rax, 1        ; 오른쪽 순환
```

### 2.5 문자열 명령어


x86/x64 어셈블리 MOV 명령어 예시입니다. 레지스터 간 복사, 즉시값 로드, 메모리 읽기/쓰기 등 다양한 피연산자 조합을 보여줍니다. `[]`는 메모리 간접 참조를 의미합니다.

```nasm
; REP 접두어와 함께 사용
rep  movsb        ; RCX번 반복: [rdi] = [rsi], rsi++, rdi++
rep  stosd        ; RCX번 반복: [rdi] = eax, rdi += 4
repe cmpsb        ; ZF=1 동안 반복 비교
repne scasb       ; ZF=0 동안 반복 스캔 (AL 값 검색)
```

---

## 3. 스택 프레임 구조

### 3.1 함수 호출 시 스택 레이아웃 (x64)

```
높은 주소
┌─────────────────────┐
│   ...상위 프레임...   │
├─────────────────────┤ ← caller의 RBP (저장된 RBP)
│  저장된 RBP          │ ← 현재 RBP
├─────────────────────┤
│  지역 변수 1         │ ← [rbp - 8]
├─────────────────────┤
│  지역 변수 2         │ ← [rbp - 16]
├─────────────────────┤
│  ...                │
├─────────────────────┤ ← RSP (스택 최상단)
낮은 주소
```

### 3.2 함수 프롤로그/에필로그


x86/x64 어셈블리 MOV 명령어 예시입니다. 레지스터 간 복사, 즉시값 로드, 메모리 읽기/쓰기 등 다양한 피연산자 조합을 보여줍니다. `[]`는 메모리 간접 참조를 의미합니다.

```nasm
; 프롤로그 — 함수 시작
push rbp          ; 이전 베이스 포인터 저장
mov  rbp, rsp     ; 현재 스택을 새 프레임 베이스로
sub  rsp, 0x30    ; 지역 변수 공간 확보 (16바이트 정렬 필수)

; 에필로그 — 함수 종료
mov  rsp, rbp     ; 스택 복원 (또는 leave 명령어)
pop  rbp          ; 이전 베이스 포인터 복원
ret               ; 반환

; LEAVE 명령어 = mov rsp, rbp + pop rbp
leave
ret
```

### 3.3 스택 정렬 요구사항

- **x64**: CALL 직전에 RSP는 반드시 **16바이트 정렬** 상태여야 함
- CALL은 8바이트(RIP) push → 프롤로그에서 RBP(8바이트) push → 총 16바이트 유지

---

## 4. Calling Convention

### 4.1 cdecl (x86 32bit)

```
인자 전달: 오른쪽 → 왼쪽 순서로 스택에 push
반환값:    EAX (64bit 값은 EDX:EAX)
스택 정리: 호출자(caller)가 책임
보존 레지스터: EBX, ESI, EDI, EBP
```

NASM(Netwide Assembler) 어셈블리 코드입니다. x86/x64 셸코드 개발이나 저수준 프로그래밍에 사용하는 어셈블러 문법입니다.

```nasm
; cdecl 예: add(1, 2)
push 2            ; 두 번째 인자
push 1            ; 첫 번째 인자
call add_func
add  esp, 8       ; caller가 스택 정리 (인자 2개 × 4바이트)
; 결과는 EAX에
```

### 4.2 stdcall (x86 32bit, Windows API)

```
인자 전달: 오른쪽 → 왼쪽 순서로 스택에 push
반환값:    EAX
스택 정리: 피호출자(callee)가 RET n으로 정리
보존 레지스터: EBX, ESI, EDI, EBP
```

NASM(Netwide Assembler) 어셈블리 코드입니다. x86/x64 셸코드 개발이나 저수준 프로그래밍에 사용하는 어셈블러 문법입니다.

```nasm
; stdcall 함수 반환 시
ret 8             ; 8바이트(인자 2개) 스택 정리 후 반환
```

### 4.3 fastcall (x86 32bit, MSVC)

```
인자 전달: ECX(1번째), EDX(2번째), 나머지는 스택
반환값:    EAX
스택 정리: 피호출자
```

### 4.4 System V AMD64 ABI (Linux/macOS x64)

```
정수/포인터 인자: RDI, RSI, RDX, RCX, R8, R9 (순서대로)
부동소수점 인자: XMM0~XMM7
추가 인자:      스택 (왼쪽 → 오른쪽)
반환값:         RAX (정수/포인터), XMM0 (float)
64bit 반환:     RAX:RDX
스택 정리:      호출자
Callee-saved:   RBX, RBP, R12~R15
Caller-saved:   RAX, RCX, RDX, RSI, RDI, R8~R11, XMM0~XMM15
```

NASM(Netwide Assembler) 어셈블리 코드입니다. x86/x64 셸코드 개발이나 저수준 프로그래밍에 사용하는 어셈블러 문법입니다.

```nasm
; System V AMD64 예: write(1, buf, len)
mov rax, 1        ; syscall 번호 (write)
mov rdi, 1        ; fd = stdout
lea rsi, [buf]    ; buf 주소
mov rdx, 13       ; 길이
syscall
```

### 4.5 Windows x64 ABI

```
정수/포인터 인자: RCX, RDX, R8, R9 (순서대로)
부동소수점 인자: XMM0~XMM3 (동시에 정수 위치도 채움)
추가 인자:      스택 (32바이트 shadow space 필수 할당)
반환값:         RAX
Callee-saved:   RBX, RBP, RDI, RSI, R12~R15, XMM6~XMM15
```

---

## 5. GDB 실전 명령어

### 5.1 기본 시작

```bash
gdb ./binary                    # 바이너리 로드
gdb -p 1234                     # 실행 중인 프로세스 attach
gdb --args ./binary arg1 arg2   # 인자와 함께 시작

# .gdbinit에 넣어두면 편리한 설정
set disassembly-flavor intel    # AT&T → Intel 문법으로 변경
set pagination off
set print pretty on
```

### 5.2 실행 제어

GDB 디버거 명령어입니다. 리버싱이나 익스플로잇 개발 시 프로그램 실행을 단계별로 제어하고 메모리/레지스터 상태를 확인합니다.

```gdb
run                     # 실행 (r)
run arg1 arg2           # 인자와 함께 실행
continue                # 계속 실행 (c)
next                    # 다음 줄 (함수 호출 건너뜀) (n)
nexti                   # 다음 명령어 1개 (ni)
step                    # 다음 줄 (함수 내부 진입) (s)
stepi                   # 명령어 1개 진입 (si)
finish                  # 현재 함수 끝까지 실행 (fin)
until 0x401234          # 해당 주소까지 실행
```

### 5.3 브레이크포인트

GDB 디버거 명령어입니다. 리버싱이나 익스플로잇 개발 시 프로그램 실행을 단계별로 제어하고 메모리/레지스터 상태를 확인합니다.

```gdb
break main              # 함수명으로 브레이크포인트
break *0x401234         # 주소로 브레이크포인트
break main+10           # 오프셋으로
info breakpoints        # 브레이크포인트 목록 (i b)
delete 1                # 1번 브레이크포인트 삭제
disable 2               # 비활성화
enable 2                # 활성화
condition 1 rax==0      # 조건부 브레이크포인트
watch *0x601060         # 메모리 쓰기 감시 (watchpoint)
rwatch *0x601060        # 메모리 읽기 감시
```

### 5.4 레지스터 확인

GDB 디버거 명령어입니다. 리버싱이나 익스플로잇 개발 시 프로그램 실행을 단계별로 제어하고 메모리/레지스터 상태를 확인합니다.

```gdb
info registers          # 모든 레지스터 출력 (i r)
info registers rax rbx  # 특정 레지스터만
print $rax              # RAX 값 출력
print/x $rax            # 16진수로 출력
print/d $rax            # 10진수로 출력
set $rax = 0x1234       # 레지스터 값 변경

# 레지스터 상태 한눈에 보기
layout regs             # TUI 모드에서 레지스터 창 표시
```

### 5.5 메모리 확인 (examine)

GDB 디버거 명령어입니다. 리버싱이나 익스플로잇 개발 시 프로그램 실행을 단계별로 제어하고 메모리/레지스터 상태를 확인합니다.

```gdb
# x/[개수][형식][크기] 주소
x/10gx $rsp             # RSP부터 64bit(g) 10개 16진수(x)
x/20wx 0x601000         # 32bit(w) 20개
x/s 0x401234            # 문자열로 출력
x/i $rip                # 현재 명령어 디스어셈블
x/20i main              # main부터 20개 명령어
x/b $rax                # 바이트 단위

# 크기: b=1byte, h=2byte, w=4byte, g=8byte
# 형식: x=hex, d=dec, u=udec, o=oct, t=bin, a=addr, s=str, i=inst
```

### 5.6 스택 분석

GDB 디버거 명령어입니다. 리버싱이나 익스플로잇 개발 시 프로그램 실행을 단계별로 제어하고 메모리/레지스터 상태를 확인합니다.

```gdb
info frame              # 현재 스택 프레임 정보
backtrace               # 콜스택 출력 (bt)
backtrace full          # 지역 변수 포함 콜스택
frame 2                 # 2번 프레임으로 이동
info locals             # 현재 프레임 지역 변수
info args               # 현재 함수 인자

x/20gx $rsp             # 스택 내용 직접 확인
```

### 5.7 디스어셈블

GDB 디버거 명령어입니다. 리버싱이나 익스플로잇 개발 시 프로그램 실행을 단계별로 제어하고 메모리/레지스터 상태를 확인합니다.

```gdb
disassemble main        # main 함수 디스어셈블 (disas)
disassemble 0x401000,0x401050  # 주소 범위
disassemble /r main     # 바이트 코드 포함
set disassembly-flavor intel   # Intel 문법
```

---

## 6. NASM 어셈블리 예제

### 6.1 Hello World (64bit Linux)

NASM(Netwide Assembler) 어셈블리 코드입니다. x86/x64 셸코드 개발이나 저수준 프로그래밍에 사용하는 어셈블러 문법입니다.

```nasm
; hello.asm — 64bit Linux
; 빌드: nasm -f elf64 hello.asm -o hello.o && ld hello.o -o hello

section .data
    msg db "Hello, World!", 0x0a
    msglen equ $ - msg

section .text
    global _start

_start:
    ; write(1, msg, msglen)
    mov rax, 1          ; sys_write
    mov rdi, 1          ; fd = stdout
    lea rsi, [rel msg]  ; 메시지 주소
    mov rdx, msglen     ; 길이
    syscall

    ; exit(0)
    mov rax, 60         ; sys_exit
    xor rdi, rdi        ; exit code = 0
    syscall
```

```bash
nasm -f elf64 hello.asm -o hello.o
ld hello.o -o hello
./hello
```

### 6.2 함수 호출 예제 (System V AMD64 ABI)

NASM(Netwide Assembler) 어셈블리 코드입니다. x86/x64 셸코드 개발이나 저수준 프로그래밍에 사용하는 어셈블러 문법입니다.

```nasm
; func_example.asm — 함수 호출 규약 데모
; 빌드: nasm -f elf64 func_example.asm -o func_example.o
;       gcc -no-pie func_example.o -o func_example

section .data
    fmt db "%d", 0x0a, 0

section .text
    global main
    extern printf

; int add(int a, int b) — 두 수의 합 반환
add_func:
    push rbp
    mov  rbp, rsp
    ; 인자: rdi=a, rsi=b
    mov  rax, rdi
    add  rax, rsi
    pop  rbp
    ret

; int factorial(int n)
factorial:
    push rbp
    mov  rbp, rsp

    cmp  rdi, 1
    jle  .base_case

    push rdi            ; n 저장
    dec  rdi
    call factorial      ; factorial(n-1)
    pop  rdi
    imul rax, rdi       ; n * factorial(n-1)
    jmp  .done

.base_case:
    mov rax, 1

.done:
    pop rbp
    ret

main:
    push rbp
    mov  rbp, rsp
    sub  rsp, 0x20      ; 16바이트 정렬 유지 (shadow space)

    ; add(3, 7) 호출
    mov rdi, 3
    mov rsi, 7
    call add_func
    ; 결과: rax = 10

    ; printf("%d\n", result)
    lea rdi, [rel fmt]
    mov rsi, rax
    xor eax, eax        ; 부동소수점 인자 없음
    call printf

    ; factorial(10) 호출
    mov rdi, 10
    call factorial

    lea rdi, [rel fmt]
    mov rsi, rax
    xor eax, eax
    call printf

    xor eax, eax
    leave
    ret
```

### 6.3 루프와 문자열 처리 예제

NASM(Netwide Assembler) 어셈블리 코드입니다. x86/x64 셸코드 개발이나 저수준 프로그래밍에 사용하는 어셈블러 문법입니다.

```nasm
; loop_str.asm — 문자열 길이 계산
section .text
    global strlen_asm

; size_t strlen_asm(const char *s)
; 인자: rdi = 문자열 포인터
strlen_asm:
    push rbp
    mov  rbp, rsp

    xor  rcx, rcx       ; 카운터 = 0
.loop:
    cmp  BYTE PTR [rdi + rcx], 0   ; null 체크
    je   .done
    inc  rcx
    jmp  .loop
.done:
    mov  rax, rcx       ; 길이 반환
    pop  rbp
    ret

; 동일한 기능을 REPNE SCASB로 구현
strlen_asm2:
    push rbp
    mov  rbp, rsp

    mov  rdi, rdi       ; 문자열 포인터 (이미 rdi에 있음)
    xor  al,  al        ; 찾을 값 = 0 (null)
    mov  rcx, -1        ; 최대 탐색 횟수
    repne scasb         ; [rdi]와 al 비교, 불일치하면 rdi++, rcx--
    not  rcx            ; ~(-match_pos - 2) = 길이
    dec  rcx            ; null 바이트 제외
    mov  rax, rcx

    pop  rbp
    ret
```

---

## 7. 자주 쓰는 패턴 정리

### 7.1 레지스터 초기화


x86/x64 어셈블리 MOV 명령어 예시입니다. 레지스터 간 복사, 즉시값 로드, 메모리 읽기/쓰기 등 다양한 피연산자 조합을 보여줍니다. `[]`는 메모리 간접 참조를 의미합니다.

```nasm
xor rax, rax        ; rax = 0 (mov rax, 0보다 짧음)
xor eax, eax        ; RAX 전체를 0으로 (상위 32bit 자동 클리어)
```

### 7.2 스택 정렬 맞추기

NASM(Netwide Assembler) 어셈블리 코드입니다. x86/x64 셸코드 개발이나 저수준 프로그래밍에 사용하는 어셈블러 문법입니다.

```nasm
; 함수 호출 전 RSP가 16바이트 정렬인지 확인
and rsp, ~0xf       ; 하위 4비트 클리어 (정렬 강제)
```

### 7.3 NOP sled

NASM(Netwide Assembler) 어셈블리 코드입니다. x86/x64 셸코드 개발이나 저수준 프로그래밍에 사용하는 어셈블러 문법입니다.

```nasm
nop                 ; 0x90, 아무것도 안 함
nop DWORD PTR [rax] ; 다중 바이트 NOP
```

### 7.4 시스템 콜 번호 참조 (Linux x64)

| syscall | 번호 (RAX) | 인자 |
|---------|-----------|------|
| read    | 0         | rdi=fd, rsi=buf, rdx=count |
| write   | 1         | rdi=fd, rsi=buf, rdx=count |
| open    | 2         | rdi=path, rsi=flags, rdx=mode |
| close   | 3         | rdi=fd |
| execve  | 59        | rdi=path, rsi=argv, rdx=envp |
| exit    | 60        | rdi=code |
| mmap    | 9         | rdi=addr, rsi=len, rdx=prot, r10=flags, r8=fd, r9=off |

---

<!-- detect-validate-19 -->
## 익스플로잇 완화 검증 (바이너리 수준)

어셈블리 수준 이해는 *익스플로잇 완화가 바이너리에 실제 적용됐는가*를 확인하는 능력이다. 공격은 스택·레지스터·반환 흐름을 노린다. 방어자는 **NX·카나리·PIE·RELRO 가 컴파일 결과에 실제로 들어갔는가**를 검증해야 한다. 검증은 **소유 바이너리**에서만.

### 공격 → 노리는 약점 → 1차 통제(방어자) → 검증 신호

| 기법 | 노리는 약점 | 1차 통제(방어자) | 검증 신호 |
|---|---|---|---|
| 리턴 주소 덮기 | 스택 보호 부재 | 스택 카나리 | checksec 에 "Canary found" 없음 |
| 직접 셸코드 실행 | 실행 가능 스택 | NX/DEP | "NX disabled"·GNU_STACK RWE |
| 고정 주소 가젯 | 비-PIE 로딩 | PIE/ASLR | checksec "No PIE" |
| GOT 덮어쓰기 | 쓰기 가능 GOT | Full RELRO | "Partial/No RELRO" |

### 방어 검증 (직접 확인)

```bash
# 1) 바이너리에 익스플로잇 완화가 실제 적용됐는지 확인 — 빌드 옵션 ≠ 컴파일 결과
checksec --file=./target 2>/dev/null || readelf -lW ./target | grep -E "GNU_STACK|GNU_RELRO"
#   GNU_STACK 가 RWE 면 NX 미적용 → 스택 셸코드 표면
# 2) 시스템 ASLR 이 켜져 있는지(완화 재현성 검증)
cat /proc/sys/kernel/randomize_va_space   # 2 여야 완전 ASLR
```

> 익스플로잇 방어의 출발점은 *완화가 바이너리에 실제로 박혀 있는가*다 — "하드닝 플래그 줬다"와 "NX·카나리·PIE 가 산출물에 있다"는 다르다. 소유 바이너리에 checksec/readelf 로 직접 확인한다([[09_Exploit_Techniques]], [[03_System_Hacking]], [[65_Reverse_Engineering_Advanced]]).

**최신 기법·통제 (2025–2026):**
- ARM64·RISC-V·CET/PAC 이해가 확장됨 — 분석은 소유 바이너리 한정. 검증: 디스어셈블/추정이 재현 가능한가([[04_Reverse_Engineering]])
- 컴파일러 최적화가 정적 이해 방해 — 동적확인과 교차검증

---

<a name="english"></a>

# x86/x64 Assembly Fundamentals

## 1. Register Architecture

### 1.1 General Purpose Registers

| 64bit | 32bit | 16bit | 8bit(H) | 8bit(L) | Primary Use |
|-------|-------|-------|---------|---------|-------------|
| RAX   | EAX   | AX    | AH      | AL      | Accumulator, function return value |
| RBX   | EBX   | BX    | BH      | BL      | Base address |
| RCX   | ECX   | CX    | CH      | CL      | Counter, 4th argument |
| RDX   | EDX   | DX    | DH      | DL      | Data, 3rd argument |
| RSI   | ESI   | SI    | -       | SIL     | Source index, 2nd argument |
| RDI   | EDI   | DI    | -       | DIL     | Destination index, 1st argument |
| RSP   | ESP   | SP    | -       | SPL     | Stack pointer |
| RBP   | EBP   | BP    | -       | BPL     | Base pointer (frame) |
| R8    | R8D   | R8W   | -       | R8B     | 5th argument |
| R9    | R9D   | R9W   | -       | R9B     | 6th argument |
| R10~R15 | ... | ...  | -       | ...     | Temporary storage |

```
RAX (64bit)
├── EAX (lower 32bit)
│   ├── AX (lower 16bit)
│   │   ├── AH (bits 8~15)
│   │   └── AL (bits 0~7)
```

### 1.2 Special Purpose Registers

| Register | Description |
|----------|-------------|
| RIP      | Instruction Pointer — address of the next instruction to execute |
| RFLAGS   | Flags register (collection of status bits) |

### 1.3 Segment Registers

| Register | Purpose |
|----------|---------|
| CS       | Code Segment |
| DS       | Data Segment |
| SS       | Stack Segment |
| ES       | Extra Segment |
| FS       | Thread-local storage (Linux: TLS, Windows: TEB) |
| GS       | Kernel structure access (Linux: percpu, Windows: TEB) |

### 1.4 Key RFLAGS Bits

| Bit | Name | Description |
|-----|------|-------------|
| CF (0)  | Carry Flag       | Carry/borrow occurred |
| PF (2)  | Parity Flag      | Even number of 1-bits in low byte of result |
| AF (4)  | Auxiliary Flag   | BCD arithmetic carry |
| ZF (6)  | Zero Flag        | Result is zero |
| SF (7)  | Sign Flag        | Most significant bit of result (sign) |
| TF (8)  | Trap Flag        | Single-step execution mode |
| IF (9)  | Interrupt Flag   | External interrupts enabled |
| DF (10) | Direction Flag   | String operation direction |
| OF (11) | Overflow Flag    | Signed overflow |

---

## 2. Core Instructions

### 2.1 Data Movement

x86/x64 assembly data movement instructions. Use `MOV` to copy data between registers and memory, and `LEA` to compute addresses without actually accessing memory. Square brackets `[]` indicate pointer dereference for memory access.

```nasm
; MOV — copy data
mov rax, 0x1234          ; immediate → register
mov rax, rbx             ; register → register
mov rax, [rbx]           ; memory (address rbx points to) → register
mov [rax], rbx           ; register → memory
mov [rax + 8], rcx       ; offset memory access
mov BYTE PTR [rax], 0x41 ; sized memory write

; LEA — compute effective address (no actual memory access)
lea rax, [rbx + rcx*4 + 8]  ; address computation only
lea rdi, [rip + msg]         ; RIP-relative address (common in PIE code)

; XCHG — exchange
xchg rax, rbx

; MOVZX / MOVSX — zero-extend / sign-extend
movzx rax, BYTE PTR [rbx]   ; zero-extend 8bit to 64bit
movsx rax, DWORD PTR [rbx]  ; sign-extend 32bit to 64bit
```

### 2.2 Stack Manipulation

Assembly code for stack manipulation and function call/return. `PUSH` saves a value to the stack and `POP` retrieves it. `CALL` saves the return address to the stack then jumps. `RET` returns execution to the address popped from the stack.

```nasm
; PUSH — decrement RSP by 8 and store value
push rax          ; [rsp-8] = rax, rsp -= 8
push 0x1234       ; push immediate value
push QWORD PTR [rbx]  ; push memory value

; POP — retrieve value and increment RSP by 8
pop rax           ; rax = [rsp], rsp += 8
pop QWORD PTR [rbx]   ; pop to memory

; PUSHA/POPA — save/restore all general registers (32bit only)
; Use individual push/pop in 64bit mode
```

### 2.3 Control Flow

NASM (Netwide Assembler) assembly syntax used for x86/x64 shellcode development and low-level programming.

```nasm
; JMP — unconditional jump
jmp 0x401000      ; absolute address
jmp rax           ; indirect jump via register
jmp [rax]         ; indirect jump via memory
jmp short .label  ; short jump (±127 bytes)

; Conditional jumps (used after CMP/TEST)
je  .equal        ; ZF=1 (equal)
jne .not_equal    ; ZF=0
jz  .zero         ; ZF=1 (same as je)
jnz .not_zero     ; ZF=0
jg  .greater      ; SF=OF, ZF=0 (signed greater than)
jge .greater_eq   ; SF=OF (signed greater or equal)
jl  .less         ; SF≠OF (signed less than)
jle .less_eq      ; SF≠OF or ZF=1
ja  .above        ; CF=0, ZF=0 (unsigned above)
jb  .below        ; CF=1 (unsigned below)
jae .above_eq     ; CF=0
jbe .below_eq     ; CF=1 or ZF=1
js  .sign         ; SF=1 (negative)
jns .not_sign     ; SF=0
jo  .overflow     ; OF=1
jno .not_overflow ; OF=0

; CALL / RET
call 0x401234     ; [rsp-8] = rip+5, rsp -= 8, jmp 0x401234
call rax          ; indirect call
ret               ; rip = [rsp], rsp += 8
ret 0x10          ; ret + stack cleanup (stdcall)

; LOOP
loop .label       ; rcx -= 1, jump if rcx != 0
```

### 2.4 Arithmetic/Logical Operations

```nasm
; Arithmetic
add rax, rbx      ; rax += rbx
sub rax, rbx      ; rax -= rbx
mul rbx           ; rdx:rax = rax * rbx (unsigned)
imul rax, rbx     ; rax = rax * rbx (signed)
imul rax, rbx, 5  ; rax = rbx * 5
div rbx           ; rax = rdx:rax / rbx, rdx = remainder (unsigned)
idiv rbx          ; signed division
inc rax           ; rax++
dec rax           ; rax--
neg rax           ; rax = -rax

; Logical
and rax, rbx      ; bitwise AND
or  rax, rbx      ; bitwise OR
xor rax, rax      ; rax = 0 (XOR with itself = register clear)
not rax           ; bitwise NOT
test rax, rax     ; AND operation (discard result, set ZF only)
cmp  rax, rbx     ; SUB operation (discard result, set flags only)

; Shifts
shl rax, 3        ; logical left shift (×8)
shr rax, 3        ; logical right shift (÷8)
sar rax, 3        ; arithmetic right shift (preserves sign)
rol rax, 1        ; rotate left
ror rax, 1        ; rotate right
```

### 2.5 String Instructions

```nasm
; Used with REP prefix
rep  movsb        ; repeat RCX times: [rdi] = [rsi], rsi++, rdi++
rep  stosd        ; repeat RCX times: [rdi] = eax, rdi += 4
repe cmpsb        ; repeat while ZF=1, compare bytes
repne scasb       ; repeat while ZF=0, scan for AL value
```

---

## 3. Stack Frame Structure

### 3.1 Stack Layout During Function Call (x64)

```
High address
┌─────────────────────┐
│   ...caller frame..  │
├─────────────────────┤ ← caller's RBP (saved RBP)
│  Saved RBP           │ ← current RBP
├─────────────────────┤
│  Local variable 1    │ ← [rbp - 8]
├─────────────────────┤
│  Local variable 2    │ ← [rbp - 16]
├─────────────────────┤
│  ...                 │
├─────────────────────┤ ← RSP (top of stack)
Low address
```

### 3.2 Function Prologue/Epilogue

```nasm
; Prologue — function entry
push rbp          ; save previous base pointer
mov  rbp, rsp     ; set current stack as new frame base
sub  rsp, 0x30    ; allocate local variable space (16-byte alignment required)

; Epilogue — function exit
mov  rsp, rbp     ; restore stack (or use leave instruction)
pop  rbp          ; restore previous base pointer
ret               ; return

; LEAVE instruction = mov rsp, rbp + pop rbp
leave
ret
```

### 3.3 Stack Alignment Requirements

- **x64**: RSP must be **16-byte aligned** immediately before a CALL
- CALL pushes 8 bytes (RIP) → prologue pushes RBP (8 bytes) → maintains 16-byte total

---

## 4. Calling Conventions

### 4.1 cdecl (x86 32bit)

```
Arguments: pushed to stack right-to-left
Return:    EAX (64bit values in EDX:EAX)
Cleanup:   caller responsible
Preserved: EBX, ESI, EDI, EBP
```

```nasm
; cdecl example: add(1, 2)
push 2            ; second argument
push 1            ; first argument
call add_func
add  esp, 8       ; caller cleans stack (2 args × 4 bytes)
; result in EAX
```

### 4.2 stdcall (x86 32bit, Windows API)

```
Arguments: pushed to stack right-to-left
Return:    EAX
Cleanup:   callee cleans stack with RET n
Preserved: EBX, ESI, EDI, EBP
```

```nasm
; stdcall function return
ret 8             ; clean 8 bytes (2 args) from stack then return
```

### 4.3 fastcall (x86 32bit, MSVC)

```
Arguments: ECX (1st), EDX (2nd), rest on stack
Return:    EAX
Cleanup:   callee
```

### 4.4 System V AMD64 ABI (Linux/macOS x64)

```
Integer/pointer args: RDI, RSI, RDX, RCX, R8, R9 (in order)
Floating-point args:  XMM0~XMM7
Additional args:      stack (left to right)
Return:               RAX (integer/pointer), XMM0 (float)
64bit return:         RAX:RDX
Cleanup:              caller
Callee-saved:         RBX, RBP, R12~R15
Caller-saved:         RAX, RCX, RDX, RSI, RDI, R8~R11, XMM0~XMM15
```

```nasm
; System V AMD64 example: write(1, buf, len)
mov rax, 1        ; syscall number (write)
mov rdi, 1        ; fd = stdout
lea rsi, [buf]    ; buf address
mov rdx, 13       ; length
syscall
```

### 4.5 Windows x64 ABI

```
Integer/pointer args: RCX, RDX, R8, R9 (in order)
Floating-point args:  XMM0~XMM3 (also fills corresponding integer slots)
Additional args:      stack (32-byte shadow space required)
Return:               RAX
Callee-saved:         RBX, RBP, RDI, RSI, R12~R15, XMM6~XMM15
```

---

## 5. GDB Practical Commands

### 5.1 Getting Started

```bash
gdb ./binary                    # load binary
gdb -p 1234                     # attach to running process
gdb --args ./binary arg1 arg2   # start with arguments

# Useful .gdbinit settings
set disassembly-flavor intel    # change from AT&T to Intel syntax
set pagination off
set print pretty on
```

### 5.2 Execution Control

```gdb
run                     # run (r)
run arg1 arg2           # run with arguments
continue                # continue execution (c)
next                    # next line (skip over function calls) (n)
nexti                   # next single instruction (ni)
step                    # next line (step into function calls) (s)
stepi                   # step single instruction (si)
finish                  # run until end of current function (fin)
until 0x401234          # run until that address
```

### 5.3 Breakpoints

```gdb
break main              # breakpoint at function name
break *0x401234         # breakpoint at address
break main+10           # breakpoint at offset
info breakpoints        # list breakpoints (i b)
delete 1                # delete breakpoint #1
disable 2               # disable breakpoint
enable 2                # enable breakpoint
condition 1 rax==0      # conditional breakpoint
watch *0x601060         # memory write watchpoint
rwatch *0x601060        # memory read watchpoint
```

### 5.4 Examining Registers

```gdb
info registers          # print all registers (i r)
info registers rax rbx  # specific registers only
print $rax              # print RAX value
print/x $rax            # print in hexadecimal
print/d $rax            # print in decimal
set $rax = 0x1234       # modify register value

# View register state at a glance
layout regs             # show register window in TUI mode
```

### 5.5 Memory Examination (examine)

```gdb
# x/[count][format][size] address
x/10gx $rsp             # 10 64bit(g) values from RSP in hex(x)
x/20wx 0x601000         # 20 32bit(w) values
x/s 0x401234            # print as string
x/i $rip                # disassemble current instruction
x/20i main              # 20 instructions from main
x/b $rax                # byte-by-byte

# sizes: b=1byte, h=2byte, w=4byte, g=8byte
# formats: x=hex, d=dec, u=udec, o=oct, t=bin, a=addr, s=str, i=inst
```

### 5.6 Stack Analysis

```gdb
info frame              # current stack frame info
backtrace               # print call stack (bt)
backtrace full          # call stack with local variables
frame 2                 # switch to frame #2
info locals             # local variables in current frame
info args               # current function arguments

x/20gx $rsp             # inspect stack contents directly
```

### 5.7 Disassembly

```gdb
disassemble main        # disassemble main function (disas)
disassemble 0x401000,0x401050  # address range
disassemble /r main     # include byte codes
set disassembly-flavor intel   # Intel syntax
```

---

## 6. NASM Assembly Examples

### 6.1 Hello World (64bit Linux)

```nasm
; hello.asm — 64bit Linux
; Build: nasm -f elf64 hello.asm -o hello.o && ld hello.o -o hello

section .data
    msg db "Hello, World!", 0x0a
    msglen equ $ - msg

section .text
    global _start

_start:
    ; write(1, msg, msglen)
    mov rax, 1          ; sys_write
    mov rdi, 1          ; fd = stdout
    lea rsi, [rel msg]  ; message address
    mov rdx, msglen     ; length
    syscall

    ; exit(0)
    mov rax, 60         ; sys_exit
    xor rdi, rdi        ; exit code = 0
    syscall
```

```bash
nasm -f elf64 hello.asm -o hello.o
ld hello.o -o hello
./hello
```

### 6.2 Function Call Example (System V AMD64 ABI)

```nasm
; func_example.asm — calling convention demo
; Build: nasm -f elf64 func_example.asm -o func_example.o
;        gcc -no-pie func_example.o -o func_example

section .data
    fmt db "%d", 0x0a, 0

section .text
    global main
    extern printf

; int add(int a, int b) — returns sum of two numbers
add_func:
    push rbp
    mov  rbp, rsp
    ; args: rdi=a, rsi=b
    mov  rax, rdi
    add  rax, rsi
    pop  rbp
    ret

; int factorial(int n)
factorial:
    push rbp
    mov  rbp, rsp

    cmp  rdi, 1
    jle  .base_case

    push rdi            ; save n
    dec  rdi
    call factorial      ; factorial(n-1)
    pop  rdi
    imul rax, rdi       ; n * factorial(n-1)
    jmp  .done

.base_case:
    mov rax, 1

.done:
    pop rbp
    ret

main:
    push rbp
    mov  rbp, rsp
    sub  rsp, 0x20      ; maintain 16-byte alignment (shadow space)

    ; call add(3, 7)
    mov rdi, 3
    mov rsi, 7
    call add_func
    ; result: rax = 10

    ; printf("%d\n", result)
    lea rdi, [rel fmt]
    mov rsi, rax
    xor eax, eax        ; no floating-point args
    call printf

    ; call factorial(10)
    mov rdi, 10
    call factorial

    lea rdi, [rel fmt]
    mov rsi, rax
    xor eax, eax
    call printf

    xor eax, eax
    leave
    ret
```

### 6.3 Loop and String Processing Example

```nasm
; loop_str.asm — compute string length
section .text
    global strlen_asm

; size_t strlen_asm(const char *s)
; argument: rdi = string pointer
strlen_asm:
    push rbp
    mov  rbp, rsp

    xor  rcx, rcx       ; counter = 0
.loop:
    cmp  BYTE PTR [rdi + rcx], 0   ; null check
    je   .done
    inc  rcx
    jmp  .loop
.done:
    mov  rax, rcx       ; return length
    pop  rbp
    ret

; Same functionality using REPNE SCASB
strlen_asm2:
    push rbp
    mov  rbp, rsp

    mov  rdi, rdi       ; string pointer (already in rdi)
    xor  al,  al        ; value to find = 0 (null)
    mov  rcx, -1        ; maximum scan count
    repne scasb         ; compare [rdi] with al, if mismatch rdi++, rcx--
    not  rcx            ; ~(-match_pos - 2) = length
    dec  rcx            ; exclude null byte
    mov  rax, rcx

    pop  rbp
    ret
```

---

## 7. Common Patterns Reference

### 7.1 Register Zeroing

```nasm
xor rax, rax        ; rax = 0 (shorter than mov rax, 0)
xor eax, eax        ; zero out entire RAX (upper 32bit auto-cleared)
```

### 7.2 Stack Alignment

```nasm
; Ensure RSP is 16-byte aligned before function calls
and rsp, ~0xf       ; clear lower 4 bits (force alignment)
```

### 7.3 NOP Sled

```nasm
nop                 ; 0x90, does nothing
nop DWORD PTR [rax] ; multi-byte NOP
```

### 7.4 Linux x64 Syscall Number Reference

| syscall | Number (RAX) | Arguments |
|---------|-------------|-----------|
| read    | 0           | rdi=fd, rsi=buf, rdx=count |
| write   | 1           | rdi=fd, rsi=buf, rdx=count |
| open    | 2           | rdi=path, rsi=flags, rdx=mode |
| close   | 3           | rdi=fd |
| execve  | 59          | rdi=path, rsi=argv, rdx=envp |
| exit    | 60          | rdi=code |
| mmap    | 9           | rdi=addr, rsi=len, rdx=prot, r10=flags, r8=fd, r9=off |

<!-- detect-validate-19 -->
## Exploit Mitigation Validation (Binary Level)

Assembly-level understanding is the ability to confirm *whether exploit mitigations are actually present in the binary*. Attacks target the stack, registers, and return flow. Defenders must verify **whether NX, canary, PIE, and RELRO actually made it into the compiled artifact**. Validate only on **owned binaries**.

### Attack -> Targeted weakness -> Primary control (defender) -> Validation signal

| Technique | Targeted weakness | Primary control (defender) | Validation signal |
|---|---|---|---|
| Return-address overwrite | No stack protection | Stack canary | No "Canary found" in checksec |
| Direct shellcode execution | Executable stack | NX/DEP | "NX disabled" / GNU_STACK RWE |
| Fixed-address gadgets | Non-PIE loading | PIE/ASLR | checksec "No PIE" |
| GOT overwrite | Writable GOT | Full RELRO | "Partial/No RELRO" |

### Defense validation (verify directly)

```bash
# 1) Confirm exploit mitigations are actually present in the binary — build flags != artifact
checksec --file=./target 2>/dev/null || readelf -lW ./target | grep -E "GNU_STACK|GNU_RELRO"
#   RWE GNU_STACK means NX is absent -> stack-shellcode surface
# 2) Confirm system ASLR is enabled (mitigation reproducibility)
cat /proc/sys/kernel/randomize_va_space   # 2 = full ASLR
```

> Exploit defense starts with *whether the mitigation is truly baked into the binary* -- "we passed hardening flags" differs from "NX, canary, and PIE are in the artifact". Confirm directly with checksec/readelf on owned binaries ([[09_Exploit_Techniques]], [[03_System_Hacking]], [[65_Reverse_Engineering_Advanced]]).
