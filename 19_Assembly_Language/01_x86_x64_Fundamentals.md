# x86/x64 어셈블리 기초

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

```gdb
disassemble main        # main 함수 디스어셈블 (disas)
disassemble 0x401000,0x401050  # 주소 범위
disassemble /r main     # 바이트 코드 포함
set disassembly-flavor intel   # Intel 문법
```

---

## 6. NASM 어셈블리 예제

### 6.1 Hello World (64bit Linux)

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

```nasm
xor rax, rax        ; rax = 0 (mov rax, 0보다 짧음)
xor eax, eax        ; RAX 전체를 0으로 (상위 32bit 자동 클리어)
```

### 7.2 스택 정렬 맞추기

```nasm
; 함수 호출 전 RSP가 16바이트 정렬인지 확인
and rsp, ~0xf       ; 하위 4비트 클리어 (정렬 강제)
```

### 7.3 NOP sled

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
