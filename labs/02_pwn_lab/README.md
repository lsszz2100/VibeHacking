# 바이너리 익스플로잇 랩 (02_pwn_lab)

이 랩은 x86/x64 바이너리 익스플로잇의 핵심 기법을 단계별로 학습하기 위한 환경입니다.
Ubuntu 22.04 기반 서버에서 5개의 취약한 C 바이너리를 xinetd로 서비스하며,
pwntools와 GDB가 설치된 클라이언트 컨테이너에서 공격합니다.

---

## 서비스 구성

| 포트 | 챌린지 | 취약점 | 보호 기법 | 난이도 |
|------|--------|--------|-----------|--------|
| 10001 | chal01 | 스택 오버플로우 (BOF 기초) | 없음 (NX off) | ★☆☆ |
| 10002 | chal02 | ret2libc | NX on, ASLR off (setarch -R) | ★★☆ |
| 10003 | chal03 | ROP 체인 | NX on, Full RELRO, PIE off | ★★★ |
| 10004 | chal04 | 포맷 스트링 | NX on, PIE off | ★★☆ |
| 10005 | chal05 | 힙 익스플로잇 (tcache poisoning) | NX on, PIE off | ★★★★ |

---

## 빠른 시작

```bash
cd labs/02_pwn_lab
docker compose up -d

# pwntools 클라이언트 컨테이너에 접속
docker exec -it pwn_lab_client bash

# 챌린지 서버 연결 테스트
nc 172.17.0.10 10001
```

---

## 챌린지 상세 설명

### chal01 — BOF 기초 (NX 없음)
**포트**: 10001 | **바이너리**: 32비트 ELF | **보호**: 없음

**설명**:
`gets()` 함수로 인한 고전적인 스택 버퍼 오버플로우입니다.
스택이 실행 가능(NX off)하므로 셸코드를 직접 스택에 올려 실행할 수 있습니다.

**목표**: `win()` 함수 호출 또는 셸코드 실행으로 `flag01.txt` 읽기

**힌트**:
```python
# pwntools cyclic으로 오프셋 계산
from pwn import *
payload = cyclic(200)
# → 코어 덤프에서 EIP 값 확인: cyclic_find(core.eip)
```

**단계**:
1. `checksec` 명령으로 보호 기법 확인
2. `cyclic(200)` 전송 후 코어 덤프로 오프셋 파악
3. `win()` 주소로 리턴 주소 덮어쓰기
4. (심화) 셸코드 작성 후 스택에서 실행

---

### chal02 — ret2libc
**포트**: 10002 | **바이너리**: 64비트 ELF | **보호**: NX on, ASLR off (`setarch -R` 적용)

**설명**:
NX(No-eXecute)로 인해 스택에서 셸코드 직접 실행이 불가능합니다.
대신 `system("/bin/sh")`을 호출하도록 리턴 주소를 조작합니다.

**목표**: `system("/bin/sh")` 호출로 쉘 획득

**힌트**:
```bash
# libc에서 /bin/sh 문자열 주소 찾기
strings -a -t x /lib/x86_64-linux-gnu/libc.so.6 | grep "/bin/sh"

# pop rdi; ret 가젯 찾기
ROPgadget --binary /challenges/bin/chal02 | grep "pop rdi"
```

**단계**:
1. `read(0, buf, 512)` → 128바이트 버퍼 오버플로우 확인
2. `checksec`으로 NX on 확인
3. `pop rdi; ret` 가젯 주소 확인
4. 페이로드: `padding + pop_rdi + bin_sh_addr + system_addr`

---

### chal03 — ROP 체인
**포트**: 10003 | **바이너리**: 64비트 ELF | **보호**: NX on, Full RELRO, PIE off

**설명**:
바이너리 내 가젯을 체이닝하여 `execve("/bin/sh", NULL, NULL)` syscall을 호출합니다.
`/bin/sh` 문자열도 직접 바이너리에 없으므로 쓰기 가능한 영역을 활용해야 합니다.

**목표**: ROP 체인으로 `/bin/sh` 쉘 실행

**힌트**:
```bash
# ROPgadget으로 가젯 탐색
ROPgadget --binary /challenges/bin/chal03 --rop

# ropper 사용
ropper -f /challenges/bin/chal03

# 필요한 가젯:
# pop rax; ret   → rax = 59 (execve syscall 번호)
# pop rdi; ret   → rdi = "/bin/sh" 주소
# pop rsi; ret   → rsi = 0
# pop rdx; ret   → rdx = 0
# syscall; ret
```

**페이로드 구조**:
```
buf_pad + pop_rax + 59 + pop_rdi + bin_sh + pop_rsi + 0 + pop_rdx + 0 + syscall
```

---

### chal04 — 포맷 스트링
**포트**: 10004 | **바이너리**: 64비트 ELF | **보호**: NX on, PIE off

**설명**:
`printf(user_input)` 형태의 취약점입니다.
`%p`로 스택 값을 읽고, `%n`으로 임의 주소에 값을 씁니다.

**목표**: `printf` GOT를 `win()`으로 덮어씌워 `flag04.txt` 읽기

**힌트**:
```python
from pwn import *

# 스택 오프셋 찾기
# AAAA.%p.%p.%p... → 0x41414141이 나오는 위치
p.sendline(b"AAAA" + b".%p" * 20)

# pwntools fmtstr_payload 활용
payload = fmtstr_payload(offset, {printf_got: win_addr})
```

**1단계 — 스택 읽기**:
```
입력: %p %p %p %p %p
결과: 스택 값들이 16진수로 출력됨
```

**2단계 — 임의 주소 읽기**:
```
입력: \x10\x40\x40\x00\x00\x00\x00\x00%6$s
(주소 8바이트 + 해당 주소의 값을 문자열로 읽기)
```

**3단계 — 임의 주소 쓰기**:
```python
# fmtstr_payload가 자동으로 %n 기반 쓰기 페이로드 생성
```

---

### chal05 — 힙 익스플로잇 (tcache poisoning)
**포트**: 10005 | **바이너리**: 64비트 ELF | **보호**: NX on, PIE off

**설명**:
힙 관리 프로그램에 dangling pointer, double-free, 힙 오버플로우 취약점이 있습니다.
tcache bin의 fd 포인터를 오염시켜 임의 주소에 malloc()을 할당합니다.

**목표**: `win()` 함수 포인터를 임의 위치에 쓰거나 GOT 오버라이트

**힌트**:
```
1. malloc(64) × 2 → chunk A, chunk B
2. free(chunk A) → tcache에 들어감
3. chunk B를 오버플로우하여 chunk A의 fd(next) 포인터를 타겟 주소로 변조
4. malloc() → chunk A 반환
5. malloc() → 타겟 주소에 할당됨 → win() 주소 쓰기
```

```python
# tcache poisoning 개념
# free() 후 chunk->fd = &target
# 두 번째 malloc() 시 target 주소 반환
```

---

## 필수 도구 사용법

### checksec — 보호 기법 확인
```bash
checksec --file=/challenges/bin/chal01
# 출력 예:
# RELRO: No RELRO
# Stack: No canary found
# NX: NX disabled
# PIE: No PIE
```

### pwndbg / GDB 디버깅
```bash
gdb /challenges/bin/chal01

# pwndbg 명령어
(gdb) start
(gdb) cyclic 200
(gdb) run < <(python3 -c "from pwn import *; print(cyclic(200).decode())")
(gdb) info registers
(gdb) x/20wx $esp
(gdb) pattern search   # 오프셋 자동 계산
```

### pwntools 기본 사용법
```python
from pwn import *

# 원격 연결
p = remote("172.17.0.10", 10001)

# 로컬 프로세스
p = process("/challenges/bin/chal01")

# 데이터 송수신
p.sendline(b"hello")
data = p.recvuntil(b":")
p.recvline()

# 패킹/언패킹
addr = p64(0xdeadbeef)   # 8바이트 리틀엔디안
addr = p32(0xdeadbeef)   # 4바이트 리틀엔디안
val = u64(data[:8])

# 인터랙티브 쉘
p.interactive()
```

### ROPgadget 사용법
```bash
# 모든 가젯 출력
ROPgadget --binary chal03

# 특정 가젯 검색
ROPgadget --binary chal03 | grep "pop rdi"
ROPgadget --binary chal03 | grep "syscall"

# ROP 체인 자동 생성 시도
ROPgadget --binary chal03 --ropchain
```

---

## 트러블슈팅

```bash
# ASLR 비활성화 (컨테이너 내부에서)
echo 0 | tee /proc/sys/kernel/randomize_va_space

# 코어 덤프 활성화
ulimit -c unlimited
echo "/tmp/core.%e.%p" > /proc/sys/kernel/core_pattern

# 바이너리 아키텍처 확인
file /challenges/bin/chal01
# → ELF 32-bit LSB executable ...

# 라이브러리 버전 확인
ldd /challenges/bin/chal02
```
