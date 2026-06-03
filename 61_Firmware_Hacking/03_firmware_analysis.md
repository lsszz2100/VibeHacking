> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 펌웨어 정적 분석

## 0. 초보자를 위한 개념 이해

### 펌웨어 정적 분석이란?

**정적 분석(Static Analysis)**은 코드를 **실행하지 않고** 소스코드나 바이너리를 직접 검사해 취약점을 찾는 방법입니다.

```
동적 분석 vs 정적 분석:

동적 분석:                    정적 분석:
  실행 → 관찰                  코드 자체 검사
  장점: 실제 동작 확인          장점: 실행 없이 분석
  단점: 실행 환경 필요           단점: 실행 경로 100% 파악 어려움
  예시: 에뮬레이터에서 실행      예시: 바이너리/소스코드 검사
```

**펌웨어 정적 분석 흐름:**
```
펌웨어 추출
    ↓
파일시스템 마운트 (squashfs, jffs2 등)
    ↓
파일 탐색 (설정 파일, 스크립트, 바이너리)
    ↓                    ↓
자격증명/시크릿 검색    바이너리 역공학 (strings, Ghidra, IDA)
    ↓                    ↓
취약한 패턴 탐지 (인젝션, 버퍼오버플로)
    ↓
결과 정리 및 검증
```

### 무엇을 찾나?

| 취약점 유형 | 예시 | 왜 위험한가 |
|------------|------|------------|
| 하드코딩된 자격증명 | `admin:admin123` 또는 SSH 개인키 | 전체 장비 접근 가능 |
| 백도어 계정 | `backdoor:$1$...` 숨겨진 사용자 | 제조사가 비밀리에 접근 가능 |
| 커맨드 인젝션 | `system(user_input)` 패턴 | OS 명령 실행 |
| 버퍼 오버플로 | `strcpy(buf, user_input)` | 코드 실행 |
| 하드코딩된 API 키 | `API_KEY="sk-..."` | 서비스 계정 탈취 |
| 비밀 엔드포인트 | `/cgi-bin/debug.cgi` | 숨겨진 관리 기능 |

---

## 분석 목표

추출된 펌웨어에서 다음을 찾는다:
- 하드코딩된 자격 증명 / 백도어
- 명령 인젝션에 취약한 함수 호출
- 버퍼 오버플로 취약점
- 인증 우회 로직
- 비밀 API 엔드포인트

## 파일시스템 탐색

```bash
# 추출 후 디렉토리 구조 파악
find squashfs-root/ -maxdepth 3 -type d | head -50
ls squashfs-root/etc/
ls squashfs-root/usr/sbin/

# 중요 파일 빠른 목록
find squashfs-root/ \( \
    -name "*.conf" -o -name "*.cfg" -o \
    -name "passwd"  -o -name "shadow" -o \
    -name "*.sh"    -o -name "*.cgi"  \
\) 2>/dev/null

# SUID/SGID 파일 (권한 상승 경로)
find squashfs-root/ -perm /6000 -type f 2>/dev/null

# 심볼릭 링크
find squashfs-root/ -type l 2>/dev/null
```

## 자격 증명 수동 분석

```bash
# /etc/passwd 분석
cat squashfs-root/etc/passwd
# root:x:0:0:root:/root:/bin/bash  → 정상
# admin:$1$xyz...:0:0::/:/bin/sh   → MD5 해시, 크래킹 시도

# /etc/shadow 존재 시
john --wordlist=/usr/share/wordlists/rockyou.txt shadow

# 웹 자격 증명
cat squashfs-root/etc/htpasswd
cat squashfs-root/etc/lighttpd.user

# nvram/설정 파일에서 자격 증명
grep -r "password\|passwd\|secret\|api_key\|token" \
     squashfs-root/etc/ 2>/dev/null --include="*.conf" --include="*.cfg"

# 바이너리에서 하드코딩된 문자열
strings squashfs-root/usr/sbin/httpd | grep -i "admin\|password\|backdoor"
```

## CGI/웹 스크립트 분석

```bash
# CGI 스크립트 찾기
find squashfs-root/ -name "*.cgi" -o -path "*/cgi-bin/*" 2>/dev/null

# 명령 인젝션 패턴 검색
grep -r "system\|popen\|exec\|passthru\|shell_exec" \
     squashfs-root/www/ 2>/dev/null

# 입력 필터링 부재 체크 (쉘 스크립트 CGI)
grep -l "QUERY_STRING\|HTTP_" squashfs-root/www/ 2>/dev/null | head -10

# 예시: 취약한 패턴
# ping.cgi: system("ping -c 4 " . $_GET['ip']);
# → ip=127.0.0.1; cat /etc/passwd 로 인젝션 가능
```

## 바이너리 분석 (Ghidra/Radare2)

### Ghidra 사용법
```bash
# Ghidra 실행 (GUI)
ghidra

# 스크립트 기반 자동 분석
analyzeHeadless /tmp/ghidra_project MyProject \
    -import squashfs-root/usr/sbin/httpd \
    -postScript FindStrings.java
```

### Radare2 사용법
```bash
# 기본 분석
r2 squashfs-root/usr/sbin/httpd
[0x...]> aaaa        # 전체 분석
[0x...]> iz          # 문자열 목록
[0x...]> afl         # 함수 목록
[0x...]> s main      # main으로 이동
[0x...]> pdf         # 함수 디스어셈블

# 위험 함수 참조 찾기
[0x...]> axt sym.imp.system   # system() 호출 위치
[0x...]> axt sym.imp.strcpy   # strcpy() 호출 위치
[0x...]> axt sym.imp.gets     # gets() 호출 위치
```

### 자동 바이너리 분석
```python
#!/usr/bin/env python3
"""임베디드 바이너리 취약점 정적 분석 도구."""

import argparse
import subprocess
import sys
from pathlib import Path
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, as_completed


DANGEROUS_FUNCTIONS = {
    "strcpy": "버퍼 오버플로 (길이 미체크)",
    "strcat": "버퍼 오버플로 (길이 미체크)",
    "gets": "버퍼 오버플로 (사용 금지)",
    "sprintf": "포맷 스트링/버퍼 오버플로",
    "vsprintf": "포맷 스트링/버퍼 오버플로",
    "system": "명령 인젝션",
    "popen": "명령 인젝션",
    "execl": "명령 인젝션",
    "execv": "명령 인젝션",
    "scanf": "버퍼 오버플로",
}

INTERESTING_STRINGS = [
    "password", "passwd", "secret", "backdoor",
    "admin", "debug", "telnet", "ssh", "ftp",
    "/bin/sh", "/bin/bash", "eval", "system",
    "192.168.", "10.0.", "172.16.",
]


@dataclass
class BinaryFinding:
    path: str
    arch: str
    dangerous_funcs: dict[str, str] = field(default_factory=dict)
    interesting_strings: list[str] = field(default_factory=list)
    has_nx: bool = False
    has_canary: bool = False
    has_pie: bool = False


def detect_arch(binary: Path) -> str:
    result = subprocess.run(
        ["file", "-b", str(binary)], capture_output=True, text=True
    )
    output = result.stdout
    if "ARM" in output:
        return "ARM" + (" 64" if "aarch64" in output else " 32")
    if "MIPS" in output:
        return "MIPS" + (" 64" if "64-bit" in output else " 32")
    if "x86-64" in output or "x86_64" in output:
        return "x86_64"
    if "80386" in output or "x86" in output:
        return "x86"
    return "Unknown"


def check_protections(binary: Path) -> dict[str, bool]:
    result = subprocess.run(
        ["readelf", "-d", str(binary)], capture_output=True, text=True
    )
    checksec = {"nx": False, "canary": False, "pie": False}

    result2 = subprocess.run(
        ["checksec", "--file", str(binary)], capture_output=True, text=True
    )
    out = result2.stdout.lower()
    checksec["nx"] = "nx enabled" in out
    checksec["canary"] = "canary found" in out
    checksec["pie"] = "pie enabled" in out
    return checksec


def find_dangerous_imports(binary: Path) -> dict[str, str]:
    result = subprocess.run(
        ["nm", "-D", str(binary)], capture_output=True, text=True
    )
    found = {}
    for line in result.stdout.splitlines():
        for func, desc in DANGEROUS_FUNCTIONS.items():
            if f" U {func}@@" in line or f" U {func}\n" in line or line.endswith(f" {func}"):
                found[func] = desc
    return found


def find_interesting_strings(binary: Path) -> list[str]:
    result = subprocess.run(
        ["strings", "-n", "6", str(binary)], capture_output=True, text=True
    )
    return [
        s for s in result.stdout.splitlines()
        if any(kw in s.lower() for kw in INTERESTING_STRINGS)
    ][:30]


def analyze_binary(binary: Path) -> BinaryFinding:
    arch = detect_arch(binary)
    protections = check_protections(binary)
    dangerous = find_dangerous_imports(binary)
    strings = find_interesting_strings(binary)

    return BinaryFinding(
        path=str(binary),
        arch=arch,
        dangerous_funcs=dangerous,
        interesting_strings=strings,
        has_nx=protections["nx"],
        has_canary=protections["canary"],
        has_pie=protections["pie"],
    )


def scan_directory(root: Path, max_files: int = 200) -> list[BinaryFinding]:
    binaries = [
        p for p in root.rglob("*")
        if p.is_file() and not p.suffix
        and p.stat().st_size > 500
    ][:max_files]

    findings: list[BinaryFinding] = []
    with ThreadPoolExecutor(max_workers=6) as ex:
        futures = {ex.submit(analyze_binary, b): b for b in binaries}
        for i, fut in enumerate(as_completed(futures), 1):
            try:
                finding = fut.result()
                if finding.dangerous_funcs or finding.interesting_strings:
                    findings.append(finding)
            except Exception:
                pass
            if i % 20 == 0:
                print(f"    진행: {i}/{len(binaries)}", end="\r")
    return findings


def print_report(findings: list[BinaryFinding]) -> None:
    print(f"\n{'='*70}")
    print(f"분석 결과: {len(findings)}개 바이너리에서 발견")
    print(f"{'='*70}")

    high_risk = [
        f for f in findings
        if f.dangerous_funcs and not (f.has_nx and f.has_canary)
    ]
    print(f"\n[!] 고위험 바이너리 ({len(high_risk)}개) — 보호 없음 + 위험 함수:")
    for f in high_risk[:15]:
        print(f"\n  파일: {f.path}")
        print(f"  아키: {f.arch} | NX:{f.has_nx} | 카나리:{f.has_canary} | PIE:{f.has_pie}")
        print(f"  위험 함수: {', '.join(f.dangerous_funcs.keys())}")
        if f.interesting_strings:
            print(f"  주목 문자열: {f.interesting_strings[0]}")


def main() -> None:
    parser = argparse.ArgumentParser(description="임베디드 바이너리 정적 분석")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-f", "--file", type=Path, help="단일 바이너리")
    group.add_argument("-d", "--dir", type=Path, help="디렉토리 일괄 스캔")
    parser.add_argument("--max", type=int, default=200, help="최대 분석 파일 수")
    args = parser.parse_args()

    if args.file:
        if not args.file.exists():
            print(f"[!] 파일 없음: {args.file}", file=sys.stderr)
            sys.exit(1)
        finding = analyze_binary(args.file)
        print_report([finding])
    else:
        if not args.dir.exists():
            print(f"[!] 디렉토리 없음: {args.dir}", file=sys.stderr)
            sys.exit(1)
        print(f"[*] 스캔 중: {args.dir} (최대 {args.max}개)")
        findings = scan_directory(args.dir, args.max)
        print_report(findings)


if __name__ == "__main__":
    main()
```

## 네트워크 서비스 분석

```bash
# 바이너리에서 열린 포트 탐지
strings squashfs-root/usr/sbin/httpd | grep -E ":[0-9]{2,5}"

# 시작 스크립트 분석
grep -r "listen\|port\|bind\|socket" squashfs-root/etc/init.d/ 2>/dev/null

# Telnet 데몬 찾기 (명시적 취약점)
find squashfs-root/ -name "telnetd" -o -name "busybox" | xargs strings | grep -i telnet

# 웹서버 설정
cat squashfs-root/etc/lighttpd.conf 2>/dev/null
cat squashfs-root/etc/httpd.conf 2>/dev/null
```

## 인증 우회 패턴

```bash
# 공통 인증 우회 패턴 검색
grep -r "strcmp.*admin\|strcmp.*password" squashfs-root/ 2>/dev/null
grep -r "if.*0.*==\|if.*auth" squashfs-root/www/ 2>/dev/null

# 매직 패킷/토큰
strings squashfs-root/usr/sbin/* | grep -E "[A-Za-z0-9+/]{20,}={0,2}"

# 디버그 백도어
grep -r "BACKDOOR\|DEBUG_MODE\|FACTORY_MODE" squashfs-root/ 2>/dev/null
```

다음 파일에서 QEMU를 활용한 펌웨어 에뮬레이션 기법을 다룬다.

---

<a name="english"></a>

# Firmware Static Analysis

## Analysis Goals

Search for the following in extracted firmware:
- Hardcoded credentials / backdoors
- Function calls vulnerable to command injection
- Buffer overflow vulnerabilities
- Authentication bypass logic
- Secret API endpoints

## Filesystem Exploration

```bash
# Understand directory structure after extraction
find squashfs-root/ -maxdepth 3 -type d | head -50
ls squashfs-root/etc/
ls squashfs-root/usr/sbin/

# Quick list of important files
find squashfs-root/ \( \
    -name "*.conf" -o -name "*.cfg" -o \
    -name "passwd"  -o -name "shadow" -o \
    -name "*.sh"    -o -name "*.cgi"  \
\) 2>/dev/null

# SUID/SGID files (privilege escalation paths)
find squashfs-root/ -perm /6000 -type f 2>/dev/null

# Symbolic links
find squashfs-root/ -type l 2>/dev/null
```

## Manual Credential Analysis

```bash
# Analyze /etc/passwd
cat squashfs-root/etc/passwd
# root:x:0:0:root:/root:/bin/bash  → normal
# admin:$1$xyz...:0:0::/:/bin/sh   → MD5 hash, attempt cracking

# If /etc/shadow exists
john --wordlist=/usr/share/wordlists/rockyou.txt shadow

# Web credentials
cat squashfs-root/etc/htpasswd
cat squashfs-root/etc/lighttpd.user

# Credentials in nvram/config files
grep -r "password\|passwd\|secret\|api_key\|token" \
     squashfs-root/etc/ 2>/dev/null --include="*.conf" --include="*.cfg"

# Hardcoded strings in binaries
strings squashfs-root/usr/sbin/httpd | grep -i "admin\|password\|backdoor"
```

## CGI/Web Script Analysis

```bash
# Find CGI scripts
find squashfs-root/ -name "*.cgi" -o -path "*/cgi-bin/*" 2>/dev/null

# Search for command injection patterns
grep -r "system\|popen\|exec\|passthru\|shell_exec" \
     squashfs-root/www/ 2>/dev/null

# Check for missing input filtering (shell script CGI)
grep -l "QUERY_STRING\|HTTP_" squashfs-root/www/ 2>/dev/null | head -10

# Example: vulnerable pattern
# ping.cgi: system("ping -c 4 " . $_GET['ip']);
# → Injection possible with ip=127.0.0.1; cat /etc/passwd
```

## Binary Analysis (Ghidra/Radare2)

### Ghidra Usage
```bash
# Run Ghidra (GUI)
ghidra

# Script-based automated analysis
analyzeHeadless /tmp/ghidra_project MyProject \
    -import squashfs-root/usr/sbin/httpd \
    -postScript FindStrings.java
```

### Radare2 Usage
```bash
# Basic analysis
r2 squashfs-root/usr/sbin/httpd
[0x...]> aaaa        # Full analysis
[0x...]> iz          # String list
[0x...]> afl         # Function list
[0x...]> s main      # Jump to main
[0x...]> pdf         # Disassemble function

# Find dangerous function references
[0x...]> axt sym.imp.system   # Locations calling system()
[0x...]> axt sym.imp.strcpy   # Locations calling strcpy()
[0x...]> axt sym.imp.gets     # Locations calling gets()
```

### Automated Binary Analysis
```python
#!/usr/bin/env python3
"""Embedded binary vulnerability static analysis tool."""

import argparse
import subprocess
import sys
from pathlib import Path
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, as_completed


DANGEROUS_FUNCTIONS = {
    "strcpy": "Buffer overflow (no length check)",
    "strcat": "Buffer overflow (no length check)",
    "gets": "Buffer overflow (prohibited function)",
    "sprintf": "Format string/buffer overflow",
    "vsprintf": "Format string/buffer overflow",
    "system": "Command injection",
    "popen": "Command injection",
    "execl": "Command injection",
    "execv": "Command injection",
    "scanf": "Buffer overflow",
}

INTERESTING_STRINGS = [
    "password", "passwd", "secret", "backdoor",
    "admin", "debug", "telnet", "ssh", "ftp",
    "/bin/sh", "/bin/bash", "eval", "system",
    "192.168.", "10.0.", "172.16.",
]


@dataclass
class BinaryFinding:
    path: str
    arch: str
    dangerous_funcs: dict[str, str] = field(default_factory=dict)
    interesting_strings: list[str] = field(default_factory=list)
    has_nx: bool = False
    has_canary: bool = False
    has_pie: bool = False


def detect_arch(binary: Path) -> str:
    result = subprocess.run(["file", "-b", str(binary)], capture_output=True, text=True)
    output = result.stdout
    if "ARM" in output:
        return "ARM" + (" 64" if "aarch64" in output else " 32")
    if "MIPS" in output:
        return "MIPS" + (" 64" if "64-bit" in output else " 32")
    if "x86-64" in output or "x86_64" in output:
        return "x86_64"
    if "80386" in output or "x86" in output:
        return "x86"
    return "Unknown"


def check_protections(binary: Path) -> dict[str, bool]:
    checksec = {"nx": False, "canary": False, "pie": False}
    result2 = subprocess.run(["checksec", "--file", str(binary)], capture_output=True, text=True)
    out = result2.stdout.lower()
    checksec["nx"] = "nx enabled" in out
    checksec["canary"] = "canary found" in out
    checksec["pie"] = "pie enabled" in out
    return checksec


def find_dangerous_imports(binary: Path) -> dict[str, str]:
    result = subprocess.run(["nm", "-D", str(binary)], capture_output=True, text=True)
    found = {}
    for line in result.stdout.splitlines():
        for func, desc in DANGEROUS_FUNCTIONS.items():
            if f" U {func}@@" in line or f" U {func}\n" in line or line.endswith(f" {func}"):
                found[func] = desc
    return found


def find_interesting_strings(binary: Path) -> list[str]:
    result = subprocess.run(["strings", "-n", "6", str(binary)], capture_output=True, text=True)
    return [
        s for s in result.stdout.splitlines()
        if any(kw in s.lower() for kw in INTERESTING_STRINGS)
    ][:30]


def analyze_binary(binary: Path) -> BinaryFinding:
    arch = detect_arch(binary)
    protections = check_protections(binary)
    dangerous = find_dangerous_imports(binary)
    strings = find_interesting_strings(binary)
    return BinaryFinding(
        path=str(binary), arch=arch,
        dangerous_funcs=dangerous, interesting_strings=strings,
        has_nx=protections["nx"], has_canary=protections["canary"],
        has_pie=protections["pie"],
    )


def scan_directory(root: Path, max_files: int = 200) -> list[BinaryFinding]:
    binaries = [
        p for p in root.rglob("*")
        if p.is_file() and not p.suffix and p.stat().st_size > 500
    ][:max_files]

    findings: list[BinaryFinding] = []
    with ThreadPoolExecutor(max_workers=6) as ex:
        futures = {ex.submit(analyze_binary, b): b for b in binaries}
        for i, fut in enumerate(as_completed(futures), 1):
            try:
                finding = fut.result()
                if finding.dangerous_funcs or finding.interesting_strings:
                    findings.append(finding)
            except Exception:
                pass
            if i % 20 == 0:
                print(f"    Progress: {i}/{len(binaries)}", end="\r")
    return findings


def print_report(findings: list[BinaryFinding]) -> None:
    print(f"\n{'='*70}")
    print(f"Analysis results: found in {len(findings)} binary/binaries")
    print(f"{'='*70}")

    high_risk = [f for f in findings if f.dangerous_funcs and not (f.has_nx and f.has_canary)]
    print(f"\n[!] High-risk binaries ({len(high_risk)}) — no protections + dangerous functions:")
    for f in high_risk[:15]:
        print(f"\n  File: {f.path}")
        print(f"  Arch: {f.arch} | NX:{f.has_nx} | Canary:{f.has_canary} | PIE:{f.has_pie}")
        print(f"  Dangerous functions: {', '.join(f.dangerous_funcs.keys())}")
        if f.interesting_strings:
            print(f"  Notable string: {f.interesting_strings[0]}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Embedded binary static analysis")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-f", "--file", type=Path, help="Single binary")
    group.add_argument("-d", "--dir", type=Path, help="Directory batch scan")
    parser.add_argument("--max", type=int, default=200, help="Max files to analyze")
    args = parser.parse_args()

    if args.file:
        if not args.file.exists():
            print(f"[!] File not found: {args.file}", file=sys.stderr)
            sys.exit(1)
        finding = analyze_binary(args.file)
        print_report([finding])
    else:
        if not args.dir.exists():
            print(f"[!] Directory not found: {args.dir}", file=sys.stderr)
            sys.exit(1)
        print(f"[*] Scanning: {args.dir} (max {args.max} files)")
        findings = scan_directory(args.dir, args.max)
        print_report(findings)


if __name__ == "__main__":
    main()
```

## Network Service Analysis

```bash
# Detect open ports from binary
strings squashfs-root/usr/sbin/httpd | grep -E ":[0-9]{2,5}"

# Analyze startup scripts
grep -r "listen\|port\|bind\|socket" squashfs-root/etc/init.d/ 2>/dev/null

# Find Telnet daemon (explicit vulnerability)
find squashfs-root/ -name "telnetd" -o -name "busybox" | xargs strings | grep -i telnet

# Web server configuration
cat squashfs-root/etc/lighttpd.conf 2>/dev/null
cat squashfs-root/etc/httpd.conf 2>/dev/null
```

## Authentication Bypass Patterns

```bash
# Search for common authentication bypass patterns
grep -r "strcmp.*admin\|strcmp.*password" squashfs-root/ 2>/dev/null
grep -r "if.*0.*==\|if.*auth" squashfs-root/www/ 2>/dev/null

# Magic packets/tokens
strings squashfs-root/usr/sbin/* | grep -E "[A-Za-z0-9+/]{20,}={0,2}"

# Debug backdoors
grep -r "BACKDOOR\|DEBUG_MODE\|FACTORY_MODE" squashfs-root/ 2>/dev/null
```

The next file covers firmware emulation techniques using QEMU.
