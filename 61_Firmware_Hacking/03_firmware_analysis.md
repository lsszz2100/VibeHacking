# 펌웨어 정적 분석

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

    # 위험 함수 없는 보호 미적용 바이너리 우선 출력
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
