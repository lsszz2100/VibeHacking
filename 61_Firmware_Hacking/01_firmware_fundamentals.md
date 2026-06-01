> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 펌웨어 해킹 기초

## 펌웨어란?

펌웨어(Firmware)는 하드웨어 장치를 제어하는 저수준 소프트웨어로, ROM/Flash 메모리에 저장된다. IoT 기기, 라우터, 임베디드 시스템, 산업 제어 장비 등 모든 임베디드 장치에 존재하며, 취약한 펌웨어는 전체 장치를 완전히 장악당할 수 있다.

## 펌웨어 유형

### 저장 매체별 분류
| 유형 | 특성 | 예시 |
|------|------|------|
| **NOR Flash** | 랜덤 읽기, 느린 쓰기/지우기 | 부트로더, BIOS |
| **NAND Flash** | 순차 읽기, 빠른 쓰기 | 파일시스템, 대용량 저장 |
| **eMMC** | NAND + 컨트롤러 통합 | 스마트폰, SBC |
| **EEPROM** | 소용량, 바이트 단위 수정 | 설정 저장, 시리얼 번호 |

### 아키텍처별 분류
```
x86/x64   — PC BIOS/UEFI, 산업용 PC
ARM       — 스마트폰, IoT, 라즈베리파이
MIPS      — 홈 라우터, 임베디드 네트워크 장비
PowerPC   — 자동차 ECU, 항공 시스템
RISC-V    — 신규 임베디드 플랫폼
```

## 파일시스템 구조

### 일반적인 펌웨어 레이아웃
```
+------------------+
| 부트로더         |  U-Boot, RedBoot, GRUB
+------------------+
| 커널 이미지      |  Linux zImage, uImage
+------------------+
| 파일시스템       |  SquashFS, JFFS2, YAFFS2
+------------------+
| 설정 파티션      |  NVRAM, 사용자 설정
+------------------+
```

### 일반 임베디드 파일시스템
```
SquashFS   — 읽기 전용, 압축, 가장 흔함
JFFS2      — 읽기/쓰기, NAND/NOR 최적화
UBIFS      — 대용량 NAND 최적화
CramFS     — 소형, 읽기 전용
ROMFS      — 매우 단순한 읽기 전용
ext2/4     — 일반적인 Linux 파일시스템
```

## 취약점 클래스

### 1. 하드코딩된 자격 증명
```bash
# 흔한 패턴
admin:admin, root:root, admin:password
admin:1234, user:user, guest:guest

# 펌웨어에서 검색
strings firmware.bin | grep -i "password\|passwd\|credential\|secret"
grep -r "admin" /extracted_fs/etc/
```

### 2. 디버그 인터페이스 노출
```
UART 콘솔 — 시리얼 디버그 포트, 종종 root 쉘 제공
JTAG      — 직접 메모리 접근, 디버깅
SSH/Telnet — 프로덕션에서 활성화된 채 방치
웹 디버그 — 숨겨진 관리 엔드포인트
```

### 3. 암호화되지 않은 업데이트
```
서명 없는 업데이트 → 악성 펌웨어 플래시 가능
암호화되지 않은 전송 → MITM 업데이트 인터셉트
롤백 보호 없음 → 구버전 취약 펌웨어로 다운그레이드
```

### 4. 취약한 웹 인터페이스
```
명령 인젝션 — 핑, 트레이스라우트, DNS 조회 필드
경로 순회 — 파일 다운로드 기능
인증 우회 — 숨겨진 관리 페이지
CSRF — 크로스 사이트 요청 위조
```

## 도구 체인

### 필수 도구
```bash
# 바이너리 분석
binwalk      — 펌웨어 추출/분석
file         — 파일 타입 탐지
strings      — 출력 가능한 문자열 추출
hexdump/xxd  — 16진수 덤프

# 디스어셈블리
radare2      — 멀티 아키텍처 리버싱
Ghidra       — NSA 무료 디컴파일러
IDA Pro      — 상업용 표준 도구

# 파일시스템
jefferson    — JFFS2 추출기
unsquashfs   — SquashFS 추출
mtd-utils    — MTD 디바이스 유틸리티
```

### 설치
```bash
# binwalk 설치 (추출 의존성 포함)
sudo apt install binwalk python3-pip
pip3 install binwalk

# 추가 추출 도구
sudo apt install squashfs-tools jefferson mtd-utils

# 에뮬레이션 도구
sudo apt install qemu-user-static qemu-system
```

## 기초 분석 워크플로우

```
1. 펌웨어 획득
   ├── 벤더 웹사이트에서 다운로드
   ├── 장치에서 직접 덤프 (UART/JTAG)
   └── 업데이트 메커니즘 인터셉트

2. 초기 정찰
   ├── file firmware.bin      → 포맷 식별
   ├── binwalk firmware.bin   → 내장 파일/시그니처
   └── strings firmware.bin   → 출력 가능한 문자열

3. 추출
   ├── binwalk -e firmware.bin
   ├── dd + 수동 오프셋 추출
   └── 커스텀 스크립트

4. 파일시스템 분석
   ├── 설정 파일 → 자격 증명, 엔드포인트
   ├── 바이너리 → 취약한 함수, 백도어
   └── 스크립트 → 시작 로직, 서비스

5. 동적 분석
   ├── QEMU 에뮬레이션
   ├── 실제 하드웨어 디버깅
   └── 네트워크 서비스 분석
```

## 펌웨어 정보 수집 CLI

```python
#!/usr/bin/env python3
"""펌웨어 초기 정찰 도구."""

import argparse
import subprocess
import hashlib
import sys
from pathlib import Path
from dataclasses import dataclass, field


@dataclass
class FirmwareInfo:
    path: Path
    size: int
    md5: str
    sha256: str
    file_type: str
    entropy: float
    strings_count: int
    interesting_strings: list[str] = field(default_factory=list)


INTERESTING_PATTERNS = [
    "password", "passwd", "secret", "token", "key",
    "admin", "root", "backdoor", "debug", "telnet",
    "ssh", "ftp", "http", "https", "192.168", "10.0.",
    "eval(", "system(", "exec(", "popen(",
]


def compute_hashes(path: Path) -> tuple[str, str]:
    data = path.read_bytes()
    return (
        hashlib.md5(data).hexdigest(),
        hashlib.sha256(data).hexdigest(),
    )


def get_file_type(path: Path) -> str:
    result = subprocess.run(
        ["file", "-b", str(path)],
        capture_output=True, text=True
    )
    return result.stdout.strip()


def compute_entropy(path: Path) -> float:
    import math
    data = path.read_bytes()
    if not data:
        return 0.0
    freq = [0] * 256
    for byte in data:
        freq[byte] += 1
    entropy = 0.0
    length = len(data)
    for count in freq:
        if count:
            p = count / length
            entropy -= p * math.log2(p)
    return round(entropy, 4)


def extract_interesting_strings(path: Path) -> tuple[int, list[str]]:
    result = subprocess.run(
        ["strings", "-n", "8", str(path)],
        capture_output=True, text=True
    )
    all_strings = result.stdout.splitlines()
    interesting = [
        s for s in all_strings
        if any(pat in s.lower() for pat in INTERESTING_PATTERNS)
    ]
    return len(all_strings), interesting[:50]


def analyze_firmware(path: Path) -> FirmwareInfo:
    md5, sha256 = compute_hashes(path)
    file_type = get_file_type(path)
    entropy = compute_entropy(path)
    strings_count, interesting = extract_interesting_strings(path)

    return FirmwareInfo(
        path=path,
        size=path.stat().st_size,
        md5=md5,
        sha256=sha256,
        file_type=file_type,
        entropy=entropy,
        strings_count=strings_count,
        interesting_strings=interesting,
    )


def run_binwalk(path: Path, extract: bool = False) -> str:
    cmd = ["binwalk"]
    if extract:
        cmd.append("-e")
    cmd.append(str(path))
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.stdout


def main() -> None:
    parser = argparse.ArgumentParser(
        description="펌웨어 초기 정찰 도구",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("firmware", type=Path, help="분석할 펌웨어 파일")
    parser.add_argument("-e", "--extract", action="store_true",
                        help="binwalk로 자동 추출")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="자세한 출력")
    args = parser.parse_args()

    if not args.firmware.exists():
        print(f"[!] 파일을 찾을 수 없음: {args.firmware}", file=sys.stderr)
        sys.exit(1)

    print(f"[*] 펌웨어 분석: {args.firmware}")
    info = analyze_firmware(args.firmware)

    print(f"\n{'='*60}")
    print(f"파일 크기  : {info.size:,} bytes ({info.size/1024/1024:.2f} MB)")
    print(f"MD5        : {info.md5}")
    print(f"SHA256     : {info.sha256}")
    print(f"파일 타입  : {info.file_type}")
    print(f"엔트로피   : {info.entropy:.4f} (7.0+ = 암호화/압축 의심)")
    print(f"문자열 수  : {info.strings_count:,}")
    print(f"{'='*60}")

    if info.interesting_strings:
        print(f"\n[!] 주목할 문자열 ({len(info.interesting_strings)}개):")
        for s in info.interesting_strings:
            print(f"    {s}")

    print(f"\n[*] Binwalk 분석:")
    bw_out = run_binwalk(args.firmware, extract=args.extract)
    print(bw_out)

    if args.extract:
        extract_dir = args.firmware.parent / f"_{args.firmware.name}.extracted"
        if extract_dir.exists():
            print(f"[+] 추출 완료: {extract_dir}")


if __name__ == "__main__":
    main()
```

## 실전 팁

```bash
# 엔트로피 높은 영역 찾기 (암호화/압축)
binwalk -E firmware.bin

# 특정 오프셋에서 추출
dd if=firmware.bin bs=1 skip=0x100000 count=0x200000 of=squashfs.bin

# SquashFS 마운트
unsquashfs squashfs.bin
# 마운트된 파일시스템: ./squashfs-root/

# 하드코딩된 자격 증명 빠른 검색
grep -r "password\|passwd" squashfs-root/etc/ 2>/dev/null
find squashfs-root/ -name "shadow" -o -name "passwd" 2>/dev/null
```

펌웨어 분석의 핵심은 **추출 → 파일시스템 탐색 → 취약점 식별** 3단계다. 다음 파일에서 실제 추출 기법을 심화한다.

---

<a name="english"></a>

# Firmware Hacking Fundamentals

## What is Firmware?

Firmware is low-level software that controls hardware devices, stored in ROM/Flash memory. It exists in every embedded device — IoT gadgets, routers, embedded systems, industrial control equipment — and vulnerable firmware can lead to complete compromise of the entire device.

## Firmware Types

### Classification by Storage Medium
| Type | Characteristics | Examples |
|------|----------------|---------|
| **NOR Flash** | Random read, slow write/erase | Bootloaders, BIOS |
| **NAND Flash** | Sequential read, fast write | Filesystems, large storage |
| **eMMC** | NAND + integrated controller | Smartphones, SBCs |
| **EEPROM** | Small capacity, byte-level modification | Config storage, serial numbers |

### Classification by Architecture
```
x86/x64   — PC BIOS/UEFI, industrial PCs
ARM       — Smartphones, IoT, Raspberry Pi
MIPS      — Home routers, embedded network equipment
PowerPC   — Automotive ECUs, avionics systems
RISC-V    — New embedded platforms
```

## Filesystem Structure

### Typical Firmware Layout
```
+------------------+
| Bootloader       |  U-Boot, RedBoot, GRUB
+------------------+
| Kernel Image     |  Linux zImage, uImage
+------------------+
| Filesystem       |  SquashFS, JFFS2, YAFFS2
+------------------+
| Config Partition |  NVRAM, user settings
+------------------+
```

### Common Embedded Filesystems
```
SquashFS   — Read-only, compressed, most common
JFFS2      — Read/write, optimized for NAND/NOR
UBIFS      — Optimized for large NAND
CramFS     — Small, read-only
ROMFS      — Very simple read-only
ext2/4     — Standard Linux filesystem
```

## Vulnerability Classes

### 1. Hardcoded Credentials
```bash
# Common patterns
admin:admin, root:root, admin:password
admin:1234, user:user, guest:guest

# Search in firmware
strings firmware.bin | grep -i "password\|passwd\|credential\|secret"
grep -r "admin" /extracted_fs/etc/
```

### 2. Exposed Debug Interfaces
```
UART console — Serial debug port, often provides root shell
JTAG         — Direct memory access, debugging
SSH/Telnet   — Left enabled in production builds
Web debug    — Hidden administrative endpoints
```

### 3. Unencrypted Updates
```
Unsigned updates    → Malicious firmware can be flashed
Unencrypted transit → MITM update interception
No rollback protection → Downgrade to older vulnerable firmware
```

### 4. Vulnerable Web Interface
```
Command injection — Ping, traceroute, DNS lookup fields
Path traversal    — File download functionality
Authentication bypass — Hidden admin pages
CSRF              — Cross-site request forgery
```

## Toolchain

### Essential Tools
```bash
# Binary analysis
binwalk      — Firmware extraction/analysis
file         — File type detection
strings      — Printable string extraction
hexdump/xxd  — Hex dump

# Disassembly
radare2      — Multi-architecture reversing
Ghidra       — NSA free decompiler
IDA Pro      — Commercial industry standard

# Filesystem
jefferson    — JFFS2 extractor
unsquashfs   — SquashFS extraction
mtd-utils    — MTD device utilities
```

### Installation
```bash
# Install binwalk (with extraction dependencies)
sudo apt install binwalk python3-pip
pip3 install binwalk

# Additional extraction tools
sudo apt install squashfs-tools jefferson mtd-utils

# Emulation tools
sudo apt install qemu-user-static qemu-system
```

## Basic Analysis Workflow

```
1. Firmware Acquisition
   ├── Download from vendor website
   ├── Dump directly from device (UART/JTAG)
   └── Intercept update mechanism

2. Initial Reconnaissance
   ├── file firmware.bin      → Identify format
   ├── binwalk firmware.bin   → Embedded files/signatures
   └── strings firmware.bin   → Printable strings

3. Extraction
   ├── binwalk -e firmware.bin
   ├── dd + manual offset extraction
   └── Custom scripts

4. Filesystem Analysis
   ├── Config files → Credentials, endpoints
   ├── Binaries    → Vulnerable functions, backdoors
   └── Scripts     → Startup logic, services

5. Dynamic Analysis
   ├── QEMU emulation
   ├── Real hardware debugging
   └── Network service analysis
```

## Firmware Reconnaissance CLI

```python
#!/usr/bin/env python3
"""Firmware initial reconnaissance tool."""

import argparse
import subprocess
import hashlib
import sys
from pathlib import Path
from dataclasses import dataclass, field


@dataclass
class FirmwareInfo:
    path: Path
    size: int
    md5: str
    sha256: str
    file_type: str
    entropy: float
    strings_count: int
    interesting_strings: list[str] = field(default_factory=list)


INTERESTING_PATTERNS = [
    "password", "passwd", "secret", "token", "key",
    "admin", "root", "backdoor", "debug", "telnet",
    "ssh", "ftp", "http", "https", "192.168", "10.0.",
    "eval(", "system(", "exec(", "popen(",
]


def compute_hashes(path: Path) -> tuple[str, str]:
    data = path.read_bytes()
    return (
        hashlib.md5(data).hexdigest(),
        hashlib.sha256(data).hexdigest(),
    )


def get_file_type(path: Path) -> str:
    result = subprocess.run(
        ["file", "-b", str(path)],
        capture_output=True, text=True
    )
    return result.stdout.strip()


def compute_entropy(path: Path) -> float:
    import math
    data = path.read_bytes()
    if not data:
        return 0.0
    freq = [0] * 256
    for byte in data:
        freq[byte] += 1
    entropy = 0.0
    length = len(data)
    for count in freq:
        if count:
            p = count / length
            entropy -= p * math.log2(p)
    return round(entropy, 4)


def extract_interesting_strings(path: Path) -> tuple[int, list[str]]:
    result = subprocess.run(
        ["strings", "-n", "8", str(path)],
        capture_output=True, text=True
    )
    all_strings = result.stdout.splitlines()
    interesting = [
        s for s in all_strings
        if any(pat in s.lower() for pat in INTERESTING_PATTERNS)
    ]
    return len(all_strings), interesting[:50]


def analyze_firmware(path: Path) -> FirmwareInfo:
    md5, sha256 = compute_hashes(path)
    file_type = get_file_type(path)
    entropy = compute_entropy(path)
    strings_count, interesting = extract_interesting_strings(path)

    return FirmwareInfo(
        path=path,
        size=path.stat().st_size,
        md5=md5,
        sha256=sha256,
        file_type=file_type,
        entropy=entropy,
        strings_count=strings_count,
        interesting_strings=interesting,
    )


def run_binwalk(path: Path, extract: bool = False) -> str:
    cmd = ["binwalk"]
    if extract:
        cmd.append("-e")
    cmd.append(str(path))
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.stdout


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Firmware initial reconnaissance tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("firmware", type=Path, help="Firmware file to analyze")
    parser.add_argument("-e", "--extract", action="store_true",
                        help="Auto-extract with binwalk")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Verbose output")
    args = parser.parse_args()

    if not args.firmware.exists():
        print(f"[!] File not found: {args.firmware}", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Analyzing firmware: {args.firmware}")
    info = analyze_firmware(args.firmware)

    print(f"\n{'='*60}")
    print(f"File size  : {info.size:,} bytes ({info.size/1024/1024:.2f} MB)")
    print(f"MD5        : {info.md5}")
    print(f"SHA256     : {info.sha256}")
    print(f"File type  : {info.file_type}")
    print(f"Entropy    : {info.entropy:.4f} (7.0+ = encrypted/compressed suspected)")
    print(f"String count: {info.strings_count:,}")
    print(f"{'='*60}")

    if info.interesting_strings:
        print(f"\n[!] Notable strings ({len(info.interesting_strings)}):")
        for s in info.interesting_strings:
            print(f"    {s}")

    print(f"\n[*] Binwalk analysis:")
    bw_out = run_binwalk(args.firmware, extract=args.extract)
    print(bw_out)

    if args.extract:
        extract_dir = args.firmware.parent / f"_{args.firmware.name}.extracted"
        if extract_dir.exists():
            print(f"[+] Extraction complete: {extract_dir}")


if __name__ == "__main__":
    main()
```

## Practical Tips

```bash
# Find high-entropy regions (encrypted/compressed)
binwalk -E firmware.bin

# Extract from specific offset
dd if=firmware.bin bs=1 skip=0x100000 count=0x200000 of=squashfs.bin

# Mount SquashFS
unsquashfs squashfs.bin
# Mounted filesystem: ./squashfs-root/

# Quick search for hardcoded credentials
grep -r "password\|passwd" squashfs-root/etc/ 2>/dev/null
find squashfs-root/ -name "shadow" -o -name "passwd" 2>/dev/null
```

The core of firmware analysis is the three-step process: **extraction → filesystem exploration → vulnerability identification**. The next file covers actual extraction techniques in depth.
