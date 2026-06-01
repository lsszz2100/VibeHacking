> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 펌웨어 추출 기법

## 추출 방법 개요

```
소프트웨어 방법          하드웨어 방법
├── 벤더 업데이트 파일   ├── UART/직렬 콘솔
├── OTA 캡처             ├── JTAG/SWD 디버거
├── 관리 인터페이스      ├── 플래시 칩 직접 읽기
└── 펌웨어 업데이트 API  └── In-Circuit Emulation (ICE)
```

## 소프트웨어 추출

### 1. 벤더 제공 파일 분석
```bash
# 일반적인 컨테이너 포맷
.bin   — 원시 바이너리 (가장 흔함)
.img   — 디스크/파일시스템 이미지
.trx   — Broadcom 라우터 포맷
.chk   — Netgear 체크섬 포맷
.dlf   — D-Link 포맷
.zip/.tar.gz — 압축 아카이브

# 다중 파트 펌웨어
binwalk -e firmware.bin
# → _firmware.bin.extracted/ 에 파일 생성
```

### 2. OTA 업데이트 인터셉트
```bash
# 장치를 Burp Suite 또는 mitmproxy 뒤에 배치
mitmproxy --mode transparent --ssl-insecure

# 펌웨어 다운로드 URL 캡처 후
curl -O "https://firmware.vendor.com/model/fw_v2.1.bin"
```

### 3. 웹 인터페이스 통한 추출
```bash
# 백업 파일 다운로드 (흔히 암호화 안 됨)
curl -c cookies.txt -b cookies.txt \
     http://192.168.1.1/cgi-bin/backup.cgi \
     -o backup.tar.gz

# 백업에서 설정/바이너리 추출
tar xzf backup.tar.gz
```

## 하드웨어 추출

### UART 직렬 콘솔

#### 하드웨어 설정
```
장치 PCB에서 UART 핀 찾기:
  VCC  — 3.3V 또는 5V
  GND  — 그라운드
  TX   — 장치에서 송신
  RX   — 장치로 수신

USB-UART 어댑터 연결 (3.3V!):
  어댑터 GND → 장치 GND
  어댑터 RX  → 장치 TX
  어댑터 TX  → 장치 RX
```

#### 소프트웨어 설정
```bash
# 직렬 연결
screen /dev/ttyUSB0 115200
# 또는
minicom -D /dev/ttyUSB0 -b 115200

# 공통 보드레이트 시도
for baud in 9600 19200 38400 57600 115200; do
    echo "시도: $baud"
    screen /dev/ttyUSB0 $baud
done
```

#### 부트로더 인터셉트
```bash
# 전원 인가 시 키 입력으로 U-Boot 중단
# 일반적인 중단 키: 스페이스, 'a', 's', Enter

U-Boot> printenv        # 환경 변수 표시
U-Boot> tftp 0x80000000 firmware.bin  # TFTP 서버에서 로드
U-Boot> md 0x80000000 1000  # 메모리 덤프

# TFTP를 통한 파일시스템 덤프
U-Boot> tftpput 0x80000000 4000000 dump.bin
```

### JTAG 추출

```bash
# OpenOCD로 JTAG 연결
openocd -f interface/ftdi/mini-module.cfg \
        -f target/at91sam3.cfg

# OpenOCD 텔넷에서
telnet localhost 4444
> halt
> dump_image firmware_dump.bin 0x00000000 0x100000
> exit

# 흔한 JTAG 핀아웃 (ARM SWD)
SWDCLK — 클록
SWDIO  — 데이터
GND    — 그라운드
VCC    — 레퍼런스 전압 (3.3V)
nRESET — 리셋 (선택사항)
```

### 플래시 칩 직접 읽기

```bash
# SOP8/SOIC8 플래시 칩 식별
# 데이터시트에서 칩 파트넘버 검색

# CH341A 프로그래머 사용 (SPI 플래시)
flashrom -p ch341a_spi -r firmware_backup.bin
flashrom -p ch341a_spi -V  # 지원 칩 목록

# 클립 붙인 채로 읽기 (ISP)
flashrom -p ch341a_spi \
         -c "W25Q64BV/W25Q64CV" \
         -r dump.bin
```

## 자동화 추출 파이프라인

```python
#!/usr/bin/env python3
"""펌웨어 추출 및 분석 자동화 파이프라인."""

import argparse
import subprocess
import shutil
import sys
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed


def run_cmd(cmd: list[str], cwd: Path | None = None) -> tuple[int, str, str]:
    result = subprocess.run(
        cmd, capture_output=True, text=True, cwd=cwd
    )
    return result.returncode, result.stdout, result.stderr


def extract_with_binwalk(fw: Path, out_dir: Path) -> bool:
    rc, stdout, stderr = run_cmd(
        ["binwalk", "--extract", "--directory", str(out_dir), str(fw)]
    )
    return rc == 0


def extract_squashfs(sq_path: Path, out_dir: Path) -> bool:
    rc, _, _ = run_cmd(
        ["unsquashfs", "-d", str(out_dir), str(sq_path)]
    )
    return rc == 0


def find_credentials(root: Path) -> list[dict[str, str]]:
    credential_files = [
        "etc/passwd", "etc/shadow", "etc/config/passwd",
        "etc/htpasswd", "etc/lighttpd.user",
    ]
    creds: list[dict[str, str]] = []

    for cf in credential_files:
        p = root / cf
        if p.exists():
            try:
                content = p.read_text(errors="ignore")
                creds.append({"file": cf, "content": content[:500]})
            except OSError:
                pass

    # 재귀 검색
    for path in root.rglob("*.conf"):
        try:
            text = path.read_text(errors="ignore")
            if any(kw in text.lower() for kw in ["password", "passwd", "secret"]):
                creds.append({
                    "file": str(path.relative_to(root)),
                    "content": text[:300],
                })
        except OSError:
            pass

    return creds


def find_binaries_with_dangerous_functions(root: Path) -> list[str]:
    dangerous = ["system", "popen", "strcpy", "gets", "sprintf"]
    found: list[str] = []

    def check_binary(bin_path: Path) -> str | None:
        rc, stdout, _ = run_cmd(["strings", str(bin_path)])
        if rc != 0:
            return None
        funcs = [f for f in dangerous if f in stdout]
        if funcs:
            return f"{bin_path.relative_to(root)}: {', '.join(funcs)}"
        return None

    binaries = [
        p for p in root.rglob("*")
        if p.is_file() and not p.suffix and p.stat().st_size > 1000
    ]

    with ThreadPoolExecutor(max_workers=8) as ex:
        futures = {ex.submit(check_binary, b): b for b in binaries[:100]}
        for fut in as_completed(futures):
            result = fut.result()
            if result:
                found.append(result)

    return found


def find_network_services(root: Path) -> list[str]:
    services: list[str] = []
    init_dirs = ["etc/init.d", "etc/rc.d", "etc/scripts"]
    for d in init_dirs:
        p = root / d
        if not p.exists():
            continue
        for script in p.iterdir():
            if script.is_file():
                try:
                    text = script.read_text(errors="ignore")
                    if any(svc in text for svc in
                           ["telnetd", "dropbear", "sshd", "ftpd",
                            "httpd", "lighttpd", "uhttpd"]):
                        services.append(str(script.relative_to(root)))
                except OSError:
                    pass
    return services


def main() -> None:
    parser = argparse.ArgumentParser(
        description="펌웨어 추출 및 자동 분석 파이프라인",
    )
    parser.add_argument("firmware", type=Path)
    parser.add_argument("-o", "--output", type=Path, default=Path("fw_analysis"))
    parser.add_argument("--skip-extract", action="store_true")
    args = parser.parse_args()

    if not args.firmware.exists():
        print(f"[!] 파일 없음: {args.firmware}", file=sys.stderr)
        sys.exit(1)

    args.output.mkdir(parents=True, exist_ok=True)
    extract_dir = args.output / "extracted"

    if not args.skip_extract:
        print(f"[*] binwalk 추출 중...")
        extract_with_binwalk(args.firmware, extract_dir)

    # 추출된 SquashFS 찾기
    squashfs_files = list(extract_dir.rglob("*.squashfs")) + \
                     list(extract_dir.rglob("squashfs-root"))
    
    fs_root = extract_dir
    for sq in squashfs_files:
        if sq.suffix == ".squashfs":
            sq_out = args.output / "squashfs_root"
            print(f"[*] SquashFS 추출: {sq}")
            extract_squashfs(sq, sq_out)
            fs_root = sq_out
            break
        elif sq.is_dir():
            fs_root = sq

    print(f"\n[*] 자격 증명 검색...")
    creds = find_credentials(fs_root)
    if creds:
        print(f"[!] 자격 증명 파일 {len(creds)}개 발견:")
        for c in creds:
            print(f"    {c['file']}")

    print(f"\n[*] 취약한 바이너리 검색...")
    dangerous = find_binaries_with_dangerous_functions(fs_root)
    if dangerous:
        print(f"[!] 위험 함수 사용 바이너리 {len(dangerous)}개:")
        for d in dangerous[:10]:
            print(f"    {d}")

    print(f"\n[*] 네트워크 서비스 식별...")
    services = find_network_services(fs_root)
    if services:
        print(f"[+] 시작 스크립트에서 서비스 발견:")
        for s in services:
            print(f"    {s}")

    print(f"\n[+] 분석 완료. 결과: {args.output}")


if __name__ == "__main__":
    main()
```

## 암호화된 펌웨어 처리

```bash
# 암호화 탐지
binwalk -E firmware.bin  # 높은 엔트로피 → 암호화
file firmware.bin        # "data" → 압축 또는 암호화

# 가능한 전략
# 1. 구버전 비암호화 펌웨어에서 키 추출
# 2. 다른 파티션에서 키 검색
strings firmware.bin | grep -i "key\|aes\|rsa\|decrypt"

# 3. 메모리에서 복호화된 펌웨어 덤프 (UART 부팅 후)
# 4. 업데이트 바이너리 리버싱으로 암호화 루틴 파악

# OpenSSL 브루트포스 (알려진 포맷인 경우)
for key in $(cat wordlist.txt); do
    openssl aes-128-cbc -d -k "$key" -in enc.bin -out dec.bin 2>/dev/null
    file dec.bin | grep -v "data" && echo "키 발견: $key" && break
done
```

다음 파일에서 추출된 펌웨어의 정적 분석 기법을 다룬다.

---

<a name="english"></a>

# Firmware Extraction Techniques

## Extraction Method Overview

```
Software Methods           Hardware Methods
├── Vendor update files    ├── UART/Serial console
├── OTA capture            ├── JTAG/SWD debugger
├── Management interface   ├── Direct flash chip read
└── Firmware update API    └── In-Circuit Emulation (ICE)
```

## Software Extraction

### 1. Analyzing Vendor-Provided Files
```bash
# Common container formats
.bin   — Raw binary (most common)
.img   — Disk/filesystem image
.trx   — Broadcom router format
.chk   — Netgear checksum format
.dlf   — D-Link format
.zip/.tar.gz — Compressed archives

# Multi-part firmware
binwalk -e firmware.bin
# → Creates files in _firmware.bin.extracted/
```

### 2. OTA Update Interception
```bash
# Place device behind Burp Suite or mitmproxy
mitmproxy --mode transparent --ssl-insecure

# After capturing firmware download URL
curl -O "https://firmware.vendor.com/model/fw_v2.1.bin"
```

### 3. Extraction via Web Interface
```bash
# Download backup file (often not encrypted)
curl -c cookies.txt -b cookies.txt \
     http://192.168.1.1/cgi-bin/backup.cgi \
     -o backup.tar.gz

# Extract configuration/binaries from backup
tar xzf backup.tar.gz
```

## Hardware Extraction

### UART Serial Console

#### Hardware Setup
```
Locate UART pins on device PCB:
  VCC  — 3.3V or 5V
  GND  — Ground
  TX   — Transmit from device
  RX   — Receive to device

Connect USB-UART adapter (3.3V!):
  Adapter GND → Device GND
  Adapter RX  → Device TX
  Adapter TX  → Device RX
```

#### Software Setup
```bash
# Serial connection
screen /dev/ttyUSB0 115200
# or
minicom -D /dev/ttyUSB0 -b 115200

# Try common baud rates
for baud in 9600 19200 38400 57600 115200; do
    echo "Trying: $baud"
    screen /dev/ttyUSB0 $baud
done
```

#### Bootloader Interception
```bash
# Press key during power-on to interrupt U-Boot
# Common interrupt keys: Space, 'a', 's', Enter

U-Boot> printenv        # Show environment variables
U-Boot> tftp 0x80000000 firmware.bin  # Load from TFTP server
U-Boot> md 0x80000000 1000  # Memory dump

# Filesystem dump via TFTP
U-Boot> tftpput 0x80000000 4000000 dump.bin
```

### JTAG Extraction

```bash
# Connect JTAG with OpenOCD
openocd -f interface/ftdi/mini-module.cfg \
        -f target/at91sam3.cfg

# From OpenOCD telnet
telnet localhost 4444
> halt
> dump_image firmware_dump.bin 0x00000000 0x100000
> exit

# Common JTAG pinout (ARM SWD)
SWDCLK — Clock
SWDIO  — Data
GND    — Ground
VCC    — Reference voltage (3.3V)
nRESET — Reset (optional)
```

### Direct Flash Chip Reading

```bash
# Identify SOP8/SOIC8 flash chip
# Search chip part number in datasheet

# Using CH341A programmer (SPI flash)
flashrom -p ch341a_spi -r firmware_backup.bin
flashrom -p ch341a_spi -V  # List supported chips

# Read with clip attached (ISP)
flashrom -p ch341a_spi \
         -c "W25Q64BV/W25Q64CV" \
         -r dump.bin
```

## Automated Extraction Pipeline

```python
#!/usr/bin/env python3
"""Automated firmware extraction and analysis pipeline."""

import argparse
import subprocess
import shutil
import sys
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed


def run_cmd(cmd: list[str], cwd: Path | None = None) -> tuple[int, str, str]:
    result = subprocess.run(cmd, capture_output=True, text=True, cwd=cwd)
    return result.returncode, result.stdout, result.stderr


def extract_with_binwalk(fw: Path, out_dir: Path) -> bool:
    rc, stdout, stderr = run_cmd(
        ["binwalk", "--extract", "--directory", str(out_dir), str(fw)]
    )
    return rc == 0


def extract_squashfs(sq_path: Path, out_dir: Path) -> bool:
    rc, _, _ = run_cmd(["unsquashfs", "-d", str(out_dir), str(sq_path)])
    return rc == 0


def find_credentials(root: Path) -> list[dict[str, str]]:
    credential_files = [
        "etc/passwd", "etc/shadow", "etc/config/passwd",
        "etc/htpasswd", "etc/lighttpd.user",
    ]
    creds: list[dict[str, str]] = []

    for cf in credential_files:
        p = root / cf
        if p.exists():
            try:
                content = p.read_text(errors="ignore")
                creds.append({"file": cf, "content": content[:500]})
            except OSError:
                pass

    for path in root.rglob("*.conf"):
        try:
            text = path.read_text(errors="ignore")
            if any(kw in text.lower() for kw in ["password", "passwd", "secret"]):
                creds.append({
                    "file": str(path.relative_to(root)),
                    "content": text[:300],
                })
        except OSError:
            pass

    return creds


def find_binaries_with_dangerous_functions(root: Path) -> list[str]:
    dangerous = ["system", "popen", "strcpy", "gets", "sprintf"]
    found: list[str] = []

    def check_binary(bin_path: Path) -> str | None:
        rc, stdout, _ = run_cmd(["strings", str(bin_path)])
        if rc != 0:
            return None
        funcs = [f for f in dangerous if f in stdout]
        if funcs:
            return f"{bin_path.relative_to(root)}: {', '.join(funcs)}"
        return None

    binaries = [
        p for p in root.rglob("*")
        if p.is_file() and not p.suffix and p.stat().st_size > 1000
    ]

    with ThreadPoolExecutor(max_workers=8) as ex:
        futures = {ex.submit(check_binary, b): b for b in binaries[:100]}
        for fut in as_completed(futures):
            result = fut.result()
            if result:
                found.append(result)

    return found


def find_network_services(root: Path) -> list[str]:
    services: list[str] = []
    init_dirs = ["etc/init.d", "etc/rc.d", "etc/scripts"]
    for d in init_dirs:
        p = root / d
        if not p.exists():
            continue
        for script in p.iterdir():
            if script.is_file():
                try:
                    text = script.read_text(errors="ignore")
                    if any(svc in text for svc in
                           ["telnetd", "dropbear", "sshd", "ftpd",
                            "httpd", "lighttpd", "uhttpd"]):
                        services.append(str(script.relative_to(root)))
                except OSError:
                    pass
    return services


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Firmware extraction and automated analysis pipeline",
    )
    parser.add_argument("firmware", type=Path)
    parser.add_argument("-o", "--output", type=Path, default=Path("fw_analysis"))
    parser.add_argument("--skip-extract", action="store_true")
    args = parser.parse_args()

    if not args.firmware.exists():
        print(f"[!] File not found: {args.firmware}", file=sys.stderr)
        sys.exit(1)

    args.output.mkdir(parents=True, exist_ok=True)
    extract_dir = args.output / "extracted"

    if not args.skip_extract:
        print(f"[*] Extracting with binwalk...")
        extract_with_binwalk(args.firmware, extract_dir)

    squashfs_files = list(extract_dir.rglob("*.squashfs")) + \
                     list(extract_dir.rglob("squashfs-root"))

    fs_root = extract_dir
    for sq in squashfs_files:
        if sq.suffix == ".squashfs":
            sq_out = args.output / "squashfs_root"
            print(f"[*] Extracting SquashFS: {sq}")
            extract_squashfs(sq, sq_out)
            fs_root = sq_out
            break
        elif sq.is_dir():
            fs_root = sq

    print(f"\n[*] Searching for credentials...")
    creds = find_credentials(fs_root)
    if creds:
        print(f"[!] Found {len(creds)} credential file(s):")
        for c in creds:
            print(f"    {c['file']}")

    print(f"\n[*] Searching for vulnerable binaries...")
    dangerous = find_binaries_with_dangerous_functions(fs_root)
    if dangerous:
        print(f"[!] {len(dangerous)} binaries with dangerous functions:")
        for d in dangerous[:10]:
            print(f"    {d}")

    print(f"\n[*] Identifying network services...")
    services = find_network_services(fs_root)
    if services:
        print(f"[+] Services found in startup scripts:")
        for s in services:
            print(f"    {s}")

    print(f"\n[+] Analysis complete. Results: {args.output}")


if __name__ == "__main__":
    main()
```

## Handling Encrypted Firmware

```bash
# Detect encryption
binwalk -E firmware.bin  # High entropy → encrypted
file firmware.bin        # "data" → compressed or encrypted

# Possible strategies
# 1. Extract key from older, unencrypted firmware
# 2. Search for key in other partitions
strings firmware.bin | grep -i "key\|aes\|rsa\|decrypt"

# 3. Dump decrypted firmware from memory (after UART boot)
# 4. Reverse update binary to understand encryption routine

# OpenSSL brute force (if known format)
for key in $(cat wordlist.txt); do
    openssl aes-128-cbc -d -k "$key" -in enc.bin -out dec.bin 2>/dev/null
    file dec.bin | grep -v "data" && echo "Key found: $key" && break
done
```

The next file covers static analysis techniques for extracted firmware.
